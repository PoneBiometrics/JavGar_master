/*
 * FROST Key Receiver - Zephyr USB HID Implementation
 * Receives FROST cryptographic key data via USB HID from Windows host
 */

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/class/usb_hid.h>
#include <string.h>

#define LOG_LEVEL LOG_LEVEL_INF
LOG_MODULE_REGISTER(frost_receiver);

static bool configured;
static const struct device *hdev;
static struct k_work report_send;
static ATOMIC_DEFINE(hid_ep_in_busy, 1);

#define HID_EP_BUSY_FLAG	0
#define REPORT_ID_1		0x01
#define REPORT_PERIOD		K_SECONDS(2)

// Message protocol constants - MUST match sender
#define MSG_HEADER_MAGIC 0x46524F53 // "FROS" as hex
#define MSG_VERSION 0x01

// Message types for the protocol
typedef enum {
    MSG_TYPE_SECRET_SHARE = 0x01,
    MSG_TYPE_PUBLIC_KEY = 0x02,
    MSG_TYPE_COMMITMENTS = 0x03,
    MSG_TYPE_END_TRANSMISSION = 0xFF
} message_type_t;

// Header for each message in the protocol
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;        // Magic number to identify our protocol
    uint8_t version;       // Protocol version
    uint8_t msg_type;      // Type of message
    uint16_t payload_len;  // Length of payload following the header
    uint32_t participant;  // Participant ID (1-based)
} message_header_t;
#pragma pack(pop)

// Data structures for received data
#pragma pack(push, 1)
typedef struct {
    uint32_t receiver_index;
    uint8_t value[32];
} serialized_share_t;

typedef struct {
    uint32_t index;
    uint32_t max_participants;
    uint8_t public_key[64];
    uint8_t group_public_key[33];
} serialized_pubkey_t;
#pragma pack(pop)

// Storage for received data
static struct {
    bool has_secret_share;
    bool has_public_key;
    bool has_commitments;
    bool transmission_complete;
    
    serialized_share_t secret_share;
    serialized_pubkey_t public_key;
    
    // Commitments data (variable size)
    uint32_t commitment_index;
    uint32_t num_coefficients;
    uint8_t zkp_z[32];
    uint8_t zkp_r[64];
    uint8_t *coefficient_commitments;
    size_t coefficient_commitments_size;
    
    uint32_t participant_id;
} received_data = {0};

// Buffer for assembling incoming data
static uint8_t receive_buffer[2048];  // Increased buffer size
static size_t receive_buffer_pos = 0;
static size_t expected_message_size = 0;
static bool receiving_message = false;

static struct report {
	uint8_t id;
	uint8_t value;
} __packed report_1 = {
	.id = REPORT_ID_1,
	.value = 0,
};

static void report_event_handler(struct k_timer *dummy);
static K_TIMER_DEFINE(event_timer, report_event_handler, NULL);

/*
 * Enhanced HID Report Descriptor for bidirectional communication
 * Supports both input and output reports for receiving data from host
 */
static const uint8_t hid_report_desc[] = {
	HID_USAGE_PAGE(HID_USAGE_GEN_DESKTOP),
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_COLLECTION(HID_COLLECTION_APPLICATION),
	
	// Input report (device to host) - for status/acknowledgments
	HID_LOGICAL_MIN8(0x00),
	HID_LOGICAL_MAX16(0xFF, 0x00),
	HID_REPORT_ID(0x01),
	HID_REPORT_SIZE(8),
	HID_REPORT_COUNT(1),
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_INPUT(0x02),
	
	// Output report (host to device) - for receiving FROST data
	HID_LOGICAL_MIN8(0x00),
	HID_LOGICAL_MAX16(0xFF, 0x00),
	HID_REPORT_ID(0x02),
	HID_REPORT_SIZE(8),
	HID_REPORT_COUNT(64),  // 64-byte reports to match sender
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_OUTPUT(0x02),
	
	HID_END_COLLECTION,
};

// Helper function to print hex data
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    LOG_INF("%s:", label);
    for (size_t i = 0; i < len; i++) {
        printk("%02x", data[i]);
        if ((i + 1) % 16 == 0) {
            printk("\n");
        } else if ((i + 1) % 8 == 0) {
            printk("  ");
        } else {
            printk(" ");
        }
    }
    if (len % 16 != 0) {
        printk("\n");
    }
}

// Function to process a complete message
static void process_message(const uint8_t *data, size_t len) {
    if (len < sizeof(message_header_t)) {
        LOG_ERR("Message too short for header: %zu bytes", len);
        return;
    }
    
    const message_header_t *header = (const message_header_t *)data;
    const uint8_t *payload = data + sizeof(message_header_t);
    size_t payload_len = len - sizeof(message_header_t);
    
    // Validate header
    if (header->magic != MSG_HEADER_MAGIC) {
        LOG_ERR("Invalid magic number: 0x%08x (expected 0x%08x)", 
                header->magic, MSG_HEADER_MAGIC);
        return;
    }
    
    if (header->version != MSG_VERSION) {
        LOG_ERR("Unsupported version: %d", header->version);
        return;
    }
    
    if (header->payload_len != payload_len) {
        LOG_ERR("Payload length mismatch: expected %d, got %zu", 
                header->payload_len, payload_len);
        return;
    }
    
    LOG_INF("Received message: type=0x%02x, participant=%u, payload_len=%u",
            header->msg_type, header->participant, header->payload_len);
    
    received_data.participant_id = header->participant;
    
    switch (header->msg_type) {
        case MSG_TYPE_SECRET_SHARE: {
            if (payload_len != sizeof(serialized_share_t)) {
                LOG_ERR("Invalid secret share size: %zu (expected %zu)", 
                        payload_len, sizeof(serialized_share_t));
                break;
            }
            
            memcpy(&received_data.secret_share, payload, sizeof(serialized_share_t));
            received_data.has_secret_share = true;
            
            LOG_INF("Secret share received:");
            LOG_INF("  Receiver index: %u", received_data.secret_share.receiver_index);
            print_hex("  Share value", received_data.secret_share.value, 32);
            break;
        }
        
        case MSG_TYPE_PUBLIC_KEY: {
            if (payload_len != sizeof(serialized_pubkey_t)) {
                LOG_ERR("Invalid public key size: %zu (expected %zu)", 
                        payload_len, sizeof(serialized_pubkey_t));
                break;
            }
            
            memcpy(&received_data.public_key, payload, sizeof(serialized_pubkey_t));
            received_data.has_public_key = true;
            
            LOG_INF("Public key received:");
            LOG_INF("  Index: %u", received_data.public_key.index);
            LOG_INF("  Max participants: %u", received_data.public_key.max_participants);
            print_hex("  Public key", received_data.public_key.public_key, 64);
            print_hex("  Group public key", received_data.public_key.group_public_key, 33);
            break;
        }
        
        case MSG_TYPE_COMMITMENTS: {
            if (payload_len < sizeof(uint32_t) * 2 + 32 + 64) {
                LOG_ERR("Invalid commitments size: %zu", payload_len);
                break;
            }
            
            const uint8_t *ptr = payload;
            
            // Parse index and num_coefficients
            memcpy(&received_data.commitment_index, ptr, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            memcpy(&received_data.num_coefficients, ptr, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            
            // Parse zkp_z and zkp_r
            memcpy(received_data.zkp_z, ptr, 32);
            ptr += 32;
            memcpy(received_data.zkp_r, ptr, 64);
            ptr += 64;
            
            // Parse coefficient commitments
            size_t coef_size = payload_len - (sizeof(uint32_t) * 2 + 32 + 64);
            if (received_data.coefficient_commitments) {
                k_free(received_data.coefficient_commitments);
            }
            received_data.coefficient_commitments = k_malloc(coef_size);
            if (received_data.coefficient_commitments) {
                memcpy(received_data.coefficient_commitments, ptr, coef_size);
                received_data.coefficient_commitments_size = coef_size;
                received_data.has_commitments = true;
                
                LOG_INF("Commitments received:");
                LOG_INF("  Index: %u", received_data.commitment_index);
                LOG_INF("  Num coefficients: %u", received_data.num_coefficients);
                print_hex("  ZKP z", received_data.zkp_z, 32);
                print_hex("  ZKP r", received_data.zkp_r, 64);
                LOG_INF("  Coefficient commitments size: %zu bytes", coef_size);
            } else {
                LOG_ERR("Failed to allocate memory for commitments");
            }
            break;
        }
        
        case MSG_TYPE_END_TRANSMISSION: {
            LOG_INF("End transmission received");
            received_data.transmission_complete = true;
            
            // Print summary of received data
            LOG_INF("\n=== FROST Key Data Summary ===");
            LOG_INF("Participant ID: %u", received_data.participant_id);
            LOG_INF("Secret share: %s", received_data.has_secret_share ? "YES" : "NO");
            LOG_INF("Public key: %s", received_data.has_public_key ? "YES" : "NO");
            LOG_INF("Commitments: %s", received_data.has_commitments ? "YES" : "NO");
            LOG_INF("Transmission complete: %s", received_data.transmission_complete ? "YES" : "NO");
            
            if (received_data.has_secret_share && received_data.has_public_key && 
                received_data.has_commitments) {
                LOG_INF(">>> All FROST key data received successfully! <<<");
                
                // Send acknowledgment by changing the status report
                report_1.value = 0xFF; // Signal successful reception
            } else {
                LOG_WRN(">>> Incomplete FROST key data received <<<");
                report_1.value = 0xEE; // Signal incomplete reception
            }
            break;
        }
        
        default:
            LOG_WRN("Unknown message type: 0x%02x", header->msg_type);
            break;
    }
}

// Function to handle incoming data chunks
static void handle_incoming_data(const uint8_t *data, size_t len) {
    LOG_DBG("Received %zu bytes of raw data", len);
    
    if (len == 0) {
        return;
    }
    
    // Skip report ID if present (check if first byte is report ID)
    const uint8_t *actual_data = data;
    size_t actual_len = len;
    
    // If this looks like it starts with a report ID (0x02 for output reports), skip it
    if (len > 0 && data[0] == 0x02) {
        actual_data = data + 1;
        actual_len = len - 1;
        LOG_DBG("Skipped report ID, processing %zu bytes", actual_len);
    }
    
    // Remove trailing zeros (common in HID reports)
    while (actual_len > 0 && actual_data[actual_len - 1] == 0) {
        actual_len--;
    }
    
    if (actual_len == 0) {
        LOG_DBG("No actual data after processing");
        return;
    }
    
    LOG_DBG("Processing %zu bytes of actual data", actual_len);
    
    // If we're not currently receiving a message, check if this is the start of one
    if (!receiving_message) {
        if (actual_len >= sizeof(message_header_t)) {
            const message_header_t *header = (const message_header_t *)actual_data;
            if (header->magic == MSG_HEADER_MAGIC) {
                // This looks like the start of a new message
                expected_message_size = sizeof(message_header_t) + header->payload_len;
                receiving_message = true;
                receive_buffer_pos = 0;
                LOG_INF("Starting new message, expecting %zu bytes total", expected_message_size);
                
                // Validate expected size
                if (expected_message_size > sizeof(receive_buffer)) {
                    LOG_ERR("Message too large: %zu bytes (max %zu)", 
                            expected_message_size, sizeof(receive_buffer));
                    receiving_message = false;
                    return;
                }
            } else {
                LOG_DBG("Data doesn't look like message start (magic=0x%08x), ignoring", 
                        header->magic);
                return;
            }
        } else {
            LOG_DBG("Not enough data for header (%zu < %zu), ignoring", 
                    actual_len, sizeof(message_header_t));
            return;
        }
    }
    
    // Add data to buffer
    size_t space_available = sizeof(receive_buffer) - receive_buffer_pos;
    size_t bytes_to_copy = (actual_len > space_available) ? space_available : actual_len;
    
    if (bytes_to_copy > 0) {
        memcpy(receive_buffer + receive_buffer_pos, actual_data, bytes_to_copy);
        receive_buffer_pos += bytes_to_copy;
        
        LOG_DBG("Buffer now has %zu bytes (expecting %zu)", 
                receive_buffer_pos, expected_message_size);
        
        // Check if we have a complete message
        if (receive_buffer_pos >= expected_message_size) {
            LOG_INF("Complete message received, processing...");
            process_message(receive_buffer, expected_message_size);
            
            // Reset for next message
            receiving_message = false;
            receive_buffer_pos = 0;
            expected_message_size = 0;
        }
    }
}

static void send_report(struct k_work *work)
{
	int ret, wrote;

	if (!atomic_test_and_set_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG)) {
		ret = hid_int_ep_write(hdev, (uint8_t *)&report_1,
				       sizeof(report_1), &wrote);
		if (ret != 0) {
			/*
			 * Do nothing and wait until host has reset the device
			 * and hid_ep_in_busy is cleared.
			 */
			LOG_ERR("Failed to submit report");
		} else {
			LOG_DBG("Status report submitted (value=0x%02x)", report_1.value);
		}
	} else {
		LOG_DBG("HID IN endpoint busy");
	}
}

static void int_in_ready_cb(const struct device *dev)
{
	ARG_UNUSED(dev);
	if (!atomic_test_and_clear_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG)) {
		LOG_WRN("IN endpoint callback without preceding buffer write");
	}
}

// Output report callback - this is where we receive data from the host
static void int_out_ready_cb(const struct device *dev)
{
	uint8_t buffer[65]; // 64 bytes + potential report ID
	int ret, received;
	
	ret = hid_int_ep_read(dev, buffer, sizeof(buffer), &received);
	if (ret == 0 && received > 0) {
		LOG_DBG("HID OUT: Received %d bytes from host", received);
		handle_incoming_data(buffer, received);
	} else if (ret != 0) {
		LOG_ERR("Failed to read from HID OUT endpoint: %d", ret);
	}
}

// Set Output Report callback - alternative way to receive data
static int set_report_cb(const struct device *dev, struct usb_setup_packet *setup,
			 int32_t *len, uint8_t **data)
{
	LOG_DBG("Set report callback: type=%d, id=%d, len=%d", 
	        setup->wValue >> 8, setup->wValue & 0xFF, *len);
	
	if (*len > 0 && *data) {
		handle_incoming_data(*data, *len);
	}
	
	return 0;
}

static void on_idle_cb(const struct device *dev, uint16_t report_id)
{
	LOG_DBG("On idle callback");
	k_work_submit(&report_send);
}

static void report_event_handler(struct k_timer *dummy)
{
	/* Increment reported data for heartbeat */
	if (report_1.value < 0xEE) {
		report_1.value++;
	} else if (!received_data.transmission_complete) {
		report_1.value = 1; // Reset counter if not in final state
	}
	k_work_submit(&report_send);
}

static void protocol_cb(const struct device *dev, uint8_t protocol)
{
	LOG_INF("New protocol: %s", protocol == HID_PROTOCOL_BOOT ?
		"boot" : "report");
}

static const struct hid_ops ops = {
	.int_in_ready = int_in_ready_cb,
	.int_out_ready = int_out_ready_cb,
	.on_idle = on_idle_cb,
	.protocol_change = protocol_cb,
	.set_report = set_report_cb,
};

static void status_cb(enum usb_dc_status_code status, const uint8_t *param)
{
	switch (status) {
	case USB_DC_RESET:
		configured = false;
		LOG_INF("USB Reset");
		break;
	case USB_DC_CONFIGURED:
		if (!configured) {
			int_in_ready_cb(hdev);
			configured = true;
			LOG_INF("USB Configured - Ready to receive FROST data");
		}
		break;
	case USB_DC_SOF:
		break;
	default:
		LOG_DBG("USB status %u unhandled", status);
		break;
	}
}

int main(void)
{
	int ret;

	LOG_INF("=== FROST Key Receiver Starting ===");

	hdev = device_get_binding("HID_0");
	if (hdev == NULL) {
		LOG_ERR("Cannot get USB HID Device");
		return -ENODEV;
	}

	LOG_INF("HID Device: dev %p", hdev);
	LOG_INF("Ready to receive FROST cryptographic key data via USB HID");

	usb_hid_register_device(hdev, hid_report_desc, sizeof(hid_report_desc),
				&ops);

	atomic_set_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
	k_timer_start(&event_timer, REPORT_PERIOD, REPORT_PERIOD);

	if (usb_hid_set_proto_code(hdev, HID_BOOT_IFACE_CODE_NONE)) {
		LOG_WRN("Failed to set Protocol Code");
	}

	ret = usb_hid_init(hdev);
	if (ret != 0) {
		LOG_ERR("Failed to initialize HID: %d", ret);
		return ret;
	}

	LOG_INF("Starting FROST key receiver application");

	ret = usb_enable(status_cb);
	if (ret != 0) {
		LOG_ERR("Failed to enable USB: %d", ret);
		return ret;
	}

	k_work_init(&report_send, send_report);

	LOG_INF("=== FROST Key Receiver Ready ===");
	LOG_INF("Connect to host and start key distribution...");

	return 0;
}