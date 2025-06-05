/*
 * FROST Key Receiver - Fixed Zephyr USB HID Implementation
 * Receives FROST cryptographic key data via USB HID from Windows host
 */

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/class/usb_hid.h>
#include <zephyr/logging/log.h>
#include <string.h>

#define LOG_LEVEL LOG_LEVEL_INF
LOG_MODULE_REGISTER(frost_receiver);

static bool configured;
static const struct device *hdev;
static struct k_work report_send;
static ATOMIC_DEFINE(hid_ep_in_busy, 1);

#define HID_EP_BUSY_FLAG	0
#define REPORT_ID_INPUT		0x01  // Input reports (device to host)
#define REPORT_ID_OUTPUT	0x02  // Output reports (host to device)
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
struct __attribute__((packed)) message_header {
    uint32_t magic;        // Magic number to identify our protocol
    uint8_t version;       // Protocol version
    uint8_t msg_type;      // Type of message
    uint16_t payload_len;  // Length of payload following the header
    uint32_t participant;  // Participant ID (1-based)
};

// Data structures for received data
struct __attribute__((packed)) serialized_share {
    uint32_t receiver_index;
    uint8_t value[32];
};

struct __attribute__((packed)) serialized_pubkey {
    uint32_t index;
    uint32_t max_participants;
    uint8_t public_key[64];
    uint8_t group_public_key[33];
};

// Storage for received data - using static allocation
static struct received_frost_data {
    bool has_secret_share;
    bool has_public_key;
    bool has_commitments;
    bool transmission_complete;
    
    struct serialized_share secret_share;
    struct serialized_pubkey public_key;
    
    // Commitments data (fixed size)
    uint32_t commitment_index;
    uint32_t num_coefficients;
    uint8_t zkp_z[32];
    uint8_t zkp_r[64];
    uint8_t coefficient_commitments[256];  // Reduced size
    size_t coefficient_commitments_size;
    
    uint32_t participant_id;
} received_data;

// Buffer for assembling incoming data - reduced size and moved to static
#define RECEIVE_BUFFER_SIZE 512  // Reduced from 1024
static uint8_t receive_buffer[RECEIVE_BUFFER_SIZE];
static size_t receive_buffer_pos = 0;
static size_t expected_message_size = 0;
static bool receiving_message = false;

// Mutex to protect buffer access
K_MUTEX_DEFINE(buffer_mutex);

static struct report {
	uint8_t id;
	uint8_t value;
} __packed report_1 = {
	.id = REPORT_ID_INPUT,
	.value = 0,
};

static void report_event_handler(struct k_timer *dummy);
K_TIMER_DEFINE(event_timer, report_event_handler, NULL);

/*
 * Fixed HID Report Descriptor
 */
static const uint8_t hid_report_desc[] = {
	HID_USAGE_PAGE(HID_USAGE_GEN_DESKTOP),
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_COLLECTION(HID_COLLECTION_APPLICATION),
	
	// Input report (device to host)
	HID_REPORT_ID(REPORT_ID_INPUT),
	HID_LOGICAL_MIN8(0x00),
	HID_LOGICAL_MAX16(0xFF, 0x00),
	HID_REPORT_SIZE(8),
	HID_REPORT_COUNT(1),
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_INPUT(0x02),
	
	// Output report (host to device)
	HID_REPORT_ID(REPORT_ID_OUTPUT),
	HID_LOGICAL_MIN8(0x00),
	HID_LOGICAL_MAX16(0xFF, 0x00),
	HID_REPORT_SIZE(8),
	HID_REPORT_COUNT(63),  // 63 bytes data + 1 byte report ID = 64 total
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_OUTPUT(0x02),
	
	HID_END_COLLECTION,
};

// Helper function to safely print hex data - simplified to avoid stack issues
static void print_hex_safe(const char *label, const uint8_t *data, size_t len)
{
    if (!data || len == 0) {
        LOG_INF("%s: (empty)", label);
        return;
    }
    
    // Very limited output to avoid any buffer issues
    size_t max_len = (len > 16) ? 16 : len;
    LOG_INF("%s (%zu bytes): %02x%02x%02x%02x...", 
            label, len, 
            data[0], 
            max_len > 1 ? data[1] : 0,
            max_len > 2 ? data[2] : 0,
            max_len > 3 ? data[3] : 0);
}

// Function to safely process a complete message - simplified
static void process_message(const uint8_t *data, size_t len)
{
    if (!data || len < sizeof(struct message_header)) {
        LOG_ERR("Invalid message size");
        return;
    }
    
    const struct message_header *header = (const struct message_header *)data;
    
    // Validate header
    if (header->magic != MSG_HEADER_MAGIC || header->version != MSG_VERSION) {
        LOG_ERR("Invalid header");
        return;
    }
    
    const uint8_t *payload = data + sizeof(struct message_header);
    size_t payload_len = len - sizeof(struct message_header);
    
    LOG_INF("Message: type=0x%02x, participant=%u, payload=%zu",
            header->msg_type, header->participant, payload_len);
    
    received_data.participant_id = header->participant;
    
    switch (header->msg_type) {
        case MSG_TYPE_SECRET_SHARE:
            if (payload_len >= sizeof(struct serialized_share)) {
                // Use direct assignment to avoid memcpy issues
                const struct serialized_share *share = (const struct serialized_share *)payload;
                received_data.secret_share.receiver_index = share->receiver_index;
                for (int i = 0; i < 32; i++) {
                    received_data.secret_share.value[i] = share->value[i];
                }
                received_data.has_secret_share = true;
                LOG_INF("Secret share received (index=%u)", share->receiver_index);
                print_hex_safe("Share", share->value, 32);
            }
            break;
            
        case MSG_TYPE_PUBLIC_KEY:
            if (payload_len >= sizeof(struct serialized_pubkey)) {
                const struct serialized_pubkey *pubkey = (const struct serialized_pubkey *)payload;
                received_data.public_key.index = pubkey->index;
                received_data.public_key.max_participants = pubkey->max_participants;
                for (int i = 0; i < 64; i++) {
                    received_data.public_key.public_key[i] = pubkey->public_key[i];
                }
                for (int i = 0; i < 33; i++) {
                    received_data.public_key.group_public_key[i] = pubkey->group_public_key[i];
                }
                received_data.has_public_key = true;
                LOG_INF("Public key received (index=%u)", pubkey->index);
            }
            break;
            
        case MSG_TYPE_COMMITMENTS:
            if (payload_len >= 8 + 32 + 64) {  // Minimum size check
                const uint8_t *ptr = payload;
                received_data.commitment_index = *(uint32_t*)ptr;
                ptr += 4;
                received_data.num_coefficients = *(uint32_t*)ptr;
                ptr += 4;
                
                for (int i = 0; i < 32; i++) {
                    received_data.zkp_z[i] = ptr[i];
                }
                ptr += 32;
                
                for (int i = 0; i < 64; i++) {
                    received_data.zkp_r[i] = ptr[i];
                }
                ptr += 64;
                
                // Copy remaining coefficient data safely
                size_t coef_size = payload_len - (8 + 32 + 64);
                if (coef_size <= sizeof(received_data.coefficient_commitments)) {
                    for (size_t i = 0; i < coef_size; i++) {
                        received_data.coefficient_commitments[i] = ptr[i];
                    }
                    received_data.coefficient_commitments_size = coef_size;
                    received_data.has_commitments = true;
                    LOG_INF("Commitments received (index=%u)", received_data.commitment_index);
                }
            }
            break;
            
        case MSG_TYPE_END_TRANSMISSION:
            LOG_INF("End transmission received");
            received_data.transmission_complete = true;
            
            LOG_INF("=== FROST Summary ===");
            LOG_INF("Participant: %u", received_data.participant_id);
            LOG_INF("Secret: %s", received_data.has_secret_share ? "OK" : "NO");
            LOG_INF("Public: %s", received_data.has_public_key ? "OK" : "NO");
            LOG_INF("Commits: %s", received_data.has_commitments ? "OK" : "NO");
            
            if (received_data.has_secret_share && received_data.has_public_key && 
                received_data.has_commitments) {
                LOG_INF("SUCCESS: All data received!");
                report_1.value = 0xFF;
            } else {
                LOG_WRN("INCOMPLETE data received");
                report_1.value = 0xEE;
            }
            break;
            
        default:
            LOG_WRN("Unknown message type: 0x%02x", header->msg_type);
            break;
    }
}

// Simplified data handling to avoid stack/memory issues
static void handle_incoming_data(const uint8_t *data, size_t len)
{
    if (!data || len == 0) return;
    
    if (k_mutex_lock(&buffer_mutex, K_MSEC(100)) != 0) {
        LOG_ERR("Mutex lock failed");
        return;
    }
    
    // Skip report ID if present
    const uint8_t *actual_data = data;
    size_t actual_len = len;
    
    if (len > 0 && data[0] == REPORT_ID_OUTPUT) {
        actual_data = data + 1;
        actual_len = len - 1;
    }
    
    // Remove trailing zeros
    while (actual_len > 0 && actual_data[actual_len - 1] == 0) {
        actual_len--;
    }
    
    if (actual_len == 0) {
        k_mutex_unlock(&buffer_mutex);
        return;
    }
    
    // Check for new message start
    if (!receiving_message && actual_len >= sizeof(struct message_header)) {
        const struct message_header *header = (const struct message_header *)actual_data;
        if (header->magic == MSG_HEADER_MAGIC) {
            expected_message_size = sizeof(struct message_header) + header->payload_len;
            
            if (expected_message_size <= RECEIVE_BUFFER_SIZE) {
                receiving_message = true;
                receive_buffer_pos = 0;
                LOG_INF("New message: %zu bytes expected", expected_message_size);
            } else {
                LOG_ERR("Message too large: %zu", expected_message_size);
                k_mutex_unlock(&buffer_mutex);
                return;
            }
        }
    }
    
    // Add data to buffer
    if (receiving_message && receive_buffer_pos < RECEIVE_BUFFER_SIZE) {
        size_t space = RECEIVE_BUFFER_SIZE - receive_buffer_pos;
        size_t to_copy = (actual_len > space) ? space : actual_len;
        
        // Copy byte by byte to avoid any alignment issues
        for (size_t i = 0; i < to_copy; i++) {
            receive_buffer[receive_buffer_pos + i] = actual_data[i];
        }
        receive_buffer_pos += to_copy;
        
        LOG_DBG("Buffer: %zu/%zu", receive_buffer_pos, expected_message_size);
        
        // Check if complete
        if (receive_buffer_pos >= expected_message_size) {
            LOG_INF("Message complete, processing");
            process_message(receive_buffer, expected_message_size);
            
            // Reset
            receiving_message = false;
            receive_buffer_pos = 0;
            expected_message_size = 0;
        }
    }
    
    k_mutex_unlock(&buffer_mutex);
}

static void send_report(struct k_work *work)
{
	int ret, wrote;

	if (!atomic_test_and_set_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG)) {
		ret = hid_int_ep_write(hdev, (uint8_t *)&report_1,
				       sizeof(report_1), &wrote);
		if (ret != 0) {
			LOG_ERR("Report send failed: %d", ret);
		}
	}
}

static void int_in_ready_cb(const struct device *dev)
{
	atomic_clear_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
}

static void int_out_ready_cb(const struct device *dev)
{
	uint8_t buffer[64];
	int ret, received;
	
	ret = hid_int_ep_read(dev, buffer, sizeof(buffer), &received);
	if (ret == 0 && received > 0) {
		handle_incoming_data(buffer, received);
	}
}

static int set_report_cb(const struct device *dev, struct usb_setup_packet *setup,
			 int32_t *len, uint8_t **data)
{
	if (*len > 0 && *data) {
		handle_incoming_data(*data, *len);
	}
	return 0;
}

static void on_idle_cb(const struct device *dev, uint16_t report_id)
{
	k_work_submit(&report_send);
}

static void report_event_handler(struct k_timer *dummy)
{
	if (!received_data.transmission_complete) {
		if (report_1.value < 100) {
			report_1.value++;
		} else {
			report_1.value = 1;
		}
		k_work_submit(&report_send);
	}
}

static void protocol_cb(const struct device *dev, uint8_t protocol)
{
	LOG_INF("Protocol: %s", protocol == HID_PROTOCOL_BOOT ? "boot" : "report");
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
			LOG_INF("USB Configured - Ready for FROST data");
		}
		break;
	case USB_DC_SOF:
		break;
	default:
		break;
	}
}

int main(void)
{
	int ret;

	LOG_INF("=== FROST Key Receiver Starting ===");
	
	// Initialize data structure
	memset(&received_data, 0, sizeof(received_data));

	hdev = device_get_binding("HID_0");
	if (hdev == NULL) {
		LOG_ERR("Cannot get USB HID Device");
		return -ENODEV;
	}

	usb_hid_register_device(hdev, hid_report_desc, sizeof(hid_report_desc), &ops);

	atomic_set_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
	k_timer_start(&event_timer, REPORT_PERIOD, REPORT_PERIOD);

	ret = usb_hid_init(hdev);
	if (ret != 0) {
		LOG_ERR("Failed to initialize HID: %d", ret);
		return ret;
	}

	ret = usb_enable(status_cb);
	if (ret != 0) {
		LOG_ERR("Failed to enable USB: %d", ret);
		return ret;
	}

	k_work_init(&report_send, send_report);

	LOG_INF("=== FROST Receiver Ready ===");
	return 0;
}