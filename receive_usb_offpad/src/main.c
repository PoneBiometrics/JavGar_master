/*
 * FROST Key Receiver - Chunked Data Protocol with Flash Storage
 * Receives FROST cryptographic key data via USB HID from Windows host
 * Now handles chunked transmission with length bytes
 * Stores received data to flash memory for persistence
 */

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/class/usb_hid.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
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

// Flash storage partition
#define STORAGE_PARTITION     storage_partition

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

// Flash storage structure - matches the UART version
typedef struct {
    // Keypair storage
    uint32_t keypair_index;
    uint32_t keypair_max_participants;
    uint8_t keypair_secret[32];
    uint8_t keypair_public_key[64];
    uint8_t keypair_group_public_key[33];

    // Commitments storage
    uint32_t commitments_index;
    uint32_t commitments_num_coefficients;
    uint8_t commitments_zkp_z[32];
    uint8_t commitments_zkp_r[64];
    // Coefficient commitments data
    uint8_t commitments_coefficient_data[512];  // Increased size
    size_t commitments_coefficient_data_size;
} __packed frost_flash_storage_t;

// Storage for received data - using static allocation
static struct received_frost_data {
    bool has_secret_share;
    bool has_public_key;
    bool has_commitments;
    bool transmission_complete;
    
    struct serialized_share secret_share;
    struct serialized_pubkey public_key;
    
    // Commitments data (increased size)
    uint32_t commitment_index;
    uint32_t num_coefficients;
    uint8_t zkp_z[32];
    uint8_t zkp_r[64];
    uint8_t coefficient_commitments[512];  // Increased size
    size_t coefficient_commitments_size;
    
    uint32_t participant_id;
} received_data;

// NEW: Chunked data reassembly buffer - larger for complete messages
#define REASSEMBLY_BUFFER_SIZE 2048
static uint8_t reassembly_buffer[REASSEMBLY_BUFFER_SIZE];
static size_t reassembly_pos = 0;
static size_t expected_total_size = 0;
static bool reassembling_message = false;

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

// Timeout handling for stuck receive states
static void receive_timeout_handler(struct k_timer *timer);
K_TIMER_DEFINE(receive_timeout_timer, receive_timeout_handler, NULL);

/*
 * Fixed HID Report Descriptor - Updated for chunked protocol
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
	
	// Output report (host to device) - Updated for chunked data
	HID_REPORT_ID(REPORT_ID_OUTPUT),
	HID_LOGICAL_MIN8(0x00),
	HID_LOGICAL_MAX16(0xFF, 0x00),
	HID_REPORT_SIZE(8),
	HID_REPORT_COUNT(63),  // 63 bytes data + 1 byte report ID = 64 total
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_OUTPUT(0x02),
	
	HID_END_COLLECTION,
};

// Helper function to safely print hex data
static void print_hex_safe(const char *label, const uint8_t *data, size_t len)
{
    if (!data || len == 0) {
        LOG_INF("%s: (empty)", label);
        return;
    }
    
    size_t max_len = (len > 16) ? 16 : len;
    LOG_INF("%s (%zu bytes): %02x%02x%02x%02x...", 
            label, len, 
            data[0], 
            max_len > 1 ? data[1] : 0,
            max_len > 2 ? data[2] : 0,
            max_len > 3 ? data[3] : 0);
}

// Function to reset reassembly state
static void reset_reassembly_state(void)
{
    reassembling_message = false;
    reassembly_pos = 0;
    expected_total_size = 0;
    k_timer_stop(&receive_timeout_timer);
    LOG_INF("Reassembly state reset");
}

// Function to write FROST key material to flash
static int write_frost_data_to_flash(void) {
    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc < 0) {
        LOG_ERR("Failed to open flash area (%d)", rc);
        return rc;
    }

    // Prepare serializable storage structure
    frost_flash_storage_t flash_data = {0};

    // Fill keypair data from received_data
    if (received_data.has_secret_share) {
        flash_data.keypair_index = received_data.secret_share.receiver_index;
        memcpy(flash_data.keypair_secret, received_data.secret_share.value, 32);
    }
    
    if (received_data.has_public_key) {
        flash_data.keypair_index = received_data.public_key.index;
        flash_data.keypair_max_participants = received_data.public_key.max_participants;
        memcpy(flash_data.keypair_public_key, received_data.public_key.public_key, 64);
        memcpy(flash_data.keypair_group_public_key, received_data.public_key.group_public_key, 33);
    }

    // Fill commitments data
    if (received_data.has_commitments) {
        flash_data.commitments_index = received_data.commitment_index;
        flash_data.commitments_num_coefficients = received_data.num_coefficients;
        memcpy(flash_data.commitments_zkp_z, received_data.zkp_z, 32);
        memcpy(flash_data.commitments_zkp_r, received_data.zkp_r, 64);
        memcpy(flash_data.commitments_coefficient_data, received_data.coefficient_commitments, 
               received_data.coefficient_commitments_size);
        flash_data.commitments_coefficient_data_size = received_data.coefficient_commitments_size;
    }

    // Get flash device details
    const struct device *flash_dev = flash_area_get_device(fa);
    if (!device_is_ready(flash_dev)) {
        LOG_ERR("Flash device not ready");
        flash_area_close(fa);
        return -1;
    }

    // Get erase block size
    struct flash_pages_info info;
    rc = flash_get_page_info_by_offs(flash_dev, fa->fa_off, &info);
    if (rc != 0) {
        LOG_ERR("Failed to get flash page info (%d)", rc);
        flash_area_close(fa);
        return rc;
    }

    // Erase flash sector
    size_t erase_size = ROUND_UP(sizeof(frost_flash_storage_t), info.size);
    rc = flash_area_erase(fa, 0, erase_size);
    if (rc != 0) {
        LOG_ERR("Failed to erase flash (%d)", rc);
        flash_area_close(fa);
        return rc;
    }

    // Prepare padded write buffer
    size_t write_block_size = flash_get_write_block_size(flash_dev);
    size_t padded_size = ROUND_UP(sizeof(frost_flash_storage_t), write_block_size);
    uint8_t padded_buf[padded_size];
    memset(padded_buf, 0xFF, padded_size);
    memcpy(padded_buf, &flash_data, sizeof(frost_flash_storage_t));

    // Write to flash
    rc = flash_area_write(fa, 0, padded_buf, padded_size);
    if (rc != 0) {
        LOG_ERR("Failed to write to flash (%d)", rc);
        flash_area_close(fa);
        return rc;
    }

    LOG_INF("FROST key material written to flash.");
    flash_area_close(fa);
    return 0;
}

// Function to read and log FROST key material from flash
static int read_frost_data_from_flash(void) {
    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc < 0) {
        LOG_ERR("Failed to open flash area (%d)", rc);
        return rc;
    }

    // Read back stored data
    frost_flash_storage_t flash_data;
    rc = flash_area_read(fa, 0, &flash_data, sizeof(frost_flash_storage_t));
    if (rc != 0) {
        LOG_ERR("Failed to read flash: %d", rc);
        flash_area_close(fa);
        return rc;
    }

    // Log keypair information
    LOG_INF("=== Stored Keypair ===");
    LOG_INF("Participant Index: %d", flash_data.keypair_index);
    LOG_INF("Max Participants: %d", flash_data.keypair_max_participants);
    
    // Log secret and public keys in hex
    char hex_buf[129];
    for (int i = 0; i < 32; i++) {
        sprintf(&hex_buf[i * 2], "%02x", flash_data.keypair_secret[i]);
    }
    hex_buf[64] = '\0';
    LOG_INF("Secret Share: %s", hex_buf);

    for (int i = 0; i < 64; i++) {
        sprintf(&hex_buf[i * 2], "%02x", flash_data.keypair_public_key[i]);
    }
    hex_buf[128] = '\0';
    LOG_INF("Public Key: %s", hex_buf);

    for (int i = 0; i < 33; i++) {
        sprintf(&hex_buf[i * 2], "%02x", flash_data.keypair_group_public_key[i]);
    }
    hex_buf[66] = '\0';
    LOG_INF("Group Public Key: %s", hex_buf);

    // Log commitments info
    LOG_INF("=== Stored Commitments ===");
    LOG_INF("Commitments Index: %d", flash_data.commitments_index);
    LOG_INF("Num Coefficients: %d", flash_data.commitments_num_coefficients);
    LOG_INF("Coefficient Data Size: %zu", flash_data.commitments_coefficient_data_size);

    flash_area_close(fa);
    return 0;
}

// Function to safely process a complete message
static void process_message(const uint8_t *data, size_t len)
{
    if (!data || len < sizeof(struct message_header)) {
        LOG_ERR("Invalid message size: %zu", len);
        return;
    }
    
    const struct message_header *header = (const struct message_header *)data;
    
    // Validate header
    if (header->magic != MSG_HEADER_MAGIC || header->version != MSG_VERSION) {
        LOG_ERR("Invalid header: magic=0x%08x, version=0x%02x", header->magic, header->version);
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
                const struct serialized_share *share = (const struct serialized_share *)payload;
                received_data.secret_share.receiver_index = share->receiver_index;
                for (int i = 0; i < 32; i++) {
                    received_data.secret_share.value[i] = share->value[i];
                }
                received_data.has_secret_share = true;
                LOG_INF("Secret share received (index=%u)", share->receiver_index);
                print_hex_safe("Share", share->value, 32);
            } else {
                LOG_ERR("Secret share payload too small: %zu", payload_len);
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
                LOG_INF("Public key received (index=%u, max_participants=%u)", 
                        pubkey->index, pubkey->max_participants);
            } else {
                LOG_ERR("Public key payload too small: %zu", payload_len);
            }
            break;
            
        case MSG_TYPE_COMMITMENTS:
            if (payload_len >= 8 + 32 + 64) {
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
                
                // Copy remaining coefficient data safely with bounds checking
                size_t coef_size = payload_len - (8 + 32 + 64);
                if (coef_size <= sizeof(received_data.coefficient_commitments)) {
                    for (size_t i = 0; i < coef_size; i++) {
                        received_data.coefficient_commitments[i] = ptr[i];
                    }
                    received_data.coefficient_commitments_size = coef_size;
                    received_data.has_commitments = true;
                    LOG_INF("Commitments received (index=%u, coefficients=%u, coef_size=%zu)", 
                            received_data.commitment_index, received_data.num_coefficients, coef_size);
                } else {
                    LOG_ERR("Coefficient data too large: %zu > %zu", coef_size, 
                            sizeof(received_data.coefficient_commitments));
                }
            } else {
                LOG_ERR("Commitments payload too small: %zu", payload_len);
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
                
                // Write received data to flash
                int rc = write_frost_data_to_flash();
                if (rc == 0) {
                    LOG_INF("Data successfully stored to flash");
                    // Read back and verify the data
                    read_frost_data_from_flash();
                    report_1.value = 0xFF;  // Success indicator
                } else {
                    LOG_ERR("Failed to store data to flash");
                    report_1.value = 0xEE;  // Error indicator
                }
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

// Timeout handler to reset stuck receive state
static void receive_timeout_handler(struct k_timer *timer)
{
    if (k_mutex_lock(&buffer_mutex, K_MSEC(10)) == 0) {
        if (reassembling_message) {
            LOG_WRN("Reassembly timeout - resetting state (had %zu/%zu bytes)", 
                    reassembly_pos, expected_total_size);
            reset_reassembly_state();
        }
        k_mutex_unlock(&buffer_mutex);
    }
}

// NEW: Enhanced chunked data handler
static void handle_chunked_data(const uint8_t *data, size_t len)
{
    if (!data || len < 3) {  // Report ID + Length + at least 1 byte data
        LOG_WRN("Invalid chunk: too small (%zu bytes)", len);
        return;
    }
    
    if (k_mutex_lock(&buffer_mutex, K_MSEC(100)) != 0) {
        LOG_ERR("Mutex lock failed");
        return;
    }
    
    // Extract chunk info: [Report ID][Length][Data...]
    uint8_t report_id = data[0];
    uint8_t chunk_len = data[1];
    const uint8_t *chunk_data = data + 2;
    
    // Validate chunk
    if (report_id != REPORT_ID_OUTPUT) {
        LOG_WRN("Wrong report ID: 0x%02x", report_id);
        k_mutex_unlock(&buffer_mutex);
        return;
    }
    
    if (chunk_len == 0 || chunk_len > (len - 2)) {
        LOG_WRN("Invalid chunk length: %u (packet size: %zu)", chunk_len, len);
        k_mutex_unlock(&buffer_mutex);
        return;
    }
    
    LOG_INF("CHUNK: %u bytes, reassembly=%d, pos=%zu/%zu", 
            chunk_len, reassembling_message, reassembly_pos, expected_total_size);
    
    // Check if this is the start of a new message
    if (!reassembling_message && chunk_len >= sizeof(struct message_header)) {
        const struct message_header *header = (const struct message_header *)chunk_data;
        if (header->magic == MSG_HEADER_MAGIC) {
            // This is a new message start
            expected_total_size = sizeof(struct message_header) + header->payload_len;
            
            if (expected_total_size <= REASSEMBLY_BUFFER_SIZE) {
                reassembling_message = true;
                reassembly_pos = 0;
                LOG_INF("NEW MESSAGE START: type=0x%02x, total=%zu bytes expected", 
                        header->msg_type, expected_total_size);
                
                // Start timeout timer
                k_timer_start(&receive_timeout_timer, K_SECONDS(30), K_NO_WAIT);
            } else {
                LOG_ERR("Message too large: %zu > %d", expected_total_size, REASSEMBLY_BUFFER_SIZE);
                k_mutex_unlock(&buffer_mutex);
                return;
            }
        } else {
            LOG_WRN("Not a message start (magic=0x%08x)", header->magic);
            k_mutex_unlock(&buffer_mutex);
            return;
        }
    }
    
    // Add chunk to reassembly buffer if we're reassembling
    if (reassembling_message) {
        size_t space_available = REASSEMBLY_BUFFER_SIZE - reassembly_pos;
        size_t bytes_to_copy = (chunk_len > space_available) ? space_available : chunk_len;
        
        if (bytes_to_copy > 0) {
            memcpy(reassembly_buffer + reassembly_pos, chunk_data, bytes_to_copy);
            reassembly_pos += bytes_to_copy;
            
            LOG_INF("REASSEMBLY: %zu/%zu bytes (+%zu)", 
                    reassembly_pos, expected_total_size, bytes_to_copy);
            
            // Check if message is complete
            if (reassembly_pos >= expected_total_size) {
                LOG_INF("MESSAGE COMPLETE: Processing %zu bytes", expected_total_size);
                
                // Stop timeout timer
                k_timer_stop(&receive_timeout_timer);
                
                // Process the complete message
                process_message(reassembly_buffer, expected_total_size);
                
                // Reset for next message
                reset_reassembly_state();
                
                // If we received more data than expected, handle overflow
                if (reassembly_pos > expected_total_size) {
                    size_t overflow = reassembly_pos - expected_total_size;
                    LOG_WRN("Data overflow: %zu bytes", overflow);
                }
            }
        } else {
            LOG_ERR("No space in reassembly buffer");
            reset_reassembly_state();
        }
    } else {
        LOG_WRN("Received chunk but not reassembling - discarded %u bytes", chunk_len);
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
		// Reset/update timeout on successful data reception
		k_timer_stop(&receive_timeout_timer);
		if (reassembling_message) {
			k_timer_start(&receive_timeout_timer, K_SECONDS(30), K_NO_WAIT);
		}
		
		handle_chunked_data(buffer, received);
	}
}

static int set_report_cb(const struct device *dev, struct usb_setup_packet *setup,
			 int32_t *len, uint8_t **data)
{
	if (*len > 0 && *data) {
		// Reset/update timeout on successful data reception
		k_timer_stop(&receive_timeout_timer);
		if (reassembling_message) {
			k_timer_start(&receive_timeout_timer, K_SECONDS(30), K_NO_WAIT);
		}
		
		handle_chunked_data(*data, *len);
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
		// Reset reassembly state on USB reset
		if (k_mutex_lock(&buffer_mutex, K_MSEC(100)) == 0) {
			reset_reassembly_state();
			k_mutex_unlock(&buffer_mutex);
		}
		break;
	case USB_DC_CONFIGURED:
		if (!configured) {
			int_in_ready_cb(hdev);
			configured = true;
			LOG_INF("USB Configured - Ready for chunked FROST data");
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

	LOG_INF("=== FROST Key Receiver with Chunked Protocol Starting ===");
	
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

	LOG_INF("=== FROST Receiver with Chunked Protocol Ready ===");
	LOG_INF("Reassembly buffer size: %d bytes", REASSEMBLY_BUFFER_SIZE);
	return 0;
}