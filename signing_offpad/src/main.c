#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/class/usb_hid.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/random/random.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <stdlib.h>
#include "examples_util.h"

#define LOG_LEVEL LOG_LEVEL_INF
LOG_MODULE_REGISTER(frost_hid_device);

// Flash storage partition
#define STORAGE_PARTITION storage_partition

// HID configuration
#define REPORT_ID_INPUT  0x01
#define REPORT_ID_OUTPUT 0x02
#define HID_EP_BUSY_FLAG 0
#define MY_HID_REPORT_SIZE  64
#define CHUNK_SIZE       61
#define CHUNK_DELAY_MS   50

// Message protocol constants
#define MSG_HEADER_MAGIC 0x46524F53 // "FROS"
#define MSG_VERSION      0x01

// Message types
typedef enum {
    MSG_TYPE_NONCE_COMMITMENT  = 0x04,
    MSG_TYPE_END_TRANSMISSION  = 0xFF,
    MSG_TYPE_READY             = 0x06,
    MSG_TYPE_SIGN              = 0x07,
    MSG_TYPE_SIGNATURE_SHARE   = 0x08
} message_type_t;

// Message header
typedef struct {
    uint32_t magic;        
    uint8_t version;       
    uint8_t msg_type;      
    uint16_t payload_len;  
    uint32_t participant;  
} __packed message_header_t;

// Nonce commitment structure - EXACTLY matches secp256k1_frost_nonce_commitment
typedef struct {
    uint32_t index;
    uint8_t hiding[64];     // Full 64-byte point serialization
    uint8_t binding[64];    // Full 64-byte point serialization
} __packed serialized_nonce_commitment_t;

// Signature share structure - EXACTLY matches secp256k1_frost_signature_share
typedef struct {
    uint32_t index;
    uint8_t response[32];
} __packed serialized_signature_share_t;

// Keypair structure for transmission
typedef struct {
    uint32_t index;
    uint32_t max_participants;
    uint8_t secret[32];
    uint8_t public_key[64];      // Individual public key
    uint8_t group_public_key[64]; // Group public key (same for all)
} __packed serialized_keypair_t;

// Flash storage structure
typedef struct {
    uint32_t keypair_index;
    uint32_t keypair_max_participants;
    uint8_t keypair_secret[32];
    uint8_t keypair_public_key[64];
    uint8_t keypair_group_public_key[64];
} __packed frost_flash_storage_t;

// Global state
static bool configured = false;
static const struct device *hdev;
static ATOMIC_DEFINE(hid_ep_in_busy, 1);
static struct k_work sign_work;
static struct k_work send_share_work;
static struct k_work report_send;
static frost_flash_storage_t flash_data;
static bool flash_data_valid = false;
static uint8_t chunk_buffer[MY_HID_REPORT_SIZE];
static secp256k1_context *secp256k1_ctx;
static secp256k1_frost_keypair keypair;
static secp256k1_frost_nonce *current_nonce = NULL;

// Store computed signature share
static secp256k1_frost_signature_share computed_signature_share;
static bool signature_share_computed = false;

// Receive buffer for accumulating messages
#define REASSEMBLY_BUFFER_SIZE 2048
static uint8_t receive_buffer[REASSEMBLY_BUFFER_SIZE];
static size_t receive_buffer_pos = 0;
static size_t expected_total_size = 0;
static bool reassembling_message = false;

// Mutex to protect buffer access
K_MUTEX_DEFINE(buffer_mutex);

// Report structure
static struct report {
	uint8_t id;
	uint8_t value;
} __packed report_1 = {
	.id = REPORT_ID_INPUT,
	.value = 0,
};

// Timer for periodic reports
static void report_event_handler(struct k_timer *dummy);
K_TIMER_DEFINE(event_timer, report_event_handler, NULL);
#define REPORT_PERIOD K_SECONDS(2)

// Timeout handling for stuck receive states
static void receive_timeout_handler(struct k_timer *timer);
K_TIMER_DEFINE(receive_timeout_timer, receive_timeout_handler, NULL);

// Fixed HID Report Descriptor - Using the working version format
static const uint8_t hid_report_desc[] = {
	HID_USAGE_PAGE(HID_USAGE_GEN_DESKTOP),
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_COLLECTION(HID_COLLECTION_APPLICATION),
	
	// Input report (device to host)
	HID_REPORT_ID(REPORT_ID_INPUT),
	HID_LOGICAL_MIN8(0x00),
	HID_LOGICAL_MAX16(0xFF, 0x00),
	HID_REPORT_SIZE(8),
	HID_REPORT_COUNT(63),  // 63 bytes data + 1 byte report ID = 64 total
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

// Helper function to log hex data
static void log_hex(const char *label, const uint8_t *data, size_t len) {
    char hexstr[129]; // Enough for 64 bytes
    size_t print_len = (len > 64) ? 64 : len;
    
    for (size_t i = 0; i < print_len; i++) {
        snprintf(&hexstr[i * 2], 3, "%02x", data[i]);
    }
    hexstr[print_len * 2] = '\0';
    
    if (len > 64) {
        LOG_INF("%s (first 64 bytes): %s...", label, hexstr);
    } else {
        LOG_INF("%s: %s", label, hexstr);
    }
}

// Function to reset reassembly state
static void reset_reassembly_state(void)
{
    reassembling_message = false;
    receive_buffer_pos = 0;
    expected_total_size = 0;
    k_timer_stop(&receive_timeout_timer);
    LOG_INF("Reassembly state reset");
}

// Generate nonce at startup - exactly like example.c
static void generate_nonce(void) {
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    
    if (!fill_random(binding_seed, sizeof(binding_seed))) {
        LOG_ERR("Failed to generate binding_seed");
        return;
    }
    if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
        LOG_ERR("Failed to generate hiding_seed");
        return;
    }

    if (current_nonce != NULL) {
        secp256k1_frost_nonce_destroy(current_nonce);
    }
    
    // Create nonce exactly like example.c
    current_nonce = secp256k1_frost_nonce_create(
        secp256k1_ctx, &keypair, binding_seed, hiding_seed);
    
    if (current_nonce) {
        LOG_INF("Generated nonce at startup");
        log_hex("Nonce hiding", current_nonce->commitments.hiding, 32);
        log_hex("Nonce binding", current_nonce->commitments.binding, 32);
    } else {
        LOG_ERR("Failed to generate nonce at startup");
    }
}

// Read FROST data from flash
static int read_frost_data_from_flash(void) {
    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc < 0) {
        LOG_ERR("Failed to open flash area (%d)", rc);
        return rc;
    }

    if (fa->fa_size < sizeof(frost_flash_storage_t)) {
        LOG_ERR("Flash area too small");
        flash_area_close(fa);
        return -ENOSPC;
    }

    rc = flash_area_read(fa, 0, &flash_data, sizeof(frost_flash_storage_t));
    flash_area_close(fa);
    
    if (rc != 0) {
        LOG_ERR("Failed to read flash: %d", rc);
        return rc;
    }

    if (flash_data.keypair_index == 0 || flash_data.keypair_index > 255) {
        LOG_WRN("Invalid flash data (index=%u)", flash_data.keypair_index);
        return -EINVAL;
    }

    flash_data_valid = true;
    LOG_INF("Flash data loaded - Participant: %u", flash_data.keypair_index);
    return 0;
}

// Load key material into secp256k1 structure - exactly like example.c
static int load_frost_key_material(void) {
    if (!flash_data_valid) return -1;
    
    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    keypair.public_keys.index = flash_data.keypair_index;
    keypair.public_keys.max_participants = flash_data.keypair_max_participants;
    memcpy(keypair.secret, flash_data.keypair_secret, 32);
    memcpy(keypair.public_keys.public_key, flash_data.keypair_public_key, 64);
    memcpy(keypair.public_keys.group_public_key, 
           flash_data.keypair_group_public_key, 64);
    
    return 0;
}

// Send data in chunks via HID
static int send_chunked_data(const uint8_t *data, size_t len) {
    if (!configured || !data || len == 0) {
        return -EINVAL;
    }

    size_t offset = 0;
    int chunk_count = 0;
    
    while (offset < len) {
        // Wait for endpoint to be available
        int timeout = 100;
        while (atomic_test_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG) && timeout-- > 0) {
            k_msleep(10);
        }
        if (timeout <= 0) {
            LOG_ERR("HID endpoint timeout");
            return -ETIMEDOUT;
        }
        
        // Prepare chunk
        memset(chunk_buffer, 0, sizeof(chunk_buffer));
        chunk_buffer[0] = REPORT_ID_INPUT;
        size_t remaining = len - offset;
        size_t chunk_size = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
        chunk_buffer[1] = (uint8_t)chunk_size;
        memcpy(&chunk_buffer[2], data + offset, chunk_size);
        
        // Send chunk
        atomic_set_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
        int wrote;
        int ret = hid_int_ep_write(hdev, chunk_buffer, sizeof(chunk_buffer), &wrote);
        if (ret != 0) {
            LOG_ERR("Failed to send chunk: %d", ret);
            atomic_clear_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
            return ret;
        }
        
        offset += chunk_size;
        chunk_count++;
        k_msleep(CHUNK_DELAY_MS);
    }
    
    LOG_INF("Sent %d chunks (%zu bytes total)", chunk_count, len);
    return 0;
}

// Send a complete message
static int send_message(uint8_t msg_type, uint32_t participant, 
                       const void* payload, uint16_t payload_len) {
    message_header_t header = {
        .magic = MSG_HEADER_MAGIC,
        .version = MSG_VERSION,
        .msg_type = msg_type,
        .payload_len = payload_len,
        .participant = participant
    };
    
    size_t total_len = sizeof(header) + payload_len;
    uint8_t *buffer = malloc(total_len);
    if (!buffer) {
        LOG_ERR("Failed to allocate message buffer");
        return -ENOMEM;
    }
    
    memcpy(buffer, &header, sizeof(header));
    if (payload_len > 0 && payload) {
        memcpy(buffer + sizeof(header), payload, payload_len);
    }
    
    LOG_INF("Sending: type=0x%02x, part=%u, len=%u", 
            msg_type, participant, payload_len);
    
    int ret = send_chunked_data(buffer, total_len);
    free(buffer);
    return ret;
}

// Generate and send nonce commitment AND keypair
static int send_nonce_commitment_and_keypair(void) {
    if (!current_nonce) {
        LOG_ERR("No nonce available to send commitment");
        return -1;
    }
    
    // Prepare combined payload: nonce_commitment + keypair
    size_t payload_len = sizeof(serialized_nonce_commitment_t) + sizeof(serialized_keypair_t);
    uint8_t* combined_payload = malloc(payload_len);
    if (!combined_payload) {
        LOG_ERR("Failed to allocate memory for combined payload");
        return -ENOMEM;
    }

    // First part: nonce commitment
    serialized_nonce_commitment_t* nonce_part = (serialized_nonce_commitment_t*)combined_payload;
    nonce_part->index = keypair.public_keys.index;
    // Copy the full 64-byte commitments exactly as they are
    memcpy(nonce_part->hiding, current_nonce->commitments.hiding, 64);
    memcpy(nonce_part->binding, current_nonce->commitments.binding, 64);

    // Second part: keypair
    serialized_keypair_t* keypair_part = (serialized_keypair_t*)(combined_payload + sizeof(serialized_nonce_commitment_t));
    keypair_part->index = keypair.public_keys.index;
    keypair_part->max_participants = keypair.public_keys.max_participants;
    memcpy(keypair_part->secret, keypair.secret, 32);
    memcpy(keypair_part->public_key, keypair.public_keys.public_key, 64);
    memcpy(keypair_part->group_public_key, keypair.public_keys.group_public_key, 64);

    LOG_INF("Sending nonce commitment and keypair for participant %u", keypair.public_keys.index);
    log_hex("Sending hiding commitment", nonce_part->hiding, 32);
    log_hex("Sending binding commitment", nonce_part->binding, 32);
    log_hex("Sending public key", keypair_part->public_key, 32);
    log_hex("Sending group public key", keypair_part->group_public_key, 32);
    
    int ret = send_message(MSG_TYPE_NONCE_COMMITMENT, 
                          keypair.public_keys.index,
                          combined_payload, payload_len);
    
    free(combined_payload);
    return ret;
}

// Function to send signature share
static int send_signature_share(void) {
    if (!signature_share_computed) {
        LOG_ERR("No signature share computed yet");
        return -1;
    }

    serialized_signature_share_t serialized = {
        .index = keypair.public_keys.index
    };
    memcpy(serialized.response, computed_signature_share.response, 32);

    LOG_INF("*** SENDING SIGNATURE SHARE TO COORDINATOR ***");
    log_hex("Signature Share", serialized.response, 32);

    int ret = send_message(MSG_TYPE_SIGNATURE_SHARE, 
                          keypair.public_keys.index,
                          &serialized, sizeof(serialized));
    
    if (ret == 0) {
        LOG_INF("Signature share sent successfully to coordinator");
        // Send end transmission marker
        send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0);
    } else {
        LOG_ERR("Failed to send signature share to coordinator");
    }
    
    return ret;
}

// Process signing data and compute signature share - exactly like example.c
static void process_sign_message(void) {
    const message_header_t *header = (const message_header_t *)receive_buffer;
    const uint8_t* payload = receive_buffer + sizeof(message_header_t);
    
    if (header->payload_len < 32 + 4) {
        LOG_ERR("Invalid sign message length");
        return;
    }
    
    if (!current_nonce) {
        LOG_ERR("No nonce available for signing");
        return;
    }
    
    if (current_nonce->used) {
        LOG_ERR("Nonce already used");
        return;
    }
    
    // Parse payload: [msghash (32 bytes)][num_commitments (4 bytes)][commitments...]
    uint8_t* msg_hash = (uint8_t*)payload;
    uint32_t num_commitments = *(uint32_t*)(payload + 32);
    serialized_nonce_commitment_t* serialized_commitments = (serialized_nonce_commitment_t*)(payload + 32 + 4);
    
    LOG_INF("Received signing request");
    LOG_INF("Message hash (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x...", 
            msg_hash[0], msg_hash[1], msg_hash[2], msg_hash[3],
            msg_hash[4], msg_hash[5], msg_hash[6], msg_hash[7]);
    LOG_INF("Number of commitments: %u", num_commitments);
    
    // Convert serialized commitments to secp256k1_frost_nonce_commitment array
    secp256k1_frost_nonce_commitment *signing_commitments = 
        malloc(num_commitments * sizeof(secp256k1_frost_nonce_commitment));
    if (!signing_commitments) {
        LOG_ERR("Failed to allocate memory for signing commitments");
        return;
    }
    
    for (uint32_t i = 0; i < num_commitments; i++) {
        signing_commitments[i].index = serialized_commitments[i].index;
        memcpy(signing_commitments[i].hiding, serialized_commitments[i].hiding, 64);
        memcpy(signing_commitments[i].binding, serialized_commitments[i].binding, 64);
    }
    
    // Compute signature share EXACTLY like example.c
    int return_val = secp256k1_frost_sign(&computed_signature_share,
                                         msg_hash, num_commitments,
                                         &keypair, current_nonce, signing_commitments);
    
    if (return_val == 1) {
        signature_share_computed = true;
        
        LOG_INF("*** SIGNATURE SHARE COMPUTED SUCCESSFULLY ***");
        log_hex("SIGNATURE SHARE (32 bytes)", computed_signature_share.response, 32);
        
        // Print signature share to console - exactly like example.c
        char hex_str[65];
        for (int i = 0; i < 32; i++) {
            sprintf(hex_str + i * 2, "%02x", computed_signature_share.response[i]);
        }
        hex_str[64] = '\0';
        printk("\n\n=== FROST SIGNATURE SHARE ===\n");
        printk("Participant: %u\n", keypair.public_keys.index);
        printk("Signature: %s\n", hex_str);
        printk("=============================\n\n");
        
        // Schedule work to send signature share to coordinator
        k_work_submit(&send_share_work);
        
    } else {
        LOG_ERR("Failed to compute signature share");
        signature_share_computed = false;
    }
    
    // Clean up
    free(signing_commitments);
}

// Process accumulated message data
static void process_received_message(void) {
    LOG_DBG("Processing receive buffer: %zu bytes", receive_buffer_pos);
    
    if (receive_buffer_pos < sizeof(message_header_t)) {
        LOG_DBG("Insufficient data for header (%zu bytes, need %zu)", 
                receive_buffer_pos, sizeof(message_header_t));
        return;
    }
    
    const message_header_t *header = (const message_header_t *)receive_buffer;
    
    LOG_DBG("Header check: magic=0x%08x (expected=0x%08x), version=%d, type=0x%02x, len=%d", 
            header->magic, MSG_HEADER_MAGIC, header->version, header->msg_type, header->payload_len);
    
    // Validate message header
    if (header->magic != MSG_HEADER_MAGIC || header->version != MSG_VERSION) {
        LOG_WRN("Invalid message header: magic=0x%08x, version=%d", 
                header->magic, header->version);
        // Reset buffer on invalid message
        receive_buffer_pos = 0;
        return;
    }
    
    // Check if we have the complete message
    size_t expected_total = sizeof(message_header_t) + header->payload_len;
    if (receive_buffer_pos < expected_total) {
        LOG_DBG("Waiting for more data: have %zu, need %zu", receive_buffer_pos, expected_total);
        return;
    }
    
    // Process the message
    switch (header->msg_type) {
        case MSG_TYPE_READY:
            LOG_INF("*** Received READY signal from host (participant %u) ***", header->participant);
            k_work_submit(&sign_work);
            break;
            
        case MSG_TYPE_SIGN:
            LOG_INF("*** Received SIGN request from host (participant %u) ***", header->participant);
            k_work_submit(&sign_work);
            break;
            
        default:
            LOG_WRN("Unknown message type: 0x%02x", header->msg_type);
            break;
    }
    
    // Reset buffer after processing
    LOG_DBG("Resetting receive buffer");
    receive_buffer_pos = 0;
}

// Enhanced chunked data handler
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
            chunk_len, reassembling_message, receive_buffer_pos, expected_total_size);
    
    // Check if this is the start of a new message
    if (!reassembling_message && chunk_len >= sizeof(message_header_t)) {
        const message_header_t *header = (const message_header_t *)chunk_data;
        if (header->magic == MSG_HEADER_MAGIC) {
            // This is a new message start
            expected_total_size = sizeof(message_header_t) + header->payload_len;
            
            if (expected_total_size <= REASSEMBLY_BUFFER_SIZE) {
                reassembling_message = true;
                receive_buffer_pos = 0;
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
        size_t space_available = REASSEMBLY_BUFFER_SIZE - receive_buffer_pos;
        size_t bytes_to_copy = (chunk_len > space_available) ? space_available : chunk_len;
        
        if (bytes_to_copy > 0) {
            memcpy(receive_buffer + receive_buffer_pos, chunk_data, bytes_to_copy);
            receive_buffer_pos += bytes_to_copy;
            
            LOG_INF("REASSEMBLY: %zu/%zu bytes (+%zu)", 
                    receive_buffer_pos, expected_total_size, bytes_to_copy);
            
            // Check if message is complete
            if (receive_buffer_pos >= expected_total_size) {
                LOG_INF("MESSAGE COMPLETE: Processing %zu bytes", expected_total_size);
                
                // Stop timeout timer
                k_timer_stop(&receive_timeout_timer);
                
                // Process the complete message
                process_received_message();
                
                // Reset for next message
                reset_reassembly_state();
                
                // If we received more data than expected, handle overflow
                if (receive_buffer_pos > expected_total_size) {
                    size_t overflow = receive_buffer_pos - expected_total_size;
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

// Timeout handler to reset stuck receive state
static void receive_timeout_handler(struct k_timer *timer)
{
    if (k_mutex_lock(&buffer_mutex, K_MSEC(10)) == 0) {
        if (reassembling_message) {
            LOG_WRN("Reassembly timeout - resetting state (had %zu/%zu bytes)", 
                    receive_buffer_pos, expected_total_size);
            reset_reassembly_state();
        }
        k_mutex_unlock(&buffer_mutex);
    }
}

// Work handler for sending signature share
static void send_share_work_handler(struct k_work *work) {
    if (!configured || !flash_data_valid || !signature_share_computed) {
        LOG_ERR("Device not ready for sending signature share");
        return;
    }
    
    LOG_INF("Sending signature share to coordinator...");
    
    // Wait a moment before sending to ensure coordinator is ready
    k_msleep(1000);
    
    if (send_signature_share() != 0) {
        LOG_ERR("Failed to send signature share to coordinator");
    }
}

// Work handler
static void sign_work_handler(struct k_work *work) {
    if (!configured || !flash_data_valid) {
        LOG_ERR("Device not ready for signing");
        return;
    }
    
    const message_header_t *header = (const message_header_t *)receive_buffer;
    
    switch (header->msg_type) {
        case MSG_TYPE_READY:
            LOG_INF("Processing READY message");
            if (send_nonce_commitment_and_keypair() == 0) {
                // Send end transmission marker
                send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0);
            }
            break;
            
        case MSG_TYPE_SIGN:
            LOG_INF("Processing SIGN message");
            process_sign_message();
            break;
            
        default:
            LOG_WRN("Unknown message type in work handler");
            break;
    }
}

// Report work handler
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

// Timer event handler
static void report_event_handler(struct k_timer *dummy)
{
	if (!configured) {
		if (report_1.value < 100) {
			report_1.value++;
		} else {
			report_1.value = 1;
		}
		k_work_submit(&report_send);
	}
}

// HID callbacks
static void int_in_ready_cb(const struct device *dev) {
    atomic_clear_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
}

static void int_out_ready_cb(const struct device *dev) {
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

static void protocol_cb(const struct device *dev, uint8_t protocol) {
    LOG_INF("Protocol: %s", protocol == HID_PROTOCOL_BOOT ? "boot" : "report");
}

static const struct hid_ops ops = {
    .int_in_ready = int_in_ready_cb,
    .int_out_ready = int_out_ready_cb,
    .on_idle = on_idle_cb,
    .protocol_change = protocol_cb,
    .set_report = set_report_cb,
};

// USB status callback
static void status_cb(enum usb_dc_status_code status, const uint8_t *param) {
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
            atomic_clear_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
            configured = true;
            receive_buffer_pos = 0;
            LOG_INF("USB Configured - Ready");
        }
        break;
    default:
        break;
    }
}

int main(void) {
    int ret;
    LOG_INF("=== FROST HID Signing Device Starting ===");
    
    // Create secp256k1 context EXACTLY like example.c
    secp256k1_ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (secp256k1_ctx == NULL) {
        LOG_ERR("Failed to create secp256k1 context");
        return -1;
    }
    
    // Initialize work queues
    k_work_init(&sign_work, sign_work_handler);
    k_work_init(&send_share_work, send_share_work_handler);
    k_work_init(&report_send, send_report);
    
    // Read flash data
    if (read_frost_data_from_flash() != 0) {
        LOG_ERR("Failed to read flash data");
        return -1;
    }
    
    // Load key material
    if (load_frost_key_material() != 0) {
        LOG_ERR("Failed to load key material");
        return -1;
    }
    
    // Generate nonce at startup
    generate_nonce();
    
    // Initialize USB HID
    hdev = device_get_binding("HID_0");
    if (hdev == NULL) {
        LOG_ERR("Cannot get USB HID Device");
        return -1;
    }
    
    usb_hid_register_device(hdev, hid_report_desc, sizeof(hid_report_desc), &ops);
    
    // Start periodic timer
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
    
    LOG_INF("=== FROST HID Device Ready ===");
    LOG_INF("Reassembly buffer size: %d bytes", REASSEMBLY_BUFFER_SIZE);
    
    // Main loop
    while (1) {
        k_msleep(1000);
    }
    
    // Cleanup (never reached)
    if (current_nonce) {
        secp256k1_frost_nonce_destroy(current_nonce);
    }
    secp256k1_context_destroy(secp256k1_ctx);
    
    return 0;
}