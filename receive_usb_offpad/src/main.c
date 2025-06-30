#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/class/usb_hid.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <string.h>
#include "examples_util.h"

#define LOG_LEVEL LOG_LEVEL_INF
LOG_MODULE_REGISTER(frost_receiver);

static bool configured;
static const struct device *hdev;
static struct k_work report_send;
static ATOMIC_DEFINE(hid_ep_in_busy, 1);

// Work queue for flash operations
static struct k_work flash_work;
static struct k_work cleanup_work;

#define HID_EP_BUSY_FLAG    0
#define REPORT_ID_INPUT     0x01  
#define REPORT_ID_OUTPUT    0x02  
#define REPORT_PERIOD       K_SECONDS(2)

// Flash storage partition
#define STORAGE_PARTITION     storage_partition

// Message protocol constants
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
    uint32_t magic;
    uint8_t version;
    uint8_t msg_type;
    uint16_t payload_len;
    uint32_t participant;
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
    uint8_t group_public_key[64]; 
};

// Flash storage structure
typedef struct {
    uint32_t keypair_index;
    uint32_t keypair_max_participants;
    uint8_t keypair_secret[32];
    uint8_t keypair_public_key[64];     
    uint8_t keypair_group_public_key[64]; 
    uint32_t commitments_index;
    uint32_t commitments_num_coefficients;
    uint8_t commitments_zkp_z[32];
    uint8_t commitments_zkp_r[64];
    uint8_t commitments_coefficient_data[512];  
    size_t commitments_coefficient_data_size;
} __packed frost_flash_storage_t;

// Storage for received data
static struct received_frost_data {
    bool has_secret_share;
    bool has_public_key;
    bool has_commitments;
    bool transmission_complete;
    bool flash_write_pending;
    bool operation_complete;         
    bool system_shutting_down;       
    
    struct serialized_share secret_share;
    struct serialized_pubkey public_key;
    
    uint32_t commitment_index;
    uint32_t num_coefficients;
    uint8_t zkp_z[32];
    uint8_t zkp_r[64];
    uint8_t coefficient_commitments[512];  
    size_t coefficient_commitments_size;
    
    uint32_t participant_id;
} received_data;

// Chunked data reassembly buffer
#define REASSEMBLY_BUFFER_SIZE 2048
static __aligned(4) uint8_t reassembly_buffer[REASSEMBLY_BUFFER_SIZE];
static size_t reassembly_pos = 0;
static size_t expected_total_size = 0;
static bool reassembling_message = false;

// Mutex to protect buffer access
K_MUTEX_DEFINE(buffer_mutex);

// Forward declarations
static void process_message(const uint8_t *data, size_t len);
static void handle_chunked_data(const uint8_t *data, size_t len);

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

// Timer for controlled shutdown
static void shutdown_timer_handler(struct k_timer *timer);
K_TIMER_DEFINE(shutdown_timer, shutdown_timer_handler, NULL);

// HID Report Descriptor
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

// Helper function to print hex data
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
    memset(reassembly_buffer, 0, sizeof(reassembly_buffer));
    LOG_DBG("Reassembly state reset");
}

// Function to write FROST key material to flash
static int write_frost_data_to_flash(void) {
    LOG_INF("Starting flash write operation...");
    
    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc < 0) {
        LOG_ERR("Failed to open flash area (%d)", rc);
        return rc;
    }

    if (!fa) {
        LOG_ERR("Flash area is NULL");
        return -EINVAL;
    }

    LOG_INF("Flash area opened successfully");

    // Prepare serializable storage structure
    static __aligned(8) frost_flash_storage_t flash_data;  
    memset(&flash_data, 0, sizeof(frost_flash_storage_t));  

    LOG_INF("Preparing flash data structure...");

    // Fill keypair data from received_data
    if (received_data.has_secret_share) {
        flash_data.keypair_index = received_data.secret_share.receiver_index;
        memcpy(flash_data.keypair_secret, received_data.secret_share.value, 32);
        LOG_INF("Secret share data copied");
    }
    
    if (received_data.has_public_key) {
        flash_data.keypair_index = received_data.public_key.index;
        flash_data.keypair_max_participants = received_data.public_key.max_participants;
        memcpy(flash_data.keypair_public_key, received_data.public_key.public_key, 64);
        memcpy(flash_data.keypair_group_public_key, received_data.public_key.group_public_key, 64);
        LOG_INF("Public key data copied");
    }

    // Fill commitments data
    if (received_data.has_commitments) {
        flash_data.commitments_index = received_data.commitment_index;
        flash_data.commitments_num_coefficients = received_data.num_coefficients;
        memcpy(flash_data.commitments_zkp_z, received_data.zkp_z, 32);
        memcpy(flash_data.commitments_zkp_r, received_data.zkp_r, 64);
        
        size_t copy_size = received_data.coefficient_commitments_size;
        if (copy_size > sizeof(flash_data.commitments_coefficient_data)) {
            copy_size = sizeof(flash_data.commitments_coefficient_data);
        }
        memcpy(flash_data.commitments_coefficient_data, received_data.coefficient_commitments, copy_size);
        flash_data.commitments_coefficient_data_size = copy_size;
        LOG_INF("Commitments data copied (size: %zu)", copy_size);
    }

    // Get flash device details
    const struct device *flash_dev = flash_area_get_device(fa);
    if (!flash_dev || !device_is_ready(flash_dev)) {
        LOG_ERR("Flash device not ready");
        flash_area_close(fa);
        return -ENODEV;
    }

    // Get erase block size
    struct flash_pages_info info;
    rc = flash_get_page_info_by_offs(flash_dev, fa->fa_off, &info);
    if (rc != 0) {
        LOG_ERR("Failed to get flash page info (%d)", rc);
        flash_area_close(fa);
        return rc;
    }

    LOG_INF("Flash info: offset=0x%lx, size=%zu, page_size=%zu", 
            (unsigned long)fa->fa_off, fa->fa_size, info.size);

    // Validate flash area size
    if (fa->fa_size < sizeof(frost_flash_storage_t)) {
        LOG_ERR("Flash area too small: %zu < %zu", fa->fa_size, sizeof(frost_flash_storage_t));
        flash_area_close(fa);
        return -ENOSPC;
    }

    // Calculate erase size
    size_t erase_size = ROUND_UP(sizeof(frost_flash_storage_t), info.size);
    if (erase_size > fa->fa_size) {
        erase_size = fa->fa_size;
    }

    LOG_INF("Erasing %zu bytes from flash", erase_size);

    // Erase flash sector
    rc = flash_area_erase(fa, 0, erase_size);
    if (rc != 0) {
        LOG_ERR("Failed to erase flash (%d)", rc);
        flash_area_close(fa);
        return rc;
    }

    LOG_INF("Flash erased successfully");

    // Get write alignment requirements
    size_t write_block_size = flash_get_write_block_size(flash_dev);
    size_t padded_size = ROUND_UP(sizeof(frost_flash_storage_t), write_block_size);
    
    LOG_INF("Writing %zu bytes to flash (padded to %zu, write_block=%zu)", 
            sizeof(frost_flash_storage_t), padded_size, write_block_size);

    // Use static buffer with proper alignment
    if (padded_size > 1024) {  
        LOG_ERR("Padded size too large: %zu", padded_size);
        flash_area_close(fa);
        return -ENOMEM;
    }
    
    static __aligned(8) uint8_t padded_buf[1024];  
    memset(padded_buf, 0xFF, padded_size);
    memcpy(padded_buf, &flash_data, sizeof(frost_flash_storage_t));

    LOG_INF("Writing to flash...");

    // Write to flash
    rc = flash_area_write(fa, 0, padded_buf, padded_size);
    if (rc != 0) {
        LOG_ERR("Failed to write to flash (%d)", rc);
        flash_area_close(fa);
        return rc;
    }

    LOG_INF("Flash write successful, verifying...");

    // Verify write
    static __aligned(8) frost_flash_storage_t verify_data;  
    rc = flash_area_read(fa, 0, &verify_data, sizeof(frost_flash_storage_t));
    if (rc != 0) {
        LOG_ERR("Failed to verify flash read (%d)", rc);
        flash_area_close(fa);
        return rc;
    }
    
    if (memcmp(&flash_data, &verify_data, sizeof(frost_flash_storage_t)) != 0) {
        LOG_ERR("Flash verification failed!");
        flash_area_close(fa);
        return -EIO;
    }

    flash_area_close(fa);
    
    LOG_INF("FROST key material written and verified successfully");
    return 0;
}

// Function to read and log FROST key material from flash
static int read_frost_data_from_flash(void) {
    LOG_INF("Reading flash data for verification...");
    
    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc < 0) {
        LOG_ERR("Failed to open flash area (%d)", rc);
        return rc;
    }

    if (!fa) {
        LOG_ERR("Flash area is NULL");
        return -EINVAL;
    }

    // Validate flash area size
    if (fa->fa_size < sizeof(frost_flash_storage_t)) {
        LOG_ERR("Flash area too small for data structure");
        flash_area_close(fa);
        return -ENOSPC;
    }

    // Read back stored data
    static __aligned(8) frost_flash_storage_t flash_data;  
    rc = flash_area_read(fa, 0, &flash_data, sizeof(frost_flash_storage_t));
    if (rc != 0) {
        LOG_ERR("Failed to read flash: %d", rc);
        flash_area_close(fa);
        return rc;
    }

    // Log keypair information
    LOG_INF("=== Stored Keypair ===");
    LOG_INF("Participant Index: %u", flash_data.keypair_index);
    LOG_INF("Max Participants: %u", flash_data.keypair_max_participants);
    
    // Log hex data with static buffer
    static char hex_buf[129];  
    
    // Log secret share
    for (size_t i = 0; i < 32; i++) {
        sprintf(&hex_buf[i * 2], "%02x", flash_data.keypair_secret[i]);
    }
    hex_buf[64] = '\0';
    LOG_INF("Secret Share (32 bytes): %s", hex_buf);

    // Log public key
    for (size_t i = 0; i < 64; i++) {
        sprintf(&hex_buf[i * 2], "%02x", flash_data.keypair_public_key[i]);
    }
    hex_buf[128] = '\0';
    LOG_INF("Public Key (64 bytes): %s", hex_buf);

    // Log group public key
    for (size_t i = 0; i < 64; i++) {
        sprintf(&hex_buf[i * 2], "%02x", flash_data.keypair_group_public_key[i]);
    }
    hex_buf[128] = '\0';
    LOG_INF("Group Public Key (64 bytes): %s", hex_buf);

    flash_area_close(fa);
    
    LOG_INF("Flash read completed successfully");
    return 0;
}

static void perform_safe_shutdown(void)
{
    LOG_INF("=== MISSION ACCOMPLISHED ===");
    LOG_INF("FROST key for participant %u stored successfully", received_data.participant_id);
    LOG_INF("Device can be safely disconnected from USB.");
    
    received_data.system_shutting_down = true;
    received_data.operation_complete = true;
    
    // Stop all timers to prevent further activity
    k_timer_stop(&event_timer);
    k_timer_stop(&receive_timeout_timer);
    k_timer_stop(&shutdown_timer);
    
    // Give time for logs to flush
    k_sleep(K_MSEC(500));
    
    LOG_INF("SUCCESS: Operation complete - system ready for disconnect");
    
}

// Cleanup work handler
static void cleanup_work_handler(struct k_work *work)
{
    perform_safe_shutdown();
}

// Flash work handler
static void flash_work_handler(struct k_work *work)
{
    LOG_INF("Starting flash write operation...");
    
    // Check that we have all required data
    if (!received_data.has_secret_share || !received_data.has_public_key || !received_data.has_commitments) {
        LOG_ERR("Missing required data for flash write");
        return;
    }
    
    // Write data to flash
    int rc = write_frost_data_to_flash();
    
    if (rc == 0) {
        LOG_INF("Data successfully stored to flash");
        
        // Small delay before reading back
        k_sleep(K_MSEC(100));
        
        // Read back and verify the data
        rc = read_frost_data_from_flash();
        if (rc == 0) {
            LOG_INF("Flash operation completed successfully");
            
            // Mark flash operation as complete
            received_data.flash_write_pending = false;
            
            // Schedule cleanup
            k_work_submit(&cleanup_work);
            
        } else {
            LOG_ERR("Failed to read back flash data");
        }
    } else {
        LOG_ERR("Failed to store data to flash (error: %d)", rc);
    }
    
    // Exit cleanly from work handler
    LOG_INF("Flash work handler exiting cleanly");
}

// Shutdown timer handler
static void shutdown_timer_handler(struct k_timer *timer)
{
    // Submit cleanup work
    k_work_submit(&cleanup_work);
}

// Function to process a complete message
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
    
    if (header->payload_len > (len - sizeof(struct message_header))) {
        LOG_ERR("Invalid payload length: %u > %zu", header->payload_len, 
                len - sizeof(struct message_header));
        return;
    }
    
    const uint8_t *payload = data + sizeof(struct message_header);
    size_t payload_len = header->payload_len;
    
    LOG_INF("Message: type=0x%02x, participant=%u, payload=%zu",
            header->msg_type, header->participant, payload_len);
    
    received_data.participant_id = header->participant;
    
    switch (header->msg_type) {
        case MSG_TYPE_SECRET_SHARE:
            if (payload_len >= sizeof(struct serialized_share)) {
                const struct serialized_share *share = (const struct serialized_share *)payload;
                received_data.secret_share.receiver_index = share->receiver_index;
                memcpy(received_data.secret_share.value, share->value, 32);
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
                memcpy(received_data.public_key.public_key, pubkey->public_key, 64);
                memcpy(received_data.public_key.group_public_key, pubkey->group_public_key, 64);
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
                
                memcpy(&received_data.commitment_index, ptr, sizeof(uint32_t));
                ptr += sizeof(uint32_t);
                memcpy(&received_data.num_coefficients, ptr, sizeof(uint32_t));
                ptr += sizeof(uint32_t);
                
                memcpy(received_data.zkp_z, ptr, 32);
                ptr += 32;
                
                memcpy(received_data.zkp_r, ptr, 64);
                ptr += 64;
                
                // Copy remaining coefficient data safely
                size_t coef_size = payload_len - (8 + 32 + 64);
                if (coef_size <= sizeof(received_data.coefficient_commitments)) {
                    memcpy(received_data.coefficient_commitments, ptr, coef_size);
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
                
                // Schedule flash write
                if (!received_data.flash_write_pending) {
                    received_data.flash_write_pending = true;
                    k_work_submit(&flash_work);
                }
            } else {
                LOG_WRN("INCOMPLETE data received");
                // Still trigger cleanup after delay
                k_timer_start(&shutdown_timer, K_SECONDS(2), K_NO_WAIT);
            }
            break;
            
        default:
            LOG_WRN("Unknown message type: 0x%02x", header->msg_type);
            
            // Auto-trigger completion check if we have received the main data
            if (!received_data.transmission_complete && 
                received_data.has_secret_share && 
                received_data.has_public_key && 
                received_data.has_commitments) {
                
                LOG_INF("Auto-triggering completion (all data received, assuming END_TRANSMISSION lost)");
                received_data.transmission_complete = true;
                
                LOG_INF("=== FROST Summary (Auto-completed) ===");
                LOG_INF("Participant: %u", received_data.participant_id);
                LOG_INF("Secret: OK");
                LOG_INF("Public: OK");
                LOG_INF("Commits: OK");
                LOG_INF("SUCCESS: All data received!");
                
                // Schedule flash write
                if (!received_data.flash_write_pending) {
                    received_data.flash_write_pending = true;
                    k_work_submit(&flash_work);
                }
            }
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

// Chunked data handler
static void handle_chunked_data(const uint8_t *data, size_t len)
{
    // Don't process data if system is shutting down
    if (received_data.system_shutting_down) {
        return;
    }
    
    if (!data || len < 3) {  
        LOG_WRN("Invalid chunk: too small (%zu bytes)", len);
        return;
    }
    
    if (k_mutex_lock(&buffer_mutex, K_MSEC(100)) != 0) {
        LOG_ERR("Mutex lock failed");
        return;
    }
    
    // Extract chunk info
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
    
    LOG_DBG("CHUNK: %u bytes, reassembly=%d, pos=%zu/%zu", 
            chunk_len, reassembling_message, reassembly_pos, expected_total_size);
    
    // Check if this is the start of a new message
    if (!reassembling_message && chunk_len >= sizeof(struct message_header)) {
        const struct message_header *header = (const struct message_header *)chunk_data;
        if (header->magic == MSG_HEADER_MAGIC && header->version == MSG_VERSION) {
            // This is a new message start
            expected_total_size = sizeof(struct message_header) + header->payload_len;
            
            // Validate expected size
            if (expected_total_size > REASSEMBLY_BUFFER_SIZE) {
                LOG_ERR("Message too large: %zu > %d", expected_total_size, REASSEMBLY_BUFFER_SIZE);
                k_mutex_unlock(&buffer_mutex);
                return;
            }
            
            if (expected_total_size < sizeof(struct message_header)) {
                LOG_ERR("Message too small: %zu < %zu", expected_total_size, sizeof(struct message_header));
                k_mutex_unlock(&buffer_mutex);
                return;
            }
            
            reassembling_message = true;
            reassembly_pos = 0;
            memset(reassembly_buffer, 0, sizeof(reassembly_buffer));
            
            LOG_INF("NEW MESSAGE START: type=0x%02x, total=%zu bytes expected", 
                    header->msg_type, expected_total_size);
            
            // Start timeout timer
            k_timer_start(&receive_timeout_timer, K_SECONDS(30), K_NO_WAIT);
        } else {
            LOG_WRN("Not a message start (magic=0x%08x, version=%d)", header->magic, header->version);
            k_mutex_unlock(&buffer_mutex);
            return;
        }
    }
    
    // Add chunk to reassembly buffer if we're reassembling
    if (reassembling_message) {
        size_t space_available = REASSEMBLY_BUFFER_SIZE - reassembly_pos;
        size_t remaining = expected_total_size - reassembly_pos;
        size_t bytes_to_copy = MIN(chunk_len, MIN(space_available, remaining));
        
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
            }
        } else {
            LOG_ERR("Buffer overflow protection activated");
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

    // Don't send reports if system is shutting down
    if (received_data.system_shutting_down) {
        return;
    }

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
    
    // Don't process data if system is shutting down
    if (received_data.system_shutting_down) {
        return;
    }
    
    ret = hid_int_ep_read(dev, buffer, sizeof(buffer), &received);
    if (ret == 0 && received > 0) {
        // Reset timeout on successful data reception
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
    // Don't process data if system is shutting down
    if (received_data.system_shutting_down) {
        return 0;
    }
    
    if (*len > 0 && *data) {
        // Reset timeout on successful data reception
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
    if (!received_data.system_shutting_down) {
        k_work_submit(&report_send);
    }
}

static void report_event_handler(struct k_timer *dummy)
{
    if (!received_data.transmission_complete && !received_data.system_shutting_down) {
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

// Function to reset all data 
static void reset_all_data(void)
{
    if (k_mutex_lock(&buffer_mutex, K_MSEC(100)) == 0) {
        // Reset reassembly state
        reset_reassembly_state();
        
        // Reset received data
        memset(&received_data, 0, sizeof(received_data));
        
        // Stop all timers
        k_timer_stop(&receive_timeout_timer);
        k_timer_stop(&shutdown_timer);
        
        // Reset report value
        report_1.value = 0;
        
        k_mutex_unlock(&buffer_mutex);
        LOG_INF("All data structures reset");
    }
}

static void status_cb(enum usb_dc_status_code status, const uint8_t *param)
{
    switch (status) {
    case USB_DC_RESET:
        configured = false;
        LOG_INF("USB Reset");
        reset_all_data();
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

    LOG_INF("=== FROST HID Key Receiver Starting ===");
    
    // Initialize data structure
    memset(&received_data, 0, sizeof(received_data));
    memset(reassembly_buffer, 0, sizeof(reassembly_buffer));
    
    // Initialize work queues
    k_work_init(&flash_work, flash_work_handler);
    k_work_init(&cleanup_work, cleanup_work_handler);

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

    LOG_INF("=== FROST HID Receiver Ready ===");
    LOG_INF("Reassembly buffer size: %d bytes", REASSEMBLY_BUFFER_SIZE);
    
    // Safe main loop that waits for completion
    while (!received_data.operation_complete) {
        k_sleep(K_SECONDS(1));
        
        // Periodic status check
        if (received_data.operation_complete) {
            LOG_INF("Operation completed - exiting main loop");
            break;
        }
    }
    
    LOG_INF("Main thread exiting cleanly");
    return 0;
}