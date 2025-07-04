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

#define STORAGE_PARTITION storage_partition

// HID communication constants
#define REPORT_ID_INPUT  0x01
#define REPORT_ID_OUTPUT 0x02
#define HID_EP_BUSY_FLAG 0
#define MY_HID_REPORT_SIZE  64    // USB HID report size
#define CHUNK_SIZE       61       // Data per chunk (64 - 1 report_id - 1 length - 1 data)
#define CHUNK_DELAY_MS   50       // Delay between chunks

// Protocol constants
#define MSG_HEADER_MAGIC 0x46524F53
#define MSG_VERSION      0x01

// Message types for FROST HID protocol
typedef enum {
    MSG_TYPE_NONCE_COMMITMENT  = 0x04,
    MSG_TYPE_END_TRANSMISSION  = 0xFF,
    MSG_TYPE_READY             = 0x06,
    MSG_TYPE_SIGN              = 0x07,
    MSG_TYPE_SIGNATURE_SHARE   = 0x08
} message_type_t;

// Message header structure
typedef struct {
    uint32_t magic;        
    uint8_t version;       
    uint8_t msg_type;      
    uint16_t payload_len;  
    uint32_t participant;  
} __packed message_header_t;

// Serialized data structures for HID communication
typedef struct {
    uint32_t index;
    uint8_t hiding[64];
    uint8_t binding[64];
} __packed serialized_nonce_commitment_t;

typedef struct {
    uint32_t index;
    uint8_t response[32];
} __packed serialized_signature_share_t;

typedef struct {
    uint32_t index;
    uint32_t max_participants;
    uint8_t secret[32];
    uint8_t public_key[64];
    uint8_t group_public_key[64];
} __packed serialized_keypair_t;

// Extended flash storage
typedef struct {
    // Keypair data
    uint32_t keypair_index;
    uint32_t keypair_max_participants;
    uint8_t keypair_secret[32];
    uint8_t keypair_public_key[64];
    uint8_t keypair_group_public_key[64];
    
    // Nonce persistence data
    uint32_t nonce_session_id;
    uint8_t nonce_hiding_secret[32];
    uint8_t nonce_binding_secret[32];
    uint8_t nonce_hiding_commitment[64];
    uint8_t nonce_binding_commitment[64];
    uint8_t nonce_used;     // Replay protection flag
    uint8_t nonce_valid;    // Validity flag
    uint8_t reserved[2];
} __packed extended_frost_storage_t;

// Global state variables
static bool configured = false;
static const struct device *hdev;
static ATOMIC_DEFINE(hid_ep_in_busy, 1);

// Work queues for asynchronous protocol handling
static struct k_work sign_work;
static struct k_work send_share_work;
static struct k_work report_send;

static extended_frost_storage_t flash_data;
static bool flash_data_valid = false;
static uint8_t chunk_buffer[MY_HID_REPORT_SIZE];
static secp256k1_context *secp256k1_ctx;
static secp256k1_frost_keypair keypair;

static secp256k1_frost_signature_share computed_signature_share;
static bool signature_share_computed = false;

static uint32_t current_session_id = 0;

// Message reassembly for chunked HID data
#define REASSEMBLY_BUFFER_SIZE 2048
static uint8_t receive_buffer[REASSEMBLY_BUFFER_SIZE];
static size_t receive_buffer_pos = 0;
static size_t expected_total_size = 0;
static bool reassembling_message = false;

K_MUTEX_DEFINE(buffer_mutex);

// HID report structure
static struct report {
	uint8_t id;
	uint8_t value;
} __packed report_1 = {
	.id = REPORT_ID_INPUT,
	.value = 0,
};

// Timers for HID reports and timeout handling
static void report_event_handler(struct k_timer *dummy);
K_TIMER_DEFINE(event_timer, report_event_handler, NULL);
#define REPORT_PERIOD K_SECONDS(2)

static void receive_timeout_handler(struct k_timer *timer);
K_TIMER_DEFINE(receive_timeout_timer, receive_timeout_handler, NULL);

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
	HID_REPORT_COUNT(63),
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_INPUT(0x02),
	
	// Output report (host to device)
	HID_REPORT_ID(REPORT_ID_OUTPUT),
	HID_LOGICAL_MIN8(0x00),
	HID_LOGICAL_MAX16(0xFF, 0x00),
	HID_REPORT_SIZE(8),
	HID_REPORT_COUNT(63),
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_OUTPUT(0x02),
	
	HID_END_COLLECTION,
};

// Helper function to log hex data
static void log_hex(const char *label, const uint8_t *data, size_t len) {
    char hexstr[129];
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

// Reset message reassembly state
static void reset_reassembly_state(void)
{
    reassembling_message = false;
    receive_buffer_pos = 0;
    expected_total_size = 0;
    k_timer_stop(&receive_timeout_timer);
    LOG_INF("Reassembly state reset");
}

// Read extended data from flash
static int read_extended_flash_data(void) {
    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc < 0) {
        LOG_ERR("Failed to open flash area (%d)", rc);
        return rc;
    }

    if (fa->fa_size < sizeof(extended_frost_storage_t)) {
        LOG_ERR("Flash area too small (%zu < %zu)", fa->fa_size, sizeof(extended_frost_storage_t));
        flash_area_close(fa);
        return -ENOSPC;
    }

    rc = flash_area_read(fa, 0, &flash_data, sizeof(extended_frost_storage_t));
    flash_area_close(fa);
    
    if (rc != 0) {
        LOG_ERR("Failed to read flash: %d", rc);
        return rc;
    }

    if (flash_data.keypair_index == 0 || flash_data.keypair_index > 255) {
        LOG_WRN("Invalid keypair data (index=%u)", flash_data.keypair_index);
        return -EINVAL;
    }

    flash_data_valid = true;
    LOG_INF("Extended flash data loaded - Participant: %u", flash_data.keypair_index);
    
    if (flash_data.nonce_valid) {
        LOG_INF("Stored nonce found - Session ID: %u, Used: %s", 
                flash_data.nonce_session_id, 
                flash_data.nonce_used ? "YES" : "NO");
    } else {
        LOG_INF("No valid stored nonce found");
    }
    
    return 0;
}

// Write extended data to flash
static int write_extended_flash_data(void) {
    if (!flash_data_valid) {
        LOG_ERR("Cannot write invalid flash data");
        return -EINVAL;
    }

    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc < 0) {
        LOG_ERR("Failed to open flash area for write (%d)", rc);
        return rc;
    }

    rc = flash_area_erase(fa, 0, sizeof(extended_frost_storage_t));
    if (rc != 0) {
        LOG_ERR("Failed to erase flash: %d", rc);
        flash_area_close(fa);
        return rc;
    }

    rc = flash_area_write(fa, 0, &flash_data, sizeof(extended_frost_storage_t));
    if (rc != 0) {
        LOG_ERR("Failed to write flash: %d", rc);
        flash_area_close(fa);
        return rc;
    }

    flash_area_close(fa);
    LOG_INF("Extended flash data written successfully");
    return 0;
}

// Save nonce to flash
static int save_nonce_to_flash(const secp256k1_frost_nonce *nonce, uint32_t session_id) {
    if (!nonce || !flash_data_valid) {
        LOG_ERR("Cannot save nonce - invalid parameters");
        return -EINVAL;
    }

    LOG_INF("=== SAVING NONCE TO FLASH ===");
    
    flash_data.nonce_session_id = session_id;
    memcpy(flash_data.nonce_hiding_secret, nonce->hiding, 32);
    memcpy(flash_data.nonce_binding_secret, nonce->binding, 32);
    memcpy(flash_data.nonce_hiding_commitment, nonce->commitments.hiding, 64);
    memcpy(flash_data.nonce_binding_commitment, nonce->commitments.binding, 64);
    flash_data.nonce_used = 0;  // Mark as unused
    flash_data.nonce_valid = 1; // Mark as valid
    
    int rc = write_extended_flash_data();
    if (rc != 0) {
        LOG_ERR("Failed to save nonce to flash: %d", rc);
        return rc;
    }
    
    LOG_INF("Nonce persisted to flash - safe for device restart");
    LOG_INF("Session ID: %u", session_id);
    log_hex("Hiding secret saved", flash_data.nonce_hiding_secret, 8);
    log_hex("Binding secret saved", flash_data.nonce_binding_secret, 8);
    log_hex("Hiding commitment saved", flash_data.nonce_hiding_commitment, 16);
    log_hex("Binding commitment saved", flash_data.nonce_binding_commitment, 16);
    
    return 0;
}

// Load original nonce from flash
static secp256k1_frost_nonce* load_original_nonce_from_flash(uint32_t expected_session_id) {
    if (!flash_data_valid) {
        LOG_ERR("Cannot load nonce - flash data invalid");
        return NULL;
    }
    
    if (!flash_data.nonce_valid) {
        LOG_ERR("No valid nonce stored in flash");
        return NULL;
    }
    
    if (flash_data.nonce_session_id != expected_session_id) {
        LOG_WRN("Session ID mismatch - stored: %u, expected: %u", 
                flash_data.nonce_session_id, expected_session_id);
    }
    
    if (flash_data.nonce_used) {
        LOG_ERR("Stored nonce already used - replay protection activated");
        return NULL;
    }
    
    LOG_INF("=== LOADING ORIGINAL NONCE FROM FLASH ===");
    
    secp256k1_frost_nonce* restored_nonce = 
        (secp256k1_frost_nonce*)malloc(sizeof(secp256k1_frost_nonce));
    
    if (!restored_nonce) {
        LOG_ERR("Failed to allocate memory for restored nonce");
        return NULL;
    }
    
    // Restore nonce from flash data
    memcpy(restored_nonce->hiding, flash_data.nonce_hiding_secret, 32);
    memcpy(restored_nonce->binding, flash_data.nonce_binding_secret, 32);
    restored_nonce->commitments.index = keypair.public_keys.index;
    memcpy(restored_nonce->commitments.hiding, flash_data.nonce_hiding_commitment, 64);
    memcpy(restored_nonce->commitments.binding, flash_data.nonce_binding_commitment, 64);
    restored_nonce->used = 0;
    
    LOG_INF("Original nonce restored from flash");
    LOG_INF("Session ID: %u", flash_data.nonce_session_id);
    log_hex("Hiding secret restored", restored_nonce->hiding, 8);
    log_hex("Binding secret restored", restored_nonce->binding, 8);
    log_hex("Hiding commitment", restored_nonce->commitments.hiding, 16);
    log_hex("Binding commitment", restored_nonce->commitments.binding, 16);
    
    return restored_nonce;
}

// Mark nonce as used for replay protection
static int mark_nonce_as_used(void) {
    if (!flash_data_valid || !flash_data.nonce_valid) {
        LOG_ERR("Cannot mark nonce as used - invalid flash data");
        return -EINVAL;
    }
    
    LOG_INF("=== MARKING NONCE AS USED ===");
    
    flash_data.nonce_used = 1;
    
    int rc = write_extended_flash_data();
    if (rc != 0) {
        LOG_ERR("Failed to mark nonce as used: %d", rc);
        return rc;
    }
    
    LOG_INF("Nonce marked as used - replay protection activated");
    return 0;
}

// Verify that coordinator's commitment matches our stored commitment
static bool verify_commitment_consistency(const serialized_nonce_commitment_t* coordinator_commitment) {
    if (!flash_data_valid || !flash_data.nonce_valid) {
        LOG_ERR("Cannot verify commitment - no stored nonce");
        return false;
    }
    
    LOG_INF("=== VERIFYING COMMITMENT CONSISTENCY ===");
    
    bool hiding_match = (memcmp(coordinator_commitment->hiding, 
                                flash_data.nonce_hiding_commitment, 64) == 0);
    bool binding_match = (memcmp(coordinator_commitment->binding, 
                                 flash_data.nonce_binding_commitment, 64) == 0);
    
    LOG_INF("Commitment verification:");
    LOG_INF("  Index match: %s (%u vs %u)", 
            (coordinator_commitment->index == keypair.public_keys.index) ? "YES" : "NO",
            coordinator_commitment->index, keypair.public_keys.index);
    LOG_INF("  Hiding match: %s", hiding_match ? "YES" : "NO");
    LOG_INF("  Binding match: %s", binding_match ? "YES" : "NO");
    
    if (!hiding_match) {
        LOG_ERR("Hiding commitment mismatch!");
        log_hex("Expected (stored)", flash_data.nonce_hiding_commitment, 16);
        log_hex("Received (coordinator)", coordinator_commitment->hiding, 16);
    }
    
    if (!binding_match) {
        LOG_ERR("Binding commitment mismatch!");
        log_hex("Expected (stored)", flash_data.nonce_binding_commitment, 16);
        log_hex("Received (coordinator)", coordinator_commitment->binding, 16);
    }
    
    bool all_match = hiding_match && binding_match && 
                     (coordinator_commitment->index == keypair.public_keys.index);
    
    if (all_match) {
        LOG_INF("Commitment verification passed - coordinator has correct data");
    } else {
        LOG_ERR("Commitment verification failed - data inconsistency detected");
    }
    
    return all_match;
}

// Load FROST keypair from flash data
static int load_frost_key_material(void) {
    if (!flash_data_valid) return -1;
    
    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    keypair.public_keys.index = flash_data.keypair_index;
    keypair.public_keys.max_participants = flash_data.keypair_max_participants;
    memcpy(keypair.secret, flash_data.keypair_secret, 32);
    memcpy(keypair.public_keys.public_key, flash_data.keypair_public_key, 64);
    memcpy(keypair.public_keys.group_public_key, 
           flash_data.keypair_group_public_key, 64);
    
    LOG_INF("FROST key material loaded successfully");
    return 0;
}

// Verify loaded keypair is valid
static void verify_keypair_consistency(void) {
    LOG_INF("=== KEYPAIR CONSISTENCY VERIFICATION ===");
    
    if (keypair.public_keys.index == 0 || keypair.public_keys.index > 255) {
        LOG_ERR("Invalid participant index: %u", keypair.public_keys.index);
        return;
    }
    
    // Check secret key is not all zeros
    bool secret_zeros = true;
    for (int i = 0; i < 32; i++) {
        if (keypair.secret[i] != 0) {
            secret_zeros = false;
            break;
        }
    }
    
    if (secret_zeros) {
        LOG_ERR("Secret key is all zeros!");
        return;
    }
    
    // Check public keys are not all zeros
    bool pub_zeros = true, group_zeros = true;
    for (int i = 0; i < 64; i++) {
        if (keypair.public_keys.public_key[i] != 0) pub_zeros = false;
        if (keypair.public_keys.group_public_key[i] != 0) group_zeros = false;
    }
    
    if (pub_zeros || group_zeros) {
        LOG_ERR("Public keys contain all zeros!");
        return;
    }
    
    LOG_INF("Keypair consistency verified");
    LOG_INF("  Index: %u", keypair.public_keys.index);
    LOG_INF("  Max participants: %u", keypair.public_keys.max_participants);
    log_hex("  Secret (first 8 bytes)", keypair.secret, 8);
    log_hex("  Public key (first 8 bytes)", keypair.public_keys.public_key, 8);
    log_hex("  Group key (first 8 bytes)", keypair.public_keys.group_public_key, 8);
}

// Send data via chunked HID reports 
static int send_chunked_data(const uint8_t *data, size_t len) {
    if (!configured || !data || len == 0) {
        return -EINVAL;
    }

    size_t offset = 0;
    int chunk_count = 0;
    
    while (offset < len) {
        // Wait for HID endpoint to be ready
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
        
        // Send chunk via HID
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

// Send protocol message via chunked HID
static int send_message(uint8_t msg_type, uint32_t participant, 
                       const void* payload, uint16_t payload_len) {
    message_header_t header = {
        .magic = MSG_HEADER_MAGIC,
        .version = MSG_VERSION,
        .msg_type = msg_type,
        .payload_len = payload_len,
        .participant = participant
    };
    
    // Combine header and payload into single buffer
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

// PHASE 1: Generate fresh nonce and save to flash
static int generate_and_save_nonce_PHASE1(void) {
    LOG_INF("=== PHASE 1: GENERATE AND PERSIST NONCE ===");
    
    if (!flash_data_valid) {
        LOG_ERR("Flash data not valid, cannot proceed");
        return -1;
    }
    
    current_session_id = sys_rand32_get();
    
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    
    if (!fill_random(binding_seed, sizeof(binding_seed))) {
        LOG_ERR("Failed to generate binding_seed");
        return -1;
    }
    if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
        LOG_ERR("Failed to generate hiding_seed");
        return -1;
    }

    LOG_INF("Generating fresh nonce for participant %u", keypair.public_keys.index);
    LOG_INF("Session ID: %u", current_session_id);
    log_hex("Binding seed", binding_seed, 8);
    log_hex("Hiding seed", hiding_seed, 8);
    
    secp256k1_frost_nonce* fresh_nonce = secp256k1_frost_nonce_create(
        secp256k1_ctx, &keypair, binding_seed, hiding_seed);
    
    if (!fresh_nonce) {
        LOG_ERR("Failed to create fresh nonce");
        return -1;
    }
    
    LOG_INF("Fresh nonce generated successfully");
    log_hex("Generated hiding commitment", fresh_nonce->commitments.hiding, 16);
    log_hex("Generated binding commitment", fresh_nonce->commitments.binding, 16);
    
    // Save nonce to flash for persistence
    int save_result = save_nonce_to_flash(fresh_nonce, current_session_id);
    if (save_result != 0) {
        LOG_ERR("Failed to save nonce to flash!");
        secp256k1_frost_nonce_destroy(fresh_nonce);
        return -1;
    }
    
    secp256k1_frost_nonce_destroy(fresh_nonce);
    
    LOG_INF("PHASE 1 NONCE GENERATION AND PERSISTENCE COMPLETE");
    LOG_INF("Device can safely restart - nonce is preserved in flash");
    
    return 0;
}

// PHASE 1: Send nonce commitment and keypair data
static int send_nonce_commitment_and_keypair_PHASE1(void) {
    LOG_INF("=== PHASE 1: SENDING NONCE COMMITMENT AND KEYPAIR ===");
    
    if (!flash_data_valid || !flash_data.nonce_valid) {
        LOG_ERR("No valid nonce data available");
        return -1;
    }
    
    // Prepare combined payload with nonce commitment + keypair
    size_t payload_len = sizeof(serialized_nonce_commitment_t) + sizeof(serialized_keypair_t);
    uint8_t* combined_payload = malloc(payload_len);
    if (!combined_payload) {
        LOG_ERR("Failed to allocate memory for combined payload");
        return -ENOMEM;
    }

    // Fill nonce commitment data
    serialized_nonce_commitment_t* nonce_part = (serialized_nonce_commitment_t*)combined_payload;
    nonce_part->index = keypair.public_keys.index;
    memcpy(nonce_part->hiding, flash_data.nonce_hiding_commitment, 64);
    memcpy(nonce_part->binding, flash_data.nonce_binding_commitment, 64);

    // Fill keypair data
    serialized_keypair_t* keypair_part = (serialized_keypair_t*)(combined_payload + sizeof(serialized_nonce_commitment_t));
    keypair_part->index = keypair.public_keys.index;
    keypair_part->max_participants = keypair.public_keys.max_participants;
    memcpy(keypair_part->secret, keypair.secret, 32);
    memcpy(keypair_part->public_key, keypair.public_keys.public_key, 64);
    memcpy(keypair_part->group_public_key, keypair.public_keys.group_public_key, 64);

    LOG_INF("*** SENDING PERSISTED NONCE COMMITMENT AND KEYPAIR ***");
    LOG_INF("Participant: %u", keypair.public_keys.index);
    LOG_INF("Session ID: %u", flash_data.nonce_session_id);
    log_hex("Sending hiding commitment", nonce_part->hiding, 16);
    log_hex("Sending binding commitment", nonce_part->binding, 16);
    
    int ret = send_message(MSG_TYPE_NONCE_COMMITMENT, 
                          keypair.public_keys.index,
                          combined_payload, payload_len);
    
    free(combined_payload);
    
    if (ret == 0) {
        LOG_INF("PHASE 1 SUCCESS: Persisted nonce commitment and keypair sent");
    } else {
        LOG_ERR("PHASE 1 FAILED: Failed to send nonce commitment and keypair");
    }
    
    return ret;
}

// PHASE 3: Send signature share and mark nonce as used
static int send_signature_share_and_mark_used_PHASE3(void) {
    LOG_INF("=== PHASE 3: SENDING SIGNATURE SHARE AND MARKING NONCE USED ===");
    
    if (!signature_share_computed) {
        LOG_ERR("No signature share computed yet");
        return -1;
    }

    serialized_signature_share_t serialized = {
        .index = keypair.public_keys.index
    };
    memcpy(serialized.response, computed_signature_share.response, 32);

    LOG_INF("*** SENDING SIGNATURE SHARE TO COORDINATOR ***");
    LOG_INF("Participant: %u", keypair.public_keys.index);
    log_hex("Signature Share", serialized.response, 32);

    int ret = send_message(MSG_TYPE_SIGNATURE_SHARE, 
                          keypair.public_keys.index,
                          &serialized, sizeof(serialized));
    
    if (ret == 0) {
        LOG_INF("PHASE 3 SUCCESS: Signature share sent to coordinator");
        
        // Mark nonce as used for replay protection
        int mark_result = mark_nonce_as_used();
        if (mark_result == 0) {
            LOG_INF("Nonce marked as used - replay protection activated");
        } else {
            LOG_WRN("Failed to mark nonce as used, but signature sent");
        }
        
        send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0);
    } else {
        LOG_ERR("PHASE 3 FAILED: Failed to send signature share to coordinator");
    }
    
    return ret;
}

// PHASE 2: Process sign message using original persisted nonce
static void process_sign_message_PHASE2_FIXED(void) {
    LOG_INF("=== PHASE 2: PROCESSING SIGN MESSAGE (FIXED - ORIGINAL NONCE) ===");
    
    const message_header_t *header = (const message_header_t *)receive_buffer;
    const uint8_t* payload = receive_buffer + sizeof(message_header_t);
    
    if (header->payload_len < 32 + 4) {
        LOG_ERR("Invalid sign message length");
        return;
    }
    
    // Parse sign message payload
    uint8_t* msg_hash = (uint8_t*)payload;
    uint32_t num_commitments = *(uint32_t*)(payload + 32);
    serialized_nonce_commitment_t* serialized_commitments = (serialized_nonce_commitment_t*)(payload + 32 + 4);
    
    LOG_INF("*** PROCESSING SIGN MESSAGE DATA ***");
    LOG_INF("Message hash (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x...", 
            msg_hash[0], msg_hash[1], msg_hash[2], msg_hash[3],
            msg_hash[4], msg_hash[5], msg_hash[6], msg_hash[7]);
    LOG_INF("Number of commitments: %u", num_commitments);
    
    // Verify message hash (expecting "Hello World!" message)
    unsigned char expected_msg[12] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    unsigned char expected_hash[32];
    unsigned char tag[14] = {'f', 'r', 'o', 's', 't', '_', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};
    secp256k1_tagged_sha256(secp256k1_ctx, expected_hash, tag, sizeof(tag), expected_msg, sizeof(expected_msg));
    
    if (memcmp(msg_hash, expected_hash, 32) != 0) {
        LOG_ERR("Message hash verification FAILED!");
        return;
    }
    LOG_INF("Message hash verified correctly (Hello World!)");
    
    // Find our commitment in the coordinator's list
    serialized_nonce_commitment_t* our_commitment_from_coordinator = NULL;
    
    for (uint32_t i = 0; i < num_commitments; i++) {
        if (serialized_commitments[i].index == keypair.public_keys.index) {
            our_commitment_from_coordinator = &serialized_commitments[i];
            LOG_INF("Found our commitment at position %u", i);
            break;
        }
    }
    
    if (!our_commitment_from_coordinator) {
        LOG_ERR("Our commitment not found in coordinator's list!");
        return;
    }
    
    // Verify commitment consistency
    if (!verify_commitment_consistency(our_commitment_from_coordinator)) {
        LOG_ERR("Commitment consistency verification failed!");
        return;
    }
    
    // Load original nonce from flash
    secp256k1_frost_nonce* original_nonce = 
        load_original_nonce_from_flash(current_session_id);
    
    if (!original_nonce) {
        LOG_ERR("Failed to load original nonce from flash");
        return;
    }
    
    LOG_INF("Using ORIGINAL nonce from flash persistence");
    
    // Prepare commitments array for signing
    secp256k1_frost_nonce_commitment *signing_commitments = 
        malloc(num_commitments * sizeof(secp256k1_frost_nonce_commitment));
    if (!signing_commitments) {
        LOG_ERR("Failed to allocate memory for signing commitments");
        free(original_nonce);
        return;
    }
    
    for (uint32_t i = 0; i < num_commitments; i++) {
        signing_commitments[i].index = serialized_commitments[i].index;
        memcpy(signing_commitments[i].hiding, serialized_commitments[i].hiding, 64);
        memcpy(signing_commitments[i].binding, serialized_commitments[i].binding, 64);
        
        LOG_INF("Commitment %u: participant %u", i, signing_commitments[i].index);
    }
    
    LOG_INF("Computing signature share using ORIGINAL nonce from flash...");
    LOG_INF("Participant index: %u", keypair.public_keys.index);
    LOG_INF("Number of signers: %u", num_commitments);
    LOG_INF("Using original nonce secrets from flash persistence");
    
    memset(&computed_signature_share, 0, sizeof(computed_signature_share));
    
    // Compute signature share using original nonce
    int return_val = secp256k1_frost_sign(&computed_signature_share,
                                         msg_hash, num_commitments,
                                         &keypair, original_nonce, signing_commitments);
    
    if (return_val == 1) {
        signature_share_computed = true;
        
        LOG_INF("*** SIGNATURE SHARE COMPUTED SUCCESSFULLY ***");
        LOG_INF("Used ORIGINAL nonce from flash persistence");
        log_hex("SIGNATURE SHARE (32 bytes)", computed_signature_share.response, 32);
        
        // Validate signature share is not all zeros
        bool all_zeros = true;
        for (int i = 0; i < 32; i++) {
            if (computed_signature_share.response[i] != 0) {
                all_zeros = false;
                break;
            }
        }
        
        if (all_zeros) {
            LOG_ERR("Signature share is all zeros - this indicates an error!");
            signature_share_computed = false;
        } else {
            LOG_INF("Signature share appears valid (not all zeros)");
            
            // Pretty print signature share
            char hex_str[65];
            for (int i = 0; i < 32; i++) {
                sprintf(hex_str + i * 2, "%02x", computed_signature_share.response[i]);
            }
            hex_str[64] = '\0';
            printk("\n\n=== FROST SIGNATURE SHARE ===\n");
            printk("Participant: %u\n", keypair.public_keys.index);
            printk("Signature: %s\n", hex_str);
            printk("=============================\n\n");
            
            // Schedule signature share transmission
            k_work_submit(&send_share_work);
        }
        
    } else {
        LOG_ERR("Failed to compute signature share (return_val=%d)", return_val);
        signature_share_computed = false;
    }
    
    free(signing_commitments);
    free(original_nonce);
}

// Process complete reassembled message
static void process_received_message(void) {
    if (receive_buffer_pos < sizeof(message_header_t)) {
        return;
    }
    
    const message_header_t *header = (const message_header_t *)receive_buffer;
    
    // Validate message header
    if (header->magic != MSG_HEADER_MAGIC || header->version != MSG_VERSION) {
        LOG_WRN("Invalid message header: magic=0x%08x, version=%d", 
                header->magic, header->version);
        receive_buffer_pos = 0;
        return;
    }
    
    size_t expected_total = sizeof(message_header_t) + header->payload_len;
    if (receive_buffer_pos < expected_total) {
        return;
    }
    
    // Dispatch message to work queue for processing
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
    
    receive_buffer_pos = 0;
}

// Handle chunked data from HID reports and reassemble messages
static void handle_chunked_data(const uint8_t *data, size_t len)
{
    if (!data || len < 3) {
        LOG_WRN("Invalid chunk: too small (%zu bytes)", len);
        return;
    }
    
    if (k_mutex_lock(&buffer_mutex, K_MSEC(100)) != 0) {
        LOG_ERR("Mutex lock failed");
        return;
    }
    
    // Parse chunk
    uint8_t report_id = data[0];
    uint8_t chunk_len = data[1];
    const uint8_t *chunk_data = data + 2;
    
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
    
    // Check if this is the start of a new message
    if (!reassembling_message && chunk_len >= sizeof(message_header_t)) {
        const message_header_t *header = (const message_header_t *)chunk_data;
        if (header->magic == MSG_HEADER_MAGIC) {
            expected_total_size = sizeof(message_header_t) + header->payload_len;
            
            if (expected_total_size <= REASSEMBLY_BUFFER_SIZE) {
                reassembling_message = true;
                receive_buffer_pos = 0;
                LOG_INF("NEW MESSAGE START: type=0x%02x, total=%zu bytes expected", 
                        header->msg_type, expected_total_size);
                
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
    
    // Add chunk to reassembly buffer
    if (reassembling_message) {
        size_t space_available = REASSEMBLY_BUFFER_SIZE - receive_buffer_pos;
        size_t bytes_to_copy = (chunk_len > space_available) ? space_available : chunk_len;
        
        if (bytes_to_copy > 0) {
            memcpy(receive_buffer + receive_buffer_pos, chunk_data, bytes_to_copy);
            receive_buffer_pos += bytes_to_copy;
            
            // Check if message is complete
            if (receive_buffer_pos >= expected_total_size) {
                LOG_INF("MESSAGE COMPLETE: Processing %zu bytes", expected_total_size);
                
                k_timer_stop(&receive_timeout_timer);
                process_received_message();
                reset_reassembly_state();
            }
        } else {
            LOG_ERR("No space in reassembly buffer");
            reset_reassembly_state();
        }
    }
    
    k_mutex_unlock(&buffer_mutex);
}

// Timeout handler for stuck reassembly
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
    LOG_INF("send_share_work_handler called");
    
    if (!configured || !flash_data_valid || !signature_share_computed) {
        LOG_ERR("Device not ready for sending signature share");
        return;
    }
    
    LOG_INF("Sending signature share and marking nonce as used...");
    k_msleep(1000);
    
    if (send_signature_share_and_mark_used_PHASE3() != 0) {
        LOG_ERR("Failed to send signature share");
    }
}

// Work handler for protocol phases
static void sign_work_handler(struct k_work *work) {
    LOG_INF("sign_work_handler called");
    
    if (!configured || !flash_data_valid) {
        LOG_ERR("Device not ready for signing");
        return;
    }
    
    const message_header_t *header = (const message_header_t *)receive_buffer;
    
    switch (header->msg_type) {
        case MSG_TYPE_READY:
            LOG_INF("Processing READY message - PHASE 1");
            
            if (generate_and_save_nonce_PHASE1() == 0) {
                if (send_nonce_commitment_and_keypair_PHASE1() == 0) {
                    send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0);
                }
            }
            break;
            
        case MSG_TYPE_SIGN:
            LOG_INF("Processing SIGN message - PHASE 2 (FIXED with original nonce)");
            process_sign_message_PHASE2_FIXED();
            break;
            
        default:
            LOG_WRN("Unknown message type in work handler: 0x%02x", header->msg_type);
            break;
    }
}

// Send periodic HID reports
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

// Timer handler for periodic reports
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

// HID callback - input endpoint ready
static void int_in_ready_cb(const struct device *dev) {
    atomic_clear_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
}

// HID callback - output endpoint data received
static void int_out_ready_cb(const struct device *dev) {
    uint8_t buffer[64];
    int ret, received;
    
    ret = hid_int_ep_read(dev, buffer, sizeof(buffer), &received);
    if (ret == 0 && received > 0) {
        // Reset timeout on data reception
        k_timer_stop(&receive_timeout_timer);
        if (reassembling_message) {
            k_timer_start(&receive_timeout_timer, K_SECONDS(30), K_NO_WAIT);
        }
        
        handle_chunked_data(buffer, received);
    }
}

// HID callback - set report received
static int set_report_cb(const struct device *dev, struct usb_setup_packet *setup,
			 int32_t *len, uint8_t **data)
{
	if (*len > 0 && *data) {
		// Reset timeout on data reception
		k_timer_stop(&receive_timeout_timer);
		if (reassembling_message) {
			k_timer_start(&receive_timeout_timer, K_SECONDS(30), K_NO_WAIT);
		}
		
		handle_chunked_data(*data, *len);
	}
	return 0;
}

// HID callback - idle state
static void on_idle_cb(const struct device *dev, uint16_t report_id)
{
	k_work_submit(&report_send);
}

// HID callback - protocol change
static void protocol_cb(const struct device *dev, uint8_t protocol) {
    LOG_INF("Protocol: %s", protocol == HID_PROTOCOL_BOOT ? "boot" : "report");
}

// HID operations structure
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
    LOG_INF("=== FROST HID Device with NONCE PERSISTENCE ===");
    LOG_INF("Nonces survive device restarts via flash storage");
    
    // Initialize secp256k1 context
    secp256k1_ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (secp256k1_ctx == NULL) {
        LOG_ERR("Failed to create secp256k1 context");
        return -1;
    }
    LOG_INF("secp256k1 context created successfully");
    
    // Initialize work queues for asynchronous processing
    k_work_init(&sign_work, sign_work_handler);
    k_work_init(&send_share_work, send_share_work_handler);
    k_work_init(&report_send, send_report);
    LOG_INF("Work queues initialized");
    
    // Load persistent data from flash
    if (read_extended_flash_data() != 0) {
        LOG_ERR("Failed to read extended flash data");
        return -1;
    }
    
    // Load FROST keypair
    if (load_frost_key_material() != 0) {
        LOG_ERR("Failed to load key material");
        return -1;
    }
    
    verify_keypair_consistency();
    
    // Initialize USB HID device
    hdev = device_get_binding("HID_0");
    if (hdev == NULL) {
        LOG_ERR("Cannot get USB HID Device");
        return -1;
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
    
    LOG_INF("=== FROST HID Device Ready (NONCE PERSISTENCE) ===");
    LOG_INF("Participant %u ready for FROST protocol", keypair.public_keys.index);
    LOG_INF("Flash storage supports nonce persistence across restarts");
    LOG_INF("Replay protection activated");
    
    // Main loop
    while (1) {
        k_msleep(1000);
    }
    
    secp256k1_context_destroy(secp256k1_ctx);
    
    return 0;
}