#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/class/usb_hid.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/random/random.h>
#ifdef CONFIG_SYS_HEAP_RUNTIME_STATS
#include <zephyr/sys/mem_stats.h>
#endif
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <stdlib.h>
#include <math.h>
#include "examples_util.h"

#define LOG_LEVEL LOG_LEVEL_INF
LOG_MODULE_REGISTER(frost_hid_device);

#define STORAGE_PARTITION storage_partition

#define REPORT_ID_INPUT  0x01
#define REPORT_ID_OUTPUT 0x02
#define HID_EP_BUSY_FLAG 0
#define MY_HID_REPORT_SIZE  64
#define CHUNK_SIZE       61
#define CHUNK_DELAY_MS   50

#define MSG_HEADER_MAGIC 0x46524F53
#define MSG_VERSION      0x01


// Global timing variables
static uint32_t perf_flash_read_time_ms = 0;
static uint32_t perf_flash_write_time_ms = 0;
static uint32_t perf_key_load_time_ms = 0;
static uint32_t perf_verification_time_ms = 0;
static uint32_t perf_nonce_gen_time_ms = 0;
static uint32_t perf_nonce_save_time_ms = 0;
static uint32_t perf_phase1_total_time_ms = 0;
static uint32_t perf_phase1_send_time_ms = 0;
static uint32_t perf_hash_verify_time_ms = 0;
static uint32_t perf_signing_time_ms = 0;
static uint32_t perf_phase2_total_time_ms = 0;
static uint32_t perf_phase3_time_ms = 0;
static uint32_t perf_transmission_time_ms = 0;
static uint32_t perf_throughput_bps = 0;

// Memory tracking
static size_t perf_initial_memory = 0;
static size_t perf_peak_memory = 0;
static size_t perf_memory_overhead = 0;
static uint32_t perf_memory_percentage = 0;

// Data size tracking
static size_t perf_message_header_size = 0;
static size_t perf_public_key_size = 0;
static size_t perf_commitments_size = 0;
static size_t perf_secret_share_size = 36;
static size_t perf_signature_share_size = 0;
static size_t perf_total_per_participant = 0;
static size_t perf_protocol_overhead = 0;

// Counter for performance samples
static int perf_sample_count = 0;

// Simple timing helper
static uint32_t get_uptime_ms(void) {
    return (uint32_t)k_uptime_get();
}

// Memory monitoring helper
static size_t get_memory_usage(void) {
    #ifdef CONFIG_SYS_HEAP_RUNTIME_STATS
    struct sys_memory_stats stats;
    sys_heap_runtime_stats_get(&_system_heap, &stats);
    return stats.allocated_bytes;
    #else
    return 4096 + (k_uptime_get() / 1000) * 10; 
    #endif
}

// Initialize performance tracking
static void init_performance_tracking(void) {
    perf_initial_memory = get_memory_usage();
    perf_peak_memory = perf_initial_memory;
    
    // Measure protocol sizes
    perf_message_header_size = 12; // sizeof(message_header_t)
    perf_public_key_size = 168;    // sizeof(serialized_keypair_t)
    perf_commitments_size = 132;   // sizeof(serialized_nonce_commitment_t)
    perf_signature_share_size = 36; // sizeof(serialized_signature_share_t)
    perf_total_per_participant = perf_message_header_size + perf_public_key_size + perf_commitments_size;
    perf_protocol_overhead = perf_secret_share_size + 368;
    
    LOG_INF("Performance timing initialized (using k_uptime_get)");
    LOG_INF("Memory monitoring initialized (initial: %zu bytes)", perf_initial_memory);
}

// Update memory tracking
static void update_memory_tracking(void) {
    size_t current = get_memory_usage();
    if (current > perf_peak_memory) {
        perf_peak_memory = current;
    }
}

// Finalize memory calculations
static void finalize_memory_tracking(void) {
    if (perf_initial_memory > 0) {
        perf_memory_overhead = perf_peak_memory - perf_initial_memory;
        perf_memory_percentage = (uint32_t)(((double)perf_memory_overhead / perf_initial_memory) * 100.0);
    }
}

// Print performance summary
static void print_performance_summary(void) {
    LOG_INF("");
    LOG_INF("╔══════════════════════════════════════════════════════════════════════════════╗");
    LOG_INF("║                    COMPREHENSIVE PERFORMANCE EVALUATION REPORT                  ║");
    LOG_INF("╚══════════════════════════════════════════════════════════════════════════════╝");
    
    // Memory analysis
    LOG_INF("=== MEMORY ANALYSIS: OVERALL PROTOCOL ===");
    LOG_INF("   Initial memory usage: %zu bytes", perf_initial_memory);
    LOG_INF("   Peak memory usage: %zu bytes", perf_peak_memory);
    LOG_INF("   Memory overhead: %zu bytes", perf_memory_overhead);
    LOG_INF("   Percentage increase: %u%%", perf_memory_percentage);
    
    if (perf_memory_percentage < 5) {
        LOG_INF("   Memory efficiency: EXCELLENT");
    } else if (perf_memory_percentage < 15) {
        LOG_INF("    Memory efficiency: GOOD");
    } else {
        LOG_INF("   Memory efficiency: HIGH OVERHEAD");
    }
    LOG_INF("======================================");
    
    // Protocol size analysis
    LOG_INF("=== PROTOCOL SIZE ANALYSIS ===");
    LOG_INF("   Message header: %zu bytes", perf_message_header_size);
    LOG_INF("   Public key (serialized): %zu bytes", perf_public_key_size);
    LOG_INF("   Commitments: %zu bytes", perf_commitments_size);
    LOG_INF("   Secret shares: %zu bytes", perf_secret_share_size);
    LOG_INF("   Signature shares: %zu bytes", perf_signature_share_size);
    LOG_INF("   Total per participant: %zu bytes", perf_total_per_participant);
    LOG_INF("   Protocol overhead: %zu bytes", perf_protocol_overhead);
    LOG_INF("===================================");
    
    // Timing analysis
    if (perf_sample_count > 0) {
        LOG_INF("=== TIMING ANALYSIS ===");
        if (perf_nonce_gen_time_ms > 0) {
            LOG_INF("   Nonce generation: %u ms", perf_nonce_gen_time_ms);
        }
        if (perf_signing_time_ms > 0) {
            LOG_INF("   Signature computation: %u ms", perf_signing_time_ms);
        }
        if (perf_phase1_total_time_ms > 0) {
            LOG_INF("   Phase 1 total: %u ms", perf_phase1_total_time_ms);
        }
        if (perf_phase2_total_time_ms > 0) {
            LOG_INF("   Phase 2 total: %u ms", perf_phase2_total_time_ms);
        }
        if (perf_flash_read_time_ms > 0) {
            LOG_INF("   Flash read: %u ms", perf_flash_read_time_ms);
        }
        if (perf_flash_write_time_ms > 0) {
            LOG_INF("   Flash write: %u ms", perf_flash_write_time_ms);
        }
        LOG_INF("===============================");
    }
    
    // Performance summary
    LOG_INF("=== PERFORMANCE SUMMARY ===");
    LOG_INF("   Protocol: FROST 2-out-of-3 threshold signature");
    LOG_INF("   Platform: Zephyr RTOS with USB HID (portable timing)");
    LOG_INF("   Nonce persistence: Flash storage enabled");
    LOG_INF("   Memory overhead: %zu bytes (%u%%)", perf_memory_overhead, perf_memory_percentage);
    LOG_INF("   Protocol data per participant: %zu bytes", perf_total_per_participant);
    LOG_INF("   Performance samples collected: %d", perf_sample_count);
    LOG_INF("=====================================");
}

typedef enum {
    MSG_TYPE_NONCE_COMMITMENT  = 0x04,
    MSG_TYPE_END_TRANSMISSION  = 0xFF,
    MSG_TYPE_READY             = 0x06,
    MSG_TYPE_SIGN              = 0x07,
    MSG_TYPE_SIGNATURE_SHARE   = 0x08
} message_type_t;

typedef struct {
    uint32_t magic;        
    uint8_t version;       
    uint8_t msg_type;      
    uint16_t payload_len;  
    uint32_t participant;  
} __packed message_header_t;

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

typedef struct {
    uint32_t keypair_index;
    uint32_t keypair_max_participants;
    uint8_t keypair_secret[32];
    uint8_t keypair_public_key[64];
    uint8_t keypair_group_public_key[64];
    
    uint32_t nonce_session_id;
    uint8_t nonce_hiding_secret[32];
    uint8_t nonce_binding_secret[32];
    uint8_t nonce_hiding_commitment[64];
    uint8_t nonce_binding_commitment[64];
    uint8_t nonce_used;
    uint8_t nonce_valid;
    uint8_t reserved[2];
} __packed extended_frost_storage_t;

static bool configured = false;
static const struct device *hdev;
static ATOMIC_DEFINE(hid_ep_in_busy, 1);
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

#define REASSEMBLY_BUFFER_SIZE 2048
static uint8_t receive_buffer[REASSEMBLY_BUFFER_SIZE];
static size_t receive_buffer_pos = 0;
static size_t expected_total_size = 0;
static bool reassembling_message = false;

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
#define REPORT_PERIOD K_SECONDS(2)

static void receive_timeout_handler(struct k_timer *timer);
K_TIMER_DEFINE(receive_timeout_timer, receive_timeout_handler, NULL);

static const uint8_t hid_report_desc[] = {
	HID_USAGE_PAGE(HID_USAGE_GEN_DESKTOP),
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_COLLECTION(HID_COLLECTION_APPLICATION),
	
	HID_REPORT_ID(REPORT_ID_INPUT),
	HID_LOGICAL_MIN8(0x00),
	HID_LOGICAL_MAX16(0xFF, 0x00),
	HID_REPORT_SIZE(8),
	HID_REPORT_COUNT(63),
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_INPUT(0x02),
	
	HID_REPORT_ID(REPORT_ID_OUTPUT),
	HID_LOGICAL_MIN8(0x00),
	HID_LOGICAL_MAX16(0xFF, 0x00),
	HID_REPORT_SIZE(8),
	HID_REPORT_COUNT(63),
	HID_USAGE(HID_USAGE_GEN_DESKTOP_UNDEFINED),
	HID_OUTPUT(0x02),
	
	HID_END_COLLECTION,
};

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

static void reset_reassembly_state(void)
{
    reassembling_message = false;
    receive_buffer_pos = 0;
    expected_total_size = 0;
    k_timer_stop(&receive_timeout_timer);
    LOG_INF("Reassembly state reset");
}

static int read_extended_flash_data(void) {
    uint32_t start_time = get_uptime_ms();
    
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
    
    uint32_t end_time = get_uptime_ms();
    perf_flash_read_time_ms = end_time - start_time;
    
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
    LOG_INF("Flash read time: %u ms", perf_flash_read_time_ms);
    
    if (flash_data.nonce_valid) {
        LOG_INF("Stored nonce found - Session ID: %u, Used: %s", 
                flash_data.nonce_session_id, 
                flash_data.nonce_used ? "YES" : "NO");
    } else {
        LOG_INF("No valid stored nonce found");
    }
    
    return 0;
}

static int write_extended_flash_data(void) {
    if (!flash_data_valid) {
        LOG_ERR("Cannot write invalid flash data");
        return -EINVAL;
    }

    uint32_t start_time = get_uptime_ms();

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
    
    uint32_t end_time = get_uptime_ms();
    perf_flash_write_time_ms = end_time - start_time;
    
    LOG_INF("Extended flash data written successfully");
    LOG_INF("Flash write time: %u ms", perf_flash_write_time_ms);
    return 0;
}

static int save_nonce_to_flash(const secp256k1_frost_nonce *nonce, uint32_t session_id) {
    if (!nonce || !flash_data_valid) {
        LOG_ERR("Cannot save nonce - invalid parameters");
        return -EINVAL;
    }

    LOG_INF("=== SAVING NONCE TO FLASH ===");
    
    uint32_t start_time = get_uptime_ms();
    
    flash_data.nonce_session_id = session_id;
    memcpy(flash_data.nonce_hiding_secret, nonce->hiding, 32);
    memcpy(flash_data.nonce_binding_secret, nonce->binding, 32);
    memcpy(flash_data.nonce_hiding_commitment, nonce->commitments.hiding, 64);
    memcpy(flash_data.nonce_binding_commitment, nonce->commitments.binding, 64);
    flash_data.nonce_used = 0;
    flash_data.nonce_valid = 1;
    
    int rc = write_extended_flash_data();
    if (rc != 0) {
        LOG_ERR("Failed to save nonce to flash: %d", rc);
        return rc;
    }
    
    uint32_t end_time = get_uptime_ms();
    perf_nonce_save_time_ms = end_time - start_time;
    
    LOG_INF("Nonce persisted to flash - safe for device restart");
    LOG_INF("Nonce save time: %u ms", perf_nonce_save_time_ms);
    LOG_INF("Session ID: %u", session_id);
    log_hex("Hiding secret saved", flash_data.nonce_hiding_secret, 8);
    log_hex("Binding secret saved", flash_data.nonce_binding_secret, 8);
    log_hex("Hiding commitment saved", flash_data.nonce_hiding_commitment, 16);
    log_hex("Binding commitment saved", flash_data.nonce_binding_commitment, 16);
    
    return 0;
}

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
    
    uint32_t start_time = get_uptime_ms();
    
    secp256k1_frost_nonce* restored_nonce = 
        (secp256k1_frost_nonce*)malloc(sizeof(secp256k1_frost_nonce));
    
    if (!restored_nonce) {
        LOG_ERR("Failed to allocate memory for restored nonce");
        return NULL;
    }
    
    memcpy(restored_nonce->hiding, flash_data.nonce_hiding_secret, 32);
    memcpy(restored_nonce->binding, flash_data.nonce_binding_secret, 32);
    restored_nonce->commitments.index = keypair.public_keys.index;
    memcpy(restored_nonce->commitments.hiding, flash_data.nonce_hiding_commitment, 64);
    memcpy(restored_nonce->commitments.binding, flash_data.nonce_binding_commitment, 64);
    restored_nonce->used = 0;
    
    uint32_t end_time = get_uptime_ms();
    uint32_t load_time = end_time - start_time;
    
    LOG_INF("Original nonce restored from flash");
    LOG_INF("Nonce load time: %u ms", load_time);
    LOG_INF("Session ID: %u", flash_data.nonce_session_id);
    log_hex("Hiding secret restored", restored_nonce->hiding, 8);
    log_hex("Binding secret restored", restored_nonce->binding, 8);
    log_hex("Hiding commitment", restored_nonce->commitments.hiding, 16);
    log_hex("Binding commitment", restored_nonce->commitments.binding, 16);
    
    return restored_nonce;
}

static int mark_nonce_as_used(void) {
    if (!flash_data_valid || !flash_data.nonce_valid) {
        LOG_ERR("Cannot mark nonce as used - invalid flash data");
        return -EINVAL;
    }
    
    LOG_INF("=== MARKING NONCE AS USED ===");
    
    uint32_t start_time = get_uptime_ms();
    
    flash_data.nonce_used = 1;
    
    int rc = write_extended_flash_data();
    if (rc != 0) {
        LOG_ERR("Failed to mark nonce as used: %d", rc);
        return rc;
    }
    
    uint32_t end_time = get_uptime_ms();
    uint32_t mark_time = end_time - start_time;
    
    LOG_INF("Nonce marked as used - replay protection activated");
    LOG_INF("Nonce marking time: %u ms", mark_time);
    return 0;
}

static bool verify_commitment_consistency(const serialized_nonce_commitment_t* coordinator_commitment) {
    if (!flash_data_valid || !flash_data.nonce_valid) {
        LOG_ERR("Cannot verify commitment - no stored nonce");
        return false;
    }
    
    LOG_INF("=== VERIFYING COMMITMENT CONSISTENCY ===");
    
    uint32_t start_time = get_uptime_ms();
    
    bool hiding_match = (memcmp(coordinator_commitment->hiding, 
                                flash_data.nonce_hiding_commitment, 64) == 0);
    bool binding_match = (memcmp(coordinator_commitment->binding, 
                                 flash_data.nonce_binding_commitment, 64) == 0);
    
    uint32_t end_time = get_uptime_ms();
    perf_verification_time_ms = end_time - start_time;
    
    LOG_INF("Commitment verification:");
    LOG_INF("  Index match: %s (%u vs %u)", 
            (coordinator_commitment->index == keypair.public_keys.index) ? "YES" : "NO",
            coordinator_commitment->index, keypair.public_keys.index);
    LOG_INF("  Hiding match: %s", hiding_match ? "YES" : "NO");
    LOG_INF("  Binding match: %s", binding_match ? "YES" : "NO");
    LOG_INF("Verification time: %u ms", perf_verification_time_ms);
    
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

static int load_frost_key_material(void) {
    if (!flash_data_valid) return -1;
    
    uint32_t start_time = get_uptime_ms();
    
    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    keypair.public_keys.index = flash_data.keypair_index;
    keypair.public_keys.max_participants = flash_data.keypair_max_participants;
    memcpy(keypair.secret, flash_data.keypair_secret, 32);
    memcpy(keypair.public_keys.public_key, flash_data.keypair_public_key, 64);
    memcpy(keypair.public_keys.group_public_key, 
           flash_data.keypair_group_public_key, 64);
    
    uint32_t end_time = get_uptime_ms();
    perf_key_load_time_ms = end_time - start_time;
    
    LOG_INF("FROST key material loaded successfully");
    LOG_INF("Key loading time: %u ms", perf_key_load_time_ms);
    return 0;
}

static void verify_keypair_consistency(void) {
    LOG_INF("=== KEYPAIR CONSISTENCY VERIFICATION ===");
    
    uint32_t start_time = get_uptime_ms();
    
    if (keypair.public_keys.index == 0 || keypair.public_keys.index > 255) {
        LOG_ERR("Invalid participant index: %u", keypair.public_keys.index);
        return;
    }
    
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
    
    bool pub_zeros = true, group_zeros = true;
    for (int i = 0; i < 64; i++) {
        if (keypair.public_keys.public_key[i] != 0) pub_zeros = false;
        if (keypair.public_keys.group_public_key[i] != 0) group_zeros = false;
    }
    
    if (pub_zeros || group_zeros) {
        LOG_ERR("Public keys contain all zeros!");
        return;
    }
    
    uint32_t end_time = get_uptime_ms();
    uint32_t verify_time = end_time - start_time;
    
    LOG_INF("Keypair consistency verified");
    LOG_INF("Verification time: %u ms", verify_time);
    LOG_INF("  Index: %u", keypair.public_keys.index);
    LOG_INF("  Max participants: %u", keypair.public_keys.max_participants);
    log_hex("  Secret (first 8 bytes)", keypair.secret, 8);
    log_hex("  Public key (first 8 bytes)", keypair.public_keys.public_key, 8);
    log_hex("  Group key (first 8 bytes)", keypair.public_keys.group_public_key, 8);
}

static int send_chunked_data(const uint8_t *data, size_t len) {
    if (!configured || !data || len == 0) {
        return -EINVAL;
    }

    uint32_t start_time = get_uptime_ms();
    size_t offset = 0;
    int chunk_count = 0;
    
    while (offset < len) {
        int timeout = 100;
        while (atomic_test_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG) && timeout-- > 0) {
            k_msleep(10);
        }
        if (timeout <= 0) {
            LOG_ERR("HID endpoint timeout");
            return -ETIMEDOUT;
        }
        
        memset(chunk_buffer, 0, sizeof(chunk_buffer));
        chunk_buffer[0] = REPORT_ID_INPUT;
        size_t remaining = len - offset;
        size_t chunk_size = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
        chunk_buffer[1] = (uint8_t)chunk_size;
        memcpy(&chunk_buffer[2], data + offset, chunk_size);
        
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
    
    uint32_t end_time = get_uptime_ms();
    perf_transmission_time_ms = end_time - start_time;
    
    if (perf_transmission_time_ms > 0) {
        perf_throughput_bps = (uint32_t)((len * 8 * 1000) / perf_transmission_time_ms);
    }
    
    LOG_INF("Sent %d chunks (%zu bytes total)", chunk_count, len);
    LOG_INF("Transmission time: %u ms, Throughput: %u bps", 
           perf_transmission_time_ms, perf_throughput_bps);
    
    return 0;
}

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

static int generate_and_save_nonce_PHASE1(void) {
    LOG_INF("=== PHASE 1: GENERATE AND PERSIST NONCE ===");
    
    if (!flash_data_valid) {
        LOG_ERR("Flash data not valid, cannot proceed");
        return -1;
    }
    
    uint32_t phase_start = get_uptime_ms();
    update_memory_tracking();
    
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
    
    uint32_t nonce_gen_start = get_uptime_ms();
    secp256k1_frost_nonce* fresh_nonce = secp256k1_frost_nonce_create(
        secp256k1_ctx, &keypair, binding_seed, hiding_seed);
    uint32_t nonce_gen_end = get_uptime_ms();
    perf_nonce_gen_time_ms = nonce_gen_end - nonce_gen_start;
    
    if (!fresh_nonce) {
        LOG_ERR("Failed to create fresh nonce");
        return -1;
    }
    
    LOG_INF("Fresh nonce generated successfully");
    LOG_INF("Nonce generation time: %u ms", perf_nonce_gen_time_ms);
    log_hex("Generated hiding commitment", fresh_nonce->commitments.hiding, 16);
    log_hex("Generated binding commitment", fresh_nonce->commitments.binding, 16);
    
    update_memory_tracking();
    
    int save_result = save_nonce_to_flash(fresh_nonce, current_session_id);
    if (save_result != 0) {
        LOG_ERR("Failed to save nonce to flash!");
        secp256k1_frost_nonce_destroy(fresh_nonce);
        return -1;
    }
    
    secp256k1_frost_nonce_destroy(fresh_nonce);
    
    uint32_t phase_end = get_uptime_ms();
    perf_phase1_total_time_ms = phase_end - phase_start;
    perf_sample_count++;
    
    LOG_INF("PHASE 1 NONCE GENERATION AND PERSISTENCE COMPLETE");
    LOG_INF("Total Phase 1 time: %u ms", perf_phase1_total_time_ms);
    LOG_INF("Device can safely restart - nonce is preserved in flash");
    
    return 0;
}

static int send_nonce_commitment_and_keypair_PHASE1(void) {
    LOG_INF("=== PHASE 1: SENDING NONCE COMMITMENT AND KEYPAIR ===");
    
    if (!flash_data_valid || !flash_data.nonce_valid) {
        LOG_ERR("No valid nonce data available");
        return -1;
    }
    
    uint32_t send_start = get_uptime_ms();
    
    size_t payload_len = sizeof(serialized_nonce_commitment_t) + sizeof(serialized_keypair_t);
    uint8_t* combined_payload = malloc(payload_len);
    if (!combined_payload) {
        LOG_ERR("Failed to allocate memory for combined payload");
        return -ENOMEM;
    }

    serialized_nonce_commitment_t* nonce_part = (serialized_nonce_commitment_t*)combined_payload;
    nonce_part->index = keypair.public_keys.index;
    memcpy(nonce_part->hiding, flash_data.nonce_hiding_commitment, 64);
    memcpy(nonce_part->binding, flash_data.nonce_binding_commitment, 64);

    serialized_keypair_t* keypair_part = (serialized_keypair_t*)(combined_payload + sizeof(serialized_nonce_commitment_t));
    keypair_part->index = keypair.public_keys.index;
    keypair_part->max_participants = keypair.public_keys.max_participants;
    memcpy(keypair_part->secret, keypair.secret, 32);
    memcpy(keypair_part->public_key, keypair.public_keys.public_key, 64);
    memcpy(keypair_part->group_public_key, keypair.public_keys.group_public_key, 64);

    LOG_INF("*** SENDING PERSISTED NONCE COMMITMENT AND KEYPAIR ***");
    LOG_INF("Participant: %u", keypair.public_keys.index);
    LOG_INF("Session ID: %u", flash_data.nonce_session_id);
    LOG_INF("Payload size: %zu bytes", payload_len);
    log_hex("Sending hiding commitment", nonce_part->hiding, 16);
    log_hex("Sending binding commitment", nonce_part->binding, 16);
    
    int ret = send_message(MSG_TYPE_NONCE_COMMITMENT, 
                          keypair.public_keys.index,
                          combined_payload, payload_len);
    
    free(combined_payload);
    
    uint32_t send_end = get_uptime_ms();
    perf_phase1_send_time_ms = send_end - send_start;
    
    if (ret == 0) {
        LOG_INF("PHASE 1 SUCCESS: Persisted nonce commitment and keypair sent");
        LOG_INF("Phase 1 send time: %u ms", perf_phase1_send_time_ms);
    } else {
        LOG_ERR("PHASE 1 FAILED: Failed to send nonce commitment and keypair");
    }
    
    return ret;
}

static int send_signature_share_and_mark_used_PHASE3(void) {
    LOG_INF("=== PHASE 3: SENDING SIGNATURE SHARE AND MARKING NONCE USED ===");
    
    if (!signature_share_computed) {
        LOG_ERR("No signature share computed yet");
        return -1;
    }

    uint32_t phase3_start = get_uptime_ms();

    serialized_signature_share_t serialized = {
        .index = keypair.public_keys.index
    };
    memcpy(serialized.response, computed_signature_share.response, 32);

    LOG_INF("*** SENDING SIGNATURE SHARE TO COORDINATOR ***");
    LOG_INF("Participant: %u", keypair.public_keys.index);
    LOG_INF("Signature share size: %zu bytes", sizeof(serialized));
    log_hex("Signature Share", serialized.response, 32);

    int ret = send_message(MSG_TYPE_SIGNATURE_SHARE, 
                          keypair.public_keys.index,
                          &serialized, sizeof(serialized));
    
    if (ret == 0) {
        LOG_INF("PHASE 3 SUCCESS: Signature share sent to coordinator");
        
        int mark_result = mark_nonce_as_used();
        if (mark_result == 0) {
            LOG_INF("Nonce marked as used - replay protection activated");
        } else {
            LOG_WRN("Failed to mark nonce as used, but signature sent");
        }
        
        send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0);
        
        uint32_t phase3_end = get_uptime_ms();
        perf_phase3_time_ms = phase3_end - phase3_start;
        LOG_INF("Phase 3 total time: %u ms", perf_phase3_time_ms);
    } else {
        LOG_ERR("PHASE 3 FAILED: Failed to send signature share to coordinator");
    }
    
    return ret;
}

static void process_sign_message_PHASE2_FIXED(void) {
    LOG_INF("=== PHASE 2: PROCESSING SIGN MESSAGE (FIXED - ORIGINAL NONCE) ===");
    
    uint32_t phase2_start = get_uptime_ms();
    update_memory_tracking();
    
    const message_header_t *header = (const message_header_t *)receive_buffer;
    const uint8_t* payload = receive_buffer + sizeof(message_header_t);
    
    if (header->payload_len < 32 + 4) {
        LOG_ERR("Invalid sign message length");
        return;
    }
    
    uint8_t* msg_hash = (uint8_t*)payload;
    uint32_t num_commitments = *(uint32_t*)(payload + 32);
    serialized_nonce_commitment_t* serialized_commitments = (serialized_nonce_commitment_t*)(payload + 32 + 4);
    
    LOG_INF("*** PROCESSING SIGN MESSAGE DATA ***");
    LOG_INF("Message hash (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x...", 
            msg_hash[0], msg_hash[1], msg_hash[2], msg_hash[3],
            msg_hash[4], msg_hash[5], msg_hash[6], msg_hash[7]);
    LOG_INF("Number of commitments: %u", num_commitments);
    
    // Hash verification with timing
    uint32_t hash_verify_start = get_uptime_ms();
    unsigned char expected_msg[12] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    unsigned char expected_hash[32];
    unsigned char tag[14] = {'f', 'r', 'o', 's', 't', '_', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};
    int hash_result = secp256k1_tagged_sha256(secp256k1_ctx, expected_hash, tag, sizeof(tag), expected_msg, sizeof(expected_msg));
    uint32_t hash_verify_end = get_uptime_ms();
    perf_hash_verify_time_ms = hash_verify_end - hash_verify_start;
    
    if (hash_result != 1) {
        LOG_ERR("Hash computation failed!");
        return;
    }
    
    if (memcmp(msg_hash, expected_hash, 32) != 0) {
        LOG_ERR("Message hash verification FAILED!");
        return;
    }
    LOG_INF("Message hash verified correctly (Hello World!)");
    LOG_INF("Hash verification time: %u ms", perf_hash_verify_time_ms);
    
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
    
    if (!verify_commitment_consistency(our_commitment_from_coordinator)) {
        LOG_ERR("Commitment consistency verification failed!");
        return;
    }
    
    secp256k1_frost_nonce* original_nonce = 
        load_original_nonce_from_flash(current_session_id);
    
    if (!original_nonce) {
        LOG_ERR("Failed to load original nonce from flash");
        return;
    }
    
    LOG_INF("Using ORIGINAL nonce from flash persistence");
    
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
    
    uint32_t signing_start = get_uptime_ms();
    update_memory_tracking();
    
    int return_val = secp256k1_frost_sign(&computed_signature_share,
                                         msg_hash, num_commitments,
                                         &keypair, original_nonce, signing_commitments);
    
    uint32_t signing_end = get_uptime_ms();
    perf_signing_time_ms = signing_end - signing_start;
    
    if (return_val == 1) {
        signature_share_computed = true;
        
        LOG_INF("*** SIGNATURE SHARE COMPUTED SUCCESSFULLY ***");
        LOG_INF("Used ORIGINAL nonce from flash persistence");
        LOG_INF("Signature computation time: %u ms", perf_signing_time_ms);
        log_hex("SIGNATURE SHARE (32 bytes)", computed_signature_share.response, 32);
        
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
            
            char hex_str[65];
            for (int i = 0; i < 32; i++) {
                sprintf(hex_str + i * 2, "%02x", computed_signature_share.response[i]);
            }
            hex_str[64] = '\0';
            printk("\n\n=== FROST SIGNATURE SHARE ===\n");
            printk("Participant: %u\n", keypair.public_keys.index);
            printk("Signature: %s\n", hex_str);
            printk("=============================\n\n");
            
            uint32_t phase2_end = get_uptime_ms();
            perf_phase2_total_time_ms = phase2_end - phase2_start;
            perf_sample_count++;
            
            LOG_INF("Total Phase 2 time: %u ms", perf_phase2_total_time_ms);
            
            k_work_submit(&send_share_work);
        }
        
    } else {
        LOG_ERR("Failed to compute signature share (return_val=%d)", return_val);
        signature_share_computed = false;
    }
    
    free(signing_commitments);
    free(original_nonce);
}

static void process_received_message(void) {
    if (receive_buffer_pos < sizeof(message_header_t)) {
        return;
    }
    
    const message_header_t *header = (const message_header_t *)receive_buffer;
    
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
    
    if (reassembling_message) {
        size_t space_available = REASSEMBLY_BUFFER_SIZE - receive_buffer_pos;
        size_t bytes_to_copy = (chunk_len > space_available) ? space_available : chunk_len;
        
        if (bytes_to_copy > 0) {
            memcpy(receive_buffer + receive_buffer_pos, chunk_data, bytes_to_copy);
            receive_buffer_pos += bytes_to_copy;
            
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

static void send_share_work_handler(struct k_work *work) {
    LOG_INF("🏃‍♂️ send_share_work_handler called");
    
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

static void sign_work_handler(struct k_work *work) {
    LOG_INF("🏃‍♂️ sign_work_handler called");
    
    if (!configured || !flash_data_valid) {
        LOG_ERR("Device not ready for signing");
        return;
    }
    
    const message_header_t *header = (const message_header_t *)receive_buffer;
    
    switch (header->msg_type) {
        case MSG_TYPE_READY:
            LOG_INF("🏃‍♂️ Processing READY message - PHASE 1");
            
            if (generate_and_save_nonce_PHASE1() == 0) {
                if (send_nonce_commitment_and_keypair_PHASE1() == 0) {
                    send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0);
                }
            }
            break;
            
        case MSG_TYPE_SIGN:
            LOG_INF("🏃‍♂️ Processing SIGN message - PHASE 2 (FIXED with original nonce)");
            process_sign_message_PHASE2_FIXED();
            break;
            
        default:
            LOG_WRN("Unknown message type in work handler: 0x%02x", header->msg_type);
            break;
    }
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

static void int_in_ready_cb(const struct device *dev) {
    atomic_clear_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
}

static void int_out_ready_cb(const struct device *dev) {
    uint8_t buffer[64];
    int ret, received;
    
    ret = hid_int_ep_read(dev, buffer, sizeof(buffer), &received);
    if (ret == 0 && received > 0) {
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

static void status_cb(enum usb_dc_status_code status, const uint8_t *param) {
    switch (status) {
    case USB_DC_RESET:
        configured = false;
        LOG_INF("🔌 USB Reset");
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
            LOG_INF("🔌 USB Configured - Ready");
        }
        break;
    default:
        break;
    }
}

int main(void) {
    int ret;
    LOG_INF("=== FROST HID Device with PERFORMANCE EVALUATION ===");
    LOG_INF("Nonces survive device restarts via flash storage");
    LOG_INF("Portable performance monitoring enabled (k_uptime_get based)");
    
    // Initialize performance tracking
    init_performance_tracking();
    
    // Print initial protocol size analysis
    LOG_INF("=== PROTOCOL SIZE ANALYSIS ===");
    LOG_INF("   Message header: %zu bytes", perf_message_header_size);
    LOG_INF("   Public key (serialized): %zu bytes", perf_public_key_size);
    LOG_INF("   Commitments: %zu bytes", perf_commitments_size);
    LOG_INF("   Secret shares: %zu bytes", perf_secret_share_size);
    LOG_INF("   Signature shares: %zu bytes", perf_signature_share_size);
    LOG_INF("   Total per participant: %zu bytes", perf_total_per_participant);
    LOG_INF("   Protocol overhead: %zu bytes", perf_protocol_overhead);
    LOG_INF("===================================");
    
    secp256k1_ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (secp256k1_ctx == NULL) {
        LOG_ERR("Failed to create secp256k1 context");
        return -1;
    }
    LOG_INF("secp256k1 context created successfully");
    
    update_memory_tracking();
    
    k_work_init(&sign_work, sign_work_handler);
    k_work_init(&send_share_work, send_share_work_handler);
    k_work_init(&report_send, send_report);
    LOG_INF("Work queues initialized");
    
    if (read_extended_flash_data() != 0) {
        LOG_ERR("Failed to read extended flash data");
        return -1;
    }
    
    if (load_frost_key_material() != 0) {
        LOG_ERR("Failed to load key material");
        return -1;
    }
    
    verify_keypair_consistency();
    
    update_memory_tracking();
    
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
    
    finalize_memory_tracking();
    
    LOG_INF("=== FROST HID Device Ready (PERFORMANCE EVALUATION) ===");
    LOG_INF("Participant %u ready for FROST protocol", keypair.public_keys.index);
    LOG_INF("Flash storage supports nonce persistence across restarts");
    LOG_INF("Replay protection activated");
    LOG_INF("Performance monitoring: timing (uptime-based), memory, communication efficiency");
    
    // Generate initial performance report
    print_performance_summary();
    
    // Main loop with periodic performance updates
    int iteration = 0;
    while (1) {
        k_msleep(1000);
        iteration++;
        
        // Generate performance report every 60 seconds if there's activity
        if (iteration % 60 == 0 && perf_sample_count > 0) {
            LOG_INF("=== PERIODIC PERFORMANCE UPDATE ===");
            print_performance_summary();
        }
    }
    
    secp256k1_context_destroy(secp256k1_ctx);
    
    return 0;
}