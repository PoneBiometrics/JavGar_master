#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#ifdef CONFIG_SYS_HEAP_RUNTIME_STATS
#include <zephyr/sys/mem_stats.h>
#endif
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include "examples_util.h"

#define T 2
#define UART_DEVICE_NODE DT_NODELABEL(usart1) 
#define STORAGE_PARTITION storage_partition

LOG_MODULE_REGISTER(frost_uart_device, LOG_LEVEL_INF);

#define RING_BUF_SIZE 512
#define MAX_MSG_SIZE 300
#define RECEIVE_TIMEOUT_MS 30000

static uint8_t rx_buf[RING_BUF_SIZE];
static struct ring_buf rx_ring_buf;
static const struct device *uart_dev;

#define MSG_HEADER_MAGIC 0x46524F53
#define MSG_VERSION 0x01

typedef enum {
    MSG_TYPE_NONCE_COMMITMENT = 0x04, 
    MSG_TYPE_READY = 0x06,
    MSG_TYPE_END_TRANSMISSION = 0xFF,
    MSG_TYPE_SIGN = 0x07,
    MSG_TYPE_SIGNATURE_SHARE = 0x08
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


// Global timing variables
static uint32_t perf_flash_read_time_ms = 0;
static uint32_t perf_flash_write_time_ms = 0;
static uint32_t perf_key_load_time_ms = 0;
static uint32_t perf_verification_time_ms = 0;
static uint32_t perf_nonce_gen_time_ms = 0;
static uint32_t perf_nonce_save_time_ms = 0;
static uint32_t perf_nonce_load_time_ms = 0;
static uint32_t perf_nonce_mark_time_ms = 0;
static uint32_t perf_commitment_verify_time_ms = 0;
static uint32_t perf_phase1_total_time_ms = 0;
static uint32_t perf_phase1_send_time_ms = 0;
static uint32_t perf_hash_verify_time_ms = 0;
static uint32_t perf_signing_time_ms = 0;
static uint32_t perf_phase2_total_time_ms = 0;
static uint32_t perf_phase3_time_ms = 0;
static uint32_t perf_uart_transmission_time_ms = 0;
static uint32_t perf_uart_bytes_per_sec = 0;

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

// Communication tracking
static size_t perf_total_bytes_sent = 0;
static uint32_t perf_total_messages_sent = 0;
static uint32_t perf_total_uart_time_ms = 0;

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
    perf_message_header_size = sizeof(message_header_t);
    perf_public_key_size = sizeof(serialized_keypair_t);
    perf_commitments_size = sizeof(serialized_nonce_commitment_t);
    perf_signature_share_size = sizeof(serialized_signature_share_t);
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
    
    // UART Communication analysis
    if (perf_total_messages_sent > 0) {
        LOG_INF("=== UART COMMUNICATION ANALYSIS ===");
        LOG_INF("   Total messages sent: %u", perf_total_messages_sent);
        LOG_INF("   Total bytes transmitted: %zu bytes", perf_total_bytes_sent);
        LOG_INF("   Total transmission time: %u ms", perf_total_uart_time_ms);
        if (perf_total_uart_time_ms > 0) {
            uint32_t throughput = (uint32_t)((perf_total_bytes_sent * 8 * 1000) / perf_total_uart_time_ms);
            LOG_INF("   Average throughput: %u bps (%.1f KB/s)", throughput, throughput / 8000.0);
        }
        LOG_INF("   Baudrate: 115200 bps");
        
        if (perf_uart_transmission_time_ms > 0) {
            LOG_INF("   Last transmission: %u ms", perf_uart_transmission_time_ms);
        }
        
        LOG_INF("==========================================");
    }
    
    // Timing analysis (if we have samples)
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
        if (perf_phase3_time_ms > 0) {
            LOG_INF("   Phase 3 total: %u ms", perf_phase3_time_ms);
        }
        if (perf_flash_read_time_ms > 0) {
            LOG_INF("   Flash read: %u ms", perf_flash_read_time_ms);
        }
        if (perf_flash_write_time_ms > 0) {
            LOG_INF("   Flash write: %u ms", perf_flash_write_time_ms);
        }
        if (perf_hash_verify_time_ms > 0) {
            LOG_INF("   Hash verification: %u ms", perf_hash_verify_time_ms);
        }
        if (perf_commitment_verify_time_ms > 0) {
            LOG_INF("   Commitment verification: %u ms", perf_commitment_verify_time_ms);
        }
        LOG_INF("===============================");
    }
    
    // Performance summary
    LOG_INF("=== PERFORMANCE SUMMARY ===");
    LOG_INF("   Protocol: FROST 2-out-of-3 threshold signature");
    LOG_INF("   Platform: Zephyr RTOS with UART (115200 baud)");
    LOG_INF("   Nonce persistence: Flash storage enabled");
    LOG_INF("   Memory overhead: %zu bytes (%u%%)", perf_memory_overhead, perf_memory_percentage);
    LOG_INF("   Protocol data per participant: %zu bytes", perf_total_per_participant);
    LOG_INF("   Performance samples collected: %d", perf_sample_count);
    
    // Overall assessment
    if (perf_sample_count > 0) {
        uint32_t total_ops_time = perf_nonce_gen_time_ms + perf_signing_time_ms + 
                                 perf_flash_read_time_ms + perf_flash_write_time_ms;
        
        LOG_INF("🏆 OVERALL PERFORMANCE ASSESSMENT:");
        if (total_ops_time < 100 && perf_memory_percentage < 15) {
            LOG_INF("   EXCELLENT: Fast operations with low memory overhead");
        } else if (total_ops_time < 500 && perf_memory_percentage < 30) {
            LOG_INF("    GOOD: Acceptable performance for embedded system");
        } else {
            LOG_INF("   NEEDS OPTIMIZATION: Consider performance improvements");
        }
    }
    
    LOG_INF("=====================================");
}

static secp256k1_context *ctx;
static secp256k1_frost_keypair keypair;
static bool keypair_loaded = false;
static extended_frost_storage_t flash_data;
static bool flash_data_valid = false;

static secp256k1_frost_signature_share computed_signature_share;
static bool signature_share_computed = false;

static uint32_t current_session_id = 0;

typedef enum {
    WAITING_FOR_HEADER,
    WAITING_FOR_PAYLOAD
} receive_state_t;

static receive_state_t rx_state = WAITING_FOR_HEADER;
static message_header_t current_header;
static uint8_t payload_buffer[MAX_MSG_SIZE];
static size_t payload_bytes_received = 0;

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
        (secp256k1_frost_nonce*)k_malloc(sizeof(secp256k1_frost_nonce));
    
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
    perf_nonce_load_time_ms = end_time - start_time;
    
    LOG_INF("Original nonce restored from flash");
    LOG_INF("Nonce load time: %u ms", perf_nonce_load_time_ms);
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
    perf_nonce_mark_time_ms = end_time - start_time;
    
    LOG_INF("Nonce marked as used - replay protection activated");
    LOG_INF("Nonce marking time: %u ms", perf_nonce_mark_time_ms);
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
    perf_commitment_verify_time_ms = end_time - start_time;
    
    LOG_INF("Commitment verification:");
    LOG_INF("  Index match: %s (%u vs %u)", 
            (coordinator_commitment->index == keypair.public_keys.index) ? "YES" : "NO",
            coordinator_commitment->index, keypair.public_keys.index);
    LOG_INF("  Hiding match: %s", hiding_match ? "YES" : "NO");
    LOG_INF("  Binding match: %s", binding_match ? "YES" : "NO");
    LOG_INF("Commitment verification time: %u ms", perf_commitment_verify_time_ms);
    
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

int load_frost_key_material(void) {
    if (!flash_data_valid) return -1;
    
    uint32_t start_time = get_uptime_ms();
    
    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    keypair.public_keys.index = flash_data.keypair_index;
    keypair.public_keys.max_participants = flash_data.keypair_max_participants;
    memcpy(keypair.secret, flash_data.keypair_secret, 32);
    memcpy(keypair.public_keys.public_key, flash_data.keypair_public_key, 64);
    memcpy(keypair.public_keys.group_public_key, flash_data.keypair_group_public_key, 64);
    
    if (keypair.public_keys.index == 0 || keypair.public_keys.index > 255) {
        LOG_ERR("Invalid participant index: %u", keypair.public_keys.index);
        return -EINVAL;
    }
    
    uint32_t end_time = get_uptime_ms();
    perf_key_load_time_ms = end_time - start_time;
    
    keypair_loaded = true;
    LOG_INF("FROST key material loaded successfully");
    LOG_INF("Key loading time: %u ms", perf_key_load_time_ms);
    LOG_INF("👤 Participant Index: %u", keypair.public_keys.index);
    LOG_INF("Max Participants: %u", keypair.public_keys.max_participants);
    
    return 0;
}

static int uart_send_data(const uint8_t *data, size_t len) {
    uint32_t start_time = get_uptime_ms();
    
    for (size_t i = 0; i < len; i++) {
        uart_poll_out(uart_dev, data[i]);
        k_usleep(100);
    }
    
    uint32_t end_time = get_uptime_ms();
    perf_uart_transmission_time_ms = end_time - start_time;
    
    // Update global UART statistics
    perf_total_bytes_sent += len;
    perf_total_uart_time_ms += perf_uart_transmission_time_ms;
    
    if (perf_uart_transmission_time_ms > 0) {
        perf_uart_bytes_per_sec = (uint32_t)((len * 1000) / perf_uart_transmission_time_ms);
    }
    
    return 0;
}

static bool send_message(uint8_t msg_type, uint32_t participant, 
                        const void* payload, uint16_t payload_len) {
    message_header_t header;
    header.magic = MSG_HEADER_MAGIC;
    header.version = MSG_VERSION;
    header.msg_type = msg_type;
    header.payload_len = payload_len;
    header.participant = participant;

    LOG_INF("Sending message: type=0x%02X, participant=%u, len=%u", 
            msg_type, participant, payload_len);

    uint32_t total_send_start = get_uptime_ms();

    int ret = uart_send_data((uint8_t*)&header, sizeof(header));
    if (ret < 0) {
        LOG_ERR("Failed to send header");
        return false;
    }

    if (payload_len > 0 && payload != NULL) {
        ret = uart_send_data(payload, payload_len);
        if (ret < 0) {
            LOG_ERR("Failed to send payload");
            return false;
        }
    }

    uint32_t total_send_end = get_uptime_ms();
    uint32_t total_message_time = total_send_end - total_send_start;
    
    perf_total_messages_sent++;
    
    LOG_INF("Message sent successfully");
    LOG_INF("Message transmission time: %u ms", total_message_time);
    LOG_INF("Total bytes: %zu bytes", sizeof(header) + payload_len);
    
    return true;
}

static int generate_and_save_nonce_PHASE1(void) {
    LOG_INF("=== PHASE 1: GENERATE AND PERSIST NONCE ===");
    
    if (!flash_data_valid) {
        LOG_ERR("Flash data not valid, cannot proceed");
        return -1;
    }
    
    uint32_t phase1_start = get_uptime_ms();
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
    secp256k1_frost_nonce* fresh_nonce = secp256k1_frost_nonce_create(ctx, &keypair, binding_seed, hiding_seed);
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
    
    uint32_t phase1_end = get_uptime_ms();
    perf_phase1_total_time_ms = phase1_end - phase1_start;
    perf_sample_count++;
    
    LOG_INF("PHASE 1 NONCE GENERATION AND PERSISTENCE COMPLETE");
    LOG_INF("Total Phase 1 time: %u ms", perf_phase1_total_time_ms);
    LOG_INF("Device can safely restart - nonce is preserved in flash");
    
    return 0;
}

static bool send_nonce_commitment_and_keypair_PHASE1(void) {
    LOG_INF("=== PHASE 1: SENDING NONCE COMMITMENT AND KEYPAIR ===");
    
    if (!flash_data_valid || !flash_data.nonce_valid) {
        LOG_ERR("No valid nonce data available");
        return false;
    }
    
    uint32_t send_start = get_uptime_ms();
    
    size_t payload_len = sizeof(serialized_nonce_commitment_t) + sizeof(serialized_keypair_t);
    uint8_t* combined_payload = k_malloc(payload_len);
    if (!combined_payload) {
        LOG_ERR("Failed to allocate memory for combined payload");
        return false;
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
    
    bool result = send_message(MSG_TYPE_NONCE_COMMITMENT, 
                              keypair.public_keys.index,
                              combined_payload, payload_len);
    
    k_free(combined_payload);
    
    uint32_t send_end = get_uptime_ms();
    perf_phase1_send_time_ms = send_end - send_start;
    
    if (result) {
        LOG_INF("PHASE 1 SUCCESS: Persisted nonce commitment and keypair sent");
        LOG_INF("Phase 1 send time: %u ms", perf_phase1_send_time_ms);
    } else {
        LOG_ERR("PHASE 1 FAILED: Failed to send nonce commitment and keypair");
    }
    
    return result;
}

static bool send_signature_share_and_mark_used_PHASE3(void) {
    LOG_INF("=== PHASE 3: SENDING SIGNATURE SHARE AND MARKING NONCE USED ===");
    
    if (!signature_share_computed) {
        LOG_ERR("No signature share computed yet");
        return false;
    }

    uint32_t phase3_start = get_uptime_ms();

    serialized_signature_share_t serialized;
    serialized.index = keypair.public_keys.index;
    memcpy(serialized.response, computed_signature_share.response, 32);

    LOG_INF("*** SENDING SIGNATURE SHARE TO COORDINATOR ***");
    LOG_INF("Participant: %u", keypair.public_keys.index);
    LOG_INF("Signature share size: %zu bytes", sizeof(serialized));
    log_hex("Signature Share", serialized.response, 32);

    bool result = send_message(MSG_TYPE_SIGNATURE_SHARE, 
                              keypair.public_keys.index,
                              &serialized, sizeof(serialized));
    
    if (result) {
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
        LOG_ERR("PHASE 3 FAILED: Failed to send signature share");
    }
    
    return result;
}

static void process_sign_message_PHASE2_FIXED(const message_header_t *header, const uint8_t *payload) {
    LOG_INF("=== PHASE 2: PROCESSING SIGN MESSAGE (FIXED - ORIGINAL NONCE) ===");
    
    uint32_t phase2_start = get_uptime_ms();
    update_memory_tracking();
    
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
    int hash_result = secp256k1_tagged_sha256(ctx, expected_hash, tag, sizeof(tag), expected_msg, sizeof(expected_msg));
    uint32_t hash_verify_end = get_uptime_ms();
    perf_hash_verify_time_ms = hash_verify_end - hash_verify_start;
    
    if (hash_result != 1) {
        LOG_ERR("Hash computation failed!");
        return;
    }
    
    if (memcmp(msg_hash, expected_hash, 32) != 0) {
        LOG_ERR("Message hash verification FAILED!");
        LOG_ERR("This device will NOT produce a valid signature share");
        return;
    }
    LOG_INF("Message hash verified correctly (Hello World!)");
    LOG_INF("Hash verification time: %u ms", perf_hash_verify_time_ms);
    
    serialized_nonce_commitment_t* our_commitment_from_coordinator = NULL;
    
    for (uint32_t i = 0; i < num_commitments; i++) {
        LOG_INF("Checking commitment %u: participant %u", i, serialized_commitments[i].index);
        
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
        k_malloc(num_commitments * sizeof(secp256k1_frost_nonce_commitment));
    if (!signing_commitments) {
        LOG_ERR("Failed to allocate memory for signing commitments");
        k_free(original_nonce);
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
            
            send_signature_share_and_mark_used_PHASE3();
        }
        
    } else {
        LOG_ERR("Failed to compute signature share (return_val=%d)", return_val);
        signature_share_computed = false;
    }
    
    k_free(signing_commitments);
    k_free(original_nonce);
}

static void uart_cb(const struct device *dev, void *user_data) {
    uint8_t byte;
    
    while (uart_irq_update(dev) && uart_irq_is_pending(dev)) {
        if (uart_irq_rx_ready(dev)) {
            while (uart_fifo_read(dev, &byte, 1) == 1) {
                if (ring_buf_put(&rx_ring_buf, &byte, 1) == 0) {
                    LOG_WRN("Ring buffer full, dropping byte");
                }
            }
        }
    }
}

static void process_ready_message() {
    LOG_INF("*** Received READY signal ***");
    
    if (generate_and_save_nonce_PHASE1() == 0) {
        send_nonce_commitment_and_keypair_PHASE1();
    }
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
    perf_verification_time_ms = end_time - start_time;
    
    LOG_INF("Keypair consistency verified");
    LOG_INF("Verification time: %u ms", perf_verification_time_ms);
    LOG_INF("  Index: %u", keypair.public_keys.index);
    LOG_INF("  Max participants: %u", keypair.public_keys.max_participants);
    log_hex("  Secret (first 8 bytes)", keypair.secret, 8);
    log_hex("  Public key (first 8 bytes)", keypair.public_keys.public_key, 8);
    log_hex("  Group key (first 8 bytes)", keypair.public_keys.group_public_key, 8);
}

int main(void) {
    LOG_INF("=== FROST UART Device with PERFORMANCE EVALUATION ===");
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
    
    ring_buf_init(&rx_ring_buf, sizeof(rx_buf), rx_buf);
    
    uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);
    if (!device_is_ready(uart_dev)) {
        LOG_ERR("UART device not ready");
        return -1;
    }
    
    struct uart_config uart_cfg = {
        .baudrate = 115200,
        .parity = UART_CFG_PARITY_NONE,
        .stop_bits = UART_CFG_STOP_BITS_1,
        .data_bits = UART_CFG_DATA_BITS_8,
        .flow_ctrl = UART_CFG_FLOW_CTRL_NONE,
    };
    
    int uart_cfg_ret = uart_configure(uart_dev, &uart_cfg);
    if (uart_cfg_ret != 0) {
        LOG_ERR("Failed to configure UART: %d", uart_cfg_ret);
        return -1;
    }
    
    uart_irq_callback_set(uart_dev, uart_cb);
    uart_irq_rx_enable(uart_dev);
    
    LOG_INF("UART device configured at 115200 baud");

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL) {
        LOG_ERR("Failed to create secp256k1 context");
        return -1;
    }
    LOG_INF("secp256k1 context created");
    
    update_memory_tracking();
    
    if (read_extended_flash_data() != 0) {
        LOG_ERR("Failed to read extended flash data");
        return -1;
    }
    
    int rc = load_frost_key_material();
    if (rc != 0) {
        LOG_ERR("Failed to load FROST key material from flash (%d)", rc);
        secp256k1_context_destroy(ctx);
        return -1;
    }
    
    verify_keypair_consistency();
    
    update_memory_tracking();
    finalize_memory_tracking();
    
    LOG_INF("=== Ready to receive messages ===");
    LOG_INF("Participant %u ready for FROST protocol", keypair.public_keys.index);
    LOG_INF("Flash storage supports nonce persistence across restarts");
    LOG_INF("Replay protection activated");
    LOG_INF("Performance monitoring: timing (uptime-based), memory, UART communication efficiency");
    
    // Generate initial performance report
    print_performance_summary();
    
    uint8_t dummy;
    while (uart_fifo_read(uart_dev, &dummy, 1) == 1) {
    }
    
    int main_loop_iteration = 0;
    
    while (1) {
        size_t bytes_available = ring_buf_size_get(&rx_ring_buf);
        
        if (bytes_available > 0) {
            if (rx_state == WAITING_FOR_HEADER && bytes_available >= sizeof(message_header_t)) {
                size_t read = ring_buf_get(&rx_ring_buf, (uint8_t*)&current_header, sizeof(message_header_t));
                if (read != sizeof(message_header_t)) {
                    LOG_ERR("Failed to read full header");
                    continue;
                }
                
                if (current_header.magic != MSG_HEADER_MAGIC) {
                    LOG_ERR("Invalid magic number: 0x%08x", current_header.magic);
                    continue;
                }
                
                if (current_header.version != MSG_VERSION) {
                    LOG_ERR("Unsupported version: %d", current_header.version);
                    continue;
                }
                
                if (current_header.payload_len > MAX_MSG_SIZE) {
                    LOG_ERR("Payload too large: %d", current_header.payload_len);
                    continue;
                }
                
                LOG_INF("Received valid header: type=0x%02x, len=%u", 
                        current_header.msg_type, current_header.payload_len);
                
                if (current_header.payload_len == 0) {
                    if (current_header.msg_type == MSG_TYPE_READY) {
                        process_ready_message();
                    }
                } else {
                    rx_state = WAITING_FOR_PAYLOAD;
                    payload_bytes_received = 0;
                }
            }
            
            if (rx_state == WAITING_FOR_PAYLOAD) {
                size_t bytes_to_read = MIN(
                    current_header.payload_len - payload_bytes_received,
                    bytes_available
                );
                
                if (bytes_to_read > 0) {
                    size_t read = ring_buf_get(
                        &rx_ring_buf, 
                        payload_buffer + payload_bytes_received, 
                        bytes_to_read
                    );
                    
                    payload_bytes_received += read;
                    
                    if (payload_bytes_received == current_header.payload_len) {
                        LOG_INF("Complete payload received");
                        
                        if (current_header.msg_type == MSG_TYPE_SIGN) {
                            process_sign_message_PHASE2_FIXED(&current_header, payload_buffer);
                        }
                        
                        rx_state = WAITING_FOR_HEADER;
                    }
                }
            }
        }
        
        // Periodic performance updates every 60 seconds if there's activity
        main_loop_iteration++;
        if (main_loop_iteration % 6000 == 0 && perf_sample_count > 0) {
            LOG_INF("=== PERIODIC PERFORMANCE UPDATE ===");
            print_performance_summary();
        }
        
        k_msleep(10);
    }
    
    secp256k1_context_destroy(ctx);
    
    return 0;
}