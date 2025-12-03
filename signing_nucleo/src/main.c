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
    LOG_INF("✅ Extended flash data loaded - Participant: %u", flash_data.keypair_index);
    
    if (flash_data.nonce_valid) {
        LOG_INF("💾 Stored nonce found - Session ID: %u, Used: %s", 
                flash_data.nonce_session_id, 
                flash_data.nonce_used ? "YES" : "NO");
    } else {
        LOG_INF("💾 No valid stored nonce found");
    }
    
    return 0;
}

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
    LOG_INF("✅ Extended flash data written successfully");
    return 0;
}

static int save_nonce_to_flash(const secp256k1_frost_nonce *nonce, uint32_t session_id) {
    if (!nonce || !flash_data_valid) {
        LOG_ERR("❌ Cannot save nonce - invalid parameters");
        return -EINVAL;
    }

    LOG_INF("💾 === SAVING NONCE TO FLASH ===");
    
    flash_data.nonce_session_id = session_id;
    memcpy(flash_data.nonce_hiding_secret, nonce->hiding, 32);
    memcpy(flash_data.nonce_binding_secret, nonce->binding, 32);
    memcpy(flash_data.nonce_hiding_commitment, nonce->commitments.hiding, 64);
    memcpy(flash_data.nonce_binding_commitment, nonce->commitments.binding, 64);
    flash_data.nonce_used = 0;
    flash_data.nonce_valid = 1;
    
    int rc = write_extended_flash_data();
    if (rc != 0) {
        LOG_ERR("❌ Failed to save nonce to flash: %d", rc);
        return rc;
    }
    
    LOG_INF("✅ Nonce persisted to flash - safe for device restart");
    LOG_INF("💾 Session ID: %u", session_id);
    log_hex("💾 Hiding secret saved", flash_data.nonce_hiding_secret, 8);
    log_hex("💾 Binding secret saved", flash_data.nonce_binding_secret, 8);
    log_hex("💾 Hiding commitment saved", flash_data.nonce_hiding_commitment, 16);
    log_hex("💾 Binding commitment saved", flash_data.nonce_binding_commitment, 16);
    
    return 0;
}

static secp256k1_frost_nonce* load_original_nonce_from_flash(uint32_t expected_session_id) {
    if (!flash_data_valid) {
        LOG_ERR("❌ Cannot load nonce - flash data invalid");
        return NULL;
    }
    
    if (!flash_data.nonce_valid) {
        LOG_ERR("❌ No valid nonce stored in flash");
        return NULL;
    }
    
    if (flash_data.nonce_session_id != expected_session_id) {
        LOG_WRN("⚠️ Session ID mismatch - stored: %u, expected: %u", 
                flash_data.nonce_session_id, expected_session_id);
    }
    
    if (flash_data.nonce_used) {
        LOG_ERR("❌ Stored nonce already used - replay protection activated");
        return NULL;
    }
    
    LOG_INF("💾 === LOADING ORIGINAL NONCE FROM FLASH ===");
    
    secp256k1_frost_nonce* restored_nonce = 
        (secp256k1_frost_nonce*)k_malloc(sizeof(secp256k1_frost_nonce));
    
    if (!restored_nonce) {
        LOG_ERR("❌ Failed to allocate memory for restored nonce");
        return NULL;
    }
    
    memcpy(restored_nonce->hiding, flash_data.nonce_hiding_secret, 32);
    memcpy(restored_nonce->binding, flash_data.nonce_binding_secret, 32);
    restored_nonce->commitments.index = keypair.public_keys.index;
    memcpy(restored_nonce->commitments.hiding, flash_data.nonce_hiding_commitment, 64);
    memcpy(restored_nonce->commitments.binding, flash_data.nonce_binding_commitment, 64);
    restored_nonce->used = 0;
    
    LOG_INF("✅ Original nonce restored from flash");
    LOG_INF("💾 Session ID: %u", flash_data.nonce_session_id);
    log_hex("💾 Hiding secret restored", restored_nonce->hiding, 8);
    log_hex("💾 Binding secret restored", restored_nonce->binding, 8);
    log_hex("💾 Hiding commitment", restored_nonce->commitments.hiding, 16);
    log_hex("💾 Binding commitment", restored_nonce->commitments.binding, 16);
    
    return restored_nonce;
}

static int mark_nonce_as_used(void) {
    if (!flash_data_valid || !flash_data.nonce_valid) {
        LOG_ERR("❌ Cannot mark nonce as used - invalid flash data");
        return -EINVAL;
    }
    
    LOG_INF("🔒 === MARKING NONCE AS USED ===");
    
    flash_data.nonce_used = 1;
    
    int rc = write_extended_flash_data();
    if (rc != 0) {
        LOG_ERR("❌ Failed to mark nonce as used: %d", rc);
        return rc;
    }
    
    LOG_INF("✅ Nonce marked as used - replay protection activated");
    return 0;
}

static bool verify_commitment_consistency(const serialized_nonce_commitment_t* coordinator_commitment) {
    if (!flash_data_valid || !flash_data.nonce_valid) {
        LOG_ERR("❌ Cannot verify commitment - no stored nonce");
        return false;
    }
    
    LOG_INF("🔍 === VERIFYING COMMITMENT CONSISTENCY ===");
    
    bool hiding_match = (memcmp(coordinator_commitment->hiding, 
                                flash_data.nonce_hiding_commitment, 64) == 0);
    bool binding_match = (memcmp(coordinator_commitment->binding, 
                                 flash_data.nonce_binding_commitment, 64) == 0);
    
    LOG_INF("🔍 Commitment verification:");
    LOG_INF("🔍   Index match: %s (%u vs %u)", 
            (coordinator_commitment->index == keypair.public_keys.index) ? "✅ YES" : "❌ NO",
            coordinator_commitment->index, keypair.public_keys.index);
    LOG_INF("🔍   Hiding match: %s", hiding_match ? "✅ YES" : "❌ NO");
    LOG_INF("🔍   Binding match: %s", binding_match ? "✅ YES" : "❌ NO");
    
    if (!hiding_match) {
        LOG_ERR("❌ Hiding commitment mismatch!");
        log_hex("Expected (stored)", flash_data.nonce_hiding_commitment, 16);
        log_hex("Received (coordinator)", coordinator_commitment->hiding, 16);
    }
    
    if (!binding_match) {
        LOG_ERR("❌ Binding commitment mismatch!");
        log_hex("Expected (stored)", flash_data.nonce_binding_commitment, 16);
        log_hex("Received (coordinator)", coordinator_commitment->binding, 16);
    }
    
    bool all_match = hiding_match && binding_match && 
                     (coordinator_commitment->index == keypair.public_keys.index);
    
    if (all_match) {
        LOG_INF("✅ Commitment verification passed - coordinator has correct data");
    } else {
        LOG_ERR("❌ Commitment verification failed - data inconsistency detected");
    }
    
    return all_match;
}

int load_frost_key_material(void) {
    if (!flash_data_valid) return -1;
    
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
    
    keypair_loaded = true;
    LOG_INF("✅ FROST key material loaded successfully");
    LOG_INF("👤 Participant Index: %u", keypair.public_keys.index);
    LOG_INF("📊 Max Participants: %u", keypair.public_keys.max_participants);
    
    return 0;
}

static int uart_send_data(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uart_poll_out(uart_dev, data[i]);
        k_usleep(100);
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

    LOG_INF("📤 Sending message: type=0x%02X, participant=%u, len=%u", 
            msg_type, participant, payload_len);

    int ret = uart_send_data((uint8_t*)&header, sizeof(header));
    if (ret < 0) {
        LOG_ERR("❌ Failed to send header");
        return false;
    }

    if (payload_len > 0 && payload != NULL) {
        ret = uart_send_data(payload, payload_len);
        if (ret < 0) {
            LOG_ERR("❌ Failed to send payload");
            return false;
        }
    }

    LOG_INF("✅ Message sent successfully");
    return true;
}

static int generate_and_save_nonce_PHASE1(void) {
    LOG_INF("🔑 === PHASE 1: GENERATE AND PERSIST NONCE ===");
    
    if (!flash_data_valid) {
        LOG_ERR("❌ Flash data not valid, cannot proceed");
        return -1;
    }
    
    current_session_id = sys_rand32_get();
    
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};

    if (!fill_random(binding_seed, sizeof(binding_seed))) {
        LOG_ERR("❌ Failed to generate binding_seed");
        return -1;
    }
    if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
        LOG_ERR("❌ Failed to generate hiding_seed");
        return -1;
    }

    LOG_INF("🎲 Generating fresh nonce for participant %u", keypair.public_keys.index);
    LOG_INF("🆔 Session ID: %u", current_session_id);
    log_hex("🔑 Binding seed", binding_seed, 8);
    log_hex("🔑 Hiding seed", hiding_seed, 8);

    secp256k1_frost_nonce* fresh_nonce = secp256k1_frost_nonce_create(ctx, &keypair, binding_seed, hiding_seed);
    if (!fresh_nonce) {
        LOG_ERR("❌ Failed to create fresh nonce");
        return -1;
    }

    LOG_INF("✅ Fresh nonce generated successfully");
    log_hex("🔐 Generated hiding commitment", fresh_nonce->commitments.hiding, 16);
    log_hex("🔐 Generated binding commitment", fresh_nonce->commitments.binding, 16);
    
    int save_result = save_nonce_to_flash(fresh_nonce, current_session_id);
    if (save_result != 0) {
        LOG_ERR("❌ Failed to save nonce to flash!");
        secp256k1_frost_nonce_destroy(fresh_nonce);
        return -1;
    }
    
    secp256k1_frost_nonce_destroy(fresh_nonce);
    
    LOG_INF("🎉 PHASE 1 NONCE GENERATION AND PERSISTENCE COMPLETE");
    LOG_INF("💾 Device can safely restart - nonce is preserved in flash");
    
    return 0;
}

static bool send_nonce_commitment_and_keypair_PHASE1(void) {
    LOG_INF("📤 === PHASE 1: SENDING NONCE COMMITMENT AND KEYPAIR ===");
    
    if (!flash_data_valid || !flash_data.nonce_valid) {
        LOG_ERR("❌ No valid nonce data available");
        return false;
    }
    
    size_t payload_len = sizeof(serialized_nonce_commitment_t) + sizeof(serialized_keypair_t);
    uint8_t* combined_payload = k_malloc(payload_len);
    if (!combined_payload) {
        LOG_ERR("❌ Failed to allocate memory for combined payload");
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

    LOG_INF("📤 *** SENDING PERSISTED NONCE COMMITMENT AND KEYPAIR ***");
    LOG_INF("📋 Participant: %u", keypair.public_keys.index);
    LOG_INF("🆔 Session ID: %u", flash_data.nonce_session_id);
    log_hex("📤 Sending hiding commitment", nonce_part->hiding, 16);
    log_hex("📤 Sending binding commitment", nonce_part->binding, 16);
    
    bool result = send_message(MSG_TYPE_NONCE_COMMITMENT, 
                              keypair.public_keys.index,
                              combined_payload, payload_len);
    
    k_free(combined_payload);
    
    if (result) {
        LOG_INF("✅ PHASE 1 SUCCESS: Persisted nonce commitment and keypair sent");
    } else {
        LOG_ERR("❌ PHASE 1 FAILED: Failed to send nonce commitment and keypair");
    }
    
    return result;
}

static bool send_signature_share_and_mark_used_PHASE3(void) {
    LOG_INF("📤 === PHASE 3: SENDING SIGNATURE SHARE AND MARKING NONCE USED ===");
    
    if (!signature_share_computed) {
        LOG_ERR("❌ No signature share computed yet");
        return false;
    }

    serialized_signature_share_t serialized;
    serialized.index = keypair.public_keys.index;
    memcpy(serialized.response, computed_signature_share.response, 32);

    LOG_INF("📤 *** SENDING SIGNATURE SHARE TO COORDINATOR ***");
    LOG_INF("📋 Participant: %u", keypair.public_keys.index);
    log_hex("📤 Signature Share", serialized.response, 32);

    bool result = send_message(MSG_TYPE_SIGNATURE_SHARE, 
                              keypair.public_keys.index,
                              &serialized, sizeof(serialized));
    
    if (result) {
        LOG_INF("✅ PHASE 3 SUCCESS: Signature share sent to coordinator");
        
        int mark_result = mark_nonce_as_used();
        if (mark_result == 0) {
            LOG_INF("🔒 Nonce marked as used - replay protection activated");
        } else {
            LOG_WRN("⚠️ Failed to mark nonce as used, but signature sent");
        }
        
        send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0);
    } else {
        LOG_ERR("❌ PHASE 3 FAILED: Failed to send signature share");
    }
    
    return result;
}

static void process_sign_message_PHASE2_FIXED(const message_header_t *header, const uint8_t *payload) {
    LOG_INF("📝 === PHASE 2: PROCESSING SIGN MESSAGE (FIXED - ORIGINAL NONCE) ===");
    
    if (header->payload_len < 32 + 4) {
        LOG_ERR("❌ Invalid sign message length");
        return;
    }
    
    uint8_t* msg_hash = (uint8_t*)payload;
    uint32_t num_commitments = *(uint32_t*)(payload + 32);
    serialized_nonce_commitment_t* serialized_commitments = (serialized_nonce_commitment_t*)(payload + 32 + 4);
    
    LOG_INF("📝 *** PROCESSING SIGN MESSAGE DATA ***");
    LOG_INF("📋 Message hash (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x...", 
            msg_hash[0], msg_hash[1], msg_hash[2], msg_hash[3],
            msg_hash[4], msg_hash[5], msg_hash[6], msg_hash[7]);
    LOG_INF("📋 Number of commitments: %u", num_commitments);
    
    unsigned char expected_msg[12] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    unsigned char expected_hash[32];
    unsigned char tag[14] = {'f', 'r', 'o', 's', 't', '_', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};
    secp256k1_tagged_sha256(ctx, expected_hash, tag, sizeof(tag), expected_msg, sizeof(expected_msg));
    
    if (memcmp(msg_hash, expected_hash, 32) != 0) {
        LOG_ERR("❌ Message hash verification FAILED!");
        LOG_ERR("❌ This device will NOT produce a valid signature share");
        return;
    }
    LOG_INF("✅ Message hash verified correctly");
    
    serialized_nonce_commitment_t* our_commitment_from_coordinator = NULL;
    
    for (uint32_t i = 0; i < num_commitments; i++) {
        LOG_INF("🔍 Checking commitment %u: participant %u", i, serialized_commitments[i].index);
        
        if (serialized_commitments[i].index == keypair.public_keys.index) {
            our_commitment_from_coordinator = &serialized_commitments[i];
            LOG_INF("🎯 Found our commitment at position %u", i);
            break;
        }
    }
    
    if (!our_commitment_from_coordinator) {
        LOG_ERR("❌ Our commitment not found in coordinator's list!");
        return;
    }
    
    if (!verify_commitment_consistency(our_commitment_from_coordinator)) {
        LOG_ERR("❌ Commitment consistency verification failed!");
        return;
    }
    
    secp256k1_frost_nonce* original_nonce = 
        load_original_nonce_from_flash(current_session_id);
    
    if (!original_nonce) {
        LOG_ERR("❌ Failed to load original nonce from flash");
        return;
    }
    
    LOG_INF("🎉 Using ORIGINAL nonce from flash persistence");
    
    secp256k1_frost_nonce_commitment *signing_commitments = 
        k_malloc(num_commitments * sizeof(secp256k1_frost_nonce_commitment));
    if (!signing_commitments) {
        LOG_ERR("❌ Failed to allocate memory for signing commitments");
        k_free(original_nonce);
        return;
    }
    
    for (uint32_t i = 0; i < num_commitments; i++) {
        signing_commitments[i].index = serialized_commitments[i].index;
        memcpy(signing_commitments[i].hiding, serialized_commitments[i].hiding, 64);
        memcpy(signing_commitments[i].binding, serialized_commitments[i].binding, 64);
        
        LOG_INF("📋 Commitment %u: participant %u", i, signing_commitments[i].index);
    }
    
    LOG_INF("🔄 Computing signature share using ORIGINAL nonce from flash...");
    LOG_INF("📋 Participant index: %u", keypair.public_keys.index);
    LOG_INF("📋 Number of signers: %u", num_commitments);
    LOG_INF("🔐 Using original nonce secrets from flash persistence");
    
    memset(&computed_signature_share, 0, sizeof(computed_signature_share));
    
    int return_val = secp256k1_frost_sign(&computed_signature_share,
                                         msg_hash, num_commitments,
                                         &keypair, original_nonce, signing_commitments);
    
    if (return_val == 1) {
        signature_share_computed = true;
        
        LOG_INF("🎉 *** SIGNATURE SHARE COMPUTED SUCCESSFULLY ***");
        LOG_INF("🎉 Used ORIGINAL nonce from flash persistence");
        log_hex("🎯 SIGNATURE SHARE (32 bytes)", computed_signature_share.response, 32);
        
        bool all_zeros = true;
        for (int i = 0; i < 32; i++) {
            if (computed_signature_share.response[i] != 0) {
                all_zeros = false;
                break;
            }
        }
        
        if (all_zeros) {
            LOG_ERR("❌ Signature share is all zeros - this indicates an error!");
            signature_share_computed = false;
        } else {
            LOG_INF("✅ Signature share appears valid (not all zeros)");
            
            char hex_str[65];
            for (int i = 0; i < 32; i++) {
                sprintf(hex_str + i * 2, "%02x", computed_signature_share.response[i]);
            }
            hex_str[64] = '\0';
            printk("\n\n=== FROST SIGNATURE SHARE ===\n");
            printk("Participant: %u\n", keypair.public_keys.index);
            printk("Signature: %s\n", hex_str);
            printk("=============================\n\n");
            
            send_signature_share_and_mark_used_PHASE3();
        }
        
    } else {
        LOG_ERR("❌ Failed to compute signature share (return_val=%d)", return_val);
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
    LOG_INF("📨 *** Received READY signal ***");
    
    if (generate_and_save_nonce_PHASE1() == 0) {
        send_nonce_commitment_and_keypair_PHASE1();
    }
}

static void verify_keypair_consistency(void) {
    LOG_INF("🔍 === KEYPAIR CONSISTENCY VERIFICATION ===");
    
    if (keypair.public_keys.index == 0 || keypair.public_keys.index > 255) {
        LOG_ERR("❌ Invalid participant index: %u", keypair.public_keys.index);
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
        LOG_ERR("❌ Secret key is all zeros!");
        return;
    }
    
    bool pub_zeros = true, group_zeros = true;
    for (int i = 0; i < 64; i++) {
        if (keypair.public_keys.public_key[i] != 0) pub_zeros = false;
        if (keypair.public_keys.group_public_key[i] != 0) group_zeros = false;
    }
    
    if (pub_zeros || group_zeros) {
        LOG_ERR("❌ Public keys contain all zeros!");
        return;
    }
    
    LOG_INF("✅ Keypair consistency verified");
    LOG_INF("  Index: %u", keypair.public_keys.index);
    LOG_INF("  Max participants: %u", keypair.public_keys.max_participants);
    log_hex("  Secret (first 8 bytes)", keypair.secret, 8);
    log_hex("  Public key (first 8 bytes)", keypair.public_keys.public_key, 8);
    log_hex("  Group key (first 8 bytes)", keypair.public_keys.group_public_key, 8);
}

int main(void) {
    LOG_INF("🚀 === FROST UART Device with NONCE PERSISTENCE ===");
    LOG_INF("💾 Nonces survive device restarts via flash storage");
    
    ring_buf_init(&rx_ring_buf, sizeof(rx_buf), rx_buf);
    
    uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);
    if (!device_is_ready(uart_dev)) {
        LOG_ERR("❌ UART device not ready");
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
        LOG_ERR("❌ Failed to configure UART: %d", uart_cfg_ret);
        return -1;
    }
    
    uart_irq_callback_set(uart_dev, uart_cb);
    uart_irq_rx_enable(uart_dev);
    
    LOG_INF("✅ UART device configured at 115200 baud");

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL) {
        LOG_ERR("❌ Failed to create secp256k1 context");
        return -1;
    }
    LOG_INF("✅ secp256k1 context created");
    
    if (read_extended_flash_data() != 0) {
        LOG_ERR("❌ Failed to read extended flash data");
        return -1;
    }
    
    int rc = load_frost_key_material();
    if (rc != 0) {
        LOG_ERR("❌ Failed to load FROST key material from flash (%d)", rc);
        secp256k1_context_destroy(ctx);
        return -1;
    }
    
    verify_keypair_consistency();
    
    LOG_INF("🎯 === Ready to receive messages ===");
    LOG_INF("👤 Participant %u ready for FROST protocol", keypair.public_keys.index);
    LOG_INF("💾 Flash storage supports nonce persistence across restarts");
    LOG_INF("🔒 Replay protection activated");
    
    uint8_t dummy;
    while (uart_fifo_read(uart_dev, &dummy, 1) == 1) {
    }
    
    while (1) {
        size_t bytes_available = ring_buf_size_get(&rx_ring_buf);
        
        if (bytes_available > 0) {
            if (rx_state == WAITING_FOR_HEADER && bytes_available >= sizeof(message_header_t)) {
                size_t read = ring_buf_get(&rx_ring_buf, (uint8_t*)&current_header, sizeof(message_header_t));
                if (read != sizeof(message_header_t)) {
                    LOG_ERR("❌ Failed to read full header");
                    continue;
                }
                
                if (current_header.magic != MSG_HEADER_MAGIC) {
                    LOG_ERR("❌ Invalid magic number: 0x%08x", current_header.magic);
                    continue;
                }
                
                if (current_header.version != MSG_VERSION) {
                    LOG_ERR("❌ Unsupported version: %d", current_header.version);
                    continue;
                }
                
                if (current_header.payload_len > MAX_MSG_SIZE) {
                    LOG_ERR("❌ Payload too large: %d", current_header.payload_len);
                    continue;
                }
                
                LOG_INF("📨 Received valid header: type=0x%02x, len=%u", 
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
                        LOG_INF("📦 Complete payload received");
                        
                        if (current_header.msg_type == MSG_TYPE_SIGN) {
                            process_sign_message_PHASE2_FIXED(&current_header, payload_buffer);
                        }
                        
                        rx_state = WAITING_FOR_HEADER;
                    }
                }
            }
        }
        
        k_msleep(10);
    }
    
    secp256k1_context_destroy(ctx);
    
    return 0;
}