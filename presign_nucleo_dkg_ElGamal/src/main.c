// Board/Device FROST DKG - END-TO-END ENCRYPTED SHARES
// Shares are encrypted before sending, never sent in plaintext
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/random/random.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <secp256k1_ecdh.h>
#include "examples_util.h"

LOG_MODULE_REGISTER(frost_dkg_device, LOG_LEVEL_INF);

#define RING_BUF_SIZE 2048
#define MAX_MSG_SIZE 2048           
#define UART_DEVICE_NODE DT_NODELABEL(usart1)
#define DKG_CONTEXT_SIZE 32
#define MAX_PARTICIPANTS 10
#define SECRET_VALUE_SIZE 32

#define MSG_HEADER_MAGIC 0x46524F53
#define MSG_VERSION 0x01

typedef enum {
    MSG_TYPE_DKG_CONTEXT = 0x10,
    MSG_TYPE_DKG_COMMITMENT = 0x11,
    MSG_TYPE_DKG_ALL_COMMITMENTS = 0x12,
    MSG_TYPE_DKG_VALIDATION_RESULT = 0x13,
    MSG_TYPE_DKG_FINALIZE = 0x15,
    MSG_TYPE_DKG_COMPLETE = 0x16,
    MSG_TYPE_DKG_SEND_SHARES = 0x17,
    MSG_TYPE_READY = 0x06,
    MSG_TYPE_PING = 0x09,
    MSG_TYPE_ELGAMAL_READY = 0x20,
    MSG_TYPE_ELGAMAL_PUBKEY = 0x21,
    MSG_TYPE_ELGAMAL_PUBKEY_LIST = 0x22,
    MSG_TYPE_DKG_SECRET_SHARE_ENCRYPTED = 0x31
} message_type_t;

typedef struct {
    uint32_t magic;       
    uint8_t version;       
    uint8_t msg_type;      
    uint16_t payload_len;  
    uint32_t participant;  
} __packed message_header_t;

typedef struct {
    uint32_t num_participants;
    uint32_t threshold;
    uint8_t context[DKG_CONTEXT_SIZE];
} __packed serialized_dkg_context_t;

typedef struct {
    uint32_t index;
    uint32_t num_coefficients;
    uint8_t zkp_z[32];
    uint8_t zkp_r[64];
    uint8_t coefficient_commitments[];
} __packed serialized_dkg_commitment_t;

typedef struct {
    uint32_t participant_index;
    bool validation_result;
} __packed serialized_validation_result_t;

typedef struct {
    uint8_t private_key[32];       
    secp256k1_pubkey public_key;   
} ecc_elgamal_keypair_t;

typedef struct {
    uint32_t participant_index;
    uint8_t public_key_serialized[33];  
} __packed serialized_elgamal_pubkey_t;

typedef struct {
    uint32_t num_participants;
    serialized_elgamal_pubkey_t pubkeys[];  
} __packed serialized_elgamal_pubkey_list_t;

typedef struct {
    uint32_t generator_index;
    uint32_t receiver_index;
    uint8_t c1_serialized[33];
    uint8_t c2[SECRET_VALUE_SIZE];
} __packed encrypted_share_message_t;

typedef struct {
    uint32_t participant_index;
    uint8_t public_key_serialized[33];
    bool is_valid;  
} elgamal_pubkey_storage_t;

typedef struct {
    uint32_t num_shares;
    encrypted_share_message_t shares[];
} __packed serialized_encrypted_shares_batch_t;

#define STORAGE_PARTITION storage_partition

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
    uint8_t commitments_coefficient_data[10 * sizeof(secp256k1_frost_vss_commitment)];
} __packed frost_flash_storage_t;

static secp256k1_context *ctx;                     
static secp256k1_frost_keypair keypair;            
static secp256k1_frost_vss_commitments *my_commitment = NULL;
static secp256k1_frost_keygen_secret_share my_shares[MAX_PARTICIPANTS];
static secp256k1_frost_keygen_secret_share received_shares[MAX_PARTICIPANTS];
static secp256k1_frost_vss_commitments* all_commitments[MAX_PARTICIPANTS] = {0};

static elgamal_pubkey_storage_t elgamal_pubkeys[MAX_PARTICIPANTS];
static uint32_t num_elgamal_pubkeys = 0;

static ecc_elgamal_keypair_t our_elgamal_keypair;
static bool elgamal_keypair_ready = false;

static uint8_t rx_buf[RING_BUF_SIZE];   
static struct ring_buf rx_ring_buf;     
static const struct device *uart_dev;   

static uint32_t my_participant_index = 0;
static uint32_t dkg_num_participants = 0;
static uint32_t dkg_threshold = 0;
static uint8_t dkg_context[DKG_CONTEXT_SIZE];
static uint32_t shares_received = 0;
static uint32_t commitments_received = 0;

typedef enum {
    WAITING_FOR_HEADER,     
    WAITING_FOR_PAYLOAD     
} receive_state_t;

static receive_state_t rx_state = WAITING_FOR_HEADER;  
static message_header_t current_header;                
static uint8_t payload_buffer[MAX_MSG_SIZE];           
static size_t payload_bytes_received = 0;

static int ecc_elgamal_encrypt_value(const secp256k1_pubkey *recipient_pubkey,
                                     const uint8_t *value_32_bytes,
                                     secp256k1_pubkey *c1_out, uint8_t *c2_out) {
    uint8_t ephemeral_key[32];      
    uint8_t shared_secret[32];      
    
    sys_rand_get(ephemeral_key, 32); // Get r, the epheremal key
    if (ephemeral_key[0] == 0) ephemeral_key[0] = 0x01;
    
    if (!secp256k1_ec_pubkey_create(ctx, c1_out, ephemeral_key)) { // Compute c1 = r*G
        LOG_ERR("Failed to create ephemeral public key");
        memset(ephemeral_key, 0, sizeof(ephemeral_key));
        return 0;
    }
    
    if (!secp256k1_ecdh(ctx, shared_secret, recipient_pubkey, ephemeral_key, // Compute shared secret r*pk
                        secp256k1_ecdh_hash_function_sha256, NULL)) {
        LOG_ERR("Failed to compute ECDH shared secret");
        memset(ephemeral_key, 0, sizeof(ephemeral_key));
        return 0;
    }
    
    for (int i = 0; i < SECRET_VALUE_SIZE; i++) {
        c2_out[i] = shared_secret[i] ^ value_32_bytes[i];
    }
    
    memset(ephemeral_key, 0, sizeof(ephemeral_key));
    memset(shared_secret, 0, sizeof(shared_secret));
    
    return 1;
}

static int ecc_elgamal_decrypt_value(const ecc_elgamal_keypair_t *keypair,
                                     const secp256k1_pubkey *c1, const uint8_t *c2,
                                     uint8_t *value_32_bytes_out) {
    uint8_t shared_secret[32];      
    
    if (!secp256k1_ecdh(ctx, shared_secret, c1, keypair->private_key,  // Compute hashed shared secret sk*c1  
                        secp256k1_ecdh_hash_function_sha256, NULL)) {
        LOG_ERR("Failed to compute ECDH shared secret for decryption");
        return 0;
    }
    
    for (int i = 0; i < SECRET_VALUE_SIZE; i++) {
        value_32_bytes_out[i] = c2[i] ^ shared_secret[i]; // value = c2 XOR shared_secret
    }
    
    memset(shared_secret, 0, sizeof(shared_secret));
    return 1;
}

static secp256k1_pubkey* find_participant_pubkey(uint32_t participant_index) {
    static secp256k1_pubkey found_pubkey;  
    
    for (uint32_t i = 0; i < num_elgamal_pubkeys; i++) {
        if (elgamal_pubkeys[i].participant_index == participant_index && 
            elgamal_pubkeys[i].is_valid) {
            if (secp256k1_ec_pubkey_parse(ctx, &found_pubkey, 
                                         elgamal_pubkeys[i].public_key_serialized, 33)) {
                return &found_pubkey;
            }
            break;
        }
    }
    return NULL;
}

static int ecc_elgamal_keygen(ecc_elgamal_keypair_t *keypair) {
    LOG_INF("=== ElGamal Key Generation ===");
    
    sys_rand_get(keypair->private_key, 32);
    
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (keypair->private_key[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        keypair->private_key[0] = 0x01;
    }
    
    if (!secp256k1_ec_pubkey_create(ctx, &keypair->public_key, keypair->private_key)) {
        LOG_ERR("Failed to create public key");
        return 0;
    }
    
    LOG_INF("ElGamal keypair generated successfully");
    
    return 1;
}

static void print_elgamal_private_key_hex(const char *label, const uint8_t *private_key) {
    char hex_buf[65];
    for (int i = 0; i < 32; i++) {
        snprintf(&hex_buf[i * 2], 3, "%02x", private_key[i]);
    }
    hex_buf[64] = '\0';
    
    LOG_INF("%s: %s", label, hex_buf);
}

static void print_elgamal_public_key_hex(const char *label, const secp256k1_pubkey *pubkey) {
    uint8_t serialized[33];
    size_t len = 33;
    
    if (secp256k1_ec_pubkey_serialize(ctx, serialized, &len, pubkey, SECP256K1_EC_COMPRESSED)) {
        char hex_buf[67];
        for (int i = 0; i < 33; i++) {
            snprintf(&hex_buf[i * 2], 3, "%02x", serialized[i]);
        }
        hex_buf[66] = '\0';
        LOG_INF("%s: %s", label, hex_buf);
    }
}

static void print_all_received_elgamal_pubkeys(void) {
    LOG_INF("=== Received ElGamal Public Keys ===");
    LOG_INF("Total participants: %u", num_elgamal_pubkeys);
    
    for (uint32_t i = 0; i < num_elgamal_pubkeys; i++) {
        if (elgamal_pubkeys[i].is_valid) {
            char hex_buf[67];
            for (int j = 0; j < 33; j++) {
                snprintf(&hex_buf[j * 2], 3, "%02x", 
                        elgamal_pubkeys[i].public_key_serialized[j]);
            }
            hex_buf[66] = '\0';
            
            LOG_INF("Participant %u: %s", elgamal_pubkeys[i].participant_index, hex_buf);
        }
    }
    LOG_INF("=====================================");
}

void log_hex_bytes(const char *label, const unsigned char *data, size_t len) {
    char hex_buf[129];
    size_t display_len = len > 64 ? 64 : len;
    
    for (size_t i = 0; i < display_len; i++) {
        snprintf(&hex_buf[i * 2], 3, "%02x", data[i]);
    }
    hex_buf[display_len * 2] = '\0';
    
    LOG_INF("%s (%zu bytes): %s%s", label, len, hex_buf, len > 64 ? "..." : "");
}

static int write_frost_data_to_flash(void) {
    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc != 0) {
        LOG_ERR("Failed to open flash area: %d", rc);
        return rc;
    }

    rc = flash_area_erase(fa, 0, fa->fa_size);
    if (rc != 0) {
        LOG_ERR("Failed to erase flash: %d", rc);
        flash_area_close(fa);
        return rc;
    }

    frost_flash_storage_t flash_data = {0};
    
    flash_data.keypair_index = keypair.public_keys.index;
    flash_data.keypair_max_participants = keypair.public_keys.max_participants;
    memcpy(flash_data.keypair_secret, keypair.secret, 32);
    memcpy(flash_data.keypair_public_key, keypair.public_keys.public_key, 64);
    memcpy(flash_data.keypair_group_public_key, keypair.public_keys.group_public_key, 64);
    
    if (my_commitment) {
        flash_data.commitments_index = my_commitment->index;
        flash_data.commitments_num_coefficients = my_commitment->num_coefficients;
        memcpy(flash_data.commitments_zkp_z, my_commitment->zkp_z, 32);
        memcpy(flash_data.commitments_zkp_r, my_commitment->zkp_r, 64);
        
        size_t coef_size = my_commitment->num_coefficients * 
                          sizeof(secp256k1_frost_vss_commitment);
        if (coef_size <= sizeof(flash_data.commitments_coefficient_data)) {
            memcpy(flash_data.commitments_coefficient_data, 
                   my_commitment->coefficient_commitments, coef_size);
        }
    }

    rc = flash_area_write(fa, 0, &flash_data, sizeof(frost_flash_storage_t));
    if (rc != 0) {
        LOG_ERR("Failed to write flash: %d", rc);
        flash_area_close(fa);
        return rc;
    }

    flash_area_close(fa);
    LOG_INF("DKG data written to flash successfully");
    return 0;
}

static int read_frost_data_from_flash(void) {
    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc != 0) {
        LOG_ERR("Failed to open flash area: %d", rc);
        return rc;
    }

    frost_flash_storage_t flash_data;
    rc = flash_area_read(fa, 0, &flash_data, sizeof(frost_flash_storage_t));
    if (rc != 0) {
        LOG_ERR("Failed to read flash: %d", rc);
        flash_area_close(fa);
        return rc;
    }

    if (flash_data.keypair_index > 0 && flash_data.keypair_index <= 255) {
        LOG_INF("=== Stored DKG Keypair ===");
        LOG_INF("Participant Index: %u", flash_data.keypair_index);
        LOG_INF("Max Participants: %u", flash_data.keypair_max_participants);
        
        log_hex_bytes("Secret", flash_data.keypair_secret, 32);
        log_hex_bytes("Public Key", flash_data.keypair_public_key, 64);
        log_hex_bytes("Group Public Key", flash_data.keypair_group_public_key, 64);
    }

    flash_area_close(fa);
    return 0;
}

static void uart_isr(const struct device *dev, void *user_data) {
    uint8_t buffer[64];
    int bytes_read;
    
    ARG_UNUSED(user_data);
    
    while ((bytes_read = uart_fifo_read(dev, buffer, sizeof(buffer))) > 0) {
        int bytes_written = ring_buf_put(&rx_ring_buf, buffer, bytes_read);
        if (bytes_written < bytes_read) {
            LOG_WRN("Ring buffer overflow: %d bytes lost", bytes_read - bytes_written);
        }
    }
}

static int send_data(const uint8_t* data, size_t len) {
    const uint8_t* ptr = data;
    size_t remaining = len;
    
    while (remaining > 0) {
        int bytes_sent = uart_fifo_fill(uart_dev, ptr, remaining);
        if (bytes_sent <= 0) {
            k_msleep(1);
            continue;
        }
        
        ptr += bytes_sent;
        remaining -= bytes_sent;
    }
    
    return 0;
}

static int send_message(uint8_t msg_type, const void* payload, uint16_t payload_len) {
    message_header_t header;
    
    header.magic = MSG_HEADER_MAGIC;
    header.version = MSG_VERSION;
    header.msg_type = msg_type;
    header.payload_len = payload_len;
    header.participant = my_participant_index;
    
    LOG_INF("Sending message: type=0x%02X, len=%u", msg_type, payload_len);
    
    int rc = send_data((uint8_t*)&header, sizeof(header));
    if (rc != 0) {
        LOG_ERR("Failed to send header");
        return -1;
    }
    
    k_msleep(100);
    
    if (payload_len > 0 && payload) {
        rc = send_data((uint8_t*)payload, payload_len);
        if (rc != 0) {
            LOG_ERR("Failed to send payload");
            return -1;
        }
    }
    
    LOG_INF("Message sent successfully");
    k_msleep(500);
    return 0;
}

static void cleanup_dkg_resources(void) {
    LOG_INF("Cleaning up DKG resources");
    
    if (my_commitment) {
        secp256k1_frost_vss_commitments_destroy(my_commitment);
        my_commitment = NULL;
    }
    
    memset(my_shares, 0, sizeof(my_shares));
    memset(received_shares, 0, sizeof(received_shares));
    
    for (uint32_t i = 0; i < MAX_PARTICIPANTS; i++) {
        if (all_commitments[i]) {
            secp256k1_frost_vss_commitments_destroy(all_commitments[i]);
            all_commitments[i] = NULL;
        }
    }
    
    shares_received = 0;
    commitments_received = 0;
    
    LOG_INF("DKG resources cleaned up");
}

static int handle_elgamal_ready(void) {
    LOG_INF("=== ElGamal Phase: Ready Signal Received ===");
    
    uint32_t participant_index = current_header.participant;
    LOG_INF("Using participant index from header: %u", participant_index);
    
    if (!ecc_elgamal_keygen(&our_elgamal_keypair)) {
        LOG_ERR("Failed to generate ElGamal keypair");
        return -1;
    }
    
    elgamal_keypair_ready = true;
    
    LOG_INF("ElGamal keypair generated successfully");
    print_elgamal_private_key_hex("ElGamal Private Key", our_elgamal_keypair.private_key);
    print_elgamal_public_key_hex("ElGamal Public Key", &our_elgamal_keypair.public_key);
    
    serialized_elgamal_pubkey_t elgamal_msg;
    elgamal_msg.participant_index = participant_index;
    
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, elgamal_msg.public_key_serialized, &len, 
                                       &our_elgamal_keypair.public_key, 
                                       SECP256K1_EC_COMPRESSED)) {
        LOG_ERR("Failed to serialize ElGamal public key");
        return -1;
    }
    
    if (send_message(MSG_TYPE_ELGAMAL_PUBKEY, &elgamal_msg, sizeof(elgamal_msg)) != 0) {
        LOG_ERR("Failed to send ElGamal public key");
        return -1;
    }
    
    LOG_INF("ElGamal public key sent to coordinator");
    
    return 0;
}

static int handle_elgamal_pubkey_list(const serialized_elgamal_pubkey_list_t* pubkey_list_msg) {
    LOG_INF("=== Receiving ElGamal Public Key List ===");
    LOG_INF("Number of participants: %u", pubkey_list_msg->num_participants);
    
    if (pubkey_list_msg->num_participants > MAX_PARTICIPANTS) {
        LOG_ERR("Too many participants");
        return -1;
    }
    
    memset(elgamal_pubkeys, 0, sizeof(elgamal_pubkeys));
    num_elgamal_pubkeys = pubkey_list_msg->num_participants;
    
    for (uint32_t i = 0; i < pubkey_list_msg->num_participants; i++) {
        elgamal_pubkeys[i].participant_index = pubkey_list_msg->pubkeys[i].participant_index;
        memcpy(elgamal_pubkeys[i].public_key_serialized, 
               pubkey_list_msg->pubkeys[i].public_key_serialized, 33);
        elgamal_pubkeys[i].is_valid = true;
    }
    
    print_all_received_elgamal_pubkeys();
    
    LOG_INF("Ready to proceed with DKG - shares will be encrypted");
    
    return 0;
}

static int handle_dkg_context_message(const serialized_dkg_context_t* ctx_msg) {
    LOG_INF("=== Phase 1: DKG Context Received ===");
    
    dkg_num_participants = ctx_msg->num_participants;
    dkg_threshold = ctx_msg->threshold;
    memcpy(dkg_context, ctx_msg->context, DKG_CONTEXT_SIZE);
    my_participant_index = current_header.participant;
    
    LOG_INF("Participants: %u, Threshold: %u", dkg_num_participants, dkg_threshold);
    LOG_INF("My participant index: %u", my_participant_index);
    
    if (!elgamal_keypair_ready) {
        LOG_ERR("ElGamal keypair not ready");
        return -1;
    }
    
    cleanup_dkg_resources();
    
    my_commitment = secp256k1_frost_vss_commitments_create(dkg_threshold);
    if (my_commitment == NULL) {
        LOG_ERR("Failed to create VSS commitments");
        return -1;
    }
    
    memset(my_shares, 0, sizeof(my_shares));
    memset(received_shares, 0, sizeof(received_shares));
    
    for (uint32_t i = 0; i < dkg_num_participants; i++) {
        all_commitments[i] = secp256k1_frost_vss_commitments_create(dkg_threshold);
        if (all_commitments[i] == NULL) {
            LOG_ERR("Failed to create commitment %u", i);
            cleanup_dkg_resources();
            return -1;
        }
    }
    
    LOG_INF("Generating DKG commitment and shares...");
    
    int result = secp256k1_frost_keygen_dkg_begin(
        ctx, my_commitment, my_shares, dkg_num_participants, dkg_threshold, 
        my_participant_index, dkg_context, DKG_CONTEXT_SIZE
    );
    
    if (result != 1) {
        LOG_ERR("secp256k1_frost_keygen_dkg_begin failed: result=%d", result);
        cleanup_dkg_resources();
        return -1;
    }
    
    LOG_INF("DKG commitment and shares generated successfully");
    
    uint32_t my_slot = my_participant_index - 1;  
    
    all_commitments[my_slot]->index = my_commitment->index;
    all_commitments[my_slot]->num_coefficients = my_commitment->num_coefficients;
    memcpy(all_commitments[my_slot]->zkp_z, my_commitment->zkp_z, 32);
    memcpy(all_commitments[my_slot]->zkp_r, my_commitment->zkp_r, 64);
    
    size_t coef_data_size = my_commitment->num_coefficients * 
                           sizeof(secp256k1_frost_vss_commitment);
    memcpy(all_commitments[my_slot]->coefficient_commitments, 
           my_commitment->coefficient_commitments, coef_data_size);
    
    size_t total_size = sizeof(serialized_dkg_commitment_t) + coef_data_size;
    
    if (total_size > MAX_MSG_SIZE) {
        LOG_ERR("Commitment message too large");
        cleanup_dkg_resources();
        return -1;
    }
    
    uint8_t* buffer = k_malloc(total_size);
    if (!buffer) {
        LOG_ERR("Memory allocation failed");
        cleanup_dkg_resources();
        return -1;
    }
    
    serialized_dkg_commitment_t* ser_commitment = (serialized_dkg_commitment_t*)buffer;
    ser_commitment->index = my_commitment->index;
    ser_commitment->num_coefficients = my_commitment->num_coefficients;
    memcpy(ser_commitment->zkp_z, my_commitment->zkp_z, 32);
    memcpy(ser_commitment->zkp_r, my_commitment->zkp_r, 64);
    memcpy(ser_commitment->coefficient_commitments, 
           my_commitment->coefficient_commitments, coef_data_size);
    
    int rc = send_message(MSG_TYPE_DKG_COMMITMENT, buffer, (uint16_t)total_size);
    k_free(buffer);
    
    if (rc != 0) {
        LOG_ERR("Failed to send commitment");
        cleanup_dkg_resources();
        return -1;
    }
    
    LOG_INF("Commitment sent to coordinator");
    return 0;
}

static int handle_dkg_all_commitments(const serialized_dkg_commitment_t* commitment_msg) {
    LOG_INF("=== Received Commitment from Participant %u ===", commitment_msg->index);
    
    if (commitment_msg->index == my_participant_index) return 0;
    
    uint32_t slot = commitment_msg->index - 1;
    
    if (all_commitments[slot] == NULL) {
        LOG_ERR("Commitment slot not allocated");
        return -1;
    }
    
    all_commitments[slot]->index = commitment_msg->index;
    all_commitments[slot]->num_coefficients = commitment_msg->num_coefficients;
    memcpy(all_commitments[slot]->zkp_z, commitment_msg->zkp_z, 32);
    memcpy(all_commitments[slot]->zkp_r, commitment_msg->zkp_r, 64);
    
    size_t coef_data_size = commitment_msg->num_coefficients * 
                           sizeof(secp256k1_frost_vss_commitment);
    memcpy(all_commitments[slot]->coefficient_commitments, 
           commitment_msg->coefficient_commitments, coef_data_size);
    
    int validation_result = secp256k1_frost_keygen_dkg_commitment_validate(
        ctx, all_commitments[slot], dkg_context, DKG_CONTEXT_SIZE);
    
    if (validation_result != 1) {
        LOG_ERR("Validation failed");
        return -1;
    }
    
    LOG_INF("Commitment validated successfully");
    commitments_received++;
    
    return 0;
}

static int handle_dkg_validation_result(const serialized_validation_result_t* result) {
    LOG_INF("=== Validation Result: %s ===", result->validation_result ? "SUCCESS" : "FAILED");
    
    if (!result->validation_result) {
        LOG_ERR("Commitment validation failed");
        cleanup_dkg_resources();
        return -1;
    }
    
    LOG_INF("Ready to send encrypted shares");
    return 0;
}

static int handle_dkg_send_shares_request(void) {
    LOG_INF("=== Coordinator Requesting Shares - Will Encrypt Before Sending ===");
    
    size_t total_size = sizeof(serialized_encrypted_shares_batch_t) + 
                       (dkg_num_participants * sizeof(encrypted_share_message_t));
    
    if (total_size > MAX_MSG_SIZE) {
        LOG_ERR("Encrypted shares batch too large");
        return -1;
    }
    
    uint8_t* buffer = k_malloc(total_size);
    if (!buffer) {
        LOG_ERR("Memory allocation failed");
        return -1;
    }
    
    serialized_encrypted_shares_batch_t* batch = 
        (serialized_encrypted_shares_batch_t*)buffer;
    batch->num_shares = dkg_num_participants;
    
    LOG_INF("Encrypting %u shares with recipient public keys...", dkg_num_participants);
    
    for (uint32_t i = 0; i < dkg_num_participants; i++) {
        uint32_t receiver_index = my_shares[i].receiver_index;
        
        secp256k1_pubkey* recipient_pubkey = find_participant_pubkey(receiver_index);
        if (!recipient_pubkey) {
            LOG_ERR("No ElGamal public key for participant %u", receiver_index);
            k_free(buffer);
            return -1;
        }
        
        batch->shares[i].generator_index = my_shares[i].generator_index;
        batch->shares[i].receiver_index = my_shares[i].receiver_index;
        
        secp256k1_pubkey c1;
        if (!ecc_elgamal_encrypt_value(recipient_pubkey, my_shares[i].value, 
                                       &c1, batch->shares[i].c2)) {
            LOG_ERR("Encryption failed for receiver %u", receiver_index);
            k_free(buffer);
            return -1;
        }
        
        size_t len = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, batch->shares[i].c1_serialized, &len, 
                                          &c1, SECP256K1_EC_COMPRESSED)) {
            LOG_ERR("Failed to serialize c1");
            k_free(buffer);
            return -1;
        }
        
        LOG_INF("  ✓ Encrypted share for participant %u", receiver_index);
    }
    
    memset(my_shares, 0, sizeof(my_shares));
    
    int rc = send_message(MSG_TYPE_DKG_SECRET_SHARE_ENCRYPTED, buffer, (uint16_t)total_size);
    k_free(buffer);
    
    if (rc != 0) {
        LOG_ERR("Failed to send encrypted shares");
        return -1;
    }
    
    LOG_INF("All encrypted shares sent to coordinator");
    return 0;
}

static int handle_dkg_encrypted_secret_share(const encrypted_share_message_t* enc_share_msg) {
    LOG_INF("=== Received Encrypted Share: gen=%u, recv=%u ===", 
            enc_share_msg->generator_index, enc_share_msg->receiver_index);
    
    if (enc_share_msg->receiver_index != my_participant_index) {
        LOG_ERR("Share not for us");
        return -1;
    }
    
    if (shares_received >= dkg_num_participants) {
        LOG_ERR("Already received max shares");
        return -1;
    }
    
    secp256k1_pubkey c1;
    if (!secp256k1_ec_pubkey_parse(ctx, &c1, enc_share_msg->c1_serialized, 33)) {
        LOG_ERR("Failed to parse c1");
        return -1;
    }
    
    LOG_INF("Decrypting share using ElGamal private key...");
    
    uint8_t decrypted_value[32];
    if (!ecc_elgamal_decrypt_value(&our_elgamal_keypair, &c1, enc_share_msg->c2, 
                                   decrypted_value)) {
        LOG_ERR("Decryption failed");
        return -1;
    }
    
    LOG_INF("✓ Successfully decrypted share from generator %u", 
            enc_share_msg->generator_index);
    
    received_shares[shares_received].generator_index = enc_share_msg->generator_index;
    received_shares[shares_received].receiver_index = enc_share_msg->receiver_index;
    memcpy(received_shares[shares_received].value, decrypted_value, 32);
    
    LOG_INF("Stored decrypted share %u", shares_received);
    log_hex_bytes("  Share value", decrypted_value, 32);
    
    shares_received++;
    LOG_INF("Total shares received: %u/%u", shares_received, dkg_num_participants);
    
    return 0;
}

static int verify_complete_shares(void) {
    LOG_INF("Verifying complete shares...");
    
    bool generator_seen[MAX_PARTICIPANTS] = {false};
    
    for (uint32_t i = 0; i < shares_received; i++) {
        uint32_t gen_idx = received_shares[i].generator_index;
        
        if (gen_idx < 1 || gen_idx > dkg_num_participants) {
            LOG_ERR("Invalid generator index");
            return -1;
        }
        
        if (generator_seen[gen_idx - 1]) {
            LOG_ERR("Duplicate share");
            return -1;
        }
        
        generator_seen[gen_idx - 1] = true;
    }
    
    for (uint32_t i = 0; i < dkg_num_participants; i++) {
        if (!generator_seen[i]) {
            LOG_ERR("Missing share from generator %u", i + 1);
            return -1;
        }
    }
    
    LOG_INF("Share verification passed");
    return 0;
}

static int handle_dkg_finalize(void) {
    LOG_INF("=== DKG Finalization ===");
    
    LOG_INF("Encrypted shares received: %u", shares_received);
    LOG_INF("Expected shares: %u", dkg_num_participants);
    
    if (verify_complete_shares() != 0) {
        LOG_ERR("Share verification failed");
        return -1;
    }
    
    LOG_INF("Calling secp256k1_frost_keygen_dkg_finalize...");
    
    int result = secp256k1_frost_keygen_dkg_finalize(
        ctx, 
        &keypair, 
        my_participant_index,
        dkg_num_participants,
        received_shares,
        all_commitments
    );
    
    if (result != 1) {
        LOG_ERR("secp256k1_frost_keygen_dkg_finalize failed: result=%d", result);
        return -1;
    }
    
    LOG_INF("DKG finalization completed successfully!");
    
    LOG_INF("Generated Keypair:");
    LOG_INF("  Participant Index: %u", keypair.public_keys.index);
    LOG_INF("  Max Participants: %u", keypair.public_keys.max_participants);
    log_hex_bytes("  Secret Key", keypair.secret, 32);
    log_hex_bytes("  Public Key", keypair.public_keys.public_key, 64);
    log_hex_bytes("  Group Public Key", keypair.public_keys.group_public_key, 64);
    
    if (write_frost_data_to_flash() != 0) {
        LOG_ERR("Failed to write to flash");
        return -1;
    }
    
    LOG_INF("Keypair saved to flash");
    
    if (send_message(MSG_TYPE_DKG_COMPLETE, NULL, 0) != 0) {
        LOG_ERR("Failed to send completion");
        return -1;
    }
    
    LOG_INF("=== DKG Protocol Completed Successfully ===");
    LOG_INF("✓ End-to-end encrypted shares (coordinator never saw plaintext)");
    LOG_INF("✓ FROST keypair generated and stored");
    
    return 0;
}

static int process_received_message(void) {
    LOG_INF("Processing message type: 0x%02X", current_header.msg_type);
    
    switch (current_header.msg_type) {
        case MSG_TYPE_ELGAMAL_READY:
            return handle_elgamal_ready();
            
        case MSG_TYPE_ELGAMAL_PUBKEY_LIST:
            if (current_header.payload_len >= sizeof(serialized_elgamal_pubkey_list_t)) {
                return handle_elgamal_pubkey_list(
                    (serialized_elgamal_pubkey_list_t*)payload_buffer);
            }
            return -1;
            
        case MSG_TYPE_DKG_CONTEXT:
            if (current_header.payload_len >= sizeof(serialized_dkg_context_t)) {
                return handle_dkg_context_message((serialized_dkg_context_t*)payload_buffer);
            }
            return -1;
            
        case MSG_TYPE_DKG_ALL_COMMITMENTS:
            if (current_header.payload_len >= sizeof(serialized_dkg_commitment_t)) {
                return handle_dkg_all_commitments(
                    (serialized_dkg_commitment_t*)payload_buffer);
            }
            return -1;
            
        case MSG_TYPE_DKG_VALIDATION_RESULT:
            if (current_header.payload_len >= sizeof(serialized_validation_result_t)) {
                return handle_dkg_validation_result(
                    (serialized_validation_result_t*)payload_buffer);
            }
            return -1;
            
        case MSG_TYPE_DKG_SEND_SHARES:
            return handle_dkg_send_shares_request();
            
        case MSG_TYPE_DKG_SECRET_SHARE_ENCRYPTED:
            if (current_header.payload_len >= sizeof(encrypted_share_message_t)) {
                return handle_dkg_encrypted_secret_share(
                    (encrypted_share_message_t*)payload_buffer);
            }
            return -1;
            
        case MSG_TYPE_DKG_FINALIZE:
            return handle_dkg_finalize();
            
        case MSG_TYPE_PING:
            if (send_message(MSG_TYPE_READY, NULL, 0) != 0) {
                return -1;
            }
            LOG_INF("Responded to PING");
            return 0;
            
        default:
            LOG_WRN("Unknown message type: 0x%02X", current_header.msg_type);
            return -1;
    }
}

int main(void) {
    LOG_INF("FROST DKG Device Starting - END-TO-END ENCRYPTED SHARES");
    LOG_INF("Shares are encrypted before sending, never in plaintext");
    
    memset(elgamal_pubkeys, 0, sizeof(elgamal_pubkeys));
    num_elgamal_pubkeys = 0;
    memset(&our_elgamal_keypair, 0, sizeof(our_elgamal_keypair));
    elgamal_keypair_ready = false;
    
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL) {
        LOG_ERR("Failed to create secp256k1 context");
        return -1;
    }
    LOG_INF("secp256k1 context created");
    
    read_frost_data_from_flash();
    
    uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);
    if (!device_is_ready(uart_dev)) {
        LOG_ERR("UART device not ready");
        return -1;
    }
    
    ring_buf_init(&rx_ring_buf, sizeof(rx_buf), rx_buf);
    
    uart_irq_callback_user_data_set(uart_dev, uart_isr, NULL);
    uart_irq_rx_enable(uart_dev);
    
    LOG_INF("UART initialized at 115200 baud");
    
    LOG_INF("=== Ready for FROST DKG Protocol ===");
    LOG_INF("ElGamal: End-to-end encrypted shares");
    LOG_INF("Waiting for coordinator messages...");
    
    uint8_t dummy;
    while (uart_fifo_read(uart_dev, &dummy, 1) == 1) {
    }
    
    ring_buf_reset(&rx_ring_buf);
    
    while (1) {
        size_t bytes_available = ring_buf_size_get(&rx_ring_buf);
        
        if (bytes_available > 0) {
            if (rx_state == WAITING_FOR_HEADER && 
                bytes_available >= sizeof(message_header_t)) {
                size_t bytes_read = ring_buf_get(&rx_ring_buf, (uint8_t*)&current_header, 
                                                sizeof(message_header_t));
                
                if (bytes_read == sizeof(message_header_t)) {
                    if (current_header.magic == MSG_HEADER_MAGIC && 
                        current_header.version == MSG_VERSION) {
                        LOG_INF("Valid header: type=0x%02X, len=%u", 
                                current_header.msg_type, current_header.payload_len);
                        
                        if (current_header.payload_len > 0) {
                            if (current_header.payload_len > MAX_MSG_SIZE) {
                                LOG_ERR("Payload too large");
                                rx_state = WAITING_FOR_HEADER;
                                continue;
                            }
                            
                            rx_state = WAITING_FOR_PAYLOAD;
                            payload_bytes_received = 0;
                        } else {
                            if (process_received_message() != 0) {
                                LOG_ERR("Message processing failed");
                            }
                            rx_state = WAITING_FOR_HEADER;
                        }
                    } else {
                        LOG_ERR("Invalid header");
                        rx_state = WAITING_FOR_HEADER;
                    }
                }
            } else if (rx_state == WAITING_FOR_PAYLOAD) {
                size_t remaining = current_header.payload_len - payload_bytes_received;
                size_t available = bytes_available;
                size_t to_read = (remaining < available) ? remaining : available;
                
                size_t bytes_read = ring_buf_get(&rx_ring_buf, 
                                                payload_buffer + payload_bytes_received, 
                                                to_read);
                payload_bytes_received += bytes_read;
                
                if (payload_bytes_received >= current_header.payload_len) {
                    if (process_received_message() != 0) {
                        LOG_ERR("Message processing failed");
                    }
                    
                    rx_state = WAITING_FOR_HEADER;
                    payload_bytes_received = 0;
                }
            }
        }
        
        k_msleep(10);
    }
    
    return 0;
}