// HID Board FROST DKG - END-TO-END ENCRYPTED SHARES
// Shares are encrypted before sending, never sent in plaintext
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
#include <stdio.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <secp256k1_ecdh.h>

LOG_MODULE_REGISTER(frost_dkg_device, LOG_LEVEL_INF);

#define STORAGE_PARTITION storage_partition
#define REPORT_ID_INPUT  0x01
#define REPORT_ID_OUTPUT 0x02
#define HID_EP_BUSY_FLAG 0
#define MY_HID_REPORT_SIZE  64
#define CHUNK_SIZE       61
#define CHUNK_DELAY_MS   50
#define MSG_HEADER_MAGIC 0x46524F53
#define MSG_VERSION 0x01
#define DKG_CONTEXT_SIZE 32
#define MAX_PARTICIPANTS 10
#define SECRET_VALUE_SIZE 32
#define REASSEMBLY_BUFFER_SIZE 4096

static uint8_t receive_buffer[REASSEMBLY_BUFFER_SIZE];
static size_t receive_buffer_pos = 0;
static size_t expected_total_size = 0;
static bool reassembling_message = false;

K_MUTEX_DEFINE(buffer_mutex);

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

static uint32_t my_participant_index = 0;
static uint32_t dkg_num_participants = 0;
static uint32_t dkg_threshold = 0;
static uint8_t dkg_context[DKG_CONTEXT_SIZE];
static uint32_t shares_received = 0;
static uint32_t commitments_received = 0;
static bool configured = false;
static const struct device *hdev;
static ATOMIC_DEFINE(hid_ep_in_busy, 1);

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

static struct k_work report_send;
static struct k_work dkg_work;
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

void log_hex_bytes(const char *label, const unsigned char *data, size_t len) {
    char hex_buf[65];
    size_t display_len = len > 32 ? 32 : len;
    for (size_t i = 0; i < display_len; i++) {
        snprintf(&hex_buf[i * 2], 3, "%02x", data[i]);
    }
    hex_buf[display_len * 2] = '\0';
    LOG_INF("%s (%zu bytes): %s%s", label, len, hex_buf, len > 32 ? "..." : "");
}

static int ecc_elgamal_encrypt_value(const secp256k1_pubkey *recipient_pubkey,
                                     const uint8_t *value_32_bytes,
                                     secp256k1_pubkey *c1_out, uint8_t *c2_out) {
    uint8_t ephemeral_key[32];
    uint8_t shared_secret[32];
    
    sys_rand_get(ephemeral_key, 32);
    if (ephemeral_key[0] == 0) ephemeral_key[0] = 0x01;
    
    if (!secp256k1_ec_pubkey_create(ctx, c1_out, ephemeral_key)) {
        LOG_ERR("Failed to create ephemeral public key");
        memset(ephemeral_key, 0, sizeof(ephemeral_key));
        return 0;
    }
    
    if (!secp256k1_ecdh(ctx, shared_secret, recipient_pubkey, ephemeral_key,
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
    
    if (!secp256k1_ecdh(ctx, shared_secret, c1, keypair->private_key,
                        secp256k1_ecdh_hash_function_sha256, NULL)) {
        LOG_ERR("Failed to compute ECDH shared secret for decryption");
        return 0;
    }
    
    for (int i = 0; i < SECRET_VALUE_SIZE; i++) {
        value_32_bytes_out[i] = c2[i] ^ shared_secret[i];
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
    if (keypair->private_key[0] == 0) keypair->private_key[0] = 0x01;
    
    if (!secp256k1_ec_pubkey_create(ctx, &keypair->public_key, keypair->private_key)) {
        LOG_ERR("Failed to create public key");
        return 0;
    }
    
    LOG_INF("ElGamal keypair generated successfully");
    return 1;
}

static void print_elgamal_keypair_hex(const char *label, const ecc_elgamal_keypair_t *keypair) {
    char hex_buf[67];
    
    LOG_INF("%s Private Key:", label);
    for (int i = 0; i < 32; i++) {
        snprintf(&hex_buf[i * 2], 3, "%02x", keypair->private_key[i]);
    }
    hex_buf[64] = '\0';
    LOG_INF("  %s", hex_buf);
    
    uint8_t serialized[33];
    size_t len = 33;
    if (secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &keypair->public_key, 
                                     SECP256K1_EC_COMPRESSED)) {
        for (int i = 0; i < 33; i++) {
            snprintf(&hex_buf[i * 2], 3, "%02x", serialized[i]);
        }
        hex_buf[66] = '\0';
        LOG_INF("%s Public Key: %s", label, hex_buf);
    }
}

static void print_all_elgamal_pubkeys(void) {
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

static void reset_reassembly_state(void) {
    receive_buffer_pos = 0;
    expected_total_size = 0;
    reassembling_message = false;
}

static int send_chunked_data(const uint8_t *data, size_t len) {
    if (!configured || !data || len == 0) {
        return -EINVAL;
    }

    size_t offset = 0;
    int chunk_count = 0;
    uint8_t chunk_buffer[MY_HID_REPORT_SIZE];
    
    LOG_INF("Sending: %zu bytes via chunked HID", len);
    
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
        int ret = hid_int_ep_write(hdev, chunk_buffer, sizeof(chunk_buffer), NULL);
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
    uint8_t *buffer = k_malloc(total_len);
    if (!buffer) {
        LOG_ERR("Failed to allocate message buffer");
        return -ENOMEM;
    }
    
    memcpy(buffer, &header, sizeof(header));
    if (payload_len > 0 && payload) {
        memcpy(buffer + sizeof(header), payload, payload_len);
    }
    
    LOG_INF("Sending: type=0x%02x, part=%u, len=%u", msg_type, participant, payload_len);
    
    int ret = send_chunked_data(buffer, total_len);
    k_free(buffer);
    return ret;
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
}

static int handle_elgamal_ready(void) {
    LOG_INF("=== ElGamal Phase: Ready Signal Received ===");
    
    const message_header_t* header = (const message_header_t*)receive_buffer;
    uint32_t participant_index = header->participant;
    LOG_INF("Using participant index: %u", participant_index);
    
    if (!ecc_elgamal_keygen(&our_elgamal_keypair)) {
        LOG_ERR("Failed to generate ElGamal keypair");
        return -1;
    }
    
    elgamal_keypair_ready = true;
    print_elgamal_keypair_hex("ElGamal", &our_elgamal_keypair);
    
    serialized_elgamal_pubkey_t elgamal_msg;
    elgamal_msg.participant_index = participant_index;
    
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, elgamal_msg.public_key_serialized, &len,
                                       &our_elgamal_keypair.public_key, 
                                       SECP256K1_EC_COMPRESSED)) {
        LOG_ERR("Failed to serialize ElGamal public key");
        return -1;
    }
    
    if (send_message(MSG_TYPE_ELGAMAL_PUBKEY, participant_index, 
                    &elgamal_msg, sizeof(elgamal_msg)) != 0) {
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
    
    print_all_elgamal_pubkeys();
    LOG_INF("Ready to proceed with DKG - shares will be encrypted");
    return 0;
}

static int handle_dkg_context_message(const serialized_dkg_context_t* ctx_msg) {
    LOG_INF("=== Phase 1: DKG Context Received ===");
    
    const message_header_t* header = (const message_header_t*)receive_buffer;
    
    dkg_num_participants = ctx_msg->num_participants;
    dkg_threshold = ctx_msg->threshold;
    memcpy(dkg_context, ctx_msg->context, DKG_CONTEXT_SIZE);
    my_participant_index = header->participant;
    
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
    
    int rc = send_message(MSG_TYPE_DKG_COMMITMENT, my_participant_index, 
                         buffer, (uint16_t)total_size);
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
    LOG_INF("=== Validation Result: %s ===", 
            result->validation_result ? "SUCCESS" : "FAILED");
    
    if (!result->validation_result) {
        LOG_ERR("Commitment validation failed");
        cleanup_dkg_resources();
        return -1;
    }
    
    LOG_INF("Ready to send encrypted shares");
    return 0;
}

// MODIFIED: Encrypt shares before sending
static int handle_dkg_send_shares_request(void) {
    LOG_INF("=== Coordinator Requesting Shares - Will Encrypt Before Sending ===");
    
    size_t total_size = sizeof(serialized_encrypted_shares_batch_t) + 
                       (dkg_num_participants * sizeof(encrypted_share_message_t));
    
    uint8_t* buffer = k_malloc(total_size);
    if (!buffer) {
        LOG_ERR("Memory allocation failed");
        return -1;
    }
    
    serialized_encrypted_shares_batch_t* batch = 
        (serialized_encrypted_shares_batch_t*)buffer;
    batch->num_shares = dkg_num_participants;
    
    LOG_INF("Encrypting %u shares with recipient public keys...", dkg_num_participants);
    
    // Encrypt each share for its intended recipient
    for (uint32_t i = 0; i < dkg_num_participants; i++) {
        uint32_t receiver_index = my_shares[i].receiver_index;
        
        // Find recipient's ElGamal public key
        secp256k1_pubkey* recipient_pubkey = find_participant_pubkey(receiver_index);
        if (!recipient_pubkey) {
            LOG_ERR("No ElGamal public key for participant %u", receiver_index);
            k_free(buffer);
            return -1;
        }
        
        // Set routing info (not encrypted)
        batch->shares[i].generator_index = my_shares[i].generator_index;
        batch->shares[i].receiver_index = my_shares[i].receiver_index;
        
        // Encrypt the share value
        secp256k1_pubkey c1;
        if (!ecc_elgamal_encrypt_value(recipient_pubkey, my_shares[i].value, 
                                       &c1, batch->shares[i].c2)) {
            LOG_ERR("Encryption failed for receiver %u", receiver_index);
            k_free(buffer);
            return -1;
        }
        
        // Serialize c1
        size_t len = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, batch->shares[i].c1_serialized, &len, 
                                          &c1, SECP256K1_EC_COMPRESSED)) {
            LOG_ERR("Failed to serialize c1");
            k_free(buffer);
            return -1;
        }
        
        LOG_INF("  ✓ Encrypted share for participant %u", receiver_index);
    }
    
    // Clear plaintext shares from memory
    memset(my_shares, 0, sizeof(my_shares));
    
    int rc = send_message(MSG_TYPE_DKG_SECRET_SHARE_ENCRYPTED, my_participant_index, 
                         buffer, (uint16_t)total_size);
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
    
    // Deserialize c1
    secp256k1_pubkey c1;
    if (!secp256k1_ec_pubkey_parse(ctx, &c1, enc_share_msg->c1_serialized, 33)) {
        LOG_ERR("Failed to parse c1");
        return -1;
    }
    
    LOG_INF("Decrypting share using ElGamal private key...");
    
    // Decrypt the share
    uint8_t decrypted_value[32];
    if (!ecc_elgamal_decrypt_value(&our_elgamal_keypair, &c1, enc_share_msg->c2, 
                                   decrypted_value)) {
        LOG_ERR("Decryption failed");
        return -1;
    }
    
    LOG_INF("✓ Successfully decrypted share from generator %u", 
            enc_share_msg->generator_index);
    
    // Store the decrypted share
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
    
    if (send_message(MSG_TYPE_DKG_COMPLETE, my_participant_index, NULL, 0) != 0) {
        LOG_ERR("Failed to send completion");
        return -1;
    }
    
    LOG_INF("=== DKG Protocol Completed Successfully ===");
    LOG_INF("✓ End-to-end encrypted shares (coordinator never saw plaintext)");
    LOG_INF("✓ FROST keypair generated and stored");
    
    return 0;
}

static void dkg_work_handler(struct k_work *work) {
    const message_header_t *header = (const message_header_t *)receive_buffer;
    const void *payload = (header->payload_len > 0) ? 
                         (receive_buffer + sizeof(message_header_t)) : NULL;
    
    LOG_INF("Processing: type=0x%02x, participant=%u, payload_len=%u",
            header->msg_type, header->participant, header->payload_len);
    
    if (my_participant_index == 0) {
        my_participant_index = header->participant;
        LOG_INF("Set my participant index to: %u", my_participant_index);
    }
    
    switch (header->msg_type) {
        case MSG_TYPE_PING:
            LOG_INF("*** Received PING ***");
            send_message(MSG_TYPE_READY, my_participant_index ? my_participant_index : 1, 
                        NULL, 0);
            LOG_INF("Responded to PING");
            break;
            
        case MSG_TYPE_ELGAMAL_READY:
            handle_elgamal_ready();
            break;
            
        case MSG_TYPE_ELGAMAL_PUBKEY_LIST:
            if (payload) {
                handle_elgamal_pubkey_list((serialized_elgamal_pubkey_list_t*)payload);
            }
            break;
            
        case MSG_TYPE_DKG_CONTEXT:
            if (payload) {
                handle_dkg_context_message((serialized_dkg_context_t*)payload);
            }
            break;
            
        case MSG_TYPE_DKG_ALL_COMMITMENTS:
            if (payload) {
                handle_dkg_all_commitments((serialized_dkg_commitment_t*)payload);
            }
            break;
            
        case MSG_TYPE_DKG_VALIDATION_RESULT:
            if (payload) {
                handle_dkg_validation_result((serialized_validation_result_t*)payload);
            }
            break;
            
        case MSG_TYPE_DKG_SEND_SHARES:
            handle_dkg_send_shares_request();
            break;
            
        case MSG_TYPE_DKG_SECRET_SHARE_ENCRYPTED:
            if (payload) {
                handle_dkg_encrypted_secret_share((encrypted_share_message_t*)payload);
            }
            break;
            
        case MSG_TYPE_DKG_FINALIZE:
            handle_dkg_finalize();
            break;
            
        default:
            LOG_WRN("Unknown message type: 0x%02X", header->msg_type);
            break;
    }
}

static void handle_chunked_data(const uint8_t* data, size_t len) {
    if (k_mutex_lock(&buffer_mutex, K_MSEC(100)) != 0) {
        return;
    }
    
    if (len < 2) {
        k_mutex_unlock(&buffer_mutex);
        return;
    }
    
    uint8_t chunk_len = data[1];
    const uint8_t* chunk_data = &data[2];
    
    if (chunk_len == 0 || chunk_len > (len - 2)) {
        LOG_WRN("Invalid chunk length: %u", chunk_len);
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
                LOG_INF("NEW MESSAGE: type=0x%02x, total=%zu bytes", 
                       header->msg_type, expected_total_size);
                k_timer_start(&receive_timeout_timer, K_SECONDS(30), K_NO_WAIT);
            } else {
                LOG_ERR("Message too large: %zu", expected_total_size);
                k_mutex_unlock(&buffer_mutex);
                return;
            }
        }
    }
    
    if (reassembling_message) {
        size_t space_available = REASSEMBLY_BUFFER_SIZE - receive_buffer_pos;
        size_t bytes_to_copy = (chunk_len > space_available) ? space_available : chunk_len;
        
        if (bytes_to_copy > 0) {
            memcpy(receive_buffer + receive_buffer_pos, chunk_data, bytes_to_copy);
            receive_buffer_pos += bytes_to_copy;
            
            if (receive_buffer_pos >= expected_total_size) {
                LOG_INF("MESSAGE COMPLETE: %zu bytes", expected_total_size);
                k_timer_stop(&receive_timeout_timer);
                k_work_submit(&dkg_work);
                reset_reassembly_state();
            }
        }
    }
    
    k_mutex_unlock(&buffer_mutex);
}

static void receive_timeout_handler(struct k_timer *timer) {
    LOG_WRN("Receive timeout - resetting");
    if (k_mutex_lock(&buffer_mutex, K_MSEC(100)) == 0) {
        reset_reassembly_state();
        k_mutex_unlock(&buffer_mutex);
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
                         int32_t *len, uint8_t **data) {
    if (*len > 0 && *data) {
        k_timer_stop(&receive_timeout_timer);
        if (reassembling_message) {
            k_timer_start(&receive_timeout_timer, K_SECONDS(30), K_NO_WAIT);
        }
        handle_chunked_data(*data, *len);
    }
    return 0;
}

static void on_idle_cb(const struct device *dev, uint16_t report_id) {
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

static void send_report(struct k_work *work) {
    if (!atomic_test_and_set_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG)) {
        int ret = hid_int_ep_write(hdev, (uint8_t *)&report_1, sizeof(report_1), NULL);
        if (ret != 0) {
            atomic_clear_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
        }
    }
}

static void report_event_handler(struct k_timer *dummy) {
    if (!configured) {
        if (report_1.value < 100) {
            report_1.value++;
        } else {
            report_1.value = 1;
        }
        k_work_submit(&report_send);
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
    
    k_work_init(&report_send, send_report);
    k_work_init(&dkg_work, dkg_work_handler);
    
    hdev = device_get_binding("HID_0");
    if (hdev == NULL) {
        LOG_ERR("Cannot get USB HID Device");
        return -1;
    }
    
    usb_hid_register_device(hdev, hid_report_desc, sizeof(hid_report_desc), &ops);
    
    atomic_set_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
    k_timer_start(&event_timer, REPORT_PERIOD, REPORT_PERIOD);
    
    int ret = usb_hid_init(hdev);
    if (ret != 0) {
        LOG_ERR("Failed to initialize HID: %d", ret);
        return ret;
    }
    
    ret = usb_enable(status_cb);
    if (ret != 0) {
        LOG_ERR("Failed to enable USB: %d", ret);
        return ret;
    }
    
    LOG_INF("=== Ready for FROST DKG Protocol ===");
    LOG_INF("ElGamal: End-to-end encrypted shares");
    LOG_INF("Waiting for coordinator messages...");
    
    while (1) {
        k_msleep(100);
    }
    
    cleanup_dkg_resources();
    secp256k1_context_destroy(ctx);
    return 0;
}