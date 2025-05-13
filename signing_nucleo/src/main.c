#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>

#include "examples_util.h"

#define T 2
#define UART_DEVICE_NODE DT_NODELABEL(usart1) // usart1 if attaching a new USB in the pins, yellow to D8 and orange to D2 (using COM different to COM3) or usart2 if using COM3 (in this case not possible to debug at the same time)

LOG_MODULE_REGISTER(signer, LOG_LEVEL_INF);

// Serializable version of FROST structures for flash storage
typedef struct {
    // Keypair storage
    uint32_t keypair_index;
    uint32_t keypair_max_participants;
    uint8_t keypair_secret[32];
    uint8_t keypair_public_key[64];
    uint8_t keypair_group_public_key[33];
} __packed frost_flash_storage_t;

#define STORAGE_PARTITION     storage_partition

// Message protocol definitions
#define MSG_HEADER_MAGIC 0x46524F53 // "FROS" as hex
#define MSG_VERSION 0x01

// Message types for our protocol
typedef enum {
    MSG_TYPE_SECRET_SHARE = 0x01,
    MSG_TYPE_PUBLIC_KEY = 0x02,
    MSG_TYPE_COMMITMENTS = 0x03,
    MSG_TYPE_NONCE_COMMITMENT = 0x04, 
    MSG_TYPE_END_TRANSMISSION = 0xFF
} message_type_t;

// Header for each message in our protocol
typedef struct {
    uint32_t magic;        // Magic number to identify our protocol
    uint8_t version;       // Protocol version
    uint8_t msg_type;      // Type of message
    uint16_t payload_len;  // Length of payload following the header
    uint32_t participant;  // Participant ID
} __packed message_header_t;

// Serialized nonce commitment structure for transmission
typedef struct {
    uint32_t participant_index;
    uint8_t hiding[32];     
    uint8_t binding[32];    
} __packed serialized_nonce_commitment_t;

// Function to load FROST key material from flash and reconstruct keypair and commitments
int load_frost_key_material(secp256k1_context *ctx, secp256k1_frost_keypair *keypair) 
{
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

    // Reconstruct keypair
    memset(keypair, 0, sizeof(secp256k1_frost_keypair));
    keypair->public_keys.index = flash_data.keypair_index;
    keypair->public_keys.max_participants = flash_data.keypair_max_participants;

    // Copy secret key
    memcpy(keypair->secret, flash_data.keypair_secret, 32);

    // Copy public keys
    memcpy(keypair->public_keys.public_key, 
    flash_data.keypair_public_key, 64);
    memcpy(keypair->public_keys.group_public_key, 
    flash_data.keypair_group_public_key, 33);

    flash_area_close(fa);
    return 0;
}

static void log_hex(const char *label, const uint8_t *data, size_t len) {
    char hexstr[2 * len + 1];

    for (size_t i = 0; i < len; i++) {
        snprintf(&hexstr[i * 2], 3, "%02x", data[i]);
    }

    LOG_INF("%s: 0x%s", label, hexstr);
}

// Helper function to send multiple bytes through UART
static int uart_poll_out_multi(const struct device *uart, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uart_poll_out(uart, data[i]);
        // Small delay to ensure stable transmission
        k_usleep(100);
    }
    return 0;
}

// Function to send a message
static bool send_message(const struct device *uart, uint8_t msg_type, 
    uint32_t participant, const void* payload, uint16_t payload_len) {
    message_header_t header;

    // Fill header
    header.magic = MSG_HEADER_MAGIC;
    header.version = MSG_VERSION;
    header.msg_type = msg_type;
    header.payload_len = payload_len;
    header.participant = participant;

    // Send header
    int ret = uart_poll_out_multi(uart, (uint8_t*)&header, sizeof(header));
    if (ret < 0) {
        LOG_ERR("Failed to send header, error: %d", ret);
        return false;
    }

    // Send payload
    if (payload_len > 0 && payload != NULL) {
        ret = uart_poll_out_multi(uart, payload, payload_len);
        if (ret < 0) {
            LOG_ERR("Failed to send payload, error: %d", ret);
            return false;
        }
    }

    return true;
}

// Function to send nonce commitment to the computer
bool send_nonce_commitment(const struct device *uart, uint32_t participant_index,
        const secp256k1_frost_nonce_commitment *commitment) {
    serialized_nonce_commitment_t serialized;

    // Prepare serialized data
    serialized.participant_index = participant_index;
    memcpy(serialized.hiding, commitment->hiding, sizeof(serialized.hiding));
    memcpy(serialized.binding, commitment->binding, sizeof(serialized.binding));

    // Send message
    return send_message(uart, MSG_TYPE_NONCE_COMMITMENT, participant_index,
    &serialized, sizeof(serialized));
}

// Function to send end transmission marker
bool send_end_transmission(const struct device *uart, uint32_t participant_index) {
    return send_message(uart, MSG_TYPE_END_TRANSMISSION, participant_index, NULL, 0);
}

int main(void) {

    LOG_INF("FROST Key Material Loader");

    // Create secp256k1 context
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
    );
    if (ctx == NULL) {
        LOG_ERR("Failed to create secp256k1 context");
        return;
    }

    secp256k1_frost_keypair keypair;

    // Attempt to load key material from flash
    int rc = load_frost_key_material(ctx, &keypair);
    if (rc != 0) {
        LOG_ERR("Failed to load FROST key material from flash");
        secp256k1_context_destroy(ctx);
        return;
    }

    // Log loaded key material details
    LOG_INF("=== Loaded FROST Key Material ===");
    LOG_INF("Participant Index: %d", keypair.public_keys.index);
    LOG_INF("Max Participants: %d", keypair.public_keys.max_participants);
    // Log key details
    log_hex("Secret Key", keypair.secret, 32);
    log_hex("Public Key", keypair.public_keys.public_key, 64);
    log_hex("Group Public Key", keypair.public_keys.group_public_key, 33);

    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};

    /* Generate 32 bytes of randomness to use for computing the nonce. */
    if (!fill_random(binding_seed, sizeof(binding_seed))) {
        LOG_INF("Failed to generate binding_seed");
        return 1;
    }
    if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
        LOG_INF("Failed to generate hiding_seed");
        return 1;
    }

    secp256k1_frost_nonce *nonces[T];
    secp256k1_frost_nonce_commitment signing_commitments[T];

    //* Create the nonce (the function already computes its commitment) */
    nonces[keypair.public_keys.index - 1] = secp256k1_frost_nonce_create(ctx, &keypair, binding_seed, hiding_seed);
    if (!nonces[keypair.public_keys.index - 1]) {
        LOG_ERR("Failed to create nonce");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    log_hex("Nonce hiding commitment", 
            nonces[keypair.public_keys.index - 1]->commitments.hiding, 
            sizeof(nonces[keypair.public_keys.index - 1]->commitments.hiding));
    log_hex("Nonce binding commitment", 
            nonces[keypair.public_keys.index - 1]->commitments.binding, 
            sizeof(nonces[keypair.public_keys.index - 1]->commitments.binding));

    // Get UART device
    const struct device *uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);
    if (!device_is_ready(uart_dev)) {
        LOG_ERR("UART device not ready");
        return -1;
    }
    LOG_INF("UART device ready");

    // Send nonce commitment over UART
    LOG_INF("Sending nonce commitment over UART...");
    if (!send_nonce_commitment(uart_dev, keypair.public_keys.index, 
                              &nonces[keypair.public_keys.index - 1]->commitments)) {
        LOG_ERR("Failed to send nonce commitment");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    LOG_INF("Nonce commitment sent successfully");

    // Send end transmission marker
    if (!send_end_transmission(uart_dev, keypair.public_keys.index)) {
        LOG_ERR("Failed to send end transmission marker");
    } else {
        LOG_INF("End transmission marker sent");
    }

    // Clean up
    secp256k1_context_destroy(ctx);
    LOG_INF("FROST signer completed successfully");
    return 0;
}