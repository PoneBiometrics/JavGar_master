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

// Buffer sizes
#define RING_BUF_SIZE 512
#define MAX_MSG_SIZE 300
#define RECEIVE_TIMEOUT_MS 30000

static uint8_t rx_buf[RING_BUF_SIZE];
static struct ring_buf rx_ring_buf;
static const struct device *uart_dev;

// Message protocol definitions
#define MSG_HEADER_MAGIC 0x46524F53 // "FROS" as hex
#define MSG_VERSION 0x01

// Message types
typedef enum {
    MSG_TYPE_NONCE_COMMITMENT = 0x04, 
    MSG_TYPE_READY = 0x06,
    MSG_TYPE_END_TRANSMISSION = 0xFF,
    MSG_TYPE_SIGN = 0x07,
    MSG_TYPE_SIGNATURE_SHARE = 0x08
} message_type_t;

// Message header
typedef struct {
    uint32_t magic;        
    uint8_t version;       
    uint8_t msg_type;      
    uint16_t payload_len;  
    uint32_t participant;  
} __packed message_header_t;

// Nonce commitment structure
typedef struct {
    uint32_t index;
    uint8_t hiding[64];
    uint8_t binding[64];
} __packed serialized_nonce_commitment_t;

// Signature share structure
typedef struct {
    uint32_t index;
    uint8_t response[32];
} __packed serialized_signature_share_t;

// Keypair structure for transmission
typedef struct {
    uint32_t index;
    uint32_t max_participants;
    uint8_t secret[32];
    uint8_t public_key[64];
    uint8_t group_public_key[64];
} __packed serialized_keypair_t;

// Flash storage structure
typedef struct {
    uint32_t keypair_index;
    uint32_t keypair_max_participants;
    uint8_t keypair_secret[32];
    uint8_t keypair_public_key[64];
    uint8_t keypair_group_public_key[64];
} __packed frost_flash_storage_t;

// Global FROST objects
static secp256k1_context *ctx;
static secp256k1_frost_keypair keypair;
static secp256k1_frost_nonce *current_nonce = NULL;
static bool keypair_loaded = false;

// Store computed signature share
static secp256k1_frost_signature_share computed_signature_share;
static bool signature_share_computed = false;

// Receive state management
typedef enum {
    WAITING_FOR_HEADER,
    WAITING_FOR_PAYLOAD
} receive_state_t;

static receive_state_t rx_state = WAITING_FOR_HEADER;
static message_header_t current_header;
static uint8_t payload_buffer[MAX_MSG_SIZE];
static size_t payload_bytes_received = 0;

// Function to load FROST key material from flash
int load_frost_key_material(void) {
    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc < 0) {
        LOG_ERR("Failed to open flash area (%d)", rc);
        return rc;
    }

    // Read stored data
    frost_flash_storage_t flash_data;
    rc = flash_area_read(fa, 0, &flash_data, sizeof(frost_flash_storage_t));
    if (rc != 0) {
        LOG_ERR("Failed to read flash: %d", rc);
        flash_area_close(fa);
        return rc;
    }

    // Reconstruct keypair
    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    keypair.public_keys.index = flash_data.keypair_index;
    keypair.public_keys.max_participants = flash_data.keypair_max_participants;
    memcpy(keypair.secret, flash_data.keypair_secret, 32);
    memcpy(keypair.public_keys.public_key, flash_data.keypair_public_key, 64);
    memcpy(keypair.public_keys.group_public_key, flash_data.keypair_group_public_key, 64);

    flash_area_close(fa);
    
    // Validate loaded data
    if (keypair.public_keys.index == 0 || keypair.public_keys.index > 255) {
        LOG_ERR("Invalid participant index: %u", keypair.public_keys.index);
        return -EINVAL;
    }
    
    keypair_loaded = true;
    LOG_INF("FROST key material loaded successfully");
    LOG_INF("Participant Index: %u", keypair.public_keys.index);
    LOG_INF("Max Participants: %u", keypair.public_keys.max_participants);
    
    return 0;
}

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

// Helper function to send data via UART
static int uart_send_data(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uart_poll_out(uart_dev, data[i]);
        k_usleep(100);
    }
    return 0;
}

// Function to send a message
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

    // Send header
    int ret = uart_send_data((uint8_t*)&header, sizeof(header));
    if (ret < 0) {
        LOG_ERR("Failed to send header");
        return false;
    }

    // Send payload if present
    if (payload_len > 0 && payload != NULL) {
        ret = uart_send_data(payload, payload_len);
        if (ret < 0) {
            LOG_ERR("Failed to send payload");
            return false;
        }
    }

    LOG_INF("Message sent successfully");
    return true;
}

// Generate nonce at startup
static void generate_nonce(void) {
    if (!keypair_loaded) {
        LOG_ERR("Keypair not loaded");
        return;
    }
    
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

    LOG_INF("Generating nonce at startup for participant %u", keypair.public_keys.index);

    if (current_nonce != NULL) {
        secp256k1_frost_nonce_destroy(current_nonce);
    }
    current_nonce = secp256k1_frost_nonce_create(ctx, &keypair, binding_seed, hiding_seed);
    if (!current_nonce) {
        LOG_ERR("Failed to create nonce");
        return;
    }

    log_hex("Nonce hiding commitment", current_nonce->commitments.hiding, 32);
    log_hex("Nonce binding commitment", current_nonce->commitments.binding, 32);
}

// Generate and send nonce commitment AND keypair
static bool send_nonce_commitment_and_keypair(void) {
    if (!current_nonce) {
        LOG_ERR("No nonce available to send commitment");
        return false;
    }
    
    // Prepare combined payload
    size_t payload_len = sizeof(serialized_nonce_commitment_t) + sizeof(serialized_keypair_t);
    uint8_t* combined_payload = k_malloc(payload_len);
    if (!combined_payload) {
        LOG_ERR("Failed to allocate memory for combined payload");
        return false;
    }

    // Nonce commitment
    serialized_nonce_commitment_t* nonce_part = (serialized_nonce_commitment_t*)combined_payload;
    nonce_part->index = keypair.public_keys.index;
    memcpy(nonce_part->hiding, current_nonce->commitments.hiding, 64);
    memcpy(nonce_part->binding, current_nonce->commitments.binding, 64);

    // Keypair
    serialized_keypair_t* keypair_part = (serialized_keypair_t*)(combined_payload + sizeof(serialized_nonce_commitment_t));
    keypair_part->index = keypair.public_keys.index;
    keypair_part->max_participants = keypair.public_keys.max_participants;
    memcpy(keypair_part->secret, keypair.secret, 32);
    memcpy(keypair_part->public_key, keypair.public_keys.public_key, 64);
    memcpy(keypair_part->group_public_key, keypair.public_keys.group_public_key, 64);

    LOG_INF("Sending nonce commitment and keypair for participant %u", keypair.public_keys.index);
    
    bool result = send_message(MSG_TYPE_NONCE_COMMITMENT, 
                              keypair.public_keys.index,
                              combined_payload, payload_len);
    
    k_free(combined_payload);
    
    if (result) {
        LOG_INF("Nonce commitment and keypair sent successfully");
        send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0);
    }
    
    return result;
}

// Function to send signature share
static bool send_signature_share(void) {
    if (!signature_share_computed) {
        LOG_ERR("No signature share computed yet");
        return false;
    }

    serialized_signature_share_t serialized;
    serialized.index = keypair.public_keys.index;
    memcpy(serialized.response, computed_signature_share.response, 32);

    LOG_INF("*** SENDING SIGNATURE SHARE TO COORDINATOR ***");
    log_hex("Signature Share", serialized.response, 32);

    bool result = send_message(MSG_TYPE_SIGNATURE_SHARE, 
                              keypair.public_keys.index,
                              &serialized, sizeof(serialized));
    
    if (result) {
        LOG_INF("Signature share sent successfully to coordinator");
        send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0);
    } else {
        LOG_ERR("Failed to send signature share");
    }
    
    return result;
}

// Process signing request and compute signature share
static void process_sign_message(const message_header_t *header, const uint8_t *payload) {
    if (header->payload_len < 32 + 4) {
        LOG_ERR("Invalid sign message length");
        return;
    }
    
    // Parse payload
    uint8_t* msg_hash = (uint8_t*)payload;
    uint32_t num_commitments = *(uint32_t*)(payload + 32);
    serialized_nonce_commitment_t* serialized_commitments = (serialized_nonce_commitment_t*)(payload + 32 + 4);
    
    LOG_INF("Received signing request");
    LOG_INF("Message hash (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x...", 
            msg_hash[0], msg_hash[1], msg_hash[2], msg_hash[3],
            msg_hash[4], msg_hash[5], msg_hash[6], msg_hash[7]);
    LOG_INF("Number of commitments: %u", num_commitments);
    
    if (!current_nonce) {
        LOG_ERR("No nonce available for signing");
        return;
    }
    
    if (current_nonce->used) {
        LOG_ERR("Nonce already used");
        return;
    }
    
    // Convert serialized commitments
    secp256k1_frost_nonce_commitment *signing_commitments = 
        k_malloc(num_commitments * sizeof(secp256k1_frost_nonce_commitment));
    if (!signing_commitments) {
        LOG_ERR("Failed to allocate memory for signing commitments");
        return;
    }
    
    for (uint32_t i = 0; i < num_commitments; i++) {
        signing_commitments[i].index = serialized_commitments[i].index;
        memcpy(signing_commitments[i].hiding, serialized_commitments[i].hiding, 64);
        memcpy(signing_commitments[i].binding, serialized_commitments[i].binding, 64);
    }
    
    // Compute signature share
    int return_val = secp256k1_frost_sign(&computed_signature_share,
                                         msg_hash, num_commitments,
                                         &keypair, current_nonce, signing_commitments);
    
    if (return_val == 1) {
        signature_share_computed = true;
        
        LOG_INF("*** SIGNATURE SHARE COMPUTED SUCCESSFULLY ***");
        log_hex("SIGNATURE SHARE (32 bytes)", computed_signature_share.response, 32);
        
        // Print signature share
        char hex_str[65];
        for (int i = 0; i < 32; i++) {
            sprintf(hex_str + i * 2, "%02x", computed_signature_share.response[i]);
        }
        hex_str[64] = '\0';
        printk("\n\n=== FROST SIGNATURE SHARE ===\n");
        printk("Participant: %u\n", keypair.public_keys.index);
        printk("Signature: %s\n", hex_str);
        printk("=============================\n\n");
        
        // Enviar share inmediatamente
        send_signature_share();
        
    } else {
        LOG_ERR("Failed to compute signature share");
        signature_share_computed = false;
    }
    
    k_free(signing_commitments);
}

// UART interrupt callback
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

// Procesar mensaje READY
static void process_ready_message() {
    LOG_INF("*** Received READY signal ***");
    send_nonce_commitment_and_keypair();
}

// Main application
int main(void) {
    LOG_INF("=== FROST UART Signing Device Starting ===");
    
    // Initialize ring buffer
    ring_buf_init(&rx_ring_buf, sizeof(rx_buf), rx_buf);
    
    // Get UART device
    uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);
    if (!device_is_ready(uart_dev)) {
        LOG_ERR("UART device not ready");
        return -1;
    }
    
    // Configure UART with detailed settings
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

    // Initialize secp256k1 context
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL) {
        LOG_ERR("Failed to create secp256k1 context");
        return -1;
    }
    LOG_INF("secp256k1 context created");
    
    // Load FROST key material from flash
    int rc = load_frost_key_material();
    if (rc != 0) {
        LOG_ERR("Failed to load FROST key material from flash (%d)", rc);
        secp256k1_context_destroy(ctx);
        return -1;
    }
    
    // Generate nonce at startup
    generate_nonce();
    
    LOG_INF("=== Ready to receive messages ===");
    LOG_INF("Participant %u ready for FROST protocol", keypair.public_keys.index);
    
    // Flush UART buffers
    uint8_t dummy;
    while (uart_fifo_read(uart_dev, &dummy, 1) == 1) {
        // Discard any existing data
    }
    
    // Main processing loop
    while (1) {
        size_t bytes_available = ring_buf_size_get(&rx_ring_buf);
        
        if (bytes_available > 0) {
            if (rx_state == WAITING_FOR_HEADER && bytes_available >= sizeof(message_header_t)) {
                // Read complete header
                size_t read = ring_buf_get(&rx_ring_buf, (uint8_t*)&current_header, sizeof(message_header_t));
                if (read != sizeof(message_header_t)) {
                    LOG_ERR("Failed to read full header");
                    continue;
                }
                
                // Validate header
                if (current_header.magic != MSG_HEADER_MAGIC) {
                    LOG_ERR("Invalid magic number: 0x%08x", current_header.magic);
                    LOG_HEXDUMP_ERR((uint8_t*)&current_header, sizeof(message_header_t), "Invalid header:");
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
                    // Process message without payload
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
                    LOG_DBG("Read %zu payload bytes (%zu/%u)", 
                            read, payload_bytes_received, current_header.payload_len);
                    
                    if (payload_bytes_received == current_header.payload_len) {
                        LOG_INF("Complete payload received");
                        
                        if (current_header.msg_type == MSG_TYPE_SIGN) {
                            process_sign_message(&current_header, payload_buffer);
                        }
                        
                        rx_state = WAITING_FOR_HEADER;
                    }
                }
            }
        }
        
        k_msleep(10);
    }
    
    return 0;
}