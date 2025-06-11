#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include "examples_util.h"

LOG_MODULE_REGISTER(frost_device, LOG_LEVEL_INF);

#define T 2
#define UART_DEVICE_NODE DT_NODELABEL(usart1) 
#define STORAGE_PARTITION storage_partition

// Communication and receive state
#define RING_BUF_SIZE 512
#define MAX_MSG_SIZE 256

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

// Nonce commitment structure for transmission
typedef struct {
    uint32_t participant_index;
    uint8_t hiding[32];     
    uint8_t binding[32];    
} __packed serialized_nonce_commitment_t;

// Signature share structure for transmission
typedef struct {
    uint32_t participant_index;
    uint8_t response[32];
} __packed serialized_signature_share_t;

// Flash storage structure
typedef struct {
    uint32_t keypair_index;
    uint32_t keypair_max_participants;
    uint8_t keypair_secret[32];
    uint8_t keypair_public_key[64];
    uint8_t keypair_group_public_key[33];
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
    memcpy(keypair.public_keys.group_public_key, flash_data.keypair_group_public_key, 33);

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

// Helper function to send data via UART
static int uart_send_data(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uart_poll_out(uart_dev, data[i]);
        k_usleep(100); // Small delay for stability
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

// Function to generate nonce at startup
static void generate_nonce(void) {
    if (!keypair_loaded) {
        LOG_ERR("Keypair not loaded");
        return;
    }
    
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};

    // Generate randomness for nonce creation
    if (!fill_random(binding_seed, sizeof(binding_seed))) {
        LOG_ERR("Failed to generate binding_seed");
        return;
    }
    if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
        LOG_ERR("Failed to generate hiding_seed");
        return;
    }

    LOG_INF("Generating nonce at startup for participant %u", keypair.public_keys.index);

    // Create nonce and store for later use
    if (current_nonce != NULL) {
        secp256k1_frost_nonce_destroy(current_nonce);
    }
    current_nonce = secp256k1_frost_nonce_create(ctx, &keypair, binding_seed, hiding_seed);
    if (!current_nonce) {
        LOG_ERR("Failed to create nonce");
        return;
    }

    // Log the generated commitments
    log_hex("Nonce hiding commitment", current_nonce->commitments.hiding, 32);
    log_hex("Nonce binding commitment", current_nonce->commitments.binding, 32);
}

// Function to send nonce commitment
static bool send_nonce_commitment(void) {
    if (!current_nonce) {
        LOG_ERR("No nonce available");
        return false;
    }

    serialized_nonce_commitment_t serialized;
    serialized.participant_index = keypair.public_keys.index;
    memcpy(serialized.hiding, current_nonce->commitments.hiding, 32);
    memcpy(serialized.binding, current_nonce->commitments.binding, 32);

    bool result = send_message(MSG_TYPE_NONCE_COMMITMENT, 
                              keypair.public_keys.index,
                              &serialized, sizeof(serialized));
    
    if (result) {
        LOG_INF("Nonce commitment sent successfully");
        // Send end transmission marker
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
    serialized.participant_index = keypair.public_keys.index;
    memcpy(serialized.response, computed_signature_share.response, 32);

    LOG_INF("*** SENDING SIGNATURE SHARE ***");
    log_hex("Signature Share", serialized.response, 32);

    bool result = send_message(MSG_TYPE_SIGNATURE_SHARE, 
                              keypair.public_keys.index,
                              &serialized, sizeof(serialized));
    
    if (result) {
        LOG_INF("Signature share sent successfully to coordinator");
        // Send end transmission marker
        send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0);
    } else {
        LOG_ERR("Failed to send signature share");
    }
    
    return result;
}

// Process READY message
static void process_ready_message() {
    LOG_INF("*** Received READY signal ***");
    send_nonce_commitment();
}

// Process signing request and compute signature share
static void process_sign_message(const message_header_t *header, const uint8_t *payload) {
    if (header->payload_len < 32 + 4) {
        LOG_ERR("Invalid sign message length");
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
    
    // Check if we have a nonce for this participant
    if (!current_nonce) {
        LOG_ERR("No nonce available for signing");
        return;
    }
    
    if (current_nonce->used) {
        LOG_ERR("Nonce already used");
        return;
    }
    
    // Convert serialized commitments to secp256k1_frost_nonce_commitment array
    secp256k1_frost_nonce_commitment *signing_commitments = 
        k_malloc(num_commitments * sizeof(secp256k1_frost_nonce_commitment));
    if (!signing_commitments) {
        LOG_ERR("Failed to allocate memory for signing commitments");
        return;
    }
    
    for (uint32_t i = 0; i < num_commitments; i++) {
        signing_commitments[i].index = serialized_commitments[i].participant_index;
        memcpy(signing_commitments[i].hiding, serialized_commitments[i].hiding, 32);
        memcpy(signing_commitments[i].binding, serialized_commitments[i].binding, 32);
    }
    
    // Compute signature share
    int return_val = secp256k1_frost_sign(&computed_signature_share,
                                         msg_hash, num_commitments,
                                         &keypair, current_nonce, signing_commitments);
    
    if (return_val == 1) {
        signature_share_computed = true;
        
        LOG_INF("*** SIGNATURE SHARE COMPUTED SUCCESSFULLY ***");
        log_hex("SIGNATURE SHARE (32 bytes)", computed_signature_share.response, 32);
        
        // Print signature share in hex format
        char hex_str[65];
        for (int i = 0; i < 32; i++) {
            sprintf(hex_str + i * 2, "%02x", computed_signature_share.response[i]);
        }
        hex_str[64] = '\0';
        printk("\n\n=== FROST SIGNATURE SHARE ===\n");
        printk("Participant: %u\n", keypair.public_keys.index);
        printk("Signature: %s\n", hex_str);
        printk("=============================\n\n");
        
        // Wait a moment then send the signature share to the coordinator
        k_msleep(1000);
        LOG_INF("Sending signature share to coordinator...");
        if (!send_signature_share()) {
            LOG_ERR("Failed to send signature share to coordinator");
        }
        
    } else {
        LOG_ERR("Failed to compute signature share");
        signature_share_computed = false;
    }
    
    // Clean up
    k_free(signing_commitments);
}

// UART interrupt callback
static void uart_cb(const struct device *dev, void *user_data) {
    uint8_t byte;
    
    while (uart_irq_update(dev) && uart_irq_is_pending(dev)) {
        if (uart_irq_rx_ready(dev)) {
            while (uart_fifo_read(dev, &byte, 1) == 1) {
                ring_buf_put(&rx_ring_buf, &byte, 1);
            }
        }
    }
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
    
    // Configure UART
    uart_irq_callback_set(uart_dev, uart_cb);
    uart_irq_rx_enable(uart_dev);
    LOG_INF("UART device configured");
    
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
    
    uint8_t temp_buf[64];
    size_t bytes_read;
    
    // Main processing loop
    while (1) {
        // Process received data
        if (rx_state == WAITING_FOR_HEADER) {
            // Try to read complete header
            bytes_read = ring_buf_peek(&rx_ring_buf, temp_buf, sizeof(message_header_t));
            
            if (bytes_read == sizeof(message_header_t)) {
                memcpy(&current_header, temp_buf, sizeof(message_header_t));
                
                // Validate header
                if (current_header.magic != MSG_HEADER_MAGIC) {
                    LOG_ERR("Invalid magic number: 0x%08x", current_header.magic);
                    ring_buf_get(&rx_ring_buf, temp_buf, 1); // Discard one byte
                    continue;
                }
                
                if (current_header.version != MSG_VERSION) {
                    LOG_ERR("Unsupported version: %d", current_header.version);
                    ring_buf_get(&rx_ring_buf, temp_buf, sizeof(message_header_t));
                    continue;
                }
                
                if (current_header.payload_len > MAX_MSG_SIZE) {
                    LOG_ERR("Payload too large: %d", current_header.payload_len);
                    ring_buf_get(&rx_ring_buf, temp_buf, sizeof(message_header_t));
                    continue;
                }
                
                // Header is valid, consume it
                ring_buf_get(&rx_ring_buf, temp_buf, sizeof(message_header_t));
                
                LOG_DBG("Valid header received: type=0x%02x, len=%u", 
                        current_header.msg_type, current_header.payload_len);
                
                if (current_header.payload_len == 0) {
                    // Process message without payload immediately
                    if (current_header.msg_type == MSG_TYPE_READY) {
                        process_ready_message();
                    }
                    rx_state = WAITING_FOR_HEADER;
                } else {
                    // Wait for payload
                    rx_state = WAITING_FOR_PAYLOAD;
                    payload_bytes_received = 0;
                }
            }
        }
        
        if (rx_state == WAITING_FOR_PAYLOAD) {
            // Try to read remaining payload
            uint16_t remaining = current_header.payload_len - payload_bytes_received;
            bytes_read = ring_buf_get(&rx_ring_buf, 
                                     payload_buffer + payload_bytes_received, 
                                     remaining);
            
            payload_bytes_received += bytes_read;
            
            if (payload_bytes_received == current_header.payload_len) {
                // Complete payload received, process message
                LOG_DBG("Complete payload received (%u bytes)", payload_bytes_received);
                
                if (current_header.msg_type == MSG_TYPE_SIGN) {
                    process_sign_message(&current_header, payload_buffer);
                }
                
                rx_state = WAITING_FOR_HEADER;
            }
        }
        
        // Small delay to prevent busy waiting
        k_msleep(10);
    }
    
    // Cleanup (never reached in normal operation)
    if (current_nonce) {
        secp256k1_frost_nonce_destroy(current_nonce);
    }
    secp256k1_context_destroy(ctx);
    
    return 0;
}