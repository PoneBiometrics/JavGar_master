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

LOG_MODULE_REGISTER(frost_nonce_sender, LOG_LEVEL_INF);

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
    MSG_TYPE_END_TRANSMISSION = 0xFF
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
static bool keypair_loaded = false;
static bool ready_received = false;
static bool transmission_complete = false;

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
    char hexstr[65]; // Enough for 32 bytes
    size_t print_len = (len > 32) ? 32 : len;
    
    for (size_t i = 0; i < print_len; i++) {
        snprintf(&hexstr[i * 2], 3, "%02x", data[i]);
    }
    hexstr[print_len * 2] = '\0';
    
    if (len > 32) {
        LOG_INF("%s (first 32 bytes): %s...", label, hexstr);
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

// Function to generate and send nonce commitment
static bool send_nonce_commitment(void) {
    if (!keypair_loaded) {
        LOG_ERR("Keypair not loaded");
        return false;
    }
    
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};

    // Generate randomness for nonce creation
    if (!fill_random(binding_seed, sizeof(binding_seed))) {
        LOG_ERR("Failed to generate binding_seed");
        return false;
    }
    if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
        LOG_ERR("Failed to generate hiding_seed");
        return false;
    }

    LOG_INF("Generating nonce commitment for participant %u", keypair.public_keys.index);

    // Create nonce and commitment
    secp256k1_frost_nonce *nonce = secp256k1_frost_nonce_create(ctx, &keypair, binding_seed, hiding_seed);
    if (!nonce) {
        LOG_ERR("Failed to create nonce");
        return false;
    }

    // Log the generated commitments
    log_hex("Nonce hiding commitment", nonce->commitments.hiding, 32);
    log_hex("Nonce binding commitment", nonce->commitments.binding, 32);

    // Prepare serialized data
    serialized_nonce_commitment_t serialized;
    serialized.participant_index = keypair.public_keys.index;
    memcpy(serialized.hiding, nonce->commitments.hiding, 32);
    memcpy(serialized.binding, nonce->commitments.binding, 32);

    // Send the commitment
    bool result = send_message(MSG_TYPE_NONCE_COMMITMENT, keypair.public_keys.index,
                              &serialized, sizeof(serialized));

    // Clean up
    secp256k1_frost_nonce_destroy(nonce);
    
    if (result) {
        LOG_INF("Nonce commitment sent successfully");
    } else {
        LOG_ERR("Failed to send nonce commitment");
    }
    
    return result;
}

// Process received READY message
static void process_ready_message(const message_header_t *header) {
    LOG_INF("*** Received READY signal from host (participant %u) ***", header->participant);
    ready_received = true;
    
    // Generate and send nonce commitment
    if (send_nonce_commitment()) {
        // Send end transmission marker
        if (send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0)) {
            LOG_INF("End transmission marker sent");
            transmission_complete = true;
        } else {
            LOG_ERR("Failed to send end transmission marker");
        }
    } else {
        LOG_ERR("Failed to send nonce commitment");
    }
}

// Process a complete received message
static void process_message(const message_header_t *header, const uint8_t *payload) {
    LOG_INF("Processing message: type=0x%02x, participant=%u, len=%u", 
            header->msg_type, header->participant, header->payload_len);
    
    switch (header->msg_type) {
        case MSG_TYPE_READY:
            process_ready_message(header);
            break;
        
        default:
            LOG_WRN("Unknown message type: 0x%02x", header->msg_type);
            break;
    }
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
void main(void) {
    LOG_INF("=== FROST UART Nonce Commitment Sender Starting ===");
    
    // Initialize ring buffer
    ring_buf_init(&rx_ring_buf, sizeof(rx_buf), rx_buf);
    
    // Get UART device
    uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);
    if (!device_is_ready(uart_dev)) {
        LOG_ERR("UART device not ready");
        return;
    }
    
    // Configure UART
    uart_irq_callback_set(uart_dev, uart_cb);
    uart_irq_rx_enable(uart_dev);
    LOG_INF("UART device configured");
    
    // Initialize secp256k1 context
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL) {
        LOG_ERR("Failed to create secp256k1 context");
        return;
    }
    LOG_INF("secp256k1 context created");
    
    // Load FROST key material from flash
    int rc = load_frost_key_material();
    if (rc != 0) {
        LOG_ERR("Failed to load FROST key material from flash (%d)", rc);
        secp256k1_context_destroy(ctx);
        return;
    }
    
    LOG_INF("=== Ready to receive READY signal and send nonce commitment ===");
    
    uint8_t temp_buf[64];
    size_t bytes_read;
    
    // Main processing loop
    while (!transmission_complete) {
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
                    // No payload, process immediately
                    process_message(&current_header, NULL);
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
                process_message(&current_header, payload_buffer);
                rx_state = WAITING_FOR_HEADER;
            }
        }
        
        // Small delay to prevent busy waiting
        k_msleep(10);
    }
    
    // Cleanup
    secp256k1_context_destroy(ctx);
    LOG_INF("=== FROST UART nonce commitment sender completed ===");
}