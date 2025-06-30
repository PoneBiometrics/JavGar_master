#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include "examples_util.h"

// Initialize logging module for this application
LOG_MODULE_REGISTER(frost_receiver, LOG_LEVEL_INF);

#define RING_BUF_SIZE 1024          
#define MAX_MSG_SIZE 512            
#define UART_DEVICE_NODE DT_NODELABEL(usart1)  // Device tree UART node

// Message protocol definitions
#define MSG_HEADER_MAGIC 0x46524F53 // "FROS" as hex 
#define MSG_VERSION 0x01            

// Message types for FROST key distribution protocol
typedef enum {
    MSG_TYPE_SECRET_SHARE = 0x01,       
    MSG_TYPE_PUBLIC_KEY = 0x02,         
    MSG_TYPE_COMMITMENTS = 0x03,       
    MSG_TYPE_END_TRANSMISSION = 0xFF    
} message_type_t;

// Header structure for each message in the protocol
typedef struct {
    uint32_t magic;       
    uint8_t version;       
    uint8_t msg_type;      
    uint16_t payload_len;  
    uint32_t participant;  
} __packed message_header_t;

// Flash storage partition identifier
#define STORAGE_PARTITION     storage_partition

typedef struct {
    // Keypair storage
    uint32_t keypair_index;                 
    uint32_t keypair_max_participants;      
    uint8_t keypair_secret[32];             
    uint8_t keypair_public_key[64];         
    uint8_t keypair_group_public_key[64];   

    // Commitments storage 
    uint32_t commitments_index;             
    uint32_t commitments_num_coefficients; 
    uint8_t commitments_zkp_z[32];         
    uint8_t commitments_zkp_r[64];          
    // Assuming maximum threshold of 10 coefficients for polynomial
    uint8_t commitments_coefficient_data[10 * sizeof(secp256k1_frost_vss_commitment)];
} __packed frost_flash_storage_t;

// FROST cryptographic structures 
static secp256k1_context *ctx;                     
static secp256k1_frost_keypair keypair;            
static secp256k1_frost_vss_commitments *commitments; 

// Communication buffers and UART device
static uint8_t rx_buf[RING_BUF_SIZE];   
static struct ring_buf rx_ring_buf;     
static const struct device *uart_dev;   

// Message receive state machine
typedef enum {
    WAITING_FOR_HEADER,     
    WAITING_FOR_PAYLOAD     
} receive_state_t;

// Reception state variables
static receive_state_t rx_state = WAITING_FOR_HEADER;  /
static message_header_t current_header;                
static uint8_t payload_buffer[MAX_MSG_SIZE];           
static size_t payload_bytes_received = 0;              

// Helper function to log binary data as hexadecimal
void log_hex_bytes(const char *label, const unsigned char *data, size_t len) {
    char hex_buf[3 * MAX_MSG_SIZE + 1];  // Buffer for hex string (2 chars + space per byte)
    size_t pos = 0;

    for (size_t i = 0; i < len && pos < sizeof(hex_buf) - 3; i++) {
        pos += snprintf(&hex_buf[pos], sizeof(hex_buf) - pos, "%02x ", data[i]);
    }

    hex_buf[pos] = '\0';
    LOG_INF("%s: %s", label, hex_buf);
}

int write_frost_data_to_flash(void) {
    const struct flash_area *fa;
    
    // Open the designated flash partition for storage
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc < 0) {
        LOG_ERR("Failed to open flash area (%d)", rc);
        return rc;
    }

    frost_flash_storage_t flash_data = {0};

    // Fill keypair data from the received and processed information
    flash_data.keypair_index = keypair.public_keys.index;
    flash_data.keypair_max_participants = keypair.public_keys.max_participants;
    memcpy(flash_data.keypair_secret, keypair.secret, 32);
    memcpy(flash_data.keypair_public_key, keypair.public_keys.public_key, 64);
    memcpy(flash_data.keypair_group_public_key, keypair.public_keys.group_public_key, 64);

    // Get flash device handle and verify it's ready
    const struct device *flash_dev = flash_area_get_device(fa);
    if (!device_is_ready(flash_dev)) {
        LOG_ERR("Flash device not ready");
        flash_area_close(fa);
        return -1;
    }

    // Get flash page information for proper erase alignment
    struct flash_pages_info info;
    rc = flash_get_page_info_by_offs(flash_dev, fa->fa_off, &info);
    if (rc != 0) {
        LOG_ERR("Failed to get flash page info (%d)", rc);
        flash_area_close(fa);
        return rc;
    }

    // Erase flash sector
    size_t erase_size = ROUND_UP(sizeof(frost_flash_storage_t), info.size);
    rc = flash_area_erase(fa, 0, erase_size);
    if (rc != 0) {
        LOG_ERR("Failed to erase flash (%d)", rc);
        flash_area_close(fa);
        return rc;
    }

    // Prepare write buffer with proper alignment for flash write requirements
    size_t write_block_size = flash_get_write_block_size(flash_dev);
    size_t padded_size = ROUND_UP(sizeof(frost_flash_storage_t), write_block_size);
    uint8_t padded_buf[padded_size];
    
    // Initialize padding with 0xFF
    memset(padded_buf, 0xFF, padded_size);
    memcpy(padded_buf, &flash_data, sizeof(frost_flash_storage_t));

    // Write the data to flash storage
    rc = flash_area_write(fa, 0, padded_buf, padded_size);
    if (rc != 0) {
        LOG_ERR("Failed to write to flash (%d)", rc);
        flash_area_close(fa);
        return rc;
    }

    LOG_INF("FROST key material written to flash.");
    flash_area_close(fa);
    return 0;
}

int read_frost_data_from_flash(void) {
    const struct flash_area *fa;
    
    // Open the flash partition where data was stored
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc < 0) {
        LOG_ERR("Failed to open flash area (%d)", rc);
        return rc;
    }

    // Read back the stored data structure
    frost_flash_storage_t flash_data;
    rc = flash_area_read(fa, 0, &flash_data, sizeof(frost_flash_storage_t));
    if (rc != 0) {
        LOG_ERR("Failed to read flash: %d", rc);
        flash_area_close(fa);
        return rc;
    }

    // Log the retrieved keypair information for verification
    LOG_INF("=== Stored Keypair ===");
    LOG_INF("Participant Index: %d", flash_data.keypair_index);
    LOG_INF("Max Participants: %d", flash_data.keypair_max_participants);
    
    char hex_buf[129];  
    
    // Log the secret share (32 bytes)
    for (int i = 0; i < 32; i++) {
        sprintf(&hex_buf[i * 2], "%02x", flash_data.keypair_secret[i]);
    }
    hex_buf[64] = '\0';
    LOG_INF("Secret Share: %s", hex_buf);

    // Log the public key (64 bytes)
    for (int i = 0; i < 64; i++) {
        sprintf(&hex_buf[i * 2], "%02x", flash_data.keypair_public_key[i]);
    }
    hex_buf[128] = '\0';
    LOG_INF("Public Key: %s", hex_buf);

    // Log the group public key (64 bytes)
    for (int i = 0; i < 64; i++) {
        sprintf(&hex_buf[i * 2], "%02x", flash_data.keypair_group_public_key[i]);
    }
    hex_buf[128] = '\0';
    LOG_INF("Group Public Key: %s", hex_buf);

    flash_area_close(fa);
    return 0;
}

static void process_secret_share(const uint8_t *payload, uint16_t len) {
    // Validate payload size - should contain receiver index + 32-byte share
    if (len != sizeof(uint32_t) + 32) {
        LOG_ERR("Invalid secret share payload size: %d", len);
        return;
    }
    
    // Extract receiver index
    uint32_t receiver_index;
    memcpy(&receiver_index, payload, sizeof(uint32_t));
    
    // Store the secret share in the keypair structure
    memcpy(keypair.secret, payload + sizeof(uint32_t), 32);
    
    LOG_INF("Received secret share for participant %d", receiver_index);
    log_hex_bytes("Secret share", keypair.secret, 32);
}

static void process_public_key(const uint8_t *payload, uint16_t len) {
    // Validate payload size - should contain index + max_participants + 2 * 64-byte keys
    if (len != sizeof(uint32_t) * 2 + 64 + 64) { 
        LOG_ERR("Invalid public key payload size: %d (expected %zu)", len, sizeof(uint32_t) * 2 + 64 + 64);
        return;
    }
    
    // Parse the public key message payload
    uint32_t index, max_participants;
    uint8_t *ptr = (uint8_t *)payload;
    
    // Extract participant index
    memcpy(&index, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    
    // Extract maximum number of participants
    memcpy(&max_participants, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    
    // Initialize the public key part of the keypair structure
    keypair.public_keys.index = index;
    keypair.public_keys.max_participants = max_participants;
    
    // Copy this participant's public key (64 bytes)
    memcpy(keypair.public_keys.public_key, ptr, 64);
    ptr += 64;
    
    // Copy the group's aggregate public key (64 bytes)
    memcpy(keypair.public_keys.group_public_key, ptr, 64); 
    
    LOG_INF("Received public key for index %d (max participants: %d)",
           index, max_participants);
    log_hex_bytes("Public key", keypair.public_keys.public_key, 64);
    log_hex_bytes("Group public key", keypair.public_keys.group_public_key, 64);
}

static void process_commitments(const uint8_t *payload, uint16_t len) {
    // Validate minimum payload size for commitments
    if (len < sizeof(uint32_t) * 2 + 32 + 64) {
        LOG_ERR("Invalid commitments payload size: %d", len);
        return;
    }
    
    // Parse commitments data from payload
    uint32_t index, num_coefficients;
    uint8_t *ptr = (uint8_t *)payload;
    
    // Extract commitment index
    memcpy(&index, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    
    // Extract number of polynomial coefficients
    memcpy(&num_coefficients, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    

    if (commitments != NULL) {
        secp256k1_frost_vss_commitments_destroy(commitments);
    }
    
    // Create new commitments structure for the received data
    commitments = secp256k1_frost_vss_commitments_create(num_coefficients);
    if (commitments == NULL) {
        LOG_ERR("Failed to create commitments structure");
        return;
    }
    
    // Fill in the commitments data structure
    commitments->index = index;
    commitments->num_coefficients = num_coefficients;
    
    // Copy zero-knowledge proof components
    memcpy(commitments->zkp_z, ptr, 32); 
    ptr += 32;
    
    memcpy(commitments->zkp_r, ptr, 64); 
    ptr += 64;
    
    // Copy the polynomial coefficient commitments
    size_t coef_data_size = num_coefficients * sizeof(secp256k1_frost_vss_commitment);
    memcpy(commitments->coefficient_commitments, ptr, coef_data_size);
    
    LOG_INF("Received commitments (index: %d, num_coefficients: %d)", 
           index, num_coefficients);
}

// Process end of transmission signal
static void process_end_transmission(void) {
    LOG_INF("End of transmission received");
    LOG_INF("All FROST key material received successfully!");

    int rc = write_frost_data_to_flash();
    if (rc == 0) {
        read_frost_data_from_flash();
    }
}

// Message processing function 
static void process_message(const message_header_t *header, const uint8_t *payload) {
    LOG_INF("Processing message type 0x%02x for participant %d (payload len: %d)", 
           header->msg_type, header->participant, header->payload_len);
    
    switch (header->msg_type) {
        case MSG_TYPE_SECRET_SHARE:
            process_secret_share(payload, header->payload_len);
            break;
        
        case MSG_TYPE_PUBLIC_KEY:
            process_public_key(payload, header->payload_len);
            break;
        
        case MSG_TYPE_COMMITMENTS:
            process_commitments(payload, header->payload_len);
            break;
        
        case MSG_TYPE_END_TRANSMISSION:
            process_end_transmission();
            break;
        
        default:
            LOG_WRN("Unknown message type: 0x%02x", header->msg_type);
            break;
    }
}

// UART interrupt service routine callback
static void uart_cb(const struct device *dev, void *user_data) {
    uint8_t byte;
    
    // Process all available bytes from UART FIFO
    while (uart_irq_update(dev) && uart_irq_is_pending(dev)) {
        if (uart_irq_rx_ready(dev)) {
            // Read available bytes into ring buffer for later processing
            while (uart_fifo_read(dev, &byte, 1) == 1) {
                ring_buf_put(&rx_ring_buf, &byte, 1);
            }
        }
    }
}

void main(void) {
    uint8_t temp_buf[64];       
    size_t bytes_read;          
    
    LOG_INF("FROST Key Receiver starting...");
    
    ring_buf_init(&rx_ring_buf, sizeof(rx_buf), rx_buf);
    
    uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);
    if (!device_is_ready(uart_dev)) {
        LOG_ERR("UART device not ready");
        return;
    }
    
    // Configure UART interrupts for asynchronous reception
    uart_irq_callback_set(uart_dev, uart_cb);
    uart_irq_rx_enable(uart_dev);
    
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx == NULL) {
        LOG_ERR("Failed to create secp256k1 context");
        return;
    }
    
    // Initialize FROST data structures to clean state
    memset(&keypair, 0, sizeof(keypair));
    commitments = NULL;
    
    LOG_INF("Ready to receive FROST key material...");
    
    // Main message processing loop
    while (1) {
        if (rx_state == WAITING_FOR_HEADER) {
            bytes_read = ring_buf_peek(&rx_ring_buf, temp_buf, sizeof(message_header_t));
            
            if (bytes_read == sizeof(message_header_t)) {
                memcpy(&current_header, temp_buf, sizeof(message_header_t));
                
                // Validate magic number - ensures we're processing our protocol
                if (current_header.magic != MSG_HEADER_MAGIC) {
                    LOG_ERR("Invalid magic number: 0x%08x", current_header.magic);
                    // Discard one byte and try to resync
                    ring_buf_get(&rx_ring_buf, temp_buf, 1);
                    continue;
                }
                
                // Validate protocol version for compatibility
                if (current_header.version != MSG_VERSION) {
                    LOG_ERR("Unsupported protocol version: %d", current_header.version);
                    // Discard the invalid header
                    ring_buf_get(&rx_ring_buf, temp_buf, sizeof(message_header_t));
                    continue;
                }
                
                // Validate payload size is reasonable
                if (current_header.payload_len > MAX_MSG_SIZE) {
                    LOG_ERR("Payload too large: %d", current_header.payload_len);
                    // Discard the invalid header
                    ring_buf_get(&rx_ring_buf, temp_buf, sizeof(message_header_t));
                    continue;
                }
                
                // Header is valid - consume it from the ring buffer
                ring_buf_get(&rx_ring_buf, temp_buf, sizeof(message_header_t));
                
                // Check if this message has no payload
                if (current_header.payload_len == 0) {
                    process_message(&current_header, NULL);
                } else {
                    rx_state = WAITING_FOR_PAYLOAD;
                    payload_bytes_received = 0;
                }
            }
        }
        
        // Handle payload reception state
        if (rx_state == WAITING_FOR_PAYLOAD) {
            // Calculate how many more payload bytes we need
            uint16_t remaining = current_header.payload_len - payload_bytes_received;
            
            // Try to read remaining payload bytes
            bytes_read = ring_buf_get(&rx_ring_buf, 
                                     payload_buffer + payload_bytes_received, 
                                     remaining);
            
            payload_bytes_received += bytes_read;
            
            // Check if payload reception is complete
            if (payload_bytes_received == current_header.payload_len) {
                process_message(&current_header, payload_buffer);
                rx_state = WAITING_FOR_HEADER;
            }
        }
        
        k_msleep(10);
    }
}