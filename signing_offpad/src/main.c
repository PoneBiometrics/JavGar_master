#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/class/usb_hid.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/random/rand32.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <stdlib.h>

#define LOG_LEVEL LOG_LEVEL_INF
LOG_MODULE_REGISTER(frost_hid_device);

// Flash storage partition
#define STORAGE_PARTITION storage_partition

// HID configuration
#define REPORT_ID_INPUT  0x01
#define REPORT_ID_OUTPUT 0x02
#define HID_EP_BUSY_FLAG 0
#define HID_REPORT_SIZE  64
#define CHUNK_SIZE       61
#define CHUNK_DELAY_MS   50

// Message protocol constants
#define MSG_HEADER_MAGIC 0x46524F53 // "FROS"
#define MSG_VERSION      0x01

// Message types
typedef enum {
    MSG_TYPE_NONCE_COMMITMENT  = 0x04,
    MSG_TYPE_END_TRANSMISSION  = 0xFF,
    MSG_TYPE_READY             = 0x06,
    MSG_TYPE_SIGN              = 0x07,
    MSG_TYPE_SIGNATURE_SHARE   = 0x08
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
    uint32_t participant_index;
    uint8_t hiding[32];
    uint8_t binding[32];
} __packed serialized_nonce_commitment_t;

// Updated signature share structure with public key AND group public key
typedef struct {
    uint32_t participant_index;
    uint8_t response[32];
    uint8_t public_key[64]; // Public key of the participant
    uint8_t group_public_key[64]; // Group public key for aggregation
} __packed serialized_signature_share_t;

// Flash storage structure
typedef struct {
    uint32_t keypair_index;
    uint32_t keypair_max_participants;
    uint8_t keypair_secret[32];
    uint8_t keypair_public_key[64];
    uint8_t keypair_group_public_key[64]; // Changed from 33 to 64 bytes
} __packed frost_flash_storage_t;

// Global state
static bool configured = false;
static const struct device *hdev;
static ATOMIC_DEFINE(hid_ep_in_busy, 1);
static struct k_work sign_work;
static struct k_work send_share_work;
static frost_flash_storage_t flash_data;
static bool flash_data_valid = false;
static uint8_t chunk_buffer[HID_REPORT_SIZE];
static secp256k1_context *secp256k1_ctx;
static secp256k1_frost_keypair keypair;
static secp256k1_frost_nonce *current_nonce = NULL;

// Store computed signature share
static secp256k1_frost_signature_share computed_signature_share;
static bool signature_share_computed = false;

// Receive buffer for accumulating messages
static uint8_t receive_buffer[512];
static size_t receive_buffer_pos = 0;

// Fixed HID Report Descriptor
static const uint8_t hid_report_desc[] = {
    0x06, 0x00, 0xFF,       // Usage Page (Vendor)
    0x09, 0x01,             // Usage (Custom)
    0xA1, 0x01,             // Collection (Application)
    
    // Input Report (Device to Host)
    0x85, REPORT_ID_INPUT,  // Report ID (Input)
    0x09, 0x02,             // Usage (Data)
    0x15, 0x00,             // Logical Min (0)
    0x26, 0xFF, 0x00,       // Logical Max (255)
    0x75, 0x08,             // Report Size (8)
    0x95, 0x3F,             // Report Count (63)
    0x81, 0x02,             // Input (Data,Var,Abs)
    
    // Output Report (Host to Device) 
    0x85, REPORT_ID_OUTPUT, // Report ID (Output)
    0x09, 0x03,             // Usage (Feature)
    0x15, 0x00,             // Logical Min (0)
    0x26, 0xFF, 0x00,       // Logical Max (255)
    0x75, 0x08,             // Report Size (8)
    0x95, 0x3F,             // Report Count (63)
    0x91, 0x02,             // Output (Data,Var,Abs)
    
    0xC0                    // End Collection
};

// Fill buffer with random data
static bool fill_random(unsigned char *data, size_t len) {
    sys_csrand_get(data, len);
    return true;
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

// Generate nonce at startup
static void generate_nonce(void) {
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

    if (current_nonce != NULL) {
        secp256k1_frost_nonce_destroy(current_nonce);
    }
    
    current_nonce = secp256k1_frost_nonce_create(
        secp256k1_ctx, &keypair, binding_seed, hiding_seed);
    
    if (current_nonce) {
        LOG_INF("Generated nonce at startup");
        log_hex("Nonce hiding", current_nonce->commitments.hiding, 32);
        log_hex("Nonce binding", current_nonce->commitments.binding, 32);
    } else {
        LOG_ERR("Failed to generate nonce at startup");
    }
}

// Process accumulated message data
static void process_received_message(void) {
    LOG_DBG("Processing receive buffer: %zu bytes", receive_buffer_pos);
    
    if (receive_buffer_pos < sizeof(message_header_t)) {
        LOG_DBG("Insufficient data for header (%zu bytes, need %zu)", 
                receive_buffer_pos, sizeof(message_header_t));
        return;
    }
    
    const message_header_t *header = (const message_header_t *)receive_buffer;
    
    LOG_DBG("Header check: magic=0x%08x (expected=0x%08x), version=%d, type=0x%02x, len=%d", 
            header->magic, MSG_HEADER_MAGIC, header->version, header->msg_type, header->payload_len);
    
    // Validate message header
    if (header->magic != MSG_HEADER_MAGIC || header->version != MSG_VERSION) {
        LOG_WRN("Invalid message header: magic=0x%08x, version=%d", 
                header->magic, header->version);
        // Reset buffer on invalid message
        receive_buffer_pos = 0;
        return;
    }
    
    // Check if we have the complete message
    size_t expected_total = sizeof(message_header_t) + header->payload_len;
    if (receive_buffer_pos < expected_total) {
        LOG_DBG("Waiting for more data: have %zu, need %zu", receive_buffer_pos, expected_total);
        return;
    }
    
    // Process the message
    const uint8_t* payload = receive_buffer + sizeof(message_header_t);
    
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
    
    // Reset buffer after processing
    LOG_DBG("Resetting receive buffer");
    receive_buffer_pos = 0;
}

// HID callbacks
static void int_in_ready_cb(const struct device *dev) {
    atomic_clear_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
}

static void int_out_ready_cb(const struct device *dev) {
    uint8_t buffer[HID_REPORT_SIZE];
    int ret, received;
    
    ret = hid_int_ep_read(dev, buffer, sizeof(buffer), &received);
    if (ret == 0 && received > 0) {
        LOG_DBG("Received %d bytes from host", received);
        
        // Debug: Print received buffer
        if (received >= 3) {
            LOG_DBG("Raw HID data: ID=0x%02X, Len=%d, Data[0]=0x%02X, Data[1]=0x%02X", 
                    buffer[0], received > 1 ? buffer[1] : 0, 
                    received > 2 ? buffer[2] : 0, received > 3 ? buffer[3] : 0);
        }
        
        // Process HID report: [Report ID][Length][Data...]
        if (received >= 3 && buffer[0] == REPORT_ID_OUTPUT) {
            uint8_t chunk_len = buffer[1];
            
            LOG_DBG("Processing chunk: report_id=%d, chunk_len=%d", buffer[0], chunk_len);
            
            if (chunk_len > 0 && chunk_len <= (received - 2)) {
                size_t available_space = sizeof(receive_buffer) - receive_buffer_pos;
                size_t copy_len = (chunk_len < available_space) ? chunk_len : available_space;
                
                if (copy_len > 0) {
                    memcpy(receive_buffer + receive_buffer_pos, buffer + 2, copy_len);
                    receive_buffer_pos += copy_len;
                    
                    LOG_DBG("Appended %zu bytes to receive buffer (total: %zu)", 
                            copy_len, receive_buffer_pos);
                    
                    // Try to process the accumulated message
                    process_received_message();
                } else {
                    LOG_WRN("No space available in receive buffer");
                }
            } else {
                LOG_WRN("Invalid chunk length: %d (received: %d)", chunk_len, received);
            }
        } else {
            LOG_WRN("Invalid HID report format: ID=0x%02X, received=%d", 
                    received > 0 ? buffer[0] : 0, received);
        }
    } else if (ret != 0) {
        LOG_ERR("Failed to read from HID endpoint: %d", ret);
    }
}

static void protocol_cb(const struct device *dev, uint8_t protocol) {
    LOG_INF("Protocol: %s", protocol == HID_PROTOCOL_BOOT ? "boot" : "report");
}

static const struct hid_ops ops = {
    .int_in_ready = int_in_ready_cb,
    .int_out_ready = int_out_ready_cb,
    .protocol_change = protocol_cb,
};

// USB status callback
static void status_cb(enum usb_dc_status_code status, const uint8_t *param) {
    switch (status) {
    case USB_DC_RESET:
        configured = false;
        receive_buffer_pos = 0;
        LOG_INF("USB Reset");
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

// Read FROST data from flash
static int read_frost_data_from_flash(void) {
    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(STORAGE_PARTITION), &fa);
    if (rc < 0) {
        LOG_ERR("Failed to open flash area (%d)", rc);
        return rc;
    }

    if (fa->fa_size < sizeof(frost_flash_storage_t)) {
        LOG_ERR("Flash area too small");
        flash_area_close(fa);
        return -ENOSPC;
    }

    rc = flash_area_read(fa, 0, &flash_data, sizeof(frost_flash_storage_t));
    flash_area_close(fa);
    
    if (rc != 0) {
        LOG_ERR("Failed to read flash: %d", rc);
        return rc;
    }

    if (flash_data.keypair_index == 0 || flash_data.keypair_index > 255) {
        LOG_WRN("Invalid flash data (index=%u)", flash_data.keypair_index);
        return -EINVAL;
    }

    flash_data_valid = true;
    LOG_INF("Flash data loaded - Participant: %u", flash_data.keypair_index);
    return 0;
}

// Load key material into secp256k1 structure
static int load_frost_key_material(void) {
    if (!flash_data_valid) return -1;
    
    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    keypair.public_keys.index = flash_data.keypair_index;
    keypair.public_keys.max_participants = flash_data.keypair_max_participants;
    memcpy(keypair.secret, flash_data.keypair_secret, 32);
    memcpy(keypair.public_keys.public_key, flash_data.keypair_public_key, 64);
    memcpy(keypair.public_keys.group_public_key, 
           flash_data.keypair_group_public_key, 64);
    
    return 0;
}

// Send data in chunks via HID
static int send_chunked_data(const uint8_t *data, size_t len) {
    if (!configured || !data || len == 0) {
        return -EINVAL;
    }

    size_t offset = 0;
    int chunk_count = 0;
    
    while (offset < len) {
        // Wait for endpoint to be available
        int timeout = 100;
        while (atomic_test_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG) && timeout-- > 0) {
            k_msleep(10);
        }
        if (timeout <= 0) {
            LOG_ERR("HID endpoint timeout");
            return -ETIMEDOUT;
        }
        
        // Prepare chunk
        memset(chunk_buffer, 0, sizeof(chunk_buffer));
        chunk_buffer[0] = REPORT_ID_INPUT;
        size_t remaining = len - offset;
        size_t chunk_size = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
        chunk_buffer[1] = (uint8_t)chunk_size;
        memcpy(&chunk_buffer[2], data + offset, chunk_size);
        
        // Send chunk
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
    
    LOG_INF("Sent %d chunks (%zu bytes total)", chunk_count, len);
    return 0;
}

// Send a complete message
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

// Generate and send nonce commitment
static int send_nonce_commitment(void) {
    if (!current_nonce) {
        LOG_ERR("No nonce available to send commitment");
        return -1;
    }
    
    serialized_nonce_commitment_t serialized = {
        .participant_index = keypair.public_keys.index
    };
    memcpy(serialized.hiding, current_nonce->commitments.hiding, 32);
    memcpy(serialized.binding, current_nonce->commitments.binding, 32);
    
    LOG_INF("Sending nonce commitment for participant %u", keypair.public_keys.index);
    
    int ret = send_message(MSG_TYPE_NONCE_COMMITMENT, 
                          keypair.public_keys.index,
                          &serialized, sizeof(serialized));
    
    return ret;
}

// Updated function to send signature share with public key AND group public key
static int send_signature_share(void) {
    if (!signature_share_computed) {
        LOG_ERR("No signature share computed yet");
        return -1;
    }

    serialized_signature_share_t serialized = {
        .participant_index = keypair.public_keys.index
    };
    memcpy(serialized.response, computed_signature_share.response, 32);
    // Include public key and group public key in the response
    memcpy(serialized.public_key, keypair.public_keys.public_key, 64);
    memcpy(serialized.group_public_key, keypair.public_keys.group_public_key, 64);

    LOG_INF("*** SENDING SIGNATURE SHARE TO COORDINATOR WITH PUBLIC KEY AND GROUP PUBLIC KEY ***");
    log_hex("Signature Share", serialized.response, 32);
    log_hex("Public Key", serialized.public_key, 32);
    log_hex("Group Public Key", serialized.group_public_key, 32);

    int ret = send_message(MSG_TYPE_SIGNATURE_SHARE, 
                          keypair.public_keys.index,
                          &serialized, sizeof(serialized));
    
    if (ret == 0) {
        LOG_INF("Signature share sent successfully to coordinator");
        // Send end transmission marker
        send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0);
    } else {
        LOG_ERR("Failed to send signature share to coordinator");
    }
    
    return ret;
}

// Process signing data and compute signature share
static void process_sign_message(void) {
    const message_header_t *header = (const message_header_t *)receive_buffer;
    const uint8_t* payload = receive_buffer + sizeof(message_header_t);
    
    if (header->payload_len < 32 + 4) {
        LOG_ERR("Invalid sign message length");
        return;
    }
    
    if (!current_nonce) {
        LOG_ERR("No nonce available for signing");
        return;
    }
    
    if (current_nonce->used) {
        LOG_ERR("Nonce already used");
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
    
    // Convert serialized commitments to secp256k1_frost_nonce_commitment array
    secp256k1_frost_nonce_commitment *signing_commitments = 
        malloc(num_commitments * sizeof(secp256k1_frost_nonce_commitment));
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
        
        // Print signature share to console
        char hex_str[65];
        for (int i = 0; i < 32; i++) {
            sprintf(hex_str + i * 2, "%02x", computed_signature_share.response[i]);
        }
        hex_str[64] = '\0';
        printk("\n\n=== FROST SIGNATURE SHARE ===\n");
        printk("Participant: %u\n", keypair.public_keys.index);
        printk("Signature: %s\n", hex_str);
        printk("=============================\n\n");
        
        // Schedule work to send signature share to coordinator
        k_work_submit(&send_share_work);
        
    } else {
        LOG_ERR("Failed to compute signature share");
        signature_share_computed = false;
    }
    
    // Clean up
    free(signing_commitments);
}

// Work handler for sending signature share
static void send_share_work_handler(struct k_work *work) {
    if (!configured || !flash_data_valid || !signature_share_computed) {
        LOG_ERR("Device not ready for sending signature share");
        return;
    }
    
    LOG_INF("Sending signature share to coordinator...");
    
    // Wait a moment before sending to ensure coordinator is ready
    k_msleep(1000);
    
    if (send_signature_share() != 0) {
        LOG_ERR("Failed to send signature share to coordinator");
    }
}

// Work handler
static void sign_work_handler(struct k_work *work) {
    if (!configured || !flash_data_valid) {
        LOG_ERR("Device not ready for signing");
        return;
    }
    
    const message_header_t *header = (const message_header_t *)receive_buffer;
    
    switch (header->msg_type) {
        case MSG_TYPE_READY:
            LOG_INF("Processing READY message");
            if (send_nonce_commitment() == 0) {
                // Send end transmission marker
                send_message(MSG_TYPE_END_TRANSMISSION, keypair.public_keys.index, NULL, 0);
            }
            break;
            
        case MSG_TYPE_SIGN:
            LOG_INF("Processing SIGN message");
            process_sign_message();
            break;
            
        default:
            LOG_WRN("Unknown message type in work handler");
            break;
    }
}

int main(void) {
    int ret;
    LOG_INF("=== FROST HID Signing Device Starting ===");
    
    // Create secp256k1 context
    secp256k1_ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (secp256k1_ctx == NULL) {
        LOG_ERR("Failed to create secp256k1 context");
        return -1;
    }
    
    // Initialize work queues
    k_work_init(&sign_work, sign_work_handler);
    k_work_init(&send_share_work, send_share_work_handler);
    
    // Read flash data
    if (read_frost_data_from_flash() != 0) {
        LOG_ERR("Failed to read flash data");
        return -1;
    }
    
    // Load key material
    if (load_frost_key_material() != 0) {
        LOG_ERR("Failed to load key material");
        return -1;
    }
    
    // Generate nonce at startup
    generate_nonce();
    
    // Initialize USB HID
    hdev = device_get_binding("HID_0");
    if (hdev == NULL) {
        LOG_ERR("Cannot get USB HID Device");
        return -1;
    }
    
    usb_hid_register_device(hdev, hid_report_desc, sizeof(hid_report_desc), &ops);
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
    
    LOG_INF("=== FROST HID Device Ready ===");
    
    // Main loop
    while (1) {
        k_msleep(1000);
    }
    
    // Cleanup (never reached)
    if (current_nonce) {
        secp256k1_frost_nonce_destroy(current_nonce);
    }
    secp256k1_context_destroy(secp256k1_ctx);
    
    return 0;
}