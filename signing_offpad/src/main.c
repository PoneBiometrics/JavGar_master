/*
 * FROST Nonce Commitment Sender - USB HID Version (Fixed)
 * Waits for READY signal before sending nonce commitments
 */
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
LOG_MODULE_REGISTER(frost_sender);

// Flash storage partition
#define STORAGE_PARTITION storage_partition

// HID configuration
#define REPORT_ID_INPUT  0x01
#define REPORT_ID_OUTPUT 0x02
#define HID_EP_BUSY_FLAG 0
#define HID_REPORT_SIZE  64
#define CHUNK_SIZE       61    // 64 - 1 (report ID) - 1 (length) - 1 (safety)
#define CHUNK_DELAY_MS   50

// Message protocol constants
#define MSG_HEADER_MAGIC 0x46524F53 // "FROS"
#define MSG_VERSION      0x01

// Message types
typedef enum {
    MSG_TYPE_NONCE_COMMITMENT  = 0x04,
    MSG_TYPE_END_TRANSMISSION  = 0xFF,
    MSG_TYPE_READY             = 0x06
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

// Flash storage structure
typedef struct {
    uint32_t keypair_index;
    uint32_t keypair_max_participants;
    uint8_t keypair_secret[32];
    uint8_t keypair_public_key[64];
    uint8_t keypair_group_public_key[33];
} __packed frost_flash_storage_t;

// Global state
static bool configured = false;
static const struct device *hdev;
static ATOMIC_DEFINE(hid_ep_in_busy, 1);
static struct k_work send_work;
static frost_flash_storage_t flash_data;
static bool flash_data_valid = false;
static uint8_t chunk_buffer[HID_REPORT_SIZE];
static secp256k1_context *secp256k1_ctx;
static secp256k1_frost_keypair keypair;

// State variables
static bool host_ready = false;
static bool transmission_complete = false;

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
    if (header->msg_type == MSG_TYPE_READY) {
        LOG_INF("*** Received READY signal from host (participant %u) ***", header->participant);
        host_ready = true;
        
        // Trigger transmission if configured
        if (configured && !transmission_complete) {
            LOG_INF("*** Triggering nonce transmission ***");
            k_work_submit(&send_work);
        } else {
            LOG_WRN("Cannot trigger transmission: configured=%d, complete=%d", 
                    configured, transmission_complete);
        }
    } else {
        LOG_DBG("Received message type 0x%02x (not READY)", header->msg_type);
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
                    
                    // Debug: Print what we have so far
                    if (receive_buffer_pos >= 4) {
                        uint32_t magic = *(uint32_t*)receive_buffer;
                        LOG_DBG("Buffer magic: 0x%08X (expected: 0x%08X)", magic, MSG_HEADER_MAGIC);
                    }
                    
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
        host_ready = false;
        transmission_complete = false;
        receive_buffer_pos = 0;
        LOG_INF("USB Reset");
        break;
    case USB_DC_CONFIGURED:
        if (!configured) {
            atomic_clear_bit(hid_ep_in_busy, HID_EP_BUSY_FLAG);
            configured = true;
            receive_buffer_pos = 0;
            LOG_INF("USB Configured - Waiting for READY signal");
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
           flash_data.keypair_group_public_key, 33);
    
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
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    
    if (!fill_random(binding_seed, sizeof(binding_seed)) ||
        !fill_random(hiding_seed, sizeof(hiding_seed))) {
        LOG_ERR("Failed to generate randomness");
        return -1;
    }
    
    LOG_INF("Generating nonce commitment for participant %u", keypair.public_keys.index);
    
    secp256k1_frost_nonce *nonce = secp256k1_frost_nonce_create(
        secp256k1_ctx, &keypair, binding_seed, hiding_seed);
    if (!nonce) {
        LOG_ERR("Failed to create nonce");
        return -1;
    }
    
    serialized_nonce_commitment_t serialized = {
        .participant_index = keypair.public_keys.index
    };
    memcpy(serialized.hiding, nonce->commitments.hiding, 32);
    memcpy(serialized.binding, nonce->commitments.binding, 32);
    
    LOG_INF("Nonce commitment generated successfully");
    
    int ret = send_message(MSG_TYPE_NONCE_COMMITMENT, 
                          keypair.public_keys.index,
                          &serialized, sizeof(serialized));
    
    secp256k1_frost_nonce_destroy(nonce);
    return ret;
}

// Main transmission sequence
static void perform_transmission(void) {
    if (transmission_complete) {
        return;
    }
    if (!flash_data_valid || !configured || !host_ready) {
        LOG_ERR("Not ready for transmission");
        return;
    }
    
    LOG_INF("=== Starting FROST Transmission ===");
    
    k_msleep(100); // Small delay
    
    int ret = send_nonce_commitment();
    if (ret == 0) {
        LOG_INF("Nonce commitment sent successfully");
        
        k_msleep(50);
        
        ret = send_message(MSG_TYPE_END_TRANSMISSION, 
                          keypair.public_keys.index, NULL, 0);
        if (ret == 0) {
            LOG_INF("End transmission sent successfully");
            transmission_complete = true;
        }
    }
    
    LOG_INF("=== Transmission Complete ===");
    host_ready = false; // Reset for next cycle
}

// Work handler
static void send_work_handler(struct k_work *work) {
    perform_transmission();
}

int main(void) {
    int ret;
    LOG_INF("=== FROST HID Nonce Sender Starting ===");
    
    // Create secp256k1 context
    secp256k1_ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (secp256k1_ctx == NULL) {
        LOG_ERR("Failed to create secp256k1 context");
        return -1;
    }
    
    // Initialize work queue
    k_work_init(&send_work, send_work_handler);
    
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
    
    LOG_INF("=== FROST HID Sender Ready - Waiting for READY signal ===");
    
    // Main loop
    while (1) {
        k_msleep(5000);
        LOG_INF("Status: USB=%s, Host Ready=%s, Flash=%s", 
                configured ? "OK" : "NO",
                host_ready ? "YES" : "NO", 
                flash_data_valid ? "OK" : "NO");
    }
    
    return 0;
}