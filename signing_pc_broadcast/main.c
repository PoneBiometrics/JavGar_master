#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")

#define N 3
#define T 2
#define MAX_PARTICIPANTS 10
#define MAX_DEVICES 50

#define VENDOR_ID 0x2FE3   
#define PRODUCT_ID 0x100   

// Device discovery timeout
#define PING_RESPONSE_TIMEOUT_MS 3000
#define POST_DISCOVERY_DELAY_MS 2000       
#define COMMITMENT_COLLECTION_TIMEOUT_MS 15000
#define SIGNATURE_COLLECTION_TIMEOUT_MS 45000

// USB HID specific timeouts and retry counts - FIXED VALUES
#define HID_SEND_RETRY_COUNT 3
#define HID_RECEIVE_RETRY_COUNT 2
#define HID_USB_RECOVERY_DELAY_MS 200
#define HID_CHUNK_DELAY_MS 50
#define HID_DEVICE_STABILIZATION_MS 100

// Device-specific delays for offpad board
#define OFFPAD_PRE_SEND_DELAY_MS 200
#define OFFPAD_POST_SEND_DELAY_MS 300
#define OFFPAD_PRE_RECEIVE_DELAY_MS 500

typedef enum {
    COMM_TYPE_UART = 1,
    COMM_TYPE_USB_HID = 2,
    COMM_TYPE_LOCAL_COMPUTER = 3
} communication_type_t;

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
} local_frost_storage_t;

typedef struct {
    communication_type_t type;
    bool active;
    bool responded_phase1;
    bool responded_phase2;
    uint32_t participant_id;
    char device_identifier[256];
    
    // FIXED: Add device-specific synchronization
    CRITICAL_SECTION device_lock;
    bool lock_initialized;
    
    union {
        HANDLE uart_handle;
        struct {
            HANDLE hid_handle;
            PHIDP_PREPARSED_DATA preparsed_data;
            HIDP_CAPS capabilities;
            USHORT output_report_length;
            USHORT input_report_length;
        };
        struct {
            char participant_file_path[MAX_PATH];
            char nonce_storage_path[MAX_PATH];
            secp256k1_frost_keypair keypair;
            local_frost_storage_t persistent_storage; 
            uint32_t session_id;
            bool nonce_generated;
            bool nonce_used;
        };
    };
} comm_handle_t;

#define MSG_HEADER_MAGIC 0x46524F53
#define MSG_VERSION 0x01

typedef enum {
    MSG_TYPE_NONCE_COMMITMENT = 0x04,  
    MSG_TYPE_READY = 0x06,            
    MSG_TYPE_END_TRANSMISSION = 0xFF,
    MSG_TYPE_SIGN = 0x07,
    MSG_TYPE_SIGNATURE_SHARE = 0x08,
    MSG_TYPE_PING = 0x09
} message_type_t;

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;        
    uint8_t version;       
    uint8_t msg_type;      
    uint16_t payload_len;  
    uint32_t participant;  
} message_header_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t index;
    uint8_t hiding[64];
    uint8_t binding[64];
} serialized_nonce_commitment_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t index;
    uint8_t response[32];
} serialized_signature_share_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t index;
    uint32_t max_participants;
    uint8_t secret[32];
    uint8_t public_key[64];
    uint8_t group_public_key[64];
} serialized_keypair_t;
#pragma pack(pop)

typedef struct {
    uint32_t participant_id;
    bool has_commitment;
    bool has_signature_share;
    serialized_nonce_commitment_t commitment;
    serialized_keypair_t keypair;
    serialized_signature_share_t signature_share;
} participant_data_t;

typedef struct {
    uint32_t receiver_index;
    uint8_t secret_value[32];
    uint32_t pubkey_index;
    uint32_t max_participants;
    uint8_t public_key[64];
    uint8_t group_public_key[64];
} parsed_participant_data_t;

// FIXED: Thread-specific data structure with better synchronization
typedef struct {
    int device_index;
    comm_handle_t* device;
    uint8_t msg_type;
    void* payload;
    uint16_t payload_len;
    
    // Results
    BOOL send_success;
    BOOL receive_success;
    uint8_t receive_buffer[2048];  // FIXED: Larger buffer
    size_t bytes_received;
    DWORD thread_id;
    HANDLE thread_handle;
    
    // FIXED: Thread synchronization
    HANDLE ready_event;
    HANDLE complete_event;
    volatile bool should_terminate;
} device_thread_data_t;

// Global variables for device management
static comm_handle_t discovered_devices[MAX_DEVICES];
static int num_discovered_devices = 0;
static CRITICAL_SECTION device_lock;

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 8; i++) {
        printf("%02x", data[i]);
    }
    if (len > 8) printf("...");
    printf("\n");
}

void print_full_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s:\n", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && (i + 1) < len) {
            printf("\n");
        }
    }
    printf("\n");
}

static int hex_to_bytes(const char* hex_str, uint8_t* bytes, size_t max_bytes) {
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0 || hex_len / 2 > max_bytes) {
        return -1;
    }
    
    for (size_t i = 0; i < hex_len; i += 2) {
        char hex_byte[3] = {hex_str[i], hex_str[i+1], '\0'};
        bytes[i/2] = (uint8_t)strtol(hex_byte, NULL, 16);
    }
    
    return (int)(hex_len / 2);
}

static bool fill_random_simple(unsigned char* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (unsigned char)(rand() & 0xFF);
    }
    return true;
}

HANDLE setup_uart_port(const char *port_name) {
    HANDLE hSerial = CreateFile(port_name,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSerial == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }

    DCB dcbSerialParams = {0};
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
    if (!GetCommState(hSerial, &dcbSerialParams)) {
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }
    dcbSerialParams.BaudRate = CBR_115200;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;
    if (!SetCommState(hSerial, &dcbSerialParams)) {
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }

    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 50;
    timeouts.ReadTotalTimeoutConstant = 1000;
    timeouts.ReadTotalTimeoutMultiplier = 10;
    timeouts.WriteTotalTimeoutConstant = 1000;
    timeouts.WriteTotalTimeoutMultiplier = 10;
    if (!SetCommTimeouts(hSerial, &timeouts)) {
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }
    return hSerial;
}

// FIXED: Improved HID send with device-specific handling
BOOL send_hid_data_thread_safe(comm_handle_t* comm, const void* data, size_t len) {
    if (!comm->lock_initialized) {
        return FALSE;
    }
    
    EnterCriticalSection(&comm->device_lock);
    
    const uint8_t* data_ptr = (const uint8_t*)data;
    size_t bytes_sent = 0;
    int retry_count = 0;
    BOOL overall_success = FALSE;
    
    printf("[Thread %lu] HID Send: %zu bytes to participant %u\n", 
           GetCurrentThreadId(), len, comm->participant_id);
    
    // FIXED: Offpad-specific pre-send stabilization
    Sleep(OFFPAD_PRE_SEND_DELAY_MS);
    
    while (bytes_sent < len && retry_count < HID_SEND_RETRY_COUNT) {
        uint8_t* report = (uint8_t*)calloc(1, comm->output_report_length);
        if (!report) break;
        
        report[0] = 0x02;
        size_t available_space = comm->output_report_length - 2;
        size_t remaining = len - bytes_sent;
        size_t chunk_size = (available_space < remaining) ? available_space : remaining;
        
        report[1] = (uint8_t)chunk_size;
        memcpy(report + 2, data_ptr + bytes_sent, chunk_size);
        
        // FIXED: Try both HidD_SetOutputReport and WriteFile
        BOOL chunk_success = FALSE;
        
        if (HidD_SetOutputReport(comm->hid_handle, report, comm->output_report_length)) {
            chunk_success = TRUE;
        } else {
            // Fallback to WriteFile with overlap
            DWORD bytes_written;
            OVERLAPPED overlapped = {0};
            overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
            
            if (overlapped.hEvent) {
                if (WriteFile(comm->hid_handle, report, comm->output_report_length, 
                             &bytes_written, &overlapped)) {
                    chunk_success = TRUE;
                } else if (GetLastError() == ERROR_IO_PENDING) {
                    if (WaitForSingleObject(overlapped.hEvent, 3000) == WAIT_OBJECT_0) {
                        if (GetOverlappedResult(comm->hid_handle, &overlapped, &bytes_written, FALSE)) {
                            chunk_success = TRUE;
                        }
                    }
                }
                CloseHandle(overlapped.hEvent);
            }
        }
        
        free(report);
        
        if (chunk_success) {
            bytes_sent += chunk_size;
            Sleep(HID_CHUNK_DELAY_MS);  // Inter-chunk delay
            
            if (bytes_sent >= len) {
                overall_success = TRUE;
                break;
            }
        } else {
            retry_count++;
            if (retry_count < HID_SEND_RETRY_COUNT) {
                Sleep(HID_USB_RECOVERY_DELAY_MS * retry_count);
                bytes_sent = 0;  // Full retry
            }
        }
    }
    
    // FIXED: Offpad-specific post-send delay
    Sleep(OFFPAD_POST_SEND_DELAY_MS);
    
    LeaveCriticalSection(&comm->device_lock);
    
    printf("[Thread %lu] HID Send %s: %zu/%zu bytes\n", 
           GetCurrentThreadId(), overall_success ? "SUCCESS" : "FAILED", 
           bytes_sent, len);
    
    return overall_success;
}

// FIXED: Improved HID receive with better error handling
BOOL receive_hid_data_thread_safe(comm_handle_t* comm, void* buffer, size_t max_len, 
                                  size_t* bytes_read, DWORD timeout_ms) {
    if (!comm->lock_initialized) {
        return FALSE;
    }
    
    EnterCriticalSection(&comm->device_lock);
    
    uint8_t* recv_buffer = (uint8_t*)buffer;
    *bytes_read = 0;
    DWORD start_time = GetTickCount();
    int consecutive_failures = 0;
    
    printf("[Thread %lu] HID Receive: max %zu bytes, timeout %lums\n", 
           GetCurrentThreadId(), max_len, timeout_ms);
    
    // FIXED: Offpad-specific pre-receive delay
    Sleep(OFFPAD_PRE_RECEIVE_DELAY_MS);
    
    while (*bytes_read < max_len && 
           (GetTickCount() - start_time) < timeout_ms && 
           consecutive_failures < HID_RECEIVE_RETRY_COUNT) {
        
        uint8_t* report = (uint8_t*)calloc(1, comm->input_report_length);
        if (!report) break;
        
        DWORD bytes_read_hid = 0;
        BOOL read_success = FALSE;
        
        // FIXED: Use overlapped I/O for better timeout control
        OVERLAPPED overlapped = {0};
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        
        if (overlapped.hEvent) {
            if (ReadFile(comm->hid_handle, report, comm->input_report_length, 
                        &bytes_read_hid, &overlapped)) {
                read_success = TRUE;
            } else if (GetLastError() == ERROR_IO_PENDING) {
                DWORD wait_result = WaitForSingleObject(overlapped.hEvent, 1000);
                if (wait_result == WAIT_OBJECT_0) {
                    if (GetOverlappedResult(comm->hid_handle, &overlapped, &bytes_read_hid, FALSE)) {
                        read_success = TRUE;
                    }
                }
            }
            CloseHandle(overlapped.hEvent);
        }
        
        if (read_success && bytes_read_hid > 0) {
            uint8_t report_id = report[0];
            
            if (report_id == 0x01 && bytes_read_hid >= 3) {
                uint8_t chunk_len = report[1];
                if (chunk_len > 0 && chunk_len <= (bytes_read_hid - 2)) {
                    size_t copy_len = (*bytes_read + chunk_len <= max_len) ? 
                                    chunk_len : (max_len - *bytes_read);
                    memcpy(recv_buffer + *bytes_read, report + 2, copy_len);
                    *bytes_read += copy_len;
                    
                    consecutive_failures = 0;  // Reset failure count
                    
                    // Check for complete message
                    if (*bytes_read >= sizeof(message_header_t)) {
                        message_header_t* header = (message_header_t*)recv_buffer;
                        if (header->magic == MSG_HEADER_MAGIC) {
                            size_t expected_total = sizeof(message_header_t) + header->payload_len;
                            if (*bytes_read >= expected_total) {
                                *bytes_read = expected_total;
                                free(report);
                                LeaveCriticalSection(&comm->device_lock);
                                printf("[Thread %lu] HID Receive SUCCESS: %zu bytes\n", 
                                       GetCurrentThreadId(), *bytes_read);
                                return TRUE;
                            }
                        }
                    }
                }
            }
        } else {
            consecutive_failures++;
            Sleep(100);
        }
        
        free(report);
    }
    
    LeaveCriticalSection(&comm->device_lock);
    
    printf("[Thread %lu] HID Receive %s: %zu bytes\n", 
           GetCurrentThreadId(), (*bytes_read > 0) ? "PARTIAL" : "FAILED", 
           *bytes_read);
    
    return (*bytes_read > 0);
}

BOOL send_data(comm_handle_t* comm, const void* data, size_t len) {
    switch (comm->type) {
        case COMM_TYPE_UART: {
            DWORD bytes_written;
            return WriteFile(comm->uart_handle, data, (DWORD)len, &bytes_written, NULL) 
                   && bytes_written == len;
        }
        case COMM_TYPE_USB_HID: {
            return send_hid_data_thread_safe(comm, data, len);
        }
        case COMM_TYPE_LOCAL_COMPUTER:
            return TRUE;
        default:
            return FALSE;
    }
}

BOOL receive_data_with_timeout(comm_handle_t* comm, void* buffer, size_t max_len, size_t* bytes_read, DWORD timeout_ms) {
    *bytes_read = 0;
    DWORD start_time = GetTickCount();
    
    switch (comm->type) {
        case COMM_TYPE_UART: {
            uint8_t* buf = (uint8_t*)buffer;
            while (*bytes_read < max_len && (GetTickCount() - start_time) < timeout_ms) {
                DWORD bytes_read_now;
                if (ReadFile(comm->uart_handle, buf + *bytes_read, 1, &bytes_read_now, NULL) && bytes_read_now > 0) {
                    (*bytes_read)++;
                    
                    if (*bytes_read >= sizeof(message_header_t)) {
                        message_header_t* header = (message_header_t*)buffer;
                        if (header->magic == MSG_HEADER_MAGIC) {
                            size_t expected_total = sizeof(message_header_t) + header->payload_len;
                            if (*bytes_read >= expected_total) {
                                return TRUE;
                            }
                        }
                    }
                } else {
                    Sleep(10);
                }
            }
            return *bytes_read > 0;
        }
        case COMM_TYPE_USB_HID: {
            return receive_hid_data_thread_safe(comm, buffer, max_len, bytes_read, timeout_ms);
        }
        case COMM_TYPE_LOCAL_COMPUTER:
            return TRUE;
        default:
            return FALSE;
    }
}

BOOL send_message(comm_handle_t* comm, uint8_t msg_type, uint32_t participant, 
                  const void* payload, uint16_t payload_len) {
    if (comm->type == COMM_TYPE_LOCAL_COMPUTER) {
        return TRUE;
    }
    
    message_header_t header;
    header.magic = MSG_HEADER_MAGIC;
    header.version = MSG_VERSION;
    header.msg_type = msg_type;
    header.payload_len = payload_len;
    header.participant = participant;
    
    size_t total_size = sizeof(header) + payload_len;
    uint8_t* combined_buffer = (uint8_t*)malloc(total_size);
    if (!combined_buffer) return FALSE;
    
    memcpy(combined_buffer, &header, sizeof(header));
    if (payload_len > 0 && payload) {
        memcpy(combined_buffer + sizeof(header), payload, payload_len);
    }
    
    BOOL result = send_data(comm, combined_buffer, total_size);
    free(combined_buffer);
    
    return result;
}

// FIXED: Improved send thread with proper synchronization
DWORD WINAPI device_send_thread(LPVOID param) {
    device_thread_data_t* data = (device_thread_data_t*)param;
    
    printf("[Thread %lu] Send thread started for device %s\n", 
           GetCurrentThreadId(), data->device->device_identifier);
    
    // Wait for ready signal
    if (WaitForSingleObject(data->ready_event, 5000) != WAIT_OBJECT_0) {
        printf("[Thread %lu] Send thread timeout waiting for ready signal\n", GetCurrentThreadId());
        data->send_success = FALSE;
        SetEvent(data->complete_event);
        return 1;
    }
    
    if (data->should_terminate) {
        SetEvent(data->complete_event);
        return 0;
    }
    
    // FIXED: Device-specific stabilization delay
    Sleep(HID_DEVICE_STABILIZATION_MS);
    
    data->send_success = send_message(data->device, data->msg_type, 0, data->payload, data->payload_len);
    
    printf("[Thread %lu] Send %s to device %s\n", 
           GetCurrentThreadId(), 
           data->send_success ? "SUCCESS" : "FAILED",
           data->device->device_identifier);
    
    SetEvent(data->complete_event);
    return 0;
}

// FIXED: Improved receive thread with better error handling
DWORD WINAPI device_receive_thread(LPVOID param) {
    device_thread_data_t* data = (device_thread_data_t*)param;
    
    printf("[Thread %lu] Receive thread started for device %s\n", 
           GetCurrentThreadId(), data->device->device_identifier);
    
    // Wait for ready signal
    if (WaitForSingleObject(data->ready_event, 5000) != WAIT_OBJECT_0) {
        printf("[Thread %lu] Receive thread timeout waiting for ready signal\n", GetCurrentThreadId());
        data->receive_success = FALSE;
        SetEvent(data->complete_event);
        return 1;
    }
    
    if (data->should_terminate) {
        SetEvent(data->complete_event);
        return 0;
    }
    
    // FIXED: Longer timeout for HID devices, especially offpad
    DWORD timeout = (data->device->type == COMM_TYPE_USB_HID) ? 35000 : 15000;
    
    // FIXED: Additional stabilization for HID devices
    if (data->device->type == COMM_TYPE_USB_HID) {
        Sleep(HID_DEVICE_STABILIZATION_MS * 2);
    }
    
    data->receive_success = receive_data_with_timeout(
        data->device, 
        data->receive_buffer, 
        sizeof(data->receive_buffer), 
        &data->bytes_received, 
        timeout
    );
    
    printf("[Thread %lu] Receive %s from device %s (%zu bytes)\n", 
           GetCurrentThreadId(), 
           data->receive_success ? "SUCCESS" : "FAILED",
           data->device->device_identifier,
           data->bytes_received);
    
    SetEvent(data->complete_event);
    return 0;
}

// FIXED: Improved broadcast with staggered start
int broadcast_message_simultaneously(uint8_t msg_type, const void* payload, uint16_t payload_len) {
    printf("\n=== IMPROVED SIMULTANEOUS BROADCAST ===\n");
    printf("Broadcasting message type 0x%02X with staggered thread start\n", msg_type);
    
    device_thread_data_t thread_data[MAX_DEVICES];
    int active_threads = 0;
    
    EnterCriticalSection(&device_lock);
    
    // Create threads for active devices
    for (int i = 0; i < num_discovered_devices; i++) {
        if (discovered_devices[i].active && discovered_devices[i].type != COMM_TYPE_LOCAL_COMPUTER) {
            thread_data[active_threads].device_index = i;
            thread_data[active_threads].device = &discovered_devices[i];
            thread_data[active_threads].msg_type = msg_type;
            thread_data[active_threads].payload = (void*)payload;
            thread_data[active_threads].payload_len = payload_len;
            thread_data[active_threads].send_success = FALSE;
            thread_data[active_threads].should_terminate = FALSE;
            
            // FIXED: Create synchronization events
            thread_data[active_threads].ready_event = CreateEvent(NULL, FALSE, FALSE, NULL);
            thread_data[active_threads].complete_event = CreateEvent(NULL, FALSE, FALSE, NULL);
            
            thread_data[active_threads].thread_handle = CreateThread(
                NULL, 0, device_send_thread, &thread_data[active_threads], 0, 
                &thread_data[active_threads].thread_id);
            
            if (thread_data[active_threads].thread_handle) {
                active_threads++;
            } else {
                CloseHandle(thread_data[active_threads].ready_event);
                CloseHandle(thread_data[active_threads].complete_event);
            }
        }
    }
    
    LeaveCriticalSection(&device_lock);
    
    printf("Created %d send threads\n", active_threads);
    
    // FIXED: Start threads with staggered timing
    for (int i = 0; i < active_threads; i++) {
        SetEvent(thread_data[i].ready_event);
        Sleep(50);  // Stagger thread starts
    }
    
    // Wait for all threads
    HANDLE* complete_events = (HANDLE*)malloc(active_threads * sizeof(HANDLE));
    for (int i = 0; i < active_threads; i++) {
        complete_events[i] = thread_data[i].complete_event;
    }
    
    DWORD wait_result = WaitForMultipleObjects(active_threads, complete_events, TRUE, 30000);
    
    int successful_sends = 0;
    for (int i = 0; i < active_threads; i++) {
        if (thread_data[i].send_success) {
            successful_sends++;
        }
        
        CloseHandle(thread_data[i].thread_handle);
        CloseHandle(thread_data[i].ready_event);
        CloseHandle(thread_data[i].complete_event);
    }
    
    free(complete_events);
    
    printf("Broadcast complete: %d/%d devices successful\n", successful_sends, active_threads);
    return successful_sends;
}

// FIXED: Improved response collection with staggered start
int collect_responses_simultaneously(participant_data_t* participants, uint8_t expected_msg_type, 
                                    int target_count, DWORD timeout_ms) {
    printf("\n=== IMPROVED SIMULTANEOUS COLLECTION ===\n");
    printf("Collecting %d responses of type 0x%02X with %lums timeout\n", 
           target_count, expected_msg_type, timeout_ms);
    
    device_thread_data_t thread_data[MAX_DEVICES];
    int active_threads = 0;
    int collected_count = 0;
    
    EnterCriticalSection(&device_lock);
    
    // Create receive threads
    for (int i = 0; i < num_discovered_devices; i++) {
        if (discovered_devices[i].active && discovered_devices[i].type != COMM_TYPE_LOCAL_COMPUTER) {
            thread_data[active_threads].device_index = i;
            thread_data[active_threads].device = &discovered_devices[i];
            thread_data[active_threads].msg_type = expected_msg_type;
            thread_data[active_threads].receive_success = FALSE;
            thread_data[active_threads].bytes_received = 0;
            thread_data[active_threads].should_terminate = FALSE;
            
            thread_data[active_threads].ready_event = CreateEvent(NULL, FALSE, FALSE, NULL);
            thread_data[active_threads].complete_event = CreateEvent(NULL, FALSE, FALSE, NULL);
            
            thread_data[active_threads].thread_handle = CreateThread(
                NULL, 0, device_receive_thread, &thread_data[active_threads], 0, 
                &thread_data[active_threads].thread_id);
            
            if (thread_data[active_threads].thread_handle) {
                active_threads++;
            } else {
                CloseHandle(thread_data[active_threads].ready_event);
                CloseHandle(thread_data[active_threads].complete_event);
            }
        }
    }
    
    LeaveCriticalSection(&device_lock);
    
    printf("Created %d receive threads\n", active_threads);
    
    // FIXED: Start threads with staggered timing
    for (int i = 0; i < active_threads; i++) {
        SetEvent(thread_data[i].ready_event);
        Sleep(100);  // Longer stagger for receive threads
    }
    
    // Wait for completion
    HANDLE* complete_events = (HANDLE*)malloc(active_threads * sizeof(HANDLE));
    for (int i = 0; i < active_threads; i++) {
        complete_events[i] = thread_data[i].complete_event;
    }
    
    DWORD wait_result = WaitForMultipleObjects(active_threads, complete_events, TRUE, timeout_ms);
    
    // Process results
    for (int i = 0; i < active_threads; i++) {
        if (thread_data[i].receive_success && thread_data[i].bytes_received >= sizeof(message_header_t)) {
            message_header_t* header = (message_header_t*)thread_data[i].receive_buffer;
            
            if (header->magic == MSG_HEADER_MAGIC && header->msg_type == expected_msg_type) {
                uint32_t participant_id = header->participant;
                
                // Find participant slot
                int slot = -1;
                for (int j = 0; j < MAX_PARTICIPANTS; j++) {
                    if (participants[j].participant_id == participant_id) {
                        slot = j;
                        break;
                    } else if (participants[j].participant_id == 0) {
                        participants[j].participant_id = participant_id;
                        slot = j;
                        break;
                    }
                }
                
                if (slot >= 0) {
                    uint8_t* payload_data = thread_data[i].receive_buffer + sizeof(message_header_t);
                    
                    if (expected_msg_type == MSG_TYPE_NONCE_COMMITMENT) {
                        if (!participants[slot].has_commitment) {
                            memcpy(&participants[slot].commitment, payload_data, sizeof(serialized_nonce_commitment_t));
                            memcpy(&participants[slot].keypair, 
                                   payload_data + sizeof(serialized_nonce_commitment_t), 
                                   sizeof(serialized_keypair_t));
                            participants[slot].has_commitment = true;
                            thread_data[i].device->responded_phase1 = true;
                            collected_count++;
                        }
                    } else if (expected_msg_type == MSG_TYPE_SIGNATURE_SHARE) {
                        if (!participants[slot].has_signature_share) {
                            memcpy(&participants[slot].signature_share, payload_data, sizeof(serialized_signature_share_t));
                            participants[slot].has_signature_share = true;
                            thread_data[i].device->responded_phase2 = true;
                            collected_count++;
                        }
                    }
                }
            }
        }
        
        CloseHandle(thread_data[i].thread_handle);
        CloseHandle(thread_data[i].ready_event);
        CloseHandle(thread_data[i].complete_event);
    }
    
    free(complete_events);
    
    printf("Collection complete: %d/%d responses collected\n", collected_count, target_count);
    return collected_count;
}

// FIXED: Initialize device locks during discovery
static void initialize_device_lock(comm_handle_t* device) {
    if (!device->lock_initialized) {
        InitializeCriticalSection(&device->device_lock);
        device->lock_initialized = true;
    }
}

static void cleanup_device_lock(comm_handle_t* device) {
    if (device->lock_initialized) {
        DeleteCriticalSection(&device->device_lock);
        device->lock_initialized = false;
    }
}

// Discovery functions (keeping original implementation with lock initialization)
static int read_participant_file(const char* file_path, parsed_participant_data_t* data) {
    printf("Reading participant file: %s\n", file_path);
    
    FILE* fp = fopen(file_path, "r");
    if (!fp) {
        printf("Failed to open participant file: %s\n", file_path);
        return -1;
    }
    
    char line[512];
    bool in_secret_section = false;
    bool in_pubkey_section = false;
    
    memset(data, 0, sizeof(parsed_participant_data_t));
    
    while (fgets(line, sizeof(line), fp)) {
        char* newline = strchr(line, '\n');
        if (newline) *newline = '\0';
        
        if (strstr(line, "[SECRET_SHARE]")) {
            in_secret_section = true;
            in_pubkey_section = false;
        } else if (strstr(line, "[PUBLIC_KEY]")) {
            in_secret_section = false;
            in_pubkey_section = true;
        } else if (strstr(line, "[COMMITMENTS]")) {
            in_secret_section = false;
            in_pubkey_section = false;
        } else if (in_secret_section) {
            if (strncmp(line, "receiver_index=", 15) == 0) {
                data->receiver_index = (uint32_t)atoi(line + 15);
            } else if (strncmp(line, "value=", 6) == 0) {
                hex_to_bytes(line + 6, data->secret_value, 32);
            }
        } else if (in_pubkey_section) {
            if (strncmp(line, "index=", 6) == 0) {
                data->pubkey_index = (uint32_t)atoi(line + 6);
            } else if (strncmp(line, "max_participants=", 17) == 0) {
                data->max_participants = (uint32_t)atoi(line + 17);
            } else if (strncmp(line, "public_key=", 11) == 0) {
                hex_to_bytes(line + 11, data->public_key, 64);
            } else if (strncmp(line, "group_public_key=", 17) == 0) {
                hex_to_bytes(line + 17, data->group_public_key, 64);
            }
        }
    }
    
    fclose(fp);
    return 0;
}

int discover_local_files(void) {
    printf("\n=== DISCOVERING LOCAL FILE PARTICIPANTS ===\n");
    
    WIN32_FIND_DATA find_file_data;
    HANDLE h_find = FindFirstFile("frost_keys\\participant_*.frost", &find_file_data);
    
    if (h_find == INVALID_HANDLE_VALUE) {
        printf("No frost_keys directory or no participant files found\n");
        return 0;
    }
    
    int discovered_count = 0;
    
    do {
        if (num_discovered_devices >= MAX_DEVICES) {
            printf("Maximum device limit reached\n");
            break;
        }
        
        char full_path[MAX_PATH];
        sprintf(full_path, "frost_keys\\%s", find_file_data.cFileName);
        
        printf("Found participant file: %s\n", full_path);
        
        parsed_participant_data_t parsed_data;
        if (read_participant_file(full_path, &parsed_data) == 0) {
            comm_handle_t* device = &discovered_devices[num_discovered_devices];
            
            memset(device, 0, sizeof(comm_handle_t));
            device->type = COMM_TYPE_LOCAL_COMPUTER;
            device->active = true;
            device->participant_id = parsed_data.pubkey_index;
            strcpy(device->device_identifier, full_path);
            strcpy(device->participant_file_path, full_path);
            
            sprintf(device->nonce_storage_path, "frost_keys\\participant_%u_nonce.bin", 
                    parsed_data.pubkey_index);
            
            device->keypair.public_keys.index = parsed_data.pubkey_index;
            device->keypair.public_keys.max_participants = parsed_data.max_participants;
            memcpy(device->keypair.secret, parsed_data.secret_value, 32);
            memcpy(device->keypair.public_keys.public_key, parsed_data.public_key, 64);
            memcpy(device->keypair.public_keys.group_public_key, parsed_data.group_public_key, 64);
            
            FILE* storage_fp = fopen(device->nonce_storage_path, "rb");
            if (storage_fp) {
                fread(&device->persistent_storage, sizeof(local_frost_storage_t), 1, storage_fp);
                fclose(storage_fp);
            } else {
                memset(&device->persistent_storage, 0, sizeof(local_frost_storage_t));
                device->persistent_storage.keypair_index = device->keypair.public_keys.index;
                device->persistent_storage.keypair_max_participants = device->keypair.public_keys.max_participants;
                memcpy(device->persistent_storage.keypair_secret, device->keypair.secret, 32);
                memcpy(device->persistent_storage.keypair_public_key, device->keypair.public_keys.public_key, 64);
                memcpy(device->persistent_storage.keypair_group_public_key, device->keypair.public_keys.group_public_key, 64);
            }
            
            printf("  Successfully set up local participant %u\n", device->participant_id);
            num_discovered_devices++;
            discovered_count++;
        }
        
    } while (FindNextFile(h_find, &find_file_data) != 0);
    
    FindClose(h_find);
    
    printf("Discovered %d local file participants\n", discovered_count);
    return discovered_count;
}

int test_uart_device_with_ping(const char* port_name) {
    HANDLE uart_handle = setup_uart_port(port_name);
    if (uart_handle == INVALID_HANDLE_VALUE) {
        return -1;
    }
    
    message_header_t ping_header = {
        .magic = MSG_HEADER_MAGIC,
        .version = MSG_VERSION,
        .msg_type = MSG_TYPE_PING,
        .payload_len = 0,
        .participant = 0
    };
    
    DWORD bytes_written;
    if (WriteFile(uart_handle, &ping_header, sizeof(ping_header), &bytes_written, NULL) && 
        bytes_written == sizeof(ping_header)) {
        
        Sleep(100);
        
        uint8_t buffer[512];
        DWORD bytes_read = 0;
        DWORD start_time = GetTickCount();
        uint8_t* buf_ptr = buffer;
        
        while (bytes_read < sizeof(buffer) && (GetTickCount() - start_time) < PING_RESPONSE_TIMEOUT_MS) {
            DWORD bytes_read_now;
            if (ReadFile(uart_handle, buf_ptr + bytes_read, 1, &bytes_read_now, NULL) && bytes_read_now > 0) {
                bytes_read++;
                
                if (bytes_read >= sizeof(message_header_t)) {
                    message_header_t* resp_header = (message_header_t*)buffer;
                    if (resp_header->magic == MSG_HEADER_MAGIC && 
                        resp_header->msg_type == MSG_TYPE_READY) {
                        
                        uint32_t participant_id = resp_header->participant;
                        CloseHandle(uart_handle);
                        return (int)participant_id;
                    }
                }
            } else {
                Sleep(10);
            }
        }
    }
    
    CloseHandle(uart_handle);
    return -1;
}

int discover_uart_devices(void) {
    printf("\n=== DISCOVERING UART DEVICES WITH PING ===\n");
    
    int discovered_count = 0;
    
    for (int com_port = 1; com_port <= 7; com_port++) {
        if (num_discovered_devices >= MAX_DEVICES) {
            break;
        }
        
        char port_name[20];
        sprintf(port_name, "COM%d", com_port);
        
        printf("Testing %s with PING...", port_name);
        
        int participant_id = test_uart_device_with_ping(port_name);
        if (participant_id > 0) {
            printf(" FOUND participant %d\n", participant_id);
            
            HANDLE uart_handle = setup_uart_port(port_name);
            if (uart_handle != INVALID_HANDLE_VALUE) {
                comm_handle_t* device = &discovered_devices[num_discovered_devices];
                
                memset(device, 0, sizeof(comm_handle_t));
                device->type = COMM_TYPE_UART;
                device->active = true;
                device->participant_id = participant_id;
                device->uart_handle = uart_handle;
                strcpy(device->device_identifier, port_name);
                
                // FIXED: Initialize device lock for UART too
                initialize_device_lock(device);
                
                printf("  Successfully set up UART participant %d on %s\n", participant_id, port_name);
                num_discovered_devices++;
                discovered_count++;
            }
        } else {
            printf(" no FROST device response\n");
        }
        
        Sleep(100);
    }
    
    printf("Discovered %d UART participants with PING protocol\n", discovered_count);
    return discovered_count;
}

int test_hid_device_with_ping(HANDLE hid_handle, HIDP_CAPS* capabilities) {
    message_header_t ping_header = {
        .magic = MSG_HEADER_MAGIC,
        .version = MSG_VERSION,
        .msg_type = MSG_TYPE_PING,
        .payload_len = 0,
        .participant = 0
    };
    
    uint8_t report[64];
    memset(report, 0, sizeof(report));
    report[0] = 0x02;
    report[1] = sizeof(ping_header);
    memcpy(report + 2, &ping_header, sizeof(ping_header));
    
    if (HidD_SetOutputReport(hid_handle, report, capabilities->OutputReportByteLength)) {
        Sleep(200);
        
        uint8_t recv_buffer[512];
        size_t total_received = 0;
        DWORD start_time = GetTickCount();
        
        while (total_received < sizeof(recv_buffer) && (GetTickCount() - start_time) < PING_RESPONSE_TIMEOUT_MS) {
            uint8_t* hid_report = (uint8_t*)calloc(1, capabilities->InputReportByteLength);
            if (!hid_report) break;
            
            DWORD bytes_read;
            if (ReadFile(hid_handle, hid_report, capabilities->InputReportByteLength, &bytes_read, NULL) && 
                bytes_read > 0) {
                
                if (hid_report[0] == 0x01 && bytes_read >= 3) {
                    uint8_t chunk_len = hid_report[1];
                    if (chunk_len > 0 && chunk_len <= (bytes_read - 2)) {
                        size_t copy_len = (total_received + chunk_len <= sizeof(recv_buffer)) ? 
                                        chunk_len : (sizeof(recv_buffer) - total_received);
                        memcpy(recv_buffer + total_received, hid_report + 2, copy_len);
                        total_received += copy_len;
                        
                        if (total_received >= sizeof(message_header_t)) {
                            message_header_t* resp_header = (message_header_t*)recv_buffer;
                            if (resp_header->magic == MSG_HEADER_MAGIC && 
                                resp_header->msg_type == MSG_TYPE_READY) {
                                
                                uint32_t participant_id = resp_header->participant;
                                free(hid_report);
                                return (int)participant_id;
                            }
                        }
                    }
                }
            }
            free(hid_report);
            Sleep(50);
        }
    }
    
    return -1;
}

int discover_hid_devices(void) {
    printf("\n=== DISCOVERING HID DEVICES WITH PING ===\n");
    
    GUID hid_guid;
    HDEVINFO device_info_set;
    SP_DEVICE_INTERFACE_DATA device_interface_data;
    PSP_DEVICE_INTERFACE_DETAIL_DATA device_interface_detail_data;
    DWORD required_size;
    int discovered_count = 0;

    HidD_GetHidGuid(&hid_guid);
    device_info_set = SetupDiGetClassDevs(&hid_guid, NULL, NULL, 
                                         DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (device_info_set == INVALID_HANDLE_VALUE) {
        printf("Failed to get HID device information set\n");
        return 0;
    }

    device_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
    
    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(device_info_set, NULL, &hid_guid, 
                                                  i, &device_interface_data); i++) {
        if (num_discovered_devices >= MAX_DEVICES) {
            break;
        }
        
        SetupDiGetDeviceInterfaceDetail(device_info_set, &device_interface_data, 
                                       NULL, 0, &required_size, NULL);
        device_interface_detail_data = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(required_size);
        if (!device_interface_detail_data) continue;
        device_interface_detail_data->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        if (SetupDiGetDeviceInterfaceDetail(device_info_set, &device_interface_data,
                                           device_interface_detail_data, required_size,
                                           NULL, NULL)) {
            
            HANDLE temp_handle = CreateFile(device_interface_detail_data->DevicePath,
                                          GENERIC_READ | GENERIC_WRITE,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                                          NULL, OPEN_EXISTING, 0, NULL);
            
            if (temp_handle != INVALID_HANDLE_VALUE) {
                HIDD_ATTRIBUTES attributes;
                attributes.Size = sizeof(HIDD_ATTRIBUTES);
                if (HidD_GetAttributes(temp_handle, &attributes)) {
                    if (attributes.VendorID == VENDOR_ID && attributes.ProductID == PRODUCT_ID) {
                        printf("Found matching HID device: VID:0x%04X PID:0x%04X\n", 
                               attributes.VendorID, attributes.ProductID);
                        
                        PHIDP_PREPARSED_DATA preparsed_data;
                        if (HidD_GetPreparsedData(temp_handle, &preparsed_data)) {
                            HIDP_CAPS capabilities;
                            if (HidP_GetCaps(preparsed_data, &capabilities) == HIDP_STATUS_SUCCESS) {
                                
                                printf("Testing HID device with PING...");
                                
                                int participant_id = test_hid_device_with_ping(temp_handle, &capabilities);
                                if (participant_id > 0) {
                                    printf(" FOUND participant %d\n", participant_id);
                                    
                                    comm_handle_t* device = &discovered_devices[num_discovered_devices];
                                    memset(device, 0, sizeof(comm_handle_t));
                                    device->type = COMM_TYPE_USB_HID;
                                    device->active = true;
                                    device->participant_id = participant_id;
                                    device->hid_handle = temp_handle;
                                    device->preparsed_data = preparsed_data;
                                    device->capabilities = capabilities;
                                    device->output_report_length = capabilities.OutputReportByteLength;
                                    device->input_report_length = capabilities.InputReportByteLength;
                                    strcpy(device->device_identifier, device_interface_detail_data->DevicePath);
                                    
                                    // FIXED: Initialize device-specific lock
                                    initialize_device_lock(device);
                                    
                                    printf("  Successfully set up HID participant %u\n", participant_id);
                                    num_discovered_devices++;
                                    discovered_count++;
                                    
                                    temp_handle = INVALID_HANDLE_VALUE; // Don't close this handle
                                    goto hid_device_found;
                                } else {
                                    printf(" no FROST device response\n");
                                    HidD_FreePreparsedData(preparsed_data);
                                }
                            } else {
                                HidD_FreePreparsedData(preparsed_data);
                            }
                        }
                    }
                }
                
                if (temp_handle != INVALID_HANDLE_VALUE) {
                    CloseHandle(temp_handle);
                }
            }
        }
        hid_device_found:
        free(device_interface_detail_data);
    }

    SetupDiDestroyDeviceInfoList(device_info_set);
    
    printf("Discovered %d HID participants with PING protocol\n", discovered_count);
    return discovered_count;
}

// Local computer participant functions (keeping original implementation)
static int generate_and_save_nonce_PHASE1_local(comm_handle_t* comm, secp256k1_context* ctx) {
    if (comm->type != COMM_TYPE_LOCAL_COMPUTER) {
        return -1;
    }
    
    printf("=== PHASE 1: GENERATE AND PERSIST NONCE (LOCAL FILE) ===\n");
    printf("Generating fresh nonce for participant %u\n", comm->keypair.public_keys.index);
    
    comm->session_id = rand();
    
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    
    if (!fill_random_simple(binding_seed, sizeof(binding_seed))) {
        printf("Failed to generate binding_seed\n");
        return -1;
    }
    if (!fill_random_simple(hiding_seed, sizeof(hiding_seed))) {
        printf("Failed to generate hiding_seed\n");
        return -1;
    }
    
    printf("Session ID: %u\n", comm->session_id);
    print_hex("Binding seed", binding_seed, 8);
    print_hex("Hiding seed", hiding_seed, 8);
    
    secp256k1_frost_nonce* temp_nonce = secp256k1_frost_nonce_create(ctx, &comm->keypair, binding_seed, hiding_seed);
    if (!temp_nonce) {
        printf("Failed to create nonce\n");
        return -1;
    }
    
    printf("Fresh nonce generated successfully\n");
    print_hex("Generated hiding commitment", temp_nonce->commitments.hiding, 16);
    print_hex("Generated binding commitment", temp_nonce->commitments.binding, 16);
    
    comm->persistent_storage.nonce_session_id = comm->session_id;
    memcpy(comm->persistent_storage.nonce_hiding_secret, temp_nonce->hiding, 32);
    memcpy(comm->persistent_storage.nonce_binding_secret, temp_nonce->binding, 32);
    memcpy(comm->persistent_storage.nonce_hiding_commitment, temp_nonce->commitments.hiding, 64);
    memcpy(comm->persistent_storage.nonce_binding_commitment, temp_nonce->commitments.binding, 64);
    comm->persistent_storage.nonce_used = 0;
    comm->persistent_storage.nonce_valid = 1;
    
    FILE* fp = fopen(comm->nonce_storage_path, "wb");
    if (fp) {
        fwrite(&comm->persistent_storage, sizeof(local_frost_storage_t), 1, fp);
        fclose(fp);
    }
    
    secp256k1_frost_nonce_destroy(temp_nonce);
    
    comm->nonce_generated = true;
    comm->nonce_used = false;
    
    printf("PHASE 1 NONCE GENERATION AND PERSISTENCE COMPLETE\n");
    return 0;
}

static bool send_nonce_commitment_local_computer_PHASE1(comm_handle_t* comm, 
                                                       serialized_nonce_commitment_t* out_commitment,
                                                       serialized_keypair_t* out_keypair) {
    if (comm->type != COMM_TYPE_LOCAL_COMPUTER || !comm->persistent_storage.nonce_valid) {
        return false;
    }
    
    printf("=== PHASE 1: SENDING PERSISTED NONCE COMMITMENT (LOCAL) ===\n");
    printf("Participant: %u\n", comm->keypair.public_keys.index);
    printf("Session ID: %u\n", comm->persistent_storage.nonce_session_id);
    
    out_commitment->index = comm->keypair.public_keys.index;
    memcpy(out_commitment->hiding, comm->persistent_storage.nonce_hiding_commitment, 64);
    memcpy(out_commitment->binding, comm->persistent_storage.nonce_binding_commitment, 64);
    
    out_keypair->index = comm->keypair.public_keys.index;
    out_keypair->max_participants = comm->keypair.public_keys.max_participants;
    memcpy(out_keypair->secret, comm->keypair.secret, 32);
    memcpy(out_keypair->public_key, comm->keypair.public_keys.public_key, 64);
    memcpy(out_keypair->group_public_key, comm->keypair.public_keys.group_public_key, 64);
    
    print_hex("Sending hiding commitment", out_commitment->hiding, 16);
    print_hex("Sending binding commitment", out_commitment->binding, 16);
    
    printf("PHASE 1 SUCCESS: Persisted nonce commitment and keypair sent\n");
    return true;
}

static secp256k1_frost_nonce* load_original_nonce_from_storage(comm_handle_t* comm, uint32_t expected_session_id) {
    if (comm->type != COMM_TYPE_LOCAL_COMPUTER) {
        return NULL;
    }
    
    if (!comm->persistent_storage.nonce_valid) {
        printf("No valid nonce stored in persistent storage\n");
        return NULL;
    }
    
    if (comm->persistent_storage.nonce_session_id != expected_session_id) {
        printf("Session ID mismatch - stored: %u, expected: %u\n", 
               comm->persistent_storage.nonce_session_id, expected_session_id);
    }
    
    if (comm->persistent_storage.nonce_used) {
        printf("Stored nonce already used - replay protection activated\n");
        return NULL;
    }
    
    printf("=== LOADING ORIGINAL NONCE FROM PERSISTENT STORAGE ===\n");
    
    secp256k1_frost_nonce* restored_nonce = 
        (secp256k1_frost_nonce*)malloc(sizeof(secp256k1_frost_nonce));
    
    if (!restored_nonce) {
        printf("Failed to allocate memory for restored nonce\n");
        return NULL;
    }
    
    memcpy(restored_nonce->hiding, comm->persistent_storage.nonce_hiding_secret, 32);
    memcpy(restored_nonce->binding, comm->persistent_storage.nonce_binding_secret, 32);
    restored_nonce->commitments.index = comm->keypair.public_keys.index;
    memcpy(restored_nonce->commitments.hiding, comm->persistent_storage.nonce_hiding_commitment, 64);
    memcpy(restored_nonce->commitments.binding, comm->persistent_storage.nonce_binding_commitment, 64);
    restored_nonce->used = 0;
    
    printf("Original nonce restored from persistent storage\n");
    printf("Session ID: %u\n", comm->persistent_storage.nonce_session_id);
    print_hex("Hiding secret restored", restored_nonce->hiding, 8);
    print_hex("Binding secret restored", restored_nonce->binding, 8);
    print_hex("Hiding commitment", restored_nonce->commitments.hiding, 16);
    print_hex("Binding commitment", restored_nonce->commitments.binding, 16);
    
    return restored_nonce;
}

static bool verify_commitment_consistency_local(comm_handle_t* comm, 
                                               const serialized_nonce_commitment_t* coordinator_commitment) {
    if (!comm->persistent_storage.nonce_valid) {
        printf("Cannot verify commitment - no stored nonce\n");
        return false;
    }
    
    printf("=== VERIFYING COMMITMENT CONSISTENCY (LOCAL) ===\n");
    
    bool hiding_match = (memcmp(coordinator_commitment->hiding, 
                                comm->persistent_storage.nonce_hiding_commitment, 64) == 0);
    bool binding_match = (memcmp(coordinator_commitment->binding, 
                                 comm->persistent_storage.nonce_binding_commitment, 64) == 0);
    
    printf("Commitment verification:\n");
    printf("  Index match: %s (%u vs %u)\n", 
           (coordinator_commitment->index == comm->keypair.public_keys.index) ? "YES" : "NO",
           coordinator_commitment->index, comm->keypair.public_keys.index);
    printf("  Hiding match: %s\n", hiding_match ? "YES" : "NO");
    printf("  Binding match: %s\n", binding_match ? "YES" : "NO");
    
    if (!hiding_match) {
        printf("Hiding commitment mismatch!\n");
        print_hex("Expected (stored)", comm->persistent_storage.nonce_hiding_commitment, 16);
        print_hex("Received (coordinator)", coordinator_commitment->hiding, 16);
    }
    
    if (!binding_match) {
        printf("Binding commitment mismatch!\n");
        print_hex("Expected (stored)", comm->persistent_storage.nonce_binding_commitment, 16);
        print_hex("Received (coordinator)", coordinator_commitment->binding, 16);
    }
    
    bool all_match = hiding_match && binding_match && 
                     (coordinator_commitment->index == comm->keypair.public_keys.index);
    
    if (all_match) {
        printf("Commitment verification passed - coordinator has correct data\n");
    } else {
        printf("Commitment verification failed - data inconsistency detected\n");
    }
    
    return all_match;
}

static bool process_sign_message_local_computer_PHASE2(comm_handle_t* comm, secp256k1_context* ctx,
                                                      unsigned char* msg_hash,
                                                      serialized_nonce_commitment_t* commitments,
                                                      int num_commitments,
                                                      serialized_signature_share_t* out_signature_share) {
    if (comm->type != COMM_TYPE_LOCAL_COMPUTER) {
        printf("ERROR: Invalid local computer participant state\n");
        return false;
    }
    
    // Verify message hash
    unsigned char expected_msg[12] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    unsigned char expected_hash[32];
    unsigned char tag[14] = {'f', 'r', 'o', 's', 't', '_', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};
    secp256k1_tagged_sha256(ctx, expected_hash, tag, sizeof(tag), expected_msg, sizeof(expected_msg));
    
    if (memcmp(msg_hash, expected_hash, 32) != 0) {
        printf("Message hash verification FAILED!\n");
        return false;
    }
    printf("Message hash verified correctly\n");
    
    // Find commitment in the coordinator's list
    serialized_nonce_commitment_t* our_commitment_from_coordinator = NULL;
    
    for (int i = 0; i < num_commitments; i++) {
        printf("Checking commitment %d: participant %u\n", i, commitments[i].index);
        
        if (commitments[i].index == comm->keypair.public_keys.index) {
            our_commitment_from_coordinator = &commitments[i];
            printf("Found our commitment at position %d\n", i);
            break;
        }
    }
    
    if (!our_commitment_from_coordinator) {
        printf("Our commitment not found in coordinator's list!\n");
        return false;
    }
    
    // Verify commitment consistency
    if (!verify_commitment_consistency_local(comm, our_commitment_from_coordinator)) {
        printf("Commitment consistency verification failed!\n");
        return false;
    }
    
    secp256k1_frost_nonce* original_nonce = 
        load_original_nonce_from_storage(comm, comm->persistent_storage.nonce_session_id);
    
    if (!original_nonce) {
        printf("Failed to load original nonce from persistent storage\n");
        return false;
    }
    
    printf("Using ORIGINAL nonce from persistent storage\n");
    
    // Prepare commitments array for signing
    secp256k1_frost_nonce_commitment *signing_commitments = 
        (secp256k1_frost_nonce_commitment*)malloc(num_commitments * sizeof(secp256k1_frost_nonce_commitment));
    if (!signing_commitments) {
        printf("Failed to allocate memory for signing commitments\n");
        free(original_nonce);
        return false;
    }
    
    for (int i = 0; i < num_commitments; i++) {
        signing_commitments[i].index = commitments[i].index;
        memcpy(signing_commitments[i].hiding, commitments[i].hiding, 64);
        memcpy(signing_commitments[i].binding, commitments[i].binding, 64);
        
        printf("Commitment %d: participant %u\n", i, signing_commitments[i].index);
    }
    
    printf("Computing signature share using ORIGINAL nonce from storage...\n");
    printf("Participant index: %u\n", comm->keypair.public_keys.index);
    printf("Number of signers: %d\n", num_commitments);
    
    secp256k1_frost_signature_share computed_signature_share;
    memset(&computed_signature_share, 0, sizeof(computed_signature_share));
    
    // Compute signature share using original nonce
    int return_val = secp256k1_frost_sign(&computed_signature_share,
                                         msg_hash, num_commitments,
                                         &comm->keypair, original_nonce, signing_commitments);
    
    if (return_val == 1) {
        printf("*** SIGNATURE SHARE COMPUTED SUCCESSFULLY ***\n");
        printf("Used ORIGINAL nonce from persistent storage\n");
        print_hex("SIGNATURE SHARE (32 bytes)", computed_signature_share.response, 32);
        
        // Validate signature share is not all zeros
        bool all_zeros = true;
        for (int i = 0; i < 32; i++) {
            if (computed_signature_share.response[i] != 0) {
                all_zeros = false;
                break;
            }
        }
        
        if (all_zeros) {
            printf("Signature share is all zeros - this indicates an error!\n");
            free(signing_commitments);
            free(original_nonce);
            return false;
        }
        
        printf("Signature share appears valid (not all zeros)\n");
        
        // Mark nonce as used
        comm->persistent_storage.nonce_used = 1;
        FILE* fp = fopen(comm->nonce_storage_path, "wb");
        if (fp) {
            fwrite(&comm->persistent_storage, sizeof(local_frost_storage_t), 1, fp);
            fclose(fp);
        }
        
        out_signature_share->index = comm->keypair.public_keys.index;
        memcpy(out_signature_share->response, computed_signature_share.response, 32);
        
        free(signing_commitments);
        free(original_nonce);
        return true;
        
    } else {
        printf("Failed to compute signature share (return_val=%d)\n", return_val);
        free(signing_commitments);
        free(original_nonce);
        return false;
    }
}

// FIXED: Updated collection functions with simultaneous communication
int collect_commitments_from_devices(participant_data_t* participants, int target_count, DWORD timeout_ms) {
    printf("\n=== COLLECTING COMMITMENTS (FIXED SIMULTANEOUS MODE) ===\n");
    
    int collected_count = 0;
    secp256k1_context* temp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    
    // First, process all local computer participants (unchanged)
    for (int i = 0; i < num_discovered_devices && collected_count < target_count; i++) {
        if (!discovered_devices[i].active || discovered_devices[i].type != COMM_TYPE_LOCAL_COMPUTER) {
            continue;
        }
        
        comm_handle_t* device = &discovered_devices[i];
        
        if (generate_and_save_nonce_PHASE1_local(device, temp_ctx) == 0) {
            serialized_nonce_commitment_t commitment;
            serialized_keypair_t keypair;
            
            if (send_nonce_commitment_local_computer_PHASE1(device, &commitment, &keypair)) {
                // Find or create participant slot
                int slot = -1;
                for (int j = 0; j < MAX_PARTICIPANTS; j++) {
                    if (participants[j].participant_id == 0) {
                        participants[j].participant_id = device->participant_id;
                        slot = j;
                        break;
                    } else if (participants[j].participant_id == device->participant_id) {
                        slot = j;
                        break;
                    }
                }
                
                if (slot >= 0) {
                    participants[slot].commitment = commitment;
                    participants[slot].keypair = keypair;
                    participants[slot].has_commitment = true;
                    device->responded_phase1 = true;
                    
                    printf("Collected commitment from local participant %u\n", device->participant_id);
                    collected_count++;
                }
            }
        }
    }
    
    // Then collect from external devices SIMULTANEOUSLY
    if (collected_count < target_count) {
        printf("Need %d more commitments from external devices\n", target_count - collected_count);
        int external_collected = collect_responses_simultaneously(participants, MSG_TYPE_NONCE_COMMITMENT, 
                                                                target_count - collected_count, timeout_ms);
        collected_count += external_collected;
    }
    
    secp256k1_context_destroy(temp_ctx);
    
    printf("Total commitments collected: %d/%d\n", collected_count, target_count);
    return collected_count;
}

int collect_signature_shares_from_devices(participant_data_t* participants, int target_count, 
                                         serialized_nonce_commitment_t* sorted_commitments,
                                         int commitment_count, unsigned char* msg_hash,
                                         DWORD timeout_ms) {
    printf("\n=== COLLECTING SIGNATURE SHARES (FIXED SIMULTANEOUS MODE) ===\n");
    
    int collected_count = 0;
    secp256k1_context* temp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    
    // First process local computer participants (unchanged)
    for (int i = 0; i < num_discovered_devices && collected_count < target_count; i++) {
        if (!discovered_devices[i].active || 
            discovered_devices[i].type != COMM_TYPE_LOCAL_COMPUTER ||
            !discovered_devices[i].responded_phase1 ||
            discovered_devices[i].responded_phase2) {
            continue;
        }
        
        comm_handle_t* device = &discovered_devices[i];
        uint32_t participant_id = device->participant_id;
        
        // Find participant slot
        int slot = -1;
        for (int j = 0; j < MAX_PARTICIPANTS; j++) {
            if (participants[j].participant_id == participant_id) {
                slot = j;
                break;
            }
        }
        
        if (slot >= 0 && !participants[slot].has_signature_share) {
            printf("Processing local computer participant %u for signature\n", participant_id);
            
            if (process_sign_message_local_computer_PHASE2(device, temp_ctx, msg_hash, 
                                                         sorted_commitments, commitment_count, 
                                                         &participants[slot].signature_share)) {
                participants[slot].has_signature_share = true;
                device->responded_phase2 = true;
                
                printf("Collected signature share from local participant %u\n", participant_id);
                print_hex("Signature share", participants[slot].signature_share.response, 32);
                collected_count++;
            } else {
                printf("Failed to get signature share from local participant %u\n", participant_id);
            }
        }
    }
    
    // Then collect from external devices SIMULTANEOUSLY
    if (collected_count < target_count) {
        printf("Need %d more signature shares from external devices\n", target_count - collected_count);
        int external_collected = collect_responses_simultaneously(participants, MSG_TYPE_SIGNATURE_SHARE,
                                                                target_count - collected_count, timeout_ms);
        collected_count += external_collected;
    }
    
    secp256k1_context_destroy(temp_ctx);
    
    printf("Total signature shares collected: %d/%d\n", collected_count, target_count);
    return collected_count;
}

void close_communication(comm_handle_t* comm) {
    if (comm->type == COMM_TYPE_UART && comm->uart_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(comm->uart_handle);
        comm->uart_handle = INVALID_HANDLE_VALUE;
    } else if (comm->type == COMM_TYPE_USB_HID && comm->hid_handle != INVALID_HANDLE_VALUE) {
        if (comm->preparsed_data) {
            HidD_FreePreparsedData(comm->preparsed_data);
            comm->preparsed_data = NULL;
        }
        CloseHandle(comm->hid_handle);
        comm->hid_handle = INVALID_HANDLE_VALUE;
    }
    
    // FIXED: Clean up device lock
    cleanup_device_lock(comm);
    comm->active = false;
}

void cleanup_all_devices(void) {
    EnterCriticalSection(&device_lock);
    
    for (int i = 0; i < num_discovered_devices; i++) {
        close_communication(&discovered_devices[i]);
    }
    
    num_discovered_devices = 0;
    
    LeaveCriticalSection(&device_lock);
}

void compute_message_hash_verified(unsigned char* msg_hash, const unsigned char* msg, size_t msg_len) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char tag[14] = {'f', 'r', 'o', 's', 't', '_', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};
    int return_val = secp256k1_tagged_sha256(ctx, msg_hash, tag, sizeof(tag), msg, msg_len);
    assert(return_val == 1);
    
    printf("Message hash computation verified:\n");
    printf("   Message: \"");
    for (size_t i = 0; i < msg_len; i++) {
        printf("%c", msg[i]);
    }
    printf("\"\n");
    printf("   Hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", msg_hash[i]);
    }
    printf("\n");
    
    secp256k1_context_destroy(ctx);
}

int aggregate_and_verify_signature_ENHANCED(serialized_signature_share_t* signature_shares,
                                           serialized_keypair_t* participant_keypairs,
                                           serialized_nonce_commitment_t* commitments,
                                           int num_shares,
                                           unsigned char* msg_hash,
                                           unsigned char* final_signature) {
    
    printf("\n=== FROST AGGREGATION ===\n");
    
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("Failed to create secp256k1 context\n");
        return 0;
    }
    
    // Find aggregator (lowest index)
    uint32_t aggregator_index = UINT32_MAX;
    int aggregator_pos = -1;
    
    for (int i = 0; i < num_shares; i++) {
        if (participant_keypairs[i].index < aggregator_index) {
            aggregator_index = participant_keypairs[i].index;
            aggregator_pos = i;
        }
    }
    
    if (aggregator_pos == -1) {
        printf("ERROR: No valid aggregator found\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    
    printf("Selected aggregator: Participant %u (lowest index)\n", aggregator_index);
    
    secp256k1_frost_keypair aggregator_keypair;
    memset(&aggregator_keypair, 0, sizeof(secp256k1_frost_keypair));
    
    aggregator_keypair.public_keys.index = participant_keypairs[aggregator_pos].index;
    aggregator_keypair.public_keys.max_participants = participant_keypairs[aggregator_pos].max_participants;
    memcpy(aggregator_keypair.secret, participant_keypairs[aggregator_pos].secret, 32);
    memcpy(aggregator_keypair.public_keys.public_key, participant_keypairs[aggregator_pos].public_key, 64);
    memcpy(aggregator_keypair.public_keys.group_public_key, participant_keypairs[aggregator_pos].group_public_key, 64);
    
    // Create sorted arrays
    typedef struct {
        uint32_t participant_index;
        int signature_pos;
        int keypair_pos;
        int commitment_pos;
    } participant_mapping_t;
    
    participant_mapping_t mappings[num_shares];
    
    for (int i = 0; i < num_shares; i++) {
        mappings[i].participant_index = signature_shares[i].index;
        mappings[i].signature_pos = i;
        
        mappings[i].keypair_pos = -1;
        mappings[i].commitment_pos = -1;
        
        for (int j = 0; j < num_shares; j++) {
            if (participant_keypairs[j].index == mappings[i].participant_index) {
                mappings[i].keypair_pos = j;
            }
            if (commitments[j].index == mappings[i].participant_index) {
                mappings[i].commitment_pos = j;
            }
        }
        
        if (mappings[i].keypair_pos == -1 || mappings[i].commitment_pos == -1) {
            printf("ERROR: Missing data for participant %u\n", mappings[i].participant_index);
            secp256k1_context_destroy(ctx);
            return 0;
        }
    }
    
    // Sort by participant index
    for (int i = 0; i < num_shares - 1; i++) {
        for (int j = i + 1; j < num_shares; j++) {
            if (mappings[i].participant_index > mappings[j].participant_index) {
                participant_mapping_t temp = mappings[i];
                mappings[i] = mappings[j];
                mappings[j] = temp;
            }
        }
    }
    
    printf("Sorted participant order: ");
    for (int i = 0; i < num_shares; i++) {
        printf("%u ", mappings[i].participant_index);
    }
    printf("\n");
    
    secp256k1_frost_pubkey public_keys[num_shares];
    secp256k1_frost_nonce_commitment signing_commitments[num_shares];
    secp256k1_frost_signature_share frost_signature_shares[num_shares];
    
    for (int i = 0; i < num_shares; i++) {
        participant_mapping_t* m = &mappings[i];
        
        frost_signature_shares[i].index = signature_shares[m->signature_pos].index;
        memcpy(frost_signature_shares[i].response, signature_shares[m->signature_pos].response, 32);
        
        public_keys[i].index = participant_keypairs[m->keypair_pos].index;
        public_keys[i].max_participants = participant_keypairs[m->keypair_pos].max_participants;
        memcpy(public_keys[i].public_key, participant_keypairs[m->keypair_pos].public_key, 64);
        memcpy(public_keys[i].group_public_key, participant_keypairs[m->keypair_pos].group_public_key, 64);
        
        signing_commitments[i].index = commitments[m->commitment_pos].index;
        memcpy(signing_commitments[i].hiding, commitments[m->commitment_pos].hiding, 64);
        memcpy(signing_commitments[i].binding, commitments[m->commitment_pos].binding, 64);
        
        printf("Position %d: Participant %u\n", i, m->participant_index);
        printf("   Signature response: %02x%02x%02x%02x...\n",
               frost_signature_shares[i].response[0], frost_signature_shares[i].response[1],
               frost_signature_shares[i].response[2], frost_signature_shares[i].response[3]);
    }
    
    printf("\nAttempting signature aggregation...\n");
    printf("Using %d signature shares from participants\n", num_shares);
    
    int return_val = secp256k1_frost_aggregate(ctx, final_signature, msg_hash,
                                              &aggregator_keypair, public_keys, 
                                              signing_commitments,
                                              frost_signature_shares, num_shares);
    
    if (return_val == 1) {
        printf("*** SIGNATURE AGGREGATION SUCCESS! ***\n");
        
        int is_signature_valid = secp256k1_frost_verify(ctx, final_signature, msg_hash, 
                                                        &aggregator_keypair.public_keys);
        
        if (is_signature_valid) {
            printf("PERFECT: FROST signature is mathematically valid!\n");
            printf("\nFinal FROST Signature (64 bytes):\n");
            for (int i = 0; i < 64; i++) {
                printf("%02x", final_signature[i]);
                if ((i + 1) % 32 == 0) printf("\n");
            }
            printf("\n");
        } else {
            printf("WARNING: Aggregation succeeded but verification failed\n");
        }
        
        secp256k1_context_destroy(ctx);
        return is_signature_valid;
        
    } else {
        printf("*** SIGNATURE AGGREGATION FAILED ***\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
}

int main(void) {
    printf("=== FIXED FROST COORDINATOR WITH THREAD-SAFE HID ===\n");
    printf("PING/READY discovery protocol enabled\n");
    printf("Fixed simultaneous communication with offpad board support\n");
    printf("Device-specific synchronization and enhanced HID error handling\n\n");
    
    srand((unsigned int)time(NULL));
    InitializeCriticalSection(&device_lock);
    
    secp256k1_context* main_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!main_ctx) {
        printf("Failed to create main secp256k1 context\n");
        return 1;
    }
    
    participant_data_t participants[MAX_PARTICIPANTS];
    memset(participants, 0, sizeof(participants));
    
    unsigned char msg[12] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    unsigned char msg_hash[32];
    
    printf("Computing message hash...\n");
    compute_message_hash_verified(msg_hash, msg, sizeof(msg));
    
    printf("\n=== DEVICE DISCOVERY PHASE ===\n");
    
    // Step 1: Discover local file participants
    int local_files_found = discover_local_files();
    
    // Step 2: If we don't have enough, discover external devices using PING
    if (local_files_found < T) {
        printf("\nNeed more participants, searching for external devices with PING discovery...\n");
        discover_uart_devices();
        discover_hid_devices();
    }
    
    printf("\n=== DISCOVERY COMPLETE ===\n");
    printf("Total devices discovered: %d\n", num_discovered_devices);
    for (int i = 0; i < num_discovered_devices; i++) {
        const char* type_str = (discovered_devices[i].type == COMM_TYPE_LOCAL_COMPUTER) ? "LOCAL" :
                              (discovered_devices[i].type == COMM_TYPE_UART) ? "UART" : "HID";
        printf("  Device %d: %s participant %u (%s)\n", i, type_str, 
               discovered_devices[i].participant_id, discovered_devices[i].device_identifier);
    }
    
    if (num_discovered_devices < T) {
        printf("\nERROR: Only found %d devices, need %d for threshold signature\n", 
               num_discovered_devices, T);
        cleanup_all_devices();
        secp256k1_context_destroy(main_ctx);
        return 1;
    }
    
    // Post-discovery stabilization delay
    printf("\n=== POST-DISCOVERY STABILIZATION ===\n");
    printf("Waiting %d ms for devices to stabilize after discovery...\n", POST_DISCOVERY_DELAY_MS);
    Sleep(POST_DISCOVERY_DELAY_MS);
    printf("Stabilization complete, proceeding with FROST protocol\n");
    
    printf("\n=== PHASE 1: COMMITMENT COLLECTION (FIXED SIMULTANEOUS) ===\n");
    
    // Send READY message to all external devices SIMULTANEOUSLY
    int sent_ready = broadcast_message_simultaneously(MSG_TYPE_READY, NULL, 0);
    printf("FIXED SIMULTANEOUS READY broadcast sent to %d devices\n", sent_ready);
    
    // Collect commitments SIMULTANEOUSLY
    int collected_commitments = collect_commitments_from_devices(participants, T, COMMITMENT_COLLECTION_TIMEOUT_MS);
    
    if (collected_commitments < T) {
        printf("ERROR: Only collected %d commitments, need %d\n", collected_commitments, T);
        cleanup_all_devices();
        secp256k1_context_destroy(main_ctx);
        return 1;
    }
    
    printf("\nPhase 1 complete: %d commitments collected SIMULTANEOUSLY\n", collected_commitments);
    
    // Prepare sorted commitments array
    serialized_nonce_commitment_t sorted_commitments[T];
    serialized_keypair_t sorted_keypairs[T];
    int commitment_count = 0;
    
    for (int i = 0; i < MAX_PARTICIPANTS && commitment_count < T; i++) {
        if (participants[i].participant_id != 0 && participants[i].has_commitment) {
            sorted_commitments[commitment_count] = participants[i].commitment;
            sorted_keypairs[commitment_count] = participants[i].keypair;
            commitment_count++;
        }
    }
    
    // Sort by participant index for consistency
    for (int i = 0; i < commitment_count - 1; i++) {
        for (int j = i + 1; j < commitment_count; j++) {
            if (sorted_commitments[i].index > sorted_commitments[j].index) {
                serialized_nonce_commitment_t temp_comm = sorted_commitments[i];
                sorted_commitments[i] = sorted_commitments[j];
                sorted_commitments[j] = temp_comm;
                
                serialized_keypair_t temp_key = sorted_keypairs[i];
                sorted_keypairs[i] = sorted_keypairs[j];
                sorted_keypairs[j] = temp_key;
            }
        }
    }
    
    printf("\n=== PHASE 2: SIGNATURE COLLECTION (FIXED SIMULTANEOUS) ===\n");
    
    // Prepare signing message payload
    uint16_t payload_len = 32 + 4 + commitment_count * sizeof(serialized_nonce_commitment_t);
    uint8_t* payload = (uint8_t*)malloc(payload_len);
    if (!payload) {
        printf("Failed to allocate signing payload\n");
        cleanup_all_devices();
        secp256k1_context_destroy(main_ctx);
        return 1;
    }
    
    memcpy(payload, msg_hash, 32);
    *(uint32_t*)(payload + 32) = commitment_count;
    memcpy(payload + 32 + 4, sorted_commitments, commitment_count * sizeof(serialized_nonce_commitment_t));
    
    // Send signing data to all responding devices SIMULTANEOUSLY
    int sent_sign = broadcast_message_simultaneously(MSG_TYPE_SIGN, payload, payload_len);
    printf("FIXED SIMULTANEOUS SIGN broadcast sent to %d devices\n", sent_sign);
    
    free(payload);
    
    // Collect signature shares SIMULTANEOUSLY with enhanced timeout
    int collected_signatures = collect_signature_shares_from_devices(participants, T, 
                                                                   sorted_commitments, commitment_count,
                                                                   msg_hash, SIGNATURE_COLLECTION_TIMEOUT_MS);
    
    if (collected_signatures < T) {
        printf("ERROR: Only collected %d signatures, need %d\n", collected_signatures, T);
        printf("The HID thread-safe fixes should have resolved this issue.\n");
        cleanup_all_devices();
        secp256k1_context_destroy(main_ctx);
        return 1;
    }
    
    printf("\nPhase 2 complete: %d signature shares collected SIMULTANEOUSLY\n", collected_signatures);
    
    printf("\n=== SIGNATURE AGGREGATION ===\n");
    
    // Extract final data for aggregation
    serialized_signature_share_t final_signature_shares[T];
    int share_count = 0;
    
    for (int i = 0; i < MAX_PARTICIPANTS && share_count < T; i++) {
        if (participants[i].participant_id != 0 && participants[i].has_signature_share) {
            final_signature_shares[share_count] = participants[i].signature_share;
            share_count++;
        }
    }
    
    unsigned char final_signature[64];
    memset(final_signature, 0, sizeof(final_signature));
    
    int aggregation_result = aggregate_and_verify_signature_ENHANCED(final_signature_shares, 
                                                                    sorted_keypairs,
                                                                    sorted_commitments,
                                                                    share_count, 
                                                                    msg_hash, 
                                                                    final_signature);
    
    if (aggregation_result) {
        printf("\n=== FROST SIGNATURE PROTOCOL SUCCESS! ===\n");
        printf("FIXED SIMULTANEOUS COMMUNICATION WITH THREAD-SAFE HID\n");
        printf("All device communication happened in parallel with proper synchronization\n");
        printf("Offpad board compatibility restored with enhanced error handling\n\n");
        printf("Final aggregated FROST signature:\n");
        for (int i = 0; i < 64; i++) {
            printf("%02x", final_signature[i]);
            if (i == 31) printf("\n");
        }
        printf("\n");
        
        printf("\nParticipants that contributed:\n");
        for (int i = 0; i < MAX_PARTICIPANTS; i++) {
            if (participants[i].participant_id != 0 && participants[i].has_signature_share) {
                printf("  Participant %u\n", participants[i].participant_id);
            }
        }
    } else {
        printf("\nFROST SIGNATURE PROTOCOL FAILED\n");
        printf("Check HID device connections and USB power management settings\n");
    }
    
    cleanup_all_devices();
    DeleteCriticalSection(&device_lock);
    secp256k1_context_destroy(main_ctx);
    
    printf("\nPress Enter to exit...\n");
    getchar();
    return 0;
}