#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <windows.h>
#include <stdbool.h>
#include <setupapi.h>
#include <hidsdi.h>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")

#define N 3 // Number of participants
#define T 2 // Threshold of needed participants

// USB HID constants - MUST match receiver
#define VENDOR_ID 0x2FE3   // Nordic Semiconductor
#define PRODUCT_ID 0x100   // Adjust based on your device

// Communication types
typedef enum {
    COMM_TYPE_UART = 1,
    COMM_TYPE_USB_HID = 2
} communication_type_t;

// Communication handle wrapper
typedef struct {
    communication_type_t type;
    union {
        HANDLE uart_handle;
        struct {
            HANDLE hid_handle;
            PHIDP_PREPARSED_DATA preparsed_data;
            HIDP_CAPS capabilities;
            USHORT output_report_length;
            USHORT input_report_length;
        };
    };
} comm_handle_t;

// Constants for message protocol
#define MSG_HEADER_MAGIC 0x46524F53 // "FROS" as hex
#define MSG_VERSION 0x01

// Message types for our protocol
typedef enum {
    MSG_TYPE_NONCE_COMMITMENT = 0x04,  
    MSG_TYPE_ALL_NONCE_COMMITMENTS = 0x05,  
    MSG_TYPE_READY = 0x06,            
    MSG_TYPE_END_TRANSMISSION = 0xFF,
    MSG_TYPE_SIGN = 0x07,
    MSG_TYPE_SIGNATURE_SHARE = 0x08   // Para recibir signature shares
} message_type_t;

// Header for each message in our protocol
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;        // Magic number to identify our protocol
    uint8_t version;       // Protocol version
    uint8_t msg_type;      // Type of message
    uint16_t payload_len;  // Length of payload following the header
    uint32_t participant;  // Participant ID 
} message_header_t;
#pragma pack(pop)

// Nonce commitment structure 
#pragma pack(push, 1)
typedef struct {
    uint32_t participant_index;
    uint8_t hiding[32];     
    uint8_t binding[32];    
} serialized_nonce_commitment_t;
#pragma pack(pop)

// Signature share structure
#pragma pack(push, 1)
typedef struct {
    uint32_t participant_index;
    uint8_t response[32];
} serialized_signature_share_t;
#pragma pack(pop)

// Helper function to print hex data
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 8; i++) {
        printf("%02x", data[i]);
    }
    if (len > 8) printf("...");
    printf("\n");
}

// Helper function to print full hex data
void print_full_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// ================== HID HELPER FUNCTIONS ==================
comm_handle_t find_hid_device(USHORT vendor_id, USHORT product_id) {
    comm_handle_t comm = {0};
    GUID hid_guid;
    HDEVINFO device_info_set;
    SP_DEVICE_INTERFACE_DATA device_interface_data;
    PSP_DEVICE_INTERFACE_DETAIL_DATA device_interface_detail_data;
    DWORD required_size;

    printf("Looking for HID device with VID:0x%04X PID:0x%04X\n", vendor_id, product_id);

    HidD_GetHidGuid(&hid_guid);
    device_info_set = SetupDiGetClassDevs(&hid_guid, NULL, NULL, 
                                         DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (device_info_set == INVALID_HANDLE_VALUE) {
        printf("Failed to get device information set. Error: %lu\n", GetLastError());
        return comm;
    }

    device_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
    
    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(device_info_set, NULL, &hid_guid, 
                                                  i, &device_interface_data); i++) {
        SetupDiGetDeviceInterfaceDetail(device_info_set, &device_interface_data, 
                                       NULL, 0, &required_size, NULL);
        device_interface_detail_data = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(required_size);
        if (!device_interface_detail_data) continue;
        device_interface_detail_data->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        if (SetupDiGetDeviceInterfaceDetail(device_info_set, &device_interface_data,
                                           device_interface_detail_data, required_size,
                                           NULL, NULL)) {
            
            printf("Trying device path: %s\n", device_interface_detail_data->DevicePath);
            
            // Try different access modes for better compatibility
            DWORD access_modes[] = {
                GENERIC_READ | GENERIC_WRITE,
                GENERIC_WRITE,
                GENERIC_READ | GENERIC_WRITE | FILE_SHARE_READ | FILE_SHARE_WRITE
            };
            
            HANDLE temp_handle = INVALID_HANDLE_VALUE;
            
            for (int mode_idx = 0; mode_idx < 3 && temp_handle == INVALID_HANDLE_VALUE; mode_idx++) {
                temp_handle = CreateFile(device_interface_detail_data->DevicePath,
                                       access_modes[mode_idx],
                                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                                       NULL, OPEN_EXISTING, 0, NULL);
                
                if (temp_handle == INVALID_HANDLE_VALUE) {
                    DWORD error = GetLastError();
                    printf("  Access mode %d failed. Error: %lu\n", mode_idx, error);
                }
            }
            
            if (temp_handle != INVALID_HANDLE_VALUE) {
                printf("  Device opened successfully\n");
                
                HIDD_ATTRIBUTES attributes;
                attributes.Size = sizeof(HIDD_ATTRIBUTES);
                if (HidD_GetAttributes(temp_handle, &attributes)) {
                    printf("  Device attributes: VID:0x%04X PID:0x%04X Ver:0x%04X\n", 
                           attributes.VendorID, attributes.ProductID, attributes.VersionNumber);
                    
                    if (attributes.VendorID == vendor_id && attributes.ProductID == product_id) {
                        printf("  MATCH FOUND!\n");
                        
                        PHIDP_PREPARSED_DATA preparsed_data;
                        if (HidD_GetPreparsedData(temp_handle, &preparsed_data)) {
                            HIDP_CAPS capabilities;
                            if (HidP_GetCaps(preparsed_data, &capabilities) == HIDP_STATUS_SUCCESS) {
                                printf("  Device capabilities:\n");
                                printf("    Usage Page: 0x%04X\n", capabilities.UsagePage);
                                printf("    Usage: 0x%04X\n", capabilities.Usage);
                                printf("    Input Report Length: %d\n", capabilities.InputReportByteLength);
                                printf("    Output Report Length: %d\n", capabilities.OutputReportByteLength);
                                
                                comm.type = COMM_TYPE_USB_HID;
                                comm.hid_handle = temp_handle;
                                comm.preparsed_data = preparsed_data;
                                comm.capabilities = capabilities;
                                comm.output_report_length = capabilities.OutputReportByteLength;
                                comm.input_report_length = capabilities.InputReportByteLength;
                                
                                free(device_interface_detail_data);
                                SetupDiDestroyDeviceInfoList(device_info_set);
                                return comm;
                            } else {
                                printf("  Failed to get HID capabilities\n");
                            }
                            HidD_FreePreparsedData(preparsed_data);
                        } else {
                            printf("  Failed to get preparsed data\n");
                        }
                    } else {
                        printf("  VID/PID mismatch\n");
                    }
                } else {
                    printf("  Failed to get device attributes. Error: %lu\n", GetLastError());
                }
                CloseHandle(temp_handle);
            } else {
                printf("  Failed to open device. Error: %lu\n", GetLastError());
            }
        } else {
            printf("Failed to get device interface detail. Error: %lu\n", GetLastError());
        }
        free(device_interface_detail_data);
    }

    SetupDiDestroyDeviceInfoList(device_info_set);
    printf("Target device not found.\n");
    return comm;
}

BOOL send_hid_data(comm_handle_t* comm, const void* data, size_t len) {
    const uint8_t* data_ptr = (const uint8_t*)data;
    size_t bytes_sent = 0;
    
    printf("Sending %zu bytes via HID (Report Length: %d)\n", len, comm->output_report_length);
    
    while (bytes_sent < len) {
        uint8_t* report = (uint8_t*)calloc(1, comm->output_report_length);
        if (!report) {
            printf("Failed to allocate report buffer\n");
            return FALSE;
        }
        
        // Set report ID
        report[0] = 0x02;
        
        // Calculate chunk size - leave room for report ID and length byte
        size_t available_space = comm->output_report_length - 2; // -1 for report ID, -1 for length
        size_t remaining = len - bytes_sent;
        size_t chunk_size = (available_space < remaining) ? available_space : remaining;
        
        // Set the actual data length in the second byte
        report[1] = (uint8_t)chunk_size;
        
        // Copy data to report buffer starting at byte 2
        memcpy(report + 2, data_ptr + bytes_sent, chunk_size);
        
        printf("Sending chunk %zu bytes (sent: %zu/%zu), full report: %d bytes\n", 
               chunk_size, bytes_sent, len, comm->output_report_length);
        
        // Try HidD_SetOutputReport first
        if (!HidD_SetOutputReport(comm->hid_handle, report, comm->output_report_length)) {
            DWORD error = GetLastError();
            printf("HidD_SetOutputReport failed. Error: %lu. Trying WriteFile...\n", error);
            
            // Try alternative method using WriteFile
            DWORD bytes_written;
            OVERLAPPED overlapped = {0};
            overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
            
            if (overlapped.hEvent) {
                BOOL write_result = WriteFile(comm->hid_handle, report, comm->output_report_length, 
                                            &bytes_written, &overlapped);
                if (!write_result) {
                    DWORD write_error = GetLastError();
                    if (write_error == ERROR_IO_PENDING) {
                        // Wait for completion
                        DWORD wait_result = WaitForSingleObject(overlapped.hEvent, 5000);
                        if (wait_result == WAIT_OBJECT_0) {
                            if (GetOverlappedResult(comm->hid_handle, &overlapped, &bytes_written, FALSE)) {
                                printf("WriteFile method succeeded (%lu bytes)\n", bytes_written);
                                write_result = TRUE;
                            } else {
                                printf("GetOverlappedResult failed. Error: %lu\n", GetLastError());
                            }
                        } else {
                            printf("WriteFile timeout. Wait result: %lu\n", wait_result);
                        }
                    } else {
                        printf("WriteFile failed immediately. Error: %lu\n", write_error);
                    }
                }
                CloseHandle(overlapped.hEvent);
                
                if (!write_result) {
                    printf("Both HID send methods failed\n");
                    free(report);
                    return FALSE;
                }
            } else {
                printf("Failed to create event for overlapped I/O\n");
                free(report);
                return FALSE;
            }
        } else {
            printf("HidD_SetOutputReport succeeded\n");
        }
        
        free(report);
        bytes_sent += chunk_size;
        
        // Delay between chunks to prevent overwhelming the receiver
        Sleep(200);
    }
    
    printf("Successfully sent all %zu bytes in HID chunks\n", bytes_sent);
    return TRUE;
}

// Enhanced receive function with chunked data support
BOOL receive_hid_data_chunked(comm_handle_t* comm, void* buffer, size_t max_len, size_t* total_received) {
    uint8_t* recv_buffer = (uint8_t*)buffer;
    *total_received = 0;
    
    while (*total_received < max_len) {
        uint8_t* report = (uint8_t*)calloc(1, comm->input_report_length);
        if (!report) return FALSE;
        
        DWORD bytes_read;
        if (!ReadFile(comm->hid_handle, report, comm->input_report_length, &bytes_read, NULL)) {
            free(report);
            return FALSE;
        }
        
        if (bytes_read > 0) {
            // Parse chunked data: [Report ID][Length][Data...]
            uint8_t report_id = report[0];
            if (report_id == 0x01 && bytes_read >= 3) { // Input report with data
                uint8_t chunk_len = report[1];
                if (chunk_len > 0 && chunk_len <= (bytes_read - 2)) {
                    size_t copy_len = (*total_received + chunk_len <= max_len) ? chunk_len : (max_len - *total_received);
                    memcpy(recv_buffer + *total_received, report + 2, copy_len);
                    *total_received += copy_len;
                    
                    printf("Received chunk: %u bytes (total: %zu)\n", chunk_len, *total_received);
                    
                    // Check if this looks like a complete message
                    if (*total_received >= sizeof(message_header_t)) {
                        message_header_t* header = (message_header_t*)recv_buffer;
                        if (header->magic == MSG_HEADER_MAGIC) {
                            size_t expected_total = sizeof(message_header_t) + header->payload_len;
                            if (*total_received >= expected_total) {
                                printf("Complete message received (%zu bytes)\n", expected_total);
                                *total_received = expected_total; // Trim to exact message size
                                free(report);
                                return TRUE;
                            }
                        }
                    }
                }
            }
        }
        
        free(report);
        
        // Timeout after reasonable wait
        Sleep(100);
        static int timeout_counter = 0;
        if (++timeout_counter > 50) { // 5 second timeout
            printf("Timeout waiting for complete message\n");
            timeout_counter = 0;
            break;
        }
    }
    
    return (*total_received > 0);
}

// ================== GENERIC COMMUNICATION FUNCTIONS ==================
BOOL send_data(comm_handle_t* comm, const void* data, size_t len) {
    switch (comm->type) {
        case COMM_TYPE_UART: {
            DWORD bytes_written;
            return WriteFile(comm->uart_handle, data, (DWORD)len, &bytes_written, NULL) 
                   && bytes_written == len;
        }
        case COMM_TYPE_USB_HID:
            return send_hid_data(comm, data, len);
        default:
            return FALSE;
    }
}

BOOL receive_data(comm_handle_t* comm, void* buffer, size_t max_len, size_t* bytes_read) {
    switch (comm->type) {
        case COMM_TYPE_UART: {
            DWORD bytes_read_now;
            if (!ReadFile(comm->uart_handle, buffer, (DWORD)max_len, &bytes_read_now, NULL)) {
                return FALSE;
            }
            *bytes_read = bytes_read_now;
            return TRUE;
        }
        case COMM_TYPE_USB_HID:
            return receive_hid_data_chunked(comm, buffer, max_len, bytes_read);
        default:
            return FALSE;
    }
}

// ================== MESSAGE FUNCTIONS ==================
BOOL send_message(comm_handle_t* comm, uint8_t msg_type, uint32_t participant, 
                  const void* payload, uint16_t payload_len) {
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
    
    printf("Sending message: type=0x%02X, participant=%u, len=%u\n", 
           msg_type, participant, payload_len);
    
    BOOL result = send_data(comm, combined_buffer, total_size);
    free(combined_buffer);
    
    if (result) {
        printf("Message sent successfully\n");
        Sleep(500); // Delay after sending
    }
    
    return result;
}

BOOL receive_complete_message(comm_handle_t* comm, uint8_t* buffer, size_t max_len, 
                              message_header_t** header, void** payload) {
    size_t bytes_received;
    if (!receive_data(comm, buffer, max_len, &bytes_received)) {
        return FALSE;
    }
    
    if (bytes_received < sizeof(message_header_t)) {
        printf("Received incomplete message (%zu bytes)\n", bytes_received);
        return FALSE;
    }
    
    *header = (message_header_t*)buffer;
    
    // Validate header
    if ((*header)->magic != MSG_HEADER_MAGIC || (*header)->version != MSG_VERSION) {
        printf("Invalid message header: magic=0x%08x, version=%d\n", 
               (*header)->magic, (*header)->version);
        return FALSE;
    }
    
    // Set payload pointer
    if ((*header)->payload_len > 0) {
        *payload = buffer + sizeof(message_header_t);
    } else {
        *payload = NULL;
    }
    
    printf("Received valid message: type=0x%02X, len=%u\n", 
           (*header)->msg_type, (*header)->payload_len);
    
    return TRUE;
}

// ================== SERIAL PORT SETUP ==================
HANDLE setup_uart_port(const char *port_name) {
    HANDLE hSerial = CreateFile(port_name,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
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
    timeouts.ReadIntervalTimeout = 100;
    timeouts.ReadTotalTimeoutConstant = 10000; // 10 second timeout
    timeouts.ReadTotalTimeoutMultiplier = 10;
    timeouts.WriteTotalTimeoutConstant = 1000;
    timeouts.WriteTotalTimeoutMultiplier = 10;
    if (!SetCommTimeouts(hSerial, &timeouts)) {
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }
    return hSerial;
}

comm_handle_t setup_communication(int participant_id) {
    comm_handle_t comm = {0};
    
    printf("\n=== Setting up communication for participant %d ===\n", participant_id);
    printf("Select communication method:\n");
    printf("1. UART/Serial (COM port)\n");
    printf("2. USB HID\n");
    printf("Enter choice (1 or 2): ");
    
    int choice;
    scanf("%d", &choice);
    getchar();
    
    switch (choice) {
        case 1: {
            printf("Enter COM port (e.g., COM4): ");
            char port_name[10];
            scanf("%9s", port_name);
            getchar();
            
            HANDLE uart_handle = setup_uart_port(port_name);
            if (uart_handle != INVALID_HANDLE_VALUE) {
                comm.type = COMM_TYPE_UART;
                comm.uart_handle = uart_handle;
                printf("UART communication set up on %s\n", port_name);
            } else {
                printf("Failed to open UART port %s\n", port_name);
            }
            break;
        }
        case 2: {
            printf("Searching for USB HID device (VID:0x%04X, PID:0x%04X)...\n", 
                   VENDOR_ID, PRODUCT_ID);
            comm = find_hid_device(VENDOR_ID, PRODUCT_ID);
            if (comm.type != 0) {
                printf("USB HID device found!\n");
                printf("Waiting for device to stabilize...\n");
                Sleep(1000); // Give device time to stabilize
            } else {
                printf("USB HID device not found\n");
            }
            break;
        }
        default:
            printf("Invalid choice\n");
            break;
    }
    return comm;
}

void close_communication(comm_handle_t* comm) {
    if (comm->type == COMM_TYPE_UART && comm->uart_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(comm->uart_handle);
    } else if (comm->type == COMM_TYPE_USB_HID && comm->hid_handle != INVALID_HANDLE_VALUE) {
        if (comm->preparsed_data) {
            HidD_FreePreparsedData(comm->preparsed_data);
        }
        CloseHandle(comm->hid_handle);
    }
    memset(comm, 0, sizeof(comm_handle_t));
}

// ================== FROST SIGNING FUNCTIONS ==================
void compute_message_hash(unsigned char* msg_hash, const unsigned char* msg, size_t msg_len) {
    secp256k1_context* sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char tag[14] = {'f', 'r', 'o', 's', 't', '\0', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};
    int return_val = secp256k1_tagged_sha256(sign_verify_ctx, msg_hash, tag, sizeof(tag), msg, msg_len);
    assert(return_val == 1);
    secp256k1_context_destroy(sign_verify_ctx);
}

// ================== MAIN PROGRAM ==================
int main(void) {
    printf("=== FROST Signature Coordinator with Immediate Share Collection ===\n\n");
    
    serialized_nonce_commitment_t commitments[N];
    serialized_signature_share_t signature_shares[N];
    int commitments_received = 0;
    int shares_received = 0;
    uint8_t receive_buffer[1024];
    
    // Initialize signature shares array
    memset(signature_shares, 0, sizeof(signature_shares));
    
    // Mensaje a firmar
    unsigned char msg[12] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    unsigned char msghash[32];
    compute_message_hash(msghash, msg, sizeof(msg));
    print_hex("Message Hash", msghash, sizeof(msghash));
    
    // Fase 1: Recopilar compromisos de nonce
    for (int i = 0; i < N; i++) {
        printf("\n=== Processing Participant %d (Nonce Commitment) ===\n", i+1);
        
        // Setup communication
        comm_handle_t comm = setup_communication(i+1);
        if (comm.type == 0) {
            printf("Skipping participant %d due to communication failure\n", i+1);
            continue;
        }
        
        // Send READY signal to trigger nonce generation
        printf("Sending READY signal to participant %d...\n", i+1);
        if (!send_message(&comm, MSG_TYPE_READY, i+1, NULL, 0)) {
            printf("Failed to send READY signal to participant %d\n", i+1);
            close_communication(&comm);
            continue;
        }
        
        // Wait for nonce commitment response
        printf("Waiting for nonce commitment from participant %d...\n", i+1);
        
        message_header_t* header;
        void* payload;
        
        if (receive_complete_message(&comm, receive_buffer, sizeof(receive_buffer), &header, &payload)) {
            if (header->msg_type == MSG_TYPE_NONCE_COMMITMENT && 
                header->payload_len == sizeof(serialized_nonce_commitment_t)) {
                
                // Store the commitment
                memcpy(&commitments[commitments_received], payload, sizeof(serialized_nonce_commitment_t));
                
                printf("Received nonce commitment from participant %d (index: %u)\n", 
                       i+1, commitments[commitments_received].participant_index);
                print_hex("  Hiding", commitments[commitments_received].hiding, 32);
                print_hex("  Binding", commitments[commitments_received].binding, 32);
                
                commitments_received++;
            } else {
                printf("Received unexpected message type: 0x%02X\n", header->msg_type);
            }
        } else {
            printf("Failed to receive nonce commitment from participant %d\n", i+1);
        }
        
        // Close communication
        close_communication(&comm);
        
        // Break early if we have enough commitments
        if (commitments_received >= T) {
            printf("\nReceived minimum %d commitments. Continuing...\n", T);
            break;
        }
    }
    
    if (commitments_received < T) {
        printf("\nError: Received only %d commitments, need at least %d\n", 
               commitments_received, T);
        printf("Press Enter to exit...\n");
        getchar();
        return 1;
    }
    
    // Display summary
    printf("\n=== FROST Nonce Commitment Collection Complete ===\n");
    printf("Collected %d nonce commitments:\n", commitments_received);
    for (int i = 0; i < commitments_received; i++) {
        printf("Participant %u:\n", commitments[i].participant_index);
        print_hex("  Hiding", commitments[i].hiding, 32);
        print_hex("  Binding", commitments[i].binding, 32);
    }
    
    // Fase 2: Enviar hash y compromisos a cada dispositivo Y recibir signature shares inmediatamente
    printf("\n=== Sending Signing Data and Collecting Signature Shares ===\n");
    
    for (int i = 0; i < T; i++) {
        uint32_t participant_index = commitments[i].participant_index;
        printf("\n=== Processing Participant %u ===\n", participant_index);
        
        // Setup communication
        comm_handle_t comm = setup_communication(participant_index);
        if (comm.type == 0) {
            printf("Skipping participant %u due to communication failure\n", participant_index);
            continue;
        }
        
        // Preparar payload: [msghash][num_commitments][commitments...]
        uint16_t payload_len = 32 + 4 + T * sizeof(serialized_nonce_commitment_t);
        uint8_t* payload = (uint8_t*)malloc(payload_len);
        if (!payload) {
            close_communication(&comm);
            continue;
        }
        
        // Copiar msghash (32 bytes)
        memcpy(payload, msghash, 32);
        // Copiar num_commitments (T)
        *(uint32_t*)(payload + 32) = T;
        // Copiar los T compromisos
        memcpy(payload + 32 + 4, commitments, T * sizeof(serialized_nonce_commitment_t));
        
        // Enviar mensaje de firma
        printf("Sending signing data to participant %u...\n", participant_index);
        if (!send_message(&comm, MSG_TYPE_SIGN, participant_index, payload, payload_len)) {
            printf("Failed to send signing data to participant %u\n", participant_index);
            free(payload);
            close_communication(&comm);
            continue;
        } else {
            printf("Signing data sent successfully to participant %u\n", participant_index);
            printf("  Message hash sent: ");
            print_hex("", msghash, 8); // Solo primeros 8 bytes
            printf("  Number of commitments sent: %d\n", T);
        }
        
        free(payload);
        
        // Inmediatamente después de enviar, esperar por la signature share
        printf("Waiting for signature share from participant %u...\n", participant_index);
        
        message_header_t* header;
        void* payload_response;
        DWORD start_time = GetTickCount();
        DWORD timeout_ms = 20000; // 20 second timeout
        BOOL received_share = FALSE;
        
        while (!received_share && (GetTickCount() - start_time) < timeout_ms) {
            if (receive_complete_message(&comm, receive_buffer, sizeof(receive_buffer), 
                                       &header, &payload_response)) {
                if (header->msg_type == MSG_TYPE_SIGNATURE_SHARE && 
                    header->payload_len == sizeof(serialized_signature_share_t)) {
                    
                    // Store the signature share
                    serialized_signature_share_t* sig_share = (serialized_signature_share_t*)payload_response;
                    memcpy(&signature_shares[shares_received], sig_share, sizeof(serialized_signature_share_t));
                    
                    printf("\n*** SIGNATURE SHARE RECEIVED from Participant %u ***\n", 
                           sig_share->participant_index);
                    print_full_hex("Signature Share", sig_share->response, 32);
                    
                    // Print signature share in a formatted way
                    printf("\n=== FROST SIGNATURE SHARE %d ===\n", shares_received + 1);
                    printf("Participant: %u\n", sig_share->participant_index);
                    printf("Share: ");
                    for (int j = 0; j < 32; j++) {
                        printf("%02x", sig_share->response[j]);
                    }
                    printf("\n");
                    printf("===============================\n\n");
                    
                    shares_received++;
                    received_share = TRUE;
                } else if (header->msg_type == MSG_TYPE_END_TRANSMISSION) {
                    printf("Received end transmission marker\n");
                } else {
                    printf("Received unexpected message type: 0x%02X (expected signature share)\n", 
                           header->msg_type);
                }
            }
            
            // Small delay before retrying
            Sleep(100);
        }
        
        if (!received_share) {
            printf("*** TIMEOUT: No signature share received from participant %u ***\n", participant_index);
        }
        
        close_communication(&comm);
    }
    
    printf("\n=== Signing Process Complete ===\n");
    
    if (shares_received >= T) {
        printf("\n=== SIGNATURE SHARE COLLECTION COMPLETE ===\n");
        printf("Successfully collected signature shares from %d participants:\n\n", shares_received);
        
        for (int i = 0; i < shares_received; i++) {
            if (signature_shares[i].participant_index != 0) {
                printf("Participant %u Signature Share:\n", signature_shares[i].participant_index);
                printf("  ");
                for (int j = 0; j < 32; j++) {
                    printf("%02x", signature_shares[i].response[j]);
                }
                printf("\n\n");
            }
        }
        
        printf("All signature shares have been collected and displayed.\n");
        printf("These shares can now be aggregated to form the final FROST signature.\n");
    } else {
        printf("\n=== INCOMPLETE SIGNATURE COLLECTION ===\n");
        printf("Only received %d signature shares out of %d required.\n", shares_received, T);
        printf("Some devices may have failed to compute or send their shares.\n");
    }
    
    printf("\nPress Enter to exit...\n");
    getchar();
    return 0;
}