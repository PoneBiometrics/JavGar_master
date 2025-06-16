#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")

#define N 3 // Number of participants
#define T 2 // Threshold of needed participants

// USB HID constants
#define VENDOR_ID 0x2FE3   
#define PRODUCT_ID 0x100   

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
        };
    };
} comm_handle_t;

// Constants for message protocol - MUST match receiver
#define MSG_HEADER_MAGIC 0x46524F53 // "FROS" as hex
#define MSG_VERSION 0x01

// Message types for our protocol
typedef enum {
    MSG_TYPE_SECRET_SHARE = 0x01,
    MSG_TYPE_PUBLIC_KEY = 0x02,
    MSG_TYPE_COMMITMENTS = 0x03,
    MSG_TYPE_END_TRANSMISSION = 0xFF
} message_type_t;

// Header for each message in our protocol
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;        // Magic number to identify our protocol
    uint8_t version;       // Protocol version
    uint8_t msg_type;      // Type of message
    uint16_t payload_len;  // Length of payload following the header
    uint32_t participant;  // Participant ID (1-based)
} message_header_t;
#pragma pack(pop)

// Corrected structures to match the example format
#pragma pack(push, 1)
typedef struct {
    uint32_t receiver_index;
    uint8_t value[32];
} serialized_share_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t index;
    uint32_t max_participants;
    uint8_t public_key[64];      // 64 bytes like in example
    uint8_t group_public_key[64]; // 64 bytes like in example
} serialized_pubkey_t;
#pragma pack(pop)

// Helper function to print hex data
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// fill_random is provided by examples_util.h - no need to implement

// Enhanced USB HID helper functions
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
            
            DWORD access_modes[] = {
                GENERIC_WRITE,
                GENERIC_READ | GENERIC_WRITE,
                GENERIC_WRITE | FILE_SHARE_READ | FILE_SHARE_WRITE
            };
            
            HANDLE temp_handle = INVALID_HANDLE_VALUE;
            
            for (int mode_idx = 0; mode_idx < 3 && temp_handle == INVALID_HANDLE_VALUE; mode_idx++) {
                temp_handle = CreateFile(device_interface_detail_data->DevicePath,
                                       access_modes[mode_idx],
                                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                                       NULL, OPEN_EXISTING, 0, NULL);
                
                if (temp_handle == INVALID_HANDLE_VALUE) {
                    temp_handle = CreateFile(device_interface_detail_data->DevicePath,
                                           access_modes[mode_idx],
                                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                                           NULL, OPEN_EXISTING, 
                                           FILE_FLAG_OVERLAPPED, NULL);
                }
            }
            
            if (temp_handle != INVALID_HANDLE_VALUE) {
                HIDD_ATTRIBUTES attributes;
                attributes.Size = sizeof(HIDD_ATTRIBUTES);
                if (HidD_GetAttributes(temp_handle, &attributes)) {
                    if (attributes.VendorID == vendor_id && attributes.ProductID == product_id) {
                        printf("Found matching device!\n");
                        
                        PHIDP_PREPARSED_DATA preparsed_data;
                        if (HidD_GetPreparsedData(temp_handle, &preparsed_data)) {
                            HIDP_CAPS capabilities;
                            if (HidP_GetCaps(preparsed_data, &capabilities) == HIDP_STATUS_SUCCESS) {
                                comm.type = COMM_TYPE_USB_HID;
                                comm.hid_handle = temp_handle;
                                comm.preparsed_data = preparsed_data;
                                comm.capabilities = capabilities;
                                comm.output_report_length = capabilities.OutputReportByteLength;
                                
                                free(device_interface_detail_data);
                                SetupDiDestroyDeviceInfoList(device_info_set);
                                return comm;
                            }
                            HidD_FreePreparsedData(preparsed_data);
                        }
                    }
                }
                CloseHandle(temp_handle);
            }
        }
        free(device_interface_detail_data);
    }

    SetupDiDestroyDeviceInfoList(device_info_set);
    printf("Device not found.\n");
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
        
        report[0] = 0x02;
        size_t available_space = comm->output_report_length - 2;
        size_t remaining = len - bytes_sent;
        size_t chunk_size = (available_space < remaining) ? available_space : remaining;
        
        report[1] = (uint8_t)chunk_size;
        memcpy(report + 2, data_ptr + bytes_sent, chunk_size);
        
        if (!HidD_SetOutputReport(comm->hid_handle, report, comm->output_report_length)) {
            DWORD error = GetLastError();
            printf("Failed to send HID report. Error: %lu\n", error);
            
            DWORD bytes_written;
            OVERLAPPED overlapped = {0};
            overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
            
            if (overlapped.hEvent) {
                BOOL write_result = WriteFile(comm->hid_handle, report, comm->output_report_length, 
                                            &bytes_written, &overlapped);
                if (!write_result) {
                    if (GetLastError() == ERROR_IO_PENDING) {
                        if (WaitForSingleObject(overlapped.hEvent, 5000) == WAIT_OBJECT_0) {
                            if (GetOverlappedResult(comm->hid_handle, &overlapped, &bytes_written, FALSE)) {
                                write_result = TRUE;
                            }
                        }
                    }
                }
                CloseHandle(overlapped.hEvent);
                
                if (!write_result) {
                    free(report);
                    return FALSE;
                }
            } else {
                free(report);
                return FALSE;
            }
        }
        
        free(report);
        bytes_sent += chunk_size;
        Sleep(100);
    }
    
    return TRUE;
}

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

BOOL send_message(comm_handle_t* comm, uint8_t msg_type, uint32_t participant, 
                  const void* payload, uint16_t payload_len) {
    message_header_t header;
    
    header.magic = MSG_HEADER_MAGIC;
    header.version = MSG_VERSION;
    header.msg_type = msg_type;
    header.payload_len = payload_len;
    header.participant = participant;
    
    printf("Sending message: type=0x%02X, participant=%u, payload_len=%u\n",
           msg_type, participant, payload_len);
    
    size_t total_size = sizeof(header) + payload_len;
    uint8_t* combined_buffer = (uint8_t*)malloc(total_size);
    if (!combined_buffer) {
        return FALSE;
    }
    
    memcpy(combined_buffer, &header, sizeof(header));
    if (payload_len > 0 && payload) {
        memcpy(combined_buffer + sizeof(header), payload, payload_len);
    }
    
    BOOL result = send_data(comm, combined_buffer, total_size);
    free(combined_buffer);
    
    if (result) {
        printf("Message sent successfully\n");
        Sleep(1000);
    }
    
    return result;
}

BOOL send_secret_share(comm_handle_t* comm, uint32_t participant, 
                       const secp256k1_frost_keygen_secret_share *share) {
    serialized_share_t serialized;
    serialized.receiver_index = share->receiver_index;
    memcpy(serialized.value, share->value, sizeof(serialized.value));
    
    return send_message(comm, MSG_TYPE_SECRET_SHARE, participant,
                       &serialized, sizeof(serialized));
}

BOOL send_public_key(comm_handle_t* comm, uint32_t participant, 
                    const secp256k1_frost_pubkey *pubkey) {
    serialized_pubkey_t serialized;
    serialized.index = pubkey->index;
    serialized.max_participants = pubkey->max_participants;
    memcpy(serialized.public_key, pubkey->public_key, sizeof(serialized.public_key));
    memcpy(serialized.group_public_key, pubkey->group_public_key, sizeof(serialized.group_public_key));
    
    return send_message(comm, MSG_TYPE_PUBLIC_KEY, participant,
                       &serialized, sizeof(serialized));
}

BOOL send_commitments(comm_handle_t* comm, uint32_t participant, 
                     const secp256k1_frost_vss_commitments *commitments) {
    size_t coef_data_size = commitments->num_coefficients * sizeof(secp256k1_frost_vss_commitment);
    size_t total_size = sizeof(uint32_t) * 2 + sizeof(uint8_t) * 32 + sizeof(uint8_t) * 64 + coef_data_size;
    
    uint8_t* buffer = (uint8_t*)malloc(total_size);
    if (!buffer) {
        return FALSE;
    }
    
    uint8_t *ptr = buffer;
    
    memcpy(ptr, &commitments->index, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, &commitments->num_coefficients, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    
    memcpy(ptr, commitments->zkp_z, 32);
    ptr += 32;
    memcpy(ptr, commitments->zkp_r, 64);
    ptr += 64;
    
    memcpy(ptr, commitments->coefficient_commitments, coef_data_size);
    
    BOOL result = send_message(comm, MSG_TYPE_COMMITMENTS, participant,
                              buffer, (uint16_t)total_size);
    
    free(buffer);
    return result;
}

BOOL send_end_transmission(comm_handle_t* comm, uint32_t participant) {
    return send_message(comm, MSG_TYPE_END_TRANSMISSION, participant, NULL, 0);
}

HANDLE setup_uart_port(const char *port_name) {
    HANDLE hSerial = CreateFile(port_name,
        GENERIC_WRITE,
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
    timeouts.ReadIntervalTimeout = 50;
    timeouts.ReadTotalTimeoutConstant = 50;
    timeouts.ReadTotalTimeoutMultiplier = 10;
    timeouts.WriteTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutMultiplier = 10;
    if (!SetCommTimeouts(hSerial, &timeouts)) {
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }
    return hSerial;
}

comm_handle_t setup_communication(int participant_id) {
    comm_handle_t comm = {0};
    
    printf("\nSelect communication method for participant %d:\n", participant_id);
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
            scanf("%s", port_name);
            getchar();
            
            HANDLE uart_handle = setup_uart_port(port_name);
            if (uart_handle != INVALID_HANDLE_VALUE) {
                comm.type = COMM_TYPE_UART;
                comm.uart_handle = uart_handle;
                printf("UART communication setup successful on %s\n", port_name);
            }
            break;
        }
        case 2: {
            comm = find_hid_device(VENDOR_ID, PRODUCT_ID);
            if (comm.type == COMM_TYPE_USB_HID) {
                printf("USB HID communication setup successful\n");
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

int main(void) {
    printf("=== Starting FROST Key Generation and Distribution ===\n\n");

    /* Initialization */
    secp256k1_context *ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[N];
    secp256k1_frost_keypair keypairs[N];
    secp256k1_frost_pubkey public_keys[N];
    int return_val;

    /* Create context */
    printf("Initializing context...\n");
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("Failed to create context!\n");
        return 1;
    }
    printf("Context created successfully.\n");

    /* Key generation */
    printf("\nGenerating dealer commitments...\n");
    dealer_commitments = secp256k1_frost_vss_commitments_create(T);
    if (!dealer_commitments) {
        printf("Failed to create commitments!\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("Dealer commitments created.\n");

    printf("\nRunning keygen_with_dealer...\n");
    return_val = secp256k1_frost_keygen_with_dealer(
        ctx,
        dealer_commitments,
        shares_by_participant,
        keypairs,
        N,
        T
    );
    if (return_val != 1) {
        printf("Key generation failed!\n");
        secp256k1_frost_vss_commitments_destroy(dealer_commitments);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("Key generation succeeded.\n");

    /* Extract public keys from keypairs */
    for (int i = 0; i < N; i++) {
        secp256k1_frost_pubkey_from_keypair(&public_keys[i], &keypairs[i]);
    }

    /* Print keys and shares (for debugging) */
    printf("\n=== Participants ===\n\n");
    for (int i = 0; i < N; i++) {
        printf("Participant %d:\n", i + 1);
        printf("  Receiver Index: %u\n", shares_by_participant[i].receiver_index);
        print_hex("  Secret Share", shares_by_participant[i].value, 32);
        print_hex("  Public Key", keypairs[i].public_keys.public_key, 64);
        print_hex("  Group Public Key", keypairs[i].public_keys.group_public_key, 64);
        printf("\n");
    }

    /* Key distribution */
    printf("\n=== Starting Key Distribution ===\n\n");
    
    for (int i = 0; i < N; i++) {
        printf("Preparing to send data to participant %d's device...\n", i + 1);
        
        comm_handle_t comm = setup_communication(i + 1);
        if (comm.type == 0) {
            printf("Failed to set up communication for participant %d. Skipping.\n", i + 1);
            continue;
        }
        printf("Sending data to participant %d...\n", i + 1);
        
        if (!send_secret_share(&comm, i + 1, &shares_by_participant[i])) {
            printf("Failed to send secret share to participant %d.\n", i + 1);
            close_communication(&comm);
            continue;
        }
        printf("Secret share sent successfully. Waiting...\n");
        Sleep(2000);  // Increased delay
        
        if (!send_public_key(&comm, i + 1, &public_keys[i])) {
            printf("Failed to send public key to participant %d.\n", i + 1);
            close_communication(&comm);
            continue;
        }
        printf("Public key sent successfully. Waiting...\n");
        Sleep(2000);  // Increased delay
        
        if (!send_commitments(&comm, i + 1, dealer_commitments)) {
            printf("Failed to send commitments to participant %d.\n", i + 1);
            close_communication(&comm);
            continue;
        }
        printf("Commitments sent successfully. Waiting before end transmission...\n");
        Sleep(3000);  // Longer delay before end transmission
        
        // Try sending end transmission multiple times if it fails
        int retry_count = 0;
        bool end_sent = false;
        while (retry_count < 3 && !end_sent) {
            printf("Attempting to send end transmission (attempt %d/3)...\n", retry_count + 1);
            if (send_end_transmission(&comm, i + 1)) {
                printf("End transmission sent successfully.\n");
                end_sent = true;
            } else {
                printf("End transmission failed (attempt %d/3). Retrying...\n", retry_count + 1);
                retry_count++;
                Sleep(1000);  // Wait before retry
            }
        }
        
        if (!end_sent) {
            printf("Warning: Could not send end transmission after 3 attempts.\n");
            printf("Participant %d should still have received all key data.\n", i + 1);
        }
        
        printf("Successfully sent all data to participant %d.\n", i + 1);
        close_communication(&comm);
        Sleep(2000);
    }
    
    printf("\n=== Key Distribution Completed ===\n");
    
    /* Cleanup */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    secp256k1_context_destroy(ctx);
    return 0;
}