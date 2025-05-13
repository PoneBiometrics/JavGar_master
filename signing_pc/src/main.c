#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <windows.h>
#include <stdbool.h>

#define N 3 // Number of participants
#define T 2 // Threshold of needed participants

// Helper function to print hex data
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Constants for message protocol
#define MSG_HEADER_MAGIC 0x46524F53 // "FROS" as hex
#define MSG_VERSION 0x01

// Message types for our protocol
typedef enum {
    MSG_TYPE_SECRET_SHARE = 0x01,
    MSG_TYPE_PUBLIC_KEY = 0x02,
    MSG_TYPE_COMMITMENTS = 0x03,
    MSG_TYPE_NONCE_COMMITMENT = 0x04,  
    MSG_TYPE_ALL_NONCE_COMMITMENTS = 0x05,  
    MSG_TYPE_END_TRANSMISSION = 0xFF
} message_type_t;

// Header for each message in our protocol
typedef struct {
    uint32_t magic;        // Magic number to identify our protocol
    uint8_t version;       // Protocol version
    uint8_t msg_type;      // Type of message
    uint16_t payload_len;  // Length of payload following the header
    uint32_t participant;  // Participant ID 
} __attribute__((packed)) message_header_t;

// Nonce commitment structure 
typedef struct {
    uint32_t participant_index;
    uint8_t hiding[32];     
    uint8_t binding[32];    
} __attribute__((packed)) serialized_nonce_commitment_t;

// Structure for all nonce commitments to be sent to boards
typedef struct {
    uint32_t num_commitments;  
    serialized_nonce_commitment_t commitments[N];  // Array of all commitments
} __attribute__((packed)) all_nonce_commitments_t;

// Function to send a message with header and payload
BOOL send_message(HANDLE hSerial, uint8_t msg_type, uint32_t participant, 
                  const void* payload, uint16_t payload_len) {
    DWORD bytes_written;
    message_header_t header;
    
    // Fill header
    header.magic = MSG_HEADER_MAGIC;
    header.version = MSG_VERSION;
    header.msg_type = msg_type;
    header.payload_len = payload_len;
    header.participant = participant;
    
    // Send header
    if (!WriteFile(hSerial, &header, sizeof(header), &bytes_written, NULL) || 
        bytes_written != sizeof(header)) {
        printf("Failed to send header. Error: %lu\n", GetLastError());
        return FALSE;
    }
    
    // Send payload
    if (payload_len > 0) {
        if (!WriteFile(hSerial, payload, payload_len, &bytes_written, NULL) || 
            bytes_written != payload_len) {
            printf("Failed to send payload. Error: %lu\n", GetLastError());
            return FALSE;
        }
    }
    
    return TRUE;
}

// Function to receive a message header
BOOL receive_header(HANDLE hSerial, message_header_t *header) {
    DWORD bytes_read;
    
    // Read header
    if (!ReadFile(hSerial, header, sizeof(message_header_t), &bytes_read, NULL) || 
        bytes_read != sizeof(message_header_t)) {
        printf("Failed to read header. Error: %lu\n", GetLastError());
        return FALSE;
    }
    
    // Check magic number
    if (header->magic != MSG_HEADER_MAGIC) {
        printf("Invalid message header. Magic number mismatch.\n");
        return FALSE;
    }
    
    // Check version
    if (header->version != MSG_VERSION) {
        printf("Unsupported protocol version: %d\n", header->version);
        return FALSE;
    }
    
    return TRUE;
}

// Function to receive a nonce commitment
BOOL receive_nonce_commitment(HANDLE hSerial, message_header_t *header, 
                              serialized_nonce_commitment_t *commitment) {
    DWORD bytes_read;
    
    // Verify payload length
    if (header->payload_len != sizeof(serialized_nonce_commitment_t)) {
        printf("Invalid payload length for nonce commitment: %d\n", header->payload_len);
        return FALSE;
    }
    
    // Read commitment data
    if (!ReadFile(hSerial, commitment, sizeof(serialized_nonce_commitment_t), 
                  &bytes_read, NULL) || 
        bytes_read != sizeof(serialized_nonce_commitment_t)) {
        printf("Failed to read nonce commitment. Error: %lu\n", GetLastError());
        return FALSE;
    }
    
    return TRUE;
}

// Function to open and configure the serial port
HANDLE setup_serial_port(const char *port_name) {
    HANDLE hSerial = CreateFile(port_name,
        GENERIC_READ | GENERIC_WRITE,  // Need read and write permission
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    
    if (hSerial == INVALID_HANDLE_VALUE) {
        printf("Failed to open COM port %s. Error: %lu\n", port_name, GetLastError());
        return INVALID_HANDLE_VALUE;
    }
    
    // Configure serial port settings
    DCB dcbSerialParams = {0};
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
    if (!GetCommState(hSerial, &dcbSerialParams)) {
        printf("Error getting port state\n");
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }
    
    dcbSerialParams.BaudRate = CBR_115200;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;
    
    if (!SetCommState(hSerial, &dcbSerialParams)) {
        printf("Error setting port state\n");
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }
    
    // Set timeouts
    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 50;
    timeouts.ReadTotalTimeoutConstant = 2000;  // Increased timeout for reading
    timeouts.ReadTotalTimeoutMultiplier = 10;
    timeouts.WriteTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutMultiplier = 10;
    
    if (!SetCommTimeouts(hSerial, &timeouts)) {
        printf("Error setting timeouts\n");
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }
    
    // Purge any existing data in buffers
    if (!PurgeComm(hSerial, PURGE_RXCLEAR | PURGE_TXCLEAR)) {
        printf("Error purging comm port\n");
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }
    
    return hSerial;
}

// Function to discard any existing bytes in the buffer
void flush_serial(HANDLE hSerial) {
    PurgeComm(hSerial, PURGE_RXCLEAR | PURGE_TXCLEAR);
}

// Function to read a specific number of bytes with timeout
BOOL read_exact_bytes(HANDLE hSerial, void *buffer, DWORD size, DWORD *bytes_read) {
    DWORD total_read = 0;
    DWORD bytes_read_now;
    char *buf = (char*)buffer;
    
    while (total_read < size) {
        if (!ReadFile(hSerial, buf + total_read, size - total_read, &bytes_read_now, NULL)) {
            printf("Read failed. Error: %lu\n", GetLastError());
            *bytes_read = total_read;
            return FALSE;
        }
        
        if (bytes_read_now == 0) {
            // Timeout occurred
            printf("Read timeout. Read %lu of %lu bytes.\n", total_read, size);
            *bytes_read = total_read;
            return FALSE;
        }
        
        total_read += bytes_read_now;
    }
    
    *bytes_read = total_read;
    return TRUE;
}

// Function to receive nonce commitments from a board
BOOL receive_nonce_commitments_from_board(HANDLE hSerial, 
                                         serialized_nonce_commitment_t *commitment) {
    message_header_t header;
    BOOL result = FALSE;
    DWORD bytes_read;
    
    while (1) {
        // Read header
        printf("Waiting for message...\n");
        if (!receive_header(hSerial, &header)) {
            printf("Failed to receive header. Retrying...\n");
            Sleep(1000);  // Wait a bit before retrying
            continue;
        }
        
        printf("Received message: Type=%d, Length=%d, Participant=%d\n", 
               header.msg_type, header.payload_len, header.participant);
        
        // Process based on message type
        if (header.msg_type == MSG_TYPE_NONCE_COMMITMENT) {
            if (!receive_nonce_commitment(hSerial, &header, commitment)) {
                printf("Failed to receive nonce commitment\n");
                return FALSE;
            }
            
            printf("Received Nonce Commitment from Participant %d\n", commitment->participant_index);
            print_hex("  Hiding Commitment", commitment->hiding, sizeof(commitment->hiding));
            print_hex("  Binding Commitment", commitment->binding, sizeof(commitment->binding));
            
            result = TRUE;
            break;
        } else if (header.msg_type == MSG_TYPE_END_TRANSMISSION) {
            printf("End of transmission received from Participant %d\n", header.participant);
            return FALSE;
        } else {
            // Skip unknown payload data
            if (header.payload_len > 0) {
                printf("Unknown message type %d. Skipping %d bytes of payload\n", 
                       header.msg_type, header.payload_len);
                
                // Allocate buffer for unknown payload
                uint8_t *buffer = (uint8_t*)malloc(header.payload_len);
                if (!buffer) {
                    printf("Memory allocation failed\n");
                    return FALSE;
                }
                
                // Read and discard payload
                result = read_exact_bytes(hSerial, buffer, header.payload_len, &bytes_read);
                free(buffer);
                
                if (!result) {
                    printf("Failed to skip payload for unknown message type\n");
                    return FALSE;
                }
            }
        }
    }
    
    return result;
}

// Function to send all nonce commitments to a board
BOOL send_all_nonce_commitments(HANDLE hSerial, uint32_t participant_id,
                               all_nonce_commitments_t *all_commitments) {
    return send_message(hSerial, MSG_TYPE_ALL_NONCE_COMMITMENTS, participant_id,
                       all_commitments, sizeof(all_nonce_commitments_t));
}

// Structure to hold board communication handles and participant IDs
typedef struct {
    HANDLE serial_handle;
    uint32_t participant_id;
    char port_name[10];
} board_connection_t;

int main(void) {
    printf("=== FROST Nonce Commitment Coordinator ===\n\n");
    
    // Array to store board connections
    board_connection_t boards[N];
    int active_boards = 0;
    
    // Collect port names for all boards
    for (int i = 0; i < N; i++) {
        printf("Enter COM port for board %d (e.g., COM4) or leave empty to skip: ", i+1);
        char port_name[10];
        fgets(port_name, sizeof(port_name), stdin);
        
        // Remove newline character if present
        size_t len = strlen(port_name);
        if (len > 0 && port_name[len-1] == '\n') {
            port_name[len-1] = '\0';
            len--;
        }
        
        // Skip if empty
        if (len == 0) {
            printf("Skipping board %d\n", i+1);
            continue;
        }
        
        // Copy port name
        strncpy(boards[active_boards].port_name, port_name, sizeof(boards[active_boards].port_name));
        boards[active_boards].participant_id = i+1;  
        active_boards++;
    }
    
    // Check if we have enough boards
    if (active_boards < T) {
        printf("Error: Need at least %d boards, but only %d provided.\n", T, active_boards);
        return 1;
    }
    
    // Open serial ports for each active board
    for (int i = 0; i < active_boards; i++) {
        boards[i].serial_handle = setup_serial_port(boards[i].port_name);
        if (boards[i].serial_handle == INVALID_HANDLE_VALUE) {
            printf("Failed to set up serial port %s for board %d.\n", 
                   boards[i].port_name, boards[i].participant_id);
            
            // Close previously opened ports
            for (int j = 0; j < i; j++) {
                CloseHandle(boards[j].serial_handle);
            }
            return 1;
        }
        
        // Flush any existing data
        flush_serial(boards[i].serial_handle);
    }
    
    printf("\nPress Enter to begin receiving nonce commitments...\n");
    getchar();
    
    // Prepare data structure to collect all nonce commitments
    all_nonce_commitments_t all_commitments;
    all_commitments.num_commitments = 0;
    
    // Receive nonce commitments from T boards
    int commitments_received = 0;
    for (int i = 0; i < active_boards && commitments_received < T; i++) {
        printf("\nReceiving nonce commitment from board %d (Participant %d)...\n", 
               i+1, boards[i].participant_id);
        
        if (receive_nonce_commitments_from_board(boards[i].serial_handle, 
                                              &all_commitments.commitments[commitments_received])) {
            commitments_received++;
            all_commitments.num_commitments = commitments_received;
            
            printf("Successfully received nonce commitment (%d of %d needed)\n", 
                   commitments_received, T);
        } else {
            printf("Failed to receive nonce commitment from board %d\n", i+1);
        }
    }
    
    // Check if we received enough commitments
    if (commitments_received < T) {
        printf("\nError: Received only %d nonce commitments, but need at least %d.\n", 
               commitments_received, T);
        
        // Close all serial ports
        for (int i = 0; i < active_boards; i++) {
            CloseHandle(boards[i].serial_handle);
        }
        return 1;
    }
    
    printf("\nSuccessfully received %d nonce commitments.\n", commitments_received);
    
    // Copy commitments into secp256k1_frost_nonce_commitment format
    printf("\nCopying commitments to secp256k1_frost_nonce_commitment format...\n");
    
    // Set up the frost nonce array and signing commitments
    secp256k1_frost_nonce_commitment signing_commitments[N];
    
    // Initialize the signing_commitments array to zeros
    memset(signing_commitments, 0, sizeof(signing_commitments));
    
    // Copy received commitments into the signing_commitments array
    for (int i = 0; i < commitments_received; i++) {
        uint32_t index = all_commitments.commitments[i].participant_index - 1;
        
        // Create a frost nonce commitment from the serialized data
        secp256k1_frost_nonce_commitment commitment;
        
        // Copy hiding and binding values to the nonce commitment structure
        memcpy(commitment.hiding, all_commitments.commitments[i].hiding, 32);
        memcpy(commitment.binding, all_commitments.commitments[i].binding, 32);
        
        // Store in the signing_commitments array
        memcpy(&signing_commitments[index], &commitment, sizeof(secp256k1_frost_nonce_commitment));
        
        printf("Processed commitment %d for participant %d\n", i+1, index+1);
    }
    
    printf("\nNow sending all collected nonce commitments to each board...\n");
    
    // Send all nonce commitments to each board
    for (int i = 0; i < active_boards; i++) {
        printf("Sending all nonce commitments to board %d (Participant %d)...\n", 
               i+1, boards[i].participant_id);
        
        if (send_all_nonce_commitments(boards[i].serial_handle, boards[i].participant_id, 
                                     &all_commitments)) {
            printf("Successfully sent all nonce commitments to board %d\n", i+1);
            
            // Send end transmission message
            send_message(boards[i].serial_handle, MSG_TYPE_END_TRANSMISSION, 
                       boards[i].participant_id, NULL, 0);
        } else {
            printf("Failed to send all nonce commitments to board %d\n", i+1);
        }
    }
    
    // Clean up
    for (int i = 0; i < active_boards; i++) {
        CloseHandle(boards[i].serial_handle);
    }
    
    printf("\nAll operations completed. Press Enter to exit...\n");
    getchar();
    
    return 0;
}