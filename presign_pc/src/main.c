#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <windows.h>

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
    MSG_TYPE_END_TRANSMISSION = 0xFF
} message_type_t;

// Header for each message in our protocol
typedef struct {
    uint32_t magic;        // Magic number to identify our protocol
    uint8_t version;       // Protocol version
    uint8_t msg_type;      // Type of message
    uint16_t payload_len;  // Length of payload following the header
    uint32_t participant;  // Participant ID (1-based)
} __attribute__((packed)) message_header_t;

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
    
    // Send payload (if any)
    if (payload_len > 0) {
        if (!WriteFile(hSerial, payload, payload_len, &bytes_written, NULL) || 
            bytes_written != payload_len) {
            printf("Failed to send payload. Error: %lu\n", GetLastError());
            return FALSE;
        }
    }
    
    return TRUE;
}

// Function to send a secret share to a participant
BOOL send_secret_share(HANDLE hSerial, uint32_t participant, 
                       const secp256k1_frost_keygen_secret_share *share) {
    // Structure to hold just the serialized data from the secret share
    typedef struct {
        uint32_t receiver_index;
        uint8_t value[32];
    } __attribute__((packed)) serialized_share_t;
    
    serialized_share_t serialized;
    serialized.receiver_index = share->receiver_index;
    memcpy(serialized.value, share->value, sizeof(serialized.value));
    
    return send_message(hSerial, MSG_TYPE_SECRET_SHARE, participant,
                       &serialized, sizeof(serialized));
}

// Function to send public key data to a participant
BOOL send_public_key(HANDLE hSerial, uint32_t participant, 
                    const secp256k1_frost_pubkey *pubkey) {
    // Structure to hold just the serialized data from the public key
    typedef struct {
        uint32_t index;
        uint32_t max_participants;
        uint8_t public_key[64];
        uint8_t group_public_key[33];
    } __attribute__((packed)) serialized_pubkey_t;
    
    serialized_pubkey_t serialized;
    serialized.index = pubkey->index;
    serialized.max_participants = pubkey->max_participants;
    memcpy(serialized.public_key, pubkey->public_key, sizeof(serialized.public_key));
    memcpy(serialized.group_public_key, pubkey->group_public_key, sizeof(serialized.group_public_key));
    
    return send_message(hSerial, MSG_TYPE_PUBLIC_KEY, participant,
                       &serialized, sizeof(serialized));
}

// Function to send commitment data to a participant
BOOL send_commitments(HANDLE hSerial, uint32_t participant, 
                     const secp256k1_frost_vss_commitments *commitments) {
    // Calculate size needed for the serialized data
    size_t coef_data_size = commitments->num_coefficients * sizeof(secp256k1_frost_vss_commitment);
    size_t total_size = sizeof(uint32_t) * 2 + sizeof(uint8_t) * 32 + sizeof(uint8_t) * 64 + coef_data_size;
    
    // Allocate buffer for serialized data
    uint8_t *buffer = (uint8_t*)malloc(total_size);
    if (!buffer) {
        printf("Memory allocation failed\n");
        return FALSE;
    }
    
    // Fill the buffer with serialized data
    uint8_t *ptr = buffer;
    
    // index and num_coefficients
    memcpy(ptr, &commitments->index, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, &commitments->num_coefficients, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    
    // zkp_z and zkp_r
    memcpy(ptr, commitments->zkp_z, 32);
    ptr += 32;
    memcpy(ptr, commitments->zkp_r, 64);
    ptr += 64;
    
    // coefficient_commitments
    memcpy(ptr, commitments->coefficient_commitments, coef_data_size);
    
    // Send the message
    BOOL result = send_message(hSerial, MSG_TYPE_COMMITMENTS, participant,
                              buffer, (uint16_t)total_size);
    
    // Free buffer
    free(buffer);
    return result;
}

// Function to signal end of transmission
BOOL send_end_transmission(HANDLE hSerial, uint32_t participant) {
    return send_message(hSerial, MSG_TYPE_END_TRANSMISSION, participant, NULL, 0);
}

// Function to open and configure the serial port
HANDLE setup_serial_port(const char *port_name) {
    HANDLE hSerial = CreateFile(port_name,
        GENERIC_WRITE,
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
    timeouts.ReadTotalTimeoutConstant = 50;
    timeouts.ReadTotalTimeoutMultiplier = 10;
    timeouts.WriteTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutMultiplier = 10;
    
    if (!SetCommTimeouts(hSerial, &timeouts)) {
        printf("Error setting timeouts\n");
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }
    
    return hSerial;
}

int main(void) {
    printf("=== Starting FROST Key Generation and Distribution ===\n\n");
    
    /* Initialization */
    secp256k1_context *ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[N];
    secp256k1_frost_keypair keypairs[N];
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
    
    /* Print keys and shares (for debugging) */
    printf("\n=== Participants ===\n\n");
    for (int i = 0; i < N; i++) {
        printf("Participant %d:\n", i + 1);
        printf("  Receiver Index: %u\n", shares_by_participant[i].receiver_index);
        print_hex("  Secret Share", shares_by_participant[i].value, 32);
        print_hex("  Public Key", keypairs[i].public_keys.public_key, 64);
        print_hex("  Group Public Key", keypairs[i].public_keys.group_public_key, 33);
        printf("\n");
    }
    
    /* Key distribution */
    printf("\n=== Starting Key Distribution ===\n\n");
    for (int i = 0; i < N; i++) {
        printf("Preparing to send data to participant %d's device...\n", i + 1);
        printf("Connect the device and enter COM port (e.g., COM4): ");
        char port_name[10];
        scanf("%s", port_name);
        getchar(); // Consume newline
        
        HANDLE hSerial = setup_serial_port(port_name);
        if (hSerial == INVALID_HANDLE_VALUE) {
            printf("Failed to set up serial port. Skipping participant %d.\n", i + 1);
            continue;
        }
        
        printf("Sending data to participant %d via %s...\n", i + 1, port_name);
        
        // Send the secret share
        if (!send_secret_share(hSerial, i + 1, &shares_by_participant[i])) {
            printf("Failed to send secret share to participant %d.\n", i + 1);
            CloseHandle(hSerial);
            continue;
        }
        
        // Send the public key
        if (!send_public_key(hSerial, i + 1, &keypairs[i].public_keys)) {
            printf("Failed to send public key to participant %d.\n", i + 1);
            CloseHandle(hSerial);
            continue;
        }
        
        // Send the commitments
        if (!send_commitments(hSerial, i + 1, dealer_commitments)) {
            printf("Failed to send commitments to participant %d.\n", i + 1);
            CloseHandle(hSerial);
            continue;
        }
        
        // Signal end of transmission
        if (!send_end_transmission(hSerial, i + 1)) {
            printf("Failed to send end transmission to participant %d.\n", i + 1);
            CloseHandle(hSerial);
            continue;
        }
        
        printf("Successfully sent all data to participant %d.\n", i + 1);
        CloseHandle(hSerial);
    }
    
    printf("\n=== Key Distribution Completed ===\n");
    
    /* Cleanup */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    secp256k1_context_destroy(ctx);
    
    return 0;
}