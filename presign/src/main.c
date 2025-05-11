#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

/*
THIS FILE HAS BEEN COMPILED IN A WINDOWS COMPUTER IN A MSYS2 TERMINAL 
gcc -g main.c -lsecp256k1 -o main.exe
./main.exe
USING THE LIBRARY https://github.com/bancaditalia/secp256k1-frost BUILDING IT AS EXPLAINED IN THE README WITH AUTOTOOLS
*/

#include <secp256k1.h>
#include <secp256k1_frost.h>

//#include "secp256k1-frost/examples/examples_util.h"

#include <windows.h>

#define N 3 // Number of participants
#define T 2 // Threshold of needed participants

// Helper function to print hex data (e.g., public keys)
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void print_secret_share(const secp256k1_frost_keygen_secret_share *share) {
    printf("  Receiver Index: %u\n", share->receiver_index);
    print_hex("  Secret Share", share->value, sizeof(share->value));
}

int main(void) {
    printf("=== Starting FROST Presigning proccess ===\n");
    printf("\n");

    unsigned char msg[12] = "Hello World!";
    unsigned char msg_hash[32];
    unsigned char tag[14] = "frost_protocol";
    uint32_t index;
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    unsigned char signature[64];
    int is_signature_valid;
    int return_val;

    /* context used to sign and verify signatures */
    secp256k1_context *sign_verify_ctx;

    /* Use of a centralized trusted dealer to generate keys */
    // Creation of a structure to store the things required for the scheme
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[N];
    /* keypairs stores private and public keys for each participant */
    secp256k1_frost_keypair keypairs[N];
    /* public_keys stores only public keys for each participant (this info can/should be shared among signers) */
    secp256k1_frost_pubkey public_keys[N];

    /*** INITIALIZATION OF CONTEXT ***/
    printf("Initializing context...\n");
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!sign_verify_ctx) {
        printf("Failed to create context!\n");
        return 1;
    }
    printf("Context created successfully.\n");

    /*** KEY GENERATION ***/

    /*
    SECP256K1_API secp256k1_frost_vss_commitments *secp256k1_frost_vss_commitments_create(uint32_t threshold) {
    uint32_t num_coefficients;
    secp256k1_frost_vss_commitments *vss;
    if (threshold < 1) { // Need to at least have one participating device
        return NULL;
    }
    num_coefficients = threshold - 1; // The polynomial degree is t-1
    vss = (secp256k1_frost_vss_commitments *) checked_malloc(&default_error_callback,
                                                             sizeof(secp256k1_frost_vss_commitments));
    vss->index = 0;
    memset(vss->zkp_z, 0, SCALAR_SIZE);
    memset(vss->zkp_r, 0, 64);

    vss->num_coefficients = num_coefficients + 1;
    vss->coefficient_commitments = (secp256k1_frost_vss_commitment *)
            checked_malloc(&default_error_callback, (num_coefficients + 1) * sizeof(secp256k1_frost_vss_commitment));
    return vss; //The function returns the coefficient commitments
    */

    printf("\nGenerating dealer commitments...\n");
    dealer_commitments = secp256k1_frost_vss_commitments_create(T);
    if (!dealer_commitments) {
        printf("Failed to create commitments!\n");
        return 1;
    }
    printf("Dealer commitments created.\n");

    /*
    SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_keygen_with_dealer(
        const secp256k1_context *ctx,
        secp256k1_frost_vss_commitments *share_commitment,
        secp256k1_frost_keygen_secret_share *shares,
        secp256k1_frost_keypair *keypairs,
        uint32_t num_participants,
        uint32_t threshold) {

        secp256k1_scalar secret; // The secret from which the shares are generated
        secp256k1_gej group_public_key;
        uint32_t generator_index, index;

        if (ctx == NULL || share_commitment == NULL || shares == NULL || keypairs == NULL) { // Checking not NULL
        return 0;
        }

        // We use generator_index=0 as we are generating shares with a dealer, we only use one generator point
        generator_index = 0;

        //Parameter checking
        if (threshold < 1 || num_participants < 1 || threshold > num_participants) { // We should have at least two participants and the threshold should be less than the total number of possible participants
        return 0;
        }

        //Initialization
        share_commitment->index = generator_index;
        if (initialize_random_scalar(&secret) == 0) { // Generating a random scalar as the secret to share
            return 0;
        }

        // Scalar mulipliation on the elliptic curve using the context, the secret as the scalar to multiply the generator point and the group public key as the result
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &group_public_key, &secret); // he generator point is defined within the secp256k1 library and is part of the precomputed tables used for efficient scalar multiplication. The ctx->initial field in the secp256k1_ecmult_gen_context structure typically contains the generator point G

        //Generate shares
        if (generate_shares(ctx, share_commitment, shares, num_participants, // This generates the shares using Shamir's secret sharing using the context, the commitments, the shares, the number of participants, the threshold, the generator index and the secret, and the threshold. It does this by generating the corresponding polynomial and evaluating it
                        threshold, generator_index, &secret) == 0) {
        return 0;
        }

        // Preparing output
        for (index = 0; index < num_participants; index++) { // Looping through the participants
            secp256k1_scalar share_value; // Correspoding share
            secp256k1_gej pubkey; // Jacobian elliptic curve point to store the public key

            secp256k1_scalar_set_b32(&share_value, shares[index].value, NULL); // Setting the share value
            secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pubkey, &share_value); // Scalar multiplication on the elliptic curve using the context, the share value as the scalar to multiply the generator point and the public key as the result
            serialize_point(&pubkey, keypairs[index].public_keys.public_key); // Serializing the elliptic curve point public key into a byte array

            memcpy(&keypairs[index].secret, &shares[index].value, SCALAR_SIZE); // Copying the share value into the secret of the keypair
            serialize_point(&group_public_key, keypairs[index].public_keys.group_public_key); // Serializing the elliptic curve point group public key into a byte array
            keypairs[index].public_keys.index = shares[index].receiver_index; // Setting the index of the public keys
            keypairs[index].public_keys.max_participants = num_participants; // Setting the maximum number of participants, which is N
        }
    return 1;
    }
    */

    printf("\nRunning keygen_with_dealer...\n");
    return_val = secp256k1_frost_keygen_with_dealer( // This generates the keypairs, containing the corresponding share and public key for each participant
        sign_verify_ctx, 
        dealer_commitments,
        shares_by_participant, 
        keypairs, 
        N, 
        T
    );
    if (return_val != 1) {
        return 1;
    }
    printf("Key generation succeeded.\n");

    // Print shares and public keys for all participants
    printf("\n=== Participants ===\n");
    printf("\n");
    for (int i = 0; i < N; i++) {
        printf("Participant %d:\n", i + 1);

        // Print secret share
        print_secret_share(&shares_by_participant[i]);

        // Print public key
        print_hex("  Group Public Key", keypairs[i].public_keys.group_public_key, 33);
        print_hex("  Public Key", keypairs[i].public_keys.public_key, sizeof(keypairs[i].public_keys.public_key));

        // Print public key metadata (if available)
        printf("  Public Key Index: %u\n", keypairs[i].public_keys.index);
        printf("  Max Participants: %u\n", keypairs[i].public_keys.max_participants);
    }

    printf("\n=== Generation Completed Successfully ===\n");
    printf("\n");

/* KEY DISTRIBUTION */
    printf("\n=== Starting Key Distribution ===\n");
    printf("\n");

    for (int i = 0; i < N; i++) {
        printf("Sending data to participant %d's device...\n", i + 1);
        printf("Connect the device and press Enter...");
        getchar(); // Wait for user to connect each device sequentially
    
        HANDLE hSerial = CreateFile("COM4", // Change this value depending on the port that is going to be used for the communication
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    
        if (hSerial == INVALID_HANDLE_VALUE) {
            printf("Failed to open COM port. Error: %lu\n", GetLastError());
            return 1;
        }
    
        // Configure serial port settings
        DCB dcbSerialParams = {0};
        dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
        if (!GetCommState(hSerial, &dcbSerialParams)) {
            printf("Error getting port state\n");
            CloseHandle(hSerial);
            return 1;
        }
    
        dcbSerialParams.BaudRate = CBR_115200;
        dcbSerialParams.ByteSize = 8;
        dcbSerialParams.StopBits = ONESTOPBIT;
        dcbSerialParams.Parity = NOPARITY;
    
        if (!SetCommState(hSerial, &dcbSerialParams)) {
            printf("Error setting port state\n");
            CloseHandle(hSerial);
            return 1;
        }
    
        // Prepare data structure (packed for binary transmission)
        #pragma pack(push, 1)
        typedef struct {
            uint32_t receiver_index;
            uint8_t secret_share[32];
            uint8_t public_key[64];
            uint8_t group_public_key[33];
            uint32_t key_index;
            uint32_t max_participants;
        } ParticipantData;
        #pragma pack(pop)

        #pragma pack(push, 1)
        typedef struct {
            uint32_t index;
            uint32_t num_coefficients;
            uint8_t zkp_z[32];
            uint8_t zkp_r[64];
            uint8_t coefficients[T][33]; // T is the threshold
        } DealerCommitmentsData;
        #pragma pack(pop)
    
        ParticipantData data;
        data.receiver_index = shares_by_participant[i].receiver_index;
        memcpy(data.secret_share, shares_by_participant[i].value, 32);
        memcpy(data.public_key, keypairs[i].public_keys.public_key, 64);
        memcpy(data.group_public_key, keypairs[i].public_keys.group_public_key, 33);
        data.key_index = keypairs[i].public_keys.index;
        data.max_participants = keypairs[i].public_keys.max_participants;

        printf("Sending dealer commitments...\n");
        DealerCommitmentsData d_data;
        d_data.index = dealer_commitments->index;
        d_data.num_coefficients = dealer_commitments->num_coefficients;
        memcpy(d_data.zkp_z, dealer_commitments->zkp_z, 32);
        memcpy(d_data.zkp_r, dealer_commitments->zkp_r, 64);
        for (uint32_t j = 0; j < T; j++) {
            memcpy(d_data.coefficients[j], dealer_commitments->coefficient_commitments[j].data, 33);
        }

        // Send it over serial
        DWORD bytesWritten;
        WriteFile(hSerial, &d_data, sizeof(d_data), &bytesWritten, NULL);
        CloseHandle(hSerial);
        printf("Dealer commitments sent.\n");
    
        // Send data
        if (!WriteFile(hSerial, &data, sizeof(data), &bytesWritten, NULL)) {
            printf("Write failed. Error: %lu\n", GetLastError());
            CloseHandle(hSerial);
            return 1;
        }
    
        if (bytesWritten != sizeof(data)) {
            printf("Partial write: %lu/%zu bytes\n", bytesWritten, sizeof(data));
            CloseHandle(hSerial);
            return 1;
        }
    
        printf("Successfully sent data to participant %d\n", i + 1);
        CloseHandle(hSerial);
    }
    
    printf("\n=== Key Distribution Completed ===\n");
     
    // Cleanup
    secp256k1_context_destroy(sign_verify_ctx);
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    
    return 0;
}