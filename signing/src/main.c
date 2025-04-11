#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h> 
#include <zephyr/logging/log.h>

#include <secp256k1.h>
#include <secp256k1_frost.h>

#define N 3 
#define T 2

LOG_MODULE_REGISTER(uart_receiver, LOG_LEVEL_INF);

int main(void) {

    LOG_INF("System initialized");

    unsigned char msg[12] = "Hello World!";
    unsigned char msg_hash[32];
    unsigned char tag[14] = "frost_protocol";
    uint32_t index;
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    unsigned char signature[64];
    int is_signature_valid;
    int return_val;

    secp256k1_context *sign_verify_ctx;

    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[N];
    secp256k1_frost_keypair keypairs[N];
    secp256k1_frost_pubkey public_keys[N];
    secp256k1_frost_signature_share signature_shares[N];
    secp256k1_frost_nonce *nonces[N];
    secp256k1_frost_nonce_commitment signing_commitments[N];

    LOG_INF("Initializing context...\n");
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!sign_verify_ctx) {
        printf("Failed to create context!\n");
        return 1;
    }
    LOG_INF("Context created successfully.\n");
}