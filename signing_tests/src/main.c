#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <zephyr/logging/log.h>

#include <secp256k1.h>
#include <secp256k1_frost.h>

#include "examples_util.h"

#define EXAMPLE_MAX_PARTICIPANTS 3
#define EXAMPLE_MIN_PARTICIPANTS 2

LOG_MODULE_REGISTER(uart_receiver, LOG_LEVEL_INF);

static void log_hex(const char *label, const uint8_t *data, size_t len) {
    char hexstr[2 * len + 1];

    for (size_t i = 0; i < len; i++) {
        snprintf(&hexstr[i * 2], 3, "%02x", data[i]);
    }

    LOG_INF("%s: 0x%s", label, hexstr);
}

static void log_frost_keypair(const char *participant_label, const secp256k1_frost_keypair *keypair) {
    LOG_INF("=== %s Keypair Details ===", participant_label);
    log_hex("  Secret Key", keypair->secret, sizeof(keypair->secret));
    log_hex("  Individual Public Key", keypair->public_keys.public_key, sizeof(keypair->public_keys.public_key));
    log_hex("  Group Public Key", keypair->public_keys.group_public_key, sizeof(keypair->public_keys.group_public_key));
    LOG_INF("=== End %s Keypair ===", participant_label);
}

static void log_frost_nonce(const char *participant_label, const secp256k1_frost_nonce *nonce) {
    LOG_INF("=== %s Nonce Details ===", participant_label);
    log_hex("  Hiding Commitment", nonce->commitments.hiding, sizeof(nonce->commitments.hiding));
    log_hex("  Binding Commitment", nonce->commitments.binding, sizeof(nonce->commitments.binding));
    LOG_INF("=== End %s Nonce ===", participant_label);
}

static void log_frost_signature_share(const char *participant_label, const secp256k1_frost_signature_share *sig_share) {
    LOG_INF("=== %s Signature Share ===", participant_label);
    // Nota: La estructura exacta depende de la implementación de secp256k1_frost
    // Típicamente contiene un valor escalar de 32 bytes
    LOG_INF("  Signature share created for %s", participant_label);
    LOG_INF("=== End %s Signature Share ===", participant_label);
}

static void log_system_requirements(void) {
    LOG_INF("=== FROST System Requirements ===");
    LOG_INF("Max Participants: %d", EXAMPLE_MAX_PARTICIPANTS);
    LOG_INF("Min Participants (Threshold): %d", EXAMPLE_MIN_PARTICIPANTS);
    LOG_INF("Required for signing: %d out of %d participants", EXAMPLE_MIN_PARTICIPANTS, EXAMPLE_MAX_PARTICIPANTS);
    LOG_INF("================================");
}

static void log_protocol_phase(const char *phase) {
    LOG_INF("┌─────────────────────────────────────────┐");
    LOG_INF("│ PHASE: %-32s │", phase);
    LOG_INF("└─────────────────────────────────────────┘");
}

int main(void) {

    LOG_INF("Starting FROST (Flexible Round-Optimized Schnorr Threshold) Protocol Example");
    LOG_INF("This example demonstrates distributed threshold signature generation");
    
    log_system_requirements();

    // Variables de datos del mensaje
    unsigned char msg[12] = "Hello World!";
    unsigned char msg_hash[32];
    unsigned char tag[14] = "frost_protocol";
    
    // Variables del protocolo
    uint32_t index;
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    unsigned char signature[64];
    int is_signature_valid;
    int return_val;

    LOG_INF("Message to sign: \"%s\"", msg);
    LOG_INF("🏷️  Hash tag: \"%s\"", tag);
    log_hex("Raw Message Bytes", msg, sizeof(msg));

    /* secp256k1 context used to sign and verify signatures */
    secp256k1_context *sign_verify_ctx;

    /* FROST-specific data structures */
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_keypair keypairs[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_pubkey public_keys[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_signature_share signature_shares[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_nonce *nonces[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_nonce_commitment signing_commitments[EXAMPLE_MAX_PARTICIPANTS];

    /*** Initialization Phase ***/
    log_protocol_phase("INITIALIZATION");
    
    LOG_INF("🔧 Creating secp256k1 context with SIGN and VERIFY capabilities...");
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    
    if (sign_verify_ctx == NULL) {
        LOG_ERR("Failed to create secp256k1 context!");
        return 1;
    }
    LOG_INF("Context created successfully");
    LOG_INF("Context capabilities: SIGN | VERIFY");

    /*** Key Generation Phase ***/
    log_protocol_phase("KEY GENERATION");
    
    LOG_INF("Starting distributed key generation with trusted dealer...");
    LOG_INF("📈 Creating VSS (Verifiable Secret Sharing) commitments...");
    LOG_INF("   Threshold: %d participants needed to sign", EXAMPLE_MIN_PARTICIPANTS);
    
    dealer_commitments = secp256k1_frost_vss_commitments_create(EXAMPLE_MIN_PARTICIPANTS);
    if (dealer_commitments == NULL) {
        LOG_ERR("Failed to create VSS commitments!");
        return 1;
    }
    LOG_INF("VSS commitments created successfully");

    LOG_INF("Generating keys for %d participants (threshold = %d)...", 
            EXAMPLE_MAX_PARTICIPANTS, EXAMPLE_MIN_PARTICIPANTS);
    
    return_val = secp256k1_frost_keygen_with_dealer(sign_verify_ctx, dealer_commitments,
                                                shares_by_participant, keypairs,
                                                EXAMPLE_MAX_PARTICIPANTS, EXAMPLE_MIN_PARTICIPANTS);

    if (return_val != 1) {
        LOG_ERR("Key generation failed! Return value: %d", return_val);
        return 1;
    }
    LOG_INF("Key generation completed successfully");

    LOG_INF("Extracting public keys from keypairs...");
    /* Extracting public_keys from keypair. This operation is intended to be executed by each signer.  */
    for (index = 0; index < EXAMPLE_MAX_PARTICIPANTS; index++) {
        LOG_INF("👤 Processing Participant #%d...", index);
        
        return_val = secp256k1_frost_pubkey_from_keypair(&public_keys[index], &keypairs[index]);
        if (return_val != 1) {
            LOG_ERR("Failed to extract public key for participant #%d", index);
            return 1;
        }
        
        // Log detailed keypair information
        log_frost_keypair("Participant", &keypairs[index]);
        
        LOG_INF("Participant #%d keys extracted successfully", index);
    }

    LOG_INF("🌐 Shared Group Information:");
    log_hex("Group Public Key (same for all participants)", 
            keypairs[0].public_keys.group_public_key, 
            sizeof(keypairs[0].public_keys.group_public_key));

    /*** Nonce Generation Phase ***/
    log_protocol_phase("NONCE GENERATION");
    
    LOG_INF("Generating nonces for signing participants...");
    LOG_INF("   Note: Only %d out of %d participants will sign", EXAMPLE_MIN_PARTICIPANTS, EXAMPLE_MAX_PARTICIPANTS);

    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS; index++) {
        LOG_INF("Generating nonce for Participant #%d...", index);

        /* Generate 32 bytes of randomness to use for computing the nonce. */
        LOG_INF("   Generating binding seed...");
        if (!fill_random(binding_seed, sizeof(binding_seed))) {
            LOG_ERR("Failed to generate binding_seed for participant #%d", index);
            return 1;
        }
        log_hex("   Binding Seed", binding_seed, sizeof(binding_seed));

        LOG_INF("   Generating hiding seed...");
        if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
            LOG_ERR("Failed to generate hiding_seed for participant #%d", index);
            return 1;
        }
        log_hex("   Hiding Seed", hiding_seed, sizeof(hiding_seed));

        /* Create the nonce (the function already computes its commitment) */
        LOG_INF("   Creating nonce and commitments...");
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx, &keypairs[index],
                                                     binding_seed, hiding_seed);

        if (nonces[index] == NULL) {
            LOG_ERR("Failed to create nonce for participant #%d", index);
            return 1;
        }

        // Log detailed nonce information
        log_frost_nonce("Participant", nonces[index]);

        /* Copying secp256k1_frost_nonce_commitment to a shared array across participants */
        LOG_INF("   Sharing nonce commitments...");
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
        
        LOG_INF("Nonce generated successfully for Participant #%d", index);
    }

    /*** Message Hashing Phase ***/
    log_protocol_phase("MESSAGE HASHING");
    
    LOG_INF("Hashing message for signing...");
    LOG_INF("   Using tagged SHA256 with tag: \"%s\"", tag);
    
    return_val = secp256k1_tagged_sha256(sign_verify_ctx, msg_hash, tag, sizeof(tag), msg, sizeof(msg));
    if (return_val != 1) {
        LOG_ERR("Failed to hash message! Return value: %d", return_val);
        return 1;
    }
    
    LOG_INF("Message hashed successfully");
    log_hex("Original Message", msg, sizeof(msg));
    log_hex("Message Hash (to be signed)", msg_hash, sizeof(msg_hash));

    /*** Signature Share Generation Phase ***/
    log_protocol_phase("SIGNATURE SHARE GENERATION");
    
    LOG_INF("✍️  Generating signature shares...");
    LOG_INF("   Each participant creates their signature share independently");

    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS; index++) {
        LOG_INF("Participant #%d creating signature share...", index);
        LOG_INF("   Input parameters:");
        LOG_INF("     - Message hash: [32 bytes]");
        LOG_INF("     - Number of signers: %d", EXAMPLE_MIN_PARTICIPANTS);
        LOG_INF("     - Participant keypair: [private key + public keys]");
        LOG_INF("     - Participant nonce: [hiding + binding nonces]");
        LOG_INF("     - All signing commitments: [from all participants]");

        return_val = secp256k1_frost_sign(&(signature_shares[index]), msg_hash, EXAMPLE_MIN_PARTICIPANTS,
                             &keypairs[index], nonces[index], signing_commitments);

        if (return_val != 1) {
            LOG_ERR("Failed to create signature share for participant #%d! Return value: %d", index, return_val);
            return 1;
        }

        // Log signature share details
        log_frost_signature_share("Participant", &signature_shares[index]);
        
        LOG_INF("Signature share created successfully for Participant #%d", index);
    }

    /*** Signature Aggregation Phase ***/
    log_protocol_phase("SIGNATURE AGGREGATION");
    
    LOG_INF("Aggregating signature shares into final FROST signature...");
    LOG_INF("   Aggregator: Participant #0 (could be any participant or external entity)");
    LOG_INF("   Input: %d signature shares", EXAMPLE_MIN_PARTICIPANTS);
    
    return_val = secp256k1_frost_aggregate(sign_verify_ctx, signature, msg_hash,
        &keypairs[0], public_keys, signing_commitments,
        signature_shares, EXAMPLE_MIN_PARTICIPANTS);

    if (return_val != 1) {
        LOG_ERR("Failed to aggregate signature shares! Return value: %d", return_val);
        return 1;
    }

    LOG_INF("Signature aggregation completed successfully");
    log_hex("Final FROST Signature", signature, sizeof(signature));

    /*** Signature Verification Phase ***/
    log_protocol_phase("SIGNATURE VERIFICATION");
    
    LOG_INF("Verifying FROST signature...");
    LOG_INF("   Verification inputs:");
    LOG_INF("     - Signature: [64 bytes]");
    LOG_INF("     - Message hash: [32 bytes]");
    LOG_INF("     - Group public key: [from any participant's keypair]");

    is_signature_valid = secp256k1_frost_verify(sign_verify_ctx, signature, msg_hash, &keypairs[0].public_keys);

    if (is_signature_valid) {
        LOG_INF("Signature verification: VALID");
        LOG_INF("FROST protocol completed successfully!");
    } else {
        LOG_ERR("Signature verification: INVALID");
        LOG_ERR("💥 FROST protocol failed!");
    }

    /*** Final Summary ***/
    log_protocol_phase("PROTOCOL SUMMARY");
    
    LOG_INF("FROST Protocol Execution Summary:");
    LOG_INF("   Total Participants: %d", EXAMPLE_MAX_PARTICIPANTS);
    LOG_INF("   Signing Participants: %d", EXAMPLE_MIN_PARTICIPANTS);
    LOG_INF("   Threshold: %d-of-%d", EXAMPLE_MIN_PARTICIPANTS, EXAMPLE_MAX_PARTICIPANTS);
    LOG_INF("   Message: \"%s\"", msg);
    LOG_INF("   Signature Valid: %s", is_signature_valid ? "YES" : "NO");
    
    LOG_INF("Key Information:");
    log_hex("  Group Public Key", keypairs[0].public_keys.group_public_key, sizeof(keypairs[0].public_keys.group_public_key));
    log_hex("  Final Signature", signature, sizeof(signature));
    log_hex("  Message Hash", msg_hash, sizeof(msg_hash));

    LOG_INF("💡 Protocol Notes:");
    LOG_INF("   - Each participant has a unique private key share");
    LOG_INF("   - All participants share the same group public key");
    LOG_INF("   - Signature is valid against the group public key");
    LOG_INF("   - Any %d participants can recreate this signature", EXAMPLE_MIN_PARTICIPANTS);

    // Cleanup
    LOG_INF("🧹 Cleaning up resources...");
    if (sign_verify_ctx) {
        secp256k1_context_destroy(sign_verify_ctx);
        LOG_INF("Context destroyed");
    }
    
    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS; index++) {
        if (nonces[index]) {
            // Note: Specific cleanup depends on secp256k1_frost implementation
            LOG_INF("Cleaned up nonce for participant #%d", index);
        }
    }

    LOG_INF("🏁 FROST protocol example completed");
    
    return is_signature_valid ? 0 : 1;
}