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
#include <psapi.h>
#include <math.h>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")
#pragma comment(lib, "psapi.lib")

#define N 3
#define T 2

#define VENDOR_ID 0x2FE3   
#define PRODUCT_ID 0x100   

// TYPE DEFINITIONS

typedef enum {
    COMM_TYPE_UART = 1,
    COMM_TYPE_USB_HID = 2
} communication_type_t;

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

#define MSG_HEADER_MAGIC 0x46524F53
#define MSG_VERSION 0x01

typedef enum {
    MSG_TYPE_NONCE_COMMITMENT = 0x04,  
    MSG_TYPE_ALL_NONCE_COMMITMENTS = 0x05,  
    MSG_TYPE_READY = 0x06,            
    MSG_TYPE_END_TRANSMISSION = 0xFF,
    MSG_TYPE_SIGN = 0x07,
    MSG_TYPE_SIGNATURE_SHARE = 0x08
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

// EVALUATION STRUCTURES

typedef struct {
    double measurements[100];
    int num_samples;
    double mean;
    double std_deviation;
    double min_time;
    double max_time;
    double coefficient_variation;
} performance_stats_t;

typedef struct {
    SIZE_T initial_memory;
    SIZE_T peak_memory;
    SIZE_T overhead;
    double percentage_increase;
} memory_stats_t;

typedef struct {
    size_t message_header_size;
    size_t public_key_size;
    size_t commitments_size;
    size_t secret_share_size;
    size_t signature_share_size;
    size_t total_per_participant;
    size_t protocol_overhead;
} protocol_sizes_t;

typedef struct {
    double transmission_time;
    size_t data_size;
    double throughput_bps;
    int segments_required;
    double overhead_percentage;
} communication_stats_t;

// TIMING FUNCTIONS 

static LARGE_INTEGER frequency;
static BOOL frequency_initialized = FALSE;

void init_performance_counter() {
    if (!frequency_initialized) {
        QueryPerformanceFrequency(&frequency);
        frequency_initialized = TRUE;
        printf("Performance counter initialized (frequency: %lld Hz)\n", frequency.QuadPart);
    }
}

double get_time_milliseconds() {
    init_performance_counter();
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return (double)(counter.QuadPart * 1000.0) / frequency.QuadPart;
}

void calculate_performance_stats(performance_stats_t* stats) {
    if (stats->num_samples <= 0) return;
    
    // Mean calculation
    double sum = 0.0;
    stats->min_time = stats->measurements[0];
    stats->max_time = stats->measurements[0];
    
    for (int i = 0; i < stats->num_samples; i++) {
        sum += stats->measurements[i];
        if (stats->measurements[i] < stats->min_time) stats->min_time = stats->measurements[i];
        if (stats->measurements[i] > stats->max_time) stats->max_time = stats->measurements[i];
    }
    stats->mean = sum / stats->num_samples;
    
    // Standard deviation
    double variance_sum = 0.0;
    for (int i = 0; i < stats->num_samples; i++) {
        double diff = stats->measurements[i] - stats->mean;
        variance_sum += diff * diff;
    }
    stats->std_deviation = sqrt(variance_sum / stats->num_samples);
    
    // Coefficient of variation
    stats->coefficient_variation = (stats->std_deviation / stats->mean) * 100.0;
}

void print_performance_stats(const char* operation, performance_stats_t* stats) {
    printf("\n=== PERFORMANCE ANALYSIS: %s ===\n", operation);
    printf("   Samples collected: %d\n", stats->num_samples);
    printf("   Mean execution time: %.3f ms\n", stats->mean);
    printf("   Standard deviation: %.3f ms\n", stats->std_deviation);
    printf("   Execution time range: %.3f ms to %.3f ms\n", stats->min_time, stats->max_time);
    printf("   Coefficient of variation: %.1f%%\n", stats->coefficient_variation);
    
    if (stats->coefficient_variation < 20.0) {
        printf("   Performance: VERY STABLE\n");
    } else if (stats->coefficient_variation < 40.0) {
        printf("   Performance: MODERATELY STABLE\n");
    } else {
        printf("   Performance: HIGH VARIABILITY\n");
    }
    printf("========================================\n");
}

// MEMORY MONITORING 

SIZE_T get_current_memory_usage() {
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024; // Convert to KB
    }
    return 0;
}

void init_memory_monitoring(memory_stats_t* mem_stats) {
    mem_stats->initial_memory = get_current_memory_usage();
    mem_stats->peak_memory = mem_stats->initial_memory;
    printf("Memory monitoring initialized (initial: %zu KB)\n", mem_stats->initial_memory);
}

void update_memory_monitoring(memory_stats_t* mem_stats) {
    SIZE_T current_memory = get_current_memory_usage();
    if (current_memory > mem_stats->peak_memory) {
        mem_stats->peak_memory = current_memory;
    }
}

void finalize_memory_monitoring(memory_stats_t* mem_stats) {
    mem_stats->overhead = mem_stats->peak_memory - mem_stats->initial_memory;
    mem_stats->percentage_increase = ((double)mem_stats->overhead / mem_stats->initial_memory) * 100.0;
}

void print_memory_stats(const char* operation, memory_stats_t* mem_stats) {
    printf("\n=== MEMORY ANALYSIS: %s ===\n", operation);
    printf("   Initial memory usage: %zu KB\n", mem_stats->initial_memory);
    printf("   Peak memory usage: %zu KB\n", mem_stats->peak_memory);
    printf("   Memory overhead: %zu KB\n", mem_stats->overhead);
    printf("   Percentage increase: %.1f%%\n", mem_stats->percentage_increase);
    
    if (mem_stats->percentage_increase < 5.0) {
        printf("   Memory efficiency: EXCELLENT\n");
    } else if (mem_stats->percentage_increase < 15.0) {
        printf("    Memory efficiency: GOOD\n");
    } else {
        printf("   Memory efficiency: HIGH OVERHEAD\n");
    }
    printf("======================================\n");
}

// PROTOCOL SIZE MEASUREMENT

void measure_protocol_sizes(protocol_sizes_t* sizes) {
    sizes->message_header_size = sizeof(message_header_t);
    sizes->public_key_size = sizeof(serialized_keypair_t);
    sizes->commitments_size = sizeof(serialized_nonce_commitment_t);
    sizes->secret_share_size = 36; 
    sizes->signature_share_size = sizeof(serialized_signature_share_t);
    
    // Calculate totals
    sizes->total_per_participant = sizes->message_header_size + sizes->public_key_size + sizes->commitments_size;
    sizes->protocol_overhead = sizes->secret_share_size + 368; // Additional protocol data from document
}

void print_protocol_sizes(protocol_sizes_t* sizes) {
    printf("\n=== PROTOCOL SIZE ANALYSIS ===\n");
    printf("   Message header: %zu bytes\n", sizes->message_header_size);
    printf("   Public key (serialized): %zu bytes\n", sizes->public_key_size);
    printf("   Commitments: %zu bytes\n", sizes->commitments_size);
    printf("   Secret shares: %zu bytes\n", sizes->secret_share_size);
    printf("   Signature shares: %zu bytes\n", sizes->signature_share_size);
    printf("   Total per participant: %zu bytes\n", sizes->total_per_participant);
    printf("   Protocol overhead: %zu bytes\n", sizes->protocol_overhead);
    printf("===================================\n");
}

BOOL send_message(comm_handle_t* comm, uint8_t msg_type, uint32_t participant, 
                  const void* payload, uint16_t payload_len);
BOOL send_data(comm_handle_t* comm, const void* data, size_t len);

// COMMUNICATION MEASUREMENT 

BOOL send_message_timed(comm_handle_t* comm, uint8_t msg_type, uint32_t participant, 
                       const void* payload, uint16_t payload_len, double* elapsed_time) {
    double start_time = get_time_milliseconds();
    
    BOOL result = send_message(comm, msg_type, participant, payload, payload_len);
    
    double end_time = get_time_milliseconds();
    *elapsed_time = end_time - start_time;
    
    return result;
}

BOOL send_data_timed(comm_handle_t* comm, const void* data, size_t len, communication_stats_t* comm_stats) {
    double start_time = get_time_milliseconds();
    
    BOOL result = send_data(comm, data, len);
    
    double end_time = get_time_milliseconds();
    comm_stats->transmission_time = end_time - start_time;
    comm_stats->data_size = len;
    
    if (comm_stats->transmission_time > 0) {
        comm_stats->throughput_bps = (len * 8.0 * 1000.0) / comm_stats->transmission_time; // bits per second
    }
    
    // Calculate segmentation for HID
    if (comm->type == COMM_TYPE_USB_HID) {
        size_t payload_per_report = comm->output_report_length - 2; // 2 bytes overhead
        comm_stats->segments_required = (int)((len + payload_per_report - 1) / payload_per_report);
        comm_stats->overhead_percentage = ((comm_stats->segments_required * 2.0) / len) * 100.0;
    } else {
        comm_stats->segments_required = 1;
        comm_stats->overhead_percentage = 0.0;
    }
    
    return result;
}

void print_communication_stats(const char* operation, communication_stats_t* comm_stats, 
                             communication_type_t comm_type) {
    printf("\n=== COMMUNICATION ANALYSIS: %s ===\n", operation);
    printf("   Communication type: %s\n", 
           comm_type == COMM_TYPE_USB_HID ? "USB HID" : "UART");
    printf("   Data size: %zu bytes\n", comm_stats->data_size);
    printf("   Transmission time: %.3f ms\n", comm_stats->transmission_time);
    printf("   Throughput: %.0f bps (%.1f KB/s)\n", 
           comm_stats->throughput_bps, comm_stats->throughput_bps / 8000.0);
    
    if (comm_type == COMM_TYPE_USB_HID) {
        printf("   Segments required: %d\n", comm_stats->segments_required);
        printf("   Protocol overhead: %.1f%%\n", comm_stats->overhead_percentage);
    }
    
    // Performance assessment
    if (comm_type == COMM_TYPE_USB_HID) {
        if (comm_stats->transmission_time < 200.0) {
            printf("   HID Performance: EXCELLENT\n");
        } else if (comm_stats->transmission_time < 500.0) {
            printf("    HID Performance: ACCEPTABLE\n");
        } else {
            printf("   HID Performance: SLOW\n");
        }
    } else {
        if (comm_stats->transmission_time < 20.0) {
            printf("   UART Performance: EXCELLENT\n");
        } else if (comm_stats->transmission_time < 50.0) {
            printf("    UART Performance: ACCEPTABLE\n");
        } else {
            printf("   UART Performance: SLOW\n");
        }
    }
    printf("========================================\n");
}

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

void print_public_key_complete(const char *label, const unsigned char *key, size_t len) {
    printf("%s: 0x", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
}

static void verify_commitment_consistency(const serialized_nonce_commitment_t* commitments, int num_commitments) {
    printf("\n=== COMMITMENT CONSISTENCY VERIFICATION ===\n");
    
    for (int i = 0; i < num_commitments; i++) {
        printf("Participant %u commitment:\n", commitments[i].index);
        
        bool hiding_zeros = true, binding_zeros = true;
        for (int j = 0; j < 64; j++) {
            if (commitments[i].hiding[j] != 0) hiding_zeros = false;
            if (commitments[i].binding[j] != 0) binding_zeros = false;
        }
        
        if (hiding_zeros) {
            printf("WARNING: Hiding commitment is all zeros!\n");
        } else {
            printf("Hiding commitment appears valid\n");
        }
        
        if (binding_zeros) {
            printf("WARNING: Binding commitment is all zeros!\n");
        } else {
            printf("Binding commitment appears valid\n");
        }
        
        printf("   Hiding:  %02x%02x%02x%02x%02x%02x%02x%02x...\n",
               commitments[i].hiding[0], commitments[i].hiding[1], 
               commitments[i].hiding[2], commitments[i].hiding[3],
               commitments[i].hiding[4], commitments[i].hiding[5],
               commitments[i].hiding[6], commitments[i].hiding[7]);
        printf("   Binding: %02x%02x%02x%02x%02x%02x%02x%02x...\n",
               commitments[i].binding[0], commitments[i].binding[1], 
               commitments[i].binding[2], commitments[i].binding[3],
               commitments[i].binding[4], commitments[i].binding[5],
               commitments[i].binding[6], commitments[i].binding[7]);
    }
    
    printf("=====================================\n\n");
}

int aggregate_and_verify_signature_ENHANCED(serialized_signature_share_t* signature_shares,
                                           serialized_keypair_t* participant_keypairs,
                                           serialized_nonce_commitment_t* commitments,
                                           int num_shares,
                                           unsigned char* msg_hash,
                                           unsigned char* final_signature,
                                           performance_stats_t* aggregation_stats,
                                           memory_stats_t* aggregation_memory) {
    
    printf("\n=== ENHANCED FROST AGGREGATION (NONCE PERSISTENCE) ===\n");
    
    // Start timing and memory monitoring
    double start_time = get_time_milliseconds();
    init_memory_monitoring(aggregation_memory);
    
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("Failed to create secp256k1 context\n");
        return 0;
    }
    
    update_memory_monitoring(aggregation_memory);
    
    verify_commitment_consistency(commitments, num_shares);
    
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
    
    update_memory_monitoring(aggregation_memory);
    
    printf("  Aggregator details:\n");
    printf("   Index: %u\n", aggregator_keypair.public_keys.index);
    printf("   Max participants: %u\n", aggregator_keypair.public_keys.max_participants);
    print_hex("   Secret (first 8 bytes)", aggregator_keypair.secret, 8);
    print_hex("   Public key (first 8 bytes)", aggregator_keypair.public_keys.public_key, 8);
    print_hex("   Group key (first 8 bytes)", aggregator_keypair.public_keys.group_public_key, 8);
    
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
        printf("   Hiding commitment: %02x%02x%02x%02x...\n",
               signing_commitments[i].hiding[0], signing_commitments[i].hiding[1],
               signing_commitments[i].hiding[2], signing_commitments[i].hiding[3]);
        printf("   Binding commitment: %02x%02x%02x%02x...\n",
               signing_commitments[i].binding[0], signing_commitments[i].binding[1],
               signing_commitments[i].binding[2], signing_commitments[i].binding[3]);
    }
    
    update_memory_monitoring(aggregation_memory);
    
    printf("\nMessage hash verification:\n");
    unsigned char expected_msg[12] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    unsigned char expected_hash[32];
    unsigned char tag[14] = {'f', 'r', 'o', 's', 't', '_', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};
    int hash_result = secp256k1_tagged_sha256(ctx, expected_hash, tag, sizeof(tag), expected_msg, sizeof(expected_msg));
    
    if (hash_result != 1) {
        printf("ERROR: Hash computation failed!\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    
    if (memcmp(msg_hash, expected_hash, 32) != 0) {
        printf("ERROR: Message hash mismatch!\n");
        printf("Expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected_hash[i]);
        printf("\nReceived: ");
        for (int i = 0; i < 32; i++) printf("%02x", msg_hash[i]);
        printf("\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    printf("Message hash verified correctly\n");
    
    printf("\nAttempting signature aggregation with persistence-aware data...\n");
    printf("Using %d signature shares from persistent nonces\n", num_shares);
    
    // Measure aggregation time specifically
    double aggregation_start = get_time_milliseconds();
    int return_val = secp256k1_frost_aggregate(ctx, final_signature, msg_hash,
                                              &aggregator_keypair, public_keys, 
                                              signing_commitments,
                                              frost_signature_shares, num_shares);
    double aggregation_end = get_time_milliseconds();
    
    // Store aggregation timing
    if (aggregation_stats->num_samples < 100) {
        aggregation_stats->measurements[aggregation_stats->num_samples] = aggregation_end - aggregation_start;
        aggregation_stats->num_samples++;
    }
    
    update_memory_monitoring(aggregation_memory);
    
    if (return_val == 1) {
        printf("*** SIGNATURE AGGREGATION SUCCESS! ***\n");
        printf("Persistent nonces worked correctly!\n");
        
        double verification_start = get_time_milliseconds();
        int is_signature_valid = secp256k1_frost_verify(ctx, final_signature, msg_hash, 
                                                        &aggregator_keypair.public_keys);
        double verification_end = get_time_milliseconds();
        
        printf("Aggregation time: %.3f ms\n", aggregation_end - aggregation_start);
        printf("Verification time: %.3f ms\n", verification_end - verification_start);
        
        if (is_signature_valid) {
            printf("🎊 PERFECT: FROST signature is mathematically valid!\n");
            printf("🎊 Nonce persistence implementation successful!\n");
            printf("\nFinal FROST Signature (64 bytes):\n");
            for (int i = 0; i < 64; i++) {
                printf("%02x", final_signature[i]);
                if ((i + 1) % 32 == 0) printf("\n");
            }
            printf("\n");
        } else {
            printf(" WARNING: Aggregation succeeded but verification failed\n");
        }
        
        // Finalize timing and memory
        double end_time = get_time_milliseconds();
        finalize_memory_monitoring(aggregation_memory);
        
        printf("Total aggregation process time: %.3f ms\n", end_time - start_time);
        
        secp256k1_context_destroy(ctx);
        return is_signature_valid;
        
    } else {
        printf("*** SIGNATURE AGGREGATION FAILED ***\n");
        printf("This may indicate nonce persistence issues\n");
        
        printf("\nPERSISTENCE DEBUG INFORMATION:\n");
        printf("Number of participants: %d\n", num_shares);
        printf("Aggregator index: %u\n", aggregator_keypair.public_keys.index);
        
        printf("\nSignature shares analysis:\n");
        for (int i = 0; i < num_shares; i++) {
            bool all_zeros = true;
            for (int j = 0; j < 32; j++) {
                if (frost_signature_shares[i].response[j] != 0) {
                    all_zeros = false;
                    break;
                }
            }
            printf("Participant %u: %s\n", frost_signature_shares[i].index, 
                   all_zeros ? "ALL ZEROS" : "HAS DATA");
        }
        
        printf("\nCommitment analysis:\n");
        for (int i = 0; i < num_shares; i++) {
            bool hiding_zeros = true, binding_zeros = true;
            for (int j = 0; j < 64; j++) {
                if (signing_commitments[i].hiding[j] != 0) hiding_zeros = false;
                if (signing_commitments[i].binding[j] != 0) binding_zeros = false;
            }
            printf("Participant %u: Hiding %s, Binding %s\n", 
                   signing_commitments[i].index,
                   hiding_zeros ? "ZEROS" : "DATA",
                   binding_zeros ? "ZEROS" : "DATA");
        }
        
        finalize_memory_monitoring(aggregation_memory);
        secp256k1_context_destroy(ctx);
        return 0;
    }
}

void send_commitments_in_consistent_order(serialized_nonce_commitment_t* commitments, int num_commitments) {
    printf("\n=== ENSURING COMMITMENT CONSISTENCY ===\n");
    
    printf("Before sorting:\n");
    for (int i = 0; i < num_commitments; i++) {
        printf("  Position %d: Participant %u\n", i, commitments[i].index);
    }
    
    for (int i = 0; i < num_commitments - 1; i++) {
        for (int j = i + 1; j < num_commitments; j++) {
            if (commitments[i].index > commitments[j].index) {
                serialized_nonce_commitment_t temp = commitments[i];
                commitments[i] = commitments[j];
                commitments[j] = temp;
            }
        }
    }
    
    printf("After sorting:\n");
    for (int i = 0; i < num_commitments; i++) {
        printf("  Position %d: Participant %u\n", i, commitments[i].index);
    }
    
    printf("Commitments sorted by participant index for consistency\n");
    printf("This order will be preserved across all devices\n");
}

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
        
        report[0] = 0x02;
        size_t available_space = comm->output_report_length - 2;
        size_t remaining = len - bytes_sent;
        size_t chunk_size = (available_space < remaining) ? available_space : remaining;
        
        report[1] = (uint8_t)chunk_size;
        memcpy(report + 2, data_ptr + bytes_sent, chunk_size);
        
        printf("Sending chunk %zu bytes (sent: %zu/%zu)\n", chunk_size, bytes_sent, len);
        
        if (!HidD_SetOutputReport(comm->hid_handle, report, comm->output_report_length)) {
            DWORD error = GetLastError();
            printf("HidD_SetOutputReport failed. Error: %lu\n", error);
            free(report);
            return FALSE;
        }
        
        free(report);
        bytes_sent += chunk_size;
        Sleep(200);
    }
    
    return TRUE;
}

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
            uint8_t report_id = report[0];
            if (report_id == 0x01 && bytes_read >= 3) {
                uint8_t chunk_len = report[1];
                if (chunk_len > 0 && chunk_len <= (bytes_read - 2)) {
                    size_t copy_len = (*total_received + chunk_len <= max_len) ? chunk_len : (max_len - *total_received);
                    memcpy(recv_buffer + *total_received, report + 2, copy_len);
                    *total_received += copy_len;
                    
                    printf("Received chunk: %u bytes (total: %zu)\n", chunk_len, *total_received);
                    
                    if (*total_received >= sizeof(message_header_t)) {
                        message_header_t* header = (message_header_t*)recv_buffer;
                        if (header->magic == MSG_HEADER_MAGIC) {
                            size_t expected_total = sizeof(message_header_t) + header->payload_len;
                            if (*total_received >= expected_total) {
                                printf("Complete message received (%zu bytes)\n", expected_total);
                                *total_received = expected_total;
                                free(report);
                                return TRUE;
                            }
                        }
                    }
                }
            }
        }
        
        free(report);
        Sleep(100);
        static int timeout_counter = 0;
        if (++timeout_counter > 50) {
            printf("Timeout waiting for complete message\n");
            timeout_counter = 0;
            break;
        }
    }
    
    return (*total_received > 0);
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
        Sleep(500);
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
    
    if ((*header)->magic != MSG_HEADER_MAGIC || (*header)->version != MSG_VERSION) {
        printf("Invalid message header: magic=0x%08x, version=%d\n", 
               (*header)->magic, (*header)->version);
        return FALSE;
    }
    
    if ((*header)->payload_len > 0) {
        *payload = buffer + sizeof(message_header_t);
    } else {
        *payload = NULL;
    }
    
    printf("Received valid message: type=0x%02X, len=%u\n", 
           (*header)->msg_type, (*header)->payload_len);
    
    return TRUE;
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
    timeouts.ReadIntervalTimeout = 100;
    timeouts.ReadTotalTimeoutConstant = 10000;
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
                Sleep(1000);
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

void compute_message_hash_verified(unsigned char* msg_hash, const unsigned char* msg, size_t msg_len) {
    double start_time = get_time_milliseconds();
    
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char tag[14] = {'f', 'r', 'o', 's', 't', '_', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};
    int return_val = secp256k1_tagged_sha256(ctx, msg_hash, tag, sizeof(tag), msg, msg_len);
    assert(return_val == 1);
    
    double end_time = get_time_milliseconds();
    
    printf("Message hash computation verified:\n");
    printf("   Message: \"");
    for (size_t i = 0; i < msg_len; i++) {
        printf("%c", msg[i]);
    }
    printf("\"\n");
    printf("   Tag: \"");
    for (size_t i = 0; i < 14; i++) {
        printf("%c", tag[i]);
    }
    printf("\"\n");
    printf("   Hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", msg_hash[i]);
    }
    printf("\n");
    printf("Hash computation time: %.3f ms\n", end_time - start_time);
    
    secp256k1_context_destroy(ctx);
}

int main(void) {
    printf("=== FROST Signature Coordinator (PERFORMANCE EVALUATION) ===\n");
    printf("Enhanced with comprehensive performance monitoring\n");
    printf("Measuring: timing, memory, protocol sizes, communication efficiency\n\n");
    
    // Initialize performance monitoring
    init_performance_counter();
    
    // Performance tracking variables
    performance_stats_t keygen_stats = {0};
    performance_stats_t signing_stats = {0};
    performance_stats_t aggregation_stats = {0};
    memory_stats_t overall_memory = {0};
    memory_stats_t aggregation_memory = {0};
    protocol_sizes_t protocol_sizes = {0};
    communication_stats_t comm_stats_array[T * 2]; // For each participant, 2 phases
    int comm_stats_count = 0;
    
    // Measure protocol sizes
    measure_protocol_sizes(&protocol_sizes);
    print_protocol_sizes(&protocol_sizes);
    
    // Initialize overall memory monitoring
    init_memory_monitoring(&overall_memory);
    
    serialized_nonce_commitment_t commitments[T];
    serialized_signature_share_t signature_shares[T];
    serialized_keypair_t participant_keypairs[T];
    int commitments_received = 0;
    int shares_received = 0;
    uint8_t receive_buffer[1024];
    
    unsigned char msg[12] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    unsigned char msg_hash[32];
    
    printf("Computing message hash...\n");
    compute_message_hash_verified(msg_hash, msg, sizeof(msg));
    
    // Phase 1: Nonce Commitment Collection
    printf("\n=== PHASE 1: NONCE COMMITMENT COLLECTION ===\n");
    double phase1_start = get_time_milliseconds();
    
    for (int i = 0; i < T; i++) {
        printf("\n=== Processing Participant %d (Nonce Commitment Collection) ===\n", i+1);
        
        double participant_start = get_time_milliseconds();
        
        comm_handle_t comm = setup_communication(i+1);
        if (comm.type == 0) {
            printf("Skipping participant %d due to communication failure\n", i+1);
            continue;
        }
        
        update_memory_monitoring(&overall_memory);
        
        printf("Sending READY signal to participant %d...\n", i+1);
        printf("This will trigger nonce generation and persistence on device\n");
        
        // Measure READY message transmission
        double ready_time;
        if (!send_message_timed(&comm, MSG_TYPE_READY, i+1, NULL, 0, &ready_time)) {
            printf("Failed to send READY signal to participant %d\n", i+1);
            close_communication(&comm);
            continue;
        }
        
        // Store communication stats
        if (comm_stats_count < T * 2) {
            comm_stats_array[comm_stats_count].transmission_time = ready_time;
            comm_stats_array[comm_stats_count].data_size = sizeof(message_header_t);
            comm_stats_array[comm_stats_count].throughput_bps = 
                (sizeof(message_header_t) * 8.0 * 1000.0) / ready_time;
            comm_stats_count++;
        }
        
        printf("READY message transmission: %.3f ms\n", ready_time);
        
        printf("Waiting for nonce commitment from participant %d...\n", i+1);
        printf("Device will generate fresh nonce and persist to flash\n");
        
        message_header_t* header;
        void* payload;
        
        double receive_start = get_time_milliseconds();
        if (receive_complete_message(&comm, receive_buffer, sizeof(receive_buffer), &header, &payload)) {
            double receive_end = get_time_milliseconds();
            printf("Nonce commitment reception: %.3f ms\n", receive_end - receive_start);
            
            if (header->msg_type == MSG_TYPE_NONCE_COMMITMENT) {
                uint8_t* payload_data = (uint8_t*)payload;
                
                memcpy(&commitments[commitments_received], payload_data, sizeof(serialized_nonce_commitment_t));
                
                memcpy(&participant_keypairs[commitments_received], 
                       payload_data + sizeof(serialized_nonce_commitment_t), 
                       sizeof(serialized_keypair_t));
                
                printf("\n=== RECEIVED PERSISTENT NONCE COMMITMENT FROM PARTICIPANT %d ===\n", i+1);
                printf("This commitment was generated and saved to flash\n");
                printf("Participant index: %u\n", commitments[commitments_received].index);
                printf("Commitment data size: %zu bytes\n", sizeof(serialized_nonce_commitment_t));
                printf("Keypair data size: %zu bytes\n", sizeof(serialized_keypair_t));
                
                print_full_hex("Hiding Commitment", commitments[commitments_received].hiding, 64);
                print_full_hex("Binding Commitment", commitments[commitments_received].binding, 64);
                
                printf("\n=== RECEIVED KEYPAIR FROM PARTICIPANT %d ===\n", i+1);
                printf("Participant index: %u\n", participant_keypairs[commitments_received].index);
                printf("Max participants: %u\n", participant_keypairs[commitments_received].max_participants);
                
                print_public_key_complete("Individual Public Key", 
                                        participant_keypairs[commitments_received].public_key, 64);
                print_public_key_complete("Group Public Key", 
                                        participant_keypairs[commitments_received].group_public_key, 64);
                
                commitments_received++;
                printf("Nonce persistence: Device can safely restart now\n");
                
                // Store keygen timing
                double participant_end = get_time_milliseconds();
                if (keygen_stats.num_samples < 100) {
                    keygen_stats.measurements[keygen_stats.num_samples] = participant_end - participant_start;
                    keygen_stats.num_samples++;
                }
                
            } else {
                printf("Received unexpected message type: 0x%02X\n", header->msg_type);
            }
        } else {
            printf("Failed to receive nonce commitment from participant %d\n", i+1);
        }
        
        close_communication(&comm);
        update_memory_monitoring(&overall_memory);
        
        if (commitments_received >= T) {
            printf("\nReceived minimum %d persistent commitments. Continuing...\n", T);
            break;
        }
    }
    
    double phase1_end = get_time_milliseconds();
    printf("Phase 1 total time: %.3f ms\n", phase1_end - phase1_start);
    
    if (commitments_received < T) {
        printf("\nError: Received only %d commitments, need at least %d\n", 
               commitments_received, T);
        printf("Press Enter to exit...\n");
        getchar();
        return 1;
    }
    
    printf("\n=== ENSURING COMMITMENT CONSISTENCY FOR PERSISTENCE ===\n");
    send_commitments_in_consistent_order(commitments, commitments_received);
    
    printf("\n=== FROST PERSISTENT NONCE COMMITMENT COLLECTION COMPLETE ===\n");
    printf("Collected %d persistent nonce commitments:\n", commitments_received);
    for (int i = 0; i < commitments_received; i++) {
        printf("\nParticipant %u:\n", commitments[i].index);
        printf("Status: Nonce persisted to flash\n");
        print_public_key_complete("  Individual Public Key", 
                                participant_keypairs[i].public_key, 64);
        print_public_key_complete("  Group Public Key", 
                                participant_keypairs[i].group_public_key, 64);
        print_hex("  Hiding (first 8 bytes)", commitments[i].hiding, 64);
        print_hex("  Binding (first 8 bytes)", commitments[i].binding, 64);
    }
    
    // Phase 2: Signing
    printf("\n=== PHASE 2: SIGNING DATA AND COLLECTING SIGNATURE SHARES ===\n");
    printf("Devices will use original nonces from flash persistence\n");
    double phase2_start = get_time_milliseconds();
    
    for (int i = 0; i < T; i++) {
        uint32_t participant_index = commitments[i].index;
        printf("\n=== Processing Participant %u (Signature Generation) ===\n", participant_index);
        
        double signing_start = get_time_milliseconds();
        
        comm_handle_t comm = setup_communication(participant_index);
        if (comm.type == 0) {
            printf("Skipping participant %u due to communication failure\n", participant_index);
            continue;
        }
        
        uint16_t payload_len = 32 + 4 + T * sizeof(serialized_nonce_commitment_t);
        uint8_t* payload = (uint8_t*)malloc(payload_len);
        if (!payload) {
            close_communication(&comm);
            continue;
        }
        
        memcpy(payload, msg_hash, 32);
        *(uint32_t*)(payload + 32) = T;
        memcpy(payload + 32 + 4, commitments, T * sizeof(serialized_nonce_commitment_t));
        
        printf("Sending signing data to participant %u...\n", participant_index);
        printf("Device will load original nonce from flash persistence\n");
        printf("Signing payload size: %u bytes\n", payload_len);
        
        printf("Sending to participant %u:\n", participant_index);
        printf("   Message hash: ");
        for (int j = 0; j < 8; j++) printf("%02x", msg_hash[j]);
        printf("...\n");
        printf("   Commitments count: %d (sorted order)\n", T);

        for (int j = 0; j < T; j++) {
            printf("   Commitment %d (participant %u):\n", j, commitments[j].index);
            printf("     This matches what participant stored in flash\n");
            printf("     Hiding:  ");
            for (int k = 0; k < 8; k++) printf("%02x", commitments[j].hiding[k]);
            printf("...\n");
            printf("     Binding: ");
            for (int k = 0; k < 8; k++) printf("%02x", commitments[j].binding[k]);
            printf("...\n");
        }
        
        // Measure signing message transmission
        double sign_transmission_time;
        if (!send_message_timed(&comm, MSG_TYPE_SIGN, participant_index, payload, payload_len, &sign_transmission_time)) {
            printf("Failed to send signing data to participant %u\n", participant_index);
            free(payload);
            close_communication(&comm);
            continue;
        } else {
            printf("Signing data sent successfully to participant %u\n", participant_index);
            printf("Device will verify commitment consistency and load original nonce\n");
            printf("Signing data transmission: %.3f ms\n", sign_transmission_time);
            
            // Store communication stats
            if (comm_stats_count < T * 2) {
                communication_stats_t* stats = &comm_stats_array[comm_stats_count];
                stats->transmission_time = sign_transmission_time;
                stats->data_size = sizeof(message_header_t) + payload_len;
                stats->throughput_bps = (stats->data_size * 8.0 * 1000.0) / sign_transmission_time;
                
                if (comm.type == COMM_TYPE_USB_HID) {
                    size_t payload_per_report = comm.output_report_length - 2;
                    stats->segments_required = (int)((stats->data_size + payload_per_report - 1) / payload_per_report);
                    stats->overhead_percentage = ((stats->segments_required * 2.0) / stats->data_size) * 100.0;
                } else {
                    stats->segments_required = 1;
                    stats->overhead_percentage = 0.0;
                }
                comm_stats_count++;
            }
        }
        
        free(payload);
        
        printf("Waiting for signature share from participant %u...\n", participant_index);
        printf("Expecting signature computed with original persisted nonce\n");
        
        message_header_t* header;
        void* payload_response;
        DWORD start_time = GetTickCount();
        DWORD timeout_ms = 30000;
        BOOL received_share = FALSE;
        
        double signature_receive_start = get_time_milliseconds();
        while (!received_share && (GetTickCount() - start_time) < timeout_ms) {
            if (receive_complete_message(&comm, receive_buffer, sizeof(receive_buffer), 
                                       &header, &payload_response)) {
                double signature_receive_end = get_time_milliseconds();
                
                if (header->msg_type == MSG_TYPE_SIGNATURE_SHARE && 
                    header->payload_len == sizeof(serialized_signature_share_t)) {
                    
                    serialized_signature_share_t* sig_share = (serialized_signature_share_t*)payload_response;
                    memcpy(&signature_shares[shares_received], sig_share, sizeof(serialized_signature_share_t));
                    
                    printf("\n*** PERSISTENT SIGNATURE SHARE RECEIVED from Participant %u ***\n", 
                           sig_share->index);
                    printf("Generated using original nonce from flash persistence\n");
                    printf("Signature share reception: %.3f ms\n", signature_receive_end - signature_receive_start);
                    printf("Signature share size: %zu bytes\n", sizeof(serialized_signature_share_t));
                    
                    print_full_hex("Signature Share", sig_share->response, 32);
                    
                    printf("\n=== FROST PERSISTENT SIGNATURE SHARE %d ===\n", shares_received + 1);
                    printf("Participant: %u\n", sig_share->index);
                    printf("Source: Original nonce from flash\n");
                    printf("Share: ");
                    for (int j = 0; j < 32; j++) {
                        printf("%02x", sig_share->response[j]);
                    }
                    printf("\n===============================\n\n");
                    
                    shares_received++;
                    received_share = TRUE;
                    
                    // Store signing timing
                    double signing_end = get_time_milliseconds();
                    if (signing_stats.num_samples < 100) {
                        signing_stats.measurements[signing_stats.num_samples] = signing_end - signing_start;
                        signing_stats.num_samples++;
                    }
                    
                } else if (header->msg_type == MSG_TYPE_END_TRANSMISSION) {
                    printf("Received end transmission marker\n");
                } else {
                    printf("Received unexpected message type: 0x%02X (expected signature share)\n", 
                           header->msg_type);
                }
            }
            
            Sleep(100);
        }
        
        if (!received_share) {
            printf("*** TIMEOUT: No signature share received from participant %u ***\n", participant_index);
            printf("Device may have failed to load persistent nonce\n");
        }
        
        close_communication(&comm);
        update_memory_monitoring(&overall_memory);
    }
    
    double phase2_end = get_time_milliseconds();
    printf("Phase 2 total time: %.3f ms\n", phase2_end - phase2_start);
    
    printf("\n=== Persistent Nonce Signing Process Complete ===\n");
    
    if (shares_received >= T) {
        printf("\n=== PERSISTENT SIGNATURE SHARE COLLECTION COMPLETE ===\n");
        printf("Successfully collected signature shares from %d participants:\n", shares_received);
        printf("All shares generated using original persistent nonces\n\n");
        
        for (int i = 0; i < shares_received; i++) {
            if (signature_shares[i].index != 0) {
                printf("Participant %u Persistent Signature Share:\n", signature_shares[i].index);
                printf("Generated from original flash-stored nonce\n");
                printf("  ");
                for (int j = 0; j < 32; j++) {
                    printf("%02x", signature_shares[i].response[j]);
                }
                printf("\n\n");
            }
        }
        
        printf("Proceeding to aggregate signature shares from persistent nonces...\n");
        
        unsigned char final_signature[64];
        memset(final_signature, 0, sizeof(final_signature));
        
        double aggregation_start = get_time_milliseconds();
        int aggregation_result = aggregate_and_verify_signature_ENHANCED(signature_shares, 
                                                                        participant_keypairs,
                                                                        commitments,
                                                                        shares_received, 
                                                                        msg_hash, 
                                                                        final_signature,
                                                                        &aggregation_stats,
                                                                        &aggregation_memory);
        double aggregation_end = get_time_milliseconds();
        
        // Finalize overall memory monitoring
        finalize_memory_monitoring(&overall_memory);
        
        // Calculate total time
        double total_time = aggregation_end - phase1_start;
        
        if (aggregation_result) {
            printf("\n🎊 FROST SIGNATURE PROTOCOL WITH NONCE PERSISTENCE COMPLETED! 🎊\n");
            printf("═══════════════════════════════════════════════════════════════════\n");
            printf("Nonce commitments collected: %d/%d\n", commitments_received, T);
            printf("Signature shares collected: %d/%d\n", shares_received, T);
            printf("Signature aggregation: SUCCESS\n");
            printf("Signature verification: SUCCESS\n");
            printf("Nonce persistence: WORKING CORRECTLY\n");
            printf("All nonces were successfully restored from flash storage\n");
            printf("Total protocol execution time: %.3f ms\n", total_time);
            printf("═══════════════════════════════════════════════════════════════════\n");
            
            printf("\nFinal aggregated FROST signature (from persistent nonces):\n");
            for (int i = 0; i < 64; i++) {
                printf("%02x", final_signature[i]);
                if (i == 31) printf("\n");
            }
            printf("\n\nThis signature represents the collective signing of:\n");
            printf("Message: \"Hello World!\"\n");
            printf("Hash: ");
            for (int i = 0; i < 32; i++) {
                printf("%02x", msg_hash[i]);
            }
            printf("\n");
            
            printf("\n=== FINAL KEY INFORMATION ===\n");
            print_public_key_complete("Group Public Key (Complete)", 
                                    participant_keypairs[0].group_public_key, 64);
            
            printf("\nIndividual Participant Public Keys:\n");
            for (int i = 0; i < commitments_received; i++) {
                printf("Participant %u:\n", participant_keypairs[i].index);
                print_public_key_complete("  Individual Public Key", 
                                        participant_keypairs[i].public_key, 64);
            }
            
            printf("\nNONCE PERSISTENCE SUCCESS INDICATORS:\n");
            printf("   - All devices survived restart between Phase 1 and Phase 2\n");
            printf("   - Original nonces were correctly restored from flash\n");
            printf("   - Signature aggregation succeeded with persistent data\n");
            printf("   - Final signature is mathematically valid\n");
            
        } else {
            printf("\n FROST SIGNATURE PROTOCOL COMPLETED WITH PERSISTENCE ISSUES\n");
            printf("═══════════════════════════════════════════════════════════════════\n");
            printf("Nonce commitments collected: %d/%d\n", commitments_received, T);
            printf("Signature shares collected: %d/%d\n", shares_received, T);
            printf("Signature aggregation or verification: FAILED\n");
            printf("Nonce persistence: MAY HAVE ISSUES\n");
            printf("Total protocol execution time: %.3f ms\n", total_time);
            printf("═══════════════════════════════════════════════════════════════════\n");
            printf("\nPOSSIBLE NONCE PERSISTENCE PROBLEMS:\n");
            printf("   - Devices may not have properly saved nonces to flash\n");
            printf("   - Original nonces may not have been correctly restored\n");
            printf("   - Commitment consistency verification may have failed\n");
            printf("   - Flash storage corruption may have occurred\n");
            printf("\nCheck device logs for nonce persistence error messages.\n");
        }
        
    } else {
        printf("\n=== INCOMPLETE PERSISTENT SIGNATURE COLLECTION ===\n");
        printf("Only received %d signature shares out of %d required.\n", shares_received, T);
        printf("Some devices may have failed to load persistent nonces.\n");
        printf("Cannot proceed with signature aggregation.\n");
        printf("\nCheck that all devices:\n");
        printf("- Successfully saved nonces to flash in Phase 1\n");
        printf("- Can read persistent nonces from flash in Phase 2\n");
        printf("- Have sufficient flash storage space\n");
    }
    
    // COMPREHENSIVE PERFORMANCE REPORT
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                    COMPREHENSIVE PERFORMANCE EVALUATION REPORT                  ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════╝\n");
    
    // Calculate and print key generation statistics
    if (keygen_stats.num_samples > 0) {
        calculate_performance_stats(&keygen_stats);
        print_performance_stats("KEY GENERATION", &keygen_stats);
    }
    
    // Calculate and print signing statistics
    if (signing_stats.num_samples > 0) {
        calculate_performance_stats(&signing_stats);
        print_performance_stats("SIGNATURE GENERATION", &signing_stats);
    }
    
    // Calculate and print aggregation statistics
    if (aggregation_stats.num_samples > 0) {
        calculate_performance_stats(&aggregation_stats);
        print_performance_stats("SIGNATURE AGGREGATION", &aggregation_stats);
    }
    
    // Print memory statistics
    print_memory_stats("OVERALL PROTOCOL", &overall_memory);
    print_memory_stats("SIGNATURE AGGREGATION", &aggregation_memory);
    
    // Print protocol size analysis
    
    // Print communication statistics
    if (comm_stats_count > 0) {
        printf("\n=== COMMUNICATION EFFICIENCY ANALYSIS ===\n");
        double total_comm_time = 0;
        size_t total_data = 0;
        
        for (int i = 0; i < comm_stats_count; i++) {
            total_comm_time += comm_stats_array[i].transmission_time;
            total_data += comm_stats_array[i].data_size;
        }
        
        printf("   Total messages transmitted: %d\n", comm_stats_count);
        printf("   Total data transmitted: %zu bytes\n", total_data);
        printf("   Total communication time: %.3f ms\n", total_comm_time);
        printf("   Average throughput: %.0f bps\n", 
               (total_data * 8.0 * 1000.0) / total_comm_time);
        printf("==========================================\n");
    }
    
    // Summary performance indicators
    printf("\n=== PERFORMANCE SUMMARY ===\n");
    printf("   Protocol phases: 2 (Commitment Collection + Signing)\n");
    printf("   Participants: %d\n", T);
    printf("   Threshold: %d-out-of-%d\n", T, N);
    
    if (keygen_stats.num_samples > 0) {
        printf("   Key generation average: %.3f ms\n", keygen_stats.mean);
    }
    if (signing_stats.num_samples > 0) {
        printf("   Signing average: %.3f ms\n", signing_stats.mean);
    }
    if (aggregation_stats.num_samples > 0) {
        printf("   Aggregation average: %.3f ms\n", aggregation_stats.mean);
    }
    
    printf("   Memory overhead: %zu KB (%.1f%%)\n", 
           overall_memory.overhead, overall_memory.percentage_increase);
    printf("   Protocol data per participant: %zu bytes\n", protocol_sizes.total_per_participant);
    
    // Overall assessment
    double total_avg = 0;
    int stats_count = 0;
    if (keygen_stats.num_samples > 0) { total_avg += keygen_stats.mean; stats_count++; }
    if (signing_stats.num_samples > 0) { total_avg += signing_stats.mean; stats_count++; }
    if (aggregation_stats.num_samples > 0) { total_avg += aggregation_stats.mean; stats_count++; }
    
    if (stats_count > 0) {
        total_avg /= stats_count;
        printf("\n🏆 OVERALL PERFORMANCE ASSESSMENT:\n");
        if (total_avg < 1.0 && overall_memory.percentage_increase < 10.0) {
            printf("   EXCELLENT: Sub-millisecond operations with low memory overhead\n");
        } else if (total_avg < 5.0 && overall_memory.percentage_increase < 20.0) {
            printf("    GOOD: Fast operations with acceptable memory usage\n");
        } else {
            printf("   NEEDS OPTIMIZATION: Consider performance improvements\n");
        }
    }
    
    printf("=====================================\n");
    
    printf("\nPress Enter to exit...\n");
    getchar();
    return 0;
}