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
#include <math.h>
#include <psapi.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")
#pragma comment(lib, "psapi.lib")

#define N 3
#define T 2
#define NUM_BENCHMARK_RUNS 50  

#define VENDOR_ID 0x2FE3   
#define PRODUCT_ID 0x100   

// PERFORMANCE EVALUATION STRUCTURES

typedef struct {
    double measurements[NUM_BENCHMARK_RUNS];
    double mean;
    double std_deviation;
    double min_value;
    double max_value;
    int num_samples;
} performance_stats_t;

typedef struct {
    performance_stats_t key_generation;
    performance_stats_t secret_share_transmission;
    performance_stats_t public_key_transmission;
    performance_stats_t commitments_transmission;
    performance_stats_t end_transmission;
    performance_stats_t total_distribution_time;
} timing_benchmarks_t;

typedef struct {
    size_t secret_share_size;
    size_t public_key_size;
    size_t commitments_size;
    size_t message_header_size;
    size_t total_protocol_overhead;
    size_t uart_chunked_overhead;
    size_t hid_chunked_overhead;
} message_size_analysis_t;

typedef struct {
    SIZE_T initial_memory;
    SIZE_T peak_memory;
    SIZE_T final_memory;
    SIZE_T memory_overhead;
} memory_analysis_t;

// COMMUNICATION STRUCTURES

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
        };
    };
} comm_handle_t;

#define MSG_HEADER_MAGIC 0x46524F53
#define MSG_VERSION 0x01

typedef enum {
    MSG_TYPE_SECRET_SHARE = 0x01,
    MSG_TYPE_PUBLIC_KEY = 0x02,
    MSG_TYPE_COMMITMENTS = 0x03,
    MSG_TYPE_END_TRANSMISSION = 0xFF
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
    uint32_t receiver_index;
    uint8_t value[32];
} serialized_share_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t index;
    uint32_t max_participants;
    uint8_t public_key[64];
    uint8_t group_public_key[64];
} serialized_pubkey_t;
#pragma pack(pop)

// Global timing variables (initialize once)
static LARGE_INTEGER g_frequency = {0};
static bool g_timing_initialized = false;

// Initialize timing system once
void initialize_timing() {
    if (!g_timing_initialized) {
        QueryPerformanceFrequency(&g_frequency);
        g_timing_initialized = true;
        
        // Set process priority
        SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        
        printf("Timing system initialized. Frequency: %lld Hz\n", g_frequency.QuadPart);
    }
}

// Timing function
double get_time_milliseconds_fast() {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / (double)g_frequency.QuadPart;
}

// Timing function for compatibility
double get_time_milliseconds() {
    if (!g_timing_initialized) {
        initialize_timing();
    }
    return get_time_milliseconds_fast();
}

SIZE_T get_current_memory_usage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize;
    }
    return 0;
}

void calculate_statistics(performance_stats_t* stats) {
    if (stats->num_samples == 0) return;
    
    // Calculate mean
    double sum = 0.0;
    stats->min_value = stats->measurements[0];
    stats->max_value = stats->measurements[0];
    
    for (int i = 0; i < stats->num_samples; i++) {
        sum += stats->measurements[i];
        if (stats->measurements[i] < stats->min_value) {
            stats->min_value = stats->measurements[i];
        }
        if (stats->measurements[i] > stats->max_value) {
            stats->max_value = stats->measurements[i];
        }
    }
    stats->mean = sum / stats->num_samples;
    
    // Calculate standard deviation
    double variance_sum = 0.0;
    for (int i = 0; i < stats->num_samples; i++) {
        double diff = stats->measurements[i] - stats->mean;
        variance_sum += diff * diff;
    }
    stats->std_deviation = sqrt(variance_sum / (stats->num_samples - 1));
}

void add_measurement(performance_stats_t* stats, double measurement) {
    if (stats->num_samples < NUM_BENCHMARK_RUNS) {
        stats->measurements[stats->num_samples] = measurement;
        stats->num_samples++;
    }
}

void print_performance_stats(const char* operation_name, const performance_stats_t* stats) {
    printf("\n--- %s Performance Statistics ---\n", operation_name);
    printf("Mean: %.6f ms (σ = %.6f)\n", stats->mean, stats->std_deviation);
    printf("Min: %.6f ms, Max: %.6f ms\n", stats->min_value, stats->max_value);
    printf("Coefficient of Variation: %.2f%%\n", (stats->std_deviation / stats->mean) * 100.0);
    printf("Samples: %d\n", stats->num_samples);
}

void print_detailed_measurements(const char* operation_name, const performance_stats_t* stats) {
    printf("\n--- Detailed Measurements for %s ---\n", operation_name);
    printf("Iteration\tTime (ms)\n");
    for (int i = 0; i < stats->num_samples; i++) {
        printf("%d\t\t%.6f\n", i + 1, stats->measurements[i]);
    }
}

void analyze_message_sizes(message_size_analysis_t* analysis) {
    printf("\n=== MESSAGE SIZE ANALYSIS ===\n");
    
    analysis->message_header_size = sizeof(message_header_t);
    analysis->secret_share_size = sizeof(serialized_share_t);
    analysis->public_key_size = sizeof(serialized_pubkey_t);
    
    // Estimate commitments size (variable based on coefficients)
    analysis->commitments_size = sizeof(uint32_t) * 2 + 32 + 64 + (T * 64); // Estimated
    
    analysis->total_protocol_overhead = analysis->message_header_size * 4; // 4 message types
    
    // Calculate chunking overhead for different communication methods
    analysis->uart_chunked_overhead = 0; // No chunking overhead for UART
    
    size_t total_data = analysis->secret_share_size + analysis->public_key_size + analysis->commitments_size;
    int estimated_hid_reports = (total_data / 60) + 1; 
    analysis->hid_chunked_overhead = estimated_hid_reports * 2; // 2 bytes overhead per report
    
    printf("Message Header Size: %zu bytes\n", analysis->message_header_size);
    printf("Secret Share Size: %zu bytes\n", analysis->secret_share_size);
    printf("Public Key Size: %zu bytes\n", analysis->public_key_size);
    printf("Commitments Size (estimated): %zu bytes\n", analysis->commitments_size);
    printf("Total Protocol Overhead: %zu bytes\n", analysis->total_protocol_overhead);
    printf("UART Chunking Overhead: %zu bytes\n", analysis->uart_chunked_overhead);
    printf("HID Chunking Overhead (estimated): %zu bytes\n", analysis->hid_chunked_overhead);
    
    size_t total_per_participant = analysis->secret_share_size + analysis->public_key_size + 
                                   analysis->commitments_size + analysis->total_protocol_overhead;
    printf("Total Data per Participant: %zu bytes\n", total_per_participant);
    printf("Total Data for %d Participants: %zu bytes\n", N, total_per_participant * N);
}

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
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

BOOL send_message_timed(comm_handle_t* comm, uint8_t msg_type, uint32_t participant, 
                       const void* payload, uint16_t payload_len, double* elapsed_time) {
    double start_time = get_time_milliseconds();
    
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
    
    double end_time = get_time_milliseconds();
    *elapsed_time = end_time - start_time;
    
    if (result) {
        printf("Message sent successfully in %.3f ms\n", *elapsed_time);
        Sleep(1000);
    }
    
    return result;
}

BOOL send_message(comm_handle_t* comm, uint8_t msg_type, uint32_t participant, 
                  const void* payload, uint16_t payload_len) {
    double elapsed_time;
    return send_message_timed(comm, msg_type, participant, payload, payload_len, &elapsed_time);
}

BOOL send_secret_share_timed(comm_handle_t* comm, uint32_t participant, 
                           const secp256k1_frost_keygen_secret_share *share, double* elapsed_time) {
    serialized_share_t serialized;
    serialized.receiver_index = share->receiver_index;
    memcpy(serialized.value, share->value, sizeof(serialized.value));
    
    return send_message_timed(comm, MSG_TYPE_SECRET_SHARE, participant,
                             &serialized, sizeof(serialized), elapsed_time);
}

BOOL send_public_key_timed(comm_handle_t* comm, uint32_t participant, 
                          const secp256k1_frost_pubkey *pubkey, double* elapsed_time) {
    serialized_pubkey_t serialized;
    serialized.index = pubkey->index;
    serialized.max_participants = pubkey->max_participants;
    memcpy(serialized.public_key, pubkey->public_key, sizeof(serialized.public_key));
    memcpy(serialized.group_public_key, pubkey->group_public_key, sizeof(serialized.group_public_key));
    
    return send_message_timed(comm, MSG_TYPE_PUBLIC_KEY, participant,
                             &serialized, sizeof(serialized), elapsed_time);
}

BOOL send_commitments_timed(comm_handle_t* comm, uint32_t participant, 
                           const secp256k1_frost_vss_commitments *commitments, double* elapsed_time) {
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
    
    BOOL result = send_message_timed(comm, MSG_TYPE_COMMITMENTS, participant,
                                    buffer, (uint16_t)total_size, elapsed_time);
    
    free(buffer);
    return result;
}

BOOL send_end_transmission_timed(comm_handle_t* comm, uint32_t participant, double* elapsed_time) {
    return send_message_timed(comm, MSG_TYPE_END_TRANSMISSION, participant, NULL, 0, elapsed_time);
}

// Wrapper functions for backward compatibility
BOOL send_secret_share(comm_handle_t* comm, uint32_t participant, 
                       const secp256k1_frost_keygen_secret_share *share) {
    double elapsed_time;
    return send_secret_share_timed(comm, participant, share, &elapsed_time);
}

BOOL send_public_key(comm_handle_t* comm, uint32_t participant, 
                    const secp256k1_frost_pubkey *pubkey) {
    double elapsed_time;
    return send_public_key_timed(comm, participant, pubkey, &elapsed_time);
}

BOOL send_commitments(comm_handle_t* comm, uint32_t participant, 
                     const secp256k1_frost_vss_commitments *commitments) {
    double elapsed_time;
    return send_commitments_timed(comm, participant, commitments, &elapsed_time);
}

BOOL send_end_transmission(comm_handle_t* comm, uint32_t participant) {
    double elapsed_time;
    return send_end_transmission_timed(comm, participant, &elapsed_time);
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

void benchmark_key_generation(timing_benchmarks_t* benchmarks, memory_analysis_t* memory_analysis) {
    printf("\n=== OPTIMIZED KEY GENERATION BENCHMARKING ===\n");
    printf("Running %d iterations...\n", NUM_BENCHMARK_RUNS);
    
    if (!g_timing_initialized) {
        initialize_timing();
    }
    
    // Pre-allocate all memory outside timing loop
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("Failed to create context for benchmarking!\n");
        return;
    }
    
    // Pre-allocate arrays
    secp256k1_frost_keygen_secret_share (*shares_array)[N] = malloc(NUM_BENCHMARK_RUNS * sizeof(*shares_array));
    secp256k1_frost_keypair (*keypairs_array)[N] = malloc(NUM_BENCHMARK_RUNS * sizeof(*keypairs_array));
    secp256k1_frost_vss_commitments **commitments_array = malloc(NUM_BENCHMARK_RUNS * sizeof(secp256k1_frost_vss_commitments*));
    
    if (!shares_array || !keypairs_array || !commitments_array) {
        printf("Failed to allocate memory for benchmarking!\n");
        goto cleanup;
    }
    
    // Pre-create all commitments
    for (int i = 0; i < NUM_BENCHMARK_RUNS; i++) {
        commitments_array[i] = secp256k1_frost_vss_commitments_create(T);
        if (!commitments_array[i]) {
            printf("Failed to pre-create commitments for iteration %d\n", i);
            goto cleanup;
        }
    }
    
    // Initial memory measurement
    memory_analysis->initial_memory = get_current_memory_usage();
    
    printf("Starting precise timing measurements...\n");
    
    // Main benchmarking loop
    for (int i = 0; i < NUM_BENCHMARK_RUNS; i++) {
        // Reset commitments state
        secp256k1_frost_vss_commitments_destroy(commitments_array[i]);
        commitments_array[i] = secp256k1_frost_vss_commitments_create(T);
        
        double start_time = get_time_milliseconds_fast();
        
        int return_val = secp256k1_frost_keygen_with_dealer(
            ctx, commitments_array[i], shares_array[i], keypairs_array[i], N, T
        );
        
        double end_time = get_time_milliseconds_fast();
        
        double elapsed = end_time - start_time;
        
        if (return_val == 1) {
            add_measurement(&benchmarks->key_generation, elapsed);
            if (i % 10 == 0) { // Print every 10th iteration
                printf("Iteration %d: %.6f ms\n", i + 1, elapsed);
            }
        } else {
            printf("Key generation failed at iteration %d\n", i + 1);
        }
    }
    
    // Take final memory measurement
    memory_analysis->peak_memory = get_current_memory_usage();
    memory_analysis->final_memory = memory_analysis->peak_memory;
    memory_analysis->memory_overhead = memory_analysis->peak_memory - memory_analysis->initial_memory;
    
cleanup:
    // Cleanup
    if (commitments_array) {
        for (int i = 0; i < NUM_BENCHMARK_RUNS; i++) {
            if (commitments_array[i]) {
                secp256k1_frost_vss_commitments_destroy(commitments_array[i]);
            }
        }
        free(commitments_array);
    }
    
    free(shares_array);
    free(keypairs_array);
    secp256k1_context_destroy(ctx);
    
    // Reset process priority
    SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    
    calculate_statistics(&benchmarks->key_generation);
    print_performance_stats("Key Generation", &benchmarks->key_generation);
}

void benchmark_communication_protocols(timing_benchmarks_t* benchmarks, 
                                      secp256k1_frost_keygen_secret_share* shares,
                                      secp256k1_frost_pubkey* public_keys,
                                      secp256k1_frost_vss_commitments* commitments) {
    printf("\n=== BENCHMARKING COMMUNICATION PROTOCOLS ===\n");
    
    printf("Choose communication method for benchmarking:\n");
    printf("1. UART/Serial\n");
    printf("2. USB HID\n");
    printf("3. Both (recommended)\n");
    printf("Enter choice: ");
    
    int choice;
    scanf("%d", &choice);
    getchar();
    
    if (choice == 1 || choice == 3) {
        printf("\nBenchmarking UART communication...\n");
        printf("Enter COM port: ");
        char port_name[10];
        scanf("%s", port_name);
        getchar();
        
        HANDLE uart_handle = setup_uart_port(port_name);
        if (uart_handle != INVALID_HANDLE_VALUE) {
            comm_handle_t uart_comm = {0};
            uart_comm.type = COMM_TYPE_UART;
            uart_comm.uart_handle = uart_handle;
            
            // Benchmark each communication type
            printf("Benchmarking secret share transmission...\n");
            for (int i = 0; i < NUM_BENCHMARK_RUNS && i < N; i++) {
                double elapsed_time;
                if (send_secret_share_timed(&uart_comm, i + 1, &shares[i], &elapsed_time)) {
                    add_measurement(&benchmarks->secret_share_transmission, elapsed_time);
                    printf("Iteration %d: %.3f ms\n", i + 1, elapsed_time);
                }
                Sleep(100);
            }
            
            printf("Benchmarking public key transmission...\n");
            for (int i = 0; i < NUM_BENCHMARK_RUNS && i < N; i++) {
                double elapsed_time;
                if (send_public_key_timed(&uart_comm, i + 1, &public_keys[i], &elapsed_time)) {
                    add_measurement(&benchmarks->public_key_transmission, elapsed_time);
                    printf("Iteration %d: %.3f ms\n", i + 1, elapsed_time);
                }
                Sleep(100);
            }
            
            printf("Benchmarking commitments transmission...\n");
            for (int i = 0; i < NUM_BENCHMARK_RUNS && i < N; i++) {
                double elapsed_time;
                if (send_commitments_timed(&uart_comm, i + 1, commitments, &elapsed_time)) {
                    add_measurement(&benchmarks->commitments_transmission, elapsed_time);
                    printf("Iteration %d: %.3f ms\n", i + 1, elapsed_time);
                }
                Sleep(100);
            }
            
            CloseHandle(uart_handle);
        }
    }
    
    if (choice == 2 || choice == 3) {
        printf("\nBenchmarking HID communication...\n");
        comm_handle_t hid_comm = find_hid_device(VENDOR_ID, PRODUCT_ID);
        if (hid_comm.type == COMM_TYPE_USB_HID) {
            printf("Note: HID benchmarks will be added to existing UART results for comparison\n");
            
            close_communication(&hid_comm);
        }
    }
    
    calculate_statistics(&benchmarks->secret_share_transmission);
    calculate_statistics(&benchmarks->public_key_transmission);
    calculate_statistics(&benchmarks->commitments_transmission);
    
    print_performance_stats("Secret Share Transmission", &benchmarks->secret_share_transmission);
    print_performance_stats("Public Key Transmission", &benchmarks->public_key_transmission);
    print_performance_stats("Commitments Transmission", &benchmarks->commitments_transmission);
}

void print_comprehensive_results(const timing_benchmarks_t* benchmarks, 
                               const message_size_analysis_t* message_analysis,
                               const memory_analysis_t* memory_analysis) {
    printf("\n");
    printf("=====================================\n");
    printf("    COMPREHENSIVE EVALUATION RESULTS\n");
    printf("=====================================\n");
    
    // Performance Summary Table
    printf("\n--- PERFORMANCE SUMMARY ---\n");
    printf("Operation\t\t\tMean (ms)\tStd Dev (σ)\tMin (ms)\tMax (ms)\n");
    printf("Key Generation\t\t\t%.6f\t%.6f\t%.6f\t%.6f\n",
           benchmarks->key_generation.mean, benchmarks->key_generation.std_deviation,
           benchmarks->key_generation.min_value, benchmarks->key_generation.max_value);
    
    if (benchmarks->secret_share_transmission.num_samples > 0) {
        printf("Secret Share Transmission\t%.6f\t%.6f\t%.6f\t%.6f\n",
               benchmarks->secret_share_transmission.mean, benchmarks->secret_share_transmission.std_deviation,
               benchmarks->secret_share_transmission.min_value, benchmarks->secret_share_transmission.max_value);
    }
    
    if (benchmarks->public_key_transmission.num_samples > 0) {
        printf("Public Key Transmission\t\t%.6f\t%.6f\t%.6f\t%.6f\n",
               benchmarks->public_key_transmission.mean, benchmarks->public_key_transmission.std_deviation,
               benchmarks->public_key_transmission.min_value, benchmarks->public_key_transmission.max_value);
    }
    
    if (benchmarks->commitments_transmission.num_samples > 0) {
        printf("Commitments Transmission\t%.6f\t%.6f\t%.6f\t%.6f\n",
               benchmarks->commitments_transmission.mean, benchmarks->commitments_transmission.std_deviation,
               benchmarks->commitments_transmission.min_value, benchmarks->commitments_transmission.max_value);
    }
    
    // Memory Analysis
    printf("\n--- MEMORY USAGE ANALYSIS ---\n");
    printf("Initial Memory: %zu KB\n", memory_analysis->initial_memory / 1024);
    printf("Peak Memory: %zu KB\n", memory_analysis->peak_memory / 1024);
    printf("Final Memory: %zu KB\n", memory_analysis->final_memory / 1024);
    printf("Memory Overhead: %zu KB\n", memory_analysis->memory_overhead / 1024);
    
    // Message Size Analysis
    printf("\n--- MESSAGE SIZE ANALYSIS ---\n");
    printf("Protocol Component\t\tSize (bytes)\n");
    printf("Message Header\t\t\t%zu\n", message_analysis->message_header_size);
    printf("Secret Share\t\t\t%zu\n", message_analysis->secret_share_size);
    printf("Public Key\t\t\t%zu\n", message_analysis->public_key_size);
    printf("Commitments (estimated)\t\t%zu\n", message_analysis->commitments_size);
    printf("Total Protocol Overhead\t\t%zu\n", message_analysis->total_protocol_overhead);
    
    // Network Analysis
    printf("\n--- NETWORK COMMUNICATION ANALYSIS ---\n");
    printf("Communication Method\t\tOverhead\t\tSuitability\n");
    printf("UART (115200 baud)\t\t%zu bytes\t\tHigh reliability\n", message_analysis->uart_chunked_overhead);
    printf("USB HID\t\t\t\t%zu bytes\t\tPlug-and-play\n", message_analysis->hid_chunked_overhead);
    
    printf("\n--- FROST PROTOCOL CHARACTERISTICS ---\n");
    printf("Participants (N): %d\n", N);
    printf("Threshold (T): %d\n", T);
    printf("Security: SECP256K1 equivalent\n");
    printf("Key Generation: Distributed with dealer\n");
    printf("Signing: Requires %d-of-%d participants\n", T, N);
    printf("Communication Rounds: 4 per participant setup\n");
    
    printf("\n=====================================\n");
    printf("    EVALUATION COMPLETE\n");
    printf("=====================================\n");
}

int main(void) {
    printf("=====================================\n");
    printf("  FROST PERFORMANCE EVALUATION SYSTEM\n");
    printf("=====================================\n");
    printf("Threshold: %d-of-%d, Benchmarks: %d iterations\n\n", T, N, NUM_BENCHMARK_RUNS);

    // Initialize evaluation structures
    timing_benchmarks_t benchmarks = {0};
    message_size_analysis_t message_analysis = {0};
    memory_analysis_t memory_analysis = {0};
    
    secp256k1_context *ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[N];
    secp256k1_frost_keypair keypairs[N];
    secp256k1_frost_pubkey public_keys[N];
    int return_val;

    printf("=== Starting FROST Key Generation and Distribution ===\n\n");

    benchmark_key_generation(&benchmarks, &memory_analysis);
    
    analyze_message_sizes(&message_analysis);
    
    printf("\n=== Generating actual keys for distribution ===\n");
    
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("Failed to create context!\n");
        return 1;
    }

    dealer_commitments = secp256k1_frost_vss_commitments_create(T);
    if (!dealer_commitments) {
        printf("Failed to create commitments!\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }

    return_val = secp256k1_frost_keygen_with_dealer(
        ctx, dealer_commitments, shares_by_participant, keypairs, N, T
    );
    if (return_val != 1) {
        printf("Key generation failed!\n");
        secp256k1_frost_vss_commitments_destroy(dealer_commitments);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    for (int i = 0; i < N; i++) {
        secp256k1_frost_pubkey_from_keypair(&public_keys[i], &keypairs[i]);
    }

    printf("\n=== Participants ===\n\n");
    for (int i = 0; i < N; i++) {
        printf("Participant %d:\n", i + 1);
        printf("  Receiver Index: %u\n", shares_by_participant[i].receiver_index);
        print_hex("  Secret Share", shares_by_participant[i].value, 32);
        print_hex("  Public Key", keypairs[i].public_keys.public_key, 64);
        print_hex("  Group Public Key", keypairs[i].public_keys.group_public_key, 64);
        printf("\n");
    }

    printf("\n=== Communication Benchmarking ===\n");
    printf("Do you want to benchmark communication protocols? (y/n): ");
    char choice;
    scanf(" %c", &choice);
    getchar();
    
    if (choice == 'y' || choice == 'Y') {
        benchmark_communication_protocols(&benchmarks, shares_by_participant, public_keys, dealer_commitments);
    }

    printf("\n=== Starting Key Distribution ===\n\n");
    
    for (int i = 0; i < N; i++) {
        printf("Preparing to send data to participant %d's device...\n", i + 1);
        
        comm_handle_t comm = setup_communication(i + 1);
        if (comm.type == 0) {
            printf("Failed to set up communication for participant %d. Skipping.\n", i + 1);
            continue;
        }
        
        double total_start_time = get_time_milliseconds();
        
        printf("Sending data to participant %d...\n", i + 1);
        
        if (!send_secret_share(&comm, i + 1, &shares_by_participant[i])) {
            printf("Failed to send secret share to participant %d.\n", i + 1);
            close_communication(&comm);
            continue;
        }
        printf("Secret share sent successfully. Waiting...\n");
        Sleep(2000);
        
        if (!send_public_key(&comm, i + 1, &public_keys[i])) {
            printf("Failed to send public key to participant %d.\n", i + 1);
            close_communication(&comm);
            continue;
        }
        printf("Public key sent successfully. Waiting...\n");
        Sleep(2000);
        
        if (!send_commitments(&comm, i + 1, dealer_commitments)) {
            printf("Failed to send commitments to participant %d.\n", i + 1);
            close_communication(&comm);
            continue;
        }
        printf("Commitments sent successfully. Waiting before end transmission...\n");
        Sleep(3000);
        
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
                Sleep(1000);
            }
        }
        
        double total_end_time = get_time_milliseconds();
        double total_distribution_time = total_end_time - total_start_time;
        add_measurement(&benchmarks.total_distribution_time, total_distribution_time);
        
        if (!end_sent) {
            printf("Warning: Could not send end transmission after 3 attempts.\n");
            printf("Participant %d should still have received all key data.\n", i + 1);
        }
        
        printf("Successfully sent all data to participant %d in %.3f ms.\n", i + 1, total_distribution_time);
        close_communication(&comm);
        Sleep(2000);
    }
    
    calculate_statistics(&benchmarks.total_distribution_time);
    print_comprehensive_results(&benchmarks, &message_analysis, &memory_analysis);
    
    printf("\nDo you want to see detailed measurement tables? (y/n): ");
    scanf(" %c", &choice);
    if (choice == 'y' || choice == 'Y') {
        print_detailed_measurements("Key Generation", &benchmarks.key_generation);
        if (benchmarks.secret_share_transmission.num_samples > 0) {
            print_detailed_measurements("Secret Share Transmission", &benchmarks.secret_share_transmission);
        }
        if (benchmarks.total_distribution_time.num_samples > 0) {
            print_detailed_measurements("Total Distribution Time", &benchmarks.total_distribution_time);
        }
    }
    
    printf("\n=== Key Distribution Completed ===\n");
    
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    secp256k1_context_destroy(ctx);
    return 0;
}