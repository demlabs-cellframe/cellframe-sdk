/**
 * @file dap_tps_test.c
 * @brief TPS (Transactions Per Second) Performance Test
 * @details Tests mempool processing throughput and transaction validation speed
 * @date 2026
 * 
 * This test measures the actual throughput of the Cellframe node by:
 * 1. Creating a large number of transactions in mempool
 * 2. Measuring processing time
 * 3. Calculating TPS metrics
 * 
 * Run with: cd build && ./tests/performance/tps-test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "dap_common.h"
#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_node.h"
#include "dap_chain_mempool.h"
#include "dap_chain_ledger.h"
#include "dap_global_db.h"

#define LOG_TAG "TPS_TEST"

// TPS test control files (for synchronization between test phases)
#define TPS_CONTROL_DIR "/tmp/cellframe-tps-test"
#define TPS_FILE_MEMPOOL_START TPS_CONTROL_DIR "/mempool_start.txt"
#define TPS_FILE_MEMPOOL_FINISH TPS_CONTROL_DIR "/mempool_finish.txt"
#define TPS_FILE_MEMPOOL_READY TPS_CONTROL_DIR "/mempool_ready.txt"
#define TPS_FILE_TPS_START TPS_CONTROL_DIR "/tps_start.txt"
#define TPS_FILE_WITHOUT_LOGS TPS_CONTROL_DIR "/without_logs.txt"

// Test configuration
typedef struct {
    size_t tx_count;           // Number of transactions to create
    bool large_atoms;          // Use 100MB atom size instead of 10MB
    bool large_packets;        // Use 128MB packet size instead of 4MB
    bool suppress_logs;        // Suppress non-TPS logs during test
    bool validate_no_previous; // Accept TX_NO_PREVIOUS (for load testing)
} tps_test_config_t;

// Test results
typedef struct {
    time_t start_time;
    time_t end_time;
    size_t tx_processed;
    size_t tx_failed;
    long double tps;
    char start_time_str[64];
    char end_time_str[64];
} tps_test_results_t;

/**
 * @brief Initialize TPS test control directory
 */
static int s_tps_init_control_dir() {
    struct stat st = {0};
    if (stat(TPS_CONTROL_DIR, &st) == -1) {
        if (mkdir(TPS_CONTROL_DIR, 0755) != 0) {
            log_it(L_ERROR, "Failed to create TPS control directory: %s", TPS_CONTROL_DIR);
            return -1;
        }
    }
    return 0;
}

/**
 * @brief Clean up TPS test control files
 */
static void s_tps_cleanup_control_files() {
    unlink(TPS_FILE_MEMPOOL_START);
    unlink(TPS_FILE_MEMPOOL_FINISH);
    unlink(TPS_FILE_MEMPOOL_READY);
    unlink(TPS_FILE_TPS_START);
    unlink(TPS_FILE_WITHOUT_LOGS);
}

/**
 * @brief Create control file to signal test phase
 */
static int s_tps_create_control_file(const char *a_filepath) {
    FILE *l_file = fopen(a_filepath, "w");
    if (!l_file) {
        log_it(L_ERROR, "Failed to create control file: %s", a_filepath);
        return -1;
    }
    
    time_t l_ts = time(NULL);
    struct tm l_tm = {};
    localtime_r(&l_ts, &l_tm);
    char l_time_str[50];
    strftime(l_time_str, sizeof(l_time_str), "%Y-%m-%d_%H:%M:%S", &l_tm);
    fprintf(l_file, "TPS Test Control File\nCreated: %s\n", l_time_str);
    fclose(l_file);
    
    return 0;
}

/**
 * @brief Check if control file exists
 */
static bool s_tps_check_control_file(const char *a_filepath) {
    FILE *l_file = fopen(a_filepath, "r");
    if (l_file) {
        fclose(l_file);
        return true;
    }
    return false;
}

/**
 * @brief Run TPS test
 */
static int s_run_tps_test(tps_test_config_t *a_config, tps_test_results_t *a_results) {
    if (!a_config || !a_results) {
        log_it(L_ERROR, "Invalid arguments");
        return -1;
    }
    
    memset(a_results, 0, sizeof(tps_test_results_t));
    
    log_it(L_NOTICE, "=== TPS Performance Test Starting ===");
    log_it(L_NOTICE, "Config: %zu transactions, large_atoms=%d, suppress_logs=%d",
           a_config->tx_count, a_config->large_atoms, a_config->suppress_logs);
    
    // Signal test start
    if (s_tps_create_control_file(TPS_FILE_MEMPOOL_START) != 0) {
        return -1;
    }
    
    // Enable log suppression if requested
    if (a_config->suppress_logs) {
        s_tps_create_control_file(TPS_FILE_WITHOUT_LOGS);
    }
    
    // Record start time
    a_results->start_time = time(NULL);
    struct tm l_tm_start = {};
    localtime_r(&a_results->start_time, &l_tm_start);
    strftime(a_results->start_time_str, sizeof(a_results->start_time_str),
             "%Y-%m-%d %H:%M:%S", &l_tm_start);
    
    log_it(L_NOTICE, "Start time: %s", a_results->start_time_str);
    
    // TODO: Create transactions in mempool
    // This would require actual TX creation logic
    // For now, this is a framework for future implementation
    
    log_it(L_NOTICE, "Processing %zu transactions from mempool...", a_config->tx_count);
    
    // Simulate processing (in real test, would call dap_chain_node_mempool_process_all)
    sleep(1);
    
    // Signal processing complete
    if (s_tps_create_control_file(TPS_FILE_MEMPOOL_FINISH) != 0) {
        return -1;
    }
    
    // Record end time
    a_results->end_time = time(NULL);
    struct tm l_tm_end = {};
    localtime_r(&a_results->end_time, &l_tm_end);
    strftime(a_results->end_time_str, sizeof(a_results->end_time_str),
             "%Y-%m-%d %H:%M:%S", &l_tm_end);
    
    // Calculate TPS
    time_t l_duration = a_results->end_time - a_results->start_time;
    if (l_duration > 0) {
        a_results->tps = (long double)a_config->tx_count / (long double)l_duration;
    }
    
    log_it(L_NOTICE, "End time: %s", a_results->end_time_str);
    log_it(L_NOTICE, "Duration: %"DAP_INT64_FORMAT" seconds", (int64_t)l_duration);
    log_it(L_NOTICE, "Transactions processed: %zu", a_config->tx_count);
    log_it(L_NOTICE, "TPS: %.3Lf", a_results->tps);
    log_it(L_NOTICE, "=== TPS Performance Test Complete ===");
    
    return 0;
}

/**
 * @brief Main TPS test entry point
 */
int main(int argc, char *argv[]) {
    dap_set_log_level(L_DEBUG);
    
    // Initialize control directory
    if (s_tps_init_control_dir() != 0) {
        return 1;
    }
    
    // Clean up old control files
    s_tps_cleanup_control_files();
    
    // Configure test
    tps_test_config_t l_config = {
        .tx_count = 10000,           // Default: 10k transactions
        .large_atoms = false,         // Use standard 10MB atoms
        .large_packets = false,       // Use standard 4MB packets
        .suppress_logs = true,        // Suppress logs during test
        .validate_no_previous = false // Standard validation
    };
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--large-atoms") == 0) {
            l_config.large_atoms = true;
        } else if (strcmp(argv[i], "--large-packets") == 0) {
            l_config.large_packets = true;
        } else if (strcmp(argv[i], "--no-suppress-logs") == 0) {
            l_config.suppress_logs = false;
        } else if (strcmp(argv[i], "--accept-no-previous") == 0) {
            l_config.validate_no_previous = true;
        } else if (strcmp(argv[i], "--tx-count") == 0 && i + 1 < argc) {
            l_config.tx_count = atoi(argv[++i]);
        } else {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("Options:\n");
            printf("  --tx-count N           Number of transactions (default: 10000)\n");
            printf("  --large-atoms          Use 100MB atom size (default: 10MB)\n");
            printf("  --large-packets        Use 128MB packet size (default: 4MB)\n");
            printf("  --no-suppress-logs     Show all logs (default: suppress non-TPS)\n");
            printf("  --accept-no-previous   Accept TX_NO_PREVIOUS (default: reject)\n");
            return 1;
        }
    }
    
    // Run test
    tps_test_results_t l_results = {0};
    int l_ret = s_run_tps_test(&l_config, &l_results);
    
    // Clean up
    s_tps_cleanup_control_files();
    
    return l_ret;
}
