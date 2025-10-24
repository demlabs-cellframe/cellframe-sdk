/**
 * @file dap_chain_net_vpn_client_connectivity_test.h
 * @brief Connectivity and speed testing for VPN protocols
 * @details Tests throughput, latency, and Internet connectivity through established tunnels
 * @date 2025-10-23
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "dap_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct dap_vpn_connectivity_test dap_vpn_connectivity_test_t;

/**
 * @brief Test status
 */
typedef enum {
    CONNECTIVITY_TEST_STATUS_IDLE = 0,       ///< Not started
    CONNECTIVITY_TEST_STATUS_TESTING,        ///< Test in progress
    CONNECTIVITY_TEST_STATUS_SUCCESS,        ///< Test passed
    CONNECTIVITY_TEST_STATUS_FAILED,         ///< Test failed
    CONNECTIVITY_TEST_STATUS_TIMEOUT         ///< Test timed out
} dap_vpn_connectivity_test_status_t;

/**
 * @brief Test result structure
 */
typedef struct {
    // Protocol info
    char *protocol_name;                     ///< Protocol name
    dap_stream_t *stream;                    ///< Stream connection
    
    // Performance metrics
    float throughput_mbps;                   ///< Measured throughput (Mbps)
    uint32_t latency_ms;                     ///< Average latency (ms)
    uint32_t latency_min_ms;                 ///< Minimum latency
    uint32_t latency_max_ms;                 ///< Maximum latency
    float packet_loss_percent;               ///< Packet loss percentage
    float jitter_ms;                         ///< Jitter (latency variation)
    
    // Connectivity checks
    bool dns_working;                        ///< DNS resolution works
    bool http_working;                       ///< HTTP connectivity works
    bool https_working;                      ///< HTTPS connectivity works
    bool captive_portal_detected;            ///< Captive portal detected
    
    // Composite score
    float score;                             ///< Overall quality score (0.0-1.0)
    
    // Status
    dap_vpn_connectivity_test_status_t status;
    char *failure_reason;                    ///< Failure reason if failed
    
    // Timing
    uint64_t test_start_ts;                  ///< Test start timestamp (ms)
    uint64_t test_end_ts;                    ///< Test end timestamp (ms)
    uint32_t test_duration_ms;               ///< Total test duration
} dap_vpn_connectivity_result_t;

/**
 * @brief Test completion callback
 */
typedef void (*dap_vpn_connectivity_test_callback_t)(
    dap_vpn_connectivity_test_t *test,
    dap_vpn_connectivity_result_t *result,
    void *user_data
);

/**
 * @brief Test parameters
 */
typedef struct {
    // Connection info
    dap_stream_t *stream;                    ///< Stream to test
    const char *protocol_name;               ///< Protocol name for logging
    
    // Speed test configuration
    const char *speed_test_url;              ///< Speed test endpoint URL
    uint32_t speed_test_size_mb;             ///< Download size for speed test (MB)
    bool enable_speed_test;                  ///< Enable throughput test (default: true)
    
    // Latency test configuration
    const char *latency_test_target;         ///< Target for latency test (IP or hostname)
    uint32_t latency_test_count;             ///< Number of ping attempts (default: 3)
    bool enable_latency_test;                ///< Enable latency test (default: true)
    
    // Connectivity verification
    const char *dns_test_hostname;           ///< Hostname for DNS test (default: dns.google.com)
    const char *http_test_url;               ///< URL for HTTP test (default: http://clients3.google.com/generate_204)
    const char *https_test_url;              ///< URL for HTTPS test (default: https://www.google.com)
    bool enable_connectivity_verify;         ///< Enable connectivity checks (default: true)
    
    // Timeouts
    uint32_t timeout_ms;                     ///< Total test timeout (default: 30000)
    uint32_t per_test_timeout_ms;            ///< Timeout per individual test (default: 10000)
    
    // Callbacks
    dap_vpn_connectivity_test_callback_t on_complete;
    void *user_data;
} dap_vpn_connectivity_test_params_t;

// =============================================================================
// API Functions
// =============================================================================

/**
 * @brief Start connectivity test
 * @param params Test parameters
 * @return Test instance or NULL on error
 * @note Test runs asynchronously, use callback to receive results
 */
dap_vpn_connectivity_test_t* dap_vpn_connectivity_test_start(
    const dap_vpn_connectivity_test_params_t *params
);

/**
 * @brief Cancel ongoing test
 * @param test Test instance
 */
void dap_vpn_connectivity_test_cancel(dap_vpn_connectivity_test_t *test);

/**
 * @brief Get test result
 * @param test Test instance
 * @return Test result (owned by test, do not free)
 */
const dap_vpn_connectivity_result_t* dap_vpn_connectivity_test_get_result(
    const dap_vpn_connectivity_test_t *test
);

/**
 * @brief Check if test is complete
 * @param test Test instance
 * @return true if test finished (success, failure, or timeout)
 */
bool dap_vpn_connectivity_test_is_complete(const dap_vpn_connectivity_test_t *test);

/**
 * @brief Destroy test instance
 * @param test Test instance
 */
void dap_vpn_connectivity_test_destroy(dap_vpn_connectivity_test_t *test);

/**
 * @brief Get default test parameters
 * @param stream Stream to test
 * @param protocol_name Protocol name
 * @return Default parameters structure
 */
dap_vpn_connectivity_test_params_t dap_vpn_connectivity_test_default_params(
    dap_stream_t *stream,
    const char *protocol_name
);

/**
 * @brief Perform quick latency test only (no speed test)
 * @param stream Stream to test
 * @param target Ping target (IP or hostname)
 * @param count Number of pings (default: 3)
 * @param out_latency_ms Output: average latency
 * @return 0 on success, negative on error
 */
int dap_vpn_connectivity_test_quick_latency(
    dap_stream_t *stream,
    const char *target,
    uint32_t count,
    uint32_t *out_latency_ms
);

/**
 * @brief Perform quick connectivity check only (DNS + HTTP)
 * @param stream Stream to test
 * @param out_dns_ok Output: DNS works
 * @param out_http_ok Output: HTTP works
 * @return 0 on success, negative on error
 */
int dap_vpn_connectivity_test_quick_check(
    dap_stream_t *stream,
    bool *out_dns_ok,
    bool *out_http_ok
);

/**
 * @brief Calculate composite score from metrics
 * @param throughput_mbps Throughput in Mbps
 * @param latency_ms Latency in ms
 * @param packet_loss_percent Packet loss percentage
 * @param dns_ok DNS working
 * @param http_ok HTTP working
 * @return Score (0.0-1.0)
 */
float dap_vpn_connectivity_test_calculate_score(
    float throughput_mbps,
    uint32_t latency_ms,
    float packet_loss_percent,
    bool dns_ok,
    bool http_ok
);

// Utility functions
const char* dap_vpn_connectivity_test_status_to_string(dap_vpn_connectivity_test_status_t status);

#ifdef __cplusplus
}
#endif

