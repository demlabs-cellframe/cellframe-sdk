/**
 * @file dap_chain_net_vpn_client_protocol_probe.h
 * @brief Parallel protocol probing for VPN client
 * @details Attempts to establish connections using multiple transport protocols simultaneously,
 *          allowing the client to find the best working protocol and detect censorship
 * @date 2025-10-23
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "dap_stream.h"
#include "dap_stream_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct dap_vpn_protocol_probe dap_vpn_protocol_probe_t;

/**
 * @brief Protocol probe status
 */
typedef enum {
    PROTOCOL_PROBE_STATUS_IDLE = 0,      ///< Not started
    PROTOCOL_PROBE_STATUS_PROBING,       ///< Connection attempts in progress
    PROTOCOL_PROBE_STATUS_ESTABLISHED,   ///< Handshake completed successfully
    PROTOCOL_PROBE_STATUS_FAILED,        ///< Connection failed
    PROTOCOL_PROBE_STATUS_TIMEOUT        ///< Probe timed out
} dap_vpn_protocol_probe_status_t;

/**
 * @brief Single protocol result
 */
typedef struct {
    char *protocol_name;                 ///< Protocol name (e.g., "UDP", "TCP")
    dap_stream_transport_t *transport;   ///< Transport instance
    dap_stream_t *stream;                ///< Established stream (if successful)
    dap_vpn_protocol_probe_status_t status; ///< Probe status
    
    // Performance metrics (from verification)
    float throughput_mbps;               ///< Measured throughput
    uint32_t latency_ms;                 ///< Measured latency
    float packet_loss_percent;           ///< Measured packet loss
    float score;                         ///< Composite score (0.0-1.0)
    
    // Timing
    uint64_t probe_start_ts;             ///< Probe start timestamp (ms)
    uint64_t probe_end_ts;               ///< Probe end timestamp (ms)
    uint32_t connection_time_ms;         ///< Time to establish connection
    
    // Failure info
    char *failure_reason;                ///< Human-readable failure reason
    int error_code;                      ///< Error code (if failed)
    
    // Block detection
    bool potentially_blocked;            ///< Protocol may be blocked by DPI
    uint32_t consecutive_failures;       ///< Number of consecutive failures
    uint64_t blocked_until_ts;           ///< Exclude from probes until this timestamp
} dap_vpn_protocol_result_t;

/**
 * @brief Probe results collection
 */
typedef struct {
    dap_vpn_protocol_result_t *protocols; ///< Array of protocol results
    uint32_t protocol_count;              ///< Total number of protocols probed
    uint32_t established_count;           ///< Number of successfully established
    uint32_t failed_count;                ///< Number of failed protocols
    uint32_t verified_ok_count;           ///< Number verified with good connectivity
    
    // Best protocol info
    dap_vpn_protocol_result_t *best_protocol; ///< Highest scoring protocol
    float best_score;                     ///< Highest score achieved
} dap_vpn_protocol_probe_result_t;

/**
 * @brief Callback for protocol establishment
 * @param probe Probe instance
 * @param protocol_name Protocol that was established
 * @param stream Established stream
 * @param user_data User data from params
 */
typedef void (*dap_vpn_protocol_probe_established_callback_t)(
    dap_vpn_protocol_probe_t *probe,
    const char *protocol_name,
    dap_stream_t *stream,
    void *user_data
);

/**
 * @brief Callback for probe completion
 * @param probe Probe instance
 * @param results Probe results
 * @param user_data User data from params
 */
typedef void (*dap_vpn_protocol_probe_complete_callback_t)(
    dap_vpn_protocol_probe_t *probe,
    dap_vpn_protocol_probe_result_t *results,
    void *user_data
);

/**
 * @brief Protocol probe parameters
 */
typedef struct {
    // Server info
    const char *server_address;          ///< Server address (IP or hostname)
    uint16_t server_port;                ///< Server port
    
    // Protocols to probe
    dap_stream_transport_t **protocols;  ///< Array of transport protocols to try
    uint32_t protocol_count;             ///< Number of protocols in array
    
    // Timing
    uint32_t timeout_ms;                 ///< Total timeout for probe phase (default: 10000)
    uint32_t per_protocol_timeout_ms;    ///< Timeout per protocol (default: 5000)
    
    // Callbacks
    dap_vpn_protocol_probe_established_callback_t on_protocol_established;
    dap_vpn_protocol_probe_complete_callback_t on_probe_complete;
    void *user_data;
    
    // Options
    bool skip_blocked_protocols;         ///< Skip protocols marked as blocked (default: false)
    bool parallel_mode;                  ///< True = parallel, False = sequential (default: true)
    uint32_t max_concurrent;             ///< Max concurrent probes in parallel mode (default: 0=all)
} dap_vpn_protocol_probe_params_t;

// =============================================================================
// API Functions
// =============================================================================

/**
 * @brief Start parallel protocol probe
 * @param params Probe parameters
 * @return Probe instance or NULL on error
 * @note Probe runs asynchronously, use callbacks to receive results
 */
dap_vpn_protocol_probe_t* dap_vpn_protocol_probe_parallel_start(
    const dap_vpn_protocol_probe_params_t *params
);

/**
 * @brief Cancel ongoing probe
 * @param probe Probe instance
 */
void dap_vpn_protocol_probe_cancel(dap_vpn_protocol_probe_t *probe);

/**
 * @brief Get probe results
 * @param probe Probe instance
 * @return Probe results (owned by probe, do not free)
 * @note Results are only valid after probe completion
 */
const dap_vpn_protocol_probe_result_t* dap_vpn_protocol_probe_get_results(
    const dap_vpn_protocol_probe_t *probe
);

/**
 * @brief Get results sorted by score (highest first)
 * @param probe Probe instance
 * @return Sorted results (owned by probe, do not free)
 */
const dap_vpn_protocol_probe_result_t* dap_vpn_protocol_probe_get_sorted_by_score(
    const dap_vpn_protocol_probe_t *probe
);

/**
 * @brief Check if all protocols have been verified
 * @param probe Probe instance
 * @return true if all probes finished (success or failure)
 */
bool dap_vpn_protocol_probe_all_verified(const dap_vpn_protocol_probe_t *probe);

/**
 * @brief Add established protocol to results
 * @param probe Probe instance
 * @param protocol_name Protocol name
 * @param stream Established stream
 * @note Internal function, called by probe callbacks
 */
void dap_vpn_protocol_probe_add_established(dap_vpn_protocol_probe_t *probe,
                                             const char *protocol_name,
                                             dap_stream_t *stream);

/**
 * @brief Update protocol result with verification metrics
 * @param probe Probe instance
 * @param result Verification result
 * @note Internal function, called by connectivity test
 */
void dap_vpn_protocol_probe_update_result(dap_vpn_protocol_probe_t *probe,
                                           const dap_vpn_protocol_result_t *result);

/**
 * @brief Get count of established protocols
 * @param probe Probe instance
 * @return Number of established protocols
 */
uint32_t dap_vpn_protocol_probe_get_established_count(const dap_vpn_protocol_probe_t *probe);

/**
 * @brief Mark protocol as potentially blocked
 * @param probe Probe instance
 * @param protocol_name Protocol name
 * @param block_duration_ms Duration to block (0 = permanent)
 */
void dap_vpn_protocol_probe_mark_blocked(dap_vpn_protocol_probe_t *probe,
                                          const char *protocol_name,
                                          uint32_t block_duration_ms);

/**
 * @brief Check if protocol is currently blocked
 * @param probe Probe instance
 * @param protocol_name Protocol name
 * @return true if blocked
 */
bool dap_vpn_protocol_probe_is_blocked(const dap_vpn_protocol_probe_t *probe,
                                        const char *protocol_name);

/**
 * @brief Destroy probe instance
 * @param probe Probe instance
 * @note Closes all non-selected streams
 */
void dap_vpn_protocol_probe_destroy(dap_vpn_protocol_probe_t *probe);

/**
 * @brief Get default probe parameters
 * @param server_address Server address
 * @param server_port Server port
 * @return Default parameters structure
 */
dap_vpn_protocol_probe_params_t dap_vpn_protocol_probe_default_params(
    const char *server_address,
    uint16_t server_port
);

// Utility functions
const char* dap_vpn_protocol_probe_status_to_string(dap_vpn_protocol_probe_status_t status);

#ifdef __cplusplus
}
#endif

