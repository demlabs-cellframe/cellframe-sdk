/**
 * @file dap_chain_net_vpn_client_uplink_pool.h
 * @brief Multi-uplink pool manager for VPN client
 * @details Manages multiple simultaneous VPN connections (uplinks) with load balancing,
 *          health monitoring, and automatic failover
 * @date 2025-10-23
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "dap_stream.h"
#include "dap_timerfd.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct dap_vpn_uplink dap_vpn_uplink_t;
typedef struct dap_vpn_uplink_pool dap_vpn_uplink_pool_t;

/**
 * @brief Uplink health status
 */
typedef enum {
    UPLINK_HEALTH_EXCELLENT = 0,  ///< Score > 0.8, latency < 100ms
    UPLINK_HEALTH_GOOD,           ///< Score > 0.6, latency < 200ms
    UPLINK_HEALTH_FAIR,           ///< Score > 0.4, latency < 500ms
    UPLINK_HEALTH_POOR,           ///< Score > 0.3, latency < 1000ms
    UPLINK_HEALTH_CRITICAL        ///< Score <= 0.3 or latency >= 1000ms
} dap_vpn_uplink_health_status_t;

/**
 * @brief Uplink state
 */
typedef enum {
    UPLINK_STATE_IDLE = 0,        ///< Not connected
    UPLINK_STATE_CONNECTING,      ///< Connection in progress
    UPLINK_STATE_VERIFYING,       ///< Speed test and connectivity verification
    UPLINK_STATE_ACTIVE,          ///< Ready for traffic routing
    UPLINK_STATE_STANDBY,         ///< Connected but not actively used
    UPLINK_STATE_DEGRADED,        ///< Performance degraded, failover candidate
    UPLINK_STATE_FAILED           ///< Connection failed
} dap_vpn_uplink_state_t;

/**
 * @brief Traffic balancing strategy
 */
typedef enum {
    BALANCE_STRATEGY_ROUND_ROBIN = 0,  ///< Simple round-robin
    BALANCE_STRATEGY_WEIGHTED,         ///< Weight by score (better = more traffic)
    BALANCE_STRATEGY_LEAST_LOADED,     ///< Route to least loaded uplink
    BALANCE_STRATEGY_FASTEST,          ///< Always use fastest (lowest latency)
    BALANCE_STRATEGY_HYBRID            ///< Weighted + least loaded combined
} dap_vpn_uplink_balance_strategy_t;

/**
 * @brief Uplink statistics
 */
typedef struct {
    // Performance metrics
    float throughput_mbps;           ///< Current throughput in Mbps
    uint32_t latency_ms;             ///< Current RTT latency
    float packet_loss_percent;       ///< Packet loss percentage
    float score;                     ///< Composite score (0.0-1.0)
    
    // Traffic counters
    uint64_t bytes_sent;             ///< Total bytes sent through this uplink
    uint64_t bytes_received;         ///< Total bytes received
    uint64_t packets_sent;           ///< Total packets sent
    uint64_t packets_received;       ///< Total packets received
    uint64_t packets_dropped;        ///< Packets dropped due to errors
    
    // Health monitoring
    uint32_t consecutive_failures;   ///< Number of consecutive failed health checks
    uint64_t last_health_check_ts;   ///< Timestamp of last health check (ms)
    uint64_t uptime_seconds;         ///< Total uptime since connection
    
    // Performance history
    float avg_throughput_mbps;       ///< Average throughput over last N samples
    uint32_t avg_latency_ms;         ///< Average latency over last N samples
    float score_history[10];         ///< Last 10 score samples for trend analysis
    uint8_t score_history_index;     ///< Current index in circular buffer
} dap_vpn_uplink_stats_t;

/**
 * @brief Health thresholds configuration
 */
typedef struct {
    float score_excellent;           ///< Score threshold for EXCELLENT (default: 0.8)
    float score_good;                ///< Score threshold for GOOD (default: 0.6)
    float score_fair;                ///< Score threshold for FAIR (default: 0.4)
    float score_poor;                ///< Score threshold for POOR (default: 0.3)
    uint32_t latency_excellent;      ///< Latency threshold for EXCELLENT (ms, default: 100)
    uint32_t latency_good;           ///< Latency threshold for GOOD (ms, default: 200)
    uint32_t latency_fair;           ///< Latency threshold for FAIR (ms, default: 500)
    uint32_t latency_poor;           ///< Latency threshold for POOR (ms, default: 1000)
    uint32_t max_consecutive_failures; ///< Max failures before marking as FAILED (default: 3)
    float degradation_threshold;     ///< Score drop % to trigger re-verification (default: 0.3)
} dap_vpn_uplink_health_thresholds_t;

/**
 * @brief Single uplink structure
 */
struct dap_vpn_uplink {
    // Connection info
    char *server_address;            ///< Server address (IP or hostname)
    uint16_t server_port;            ///< Server port
    char *protocol_name;             ///< Transport protocol name (e.g., "UDP", "TCP")
    dap_stream_t *stream;            ///< DAP stream connection
    
    // State
    dap_vpn_uplink_state_t state;    ///< Current uplink state
    dap_vpn_uplink_health_status_t health; ///< Current health status
    
    // Statistics
    dap_vpn_uplink_stats_t stats;    ///< Performance and traffic statistics
    
    // Metadata
    uint64_t id;                     ///< Unique uplink ID
    uint64_t created_at;             ///< Creation timestamp (ms)
    uint64_t connected_at;           ///< Connection timestamp (ms)
    
    // Payment tracking (for economy mode)
    char *payment_tx_hash;           ///< Transaction hash for paid mode
    uint64_t payment_expires_at;     ///< Payment expiration timestamp
    uint64_t payment_remaining_bytes; ///< Remaining paid bandwidth
    
    // Internal
    pthread_mutex_t lock;            ///< Per-uplink lock for thread-safety
    dap_vpn_uplink_pool_t *pool;     ///< Back-reference to parent pool
};

/**
 * @brief Uplink pool configuration
 */
typedef struct {
    uint32_t max_uplinks;                       ///< Max number of uplinks (default: 4)
    uint32_t desired_active_uplinks;            ///< Desired number of active uplinks (default: 2)
    dap_vpn_uplink_balance_strategy_t strategy; ///< Traffic balancing strategy
    dap_vpn_uplink_health_thresholds_t thresholds; ///< Health monitoring thresholds
    uint32_t health_check_interval_ms;          ///< Interval for health checks (default: 60000)
    uint32_t rebalance_interval_ms;             ///< Interval for traffic rebalancing (default: 10000)
    bool auto_failover_enabled;                 ///< Enable automatic failover (default: true)
    bool preemptive_standby_enabled;            ///< Enable preemptive standby uplinks (default: true)
} dap_vpn_uplink_pool_config_t;

/**
 * @brief Callback for uplink state changes
 */
typedef void (*dap_vpn_uplink_state_callback_t)(dap_vpn_uplink_t *uplink, 
                                                 dap_vpn_uplink_state_t old_state,
                                                 dap_vpn_uplink_state_t new_state,
                                                 void *user_data);

/**
 * @brief Callback for uplink health changes
 */
typedef void (*dap_vpn_uplink_health_callback_t)(dap_vpn_uplink_t *uplink,
                                                  dap_vpn_uplink_health_status_t old_health,
                                                  dap_vpn_uplink_health_status_t new_health,
                                                  void *user_data);

/**
 * @brief Uplink pool structure
 */
struct dap_vpn_uplink_pool {
    // Configuration
    dap_vpn_uplink_pool_config_t config;
    
    // Uplinks array
    dap_vpn_uplink_t **uplinks;      ///< Array of uplink pointers
    uint32_t uplink_count;           ///< Current number of uplinks
    uint32_t active_uplink_count;    ///< Number of active uplinks
    uint64_t next_uplink_id;         ///< Next uplink ID to assign
    
    // Load balancing
    uint32_t round_robin_index;      ///< Current index for round-robin
    uint64_t total_bytes_routed;     ///< Total bytes routed through all uplinks
    
    // Timers
    dap_timerfd_t *health_check_timer; ///< Timer for periodic health checks
    dap_timerfd_t *rebalance_timer;    ///< Timer for traffic rebalancing
    
    // Callbacks
    dap_vpn_uplink_state_callback_t state_callback;
    dap_vpn_uplink_health_callback_t health_callback;
    void *callback_user_data;
    
    // Thread-safety
    pthread_rwlock_t pool_lock;      ///< Read-write lock for pool operations
};

// =============================================================================
// API Functions
// =============================================================================

/**
 * @brief Create uplink pool with default configuration
 * @return New uplink pool instance or NULL on error
 */
dap_vpn_uplink_pool_t* dap_vpn_uplink_pool_create(void);

/**
 * @brief Create uplink pool with custom configuration
 * @param config Pool configuration
 * @return New uplink pool instance or NULL on error
 */
dap_vpn_uplink_pool_t* dap_vpn_uplink_pool_create_ext(const dap_vpn_uplink_pool_config_t *config);

/**
 * @brief Destroy uplink pool and all uplinks
 * @param pool Uplink pool
 */
void dap_vpn_uplink_pool_destroy(dap_vpn_uplink_pool_t *pool);

/**
 * @brief Add uplink to pool
 * @param pool Uplink pool
 * @param server_address Server address
 * @param server_port Server port
 * @param protocol_name Protocol name (e.g., "UDP", "TCP")
 * @param stream DAP stream connection
 * @param initial_score Initial score from verification (0.0-1.0)
 * @return New uplink instance or NULL on error
 */
dap_vpn_uplink_t* dap_vpn_uplink_pool_add(dap_vpn_uplink_pool_t *pool,
                                           const char *server_address,
                                           uint16_t server_port,
                                           const char *protocol_name,
                                           dap_stream_t *stream,
                                           float initial_score);

/**
 * @brief Remove uplink from pool
 * @param pool Uplink pool
 * @param uplink_id Uplink ID to remove
 * @return true if removed, false if not found
 */
bool dap_vpn_uplink_pool_remove(dap_vpn_uplink_pool_t *pool, uint64_t uplink_id);

/**
 * @brief Get best uplink based on criteria
 * @param pool Uplink pool
 * @param prefer_low_latency Prefer low latency over throughput
 * @return Best uplink or NULL if no uplinks available
 * @note Returns uplink with highest score, or lowest latency if prefer_low_latency=true
 */
dap_vpn_uplink_t* dap_vpn_uplink_pool_get_best(dap_vpn_uplink_pool_t *pool, bool prefer_low_latency);

/**
 * @brief Get next uplink for routing (based on balancing strategy)
 * @param pool Uplink pool
 * @return Next uplink to use or NULL if no uplinks available
 */
dap_vpn_uplink_t* dap_vpn_uplink_pool_get_next(dap_vpn_uplink_pool_t *pool);

/**
 * @brief Update uplink statistics
 * @param uplink Uplink to update
 * @param throughput_mbps Current throughput
 * @param latency_ms Current latency
 * @param packet_loss_percent Packet loss percentage
 */
void dap_vpn_uplink_update_stats(dap_vpn_uplink_t *uplink,
                                  float throughput_mbps,
                                  uint32_t latency_ms,
                                  float packet_loss_percent);

/**
 * @brief Update uplink traffic counters
 * @param uplink Uplink
 * @param bytes_sent Bytes sent in this update
 * @param bytes_received Bytes received in this update
 */
void dap_vpn_uplink_update_traffic(dap_vpn_uplink_t *uplink,
                                    uint64_t bytes_sent,
                                    uint64_t bytes_received);

/**
 * @brief Perform health check on uplink
 * @param uplink Uplink to check
 * @return New health status
 */
dap_vpn_uplink_health_status_t dap_vpn_uplink_check_health(dap_vpn_uplink_t *uplink);

/**
 * @brief Perform health check on all uplinks in pool
 * @param pool Uplink pool
 */
void dap_vpn_uplink_pool_check_health_all(dap_vpn_uplink_pool_t *pool);

/**
 * @brief Rebalance traffic across active uplinks
 * @param pool Uplink pool
 * @details Updates weights/priorities based on current statistics
 */
void dap_vpn_uplink_pool_rebalance(dap_vpn_uplink_pool_t *pool);

/**
 * @brief Set state callback
 * @param pool Uplink pool
 * @param callback State change callback
 * @param user_data User data for callback
 */
void dap_vpn_uplink_pool_set_state_callback(dap_vpn_uplink_pool_t *pool,
                                             dap_vpn_uplink_state_callback_t callback,
                                             void *user_data);

/**
 * @brief Set health callback
 * @param pool Uplink pool
 * @param callback Health change callback
 * @param user_data User data for callback
 */
void dap_vpn_uplink_pool_set_health_callback(dap_vpn_uplink_pool_t *pool,
                                              dap_vpn_uplink_health_callback_t callback,
                                              void *user_data);

/**
 * @brief Get uplink by ID
 * @param pool Uplink pool
 * @param uplink_id Uplink ID
 * @return Uplink or NULL if not found
 */
dap_vpn_uplink_t* dap_vpn_uplink_pool_get_by_id(dap_vpn_uplink_pool_t *pool, uint64_t uplink_id);

/**
 * @brief Get pool statistics summary
 * @param pool Uplink pool
 * @param out_active_count Output: number of active uplinks
 * @param out_total_throughput Output: total throughput (Mbps)
 * @param out_avg_latency Output: average latency (ms)
 * @param out_total_bytes_routed Output: total bytes routed
 */
void dap_vpn_uplink_pool_get_stats(dap_vpn_uplink_pool_t *pool,
                                    uint32_t *out_active_count,
                                    float *out_total_throughput,
                                    uint32_t *out_avg_latency,
                                    uint64_t *out_total_bytes_routed);

/**
 * @brief Get default pool configuration
 * @return Default configuration structure
 */
dap_vpn_uplink_pool_config_t dap_vpn_uplink_pool_default_config(void);

// Utility functions for state/health conversion
const char* dap_vpn_uplink_state_to_string(dap_vpn_uplink_state_t state);
const char* dap_vpn_uplink_health_to_string(dap_vpn_uplink_health_status_t health);
const char* dap_vpn_uplink_balance_strategy_to_string(dap_vpn_uplink_balance_strategy_t strategy);

#ifdef __cplusplus
}
#endif

