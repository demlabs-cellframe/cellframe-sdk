/**
 * @file dap_chain_net_vpn_client_state.h
 * @brief VPN Client State Machine
 *
 * Centralized state machine for VPN connection lifecycle management with
 * automatic reconnect, keepalive, and crash recovery integration.
 *
 * @date 2025-10-23
 * @copyright (c) 2025 Cellframe Network
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "dap_events_socket.h"
#include "dap_chain_net_srv.h"  // For dap_chain_srv_price_unit_uid_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief VPN client connection states
 */
typedef enum dap_chain_net_vpn_client_state {
    VPN_STATE_DISCONNECTED = 0,     // No connection, idle
    VPN_STATE_CONNECTING,           // Establishing connection
    VPN_STATE_VERIFYING_CONNECTIVITY, // Testing protocols and connectivity
    VPN_STATE_ROUTING_SETUP,        // Setting up routing table entries
    VPN_STATE_CONNECTED,            // Active VPN tunnel
    VPN_STATE_CONNECTION_LOST,      // Connection dropped, deciding next action
    VPN_STATE_RECONNECTING,         // Attempting to reconnect
    VPN_STATE_DISCONNECTING,        // Gracefully closing connection
    VPN_STATE_CONNECT_FAILED,       // Connection failed, temporary state
    VPN_STATE_SHUTDOWN,             // Daemon shutting down
    VPN_STATE_MAX                   // Sentinel value
} dap_chain_net_vpn_client_state_t;

/**
 * @brief State machine events
 */
typedef enum dap_chain_net_vpn_client_event {
    VPN_EVENT_USER_CONNECT = 0,     // User initiated connect
    VPN_EVENT_USER_DISCONNECT,      // User initiated disconnect
    VPN_EVENT_CONNECTION_SUCCESS,   // Connection established successfully
    VPN_EVENT_CONNECTION_FAILED,    // Connection establishment failed
    VPN_EVENT_PROTOCOLS_PROBED,     // Protocol probing completed
    VPN_EVENT_VERIFICATION_SUCCESS, // Connectivity verification passed
    VPN_EVENT_VERIFICATION_FAILED,  // Connectivity verification failed
    VPN_EVENT_ROUTING_COMPLETE,     // Routing table setup complete
    VPN_EVENT_CONNECTION_LOST,      // Connection dropped unexpectedly
    VPN_EVENT_KEEPALIVE_TIMEOUT,    // Keepalive timeout (no response from server)
    VPN_EVENT_RECONNECT_SUCCESS,    // Reconnection successful
    VPN_EVENT_RECONNECT_FAILED,     // Reconnection failed
    VPN_EVENT_SERVER_DISCONNECT,    // Server initiated disconnect
    VPN_EVENT_SHUTDOWN,             // Daemon shutdown requested
    VPN_EVENT_MAX                   // Sentinel value
} dap_chain_net_vpn_client_event_t;

/**
 * @brief Reconnect policy configuration
 */
typedef struct dap_chain_net_vpn_client_reconnect_policy {
    bool enabled;                   // Auto-reconnect enabled?
    uint32_t max_attempts;          // Maximum reconnect attempts (0 = infinite)
    uint32_t initial_delay_ms;      // Initial delay between reconnects (ms)
    uint32_t max_delay_ms;          // Maximum delay between reconnects (ms)
    uint32_t reset_after_ms;        // Reset attempt counter after this much successful connection time
} dap_chain_net_vpn_client_reconnect_policy_t;

/**
 * @brief State machine context
 */
typedef struct dap_chain_net_vpn_client_sm dap_chain_net_vpn_client_sm_t;

/**
 * @brief State change callback
 * @param a_sm State machine context
 * @param a_old_state Previous state
 * @param a_new_state New state
 * @param a_event Event that triggered transition
 * @param a_user_data User data passed during callback registration
 */
typedef void (*dap_chain_net_vpn_client_state_callback_t)(
    dap_chain_net_vpn_client_sm_t *a_sm,
    dap_chain_net_vpn_client_state_t a_old_state,
    dap_chain_net_vpn_client_state_t a_new_state,
    dap_chain_net_vpn_client_event_t a_event,
    void *a_user_data
);

/**
 * @brief Connection parameters
 */
typedef struct dap_chain_net_vpn_client_connect_params {
    char *server_address;           // Server hostname or IP (for single-hop or first hop)
    uint16_t server_port;           // Server port
    char *network_name;             // Cellframe network name
    char *transport_type;           // Transport type (http/udp/websocket)
    char *obfuscation_level;        // Obfuscation level (none/low/medium/high/paranoid)
    uint32_t connection_timeout_ms; // Connection timeout in milliseconds (0 = use default)
    bool no_routing;                // Don't modify routing table
    bool no_dns;                    // Don't modify DNS settings
    
    // Multi-hop parameters (single-hop is just multi-hop with hop_count=1)
    dap_chain_node_addr_t *route;              // Route (array of node addresses, 1 for single-hop)
    uint8_t hop_count;                          // Number of hops (1 for single-hop, N for multi-hop)
    uint8_t tunnel_count;                       // Parallel tunnels per hop (default 1)
    dap_chain_hash_fast_t *payment_tx_hashes;  // Payment TX hashes for each hop (array)
    uint32_t session_id;                        // Session ID (for multi-hop tracking)
    
    // Payment parameters
    char *wallet_name;              // Wallet name for automatic payment TX creation
    char *payment_token;            // Token ticker for payment (e.g., "KEL", "mKEL")
    uint64_t service_units;         // Amount of service units to purchase
    dap_chain_net_srv_price_unit_uid_t service_unit_type; // Service unit type (bytes, seconds, etc)
} dap_chain_net_vpn_client_connect_params_t;

/**
 * @brief Initialize state machine
 * @return State machine context or NULL on error
 */
dap_chain_net_vpn_client_sm_t* dap_chain_net_vpn_client_sm_init(void);

/**
 * @brief Deinitialize state machine and cleanup resources
 * @param a_sm State machine context
 */
void dap_chain_net_vpn_client_sm_deinit(dap_chain_net_vpn_client_sm_t *a_sm);

/**
 * @brief Process event and perform state transition
 * @param a_sm State machine context
 * @param a_event Event to process
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_sm_transition(dap_chain_net_vpn_client_sm_t *a_sm,
                                            dap_chain_net_vpn_client_event_t a_event);

/**
 * @brief Get current state
 * @param a_sm State machine context
 * @return Current state
 */
dap_chain_net_vpn_client_state_t dap_chain_net_vpn_client_sm_get_state(
    const dap_chain_net_vpn_client_sm_t *a_sm);

/**
 * @brief Register state change callback
 * @param a_sm State machine context
 * @param a_callback Callback function
 * @param a_user_data User data to pass to callback
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_sm_register_callback(
    dap_chain_net_vpn_client_sm_t *a_sm,
    dap_chain_net_vpn_client_state_callback_t a_callback,
    void *a_user_data);

/**
 * @brief Set reconnect policy
 * @param a_sm State machine context
 * @param a_policy Reconnect policy configuration
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_sm_set_reconnect_policy(
    dap_chain_net_vpn_client_sm_t *a_sm,
    const dap_chain_net_vpn_client_reconnect_policy_t *a_policy);

/**
 * @brief Get reconnect policy
 * @param a_sm State machine context
 * @param a_out_policy Output pointer for policy
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_sm_get_reconnect_policy(
    const dap_chain_net_vpn_client_sm_t *a_sm,
    dap_chain_net_vpn_client_reconnect_policy_t *a_out_policy);

/**
 * @brief Set connection parameters for next connection attempt
 * @param a_sm State machine context
 * @param a_params Connection parameters (will be copied)
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_sm_set_connect_params(
    dap_chain_net_vpn_client_sm_t *a_sm,
    const dap_chain_net_vpn_client_connect_params_t *a_params);

/**
 * @brief Start keepalive mechanism
 * @param a_sm State machine context
 * @param a_interval_ms Keepalive interval in milliseconds
 * @param a_timeout_ms Keepalive timeout in milliseconds
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_sm_start_keepalive(
    dap_chain_net_vpn_client_sm_t *a_sm,
    uint32_t a_interval_ms,
    uint32_t a_timeout_ms);

/**
 * @brief Set keepalive parameters
 * @param a_sm State machine context
 * @param a_interval_ms Keepalive interval in milliseconds
 * @param a_timeout_ms Keepalive timeout in milliseconds
 */
void dap_chain_net_vpn_client_sm_set_keepalive(
    dap_chain_net_vpn_client_sm_t *a_sm,
    uint32_t a_interval_ms,
    uint32_t a_timeout_ms);

/**
 * @brief Set connection timeout
 * @param a_sm State machine context
 * @param a_timeout_ms Connection timeout in milliseconds
 */
void dap_chain_net_vpn_client_sm_set_connection_timeout(
    dap_chain_net_vpn_client_sm_t *a_sm,
    uint32_t a_timeout_ms);

/**
 * @brief Stop keepalive mechanism
 * @param a_sm State machine context
 */
void dap_chain_net_vpn_client_sm_stop_keepalive(dap_chain_net_vpn_client_sm_t *a_sm);

/**
 * @brief Update keepalive response timestamp (call when receiving data from server)
 * @param a_sm State machine context
 */
void dap_chain_net_vpn_client_sm_keepalive_response(dap_chain_net_vpn_client_sm_t *a_sm);

/**
 * @brief Get connection statistics
 * @param a_sm State machine context
 * @param a_out_uptime_sec Connection uptime in seconds
 * @param a_out_bytes_sent Bytes sent
 * @param a_out_bytes_received Bytes received
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_sm_get_stats(
    const dap_chain_net_vpn_client_sm_t *a_sm,
    uint64_t *a_out_uptime_sec,
    uint64_t *a_out_bytes_sent,
    uint64_t *a_out_bytes_received);

/**
 * @brief Get reconnect attempt count
 * @param a_sm State machine context
 * @return Current reconnect attempt number, 0 if not reconnecting
 */
uint32_t dap_chain_net_vpn_client_sm_get_reconnect_attempt(
    const dap_chain_net_vpn_client_sm_t *a_sm);

/**
 * @brief Convert state to string
 * @param a_state State enum value
 * @return State name string (do not free)
 */
const char* dap_chain_net_vpn_client_state_to_string(dap_chain_net_vpn_client_state_t a_state);

/**
 * @brief Convert event to string
 * @param a_event Event enum value
 * @return Event name string (do not free)
 */
const char* dap_chain_net_vpn_client_event_to_string(dap_chain_net_vpn_client_event_t a_event);

/**
 * @brief Check if state machine is in a connected state
 * @param a_sm State machine context
 * @return true if connected or reconnecting, false otherwise
 */
bool dap_chain_net_vpn_client_sm_is_connected(const dap_chain_net_vpn_client_sm_t *a_sm);

/**
 * @brief Free connection parameters
 * @param a_params Parameters structure to free
 */
void dap_chain_net_vpn_client_connect_params_free(dap_chain_net_vpn_client_connect_params_t *a_params);

#ifdef __cplusplus
} // extern "C"
#endif

