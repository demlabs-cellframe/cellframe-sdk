/**
 * @file dap_chain_net_vpn_client_state_internal.h
 * @brief Internal API for VPN Client State Machine modules
 * @details This header is NOT part of the public API. It's shared between
 *          state machine implementation modules (state.c, state_handlers.c,
 *          state_tunnel.c, state_payment.c) but not exposed externally.
 * @date 2025-10-25
 * @copyright (c) 2025 Cellframe Network
 */

#pragma once

#include "dap_chain_net_vpn_client_state.h"
#include "dap_chain_net_vpn_client_protocol_probe.h"
#include "dap_chain_net_vpn_client_connectivity_test.h"
#include "dap_chain_net_vpn_client_uplink_pool.h"
#include "dap_chain_net_vpn_client_backup.h"
#include "dap_chain_net_vpn_client_network.h"
#include "dap_chain_node_client.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "dap_chain_net_vpn_client_multihop_tx.h"
#include "dap_chain_net_vpn_client_receipt.h"
#include "dap_chain_net_vpn_client_payment.h"
#include "dap_vpn_client_wallet.h"
#include "dap_vpn_client_network_registry.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_client.h"
#include "dap_timerfd.h"
#include "dap_common.h"
#include "../../tun/include/dap_net_tun.h"

#define LOG_TAG "dap_chain_net_vpn_client_state"

// Debug flag for verbose packet logging (defined in state.c)
extern bool g_debug_more;

// Maximum number of state change callbacks
#define MAX_CALLBACKS 8

// Default reconnect policy
#define DEFAULT_MAX_ATTEMPTS 10
#define DEFAULT_INITIAL_DELAY_MS 1000
#define DEFAULT_MAX_DELAY_MS 60000
#define DEFAULT_RESET_AFTER_MS 300000  // 5 minutes

// Default connection timeout
#define DEFAULT_CONNECTION_TIMEOUT_MS 5000  // 5 seconds

// Default keepalive settings
#define DEFAULT_KEEPALIVE_INTERVAL_MS 10000   // 10 seconds
#define DEFAULT_KEEPALIVE_TIMEOUT_MS 30000    // 30 seconds

// Default protocol probe settings
#define DEFAULT_PROTOCOL_PROBE_TIMEOUT_MS 10000        // 10 seconds total
#define DEFAULT_PROTOCOL_PROBE_PER_PROTO_TIMEOUT_MS 5000  // 5 seconds per protocol

/**
 * @brief State machine context structure (internal definition)
 */
struct dap_chain_net_vpn_client_sm {
    dap_chain_net_vpn_client_state_t current_state;
    dap_chain_net_vpn_client_state_t previous_state;
    
    // Reconnect policy
    dap_chain_net_vpn_client_reconnect_policy_t reconnect_policy;
    uint32_t reconnect_attempt;
    int64_t connection_established_time;  // Timestamp when connection was established
    int64_t last_reconnect_time;          // Timestamp of last reconnect attempt
    
    // Connection parameters
    dap_chain_net_vpn_client_connect_params_t *connect_params;
    
    // Node client connection
    dap_chain_node_client_t *node_client;     // Active node client connection
    uint32_t connection_timeout_ms;           // Connection timeout in milliseconds
    
    // VPN Channels (multiple channels for load balancing / parallel tunnels)
    // Channels can be: different connections OR different esockets over one socket (platform-dependent)
    pthread_rwlock_t vpn_channels_rwlock;     // RW lock for thread-safe channel list access
    dap_list_t *vpn_channel_uuids;            // List of dap_stream_ch_uuid_t for VPN channels ('R')
    dap_stream_ch_uuid_t primary_channel_uuid; // Primary VPN channel UUID (first/main channel)
    
    // TUN Device
    dap_net_tun_t *tun_handle;               // Unified TUN device handle
    char *tun_device_name;                   // TUN device name (e.g., "tun0")
    char *tun_local_ip;                      // Client's VPN IP address
    char *tun_remote_ip;                     // Server's VPN gateway IP
    uint32_t tun_mtu;                        // MTU for TUN device
    
    // Statistics
    int64_t connection_start_time;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    
    // Keepalive
    dap_timerfd_t *keepalive_timer;
    uint32_t keepalive_interval_ms;
    uint32_t keepalive_timeout_ms;
    int64_t last_keepalive_response;
    
    // Protocol Probe & Connectivity Test
    dap_vpn_protocol_probe_t *protocol_probe;          // Active protocol probe
    dap_vpn_connectivity_test_t *connectivity_test;    // Active connectivity test
    
    // Callbacks
    dap_chain_net_vpn_client_state_callback_t callbacks[MAX_CALLBACKS];
    void *callback_args[MAX_CALLBACKS];
    uint32_t callback_count;
    
    // Shutdown flag
    bool shutdown_requested;
    
    // Thread safety
    pthread_mutex_t mutex;
};

// ============================================================================
// State Handlers (state_handlers.c)
// ============================================================================

/**
 * @brief State entry functions
 */
void state_disconnected_entry(dap_chain_net_vpn_client_sm_t *a_sm);
void state_connecting_entry(dap_chain_net_vpn_client_sm_t *a_sm);
void state_verifying_connectivity_entry(dap_chain_net_vpn_client_sm_t *a_sm);
void state_routing_setup_entry(dap_chain_net_vpn_client_sm_t *a_sm);
void state_connected_entry(dap_chain_net_vpn_client_sm_t *a_sm);
void state_connection_lost_entry(dap_chain_net_vpn_client_sm_t *a_sm);
void state_reconnecting_entry(dap_chain_net_vpn_client_sm_t *a_sm);
void state_disconnecting_entry(dap_chain_net_vpn_client_sm_t *a_sm);
void state_connect_failed_entry(dap_chain_net_vpn_client_sm_t *a_sm);
void state_shutdown_entry(dap_chain_net_vpn_client_sm_t *a_sm);

/**
 * @brief State exit functions
 */
void state_verifying_connectivity_exit(dap_chain_net_vpn_client_sm_t *a_sm);
void state_routing_setup_exit(dap_chain_net_vpn_client_sm_t *a_sm);
void state_connected_exit(dap_chain_net_vpn_client_sm_t *a_sm);

// ============================================================================
// TUN/Stream Callbacks (state_tunnel.c)
// ============================================================================

/**
 * @brief TUN device data received callback
 * @details Called when packet arrives from TUN device (from local network stack).
 *          Forwards packet to VPN server via stream channel.
 */
void s_tun_data_received_callback(dap_net_tun_t *a_tun, const void *a_data, 
                                   size_t a_data_size, void *a_user_data);

/**
 * @brief TUN device error callback
 * @details Called when TUN device encounters an error.
 *          Triggers CONNECTION_LOST event if connected.
 */
void s_tun_error_callback(dap_net_tun_t *a_tun, int a_error_code, 
                          const char *a_error_msg, void *a_user_data);

/**
 * @brief Stream channel packet received callback
 * @details Called when packet arrives from VPN server via stream channel.
 *          Forwards packet to TUN device (to local network stack).
 */
void s_stream_ch_packet_in_callback(dap_stream_ch_t *a_ch, void *a_arg);

// ============================================================================
// Payment Functions (state_payment.c)
// ============================================================================

/**
 * @brief Create payment transaction for VPN service
 * @param a_sm State machine context
 * @param a_node_info Node information for service provider
 * @param a_net_name Network name
 * @return 0 on success, negative error code on failure
 */
int vpn_client_payment_tx_create(dap_chain_net_vpn_client_sm_t *a_sm,
                                  dap_chain_node_info_t *a_node_info,
                                  const char *a_net_name);

/**
 * @brief Validate payment parameters
 * @param a_sm State machine context
 * @return 0 if valid, negative error code if invalid
 */
int vpn_client_payment_validate(dap_chain_net_vpn_client_sm_t *a_sm);

// ============================================================================
// Helper Functions (shared across modules)
// ============================================================================

/**
 * @brief Calculate exponential backoff delay
 * @param a_attempt Current attempt number
 * @param a_initial_delay_ms Initial delay in milliseconds
 * @param a_max_delay_ms Maximum delay in milliseconds
 * @return Delay in milliseconds
 */
uint32_t calculate_backoff_delay(uint32_t a_attempt, uint32_t a_initial_delay_ms, 
                                  uint32_t a_max_delay_ms);

/**
 * @brief Get current timestamp in milliseconds
 * @return Current time in milliseconds since epoch
 */
int64_t get_current_time_ms(void);

/**
 * @brief Notify all registered state change callbacks
 * @param a_sm State machine context
 */
void notify_state_callbacks(dap_chain_net_vpn_client_sm_t *a_sm);

/**
 * @brief Cleanup node client connection
 * @param a_sm State machine context
 */
void cleanup_node_client(dap_chain_net_vpn_client_sm_t *a_sm);

/**
 * @brief Cleanup TUN device
 * @param a_sm State machine context
 */
void cleanup_tun_device(dap_chain_net_vpn_client_sm_t *a_sm);

/**
 * @brief Cleanup keepalive timer
 * @param a_sm State machine context
 */
void cleanup_keepalive_timer(dap_chain_net_vpn_client_sm_t *a_sm);

// ===========================================================================
// Helper Functions Implementations (state_tunnel.c or state.c)
// ===========================================================================

/**
 * @brief Cleanup all TUN-related resources
 * @details This is called from state_disconnected_entry and other cleanup paths.
 *          Safely closes TUN device and frees all related memory.
 * @param a_sm State machine context
 */
static inline void cleanup_tun_device(dap_chain_net_vpn_client_sm_t *a_sm) {
    if (a_sm->tun_handle) {
        log_it(L_INFO, "Closing TUN device: %s", 
               a_sm->tun_device_name ? a_sm->tun_device_name : "unknown");
        dap_net_tun_deinit(a_sm->tun_handle);
        a_sm->tun_handle = NULL;
    }
    
    // Free TUN configuration
    DAP_DELETE(a_sm->tun_device_name);
    DAP_DELETE(a_sm->tun_local_ip);
    DAP_DELETE(a_sm->tun_remote_ip);
    a_sm->tun_mtu = 0;
    
    // Clear VPN channel reference
    a_sm->vpn_channel = NULL;
}

/**
 * @brief Cleanup node client connection
 * @param a_sm State machine context
 */
static inline void cleanup_node_client(dap_chain_net_vpn_client_sm_t *a_sm) {
    if (a_sm->node_client) {
        log_it(L_INFO, "Closing node client connection");
        dap_chain_node_client_close_mt(a_sm->node_client);
        a_sm->node_client = NULL;
    }
}

/**
 * @brief Cleanup keepalive timer
 * @param a_sm State machine context
 */
static inline void cleanup_keepalive_timer(dap_chain_net_vpn_client_sm_t *a_sm) {
    if (a_sm->keepalive_timer) {
        dap_timerfd_delete(a_sm->keepalive_timer);
        a_sm->keepalive_timer = NULL;
    }
}

// =============================================================================
// TUN Device & Stream Callbacks (from dap_chain_net_vpn_client_state_tunnel.c)
// =============================================================================

/**
 * @brief TUN device data received callback (NEW EXTENDED API)
 * @details Forwards packets from TUN device to VPN server via stream channel.
 *          Uses channel_info (worker + UUID) provided by dap_net_tun_t.
 */
void dap_chain_net_vpn_client_tun_data_received_callback(
    dap_net_tun_t *a_tun,
    const void *a_data,
    size_t a_data_size,
    const dap_net_tun_channel_info_t *a_channel_info,
    void *a_user_data);

/**
 * @brief TUN device error callback
 * @details Handles TUN device errors
 */
void dap_chain_net_vpn_client_tun_error_callback(
    dap_net_tun_t *a_tun,
    int a_error_code,
    const char *a_error_msg,
    void *a_user_data);

/**
 * @brief Stream channel packet received callback
 * @details Forwards packets from VPN server to TUN device
 */
void dap_chain_net_vpn_client_stream_packet_in_callback(
    dap_stream_ch_chain_net_srv_t *a_ch_srv,
    uint8_t a_pkt_type,
    dap_stream_ch_pkt_t *a_pkt,
    void *a_arg);

#endif // DAP_CHAIN_NET_VPN_CLIENT_STATE_INTERNAL_H

