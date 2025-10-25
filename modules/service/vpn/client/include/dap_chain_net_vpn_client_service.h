/**
 * @file dap_chain_net_vpn_client_service.h
 * @brief VPN Client Service Core
 *
 * High-level service interface that wraps State Machine and provides
 * connection management, statistics, and lifecycle control.
 *
 * @date 2025-10-23
 * @copyright (c) 2025 Cellframe Network
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "dap_common.h"
#include "dap_chain_net_vpn_client_state.h"
#include "dap_chain_net_vpn_client_backup.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Service instance (opaque)
 */
typedef struct dap_chain_net_vpn_client_service dap_chain_net_vpn_client_service_t;

/**
 * @brief Service state (mapped from State Machine states)
 */
typedef enum dap_chain_net_vpn_client_service_state {
    DAP_CHAIN_NET_VPN_CLIENT_SERVICE_STATE_DISCONNECTED = 0,
    DAP_CHAIN_NET_VPN_CLIENT_SERVICE_STATE_CONNECTING,
    DAP_CHAIN_NET_VPN_CLIENT_SERVICE_STATE_CONNECTED,
    DAP_CHAIN_NET_VPN_CLIENT_SERVICE_STATE_CONNECTION_LOST,
    DAP_CHAIN_NET_VPN_CLIENT_SERVICE_STATE_RECONNECTING,
    DAP_CHAIN_NET_VPN_CLIENT_SERVICE_STATE_DISCONNECTING,
    DAP_CHAIN_NET_VPN_CLIENT_SERVICE_STATE_CONNECT_FAILED,
    DAP_CHAIN_NET_VPN_CLIENT_SERVICE_STATE_SHUTDOWN
} dap_chain_net_vpn_client_service_state_t;

/**
 * @brief Connection configuration
 */
typedef struct dap_chain_net_vpn_client_config {
    char *server_host;              // Server hostname/IP
    uint16_t server_port;           // Server port
    char *network_name;             // Cellframe network name
    char *payment_tx_hash;          // Payment transaction hash
    char *transport_type;           // Transport: "http", "udp", "websocket"
    char *obfuscation_mode;         // Obfuscation: "none", "low", "medium", "high", "paranoid"
    bool enable_routing;            // Enable automatic routing configuration
    bool enable_dns_override;       // Enable automatic DNS override
    bool auto_reconnect;            // Enable auto-reconnect
    uint32_t reconnect_interval_ms; // Reconnect interval in milliseconds
    uint32_t connection_timeout_ms; // Connection timeout in milliseconds (0 = use default)
    bool multi_hop_enabled;         // Enable multi-hop routing
    char *multi_hop_route;          // Multi-hop route (comma-separated servers)
} dap_chain_net_vpn_client_config_t;

/**
 * @brief Service status
 */
typedef struct dap_chain_net_vpn_client_service_status {
    dap_chain_net_vpn_client_service_state_t state;
    char *server_host;
    uint16_t server_port;
    uint64_t uptime_seconds;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    uint32_t reconnect_attempt;
} dap_chain_net_vpn_client_service_status_t;

/**
 * @brief State change callback
 * @param a_new_state New service state
 * @param a_user_data User data
 */
typedef void (*dap_chain_net_vpn_client_service_state_callback_t)(
    dap_chain_net_vpn_client_service_state_t a_new_state,
    void *a_user_data
);

/**
 * @brief Create service instance
 * @return Service instance or NULL on error
 */
dap_chain_net_vpn_client_service_t* dap_chain_net_vpn_client_service_create(void);

/**
 * @brief Get global service instance (singleton)
 * @return Service instance (creates if not exists) or NULL on error
 */
dap_chain_net_vpn_client_service_t* dap_chain_net_vpn_client_service_get_instance(void);

/**
 * @brief Destroy service instance
 * @param a_service Service instance
 */
void dap_chain_net_vpn_client_service_destroy(dap_chain_net_vpn_client_service_t *a_service);

/**
 * @brief Connect to VPN server
 * @param a_service Service instance
 * @param a_config Connection configuration
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_service_connect(
    dap_chain_net_vpn_client_service_t *a_service,
    const dap_chain_net_vpn_client_config_t *a_config
);

/**
 * @brief Disconnect from VPN server
 * @param a_service Service instance
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_service_disconnect(dap_chain_net_vpn_client_service_t *a_service);

/**
 * @brief Get service status
 * @param a_service Service instance
 * @param a_out_status Output status structure
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_service_get_status(
    const dap_chain_net_vpn_client_service_t *a_service,
    dap_chain_net_vpn_client_service_status_t *a_out_status
);

/**
 * @brief Get current state
 * @param a_service Service instance
 * @return Current state
 */
dap_chain_net_vpn_client_service_state_t dap_chain_net_vpn_client_service_get_state(
    const dap_chain_net_vpn_client_service_t *a_service
);

/**
 * @brief Set state change callback
 * @param a_service Service instance
 * @param a_callback Callback function
 * @param a_user_data User data
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_service_set_state_callback(
    dap_chain_net_vpn_client_service_t *a_service,
    dap_chain_net_vpn_client_service_state_callback_t a_callback,
    void *a_user_data
);

/**
 * @brief Convert state to string
 * @param a_state State enum value
 * @return State name string (do not free)
 */
const char* dap_chain_net_vpn_client_service_state_to_string(
    dap_chain_net_vpn_client_service_state_t a_state
);

/**
 * @brief Check if service is connected
 * @param a_service Service instance
 * @return true if connected or reconnecting, false otherwise
 */
bool dap_chain_net_vpn_client_service_is_connected(
    const dap_chain_net_vpn_client_service_t *a_service
);

/**
 * @brief Update statistics (bytes sent/received)
 * @param a_service Service instance
 * @param a_bytes_sent Bytes sent
 * @param a_bytes_received Bytes received
 */
void dap_chain_net_vpn_client_service_update_stats(
    dap_chain_net_vpn_client_service_t *a_service,
    uint64_t a_bytes_sent,
    uint64_t a_bytes_received
);

#ifdef __cplusplus
} // extern "C"
#endif
