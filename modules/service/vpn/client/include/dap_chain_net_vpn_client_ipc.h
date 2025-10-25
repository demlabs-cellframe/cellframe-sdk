#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "dap_chain_net_vpn_client_protocol.h"
#include "dap_server.h"
#include "dap_events_socket.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief IPC Server configuration
 */
typedef struct dap_chain_net_vpn_client_ipc_config {
    char *socket_path;                              ///< Unix socket path (Linux/macOS)
    char *named_pipe;                               ///< Named pipe path (Windows)
    uint32_t max_clients;                           ///< Maximum concurrent clients
    uint32_t request_timeout_sec;                   ///< Request timeout in seconds
    bool auto_cleanup;                              ///< Auto cleanup socket on start
} dap_chain_net_vpn_client_ipc_config_t;

/**
 * @brief IPC request handler callback
 * @param a_request IPC request
 * @param a_user_data User data
 * @return IPC response (caller owns, must free)
 */
typedef dap_chain_net_vpn_client_ipc_response_t* (*dap_chain_net_vpn_client_ipc_handler_t)(
    const dap_chain_net_vpn_client_ipc_request_t *a_request,
    void *a_user_data
);

/**
 * @brief Initialize IPC server
 * @param a_config Server configuration
 * @param a_handler Request handler callback
 * @param a_user_data User data for handler
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_ipc_init(const dap_chain_net_vpn_client_ipc_config_t *a_config,
                                       dap_chain_net_vpn_client_ipc_handler_t a_handler,
                                       void *a_user_data);

/**
 * @brief Deinitialize IPC server
 */
void dap_chain_net_vpn_client_ipc_deinit();

/**
 * @brief Start IPC server
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_ipc_start();

/**
 * @brief Stop IPC server
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_ipc_stop();

/**
 * @brief Check if IPC server is running
 * @return true if running, false otherwise
 */
bool dap_chain_net_vpn_client_ipc_is_running();

/**
 * @brief Get number of active IPC clients
 * @return Number of active clients
 */
uint32_t dap_chain_net_vpn_client_ipc_get_client_count();

/**
 * @brief Broadcast event to all subscribed clients
 * @param a_event Event to broadcast
 * @return Number of clients notified, negative on error
 */
int dap_chain_net_vpn_client_ipc_broadcast_event(const dap_chain_net_vpn_client_ipc_event_t *a_event);

/**
 * @brief Broadcast event to specific client
 * @param a_client_fd Client file descriptor
 * @param a_event Event to send
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_ipc_send_event(int a_client_fd, const dap_chain_net_vpn_client_ipc_event_t *a_event);

#ifdef __cplusplus
} // extern "C"
#endif

