/**
 * @file dap_chain_net_srv_vpn_tun.h
 * @brief VPN Service TUN Device Management Module
 * @details TUN device initialization, event socket callbacks, packet routing
 * 
 * @date 2025-10-25
 * @copyright (C) 2023-2025 Cellframe Network
 */

#pragma once

#include "dap_events_socket.h"
#include "dap_worker.h"
#include "dap_config.h"
#include <netinet/in.h>

// Forward declarations for unified TUN API
typedef struct dap_net_tun dap_net_tun_t;
typedef struct dap_net_tun_channel_info dap_net_tun_channel_info_t;

// TUN device initialization

/**
 * @brief Initialize TUN device infrastructure (s_raw_server structure)
 * @return 0 on success, negative on error
 */
int vpn_srv_tun_init(void);

/**
 * @brief Create TUN device using unified TUN API
 * @param a_config Configuration
 * @return 0 on success, negative on error
 */
int vpn_srv_tun_create(dap_config_t *a_config);

/**
 * @brief Create event stream for TUN file descriptor
 * @param a_worker Worker to attach to
 * @param a_tun_fd TUN device file descriptor
 * @return Events socket wrapping TUN device
 */
dap_events_socket_t *vpn_srv_tun_event_stream_create(dap_worker_t *a_worker, int a_tun_fd);

// TUN event socket callbacks

/**
 * @brief TUN event socket constructor
 * @param a_es Events socket
 * @param a_arg User argument (unused)
 */
void vpn_srv_es_tun_new(dap_events_socket_t *a_es, void *a_arg);

/**
 * @brief TUN event socket destructor
 * @param a_es Events socket
 * @param a_arg User argument (unused)
 */
void vpn_srv_es_tun_delete(dap_events_socket_t *a_es, void *a_arg);

/**
 * @brief TUN data read callback - routes packets to clients based on destination IP
 * @param a_es Events socket
 * @param a_arg User argument (unused)
 */
void vpn_srv_es_tun_read(dap_events_socket_t *a_es, void *a_arg);

/**
 * @brief TUN write callback - writes VPN packets to TUN device
 * @param a_es Events socket
 * @param a_arg User argument (unused)
 * @return false (handled synchronously)
 */
bool vpn_srv_es_tun_write(dap_events_socket_t *a_es, void *a_arg);

/**
 * @brief TUN write finished callback - restores buffer size
 * @param a_es Events socket
 * @param a_arg User argument (unused)
 */
void vpn_srv_es_tun_write_finished(dap_events_socket_t *a_es, void *a_arg);

/**
 * @brief TUN error callback
 * @param a_es Events socket
 * @param a_error Error code
 */
void vpn_srv_es_tun_error(dap_events_socket_t *a_es, int a_error);

// TUN data callback (from unified TUN API)

/**
 * @brief TUN data received callback (unified TUN API - NEW SIGNATURE)
 * @param a_tun TUN device handle
 * @param a_data Received packet data
 * @param a_data_size Packet size
 * @param a_channel_info Channel routing info (worker + UUID) - NULL for SERVER mode
 * @param a_arg User argument (unused)
 */
void vpn_srv_tun_data_received_callback(
    dap_net_tun_t *a_tun,
    const void *a_data,
    size_t a_data_size,
    const dap_net_tun_channel_info_t *a_channel_info,
    void *a_arg);

/**
 * @brief TUN error callback (unified TUN API - NEW SIGNATURE)
 * @param a_tun TUN device handle
 * @param a_error Error code
 * @param a_error_msg Error message (may be NULL)
 * @param a_arg User argument (unused)
 */
void vpn_srv_tun_error_callback(
    dap_net_tun_t *a_tun,
    int a_error,
    const char *a_error_msg,
    void *a_arg);

