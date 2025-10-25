/**
 * @file dap_chain_net_srv_vpn_session.h
 * @brief VPN Service Session Management Module
 * @details Client session tracking, IP allocation, worker affinity
 * 
 * @date 2025-10-25
 * @copyright (C) 2023-2025 Cellframe Network
 */

#pragma once

#include "dap_stream_ch.h"
#include <netinet/in.h>

// Forward declaration
typedef struct dap_chain_net_srv_ch_vpn dap_chain_net_srv_ch_vpn_t;

/**
 * @brief Find VPN client session by destination IP address
 * @param a_ip_dst Destination IP address
 * @return Client structure or NULL if not found
 */
dap_chain_net_srv_ch_vpn_t* vpn_srv_session_find_by_ip(struct in_addr a_ip_dst);

/**
 * @brief Find VPN client session by stream channel
 * @param a_ch Stream channel
 * @return Client structure or NULL if not found
 */
dap_chain_net_srv_ch_vpn_t* vpn_srv_session_find_by_stream(dap_stream_ch_t *a_ch);

/**
 * @brief Add new client session to global registry
 * @param a_ch_vpn Client VPN structure
 * @return 0 on success, negative on error
 */
int vpn_srv_session_add(dap_chain_net_srv_ch_vpn_t *a_ch_vpn);

/**
 * @brief Remove client session from global registry
 * @param a_ch_vpn Client VPN structure
 * @return 0 on success, negative on error
 */
int vpn_srv_session_remove(dap_chain_net_srv_ch_vpn_t *a_ch_vpn);

/**
 * @brief Cleanup all client sessions (on service deinit)
 */
void vpn_srv_session_cleanup_all(void);

/**
 * @brief Add client to worker-local TUN socket registry
 * @param a_worker_id Worker ID
 * @param a_ch_vpn Client VPN structure
 * @param a_esocket Events socket
 * @return 0 on success, negative on error
 */
int vpn_srv_session_tun_socket_add(uint32_t a_worker_id,
                                    dap_chain_net_srv_ch_vpn_t *a_ch_vpn,
                                    dap_events_socket_t *a_esocket);

/**
 * @brief Remove client from worker-local TUN socket registry
 * @param a_worker_id Worker ID
 * @param a_addr Client IP address
 * @return 0 on success, negative on error
 */
int vpn_srv_session_tun_socket_remove(uint32_t a_worker_id, struct in_addr a_addr);

/**
 * @brief Update client worker affinity after reassignment
 * @param a_worker_id New worker ID
 * @param a_addr Client IP address
 * @param a_new_worker_id New worker ID
 * @return 0 on success, negative on error
 */
int vpn_srv_session_tun_socket_update_worker(uint32_t a_worker_id,
                                               struct in_addr a_addr,
                                               uint32_t a_new_worker_id);


