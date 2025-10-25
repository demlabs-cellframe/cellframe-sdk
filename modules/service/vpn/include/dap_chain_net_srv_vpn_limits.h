/**
 * @file dap_chain_net_srv_vpn_limits.h
 * @brief VPN Service Traffic Limits & Statistics Module
 * @details Bandwidth tracking, time-based limits, GDB persistence
 * 
 * @date 2025-10-25
 * @copyright (C) 2023-2025 Cellframe Network
 */

#pragma once

#include "dap_stream_ch.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_stream_session.h"

/**
 * @brief Update traffic limits after data transfer
 * @param a_ch Stream channel
 * @param a_srv_session Service session
 * @param a_usage Usage record
 * @param a_bytes Bytes transferred
 */
void vpn_srv_limits_update(dap_stream_ch_t *a_ch,
                            dap_chain_net_srv_stream_session_t *a_srv_session,
                            dap_chain_net_srv_usage_t *a_usage,
                            size_t a_bytes);

/**
 * @brief Save remaining limits to GDB (timer callback wrapper)
 * @param a_arg remain_limits_save_arg_t structure
 * @return true to continue timer, false to stop
 */
bool vpn_srv_limits_save(void *a_arg);

/**
 * @brief Get remaining service limits from GDB
 * @param a_srv Service handle
 * @param a_usage_id Usage ID
 * @param a_srv_client Service client
 * @return Remaining service structure, NULL if not found (must be freed by caller)
 */
dap_stream_ch_chain_net_srv_remain_service_store_t* vpn_srv_limits_get_remain_service(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client);

/**
 * @brief Save remaining service limits to GDB
 * @param a_srv Service handle
 * @param a_usage_id Usage ID
 * @param a_srv_client Service client
 * @return 0 on success, negative on error
 */
int vpn_srv_limits_save_remain_service(dap_chain_net_srv_t *a_srv,
                                        uint32_t a_usage_id,
                                        dap_chain_net_srv_client_remote_t *a_srv_client);

/**
 * @brief Get server public key hash string for GDB operations
 * @param a_usage Usage record
 * @return Public key hash string (must be freed by caller), NULL on error
 */
char* vpn_srv_limits_get_pkey_str(dap_chain_net_srv_usage_t *a_usage);


