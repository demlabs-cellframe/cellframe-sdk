/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2021-2025
 * All rights reserved.
 *
 * This file is part of DAP SDK the open source project
 *
 *    DAP SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    DAP SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "dap_chain_wallet.h"
#include "dap_chain_net.h"
#include "dap_timerfd.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Balance monitoring for VPN client
 * 
 * Periodically checks wallet balance and triggers notifications
 * when balance drops below configured thresholds.
 */

/**
 * @brief Balance notification callback
 * 
 * @param a_wallet Wallet being monitored
 * @param a_net Network
 * @param a_token Token ticker
 * @param a_balance Current balance
 * @param a_threshold Threshold that triggered notification
 * @param a_user_data User data passed during monitor initialization
 */
typedef void (*dap_vpn_balance_notification_cb_t)(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    const char *a_token,
    uint256_t a_balance,
    uint256_t a_threshold,
    void *a_user_data);

/**
 * @brief Balance monitor configuration
 */
typedef struct dap_vpn_balance_monitor_config {
    uint32_t check_interval_sec;           // Check interval in seconds (default: 300 = 5 min)
    uint256_t low_balance_threshold;       // Threshold for low balance warning
    uint256_t critical_balance_threshold;  // Threshold for critical balance (auto-disconnect)
    dap_vpn_balance_notification_cb_t notification_callback;
    void *callback_user_data;
} dap_vpn_balance_monitor_config_t;

/**
 * @brief Balance monitor handle
 */
typedef struct dap_vpn_balance_monitor dap_vpn_balance_monitor_t;

/**
 * @brief Start balance monitoring for wallet
 * 
 * @param a_wallet Wallet to monitor
 * @param a_net Network
 * @param a_token Token ticker
 * @param a_config Monitor configuration
 * @return Monitor handle or NULL on error
 */
dap_vpn_balance_monitor_t* dap_vpn_balance_monitor_start(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    const char *a_token,
    const dap_vpn_balance_monitor_config_t *a_config);

/**
 * @brief Stop balance monitoring
 * 
 * @param a_monitor Monitor handle
 */
void dap_vpn_balance_monitor_stop(dap_vpn_balance_monitor_t *a_monitor);

/**
 * @brief Force immediate balance check
 * 
 * @param a_monitor Monitor handle
 * @return 0 on success, negative on error
 */
int dap_vpn_balance_monitor_check_now(dap_vpn_balance_monitor_t *a_monitor);

/**
 * @brief Get current balance (cached from last check)
 * 
 * @param a_monitor Monitor handle
 * @param[out] a_balance Output balance
 * @return 0 on success, negative on error
 */
int dap_vpn_balance_monitor_get_cached_balance(
    dap_vpn_balance_monitor_t *a_monitor,
    uint256_t *a_balance);

/**
 * @brief Update threshold values
 * 
 * @param a_monitor Monitor handle
 * @param a_low_threshold New low balance threshold (or NULL to keep current)
 * @param a_critical_threshold New critical threshold (or NULL to keep current)
 * @return 0 on success, negative on error
 */
int dap_vpn_balance_monitor_set_thresholds(
    dap_vpn_balance_monitor_t *a_monitor,
    const uint256_t *a_low_threshold,
    const uint256_t *a_critical_threshold);

#ifdef __cplusplus
}
#endif

