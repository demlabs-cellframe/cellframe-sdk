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

#include "dap_vpn_client_balance_monitor.h"
#include "dap_vpn_client_wallet.h"
#include "dap_common.h"
#include "dap_timerfd.h"
#include <string.h>

#define LOG_TAG "vpn_balance_monitor"

#define DEFAULT_CHECK_INTERVAL_SEC 300  // 5 minutes

/**
 * @brief Balance monitor internal structure
 */
struct dap_vpn_balance_monitor {
    dap_chain_wallet_t *wallet;
    dap_chain_net_t *net;
    char token[DAP_CHAIN_TICKER_SIZE_MAX];
    
    dap_vpn_balance_monitor_config_t config;
    
    dap_timerfd_t *check_timer;
    uint256_t last_balance;
    time_t last_check_time;
    
    bool low_balance_warned;        // Already warned about low balance
    bool critical_balance_warned;    // Already warned about critical balance
};

/**
 * @brief Timer callback for periodic balance checks
 */
static bool s_balance_check_timer_callback(void *a_arg)
{
    dap_vpn_balance_monitor_t *l_monitor = (dap_vpn_balance_monitor_t *)a_arg;
    if (!l_monitor) {
        return false;  // Stop timer
    }
    
    // Perform balance check
    dap_vpn_balance_monitor_check_now(l_monitor);
    
    return true;  // Continue timer
}

/**
 * @brief Start balance monitoring
 */
dap_vpn_balance_monitor_t* dap_vpn_balance_monitor_start(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    const char *a_token,
    const dap_vpn_balance_monitor_config_t *a_config)
{
    if (!a_wallet || !a_net || !a_token) {
        log_it(L_ERROR, "Invalid arguments for balance monitor");
        return NULL;
    }
    
    dap_vpn_balance_monitor_t *l_monitor = DAP_NEW_Z(dap_vpn_balance_monitor_t);
    if (!l_monitor) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    l_monitor->wallet = a_wallet;
    l_monitor->net = a_net;
    dap_stpcpy(l_monitor->token, a_token);
    
    // Copy config or use defaults
    if (a_config) {
        memcpy(&l_monitor->config, a_config, sizeof(dap_vpn_balance_monitor_config_t));
    } else {
        // Default config
        l_monitor->config.check_interval_sec = DEFAULT_CHECK_INTERVAL_SEC;
        l_monitor->config.low_balance_threshold = dap_chain_uint256_from(1000000000);  // 1 token
        l_monitor->config.critical_balance_threshold = dap_chain_uint256_from(100000000);  // 0.1 token
        l_monitor->config.notification_callback = NULL;
        l_monitor->config.callback_user_data = NULL;
    }
    
    // Perform initial check
    dap_vpn_balance_monitor_check_now(l_monitor);
    
    // Start periodic timer
    l_monitor->check_timer = dap_timerfd_start(
        l_monitor->config.check_interval_sec * 1000,  // Convert to milliseconds
        s_balance_check_timer_callback,
        l_monitor
    );
    
    if (!l_monitor->check_timer) {
        log_it(L_ERROR, "Failed to start balance check timer");
        DAP_DELETE(l_monitor);
        return NULL;
    }
    
    log_it(L_NOTICE, "Balance monitor started for wallet (check interval: %u sec)",
           l_monitor->config.check_interval_sec);
    
    return l_monitor;
}

/**
 * @brief Stop balance monitoring
 */
void dap_vpn_balance_monitor_stop(dap_vpn_balance_monitor_t *a_monitor)
{
    if (!a_monitor)
        return;
    
    if (a_monitor->check_timer) {
        dap_timerfd_delete_mt(a_monitor->check_timer);
        a_monitor->check_timer = NULL;
    }
    
    log_it(L_INFO, "Balance monitor stopped");
    DAP_DELETE(a_monitor);
}

/**
 * @brief Force immediate balance check
 */
int dap_vpn_balance_monitor_check_now(dap_vpn_balance_monitor_t *a_monitor)
{
    if (!a_monitor) {
        return -1;
    }
    
    // Query current balance
    uint256_t l_balance = {};
    if (dap_vpn_client_wallet_get_balance(
            a_monitor->wallet,
            a_monitor->net,
            a_monitor->token,
            &l_balance) < 0) {
        log_it(L_WARNING, "Failed to query balance");
        return -2;
    }
    
    // Update cached balance
    a_monitor->last_balance = l_balance;
    a_monitor->last_check_time = time(NULL);
    
    log_it(L_DEBUG, "Balance check: "UINT256_FORMAT_U" %s",
           UINT256_FORMAT_PARAM(l_balance), a_monitor->token);
    
    // Check thresholds
    bool l_is_low = compare256(l_balance, a_monitor->config.low_balance_threshold) < 0;
    bool l_is_critical = compare256(l_balance, a_monitor->config.critical_balance_threshold) < 0;
    
    if (l_is_critical && !a_monitor->critical_balance_warned) {
        log_it(L_WARNING, "CRITICAL: Balance below threshold! Balance: "UINT256_FORMAT_U", Threshold: "UINT256_FORMAT_U,
               UINT256_FORMAT_PARAM(l_balance),
               UINT256_FORMAT_PARAM(a_monitor->config.critical_balance_threshold));
        
        if (a_monitor->config.notification_callback) {
            a_monitor->config.notification_callback(
                a_monitor->wallet,
                a_monitor->net,
                a_monitor->token,
                l_balance,
                a_monitor->config.critical_balance_threshold,
                a_monitor->config.callback_user_data
            );
        }
        
        a_monitor->critical_balance_warned = true;
        a_monitor->low_balance_warned = true;  // Also mark low balance as warned
        
    } else if (l_is_low && !a_monitor->low_balance_warned) {
        log_it(L_WARNING, "WARNING: Low balance! Balance: "UINT256_FORMAT_U", Threshold: "UINT256_FORMAT_U,
               UINT256_FORMAT_PARAM(l_balance),
               UINT256_FORMAT_PARAM(a_monitor->config.low_balance_threshold));
        
        if (a_monitor->config.notification_callback) {
            a_monitor->config.notification_callback(
                a_monitor->wallet,
                a_monitor->net,
                a_monitor->token,
                l_balance,
                a_monitor->config.low_balance_threshold,
                a_monitor->config.callback_user_data
            );
        }
        
        a_monitor->low_balance_warned = true;
        
    } else if (!l_is_low) {
        // Balance is above thresholds - reset warning flags
        a_monitor->low_balance_warned = false;
        a_monitor->critical_balance_warned = false;
    }
    
    return 0;
}

/**
 * @brief Get cached balance
 */
int dap_vpn_balance_monitor_get_cached_balance(
    dap_vpn_balance_monitor_t *a_monitor,
    uint256_t *a_balance)
{
    if (!a_monitor || !a_balance) {
        return -1;
    }
    
    *a_balance = a_monitor->last_balance;
    return 0;
}

/**
 * @brief Update thresholds
 */
int dap_vpn_balance_monitor_set_thresholds(
    dap_vpn_balance_monitor_t *a_monitor,
    const uint256_t *a_low_threshold,
    const uint256_t *a_critical_threshold)
{
    if (!a_monitor) {
        return -1;
    }
    
    if (a_low_threshold) {
        a_monitor->config.low_balance_threshold = *a_low_threshold;
        log_it(L_INFO, "Low balance threshold updated: "UINT256_FORMAT_U,
               UINT256_FORMAT_PARAM(*a_low_threshold));
    }
    
    if (a_critical_threshold) {
        a_monitor->config.critical_balance_threshold = *a_critical_threshold;
        log_it(L_INFO, "Critical balance threshold updated: "UINT256_FORMAT_U,
               UINT256_FORMAT_PARAM(*a_critical_threshold));
    }
    
    // Reset warning flags to re-check with new thresholds
    a_monitor->low_balance_warned = false;
    a_monitor->critical_balance_warned = false;
    
    // Trigger immediate check
    dap_vpn_balance_monitor_check_now(a_monitor);
    
    return 0;
}

