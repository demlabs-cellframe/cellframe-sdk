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

#include "dap_vpn_client_wallet.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "dap_common.h"
#include "dap_file_utils.h"
#include <string.h>
#include <dirent.h>

#define LOG_TAG "vpn_client_wallet"

// Global state
static char *s_wallets_path = NULL;

/**
 * @brief Initialize wallet manager
 */
int dap_vpn_client_wallet_init(const char *a_wallets_path)
{
    if (!a_wallets_path) {
        log_it(L_ERROR, "Wallets path is NULL");
        return -1;
    }
    
    s_wallets_path = dap_strdup(a_wallets_path);
    if (!s_wallets_path) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -2;
    }
    
    // Ensure wallets directory exists
    dap_mkdir_with_parents(s_wallets_path);
    
    log_it(L_NOTICE, "VPN client wallet manager initialized: path=%s", s_wallets_path);
    return 0;
}

/**
 * @brief Deinitialize wallet manager
 */
void dap_vpn_client_wallet_deinit(void)
{
    DAP_DELETE(s_wallets_path);
    s_wallets_path = NULL;
}

/**
 * @brief Check if running in embedded mode
 * @note Embedded mode = blockchain networks are initialized
 */
bool dap_vpn_client_wallet_is_embedded_mode(void)
{
    // Check if any blockchain network is available
    // Try common network names
    const char *l_common_nets[] = {"Backbone", "KelVPN", "Raiden", "Keller", NULL};
    
    for (size_t i = 0; l_common_nets[i] != NULL; i++) {
        if (dap_chain_net_by_name(l_common_nets[i]) != NULL) {
            return true;  // Found at least one network - embedded mode
        }
    }
    
    return false;  // No networks found - standalone mode
}

/**
 * @brief Create a new wallet
 */
dap_chain_wallet_t* dap_vpn_client_wallet_create(
    const char *a_wallet_name,
    dap_enc_key_type_t a_sig_type)
{
    if (!a_wallet_name) {
        log_it(L_ERROR, "Wallet name is NULL");
        return NULL;
    }
    
    if (!s_wallets_path) {
        log_it(L_ERROR, "Wallet manager not initialized");
        return NULL;
    }
    
    // Use standard dap_chain_wallet_create API
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_create(
        a_wallet_name,
        s_wallets_path,
        dap_sign_type_from_key_type(a_sig_type),  // Convert enc_key_type to sign_type
        NULL  // no password
    );
    
    if (!l_wallet) {
        log_it(L_ERROR, "Failed to create wallet '%s'", a_wallet_name);
        return NULL;
    }
    
    log_it(L_NOTICE, "Created wallet '%s' with sig_type=%d", a_wallet_name, a_sig_type);
    return l_wallet;
}

/**
 * @brief Open an existing wallet
 */
dap_chain_wallet_t* dap_vpn_client_wallet_open(const char *a_wallet_name)
{
    if (!a_wallet_name) {
        log_it(L_ERROR, "Wallet name is NULL");
        return NULL;
    }
    
    if (!s_wallets_path) {
        log_it(L_ERROR, "Wallet manager not initialized");
        return NULL;
    }
    
    // Use standard dap_chain_wallet_open API
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(
        a_wallet_name,
        s_wallets_path,
        NULL  // network ID optional
    );
    
    if (!l_wallet) {
        log_it(L_ERROR, "Failed to open wallet '%s'", a_wallet_name);
        return NULL;
    }
    
    log_it(L_INFO, "Opened wallet '%s'", a_wallet_name);
    return l_wallet;
}

/**
 * @brief Close wallet
 */
void dap_vpn_client_wallet_close(dap_chain_wallet_t *a_wallet)
{
    if (!a_wallet)
        return;
    
    dap_chain_wallet_close(a_wallet);
    log_it(L_INFO, "Closed wallet");
}

/**
 * @brief Get wallet address for specific network
 */
dap_chain_addr_t* dap_vpn_client_wallet_get_addr(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net)
{
    if (!a_wallet || !a_net) {
        log_it(L_ERROR, "Invalid arguments: wallet=%p, net=%p", a_wallet, a_net);
        return NULL;
    }
    
    // Use standard API
    dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_addr) {
        log_it(L_ERROR, "Failed to get address for network '%s'", a_net->pub.name);
        return NULL;
    }
    
    // Make a copy for caller
    dap_chain_addr_t *l_addr_copy = DAP_NEW_Z(dap_chain_addr_t);
    if (l_addr_copy) {
        memcpy(l_addr_copy, l_addr, sizeof(dap_chain_addr_t));
    }
    
    return l_addr_copy;
}

/**
 * @brief Get wallet balance in specific network
 */
int dap_vpn_client_wallet_get_balance(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    const char *a_token_ticker,
    uint256_t *a_balance)
{
    if (!a_wallet || !a_net || !a_token_ticker || !a_balance) {
        log_it(L_ERROR, "Invalid arguments for get_balance");
        return -1;
    }
    
    // Get wallet address
    dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_addr) {
        log_it(L_ERROR, "Failed to get wallet address");
        return -2;
    }
    
    // Check mode
    if (dap_vpn_client_wallet_is_embedded_mode()) {
        // Embedded mode: direct ledger access
        dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);
        if (!l_ledger) {
            log_it(L_ERROR, "Ledger not found for network '%s'", a_net->pub.name);
            return -3;
        }
        
        *a_balance = dap_ledger_calc_balance(l_ledger, l_addr, a_token_ticker);
        char *l_balance_str = dap_chain_balance_print(*a_balance);
        log_it(L_DEBUG, "Balance (embedded): %s %s", l_balance_str, a_token_ticker);
        DAP_DELETE(l_balance_str);
        return 0;
        
    } else {
        // Standalone mode: need to query remote node
        log_it(L_WARNING, "Balance query in standalone mode not yet implemented - requires remote node connection");
        // TODO: Implement remote balance query via dap_chain_node_client
        *a_balance = uint256_0;
        return -4;
    }
}

/**
 * @brief List all available wallets
 */
char** dap_vpn_client_wallet_list(size_t *a_count)
{
    if (!a_count) {
        log_it(L_ERROR, "Count pointer is NULL");
        return NULL;
    }
    
    if (!s_wallets_path) {
        log_it(L_ERROR, "Wallet manager not initialized");
        return NULL;
    }
    
    DIR *l_dir = opendir(s_wallets_path);
    if (!l_dir) {
        log_it(L_WARNING, "Cannot open wallets directory: %s", s_wallets_path);
        *a_count = 0;
        return NULL;
    }
    
    // Count wallet files (*.dwallet extension)
    size_t l_wallet_count = 0;
    struct dirent *l_entry;
    while ((l_entry = readdir(l_dir)) != NULL) {
        if (l_entry->d_type == DT_REG) {
            size_t l_name_len = strlen(l_entry->d_name);
            if (l_name_len > 8 && strcmp(l_entry->d_name + l_name_len - 8, ".dwallet") == 0) {
                l_wallet_count++;
            }
        }
    }
    
    if (l_wallet_count == 0) {
        closedir(l_dir);
        *a_count = 0;
        return NULL;
    }
    
    // Allocate array
    char **l_wallet_names = DAP_NEW_Z_SIZE(char*, l_wallet_count * sizeof(char*));
    if (!l_wallet_names) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        closedir(l_dir);
        return NULL;
    }
    
    // Read wallet names
    rewinddir(l_dir);
    size_t l_idx = 0;
    while ((l_entry = readdir(l_dir)) != NULL && l_idx < l_wallet_count) {
        if (l_entry->d_type == DT_REG) {
            size_t l_name_len = strlen(l_entry->d_name);
            if (l_name_len > 8 && strcmp(l_entry->d_name + l_name_len - 8, ".dwallet") == 0) {
                // Copy wallet name without .dwallet extension
                char *l_name = DAP_NEW_Z_SIZE(char, l_name_len - 8 + 1);
                if (l_name) {
                    strncpy(l_name, l_entry->d_name, l_name_len - 8);
                    l_name[l_name_len - 8] = '\0';
                    l_wallet_names[l_idx] = l_name;
                    l_idx++;
                }
            }
        }
    }
    
    closedir(l_dir);
    *a_count = l_wallet_count;
    return l_wallet_names;
}

