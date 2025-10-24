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
#include "dap_enc_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Wallet Manager for VPN Client
 * 
 * Thin wrapper over dap_chain_wallet_* API with mode detection (standalone/embedded).
 * Provides unified interface for wallet operations regardless of deployment mode.
 */

/**
 * @brief Initialize wallet manager
 * 
 * @param a_wallets_path Path to wallets directory
 * @return 0 on success, negative on error
 */
int dap_vpn_client_wallet_init(const char *a_wallets_path);

/**
 * @brief Deinitialize wallet manager
 */
void dap_vpn_client_wallet_deinit(void);

/**
 * @brief Create a new wallet
 * 
 * @param a_wallet_name Wallet name
 * @param a_sig_type Signature algorithm type
 * @return Wallet pointer or NULL on error
 */
dap_chain_wallet_t* dap_vpn_client_wallet_create(
    const char *a_wallet_name,
    dap_enc_key_type_t a_sig_type);

/**
 * @brief Open an existing wallet
 * 
 * @param a_wallet_name Wallet name
 * @return Wallet pointer or NULL on error
 */
dap_chain_wallet_t* dap_vpn_client_wallet_open(const char *a_wallet_name);

/**
 * @brief Close wallet
 * 
 * @param a_wallet Wallet to close
 */
void dap_vpn_client_wallet_close(dap_chain_wallet_t *a_wallet);

/**
 * @brief Get wallet address for specific network
 * 
 * @param a_wallet Wallet
 * @param a_net Network
 * @return Address pointer or NULL on error (caller must free with DAP_DELETE)
 */
dap_chain_addr_t* dap_vpn_client_wallet_get_addr(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net);

/**
 * @brief Get wallet balance in specific network
 * 
 * Note: In standalone mode, this requires connection to remote node
 * 
 * @param a_wallet Wallet
 * @param a_net Network
 * @param a_token_ticker Token ticker (e.g., "KEL", "CELL")
 * @param[out] a_balance Output balance
 * @return 0 on success, negative on error
 */
int dap_vpn_client_wallet_get_balance(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    const char *a_token_ticker,
    uint256_t *a_balance);

/**
 * @brief List all available wallets
 * 
 * @param[out] a_count Output: number of wallets
 * @return Array of wallet names (caller must free each string and array), or NULL
 */
char** dap_vpn_client_wallet_list(size_t *a_count);

/**
 * @brief Check if running in embedded mode (within cellframe-node)
 * 
 * @return true if embedded, false if standalone
 */
bool dap_vpn_client_wallet_is_embedded_mode(void);

#ifdef __cplusplus
}
#endif

