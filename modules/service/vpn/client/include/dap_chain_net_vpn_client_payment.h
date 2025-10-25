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
#include "dap_chain_datum_tx.h"
#include "dap_chain_net_vpn_client_receipt.h"
#include "dap_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Payment configuration structure
 * 
 * This structure is used by VPN client to provide payment proof
 * via blockchain transaction hash. Payment is ALWAYS required.
 */
typedef struct dap_chain_net_vpn_client_payment_config {
    dap_hash_fast_t tx_hash;         ///< Transaction hash (256-bit) - REQUIRED
    char network_name[64];           ///< Network name ("Backbone", "Kelvin", etc.)
} dap_chain_net_vpn_client_payment_config_t;

/**
 * @brief Payment status result from server
 */
typedef enum dap_chain_net_vpn_client_payment_status {
    DAP_CHAIN_NET_VPN_PAYMENT_STATUS_ACCEPTED = 0,        ///< Payment accepted, connection granted
    DAP_CHAIN_NET_VPN_PAYMENT_STATUS_INVALID_FORMAT = 1,  ///< Invalid tx_hash format
    DAP_CHAIN_NET_VPN_PAYMENT_STATUS_NOT_FOUND = 2,       ///< Transaction not found on blockchain
    DAP_CHAIN_NET_VPN_PAYMENT_STATUS_PENDING = 3,         ///< Transaction not yet confirmed
    DAP_CHAIN_NET_VPN_PAYMENT_STATUS_INSUFFICIENT = 4,    ///< Payment amount too low
    DAP_CHAIN_NET_VPN_PAYMENT_STATUS_ALREADY_USED = 5,    ///< Payment already consumed
    DAP_CHAIN_NET_VPN_PAYMENT_STATUS_EXPIRED = 6,         ///< Payment validity period expired
    DAP_CHAIN_NET_VPN_PAYMENT_STATUS_NETWORK_MISMATCH = 7 ///< Wrong blockchain network
} dap_chain_net_vpn_client_payment_status_t;

/**
 * @brief Initialize payment configuration
 * 
 * @param a_config Payment config structure to initialize
 * @param a_tx_hash Transaction hash (hex string, 64 characters)
 * @param a_network Network name (e.g., "Backbone")
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_payment_config_init(
    dap_chain_net_vpn_client_payment_config_t *a_config,
    const char *a_tx_hash,
    const char *a_network);

/**
 * @brief Validate transaction hash format
 * 
 * @param a_tx_hash Transaction hash (hex string)
 * @return true if valid format, false otherwise
 */
bool dap_chain_net_vpn_client_payment_validate_tx_hash(const char *a_tx_hash);

/**
 * @brief Serialize payment config for network transmission
 * 
 * @param a_config Payment config
 * @param[out] a_out_data Output: serialized data (must be freed by caller)
 * @param[out] a_out_size Output: serialized data size
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_payment_serialize(
    const dap_chain_net_vpn_client_payment_config_t *a_config,
    uint8_t **a_out_data,
    size_t *a_out_size);

/**
 * @brief Get human-readable payment status message
 * 
 * @param a_status Payment status code
 * @return Status message string
 */
const char* dap_chain_net_vpn_client_payment_status_to_string(
    dap_chain_net_vpn_client_payment_status_t a_status);

/**
 * @brief Multi-hop payment finalization
 * 
 * After collecting all receipts from relay nodes, finalize payment by creating
 * a transaction that spends the conditional outputs using collected receipts as proof.
 */

/**
 * @brief Finalize multi-hop payment
 * 
 * Creates a finalization transaction with IN_COND for each hop's conditional transaction.
 * Includes all collected receipts as proof of service delivery.
 * 
 * @param a_wallet Client wallet for signing
 * @param a_net Network
 * @param a_collector Receipt collector with all collected receipts
 * @param[out] a_tx_hash Output: finalization transaction hash
 * @return 0 on success, negative on error
 */
int dap_vpn_client_payment_finalize_multihop(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    dap_vpn_client_receipt_collector_t *a_collector,
    dap_chain_hash_fast_t *a_tx_hash);

/**
 * @brief Estimate payment for multi-hop route
 * 
 * @param a_net Network
 * @param a_route Route (array of node addresses)
 * @param a_hop_count Number of hops
 * @param a_service_units Service units (bytes or seconds)
 * @param a_unit_type Unit type
 * @param[out] a_total_cost Output: total cost in datoshi
 * @return 0 on success, negative on error
 */
int dap_vpn_client_payment_estimate_multihop(
    dap_chain_net_t *a_net,
    const dap_chain_node_addr_t *a_route,
    uint8_t a_hop_count,
    uint64_t a_service_units,
    dap_chain_net_srv_price_unit_uid_t a_unit_type,
    uint256_t *a_total_cost);

/**
 * @brief Check if wallet has sufficient balance for multi-hop route
 * 
 * @param a_wallet Wallet
 * @param a_net Network
 * @param a_token_ticker Token ticker
 * @param a_total_cost Required amount
 * @return true if balance sufficient, false otherwise
 */
bool dap_vpn_client_payment_check_balance(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    const char *a_token_ticker,
    uint256_t a_total_cost);

#ifdef __cplusplus
}
#endif

