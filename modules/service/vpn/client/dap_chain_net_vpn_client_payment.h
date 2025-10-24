/*
 * Authors:
 * Cellframe Team <https://cellframe.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2025
 * All rights reserved.

 This file is part of Cellframe Node VPN Client

    Cellframe Node VPN Client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cellframe Node VPN Client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any Cellframe Node VPN Client based project.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file dap_chain_net_vpn_client_payment.h
 * @brief Cellframe VPN Client Payment Handler
 * 
 * This module handles payment modes for VPN client connections:
 * - Free mode: Limited bandwidth/time access
 * - Paid mode: Full access with blockchain transaction proof
 * 
 * Architecture:
 * - Client sends payment_tx_hash to VPN service (not to stream layer)
 * - VPN service validates transaction and decides to accept/reject
 * - Stream layer remains agnostic to payment logic
 * 
 * @date 2025-10-23
 * @author Cellframe Team
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "dap_common.h"
#include "dap_hash.h"

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
int dap_chain_net_vpn_client_payment_config_init(dap_chain_net_vpn_client_payment_config_t *a_config,
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
 * @brief Serialize payment config to send to VPN service
 * 
 * Creates a binary packet with payment information that will be sent
 * to VPN service via VPN channel (not via stream handshake).
 * 
 * Packet format:
 * - 32 bytes: tx_hash
 * - 1 byte: network_name length
 * - N bytes: network_name (UTF-8)
 * 
 * @param a_config Payment configuration
 * @param a_out_data Output buffer (allocated by function, caller must free)
 * @param a_out_size Output size in bytes
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_payment_serialize(const dap_chain_net_vpn_client_payment_config_t *a_config,
                                                 uint8_t **a_out_data,
                                                 size_t *a_out_size);

/**
 * @brief Get human-readable payment status message
 * 
 * @param a_status Payment status code
 * @return Status message string
 */
const char* dap_chain_net_vpn_client_payment_status_to_string(dap_chain_net_vpn_client_payment_status_t a_status);


