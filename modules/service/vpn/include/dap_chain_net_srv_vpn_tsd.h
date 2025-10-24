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

#include <stdint.h>
#include "dap_chain_datum_tx.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Transaction Specific Data (TSD) types for VPN service
 * 
 * Use with standard dap_chain_datum_tx_item_tsd_create() API.
 * 
 * Example:
 *   uint8_t hop_index = 2;
 *   dap_chain_tx_tsd_t *tsd = dap_chain_datum_tx_item_tsd_create(
 *       &hop_index, VPN_TSD_TYPE_MULTIHOP_HOP_INDEX, sizeof(hop_index));
 *   dap_chain_datum_tx_add_item(&tx, tsd);
 *   DAP_DELETE(tsd);
 */

// Multi-hop route: array of dap_chain_node_addr_t for complete route
#define VPN_TSD_TYPE_MULTIHOP_ROUTE         0x1001

// Hop index: uint8_t - which hop in route this transaction is for
#define VPN_TSD_TYPE_MULTIHOP_HOP_INDEX     0x1002

// Tunnel count: uint8_t - number of parallel tunnels for this hop
#define VPN_TSD_TYPE_MULTIHOP_TUNNEL_COUNT  0x1003

// Previous hop TX: dap_chain_hash_fast_t - hash of previous hop's conditional TX
#define VPN_TSD_TYPE_MULTIHOP_PREV_HOP_TX   0x1004

// Session ID: uint32_t - unique identifier for multi-hop session
#define VPN_TSD_TYPE_MULTIHOP_SESSION_ID    0x1005

// Total hops: uint8_t - total number of hops in route
#define VPN_TSD_TYPE_MULTIHOP_TOTAL_HOPS    0x1006

// Tunnel ID: uint8_t - tunnel identifier for parallel tunnels
#define VPN_TSD_TYPE_MULTIHOP_TUNNEL_ID     0x1007

// Bytes forwarded: uint64_t - number of bytes forwarded through this hop
#define VPN_TSD_TYPE_MULTIHOP_BYTES_FWD     0x1008

// Next hop address: dap_chain_node_addr_t - address of next hop (if not last)
#define VPN_TSD_TYPE_MULTIHOP_NEXT_HOP      0x1009

#ifdef __cplusplus
}
#endif
