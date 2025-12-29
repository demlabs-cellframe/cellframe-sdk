/*
 * Authors:
 * CellFrame Team <https://cellframe.net>
 * DeM Labs Inc.   <https://demlabs.net>
 *
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * This file is part of CellFrame SDK
 *
 * CellFrame SDK is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CellFrame SDK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_chain.h"
#include "dap_chain_ledger.h"

/**
 * @brief Common types and helpers for net-srv that services can use without depending on net module
 * @details This header provides minimal interface for services to interact with network
 *          without creating circular dependencies. Services only work with ledger and IDs.
 */

/**
 * @brief Get chain ID by name from network (wrapper for services)
 * @param a_net_id Network ID
 * @param a_chain_name Chain name
 * @return Chain ID or 0 if not found
 */
dap_chain_id_t dap_chain_net_srv_get_chain_id_by_name(dap_chain_net_id_t a_net_id, const char *a_chain_name);

/**
 * @brief Get default chain ID by type from network (wrapper for services)
 * @param a_net_id Network ID
 * @param a_chain_type Chain type
 * @return Chain ID or 0 if not found
 */
dap_chain_id_t dap_chain_net_srv_get_chain_id_by_type(dap_chain_net_id_t a_net_id, dap_chain_type_t a_chain_type);

/**
 * @brief Get network ID by name (wrapper for services)
 * @param a_net_name Network name
 * @return Network ID
 */
dap_chain_net_id_t dap_chain_net_srv_get_net_id_by_name(const char *a_net_name);

/**
 * @brief Register callbacks from net module (called by net during init)
 * @details This allows net-srv to provide net functionality to services without depending on net
 */
void dap_chain_net_srv_set_net_callbacks(
    dap_chain_id_t (*a_get_chain_id_by_name)(dap_chain_net_id_t, const char *),
    dap_chain_id_t (*a_get_chain_id_by_type)(dap_chain_net_id_t, dap_chain_type_t),
    dap_chain_net_id_t (*a_get_net_id_by_name)(const char *)
);
