/*
 * Authors:
 * Dmitriy Gerasimov <naeper@demlabs.net>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 *
 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "dap_chain_common.h"
#include "dap_list.h"
#include "dap_math_ops.h"
#include "uthash.h"
#include "dap_chain_types.h"

typedef struct dap_chain dap_chain_t;
typedef struct dap_ledger dap_ledger_t;
struct dap_config;

#define DAP_CHAIN_NET_NAME_MAX 32
#define DAP_CHAIN_NET_NODES_POSTFIX "nodes.list"

typedef enum dap_chain_net_state {
    NET_STATE_LOADING = 0,
    NET_STATE_OFFLINE,
    NET_STATE_LINKS_PREPARE,
    NET_STATE_LINKS_CONNECTING,
    NET_STATE_LINKS_ESTABLISHED,
    NET_STATE_SYNC_CHAINS,
    NET_STATE_ONLINE
} dap_chain_net_state_t;

typedef struct dap_chain_net {
    struct {
        dap_chain_net_id_t id;
        char name[DAP_CHAIN_NET_NAME_MAX + 1];
        char gdb_nodes[DAP_CHAIN_NET_NAME_MAX + sizeof(DAP_CHAIN_NET_NODES_POSTFIX) + 1];
        const char *gdb_groups_prefix;
        const char *native_ticker;
        // PoA section
        dap_list_t *keys;               // List of PoA certs for net
        uint16_t keys_min_count;        // PoA minimum required number
        //
        dap_chain_t *chains;            // double-linked list of chains
        dap_ledger_t *ledger;
        uint256_t fee_value;            // Net fee
        dap_chain_addr_t fee_addr;
        dap_chain_net_id_t *bridged_networks;   // List of bridged network ID's allowed to cross-network TX
        uint16_t bridged_networks_count;
        struct dap_config *config;
        dap_chain_node_role_t node_role;
        bool mempool_autoproc;
    } pub;
    UT_hash_handle hh, hh2;
    uint8_t pvt[];
} dap_chain_net_t;

