/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "dap_chain_ledger.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_order.h"

#define DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID 0x13

typedef struct dap_chain_net_srv_stake_item {
    bool is_active;
    dap_chain_net_t *net;
    char token[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t value;
    dap_chain_addr_t addr_hldr;
    dap_chain_addr_t addr_fee;
    dap_chain_addr_t signing_addr;
    uint256_t fee_value;
    dap_chain_hash_fast_t tx_hash;
    dap_chain_node_addr_t node_addr;
    UT_hash_handle hh;
} dap_chain_net_srv_stake_item_t;

typedef struct dap_srv_stake_order_ext {
    dap_chain_addr_t addr_hldr;
    dap_chain_addr_t signing_addr;
    uint256_t fee_value;
} dap_srv_stake_order_ext_t;

typedef struct dap_chain_net_srv_stake {
    bool initialized;
    dap_chain_net_srv_stake_item_t *itemlist;
} dap_chain_net_srv_stake_t;

int dap_chain_net_srv_stake_pos_delegate_init();
void dap_chain_net_srv_stake_pos_delegate_deinit();
bool dap_chain_net_srv_stake_validator(dap_chain_addr_t *a_addr, dap_chain_datum_t *a_datum);
bool dap_chain_net_srv_stake_key_delegated(dap_chain_addr_t *a_addr);
dap_list_t *dap_chain_net_srv_stake_get_validators();
