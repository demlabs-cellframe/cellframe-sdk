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
#include "dap_math_ops.h"

#define DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID 0x13

typedef struct dap_chain_net_srv_stake_item {
    dap_chain_net_t *net;
    uint256_t value;
    dap_chain_addr_t signing_addr;
    dap_chain_hash_fast_t tx_hash;
    dap_chain_node_addr_t node_addr;
    UT_hash_handle hh;
} dap_chain_net_srv_stake_item_t;

typedef struct dap_chain_net_srv_stake {
    bool initialized;
    uint256_t delegate_allowed_min;
    dap_list_t *auth_cert_pkeys;
    dap_chain_net_srv_stake_item_t *itemlist;
} dap_chain_net_srv_stake_t;

int dap_chain_net_srv_stake_pos_delegate_init();
void dap_chain_net_srv_stake_pos_delegate_deinit();

void dap_chain_net_srv_stake_key_delegate(dap_chain_net_t *a_net, dap_chain_addr_t *a_signing_addr, dap_hash_fast_t *a_stake_tx_hash,
                                          uint256_t a_value, dap_chain_node_addr_t *a_node_addr);
bool dap_chain_net_srv_stake_key_delegated(dap_chain_addr_t *a_addr);
dap_list_t *dap_chain_net_srv_stake_get_validators();
void dap_chain_net_srv_stake_get_fee_validators(dap_chain_net_t *a_net, dap_string_t *a_string);
