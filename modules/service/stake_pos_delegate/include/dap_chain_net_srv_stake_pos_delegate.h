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
    UT_hash_handle hh,ht;
} dap_chain_net_srv_stake_item_t;


typedef struct dap_chain_net_srv_stake_cache_data {
    dap_chain_hash_fast_t tx_hash;
    dap_chain_addr_t signing_addr;
} DAP_ALIGN_PACKED dap_chain_net_srv_stake_cache_data_t;

typedef struct dap_chain_net_srv_stake_cache_item {
    dap_chain_hash_fast_t tx_hash;
    dap_chain_addr_t signing_addr;
    UT_hash_handle hh;
} dap_chain_net_srv_stake_cache_item_t;

typedef struct dap_chain_net_srv_stake {
    uint256_t delegate_allowed_min;
    dap_chain_net_srv_stake_item_t *itemlist;
    dap_chain_net_srv_stake_item_t *tx_itemlist;
    dap_chain_net_srv_stake_cache_item_t *cache;
} dap_chain_net_srv_stake_t;

int dap_chain_net_srv_stake_pos_delegate_init();
void dap_chain_net_srv_stake_pos_delegate_deinit();

void dap_chain_net_srv_stake_key_delegate(dap_chain_net_t *a_net, dap_chain_addr_t *a_signing_addr, dap_hash_fast_t *a_stake_tx_hash,
                                          uint256_t a_value, dap_chain_node_addr_t *a_node_addr);
void dap_chain_net_srv_stake_key_invalidate(dap_chain_addr_t *a_signing_addr);
void dap_chain_net_srv_stake_set_allowed_min_value(uint256_t a_value);
uint256_t dap_chain_net_srv_stake_get_allowed_min_value();

bool dap_chain_net_srv_stake_key_delegated(dap_chain_addr_t *a_addr);
int dap_chain_net_srv_stake_verify_key_and_node(dap_chain_addr_t* a_signing_addr, dap_chain_node_addr_t* a_node_addr);
dap_list_t *dap_chain_net_srv_stake_get_validators(dap_chain_net_id_t a_net_id);

bool dap_chain_net_srv_stake_get_fee_validators(dap_chain_net_t *a_net,
                                                uint256_t *a_max_fee, uint256_t *a_average_fee, uint256_t *a_min_fee);

void dap_chain_net_srv_stake_get_fee_validators_str(dap_chain_net_t *a_net, dap_string_t *a_string);

int dap_chain_net_srv_stake_load_cache(dap_chain_net_t *a_net);
void dap_chain_net_srv_stake_cache_purge(dap_chain_net_t *a_net);

dap_chain_datum_decree_t *dap_chain_net_srv_stake_decree_approve(dap_chain_net_t *a_net,
                                                                 dap_hash_fast_t *a_stake_tx_hash, dap_cert_t *a_cert);
