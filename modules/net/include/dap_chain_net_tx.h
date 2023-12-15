/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2022
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

#include "dap_chain_net.h"
#include "dap_chain_datum_tx_items.h"

typedef enum dap_chain_net_tx_search_type {
    /// Search local, in memory, possible load data from drive to memory
    TX_SEARCH_TYPE_LOCAL,
    /// Do the request to the network if its not full node, search inside shard
    TX_SEARCH_TYPE_CELL,
    /// Do the request for unspent txs in cell
    TX_SEARCH_TYPE_CELL_UNSPENT,
    /// Do the search in whole network and request tx from others cells if need
    TX_SEARCH_TYPE_NET,
    /// Do the search in whole network but search only unspent
    TX_SEARCH_TYPE_NET_UNSPENT,
    /// Do the request for spent txs in cell
    TX_SEARCH_TYPE_CELL_SPENT,
    /// Do the search in blockchain
    TX_SEARCH_TYPE_BLOCKCHAIN
}dap_chain_net_tx_search_type_t;

typedef struct dap_chain_datum_tx_spends_item{
    dap_chain_datum_tx_t * tx;
    dap_hash_fast_t tx_hash;

    dap_chain_tx_out_cond_t *out_cond;
    dap_chain_tx_in_cond_t *in_cond;

    dap_chain_datum_tx_t * tx_next;
    UT_hash_handle hh;
}dap_chain_datum_tx_spends_item_t;

typedef struct dap_chain_datum_tx_spends_items{
    dap_chain_datum_tx_spends_item_t * tx_outs;
    dap_chain_datum_tx_spends_item_t * tx_ins;
} dap_chain_datum_tx_spends_items_t;
typedef void (dap_chain_net_tx_hash_callback_t)(dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_tx, void *a_arg);


// TX functions
dap_chain_datum_tx_t * dap_chain_net_get_tx_by_hash(dap_chain_net_t * a_net, dap_chain_hash_fast_t * a_tx_hash,
                                                     dap_chain_net_tx_search_type_t a_search_type);

dap_list_t * dap_chain_net_get_tx_cond_chain(dap_chain_net_t * a_net, dap_hash_fast_t * a_tx_hash, dap_chain_net_srv_uid_t a_srv_uid);

uint256_t dap_chain_net_get_tx_total_value(dap_chain_net_t * a_net, dap_chain_datum_tx_t * a_tx );

void dap_chain_net_get_tx_all(dap_chain_net_t * a_net, dap_chain_net_tx_search_type_t a_search_type ,dap_chain_net_tx_hash_callback_t a_tx_callback, void * a_arg);


dap_list_t * dap_chain_net_get_tx_cond_all_by_srv_uid(dap_chain_net_t * a_net, const dap_chain_net_srv_uid_t a_srv_uid,
                                                      const dap_time_t a_time_from, const dap_time_t a_time_to,
                                                     const dap_chain_net_tx_search_type_t a_search_type);
dap_list_t * dap_chain_net_get_tx_cond_all_for_addr(dap_chain_net_t * a_net, dap_chain_addr_t * a_addr, dap_chain_net_srv_uid_t a_srv_uid);

dap_list_t * dap_chain_net_get_tx_all_from_tx(dap_chain_net_t * a_net, dap_hash_fast_t * l_tx_hash);




dap_chain_datum_tx_spends_items_t * dap_chain_net_get_tx_cond_all_with_spends_by_srv_uid(dap_chain_net_t * a_net, const dap_chain_net_srv_uid_t a_srv_uid,
                                                      const dap_time_t a_time_from, const dap_time_t a_time_to,
                                                     const dap_chain_net_tx_search_type_t a_search_type);
void dap_chain_datum_tx_spends_item_free(dap_chain_datum_tx_spends_item_t * a_items);
void dap_chain_datum_tx_spends_items_free(dap_chain_datum_tx_spends_items_t * a_items);

bool dap_chain_net_tx_get_fee(dap_chain_net_id_t a_net_id, uint256_t *a_value, dap_chain_addr_t *a_addr);
bool dap_chain_net_tx_set_fee(dap_chain_net_id_t a_net_id, uint256_t a_value, dap_chain_addr_t a_addr);
