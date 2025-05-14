/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2022
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
#include "dap_json_rpc_errors.h"

typedef enum s_com_tx_create_json_err {
    DAP_CHAIN_NET_TX_CREATE_JSON_OK = 0,
    DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_JSON = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE,
    DAP_CHAIN_NET_TX_CREATE_JSON_WRONG_JSON_FORMAT,
    DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_NET,
    DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_NET_BY_NAME,
    DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_CHAIN_BY_NAME,
    DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_NET_IN_JSON,
    DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_ARRAY_ITEMS,
    DAP_CHAIN_NET_TX_CREATE_JSON_INVALID_ITEMS,
    DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_ADD_TRANSACTION_TO_MEMPOOL,
    DAP_CHAIN_NET_TX_CREATE_JSON_WRONG_ARGUMENTS,
    DAP_CHAIN_NET_TX_CREATE_JSON_ENOUGH_MEMORY,
    DAP_CHAIN_NET_TX_CREATE_JSON_INTEGER_OVERFLOW,
    DAP_CHAIN_NET_TX_CREATE_JSON_TRANSACTION_NOT_CORRECT_ERR,    
    DAP_CHAIN_NET_TX_CREATE_JSON_CANT_CREATED_ITEM_ERR,
    DAP_CHAIN_NET_TX_CREATE_JSON_SIGN_VERIFICATION_FAILED
}s_com_tx_create_json_err_t;

typedef enum s_type_of_tx {
    DAP_CHAIN_NET_TX_NORMAL = 0,
    DAP_CHAIN_NET_TX_STAKE_LOCK,
    DAP_CHAIN_NET_TX_STAKE_UNLOCK,
    DAP_CHAIN_NET_TX_REWARD,

    DAP_CHAIN_NET_TX_TYPE_ERR
}s_type_of_tx_t;

typedef struct dap_tx_creator_tokenizer {
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t sum;
    UT_hash_handle hh;
} dap_tx_creator_tokenizer_t;

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
typedef void (dap_chain_net_tx_hash_callback_t)(dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, void *a_arg);

typedef struct dap_chain_datum_tx_cond_list_item {
    dap_hash_fast_t hash;
    dap_chain_datum_tx_t *tx;
} dap_chain_datum_tx_cond_list_item_t;

#ifdef __cplusplus
extern "C" {
#endif

// TX functions
dap_chain_datum_tx_t * dap_chain_net_get_tx_by_hash(dap_chain_net_t * a_net, dap_chain_hash_fast_t * a_tx_hash,
                                                     dap_chain_net_tx_search_type_t a_search_type);

dap_list_t * dap_chain_net_get_tx_cond_chain(dap_chain_net_t * a_net, dap_hash_fast_t * a_tx_hash, dap_chain_net_srv_uid_t a_srv_uid);

void dap_chain_net_get_tx_all(dap_chain_net_t * a_net, dap_chain_net_tx_search_type_t a_search_type ,dap_chain_net_tx_hash_callback_t a_tx_callback, void * a_arg);

//return list of dap_chain_datum_tx_cond_list_item_t
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

/**
 * @brief Compose transaction from json. If a_net is NULL it means offline tx creation and 
 *          tx will be created from json as is without any checks and conversions.
 * @param a_tx_json input json
 * @param a_net network. If NULL it means offline tx creation
 * @param a_json_obj_error json object for tx items errors messages
 * @param a_out_tx pointer to output transaction pointer
 * @param a_items_count count of total items in input json transaction
 * @param a_items_ready count of valid items in output transaction
 * 
 * @return s_com_tx_create_json_err_t status code
 */
int dap_chain_net_tx_create_by_json(json_object *a_tx_json, dap_chain_net_t *a_net, json_object *a_json_obj_error, 
                                        dap_chain_datum_tx_t** a_out_tx, size_t* a_items_count, size_t *a_items_ready);

/**
 * @brief Convert binary transaction to json
 * @param a_tx input transaction
 * @param a_out_json pointer to json object created by json_object_new_object()
 * 
 * @return s_com_tx_create_json_err_t status code
 */
int dap_chain_net_tx_to_json(dap_chain_datum_tx_t *a_tx, json_object *a_out_json, const char *a_net_name);

#ifdef __cplusplus
}
#endif
