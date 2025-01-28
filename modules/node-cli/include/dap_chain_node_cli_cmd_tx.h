/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
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

#include "dap_chain.h"
#include "dap_chain_ledger.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"

typedef struct dap_chain_tx_hash_processed_ht{
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
}dap_chain_tx_hash_processed_ht_t;

typedef enum s_com_ledger_err{
    DAP_CHAIN_NODE_CLI_COM_LEDGER_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_LEDGER_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR,
    DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_LEDGER_INCOMPATIBLE_PARAMS_ERR,
    DAP_CHAIN_NODE_CLI_COM_LEDGER_WALLET_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_COM_LEDGER_TRESHOLD_ERR,
    DAP_CHAIN_NODE_CLI_COM_LEDGER_LACK_ERR,
    DAP_CHAIN_NODE_CLI_COM_LEDGER_NET_FIND_ERR,
    DAP_CHAIN_NODE_CLI_COM_LEDGER_ID_NET_ADDR_DIF_ERR,
    DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR,
    DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_HASH_ERR,

    /* add custom codes here */

    DAP_CHAIN_NODE_CLI_COM_LEDGER_UNKNOWN /* MAX */
} s_com_ledger_err_t;

typedef enum s_com_token_err{
    DAP_CHAIN_NODE_CLI_COM_TOKEN_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_HASH_ERR,
    DAP_CHAIN_NODE_CLI_COM_TOKEN_FOUND_ERR,

    /* add custom codes here */

    DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN /* MAX */
} s_com_token_err_t;

#ifdef __cplusplus
extern "C" {
#endif

void s_dap_chain_tx_hash_processed_ht_free(dap_chain_tx_hash_processed_ht_t **l_hash_processed);

/**
 *
 * return history json
 */
json_object * dap_db_history_tx(json_object* a_json_arr_reply, dap_chain_hash_fast_t* a_tx_hash, dap_chain_t * a_chain, const char *a_hash_out_type, dap_chain_net_t * l_net);
json_object * dap_db_history_addr(json_object* a_json_arr_reply, dap_chain_addr_t * a_addr, dap_chain_t * a_chain, const char *a_hash_out_type, const char * l_addr_str, json_object *json_obj_summary, size_t a_limit, size_t a_offset,
bool a_brief,
const char *a_srv,
dap_chain_tx_tag_action_type_t a_action, bool a_head);
json_object * dap_db_tx_history_to_json(json_object* a_json_arr_reply,
                                        dap_chain_hash_fast_t* a_tx_hash,
                                        dap_hash_fast_t * l_atom_hash,
                                        dap_chain_datum_tx_t * l_tx,
                                        dap_chain_t * a_chain, 
                                        const char *a_hash_out_type, 
                                        dap_chain_datum_iter_t *a_datum_iter,
                                        int l_ret_code,
                                        bool *accepted_tx,
                                        bool out_brief);

json_object *dap_db_history_tx_all(json_object* a_json_arr_reply, dap_chain_t *l_chain, dap_chain_net_t *l_net,
                                    const char *l_hash_out_type, json_object *json_obj_summary,
                                    size_t a_limit, size_t a_offset, bool out_brief,
                                    const char *a_srv,
                                    dap_chain_tx_tag_action_type_t a_action, bool a_head);

bool s_dap_chain_datum_tx_out_data(json_object* a_json_arr_reply,
                                          dap_chain_datum_tx_t *a_datum,
                                          dap_ledger_t *a_ledger,
                                          json_object * json_obj_out,
                                          const char *a_hash_out_type,
                                          dap_chain_hash_fast_t *a_tx_hash);

/**
 * ledger command
 *
 */
int com_ledger(int a_argc, char ** a_argv, void **a_str_reply);

/**
 * token command
 *
 */
int com_token(int a_argc, char ** a_argv, void **a_str_reply);

/**
 * decree command
 *
 */
int cmd_decree(int a_argc, char **a_argv, void **a_str_reply);

#ifdef __cplusplus
}
#endif