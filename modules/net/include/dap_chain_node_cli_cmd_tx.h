/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

 DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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
#include "dap_chain_common.h"
#include "json.h"

typedef struct dap_chain_tx_hash_processed_ht{
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
}dap_chain_tx_hash_processed_ht_t;

void s_dap_chain_tx_hash_processed_ht_free(dap_chain_tx_hash_processed_ht_t **l_hash_processed);

/**
 *
 * return history json
 */
json_object * dap_db_history_tx(dap_chain_hash_fast_t* a_tx_hash, dap_chain_t * a_chain, const char *a_hash_out_type, dap_chain_net_t * l_net);
json_object * dap_db_history_addr(dap_chain_addr_t * a_addr, dap_chain_t * a_chain, const char *a_hash_out_type, const char * l_addr_str, size_t a_limit, size_t a_offset);
json_object * dap_db_tx_history_to_json(dap_chain_hash_fast_t* a_tx_hash,
                                        dap_hash_fast_t * l_atom_hash,
                                        dap_chain_datum_tx_t * l_tx,
                                        dap_chain_t * a_chain, 
                                        const char *a_hash_out_type, 
                                        dap_chain_net_t * l_net,
                                        int l_ret_code,
                                        bool *accepted_tx,
                                        bool out_brief);
json_object *dap_db_history_tx_all(dap_chain_t *l_chain, dap_chain_net_t *l_net,
                                   const char *l_hash_out_type, json_object *json_obj_summary,
                                   size_t a_limit, size_t a_offset, bool out_brief);

/**
 * ledger command
 *
 */
int com_ledger(int a_argc, char ** a_argv, void **a_str_reply);

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

