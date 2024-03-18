/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
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
#include "dap_chain_net.h"
#include "dap_chain_node.h"
#include "dap_chain_node_cli.h"
#include "json.h"

int dap_chain_node_cli_cmd_values_parse_net_chain_for_json(int *a_arg_index, int a_argc,
                                                           char **a_argv,
                                                           dap_chain_t **a_chain, dap_chain_net_t **a_net);


int dap_chain_node_cli_cmd_values_parse_net_chain(int *a_arg_index, int a_argc, char **a_argv, void **a_str_reply,
                             dap_chain_t ** a_chain, dap_chain_net_t ** a_net);

/**
 * global_db command
 */
int com_global_db(int a_argc,  char **a_argv, void **a_str_reply);

/**
 * Node command
 */
int com_node(int a_argc,  char **a_argv, void **a_str_reply);

#ifndef DAP_OS_ANDROID
/**
 * Traceroute command
 *
 * return 0 OK, -1 Err
 */
int com_traceroute(int a_argc,  char** argv, void **a_str_reply);

/**
 * Tracepath command
 *
 * return 0 OK, -1 Err
 */
int com_tracepath(int a_argc,  char** argv, void **a_str_reply);

/**
 * Ping command
 *
 * return 0 OK, -1 Err
 */
int com_ping(int a_argc,  char** argv, void **a_str_reply);
#endif
/**
 * Help command
 */
int com_help(int a_argc,  char **a_argv, void **a_str_reply);

int com_version(int a_argc, char **a_argv, void **a_str_reply);

/**
 * Token declaration
 */
int com_token_decl(int a_argc,  char **a_argv, void **a_str_reply);

int com_token_update(int a_argc, char **a_argv, void **a_str_reply);

/**
 * Token declaration add sign
 */
int com_token_decl_sign ( int a_argc,  char **a_argv, void **a_str_reply);

/*
 * Token update sign
 */
int com_token_update_sign(int argc, char ** argv, void **a_str_reply);

/**
 * Token emission
 */
int com_token_emit (int a_argc,  char **a_argv, void **a_str_reply);

typedef enum s_com_tx_wallet_err{
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_MEMORY_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_FOUND_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_TO_LONG_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ALREADY_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ACTIVE_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CONVERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_BACKUP_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PROTECTION_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_HASH_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CHAIN_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INTERNAL_ERR,

    /* add custom codes here */

    DAP_CHAIN_NODE_CLI_COM_TX_UNKNOWN /* MAX */
} s_com_tx_wallet_err_t;

/**
 * com_tx_create command
 *
 * Wallet info
 */
int com_tx_wallet(int a_argc, char **a_argv, void **a_str_reply);

/**
 * com_tx_create command
 *
 * Create transaction
 */
int com_tx_create(int a_argc, char **a_argv, void **a_str_reply);
int com_tx_create_json(int a_argc, char **a_argv, void **a_str_reply);
int com_tx_cond_create(int a_argc, char **a_argv, void **a_str_reply);
int com_txs_cond_remove(int a_argc, char **a_argv, void **a_str_reply);

/**
 * tx_verify command
 *
 * Verifing transaction
 */
int com_tx_verify(int a_argc, char ** a_argv, void **a_str_reply);

typedef enum s_com_tx_history_err{
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_MEMORY_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR,

    /* add custom codes here */

    //DAP_CHAIN_NODE_CLI_COM_TX_UNKNOWN /* MAX */
} s_com_tx_history_err_t;

char *dap_chain_node_cli_com_tx_history_err(int a_code);

/**
 * tx_history command
 *
 * Transaction history for an address
 */
int com_tx_history(int a_argc, char ** a_argv, void **a_str_reply);


// Print log info
int com_print_log(int a_argc, char **a_argv, void **a_str_reply);

// Print statistics
int com_stats(int a_argc, char **a_argv, void **a_str_reply);

int com_exit(int a_argc, char **a_argv, void **a_str_reply);

int cmd_gdb_import(int a_argc, char **a_argv, void **a_str_reply);
int cmd_gdb_export(int a_argc, char **a_argv, void **a_str_reply);

typedef enum cmd_mempool_list_err{
    DAP_CHAIN_NODE_CLI_COM_MEMPOOL_LIST_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_MEMPOOL_LIST_CAN_NOT_READ_EMISSION,
    DAP_CHAIN_NODE_CLI_COM_MEMPOOL_LIST_CHAIN_NOT_FOUND,
    DAP_CHAIN_NODE_CLI_COM_MEMPOOL_LIST_CAN_NOT_GET_MEMPOOL_GROUP,
    /* add custom codes here */

    DAP_CHAIN_NODE_CLI_COM_MEMPOOL_LIST_UNKNOWN /* MAX */
} cmd_mempool_list_err_t;
int com_mempool(int a_argc, char **a_argv, void **a_str_reply);
/**
 * Place public CA into the mempool
 */
int com_chain_ca_pub( int a_argc,  char **a_argv, void **a_str_reply);
int com_chain_ca_copy( int a_argc,  char **a_argv, void **a_str_reply);
int com_signer(int a_argc, char **a_argv, void **a_str_reply);
//remove func
int cmd_remove(int a_argc, char **a_argv, void **a_str_reply);

