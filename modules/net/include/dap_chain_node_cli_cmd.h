/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
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

#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_node.h"
#include "dap_chain_node_cli.h"

int dap_chain_node_cli_cmd_values_parse_net_chain(int *a_arg_index,int a_argc, char **a_argv, char ** a_str_reply,
                             dap_chain_t ** a_chain, dap_chain_net_t ** a_net);

/**
 * global_db command
 */
int com_global_db(int a_argc,  char **a_argv, char **a_str_reply);

/**
 * Node command
 */
int com_node(int a_argc,  char **a_argv, char **a_str_reply);

/**
 * Traceroute command
 *
 * return 0 OK, -1 Err
 */
int com_traceroute(int a_argc,  char** argv, char **a_str_reply);

/**
 * Tracepath command
 *
 * return 0 OK, -1 Err
 */
int com_tracepath(int a_argc,  char** argv, char **a_str_reply);

/**
 * Ping command
 *
 * return 0 OK, -1 Err
 */
int com_ping(int a_argc,  char** argv, char **a_str_reply);

/**
 * Help command
 */
int com_help(int a_argc,  char **a_argv, char **a_str_reply);

int com_version(int a_argc, char **a_argv, char **a_str_reply);

/**
 * Token declaration
 */
int com_token_decl(int a_argc,  char **a_argv, char ** str_reply);

int com_token_update(int a_argc, char **a_argv, char ** a_str_reply);

/**
 * Token declaration add sign
 */
int com_token_decl_sign ( int a_argc,  char **a_argv, char ** str_reply);

/*
 * Token update sign
 */
int com_token_update_sign(int argc, char ** argv, char ** a_str_reply);

/**
 * Token emission
 */
int com_token_emit (int a_argc,  char **a_argv, char ** str_reply);


/**
 * com_tx_create command
 *
 * Wallet info
 */
int com_tx_wallet(int a_argc, char **a_argv, char **a_str_reply);

/**
 * com_tx_create command
 *
 * Create transaction
 */
int com_tx_create(int a_argc, char **a_argv, char **a_str_reply);
int com_tx_create_json(int a_argc, char **a_argv, char **a_str_reply);
int com_tx_cond_create(int a_argc, char **a_argv, char **a_str_reply);

/**
 * tx_verify command
 *
 * Verifing transaction
 */
int com_tx_verify(int a_argc, char ** a_argv, char **a_str_reply);

/**
 * tx_history command
 *
 * Transaction history for an address
 */
int com_tx_history(int a_argc, char **a_argv, char **a_str_reply);

// Print log info
int com_print_log(int a_argc, char **a_argv, char **a_str_reply);

// Print statistics
int com_stats(int a_argc, char **a_argv, char **a_str_reply);

int com_exit(int a_argc, char **a_argv, char **a_str_reply);

int cmd_gdb_import(int a_argc, char **a_argv, char **a_str_reply);
int cmd_gdb_export(int a_argc, char **a_argv, char **a_str_reply);

int com_mempool(int a_argc, char **a_argv, char  **a_str_reply);
/**
 * Place public CA into the mempool
 */
int com_mempool_add_ca( int a_argc,  char **a_argv, char **a_str_reply);
int com_chain_ca_pub( int a_argc,  char **a_argv, char **a_str_reply);
int com_chain_ca_copy( int a_argc,  char **a_argv, char **a_str_reply);
int com_signer(int a_argc, char **a_argv, char **a_str_reply);
//remove func
int cmd_remove(int a_argc, char **a_argv, char ** a_str_reply);
