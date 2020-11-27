/*
 * Authors:
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

#include "dap_chain.h"
#include "dap_chain_common.h"

/**
 *
 * return history string
 */
char* dap_db_history_tx(dap_chain_hash_fast_t* a_tx_hash, dap_chain_t * a_chain, const char *a_hash_out_type);
char* dap_db_history_addr(dap_chain_addr_t * a_addr, dap_chain_t * a_chain, const char *a_hash_out_type);

/**
 * ledger command
 *
 */
int com_ledger(int a_argc, char ** a_argv, void *a_arg_func, char **a_str_reply);

/**
 * token command
 *
 */
int com_token(int a_argc, char ** a_argv, void *a_arg_func, char **a_str_reply);

