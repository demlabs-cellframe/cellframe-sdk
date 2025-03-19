/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe  https://cellframe.net
 * Copyright  (c) 2019-2021
 * All rights reserved.

 This file is part of Cellframe SDK

 Cellframe SDK is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Cellframe SDK is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "dap_events_socket.h"
#include "dap_common.h"
#include "dap_config.h"
#include "uthash.h"

#include "dap_cli_server.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum dap_chain_node_cli_cmd {
    DAP_CHAIN_NODE_CLI_CMD_ID_EXIT,
    DAP_CHAIN_NODE_CLI_CMD_ID_TX_HISTORY,
    DAP_CHAIN_NODE_CLI_CMD_ID_WALLET,
    DAP_CHAIN_NODE_CLI_CMD_ID_MEMPOOL,
    DAP_CHAIN_NODE_CLI_CMD_ID_LEDGER,
    DAP_CHAIN_NODE_CLI_CMD_ID_TX_CREATE,
    DAP_CHAIN_NODE_CLI_CMD_ID_TX_CREATE_JSON,
    DAP_CHAIN_NODE_CLI_CMD_ID_TX_VERIFY,
    DAP_CHAIN_NODE_CLI_CMD_ID_TX_COND_CREATE,
    DAP_CHAIN_NODE_CLI_CMD_ID_TX_COND_REMOVE,
    DAP_CHAIN_NODE_CLI_CMD_ID_TX_COND_UNSPENT_FIND,
    DAP_CHAIN_NODE_CLI_CMD_ID_CHAIN_CA_COPY,
    DAP_CHAIN_NODE_CLI_CMD_ID_DAG,
    DAP_CHAIN_NODE_CLI_CMD_ID_DAG_POA,
    DAP_CHAIN_NODE_CLI_CMD_ID_BLOCK,
    DAP_CHAIN_NODE_CLI_CMD_ID_TOKEN,
    DAP_CHAIN_NODE_CLI_CMD_ID_ESBOCS,
    DAP_CHAIN_NODE_CLI_CMD_ID_GLOBAL_DB,
    DAP_CHAIN_NODE_CLI_CMD_ID_NET_SRV,
    DAP_CHAIN_NODE_CLI_CMD_ID_NET,
    DAP_CHAIN_NODE_CLI_CMD_ID_SRV_STAKE,
    DAP_CHAIN_NODE_CLI_CMD_ID_SRV_DATUM,
    DAP_CHAIN_NODE_CLI_CMD_ID_POLL,
    DAP_CHAIN_NODE_CLI_CMD_ID_SRV_XCHANGE,
    DAP_CHAIN_NODE_CLI_CMD_ID_EMIT_DELEGATE,
    DAP_CHAIN_NODE_CLI_CMD_ID_TOKEN_DECL,
    DAP_CHAIN_NODE_CLI_CMD_ID_TOKEN_UPDATE,
    DAP_CHAIN_NODE_CLI_CMD_ID_TOKEN_UPDATE_SIGN,
    DAP_CHAIN_NODE_CLI_CMD_ID_TOKEN_DECL_SIGN,
    DAP_CHAIN_NODE_CLI_CMD_ID_CHAIN_CA_PUB,
    DAP_CHAIN_NODE_CLI_CMD_ID_TOKEN_EMIT,
    DAP_CHAIN_NODE_CLI_CMD_ID_FIND,
    DAP_CHAIN_NODE_CLI_CMD_ID_VERSION,
    DAP_CHAIN_NODE_CLI_CMD_ID_REMOVE,
    DAP_CHAIN_NODE_CLI_CMD_ID_GDB_IMPORT,
    DAP_CHAIN_NODE_CLI_CMD_ID_GDB_EXPORT,
    DAP_CHAIN_NODE_CLI_CMD_ID_STATS,
    DAP_CHAIN_NODE_CLI_CMD_ID_PRINT_LOG,
    DAP_CHAIN_NODE_CLI_CMD_ID_STAKE_LOCK,
    DAP_CHAIN_NODE_CLI_CMD_ID_EXEC_CMD,
    DAP_CHAIN_NODE_CLI_CMD_ID_POLICY,
    DAP_CHAIN_NODE_CLI_CMD_ID_DECREE,
    DAP_CHAIN_NODE_CLI_CMD_ID_NODE,
    DAP_CHAIN_NODE_CLI_CMD_ID_VPN_STAT,
    DAP_CHAIN_NODE_CLI_CMD_ID_VPN_CLIENT,
    DAP_CHAIN_NODE_CLI_CMD_ID_HELP,
    DAP_CHAIN_NODE_CLI_CMD_ID_TOTAL
} dap_chain_node_cli_cmd_t;

/**
 * Initialization of the server side of the interaction
 * with the console kelvin-node-cli
 */
int dap_chain_node_cli_init(dap_config_t * g_config);

/**
 * Deinitialization of the server side
 */
void dap_chain_node_cli_delete(void);

#ifdef __cplusplus
}
#endif