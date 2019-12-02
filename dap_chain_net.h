/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Aleksandr Lysikov <alexander.lysikov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2019
* All rights reserved.

This file is part of CellFrame SDK the open source project

CellFrame SDK is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CellFrame SDK is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>

#include "win32/ip.h"
#include "win32/iphdr.h"
#define herror perror
#endif


#include <stdint.h>
#include <string.h>
#include "dap_strfuncs.h"
#include "dap_chain_common.h"
#include "dap_chain_node.h"
#include "dap_chain.h"
#include "dap_chain_ledger.h"


#define DAP_CHAIN_NET_NAME_MAX 32

typedef  enum dap_chain_net_state{
    NET_STATE_OFFLINE = 0,
    NET_STATE_LINKS_PREPARE,
    NET_STATE_LINKS_CONNECTING,
    NET_STATE_LINKS_ESTABLISHED,
    NET_STATE_ADDR_REQUEST, // Waiting for address assign
    NET_STATE_ONLINE,
    NET_STATE_SYNC_GDB,
    NET_STATE_SYNC_CHAINS,
} dap_chain_net_state_t;

typedef struct dap_chain_net{
    struct {
        dap_chain_net_id_t id;
        dap_chain_cell_id_t cell_id; // Cell where the node is connected to. {{0}} if not celled(sharder) blockchain
        char * name;
        char * gdb_groups_prefix;
        char * gdb_nodes_aliases;
        char * gdb_nodes;

        dap_chain_t * chains; // double-linked list of chains
        dap_ledger_t  *ledger;
    } pub;
    uint8_t pvt[];
} dap_chain_net_t;


int dap_chain_net_init(void);
void dap_chain_net_deinit(void);

void dap_chain_net_load_all();

int dap_chain_net_state_go_to(dap_chain_net_t * a_net, dap_chain_net_state_t a_new_state);

inline static int dap_chain_net_start(dap_chain_net_t * a_net){ return dap_chain_net_state_go_to(a_net,NET_STATE_ONLINE); }
inline static int dap_chain_net_stop(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_OFFLINE); }
inline static int dap_chain_net_links_establish(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_LINKS_ESTABLISHED); }
inline static int dap_chain_net_sync_chains(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_SYNC_CHAINS); }
inline static int dap_chain_net_sync_gdb(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_SYNC_GDB); }
inline static int dap_chain_net_sync_all(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_SYNC_GDB); }//NET_STATE_ONLINE

void dap_chain_net_delete( dap_chain_net_t * a_net);
void dap_chain_net_proc_datapool (dap_chain_net_t * a_net);

dap_chain_net_t * dap_chain_net_by_name( const char * a_name);
dap_chain_net_t * dap_chain_net_by_id( dap_chain_net_id_t a_id);
dap_chain_net_id_t dap_chain_net_id_by_name( const char * a_name);
dap_ledger_t * dap_chain_ledger_by_net_name( const char * a_net_name);

dap_chain_t * dap_chain_net_get_chain_by_name( dap_chain_net_t * l_net, const char * a_name);

dap_chain_node_addr_t * dap_chain_net_get_cur_addr( dap_chain_net_t * l_net);
uint64_t dap_chain_net_get_cur_addr_int(dap_chain_net_t * l_net);
dap_chain_cell_id_t * dap_chain_net_get_cur_cell( dap_chain_net_t * l_net);

dap_list_t* dap_chain_net_get_node_list(dap_chain_net_t * l_net);

void dap_chain_net_links_connect(dap_chain_net_t * a_net);

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
    TX_SEARCH_TYPE_NET_UNSPENT
}dap_chain_net_tx_search_type_t;

dap_chain_datum_tx_t * dap_chain_net_get_tx_by_hash(dap_chain_net_t * a_net, dap_chain_hash_fast_t * a_tx_hash,
                                                     dap_chain_net_tx_search_type_t a_search_type);

/**
 * @brief dap_chain_net_get_gdb_group_mempool
 * @param l_chain
 * @return
 */
DAP_STATIC_INLINE char * dap_chain_net_get_gdb_group_mempool(dap_chain_t * l_chain)
{
    dap_chain_net_t * l_net = l_chain ? dap_chain_net_by_id(l_chain->net_id) : NULL;
    if ( l_net ) {
        const char c_mempool_group_str[]="mempool";
		return dap_strdup_printf("%s.chain-%s.%s",l_net->pub.gdb_groups_prefix,l_chain->name,c_mempool_group_str);
    }
    return NULL;
}

dap_chain_t * dap_chain_net_get_chain_by_chain_type(dap_chain_net_t * l_net, dap_chain_type_t a_datum_type);
char * dap_chain_net_get_gdb_group_mempool_by_chain_type(dap_chain_net_t * l_net, dap_chain_type_t a_datum_type);
