/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
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
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdint.h>
#include <string.h>
#include "dap_chain_common.h"
#include "dap_chain_node.h"
#include "dap_chain.h"


#define DAP_CHAIN_NET_NAME_MAX 32

typedef  enum dap_chain_net_state{
    NET_STATE_OFFLINE = 0,
    NET_STATE_LINKS_PING,
    NET_STATE_LINKS_CONNECTING,
    NET_STATE_LINKS_ESTABLISHED,
    NET_STATE_SYNC_GDB,
    NET_STATE_SYNC_CHAINS,
    NET_STATE_STAND_BY,
} dap_chain_net_state_t;


typedef struct dap_chain_net{
    struct {
        dap_chain_net_id_t id;
        dap_chain_cell_id_t cell_id; // Cell where the node is connected to. {{0}} if not celled(sharder) blockchain
        char * name;
        char * gdb_groups_prefix;
        dap_chain_t * chains; // double-linked list of chains
    } pub;
    uint8_t pvt[];
} dap_chain_net_t;


int dap_chain_net_init(void);
void dap_chain_net_deinit(void);

int dap_chain_net_load(const char * a_net_name);

int dap_chain_net_state_go_to(dap_chain_net_t * a_net, dap_chain_net_state_t a_new_state);

inline static int dap_chain_net_start(dap_chain_net_t * a_net){ return dap_chain_net_state_go_to(a_net,NET_STATE_STAND_BY); }
inline static int dap_chain_net_stop(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_OFFLINE); }
inline static int dap_chain_net_links_establish(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_LINKS_ESTABLISHED); }
inline static int dap_chain_net_sync_chains(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_SYNC_CHAINS); }
inline static int dap_chain_net_sync_gdb(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_SYNC_GDB); }
inline static int dap_chain_net_sync_all(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_STAND_BY); }

void dap_chain_net_delete( dap_chain_net_t * a_net);
void dap_chain_net_proc_datapool (dap_chain_net_t * a_net);

dap_chain_net_t * dap_chain_net_by_name( const char * a_name);
dap_chain_net_t * dap_chain_net_by_id( dap_chain_net_id_t a_id);
dap_chain_net_id_t dap_chain_net_id_by_name( const char * a_name);

dap_chain_t * dap_chain_net_get_chain_by_name( dap_chain_net_t * l_net, const char * a_name);

dap_chain_node_addr_t * dap_chain_net_get_cur_addr( dap_chain_net_t * l_net);

void dap_chain_net_links_connect(dap_chain_net_t * a_net);


/**
 * @brief dap_chain_net_get_gdb_group_mempool
 * @param l_chain
 * @return
 */
static inline char * dap_chain_net_get_gdb_group_mempool(dap_chain_t * l_chain)
{
    dap_chain_net_t * l_net = dap_chain_net_by_id(l_chain->net_id);
    char * l_ret = NULL;
    if ( l_net ) {
        const char c_mempool_group_str[]="mempool";
        size_t l_ret_size =  strlen( l_net->pub.gdb_groups_prefix ) + 1 +
                strlen( l_chain->name)+1+strlen(c_mempool_group_str)+1;
        l_ret = DAP_NEW_Z_SIZE(char, l_ret_size);
        snprintf( l_ret,l_ret_size,"%s.%s.%s",l_net->pub.gdb_groups_prefix,l_chain->name,c_mempool_group_str);
    }
    return l_ret;
}
