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

#include <stdint.h>
#include <string.h>
#include "dap_net.h"
#include "dap_stream_ch.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_chain_common.h"
#include "dap_chain_node.h"
#include "dap_chain.h"
#include "dap_chain_ledger.h"


#define DAP_CHAIN_NET_NAME_MAX 32

struct dap_chain_node_info;
typedef struct dap_chain_node_client dap_chain_node_client_t;

typedef  enum dap_chain_net_state{
    NET_STATE_OFFLINE = 0,
    NET_STATE_LINKS_PREPARE,
    NET_STATE_LINKS_CONNECTING,
    NET_STATE_LINKS_ESTABLISHED,
    NET_STATE_ADDR_REQUEST, // Waiting for address assign
    NET_STATE_SYNC_GDB,
    NET_STATE_SYNC_CHAINS,
    NET_STATE_ONLINE
} dap_chain_net_state_t;

static const char * g_net_state_str[]={
    [NET_STATE_OFFLINE] = "NET_STATE_OFFLINE",
    [NET_STATE_LINKS_PREPARE]="NET_STATE_LINKS_PREPARE",
    [NET_STATE_LINKS_CONNECTING]="NET_STATE_LINKS_CONNECTING",
    [NET_STATE_LINKS_ESTABLISHED]="NET_STATE_LINKS_ESTABLISHED",
    [NET_STATE_ADDR_REQUEST]="NET_STATE_ADDR_REQUEST", // Waiting for address assign
    [NET_STATE_SYNC_GDB]="NET_STATE_SYNC_GDB",
    [NET_STATE_SYNC_CHAINS]="NET_STATE_SYNC_CHAINS",
    [NET_STATE_ONLINE]="NET_STATE_ONLINE"
};


typedef struct dap_chain_net{
    struct {
        dap_chain_net_id_t id;
        char * name;
        char * gdb_groups_prefix;
        char * gdb_nodes_aliases;
        char * gdb_nodes;

        bool mempool_autoproc;

        dap_chain_t * chains; // double-linked list of chains
        dap_chain_t * default_chain;
        dap_ledger_t  *ledger;
    } pub;
    uint8_t pvt[];
} dap_chain_net_t;

int dap_chain_net_init(void);
void dap_chain_net_deinit(void);

void dap_chain_net_load_all();

int dap_chain_net_state_go_to(dap_chain_net_t * a_net, dap_chain_net_state_t a_new_state);
dap_chain_net_state_t dap_chain_net_get_target_state(dap_chain_net_t *a_net);

inline static int dap_chain_net_start(dap_chain_net_t * a_net){ return dap_chain_net_state_go_to(a_net,NET_STATE_ONLINE); }
inline static int dap_chain_net_stop(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_OFFLINE); }
inline static int dap_chain_net_links_establish(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_LINKS_ESTABLISHED); }
inline static int dap_chain_net_sync_gdb(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_SYNC_GDB); }
inline static int dap_chain_net_sync_chains(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_SYNC_CHAINS); }
inline static int dap_chain_net_sync_all(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_SYNC_CHAINS); }
void dap_chain_net_set_state ( dap_chain_net_t * l_net, dap_chain_net_state_t a_state);
dap_chain_net_state_t dap_chain_net_get_state ( dap_chain_net_t * l_net);

/**
 * @brief dap_chain_net_state_to_str
 * @param a_state
 * @return
 */
static inline const char * dap_chain_net_state_to_str(dap_chain_net_state_t a_state){
    if(a_state< NET_STATE_OFFLINE || a_state > NET_STATE_ONLINE)
        return "<Undefined net state>";
    else
        return g_net_state_str[a_state];
}

void dap_chain_net_delete( dap_chain_net_t * a_net);
void dap_chain_net_proc_mempool (dap_chain_net_t * a_net);
void dap_chain_net_set_flag_sync_from_zero(dap_chain_net_t * a_net, bool a_flag_sync_from_zero);
bool dap_chain_net_get_flag_sync_from_zero( dap_chain_net_t * a_net);

bool dap_chain_net_sync_trylock(dap_chain_net_t *a_net, dap_chain_node_client_t *a_client);
bool dap_chain_net_sync_unlock(dap_chain_net_t *a_net, dap_chain_node_client_t *a_client);

dap_chain_net_t * dap_chain_net_by_name( const char * a_name);
dap_chain_net_t * dap_chain_net_by_id( dap_chain_net_id_t a_id);
uint16_t dap_chain_net_acl_idx_by_id(dap_chain_net_id_t a_id);
dap_chain_net_id_t dap_chain_net_id_by_name( const char * a_name);
dap_ledger_t * dap_chain_ledger_by_net_name( const char * a_net_name);
dap_string_t* dap_cli_list_net();

dap_chain_t * dap_chain_net_get_chain_by_name( dap_chain_net_t * l_net, const char * a_name);

dap_chain_node_addr_t * dap_chain_net_get_cur_addr( dap_chain_net_t * l_net);
uint64_t dap_chain_net_get_cur_addr_int(dap_chain_net_t * l_net);
dap_chain_cell_id_t * dap_chain_net_get_cur_cell( dap_chain_net_t * l_net);
const char* dap_chain_net_get_type(dap_chain_t *l_chain);

dap_list_t* dap_chain_net_get_link_node_list(dap_chain_net_t * l_net, bool a_is_only_cur_cell);
dap_list_t* dap_chain_net_get_node_list(dap_chain_net_t * l_net);

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
    /// Do the search in whole
    TX_SEARCH_TYPE_NET_SPENT
}dap_chain_net_tx_search_type_t;

dap_chain_datum_tx_t * dap_chain_net_get_tx_by_hash(dap_chain_net_t * a_net, dap_chain_hash_fast_t * a_tx_hash,
                                                     dap_chain_net_tx_search_type_t a_search_type);

dap_chain_node_role_t dap_chain_net_get_role(dap_chain_net_t * a_net);

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

DAP_STATIC_INLINE char * dap_chain_net_get_gdb_group_from_chain(dap_chain_t * l_chain)
{
    dap_chain_net_t * l_net = l_chain ? dap_chain_net_by_id(l_chain->net_id) : NULL;
    if ( l_net )
		return dap_strdup_printf( "chain-gdb.%s.chain-%016llX",l_net->pub.name, l_chain->id.uint64);

    return NULL;
}

dap_chain_t * dap_chain_net_get_chain_by_chain_type(dap_chain_net_t * l_net, dap_chain_type_t a_datum_type);
char * dap_chain_net_get_gdb_group_mempool_by_chain_type(dap_chain_net_t * l_net, dap_chain_type_t a_datum_type);
dap_chain_net_t **dap_chain_net_list(uint16_t *a_size);
bool dap_chain_net_get_extra_gdb_group(dap_chain_net_t *a_net, dap_chain_node_addr_t a_node_addr);

int dap_chain_net_verify_datum_for_add(dap_chain_net_t *a_net, dap_chain_datum_t * a_datum );
void dap_chain_net_dump_datum(dap_string_t *a_str_out, dap_chain_datum_t *a_datum, const char *a_hash_out_type);
int dap_chain_net_add_downlink(dap_chain_net_t *a_net, dap_stream_worker_t *a_worker, dap_stream_ch_uuid_t a_ch_uuid);
void dap_chain_net_add_gdb_notify_callback(dap_chain_net_t *a_net, dap_global_db_obj_callback_notify_t a_callback, void *a_cb_arg);
void dap_chain_net_sync_gdb_broadcast(void *a_arg, const char a_op_code, const char *a_group,
                                      const char *a_key, const void *a_value, const size_t a_value_len);

struct dap_chain_node_client * dap_chain_net_client_create_n_connect( dap_chain_net_t * a_net, struct dap_chain_node_info *a_link_info);
struct dap_chain_node_client * dap_chain_net_client_create_n_connect_channels( dap_chain_net_t * a_net,struct dap_chain_node_info *a_link_info,
                                                                               const char * a_channels);
int dap_cert_chain_file_save(dap_chain_datum_t * l_datum, char * net_name);
