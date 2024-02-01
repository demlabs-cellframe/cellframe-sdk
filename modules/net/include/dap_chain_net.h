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
#include "dap_time.h"
#include "dap_math_ops.h"
#include "dap_stream_ch.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_chain_common.h"
#include "dap_chain.h"
#include "dap_chain_node.h"
#include "dap_chain_net_decree.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_anchor.h"
#include "dap_chain_datum_tx.h"
#include "uthash.h"

#define DAP_CHAIN_NET_NAME_MAX 32
#define DAP_CHAIN_NET_MEMPOOL_TTL 48 // Hours

struct dap_chain_node_info;
typedef struct dap_chain_node_client dap_chain_node_client_t;
typedef struct dap_ledger dap_ledger_t;

typedef enum dap_chain_net_state{
    NET_STATE_OFFLINE = 0,
    NET_STATE_LINKS_PREPARE,
    NET_STATE_LINKS_CONNECTING,
    NET_STATE_LINKS_ESTABLISHED,
    NET_STATE_ADDR_REQUEST, // Waiting for address assign
    NET_STATE_SYNC_GDB,
    NET_STATE_SYNC_CHAINS,
    NET_STATE_ONLINE
} dap_chain_net_state_t;

typedef struct dap_chain_net{
    struct {
        dap_chain_net_id_t id;
        char * name;
        char * gdb_groups_prefix;
        char * gdb_nodes_aliases;
        char * gdb_nodes;

        dap_list_t *keys;               // List of PoA certs for net

        bool mempool_autoproc;

        dap_chain_t *chains; // double-linked list of chains
        const char *native_ticker;
        dap_ledger_t *ledger;
        dap_chain_net_decree_t *decree;
        // Net fee
        uint256_t fee_value;
        dap_chain_addr_t fee_addr;

        pthread_mutex_t balancer_mutex;
        dap_list_t *link_list;
        dap_list_t *bridged_networks;   // List of bridged network ID's allowed to cross-network TX
    } pub;
    uint8_t pvt[];
} dap_chain_net_t;

DAP_STATIC_INLINE int dap_chain_net_id_parse(const char *a_id_str, dap_chain_net_id_t *a_id)
{
    uint64_t l_id;
    int res = dap_id_uint64_parse(a_id_str, &l_id);
    if (!res)
        a_id->uint64 = l_id;
    return res;
}

typedef bool (dap_chain_datum_filter_func_t)(dap_chain_datum_t *a_datum, dap_chain_t * a_chain, void *a_filter_func_param);

int dap_chain_net_init(void);
void dap_chain_net_deinit(void);

DAP_STATIC_INLINE uint64_t dap_chain_net_get_cur_addr_int(dap_chain_net_t *a_net) { return g_node_addr.uint64; }

void dap_chain_net_load_all();

int dap_chain_net_state_go_to(dap_chain_net_t * a_net, dap_chain_net_state_t a_new_state);
dap_chain_net_state_t dap_chain_net_get_target_state(dap_chain_net_t *a_net);
void dap_chain_net_set_state ( dap_chain_net_t * l_net, dap_chain_net_state_t a_state);
dap_chain_net_state_t dap_chain_net_get_state ( dap_chain_net_t * l_net);

inline static int dap_chain_net_start(dap_chain_net_t * a_net){ return dap_chain_net_state_go_to(a_net,NET_STATE_ONLINE); }
inline static int dap_chain_net_stop(dap_chain_net_t *a_net)
{
    if (dap_chain_net_get_target_state(a_net) == NET_STATE_ONLINE) {
        dap_chain_net_state_go_to(a_net, NET_STATE_OFFLINE);
        return true;
    }
    if (dap_chain_net_get_state(a_net) != NET_STATE_OFFLINE)
        dap_chain_net_state_go_to(a_net, NET_STATE_OFFLINE);
    return false;
}
inline static int dap_chain_net_links_establish(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_LINKS_ESTABLISHED); }
inline static int dap_chain_net_sync_gdb(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_SYNC_GDB); }
inline static int dap_chain_net_sync_chains(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_SYNC_CHAINS); }
inline static int dap_chain_net_sync_all(dap_chain_net_t * a_net) { return dap_chain_net_state_go_to(a_net,NET_STATE_SYNC_CHAINS); }

void dap_chain_net_delete( dap_chain_net_t * a_net);
void dap_chain_net_proc_mempool(dap_chain_net_t *a_net);
void dap_chain_net_set_flag_sync_from_zero(dap_chain_net_t * a_net, bool a_flag_sync_from_zero);
bool dap_chain_net_get_flag_sync_from_zero( dap_chain_net_t * a_net);

bool dap_chain_net_sync_trylock(dap_chain_net_t *a_net, dap_chain_node_client_t *a_client);
bool dap_chain_net_sync_unlock(dap_chain_net_t *a_net, dap_chain_node_client_t *a_client);

void dap_chain_net_add_cluster_link(dap_chain_net_t *a_net, dap_stream_node_addr_t *a_node_addr);
dap_chain_net_t * dap_chain_net_by_name( const char * a_name);
dap_chain_net_t * dap_chain_net_by_id( dap_chain_net_id_t a_id);
uint16_t dap_chain_net_get_acl_idx(dap_chain_net_t *a_net);
dap_chain_net_id_t dap_chain_net_id_by_name( const char * a_name);
dap_ledger_t * dap_ledger_by_net_name( const char * a_net_name);
dap_string_t* dap_cli_list_net();

dap_chain_t * dap_chain_net_get_chain_by_name( dap_chain_net_t * l_net, const char * a_name);
dap_chain_t *dap_chain_net_get_chain_by_id(dap_chain_net_t *l_net, dap_chain_id_t a_chain_id);

uint64_t dap_chain_net_get_cur_addr_int(dap_chain_net_t * l_net);
dap_chain_cell_id_t * dap_chain_net_get_cur_cell( dap_chain_net_t * l_net);
const char* dap_chain_net_get_type(dap_chain_t *l_chain);

dap_list_t* dap_chain_net_get_link_node_list(dap_chain_net_t * l_net, bool a_is_only_cur_cell);
dap_list_t* dap_chain_net_get_node_list(dap_chain_net_t * a_net);
dap_list_t* dap_chain_net_get_node_list_cfg(dap_chain_net_t * a_net);
dap_chain_node_role_t dap_chain_net_get_role(dap_chain_net_t * a_net);
dap_chain_node_info_t *dap_chain_net_balancer_link_from_cfg(dap_chain_net_t *a_net);

int dap_chain_net_add_poa_certs_to_cluster(dap_chain_net_t *a_net, dap_global_db_cluster_t *a_cluster);
bool dap_chain_net_add_validator_to_clusters(dap_chain_t *a_chain, dap_stream_node_addr_t *a_addr);
dap_global_db_cluster_t *dap_chain_net_get_mempool_cluster(dap_chain_t *a_chain);

int dap_chain_net_add_reward(dap_chain_net_t *a_net, uint256_t a_reward, uint64_t a_block_num);
uint256_t dap_chain_net_get_reward(dap_chain_net_t *a_net, uint64_t a_block_num);

/**
 * @brief dap_chain_net_get_gdb_group_mempool
 * @param l_chain
 * @return
 */
DAP_STATIC_INLINE char *dap_chain_net_get_gdb_group_mempool_new(dap_chain_t *a_chain)
{
    dap_chain_net_t *l_net = a_chain ? dap_chain_net_by_id(a_chain->net_id) : NULL;
    return l_net
            ? dap_strdup_printf("%s.chain-%s.mempool", l_net->pub.gdb_groups_prefix, a_chain->name)
            : NULL;
}

DAP_STATIC_INLINE char *dap_chain_net_get_gdb_group_nochain_new(dap_chain_t *a_chain)
{
    dap_chain_net_t *l_net = a_chain ? dap_chain_net_by_id(a_chain->net_id) : NULL;
    return l_net
            ? dap_strdup_printf("%s.chain-%s.data", l_net->pub.name, a_chain->name)
            : NULL;
}

dap_chain_t *dap_chain_net_get_chain_by_chain_type(dap_chain_net_t *a_net, dap_chain_type_t a_datum_type);
dap_chain_t *dap_chain_net_get_default_chain_by_chain_type(dap_chain_net_t *a_net, dap_chain_type_t a_datum_type);
char *dap_chain_net_get_gdb_group_mempool_by_chain_type(dap_chain_net_t *a_net, dap_chain_type_t a_datum_type);
dap_chain_net_t **dap_chain_net_list(uint16_t *a_size);

int dap_chain_net_verify_datum_for_add(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, dap_hash_fast_t *a_datum_hash);
char *dap_chain_net_verify_datum_err_code_to_str(dap_chain_datum_t *a_datum, int a_code);

void dap_chain_add_mempool_notify_callback(dap_chain_t *a_chain, dap_store_obj_callback_notify_t a_callback, void *a_cb_arg);
void dap_chain_net_add_nodelist_notify_callback(dap_chain_net_t *a_net, dap_store_obj_callback_notify_t a_callback, void *a_cb_arg);
void dap_chain_net_srv_order_add_notify_callback(dap_chain_net_t *a_net, dap_store_obj_callback_notify_t a_callback, void *a_cb_arg);

/**
 * @brief dap_chain_datum_list
 * Get datum list by filter
 * @param a_net
 * @param a_chain  if NULL, then for all chains
 * @param a_filter_func
 * @param a_filter_func_param
 */
dap_list_t *dap_chain_datum_list(dap_chain_net_t *a_net, dap_chain_t *a_chain, dap_chain_datum_filter_func_t *a_filter_func, void *a_filter_func_param);

int dap_chain_datum_add(dap_chain_t * a_chain, dap_chain_datum_t *a_datum, size_t a_datum_size, dap_hash_fast_t *a_datum_hash);

bool dap_chain_net_get_load_mode(dap_chain_net_t * a_net);
void dap_chain_net_announce_addrs();
char *dap_chain_net_links_dump(dap_chain_net_t*);
int dap_chain_net_link_manager_init();
