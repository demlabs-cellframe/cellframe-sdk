/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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


#include <stdlib.h>
#define _XOPEN_SOURCE       /* See feature_test_macros(7) */
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#ifdef DAP_OS_UNIX
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <pthread.h>

#include "uthash.h"
#include "utlist.h"

#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_config.h"
#include "dap_hash.h"
#include "dap_cert.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_ledger.h"

#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"

#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"

#include "dap_module.h"

#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

#define _XOPEN_SOURCE       /* See feature_test_macros(7) */
#define __USE_XOPEN
#define _GNU_SOURCE
#include <time.h>

#define LOG_TAG "chain_net"

#define F_DAP_CHAIN_NET_SHUTDOWN  ( 1 << 9 )
#define F_DAP_CHAIN_NET_GO_SYNC   ( 1 << 10 )

// maximum number of connections
static size_t s_max_links_count = 5;// by default 5
// number of required connections
static size_t s_required_links_count = 3;// by default 3

/**
  * @struct dap_chain_net_pvt
  * @details Private part of chain_net dap object
  */
typedef struct dap_chain_net_pvt{
    pthread_t proc_tid;
#ifndef _WIN32
    pthread_cond_t state_proc_cond;
#else
    HANDLE state_proc_cond;
#endif
    pthread_mutex_t state_mutex_cond;
    dap_chain_node_role_t node_role;
    uint32_t  flags;
    time_t    last_sync;

    dap_chain_node_addr_t * node_addr;
    dap_chain_node_info_t * node_info; // Current node's info

    dap_chain_node_client_t * links;
    size_t links_count;

    dap_chain_node_addr_t *links_addrs;
    size_t links_addrs_count;

    size_t addr_request_attempts;
    bool load_mode;
    uint8_t padding2[7];
    char ** seed_aliases;

    uint16_t gdb_sync_groups_count;
    uint16_t gdb_sync_nodes_addrs_count;
    char **gdb_sync_groups;
    dap_chain_node_addr_t *gdb_sync_nodes_addrs;

    uint8_t padding3[6];
    uint16_t seed_aliases_count;

    dap_chain_net_state_t state;
    dap_chain_net_state_t state_target;
} dap_chain_net_pvt_t;

typedef struct dap_chain_net_item{
    char name [DAP_CHAIN_NET_NAME_MAX];
    dap_chain_net_id_t net_id;
    dap_chain_net_t * chain_net;
    UT_hash_handle hh;
} dap_chain_net_item_t;

#define PVT(a) ( (dap_chain_net_pvt_t *) (void*) a->pvt )
#define PVT_S(a) ( (dap_chain_net_pvt_t *) (void*) a.pvt )

static dap_chain_net_item_t * s_net_items = NULL;
static dap_chain_net_item_t * s_net_items_ids = NULL;


static const char * c_net_states[]={
    [NET_STATE_OFFLINE] = "NET_STATE_OFFLINE",
    [NET_STATE_LINKS_PREPARE ] = "NET_STATE_LINKS_PREPARE",
    [NET_STATE_LINKS_CONNECTING] = "NET_STATE_LINKS_CONNECTING",
    [NET_STATE_LINKS_ESTABLISHED]= "NET_STATE_LINKS_ESTABLISHED",
    [NET_STATE_SYNC_GDB]= "NET_STATE_SYNC_GDB",
    [NET_STATE_SYNC_CHAINS]= "NET_STATE_SYNC_CHAINS",
    [NET_STATE_ADDR_REQUEST]= "NET_STATE_ADDR_REQUEST",
    [NET_STATE_ONLINE]= "NET_STATE_ONLINE"
};

static dap_chain_net_t * s_net_new(const char * a_id, const char * a_name , const char * a_node_role);
inline static const char * s_net_state_to_str(dap_chain_net_state_t l_state);
static int s_net_states_proc(dap_chain_net_t * l_net);
static void * s_net_proc_thread ( void * a_net);
static void s_net_proc_thread_start( dap_chain_net_t * a_net );
static void s_net_proc_kill( dap_chain_net_t * a_net );
int s_net_load(const char * a_net_name);

static void s_gbd_history_callback_notify (void * a_arg,const char a_op_code, const char * a_prefix, const char * a_group,
                                                     const char * a_key, const void * a_value,
                                                     const size_t a_value_len);
static void s_chain_callback_notify(void * a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id);

static int s_cli_net(int argc, char ** argv, void *arg_func, char **str_reply);

static bool s_seed_mode = false;


/**
 * @brief s_net_set_go_sync
 * @param a_net
 * @return
 */
void s_net_set_go_sync(dap_chain_net_t * a_net)
{
    if(!a_net)
        return;
    dap_chain_net_state_go_to(a_net, NET_STATE_SYNC_REQUESTED);
}

/**
 * @brief s_net_state_to_str
 * @param l_state
 * @return
 */
inline static const char * s_net_state_to_str(dap_chain_net_state_t l_state)
{
    return c_net_states[l_state];
}

/**
 * @brief dap_chain_net_state_go_to
 * @param a_net
 * @param a_new_state
 */
int dap_chain_net_state_go_to(dap_chain_net_t * a_net, dap_chain_net_state_t a_new_state)
{
    if (a_new_state == NET_STATE_SYNC_REQUESTED) {
        if (PVT(a_net)->state_target != NET_STATE_OFFLINE) {
            PVT(a_net)->state_target = NET_STATE_ONLINE;
        }
    } else {
        if (PVT(a_net)->state_target == a_new_state){
            log_it(L_WARNING,"Already going to state %s",s_net_state_to_str(a_new_state));
        }
        PVT(a_net)->state_target = a_new_state;
    }
    pthread_mutex_lock( &PVT(a_net)->state_mutex_cond);
    // set flag for sync
    PVT(a_net)->flags |= F_DAP_CHAIN_NET_GO_SYNC;
#ifndef _WIN32
    pthread_cond_signal( &PVT(a_net)->state_proc_cond );
#else
    SetEvent( PVT(a_net)->state_proc_cond );
#endif
    pthread_mutex_unlock( &PVT(a_net)->state_mutex_cond);
    return 0;
}

/**
 * @brief s_gbd_history_callback_notify
 * @param a_arg
 * @param a_op_code
 * @param a_prefix
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_len
 */
static void s_gbd_history_callback_notify (void * a_arg, const char a_op_code, const char * a_prefix, const char * a_group,
                                                     const char * a_key, const void * a_value,
                                                     const size_t a_value_len)
{
    (void) a_op_code;
    UNUSED(a_prefix);
    UNUSED(a_value_len);
    if (a_arg) {
        dap_chain_net_t * l_net = (dap_chain_net_t *) a_arg;
        s_net_set_go_sync(l_net);
        /*if (!PVT (l_net)->load_mode ){
            if( pthread_mutex_trylock( &PVT (l_net)->state_mutex) == 0 ){
                if ( PVT(l_net)->state == NET_STATE_ONLINE || PVT(l_net)->state == NET_STATE_ONLINE  )
                    dap_chain_net_sync_all(l_net);
                pthread_mutex_unlock( &PVT (l_net)->state_mutex);
            }
        }*/
    }
    if (!dap_config_get_item_bool_default(g_config, "srv", "order_signed_only", false)) {
        return;
    }
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    char *l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group(l_net);
    if (strcmp(a_group, l_gdb_group_str)) {
        dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)a_value;
        if (l_order->version == 1) {
            dap_chain_global_db_gr_del((char *)a_key, a_group);
        } else {
            dap_sign_t *l_sign = (dap_sign_t *)&l_order->ext[l_order->ext_size];
            dap_chain_hash_fast_t l_pkey_hash;
            if (!dap_sign_get_pkey_hash(l_sign, &l_pkey_hash)) {
                return;
            }
            dap_chain_addr_t l_addr = {0};
            dap_chain_addr_fill(&l_addr, l_sign->header.type, &l_pkey_hash, l_net->pub.id);
            uint64_t l_solvency = dap_chain_ledger_calc_balance(l_net->pub.ledger, &l_addr, l_order->price_ticker);
            if (l_solvency < l_order->price) {
                dap_chain_global_db_gr_del((char *)a_key, a_group);
            }
            // TODO check for delegated key
        }
        DAP_DELETE(l_gdb_group_str);
    }
}

/**
 * @brief s_chain_callback_notify
 * @param a_arg
 * @param a_chain
 * @param a_id
 */
static void s_chain_callback_notify(void * a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id)
{
    UNUSED(a_chain);
    UNUSED(a_id);
    if(!a_arg)
        return;
    dap_chain_net_t * l_net = (dap_chain_net_t *) a_arg;
    s_net_set_go_sync(l_net);
}


/**
 * @brief s_net_states_proc
 * @param l_net
 */
static int s_net_states_proc(dap_chain_net_t * l_net)
{

    dap_chain_net_pvt_t *l_pvt_net = PVT(l_net);

    int ret=0;

    switch ( l_pvt_net->state ){
        case NET_STATE_OFFLINE:{
            // reset current link
            l_pvt_net->links_count = 0;
            // delete all links
            dap_chain_node_client_close(l_pvt_net->links);
            l_pvt_net->links = NULL;
            l_pvt_net->links_addrs_count = 0;
            if ( l_pvt_net->links_addrs )
                DAP_DELETE(l_pvt_net->links_addrs);
            l_pvt_net->links_addrs = NULL;

            if ( l_pvt_net->state_target != NET_STATE_OFFLINE ){
                l_pvt_net->state = NET_STATE_LINKS_PREPARE;
                break;
            }
            // disable SYNC_GDB
            l_pvt_net->flags &= ~F_DAP_CHAIN_NET_GO_SYNC;
            l_pvt_net->last_sync = 0;
        } break;
        case NET_STATE_LINKS_PREPARE:{
            log_it(L_NOTICE,"%s.state: NET_STATE_LINKS_PREPARE",l_net->pub.name);
            switch (l_pvt_net->node_role.enums) {
                case NODE_ROLE_ROOT:
                case NODE_ROLE_ROOT_MASTER:
                case NODE_ROLE_ARCHIVE:
                case NODE_ROLE_CELL_MASTER:{
                    // This roles load predefined links from global_db
                    if ( l_pvt_net->node_info ) {
                        if (l_pvt_net->links_addrs )
                            DAP_DELETE(l_pvt_net->links_addrs);
                        l_pvt_net->links_addrs_count = l_pvt_net->node_info->hdr.links_number;
                        l_pvt_net->links_addrs = DAP_NEW_Z_SIZE( dap_chain_node_addr_t,
                                                                  l_pvt_net->links_addrs_count * sizeof(dap_chain_node_addr_t));
                        for (size_t i =0 ; i < l_pvt_net->node_info->hdr.links_number; i++ ){
                            l_pvt_net->links_addrs[i].uint64 = l_pvt_net->node_info->links[i].uint64;
                        }
                    }else {
                        log_it(L_WARNING,"No nodeinfo in global_db to prepare links for connecting, find nearest 3 links and fill global_db");
                    }

                    // add other root nodes for connect
                    //if(!l_pvt_net->links_addrs_count)
                    {
                        // use no more then 4 root node
                        int l_use_root_nodes = min(4, l_pvt_net->seed_aliases_count);
                        if(!l_pvt_net->links_addrs_count) {
                            l_pvt_net->links_addrs = DAP_NEW_Z_SIZE(dap_chain_node_addr_t,
                                    l_use_root_nodes * sizeof(dap_chain_node_addr_t));
                        }
                        else{
                            l_pvt_net->links_addrs = DAP_REALLOC(l_pvt_net->links_addrs,
                                    (l_pvt_net->links_addrs_count+l_use_root_nodes) * sizeof(dap_chain_node_addr_t));
                            memset(l_pvt_net->links_addrs + l_pvt_net->links_addrs_count, 0,
                                    l_use_root_nodes * sizeof(dap_chain_node_addr_t));
                        }

                        for(uint16_t i = 0; i < l_use_root_nodes; i++) {
                            dap_chain_node_addr_t * l_node_addr = dap_chain_node_alias_find(l_net, l_pvt_net->seed_aliases[i]);
                            if(l_node_addr) {
                                l_pvt_net->links_addrs[l_pvt_net->links_addrs_count].uint64 = l_node_addr->uint64;
                                l_pvt_net->links_addrs_count++;
                            }
                        }
                    }
                    // shuffle the order of the nodes
                    for(size_t i = 0; i < l_pvt_net->links_addrs_count; i++) {
                        unsigned int l_new_node_pos = rand() % (l_pvt_net->links_addrs_count);
                        if(i == l_new_node_pos)
                            continue;
                        uint64_t l_tmp_uint64 = l_pvt_net->links_addrs[i].uint64;
                        l_pvt_net->links_addrs[i].uint64 = l_pvt_net->links_addrs[l_new_node_pos].uint64;
                        l_pvt_net->links_addrs[l_new_node_pos].uint64 = l_tmp_uint64;
                    }


                } break;
                case NODE_ROLE_FULL:
                case NODE_ROLE_MASTER:
                case NODE_ROLE_LIGHT:{
                    // If we haven't any assigned shard - connect to root-0
                    if(1) { //if(l_net->pub.cell_id.uint64 == 0) {

                    //dap_chain_net_pvt_t *pvt_debug = l_pvt_net;
                    // get current node address
                    dap_chain_node_addr_t l_address;
                    l_address.uint64 = dap_chain_net_get_cur_addr(l_net) ?
                                         dap_chain_net_get_cur_addr(l_net)->uint64 :
                                         dap_db_get_cur_node_addr(l_net->pub.name);

                    // get current node info
                    dap_chain_node_info_t *l_cur_node_info = dap_chain_node_info_read(l_net, &l_address);

                    if ( l_cur_node_info ) {
                        uint16_t l_links_addrs_count = l_cur_node_info->hdr.links_number + l_pvt_net->seed_aliases_count;
                        l_pvt_net->links_addrs = DAP_NEW_Z_SIZE(dap_chain_node_addr_t,
                                l_links_addrs_count * sizeof(dap_chain_node_addr_t));

                        // add linked nodes for connect
                        for(uint16_t i = 0; i < min(4, l_cur_node_info->hdr.links_number); i++) {
                            dap_chain_node_addr_t *l_addr = l_cur_node_info->links + i;
                            //dap_chain_node_addr_t link_addr = l_cur_node_info->links[i];
                            dap_chain_node_info_t *l_remore_node_info = dap_chain_node_info_read(l_net, l_addr);
                            if(l_remore_node_info) {
                                // if only nodes from the same cell of cell=0
                                if(!l_cur_node_info->hdr.cell_id.uint64 ||
                                    l_cur_node_info->hdr.cell_id.uint64 == l_remore_node_info->hdr.cell_id.uint64) {
                                    l_pvt_net->links_addrs[l_pvt_net->links_addrs_count].uint64 =
                                            l_remore_node_info->hdr.address.uint64;
                                    l_pvt_net->links_addrs_count++;
                                }
                                DAP_DELETE(l_remore_node_info);
                            }
                        }
                    }
                    // if no links then add root nodes for connect
                    if(!l_pvt_net->links_addrs_count){
                        // use no more then 4 root node
                        int l_use_root_nodes = min(4, l_pvt_net->seed_aliases_count);
                        l_pvt_net->links_addrs = DAP_NEW_Z_SIZE(dap_chain_node_addr_t,
                                l_use_root_nodes * sizeof(dap_chain_node_addr_t));

                        for(uint16_t i = 0; i < l_use_root_nodes; i++) {
                            dap_chain_node_addr_t * l_node_addr = dap_chain_node_alias_find(l_net, l_pvt_net->seed_aliases[i]);
                            if(l_node_addr) {
                                l_pvt_net->links_addrs[l_pvt_net->links_addrs_count].uint64 = l_node_addr->uint64;
                                l_pvt_net->links_addrs_count++;
                            }
                        }
                    }
                    // shuffle the order of the nodes
                    for(size_t i = 0; i < l_pvt_net->links_addrs_count; i++) {
                        unsigned int l_new_node_pos = rand() % (l_pvt_net->links_addrs_count);
                        if(i==l_new_node_pos)
                            continue;
                        uint64_t l_tmp_uint64 = l_pvt_net->links_addrs[i].uint64;
                        l_pvt_net->links_addrs[i].uint64 = l_pvt_net->links_addrs[l_new_node_pos].uint64;
                        l_pvt_net->links_addrs[l_new_node_pos].uint64 = l_tmp_uint64;
                    }
                    DAP_DELETE(l_cur_node_info);
                }else {
                        // TODO read cell's nodelist and populate array with it
                    }
                } break;
            }
            if ( l_pvt_net->state_target > NET_STATE_LINKS_PREPARE ){
                if ( l_pvt_net->links_addrs_count>0 ) { // If links are present
                    l_pvt_net->state = NET_STATE_LINKS_CONNECTING;
                    log_it(L_DEBUG,"Prepared %u links, start to establish them", l_pvt_net->links_addrs_count );
                } else {
                    log_it(L_WARNING,"No links for connecting, return back to OFFLINE state");
                    l_pvt_net->state = NET_STATE_OFFLINE;
                    // remove looping
                    l_pvt_net->state_target = NET_STATE_OFFLINE;
                }
            }else {
                log_it(L_WARNING,"Target state is NET_STATE_LINKS_PREPARE? Realy?");
                l_pvt_net->state = NET_STATE_OFFLINE;
            }
        }
        break;

        case NET_STATE_LINKS_CONNECTING:{
            size_t l_links_count = l_pvt_net->links_count;
            if(l_links_count >= s_required_links_count || (l_links_count + 1) >= s_max_links_count) {
                // TODO what if other failed and we want more?
            }
            if (l_links_count < l_pvt_net->links_addrs_count) {
                l_pvt_net->links_count++;
            } else {
                log_it(L_NOTICE, "Can't establish enough links, go to offline");
                l_pvt_net->state = NET_STATE_OFFLINE;
                l_pvt_net->state_target = NET_STATE_OFFLINE;
                break;
            }
            log_it(L_DEBUG, "%s.state: NET_STATE_LINKS_CONNECTING",l_net->pub.name);
            log_it(L_DEBUG, "Establishing connection with " NODE_ADDR_FP_STR,
                   NODE_ADDR_FP_ARGS_S( l_pvt_net->links_addrs[l_links_count]) );
            dap_chain_node_info_t *l_link_node_info = dap_chain_node_info_read(l_net, &l_pvt_net->links_addrs[l_links_count]);
            if ( l_link_node_info ) {
                dap_chain_node_client_t *l_node_client = dap_chain_node_client_connect(l_link_node_info);
                if(!l_node_client) {
                    DAP_DELETE(l_link_node_info);
                    ret = -1;
                    break;
                }
                // wait connected
                int timeout_ms = 5000; //5 sec = 5000 ms
                int res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
                if (res == 0 ){
                    log_it(L_DEBUG, "Connected link %u", l_links_count);
                    l_pvt_net->links = l_node_client;
                    l_pvt_net->state = NET_STATE_LINKS_ESTABLISHED;
                }else {
                    log_it(L_DEBUG, "Cant establish link %u", l_links_count);
                    dap_chain_node_client_close(l_node_client);
                    l_node_client = NULL;
                }
            }
        }
        break;

        case NET_STATE_LINKS_ESTABLISHED:{
            log_it(L_DEBUG,"%s.state: NET_STATE_LINKS_ESTABLISHED",l_net->pub.name);
            switch (l_pvt_net->state_target) {
                case NET_STATE_ONLINE:{ // Online
                    switch ( l_pvt_net->node_role.enums ){
                        case NODE_ROLE_ROOT_MASTER:
                        case NODE_ROLE_ROOT:{
                            /*dap_chain_node_client_t * l_node_client = NULL, *l_node_client_tmp = NULL;

                            // Send everybody your address when linked
                            HASH_ITER(hh,l_pvt_net->links,l_node_client,l_node_client_tmp){
                                dap_stream_ch_chain_net_pkt_write(dap_client_get_stream_ch(
                                                  l_node_client->client, dap_stream_ch_chain_net_get_id()),
                                                   DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR, l_net->pub.id,
                                                   dap_chain_net_get_cur_addr(l_net),
                                                   sizeof (dap_chain_node_addr_t) );
                            }*/
                            l_pvt_net->state = NET_STATE_SYNC_GDB;
                        }break;
                        case NODE_ROLE_CELL_MASTER:
                        case NODE_ROLE_MASTER:{
                            l_pvt_net->state = NET_STATE_SYNC_GDB;//NET_STATE_ADDR_REQUEST;
                        } break;
                       default:{
                        // get addr for current node if it absent
                        if(!dap_chain_net_get_cur_addr_int(l_net))
                            l_pvt_net->state = NET_STATE_ADDR_REQUEST;
                        else
                            PVT( l_net)->state = NET_STATE_SYNC_GDB;
                       }
                    }
                }
                break;

                case NET_STATE_SYNC_GDB: // we need only to sync gdb
                    l_pvt_net->state = NET_STATE_SYNC_GDB ;
                    if ( l_pvt_net->addr_request_attempts >=10 && l_pvt_net->state == NET_STATE_ADDR_REQUEST){
                        l_pvt_net->addr_request_attempts = 0;
                        switch( l_pvt_net->state_target){
                            case NET_STATE_ONLINE:
                            case NET_STATE_SYNC_GDB:
                                l_pvt_net->state = NET_STATE_SYNC_GDB;
                                break;

                            case NET_STATE_SYNC_CHAINS:
                                l_pvt_net->state = NET_STATE_SYNC_CHAINS;
                                break;
                            default: {
                                l_pvt_net->state = NET_STATE_OFFLINE;
                                l_pvt_net->state_target = NET_STATE_OFFLINE;
                            }
                        }
                    }
                    break;

                case NET_STATE_SYNC_CHAINS:
                    l_pvt_net->state = (l_pvt_net->node_info && l_pvt_net->node_info->hdr.address.uint64)?
                                NET_STATE_SYNC_CHAINS : NET_STATE_ADDR_REQUEST;
                    break;

                case NET_STATE_ADDR_REQUEST :
                    l_pvt_net->state = NET_STATE_ADDR_REQUEST;
                    break;
                default: break;
            }
        } break;
        // get addr for remote node
        case NET_STATE_ADDR_REQUEST: {
            int l_is_addr_leased = 0;
            dap_chain_node_client_t *l_node_client = l_pvt_net->links;
            uint8_t l_ch_id = dap_stream_ch_chain_net_get_id(); // Channel id for chain net request
            dap_stream_ch_t *l_ch_chain = dap_client_get_stream_ch(l_node_client->client, l_ch_id);
            // set callback for l_ch_id
            dap_chain_node_client_set_callbacks(l_node_client->client, l_ch_id);
            // send request for new address
            size_t res = dap_stream_ch_chain_net_pkt_write(l_ch_chain,
                    DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE_REQUEST,
                    //DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_REQUEST,
                    l_net->pub.id, NULL, 0);
            if (res == 0) {
                log_it(L_WARNING,"Can't send NODE_ADDR_REQUEST packet");
                dap_chain_node_client_close(l_node_client);
                l_node_client = NULL;
                l_pvt_net->state = NET_STATE_LINKS_CONNECTING;
                break; // try with another link
            }
            // wait for finishing of request
            int timeout_ms = 5000; // 5 sec = 5 000 ms
            // TODO add progress info to console
            l_pvt_net->addr_request_attempts++;
            int l_res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_NODE_ADDR_LEASED, timeout_ms);
            switch (l_res) {
                case -1:
                    log_it(L_WARNING,"Timeout with addr leasing");
                    // try again 3 times
                    if (l_pvt_net->addr_request_attempts < 3) {
                        break;
                    }
                    l_pvt_net->state = NET_STATE_LINKS_CONNECTING;
                    break; // try with another link
                case 0:
                    log_it(L_INFO, "Node address leased");
                    l_is_addr_leased++;
                    l_pvt_net->addr_request_attempts = 0;
                    break;
                default:
                    if (l_node_client->last_error[0]) {
                        log_it(L_INFO, "Node address request error %d: \"%s\"", l_res, l_node_client->last_error);
                        l_node_client->last_error[0] = '\0';
                    }
                    log_it(L_INFO, "Node address request error %d", l_res);
                    l_pvt_net->state = NET_STATE_LINKS_CONNECTING;
                    break;
            }
            if (l_is_addr_leased > 0) {
                l_pvt_net->state = NET_STATE_SYNC_GDB;
            }
        }
        break;
        case NET_STATE_SYNC_GDB:{
            // send request
            dap_chain_node_client_t *l_node_client = l_pvt_net->links;
            dap_stream_ch_chain_sync_request_t l_sync_gdb = {};
            // Get last timestamp in log
            l_sync_gdb.id_start = (uint64_t) dap_db_log_get_last_id_remote(l_node_client->remote_node_addr.uint64);
            // no limit
            l_sync_gdb.id_end = (uint64_t)0;

            l_sync_gdb.node_addr.uint64 = dap_chain_net_get_cur_addr(l_net) ?
                                              dap_chain_net_get_cur_addr(l_net)->uint64 :
                                              dap_db_get_cur_node_addr(l_net->pub.name);

            dap_chain_id_t l_chain_id_null = {};
            dap_chain_cell_id_t l_chain_cell_id_null = {};
            l_chain_id_null.uint64 = l_net->pub.id.uint64;
            l_chain_cell_id_null.uint64 = dap_chain_net_get_cur_cell(l_net) ? dap_chain_net_get_cur_cell(l_net)->uint64 : 0;

            log_it(L_DEBUG, "Prepared request to gdb sync from %llu to %llu", l_sync_gdb.id_start, l_sync_gdb.id_end);
            // find dap_chain_id_t
            dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, "gdb");
            dap_chain_id_t l_chain_id = l_chain ? l_chain->id : (dap_chain_id_t ) {};

            size_t l_res = dap_stream_ch_chain_pkt_write(dap_client_get_stream_ch(l_node_client->client, dap_stream_ch_chain_get_id()),
                                                        DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB, l_net->pub.id, l_chain_id,
                                                        l_net->pub.cell_id, &l_sync_gdb, sizeof(l_sync_gdb));
            if (l_res == 0) {
                log_it(L_WARNING, "Can't send GDB sync request");
                dap_chain_node_client_close(l_node_client);
                l_node_client = NULL;
                l_pvt_net->state = NET_STATE_LINKS_CONNECTING;
                break;  //try another link
            }

            // wait for finishing of request
            int timeout_ms = 300000; // 5 min = 300 sec = 300 000 ms
            // TODO add progress info to console
            l_res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_SYNCED, timeout_ms);
            switch (l_res) {
            case -1:
                log_it(L_WARNING,"Timeout with link sync");
                break;
            case 0:
                log_it(L_INFO, "Node sync completed");
                break;
            default:
                log_it(L_INFO, "Node sync error %d",l_res);
            }
            if (l_res) { // try another link
                break;
            }
            if(l_pvt_net->state_target >= NET_STATE_SYNC_CHAINS){
                l_pvt_net->state = NET_STATE_SYNC_CHAINS;
            } else {
                l_pvt_net->flags &= ~F_DAP_CHAIN_NET_GO_SYNC;
                l_pvt_net->state = NET_STATE_ONLINE;
            }
        }
        break;

        case NET_STATE_SYNC_CHAINS: {
            dap_chain_node_client_t *l_node_client = l_pvt_net->links;
            uint8_t l_ch_id = dap_stream_ch_chain_get_id(); // Channel id for global_db and chains sync
            dap_stream_ch_t *l_ch_chain = dap_client_get_stream_ch(l_node_client->client, l_ch_id);
            if(!l_ch_chain) {
                log_it(L_DEBUG,"Can't get stream_ch for id='%c' ", l_ch_id);
                l_pvt_net->state = NET_STATE_LINKS_CONNECTING;
                break;
            }
            dap_chain_t * l_chain = NULL;
            int l_sync_errors = 0;
            DL_FOREACH(l_net->pub.chains, l_chain ){
                //size_t l_lasts_size = 0;
                //dap_chain_atom_ptr_t * l_lasts;
                //dap_chain_atom_iter_t * l_atom_iter = l_chain->callback_atom_iter_create(l_chain);
                //l_lasts = l_chain->callback_atom_iter_get_lasts(l_atom_iter, &l_lasts_size);
                //if( l_lasts ) {
                    l_node_client->state = NODE_CLIENT_STATE_CONNECTED;
                    dap_stream_ch_chain_sync_request_t l_request ;
                    memset(&l_request, 0, sizeof (l_request));
                    //dap_hash_fast(l_lasts[0], l_chain->callback_atom_get_size(l_lasts[0]), &l_request.hash_from);
                    dap_stream_ch_chain_pkt_write(l_ch_chain,
                    DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS, l_net->pub.id, l_chain->id,
                            l_net->pub.cell_id, &l_request, sizeof(l_request));
                    //
                    //                        dap_chain_node_client_send_ch_pkt(l_node_client,l_ch_id,
                    //                                                      DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS,
                    //                                                      &l_request,sizeof (l_request) );

                    // wait for finishing of request
                    int timeout_ms = 120000; // 2 min = 120 sec = 120 000 ms
                    // TODO add progress info to console
                    int l_res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_SYNCED, timeout_ms);
                    switch (l_res) {
                    case -1:
                        log_it(L_WARNING,"Timeout with sync of chain '%s' ", l_chain->name);
                        break;
                    case 0:
                        // flush global_db
                        dap_chain_global_db_flush();
                        log_it(L_INFO, "sync of chain '%s' completed ", l_chain->name);
                        // set time of last sync
                        {
                            struct timespec l_to;
                            clock_gettime( CLOCK_MONOTONIC, &l_to);
                            l_pvt_net->last_sync = l_to.tv_sec;
                        }
                        break;
                    default:
                        log_it(L_ERROR, "sync of chain '%s' error %d", l_chain->name,l_res);
                    }
                    if (l_res) {
                        l_sync_errors++;
                    }
                    //DAP_DELETE( l_lasts );
                //}
                //DAP_DELETE( l_atom_iter );
            }
            dap_chain_node_client_close(l_node_client);
            l_node_client = NULL;
            if (l_sync_errors) {
                l_pvt_net->state = NET_STATE_LINKS_CONNECTING;
                break;
            }
            log_it(L_INFO, "Synchronization done");
            l_pvt_net->flags &= ~F_DAP_CHAIN_NET_GO_SYNC;
            l_pvt_net->state = NET_STATE_ONLINE;
            l_pvt_net->links_count = 0;
        }
        break;

        case NET_STATE_ONLINE: {
            if (l_pvt_net->flags & F_DAP_CHAIN_NET_GO_SYNC)
            {
                switch ( l_pvt_net->state_target) {
                // disconnect
                case NET_STATE_OFFLINE:
                    l_pvt_net->state = NET_STATE_OFFLINE;
                    log_it(L_NOTICE, "Going to disconnet");
                    break;
                case NET_STATE_ONLINE:
                case NET_STATE_SYNC_GDB:
                case NET_STATE_SYNC_CHAINS:
                    l_pvt_net->state = NET_STATE_LINKS_CONNECTING;
                    break;
                default: break;
                }
            }
        }
        break;
        default: log_it (L_DEBUG, "Unprocessed state");
    }
    return ret;
}

// Global
/*static void s_net_proc_thread_callback_update_db(void)
{
    dap_chain_net_item_t *l_net_item, *l_net_item_tmp;
    printf("update0\n");
    HASH_ITER(hh, s_net_items, l_net_item, l_net_item_tmp)
    {
        s_net_set_go_sync(l_net_item->chain_net);
    }
    printf("update1\n");
}*/

/**
 * @brief s_net_proc_thread
 * @details Brings up and check the Dap Chain Network
 * @param a_cfg Network1 configuration
 * @return
 */
static void *s_net_proc_thread ( void *a_net )
{
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_net;
    dap_chain_net_pvt_t *p_net = (dap_chain_net_pvt_t *)(void *)l_net->pvt;

    const uint64_t l_timeout_ms = 60000;// 60 sec

    // set callback to update data
    //dap_chain_global_db_set_callback_for_update_base(s_net_proc_thread_callback_update_db);

    while( !(p_net->flags & F_DAP_CHAIN_NET_SHUTDOWN) ) {

        // check or start sync
        s_net_states_proc( l_net );
        if (p_net->flags & F_DAP_CHAIN_NET_GO_SYNC) {
            continue;
        }
        struct timespec l_to;
#ifndef _WIN32
        int l_ret = 0;
        // prepare for signal waiting
        clock_gettime( CLOCK_MONOTONIC, &l_to );
        int64_t l_nsec_new = l_to.tv_nsec + l_timeout_ms * 1000000ll;
        // if the new number of nanoseconds is more than a second
        if(l_nsec_new > (long) 1e9) {
            l_to.tv_sec += l_nsec_new / (long) 1e9;
            l_to.tv_nsec = l_nsec_new % (long) 1e9;
        }
        else
            l_to.tv_nsec = (long) l_nsec_new;
        pthread_mutex_lock( &p_net->state_mutex_cond );
        // wait if flag not set then go to SYNC_GDB
        while ((p_net->flags & F_DAP_CHAIN_NET_GO_SYNC) == 0 && l_ret == 0) {
            // signal waiting
            l_ret = pthread_cond_timedwait( &p_net->state_proc_cond, &p_net->state_mutex_cond, &l_to );
        }
        pthread_mutex_unlock(&p_net->state_mutex_cond);
#else // WIN32

        WaitForSingleObject( p_net->state_proc_cond, (uint32_t)l_timeout_ms );

#endif
        // checking whether new sync is needed
        time_t l_sync_timeout = 300; // 300 sec = 5 min
        clock_gettime(CLOCK_MONOTONIC, &l_to);
        // start sync every l_sync_timeout sec
        if(l_to.tv_sec >= p_net->last_sync + l_sync_timeout) {
            p_net->flags |= F_DAP_CHAIN_NET_GO_SYNC;
        }
    }

    return NULL;
}

/**
 * @brief net_proc_start
 * @param a_cfg
 */
static void s_net_proc_thread_start( dap_chain_net_t * a_net )
{
    if ( pthread_create(& PVT(a_net)->proc_tid ,NULL, s_net_proc_thread, a_net) == 0 ){
        log_it (L_NOTICE,"Network processing thread started");
    }
}

/**
 * @brief s_net_proc_kill
 * @param a_net
 */
static void s_net_proc_kill( dap_chain_net_t * a_net )
{
    if ( !PVT(a_net)->proc_tid )
        return;

    log_it( L_NOTICE,"Sent KILL signal to the net process thread %d, waiting for shutdown...", PVT(a_net)->proc_tid );

    PVT(a_net)->flags |= F_DAP_CHAIN_NET_SHUTDOWN;

#ifndef _WIN32
    pthread_cond_signal( &PVT(a_net)->state_proc_cond );
#else
    SetEvent( PVT(a_net)->state_proc_cond );
#endif

    pthread_join( PVT(a_net)->proc_tid , NULL );
    log_it( L_NOTICE,"Net process thread %d shutted down", PVT(a_net)->proc_tid );

    PVT(a_net)->proc_tid = 0;

    return;
}

dap_chain_node_role_t dap_chain_net_get_role(dap_chain_net_t * a_net)
{
    return  PVT(a_net)->node_role;
}

/**
 * @brief dap_chain_net_new
 * @param a_id
 * @param a_name
 * @param a_node_role
 * @param a_node_name
 * @return
 */
static dap_chain_net_t *s_net_new(const char * a_id, const char * a_name ,
                                    const char * a_node_role)
{
    dap_chain_net_t *ret = DAP_NEW_Z_SIZE( dap_chain_net_t, sizeof(ret->pub) + sizeof(dap_chain_net_pvt_t) );
    ret->pub.name = strdup( a_name );

#ifndef _WIN32
    pthread_condattr_t l_attr;
    pthread_condattr_init( &l_attr );
    pthread_condattr_setclock( &l_attr, CLOCK_MONOTONIC );
    pthread_cond_init( &PVT(ret)->state_proc_cond, &l_attr );
#else
    PVT(ret)->state_proc_cond = CreateEventA( NULL, FALSE, FALSE, NULL );
#endif

    //    if ( sscanf(a_id,"0x%016lx", &ret->pub.id.uint64 ) == 1 ){
    if ( sscanf(a_id,"0x%016llx", &ret->pub.id.uint64 ) == 1 ){
        if (strcmp (a_node_role, "root_master")==0){
            PVT(ret)->node_role.enums = NODE_ROLE_ROOT_MASTER;
            log_it (L_NOTICE, "Node role \"root master\" selected");
        } else if (strcmp( a_node_role,"root") == 0){
            PVT(ret)->node_role.enums = NODE_ROLE_ROOT;
            log_it (L_NOTICE, "Node role \"root\" selected");

        } else if (strcmp( a_node_role,"archive") == 0){
            PVT(ret)->node_role.enums = NODE_ROLE_ARCHIVE;
            log_it (L_NOTICE, "Node role \"archive\" selected");

        } else if (strcmp( a_node_role,"cell_master") == 0){
            PVT(ret)->node_role.enums = NODE_ROLE_CELL_MASTER;
            log_it (L_NOTICE, "Node role \"cell master\" selected");

        }else if (strcmp( a_node_role,"master") == 0){
            PVT(ret)->node_role.enums = NODE_ROLE_MASTER;
            log_it (L_NOTICE, "Node role \"master\" selected");

        }else if (strcmp( a_node_role,"full") == 0){
            PVT(ret)->node_role.enums = NODE_ROLE_FULL;
            log_it (L_NOTICE, "Node role \"full\" selected");

        }else if (strcmp( a_node_role,"light") == 0){
            PVT(ret)->node_role.enums = NODE_ROLE_LIGHT;
            log_it (L_NOTICE, "Node role \"light\" selected");

        }else{
            log_it(L_ERROR,"Unknown node role \"%s\"",a_node_role);
            DAP_DELETE(ret);
            return  NULL;
        }
    } else {
        log_it (L_ERROR, "Wrong id format (\"%s\"). Must be like \"0x0123456789ABCDE\"" , a_id );
        DAP_DELETE(ret);
        return  NULL;
    }
    return ret;

}

/**
 * @brief dap_chain_net_delete
 * @param a_net
 */
void dap_chain_net_delete( dap_chain_net_t * a_net )
{
    if(PVT(a_net)->seed_aliases) {
        DAP_DELETE(PVT(a_net)->seed_aliases);
        PVT(a_net)->seed_aliases = NULL;
    }
    DAP_DELETE( PVT(a_net) );
}


/**
 * @brief dap_chain_net_init
 * @return
 */
int dap_chain_net_init()
{
    dap_chain_node_cli_cmd_item_create ("net", s_cli_net, NULL, "Network commands",
        "net -net <chain net name> go < online | offline >\n"
            "\tFind and establish links and stay online\n"
        "net -net <chain net name> get status\n"
            "\tLook at current status\n"
        "net -net <chain net name> stats tx [-from <From time>] [-to <To time>] [-prev_sec <Seconds>] \n"
            "\tTransactions statistics. Time format is <Year>-<Month>-<Day>_<Hours>:<Minutes>:<Seconds> or just <Seconds> \n"
        "net -net <chain net name> sync < all | gdb | chains >\n"
            "\tSyncronyze gdb, chains or everything\n\n"
        "net -net <chain net name> link < list | add | del | info | establish >\n"
            "\tList,add,del, dump or establish links\n\n"
                                        );
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    dap_chain_global_db_add_history_group_prefix("global", GROUP_LOCAL_HISTORY);

    dap_chain_global_db_add_history_callback_notify("global", s_gbd_history_callback_notify, NULL );

    // maximum number of connections to other nodes
    s_max_links_count = dap_config_get_item_int32_default(g_config, "general", "max_links", s_max_links_count);
    // required number of connections to other nodes
    s_required_links_count = dap_config_get_item_int32_default(g_config, "general", "require_links", s_required_links_count);

    dap_chain_net_load_all();
    return 0;
}

void dap_chain_net_load_all()
{
    char * l_net_dir_str = dap_strdup_printf("%s/network", dap_config_path());
    DIR * l_net_dir = opendir( l_net_dir_str);
    if ( l_net_dir ){
        struct dirent * l_dir_entry;
        while ( (l_dir_entry = readdir(l_net_dir) )!= NULL ){
            if (l_dir_entry->d_name[0]=='\0' || l_dir_entry->d_name[0]=='.')
                continue;
            // don't search in directories
            char * l_full_path = dap_strdup_printf("%s/%s", l_net_dir_str, l_dir_entry->d_name);
            if(dap_dir_test(l_full_path)) {
                DAP_DELETE(l_full_path);
                continue;
            }
            DAP_DELETE(l_full_path);
            // search only ".cfg" files
            if(strlen(l_dir_entry->d_name) > 4) { // It has non zero name excluding file extension
                if(strncmp(l_dir_entry->d_name + strlen(l_dir_entry->d_name) - 4, ".cfg", 4) != 0) {
                    // its not .cfg file
                    continue;
                }
            }
            log_it(L_DEBUG,"Network config %s try to load", l_dir_entry->d_name);
            //char* l_dot_pos = rindex(l_dir_entry->d_name,'.');
            char* l_dot_pos = strchr(l_dir_entry->d_name,'.');
            if ( l_dot_pos )
                *l_dot_pos = '\0';
            s_net_load(l_dir_entry->d_name );
        }
        closedir(l_net_dir);
    }
    DAP_DELETE (l_net_dir_str);
}

/**
 * @brief s_cli_net
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
static int s_cli_net( int argc, char **argv, void *arg_func, char **a_str_reply)
{
    int arg_index = 1;
    dap_chain_net_t * l_net = NULL;

    // command 'net list'
    if(dap_chain_node_cli_find_option_val(argv, arg_index, argc, "list", NULL) == arg_index) {

        dap_string_t *l_string_ret = dap_string_new("list of nets: ");
        // show list of nets
        dap_chain_net_item_t * l_net_item, *l_net_item_tmp;
        int l_net_i = 0;
        HASH_ITER(hh, s_net_items, l_net_item, l_net_item_tmp)
        {
            if(l_net_i > 0)
                dap_string_append(l_string_ret, ", ");
            dap_string_append_printf(l_string_ret, "%s", l_net_item->name);
            l_net_i++;
        }
        if(!l_net_i)
            dap_string_append(l_string_ret, "-\n");
        else
            dap_string_append(l_string_ret, "\n");

        dap_chain_node_cli_set_reply_text(a_str_reply, l_string_ret->str);
        dap_string_free(l_string_ret, true);
        return 0;
    }

    int ret = dap_chain_node_cli_cmd_values_parse_net_chain( &arg_index, argc, argv, a_str_reply, NULL, &l_net );

    if ( l_net ) {
        const char *l_sync_str = NULL;
        const char *l_links_str = NULL;
        const char *l_go_str = NULL;
        const char *l_get_str = NULL;
        const char *l_stats_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "sync", &l_sync_str);
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "link", &l_links_str);
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "go", &l_go_str);
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "get", &l_get_str);
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "stats", &l_stats_str);

        if ( l_stats_str ){
            if ( strcmp(l_stats_str,"tx") == 0 ) {
                const char *l_to_str = NULL;
                struct tm l_to_tm = {0};

                const char *l_from_str = NULL;
                struct tm l_from_tm = {0};

                const char *l_prev_sec_str = NULL;
                //time_t l_prev_sec_ts;

                const char c_time_fmt[]="%Y-%m-%d_%H:%M:%S";

                // Read from/to time
                dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-from", &l_from_str);
                dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-to", &l_to_str);
                dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-prev_sec", &l_prev_sec_str);

                if (l_from_str ) {
                    strptime( (char *)l_from_str, c_time_fmt, &l_from_tm );
                }

                if (l_to_str) {
                    strptime( (char *)l_to_str, c_time_fmt, &l_to_tm );
                }

                if ( l_to_str == NULL ){ // If not set '-to' - we set up current time
                    time_t l_ts_now = time(NULL);
                    localtime_r(&l_ts_now, &l_to_tm);
                }

                if ( l_prev_sec_str ){
                    time_t l_ts_now = time(NULL);
                    l_ts_now -= strtol( l_prev_sec_str, NULL,10 );
                    localtime_r(&l_ts_now, &l_from_tm );
                }/*else if ( l_from_str == NULL ){ // If not set '-from' we set up current time minus 10 seconds
                    time_t l_ts_now = time(NULL);
                    l_ts_now -= 10;
                    localtime_r(&l_ts_now, &l_from_tm );
                }*/

                // Form timestamps from/to
                time_t l_from_ts = mktime(&l_from_tm);
                time_t l_to_ts = mktime(&l_to_tm);

                // Produce strings
                char l_from_str_new[50];
                char l_to_str_new[50];
                strftime(l_from_str_new, sizeof(l_from_str_new), c_time_fmt,&l_from_tm );
                strftime(l_to_str_new, sizeof(l_to_str_new), c_time_fmt,&l_to_tm );


                dap_string_t * l_ret_str = dap_string_new("Transactions statistics:\n");

                dap_string_append_printf( l_ret_str, "\tFrom: %s\tTo: %s\n", l_from_str_new, l_to_str_new);
                log_it(L_INFO, "Calc TPS from %s to %s", l_from_str_new, l_to_str_new);
                uint64_t l_tx_count = dap_chain_ledger_count_from_to ( l_net->pub.ledger, l_from_ts, l_to_ts);
                long double l_tps = l_to_ts == l_from_ts ? 0 :
                                                     (long double) l_tx_count / (long double) ( l_to_ts - l_from_ts );
                dap_string_append_printf( l_ret_str, "\tSpeed:  %.3Lf TPS\n", l_tps );
                dap_string_append_printf( l_ret_str, "\tTotal:  %llu\n", l_tx_count );
                dap_chain_node_cli_set_reply_text( a_str_reply, l_ret_str->str );
                dap_string_free( l_ret_str, false );
            }
        } else if ( l_go_str){
            if ( strcmp(l_go_str,"online") == 0 ) {
                dap_chain_net_state_go_to(l_net, NET_STATE_ONLINE);
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network \"%s\" go from state %s to %s",
                                                    l_net->pub.name,c_net_states[PVT(l_net)->state],
                                                    c_net_states[PVT(l_net)->state_target]);
            } else if ( strcmp(l_go_str,"offline") == 0 ) {
                dap_chain_net_state_go_to(l_net, NET_STATE_OFFLINE);
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network \"%s\" go from state %s to %s",
                                                    l_net->pub.name,c_net_states[PVT(l_net)->state],
                                                    c_net_states[PVT(l_net)->state_target]);

            }
            else if(strcmp(l_go_str, "sync") == 0) {
                dap_chain_net_state_go_to(l_net, NET_STATE_SYNC_GDB);
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network \"%s\" go from state %s to %s",
                        l_net->pub.name, c_net_states[PVT(l_net)->state],
                        c_net_states[PVT(l_net)->state_target]);

            }

        } else if ( l_get_str){
            if ( strcmp(l_get_str,"status") == 0 ) {
                // get current node address
                dap_chain_node_addr_t l_cur_node_addr = { 0 };
                l_cur_node_addr.uint64 = dap_chain_net_get_cur_addr(l_net) ? dap_chain_net_get_cur_addr(l_net)->uint64 : dap_db_get_cur_node_addr(l_net->pub.name);
                if(!l_cur_node_addr.uint64) {
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                            "Network \"%s\" has state %s (target state %s), active links %u from %u, cur node address not defined",
                            l_net->pub.name, c_net_states[PVT(l_net)->state],
                            c_net_states[PVT(l_net)->state_target], PVT(l_net)->links_count,
                            PVT(l_net)->links_addrs_count
                            );
                }
                else {
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                            "Network \"%s\" has state %s (target state %s), active links %u from %u, cur node address " NODE_ADDR_FP_STR,
                            l_net->pub.name, c_net_states[PVT(l_net)->state],
                            c_net_states[PVT(l_net)->state_target], PVT(l_net)->links_count,
                            PVT(l_net)->links_addrs_count,
                            NODE_ADDR_FP_ARGS_S(l_cur_node_addr)
                            );
                }
                ret = 0;
            }
        } else if ( l_links_str ){
            if ( strcmp(l_links_str,"list") == 0 ) {

            } else if ( strcmp(l_links_str,"add") == 0 ) {

            } else if ( strcmp(l_links_str,"del") == 0 ) {

            }  else if ( strcmp(l_links_str,"info") == 0 ) {

            } else if ( strcmp (l_links_str,"disconnect_all") == 0 ){
                ret = 0;
                dap_chain_net_stop(l_net);
            }else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Subcommand \"link\" requires one of parameter: list\n");
                ret = -3;
            }

        } else if( l_sync_str) {
            if ( strcmp(l_sync_str,"all") == 0 ) {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "SYNC_ALL state requested to state machine. Current state: %s\n",
                                                  c_net_states[ PVT(l_net)->state] );
                dap_chain_net_sync_all(l_net);
            } else if ( strcmp(l_sync_str,"gdb") == 0) {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "SYNC_GDB state requested to state machine. Current state: %s\n",
                                                  c_net_states[ PVT(l_net)->state] );
                dap_chain_net_sync_gdb(l_net);

            }  else if ( strcmp(l_sync_str,"chains") == 0) {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "SYNC_CHAINS state requested to state machine. Current state: %s\n",
                                                  c_net_states[ PVT(l_net)->state] );
                dap_chain_net_sync_chains(l_net);

            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Subcommand \"sync\" requires one of parameter: all,gdb,chains\n");
                ret = -2;
            }
        } else {
            dap_chain_node_cli_set_reply_text(a_str_reply,"Command requires one of subcomand: sync, links\n");
            ret = -1;
        }

    }
    return  ret;
}

// for sequential loading chains
typedef struct list_priority_{
    uint16_t prior;
    char * chains_path;
}list_priority;

static int callback_compare_prioritity_list(const void * a_item1, const void * a_item2)
{
    list_priority *l_item1 = (list_priority*) a_item1;
    list_priority *l_item2 = (list_priority*) a_item2;
    if(!l_item1 || !l_item2 || l_item1->prior == l_item2->prior)
        return 0;
    if(l_item1->prior > l_item2->prior)
        return 1;
    return -1;
}

/**
 * @brief s_net_load
 * @param a_net_name
 * @return
 */
int s_net_load(const char * a_net_name)
{
    dap_config_t *l_cfg=NULL;
    dap_string_t *l_cfg_path = dap_string_new("network/");
    dap_string_append(l_cfg_path,a_net_name);

    if( ( l_cfg = dap_config_open ( l_cfg_path->str ) ) == NULL ) {
        log_it(L_ERROR,"Can't open default network config");
        dap_string_free(l_cfg_path,true);
        return -1;
    } else {
        dap_string_free(l_cfg_path,true);
        dap_chain_net_t * l_net = s_net_new(
                                            dap_config_get_item_str(l_cfg , "general" , "id" ),
                                            dap_config_get_item_str(l_cfg , "general" , "name" ),
                                            dap_config_get_item_str(l_cfg , "general" , "node-role" )
                                           );
        if(!l_net) {
            log_it(L_ERROR,"Can't create l_net");
            return -1;
        }
        PVT(l_net)->load_mode = true;
        l_net->pub.gdb_groups_prefix = dap_strdup (
                    dap_config_get_item_str_default(l_cfg , "general" , "gdb_groups_prefix",
                                                    dap_config_get_item_str(l_cfg , "general" , "name" ) ) );
        dap_chain_global_db_add_history_group_prefix( l_net->pub.gdb_groups_prefix, GROUP_LOCAL_HISTORY);
        dap_chain_global_db_add_history_callback_notify(l_net->pub.gdb_groups_prefix, s_gbd_history_callback_notify, l_net );

        l_net->pub.gdb_nodes = dap_strdup_printf("%s.nodes",l_net->pub.gdb_groups_prefix);
        l_net->pub.gdb_nodes_aliases = dap_strdup_printf("%s.nodes.aliases",l_net->pub.gdb_groups_prefix);

        // for sync special groups - nodes
        char **l_gdb_sync_nodes_addrs = dap_config_get_array_str(l_cfg, "general", "gdb_sync_nodes_addrs",
                &PVT(l_net)->gdb_sync_nodes_addrs_count);
        if(l_gdb_sync_nodes_addrs && PVT(l_net)->gdb_sync_nodes_addrs_count > 0) {
            PVT(l_net)->gdb_sync_nodes_addrs = (dap_chain_node_addr_t*) DAP_NEW_Z_SIZE(char**,
                    sizeof(dap_chain_node_addr_t)*PVT(l_net)->gdb_sync_nodes_addrs_count);
            for(uint16_t i = 0; i < PVT(l_net)->gdb_sync_nodes_addrs_count; i++) {
                dap_chain_node_addr_from_str(PVT(l_net)->gdb_sync_nodes_addrs + i, l_gdb_sync_nodes_addrs[i]);
            }
        }
        // for sync special groups - groups
        char **l_gdb_sync_groups = dap_config_get_array_str(l_cfg, "general", "gdb_sync_groups", &PVT(l_net)->gdb_sync_groups_count);
        if(l_gdb_sync_groups && PVT(l_net)->gdb_sync_groups_count > 0) {
            PVT(l_net)->gdb_sync_groups = (char **) DAP_NEW_SIZE(char**, sizeof(char*)*PVT(l_net)->gdb_sync_groups_count);
            for(uint16_t i = 0; i < PVT(l_net)->gdb_sync_groups_count; i++) {
                PVT(l_net)->gdb_sync_groups[i] = dap_strdup(l_gdb_sync_groups[i]);
                // added group to history log
                dap_list_t *l_groups0 = dap_chain_global_db_driver_get_groups_by_mask(PVT(l_net)->gdb_sync_groups[i]);
                dap_list_t *l_groups = l_groups0;
                while(l_groups) {
                    char *l_group_name = l_groups->data;
                    // do not use groups with names like *.del
                    if(!strstr(l_group_name, ".del")) {
                        const char *l_history_group = dap_chain_global_db_add_history_extra_group(l_group_name,
                                                        PVT(l_net)->gdb_sync_nodes_addrs,
                                                        &PVT(l_net)->gdb_sync_nodes_addrs_count);
                        dap_chain_global_db_add_history_extra_group_callback_notify(l_group_name,
                                s_gbd_history_callback_notify, l_net);
                        // create history for group
                        if(dap_db_log_get_group_history_last_id(l_history_group) <= 0) {
                            size_t l_data_size_out = 0;
                            dap_store_obj_t *l_obj = dap_chain_global_db_obj_gr_get(NULL, &l_data_size_out, l_group_name);
                            if(l_obj && l_data_size_out > 0) {
                                dap_db_history_add('a', l_obj, l_data_size_out, l_history_group);
                                dap_store_obj_free(l_obj, l_data_size_out);
                            }
                        }
                    }
                    l_groups = dap_list_next(l_groups);
                }
                dap_list_free_full(l_groups0, (dap_callback_destroyed_t)free);
            }
        }


        // Add network to the list
        dap_chain_net_item_t * l_net_item = DAP_NEW_Z( dap_chain_net_item_t);
        dap_chain_net_item_t * l_net_item2 = DAP_NEW_Z( dap_chain_net_item_t);
        dap_snprintf(l_net_item->name,sizeof (l_net_item->name),"%s"
                     ,dap_config_get_item_str(l_cfg , "general" , "name" ));
        l_net_item->chain_net = l_net;
        l_net_item->net_id.uint64 = l_net->pub.id.uint64;
        HASH_ADD_STR(s_net_items,name,l_net_item);

        memcpy( l_net_item2,l_net_item,sizeof (*l_net_item));
        HASH_ADD(hh,s_net_items_ids,net_id,sizeof ( l_net_item2->net_id),l_net_item2);

        // LEDGER model
        uint16_t l_ledger_flags = 0;
        switch ( PVT( l_net )->node_role.enums ) {
            case NODE_ROLE_ROOT_MASTER:
            case NODE_ROLE_ROOT:
            case NODE_ROLE_ARCHIVE:
                l_ledger_flags |= DAP_CHAIN_LEDGER_CHECK_TOKEN_EMISSION;
            case NODE_ROLE_MASTER:
                l_ledger_flags |= DAP_CHAIN_LEDGER_CHECK_CELLS_DS;
            case NODE_ROLE_CELL_MASTER:
                l_ledger_flags |= DAP_CHAIN_LEDGER_CHECK_TOKEN_EMISSION;
            case NODE_ROLE_FULL:
            case NODE_ROLE_LIGHT:
                l_ledger_flags |= DAP_CHAIN_LEDGER_CHECK_LOCAL_DS;
        }
        // init LEDGER model
        l_net->pub.ledger = dap_chain_ledger_create(l_ledger_flags);
        // Check if seed nodes are present in local db alias
        char **l_seed_aliases = dap_config_get_array_str( l_cfg , "general" ,"seed_nodes_aliases"
                                                             ,&PVT(l_net)->seed_aliases_count);
        PVT(l_net)->seed_aliases = PVT(l_net)->seed_aliases_count>0 ?
                                   (char **)DAP_NEW_SIZE(char**, sizeof(char*)*PVT(l_net)->seed_aliases_count) : NULL;
        for(size_t i = 0; i < PVT(l_net)->seed_aliases_count; i++) {
            PVT(l_net)->seed_aliases[i] = dap_strdup(l_seed_aliases[i]);
        }

        uint16_t l_seed_nodes_addrs_len =0;
        char ** l_seed_nodes_addrs = dap_config_get_array_str( l_cfg , "general" ,"seed_nodes_addrs"
                                                             ,&l_seed_nodes_addrs_len);

        uint16_t l_seed_nodes_ipv4_len =0;
        char ** l_seed_nodes_ipv4 = dap_config_get_array_str( l_cfg , "general" ,"seed_nodes_ipv4"
                                                             ,&l_seed_nodes_ipv4_len);

        uint16_t l_seed_nodes_ipv6_len =0;
        char ** l_seed_nodes_ipv6 = dap_config_get_array_str( l_cfg , "general" ,"seed_nodes_ipv6"
                                                             ,&l_seed_nodes_ipv6_len);

        uint16_t l_seed_nodes_hostnames_len =0;
        char ** l_seed_nodes_hostnames = dap_config_get_array_str( l_cfg , "general" ,"seed_nodes_hostnames"
                                                             ,&l_seed_nodes_hostnames_len);

        uint16_t l_seed_nodes_port_len =0;
        char ** l_seed_nodes_port = dap_config_get_array_str( l_cfg , "general" ,"seed_nodes_port"
                                                                     ,&l_seed_nodes_port_len);

        const char * l_node_addr_type = dap_config_get_item_str_default(l_cfg , "general" ,"node_addr_type","auto");

        const char * l_node_addr_str = NULL;
        const char * l_node_alias_str = NULL;

        // use unique addr from pub key
        if(!dap_strcmp(l_node_addr_type, "auto")) {
            size_t l_pub_key_data_size = 0;
            uint8_t *l_pub_key_data = NULL;

            // read pub key
            l_pub_key_data = dap_chain_global_db_gr_get("cur-node-addr-pkey", &l_pub_key_data_size, GROUP_LOCAL_NODE_ADDR);
            // generate new pub key
            if(!l_pub_key_data || !l_pub_key_data_size){

                const char * l_certs_name_str = "node-addr";
                dap_cert_t ** l_certs = NULL;
                size_t l_certs_size = 0;
                dap_cert_t * l_cert = NULL;
                // Load certs or create if not found
                if(!dap_cert_parse_str_list(l_certs_name_str, &l_certs, &l_certs_size)) { // Load certs
                    const char *l_cert_folder = dap_cert_get_folder(0);
                    // create new cert
                    if(l_cert_folder) {
                        char *l_cert_path = dap_strdup_printf("%s/%s.dcert", l_cert_folder, l_certs_name_str);
                        l_cert = dap_cert_generate(l_certs_name_str, l_cert_path, DAP_ENC_KEY_TYPE_SIG_DILITHIUM);
                        DAP_DELETE(l_cert_path);
                    }
                }
                if(l_certs_size > 0)
                    l_cert = l_certs[0];
                if(l_cert) {
                    l_pub_key_data = dap_enc_key_serealize_pub_key(l_cert->enc_key, &l_pub_key_data_size);
                    // save pub key
                    if(l_pub_key_data && l_pub_key_data_size > 0)
                        dap_chain_global_db_gr_set(dap_strdup("cur-node-addr-pkey"), (uint8_t*) l_pub_key_data, l_pub_key_data_size,
                        GROUP_LOCAL_NODE_ADDR);
                }
            }
            // generate addr from pub_key
            dap_chain_hash_fast_t l_hash;
            if(l_pub_key_data_size > 0 && dap_hash_fast(l_pub_key_data, l_pub_key_data_size, &l_hash) == 1) {
                l_node_addr_str = dap_strdup_printf("%04X::%04X::%04X::%04X",
                        (uint16_t) *(uint16_t*) (l_hash.raw),
                        (uint16_t) *(uint16_t*) (l_hash.raw + 2),
                        (uint16_t) *(uint16_t*) (l_hash.raw + DAP_CHAIN_HASH_FAST_SIZE - 4),
                        (uint16_t) *(uint16_t*) (l_hash.raw + DAP_CHAIN_HASH_FAST_SIZE - 2));
            }
            DAP_DELETE(l_pub_key_data);
        }
        // use static addr from setting
        else if(!dap_strcmp(l_node_addr_type, "static")) {
            //const char * l_node_ipv4_str = dap_config_get_item_str(l_cfg , "general" ,"node-ipv4");
            l_node_addr_str = dap_strdup(dap_config_get_item_str(l_cfg, "general", "node-addr"));
            l_node_alias_str = dap_config_get_item_str(l_cfg, "general", "node-alias");
        }

        log_it (L_DEBUG, "Read %u aliases, %u address and %u ipv4 addresses, check them",
                PVT(l_net)->seed_aliases_count,l_seed_nodes_addrs_len, l_seed_nodes_ipv4_len );
        // save new nodes from cfg file to db
        for ( size_t i = 0; i < PVT(l_net)->seed_aliases_count &&
                            i < l_seed_nodes_addrs_len &&
                            (
                                ( l_seed_nodes_ipv4_len  && i < l_seed_nodes_ipv4_len  ) ||
                                ( l_seed_nodes_ipv6_len  && i < l_seed_nodes_ipv6_len  ) ||
                                ( l_seed_nodes_hostnames_len  && i < l_seed_nodes_hostnames_len  )
                              )
                                                                    ; i++ ){
            dap_chain_node_addr_t * l_seed_node_addr;
            l_seed_node_addr = dap_chain_node_alias_find(l_net, PVT(l_net)->seed_aliases[i] );
            if (l_seed_node_addr == NULL){
                log_it(L_NOTICE, "Not found alias %s in database, prefill it",PVT(l_net)->seed_aliases[i]);
                dap_chain_node_info_t * l_node_info = DAP_NEW_Z(dap_chain_node_info_t);
                l_seed_node_addr = DAP_NEW_Z(dap_chain_node_addr_t);
                dap_snprintf( l_node_info->hdr.alias,sizeof ( l_node_info->hdr.alias),"%s",PVT(l_net)->seed_aliases[i]);
                if (sscanf(l_seed_nodes_addrs[i],NODE_ADDR_FP_STR, NODE_ADDR_FPS_ARGS(l_seed_node_addr) ) != 4 ){
                    log_it(L_ERROR,"Wrong address format,  should be like 0123::4567::890AB::CDEF");
                    DAP_DELETE(l_seed_node_addr);
                    DAP_DELETE(l_node_info);
                    l_seed_node_addr = NULL;
                    continue;
                }
                if( l_seed_node_addr ){
                    if ( l_seed_nodes_ipv4_len )
                        inet_pton( AF_INET, l_seed_nodes_ipv4[i],&l_node_info->hdr.ext_addr_v4);
                    if ( l_seed_nodes_ipv6_len )
                        inet_pton( AF_INET6, l_seed_nodes_ipv6[i],&l_node_info->hdr.ext_addr_v6);
                    if(l_seed_nodes_port_len && l_seed_nodes_port_len >= i)
                        l_node_info->hdr.ext_port = strtoul(l_seed_nodes_port[i], NULL, 10);
                    else
                        l_node_info->hdr.ext_port = 8079;

                    if ( l_seed_nodes_hostnames_len ){
                        struct addrinfo l_hints={0};

                        l_hints.ai_family = AF_UNSPEC ;    /* Allow IPv4 or IPv6 */
                        //l_hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */

                        log_it( L_DEBUG, "Resolve %s addr", l_seed_nodes_hostnames[i]);
                        struct hostent *l_he;

                        if ( (l_he = gethostbyname (l_seed_nodes_hostnames[i]) ) != NULL  ){
                            struct in_addr **l_addr_list = (struct in_addr **) l_he->h_addr_list;
                            for(int i = 0; l_addr_list[i] != NULL; i++ ) {
                                log_it( L_NOTICE, "Resolved %s to %s (ipv4)", l_seed_nodes_hostnames[i] ,
                                        inet_ntoa( *l_addr_list[i]  ) );
                                l_node_info->hdr.ext_addr_v4.s_addr = l_addr_list[i]->s_addr;
                            }
                        } else {
                            herror("gethostname");
                        }
                    }

                    l_node_info->hdr.address.uint64 = l_seed_node_addr->uint64;
                    if ( l_node_info->hdr.ext_addr_v4.s_addr ||
                            l_node_info->hdr.ext_addr_v6.s6_addr32[0] ){
                        int l_ret;
                        if ( (l_ret = dap_chain_node_info_save(l_net, l_node_info)) ==0 ){
                            if (dap_chain_node_alias_register(l_net,PVT(l_net)->seed_aliases[i],l_seed_node_addr))
                                log_it(L_NOTICE,"Seed node "NODE_ADDR_FP_STR" added to the curent list",NODE_ADDR_FP_ARGS(l_seed_node_addr) );
                            else {
                                log_it(L_WARNING,"Cant register alias %s for address "NODE_ADDR_FP_STR,NODE_ADDR_FP_ARGS(l_seed_node_addr));
                            }
                        }else{
                            log_it(L_WARNING,"Cant save node info for address "NODE_ADDR_FP_STR" return code %d",
                                   NODE_ADDR_FP_ARGS(l_seed_node_addr), l_ret);
                        }
                    }
                    DAP_DELETE( l_seed_node_addr);
                }else
                    log_it(L_WARNING,"No address for seed node, can't populate global_db with it");
                DAP_DELETE( l_node_info);
            }else{
                log_it(L_DEBUG,"Seed alias %s is present",PVT(l_net)->seed_aliases[i]);
                DAP_DELETE( l_seed_node_addr);
            }

         }
         //DAP_DELETE( l_seed_nodes_ipv4);
         //DAP_DELETE(l_seed_nodes_addrs);
        if ( l_node_addr_str || l_node_alias_str ){
            dap_chain_node_addr_t * l_node_addr;
            if ( l_node_addr_str == NULL)
                l_node_addr = dap_chain_node_alias_find(l_net, l_node_alias_str);
            else{
                l_node_addr = DAP_NEW_Z(dap_chain_node_addr_t);
                bool parse_succesfully = false;
                if ( sscanf(l_node_addr_str, "0x%016llx",&l_node_addr->uint64 ) == 1 ){
                    log_it(L_DEBUG, "Parse node address with format 0x016llx");
                    parse_succesfully = true;
                }
                if ( !parse_succesfully && dap_chain_node_addr_from_str(l_node_addr, l_node_addr_str) == 0) {
                    log_it(L_DEBUG, "Parse node address with format 04hX::04hX::04hX::04hX");
                    parse_succesfully = true;
                }

                if (!parse_succesfully){
                    log_it(L_ERROR,"Can't parse node address %s", l_node_addr_str);
                    DAP_DELETE(l_node_addr);
                    l_node_addr = NULL;
                }
                log_it(L_NOTICE, "Parse node addr " NODE_ADDR_FP_STR " successfully", NODE_ADDR_FP_ARGS(l_node_addr));
                PVT(l_net)->node_addr = l_node_addr;
                //}
            }
            if ( l_node_addr ) {
                char *l_addr_hash_str = dap_chain_node_addr_to_hash_str(l_node_addr);
                // save current node address
                dap_db_set_cur_node_addr(l_node_addr->uint64, l_net->pub.name);
                if(!l_addr_hash_str){
                    log_it(L_ERROR,"Can't get hash string for node address!");
                } else {
                    PVT(l_net)->node_info = dap_chain_node_info_read (l_net, l_node_addr);
                    if ( PVT(l_net)->node_info ) {
                        log_it(L_NOTICE,"GDB Info: node_addr: " NODE_ADDR_FP_STR"  links: %u cell_id: 0x%016X ",
                               NODE_ADDR_FP_ARGS(l_node_addr),
                               PVT(l_net)->node_info->hdr.links_number,
                               PVT(l_net)->node_info->hdr.cell_id.uint64);
                        // save cell_id
                        l_net->pub.cell_id.uint64 = PVT(l_net)->node_info->hdr.cell_id.uint64;
                    }else {
                        log_it(L_WARNING, "Not present node_info in database for our own address " NODE_ADDR_FP_STR,
                               NODE_ADDR_FP_ARGS(l_node_addr) );
                    }
                }
            }
            else{
                log_it(L_WARNING, "Not present our own address %s in database", (l_node_alias_str) ? l_node_alias_str: "");
            }


         }
/*        // if present 'l_node_ipv4_str' and no 'l_node_addr_str' and 'l_node_alias_str'
        if(!PVT(l_net)->node_info && l_node_ipv4_str) {
            dap_chain_node_info_t *l_node_info = DAP_NEW_Z(dap_chain_node_info_t);
            inet_pton( AF_INET, l_node_ipv4_str, &l_node_info->hdr.ext_addr_v4);
            PVT(l_net)->node_info = l_node_info;
        }*/

        // Init chains
        //size_t l_chains_path_size =strlen(dap_config_path())+1+strlen(l_net->pub.name)+1+strlen("network")+1;
        //char * l_chains_path = DAP_NEW_Z_SIZE (char,l_chains_path_size);
        //dap_snprintf(l_chains_path,l_chains_path_size,"%s/network/%s",dap_config_path(),l_net->pub.name);
        char * l_chains_path = dap_strdup_printf("%s/network/%s", dap_config_path(), l_net->pub.name);
        DIR * l_chains_dir = opendir(l_chains_path);
        DAP_DELETE (l_chains_path);
        if ( l_chains_dir ){
            // for sequential loading chains
            dap_list_t *l_prior_list = NULL;

            struct dirent * l_dir_entry;
            while ( (l_dir_entry = readdir(l_chains_dir) )!= NULL ){
                if (l_dir_entry->d_name[0]=='\0')
                    continue;
                char * l_entry_name = strdup(l_dir_entry->d_name);
                if (strlen (l_entry_name) > 4 ){ // It has non zero name excluding file extension
                    if ( strncmp (l_entry_name+ strlen(l_entry_name)-4,".cfg",4) == 0 ) { // its .cfg file
                        l_entry_name [strlen(l_entry_name)-4] = 0;
                        log_it(L_DEBUG,"Open chain config \"%s\"...",l_entry_name);
                        l_chains_path = dap_strdup_printf("network/%s/%s",l_net->pub.name,l_entry_name);
                        dap_config_t * l_cfg = dap_config_open(l_chains_path);
                        if(l_cfg) {
                            list_priority *l_chain_prior = DAP_NEW_Z(list_priority);
                            l_chain_prior->prior = dap_config_get_item_uint16_default(l_cfg, "chain", "load_priority", 100);
                            l_chain_prior->chains_path = l_chains_path;
                            // add chain to load list;
                            l_prior_list = dap_list_append(l_prior_list, l_chain_prior);
                        }
                        // Create chain object
//                        dap_chain_t * l_chain = dap_chain_load_from_cfg(l_net->pub.ledger, l_net->pub.name,
//                                l_net->pub.id, l_chains_path);
//                        if(l_chain) {
//                            DL_APPEND(l_net->pub.chains, l_chain);
//                            if(l_chain->callback_created)
//                                l_chain->callback_created(l_chain, l_cfg);
//                        }
//                        DAP_DELETE (l_chains_path);
                    }
                }
                DAP_DELETE (l_entry_name);
            }
            closedir(l_chains_dir);

            // sort list with chains names by priority
            l_prior_list = dap_list_sort(l_prior_list, callback_compare_prioritity_list);
            // load chains by priority
            dap_list_t *l_list = l_prior_list;
            while(l_list){
                list_priority *l_chain_prior = l_list->data;
                // Create chain object
                dap_chain_t * l_chain = dap_chain_load_from_cfg(l_net->pub.ledger, l_net->pub.name,
                        l_net->pub.id, l_chain_prior->chains_path);
                if(l_chain) {
                    DL_APPEND(l_net->pub.chains, l_chain);
                    if(l_chain->callback_created)
                        l_chain->callback_created(l_chain, l_cfg);
                    // add a callback to monitor changes in the chain
                    dap_chain_add_callback_notify(l_chain, s_chain_callback_notify, l_net);
                }
                DAP_DELETE (l_chain_prior->chains_path);
                l_list = dap_list_next(l_list);
            }
            dap_list_free(l_prior_list);

            const char* l_default_chain_name = dap_config_get_item_str(l_cfg , "general" , "default_chain");
            if(l_default_chain_name)
                l_net->pub.default_chain = dap_chain_net_get_chain_by_name(l_net, l_default_chain_name);
            else
                l_net->pub.default_chain = NULL;

        } else {
            log_it(L_ERROR,"Can't any chains for network %s",l_net->pub.name);
            PVT(l_net)->load_mode = false;

            return -2;
        }
        // Do specific role actions post-chain created
        switch ( PVT( l_net )->node_role.enums ) {
            case NODE_ROLE_ROOT_MASTER:{
                // Set to process everything in datum pool
                dap_chain_t * l_chain = NULL;
                DL_FOREACH(l_net->pub.chains, l_chain ) l_chain->is_datum_pool_proc = true;
                log_it(L_INFO,"Root master node role established");
            } // Master root includes root
            case NODE_ROLE_ROOT:{
                // Set to process only zerochain
                dap_chain_id_t l_chain_id = {{0}};
                dap_chain_t * l_chain = dap_chain_find_by_id(l_net->pub.id,l_chain_id);
                if (l_chain )
                   l_chain->is_datum_pool_proc = true;

                PVT(l_net)->state_target = NET_STATE_ONLINE;
                log_it(L_INFO,"Root node role established");
            } break;
            case NODE_ROLE_CELL_MASTER:
            case NODE_ROLE_MASTER:{

                uint16_t l_proc_chains_count=0;
                char ** l_proc_chains = dap_config_get_array_str(l_cfg,"role-master" , "proc_chains", &l_proc_chains_count );
                for ( size_t i = 0; i< l_proc_chains_count ; i++){
                    dap_chain_id_t l_chain_id = {{0}};
                    if(dap_sscanf( l_proc_chains[i], "0x%16lX",  &l_chain_id.uint64) ==1 || dap_scanf("0x%16lx",  &l_chain_id.uint64) == 1){
                        dap_chain_t * l_chain = dap_chain_find_by_id(l_net->pub.id, l_chain_id );
                        if ( l_chain ){
                            l_chain->is_datum_pool_proc = true;
                        }else{
                            log_it( L_WARNING, "Can't find chain id " );
                        }
                    }
                    DAP_DELETE( l_proc_chains[i]);
                    l_proc_chains[i] = NULL;
                }
                //if ( l_proc_chains )
                //    DAP_DELETE (l_proc_chains);
                //l_proc_chains = NULL;

                PVT(l_net)->state_target = NET_STATE_ONLINE;
                log_it(L_INFO,"Master node role established");
            } break;
            case NODE_ROLE_FULL:{
                log_it(L_INFO,"Full node role established");
                PVT(l_net)->state_target = NET_STATE_ONLINE;
            } break;
            case NODE_ROLE_LIGHT:
            default:
                log_it(L_INFO,"Light node role established");

        }

        if (s_seed_mode || !dap_config_get_item_bool_default(g_config ,"general", "auto_online",false ) ) { // If we seed we do everything manual. First think - prefil list of node_addrs and its aliases
            PVT(l_net)->state_target = NET_STATE_OFFLINE;
        }
        PVT(l_net)->load_mode = false;
        PVT(l_net)->flags |= F_DAP_CHAIN_NET_GO_SYNC;

        // Start the proc thread
        s_net_proc_thread_start(l_net);
        log_it(L_NOTICE, "Сhain network \"%s\" initialized",l_net_item->name);
        dap_config_close(l_cfg);
    }
    return 0;
}

/**
 * @brief dap_chain_net_deinit
 */
void dap_chain_net_deinit()
{
}

dap_chain_net_t **dap_chain_net_list(uint16_t *a_size)
{
    *a_size = HASH_COUNT(s_net_items);
    dap_chain_net_t **l_net_list = DAP_NEW_SIZE(dap_chain_net_t *, (*a_size) * sizeof(dap_chain_net_t *));
    dap_chain_net_item_t *l_current_item, *l_tmp;
    int i = 0;
    HASH_ITER(hh, s_net_items, l_current_item, l_tmp) {
        l_net_list[i++] = l_current_item->chain_net;
    }
    return l_net_list;
}

/**
 * @brief dap_chain_net_by_name
 * @param a_name
 * @return
 */
dap_chain_net_t * dap_chain_net_by_name( const char * a_name)
{
    dap_chain_net_item_t * l_net_item = NULL;
    if(a_name)
        HASH_FIND_STR(s_net_items,a_name,l_net_item );
    if ( l_net_item )
        return l_net_item->chain_net;
    else
        return NULL;
}

/**
 * @brief dap_chain_ledger_by_net_name
 * @param a_net_name
 * @return
 */
dap_ledger_t * dap_chain_ledger_by_net_name( const char * a_net_name)
{
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if(l_net)
        return l_net->pub.ledger;
    return NULL;
}

/**
 * @brief dap_chain_net_by_id
 * @param a_id
 * @return
 */
dap_chain_net_t * dap_chain_net_by_id( dap_chain_net_id_t a_id)
{
    dap_chain_net_item_t * l_net_item = NULL;
    HASH_FIND(hh,s_net_items_ids,&a_id,sizeof (a_id), l_net_item );
    if ( l_net_item )
        return l_net_item->chain_net;
    else
        return NULL;

}


/**
 * @brief dap_chain_net_id_by_name
 * @param a_name
 * @return
 */
dap_chain_net_id_t dap_chain_net_id_by_name( const char * a_name)
{
    dap_chain_net_t *l_net = dap_chain_net_by_name( a_name );
    dap_chain_net_id_t l_ret = {0};
    if (l_net)
        l_ret.uint64 = l_net->pub.id.uint64;
    return l_ret;
}

/**
 * @brief dap_chain_net_get_chain_by_name
 * @param l_net
 * @param a_name
 * @return
 */
dap_chain_t * dap_chain_net_get_chain_by_name( dap_chain_net_t * l_net, const char * a_name)
{
   dap_chain_t * l_chain;
   DL_FOREACH(l_net->pub.chains, l_chain){
        if(dap_strcmp(l_chain->name,a_name) == 0)
            return  l_chain;
   }
   return NULL;
}

/**
 * @brief dap_chain_net_get_chain_by_chain_type
 * @param a_datum_type
 * @return
 */
dap_chain_t * dap_chain_net_get_chain_by_chain_type(dap_chain_net_t * l_net, dap_chain_type_t a_datum_type)
{
    dap_chain_t * l_chain;
    if(!l_net)
        return NULL;
    DL_FOREACH(l_net->pub.chains, l_chain)
    {
        for(uint16_t i = 0; i < l_chain->datum_types_count; i++) {
            if(l_chain->datum_types[i] == a_datum_type)
                return l_chain;
        }
    }
    return NULL;
}

/**
 * @brief dap_chain_net_get_gdb_group_mempool_by_chain_type
 * @param a_datum_type
 * @return
 */
char * dap_chain_net_get_gdb_group_mempool_by_chain_type(dap_chain_net_t * l_net, dap_chain_type_t a_datum_type)
{
    dap_chain_t * l_chain;
    if(!l_net)
        return NULL;
    DL_FOREACH(l_net->pub.chains, l_chain)
    {
        for(uint16_t i = 0; i < l_chain->datum_types_count; i++) {
            if(l_chain->datum_types[i] == a_datum_type)
                return dap_chain_net_get_gdb_group_mempool(l_chain);
        }
    }
    return NULL;
}


/**
 * @brief dap_chain_net_get_cur_addr
 * @param l_net
 * @return
 */
dap_chain_node_addr_t * dap_chain_net_get_cur_addr( dap_chain_net_t * l_net)
{
    return  PVT(l_net)->node_info ? &PVT(l_net)->node_info->hdr.address : PVT(l_net)->node_addr;
}

uint64_t dap_chain_net_get_cur_addr_int(dap_chain_net_t * l_net)
{
    return dap_chain_net_get_cur_addr(l_net) ? dap_chain_net_get_cur_addr(l_net)->uint64 :
                                               dap_db_get_cur_node_addr(l_net->pub.name);
}

dap_chain_cell_id_t * dap_chain_net_get_cur_cell( dap_chain_net_t * l_net)
{
    return  PVT(l_net)->node_info? &PVT(l_net)->node_info->hdr.cell_id: 0;
}


/**
 * Get nodes list (list of dap_chain_node_addr_t struct)
 */
dap_list_t* dap_chain_net_get_link_node_list(dap_chain_net_t * l_net, bool a_is_only_cur_cell)
{
    dap_list_t *l_node_list = NULL;
    // get cur node address
    dap_chain_node_addr_t l_cur_node_addr = { 0 };
    l_cur_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);

    dap_chain_node_info_t *l_cur_node_info = dap_chain_node_info_read(l_net, &l_cur_node_addr);
    // add links to nodes list only from the same cell
    if(l_cur_node_info) {
        for(unsigned int i = 0; i < l_cur_node_info->hdr.links_number; i++) {
            bool l_is_add = true;
            dap_chain_node_addr_t *l_remote_address = l_cur_node_info->links + i;
            if(a_is_only_cur_cell) {
                // get remote node list
                dap_chain_node_info_t *l_remote_node_info = dap_chain_node_info_read(l_net, l_remote_address);
                if(!l_remote_node_info || l_remote_node_info->hdr.cell_id.uint64 != l_cur_node_info->hdr.cell_id.uint64)
                    l_is_add = false;
                DAP_DELETE(l_remote_node_info);
            }
            if(l_is_add) {
                dap_chain_node_addr_t *l_address = DAP_NEW(dap_chain_node_addr_t);
                l_address->uint64 = l_cur_node_info->links[i].uint64;
                l_node_list = dap_list_append(l_node_list, l_address);
            }
        }

    }
    DAP_DELETE(l_cur_node_info);
    return l_node_list;
}

/**
 * Get remote nodes list (list of dap_chain_node_addr_t struct)
 */
dap_list_t* dap_chain_net_get_node_list(dap_chain_net_t * l_net)
{
    dap_list_t *l_node_list = NULL;
    /*
     dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
     // get nodes from seed_nodes
     for(uint16_t i = 0; i < l_net_pvt->seed_aliases_count; i++) {
     dap_chain_node_addr_t *l_node_address = dap_chain_node_alias_find(l_net, l_net_pvt->seed_aliases[i]);
     l_node_list = dap_list_append(l_node_list, l_node_address);
     }*/

    // get nodes list from global_db
    dap_global_db_obj_t *l_objs = NULL;
    size_t l_nodes_count = 0;
    // read all node
    l_objs = dap_chain_global_db_gr_load(l_net->pub.gdb_nodes, &l_nodes_count);
    if(!l_nodes_count || !l_objs)
        return l_node_list;
    for(size_t i = 0; i < l_nodes_count; i++) {
        dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t *) l_objs[i].value;
        dap_chain_node_addr_t *l_address = DAP_NEW(dap_chain_node_addr_t);
        l_address->uint64 = l_node_info->hdr.address.uint64;
        l_node_list = dap_list_append(l_node_list, l_address);
    }
    dap_chain_global_db_objs_delete(l_objs, l_nodes_count);
    return l_node_list;

        // get remote node list
        /*dap_chain_node_info_t *l_node_info = dap_chain_node_info_read(l_net, l_node_address);
        if(!l_node_info)
            continue;
        // start connect
        //debug inet_pton( AF_INET, "192.168.100.93", &l_node_info->hdr.ext_addr_v4);
        dap_chain_node_client_t *l_node_client = dap_chain_node_client_connect(l_node_info);
        //dap_chain_node_client_t *l_node_client = dap_chain_client_connect(l_node_info, l_stage_target, l_active_channels);
        if(!l_node_client) {
            DAP_DELETE(l_node_info);
            continue;
        }
        // wait connected
        int timeout_ms = 5000; //5 sec = 5000 ms
        int res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
        if(res) {
            // clean client struct
            dap_chain_node_client_close(l_node_client);
            DAP_DELETE(l_node_info);
            continue;
        }
        res = dap_chain_node_client_send_nodelist_req(l_node_client);
        if(res) {
            // clean client struct
            dap_chain_node_client_close(l_node_client);
            DAP_DELETE(l_node_info);
            continue;
        }
        res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_NODELIST_GOT, timeout_ms);
        if(res) {
            // clean client struct
            dap_chain_node_client_close(l_node_client);
            DAP_DELETE(l_node_info);
            continue;
        }
        DAP_DELETE(l_node_info);
        */
}

/**
 * @brief dap_chain_net_proc_datapool
 * @param a_net
 */
void dap_chain_net_proc_mempool (dap_chain_net_t * a_net)
{

    dap_string_t * l_str_tmp = dap_string_new(NULL);
    dap_chain_t *l_chain;
    DL_FOREACH(a_net->pub.chains, l_chain) {
        char *l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);

        size_t l_objs_size = 0;
        dap_global_db_obj_t * l_objs = dap_chain_global_db_gr_load(l_gdb_group_mempool, &l_objs_size);
        if(l_objs_size) {
            log_it(L_INFO, "%s.%s: Found %u records :", a_net->pub.name, l_chain->name,
                    l_objs_size);
            size_t l_datums_size = l_objs_size;
            dap_chain_datum_t ** l_datums = DAP_NEW_Z_SIZE(dap_chain_datum_t*,
                    sizeof(dap_chain_datum_t*) * l_datums_size);
            size_t l_objs_size_tmp = (l_objs_size > 15) ? min(l_objs_size, 10) : l_objs_size;
            for(size_t i = 0; i < l_objs_size; i++) {
                dap_chain_datum_t * l_datum = (dap_chain_datum_t*) l_objs[i].value;
                int l_verify_datum= dap_chain_net_verify_datum_for_add( a_net, l_datum) ;
                if (l_verify_datum != 0){
                    log_it(L_WARNING, "Datum doesn't pass verifications (code %d), delete such datum from pool",
                                             l_verify_datum);
                    dap_chain_global_db_gr_del(dap_strdup(l_objs[i].key), l_gdb_group_mempool);
                    l_datums[i] = NULL;
                }else{
                    l_datums[i] = l_datum;
                    if(i < l_objs_size_tmp) {
                        char buf[50];
                        time_t l_ts_create = (time_t) l_datum->header.ts_create;
                        log_it(L_INFO, "\t\t0x%s: type_id=%s ts_create=%s data_size=%u",
                                l_objs[i].key, c_datum_type_str[l_datum->header.type_id],
                                ctime_r(&l_ts_create, buf), l_datum->header.data_size);
                    }
                }
            }
            size_t l_objs_processed = l_chain->callback_datums_pool_proc(l_chain, l_datums, l_datums_size);
            // Delete processed objects
            size_t l_objs_processed_tmp = (l_objs_processed > 15) ? min(l_objs_processed, 10) : l_objs_processed;
            for(size_t i = 0; i < l_objs_processed; i++) {
                dap_chain_global_db_gr_del(dap_strdup(l_objs[i].key), l_gdb_group_mempool);
                if(i < l_objs_processed_tmp) {
                    dap_string_append_printf(l_str_tmp, "New event created, removed datum 0x%s from mempool \n",
                            l_objs[i].key);
                }
            }
            if(l_objs_processed < l_datums_size)
                log_it(L_WARNING, "%s.%s: %d records not processed", a_net->pub.name, l_chain->name,
                        l_datums_size - l_objs_processed);
            dap_chain_global_db_objs_delete(l_objs, l_objs_size);

            // Cleanup datums array
            if(l_datums){
                for(size_t i = 0; i < l_objs_size; i++) {
                    if (l_datums[i])
                        DAP_DELETE(l_datums[i]);
                }
                DAP_DEL_Z(l_datums);
            }
        }
        else {
            log_it(L_INFO, "%s.%s: No records in mempool", a_net->pub.name, l_chain ? l_chain->name : "[no chain]");
        }
        DAP_DELETE(l_gdb_group_mempool);

    }
}

/**
 * @brief dap_chain_net_tx_get_by_hash
 * @param a_net
 * @param a_tx_hash
 * @param a_search_type
 * @return
 */
dap_chain_datum_tx_t * dap_chain_net_get_tx_by_hash(dap_chain_net_t * a_net, dap_chain_hash_fast_t * a_tx_hash,
                                                     dap_chain_net_tx_search_type_t a_search_type)
{
    dap_ledger_t * l_ledger = dap_chain_ledger_by_net_name( a_net->pub.name );
    dap_chain_datum_tx_t * l_tx = NULL;

    switch (a_search_type) {
        case TX_SEARCH_TYPE_NET:
        case TX_SEARCH_TYPE_CELL:
        case TX_SEARCH_TYPE_LOCAL:{
            if ( ! l_tx ){
                // pass all chains
                for ( dap_chain_t * l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next){
                    if ( l_chain->callback_tx_find_by_hash ){
                        // try to find transaction in chain ( inside shard )
                        l_tx = l_chain->callback_tx_find_by_hash( l_chain, a_tx_hash );
                        if (l_tx)
                            break;
                    }
                }
            }
        }break;

        case TX_SEARCH_TYPE_NET_UNSPENT:
        case TX_SEARCH_TYPE_CELL_UNSPENT:{
            l_tx = dap_chain_ledger_tx_find_by_hash( l_ledger, a_tx_hash );
        }break;
    }
    return l_tx;
}

/**
 * @brief dap_chain_net_get_add_gdb_group
 * @param a_net
 * @param a_node_addr
 * @return
 */
dap_list_t * dap_chain_net_get_add_gdb_group(dap_chain_net_t * a_net, dap_chain_node_addr_t a_node_addr)
{
    dap_list_t *l_list_groups = NULL;
    if(!a_net || !PVT(a_net) || !PVT(a_net)->gdb_sync_nodes_addrs)
        return NULL;
    for(uint16_t i = 0; i < PVT(a_net)->gdb_sync_nodes_addrs_count; i++) {
        if(a_node_addr.uint64 == PVT(a_net)->gdb_sync_nodes_addrs[i].uint64) {
            for(uint16_t j = 0; j < PVT(a_net)->gdb_sync_groups_count; j++)
                l_list_groups = dap_list_append(l_list_groups, PVT(a_net)->gdb_sync_groups[j]);
        }
    }
    return l_list_groups;
}

/**
 * @brief dap_chain_net_verify_datum_for_add
 * @param a_net
 * @param a_datum
 * @return
 */
int dap_chain_net_verify_datum_for_add(dap_chain_net_t *a_net, dap_chain_datum_t * a_datum )
{
    if( ! a_datum)
        return -10;
    if( ! a_net )
        return -11;

    switch ( a_datum->header.type_id) {
        case DAP_CHAIN_DATUM_TX: return dap_chain_ledger_tx_add_check( a_net->pub.ledger,
                                                                   (dap_chain_datum_tx_t*) a_datum->data );
        case DAP_CHAIN_DATUM_TOKEN_DECL: return dap_chain_ledger_token_decl_add_check( a_net->pub.ledger,
                                                                   (dap_chain_datum_token_t*) a_datum->data );
        case DAP_CHAIN_DATUM_TOKEN_EMISSION : return dap_chain_ledger_token_emission_add_check( a_net->pub.ledger,
                                                                   (dap_chain_datum_token_emission_t*) a_datum->data, a_datum->header.data_size );
        default: return 0;
    }
}

/**
 * @brief dap_chain_net_dump_datum
 * @param a_str_out
 * @param a_datum
 */
void dap_chain_net_dump_datum(dap_string_t * a_str_out, dap_chain_datum_t * a_datum)
{
    if( a_datum == NULL){
        dap_string_append_printf(a_str_out,"==Datum is NULL\n");
        return;
    }
    switch (a_datum->header.type_id){
        case DAP_CHAIN_DATUM_TOKEN_DECL:{
            dap_chain_datum_token_t * l_token = (dap_chain_datum_token_t*) a_datum->data;
            size_t l_token_size = a_datum->header.data_size;
            if(l_token_size < sizeof(dap_chain_datum_token_t)){
                dap_string_append_printf(a_str_out,"==Datum has incorrect size. Only %lu, while at least %lu is expected\n",
                                         l_token_size, sizeof(dap_chain_datum_token_t));
                return;
            }
            dap_string_append_printf(a_str_out,"==Datum Token Declaration\n");
            dap_string_append_printf(a_str_out, "ticker: %s\n", l_token->ticker);
            dap_string_append_printf(a_str_out, "size: %zd\n", l_token_size);
            switch (l_token->type) {
                case DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE:{
                    dap_string_append_printf(a_str_out, "type: SIMPLE\n");
                    dap_string_append_printf(a_str_out, "sign_total: %u\n", l_token->header_private.signs_total );
                    dap_string_append_printf(a_str_out, "sign_valid: %u\n", l_token->header_private.signs_valid );
                    dap_string_append_printf(a_str_out, "total_supply: %u\n", l_token->header_private.total_supply );
                }break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE:{
                    dap_string_append_printf(a_str_out,"type: PRIVATE_UPDATE\n");
                    dap_chain_datum_token_tsd_t * l_tsd = dap_chain_datum_token_tsd_get(l_token, l_token_size);
                    if (l_tsd == NULL)
                        dap_string_append_printf(a_str_out,"<CORRUPTED TSD SECTION>\n");
                    else{
                        size_t l_offset = 0;
                        size_t l_offset_max = l_token->header_private_decl.tsd_total_size;
                        while( l_offset< l_offset_max){
                            if ( (l_tsd->size+l_offset) >l_offset_max){
                                log_it(L_WARNING, "<CORRUPTED TSD> too big size %zd when left maximum %zd",
                                       l_tsd->size, l_offset_max - l_offset);
                                return;
                            }
                            switch( l_tsd->type){
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS:
                                    dap_string_append_printf(a_str_out,"flags_set: ");
                                    dap_chain_datum_token_flags_dump(a_str_out,
                                                                     dap_chain_datum_token_tsd_get_scalar(l_tsd, uint16_t));
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS:
                                    dap_string_append_printf(a_str_out,"flags_unset: ");
                                    dap_chain_datum_token_flags_dump(a_str_out,
                                                                     dap_chain_datum_token_tsd_get_scalar(l_tsd, uint16_t));
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY:
                                    dap_string_append_printf(a_str_out,"total_supply: %u\n",
                                                             dap_chain_datum_token_tsd_get_scalar(l_tsd, uint128_t) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID :
                                    dap_string_append_printf(a_str_out,"total_signs_valid: %u\n",
                                                             dap_chain_datum_token_tsd_get_scalar(l_tsd, uint16_t) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_ADD :
                                    if(l_tsd->size == sizeof(dap_chain_hash_fast_t) ){
                                        char *l_hash_str = dap_chain_hash_fast_to_str_new(
                                                    (dap_chain_hash_fast_t*) l_tsd->data );
                                        dap_string_append_printf(a_str_out,"total_signs_add: %s\n", l_hash_str );
                                        DAP_DELETE( l_hash_str );
                                    }else
                                        dap_string_append_printf(a_str_out,"total_signs_add: <WRONG SIZE %zd>\n", l_tsd->size);
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_REMOVE :
                                    if(l_tsd->size == sizeof(dap_chain_hash_fast_t) ){
                                        char *l_hash_str = dap_chain_hash_fast_to_str_new(
                                                    (dap_chain_hash_fast_t*) l_tsd->data );
                                        dap_string_append_printf(a_str_out,"total_signs_remove: %s\n", l_hash_str );
                                        DAP_DELETE( l_hash_str );
                                    }else
                                        dap_string_append_printf(a_str_out,"total_signs_add: <WRONG SIZE %zd>\n", l_tsd->size);
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD  :
                                    dap_string_append_printf(a_str_out,"datum_type_allowed_add: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_REMOVE  :
                                    dap_string_append_printf(a_str_out,"datum_type_allowed_remove: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD  :
                                    dap_string_append_printf(a_str_out,"datum_type_blocked_add: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_REMOVE:
                                    dap_string_append_printf(a_str_out,"datum_type_blocked_remove: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD:
                                    dap_string_append_printf(a_str_out,"tx_sender_allowed_add: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE:
                                    dap_string_append_printf(a_str_out,"tx_sender_allowed_remove: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD:
                                    dap_string_append_printf(a_str_out,"tx_sender_blocked_add: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE:
                                    dap_string_append_printf(a_str_out,"tx_sender_blocked_remove: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:
                                    dap_string_append_printf(a_str_out,"tx_receiver_allowed_add: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE:
                                    dap_string_append_printf(a_str_out,"tx_receiver_allowed: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD:
                                    dap_string_append_printf(a_str_out, "tx_receiver_blocked_add: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE:
                                    dap_string_append_printf(a_str_out, "tx_receiver_blocked_remove: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                default: dap_string_append_printf(a_str_out, "<0x%04X>: <size %zd>\n", l_tsd->type, l_tsd->size);
                            }
                            l_offset += dap_chain_datum_token_tsd_size(l_tsd);

                        }
                    }
                }break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL:{
                    dap_string_append_printf(a_str_out,"type: PRIVATE_DECL\n");
                    dap_string_append_printf(a_str_out,"flags: ");
                    dap_chain_datum_token_flags_dump(a_str_out, l_token->header_private_decl.flags);
                    dap_chain_datum_token_tsd_t * l_tsd_first = dap_chain_datum_token_tsd_get(l_token, l_token_size);
                    if (l_tsd_first == NULL)
                        dap_string_append_printf(a_str_out,"<CORRUPTED TSD SECTION>\n");
                    else{
                        size_t l_offset = 0;
                        size_t l_offset_max = l_token->header_private_decl.tsd_total_size;
                        while( l_offset< l_offset_max){
                            dap_chain_datum_token_tsd_t * l_tsd = (void*)l_tsd_first + l_offset;
                            if ( (l_tsd->size+l_offset) >l_offset_max){
                                log_it(L_WARNING, "<CORRUPTED TSD> too big size %zd when left maximum %zd",
                                       l_tsd->size, l_offset_max - l_offset);
                                return;
                            }
                            switch( l_tsd->type){
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY:
                                    dap_string_append_printf(a_str_out,"total_supply: %lu\n",
                                                             dap_chain_datum_token_tsd_get_scalar(l_tsd, uint128_t) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID :
                                    dap_string_append_printf(a_str_out,"total_signs_valid: %u\n",
                                                             dap_chain_datum_token_tsd_get_scalar(l_tsd, uint16_t) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD  :
                                    dap_string_append_printf(a_str_out,"datum_type_allowed: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD  :
                                    dap_string_append_printf(a_str_out,"datum_type_blocked: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD:
                                    dap_string_append_printf(a_str_out,"tx_sender_allowed: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD:
                                    dap_string_append_printf(a_str_out,"tx_sender_blocked: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:
                                    dap_string_append_printf(a_str_out,"tx_receiver_allowed: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD:
                                    dap_string_append_printf(a_str_out, "tx_receiver_blocked: %s\n",
                                                             dap_chain_datum_token_tsd_get_string_const(l_tsd) );
                                break;
                                default: dap_string_append_printf(a_str_out, "<0x%04X>: <size %zd>\n", l_tsd->type, l_tsd->size);
                            }
                            l_offset += dap_chain_datum_token_tsd_size(l_tsd);

                        }
                    }

                    size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_private_decl.tsd_total_size;
                    dap_chain_datum_token_certs_dump(a_str_out, l_token->data_n_tsd, l_certs_field_size);
                }break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PUBLIC:{
                    dap_string_append_printf(a_str_out,"type: PUBLIC\n");
                }break;
                default:
                    dap_string_append_printf(a_str_out,"type: UNKNOWN\n");
            }

        }break;
    }
}
