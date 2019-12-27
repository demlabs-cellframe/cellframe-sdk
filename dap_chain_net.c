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
#include "dap_chain_net.h"
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
    pthread_mutex_t state_mutex;
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

    uint8_t padding3[6];
    uint16_t seed_aliases_count;

    dap_chain_net_state_t state;
    //dap_chain_net_state_t state_prev;
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
static int s_cli_net(int argc, char ** argv, char **str_reply);

static bool s_seed_mode = false;


/**
 * @brief s_net_set_go_sync
 * @param a_net
 * @return
 */
void s_net_set_go_sync(dap_chain_net_t * a_net)
{
    if(a_net)
        PVT(a_net)->flags |= F_DAP_CHAIN_NET_GO_SYNC;
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
    pthread_mutex_lock( &PVT(a_net)->state_mutex);
    if (PVT(a_net)->state_target == a_new_state){
        log_it(L_WARNING,"Already going to state %s",s_net_state_to_str(a_new_state));
    }
    PVT(a_net)->state_target = a_new_state;
#ifndef _WIN32
    pthread_cond_signal( &PVT(a_net)->state_proc_cond );
#else
    SetEvent( PVT(a_net)->state_proc_cond );
#endif    
    pthread_mutex_unlock( &PVT(a_net)->state_mutex);
    return 0;
}

/**
 * @brief s_gbd_history_callback_notify
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

    if (a_arg) {
        dap_chain_net_t * l_net = (dap_chain_net_t *) a_arg;
        if (!PVT (l_net)->load_mode ){
            if( pthread_mutex_trylock( &PVT (l_net)->state_mutex) == 0 ){
                if ( PVT(l_net)->state == NET_STATE_ONLINE || PVT(l_net)->state == NET_STATE_ONLINE  )
                    dap_chain_net_sync_all(l_net);
                pthread_mutex_unlock( &PVT (l_net)->state_mutex);
            }
        }
    }
}



/**
 * @brief s_net_states_proc
 * @param l_net
 */
static int s_net_states_proc(dap_chain_net_t * l_net)
{
    dap_chain_net_pvt_t *pvt_debug = PVT(l_net);
    int ret=0;
lb_proc_state:
    pthread_mutex_lock(&PVT(l_net)->state_mutex );
    switch ( PVT(l_net)->state ){
        case NET_STATE_OFFLINE:{
            //log_it(L_DEBUG,"%s.state: NET_STATE_OFFLINE",l_net->pub.name);
            // reset current link
            PVT(l_net)->links_count = 0;
            // delete all links
            dap_chain_node_client_t * l_node_client = NULL, *l_node_client_tmp = NULL;
            HASH_ITER(hh,PVT(l_net)->links,l_node_client,l_node_client_tmp){
                HASH_DEL(PVT(l_net)->links, l_node_client);
                dap_chain_node_client_close(l_node_client);
            }
            PVT(l_net)->links_addrs_count = 0;
            if ( PVT(l_net)->links_addrs )
                DAP_DELETE(PVT(l_net)->links_addrs);
            PVT(l_net)->links_addrs = NULL;

            if ( PVT(l_net)->state_target != NET_STATE_OFFLINE ){
                PVT(l_net)->state = NET_STATE_LINKS_PREPARE;
                pthread_mutex_unlock(&PVT(l_net)->state_mutex );
                goto lb_proc_state;
            }
        } break;
        case NET_STATE_LINKS_PREPARE:{
            log_it(L_NOTICE,"%s.state: NET_STATE_LINKS_PREPARE",l_net->pub.name);
            switch (PVT(l_net)->node_role.enums) {
                case NODE_ROLE_ROOT:
                case NODE_ROLE_ROOT_MASTER:
                case NODE_ROLE_ARCHIVE:
                case NODE_ROLE_CELL_MASTER:{
                    // This roles load predefined links from global_db
                    if ( PVT(l_net)->node_info ) {
                        if (PVT(l_net)->links_addrs )
                            DAP_DELETE(PVT(l_net)->links_addrs);
                        PVT(l_net)->links_addrs_count = PVT(l_net)->node_info->hdr.links_number;
                        PVT(l_net)->links_addrs = DAP_NEW_Z_SIZE( dap_chain_node_addr_t,
                                                                  PVT(l_net)->links_addrs_count);
                        for (size_t i =0 ; i < PVT(l_net)->node_info->hdr.links_number; i++ ){
                            PVT(l_net)->links_addrs[i].uint64 = PVT(l_net)->node_info->links[i].uint64;
                        }
                    }else {
                        log_it(L_WARNING,"No nodeinfo in global_db to prepare links for connecting, find nearest 3 links and fill global_db");
                    }

                    // add other root nodes for connect
                    //if(!PVT(l_net)->links_addrs_count)
                    {
                        // use no more then 4 root node
                        int l_use_root_nodes = min(4, PVT(l_net)->seed_aliases_count);
                        if(!PVT(l_net)->links_addrs_count) {
                            PVT(l_net)->links_addrs = DAP_NEW_Z_SIZE(dap_chain_node_addr_t,
                                    l_use_root_nodes * sizeof(dap_chain_node_addr_t));
                        }
                        else{
                            PVT(l_net)->links_addrs = DAP_REALLOC(PVT(l_net)->links_addrs,
                                    (PVT(l_net)->links_addrs_count+l_use_root_nodes) * sizeof(dap_chain_node_addr_t));
                            memset(PVT(l_net)->links_addrs + PVT(l_net)->links_addrs_count, 0,
                                    l_use_root_nodes * sizeof(dap_chain_node_addr_t));
                        }

                        for(uint16_t i = 0; i < l_use_root_nodes; i++) {
                            dap_chain_node_addr_t * l_node_addr = dap_chain_node_alias_find(l_net, PVT(l_net)->seed_aliases[i]);
                            if(l_node_addr) {
                                PVT(l_net)->links_addrs[PVT(l_net)->links_addrs_count].uint64 = l_node_addr->uint64;
                                PVT(l_net)->links_addrs_count++;
                            }
                        }
                    }
                    // shuffle the order of the nodes
                    for(size_t i = 0; i < PVT(l_net)->links_addrs_count; i++) {
                        unsigned int l_new_node_pos = rand() % (PVT(l_net)->links_addrs_count);
                        if(i == l_new_node_pos)
                            continue;
                        uint64_t l_tmp_uint64 = PVT(l_net)->links_addrs[i].uint64;
                        PVT(l_net)->links_addrs[i].uint64 = PVT(l_net)->links_addrs[l_new_node_pos].uint64;
                        PVT(l_net)->links_addrs[l_new_node_pos].uint64 = l_tmp_uint64;
                    }


                } break;
                case NODE_ROLE_FULL:
                case NODE_ROLE_MASTER:
                case NODE_ROLE_LIGHT:{
                    // If we haven't any assigned shard - connect to root-0
                if(l_net->pub.cell_id.uint64 == 0) {

                    dap_chain_net_pvt_t *pvt_debug = PVT(l_net);
                    // get current node address
                    dap_chain_node_addr_t l_address;
                    l_address.uint64 = dap_chain_net_get_cur_addr(l_net) ?
                                         dap_chain_net_get_cur_addr(l_net)->uint64 :
                                         dap_db_get_cur_node_addr(l_net->pub.name);

                    // get current node info
                    dap_chain_node_info_t *l_cur_node_info = dap_chain_node_info_read(l_net, &l_address);

                    if ( l_cur_node_info ) {
                        uint16_t l_links_addrs_count = l_cur_node_info->hdr.links_number + PVT(l_net)->seed_aliases_count;
                        PVT(l_net)->links_addrs = DAP_NEW_Z_SIZE(dap_chain_node_addr_t,
                                l_links_addrs_count * sizeof(dap_chain_node_addr_t));

                        // add linked nodes for connect
                        for(uint16_t i = 0; i < min(1, l_cur_node_info->hdr.links_number); i++) {
                            dap_chain_node_addr_t *l_addr = l_cur_node_info->links + i;
                            dap_chain_node_info_t *l_remore_node_info = dap_chain_node_info_read(l_net, l_addr);
                            // if only nodes from the same cell
                            if(l_cur_node_info->hdr.cell_id.uint64 == l_remore_node_info->hdr.cell_id.uint64) {
                                PVT(l_net)->links_addrs[PVT(l_net)->links_addrs_count].uint64 =
                                        l_remore_node_info->hdr.address.uint64;
                                PVT(l_net)->links_addrs_count++;
                            }
                            DAP_DELETE(l_remore_node_info);
                        }
                    }
                    // add root nodes for connect
                    if(!PVT(l_net)->links_addrs_count){
                        // use no more then 4 root node
                        int l_use_root_nodes = min(4, PVT(l_net)->seed_aliases_count);
                        PVT(l_net)->links_addrs = DAP_NEW_Z_SIZE(dap_chain_node_addr_t,
                                l_use_root_nodes * sizeof(dap_chain_node_addr_t));

                        for(uint16_t i = 0; i < l_use_root_nodes; i++) {
                            dap_chain_node_addr_t * l_node_addr = dap_chain_node_alias_find(l_net, PVT(l_net)->seed_aliases[i]);
                            if(l_node_addr) {
                                PVT(l_net)->links_addrs[PVT(l_net)->links_addrs_count].uint64 = l_node_addr->uint64;
                                PVT(l_net)->links_addrs_count++;
                            }
                        }
                    }
                    // shuffle the order of the nodes
                    for(size_t i = 0; i < PVT(l_net)->links_addrs_count; i++) {
                        unsigned int l_new_node_pos = rand() % (PVT(l_net)->links_addrs_count);
                        if(i==l_new_node_pos)
                            continue;
                        uint64_t l_tmp_uint64 = PVT(l_net)->links_addrs[i].uint64;
                        PVT(l_net)->links_addrs[i].uint64 = PVT(l_net)->links_addrs[l_new_node_pos].uint64;
                        PVT(l_net)->links_addrs[l_new_node_pos].uint64 = l_tmp_uint64;
                    }
                    DAP_DELETE(l_cur_node_info);
                }else {
                        // TODO read cell's nodelist and populate array with it
                    }
                } break;
            }
            if ( PVT(l_net)->state_target != NET_STATE_LINKS_PREPARE ){
                if ( PVT(l_net)->links_addrs_count>0 ) { // If links are present
                    PVT(l_net)->state = NET_STATE_LINKS_CONNECTING;
                    log_it(L_DEBUG,"Prepared %u links, start to establish them", PVT(l_net)->links_addrs_count );
                } else {
                    log_it(L_WARNING,"No links for connecting, return back to OFFLINE state");
                    PVT(l_net)->state = NET_STATE_OFFLINE;
                    // remove looping
                    PVT(l_net)->state_target = NET_STATE_OFFLINE;
                }
            }else {
                log_it(L_WARNING,"Target state is NET_STATE_LINKS_PREPARE? Realy?");
                PVT(l_net)->state = NET_STATE_OFFLINE;
            }
        } pthread_mutex_unlock(&PVT(l_net)->state_mutex ); goto lb_proc_state;
        case NET_STATE_LINKS_CONNECTING:{
            log_it(L_NOTICE,"%s.state: NET_STATE_LINKS_CONNECTING",l_net->pub.name);
            //size_t l_links_established = 0;
            for(size_t j = PVT(l_net)->links_count; j < PVT(l_net)->links_addrs_count; j++) {
                //size_t j =
                log_it(L_INFO,"Establishing connection with " NODE_ADDR_FP_STR,
                       NODE_ADDR_FP_ARGS_S( PVT(l_net)->links_addrs[j]) );
                dap_chain_node_info_t *l_link_node_info = dap_chain_node_info_read(l_net, &PVT(l_net)->links_addrs[j] );
                if ( l_link_node_info ) {
                    dap_chain_node_client_t *l_node_client = dap_chain_node_client_connect(l_link_node_info );
                    if(!l_node_client) {
                        DAP_DELETE(l_link_node_info);
                        ret = -1;
                        break;
                    }
                    // wait connected
                    int timeout_ms = 5000; //5 sec = 5000 ms
                    int res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
                    if (res == 0 ){
                        log_it(L_NOTICE, "Connected link %u",j);
                        HASH_ADD(hh, PVT(l_net)->links, remote_node_addr, sizeof(l_node_client->remote_node_addr), l_node_client);
                        PVT(l_net)->links_count++;
                        if(PVT(l_net)->links_count >= s_required_links_count || (PVT(l_net)->links_count + 1) >= s_max_links_count)
                            break;
                    }else {
                        log_it(L_NOTICE, "Cant establish link %u",j);
                        dap_chain_node_client_close(l_node_client);
                    }
                }
            }
            if (PVT(l_net)->links_count >0 ){
                log_it(L_NOTICE, "Established %u links",PVT(l_net)->links_count);
                PVT(l_net)->state = NET_STATE_LINKS_ESTABLISHED;
            }else {
                log_it(L_NOTICE, "Can't establish links, go to offline");
                PVT(l_net)->state = NET_STATE_OFFLINE ;
                PVT(l_net)->state_target = NET_STATE_OFFLINE ;
            }
        } pthread_mutex_unlock(&PVT(l_net)->state_mutex ); goto lb_proc_state;

        case NET_STATE_LINKS_ESTABLISHED:{
            log_it(L_NOTICE,"%s.state: NET_STATE_LINKS_ESTABLISHED",l_net->pub.name);
            switch (PVT(l_net)->state_target) {
                case NET_STATE_ONLINE:{ // Online
                    switch ( PVT(l_net)->node_role.enums ){
                        case NODE_ROLE_ROOT_MASTER:
                        case NODE_ROLE_ROOT:{
                            dap_chain_node_client_t * l_node_client = NULL, *l_node_client_tmp = NULL;

                            // Send everybody your address when linked
                            HASH_ITER(hh,PVT(l_net)->links,l_node_client,l_node_client_tmp){
                                dap_stream_ch_chain_net_pkt_write(dap_client_get_stream_ch(
                                                  l_node_client->client, dap_stream_ch_chain_net_get_id()),
                                                   DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR, l_net->pub.id,
                                                   dap_chain_net_get_cur_addr(l_net),
                                                   sizeof (dap_chain_node_addr_t) );
                            }
                            PVT(l_net)->state = NET_STATE_SYNC_GDB;
                        }break;
                        case NODE_ROLE_CELL_MASTER:
                        case NODE_ROLE_MASTER:{
                            PVT(l_net)->state = NET_STATE_ADDR_REQUEST;
                        } break;
                       default:{
                        // get addr for current node if it absent
                        if(!dap_chain_net_get_cur_addr_int(l_net))
                            PVT(l_net)->state = NET_STATE_ADDR_REQUEST;
                        else
                            PVT( l_net)->state = NET_STATE_SYNC_GDB;
                       }
                    }
                }pthread_mutex_unlock(&PVT(l_net)->state_mutex ); goto lb_proc_state;
                case NET_STATE_SYNC_GDB: // we need only to sync gdb
                    PVT(l_net)->state = NET_STATE_SYNC_GDB ;
                    if ( PVT(l_net)->addr_request_attempts >=10 && PVT(l_net)->state == NET_STATE_ADDR_REQUEST){
                        PVT(l_net)->addr_request_attempts = 0;
                        switch( PVT(l_net)->state_target){
                            case NET_STATE_ONLINE:
                            case NET_STATE_SYNC_GDB:
                                PVT(l_net)->state = NET_STATE_SYNC_GDB;
                            pthread_mutex_unlock(&PVT(l_net)->state_mutex );
                            goto lb_proc_state;
                            case NET_STATE_SYNC_CHAINS:
                                PVT(l_net)->state = NET_STATE_SYNC_CHAINS;
                            pthread_mutex_unlock(&PVT(l_net)->state_mutex );
                            goto lb_proc_state;
                            default: {
                                PVT(l_net)->state = NET_STATE_OFFLINE;
                                PVT(l_net)->state_target = NET_STATE_OFFLINE;
                            }
                        }
                    }
                pthread_mutex_unlock(&PVT(l_net)->state_mutex ); goto lb_proc_state;
                case NET_STATE_SYNC_CHAINS:
                    PVT(l_net)->state = (PVT(l_net)->node_info && PVT(l_net)->node_info->hdr.address.uint64)?
                                NET_STATE_SYNC_CHAINS : NET_STATE_ADDR_REQUEST;
                pthread_mutex_unlock(&PVT(l_net)->state_mutex ); goto lb_proc_state;
                case NET_STATE_ADDR_REQUEST :
                    PVT(l_net)->state = NET_STATE_ADDR_REQUEST;
                pthread_mutex_unlock(&PVT(l_net)->state_mutex ); goto lb_proc_state;
                default:{}
            }
        }break;
        // get addr for remote node
        case NET_STATE_ADDR_REQUEST:{
            int l_is_addr_leased = 0;
            dap_chain_node_client_t * l_node_client = NULL, *l_node_client_tmp = NULL;

            HASH_ITER(hh,PVT(l_net)->links,l_node_client,l_node_client_tmp){
                uint8_t l_ch_id = dap_stream_ch_chain_net_get_id(); // Channel id for chain net request
                dap_stream_ch_t * l_ch_chain = dap_client_get_stream_ch(l_node_client->client, l_ch_id);
                // set callback for l_ch_id
                dap_chain_node_client_set_callbacks( l_node_client->client, l_ch_id);
                // send request for new address
                size_t res = dap_stream_ch_chain_net_pkt_write(l_ch_chain,
                        DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE_REQUEST,
                        //DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_REQUEST,
                        l_net->pub.id, NULL, 0);
                if(res == 0) {
                    log_it(L_WARNING,"Can't send NODE_ADDR_REQUEST packet");
                    HASH_DEL(PVT(l_net)->links,l_node_client);
                    dap_chain_node_client_close(l_node_client);
                    continue; // try with another link
                }

                // wait for finishing of request
                int timeout_ms = 5000; // 5 sec = 5 000 ms
                // TODO add progress info to console
                PVT(l_net)->addr_request_attempts++;
                int l_res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_NODE_ADDR_LEASED, timeout_ms);
                switch (l_res) {
                    case -1:
                        log_it(L_WARNING,"Timeout with addr leasing");
                        // try again 3 times
                        if(PVT(l_net)->addr_request_attempts < 3) {
                            pthread_mutex_unlock(&PVT(l_net)->state_mutex);
                            goto lb_proc_state;
                        }
                    continue; // try with another link
                    case 0:
                        log_it(L_INFO, "Node address leased");
                        l_is_addr_leased++;
                        //PVT(l_net)->state = NET_STATE_SYNC_GDB;
                        //pthread_mutex_unlock(&PVT(l_net)->state_mutex ); goto lb_proc_state;
                        break;
                    default:
                        if ( l_node_client->last_error[0] ){
                            log_it(L_INFO, "Node address request error %d: \"%s\"",l_res, l_node_client->last_error );
                            l_node_client->last_error[0]='\0';
                        }
                        log_it(L_INFO, "Node address request error %d",l_res);
                    continue;
                }
            }
            if(l_is_addr_leased > 0) {
                PVT(l_net)->state = NET_STATE_SYNC_GDB;
                pthread_mutex_unlock(&PVT(l_net)->state_mutex);
                goto lb_proc_state;
            }
            else{
                log_it(L_WARNING,"Haven't received address from any links, return back to LINKS_ESTABLISHED");
                PVT(l_net)->state = NET_STATE_LINKS_ESTABLISHED;
                pthread_mutex_unlock(&PVT(l_net)->state_mutex );goto lb_proc_state; // One address assigned its enought for now
            }

        }
        break;
        case NET_STATE_SYNC_GDB:{
            // send request
            dap_chain_node_client_t * l_node_client = NULL, *l_node_client_tmp = NULL;
            HASH_ITER(hh,PVT(l_net)->links,l_node_client,l_node_client_tmp){
            dap_stream_ch_chain_sync_request_t l_sync_gdb = { { 0 } };
                // Get last timestamp in log
                l_sync_gdb.id_start = (uint64_t) dap_db_log_get_last_id_remote(l_node_client->remote_node_addr.uint64);
                // no limit
                l_sync_gdb.id_end = (uint64_t)0;

                l_sync_gdb.node_addr.uint64 = dap_chain_net_get_cur_addr(l_net) ?
                                                  dap_chain_net_get_cur_addr(l_net)->uint64 :
                                                  dap_db_get_cur_node_addr(l_net->pub.name);

                dap_chain_id_t l_chain_id_null = { { 0 } };
                dap_chain_cell_id_t l_chain_cell_id_null = { { 0 } };
                l_chain_id_null.uint64 = l_net->pub.id.uint64;
                l_chain_cell_id_null.uint64 = dap_chain_net_get_cur_cell(l_net) ? dap_chain_net_get_cur_cell(l_net)->uint64 : 0;

                log_it(L_DEBUG,"Prepared request to gdb sync from %llu to %llu",l_sync_gdb.id_start,l_sync_gdb.id_end);
                // find dap_chain_id_t
                dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, "gdb");
                dap_chain_id_t l_chain_id = l_chain ? l_chain->id : (dap_chain_id_t ) { { 0 } };

                size_t l_res = dap_stream_ch_chain_pkt_write(dap_client_get_stream_ch(l_node_client->client, dap_stream_ch_chain_get_id()),
                                                            DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB, l_net->pub.id, l_chain_id,
                                                            l_net->pub.cell_id, &l_sync_gdb, sizeof(l_sync_gdb));
                if(l_res == 0) {
                    log_it(L_WARNING,"Can't send GDB sync request");
                    HASH_DEL(PVT(l_net)->links,l_node_client);
                    dap_chain_node_client_close(l_node_client);
                    PVT(l_net)->state = NET_STATE_OFFLINE;
                    continue;
                }

                // wait for finishing of request
                int timeout_ms = 50000; // 2 min = 120 sec = 120 000 ms
                // TODO add progress info to console
                int res = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_SYNCED, timeout_ms);
                switch (res) {
                case -1:
                    log_it(L_WARNING,"Timeout with link sync");
                    break;
                case 0:
                    log_it(L_INFO, "Node sync completed");
                    break;
                default:
                    log_it(L_INFO, "Node sync error %d",res);
                }
            }
            if(PVT(l_net)->state_target >= NET_STATE_ONLINE){
                PVT(l_net)->state = NET_STATE_SYNC_CHAINS;
            }else {
                PVT(l_net)->state = NET_STATE_ONLINE;
            }
        }
            pthread_mutex_unlock(&PVT(l_net)->state_mutex);
            goto lb_proc_state;

        case NET_STATE_SYNC_CHAINS:{
            dap_chain_node_client_t * l_node_client = NULL, *l_node_client_tmp = NULL;
            uint8_t l_ch_id = dap_stream_ch_chain_get_id(); // Channel id for global_db and chains sync

            HASH_ITER(hh,PVT(l_net)->links,l_node_client,l_node_client_tmp){
                dap_stream_ch_t * l_ch_chain = dap_client_get_stream_ch(l_node_client->client, l_ch_id);
                if(!l_ch_chain){
                    log_it(L_DEBUG,"Can't get stream_ch for id='%c' ", l_ch_id);
                    continue;
                }
                dap_chain_t * l_chain = NULL;
                DL_FOREACH(l_net->pub.chains, l_chain ){
                    //size_t l_lasts_size = 0;
                    //dap_chain_atom_ptr_t * l_lasts;
                    //dap_chain_atom_iter_t * l_atom_iter = l_chain->callback_atom_iter_create(l_chain);
                    //l_lasts = l_chain->callback_atom_iter_get_lasts(l_atom_iter, &l_lasts_size);
                    //if( l_lasts ) {
                        l_node_client->state = NODE_CLIENT_STATE_CONNECTED;
                        dap_stream_ch_chain_sync_request_t l_request = { { 0 } };
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
                            log_it(L_INFO, "sync of chain '%s' completed ", l_chain->name);
                            // set time of last sync
                            {
                                struct timespec l_to;
                                clock_gettime( CLOCK_MONOTONIC, &l_to);
                                PVT(l_net)->last_sync = l_to.tv_sec;
                            }
                            break;
                        default:
                            log_it(L_INFO, "sync of chain '%s' error %d", l_chain->name,l_res);
                        }

                        //DAP_DELETE( l_lasts );
                    //}
                    //DAP_DELETE( l_atom_iter );
                }

            }
            PVT(l_net)->state = NET_STATE_ONLINE;
            // end sync, return to online state
            if(PVT(l_net)->state_target > NET_STATE_ONLINE)
                PVT(l_net)->state_target = NET_STATE_ONLINE;
        }
        pthread_mutex_unlock(&PVT(l_net)->state_mutex);
        goto lb_proc_state;

        case NET_STATE_ONLINE: {
            //log_it(L_NOTICE, "State online");
            switch ( PVT(l_net)->state_target) {
            // disconnect
            case NET_STATE_OFFLINE:
                PVT(l_net)->state = NET_STATE_OFFLINE;
                log_it(L_NOTICE, "Going to disconnet");
                pthread_mutex_unlock(&PVT(l_net)->state_mutex);
                goto lb_proc_state;
            case NET_STATE_ONLINE:
                // if flag set then go to SYNC_GDB
                if(PVT(l_net)->flags & F_DAP_CHAIN_NET_GO_SYNC)
                    PVT(l_net)->flags &= ~F_DAP_CHAIN_NET_GO_SYNC;
                else
                    break;
                // sync
            case NET_STATE_SYNC_GDB:
                PVT(l_net)->state = NET_STATE_SYNC_GDB;
                pthread_mutex_unlock(&PVT(l_net)->state_mutex);
                goto lb_proc_state;
                    PVT(l_net)->state = NET_STATE_SYNC_GDB;
                    pthread_mutex_unlock(&PVT(l_net)->state_mutex);
                    goto lb_proc_state;
            }
        }
            break;
        default: log_it (L_DEBUG, "Unprocessed state");
    }
    pthread_mutex_unlock(&PVT(l_net)->state_mutex );
    return ret;
}

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

    const uint64_t l_timeout_ms = 20000;// 20 sec

    while( !(p_net->flags & F_DAP_CHAIN_NET_SHUTDOWN) ) {

        s_net_states_proc( l_net );
    #ifndef _WIN32
        pthread_mutex_lock( &p_net->state_mutex );

        // prepare for signal waiting

        struct timespec l_to;

        clock_gettime( CLOCK_MONOTONIC, &l_to );
        int64_t l_nsec_new = l_to.tv_nsec + l_timeout_ms * 1000000ll;

        // if the new number of nanoseconds is more than a second
        if(l_nsec_new > (long) 1e9) {
            l_to.tv_sec += l_nsec_new / (long) 1e9;
            l_to.tv_nsec = l_nsec_new % (long) 1e9;
        }
        else
            l_to.tv_nsec = (long) l_nsec_new;

        // signal waiting
        pthread_cond_timedwait( &p_net->state_proc_cond, &p_net->state_mutex, &l_to );

        // checking whether new sync is needed
        time_t l_sync_timeout = 300;// 300 sec = 5 min
        clock_gettime( CLOCK_MONOTONIC, &l_to );
        if(l_to.tv_sec >= p_net->last_sync + l_sync_timeout)
            p_net->flags |= F_DAP_CHAIN_NET_GO_SYNC;

        pthread_mutex_unlock( &p_net->state_mutex );
    #else // WIN32

        WaitForSingleObject( p_net->state_proc_cond, (uint32_t)l_timeout_ms );

    #endif
        log_it( L_DEBUG, "Waked up s_net_proc_thread( )" );
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

    pthread_mutex_init( &PVT(ret)->state_mutex, NULL );

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
    dap_chain_node_cli_cmd_item_create ("net", s_cli_net, "Network commands",
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
    dap_chain_global_db_add_history_group_prefix("global");

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
 * @param str_reply
 * @return
 */
static int s_cli_net( int argc, char **argv, char **a_str_reply)
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
                time_t l_prev_sec_ts;

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
                            c_net_states[PVT(l_net)->state_target], HASH_COUNT(PVT(l_net)->links),
                            PVT(l_net)->links_addrs_count
                            );
                }
                else {
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                            "Network \"%s\" has state %s (target state %s), active links %u from %u, cur node address " NODE_ADDR_FP_STR,
                            l_net->pub.name, c_net_states[PVT(l_net)->state],
                            c_net_states[PVT(l_net)->state_target], HASH_COUNT(PVT(l_net)->links),
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
                    dap_config_get_item_str_default(l_cfg , "general" , "gdb_groups_prefix","" ) );
        dap_chain_global_db_add_history_group_prefix( l_net->pub.gdb_groups_prefix);
        dap_chain_global_db_add_history_callback_notify(l_net->pub.gdb_groups_prefix, s_gbd_history_callback_notify, l_net );

        l_net->pub.gdb_nodes = dap_strdup_printf("%s.nodes",l_net->pub.gdb_groups_prefix);
        l_net->pub.gdb_nodes_aliases = dap_strdup_printf("%s.nodes.aliases",l_net->pub.gdb_groups_prefix);



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

        //const char * l_node_ipv4_str = dap_config_get_item_str(l_cfg , "general" ,"node-ipv4");
        const char * l_node_addr_str = dap_config_get_item_str(l_cfg , "general" ,"node-addr");
        const char * l_node_alias_str = dap_config_get_item_str(l_cfg , "general" , "node-alias");
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
                        struct addrinfo l_hints={0}, *l_servinfo, *p;
                        int rv;
                        l_hints.ai_family = AF_UNSPEC ;    /* Allow IPv4 or IPv6 */
                        //l_hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */

                        log_it( L_DEBUG, "Resolve %s addr", l_seed_nodes_hostnames[i]);
                        struct hostent *l_he;

                        if ( l_he = gethostbyname (l_seed_nodes_hostnames[i])   ){
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
                    log_it(L_DEBUG, "Parse node address with format " NODE_ADDR_FP_STR);
                    parse_succesfully = true;
                }

                if (!parse_succesfully){
                    log_it(L_ERROR,"Can't parse node address");
                    DAP_DELETE(l_node_addr);
                    l_node_addr = NULL;
                }
                log_it(L_NOTICE, "Parse node addr %s successfully", l_node_addr_str);
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
                        log_it(L_NOTICE,"GDB Info: node_addr: " NODE_ADDR_FP_STR"  links: %u cell_id: 0x%0l16X ",
                               NODE_ADDR_FP_ARGS(l_node_addr),
                               PVT(l_net)->node_info->hdr.links_number,
                               PVT(l_net)->node_info->hdr.cell_id.uint64);
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
                }
                DAP_DELETE (l_chain_prior->chains_path);
                l_list = dap_list_next(l_list);
            }
            dap_list_free(l_prior_list);

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
    return  PVT(l_net)->node_info? &PVT(l_net)->node_info->hdr.address: PVT(l_net)->node_addr;
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
    for(dap_chain_type_t i = CHAIN_TYPE_FIRST + 1; i < CHAIN_TYPE_LAST; i++) {
        dap_chain_t * l_chain = dap_chain_net_get_chain_by_chain_type(a_net, i);
        char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);

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
                l_datums[i] = l_datum;
                if(i < l_objs_size_tmp) {
                    char buf[50];
                    time_t l_ts_create = (time_t) l_datum->header.ts_create;
                    log_it(L_INFO, "\t\t0x%s: type_id=%s ts_create=%s data_size=%u",
                            l_objs[i].key, c_datum_type_str[l_datum->header.type_id],
                            ctime_r(&l_ts_create, buf), l_datum->header.data_size);
                }
            }
            size_t l_objs_processed = l_chain->callback_datums_pool_proc(l_chain, l_datums, l_datums_size);
            // Delete processed objects
            size_t l_objs_processed_tmp = (l_objs_processed > 15) ? min(l_objs_processed, 10) : l_objs_processed;
            for(size_t i = 0; i < l_objs_processed; i++) {
                if(dap_chain_global_db_gr_del(l_objs[i].key, l_gdb_group_mempool))
                    s_net_set_go_sync(a_net);
                if(i < l_objs_processed_tmp) {
                    dap_string_append_printf(l_str_tmp, "New event created, removed datum 0x%s from mempool \n",
                            l_objs[i].key);
                }
            }
            if(l_objs_processed < l_datums_size)
                log_it(L_WARNING, "%s.%s: %d records not processed", a_net->pub.name, l_chain->name,
                        l_datums_size - l_objs_processed);
            dap_chain_global_db_objs_delete(l_objs, l_objs_size);
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

