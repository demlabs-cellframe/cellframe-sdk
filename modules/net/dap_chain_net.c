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


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef  _XOPEN_SOURCE
#define _XOPEN_SOURCE       /* See feature_test_macros(7) */
#endif
#ifndef __USE_XOPEN
#define __USE_XOPEN
#endif
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>


#ifdef DAP_OS_UNIX
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif


#include "uthash.h"
#include "utlist.h"

#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_enc_base58.h"
#include "dap_config.h"
#include "dap_hash.h"
#include "dap_cert.h"
#include "dap_cert_file.h"

#include "dap_timerfd.h"
#include "dap_stream_worker.h"
#include "dap_worker.h"
#include "dap_proc_queue.h"
#include "dap_proc_thread.h"

#include "dap_enc_http.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_pvt.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_notify_srv.h"
#include "dap_chain_ledger.h"
#include "dap_chain_cs_none.h"

#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"

#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_chain_node_dns_client.h"

#include "dap_module.h"

#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

#define LOG_TAG "chain_net"

#define F_DAP_CHAIN_NET_SYNC_FROM_ZERO   ( 1 << 8 )
#define F_DAP_CHAIN_NET_SHUTDOWN         ( 1 << 9 )
#define F_DAP_CHAIN_NET_GO_SYNC          ( 1 << 10 )

// maximum number of connections
static size_t s_max_links_count = 5;// by default 5
// number of required connections
static size_t s_required_links_count = 3;// by default 3
static pthread_t s_net_check_pid;
static bool s_debug_more = false;

struct link_dns_request {
    uint32_t link_id;
    dap_chain_net_t * net;
    uint_fast16_t tries;
};

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
    dap_chain_node_info_t * node_info;  // Current node's info

    // Established links
    dap_list_t *links;                  // Links list
    size_t links_connected_count;

    // Prepared links
    dap_list_t *links_info;             // Links info list

    atomic_uint links_dns_requests;

    bool load_mode;
    char ** seed_aliases;

    uint16_t bootstrap_nodes_count;
    struct in_addr *bootstrap_nodes_addrs;
    uint16_t *bootstrap_nodes_ports;

    uint16_t gdb_sync_groups_count;
    uint16_t gdb_sync_nodes_addrs_count;
    char **gdb_sync_groups;
    dap_chain_node_addr_t *gdb_sync_nodes_addrs;

    uint16_t seed_aliases_count;

    dap_chain_net_state_t state;
    dap_chain_net_state_t state_target;
    uint16_t acl_idx;

    // Main loop timer
    dap_timerfd_t * main_timer;

    // General rwlock for structure
    pthread_rwlock_t rwlock;

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


// Node link callbacks
static void s_node_link_callback_connected(dap_chain_node_client_t * a_node_client, void * a_arg);
static void s_node_link_callback_disconnected(dap_chain_node_client_t * a_node_client, void * a_arg);
static void s_node_link_callback_stage(dap_chain_node_client_t * a_node_client,dap_client_stage_t a_stage, void * a_arg);
static void s_node_link_callback_error(dap_chain_node_client_t * a_node_client, int a_error, void * a_arg);
static void s_node_link_callback_delete(dap_chain_node_client_t * a_node_client, void * a_arg);

static const dap_chain_node_client_callbacks_t s_node_link_callbacks={
    .connected=s_node_link_callback_connected,
    .disconnected=s_node_link_callback_disconnected,
    .stage=s_node_link_callback_stage,
    .error=s_node_link_callback_error
};


// State machine switchs here
static bool s_net_states_proc(dap_proc_thread_t *a_thread, void *a_arg);

// Notify about net states
static void s_net_states_notify(dap_chain_net_t * l_net );
static void s_net_links_notify(dap_chain_net_t * a_net );

// Prepare link success/error endpoints
static void s_net_state_link_prepare_success(dap_worker_t * a_worker,dap_chain_node_info_t * a_node_info, void * a_arg);
static void s_net_state_link_prepare_error(dap_worker_t * a_worker,dap_chain_node_info_t * a_node_info, void * a_arg, int a_errno);


static void s_net_proc_kill( dap_chain_net_t * a_net );
int s_net_load(const char * a_net_name, uint16_t a_acl_idx);

// Notify callback for GlobalDB changes
static void s_gbd_history_callback_notify (void * a_arg,const char a_op_code, const char * a_prefix, const char * a_group,
                                                     const char * a_key, const void * a_value,
                                                     const size_t a_value_len);
static void s_chain_callback_notify(void * a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id, void *a_atom, size_t a_atom_size);

static int s_cli_net(int argc, char ** argv, void *arg_func, char **str_reply);

static bool s_seed_mode = false;

static uint8_t *dap_chain_net_set_acl(dap_chain_hash_fast_t *a_pkey_hash);

static dap_global_db_obj_callback_notify_t s_srv_callback_notify = NULL;


char *dap_chain_net_get_gdb_group_acl(dap_chain_net_t *a_net)
{
    if (a_net) {
        const char l_path[] = "network/";
        char l_cfg_path[strlen(a_net->pub.name) + strlen(l_path) + 1];
        strcpy(l_cfg_path, l_path);
        strcat(l_cfg_path, a_net->pub.name);
        dap_config_t *l_cfg = dap_config_open(l_cfg_path);
        const char *l_auth_gdb = dap_config_get_item_str(l_cfg, "auth", "acl_accept_ca_gdb");
        if (l_auth_gdb) {
            return dap_strdup_printf("%s.%s", a_net->pub.gdb_groups_prefix, l_auth_gdb);
        }
    }
    return NULL;
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
    if (PVT(a_net)->state_target == a_new_state){
        log_it(L_WARNING,"Already going to state %s",s_net_state_to_str(a_new_state));
    }
    PVT(a_net)->state_target = a_new_state;

    pthread_mutex_lock( &PVT(a_net)->state_mutex_cond); // Preventing call of state_go_to before wait cond will be armed
    // set flag for sync
    PVT(a_net)->flags |= F_DAP_CHAIN_NET_GO_SYNC;
#ifndef _WIN32
    pthread_cond_signal( &PVT(a_net)->state_proc_cond );
#else
    SetEvent( PVT(a_net)->state_proc_cond );
#endif
    pthread_mutex_unlock( &PVT(a_net)->state_mutex_cond);
    dap_proc_queue_add_callback(dap_events_worker_get_auto(), s_net_states_proc, a_net);
    return 0;
}


void dap_chain_net_set_srv_callback_notify(dap_global_db_obj_callback_notify_t a_callback)
{
    s_srv_callback_notify = a_callback;
}

void dap_chain_net_sync_gdb_broadcast(void *a_arg, const char a_op_code, const char *a_prefix, const char *a_group,
                                      const char *a_key, const void *a_value, const size_t a_value_len)
{
    UNUSED(a_prefix);
    UNUSED(a_value_len);
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    if (PVT(l_net)->state == NET_STATE_ONLINE) {
        char *l_group;
        if (a_op_code == 'd') {
            l_group = dap_strdup_printf("%s.del", a_group);
        } else {
            l_group = (char *)a_group;
        }
        dap_store_obj_t *l_obj = (dap_store_obj_t *)dap_chain_global_db_obj_get(a_key, l_group);
        if (a_op_code == 'd') {
            DAP_DELETE(l_group);
        }
        if (!l_obj) {
            log_it(L_DEBUG, "Notified GDB event does not exist");
            return;
        }
        l_obj->type = (uint8_t)a_op_code;
        DAP_DELETE(l_obj->group);
        l_obj->group = dap_strdup(a_group);
        dap_list_t *l_list_out = dap_store_packet_multiple(l_obj, l_obj->timestamp, 1);
        // Expect only one element in list
        dap_store_obj_pkt_t *l_data_out = (dap_store_obj_pkt_t *)l_list_out->data;
        dap_store_obj_free(l_obj, 1);
        dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, "gdb");
        dap_chain_id_t l_chain_id = l_chain ? l_chain->id : (dap_chain_id_t) {};
        pthread_rwlock_rdlock(&PVT(l_net)->rwlock);
        for (dap_list_t *l_tmp = PVT(l_net)->links; l_tmp; l_tmp = dap_list_next(l_tmp)) {
            dap_chain_node_client_t *l_node_client = (dap_chain_node_client_t *)l_tmp->data;
            dap_stream_ch_chain_pkt_write_mt( dap_client_get_stream_worker(l_node_client->client), l_node_client->ch_chain_uuid, DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB, l_net->pub.id.uint64,
                                                 l_chain_id.uint64, l_net->pub.cell_id.uint64, l_data_out,
                                                 sizeof(dap_store_obj_pkt_t) + l_data_out->data_size);
        }
        pthread_rwlock_unlock(&PVT(l_net)->rwlock);
        dap_list_free_full(l_list_out, free);
    }
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
                                                     const char * a_key, const void * a_value, const size_t a_value_len)
{
    if (!a_arg) {
        return;
    }
    dap_chain_node_mempool_autoproc_notify(a_arg, a_op_code, a_prefix, a_group, a_key, a_value, a_value_len);
    dap_chain_net_sync_gdb_broadcast(a_arg, a_op_code, a_prefix, a_group, a_key, a_value, a_value_len);
    if (s_srv_callback_notify) {
        s_srv_callback_notify(a_arg, a_op_code, a_prefix, a_group, a_key, a_value, a_value_len);
    }
}

/**
 * @brief s_chain_callback_notify
 * @param a_arg
 * @param a_chain
 * @param a_id
 */
static void s_chain_callback_notify(void * a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id, void* a_atom, size_t a_atom_size)
{
    if (!a_arg)
        return;
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    if (PVT(l_net)->state == NET_STATE_ONLINE) {
        pthread_rwlock_rdlock(&PVT(l_net)->rwlock);
        for (dap_list_t *l_tmp = PVT(l_net)->links; l_tmp; l_tmp = dap_list_next(l_tmp)) {
            dap_chain_node_client_t *l_node_client = (dap_chain_node_client_t *)l_tmp->data;
            dap_stream_worker_t * l_worker = dap_client_get_stream_worker( l_node_client->client);
            if(l_worker)
                dap_stream_ch_chain_pkt_write_mt(l_worker, l_node_client->ch_chain_uuid, DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN,
                                              l_net->pub.id.uint64, a_chain->id.uint64, a_id.uint64, a_atom, a_atom_size);
        }
        pthread_rwlock_unlock(&PVT(l_net)->rwlock);
    }
}

/**
 * @brief s_fill_links_from_root_aliases
 * @param a_net
 */
static void s_fill_links_from_root_aliases(dap_chain_net_t * a_net)
{
     dap_chain_net_pvt_t *l_pvt_net = PVT(a_net);
     uint64_t l_own_addr = dap_chain_net_get_cur_addr_int(a_net);
     for (size_t i = 0; i < MIN(s_max_links_count, l_pvt_net->seed_aliases_count); i++) {
         pthread_rwlock_rdlock(&l_pvt_net->rwlock);
         if (dap_list_length(l_pvt_net->links_info) >= s_max_links_count) {
             pthread_rwlock_unlock(&l_pvt_net->rwlock);
             break;
         }else
            pthread_rwlock_unlock(&l_pvt_net->rwlock);

         dap_chain_node_addr_t *l_link_addr = dap_chain_node_alias_find(a_net, l_pvt_net->seed_aliases[i]);
         if (!l_link_addr)
             continue;

         if (l_link_addr->uint64 == l_own_addr) {
             continue;   // Do not link with self
         }
         dap_chain_node_info_t *l_link_node_info = dap_chain_node_info_read(a_net, l_link_addr);
         if(l_link_node_info) {
             pthread_rwlock_wrlock(&l_pvt_net->rwlock);
             l_pvt_net->links_info = dap_list_append(l_pvt_net->links_info, l_link_node_info);
             pthread_rwlock_unlock(&l_pvt_net->rwlock);
         } else {
             log_it(L_WARNING, "Not found link %s."NODE_ADDR_FP_STR" in the node list", a_net->pub.name,
                    NODE_ADDR_FPS_ARGS(l_link_addr));
         }
     }
}

/**
 * @brief s_node_link_callback_connected
 * @param a_node_client
 * @param a_arg
 */
static void s_node_link_callback_connected(dap_chain_node_client_t * a_node_client, void * a_arg)
{
    dap_chain_net_t * l_net = (dap_chain_net_t *) a_arg;
    dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);
    dap_chain_node_info_t * l_link_info = a_node_client->info;



    a_node_client->stream_worker = dap_client_get_stream_worker(a_node_client->client);
    if(a_node_client->stream_worker == NULL){
        log_it(L_ERROR, "Stream worker is NULL in connected() callback, do nothing");
        a_node_client->state = NODE_CLIENT_STATE_ERROR;
        return;
    }

    a_node_client->state = NODE_CLIENT_STATE_ESTABLISHED;

    if( !a_node_client->is_reconnecting || s_debug_more )
        log_it(L_NOTICE, "Established connection with %s."NODE_ADDR_FP_STR,l_net->pub.name,
               NODE_ADDR_FP_ARGS_S(a_node_client->remote_node_addr));
    pthread_rwlock_wrlock(&l_net_pvt->rwlock);
    l_net_pvt->links = dap_list_append(l_net_pvt->links, a_node_client);
    l_net_pvt->links_connected_count++;
    s_net_links_notify(l_net);

    // If we're fist time here - initiate the GDB sync
    if (! a_node_client->is_reconnecting){
        dap_stream_ch_chain_sync_request_t l_sync_gdb = {};
        // Get last timestamp in log if wasn't SYNC_FROM_ZERO flag
        if (! (l_net_pvt->flags & F_DAP_CHAIN_NET_SYNC_FROM_ZERO) )
            l_sync_gdb.id_start = (uint64_t) dap_db_get_last_id_remote(a_node_client->remote_node_addr.uint64);
        l_sync_gdb.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
        log_it(L_DEBUG, "Prepared request to gdb sync from %"DAP_UINT64_FORMAT_U" to %"DAP_UINT64_FORMAT_U"", l_sync_gdb.id_start, l_sync_gdb.id_end?l_sync_gdb.id_end:-1 );
        // find dap_chain_id_t
        dap_chain_t *l_chain = l_net->pub.chains;
        dap_chain_id_t l_chain_id = l_chain ? l_chain->id : (dap_chain_id_t ) {0};

        a_node_client->ch_chain = dap_client_get_stream_ch_unsafe(a_node_client->client,dap_stream_ch_chain_get_id() );
        if (a_node_client->ch_chain)
            a_node_client->ch_chain_uuid = a_node_client->ch_chain->uuid;

        a_node_client->ch_chain_net = dap_client_get_stream_ch_unsafe(a_node_client->client,dap_stream_ch_chain_get_id() );
        if(a_node_client->ch_chain_net)
            a_node_client->ch_chain_net_uuid = a_node_client->ch_chain_net->uuid;

        dap_stream_ch_chain_pkt_write_unsafe( a_node_client->ch_chain ,
                                                           DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_REQ, l_net->pub.id.uint64,
                                                        l_chain_id.uint64, l_net->pub.cell_id.uint64, &l_sync_gdb, sizeof(l_sync_gdb));
    }
    a_node_client->is_reconnecting = false;

    if(l_net_pvt->state == NET_STATE_LINKS_CONNECTING ){
        l_net_pvt->state = NET_STATE_LINKS_ESTABLISHED;
        dap_proc_queue_add_callback_inter(a_node_client->stream_worker->worker->proc_queue_input,s_net_states_proc,l_net );
    }
    pthread_rwlock_unlock(&l_net_pvt->rwlock);

}

/**
 * @brief s_node_link_callback_disconnected
 * @param a_node_client
 * @param a_arg
 */
static void s_node_link_callback_disconnected(dap_chain_node_client_t * a_node_client, void * a_arg)
{
    dap_chain_net_t * l_net = (dap_chain_net_t *) a_arg;
    dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);
    pthread_rwlock_wrlock(&l_net_pvt->rwlock);
        if ( l_net_pvt->state_target ==NET_STATE_ONLINE ){
            if(s_debug_more)
                log_it(L_NOTICE, "%s."NODE_ADDR_FP_STR" disconnected, reconnecting back...",
                   l_net->pub.name,
                   NODE_ADDR_FP_ARGS_S(a_node_client->remote_node_addr) );

            a_node_client->is_reconnecting = true;

            dap_chain_net_client_create_n_connect(l_net, a_node_client->info);
        }else if (l_net_pvt->state_target == NET_STATE_OFFLINE){
            log_it(L_INFO, "%s."NODE_ADDR_FP_STR" disconnected",l_net->pub.name,NODE_ADDR_FP_ARGS_S(a_node_client->info->hdr.address));

        }else{
            log_it(L_CRITICAL,"Link "NODE_ADDR_FP_STR" disconnected, but wrong target state %s: could be only NET_STATE_ONLINE or NET_STATE_OFFLINE "
                   ,NODE_ADDR_FP_ARGS_S(a_node_client->remote_node_addr)
                   , c_net_states[l_net_pvt->state_target]  );
        }
        if(l_net_pvt->links_connected_count)
            l_net_pvt->links_connected_count--;
        else
            log_it(L_CRITICAL,"Links count is zero in disconnected callback, looks smbd decreased it twice or forget to increase on connect/reconnect");
    pthread_rwlock_unlock(&l_net_pvt->rwlock);

    s_node_link_callback_delete(a_node_client,a_arg);
}

/**
 * @brief s_node_link_callback_stage
 * @param a_node_client
 * @param a_stage
 * @param a_arg
 */
static void s_node_link_callback_stage(dap_chain_node_client_t * a_node_client,dap_client_stage_t a_stage, void * a_arg)
{
    dap_chain_net_t * l_net = (dap_chain_net_t *) a_arg;
    if( s_debug_more)
        log_it(L_INFO,"%s."NODE_ADDR_FP_STR" stage %s",l_net->pub.name,NODE_ADDR_FP_ARGS_S(a_node_client->remote_node_addr),
                                                        dap_client_stage_str(a_stage));
    dap_notify_server_send_f_mt("{"
                            "class:\"NetLinkStage\","
                            "net_id:0x%016" DAP_UINT64_FORMAT_X ","
                            "cell_id:0x%016"DAP_UINT64_FORMAT_X","
                            "address:\""NODE_ADDR_FP_STR"\","
                            "state:\"%s\""
                        "}\n", a_node_client->net->pub.id.uint64, a_node_client->info->hdr.cell_id.uint64,
                                NODE_ADDR_FP_ARGS_S(a_node_client->info->hdr.address),
                                dap_chain_node_client_state_to_str(a_node_client->state) );
}

/**
 * @brief s_node_link_callback_error
 * @param a_node_client
 * @param a_error
 * @param a_arg
 */
static void s_node_link_callback_error(dap_chain_node_client_t * a_node_client, int a_error, void * a_arg)
{
    dap_chain_net_t * l_net = (dap_chain_net_t *) a_arg;
    log_it(L_WARNING, "Can't establish link with %s."NODE_ADDR_FP_STR, l_net->pub.name,
           NODE_ADDR_FP_ARGS_S(a_node_client->remote_node_addr));
    dap_notify_server_send_f_mt("{"
                            "class:\"NetLinkError\","
                            "net_id:0x%016" DAP_UINT64_FORMAT_X ","
                            "cell_id:0x%016"DAP_UINT64_FORMAT_X","
                            "address:\""NODE_ADDR_FP_STR"\","
                            "error:\%d"
                        "}\n", a_node_client->net->pub.id.uint64, a_node_client->info->hdr.cell_id.uint64,
                                NODE_ADDR_FP_ARGS_S(a_node_client->info->hdr.address),
                                a_error);
}

/**
 * @brief s_node_link_callback_delete
 * @param a_node_client
 * @param a_arg
 */
static void s_node_link_callback_delete(dap_chain_node_client_t * a_node_client, void * a_arg)
{
    log_it(L_DEBUG,"Remove node client from list");
    dap_chain_net_t * l_net = (dap_chain_net_t *) a_arg;
    dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);
    pthread_rwlock_wrlock(&l_net_pvt->rwlock);
    for ( dap_list_t * it = l_net_pvt->links; it; it=it->next ){
        dap_chain_node_client_t * l_client =(dap_chain_node_client_t *) it->data;
        // Cut out current iterator if it equals with deleting handler
        if (l_client == a_node_client){
            if (it->prev)
                it->prev->next = it->next;
            if (it->next)
                it->next->prev = it->prev;
        }
    }
    pthread_rwlock_unlock(&l_net_pvt->rwlock);
    dap_chain_node_client_close(a_node_client);

    dap_notify_server_send_f_mt("{"
                            "class:\"NetLinkDelete\","
                            "net_id:0x%016" DAP_UINT64_FORMAT_X ","
                            "cell_id:0x%016"DAP_UINT64_FORMAT_X","
                            "address:\""NODE_ADDR_FP_STR"\""
                        "}\n", a_node_client->net->pub.id.uint64, a_node_client->info->hdr.cell_id.uint64,
                                NODE_ADDR_FP_ARGS_S(a_node_client->info->hdr.address));
}

/**
 * @brief s_net_state_link_prepare_success
 * @param a_worker
 * @param a_node_info
 * @param a_arg
 */
static void s_net_state_link_prepare_success(dap_worker_t * a_worker,dap_chain_node_info_t * a_node_info, void * a_arg)
{
    if(s_debug_more){
        char l_node_addr_str[INET_ADDRSTRLEN]={};
        inet_ntop(AF_INET,&a_node_info->hdr.ext_addr_v4,l_node_addr_str, INET_ADDRSTRLEN);
        log_it(L_DEBUG,"Link " NODE_ADDR_FP_STR " (%s) prepare success", NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address),
                                                                                     l_node_addr_str );
    }

    struct link_dns_request * l_dns_request = (struct link_dns_request *) a_arg;
    dap_chain_net_t * l_net = l_dns_request->net;
    dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);
    uint64_t l_own_addr =0;
    if (a_node_info->hdr.address.uint64 != l_own_addr) {
        pthread_rwlock_wrlock(&l_net_pvt->rwlock);
        l_net_pvt->links_info = dap_list_append(l_net_pvt->links_info, a_node_info);
        pthread_rwlock_unlock(&l_net_pvt->rwlock);
        l_dns_request->tries = 0;
    }
    pthread_rwlock_rdlock(&l_net_pvt->rwlock);

    l_dns_request->tries++;
    l_net_pvt->links_dns_requests--;
    if (l_net_pvt->links_dns_requests == 0){ // It was the last one
        if (l_net_pvt->state != NET_STATE_LINKS_ESTABLISHED){
            l_net_pvt->state = NET_STATE_LINKS_ESTABLISHED;
            dap_proc_queue_add_callback_inter( a_worker->proc_queue_input,s_net_states_proc,l_net );
        }
    }
    pthread_rwlock_unlock(&l_net_pvt->rwlock);
    dap_notify_server_send_f_mt("{"
                            "class:\"NetLinkPrepareSuccess\","
                            "net_id:0x%016" DAP_UINT64_FORMAT_X ","
                            "cell_id:0x%016"DAP_UINT64_FORMAT_X","
                            "address:\""NODE_ADDR_FP_STR"\""
                        "}\n", l_net->pub.id.uint64, a_node_info->hdr.cell_id.uint64,
                                NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address));
    DAP_DELETE(l_dns_request);
}

/**
 * @brief s_net_state_link_prepare_error
 * @param a_worker
 * @param a_node_info
 * @param a_arg
 * @param a_errno
 */
static void s_net_state_link_prepare_error(dap_worker_t * a_worker,dap_chain_node_info_t * a_node_info, void * a_arg, int a_errno)
{
    struct link_dns_request * l_dns_request = (struct link_dns_request *) a_arg;
    dap_chain_net_t * l_net = l_dns_request->net;
    dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);
    char l_node_addr_str[INET_ADDRSTRLEN]={};
    inet_ntop(AF_INET,&a_node_info->hdr.ext_addr_v4,l_node_addr_str,sizeof (a_node_info->hdr.ext_addr_v4));
    log_it(L_WARNING,"Link " NODE_ADDR_FP_STR " (%s) prepare error with code %d", NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address),
                                                                                 l_node_addr_str,a_errno );

    dap_notify_server_send_f_mt("{"
                            "class:\"NetLinkPrepareError\","
                            "net_id:0x%016" DAP_UINT64_FORMAT_X ","
                            "cell_id:0x%016"DAP_UINT64_FORMAT_X","
                            "address:\""NODE_ADDR_FP_STR"\","
                            "error: %d"
                        "}\n", l_net->pub.id.uint64, a_node_info->hdr.cell_id.uint64,
                                NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address),a_errno);

    pthread_rwlock_wrlock(&l_net_pvt->rwlock);
    if(l_net_pvt->links_dns_requests)
        l_net_pvt->links_dns_requests--;

    if(!l_net_pvt->links_dns_requests ){
        if( l_net_pvt->state != NET_STATE_OFFLINE){
            log_it(L_WARNING,"Can't prepare links via DNS requests. Prefilling links with root addresses");
            l_net_pvt->state = NET_STATE_LINKS_CONNECTING;
            pthread_rwlock_unlock(&l_net_pvt->rwlock);
            s_fill_links_from_root_aliases(l_net);
            dap_proc_queue_add_callback_inter( a_worker->proc_queue_input,s_net_states_proc,l_net );
            DAP_DELETE(l_dns_request);
            return;
        }
    }
    pthread_rwlock_unlock(&l_net_pvt->rwlock);
    DAP_DELETE(l_dns_request);
}

/**
 * @brief s_net_states_notify
 * @param l_net
 */
static void s_net_states_notify(dap_chain_net_t * l_net )
{
    dap_notify_server_send_f_mt("{"
                                    "class:\"NetStates\","
                                    "net_id: 0x%016" DAP_UINT64_FORMAT_X ","
                                    "state: \"%s\","
                                    "state_target:\"%s\""
                                "}\n", l_net->pub.id.uint64,
                                       dap_chain_net_state_to_str( PVT(l_net)->state),
                                       dap_chain_net_state_to_str(PVT(l_net)->state_target));

}

/**
 * @brief s_net_links_notify
 * @param l_net
 */
static void s_net_links_notify(dap_chain_net_t * a_net )
{
    dap_chain_net_pvt_t * l_net_pvt = PVT(a_net);
    dap_string_t * l_str_reply = dap_string_new("[");

    size_t i =0;
    for (dap_list_t * l_item = l_net_pvt->links; l_item;  l_item = l_item->next ) {
        dap_chain_node_client_t * l_node_client = l_item->data;

        if(l_node_client){
            dap_chain_node_info_t * l_info = l_node_client->info;
            char l_ext_addr_v4[INET_ADDRSTRLEN]={};
            char l_ext_addr_v6[INET6_ADDRSTRLEN]={};
            inet_ntop(AF_INET,&l_info->hdr.ext_addr_v4,l_ext_addr_v4,sizeof (l_info->hdr.ext_addr_v4));
            inet_ntop(AF_INET6,&l_info->hdr.ext_addr_v6,l_ext_addr_v6,sizeof (l_info->hdr.ext_addr_v6));

            dap_string_append_printf(l_str_reply,"{"
                                        "id:%u,"
                                        "address:\""NODE_ADDR_FP_STR"\","
                                        "alias:\"%s\","
                                        "cell_id:0x%016"DAP_UINT64_FORMAT_X","
                                        "ext_ipv4:\"%s\","
                                        "ext_ipv6:\"%s\","
                                        "ext_port:%u"
                                        "state:\"%s\""
                                    "}", i,NODE_ADDR_FP_ARGS_S(l_info->hdr.address), l_info->hdr.alias, l_info->hdr.cell_id.uint64,
                                     l_ext_addr_v4, l_ext_addr_v6,l_info->hdr.ext_port
                                     , dap_chain_node_client_state_to_str(l_node_client->state) );
        }
        i++;
    }


    dap_notify_server_send_f_mt("{"
                                    "class:\"NetLinks\","
                                    "net_id:0x%016" DAP_UINT64_FORMAT_X ","
                                    "links:%s"
                                "}\n", a_net->pub.id.uint64,
                                       l_str_reply->str);
    dap_string_free(l_str_reply,true);

}

/**
 * @brief s_net_states_proc
 * @param l_net
 */
static bool s_net_states_proc(dap_proc_thread_t *a_thread, void *a_arg)
{
    bool l_repeat_after_exit = false; // If true - repeat on next iteration of proc thread loop
    dap_chain_net_t *l_net = (dap_chain_net_t *) a_arg;
    assert(l_net);
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    assert(l_net_pvt);
    if (l_net_pvt->state_target == NET_STATE_OFFLINE) {
        l_net_pvt->state = NET_STATE_OFFLINE;
        return true;
    }

    pthread_rwlock_wrlock(&l_net_pvt->rwlock);

    switch (l_net_pvt->state) {
        // State OFFLINE where we don't do anything
        case NET_STATE_OFFLINE: {
            // delete all links
            dap_list_t *l_tmp = l_net_pvt->links;
            while (l_tmp) {
                dap_list_t *l_next =l_tmp->next;
                dap_chain_node_client_close(l_tmp->data);
                DAP_DELETE(l_tmp);
                l_tmp = l_next;
            }
            l_net_pvt->links = NULL;
            if(l_net_pvt->links_info){
                dap_list_free_full(l_net_pvt->links_info, free);
                l_net_pvt->links_info = NULL;
            }
            if ( l_net_pvt->state_target != NET_STATE_OFFLINE ){
                l_net_pvt->state = NET_STATE_LINKS_PREPARE;
                l_repeat_after_exit = true;
                break;
            }
            // disable SYNC_GDB
            l_net_pvt->flags &= ~F_DAP_CHAIN_NET_GO_SYNC;
            l_net_pvt->last_sync = 0;
        } break;

        // Prepare links
        case NET_STATE_LINKS_PREPARE: {
            log_it(L_NOTICE,"%s.state: NET_STATE_LINKS_PREPARE", l_net->pub.name);
            s_net_states_notify(l_net);
            uint64_t l_own_addr = dap_chain_net_get_cur_addr_int(l_net);
            if (l_net_pvt->node_info) {
                for (size_t i = 0; i < l_net_pvt->node_info->hdr.links_number; i++) {
                    dap_chain_node_info_t *l_link_node_info = dap_chain_node_info_read(l_net, &l_net_pvt->node_info->links[i]);
                    if (!l_link_node_info || l_link_node_info->hdr.address.uint64 == l_own_addr) {
                        continue;   // Do not link with self
                    }
                    l_net_pvt->links_info = dap_list_append(l_net_pvt->links_info, l_link_node_info);
                    if (dap_list_length(l_net_pvt->links_info) >= s_max_links_count) {
                        break;
                    }
                }
            } else {
                log_it(L_WARNING,"No nodeinfo in global_db to prepare links for connecting, try to add links from root servers");
            }
            switch (l_net_pvt->node_role.enums) {
                case NODE_ROLE_ROOT:
                case NODE_ROLE_ROOT_MASTER:
                case NODE_ROLE_ARCHIVE:
                case NODE_ROLE_CELL_MASTER: {
                    if (l_net_pvt->seed_aliases_count) {
                        // Add other root nodes as synchronization links
                        pthread_rwlock_unlock(&l_net_pvt->rwlock);
                        s_fill_links_from_root_aliases(l_net);
                        pthread_rwlock_wrlock(&l_net_pvt->rwlock);
                        l_net_pvt->state = NET_STATE_LINKS_CONNECTING;
                        l_repeat_after_exit = true;
                        break;
                    }
                }
                case NODE_ROLE_FULL:
                case NODE_ROLE_MASTER:
                case NODE_ROLE_LIGHT:
                default: {
                    // Get DNS request result from root nodes as synchronization links
                    bool l_sync_fill_root_nodes = false;
                    uint32_t l_link_id=0;
                    if (!l_sync_fill_root_nodes){
                        for (size_t n=0; n< s_required_links_count;n++ ) {
                            struct in_addr l_addr = {};
                            uint16_t i, l_port;
                            if (l_net_pvt->seed_aliases_count) {
                                i = rand() % l_net_pvt->seed_aliases_count;
                                dap_chain_node_addr_t *l_remote_addr = dap_chain_node_alias_find(l_net, l_net_pvt->seed_aliases[i]);
                                if (l_remote_addr){
                                    dap_chain_node_info_t *l_remote_node_info = dap_chain_node_info_read(l_net, l_remote_addr);
                                    if(l_remote_node_info){
                                        l_addr.s_addr = l_remote_node_info ? l_remote_node_info->hdr.ext_addr_v4.s_addr : 0;
                                        DAP_DELETE(l_remote_node_info);
                                        l_port = DNS_LISTEN_PORT;
                                    }else{
                                        log_it(L_WARNING,"Can't find node info for node addr "NODE_ADDR_FP_STR,
                                               NODE_ADDR_FP_ARGS(l_remote_addr));
                                    }
                                }else{
                                    log_it(L_WARNING,"Can't find alias info for seed alias %s",l_net_pvt->seed_aliases[i]);
                                }
                            } else if (l_net_pvt->bootstrap_nodes_count) {
                                i = rand() % l_net_pvt->bootstrap_nodes_count;
                                l_addr = l_net_pvt->bootstrap_nodes_addrs[i];
                                l_port = l_net_pvt->bootstrap_nodes_ports[i];
                            } else {
                                log_it(L_ERROR, "No root servers present in configuration file. Can't establish DNS requests");
                                if (!dap_list_length(l_net_pvt->links_info)) {   // No links can be prepared, go offline
                                    l_net_pvt->state_target = NET_STATE_OFFLINE;
                                }
                            }
                            if (l_addr.s_addr) {
                                dap_chain_node_info_t *l_link_node_info = DAP_NEW_Z(dap_chain_node_info_t);
                                if(! l_link_node_info){
                                    log_it(L_CRITICAL,"Can't allocate memory for node link info");
                                    break;
                                }
    #ifdef DAP_OS_UNIX
                                struct in_addr _in_addr = { .s_addr = l_addr.s_addr  };
    #else
                                struct in_addr _in_addr = { { .S_addr = l_addr.S_un.S_addr } };
    #endif

                                l_sync_fill_root_nodes = false;
                                if (l_net_pvt->state_target != NET_STATE_OFFLINE) {
                                    l_net_pvt->links_dns_requests++;
                                    struct link_dns_request * l_dns_request = DAP_NEW_Z(struct link_dns_request);
                                    l_dns_request->net = l_net;
                                    l_dns_request->link_id = l_link_id;
                                    if(dap_chain_node_info_dns_request(l_addr, l_port, l_net->pub.name, l_link_node_info,
                                                                        s_net_state_link_prepare_success,
                                                                    s_net_state_link_prepare_error,l_dns_request) != 0 ){
                                        log_it(L_ERROR, "Can't process node info dns request");
                                        DAP_DEL_Z(l_link_node_info);

                                    }
                                }else{
                                    DAP_DEL_Z(l_link_node_info);
                                }
                            }
                            l_link_id++;
                        }
                    }
                    if (l_sync_fill_root_nodes){
                        log_it(L_ATT,"Not found bootstrap addresses, fill seed nodelist from root aliases");
                        pthread_rwlock_unlock(&l_net_pvt->rwlock);
                        s_fill_links_from_root_aliases(l_net);
                        pthread_rwlock_wrlock(&l_net_pvt->rwlock);
                    }
                } break;
            }
        } break;

        case NET_STATE_LINKS_CONNECTING: {
            log_it(L_INFO, "%s.state: NET_STATE_LINKS_CONNECTING",l_net->pub.name);
            for (dap_list_t *l_tmp = l_net_pvt->links_info; l_tmp; l_tmp = dap_list_next(l_tmp)) {
                dap_chain_node_info_t *l_link_info = (dap_chain_node_info_t *)l_tmp->data;
                (void) dap_chain_net_client_create_n_connect(l_net,l_link_info);
            }
        } break;
        case NET_STATE_LINKS_ESTABLISHED:{
            log_it(L_INFO,"%s.state: NET_STATE_LINKS_ESTABLISHED", l_net->pub.name);
            for (dap_list_t *l_tmp = l_net_pvt->links ; l_tmp; l_tmp = dap_list_next(l_tmp)) {
                dap_chain_node_client_t *l_link = (dap_chain_node_client_t *)l_tmp->data;
                //
            }
        }break;
        case NET_STATE_SYNC_GDB :{
            log_it(L_INFO,"%s.state: NET_STATE_SYNC_GDB", l_net->pub.name);
        }break;

        case NET_STATE_SYNC_CHAINS:{
            log_it(L_INFO,"%s.state: NET_STATE_SYNC_CHAINS", l_net->pub.name);
        }break;


        case NET_STATE_ONLINE: {
            log_it(L_NOTICE,"%s.state: NET_STATE_ONLINE", l_net->pub.name);
        }
        break;
        default: log_it (L_DEBUG, "Unprocessed state");
    }
    s_net_states_notify(l_net);
    pthread_rwlock_unlock(&l_net_pvt->rwlock);

    return ! l_repeat_after_exit;
}
/**
 * @brief dap_chain_net_client_create_n_connect
 * @param a_net
 * @param a_link_info
 * @return
 */
struct dap_chain_node_client * dap_chain_net_client_create_n_connect( dap_chain_net_t * a_net,struct dap_chain_node_info* a_link_info)
{
    return dap_chain_node_client_create_n_connect(a_net, a_link_info,"CN",(dap_chain_node_client_callbacks_t *)&s_node_link_callbacks,a_net);
}

/**
 * @brief dap_chain_net_client_create_n_connect_channels
 * @param a_net
 * @param a_link_info
 * @param a_channels
 * @return
 */
struct dap_chain_node_client * dap_chain_net_client_create_n_connect_channels( dap_chain_net_t * a_net,struct dap_chain_node_info* a_link_info,const char * a_channels )
{
    return dap_chain_node_client_create_n_connect(a_net, a_link_info,a_channels,(dap_chain_node_client_callbacks_t *)&s_node_link_callbacks,a_net);
}


/**
 * @brief dap_chain_net_get_role
 * @param a_net
 * @return
 */
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
#ifndef DAP_OS_DARWIN
    pthread_condattr_setclock( &l_attr, CLOCK_MONOTONIC );
#endif
    pthread_cond_init( &PVT(ret)->state_proc_cond, &l_attr );
#else
    PVT(ret)->state_proc_cond = CreateEventA( NULL, FALSE, FALSE, NULL );
#endif

    if ( sscanf(a_id,"0x%016lx", &ret->pub.id.uint64 ) == 1 ){
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
    dap_chain_node_client_init();
    dap_chain_node_cli_cmd_item_create ("net", s_cli_net, NULL, "Network commands",
        "net list [chains -n <chain net name>]"
            "\tList all networks or list all chains in selected network"
        "net -net <chain net name> [-mode update|all] go < online | offline >\n"
            "\tFind and establish links and stay online. \n"
            "\tMode \"update\" is by default when only new chains and gdb are updated. Mode \"all\" updates everything from zero\n"
        "net -net <chain net name> get status\n"
            "\tLook at current status\n"
        "net -net <chain net name> stats tx [-from <From time>] [-to <To time>] [-prev_sec <Seconds>] \n"
            "\tTransactions statistics. Time format is <Year>-<Month>-<Day>_<Hours>:<Minutes>:<Seconds> or just <Seconds> \n"
        "net -net <chain net name> [-mode update|all] sync < all | gdb | chains >\n"
            "\tSyncronyze gdb, chains or everything\n"
            "\tMode \"update\" is by default when only new chains and gdb are updated. Mode \"all\" updates everything from zero\n"
        "net -net <chain net name> link < list | add | del | info | establish >\n"
            "\tList, add, del, dump or establish links\n"
        "net -net <chain net name> ca add {-cert <cert name> | -hash <cert hash>}\n"
            "\tAdd certificate to list of authority cetificates in GDB group\n"
        "net -net <chain net name> ca list\n"
            "\tPrint list of authority cetificates from GDB group\n"
        "net -net <chain net name> ca del -hash <cert hash> [-H hex|base58(default)]\n"
            "\tDelete certificate from list of authority cetificates in GDB group by it's hash\n"
        "net -net <chain net name> ledger reload\n"
            "\tPurge the cache of chain net ledger and recalculate it from chain file\n"                                        );
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    dap_chain_global_db_add_history_group_prefix("global", GROUP_LOCAL_HISTORY);

    dap_chain_global_db_add_history_callback_notify("global", s_gbd_history_callback_notify, NULL );

    // maximum number of connections to other nodes
    s_max_links_count = dap_config_get_item_int32_default(g_config, "general", "max_links", s_max_links_count);
    // required number of connections to other nodes
    s_required_links_count = dap_config_get_item_int32_default(g_config, "general", "require_links", s_required_links_count);
    s_debug_more = dap_config_get_item_bool_default(g_config,"chain_net","debug_more",false);

    dap_chain_net_load_all();

    dap_enc_http_set_acl_callback(dap_chain_net_set_acl);
    log_it(L_NOTICE,"Chain networks initialized");
    return 0;
}

void dap_chain_net_load_all()
{
    char * l_net_dir_str = dap_strdup_printf("%s/network", dap_config_path());
    DIR * l_net_dir = opendir( l_net_dir_str);
    if ( l_net_dir ){
        struct dirent * l_dir_entry;
        uint16_t l_acl_idx = 0;
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
            s_net_load(l_dir_entry->d_name, l_acl_idx++);
        }
        closedir(l_net_dir);
    }else{
        int l_errno = errno;
        char l_errbuf[128];
        l_errbuf[0] = 0;
        strerror_r(l_errno,l_errbuf,sizeof (l_errbuf));
        log_it(L_WARNING,"Can't open entries on path %s: \"%s\" (code %d)", l_net_dir_str, l_errbuf, l_errno);
    }
    DAP_DELETE (l_net_dir_str);
}

void s_set_reply_text_node_status(char **a_str_reply, dap_chain_net_t * a_net){
    char* l_node_address_text_block = NULL;
    dap_chain_node_addr_t l_cur_node_addr = { 0 };
    l_cur_node_addr.uint64 = dap_chain_net_get_cur_addr_int(a_net);
    if(!l_cur_node_addr.uint64)
        l_node_address_text_block = dap_strdup_printf(", cur node address not defined");
    else
        l_node_address_text_block = dap_strdup_printf(", cur node address " NODE_ADDR_FP_STR,NODE_ADDR_FP_ARGS_S(l_cur_node_addr));

    char* l_sync_current_link_text_block = NULL;
    if (PVT(a_net)->state != NET_STATE_OFFLINE)
        l_sync_current_link_text_block = dap_strdup_printf(", active links %u from %u",
                                                           dap_list_length(PVT(a_net)->links),
                                                           dap_list_length(PVT(a_net)->links_info));
    dap_chain_node_cli_set_reply_text(a_str_reply,
                                      "Network \"%s\" has state %s (target state %s)%s%s",
                                      a_net->pub.name, c_net_states[PVT(a_net)->state],
                                      c_net_states[PVT(a_net)->state_target],
                                      (l_sync_current_link_text_block)? l_sync_current_link_text_block: "",
                                      l_node_address_text_block
                                      );
    DAP_DELETE(l_sync_current_link_text_block);
    DAP_DELETE(l_node_address_text_block);
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
    UNUSED(arg_func);
    int arg_index = 1;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    // command 'list'
    const char * l_list_cmd = NULL;

    if(dap_chain_node_cli_find_option_val(argv, arg_index, argc, "list", &l_list_cmd) != 0) {
        dap_string_t *l_string_ret = dap_string_new("");
        if (dap_strcmp(l_list_cmd,"chains")==0){
            const char * l_net_str = NULL;
            dap_chain_net_t* l_net = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-net", &l_net_str);
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "--net", &l_net_str);
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-n", &l_net_str);
            l_net = dap_chain_net_by_name(l_net_str);

            if (l_net){
                dap_string_append(l_string_ret,"Chains:\n ");
                dap_chain_t * l_chain = l_net->pub.chains;
                while (l_chain) {
                    dap_string_append_printf(l_string_ret, "\t%s:\n", l_chain->name );
                    l_chain = l_chain->next;
                }
            }else{
                dap_chain_net_item_t * l_net_item, *l_net_item_tmp;
                int l_net_i = 0;
                dap_string_append(l_string_ret,"Networks:\n ");
                HASH_ITER(hh, s_net_items, l_net_item, l_net_item_tmp){
                    l_net = l_net_item->chain_net;
                    dap_string_append_printf(l_string_ret, "\t%s:\n", l_net_item->name);
                    l_net_i++;

                    dap_chain_t * l_chain = l_net->pub.chains;
                    while (l_chain) {
                        dap_string_append_printf(l_string_ret, "\t\t%s:\n", l_chain->name );
                        l_chain = l_chain->next;
                    }
                }
            }

        }else{
            dap_string_append(l_string_ret,"Networks:\n ");
            // show list of nets
            dap_chain_net_item_t * l_net_item, *l_net_item_tmp;
            int l_net_i = 0;
            HASH_ITER(hh, s_net_items, l_net_item, l_net_item_tmp){
                dap_string_append_printf(l_string_ret, "%s\n", l_net_item->name);
                l_net_i++;
            }
            dap_string_append(l_string_ret, "\n");
        }

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
        const char *l_ca_str = NULL;
        const char *l_ledger_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "sync", &l_sync_str);
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "link", &l_links_str);
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "go", &l_go_str);
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "get", &l_get_str);
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "stats", &l_stats_str);
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "ca", &l_ca_str);
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "ledger", &l_ledger_str);

        const char * l_sync_mode_str = "updates";
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-mode", &l_sync_mode_str);
        if ( !dap_strcmp(l_sync_mode_str,"all") )
            dap_chain_net_get_flag_sync_from_zero(l_net);

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
                dap_string_append_printf( l_ret_str, "\tTotal:  %"DAP_UINT64_FORMAT_U"\n", l_tx_count );
                dap_chain_node_cli_set_reply_text( a_str_reply, l_ret_str->str );
                dap_string_free( l_ret_str, false );
            }
        } else if ( l_go_str){
            if ( strcmp(l_go_str,"online") == 0 ) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network \"%s\" going from state %s to %s",
                                                  l_net->pub.name,c_net_states[PVT(l_net)->state],
                                                  c_net_states[NET_STATE_ONLINE]);
                dap_chain_net_state_go_to(l_net, NET_STATE_ONLINE);
            } else if ( strcmp(l_go_str,"offline") == 0 ) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network \"%s\" going from state %s to %s",
                                                  l_net->pub.name,c_net_states[PVT(l_net)->state],
                                                  c_net_states[NET_STATE_OFFLINE]);
                dap_chain_net_state_go_to(l_net, NET_STATE_OFFLINE);

            }
            else if(strcmp(l_go_str, "sync") == 0) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network \"%s\" resynchronizing",
                                                  l_net->pub.name);
                dap_chain_net_state_go_to(l_net, NET_STATE_SYNC_GDB);
            }

        } else if ( l_get_str){
            if ( strcmp(l_get_str,"status") == 0 ) {
                s_set_reply_text_node_status(a_str_reply, l_net);
                ret = 0;
            }
        } else if ( l_links_str ){
            if ( strcmp(l_links_str,"list") == 0 ) {
                size_t i =0;
                dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);
                pthread_rwlock_rdlock(&l_net_pvt->rwlock );
                size_t l_links_count = dap_list_length(l_net_pvt->links);
                dap_string_t *l_reply = dap_string_new("");
                dap_string_append_printf(l_reply,"Links %u:\n", l_links_count);
                for (dap_list_t * l_item = l_net_pvt->links; l_item;  l_item = l_item->next ) {
                    dap_chain_node_client_t * l_node_client = l_item->data;

                    if(l_node_client){
                        dap_chain_node_info_t * l_info = l_node_client->info;
                        char l_ext_addr_v4[INET_ADDRSTRLEN]={};
                        char l_ext_addr_v6[INET6_ADDRSTRLEN]={};
                        inet_ntop(AF_INET,&l_info->hdr.ext_addr_v4,l_ext_addr_v4,sizeof (l_info->hdr.ext_addr_v4));
                        inet_ntop(AF_INET6,&l_info->hdr.ext_addr_v6,l_ext_addr_v6,sizeof (l_info->hdr.ext_addr_v6));

                        dap_string_append_printf(l_reply,
                                                    "\t"NODE_ADDR_FP_STR":\n"
                                                    "\t\talias: %s\n"
                                                    "\t\tcell_id: 0x%016"DAP_UINT64_FORMAT_X"\n"
                                                    "\t\text_ipv4: %s\n"
                                                    "\t\text_ipv6: %s\n"
                                                    "\t\text_port: %u\n"
                                                    "\t\tstate: %s\n"
                                                , NODE_ADDR_FP_ARGS_S(l_info->hdr.address), l_info->hdr.alias, l_info->hdr.cell_id,
                                                 l_ext_addr_v4, l_ext_addr_v6,l_info->hdr.ext_port
                                                 , dap_chain_node_client_state_to_str(l_node_client->state) );
                    }
                    i++;
                }
                pthread_rwlock_unlock(&l_net_pvt->rwlock );
                dap_chain_node_cli_set_reply_text(a_str_reply,"%s",l_reply->str);
                dap_string_free(l_reply,true);

            } else if ( strcmp(l_links_str,"add") == 0 ) {
                dap_chain_node_cli_set_reply_text(a_str_reply,"Not implemented\n");
            } else if ( strcmp(l_links_str,"del") == 0 ) {
                dap_chain_node_cli_set_reply_text(a_str_reply,"Not implemented\n");

            }  else if ( strcmp(l_links_str,"info") == 0 ) {
                dap_chain_node_cli_set_reply_text(a_str_reply,"Not implemented\n");

            } else if ( strcmp (l_links_str,"disconnect_all") == 0 ){
                ret = 0;
                dap_chain_net_stop(l_net);
                dap_chain_node_cli_set_reply_text(a_str_reply,"Stopped network\n");
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
        } else if (l_ca_str) {
            if (strcmp(l_ca_str, "add") == 0 ) {
                const char *l_cert_string = NULL, *l_hash_string = NULL;



                dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-cert", &l_cert_string);
                dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-hash", &l_hash_string);

                if (!l_cert_string && !l_hash_string) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "One of -cert or -hash parameters is mandatory");
                    return -6;
                }
                char *l_hash_hex_str;
                //char *l_hash_base58_str;
                // hash may be in hex or base58 format
                if(!dap_strncmp(l_hash_string, "0x", 2) || !dap_strncmp(l_hash_string, "0X", 2)) {
                    l_hash_hex_str = dap_strdup(l_hash_string);
                    //l_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_hash_string);
                }
                else {
                    l_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_hash_string);
                    //l_hash_base58_str = dap_strdup(l_hash_string);
                }

                if (l_cert_string) {
                    dap_cert_t * l_cert = dap_cert_find_by_name(l_cert_string);
                    if (l_cert == NULL) {
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't find \"%s\" certificate", l_cert_string);
                        return -7;
                    }
                    if (l_cert->enc_key == NULL) {
                        dap_chain_node_cli_set_reply_text(a_str_reply, "No key found in \"%s\" certificate", l_cert_string );
                        return -8;
                    }
                    // Get publivc key hash
                    size_t l_pub_key_size = 0;
                    uint8_t *l_pub_key = dap_enc_key_serealize_pub_key(l_cert->enc_key, &l_pub_key_size);;
                    if (l_pub_key == NULL) {
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't serialize public key of certificate \"%s\"", l_cert_string);
                        return -9;
                    }
                    dap_chain_hash_fast_t l_pkey_hash;
                    dap_hash_fast(l_pub_key, l_pub_key_size, &l_pkey_hash);
                    l_hash_hex_str = dap_chain_hash_fast_to_str_new(&l_pkey_hash);
                    //l_hash_base58_str = dap_enc_base58_encode_hash_to_str(&l_pkey_hash);
                }
                const char c = '1';
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Database ACL group not defined for this network");
                    return -11;
                }
                ret = dap_chain_global_db_gr_set(dap_strdup(l_hash_hex_str), (void *)&c, 1, dap_chain_net_get_gdb_group_acl(l_net));
                DAP_DELETE(l_gdb_group_str);
                DAP_DELETE(l_hash_hex_str);
                if (!ret) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Can't save public key hash in database");
                    return -10;
                }
                return 0;
            } else if (strcmp(l_ca_str, "list") == 0 ) {
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Database ACL group not defined for this network");
                    return -11;
                }
                size_t l_objs_count;
                dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(l_gdb_group_str, &l_objs_count);
                DAP_DELETE(l_gdb_group_str);
                dap_string_t *l_reply = dap_string_new("");
                for (size_t i = 0; i < l_objs_count; i++) {
                    dap_string_append(l_reply, l_objs[i].key);
                    dap_string_append(l_reply, "\n");
                }
                dap_chain_global_db_objs_delete(l_objs, l_objs_count);
                *a_str_reply = l_reply->len ? l_reply->str : dap_strdup("No entries found");
                dap_string_free(l_reply, false);
                return 0;
            } else if (strcmp(l_ca_str, "del") == 0 ) {
                const char *l_hash_string = NULL;
                dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-hash", &l_hash_string);
                if (!l_hash_string) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Format should be 'net ca del -hash <hash string>");
                    return -6;
                }
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Database ACL group not defined for this network");
                    return -11;
                }
                ret = dap_chain_global_db_gr_del((char *)l_hash_string, l_gdb_group_str);
                DAP_DELETE(l_gdb_group_str);
                if (!ret) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Cant't find certificate public key hash in database");
                    return -10;
                }
                return 0;
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Subcommand \"ca\" requires one of parameter: add, list, del\n");
                ret = -5;
            }
        } else if (l_ledger_str && !strcmp(l_ledger_str, "reload")) {
            dap_chain_ledger_purge(l_net->pub.ledger);
            dap_chain_t *l_chain;
            DL_FOREACH(l_net->pub.chains, l_chain) {
                if (l_chain->callback_purge) {
                    l_chain->callback_purge(l_chain);
                }
                if (!strcmp(DAP_CHAIN_PVT(l_chain)->cs_name, "none")) {
                    dap_chain_gdb_ledger_load((char *)dap_chain_gdb_get_group(l_chain), l_chain);
                } else {
                    dap_chain_load_all(l_chain);
                }
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
int s_net_load(const char * a_net_name, uint16_t a_acl_idx)
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
        dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);
        if(!l_net) {
            log_it(L_ERROR,"Can't create l_net");
            return -1;
        }
        l_net_pvt->load_mode = true;
        l_net_pvt->acl_idx = a_acl_idx;
        l_net->pub.gdb_groups_prefix = dap_strdup (
                    dap_config_get_item_str_default(l_cfg , "general" , "gdb_groups_prefix",
                                                    dap_config_get_item_str(l_cfg , "general" , "name" ) ) );
        dap_chain_global_db_add_history_group_prefix( l_net->pub.gdb_groups_prefix, GROUP_LOCAL_HISTORY);
        dap_chain_global_db_add_history_callback_notify(l_net->pub.gdb_groups_prefix, s_gbd_history_callback_notify, l_net );

        l_net->pub.gdb_nodes = dap_strdup_printf("%s.nodes",l_net->pub.gdb_groups_prefix);
        l_net->pub.gdb_nodes_aliases = dap_strdup_printf("%s.nodes.aliases",l_net->pub.gdb_groups_prefix);

        // for sync special groups - nodes
        char **l_gdb_sync_nodes_addrs = dap_config_get_array_str(l_cfg, "general", "gdb_sync_nodes_addrs",
                &l_net_pvt->gdb_sync_nodes_addrs_count);
        if(l_gdb_sync_nodes_addrs && l_net_pvt->gdb_sync_nodes_addrs_count > 0) {
            l_net_pvt->gdb_sync_nodes_addrs = (dap_chain_node_addr_t*) DAP_NEW_Z_SIZE(char**,
                    sizeof(dap_chain_node_addr_t)*l_net_pvt->gdb_sync_nodes_addrs_count);
            for(uint16_t i = 0; i < l_net_pvt->gdb_sync_nodes_addrs_count; i++) {
                dap_chain_node_addr_from_str(l_net_pvt->gdb_sync_nodes_addrs + i, l_gdb_sync_nodes_addrs[i]);
            }
        }
        // for sync special groups - groups
        char **l_gdb_sync_groups = dap_config_get_array_str(l_cfg, "general", "gdb_sync_groups", &l_net_pvt->gdb_sync_groups_count);
        if(l_gdb_sync_groups && l_net_pvt->gdb_sync_groups_count > 0) {
            l_net_pvt->gdb_sync_groups = (char **) DAP_NEW_SIZE(char**, sizeof(char*)*l_net_pvt->gdb_sync_groups_count);
            for(uint16_t i = 0; i < l_net_pvt->gdb_sync_groups_count; i++) {
                l_net_pvt->gdb_sync_groups[i] = dap_strdup(l_gdb_sync_groups[i]);
                // added group to history log
                dap_list_t *l_groups0 = dap_chain_global_db_driver_get_groups_by_mask(l_net_pvt->gdb_sync_groups[i]);
                dap_list_t *l_groups = l_groups0;
                while(l_groups) {
                    char *l_group_name = l_groups->data;
                    // do not use groups with names like *.del
                    if(dap_fnmatch("*.del", l_group_name, 0)) {
                        const char *l_history_group = dap_chain_global_db_add_history_extra_group(l_group_name,
                                                        l_net_pvt->gdb_sync_nodes_addrs,
                                                        &l_net_pvt->gdb_sync_nodes_addrs_count);
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
        l_net->pub.ledger = dap_chain_ledger_create(l_ledger_flags, l_net->pub.name);
        // Check if seed nodes are present in local db alias
        char **l_seed_aliases = dap_config_get_array_str( l_cfg , "general" ,"seed_nodes_aliases"
                                                             ,&l_net_pvt->seed_aliases_count);
        l_net_pvt->seed_aliases = l_net_pvt->seed_aliases_count>0 ?
                                   (char **)DAP_NEW_SIZE(char**, sizeof(char*)*PVT(l_net)->seed_aliases_count) : NULL;
        for(size_t i = 0; i < PVT(l_net)->seed_aliases_count; i++) {
            l_net_pvt->seed_aliases[i] = dap_strdup(l_seed_aliases[i]);
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
        uint16_t l_bootstrap_nodes_len = 0;
        char **l_bootstrap_nodes = dap_config_get_array_str(l_cfg, "general", "bootstrap_hostnames", &l_bootstrap_nodes_len);

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
                l_net_pvt->seed_aliases_count,l_seed_nodes_addrs_len, l_seed_nodes_ipv4_len );
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
            l_seed_node_addr = dap_chain_node_alias_find(l_net, l_net_pvt->seed_aliases[i] );
            //if (l_seed_node_addr == NULL){
                log_it(L_NOTICE, "Update alias %s in database, prefill it",l_net_pvt->seed_aliases[i]);
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
                    #ifdef DAP_OS_BSD
                	l_node_info->hdr.ext_addr_v6.__u6_addr.__u6_addr32[0]
                    #else
                        l_node_info->hdr.ext_addr_v6.s6_addr32[0] 
                    #endif
                            ){
                        int l_ret;
                        if ( (l_ret = dap_chain_node_info_save(l_net, l_node_info)) ==0 ){
                            if (dap_chain_node_alias_register(l_net,l_net_pvt->seed_aliases[i],l_seed_node_addr))
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
            /*}else{
                log_it(L_DEBUG,"Seed alias %s is present",PVT(l_net)->seed_aliases[i]);
                dap_chain_node_info_t * l_node_info= dap_chain_node_info_read(l_net,l_seed_node_addr);
                l_node
                DAP_DELETE( l_seed_node_addr);
            }*/
        }
        PVT(l_net)->bootstrap_nodes_count = 0;
        PVT(l_net)->bootstrap_nodes_addrs = DAP_NEW_SIZE(struct in_addr, l_bootstrap_nodes_len * sizeof(struct in_addr));
        PVT(l_net)->bootstrap_nodes_ports = DAP_NEW_SIZE(uint16_t, l_bootstrap_nodes_len * sizeof(uint16_t));
        for (int i = 0; i < l_bootstrap_nodes_len; i++) {
            char *l_bootstrap_port_str = strchr(l_bootstrap_nodes[i], ':');
            if (!l_bootstrap_port_str) {
                continue;
            }
            uint16_t l_bootstrap_port = atoi(l_bootstrap_port_str + 1);
            if (!l_bootstrap_port) {
                continue;
            }
            int l_bootstrap_name_len = l_bootstrap_port_str - l_bootstrap_nodes[i];
            char *l_bootstrap_name = DAP_NEW_SIZE(char, l_bootstrap_name_len + 1);
            strncpy(l_bootstrap_name, l_bootstrap_nodes[i], l_bootstrap_name_len);
            struct in_addr l_bootstrap_addr;
            if (dap_net_resolve_host(l_bootstrap_name, AF_INET, (struct sockaddr* )&l_bootstrap_addr) == 0) {
                PVT(l_net)->bootstrap_nodes_addrs[PVT(l_net)->bootstrap_nodes_count] = l_bootstrap_addr;
                PVT(l_net)->bootstrap_nodes_ports[PVT(l_net)->bootstrap_nodes_count] = l_bootstrap_port;
                PVT(l_net)->bootstrap_nodes_count++;
            }
            DAP_DELETE(l_bootstrap_name);
        }
        if ( l_node_addr_str || l_node_alias_str ){
            dap_chain_node_addr_t * l_node_addr;
            if ( l_node_addr_str == NULL)
                l_node_addr = dap_chain_node_alias_find(l_net, l_node_alias_str);
            else{
                l_node_addr = DAP_NEW_Z(dap_chain_node_addr_t);
                bool parse_succesfully = false;
                if ( sscanf(l_node_addr_str, "0x%016" DAP_UINT64_FORMAT_x ,&l_node_addr->uint64 ) == 1 ){
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
                if(l_node_addr)
                    log_it(L_NOTICE, "Parse node addr " NODE_ADDR_FP_STR " successfully", NODE_ADDR_FP_ARGS(l_node_addr));
                l_net_pvt->node_addr = l_node_addr;

            }
            if ( l_node_addr ) {
                char *l_addr_hash_str = dap_chain_node_addr_to_hash_str(l_node_addr);
                // save current node address
                dap_db_set_cur_node_addr(l_node_addr->uint64, l_net->pub.name);
                if(!l_addr_hash_str){
                    log_it(L_ERROR,"Can't get hash string for node address!");
                } else {
                    l_net_pvt->node_info = dap_chain_node_info_read (l_net, l_node_addr);
                    if ( !l_net_pvt->node_info ) { // If not present - create it
                        l_net_pvt->node_info = DAP_NEW_Z(dap_chain_node_info_t);
                        memcpy(&l_net_pvt->node_info->hdr.address, l_node_addr,sizeof (*l_node_addr));
                        if (dap_config_get_item_bool_default(g_config,"server","enabled",false) ){
                            const char * l_ext_addr_v4 = dap_config_get_item_str_default(g_config,"server","ext_address",NULL);
                            const char * l_ext_addr_v6 = dap_config_get_item_str_default(g_config,"server","ext_address6",NULL);
                            uint16_t l_ext_port = dap_config_get_item_uint16_default(g_config,"server","ext_port_tcp",0);
                            uint16_t l_node_info_port = l_ext_port? l_ext_port :
                                                    dap_config_get_item_uint16_default(g_config,"server","listen_port_tcp",8089);
                            if (l_ext_addr_v4)
                                inet_pton(AF_INET,l_ext_addr_v4,&l_net_pvt->node_info->hdr.ext_addr_v4 );
                            if (l_ext_addr_v6)
                                inet_pton(AF_INET6,l_ext_addr_v6,&l_net_pvt->node_info->hdr.ext_addr_v6 );
                            l_net_pvt->node_info->hdr.ext_port =l_node_info_port;
                            log_it(L_INFO,"Server is enabled on %s:%u",l_ext_addr_v4?l_ext_addr_v4:"<none>",
                                   l_node_info_port);
                        }else
                            log_it(L_INFO,"Server is disabled, add only node address in nodelist");

                        dap_chain_node_info_save(l_net,l_net_pvt->node_info);
                    }
                    log_it(L_NOTICE,"GDB Info: node_addr: " NODE_ADDR_FP_STR"  links: %u cell_id: 0x%016X ",
                           NODE_ADDR_FP_ARGS(l_node_addr),
                           l_net_pvt->node_info->hdr.links_number,
                           l_net_pvt->node_info->hdr.cell_id.uint64);
                    // save cell_id
                    l_net->pub.cell_id.uint64 = l_net_pvt->node_info->hdr.cell_id.uint64;
                }
            }
            else{
                log_it(L_WARNING, "Not present our own address %s in database", (l_node_alias_str) ? l_node_alias_str: "");
            }


         }
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
            l_net_pvt->load_mode = false;

            return -2;
        }
        // Do specific role actions post-chain created
        l_net_pvt->state_target = NET_STATE_OFFLINE;
        dap_chain_net_state_t l_target_state = NET_STATE_OFFLINE;
        switch ( l_net_pvt->node_role.enums ) {
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

                l_target_state = NET_STATE_ONLINE;
                log_it(L_INFO,"Root node role established");
            } break;
            case NODE_ROLE_CELL_MASTER:
            case NODE_ROLE_MASTER:{

                uint16_t l_proc_chains_count=0;
                char ** l_proc_chains = dap_config_get_array_str(l_cfg,"role-master" , "proc_chains", &l_proc_chains_count );
                for ( size_t i = 0; i< l_proc_chains_count ; i++){
                    dap_chain_id_t l_chain_id = {{0}};
                    if(dap_sscanf( l_proc_chains[i], "0x%16"DAP_UINT64_FORMAT_X,  &l_chain_id.uint64) ==1 || dap_scanf("0x%16"DAP_UINT64_FORMAT_x,  &l_chain_id.uint64) == 1){
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

                l_target_state = NET_STATE_ONLINE;
                log_it(L_INFO,"Master node role established");
            } break;
            case NODE_ROLE_FULL:{
                log_it(L_INFO,"Full node role established");
                l_target_state = NET_STATE_ONLINE;
            } break;
            case NODE_ROLE_LIGHT:
            default:
                log_it(L_INFO,"Light node role established");

        }

        if (s_seed_mode || !dap_config_get_item_bool_default(g_config ,"general", "auto_online",false ) ) { // If we seed we do everything manual. First think - prefil list of node_addrs and its aliases
            l_target_state = NET_STATE_OFFLINE;
        }
        l_net_pvt->load_mode = false;

        if (l_target_state != l_net_pvt->state_target)
            dap_chain_net_state_go_to(l_net, l_target_state);

        // Start the proc thread
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
    if(*a_size){
        dap_chain_net_t **l_net_list = DAP_NEW_SIZE(dap_chain_net_t *, (*a_size) * sizeof(dap_chain_net_t *));
        dap_chain_net_item_t *l_current_item, *l_tmp;
        int i = 0;
        HASH_ITER(hh, s_net_items, l_current_item, l_tmp) {
            l_net_list[i++] = l_current_item->chain_net;
            if(i > *a_size)
                break;
        }
        return l_net_list;
    }else
        return NULL;
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
    return l_net_item ? l_net_item->chain_net : NULL;
}

/**
 * @brief dap_chain_ledger_by_net_name
 * @param a_net_name
 * @return
 */
dap_ledger_t * dap_chain_ledger_by_net_name( const char * a_net_name)
{
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    return l_net ? l_net->pub.ledger : NULL;
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
    return l_net_item ? l_net_item->chain_net : NULL;
}

/**
 * @brief dap_chain_net_by_id
 * @param a_id
 * @return
 */
uint16_t dap_chain_net_acl_idx_by_id(dap_chain_net_id_t a_id)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_id);
    return l_net ? PVT(l_net)->acl_idx : (uint16_t)-1;
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
 * @brief dap_chain_net_get_state
 * @param l_net
 * @return
 */
dap_chain_net_state_t dap_chain_net_get_state ( dap_chain_net_t * l_net)
{
    assert(l_net);
    pthread_rwlock_rdlock(&PVT(l_net)->rwlock);
    dap_chain_net_state_t l_ret = PVT(l_net)->state;
    pthread_rwlock_unlock(&PVT(l_net)->rwlock);
    return l_ret;
}

/**
 * @brief dap_chain_net_set_state
 * @param l_net
 * @param a_state
 */
void dap_chain_net_set_state ( dap_chain_net_t * l_net, dap_chain_net_state_t a_state)
{
    assert(l_net);
    log_it(L_DEBUG,"%s set state %s", l_net->pub.name, dap_chain_net_state_to_str(a_state)  );
    pthread_rwlock_wrlock(&PVT(l_net)->rwlock);
    if( a_state == PVT(l_net)->state){
        pthread_rwlock_unlock(&PVT(l_net)->rwlock);
        return;
    }
    PVT(l_net)->state = a_state;
    pthread_rwlock_unlock(&PVT(l_net)->rwlock);
    dap_proc_queue_add_callback(dap_events_worker_get_auto(), s_net_states_proc,l_net );
}


/**
 * @brief dap_chain_net_get_cur_addr
 * @param l_net
 * @return
 */
dap_chain_node_addr_t * dap_chain_net_get_cur_addr( dap_chain_net_t * l_net)
{
    return l_net ? (PVT(l_net)->node_info ? &PVT(l_net)->node_info->hdr.address : PVT(l_net)->node_addr) : NULL;
}

uint64_t dap_chain_net_get_cur_addr_int(dap_chain_net_t * l_net)
{
    if (!l_net)
        return 0;
    return dap_chain_net_get_cur_addr(l_net) ? dap_chain_net_get_cur_addr(l_net)->uint64 :
                                               dap_db_get_cur_node_addr(l_net->pub.name);
}

dap_chain_cell_id_t * dap_chain_net_get_cur_cell( dap_chain_net_t * l_net)
{
    return  PVT(l_net)->node_info ? &PVT(l_net)->node_info->hdr.cell_id: 0;
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
}

/**
 * @brief dap_chain_net_set_flag_sync_from_zero
 * @param a_net
 * @param a_flag_sync_from_zero
 */
void dap_chain_net_set_flag_sync_from_zero( dap_chain_net_t * a_net, bool a_flag_sync_from_zero)
{
    if( a_flag_sync_from_zero)
        PVT(a_net)->flags |= F_DAP_CHAIN_NET_SYNC_FROM_ZERO;
    else
        PVT(a_net)->flags ^= F_DAP_CHAIN_NET_SYNC_FROM_ZERO;
}

/**
 * @brief dap_chain_net_get_flag_sync_from_zero
 * @param a_net
 * @return
 */
bool dap_chain_net_get_flag_sync_from_zero( dap_chain_net_t * a_net)
{
    return PVT(a_net)->flags &F_DAP_CHAIN_NET_SYNC_FROM_ZERO ;
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
                        char buf[50] = { '\0' };
                        const char *l_type = NULL;
                        DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_type)
                        time_t l_ts_create = (time_t) l_datum->header.ts_create;
                        log_it(L_INFO, "\t\t0x%s: type_id=%s ts_create=%s data_size=%u",
                                l_objs[i].key, l_type,
                                dap_ctime_r(&l_ts_create, buf), l_datum->header.data_size);
                    }
                }
            }
            size_t l_objs_processed = l_chain->callback_add_datums(l_chain, l_datums, l_datums_size);
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
void dap_chain_net_dump_datum(dap_string_t * a_str_out, dap_chain_datum_t * a_datum, const char *a_hash_out_type)
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
            dap_hash_fast_t l_hash ={0};
            switch (l_token->type) {
                case DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE:{
                    dap_string_append_printf(a_str_out, "type: SIMPLE\n");
                    dap_string_append_printf(a_str_out, "sign_total: %u\n", l_token->header_private.signs_total );
                    dap_string_append_printf(a_str_out, "sign_valid: %u\n", l_token->header_private.signs_valid );
                    dap_string_append_printf(a_str_out, "total_supply: %u\n", l_token->header_private.total_supply );
                }break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE:{
                    dap_string_append_printf(a_str_out,"type: PRIVATE_UPDATE\n");
                    dap_tsd_t * l_tsd = dap_chain_datum_token_tsd_get(l_token, l_token_size);
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
                                                                     dap_tsd_get_scalar(l_tsd, uint16_t));
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS:
                                    dap_string_append_printf(a_str_out,"flags_unset: ");
                                    dap_chain_datum_token_flags_dump(a_str_out,
                                                                     dap_tsd_get_scalar(l_tsd, uint16_t));
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY:
                                    dap_string_append_printf(a_str_out,"total_supply: %u\n",
                                                             dap_tsd_get_scalar(l_tsd, uint128_t) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID :
                                    dap_string_append_printf(a_str_out,"total_signs_valid: %u\n",
                                                             dap_tsd_get_scalar(l_tsd, uint16_t) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_ADD :
                                    if(l_tsd->size == sizeof(dap_chain_hash_fast_t) ){
                                        char *l_hash_str;
                                        if(!dap_strcmp(a_hash_out_type, "hex") || !dap_strcmp(a_hash_out_type, "content_hash") )
                                            l_hash_str = dap_chain_hash_fast_to_str_new((dap_chain_hash_fast_t*) l_tsd->data);
                                        else
                                            l_hash_str = dap_enc_base58_encode_hash_to_str((dap_chain_hash_fast_t*) l_tsd->data);
                                        dap_string_append_printf(a_str_out,"total_signs_add: %s\n", l_hash_str );
                                        DAP_DELETE( l_hash_str );
                                    }else
                                        dap_string_append_printf(a_str_out,"total_signs_add: <WRONG SIZE %zd>\n", l_tsd->size);
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_REMOVE :
                                    if(l_tsd->size == sizeof(dap_chain_hash_fast_t) ){
                                        char *l_hash_str;
                                        if(!dap_strcmp(a_hash_out_type,"hex")|| !dap_strcmp(a_hash_out_type, "content_hash"))
                                            l_hash_str = dap_chain_hash_fast_to_str_new((dap_chain_hash_fast_t*) l_tsd->data);
                                        else
                                            l_hash_str = dap_enc_base58_encode_hash_to_str((dap_chain_hash_fast_t*) l_tsd->data);
                                        dap_string_append_printf(a_str_out,"total_signs_remove: %s\n", l_hash_str );
                                        DAP_DELETE( l_hash_str );
                                    }else
                                        dap_string_append_printf(a_str_out,"total_signs_add: <WRONG SIZE %zd>\n", l_tsd->size);
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD  :
                                    dap_string_append_printf(a_str_out,"datum_type_allowed_add: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_REMOVE  :
                                    dap_string_append_printf(a_str_out,"datum_type_allowed_remove: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD  :
                                    dap_string_append_printf(a_str_out,"datum_type_blocked_add: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_REMOVE:
                                    dap_string_append_printf(a_str_out,"datum_type_blocked_remove: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD:
                                    dap_string_append_printf(a_str_out,"tx_sender_allowed_add: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE:
                                    dap_string_append_printf(a_str_out,"tx_sender_allowed_remove: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD:
                                    dap_string_append_printf(a_str_out,"tx_sender_blocked_add: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE:
                                    dap_string_append_printf(a_str_out,"tx_sender_blocked_remove: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:
                                    dap_string_append_printf(a_str_out,"tx_receiver_allowed_add: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE:
                                    dap_string_append_printf(a_str_out,"tx_receiver_allowed: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD:
                                    dap_string_append_printf(a_str_out, "tx_receiver_blocked_add: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE:
                                    dap_string_append_printf(a_str_out, "tx_receiver_blocked_remove: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                default: dap_string_append_printf(a_str_out, "<0x%04X>: <size %zd>\n", l_tsd->type, l_tsd->size);
                            }
                            l_offset += dap_tsd_size(l_tsd);

                        }
                    }
                }break;
                case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL:{
                    dap_string_append_printf(a_str_out,"type: PRIVATE_DECL\n");
                    dap_string_append_printf(a_str_out,"flags: ");
                    dap_chain_datum_token_flags_dump(a_str_out, l_token->header_private_decl.flags);
                    dap_tsd_t * l_tsd_first = dap_chain_datum_token_tsd_get(l_token, l_token_size);
                    if (l_tsd_first == NULL)
                        dap_string_append_printf(a_str_out,"<CORRUPTED TSD SECTION>\n");
                    else{
                        size_t l_offset = 0;
                        size_t l_offset_max = l_token->header_private_decl.tsd_total_size;
                        while( l_offset< l_offset_max){
                            dap_tsd_t * l_tsd = (void*)l_tsd_first + l_offset;
                            if ( (l_tsd->size+l_offset) >l_offset_max){
                                log_it(L_WARNING, "<CORRUPTED TSD> too big size %zd when left maximum %zd",
                                       l_tsd->size, l_offset_max - l_offset);
                                return;
                            }
                            switch( l_tsd->type){
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY:
                                    dap_string_append_printf(a_str_out,"total_supply: %lu\n",
                                                             dap_tsd_get_scalar(l_tsd, uint128_t) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID :
                                    dap_string_append_printf(a_str_out,"total_signs_valid: %u\n",
                                                             dap_tsd_get_scalar(l_tsd, uint16_t) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD  :
                                    dap_string_append_printf(a_str_out,"datum_type_allowed: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD  :
                                    dap_string_append_printf(a_str_out,"datum_type_blocked: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD:
                                    dap_string_append_printf(a_str_out,"tx_sender_allowed: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD:
                                    dap_string_append_printf(a_str_out,"tx_sender_blocked: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD:
                                    dap_string_append_printf(a_str_out,"tx_receiver_allowed: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD:
                                    dap_string_append_printf(a_str_out, "tx_receiver_blocked: %s\n",
                                                             dap_tsd_get_string_const(l_tsd) );
                                break;
                                default: dap_string_append_printf(a_str_out, "<0x%04X>: <size %zd>\n", l_tsd->type, l_tsd->size);
                            }
                            l_offset += dap_tsd_size(l_tsd);

                        }
                    }

                    size_t l_certs_field_size = l_token_size - sizeof(*l_token) - l_token->header_private_decl.tsd_total_size;
                    dap_chain_datum_token_certs_dump(a_str_out, l_token->data_n_tsd, l_certs_field_size);
                }break;
                case DAP_CHAIN_DATUM_TX:{
                    dap_chain_datum_tx_t * l_tx =(dap_chain_datum_tx_t *) a_datum->data;
                    char buf[50];
                    time_t l_ts_created = l_tx->header.ts_created;
                    dap_string_append_printf(a_str_out,"type: TX\n");
                    dap_string_append_printf(a_str_out,"type: ts_created: %s \n", dap_ctime_r(&l_ts_created, buf));
                    int l_items_count = -1;
                    dap_list_t * l_items = dap_chain_datum_tx_items_get(l_tx,TX_ITEM_TYPE_ANY,&l_items_count);
                    dap_string_append_printf(a_str_out,"type: items_count: %d \n", l_items_count );
                    if (l_items_count>0){
                        size_t n=0;
                        for( dap_list_t * l_cur = l_items; l_cur; l_cur = l_cur->next ){
                            dap_string_append_printf(a_str_out,"Item #%zd\n",n);
                            byte_t *l_tx_item = l_cur->data;
                            dap_chain_tx_item_type_t l_item_type = dap_chain_datum_tx_item_get_type(l_tx_item);
                            dap_string_append_printf(a_str_out,"\ttype: %s \n",
                                                     dap_chain_datum_tx_item_type_to_str (l_item_type) );
                            switch (l_item_type) {
                                case TX_ITEM_TYPE_IN:{
                                    dap_chain_tx_in_t * l_in = l_cur->data;
                                    dap_string_append_printf(a_str_out,"\ttx_out_prev_idx: %u\n", l_in->header.tx_out_prev_idx );
                                    dap_string_append_printf(a_str_out,"\ttx_out_prev_idx : %u\n", l_in->header.tx_prev_hash );
                                    char l_tx_prev_hash_str[70]={[0]='\0'};
                                    dap_hash_fast_to_str(&l_in->header.tx_prev_hash, l_tx_prev_hash_str,sizeof (l_tx_prev_hash_str)-1);
                                    dap_string_append_printf(a_str_out,"\ttx_prev_hash : %s\n", l_tx_prev_hash_str );
                                } break;
                                case TX_ITEM_TYPE_OUT:{
                                    dap_chain_tx_out_t * l_out = l_cur->data;
                                    dap_string_append_printf(a_str_out,"\tvalue: %u\n", l_out->header.value );
                                    char * l_addr_str = dap_chain_addr_to_str(&l_out->addr);
                                    dap_string_append_printf(a_str_out,"\taddr : %s\n", l_addr_str );
                                    DAP_DELETE(l_addr_str);
                                } break;
                                case TX_ITEM_TYPE_OUT_EXT:{
                                    dap_chain_tx_out_ext_t * l_out_ext = l_cur->data;
                                    dap_string_append_printf(a_str_out,"\tvalue: %u\n", l_out_ext->header.value );
                                    char * l_addr_str = dap_chain_addr_to_str(&l_out_ext->addr);
                                    dap_string_append_printf(a_str_out,"\taddr : %s\n", l_addr_str );
                                    dap_string_append_printf(a_str_out,"\ttoken : %s\n", l_out_ext->token );
                                    DAP_DELETE(l_addr_str);
                                } break;
                                case TX_ITEM_TYPE_SIG:{
                                    dap_chain_tx_sig_t * l_item_sign = l_cur->data;
                                    dap_sign_t *l_sign = (dap_sign_t *)l_item_sign->sig;
                                    dap_hash_fast_t l_sign_hash;
                                    char l_sign_hash_str[70]={[0]='\0'};
                                    dap_string_append_printf(a_str_out,"\tsig_size: %u\n", l_item_sign->header.sig_size );
                                    dap_string_append_printf(a_str_out,"\ttype: %s\n", dap_sign_type_to_str(l_sign->header.type) );
                                    dap_sign_get_pkey_hash(l_sign,&l_sign_hash);
                                    dap_hash_fast_to_str(&l_sign_hash,l_sign_hash_str,sizeof (l_sign_hash_str)-1);
                                    dap_string_append_printf(a_str_out,"\tpkey_hash: %s\n", l_sign_hash_str );
                                } break;
                                case TX_ITEM_TYPE_TOKEN:{
                                    dap_chain_tx_token_t * l_token = l_cur->data;
                                    dap_string_append_printf(a_str_out,"\tticker: %s\n", l_token->header.ticker );
                                    dap_string_append_printf(a_str_out,"\ttoken_emission_chain: 0x%016x\n", l_token->header.token_emission_chain_id );
                                    char l_token_emission_hash_str[70]={ [0]='\0'};
                                    dap_chain_hash_fast_to_str(& l_token->header.token_emission_hash,l_token_emission_hash_str,
                                                               sizeof (l_token_emission_hash_str)-1);
                                    dap_string_append_printf(a_str_out,"\ttoken_emission_hash: %s", l_token_emission_hash_str );
                                } break;
                                case TX_ITEM_TYPE_TOKEN_EXT:{
                                    dap_chain_tx_token_ext_t * l_token = l_cur->data;
                                    dap_string_append_printf(a_str_out,"\tversion: %u\n",l_token->header.version );
                                    dap_string_append_printf(a_str_out,"\tticker: %s\n", l_token->header.ticker );
                                    dap_string_append_printf(a_str_out,"\text_net: 0x%016x\n",l_token->header.ext_net_id );
                                    dap_string_append_printf(a_str_out,"\text_chain: 0x%016x\n",l_token->header.ext_chain_id  );
                                    dap_string_append_printf(a_str_out,"\text_tx_out_idx: %u\n",l_token->header.ext_tx_out_idx  );
                                    char l_token_emission_hash_str[70]={ [0]='\0'};
                                    dap_chain_hash_fast_to_str(& l_token->header.ext_tx_hash,l_token_emission_hash_str,
                                                               sizeof (l_token_emission_hash_str)-1);
                                    dap_string_append_printf(a_str_out,"\text_tx_hash: %s", l_token_emission_hash_str );
                                } break;
                                case TX_ITEM_TYPE_IN_COND:{
                                    dap_chain_tx_in_cond_t * l_in = l_cur->data;
                                    dap_string_append_printf(a_str_out,"\ttx_out_prev_idx: %u\n", l_in->header.tx_out_prev_idx );
                                    dap_string_append_printf(a_str_out,"\ttx_out_prev_idx : %u\n", l_in->header.tx_prev_hash );
                                    dap_string_append_printf(a_str_out,"\treceipt_idx : %u\n", l_in->header.receipt_idx );
                                    char l_tx_prev_hash_str[70]={[0]='\0'};
                                    dap_hash_fast_to_str(&l_in->header.tx_prev_hash, l_tx_prev_hash_str,sizeof (l_tx_prev_hash_str)-1);
                                    dap_string_append_printf(a_str_out,"\ttx_prev_hash : %s\n", l_tx_prev_hash_str );
                                } break;
                                case TX_ITEM_TYPE_OUT_COND:{
                                    dap_chain_tx_out_cond_t * l_out = l_cur->data;
                                    dap_string_append_printf(a_str_out,"\tvalue: %u\n", l_out->header.value );
                                    switch ( l_out->header.subtype){
                                        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY:{
                                            dap_string_append_printf(a_str_out,"\tsubtype: DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY\n");
                                            dap_string_append_printf(a_str_out,"\tsrv_uid: 0x%016x\n", l_out->subtype.srv_pay.srv_uid.uint64 );
                                            switch (l_out->subtype.srv_pay.unit.enm) {
                                                case SERV_UNIT_UNDEFINED: dap_string_append_printf(a_str_out,"\tunit: SERV_UNIT_UNDEFINED\n"); break;
                                                case SERV_UNIT_MB: dap_string_append_printf(a_str_out,"\tunit: SERV_UNIT_MB\n"); break;
                                                case SERV_UNIT_SEC: dap_string_append_printf(a_str_out,"\tunit: SERV_UNIT_SEC\n"); break;
                                                case SERV_UNIT_DAY: dap_string_append_printf(a_str_out,"\tunit: SERV_UNIT_DAY\n"); break;
                                                case SERV_UNIT_KB: dap_string_append_printf(a_str_out,"\tunit: SERV_UNIT_KB\n"); break;
                                                case SERV_UNIT_B : dap_string_append_printf(a_str_out,"\tunit: SERV_UNIT_B\n"); break;
                                                default: dap_string_append_printf(a_str_out,"\tunit: SERV_UNIT_UNKNOWN\n"); break;
                                            }
                                            dap_string_append_printf(a_str_out,"\tunit_price_max: %"DAP_UINT64_FORMAT_U"\n", l_out->subtype.srv_pay.unit_price_max_datoshi);
                                            char l_pkey_hash_str[70]={[0]='\0'};
                                            dap_chain_hash_fast_to_str(&l_out->subtype.srv_pay.pkey_hash, l_pkey_hash_str, sizeof (l_pkey_hash_str)-1);
                                            dap_string_append_printf(a_str_out,"\tpkey_hash: %s\n", l_pkey_hash_str );
                                        }break;
                                        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE:{
                                            dap_string_append_printf(a_str_out,"\tsubtype: DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE\n");
                                        }break;
                                        case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE:{
                                            dap_string_append_printf(a_str_out,"\tsubtype: DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE\n");
                                        }break;
                                    }
                                    dap_string_append_printf(a_str_out,"\tparams_size : %u\n", l_out->params_size );
                                } break;
                                case TX_ITEM_TYPE_RECEIPT:{} break;
                                default:{}
                            }
                            n++;
                        }
                    }
                    dap_list_free(l_items);


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

static bool s_net_check_acl(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_pkey_hash)
{
    const char l_path[] = "network/";
    char l_cfg_path[strlen(a_net->pub.name) + strlen(l_path) + 1];
    strcpy(l_cfg_path, l_path);
    strcat(l_cfg_path, a_net->pub.name);
    dap_config_t *l_cfg = dap_config_open(l_cfg_path);
    const char *l_auth_type = dap_config_get_item_str(l_cfg, "auth", "type");
    bool l_authorized = true;
    if (l_auth_type && !strcmp(l_auth_type, "ca")) {
        if (dap_hash_fast_is_blank(a_pkey_hash)) {
            return false;
        }
        l_authorized = false;
        const char *l_auth_hash_str = dap_chain_hash_fast_to_str_new(a_pkey_hash);
        uint16_t l_acl_list_len = 0;
        char **l_acl_list = dap_config_get_array_str(l_cfg, "auth", "acl_accept_ca_list", &l_acl_list_len);
        for (uint16_t i = 0; i < l_acl_list_len; i++) {
            if (!strcmp(l_acl_list[i], l_auth_hash_str)) {
                l_authorized = true;
                break;
            }
        }
        if (!l_authorized) {
            const char *l_acl_gdb = dap_config_get_item_str(l_cfg, "auth", "acl_accept_ca_gdb");
            if (l_acl_gdb) {
                size_t l_objs_count;
                dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(l_acl_gdb, &l_objs_count);
                for (size_t i = 0; i < l_objs_count; i++) {
                    if (!strcmp(l_objs[i].key, l_auth_hash_str)) {
                        l_authorized = true;
                        break;
                    }
                }
                dap_chain_global_db_objs_delete(l_objs, l_objs_count);
            }
        }
        if (!l_authorized) {
            const char *l_acl_chains = dap_config_get_item_str(l_cfg, "auth", "acl_accept_ca_chains");
            if (l_acl_chains && !strcmp(l_acl_chains, "all")) {
                dap_list_t *l_certs = dap_cert_get_all_mem();
                for (dap_list_t *l_tmp = l_certs; l_tmp; l_tmp = dap_list_next(l_tmp)) {
                    dap_cert_t *l_cert = (dap_cert_t *)l_tmp->data;
                    size_t l_pkey_size;
                    uint8_t *l_pkey_ser = dap_enc_key_serealize_pub_key(l_cert->enc_key, &l_pkey_size);
                    dap_chain_hash_fast_t l_cert_hash;
                    dap_hash_fast(l_pkey_ser, l_pkey_size, &l_cert_hash);
                    if (!memcmp(l_pkey_ser, a_pkey_hash, sizeof(dap_chain_hash_fast_t))) {
                        l_authorized = true;
                        DAP_DELETE(l_pkey_ser);
                        break;
                    }
                    DAP_DELETE(l_pkey_ser);
                }
            }
        }
    }
    return l_authorized;
}

static uint8_t *dap_chain_net_set_acl(dap_chain_hash_fast_t *a_pkey_hash)
{
    uint16_t l_net_count;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    if (l_net_count && l_net_list) {
        uint8_t *l_ret = DAP_NEW_SIZE(uint8_t, l_net_count);
        for (uint16_t i = 0; i < l_net_count; i++) {
            l_ret[i] = s_net_check_acl(l_net_list[i], a_pkey_hash);
        }
        DAP_DELETE(l_net_list);
        return l_ret;
    }
    return NULL;
}
