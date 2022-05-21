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

#include "json-c/json.h"
#include "json-c/json_object.h"

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
static bool s_debug_more = false;

struct link_dns_request {
    //uint32_t link_id; // not used
    dap_chain_net_t * net;
    uint_fast16_t tries;
};

struct net_link {
    dap_chain_node_info_t *link_info;
    dap_chain_node_client_t *link;
};

struct downlink {
    dap_stream_worker_t *worker;
    dap_stream_ch_uuid_t uuid;
    UT_hash_handle hh;
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

    //Active synchronizing link
    dap_chain_node_client_t *active_link;
    dap_list_t *links_queue;            // Links waiting for sync

    dap_list_t *net_links;              // Links list
    size_t links_connected_count;
    bool only_static_links;

    struct downlink *downlinks;             // List of links who sent SYNC REQ, it used for sync broadcasting
    dap_list_t *records_queue;
    dap_list_t *atoms_queue;

    atomic_uint links_dns_requests;

    bool load_mode;
    char ** seed_aliases;

    uint16_t bootstrap_nodes_count;
    struct in_addr *bootstrap_nodes_addrs;
    uint16_t *bootstrap_nodes_ports;

    uint16_t gdb_sync_groups_count;
    uint16_t gdb_sync_nodes_addrs_count;
    uint16_t gdb_sync_nodes_links_count;
    char **gdb_sync_groups;
    dap_chain_node_addr_t *gdb_sync_nodes_addrs;
    uint32_t *gdb_sync_nodes_links_ips;
    uint16_t *gdb_sync_nodes_links_ports;

    uint16_t seed_aliases_count;

    dap_chain_net_state_t state;
    dap_chain_net_state_t state_target;
    uint16_t acl_idx;

    // Main loop timer
    dap_timerfd_t * main_timer;

    // General rwlock for structure
    pthread_rwlock_t rwlock;

    dap_list_t *gdb_notifiers;
} dap_chain_net_pvt_t;

typedef struct dap_chain_net_item{
    char name [DAP_CHAIN_NET_NAME_MAX];
    dap_chain_net_id_t net_id;
    dap_chain_net_t * chain_net;
    UT_hash_handle hh;
} dap_chain_net_item_t;

#define PVT(a) ( (dap_chain_net_pvt_t *) (void*) a->pvt )
#define PVT_S(a) ( (dap_chain_net_pvt_t *) (void*) a.pvt )

pthread_rwlock_t    g_net_items_rwlock  = PTHREAD_RWLOCK_INITIALIZER,
                    g_net_ids_rwlock    = PTHREAD_RWLOCK_INITIALIZER;
static dap_chain_net_item_t     *s_net_items        = NULL,
                                *s_net_items_ids    = NULL;


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
    .error=s_node_link_callback_error,
    .delete=s_node_link_callback_delete
};


// State machine switchs here
static bool s_net_states_proc(dap_proc_thread_t *a_thread, void *a_arg);

// Notify about net states
struct json_object *net_states_json_collect(dap_chain_net_t * l_net);
static void s_net_states_notify(dap_chain_net_t * l_net);

// Prepare link success/error endpoints
static void s_net_state_link_prepare_success(dap_worker_t * a_worker,dap_chain_node_info_t * a_node_info, void * a_arg);
static void s_net_state_link_prepare_error(dap_worker_t * a_worker,dap_chain_node_info_t * a_node_info, void * a_arg, int a_errno);


// Replace link success/error callbacks
static void s_net_state_link_replace_success(dap_worker_t *a_worker,dap_chain_node_info_t *a_node_info, void *a_arg);
static void s_net_state_link_replace_error(dap_worker_t *a_worker,dap_chain_node_info_t *a_node_info, void *a_arg, int a_errno);


//static void s_net_proc_kill( dap_chain_net_t * a_net );
int s_net_load(const char * a_net_name, uint16_t a_acl_idx);

// Notify callback for GlobalDB changes
static void s_gbd_history_callback_notify (void * a_arg, const char a_op_code, const char * a_group,
                                                     const char * a_key, const void * a_value,
                                                     const size_t a_value_len);
static void s_chain_callback_notify(void * a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id, void *a_atom, size_t a_atom_size);

static int s_cli_net(int argc, char ** argv, char **str_reply);

static bool s_seed_mode = false;

static uint8_t *dap_chain_net_set_acl(dap_chain_hash_fast_t *a_pkey_hash);

static bool s_start_dns_request(dap_chain_net_t *a_net, dap_chain_node_info_t *a_link_node_info);

/**
 * @brief
 * init network settings from cellrame-node.cfg file
 * register net* commands in cellframe-node-cli interface
 * @return
 */
int dap_chain_net_init()
{
    dap_stream_ch_chain_init();
    dap_stream_ch_chain_net_init();
    dap_chain_node_client_init();
    dap_chain_node_cli_cmd_item_create ("net", s_cli_net, "Network commands",
        "net list [chains -n <chain net name>]"
            "\tList all networks or list all chains in selected network"
        "net -net <chain net name> [-mode {update | all}] go {online | offline | sync}\n"
            "\tFind and establish links and stay online. \n"
            "\tMode \"update\" is by default when only new chains and gdb are updated. Mode \"all\" updates everything from zero\n"
        "net -net <chain net name> get status\n"
            "\tLook at current status\n"
        "net -net <chain net name> stats tx [-from <From time>] [-to <To time>] [-prev_sec <Seconds>] \n"
            "\tTransactions statistics. Time format is <Year>-<Month>-<Day>_<Hours>:<Minutes>:<Seconds> or just <Seconds> \n"
        "net -net <chain net name> [-mode {update | all}] sync {all | gdb | chains}\n"
            "\tSyncronyze gdb, chains or everything\n"
            "\tMode \"update\" is by default when only new chains and gdb are updated. Mode \"all\" updates everything from zero\n"
        "net -net <chain net name> link {list | add | del | info | establish}\n"
            "\tList, add, del, dump or establish links\n"
        "net -net <chain net name> ca add {-cert <cert name> | -hash <cert hash>}\n"
            "\tAdd certificate to list of authority cetificates in GDB group\n"
        "net -net <chain net name> ca list\n"
            "\tPrint list of authority cetificates from GDB group\n"
        "net -net <chain net name> ca del -hash <cert hash> [-H {hex | base58(default)}]\n"
            "\tDelete certificate from list of authority cetificates in GDB group by it's hash\n"
        "net -net <chain net name> ledger reload\n"
            "\tPurge the cache of chain net ledger and recalculate it from chain file\n");
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);

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

/**
 * @brief get certificate hash from chain config [acl_accept_ca_gdb] param
 *
 * @param a_net dap_chain_net_t chain object
 * @return char*
 */
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
 * @brief convert dap_chain_net_state_t net state object to string
 *
 * @param l_state dap_chain_net_state_t
 * @return const char*
 */
inline static const char * s_net_state_to_str(dap_chain_net_state_t l_state)
{
    return c_net_states[l_state];
}

/**
 * @brief set current network state to F_DAP_CHAIN_NET_GO_SYNC
 *
 * @param a_net dap_chain_net_t network object
 * @param a_new_state dap_chain_net_state_t new network state
 * @return int
 */
int dap_chain_net_state_go_to(dap_chain_net_t * a_net, dap_chain_net_state_t a_new_state)
{
    if (PVT(a_net)->state != NET_STATE_OFFLINE){
        PVT(a_net)->state = PVT(a_net)->state_target = NET_STATE_OFFLINE;
        s_net_states_proc(NULL, a_net);
    }

    PVT(a_net)->state_target = a_new_state;

    pthread_mutex_lock( &PVT(a_net)->state_mutex_cond); // Preventing call of state_go_to before wait cond will be armed
    // set flag for sync
    PVT(a_net)->flags |= F_DAP_CHAIN_NET_GO_SYNC;
    //PVT(a_net)->flags |= F_DAP_CHAIN_NET_SYNC_FROM_ZERO;  // TODO set this flag according to -mode argument from command line
#ifndef _WIN32
    pthread_cond_signal( &PVT(a_net)->state_proc_cond );
#else
    SetEvent( PVT(a_net)->state_proc_cond );
#endif
    pthread_mutex_unlock( &PVT(a_net)->state_mutex_cond);
    dap_proc_queue_add_callback(dap_events_worker_get_auto(), s_net_states_proc, a_net);
    return 0;
}

dap_chain_net_state_t dap_chain_net_get_target_state(dap_chain_net_t *a_net)
{
    return PVT(a_net)->state_target;
}

/**
 * @brief set s_srv_callback_notify
 *
 * @param a_callback dap_global_db_obj_callback_notify_t callback function
 */
void dap_chain_net_add_gdb_notify_callback(dap_chain_net_t *a_net, dap_global_db_obj_callback_notify_t a_callback, void *a_cb_arg)
{
    dap_chain_gdb_notifier_t *l_notifier = DAP_NEW(dap_chain_gdb_notifier_t);
    l_notifier->callback = a_callback;
    l_notifier->cb_arg = a_cb_arg;
    PVT(a_net)->gdb_notifiers = dap_list_append(PVT(a_net)->gdb_notifiers, l_notifier);
}

int dap_chain_net_add_downlink(dap_chain_net_t *a_net, dap_stream_worker_t *a_worker, dap_stream_ch_uuid_t a_ch_uuid)
{
    if (!a_net || !a_worker)
        return -1;
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
    unsigned a_hash_value;
    HASH_VALUE(&a_ch_uuid, sizeof(a_ch_uuid), a_hash_value);
    struct downlink *l_downlink = NULL;
    pthread_rwlock_rdlock(&l_net_pvt->rwlock);
    HASH_FIND_BYHASHVALUE(hh, l_net_pvt->downlinks, &a_ch_uuid, sizeof(a_ch_uuid), a_hash_value, l_downlink);
    if (l_downlink) {
        pthread_rwlock_unlock(&l_net_pvt->rwlock);
        return -2;
    }
    l_downlink = DAP_NEW_Z(struct downlink);
    l_downlink->worker = a_worker;
    l_downlink->uuid = a_ch_uuid;
    HASH_ADD_BYHASHVALUE(hh, l_net_pvt->downlinks, uuid, sizeof(a_ch_uuid), a_hash_value, l_downlink);
    pthread_rwlock_unlock(&l_net_pvt->rwlock);
    return 0;
}

static bool s_net_send_records(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    dap_store_obj_t *l_obj, *l_arg = (dap_store_obj_t *)a_arg;
    dap_chain_net_t *l_net = (dap_chain_net_t *)l_arg->cb_arg;
    if (l_arg->type == DAP_DB$K_OPTYPE_DEL) {
        char *l_group = dap_strdup_printf("%s.del", l_arg->group);
        l_obj = dap_chain_global_db_obj_get(l_arg->key, l_group);
        DAP_DELETE(l_group);
    } else
        l_obj = dap_chain_global_db_obj_get(l_arg->key, l_arg->group);

    if (!l_obj) {
        log_it(L_DEBUG, "Notified GDB event does not exist");
        return true;
    }
    l_obj->type = l_arg->type;
    if (l_obj->type == DAP_DB$K_OPTYPE_DEL) {
        DAP_DELETE(l_obj->group);
        l_obj->group = l_arg->group;
    } else
        DAP_DELETE(l_arg->group);
    DAP_DELETE(l_arg->key);
    DAP_DELETE(l_arg);
    pthread_rwlock_wrlock(&PVT(l_net)->rwlock);
    if (PVT(l_net)->state) {
        dap_list_t *it = NULL;
        do {
            dap_store_obj_t *l_obj_cur = it ? (dap_store_obj_t *)it->data : l_obj;
            dap_chain_t *l_chain = NULL;
            if (l_obj_cur->type == DAP_DB$K_OPTYPE_ADD)
                l_chain = dap_chain_get_chain_from_group_name(l_net->pub.id, l_obj->group);
            dap_chain_id_t l_chain_id = l_chain ? l_chain->id : (dap_chain_id_t) {};
            dap_chain_cell_id_t l_cell_id = l_chain ? l_chain->cells->id : (dap_chain_cell_id_t){};
            if (!l_obj_cur->group)
                break;
            dap_store_obj_pkt_t *l_data_out = dap_store_packet_single(l_obj_cur);
            dap_store_obj_free_one(l_obj_cur);
            struct downlink *l_link, *l_tmp;
            HASH_ITER(hh, PVT(l_net)->downlinks, l_link, l_tmp) {
                dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(l_link->worker, l_link->uuid);
                if (!l_ch) {
                    HASH_DEL(PVT(l_net)->downlinks, l_link);
                    DAP_DELETE(l_link);
                    continue;
                }
                dap_stream_ch_chain_pkt_write_mt(l_link->worker, l_link->uuid, DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB, l_net->pub.id.uint64,
                                                     l_chain_id.uint64, l_cell_id.uint64, l_data_out,
                                                     sizeof(dap_store_obj_pkt_t) + l_data_out->data_size);
            }
            DAP_DELETE(l_data_out);
            if (it)
                PVT(l_net)->records_queue = dap_list_delete_link(PVT(l_net)->records_queue, it);
            it = PVT(l_net)->records_queue;
        } while (it);
    } else
        //PVT(l_net)->records_queue = dap_list_append(PVT(l_net)->records_queue, l_obj);
        dap_store_obj_free_one(l_obj);
    pthread_rwlock_unlock(&PVT(l_net)->rwlock);
    return true;
}

static void s_record_obj_free(void *a_obj) { return dap_store_obj_free_one((dap_store_obj_t *)a_obj); }

/**
 * @brief executes, when you add data to gdb and sends it to current network connected nodes
 * @param a_arg arguments. Can be network object (dap_chain_net_t)
 * @param a_op_code object type (f.e. l_net->type from dap_store_obj)
 * @param a_group group, for example "chain-gdb.home21-network.chain-F"
 * @param a_key key hex value, f.e. 0x12EFA084271BAA5EEE93B988E73444B76B4DF5F63DADA4B300B051E29C2F93
 * @param a_value buffer with data
 * @param a_value_len buffer size
 */
void dap_chain_net_sync_gdb_broadcast(void *a_arg, const char a_op_code, const char *a_group,
                                      const char *a_key, const void *a_value, const size_t a_value_len)
{
    UNUSED(a_value);
    UNUSED(a_value_len);
    if (!a_arg || !a_group || !a_key)
        return;
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    if (!HASH_COUNT(PVT(l_net)->downlinks)) {
        if (PVT(l_net)->records_queue) {
            pthread_rwlock_wrlock(&PVT(l_net)->rwlock);
            dap_list_free_full(PVT(l_net)->records_queue, s_record_obj_free);
            PVT(l_net)->records_queue = NULL;
            pthread_rwlock_unlock(&PVT(l_net)->rwlock);
        }
        return;
    }
    // Use it instead of new type definition to pack params in one callback arg
    dap_store_obj_t *l_obj = DAP_NEW(dap_store_obj_t);
    l_obj->type = a_op_code;
    l_obj->key = dap_strdup(a_key);
    l_obj->group = dap_strdup(a_group);
    l_obj->cb_arg = a_arg;
    dap_proc_queue_add_callback(dap_events_worker_get_auto(), s_net_send_records, l_obj);
}

static void s_atom_obj_free(void *a_atom_obj)
{
    dap_store_obj_t *l_obj = (dap_store_obj_t *)a_atom_obj;
    DAP_DELETE(l_obj->value);
    DAP_DELETE(l_obj);
}

static bool s_net_send_atoms(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    dap_store_obj_t *l_arg = (dap_store_obj_t *)a_arg;
    dap_chain_net_t *l_net = (dap_chain_net_t *)l_arg->cb_arg;
    pthread_rwlock_rdlock(&PVT(l_net)->rwlock);
    if (PVT(l_net)->state != NET_STATE_SYNC_CHAINS) {
        dap_list_t *it = NULL;
        do {
            dap_store_obj_t *l_obj_cur = it ? (dap_store_obj_t *)it->data : l_arg;
            dap_chain_t *l_chain = (dap_chain_t *)l_obj_cur->group;
            uint64_t l_cell_id = l_obj_cur->timestamp;
            struct downlink *l_link, *l_tmp;
            HASH_ITER(hh, PVT(l_net)->downlinks, l_link, l_tmp) {
                dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(l_link->worker, l_link->uuid);
                if (!l_ch) {
                    HASH_DEL(PVT(l_net)->downlinks, l_link);
                    DAP_DELETE(l_link);
                    continue;
                }
                dap_stream_ch_chain_pkt_write_mt(l_link->worker, l_link->uuid, DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN,
                                                 l_net->pub.id.uint64, l_chain->id.uint64, l_cell_id,
                                                 l_obj_cur->value, l_obj_cur->value_len);
            }
            s_atom_obj_free(l_obj_cur);
            if (it)
                PVT(l_net)->atoms_queue = dap_list_delete_link(PVT(l_net)->atoms_queue, it);
            it = PVT(l_net)->atoms_queue;
        } while (it);
    } else
        //PVT(l_net)->atoms_queue = dap_list_append(PVT(l_net)->atoms_queue, l_arg);
        s_atom_obj_free(a_arg);
    pthread_rwlock_unlock(&PVT(l_net)->rwlock);
    return true;
}

/**
 * @brief s_chain_callback_notify
 * @param a_arg
 * @param a_chain
 * @param a_id
 */
static void s_chain_callback_notify(void *a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id, void* a_atom, size_t a_atom_size)
{
    if (!a_arg)
        return;
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    if (!HASH_COUNT(PVT(l_net)->downlinks)) {
        if (PVT(l_net)->atoms_queue) {
            pthread_rwlock_wrlock(&PVT(l_net)->rwlock);
            dap_list_free_full(PVT(l_net)->atoms_queue, s_atom_obj_free);
            PVT(l_net)->atoms_queue = NULL;
            pthread_rwlock_unlock(&PVT(l_net)->rwlock);
        }
        return;
    }
    // Use it instead of new type definition to pack params in one callback arg
    dap_store_obj_t *l_obj = DAP_NEW(dap_store_obj_t);
    l_obj->timestamp = a_id.uint64;
    l_obj->value = DAP_DUP_SIZE(a_atom, a_atom_size);
    l_obj->value_len = a_atom_size;
    l_obj->group = (char *)a_chain;
    l_obj->cb_arg = a_arg;
    dap_proc_queue_add_callback(dap_events_worker_get_auto(), s_net_send_atoms, l_obj);
}

/**
 * @brief added like callback in dap_chain_global_db_add_sync_group
 *
 * @param a_arg arguments. Can be network object (dap_chain_net_t)
 * @param a_op_code object type (f.e. l_net->type from dap_store_obj)
 * @param a_group group, for example "chain-gdb.home21-network.chain-F"
 * @param a_key key hex value, f.e. 0x12EFA084271BAA5EEE93B988E73444B76B4DF5F63DADA4B300B051E29C2F93
 * @param a_value buffer with data
 * @param a_value_len buffer size
 */
static void s_gbd_history_callback_notify(void *a_arg, const char a_op_code, const char *a_group,
                                          const char *a_key, const void *a_value, const size_t a_value_len)
{
    if (!a_arg) {
        return;
    }
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    for (dap_list_t *it = PVT(l_net)->gdb_notifiers; it; it = it->next) {
        dap_chain_gdb_notifier_t *el = (dap_chain_gdb_notifier_t *)it->data;
        if (!el)
            continue;
        dap_global_db_obj_callback_notify_t l_callback = el->callback;
        if (l_callback)
            l_callback(el->cb_arg, a_op_code, a_group, a_key, a_value, a_value_len);
    }
    dap_chain_t *l_chain;
    DL_FOREACH(l_net->pub.chains, l_chain) {
        if (!l_chain) {
            continue;
        }
        char *l_gdb_group_str = dap_chain_net_get_gdb_group_mempool(l_chain);
        if (!strcmp(a_group, l_gdb_group_str)) {
            for (dap_list_t *it = DAP_CHAIN_PVT(l_chain)->mempool_notifires; it; it = it->next) {
                dap_chain_gdb_notifier_t *el = (dap_chain_gdb_notifier_t *)it->data;
                if (!el)
                    continue;
                dap_global_db_obj_callback_notify_t l_callback = el->callback;
                if (l_callback)
                    l_callback(el->cb_arg, a_op_code, a_group, a_key, a_value, a_value_len);
            }
        }
        DAP_DELETE(l_gdb_group_str);
    }
}

/**
 * @brief Get the possible number of links
 */
static size_t s_get_dns_max_links_count_from_cfg(dap_chain_net_t *a_net)
{
    dap_chain_net_pvt_t *l_net_pvt = a_net ? PVT(a_net) : NULL;
    if(!l_net_pvt)
        return 0;
    return (size_t)(l_net_pvt->seed_aliases_count + l_net_pvt->bootstrap_nodes_count);
}

/**
 * @brief Get one random link
 */
static dap_chain_node_info_t *s_get_dns_link_from_cfg(dap_chain_net_t *a_net)
{
    dap_chain_net_pvt_t *l_net_pvt = a_net ? PVT(a_net) : NULL;
    if(!l_net_pvt) return NULL;
    struct in_addr l_addr = {};
    uint16_t i, l_port;
    uint64_t l_node_adrr = 0;
    if (l_net_pvt->seed_aliases_count) {
        i = rand() % l_net_pvt->seed_aliases_count;
        dap_chain_node_addr_t *l_remote_addr = dap_chain_node_alias_find(a_net, l_net_pvt->seed_aliases[i]);
        if (l_remote_addr){
            dap_chain_node_info_t *l_remote_node_info = dap_chain_node_info_read(a_net, l_remote_addr);
            if(l_remote_node_info){
                l_node_adrr = l_remote_node_info->hdr.address.uint64;
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
        l_node_adrr = 0;
        l_addr = l_net_pvt->bootstrap_nodes_addrs[i];
        l_port = l_net_pvt->bootstrap_nodes_ports[i];
    }
    if (!l_addr.s_addr)
        return NULL;
    dap_chain_node_info_t *l_link_node_info = DAP_NEW_Z(dap_chain_node_info_t);
    if(! l_link_node_info){
        log_it(L_CRITICAL,"Can't allocate memory for node link info");
        return NULL;
    }
    l_link_node_info->hdr.address.uint64 = l_node_adrr;
    l_link_node_info->hdr.ext_addr_v4 = l_addr;
    l_link_node_info->hdr.ext_port = l_port;
    return l_link_node_info;
}

/**
 * @brief Check if the current link is already present or not
 *
 * @param a_net Network
 * @param a_link_node_info Node info
 */
static bool dap_chain_net_link_is_present(dap_chain_net_t *a_net, dap_chain_node_info_t *a_link_node_info)
{
    dap_chain_net_pvt_t *l_net_pvt = a_net ? PVT(a_net) : NULL;
    if(!l_net_pvt)
        return false;
    dap_list_t *l_net_links = l_net_pvt->net_links;
    while(l_net_links) {
        dap_chain_node_info_t *l_link_node_info = (dap_chain_node_info_t*) l_net_links->data;
        if(dap_chain_node_info_addr_match(l_link_node_info, a_link_node_info))
            return true;
        l_net_links = dap_list_next(l_net_links);
    }
    return false;
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
         if (dap_list_length(l_pvt_net->net_links) >= s_max_links_count) {
             pthread_rwlock_unlock(&l_pvt_net->rwlock);
             break;
         } else
            pthread_rwlock_unlock(&l_pvt_net->rwlock);

         dap_chain_node_addr_t *l_link_addr = dap_chain_node_alias_find(a_net, l_pvt_net->seed_aliases[i]);
         if (!l_link_addr)
             continue;

         if (l_link_addr->uint64 == l_own_addr) {
             continue;   // Do not link with self
         }
         dap_chain_node_info_t *l_link_node_info = dap_chain_node_info_read(a_net, l_link_addr);
         if(l_link_node_info && !dap_chain_net_link_is_present(a_net, l_link_node_info)) {
             struct net_link *l_new_link = DAP_NEW_Z(struct net_link);
             l_new_link->link_info = l_link_node_info;
             pthread_rwlock_wrlock(&l_pvt_net->rwlock);
             l_pvt_net->net_links = dap_list_append(l_pvt_net->net_links, l_new_link);
             pthread_rwlock_unlock(&l_pvt_net->rwlock);
         } else {
             log_it(L_WARNING, "Not found link %s."NODE_ADDR_FP_STR" in the node list or link is already in use", a_net->pub.name,
                    NODE_ADDR_FP_ARGS(l_link_addr));
             DAP_DELETE(l_link_node_info);
         }
     }
}

/**
 * @brief s_net_state_link_replace_error
 * @param a_worker
 * @param a_node_info
 * @param a_arg
 * @param a_errno
 */
/*static void s_net_state_link_replace_error(dap_worker_t *a_worker, dap_chain_node_info_t *a_node_info, void *a_arg, int a_errno)
{
    UNUSED(a_worker);
    struct link_dns_request *l_dns_request = (struct link_dns_request *)a_arg;
    dap_chain_net_t *l_net = l_dns_request->net;
    char l_node_addr_str[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &a_node_info->hdr.ext_addr_v4, l_node_addr_str, sizeof (a_node_info->hdr.ext_addr_v4));
    log_it(L_WARNING,"Link " NODE_ADDR_FP_STR " (%s) replace error with code %d", NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address),
                                                                                 l_node_addr_str,a_errno );
    struct json_object *l_json = net_states_json_collect(l_net);
    char l_err_str[128] = { };
    dap_snprintf(l_err_str, sizeof(l_err_str)
                 , "Link " NODE_ADDR_FP_STR " [%s] replace errno %d"
                 , NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address), l_node_addr_str, a_errno);
    json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
    DAP_DELETE(a_node_info);
    dap_chain_node_info_t *l_link_node_info = NULL;
    for (int i = 0; i < 1000; i++) {
        l_link_node_info = s_get_dns_link_from_cfg(l_net);
        if (l_link_node_info)
            break;
    }
    if (!l_link_node_info || PVT(l_net)->state == NET_STATE_OFFLINE) { // We have lost this link forever
        DAP_DELETE(l_dns_request);
        return;
    }
    if (dap_chain_node_info_dns_request(l_link_node_info->hdr.ext_addr_v4,
                                        l_link_node_info->hdr.ext_port,
                                        l_net->pub.name,
                                        l_link_node_info,  // use it twice
                                        s_net_state_link_replace_success,
                                        s_net_state_link_replace_error,
                                        l_dns_request)) {
        log_it(L_ERROR, "Can't process node info dns request");
        DAP_DELETE(l_link_node_info);
        DAP_DELETE(l_dns_request);
    }
}*/

/**
 * @brief s_net_state_link_repace_success
 * @param a_worker
 * @param a_node_info
 * @param a_arg
 */

/*static void s_net_state_link_replace_success(dap_worker_t *a_worker, dap_chain_node_info_t *a_node_info, void *a_arg)
{
    if (s_debug_more) {
        char l_node_addr_str[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &a_node_info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
        log_it(L_DEBUG,"Link " NODE_ADDR_FP_STR " (%s) replace success", NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address),
                                                                                     l_node_addr_str);
    }

    struct link_dns_request *l_dns_request = (struct link_dns_request *)a_arg;
    dap_chain_net_t *l_net = l_dns_request->net;
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    if (l_net_pvt->state == NET_STATE_OFFLINE) {
        DAP_DELETE(l_dns_request);
        return;
    }
    uint64_t l_own_addr = dap_chain_net_get_cur_addr_int(l_net);
    if (a_node_info->hdr.address.uint64 == l_own_addr) {
        s_net_state_link_replace_error(a_worker, a_node_info, a_arg, EWOULDBLOCK);
        return;
    }
    struct net_link *l_new_link = DAP_NEW_Z(struct net_link);
    l_new_link->link_info = a_node_info;
    l_new_link->link = dap_chain_net_client_create_n_connect(l_net, a_node_info);
    pthread_rwlock_wrlock(&l_net_pvt->rwlock);
    l_net_pvt->net_links = dap_list_append(l_net_pvt->net_links, l_new_link);
    pthread_rwlock_unlock(&l_net_pvt->rwlock);
    struct json_object *l_json = net_states_json_collect(l_net);
    char l_err_str[128] = { };
    dap_snprintf(l_err_str, sizeof(l_err_str)
                 , "Link " NODE_ADDR_FP_STR " replace success"
                 , NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address));
    json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
    DAP_DELETE(l_dns_request);
}*/

/**
 * @brief s_node_link_callback_connected
 * @param a_node_client
 * @param a_arg
 */
static void s_node_link_callback_connected(dap_chain_node_client_t * a_node_client, void * a_arg)
{
    dap_chain_net_t * l_net = (dap_chain_net_t *) a_arg;
    dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);

    a_node_client->stream_worker = dap_client_get_stream_worker(a_node_client->client);
    if(a_node_client->stream_worker == NULL){
        log_it(L_ERROR, "Stream worker is NULL in connected() callback, do nothing");
        a_node_client->state = NODE_CLIENT_STATE_ERROR;
        return;
    }

    a_node_client->resync_gdb = l_net_pvt->flags & F_DAP_CHAIN_NET_SYNC_FROM_ZERO;
    if ( s_debug_more )
    log_it(L_NOTICE, "Established connection with %s."NODE_ADDR_FP_STR,l_net->pub.name,
           NODE_ADDR_FP_ARGS_S(a_node_client->remote_node_addr));
    pthread_rwlock_wrlock(&l_net_pvt->rwlock);
    l_net_pvt->links_connected_count++;
    a_node_client->is_connected = true;
    struct json_object *l_json = net_states_json_collect(l_net);
    char l_err_str[128] = { };
    dap_snprintf(l_err_str, sizeof(l_err_str)
                 , "Established connection with link " NODE_ADDR_FP_STR
                 , NODE_ADDR_FP_ARGS_S(a_node_client->info->hdr.address));
    json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
    if(l_net_pvt->state == NET_STATE_LINKS_CONNECTING ){
        l_net_pvt->state = NET_STATE_LINKS_ESTABLISHED;
        dap_proc_queue_add_callback_inter(a_node_client->stream_worker->worker->proc_queue_input,s_net_states_proc,l_net );
    }
    pthread_rwlock_unlock(&l_net_pvt->rwlock);

}

static void s_node_link_remove(dap_chain_net_pvt_t *a_net_pvt, dap_chain_node_client_t *a_node_client)
{
    for (dap_list_t *it = a_net_pvt->net_links; it; it = it->next) {
        if (((struct net_link *)it->data)->link == a_node_client) {
            DAP_DELETE(((struct net_link *)it->data)->link_info);
            a_net_pvt->net_links = dap_list_delete_link(a_net_pvt->net_links, it);
            break;
        }
    }
}

/**
 * @brief s_node_link_callback_disconnected
 * @param a_node_client
 * @param a_arg
 */

static void s_node_link_callback_disconnected(dap_chain_node_client_t *a_node_client, void *a_arg)
{
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    pthread_rwlock_wrlock(&l_net_pvt->rwlock);
    if (a_node_client->is_connected) {
        a_node_client->is_connected = false;
        log_it(L_INFO, "%s."NODE_ADDR_FP_STR" disconnected.%s",l_net->pub.name,
               NODE_ADDR_FP_ARGS_S(a_node_client->info->hdr.address),
               l_net_pvt->state_target == NET_STATE_OFFLINE ? "" : " Replace it...");
        if (l_net_pvt->links_connected_count)
            l_net_pvt->links_connected_count--;
        else
            log_it(L_ERROR, "Links count is zero in disconnected callback, looks smbd decreased it twice or forget to increase on connect/reconnect");
    }
    if (l_net_pvt->state_target != NET_STATE_OFFLINE) {
        a_node_client->keep_connection = true;
        for (dap_list_t *it = l_net_pvt->net_links; it; it = it->next) {
            if (((struct net_link *)it->data)->link == NULL) {  // We have a free prepared link
                s_node_link_remove(l_net_pvt, a_node_client);
                a_node_client->keep_connection = false;
                ((struct net_link *)it->data)->link = dap_chain_net_client_create_n_connect(l_net,
                                                        ((struct net_link *)it->data)->link_info);
                pthread_rwlock_unlock(&l_net_pvt->rwlock);
                return;
            }
        }
        if (l_net_pvt->only_static_links) {
            pthread_rwlock_unlock(&l_net_pvt->rwlock);
            return;
        }
        dap_chain_node_info_t *l_link_node_info = NULL;
        int l_n = 0;
        while(l_n < 100) {
            l_n++;
            l_link_node_info = s_get_dns_link_from_cfg(l_net);
            // If this connect not exists
            if(l_link_node_info && !dap_chain_net_link_is_present(l_net, l_link_node_info)) {
                break;
            }
        }

        if (l_link_node_info) {
            if(!s_start_dns_request(l_net, l_link_node_info)) {
            /*struct link_dns_request *l_dns_request = DAP_NEW_Z(struct link_dns_request);
            l_dns_request->net = l_net;
            if (dap_chain_node_info_dns_request(l_link_node_info->hdr.ext_addr_v4,
                                                l_link_node_info->hdr.ext_port,
                                                l_net->pub.name,
                                                l_link_node_info,  // use it twice
                                                s_net_state_link_prepare_success,//s_net_state_link_replace_success,
                                                s_net_state_link_prepare_error,//s_net_state_link_replace_error,
                                                l_dns_request)) {
                                                */
                log_it(L_ERROR, "Can't process node info dns request");
                DAP_DELETE(l_link_node_info);
            } else {
                s_node_link_remove(l_net_pvt, a_node_client);
                a_node_client->keep_connection = false;
            }
        }
    }
    pthread_rwlock_unlock(&l_net_pvt->rwlock);
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
    struct json_object *l_json = net_states_json_collect(l_net);
    json_object_object_add(l_json, "errorMessage", json_object_new_string(" "));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
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
    struct json_object *l_json = net_states_json_collect(l_net);
    char l_node_addr_str[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &a_node_client->info->hdr.ext_addr_v4, l_node_addr_str, sizeof (a_node_client->info->hdr.ext_addr_v4));
    char l_err_str[128] = { };
    dap_snprintf(l_err_str, sizeof(l_err_str)
                 , "Link " NODE_ADDR_FP_STR " [%s] can't be established, errno %d"
                 , NODE_ADDR_FP_ARGS_S(a_node_client->info->hdr.address), l_node_addr_str, a_error);
    json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
}

/**
 * @brief s_node_link_callback_delete
 * @param a_node_client
 * @param a_arg
 */
static void s_node_link_callback_delete(dap_chain_node_client_t * a_node_client, void * a_arg)
{
    dap_chain_net_t * l_net = (dap_chain_net_t *) a_arg;
    dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);
    if (!a_node_client->keep_connection) {
        struct json_object *l_json = net_states_json_collect(l_net);
        json_object_object_add(l_json, "errorMessage", json_object_new_string("Link deleted"));
        dap_notify_server_send_mt(json_object_get_string(l_json));
        json_object_put(l_json);
        return;
    } else if (a_node_client->is_connected) {
        a_node_client->is_connected = false;
        if (l_net_pvt->links_connected_count)
            l_net_pvt->links_connected_count--;
        else
            log_it(L_ERROR, "Links count is zero in delete callback");
        // If the last link is lost, change the status to NET_STATE_OFFLINE
        if(!l_net_pvt->links_connected_count) {
            l_net_pvt->state = NET_STATE_OFFLINE;
        }
    }
    dap_chain_net_sync_unlock(l_net, a_node_client);
    pthread_rwlock_wrlock(&l_net_pvt->rwlock);
    for ( dap_list_t * it = l_net_pvt->net_links; it; it=it->next ){
        if (((struct net_link *)it->data)->link == a_node_client) {
            log_it(L_DEBUG,"Replace node client with new one");
            ((struct net_link *)it->data)->link = dap_chain_net_client_create_n_connect(l_net, a_node_client->info);
        }
    }
    pthread_rwlock_unlock(&l_net_pvt->rwlock);
    struct json_object *l_json = net_states_json_collect(l_net);
    json_object_object_add(l_json, "errorMessage", json_object_new_string("Link restart"));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
    // Then a_alient wiil be destroyed in a right way
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
    uint64_t l_own_addr = dap_chain_net_get_cur_addr_int(l_net);
    if (a_node_info->hdr.address.uint64 != l_own_addr) {
        struct net_link *l_new_link = DAP_NEW_Z(struct net_link);
        l_new_link->link_info = a_node_info;
        pthread_rwlock_wrlock(&l_net_pvt->rwlock);
        l_net_pvt->net_links = dap_list_append(l_net_pvt->net_links, l_new_link);
        pthread_rwlock_unlock(&l_net_pvt->rwlock);
        l_dns_request->tries = 0;
    }
    pthread_rwlock_rdlock(&l_net_pvt->rwlock);

    l_dns_request->tries++;
    l_net_pvt->links_dns_requests--;
    if (l_net_pvt->links_dns_requests == 0){ // It was the last one
        if (l_net_pvt->state != NET_STATE_LINKS_CONNECTING){
            l_net_pvt->state = NET_STATE_LINKS_CONNECTING;
        }
        dap_proc_queue_add_callback_inter( a_worker->proc_queue_input,s_net_states_proc,l_net );
    }
    pthread_rwlock_unlock(&l_net_pvt->rwlock);
    struct json_object *l_json = net_states_json_collect(l_net);
    char l_err_str[128] = { };
    dap_snprintf(l_err_str, sizeof(l_err_str)
                 , "Link " NODE_ADDR_FP_STR " prepared"
                 , NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address));
    json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
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
    inet_ntop(AF_INET,&a_node_info->hdr.ext_addr_v4,l_node_addr_str, INET_ADDRSTRLEN);
    log_it(L_WARNING,"Link " NODE_ADDR_FP_STR " (%s) prepare error with code %d", NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address),
                                                                                 l_node_addr_str,a_errno );
    struct json_object *l_json = net_states_json_collect(l_net);
    char l_err_str[128] = { };
    dap_snprintf(l_err_str, sizeof(l_err_str)
                 , "Link " NODE_ADDR_FP_STR " [%s] can't be prepared, errno %d"
                 , NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address), l_node_addr_str, a_errno);
    json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
    pthread_rwlock_wrlock(&l_net_pvt->rwlock);
    if(l_net_pvt->links_dns_requests)
        l_net_pvt->links_dns_requests--;

    if(!l_net_pvt->links_dns_requests ){
        if( l_net_pvt->state_target != NET_STATE_OFFLINE){
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
 * @brief Get list of the unique links for the selected net
 * @param a_net
 * @return list of dap_chain_node_info_t or NULL
 */
static dap_chain_node_info_list_t* s_get_links(dap_chain_net_t *a_net)
{
    dap_chain_net_pvt_t *l_net_pvt = a_net ? PVT(a_net) : NULL;
    if(!l_net_pvt)
        return false;

    dap_chain_node_info_list_t *l_node_list = NULL;
    // Choose between the allowed number of links and the number of real links
    size_t l_max_links_count = MIN(s_max_links_count, s_get_dns_max_links_count_from_cfg(a_net));
    size_t l_cur_links_count = 0;
    size_t l_n = 0;// Protect from eternal loop
    while(l_cur_links_count < l_max_links_count) {
        if(l_n > 1000) // It's a problem with link prepare
            break;
        l_n++;
        dap_chain_node_info_t *l_link_node_info = s_get_dns_link_from_cfg(a_net);
        if(!l_link_node_info)
            continue;
        // Protect against using the same node
        if(dap_chain_node_info_list_is_added(l_node_list, l_link_node_info)) {
            DAP_DEL_Z(l_link_node_info);
            continue;
        }
        l_node_list = dap_chain_node_info_list_add(l_node_list, l_link_node_info);
        l_cur_links_count++;
    }
    return l_node_list;
}

/**
 * @brief Launch a connect with a link
 * @param a_net
 * @param a_link_node_info node parameters
 * @return list of dap_chain_node_info_t
 */
static bool s_start_dns_request(dap_chain_net_t *a_net, dap_chain_node_info_t *a_link_node_info)
{
    dap_chain_net_pvt_t *l_net_pvt = a_net ? PVT(a_net) : NULL;
    if(!l_net_pvt)
        return false;
    l_net_pvt->links_dns_requests++;
    struct link_dns_request *l_dns_request = DAP_NEW_Z(struct link_dns_request);
    l_dns_request->net = a_net;
    //l_dns_request->link_id = a_link_id;
    if(dap_chain_node_info_dns_request(a_link_node_info->hdr.ext_addr_v4,
            a_link_node_info->hdr.ext_port,
            a_net->pub.name,
            a_link_node_info, // use it twice
            s_net_state_link_prepare_success,
            s_net_state_link_prepare_error,
            l_dns_request)) {
        log_it(L_ERROR, "Can't process node info dns request");
        //l_node_list = dap_chain_node_info_list_del(l_node_list, a_link_node_info);
        DAP_DEL_Z(l_dns_request);
        return false;
    }
    return true;
}


struct json_object *net_states_json_collect(dap_chain_net_t * l_net) {
    struct json_object *l_json = json_object_new_object();
    json_object_object_add(l_json, "class"            , json_object_new_string("NetStates"));
    json_object_object_add(l_json, "name"             , json_object_new_string((const char*)l_net->pub.name));
    json_object_object_add(l_json, "networkState"     , json_object_new_string(dap_chain_net_state_to_str(PVT(l_net)->state)));
    json_object_object_add(l_json, "targetState"      , json_object_new_string(dap_chain_net_state_to_str(PVT(l_net)->state_target)));
    json_object_object_add(l_json, "linksCount"       , json_object_new_int(dap_list_length(PVT(l_net)->net_links)));
    json_object_object_add(l_json, "activeLinksCount" , json_object_new_int(PVT(l_net)->links_connected_count));
    char l_node_addr_str[24] = {'\0'};
    dap_snprintf(l_node_addr_str, sizeof(l_node_addr_str), NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS(PVT(l_net)->node_addr));
    json_object_object_add(l_json, "nodeAddress"     , json_object_new_string(l_node_addr_str));
    return l_json;
}

/**
 * @brief s_net_states_notify
 * @param l_net
 */
static void s_net_states_notify(dap_chain_net_t * l_net) {
    struct json_object *l_json = net_states_json_collect(l_net);
    json_object_object_add(l_json, "errorMessage", json_object_new_string(" ")); // regular notify has no error
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
}

/**
 * @brief s_net_states_proc
 * @param l_net
 */
static bool s_net_states_proc(dap_proc_thread_t *a_thread, void *a_arg) {
    UNUSED(a_thread);
    bool l_repeat_after_exit = false; // If true - repeat on next iteration of proc thread loop
    dap_chain_net_t *l_net = (dap_chain_net_t *) a_arg;
    assert(l_net);
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    assert(l_net_pvt);
    if (l_net_pvt->state_target == NET_STATE_OFFLINE) {
        l_net_pvt->state = NET_STATE_OFFLINE;
    }

    pthread_rwlock_wrlock(&l_net_pvt->rwlock);

    switch (l_net_pvt->state) {
        // State OFFLINE where we don't do anything
        case NET_STATE_OFFLINE: {
            l_net_pvt->links_connected_count = 0;
            // delete all links
            dap_list_t *l_tmp = l_net_pvt->net_links;
            while (l_tmp) {
                dap_list_t *l_next =l_tmp->next;
                dap_chain_node_client_t *l_link = ((struct net_link *)l_tmp->data)->link;
                if (l_link) {
                    l_link->keep_connection = false;
                    dap_chain_node_client_close(l_link);
                }
                DAP_DEL_Z(((struct net_link *)l_tmp->data)->link_info);
                l_tmp = l_next;
            }
            dap_list_free_full(l_net_pvt->net_links, NULL);
            l_net_pvt->net_links = NULL;
            if ( l_net_pvt->state_target != NET_STATE_OFFLINE ){
                l_net_pvt->state = NET_STATE_LINKS_PREPARE;
                l_repeat_after_exit = true;
                break;
            }
            // disable SYNC_GDB
            l_net_pvt->active_link = NULL;
            l_net_pvt->flags &= ~F_DAP_CHAIN_NET_GO_SYNC;
            l_net_pvt->last_sync = 0;
        } break;

        // Prepare links
        case NET_STATE_LINKS_PREPARE: {
            log_it(L_NOTICE,"%s.state: NET_STATE_LINKS_PREPARE", l_net->pub.name);
            s_net_states_notify(l_net);
            for (int i = 0; i < l_net_pvt->gdb_sync_nodes_links_count; i++) {
                if (i >= l_net_pvt->gdb_sync_nodes_addrs_count)
                    break;
                dap_chain_node_info_t *l_link_node_info = DAP_NEW_Z(dap_chain_node_info_t);
                l_link_node_info->hdr.address.uint64 = l_net_pvt->gdb_sync_nodes_addrs[i].uint64;
                l_link_node_info->hdr.ext_addr_v4.s_addr = l_net_pvt->gdb_sync_nodes_links_ips[i];
                l_link_node_info->hdr.ext_port = l_net_pvt->gdb_sync_nodes_links_ports[i];
                if(!dap_chain_net_link_is_present(l_net, l_link_node_info)){
                    struct net_link *l_new_link = DAP_NEW_Z(struct net_link);
                    l_new_link->link_info = l_link_node_info;
                    l_net_pvt->net_links = dap_list_append(l_net_pvt->net_links, l_new_link);
                }
                else{
                    DAP_DELETE(l_link_node_info);
                }

            }
            uint64_t l_own_addr = dap_chain_net_get_cur_addr_int(l_net);
            if (l_net_pvt->node_info) {
                for (size_t i = 0; i < l_net_pvt->node_info->hdr.links_number; i++) {
                    dap_chain_node_info_t *l_link_node_info = dap_chain_node_info_read(l_net, &l_net_pvt->node_info->links[i]);
                    if (!l_link_node_info || l_link_node_info->hdr.address.uint64 == l_own_addr) {
                        continue;   // Do not link with self
                    }
                    if(!dap_chain_net_link_is_present(l_net, l_link_node_info)) {
                        struct net_link *l_new_link = DAP_NEW_Z(struct net_link);
                        l_new_link->link_info = l_link_node_info;
                        l_net_pvt->net_links = dap_list_append(l_net_pvt->net_links, l_new_link);
                        if(dap_list_length(l_net_pvt->net_links) >= s_max_links_count) {

                            break;
                        }
                    }
                    else {
                        DAP_DELETE(l_link_node_info);
                    }
                }
            } else {
                log_it(L_WARNING,"No nodeinfo in global_db to prepare links for connecting, try to add links from root servers");
            }
            if (l_net_pvt->only_static_links) {
                if (l_net_pvt->seed_aliases_count) {
                    // Add other root nodes as synchronization links
                    pthread_rwlock_unlock(&l_net_pvt->rwlock);
                    s_fill_links_from_root_aliases(l_net);
                    pthread_rwlock_wrlock(&l_net_pvt->rwlock);
                    l_net_pvt->state = NET_STATE_LINKS_CONNECTING;
                    l_repeat_after_exit = true;
                    break;
                }
            } else {
                if (!l_net_pvt->seed_aliases_count && ! l_net_pvt->bootstrap_nodes_count){
                   log_it(L_ERROR, "No root servers present in configuration file. Can't establish DNS requests");
                   if (l_net_pvt->net_links) { // We have other links
                       l_net_pvt->state = NET_STATE_LINKS_CONNECTING;
                       l_repeat_after_exit = true;
                   }
                   break;
                }
                // Get DNS request result from root nodes as synchronization links
                bool l_sync_fill_root_nodes = false;
                if (!l_sync_fill_root_nodes) {
                    // Get list of the unique links for l_net
                    dap_chain_node_info_list_t *l_node_list = s_get_links(l_net);
                    // Start connect to links from list
                    dap_chain_node_info_list_t *l_node_list_cur = l_node_list;
                    while(l_node_list_cur) {
                        dap_chain_node_info_t *l_link_node_info = (dap_chain_node_info_t*)l_node_list_cur->data;
                        char l_node_addr_str[INET_ADDRSTRLEN] = { };
                        inet_ntop(AF_INET, &l_link_node_info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
                        log_it(L_DEBUG, "Start DNS request to %s", l_node_addr_str);
                        if(!s_start_dns_request(l_net, l_link_node_info))
                        {
                            DAP_DEL_Z(l_link_node_info);
                        }
                        l_node_list_cur = dap_list_next(l_node_list_cur);
                    }
                    dap_chain_node_info_list_free(l_node_list);

                } else {
                    log_it(L_ATT, "Not use bootstrap addresses, fill seed nodelist from root aliases");
                    pthread_rwlock_unlock(&l_net_pvt->rwlock);
                    s_fill_links_from_root_aliases(l_net);
                    pthread_rwlock_wrlock(&l_net_pvt->rwlock);
                }
            }
        } break;

        case NET_STATE_LINKS_CONNECTING: {
            log_it(L_INFO, "%s.state: NET_STATE_LINKS_CONNECTING",l_net->pub.name);
            size_t l_used_links = 0;
            for (dap_list_t *l_tmp = l_net_pvt->net_links; l_tmp; l_tmp = dap_list_next(l_tmp)) {
                dap_chain_node_info_t *l_link_info = ((struct net_link *)l_tmp->data)->link_info;
                dap_chain_node_client_t *l_client = dap_chain_net_client_create_n_connect(l_net, l_link_info);
                ((struct net_link *)l_tmp->data)->link = l_client;
                if (++l_used_links == s_required_links_count)
                    break;
            }
        } break;

        case NET_STATE_LINKS_ESTABLISHED:{
            log_it(L_INFO,"%s.state: NET_STATE_LINKS_ESTABLISHED", l_net->pub.name);
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

int s_net_list_compare_uuids(const void *a_uuid1, const void *a_uuid2)
{
    return memcmp(a_uuid1, a_uuid2, sizeof(dap_events_socket_uuid_t));
}

bool dap_chain_net_sync_trylock(dap_chain_net_t *a_net, dap_chain_node_client_t *a_client)
{
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
    pthread_rwlock_rdlock(&l_net_pvt->rwlock);
    bool l_found = false;
    if (l_net_pvt->active_link) {
        for (dap_list_t *l_links = l_net_pvt->net_links; l_links; l_links = dap_list_next(l_links)) {
            dap_chain_node_client_t *l_client = ((struct net_link *)l_links->data)->link;
            if (l_client == l_net_pvt->active_link &&
                        l_client->state >= NODE_CLIENT_STATE_ESTABLISHED &&
                        l_client->state < NODE_CLIENT_STATE_SYNCED &&
                        a_client != l_client) {
                l_found = true;
                break;
            }
        }
    }
    if (!l_found) {
        l_net_pvt->active_link = a_client;
    }
    if (l_found && !dap_list_find_custom(l_net_pvt->links_queue, &a_client->uuid, s_net_list_compare_uuids)) {
        dap_events_socket_uuid_t *l_uuid = DAP_DUP(&a_client->uuid);
        l_net_pvt->links_queue = dap_list_append(l_net_pvt->links_queue, l_uuid);
    }
    pthread_rwlock_unlock(&l_net_pvt->rwlock);
    return !l_found;
}

bool dap_chain_net_sync_unlock(dap_chain_net_t *a_net, dap_chain_node_client_t *a_client)
{
    if (!a_net)
        return false;
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
    pthread_rwlock_rdlock(&l_net_pvt->rwlock);
    if (!a_client || l_net_pvt->active_link == a_client)
        l_net_pvt->active_link = NULL;
    while (l_net_pvt->active_link == NULL && l_net_pvt->links_queue) {
        dap_events_socket_uuid_t *l_uuid = l_net_pvt->links_queue->data;
        pthread_rwlock_unlock(&l_net_pvt->rwlock);
        dap_chain_node_sync_status_t l_status = dap_chain_node_client_start_sync(l_uuid);
        pthread_rwlock_rdlock(&l_net_pvt->rwlock);
        if (l_status != NODE_SYNC_STATUS_WAITING) {
            DAP_DELETE(l_uuid);
            dap_list_t *l_to_remove = l_net_pvt->links_queue;
            l_net_pvt->links_queue = l_net_pvt->links_queue->next;
            DAP_DELETE(l_to_remove);
        } else {
            break;
        }
    }
    pthread_rwlock_unlock(&l_net_pvt->rwlock);
    return l_net_pvt->active_link;
}
/**
 * @brief dap_chain_net_client_create_n_connect
 * @param a_net
 * @param a_link_info
 * @return
 */
struct dap_chain_node_client * dap_chain_net_client_create_n_connect( dap_chain_net_t * a_net,struct dap_chain_node_info* a_link_info)
{
    dap_chain_node_client_t *l_ret = dap_chain_node_client_create_n_connect(a_net,
                                                                            a_link_info,
                                                                            "CN",
                                                                            (dap_chain_node_client_callbacks_t *)&s_node_link_callbacks,
                                                                            a_net);
    if (l_ret)
        l_ret->keep_connection = true;
    return l_ret;
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
 * @brief set node role
 * [root_master, root, archive, cell_master, master, full, light]
 * @param a_id
 * @param a_name
 * @param a_node_role
 * @return dap_chain_net_t*
 */
static dap_chain_net_t *s_net_new(const char * a_id, const char * a_name ,
                                    const char * a_node_role)
{
    if (!a_id || !a_name || !a_node_role)
        return NULL;
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
    pthread_mutex_init(&(PVT(ret)->state_mutex_cond), NULL);
    if (dap_sscanf(a_id, "0x%016"DAP_UINT64_FORMAT_X, &ret->pub.id.uint64) != 1) {
        log_it (L_ERROR, "Wrong id format (\"%s\"). Must be like \"0x0123456789ABCDE\"" , a_id );
        DAP_DELETE(ret);
        return NULL;
    }
    if (strcmp (a_node_role, "root_master")==0){
        PVT(ret)->node_role.enums = NODE_ROLE_ROOT_MASTER;
    } else if (strcmp( a_node_role,"root") == 0){
        PVT(ret)->node_role.enums = NODE_ROLE_ROOT;
    } else if (strcmp( a_node_role,"archive") == 0){
        PVT(ret)->node_role.enums = NODE_ROLE_ARCHIVE;
    } else if (strcmp( a_node_role,"cell_master") == 0){
        PVT(ret)->node_role.enums = NODE_ROLE_CELL_MASTER;
    }else if (strcmp( a_node_role,"master") == 0){
        PVT(ret)->node_role.enums = NODE_ROLE_MASTER;
    }else if (strcmp( a_node_role,"full") == 0){
        PVT(ret)->node_role.enums = NODE_ROLE_FULL;
    }else if (strcmp( a_node_role,"light") == 0){
        PVT(ret)->node_role.enums = NODE_ROLE_LIGHT;
    }else{
        log_it(L_ERROR,"Unknown node role \"%s\" for network '%s'", a_node_role, a_name);
        DAP_DELETE(ret);
        return NULL;
    }
    log_it (L_NOTICE, "Node role \"%s\" selected for network '%s'", a_node_role, a_name);
    return ret;
}

/**
 * @brief dap_chain_net_delete
 * free dap_chain_net_t * a_net object
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
 * @brief
 * load network config settings
 */
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
                                                           PVT(a_net)->links_connected_count,
                                                           dap_list_length(PVT(a_net)->net_links));
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
 * @brief get type of chain
 *
 * @param l_chain
 * @return char*
 */
const char* dap_chain_net_get_type(dap_chain_t *l_chain)
{
    if (!l_chain){
        log_it(L_DEBUG, "dap_get_chain_type. Chain object is 0");
        return NULL;
    }
    return (const char*)DAP_CHAIN_PVT(l_chain)->cs_name;
}

/**
 * @brief reload ledger
 * command cellframe-node-cli net -net <network_name> ledger reload
 * @param l_net
 * @return true
 * @return false
 */
void s_chain_net_ledger_cache_reload(dap_chain_net_t *l_net)
{
    dap_chain_ledger_purge(l_net->pub.ledger, false);
    dap_chain_t *l_chain = NULL;
    DL_FOREACH(l_net->pub.chains, l_chain)
    {
        if (l_chain->callback_purge)
            l_chain->callback_purge(l_chain);

        if (!strcmp(DAP_CHAIN_PVT(l_chain)->cs_name, "none"))
            dap_chain_gdb_ledger_load((char *)dap_chain_gdb_get_group(l_chain), l_chain);
        else
            dap_chain_load_all(l_chain);
        }
    bool l_processed;
        do {
            l_processed = false;
            DL_FOREACH(l_net->pub.chains, l_chain) {
               if (l_chain->callback_atom_add_from_treshold) {
                    while (l_chain->callback_atom_add_from_treshold(l_chain, NULL)) {
                        log_it(L_DEBUG, "Added atom from treshold");
                        l_processed = true;
                    }
                }
            }
        } while (l_processed);
}

/**
 * @brief update ledger cache at once
 * if you node build need ledger cache one time reload, uncomment this function
 * iat the end of s_net_load
 * @param l_net network object
 * @return true
 * @return false
 */
bool s_chain_net_reload_ledger_cache_once(dap_chain_net_t *l_net)
{
    if (!l_net)
        return false;
    // create directory for cache checking file (cellframe-node/cache)
    char *l_cache_dir = dap_strdup_printf( "%s/%s", g_sys_dir_path, "cache");
    if (dap_mkdir_with_parents(l_cache_dir) != 0) {
        log_it(L_WARNING,"Error during disposable cache check file creation");
        return false;
    }
    // create file, if it not presented. If file exists, ledger cache operation is stopped
    char *l_cache_file = dap_strdup_printf( "%s/%s.cache", l_cache_dir, "5B0FEEF6-B0D5-48A9-BFA2-32E8B294366D");
    if (dap_file_simple_test(l_cache_file)) {
        return false;
    }

    log_it(L_WARNING,"Start one time ledger cache reloading");
    static FILE *s_cache_file = NULL;
    s_cache_file = fopen(l_cache_file, "a");
    if(!s_cache_file) {
        s_cache_file = fopen(l_cache_file, "w");
        if (!s_cache_file) {
            dap_fprintf(stderr, "Can't open cache file %s for one time ledger cache reloading.\
                Please, do it manually using command\
                cellframe-node-cli net -net <network_name>> ledger reload'\n", l_cache_file);
            return -1;
        }
    }
    // reload ledger cache (same as net -net <network_name>> ledger reload command)
    if (dap_file_simple_test(l_cache_file))
        s_chain_net_ledger_cache_reload(l_net);
    fclose(s_cache_file);
    return true;
}

/**
 * @brief
 * register net* command in cellframe-node-cli interface
 * @param argc arguments count
 * @param argv arguments value
 * @param arg_func
 * @param str_reply
 * @return
 */
static int s_cli_net(int argc, char **argv, char **a_str_reply)
{
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

    if(dap_chain_node_cli_find_option_val(argv, arg_index, min(argc, arg_index + 1), "list", &l_list_cmd) != 0 ) {
        dap_string_t *l_string_ret = dap_string_new("");
        if (dap_strcmp(l_list_cmd,"chains")==0){
            const char * l_net_str = NULL;
            dap_chain_net_t* l_net = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-net", &l_net_str);

            l_net = dap_chain_net_by_name(l_net_str);

            if (l_net){
                dap_string_append(l_string_ret,"Chains:\n");
                dap_chain_t * l_chain = l_net->pub.chains;
                while (l_chain) {
                    dap_string_append_printf(l_string_ret, "\t%s:\n", l_chain->name );
                    l_chain = l_chain->next;
                }
            }else{
                dap_chain_net_item_t * l_net_item, *l_net_item_tmp;
                int l_net_i = 0;
                dap_string_append(l_string_ret,"Networks:\n");
                pthread_rwlock_rdlock(&g_net_items_rwlock);
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
                pthread_rwlock_unlock(&g_net_items_rwlock);
            }

        }else{
            dap_string_append(l_string_ret,"Networks:\n");
            // show list of nets
            dap_chain_net_item_t * l_net_item, *l_net_item_tmp;
            int l_net_i = 0;
            pthread_rwlock_rdlock(&g_net_items_rwlock);
            HASH_ITER(hh, s_net_items, l_net_item, l_net_item_tmp){
                dap_string_append_printf(l_string_ret, "\t%s\n", l_net_item->name);
                l_net_i++;
            }
            pthread_rwlock_unlock(&g_net_items_rwlock);
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
        if (l_stats_str) {
            char l_from_str_new[50], l_to_str_new[50];
            const char c_time_fmt[]="%Y-%m-%d_%H:%M:%S";
            struct tm l_from_tm = {}, l_to_tm = {};
            if (strcmp(l_stats_str,"tx") == 0) {
                const char *l_to_str = NULL;
                const char *l_from_str = NULL;
                const char *l_prev_sec_str = NULL;
                // Read from/to time
                dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-from", &l_from_str);
                dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-to", &l_to_str);
                dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-prev_sec", &l_prev_sec_str);
                time_t l_ts_now = time(NULL);
                if (l_from_str) {
                    strptime( (char *)l_from_str, c_time_fmt, &l_from_tm );
                    if (l_to_str) {
                        strptime( (char *)l_to_str, c_time_fmt, &l_to_tm );
                    } else { // If not set '-to' - we set up current time
                        localtime_r(&l_ts_now, &l_to_tm);
                    }
                } else if (l_prev_sec_str) {
                    l_ts_now -= strtol( l_prev_sec_str, NULL,10 );
                    localtime_r(&l_ts_now, &l_from_tm );
                } else if ( l_from_str == NULL ) { // If not set '-from' we set up current time minus 60 seconds
                    l_ts_now -= 60;
                    localtime_r(&l_ts_now, &l_from_tm );
                }
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
            } else if (strcmp(l_stats_str, "tps") == 0) {
                struct timespec l_from_time_acc = {}, l_to_time_acc = {};
                dap_string_t * l_ret_str = dap_string_new("Transactions per second peak values:\n");
                size_t l_tx_num = dap_chain_ledger_count_tps(l_net->pub.ledger, &l_from_time_acc, &l_to_time_acc);
                if (l_tx_num) {
                    localtime_r(&l_from_time_acc.tv_sec, &l_from_tm);
                    strftime(l_from_str_new, sizeof(l_from_str_new), c_time_fmt, &l_from_tm);
                    localtime_r(&l_to_time_acc.tv_sec, &l_to_tm);
                    strftime(l_to_str_new, sizeof(l_to_str_new), c_time_fmt, &l_to_tm);
                    dap_string_append_printf(l_ret_str, "\tFrom: %s\tTo: %s\n", l_from_str_new, l_to_str_new);
                    uint64_t l_diff_ns = (l_to_time_acc.tv_sec - l_from_time_acc.tv_sec) * 1000000000 +
                                            l_to_time_acc.tv_nsec - l_from_time_acc.tv_nsec;
                    long double l_tps = (long double)(l_tx_num * 1000000000) / (long double)(l_diff_ns);
                    dap_string_append_printf(l_ret_str, "\tSpeed:  %.3Lf TPS\n", l_tps);
                }
                dap_string_append_printf(l_ret_str, "\tTotal:  %zu\n", l_tx_num);
                dap_chain_node_cli_set_reply_text(a_str_reply, l_ret_str->str);
                dap_string_free(l_ret_str, false);
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Subcommand 'stats' requires one of parameter: tx, tps\n");
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

            } else if (strcmp(l_go_str, "sync") == 0) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network \"%s\" resynchronizing",
                                                  l_net->pub.name);
                if (PVT(l_net)->state_target == NET_STATE_ONLINE)
                    dap_chain_net_state_go_to(l_net, NET_STATE_ONLINE);
                else
                    dap_chain_net_state_go_to(l_net, NET_STATE_SYNC_CHAINS);
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Subcommand 'go' requires one of parameters: online, offline, sync\n");
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
                size_t l_links_count = dap_list_length(l_net_pvt->net_links);
                dap_string_t *l_reply = dap_string_new("");
                dap_string_append_printf(l_reply,"Links %zu:\n", l_links_count);
                for (dap_list_t * l_item = l_net_pvt->net_links; l_item;  l_item = l_item->next ) {
                    dap_chain_node_client_t *l_node_client = ((struct net_link *)l_item->data)->link;
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
                                                    "\t\tstate: %s\n",
                                                 NODE_ADDR_FP_ARGS_S(l_info->hdr.address), l_info->hdr.alias, l_info->hdr.cell_id.uint64,
                                                 l_ext_addr_v4, l_ext_addr_v6, l_info->hdr.ext_port,
                                                 dap_chain_node_client_state_to_str(l_node_client->state) );
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
                                                  "Subcommand 'link' requires one of parameters: list, add, del, info, disconnect_all\n");
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
                // TODO set PVT flag to exclude GDB sync
                dap_chain_net_sync_chains(l_net);

            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Subcommand 'sync' requires one of parameters: all, gdb, chains\n");
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
                ret = dap_chain_global_db_gr_set(l_hash_hex_str, &c, 1, dap_chain_net_get_gdb_group_acl(l_net));
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
                ret = dap_chain_global_db_gr_del(l_hash_string, l_gdb_group_str);
                DAP_DELETE(l_gdb_group_str);
                if (!ret) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Cant't find certificate public key hash in database");
                    return -10;
                }
                return 0;
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Subcommand 'ca' requires one of parameter: add, list, del\n");
                ret = -5;
            }
        } else if (l_ledger_str && !strcmp(l_ledger_str, "reload"))
        {
           s_chain_net_ledger_cache_reload(l_net);
        }
        else
        {
            dap_chain_node_cli_set_reply_text(a_str_reply,
                                              "Command 'net' requires one of subcomands: sync, link, go, get, stats, ca, ledger");
            ret = -1;
        }

    }
    return  ret;
}

/**
 * @brief remove_duplicates_in_chain_by_priority
 * remove duplicates default datum types in chain by priority
 * @param *l_chain_1 chain 1
 * @param *l_chain_2 chain 2
 * @return void
 */

static void remove_duplicates_in_chain_by_priority(dap_chain_t *l_chain_1, dap_chain_t *l_chain_2)
{
	dap_chain_t *l_chain_high_priority = (l_chain_1->load_priority > l_chain_2->load_priority) ? l_chain_2 : l_chain_1; //such distribution is made for correct operation with the same priority
	dap_chain_t *l_chain_low_priority = (l_chain_1->load_priority > l_chain_2->load_priority) ? l_chain_1 : l_chain_2; //...^...^...^...

	for (int i = 0; i < l_chain_high_priority->default_datum_types_count; i++)
	{
		for (int j = 0; j < l_chain_low_priority->default_datum_types_count; j++)
		{
			if (l_chain_high_priority->default_datum_types[i] == l_chain_low_priority->default_datum_types[j])
			{
				l_chain_low_priority->default_datum_types[j] = l_chain_low_priority->default_datum_types[l_chain_low_priority->default_datum_types_count - 1];
				--l_chain_low_priority->default_datum_types_count;
				--j;
			}
		}
	}
}

// for sequential loading chains
typedef struct list_priority_{
    uint16_t prior;
    char * chains_path;
}list_priority;

static int callback_compare_prioritity_list(const void * a_item1, const void * a_item2, void *a_unused)
{
    UNUSED(a_unused);
    list_priority *l_item1 = (list_priority*) a_item1;
    list_priority *l_item2 = (list_priority*) a_item2;
    if(!l_item1 || !l_item2 || l_item1->prior == l_item2->prior)
        return 0;
    if(l_item1->prior > l_item2->prior)
        return 1;
    return -1;
}

/**
 * @brief load network config settings from cellframe-node.cfg file
 *
 * @param a_net_name const char *: network name, for example "home21-network"
 * @param a_acl_idx currently 0
 * @return int
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
        if(!l_net) {
            log_it(L_ERROR,"Can't create l_net");
            return -1;
        }
        dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);
        l_net_pvt->load_mode = true;
        l_net_pvt->acl_idx = a_acl_idx;
        l_net->pub.gdb_groups_prefix = dap_strdup (
                    dap_config_get_item_str_default(l_cfg , "general" , "gdb_groups_prefix",
                                                    dap_config_get_item_str(l_cfg , "general" , "name" ) ) );
        dap_chain_global_db_add_sync_group(l_net->pub.name, "global", s_gbd_history_callback_notify, l_net);
        dap_chain_global_db_add_sync_group(l_net->pub.name, l_net->pub.gdb_groups_prefix, s_gbd_history_callback_notify, l_net);

        l_net->pub.gdb_nodes = dap_strdup_printf("%s.nodes",l_net->pub.gdb_groups_prefix);
        l_net->pub.gdb_nodes_aliases = dap_strdup_printf("%s.nodes.aliases",l_net->pub.gdb_groups_prefix);

        // nodes for special sync
        char **l_gdb_sync_nodes_addrs = dap_config_get_array_str(l_cfg, "general", "gdb_sync_nodes_addrs",
                &l_net_pvt->gdb_sync_nodes_addrs_count);
        if(l_gdb_sync_nodes_addrs && l_net_pvt->gdb_sync_nodes_addrs_count > 0) {
            l_net_pvt->gdb_sync_nodes_addrs = DAP_NEW_Z_SIZE(dap_chain_node_addr_t,
                    sizeof(dap_chain_node_addr_t)*l_net_pvt->gdb_sync_nodes_addrs_count);
            for(uint16_t i = 0; i < l_net_pvt->gdb_sync_nodes_addrs_count; i++) {
                dap_chain_node_addr_from_str(l_net_pvt->gdb_sync_nodes_addrs + i, l_gdb_sync_nodes_addrs[i]);
            }
        }
        // links for special sync
        uint16_t l_gdb_links_count = 0;
        PVT(l_net)->gdb_sync_nodes_links_count = 0;
        char **l_gdb_sync_nodes_links = dap_config_get_array_str(l_cfg, "general", "gdb_sync_nodes_links", &l_gdb_links_count);
        if (l_gdb_sync_nodes_links && l_gdb_links_count > 0) {
            l_net_pvt->gdb_sync_nodes_links_ips = DAP_NEW_Z_SIZE(uint32_t, l_gdb_links_count * sizeof(uint32_t));
            l_net_pvt->gdb_sync_nodes_links_ports = DAP_NEW_SIZE(uint16_t, l_gdb_links_count * sizeof(uint16_t));
            for(uint16_t i = 0; i < l_gdb_links_count; i++) {
                char *l_gdb_link_port_str = strchr(l_gdb_sync_nodes_links[i], ':');
                if (!l_gdb_link_port_str) {
                    continue;
                }
                uint16_t l_gdb_link_port = atoi(l_gdb_link_port_str + 1);
                if (!l_gdb_link_port) {
                    continue;
                }
                int l_gdb_link_len = l_gdb_link_port_str - l_gdb_sync_nodes_links[i];
                char l_gdb_link_ip_str[l_gdb_link_len + 1];
                memcpy(l_gdb_link_ip_str, l_gdb_sync_nodes_links[i], l_gdb_link_len);
                l_gdb_link_ip_str[l_gdb_link_len] = '\0';
                struct in_addr l_in_addr;
                if (inet_pton(AF_INET, (const char *)l_gdb_link_ip_str, &l_in_addr) > 0) {
                    PVT(l_net)->gdb_sync_nodes_links_ips[PVT(l_net)->gdb_sync_nodes_links_count] = l_in_addr.s_addr;
                    PVT(l_net)->gdb_sync_nodes_links_ports[PVT(l_net)->gdb_sync_nodes_links_count] = l_gdb_link_port;
                    PVT(l_net)->gdb_sync_nodes_links_count++;
                }
            }
        }
        // groups for special sync
        uint16_t l_gdb_sync_groups_count;
        char **l_gdb_sync_groups = dap_config_get_array_str(l_cfg, "general", "gdb_sync_groups", &l_gdb_sync_groups_count);
        if (l_gdb_sync_groups && l_gdb_sync_groups_count > 0) {
            for(uint16_t i = 0; i < l_gdb_sync_groups_count; i++) {
                // add group to special sync
                dap_chain_global_db_add_sync_extra_group(l_net->pub.name, l_gdb_sync_groups[i], s_gbd_history_callback_notify, l_net);
            }
        }

        // Add network to the list
        dap_chain_net_item_t * l_net_item = DAP_NEW_Z( dap_chain_net_item_t);
        dap_chain_net_item_t * l_net_item2 = DAP_NEW_Z( dap_chain_net_item_t);
        dap_snprintf(l_net_item->name,sizeof (l_net_item->name),"%s"
                     ,dap_config_get_item_str(l_cfg , "general" , "name" ));
        l_net_item->chain_net = l_net;
        l_net_item->net_id.uint64 = l_net->pub.id.uint64;
        pthread_rwlock_wrlock(&g_net_items_rwlock);
        HASH_ADD_STR(s_net_items,name,l_net_item);
        pthread_rwlock_unlock(&g_net_items_rwlock);

        memcpy( l_net_item2,l_net_item,sizeof (*l_net_item));
        pthread_rwlock_wrlock(&g_net_ids_rwlock);
        HASH_ADD(hh,s_net_items_ids,net_id,sizeof ( l_net_item2->net_id),l_net_item2);
        pthread_rwlock_unlock(&g_net_ids_rwlock);

        // LEDGER model
        uint16_t l_ledger_flags = 0;
        switch ( PVT( l_net )->node_role.enums ) {
            case NODE_ROLE_ROOT_MASTER:
            case NODE_ROLE_ROOT:
            case NODE_ROLE_ARCHIVE:
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
            char *l_addr_key = dap_strdup_printf("node-addr-%s", l_net->pub.name);
            l_pub_key_data = dap_chain_global_db_gr_get(l_addr_key, &l_pub_key_data_size, GROUP_LOCAL_NODE_ADDR);
            // generate a new pub key if it doesn't exist
            if(!l_pub_key_data || !l_pub_key_data_size){

                const char * l_certs_name_str = l_addr_key;
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
                        dap_chain_global_db_gr_set(l_addr_key, l_pub_key_data, l_pub_key_data_size,
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
            DAP_DELETE(l_addr_key);
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
            dap_chain_node_addr_t *l_seed_node_addr;
            dap_chain_node_info_t *l_node_info = NULL;
            l_seed_node_addr = dap_chain_node_alias_find(l_net, l_net_pvt->seed_aliases[i]);
            if (l_seed_node_addr) {
                l_node_info = dap_chain_node_info_read(l_net, l_seed_node_addr);
                DAP_DELETE(l_seed_node_addr);
            }
            if (!l_seed_node_addr || !l_node_info) {
                log_it(L_NOTICE, "Update alias %s in database, prefill it",l_net_pvt->seed_aliases[i]);
                l_node_info = DAP_NEW_Z(dap_chain_node_info_t);
                l_seed_node_addr = DAP_NEW_Z(dap_chain_node_addr_t);
                dap_snprintf( l_node_info->hdr.alias,sizeof ( l_node_info->hdr.alias),"%s",PVT(l_net)->seed_aliases[i]);
                if (dap_sscanf(l_seed_nodes_addrs[i],NODE_ADDR_FP_STR, NODE_ADDR_FPS_ARGS(l_seed_node_addr) ) != 4 ){
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
                                log_it(L_WARNING,"Cant register alias %s for address "NODE_ADDR_FP_STR, l_net_pvt->seed_aliases[i], NODE_ADDR_FP_ARGS(l_seed_node_addr));
                            }
                        }else{
                            log_it(L_WARNING,"Cant save node info for address "NODE_ADDR_FP_STR" return code %d",
                                   NODE_ADDR_FP_ARGS(l_seed_node_addr), l_ret);
                        }
                    }
                    DAP_DELETE(l_seed_node_addr);
                }else
                    log_it(L_WARNING,"No address for seed node, can't populate global_db with it");
                DAP_DELETE( l_node_info);
            } else {
                log_it(L_DEBUG,"Seed alias %s is present", PVT(l_net)->seed_aliases[i]);
                DAP_DELETE(l_node_info);
            }
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
                if (dap_sscanf(l_node_addr_str, "0x%016"DAP_UINT64_FORMAT_x, &l_node_addr->uint64 ) == 1 ){
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
                            uint16_t l_node_info_port = l_ext_port ? l_ext_port :
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
                        if (l_net_pvt->node_info->hdr.ext_port &&
                                (l_net_pvt->node_info->hdr.ext_addr_v4.s_addr != INADDR_ANY ||
                                 memcmp(&l_net_pvt->node_info->hdr.ext_addr_v6, &in6addr_any, sizeof(struct in6_addr))))
                            // Save only info with non null address & port!
                            dap_chain_node_info_save(l_net,l_net_pvt->node_info);
                    }
                    log_it(L_NOTICE,"GDB Info: node_addr: " NODE_ADDR_FP_STR"  links: %u cell_id: 0x%016"DAP_UINT64_FORMAT_X,
                           NODE_ADDR_FP_ARGS(l_node_addr),
                           l_net_pvt->node_info->hdr.links_number,
                           l_net_pvt->node_info->hdr.cell_id.uint64);
                }
            }
            else{
                log_it(L_WARNING, "Not present our own address %s in database", (l_node_alias_str) ? l_node_alias_str: "");
            }


         }
        char * l_chains_path = dap_strdup_printf("%s/network/%s", dap_config_path(), l_net->pub.name);
        DIR * l_chains_dir = opendir(l_chains_path);
        DAP_DEL_Z(l_chains_path);
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
            dap_chain_t *l_chain;
            dap_list_t *l_list = l_prior_list;
            while(l_list){
                list_priority *l_chain_prior = l_list->data;
                // Create chain object
                l_chain = dap_chain_load_from_cfg(l_net->pub.ledger, l_net->pub.name,
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
            dap_list_free_full(l_prior_list, NULL);

            dap_chain_t *l_chain02;

            DL_FOREACH(l_net->pub.chains, l_chain){
                DL_FOREACH(l_net->pub.chains, l_chain02){
                    if (l_chain != l_chain02){
                        if (l_chain->id.uint64 == l_chain02->id.uint64)
                        {
                            log_it(L_ERROR, "Your network %s has chains with duplicate ids: 0x%"DAP_UINT64_FORMAT_U", chain01: %s, chain02: %s", l_chain->net_name,
                                            l_chain->id.uint64, l_chain->name,l_chain02->name);
                            log_it(L_ERROR, "Please, fix your configs and restart node");
                            return -2;
                        }
                        if (!dap_strcmp(l_chain->name, l_chain02->name))
                        {
                            log_it(L_ERROR, "Your network %s has chains with duplicate names %s: chain01 id = 0x%"DAP_UINT64_FORMAT_U", chain02 id = 0x%"DAP_UINT64_FORMAT_U"",l_chain->net_name,
                                   l_chain->name, l_chain->id.uint64, l_chain02->id.uint64);
                            log_it(L_ERROR, "Please, fix your configs and restart node");
                            return -2;
                        }
						remove_duplicates_in_chain_by_priority(l_chain, l_chain02);
                    }
                }
            }

            bool l_processed;
            do {
                l_processed = false;
                DL_FOREACH(l_net->pub.chains, l_chain) {
                    if (l_chain->callback_atom_add_from_treshold) {
                        while (l_chain->callback_atom_add_from_treshold(l_chain, NULL)) {
                            log_it(L_DEBUG, "Added atom from treshold");
                            l_processed = true;
                        }
                    }
                }
            } while (l_processed);

            const char* l_default_chain_name = dap_config_get_item_str(l_cfg , "general" , "default_chain");
            if(l_default_chain_name)
                l_net->pub.default_chain = dap_chain_net_get_chain_by_name(l_net, l_default_chain_name);
            else
                l_net->pub.default_chain = NULL;

        } else {
            log_it(L_ERROR, "Can't find any chains for network %s", l_net->pub.name);
            l_net_pvt->load_mode = false;
            return -2;
        }
        // Do specific role actions post-chain created
        l_net_pvt->state_target = NET_STATE_OFFLINE;
        dap_chain_net_state_t l_target_state = NET_STATE_OFFLINE;
        l_net_pvt->only_static_links = false;
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
                l_net_pvt->only_static_links = true;
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
                }
                l_net_pvt->only_static_links = true;
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
        if (!l_net_pvt->only_static_links)
            l_net_pvt->only_static_links = dap_config_get_item_bool_default(l_cfg, "general", "links_static_only", false);
        if (s_seed_mode || !dap_config_get_item_bool_default(g_config ,"general", "auto_online",false ) ) { // If we seed we do everything manual. First think - prefil list of node_addrs and its aliases
            l_target_state = NET_STATE_OFFLINE;
        }
        l_net_pvt->load_mode = false;
        dap_chain_ledger_load_end(l_net->pub.ledger);

        // reload ledger cache at once
        s_chain_net_reload_ledger_cache_once(l_net);

        dap_chain_net_add_gdb_notify_callback(l_net, dap_chain_net_sync_gdb_broadcast, l_net);
        if (l_target_state != l_net_pvt->state_target)
            dap_chain_net_state_go_to(l_net, l_target_state);

        // Start the proc thread
        log_it(L_INFO, "Chain network \"%s\" initialized",l_net_item->name);

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
    pthread_rwlock_rdlock(&g_net_items_rwlock);
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
        pthread_rwlock_unlock(&g_net_items_rwlock);
    } else {
        pthread_rwlock_unlock(&g_net_items_rwlock);
        return NULL;
    }
}

/**
 * @brief dap_chain_net_by_name
 * @param a_name
 * @return
 */
dap_chain_net_t * dap_chain_net_by_name( const char * a_name)
{
    dap_chain_net_item_t * l_net_item = NULL;
    if(a_name) {
        pthread_rwlock_rdlock(&g_net_items_rwlock);
        HASH_FIND_STR(s_net_items,a_name,l_net_item );
        pthread_rwlock_unlock(&g_net_items_rwlock);
    }
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
    pthread_rwlock_rdlock(&g_net_ids_rwlock);
    HASH_FIND(hh,s_net_items_ids,&a_id,sizeof (a_id), l_net_item );
    pthread_rwlock_unlock(&g_net_ids_rwlock);
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
        for(int i = 0; i < l_chain->datum_types_count; i++) {
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
        for(int i = 0; i < l_chain->datum_types_count; i++) {
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
void dap_chain_net_set_flag_sync_from_zero(dap_chain_net_t * a_net, bool a_flag_sync_from_zero)
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
            log_it(L_INFO, "%s.%s: Found %zu records :", a_net->pub.name, l_chain->name,
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
                    dap_chain_global_db_gr_del( l_objs[i].key, l_gdb_group_mempool);
                    l_datums[i] = NULL;
                }else{
                    l_datums[i] = l_datum;
                    if(i < l_objs_size_tmp) {
                        char buf[50] = { '\0' };
                        const char *l_type = NULL;
                        DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_type)
                        dap_time_t l_ts_create = (dap_time_t) l_datum->header.ts_create;
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
                dap_chain_global_db_gr_del(l_objs[i].key, l_gdb_group_mempool);
                if(i < l_objs_processed_tmp) {
                    dap_string_append_printf(l_str_tmp, "New event created, removed datum 0x%s from mempool \n",
                            l_objs[i].key);
                }
            }
            if(l_objs_processed < l_datums_size)
                log_it(L_WARNING, "%s.%s: %zu records not processed", a_net->pub.name, l_chain->name,
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
    dap_ledger_t * l_ledger = a_net->pub.ledger;
    dap_chain_datum_tx_t * l_tx = NULL;

    switch (a_search_type) {
        case TX_SEARCH_TYPE_NET:
        case TX_SEARCH_TYPE_CELL:
        case TX_SEARCH_TYPE_LOCAL:
        case TX_SEARCH_TYPE_CELL_SPENT:
        case TX_SEARCH_TYPE_NET_SPENT: {

            if ( ! l_tx ){
                // pass all chains
                for ( dap_chain_t * l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next){
                    if ( l_chain->callback_tx_find_by_hash ){
                        // try to find transaction in chain ( inside shard )
                        l_tx = l_chain->callback_tx_find_by_hash(l_chain, a_tx_hash);
                        if (l_tx) {
                            if ((a_search_type == TX_SEARCH_TYPE_CELL_SPENT ||
                                    a_search_type == TX_SEARCH_TYPE_NET_SPENT) &&
                                    (!dap_chain_ledger_tx_spent_find_by_hash(l_ledger, a_tx_hash)))
                                return NULL;
                            break;
                        }
                    }
                }
            }
        } break;

        case TX_SEARCH_TYPE_NET_UNSPENT:
        case TX_SEARCH_TYPE_CELL_UNSPENT:
            l_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, a_tx_hash);
            break;
    }
    return l_tx;
}

/**
 * @brief dap_chain_net_get_add_gdb_group
 * @param a_net
 * @param a_node_addr
 * @return
 */
bool dap_chain_net_get_add_gdb_group(dap_chain_net_t *a_net, dap_chain_node_addr_t a_node_addr)
{
    if(!a_net || !PVT(a_net) || !PVT(a_net)->gdb_sync_nodes_addrs)
        return false;
    for(uint16_t i = 0; i < PVT(a_net)->gdb_sync_nodes_addrs_count; i++) {
        if(a_node_addr.uint64 == PVT(a_net)->gdb_sync_nodes_addrs[i].uint64) {
            return true;
        }
    }
    return false;
}

/**
 * @brief dap_chain_net_verify_datum_for_add
 * process datum verification process. Can be:
 *   if DAP_CHAIN_DATUM_TX, called dap_chain_ledger_tx_add_check
 *   if DAP_CHAIN_DATUM_TOKEN_DECL, called dap_chain_ledger_token_decl_add_check
 *   if DAP_CHAIN_DATUM_TOKEN_EMISSION, called dap_chain_ledger_token_emission_add_check
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
        case DAP_CHAIN_DATUM_TX:
            return dap_chain_ledger_tx_add_check( a_net->pub.ledger, (dap_chain_datum_tx_t*)a_datum->data );
        case DAP_CHAIN_DATUM_TOKEN_DECL:
            return dap_chain_ledger_token_decl_add_check( a_net->pub.ledger, (dap_chain_datum_token_t *)a_datum->data);
        case DAP_CHAIN_DATUM_TOKEN_EMISSION:
            return dap_chain_ledger_token_emission_add_check( a_net->pub.ledger, a_datum->data, a_datum->header.data_size );
        default: return 0;
    }
}

/**
 * @brief check certificate access list, written in chain config
 *
 * @param a_net - network object
 * @param a_pkey_hash - certificate hash
 * @return true
 * @return false
 */
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
                    if (!memcmp(&l_cert_hash, a_pkey_hash, sizeof(dap_chain_hash_fast_t))) {
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

/**
 * @brief s_acl_callback function. Usually called from enc_http_proc
 * set acl (l_enc_key_ks->acl_list) from acl_accept_ca_list, acl_accept_ca_gdb chain config parameters in [auth] section
 * @param a_pkey_hash dap_chain_hash_fast_t hash object
 * @return uint8_t*
 */
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

/**
 * @brief dap_cert_chain_file_save
 * @param datum
 */
int dap_cert_chain_file_save(dap_chain_datum_t *datum, char *net_name)
{
    const char *s_system_chain_ca_dir = dap_config_get_item_str(g_config, "resources", "chain_ca_folder");
    if(dap_strlen(s_system_chain_ca_dir) == 0) {
        log_it(L_ERROR, "Not found 'chain_ca_folder' in .cfg file");
        return -1;
    }
    dap_cert_t *cert = dap_cert_mem_load(datum->data, datum->header.data_size);
    if(!cert) {
        log_it(L_ERROR, "Can't load cert, size: %d", datum->header.data_size);
        return -1;
    }
    const char *cert_name = cert->name;
    size_t cert_path_length = dap_strlen(net_name) + dap_strlen(cert_name) + 9 + dap_strlen(s_system_chain_ca_dir);
    char *cert_path = DAP_NEW_Z_SIZE(char, cert_path_length);
    snprintf(cert_path, cert_path_length, "%s/%s/%s.dcert", s_system_chain_ca_dir, net_name, cert_name);
    // In cert_path resolve all `..` and `.`s
    char *cert_path_c = dap_canonicalize_filename(cert_path, NULL);
    DAP_DELETE(cert_path);
    // Protect the ca folder from using "/.." in cert_name
    if(dap_strncmp(s_system_chain_ca_dir, cert_path_c, dap_strlen(s_system_chain_ca_dir))) {
        log_it(L_ERROR, "Cert path '%s' is not in ca dir: %s", cert_path_c, s_system_chain_ca_dir);
        return -1;
    }
    int l_ret = dap_cert_file_save(cert, cert_path_c);
    DAP_DELETE(cert_path_c);
//  if ( access( l_cert_path, F_OK ) != -1 ) {
//      log_it (L_ERROR, "File %s is already exists.", l_cert_path);
//      return -1;
//  } else
    return l_ret;
}
