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
#include "dap_chain.h"
#include "dap_list.h"
#include "dap_time.h"
#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_enc_base58.h"
#include "dap_config.h"
#include "dap_hash.h"
#include "dap_cert.h"
#include "dap_cert_file.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_out.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_timerfd.h"
#include "dap_stream_worker.h"
#include "dap_worker.h"
#include "dap_proc_queue.h"
#include "dap_proc_thread.h"
#include "dap_enc_http.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_anchor.h"
#include "dap_chain_tx.h"
#include "dap_chain_net.h"
#include "dap_chain_net_node_list.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_anchor.h"
#include "dap_chain_net_decree.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_balancer.h"
#include "dap_chain_pvt.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_notify_srv.h"
#include "dap_chain_ledger.h"
#include "dap_chain_cs_none.h"
#include "dap_client_http.h"
#include "dap_global_db.h"
#include "dap_global_db_remote.h"

#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_stream_ch.h"
#include "dap_stream.h"
#include "dap_stream_ch_pkt.h"
#include "dap_chain_node_dns_client.h"
#include "dap_module.h"
#include "rand/dap_rand.h"
#include "json.h"
#include "json_object.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_net_srv_xchange.h"

#include "dap_chain_cs_esbocs.h"

#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

#define LOG_TAG "chain_net"

#define F_DAP_CHAIN_NET_SYNC_FROM_ZERO   ( 1 << 8 )

static bool s_debug_more = false;

#define NODELIST_GROUP_NAME "nodes.v2"

struct balancer_link_request {
    dap_chain_node_info_t *link_info;
    dap_chain_net_t *net;
    dap_worker_t *worker;
    bool from_http;
    int link_replace_tries;
};

struct net_link {
    uint64_t uplink_ip;
    dap_chain_node_info_t *link_info;
    dap_chain_node_client_t *link;
    dap_timerfd_t *delay_timer;
    UT_hash_handle hh;
};

struct downlink {
    dap_chain_net_t *net;
    dap_stream_worker_t *worker;
    dap_stream_ch_uuid_t ch_uuid;
    dap_events_socket_uuid_t esocket_uuid;
    char addr[INET_ADDRSTRLEN];
    int port;
    UT_hash_handle hh;
};

struct block_reward {
    uint64_t block_number;
    uint256_t reward;
    struct block_reward *prev, *next;
};

/**
  * @struct dap_chain_net_pvt
  * @details Private part of chain_net dap object
  */
typedef struct dap_chain_net_pvt{
    pthread_t proc_tid;
    dap_chain_node_role_t node_role;
    uint32_t  flags;
    time_t    last_sync;

    dap_chain_node_addr_t * node_addr;
    dap_chain_node_info_t * node_info;  // Current node's info

    atomic_uint balancer_link_requests;
    bool balancer_http;
    //Active synchronizing link
    dap_chain_node_client_t *active_link;
    dap_list_t *links_queue;            // Links waiting for sync

    struct net_link *net_links;         // Links HT
    bool only_static_links;
    uint16_t required_links_count;
    uint16_t max_links_count;
    uint16_t reconnect_delay;         // sec

    struct downlink *downlinks;         // HT of links who sent SYNC REQ, it used for sync broadcasting
    atomic_uint downlinks_cnt;

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
    struct in_addr *seed_nodes_addrs_v4;
    uint16_t *seed_nodes_ports;
    uint64_t *seed_nodes_addrs;

    _Atomic(dap_chain_net_state_t) state, state_target;
    uint16_t acl_idx;

    // Main loop timer
    dap_interval_timer_t main_timer;
    pthread_mutex_t uplinks_mutex, downlinks_mutex;
    pthread_rwlock_t states_lock;

    dap_list_t *gdb_notifiers;

    dap_interval_timer_t update_links_timer;

    // Block sign rewards history
    struct block_reward *rewards;
} dap_chain_net_pvt_t;

typedef struct dap_chain_net_item{
    char name[DAP_CHAIN_NET_NAME_MAX];
    dap_chain_net_id_t net_id;
    dap_chain_net_t *chain_net;
    UT_hash_handle hh, hh2;
} dap_chain_net_item_t;

#define PVT(a) ( (dap_chain_net_pvt_t *) (void*) a->pvt )
#define PVT_S(a) ( (dap_chain_net_pvt_t *) (void*) a.pvt )

static dap_chain_net_item_t *s_net_items = NULL, *s_net_ids = NULL;

static const char *c_net_states[] = {
    [NET_STATE_OFFLINE]             = "NET_STATE_OFFLINE",
    [NET_STATE_LINKS_PREPARE ]      = "NET_STATE_LINKS_PREPARE",
    [NET_STATE_LINKS_CONNECTING]    = "NET_STATE_LINKS_CONNECTING",
    [NET_STATE_LINKS_ESTABLISHED]   = "NET_STATE_LINKS_ESTABLISHED",
    [NET_STATE_SYNC_GDB]            = "NET_STATE_SYNC_GDB",
    [NET_STATE_SYNC_CHAINS]         = "NET_STATE_SYNC_CHAINS",
    [NET_STATE_ADDR_REQUEST]        = "NET_STATE_ADDR_REQUEST",
    [NET_STATE_ONLINE]              = "NET_STATE_ONLINE"
};

static inline const char * dap_chain_net_state_to_str(dap_chain_net_state_t a_state) {
    return a_state < NET_STATE_OFFLINE || a_state > NET_STATE_ONLINE ? "NET_STATE_INVALID" : c_net_states[a_state];
}

// Node link callbacks
static void s_node_link_callback_connected(dap_chain_node_client_t * a_node_client, void * a_arg);
static void s_node_link_callback_disconnected(dap_chain_node_client_t * a_node_client, void * a_arg);
static void s_node_link_callback_stage(dap_chain_node_client_t * a_node_client,dap_client_stage_t a_stage, void * a_arg);
static void s_node_link_callback_error(dap_chain_node_client_t * a_node_client, int a_error, void * a_arg);
static void s_node_link_callback_delete(dap_chain_node_client_t * a_node_client, void * a_arg);

static const dap_chain_node_client_callbacks_t s_node_link_callbacks = {
    .connected      = s_node_link_callback_connected,
    .disconnected   = s_node_link_callback_disconnected,
    .stage          = s_node_link_callback_stage,
    .error          = s_node_link_callback_error,
    .delete         = s_node_link_callback_delete
};

// State machine switchs here
static bool s_net_states_proc(dap_proc_thread_t *a_thread, void *a_arg);

struct json_object *s_net_states_json_collect(dap_chain_net_t * l_net);

static void s_net_states_notify(dap_chain_net_t * l_net);

//static void s_net_proc_kill( dap_chain_net_t * a_net );
int s_net_init(const char * a_net_name, uint16_t a_acl_idx);

int s_net_load(dap_chain_net_t *a_net);

// Notify callback for GlobalDB changes
static void s_gbd_history_callback_notify(dap_global_db_context_t *a_context, dap_store_obj_t *a_obj, void *a_arg);
static void s_chain_callback_notify(void * a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id, void *a_atom, size_t a_atom_size);
static int s_cli_net(int argc, char ** argv, char **str_reply);
static uint8_t *s_net_set_acl(dap_chain_hash_fast_t *a_pkey_hash);
static void s_prepare_links_from_balancer(dap_chain_net_t *a_net);
static bool s_new_balancer_link_request(dap_chain_net_t *a_net, int a_link_replace_tries);

//Timer update links

static void s_update_links_timer_callback(void *a_arg){
    dap_chain_net_t *l_net = (dap_chain_net_t*)a_arg;
    //Updated links
   dap_chain_net_node_list_request(l_net, NULL, true, 1);
}

/**
 * @brief
 * init network settings from cellrame-node.cfg file
 * register net* commands in cellframe-node-cli interface
 * @return
 */
int dap_chain_net_init()
{
    dap_ledger_init();
    dap_stream_ch_chain_init();
    dap_stream_ch_chain_net_init();
    dap_chain_node_client_init();
    dap_cli_server_cmd_add ("net", s_cli_net, "Network commands",
        "net list [chains -net <chain net name>]\n"
            "\tList all networks or list all chains in selected network\n"
        "net -net <chain net name> [-mode {update | all}] go {online | offline | sync}\n"
            "\tFind and establish links and stay online. \n"
            "\tMode \"update\" is by default when only new chains and gdb are updated. Mode \"all\" updates everything from zero\n"
        "net -net <chain net name> get {status | fee | id}\n"
            "\tDisplays the current current status, current fee or net id.\n"
        "net -net <chain net name> stats {tx | tps} [-from <From time>] [-to <To time>] [-prev_sec <Seconds>] \n"
            "\tTransactions statistics. Time format is <Year>-<Month>-<Day>_<Hours>:<Minutes>:<Seconds> or just <Seconds> \n"
        "net -net <chain net name> [-mode {update | all}] sync {all | gdb | chains}\n"
            "\tSyncronyze gdb, chains or everything\n"
            "\tMode \"update\" is by default when only new chains and gdb are updated. Mode \"all\" updates everything from zero\n"
        "net -net <chain net name> link {list | add | del | info [-addr] | disconnect_all}\n"
            "\tList, add, del, dump or establish links\n"
        "net -net <chain net name> ca add {-cert <cert name> | -hash <cert hash>}\n"
            "\tAdd certificate to list of authority cetificates in GDB group\n"
        "net -net <chain net name> ca list\n"
            "\tPrint list of authority cetificates from GDB group\n"
        "net -net <chain net name> ca del -hash <cert hash> [-H {hex | base58(default)}]\n"
            "\tDelete certificate from list of authority cetificates in GDB group by it's hash\n"
        "net -net <chain net name> ledger reload\n"
            "\tPurge the cache of chain net ledger and recalculate it from chain file\n"
        "net -net <chain net name> poa_cets list\n"
            "\tPrint list of PoA cerificates for this network\n");

    s_debug_more = dap_config_get_item_bool_default(g_config,"chain_net","debug_more",false);

    char * l_net_dir_str = dap_strdup_printf("%s/network", dap_config_path());
    DIR * l_net_dir = opendir( l_net_dir_str);
    if ( l_net_dir ){
        struct dirent * l_dir_entry = NULL;
        uint16_t l_acl_idx = 0;
        while ( (l_dir_entry = readdir(l_net_dir) ) ){
            if (l_dir_entry->d_name[0]=='\0' || l_dir_entry->d_name[0]=='.')
                continue;
            // don't search in directories
            char l_full_path[MAX_PATH + 1] = {0};
            dap_snprintf(l_full_path, sizeof(l_full_path), "%s/%s", l_net_dir_str, l_dir_entry->d_name);
            if(dap_dir_test(l_full_path)) {
                continue;
            }
            // search only ".cfg" files
            if(strlen(l_dir_entry->d_name) > 4) { // It has non zero name excluding file extension
                if( strncmp(l_dir_entry->d_name + strlen(l_dir_entry->d_name) - 4, ".cfg", 4) ) {
                    // its not .cfg file
                    continue;
                }
            }
            log_it(L_DEBUG,"Network config %s try to load", l_dir_entry->d_name);
            //char* l_dot_pos = rindex(l_dir_entry->d_name,'.');
            char* l_dot_pos = strchr(l_dir_entry->d_name,'.');
            if ( l_dot_pos )
                *l_dot_pos = '\0';
            s_net_init(l_dir_entry->d_name, l_acl_idx++);
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

    dap_enc_http_set_acl_callback(s_net_set_acl);
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
 * @brief set current network state to F_DAP_CHAIN_NET_GO_SYNC
 *
 * @param a_net dap_chain_net_t network object
 * @param a_new_state dap_chain_net_state_t new network state
 * @return int
 */
int dap_chain_net_state_go_to(dap_chain_net_t * a_net, dap_chain_net_state_t a_new_state)
{
    if (PVT(a_net)->load_mode) {
        log_it(L_ERROR, "Can't change state of loading network '%s'", a_net->pub.name);
        return -1;
    }
    if (PVT(a_net)->state != NET_STATE_OFFLINE){
        PVT(a_net)->state = PVT(a_net)->state_target = NET_STATE_OFFLINE;
        s_net_states_proc(NULL, a_net);
    }
    PVT(a_net)->state_target = a_new_state;
    //PVT(a_net)->flags |= F_DAP_CHAIN_NET_SYNC_FROM_ZERO;  // TODO set this flag according to -mode argument from command line
    if(a_new_state == NET_STATE_ONLINE)
        dap_chain_esbocs_start_timer(a_net->pub.id);

    if (a_new_state == NET_STATE_OFFLINE){
        dap_chain_esbocs_stop_timer(a_net->pub.id);
        return 0;
    }
    return dap_proc_queue_add_callback(dap_events_worker_get_auto(), s_net_states_proc, a_net);
}

dap_chain_net_state_t dap_chain_net_get_target_state(dap_chain_net_t *a_net)
{
    dap_chain_net_state_t l_ret = PVT(a_net)->state_target;
    return l_ret;
}

/**
 * @brief set s_srv_callback_notify
 *
 * @param a_callback dap_global_db_obj_callback_notify_t callback function
 */
void dap_chain_net_add_gdb_notify_callback(dap_chain_net_t *a_net, dap_store_obj_callback_notify_t a_callback, void *a_cb_arg)
{
    dap_chain_gdb_notifier_t *l_notifier = DAP_NEW(dap_chain_gdb_notifier_t);
    if (!l_notifier) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    }
    l_notifier->callback = a_callback;
    l_notifier->cb_arg = a_cb_arg;
    PVT(a_net)->gdb_notifiers = dap_list_append(PVT(a_net)->gdb_notifiers, l_notifier);
}

void dap_chain_net_add_downlink_cb(UNUSED_ARG dap_worker_t *a_worker, void *a_arg) {
    struct downlink *l_downlink = (struct downlink*)a_arg;
    if (!l_downlink->net) {
        DAP_DELETE(l_downlink);
        return;
    }
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_downlink->net);
    unsigned a_hash_value;
    HASH_VALUE(&l_downlink->ch_uuid, sizeof(l_downlink->ch_uuid), a_hash_value);
    struct downlink *l_sought_downlink = NULL;
    pthread_mutex_lock(&l_net_pvt->downlinks_mutex);
    HASH_FIND_BYHASHVALUE(hh, l_net_pvt->downlinks, &l_downlink->ch_uuid, sizeof(l_downlink->ch_uuid), a_hash_value, l_sought_downlink);
    if (l_sought_downlink) {
        pthread_mutex_unlock(&l_net_pvt->downlinks_mutex);
        DAP_DELETE(l_downlink);
        return;
    }
    HASH_ADD_BYHASHVALUE(hh, l_net_pvt->downlinks, ch_uuid, sizeof(l_downlink->ch_uuid), a_hash_value, l_downlink);
    l_net_pvt->downlinks_cnt++;
    pthread_mutex_unlock(&l_net_pvt->downlinks_mutex);
}

void dap_chain_net_add_downlink(dap_chain_net_t *a_net, dap_stream_worker_t *a_worker,
                               dap_stream_ch_uuid_t a_ch_uuid, dap_events_socket_uuid_t a_esocket_uuid,
                               char *a_addr, int a_port)
{
    struct downlink *l_downlink = DAP_NEW_Z(struct downlink);
    if (!l_downlink) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    }
    *l_downlink = (struct downlink) {
            .net            = a_net,
            .worker         = a_worker,
            .ch_uuid        = a_ch_uuid,
            .esocket_uuid   = a_esocket_uuid,
            .port           = a_port
    };
    strncpy(l_downlink->addr, a_addr, INET_ADDRSTRLEN - 1);
    dap_worker_exec_callback_on(a_worker->worker, dap_chain_net_add_downlink_cb, l_downlink);
}

uint32_t dap_chain_net_get_downlink_count(dap_chain_net_t *a_net)
{
    uint32_t l_count = 0;
    if (!a_net)
        return -1;
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
    l_count = l_net_pvt->downlinks_cnt;
    return l_count;
}

void dap_chain_net_del_downlink(dap_stream_ch_uuid_t *a_ch_uuid) {
    unsigned l_hash_value;
    HASH_VALUE(a_ch_uuid, sizeof(*a_ch_uuid), l_hash_value);
    struct downlink *l_downlink = NULL;
    for (dap_chain_net_item_t *l_net_item = s_net_items; l_net_item && !l_downlink; l_net_item = l_net_item->hh.next) {
        dap_chain_net_pvt_t *l_net_pvt = PVT(l_net_item->chain_net);
        pthread_mutex_lock(&l_net_pvt->downlinks_mutex);
        HASH_FIND_BYHASHVALUE(hh, l_net_pvt->downlinks, a_ch_uuid, sizeof(*a_ch_uuid), l_hash_value, l_downlink);
        if (l_downlink) {
            HASH_DEL(l_net_pvt->downlinks, l_downlink);
            l_net_pvt->downlinks_cnt--;
            log_it(L_MSG, "Remove downlink %s : %d from net ht", l_downlink->addr, l_downlink->port);
            DAP_DELETE(l_downlink);
        }
        pthread_mutex_unlock(&l_net_pvt->downlinks_mutex);
    }
}

/**
 * @brief executes, when you add data to gdb and sends it to current network connected nodes
 * @param a_arg arguments. Can be network object (dap_chain_net_t)
 * @param a_op_code object type (f.e. l_net->type from dap_store_obj)
 * @param a_group group, for example "chain-gdb.home21-network.chain-F"
 * @param a_key key hex value, f.e. 0x12EFA084271BAA5EEE93B988E73444B76B4DF5F63DADA4B300B051E29C2F93
 * @param a_value buffer with data
 * @param a_value_size buffer size
 */
void dap_chain_net_sync_gdb_broadcast(dap_global_db_context_t *a_context, dap_store_obj_t *a_obj, void *a_arg)
{
    if (!a_arg || !a_obj || !a_obj->group || !a_obj->key)
        return;
    // Check object lifetime for broadcasting decision
    dap_time_t l_time_diff = dap_nanotime_to_sec(dap_nanotime_now() - a_obj->timestamp);
    if (l_time_diff > DAP_BROADCAST_LIFETIME * 60)
        return;

    dap_chain_net_t *l_net = (dap_chain_net_t*)a_arg;
    dap_global_db_pkt_t *l_data_out = dap_global_db_pkt_serialize(a_obj);
    struct downlink *l_link, *l_tmp;
    dap_stream_ch_cachet_t *l_active_downs = NULL;
    pthread_mutex_lock(&PVT(l_net)->downlinks_mutex);
    size_t l_new_count = 0, l_count = HASH_COUNT(PVT(l_net)->downlinks);
    l_active_downs = DAP_NEW_Z_COUNT(dap_stream_ch_cachet_t, l_count);
    HASH_ITER(hh, PVT(l_net)->downlinks, l_link, l_tmp) {
        if (dap_stream_ch_check_uuid_mt(l_link->worker, l_link->ch_uuid)) {
            l_active_downs[l_new_count++] = (dap_stream_ch_cachet_t){ .stream_worker = l_link->worker, .uuid = l_link->ch_uuid };
        }
    }
    pthread_mutex_unlock(&PVT(l_net)->downlinks_mutex);
    if (l_new_count < l_count) {
        l_active_downs = DAP_REALLOC_COUNT(l_active_downs, l_new_count);
    }
    if (!dap_stream_ch_chain_pkt_write_multi_mt(l_active_downs, //_inter(a_context->queue_worker_ch_io_input[l_link->worker->worker->id],
                                         l_new_count,
                                         DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB, l_net->pub.id.uint64,
                                         0, 0, l_data_out,
                                         sizeof(dap_global_db_pkt_t) + l_data_out->data_size))
        debug_if(g_debug_reactor, L_ERROR, "Can't broadcast pkt");

    DAP_DELETE(l_active_downs);
    DAP_DELETE(l_data_out);
}

struct net_broadcast_atoms_args {
    dap_chain_atom_ptr_t atom;
    size_t atom_size;
    dap_chain_net_t *net;
    uint64_t chain_id;
    uint64_t cell_id;
};

static bool s_net_send_atoms(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);

    struct net_broadcast_atoms_args *l_args = a_arg;
    dap_chain_net_t *l_net = l_args->net;
    struct downlink *l_link, *l_tmp;
    dap_stream_ch_cachet_t *l_active_downs = NULL;
    pthread_mutex_lock(&PVT(l_net)->downlinks_mutex);
    size_t l_new_count = 0, l_count = HASH_COUNT(PVT(l_net)->downlinks);
    l_active_downs = DAP_NEW_Z_COUNT(dap_stream_ch_cachet_t, l_count);
    HASH_ITER(hh, PVT(l_net)->downlinks, l_link, l_tmp) {
        if (dap_stream_ch_check_uuid_mt(l_link->worker, l_link->ch_uuid)) {
            l_active_downs[l_new_count++] = (dap_stream_ch_cachet_t){ .stream_worker = l_link->worker, .uuid = l_link->ch_uuid };
        }
    }
    pthread_mutex_unlock(&PVT(l_net)->downlinks_mutex);
    if (l_new_count < l_count) {
        l_active_downs = DAP_REALLOC_COUNT(l_active_downs, l_new_count);
    }
    if(!dap_stream_ch_chain_pkt_write_multi_mt(l_active_downs, l_new_count, DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN,
                                     l_net->pub.id.uint64, l_args->chain_id, l_args->cell_id,
                                     l_args->atom, l_args->atom_size))
        debug_if(g_debug_reactor, L_ERROR, "Can't broadcast atom");
    DAP_DELETE(l_active_downs);
    DAP_DELETE(l_args->atom);
    DAP_DELETE(l_args);
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
    if (!a_arg || !a_chain || !a_atom) {
        log_it(L_ERROR, "Argument is NULL for s_chain_callback_notify");
        return;
    }
    dap_chain_net_t *l_net = (dap_chain_net_t*)a_arg;
    // Check object lifetime for broadcasting decision
    dap_time_t l_time_diff = dap_time_now() - a_chain->callback_atom_get_timestamp(a_atom);
    if (l_time_diff > DAP_BROADCAST_LIFETIME * 60)
        return;

    struct net_broadcast_atoms_args *l_args = DAP_NEW(struct net_broadcast_atoms_args);
    if (!l_args) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    }
    l_args->net = l_net;
    l_args->atom = DAP_DUP_SIZE(a_atom, a_atom_size);
    l_args->atom_size = a_atom_size;
    l_args->chain_id = a_chain->id.uint64;
    l_args->cell_id = a_id.uint64;
    dap_proc_queue_add_callback(dap_events_worker_get_auto(), s_net_send_atoms, l_args);
}

/**
 * @brief added like callback in dap_global_db_add_sync_group
 *
 * @param a_arg arguments. Can be network object (dap_chain_net_t)
 * @param a_op_code object type (f.e. l_net->type from dap_store_obj)
 * @param a_group group, for example "chain-gdb.home21-network.chain-F"
 * @param a_key key hex value, f.e. 0x12EFA084271BAA5EEE93B988E73444B76B4DF5F63DADA4B300B051E29C2F93
 * @param a_value buffer with data
 * @param a_value_len buffer size
 */
static void s_gbd_history_callback_notify(dap_global_db_context_t *a_context, dap_store_obj_t *a_obj, void *a_arg)
{
    if (!a_obj || !a_arg)
        return;
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    for (dap_list_t *it = PVT(l_net)->gdb_notifiers; it; it = it->next) {
        dap_chain_gdb_notifier_t *el = (dap_chain_gdb_notifier_t *)it->data;
        if (!el)
            continue;
        if (el->callback)
            el->callback(a_context, a_obj, el->cb_arg);
    }
    dap_chain_t *l_chain;
    DL_FOREACH(l_net->pub.chains, l_chain) {
        if (!l_chain) {
            continue;
        }
        char *l_gdb_group_str = dap_chain_net_get_gdb_group_mempool_new(l_chain);
        if (!strcmp(a_obj->group, l_gdb_group_str)) {
            for (dap_list_t *it = DAP_CHAIN_PVT(l_chain)->mempool_notifires; it; it = it->next) {
                dap_chain_gdb_notifier_t *el = (dap_chain_gdb_notifier_t *)it->data;
                if (!el)
                    continue;
                if (el->callback)
                    el->callback(a_context, a_obj, el->cb_arg);
            }
        }
        DAP_DELETE(l_gdb_group_str);
    }
}

dap_chain_node_info_t *dap_get_balancer_link_from_cfg(dap_chain_net_t *a_net)
{
    dap_chain_net_pvt_t *l_net_pvt = a_net ? PVT(a_net) : NULL;
    if(!l_net_pvt) return NULL;
    struct in_addr l_addr = {};
    uint16_t i, l_port = 0;
    uint64_t l_node_adrr = 0;
    if (l_net_pvt->seed_aliases_count) {
        do {
            i = dap_random_uint16() % l_net_pvt->seed_aliases_count;
        } while (l_net_pvt->seed_nodes_addrs[i] == l_net_pvt->node_addr->uint64);

        /*dap_chain_node_addr_t *l_remote_addr = dap_chain_node_alias_find(a_net, l_net_pvt->seed_aliases[i]);
        if (l_remote_addr){
            */
            dap_chain_node_info_t *l_link_node_info = DAP_NEW_Z(dap_chain_node_info_t);
            if(l_link_node_info){
                l_link_node_info->hdr.address.uint64 = l_net_pvt->seed_nodes_addrs[i];
                l_link_node_info->hdr.ext_addr_v4.s_addr = l_net_pvt->seed_nodes_addrs_v4[i].s_addr;
                l_link_node_info->hdr.ext_port = l_net_pvt->seed_nodes_ports[i];
                return l_link_node_info;
            }else{
                log_it(L_WARNING,"Can't allocate memory");
                return NULL;
            }
        /*}
        else{
            log_it(L_WARNING,"Can't find alias info for seed alias %s",l_net_pvt->seed_aliases[i]);
            return NULL;
        }*/
    } else if (l_net_pvt->bootstrap_nodes_count) {
        i = dap_random_uint16() % l_net_pvt->bootstrap_nodes_count;
        l_node_adrr = 0;
        l_addr = l_net_pvt->bootstrap_nodes_addrs[i];
        l_port = l_net_pvt->bootstrap_nodes_ports[i];
    }
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

dap_chain_node_info_t *dap_chain_get_root_addr(dap_chain_net_t *a_net, dap_chain_node_addr_t* a_node_addr )
{
    dap_chain_net_pvt_t *l_net_pvt = a_net ? PVT(a_net) : NULL;
    if(!l_net_pvt) return NULL;

    for(int i = 0; i < l_net_pvt->seed_aliases_count; i++)
    {
        if(l_net_pvt->seed_nodes_addrs[i] == a_node_addr->uint64)
        {
            dap_chain_node_info_t *l_link_node_info = DAP_NEW_Z(dap_chain_node_info_t);
            if(l_link_node_info){
                l_link_node_info->hdr.address.uint64 = l_net_pvt->seed_nodes_addrs[i];
                l_link_node_info->hdr.ext_addr_v4.s_addr = l_net_pvt->seed_nodes_addrs_v4[i].s_addr;
                l_link_node_info->hdr.ext_port = l_net_pvt->seed_nodes_ports[i];
                return l_link_node_info;
            }else{
                log_it(L_WARNING,"Can't allocate memory");
                return NULL;
            }

        }
    }
    return NULL;
}

/**
 * @brief Check if the current link is already present or not
 *
 * @param a_net Network
 * @param a_link_node_info Node info
 */
static struct net_link *s_net_link_find(dap_chain_net_t *a_net, dap_chain_node_info_t *a_link_node_info)
{
    uint64_t l_addr = a_link_node_info->hdr.ext_addr_v4.s_addr;
    struct net_link *l_present;
    pthread_mutex_lock(&PVT(a_net)->uplinks_mutex);
    HASH_FIND(hh, PVT(a_net)->net_links, &l_addr, sizeof(l_addr), l_present);
    pthread_mutex_unlock(&PVT(a_net)->uplinks_mutex);
    return l_present;
}

static int s_net_link_add(dap_chain_net_t *a_net, dap_chain_node_info_t *a_link_node_info)
{
    if (!a_link_node_info)
        return -1;
    dap_chain_net_pvt_t *l_pvt_net = PVT(a_net);
    pthread_mutex_lock(&l_pvt_net->uplinks_mutex);
    if (HASH_COUNT(l_pvt_net->net_links) >= PVT(a_net)->max_links_count) {
        pthread_mutex_unlock(&l_pvt_net->uplinks_mutex);
        return 1;
    }
    uint64_t l_own_addr = dap_chain_net_get_cur_addr_int(a_net);
    if (a_link_node_info->hdr.address.uint64 == l_own_addr) {
        pthread_mutex_unlock(&l_pvt_net->uplinks_mutex);
        return -2;
    }
    uint64_t l_addr = a_link_node_info->hdr.ext_addr_v4.s_addr;
    struct net_link *l_new_link;
    HASH_FIND(hh, l_pvt_net->net_links, &l_addr, sizeof(l_addr), l_new_link);
    if (l_new_link) {
        pthread_mutex_unlock(&l_pvt_net->uplinks_mutex);
        return -3;
    }
    l_new_link = DAP_NEW_Z(struct net_link);
    if (!l_new_link) {
        log_it(L_CRITICAL, "Memory allocation error");
        pthread_mutex_unlock(&PVT(a_net)->uplinks_mutex);
        return -4;
    }
    l_new_link->link_info = DAP_DUP(a_link_node_info);
    l_new_link->uplink_ip = a_link_node_info->hdr.ext_addr_v4.s_addr;
    HASH_ADD(hh, l_pvt_net->net_links, uplink_ip, sizeof(l_new_link->uplink_ip), l_new_link);
    pthread_mutex_unlock(&l_pvt_net->uplinks_mutex);
    return 0;
}

static int s_net_link_remove(dap_chain_net_pvt_t *a_net_pvt, dap_chain_node_client_t *a_link, bool a_rebase)
{
    struct net_link *l_link = NULL, *l_link_tmp = NULL, *l_link_found = NULL;
    HASH_ITER(hh, a_net_pvt->net_links, l_link, l_link_tmp) {
        if (l_link->link == a_link) {
            l_link_found = l_link;
            break;
        }
    }
    if (!l_link_found) {
        log_it(L_WARNING, "Can't find link %p to remove it from links HT", a_link);
        return 1;
    }
    HASH_DEL(a_net_pvt->net_links, l_link_found);
    if (l_link_found->delay_timer) {
        dap_timerfd_delete_mt(l_link_found->delay_timer->worker, l_link_found->delay_timer->esocket_uuid);
        l_link_found->delay_timer = NULL;
    }
    dap_chain_node_client_t *l_client = l_link_found->link;
    a_net_pvt->links_queue = dap_list_remove_all(a_net_pvt->links_queue, l_client);
    if (a_rebase) {
        l_link_found->link = NULL;
        // Add it to the list end
        HASH_ADD(hh, a_net_pvt->net_links, uplink_ip, sizeof(l_link_found->uplink_ip), l_link_found);
    } else {
        DAP_DEL_Z(l_link_found->link_info);
        DAP_DELETE(l_link_found);
    }
    return 0;
}

static size_t s_net_get_active_links_count(dap_chain_net_t * a_net)
{
    int l_ret = 0;
    struct net_link *l_link, *l_link_tmp;
    HASH_ITER(hh, PVT(a_net)->net_links, l_link, l_link_tmp)
        if (l_link->link)
            l_ret++;
    return l_ret;
}

static struct net_link *s_get_free_link(dap_chain_net_t *a_net)
{
    struct net_link *l_link, *l_link_tmp;
    HASH_ITER(hh,  PVT(a_net)->net_links, l_link, l_link_tmp) {
        if (l_link->link == NULL)  // We have a free prepared link
            return l_link;
    }
    return NULL;
}

static bool s_net_link_callback_connect_delayed(void *a_arg)
{
    struct net_link *l_link = a_arg;
    dap_chain_node_client_t *l_client = l_link->link;
    log_it(L_MSG, "Connecting to link "NODE_ADDR_FP_STR" [%s]",
           NODE_ADDR_FP_ARGS_S(l_client->info->hdr.address), inet_ntoa(l_client->info->hdr.ext_addr_v4));
    dap_chain_node_client_connect(l_client, "CN");
    l_link->delay_timer = NULL;
    return false;
}

static bool s_net_link_start(dap_chain_net_t *a_net, struct net_link *a_link, uint16_t a_delay)
{
    assert(a_net && a_link);
    dap_chain_node_info_t *l_link_info = a_link->link_info;
    dap_chain_node_client_t *l_client = dap_chain_node_client_create(a_net, l_link_info, &s_node_link_callbacks, a_net);
    if (l_client)
        l_client->keep_connection = true;
    else
        return false;
    a_link->link = l_client;
    if (a_delay) {
        a_link->delay_timer = dap_timerfd_start(a_delay * 1000, s_net_link_callback_connect_delayed, a_link);
        return true;
    }
    log_it(L_MSG, "Connecting to link "NODE_ADDR_FP_STR" [%s]", NODE_ADDR_FP_ARGS_S(l_link_info->hdr.address), inet_ntoa(l_link_info->hdr.ext_addr_v4));
    return dap_chain_node_client_connect(l_client, "CN");
}

/**
 * @brief s_fill_links_from_root_aliases
 * @param a_net
 */
static void s_fill_links_from_root_aliases(dap_chain_net_t * a_net)
{
    int ret = 0;
    dap_chain_net_pvt_t *l_pvt_net = PVT(a_net);
    for (size_t i = 0; i < l_pvt_net->seed_aliases_count; i++) {
        /*
        dap_chain_node_addr_t *l_link_addr = dap_chain_node_alias_find(a_net, l_pvt_net->seed_aliases[i]);
        if (!l_link_addr)
            continue;
        dap_chain_node_info_t *l_link_node_info = dap_chain_node_info_read(a_net, l_link_addr);
        */
        dap_chain_node_info_t *l_link_node_info = dap_get_balancer_link_from_cfg(a_net);
        if (!l_link_node_info)
            log_it(L_WARNING, "Not found any root nodes");
        else {
            ret = s_net_link_add(a_net, l_link_node_info);
            DAP_DELETE(l_link_node_info);
        }
        if (ret > 0)    // Maximum links count reached
            break;
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
    pthread_rwlock_wrlock(&l_net_pvt->states_lock);
    a_node_client->is_connected = true;
    struct json_object *l_json = s_net_states_json_collect(l_net);
    char l_err_str[128] = { };
    snprintf(l_err_str, sizeof(l_err_str)
                 , "Established connection with link " NODE_ADDR_FP_STR
                 , NODE_ADDR_FP_ARGS_S(a_node_client->info->hdr.address));
    json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
    if(l_net_pvt->state == NET_STATE_LINKS_CONNECTING ){
        l_net_pvt->state = NET_STATE_LINKS_ESTABLISHED;
        dap_proc_queue_add_callback_inter(a_node_client->stream_worker->worker->proc_queue_input,s_net_states_proc,l_net );
    }
    pthread_rwlock_unlock(&l_net_pvt->states_lock);
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
    if (a_node_client->is_connected) {
        a_node_client->is_connected = false;
        log_it(L_INFO, "%s."NODE_ADDR_FP_STR" disconnected.%s",l_net->pub.name,
               NODE_ADDR_FP_ARGS_S(a_node_client->info->hdr.address),
               l_net_pvt->state_target == NET_STATE_OFFLINE ? "" : " Replace it...");
    }
    if (l_net_pvt->state_target != NET_STATE_OFFLINE) {
        pthread_mutex_lock(&l_net_pvt->uplinks_mutex);
        if (!s_net_link_remove(l_net_pvt, a_node_client, l_net_pvt->only_static_links)) {
            a_node_client->keep_connection = false;
            a_node_client->callbacks.delete = NULL;
            dap_chain_node_client_close_mt(a_node_client);  // Remove it on next context iteration
        } else {
            log_it(L_ATT, "[!] issue 9928 catched");
        }

        //char *l_key = dap_chain_node_addr_to_hash_str(&a_node_client->info->hdr.address);
        //dap_global_db_del_sync(l_net->pub.gdb_nodes, l_key);
        //DAP_DELETE(l_key);

        struct net_link *l_free_link = s_get_free_link(l_net);
        if (l_free_link) {
            pthread_mutex_unlock(&l_net_pvt->uplinks_mutex);
            s_net_link_start(l_net, l_free_link, l_net_pvt->reconnect_delay);
            return;
        }
        size_t l_current_links_prepared = HASH_COUNT(l_net_pvt->net_links);
        pthread_mutex_unlock(&l_net_pvt->uplinks_mutex);
        if (!l_net_pvt->only_static_links) {
            for (size_t i = l_current_links_prepared; i < l_net_pvt->max_links_count ; i++) {
                s_new_balancer_link_request(l_net, 0);
            }
        }
    }
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
    struct json_object *l_json = s_net_states_json_collect(l_net);
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
    log_it(L_WARNING, "Can't establish link with %s."NODE_ADDR_FP_STR, l_net? l_net->pub.name : "(unknown)" ,
           NODE_ADDR_FP_ARGS_S(a_node_client->remote_node_addr));
    if (l_net){
        struct json_object *l_json = s_net_states_json_collect(l_net);
        char l_node_addr_str[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &a_node_client->info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
        char l_err_str[128] = { };
        snprintf(l_err_str, sizeof(l_err_str)
                     , "Link " NODE_ADDR_FP_STR " [%s] can't be established, errno %d"
                     , NODE_ADDR_FP_ARGS_S(a_node_client->info->hdr.address), l_node_addr_str, a_error);
        json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
        dap_notify_server_send_mt(json_object_get_string(l_json));
        json_object_put(l_json);
    }
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
        struct json_object *l_json = s_net_states_json_collect(l_net);
        json_object_object_add(l_json, "errorMessage", json_object_new_string("Link deleted"));
        dap_notify_server_send_mt(json_object_get_string(l_json));
        json_object_put(l_json);
        return;
    } else if (a_node_client->is_connected)
        a_node_client->is_connected = false;
    dap_chain_net_sync_unlock(l_net, a_node_client);
    pthread_mutex_lock(&l_net_pvt->uplinks_mutex);
    struct net_link *l_link, *l_link_tmp;
    HASH_ITER(hh, l_net_pvt->net_links, l_link, l_link_tmp) {
        if (l_link->link == a_node_client) {
            log_it(L_DEBUG, "Replace node client with new one with %d sec", l_net_pvt->reconnect_delay);
            s_net_link_start(l_net, l_link, l_net_pvt->reconnect_delay);
        }
    }
    pthread_mutex_unlock(&l_net_pvt->uplinks_mutex);
    struct json_object *l_json = s_net_states_json_collect(l_net);
    json_object_object_add(l_json, "errorMessage", json_object_new_string("Link restart"));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
    // Then a_node_client will be destroyed in a right way
}

static void s_net_links_complete_and_start(dap_chain_net_t *a_net, dap_worker_t *a_worker)
{
    dap_chain_net_pvt_t * l_net_pvt = PVT(a_net);
    if (--l_net_pvt->balancer_link_requests == 0){ // It was the last one
        // No links obtained from DNS
        if (HASH_COUNT(l_net_pvt->net_links) == 0 && !l_net_pvt->balancer_http) {
            // Try to get links from HTTP balancer
            l_net_pvt->balancer_http = true;
            s_prepare_links_from_balancer(a_net);
            return;
        }
        if (HASH_COUNT(l_net_pvt->net_links) < l_net_pvt->max_links_count)
            s_fill_links_from_root_aliases(a_net);  // Comlete the sentence
        if (l_net_pvt->state_target != NET_STATE_OFFLINE){
            l_net_pvt->state = NET_STATE_LINKS_CONNECTING;
        }
        dap_proc_queue_add_callback_inter(a_worker->proc_queue_input, s_net_states_proc, a_net);
    }
}

/**
 * @brief s_net_state_link_prepare_success
 * @param a_worker
 * @param a_node_info
 * @param a_arg
 */
static void s_net_balancer_link_prepare_success(dap_worker_t * a_worker, dap_chain_net_node_balancer_t * a_link_full_node_list, void * a_arg)
{
    if(s_debug_more){
        char l_node_addr_str[INET_ADDRSTRLEN]={};
        dap_chain_node_info_t * l_node_info = (dap_chain_node_info_t *)a_link_full_node_list->nodes_info;
        for(size_t i=0;i<a_link_full_node_list->count_node;i++){
            inet_ntop(AF_INET,&(l_node_info + i)->hdr.ext_addr_v4,l_node_addr_str, INET_ADDRSTRLEN);
            log_it(L_DEBUG,"Link " NODE_ADDR_FP_STR " (%s) prepare success", NODE_ADDR_FP_ARGS_S((l_node_info + i)->hdr.address),
                                                                                         l_node_addr_str );
        }
    }

    struct balancer_link_request *l_balancer_request = (struct balancer_link_request *) a_arg;
    dap_chain_net_t * l_net = l_balancer_request->net;
    dap_chain_node_info_t * l_node_info = (dap_chain_node_info_t *)a_link_full_node_list->nodes_info;
    int l_res = 0;
    size_t i = 0;
    char l_err_str[128] = { };
    struct json_object *l_json;
    while(!l_res){
        if(i >= a_link_full_node_list->count_node)
            break;
        l_res = s_net_link_add(l_net, l_node_info + i);
        switch (l_res) {
        case 0:
            l_json = s_net_states_json_collect(l_net);

            snprintf(l_err_str, sizeof(l_err_str)
                         , "Link " NODE_ADDR_FP_STR " prepared"
                         , NODE_ADDR_FP_ARGS_S((l_node_info + i)->hdr.address));
            json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
            dap_notify_server_send_mt(json_object_get_string(l_json));
            json_object_put(l_json);
            debug_if(s_debug_more, L_DEBUG, "Link "NODE_ADDR_FP_STR" successfully added",
                                                   NODE_ADDR_FP_ARGS_S((l_node_info + i)->hdr.address));
            break;
        case 1:
            debug_if(s_debug_more, L_DEBUG, "Maximum prepared links reached");
            break;
        case -1:

            break;
        default:
            break;
        }
        i++;
    }
    struct net_link *l_free_link = NULL;
    bool need_link = false;
    pthread_mutex_lock(&PVT(l_net)->uplinks_mutex);
    if (l_balancer_request->link_replace_tries &&
            s_net_get_active_links_count(l_net) < PVT(l_net)->required_links_count) {
            // Auto-start new link
        dap_chain_net_state_t l_net_state = PVT(l_net)->state_target;
        if (l_net_state != NET_STATE_OFFLINE) {
            l_free_link = s_get_free_link(l_net);
            need_link = true;
        }
    }
    pthread_mutex_unlock(&PVT(l_net)->uplinks_mutex);

    // Auto-start new link
    if(need_link){
        if (l_free_link)
            s_net_link_start(l_net, l_free_link, PVT(l_net)->reconnect_delay);
        else
            s_new_balancer_link_request(l_net, l_balancer_request->link_replace_tries);
    }

    if (!l_balancer_request->link_replace_tries)
        s_net_links_complete_and_start(l_net, a_worker);
    DAP_DELETE(l_balancer_request->link_info);
    DAP_DELETE(l_balancer_request);

}

/**
 * @brief s_net_state_link_prepare_error
 * @param a_worker
 * @param a_node_info
 * @param a_arg
 * @param a_errno
 */
static void s_net_balancer_link_prepare_error(dap_worker_t * a_worker, void * a_arg, int a_errno)
{
    struct balancer_link_request *l_balancer_request = (struct balancer_link_request *)a_arg;
    dap_chain_net_t * l_net = l_balancer_request->net;
    dap_chain_node_info_t *l_node_info = l_balancer_request->link_info;
    char l_node_addr_str[INET_ADDRSTRLEN]={};
    inet_ntop(AF_INET, &l_node_info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
    log_it(L_WARNING, "Link from balancer "NODE_ADDR_FP_STR" (%s) prepare error with code %d",
                                NODE_ADDR_FP_ARGS_S(l_node_info->hdr.address), l_node_addr_str,a_errno);
    struct json_object *l_json = s_net_states_json_collect(l_net);
    char l_err_str[128] = { };
    snprintf(l_err_str, sizeof(l_err_str)
                 , "Link from balancer " NODE_ADDR_FP_STR " [%s] can't be prepared, errno %d"
                 , NODE_ADDR_FP_ARGS_S(l_node_info->hdr.address), l_node_addr_str, a_errno);
    json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
    if (!l_balancer_request->link_replace_tries)
        s_net_links_complete_and_start(l_net, a_worker);
    else
        s_new_balancer_link_request(l_net, l_balancer_request->link_replace_tries);
    //DAP_DELETE(l_node_info);
    //DAP_DELETE(l_balancer_request);
}


void s_net_http_link_prepare_success(void *a_response, size_t a_response_size, void *a_arg)
{
    struct balancer_link_request *l_balancer_request = (struct balancer_link_request *)a_arg;
    dap_chain_net_node_balancer_t* l_link_full_node_list = (dap_chain_net_node_balancer_t*)a_response;


    size_t l_response_size_need = sizeof(dap_chain_net_node_balancer_t) + (sizeof(dap_chain_node_info_t) * l_link_full_node_list->count_node);
    log_it(L_WARNING, "Get data size - %lu need - (%lu)", a_response_size, l_response_size_need);
    if (a_response_size != l_response_size_need) {
        log_it(L_ERROR, "Invalid balancer response size %lu (expected %lu)", a_response_size, l_response_size_need);
        s_new_balancer_link_request(l_balancer_request->net, l_balancer_request->link_replace_tries);
        DAP_DELETE(l_balancer_request);
        return;
    }
    s_net_balancer_link_prepare_success(l_balancer_request->worker, l_link_full_node_list, a_arg);
}

void s_net_http_link_prepare_error(int a_error_code, void *a_arg)
{
    struct balancer_link_request *l_balancer_request = (struct balancer_link_request *)a_arg;
    s_net_balancer_link_prepare_error(l_balancer_request->worker, a_arg, a_error_code);
}

/**
 * @brief Launch a connect with a link
 * @param a_net
 * @param a_link_node_info node parameters
 * @return list of dap_chain_node_info_t
 */
static bool s_new_balancer_link_request(dap_chain_net_t *a_net, int a_link_replace_tries)
{
    dap_chain_net_pvt_t *l_net_pvt = a_net ? PVT(a_net) : NULL;
    if (!l_net_pvt)
        return false;
    if (l_net_pvt->state_target == NET_STATE_OFFLINE) {
        return false;
    }
    if (a_link_replace_tries >= 3) {
        // network problems, make static links
        s_fill_links_from_root_aliases(a_net);
        pthread_mutex_lock(&l_net_pvt->uplinks_mutex);
        struct net_link *l_free_link = s_get_free_link(a_net);
        if (l_free_link)
            s_net_link_start(a_net, l_free_link, l_net_pvt->reconnect_delay);
        pthread_mutex_unlock(&l_net_pvt->uplinks_mutex);
        return true;
    }
    if(!a_link_replace_tries){

        dap_chain_net_node_balancer_t *l_link_full_node_list = dap_chain_net_balancer_get_node(a_net->pub.name,l_net_pvt->max_links_count*2);
        size_t node_cnt = 0,i = 0;
        if(l_link_full_node_list)
        {
            dap_chain_node_info_t * l_node_info = (dap_chain_node_info_t *)l_link_full_node_list->nodes_info;
            node_cnt = l_link_full_node_list->count_node;
            int l_net_link_add = 0;
            size_t l_links_count = 0;
            while(!l_net_link_add && i<node_cnt){

                l_net_link_add = s_net_link_add(a_net, l_node_info + i);
                switch (l_net_link_add) {
                case 0:
                    log_it(L_MSG, "Network LOCAL balancer issues link IP %s, [%ld blocks]", inet_ntoa((l_node_info + i)->hdr.ext_addr_v4),l_node_info->hdr.blocks_events);
                    break;
                case -1:
                    log_it(L_MSG, "Network LOCAL balancer: IP %s is already among links", inet_ntoa((l_node_info + i)->hdr.ext_addr_v4));
                    break;
                case 1:
                    log_it(L_MSG, "Network links table is full");
                    break;
                default:
                    break;
                }
                l_links_count = HASH_COUNT(l_net_pvt->net_links);
                if(l_net_link_add && l_links_count < l_net_pvt->required_links_count && i < node_cnt)l_net_link_add = 0;
                i++;
            }
            DAP_DELETE(l_link_full_node_list);
            pthread_mutex_lock(&l_net_pvt->uplinks_mutex);
            struct net_link *l_free_link = s_get_free_link(a_net);
            if (l_free_link){
                s_net_link_start(a_net, l_free_link, l_net_pvt->reconnect_delay);
                pthread_mutex_unlock(&l_net_pvt->uplinks_mutex);
                return true;
            }
            else
            {
                pthread_mutex_unlock(&l_net_pvt->uplinks_mutex);
                return false;
            }
        }
    }
    dap_chain_node_info_t *l_link_node_info = dap_get_balancer_link_from_cfg(a_net);
    if (!l_link_node_info)
        return false;
    char l_node_addr_str[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &l_link_node_info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
    log_it(L_DEBUG, "Start balancer %s request to %s", PVT(a_net)->balancer_http ? "HTTP" : "DNS", l_node_addr_str);
    struct balancer_link_request *l_balancer_request = DAP_NEW_Z(struct balancer_link_request);
    if (!l_balancer_request) {
        log_it(L_CRITICAL, "Memory allocation error");
        DAP_DELETE(l_link_node_info);
        return false;
    }
    l_balancer_request->net = a_net;
    l_balancer_request->link_info = l_link_node_info;
    l_balancer_request->worker = dap_events_worker_get_auto();
    l_balancer_request->link_replace_tries = a_link_replace_tries + 1;
    int ret;
    if (PVT(a_net)->balancer_http) {
        l_balancer_request->from_http = true;
        char *l_request = dap_strdup_printf("%s/%s?version=1,method=r,needlink=%d,net=%s",
                                                DAP_UPLINK_PATH_BALANCER,
                                                DAP_BALANCER_URI_HASH,
                                                l_net_pvt->required_links_count,
                                                a_net->pub.name);
        ret = dap_client_http_request(l_balancer_request->worker,
                                                l_node_addr_str,
                                                l_link_node_info->hdr.ext_port,
                                                "GET",
                                                "text/text",
                                                l_request,
                                                NULL,
                                                0,
                                                NULL,
                                                s_net_http_link_prepare_success,
                                                s_net_http_link_prepare_error,
                                                l_balancer_request,
                                                NULL) == NULL;
        DAP_DELETE(l_request);
    } else {
        l_link_node_info->hdr.ext_port = DNS_LISTEN_PORT;
        ret = dap_chain_node_info_dns_request(l_balancer_request->worker,
                                                l_link_node_info->hdr.ext_addr_v4,
                                                l_link_node_info->hdr.ext_port,
                                                a_net->pub.name,
                                                s_net_balancer_link_prepare_success,
                                                s_net_balancer_link_prepare_error,
                                                l_balancer_request);
    }
    if (ret) {
        log_it(L_ERROR, "Can't process balancer link %s request", PVT(a_net)->balancer_http ? "HTTP" : "DNS");
        DAP_DELETE(l_balancer_request->link_info);
        DAP_DELETE(l_balancer_request);
        return false;
    }
    if (!a_link_replace_tries)
        l_net_pvt->balancer_link_requests++;
    return true;
}

static void s_prepare_links_from_balancer(dap_chain_net_t *a_net)
{
    if (!a_net) {
        log_it(L_ERROR, "Invalid arguments in s_prepare_links_from_balancer");
        return;
    }
    // Get list of the unique links for l_net
    size_t l_max_links_count = PVT(a_net)->max_links_count;   // Not all will be success
    for (size_t l_cur_links_count = 0, n = 0; n < 100 && l_cur_links_count < l_max_links_count; ++n) {
        if (s_new_balancer_link_request(a_net, 0))
            l_cur_links_count++;
    }
}

struct json_object *s_net_states_json_collect(dap_chain_net_t *a_net)
{
    struct json_object *l_json = json_object_new_object();
    json_object_object_add(l_json, "class"            , json_object_new_string("NetStates"));
    json_object_object_add(l_json, "name"             , json_object_new_string((const char*)a_net->pub.name));
    json_object_object_add(l_json, "networkState"     , json_object_new_string(dap_chain_net_state_to_str(PVT(a_net)->state)));
    json_object_object_add(l_json, "targetState"      , json_object_new_string(dap_chain_net_state_to_str(PVT(a_net)->state_target)));
    json_object_object_add(l_json, "linksCount"       , json_object_new_int(PVT(a_net)->net_links ? HASH_COUNT(PVT(a_net)->net_links) : 0));
    json_object_object_add(l_json, "activeLinksCount" , json_object_new_int(s_net_get_active_links_count(a_net)));
    char l_node_addr_str[24] = {'\0'};
    int l_tmp = PVT(a_net)->node_addr
            ? snprintf(l_node_addr_str, sizeof(l_node_addr_str), NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS(PVT(a_net)->node_addr))
            : 0;
    json_object_object_add(l_json, "nodeAddress"     , json_object_new_string(l_tmp ? l_node_addr_str : "0000::0000::0000::0000"));
    return l_json;
}

/**
 * @brief s_net_states_notify
 * @param l_net
 */
static void s_net_states_notify(dap_chain_net_t *a_net)
{
    struct json_object *l_json = s_net_states_json_collect(a_net);
    json_object_object_add(l_json, "errorMessage", json_object_new_string(" ")); // regular notify has no error
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
}

/**
 * @brief s_net_states_proc
 * @param l_net
 */
static bool s_net_states_proc(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    bool l_repeat_after_exit = false; // If true - repeat on next iteration of proc thread loop
    dap_chain_net_t *l_net = (dap_chain_net_t *) a_arg;
    assert(l_net);
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    assert(l_net_pvt);
    if (l_net_pvt->state_target == NET_STATE_OFFLINE) {
        l_net_pvt->state = NET_STATE_OFFLINE;
    }

    switch ((dap_chain_net_state_t)l_net_pvt->state) {
        // State OFFLINE where we don't do anything
        case NET_STATE_OFFLINE: {
            log_it(L_NOTICE,"%s.state: NET_STATE_OFFLINE", l_net->pub.name);
            // delete all links
            struct net_link *l_link, *l_link_tmp;
            struct downlink *l_downlink, *l_dltmp;
            pthread_mutex_lock(&l_net_pvt->uplinks_mutex);
            HASH_ITER(hh, l_net_pvt->net_links, l_link, l_link_tmp) {
                if (l_link->delay_timer)
                    dap_timerfd_delete_mt(l_link->delay_timer->worker, l_link->delay_timer->esocket_uuid);
                if (l_link->link) {
                    dap_chain_node_client_t *l_client = l_link->link;
                    l_client->callbacks.delete = NULL;
                    dap_chain_node_client_close_mt(l_client);
                }
                HASH_DEL(l_net_pvt->net_links, l_link);
                DAP_DEL_Z(l_link->link_info);
                DAP_DELETE(l_link);
            }
            pthread_mutex_unlock(&l_net_pvt->uplinks_mutex);
            pthread_mutex_lock(&l_net_pvt->downlinks_mutex);
            HASH_ITER(hh, l_net_pvt->downlinks, l_downlink, l_dltmp) {
                HASH_DEL(l_net_pvt->downlinks, l_downlink);
                l_net_pvt->downlinks_cnt--;
                dap_events_socket_delete_mt(l_downlink->worker->worker, l_downlink->esocket_uuid);
                DAP_DELETE(l_downlink);
            }
            pthread_mutex_unlock(&l_net_pvt->downlinks_mutex);
            l_net_pvt->balancer_link_requests = 0;
            l_net_pvt->active_link = NULL;
            dap_list_free(l_net_pvt->links_queue);
            l_net_pvt->links_queue = NULL;
            if ( l_net_pvt->state_target != NET_STATE_OFFLINE ){
                l_net_pvt->state = NET_STATE_LINKS_PREPARE;
                l_repeat_after_exit = true;
            }
            l_net_pvt->last_sync = 0;

        } break;

        // Prepare links
        case NET_STATE_LINKS_PREPARE: {
            log_it(L_NOTICE,"%s.state: NET_STATE_LINKS_PREPARE", l_net->pub.name);
            s_net_states_notify(l_net);
            // Extra links from cfg
            for (int i = 0; i < l_net_pvt->gdb_sync_nodes_links_count; i++) {
                if (i >= l_net_pvt->gdb_sync_nodes_addrs_count)
                    break;
                dap_chain_node_info_t *l_link_node_info = DAP_NEW_Z(dap_chain_node_info_t);
                if (!l_link_node_info) {
                    log_it(L_CRITICAL, "Memory allocation error");
                    return false;
                }
                l_link_node_info->hdr.address.uint64 = l_net_pvt->gdb_sync_nodes_addrs[i].uint64;
                l_link_node_info->hdr.ext_addr_v4.s_addr = l_net_pvt->gdb_sync_nodes_links_ips[i];
                l_link_node_info->hdr.ext_port = l_net_pvt->gdb_sync_nodes_links_ports[i];
                s_net_link_add(l_net, l_link_node_info);
                DAP_DELETE(l_link_node_info);
            }
            // Links from node info structure (currently empty)
            if (l_net_pvt->node_info) {
                for (size_t i = 0; i < l_net_pvt->node_info->hdr.links_number; i++) {
                    dap_chain_node_info_t *l_link_node_info = dap_chain_node_info_read(l_net, &l_net_pvt->node_info->links[i]);
                    s_net_link_add(l_net, l_link_node_info);
                    DAP_DEL_Z(l_link_node_info);
                }
            } else {
                log_it(L_WARNING,"No nodeinfo in global_db to prepare links for connecting, try to add links from root servers");
            }

            if (!l_net_pvt->seed_aliases_count && ! l_net_pvt->bootstrap_nodes_count){
               log_it(L_ERROR, "No root servers present in configuration file. Can't establish DNS requests");
               if (l_net_pvt->net_links) { // We have other links
                   l_net_pvt->state = NET_STATE_LINKS_CONNECTING;
                   l_repeat_after_exit = true;
               }
               break;
            }
            // Get DNS request result from root nodes as synchronization links
            if (!l_net_pvt->only_static_links) {
                s_prepare_links_from_balancer(l_net);
            } else {
                log_it(L_ATT, "Not use bootstrap addresses, fill seed nodelist from root aliases");
                // Add other root nodes as synchronization links
                s_fill_links_from_root_aliases(l_net);
                l_net_pvt->state = NET_STATE_LINKS_CONNECTING;
                l_repeat_after_exit = true;
                break;
            }
        } break;

        case NET_STATE_LINKS_CONNECTING: {
            log_it(L_INFO, "%s.state: NET_STATE_LINKS_CONNECTING",l_net->pub.name);
            size_t l_used_links = 0;
            struct net_link *l_link, *l_link_tmp;
            HASH_ITER(hh, l_net_pvt->net_links, l_link, l_link_tmp) {
                s_net_link_start(l_net, l_link, 0);
                if (++l_used_links == l_net_pvt->required_links_count)
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
            l_net_pvt->last_sync = dap_time_now();
        }
        break;

        default: log_it (L_DEBUG, "Unprocessed state");
    }
    s_net_states_notify(l_net);
    return !l_repeat_after_exit;
}

bool dap_chain_net_sync_trylock(dap_chain_net_t *a_net, dap_chain_node_client_t *a_client)
{
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
    pthread_mutex_lock(&l_net_pvt->uplinks_mutex);
    bool l_found = false;
    if (l_net_pvt->active_link) {
        struct net_link *l_link, *l_link_tmp;
        HASH_ITER(hh, l_net_pvt->net_links, l_link, l_link_tmp) {
            dap_chain_node_client_t *l_client = l_link->link;
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
    if (l_found && !dap_list_find(l_net_pvt->links_queue, a_client, NULL))
        l_net_pvt->links_queue = dap_list_append(l_net_pvt->links_queue, a_client);
    pthread_mutex_unlock(&l_net_pvt->uplinks_mutex);
    return !l_found;
}

bool dap_chain_net_sync_unlock(dap_chain_net_t *a_net, dap_chain_node_client_t *a_client)
{
    if (!a_net)
        return false;
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
    pthread_mutex_lock(&l_net_pvt->uplinks_mutex);
    bool l_ret = false;
    if (!a_client || l_net_pvt->active_link == a_client)
        l_net_pvt->active_link = NULL;
    while (l_net_pvt->active_link == NULL && l_net_pvt->links_queue) {
        dap_chain_node_client_t *l_link = l_net_pvt->links_queue->data;
        dap_chain_node_sync_status_t l_status = dap_chain_node_client_start_sync(l_link);
        if (l_status != NODE_SYNC_STATUS_WAITING)
            // Remove list head
            l_net_pvt->links_queue = dap_list_delete_link(l_net_pvt->links_queue, l_net_pvt->links_queue);
        else
            break;
    }
    l_ret = l_net_pvt->active_link;
    pthread_mutex_unlock(&l_net_pvt->uplinks_mutex);
    if (!l_ret && l_net_pvt->state_target == NET_STATE_ONLINE && l_net_pvt->last_sync) {
        l_net_pvt->state = NET_STATE_ONLINE;
    }
    return l_ret;
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
static dap_chain_net_t *s_net_new(const char *a_id, const char *a_name,
                                  const char *a_native_ticker, const char *a_node_role)
{
    if (!a_id || !a_name || !a_native_ticker || !a_node_role)
        return NULL;
    dap_chain_net_t *l_ret = DAP_NEW_Z_SIZE(dap_chain_net_t, sizeof(dap_chain_net_t) + sizeof(dap_chain_net_pvt_t));
    if (!l_ret) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_ret->pub.name = strdup( a_name );
    l_ret->pub.native_ticker = strdup( a_native_ticker );
    pthread_mutexattr_t l_mutex_attr;
    pthread_mutexattr_init(&l_mutex_attr);
    pthread_mutexattr_settype(&l_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&PVT(l_ret)->uplinks_mutex, &l_mutex_attr);
    pthread_mutex_init(&l_ret->pub.balancer_mutex, &l_mutex_attr);
    pthread_mutex_init(&PVT(l_ret)->downlinks_mutex, &l_mutex_attr);
    pthread_mutexattr_destroy(&l_mutex_attr);
    pthread_rwlock_init(&PVT(l_ret)->states_lock, NULL);
    if (dap_chain_net_id_parse(a_id, &l_ret->pub.id) != 0) {
        DAP_DELETE(l_ret);
        return NULL;
    }
    if (strcmp (a_node_role, "root_master")==0){
        PVT(l_ret)->node_role.enums = NODE_ROLE_ROOT_MASTER;
    } else if (strcmp( a_node_role,"root") == 0){
        PVT(l_ret)->node_role.enums = NODE_ROLE_ROOT;
    } else if (strcmp( a_node_role,"archive") == 0){
        PVT(l_ret)->node_role.enums = NODE_ROLE_ARCHIVE;
    } else if (strcmp( a_node_role,"cell_master") == 0){
        PVT(l_ret)->node_role.enums = NODE_ROLE_CELL_MASTER;
    }else if (strcmp( a_node_role,"master") == 0){
        PVT(l_ret)->node_role.enums = NODE_ROLE_MASTER;
    }else if (strcmp( a_node_role,"full") == 0){
        PVT(l_ret)->node_role.enums = NODE_ROLE_FULL;
    }else if (strcmp( a_node_role,"light") == 0){
        PVT(l_ret)->node_role.enums = NODE_ROLE_LIGHT;
    }else{
        log_it(L_ERROR,"Unknown node role \"%s\" for network '%s'", a_node_role, a_name);
        DAP_DELETE(l_ret);
        return NULL;
    }
    log_it (L_NOTICE, "Node role \"%s\" selected for network '%s'", a_node_role, a_name);
    return l_ret;
}

/**
 * @brief
 * load network config settings
 */
void dap_chain_net_load_all() {
    int32_t l_ret = 0;

    if(!HASH_COUNT(s_net_items)){
        log_it(L_ERROR, "Can't find any nets");
        return;
    }
    dap_chain_net_item_t *l_net_items_current = NULL, *l_net_items_tmp = NULL;
    HASH_ITER(hh, s_net_items, l_net_items_current, l_net_items_tmp) {
        if( (l_ret = s_net_load(l_net_items_current->chain_net)) ) {
            log_it(L_ERROR, "Loading chains of net %s finished with (%d) error code.", l_net_items_current->name, l_ret);
        }
    }
}

dap_string_t* dap_cli_list_net()
{
    dap_chain_net_item_t * l_net_item, *l_net_item_tmp;
    dap_string_t *l_string_ret = dap_string_new("");
    dap_chain_net_t * l_net = NULL;
    int l_net_i = 0;
    dap_string_append(l_string_ret,"Available networks and chains:\n");
    HASH_ITER(hh, s_net_items, l_net_item, l_net_item_tmp){
        l_net = l_net_item->chain_net;
        dap_string_append_printf(l_string_ret, "\t%s:\n", l_net_item->name);
        l_net_i++;

        dap_chain_t * l_chain = l_net->pub.chains;
        while (l_chain) {
            dap_string_append_printf(l_string_ret, "\t\t%s\n", l_chain->name );
            l_chain = l_chain->next;
        }
    }
    return l_string_ret;
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
        l_sync_current_link_text_block = dap_strdup_printf(", active links %zu from %u",
                                                           s_net_get_active_links_count(a_net),
                                                           HASH_COUNT(PVT(a_net)->net_links));
    dap_cli_server_cmd_set_reply_text(a_str_reply,
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
static void s_chain_net_ledger_cache_reload(dap_chain_net_t *l_net)
{
    dap_ledger_purge(l_net->pub.ledger, false);
    dap_chain_net_srv_stake_purge(l_net);
    dap_chain_net_decree_purge(l_net);
    dap_chain_t *l_chain = NULL;
    DL_FOREACH(l_net->pub.chains, l_chain) {
        if (l_chain->callback_purge)
            l_chain->callback_purge(l_chain);
        if (l_chain->callback_set_min_validators_count)
            l_chain->callback_set_min_validators_count(l_chain, 0);
        l_net->pub.fee_value = uint256_0;
        l_net->pub.fee_addr = c_dap_chain_addr_blank;
        dap_chain_load_all(l_chain);
    }
    DL_FOREACH(l_net->pub.chains, l_chain) {
        if (l_chain->callback_atom_add_from_treshold) {
            while (l_chain->callback_atom_add_from_treshold(l_chain, NULL))
                debug_if(s_debug_more, L_DEBUG, "Added atom from treshold");
        }
    }
}

/**
 * @brief update ledger cache at once
 * if you node build need ledger cache one time reload, uncomment this function
 * iat the end of s_net_init
 * @param l_net network object
 * @return true
 * @return false
 */
static bool s_chain_net_reload_ledger_cache_once(dap_chain_net_t *l_net)
{
    if (!l_net)
        return false;
    // create directory for cache checking file (cellframe-node/cache)
    char *l_cache_dir = dap_strdup_printf( "%s/%s", g_sys_dir_path, "cache");
    if (dap_mkdir_with_parents(l_cache_dir) != 0) {
        log_it(L_WARNING,"Error during disposable cache check file creation");
        DAP_DELETE(l_cache_dir);
        return false;
    }
    // Check the file with provided UUID. Change this UUID to automatically reload cache on next node startup
    char *l_cache_file = dap_strdup_printf( "%s/%s.cache", l_cache_dir, DAP_LEDGER_CACHE_RELOAD_ONCE_UUID);
    DAP_DELETE(l_cache_dir);
    // create file, if it not presented. If file exists, ledger cache operation is stopped
    if (dap_file_simple_test(l_cache_file)) {
        log_it(L_WARNING, "Cache file '%s' already exists", l_cache_file);
        DAP_DELETE(l_cache_file);
        return false;
    }

    static FILE *s_cache_file = NULL;
    s_cache_file = fopen(l_cache_file, "a");
    if(!s_cache_file) {
        s_cache_file = fopen(l_cache_file, "w");
        if (!s_cache_file) {
            log_it(L_ERROR, "Can't open cache file %s for one time ledger cache reloading."
                "Please, do it manually using command"
                "'cellframe-node-cli net -net <network_name>> ledger reload'", l_cache_file);
            return -1;
        }
    }
    fclose(s_cache_file);
    DAP_DELETE(l_cache_file);
    return true;
}

/**
 * @brief s_chain_type_convert
 * convert dap_chain_type_t to  DAP_CNAIN* constants
 * @param a_type - dap_chain_type_t a_type [CHAIN_TYPE_TOKEN, CHAIN_TYPE_EMISSION, CHAIN_TYPE_TX]
 * @return uint16_t
 */
static const char *s_chain_type_convert_to_string(dap_chain_type_t a_type)
{
    switch (a_type) {
        case CHAIN_TYPE_TOKEN:
            return ("token");
        case CHAIN_TYPE_EMISSION:
            return ("emission");
        case CHAIN_TYPE_TX:
            return ("transaction");
        case CHAIN_TYPE_CA:
            return ("ca");
        case CHAIN_TYPE_SIGNER:
            return ("signer");

        default:
            return ("custom");
    }
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
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    // command 'list'
    const char * l_list_cmd = NULL;

    if(dap_cli_server_cmd_find_option_val(argv, arg_index, dap_min(argc, arg_index + 1), "list", &l_list_cmd) != 0 ) {
        dap_string_t *l_string_ret = dap_string_new("");
        if (dap_strcmp(l_list_cmd,"chains")==0){
            const char * l_net_str = NULL;
            dap_chain_net_t* l_net = NULL;
            if (dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &l_net_str) && !l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Parameter '-net' require <net name>");
                return -1;
            }

            l_net = dap_chain_net_by_name(l_net_str);
            if (l_net_str && !l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Wrong <net name>, use 'net list' "
                                                            "command to display a list of available networks");
                return -1;
            }

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
                HASH_ITER(hh, s_net_items, l_net_item, l_net_item_tmp){
                    l_net = l_net_item->chain_net;
                    dap_string_append_printf(l_string_ret, "\t%s:\n", l_net_item->name);
                    l_net_i++;

                    dap_chain_t * l_chain = l_net->pub.chains;
                    while (l_chain) {
                        dap_string_append_printf(l_string_ret, "\t\t%s:\n", l_chain->name );
                        if (l_chain->default_datum_types_count)
                        {
                            dap_string_append_printf(l_string_ret, "\t\t");
                            for (uint16_t i = 0; i < l_chain->default_datum_types_count; i++)
                                dap_string_append_printf(l_string_ret, "| %s ", s_chain_type_convert_to_string(l_chain->default_datum_types[i]) );
                            dap_string_append_printf(l_string_ret, "|\n");
                        }
                        l_chain = l_chain->next;
                    }
                }
            }

        }else{
            // plug for wrong command arguments
            if (argc > 2) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "To many arguments for 'net list' command see help");
                return -1;
            }

            dap_string_append(l_string_ret,"Networks:\n");
            // show list of nets
            dap_chain_net_item_t * l_net_item, *l_net_item_tmp;
            int l_net_i = 0;
            HASH_ITER(hh, s_net_items, l_net_item, l_net_item_tmp){
                dap_string_append_printf(l_string_ret, "\t%s\n", l_net_item->name);
                l_net_i++;
            }
            dap_string_append(l_string_ret, "\n");
        }

        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_string_ret->str);
        dap_string_free(l_string_ret, true);
        return 0;
    }

    int l_ret = dap_chain_node_cli_cmd_values_parse_net_chain( &arg_index, argc, argv, a_str_reply, NULL, &l_net );

    if ( l_net ) {
        const char *l_sync_str = NULL;
        const char *l_links_str = NULL;
        const char *l_go_str = NULL;
        const char *l_get_str = NULL;
        const char *l_stats_str = NULL;
        const char *l_ca_str = NULL;
        const char *l_ledger_str = NULL;
        const char *l_list_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "sync", &l_sync_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "link", &l_links_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "go", &l_go_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "get", &l_get_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "stats", &l_stats_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "ca", &l_ca_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "ledger", &l_ledger_str);
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "poa_certs", &l_list_str);

        const char * l_sync_mode_str = "updates";
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-mode", &l_sync_mode_str);
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
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-from", &l_from_str);
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-to", &l_to_str);
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-prev_sec", &l_prev_sec_str);
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
                uint64_t l_tx_count = dap_ledger_count_from_to ( l_net->pub.ledger, l_from_ts, l_to_ts);
                long double l_tps = l_to_ts == l_from_ts ? 0 :
                                                     (long double) l_tx_count / (long double) ( l_to_ts - l_from_ts );
                dap_string_append_printf( l_ret_str, "\tSpeed:  %.3Lf TPS\n", l_tps );
                dap_string_append_printf( l_ret_str, "\tTotal:  %"DAP_UINT64_FORMAT_U"\n", l_tx_count );
                dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_ret_str->str);
                dap_string_free(l_ret_str, true);
            } else if (strcmp(l_stats_str, "tps") == 0) {
                struct timespec l_from_time_acc = {}, l_to_time_acc = {};
                dap_string_t * l_ret_str = dap_string_new("Transactions per second peak values:\n");
                size_t l_tx_num = dap_ledger_count_tps(l_net->pub.ledger, &l_from_time_acc, &l_to_time_acc);
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
                dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_ret_str->str);
                dap_string_free(l_ret_str, true);
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "Subcommand 'stats' requires one of parameter: tx, tps\n");
            }
        } else if ( l_go_str){
            if ( strcmp(l_go_str,"online") == 0 ) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network \"%s\" going from state %s to %s",
                                                  l_net->pub.name,c_net_states[PVT(l_net)->state],
                                                  c_net_states[NET_STATE_ONLINE]);

                dap_chain_net_balancer_prepare_list_links(l_net->pub.name);
                dap_chain_net_state_go_to(l_net, NET_STATE_ONLINE);
            } else if ( strcmp(l_go_str,"offline") == 0 ) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network \"%s\" going from state %s to %s",
                                                  l_net->pub.name,c_net_states[PVT(l_net)->state],
                                                  c_net_states[NET_STATE_OFFLINE]);
                dap_chain_net_state_go_to(l_net, NET_STATE_OFFLINE);

            } else if (strcmp(l_go_str, "sync") == 0) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network \"%s\" resynchronizing",
                                                  l_net->pub.name);
                if (PVT(l_net)->state_target == NET_STATE_ONLINE)
                    dap_chain_net_state_go_to(l_net, NET_STATE_ONLINE);
                else
                    dap_chain_net_state_go_to(l_net, NET_STATE_SYNC_CHAINS);
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "Subcommand 'go' requires one of parameters: online, offline, sync\n");
            }
        } else if ( l_get_str){
            if ( strcmp(l_get_str,"status") == 0 ) {
                s_set_reply_text_node_status(a_str_reply, l_net);
                l_ret = 0;
            } else if ( strcmp(l_get_str, "fee") == 0) {
                dap_string_t *l_str = dap_string_new("\0");
                // Network fee
                uint256_t l_network_fee = {};
                dap_chain_addr_t l_network_fee_addr = {};
                dap_chain_net_tx_get_fee(l_net->pub.id, &l_network_fee, &l_network_fee_addr);
                char *l_network_fee_balance_str = dap_chain_balance_print(l_network_fee);
                char *l_network_fee_coins_str = dap_chain_balance_to_coins(l_network_fee);
                char *l_network_fee_addr_str = dap_chain_addr_to_str(&l_network_fee_addr);
                dap_string_append_printf(l_str, "Fees on %s network:\n"
                                                "\t Network: %s (%s) %s Addr: %s\n",
                                                  l_net->pub.name, l_network_fee_coins_str, l_network_fee_balance_str,
                                                  l_net->pub.native_ticker, l_network_fee_addr_str);
                DAP_DELETE(l_network_fee_coins_str);
                DAP_DELETE(l_network_fee_balance_str);
                DAP_DELETE(l_network_fee_addr_str);

                //Get validators fee
                dap_chain_net_srv_stake_get_fee_validators_str(l_net, l_str);
                //Get services fee
                dap_string_append_printf(l_str, "Services fee: \n");
                dap_chain_net_srv_xchange_print_fee(l_net, l_str); //Xchaneg fee

                *a_str_reply = dap_string_free(l_str, false);
                l_ret = 0;
            } else if (strcmp(l_get_str,"id") == 0 ){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Net %s has id 0x%016"DAP_UINT64_FORMAT_X,
                                                                l_net->pub.name, l_net->pub.id.uint64);
                l_ret = 0;
            }
        } else if ( l_links_str ){
            if ( strcmp(l_links_str,"list") == 0 ) {
                size_t i =0;
                dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);
                pthread_mutex_lock(&l_net_pvt->uplinks_mutex);
                size_t l_links_count = HASH_COUNT(l_net_pvt->net_links);
                dap_string_t *l_reply = dap_string_new("");
                dap_string_append_printf(l_reply,"Links %zu:\n", l_links_count);
                struct net_link *l_link, *l_link_tmp;
                HASH_ITER(hh, l_net_pvt->net_links, l_link, l_link_tmp) {
                    dap_chain_node_client_t *l_node_client = l_link->link;
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
                                                 inet_ntoa(l_link->link_info->hdr.ext_addr_v4), l_ext_addr_v6, l_info->hdr.ext_port,
                                                 dap_chain_node_client_state_to_str(l_node_client->state) );
                    }
                    i++;
                }
                pthread_mutex_unlock(&l_net_pvt->uplinks_mutex);
                dap_cli_server_cmd_set_reply_text(a_str_reply,"%s",l_reply->str);
                dap_string_free(l_reply,true);

            } else if ( strcmp(l_links_str,"add") == 0 ) {
                dap_cli_server_cmd_set_reply_text(a_str_reply,"Not implemented\n");
            } else if ( strcmp(l_links_str,"del") == 0 ) {
                dap_cli_server_cmd_set_reply_text(a_str_reply,"Not implemented\n");

            }  else if ( strcmp(l_links_str,"info") == 0 ) {
                const char *l_addr_str = NULL;
                dap_chain_node_addr_t l_node_addr = { 0 };
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-addr", &l_addr_str);
                if(l_addr_str) {
                    if(dap_chain_node_addr_from_str(&l_node_addr, l_addr_str) != 0) {
                        dap_digit_from_string(l_addr_str, l_node_addr.raw, sizeof(l_node_addr.raw));
                    }
                }else
                {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                      "Subcommand 'info' requires parameter: addr\n");
                    return -12;
                }

                char *l_key = dap_chain_node_addr_to_hash_str(&l_node_addr);
                if(!l_key)
                {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,"Can't calculate hash for addr\n");
                    return -12;
                } else{
                    size_t node_info_size = 0;
                    dap_chain_node_info_t *l_node_inf_check;
                    l_node_inf_check = (dap_chain_node_info_t *) dap_global_db_get_sync(l_net->pub.gdb_nodes, l_key, &node_info_size, NULL, NULL);
                    if(!l_node_inf_check){
                        for(int i=0;i<PVT(l_net)->seed_aliases_count;i++)
                        {
                            if(PVT(l_net)->seed_nodes_addrs[i] == l_node_addr.uint64){
                                l_node_inf_check = DAP_NEW_Z(dap_chain_node_info_t);
                                l_node_inf_check->hdr.ext_addr_v4.s_addr = PVT(l_net)->seed_nodes_addrs_v4[i].s_addr;
                                break;
                            }
                        }
                    }
                    if(l_node_inf_check){

                        uint64_t l_addr = l_node_inf_check->hdr.ext_addr_v4.s_addr;
                        struct net_link *l_new_link;
                        HASH_FIND(hh,  PVT(l_net)->net_links, &l_addr, sizeof(l_addr), l_new_link);
                        if(l_new_link)
                        {
                            dap_string_t *l_reply = dap_string_new("");
                            dap_chain_node_client_t *l_node_client = l_new_link->link;
                            if(l_node_client){
                                dap_chain_node_info_t * l_info = l_node_client->info;
                                char l_ext_addr_v6[INET6_ADDRSTRLEN]={};
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
                                                         inet_ntoa(l_new_link->link_info->hdr.ext_addr_v4), l_ext_addr_v6, l_info->hdr.ext_port,
                                                         dap_chain_node_client_state_to_str(l_node_client->state) );
                            }
                            dap_cli_server_cmd_set_reply_text(a_str_reply,"%s",l_reply->str);
                            dap_string_free(l_reply,true);
                        }
                        DAP_DELETE(l_node_inf_check);
                    }else{
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                          "Can't find this address in global db");
                        l_ret = -12;
                    }
                }
                DAP_DELETE(l_key);

            } else if ( strcmp (l_links_str,"disconnect_all") == 0 ){
                l_ret = 0;
                dap_chain_net_stop(l_net);
                dap_cli_server_cmd_set_reply_text(a_str_reply,"Stopped network\n");
            }else {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "Subcommand 'link' requires one of parameters: list, add, del, info, disconnect_all\n");
                l_ret = -3;
            }

        } else if( l_sync_str) {

            if ( strcmp(l_sync_str,"all") == 0 ) {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "SYNC_ALL state requested to state machine. Current state: %s\n",
                                                  c_net_states[ PVT(l_net)->state] );
                dap_chain_net_sync_all(l_net);
            } else if ( strcmp(l_sync_str,"gdb") == 0) {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "SYNC_GDB state requested to state machine. Current state: %s\n",
                                                  c_net_states[ PVT(l_net)->state] );
                dap_chain_net_sync_gdb(l_net);

            }  else if ( strcmp(l_sync_str,"chains") == 0) {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "SYNC_CHAINS state requested to state machine. Current state: %s\n",
                                                  c_net_states[ PVT(l_net)->state] );
                // TODO set PVT flag to exclude GDB sync
                dap_chain_net_sync_chains(l_net);

            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "Subcommand 'sync' requires one of parameters: all, gdb, chains\n");
                l_ret = -2;
            }
        } else if (l_ca_str) {
            if (strcmp(l_ca_str, "add") == 0 ) {
                const char *l_cert_string = NULL, *l_hash_string = NULL;



                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cert", &l_cert_string);
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-hash", &l_hash_string);

                if (!l_cert_string && !l_hash_string) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "One of -cert or -hash parameters is mandatory");
                    return -6;
                }
                char *l_hash_hex_str = NULL;
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
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find \"%s\" certificate", l_cert_string);
                        DAP_DEL_Z(l_hash_hex_str);
                        return -7;
                    }
                    if (l_cert->enc_key == NULL) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "No key found in \"%s\" certificate", l_cert_string );
                        DAP_DEL_Z(l_hash_hex_str);
                        return -8;
                    }
                    // Get publivc key hash
                    size_t l_pub_key_size = 0;
                    uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(l_cert->enc_key, &l_pub_key_size);;
                    if (l_pub_key == NULL) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't serialize public key of certificate \"%s\"", l_cert_string);
                        DAP_DEL_Z(l_hash_hex_str);
                        return -9;
                    }
                    dap_chain_hash_fast_t l_pkey_hash;
                    dap_hash_fast(l_pub_key, l_pub_key_size, &l_pkey_hash);
                    DAP_DEL_Z(l_hash_hex_str);
                    l_hash_hex_str = dap_chain_hash_fast_to_str_new(&l_pkey_hash);
                    //l_hash_base58_str = dap_enc_base58_encode_hash_to_str(&l_pkey_hash);
                }
                const char c = '1';
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Database ACL group not defined for this network");
                    return -11;
                }
                if( l_hash_hex_str ){
                    l_ret = dap_global_db_set_sync(l_gdb_group_str, l_hash_hex_str, &c, sizeof(c), false );
                    DAP_DELETE(l_gdb_group_str);
                    if (l_ret) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                          "Can't save public key hash %s in database", l_hash_hex_str);
                        DAP_DELETE(l_hash_hex_str);
                        return -10;
                    }
                    DAP_DELETE(l_hash_hex_str);
                } else{
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't save NULL public key hash in database");
                    return -10;
                }
                return 0;
            } else if (strcmp(l_ca_str, "list") == 0 ) {
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Database ACL group not defined for this network");
                    return -11;
                }
                size_t l_objs_count;
                dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group_str, &l_objs_count);
                DAP_DELETE(l_gdb_group_str);
                dap_string_t *l_reply = dap_string_new("");
                for (size_t i = 0; i < l_objs_count; i++) {
                    dap_string_append(l_reply, l_objs[i].key);
                    dap_string_append(l_reply, "\n");
                }
                dap_global_db_objs_delete(l_objs, l_objs_count);
                *a_str_reply = l_reply->len ? l_reply->str : dap_strdup("No entries found");
                dap_string_free(l_reply, false);
                return 0;
            } else if (strcmp(l_ca_str, "del") == 0 ) {
                const char *l_hash_string = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-hash", &l_hash_string);
                if (!l_hash_string) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Format should be 'net ca del -hash <hash string>");
                    return -6;
                }
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Database ACL group not defined for this network");
                    return -11;
                }
                l_ret = dap_global_db_del_sync(l_gdb_group_str, l_hash_string);
                DAP_DELETE(l_gdb_group_str);
                if (l_ret) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Cant't find certificate public key hash in database");
                    return -10;
                }
                return 0;
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "Subcommand 'ca' requires one of parameter: add, list, del\n");
                l_ret = -5;
            }
        } else if (l_ledger_str && !strcmp(l_ledger_str, "reload")) {
            int l_return_state = dap_chain_net_stop(l_net);
            sleep(1);   // wait to net going offline
            s_chain_net_ledger_cache_reload(l_net);
            if (l_return_state)
                dap_chain_net_start(l_net);
        } else if (l_list_str && !strcmp(l_list_str, "list")) {
            dap_list_t *l_net_keys = NULL;
            for (dap_chain_t *l_chain = l_net->pub.chains; l_chain; l_chain = l_chain->next) {
                if (!l_chain->callback_get_poa_certs)
                    continue;
                l_net_keys = l_chain->callback_get_poa_certs(l_chain, NULL, NULL);
                if (l_net_keys)
                    break;
            }
            if (!l_net_keys) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "No PoA certs found for this network");
                return -11;
            }
            dap_string_t *l_str_out = dap_string_new("List of network PoA certificates:\n");
            int i = 0;
            for (dap_list_t *it = l_net_keys; it; it = it->next) {
                dap_hash_fast_t l_pkey_hash;
                char l_pkey_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_pkey_get_hash(it->data, &l_pkey_hash);
                dap_chain_hash_fast_to_str(&l_pkey_hash, l_pkey_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                dap_string_append_printf(l_str_out, "%d) %s\n", i++, l_pkey_hash_str);
            }
            *a_str_reply = l_str_out->str;
            dap_string_free(l_str_out, false);

        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                              "Command 'net' requires one of subcomands: sync, link, go, get, stats, ca, ledger");
            l_ret = -1;
        }

    }
    return  l_ret;
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
} list_priority;

static int callback_compare_prioritity_list(const void *a_item1, const void *a_item2)
{
    list_priority   *l_item1 = (list_priority*)((dap_list_t*)a_item1)->data,
                    *l_item2 = (list_priority*)((dap_list_t*)a_item2)->data;
    if (!l_item1 || !l_item2) {
        log_it(L_CRITICAL, "Invalid arg");
        return 0;
    }
    return l_item1->prior == l_item2->prior ? 0 : l_item1->prior > l_item2->prior ? 1 : -1;
}

void s_main_timer_callback(void *a_arg)
{
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    if (l_net_pvt->state_target == NET_STATE_ONLINE &&
            l_net_pvt->state >= NET_STATE_LINKS_ESTABLISHED &&
            !s_net_get_active_links_count(l_net)) // restart network
        dap_chain_net_start(l_net);
    dap_chain_net_balancer_prepare_list_links(l_net->pub.name);
}

/**
 * @brief dap_chain_net_deinit
 */
void dap_chain_net_deinit()
{
    dap_chain_net_item_t *l_current_item, *l_tmp;
    HASH_ITER(hh, s_net_ids, l_current_item, l_tmp)
        HASH_DELETE(hh2, s_net_ids, l_current_item);
    HASH_ITER(hh, s_net_items, l_current_item, l_tmp) {
        HASH_DEL(s_net_items, l_current_item);
        dap_chain_net_delete(l_current_item->chain_net);
        DAP_DELETE(l_current_item);
    }
}

/**
 * @brief dap_chain_net_delete
 * free dap_chain_net_t * a_net object
 * @param a_net
 */
void dap_chain_net_delete(dap_chain_net_t *a_net)
{
    // Synchronously going to offline state
    PVT(a_net)->state = PVT(a_net)->state_target = NET_STATE_OFFLINE;
    s_net_states_proc(NULL, a_net);
    dap_chain_net_item_t *l_net_item;
    HASH_FIND(hh, s_net_items, a_net->pub.name, strlen(a_net->pub.name), l_net_item);
    if (l_net_item) {
        HASH_DEL(s_net_items, l_net_item);
        HASH_DELETE(hh2, s_net_ids, l_net_item);
        DAP_DELETE(l_net_item);
    }
    if (PVT(a_net)->main_timer)
        dap_interval_timer_delete(PVT(a_net)->main_timer);
    DAP_DEL_Z(PVT(a_net)->node_info);
    dap_ledger_purge(a_net->pub.ledger, true);
    dap_ledger_handle_free(a_net->pub.ledger);
    DAP_DELETE(a_net);
}

/**
 * @brief load network config settings from cellframe-node.cfg file
 *
 * @param a_net_name const char *: network name, for example "home21-network"
 * @param a_acl_idx currently 0
 * @return int
 */
int s_net_init(const char * a_net_name, uint16_t a_acl_idx)
{
    dap_config_t *l_cfg = NULL;
    dap_string_t *l_cfg_path = dap_string_new("network/");
    dap_string_append(l_cfg_path,a_net_name);

    if( !(l_cfg = dap_config_open(l_cfg_path->str)) ) {
        log_it(L_ERROR,"Can't open default network config");
        dap_string_free(l_cfg_path,true);
        return -1;
    }
    dap_string_free(l_cfg_path,true);
    dap_chain_net_t * l_net = s_net_new(
                                        dap_config_get_item_str(l_cfg , "general" , "id" ),
                                        dap_config_get_item_str(l_cfg , "general" , "name" ),
                                        dap_config_get_item_str(l_cfg , "general" , "native_ticker"),
                                        dap_config_get_item_str(l_cfg , "general" , "node-role" )
                                       );
    if(!l_net) {
        log_it(L_ERROR,"Can't create l_net");
        return -1;
    }
    // check nets with same IDs and names
    dap_chain_net_item_t *l_net_items_current = NULL, *l_net_items_tmp = NULL;
    HASH_ITER(hh, s_net_items, l_net_items_current, l_net_items_tmp) {
        if (l_net_items_current->net_id.uint64 == l_net->pub.id.uint64) {
            log_it(L_ERROR,"Can't create net %s, net %s has the same ID %"DAP_UINT64_FORMAT_U"", l_net->pub.name, l_net_items_current->name, l_net->pub.id.uint64);
            log_it(L_ERROR, "Please, fix your configs and restart node");
            dap_chain_net_delete(l_net);
            return -1;
        }
        if (!strcmp(l_net_items_current->name, l_net->pub.name)) {
            log_it(L_ERROR,"Can't create l_net ID %"DAP_UINT64_FORMAT_U", net ID %"DAP_UINT64_FORMAT_U" has the same name %s", l_net->pub.id.uint64, l_net_items_current->net_id.uint64, l_net->pub.name);
            log_it(L_ERROR, "Please, fix your configs and restart node");
            dap_chain_net_delete(l_net);
            return -1;
        }
    }
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    l_net_pvt->load_mode = true;
    l_net_pvt->acl_idx = a_acl_idx;
    l_net->pub.gdb_groups_prefix = dap_strdup (
                dap_config_get_item_str_default(l_cfg , "general" , "gdb_groups_prefix",
                                                dap_config_get_item_str(l_cfg , "general" , "name" ) ) );
    dap_global_db_add_sync_group(l_net->pub.name, "global", s_gbd_history_callback_notify, l_net);
    dap_global_db_add_sync_group(l_net->pub.name, l_net->pub.gdb_groups_prefix, s_gbd_history_callback_notify, l_net);

    l_net->pub.gdb_nodes = dap_strdup_printf("%s."NODELIST_GROUP_NAME, l_net->pub.gdb_groups_prefix);
    l_net->pub.gdb_nodes_aliases = dap_strdup_printf("%s.nodes.aliases",l_net->pub.gdb_groups_prefix);

    // Bridged netwoks allowed to send transactions to
    uint16_t l_net_ids_count = 0;
    char **l_bridged_net_ids = dap_config_get_array_str(l_cfg, "general", "bridged_network_ids", &l_net_ids_count);
    for (uint16_t i = 0; i< l_net_ids_count; i++) {
        dap_chain_net_id_t l_id;
        if (dap_chain_net_id_parse(l_bridged_net_ids[i], &l_id) != 0)
            continue;
        l_net->pub.bridged_networks = dap_list_append(l_net->pub.bridged_networks, DAP_DUP(&l_id));
    }

    // nodes for special sync
    char **l_gdb_sync_nodes_addrs = dap_config_get_array_str(l_cfg, "general", "gdb_sync_nodes_addrs",
            &l_net_pvt->gdb_sync_nodes_addrs_count);
    if(l_gdb_sync_nodes_addrs && l_net_pvt->gdb_sync_nodes_addrs_count > 0) {
        l_net_pvt->gdb_sync_nodes_addrs = DAP_NEW_Z_SIZE(dap_chain_node_addr_t,
                sizeof(dap_chain_node_addr_t)*l_net_pvt->gdb_sync_nodes_addrs_count);
        if (!l_net_pvt->gdb_sync_nodes_addrs) {
            log_it(L_CRITICAL, "Memory allocation error");
            dap_config_close(l_cfg);
            return -1;
        }
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
        if (!l_net_pvt->gdb_sync_nodes_links_ips) {
            log_it(L_CRITICAL, "Memory allocation error");
            dap_config_close(l_cfg);
            return -1;
        }
        l_net_pvt->gdb_sync_nodes_links_ports = DAP_NEW_SIZE(uint16_t, l_gdb_links_count * sizeof(uint16_t));
        if (!l_net_pvt->gdb_sync_nodes_links_ports) {
            log_it(L_CRITICAL, "Memory allocation error");
            DAP_DEL_Z(l_net_pvt->gdb_sync_nodes_links_ips);
            dap_config_close(l_cfg);
            return -1;
        }
        for(uint16_t i = 0; i < l_gdb_links_count; i++) {
            char *l_gdb_link_port_str = strchr(l_gdb_sync_nodes_links[i], ':');
            if (!l_gdb_link_port_str) {
                continue;
            }
            uint16_t l_gdb_link_port = atoi(l_gdb_link_port_str + 1);
            if (!l_gdb_link_port)
                continue;
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
            dap_global_db_add_sync_extra_group(l_net->pub.name, l_gdb_sync_groups[i], s_gbd_history_callback_notify, l_net);
        }
    }

    // Add network to the list
    dap_chain_net_item_t * l_net_item = DAP_NEW_Z( dap_chain_net_item_t);
    if (!l_net_item) {
        log_it(L_CRITICAL, "Memory allocation error");
        dap_config_close(l_cfg);
        return -1;
    }
    snprintf(l_net_item->name,sizeof (l_net_item->name),"%s"
                 ,dap_config_get_item_str(l_cfg , "general" , "name" ));
    l_net_item->chain_net = l_net;
    l_net_item->net_id.uint64 = l_net->pub.id.uint64;
    HASH_ADD_STR(s_net_items,name,l_net_item);
    HASH_ADD(hh2, s_net_ids, net_id, sizeof(l_net_item->net_id), l_net_item);

    // Check if seed nodes are present in local db alias
    char **l_seed_aliases = dap_config_get_array_str(l_cfg, "general", "seed_nodes_aliases",
                                                     &l_net_pvt->seed_aliases_count);
    if (l_net_pvt->seed_aliases_count)
        l_net_pvt->seed_aliases = DAP_NEW_Z_SIZE(char*, sizeof(char*) * l_net_pvt->seed_aliases_count);
    for(size_t i = 0; i < l_net_pvt->seed_aliases_count; i++)
        l_net_pvt->seed_aliases[i] = dap_strdup(l_seed_aliases[i]);
    // randomize seed nodes list
    for (int j = l_net_pvt->seed_aliases_count - 1; j > 0; j--) {
        short n = dap_random_uint16() % j;
        char *tmp = l_net_pvt->seed_aliases[n];
        l_net_pvt->seed_aliases[n] = l_net_pvt->seed_aliases[j];
        l_net_pvt->seed_aliases[j] = tmp;
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

    // maximum number of prepared connections to other nodes
    l_net_pvt->max_links_count = dap_config_get_item_int16_default(l_cfg, "general", "max_links", 5);
    // required number of active connections to other nodes
    l_net_pvt->required_links_count = dap_config_get_item_int16_default(l_cfg, "general", "require_links", 3);
    // wait time before reconnect attempt with same link
    l_net_pvt->reconnect_delay = dap_config_get_item_int16_default(l_cfg, "general", "reconnect_delay", 10);

    const char * l_node_addr_type = dap_config_get_item_str_default(l_cfg , "general" ,"node_addr_type","auto");

    const char * l_node_addr_str = NULL;
    const char * l_node_alias_str = NULL;

    // use unique addr from pub key
    if(!dap_strcmp(l_node_addr_type, "auto")) {
        size_t l_pub_key_data_size = 0;
        uint8_t *l_pub_key_data = NULL;

        // read pub key
        char *l_addr_key = dap_strdup_printf("node-addr-%s", l_net->pub.name);
        l_pub_key_data = dap_global_db_get_sync(GROUP_LOCAL_NODE_ADDR, l_addr_key, &l_pub_key_data_size, NULL, NULL);
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
                l_pub_key_data = dap_enc_key_serialize_pub_key(l_cert->enc_key, &l_pub_key_data_size);
                // save pub key
                if(l_pub_key_data && l_pub_key_data_size > 0)
                    dap_global_db_set(GROUP_LOCAL_NODE_ADDR, l_addr_key, l_pub_key_data, l_pub_key_data_size, false,
                                        NULL, NULL);
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
    PVT(l_net)->seed_nodes_addrs_v4 = DAP_NEW_SIZE(struct in_addr, l_net_pvt->seed_aliases_count * sizeof(struct in_addr));
    PVT(l_net)->seed_nodes_addrs = DAP_NEW_SIZE(uint64_t, l_net_pvt->seed_aliases_count * sizeof(uint64_t));
    PVT(l_net)->seed_nodes_ports = DAP_NEW_SIZE(uint16_t, l_net_pvt->seed_aliases_count * sizeof(uint16_t));
    // save new nodes from cfg file to db
    for ( size_t i = 0; i < PVT(l_net)->seed_aliases_count &&
                        i < l_seed_nodes_addrs_len &&
                        (
                            ( l_seed_nodes_ipv4_len  && i < l_seed_nodes_ipv4_len  ) ||
                            ( l_seed_nodes_ipv6_len  && i < l_seed_nodes_ipv6_len  ) ||
                            ( l_seed_nodes_hostnames_len  && i < l_seed_nodes_hostnames_len  )
                        ); i++) {
        dap_chain_node_addr_t l_seed_node_addr  = { 0 }, *l_seed_node_addr_gdb  = NULL;
        dap_chain_node_info_t l_node_info       = { 0 }, *l_node_info_gdb       = NULL;

        log_it(L_NOTICE, "Check alias %s in db", l_net_pvt->seed_aliases[i]);
        snprintf(l_node_info.hdr.alias,sizeof (l_node_info.hdr.alias),"%s", PVT(l_net)->seed_aliases[i]);
        if (dap_chain_node_addr_from_str(&l_seed_node_addr, l_seed_nodes_addrs[i])) {
            log_it(L_ERROR,"Wrong address format, must be 0123::4567::89AB::CDEF");
            continue;
        }
        if (l_seed_nodes_ipv4_len)
            inet_pton(AF_INET, l_seed_nodes_ipv4[i], &l_node_info.hdr.ext_addr_v4);
        if (l_seed_nodes_ipv6_len)
            inet_pton(AF_INET6, l_seed_nodes_ipv6[i], &l_node_info.hdr.ext_addr_v6);
        l_node_info.hdr.ext_port = l_seed_nodes_port_len && l_seed_nodes_port_len >= i ?
            strtoul(l_seed_nodes_port[i], NULL, 10) : 8079;
        l_net_pvt->seed_nodes_ports[i] = l_node_info.hdr.ext_port;
        l_net_pvt->seed_nodes_addrs[i] = l_seed_node_addr.uint64;

        if (l_seed_nodes_hostnames_len) {
            struct sockaddr l_sa = {};
            log_it(L_DEBUG, "Resolve %s addr", l_seed_nodes_hostnames[i]);
            int l_ret_code = dap_net_resolve_host(l_seed_nodes_hostnames[i], AF_INET, &l_sa);
            if (l_ret_code == 0) {
                struct in_addr *l_res = (struct in_addr *)&l_sa;
                log_it(L_NOTICE, "Resolved %s to %s (ipv4)", l_seed_nodes_hostnames[i], inet_ntoa(*l_res));
                l_node_info.hdr.ext_addr_v4.s_addr = l_res->s_addr;
                l_net_pvt->seed_nodes_addrs_v4[i].s_addr = l_res->s_addr;
            } else {
                log_it(L_ERROR, "%s", gai_strerror(l_ret_code));
            }
        }
/*
        l_seed_node_addr_gdb    = dap_chain_node_alias_find(l_net, l_net_pvt->seed_aliases[i]);
        l_node_info_gdb         = l_seed_node_addr_gdb ? dap_chain_node_info_read(l_net, l_seed_node_addr_gdb) : NULL;

        l_node_info.hdr.address = l_seed_node_addr;
        if (l_node_info.hdr.ext_addr_v4.s_addr ||
#ifdef DAP_OS_BSD
            l_node_info.hdr.ext_addr_v6.__u6_addr.__u6_addr32[0]
#else
            l_node_info.hdr.ext_addr_v6.s6_addr32[0]
#endif
        ) {
             //Let's check if config was altered
            int l_ret = l_node_info_gdb ? memcmp(&l_node_info, l_node_info_gdb, sizeof(dap_chain_node_info_t)) : 1;
            if (!l_ret) {
                log_it(L_NOTICE,"Seed node "NODE_ADDR_FP_STR" already in list", NODE_ADDR_FP_ARGS_S(l_seed_node_addr));
            } else {
                // Either not yet added or must be altered
                l_ret = dap_chain_node_info_save(l_net, &l_node_info);
                if (!l_ret) {
                    if (dap_chain_node_alias_register(l_net,l_net_pvt->seed_aliases[i], &l_seed_node_addr))
                        log_it(L_NOTICE,"Seed node "NODE_ADDR_FP_STR" added to the curent list", NODE_ADDR_FP_ARGS_S(l_seed_node_addr));
                    else
                        log_it(L_WARNING,"Cant register alias %s for address "NODE_ADDR_FP_STR, l_net_pvt->seed_aliases[i], NODE_ADDR_FP_ARGS_S(l_seed_node_addr));
                } else {
                    log_it(L_WARNING,"Cant save node info for address "NODE_ADDR_FP_STR" return code %d", NODE_ADDR_FP_ARGS_S(l_seed_node_addr), l_ret);
                }
            }
        } else
            log_it(L_WARNING,"No address for seed node, can't populate global_db with it");
        DAP_DEL_Z(l_seed_node_addr_gdb);
        DAP_DEL_Z(l_node_info_gdb);*/
    }

    dap_chain_net_node_list_init();

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
        else {
            l_node_addr = DAP_NEW_Z(dap_chain_node_addr_t);
            if (!l_node_addr) {
                log_it(L_CRITICAL, "Memory allocation error");
                dap_config_close(l_cfg);
                return -1;
            }
            if (dap_chain_node_addr_from_str(l_node_addr, l_node_addr_str) == 0)
                log_it(L_NOTICE, "Parse node addr "NODE_ADDR_FP_STR" successfully", NODE_ADDR_FP_ARGS(l_node_addr));
            else
                DAP_DEL_Z(l_node_addr);
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
                    if (!l_net_pvt->node_info) {
                        log_it(L_CRITICAL, "Memory allocation error");
                        DAP_DEL_Z(l_node_addr);
                        dap_config_close(l_cfg);
                        return -1;
                    }
                    l_net_pvt->node_info->hdr.address = *l_node_addr;
                    if (dap_config_get_item_bool_default(g_config,"server","enabled",false) ){
                        const char * l_ext_addr_v4 = dap_config_get_item_str_default(g_config,"server","ext_address",NULL);
                        const char * l_ext_addr_v6 = dap_config_get_item_str_default(g_config,"server","ext_address6",NULL);
                        uint16_t l_ext_port = dap_config_get_item_uint16_default(g_config,"server","ext_port_tcp", 8079);
                        uint16_t l_node_info_port = l_ext_port ? l_ext_port :
                                                dap_config_get_item_uint16_default(g_config,"server","listen_port_tcp",8079);
                        if (l_ext_addr_v4)
                            inet_pton(AF_INET,l_ext_addr_v4,&l_net_pvt->node_info->hdr.ext_addr_v4 );
                        if (l_ext_addr_v6)
                            inet_pton(AF_INET6,l_ext_addr_v6,&l_net_pvt->node_info->hdr.ext_addr_v6 );
                        l_net_pvt->node_info->hdr.ext_port =l_node_info_port;
                    } else
                        log_it(L_INFO,"Server is disabled, add only node address in nodelist");
                }
                log_it(L_NOTICE,"GDB Info: node_addr: " NODE_ADDR_FP_STR"  links: %u cell_id: 0x%016"DAP_UINT64_FORMAT_X,
                       NODE_ADDR_FP_ARGS(l_node_addr),
                       l_net_pvt->node_info->hdr.links_number,
                       l_net_pvt->node_info->hdr.cell_id.uint64);
            }
            DAP_DELETE(l_addr_hash_str);
        }
        else{
            log_it(L_WARNING, "Not present our own address %s in database", (l_node_alias_str) ? l_node_alias_str: "");
        }
    } else {
        log_it(L_ERROR, "The string representation of the node address could not be determined for '%s' net.", l_net->pub.name);
        HASH_DEL(s_net_items, l_net_item);
        HASH_DEL(s_net_ids, l_net_item);
        dap_chain_net_delete(l_net);
        DAP_DELETE(l_net_item);
        return -5;
    }
    DAP_DELETE(l_node_addr_str);

    /* *** Chaiins init by configs *** */
    char * l_chains_path = dap_strdup_printf("%s/network/%s", dap_config_path(), l_net->pub.name);
    DIR * l_chains_dir = opendir(l_chains_path);
    DAP_DEL_Z(l_chains_path);
    if (!l_chains_dir) {
        log_it(L_ERROR, "Can't find any chains for network %s", l_net->pub.name);
        l_net_pvt->load_mode = false;
        dap_config_close(l_cfg);
        return -2;
    }
    // for sequential loading chains
    dap_list_t *l_prior_list = NULL;

    struct dirent * l_dir_entry;
    while ( (l_dir_entry = readdir(l_chains_dir) )!= NULL ){
        if (l_dir_entry->d_name[0]=='\0')
            continue;
        char * l_entry_name = strdup(l_dir_entry->d_name);
        if (!l_entry_name) {
        log_it(L_CRITICAL, "Memory allocation error");
            dap_config_close(l_cfg);
            closedir(l_chains_dir);
            return -1;
        }
        if (strlen (l_entry_name) > 4 ){ // It has non zero name excluding file extension
            if ( strncmp (l_entry_name+ strlen(l_entry_name)-4,".cfg",4) == 0 ) { // its .cfg file
                l_entry_name [strlen(l_entry_name)-4] = 0;
                log_it(L_DEBUG,"Open chain config \"%s\"...",l_entry_name);
                l_chains_path = dap_strdup_printf("network/%s/%s",l_net->pub.name,l_entry_name);
                dap_config_t * l_cfg_new = dap_config_open(l_chains_path);
                if(l_cfg_new) {
                    list_priority *l_chain_prior = DAP_NEW_Z(list_priority);
                    if (!l_chain_prior) {
                        log_it(L_CRITICAL, "Memory allocation error");
                        DAP_DELETE(l_entry_name);
                        closedir(l_chains_dir);
                        dap_config_close(l_cfg_new);
                        dap_config_close(l_cfg);
                        return -1;
                    }
                    l_chain_prior->prior = dap_config_get_item_uint16_default(l_cfg_new, "chain", "load_priority", 100);
                    log_it(L_DEBUG, "Chain priority: %u", l_chain_prior->prior);
                    l_chain_prior->chains_path = l_chains_path;
                    // add chain to load list;
                    l_prior_list = dap_list_append(l_prior_list, l_chain_prior);
                    dap_config_close(l_cfg_new);
                }
            }
        }
        DAP_DEL_Z (l_entry_name);
    }
    closedir(l_chains_dir);

    // sort list with chains names by priority
    l_prior_list = dap_list_sort(l_prior_list, callback_compare_prioritity_list);

    // create and load chains params by priority
    dap_chain_t *l_chain;
    dap_list_t *l_list = l_prior_list;
    while(l_list){
        list_priority *l_chain_prior = l_list->data;
        // Create chain object
        l_chain = dap_chain_load_from_cfg(l_net->pub.name, l_net->pub.id, l_chain_prior->chains_path);
        if(l_chain)
            DL_APPEND(l_net->pub.chains, l_chain);
        else
            log_it(L_WARNING, "Can't process chain from config %s", l_chain_prior->chains_path);
        DAP_DELETE (l_chain_prior->chains_path);
        l_list = dap_list_next(l_list);
    }
    dap_list_free_full(l_prior_list, NULL);
    dap_chain_t *l_chain02;
    DL_FOREACH(l_net->pub.chains, l_chain){
        DL_FOREACH(l_net->pub.chains, l_chain02){
            if (l_chain != l_chain02){
                if (l_chain->id.uint64 == l_chain02->id.uint64) {
                    log_it(L_ERROR, "Your network %s has chains with duplicate ids: 0x%"DAP_UINT64_FORMAT_U", chain01: %s, chain02: %s", l_chain->net_name,
                                    l_chain->id.uint64, l_chain->name,l_chain02->name);
                    log_it(L_ERROR, "Please, fix your configs and restart node");
                    return -2;
                }
                if (!dap_strcmp(l_chain->name, l_chain02->name)) {
                    log_it(L_ERROR, "Your network %s has chains with duplicate names %s: chain01 id = 0x%"DAP_UINT64_FORMAT_U", chain02 id = 0x%"DAP_UINT64_FORMAT_U"",l_chain->net_name,
                           l_chain->name, l_chain->id.uint64, l_chain02->id.uint64);
                    log_it(L_ERROR, "Please, fix your configs and restart node");
                    return -2;
                }
                remove_duplicates_in_chain_by_priority(l_chain, l_chain02);
            }
        }
    }
    // LEDGER model
    uint16_t l_ledger_flags = 0;
    switch ( PVT( l_net )->node_role.enums ) {
    case NODE_ROLE_LIGHT:
        break;
    case NODE_ROLE_FULL:
        l_ledger_flags |= DAP_LEDGER_CHECK_LOCAL_DS;
        if (dap_config_get_item_bool_default(g_config, "ledger", "cache_enabled", false))
            l_ledger_flags |= DAP_LEDGER_CACHE_ENABLED;
    default:
        l_ledger_flags |= DAP_LEDGER_CHECK_CELLS_DS | DAP_LEDGER_CHECK_TOKEN_EMISSION;
    }

    for (dap_chain_t *l_chain = l_net->pub.chains; l_chain; l_chain = l_chain->next) {
        if (!l_chain->callback_get_poa_certs)
            continue;
        l_net->pub.keys = l_chain->callback_get_poa_certs(l_chain, NULL, NULL);
        break;
    }
    if (!l_net->pub.keys)
        log_it(L_WARNING,"PoA certificates for net %s not found.", l_net->pub.name);
    // init LEDGER model
    l_net->pub.ledger = dap_ledger_create(l_net, l_ledger_flags);

    // Decrees initializing
    dap_chain_net_decree_init(l_net);

    dap_config_close(l_cfg);
    return 0;
}

int s_net_load(dap_chain_net_t *a_net)
{
    dap_chain_net_t *l_net = a_net;

    dap_config_t *l_cfg = NULL;
    dap_string_t *l_cfg_path = dap_string_new("network/");
    dap_string_append(l_cfg_path,a_net->pub.name);

    if( !( l_cfg = dap_config_open ( l_cfg_path->str ) ) ) {
        log_it(L_ERROR,"Can't open default network config");
        dap_string_free(l_cfg_path,true);
        return -1;
    }

    dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);

    // reload ledger cache at once
    if (s_chain_net_reload_ledger_cache_once(l_net)) {
        log_it(L_WARNING,"Start one time ledger cache reloading");
        dap_ledger_purge(l_net->pub.ledger, false);
        dap_chain_net_srv_stake_purge(l_net);
    } else
        dap_chain_net_srv_stake_load_cache(l_net);

    // load chains
    dap_chain_t *l_chain = l_net->pub.chains;
    while(l_chain){
        l_net->pub.fee_value = uint256_0;
        l_net->pub.fee_addr = c_dap_chain_addr_blank;
        if (!dap_chain_load_all(l_chain)) {
            log_it (L_NOTICE, "Loaded chain files");
            if (DAP_CHAIN_PVT(l_chain)->need_reorder) {
                log_it(L_DAP, "Reordering chain files for chain %s", l_chain->name);
                if (l_chain->callback_atom_add_from_treshold)
                    while (l_chain->callback_atom_add_from_treshold(l_chain, NULL))
                        log_it(L_DEBUG, "Added atom from treshold");
                dap_chain_save_all(l_chain);
                DAP_CHAIN_PVT(l_chain)->need_reorder = false;
                if (l_chain->callback_purge) {
                    l_chain->callback_purge(l_chain);
                    dap_ledger_purge(l_net->pub.ledger, false);
                    l_net->pub.fee_value = uint256_0;
                    l_net->pub.fee_addr = c_dap_chain_addr_blank;
                    dap_chain_net_decree_purge(l_net);
                    dap_chain_load_all(l_chain);
                } else
                    log_it(L_WARNING, "No purge callback for chain %s, can't reload it with correct order", l_chain->name);
            }
        } else {
            dap_chain_save_all( l_chain );
            log_it (L_NOTICE, "Initialized chain files");
        }

        if (l_chain->callback_created)
            l_chain->callback_created(l_chain, l_cfg);

        l_chain = l_chain->next;
    }
    // Process thresholds if any
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

    // Do specific role actions post-chain created
    l_net_pvt->state_target = NET_STATE_OFFLINE;
    dap_chain_net_state_t l_target_state = NET_STATE_OFFLINE;
    l_net_pvt->only_static_links = false;
    switch ( l_net_pvt->node_role.enums ) {
        case NODE_ROLE_ROOT_MASTER:{
            // Set to process everything in datum pool
            dap_chain_t * l_chain = NULL;
            DL_FOREACH(l_net->pub.chains, l_chain)
                l_chain->is_datum_pool_proc = true;
            log_it(L_INFO,"Root master node role established");
        } // Master root includes root
        case NODE_ROLE_ROOT:{
            // Set to process only zerochain
            dap_chain_id_t l_chain_id = {{0}};
            dap_chain_t * l_chain = dap_chain_find_by_id(l_net->pub.id,l_chain_id);
            if (l_chain )
               l_chain->is_datum_pool_proc = true;
            l_net_pvt->only_static_links = true;
            log_it(L_INFO,"Root node role established");
        } break;
        case NODE_ROLE_CELL_MASTER:
        case NODE_ROLE_MASTER:{
            uint16_t l_proc_chains_count=0;
            char ** l_proc_chains = dap_config_get_array_str(l_cfg,"role-master" , "proc_chains", &l_proc_chains_count );
            for ( size_t i = 0; i< l_proc_chains_count ; i++) {
                dap_chain_id_t l_chain_id = {};
                if (dap_chain_id_parse(l_proc_chains[i], &l_chain_id) == 0) {
                    dap_chain_t * l_chain = dap_chain_find_by_id(l_net->pub.id, l_chain_id );
                    if (l_chain)
                        l_chain->is_datum_pool_proc = true;
                    else
                        log_it(L_WARNING, "Can't find chain id 0x%016" DAP_UINT64_FORMAT_X, l_chain_id.uint64);
                }
            }
            log_it(L_INFO,"Master node role established");
        } break;
        case NODE_ROLE_FULL:{
            log_it(L_INFO,"Full node role established");
        } break;
        case NODE_ROLE_LIGHT:
        default:
            log_it(L_INFO,"Light node role established");

    }
    if (!l_net_pvt->only_static_links)
        l_net_pvt->only_static_links = dap_config_get_item_bool_default(l_cfg, "general", "links_static_only", false);
    if (dap_config_get_item_bool_default(g_config ,"general", "auto_online", false))
    {
        dap_chain_net_balancer_prepare_list_links(l_net->pub.name);
        l_target_state = NET_STATE_ONLINE;
    }

    l_net_pvt->load_mode = false;

    l_net_pvt->balancer_http = !dap_config_get_item_bool_default(l_cfg, "general", "use_dns_links", false);

    dap_chain_net_add_gdb_notify_callback(l_net, dap_chain_net_sync_gdb_broadcast, l_net);
    DL_FOREACH(l_net->pub.chains, l_chain)
        // add a callback to monitor changes in the chain
        dap_chain_add_callback_notify(l_chain, s_chain_callback_notify, l_net);

    uint32_t l_timeout = dap_config_get_item_uint32_default(g_config, "node_client", "timer_update_states", 600);
    PVT(l_net)->main_timer = dap_interval_timer_create(l_timeout * 1000, s_main_timer_callback, l_net);
    log_it(L_INFO, "Chain network \"%s\" initialized",l_net->pub.name);
    PVT(l_net)->update_links_timer = dap_interval_timer_create(l_timeout * 1000, s_update_links_timer_callback, l_net);

    dap_config_close(l_cfg);

    if (l_target_state != l_net_pvt->state_target)
        dap_chain_net_state_go_to(l_net, l_target_state);

    return 0;
}

/**
 * @brief dap_chain_net_list
 * @return NULL if error
 */
dap_chain_net_t **dap_chain_net_list(uint16_t *a_size)
{
    if (!a_size)
        return NULL;
    *a_size = HASH_COUNT(s_net_items);
    if(*a_size){
        dap_chain_net_t **l_net_list = DAP_NEW_SIZE(dap_chain_net_t *, (*a_size) * sizeof(dap_chain_net_t *));
        if (!l_net_list) {
            log_it(L_CRITICAL, "Memory allocation error");
            return NULL;
        }
        dap_chain_net_item_t *l_current_item = NULL, *l_tmp = NULL;
        int i = 0;
        HASH_ITER(hh, s_net_items, l_current_item, l_tmp) {
            l_net_list[i++] = l_current_item->chain_net;
            if(i >= *a_size)
                break;
        }
        return l_net_list;
    } else {
        return NULL;
    }
}

/**
 * @brief dap_chain_net_by_name
 * @param a_name
 * @return
 */
dap_chain_net_t *dap_chain_net_by_name(const char *a_name)
{
    dap_chain_net_item_t *l_net_item = NULL;
    if (a_name) {
        HASH_FIND_STR(s_net_items,a_name,l_net_item);
    }
    return l_net_item ? l_net_item->chain_net : NULL;
}

/**
 * @brief dap_ledger_by_net_name
 * @param a_net_name
 * @return
 */
dap_ledger_t * dap_ledger_by_net_name( const char * a_net_name)
{
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    return l_net ? l_net->pub.ledger : NULL;
}

/**
 * @brief dap_chain_net_by_id
 * @param a_id
 * @return
 */
dap_chain_net_t *dap_chain_net_by_id(dap_chain_net_id_t a_id)
{
    dap_chain_net_item_t *l_net_item = NULL;
    HASH_FIND(hh2, s_net_ids, &a_id, sizeof(a_id), l_net_item);
    return l_net_item ? l_net_item->chain_net : NULL;
}

/**
 * @brief dap_chain_net_by_id
 * @param a_id
 * @return
 */
uint16_t dap_chain_net_get_acl_idx(dap_chain_net_t *a_net)
{
    return a_net ? PVT(a_net)->acl_idx : (uint16_t)-1;
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
        if(dap_strcmp(l_chain->name, a_name) == 0)
            return  l_chain;
   }
   return NULL;
}

/**
 * @brief dap_chain_net_get_chain_by_id
 * @param l_net
 * @param a_name
 * @return
 */
dap_chain_t *dap_chain_net_get_chain_by_id(dap_chain_net_t *l_net, dap_chain_id_t a_chain_id)
{
   dap_chain_t *l_chain;
   DL_FOREACH(l_net->pub.chains, l_chain)
        if (l_chain->id.uint64 == a_chain_id.uint64)
            return l_chain;
   return NULL;
}

/**
 * @brief dap_chain_net_get_chain_by_chain_type
 * @param a_datum_type
 * @return
 */
dap_chain_t *dap_chain_net_get_chain_by_chain_type(dap_chain_net_t *a_net, dap_chain_type_t a_datum_type)
{
    if (!a_net)
        return NULL;

    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, a_datum_type);
    if (l_chain)
        return l_chain;

    DL_FOREACH(a_net->pub.chains, l_chain) {
        for(int i = 0; i < l_chain->datum_types_count; i++) {
            dap_chain_type_t l_datum_type = l_chain->datum_types[i];
            if(l_datum_type == a_datum_type)
                return l_chain;
        }
    }
    return NULL;
}

/**
 * @brief dap_chain_net_get_default_chain_by_chain_type
 * @param a_datum_type
 * @return
 */
dap_chain_t * dap_chain_net_get_default_chain_by_chain_type(dap_chain_net_t *a_net, dap_chain_type_t a_datum_type)
{
    dap_chain_t * l_chain;

    if (!a_net)
        return NULL;

    DL_FOREACH(a_net->pub.chains, l_chain)
    {
        for(int i = 0; i < l_chain->default_datum_types_count; i++) {
            if(l_chain->default_datum_types[i] == a_datum_type)
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
char * dap_chain_net_get_gdb_group_mempool_by_chain_type(dap_chain_net_t *a_net, dap_chain_type_t a_datum_type)
{
    dap_chain_t *l_chain;
    if (!a_net)
        return NULL;
    DL_FOREACH(a_net->pub.chains, l_chain)
    {
        for(int i = 0; i < l_chain->datum_types_count; i++) {
            if(l_chain->datum_types[i] == a_datum_type)
                return dap_chain_net_get_gdb_group_mempool_new(l_chain);
        }
    }
    return NULL;
}

/**
 * @brief dap_chain_net_get_state
 * @param l_net
 * @return
 */
dap_chain_net_state_t dap_chain_net_get_state (dap_chain_net_t * l_net)
{
    return PVT(l_net)->state;
}

/**
 * @brief dap_chain_net_set_state
 * @param l_net
 * @param a_state
 */
void dap_chain_net_set_state(dap_chain_net_t *l_net, dap_chain_net_state_t a_state)
{
    assert(l_net);
    log_it(L_DEBUG,"%s set state %s", l_net->pub.name, dap_chain_net_state_to_str(a_state));
    if(a_state == PVT(l_net)->state){
        return;
    }
    PVT(l_net)->state = a_state;
    dap_proc_queue_add_callback(dap_events_worker_get_auto(), s_net_states_proc,l_net);
}


/**
 * @brief dap_chain_net_get_cur_addr
 * @param l_net
 * @return
 */
dap_chain_node_addr_t *dap_chain_net_get_cur_addr( dap_chain_net_t *a_net)
{
    return a_net ? (PVT(a_net)->node_info ? &PVT(a_net)->node_info->hdr.address : PVT(a_net)->node_addr) : NULL;
}

uint64_t dap_chain_net_get_cur_addr_int(dap_chain_net_t *a_net)
{
    if (!a_net)
        return 0;
    uint64_t l_ret = 0;
    if (PVT(a_net)->node_addr == NULL) { // Cache address if not present
        l_ret = dap_chain_net_get_cur_node_addr_gdb_sync(a_net->pub.name);
        if (l_ret) {
            PVT(a_net)->node_addr = DAP_NEW_Z(dap_chain_node_addr_t);
            PVT(a_net)->node_addr->uint64 = l_ret;
        }
    } else
        l_ret = PVT(a_net)->node_addr->uint64;
    return l_ret;
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
                if (l_remote_node_info)
                    DAP_DELETE(l_remote_node_info);
            }
            if(l_is_add) {
                dap_chain_node_addr_t *l_address = DAP_NEW_Z(dap_chain_node_addr_t);
                if (!l_address) {
                    log_it(L_CRITICAL, "Memory allocation error");
                    return NULL;
                }
                l_address->uint64 = l_cur_node_info->links[i].uint64;
                l_node_list = dap_list_append(l_node_list, l_address);
            }
        }
        DAP_DELETE(l_cur_node_info);
    }
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
    l_objs = dap_global_db_get_all_sync(l_net->pub.gdb_nodes, &l_nodes_count);
    if(!l_nodes_count || !l_objs)
        return l_node_list;
    for(size_t i = 0; i < l_nodes_count; i++) {
        dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t *) l_objs[i].value;
        dap_chain_node_addr_t *l_address = DAP_NEW(dap_chain_node_addr_t);
        if (!l_address) {
        log_it(L_CRITICAL, "Memory allocation error");
            return NULL;
        }
        l_address->uint64 = l_node_info->hdr.address.uint64;
        l_node_list = dap_list_append(l_node_list, l_address);
    }
    dap_global_db_objs_delete(l_objs, l_nodes_count);
    return l_node_list;
}

/**
 * Get nodes list from config file (list of dap_chain_node_addr_t struct)
 */
dap_list_t* dap_chain_net_get_node_list_cfg(dap_chain_net_t * a_net)
{
    dap_list_t *l_node_list = NULL;
    dap_chain_net_pvt_t *l_pvt_net = PVT(a_net);
    for(size_t i=0; i < l_pvt_net->seed_aliases_count;i++)
    {
        dap_chain_node_info_t *l_node_info = DAP_NEW_Z(dap_chain_node_info_t);
        l_node_info->hdr.ext_addr_v4 = l_pvt_net->seed_nodes_addrs_v4[i];
        l_node_info->hdr.ext_port = l_pvt_net->seed_nodes_ports[i];
        l_node_info->hdr.address.uint64 = l_pvt_net->seed_nodes_addrs[i];
        l_node_list = dap_list_append(l_node_list, l_node_info);
    }
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
 * @brief dap_chain_net_get_extra_gdb_group
 * @param a_net
 * @param a_node_addr
 * @return
 */
bool dap_chain_net_get_extra_gdb_group(dap_chain_net_t *a_net, dap_chain_node_addr_t a_node_addr)
{
    if (!a_net || !PVT(a_net)->gdb_sync_nodes_addrs)
        return false;
    for(uint16_t i = 0; i < PVT(a_net)->gdb_sync_nodes_addrs_count; i++) {
        if(a_node_addr.uint64 == PVT(a_net)->gdb_sync_nodes_addrs[i].uint64) {
            return true;
        }
    }
    return false;
}

void dap_chain_net_proc_mempool(dap_chain_net_t *a_net)
{
    dap_chain_t *l_chain;
    DL_FOREACH(a_net->pub.chains, l_chain)
        dap_chain_node_mempool_process_all(l_chain, true);
}

/**
 * @brief dap_chain_net_verify_datum_for_add
 * process datum verification process. Can be:
 *   if DAP_CHAIN_DATUM_TX, called dap_ledger_tx_add_check
 *   if DAP_CHAIN_DATUM_TOKEN_DECL, called dap_ledger_token_decl_add_check
 *   if DAP_CHAIN_DATUM_TOKEN_EMISSION, called dap_ledger_token_emission_add_check
 *   if DAP_CHAIN_DATUM_DECREE
 * @param a_net
 * @param a_datum
 * @return
 */
int dap_chain_net_verify_datum_for_add(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, dap_hash_fast_t *a_datum_hash)
{
    if (!a_datum)
        return -10;
    if (!a_chain)
        return -11;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    switch (a_datum->header.type_id) {
    case DAP_CHAIN_DATUM_TX:
        return dap_ledger_tx_add_check(l_net->pub.ledger, (dap_chain_datum_tx_t *)a_datum->data, a_datum->header.data_size, a_datum_hash);
    case DAP_CHAIN_DATUM_TOKEN_DECL:
        return dap_ledger_token_decl_add_check(l_net->pub.ledger, (dap_chain_datum_token_t *)a_datum->data, a_datum->header.data_size);
    case DAP_CHAIN_DATUM_TOKEN_EMISSION:
        return dap_ledger_token_emission_add_check(l_net->pub.ledger, a_datum->data, a_datum->header.data_size, a_datum_hash);
    case DAP_CHAIN_DATUM_DECREE:
        return dap_chain_net_decree_verify((dap_chain_datum_decree_t *)a_datum->data, l_net, a_datum->header.data_size, a_datum_hash);
    case DAP_CHAIN_DATUM_ANCHOR: {
        int l_result = dap_chain_net_anchor_verify((dap_chain_datum_anchor_t *)a_datum->data, a_datum->header.data_size);
        if (l_result)
            return l_result;
    }
    default:
        if (a_chain->callback_datum_find_by_hash &&
                a_chain->callback_datum_find_by_hash(a_chain, a_datum_hash, NULL, NULL))
            return -1;
    }
    return 0;
}

char *dap_chain_net_verify_datum_err_code_to_str(dap_chain_datum_t *a_datum, int a_code){
    switch (a_datum->header.type_id) {
    case DAP_CHAIN_DATUM_TX:
        return dap_ledger_tx_check_err_str(a_code);
    case DAP_CHAIN_DATUM_TOKEN_DECL:
        return dap_ledger_token_decl_add_err_code_to_str(a_code);
    case DAP_CHAIN_DATUM_TOKEN_EMISSION:
        return dap_ledger_token_emission_err_code_to_str(a_code);
    default:
        return !a_code ? "DAP_CHAIN_DATUM_VERIFY_OK" : dap_itoa(a_code);

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
    dap_snprintf(l_cfg_path, sizeof(l_cfg_path), "%s%s", l_path, a_net->pub.name);
    dap_config_t *l_cfg = dap_config_open(l_cfg_path);
    const char *l_auth_type = dap_config_get_item_str(l_cfg, "auth", "type");
    bool l_authorized = true;
    if (l_auth_type && !strcmp(l_auth_type, "ca")) {
        if (dap_hash_fast_is_blank(a_pkey_hash)) {
            return false;
        }
        l_authorized = false;
        char l_auth_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(a_pkey_hash, l_auth_hash_str, sizeof(l_auth_hash_str));
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
                dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_acl_gdb, &l_objs_count);
                for (size_t i = 0; i < l_objs_count; i++) {
                    if (!strcmp(l_objs[i].key, l_auth_hash_str)) {
                        l_authorized = true;
                        break;
                    }
                }
                dap_global_db_objs_delete(l_objs, l_objs_count);
            }
        }
        if (!l_authorized) {
            const char *l_acl_chains = dap_config_get_item_str(l_cfg, "auth", "acl_accept_ca_chains");
            if (l_acl_chains && !strcmp(l_acl_chains, "all")) {
                dap_list_t *l_certs = dap_cert_get_all_mem();
                for (dap_list_t *l_tmp = l_certs; l_tmp && !l_authorized; l_tmp = dap_list_next(l_tmp)) {
                    dap_cert_t *l_cert = (dap_cert_t *)l_tmp->data;
                    size_t l_pkey_size;
                    uint8_t *l_pkey_ser = dap_enc_key_serialize_pub_key(l_cert->enc_key, &l_pkey_size);
                    dap_chain_hash_fast_t l_cert_hash;
                    dap_hash_fast(l_pkey_ser, l_pkey_size, &l_cert_hash);
                    if (!memcmp(&l_cert_hash, a_pkey_hash, sizeof(dap_chain_hash_fast_t))) {
                        l_authorized = true;
                    }
                    DAP_DELETE(l_pkey_ser);
                }
            }
        }
    }
    dap_config_close(l_cfg);
    return l_authorized;
}

/**
 * @brief s_acl_callback function. Usually called from enc_http_proc
 * set acl (l_enc_key_ks->acl_list) from acl_accept_ca_list, acl_accept_ca_gdb chain config parameters in [auth] section
 * @param a_pkey_hash dap_chain_hash_fast_t hash object
 * @return uint8_t*
 */
static uint8_t *s_net_set_acl(dap_chain_hash_fast_t *a_pkey_hash)
{
    uint16_t l_net_count;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    if (l_net_count && l_net_list) {
        uint8_t *l_ret = DAP_NEW_SIZE(uint8_t, l_net_count);
        if (!l_ret) {
            log_it(L_CRITICAL, "Memory allocation error");
            DAP_DELETE(l_net_list);
            return NULL;
        }
        for (uint16_t i = 0; i < l_net_count; i++) {
            l_ret[i] = s_net_check_acl(l_net_list[i], a_pkey_hash);
        }
        DAP_DELETE(l_net_list);
        return l_ret;
    }
    if (l_net_list)
        DAP_DELETE(l_net_list);
    return NULL;
}

/**
 * @brief dap_chain_datum_list
 * Get datum list by filter
 * @param a_net
 * @param a_chain  if NULL, then for all chains
 * @param a_filter_func
 * @param a_filter_func_param
 */
dap_list_t* dap_chain_datum_list(dap_chain_net_t *a_net, dap_chain_t *a_chain, dap_chain_datum_filter_func_t *a_filter_func, void *a_filter_func_param)
{
    dap_list_t *l_list = NULL;
    if (!a_net)
        return NULL;
    dap_chain_t *l_chain_cur = a_chain ? a_chain : a_net->pub.chains;
    size_t l_sz;

    while(l_chain_cur) {
        // Use chain only for selected net and with callback_atom_get_datums
        if (l_chain_cur->callback_atom_get_datums)
        {
            dap_chain_cell_t *l_cell = l_chain_cur->cells;
            size_t l_atom_size = 0;
            dap_chain_atom_iter_t *l_atom_iter = l_chain_cur->callback_atom_iter_create(l_chain_cur, l_cell->id, 0);
            dap_chain_atom_ptr_t l_atom = l_chain_cur->callback_atom_iter_get_first(l_atom_iter, &l_atom_size);
            while(l_atom && l_atom_size)
            {
                size_t l_datums_count = 0;
                dap_chain_datum_t **l_datums = l_chain_cur->callback_atom_get_datums(l_atom, l_atom_size, &l_datums_count);
                dap_chain_datum_t *l_datum, *l_datum2;
                for(size_t l_datum_n = 0; l_datum_n < l_datums_count; l_datum_n++) {
                    if ( ! (l_datum = l_datums[l_datum_n]) )
                        continue;

                    if (a_filter_func && !a_filter_func(l_datum, l_chain_cur, a_filter_func_param))
                        continue;
                    /*
                    * Make a copy of the datum, copy is placed into the list,
                    * so don't forget to free whole list
                    */
                    l_sz = sizeof(dap_chain_datum_t) + l_datum->header.data_size + 16;
                    l_datum2 = DAP_NEW_Z_SIZE(dap_chain_datum_t, l_sz);
                    if (!l_datum2) {
                        log_it(L_ERROR, "Memory allocation in dap_chain_datum_list");
                        DAP_DEL_Z(l_datums);
                        dap_list_free(l_list);
                        return NULL;
                    }
                    memcpy(l_datum2, l_datum, l_sz);

                    /* Add new entry into the list */
                    l_list = dap_list_append(l_list, l_datum2);

                }
                DAP_DEL_Z(l_datums);
                // go to next transaction
                l_atom = l_chain_cur->callback_atom_iter_get_next(l_atom_iter, &l_atom_size);
            }
            l_chain_cur->callback_atom_iter_delete(l_atom_iter);
        }
        // Only for one chain
        if(a_chain)
            break;
        // go to next chain
        l_chain_cur = l_chain_cur->next;
    }
    return l_list;
}

/**
 * @brief Add datum to the ledger or smth else
 * @param a_chain
 * @param a_datum
 * @param a_datum_size
 * @return
 */
int dap_chain_datum_add(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, size_t a_datum_size, dap_hash_fast_t *a_datum_hash)
{
    size_t l_datum_data_size = a_datum->header.data_size;
    if (a_datum_size < l_datum_data_size + sizeof(a_datum->header)) {
        log_it(L_INFO,"Corrupted datum rejected: wrong size %zd not equal or less than datum size %zd",a_datum->header.data_size+ sizeof (a_datum->header),
               a_datum_size );
        return -101;
    }
    dap_ledger_t *l_ledger = dap_chain_net_by_id(a_chain->net_id)->pub.ledger;
    switch (a_datum->header.type_id) {
        case DAP_CHAIN_DATUM_DECREE: {
            dap_chain_datum_decree_t *l_decree = (dap_chain_datum_decree_t *)a_datum->data;
            size_t l_decree_size = dap_chain_datum_decree_get_size(l_decree);
            if (l_decree_size != l_datum_data_size) {
                log_it(L_WARNING, "Corrupted decree, datum size %zd is not equal to size of decree %zd", l_datum_data_size, l_decree_size);
                return -102;
            }
            return dap_chain_net_decree_load(l_decree, a_chain, a_datum_hash);
        }
        case DAP_CHAIN_DATUM_ANCHOR: {
            dap_chain_datum_anchor_t *l_anchor = (dap_chain_datum_anchor_t *)a_datum->data;
            size_t l_anchor_size = dap_chain_datum_anchor_get_size(l_anchor);
            if (l_anchor_size != l_datum_data_size) {
                log_it(L_WARNING, "Corrupted anchor, datum size %zd is not equal to size of anchor %zd", l_datum_data_size, l_anchor_size);
                return -102;
            }
            return dap_chain_net_anchor_load(l_anchor, a_chain);
        }
        case DAP_CHAIN_DATUM_TOKEN_DECL:
            return dap_ledger_token_load(l_ledger, a_datum->data, a_datum->header.data_size);

        case DAP_CHAIN_DATUM_TOKEN_EMISSION:
            return dap_ledger_token_emission_load(l_ledger, a_datum->data, a_datum->header.data_size, a_datum_hash);

        case DAP_CHAIN_DATUM_TX: {
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)a_datum->data;
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
            if (l_tx_size != l_datum_data_size) {
                log_it(L_WARNING, "Corrupted trnsaction, datum size %zd is not equal to size of TX %zd", l_datum_data_size, l_tx_size);
                return -102;
            }
            return dap_ledger_tx_load(l_ledger, l_tx, a_datum_hash);
        }
        case DAP_CHAIN_DATUM_CA:
            return dap_cert_chain_file_save(a_datum, a_chain->net_name);

        case DAP_CHAIN_DATUM_SIGNER:
        case DAP_CHAIN_DATUM_CUSTOM:
            break;
        default:
            return -666;
    }
    return 0;
}

bool dap_chain_net_get_load_mode(dap_chain_net_t * a_net)
{
    return PVT(a_net)->load_mode;
}

int dap_chain_net_add_reward(dap_chain_net_t *a_net, uint256_t a_reward, uint64_t a_block_num)
{
    dap_return_val_if_fail(a_net, -1);
    if (PVT(a_net)->rewards && PVT(a_net)->rewards->block_number >= a_block_num) {
        log_it(L_ERROR, "Can't add retrospective reward for block");
        return -2;
    }
    struct block_reward *l_new_reward = DAP_NEW_Z(struct block_reward);
    if (!l_new_reward) {
        log_it(L_CRITICAL, "Out of memory");
        return -3;
    }
    l_new_reward->block_number = a_block_num;
    l_new_reward->reward = a_reward;
    // Place new reward at begining
    DL_PREPEND(PVT(a_net)->rewards, l_new_reward);
    return 0;
}

uint256_t dap_chain_net_get_reward(dap_chain_net_t *a_net, uint64_t a_block_num)
{
    struct block_reward *l_reward;
    DL_FOREACH(PVT(a_net)->rewards, l_reward) {
        if (l_reward->block_number <= a_block_num)
            return l_reward->reward;
    }
    return uint256_0;
}

void dap_chain_net_announce_addrs() {
    if(!HASH_COUNT(s_net_items)){
        log_it(L_ERROR, "Can't find any nets");
        return;
    }
    dap_chain_net_item_t *l_net_item = NULL, *l_tmp = NULL;
    HASH_ITER(hh, s_net_items, l_net_item, l_tmp) {
        dap_chain_net_pvt_t *l_net_pvt = PVT(l_net_item->chain_net);
        if (l_net_pvt->node_info->hdr.ext_port &&
                (l_net_pvt->node_info->hdr.ext_addr_v4.s_addr != INADDR_ANY
                 || memcmp(&l_net_pvt->node_info->hdr.ext_addr_v6, &in6addr_any, sizeof(struct in6_addr))))
        {
            dap_chain_net_node_list_request(l_net_item->chain_net, l_net_pvt->node_info, false, 0);
            char l_node_addr_str[INET_ADDRSTRLEN] = { '\0' };
            inet_ntop(AF_INET, &l_net_pvt->node_info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
            log_it(L_MSG, "Announce our node address "NODE_ADDR_FP_STR" < %s:%u > in net %s",
                   NODE_ADDR_FP_ARGS(l_net_pvt->node_addr), l_node_addr_str, l_net_pvt->node_info->hdr.ext_port, l_net_item->name);
        }
    }
}

char *dap_chain_net_links_dump(dap_chain_net_t *a_net) {
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
    pthread_mutex_lock(&l_net_pvt->uplinks_mutex);
    dap_string_t *l_str_uplinks = dap_string_new("---------------------------\n"
                                         "| ↑\\↓ |\t#\t|\t\tIP\t\t|\tPort\t|\n");
    struct net_link *l_link, *l_link_tmp = NULL;
    size_t l_up_count = 0;
    HASH_ITER(hh, l_net_pvt->net_links, l_link, l_link_tmp) {
        dap_string_append_printf(l_str_uplinks, "|  ↑  |\t%zu\t|\t%s\t\t|\t%u\t|\n",
                                 ++l_up_count,
                                 inet_ntoa(l_link->link_info->hdr.ext_addr_v4),
                                 l_link->link_info->hdr.ext_port);
    }

    size_t l_down_count = 0;
    dap_string_t *l_str_downlinks = dap_string_new("---------------------------\n"
                                                 "| ↑\\↓ |\t#\t|\t\tIP\t\t|\tPort\t|\n");
    pthread_mutex_unlock(&l_net_pvt->uplinks_mutex);
    pthread_mutex_lock(&l_net_pvt->downlinks_mutex);
    struct downlink *l_downlink = NULL, *l_downtmp = NULL;
    HASH_ITER(hh, l_net_pvt->downlinks, l_downlink, l_downtmp) {
        dap_string_append_printf(l_str_downlinks, "|  ↓  |\t%zu\t|\t%s\t\t|\t%u\t|\n",
                                     ++l_down_count,
                                     l_downlink->addr, l_downlink->port);
    }
    pthread_mutex_unlock(&l_net_pvt->downlinks_mutex);
    char *l_res_str = dap_strdup_printf("Count links: %zu\n\nUplinks: %zu\n%s\n\nDownlinks: %zu\n%s\n",
                                        l_up_count + l_down_count, l_up_count, l_str_uplinks->str,
                                        l_down_count, l_str_downlinks->str);
    dap_string_free(l_str_uplinks, true);
    dap_string_free(l_str_downlinks, true);
    return l_res_str;
}

/**
 * @brief Update IP address and port in client
 * @param a_node_client - client to check address
 */
void dap_chain_net_link_update(dap_chain_node_client_t *a_node_client)
{
// sanity check
    dap_return_if_pass(!a_node_client || !a_node_client->net);
// func work
    size_t l_node_info_size = 0;
    char *l_key = dap_chain_node_addr_to_hash_str(&a_node_client->remote_node_addr);
    if(!l_key) {
        log_it(L_ERROR, "Can't calculate hash for addr\n");
        return;
    }

    dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t *)dap_global_db_get_sync(a_node_client->net->pub.gdb_nodes, l_key, &l_node_info_size, NULL, NULL);
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_node_client->net);
    pthread_mutex_lock(&l_net_pvt->uplinks_mutex);
        struct net_link *l_link = NULL, *l_link_tmp = NULL, *l_link_found = NULL;
        HASH_ITER(hh, l_net_pvt->net_links, l_link, l_link_tmp) {
            if (l_link->link == a_node_client) {
                l_link_found = l_link;
                break;
            }
        } 
        if(l_link_found && l_node_info->hdr.ext_port && 
            (l_link_found->uplink_ip != l_node_info->hdr.ext_addr_v4.s_addr || l_link_found->link->client->uplink_port != l_node_info->hdr.ext_port)) {
            char l_ip_str_old[INET_ADDRSTRLEN] = {0};
            char l_ip_str_new[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &l_link_found->uplink_ip, l_ip_str_old, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &l_node_info->hdr.ext_addr_v4.s_addr, l_ip_str_new, INET_ADDRSTRLEN);
            log_it(L_INFO, "Change IP addr to node "NODE_ADDR_FP_STR" from %s %d to %s %d", NODE_ADDR_FP_ARGS_S(l_node_info->hdr.address), l_ip_str_old, l_link_found->link->client->uplink_port, l_ip_str_new, l_node_info->hdr.ext_port);
            HASH_DEL(l_net_pvt->net_links, l_link_found);
            l_link_found->uplink_ip = l_node_info->hdr.ext_addr_v4.s_addr;
            HASH_ADD(hh, l_net_pvt->net_links, uplink_ip, sizeof(l_link_found->uplink_ip), l_link_found);
            l_link_found->link->client->uplink_port = l_node_info->hdr.ext_port;
            memcpy(l_link_found->link->client->uplink_addr, l_ip_str_new, strlen(l_ip_str_new));
        }
    pthread_mutex_unlock(&l_net_pvt->uplinks_mutex);
    DAP_DELETE(l_key);
}