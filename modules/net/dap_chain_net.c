/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
#include "dap_chain_datum_tx.h"
#include "dap_worker.h"
#include "dap_proc_thread.h"
#include "dap_enc_http.h"
#include "dap_chain_common.h"
#include "dap_chain_cell.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_anchor.h"
#include "dap_chain_net.h"
#include "dap_chain_net_node_list.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_anchor.h"
#include "dap_chain_net_decree.h"
#include "dap_chain_net_balancer.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_notify_srv.h"
#include "dap_chain_ledger.h"
#include "dap_global_db.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_ch_chain_net.h"
#include "dap_chain_ch.h"
#include "dap_stream_ch.h"
#include "dap_stream.h"
#include "dap_stream_ch_pkt.h"
#include "rand/dap_rand.h"
#include "json_object.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_net_srv_voting.h"
#include "dap_global_db_cluster.h"
#include "dap_link_manager.h"
#include "dap_stream_cluster.h"
#include "dap_http_ban_list_client.h"
#include "dap_net.h"

#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

#define LOG_TAG "chain_net"

#define F_DAP_CHAIN_NET_SYNC_FROM_ZERO   ( 1 << 8 )

static bool s_debug_more = false;

struct request_link_info {
    char addr[DAP_HOSTADDR_STRLEN + 1];
    uint16_t port;
};

struct block_reward {
    uint64_t block_number;
    uint256_t reward;
    struct block_reward *prev, *next;
};

enum sync_state {
    SYNC_STATE_IDLE,
    SYNC_STATE_WAITING,
    SYNC_STATE_SYNCED,
    SYNC_STATE_ERROR
};

struct chain_sync_context {
    enum sync_state state,
                    last_state;
    dap_time_t      stage_last_activity,
                    sync_idle_time;
    dap_stream_node_addr_t current_link;
    dap_chain_t *cur_chain;
    dap_chain_cell_t *cur_cell;
    dap_hash_fast_t requested_atom_hash;
    uint64_t requested_atom_num;
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

    dap_chain_node_info_t *node_info;  // Current node's info

    dap_balancer_type_t balancer_type;
    bool load_mode;

    uint16_t permanent_links_count;
    dap_link_info_t **permanent_links;

    uint16_t authorized_nodes_count;
    dap_stream_node_addr_t *authorized_nodes_addrs;

    uint16_t seed_nodes_count;
    struct request_link_info **seed_nodes_info;

    struct chain_sync_context sync_context;

    _Atomic(dap_chain_net_state_t) state, state_target;
    uint16_t acl_idx;

    //Global DB clusters for different access groups. Notification with cluster contents changing
    dap_global_db_cluster_t *mempool_clusters; // List of chains mempools
    dap_global_db_cluster_t *orders_cluster;
    dap_global_db_cluster_t *nodes_cluster;

    // Block sign rewards history
    struct block_reward *rewards;
    dap_chain_net_decree_t *decree;
    decree_table_t *decrees;
    anchor_table_t *anchors;
} dap_chain_net_pvt_t;

typedef struct dap_chain_net_item{
    char name[DAP_CHAIN_NET_NAME_MAX + 1];
    dap_chain_net_id_t net_id;
    dap_chain_net_t *chain_net;
    UT_hash_handle hh, hh2;
} dap_chain_net_item_t;

#define PVT(a) ((dap_chain_net_pvt_t *)a->pvt)
#define PVT_S(a) ((dap_chain_net_pvt_t *)a.pvt)

static dap_chain_net_item_t *s_net_items = NULL, *s_net_ids = NULL;
static pthread_mutex_t s_net_cond_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_net_cond = PTHREAD_COND_INITIALIZER;
static uint16_t s_net_loading_count = 0;

static const char *c_net_states[] = {
    [NET_STATE_OFFLINE]             = "NET_STATE_OFFLINE",
    [NET_STATE_LINKS_PREPARE ]      = "NET_STATE_LINKS_PREPARE",
    [NET_STATE_LINKS_CONNECTING]    = "NET_STATE_LINKS_CONNECTING",
    [NET_STATE_LINKS_ESTABLISHED]   = "NET_STATE_LINKS_ESTABLISHED",
    [NET_STATE_SYNC_CHAINS]         = "NET_STATE_SYNC_CHAINS",
    [NET_STATE_ONLINE]              = "NET_STATE_ONLINE"
};

static inline const char * dap_chain_net_state_to_str(dap_chain_net_state_t a_state) {
    return a_state < NET_STATE_OFFLINE || a_state > NET_STATE_ONLINE ? "NET_STATE_INVALID" : c_net_states[a_state];
}

// Node link callbacks
static void s_link_manager_callback_connected(dap_link_t *a_link, uint64_t a_net_id);
static void s_link_manager_callback_error(dap_link_t *a_link, uint64_t a_net_id, int a_error);
static bool s_link_manager_callback_disconnected(dap_link_t *a_link, uint64_t a_net_id, int a_links_count);
static int s_link_manager_fill_net_info(dap_link_t *a_link);
static int s_link_manager_link_request(uint64_t a_net_id);

static const dap_link_manager_callbacks_t s_link_manager_callbacks = {
    .connected      = s_link_manager_callback_connected,
    .disconnected   = s_link_manager_callback_disconnected,
    .error          = s_link_manager_callback_error,
    .fill_net_info  = s_link_manager_fill_net_info,
    .link_request   = s_link_manager_link_request,
};

// State machine switchs here
static bool s_net_states_proc(void *a_arg);
static void s_net_states_notify(dap_chain_net_t * l_net);
static void s_nodelist_change_notify(dap_store_obj_t *a_obj, void *a_arg);
//static void s_net_proc_kill( dap_chain_net_t * a_net );
static int s_net_init(const char * a_net_name, uint16_t a_acl_idx);
static bool s_net_load(void *a_arg);
static int s_net_try_online(dap_chain_net_t *a_net);
static int s_cli_net(int argc, char ** argv, void **a_str_reply);
static uint8_t *s_net_set_acl(dap_chain_hash_fast_t *a_pkey_hash);
static void s_sync_timer_callback(void *a_arg);

/**
 * @brief
 * init network settings from cellrame-node.cfg file
 * register net* commands in cellframe-node-cli interface
 * @return
 */
int dap_chain_net_init()
{
    dap_ledger_init();
    dap_chain_ch_init();
    dap_stream_ch_chain_net_init();
    dap_chain_node_client_init();
    dap_chain_net_srv_voting_init();
    dap_http_ban_list_client_init();
    dap_link_manager_init(&s_link_manager_callbacks);
    dap_chain_node_init();
    dap_cli_server_cmd_add ("net", s_cli_net, "Network commands",
        "net list [chains -net <net_name>]\n"
            "\tList all networks or list all chains in selected network\n"
        "net -net <net_name> [-mode {update | all}] go {online | offline | sync}\n"
            "\tFind and establish links and stay online. \n"
            "\tMode \"update\" is by default when only new chains and gdb are updated. Mode \"all\" updates everything from zero\n"
        "net -net <net_name> get {status | fee | id}\n"
            "\tDisplays the current current status, current fee or net id.\n"
        "net -net <net_name> stats {tx | tps} [-from <from_time>] [-to <to_time>] [-prev_sec <seconds>] \n"
            "\tTransactions statistics. Time format is <Year>-<Month>-<Day>_<Hours>:<Minutes>:<Seconds> or just <Seconds> \n"
        "net -net <net_name> [-mode {update | all}] sync {all | gdb | chains}\n"
            "\tSyncronyze gdb, chains or everything\n"
            "\tMode \"update\" is by default when only new chains and gdb are updated. Mode \"all\" updates everything from zero\n"
        "net -net <net_name> link {list | add | del | info [-addr]| disconnect_all}\n"
            "\tList, add, del, dump or establish links\n"
        "net -net <net_name> ca add {-cert <cert_name> | -hash <cert_hash>}\n"
            "\tAdd certificate to list of authority cetificates in GDB group\n"
        "net -net <net_name> ca list\n"
            "\tPrint list of authority cetificates from GDB group\n"
        "net -net <net_name> ca del -hash <cert_hash> [-H {hex | base58(default)}]\n"
            "\tDelete certificate from list of authority cetificates in GDB group by it's hash\n"
        "net -net <net_name> ledger reload\n"
            "\tPurge the cache of chain net ledger and recalculate it from chain file\n"
        "net -net <net_name> poa_certs list\n"
            "\tPrint list of PoA cerificates for this network\n");

    s_debug_more = dap_config_get_item_bool_default(g_config,"chain_net","debug_more", s_debug_more);

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
            snprintf(l_full_path, sizeof(l_full_path), "%s/%s", l_net_dir_str, l_dir_entry->d_name);
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
    } else {
        log_it(L_WARNING, "Can't open entries on path %s, error %d: \"%s\"",
                           l_net_dir_str, errno, dap_strerror(errno));
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
        const char *l_auth_gdb = dap_config_get_item_str(a_net->pub.config, "auth", "acl_accept_ca_gdb");
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
int dap_chain_net_state_go_to(dap_chain_net_t *a_net, dap_chain_net_state_t a_new_state)
{
    if (PVT(a_net)->load_mode) {
        log_it(L_ERROR, "Can't change state of loading network '%s'", a_net->pub.name);
        return -1;
    }
    if (PVT(a_net)->state_target == a_new_state) {
        log_it(L_NOTICE, "Network %s already %s state %s", a_net->pub.name,
                                PVT(a_net)->state == a_new_state ? "have" : "going to", dap_chain_net_state_to_str(a_new_state));
        return 0;
    }
    //PVT(a_net)->flags |= F_DAP_CHAIN_NET_SYNC_FROM_ZERO;  // TODO set this flag according to -mode argument from command line
    PVT(a_net)->state_target = a_new_state;
    if (a_new_state == NET_STATE_OFFLINE) {
        char l_err_str[] = "ERROR_NET_IS_OFFLINE";
        size_t l_error_size = sizeof(dap_stream_ch_chain_net_pkt_t) + sizeof(l_err_str);
        dap_stream_ch_chain_net_pkt_t *l_error = DAP_NEW_STACK_SIZE(dap_stream_ch_chain_net_pkt_t, l_error_size);
        l_error->hdr.version = DAP_STREAM_CH_CHAIN_NET_PKT_VERSION;
        l_error->hdr.net_id = a_net->pub.id;
        l_error->hdr.data_size = sizeof(l_err_str);
        memcpy(l_error->data, l_err_str, sizeof(l_err_str));
        dap_cluster_broadcast(PVT(a_net)->nodes_cluster->links_cluster, DAP_STREAM_CH_CHAIN_NET_ID,
                              DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR, l_error, l_error_size, NULL, 0);
        dap_link_manager_set_net_condition(a_net->pub.id.uint64, false);
        dap_chain_esbocs_stop_timer(a_net->pub.id);
    } else if (PVT(a_net)->state == NET_STATE_OFFLINE) {
        dap_link_manager_set_net_condition(a_net->pub.id.uint64, true);
        for (uint16_t i = 0; i < PVT(a_net)->permanent_links_count; ++i) {
            dap_link_info_t *l_permalink_info = PVT(a_net)->permanent_links[i];
            if (dap_chain_net_link_add(a_net, &l_permalink_info->node_addr, l_permalink_info->uplink_addr, l_permalink_info->uplink_port)) {
                log_it(L_ERROR, "Can't create permanent link to addr " NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_permalink_info->node_addr));
                continue;
            }
        }
        if (a_new_state == NET_STATE_ONLINE)
            dap_chain_esbocs_start_timer(a_net->pub.id);
    }
    return dap_proc_thread_callback_add(NULL, s_net_states_proc, a_net);
}

DAP_INLINE dap_chain_net_state_t dap_chain_net_get_target_state(dap_chain_net_t *a_net)
{
    return PVT(a_net)->state_target;
}

static struct request_link_info *s_balancer_link_from_cfg(dap_chain_net_t *a_net)
{
    switch (PVT(a_net)->seed_nodes_count) {
    case 0: return log_it(L_ERROR, "No available links! Add them in net config"), NULL;
    case 1: return PVT(a_net)->seed_nodes_info[0];
    default: return PVT(a_net)->seed_nodes_info[dap_random_uint16() % PVT(a_net)->seed_nodes_count];
    }
}

dap_chain_node_info_t *dap_chain_net_get_my_node_info(dap_chain_net_t *a_net)
{
    dap_return_val_if_fail(a_net, NULL);
    return PVT(a_net)->node_info;
}

bool dap_chain_net_is_my_node_authorized(dap_chain_net_t *a_net)
{
    dap_return_val_if_fail(a_net, false);
    return dap_cluster_member_find_role(PVT(a_net)->nodes_cluster->role_cluster, &g_node_addr) == DAP_GDB_MEMBER_ROLE_ROOT;
}

dap_stream_node_addr_t *dap_chain_net_get_authorized_nodes(dap_chain_net_t *a_net, size_t *a_nodes_count)
{
    dap_return_val_if_fail(a_net, false);
    return dap_cluster_get_all_members_addrs(PVT(a_net)->nodes_cluster->role_cluster, a_nodes_count, DAP_GDB_MEMBER_ROLE_ROOT);
}

int dap_chain_net_link_add(dap_chain_net_t *a_net, dap_stream_node_addr_t *a_addr, const char *a_host, uint16_t a_port)
{
    bool l_is_link_present = dap_link_manager_link_find(a_addr, a_net->pub.id.uint64);
    if (l_is_link_present || a_addr->uint64 == g_node_addr.uint64)
        return -3; // Link is already found for this net or link is to yourself
    if (dap_link_manager_link_create(a_addr, a_net->pub.id.uint64)) {
        log_it(L_ERROR, "Can't create link to addr " NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS(a_addr));
        return -1;
    }
    int rc = dap_link_manager_link_update(a_addr, a_host, a_port);
    if (rc)
        log_it(L_ERROR, "Can't update link to addr " NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS(a_addr));
    return rc;
}

/**
 * @brief s_link_manager_callback_connected
 * @param a_node_client
 * @param a_arg
 */
static void s_link_manager_callback_connected(dap_link_t *a_link, uint64_t a_net_id)
{
// sanity check
    dap_return_if_pass(!a_link || !a_net_id);
// func work
    dap_chain_net_t * l_net = dap_chain_net_by_id((dap_chain_net_id_t){.uint64 = a_net_id});
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);

    log_it(L_NOTICE, "Established connection with %s."NODE_ADDR_FP_STR,l_net->pub.name,
           NODE_ADDR_FP_ARGS_S(a_link->addr));

    struct json_object *l_json = dap_chain_net_states_json_collect(l_net);
    char l_err_str[128] = { };
    snprintf(l_err_str, sizeof(l_err_str)
                 , "Established connection with link " NODE_ADDR_FP_STR
                 , NODE_ADDR_FP_ARGS_S(a_link->addr));
    json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
    if(l_net_pvt->state == NET_STATE_LINKS_CONNECTING ){
        l_net_pvt->state = NET_STATE_LINKS_ESTABLISHED;
    }
    dap_stream_ch_chain_net_pkt_hdr_t l_announce = { .version = DAP_STREAM_CH_CHAIN_NET_PKT_VERSION,
                                                     .net_id  = l_net->pub.id };
    dap_stream_ch_pkt_send_by_addr(&a_link->addr, DAP_STREAM_CH_CHAIN_NET_ID, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ANNOUNCE,
                                   &l_announce, sizeof(l_announce));
}

static bool s_net_check_link_is_premanent(dap_chain_net_t *a_net, dap_stream_node_addr_t a_addr)
{
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
    for (uint16_t i = 0; i < l_net_pvt->permanent_links_count; i++) {
        if (l_net_pvt->permanent_links[i]->node_addr.uint64 == a_addr.uint64)
            return true;
    }
    return false;
}

/**
 * @brief s_link_manager_callback_disconnected
 * @param a_node_client
 * @param a_arg
 */

static bool s_link_manager_callback_disconnected(dap_link_t *a_link, uint64_t a_net_id, int a_links_count)
{
// sanity check
    dap_return_val_if_pass(!a_link, false);
// func work
    dap_chain_net_t *l_net = dap_chain_net_by_id((dap_chain_net_id_t){.uint64 = a_net_id});
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    bool l_link_is_permanent = s_net_check_link_is_premanent(l_net, a_link->addr);
    log_it(L_INFO, "%s."NODE_ADDR_FP_STR" can't connect for now. %s", l_net ? l_net->pub.name : "(unknown)" ,
            NODE_ADDR_FP_ARGS_S(a_link->addr),
            l_link_is_permanent ? "Setting reconnection pause for it." : "Dropping it.");
    if (!a_links_count && l_net_pvt->state == NET_STATE_ONLINE)
        l_net_pvt->state = NET_STATE_LINKS_PREPARE;
    return l_link_is_permanent;
}

/**
 * @brief s_link_manager_callback_error
 * @param a_node_client
 * @param a_error
 * @param a_arg
 */
static void s_link_manager_callback_error(dap_link_t *a_link, uint64_t a_net_id, int a_error)
{
// sanity check
    dap_return_if_pass(!a_link);
// func work
    dap_chain_net_t *l_net = dap_chain_net_by_id((dap_chain_net_id_t){.uint64 = a_net_id});
    log_it(L_WARNING, "Can't establish link with %s."NODE_ADDR_FP_STR,
           l_net ? l_net->pub.name : "(unknown)", NODE_ADDR_FP_ARGS_S(a_link->addr));
    if (l_net){
        struct json_object *l_json = dap_chain_net_states_json_collect(l_net);
        char l_err_str[512] = { };
        snprintf(l_err_str, sizeof(l_err_str)
                     , "Link " NODE_ADDR_FP_STR " [%s] can't be established, errno %d"
                     , NODE_ADDR_FP_ARGS_S(a_link->addr), a_link->uplink.client->link_info.uplink_addr, a_error);
        json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
        dap_notify_server_send_mt(json_object_get_string(l_json));
        json_object_put(l_json);
    }
}

/**
 * @brief Launch a connect with a link
 * @param a_net
 * @param a_link_node_info node parameters
 * @return list of dap_chain_node_info_t
 */
int s_link_manager_link_request(uint64_t a_net_id)
{
// sanity check
    dap_chain_net_t *l_net = dap_chain_net_by_id((dap_chain_net_id_t){.uint64 = a_net_id});
    dap_return_val_if_pass(!l_net, -1);
// func work
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    if (l_net_pvt->state_target == NET_STATE_OFFLINE)
        return -2;
    if (l_net_pvt->state == NET_STATE_LINKS_PREPARE)
        l_net_pvt->state = NET_STATE_LINKS_CONNECTING;
    struct request_link_info *l_balancer_link = s_balancer_link_from_cfg(l_net);
    if (!l_balancer_link) {
        log_it(L_ERROR, "Can't process balancer link %s request", dap_chain_net_balancer_type_to_str(PVT(l_net)->balancer_type));
        return -5;
    }
    return dap_chain_net_balancer_request(l_net, l_balancer_link->addr,  l_balancer_link->port, PVT(l_net)->balancer_type);
}

int s_link_manager_fill_net_info(dap_link_t *a_link)
{
// sanity check
    dap_return_val_if_pass(!a_link, -1);
// func work
    dap_chain_net_item_t *l_net_item = NULL, *l_tmp = NULL;
    dap_chain_node_info_t *l_node_info = NULL;
    HASH_ITER(hh, s_net_items, l_net_item, l_tmp)
        if ((l_node_info = dap_chain_node_info_read(l_net_item->chain_net, &a_link->addr)))
            break;
    if (!l_node_info)
        return -3;
    a_link->uplink.ready = true;
    if (dap_link_manager_link_update(&a_link->addr, l_node_info->ext_host, l_node_info->ext_port))
        a_link->uplink.ready = true;
    DAP_DELETE(l_node_info);
    return 0;
}

json_object *s_net_sync_status(dap_chain_net_t *a_net)
{
    // sanity check
    dap_return_val_if_pass(!a_net, NULL);

    json_object *l_jobj_chains_array = json_object_new_object();
    dap_chain_t *l_chain = NULL;
    DL_FOREACH(a_net->pub.chains, l_chain) {
        json_object *l_jobj_chain = json_object_new_object();
        json_object *l_jobj_chain_status = NULL;
        json_object *l_jobj_percent = NULL;
        double l_percent = l_chain->callback_count_atom(l_chain) ?
                                   (double) (l_chain->callback_count_atom(l_chain) * 100) / l_chain->atom_num_last : 0;
        if (l_percent > 100)
            l_percent = 100;
        char *l_percent_str = dap_strdup_printf("%.3f", l_percent);
        dap_chain_net_state_t l_state = PVT(a_net)->state;
        switch (l_state) {
            case NET_STATE_OFFLINE:
            case NET_STATE_LINKS_PREPARE:
            case NET_STATE_LINKS_ESTABLISHED:
            case NET_STATE_LINKS_CONNECTING:
                l_jobj_chain_status = json_object_new_string("not synced");
                l_jobj_percent = json_object_new_string(" - %");
                break;
            case NET_STATE_ONLINE:
                l_jobj_chain_status = json_object_new_string("synced");
                l_jobj_percent = json_object_new_string(l_percent_str);
                break;
            case NET_STATE_SYNC_CHAINS:
                if (PVT(a_net)->sync_context.cur_chain && PVT(a_net)->sync_context.cur_chain->id.uint64 == l_chain->id.uint64) {
                    l_jobj_chain_status = json_object_new_string("sync in process");
                    l_jobj_percent = json_object_new_string(l_percent_str);
                } else {
                    if (l_chain->atom_num_last == l_chain->callback_count_atom(l_chain)) {
                        l_jobj_chain_status = json_object_new_string("synced");
                        l_jobj_percent = json_object_new_string(l_percent_str);
                    } else {
                        l_jobj_chain_status = json_object_new_string("not synced");
                        l_jobj_percent = json_object_new_string(" - %");
                    }
                }
                break;
        }
        DAP_DELETE(l_percent_str);
        json_object *l_jobj_current = json_object_new_uint64(l_chain->callback_count_atom(l_chain));
        json_object *l_jobj_total = json_object_new_uint64(l_chain->atom_num_last);
        json_object_object_add(l_jobj_chain, "status", l_jobj_chain_status);
        json_object_object_add(l_jobj_chain, "current", l_jobj_current);
        json_object_object_add(l_jobj_chain, "in network", l_jobj_total);
        json_object_object_add(l_jobj_chain, "percent", l_jobj_percent);
        json_object_object_add(l_jobj_chains_array, l_chain->name, l_jobj_chain);

    }
    return l_jobj_chains_array;
}

struct json_object *dap_chain_net_states_json_collect(dap_chain_net_t *a_net) {
    json_object *l_json = json_object_new_object();
    json_object_object_add(l_json, "class"            , json_object_new_string("NetStates"));
    json_object_object_add(l_json, "name"             , json_object_new_string((const char*)a_net->pub.name));
    json_object_object_add(l_json, "networkState"     , json_object_new_string(dap_chain_net_state_to_str(PVT(a_net)->state)));
    json_object_object_add(l_json, "targetState"      , json_object_new_string(dap_chain_net_state_to_str(PVT(a_net)->state_target)));
    json_object_object_add(l_json, "linksCount"       , json_object_new_int(0));
    json_object_object_add(l_json, "activeLinksCount" , json_object_new_int(dap_link_manager_links_count(a_net->pub.id.uint64)));
    char l_node_addr_str[24] = {'\0'};
    int l_tmp = snprintf(l_node_addr_str, sizeof(l_node_addr_str), NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(g_node_addr));
    json_object_object_add(l_json, "nodeAddress"     , json_object_new_string(l_tmp ? l_node_addr_str : "0000::0000::0000::0000"));
    if (PVT(a_net)->state == NET_STATE_SYNC_CHAINS) {
        json_object *l_json_sync_status = s_net_sync_status(a_net);
        json_object_object_add(l_json, "processed", l_json_sync_status);
    }
    return l_json;
}

/**
 * @brief s_net_states_notify
 * @param l_net
 */
static void s_net_states_notify(dap_chain_net_t *a_net)
{
    struct json_object *l_json = dap_chain_net_states_json_collect(a_net);
    json_object_object_add(l_json, "errorMessage", json_object_new_string(" ")); // regular notify has no error
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
}

/**
 * @brief s_net_states_proc
 * @param l_net
 */
static bool s_net_states_proc(void *a_arg)
{
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
            if ( l_net_pvt->state_target != NET_STATE_OFFLINE ){
                l_net_pvt->state = NET_STATE_LINKS_PREPARE;
                l_repeat_after_exit = true;
            }
            l_net_pvt->last_sync = 0;
        } break;

        // Prepare links
        case NET_STATE_LINKS_PREPARE: {
            log_it(L_NOTICE,"%s.state: NET_STATE_LINKS_PREPARE", l_net->pub.name);
        } break;

        case NET_STATE_LINKS_CONNECTING: {
            log_it(L_INFO, "%s.state: NET_STATE_LINKS_CONNECTING",l_net->pub.name);
            size_t l_used_links = 0;
        } break;

        case NET_STATE_LINKS_ESTABLISHED:
            log_it(L_INFO,"%s.state: NET_STATE_LINKS_ESTABLISHED", l_net->pub.name);
            break;

        case NET_STATE_SYNC_CHAINS:
            log_it(L_INFO,"%s.state: NET_STATE_SYNC_CHAINS", l_net->pub.name);
            break;

        case NET_STATE_ONLINE:
            log_it(L_NOTICE,"%s.state: NET_STATE_ONLINE", l_net->pub.name);
            l_net_pvt->last_sync = dap_time_now();
            break;

        default:
            log_it(L_DEBUG, "Unprocessed state");
    }
    s_net_states_notify(l_net);
    return l_repeat_after_exit;
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
static dap_chain_net_t *s_net_new(dap_chain_net_id_t *a_id, const char *a_name,
                                  const char *a_native_ticker, const char *a_node_role)
{
// sanity check
    dap_return_val_if_pass(!a_id || !a_name || !a_native_ticker || !a_node_role, NULL);
    dap_chain_net_t *l_ret = NULL;
// memory alloc
    DAP_NEW_Z_SIZE_RET_VAL(l_ret, dap_chain_net_t, sizeof(dap_chain_net_t) + sizeof(dap_chain_net_pvt_t), NULL, NULL);
    DAP_NEW_Z_SIZE_RET_VAL(PVT(l_ret)->node_info, dap_chain_node_info_t, sizeof(dap_chain_node_info_t) + DAP_HOSTADDR_STRLEN + 1, NULL, l_ret);
// func work
    l_ret->pub.id.uint64 = a_id->uint64;

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
    l_ret->pub.name = dap_strdup( a_name );
    l_ret->pub.native_ticker = dap_strdup( a_native_ticker );
    if (!(l_ret->pub.name = dap_strdup(a_name)) ||
        !(l_ret->pub.native_ticker = dap_strdup( a_native_ticker )))
            DAP_DEL_MULTY(l_ret->pub.name, l_ret->pub.native_ticker, l_ret);
    log_it (L_NOTICE, "Node role \"%s\" selected for network '%s'", a_node_role, a_name);
    return l_ret;
}

/**
 * @brief
 * load network config settings
 */
void dap_chain_net_load_all()
{
    pthread_mutex_lock(&s_net_cond_lock);
    s_net_loading_count = HASH_COUNT(s_net_items);
    if (!s_net_loading_count) {
        log_it(L_ERROR, "Can't find any nets");
        pthread_mutex_unlock(&s_net_cond_lock);
        return;
    }
    dap_chain_net_item_t *l_net_items_current = NULL, *l_net_items_tmp = NULL;
    HASH_ITER(hh, s_net_items, l_net_items_current, l_net_items_tmp)
        dap_proc_thread_callback_add(NULL, s_net_load, l_net_items_current->chain_net);
    while (s_net_loading_count)
        pthread_cond_wait(&s_net_cond, &s_net_cond_lock);
    pthread_mutex_unlock(&s_net_cond_lock);
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

json_object* s_set_reply_text_node_status_json(dap_chain_net_t *a_net) {
    json_object *l_jobj_ret = json_object_new_object();
    json_object *l_jobj_net_name  = json_object_new_string(a_net->pub.name);
    if (!l_jobj_ret || !l_jobj_net_name) {
        json_object_put(l_jobj_ret);
        json_object_put(l_jobj_net_name);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_jobj_ret, "net", l_jobj_net_name);
    dap_chain_node_addr_t l_cur_node_addr = { 0 };
    l_cur_node_addr.uint64 = dap_chain_net_get_cur_addr_int(a_net);
    json_object *l_jobj_cur_node_addr;
    if(!l_cur_node_addr.uint64) {
        l_jobj_cur_node_addr = json_object_new_string("not defined");
    } else {
        char *l_cur_node_addr_str = dap_strdup_printf(NODE_ADDR_FP_STR,NODE_ADDR_FP_ARGS_S(l_cur_node_addr));
        l_jobj_cur_node_addr = json_object_new_string(l_cur_node_addr_str);
        DAP_DELETE(l_cur_node_addr_str);
    }
    if (!l_jobj_cur_node_addr) {
        json_object_put(l_jobj_ret);
        return NULL;
    }
    json_object_object_add(l_jobj_ret, "current_addr", l_jobj_cur_node_addr);
    if (PVT(a_net)->state != NET_STATE_OFFLINE) {
        json_object *l_jobj_links = json_object_new_object();
        json_object *l_jobj_active_links = json_object_new_uint64(dap_link_manager_links_count(a_net->pub.id.uint64));
        json_object *l_jobj_required_links = json_object_new_uint64(dap_link_manager_required_links_count(a_net->pub.id.uint64));
        if (!l_jobj_links || !l_jobj_active_links || !l_jobj_required_links) {
            json_object_put(l_jobj_ret);
            json_object_put(l_jobj_links);
            json_object_put(l_jobj_active_links);
            json_object_put(l_jobj_required_links);
            dap_json_rpc_allocation_error;
            return NULL;
        }
        json_object_object_add(l_jobj_links, "active", l_jobj_active_links);
        json_object_object_add(l_jobj_links, "required", l_jobj_required_links);
        json_object_object_add(l_jobj_ret, "links", l_jobj_links);
    }

    json_object *l_json_sync_status = s_net_sync_status(a_net);
    json_object_object_add(l_jobj_ret, "processed", l_json_sync_status);

    json_object *l_jobj_states = json_object_new_object();
    json_object *l_jobj_current_states = json_object_new_string(c_net_states[PVT(a_net)->state]);
    json_object *l_jobj_target_states = json_object_new_string(c_net_states[PVT(a_net)->state_target]);
    json_object_object_add(l_jobj_states, "current", l_jobj_current_states);
    json_object_object_add(l_jobj_states, "target", l_jobj_target_states);
    json_object_object_add(l_jobj_ret, "states", l_jobj_states);
    return l_jobj_ret;
}

void s_set_reply_text_node_status(void **a_str_reply, dap_chain_net_t * a_net){
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
                                                           dap_link_manager_links_count(a_net->pub.id.uint64),
                                                           0 /*HASH_COUNT(PVT(a_net)->net_links)*/);
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
 * @brief reload ledger
 * command cellframe-node-cli net -net <network_name> ledger reload
 * @param l_net
 * @return true
 * @return false
 */
void dap_chain_net_purge(dap_chain_net_t *l_net)
{
    dap_chain_net_srv_stake_purge(l_net);
    dap_chain_net_decree_deinit(l_net);
    dap_ledger_purge(l_net->pub.ledger, false);
    dap_chain_t *l_chain = NULL;
    DL_FOREACH(l_net->pub.chains, l_chain) {
        if (l_chain->callback_purge) {
            l_chain->callback_purge(l_chain);
        }
        if (!dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
            dap_chain_esbocs_set_min_validators_count(l_chain, 0);
        }
        dap_chain_load_all(l_chain);
        l_net->pub.fee_value = uint256_0;
        l_net->pub.fee_addr = c_dap_chain_addr_blank;
    }
    DL_FOREACH(l_net->pub.chains, l_chain) {
        if (l_chain->callback_atom_add_from_treshold) {
            while (l_chain->callback_atom_add_from_treshold(l_chain, NULL))
                debug_if(s_debug_more, L_DEBUG, "Added atom from treshold");
        }
    }
    dap_chain_net_decree_init(l_net);
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
        log_it(L_NOTICE, "Cache file '%s' already exists", l_cache_file);
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
static int s_cli_net(int argc, char **argv, void **reply)
{
    json_object ** json_arr_reply = (json_object **) reply;
    json_object *l_jobj_return = json_object_new_object();
    if (!l_jobj_return) {
        dap_json_rpc_allocation_error;
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    int arg_index = 1;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        json_object_put(l_jobj_return);
        dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_INVALID_PARAMETER_HASH, "%s", "invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NET_JSON_RPC_INVALID_PARAMETER_HASH;

    }

    // command 'list'
    const char * l_list_cmd = NULL;

    if(dap_cli_server_cmd_find_option_val(argv, arg_index, dap_min(argc, arg_index + 1), "list", &l_list_cmd) != 0 ) {
        if (dap_strcmp(l_list_cmd,"chains")==0){
            const char * l_net_str = NULL;
            dap_chain_net_t* l_net = NULL;
            if (dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &l_net_str) && !l_net_str) {
                json_object_put(l_jobj_return);
                dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_CAN_NOT_PARAMETER_NET_REQUIRE, "%s", "Parameter '-net' require <net name>");
                return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_PARAMETER_NET_REQUIRE;
            }

            l_net = dap_chain_net_by_name(l_net_str);
            if (l_net_str && !l_net) {
                json_object_put(l_jobj_return);
                dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_WRONG_NET, "%s", "Wrong <net name>, use 'net list' "
                                                                         "command to display a list of available networks");
                return DAP_CHAIN_NET_JSON_RPC_WRONG_NET;
            }

            if (l_net){
                json_object *l_jobj_net_name = json_object_new_string(l_net->pub.name);
                json_object *l_jobj_chains = json_object_new_array();
                if (!l_jobj_net_name || !l_jobj_chains) {
                    json_object_put(l_jobj_return);
                    json_object_put(l_jobj_net_name);
                    json_object_put(l_jobj_chains);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_chain_t * l_chain = l_net->pub.chains;
                while (l_chain) {
                    json_object *l_jobj_chain_name = json_object_new_string(l_chain->name);
                    if (!l_jobj_chain_name) {
                        json_object_put(l_jobj_return);
                        json_object_put(l_jobj_net_name);
                        json_object_put(l_jobj_chains);
                        json_object_put(l_jobj_chain_name);
                        dap_json_rpc_allocation_error;
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    json_object_array_add(l_jobj_chains, l_jobj_chain_name);
                    l_chain = l_chain->next;
                }
                json_object_object_add(l_jobj_return, "net", l_jobj_net_name);
                json_object_object_add(l_jobj_return, "chains", l_jobj_chains);
            }else{
                dap_chain_net_item_t * l_net_item, *l_net_item_tmp;
                json_object *l_jobj_networks = json_object_new_array();
                HASH_ITER(hh, s_net_items, l_net_item, l_net_item_tmp){
                    json_object *l_jobj_network = json_object_new_object();
                    json_object *l_jobj_chains = json_object_new_array();
                    l_net = l_net_item->chain_net;
                    json_object *l_jobj_network_name = json_object_new_string(l_net_item->name);
                    if (!l_jobj_network || !l_jobj_chains || !l_jobj_network_name) {
                        json_object_put(l_jobj_return);
                        json_object_put(l_jobj_network);
                        json_object_put(l_jobj_chains);
                        json_object_put(l_jobj_network_name);
                        dap_json_rpc_allocation_error;
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    json_object_object_add(l_jobj_network, "name", l_jobj_network_name);

                    dap_chain_t * l_chain = l_net->pub.chains;
                    while (l_chain) {
                        json_object *l_jobj_chain = json_object_new_object();
                        json_object *l_jobj_chain_name = json_object_new_string(l_chain->name);
                        if (!l_jobj_chain || !l_jobj_chain_name) {
                            json_object_put(l_jobj_return);
                            json_object_put(l_jobj_network);
                            json_object_put(l_jobj_chains);
                            json_object_put(l_jobj_chain);
                            json_object_put(l_jobj_chain_name);
                            dap_json_rpc_allocation_error;
                            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                        }
                        json_object_object_add(l_jobj_chain, "name", l_jobj_chain_name);
                        if (l_chain->default_datum_types_count) {
                            json_object *l_jobj_default_types = json_object_new_array();
                            if (!l_jobj_default_types) {
                                json_object_put(l_jobj_return);
                                json_object_put(l_jobj_chain);
                                json_object_put(l_jobj_chains);
                                json_object_put(l_jobj_network);
                                json_object_put(l_jobj_networks);
                                dap_json_rpc_allocation_error;
                                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                            }
                            for (uint16_t i = 0; i < l_chain->default_datum_types_count; i++) {
                                json_object *l_jobj_type_str = json_object_new_string(s_chain_type_convert_to_string(
                                        l_chain->default_datum_types[i]));
                                if (!l_jobj_type_str) {
                                    json_object_put(l_jobj_return);
                                    json_object_put(l_jobj_default_types);
                                    json_object_put(l_jobj_chain);
                                    json_object_put(l_jobj_chains);
                                    json_object_put(l_jobj_network);
                                    json_object_put(l_jobj_networks);
                                    dap_json_rpc_allocation_error;
                                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                                }
                                json_object_array_add(l_jobj_default_types, l_jobj_type_str);
                            }
                            json_object_object_add(l_jobj_chain, "default_types", l_jobj_default_types);
                        }
                        json_object_array_add(l_jobj_chains, l_jobj_chain);
                        l_chain = l_chain->next;
                    }
                    json_object_object_add(l_jobj_network, "chain", l_jobj_chains);
                    json_object_array_add(l_jobj_networks, l_jobj_network);
                }
                json_object_object_add(l_jobj_return, "networks", l_jobj_networks);
            }
        }else{
            // plug for wrong command arguments
            if (argc > 2) {
                json_object_put(l_jobj_return);
                dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_MANY_ARGUMENT_FOR_COMMAND_NET_LIST, "%s",
                                       "To many arguments for 'net list' command see help");
                return DAP_CHAIN_NET_JSON_RPC_MANY_ARGUMENT_FOR_COMMAND_NET_LIST;
            }

            json_object *l_jobj_networks = json_object_new_array();
            // show list of nets
            dap_chain_net_item_t * l_net_item, *l_net_item_tmp;
            HASH_ITER(hh, s_net_items, l_net_item, l_net_item_tmp){
                json_object *l_jobj_network_name = json_object_new_string(l_net_item->name);
                json_object_array_add(l_jobj_networks, l_jobj_network_name);
            }
            json_object_object_add(l_jobj_return, "networks", l_jobj_networks);
        }
        json_object_array_add(*reply, l_jobj_return);
        return 0;
    }

    int l_ret = dap_chain_node_cli_cmd_values_parse_net_chain_for_json(&arg_index, argc, argv, NULL, &l_net,
                                                                       CHAIN_TYPE_INVALID);

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
                const char *l_prev_day_str = NULL;
                // Read from/to time
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-from", &l_from_str);
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-to", &l_to_str);
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-prev_day", &l_prev_day_str);
                time_t l_ts_now = time(NULL);
                if (l_from_str) {
                    strptime( (char *)l_from_str, c_time_fmt, &l_from_tm );
                    if (l_to_str) {
                        strptime( (char *)l_to_str, c_time_fmt, &l_to_tm );
                    } else { // If not set '-to' - we set up current time
                        localtime_r(&l_ts_now, &l_to_tm);
                    }
                } else if (l_prev_day_str) {
                    localtime_r(&l_ts_now, &l_to_tm);
                    double l_days = strtod(l_prev_day_str, NULL);
                    l_ts_now -= (time_t)(l_days * 86400);
                    localtime_r(&l_ts_now, &l_from_tm );
                } else if ( l_from_str == NULL ) { // If not set '-from' we set up current time minus 60 seconds
                    localtime_r(&l_ts_now, &l_to_tm);
                    l_ts_now -= 86400;
                    localtime_r(&l_ts_now, &l_from_tm );
                }
                // Form timestamps from/to
                time_t l_from_ts = mktime(&l_from_tm);
                time_t l_to_ts = mktime(&l_to_tm);
                // Produce strings
                strftime(l_from_str_new, sizeof(l_from_str_new), c_time_fmt,&l_from_tm );
                strftime(l_to_str_new, sizeof(l_to_str_new), c_time_fmt,&l_to_tm );
                json_object *l_jobj_stats = json_object_new_object();
                if (!l_jobj_stats) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object *l_jobj_from = json_object_new_string(l_from_str_new);
                json_object *l_jobj_to = json_object_new_string(l_to_str_new);
                if (!l_jobj_from || !l_jobj_to) {
                    json_object_put(l_jobj_return);
                    json_object_put(l_jobj_stats);
                    json_object_put(l_jobj_from);
                    json_object_put(l_jobj_to);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_stats, "from", l_jobj_from);
                json_object_object_add(l_jobj_stats, "to", l_jobj_to);
                log_it(L_INFO, "Calc TPS from %s to %s", l_from_str_new, l_to_str_new);
                uint64_t l_tx_count = dap_ledger_count_from_to ( l_net->pub.ledger, l_from_ts * 1000000000, l_to_ts * 1000000000);
                long double l_tpd = l_to_ts == l_from_ts ? 0 :
                                                     (long double) l_tx_count / (long double) ((long double)(l_to_ts - l_from_ts) / 86400);
                char *l_tpd_str = dap_strdup_printf("%.3Lf", l_tpd);
                json_object *l_jobj_tpd = json_object_new_string(l_tpd_str);
                DAP_DELETE(l_tpd_str);
                json_object *l_jobj_total = json_object_new_uint64(l_tx_count);
#ifdef DAP_TPS_TEST
                long double l_tps = l_to_ts == l_from_ts ? 0 :
                                                     (long double) l_tx_count / (long double) (long double)(l_to_ts - l_from_ts);
                char *l_tps_str = dap_strdup_printf("%.3Lf", l_tps);
                json_object *l_jobj_tps = json_object_new_string(l_tps_str);
                DAP_DELETE(l_tps_str);
                if (!l_jobj_tpd || !l_jobj_total || !l_jobj_tps) {
                    json_object_put(l_jobj_tps);
#else
                if (!l_jobj_tpd || !l_jobj_total) {
#endif
                    
                    json_object_put(l_jobj_return);
                    json_object_put(l_jobj_stats);
                    json_object_put(l_jobj_from);
                    json_object_put(l_jobj_to);
                    json_object_put(l_jobj_tpd);
                    json_object_put(l_jobj_total);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
#ifdef DAP_TPS_TEST
                json_object_object_add(l_jobj_stats, "transaction_per_sec", l_jobj_tps);
#endif
                json_object_object_add(l_jobj_stats, "transaction_per_day", l_jobj_tpd);
                json_object_object_add(l_jobj_stats, "total", l_jobj_total);
                json_object_object_add(l_jobj_return, "transaction_statistics", l_jobj_stats);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else {
                json_object_put(l_jobj_return);
                dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETER_COMMAND_STATS, "%s",
                 "Subcommand 'stats' requires one of parameter: tx");
                return DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETER_COMMAND_STATS;
            }
        } else if ( l_go_str){
            json_object *l_jobj_net = json_object_new_string(l_net->pub.name);
            json_object *l_jobj_current_status = json_object_new_string(c_net_states[PVT(l_net)->state]);
            if (!l_jobj_net || !l_jobj_current_status) {
                json_object_put(l_jobj_return);
                json_object_put(l_jobj_net);
                json_object_put(l_jobj_current_status);
                dap_json_rpc_allocation_error;
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            json_object_object_add(l_jobj_return, "net", l_jobj_net);
            json_object_object_add(l_jobj_return, "current", l_jobj_current_status);
            if ( strcmp(l_go_str,"online") == 0 ) {
                json_object *l_jobj_to = json_object_new_string(c_net_states[NET_STATE_ONLINE]);
                if (!l_jobj_to) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_return, "to", l_jobj_to);
                dap_chain_net_state_go_to(l_net, NET_STATE_ONLINE);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp(l_go_str,"offline") == 0 ) {
                json_object *l_jobj_to = json_object_new_string(c_net_states[NET_STATE_OFFLINE]);
                if (!l_jobj_to) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_return, "to", l_jobj_to);
                dap_chain_net_state_go_to(l_net, NET_STATE_OFFLINE);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if (strcmp(l_go_str, "sync") == 0) {
                json_object *l_jobj_to = json_object_new_string("resynchronizing");
                if (!l_jobj_to) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_return, "start", l_jobj_to);
                if (PVT(l_net)->state_target == NET_STATE_ONLINE)
                    dap_chain_net_state_go_to(l_net, NET_STATE_ONLINE);
                else
                    dap_chain_net_state_go_to(l_net, NET_STATE_SYNC_CHAINS);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else {
                json_object_put(l_jobj_return);
                dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETER_COMMAND_GO, "%s",
                                       "Subcommand 'go' requires one of parameters: online, offline, sync\n");
                return DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETER_COMMAND_GO;
            }
        } else if ( l_get_str){
            if ( strcmp(l_get_str,"status") == 0 ) {
                json_object *l_jobj = s_set_reply_text_node_status_json(l_net);
                if (!l_jobj) {
                    json_object_put(l_jobj_return);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_return, "status", l_jobj);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp(l_get_str, "fee") == 0) {
                json_object *l_jobj_fees = json_object_new_object();
                json_object *l_jobj_network_name = json_object_new_string(l_net->pub.name);
                if (!l_jobj_fees || !l_jobj_network_name) {
                    json_object_put(l_jobj_return);
                    json_object_put(l_jobj_fees);
                    json_object_put(l_jobj_network_name);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_fees, "network", l_jobj_network_name);
                // Network fee
                uint256_t l_network_fee = {};
                dap_chain_addr_t l_network_fee_addr = {};
                dap_chain_net_tx_get_fee(l_net->pub.id, &l_network_fee, &l_network_fee_addr);
                const char *l_network_fee_coins_str, *l_network_fee_balance_str =
                    dap_uint256_to_char(l_network_fee, &l_network_fee_coins_str);
                json_object *l_jobj_network =  json_object_new_object();
                json_object *l_jobj_fee_coins = json_object_new_string(l_network_fee_coins_str);
                json_object *l_jobj_fee_balance = json_object_new_string(l_network_fee_balance_str);
                json_object *l_jobj_native_ticker = json_object_new_string(l_net->pub.native_ticker);
                json_object *l_jobj_fee_addr = json_object_new_string(dap_chain_addr_to_str(&l_network_fee_addr));
                if (!l_jobj_network || !l_jobj_fee_coins || !l_jobj_fee_balance || !l_jobj_native_ticker || !l_jobj_fee_addr) {
                    json_object_put(l_jobj_fees);
                    json_object_put(l_jobj_network);
                    json_object_put(l_jobj_fee_coins);
                    json_object_put(l_jobj_fee_balance);
                    json_object_put(l_jobj_native_ticker);
                    json_object_put(l_jobj_fee_addr);
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_network, "coins", l_jobj_fee_coins);
                json_object_object_add(l_jobj_network, "balance", l_jobj_fee_balance);
                json_object_object_add(l_jobj_network, "ticker", l_jobj_native_ticker);
                json_object_object_add(l_jobj_network, "addr", l_jobj_fee_addr);
                json_object_object_add(l_jobj_fees, "network", l_jobj_network);
                //Get validators fee
                json_object *l_jobj_validators = dap_chain_net_srv_stake_get_fee_validators_json(l_net);
                if (!l_jobj_validators) {
                    json_object_put(l_jobj_fees);
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                //Get services fee
                json_object *l_jobj_xchange = dap_chain_net_srv_xchange_print_fee_json(l_net); //Xchaneg fee
                if (!l_jobj_xchange) {
                    json_object_put(l_jobj_validators);
                    json_object_put(l_jobj_fees);
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_fees, "validators", l_jobj_validators);
                json_object_object_add(l_jobj_fees, "xchange", l_jobj_xchange);
                json_object_object_add(l_jobj_return, "fees", l_jobj_fees);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if (strcmp(l_get_str,"id") == 0 ){
                json_object *l_jobj_net_name = json_object_new_string(l_net->pub.name);
                char *l_id_str = dap_strdup_printf("0x%016"DAP_UINT64_FORMAT_X, l_net->pub.id.uint64);
                json_object *l_jobj_id = json_object_new_string(l_id_str);
                DAP_DELETE(l_id_str);
                if (!l_jobj_net_name || !l_jobj_id) {
                    json_object_put(l_jobj_net_name);
                    json_object_put(l_jobj_id);
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_return, "network", l_jobj_net_name);
                json_object_object_add(l_jobj_return, "id", l_jobj_id);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else {
                json_object_put(l_jobj_return);
                dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_UNKNOWN_SUBCOMMANDS,
                                       "Unknown \"%s\" subcommand, net get commands.", l_get_str);
                return DAP_CHAIN_NET_JSON_RPC_UNKNOWN_SUBCOMMANDS;
            }
        } else if ( l_links_str ){
            if ( strcmp(l_links_str,"list") == 0 ) {
                dap_cluster_t *l_net_cluster = dap_cluster_by_mnemonim(l_net->pub.name);
                if (!l_net_cluster) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_CAN_NOT_GET_CLUSTER, "%s", "Failed to obtain a cluster for "
                                                                                       "the specified network.");
                    return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_GET_CLUSTER;
                }
                json_object *l_jobj_links = dap_cluster_get_links_info_json(l_net_cluster);
                if (!l_jobj_links) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_return, "links", l_jobj_links);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp(l_links_str,"add") == 0 ) {
                json_object *l_jobj_not_implemented = json_object_new_string("Not implemented");
                if (!l_jobj_not_implemented) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_return, "add", l_jobj_not_implemented);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp(l_links_str,"del") == 0 ) {
                json_object *l_jobj_not_implemented = json_object_new_string("Not implemented");
                if (!l_jobj_not_implemented) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_return, "del", l_jobj_not_implemented);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            }  else if ( strcmp(l_links_str,"info") == 0 ) {
                json_object *l_jobj_not_implemented = json_object_new_string("Not implemented");
                if (!l_jobj_not_implemented) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_return, "info", l_jobj_not_implemented);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp (l_links_str,"disconnect_all") == 0 ){
                dap_chain_net_stop(l_net);
                json_object *l_jobj_ret = json_object_new_string("Stopped network");
                if (!l_jobj_ret) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_return, "message", l_jobj_ret);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            }else {
                json_object_put(l_jobj_return);
                dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETERS_COMMAND_LINK, "%s",
                                       "Subcommand 'link' requires one of parameters: list, add, del, info, disconnect_all");
                return DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETERS_COMMAND_LINK;
            }

        } else if( l_sync_str) {
            json_object *l_jobj_state_machine = json_object_new_object();
            json_object *l_jobj_requested = json_object_new_string("SYNC_ALL");
            json_object *l_jobj_current = json_object_new_string(c_net_states[PVT(l_net)->state]);
            if (!l_jobj_state_machine || !l_jobj_current) {
                json_object_put(l_jobj_state_machine);
                json_object_put(l_jobj_current);
                json_object_put(l_jobj_return);
                dap_json_rpc_allocation_error;
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            dap_chain_net_sync(l_net);
            if (!l_jobj_requested) {
                json_object_put(l_jobj_state_machine);
                json_object_put(l_jobj_current);
                json_object_put(l_jobj_return);
                dap_json_rpc_allocation_error;
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            json_object_object_add(l_jobj_state_machine, "current", l_jobj_current);
            json_object_object_add(l_jobj_state_machine, "requested", l_jobj_requested);
            json_object_object_add(l_jobj_return, "state_machine", l_jobj_state_machine);
            l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
        } else if (l_ca_str) {
            if (strcmp(l_ca_str, "add") == 0 ) {
                const char *l_cert_string = NULL, *l_hash_string = NULL;

                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cert", &l_cert_string);
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-hash", &l_hash_string);

                if (!l_cert_string && !l_hash_string) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETERS_CA_ADD, "%s",
                                           "One of -cert or -hash parameters is mandatory");
                    return DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETERS_CA_ADD;
                }
                
                char *l_hash_hex_str = NULL;

                if (l_cert_string) {
                    dap_cert_t * l_cert = dap_cert_find_by_name(l_cert_string);
                    if (l_cert == NULL) {
                        json_object_put(l_jobj_return);
                        dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_CAN_NOT_FIND_CERT_CA_ADD,
                                               "Can't find \"%s\" certificate", l_cert_string);
                        return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_FIND_CERT_CA_ADD;
                    }
                    if (l_cert->enc_key == NULL) {
                        json_object_put(l_jobj_return);
                        dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_CAN_NOT_KEY_IN_CERT_CA_ADD,
                                               "No key found in \"%s\" certificate", l_cert_string);
                        return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_KEY_IN_CERT_CA_ADD;
                    }
                    // Get publivc key hash
                    size_t l_pub_key_size = 0;
                    uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(l_cert->enc_key, &l_pub_key_size);;
                    if (l_pub_key == NULL) {
                        json_object_put(l_jobj_return);
                        dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_CAN_SERIALIZE_PUBLIC_KEY_CERT_CA_ADD,
                                               "Can't serialize public key of certificate \"%s\"", l_cert_string);
                        return DAP_CHAIN_NET_JSON_RPC_CAN_SERIALIZE_PUBLIC_KEY_CERT_CA_ADD;
                    }
                    dap_chain_hash_fast_t l_pkey_hash;
                    dap_hash_fast(l_pub_key, l_pub_key_size, &l_pkey_hash);
                    l_hash_hex_str = dap_chain_hash_fast_to_str_new(&l_pkey_hash);
                    //l_hash_base58_str = dap_enc_base58_encode_hash_to_str(&l_pkey_hash);
                } else {
                    l_hash_hex_str = !dap_strncmp(l_hash_string, "0x", 2) || !dap_strncmp(l_hash_string, "0X", 2)
                        ? dap_strdup(l_hash_string)
                        : dap_enc_base58_to_hex_str_from_str(l_hash_string);
                }
                const char c = '1';
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    DAP_DELETE(l_hash_hex_str);
                    json_object_put(l_jobj_return);
                    dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_ADD, "%s",
                                           "Database ACL group not defined for this network");
                    return DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_ADD;
                }
                if( l_hash_hex_str ){
                    l_ret = dap_global_db_set_sync(l_gdb_group_str, l_hash_hex_str, &c, sizeof(c), false );
                    DAP_DELETE(l_gdb_group_str);
                    if (l_ret) {
                        json_object_put(l_jobj_return);
                        dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_CAN_NOT_SAVE_PUBLIC_KEY_IN_DATABASE,
                                               "Can't save public key hash %s in database", l_hash_hex_str);
                        DAP_DELETE(l_hash_hex_str);
                        return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_SAVE_PUBLIC_KEY_IN_DATABASE;
                    } else
                        DAP_DELETE(l_hash_hex_str);
                } else{
                    json_object_put(l_jobj_return);
                    dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_CAN_NOT_SAVE_PUBLIC_KEY_IN_DATABASE, "%s",
                                           "Can't save NULL public key hash in database");
                    return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_SAVE_PUBLIC_KEY_IN_DATABASE;
                }
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if (strcmp(l_ca_str, "list") == 0 ) {
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_LIST, "%s",
                                           "Database ACL group not defined for this network");
                    return DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_LIST;
                }
                size_t l_objs_count;
                dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group_str, &l_objs_count);
                DAP_DELETE(l_gdb_group_str);
                json_object *l_jobj_list_ca = json_object_new_array();
                if (!l_jobj_list_ca) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                for (size_t i = 0; i < l_objs_count; i++) {
                    json_object *l_jobj_key = json_object_new_string(l_objs[i].key);
                    if (!l_jobj_key) {
                        json_object_put(l_jobj_list_ca);
                        json_object_put(l_jobj_return);
                        dap_json_rpc_allocation_error;
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                }
                dap_global_db_objs_delete(l_objs, l_objs_count);
                if (json_object_array_length(l_jobj_list_ca) > 0) {
                    json_object_object_add(l_jobj_return, "ca_list", l_jobj_list_ca);
                } else {
                    json_object_put(l_jobj_list_ca);
                    json_object *l_jobj_str_ret = json_object_new_string("No entries found");
                    if (!l_jobj_list_ca) {
                        json_object_put(l_jobj_return);
                        dap_json_rpc_allocation_error;
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    json_object_object_add(l_jobj_return, "ca_list", l_jobj_str_ret);
                }
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if (strcmp(l_ca_str, "del") == 0 ) {
                const char *l_hash_string = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-hash", &l_hash_string);
                if (!l_hash_string) {
                    dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_UNKNOWN_HASH_CA_DEL, "%s",
                                           "Format should be 'net ca del -hash <hash string>");
                    return DAP_CHAIN_NET_JSON_RPC_UNKNOWN_HASH_CA_DEL;
                }
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_DEL, "%s",
                                           "Database ACL group not defined for this network");
                    return DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_DEL;
                }
                char *l_ret_msg_str = dap_strdup_printf("Certificate %s has been deleted.", l_hash_string);
                json_object *l_jobj_ret = json_object_new_string(l_ret_msg_str);
                DAP_DELETE(l_ret_msg_str);
                if (l_jobj_ret) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                l_ret = dap_global_db_del_sync(l_gdb_group_str, l_hash_string);
                DAP_DELETE(l_gdb_group_str);
                if (l_ret) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_CAN_NOT_FIND_CERT_CA_DEL, "%s",
                                           "Can't find certificate public key hash in database");
                    return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_FIND_CERT_CA_DEL;
                }
                json_object_put(l_jobj_return);
                json_object_array_add(*reply, l_jobj_ret);
                return DAP_CHAIN_NET_JSON_RPC_OK;
            } else {
                dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_INVALID_PARAMETER_COMMAND_CA, "%s",
                                       "Subcommand 'ca' requires one of parameter: add, list, del");
                return DAP_CHAIN_NET_JSON_RPC_INVALID_PARAMETER_COMMAND_CA;
            }
        } else if (l_ledger_str && !strcmp(l_ledger_str, "reload")) {
            int l_return_state = dap_chain_net_stop(l_net);
            sleep(1);   // wait to net going offline
            dap_chain_net_purge(l_net);
            if (l_return_state)
                dap_chain_net_start(l_net);
        } else if (l_list_str && !strcmp(l_list_str, "list")) {
            if (!l_net->pub.keys) {
                json_object_put(l_jobj_return);
                dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_NO_POA_CERTS_FOUND_POA_CERTS, "%s",
                                       "No PoA certs found for this network");
                return DAP_CHAIN_NET_JSON_RPC_NO_POA_CERTS_FOUND_POA_CERTS;
            }
            json_object *l_jobj_pkeys = json_object_new_array();
            if (!l_jobj_pkeys) {
                json_object_put(l_jobj_return);
                dap_json_rpc_allocation_error;
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            for (dap_list_t *it = l_net->pub.keys; it; it = it->next) {
                dap_hash_fast_t l_pkey_hash;
                char l_pkey_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_pkey_get_hash(it->data, &l_pkey_hash);
                dap_chain_hash_fast_to_str(&l_pkey_hash, l_pkey_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                json_object *l_jobj_hash_key = json_object_new_string(l_pkey_hash_str);
                if (!l_jobj_hash_key) {
                    json_object_put(l_jobj_pkeys);
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_array_add(l_jobj_pkeys, l_jobj_hash_key);
            }
            if (json_object_array_length(l_jobj_pkeys) > 0) {
                json_object_object_add(l_jobj_return, "poa_certs", l_jobj_pkeys);
            } else {
                json_object_put(l_jobj_pkeys);
                json_object *l_jobj_info = json_object_new_string("empty");
                if (!l_jobj_info) {
                    json_object_put(l_jobj_return);
                    dap_json_rpc_allocation_error;
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                json_object_object_add(l_jobj_pkeys, "poa_certs", l_jobj_info);
            }
            l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
        } else {
            dap_json_rpc_error_add(DAP_CHAIN_NET_JSON_RPC_UNKNOWN_SUBCOMMANDS, "%s",
                                   "Command 'net' requires one of subcomands: sync, link, go, get, stats, ca, ledger");
            l_ret = DAP_CHAIN_NET_JSON_RPC_UNKNOWN_SUBCOMMANDS;
        }
    } else {
        json_object_put(l_jobj_return);
        l_jobj_return = NULL;
    }
    if (l_jobj_return) {
        json_object_array_add(*json_arr_reply, l_jobj_return);
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

static int callback_compare_prioritity_list(dap_list_t *a_item1, dap_list_t *a_item2)
{
    list_priority   *l_item1 = a_item1->data,
                    *l_item2 = a_item2->data;
    if (!l_item1 || !l_item2) {
        log_it(L_CRITICAL, "Invalid arg");
        return 0;
    }
    return l_item1->prior == l_item2->prior ? 0 : l_item1->prior > l_item2->prior ? 1 : -1;
}

/**
 * @brief dap_chain_net_deinit
 */
void dap_chain_net_deinit()
{
    dap_link_manager_deinit();
    dap_chain_net_balancer_deinit();
    dap_chain_net_item_t *l_current_item, *l_tmp;
    HASH_ITER(hh, s_net_ids, l_current_item, l_tmp)
        HASH_DELETE(hh2, s_net_ids, l_current_item);
    HASH_ITER(hh, s_net_items, l_current_item, l_tmp) {
        dap_chain_net_delete(l_current_item->chain_net);
    }
    dap_http_ban_list_client_deinit();
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
    s_net_states_proc(a_net);
    dap_chain_net_item_t *l_net_item;
    HASH_FIND(hh, s_net_items, a_net->pub.name, strlen(a_net->pub.name), l_net_item);
    if (l_net_item) {
        HASH_DEL(s_net_items, l_net_item);
        HASH_DELETE(hh2, s_net_ids, l_net_item);
        DAP_DELETE(l_net_item);
    }
    DAP_DEL_Z(PVT(a_net)->authorized_nodes_addrs);
    DAP_DEL_Z(PVT(a_net)->node_info);
    if (a_net->pub.ledger) {
        dap_ledger_purge(a_net->pub.ledger, true);
        dap_ledger_handle_free(a_net->pub.ledger);
    }
    DAP_DELETE(a_net);
}

#ifdef DAP_LEDGER_TEST
int dap_chain_net_test_init()
{
    dap_chain_net_id_t l_iddn = {0};
    sscanf("0xFA0", "0x%16"DAP_UINT64_FORMAT_x, &l_iddn.uint64);
    dap_chain_net_t *l_net = s_net_new(&l_iddn, "Snet", "TestCoin", "root");
    
    
    // l_net->pub.id.uint64 = l_iddn.uint64;
    // l_net->pub.native_ticker = "TestCoin";
    // l_net->pub.name = "Snet";

    dap_chain_net_item_t *l_net_item = DAP_NEW_Z(dap_chain_net_item_t);
    dap_strncpy(l_net_item->name, "Snet", DAP_CHAIN_NET_NAME_MAX);
    l_net_item->chain_net = l_net;
    l_net_item->net_id.uint64 = l_net->pub.id.uint64;

    HASH_ADD(hh2, s_net_ids, net_id, sizeof(l_net_item->net_id), l_net_item);

    return 0;
}
#endif


/**
 * @brief load network config settings from cellframe-node.cfg file
 *
 * @param a_net_name const char *: network name, for example "home21-network"
 * @param a_acl_idx currently 0
 * @return int
 */
int s_net_init(const char *a_net_name, uint16_t a_acl_idx)
{
    char *l_cfg_path = dap_strdup_printf("network/%s", a_net_name);
    dap_config_t *l_cfg = dap_config_open(l_cfg_path);
    if (!l_cfg) {
        log_it(L_ERROR,"Can't open default network config %s", l_cfg_path);
        DAP_DEL_Z(l_cfg_path);
        return -1;
    }
    DAP_DELETE(l_cfg_path);

    const char *l_net_name_str = dap_config_get_item_str(l_cfg , "general", "name");
    const char *l_net_id_str = dap_config_get_item_str(l_cfg , "general", "id");
    dap_chain_net_id_t l_net_id;
    if(!l_net_name_str || !l_net_id_str || dap_chain_net_id_parse(l_net_id_str, &l_net_id)) {
        log_it(L_ERROR,"Can't create l_net, can't read name or ID config");
        return -1;
    }

    dap_chain_net_item_t *l_net_item_finded = NULL;
    HASH_FIND_STR(s_net_items, l_net_name_str, l_net_item_finded);
    if (!l_net_item_finded)
        HASH_FIND(hh2, s_net_ids, &l_net_id, sizeof(l_net_id), l_net_item_finded);
    if (l_net_item_finded) {
        log_it(L_ERROR,"Can't create net %s ID %"DAP_UINT64_FORMAT_U", existed net %s ID %"DAP_UINT64_FORMAT_U" has the same name or ID.\n"\
                "Please, fix your configs and restart node",
                l_net_name_str, l_net_id.uint64, l_net_item_finded->name,
                l_net_item_finded->net_id.uint64);
        dap_config_close(l_cfg);
        return -2;
    }

    dap_chain_net_t *l_net = s_net_new(
                                        &l_net_id,
                                        dap_config_get_item_str(l_cfg , "general" , "name" ),
                                        dap_config_get_item_str(l_cfg , "general" , "native_ticker"),
                                        dap_config_get_item_str(l_cfg , "general" , "node-role" )
                                       );
    if(!l_net) {
        log_it(L_ERROR,"Can't create l_net");
        dap_config_close(l_cfg);
        return -1;
    }

    l_net->pub.gdb_groups_prefix = dap_strdup(
                dap_config_get_item_str_default(l_cfg, "general", "gdb_groups_prefix",
                                                dap_config_get_item_str(l_cfg, "general", "name")));
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    l_net_pvt->load_mode = true;
    l_net_pvt->acl_idx = a_acl_idx;
    // Bridged netwoks allowed to send transactions to
    uint16_t l_net_ids_count = 0;
    char **l_bridged_net_ids = dap_config_get_array_str(l_cfg, "general", "bridged_network_ids", &l_net_ids_count);
    for (uint16_t i = 0; i < l_net_ids_count; i++) {
        dap_chain_net_id_t l_id;
        if (dap_chain_net_id_parse(l_bridged_net_ids[i], &l_id) != 0)
            continue;
        l_net->pub.bridged_networks = dap_list_append(l_net->pub.bridged_networks, DAP_DUP(&l_id));
    }

    // Add network to the list
    dap_chain_net_item_t *l_net_item = DAP_NEW_Z(dap_chain_net_item_t);
    if (!l_net_item) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_chain_net_delete(l_net);
        dap_config_close(l_cfg);
        return -4;
    }
    dap_strncpy(l_net_item->name, dap_config_get_item_str(l_cfg, "general", "name"), DAP_CHAIN_NET_NAME_MAX);
    l_net_item->chain_net = l_net;
    l_net_item->net_id.uint64 = l_net->pub.id.uint64;
    
    HASH_ADD_STR(s_net_items, name, l_net_item);
    HASH_ADD(hh2, s_net_ids, net_id, sizeof(l_net_item->net_id), l_net_item);

    char **l_permanent_nodes_addrs = dap_config_get_array_str(l_cfg, "general", "permanent_nodes_addrs", &l_net_pvt->permanent_links_count);
    if (l_net_pvt->permanent_links_count) {
        l_net_pvt->permanent_links = DAP_NEW_Z_COUNT(dap_link_info_t *, l_net_pvt->permanent_links_count);
        if (!l_net_pvt->permanent_links) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            dap_chain_net_delete(l_net);
            dap_config_close(l_cfg);
            return -4;
        }
    }
    for (uint16_t i = 0; i < l_net_pvt->permanent_links_count; ++i) {
        l_net_pvt->permanent_links[i] = DAP_NEW_Z(dap_link_info_t);
        if (!l_net_pvt->permanent_links[i]) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            dap_chain_net_delete(l_net);
            dap_config_close(l_cfg);
            return -4;
        }
        if (dap_stream_node_addr_from_str(&l_net_pvt->permanent_links[i]->node_addr, l_permanent_nodes_addrs[i])) {
            log_it(L_ERROR, "Incorrect format of node address \"%s\", fix net config and restart node", l_permanent_nodes_addrs[i]);
            dap_chain_net_delete(l_net);
            dap_config_close(l_cfg);
            return -16;
        }
    }
    uint16_t l_permalink_hosts_count = 0, i, e;
    char **l_permanent_links_hosts = dap_config_get_array_str(l_cfg, "general", "permanent_nodes_hosts", &l_permalink_hosts_count);
    for (i = 0, e = 0; i < dap_min(l_permalink_hosts_count, l_net_pvt->permanent_links_count); ++i) {
        char l_host[DAP_HOSTADDR_STRLEN + 1] = { '\0' }; uint16_t l_port = 0;
        struct sockaddr_storage l_saddr;
        if ( dap_net_parse_config_address(l_permanent_links_hosts[i], l_host, &l_port, NULL, NULL) < 0
            || dap_net_resolve_host(l_host, dap_itoa(l_port), false, &l_saddr, NULL) < 0 )
        {
            log_it(L_ERROR, "Incorrect address \"%s\", fix \"%s\" network config"
                            "or check internet connection and restart node",
                            a_net_name, l_permanent_links_hosts[i]);
            ++e;
            continue;
        }
        l_net_pvt->permanent_links[i]->uplink_port = l_port;
        dap_strncpy(l_net_pvt->permanent_links[i]->uplink_addr, l_host, DAP_HOSTADDR_STRLEN);
    }
    if ( i && (e == i) ) {
        log_it(L_ERROR, "%d / %d permanent links are invalid or can't be accessed, fix \"%s\""
                        "network config or check internet connection and restart node",
                        e, i, a_net_name);
        dap_chain_net_delete(l_net);
        dap_config_close(l_cfg);
        return -16;
    }

    char **l_authorized_nodes_addrs = dap_config_get_array_str(l_cfg, "general", "authorized_nodes_addrs", &l_net_pvt->authorized_nodes_count);
    if (!l_net_pvt->authorized_nodes_count)
        log_it(L_WARNING, "Can't read PoA nodes addresses");
    else
        l_net_pvt->authorized_nodes_addrs = DAP_NEW_Z_COUNT(dap_chain_node_addr_t, l_net_pvt->authorized_nodes_count);
    for (i = 0; i < l_net_pvt->authorized_nodes_count; ++i) {
        dap_chain_node_addr_t l_addr;
        if (dap_stream_node_addr_from_str(&l_addr, l_authorized_nodes_addrs[i])) {
            log_it(L_ERROR, "Incorrect format of node address \"%s\", fix net config and restart node", l_authorized_nodes_addrs[i]);
            dap_chain_net_delete(l_net);
            dap_config_close(l_cfg);
            return -17;
        }
        l_net_pvt->authorized_nodes_addrs[i].uint64 = l_addr.uint64;
    }
    char **l_seed_nodes_hosts = dap_config_get_array_str(l_cfg, "general", "seed_nodes_hosts", &l_net_pvt->seed_nodes_count);
    if (!l_net_pvt->seed_nodes_count)
         l_seed_nodes_hosts  = dap_config_get_array_str(l_cfg, "general", "bootstrap_hosts", &l_net_pvt->seed_nodes_count);
    if (!l_net_pvt->seed_nodes_count)
        log_it(L_WARNING, "Can't read seed nodes addresses, work with local balancer only");
    else if (!(l_net_pvt->seed_nodes_info = DAP_NEW_Z_COUNT(struct request_link_info *, l_net_pvt->seed_nodes_count))) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_chain_net_delete(l_net);
        dap_config_close(l_cfg);
        return -4;
    }
    for (i = 0, e = 0; i < l_net_pvt->seed_nodes_count; ++i) {
        char l_host[DAP_HOSTADDR_STRLEN + 1] = { '\0' }; uint16_t l_port = 0;
        struct sockaddr_storage l_saddr;
        if ( dap_net_parse_config_address(l_seed_nodes_hosts[i], l_host, &l_port, NULL, NULL) < 0
            || dap_net_resolve_host(l_host, dap_itoa(l_port), false, &l_saddr, NULL) < 0)
        {
            log_it(L_ERROR, "Incorrect address \"%s\", fix \"%s\" network config"
                            "or check internet connection and restart node",
                            a_net_name, l_seed_nodes_hosts[i]);
            ++e;
            continue;
        }
        l_net_pvt->seed_nodes_info[i] = DAP_NEW_Z(struct request_link_info);
        if (!l_net_pvt->seed_nodes_info[i]) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            dap_chain_net_delete(l_net);
            dap_config_close(l_cfg);
            return -4;
        }
        l_net_pvt->seed_nodes_info[i]->port = l_port;
        dap_strncpy(l_net_pvt->seed_nodes_info[i]->addr, l_host, DAP_HOSTADDR_STRLEN);
    }
    if ( i && (e == i) ) {
        log_it(L_ERROR, "%d / %d seed links are invalid or can't be accessed, fix \"%s\""
                        "network config or check internet connection and restart node",
                        e, i, a_net_name);
        dap_chain_net_delete(l_net);
        dap_config_close(l_cfg);
        return -16;
    }

    /* *** Chains init by configs *** */
    char * l_chains_path = dap_strdup_printf("%s/network/%s", dap_config_path(), l_net->pub.name);
    DIR * l_chains_dir = opendir(l_chains_path);
    DAP_DEL_Z(l_chains_path);
    if (!l_chains_dir) {
        log_it(L_ERROR, "Can't find any chains for network %s", l_net->pub.name);
        dap_chain_net_delete(l_net);
        return -7;
    }
    // for sequential loading chains
    dap_list_t *l_prior_list = NULL;

    struct dirent * l_dir_entry;
    while ( (l_dir_entry = readdir(l_chains_dir) )!= NULL ){
        if (l_dir_entry->d_name[0]=='\0')
            continue;
        char *l_entry_name = dap_strdup(l_dir_entry->d_name);
        if (!l_entry_name) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            dap_chain_net_delete(l_net);
            closedir(l_chains_dir);
            return -8;
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
                        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                        DAP_DELETE(l_entry_name);
                        dap_config_close(l_cfg_new);
                        closedir(l_chains_dir);
                        dap_chain_net_delete(l_net);
                        return -9;
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
        DAP_DELETE(l_entry_name);
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
                    return -10;
                }
                if (!dap_strcmp(l_chain->name, l_chain02->name)) {
                    log_it(L_ERROR, "Your network %s has chains with duplicate names %s: chain01 id = 0x%"DAP_UINT64_FORMAT_U", chain02 id = 0x%"DAP_UINT64_FORMAT_U"",l_chain->net_name,
                           l_chain->name, l_chain->id.uint64, l_chain02->id.uint64);
                    log_it(L_ERROR, "Please, fix your configs and restart node");
                    return -11;
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
    // init LEDGER model
    l_net->pub.ledger = dap_ledger_create(l_net, l_ledger_flags);

    for (dap_chain_t *l_chain = l_net->pub.chains; l_chain; l_chain = l_chain->next) {
        if (!l_chain->callback_get_poa_certs)
            continue;
        l_net->pub.keys = l_chain->callback_get_poa_certs(l_chain, NULL, NULL);
        if (l_net->pub.keys)
            break;
    }
    if (!l_net->pub.keys)
        log_it(L_WARNING, "PoA certificates for net %s not found", l_net->pub.name);

    // Decrees initializing
    dap_chain_net_decree_init(l_net);

    l_net->pub.config = l_cfg;
    return 0;
}

bool s_net_load(void *a_arg)
{
    dap_chain_net_t *l_net = a_arg;
    int l_err_code = 0;

    if (!l_net->pub.config) {
        log_it(L_ERROR,"Can't open default network config");
        l_err_code = -1;
        goto ret;
    }

    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);

    // reload ledger cache at once
    if (s_chain_net_reload_ledger_cache_once(l_net)) {
        log_it(L_WARNING,"Start one time ledger cache reloading");
        dap_ledger_purge(l_net->pub.ledger, false);
        dap_chain_net_srv_stake_purge(l_net);
    } else
        dap_chain_net_srv_stake_load_cache(l_net);

    // load chains
    dap_chain_t *l_chain = l_net->pub.chains;
    while (l_chain) {
        l_net->pub.fee_value = uint256_0;
        l_net->pub.fee_addr = c_dap_chain_addr_blank;
        if (!dap_chain_load_all(l_chain)) {
            log_it (L_NOTICE, "Loaded chain files");
            if ( DAP_CHAIN_PVT(l_chain)->need_reorder ) {
                log_it(L_DAP, "Reordering chain files for chain %s", l_chain->name);
                if (l_chain->callback_atom_add_from_treshold) {
                    while (l_chain->callback_atom_add_from_treshold(l_chain, NULL))
                        log_it(L_DEBUG, "Added atom from treshold");
                }
                dap_chain_save_all(l_chain);
                DAP_CHAIN_PVT(l_chain)->need_reorder = false;
                if (l_chain->callback_purge) {
                    dap_chain_net_decree_purge(l_net);
                    l_chain->callback_purge(l_chain);
                    dap_ledger_purge(l_net->pub.ledger, false);
                    l_net->pub.fee_value = uint256_0;
                    l_net->pub.fee_addr = c_dap_chain_addr_blank;
                    dap_chain_load_all(l_chain);
                } else
                    log_it(L_WARNING, "No purge callback for chain %s, can't reload it with correct order", l_chain->name);
            }
        } else {
            //dap_chain_save_all( l_chain );
            log_it (L_NOTICE, "Initialized chain files");
        }
        l_chain->atom_num_last = 0;
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
            dap_chain_t *l_chain = dap_chain_find_by_id(l_net->pub.id, l_chain_id);
            if (l_chain)
                l_chain->is_datum_pool_proc = true;
            log_it(L_INFO,"Root node role established");
        } break;
        case NODE_ROLE_CELL_MASTER:
        case NODE_ROLE_MASTER:{
            uint16_t l_proc_chains_count=0;
            char **l_proc_chains = dap_config_get_array_str(l_net->pub.config, "role-master", "proc_chains", &l_proc_chains_count);
            for (size_t i = 0; i< l_proc_chains_count ; i++) {
                dap_chain_id_t l_chain_id = {};
                if (dap_chain_id_parse(l_proc_chains[i], &l_chain_id) == 0) {
                    dap_chain_t *l_chain = dap_chain_find_by_id(l_net->pub.id, l_chain_id );
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
    
    l_net_pvt->load_mode = false;

    l_net_pvt->balancer_type = dap_config_get_item_bool_default(l_net->pub.config, "general", "use_dns_links", false);

    // Init GlobalDB clusters for mempool, service and nodes (with aliases)
    char *l_gdb_groups_mask = NULL;
    DL_FOREACH(l_net->pub.chains, l_chain) {
        // Personal chain mempool cluster for each chain
        l_gdb_groups_mask = dap_strdup_printf("%s.chain-%s.mempool", l_net->pub.gdb_groups_prefix, l_chain->name);
        dap_global_db_cluster_t *l_cluster = dap_global_db_cluster_add(
                                                    dap_global_db_instance_get_default(),
                                                    l_net->pub.name, dap_guuid_compose(l_net->pub.id.uint64, 0),
                                                    l_gdb_groups_mask, DAP_CHAIN_NET_MEMPOOL_TTL, true,
                                                    DAP_GDB_MEMBER_ROLE_USER,
                                                    DAP_CLUSTER_TYPE_EMBEDDED);
        if (!l_cluster) {
            log_it(L_ERROR, "Can't initialize mempool cluster for network %s", l_net->pub.name);
            l_err_code = -2;
            goto ret;
        }
        dap_chain_net_add_auth_nodes_to_cluster(l_net, l_cluster);
        DAP_DELETE(l_gdb_groups_mask);
        if (l_net->pub.chains == l_chain)   // Pointer for first mempool cluster in global double-linked list of clusters
            l_net_pvt->mempool_clusters = l_cluster;
    }
    // Service orders cluster
    l_gdb_groups_mask = dap_strdup_printf("%s.service.orders", l_net->pub.gdb_groups_prefix);
    l_net_pvt->orders_cluster = dap_global_db_cluster_add(dap_global_db_instance_get_default(),
                                                          l_net->pub.name, dap_guuid_compose(l_net->pub.id.uint64, 0),
                                                          l_gdb_groups_mask, 0, true,
                                                          DAP_GDB_MEMBER_ROLE_GUEST,
                                                          DAP_CLUSTER_TYPE_EMBEDDED);
    if (!l_net_pvt->orders_cluster) {
        log_it(L_ERROR, "Can't initialize orders cluster for network %s", l_net->pub.name);
        goto ret;
    }
    dap_chain_net_add_auth_nodes_to_cluster(l_net, l_net_pvt->orders_cluster);
    DAP_DELETE(l_gdb_groups_mask);
    // node states cluster
    l_gdb_groups_mask = dap_strdup_printf("%s.nodes.states", l_net->pub.gdb_groups_prefix);
    dap_global_db_cluster_add(
        dap_global_db_instance_get_default(),
        l_net->pub.name, dap_guuid_compose(l_net->pub.id.uint64, 0),
        l_gdb_groups_mask, 0, true,
        DAP_GDB_MEMBER_ROLE_USER,
        DAP_CLUSTER_TYPE_EMBEDDED);
    DAP_DELETE(l_gdb_groups_mask);
    // Nodes and its aliases cluster
    l_net->pub.gdb_nodes = dap_strdup_printf("%s.nodes.list",l_net->pub.gdb_groups_prefix);
    l_net_pvt->nodes_cluster = dap_global_db_cluster_add(dap_global_db_instance_get_default(),
                                                         l_net->pub.name, dap_guuid_compose(l_net->pub.id.uint64, 0),
                                                         l_net->pub.gdb_nodes, 0, true,
                                                         DAP_GDB_MEMBER_ROLE_GUEST,
                                                         DAP_CLUSTER_TYPE_EMBEDDED);
    if (!l_net_pvt->nodes_cluster) {
        log_it(L_ERROR, "Can't initialize nodes cluster for network %s", l_net->pub.name);
        l_err_code = -3;
        goto ret;
    }
    dap_chain_net_add_auth_nodes_to_cluster(l_net, l_net_pvt->nodes_cluster);
    dap_chain_net_add_nodelist_notify_callback(l_net, s_nodelist_change_notify, l_net);

    if (dap_link_manager_add_net(l_net->pub.id.uint64, l_net_pvt->nodes_cluster->links_cluster,
                                dap_config_get_item_uint16_default(l_net->pub.config,
                                                                   "general", "links_required", 3))) {
        log_it(L_WARNING, "Can't add net %s to link manager", l_net->pub.name);
    }

    DL_FOREACH(l_net->pub.chains, l_chain)
        if (l_chain->callback_created)
            l_chain->callback_created(l_chain, l_net->pub.config);

     if ( dap_config_get_item_bool_default(g_config, "server", "enabled", false) ) {
        if ( !l_net_pvt->node_info->ext_port ) {
            char l_host[DAP_HOSTADDR_STRLEN + 1] = { '\0' };
            uint16_t l_ext_port = 0;
            const char *l_ext_addr = dap_config_get_item_str_default(g_config, "server", "ext_address", NULL);
            if (!l_ext_addr) {
                log_it(L_INFO, "External address is not set, will be detected automatically");
            } else {
                struct sockaddr_storage l_saddr = { };
                if ( 0 > dap_net_parse_config_address(l_ext_addr, l_host, &l_ext_port, &l_saddr, NULL) )
                    log_it(L_ERROR, "Invalid server address \"%s\", fix config and restart node", l_ext_addr);
                else {
                    uint8_t l_hostlen = dap_strlen(l_host);
                    l_net_pvt->node_info->ext_port = l_ext_port;
                    l_net_pvt->node_info->ext_host_len = dap_strncpy(l_net_pvt->node_info->ext_host, l_host, l_hostlen) - l_net_pvt->node_info->ext_host;
                }
            }
            if ( !l_net_pvt->node_info->ext_port ) {
                char **l_listening = dap_config_get_array_str(g_config, "server", DAP_CFG_PARAM_LISTEN_ADDRS, NULL);
                l_net_pvt->node_info->ext_port =
                    ( l_listening && dap_net_parse_config_address(*l_listening, NULL, &l_ext_port, NULL, NULL) > 0 && l_ext_port )
                        ? l_ext_port
                        : dap_config_get_item_int16_default(g_config, "server", DAP_CFG_PARAM_LEGACY_PORT, 8079); // TODO: default port?
            }
        } // otherwise, we're in seed list - seed config predominates server config thus disambiguating the settings
        
        if (l_net_pvt->node_info->ext_host_len) {
            log_it(L_INFO, "Server is configured with external address %s : %u",
               l_net_pvt->node_info->ext_host, l_net_pvt->node_info->ext_port);
        }
    } else
        log_it(L_INFO, "Server is disabled");

    l_net_pvt->node_info->address.uint64 = g_node_addr.uint64;

    log_it(L_NOTICE, "Net load information: node_addr " NODE_ADDR_FP_STR ", seed links %u, cell_id 0x%016"DAP_UINT64_FORMAT_X,
           NODE_ADDR_FP_ARGS_S(g_node_addr),
           l_net_pvt->seed_nodes_count,
           l_net_pvt->node_info->cell_id.uint64);

    // TODO rework alias concept
    const char * l_node_addr_type = dap_config_get_item_str_default(l_net->pub.config ,
                                                                    "general", "node_addr_type", "auto");
    if (!dap_strcmp(l_node_addr_type, "static")) {
        const char *l_node_alias_str = dap_config_get_item_str_default(l_net->pub.config, "general", "node-addr",
                                                                       dap_config_get_item_str(l_net->pub.config,
                                                                                               "general", "node-alias"));
        if (l_node_alias_str) {
            dap_stream_node_addr_t *l_alias_addr = dap_chain_node_alias_find(l_net, l_node_alias_str);
            if (!l_alias_addr)
                dap_chain_node_alias_register(l_net, l_node_alias_str, &g_node_addr);
        } else
            log_it(L_ERROR, "Can't read alias for node address from config");

    } else if (dap_strcmp(l_node_addr_type, "auto"))
        log_it(L_WARNING, "Unknown node address type will be defalted to 'auto'");

    l_net_pvt->sync_context.sync_idle_time = dap_config_get_item_uint32_default(g_config, "chain", "sync_idle_time", 60);
    dap_proc_thread_timer_add(NULL, s_sync_timer_callback, l_net, 1000);

    log_it(L_INFO, "Chain network \"%s\" initialized", l_net->pub.name);
ret:
    if (l_err_code)
        log_it(L_ERROR, "Loading chains of net %s finished with (%d) error code.", l_net->pub.name, l_err_code);
    pthread_mutex_lock(&s_net_cond_lock);
    s_net_loading_count--;
    pthread_cond_signal(&s_net_cond);
    pthread_mutex_unlock(&s_net_cond_lock);
    return false;
}

static const uint64_t s_fork_sync_step = 20; // TODO get it from config

static void s_ch_in_pkt_callback(dap_stream_ch_t *a_ch, uint8_t a_type, const void *a_data, size_t a_data_size, void *a_arg)
{
    debug_if(s_debug_more, L_DEBUG, "Got IN sync packet type %hhu size %zu from addr " NODE_ADDR_FP_STR,
                                                           a_type, a_data_size, NODE_ADDR_FP_ARGS_S(a_ch->stream->node));
    dap_chain_net_t *l_net = a_arg;
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    if (l_net_pvt->state == NET_STATE_LINKS_ESTABLISHED)
        l_net_pvt->state = NET_STATE_SYNC_CHAINS;

    switch (a_type) {
    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_SUMMARY:
    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS:
    case DAP_CHAIN_CH_PKT_TYPE_CHAIN:
    case DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN:
        // TODO sync state & address checking
        break;
    default:
        break;
    }

    switch (a_type) {
    case DAP_CHAIN_CH_PKT_TYPE_ERROR:
        l_net_pvt->sync_context.state = SYNC_STATE_ERROR;
        return;

    case DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN:
        l_net_pvt->sync_context.state = SYNC_STATE_SYNCED;
        return;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS: {
        dap_chain_ch_miss_info_t *l_miss_info = (dap_chain_ch_miss_info_t *)(((dap_chain_ch_pkt_t *)(a_data))->data);
        if (!dap_hash_fast_compare(&l_miss_info->missed_hash, &l_net_pvt->sync_context.requested_atom_hash)) {
            char l_missed_hash_str[DAP_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_miss_info->missed_hash, l_missed_hash_str, DAP_HASH_FAST_STR_SIZE);
            log_it(L_WARNING, "Get irrelevant chain sync MISSED packet with missed hash %s, but requested hash is %s",
                                                                        l_missed_hash_str,
                                                                        dap_hash_fast_to_str_static(&l_net_pvt->sync_context.requested_atom_hash));
            dap_stream_ch_write_error_unsafe(a_ch, l_net->pub.id,
                                             l_net_pvt->sync_context.cur_chain->id,
                                             l_net_pvt->sync_context.cur_cell
                                             ? l_net_pvt->sync_context.cur_cell->id
                                             : c_dap_chain_cell_id_null,
                                             DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            return;
        }
        dap_chain_atom_iter_t *l_iter = l_net_pvt->sync_context.cur_chain->callback_atom_iter_create(
                                                                            l_net_pvt->sync_context.cur_chain,
                                                                            l_net_pvt->sync_context.cur_cell
                                                                            ? l_net_pvt->sync_context.cur_cell->id
                                                                            : c_dap_chain_cell_id_null,
                                                                            NULL);
        if (!l_iter) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            dap_stream_ch_write_error_unsafe(a_ch, l_net->pub.id,
                                             l_net_pvt->sync_context.cur_chain->id,
                                             l_net_pvt->sync_context.cur_cell
                                             ? l_net_pvt->sync_context.cur_cell->id
                                             : c_dap_chain_cell_id_null,
                                             DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY);
            return;
        }
        dap_chain_atom_ptr_t l_atom = l_net_pvt->sync_context.cur_chain->callback_atom_find_by_hash(l_iter, &l_miss_info->last_hash, NULL);
        if (l_atom && l_iter->cur_num == l_miss_info->last_num) {       // We already have this subchain in our chain
            l_net_pvt->sync_context.state = SYNC_STATE_SYNCED;
            return;
        }
        dap_chain_ch_sync_request_t l_request = {};
        l_request.num_from = l_net_pvt->sync_context.requested_atom_num > s_fork_sync_step
                            ? l_net_pvt->sync_context.requested_atom_num - s_fork_sync_step
                            : 0;
        if (l_request.num_from) {
            l_atom = l_net_pvt->sync_context.cur_chain->callback_atom_get_by_num(l_iter, l_request.num_from);
            assert(l_atom);
            l_request.hash_from = *l_iter->cur_hash;
        }
        l_net_pvt->sync_context.cur_chain->callback_atom_iter_delete(l_iter);
        debug_if(s_debug_more, L_INFO, "Send sync request to node " NODE_ADDR_FP_STR
                                        " for net %s and chain %s, hash from %s, num from %" DAP_UINT64_FORMAT_U,
                                                        NODE_ADDR_FP_ARGS_S(l_net_pvt->sync_context.current_link),
                                                        l_net->pub.name, l_net_pvt->sync_context.cur_chain->name,
                                                        dap_hash_fast_to_str_static(&l_request.hash_from), l_request.num_from);
        dap_chain_ch_pkt_write_unsafe(a_ch,
                                      DAP_CHAIN_CH_PKT_TYPE_CHAIN_REQ,
                                      l_net->pub.id,
                                      l_net_pvt->sync_context.cur_chain->id,
                                      l_net_pvt->sync_context.cur_cell
                                      ? l_net_pvt->sync_context.cur_cell->id
                                      : c_dap_chain_cell_id_null,
                                      &l_request,
                                      sizeof(l_request),
                                      DAP_CHAIN_CH_PKT_VERSION_CURRENT);
        l_net_pvt->sync_context.requested_atom_hash = l_request.hash_from;
        l_net_pvt->sync_context.requested_atom_num = l_request.num_from;
    }
    default:
        break;
    }
    l_net_pvt->sync_context.stage_last_activity = dap_time_now();
}

static void s_ch_out_pkt_callback(dap_stream_ch_t *a_ch, uint8_t a_type, const void *a_data, size_t a_data_size, void *a_arg)
{
    debug_if(s_debug_more, L_DEBUG, "Sent OUT sync packet type %hhu size %zu to addr " NODE_ADDR_FP_STR,
                                                           a_type, a_data_size, NODE_ADDR_FP_ARGS_S(a_ch->stream->node));
    dap_chain_net_t *l_net = a_arg;
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    switch (a_type) {
    case DAP_CHAIN_CH_PKT_TYPE_ERROR:
        l_net_pvt->sync_context.state = SYNC_STATE_ERROR;
        break;
    default:
        break;
    }
    l_net_pvt->sync_context.stage_last_activity = dap_time_now();
}

static void s_sync_timer_callback(void *a_arg)
{
    dap_chain_net_t *l_net = a_arg;
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    if (l_net_pvt->state_target == NET_STATE_OFFLINE)
        return;
    if (l_net_pvt->sync_context.last_state == SYNC_STATE_SYNCED || l_net_pvt->sync_context.last_state == SYNC_STATE_ERROR ||
            (l_net_pvt->sync_context.last_state == SYNC_STATE_IDLE && l_net_pvt->state != NET_STATE_ONLINE) ||
            dap_time_now() - l_net_pvt->sync_context.stage_last_activity > l_net_pvt->sync_context.sync_idle_time) {
        if (!l_net_pvt->sync_context.cur_chain || l_net_pvt->sync_context.last_state == SYNC_STATE_ERROR) {
            // Go no next link
            dap_cluster_t *l_cluster = dap_cluster_by_mnemonim(l_net->pub.name);
            if (!dap_stream_node_addr_is_blank(&l_net_pvt->sync_context.current_link)) {
                dap_stream_ch_del_notifier(&l_net_pvt->sync_context.current_link, DAP_CHAIN_CH_ID,
                                           DAP_STREAM_PKT_DIR_IN, s_ch_in_pkt_callback, l_net);
                dap_stream_ch_del_notifier(&l_net_pvt->sync_context.current_link, DAP_CHAIN_CH_ID,
                                           DAP_STREAM_PKT_DIR_OUT, s_ch_out_pkt_callback, l_net);
            }
            l_net_pvt->sync_context.current_link = dap_cluster_get_random_link(l_cluster);
            if (dap_stream_node_addr_is_blank(&l_net_pvt->sync_context.current_link))
                return;     // No links in cluster
            l_net_pvt->sync_context.cur_chain = l_net->pub.chains;
            if (!l_net_pvt->sync_context.cur_chain) {
                log_it(L_ERROR, "No chains in net %s", l_net->pub.name);
                return;
            }
            dap_stream_ch_add_notifier(&l_net_pvt->sync_context.current_link, DAP_CHAIN_CH_ID,
                                       DAP_STREAM_PKT_DIR_IN, s_ch_in_pkt_callback, l_net);
            dap_stream_ch_add_notifier(&l_net_pvt->sync_context.current_link, DAP_CHAIN_CH_ID,
                                       DAP_STREAM_PKT_DIR_OUT, s_ch_out_pkt_callback, l_net);
            l_net_pvt->sync_context.state = l_net_pvt->sync_context.last_state = SYNC_STATE_WAITING;
        } else {
            l_net_pvt->sync_context.cur_chain = l_net_pvt->sync_context.cur_chain->next;
            log_it(L_DEBUG, "[%s:%d] Go to next chain %p", __FUNCTION__, __LINE__, l_net_pvt->sync_context.cur_chain);
            if (!l_net_pvt->sync_context.cur_chain) {
                if (l_net_pvt->sync_context.last_state == SYNC_STATE_SYNCED) {
                    l_net_pvt->state = NET_STATE_ONLINE;
                    l_net_pvt->sync_context.state = l_net_pvt->sync_context.last_state = SYNC_STATE_IDLE;
                    s_net_states_proc(l_net);
                } else
                    l_net_pvt->sync_context.state = l_net_pvt->sync_context.last_state = SYNC_STATE_WAITING;
                return;
            }
        }
        // TODO make correct working with cells
        assert(l_net_pvt->sync_context.cur_chain);
        if (l_net_pvt->sync_context.cur_chain->callback_load_from_gdb) {
            // This type of chain is GDB based and not synced by chains protocol
            l_net_pvt->sync_context.cur_chain = l_net_pvt->sync_context.cur_chain->next;
            log_it(L_DEBUG, "[%s:%d] Go to next chain %p", __FUNCTION__, __LINE__, l_net_pvt->sync_context.cur_chain);
            l_net_pvt->sync_context.last_state = SYNC_STATE_SYNCED;
            return;
        }
        l_net_pvt->sync_context.cur_cell = l_net_pvt->sync_context.cur_chain->cells;
        l_net_pvt->sync_context.state = l_net_pvt->sync_context.last_state = SYNC_STATE_WAITING;
        dap_chain_ch_sync_request_t l_request = {};
        uint64_t l_last_num = 0;
        if (!dap_chain_get_atom_last_hash_num(l_net_pvt->sync_context.cur_chain,
                                              l_net_pvt->sync_context.cur_cell
                                              ? l_net_pvt->sync_context.cur_cell->id
                                              : c_dap_chain_cell_id_null,
                                              &l_request.hash_from,
                                              &l_last_num)) {
            log_it(L_ERROR, "Can't get last atom hash and number for chain %s with net %s", l_net_pvt->sync_context.cur_chain->name,
                                                                                            l_net->pub.name);
            return;
        }
        l_request.num_from = l_last_num;
        dap_chain_ch_pkt_t *l_chain_pkt = dap_chain_ch_pkt_new(l_net->pub.id, l_net_pvt->sync_context.cur_chain->id,
                                                               l_net_pvt->sync_context.cur_cell ? l_net_pvt->sync_context.cur_cell->id : c_dap_chain_cell_id_null,
                                                               &l_request, sizeof(l_request), DAP_CHAIN_CH_PKT_VERSION_CURRENT);
        if (!l_chain_pkt) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return;
        }
        log_it(L_INFO, "Start synchronization process with " NODE_ADDR_FP_STR
                        " for net %s and chain %s, last hash %s, last num %" DAP_UINT64_FORMAT_U,
                                                        NODE_ADDR_FP_ARGS_S(l_net_pvt->sync_context.current_link),
                                                        l_net->pub.name, l_net_pvt->sync_context.cur_chain->name,
                                                        dap_hash_fast_to_str_static(&l_request.hash_from), l_last_num);
        dap_stream_ch_pkt_send_by_addr(&l_net_pvt->sync_context.current_link, DAP_CHAIN_CH_ID,
                                       DAP_CHAIN_CH_PKT_TYPE_CHAIN_REQ, l_chain_pkt,
                                       dap_chain_ch_pkt_get_size(l_chain_pkt));
        l_net_pvt->sync_context.requested_atom_hash = l_request.hash_from;
        l_net_pvt->sync_context.requested_atom_num = l_request.num_from;
        DAP_DELETE(l_chain_pkt);
    }
    if (l_net_pvt->sync_context.last_state != SYNC_STATE_IDLE &&
            l_net_pvt->sync_context.last_state != l_net_pvt->sync_context.state)
        l_net_pvt->sync_context.last_state = l_net_pvt->sync_context.state;
}

/**
 * @brief try net to go online
 *
 * @param a_net dap_chain_net_t *: network 
 * @return int
 *
 **/
static int s_net_try_online(dap_chain_net_t *a_net)
{
    
    dap_chain_net_t *l_net = a_net;
    
    dap_chain_net_pvt_t * l_net_pvt = PVT(l_net);
    dap_chain_net_state_t l_target_state = NET_STATE_OFFLINE;
    
    if (dap_config_get_item_bool_default(g_config ,"general", "auto_online", false))
    {
        l_target_state = NET_STATE_ONLINE;
    }
    
    if (l_target_state != l_net_pvt->state_target)
    {   
        dap_chain_net_state_go_to(l_net, l_target_state);
        log_it(L_INFO, "Network \"%s\" goes online",l_net->pub.name);
    }
    
    return 0;
}

/**
 * @brief
 * change all network states according to auto-online settings
 */
void dap_chain_net_try_online_all() {
    int32_t l_ret = 0;

    if(!HASH_COUNT(s_net_items)){
        log_it(L_ERROR, "Can't find any nets");
        return;
    }
    dap_chain_net_item_t *l_net_items_current = NULL, *l_net_items_tmp = NULL;
    HASH_ITER(hh, s_net_items, l_net_items_current, l_net_items_tmp) {
        if( (l_ret = s_net_try_online(l_net_items_current->chain_net)) ) {
            log_it(L_ERROR, "Can't try online state for net %s.  Finished with (%d) error code.", l_net_items_current->name, l_ret);
        }
    }
}


dap_global_db_cluster_t *dap_chain_net_get_mempool_cluster(dap_chain_t *a_chain)
{
    dap_return_val_if_fail(a_chain, NULL);
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net) {
        log_it(L_ERROR, "Invalid chain specified for mempool cluster search");
        return NULL;
    }
    dap_global_db_cluster_t *l_mempool = PVT(l_net)->mempool_clusters;
    dap_chain_t *l_chain;
    DL_FOREACH(l_net->pub.chains, l_chain) {
        if (l_chain == a_chain)
            return l_mempool;
        assert(l_mempool);
        l_mempool = l_mempool->next;
    }
    log_it(L_ERROR, "No mempool cluster found for chain specified");
    return NULL;
}

void dap_chain_add_mempool_notify_callback(dap_chain_t *a_chain, dap_store_obj_callback_notify_t a_callback, void *a_cb_arg)
{
    dap_global_db_cluster_add_notify_callback(dap_chain_net_get_mempool_cluster(a_chain), a_callback, a_cb_arg);
}

static void s_nodelist_change_notify(dap_store_obj_t *a_obj, void *a_arg)
{
    dap_chain_net_t *l_net = a_arg;
    dap_return_if_fail(a_obj->key && !dap_strcmp(l_net->pub.gdb_nodes, a_obj->group));
    char l_ts[DAP_TIME_STR_SIZE] = { '\0' };
    dap_nanotime_to_str_rfc822(l_ts, sizeof(l_ts), a_obj->timestamp);
    if (dap_store_obj_get_type(a_obj) == DAP_GLOBAL_DB_OPTYPE_DEL) {
        log_it(L_NOTICE, "Removed node %s from network %s at %s\n",
                                 a_obj->key, l_net->pub.name, l_ts);
        return;
    }
    dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t *)a_obj->value;
    assert(dap_chain_node_info_get_size(l_node_info) == a_obj->value_len);
    log_it(L_NOTICE, "Added node "NODE_ADDR_FP_STR" [%s : %u] to network %s at %s\n",
                             NODE_ADDR_FP_ARGS_S(l_node_info->address),
                             l_node_info->ext_host, l_node_info->ext_port,
                             l_net->pub.name, l_ts);
}

void dap_chain_net_add_nodelist_notify_callback(dap_chain_net_t *a_net, dap_store_obj_callback_notify_t a_callback, void *a_cb_arg)
{
    dap_global_db_cluster_add_notify_callback(PVT(a_net)->nodes_cluster, a_callback, a_cb_arg);
}

void dap_chain_net_srv_order_add_notify_callback(dap_chain_net_t *a_net, dap_store_obj_callback_notify_t a_callback, void *a_cb_arg)
{
    dap_global_db_cluster_add_notify_callback(PVT(a_net)->orders_cluster, a_callback, a_cb_arg);
}

int dap_chain_net_add_auth_nodes_to_cluster(dap_chain_net_t *a_net, dap_global_db_cluster_t *a_cluster)
{
    dap_return_val_if_fail(a_net && a_cluster, -1);
    for (uint16_t i = 0; i < PVT(a_net)->authorized_nodes_count; i++)
        dap_global_db_cluster_member_add(a_cluster, PVT(a_net)->authorized_nodes_addrs + i, DAP_GDB_MEMBER_ROLE_ROOT);
    return 0;
}

bool dap_chain_net_add_validator_to_clusters(dap_chain_t *a_chain, dap_stream_node_addr_t *a_addr)
{
    bool l_ret = dap_global_db_cluster_member_add(dap_chain_net_get_mempool_cluster(a_chain), a_addr, DAP_GDB_MEMBER_ROLE_ROOT);
    l_ret &= (bool)dap_global_db_cluster_member_add(PVT(dap_chain_net_by_id(a_chain->net_id))->orders_cluster, a_addr, DAP_GDB_MEMBER_ROLE_USER);
    return l_ret;
}

bool dap_chain_net_remove_validator_from_clusters(dap_chain_t *a_chain, dap_stream_node_addr_t *a_addr)
{
    bool l_ret = !dap_global_db_cluster_member_delete(dap_chain_net_get_mempool_cluster(a_chain), a_addr);
    l_ret &= !dap_global_db_cluster_member_delete(PVT(dap_chain_net_by_id(a_chain->net_id))->orders_cluster, a_addr);
    return l_ret;
}

size_t dap_chain_net_count() {
    return HASH_COUNT(s_net_items);
}

dap_chain_net_t *dap_chain_net_iter_start() {
    dap_return_val_if_pass(!s_net_items, NULL);
    return s_net_items->chain_net;
}

dap_chain_net_t *dap_chain_net_iter_next(dap_chain_net_t *a_it) {
    if (!a_it)
        return NULL;
    dap_chain_net_item_t *l_net_sought = NULL;
    HASH_FIND_STR(s_net_items, a_it->pub.name, l_net_sought);
    return l_net_sought && l_net_sought->hh.next
        ? ((dap_chain_net_item_t*)l_net_sought->hh.next)->chain_net 
        : NULL;
}

/**
 * @brief dap_chain_net_by_name
 * @param a_name
 * @return
 */
dap_chain_net_t *dap_chain_net_by_name(const char *a_name)
{
    dap_chain_net_item_t *l_net_item = NULL;
    if (a_name)
        HASH_FIND(hh, s_net_items, a_name, strlen(a_name), l_net_item);
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
    dap_proc_thread_callback_add(NULL, s_net_states_proc, l_net);
}

dap_chain_cell_id_t * dap_chain_net_get_cur_cell( dap_chain_net_t * l_net)
{
    return  PVT(l_net)->node_info ? &PVT(l_net)->node_info->cell_id: 0;
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
 *   if DAP_CHAIN_DATUM_TOKEN, called dap_ledger_token_add_check
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
    case DAP_CHAIN_DATUM_TOKEN:
        return dap_ledger_token_add_check(l_net->pub.ledger, a_datum->data, a_datum->header.data_size);
    case DAP_CHAIN_DATUM_TOKEN_EMISSION:
        return dap_ledger_token_emission_add_check(l_net->pub.ledger, a_datum->data, a_datum->header.data_size, a_datum_hash);
    case DAP_CHAIN_DATUM_DECREE:
        return dap_chain_net_decree_verify(l_net, (dap_chain_datum_decree_t *)a_datum->data, a_datum->header.data_size, a_datum_hash);
    case DAP_CHAIN_DATUM_ANCHOR: {
        int l_result = dap_chain_net_anchor_verify(l_net, (dap_chain_datum_anchor_t *)a_datum->data, a_datum->header.data_size);
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

const char *dap_chain_net_verify_datum_err_code_to_str(dap_chain_datum_t *a_datum, int a_code){
    switch (a_datum->header.type_id) {
    case DAP_CHAIN_DATUM_TX:
    case DAP_CHAIN_DATUM_TOKEN:
    case DAP_CHAIN_DATUM_TOKEN_EMISSION:
        return dap_ledger_check_error_str(a_code);
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
    const char *l_auth_type = dap_config_get_item_str(a_net->pub.config, "auth", "type");
    bool l_authorized = true;
    if (l_auth_type && !strcmp(l_auth_type, "ca")) {
        if (dap_hash_fast_is_blank(a_pkey_hash)) {
            return false;
        }
        l_authorized = false;
        char l_auth_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(a_pkey_hash, l_auth_hash_str, sizeof(l_auth_hash_str));
        uint16_t l_acl_list_len = 0;
        char **l_acl_list = dap_config_get_array_str(a_net->pub.config, "auth", "acl_accept_ca_list", &l_acl_list_len);
        for (uint16_t i = 0; i < l_acl_list_len; i++) {
            if (!strcmp(l_acl_list[i], l_auth_hash_str)) {
                l_authorized = true;
                break;
            }
        }
        if (!l_authorized) {
            const char *l_acl_gdb = dap_config_get_item_str(a_net->pub.config, "auth", "acl_accept_ca_gdb");
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
            const char *l_acl_chains = dap_config_get_item_str(a_net->pub.config, "auth", "acl_accept_ca_chains");
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
    if (!HASH_COUNT(s_net_items))
        return NULL;
    uint8_t *l_ret = DAP_NEW_Z_SIZE(uint8_t, HASH_COUNT(s_net_items));
    unsigned i = 0;
    dap_chain_net_item_t *l_net_cur = NULL, *l_net_tmp = NULL;
    HASH_ITER(hh, s_net_items, l_net_cur, l_net_tmp) {
        l_ret[i++] = s_net_check_acl(l_net_cur->chain_net, a_pkey_hash);
    }
    return l_ret;
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
            dap_chain_atom_iter_t *l_atom_iter = l_chain_cur->callback_atom_iter_create(l_chain_cur, l_cell->id, NULL);
            dap_chain_atom_ptr_t l_atom = l_chain_cur->callback_atom_iter_get(l_atom_iter, DAP_CHAIN_ITER_OP_FIRST, &l_atom_size);
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
                l_atom = l_chain_cur->callback_atom_iter_get(l_atom_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size);
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
            return dap_chain_net_anchor_load(l_anchor, a_chain, a_datum_hash);
        }
        case DAP_CHAIN_DATUM_TOKEN:
            return dap_ledger_token_load(l_ledger, a_datum->data, a_datum->header.data_size);

        case DAP_CHAIN_DATUM_TOKEN_EMISSION:
            return dap_ledger_token_emission_load(l_ledger, a_datum->data, a_datum->header.data_size, a_datum_hash);

        case DAP_CHAIN_DATUM_TX: {
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)a_datum->data;
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
            if (l_tx_size != l_datum_data_size) {
                log_it(L_WARNING, "Corrupted transaction, datum size %zd is not equal to size of TX %zd", l_datum_data_size, l_tx_size);
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

/**
 * @brief Add datum to the ledger or smth else
 * @param a_chain
 * @param a_datum
 * @param a_datum_size
 * @return
 */
int dap_chain_datum_remove(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, size_t a_datum_size, dap_hash_fast_t *a_datum_hash)
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
            return 0; 
        }
        case DAP_CHAIN_DATUM_ANCHOR: {
            dap_chain_datum_anchor_t *l_anchor = (dap_chain_datum_anchor_t *)a_datum->data;
            size_t l_anchor_size = dap_chain_datum_anchor_get_size(l_anchor);
            if (l_anchor_size != l_datum_data_size) {
                log_it(L_WARNING, "Corrupted anchor, datum size %zd is not equal to size of anchor %zd", l_datum_data_size, l_anchor_size);
                return -102;
            }
            return dap_chain_net_anchor_unload(l_anchor, a_chain, a_datum_hash);
        }
        case DAP_CHAIN_DATUM_TOKEN:
            return 0;

        case DAP_CHAIN_DATUM_TOKEN_EMISSION:
            return 0;
        case DAP_CHAIN_DATUM_TX: {
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)a_datum->data;
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
            if (l_tx_size != l_datum_data_size) {
                log_it(L_WARNING, "Corrupted trnsaction, datum size %zd is not equal to size of TX %zd", l_datum_data_size, l_tx_size);
                return -102;
            }
            return dap_ledger_tx_remove(l_ledger, l_tx, a_datum_hash);
        }
        case DAP_CHAIN_DATUM_CA:
            return 0;//dap_cert_chain_file_save(a_datum, a_chain->net_name);

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

void dap_chain_net_remove_last_reward(dap_chain_net_t *a_net)
{
    DL_DELETE(PVT(a_net)->rewards, PVT(a_net)->rewards);
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

void dap_chain_net_announce_addrs(dap_chain_net_t *a_net)
{
    dap_return_if_fail(a_net);
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
    if ( l_net_pvt->node_info->ext_port ) {
        dap_chain_net_node_list_request(a_net, l_net_pvt->node_info->ext_port, false, 'a');
        log_it(L_INFO, "Announce our node address "NODE_ADDR_FP_STR" [ %s : %u ] in net %s",
               NODE_ADDR_FP_ARGS_S(g_node_addr),
               l_net_pvt->node_info->ext_host,
               l_net_pvt->node_info->ext_port, a_net->pub.name);
    }
}

dap_chain_net_decree_t *dap_chain_net_get_net_decree(dap_chain_net_t *a_net) {
    return a_net ? PVT(a_net)->decree : NULL;
}

void dap_chain_net_set_net_decree(dap_chain_net_t *a_net, dap_chain_net_decree_t *a_decree) {
    if (!a_net) {
        log_it(L_ERROR, "Net is not initialized");
        return;
    }
    PVT(a_net)->decree = a_decree;
}

decree_table_t **dap_chain_net_get_decrees(dap_chain_net_t *a_net) {
    return a_net ? &(PVT(a_net)->decrees) : NULL;
}

anchor_table_t **dap_chain_net_get_anchors(dap_chain_net_t *a_net) {
    return a_net ? &(PVT(a_net)->anchors) : NULL;
}
