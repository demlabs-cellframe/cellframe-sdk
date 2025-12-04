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
#include <unistd.h>
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
#include "dap_cli_server.h"
#include "dap_chain_common.h"
#include "dap_chain_cell.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_anchor.h"
#include "dap_chain_datum_service_state.h"
#include "dap_chain_node_client.h"
#include "dap_chain_cs.h"
#include "dap_chain_net.h"
#include "dap_chain_cs_type.h"  // For dap_chain_cs_load/start/stop
#include "dap_chain_net_node_list.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_balancer.h"
#include "dap_notify_srv.h"
#include "dap_chain_ledger.h"
#include "dap_chain_srv.h"
#include "dap_global_db.h"
#include "dap_chain_net_ch_pkt.h"
#include "dap_chain_net_ch.h"
#include "dap_chain_ch.h"
#include "dap_stream_ch.h"
#include "dap_stream.h"
#include "dap_stream_ch_pkt.h"
#include "rand/dap_rand.h"
#include "dap_global_db_cluster.h"
#include "dap_link_manager.h"
#include "dap_stream_cluster.h"
#include "dap_http_ban_list_client.h"
#include "dap_net.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_policy.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_srv.h"
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include "dap_json.h"

#define LOG_TAG "chain_net"

#define F_DAP_CHAIN_NET_SYNC_FROM_ZERO   ( 1 << 8 )

static bool s_debug_more = false;
static const int c_sync_timer_period = 5000;  // msec
static bool s_server_enabled = false;
static atomic_bool s_load_skip = false;

struct request_link_info {
    char addr[DAP_HOSTADDR_STRLEN + 1];
    uint16_t port;
};

struct block_reward {
    uint64_t block_number;
    uint256_t reward;
    struct block_reward *prev, *next;
};


struct chain_sync_context {
    dap_chain_sync_state_t  state;
    dap_time_t              stage_last_activity,
                            sync_idle_time;
    dap_stream_node_addr_t  current_link;
    dap_chain_t             *cur_chain;
    dap_chain_cell_t        *cur_cell;
    dap_hash_fast_t         requested_atom_hash;
    uint64_t                requested_atom_num;
};

/**
  * @struct dap_chain_net_pvt
  * @details Private part of chain_net dap object
  */
typedef struct dap_chain_net_pvt {
    pthread_t proc_tid;
    uint32_t  flags;

    dap_chain_node_info_t *node_info;  // Current node's info

    dap_balancer_type_t balancer_type;

    uint16_t permanent_links_addrs_count;
    dap_stream_node_addr_t *permanent_links_addrs;

    uint16_t permanent_links_hosts_count;
    struct request_link_info **permanent_links_hosts;
    
    uint16_t seed_nodes_count;
    struct request_link_info **seed_nodes_hosts;

    struct chain_sync_context sync_context;

    _Atomic(dap_chain_net_state_t) state, state_target;
    uint16_t acl_idx;

    //Global DB clusters for different access groups. Notification with cluster contents changing
    dap_global_db_cluster_t *mempool_clusters; // List of chains mempools
    dap_global_db_cluster_t *orders_cluster;
    dap_global_db_cluster_t *nodes_cluster;
    dap_global_db_cluster_t *nodes_states;
    dap_global_db_cluster_t *common_orders;

    // Block sign rewards history
    struct block_reward *rewards;
} dap_chain_net_pvt_t;

#define PVT(a) ((dap_chain_net_pvt_t *)a->pvt)
#define PVT_S(a) ((dap_chain_net_pvt_t *)a.pvt)

static dap_chain_net_t *s_nets_by_name = NULL, *s_nets_by_id = NULL;

static const char *c_net_states[] = {
    [NET_STATE_LOADING]             = "NET_STATE_LOADING",
    [NET_STATE_OFFLINE]             = "NET_STATE_OFFLINE",
    [NET_STATE_LINKS_PREPARE ]      = "NET_STATE_LINKS_PREPARE",
    [NET_STATE_LINKS_CONNECTING]    = "NET_STATE_LINKS_CONNECTING",
    [NET_STATE_LINKS_ESTABLISHED]   = "NET_STATE_LINKS_ESTABLISHED",
    [NET_STATE_SYNC_CHAINS]         = "NET_STATE_SYNC_CHAINS",
    [NET_STATE_ONLINE]              = "NET_STATE_ONLINE"
};

static inline const char * dap_chain_net_state_to_str(dap_chain_net_state_t a_state) {
    return a_state < NET_STATE_LOADING || a_state > NET_STATE_ONLINE ? "NET_STATE_INVALID" : c_net_states[a_state];
}

// Node link callbacks
static void s_link_manager_callback_connected(dap_link_t *a_link, uint64_t a_net_id);
static void s_link_manager_callback_error(dap_link_t *a_link, uint64_t a_net_id, int a_error);
static bool s_link_manager_callback_disconnected(dap_link_t *a_link, uint64_t a_net_id, int a_links_count);
static int s_link_manager_fill_net_info(dap_link_t *a_link);
static int s_link_manager_link_request(uint64_t a_net_id);
static int s_link_manager_link_count_changed();

static const dap_link_manager_callbacks_t s_link_manager_callbacks = {
    .connected      = s_link_manager_callback_connected,
    .disconnected   = s_link_manager_callback_disconnected,
    .error          = s_link_manager_callback_error,
    .fill_net_info  = s_link_manager_fill_net_info,
    .link_request   = s_link_manager_link_request,
    .link_count_changed = s_link_manager_link_count_changed,
};

// State machine switchs here
static bool s_net_states_proc(void *a_arg);
static void s_net_states_notify(dap_chain_net_t * l_net);
static void s_nodelist_change_notify(dap_store_obj_t *a_obj, void *a_arg);
//static void s_net_proc_kill( dap_chain_net_t * a_net );
static int s_chains_init_all(dap_chain_net_t *a_net, const char *a_path, uint16_t *a_ledger_flags);
static int s_net_init(const char *a_net_name, const char *a_path, uint16_t a_acl_idx);
static void *s_net_load(void *a_arg);
static int s_net_try_online(dap_chain_net_t *a_net);
static int s_cli_net(int argc, char ** argv, dap_json_t *a_json_arr_reply, int a_version);
static uint8_t *s_net_set_acl(dap_chain_hash_fast_t *a_pkey_hash);
static void s_sync_timer_callback(void *a_arg);
static void s_set_reply_text_node_status_json(dap_chain_net_t *a_net, dap_json_t *a_json_out, int a_version);

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
    dap_chain_net_ch_init();
    dap_chain_node_client_init();
    dap_http_ban_list_client_init();
    dap_link_manager_init(&s_link_manager_callbacks);
    dap_chain_node_init();
    dap_cli_server_cmd_add ("net", s_cli_net, NULL, "Network commands", dap_chain_node_cli_cmd_id_from_str("net"),
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
    char l_path[MAX_PATH + 1], *l_end = NULL;
    int l_pos = snprintf(l_path, MAX_PATH, "%s/network/", dap_config_path());
    if (l_pos >= MAX_PATH - 4)
        return log_it(L_ERROR, "Invalid path to net configs, fix it!"), -1;
    DIR *l_dir = opendir(l_path);
    if ( l_dir ){
        struct dirent *l_dir_entry = NULL;
        uint16_t l_acl_idx = 0;
        while ( (l_dir_entry = readdir(l_dir)) ) {
            if (*l_dir_entry->d_name =='\0' || *l_dir_entry->d_name =='.')
                continue;
            // don't search in directories
            l_end = dap_strncpy(l_path + l_pos, l_dir_entry->d_name, MAX_PATH - l_pos);
            if ( dap_dir_test(l_path) )
                continue;
            // search only ".cfg" files
            if ( (int)(l_end - l_path) + l_pos > 4 && strncmp(l_end - 4, ".cfg", 4) )
                continue;

            log_it(L_DEBUG, "Loading net config \"%s\"", l_dir_entry->d_name);
            *(l_end - 4) = '\0';
            if ( !dap_dir_test(l_path) ) {
                log_it(L_ERROR, "Path \"%s\" not found, skipping it", l_path);
                continue;
            }
            s_net_init(l_path + l_pos, l_path, l_acl_idx++);
        }
        closedir(l_dir);
    } else
        log_it(L_WARNING, "Can't open entries on path %s, error %d: \"%s\"", l_path, errno, dap_strerror(errno));

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

DAP_STATIC_INLINE struct request_link_info *s_net_resolve_host(const char *a_addr) {
    char l_host[DAP_HOSTADDR_STRLEN + 1] = { '\0' }; uint16_t l_port = 0;
    struct sockaddr_storage l_saddr;
    if ( dap_net_parse_config_address(a_addr, l_host, &l_port, NULL, NULL) < 0
        || dap_net_resolve_host(l_host, dap_itoa(l_port), false, &l_saddr, NULL) < 0 )
        return NULL;
    struct request_link_info *l_ret = DAP_NEW_Z(struct request_link_info);
    l_ret->port = l_port;
    dap_strncpy(l_ret->addr, l_host, DAP_HOSTADDR_STRLEN);
    return l_ret;
}

static struct request_link_info *s_balancer_link_from_cfg(dap_chain_net_t *a_net)
{
    uint16_t l_idx;
    switch (PVT(a_net)->seed_nodes_count) {
    case 0: return log_it(L_ERROR, "No available links in net %s! Add them in net config", a_net->pub.name), NULL;
    case 1:
        l_idx = 0;
    break;
    default:
        l_idx = dap_random_uint16() % PVT(a_net)->seed_nodes_count;
    break;
    }
    if ( !PVT(a_net)->seed_nodes_hosts[l_idx] ) {
        // Unresolved before? Let's try again
        const char **l_seed_nodes_hosts = dap_config_get_array_str(a_net->pub.config, "general", "seed_nodes_hosts", NULL);
        PVT(a_net)->seed_nodes_hosts[l_idx] = s_net_resolve_host(l_seed_nodes_hosts[l_idx]);
    }
    return PVT(a_net)->seed_nodes_hosts[l_idx];
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
    if (l_is_link_present || a_addr->uint64 == g_node_addr.uint64) {
        debug_if(l_is_link_present, L_DEBUG, "Link to addr "NODE_ADDR_FP_STR" is already persent in net %s", NODE_ADDR_FP_ARGS(a_addr), a_net->pub.name);
        return -3; // Link is already found for this net or link is to yourself
    }
    if (dap_link_manager_link_create(a_addr, a_net->pub.id.uint64)) {
        log_it(L_ERROR, "Can't create link to addr " NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS(a_addr));
        return -1;
    }
    int rc = dap_link_manager_link_update(a_addr, a_host, a_port);
    if (rc)
        log_it(L_ERROR, "Can't update link to addr " NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS(a_addr));
    log_it(L_DEBUG, "Link "NODE_ADDR_FP_STR" successfully added", NODE_ADDR_FP_ARGS(a_addr));
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

    dap_json_t *l_json = dap_chain_net_states_json_collect(l_net, dap_cli_server_get_version());
    if (l_json) {
        char *l_json_str = dap_json_to_string(l_json);
        dap_notify_server_send(l_json_str);
        DAP_DELETE(l_json_str);
        dap_json_object_free(l_json);
    }
    if(l_net_pvt->state == NET_STATE_LINKS_CONNECTING ) {
        l_net_pvt->state = NET_STATE_LINKS_ESTABLISHED;
    }
    dap_chain_net_ch_pkt_hdr_t l_announce = { .version = DAP_STREAM_CH_CHAIN_NET_PKT_VERSION,
                                                     .net_id  = l_net->pub.id };
    if (dap_stream_ch_pkt_send_by_addr(&a_link->addr, DAP_CHAIN_NET_CH_ID, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ANNOUNCE,
                                   &l_announce, sizeof(l_announce)))
        log_it(L_ERROR, "Can't send accounting request for net %s and addr " NODE_ADDR_FP_STR, l_net->pub.name, NODE_ADDR_FP_ARGS_S(a_link->addr));
}

static bool s_net_check_link_is_permanent(dap_chain_net_t *a_net, dap_stream_node_addr_t a_addr)
{
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
    for (uint16_t i = 0; i < l_net_pvt->permanent_links_addrs_count; i++) {
        if (l_net_pvt->permanent_links_addrs[i].uint64 == a_addr.uint64)
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
    bool l_link_is_permanent = s_net_check_link_is_permanent(l_net, a_link->addr);
    log_it(L_INFO, "%s."NODE_ADDR_FP_STR" can't connect for now. %s", l_net ? l_net->pub.name : "(unknown)" ,
            NODE_ADDR_FP_ARGS_S(a_link->addr),
            l_link_is_permanent ? "Setting reconnection pause for it." : "Dropping it.");
    if (!a_links_count && l_net_pvt->state != NET_STATE_OFFLINE) {
        l_net_pvt->state = NET_STATE_LINKS_PREPARE;
        s_net_states_proc(l_net);
    }
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
        dap_json_t *l_json = dap_chain_net_states_json_collect(l_net, dap_config_get_item_int32_default(g_config, "cli-server", "version", 1));
        char l_err_str[DAP_HOSTADDR_STRLEN + 80];
        snprintf(l_err_str, sizeof(l_err_str)
                     , "Link " NODE_ADDR_FP_STR " [%s] can't be established, errno %d"
                     , NODE_ADDR_FP_ARGS_S(a_link->addr), a_link->uplink.client->link_info.uplink_addr, a_error);
        dap_json_object_add_string(l_json, "errorMessage", l_err_str);
        dap_notify_server_send(dap_json_to_string(l_json));
        dap_json_object_free(l_json);
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
    size_t l_required_links_count = dap_link_manager_needed_links_count(l_net->pub.id.uint64);
    for (uint16_t i = 0; i < l_net_pvt->permanent_links_addrs_count; ++i) {
        bool l_is_link_present = dap_link_manager_link_find(&l_net_pvt->permanent_links_addrs[i], a_net_id);
        if (l_is_link_present)
            continue;
        if (i >= l_net_pvt->permanent_links_hosts_count) {
            log_it(L_ERROR, "Permanent liks misconfiguration in net %s", l_net->pub.name);
            break;
        }
        if (dap_chain_net_link_add(l_net, &l_net_pvt->permanent_links_addrs[i],
                                   l_net_pvt->permanent_links_hosts[i]->addr, l_net_pvt->permanent_links_hosts[i]->port)) {
            log_it(L_ERROR, "Can't add permanent link " NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_net_pvt->permanent_links_addrs[i]));
            continue;
        }
        if (!--l_required_links_count)
            return 0;
    }
    struct request_link_info *l_balancer_link = s_balancer_link_from_cfg(l_net);
    if (!l_balancer_link)
        return log_it(L_ERROR, "Can't process balancer link %s request in net %s", 
                        dap_chain_net_balancer_type_to_str(PVT(l_net)->balancer_type), l_net->pub.name), -5;
    dap_balancer_link_request_t *l_arg = DAP_NEW_Z(dap_balancer_link_request_t);
    l_arg->net = l_net;
    l_arg->host_addr = (const char*)l_balancer_link->addr;
    l_arg->host_port = l_balancer_link->port;
    l_arg->type = PVT(l_net)->balancer_type;
    return dap_worker_exec_callback_on(dap_worker_get_auto(), dap_chain_net_balancer_request, l_arg), 0;
}


static int s_link_manager_link_count_changed()
{
    dap_json_t *l_json = dap_chain_nets_info_json_collect(dap_config_get_item_int32_default(g_config, "cli-server", "version", 1));
    dap_json_object_add_string(l_json, "errorMessage", " "); // regular notify has no error
    dap_notify_server_send(dap_json_to_string(l_json));
    dap_json_object_free(l_json);
    return 0;
}

struct request_link_info *s_get_permanent_link_info(dap_chain_net_t *a_net, dap_chain_node_addr_t *a_address)
{
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
    for (uint16_t i = 0; i < l_net_pvt->permanent_links_addrs_count; ++i) {
        if (l_net_pvt->permanent_links_addrs[i].uint64 == a_address->uint64 &&
            i < l_net_pvt->permanent_links_hosts_count &&
            i < l_net_pvt->permanent_links_hosts[i]->addr[0] &&
            i < l_net_pvt->permanent_links_hosts[i]->port)
            return l_net_pvt->permanent_links_hosts[i];
    }
    return NULL;
}

int s_link_manager_fill_net_info(dap_link_t *a_link)
{
// sanity check
    dap_return_val_if_pass(!a_link, -1);
// func work
    const char *l_host = NULL;
    uint16_t l_port = 0;
    struct request_link_info *l_permanent_link = NULL;
    for (dap_chain_net_t *l_net = s_nets_by_name; l_net; l_net = l_net->hh.next) {
        if ( dap_chain_net_get_state(l_net) > NET_STATE_OFFLINE && ( l_permanent_link = s_get_permanent_link_info(l_net, &a_link->addr) )) {
            l_host = l_permanent_link->addr;
            l_port = l_permanent_link->port;
            break;
        }
    }
    dap_chain_node_info_t *l_node_info = NULL;
    if (!l_host || !*l_host || !l_port) {
        for (dap_chain_net_t *net = s_nets_by_name; net; net = net->hh.next) {
            if (( l_node_info = dap_chain_node_info_read(net, &a_link->addr) ))
                break;
        }
        if (!l_node_info)
            return -3;
        l_host = l_node_info->ext_host;
        l_port = l_node_info->ext_port;
    }
    a_link->uplink.ready = !dap_link_manager_link_update(&a_link->addr, l_host, l_port);
    return DAP_DELETE(l_node_info), 0;
}

dap_json_t *s_net_sync_status(dap_chain_net_t *a_net, int a_version)
{
    // sanity check
    dap_return_val_if_pass(!a_net, NULL);

    dap_json_t *l_jobj_chains_array = dap_json_object_new();
    if (!l_jobj_chains_array)
        return NULL;
    
    dap_chain_t *l_chain = NULL;
    DL_FOREACH(a_net->pub.chains, l_chain) {
        dap_json_t *l_jobj_chain = dap_json_object_new();
        if (!l_jobj_chain) {
            dap_json_object_free(l_jobj_chains_array);
            return NULL;
        }
        dap_json_t *l_jobj_chain_status = NULL;
        dap_json_t *l_jobj_percent = NULL;
        
        switch (l_chain->state) {
            case CHAIN_SYNC_STATE_ERROR:
                l_jobj_chain_status = dap_json_object_new_string("error");
                break;
            case CHAIN_SYNC_STATE_IDLE:
                l_jobj_chain_status = dap_json_object_new_string("idle");
                break;
            case CHAIN_SYNC_STATE_WAITING:
                l_jobj_chain_status = dap_json_object_new_string("sync in process");
                break;
            case CHAIN_SYNC_STATE_SYNCED:
                l_jobj_chain_status = dap_json_object_new_string("synced");
                break;
            default:
                l_jobj_chain_status = dap_json_object_new_string("unknown");
                break;
        }
        if (dap_chain_net_get_load_mode(a_net)) {
            char *l_percent_str = dap_strdup_printf("%d %c", l_chain->load_progress, '%');
            l_jobj_percent = dap_json_object_new_string(l_percent_str);
            DAP_DELETE(l_percent_str);
        } else if (l_chain->state == CHAIN_SYNC_STATE_IDLE) {
            l_jobj_percent = dap_json_object_new_string(" - %");
        } else {
            double l_percent = dap_min((double)l_chain->callback_count_atom(l_chain) * 100 / l_chain->atom_num_last, 100.0);
            char *l_percent_str = dap_strdup_printf("%.3f %c", l_percent, '%');
            l_jobj_percent = dap_json_object_new_string(l_percent_str);
            DAP_DELETE(l_percent_str);
        }
        char l_id_buff[20]={0};
        sprintf(l_id_buff,"0x%016"DAP_UINT64_FORMAT_x, l_chain->id.uint64);
        dap_json_object_add_string(l_jobj_chain, "id", l_id_buff);
        dap_json_object_add_int(l_jobj_chain, "generation", l_chain->generation);
        dap_json_object_add_object(l_jobj_chain, "status", l_jobj_chain_status);
        dap_json_object_add_uint64(l_jobj_chain, "current", l_chain->callback_count_atom(l_chain));
        dap_json_object_add_uint64(l_jobj_chain, a_version == 1 ? "in network" : "in_network", l_chain->atom_num_last);
        dap_json_object_add_object(l_jobj_chain, "percent", l_jobj_percent);
        dap_json_object_add_object(l_jobj_chains_array, l_chain->name, l_jobj_chain);

    }
    return l_jobj_chains_array;
}

void s_chain_net_states_to_json(dap_chain_net_t *a_net, dap_json_t *a_json_out, int a_version) {
    dap_json_object_add_object(a_json_out, "name", dap_json_object_new_string((const char *) a_net->pub.name));
    dap_json_object_add_object(a_json_out, a_version == 1 ? "networkState" : "network_state",
                           dap_json_object_new_string(dap_chain_net_state_to_str(PVT(a_net)->state)));
    dap_json_object_add_object(a_json_out, a_version == 1 ? "targetState" : "target_state",
                           dap_json_object_new_string(dap_chain_net_state_to_str(PVT(a_net)->state_target)));
    dap_json_object_add_int(a_json_out, a_version == 1 ? "linksCount" : "links_count", 0);
    dap_json_object_add_object(a_json_out, a_version == 1 ? "activeLinksCount" : "active_links_count",
                           dap_json_object_new_int(dap_link_manager_links_count(a_net->pub.id.uint64)));
    char l_node_addr_str[24] = {'\0'};
    int l_tmp = snprintf(l_node_addr_str, sizeof(l_node_addr_str), NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(g_node_addr));
    dap_json_object_add_string(a_json_out, a_version == 1 ? "nodeAddress" : "node_addr", l_tmp ? l_node_addr_str : "0000::0000::0000::0000");
    if (PVT(a_net)->state == NET_STATE_SYNC_CHAINS) {
        dap_json_t *l_json_sync_status = s_net_sync_status(a_net, a_version);
        dap_json_object_add_object(a_json_out, "processed", l_json_sync_status);
    }
}

dap_json_t *dap_chain_net_states_json_collect(dap_chain_net_t *a_net, int a_version) {
    dap_json_t *l_json = dap_json_object_new();
    dap_json_object_add_string(l_json, "class", a_version == 1 ? "NetInfo" : "net_info");
    s_set_reply_text_node_status_json(a_net, l_json, a_version);
    s_chain_net_states_to_json(a_net, l_json, a_version);
    return l_json;
}

dap_json_t *dap_chain_net_list_json_collect(int a_version){
    dap_json_t *l_json = dap_json_object_new();
    if (!l_json)
        return NULL;
    
    dap_json_object_add_string(l_json, "class", a_version == 1 ? "NetList" : "net_list");
    dap_json_t *l_json_networks = dap_json_array_new();
    if (!l_json_networks) {
        dap_json_object_free(l_json);
        return NULL;
    }
    
    for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
        dap_json_t *l_net_name = dap_json_object_new_string(l_net->pub.name);
        if (l_net_name)
            dap_json_array_add(l_json_networks, l_net_name);
    }
    dap_json_object_add_object(l_json, "networks", l_json_networks);
    return l_json;
}

dap_json_t *dap_chain_nets_info_json_collect(int a_version){
    dap_json_t *l_json = dap_json_object_new();
    dap_json_object_add_string(l_json, "class", a_version == 1 ? "NetsInfo" : "nets_info");
    dap_json_t *l_json_networks = dap_json_object_new();
    for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
        dap_json_t *l_jobj_net_info = dap_json_object_new();
        s_set_reply_text_node_status_json(l_net, l_jobj_net_info, a_version);
        dap_json_object_add_object(l_json_networks, l_net->pub.name, l_jobj_net_info);
    }
    dap_json_object_add_object(l_json, "networks", l_json_networks);
    return l_json;
}

/**
 * @brief s_net_states_notify
 * @param l_net
 */
static void s_net_states_notify(dap_chain_net_t *a_net)
{
    dap_json_t *l_json = dap_chain_net_states_json_collect(a_net, dap_config_get_item_int32_default(g_config, "cli-server", "version", 1));
    dap_json_object_add_string(l_json, "errorMessage", " "); // regular notify has no error
    dap_notify_server_send(dap_json_to_string(l_json));
    dap_json_object_free(l_json);
}

static bool s_net_states_notify_timer_callback(UNUSED_ARG void *a_arg)
{
    for (dap_chain_net_t *net = s_nets_by_name; net; net = net->hh.next) {
        dap_json_t *l_json = dap_chain_net_states_json_collect(net, dap_config_get_item_int32_default(g_config, "cli-server", "version", 1));
        dap_json_object_add_string(l_json, "errorMessage", " "); // regular notify has no error
        dap_notify_server_send(dap_json_to_string(l_json));
        dap_json_object_free(l_json);
    }

    return true;
}

/**
 * @brief dap_chain_net_get_role
 * @param a_net
 * @return
 */
dap_chain_node_role_t dap_chain_net_get_role(dap_chain_net_t * a_net)
{
    return a_net->pub.node_role;
}

/**
 * @brief set node role
 * [root_master, root, archive, cell_master, master, full, light]
 * @param a_id
 * @param a_name
 * @param a_node_role
 * @return dap_chain_net_t*
 */
static dap_chain_net_t *s_net_new(const char *a_net_name, dap_config_t *a_cfg)
{
    dap_return_val_if_fail(a_cfg, NULL);
    const char  *l_net_name_str = dap_config_get_item_str_default(a_cfg, "general", "name", a_net_name),
                *l_net_id_str   = dap_config_get_item_str(a_cfg, "general", "id"),
                *a_node_role    = dap_config_get_item_str(a_cfg, "general", "node-role" ),
                *a_native_ticker= dap_config_get_item_str(a_cfg, "general", "native_ticker");
    dap_chain_net_id_t l_net_id;

    if (!l_net_name_str || !*l_net_name_str || !l_net_id_str || dap_chain_net_id_parse(l_net_id_str, &l_net_id))
        return log_it(L_ERROR, "Can't create l_net, can't read name or ID config"), NULL;

    dap_chain_net_t *l_net_sought = NULL;
    HASH_FIND_STR(s_nets_by_name, l_net_name_str, l_net_sought);
    if (!l_net_sought)
        HASH_FIND(hh2, s_nets_by_id, &l_net_id, sizeof(l_net_id), l_net_sought);
    if (l_net_sought) {
        log_it(L_ERROR, "Can't create net %s ID %"DAP_UINT64_FORMAT_U", an already existent net "
                        "%s ID %"DAP_UINT64_FORMAT_U" has the same name or ID.\n"\
                        "Please, fix your configs and restart node",
                        l_net_name_str, l_net_id.uint64, l_net_sought->pub.name,
                        l_net_sought->pub.id.uint64);
        return NULL;
    }

    if (!a_native_ticker)
        return log_it(L_ERROR, "Invalid native ticker, check [general] \"native_ticker\" in %s.cfg", l_net_name_str), NULL;

    uint32_t l_role;
    if (!a_node_role)
        l_role = NODE_ROLE_FULL;
    else if ( !strcmp(a_node_role, "root_master") )
        l_role = NODE_ROLE_ROOT_MASTER;
    else if ( !strcmp(a_node_role,"root") )
        l_role = NODE_ROLE_ROOT;
    else if ( !strcmp(a_node_role,"archive") )
        l_role = NODE_ROLE_ARCHIVE;
    else if ( !strcmp(a_node_role,"cell_master") )
        l_role = NODE_ROLE_CELL_MASTER;
    else if ( !strcmp(a_node_role,"master") )
        l_role = NODE_ROLE_MASTER;
    else if ( !strcmp(a_node_role,"full") )
        l_role = NODE_ROLE_FULL;
    else if ( !strcmp(a_node_role,"light") )
        l_role = NODE_ROLE_LIGHT;
    else
        return log_it(L_ERROR,"Unknown node role \"%s\" for network '%s'", a_node_role, l_net_name_str), NULL;

    dap_chain_net_t *l_ret = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_net_t, sizeof(dap_chain_net_t) + sizeof(dap_chain_net_pvt_t), NULL);
    PVT(l_ret)->node_info = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_node_info_t, sizeof(dap_chain_node_info_t) + DAP_HOSTADDR_STRLEN + 1, NULL, l_ret);

    l_ret->pub.id = l_net_id;
    l_ret->pub.node_role.enums = l_role;
    log_it (L_NOTICE, "Node role \"%s\" selected for network '%s'", a_node_role, l_net_name_str);
    dap_strncpy(l_ret->pub.name, l_net_name_str, sizeof(l_ret->pub.name));
    l_ret->pub.native_ticker = a_native_ticker;
    
    if ( dap_chain_policy_net_add(l_ret->pub.id, a_cfg) ) {
        log_it(L_ERROR, "Can't add net %s to policy module", l_ret->pub.name);
        DAP_DEL_MULTY(l_ret->pub.name, l_ret);
        return NULL;
    }
    
    l_ret->pub.config = a_cfg;
    l_ret->pub.gdb_groups_prefix
        = dap_config_get_item_str_default( a_cfg, "general", "gdb_groups_prefix", dap_config_get_item_str(a_cfg, "general", "name") );
    HASH_ADD_STR(s_nets_by_name, pub.name, l_ret);
    HASH_ADD(hh2, s_nets_by_id, pub.id, sizeof(dap_chain_net_id_t), l_ret);
    return l_ret;
}

bool s_net_disk_load_notify_callback(UNUSED_ARG void *a_arg)
{
    dap_json_t *json_obj = dap_json_object_new();
    dap_json_object_add_string(json_obj, "class", "nets_init");
    dap_json_t *l_jobj_nets = dap_json_object_new();
    for (dap_chain_net_t *net = s_nets_by_name; net; net = net->hh.next) {
        dap_json_t *json_chains = dap_json_object_new();
        for (dap_chain_t *l_chain = net->pub.chains; l_chain; l_chain = l_chain->next) {
            dap_json_t *l_jobj_chain_info = dap_json_object_new();
            dap_json_object_add_int(l_jobj_chain_info, "count_atoms", l_chain->callback_count_atom(l_chain));
            dap_json_object_add_int(l_jobj_chain_info, "load_process", l_chain->load_progress);
            dap_json_object_add_object(json_chains, l_chain->name, l_jobj_chain_info);
            log_it(L_DEBUG, "Loading net \"%s\", chain \"%s\", ID 0x%016"DAP_UINT64_FORMAT_x " [%d%%]",
                            net->pub.name, l_chain->name, l_chain->id.uint64, l_chain->load_progress);
        }
        dap_json_object_add_object(l_jobj_nets, net->pub.name, json_chains);
    }
    dap_json_object_add_object(json_obj, "nets", l_jobj_nets);
    dap_notify_server_send(dap_json_to_string(json_obj));
    dap_json_object_free(json_obj);
    //s_net_states_notify_timer_callback(NULL);
    return true;
}

/**
 * @brief
 * load network config settings
 */
void dap_chain_net_load_all()
{
    int l_nets_count = HASH_COUNT(s_nets_by_name), i = 0, l_err;
    if (!l_nets_count)
        return log_it(L_ERROR, "No networks initialized!");
    pthread_t l_tids[l_nets_count];
    dap_timerfd_t *l_load_notify_timer = dap_timerfd_start(5000, (dap_timerfd_callback_t)s_net_disk_load_notify_callback, NULL);
    for ( dap_chain_net_t *l_net = s_nets_by_name; l_net && !( l_err = pthread_create(&l_tids[i], NULL, s_net_load, l_net) ); l_net = l_net->hh.next, ++i );
    if ( i < l_nets_count ) {
        log_it(L_ERROR, "%s%d of %d nets are loading! Thread creation error %d: \"%s\"",
                        i ? "Only " : "", i, l_nets_count, l_err, dap_strerror(l_err));
        l_nets_count = i;
    }
    for ( i = 0; i < l_nets_count; l_err = pthread_join(l_tids[i++], NULL) ) {
        debug_if(l_err, L_ERROR, "Thread %d join error %d: \"%s\"", i, l_err, dap_strerror(l_err));
    }
    dap_timerfd_delete(l_load_notify_timer->worker, l_load_notify_timer->esocket_uuid);
}

dap_string_t* dap_cli_list_net()
{
    dap_string_t *l_string_ret = dap_string_new("");
    dap_string_append(l_string_ret, "Available networks and chains:\n");
    for (dap_chain_net_t *net = s_nets_by_name; net; net = net->hh.next) {
        dap_string_append_printf(l_string_ret, "\t%s:\n", net->pub.name);
        dap_chain_t *l_chain = net->pub.chains;
        while (l_chain) {
            dap_string_append_printf( l_string_ret, "\t\t%s\n", l_chain->name );
            l_chain = l_chain->next;
        }
    }
    return l_string_ret;
}

static void s_set_reply_text_node_status_json(dap_chain_net_t *a_net, dap_json_t *a_json_out, int a_version) {
    if (!a_net || !a_json_out)
        return;
    char l_id_buff[20]= { };
    sprintf(l_id_buff,"0x%016"DAP_UINT64_FORMAT_x, a_net->pub.id.uint64);
    dap_json_object_add_object(a_json_out, "net", dap_json_object_new_string(a_net->pub.name));
    dap_json_object_add_object(a_json_out, "id", dap_json_object_new_string(l_id_buff));
    dap_json_object_add_object(a_json_out, "native_ticker", dap_json_object_new_string(a_net->pub.native_ticker));
    dap_chain_node_addr_t l_cur_node_addr = { 0 };
    l_cur_node_addr.uint64 = dap_chain_net_get_cur_addr_int(a_net);
    dap_json_t *l_jobj_cur_node_addr;
    if(!l_cur_node_addr.uint64) {
        l_jobj_cur_node_addr = dap_json_object_new_string("not defined");
    } else {
        char *l_cur_node_addr_str = dap_strdup_printf(NODE_ADDR_FP_STR,NODE_ADDR_FP_ARGS_S(l_cur_node_addr));
        l_jobj_cur_node_addr = dap_json_object_new_string(l_cur_node_addr_str);
        DAP_DELETE(l_cur_node_addr_str);
    }
    if (!l_jobj_cur_node_addr) {
        return ;
    }
    dap_json_object_add_object(a_json_out, "current_addr", l_jobj_cur_node_addr);
    if (PVT(a_net)->state != NET_STATE_OFFLINE && PVT(a_net)->state != NET_STATE_LOADING) {
        dap_json_t *l_jobj_links = dap_json_object_new();
        dap_json_t *l_jobj_active_links = dap_json_object_new_uint64(dap_link_manager_links_count(a_net->pub.id.uint64));
        dap_json_t *l_jobj_required_links = dap_json_object_new_uint64(dap_link_manager_required_links_count(a_net->pub.id.uint64));
        dap_json_object_add_object(l_jobj_links, "active", l_jobj_active_links);
        dap_json_object_add_object(l_jobj_links, "required", l_jobj_required_links);
        dap_json_object_add_object(a_json_out, "links", l_jobj_links);
    }
    if (a_net->pub.bridged_networks_count) {
        dap_json_t *l_bridget = dap_json_array_new();
        uint16_t l_bridget_count = 0;  // if can't get any info about bridget net
        for (uint16_t i = 0; i < a_net->pub.bridged_networks_count; ++i) {
            dap_chain_net_t *l_bridget_net = dap_chain_net_by_id(a_net->pub.bridged_networks[i]); 
            if (l_bridget_net) {
                dap_json_t *l_net_item = dap_json_object_new();
                sprintf(l_id_buff,"0x%016"DAP_UINT64_FORMAT_x, a_net->pub.bridged_networks[i].uint64);
                    
                dap_json_object_add_object(l_net_item, "name", dap_json_object_new_string(l_bridget_net->pub.name));
                dap_json_object_add_object(l_net_item, "id", dap_json_object_new_string(l_id_buff));
                dap_json_object_add_object(l_net_item, "native_ticker", dap_json_object_new_string(l_bridget_net->pub.native_ticker));
                dap_json_array_add(l_bridget, l_net_item);
                ++l_bridget_count;
            }
        }
        if (l_bridget_count)
            dap_json_object_add_object(a_json_out, "bridged_networks", l_bridget);
    }

    dap_json_t *l_json_sync_status = s_net_sync_status(a_net, a_version);
    dap_json_object_add_object(a_json_out, "processed", l_json_sync_status);

    dap_json_t *l_jobj_states = dap_json_object_new();
    dap_json_t *l_jobj_current_states = dap_json_object_new_string(c_net_states[PVT(a_net)->state]);
    dap_json_t *l_jobj_target_states = dap_json_object_new_string(c_net_states[PVT(a_net)->state_target]);
    dap_json_object_add_object(l_jobj_states, "current", l_jobj_current_states);
    dap_json_object_add_object(l_jobj_states, "target", l_jobj_target_states);
    dap_json_object_add_object(a_json_out, "states", l_jobj_states);
}

void s_set_reply_text_node_status(dap_json_t *a_json_arr_reply, dap_chain_net_t * a_net){
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
                                                           dap_link_manager_links_count(a_net->pub.id.uint64), 0);
    char *l_reply_str = dap_strdup_printf("Network \"%s\" has state %s (target state %s)%s%s",
                                      a_net->pub.name, c_net_states[PVT(a_net)->state],
                                      c_net_states[PVT(a_net)->state_target],
                                      (l_sync_current_link_text_block)? l_sync_current_link_text_block: "",
                                      l_node_address_text_block
                                      );
    dap_json_rpc_error_add(a_json_arr_reply, -1, l_reply_str);
    DAP_DELETE(l_reply_str);
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
void dap_chain_net_purge(dap_chain_net_t *a_net)
{
    dap_chain_net_pvt_t *l_pvt = PVT(a_net);
    struct block_reward *l_reward, *l_tmp;
    DL_FOREACH_SAFE(l_pvt->rewards, l_reward, l_tmp) {
        DL_DELETE(l_pvt->rewards, l_reward);
        DAP_DELETE(l_reward);
    }
    dap_chain_srv_purge_all(a_net->pub.id);
    if (a_net->pub.ledger) {
        dap_ledger_purge(a_net->pub.ledger, false);
        dap_ledger_handle_free(a_net->pub.ledger);
    }
    if (a_net->pub.chains) {
        dap_chain_t *l_chain = NULL;
        DL_FOREACH(a_net->pub.chains, l_chain) {
            log_it(L_INFO, "Purging chain '%s'", l_chain->name);
            
            /* Delete .dchaincell files BEFORE calling callback_purge (which clears cells hash table) */
            dap_chain_cell_t *l_cell, *l_cell_tmp;
            HASH_ITER(hh, l_chain->cells, l_cell, l_cell_tmp) {
                log_it(L_INFO, "Processing cell with file_storage_path: '%s'", l_cell->file_storage_path);
                if (l_cell->file_storage_path[0]) { // Check if path is not empty
                    log_it(L_INFO, "Attempting to delete chain cell file: %s", l_cell->file_storage_path);
                    if (unlink(l_cell->file_storage_path) == 0) {
                        log_it(L_INFO, "Successfully deleted chain cell file: %s", l_cell->file_storage_path);
                    } else {
                        log_it(L_WARNING, "Failed to delete chain cell file: %s (errno: %d - %s)", 
                               l_cell->file_storage_path, errno, strerror(errno));
                    }
                } else {
                    log_it(L_WARNING, "Cell has empty file_storage_path, skipping");
                }
            }
            
            /* Now purge the chain data (this will clear the cells hash table) */
            dap_chain_purge(l_chain);
            
            /* DON'T reload chain from disk - files were deleted above! */
            /* The chain will start fresh synchronization from genesis */
            /* dap_chain_load_all(l_chain);  // REMOVED: would load nothing since files are deleted */
            
            /* Reset chain synchronization state to start from genesis */
            l_chain->atom_num_last = 0;
            l_chain->state = CHAIN_SYNC_STATE_IDLE;
            log_it(L_INFO, "Reset chain '%s' sync state: atom_num_last=0, state=IDLE", l_chain->name);
        }
        
        /* Now delete chain objects */
        dap_chain_t *l_chain_tmp = NULL;
        DL_FOREACH_SAFE(a_net->pub.chains, l_chain, l_chain_tmp) {
            DL_DELETE(a_net->pub.chains, l_chain);
            dap_chain_delete(l_chain);
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


void _s_print_chains(dap_json_t *a_obj_chain, dap_chain_t *a_chain) {
    if (!a_obj_chain || !a_chain)
        return;
    dap_json_object_add_string(a_obj_chain, "name", a_chain->name);
    dap_json_object_add_object(a_obj_chain, "consensus", dap_json_object_new_string(DAP_CHAIN_PVT(a_chain)->cs_name));

    if (a_chain->default_datum_types_count) {
        dap_json_t *l_jobj_default_types = dap_json_array_new();
        if (!l_jobj_default_types) return;
        for (uint16_t i = 0; i < a_chain->default_datum_types_count; i++) {
            dap_json_t *l_jobj_type_str = dap_json_object_new_string(dap_chain_type_to_str(
                    a_chain->default_datum_types[i]));
            if (!l_jobj_type_str) {
                dap_json_object_free(l_jobj_default_types);
                return;
            }
            dap_json_array_add(l_jobj_default_types, l_jobj_type_str);
        }
        dap_json_object_add_object(a_obj_chain, "default_types", l_jobj_default_types);
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
static int s_cli_net(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version)
{
    dap_json_t *l_jobj_return = dap_json_object_new();
    if (!l_jobj_return) {
        dap_json_rpc_allocation_error(a_json_arr_reply);
        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
    }
    int arg_index = 1;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_object_free(l_jobj_return);
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_INVALID_PARAMETER_HASH, "%s", "invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NET_JSON_RPC_INVALID_PARAMETER_HASH;

    }

    // command 'list'
    const char * l_list_cmd = NULL;

    if(dap_cli_server_cmd_find_option_val(argv, arg_index, dap_min(argc, arg_index + 1), "list", &l_list_cmd) != 0 ) {
        if (dap_strcmp(l_list_cmd,"chains")==0){
            const char * l_net_str = NULL;
            dap_chain_net_t* l_net = NULL;
            if (dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &l_net_str) && !l_net_str) {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_PARAMETER_NET_REQUIRE, "%s", "Parameter '-net' require <net name>");
                return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_PARAMETER_NET_REQUIRE;
            }

            l_net = dap_chain_net_by_name(l_net_str);
            if (l_net_str && !l_net) {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_WRONG_NET, "%s", "Wrong <net name>, use 'net list' "
                                                                         "command to display a list of available networks");
                return DAP_CHAIN_NET_JSON_RPC_WRONG_NET;
            }

            if (l_net){
                dap_json_t *l_jobj_net_name = dap_json_object_new_string(l_net->pub.name);
                dap_json_t *l_jobj_chains = dap_json_array_new();
                if (!l_jobj_net_name || !l_jobj_chains) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_object_free(l_jobj_net_name);
                    dap_json_object_free(l_jobj_chains);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_chain_t * l_chain = l_net->pub.chains;
                while (l_chain) {
                    dap_json_t *l_obj_chain = dap_json_object_new();
                    if (!l_obj_chain) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_object_free(l_jobj_net_name);
                        dap_json_object_free(l_jobj_chains);
                        dap_json_object_free(l_obj_chain);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    _s_print_chains(l_obj_chain, l_chain);
                    dap_json_array_add(l_jobj_chains, l_obj_chain);
                    l_chain = l_chain->next;
                }
                dap_json_object_add_object(l_jobj_return, "net", l_jobj_net_name);
                dap_json_object_add_object(l_jobj_return, "chains", l_jobj_chains);
            }else{
                dap_json_t *l_jobj_networks = dap_json_array_new();
                for (dap_chain_net_t *l_net = s_nets_by_name; l_net; l_net = l_net->hh.next) {
                    dap_json_t *l_jobj_network = dap_json_object_new();
                    dap_json_t *l_jobj_chains = dap_json_array_new();
                    dap_json_t *l_jobj_network_name = dap_json_object_new_string(l_net->pub.name);
                    if (!l_jobj_network || !l_jobj_chains || !l_jobj_network_name) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_object_free(l_jobj_network);
                        dap_json_object_free(l_jobj_chains);
                        dap_json_object_free(l_jobj_network_name);
                        dap_json_object_free(l_jobj_networks);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    dap_json_object_add_object(l_jobj_network, "name", l_jobj_network_name);

                    dap_chain_t * l_chain = l_net->pub.chains;
                    while (l_chain) {
                        dap_json_t *l_jobj_chain = dap_json_object_new();
                        if (!l_jobj_chain) {
                            dap_json_object_free(l_jobj_return);
                            dap_json_object_free(l_jobj_network);
                            dap_json_object_free(l_jobj_chains);
                            dap_json_object_free(l_jobj_networks);
                            dap_json_rpc_allocation_error(a_json_arr_reply);
                            return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                        }
                        _s_print_chains(l_jobj_chain, l_chain);
                        dap_json_array_add(l_jobj_chains, l_jobj_chain);
                        l_chain = l_chain->next;
                    }
                    dap_json_object_add_object(l_jobj_network, "chain", l_jobj_chains);
                    dap_json_array_add(l_jobj_networks, l_jobj_network);
                }
                dap_json_object_add_object(l_jobj_return, "networks", l_jobj_networks);
            }
        }else{
            // plug for wrong command arguments
            if (argc > 2) {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_MANY_ARGUMENT_FOR_COMMAND_NET_LIST, "%s",
                                       "To many arguments for 'net list' command see help");
                return DAP_CHAIN_NET_JSON_RPC_MANY_ARGUMENT_FOR_COMMAND_NET_LIST;
            }

            dap_json_t *l_jobj_networks = dap_json_array_new();
            if (!l_jobj_networks) {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            // show list of nets
            for (dap_chain_net_t *l_net = s_nets_by_name; l_net; l_net = l_net->hh.next) {
                dap_json_t *l_jobj_network_name = dap_json_object_new_string(l_net->pub.name);
                dap_json_array_add(l_jobj_networks, l_jobj_network_name);
            }
            dap_json_object_add_object(l_jobj_return, "networks", l_jobj_networks);
        }
        dap_json_array_add(a_json_arr_reply, l_jobj_return);
        return 0;
    }

    int l_ret = dap_chain_node_cli_cmd_values_parse_net_chain_for_json(a_json_arr_reply, &arg_index, argc, argv, NULL, &l_net,
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
                dap_json_t *l_jobj_stats = dap_json_object_new();
                if (!l_jobj_stats) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_t *l_jobj_from = dap_json_object_new_string(l_from_str_new);
                dap_json_t *l_jobj_to = dap_json_object_new_string(l_to_str_new);
                if (!l_jobj_from || !l_jobj_to) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_object_free(l_jobj_stats);
                    dap_json_object_free(l_jobj_from);
                    dap_json_object_free(l_jobj_to);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_stats, "from", l_jobj_from);
                dap_json_object_add_object(l_jobj_stats, "to", l_jobj_to);
                log_it(L_INFO, "Calc TPS from %s to %s", l_from_str_new, l_to_str_new);
                uint64_t l_tx_count = dap_ledger_count_from_to ( l_net->pub.ledger, l_from_ts * 1000000000, l_to_ts * 1000000000);
                long double l_tpd = l_to_ts == l_from_ts ? 0 :
                                                     (long double) l_tx_count / (long double) ((long double)(l_to_ts - l_from_ts) / 86400);
                char *l_tpd_str = dap_strdup_printf("%.3Lf", l_tpd);
                dap_json_t *l_jobj_tpd = dap_json_object_new_string(l_tpd_str);
                DAP_DELETE(l_tpd_str);
                dap_json_t *l_jobj_total = dap_json_object_new_uint64(l_tx_count);
#ifdef DAP_TPS_TEST
                long double l_tps = l_to_ts == l_from_ts ? 0 :
                                                     (long double) l_tx_count / (long double) (long double)(l_to_ts - l_from_ts);
                char *l_tps_str = dap_strdup_printf("%.3Lf", l_tps);
                dap_json_t *l_jobj_tps = dap_json_object_new_string(l_tps_str);
                DAP_DELETE(l_tps_str);
                if (!l_jobj_tpd || !l_jobj_total || !l_jobj_tps) {
                    dap_json_object_free(l_jobj_tps);
#else
                if (!l_jobj_tpd || !l_jobj_total) {
#endif
                    
                    dap_json_object_free(l_jobj_return);
                    dap_json_object_free(l_jobj_stats);
                    dap_json_object_free(l_jobj_from);
                    dap_json_object_free(l_jobj_to);
                    dap_json_object_free(l_jobj_tpd);
                    dap_json_object_free(l_jobj_total);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
#ifdef DAP_TPS_TEST
                dap_json_object_add_object(l_jobj_stats, "transaction_per_sec", l_jobj_tps);
#endif
                dap_json_object_add_object(l_jobj_stats, "transaction_per_day", l_jobj_tpd);
                dap_json_object_add_object(l_jobj_stats, "total", l_jobj_total);
                dap_json_object_add_object(l_jobj_return, "transaction_statistics", l_jobj_stats);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETER_COMMAND_STATS, "%s",
                 "Subcommand 'stats' requires one of parameter: tx");
                return DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETER_COMMAND_STATS;
            }
        } else if ( l_go_str){
            dap_json_t *l_jobj_net = dap_json_object_new_string(l_net->pub.name);
            dap_json_t *l_jobj_current_status = dap_json_object_new_string(c_net_states[PVT(l_net)->state]);
            if (!l_jobj_net || !l_jobj_current_status) {
                dap_json_object_free(l_jobj_return);
                dap_json_object_free(l_jobj_net);
                dap_json_object_free(l_jobj_current_status);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            dap_json_object_add_object(l_jobj_return, "net", l_jobj_net);
            dap_json_object_add_object(l_jobj_return, "current", l_jobj_current_status);
            if ( strcmp(l_go_str,"online") == 0 ) {
                dap_json_t *l_jobj_to = dap_json_object_new_string(c_net_states[NET_STATE_ONLINE]);
                if (!l_jobj_to) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "to", l_jobj_to);
                if (dap_chain_net_state_go_to(l_net, NET_STATE_ONLINE)) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START, "%s",
                                            "Can't change state of loading network\n");
                    return DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START;
                }
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp(l_go_str,"offline") == 0 ) {
                dap_json_t *l_jobj_to = dap_json_object_new_string(c_net_states[NET_STATE_OFFLINE]);
                if (!l_jobj_to) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "to", l_jobj_to);
                if ( dap_chain_net_state_go_to(l_net, NET_STATE_OFFLINE) ) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START, "%s",
                                            "Can't change state of loading network\n");
                    return DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START;
                }
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if (strcmp(l_go_str, "sync") == 0) {
                dap_json_t *l_jobj_to = dap_json_object_new_string("resynchronizing");
                if (!l_jobj_to) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "start", l_jobj_to);
                if (PVT(l_net)->state_target == NET_STATE_ONLINE)
                    l_ret = dap_chain_net_state_go_to(l_net, NET_STATE_ONLINE);
                else
                    l_ret = dap_chain_net_state_go_to(l_net, NET_STATE_SYNC_CHAINS);
                if (l_ret) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START, "%s",
                                            "Can't change state of loading network\n");
                    return DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START;
                }
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETER_COMMAND_GO, "%s",
                                       "Subcommand 'go' requires one of parameters: online, offline, sync\n");
                return DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETER_COMMAND_GO;
            }
        } else if ( l_get_str){
            if ( strcmp(l_get_str,"status") == 0 ) {
                dap_json_t *l_jobj = dap_json_object_new();
                s_set_reply_text_node_status_json(l_net, l_jobj, a_version);
                if (!l_jobj) {
                    dap_json_object_free(l_jobj_return);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "status", l_jobj);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp(l_get_str, "fee") == 0) {
                dap_json_t *l_jobj_fees = dap_json_object_new();
                if (!l_jobj_fees) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "fees", l_jobj_fees);
                dap_json_t *l_jobj_network_name = dap_json_object_new_string(l_net->pub.name);
                if (!l_jobj_network_name) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_fees, "network_name", l_jobj_network_name);
                // Network fee
                uint256_t l_network_fee = {};
                dap_chain_addr_t l_network_fee_addr = {};
                dap_chain_net_tx_get_fee(l_net->pub.id, &l_network_fee, &l_network_fee_addr);
                const char *l_network_fee_coins_str, *l_network_fee_balance_str =
                    dap_uint256_to_char(l_network_fee, &l_network_fee_coins_str);
                dap_json_t *l_jobj_network =  dap_json_object_new();
                if (!l_jobj_network) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_fees, "network_fee", l_jobj_network);
                dap_json_t *l_jobj_fee_coins = dap_json_object_new_string(l_network_fee_coins_str);
                if (!l_jobj_fee_coins) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_network, "coins", l_jobj_fee_coins);
                dap_json_t *l_jobj_fee_balance = dap_json_object_new_string(l_network_fee_balance_str);
                if (!l_jobj_fee_balance) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_network, "balance", l_jobj_fee_balance);
                dap_json_t *l_jobj_native_ticker = dap_json_object_new_string(l_net->pub.native_ticker);
                if (!l_jobj_native_ticker) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_network, "ticker", l_jobj_native_ticker);
                dap_json_t *l_jobj_fee_addr = dap_json_object_new_string(dap_chain_addr_to_str_static(&l_network_fee_addr));
                if (!l_jobj_native_ticker) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_network, "addr", l_jobj_fee_addr);
                dap_json_object_add_object(l_jobj_fees, "service_fees", dap_chain_srv_get_fees(l_net->pub.id));
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;

            } else if (strcmp(l_get_str,"id") == 0 ){
                dap_json_t *l_jobj_net_name = dap_json_object_new_string(l_net->pub.name);
                char *l_id_str = dap_strdup_printf("0x%016"DAP_UINT64_FORMAT_X, l_net->pub.id.uint64);
                dap_json_t *l_jobj_id = dap_json_object_new_string(l_id_str);
                DAP_DELETE(l_id_str);
                if (!l_jobj_net_name || !l_jobj_id) {
                    dap_json_object_free(l_jobj_net_name);
                    dap_json_object_free(l_jobj_id);
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "network", l_jobj_net_name);
                dap_json_object_add_object(l_jobj_return, "id", l_jobj_id);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNKNOWN_SUBCOMMANDS,
                                       "Unknown \"%s\" subcommand, net get commands.", l_get_str);
                return DAP_CHAIN_NET_JSON_RPC_UNKNOWN_SUBCOMMANDS;
            }
        } else if ( l_links_str ){
            if ( strcmp(l_links_str,"list") == 0 ) {
                dap_cluster_t *l_net_cluster = dap_cluster_by_mnemonim(l_net->pub.name);
                if (!l_net_cluster) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_GET_CLUSTER, "%s", "Failed to obtain a cluster for "
                                                                                       "the specified network.");
                    return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_GET_CLUSTER;
                }
                dap_json_t *l_jobj_links = dap_cluster_get_links_info_json(l_net_cluster);
                if (!l_jobj_links) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "links", l_jobj_links);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp(l_links_str,"add") == 0 ) {
                dap_json_t *l_jobj_not_implemented = dap_json_object_new_string("Not implemented");
                if (!l_jobj_not_implemented) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "add", l_jobj_not_implemented);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp(l_links_str,"del") == 0 ) {
                dap_json_t *l_jobj_not_implemented = dap_json_object_new_string("Not implemented");
                if (!l_jobj_not_implemented) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "del", l_jobj_not_implemented);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            }  else if ( strcmp(l_links_str,"info") == 0 ) {
                dap_json_t *l_jobj_not_implemented = dap_json_object_new_string("Not implemented");
                if (!l_jobj_not_implemented) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "info", l_jobj_not_implemented);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if ( strcmp (l_links_str,"disconnect_all") == 0 ){
                dap_chain_net_stop(l_net);
                dap_json_t *l_jobj_ret = dap_json_object_new_string("Stopped network");
                if (!l_jobj_ret) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_return, "message", l_jobj_ret);
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            }else {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETERS_COMMAND_LINK, "%s",
                                       "Subcommand 'link' requires one of parameters: list, add, del, info, disconnect_all");
                return DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETERS_COMMAND_LINK;
            }

        } else if( l_sync_str) {
            dap_json_t *l_jobj_state_machine = dap_json_object_new();
            dap_json_t *l_jobj_requested = dap_json_object_new_string("SYNC_ALL");
            dap_json_t *l_jobj_current = dap_json_object_new_string(c_net_states[PVT(l_net)->state]);
            if (!l_jobj_state_machine || !l_jobj_current) {
                dap_json_object_free(l_jobj_state_machine);
                dap_json_object_free(l_jobj_current);
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            dap_chain_net_sync(l_net);
            if (!l_jobj_requested) {
                dap_json_object_free(l_jobj_state_machine);
                dap_json_object_free(l_jobj_current);
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            dap_json_object_add_object(l_jobj_state_machine, "current", l_jobj_current);
            dap_json_object_add_object(l_jobj_state_machine, "requested", l_jobj_requested);
            dap_json_object_add_object(l_jobj_return, "state_machine", l_jobj_state_machine);
            l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
        } else if (l_ca_str) {
            if (strcmp(l_ca_str, "add") == 0 ) {
                const char *l_cert_string = NULL, *l_hash_string = NULL;

                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cert", &l_cert_string);
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-hash", &l_hash_string);

                if (!l_cert_string && !l_hash_string) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETERS_CA_ADD, "%s",
                                           "One of -cert or -hash parameters is mandatory");
                    return DAP_CHAIN_NET_JSON_RPC_UNDEFINED_PARAMETERS_CA_ADD;
                }
                
                char *l_hash_hex_str = NULL;

                if (l_cert_string) {
                    dap_cert_t * l_cert = dap_cert_find_by_name(l_cert_string);
                    if (l_cert == NULL) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_FIND_CERT_CA_ADD,
                                               "Can't find \"%s\" certificate", l_cert_string);
                        return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_FIND_CERT_CA_ADD;
                    }
                    if (l_cert->enc_key == NULL) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_KEY_IN_CERT_CA_ADD,
                                               "No key found in \"%s\" certificate", l_cert_string);
                        return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_KEY_IN_CERT_CA_ADD;
                    }
                    // Get publivc key hash
                    size_t l_pub_key_size = 0;
                    uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(l_cert->enc_key, &l_pub_key_size);;
                    if (l_pub_key == NULL) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_SERIALIZE_PUBLIC_KEY_CERT_CA_ADD,
                                               "Can't serialize public key of certificate \"%s\"", l_cert_string);
                        return DAP_CHAIN_NET_JSON_RPC_CAN_SERIALIZE_PUBLIC_KEY_CERT_CA_ADD;
                    }
                    dap_chain_hash_fast_t l_pkey_hash;
                    dap_hash_fast(l_pub_key, l_pub_key_size, &l_pkey_hash);
                    DAP_DELETE(l_pub_key);
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
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_ADD, "%s",
                                           "Database ACL group not defined for this network");
                    return DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_ADD;
                }
                if( l_hash_hex_str ){
                    l_ret = dap_global_db_set_sync(l_gdb_group_str, l_hash_hex_str, &c, sizeof(c), false );
                    DAP_DELETE(l_gdb_group_str);
                    if (l_ret) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_SAVE_PUBLIC_KEY_IN_DATABASE,
                                               "Can't save public key hash %s in database", l_hash_hex_str);
                        DAP_DELETE(l_hash_hex_str);
                        return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_SAVE_PUBLIC_KEY_IN_DATABASE;
                    } else
                        DAP_DELETE(l_hash_hex_str);
                } else{
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_SAVE_PUBLIC_KEY_IN_DATABASE, "%s",
                                           "Can't save NULL public key hash in database");
                    return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_SAVE_PUBLIC_KEY_IN_DATABASE;
                }
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if (strcmp(l_ca_str, "list") == 0 ) {
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_LIST, "%s",
                                           "Database ACL group not defined for this network");
                    return DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_LIST;
                }
                size_t l_objs_count;
                dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group_str, &l_objs_count);
                DAP_DELETE(l_gdb_group_str);
                dap_json_t *l_jobj_list_ca = dap_json_array_new();
                if (!l_jobj_list_ca) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                for (size_t i = 0; i < l_objs_count; i++) {
                    dap_json_t *l_jobj_key = dap_json_object_new_string(l_objs[i].key);
                    if (!l_jobj_key) {
                        dap_json_object_free(l_jobj_list_ca);
                        dap_json_object_free(l_jobj_return);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                }
                dap_global_db_objs_delete(l_objs, l_objs_count);
                if (dap_json_array_length(l_jobj_list_ca) > 0) {
                    dap_json_object_add_object(l_jobj_return, "ca_list", l_jobj_list_ca);
                } else {
                    dap_json_object_free(l_jobj_list_ca);
                    dap_json_t *l_jobj_str_ret = dap_json_object_new_string("No entries found");
                    if (!l_jobj_str_ret) {
                        dap_json_object_free(l_jobj_return);
                        dap_json_rpc_allocation_error(a_json_arr_reply);
                        return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                    }
                    dap_json_object_add_object(l_jobj_return, "ca_list", l_jobj_str_ret);
                }
                l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
            } else if (strcmp(l_ca_str, "del") == 0 ) {
                const char *l_hash_string = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-hash", &l_hash_string);
                if (!l_hash_string) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNKNOWN_HASH_CA_DEL, "%s",
                                           "Format should be 'net ca del -hash <hash string>");
                    return DAP_CHAIN_NET_JSON_RPC_UNKNOWN_HASH_CA_DEL;
                }
                char *l_gdb_group_str = dap_chain_net_get_gdb_group_acl(l_net);
                if (!l_gdb_group_str) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_DEL, "%s",
                                           "Database ACL group not defined for this network");
                    return DAP_CHAIN_NET_JSON_RPC_DATABASE_ACL_GROUP_NOT_DEFINED_FOR_THIS_NETWORK_CA_DEL;
                }
                char *l_ret_msg_str = dap_strdup_printf("Certificate %s has been deleted.", l_hash_string);
                dap_json_t *l_jobj_ret = dap_json_object_new_string(l_ret_msg_str);
                DAP_DELETE(l_ret_msg_str);
                if (l_jobj_ret) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                l_ret = dap_global_db_del_sync(l_gdb_group_str, l_hash_string);
                DAP_DELETE(l_gdb_group_str);
                if (l_ret) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_CAN_NOT_FIND_CERT_CA_DEL, "%s",
                                           "Can't find certificate public key hash in database");
                    return DAP_CHAIN_NET_JSON_RPC_CAN_NOT_FIND_CERT_CA_DEL;
                }
                dap_json_object_free(l_jobj_return);
                dap_json_array_add(a_json_arr_reply, l_jobj_ret);
                return DAP_CHAIN_NET_JSON_RPC_OK;
            } else {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_INVALID_PARAMETER_COMMAND_CA, "%s",
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
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_NO_POA_CERTS_FOUND_POA_CERTS, "%s",
                                       "No PoA certs found for this network");
                return DAP_CHAIN_NET_JSON_RPC_NO_POA_CERTS_FOUND_POA_CERTS;
            }
            dap_json_t *l_jobj_pkeys = dap_json_array_new();
            if (!l_jobj_pkeys) {
                dap_json_object_free(l_jobj_return);
                dap_json_rpc_allocation_error(a_json_arr_reply);
                return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
            }
            for (dap_list_t *it = l_net->pub.keys; it; it = it->next) {
                dap_hash_fast_t l_pkey_hash;
                char l_pkey_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_pkey_get_hash(it->data, &l_pkey_hash);
                dap_chain_hash_fast_to_str(&l_pkey_hash, l_pkey_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                dap_json_t *l_jobj_hash_key = dap_json_object_new_string(l_pkey_hash_str);
                if (!l_jobj_hash_key) {
                    dap_json_object_free(l_jobj_pkeys);
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_array_add(l_jobj_pkeys, l_jobj_hash_key);
            }
            if (dap_json_array_length(l_jobj_pkeys) > 0) {
                dap_json_object_add_object(l_jobj_return, "poa_certs", l_jobj_pkeys);
            } else {
                dap_json_object_free(l_jobj_pkeys);
                dap_json_t *l_jobj_info = dap_json_object_new_string("empty");
                if (!l_jobj_info) {
                    dap_json_object_free(l_jobj_return);
                    dap_json_rpc_allocation_error(a_json_arr_reply);
                    return DAP_JSON_RPC_ERR_CODE_MEMORY_ALLOCATED;
                }
                dap_json_object_add_object(l_jobj_pkeys, "poa_certs", l_jobj_info);
            }
            l_ret = DAP_CHAIN_NET_JSON_RPC_OK;
        } else {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_JSON_RPC_UNKNOWN_SUBCOMMANDS, "%s",
                                   "Command 'net' requires one of subcomands: sync, link, go, get, stats, ca, ledger");
            l_ret = DAP_CHAIN_NET_JSON_RPC_UNKNOWN_SUBCOMMANDS;
        }
    } else {
        dap_json_object_free(l_jobj_return);
        l_jobj_return = NULL;
    }
    if (l_jobj_return) {
        dap_json_array_add(a_json_arr_reply, l_jobj_return);
    }
    return  l_ret;
}

static int s_cmp_cfg_pri(dap_config_t *cfg1, dap_config_t *cfg2) {
    uint16_t l_pri1 = dap_config_get_item_uint16_default(cfg1, "chain", "load_priority", 100),
             l_pri2 = dap_config_get_item_uint16_default(cfg2, "chain", "load_priority", 100);
    return l_pri1 == l_pri2 ? 0 : l_pri1 > l_pri2 ? 1 : -1;
}

/**
 * @brief dap_chain_net_deinit
 */
void dap_chain_net_deinit()
{
    dap_link_manager_deinit();
    dap_chain_net_balancer_deinit();
    dap_chain_net_t *l_net, *l_tmp;
    HASH_ITER(hh2, s_nets_by_id, l_net, l_tmp) {
        dap_chain_net_delete(l_net);
    }
    dap_http_ban_list_client_deinit();
    dap_chain_policy_deinit();
}

/**
 * @brief dap_chain_net_delete
 * free dap_chain_net_t * a_net object
 * @param a_net
 */
void dap_chain_net_delete(dap_chain_net_t *a_net)
{
    dap_chain_net_pvt_t *l_pvt = PVT(a_net);
    dap_chain_net_purge(a_net);
    DAP_DEL_ARRAY(l_pvt->permanent_links_hosts, l_pvt->permanent_links_hosts_count);
    DAP_DEL_ARRAY(l_pvt->seed_nodes_hosts, l_pvt->seed_nodes_count);
    DAP_DEL_MULTY(l_pvt->permanent_links_hosts, l_pvt->seed_nodes_hosts, l_pvt->permanent_links_addrs, l_pvt->node_info);
    // TODO: delete sync_timer and whatever else is initialized AFTER chains load
    HASH_DEL(s_nets_by_name, a_net);
    HASH_DELETE(hh2, s_nets_by_id, a_net);
    dap_chain_policy_net_remove(a_net->pub.id);
    dap_config_close(a_net->pub.config);
    DAP_DELETE(a_net);
}

#ifdef DAP_LEDGER_TEST
int dap_chain_net_test_init()
{
    dap_chain_net_t *l_net = DAP_NEW_Z_SIZE( dap_chain_net_t, sizeof(dap_chain_net_t) + sizeof(dap_chain_net_pvt_t) );
    PVT(l_net)->node_info = DAP_NEW_Z_SIZE(dap_chain_node_info_t, sizeof(dap_chain_node_info_t) + DAP_HOSTADDR_STRLEN + 1 );
    l_net->pub.id.uint64 = 0xFA0;
    strcpy(l_net->pub.name, "Snet");
    l_net->pub.gdb_groups_prefix = (const char*)l_net->pub.name;
    l_net->pub.native_ticker = "TestCoin";
    l_net->pub.node_role.enums = NODE_ROLE_ROOT;
    HASH_ADD(hh2, s_nets_by_id, pub.id, sizeof(dap_chain_net_id_t), l_net);
    HASH_ADD_STR(s_nets_by_name, pub.name, l_net);
    return 0;
}
#endif


static int s_nodes_hosts_init(dap_chain_net_t *a_net, dap_config_t *a_cfg, const char *a_hosts_type, struct request_link_info ***a_hosts, uint16_t *a_hosts_count)
{
    dap_return_val_if_pass(!a_cfg || !a_hosts_type || !a_hosts || !a_hosts_count, -1);
    const char **l_nodes_addrs = dap_config_get_array_str(a_cfg, "general", a_hosts_type, a_hosts_count);
    if (*a_hosts_count) {
        *a_hosts = DAP_NEW_Z_COUNT(struct request_link_info *, *a_hosts_count);
        if (!*a_hosts) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return -1;
        }
        uint16_t i = 0, e = 0;
        for (; i < *a_hosts_count; ++i) {
            if (!( (*a_hosts)[i] = s_net_resolve_host(l_nodes_addrs[i]) )) {
                log_it(L_ERROR, "Incorrect address %s, fix \"%s\" network config "
                                "or check internet connection and restart node",
                                l_nodes_addrs[i], a_net->pub.name);
                ++e;
                continue;
            }
        }
        debug_if(e, L_ERROR, "%d / %d %s links are invalid or can't be accessed, fix \"%s\""
                        "network config or check internet connection and restart node",
                        e, i, a_hosts_type, a_net->pub.name);

    }
    return 0;
}

static int s_chains_init_all(dap_chain_net_t *a_net, const char *a_path, uint16_t *a_ledger_flags)
{
    DIR *l_chains_dir = opendir(a_path);
    if (!l_chains_dir)
        return log_it(L_ERROR, "Can't find any chains for network %s", a_net->pub.name), -1;
    dap_config_t *l_chain_config, *l_all_chain_configs = NULL, *l_tmp_cfg;
    char l_chain_cfg_path[MAX_PATH + 1] = { '\0' };
    int l_pos = snprintf(l_chain_cfg_path, MAX_PATH, "network/%s/", a_net->pub.name);
    struct dirent *l_dir_entry = NULL;
    while (( l_dir_entry = readdir(l_chains_dir) )) {
        unsigned short l_len = strlen(l_dir_entry->d_name);
        if ( l_len > 4 && !dap_strncmp(l_dir_entry->d_name + l_len - 4, ".cfg", 4) ) {
            *(l_dir_entry->d_name + l_len - 4) = '\0';
            log_it(L_DEBUG, "Opening chain config \"%s.%s\"", a_net->pub.name, l_dir_entry->d_name);
            dap_strncpy(l_chain_cfg_path + l_pos, l_dir_entry->d_name, MAX_PATH - l_pos);
            if (!( l_chain_config = dap_config_open(l_chain_cfg_path) )) {
                log_it(L_ERROR, "Can't open chain config %s, skip it", l_dir_entry->d_name);
                continue;
            }
            HASH_ADD_KEYPTR(hh, l_all_chain_configs, l_chain_config->path, strlen(l_chain_config->path), l_chain_config);
        }
    }
    closedir(l_chains_dir);
    if (!l_all_chain_configs)
        return log_it(L_ERROR, "Can't find any chains for network %s", a_net->pub.name), -2;

    HASH_SORT(l_all_chain_configs, s_cmp_cfg_pri);
    dap_chain_t *l_chain;
    dap_chain_type_t *l_types_arr;
    char l_occupied_default_types[CHAIN_TYPE_MAX] = { 0 };
    int l_poa_signers = 0, l_poa_signers_min = 0;
    HASH_ITER(hh, l_all_chain_configs, l_chain_config, l_tmp_cfg) {
        if (( l_chain = dap_chain_load_from_cfg(a_net->pub.name, a_net->pub.id, l_chain_config) )) {
            DL_APPEND(a_net->pub.chains, l_chain);
            l_types_arr = l_chain->default_datum_types;
            uint16_t
                i = 0,
                k = l_chain->default_datum_types_count;
            for ( ; i < k; ++i) {
                if ( l_occupied_default_types[l_types_arr[i]] ) {
                    if ( i < k - 1 )
                        l_types_arr[i] = l_types_arr[k - 1];
                    --i;
                    --k;
                } else
                    l_occupied_default_types[l_types_arr[i]] = 1;
            }
            if ( k < l_chain->default_datum_types_count ) {
                l_chain->default_datum_types_count = k;
                l_chain->default_datum_types = DAP_REALLOC_COUNT(l_chain->default_datum_types, k);
            }
            if (l_chain->callback_load_from_gdb && a_ledger_flags) {
                *a_ledger_flags &= ~DAP_LEDGER_MAPPED;
                *a_ledger_flags |= DAP_LEDGER_THRESHOLD_ENABLED;
            }
            if ( l_chain->callback_get_poa_certs ) {
                uint16_t l_min_count = 0;
                a_net->pub.keys = dap_list_concat(a_net->pub.keys, l_chain->callback_get_poa_certs(l_chain, NULL, &l_min_count));
                a_net->pub.keys_min_count += l_min_count;
            }
        } else {
            HASH_DEL(l_all_chain_configs, l_chain_config);
            dap_config_close(l_chain_config);
            return -3;
        }
    }
    HASH_CLEAR(hh, l_all_chain_configs);
    return 0;
}

int s_chain_net_preload(dap_chain_net_t *a_net)
{
    dap_chain_srv_start(a_net->pub.id, DAP_CHAIN_SRV_STAKE_POS_DELEGATE_LITERAL, NULL);     // Harcoded core service starting for delegated keys storage

    uint16_t l_ledger_flags = 0;
    switch ( a_net->pub.node_role.enums ) {
    case NODE_ROLE_LIGHT:
        //break;
        a_net->pub.node_role.enums = NODE_ROLE_FULL; // TODO: implement light mode
    case NODE_ROLE_FULL:
        l_ledger_flags |= DAP_LEDGER_CHECK_LOCAL_DS;
        if (dap_config_get_item_bool_default(g_config, "ledger", "cache_enabled", false))
            l_ledger_flags |= DAP_LEDGER_CACHE_ENABLED;
    default:
        l_ledger_flags |= DAP_LEDGER_CHECK_CELLS_DS | DAP_LEDGER_CHECK_TOKEN_EMISSION;
    }
    if (dap_config_get_item_bool_default(g_config, "ledger", "mapped", true))
        l_ledger_flags |= DAP_LEDGER_MAPPED;

    int l_res = s_chains_init_all(a_net, a_net->pub.config->path, &l_ledger_flags);
    if (!l_res) {
        a_net->pub.ledger = dap_ledger_create(a_net, l_ledger_flags);
        dap_ledger_set_load_mode(a_net->pub.ledger, true);
        dap_ledger_set_fee_callback(a_net->pub.ledger, dap_chain_net_tx_set_fee);
    }
    
    return l_res;
    
}

/**
 * @brief load network config settings from cellframe-node.cfg file
 *
 * @param a_net_name const char *: network name, for example "home21-network"
 * @param a_acl_idx currently 0
 * @return int
 */
int s_net_init(const char *a_net_name, const char *a_path, uint16_t a_acl_idx)
{
    dap_config_t *l_cfg = dap_config_open(a_path);
    dap_return_val_if_fail_err(l_cfg, -1, "Can't open default network config %s", a_path);

    dap_chain_net_t *l_net = s_net_new(a_net_name, l_cfg);
    if ( !l_net )
        return log_it(L_ERROR, "Can't create net \"%s\"", a_net_name), dap_config_close(l_cfg), -1;

    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    l_net_pvt->acl_idx = a_acl_idx;
    // Transaction can be sent to bridged networks
    uint16_t l_net_ids_count = 0;
    const char **l_bridged_net_ids = dap_config_get_array_str(l_cfg, "general", "bridged_network_ids", &l_net_ids_count);
    if (l_net_ids_count) {
        l_net->pub.bridged_networks = DAP_NEW_Z_COUNT(dap_chain_net_id_t, l_net_ids_count);
        unsigned i, j;
        for (i = 0, j = 0; i < l_net_ids_count; ++i) {
            if (dap_chain_net_id_parse(l_bridged_net_ids[i], &l_net->pub.bridged_networks[j]) != 0) {
                log_it(L_ERROR, "Can't add invalid net id \"%s\" to bridged net list of \"%s\"",
                       l_bridged_net_ids[i], a_net_name);
                continue;
            }
            ++j;
        }
        l_net->pub.bridged_networks_count = j;
        if (j < i)
            l_net->pub.bridged_networks = j
                ? DAP_REALLOC_COUNT(l_net->pub.bridged_networks, j)
                : ( DAP_DELETE(l_net->pub.bridged_networks), NULL ); // No bridged nets is OK
    }

    // read nodes addrs and hosts
    if (
        dap_net_common_parse_stream_addrs(l_cfg, "general", "permanent_nodes_addrs", &l_net_pvt->permanent_links_addrs, &l_net_pvt->permanent_links_addrs_count)
     || s_nodes_hosts_init(l_net, l_cfg, "permanent_nodes_hosts", &l_net_pvt->permanent_links_hosts, &l_net_pvt->permanent_links_hosts_count)
     || s_nodes_hosts_init(l_net, l_cfg, "seed_nodes_hosts", &l_net_pvt->seed_nodes_hosts, &l_net_pvt->seed_nodes_count)
     || ( !l_net_pvt->seed_nodes_count && s_nodes_hosts_init(l_net, l_cfg, "bootstrap_hosts", &l_net_pvt->seed_nodes_hosts, &l_net_pvt->seed_nodes_count) )
    ) {
        dap_chain_net_delete(l_net);
        return -4;
    }
    if ( !l_net_pvt->seed_nodes_count )
        log_it(L_WARNING, "Can't read seed nodes addresses, work with local balancer only");

    if ( dap_server_enabled() && ( l_net_pvt->node_info->ext_port = dap_config_get_item_uint16(g_config, "server", "ext_port") ))
        log_it(L_INFO, "Set external port %u for adding in node list", l_net_pvt->node_info->ext_port);

    int l_ret = s_chain_net_preload(l_net);
    return l_ret ? dap_chain_net_delete(l_net), l_ret : 0;

}

static void *s_net_load(void *a_arg)
{
    dap_chain_net_t *l_net = a_arg;
    dap_return_val_if_fail_err(l_net->pub.config, NULL, "Can't open network %s config", l_net->pub.name);

    // Services register & configure
    char *l_services_path = dap_strdup_printf("%s/network/%s/services", dap_config_path(), l_net->pub.name);
    DIR *l_service_cfg_dir = opendir(l_services_path);
    DAP_DELETE(l_services_path);
    if (l_service_cfg_dir) {
        for ( struct dirent *l_dir_entry; ( l_dir_entry = readdir(l_service_cfg_dir) ); ) {
            const char *l_entry_name = l_dir_entry->d_name;
            size_t l_entry_len = strlen(l_entry_name);
            if (l_entry_len < 4 || // It has non zero name excluding file extension
                    strncmp(l_entry_name + l_entry_len - 4, ".cfg", 4) != 0) // its not a .cfg file
                continue;
            log_it(L_DEBUG, "Opening service config \"%s\"...", l_entry_name);
            char *l_service_cfg_path = dap_strdup_printf("network/%s/services/%s", l_net->pub.name, l_entry_name);
            dap_config_t *l_cfg_new = dap_config_open(l_service_cfg_path);
            if (l_cfg_new) {
                char l_service_name[l_entry_len - 3];
                dap_strncpy(l_service_name, l_entry_name, l_entry_len - 4);
                dap_chain_srv_start(l_net->pub.id, l_service_name, l_cfg_new);
                dap_config_close(l_cfg_new);
            }
            DAP_DELETE(l_service_cfg_path);
        }
        closedir(l_service_cfg_dir);
    }
    
    dap_chain_srv_start_all(l_net->pub.id);

    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    l_net_pvt->balancer_type = dap_config_get_item_bool_default(l_net->pub.config, "general", "use_dns_links", false);
    char l_gdb_groups_mask[DAP_GLOBAL_DB_GROUP_NAME_SIZE_MAX];
    dap_chain_t *l_chain;
    DL_FOREACH(l_net->pub.chains, l_chain) {
        if (s_load_skip)
            break;
        l_net->pub.fee_value = uint256_0;
        l_net->pub.fee_addr = c_dap_chain_addr_blank;
        int l_ret = dap_chain_load_all(l_chain);
        l_chain->atom_num_last = 0;
        switch ( l_net->pub.node_role.enums ) {
        case NODE_ROLE_ROOT_MASTER:
        /* Processes everything in mempool*/
            l_chain->is_datum_pool_proc = true;
            break;
        case NODE_ROLE_ROOT:
        /* Processes zerochain only */
            l_chain->is_datum_pool_proc = !l_chain->id.uint64;
            break;
        case NODE_ROLE_CELL_MASTER:
        case NODE_ROLE_MASTER: {
        /* Processes specified chains only */
            uint16_t k = 0;
            dap_chain_id_t l_chain_id;
            const char **l_proc_chains = dap_config_get_array_str(l_net->pub.config, "role-master", "proc_chains", &k);
            while (k--)
                l_chain->is_datum_pool_proc = ( !dap_chain_id_parse(l_proc_chains[k], &l_chain_id) && (l_chain->id.uint64 == l_chain_id.uint64) );
        } break;
        default: break;
        }
        // Personal chain mempool cluster for each chain
        snprintf(l_gdb_groups_mask, sizeof(l_gdb_groups_mask), "%s.chain-%s.mempool",
                                                               l_net->pub.gdb_groups_prefix, l_chain->name);
        dap_global_db_cluster_t *l_cluster = dap_global_db_cluster_add(
                                                dap_global_db_instance_get_default(), l_net->pub.name,
                                                dap_guuid_compose(l_net->pub.id.uint64, 0), l_gdb_groups_mask,
                                                dap_config_get_item_int32_default(l_net->pub.config, "global_db", "mempool_ttl", DAP_CHAIN_NET_MEMPOOL_TTL),
                                                true, DAP_GDB_MEMBER_ROLE_USER, DAP_CLUSTER_TYPE_EMBEDDED);
        dap_return_val_if_fail_err(l_cluster, NULL, "Net \"%s\" loading error %d: can't initialize mempool cluster",
                                                    l_net->pub.name, -2);
        dap_chain_net_add_auth_nodes_to_cluster(l_net, l_cluster);
        if (l_net->pub.chains == l_chain)   // Pointer for first mempool cluster in global double-linked list of clusters
            l_net_pvt->mempool_clusters = l_cluster;
    }
    dap_ledger_load_end(l_net->pub.ledger);
    log_it(L_INFO, "Node role \"%s\" established in net %s", dap_chain_node_role_to_str(l_net->pub.node_role), l_net->pub.name);
    l_net_pvt->state_target = NET_STATE_OFFLINE;

    // Init GlobalDB clusters for service and nodes (with aliases)
    // Service orders cluster
    snprintf(l_gdb_groups_mask, sizeof(l_gdb_groups_mask), "%s.service.orders", l_net->pub.gdb_groups_prefix);
    l_net_pvt->orders_cluster = dap_global_db_cluster_add(dap_global_db_instance_get_default(),
                                                          l_net->pub.name, dap_guuid_compose(l_net->pub.id.uint64, 0),
                                                          l_gdb_groups_mask, 0, true,
                                                          DAP_GDB_MEMBER_ROLE_GUEST,
                                                          DAP_CLUSTER_TYPE_EMBEDDED);
    dap_return_val_if_fail_err(l_net_pvt->orders_cluster, NULL, "Net \"%s\" loading error %d: can't initialize orders cluster",
                                                                l_net->pub.name, -3);
    dap_chain_net_add_auth_nodes_to_cluster(l_net, l_net_pvt->orders_cluster);
    // Common orders cluster
    snprintf(l_gdb_groups_mask, sizeof(l_gdb_groups_mask), "%s.orders*", l_net->pub.gdb_groups_prefix);
    l_net_pvt->common_orders = dap_global_db_cluster_add(dap_global_db_instance_get_default(),
                                                          l_net->pub.name, dap_guuid_compose(l_net->pub.id.uint64, 0),
                                                          l_gdb_groups_mask, 0, true,
                                                          DAP_GDB_MEMBER_ROLE_USER,
                                                          DAP_CLUSTER_TYPE_EMBEDDED);
    dap_return_val_if_fail_err(l_net_pvt->common_orders, NULL, "Net \"%s\" loading error %d: can't initialize common orders cluster",
                                                               l_net->pub.name, -4);
    dap_chain_net_add_auth_nodes_to_cluster(l_net, l_net_pvt->common_orders);
    // Node states cluster
    snprintf(l_gdb_groups_mask, sizeof(l_gdb_groups_mask), "%s.nodes.states", l_net->pub.gdb_groups_prefix);
    l_net_pvt->nodes_states = dap_global_db_cluster_add(dap_global_db_instance_get_default(),
                                                        l_net->pub.name, dap_guuid_compose(l_net->pub.id.uint64, 0),
                                                        l_gdb_groups_mask, DAP_CHAIN_NET_NODES_TTL, true,
                                                        DAP_GDB_MEMBER_ROLE_USER,
                                                        DAP_CLUSTER_TYPE_EMBEDDED);
    dap_return_val_if_fail_err(l_net_pvt->nodes_states, NULL, "Net \"%s\" loading error %d: can't initialize node states cluster",
                                                               l_net->pub.name, -5);
    // Nodes and its aliases cluster
    snprintf(l_net->pub.gdb_nodes, sizeof(l_net->pub.gdb_nodes), "%s.%s", l_net->pub.gdb_groups_prefix, s_gdb_nodes_postfix);
    l_net_pvt->nodes_cluster = dap_global_db_cluster_add(dap_global_db_instance_get_default(),
                                                         l_net->pub.name, dap_guuid_compose(l_net->pub.id.uint64, 0),
                                                         l_net->pub.gdb_nodes, 7200, true,
                                                         DAP_GDB_MEMBER_ROLE_GUEST,
                                                         DAP_CLUSTER_TYPE_EMBEDDED);
    dap_return_val_if_fail_err(l_net_pvt->nodes_cluster, NULL, "Net \"%s\" loading error %d: can't initialize nodes cluster",
                                                               l_net->pub.name, -6);
    dap_chain_net_add_auth_nodes_to_cluster(l_net, l_net_pvt->nodes_cluster);
    dap_chain_net_add_nodelist_notify_callback(l_net, s_nodelist_change_notify, l_net);

    if ( dap_link_manager_add_net(l_net->pub.id.uint64, l_net_pvt->nodes_cluster->links_cluster,
                                  dap_config_get_item_uint16_default(l_net->pub.config, "general", "links_required", 3)) )
        log_it(L_WARNING, "Can't add net %s to link manager", l_net->pub.name);

    DL_FOREACH(l_net->pub.chains, l_chain)
        dap_chain_cs_load(l_chain, l_net->pub.config);

    l_net_pvt->node_info->address.uint64 = g_node_addr.uint64;

    log_it(L_NOTICE, "Net load information: node_addr " NODE_ADDR_FP_STR ", seed links %u, cell_id 0x%016"DAP_UINT64_FORMAT_X,
           NODE_ADDR_FP_ARGS_S(g_node_addr),
           l_net_pvt->seed_nodes_count,
           l_net_pvt->node_info->cell_id.uint64);

    // TODO rework alias concept
    const char * l_node_addr_type = dap_config_get_item_str_default(l_net->pub.config ,
                                                                    "general", "node_addr_type", "auto");
    if ( !dap_strcmp(l_node_addr_type, "static") ) {
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
    dap_proc_thread_timer_add(NULL, s_sync_timer_callback, l_net, c_sync_timer_period);
    // TODO! Delete the timer in "purge()"
    log_it(L_INFO, "Network \"%s\" initialized", l_net->pub.name);
    l_net_pvt->state = NET_STATE_OFFLINE;
    return l_net;
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
    for (dap_chain_t *l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next){
        for (uint16_t i = 0; i < l_chain->authorized_nodes_count; i++)
            dap_global_db_cluster_member_add(a_cluster, l_chain->authorized_nodes_addrs + i, DAP_GDB_MEMBER_ROLE_ROOT);
    }
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
    return HASH_COUNT(s_nets_by_name);
}

dap_chain_net_t *dap_chain_net_iter_start() {
    return s_nets_by_name;
}

dap_chain_net_t *dap_chain_net_iter_next(dap_chain_net_t *a_it) {
    return a_it ? a_it->hh.next : NULL;
}

/**
 * @brief dap_chain_net_by_name
 * @param a_name
 * @return
 */
dap_chain_net_t *dap_chain_net_by_name(const char *a_name)
{
    dap_chain_net_t *l_net = NULL;
    if (a_name)
        HASH_FIND_STR(s_nets_by_name, a_name, l_net);
    return l_net;
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
    dap_chain_net_t *l_net = NULL;
    HASH_FIND(hh2, s_nets_by_id, &a_id, sizeof(a_id), l_net);
    return l_net;
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
            if(l_chain->datum_types[i] == a_datum_type) {
                dap_chain_cs_callbacks_t *l_mp_cbs = dap_chain_cs_get_callbacks(l_chain);
                return dap_chain_mempool_group_name(a_net->pub.gdb_groups_prefix, l_chain->name);
            }
        }
    }
    return NULL;
}

/**
 * @brief dap_chain_net_get_state
 * @param l_net
 * @return
 */
DAP_INLINE dap_chain_net_state_t dap_chain_net_get_state (dap_chain_net_t *a_net)
{
    return PVT(a_net)->state;
}

dap_chain_cell_id_t *dap_chain_net_get_cur_cell( dap_chain_net_t *a_net)
{
    return  PVT(a_net)->node_info ? &PVT(a_net)->node_info->cell_id: 0;
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
    dap_return_val_if_pass(!a_datum, -10);
    dap_return_val_if_pass(!a_chain, -11);
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    switch (a_datum->header.type_id) {
    case DAP_CHAIN_DATUM_TX:
        if (a_datum->header.data_size < sizeof(dap_chain_datum_tx_t))
            return -156;
        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)a_datum->data;
        if (!dap_strcmp(dap_chain_get_cs_type(a_chain), "esbocs")) {
            uint256_t l_tx_fee = {};
            if (!dap_chain_datum_tx_get_fee_value(l_tx, &l_tx_fee) && !IS_ZERO_256(l_tx_fee)) {
                uint256_t l_min_fee = dap_chain_esbocs_get_fee(a_chain->net_id);
                if (compare256(l_tx_fee, l_min_fee) < 0) {
                    const char *l_tx_fee_str; dap_uint256_to_char(l_tx_fee, &l_tx_fee_str);
                    const char *l_min_fee_str; dap_uint256_to_char(l_min_fee, &l_min_fee_str);
                    log_it(L_WARNING, "Fee %s is lower than minimum fee %s for tx %s",
                           l_tx_fee_str, l_min_fee_str, dap_get_data_hash_str(l_tx, dap_chain_datum_tx_get_size(l_tx)).s);
                    return DAP_CHAIN_CS_VERIFY_CODE_NOT_ENOUGH_FEE;
                }
            } else {
                if (!dap_ledger_tx_poa_signed(l_net->pub.ledger, l_tx)) {
                    log_it(L_WARNING, "Can't get fee value from tx %s", dap_get_data_hash_str(l_tx, dap_chain_datum_tx_get_size(l_tx)).s);
                    return -157;
                }
                log_it(L_DEBUG, "Process service tx without fee");
            }
        }
        return dap_ledger_tx_add_check(l_net->pub.ledger, l_tx, a_datum->header.data_size, a_datum_hash);
    case DAP_CHAIN_DATUM_TOKEN:
        if (a_datum->header.data_size < sizeof(dap_chain_datum_token_t))
            return -156;
        return dap_ledger_token_add_check(l_net->pub.ledger, a_datum->data, a_datum->header.data_size);
    case DAP_CHAIN_DATUM_TOKEN_EMISSION:
        if (a_datum->header.data_size < sizeof(dap_chain_datum_token_emission_t))
            return -156;
        return dap_ledger_token_emission_add_check(l_net->pub.ledger, a_datum->data, a_datum->header.data_size, a_datum_hash);
    case DAP_CHAIN_DATUM_DECREE:
        return dap_ledger_decree_verify(l_net, (dap_chain_datum_decree_t *)a_datum->data, a_datum->header.data_size, a_datum_hash);
    case DAP_CHAIN_DATUM_ANCHOR:
        return dap_ledger_anchor_verify(l_net, (dap_chain_datum_anchor_t *)a_datum->data, a_datum->header.data_size);
    default:
        if (a_chain->callback_datum_find_by_hash &&
                a_chain->callback_datum_find_by_hash(a_chain, a_datum_hash, NULL, NULL))
            return -1;
    }
    return 0;
}

const char *dap_chain_net_verify_datum_err_code_to_str(dap_chain_datum_t *a_datum, int a_code)
{
    switch (a_datum->header.type_id) {
    case DAP_CHAIN_DATUM_TX:
    case DAP_CHAIN_DATUM_TOKEN:
    case DAP_CHAIN_DATUM_TOKEN_EMISSION:
        return dap_ledger_check_error_str(a_code);
    default:
        return !a_code ? "DAP_CHAIN_DATUM_VERIFY_OK" : "UNKNOWN_ERROR";

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
        const char **l_acl_list = dap_config_get_array_str(a_net->pub.config, "auth", "acl_accept_ca_list", &l_acl_list_len);
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
    uint16_t l_cnt = HASH_COUNT(s_nets_by_name);
    if ( !l_cnt )
        return NULL;
    uint8_t *l_ret = DAP_NEW_Z_COUNT(uint8_t, l_cnt);
    unsigned i = 0;
    for (dap_chain_net_t *l_net = s_nets_by_name; l_net; l_net = l_net->hh.next)
        l_ret[i++] = s_net_check_acl(l_net, a_pkey_hash);
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

static int s_load_state_from_datum(dap_chain_net_id_t a_net_id, dap_chain_datum_t *a_datum, dap_hash_fast_t *a_datum_hash)
{
    dap_chain_datum_service_state_t *l_state = (dap_chain_datum_service_state_t *)a_datum->data;
    return dap_chain_srv_load_state(a_net_id, l_state->srv_uid, l_state->states, l_state->state_size, l_state->states_count);
}

/**
 * @brief Add datum to the ledger or smth else
 * @param a_chain
 * @param a_datum
 * @param a_datum_size
 * @return
 */
int dap_chain_datum_add(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, size_t a_datum_size, dap_hash_fast_t *a_datum_hash, void *a_datum_index_data)
{
    size_t l_datum_data_size = a_datum->header.data_size;
    if (a_datum_size != l_datum_data_size + sizeof(a_datum->header)) {
        log_it(L_INFO,"Corrupted datum rejected: wrong size %zd not equal datum size %zd", l_datum_data_size + sizeof(a_datum->header),
               a_datum_size );
        return -101;
    }
    dap_ledger_t *l_ledger = dap_chain_net_by_id(a_chain->net_id)->pub.ledger;
    if ( dap_ledger_datum_is_enforced(l_ledger, a_datum_hash, false) )
        return log_it(L_ERROR, "Datum %s is blacklisted", dap_hash_fast_to_str_static(a_datum_hash)), -100;
    switch (a_datum->header.type_id) {
        case DAP_CHAIN_DATUM_DECREE: {
            dap_chain_datum_decree_t *l_decree = (dap_chain_datum_decree_t *)a_datum->data;
            size_t l_decree_size = dap_chain_datum_decree_get_size(l_decree);
            if (l_decree_size != l_datum_data_size) {
                log_it(L_WARNING, "Corrupted decree %s, datum size %zd is not equal to size of decree %zd",
                                            dap_hash_fast_to_str_static(a_datum_hash), l_datum_data_size, l_decree_size);
                return -102;
            }
            return dap_ledger_decree_load(l_decree, a_chain, a_datum_hash);
        }
        case DAP_CHAIN_DATUM_ANCHOR: {
            dap_chain_datum_anchor_t *l_anchor = (dap_chain_datum_anchor_t *)a_datum->data;
            size_t l_anchor_size = dap_chain_datum_anchor_get_size(l_anchor);
            if (l_anchor_size != l_datum_data_size) {
                log_it(L_WARNING, "Corrupted anchor %s, datum size %zd is not equal to size of anchor %zd",
                                            dap_hash_fast_to_str_static(a_datum_hash), l_datum_data_size, l_anchor_size);
                return -102;
            }
            return dap_ledger_anchor_load(l_anchor, a_chain, a_datum_hash);
        }
        case DAP_CHAIN_DATUM_TOKEN:
            return dap_ledger_token_load(l_ledger, a_datum->data, a_datum->header.data_size, a_datum->header.ts_create);

        case DAP_CHAIN_DATUM_TOKEN_EMISSION:
            return dap_ledger_token_emission_load(l_ledger, a_datum->data, a_datum->header.data_size, a_datum_hash);

        case DAP_CHAIN_DATUM_TX: {
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)a_datum->data;
            size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
            if (l_tx_size != l_datum_data_size) {
                log_it(L_WARNING, "Corrupted transaction %s, datum size %zd is not equal to size of TX %zd",
                                            dap_hash_fast_to_str_static(a_datum_hash), l_datum_data_size, l_tx_size);
                return -102;
            }
            dap_sign_t *l_sig = dap_chain_datum_tx_get_sign(l_tx, 0);
            if (l_sig && dap_sign_type_is_deprecated(l_sig->header.type)){
                dap_chain_addr_t l_addr = {};
                dap_chain_addr_fill_from_sign(&l_addr, l_sig, a_chain->net_id);
                log_it(L_WARNING, "Depricated\nsign type: %s\naddress: %s\nnet: %s\ndatum: %s", dap_sign_type_to_str(l_sig->header.type), dap_chain_addr_to_str_static(&l_addr), a_chain->net_name, dap_chain_hash_fast_to_str_static(a_datum_hash));
            }
            return dap_ledger_tx_load(l_ledger, l_tx, a_datum_hash, (dap_ledger_datum_iter_data_t*)a_datum_index_data);
        }
        case DAP_CHAIN_DATUM_CA:
            return dap_cert_chain_file_save(a_datum, a_chain->net_name);
        case DAP_CHAIN_DATUM_SERVICE_STATE:
            return l_ledger->is_hardfork_state ? s_load_state_from_datum(a_chain->net_id, a_datum, a_datum_hash) : -601;
        case DAP_CHAIN_DATUM_SIGNER:
        case DAP_CHAIN_DATUM_CUSTOM:
            break;
        default:
            return -600;
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
            return dap_ledger_anchor_unload(l_anchor, a_chain, a_datum_hash);
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

DAP_INLINE bool dap_chain_net_get_load_mode(dap_chain_net_t * a_net)
{
    return PVT(a_net)->state == NET_STATE_LOADING;
}

int dap_chain_net_add_reward(dap_chain_net_t *a_net, uint256_t a_reward, uint64_t a_block_num)
{
    dap_return_val_if_fail(a_net, -1);
    if (PVT(a_net)->rewards && PVT(a_net)->rewards->block_number >= a_block_num) {
        log_it(L_ERROR, "Can't add retrospective reward for block");
        return -2;
    }
    struct block_reward *l_new_reward = DAP_NEW_Z_RET_VAL_IF_FAIL(struct block_reward, -3);
    l_new_reward->block_number = a_block_num;
    l_new_reward->reward = a_reward;
    // Place new reward at begining
    DL_PREPEND(PVT(a_net)->rewards, l_new_reward);
    return 0;
}

void dap_chain_net_remove_last_reward(dap_chain_net_t *a_net)
{
    struct block_reward *l_last_reward = PVT(a_net)->rewards;
    DL_DELETE(PVT(a_net)->rewards, l_last_reward);
    DAP_DELETE(l_last_reward);
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


void dap_chain_net_announce_addr_all(UNUSED_ARG void *arg)
{
    for (dap_chain_net_t *net = s_nets_by_name; net; net = net->hh.next)
        dap_chain_net_announce_addr(net);
}

void dap_chain_net_announce_addr(dap_chain_net_t *a_net)
{
    dap_return_if_fail(a_net);
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
    if ( l_net_pvt->node_info->ext_port && a_net->pub.node_role.enums >= NODE_ROLE_MASTER ) {
        log_it(L_INFO, "Announce our node address "NODE_ADDR_FP_STR" [ %s : %u ] in net %s",
               NODE_ADDR_FP_ARGS_S(g_node_addr),
               l_net_pvt->node_info->ext_host,
               l_net_pvt->node_info->ext_port, a_net->pub.name);
        dap_chain_net_node_list_request(a_net, l_net_pvt->node_info->ext_port, true, 'a');
    }
}

/*------------------------------------State machine block------------------------------------*/

/**
 * @brief try net to go online
 * @param a_net dap_chain_net_t *: network 
 * @return 0 if ok
 **/
static int s_net_try_online(dap_chain_net_t *a_net)
{
// sanity check
    dap_return_val_if_pass(!a_net || !PVT(a_net), -1);
// func work
    log_it(L_INFO, "Network \"%s\" goes online",a_net->pub.name);
    return dap_chain_net_state_go_to(a_net, NET_STATE_ONLINE);
}

/**
 * @brief
 * change all network states according to auto-online settings
 */
void dap_chain_net_try_online_all() {
    int32_t l_ret = 0;

    if( !HASH_COUNT(s_nets_by_name) )
        return log_it(L_ERROR, "Can't find any nets");

    if ( !dap_config_get_item_bool_default(g_config ,"general", "auto_online", false) )
        return log_it(L_DEBUG, "Auto online is off in config");

    for (dap_chain_net_t *net = s_nets_by_name; net; net = net->hh.next) {
        if (( l_ret = s_net_try_online(net) ))
            log_it(L_ERROR, "Can't try online state for net %s.  Finished with (%d) error code.", net->pub.name, l_ret);
    }
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
        if (!l_net_pvt->sync_context.cur_chain) {
            log_it(L_DEBUG, "Got ERROR paket with NO chain net %s", l_net->pub.name);
            return;
        }
        log_it(L_DEBUG, "Got ERROR paket to %s chain in net %s", l_net_pvt->sync_context.cur_chain->name, l_net->pub.name);
        l_net_pvt->sync_context.cur_chain->state = CHAIN_SYNC_STATE_ERROR;
        return;

    case DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN:
        if (!l_net_pvt->sync_context.cur_chain) {
            log_it(L_DEBUG, "Got SYNCED_CHAIN paket with NO chain net %s", l_net->pub.name);
            return;
        }
        log_it(L_DEBUG, "Got SYNCED_CHAIN paket to %s chain net %s", l_net_pvt->sync_context.cur_chain->name, l_net->pub.name);
        l_net_pvt->sync_context.cur_chain->state = CHAIN_SYNC_STATE_SYNCED;
        l_net_pvt->sync_context.cur_chain->atom_num_last = l_net_pvt->sync_context.cur_chain->callback_count_atom(l_net_pvt->sync_context.cur_chain);
        return;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS: {
        if (!l_net_pvt->sync_context.cur_chain)
            return;
        dap_chain_ch_miss_info_t *l_miss_info = (dap_chain_ch_miss_info_t *)(((dap_chain_ch_pkt_t *)(a_data))->data);
        if (!dap_hash_fast_compare(&l_miss_info->missed_hash, &l_net_pvt->sync_context.requested_atom_hash)) {
            char l_missed_hash_str[DAP_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_miss_info->missed_hash, l_missed_hash_str, DAP_HASH_FAST_STR_SIZE);
            log_it(L_WARNING, "Get irrelevant chain sync MISSED packet with missed hash %s, but requested hash is %s. Net %s chain %s",
                                                                        l_missed_hash_str,
                                                                        dap_hash_fast_to_str_static(&l_net_pvt->sync_context.requested_atom_hash),
                                                                        l_net->pub.name, l_net_pvt->sync_context.cur_chain->name);
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
            l_net_pvt->sync_context.cur_chain->state = CHAIN_SYNC_STATE_SYNCED;
            l_net_pvt->sync_context.cur_chain->atom_num_last = l_miss_info->last_num;
            return;
        }
        dap_chain_ch_sync_request_t l_request = { .generation = l_net_pvt->sync_context.cur_chain->generation };
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
                                      l_request.generation ? sizeof(l_request) : sizeof(dap_chain_ch_sync_request_old_t),
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

    dap_chain_net_t *l_net = a_arg;
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    if (!l_net_pvt->sync_context.cur_chain)
        return;
    switch (a_type) {
    case DAP_CHAIN_CH_PKT_TYPE_ERROR:
        l_net_pvt->sync_context.cur_chain->state = CHAIN_SYNC_STATE_ERROR;
        break;
    default:
        break;
    }
    debug_if(s_debug_more, L_DEBUG, "Sent OUT sync packet type %hhu size %zu to addr " NODE_ADDR_FP_STR,
                                    a_type, a_data_size, NODE_ADDR_FP_ARGS_S(a_ch->stream->node));
}


static int s_restart_sync_chains(dap_chain_net_t *a_net)
{
    // sanity check
    dap_return_val_if_pass(!a_net || !PVT(a_net), -1);
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);

    dap_cluster_t *l_cluster = dap_cluster_by_mnemonim(a_net->pub.name);
    if (!dap_stream_node_addr_is_blank(&l_net_pvt->sync_context.current_link)) {
        dap_stream_ch_del_notifier(&l_net_pvt->sync_context.current_link, DAP_CHAIN_CH_ID,
                                    DAP_STREAM_PKT_DIR_IN, s_ch_in_pkt_callback, a_net);
        dap_stream_ch_del_notifier(&l_net_pvt->sync_context.current_link, DAP_CHAIN_CH_ID,
                                    DAP_STREAM_PKT_DIR_OUT, s_ch_out_pkt_callback, a_net);
    }
    l_net_pvt->sync_context.current_link = dap_cluster_get_random_link(l_cluster);
    if (dap_stream_node_addr_is_blank(&l_net_pvt->sync_context.current_link)) {
        log_it(L_DEBUG, "No links in net %s cluster", a_net->pub.name);
        return -2;     // No links in cluster
    }
    l_net_pvt->sync_context.cur_chain = a_net->pub.chains;
    if (!l_net_pvt->sync_context.cur_chain) {
        log_it(L_ERROR, "No chains in net %s", a_net->pub.name);
        return -3;
    }
    dap_stream_ch_add_notifier(&l_net_pvt->sync_context.current_link, DAP_CHAIN_CH_ID,
                                DAP_STREAM_PKT_DIR_IN, s_ch_in_pkt_callback, a_net);
    dap_stream_ch_add_notifier(&l_net_pvt->sync_context.current_link, DAP_CHAIN_CH_ID,
                                DAP_STREAM_PKT_DIR_OUT, s_ch_out_pkt_callback, a_net);
    dap_chain_t *l_chain = NULL;
    DL_FOREACH(a_net->pub.chains, l_chain) {
        l_chain->state = CHAIN_SYNC_STATE_IDLE;
    }
    l_net_pvt->sync_context.stage_last_activity = dap_time_now();
    return 0;
}

static dap_chain_t *s_switch_sync_chain(dap_chain_net_t *a_net)
{
// sanity check
    dap_return_val_if_pass(!a_net || !PVT(a_net), NULL);
    dap_chain_net_pvt_t *l_net_pvt = PVT(a_net);
// func work
    dap_chain_t *l_curr_chain = NULL;
    for (l_curr_chain = a_net->pub.chains; l_curr_chain && l_curr_chain->state == CHAIN_SYNC_STATE_SYNCED; l_curr_chain = l_curr_chain->next) {
        // find last not synced chain
    }
    l_net_pvt->sync_context.cur_chain = l_curr_chain;
    if (l_curr_chain) {
        debug_if(s_debug_more, L_DEBUG, "Go to chain \"%s\" for net %s", l_curr_chain->name, l_curr_chain->net_name);
        return l_curr_chain;
    }
    debug_if(s_debug_more, L_DEBUG, "Go to next chain: <NULL>");
    if (l_net_pvt->state_target != NET_STATE_ONLINE) {
        dap_chain_net_state_go_to(a_net, NET_STATE_OFFLINE);
        return NULL;
    }
    dap_chain_net_state_t l_prev_state = l_net_pvt->state;
    l_net_pvt->state = NET_STATE_ONLINE;
    s_net_states_proc(a_net);
    if(l_prev_state == NET_STATE_SYNC_CHAINS)
        dap_ledger_load_end(a_net->pub.ledger);
    return NULL;
}

static dap_chain_sync_state_t s_sync_context_state_forming(dap_chain_t *a_chains)
{
    dap_chain_sync_state_t l_ret = CHAIN_SYNC_STATE_SYNCED;
    dap_chain_t *l_chain = NULL;
    DL_FOREACH(a_chains, l_chain) {
        l_ret = dap_max(l_ret, l_chain->state);
    }
    return l_ret;
}

static void s_sync_timer_callback(void *a_arg)
{
    dap_chain_net_t *l_net = a_arg;
    dap_chain_net_pvt_t *l_net_pvt = PVT(l_net);
    if (l_net_pvt->state_target == NET_STATE_OFFLINE) // if offline no need sync
        return;
    l_net_pvt->sync_context.state = s_sync_context_state_forming(l_net->pub.chains);
    if ( // check if need restart sync chains
        l_net_pvt->sync_context.state == CHAIN_SYNC_STATE_ERROR ||
        dap_time_now() - l_net_pvt->sync_context.stage_last_activity > l_net_pvt->sync_context.sync_idle_time
    ) {
        if (s_restart_sync_chains(l_net)) {
            log_it(L_INFO, "Can't start sync chains in net %s, wait next attempt", l_net->pub.name);
            return;
        }
    } else if (l_net_pvt->state == NET_STATE_ONLINE && l_net_pvt->sync_context.state == CHAIN_SYNC_STATE_SYNCED) {
        return;
    }
    if (!s_switch_sync_chain(l_net)) {  // return if all chans synced
        log_it(L_DEBUG, "All chains in net %s synced, no need new sync request", l_net->pub.name);
        return;
    }
    if (l_net_pvt->sync_context.cur_chain->state == CHAIN_SYNC_STATE_WAITING) {
        return;
    }
    if (l_net_pvt->sync_context.cur_chain->callback_load_from_gdb) {
        // This type of chain is GDB based and not synced by chains protocol
        log_it(L_DEBUG, "Chain %s in net %s will sync from gdb", l_net_pvt->sync_context.cur_chain->name, l_net->pub.name);
        l_net_pvt->sync_context.cur_chain->state = CHAIN_SYNC_STATE_SYNCED;
        return;
    }
    // if sync more than 3 mins after online state, change state to SYNC
    if (l_net_pvt->state == NET_STATE_ONLINE && l_net_pvt->sync_context.state == CHAIN_SYNC_STATE_WAITING &&
        dap_time_now() - l_net_pvt->sync_context.stage_last_activity > l_net_pvt->sync_context.sync_idle_time ) {
        l_net_pvt->state = NET_STATE_SYNC_CHAINS;
        s_net_states_proc(l_net);
    }

    l_net_pvt->sync_context.cur_cell = l_net_pvt->sync_context.cur_chain->cells;
    l_net_pvt->sync_context.cur_chain->state = CHAIN_SYNC_STATE_WAITING;
    dap_chain_ch_sync_request_t l_request = { .generation = l_net_pvt->sync_context.cur_chain->generation};
    uint64_t l_last_num = 0;
    if (!dap_chain_get_atom_last_hash_num_ts(l_net_pvt->sync_context.cur_chain,
                                            l_net_pvt->sync_context.cur_cell
                                            ? l_net_pvt->sync_context.cur_cell->id
                                            : c_dap_chain_cell_id_null,
                                            &l_request.hash_from,
                                            &l_last_num,
                                            NULL)) {
        log_it(L_ERROR, "Can't get last atom hash and number for chain %s with net %s", l_net_pvt->sync_context.cur_chain->name,
                                                                                        l_net->pub.name);
        return;
    }
    l_request.num_from = l_last_num;

    dap_chain_ch_pkt_t *l_chain_pkt = dap_chain_ch_pkt_new(l_net->pub.id, l_net_pvt->sync_context.cur_chain->id,
                                                            l_net_pvt->sync_context.cur_cell ? l_net_pvt->sync_context.cur_cell->id : c_dap_chain_cell_id_null,
                                                            &l_request, l_request.generation ? sizeof(l_request) : sizeof(dap_chain_ch_sync_request_old_t),
                                                            DAP_CHAIN_CH_PKT_VERSION_CURRENT);
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
    l_net_pvt->sync_context.requested_atom_num = l_last_num;
    DAP_DELETE(l_chain_pkt);
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
        if(l_net_pvt->state == NET_STATE_SYNC_CHAINS)
            dap_ledger_load_end(l_net->pub.ledger);
        l_net_pvt->state = NET_STATE_OFFLINE;
    }

    switch ((dap_chain_net_state_t)l_net_pvt->state) {
        // State OFFLINE where we don't do anything
        case NET_STATE_OFFLINE: {
            log_it(L_NOTICE,"%s.state: %s", l_net->pub.name, c_net_states[l_net_pvt->state]);
            // delete all links
            if ( l_net_pvt->state_target != NET_STATE_OFFLINE ){
                l_net_pvt->state = NET_STATE_LINKS_PREPARE;
                l_repeat_after_exit = true;
            }
        } break;

        case NET_STATE_LINKS_PREPARE:
        case NET_STATE_LINKS_CONNECTING:
        case NET_STATE_LINKS_ESTABLISHED:
        case NET_STATE_SYNC_CHAINS:
        case NET_STATE_ONLINE:
            log_it(L_INFO,"%s.state: %s", l_net->pub.name, c_net_states[l_net_pvt->state]);
            break;
        default:
            log_it(L_DEBUG, "Unprocessed state");
    }
    s_net_states_notify(l_net);
    return l_repeat_after_exit;
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
    if (dap_chain_net_get_load_mode(a_net)) {
        log_it(L_ERROR, "Can't change state of loading network '%s'", a_net->pub.name);
        return -1;
    }
    if (PVT(a_net)->state_target == a_new_state) {
        log_it(L_NOTICE, "Network %s already %s state %s", a_net->pub.name,
                                PVT(a_net)->state == a_new_state ? "have" : "going to", dap_chain_net_state_to_str(a_new_state));
        return 0;
    }
    dap_chain_t *l_chain;
    //PVT(a_net)->flags |= F_DAP_CHAIN_NET_SYNC_FROM_ZERO;  // TODO set this flag according to -mode argument from command line
    PVT(a_net)->state_target = a_new_state;
    if (a_new_state == NET_STATE_SYNC_CHAINS) {
        dap_ledger_set_syncing_state(a_net->pub.ledger, true);
    } else {
        dap_ledger_set_syncing_state(a_net->pub.ledger, false);
    }
    if (a_new_state == NET_STATE_LOADING) {
        dap_ledger_set_load_mode(a_net->pub.ledger, true);
    } else {
        dap_ledger_set_load_mode(a_net->pub.ledger, false);
    }
    if (a_new_state == NET_STATE_OFFLINE) {
        char l_err_str[] = "ERROR_NET_IS_OFFLINE";
        size_t l_error_size = sizeof(dap_chain_net_ch_pkt_t) + sizeof(l_err_str);
        dap_chain_net_ch_pkt_t *l_error = DAP_NEW_STACK_SIZE(dap_chain_net_ch_pkt_t, l_error_size);
        l_error->hdr.version = DAP_STREAM_CH_CHAIN_NET_PKT_VERSION;
        l_error->hdr.net_id = a_net->pub.id;
        l_error->hdr.data_size = sizeof(l_err_str);
        memcpy(l_error->data, l_err_str, sizeof(l_err_str));
        dap_cluster_broadcast(PVT(a_net)->nodes_cluster->links_cluster, DAP_CHAIN_NET_CH_ID,
                              DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR, l_error, l_error_size, NULL, 0);
        dap_link_manager_set_net_condition(a_net->pub.id.uint64, false);
        DL_FOREACH(a_net->pub.chains, l_chain)
            dap_chain_cs_stop(l_chain);
    } else if (PVT(a_net)->state == NET_STATE_OFFLINE) {
        dap_link_manager_set_net_condition(a_net->pub.id.uint64, true);
        uint16_t l_permalink_hosts_count = 0;
        dap_config_get_array_str(a_net->pub.config, "general", "permanent_nodes_hosts", &l_permalink_hosts_count);
        for (uint16_t i = 0; i < PVT(a_net)->permanent_links_addrs_count; ++i) {
            if (dap_chain_net_link_add(a_net, PVT(a_net)->permanent_links_addrs + i,
                i < PVT(a_net)->permanent_links_hosts_count ? (PVT(a_net)->permanent_links_hosts[i])->addr : NULL,
                i < PVT(a_net)->permanent_links_hosts_count ? (PVT(a_net)->permanent_links_hosts[i])->port : 0)
             ) {
                log_it(L_ERROR, "Can't create permanent link to addr " NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS(PVT(a_net)->permanent_links_addrs + i));
                continue;
            }
            PVT(a_net)->state = NET_STATE_LINKS_CONNECTING;
        }
        if (a_new_state == NET_STATE_ONLINE) {        
            PVT(a_net)->sync_context.current_link.uint64 = 0;
            PVT(a_net)->sync_context.cur_chain = NULL;
            PVT(a_net)->sync_context.cur_cell = NULL;
            DL_FOREACH(a_net->pub.chains, l_chain)
                dap_chain_cs_start(l_chain);
        }
    }
    return dap_proc_thread_callback_add(NULL, s_net_states_proc, a_net);
}

DAP_INLINE dap_chain_net_state_t dap_chain_net_get_target_state(dap_chain_net_t *a_net)
{
    return PVT(a_net)->state_target;
}

bool dap_chain_net_stop(dap_chain_net_t *a_net)
{
    int l_attempts_count = 0;
    if ( dap_chain_net_get_target_state(a_net) == NET_STATE_ONLINE || dap_chain_net_get_state(a_net) != NET_STATE_OFFLINE )
        dap_chain_net_state_go_to(a_net, NET_STATE_OFFLINE);

    while (dap_chain_net_get_state(a_net) != NET_STATE_OFFLINE && l_attempts_count++ < 5) {
        sched_yield();
        sleep(1);
    }
    return dap_chain_net_get_state(a_net) == NET_STATE_OFFLINE;
}

/*------------------------------------State machine block end---------------------------------*/


bool dap_chain_net_is_bridged(dap_chain_net_t *a_net, dap_chain_net_id_t a_net_id)
{
    dap_return_val_if_pass(!a_net, false);
    // null  addr always pass
    if (!a_net_id.uint64 || a_net->pub.id.uint64 == a_net_id.uint64)
        return true;
    if (!a_net->pub.bridged_networks_count)
        return false;
    bool l_ret = false;
    for(uint16_t i = 0; i < a_net->pub.bridged_networks_count && !l_ret; ++i) {
            l_ret = a_net->pub.bridged_networks[i].uint64 == a_net_id.uint64;
    }
    return l_ret;
}

DAP_INLINE void dap_chain_net_set_load_skip()
{
    s_load_skip = true;
}