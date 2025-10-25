/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
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

// Platform-specific TUN device management is now in platform/ subdirectories
#include <netinet/in.h>
#include <netinet/ip.h>

#ifdef DAP_OS_BSD
typedef struct ip dap_os_iphdr_t;
#else
typedef struct iphdr dap_os_iphdr_t;
#endif


#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>

#include "uthash.h"
#include "utlist.h"

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_config.h"
#include "dap_context.h"
#include "dap_events_socket.h"
#include "dap_http_client.h"

#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_pkt.h"

#include "dap_chain_net.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_client.h"
#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_srv_stream_session.h"
#include "dap_chain_net_vpn_client.h"
#include "dap_chain_net_vpn_client_tun.h"
#include "dap_chain_net_srv_vpn_cmd.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_ledger.h"
#include "dap_events.h"
#include "dap_chain_net_srv_vpn_addr_pool.h"

#include "dap_http_simple.h"
#include "http_status_code.h"
#include "json-c/json.h"
#include "dap_chain_net_srv_vpn_traffic.h"
#include "dap_chain_net_srv_vpn_multihop.h"
#include "dap_chain_net_srv_vpn_tsd.h"
#include "tun/include/dap_net_tun.h"

#include "dap_chain_net_srv_vpn_internal.h"
#include "dap_chain_net_srv_vpn_callbacks.h"
#include "dap_chain_net_srv_vpn_stream.h"
#include "dap_chain_net_srv_vpn_tun.h"
#include "dap_chain_net_srv_vpn_session.h"
#include "dap_chain_net_srv_vpn_limits.h"

#define LOG_TAG "dap_chain_net_srv_vpn"

#define SF_MAX_EVENTS 256

// NOTE: VPN custom data structure and vpn_local_network defined in dap_chain_net_srv_vpn_internal.h

// Message for QUEUE_PTR operations
typedef struct tun_socket_msg{
    enum{
        TUN_SOCKET_MSG_NONE,
        TUN_SOCKET_MSG_IP_ASSIGNED,
        TUN_SOCKET_MSG_IP_UNASSIGNED,
        TUN_SOCKET_MSG_CH_VPN_SEND,
        TUN_SOCKET_MSG_ESOCKET_REASSIGNED,
    } type;
    dap_chain_net_srv_ch_vpn_t * ch_vpn;
    dap_events_socket_t * esocket;
    dap_events_socket_uuid_t esocket_uuid;
    bool is_reassigned_once;
    union{
        struct{ // Esocket reassigment
            uint32_t worker_id;
            struct in_addr addr;
        } esocket_reassigment;
        struct{  // IP assign/unassign
            uint32_t worker_id;
            struct in_addr addr;
            uint32_t usage_id;
        } ip_assigment;
        struct{  // IP assign/unassign
            uint32_t worker_id;
            struct in_addr addr;
        } ip_unassigment;
        struct{ // CH VPN send operation
            dap_stream_ch_vpn_pkt_t * pkt;
        } ch_vpn_send;
    };
} tun_socket_msg_t;

// Global variables (defined here, declared as extern in dap_chain_net_srv_vpn_internal.h)
dap_net_tun_t *g_vpn_tun_handle = NULL;
dap_chain_net_srv_vpn_tun_socket_t **g_vpn_tun_sockets = NULL;
dap_events_socket_t **g_vpn_tun_sockets_queue_msg = NULL;
pthread_mutex_t g_vpn_tun_sockets_mutex_started = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_vpn_tun_sockets_cond_started = PTHREAD_COND_INITIALIZER;
uint32_t g_vpn_tun_sockets_started = 0;
uint32_t g_vpn_tun_sockets_count = 0;
bool g_vpn_debug_more = false;

dap_chain_net_srv_ch_vpn_t *g_vpn_ch_vpn_addrs = NULL;
pthread_rwlock_t g_vpn_clients_rwlock = PTHREAD_RWLOCK_INITIALIZER;

vpn_local_network_t *g_vpn_raw_server = NULL;
pthread_rwlock_t g_vpn_raw_server_rwlock = PTHREAD_RWLOCK_INITIALIZER;

dap_chain_net_srv_vpn_addr_pool_t *g_vpn_addr_pool = NULL;

// Callback wrappers - delegate to modular implementations
static int s_callback_requested(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t * a_srv_client
                                    , const void * a_custom_data, size_t a_custom_data_size )
{
    return vpn_srv_callback_requested(a_srv, a_usage_id, a_srv_client, a_custom_data, a_custom_data_size);
}

static int s_callback_response_success(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t * a_srv_client
                                    , const void * a_request, size_t a_request_size )
{
    return vpn_srv_callback_response_success(a_srv, a_usage_id, a_srv_client, a_request, a_request_size);
}

static int s_callback_receipt_next_success(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t * a_srv_client,
                    const void * a_receipt_next, size_t a_receipt_next_size)
{
    return vpn_srv_callback_receipt_next_success(a_srv, a_usage_id, a_srv_client, a_receipt_next, a_receipt_next_size);
}

static int s_callback_response_error(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t * a_srv_client
                                    , const void * a_custom_data, size_t a_custom_data_size )
{
    return vpn_srv_callback_response_error(a_srv, a_usage_id, a_srv_client, a_custom_data, a_custom_data_size);
}

static dap_stream_ch_chain_net_srv_remain_service_store_t* s_callback_get_remain_service(dap_chain_net_srv_t * a_srv,  uint32_t a_usage_id,
                                         dap_chain_net_srv_client_remote_t * a_srv_client)
{
    return vpn_srv_limits_get_remain_service(a_srv, a_usage_id, a_srv_client);
}

static bool s_save_limits(void* arg)
{
    return vpn_srv_limits_save(arg);
}

static int s_callback_save_remain_service(dap_chain_net_srv_t * a_srv,  uint32_t a_usage_id,
                                          dap_chain_net_srv_client_remote_t * a_srv_client)
{
    return vpn_srv_limits_save_remain_service(a_srv, a_usage_id, a_srv_client);
}
// HTTP callback for remain limits query
static void s_callback_remain_limits(dap_http_simple_t *a_http_simple , void *arg);

static char *s_srv_vpn_addr = NULL, *s_srv_vpn_mask = NULL;

// All legacy TUN/Stream/Session functions removed - now in modular files:
// - dap_chain_net_srv_vpn_tun.c
// - dap_chain_net_srv_vpn_stream.c  
// - dap_chain_net_srv_vpn_session.c
// - dap_chain_net_srv_vpn_limits.c
// - dap_chain_net_srv_vpn_callbacks.c

/**
* @brief s_vpn_tun_init - Initialize TUN infrastructure
* @return 0 on success, negative on error
*/
static int s_vpn_tun_init()
{
    g_vpn_raw_server=DAP_NEW_Z(vpn_local_network_t);
    if (!g_vpn_raw_server) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -1;
    }
    
    // Initialize global mutexes/rwlocks
    pthread_rwlock_init(&g_vpn_raw_server_rwlock, NULL);
    pthread_rwlock_init(&g_vpn_clients_rwlock, NULL);
    pthread_mutex_init(&g_vpn_tun_sockets_mutex_started, NULL);
    pthread_cond_init(&g_vpn_tun_sockets_cond_started, NULL);

    return 0;
}

/**
 * @brief s_vpn_service_create - Register VPN service with DAP SDK using unified TUN API
 * @param g_config Configuration
 * @return 0 on success, negative on error
 */
static int s_vpn_service_create(dap_config_t * g_config)
{
    // Parse network configuration
    const char *c_addr = dap_config_get_item_str(g_config, "srv_vpn", "network_address");
    const char *c_mask = dap_config_get_item_str(g_config, "srv_vpn", "network_mask");
    if (!c_addr || !c_mask) {
        log_it(L_CRITICAL, "Error while reading network parameters from config (network_address and network_mask)");
        return -1;
    }

    inet_aton(c_addr, &g_vpn_raw_server->ipv4_network_addr);
    inet_aton(c_mask, &g_vpn_raw_server->ipv4_network_mask);
    g_vpn_raw_server->ipv4_gw.s_addr = (g_vpn_raw_server->ipv4_network_addr.s_addr | 0x01000000);
    g_vpn_raw_server->ipv4_lease_last.s_addr = g_vpn_raw_server->ipv4_gw.s_addr;
    g_vpn_raw_server->auto_cpu_reassignment = dap_config_get_item_bool_default(g_config, "srv_vpn", "auto_cpu_reassignment", false);

    // Prepare unified TUN configuration
    dap_net_tun_config_t l_tun_config = {
        .mode = DAP_NET_TUN_MODE_SERVER,
        .network_addr = g_vpn_raw_server->ipv4_network_addr,
        .network_mask = g_vpn_raw_server->ipv4_network_mask,
        .gateway_addr = g_vpn_raw_server->ipv4_gw,
        .device_name_prefix = "tun",
        .mtu = 1500,
        .worker_count = 0,  // Auto-detect CPU count
        .workers = NULL,     // Will use dap_events_worker_get()
        .on_data_received = vpn_srv_tun_data_received_callback,
        .on_error = vpn_srv_tun_error_callback,
        .callback_arg = NULL,
        .auto_cpu_reassignment = g_vpn_raw_server->auto_cpu_reassignment
    };

    // Initialize unified TUN device
    g_vpn_tun_handle = dap_net_tun_init(&l_tun_config);
    if (!g_vpn_tun_handle) {
        log_it(L_ERROR, "Failed to initialize unified TUN device");
        return -1;
    }

    // Get device info
    const char *l_tun_name = dap_net_tun_get_device_name(g_vpn_tun_handle, 0);
    if (l_tun_name) {
        g_vpn_raw_server->tun_device_name = strdup(l_tun_name);
    }

    g_vpn_tun_sockets_count = dap_net_tun_get_device_count(g_vpn_tun_handle);

    log_it(L_NOTICE, "Auto CPU reassignment is set to '%s'", g_vpn_raw_server->auto_cpu_reassignment ? "true" : "false");

    // Register VPN service with DAP SDK
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
    dap_chain_net_srv_callbacks_t l_srv_callbacks = {};
    l_srv_callbacks.requested = s_callback_requested;
    l_srv_callbacks.response_success = s_callback_response_success;
    l_srv_callbacks.response_error = s_callback_response_error;
    l_srv_callbacks.receipt_next_success = s_callback_receipt_next_success;
    l_srv_callbacks.get_remain_service = s_callback_get_remain_service;
    l_srv_callbacks.save_remain_service = s_callback_save_remain_service;

    dap_chain_net_srv_t* l_srv = dap_chain_net_srv_add(l_uid, "srv_vpn", &l_srv_callbacks);
    if (!l_srv){
        log_it(L_CRITICAL, "VPN service registration failed.");
        return -2;
    }

    dap_chain_net_srv_vpn_t* l_srv_vpn = DAP_NEW_Z(dap_chain_net_srv_vpn_t);
    if(!l_srv_vpn) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -3;
    }
    l_srv->_internal = l_srv_vpn;
    l_srv_vpn->parent = l_srv;

    // Read debug flag
    g_vpn_debug_more = dap_config_get_item_bool_default(g_config,"srv_vpn", "debug_more",false);

    return 0;
}

/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @param g_config
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_vpn_init(dap_config_t * g_config) {
    
    if(vpn_srv_tun_init()){
        log_it(L_CRITICAL, "Error initializing TUN device driver!");
        dap_chain_net_srv_vpn_deinit();
        return -1;
    }

    log_it(L_DEBUG,"Initializing TUN driver...");
    if(vpn_srv_tun_create(g_config)){
        log_it(L_CRITICAL, "Error creating TUN device driver!");
        dap_chain_net_srv_vpn_deinit();
        return -2;
    }

    log_it(L_INFO,"TUN driver configured successfuly");
    if (s_vpn_service_create(g_config)){
        log_it(L_CRITICAL, "VPN service creating failed");
        dap_chain_net_srv_vpn_deinit();
        return -3;
    }
    // Register stream channel handlers from modular functions
    dap_stream_ch_proc_add(DAP_STREAM_CH_NET_SRV_ID_VPN, vpn_srv_ch_new, vpn_srv_ch_delete,
            vpn_srv_ch_packet_in, vpn_srv_ch_packet_out);

    // add console command to display vpn statistics
    dap_cli_server_cmd_add ("vpn_stat", com_vpn_statistics, NULL, "VPN statistics",
            "vpn_stat -net <net_name> [-full]\n"
            );


    dap_server_t *l_server_default = dap_server_get_default();
    if (!l_server_default) {
        log_it(L_ERROR,"Server should be enabled, change in config file");
        return -100;
    }

    dap_http_server_t * l_http = l_server_default->_inheritor;
    if(!l_http){
        return -100;
    }

    dap_http_simple_proc_add(l_http, "/remain_limits_vpn",24000, s_callback_remain_limits);

    // add groups with limits into clusters

    
    return 0;
}

/**
 * @brief ch_sf_deinit
 */
void dap_chain_net_srv_vpn_deinit(void)
{
    // Deinitialize unified TUN device
    if (g_vpn_tun_handle) {
        dap_net_tun_deinit(g_vpn_tun_handle);
        g_vpn_tun_handle = NULL;
    }
    
    pthread_mutex_destroy(&g_vpn_tun_sockets_mutex_started);
    pthread_cond_destroy(&g_vpn_tun_sockets_cond_started);
    DAP_DEL_Z(s_srv_vpn_addr);
    DAP_DEL_Z(s_srv_vpn_mask);
    DAP_DEL_Z(g_vpn_tun_sockets);
    DAP_DEL_Z(g_vpn_tun_sockets_queue_msg);
    if(g_vpn_raw_server)
        DAP_DELETE(g_vpn_raw_server);
}

// Address pool functions moved to dap_chain_net_srv_vpn_addr_pool.c

/**
 * @brief Parse VPN custom data from JSON
 * @param a_custom_data Raw JSON data
 * @param a_custom_data_size Size of data
 * @return Parsed custom data structure or NULL on error
 */
// All legacy helper/stream/TUN esocket functions removed - now in modular files:
// - Custom data parsing: dap_chain_net_srv_vpn_callbacks.c
// - Stream handlers: dap_chain_net_srv_vpn_stream.c
// - TUN esocket callbacks: dap_chain_net_srv_vpn_tun.c
// - Limits update: dap_chain_net_srv_vpn_limits.c

static void s_callback_remain_limits(dap_http_simple_t *a_http_simple , void *a_arg)
{
    http_status_code_t * l_return_code = (http_status_code_t*)a_arg;
    *l_return_code = Http_Status_OK;
    strcpy(a_http_simple->reply_mime, "text/text");
    const char *l_net_id_str = NULL, *l_user_pkey_hash_str = NULL;
    dap_chain_net_id_t l_net_id = {};
    // request parsing
    // example: net_id=id&user_pkey_hash=pkeyhash
    char *l_first_param = DAP_DUP_SIZE((char*)a_http_simple->http_client->in_query_string, a_http_simple->http_client->in_query_string_len);
    char *l_second_param = strchr(l_first_param, '&');
    if (!l_second_param || strlen(l_second_param) == 1){
        dap_http_simple_reply_f(a_http_simple, "Wrong parameters!");
        DAP_DELETE(l_first_param);
        *l_return_code = Http_Status_OK;
        return;
    }
    *l_second_param++ = '\0';

    if (strstr(l_first_param, "net_id")){
        if (*(l_first_param + strlen("net_id")) == '='){
            l_net_id_str = l_first_param + strlen("net_id") + 1;
        }
    } else if (strstr(l_first_param, "user_pkey_hash")) {
        if (*(l_first_param + strlen("user_pkey_hash")) == '='){
            l_user_pkey_hash_str = l_first_param + strlen("user_pkey_hash") + 1;
        }
    }

    if (strstr(l_second_param, "net_id")){
        if (*(l_second_param + strlen("net_id")) == '='){
            l_net_id_str = l_second_param + strlen("net_id") + 1;
        }
    } else if (strstr(l_second_param, "user_pkey_hash")) {
        if (*(l_second_param + strlen("user_pkey_hash")) == '='){
            l_user_pkey_hash_str = l_second_param + strlen("user_pkey_hash") + 1;
        }
    }

    if (!l_net_id_str || !l_user_pkey_hash_str){
        dap_http_simple_reply_f(a_http_simple, "Wrong parameters!");
        *l_return_code = Http_Status_OK;
        DAP_DELETE(l_first_param);
        return;
    }

    l_net_id.uint64 = strtoul(l_net_id_str, NULL, 10);

    dap_stream_ch_chain_net_srv_remain_service_store_t *l_remain_service = NULL;
    const char *l_cert_name = dap_config_get_item_str_default(g_config, "srv_vpn", "receipt_sign_cert", NULL);
    if (l_cert_name){
        dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_name);
        dap_hash_fast_t price_pkey_hash = {};
        size_t l_key_size = 0;
        uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(l_cert->enc_key, &l_key_size);
        if (!l_pub_key || !l_key_size)
        {
            log_it(L_ERROR, "Can't get pkey from cert %s.", l_cert_name);
            dap_http_simple_reply_f(a_http_simple, "Internal error!");
            *l_return_code = Http_Status_OK;
            DAP_DELETE(l_first_param);
            return;
        }

        dap_hash_fast(l_pub_key, l_key_size, &price_pkey_hash);
        DAP_DELETE(l_pub_key);
        char* l_server_pkey_hash = dap_chain_hash_fast_to_str_new(&price_pkey_hash);
        if (!l_server_pkey_hash){
            log_it(L_DEBUG, "Can't get server pkey hash.");
            dap_http_simple_reply_f(a_http_simple, "Internal error!");
            *l_return_code = Http_Status_OK;
            DAP_DELETE(l_first_param);
            return;
        }

        dap_chain_net_t *l_net = dap_chain_net_by_id(l_net_id);
        if(!l_net){
            log_it(L_DEBUG, "Can't find net with id %"DAP_UINT64_FORMAT_U, l_net_id.uint64);
            dap_http_simple_reply_f(a_http_simple, "Can't find net with id %"DAP_UINT64_FORMAT_U"!", l_net_id.uint64);
            DAP_DEL_Z(l_server_pkey_hash);
            *l_return_code = Http_Status_OK;
            DAP_DELETE(l_first_param);
            return;
        }
        char *l_remain_limits_gdb_group =  dap_strdup_printf( "local.%s.0x%016"DAP_UINT64_FORMAT_x".remain_limits.%s", l_net->pub.gdb_groups_prefix, (uint64_t)DAP_CHAIN_NET_SRV_VPN_ID, l_server_pkey_hash);
        log_it(L_DEBUG, "Checkout user %s in group %s", l_user_pkey_hash_str, l_remain_limits_gdb_group);
        size_t l_remain_service_size = 0;
        l_remain_service = (dap_stream_ch_chain_net_srv_remain_service_store_t*) dap_global_db_get_sync(l_remain_limits_gdb_group, l_user_pkey_hash_str, &l_remain_service_size, NULL, NULL);
        DAP_DELETE(l_remain_limits_gdb_group);

        // Create JSON responce
        json_object *l_json_response = json_object_new_object();

        json_object *l_new_data = json_object_new_uint64(l_net_id.uint64);
        json_object_object_add(l_json_response, "net_id", l_new_data);

        l_new_data = json_object_new_uint64((uint64_t)DAP_CHAIN_NET_SRV_VPN_ID);
        json_object_object_add(l_json_response, "srv_uid", l_new_data);

        l_new_data = json_object_new_string(l_user_pkey_hash_str ? l_user_pkey_hash_str : "");
        json_object_object_add(l_json_response, "user_pkey_hash", l_new_data);

        l_new_data = json_object_new_string(l_server_pkey_hash ? l_server_pkey_hash : "");
        json_object_object_add(l_json_response, "server_pkey_hash", l_new_data);

        l_new_data = json_object_new_uint64(l_remain_service ? l_remain_service->limits_bytes : 0);
        json_object_object_add(l_json_response, "limit_bytes", l_new_data);

        l_new_data = json_object_new_uint64(l_remain_service ? l_remain_service->limits_ts : 0);
        json_object_object_add(l_json_response, "limit_sec", l_new_data);

        const char *output_string = json_object_to_json_string(l_json_response);
        dap_http_simple_reply(a_http_simple, (void*)output_string, strlen(output_string));
        strcpy(a_http_simple->reply_mime, "application/json");
        json_object_put(l_json_response);
        DAP_DEL_Z(l_server_pkey_hash);
    } else {
        dap_http_simple_reply_f(a_http_simple, "Internal error!");
        *l_return_code = Http_Status_InternalServerError;
    }
    DAP_DELETE(l_first_param);
}

