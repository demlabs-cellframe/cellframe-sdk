/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2019
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

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "rand/dap_rand.h"

#ifdef DAP_OS_LINUX
#include <dlfcn.h>
#endif

#include "dap_client.h"
#include "dap_enc_base58.h"
#include "dap_chain_node_client.h"

#include "dap_stream_ch_proc.h"
//#include "dap_stream_ch_chain_net_srv.h"

#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_vpn_client.h"

#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_chain_net_vpn_client_tun.h"
#include "dap_chain_net_srv_vpn_cmd.h"
#include "dap_modules_dynamic_cdb.h"

/*
 #if !defined( dap_http_client_state_t )
 typedef enum dap_http_client_state {
 DAP_HTTP_CLIENT_STATE_NONE = 0,
 DAP_HTTP_CLIENT_STATE_START = 1,
 DAP_HTTP_CLIENT_STATE_HEADERS = 2,
 DAP_HTTP_CLIENT_STATE_DATA = 3
 } dap_http_client_state_t;
 #endif
 */

#define LOG_TAG "vpn_client"

static EPOLL_HANDLE sf_socks_epoll_fd;


static pthread_mutex_t sf_socks_mutex;

static dap_chain_node_info_t *s_node_info = NULL;
static dap_chain_node_client_t *s_vpn_client = NULL;

dap_stream_worker_t* dap_chain_net_vpn_client_get_stream_worker(void)
{
    if(!s_vpn_client)
        return NULL;
    return dap_client_get_stream_worker( s_vpn_client->client );
}

dap_stream_ch_t* dap_chain_net_vpn_client_get_stream_ch(void)
{
    if(!s_vpn_client)
        return NULL;
    dap_stream_ch_t *l_stream = dap_client_get_stream_ch_unsafe(s_vpn_client->client, DAP_STREAM_CH_ID_NET_SRV_VPN);
    return l_stream;
}

/// TODO convert below callback to processor of stage
/*
 void s_stage_callback()
 {
 char* l_full_path = NULL;
 const char * l_path = "stream";
 const char *l_suburl = "globaldb";
 int l_full_path_size = snprintf(l_full_path, 0, "%s/%s?session_id=%s", DAP_UPLINK_PATH_STREAM, l_suburl,
 dap_client_get_stream_id(a_client_pvt->client));
 l_full_path = DAP_NEW_Z_SIZE(char, l_full_path_size + 1);
 snprintf(l_full_path, l_full_path_size + 1, "%s/%s?session_id=%s", DAP_UPLINK_PATH_STREAM, l_suburl,
 dap_client_get_stream_id(a_client_pvt->client));

 //dap_client_request(a_client_pvt->client, l_full_path, "12345", 0, m_stream_response, m_stream_error);

 const char *l_add_str = "";
 // if connect to vpn server
 const char l_active_vpn_channels[] = { VPN_CLIENT_ID, 0 };
 if(!dap_strcmp(a_client_pvt->active_channels, l_active_vpn_channels))
 l_add_str = "\r\nService-Key: test";

 {
 char *l_message = dap_strdup_printf("GET /%s HTTP/1.1\r\nHost: %s:%d%s\r\n\r\n",
 l_full_path, a_client_pvt->uplink_addr, a_client_pvt->uplink_port, l_add_str);
 size_t l_message_size = dap_strlen(l_message);
 int count = send(a_client_pvt->stream_socket, l_message, l_message_size, 0);
 DAP_DELETE(l_message);
 }
 DAP_DELETE(l_full_path);

 }*/

/**
 * Get tx_cond_hash
 *
 * return: 0 Ok, 1 Already started, <0 Error
 */
static dap_chain_hash_fast_t* dap_chain_net_vpn_client_tx_cond_hash(dap_chain_net_t *a_net,
        dap_chain_wallet_t *a_wallet, const char *a_token_ticker, uint64_t a_value_datoshi)
{
    uint8_t *l_pkey_b64 = NULL;
    size_t l_pkey_b64_size = 0;

    // Try to load from gdb
    size_t l_gdb_group_size = 0;
    char *l_gdb_group = dap_strdup_printf("local.%s", DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX);
    dap_chain_hash_fast_t *l_tx_cond_hash = (dap_chain_hash_fast_t*) dap_chain_global_db_gr_get(
            dap_strdup("client_tx_cond_hash"), &l_gdb_group_size, l_gdb_group);

    time_t l_tx_cond_ts = 0;
    // Check for entry size
    if(l_tx_cond_hash && l_gdb_group_size && l_gdb_group_size != sizeof(dap_chain_hash_fast_t)) {
        log_it(L_ERROR, "Wrong size of tx condition on database (%zd but expected %zd), may be old entry",
                l_gdb_group_size, sizeof(dap_chain_hash_fast_t));
        l_tx_cond_hash = NULL;
    }
    // If loaded lets check is it spent or not
    if(l_tx_cond_hash) {
        log_it(L_DEBUG, "2791: Search for unspent tx, net %s", a_net);
        dap_chain_datum_tx_t *l_tx = dap_chain_net_get_tx_by_hash(a_net, l_tx_cond_hash, TX_SEARCH_TYPE_NET_UNSPENT);
        if(!l_tx) { // If not found - all outs are used. Create new one
            // pass all chains
            l_tx = dap_chain_net_get_tx_by_hash(a_net, l_tx_cond_hash, TX_SEARCH_TYPE_NET);
            DAP_DELETE(l_tx_cond_hash);
            l_tx_cond_hash = NULL;
            if(l_tx) {
                l_tx_cond_ts = (time_t) l_tx->header.ts_created;
                log_it(L_DEBUG, "2791: got some tx, created %d", l_tx->header.ts_created);
            }
        }
    }
    if(l_tx_cond_hash)
        return l_tx_cond_hash;

    //l_pkey_b64 = (char*) dap_chain_global_db_gr_get(dap_strdup("client_pkey"), &l_gdb_group_size, l_gdb_group);
    dap_enc_key_t *l_enc_key = NULL;
    if(a_wallet) {
        l_enc_key = dap_chain_wallet_get_key(a_wallet, 0);
    }
    // use default pkey
    else {

    }
    /*
     // generate new pub key
     if(!l_pkey_b64){
     //if(!l_pub_key_data || !l_pub_key_data_size){
     char *l_certs_name_str = dap_strdup_printf("client.%s", DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX);
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
     size_t l_pub_key_data_size = 0;
     uint8_t *l_pub_key_data = dap_enc_key_serealize_pub_key(l_cert->enc_key, &l_pub_key_data_size);
     // save pub key
     if(l_pub_key_data && l_pub_key_data_size > 0){
     if(dap_chain_global_db_gr_set(dap_strdup("client_pkey"), l_pub_key_data, l_pub_key_data_size,
     l_gdb_group)){
     l_pkey_b64 = l_pub_key_data;
     l_pkey_b64_size = l_pub_key_data_size;
     }
     else
     DAP_DELETE(l_pub_key_data);
     }
     }
     DAP_DELETE(l_certs_name_str);
     }*/

    if(!l_enc_key)
        return NULL;

    // Try to create condition
    if(!l_tx_cond_hash) {
        dap_chain_wallet_t *l_wallet_from = a_wallet;
        log_it(L_DEBUG, "Create tx from wallet %s", l_wallet_from->name);
        dap_enc_key_t *l_key_from = l_enc_key; //dap_chain_wallet_get_key(l_wallet_from, 0);
        dap_enc_key_t *l_client_key = l_enc_key;
        //dap_chain_cell_id_t *xccell = dap_chain_net_get_cur_cell(l_tpl->net);
        //uint64_t uint64 =dap_chain_net_get_cur_cell(l_tpl->net)->uint64;

        size_t l_pub_key_data_size = 0;
        uint8_t *l_pub_key_data = dap_enc_key_serealize_pub_key(l_enc_key, &l_pub_key_data_size);
        // where to take coins for service
        dap_chain_addr_t *l_addr_from = dap_chain_wallet_get_addr(l_wallet_from, a_net->pub.id);
        dap_chain_net_srv_price_unit_uid_t l_price_unit = { .enm = SERV_UNIT_SEC };
        dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
        l_tx_cond_hash = dap_chain_proc_tx_create_cond(a_net, l_key_from, l_client_key, l_addr_from,
                a_token_ticker, a_value_datoshi, 0, l_price_unit, l_srv_uid, 0, l_pub_key_data, l_pub_key_data_size);
        //char *l_addr_from_str = dap_chain_addr_to_str(l_addr_from);
        DAP_DELETE(l_addr_from);
        if(!l_tx_cond_hash) {
            log_it(L_ERROR, "Can't create condition for user");
        } else {
            // save transaction for login
            dap_chain_global_db_gr_set("client_tx_cond_hash", l_tx_cond_hash, sizeof(dap_chain_hash_fast_t),
                    l_gdb_group);
        }
        //DAP_DELETE(l_addr_from_str);
        DAP_DELETE(l_pub_key_data);
    }
    DAP_DELETE(l_tx_cond_hash);
    dap_enc_key_delete(l_enc_key);
    DAP_DELETE(l_gdb_group);
    return l_tx_cond_hash;
}

/**
 * Init VPN client
 *
 * return: 0 Ok, 1 Ok, <0 Error
 */

int dap_chain_net_vpn_client_update(dap_chain_net_t *a_net, const char *a_wallet_name, const char *a_str_token,
        uint64_t a_value_datoshi)
{
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(a_wallet_name, dap_chain_wallet_get_path(g_config));
    if(!l_wallet) {
        return -1;
    }
    size_t l_gdb_group_size = 0;
    char *l_gdb_group = dap_strdup_printf("local.%s", DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX);
    if(!dap_chain_global_db_gr_set(dap_strdup("wallet_name"), (void*) a_wallet_name, dap_strlen(a_wallet_name) + 1,
            l_gdb_group))
        return -2;
    if(!dap_chain_global_db_gr_set(dap_strdup("token_name"), (void*) a_str_token, dap_strlen(a_str_token) + 1,
            l_gdb_group))
        return -2;
    if(!dap_chain_global_db_gr_set(dap_strdup("value_datoshi"), &a_value_datoshi, sizeof(a_value_datoshi), l_gdb_group))
        return -2;
    DAP_DELETE(l_gdb_group);
    dap_chain_hash_fast_t *l_hash = dap_chain_net_vpn_client_tx_cond_hash(a_net, l_wallet, a_str_token,
            a_value_datoshi);
    dap_chain_wallet_close(l_wallet);
    if(!l_hash)
        return -3;
    DAP_DELETE(l_hash);
    return 0;
}

/**
 * Init VPN client
 *
 * return: 0 Ok, 1 Ok, <0 Error
 */

int dap_chain_net_vpn_client_get_wallet_info(dap_chain_net_t *a_net, char **a_wallet_name, char **a_str_token,
        uint64_t *a_value_datoshi)
{
    size_t l_gdb_group_size = 0;
    char *l_gdb_group = dap_strdup_printf("local.%s", DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX);
    if(a_wallet_name)
        *a_wallet_name = (char*) dap_chain_global_db_gr_get("wallet_name", NULL, l_gdb_group);
    if(a_str_token)
        *a_str_token = (char*) dap_chain_global_db_gr_get("token_name", NULL, l_gdb_group);
    if(a_value_datoshi) {
        uint64_t *l_value_datoshi = (uint64_t*) dap_chain_global_db_gr_get("value_datoshi", NULL, l_gdb_group);
        *a_value_datoshi = l_value_datoshi ? *l_value_datoshi : 0;
        DAP_DELETE(l_value_datoshi);
    }
    return 0;
}


static const char * s_default_path_modules = "var/modules";
// get_order_state() from dynamic library
static int get_order_state_so(dap_chain_node_addr_t a_node_addr)
{
    char l_lib_path[MAX_PATH] = {'\0'};
#if defined (DAP_OS_LINUX) && !defined (__ANDROID__)
    const char * l_cdb_so_name = "libcellframe-node-cdb.so";
    dap_sprintf(l_lib_path, "%s/%s/%s", g_sys_dir_path, s_default_path_modules, l_cdb_so_name);

    void* l_cdb_handle = NULL;
    l_cdb_handle = dlopen(l_lib_path, RTLD_NOW);
    if(!l_cdb_handle){
        log_it(L_ERROR,"Can't load %s module: %s", l_cdb_so_name, dlerror());
        return -1;
    }

    int (*get_order_state_so)(dap_chain_node_addr_t);
    const char * l_init_func_name = "get_order_state";
    *(void **) (&get_order_state_so) = dlsym(l_cdb_handle, l_init_func_name);
    char* error;
    if (( error = dlerror()) != NULL) {
        log_it(L_ERROR,"%s module: %s error loading (%s)", l_cdb_so_name, l_init_func_name, error);
        return -2;
     }

    return (*get_order_state_so)(a_node_addr);
#else
    log_it(L_ERROR,"%s: module is not supported on current platfrom", __PRETTY_FUNCTION__);
    return -1;
#endif

}

char *dap_chain_net_vpn_client_check_result(dap_chain_net_t *a_net, const char* a_hash_out_type)
{


    dap_chain_net_srv_order_t * l_orders = NULL;
    size_t l_orders_num = 0;
    dap_chain_net_srv_uid_t l_srv_uid = { { 0 } };
    uint64_t l_price_min = 0, l_price_max = 0;
    dap_chain_net_srv_price_unit_uid_t l_price_unit = { { 0 } };
    dap_chain_net_srv_order_direction_t l_direction = SERV_DIR_UNDEFINED;
    dap_string_t *l_string_ret = dap_string_new("");

    if(dap_chain_net_srv_order_find_all_by(a_net, l_direction, l_srv_uid, l_price_unit, NULL, l_price_min, l_price_max, &l_orders, &l_orders_num) == 0){
        size_t l_orders_size = 0;
        for(size_t i = 0; i < l_orders_num; i++) {
            dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *) (((byte_t*) l_orders) + l_orders_size);
            //dap_chain_net_srv_order_dump_to_string(l_order, l_string_ret, l_hash_out_type);
            dap_chain_hash_fast_t l_hash={0};
            char *l_hash_str;
            dap_hash_fast(l_order, dap_chain_net_srv_order_get_size(l_order), &l_hash);
            if(!dap_strcmp(a_hash_out_type, "hex"))
                l_hash_str = dap_chain_hash_fast_to_str_new(&l_hash);
            else
                l_hash_str = dap_enc_base58_encode_hash_to_str(&l_hash);
            int l_state = get_order_state_so(l_order->node_addr);
            const char *l_state_str;
            switch (l_state)
            {
            case 0:
                l_state_str = "Not available";
                break;
            case 1:
                l_state_str = "Available";
                break;
            default:
                l_state_str = "Unknown";
            }
            dap_string_append_printf(l_string_ret, "Order %s: State %s\n", l_hash_str, l_state_str);
            DAP_DELETE(l_hash_str);
            l_orders_size += dap_chain_net_srv_order_get_size(l_order);
            //dap_string_append(l_string_ret, "\n");
        }
    }
    // return str from dap_string_t
    return dap_string_free(l_string_ret, false);
}

/**
 * Check  VPN server
 *
 * return: 0 Ok, <0 Error
 */
int dap_chain_net_vpn_client_check(dap_chain_net_t *a_net, const char *a_ipv4_str, const char *a_ipv6_str, int a_port, size_t a_data_size_to_send, size_t a_data_size_to_recv, int a_timeout_test_ms)
{
    // default 10k
    if(a_data_size_to_send==-1)
        a_data_size_to_send = 10240;
    if(a_data_size_to_recv==-1)
        a_data_size_to_recv = 10240;
    // default 10 sec = 10000 ms
    if(a_timeout_test_ms==-1)
        a_timeout_test_ms = 10000;

    int l_timeout_conn_ms = 10000;
    int l_ret = 0;
    if(!a_ipv4_str) // && !a_ipv6_str)
        return -1;
    if(!s_node_info)
        s_node_info = DAP_NEW_Z(dap_chain_node_info_t);
    s_node_info->hdr.ext_port = a_port;


    // measuring connection time
    struct timeval l_t;
    gettimeofday(&l_t, NULL);//get_cur_time_msec
    long l_t1 = (long) l_t.tv_sec * 1000 + l_t.tv_usec / 1000;

    const char l_active_channels[] = { dap_stream_ch_chain_net_srv_get_id(), 0 }; //only R, without S
    if(a_ipv4_str)
        inet_pton(AF_INET, a_ipv4_str, &(s_node_info->hdr.ext_addr_v4));
    if(a_ipv6_str)
        inet_pton(AF_INET6, a_ipv6_str, &(s_node_info->hdr.ext_addr_v6));

    s_vpn_client = dap_chain_node_client_create_n_connect(a_net, s_node_info, l_active_channels, NULL, NULL);
    if(!s_vpn_client) {
        log_it(L_ERROR, "Can't connect to VPN server=%s:%d", a_ipv4_str, a_port);
        DAP_DELETE(s_node_info);
        s_node_info = NULL;
        return -2;
    }
    // wait connected
    int l_timeout_ms = l_timeout_conn_ms; //5 sec = 5000 ms
    int l_res = dap_chain_node_client_wait(s_vpn_client, NODE_CLIENT_STATE_ESTABLISHED, l_timeout_ms);
    if(l_res) {
        log_it(L_ERROR, "No response from VPN server=%s:%d", a_ipv4_str, a_port);
        // clean client struct
        dap_chain_node_client_close(s_vpn_client);
        DAP_DELETE(s_node_info);
        s_node_info = NULL;
        return -3;
    }

    gettimeofday(&l_t, NULL);
    long l_t2 = (long) l_t.tv_sec * 1000 + l_t.tv_usec / 1000;
    int l_dtime_connect_ms = l_t2-l_t1;

    //l_ret = dap_chain_net_vpn_client_tun_init(a_ipv4_str);

    // send first packet to server
    {
        uint8_t l_ch_id = dap_stream_ch_chain_net_srv_get_id(); // Channel id for chain net request = 'R'
        dap_stream_ch_t *l_ch = dap_client_get_stream_ch_unsafe(s_vpn_client->client, l_ch_id);
        if(l_ch) {
            dap_stream_ch_chain_net_srv_pkt_test_t *l_request = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_test_t, sizeof(dap_stream_ch_chain_net_srv_pkt_test_t) + a_data_size_to_send);
            l_request->net_id.uint64 = a_net->pub.id.uint64;
            l_request->srv_uid.uint64 = DAP_CHAIN_NET_SRV_VPN_ID;
            l_request->data_size_send = a_data_size_to_send;
            l_request->data_size_recv = a_data_size_to_recv;
            l_request->data_size = a_data_size_to_send;
            randombytes(l_request->data, a_data_size_to_send);
            dap_chain_hash_fast_t l_data_hash;
            dap_hash_fast(l_request->data, l_request->data_size, &l_request->data_hash);
            if(a_ipv4_str)
                memcpy(l_request->ip_recv, a_ipv4_str, min(sizeof(l_request->ip_recv), strlen(a_ipv4_str)));

            l_request->time_connect_ms = l_dtime_connect_ms;
            gettimeofday(&l_request->send_time1, NULL);
            size_t l_request_size = l_request->data_size + sizeof(dap_stream_ch_chain_net_srv_pkt_test_t);
            dap_stream_ch_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_REQUEST, l_request, l_request_size);
            dap_stream_ch_set_ready_to_write_unsafe(l_ch, true);
            DAP_DELETE(l_request);
        }
    }
    // wait testing
    //int timeout_test_ms = 10000; //10 sec = 10000 ms
    a_timeout_test_ms -=l_dtime_connect_ms;
    // timeout not less then 5 sec
    if(a_timeout_test_ms<5000)
        a_timeout_test_ms = 5000;
    l_res = dap_chain_node_client_wait(s_vpn_client, NODE_CLIENT_STATE_CHECKED, a_timeout_test_ms);
    if(l_res) {
        log_it(L_ERROR, "No response from VPN server=%s:%d", a_ipv4_str, a_port);
    }
    else{
        log_it(L_NOTICE, "Got response from VPN server=%s:%d", a_ipv4_str, a_port);
    }
    // clean client struct
    dap_chain_node_client_close(s_vpn_client);
    DAP_DELETE(s_node_info);
    s_node_info = NULL;
    if(l_res)
        return -3;
    return l_ret;
}


/**
 * Start VPN client
 *
 * return: 0 Ok, 1 Already started, <0 Error
 */
int dap_chain_net_vpn_client_start(dap_chain_net_t *a_net, const char *a_ipv4_str, const char *a_ipv6_str, int a_port)
{
    int l_ret = 0;
    if(!a_ipv4_str) // && !a_ipv6_str)
        return -1;
    if(!s_node_info)
        s_node_info = DAP_NEW_Z(dap_chain_node_info_t);
    s_node_info->hdr.ext_port = a_port;

    const char l_active_channels[] = { dap_stream_ch_chain_net_srv_get_id(), DAP_STREAM_CH_ID_NET_SRV_VPN, 0 }; //R, S
    if(a_ipv4_str)
        inet_pton(AF_INET, a_ipv4_str, &(s_node_info->hdr.ext_addr_v4));
    if(a_ipv6_str)
        inet_pton(AF_INET6, a_ipv6_str, &(s_node_info->hdr.ext_addr_v6));

    s_vpn_client = dap_chain_node_client_connect_channels(a_net,s_node_info, l_active_channels);
    if(!s_vpn_client) {
        log_it(L_ERROR, "Can't connect to VPN server=%s:%d", a_ipv4_str, a_port);
        // clean client struct
        dap_chain_node_client_close(s_vpn_client);
        DAP_DELETE(s_node_info);
        s_node_info = NULL;
        return -2;
    }
    // wait connected
    int timeout_ms = 5000; //5 sec = 5000 ms
    int res = dap_chain_node_client_wait(s_vpn_client, NODE_CLIENT_STATE_ESTABLISHED, timeout_ms);
    if(res) {
        log_it(L_ERROR, "No response from VPN server=%s:%d", a_ipv4_str, a_port);
        // clean client struct
        dap_chain_node_client_close(s_vpn_client);
        DAP_DELETE(s_node_info);
        s_node_info = NULL;
        return -3;
    }

    l_ret = dap_chain_net_vpn_client_tun_init(a_ipv4_str);

    // send first packet to server
    {
        uint8_t l_ch_id = dap_stream_ch_chain_net_srv_get_id(); // Channel id for chain net request = 'R'
        dap_stream_ch_t *l_ch = dap_client_get_stream_ch_unsafe(s_vpn_client->client, l_ch_id);
        if(l_ch) {
            dap_stream_ch_chain_net_srv_pkt_request_t l_request;
            memset(&l_request, 0, sizeof(dap_stream_ch_chain_net_srv_pkt_request_t));
            l_request.hdr.net_id.uint64 = a_net->pub.id.uint64;
            l_request.hdr.srv_uid.uint64 = DAP_CHAIN_NET_SRV_VPN_ID;
            dap_chain_hash_fast_t *l_tx_cond = dap_chain_net_vpn_client_tx_cond_hash(a_net, NULL, NULL, 0);
            if(l_tx_cond) {
                memcpy(&l_request.hdr.tx_cond, l_tx_cond, sizeof(dap_chain_hash_fast_t));
                DAP_DELETE(l_tx_cond);
            }
            // set srv id
            dap_stream_ch_chain_net_srv_set_srv_uid(l_ch, l_request.hdr.srv_uid);
            //dap_chain_hash_fast_t l_request
            //.hdr.tx_cond = a_txCond.value();
//    	    strncpy(l_request->hdr.token, a_token.toLatin1().constData(),sizeof (l_request->hdr.token)-1);
            dap_stream_ch_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST, &l_request, sizeof(l_request));
            dap_stream_ch_set_ready_to_write_unsafe(l_ch, true);
        }
    }

    return l_ret;
}

int dap_chain_net_vpn_client_stop(void)
{
    // delete connection with VPN server
    if(s_vpn_client) {
        dap_chain_node_client_close(s_vpn_client);
        s_vpn_client = NULL;
    }
    DAP_DELETE(s_node_info);
    s_node_info = NULL;
    int l_ret = dap_chain_net_vpn_client_tun_delete();

    return l_ret;
}

dap_chain_net_vpn_client_status_t dap_chain_net_vpn_client_status(void)
{
    if(s_vpn_client) {
        uint8_t l_ch_id = dap_stream_ch_chain_net_srv_get_id(); // Channel id for chain net request = 'R'
        dap_stream_ch_t *l_ch = dap_client_get_stream_ch_unsafe(s_vpn_client->client, l_ch_id);
        if(!l_ch)
            return VPN_CLIENT_STATUS_CONN_LOST;
    }
    else
        return VPN_CLIENT_STATUS_NOT_STARTED;
    if(!dap_chain_net_vpn_client_tun_status())
        // VPN client started
        return VPN_CLIENT_STATUS_STARTED;
    return VPN_CLIENT_STATUS_STOPPED;
}

/**
 * @brief dap_chain_net_vpn_client_pkt_in
 * @param a_ch
 * @param a_arg
 */
void dap_chain_net_vpn_client_pkt_in(dap_stream_ch_t* a_ch, dap_stream_ch_pkt_t* a_pkt)
{
    ch_vpn_pkt_t * l_sf_pkt = (ch_vpn_pkt_t *) a_pkt->data;
    size_t l_sf_pkt_data_size = a_pkt->hdr.size - sizeof(l_sf_pkt->header);

    if(!a_pkt->hdr.size) {
        log_it(L_WARNING, "Bad input packet");
        return;
    }

    int remote_sock_id = l_sf_pkt->header.sock_id;
    if(l_sf_pkt->header.op_code == 0) { // Raw packets
        log_it(L_WARNING, "Bad op_code=0");
        return;
    }
//    log_it(L_DEBUG,"Got SF packet: remote_sock_id:%d op_code:0x%02x data_size:%lu"
//           ,remote_sock_id, l_sf_pkt->header.op_code, l_sf_pkt_data_size );
    if(l_sf_pkt->header.op_code >= 0xb0) { // Raw packets
        switch (l_sf_pkt->header.op_code) {
        /*        case VPN_PACKET_OP_CODE_VPN_ADDR_REPLY: { // Assigned address for peer
         if(ch_sf_tun_addr_leased(CH_VPN(a_ch), l_sf_pkt, l_sf_pkt_data_size) < 0) {
         log_it(L_WARNING, "Can't create tun");
         }
         }
         break;
         case VPN_PACKET_OP_CODE_VPN_ADDR_REQUEST: // Client request after L3 connection the new IP address
         log_it(L_WARNING, "Got VPN_PACKET_OP_CODE_VPN_ADDR_REQUEST packet with id %d, it's very strange' ",
         remote_sock_id);
         break;
         case VPN_PACKET_OP_CODE_VPN_SEND:
         log_it(L_WARNING, "Got VPN_PACKET_OP_CODE_VPN_SEND packet with id %d, it's very strange' ", remote_sock_id);

         case VPN_PACKET_OP_CODE_VPN_RECV:
         a_ch->stream->events_socket->last_ping_request = time(NULL); // not ping, but better  ;-)
         ch_sf_tun_send(CH_VPN(a_ch), l_sf_pkt->data, l_sf_pkt->header.op_data.data_size);
         break;*/
        /*
         case VPN_PACKET_OP_CODE_PING:
         a_ch->stream->events_socket->last_ping_request = time(NULL);
         send_pong_pkt(a_ch);
         break;
         case VPN_PACKET_OP_CODE_PONG:
         a_ch->stream->events_socket->last_ping_request = time(NULL);
         break;
         */
            default:
                log_it(L_WARNING, "Can't process SF type 0x%02x", l_sf_pkt->header.op_code);
        }

    }

}

/**
 * @brief dap_chain_net_vpn_client_pkt_out
 * @param a_ch
 */
void dap_chain_net_vpn_client_pkt_out(dap_stream_ch_t* a_ch)
{
    /*    ch->writable = isSmthOut;
     if(isSmthOut) {
     if(ch->stream->conn_http)
     ch->stream->conn_http->state_write = DAP_HTTP_CLIENT_STATE_DATA; //SAP_HTTP_CONN_STATE_DATA;
     }*/
}

int dap_chain_net_vpn_client_init(dap_config_t * g_config)
{
    pthread_mutex_init(&sf_socks_mutex, NULL);

    // vpn client command
    dap_chain_node_cli_cmd_item_create ("vpn_client", com_vpn_client, NULL, "VPN client control",
    "vpn_client [start -addr <server address> -port <server port>| stop | status] -net <net name>\n"
    "vpn_client init -w <wallet name> -token <token name> -value <value> -net <net name>\n"
            "vpn_client stop -net <net name>\n"
            "vpn_client status -net <net name>\n"
            "vpn_client check -addr <ip addr> -port <port> -net <net name>\n"
            "vpn_client check result -net <net name> [-H hex|base58(default)]\n"
            );


    return dap_chain_net_srv_client_vpn_init(g_config);
}

void dap_chain_net_vpn_client_deinit()
{
}
