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
#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"

#include "dap_client.h"
#include "dap_chain_node_client.h"

#include "dap_stream_ch_proc.h"
//#include "dap_stream_ch_chain_net_srv.h"

#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_srv_vpn_cdb.h" // for DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX
#include "dap_chain_net_vpn_client.h"

#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain_net_srv.h"
//#include "dap_stream_ch_chain_net_srv.h"
#include "dap_chain_net_vpn_client_tun.h"
#include "dap_chain_net_srv_vpn_cmd.h"
//#include "dap_chain_net_vpn_client_data.h"

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

static ch_vpn_socket_proxy_t *sf_socks = NULL;
static ch_vpn_socket_proxy_t *sf_socks_client = NULL;

static pthread_mutex_t sf_socks_mutex;

static dap_chain_node_info_t *s_node_info = NULL;
static dap_chain_node_client_t *s_vpn_client = NULL;

dap_stream_ch_t* dap_chain_net_vpn_client_get_stream_ch(void)
{
    if(!s_vpn_client)
        return NULL;
    dap_stream_ch_t *l_stream = dap_client_get_stream_ch(s_vpn_client->client, DAP_STREAM_CH_ID_NET_SRV_VPN);
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

/**
 * Check  VPN server
 *
 * return: 0 Ok, <0 Error
 */
int dap_chain_net_vpn_client_check(dap_chain_net_t *a_net, const char *a_ipv4_str, const char *a_ipv6_str, int a_port, int a_rate_out)
{
    int l_ret = 0;
    if(!a_ipv4_str) // && !a_ipv6_str)
        return -1;
    if(!s_node_info)
        s_node_info = DAP_NEW_Z(dap_chain_node_info_t);
    s_node_info->hdr.ext_port = a_port;

    dap_client_stage_t l_stage_target = STAGE_STREAM_STREAMING; //DAP_CLIENT_STAGE_STREAM_CTL;//STAGE_STREAM_STREAMING;
    const char l_active_channels[] = { dap_stream_ch_chain_net_srv_get_id(), 0 }; //only R, without S
    if(a_ipv4_str)
        inet_pton(AF_INET, a_ipv4_str, &(s_node_info->hdr.ext_addr_v4));
    if(a_ipv6_str)
        inet_pton(AF_INET6, a_ipv6_str, &(s_node_info->hdr.ext_addr_v6));

    s_vpn_client = dap_chain_client_connect(s_node_info, l_stage_target, l_active_channels);
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
    int l_res = dap_chain_node_client_wait(s_vpn_client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
    if(l_res) {
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
        dap_stream_ch_t *l_ch = dap_client_get_stream_ch(s_vpn_client->client, l_ch_id);
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
//          strncpy(l_request->hdr.token, a_token.toLatin1().constData(),sizeof (l_request->hdr.token)-1);
            dap_stream_ch_pkt_write(l_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_REQUEST, &l_request, sizeof(l_request));
            dap_stream_ch_set_ready_to_write(l_ch, true);
        }
    }
    // wait testing
    int timeout__ms = 10000000; //10 sec = 10000 ms
    l_res = dap_chain_node_client_wait(s_vpn_client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
    if(l_res) {
        log_it(L_ERROR, "No response from VPN server=%s:%d", a_ipv4_str, a_port);
        // clean client struct
        dap_chain_node_client_close(s_vpn_client);
        DAP_DELETE(s_node_info);
        s_node_info = NULL;
        return -3;
    }

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

    dap_client_stage_t l_stage_target = STAGE_STREAM_STREAMING; //DAP_CLIENT_STAGE_STREAM_CTL;//STAGE_STREAM_STREAMING;
    const char l_active_channels[] = { dap_stream_ch_chain_net_srv_get_id(), DAP_STREAM_CH_ID_NET_SRV_VPN, 0 }; //R, S
    if(a_ipv4_str)
        inet_pton(AF_INET, a_ipv4_str, &(s_node_info->hdr.ext_addr_v4));
    if(a_ipv6_str)
        inet_pton(AF_INET6, a_ipv6_str, &(s_node_info->hdr.ext_addr_v6));

    s_vpn_client = dap_chain_client_connect(s_node_info, l_stage_target, l_active_channels);
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
    int res = dap_chain_node_client_wait(s_vpn_client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
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
        dap_stream_ch_t *l_ch = dap_client_get_stream_ch(s_vpn_client->client, l_ch_id);
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
            dap_stream_ch_pkt_write(l_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST, &l_request, sizeof(l_request));
            dap_stream_ch_set_ready_to_write(l_ch, true);
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
        dap_stream_ch_t *l_ch = dap_client_get_stream_ch(s_vpn_client->client, l_ch_id);
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

static void vpn_socket_delete(ch_vpn_socket_proxy_t * sf)
{
    close(sf->sock);
    pthread_mutex_destroy(&(sf->mutex));
    if(sf)
        free(sf);
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
    } else { // All except CONNECT
        ch_vpn_socket_proxy_t * sf_sock = NULL;
        if((l_sf_pkt->header.op_code != VPN_PACKET_OP_CODE_CONNECT) // tcp
        && (l_sf_pkt->header.op_code != VPN_PACKET_OP_CODE_CONNECTED)) { //udp

            pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
            log_it(L_DEBUG, "Looking in hash table with %d", remote_sock_id);
            HASH_FIND_INT((CH_VPN(a_ch)->socks), &remote_sock_id, sf_sock);
            pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

            if(sf_sock != NULL) {
                pthread_mutex_lock(&sf_sock->mutex); // Unlock it in your case as soon as possible to reduce lock time
                sf_sock->time_lastused = time(NULL);
                switch (l_sf_pkt->header.op_code) {
                case VPN_PACKET_OP_CODE_SEND: {
                    int ret;
                    if((ret = send(sf_sock->sock, l_sf_pkt->data, l_sf_pkt->header.op_data.data_size, 0)) < 0) {
                        log_it(L_INFO, "Disconnected from the remote host");
                        pthread_mutex_unlock(&sf_sock->mutex);
                        pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
                        HASH_DEL(CH_VPN(a_ch)->socks, sf_sock);
                        pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

                        pthread_mutex_lock(&sf_socks_mutex);
                        HASH_DELETE(hh2, sf_socks, sf_sock);
                        HASH_DELETE(hh_sock, sf_socks_client, sf_sock);

                        struct epoll_event ev;
                        ev.data.fd = sf_sock->sock;
                        ev.events = EPOLLIN;
                        if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_DEL, sf_sock->sock, &ev) < 0) {
                            log_it(L_ERROR, "Can't remove sock_id %d from the epoll fd", remote_sock_id);
                            //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=0x%02x result=-2",sf_pkt->sock_id, sf_pkt->op_code);
                        } else {
                            log_it(L_NOTICE, "Removed sock_id %d from the the epoll fd", remote_sock_id);
                            //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=0x%02x result=0",sf_pkt->sock_id, sf_pkt->op_code);
                        }
                        pthread_mutex_unlock(&sf_socks_mutex);

                        vpn_socket_delete(sf_sock);
                    } else {
                        sf_sock->bytes_sent += ret;
                        pthread_mutex_unlock(&sf_sock->mutex);
                    }
                    log_it(L_INFO, "Send action from %d sock_id (sf_packet size %lu,  ch packet size %lu, have sent %d)"
                            , sf_sock->id, l_sf_pkt->header.op_data.data_size, a_pkt->hdr.size, ret);
                }
                    break;
                case VPN_PACKET_OP_CODE_DISCONNECT: {
                    log_it(L_INFO, "Disconnect action from %d sock_id", sf_sock->id);

                    pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
                    HASH_DEL(CH_VPN(a_ch)->socks, sf_sock);
                    pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

                    pthread_mutex_lock(&sf_socks_mutex);

                    HASH_DELETE(hh2, sf_socks, sf_sock);
                    HASH_DELETE(hh_sock, sf_socks_client, sf_sock);

                    struct epoll_event ev;
                    ev.data.fd = sf_sock->sock;
                    ev.events = EPOLLIN;
                    if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_DEL, sf_sock->sock, &ev) < 0) {
                        log_it(L_ERROR, "Can't remove sock_id %d to the epoll fd", remote_sock_id);
                        //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=%uc result=-2",sf_pkt->sock_id, sf_pkt->op_code);
                    } else {
                        log_it(L_NOTICE, "Removed sock_id %d from the epoll fd", remote_sock_id);
                        //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=%uc result=0",sf_pkt->sock_id, sf_pkt->op_code);
                    }
                    pthread_mutex_unlock(&sf_socks_mutex);

                    pthread_mutex_unlock(&sf_sock->mutex);
                    vpn_socket_delete(sf_sock);
                }
                    break;
                default: {
                    log_it(L_WARNING, "Unprocessed op code 0x%02x", l_sf_pkt->header.op_code);
                    pthread_mutex_unlock(&sf_sock->mutex);
                }
                }
            } else
                log_it(L_WARNING, "Packet input: packet with sock_id %d thats not present in current stream channel",
                        remote_sock_id);
        } else {
            HASH_FIND_INT(CH_VPN(a_ch)->socks, &remote_sock_id, sf_sock);
            if(sf_sock) {
                log_it(L_WARNING, "Socket id %d is already used, take another number for socket id", remote_sock_id);
            } else { // Connect action
                struct sockaddr_in remote_addr;
                char addr_str[1024];
                size_t addr_str_size =
                        (l_sf_pkt->header.op_connect.addr_size > (sizeof(addr_str) - 1)) ?
                                (sizeof(addr_str) - 1) :
                                l_sf_pkt->header.op_connect.addr_size;
                memset(&remote_addr, 0, sizeof(remote_addr));
                remote_addr.sin_family = AF_INET;
                remote_addr.sin_port = htons(l_sf_pkt->header.op_connect.port);

                memcpy(addr_str, l_sf_pkt->data, addr_str_size);
                addr_str[addr_str_size] = 0;

                log_it(L_DEBUG, "Connect action to %s:%u (addr_size %lu)", addr_str, l_sf_pkt->header.op_connect.port,
                        l_sf_pkt->header.op_connect.addr_size);
                if(inet_pton(AF_INET, addr_str, &(remote_addr.sin_addr)) < 0) {
                    log_it(L_ERROR, "Wrong remote address '%s:%u'", addr_str, l_sf_pkt->header.op_connect.port);

                    ch_vpn_pkt_t *l_pkt_out = DAP_NEW_Z(ch_vpn_pkt_t);
                    l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;

                    dap_stream_ch_pkt_write(a_ch, 'd', l_pkt_out,
                            l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header));
                    dap_stream_ch_set_ready_to_write(a_ch, true);

                    free(l_pkt_out);

                } else {
                    int s;
                    if((s = socket(AF_INET,
                            (l_sf_pkt->header.op_code == VPN_PACKET_OP_CODE_CONNECT) ?
                            SOCK_STREAM :
                                                                                       SOCK_DGRAM, 0)) >= 0) {
                        log_it(L_DEBUG, "Socket is created (%d)", s);
                        if(connect(s, (struct sockaddr *) &remote_addr, sizeof(remote_addr)) >= 0) {
                            fcntl(s, F_SETFL, O_NONBLOCK);
                            log_it(L_INFO, "Remote address connected (%s:%u) with sock_id %d", addr_str,
                                    l_sf_pkt->header.op_connect.port, remote_sock_id);
                            ch_vpn_socket_proxy_t * sf_sock = NULL;
                            sf_sock = DAP_NEW_Z(ch_vpn_socket_proxy_t);
                            sf_sock->id = remote_sock_id;
                            sf_sock->sock = s;
                            sf_sock->ch = a_ch;
                            pthread_mutex_init(&sf_sock->mutex, NULL);

                            pthread_mutex_lock(&sf_socks_mutex);
                            pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
                            HASH_ADD_INT(CH_VPN(a_ch)->socks, id, sf_sock);
                            log_it(L_DEBUG, "Added %d sock_id with sock %d to the hash table", sf_sock->id,
                                    sf_sock->sock);
                            HASH_ADD(hh2, sf_socks, id, sizeof(sf_sock->id), sf_sock);
                            log_it(L_DEBUG, "Added %d sock_id with sock %d to the hash table", sf_sock->id,
                                    sf_sock->sock);
                            HASH_ADD(hh_sock, sf_socks_client, sock, sizeof(int), sf_sock);
                            // log_it(L_DEBUG,"Added %d sock_id with sock %d to the socks hash table",sf->id,sf->sock);
                            pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));
                            pthread_mutex_unlock(&sf_socks_mutex);

                            struct epoll_event ev;
                            ev.data.fd = s;
                            ev.events = EPOLLIN | EPOLLERR;

                            if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_ADD, s, &ev) == -1) {
                                log_it(L_ERROR, "Can't add sock_id %d to the epoll fd", remote_sock_id);
                                //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=%uc result=-2",sf_pkt->sock_id, sf_pkt->op_code);
                            } else {
                                log_it(L_NOTICE, "Added sock_id %d  with sock %d to the epoll fd", remote_sock_id, s);
                                //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=%uc result=0",sf_pkt->sock_id, sf_pkt->op_code);
                            }
                            dap_stream_ch_set_ready_to_write(a_ch, true);
                        } else {
                            ch_vpn_pkt_t *l_pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(l_pkt_out->header));
                            l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;

                            dap_stream_ch_pkt_write(a_ch, 'd', l_pkt_out,
                                    l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header));
                            dap_stream_ch_set_ready_to_write(a_ch, true);

                            free(l_pkt_out);

                            log_it(L_INFO, "Can't connect to the remote server %s", addr_str);
                            dap_stream_ch_pkt_write_f(a_ch, 'i', "sock_id=%d op_code=%c result=-1",
                                    l_sf_pkt->header.sock_id, l_sf_pkt->header.op_code);
                            dap_stream_ch_set_ready_to_write(a_ch, true);

                        }
                    } else {
                        log_it(L_ERROR, "Can't create the socket");
                        ch_vpn_pkt_t *l_pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(l_pkt_out->header));
                        l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;

                        dap_stream_ch_pkt_write(a_ch, 'd', l_pkt_out,
                                l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header));
                        dap_stream_ch_set_ready_to_write(a_ch, true);

                        free(l_pkt_out);

                    }
                }
            }
        }
    }
}

/**
 * @brief dap_chain_net_vpn_client_pkt_out
 * @param a_ch
 */
void dap_chain_net_vpn_client_pkt_out(dap_stream_ch_t* a_ch)
{
    ch_vpn_socket_proxy_t * l_cur = NULL, *l_tmp;
    bool l_is_smth_out = false;
//    log_it(L_DEBUG,"Socket forwarding packet out callback: %u sockets in hashtable", HASH_COUNT(CH_VPN(ch)->socks) );
    HASH_ITER(hh, CH_VPN(a_ch)->socks , l_cur, l_tmp)
    {
        bool l_signal_to_break = false;
        pthread_mutex_lock(&(l_cur->mutex));
        int i;
//        log_it(L_DEBUG,"Socket with id %d has %u packets in output buffer", cur->id, cur->pkt_out_size );
        if(l_cur->pkt_out_size) {
            for(i = 0; i < l_cur->pkt_out_size; i++) {
                ch_vpn_pkt_t * pout = l_cur->pkt_out[i];
                if(pout) {
                    if(dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pout,
                            pout->header.op_data.data_size + sizeof(pout->header))) {
                        l_is_smth_out = true;
                        if(pout)
                            free(pout);
                        l_cur->pkt_out[i] = NULL;
                    } else {
                        log_it(L_WARNING,
                                "Buffer is overflowed, breaking cycle to let the upper level cycle drop data to the output socket");
                        l_is_smth_out = true;
                        l_signal_to_break = true;
                        break;
                    }
                }
            }
        }

        if(l_signal_to_break) {
            pthread_mutex_unlock(&(l_cur->mutex));
            break;
        }
        l_cur->pkt_out_size = 0;
        if(l_cur->signal_to_delete) {
            log_it(L_NOTICE, "Socket id %d got signal to be deleted", l_cur->id);
            pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
            HASH_DEL(CH_VPN(a_ch)->socks, l_cur);
            pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

            pthread_mutex_lock(&(sf_socks_mutex));
            HASH_DELETE(hh2, sf_socks, l_cur);
            HASH_DELETE(hh_sock, sf_socks_client, l_cur);
            pthread_mutex_unlock(&(sf_socks_mutex));

            pthread_mutex_unlock(&(l_cur->mutex));
            vpn_socket_delete(l_cur);
        } else
            pthread_mutex_unlock(&(l_cur->mutex));
    }
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
    "vpn_client [start -addr <server address> -port <server port>| stop | status] -net <net name>\n");


    return dap_chain_net_srv_client_vpn_init(g_config);
}

void dap_chain_net_vpn_client_deinit()
{
    pthread_mutex_destroy(&sf_socks_mutex);
}
