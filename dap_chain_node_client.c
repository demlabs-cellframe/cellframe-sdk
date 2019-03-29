/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <glib.h>
#include <time.h>

#include "dap_common.h"
#include "dap_client.h"
#include "dap_config.h"
#include "dap_events.h"
#include "dap_http_client_simple.h"
#include "dap_client_pvt.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_pkt.h"
#include "dap_chain_node_client.h"

#define LOG_TAG "dap_chain_node_client"

#define DAP_APP_NAME NODE_NETNAME"-node"
#define SYSTEM_PREFIX "/opt/"DAP_APP_NAME
#define SYSTEM_CONFIGS_DIR SYSTEM_PREFIX"/etc"

static int listen_port_tcp = 8079;

int dap_chain_node_client_init(void)
{
    int res = dap_client_init();
    res = dap_http_client_simple_init();
    dap_config_t *g_config;
    // read listen_port_tcp from settings
    dap_config_init(SYSTEM_CONFIGS_DIR);
    if((g_config = dap_config_open(DAP_APP_NAME)) == NULL) {
        return -1;
    }
    else {
        const char *port_str = dap_config_get_item_str(g_config, "server", "listen_port_tcp");
        listen_port_tcp = (port_str) ? atoi(port_str) : 8079;
    }
    if(g_config)
        dap_config_close(g_config);
    return res;
}

void dap_chain_node_client_deinit()
{
    dap_http_client_simple_deinit();
    dap_client_deinit();
}

// callback for dap_client_new() in chain_node_client_connect()
static void stage_status_callback(dap_client_t *a_client, void *a_arg)
{
    //printf("* stage_status_callback client=%x data=%x\n", a_client, a_arg);
}
// callback for dap_client_new() in chain_node_client_connect()
static void stage_status_error_callback(dap_client_t *a_client, void *a_arg)
{
    //printf("* tage_status_error_callback client=%x data=%x\n", a_client, a_arg);
}

// callback for the end of connection in dap_chain_node_client_connect()->dap_client_go_stage()
static void a_stage_end_callback(dap_client_t *a_client, void *a_arg)
{
    dap_chain_node_client_t *client = a_client->_inheritor;
    assert(client);
    if(client) {
        pthread_mutex_lock(&client->wait_mutex);
        client->state = NODE_CLIENT_STATE_CONNECTED;
        pthread_cond_signal(&client->wait_cond);
        pthread_mutex_unlock(&client->wait_mutex);
    }
}

/**
 * Create connection to server
 *
 * return a connection handle, or NULL, if an error
 */
dap_chain_node_client_t* dap_chain_node_client_connect(dap_chain_node_info_t *node_info)
{
    if(!node_info)
        return NULL;
    dap_chain_node_client_t *l_node_client = DAP_NEW_Z(dap_chain_node_client_t);
    l_node_client->state = NODE_CLIENT_STATE_INIT;
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&l_node_client->wait_cond, &attr);
    pthread_mutex_init(&l_node_client->wait_mutex, NULL);
    l_node_client->events = NULL; //dap_events_new();
    l_node_client->client = dap_client_new(l_node_client->events, stage_status_callback, stage_status_error_callback);
    l_node_client->client->_inheritor = l_node_client;

    int hostlen = 128;
    char host[hostlen];
    if(node_info->hdr.ext_addr_v4.s_addr)
    {
        struct sockaddr_in sa4 = { .sin_family = AF_INET, .sin_addr = node_info->hdr.ext_addr_v4 };
        inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa4)->sin_addr), host, hostlen);
    }
    else
    {
        struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6, .sin6_addr = node_info->hdr.ext_addr_v6 };
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &sa6)->sin6_addr), host, hostlen);
    }
    // address not defined
    if(!strcmp(host, "::")) {
        dap_chain_node_client_close(l_node_client);
        return NULL;
    }
    dap_client_set_uplink(l_node_client->client, strdup(host), listen_port_tcp);
//    dap_client_stage_t a_stage_target = STAGE_ENC_INIT;
    dap_client_stage_t a_stage_target = STAGE_STREAM_STREAMING;

    l_node_client->state = NODE_CLIENT_STATE_CONNECT;
    // Handshake & connect
    dap_client_go_stage(l_node_client->client, a_stage_target, a_stage_end_callback);
    return l_node_client;
}

/**
 * Close connection to server, delete chain_node_client_t *client
 */
void dap_chain_node_client_close(dap_chain_node_client_t *a_client)
{
    if(a_client) {
        // clean client
        dap_client_delete(a_client->client);
        dap_events_delete(a_client->events);
        pthread_cond_destroy(&a_client->wait_cond);
        pthread_mutex_destroy(&a_client->wait_mutex);
        DAP_DELETE(a_client);
    }
}

/*
 // callback for dap_client_request_enc() in client_mempool_send_datum()
 static void s_response_proc(dap_client_t *a_client, void *str, size_t str_len)
 {
 printf("* s_response_proc a_client=%x str=%s str_len=%d\n", a_client, str, str_len);
 dap_chain_node_client_t *l_client = a_client->_inheritor;
 assert(l_client);
 if(l_client) {
 if(str_len > 0) {
 //            l_client->read_data_t.data = DAP_NEW_Z_SIZE(uint8_t, str_len + 1);
 //          if(l_client->read_data_t.data) {
 //                memcpy(l_client->read_data_t.data, str, str_len);
 //                l_client->read_data_t.data_len = str_len;
 }
 }
 pthread_mutex_lock(&l_client->wait_mutex);
 l_client->state = NODE_CLIENT_STATE_SENDED;
 pthread_cond_signal(&l_client->wait_cond);
 pthread_mutex_unlock(&l_client->wait_mutex);
 }
 */

/*// callback for dap_client_request_enc() in client_mempool_send_datum()
 static void s_response_error(dap_client_t *a_client, int val)
 {
 printf("* s_response_error a_client=%x val=%d\n", a_client, val);
 client_mempool_t *mempool = a_client->_inheritor;
 assert(mempool);
 if(mempool) {
 pthread_mutex_lock(&mempool->wait_mutex);
 mempool->state = CLIENT_MEMPOOL_ERROR;
 pthread_cond_signal(&mempool->wait_cond);
 pthread_mutex_unlock(&mempool->wait_mutex);
 }
 }

 // set new state and delete previous read data
 static void dap_chain_node_client_reset(dap_chain_node_client_t *a_client, int new_state)
 {
 if(!a_client)
 return;
 pthread_mutex_lock(&a_client->wait_mutex);
 //a_client->read_data_t.data_len = 0;
 //DAP_DELETE(a_client->read_data_t.data);
 //a_client->read_data_t.data = NULL;
 a_client->state = new_state;
 pthread_mutex_unlock(&a_client->wait_mutex);
 }*/

static void dap_chain_node_client_callback(dap_stream_ch_chain_net_pkt_t *a_ch_chain_net, void *a_arg)
{
    dap_chain_node_client_t *client = (dap_chain_node_client_t*) a_arg;
    assert(client);
    int l_state;
    switch (a_ch_chain_net->hdr.type) {
    case STREAM_CH_CHAIN_NET_PKT_TYPE_PING:
        l_state = NODE_CLIENT_STATE_PING;
        break;
    case STREAM_CH_CHAIN_NET_PKT_TYPE_PONG:
        l_state = NODE_CLIENT_STATE_PONG;
        break;
    case STREAM_CH_CHAIN_NET_PKT_TYPE_GLOVAL_DB:
        l_state = NODE_CLIENT_STATE_END;
        break;

    default:
        l_state = NODE_CLIENT_STATE_ERROR;

    }
    if(client)
    {
        pthread_mutex_lock(&client->wait_mutex);
        client->state = l_state;
        pthread_cond_signal(&client->wait_cond);
        pthread_mutex_unlock(&client->wait_mutex);
    }
}

/**
 * Send stream request to server
 */
int dap_chain_node_client_send_chain_net_request(dap_chain_node_client_t *a_client, uint8_t a_ch_id, uint8_t a_type,
        char *a_buf, size_t a_buf_size)
{
    if(!a_client || a_client->state < NODE_CLIENT_STATE_CONNECTED)
        return -1;
    dap_stream_t *l_stream = dap_client_get_stream(a_client->client);
    dap_stream_ch_t * l_ch = dap_client_get_stream_ch(a_client->client, a_ch_id);
    if(l_ch)
    {
        dap_stream_ch_chain_net_t * l_ch_chain = DAP_STREAM_CH_CHAIN_NET(l_ch);
        l_ch_chain->notify_callback = dap_chain_node_client_callback;
        l_ch_chain->notify_callback_arg = a_client;
        int l_res = dap_stream_ch_chain_net_pkt_write(l_ch, a_type, a_buf, a_buf_size);
        if(l_res <= 0)
            return -1;
        bool is_ready = true;
        dap_events_socket_set_writable(l_ch->stream->events_socket, is_ready);
        //dap_stream_ch_ready_to_write(ch, true);
    }
    else
        return -1;
    return 1;
}

/**
 * wait for the complete of request
 *
 * timeout_ms timeout in milliseconds
 * waited_state state which we will wait, sample NODE_CLIENT_STATE_CONNECT or NODE_CLIENT_STATE_SENDED
 * return -1 false, 0 timeout, 1 end of connection or sending data
 */
int chain_node_client_wait(dap_chain_node_client_t *a_client, int a_waited_state, int timeout_ms)
{
    int ret = -1;
    if(!a_client)
        return -1;
    pthread_mutex_lock(&a_client->wait_mutex);
    // have waited
    if(a_client->state == a_waited_state) {
        pthread_mutex_unlock(&a_client->wait_mutex);
        return 1;
    }
    // prepare for signal waiting
    struct timespec to;
    clock_gettime(CLOCK_MONOTONIC, &to);
    int64_t nsec_new = to.tv_nsec + timeout_ms * 1000000ll;
    // if the new number of nanoseconds is more than a second
    if(nsec_new > (long) 1e9) {
        to.tv_sec += nsec_new / (long) 1e9;
        to.tv_nsec = nsec_new % (long) 1e9;
    }
    else
        to.tv_nsec = (long) nsec_new;
    // signal waiting
    int wait = pthread_cond_timedwait(&a_client->wait_cond, &a_client->wait_mutex, &to);
    if(wait == 0) //0
        ret = 1;
    else if(wait == ETIMEDOUT) // 110 260
        ret = 0;
    pthread_mutex_unlock(&a_client->wait_mutex);
    return ret;
}
