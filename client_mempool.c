/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
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
#include <string.h>
#include <time.h>
#include <assert.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <time.h>
#include <pthread.h>
#endif

#include "dap_common.h"
#include "dap_config.h"
#include "dap_events.h"
#include "dap_chain_node.h"
#include "dap_client_pvt.h"
#include "dap_http_client_simple.h"
#include "client_mempool.h"

#define DAP_APP_NAME NODE_NETNAME"-node"
#define SYSTEM_PREFIX "/opt/"DAP_APP_NAME
#define SYSTEM_CONFIGS_DIR SYSTEM_PREFIX"/etc"

#define LOG_TAG "dap_client_mempool"

static int listen_port_tcp = 8079;

// send request to server
static int client_mempool_send_request(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool,
        const char *action, bool is_last_req);


// callback for dap_client_new() in client_mempool_connect()
static void stage_status_callback(dap_client_t *a_client, void *a_arg)
{
    //printf("* stage_status_callback client=%x data=%x\n", a_client, a_arg);
}
// callback for dap_client_new() in client_mempool_connect()
static void stage_status_error_callback(dap_client_t *a_client, void *a_arg)
{
    //printf("* tage_status_error_callback client=%x data=%x\n", a_client, a_arg);
}

// callback for dap_client_request_enc() in client_mempool_send_datum()
static void a_response_proc(dap_client_t *a_client, void *str, size_t str_len)
{
    //printf("a* _response_proc a_client=%x str=%s str_len=%d\n", a_client, str, str_len);
    client_mempool_t *mempool = a_client->_inheritor;
    assert(mempool);
    if(mempool) {
        if(str_len > 0) {
            mempool->read_data_t.data = DAP_NEW_Z_SIZE(uint8_t, str_len + 1);
            if(mempool->read_data_t.data) {
                memcpy(mempool->read_data_t.data, str, str_len);
                mempool->read_data_t.data_len = str_len;
            }
        }
        pthread_mutex_lock(&mempool->wait_mutex);
        mempool->state = CLIENT_MEMPOOL_SENDED;

#ifndef _WIN32
        pthread_cond_signal(&mempool->wait_cond);
#else
        SetEvent( mempool->wait_cond );
#endif

        pthread_mutex_unlock(&mempool->wait_mutex);
    }
}

// callback for dap_client_request_enc() in client_mempool_send_datum()
static void a_response_error(dap_client_t *a_client, int val)
{
    //printf("* a_response_error a_client=%x val=%d\n", a_client, val);
    client_mempool_t *mempool = a_client->_inheritor;
    assert(mempool);
    if(mempool) {
        pthread_mutex_lock(&mempool->wait_mutex);
        mempool->state = CLIENT_MEMPOOL_ERROR;
#ifndef _WIN32
        pthread_cond_signal(&mempool->wait_cond);
#else
        SetEvent( mempool->wait_cond );
#endif
        pthread_mutex_unlock(&mempool->wait_mutex);
    }
}

// callback for the end of handshake in dap_client_go_stage() / client_mempool_connect()
static void a_stage_end_callback(dap_client_t *a_client, void *a_arg)
{
    client_mempool_t *mempool = a_client->_inheritor;
    assert(mempool);
    if(mempool) {
        pthread_mutex_lock(&mempool->wait_mutex);
        mempool->state = CLIENT_MEMPOOL_CONNECTED;
#ifndef _WIN32
        pthread_cond_signal(&mempool->wait_cond);
#else
        SetEvent( mempool->wait_cond );
#endif
        pthread_mutex_unlock(&mempool->wait_mutex);
    }
}

int client_mempool_init(void)
{
    /*dap_config_t *g_config;
    // read listen_port_tcp from settings
    dap_config_init(SYSTEM_CONFIGS_DIR);
    if((g_config = dap_config_open(DAP_APP_NAME)) == NULL) {
        return -1;
    }
    else { */
    listen_port_tcp = dap_config_get_item_int32_default(g_config, "server", "listen_port_tcp", 8079);
    /*}
    if(g_config)
        dap_config_close(g_config); */
    return 0;
}

void client_mempool_deinit()
{
    dap_http_client_simple_deinit();
    dap_client_deinit();
}

client_mempool_t *client_mempool_connect(const char *addr)
{
    if(!addr || strlen(addr) < 1)
        return NULL;
    client_mempool_t *mempool = DAP_NEW_Z(client_mempool_t);
    mempool->state = CLIENT_MEMPOOL_INIT;

    log_it(L_NOTICE, "======= client_mempool_connect( )" );

#ifndef _WIN32
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&mempool->wait_cond, &attr);
#else
    mempool->wait_cond = CreateEventA( NULL, FALSE, FALSE, NULL );
#endif

    pthread_mutex_init(&mempool->wait_mutex, NULL);
    mempool->a_events = dap_events_new();
    mempool->a_client = dap_client_new(mempool->a_events, stage_status_callback, stage_status_error_callback);
    mempool->a_client->_inheritor = mempool;
    dap_client_pvt_t *l_client_internal = DAP_CLIENT_PVT(mempool->a_client);

    l_client_internal->uplink_addr = strdup(addr);
    l_client_internal->uplink_port = listen_port_tcp; // reads from settings, default 8079
    l_client_internal->uplink_protocol_version = DAP_PROTOCOL_VERSION;
    dap_client_stage_t a_stage_target = STAGE_ENC_INIT;

    mempool->state = CLIENT_MEMPOOL_CONNECT;
    // Handshake
    dap_client_go_stage(mempool->a_client, a_stage_target, a_stage_end_callback);
    return mempool;
}

/**
 * wait for the complete of request
 *
 * timeout_ms timeout in milliseconds
 * waited_state state which we will wait, sample CLIENT_MEMPOOL_CONNECTED or CLIENT_MEMPOOL_SENDED
 * return -1 false, 0 timeout, 1 end of connection or sending data
 */
int client_mempool_wait(client_mempool_t *mempool, int waited_state, int timeout_ms)
{
    int ret = -1;
    if( !mempool )
        return -1;

    log_it(L_NOTICE, "======= client_mempool_wait( ) tm %u ms", timeout_ms );

    pthread_mutex_lock(&mempool->wait_mutex);
// have waited
    if(mempool->state == waited_state) {
        pthread_mutex_unlock(&mempool->wait_mutex);
        return 1;
    }
// prepare for signal waiting
#ifndef _WIN32
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
    int wait = pthread_cond_timedwait(&mempool->wait_cond, &mempool->wait_mutex, &to);
    if(wait == 0) //0
        ret = 1;
    else if(wait == ETIMEDOUT) // 110 260
        ret = 0;
#else
    int wait = WaitForSingleObject( mempool->wait_cond, (uint32_t)timeout_ms );
    pthread_mutex_lock(&mempool->wait_mutex);

    if ( wait == WAIT_OBJECT_0 ) return 1;
    else if ( wait == WAIT_TIMEOUT || wait == WAIT_FAILED ) {
        ret = 0;
    }
#endif

    pthread_mutex_unlock(&mempool->wait_mutex);
    return ret;
}

/**
 * get read data from server
 */
uint8_t* client_mempool_read(client_mempool_t *mempool, int *data_len)
{
    if(mempool && mempool->read_data_t.data_len > 0) {

        uint8_t*data = DAP_NEW_Z_SIZE(uint8_t, mempool->read_data_t.data_len + 1);
        if(mempool->read_data_t.data) {
            memcpy(data, mempool->read_data_t.data, mempool->read_data_t.data_len);
            if(data_len)
                *data_len = mempool->read_data_t.data_len;
            return data;
        }
    }
    return NULL;
}

void client_mempool_close(client_mempool_t *mempool)
{
    if(mempool) {
        // send last request for dehandshake with "SessionCloseAfterRequest=true"
        client_mempool_send_request(mempool, NULL, 0, true);
        // wait close session
        client_mempool_wait(mempool, CLIENT_MEMPOOL_SENDED, 500);
        // clean mempool
        dap_client_pvt_t *l_client_internal = DAP_CLIENT_PVT(mempool->a_client);
        DAP_DELETE(l_client_internal->uplink_addr);
        dap_client_delete(mempool->a_client);
        dap_events_delete(mempool->a_events);
        DAP_DELETE(mempool->read_data_t.data);
        pthread_cond_destroy(&mempool->wait_cond);
        pthread_mutex_destroy(&mempool->wait_mutex);
        DAP_DELETE(mempool);
    }
}

// set new state and delete previous read data
static void client_mempool_reset(client_mempool_t *mempool, int new_state)
{
    if(!mempool)
        return;
    pthread_mutex_lock(&mempool->wait_mutex);
    mempool->read_data_t.data_len = 0;
    DAP_DELETE(mempool->read_data_t.data);
    mempool->read_data_t.data = NULL;
    mempool->state = new_state;
    pthread_mutex_unlock(&mempool->wait_mutex);
}

// send request to server
static int client_mempool_send_request(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool,
        const char *action, bool is_last_req)
{
    if(!mempool || mempool->state < CLIENT_MEMPOOL_CONNECTED)
        return -1;
    const char * a_path = "mempool";
    const char *a_suburl = (action) ? action : "close";
    const char* a_query = NULL;
    size_t a_request_size = 1;
    uint8_t *a_request = (datum_mempool) ? dap_datum_mempool_serialize(datum_mempool, &a_request_size) : (uint8_t*) " ";
    uint8_t *a_request_out = DAP_NEW_Z_SIZE(uint8_t, a_request_size * 2); // a_request + 1 byte for type action
    dap_bin2hex(a_request_out, a_request, a_request_size);
    client_mempool_reset(mempool, CLIENT_MEMPOOL_SEND);
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(mempool->a_client);
    l_client_internal->is_close_session = is_last_req;
    dap_client_request_enc(mempool->a_client, a_path, a_suburl, a_query, a_request_out, a_request_size * 2,
            a_response_proc, a_response_error);
    if(datum_mempool)
        DAP_DELETE(a_request);
    DAP_DELETE(a_request_out);
    return 1;
}

/**
 * datum add in mempool
 *
 * return -1 not connected or error, 1 send packet OK
 */
int client_mempool_send_datum(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool)
{
    return client_mempool_send_request(mempool, datum_mempool, "add", false);
}

/**
 * datum check in mempool
 *
 * return -1 not connected or error, 1 send packet OK
 */
int client_mempool_check_datum(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool)
{
    return client_mempool_send_request(mempool, datum_mempool, "check", false);
}

/**
 * datum delete from mempool
 *
 * return -1 not connected or error, 1 send packet OK
 */
int client_mempool_del_datum(client_mempool_t *mempool, dap_datum_mempool_t *datum_mempool)
{
    return client_mempool_send_request(mempool, datum_mempool, "del", false);
}
