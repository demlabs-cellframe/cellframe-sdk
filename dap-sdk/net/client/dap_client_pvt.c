/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#else
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include <pthread.h>

#include <json-c/json.h>

#include "dap_enc_key.h"
#include "dap_enc_base64.h"
#include "dap_enc.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_cert.h"
#include "dap_uuid.h"

#include "dap_timerfd.h"
//#include "dap_http_client_simple.h"
#include "dap_client_http.h"
#include "dap_client.h"
#include "dap_client_pvt.h"
#include "dap_server.h"
#include "dap_stream.h"
#include "dap_stream_worker.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_pkt.h"
#include "dap_http_client.h"

#define LOG_TAG "dap_client_pvt"

#ifndef DAP_ENC_KS_KEY_ID_SIZE
#define DAP_ENC_KS_KEY_ID_SIZE 33
#endif

static int s_max_attempts = 3;
static int s_timeout = 20;
static bool s_debug_more = false;
static time_t s_client_timeout_read_after_connect_seconds = 5;


static bool s_stage_status_after(dap_client_pvt_t * a_client_internal);

// ENC stage callbacks
static void s_enc_init_response(dap_client_t *, void *, size_t);
static void s_enc_init_error(dap_client_t *, int);
static bool s_enc_init_delay_before_request_timer_callback(void*);

// STREAM_CTL stage callbacks
static void s_stream_ctl_response(dap_client_t *, void *, size_t);
static void s_stream_ctl_error(dap_client_t *, int);
static void s_stage_stream_streaming(dap_client_t * a_client, void* arg);

// STREAM stage callbacks
static void s_stream_response(dap_client_t *, void *, size_t);
static void s_request_response(void * a_response, size_t a_response_size, void * a_obj);
static void s_request_error(int, void *);

// Stream connection callback
static void s_stream_connected(dap_client_pvt_t * a_client_pvt);

// stream callbacks
static void s_stream_es_callback_connected(dap_events_socket_t * a_es);
static void s_stream_es_callback_delete(dap_events_socket_t * a_es, void * arg);
static void s_stream_es_callback_read(dap_events_socket_t * a_es, void * arg);
static void s_stream_es_callback_write(dap_events_socket_t * a_es, void * arg);
static void s_stream_es_callback_error(dap_events_socket_t * a_es, int a_arg);

// Timer callbacks
static bool s_stream_timer_timeout_after_connected_check(void * a_arg);
static bool s_stream_timer_timeout_check(void * a_arg);



/**
 * @brief dap_client_internal_init
 * @return
 */
int dap_client_pvt_init()
{
    s_max_attempts = dap_config_get_item_int32_default(g_config, "dap_client", "max_tries", s_max_attempts);
    s_timeout = dap_config_get_item_int32_default(g_config, "dap_client", "timeout", s_timeout);
    s_debug_more = dap_config_get_item_bool_default(g_config, "dap_client", "debug_more", false);
    s_client_timeout_read_after_connect_seconds = (time_t) dap_config_get_item_uint32_default(g_config,
                                                  "dap_client","timeout_read_after_connect", s_client_timeout_read_after_connect_seconds);

    return 0;
}

/**
 * @brief dap_client_internal_deinit
 */
void dap_client_pvt_deinit()
{
}

/**
 * @brief dap_client_internal_new
 * @param a_client_internal
 */
void dap_client_pvt_new(dap_client_pvt_t * a_client_pvt)
{
    a_client_pvt->uuid = dap_uuid_generate_uint64();
    a_client_pvt->session_key_type = DAP_ENC_KEY_TYPE_SALSA2012 ;
    a_client_pvt->session_key_open_type = DAP_ENC_KEY_TYPE_MSRLN ;
    a_client_pvt->session_key_block_size = 32;

    a_client_pvt->stage = STAGE_BEGIN; // start point of state machine
    a_client_pvt->stage_status = STAGE_STATUS_DONE;
    a_client_pvt->uplink_protocol_version = DAP_PROTOCOL_VERSION;
    a_client_pvt->events = dap_events_get_default();
    // add to list
    dap_client_pvt_hh_add_unsafe(a_client_pvt);
}



/**
 * @brief dap_client_pvt_delete_unsafe
 * @param a_client_pvt
 */
void dap_client_pvt_delete_unsafe(dap_client_pvt_t * a_client_pvt)
{
    assert(a_client_pvt);

    if (!dap_client_pvt_find(a_client_pvt->uuid)) {
        if(s_debug_more)
            log_it(L_DEBUG, "dap_client_pvt 0x%p already deleted", a_client_pvt);
        return;
    }
    if(a_client_pvt->delete_callback)
        a_client_pvt->delete_callback(a_client_pvt->client, NULL);
    if (a_client_pvt->stream_es) {
        dap_events_socket_remove_and_delete_unsafe(a_client_pvt->stream_es, true);
    }
    // delete from list
    dap_client_pvt_hh_del_unsafe(a_client_pvt);
    if(s_debug_more)
        log_it(L_INFO, "dap_client_pvt_delete 0x%p", a_client_pvt);

    if(a_client_pvt->uplink_addr)
        DAP_DELETE(a_client_pvt->uplink_addr);

    if(a_client_pvt->session_key_id)
        DAP_DELETE(a_client_pvt->session_key_id);

    if(a_client_pvt->active_channels)
        DAP_DELETE(a_client_pvt->active_channels);

    if(a_client_pvt->session_key)
        dap_enc_key_delete(a_client_pvt->session_key);

    if(a_client_pvt->session_key_open)
        dap_enc_key_delete(a_client_pvt->session_key_open);

    if(a_client_pvt->stream_key)
        dap_enc_key_delete(a_client_pvt->stream_key);

    DAP_DEL_Z(a_client_pvt)
}

/**
 * @brief s_stream_connected
 * @param a_client_pvt
 */
static void s_stream_connected(dap_client_pvt_t * a_client_pvt)
{
    log_it(L_INFO, "Remote address connected for streaming on (%s:%u) with sock_id %"DAP_FORMAT_SOCKET" (assign on worker #%u)", a_client_pvt->uplink_addr,
            a_client_pvt->uplink_port, a_client_pvt->stream_socket, a_client_pvt->stream_worker->worker->id);
    a_client_pvt->stage_status = STAGE_STATUS_DONE;
    s_stage_status_after(a_client_pvt);
    dap_events_socket_uuid_t * l_es_uuid_ptr = DAP_NEW_Z(dap_events_socket_uuid_t);
    assert(a_client_pvt->stream_es);
    *l_es_uuid_ptr = a_client_pvt->stream_es->uuid;
    if( dap_timerfd_start_on_worker(a_client_pvt->stream_es->worker, s_client_timeout_read_after_connect_seconds * 1000, s_stream_timer_timeout_after_connected_check ,l_es_uuid_ptr) == NULL ){
        log_it(L_ERROR,"Can't run timer for stream after connect check for esocket uuid %"DAP_UINT64_FORMAT_U, *l_es_uuid_ptr);
        DAP_DEL_Z(l_es_uuid_ptr);
    }
}

/**
 * @brief s_stream_timer_timeout_check
 * @param a_arg
 * @return
 */
static bool s_stream_timer_timeout_check(void * a_arg)
{
    assert(a_arg);
    dap_events_socket_uuid_t *l_es_uuid_ptr = (dap_events_socket_uuid_t*) a_arg;
    dap_worker_t *l_worker = dap_events_get_current_worker(dap_events_get_default());
    assert(l_worker);

    dap_events_socket_t * l_es = dap_worker_esocket_find_uuid(l_worker, *l_es_uuid_ptr);
    if(l_es){
        if (l_es->flags & DAP_SOCK_CONNECTING ){
            dap_client_pvt_t * l_client_pvt = (dap_client_pvt_t *)l_es->_inheritor;
            if (dap_client_pvt_find(l_client_pvt->uuid)) {
                log_it(L_WARNING,"Connecting timeout for stream uplink request http://%s:%u/, possible network problems or host is down",
                       l_client_pvt->uplink_addr, l_client_pvt->uplink_port);
                l_client_pvt->is_closed_by_timeout = true;
                if(l_es->callbacks.error_callback) {
                    l_es->callbacks.error_callback(l_es,ETIMEDOUT);
                }
                log_it(L_INFO, "Close %s sock %"DAP_FORMAT_SOCKET" type %d by timeout",
                       l_es->remote_addr_str ? l_es->remote_addr_str : "", l_es->socket, l_es->type);
                dap_client_delete_unsafe(l_client_pvt->client);
            } else {
                log_it(L_ERROR,"Connecting timeout for unexistent client");
                dap_events_socket_remove_and_delete_unsafe(l_es,true);
            }
        }else
            if(s_debug_more)
                log_it(L_DEBUG,"Socket %"DAP_FORMAT_SOCKET" is connected, close check timer", l_es->socket);
    }else
        if(s_debug_more)
            log_it(L_DEBUG,"Esocket %"DAP_UINT64_FORMAT_U" is finished, close check timer", *l_es_uuid_ptr);

    DAP_DEL_Z(l_es_uuid_ptr)
    return false;
}

/**
 * @brief s_stream_timer_timeout_after_connected_check
 * @param a_arg
 * @return
 */
static bool s_stream_timer_timeout_after_connected_check(void * a_arg)
{
    assert(a_arg);
    dap_events_socket_uuid_t *l_es_uuid_ptr = (dap_events_socket_uuid_t*) a_arg;

    dap_worker_t * l_worker = dap_events_get_current_worker(dap_events_get_default());
    assert(l_worker);

    dap_events_socket_t * l_es = dap_worker_esocket_find_uuid(l_worker, *l_es_uuid_ptr);
    if( l_es ){
        dap_client_pvt_t * l_client_pvt = (dap_client_pvt_t *)l_es->_inheritor;
        if (dap_client_pvt_find(l_client_pvt->uuid)) {
            if ( time(NULL)- l_client_pvt->ts_last_read >= s_client_timeout_read_after_connect_seconds){

                log_it(L_WARNING,"Activity timeout for streaming uplink http://%s:%u/, possible network problems or host is down",
                       l_client_pvt->uplink_addr, l_client_pvt->uplink_port);
                l_client_pvt->is_closed_by_timeout = true;
                if(l_es->callbacks.error_callback) {
                    l_es->callbacks.error_callback(l_es,ETIMEDOUT);
                }
                log_it(L_INFO, "Close streaming socket %s (%"DAP_FORMAT_SOCKET") by timeout",
                       l_es->remote_addr_str ? l_es->remote_addr_str : "", l_es->socket);
                dap_client_delete_unsafe(l_client_pvt->client);
            }else
                if(s_debug_more)
                    log_it(L_DEBUG,"Streaming socket %"DAP_FORMAT_SOCKET" is connected, close check timer", l_es->socket);
        } else {
            log_it(L_ERROR,"Activity timeout for unexistent client");
            dap_events_socket_remove_and_delete_unsafe(l_es,true);
        }

    }else
        if(s_debug_more)
            log_it(L_DEBUG,"Streaming socket %"DAP_UINT64_FORMAT_U" is finished, close check timer", *l_es_uuid_ptr);

    DAP_DEL_Z(l_es_uuid_ptr);
    return false;
}

/**
 * @brief s_enc_init_delay_before_request_timer_callback
 * @param a_arg
 * @return
 */
static bool s_enc_init_delay_before_request_timer_callback(void * a_arg)
{
    assert (a_arg);
    dap_events_socket_uuid_t* l_es_uuid_ptr = (dap_events_socket_uuid_t*) a_arg;
    dap_worker_t * l_worker = dap_events_get_current_worker(dap_events_get_default());
    dap_events_socket_t * l_es = dap_worker_esocket_find_uuid(l_worker, *l_es_uuid_ptr);
    if(l_es){
        dap_client_pvt_t * l_client_pvt =(dap_client_pvt_t*) l_es->_inheritor;
        s_stage_status_after(l_client_pvt);
    }
    DAP_DEL_Z(l_es_uuid_ptr);
    return false;
}


/**
 * @brief s_client_internal_stage_status_proc
 * @param a_client
 */
static bool s_stage_status_after(dap_client_pvt_t * a_client_pvt)
{
    if (!dap_client_pvt_find(a_client_pvt->uuid))
        return false;
    dap_worker_t * l_worker= a_client_pvt->worker;
    assert(l_worker);
    assert(l_worker->_inheritor);
    //bool l_is_unref = false;
    dap_client_stage_status_t l_stage_status = a_client_pvt->stage_status;
    dap_client_stage_t l_stage = a_client_pvt->stage;

    switch (l_stage_status) {
        case STAGE_STATUS_IN_PROGRESS: {
            if (a_client_pvt->stage_target == STAGE_BEGIN) {
                switch(l_stage) {
                case STAGE_STREAM_CONNECTED:
                case STAGE_STREAM_STREAMING:
                    dap_stream_delete(a_client_pvt->stream);
                    if(a_client_pvt->stream_es)
                       a_client_pvt->stream_es->flags |= DAP_SOCK_SIGNAL_CLOSE;
                    //dap_events_socket_remove_and_delete_unsafe(a_client_pvt->stream_es, true);
                    a_client_pvt->stream = NULL;
                    a_client_pvt->stream_es = NULL;
                    break;
                default:
                    break;
                }
                a_client_pvt->stage_status = STAGE_STATUS_DONE;
                s_stage_status_after(a_client_pvt);
                return false;
            }
            switch (l_stage) {
                case STAGE_ENC_INIT: {
                    log_it(L_INFO, "Go to stage ENC: prepare the request");


                    a_client_pvt->session_key_open = dap_enc_key_new_generate(a_client_pvt->session_key_open_type, NULL, 0, NULL, 0,
                                                                              a_client_pvt->session_key_block_size);
                    if (!a_client_pvt->session_key_open) {
                        log_it(L_ERROR, "Insufficient memory! May be a huge memory leak present");
                        a_client_pvt->stage_status = STAGE_STATUS_ERROR;
                        a_client_pvt->last_error = ERROR_OUT_OF_MEMORY;
                        break;
                    }
                    size_t l_key_size = a_client_pvt->session_key_open->pub_key_data_size;
                    dap_cert_t *l_cert = a_client_pvt->auth_cert;
                    dap_sign_t *l_sign = NULL;
                    size_t l_sign_size = 0;
                    if (l_cert) {
                        l_sign = dap_sign_create(l_cert->enc_key, a_client_pvt->session_key_open->pub_key_data, l_key_size, 0);
                        l_sign_size = dap_sign_get_size(l_sign);
                    }
                    uint8_t l_data[l_key_size + l_sign_size];
                    memset(l_data, 0, sizeof(l_data));
                    memcpy(l_data,a_client_pvt->session_key_open->pub_key_data, l_key_size);
                    if (l_sign) {
                        memcpy(l_data + l_key_size, l_sign, l_sign_size);
                    }
                    size_t l_data_str_size_max = DAP_ENC_BASE64_ENCODE_SIZE(l_key_size + l_sign_size);
                    char l_data_str[l_data_str_size_max + 1];
                    memset(l_data_str, 0, sizeof(l_data_str));
                    // DAP_ENC_DATA_TYPE_B64_URLSAFE not need because send it by POST request
                    size_t l_data_str_enc_size = dap_enc_base64_encode(l_data, l_key_size + l_sign_size, l_data_str, DAP_ENC_DATA_TYPE_B64);
                    if(s_debug_more)
                        log_it(L_DEBUG, "ENC request size %zu", l_data_str_enc_size);

                    char l_enc_init_url[1024] = { '\0' };
                    dap_snprintf(l_enc_init_url, sizeof(l_enc_init_url), DAP_UPLINK_PATH_ENC_INIT
                                 "/gd4y5yh78w42aaagh" "?enc_type=%d,pkey_exchange_type=%d,pkey_exchange_size=%zd,block_key_size=%zd",
                                 a_client_pvt->session_key_type, a_client_pvt->session_key_open_type, l_key_size,
                                 a_client_pvt->session_key_block_size );
                    int l_res = dap_client_pvt_request(a_client_pvt, l_enc_init_url,
                            l_data_str, l_data_str_enc_size, s_enc_init_response, s_enc_init_error);
                    // bad request
                    if(l_res<0){
                        a_client_pvt->stage_status = STAGE_STATUS_ERROR;
                    }
                }
                    break;
                case STAGE_STREAM_CTL: {
                    log_it(L_INFO, "Go to stage STREAM_CTL: prepare the request");
                    char *l_request = dap_strdup_printf("%d", DAP_CLIENT_PROTOCOL_VERSION);
                    size_t l_request_size = dap_strlen(l_request);
                    if(s_debug_more)
                        log_it(L_DEBUG, "STREAM_CTL request size %zu", strlen(l_request));

                    char *l_suburl;

                    uint32_t l_least_common_dap_protocol = min(a_client_pvt->remote_protocol_version,
                                                               a_client_pvt->uplink_protocol_version);

                    if(l_least_common_dap_protocol < 23){
                        l_suburl = dap_strdup_printf("stream_ctl,channels=%s",
                                                     a_client_pvt->active_channels);
                    }else{
                        l_suburl = dap_strdup_printf("channels=%s,enc_type=%d,enc_key_size=%d,enc_headers=%d",
                                                     a_client_pvt->active_channels,a_client_pvt->session_key_type,
                                                     a_client_pvt->session_key_block_size,0 );
                    }
                    if(s_debug_more)
                        log_it(L_DEBUG, "Prepared enc request for streaming");
                    dap_client_pvt_request_enc(a_client_pvt,
                    DAP_UPLINK_PATH_STREAM_CTL,
                            l_suburl, "type=tcp,maxconn=4", l_request, l_request_size,
                            s_stream_ctl_response, s_stream_ctl_error);
                    log_it(L_DEBUG, "Sent enc request for streaming");
                    DAP_DELETE(l_request);
                    DAP_DELETE(l_suburl);
                }
                    break;
                case STAGE_STREAM_SESSION: {
                    log_it(L_INFO, "Go to stage STREAM_SESSION: process the state ops");

                    a_client_pvt->stream_socket = socket(PF_INET, SOCK_STREAM, 0);
#ifdef DAP_OS_WINDOWS
                    if (a_client_pvt->stream_socket == INVALID_SOCKET) {
                        log_it(L_ERROR, "Socket create error %d", WSAGetLastError());
#else
                    if (a_client_pvt->stream_socket == -1) {
                        log_it(L_ERROR, "Error %d with socket create", errno);
#endif
                        a_client_pvt->stage_status = STAGE_STATUS_ERROR;
                        break;
                    }
                    struct timeval timeout;
                    timeout.tv_sec = 10;
                    timeout.tv_usec = 0;
#ifdef DAP_OS_WINDOWS
                    u_long l_socket_flags = 1;
                    if (ioctlsocket(a_client_pvt->stream_socket, (long)FIONBIO, &l_socket_flags) == SOCKET_ERROR) {
                        log_it(L_ERROR, "Can't set socket %zu to nonblocking mode, error %d", a_client_pvt->stream_socket, WSAGetLastError());
                    }
#else
                    // Get socket flags
                    int l_socket_flags = fcntl(a_client_pvt->stream_socket, F_GETFL);
                    if (l_socket_flags == -1){
                        log_it(L_ERROR, "Error %d can't get socket flags", errno);
                        break;;
                    }
                    // Make it non-block
                    if (fcntl( a_client_pvt->stream_socket, F_SETFL,l_socket_flags| O_NONBLOCK) == -1){
                        log_it(L_ERROR, "Error %d can't get socket flags", errno);
                        break;
                    }
#endif

                    // Wrap socket and setup callbacks
                    static dap_events_socket_callbacks_t l_s_callbacks = {
                        .read_callback = s_stream_es_callback_read,
                        .write_callback = s_stream_es_callback_write,
                        .error_callback = s_stream_es_callback_error,
                        .delete_callback = s_stream_es_callback_delete,
                        .connected_callback = s_stream_es_callback_connected
                    };//
                    a_client_pvt->stream_es = dap_events_socket_wrap_no_add(a_client_pvt->events,
                            (int)a_client_pvt->stream_socket, &l_s_callbacks);
                    a_client_pvt->stream_es->flags |= DAP_SOCK_CONNECTING ; // To catch non-blocking error when connecting we should ar WRITE flag
                    a_client_pvt->stream_es->flags |= DAP_SOCK_READY_TO_WRITE;
                    a_client_pvt->stream_es->_inheritor = a_client_pvt;
                    a_client_pvt->stream = dap_stream_new_es_client(a_client_pvt->stream_es);
                    assert(a_client_pvt->stream);
                    a_client_pvt->stream->is_client_to_uplink = true;
                    a_client_pvt->stream->session = dap_stream_session_pure_new(); // may be from in packet?

                    // new added, whether it is necessary?
                    a_client_pvt->stream->session->key = a_client_pvt->stream_key;
                    a_client_pvt->stream_worker = DAP_STREAM_WORKER(l_worker);
                    a_client_pvt->stream->stream_worker = a_client_pvt->stream_worker;

                    // connect
                    memset(&a_client_pvt->stream_es->remote_addr, 0, sizeof(a_client_pvt->stream_es->remote_addr));
                    a_client_pvt->stream_es->remote_addr_str6   = NULL; //DAP_NEW_Z_SIZE(char, INET6_ADDRSTRLEN);
                    a_client_pvt->stream_es->remote_addr.sin_family = AF_INET;
                    a_client_pvt->stream_es->remote_addr.sin_port = htons(a_client_pvt->uplink_port);
                    if(inet_pton(AF_INET, a_client_pvt->uplink_addr, &(a_client_pvt->stream_es->remote_addr.sin_addr)) < 0) {
                        log_it(L_ERROR, "Wrong remote address '%s:%u'", a_client_pvt->uplink_addr, a_client_pvt->uplink_port);
                        //close(a_client_pvt->stream_socket);
                        //a_client_pvt->stream_socket = 0;
                        a_client_pvt->stage_status = STAGE_STATUS_ERROR;
                    }
                    else {
                        int l_err = 0;
                        a_client_pvt->stream_es->remote_addr_str = dap_strdup(a_client_pvt->uplink_addr);

                        if((l_err = connect(a_client_pvt->stream_socket, (struct sockaddr *) &a_client_pvt->stream_es->remote_addr,
                                sizeof(struct sockaddr_in))) ==0) {
                            log_it(L_INFO, "Connected momentaly with %s:%u", a_client_pvt->uplink_addr, a_client_pvt->uplink_port);
                            // add to dap_worker
                            dap_worker_add_events_socket( a_client_pvt->stream_es, l_worker);

                            // Add check timer
                            assert(a_client_pvt->stream_es);
                            dap_events_socket_uuid_t * l_stream_es_uuid_ptr = DAP_NEW_Z(dap_events_socket_uuid_t);
                            *l_stream_es_uuid_ptr  = a_client_pvt->stream_es->uuid;
                            dap_timerfd_start_on_worker(a_client_pvt->worker, (unsigned long)s_client_timeout_read_after_connect_seconds * 1000,
                                                        s_stream_timer_timeout_check,l_stream_es_uuid_ptr);
                        }
                        else if (l_err != EINPROGRESS && l_err != -1){
                            char l_errbuf[128];
                            l_errbuf[0]='\0';
                            if (l_err)
                                strerror_r(l_err,l_errbuf,sizeof (l_errbuf));
                            else
                                strncpy(l_errbuf,"Unknown Error",sizeof(l_errbuf)-1);
                            log_it(L_ERROR, "Remote address can't connect (%s:%hu) with sock_id %"DAP_FORMAT_SOCKET": \"%s\" (code %d)", a_client_pvt->uplink_addr,
                                    a_client_pvt->uplink_port, a_client_pvt->stream_es->socket, l_errbuf, l_err);
#ifdef DAP_OS_WINDOWS
                            closesocket(a_client_pvt->stream_socket);
#else
                            close(a_client_pvt->stream_socket);
#endif
                            a_client_pvt->stream_socket = 0;
                            a_client_pvt->stage_status = STAGE_STATUS_ERROR;
                            a_client_pvt->last_error = ERROR_STREAM_CONNECT ;

                            s_stage_status_after(a_client_pvt);
                        }else{
                            log_it(L_INFO,"Connecting stream to remote %s:%u",a_client_pvt->uplink_addr, a_client_pvt->uplink_port);
                            // add to dap_worker
                            assert (a_client_pvt->stream_es);
                            dap_worker_add_events_socket( a_client_pvt->stream_es, l_worker);
                            dap_events_socket_uuid_t * l_stream_es_uuid_ptr = DAP_NEW_Z(dap_events_socket_uuid_t);
                            *l_stream_es_uuid_ptr = a_client_pvt->stream_es->uuid;
                            dap_timerfd_start_on_worker(a_client_pvt->worker, (unsigned long)s_client_timeout_read_after_connect_seconds * 1000,
                                                        s_stream_timer_timeout_check,l_stream_es_uuid_ptr);
                        }
                    }
                }
                break;
                case STAGE_STREAM_CONNECTED: {
                    log_it(L_INFO, "Go to stage STAGE_STREAM_CONNECTED");
                    if(!a_client_pvt->stream){
                        a_client_pvt->stage_status = STAGE_STATUS_ERROR;
                        s_stage_status_after(a_client_pvt);
                        return false;
                    }

                    size_t count_channels = a_client_pvt->active_channels? strlen(a_client_pvt->active_channels) : 0;
                    for(size_t i = 0; i < count_channels; i++) {
                        dap_stream_ch_new(a_client_pvt->stream, (uint8_t) a_client_pvt->active_channels[i]);
                        //sid->channel[i]->ready_to_write = true;
                    }

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

                    dap_events_socket_write_f_unsafe( a_client_pvt->stream_es, "GET /%s HTTP/1.1\r\n"
                                                                        "Host: %s:%d%s\r\n"
                                                                        "\r\n",
                                               l_full_path, a_client_pvt->uplink_addr, a_client_pvt->uplink_port, l_add_str);
                    DAP_DELETE(l_full_path);



                    a_client_pvt->stage_status = STAGE_STATUS_DONE;
                    s_stage_status_after(a_client_pvt);
                }
                    break;
                case STAGE_STREAM_STREAMING: {
                    log_it(L_INFO, "Go to stage STAGE_STREAM_STREAMING");
                    a_client_pvt->stage_errors = 0;

                    a_client_pvt->stage_status = STAGE_STATUS_DONE;
                    s_stage_status_after(a_client_pvt);

                }
                    break;

                default: {
                    log_it(L_ERROR, "Undefined proccessing actions for stage status %s",
                            dap_client_stage_status_str(a_client_pvt->stage_status));
                    a_client_pvt->stage_status = STAGE_STATUS_ERROR;
                    s_stage_status_after(a_client_pvt); // be carefull to not to loop!
                }
            }
        }
        break;

        case STAGE_STATUS_ERROR: {
            if (a_client_pvt->is_to_delete)
                break;
            // limit the number of attempts
            a_client_pvt->stage_errors++;
            bool l_is_last_attempt = a_client_pvt->stage_errors > s_max_attempts ? true : false;
            //if (a_client_pvt->last_error == ERROR_NETWORK_CONNECTION_TIMEOUT) {
            //    l_is_last_attempt = true;
            //}

            log_it(L_ERROR, "Error state( %s), doing callback if present", dap_client_error_str(a_client_pvt->last_error));
            if(a_client_pvt->stage_status_error_callback)
                a_client_pvt->stage_status_error_callback(a_client_pvt->client, (void*) l_is_last_attempt);

            if(a_client_pvt->stage_target == STAGE_STREAM_ABORT) {
                a_client_pvt->stage = STAGE_STREAM_ABORT;
                a_client_pvt->stage_status = STAGE_STATUS_ABORTING;
            } else {
                if(!l_is_last_attempt ) {
                    a_client_pvt->stage = STAGE_ENC_INIT;
                    // Trying the step again
                    a_client_pvt->stage_status = STAGE_STATUS_IN_PROGRESS;
                    log_it(L_INFO, "Reconnect attempt %d in 0.3 seconds with %s:%u", a_client_pvt->stage_errors,
                           a_client_pvt->uplink_addr,a_client_pvt->uplink_port);
                    // small delay before next request
                    if(dap_timerfd_start( 300,(dap_timerfd_callback_t) s_stage_status_after,
                                                   a_client_pvt) == NULL){
                        log_it(L_ERROR,"Can't run timer for small delay before the next enc_init request");
                    }
                } else {
                    if (a_client_pvt->is_always_reconnect) {
                        log_it(L_INFO, "Too many attempts, reconnect attempt in %d seconds with %s:%u",s_timeout*3,
                               a_client_pvt->uplink_addr,a_client_pvt->uplink_port);                    // Trying the step again
                        a_client_pvt->stage_status = STAGE_STATUS_IN_PROGRESS;
                        a_client_pvt->stage_errors = 0;

                        // bigger delay before next request
                        if(dap_timerfd_start( s_timeout*3000,(dap_timerfd_callback_t) s_stage_status_after,
                                                       a_client_pvt ) == NULL){
                            log_it(L_ERROR,"Can't run timer for bigger delay before the next enc_init request");
                        }
                    } else {
                        log_it(L_ERROR, "Connect to %s:%u failed", a_client_pvt->uplink_addr, a_client_pvt->uplink_port);
                        dap_client_delete_mt(a_client_pvt->client);
                    }
                }
            }
        }
        break;
        case STAGE_STATUS_DONE: {
            log_it(L_INFO, "Stage status %s is done", dap_client_stage_str(a_client_pvt->stage));
            bool l_is_last_stage = (a_client_pvt->stage == a_client_pvt->stage_target);
            if(l_is_last_stage) {
                //l_is_unref = true;
                if(a_client_pvt->stage_target_done_callback) {
                    log_it(L_NOTICE, "Stage %s is achieved",
                            dap_client_stage_str(a_client_pvt->stage));
                    a_client_pvt->stage_target_done_callback(a_client_pvt->client, NULL);
                    // Expecting that its one-shot callback
                    a_client_pvt->stage_target_done_callback = NULL;
                }
            } else if (a_client_pvt->stage_status_done_callback) {
                // go to next stage
                a_client_pvt->stage_status_done_callback(a_client_pvt->client, NULL);
            }
        }
            break;
        default:
            log_it(L_ERROR, "Undefined proccessing actions for stage status %s",
                    dap_client_stage_status_str(a_client_pvt->stage_status));
    }

    if(a_client_pvt->stage_status_callback)
        a_client_pvt->stage_status_callback(a_client_pvt->client, NULL);
    return false;
}

/**
 * @brief dap_client_internal_stage_transaction_begin
 * @param a_client_internal
 * @param a_stage_next
 * @param a_done_callback
 */
void dap_client_pvt_stage_transaction_begin(dap_client_pvt_t * a_client_internal, dap_client_stage_t a_stage_next,
        dap_client_callback_t a_done_callback)
{
    assert(a_client_internal);
    if(s_debug_more)
        log_it(L_DEBUG, "Begin transaction for client %p to the next stage %s", a_client_internal->client, dap_client_stage_str(a_stage_next));
    a_client_internal->stage_status_done_callback = a_done_callback;
    a_client_internal->stage = a_stage_next;
    a_client_internal->stage_status = STAGE_STATUS_IN_PROGRESS;
    s_stage_status_after(a_client_internal);
}

/**
 * @brief dap_client_internal_request
 * @param a_client_internal
 * @param a_path
 * @param a_request
 * @param a_request_size
 * @param a_response_proc
 */
int dap_client_pvt_request(dap_client_pvt_t * a_client_internal, const char * a_path, void * a_request,
        size_t a_request_size, dap_client_callback_data_size_t a_response_proc,
        dap_client_callback_int_t a_response_error)
{
    a_client_internal->request_response_callback = a_response_proc;
    a_client_internal->request_error_callback = a_response_error;
    a_client_internal->is_encrypted = false;
    a_client_internal->refs_count++;;

    void *l_ret = dap_client_http_request(a_client_internal->worker,  a_client_internal->uplink_addr,a_client_internal->uplink_port,
                                           a_request ? "POST" : "GET", "text/text", a_path, a_request,
                                            a_request_size, NULL, s_request_response, s_request_error, a_client_internal, NULL);

    if(l_ret)
    	return 0;
    return -1;
}

/**
 * @brief dap_client_internal_request_enc
 * @param a_client_internal
 * @param a_path
 * @param a_sub_url
 * @param a_query
 * @param a_request
 * @param a_request_size
 * @param a_response_proc
 * @param a_response_error
 */
void dap_client_pvt_request_enc(dap_client_pvt_t * a_client_internal, const char * a_path,
        const char * a_sub_url, const char * a_query
        , void * a_request, size_t a_request_size
        , dap_client_callback_data_size_t a_response_proc
        , dap_client_callback_int_t a_response_error)
{
    bool is_query_enc = true; // if true, then encode a_query string  [Why do we even need this?]
    if(s_debug_more)
        log_it(L_DEBUG, "Encrypted request: sub_url '%s' query '%s'", a_sub_url ? a_sub_url : "NULL",
            a_query ? a_query : "NULL");
    size_t l_sub_url_size = a_sub_url ? strlen(a_sub_url) : 0;
    size_t l_query_size = a_query ? strlen(a_query) : 0;
    size_t l_url_size;

//    char l_url[1024] = { 0 };
//    snprintf(l_url, 1024, "http://%s:%u", a_client_internal->uplink_addr, a_client_internal->uplink_port);
//    l_url_size = strlen(l_url);

    size_t l_sub_url_enc_size_max = l_sub_url_size ? (5 * l_sub_url_size + 16) : 0;
    char *l_sub_url_enc = l_sub_url_size ? DAP_NEW_Z_SIZE(char, l_sub_url_enc_size_max + 1) : NULL;

    size_t l_query_enc_size_max = (is_query_enc) ? (l_query_size * 5 + 16) : l_query_size;
    char *l_query_enc =
            (is_query_enc) ? (l_query_size ? DAP_NEW_Z_SIZE(char, l_query_enc_size_max + 1) : NULL) : (char*) a_query;

//    size_t l_url_full_size_max = 5 * l_sub_url_size + 5 * l_query_size + 16 + l_url_size + 2;
//    char * l_url_full = DAP_NEW_Z_SIZE(char, l_url_full_size_max + 1);

    size_t l_request_enc_size_max = a_request_size ? a_request_size * 2 + 16 : 0;
    char * l_request_enc = a_request_size ? DAP_NEW_Z_SIZE(char, l_request_enc_size_max + 1) : NULL;
    size_t l_request_enc_size = 0;

    a_client_internal->request_response_callback = a_response_proc;
    a_client_internal->request_error_callback = a_response_error;
    a_client_internal->is_encrypted = true;
    size_t i;
    dap_enc_data_type_t l_enc_type;

    if(a_client_internal->uplink_protocol_version >= 21)
        l_enc_type = DAP_ENC_DATA_TYPE_B64_URLSAFE;
    else
        l_enc_type = DAP_ENC_DATA_TYPE_B64;

    if(l_sub_url_size)
        dap_enc_code(a_client_internal->session_key,
                a_sub_url, l_sub_url_size,
                l_sub_url_enc, l_sub_url_enc_size_max,
                l_enc_type);

    if(is_query_enc && l_query_size)
        dap_enc_code(a_client_internal->session_key,
                a_query, l_query_size,
                l_query_enc, l_query_enc_size_max,
                l_enc_type);

    if(a_request_size)
        l_request_enc_size = dap_enc_code(a_client_internal->session_key,
                a_request, a_request_size,
                l_request_enc, l_request_enc_size_max,
                DAP_ENC_DATA_TYPE_RAW);

/*
    if(a_path) {
        if(l_sub_url_size) {
            if(l_query_size) {
                snprintf(l_url_full, l_url_full_size_max - 1, "%s/%s/%s?%s"
                        , l_url, a_path, l_sub_url_enc, l_query_enc);

            } else {
                snprintf(l_url_full, l_url_full_size_max, "%s/%s/%s", l_url, a_path, l_sub_url_enc);
            }
        } else {
            snprintf(l_url_full, l_url_full_size_max, "%s/%s", l_url, a_path);
        }
    } else {
        snprintf(l_url_full, l_url_full_size_max, "%s", l_url);
    }
*/
    int l_off;
    size_t l_path_size= l_query_enc_size_max + l_sub_url_enc_size_max + 1;
    char *l_path = DAP_NEW_Z_SIZE(char, l_path_size);
    l_path[0] = '\0';
    if(a_path) {
        if(l_sub_url_size){
            if(l_query_size){
                dap_snprintf(l_path, l_path_size, "%s/%s?%s", a_path?a_path:"",
                             l_sub_url_enc?l_sub_url_enc:"",
                                   l_query_enc?l_query_enc:"");
            }else{
                dap_snprintf(l_path, l_path_size, "%s/%s", a_path, l_sub_url_enc);
            }
        } else {
            dap_stpcpy(l_path, a_path);
        }
    }

    size_t size_required = a_client_internal->session_key_id ? strlen(a_client_internal->session_key_id) + 40 : 40;
    char *l_custom = DAP_NEW_Z_SIZE(char, size_required);
    size_t l_off2 = size_required;

    l_off = dap_snprintf(l_custom, l_off2, "KeyID: %s\r\n", a_client_internal->session_key_id ? a_client_internal->session_key_id : "NULL");
    l_off += a_client_internal->is_close_session
            ? dap_snprintf(l_custom + l_off, l_off2 -= l_off, "%s\r\n", "SessionCloseAfterRequest: true")
            : 0;

    a_client_internal->refs_count++;
    dap_client_http_request(a_client_internal->worker, a_client_internal->uplink_addr, a_client_internal->uplink_port, a_request ? "POST" : "GET", "text/text",
                l_path, l_request_enc, l_request_enc_size, NULL,
                s_request_response, s_request_error, a_client_internal, l_custom);
    if(l_sub_url_enc)
        DAP_DELETE(l_sub_url_enc);
    if(l_custom)
        DAP_DELETE(l_custom);
    if(l_query_enc)
        DAP_DELETE(l_query_enc);
    if(l_path)
        DAP_DELETE(l_path);
    if(l_request_enc)
        DAP_DELETE(l_request_enc);
}

/**
 * @brief s_request_error
 * @param a_err_code
 * @param a_obj
 */
static void s_request_error(int a_err_code, void * a_obj)
{
    dap_client_pvt_t * l_client_pvt = (dap_client_pvt_t *) a_obj;
    assert(l_client_pvt);

    if(l_client_pvt && l_client_pvt->request_error_callback && l_client_pvt->client)
    {
        l_client_pvt = dap_client_pvt_find(l_client_pvt->uuid);
        if(l_client_pvt && l_client_pvt->request_error_callback
                && l_client_pvt->client && l_client_pvt->client->_internal)
            l_client_pvt->request_error_callback(l_client_pvt->client, a_err_code);
    }
}

/**
 * @brief s_request_response
 * @param a_response
 * @param a_response_size
 * @param a_obj
 */
static void s_request_response(void * a_response, size_t a_response_size, void * a_obj)
{
    dap_client_pvt_t * l_client_pvt = (dap_client_pvt_t *) a_obj;
    assert(l_client_pvt);
    //int l_ref = dap_client_pvt_get_ref(a_client_internal);
    if(l_client_pvt->is_encrypted) {
        size_t l_response_dec_size_max = a_response_size ? a_response_size * 2 + 16 : 0;
        char * l_response_dec = a_response_size ? DAP_NEW_Z_SIZE(char, l_response_dec_size_max) : NULL;
        size_t l_response_dec_size = 0;
        if(a_response_size)
            l_response_dec_size = dap_enc_decode(l_client_pvt->session_key,
                    a_response, a_response_size,
                    l_response_dec, l_response_dec_size_max,
                    DAP_ENC_DATA_TYPE_RAW);

        if ( l_client_pvt->request_response_callback )
            l_client_pvt->request_response_callback(l_client_pvt->client, l_response_dec, l_response_dec_size);
        else
            log_it(L_ERROR, "NULL request_response_callback for encrypted client %p", l_client_pvt->client );

        if(l_response_dec)
            DAP_DELETE(l_response_dec);
    } else {
        if ( l_client_pvt->request_response_callback )
            l_client_pvt->request_response_callback(l_client_pvt->client, a_response, a_response_size);
        else
            log_it(L_ERROR, "NULL request_response_callback for unencrypted  client %p", l_client_pvt->client );
    }
}

/**
 * @brief s_enc_init_response
 * @param a_client
 * @param a_response
 * @param a_response_size
 */
static void s_enc_init_response(dap_client_t * a_client, void * a_response, size_t a_response_size)
{
    dap_client_pvt_t * l_client_pvt = dap_client_pvt_find(a_client->pvt_uuid);
    if (!l_client_pvt || l_client_pvt->is_to_delete) return;

    if (!l_client_pvt->session_key_open){
        log_it(L_ERROR, "m_enc_init_response: session is NULL!");
        l_client_pvt->last_error = ERROR_ENC_SESSION_CLOSED ;
        l_client_pvt->stage_status = STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_pvt);
        return;

    }

    if(a_response_size > 10) { // &&  a_response_size < 50){

        char *l_session_id_b64 = NULL;
        char *l_bob_message_b64 = NULL;
        int json_parse_count = 0;
        struct json_object *jobj = json_tokener_parse((const char *) a_response);
        if(jobj) {
            // parse encrypt_id & encrypt_msg
            json_object_object_foreach(jobj, key, val)
            {
                if(json_object_get_type(val) == json_type_string) {
                    const char *l_str = json_object_get_string(val);
                    if(!strcmp(key, "encrypt_id")) {
                        DAP_DELETE (l_session_id_b64);
                        l_session_id_b64 = DAP_NEW_Z_SIZE(char, strlen(l_str) + 1);
                        strcpy(l_session_id_b64, l_str);
                        json_parse_count++;
                    }
                    if(!strcmp(key, "encrypt_msg")) {
                        DAP_DELETE(l_bob_message_b64);
                        l_bob_message_b64 = DAP_NEW_Z_SIZE(char, strlen(l_str) + 1);
                        strcpy(l_bob_message_b64, l_str);
                        json_parse_count++;
                    }
                }
                if(json_object_get_type(val) == json_type_int) {
                    int val_int = json_object_get_int(val);
                    if(!strcmp(key, "dap_protocol_version")) {
                        l_client_pvt->remote_protocol_version = val_int;
                        json_parse_count++;
                    }
                }
            }
            // free jobj
            json_object_put(jobj);
            if(!l_client_pvt->remote_protocol_version)
                l_client_pvt->remote_protocol_version = DAP_PROTOCOL_VERSION_DEFAULT;
        }
        //char l_session_id_b64[DAP_ENC_BASE64_ENCODE_SIZE(DAP_ENC_KS_KEY_ID_SIZE) + 1] = { 0 };
        //char *l_bob_message_b64 = DAP_NEW_Z_SIZE(char, a_response_size - sizeof(l_session_id_b64) + 1);
        if(json_parse_count >= 2 && json_parse_count <=3) { //if (sscanf (a_response,"%s %s",l_session_id_b64, l_bob_message_b64) == 2 ){
            if(!l_session_id_b64){
                log_it(L_WARNING,"ENC: no session id in base64");
            }
            if(!l_bob_message_b64){
                log_it(L_WARNING,"ENC: no bob message in base64");
            }
            if( l_bob_message_b64 && l_session_id_b64){
                l_client_pvt->session_key_id = DAP_NEW_Z_SIZE(char, strlen(l_session_id_b64) + 1);
                dap_enc_base64_decode(l_session_id_b64, strlen(l_session_id_b64),
                        l_client_pvt->session_key_id, DAP_ENC_DATA_TYPE_B64);
                log_it(L_DEBUG, "ENC: session Key ID %s", l_client_pvt->session_key_id);

                char *l_bob_message = DAP_NEW_Z_SIZE(char, strlen(l_bob_message_b64) + 1);
                size_t l_bob_message_size = dap_enc_base64_decode(l_bob_message_b64, strlen(l_bob_message_b64),
                        l_bob_message, DAP_ENC_DATA_TYPE_B64);
                l_client_pvt->session_key_open->gen_alice_shared_key(
                        l_client_pvt->session_key_open, l_client_pvt->session_key_open->priv_key_data,
                        l_bob_message_size, (unsigned char*) l_bob_message);

                l_client_pvt->session_key = dap_enc_key_new_generate(l_client_pvt->session_key_type,
                        l_client_pvt->session_key_open->priv_key_data, // shared key
                        l_client_pvt->session_key_open->priv_key_data_size,
                        l_client_pvt->session_key_id, strlen(l_client_pvt->session_key_id), l_client_pvt->session_key_block_size);

                DAP_DELETE(l_bob_message);
            }

            if(l_client_pvt->stage == STAGE_ENC_INIT) { // We are in proper stage
                l_client_pvt->stage_status = STAGE_STATUS_DONE;
                s_stage_status_after(l_client_pvt);
            } else {
                log_it(L_WARNING, "ENC: initialized encryption but current stage is %s (%s)",
                        dap_client_get_stage_str(a_client), dap_client_get_stage_status_str(a_client));
            }
        } else {
            log_it(L_ERROR, "ENC: Wrong response (size %zu data '%s')", a_response_size, (char* ) a_response);
            l_client_pvt->last_error = ERROR_ENC_NO_KEY;
            l_client_pvt->stage_status = STAGE_STATUS_ERROR;
            s_stage_status_after(l_client_pvt);
        }

        DAP_DELETE(l_session_id_b64);
        DAP_DELETE(l_bob_message_b64);
    } else if(a_response_size > 1) {
        log_it(L_ERROR, "ENC: Wrong response (size %zu data '%s')", a_response_size, (char* ) a_response);
        l_client_pvt->last_error = ERROR_ENC_NO_KEY;
        l_client_pvt->stage_status = STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_pvt);
    } else {
        log_it(L_ERROR, "ENC: Wrong response (size %zu)", a_response_size);
        l_client_pvt->last_error = ERROR_ENC_NO_KEY;
        l_client_pvt->stage_status = STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_pvt);
    }
}

/**
 * @brief s_enc_init_error
 * @param a_client
 * @param a_err_code
 */
static void s_enc_init_error(dap_client_t * a_client, int a_err_code)
{
    dap_client_pvt_t * l_client_pvt = dap_client_pvt_find(a_client->pvt_uuid);
    log_it(L_ERROR, "ENC: Can't init ecnryption session, err code %d", a_err_code);
    if (!l_client_pvt) return;
    if (a_err_code == ETIMEDOUT) {
        l_client_pvt->last_error = ERROR_NETWORK_CONNECTION_TIMEOUT;
    } else {
        l_client_pvt->last_error = ERROR_NETWORK_CONNECTION_REFUSE;
    }
    l_client_pvt->stage_status = STAGE_STATUS_ERROR;
    s_stage_status_after(l_client_pvt);
}

/**
 * @brief s_stream_ctl_response
 * @param a_client
 * @param a_data
 * @param a_data_size
 */
static void s_stream_ctl_response(dap_client_t * a_client, void * a_data, size_t a_data_size)
{
    dap_client_pvt_t *l_client_pvt = dap_client_pvt_find(a_client->pvt_uuid);
    if (!l_client_pvt) return;
    if(s_debug_more)
        log_it(L_DEBUG, "STREAM_CTL response %zu bytes length recieved", a_data_size);
    char * l_response_str = DAP_NEW_Z_SIZE(char, a_data_size + 1);
    memcpy(l_response_str, a_data, a_data_size);

    if(a_data_size < 4) {
        log_it(L_ERROR, "STREAM_CTL Wrong reply: '%s'", l_response_str);
        l_client_pvt->last_error = ERROR_STREAM_CTL_ERROR_RESPONSE_FORMAT;
        l_client_pvt->stage_status = STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_pvt);
    } else if(strcmp(l_response_str, "ERROR") == 0) {
        log_it(L_WARNING, "STREAM_CTL Got ERROR from the remote site,expecting thats ERROR_AUTH");
        l_client_pvt->last_error = ERROR_STREAM_CTL_ERROR_AUTH;
        l_client_pvt->stage_status = STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_pvt);
    } else {
        int l_arg_count;
        char l_stream_id[26] = { 0 };
        char *l_stream_key = DAP_NEW_Z_SIZE(char, 4096 * 3);
        uint32_t l_remote_protocol_version;
        dap_enc_key_type_t l_enc_type = l_client_pvt->session_key_type;
        int l_enc_headers = 0;

        l_arg_count = sscanf(l_response_str, "%25s %4096s %u %d %d"
                , l_stream_id, l_stream_key, &l_remote_protocol_version, &l_enc_type, &l_enc_headers);
        if(l_arg_count < 2) {
            log_it(L_WARNING, "STREAM_CTL Need at least 2 arguments in reply (got %d)", l_arg_count);
            l_client_pvt->last_error = ERROR_STREAM_CTL_ERROR_RESPONSE_FORMAT;
            l_client_pvt->stage_status = STAGE_STATUS_ERROR;
            s_stage_status_after(l_client_pvt);
        } else {

            if(l_arg_count > 2) {
                l_client_pvt->uplink_protocol_version = l_remote_protocol_version;
                log_it(L_DEBUG, "Uplink protocol version %u", l_remote_protocol_version);
            } else
                log_it(L_WARNING, "No uplink protocol version, use legacy version %d"
                        , l_client_pvt->uplink_protocol_version = 22);

            if(strlen(l_stream_id) < 13) {
                //log_it(L_DEBUG, "Stream server id %s, stream key length(base64 encoded) %u"
                //       ,l_stream_id,strlen(l_stream_key) );
                log_it(L_DEBUG, "Stream server id %s", l_stream_id);

                // Delete old key if present
                if(l_client_pvt->stream_key)
                    dap_enc_key_delete(l_client_pvt->stream_key);

                strncpy(l_client_pvt->stream_id, (char *)l_stream_id, sizeof(l_client_pvt->stream_id) -1 );
                l_client_pvt->stream_id[sizeof(l_client_pvt->stream_id) - 1] = '\0';
                l_client_pvt->stream_key =
                        dap_enc_key_new_generate(l_enc_type, l_stream_key, strlen(l_stream_key), NULL, 0,
                                32);

                l_client_pvt->is_encrypted_headers = l_enc_headers;

                if(l_client_pvt->stage == STAGE_STREAM_CTL) { // We are on the right stage
                    l_client_pvt->stage_status = STAGE_STATUS_DONE;
                    s_stage_status_after(l_client_pvt);
                } else {
                    log_it(L_WARNING, "Expected to be stage STREAM_CTL but current stage is %s (%s)",
                            dap_client_get_stage_str(a_client), dap_client_get_stage_status_str(a_client));

                }
            } else {
                log_it(L_WARNING, "Wrong stream id response");
                l_client_pvt->last_error = ERROR_STREAM_CTL_ERROR_RESPONSE_FORMAT;
                l_client_pvt->stage_status = STAGE_STATUS_ERROR;
                s_stage_status_after(l_client_pvt);
            }

        }
        DAP_DELETE(l_stream_key);
    }
    DAP_DELETE(l_response_str);
}

/**
 * @brief s_stream_ctl_error
 * @param a_client
 * @param a_error
 */
static void s_stream_ctl_error(dap_client_t * a_client, int a_error)
{
    log_it(L_WARNING, "STREAM_CTL error %d", a_error);

    dap_client_pvt_t * l_client_pvt = DAP_CLIENT_PVT(a_client);
    assert(l_client_pvt);

    if (a_error == ETIMEDOUT) {
        l_client_pvt->last_error = ERROR_NETWORK_CONNECTION_TIMEOUT;
    } else {
        l_client_pvt->last_error = ERROR_STREAM_CTL_ERROR;
    }
    l_client_pvt->stage_status = STAGE_STATUS_ERROR;

    s_stage_status_after(l_client_pvt);

}

//
/**
 * @brief s_stream_response STREAM stage callbacks
 * @param a_client
 * @param a_data
 * @param a_data_size
 */
static void s_stream_response(dap_client_t * a_client, void * a_data, size_t a_data_size)
{
    dap_client_pvt_t * l_client_pvt = DAP_CLIENT_PVT(a_client);
    assert(l_client_pvt);
    if(s_debug_more)
        log_it(L_DEBUG, "STREAM response %zu bytes length recieved", a_data_size);
//    char * l_response_str = DAP_NEW_Z_SIZE(char, a_data_size + 1);
//    memcpy(l_response_str, a_data, a_data_size);

    if(l_client_pvt->stage == STAGE_STREAM_CONNECTED) { // We are on the right stage
        l_client_pvt->stage_status = STAGE_STATUS_DONE;
        s_stage_status_after(l_client_pvt);
    }
    else {
        log_it(L_WARNING, "Expected to be stage STREAM_CONNECTED but current stage is %s (%s)",
                dap_client_get_stage_str(a_client), dap_client_get_stage_status_str(a_client));
        l_client_pvt->stage_status = STAGE_STATUS_ERROR;
    }
    s_stage_status_after(l_client_pvt);
}

/**
 * @brief s_stage_stream_opened
 * @param a_client
 * @param arg
 */
static void s_stage_stream_streaming(dap_client_t * a_client, void* arg)
{
    log_it(L_INFO, "Stream  is opened");
}

/**
 * @brief s_stream_es_callback_new
 * @param a_es
 * @param arg
 */
static void s_stream_es_callback_connected(dap_events_socket_t * a_es)
{
    dap_client_pvt_t * l_client_pvt =(dap_client_pvt_t*) a_es->_inheritor;
    s_stream_connected(l_client_pvt);
}

/**
 * @brief s_es_stream_delete
 * @param a_es
 * @param arg
 */
static void s_stream_es_callback_delete(dap_events_socket_t *a_es, void *arg)
{
    (void) arg;
    log_it(L_INFO, "Stream delete callback");

    dap_client_pvt_t *l_client_pvt = (dap_client_pvt_t *)a_es->_inheritor;
    a_es->_inheritor = NULL; // To prevent delete in reactor

    if(l_client_pvt == NULL) {
        log_it(L_ERROR, "dap_client_pvt_t is not initialized");
        return;
    }

    if (!dap_client_pvt_find(l_client_pvt->uuid)) {
        log_it(L_ERROR, "dap_client_pvt is corrupted");
        return;
    }

    if(s_debug_more)
        log_it(L_DEBUG, "Delete stream socket for client_pvt=0x%p", l_client_pvt);

    dap_stream_delete(l_client_pvt->stream);
    if (l_client_pvt->stream_es) {
        DAP_DEL_Z(l_client_pvt->stream_es->remote_addr_str)
        DAP_DEL_Z(l_client_pvt->stream_es->remote_addr_str6)
    }
    l_client_pvt->stream = NULL;
    l_client_pvt->stream_es = NULL;
    l_client_pvt->stage_status = STAGE_STATUS_ERROR;
    l_client_pvt->stage = l_client_pvt->stage_target = STAGE_BEGIN;
}

/**
 * @brief s_es_stream_read
 * @param a_es
 * @param arg
 */
static void s_stream_es_callback_read(dap_events_socket_t * a_es, void * arg)
{
    (void) arg;
    dap_client_pvt_t * l_client_pvt =(dap_client_pvt_t *) a_es->_inheritor;

    l_client_pvt->ts_last_read = time(NULL);
    switch (l_client_pvt->stage) {
        case STAGE_STREAM_SESSION:
            dap_client_go_stage(l_client_pvt->client, STAGE_STREAM_STREAMING, s_stage_stream_streaming);
        break;
        case STAGE_STREAM_CONNECTED: { // Collect HTTP headers before streaming
            if(a_es->buf_in_size > 1) {
                char * l_pos_endl;
                l_pos_endl = (char*) memchr(a_es->buf_in, '\r', a_es->buf_in_size - 1);
                if(l_pos_endl) {
                    if(*(l_pos_endl + 1) == '\n') {
                        dap_events_socket_shrink_buf_in(a_es, l_pos_endl - (char*)a_es->buf_in);
                        log_it(L_DEBUG, "Header passed, go to streaming (%zu bytes already are in input buffer",
                                a_es->buf_in_size);

                        l_client_pvt->stage = STAGE_STREAM_STREAMING;
                        l_client_pvt->stage_status = STAGE_STATUS_DONE;
                        s_stage_status_after(l_client_pvt);

                        dap_stream_data_proc_read(l_client_pvt->stream);
                        dap_events_socket_shrink_buf_in(a_es, a_es->buf_in_size);
                    }
                }
            }
        }
            break;
        case STAGE_STREAM_STREAMING: { // if streaming - process data with stream processor
            dap_stream_data_proc_read(l_client_pvt->stream);
            dap_events_socket_shrink_buf_in(a_es, a_es->buf_in_size);
        }
            break;
        default: {
        }
    }
}

/**
 * @brief s_es_stream_write
 * @param a_es
 * @param arg
 */
static void s_stream_es_callback_write(dap_events_socket_t * a_es, void * arg)
{
    (void) arg;
    dap_client_pvt_t * l_client_pvt = a_es->_inheritor;

    if (l_client_pvt->stage_status == STAGE_STATUS_ERROR || !l_client_pvt->stream)
        return;
    switch (l_client_pvt->stage) {
        case STAGE_STREAM_STREAMING: {
            size_t i;
            bool ready_to_write = false;
            //  log_it(DEBUG,"Process channels data output (%u channels)",STREAM(sh)->channel_count);

            for(i = 0; i < l_client_pvt->stream->channel_count; i++) {
                dap_stream_ch_t * ch = l_client_pvt->stream->channel[i];
                if(ch->ready_to_write) {
                    ch->proc->packet_out_callback(ch, NULL);
                    ready_to_write |= ch->ready_to_write;
                }
            }
            //log_it(L_DEBUG,"stream_data_out (ready_to_write=%s)", ready_to_write?"true":"false");

            dap_events_socket_set_writable_unsafe(l_client_pvt->stream_es, ready_to_write);
            //log_it(ERROR,"No stream_data_write_callback is defined");
        }
            break;
        default: {
        }
    }
}

/**
 * @brief s_stream_es_callback_error
 * @param a_es
 * @param a_error
 */
static void s_stream_es_callback_error(dap_events_socket_t * a_es, int a_error)
{
    dap_client_pvt_t *l_client_pvt = (dap_client_pvt_t *) a_es->_inheritor;
    if (!l_client_pvt)
        return;
    l_client_pvt = dap_client_pvt_find(l_client_pvt->uuid);
    if (!l_client_pvt)
        return;

    char l_errbuf[128];
    l_errbuf[0]='\0';
    if (a_error)
        strerror_r(a_error,l_errbuf,sizeof (l_errbuf));
    else
        strncpy(l_errbuf,"Unknown Error",sizeof(l_errbuf)-1);

    log_it(L_WARNING, "STREAM error \"%s\" (code %d)", l_errbuf, a_error);    

    if (a_error == ETIMEDOUT) {
        l_client_pvt->last_error = ERROR_NETWORK_CONNECTION_TIMEOUT;
    } else {
        l_client_pvt->last_error = ERROR_STREAM_RESPONSE_WRONG;
    }
    l_client_pvt->stage_status = STAGE_STATUS_ERROR;

    s_stage_status_after(l_client_pvt);
}
