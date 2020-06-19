/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame SDK   https://cellframe.net
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
#endif

#include <pthread.h>

#include <json-c/json.h>

#include "dap_enc_key.h"
#include "dap_enc_base64.h"
#include "dap_enc.h"
#include "dap_common.h"
#include "dap_strfuncs.h"

//#include "dap_http_client_simple.h"
#include "dap_client_http.h"
#include "dap_client.h"
#include "dap_client_pvt.h"
#include "dap_server.h"
#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_pkt.h"
#include "dap_http_client.h"

#define LOG_TAG "dap_client_pvt"

#ifndef DAP_ENC_KS_KEY_ID_SIZE
#define DAP_ENC_KS_KEY_ID_SIZE 33
#endif

static void s_stage_status_after(dap_client_pvt_t * a_client_internal);

// ENC stage callbacks
void m_enc_init_response(dap_client_t *, void *, size_t);
void m_enc_init_error(dap_client_t *, int);

// STREAM_CTL stage callbacks
void m_stream_ctl_response(dap_client_t *, void *, size_t);
void m_stream_ctl_error(dap_client_t *, int);
void m_stage_stream_streaming(dap_client_t * a_client, void* arg);

// STREAM stage callbacks
void m_stream_response(dap_client_t *, void *, size_t);
void m_stream_error(dap_client_t *, int);

void m_request_response(void * a_response, size_t a_response_size, void * a_obj);
void m_request_error(int, void *);

// stream callbacks
void m_es_stream_delete(dap_events_socket_t * a_es, void * arg);
void m_es_stream_read(dap_events_socket_t * a_es, void * arg);
void m_es_stream_write(dap_events_socket_t * a_es, void * arg);
void m_es_stream_error(dap_events_socket_t * a_es, void * arg);

/**
 * @brief dap_client_internal_init
 * @return
 */
int dap_client_pvt_init()
{
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
void dap_client_pvt_new(dap_client_pvt_t * a_client_internal)
{
    a_client_internal->stage = STAGE_BEGIN; // start point of state machine
    a_client_internal->stage_status = STAGE_STATUS_DONE;
    a_client_internal->uplink_protocol_version = DAP_PROTOCOL_VERSION;
    // add to list
    dap_client_pvt_hh_add(a_client_internal);
}

typedef struct dap_client_pvt_ref_count {
    dap_client_pvt_t *client_internal;
    uint32_t ref_count;
    UT_hash_handle hh;
} dap_client_pvt_ref_count_t;

//static dap_client_pvt_ref_count_t *s_client_pvt_ref = NULL;
//static pthread_mutex_t s_mutex_ref = PTHREAD_MUTEX_INITIALIZER;
//static pthread_cond_t s_cond_ref = PTHREAD_COND_INITIALIZER;

/*
int dap_client_pvt_ref(dap_client_pvt_t * a_client_internal)
{
    if(a_client_internal==0x7fffd8003b00){
        int dbg = 5325;
    }
    int l_ret = 0;
    dap_client_pvt_ref_count_t *l_client_pvt_ref;
    pthread_mutex_lock(&s_mutex_ref);
    HASH_FIND(hh, s_client_pvt_ref, &a_client_internal, sizeof(dap_client_pvt_t*), l_client_pvt_ref);
    if(!l_client_pvt_ref) {
        l_client_pvt_ref = DAP_NEW_Z(dap_client_pvt_ref_count_t);
        l_client_pvt_ref->client_internal = a_client_internal;
        l_client_pvt_ref->ref_count = 1;
        HASH_ADD(hh, s_client_pvt_ref, client_internal, sizeof(dap_client_pvt_t*), l_client_pvt_ref);
    }
    else {
        l_client_pvt_ref->ref_count++;
    }
    l_ret = l_client_pvt_ref->ref_count;
    //printf("** ref %d %x\n\n", l_client_pvt_ref->ref_count, a_client_internal);
    pthread_mutex_unlock(&s_mutex_ref);

    return l_ret;
}

int dap_client_pvt_unref(dap_client_pvt_t * a_client_internal)
{
    if(a_client_internal==0x7fffd8003b00){
        int dbg = 5325;
    }
    int l_ret = -1;
    dap_client_pvt_ref_count_t *l_client_pvt_ref;
    pthread_mutex_lock(&s_mutex_ref);
    HASH_FIND(hh, s_client_pvt_ref, &a_client_internal, sizeof(dap_client_pvt_t*), l_client_pvt_ref);
    if(l_client_pvt_ref) {
        if(l_client_pvt_ref->ref_count <= 1) {
            HASH_DELETE(hh, s_client_pvt_ref, l_client_pvt_ref);
            DAP_DELETE(l_client_pvt_ref);
            pthread_cond_broadcast(&s_cond_ref);
            l_ret = 0;
        }
        else {
            l_client_pvt_ref->ref_count--;
            l_ret = l_client_pvt_ref->ref_count;
        }
    }
    else{
        l_ret = -1;
    }
    //printf("** unref %d %x\n\n", l_ret, a_client_internal);
    pthread_mutex_unlock(&s_mutex_ref);
    return l_ret;
}

int dap_client_pvt_get_ref(dap_client_pvt_t * a_client_internal)
{
    int l_ref_count = -1;
    if(a_client_internal==0x7fffd8003b00){
        int dbg = 5325;
    }
    dap_client_pvt_ref_count_t *l_client_pvt_ref;
    pthread_mutex_lock(&s_mutex_ref);
    HASH_FIND(hh, s_client_pvt_ref, &a_client_internal, sizeof(dap_client_pvt_t*), l_client_pvt_ref);
    if(l_client_pvt_ref) {
        l_ref_count = l_client_pvt_ref->ref_count;
    }
    pthread_mutex_unlock(&s_mutex_ref);
    return l_ref_count;
}

int dap_client_pvt_wait_unref(dap_client_pvt_t * a_client_internal, int a_timeout_ms)
{
    if(!a_client_internal)
        return -1;
    int l_ret = 0;
    dap_client_pvt_ref_count_t *l_client_pvt_ref;
    do {
        pthread_mutex_lock(&s_mutex_ref);
        HASH_FIND(hh, s_client_pvt_ref, &a_client_internal, sizeof(dap_client_pvt_t*), l_client_pvt_ref);
        // wait for release a_client_internal
        if(l_client_pvt_ref) {
            struct timeval now;
            struct timespec l_to;
            gettimeofday(&now, 0);
            l_to.tv_sec = now.tv_sec;      // sec
            l_to.tv_nsec = now.tv_usec * 1000; // nsec
            int64_t l_nsec_new = l_to.tv_nsec + a_timeout_ms * 1000000ll;
            // if the new number of nanoseconds is more than a second
            if(l_nsec_new > (long) 1e9) {
                l_to.tv_sec += l_nsec_new / (long) 1e9;
                l_to.tv_nsec = l_nsec_new % (long) 1e9;
            }
            else
                l_to.tv_nsec = (long) l_nsec_new;
            int l_res = pthread_cond_timedwait(&s_cond_ref, &s_mutex_ref, &l_to);
            if(l_res == ETIMEDOUT) {
                l_ret = -1;
            }
            else {
                //a_timeout_ms = 0;
                pthread_mutex_unlock(&s_mutex_ref);
                continue;
            }
        }
        else
            l_ret = 0;

        //printf("** end wait %x\n\n", a_client_internal);
        pthread_mutex_unlock(&s_mutex_ref);
    }
    while(l_client_pvt_ref);
    return l_ret;
}
*/

/**
 * @brief dap_client_disconnect
 * @param a_client
 * @return
 */
int dap_client_pvt_disconnect(dap_client_pvt_t *a_client_pvt)
{
    //dap_client_pvt_t *a_client_pvt = (a_client) ? DAP_CLIENT_PVT(a_client) : NULL;
    if(!a_client_pvt)
        return -1;
    // stop connection
    //dap_http_client_simple_request_break(l_client_internal->curl_sockfd);

    if(a_client_pvt && a_client_pvt->stream_socket) {

//        if ( l_client_internal->stream_es ) {
//            dap_events_socket_remove_and_delete( l_client_internal->stream_es, true );
//            l_client_internal->stream_es = NULL;
//        }

//        l_client_internal->stream_es->signal_close = true;
        // start stopping connection
        if(!dap_events_socket_kill_socket(a_client_pvt->stream_es)) {
            int l_counter = 0;
            // wait for stop of connection (max 0.7 sec.)
            while(a_client_pvt->stream_es && l_counter < 70) {
                dap_usleep(DAP_USEC_PER_SEC / 100);
                l_counter++;
            }
            if(l_counter >= 70) {
                dap_events_socket_remove_and_delete(a_client_pvt->stream_es, true);
            }
        }
//        if (l_client_internal->stream_socket ) {
//            close (l_client_internal->stream_socket);
//        l_client_internal->stream_socket = 0;
//        }

        return 1;
    }
    //l_client_internal->stream_socket = 0;

    a_client_pvt->is_reconnect = false;

    log_it(L_DEBUG, "dap_client_pvt_disconnect() done");

    return -1;
}

/**
 * @brief dap_client_pvt_delete
 * @param a_client_pvt
 */
static void dap_client_pvt_delete_in(dap_client_pvt_t * a_client_pvt)
{
    if(!a_client_pvt)
        return;
    // delete from list
    if(dap_client_pvt_hh_del(a_client_pvt)<0){
        log_it(L_DEBUG, "dap_client_pvt 0x%x already deleted", a_client_pvt);
        return;
    }

    dap_client_pvt_disconnect(a_client_pvt);

    log_it(L_INFO, "dap_client_pvt_delete 0x%x", a_client_pvt);

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

    //a_client_pvt->client = NULL;
    DAP_DELETE(a_client_pvt);
}

/*
static void* dap_client_pvt_delete_proc(void *a_arg)
{
    dap_client_pvt_t * l_client_pvt = (dap_client_pvt_t*)a_arg;
    // wait for release l_client_pvt
    //dap_client_pvt_wait_unref(l_client_pvt, 20000000);

    //dap_client_reset(l_client_pvt->client);
    dap_client_pvt_delete_in(l_client_pvt);
    //DAP_DELETE(l_client_pvt->client);
    pthread_exit(0);
}*/

/**
 * @brief dap_client_pvt_delete
 * @param a_client_pvt
 */
void dap_client_pvt_delete(dap_client_pvt_t * a_client_pvt)
{
    //pthread_create(&l_thread, NULL, dap_client_pvt_delete_proc, a_client_pvt);
    dap_client_pvt_delete_in(a_client_pvt);
}

/**
 * Make socket non-blocking / blocking
 * is_nonblock - (true) non-blocking / (false) blocking
 */
static void s_set_sock_nonblock(int sockfd, bool is_nonblock)
{
// for Windows
#ifdef _WIN32
    unsigned long arg = is_nonblock;
    ioctlsocket((SOCKET)sockfd, FIONBIO, &arg);
// for Unix-like OS
#else
    int arg = fcntl(sockfd, F_GETFL, NULL);
    if(is_nonblock)
        arg |= O_NONBLOCK;
    else
        arg |= ~O_NONBLOCK;
    fcntl(sockfd, F_SETFL, arg);
#endif
}

/**
 * @brief s_client_internal_stage_status_proc
 * @param a_client
 */
static void s_stage_status_after(dap_client_pvt_t * a_client_pvt)
{
    //bool l_is_unref = false;

    switch (a_client_pvt->stage_status) {
    case STAGE_STATUS_IN_PROGRESS: {
        switch (a_client_pvt->stage) {
        case STAGE_ENC_INIT: {
            log_it(L_INFO, "Go to stage ENC: prepare the request");

            a_client_pvt->session_key_open = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_MSRLN, NULL, 0, NULL, 0, 0);

            size_t l_key_str_size_max = DAP_ENC_BASE64_ENCODE_SIZE(a_client_pvt->session_key_open->pub_key_data_size);
            char *l_key_str = DAP_NEW_Z_SIZE(char, l_key_str_size_max + 1);
            // DAP_ENC_DATA_TYPE_B64_URLSAFE not need because send it by POST request
            size_t l_key_str_enc_size = dap_enc_base64_encode(a_client_pvt->session_key_open->pub_key_data,
                    a_client_pvt->session_key_open->pub_key_data_size,
                    l_key_str, DAP_ENC_DATA_TYPE_B64);

            log_it(L_DEBUG, "ENC request size %u", l_key_str_enc_size);
            int l_res = dap_client_pvt_request(a_client_pvt, DAP_UPLINK_PATH_ENC_INIT "/gd4y5yh78w42aaagh",
                    l_key_str, l_key_str_enc_size, m_enc_init_response, m_enc_init_error);
            // bad request
            if(l_res<0){
            	a_client_pvt->stage_status = STAGE_STATUS_ERROR;
            }
            DAP_DELETE(l_key_str);
        }
            break;
        case STAGE_STREAM_CTL: {
            log_it(L_INFO, "Go to stage STREAM_CTL: prepare the request");

            char *l_request = dap_strdup_printf("%d", DAP_CLIENT_PROTOCOL_VERSION);
            size_t l_request_size = dap_strlen(l_request);
            log_it(L_DEBUG, "STREAM_CTL request size %u", strlen(l_request));

            char *l_suburl;
            l_suburl = dap_strdup_printf("stream_ctl,channels=%s", a_client_pvt->active_channels);
            //
            dap_client_pvt_request_enc(a_client_pvt,
            DAP_UPLINK_PATH_STREAM_CTL,
                    l_suburl, "type=tcp,maxconn=4", l_request, l_request_size,
                    m_stream_ctl_response, m_stream_ctl_error);
            DAP_DELETE(l_request);
            DAP_DELETE(l_suburl);
        }
            break;
        case STAGE_STREAM_SESSION: {
            log_it(L_INFO, "Go to stage STREAM_SESSION: process the state ops");

            a_client_pvt->stream_socket = socket( PF_INET, SOCK_STREAM, 0);
#ifdef _WIN32 
            {
              int buffsize = 65536;
              int optsize = sizeof( int );
              setsockopt(a_client_pvt->stream_socket, SOL_SOCKET, SO_SNDBUF, (char *)&buffsize, &optsize );
              setsockopt(a_client_pvt->stream_socket, SOL_SOCKET, SO_RCVBUF, (char *)&buffsize, &optsize );
            }
#else
            int buffsize = 65536;
            setsockopt(a_client_pvt->stream_socket, SOL_SOCKET, SO_SNDBUF, (const void *) &buffsize, sizeof(int));
            setsockopt(a_client_pvt->stream_socket, SOL_SOCKET, SO_RCVBUF, (const void *) &buffsize, sizeof(int));
#endif

            // Wrap socket and setup callbacks
            static dap_events_socket_callbacks_t l_s_callbacks = {
                .read_callback = m_es_stream_read,
                .write_callback = m_es_stream_write,
                .error_callback = m_es_stream_error,
                .delete_callback = m_es_stream_delete
            };
            a_client_pvt->stream_es = dap_events_socket_wrap_no_add(a_client_pvt->events,
                    a_client_pvt->stream_socket, &l_s_callbacks);
            // add to dap_worker
            dap_events_socket_create_after(a_client_pvt->stream_es);

            a_client_pvt->stream_es->_inheritor = a_client_pvt;//->client;
            a_client_pvt->stream = dap_stream_new_es(a_client_pvt->stream_es);
            a_client_pvt->stream->is_client_to_uplink = true;
            a_client_pvt->stream_session = dap_stream_session_pure_new(); // may be from in packet?

            // new added, whether it is necessary?
            a_client_pvt->stream->session = a_client_pvt->stream_session;
            a_client_pvt->stream->session->key = a_client_pvt->stream_key;

            // connect
            struct sockaddr_in l_remote_addr;
            memset(&l_remote_addr, 0, sizeof(l_remote_addr));
            l_remote_addr.sin_family = AF_INET;
            l_remote_addr.sin_port = htons(a_client_pvt->uplink_port);
            if(inet_pton(AF_INET, a_client_pvt->uplink_addr, &(l_remote_addr.sin_addr)) < 0) {
                log_it(L_ERROR, "Wrong remote address '%s:%u'", a_client_pvt->uplink_addr, a_client_pvt->uplink_port);
                //close(a_client_pvt->stream_socket);
                dap_events_socket_kill_socket(a_client_pvt->stream_es);
                //a_client_pvt->stream_socket = 0;
                a_client_pvt->stage_status = STAGE_STATUS_ERROR;
            }
            else {
                int l_err = 0;
                if((l_err = connect(a_client_pvt->stream_socket, (struct sockaddr *) &l_remote_addr,
                        sizeof(struct sockaddr_in))) != -1) {
                    a_client_pvt->stream_es->flags &= ~DAP_SOCK_SIGNAL_CLOSE;
                    //s_set_sock_nonblock(a_client_pvt->stream_socket, false);
                    log_it(L_INFO, "Remote address connected (%s:%u) with sock_id %d", a_client_pvt->uplink_addr,
                            a_client_pvt->uplink_port, a_client_pvt->stream_socket);
                    a_client_pvt->stage_status = STAGE_STATUS_DONE;
                }
                else {
                    log_it(L_ERROR, "Remote address can't connected (%s:%u) with sock_id %d", a_client_pvt->uplink_addr,
                            a_client_pvt->uplink_port);
                    dap_events_socket_kill_socket(a_client_pvt->stream_es);
                    //close(a_client_pvt->stream_socket);
                    a_client_pvt->stream_socket = 0;
                    a_client_pvt->stage_status = STAGE_STATUS_ERROR;
                }
            }
            s_stage_status_after(a_client_pvt);

        }
            break;
        case STAGE_STREAM_CONNECTED: {
            log_it(L_INFO, "Go to stage STAGE_STREAM_CONNECTED");
            size_t count_channels = strlen(a_client_pvt->active_channels);
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

            dap_events_socket_write_f( a_client_pvt->stream_es, "GET /%s HTTP/1.1\r\n"
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
//    case STAGE_STATUS_ABORTING: {
//        log_it(L_ERROR, "Aborting state");
//    }
        break;
    case STAGE_STATUS_ERROR: {
        // limit the number of attempts
        int MAX_ATTEMPTS = 3;
        a_client_pvt->connect_attempt++;
        bool l_is_last_attempt = a_client_pvt->connect_attempt > MAX_ATTEMPTS ? true : false;

        log_it(L_ERROR, "Error state, doing callback if present");
        if(a_client_pvt->stage_status_error_callback) {
            //dap_client_pvt_ref(a_client_pvt);
            a_client_pvt->stage_status_error_callback(a_client_pvt->client, (void*)l_is_last_attempt);
            //dap_client_pvt_unref(a_client_pvt);
            // Expecting that its one-shot callback
            //a_client_internal->stage_status_error_callback = NULL;
        }
        if(a_client_pvt->stage_target == STAGE_STREAM_ABORT) {
            a_client_pvt->stage = STAGE_STREAM_ABORT;
            a_client_pvt->stage_status = STAGE_STATUS_ABORTING;
            // unref pvt
            //l_is_unref = true;
        } else if (a_client_pvt->last_error != ERROR_NETWORK_CONNECTION_TIMEOUT) {
            if(!l_is_last_attempt) {
                // small delay before next request
                log_it(L_INFO, "Connection attempt %d", a_client_pvt->connect_attempt);
#ifdef _WIN32
                Sleep(300);// 0.3 sec
#else
                usleep(300000);// 0.3 sec
#endif
                a_client_pvt->stage = STAGE_ENC_INIT;
                // Trying the step again
                a_client_pvt->stage_status = STAGE_STATUS_IN_PROGRESS;
                //dap_client_pvt_ref(a_client_pvt);
                s_stage_status_after(a_client_pvt);
            }
            else{
                log_it(L_INFO, "Too many connection attempts. Tries are over.");
                a_client_pvt->stage_status = STAGE_STATUS_DONE;
                // unref pvt
                //l_is_unref = true;
            }
        }
    }
        break;
    case STAGE_STATUS_DONE: {
        log_it(L_INFO, "Stage status %s is done",
                dap_client_stage_str(a_client_pvt->stage));
        // go to next stage
        if(a_client_pvt->stage_status_done_callback) {
            a_client_pvt->stage_status_done_callback(a_client_pvt->client, NULL);
            // Expecting that its one-shot callback
            //a_client_internal->stage_status_done_callback = NULL;
        } else
            log_it(L_WARNING, "Stage done callback is not present");

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
        } else if (a_client_pvt->stage != STAGE_STREAM_CTL) {   // need wait for dap_client_pvt_request_enc response
            log_it(L_ERROR, "!! dap_CLIENT_STAGE_STATUS_DONE but not l_is_last_stage (cur stage=%d, target=%d)!!",a_client_pvt->stage, a_client_pvt->stage_target);
        }
        //l_is_unref = true;
    }
        break;
    default:
        log_it(L_ERROR, "Undefined proccessing actions for stage status %s",
                dap_client_stage_status_str(a_client_pvt->stage_status));
    }

    if(a_client_pvt->stage_status_callback)
        a_client_pvt->stage_status_callback(a_client_pvt->client, NULL);
    //if(l_is_unref) {
        // unref pvt
        //dap_client_pvt_unref(a_client_pvt);
    //}
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
    // ref pvt client
    //dap_client_pvt_ref(a_client_internal);

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

//    size_t l_url_size_max = 0;
//    char *l_url = NULL;
//    if(a_path) {
//        l_url_size_max = dap_strlen(a_client_internal->uplink_addr) + strlen(a_path) + 15;
//        l_url = DAP_NEW_Z_SIZE(char, l_url_size_max);
//
//        snprintf(l_url, l_url_size_max, "http://%s:%u/%s", a_client_internal->uplink_addr,
//                a_client_internal->uplink_port, a_path);
//    } else {
//        l_url_size_max = strlen(a_client_internal->uplink_addr) + 15;
//        l_url = DAP_NEW_Z_SIZE(char, l_url_size_max);
//        snprintf(l_url, l_url_size_max, "http://%s:%u", a_client_internal->uplink_addr, a_client_internal->uplink_port);
//    }
    void *l_ret = dap_client_http_request(a_client_internal->uplink_addr,a_client_internal->uplink_port, a_request ? "POST" : "GET", "text/text", a_path, a_request,
            a_request_size, NULL, m_request_response, m_request_error, a_client_internal, NULL);
//    a_client_internal->curl = dap_http_client_simple_request(l_url, a_request ? "POST" : "GET", "text/text", a_request,
//            a_request_size, NULL, m_request_response, m_request_error, &a_client_internal->curl_sockfd, a_client_internal, NULL);
//    DAP_DELETE(l_url);
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
    bool is_query_enc = false; // it true, then encode a_query string
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
    char *l_path = NULL;
    if(a_path) {
        if(l_sub_url_size) {
            if(l_query_size) {
                l_path = dap_strdup_printf("%s/%s?%s", a_path, l_sub_url_enc, l_query_enc);

            } else {
                l_path = dap_strdup_printf("%s/%s", a_path, l_sub_url_enc);
            }
        } else {
            l_path = dap_strdup(a_path);
        }
    }

    size_t l_key_hdr_str_size_max = strlen(a_client_internal->session_key_id) + 10;
    char *l_key_hdr_str = DAP_NEW_Z_SIZE(char, l_key_hdr_str_size_max);
    snprintf(l_key_hdr_str, l_key_hdr_str_size_max, "KeyID: %s", a_client_internal->session_key_id);

    char *a_custom_new[2];
    size_t a_custom_count = 1;
    a_custom_new[0] = l_key_hdr_str;
    // close session
    if(a_client_internal->is_close_session) {
        a_custom_new[1] = "SessionCloseAfterRequest: true";
        a_custom_count++;
    }
    dap_client_http_request_custom(a_client_internal->uplink_addr, a_client_internal->uplink_port, a_request ? "POST" : "GET", "text/text",
                l_path, l_request_enc, l_request_enc_size, NULL,
                m_request_response, m_request_error, a_client_internal, a_custom_new, a_custom_count);
//    dap_http_client_simple_request_custom(l_url_full, a_request ? "POST" : "GET", "text/text",
//            l_request_enc, l_request_enc_size, NULL,
//            m_request_response, a_client_internal->curl_sockfd ,m_request_error, a_client_internal, a_custom_new, a_custom_count);

    DAP_DELETE(l_key_hdr_str);
    if(l_sub_url_enc)
        DAP_DELETE(l_sub_url_enc);

    if(is_query_enc && l_query_enc)
        DAP_DELETE(l_query_enc);

//    if(l_url_full)
//        DAP_DELETE(l_url_full);

    if(l_request_enc)
        DAP_DELETE(l_request_enc);
}

/**
 * @brief m_request_error
 * @param a_err_code
 * @param a_obj
 */
void m_request_error(int a_err_code, void * a_obj)
{
    dap_client_pvt_t * a_client_internal = (dap_client_pvt_t *) a_obj;
    dap_client_pvt_hh_lock();
    if(!dap_client_pvt_hh_get(a_client_internal)){
        dap_client_pvt_hh_unlock();
        return;
    }
    if(a_client_internal && a_client_internal->request_error_callback && a_client_internal->client)
    {
        if(a_client_internal && a_client_internal->request_error_callback && a_client_internal->client && a_client_internal->client->_internal)
            a_client_internal->request_error_callback(a_client_internal->client, a_err_code);
    }
    dap_client_pvt_hh_unlock();
}

/**
 * @brief m_request_response
 * @param a_response
 * @param a_response_size
 * @param a_obj
 */
void m_request_response(void * a_response, size_t a_response_size, void * a_obj)
{
    dap_client_pvt_t * a_client_internal = (dap_client_pvt_t *) a_obj;
    if(!a_client_internal || !a_client_internal->client)
        return;
    //int l_ref = dap_client_pvt_get_ref(a_client_internal);
    if(a_client_internal->is_encrypted) {
        size_t l_response_dec_size_max = a_response_size ? a_response_size * 2 + 16 : 0;
        char * l_response_dec = a_response_size ? DAP_NEW_Z_SIZE(char, l_response_dec_size_max) : NULL;
        size_t l_response_dec_size = 0;
        if(a_response_size)
            l_response_dec_size = dap_enc_decode(a_client_internal->session_key,
                    a_response, a_response_size,
                    l_response_dec, l_response_dec_size_max,
                    DAP_ENC_DATA_TYPE_RAW);

        a_client_internal->request_response_callback(a_client_internal->client, l_response_dec, l_response_dec_size);

        if(l_response_dec)
            DAP_DELETE(l_response_dec);
    } else {
        a_client_internal->request_response_callback(a_client_internal->client, a_response, a_response_size);
    }

    //int l_ref2 = dap_client_pvt_get_ref(a_client_internal);
    // unref pvt client
    //dap_client_pvt_unref(a_client_internal);
    //dap_client_pvt_unref(DAP_CLIENT_PVT(a_client_internal->client));
}

/**
 * @brief m_enc_init_response
 * @param a_client
 * @param a_response
 * @param a_response_size
 */
void m_enc_init_response(dap_client_t * a_client, void * a_response, size_t a_response_size)
{
    dap_client_pvt_t * l_client_pvt = a_client ? DAP_CLIENT_PVT(a_client) : NULL;
    if(!l_client_pvt) {
        log_it(L_ERROR, "m_enc_init_response: l_client_pvt is NULL!");
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
                    char *str = (char *) json_object_get_string(val);
                    if(!strcmp(key, "encrypt_id")) {
                        l_session_id_b64 = DAP_NEW_Z_SIZE(char, strlen(str) + 1);
                        strcpy(l_session_id_b64, str);
                        json_parse_count++;
                    }
                    if(!strcmp(key, "encrypt_msg")) {
                        l_bob_message_b64 = DAP_NEW_Z_SIZE(char, strlen(str) + 1);
                        strcpy(l_bob_message_b64, str);
                        json_parse_count++;
                    }
                }
            }
            // free jobj
            json_object_put(jobj);
        }
        //char l_session_id_b64[DAP_ENC_BASE64_ENCODE_SIZE(DAP_ENC_KS_KEY_ID_SIZE) + 1] = { 0 };
        //char *l_bob_message_b64 = DAP_NEW_Z_SIZE(char, a_response_size - sizeof(l_session_id_b64) + 1);
        if(json_parse_count == 2) { //if (sscanf (a_response,"%s %s",l_session_id_b64, l_bob_message_b64) == 2 ){
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

            l_client_pvt->session_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_IAES,
                    l_client_pvt->session_key_open->priv_key_data, // shared key
                    l_client_pvt->session_key_open->priv_key_data_size,
                    l_client_pvt->session_key_id, strlen(l_client_pvt->session_key_id), 0);

            DAP_DELETE(l_bob_message);
            if(l_client_pvt->stage == STAGE_ENC_INIT) { // We are in proper stage
                l_client_pvt->stage_status = STAGE_STATUS_DONE;
                s_stage_status_after(l_client_pvt);
            } else {
                log_it(L_WARNING, "ENC: initialized encryption but current stage is %s (%s)",
                        dap_client_get_stage_str(a_client), dap_client_get_stage_status_str(a_client));
            }
        } else {
            log_it(L_ERROR, "ENC: Wrong response (size %u data '%s')", a_response_size, (char* ) a_response);
            l_client_pvt->last_error = ERROR_ENC_NO_KEY;
            l_client_pvt->stage_status = STAGE_STATUS_ERROR;
            s_stage_status_after(l_client_pvt);
        }
        DAP_DELETE(l_session_id_b64);
        DAP_DELETE(l_bob_message_b64);
    } else if(a_response_size > 1) {
        log_it(L_ERROR, "ENC: Wrong response (size %u data '%s')", a_response_size, (char* ) a_response);
        l_client_pvt->last_error = ERROR_ENC_NO_KEY;
        l_client_pvt->stage_status = STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_pvt);
    } else {
        log_it(L_ERROR, "ENC: Wrong response (size %u)", a_response_size);
        l_client_pvt->last_error = ERROR_ENC_NO_KEY;
        l_client_pvt->stage_status = STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_pvt);
    }
}

/**
 * @brief m_enc_init_error
 * @param a_client
 * @param a_err_code
 */
void m_enc_init_error(dap_client_t * a_client, int a_err_code)
{
    dap_client_pvt_t * l_client_pvt = DAP_CLIENT_PVT(a_client);
    if(!l_client_pvt) {
        log_it(L_ERROR, "m_enc_init_error: l_client_pvt is NULL!");
        return;
    }
    //dap_client_internal_t * l_client_internal = dap_CLIENT_INTERNAL(a_client);
    log_it(L_ERROR, "ENC: Can't init ecnryption session, err code %d", a_err_code);
    if (a_err_code == ETIMEDOUT) {
        l_client_pvt->last_error = ERROR_NETWORK_CONNECTION_TIMEOUT;
    } else {
        l_client_pvt->last_error = ERROR_NETWORK_CONNECTION_REFUSE;
    }
    l_client_pvt->stage_status = STAGE_STATUS_ERROR;
    s_stage_status_after(l_client_pvt);
}

/**
 * @brief m_stream_ctl_response
 * @param a_client
 * @param a_data
 * @param a_data_size
 */
void m_stream_ctl_response(dap_client_t * a_client, void * a_data, size_t a_data_size)
{
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
    if(!l_client_internal) {
        log_it(L_ERROR, "m_stream_ctl_response: l_client_internal is NULL!");
        return;
    }
    log_it(L_DEBUG, "STREAM_CTL response %u bytes length recieved", a_data_size);
    char * l_response_str = DAP_NEW_Z_SIZE(char, a_data_size + 1);
    memcpy(l_response_str, a_data, a_data_size);

    if(a_data_size < 4) {
        log_it(L_ERROR, "STREAM_CTL Wrong reply: '%s'", l_response_str);
        l_client_internal->last_error = ERROR_STREAM_CTL_ERROR_RESPONSE_FORMAT;
        l_client_internal->stage_status = STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_internal);
    } else if(strcmp(l_response_str, "ERROR") == 0) {
        log_it(L_WARNING, "STREAM_CTL Got ERROR from the remote site,expecting thats ERROR_AUTH");
        l_client_internal->last_error = ERROR_STREAM_CTL_ERROR_AUTH;
        l_client_internal->stage_status = STAGE_STATUS_ERROR;
        s_stage_status_after(l_client_internal);
    } else {
        int l_arg_count;
        char l_stream_id[25] = { 0 };
        char *l_stream_key = DAP_NEW_Z_SIZE(char, 4096 * 3);
        void * l_stream_key_raw = DAP_NEW_Z_SIZE(char, 4096);
        size_t l_stream_key_raw_size = 0;
        uint32_t l_remote_protocol_version;

        l_arg_count = sscanf(l_response_str, "%25s %4096s %u"
                , l_stream_id, l_stream_key, &l_remote_protocol_version);
        if(l_arg_count < 2) {
            log_it(L_WARNING, "STREAM_CTL Need at least 2 arguments in reply (got %d)", l_arg_count);
            l_client_internal->last_error = ERROR_STREAM_CTL_ERROR_RESPONSE_FORMAT;
            l_client_internal->stage_status = STAGE_STATUS_ERROR;
            s_stage_status_after(l_client_internal);
        } else {

            if(l_arg_count > 2) {
                l_client_internal->uplink_protocol_version = l_remote_protocol_version;
                log_it(L_DEBUG, "Uplink protocol version %u", l_remote_protocol_version);
            } else
                log_it(L_WARNING, "No uplink protocol version, use the default version %d"
                        , l_client_internal->uplink_protocol_version = DAP_PROTOCOL_VERSION);

            if(strlen(l_stream_id) < 13) {
                //log_it(L_DEBUG, "Stream server id %s, stream key length(base64 encoded) %u"
                //       ,l_stream_id,strlen(l_stream_key) );
                log_it(L_DEBUG, "Stream server id %s, stream key '%s'"
                        , l_stream_id, l_stream_key);

                //l_stream_key_raw_size = dap_enc_base64_decode(l_stream_key,strlen(l_stream_key),
                //                                             l_stream_key_raw,DAP_ENC_DATA_TYPE_B64);
                // Delete old key if present
                if(l_client_internal->stream_key)
                    dap_enc_key_delete(l_client_internal->stream_key);

                strncpy(l_client_internal->stream_id, l_stream_id, sizeof(l_client_internal->stream_id) - 1);
                l_client_internal->stream_key =
                        dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_OAES, l_stream_key, strlen(l_stream_key), NULL, 0,
                                32);

                if(l_client_internal->stage == STAGE_STREAM_CTL) { // We are on the right stage
                    l_client_internal->stage_status = STAGE_STATUS_DONE;
                    s_stage_status_after(l_client_internal);
                } else {
                    log_it(L_WARNING, "Expected to be stage STREAM_CTL but current stage is %s (%s)",
                            dap_client_get_stage_str(a_client), dap_client_get_stage_status_str(a_client));

                }
            } else {
                log_it(L_WARNING, "Wrong stream id response");
                l_client_internal->last_error = ERROR_STREAM_CTL_ERROR_RESPONSE_FORMAT;
                l_client_internal->stage_status = STAGE_STATUS_ERROR;
                s_stage_status_after(l_client_internal);
            }

        }
        DAP_DELETE(l_stream_key);
        DAP_DELETE(l_stream_key_raw);
    }
}

/**
 * @brief m_stream_ctl_error
 * @param a_client
 * @param a_error
 */
void m_stream_ctl_error(dap_client_t * a_client, int a_error)
{
    log_it(L_WARNING, "STREAM_CTL error %d", a_error);

    dap_client_pvt_t * l_client_pvt = DAP_CLIENT_PVT(a_client);
    if(!l_client_pvt) {
        log_it(L_ERROR, "m_stream_ctl_error: l_client_pvt is NULL!");
        return;
    }
    if (a_error == ETIMEDOUT) {
        l_client_pvt->last_error = ERROR_NETWORK_CONNECTION_TIMEOUT;
    } else {
        l_client_pvt->last_error = ERROR_STREAM_CTL_ERROR;
    }
    l_client_pvt->stage_status = STAGE_STATUS_ERROR;

    s_stage_status_after(l_client_pvt);

}

// STREAM stage callbacks
void m_stream_response(dap_client_t * a_client, void * a_data, size_t a_data_size)
{
    dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
    if(!l_client_internal) {
        log_it(L_ERROR, "m_stream_ctl_response: l_client_internal is NULL!");
        return;
    }
    log_it(L_DEBUG, "STREAM response %u bytes length recieved", a_data_size);
//    char * l_response_str = DAP_NEW_Z_SIZE(char, a_data_size + 1);
//    memcpy(l_response_str, a_data, a_data_size);

    if(l_client_internal->stage == STAGE_STREAM_CONNECTED) { // We are on the right stage
        l_client_internal->stage_status = STAGE_STATUS_DONE;
        s_stage_status_after(l_client_internal);
    }
    else {
        log_it(L_WARNING, "Expected to be stage STREAM_CONNECTED but current stage is %s (%s)",
                dap_client_get_stage_str(a_client), dap_client_get_stage_status_str(a_client));
        l_client_internal->stage_status = STAGE_STATUS_ERROR;
    }
    s_stage_status_after(l_client_internal);
}

void m_stream_error(dap_client_t * a_client, int a_error)
{
    log_it(L_WARNING, "STREAM error %d", a_error);

    dap_client_pvt_t * l_client_pvt = DAP_CLIENT_PVT(a_client);
    if(!l_client_pvt) {
        log_it(L_ERROR, "m_stream_error: l_client_pvt is NULL!");
        return;
    }
    if (a_error == ETIMEDOUT) {
        l_client_pvt->last_error = ERROR_NETWORK_CONNECTION_TIMEOUT;
    } else {
        l_client_pvt->last_error = ERROR_STREAM_RESPONSE_WRONG;
    }
    l_client_pvt->stage_status = STAGE_STATUS_ERROR;

    s_stage_status_after(l_client_pvt);
}

/**
 * @brief m_stage_stream_opened
 * @param a_client
 * @param arg
 */
void m_stage_stream_streaming(dap_client_t * a_client, void* arg)
{
    log_it(L_INFO, "Stream  is opened");
}

/**
 * @brief m_es_stream_delete
 * @param a_es
 * @param arg
 */
void m_es_stream_delete(dap_events_socket_t *a_es, void *arg)
{
    log_it(L_INFO, "================= stream delete/peer reconnect");

    //dap_client_t *l_client = DAP_CLIENT(a_es);
    dap_client_pvt_t * l_client_pvt = a_es->_inheritor;

    if(l_client_pvt == NULL) {
        log_it(L_ERROR, "dap_client_pvt_t is not initialized");
        return;
    }
    //pthread_mutex_lock(&l_client->mutex);

    //dap_client_pvt_t * l_client_pvt = DAP_CLIENT_PVT(l_client);
    log_it(L_DEBUG, "client_pvt=0x%x", l_client_pvt);
    if(l_client_pvt == NULL) {
        log_it(L_ERROR, "dap_client_pvt is not initialized");
        //pthread_mutex_unlock(&l_client->mutex);
        return;
    }

    dap_stream_delete(l_client_pvt->stream);
    l_client_pvt->stream = NULL;

//    if(l_client_pvt->client && l_client_pvt->client == l_client)
//        dap_client_reset(l_client_pvt->client);
//    l_client_pvt->client= NULL;

//    log_it(L_DEBUG, "dap_stream_session_close()");
//    sleep(3);
    dap_stream_session_close(l_client_pvt->stream_session->id);
    l_client_pvt->stream_session = NULL;

    // signal to permit  deleting of l_client_pvt
    l_client_pvt->stream_es = NULL;
    //pthread_mutex_unlock(&l_client->mutex);


/*  disable reconnect from here
    if(l_client_pvt->is_reconnect) {
        log_it(L_DEBUG, "l_client_pvt->is_reconnect = true");

        dap_client_go_stage(l_client_pvt->client, STAGE_STREAM_STREAMING, m_stage_stream_streaming);
    }
    else
        log_it(L_DEBUG, "l_client_pvt->is_reconnect = false");
*/
}

/**
 * @brief m_es_stream_read
 * @param a_es
 * @param arg
 */
void m_es_stream_read(dap_events_socket_t * a_es, void * arg)
{
    //dap_client_t * l_client = DAP_CLIENT(a_es);
    dap_client_pvt_t * l_client_pvt = a_es->_inheritor;//(l_client) ? DAP_CLIENT_PVT(l_client) : NULL;
    if(!l_client_pvt) {
        log_it(L_ERROR, "m_es_stream_read: l_client_pvt is NULL!");
        return;
    }
    switch (l_client_pvt->stage) {
    case STAGE_STREAM_SESSION:
        dap_client_go_stage(l_client_pvt->client, STAGE_STREAM_STREAMING, m_stage_stream_streaming);
        break;
    case STAGE_STREAM_CONNECTED: { // Collect HTTP headers before streaming
        if(a_es->buf_in_size > 1) {
            char * l_pos_endl;
            l_pos_endl = (char*) memchr(a_es->buf_in, '\r', a_es->buf_in_size - 1);
            if(l_pos_endl) {
                if(*(l_pos_endl + 1) == '\n') {
                    dap_events_socket_shrink_buf_in(a_es, l_pos_endl - a_es->buf_in_str);
                    log_it(L_DEBUG, "Header passed, go to streaming (%lu bytes already are in input buffer",
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
 * @brief m_es_stream_write
 * @param a_es
 * @param arg
 */
void m_es_stream_write(dap_events_socket_t * a_es, void * arg)
{
    //dap_client_t * l_client = DAP_CLIENT(a_es);
    //dap_client_pvt_t * l_client_pvt = (l_client) ? DAP_CLIENT_PVT(l_client) : NULL;
    dap_client_pvt_t * l_client_pvt = a_es->_inheritor;
    if(!l_client_pvt) {
        log_it(L_ERROR, "m_es_stream_write: l_client_pvt is NULL!");
        return;
    }
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

        dap_events_socket_set_writable(l_client_pvt->stream_es, ready_to_write);
        //log_it(ERROR,"No stream_data_write_callback is defined");
    }
        break;
    default: {
    }
    }
}

void m_es_stream_error(dap_events_socket_t * a_es, void * arg)
{
    //dap_client_t * l_client = DAP_CLIENT(a_es);
    //dap_client_pvt_t * l_client_pvt = (l_client) ? DAP_CLIENT_PVT(l_client) : NULL;
    dap_client_pvt_t * l_client_pvt = a_es->_inheritor;
    if(!l_client_pvt) {
        log_it(L_ERROR, "m_es_stream_error: l_client_pvt is NULL!");
        return;
    }
    log_it(L_INFO, "m_es_stream_error");
}

