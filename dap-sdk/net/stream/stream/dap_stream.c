/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#ifdef DAP_OS_WINDOWS
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include "dap_common.h"
#include "dap_timerfd.h"
#include "dap_events.h"

#include "dap_events.h"
#include "dap_stream.h"
#include "dap_stream_pkt.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_session.h"
#include "dap_events_socket.h"

#include "dap_http.h"
#include "dap_http_client.h"
#include "dap_http_header.h"
#include "dap_stream_worker.h"
#include "dap_client_pvt.h"

#define LOG_TAG "dap_stream"

static bool s_stream_proc_pkt_in(dap_stream_t * a_stream, dap_stream_pkt_t * l_pkt, size_t l_pkt_size);

// Callbacks for HTTP client
static void s_http_client_headers_read(dap_http_client_t * a_http_client, void * a_arg); // Prepare stream when all headers are read

static void s_http_client_headers_write(dap_http_client_t * a_http_client, void * a_arg); // Output headers
static void s_http_client_data_write(dap_http_client_t * a_http_client, void * a_arg); // Write the data
static void s_http_client_data_read(dap_http_client_t * a_http_client, void * a_arg); // Read the data

static void s_esocket_callback_worker_assign(dap_events_socket_t * a_esocket, dap_worker_t * a_worker);
static void s_esocket_callback_worker_unassign(dap_events_socket_t * a_esocket, dap_worker_t * a_worker);
static void s_client_callback_worker_assign(dap_events_socket_t *a_esocket, dap_worker_t *a_worker);
static void s_client_callback_worker_unassign(dap_events_socket_t *a_esocket, dap_worker_t *a_worker);

static void s_esocket_data_read(dap_events_socket_t* a_esocket, void * a_arg);
static void s_esocket_write(dap_events_socket_t* a_esocket, void * a_arg);
static void s_esocket_callback_delete(dap_events_socket_t* a_esocket, void * a_arg);
static void s_udp_esocket_new(dap_events_socket_t* a_esocket,void * a_arg);

// Internal functions
static dap_stream_t * s_stream_new(dap_http_client_t * a_http_client); // Create new stream
static void s_http_client_new(dap_http_client_t * a_esocket, void * a_arg) { }
static void s_http_client_delete(dap_http_client_t * a_esocket, void * a_arg);

static bool s_callback_server_keepalive(void *a_arg);
static bool s_callback_client_keepalive(void *a_arg);

static bool s_dump_packet_headers = false;
static bool s_debug = false;


#ifdef  DAP_SYS_DEBUG
enum    {MEMSTAT$K_STM, MEMSTAT$K_NR};
static  dap_memstat_rec_t   s_memstat [MEMSTAT$K_NR] = {
    {.fac_len = sizeof(LOG_TAG) - 1, .fac_name = {LOG_TAG}, .alloc_sz = sizeof(dap_stream_t)},
};
#endif



bool dap_stream_get_dump_packet_headers(){ return  s_dump_packet_headers; }

static bool s_detect_loose_packet(dap_stream_t * a_stream);

dap_enc_key_type_t s_stream_get_preferred_encryption_type = DAP_ENC_KEY_TYPE_IAES;

void s_dap_stream_load_preferred_encryption_type(dap_config_t * a_config){
    const char * l_preferred_encryption_name = dap_config_get_item_str(a_config, "stream", "preferred_encryption");
    if(l_preferred_encryption_name){
        dap_enc_key_type_t l_found_key_type = dap_enc_key_type_find_by_name(l_preferred_encryption_name);
        if(l_found_key_type != DAP_ENC_KEY_TYPE_INVALID)
            s_stream_get_preferred_encryption_type = l_found_key_type;
    }

    log_it(L_NOTICE,"ecryption type is set to %s", dap_enc_get_type_name(s_stream_get_preferred_encryption_type));
}

dap_enc_key_type_t dap_stream_get_preferred_encryption_type(){
    return s_stream_get_preferred_encryption_type;
}

/**
 * @brief stream_init Init stream module
 * @return  0 if ok others if not
 */
int dap_stream_init(dap_config_t * a_config)
{
    if( dap_stream_ch_init() != 0 ){
        log_it(L_CRITICAL, "Can't init channel types submodule");
        return -1;
    }
    if( dap_stream_worker_init() != 0 ){
        log_it(L_CRITICAL, "Can't init stream worker extention submodule");
        return -2;
    }

    s_dap_stream_load_preferred_encryption_type(a_config);
    s_dump_packet_headers = dap_config_get_item_bool_default(g_config,"general","debug_dump_stream_headers",false);
    s_debug = dap_config_get_item_bool_default(g_config,"stream","debug",false);
    log_it(L_NOTICE,"Init streaming module");

#ifdef  DAP_SYS_DEBUG
    for (int i = 0; i < MEMSTAT$K_NR; i++)
        dap_memstat_reg(&s_memstat[i]);
#endif



    return 0;
}

/**
 * @brief stream_media_deinit Deinint Stream module
 */
void dap_stream_deinit()
{
    dap_stream_ch_deinit( );
}

/**
 * @brief stream_add_proc_http Add URL processor callback for streaming
 * @param sh HTTP server instance
 * @param url URL
 */
void dap_stream_add_proc_http(struct dap_http * a_http, const char * a_url)
{
    dap_http_add_proc(a_http,a_url
                      ,NULL, // _internal
                      s_http_client_new, // New
                      s_http_client_delete, // Delete
                      s_http_client_headers_read, // Headers read
                      s_http_client_headers_write, // Headerts write
                      s_http_client_data_read, // Data read
                      s_http_client_data_write, // Data write
                      NULL); // Error callback
}

/**
 * @brief stream_add_proc_udp Add processor callback for streaming
 * @param a_udp_server UDP server instance
 */
void dap_stream_add_proc_udp(dap_server_t *a_udp_server)
{
    a_udp_server->client_callbacks.read_callback = s_esocket_data_read;
    a_udp_server->client_callbacks.write_callback = s_esocket_write;
    a_udp_server->client_callbacks.delete_callback = s_esocket_callback_delete;
    a_udp_server->client_callbacks.new_callback = s_udp_esocket_new;
    a_udp_server->client_callbacks.worker_assign_callback = s_esocket_callback_worker_assign;
    a_udp_server->client_callbacks.worker_unassign_callback = s_esocket_callback_worker_unassign;

}

/**
 * @brief stream_states_update
 * @param a_stream stream instance
 */
void stream_states_update(struct dap_stream *a_stream)
{
    if(a_stream->conn_http)
        a_stream->conn_http->state_write=DAP_HTTP_CLIENT_STATE_START;
    size_t i;
    bool ready_to_write=false;
    for(i=0;i<a_stream->channel_count; i++)
        ready_to_write|=a_stream->channel[i]->ready_to_write;
    dap_events_socket_set_writable_unsafe(a_stream->esocket,ready_to_write);
    if(a_stream->conn_http)
        a_stream->conn_http->out_content_ready=true;
}



/**
 * @brief stream_new_udp Create new stream instance for UDP client
 * @param sh DAP client structure
 */
dap_stream_t * stream_new_udp(dap_events_socket_t * a_esocket)
{
    dap_stream_t * l_stm = DAP_NEW_Z(dap_stream_t);
    assert(l_stm);

#ifdef  DAP_SYS_DEBUG
    s_memstat[MEMSTAT$K_STM].alloc_nr += 1;
#endif

    l_stm->esocket = a_esocket;
    l_stm->esocket_uuid = a_esocket->uuid;
    a_esocket->_inheritor = l_stm ;

    log_it(L_NOTICE,"New stream instance udp");
    return l_stm ;
}

/**
 * @brief check_session CHeck session status, open if need
 * @param id session id
 * @param cl DAP client structure
 */
void check_session( unsigned int a_id, dap_events_socket_t *a_esocket )
{
    dap_stream_session_t *l_session = NULL;

    l_session = dap_stream_session_id_mt( a_id );

    if ( l_session == NULL ) {
        log_it(L_ERROR,"No session id %u was found",a_id);
        return;
    }

    log_it( L_INFO, "Session id %u was found with media_id = %d", a_id,l_session->media_id );

    if ( dap_stream_session_open(l_session) != 0 ) { // Create new stream

        log_it( L_ERROR, "Can't open session id %u", a_id );
        return;
    }

    dap_stream_t *l_stream;
    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT(a_esocket);
    if ( DAP_STREAM(l_http_client) == NULL )
        l_stream = stream_new_udp( a_esocket );
    else
        l_stream = DAP_STREAM( l_http_client );

    l_stream->session = l_session;

    if ( l_session->create_empty )
        log_it( L_INFO, "Session created empty" );

    log_it( L_INFO, "Opened stream session technical and data channels" );

    //size_t count_channels = strlen(l_session->active_channels);
    for (size_t i =0; i<sizeof (l_session->active_channels); i++ )
        if ( l_session->active_channels[i])
            dap_stream_ch_new( l_stream, l_session->active_channels[i] );

    stream_states_update( l_stream );

    dap_events_socket_set_readable_unsafe( a_esocket, true );

}

/**
 * @brief stream_new Create new stream instance for HTTP client
 * @return New stream_t instance
 */
dap_stream_t *s_stream_new(dap_http_client_t *a_http_client)
{
    dap_stream_t *l_stm = DAP_NEW_Z(dap_stream_t);
    assert(l_stm);

#ifdef  DAP_SYS_DEBUG
    atomic_fetch_add(&s_memstat[MEMSTAT$K_STM].alloc_nr, 1);
#endif

    l_stm->esocket = a_http_client->esocket;
    l_stm->esocket_uuid = a_http_client->esocket->uuid;
    l_stm->stream_worker = (dap_stream_worker_t *)a_http_client->esocket->worker->_inheritor;
    l_stm->conn_http = a_http_client;
    l_stm->seq_id = 0;
    l_stm->client_last_seq_id_packet = (size_t)-1;
    // Start server keep-alive timer
    dap_events_socket_uuid_t *l_es_uuid = DAP_NEW_Z(dap_events_socket_uuid_t);
    *l_es_uuid = l_stm->esocket->uuid;
    l_stm->keepalive_timer = dap_timerfd_start_on_worker(l_stm->esocket->worker,
                                                         STREAM_KEEPALIVE_TIMEOUT * 1000,
                                                         (dap_timerfd_callback_t)s_callback_server_keepalive,
                                                         l_es_uuid);
    l_stm->esocket->callbacks.worker_assign_callback = s_esocket_callback_worker_assign;
    l_stm->esocket->callbacks.worker_unassign_callback = s_esocket_callback_worker_unassign;
    a_http_client->_inheritor = l_stm;
    log_it(L_NOTICE,"New stream instance");
    return l_stm;
}

/**
 * @brief dap_stream_new_es
 * @param a_es
 * @return
 */
dap_stream_t* dap_stream_new_es_client(dap_events_socket_t * a_esocket)
{
    dap_stream_t *l_stm = DAP_NEW_Z(dap_stream_t);
    assert(l_stm);

#ifdef  DAP_SYS_DEBUG
    atomic_fetch_add(&s_memstat[MEMSTAT$K_STM].alloc_nr, 1);
#endif


    l_stm->esocket = a_esocket;
    l_stm->esocket_uuid = a_esocket->uuid;
    l_stm->is_client_to_uplink = true;
    l_stm->esocket->callbacks.worker_assign_callback = s_client_callback_worker_assign;
    l_stm->esocket->callbacks.worker_unassign_callback = s_client_callback_worker_unassign;
    return l_stm;
}

/**
 * @brief dap_stream_delete_unsafe
 * @param a_stream
 */
void dap_stream_delete_unsafe(dap_stream_t *a_stream)
{
    if(a_stream == NULL) {
        log_it(L_ERROR,"stream delete NULL instance");
        return;
    }

    while (a_stream->channel_count)
        dap_stream_ch_delete(a_stream->channel[a_stream->channel_count - 1]);

    if(a_stream->session)
        dap_stream_session_close_mt(a_stream->session->id); // TODO make stream close after timeout, not momentaly

    if (a_stream->esocket) {
        a_stream->esocket->callbacks.delete_callback = NULL; // Prevent to remove twice
        dap_events_socket_remove_and_delete_unsafe(a_stream->esocket, true);
    }

    DAP_DEL_Z(a_stream->buf_fragments);
    DAP_DEL_Z(a_stream->pkt_buf_in);
    DAP_DELETE(a_stream);

#ifdef  DAP_SYS_DEBUG
    atomic_fetch_add(&s_memstat[MEMSTAT$K_STM].free_nr, 1);
#endif

    log_it(L_NOTICE, "[stm:%p] Stream connection is over", a_stream);

}

/**
 * @brief stream_dap_delete Delete callback for UDP client
 * @param a_esocket DAP client instance
 * @param arg Not used
 */
static void s_esocket_callback_delete(dap_events_socket_t *a_esocket, void * a_arg)
{
    UNUSED(a_arg);
    assert (a_esocket);

    dap_stream_t *l_stm = DAP_STREAM(a_esocket);
    a_esocket->_inheritor = NULL; // To prevent double free
    l_stm->esocket = NULL;
    l_stm->esocket_uuid = 0;
    dap_stream_delete_unsafe(l_stm);
}

/**
 * @brief stream_header_read Read headers callback for HTTP
 * @param a_http_client HTTP client structure
 * @param a_arg Not used
 */
void s_http_client_headers_read(dap_http_client_t * a_http_client, void * a_arg)
{
    (void) a_arg;

    unsigned int id=0;

    if(a_http_client->in_query_string[0]){
        log_it(L_INFO, "[es:%p] Query string [%s]", a_http_client->esocket, a_http_client->in_query_string);

        if(sscanf(a_http_client->in_query_string,"session_id=%u",&id) == 1 ||
                sscanf(a_http_client->in_query_string,"fj913htmdgaq-d9hf=%u",&id) == 1) {

            dap_stream_session_t * ss = NULL;
            if ( !(ss = dap_stream_session_id_mt(id)) ) {
                log_it(L_ERROR,"No session id %u was found", id);
                a_http_client->reply_status_code = 404;
                strcpy(a_http_client->reply_reason_phrase, "Not found");
            }else{
                log_it(L_INFO,"Session id %u was found with channels = %s",id,ss->active_channels);
                if(dap_stream_session_open(ss)==0){ // Create new stream
                    dap_stream_t * sid = s_stream_new(a_http_client);
                    sid->session=ss;
                    dap_http_header_t *header = dap_http_header_find(a_http_client->in_headers, "Service-Key");
                    if (header)
                        ss->service_key = strdup(header->value);
                    size_t count_channels = strlen(ss->active_channels);
                    for(size_t i = 0; i < count_channels; i++) {
                        dap_stream_ch_t * l_ch = dap_stream_ch_new(sid, ss->active_channels[i]);
                        l_ch->ready_to_read = true;
                    }

                    a_http_client->reply_status_code = 200;
                    strcpy(a_http_client->reply_reason_phrase, "OK");
                    stream_states_update(sid);
                    a_http_client->state_read = DAP_HTTP_CLIENT_STATE_DATA;
                    a_http_client->state_write = DAP_HTTP_CLIENT_STATE_START;
                    dap_events_socket_set_readable_unsafe(a_http_client->esocket, true);
                    dap_events_socket_set_writable_unsafe(a_http_client->esocket, true); // Dirty hack, because previous function shouldn't
                    //                                                                    // set write flag off but it does!
                }else{
                    log_it(L_ERROR, "[es:%p] Can't open session id %u", a_http_client->esocket, id);
                    a_http_client->reply_status_code = 404;
                    strcpy(a_http_client->reply_reason_phrase, "Not found");
                }
            }
        }
    }else{
        log_it(L_ERROR, "No query string");
    }
}

/**
 * @brief s_http_client_headers_write Prepare headers for output. Creates stream structure
 * @param sh HTTP client instance
 * @param arg Not used
 */
static void s_http_client_headers_write(dap_http_client_t * a_http_client, void *a_arg)
{
UNUSED(a_arg);

    if(a_http_client->reply_status_code==200){
        dap_stream_t *l_stream = DAP_STREAM(a_http_client);

        dap_http_header_add(&a_http_client->out_headers, "Content-Type",-1, "application/octet-stream", -1);
        dap_http_header_add(&a_http_client->out_headers, "Connection", -1, "keep-alive", -1);
        dap_http_header_add(&a_http_client->out_headers, "Cache-Control", -1, "no-cache", -1);

        if(l_stream->stream_size > 0)
            dap_http_out_header_add_f(a_http_client, "Content-Length", "%u", (unsigned int) l_stream->stream_size );

        a_http_client->state_read  = DAP_HTTP_CLIENT_STATE_DATA;
        dap_events_socket_set_readable_unsafe(a_http_client->esocket,true);
    }
}

/**
 * @brief stream_data_write HTTP data write callback
 * @param a_http_client HTTP client instance
 * @param a_arg Not used
 */
static void s_http_client_data_write(dap_http_client_t * a_http_client, void * a_arg)
{
    (void) a_arg;

    if( a_http_client->reply_status_code == 200 ){
        s_esocket_write(a_http_client->esocket, a_arg);
    }else{
        log_it(L_WARNING, "Wrong request, reply status code is %u",a_http_client->reply_status_code);
    }
}

/**
 * @brief s_esocket_callback_worker_assign
 * @param a_esocket
 * @param a_worker
 */
static void s_esocket_callback_worker_assign(dap_events_socket_t * a_esocket, dap_worker_t * a_worker)
{
    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT(a_esocket);
    assert(l_http_client);
    dap_stream_t * l_stream = DAP_STREAM(l_http_client);
    assert(l_stream);
    // Restart server keepalive timer if it was unassigned before
    if (!l_stream->keepalive_timer) {
        dap_events_socket_uuid_t * l_es_uuid= DAP_NEW_Z(dap_events_socket_uuid_t);
        *l_es_uuid = a_esocket->uuid;
        l_stream->keepalive_timer = dap_timerfd_start_on_worker(a_worker,
                                                                STREAM_KEEPALIVE_TIMEOUT * 1000,
                                                                (dap_timerfd_callback_t)s_callback_server_keepalive,
                                                                l_es_uuid);
    }
}

/**
 * @brief s_esocket_callback_worker_unassign
 * @param a_esocket
 * @param a_worker
 */
static void s_esocket_callback_worker_unassign(dap_events_socket_t * a_esocket, dap_worker_t * a_worker)
{
    UNUSED(a_worker);
    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT(a_esocket);
    assert(l_http_client);
    dap_stream_t * l_stream = DAP_STREAM(l_http_client);
    assert(l_stream);
    DAP_DEL_Z(l_stream->keepalive_timer->callback_arg);
    dap_timerfd_delete(l_stream->keepalive_timer);
    l_stream->keepalive_timer = NULL;
}

static void s_client_callback_worker_assign(dap_events_socket_t * a_esocket, dap_worker_t * a_worker)
{
    dap_client_pvt_t *l_client_pvt = DAP_ESOCKET_CLIENT_PVT(a_esocket);
    assert(l_client_pvt);
    dap_stream_t *l_stream = l_client_pvt->stream;
    assert(l_stream);
    // Start client keepalive timer or restart it, if it was unassigned before
    if (!l_stream->keepalive_timer) {
        dap_events_socket_uuid_t * l_es_uuid= DAP_NEW_Z(dap_events_socket_uuid_t);
        *l_es_uuid = a_esocket->uuid;
        l_stream->keepalive_timer = dap_timerfd_start_on_worker(a_worker,
                                                                STREAM_KEEPALIVE_TIMEOUT * 1000,
                                                                (dap_timerfd_callback_t)s_callback_client_keepalive,
                                                                l_es_uuid);
    }
}

static void s_client_callback_worker_unassign(dap_events_socket_t * a_esocket, dap_worker_t * a_worker)
{
    UNUSED(a_worker);
    dap_client_pvt_t *l_client_pvt = DAP_ESOCKET_CLIENT_PVT(a_esocket);
    assert(l_client_pvt);
    dap_stream_t *l_stream = l_client_pvt->stream;
    assert(l_stream);
    DAP_DEL_Z(l_stream->keepalive_timer->callback_arg);
    dap_timerfd_delete(l_stream->keepalive_timer);
    l_stream->keepalive_timer = NULL;
}

/**
 * @brief s_data_read
 * @param a_client
 * @param a_arg
 */
static void s_esocket_data_read(dap_events_socket_t* a_client, void * a_arg)
{
    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT(a_client);
    dap_stream_t * l_stream =DAP_STREAM(l_http_client);
    int * l_ret = (int *) a_arg;
    debug_if(s_dump_packet_headers, L_DEBUG,"dap_stream_data_read: ready_to_write=%s, client->buf_in_size=%zu" ,
             (a_client->flags & DAP_SOCK_READY_TO_WRITE)?"true":"false", a_client->buf_in_size );
    *l_ret = dap_stream_data_proc_read( l_stream);
}



/**
 * @brief stream_dap_data_write Write callback for UDP client
 * @param sh DAP client instance
 * @param arg Not used
 */
static void s_esocket_write(dap_events_socket_t* a_esocket , void * a_arg){
    (void) a_arg;
    size_t i;
    bool l_ready_to_write=false;
    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT(a_esocket);
    //log_it(L_DEBUG,"Process channels data output (%u channels)", DAP_STREAM(l_http_client)->channel_count );
    for(i=0;i<DAP_STREAM(l_http_client)->channel_count; i++){
        dap_stream_ch_t * ch = DAP_STREAM(l_http_client)->channel[i];
        if(ch->ready_to_write){
            if(ch->proc->packet_out_callback)
                ch->proc->packet_out_callback(ch,NULL);
            l_ready_to_write|=ch->ready_to_write;
        }
    }
    debug_if(s_dump_packet_headers, L_DEBUG,"dap_stream_data_write: ready_to_write=%s client->buf_out_size=%zu" ,
             l_ready_to_write?"true":"false", a_esocket->buf_out_size );
    dap_events_socket_set_writable_unsafe(a_esocket, l_ready_to_write);
    //log_it(L_DEBUG,"stream_dap_data_write ok");
}

/**
 * @brief s_udp_esocket_new New connection callback for UDP client
 * @param a_esocket DAP client instance
 * @param arg Not used
 */
static void s_udp_esocket_new(dap_events_socket_t* a_esocket, void * a_arg)
{
    stream_new_udp(a_esocket);
}


/**
 * @brief s_http_client_data_read HTTP data read callback. Read packet and passes that to the channel's callback
 * @param a_http_client HTTP client instance
 * @param arg Processed number of bytes
 */
static void s_http_client_data_read(dap_http_client_t * a_http_client, void * arg)
{
    s_esocket_data_read(a_http_client->esocket,arg);
}

/**
 * @brief stream_delete Delete stream and free its resources
 * @param sid Stream id
 */
static void s_http_client_delete(dap_http_client_t * a_http_client, void *a_arg)
{
    UNUSED(a_arg);
    dap_stream_t *l_stm = DAP_STREAM(a_http_client);
    if (!l_stm) {
        log_it(L_WARNING, "Stream for http client %p is already freed", a_http_client);
        return;
    }
    l_stm->esocket = NULL;
    l_stm->esocket_uuid = 0;
    a_http_client->_inheritor = NULL; // To prevent double free
    dap_stream_delete_unsafe(l_stm);
}

/**
 * @brief dap_stream_set_ready_to_write
 * @param a_stream
 * @param a_is_ready
 */
void dap_stream_set_ready_to_write(dap_stream_t * a_stream,bool a_is_ready)
{
    if(a_is_ready && a_stream->conn_http)
        a_stream->conn_http->state_write=DAP_HTTP_CLIENT_STATE_DATA;
    dap_events_socket_set_writable_unsafe(a_stream->esocket,a_is_ready);
}

/**
 * @brief dap_stream_data_proc_read
 * @param a_stream
 * @return
 */
size_t dap_stream_data_proc_read (dap_stream_t *a_stream)
{
    dap_stream_pkt_t *l_pkt = NULL;
    if(!a_stream || !a_stream->esocket)
        return 0;

    byte_t *l_buf_in = a_stream->esocket->buf_in;
    size_t l_buf_in_size = a_stream->esocket->buf_in_size;

    // Save the received data to stream memory
    if(!a_stream->pkt_buf_in) {
        a_stream->pkt_buf_in = DAP_DUP_SIZE(l_buf_in, l_buf_in_size);
        a_stream->pkt_buf_in_data_size = l_buf_in_size;
    } else {
        debug_if(s_dump_packet_headers, L_DEBUG, "dap_stream_data_proc_read() Receive previously unprocessed data %zu bytes + new %zu bytes",
                                                  a_stream->pkt_buf_in_data_size, l_buf_in_size);
        // The current data is added to rest of the previous package
        a_stream->pkt_buf_in = DAP_REALLOC(a_stream->pkt_buf_in, a_stream->pkt_buf_in_data_size + l_buf_in_size);
        memcpy((byte_t *)a_stream->pkt_buf_in + a_stream->pkt_buf_in_data_size, l_buf_in, l_buf_in_size);
        // Increase the size of pkt_buf_in
        a_stream->pkt_buf_in_data_size += l_buf_in_size;
    }
    // Switch to stream memory
    l_buf_in = (byte_t*) a_stream->pkt_buf_in;
    l_buf_in_size = a_stream->pkt_buf_in_data_size;
    size_t l_buf_in_left = l_buf_in_size;

    if(l_buf_in_left >= sizeof(dap_stream_pkt_hdr_t)) {
        // Now lets see how many packets we have in buffer now
        while(l_buf_in_left > 0 && (l_pkt = dap_stream_pkt_detect(l_buf_in, l_buf_in_left))) { // Packet signature detected
            if(l_pkt->hdr.size > DAP_STREAM_PKT_SIZE_MAX) {
                log_it(L_ERROR, "dap_stream_data_proc_read() Too big packet size %u, drop %zu bytes", l_pkt->hdr.size, l_buf_in_left);
                // Skip this packet
                l_buf_in_left = 0;
                break;
            }

            size_t l_pkt_offset = (((uint8_t*) l_pkt) - l_buf_in);
            l_buf_in += l_pkt_offset;
            l_buf_in_left -= l_pkt_offset;

            size_t l_pkt_size = l_pkt->hdr.size + sizeof(dap_stream_pkt_hdr_t);

            //log_it(L_DEBUG, "read packet offset=%zu size=%zu buf_in_left=%zu)",l_pkt_offset, l_pkt_size, l_buf_in_left);

            // Got the whole package
            if(l_buf_in_left >= l_pkt_size) {
                // Process data
                s_stream_proc_pkt_in(a_stream, (dap_stream_pkt_t*) l_pkt, l_pkt_size);
                // Go to the next data
                l_buf_in += l_pkt_size;
                l_buf_in_left -= l_pkt_size;
            } else {
                debug_if(s_dump_packet_headers,L_DEBUG, "Input: Not all stream packet in input (pkt_size=%zu buf_in_left=%zu)", l_pkt_size, l_buf_in_left);
                break;
            }
        }
    }

    if(l_buf_in_left > 0) {
        // Save the received data to stream memory for the next piece of data
        if(!l_pkt) {
            // pkt header not found, maybe l_buf_in_left is too small to detect pkt header, will do that next time
            l_pkt = (dap_stream_pkt_t*) l_buf_in;
            debug_if(s_dump_packet_headers, L_DEBUG, "dap_stream_data_proc_read() left unprocessed data %zu bytes, l_pkt=0", l_buf_in_left);
        }
        if(l_pkt) {
            a_stream->pkt_buf_in_data_size = l_buf_in_left;
            if(l_pkt != a_stream->pkt_buf_in){
                memmove(a_stream->pkt_buf_in, l_pkt, a_stream->pkt_buf_in_data_size);
                //log_it(L_DEBUG, "dap_stream_data_proc_read() l_pkt=%zu != a_stream->pkt_buf_in=%zu", l_pkt, a_stream->pkt_buf_in);
            }

            debug_if(s_dump_packet_headers,L_DEBUG, "dap_stream_data_proc_read() left unprocessed data %zu bytes", l_buf_in_left);
        }
        else {
            log_it(L_ERROR, "dap_stream_data_proc_read() pkt header not found, drop %zu bytes", l_buf_in_left);
            DAP_DEL_Z(a_stream->pkt_buf_in);
            a_stream->pkt_buf_in_data_size = 0;
        }
    }
    else {
        DAP_DEL_Z(a_stream->pkt_buf_in);
        a_stream->pkt_buf_in_data_size = 0;
    }

    return a_stream->esocket->buf_in_size; //a_stream->conn->buf_in_size;
}

/**
 * @brief stream_proc_pkt_in
 * @param sid
 */
static bool s_stream_proc_pkt_in(dap_stream_t *a_stream, dap_stream_pkt_t *l_pkt, size_t l_pkt_size)
{
    bool l_is_clean_fragments = false;
    a_stream->is_active = true;

    switch (l_pkt->hdr.type) {
    case STREAM_PKT_TYPE_FRAGMENT_PACKET: {
        size_t l_fragm_dec_size = dap_enc_decode_out_size(a_stream->session->key, l_pkt->hdr.size, DAP_ENC_DATA_TYPE_RAW);
        a_stream->pkt_cache = DAP_NEW_Z_SIZE(byte_t, l_fragm_dec_size);
        dap_stream_fragment_pkt_t *l_fragm_pkt = (dap_stream_fragment_pkt_t*)a_stream->pkt_cache;
        size_t l_dec_pkt_size = dap_stream_pkt_read_unsafe(a_stream, l_pkt, l_fragm_pkt, l_fragm_dec_size);

        if(l_dec_pkt_size == 0) {
            debug_if(s_dump_packet_headers, L_WARNING, "Input: can't decode packet size = %zu", l_pkt_size);
            l_is_clean_fragments = true;
            break;
        }
        if(l_dec_pkt_size != l_fragm_pkt->size + sizeof(dap_stream_fragment_pkt_t)) {
            debug_if(s_dump_packet_headers, L_WARNING, "Input: decoded packet has bad size = %zu, decoded size = %zu", l_fragm_pkt->size + sizeof(dap_stream_fragment_pkt_t), l_dec_pkt_size);
            l_is_clean_fragments = true;
            break;
        }

        if(a_stream->buf_fragments_size_filled != l_fragm_pkt->mem_shift) {
            debug_if(s_dump_packet_headers, L_WARNING, "Input: wrong fragment position %u, have to be %zu. Drop packet", l_fragm_pkt->mem_shift, a_stream->buf_fragments_size_filled);
            l_is_clean_fragments = true;
            break;
        } else {
            if(!a_stream->buf_fragments || a_stream->buf_fragments_size_total < l_fragm_pkt->full_size) {
                DAP_DEL_Z(a_stream->buf_fragments);
                a_stream->buf_fragments = DAP_NEW_Z_SIZE(uint8_t, l_fragm_pkt->full_size);
                a_stream->buf_fragments_size_total = l_fragm_pkt->full_size;
            }
            memcpy(a_stream->buf_fragments + l_fragm_pkt->mem_shift, l_fragm_pkt->data, l_fragm_pkt->size);
            a_stream->buf_fragments_size_filled += l_fragm_pkt->size;
        }

        // Not last fragment, otherwise go to parsing STREAM_PKT_TYPE_DATA_PACKET
        if(a_stream->buf_fragments_size_filled < l_fragm_pkt->full_size) {
            break;
        }
        // All fragments collected, move forward
    }
    case STREAM_PKT_TYPE_DATA_PACKET: {
        dap_stream_ch_pkt_t *l_ch_pkt;
        size_t l_dec_pkt_size;

        if (l_pkt->hdr.type == STREAM_PKT_TYPE_FRAGMENT_PACKET) {
            l_ch_pkt = (dap_stream_ch_pkt_t*)a_stream->buf_fragments;
            l_dec_pkt_size = a_stream->buf_fragments_size_total;
        } else {
            size_t l_pkt_dec_size = dap_enc_decode_out_size(a_stream->session->key, l_pkt->hdr.size, DAP_ENC_DATA_TYPE_RAW);
            a_stream->pkt_cache = DAP_NEW_Z_SIZE(byte_t, l_pkt_dec_size);
            l_ch_pkt = (dap_stream_ch_pkt_t*)a_stream->pkt_cache;
            l_dec_pkt_size = dap_stream_pkt_read_unsafe(a_stream, l_pkt, l_ch_pkt, l_pkt_dec_size);
        }

        if (l_dec_pkt_size != l_ch_pkt->hdr.size + sizeof(l_ch_pkt->hdr)) {
            log_it(L_WARNING, "Input: decoded packet has bad size = %zu, decoded size = %zu", l_ch_pkt->hdr.size + sizeof(l_ch_pkt->hdr), l_dec_pkt_size);
            l_is_clean_fragments = true;
            break;
        }

        // If seq_id is less than previous - doomp eet
        if (!s_detect_loose_packet(a_stream)) {
            dap_stream_ch_t * l_ch = NULL;
            for(size_t i=0;i<a_stream->channel_count;i++){
                if(a_stream->channel[i]->proc){
                    if(a_stream->channel[i]->proc->id == l_ch_pkt->hdr.id ){
                        l_ch=a_stream->channel[i];
                    }
                }
            }
            if(l_ch) {
                l_ch->stat.bytes_read += l_ch_pkt->hdr.size;
                if(l_ch->proc && l_ch->proc->packet_in_callback) {
                    debug_if(s_dump_packet_headers, L_INFO, "Income channel packet: id='%c' size=%u type=0x%02X seq_id=0x%016"DAP_UINT64_FORMAT_X" enc_type=0x%02X", (char ) l_ch_pkt->hdr.id,
                             l_ch_pkt->hdr.size, l_ch_pkt->hdr.type, l_ch_pkt->hdr.seq_id, l_ch_pkt->hdr.enc_type);
                    l_ch->proc->packet_in_callback(l_ch, l_ch_pkt);
                }
            } else{
                log_it(L_WARNING, "Input: unprocessed channel packet id '%c'",(char) l_ch_pkt->hdr.id );
            }
        }
        // packet already defragmented
        if(l_pkt->hdr.type == STREAM_PKT_TYPE_FRAGMENT_PACKET) {
            l_is_clean_fragments = true;
        }
    } break;
    case STREAM_PKT_TYPE_SERVICE_PACKET: {
        stream_srv_pkt_t *l_srv_pkt = (stream_srv_pkt_t *)l_pkt->data;
        uint32_t l_session_id = l_srv_pkt->session_id;
        check_session(l_session_id, a_stream->esocket);
    } break;
    case STREAM_PKT_TYPE_KEEPALIVE: {
        //log_it(L_DEBUG, "Keep alive check recieved");
        dap_stream_pkt_hdr_t l_ret_pkt = {};
        l_ret_pkt.type = STREAM_PKT_TYPE_ALIVE;
        memcpy(l_ret_pkt.sig, c_dap_stream_sig, sizeof(l_ret_pkt.sig));
        dap_events_socket_write_unsafe(a_stream->esocket, &l_ret_pkt, sizeof(l_ret_pkt));
        // Reset client keepalive timer
        if (a_stream->keepalive_timer) {
            dap_timerfd_reset(a_stream->keepalive_timer);
        }
    } break;
    case STREAM_PKT_TYPE_ALIVE:
        //log_it(L_DEBUG, "Keep alive response recieved");
        break;
    default:
        log_it(L_WARNING, "Unknown header type");
    }
    // Clean memory
    DAP_DEL_Z(a_stream->pkt_cache);
    if(l_is_clean_fragments) {
        DAP_DEL_Z(a_stream->buf_fragments);
        a_stream->buf_fragments_size_total = 0;
        a_stream->buf_fragments_size_filled = 0;
    }
    return true;
}

/**
 * @brief _detect_loose_packet
 * @param a_stream
 * @return
 */
static bool s_detect_loose_packet(dap_stream_t * a_stream) {
    dap_stream_ch_pkt_t *l_ch_pkt = a_stream->buf_fragments_size_filled
            ? (dap_stream_ch_pkt_t*)a_stream->buf_fragments
            : (dap_stream_ch_pkt_t*)a_stream->pkt_cache;

    long long l_count_lost_packets =
            l_ch_pkt->hdr.seq_id || a_stream->client_last_seq_id_packet
            ? (long long) l_ch_pkt->hdr.seq_id - (long long) (a_stream->client_last_seq_id_packet + 1)
            : 0;

    if (l_count_lost_packets) {
        log_it(L_WARNING, l_count_lost_packets > 0
               ? "Packet loss detected. Current seq_id: %"DAP_UINT64_FORMAT_U", last seq_id: %"DAP_UINT64_FORMAT_U
               : "Packet replay detected, seq_id: %"DAP_UINT64_FORMAT_U, l_ch_pkt->hdr.seq_id, a_stream->client_last_seq_id_packet);
    }
    debug_if(s_debug, L_DEBUG, "Current seq_id: %"DAP_UINT64_FORMAT_U", last: %"DAP_UINT64_FORMAT_U,
                                l_ch_pkt->hdr.seq_id, a_stream->client_last_seq_id_packet);
    a_stream->client_last_seq_id_packet = l_ch_pkt->hdr.seq_id;
    return l_count_lost_packets < 0;
}

/**
 * @brief s_callback_keepalive
 * @param a_arg
 * @return
 */
static bool s_callback_keepalive(void *a_arg, bool a_server_side)
{
    if (!a_arg)
        return false;
    dap_events_socket_uuid_t * l_es_uuid = (dap_events_socket_uuid_t*) a_arg;
    dap_worker_t * l_worker = dap_events_get_current_worker(dap_events_get_default());
    dap_events_socket_t * l_es = dap_worker_esocket_find_uuid(l_worker, *l_es_uuid);
    if(l_es) {
        dap_stream_t *l_stream = NULL;
        if (a_server_side) {
            if (l_es->type == DESCRIPTOR_TYPE_SOCKET_UDP)
                l_stream = DAP_STREAM(l_es);
            else {
                dap_http_client_t *l_http_client = DAP_HTTP_CLIENT(l_es);
                assert(l_http_client);
                l_stream = DAP_STREAM(l_http_client);
            }
        } else {
            dap_client_pvt_t *l_client_pvt = DAP_ESOCKET_CLIENT_PVT(l_es);
            assert(l_client_pvt);
            l_stream = l_client_pvt->stream;
        }
        assert(l_stream);
        if (l_stream->is_active) {
            l_stream->is_active = false;
            return true;
        }
        if(s_debug)
            log_it(L_DEBUG,"Keepalive for sock fd %"DAP_FORMAT_SOCKET" uuid 0x%016"DAP_UINT64_FORMAT_x, l_es->socket, *l_es_uuid);
        dap_stream_pkt_hdr_t l_pkt = {};
        l_pkt.type = STREAM_PKT_TYPE_KEEPALIVE;
        memcpy(l_pkt.sig, c_dap_stream_sig, sizeof(l_pkt.sig));
        dap_events_socket_write_unsafe( l_es, &l_pkt, sizeof(l_pkt));
        return true;
    }else{
        if(s_debug)
            log_it(L_INFO,"Keepalive for sock uuid %016"DAP_UINT64_FORMAT_x" removed", *l_es_uuid);
        DAP_DELETE(l_es_uuid);
        return false; // Socket is removed from worker
    }
}

static bool s_callback_client_keepalive(void *a_arg)
{
    return s_callback_keepalive(a_arg, false);
}

static bool s_callback_server_keepalive(void *a_arg)
{
    return s_callback_keepalive(a_arg, true);
}
