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
#define HEADER_WITH_SIZE_FIELD 12  //This count of bytes enough for allocate memory for stream packet

static void s_stream_proc_pkt_in(dap_stream_t * a_stream);

// Callbacks for HTTP client
static void s_http_client_headers_read(dap_http_client_t * a_http_client, void * a_arg); // Prepare stream when all headers are read

static void s_http_client_headers_write(dap_http_client_t * a_http_client, void * a_arg); // Output headers
static void s_http_client_data_write(dap_http_client_t * a_http_client, void * a_arg); // Write the data
static void s_http_client_data_read(dap_http_client_t * a_http_client, void * a_arg); // Read the data

static void s_esocket_callback_worker_assign(dap_events_socket_t * a_esocket, dap_worker_t * a_worker);
static void s_esocket_callback_worker_unassign(dap_events_socket_t * a_esocket, dap_worker_t * a_worker);
static void s_client_callback_worker_assign(dap_events_socket_t * a_esocket, dap_worker_t * a_worker);
static void s_client_callback_worker_unassign(dap_events_socket_t * a_esocket, dap_worker_t * a_worker);

static void s_esocket_data_read(dap_events_socket_t* a_esocket, void * a_arg);
static void s_esocket_write(dap_events_socket_t* a_esocket, void * a_arg);
static void s_esocket_callback_delete(dap_events_socket_t* a_esocket, void * a_arg);
static void s_udp_esocket_new(dap_events_socket_t* a_esocket,void * a_arg);

// Internal functions
static dap_stream_t * s_stream_new(dap_http_client_t * a_http_client); // Create new stream
static void s_http_client_new(dap_http_client_t * a_esocket, void * a_arg);
static void s_http_client_delete(dap_http_client_t * a_esocket, void * a_arg);

static bool s_callback_server_keepalive(void *a_arg);
static bool s_callback_client_keepalive(void *a_arg);

static bool s_dump_packet_headers = false;
static bool s_debug = false;

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
    dap_stream_t * ret=(dap_stream_t*) calloc(1,sizeof(dap_stream_t));

    ret->esocket = a_esocket;
    ret->buf_defrag_size = 0;

    a_esocket->_inheritor = ret;

    log_it(L_NOTICE,"New stream instance udp");
    return ret;
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
dap_stream_t * s_stream_new(dap_http_client_t * a_http_client)
{
    dap_stream_t *l_ret= DAP_NEW_Z(dap_stream_t);

    l_ret->esocket = a_http_client->esocket;
    l_ret->stream_worker = (dap_stream_worker_t *)a_http_client->esocket->worker->_inheritor;
    l_ret->conn_http=a_http_client;
    l_ret->buf_defrag_size = 0;
    l_ret->seq_id = 0;
    l_ret->client_last_seq_id_packet = (size_t)-1;
    // Start server keep-alive timer
    dap_events_socket_uuid_t *l_es_uuid = DAP_NEW_Z(dap_events_socket_uuid_t);
    *l_es_uuid = l_ret->esocket->uuid;
    l_ret->keepalive_timer = dap_timerfd_start_on_worker(l_ret->esocket->worker,
                                                         STREAM_KEEPALIVE_TIMEOUT * 1000,
                                                         (dap_timerfd_callback_t)s_callback_server_keepalive,
                                                         l_es_uuid);
    l_ret->esocket->callbacks.worker_assign_callback = s_esocket_callback_worker_assign;
    l_ret->esocket->callbacks.worker_unassign_callback = s_esocket_callback_worker_unassign;
    a_http_client->_inheritor = l_ret;
    log_it(L_NOTICE,"New stream instance");
    return l_ret;
}


/**
 * @brief dap_stream_new_es
 * @param a_es
 * @return
 */
dap_stream_t* dap_stream_new_es_client(dap_events_socket_t * a_esocket)
{
    dap_stream_t *l_ret = DAP_NEW_Z(dap_stream_t);
    l_ret->esocket = a_esocket;
    l_ret->esocket_uuid = a_esocket->uuid;
    l_ret->buf_defrag_size=0;
    l_ret->is_client_to_uplink = true;
    l_ret->esocket->callbacks.worker_assign_callback = s_client_callback_worker_assign;
    l_ret->esocket->callbacks.worker_unassign_callback = s_client_callback_worker_unassign;
    return l_ret;
}


/**
 * @brief dap_stream_delete
 * @param a_stream
 */
void dap_stream_delete(dap_stream_t *a_stream)
{
    if(a_stream == NULL) {
        log_it(L_ERROR,"stream delete NULL instance");
        return;
    }

    while (a_stream->channel_count) {
        dap_stream_ch_delete(a_stream->channel[a_stream->channel_count - 1]);
    }

    if(a_stream->session)
        dap_stream_session_close_mt(a_stream->session->id); // TODO make stream close after timeout, not momentaly
    a_stream->session = NULL;
    a_stream->esocket = NULL;
    DAP_DELETE(a_stream);
    log_it(L_NOTICE,"Stream connection is over");
}

/**
 * @brief stream_dap_delete Delete callback for UDP client
 * @param a_esocket DAP client instance
 * @param arg Not used
 */
static void s_esocket_callback_delete(dap_events_socket_t* a_esocket, void * a_arg)
{
    UNUSED(a_arg);
    assert (a_esocket);

    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT(a_esocket);
    dap_stream_t *l_stream = DAP_STREAM(l_http_client);
    l_http_client->_inheritor = NULL; // To prevent double free
    dap_stream_delete(l_stream);
}

/**
 * @brief stream_header_read Read headers callback for HTTP
 * @param a_http_client HTTP client structure
 * @param a_arg Not used
 */
void s_http_client_headers_read(dap_http_client_t * a_http_client, void * a_arg)
{
    (void) a_arg;

   // char * raw=0;
   // int raw_size;
    unsigned int id=0;

    //log_it(L_DEBUG,"Prepare data stream");
    if(a_http_client->in_query_string[0]){
        log_it(L_INFO,"Query string [%s]",a_http_client->in_query_string);
//        if(sscanf(cl_ht->in_query_string,"fj913htmdgaq-d9hf=%u",&id)==1){
        if(sscanf(a_http_client->in_query_string,"session_id=%u",&id) == 1 ||
                sscanf(a_http_client->in_query_string,"fj913htmdgaq-d9hf=%u",&id) == 1) {
            dap_stream_session_t * ss=NULL;
            ss=dap_stream_session_id_mt(id);
            if(ss==NULL){
                log_it(L_ERROR,"No session id %u was found",id);
                a_http_client->reply_status_code=404;
                strcpy(a_http_client->reply_reason_phrase,"Not found");
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
                        //sid->channel[i]->ready_to_write = true;
                    }

                    a_http_client->reply_status_code=200;
                    strcpy(a_http_client->reply_reason_phrase,"OK");
                    stream_states_update(sid);
                    a_http_client->state_read=DAP_HTTP_CLIENT_STATE_DATA;
                    a_http_client->state_write=DAP_HTTP_CLIENT_STATE_START;
                    dap_events_socket_set_readable_unsafe(a_http_client->esocket,true);
                    dap_events_socket_set_writable_unsafe(a_http_client->esocket,true); // Dirty hack, because previous function shouldn't
                    //                                                                    // set write flag off but it does!
                }else{
                    log_it(L_ERROR,"Can't open session id %u",id);
                    a_http_client->reply_status_code=404;
                    strcpy(a_http_client->reply_reason_phrase,"Not found");
                }
            }
        }
    }else{
        log_it(L_ERROR,"No query string");
    }
}

/**
 * @brief s_http_client_headers_write Prepare headers for output. Creates stream structure
 * @param sh HTTP client instance
 * @param arg Not used
 */
static void s_http_client_headers_write(dap_http_client_t * a_http_client, void *a_arg)
{
    (void) a_arg;
    //log_it(L_DEBUG,"s_http_client_headers_write()");
    if(a_http_client->reply_status_code==200){
        dap_stream_t *l_stream=DAP_STREAM(a_http_client);

        dap_http_out_header_add(a_http_client,"Content-Type","application/octet-stream");
        dap_http_out_header_add(a_http_client,"Connection","keep-alive");
        dap_http_out_header_add(a_http_client,"Cache-Control","no-cache");

        if(l_stream->stream_size>0)
            dap_http_out_header_add_f(a_http_client,"Content-Length","%u", (unsigned int) l_stream->stream_size );

        a_http_client->state_read=DAP_HTTP_CLIENT_STATE_DATA;
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
    dap_client_pvt_t *l_client_pvt = ESOCKET_CLIENT_PVT(a_esocket);
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
    dap_client_pvt_t *l_client_pvt = ESOCKET_CLIENT_PVT(a_esocket);
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

    if (s_dump_packet_headers ) {
        log_it(L_DEBUG,"dap_stream_data_read: ready_to_write=%s, client->buf_in_size=%zu" ,
               (a_client->flags & DAP_SOCK_READY_TO_WRITE)?"true":"false", a_client->buf_in_size );
    }
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
    if (s_dump_packet_headers ) {
        log_it(L_DEBUG,"dap_stream_data_write: ready_to_write=%s client->buf_out_size=%zu" ,
               l_ready_to_write?"true":"false", a_esocket->buf_out_size );
    }
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
 * @brief s_http_client_new
 * @param a_http_client
 * @param arg
 */
static void s_http_client_new(dap_http_client_t * a_http_client, void * arg)
{

}


/**
 * @brief stream_delete Delete stream and free its resources
 * @param sid Stream id
 */
static void s_http_client_delete(dap_http_client_t * a_http_client, void * arg)
{
    s_esocket_callback_delete(a_http_client->esocket,arg);
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
    bool found_sig=false;
    dap_stream_pkt_t * pkt=NULL;

    if (!a_stream || !a_stream->esocket)
        return 0;

    char *l_buf_in = (char*)a_stream->esocket->buf_in ;
    size_t buf_in_size = a_stream->esocket->buf_in_size ;
    byte_t *proc_data = (byte_t *)l_buf_in;//a_stream->conn->buf_in;
    bool proc_data_defrag=false; // We are or not in defrag buffer
    size_t read_bytes_to=0;
    size_t bytes_left_to_read = buf_in_size;//a_stream->conn->buf_in_size;
    // Process prebuffered packets or glue defragmented data with the current input

    pkt = a_stream->pkt_buf_in;

    if ( pkt ) { // Packet signature detected
        if(a_stream->pkt_buf_in_data_size < sizeof(dap_stream_pkt_hdr_t))
        {
            //At first read header
            dap_stream_pkt_t* check_pkt = dap_stream_pkt_detect( proc_data , sizeof(dap_stream_pkt_hdr_t) - a_stream->pkt_buf_in_data_size);
            if(check_pkt){
                // Got duplication of packet header several times
                log_it(L_DEBUG, "Drop incorrect header part");
                a_stream->pkt_buf_in = NULL;
                a_stream->pkt_buf_in_data_size=0;
                return 0;
            }
            if(sizeof(dap_stream_pkt_hdr_t) - a_stream->pkt_buf_in_data_size > bytes_left_to_read)
                read_bytes_to = bytes_left_to_read;
            else
                read_bytes_to = sizeof(dap_stream_pkt_hdr_t) - a_stream->pkt_buf_in_data_size;
            memcpy((uint8_t*)a_stream->pkt_buf_in+a_stream->pkt_buf_in_data_size,proc_data,read_bytes_to);
            bytes_left_to_read-=read_bytes_to;
            a_stream->pkt_buf_in_data_size += read_bytes_to;
            proc_data += read_bytes_to;
            read_bytes_to = 0;
        }

        if  ((pkt->hdr.size + sizeof(dap_stream_pkt_hdr_t) -a_stream->pkt_buf_in_data_size) < bytes_left_to_read ) { // Looks the all packet is present in buffer
            read_bytes_to=(a_stream->pkt_buf_in->hdr.size + sizeof(dap_stream_pkt_hdr_t) -a_stream->pkt_buf_in_data_size);
        }else{
            read_bytes_to=bytes_left_to_read;
        }
        if (a_stream->pkt_buf_in_data_size + read_bytes_to > a_stream->pkt_buf_in_size_expected) {
            a_stream->pkt_buf_in_size_expected = a_stream->pkt_buf_in_data_size + read_bytes_to;
            a_stream->pkt_buf_in = (dap_stream_pkt_t *)DAP_REALLOC(a_stream->pkt_buf_in, a_stream->pkt_buf_in_size_expected);
        }
        memcpy((uint8_t*)a_stream->pkt_buf_in+a_stream->pkt_buf_in_data_size,proc_data,read_bytes_to);
        a_stream->pkt_buf_in_data_size+=read_bytes_to;
        bytes_left_to_read-=read_bytes_to;
        //log_it(L_DEBUG, "Prefilled packet buffer on %u bytes", read_bytes_to);
        read_bytes_to=0;
        if(a_stream->pkt_buf_in_data_size>=(a_stream->pkt_buf_in->hdr.size + sizeof(dap_stream_pkt_hdr_t)) ){ // If we have all the packet in packet buffer
            if(a_stream->pkt_buf_in_data_size > a_stream->pkt_buf_in->hdr.size + sizeof(dap_stream_pkt_hdr_t)){ // If we have little more data then we need for packet buffer
                log_it(L_WARNING,"Prefilled packet buffer has %zu bytes more than we need, it's lost",a_stream->pkt_buf_in_data_size-a_stream->pkt_buf_in->hdr.size);
                DAP_DEL_Z(a_stream->pkt_buf_in);
                a_stream->pkt_buf_in_data_size = 0;
            }
            else{
                s_stream_proc_pkt_in(a_stream);
            }
        }
        proc_data = (uint8_t *)(l_buf_in + buf_in_size - bytes_left_to_read);//proc_data=(a_stream->conn->buf_in + a_stream->conn->buf_in_size - bytes_left_to_read);

    }else if( a_stream->buf_defrag_size>0){ // If smth is present in defrag buffer - we glue everything together in it
        if( bytes_left_to_read  > 0){ // If there is smth to process in input buffer
            read_bytes_to=bytes_left_to_read;
            if( (read_bytes_to + a_stream->buf_defrag_size) > sizeof(a_stream->buf_defrag)   ){
                //log_it(L_WARNING,"Defrag buffer is overfilled, drop that" );
                if(read_bytes_to>sizeof(a_stream->buf_defrag))
                    read_bytes_to=sizeof(a_stream->buf_defrag);
                a_stream->buf_defrag_size=0;
            }
            //log_it(L_DEBUG,"Glue together defrag %u bytes and current %u bytes", a_stream->buf_defrag_size, read_bytes_to);
            memcpy(a_stream->buf_defrag+a_stream->buf_defrag_size,proc_data,read_bytes_to );
            bytes_left_to_read=a_stream->buf_defrag_size+read_bytes_to; // Then we have to read em all
            read_bytes_to=0;
        }else{
            bytes_left_to_read=a_stream->buf_defrag_size;
            //log_it(L_DEBUG,"Nothing to glue with defrag buffer, going to process just that (%u bytes)", bytes_left_to_read);
        }
        //log_it(L_WARNING,"Switch to defrag buffer");
        proc_data=a_stream->buf_defrag;
        proc_data_defrag=true;
    }//else
     //   log_it(DEBUG,"No prefill or defrag buffer, process directly buf_in");
    // Now lets see how many packets we have in buffer now
    while ( (pkt = dap_stream_pkt_detect( proc_data , bytes_left_to_read)) ){
        if(pkt->hdr.size > STREAM_PKT_SIZE_MAX ){
            //log_it(L_ERROR, "stream_pkt_detect() Too big packet size %u",
            //       pkt->hdr.size);
            bytes_left_to_read=0;
            break;
        }

        size_t pkt_offset=( ((uint8_t*)pkt)- proc_data );
        bytes_left_to_read -= pkt_offset ;
        found_sig=true;

        //dap_stream_pkt_t *temp_pkt = dap_stream_pkt_detect( (uint8_t*)pkt + 1 ,pkt->hdr.size+sizeof(stream_pkt_hdr_t) );
        size_t l_pkt_size = pkt->hdr.size + sizeof(dap_stream_pkt_hdr_t);
        if(bytes_left_to_read >= sizeof (dap_stream_pkt_t)){
            if (bytes_left_to_read < l_pkt_size) { // Is all the packet in da buf?
                read_bytes_to=bytes_left_to_read;
            }else{
                read_bytes_to = l_pkt_size;
            }
        }

        //log_it(L_DEBUG, "Detected packet signature pkt->hdr.size=%u read_bytes_to=%u bytes_left_to_read=%u pkt_offset=%u"
        //      ,pkt->hdr.size, read_bytes_to, bytes_left_to_read,pkt_offset);
        if(read_bytes_to > HEADER_WITH_SIZE_FIELD){ // If we have size field, we can allocate memory
            a_stream->pkt_buf_in_size_expected = l_pkt_size;
            a_stream->pkt_buf_in = DAP_NEW_SIZE(struct dap_stream_pkt, l_pkt_size);
            if (read_bytes_to > l_pkt_size) {
                //log_it(L_WARNING,"For some strange reasons we have read_bytes_to=%u is bigger than expected pkt length(%u bytes). Dropped %u bytes",
                //       pkt->hdr.size+sizeof(stream_pkt_hdr_t),read_bytes_to- pkt->hdr.size+sizeof(stream_pkt_hdr_t));
                read_bytes_to = l_pkt_size;
            }
            if(read_bytes_to>bytes_left_to_read){
                //log_it(L_WARNING,"For some strange reasons we have read_bytes_to=%u is bigger that's left in input buffer (%u bytes). Dropped %u bytes",
                //       read_bytes_to,bytes_left_to_read);
                read_bytes_to=bytes_left_to_read;
            }
            memcpy(a_stream->pkt_buf_in,pkt,read_bytes_to);
            proc_data+=(read_bytes_to + pkt_offset);
            bytes_left_to_read-=read_bytes_to;
            a_stream->pkt_buf_in_data_size=(read_bytes_to);
            if(a_stream->pkt_buf_in_data_size==l_pkt_size){
            //    log_it(INFO,"All the packet is present in da buffer (hdr.size=%u read_bytes_to=%u buf_in_size=%u)"
            //           ,sid->pkt_buf_in->hdr.size,read_bytes_to,sid->conn->buf_in_size);
                s_stream_proc_pkt_in(a_stream);
            }else if(a_stream->pkt_buf_in_data_size>l_pkt_size){
                //log_it(L_WARNING,"Input: packet buffer has %u bytes more than we need, they're lost",a_stream->pkt_buf_in_data_size-pkt->hdr.size);
            }else{
                //log_it(L_DEBUG,"Input: Not all stream packet in input (hdr.size=%u read_bytes_to=%u)",a_stream->pkt_buf_in->hdr.size,read_bytes_to);
            }
        }else{
            break;
        }
    }
    /*if(!found_sig){
        log_it(L_DEBUG,"Input: Not found signature in the incomming data ( client->buf_in_size = %u   *ret = %u )",
               sh->client->buf_in_size, *ret);
    }*/
    if(bytes_left_to_read>0){
        if(proc_data_defrag){
            memmove(a_stream->buf_defrag, proc_data, bytes_left_to_read);
            a_stream->buf_defrag_size=bytes_left_to_read;
            //log_it(L_INFO,"Fragment of %u bytes shifted in the begining the defrag buffer",bytes_left_to_read);
        }else{
            memcpy(a_stream->buf_defrag, proc_data, bytes_left_to_read);
            a_stream->buf_defrag_size=bytes_left_to_read;
            //log_it(L_INFO,"Fragment of %u bytes stored in defrag buffer",bytes_left_to_read);
        }
    }else if(proc_data_defrag){
        a_stream->buf_defrag_size=0;
    }

    return buf_in_size;//a_stream->conn->buf_in_size;
}

/**
 * @brief stream_proc_pkt_in
 * @param sid
 */
static void s_stream_proc_pkt_in(dap_stream_t * a_stream)
{
    a_stream->is_active = true;
    dap_stream_pkt_t * l_pkt = a_stream->pkt_buf_in;
    size_t l_pkt_size = a_stream->pkt_buf_in_data_size;
    a_stream->pkt_buf_in=NULL;
    a_stream->pkt_buf_in_data_size=0;

    switch (l_pkt->hdr.type) {
    case STREAM_PKT_TYPE_DATA_PACKET: {
        dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_stream->pkt_cache;

        size_t l_dec_pkt_size = dap_stream_pkt_read_unsafe(a_stream, l_pkt, l_ch_pkt, sizeof(a_stream->pkt_cache));
        if (l_dec_pkt_size == 0) {
            log_it(L_WARNING, "Input: can't decode packet size=%zu",l_pkt_size);
            DAP_DELETE(l_pkt);
            return;
        }
        if (l_dec_pkt_size != l_ch_pkt->hdr.size + sizeof(l_ch_pkt->hdr)) {
            log_it(L_WARNING, "Input: decoded packet has bad size = %u, decoded size = %zu", l_ch_pkt->hdr.size, l_dec_pkt_size);
            DAP_DELETE(l_pkt);
            return;
        }

        s_detect_loose_packet(a_stream);

        // Find channel
        dap_stream_ch_t * l_ch = NULL;
        for(size_t i=0;i<a_stream->channel_count;i++){
            if(a_stream->channel[i]->proc){
                if(a_stream->channel[i]->proc->id == l_ch_pkt->hdr.id ){
                    l_ch=a_stream->channel[i];
                }
            }
        }

        if(l_ch){
            l_ch->stat.bytes_read+=l_ch_pkt->hdr.size;
            if(l_ch->proc && l_ch->proc->packet_in_callback){
                if ( s_dump_packet_headers ){
                    log_it(L_INFO,"Income channel packet: id='%c' size=%u type=0x%02X seq_id=0x%016"DAP_UINT64_FORMAT_X" enc_type=0x%02X",(char) l_ch_pkt->hdr.id,
                        l_ch_pkt->hdr.size, l_ch_pkt->hdr.type, l_ch_pkt->hdr.seq_id , l_ch_pkt->hdr.enc_type);
                }
                l_ch->proc->packet_in_callback(l_ch,l_ch_pkt);
            }
        } else{
            log_it(L_WARNING, "Input: unprocessed channel packet id '%c'",(char) l_ch_pkt->hdr.id );
        }
    } break;
    case STREAM_PKT_TYPE_SERVICE_PACKET: {
        stream_srv_pkt_t * srv_pkt = DAP_NEW(stream_srv_pkt_t);
        memcpy(srv_pkt, l_pkt->data,sizeof(stream_srv_pkt_t));
        uint32_t session_id = srv_pkt->session_id;
        check_session(session_id,a_stream->esocket);
        DAP_DELETE(srv_pkt);
    } break;
    case STREAM_PKT_TYPE_KEEPALIVE: {
        //log_it(L_DEBUG, "Keep alive check recieved");
        dap_stream_pkt_hdr_t l_ret_pkt = {};
        l_ret_pkt.type = STREAM_PKT_TYPE_ALIVE;
        memcpy(l_ret_pkt.sig, c_dap_stream_sig, sizeof(l_ret_pkt.sig));
        dap_events_socket_write_unsafe(a_stream->esocket, &l_ret_pkt, sizeof(l_ret_pkt));
    } break;
    case STREAM_PKT_TYPE_ALIVE:
        a_stream->is_active = false; // To prevent keep-alive concurrency
        //log_it(L_DEBUG, "Keep alive response recieved");
        break;
    default:
        log_it(L_WARNING, "Unknown header type");
    }

    DAP_DELETE(l_pkt);
}

/**
 * @brief _detect_loose_packet
 * @param a_stream
 * @return
 */
static bool s_detect_loose_packet(dap_stream_t * a_stream)
{
    dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_stream->pkt_cache;

    int l_count_loosed_packets = l_ch_pkt->hdr.seq_id - (a_stream->client_last_seq_id_packet + 1);
    if(l_count_loosed_packets > 0)
    {
        log_it(L_WARNING, "Detected loosed %d packets. "
                          "Last read seq_id packet: %zu Current: %"DAP_UINT64_FORMAT_U, l_count_loosed_packets,
               a_stream->client_last_seq_id_packet, l_ch_pkt->hdr.seq_id);
    } else if(l_count_loosed_packets < 0) {
        if(a_stream->client_last_seq_id_packet != 0 && l_ch_pkt->hdr.seq_id != 0) {
        log_it(L_WARNING, "Something wrong. count_loosed packets %d can't less than zero. "
                          "Last read seq_id packet: %zu Current: %"DAP_UINT64_FORMAT_U, l_count_loosed_packets,
               a_stream->client_last_seq_id_packet, l_ch_pkt->hdr.seq_id);
        } // else client don't support seqid functionality
    }
//    log_it(L_DEBUG, "Packet seq id: %d", ch_pkt->hdr.seq_id);
//    log_it(L_DEBUG, "Last seq id: %d", sid->last_seq_id_packet);
    a_stream->client_last_seq_id_packet = l_ch_pkt->hdr.seq_id;

    return false;
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
    if (l_es) {
        dap_stream_t *l_stream = NULL;
        if (a_server_side) {
            dap_http_client_t *l_http_client = DAP_HTTP_CLIENT(l_es);
            assert(l_http_client);
            l_stream = DAP_STREAM(l_http_client);
        } else {
            dap_client_pvt_t *l_client_pvt = ESOCKET_CLIENT_PVT(l_es);
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
