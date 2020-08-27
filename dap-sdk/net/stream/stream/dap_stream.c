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

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include "dap_common.h"

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
#include "dap_udp_server.h"
#include "dap_stream_worker.h"

#define LOG_TAG "dap_stream"
#define HEADER_WITH_SIZE_FIELD 12  //This count of bytes enough for allocate memory for stream packet

void stream_proc_pkt_in(dap_stream_t * sid);

// Callbacks for HTTP client
void stream_headers_read(dap_http_client_t * sh, void * arg); // Prepare stream when all headers are read

void s_http_client_headers_write(dap_http_client_t * sh, void * arg); // Output headers
void s_http_client_data_write(dap_http_client_t * sh, void * arg); // Write the data
void stream_data_read(dap_http_client_t * sh, void * arg); // Read the data

void s_http_client_data_read(dap_events_socket_t* sh, void * arg);
void stream_dap_data_write(dap_events_socket_t* sh, void * arg);
void s_es_callback_delete(dap_events_socket_t* sh, void * arg);
void stream_dap_udp_new(dap_events_socket_t* sh,void * arg);

// Internal functions
dap_stream_t * stream_new(dap_http_client_t * a_sh); // Create new stream
void stream_delete(dap_http_client_t * sh, void * arg);

//struct ev_loop *keepalive_loop;
pthread_t keepalive_thread;

static dap_stream_t  *s_stream_keepalive_list = NULL;
static pthread_mutex_t s_mutex_keepalive_list;

static void start_keepalive( dap_stream_t *sid );
static void keepalive_cb( void );

static bool s_keep_alive_loop_quit_signal = false;
static bool s_dump_packet_headers = false;

bool dap_stream_get_dump_packet_headers(){ return  s_dump_packet_headers; }

static struct timespec keepalive_loop_sleep = { 0, STREAM_KEEPALIVE_TIMEOUT * 1000 * 1000  };

// Start keepalive stream
static void *stream_loop( void *arg )
{
    UNUSED(arg);
//    keepalive_loop = ev_loop_new(0);
//    ev_loop(keepalive_loop, 0);
  do {

    #ifndef _WIN32
      //nanosleep( &keepalive_loop_sleep, NULL );
      sleep( STREAM_KEEPALIVE_TIMEOUT );
    #else
      Sleep( STREAM_KEEPALIVE_TIMEOUT * 1000 );
    #endif

    keepalive_cb( );

  } while ( !s_keep_alive_loop_quit_signal );

  return NULL;
}

/**
 * @brief stream_init Init stream module
 * @return  0 if ok others if not
 */
int dap_stream_init( bool a_dump_packet_headers)
{
    if( dap_stream_ch_init() != 0 ){
        log_it(L_CRITICAL, "Can't init channel types submodule");
        return -1;
    }
    if( dap_stream_worker_init() != 0 ){
        log_it(L_CRITICAL, "Can't init stream worker extention submodule");
        return -2;
    }

    s_dump_packet_headers = a_dump_packet_headers;
    s_keep_alive_loop_quit_signal = false;
    pthread_mutex_init( &s_mutex_keepalive_list, NULL );
    //pthread_create( &keepalive_thread, NULL, stream_loop, NULL );

    log_it(L_NOTICE,"Init streaming module");

    return 0;
}

/**
 * @brief stream_media_deinit Deinint Stream module
 */
void dap_stream_deinit()
{
    s_keep_alive_loop_quit_signal = true;
    pthread_join( keepalive_thread, NULL );

    pthread_mutex_destroy( &s_mutex_keepalive_list );

    dap_stream_ch_deinit( );
}

/**
 * @brief stream_add_proc_http Add URL processor callback for streaming
 * @param sh HTTP server instance
 * @param url URL
 */
void dap_stream_add_proc_http(struct dap_http * sh, const char * url)
{
    dap_http_add_proc(sh,url,NULL,NULL,stream_delete,stream_headers_read,s_http_client_headers_write,stream_data_read,s_http_client_data_write,NULL);
}

/**
 * @brief stream_add_proc_udp Add processor callback for streaming
 * @param sh UDP server instance
 */
void dap_stream_add_proc_udp(dap_udp_server_t * sh)
{
    dap_server_t* server =  sh->dap_server;
    server->client_callbacks.read_callback = s_http_client_data_read;
    server->client_callbacks.write_callback = stream_dap_data_write;
    server->client_callbacks.delete_callback = s_es_callback_delete;
    server->client_callbacks.new_callback = stream_dap_udp_new;
}

/**
 * @brief stream_states_update
 * @param sid stream instance
 */
void stream_states_update(struct dap_stream *sid)
{
    if(sid->conn_http)
        sid->conn_http->state_write=DAP_HTTP_CLIENT_STATE_START;
    size_t i;
    bool ready_to_write=false;
    for(i=0;i<sid->channel_count; i++)
        ready_to_write|=sid->channel[i]->ready_to_write;
    dap_events_socket_set_writable_unsafe(sid->esocket,ready_to_write);
    if(sid->conn_http)
        sid->conn_http->out_content_ready=true;
}

/**
 * @brief stream_header_read Read headers callback for HTTP
 * @param cl_ht HTTP client structure
 * @param arg Not used
 */
void stream_headers_read(dap_http_client_t * cl_ht, void * arg)
{
    (void) arg;

   // char * raw=0;
   // int raw_size;
    unsigned int id=0;

//    log_it(L_DEBUG,"Prepare data stream");
    if(cl_ht->in_query_string[0]){
        log_it(L_INFO,"Query string [%s]",cl_ht->in_query_string);
//        if(sscanf(cl_ht->in_query_string,"fj913htmdgaq-d9hf=%u",&id)==1){
        if(sscanf(cl_ht->in_query_string,"session_id=%u",&id) == 1 ||
                sscanf(cl_ht->in_query_string,"fj913htmdgaq-d9hf=%u",&id) == 1) {
            dap_stream_session_t * ss=NULL;
            ss=dap_stream_session_id_mt(id);
            if(ss==NULL){
                log_it(L_ERROR,"No session id %u was found",id);
                cl_ht->reply_status_code=404;
                strcpy(cl_ht->reply_reason_phrase,"Not found");
            }else{
                log_it(L_INFO,"Session id %u was found with channels = %s",id,ss->active_channels);
                if(dap_stream_session_open(ss)==0){ // Create new stream
                    dap_stream_t * sid = stream_new(cl_ht);
                    sid->session=ss;
                    dap_http_header_t *header = dap_http_header_find(cl_ht->in_headers, "Service-Key");
                    if (header)
                        ss->service_key = strdup(header->value);
                    size_t count_channels = strlen(ss->active_channels);
                    for(size_t i = 0; i < count_channels; i++) {
                        dap_stream_ch_new(sid, ss->active_channels[i]);
                        //sid->channel[i]->ready_to_write = true;
                    }

                    cl_ht->reply_status_code=200;
                    strcpy(cl_ht->reply_reason_phrase,"OK");
                    cl_ht->state_read=DAP_HTTP_CLIENT_STATE_DATA;
                    dap_events_socket_set_readable_unsafe(cl_ht->esocket,true);

                    stream_states_update(sid);
                }else{
                    log_it(L_ERROR,"Can't open session id %u",id);
                    cl_ht->reply_status_code=404;
                    strcpy(cl_ht->reply_reason_phrase,"Not found");
                }
            }
        }
    }else{
        log_it(L_ERROR,"No query string");
    }
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
void check_session( unsigned int a_id, dap_events_socket_t *a_client_remote )
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

    if ( DAP_STREAM(a_client_remote) == NULL )
        l_stream = stream_new_udp( a_client_remote );
    else
        l_stream = DAP_STREAM( a_client_remote );

    l_stream->session = l_session;

    if ( l_session->create_empty )
        log_it( L_INFO, "Session created empty" );

    log_it( L_INFO, "Opened stream session technical and data channels" );

    size_t count_channels = strlen(l_session->active_channels);
    for (size_t i =0; i<sizeof (l_session->active_channels); i++ )
        if ( l_session->active_channels[i])
            dap_stream_ch_new( l_stream, l_session->active_channels[i] );

    stream_states_update( l_stream );

    dap_events_socket_set_readable_unsafe( a_client_remote, true );

    start_keepalive( l_stream );
}

/**
 * @brief stream_new Create new stream instance for HTTP client
 * @return New stream_t instance
 */
dap_stream_t * stream_new(dap_http_client_t * a_sh)
{
    dap_stream_t * ret= DAP_NEW_Z(dap_stream_t);

    pthread_rwlock_init( &ret->rwlock, NULL);
    ret->esocket = a_sh->esocket;
    ret->conn_http=a_sh;
    ret->buf_defrag_size = 0;
    ret->seq_id = 0;
    ret->client_last_seq_id_packet = (size_t)-1;

    ret->esocket->_inheritor=ret;

    log_it(L_NOTICE,"New stream instance");
    return ret;
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
    pthread_mutex_lock(&s_mutex_keepalive_list);
    if(s_stream_keepalive_list){
        DL_DELETE(s_stream_keepalive_list, a_stream);
    }
    a_stream->esocket = NULL;
    pthread_mutex_unlock(&s_mutex_keepalive_list);

    while (a_stream->channel_count) {
        dap_stream_ch_delete(a_stream->channel[a_stream->channel_count - 1]);
    }

    pthread_rwlock_wrlock(&a_stream->rwlock);
    if(a_stream->session)
        dap_stream_session_close_mt(a_stream->session->id); // TODO make stream close after timeout, not momentaly
    a_stream->session = NULL;
    pthread_rwlock_unlock(&a_stream->rwlock);
    pthread_rwlock_destroy(&a_stream->rwlock);
    DAP_DELETE(a_stream);
    log_it(L_NOTICE,"Stream connection is over");
}

/**
 * @brief stream_dap_delete Delete callback for UDP client
 * @param sh DAP client instance
 * @param arg Not used
 */
void s_es_callback_delete(dap_events_socket_t* sh, void * arg)
{
    UNUSED(arg);
    if (!sh)
        return;
    dap_stream_t *l_stream = DAP_STREAM(sh);
    dap_stream_delete(l_stream);
}


/**
 * @brief dap_stream_new_es
 * @param a_es
 * @return
 */
dap_stream_t* dap_stream_new_es(dap_events_socket_t * a_es)
{
    dap_stream_t * ret= DAP_NEW_Z(dap_stream_t);
    pthread_rwlock_init( &ret->rwlock, NULL);
    ret->esocket = a_es;
    ret->buf_defrag_size=0;
    ret->is_client_to_uplink = true;

    log_it(L_NOTICE,"New stream with events socket instance for %s",a_es->hostaddr);
    return ret;
}

/**
 * @brief s_http_client_headers_write Prepare headers for output. Creates stream structure
 * @param sh HTTP client instance
 * @param arg Not used
 */
void s_http_client_headers_write(dap_http_client_t * sh, void *arg)
{
    (void) arg;

    if(sh->reply_status_code==200){
        dap_stream_t *sid=DAP_STREAM(sh->esocket);

        dap_http_out_header_add(sh,"Content-Type","application/octet-stream");
        dap_http_out_header_add(sh,"Connnection","keep-alive");
        dap_http_out_header_add(sh,"Cache-Control","no-cache");

        if(sid->stream_size>0)
            dap_http_out_header_add_f(sh,"Content-Length","%u", (unsigned int) sid->stream_size );

        sh->state_read=DAP_HTTP_CLIENT_STATE_DATA;
        dap_events_socket_set_readable_unsafe(sh->esocket,true);
    }
}

/**
 Function for keepalive loop
static void keepalive_cb (EV_P_ ev_timer *w, int revents)
{
    struct dap_stream *sid = w->data;
    if(sid->keepalive_passed < STREAM_KEEPALIVE_PASSES)
    {
        dap_stream_send_keepalive(sid);
        sid->keepalive_passed+=1;
    }
    else{
        log_it(L_INFO, "Client disconnected");
        ev_timer_stop (keepalive_loop, &sid->keepalive_watcher);
        void * arg;
        stream_dap_delete(sid->conn,arg);
    }
}
**/

static void keepalive_cb( void )
{
  dap_stream_t  *l_stream, *tmp;
  return;
  pthread_mutex_lock( &s_mutex_keepalive_list );
  DL_FOREACH_SAFE( s_stream_keepalive_list, l_stream, tmp ) {
    if ( l_stream->keepalive_passed < STREAM_KEEPALIVE_PASSES ) {
      dap_stream_send_keepalive( l_stream );
      l_stream->keepalive_passed += 1;
    }
    else {
      log_it( L_INFO, "Client disconnected" );
      DL_DELETE( s_stream_keepalive_list, l_stream );
      s_es_callback_delete( l_stream->esocket, NULL );
    }
  }

  pthread_mutex_unlock( &s_mutex_keepalive_list );
}




/**
 * @brief start_keepalive Start keepalive signals exchange for stream
 * @param sid Stream instance
 */
void start_keepalive( dap_stream_t *sid ) {
    return;
//    keepalive_loop = EV_DEFAULT;
//    sid->keepalive_watcher.data = sid;
//    ev_timer_init (&sid->keepalive_watcher, keepalive_cb, STREAM_KEEPALIVE_TIMEOUT, STREAM_KEEPALIVE_TIMEOUT);
//    ev_timer_start (keepalive_loop, &sid->keepalive_watcher);
  pthread_mutex_lock( &s_mutex_keepalive_list );
  DL_APPEND( s_stream_keepalive_list, sid );
  pthread_mutex_unlock( &s_mutex_keepalive_list );
}

/**
 * @brief stream_data_write HTTP data write callback
 * @param sh HTTP client instance
 * @param arg Not used
 */
void s_http_client_data_write(dap_http_client_t * sh, void * arg)
{
    (void) arg;

    if(sh->reply_status_code==200){
        stream_dap_data_write(sh->esocket,arg);
    }else{
        log_it(L_WARNING, "Wrong request, reply status code is %u",sh->reply_status_code);
    }
}

/**
 * @brief s_data_read
 * @param sh
 * @param arg
 */
void s_http_client_data_read(dap_events_socket_t* a_client, void * arg)
{
    dap_stream_t * l_stream =DAP_STREAM(a_client);
    int * ret = (int *) arg;

    if (s_dump_packet_headers ) {
        log_it(L_DEBUG,"dap_stream_data_read: ready_to_write=%s, client->buf_in_size=%u" ,
               (a_client->flags & DAP_SOCK_READY_TO_WRITE)?"true":"false", a_client->buf_in_size );
    }
    *ret = dap_stream_data_proc_read( l_stream);
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

    char *buf_in = (a_stream->esocket) ? (char*)a_stream->esocket->buf_in : (char*)a_stream->esocket->buf_in;
    size_t buf_in_size = (a_stream->esocket) ? a_stream->esocket->buf_in_size : a_stream->esocket->buf_in_size;
    uint8_t *proc_data = (uint8_t *)buf_in;//a_stream->conn->buf_in;
    bool proc_data_defrag=false; // We are or not in defrag buffer
    size_t read_bytes_to=0;
    size_t bytes_left_to_read = buf_in_size;//a_stream->conn->buf_in_size;
    // Process prebuffered packets or glue defragmented data with the current input

    pkt = a_stream->pkt_buf_in;

    if ( pkt ) { // Packet signature detected
        if(a_stream->pkt_buf_in_data_size < sizeof(stream_pkt_hdr_t))
        {
            //At first read header
            dap_stream_pkt_t* check_pkt = dap_stream_pkt_detect( proc_data , sizeof(stream_pkt_hdr_t) - a_stream->pkt_buf_in_data_size);
            if(check_pkt){
                // Got duplication of packet header several times
                //log_it(L_DEBUG, "Drop incorrect header part");
                a_stream->pkt_buf_in = NULL;
                a_stream->pkt_buf_in_data_size=0;
                return 0;
            }
            if(sizeof(stream_pkt_hdr_t) - a_stream->pkt_buf_in_data_size > bytes_left_to_read)
                read_bytes_to = bytes_left_to_read;
            else
                read_bytes_to = sizeof(stream_pkt_hdr_t) - a_stream->pkt_buf_in_data_size;
            memcpy((uint8_t*)a_stream->pkt_buf_in+a_stream->pkt_buf_in_data_size,proc_data,read_bytes_to);
            bytes_left_to_read-=read_bytes_to;
            a_stream->pkt_buf_in_data_size += read_bytes_to;
            proc_data += read_bytes_to;
            read_bytes_to = 0;
        }

        if  ((pkt->hdr.size + sizeof(stream_pkt_hdr_t) -a_stream->pkt_buf_in_data_size) < bytes_left_to_read ) { // Looks the all packet is present in buffer
            read_bytes_to=(a_stream->pkt_buf_in->hdr.size + sizeof(stream_pkt_hdr_t) -a_stream->pkt_buf_in_data_size);
        }else{
            read_bytes_to=bytes_left_to_read;
        }
        memcpy((uint8_t*)a_stream->pkt_buf_in+a_stream->pkt_buf_in_data_size,proc_data,read_bytes_to);
        a_stream->pkt_buf_in_data_size+=read_bytes_to;
        bytes_left_to_read-=read_bytes_to;
        //log_it(L_DEBUG, "Prefilled packet buffer on %u bytes", read_bytes_to);
        read_bytes_to=0;
        if(a_stream->pkt_buf_in_data_size>=(a_stream->pkt_buf_in->hdr.size + sizeof(stream_pkt_hdr_t)) ){ // If we have all the packet in packet buffer
            if(a_stream->pkt_buf_in_data_size > a_stream->pkt_buf_in->hdr.size + sizeof(stream_pkt_hdr_t)){ // If we have little more data then we need for packet buffer
                //log_it(L_WARNING,"Prefilled packet buffer has %u bytes more than we need, they're lost",a_stream->pkt_buf_in_data_size-a_stream->pkt_buf_in->hdr.size);
                a_stream->pkt_buf_in_data_size = 0;
                a_stream->pkt_buf_in = NULL;
            }
            else{
                stream_proc_pkt_in(a_stream);
            }
        }
        proc_data = (uint8_t *)(buf_in + buf_in_size - bytes_left_to_read);//proc_data=(a_stream->conn->buf_in + a_stream->conn->buf_in_size - bytes_left_to_read);

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

        dap_stream_pkt_t *temp_pkt = dap_stream_pkt_detect( (uint8_t*)pkt + 1 ,pkt->hdr.size+sizeof(stream_pkt_hdr_t) );

        if(bytes_left_to_read  <(pkt->hdr.size+sizeof(stream_pkt_hdr_t) )){ // Is all the packet in da buf?
            read_bytes_to=bytes_left_to_read;
        }else{
            read_bytes_to=pkt->hdr.size+sizeof(stream_pkt_hdr_t);
        }

        //log_it(L_DEBUG, "Detected packet signature pkt->hdr.size=%u read_bytes_to=%u bytes_left_to_read=%u pkt_offset=%u"
        //      ,pkt->hdr.size, read_bytes_to, bytes_left_to_read,pkt_offset);
        if(read_bytes_to > HEADER_WITH_SIZE_FIELD){ // If we have size field, we can allocate memory
            a_stream->pkt_buf_in_size_expected =( pkt->hdr.size+sizeof(stream_pkt_hdr_t));
            size_t pkt_buf_in_size_expected=a_stream->pkt_buf_in_size_expected;
            a_stream->pkt_buf_in=(dap_stream_pkt_t *) malloc(pkt_buf_in_size_expected);
            if(read_bytes_to>(pkt->hdr.size+sizeof(stream_pkt_hdr_t) )){
                //log_it(L_WARNING,"For some strange reasons we have read_bytes_to=%u is bigger than expected pkt length(%u bytes). Dropped %u bytes",
                //       pkt->hdr.size+sizeof(stream_pkt_hdr_t),read_bytes_to- pkt->hdr.size+sizeof(stream_pkt_hdr_t));
                read_bytes_to=(pkt->hdr.size+sizeof(stream_pkt_hdr_t));
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
            if(a_stream->pkt_buf_in_data_size==(pkt->hdr.size + sizeof(stream_pkt_hdr_t))){
            //    log_it(INFO,"All the packet is present in da buffer (hdr.size=%u read_bytes_to=%u buf_in_size=%u)"
            //           ,sid->pkt_buf_in->hdr.size,read_bytes_to,sid->conn->buf_in_size);
                stream_proc_pkt_in(a_stream);
            }else if(a_stream->pkt_buf_in_data_size>pkt->hdr.size + sizeof(stream_pkt_hdr_t)){
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
 * @brief stream_dap_data_write Write callback for UDP client
 * @param sh DAP client instance
 * @param arg Not used
 */
void stream_dap_data_write(dap_events_socket_t* a_client , void * arg){
    size_t i;
    (void) arg;
    bool ready_to_write=false;
    //log_it(L_DEBUG,"Process channels data output (%u channels)", DAP_STREAM(a_client )->channel_count );

    for(i=0;i<DAP_STREAM(a_client )->channel_count; i++){
        dap_stream_ch_t * ch = DAP_STREAM(a_client )->channel[i];
        if(ch->ready_to_write){
            if(ch->proc->packet_out_callback)
                ch->proc->packet_out_callback(ch,NULL);
            ready_to_write|=ch->ready_to_write;
        }
    }
    if (s_dump_packet_headers ) {
        log_it(L_DEBUG,"dap_stream_data_write: ready_to_write=%s client->buf_out_size=%u" ,
               ready_to_write?"true":"false", a_client->buf_out_size );
    }

    //log_it(L_DEBUG,"stream_dap_data_write ok");
}

/**
 * @brief stream_dap_new New connection callback for UDP client
 * @param sh DAP client instance
 * @param arg Not used
 */
void stream_dap_udp_new(dap_events_socket_t* sh, void * arg){
//    dap_stream_t *sid = stream_new_udp(sh);
    stream_new_udp(sh);
}


static bool _detect_loose_packet(dap_stream_t * a_stream)
{
    dap_stream_ch_pkt_t * ch_pkt = (dap_stream_ch_pkt_t *) a_stream->pkt_cache;

    pthread_rwlock_wrlock (&a_stream->rwlock);

    int count_loosed_packets = ch_pkt->hdr.seq_id - (a_stream->client_last_seq_id_packet + 1);
    if(count_loosed_packets > 0)
    {
        log_it(L_WARNING, "Detected loosed %d packets. "
                          "Last read seq_id packet: %d Current: %d", count_loosed_packets,
               a_stream->client_last_seq_id_packet, ch_pkt->hdr.seq_id);
    } else if(count_loosed_packets < 0) {
        if(a_stream->client_last_seq_id_packet != 0 && ch_pkt->hdr.seq_id != 0) {
        log_it(L_WARNING, "Something wrong. count_loosed packets %d can't less than zero. "
                          "Last read seq_id packet: %d Current: %d", count_loosed_packets,
               a_stream->client_last_seq_id_packet, ch_pkt->hdr.seq_id);
        } // else client don't support seqid functionality
    }
//    log_it(L_DEBUG, "Packet seq id: %d", ch_pkt->hdr.seq_id);
//    log_it(L_DEBUG, "Last seq id: %d", sid->last_seq_id_packet);
    a_stream->client_last_seq_id_packet = ch_pkt->hdr.seq_id;
    pthread_rwlock_unlock (&a_stream->rwlock);

    return false;
}


/**
 * @brief stream_proc_pkt_in
 * @param sid
 */
void stream_proc_pkt_in(dap_stream_t * a_stream)
{
    pthread_rwlock_wrlock( &a_stream->rwlock );
    dap_stream_pkt_t * l_pkt = a_stream->pkt_buf_in;
    size_t l_pkt_size = a_stream->pkt_buf_in_data_size;
    a_stream->pkt_buf_in=NULL;
    a_stream->pkt_buf_in_data_size=0;
    a_stream->keepalive_passed = 0;
    pthread_rwlock_unlock (&a_stream->rwlock);

    if(l_pkt->hdr.type == STREAM_PKT_TYPE_DATA_PACKET)
    {
        dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_stream->pkt_cache;

        if(dap_stream_pkt_read_unsafe(a_stream,l_pkt, l_ch_pkt, sizeof(a_stream->pkt_cache))==0){
            log_it(L_WARNING, "Input: can't decode packet size=%d",l_pkt_size);
            DAP_DELETE(l_pkt);
            return;
        }

        _detect_loose_packet(a_stream);

        // Find channel
        dap_stream_ch_t * ch = NULL;
        pthread_rwlock_wrlock (&a_stream->rwlock);
        for(size_t i=0;i<a_stream->channel_count;i++){
            if(a_stream->channel[i]->proc){
                if(a_stream->channel[i]->proc->id == l_ch_pkt->hdr.id ){
                    ch=a_stream->channel[i];
                }
            }
        }
        pthread_rwlock_unlock (&a_stream->rwlock);

        if(ch){
            ch->stat.bytes_read+=l_ch_pkt->hdr.size;
            if(ch->proc)
                if(ch->proc->packet_in_callback){
                    if ( s_dump_packet_headers ){
                        log_it(L_INFO,"Income channel packet: id='%c' size=%u type=0x%02Xu seq_id=0x%016X enc_type=0x%02X",(char) l_ch_pkt->hdr.id,
                            l_ch_pkt->hdr.size, l_ch_pkt->hdr.type, l_ch_pkt->hdr.seq_id , l_ch_pkt->hdr.enc_type);
                    }
                    ch->proc->packet_in_callback(ch,l_ch_pkt);
                }

        } else if(l_ch_pkt->hdr.id == TECHICAL_CHANNEL_ID && l_ch_pkt->hdr.type == STREAM_CH_PKT_TYPE_KEEPALIVE){
            dap_stream_send_keepalive(a_stream);
        } else{
            log_it(L_WARNING, "Input: unprocessed channel packet id '%c'",(char) l_ch_pkt->hdr.id );
        }
    } else if(l_pkt->hdr.type == STREAM_PKT_TYPE_SERVICE_PACKET) {
        stream_srv_pkt_t * srv_pkt = DAP_NEW(stream_srv_pkt_t);
        memcpy(srv_pkt, l_pkt->data,sizeof(stream_srv_pkt_t));
        uint32_t session_id = srv_pkt->session_id;
        check_session(session_id,a_stream->esocket);
        DAP_DELETE(srv_pkt);
    } else {
        log_it(L_WARNING, "Unknown header type");
    }


//    ev_timer_again (keepalive_loop, &a_stream->keepalive_watcher);
    start_keepalive( a_stream );
    DAP_DELETE(l_pkt);
}

/**
 * @brief stream_data_read HTTP data read callback. Read packet and passes that to the channel's callback
 * @param sh HTTP client instance
 * @param arg Processed number of bytes
 */
void stream_data_read(dap_http_client_t * sh, void * arg)
{
    s_http_client_data_read(sh->esocket,arg);
}



/**
 * @brief stream_delete Delete stream and free its resources
 * @param sid Stream id
 */
void stream_delete(dap_http_client_t * sh, void * arg)
{
    s_es_callback_delete(sh->esocket,arg);
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
