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
#include "dap_common.h"

#include "stream.h"
#include "stream_pkt.h"
#include "stream_ch.h"
#include "stream_ch_proc.h"
#include "stream_ch_pkt.h"
#include "stream_session.h"

#include "dap_client.h"
#include "dap_http.h"
#include "dap_http_client.h"
#include "dap_http_header.h"
#include "dap_udp_server.h"


#define LOG_TAG "stream"

// Callbacks for HTTP client
void stream_headers_read(dap_http_client_t * sh, void * arg); // Prepare stream when all headers are read

void stream_headers_write(dap_http_client_t * sh, void * arg); // Output headers
void stream_data_write(dap_http_client_t * sh, void * arg); // Write the data
void stream_data_read(dap_http_client_t * sh, void * arg); // Read the data

void stream_dap_data_read(dap_client_remote_t* sh, void * arg);
void stream_dap_data_write(dap_client_remote_t* sh, void * arg);
void stream_dap_delete(dap_client_remote_t* sh, void * arg);
void stream_dap_new(dap_client_remote_t* sh,void * arg);

// Internal functions
stream_t * stream_new(dap_http_client_t * sh); // Create new stream
void stream_delete(dap_http_client_t * sh, void * arg);

struct ev_loop *keepalive_loop;
pthread_t keepalive_thread;

// Start keepalive stream
void* stream_loop(void * arg)
{
    keepalive_loop = ev_loop_new(0);
    ev_loop(keepalive_loop, 0);
    return NULL;
}

/**
 * @brief stream_init Init stream module
 * @return  0 if ok others if not
 */
int stream_init()
{
    if( stream_ch_init() != 0 ){
        log_it(L_CRITICAL, "Can't init channel types submodule");
        return -1;
    }
    pthread_create(&keepalive_thread, NULL, stream_loop, NULL);

    log_it(L_NOTICE,"Init streaming module");
    return 0;
}

/**
 * @brief stream_media_deinit Deinint Stream module
 */
void stream_deinit()
{
    stream_ch_deinit();
}

/**
 * @brief stream_add_proc_http Add URL processor callback for streaming
 * @param sh HTTP server instance
 * @param url URL
 */
void stream_add_proc_http(struct dap_http * sh, const char * url)
{
    dap_http_add_proc(sh,url,NULL,NULL,stream_delete,stream_headers_read,stream_headers_write,stream_data_read,stream_data_write,NULL);    
}

/**
 * @brief stream_add_proc_udp Add processor callback for streaming
 * @param sh UDP server instance
 */
void stream_add_proc_udp(dap_udp_server_t * sh)
{
    dap_server_t* server = sh->dap_server;
    server->client_read_callback = stream_dap_data_read; 
    server->client_write_callback = stream_dap_data_write;
    server->client_delete_callback = stream_dap_delete;
    server->client_new_callback = stream_dap_new;
}

/**
 * @brief stream_states_update
 * @param sid stream instance
 */
void stream_states_update(struct stream *sid)
{
    if(sid->conn_http)
        sid->conn_http->state_write=DAP_HTTP_CLIENT_STATE_START;
    size_t i;
    bool ready_to_write=false;
    for(i=0;i<sid->channel_count; i++)
        ready_to_write|=sid->channel[i]->ready_to_write;
    if(sid->conn_udp)
        dap_udp_client_ready_to_write(sid->conn_udp->client,ready_to_write);
    else
        dap_client_ready_to_write(sid->conn,ready_to_write);
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

    log_it(L_DEBUG,"Prepare data stream");
    if(cl_ht->in_query_string[0]){
        log_it(L_INFO,"Query string [%s]",cl_ht->in_query_string);
        if(sscanf(cl_ht->in_query_string,"fj913htmdgaq-d9hf=%u",&id)==1){
            stream_session_t * ss=NULL;
            ss=stream_session_id(id);
            if(ss==NULL){
                log_it(L_ERROR,"No session id %u was found",id);
                cl_ht->reply_status_code=404;
                strcpy(cl_ht->reply_reason_phrase,"Not found");
            }else{
                log_it(L_INFO,"Session id %u was found with media_id = %d",id,ss->media_id);
                if(stream_session_open(ss)==0){ // Create new stream
                    stream_t * sid = stream_new(cl_ht);
                    sid->session=ss;
                    if(ss->create_empty){
                        log_it(L_INFO, "Opened stream session with only technical channels");

                        cl_ht->reply_status_code=200;
                        strcpy(cl_ht->reply_reason_phrase,"OK");
                        //cl_ht->state_write=DAP_HTTP_CLIENT_STATE_START;
                        //cl_ht->client->ready_to_write=true;
                        cl_ht->state_read=DAP_HTTP_CLIENT_STATE_DATA;
                        cl_ht->out_content_ready=true;
                        stream_ch_new(sid,SERVICE_CHANNEL_ID);
                        stream_ch_new(sid,'t');
                        stream_states_update(sid);
                        dap_client_ready_to_read(cl_ht->client,true);
                    }else{
                        stream_ch_new(sid,SERVICE_CHANNEL_ID);
                        stream_ch_new(sid,'g');

                        cl_ht->reply_status_code=200;
                        strcpy(cl_ht->reply_reason_phrase,"OK");
                        cl_ht->state_read=DAP_HTTP_CLIENT_STATE_DATA;
                        dap_client_ready_to_read(cl_ht->client,true);

                        stream_states_update(sid);

                    }
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
stream_t * stream_new_udp(dap_client_remote_t * sh)
{
    stream_t * ret=(stream_t*) calloc(1,sizeof(stream_t));

    ret->conn = sh;
    ret->conn_udp=sh->_inheritor;

    sh->_internal=ret;

    log_it(L_NOTICE,"New stream instance");
    return ret;
}

/**
 * @brief check_session CHeck session status, open if need
 * @param id session id
 * @param cl DAP client structure
 */
void check_session(unsigned int id, dap_client_remote_t* cl){
    stream_session_t * ss=NULL;
    ss=stream_session_id(id);
    if(ss==NULL){
        log_it(L_ERROR,"No session id %u was found",id);
    }else{
        log_it(L_INFO,"Session id %u was found with media_id = %d",id,ss->media_id);
        if(stream_session_open(ss)==0){ // Create new stream
            stream_t * sid;
            if(STREAM(cl) == NULL)
                sid = stream_new_udp(cl);
            else
                sid = STREAM(cl);
            sid->session=ss;
            if(ss->create_empty)
                log_it(L_INFO, "Session created empty");       
            log_it(L_INFO, "Opened stream session technical and data channels");
            stream_ch_new(sid,SERVICE_CHANNEL_ID);
            stream_ch_new(sid,DATA_CHANNEL_ID);
            stream_states_update(sid);
            if(STREAM(cl)->conn_udp)
                dap_udp_client_ready_to_read(cl,true);
            else
                dap_client_ready_to_read(cl,true);
            start_keepalive(sid);
        }else{
            log_it(L_ERROR,"Can't open session id %u",id);
        }
    }
}

/**
 * @brief stream_new Create new stream instance for HTTP client
 * @return New stream_t instance
 */
stream_t * stream_new(dap_http_client_t * sh)
{
    stream_t * ret=(stream_t*) calloc(1,sizeof(stream_t));

    ret->conn = sh->client;
    ret->conn_http=sh;

    ret->conn->_internal=ret;


    log_it(L_NOTICE,"New stream instance");
    return ret;
}

/**
 * @brief stream_headers_write Prepare headers for output. Creates stream structure
 * @param sh HTTP client instance
 * @param arg Not used
 */
void stream_headers_write(dap_http_client_t * sh, void *arg)
{
    (void) arg;
    if(sh->reply_status_code==200){
        stream_t *sid=STREAM(sh->client);

        dap_http_out_header_add(sh,"Content-Type","application/octet-stream");
        dap_http_out_header_add(sh,"Connnection","keep-alive");
        dap_http_out_header_add(sh,"Cache-Control","no-cache");

        if(sid->stream_size>0)
            dap_http_out_header_add_f(sh,"Content-Length","%u", (unsigned int) sid->stream_size );

        sh->state_read=DAP_HTTP_CLIENT_STATE_DATA;
        dap_client_ready_to_read(sh->client,true);
    }
}

// Function for keepalive loop
static void keepalive_cb (EV_P_ ev_timer *w, int revents)
{
    struct stream *sid = w->data;
    if(sid->keepalive_passed < STREAM_KEEPALIVE_PASSES)
    {
        stream_send_keepalive(sid);
        sid->keepalive_passed+=1;
    }
    else{
        log_it(L_INFO, "Client disconnected");
        ev_timer_stop (keepalive_loop, &sid->keepalive_watcher);
        void * arg;
        stream_dap_delete(sid->conn,arg);
    }
}

/**
 * @brief start_keepalive Start keepalive signals exchange for stream
 * @param sid Stream instance
 */
void start_keepalive(struct stream *sid){
    keepalive_loop = EV_DEFAULT;
    sid->keepalive_watcher.data = sid;
    ev_timer_init (&sid->keepalive_watcher, keepalive_cb, STREAM_KEEPALIVE_TIMEOUT, STREAM_KEEPALIVE_TIMEOUT);
    ev_timer_start (keepalive_loop, &sid->keepalive_watcher);
}

/**
 * @brief stream_data_write HTTP data write callback
 * @param sh HTTP client instance
 * @param arg Not used
 */
void stream_data_write(dap_http_client_t * sh, void * arg)
{
    (void) arg;

    if(sh->reply_status_code==200){
        stream_dap_data_write(sh->client,arg);
    }else{
        log_it(L_WARNING, "Wrong request, reply status code is %u",sh->reply_status_code);
    }
}

/**
 * @brief stream_dap_data_read Read callback for UDP client
 * @param sh DAP client instance
 * @param arg Not used
 */
void stream_dap_data_read(dap_client_remote_t* sh, void * arg){
    stream_t * sid =STREAM(sh);
    int * ret = (int *) arg;
    int bytes_ready = 0;

    // Если имеем хотя бы целый заголовок
    if(sid->pkt_buf_in && sid->pkt_buf_in_data_size >= sizeof(stream_pkt_hdr_t)){
        //Ищем в полученном куске данных следующий пакет
        stream_pkt_t* packet_test = stream_pkt_detect( sh->buf_in, sid->conn->buf_in_size);
        if(packet_test){
            // Если нашли - рассчитываем размер блока памяти до найденного пакета
            int offset = (uint8_t*)packet_test - (uint8_t*)sh->buf_in;
            // Если этот размер совпал с размером недостающего куска - будем считать что мы получили нужный пакет
            if(offset != sid->pkt_buf_in->hdr.size+sizeof(stream_pkt_hdr_t)-sid->pkt_buf_in_data_size){
                // Если не совпал - выбрасываем предыдущий пакет и переходим к следующему
                log_it(L_WARNING,"WRONG NEXT PACKET, OFFSET IS %i, BUT NEED %i",offset,sid->pkt_buf_in->hdr.size+sizeof(stream_pkt_hdr_t)-sid->pkt_buf_in_data_size);
                sid->pkt_buf_in_data_size = 0;
                sid->pkt_buf_in = NULL;
                return;
            }
            else
                log_it(L_DEBUG,"Next packet true");
        }
        // Если всё верно - читаем следующий блок
        size_t read_bytes_to=( ((sid->pkt_buf_in->hdr.size+sizeof(stream_pkt_hdr_t)-sid->pkt_buf_in_data_size) > sid->conn->buf_in_size )
                               ? sid->conn->buf_in_size
                              :(sid->pkt_buf_in->hdr.size+sizeof(stream_pkt_hdr_t)-sid->pkt_buf_in_data_size));
        memcpy((uint8_t*)sid->pkt_buf_in+sid->pkt_buf_in_data_size,sh->buf_in,read_bytes_to);
        sid->pkt_buf_in_data_size+=read_bytes_to;
        if(sid->pkt_buf_in_data_size>=(sid->pkt_buf_in->hdr.size+sizeof(stream_pkt_hdr_t)) ){
            stream_proc_pkt_in(sid);
        }
        bytes_ready+=read_bytes_to;
    // Если имеем только часть заголовка
    }else if(sid->pkt_buf_in){
        // Если имеется хотя бы размер пакета - делаем аналогичную проверку
        stream_pkt_t* packet_test = stream_pkt_detect( sh->buf_in, sid->conn->buf_in_size);
        if(packet_test){
            int offset = (uint8_t*)packet_test - (uint8_t*)sh->buf_in;
            // Это условие также будет срабатывать если полученный кусок не содержит поле size (из-за этого происходило падение)
            if(offset != sid->pkt_buf_in->hdr.size+sizeof(stream_pkt_hdr_t)-sid->pkt_buf_in_data_size){
                log_it(L_WARNING,"WRONG NEXT PACKET, OFFSET IS %i, BUT NEED %i",offset,sid->pkt_buf_in->hdr.size+sizeof(stream_pkt_hdr_t)-sid->pkt_buf_in_data_size);
                sid->pkt_buf_in_data_size = 0;
                sid->pkt_buf_in = NULL;
                return;
            }
            else
                log_it(L_DEBUG,"Next packet true");
        }
        // Если всё верно - читаем только заголовок
        size_t read_bytes_to=(sizeof(stream_pkt_hdr_t) - sid->pkt_buf_in_data_size > sid->conn->buf_in_size 
                                ? sid->conn->buf_in_size
                                :sizeof(stream_pkt_hdr_t) - sid->pkt_buf_in_data_size);
        log_it(L_WARNING,"Special condition used, additionla part: %u",read_bytes_to);
        memcpy((uint8_t*)sid->pkt_buf_in+sid->pkt_buf_in_data_size,sh->buf_in,read_bytes_to);
        sid->pkt_buf_in_data_size+=read_bytes_to;

        bytes_ready+=read_bytes_to;
    }else{
        stream_pkt_t * pkt;
        // Try to detect packet header in dap_client buf
        while(pkt=stream_pkt_detect( sh->buf_in + bytes_ready, (sh->buf_in_size - ((size_t) bytes_ready) ))){
            size_t read_bytes_to=( (pkt->hdr.size+sizeof(stream_pkt_hdr_t)) > sid->conn->buf_in_size
                                   ?sid->conn->buf_in_size
                                   :(pkt->hdr.size+sizeof(stream_pkt_hdr_t) ) );
            if(read_bytes_to){
                 sid->pkt_buf_in=(stream_pkt_t *) calloc(1,pkt->hdr.size+sizeof(stream_pkt_hdr_t));
                memcpy(sid->pkt_buf_in,pkt,read_bytes_to);
                bytes_ready = (bytes_ready)+ read_bytes_to;
                if(read_bytes_to < sizeof(stream_pkt_hdr_t))
                    log_it(L_WARNING,"Packet size less than header");
                sid->pkt_buf_in_data_size=read_bytes_to;

                if(read_bytes_to>=(pkt->hdr.size + sizeof(stream_pkt_hdr_t))){
                    stream_proc_pkt_in(sid);
                }else{
                    log_it(L_DEBUG,"Input: Not all stream packet in input (hdr.size=%u read_bytes_to=%u)",sid->pkt_buf_in->hdr.size,read_bytes_to);
                }
                *ret = bytes_ready;
                return;
            }else
                break;
        }
        bytes_ready += sh->buf_in_size; // Эта строчка по-моему также неверная, если придут два слипшихся пакета - прочитаем только один
    }
    if(ret)
        *ret = bytes_ready;
}

/**
 * @brief stream_dap_data_write Write callback for UDP client
 * @param sh DAP client instance
 * @param arg Not used
 */
void stream_dap_data_write(dap_client_remote_t* sh, void * arg){
    size_t i;
    bool ready_to_write=false;
    //  log_it(L_DEBUG,"Process channels data output (%u channels)",STREAM(sh)->channel_count);

    for(i=0;i<STREAM(sh)->channel_count; i++){
        stream_ch_t * ch = STREAM(sh)->channel[i];
        if(ch->ready_to_write){
            if(ch->proc->packet_out_callback)
                ch->proc->packet_out_callback(ch,NULL);
            ready_to_write|=ch->ready_to_write;
        }
    }
    //log_it(L_DEBUG,"stream_data_out (ready_to_write=%s)", ready_to_write?"true":"false");

  /*  if(STREAM(sh)->conn_udp)
        dap_udp_client_ready_to_write(STREAM(sh)->conn,ready_to_write);
    else
        dap_client_ready_to_write(sh,ready_to_write);*/
    //log_it(L_ERROR,"No stream_data_write_callback is defined");
}

/**
 * @brief stream_dap_delete Delete callback for UDP client
 * @param sh DAP client instance
 * @param arg Not used
 */
void stream_dap_delete(dap_client_remote_t* sh, void * arg){
    stream_t * sid = STREAM(sh);
    if(sid == NULL)
        return;
    (void) arg;
    size_t i;
    for(i=0;i<sid->channel_count; i++)
        stream_ch_delete(sid->channel[i]);
    if(sid->session)
        stream_session_close(sid->session->id);
    //free(sid);
    log_it(L_NOTICE,"[core] Stream connection is finished");
}

/**
 * @brief stream_dap_new New connection callback for UDP client
 * @param sh DAP client instance
 * @param arg Not used
 */
void stream_dap_new(dap_client_remote_t* sh, void * arg){
    stream_t * sid = stream_new_udp(sh);
}


/**
 * @brief stream_proc_pkt_in
 * @param sid
 */
void stream_proc_pkt_in(stream_t * sid)
{
    if(sid->pkt_buf_in->hdr.type == DATA_PACKET)
    {
        stream_ch_pkt_t * ch_pkt= (stream_ch_pkt_t*) calloc(1,sid->pkt_buf_in->hdr.size);
        stream_pkt_read(sid,sid->pkt_buf_in, ch_pkt);
        stream_ch_t * ch = NULL;
        size_t i;
        for(i=0;i<sid->channel_count;i++)
            if(sid->channel[i]->proc){
                if(sid->channel[i]->proc->id == ch_pkt->hdr.id ){
                    ch=sid->channel[i];
                }
            }
        if(ch){
            ch->stat.bytes_read+=ch_pkt->hdr.size;
            if(ch->proc)
                if(ch->proc->packet_in_callback)
                    ch->proc->packet_in_callback(ch,ch_pkt);
            if(ch->proc->id == SERVICE_CHANNEL_ID && ch_pkt->hdr.type == KEEPALIVE_PACKET)
                stream_send_keepalive(sid);
        }else{
            log_it(L_WARNING, "Input: unprocessed channel packet id '%c'",(char) ch_pkt->hdr.id );
        }
        free(ch_pkt);
    }
    else if(sid->pkt_buf_in->hdr.type == SERVICE_PACKET)
    {
        stream_srv_pkt_t * srv_pkt = (stream_srv_pkt_t *)malloc(sizeof(stream_srv_pkt_t));
        memcpy(srv_pkt,sid->pkt_buf_in->data,sizeof(stream_srv_pkt_t));
        uint32_t session_id = srv_pkt->session_id;
        check_session(session_id,sid->conn);
        free(srv_pkt);
    }
    sid->keepalive_passed = 0;
    ev_timer_again (keepalive_loop, &sid->keepalive_watcher);
    free(sid->pkt_buf_in);
    sid->pkt_buf_in=NULL;
    sid->pkt_buf_in_data_size=0;
}

/**
 * @brief stream_data_read HTTP data read callback. Read packet and passes that to the channel's callback
 * @param sh HTTP client instance
 * @param arg Processed number of bytes
 */
void stream_data_read(dap_http_client_t * sh, void * arg)
{
    stream_dap_data_read(sh->client,arg);
}



/**
 * @brief stream_delete Delete stream and free its resources
 * @param sid Stream id
 */
void stream_delete(dap_http_client_t * sh, void * arg)
{
    stream_dap_delete(sh->client,arg);
}
