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


#define LOG_TAG "stream"

// Callbacks for HTTP client
void stream_headers_read(dap_http_client_t * sh, void * arg); // Prepare stream when all headers are read

void stream_headers_write(dap_http_client_t * sh, void * arg); // Output headers
void stream_data_write(dap_http_client_t * sh, void * arg); // Write the data
void stream_data_read(dap_http_client_t * sh, void * arg); // Read the data

// Internal functions
stream_t * stream_new(dap_http_client_t * sh); // Create new stream
void stream_delete(dap_http_client_t * sh, void * arg);

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
 * @brief stream_add_proc Add URL processor callback for streaming
 * @param sh HTTP server instance
 * @param url URL
 */
void stream_add_proc(struct dap_http * sh, const char * url)
{
    dap_http_add_proc(sh,url,NULL,NULL,stream_delete,stream_headers_read,stream_headers_write,stream_data_read,stream_data_write,NULL);
    //dap_http_add_proc(sh,url,NULL,NULL,NULL,stream_headers_read,stream_headers_write,NULL,stream_data_write,NULL);
}

void stream_states_update(struct stream *sid)
{
    sid->conn_http->state_write=DAP_HTTP_CLIENT_STATE_START;
    size_t i;
    bool ready_to_write=false;
    for(i=0;i<sid->channel_count; i++)
        ready_to_write|=sid->channel[i]->ready_to_write;
    dap_client_ready_to_write(sid->conn,ready_to_write);

    sid->conn_http->out_content_ready=true;
}

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
                        stream_ch_new(sid,'s');
                        stream_ch_new(sid,'t');
                        stream_states_update(sid);
                        dap_client_ready_to_read(cl_ht->client,true);
                    }else{
                        stream_ch_new(sid,'s');
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
 * @brief stream_new Create new stream instance for HTTP client
 * @return New stream_t instance
 */
stream_t * stream_new(dap_http_client_t * sh)
{
    stream_t * ret=(stream_t*) calloc(1,sizeof(stream_t));

    ret->conn = sh->client;
    ret->conn_http=sh;


    sh->_internal=ret;

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
        stream_t *sid=STREAM(sh);

        dap_http_out_header_add(sh,"Content-Type","application/octet-stream");
        dap_http_out_header_add(sh,"Connnection","keep-alive");
        dap_http_out_header_add(sh,"Cache-Control","no-cache");

        if(sid->stream_size>0)
            dap_http_out_header_add_f(sh,"Content-Length","%u", (unsigned int) sid->stream_size );

        sh->state_read=DAP_HTTP_CLIENT_STATE_DATA;
        dap_client_ready_to_read(sh->client,true);

    }
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
        size_t i;
        bool ready_to_write=false;
      //  log_it(L_DEBUG,"Process channels data output (%u channels)",STREAM(sh)->channel_count);

        for(i=0;i<STREAM(sh)->channel_count; i++){
            stream_ch_t * ch = STREAM(sh)->channel[i];
            if(ch->ready_to_write){
                ch->proc->packet_out_callback(ch,NULL);
                ready_to_write|=ch->ready_to_write;
            }
        }
        //log_it(L_DEBUG,"stream_data_out (ready_to_write=%s)", ready_to_write?"true":"false");

        dap_client_ready_to_write(sh->client,ready_to_write);
        //log_it(L_ERROR,"No stream_data_write_callback is defined");
    }else{
        log_it(L_WARNING, "Wrong request, reply status code is %u",sh->reply_status_code);
    }
}


/**
 * @brief stream_proc_pkt_in
 * @param sid
 */
void stream_proc_pkt_in(stream_t * sid)
{
    // log_it(L_DEBUG,"Input: read last bytes for current packet (hdr.size=%u)",sid->pkt_buf_in-);
    stream_ch_pkt_t * ch_pkt= (stream_ch_pkt_t*) calloc(1,sid->pkt_buf_in->hdr.size+sizeof(stream_ch_pkt_hdr_t)+16 );
    stream_pkt_read(sid,sid->pkt_buf_in, ch_pkt);

//    log_it (DEBUG, "Recieved channel packet with %lu of payload bytes (type '%c' id '%c')",
//           ch_pkt->hdr.size,(char) ch_pkt->hdr.type, (char) ch_pkt->hdr.id);
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

    }else{
         log_it(L_WARNING, "Input: unprocessed channel packet id '%c'",(char) ch_pkt->hdr.id );
    }
    free(sid->pkt_buf_in);
    sid->pkt_buf_in=NULL;
    sid->pkt_buf_in_data_size=0;
    free(ch_pkt);

}

/**
 * @brief stream_data_read HTTP data read callback. Read packet and passes that to the channel's callback
 * @param sh HTTP client instance
 * @param arg Processed number of bytes
 */




void stream_data_read(dap_http_client_t * sh, void * arg)
{

  //  log_it(L_DEBUG, "Stream data read %u bytes", sh->client->buf_in_size);
  //  log_it(L_DEBUG, "Stream data  %s", sh->client->buf_in);
    stream_t * sid =STREAM(sh);
    int * ret = (int *) arg;

    if(sid->pkt_buf_in){
        size_t read_bytes_to=( ((sid->pkt_buf_in->hdr.size-sid->pkt_buf_in_data_size) > sid->conn->buf_in_size )
                               ? sid->conn->buf_in_size
                              :(sid->pkt_buf_in->hdr.size-sid->pkt_buf_in_data_size));
        memcpy(sid->pkt_buf_in->data+sid->pkt_buf_in_data_size,sh->client->buf_in,read_bytes_to);
        sid->pkt_buf_in_data_size+=read_bytes_to;
        if(sid->pkt_buf_in_data_size>=(sid->pkt_buf_in->hdr.size) ){
            stream_proc_pkt_in(sid);
        }
        *ret+=read_bytes_to;
    }else{
        stream_pkt_t * pkt;
        while(pkt=stream_pkt_detect( sh->client->buf_in + *ret, (sh->client->buf_in_size - ((size_t) *ret) ))){
            size_t read_bytes_to=( (pkt->hdr.size+sizeof(stream_pkt_hdr_t)) > sid->conn->buf_in_size
                                   ?sid->conn->buf_in_size
                                   :(pkt->hdr.size+sizeof(stream_pkt_hdr_t) ) );
            if(read_bytes_to){
                sid->pkt_buf_in=(stream_pkt_t *) calloc(1,pkt->hdr.size+sizeof(stream_pkt_hdr_t));
                memcpy(sid->pkt_buf_in,pkt,read_bytes_to);
                *ret = (*ret)+ read_bytes_to;
                sid->pkt_buf_in_data_size=read_bytes_to-sizeof(stream_pkt_hdr_t);
                if(read_bytes_to>=(pkt->hdr.size)){
                    //log_it(L_INFO,"Input: read full packet (hdr.size=%u read_bytes_to=%u buf_in_size=%u)"
                    //       ,sid->pkt_buf_in->hdr.size,read_bytes_to,sid->conn->buf_in_size);
                    stream_proc_pkt_in(sid);
                }else{
                    log_it(L_DEBUG,"Input: Not all stream packet in input (hdr.size=%u read_bytes_to=%u)",sid->pkt_buf_in->hdr.size,read_bytes_to);
                }
                return;
            }else
                break;
        }
        //log_it(L_WARNING,"Input: Not found signature in the incomming data");
        *ret += sh->client->buf_in_size;
    }

//    log_it(L_DEBUG,"Stream read data from HTTP client: %u",sh->client->buf_in_size);
//    if(sh->client->buf_in_size )
}



/**
 * @brief stream_delete Delete stream and free its resources
 * @param sid Stream id
 */
void stream_delete(dap_http_client_t * sh, void * arg)
{
    stream_t * sid = STREAM(sh);
    if(sid == NULL)
        return;
    (void) arg;
    size_t i;
    for(i=0;i<sid->channel_count; i++)
        stream_ch_delete(sid->channel[i]);
    //free(sid);
    log_it(L_NOTICE,"[core] Stream connection is finished");
}
