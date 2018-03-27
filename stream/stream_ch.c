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

#include "dap_common.h"

#include "dap_client.h"
#include "dap_http_client.h"

#include "stream.h"
#include "stream_ch.h"
#include "stream_ch_proc.h"
#include "stream_ch_pkt.h"

#define LOG_TAG "stream_ch"

/**
 * @brief stream_ch_init Init stream channel module
 * @return Zero if ok others if no
 */
int stream_ch_init()
{
    if(stream_ch_proc_init() != 0 ){
        log_it(L_CRITICAL,"Can't init stream channel proc submodule");
        return -1;
    }
    if(stream_ch_pkt_init() != 0 ){
        log_it(L_CRITICAL,"Can't init stream channel packet submodule");
        return -1;
    }
    log_it(L_NOTICE,"Module stream channel initialized");
    return 0;
}

/**
 * @brief stream_ch_deinit Destroy stream channel submodule
 */
void stream_ch_deinit()
{
}

/**
 * @brief stream_ch_new Creates new stream channel instance
 * @param direction Direction of channel (input to the server, output to the client)
 * @return
 */
stream_ch_t* stream_ch_new(struct stream* stream,uint8_t id)
{
    stream_ch_proc_t * proc=stream_ch_proc_find(id);
    if(proc){
        stream_ch_t * ret= DAP_NEW_Z(stream_ch_t);
        ret->stream=stream;
        ret->proc=proc;
        ret->ready_to_read=true;
        ret->stream->channel[ret->stream->channel_count]=ret;
        ret->stream->channel_count++;
        pthread_mutex_init(&(ret->mutex),NULL);
        if(ret->proc->new_callback)
            ret->proc->new_callback(ret,NULL);
        return ret;
    }else{
        log_it(L_WARNING, "Unknown stream processor with id %uc",id);
        return NULL;
    }
}

/**
 * @brief stream_ch_delete Delete channel instance
 * @param ch Channel delete
 */
void stream_ch_delete(stream_ch_t*ch)
{
    if(ch->proc)
        if(ch->proc->delete_callback)
            ch->proc->delete_callback(ch,NULL);

    pthread_mutex_destroy(&(ch->mutex));

    if(ch->internal){
        free(ch->internal);
    }
    //free(ch);
}


void stream_ch_set_ready_to_write(stream_ch_t * ch,bool is_ready)
{
    pthread_mutex_lock(&ch->mutex);
    if(ch->ready_to_write!=is_ready){
        //log_it(L_DEBUG,"Change channel '%c' to %s", (char) ch->proc->id, is_ready?"true":"false");
        ch->ready_to_write=is_ready;
        if(is_ready)
            ch->stream->conn_http->state_write=DAP_HTTP_CLIENT_STATE_DATA;
        dap_client_ready_to_write(ch->stream->conn,is_ready);
    }
    pthread_mutex_unlock(&ch->mutex);
}
