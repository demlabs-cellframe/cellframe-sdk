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

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <pthread.h>

#include "dap_common.h"
#include "dap_events_socket.h"
#include "dap_http_client.h"
#include "dap_uuid.h"
#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_worker.h"

#define LOG_TAG "dap_stream_ch"

/**
 * @brief dap_stream_ch_init Init stream channel module
 * @return Zero if ok others if no
 */
int dap_stream_ch_init()
{
    if(stream_ch_proc_init() != 0 ){
        log_it(L_CRITICAL,"Can't init stream channel proc submodule");
        return -1;
    }
    if(dap_stream_ch_pkt_init() != 0 ){
        log_it(L_CRITICAL,"Can't init stream channel packet submodule");
        return -1;
    }
    log_it(L_NOTICE,"Module stream channel initialized");
    return 0;
}

/**
 * @brief dap_stream_ch_deinit Destroy stream channel submodule
 */
void dap_stream_ch_deinit()
{
}

/**
 * @brief dap_stream_ch_new Creates new stream channel instance
 * @return
 */
dap_stream_ch_t* dap_stream_ch_new(dap_stream_t* a_stream, uint8_t a_id)
{
    stream_ch_proc_t * proc=dap_stream_ch_proc_find(a_id);
    if(proc){
        dap_stream_ch_t* l_ch_new = DAP_NEW_Z(dap_stream_ch_t);
        l_ch_new->me = l_ch_new;
        l_ch_new->stream = a_stream;
        l_ch_new->proc = proc;
        l_ch_new->ready_to_read = true;
        l_ch_new->uuid = dap_uuid_generate_uint64();
        pthread_mutex_init(&(l_ch_new->mutex),NULL);

        // Init on stream worker
        dap_stream_worker_t * l_stream_worker = a_stream->stream_worker;
        l_ch_new->stream_worker = l_stream_worker;

        pthread_rwlock_wrlock(&l_stream_worker->channels_rwlock);
        HASH_ADD(hh_worker,l_stream_worker->channels, uuid,sizeof (l_ch_new->uuid ),l_ch_new);
        pthread_rwlock_unlock(&l_stream_worker->channels_rwlock);


        // Proc new callback
        if(l_ch_new->proc->new_callback)
            l_ch_new->proc->new_callback(l_ch_new,NULL);

        a_stream->channel[l_ch_new->stream->channel_count] = l_ch_new;
        a_stream->channel_count++;

        return l_ch_new;
    }else{
        log_it(L_WARNING, "Unknown stream processor with id %uc",a_id);
        return NULL;
    }
}

/**
 * @brief stream_ch_delete Delete channel instance
 * @param ch Channel delete
 */
void dap_stream_ch_delete(dap_stream_ch_t *a_ch)
{
    dap_stream_worker_t * l_stream_worker = a_ch->stream_worker;
    if(l_stream_worker){
        pthread_rwlock_wrlock(&l_stream_worker->channels_rwlock);
        HASH_DELETE(hh_worker,l_stream_worker->channels, a_ch);
        pthread_rwlock_unlock(&l_stream_worker->channels_rwlock);
    }

    pthread_mutex_lock(&a_ch->mutex);
    if (a_ch->proc)
        if (a_ch->proc->delete_callback)
            a_ch->proc->delete_callback(a_ch, NULL);
    a_ch->stream->channel[a_ch->stream->channel_count--] = NULL;
    pthread_mutex_unlock(&a_ch->mutex);

    pthread_mutex_destroy(&a_ch->mutex);

/* fixed raise, but probably may be memory leak!
    if(ch->internal){
        free(ch->internal);
    }
*/
    DAP_DELETE(a_ch);
}

/**
 * @brief dap_stream_ch_find_by_uuid_unsafe
 * @param a_worker
 * @param a_ch_uuid
 * @return
 */
dap_stream_ch_t * dap_stream_ch_find_by_uuid_unsafe(dap_stream_worker_t * a_worker, dap_stream_ch_uuid_t a_ch_uuid)
{
    if( a_worker == NULL ){
        log_it(L_WARNING,"Attempt to search for uuid 0x%016"DAP_UINT64_FORMAT_U" in NULL worker", a_ch_uuid);
        return NULL;
    } else if ( a_worker->channels){
        dap_stream_ch_t * l_ch = NULL;
        pthread_rwlock_rdlock(&a_worker->channels_rwlock);
        HASH_FIND(hh_worker,a_worker->channels ,&a_ch_uuid, sizeof(a_ch_uuid), l_ch );
        pthread_rwlock_unlock(&a_worker->channels_rwlock);
        return l_ch;
    }else
        return NULL;
}


/**
 * @brief dap_stream_ch_set_ready_to_read
 * @param a_ch
 * @param a_is_ready
 */
void dap_stream_ch_set_ready_to_read_unsafe(dap_stream_ch_t * a_ch,bool a_is_ready)
{
    if( a_ch->ready_to_read != a_is_ready){
        //log_it(L_DEBUG,"Change channel '%c' to %s", (char) ch->proc->id, is_ready?"true":"false");
        a_ch->ready_to_read=a_is_ready;
        dap_events_socket_set_readable_unsafe(a_ch->stream->esocket, a_is_ready);
    }
}

/**
 * @brief dap_stream_ch_set_ready_to_write
 * @param ch
 * @param is_ready
 */
void dap_stream_ch_set_ready_to_write_unsafe(dap_stream_ch_t * ch,bool is_ready)
{
    if(ch->ready_to_write!=is_ready){
        //log_it(L_DEBUG,"Change channel '%c' to %s", (char) ch->proc->id, is_ready?"true":"false");
        ch->ready_to_write=is_ready;
        if(is_ready && ch->stream->conn_http)
            ch->stream->conn_http->state_write=DAP_HTTP_CLIENT_STATE_DATA;
        dap_events_socket_set_writable_unsafe(ch->stream->esocket, is_ready);
    }
}

