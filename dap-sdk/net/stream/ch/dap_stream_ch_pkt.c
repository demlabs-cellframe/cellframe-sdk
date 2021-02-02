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
#include <stdarg.h>
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
#include "dap_enc.h"
#include "dap_enc_key.h"

#include "dap_events_socket.h"
#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_pkt.h"
#include "dap_stream_worker.h"

#define LOG_TAG "dap_stream_ch_pkt"

/**
 * @brief stream_ch_pkt_init
 * @return Zero if ok
 */
int dap_stream_ch_pkt_init()
{

    return 0;
}

void dap_stream_ch_pkt_deinit()
{

}

/**
 * @brief dap_stream_ch_pkt_write_f_mt
 * @param a_ch
 * @param a_type
 * @param a_str
 * @return
 */
size_t dap_stream_ch_pkt_write_f_mt(dap_stream_worker_t * a_worker , dap_stream_ch_t *a_ch, uint8_t a_type, const char * a_format,...)
{
    va_list ap;
    va_start(ap,a_format);
    int l_data_size = dap_vsnprintf(NULL,0,a_format,ap);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Can't write out formatted data '%s' with values",a_format);
        return 0;
    }
    l_data_size++; // To calc trailing zero
    dap_stream_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_stream_worker_msg_io_t);
    l_msg->ch = a_ch;
    l_msg->ch_pkt_type = a_type;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size);
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    l_data_size = dap_vsnprintf(l_msg->data,0,a_format,ap);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Can't write out formatted data '%s' with values",a_format);
        DAP_DELETE(l_msg);
        return 0;
    }
    l_data_size++;
    l_msg->data_size = l_data_size;
    int l_ret= dap_events_socket_queue_ptr_send(a_worker->queue_ch_io , l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return l_data_size;

}

/**
 * @brief dap_stream_ch_pkt_write_f_inter
 * @param a_queue
 * @param a_ch
 * @param a_type
 * @param a_format
 * @return
 */
size_t dap_stream_ch_pkt_write_f_inter(dap_events_socket_t * a_queue  , dap_stream_ch_t *a_ch, uint8_t a_type, const char * a_format,...)
{
    va_list ap;
    va_start(ap,a_format);
    int l_data_size = dap_vsnprintf(NULL,0,a_format,ap);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Can't write out formatted data '%s' with values",a_format);
        return 0;
    }
    l_data_size++; // To calc trailing zero
    dap_stream_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_stream_worker_msg_io_t);
    l_msg->ch = a_ch;
    l_msg->ch_pkt_type = a_type;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size);
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    l_data_size = dap_vsnprintf(l_msg->data,0,a_format,ap);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Can't write out formatted data '%s' with values",a_format);
        DAP_DELETE(l_msg);
        return 0;
    }
    l_data_size++;
    l_msg->data_size = l_data_size;
    int l_ret= dap_events_socket_queue_ptr_send_to_input(a_queue , l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return l_data_size;

}

/**
 * @brief dap_stream_ch_pkt_write_mt
 * @param a_ch
 * @param a_type
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_stream_ch_pkt_write_mt(dap_stream_worker_t * a_worker , dap_stream_ch_t *a_ch, uint8_t a_type, const void * a_data, size_t a_data_size)
{
    dap_stream_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_stream_worker_msg_io_t);
    l_msg->ch = a_ch;
    l_msg->ch_pkt_type = a_type;
    l_msg->data = DAP_NEW_SIZE(void,a_data_size);
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    l_msg->data_size = a_data_size;
    memcpy( l_msg->data, a_data, a_data_size);
    int l_ret= dap_events_socket_queue_ptr_send(a_worker->queue_ch_io , l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return a_data_size;
}


/**
 * @brief dap_stream_ch_pkt_write_inter
 * @param a_queue
 * @param a_ch
 * @param a_type
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_stream_ch_pkt_write_inter(dap_events_socket_t * a_queue , dap_stream_ch_t *a_ch, uint8_t a_type, const void * a_data, size_t a_data_size)
{
    dap_stream_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_stream_worker_msg_io_t);
    l_msg->ch = a_ch;
    l_msg->ch_pkt_type = a_type;
    l_msg->data = DAP_NEW_SIZE(void,a_data_size);
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    l_msg->data_size = a_data_size;
    memcpy( l_msg->data, a_data, a_data_size);
    int l_ret= dap_events_socket_queue_ptr_send_to_input(a_queue , l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return a_data_size;
}

/**
 * @brief dap_stream_ch_check_unsafe
 * @param a_worker
 * @param a_ch
 * @return
 */
bool dap_stream_ch_check_unsafe(dap_stream_worker_t * a_worker,dap_stream_ch_t * a_ch)
{
    if (a_ch){
        if ( a_worker->channels){
            dap_stream_ch_t * l_ch = NULL;
            pthread_rwlock_rdlock(&a_worker->channels_rwlock);
            HASH_FIND(hh_worker,a_worker->channels ,&a_ch, sizeof(a_ch), l_ch );
            pthread_rwlock_unlock(&a_worker->channels_rwlock);
            return l_ch == a_ch;
        }else
            return false;
    }else
        return false;
}



/**
 * @brief stream_ch_pkt_write
 * @param sid
 * @param data
 * @param data_size
 * @return
 */
size_t dap_stream_ch_pkt_write_unsafe(dap_stream_ch_t * a_ch,  uint8_t a_type, const void * a_data, size_t a_data_size)
{
    if (!a_ch) {
        log_it(L_WARNING, "Channel is NULL ptr");
        return 0;
    }
    //log_it(L_DEBUG,"Output: Has %u bytes of %c type for %c channel id",data_size, (char)type, (char) ch->proc->id );

    dap_stream_ch_pkt_hdr_t l_hdr;

    memset(&l_hdr,0,sizeof(l_hdr));
    l_hdr.id = a_ch->proc->id;
    l_hdr.size=(uint32_t) a_data_size;
    l_hdr.type=a_type;
    l_hdr.enc_type = a_ch->proc->enc_type;

    l_hdr.seq_id=a_ch->stream->seq_id;
    a_ch->stream->seq_id++;

    if ( dap_stream_get_dump_packet_headers() ){
        log_it(L_INFO,"Outgoing channel packet: id='%c' size=%u type=0x%02Xu seq_id=0x%016X enc_type=0x%02hhX",
            (char) l_hdr.id, l_hdr.size, l_hdr.type, l_hdr.seq_id , l_hdr.enc_type );
    }

    uint8_t * l_buf_selected = a_ch->buf;
    uint8_t * l_buf_allocated = NULL;
    size_t  l_buf_size_required = a_data_size + sizeof(l_hdr);

    if(l_buf_size_required > sizeof(a_ch->buf) ){
        log_it(L_WARNING,"packet size is way too big: %lu bytes", a_data_size);
        l_buf_allocated = DAP_NEW_Z_SIZE(uint8_t, l_buf_size_required);
        l_buf_selected = l_buf_allocated;
    }
    
    memcpy(l_buf_selected,&l_hdr,sizeof(l_hdr) );
    if( a_data_size )
        memcpy(l_buf_selected+sizeof(l_hdr),a_data,a_data_size );

    size_t l_ret=dap_stream_pkt_write_unsafe(a_ch->stream,l_buf_selected,a_data_size+sizeof(l_hdr));
    a_ch->stat.bytes_write+=a_data_size;
    dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);

    if(l_buf_allocated)
        DAP_DELETE(l_buf_allocated);
    return l_ret;

}

/**
 * @brief stream_ch_pkt_write_str
 * @param sid
 * @param str
 * @return
 */
size_t dap_stream_ch_pkt_write_f_unsafe(struct dap_stream_ch * a_ch, uint8_t a_type, const char * a_str,...)
{
    char l_buf[4096];
    va_list ap;
    va_start(ap,a_str);
    dap_vsnprintf(l_buf,sizeof(l_buf),a_str,ap);
    va_end(ap);
    size_t ret=dap_stream_ch_pkt_write_unsafe(a_ch,a_type,l_buf,strlen(l_buf));
    return ret;
}
