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
 * @param a_ch_uuid
 * @param a_type
 * @param a_str
 * @return
 */
size_t dap_stream_ch_pkt_write_f_mt(dap_stream_worker_t * a_worker , dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type, const char * a_format,...)
{
    if (!a_worker)
        return 0;
    va_list ap;
    va_start(ap,a_format);
    int l_data_size = dap_vsnprintf(NULL,0,a_format,ap);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Can't write out formatted data '%s' with values",a_format);
        va_end(ap);
        return 0;
    }
    l_data_size++; // To calc trailing zero
    dap_stream_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_stream_worker_msg_io_t);
    l_msg->ch_uuid = a_ch_uuid;
    l_msg->ch_pkt_type = a_type;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size);
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    l_data_size = dap_vsnprintf(l_msg->data,0,a_format,ap);
    va_end(ap);
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
 * @param a_ch_uuid
 * @param a_type
 * @param a_format
 * @return
 */
size_t dap_stream_ch_pkt_write_f_inter(dap_events_socket_t * a_queue  , dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type, const char * a_format,...)
{
    va_list ap;
    va_start(ap,a_format);
    int l_data_size = dap_vsnprintf(NULL,0,a_format,ap);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Can't write out formatted data '%s' with values",a_format);
        va_end(ap);
        return 0;
    }
    l_data_size++; // To calc trailing zero
    dap_stream_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_stream_worker_msg_io_t);
    l_msg->ch_uuid = a_ch_uuid;
    l_msg->ch_pkt_type = a_type;
    l_msg->data = DAP_NEW_SIZE(void,l_data_size);
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    l_data_size = dap_vsnprintf(l_msg->data,0,a_format,ap);
    va_end(ap);
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
size_t dap_stream_ch_pkt_write_mt(dap_stream_worker_t * a_worker , dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type, const void * a_data, size_t a_data_size)
{
    if (!a_worker)
        return 0;
    dap_stream_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_stream_worker_msg_io_t);
    l_msg->ch_uuid = a_ch_uuid;
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
 * @param a_ch_uuid
 * @param a_type
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_stream_ch_pkt_write_inter(dap_events_socket_t * a_queue_input, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type, const void * a_data, size_t a_data_size)
{
    dap_stream_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_stream_worker_msg_io_t);
    l_msg->ch_uuid = a_ch_uuid;
    l_msg->ch_pkt_type = a_type;
    l_msg->data = DAP_NEW_SIZE(void,a_data_size);
    l_msg->flags_set = DAP_SOCK_READY_TO_WRITE;
    l_msg->data_size = a_data_size;
    memcpy( l_msg->data, a_data, a_data_size);
    int l_ret= dap_events_socket_queue_ptr_send_to_input(a_queue_input, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return a_data_size;
}

/**
 * @brief dap_stream_ch_pkt_write
 * @param a_ch
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_stream_ch_pkt_write_unsafe(dap_stream_ch_t * a_ch,  uint8_t a_type, const void * a_data, size_t a_data_size)
{
    if (!a_ch) {
        log_it(L_WARNING, "Channel is NULL ptr");
        return 0;
    }
    if (!a_ch->proc) {
        log_it(L_WARNING, "Channel PROC is NULL ptr");
        return 0;
    }
    //log_it(L_DEBUG,"Output: Has %u bytes of %c type for %c channel id",data_size, (char)type, (char) ch->proc->id );



//    size_t l_ret=dap_stream_pkt_write_unsafe(a_ch->stream,l_buf_selected,a_data_size+sizeof(l_hdr));
//    a_ch->stat.bytes_write+=a_data_size;
//    dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);

    size_t  l_ret = 0, l_data_size,
            l_max_size = l_data_size = a_data_size + sizeof(dap_stream_ch_pkt_hdr_t);
    uint8_t *l_buf = a_ch->buf;

    dap_stream_ch_pkt_hdr_t l_hdr = {
        .id         = a_ch->proc->id,
        .size       = (uint32_t)a_data_size,
        .type       = a_type,
        .enc_type   = a_ch->proc->enc_type,
        .seq_id     = a_ch->stream->seq_id++
    };

    debug_if(dap_stream_get_dump_packet_headers(), L_INFO, "Outgoing channel packet: id='%c' size=%u type=0x%02X seq_id=0x%016"DAP_UINT64_FORMAT_X" enc_type=0x%02hhX",
        (char) l_hdr.id, l_hdr.size, l_hdr.type, l_hdr.seq_id , l_hdr.enc_type);

    if (l_data_size > 0 && l_data_size <= DAP_STREAM_PKT_FRAGMENT_SIZE) {
        memcpy(l_buf, &l_hdr, sizeof(dap_stream_ch_pkt_hdr_t));
        memcpy(l_buf + sizeof(dap_stream_ch_pkt_hdr_t), a_data, a_data_size);
        l_ret = dap_stream_pkt_write_unsafe(a_ch->stream, STREAM_PKT_TYPE_DATA_PACKET, l_buf, l_data_size);
    } else if (l_data_size > DAP_STREAM_PKT_FRAGMENT_SIZE) {
        /* The first fragment (has no memory shift) is the channel header
         The rest fragments just concatenate as-is */
        size_t l_fragment_size;
        dap_stream_fragment_pkt_t *l_fragment;
        for (l_fragment = (dap_stream_fragment_pkt_t*)l_buf, l_fragment_size = sizeof(dap_stream_ch_pkt_hdr_t);
             l_data_size > 0;
             l_data_size -= l_fragment_size, l_fragment_size = MIN(l_data_size, DAP_STREAM_PKT_FRAGMENT_SIZE))
        {
            l_fragment->size        = l_fragment_size;
            l_fragment->full_size   = l_max_size;
            l_fragment->mem_shift   = l_max_size - l_data_size;
            memcpy(l_fragment->data, l_fragment->mem_shift ? a_data + l_fragment->mem_shift - sizeof(dap_stream_ch_pkt_hdr_t) : &l_hdr,
                   l_fragment_size);
            l_ret += dap_stream_pkt_write_unsafe(a_ch->stream, STREAM_PKT_TYPE_FRAGMENT_PACKET, l_fragment,
                                                  l_fragment_size + sizeof(dap_stream_fragment_pkt_t));
        }
        dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
    } else {
        a_ch->stat.bytes_write = 0;
        log_it(L_WARNING, "Empty pkt, seq_id %"DAP_UINT64_FORMAT_U, l_hdr.seq_id);
        return 0;
    }
    // Statistics without header sizes
    a_ch->stat.bytes_write += a_data_size;
    return l_ret;

}

/**
 * @brief dap_stream_ch_pkt_write_str
 * @param a_ch
 * @param a_type
 * @param a_str
 * @return
 */
size_t dap_stream_ch_pkt_write_f_unsafe(dap_stream_ch_t * a_ch, uint8_t a_type, const char * a_str,...)
{
    char l_buf[4096];
    va_list ap;
    va_start(ap,a_str);
    dap_vsnprintf(l_buf,sizeof(l_buf),a_str,ap);
    va_end(ap);
    size_t ret=dap_stream_ch_pkt_write_unsafe(a_ch,a_type,l_buf,strlen(l_buf));
    return ret;
}
