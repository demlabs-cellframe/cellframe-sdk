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
size_t dap_stream_ch_pkt_write_f_mt(dap_events_socket_t *a_es, dap_enc_key_t *a_key, uint8_t a_type, const char * a_str,...)
{

}

/**
 * @brief dap_stream_ch_pkt_write_mt
 * @param a_ch
 * @param a_type
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_stream_ch_pkt_write_mt(dap_events_socket_t *a_es, dap_enc_key_t *a_key,  uint8_t a_type, const void * a_data, size_t a_data_size)
{

}


/**
 * @brief stream_ch_pkt_write
 * @param sid
 * @param data
 * @param data_size
 * @return
 */
size_t dap_stream_ch_pkt_write_unsafe(struct dap_stream_ch * a_ch,  uint8_t a_type, const void * a_data, size_t a_data_size)
{
    if (! a_data_size){
        log_it(L_WARNING,"Zero data size to write out in channel");
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


    if(a_data_size+sizeof(l_hdr)> sizeof(a_ch->buf) ){
        log_it(L_ERROR,"Too big data size %lu, bigger than encryption buffer size %lu", a_data_size, sizeof(a_ch->buf));
        a_data_size=sizeof(a_ch->buf)-sizeof(l_hdr);
    }
    memcpy(a_ch->buf,&l_hdr,sizeof(l_hdr) );
    if( a_data_size )
        memcpy(a_ch->buf+sizeof(l_hdr),a_data,a_data_size );

    size_t l_ret=dap_stream_pkt_write_unsafe(a_ch->stream,a_ch->buf,a_data_size+sizeof(l_hdr));
    a_ch->stat.bytes_write+=a_data_size;
    a_ch->ready_to_write=true;
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

