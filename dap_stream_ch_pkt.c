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

#include <stdio.h>
#include <stdarg.h>

#include "dap_common.h"
#include "dap_enc.h"
#include "dap_enc_key.h"

#include "dap_client_remote.h"
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
 * @brief stream_ch_pkt_write
 * @param sid
 * @param data
 * @param data_size
 * @return
 */
size_t dap_stream_ch_pkt_write(struct dap_stream_ch * a_ch,  uint8_t a_type, const void * a_data, size_t a_data_size)
{
    pthread_mutex_lock( &a_ch->mutex);

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

    size_t l_ret=dap_stream_pkt_write(a_ch->stream,a_ch->buf,a_data_size+sizeof(l_hdr));
    a_ch->stat.bytes_write+=a_data_size;
    pthread_mutex_unlock( &a_ch->mutex);
    return l_ret;

}

/**
 * @brief stream_ch_pkt_write_str
 * @param sid
 * @param str
 * @return
 */
size_t dap_stream_ch_pkt_write_f(struct dap_stream_ch * a_ch, uint8_t a_type, const char * a_str,...)
{
    char l_buf[4096];
    va_list ap;
    va_start(ap,a_str);
    vsnprintf(l_buf,sizeof(l_buf),a_str,ap);
    va_end(ap);
    size_t ret=dap_stream_ch_pkt_write(a_ch,a_type,l_buf,strlen(l_buf));
    return ret;
}

/**
 * @brief stream_ch_send_keepalive
 * @param ch
 * @return
 */
size_t dap_stream_ch_send_keepalive(struct dap_stream_ch * a_ch)
{
    pthread_mutex_lock( &a_ch->mutex);

    dap_stream_ch_pkt_hdr_t l_hdr;

    memset(&l_hdr,0,sizeof(l_hdr));
    l_hdr.id = a_ch->proc->id;
    l_hdr.size=0;
    l_hdr.type=STREAM_CH_PKT_TYPE_KEEPALIVE;
    l_hdr.enc_type = a_ch->proc->enc_type;
    l_hdr.seq_id=0;

    memcpy(a_ch->buf,&l_hdr,sizeof(l_hdr) );

    size_t l_ret=dap_stream_pkt_write(a_ch->stream,a_ch->buf,sizeof(l_hdr));
    pthread_mutex_unlock( &a_ch->mutex);
    return l_ret;
}
