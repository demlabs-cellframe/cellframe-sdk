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
int stream_ch_pkt_init()
{

    return 0;
}

void stream_ch_pkt_deinit()
{

}


/**
 * @brief stream_ch_pkt_write
 * @param sid
 * @param data
 * @param data_size
 * @return
 */
size_t stream_ch_pkt_write(struct dap_stream_ch * ch,  uint8_t type, const void * data, uint32_t data_size)
{
    pthread_mutex_lock( &ch->mutex);

    //log_it(L_DEBUG,"Output: Has %u bytes of %c type for %c channel id",data_size, (char)type, (char) ch->proc->id );

    dap_stream_ch_pkt_hdr_t hdr;

    memset(&hdr,0,sizeof(hdr));
    hdr.id = ch->proc->id;
    hdr.size=data_size;
    hdr.type=type;
    hdr.enc_type = ch->proc->enc_type;
    hdr.seq_id=ch->stream->seq_id;
    ch->stream->seq_id++;

    if(data_size+sizeof(hdr)> sizeof(ch->buf) ){
        log_it(L_ERROR,"Too big data size %lu, bigger than encryption buffer size %lu",data_size,sizeof(ch->buf));
        data_size=sizeof(ch->buf)-sizeof(hdr);
    }
    memcpy(ch->buf,&hdr,sizeof(hdr) );
    memcpy(ch->buf+sizeof(hdr),data,data_size );

    size_t ret=dap_stream_pkt_write(ch->stream,ch->buf,data_size+sizeof(hdr));
    ch->stat.bytes_write+=data_size;
    pthread_mutex_unlock( &ch->mutex);
    return ret;

}

/**
 * @brief stream_ch_pkt_write_str
 * @param sid
 * @param str
 * @return
 */
size_t stream_ch_pkt_write_f(struct dap_stream_ch * ch, uint8_t type, const char * str,...)
{
    char buf[4096];
    va_list ap;
    va_start(ap,str);
    vsnprintf(buf,sizeof(buf),str,ap);
    va_end(ap);
    size_t ret=stream_ch_pkt_write(ch,type,buf,strlen(buf));
    return ret;
}

/**
 * @brief stream_ch_send_keepalive
 * @param ch
 * @return
 */
size_t stream_ch_send_keepalive(struct dap_stream_ch * ch){
    pthread_mutex_lock( &ch->mutex);

    dap_stream_ch_pkt_hdr_t hdr;

    memset(&hdr,0,sizeof(hdr));
    hdr.id = ch->proc->id;
    hdr.size=0;
    hdr.type=KEEPALIVE_PACKET;
    hdr.enc_type = ch->proc->enc_type;
    hdr.seq_id=0;

    memcpy(ch->buf,&hdr,sizeof(hdr) );

    size_t ret=dap_stream_pkt_write(ch->stream,ch->buf,sizeof(hdr));
    pthread_mutex_unlock( &ch->mutex);
    return ret;
}
