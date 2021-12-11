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
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include "dap_common.h"
//#include "config.h"


#include "dap_events_socket.h"
#include "dap_worker.h"
#include "dap_http_client.h"

#include "dap_enc.h"
#include "dap_enc_key.h"

#include "dap_stream.h"
#include "dap_stream_pkt.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_proc.h"

#include "dap_enc_iaes.h"

#define LOG_TAG "stream_pkt"



static const size_t s_dap_hdr_size=8+2+1+1+4;
const uint8_t c_dap_stream_sig[8]={0xa0,0x95,0x96,0xa9,0x9e,0x5c,0xfb,0xfa};

dap_stream_pkt_t * dap_stream_pkt_detect(void * a_data, size_t data_size)
{
    uint8_t * sig_start=(uint8_t*) a_data;
    dap_stream_pkt_t * ret=NULL;

    size_t length_left=data_size;

    while( (sig_start=memchr(sig_start, c_dap_stream_sig[0],length_left)) != NULL ){
        length_left = data_size - (size_t)(sig_start - (uint8_t *)a_data);
        if(length_left < sizeof(c_dap_stream_sig) )
            break;
        if(memcmp(sig_start,c_dap_stream_sig,sizeof(c_dap_stream_sig))==0){
            ret = (dap_stream_pkt_t *)sig_start;
            if (length_left < sizeof(dap_stream_ch_pkt_hdr_t)) {
                //log_it(L_ERROR, "Too small packet size %zu", length_left); // it's not an error, just random case
                ret = NULL;
                break;
            }
            if(ret->hdr.size > STREAM_PKT_SIZE_MAX ){
                log_it(L_ERROR, "Too big packet size %u",ret->hdr.size);
                ret = NULL;
            }
            break;
        } else
            sig_start++;
    }

    return ret;
}

/**
 * @brief s_encode_dummy
 * @param a_buf
 * @param a_buf_size
 * @param a_buf_out
 * @return
 */
static size_t s_encode_dummy(const void * a_buf, size_t a_buf_size, void * a_buf_out){
    if(memcpy(a_buf_out,a_buf,a_buf_size) != NULL)
        return a_buf_size;
    else
        return 0;
}

/**
 * @brief stream_pkt_read
 * @param sid
 * @param pkt
 * @param buf_out
 */
size_t dap_stream_pkt_read_unsafe( dap_stream_t * a_stream, dap_stream_pkt_t * a_pkt, void * a_buf_out, size_t a_buf_out_size)
{
    size_t ds = a_stream->session->key->dec_na(a_stream->session->key,a_pkt->data,a_pkt->hdr.size,a_buf_out, a_buf_out_size);
//    log_it(L_DEBUG,"Stream decoded %lu bytes ( last bytes 0x%02x 0x%02x 0x%02x 0x%02x ) ", ds,
//           *((uint8_t *)buf_out+ds-4),*((uint8_t *)buf_out+ds-3),*((uint8_t *)buf_out+ds-2),*((uint8_t *)buf_out+ds-1)
//           );
//    size_t mv=35;
//    log_it(L_DEBUG,"(Decoded  bytes with mv %lu bytes 0x%02x 0x%02x 0x%02x 0x%02x ) ", mv,
//           *((uint8_t *)buf_out+mv-4),*((uint8_t *)buf_out+mv-3),*((uint8_t *)buf_out+mv-2),*((uint8_t *)buf_out+mv-1)
//           );
    return ds;
}


#define DAP_STREAM_CH_PKT_ENCRYPTION_OVERHEAD 200 //in fact is's about 2*16+15 for OAES

/**
 * @brief stream_ch_pkt_write
 * @param ch
 * @param data
 * @param data_size
 * @return
 */

size_t dap_stream_pkt_write_unsafe(dap_stream_t * a_stream, const void * a_data, size_t a_data_size)
{
    size_t ret=0;
    dap_stream_pkt_hdr_t pkt_hdr;

    uint8_t * l_buf_allocated = NULL;
    uint8_t * l_buf_selected = a_stream->buf;
    size_t  l_buf_size_required = a_data_size + DAP_STREAM_CH_PKT_ENCRYPTION_OVERHEAD;
    
    if(l_buf_size_required > sizeof(a_stream->buf) ){
        l_buf_allocated = DAP_NEW_SIZE(uint8_t, l_buf_size_required);
        l_buf_selected = l_buf_allocated;
    }

    memset(&pkt_hdr,0,sizeof(pkt_hdr));
    memcpy(pkt_hdr.sig,c_dap_stream_sig,sizeof(pkt_hdr.sig));

    pkt_hdr.size =(uint32_t) dap_enc_code( a_stream->session->key, a_data,a_data_size,l_buf_selected, l_buf_size_required, DAP_ENC_DATA_TYPE_RAW);

    ret+=dap_events_socket_write_unsafe(a_stream->esocket,&pkt_hdr,sizeof(pkt_hdr));
    ret+=dap_events_socket_write_unsafe(a_stream->esocket,l_buf_selected,pkt_hdr.size);

    if(l_buf_allocated)
        DAP_DELETE(l_buf_allocated);
    return ret;
}

/**
 * @brief dap_stream_pkt_write_mt
 * @param a_stream_session
 * @param a_es
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_stream_pkt_write_mt(dap_worker_t * a_w,dap_events_socket_uuid_t a_es_uuid, dap_enc_key_t *a_key, const void * a_data, size_t a_data_size)
{
    dap_worker_msg_io_t * l_msg = DAP_NEW_Z(dap_worker_msg_io_t);
    dap_stream_pkt_hdr_t *l_pkt_hdr;
    l_msg->esocket_uuid = a_es_uuid;
    l_msg->data_size = 16-a_data_size%16+a_data_size+sizeof(*l_pkt_hdr);
    l_msg->data = DAP_NEW_SIZE(void,l_msg->data_size);
    l_pkt_hdr=(dap_stream_pkt_hdr_t*) l_msg->data;
    memset(l_pkt_hdr,0,sizeof(*l_pkt_hdr));
    memcpy(l_pkt_hdr->sig,c_dap_stream_sig,sizeof(l_pkt_hdr->sig));
    l_msg->data_size=sizeof (*l_pkt_hdr) +dap_enc_code(a_key, a_data,a_data_size, ((byte_t*)l_msg->data)+sizeof (*l_pkt_hdr),l_msg->data_size-sizeof (*l_pkt_hdr),DAP_ENC_DATA_TYPE_RAW);

    int l_ret= dap_events_socket_queue_ptr_send(a_w->queue_es_io, l_msg );
    if (l_ret!=0){
        log_it(L_ERROR, "Wasn't send pointer to queue: code %d", l_ret);
        DAP_DELETE(l_msg);
        return 0;
    }
    return a_data_size;
}

