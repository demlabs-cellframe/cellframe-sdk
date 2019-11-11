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

#ifdef WIN32
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <wepoll.h>
#include <pthread.h>
#endif

#include "dap_common.h"
//#include "config.h"


#include "dap_client_remote.h"
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
        length_left= data_size- (size_t)  ( sig_start- (uint8_t *) a_data);
        if(length_left < sizeof(c_dap_stream_sig) )
            break;
        if(memcmp(sig_start,c_dap_stream_sig,sizeof(c_dap_stream_sig))==0){
            ret= (dap_stream_pkt_t*) sig_start;
            if(ret->hdr.size > STREAM_PKT_SIZE_MAX ){
                //log_it(L_ERROR, "Too big packet size %u",ret->hdr.size);
                ret=NULL;
            }
            break;
        }else
        sig_start+=1;
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
size_t dap_stream_pkt_read( dap_stream_t * a_stream, dap_stream_pkt_t * a_pkt, void * a_buf_out, size_t a_buf_out_size)
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



/**
 * @brief stream_ch_pkt_write
 * @param ch
 * @param data
 * @param data_size
 * @return
 */

size_t dap_stream_pkt_write(dap_stream_t * a_stream, const void * a_data, size_t a_data_size)
{
    size_t ret=0;
    stream_pkt_hdr_t pkt_hdr;

    if(a_data_size > STREAM_BUF_SIZE_MAX ){
        log_it(L_ERROR,"Too big data size %lu, bigger than encryption buffer size %lu",a_data_size,sizeof(a_stream->buf));
        a_data_size=sizeof(a_stream->buf);
    }

    memset(&pkt_hdr,0,sizeof(pkt_hdr));
    memcpy(pkt_hdr.sig,c_dap_stream_sig,sizeof(pkt_hdr.sig));

    pkt_hdr.size =(uint32_t) a_stream->session->key->enc_na(a_stream->session->key, a_data,a_data_size,a_stream->buf, STREAM_BUF_SIZE_MAX);
//    printf("*[dap_stream_pkt_write] size=%d key=0x%x _inheritor_size=%d\n", pkt_hdr.size, sid->session->key,
//            sid->session->key->_inheritor_size);

    if(a_stream->conn_udp){
        ret+=dap_udp_client_write(a_stream->conn,&pkt_hdr,sizeof(pkt_hdr));
        ret+=dap_udp_client_write(a_stream->conn,a_stream->buf,pkt_hdr.size);
    }
    else if(a_stream->conn){
        ret+=dap_client_remote_write(a_stream->conn,&pkt_hdr,sizeof(pkt_hdr));
        ret+=dap_client_remote_write(a_stream->conn,a_stream->buf,pkt_hdr.size);
    }
    else if(a_stream->events_socket) {
        ret += dap_events_socket_write(a_stream->events_socket, &pkt_hdr, sizeof(pkt_hdr));
        ret += dap_events_socket_write(a_stream->events_socket, a_stream->buf, pkt_hdr.size);
        }

    return ret;
}



/**
 * @brief dap_stream_send_keepalive
 * @param a_stream
 */
void dap_stream_send_keepalive(dap_stream_t * a_stream)
{
    dap_stream_ch_pkt_hdr_t l_pkt={0};
    l_pkt.id = TECHICAL_CHANNEL_ID;
    l_pkt.type=STREAM_CH_PKT_TYPE_KEEPALIVE;

    if( dap_stream_pkt_write( a_stream, &l_pkt, sizeof(l_pkt) ) )
        dap_stream_set_ready_to_write( a_stream, true );
}

