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

#include <stdint.h>
#include <string.h>
#include "dap_common.h"
//#include "config.h"


#include "dap_client.h"
#include "dap_http_client.h"

#include "dap_enc.h"
#include "dap_enc_key.h"

#include "stream.h"
#include "stream_pkt.h"
#include "stream_ch.h"
#include "stream_ch_pkt.h"
#include "stream_ch_proc.h"


#define LOG_TAG "stream_pkt"



const size_t dap_hdr_size=8+2+1+1+4;
const uint8_t dap_sig[8]={0xa0,0x95,0x96,0xa9,0x9e,0x5c,0xfb,0xfa};


stream_pkt_t * stream_pkt_detect(void * data, uint32_t data_size)
{
    void * sig_start=data;
    stream_pkt_t * ret=NULL;
    uint32_t length_left=data_size;
    while(sig_start=memchr(sig_start, dap_sig[0],length_left) ){
        length_left= data_size-( sig_start-data);
        if(length_left < sizeof(dap_sig) )
            break;
        if(memcmp(sig_start,dap_sig,sizeof(dap_sig))==0){
            ret=sig_start;
            if(ret->hdr.size > STREAM_PKT_SIZE_MAX ){
                log_it(L_ERROR, "Too big packet size %u",ret->hdr.size);
                ret=NULL;
            }
            break;
        }else
	    sig_start+=1;
    }
    return ret;
}

/**
 * @brief stream_pkt_read
 * @param sid
 * @param pkt
 * @param buf_out
 */
size_t stream_pkt_read(struct stream * sid,struct stream_pkt * pkt, void * buf_out)
{
    size_t ds = enc_decode(sid->session->key,pkt->data,pkt->hdr.size,buf_out,DAP_ENC_DATA_TYPE_RAW);
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

size_t stream_pkt_write(struct stream * sid, const void * data, uint32_t data_size)
{
    size_t ret=0;
    stream_pkt_hdr_t pkt_hdr;

    if(data_size> sizeof(sid->buf) ){
        log_it(L_ERROR,"Too big data size %lu, bigger than encryption buffer size %lu",data_size,sizeof(sid->buf));
        data_size=sizeof(sid->buf);
    }

    memset(&pkt_hdr,0,sizeof(pkt_hdr));
    memcpy(pkt_hdr.sig,dap_sig,sizeof(pkt_hdr.sig));

    pkt_hdr.size = enc_code(sid->session->key,data,data_size,sid->buf,DAP_ENC_DATA_TYPE_RAW);

    ret+=dap_client_write(sid->conn,&pkt_hdr,sizeof(pkt_hdr));
    ret+=dap_client_write(sid->conn,sid->buf,pkt_hdr.size);
    return ret;
}


