/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Cellframe       https://cellframe.net
* Demlabs Limited   https://demlabs.net
* Copyright  (c) 2017-2020
* All rights reserved.

This file is part of CellFrame SDK the open source project

CellFrame SDK is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CellFrame SDK is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dap_common.h>
#include <dap_stream.h>
#include <dap_stream_pkt.h>
#include <dap_stream_ch_pkt.h>
#include "dap_stream_ch_chain_net_srv_pkt.h"

#define LOG_TAG "dap_stream_ch_chain_net_srv_pkt"


size_t dap_stream_ch_chain_net_srv_pkt_data_write(dap_stream_ch_t *a_ch,
                                                  dap_chain_net_srv_uid_t a_srv_uid, uint32_t a_usage_id  ,
                                                  const void * a_data, size_t a_data_size)
{
    dap_stream_ch_chain_net_srv_pkt_data_t  * l_pkt_data;
    size_t l_pkt_data_size = sizeof (l_pkt_data->hdr) + a_data_size;
    l_pkt_data = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_data_t, l_pkt_data_size );
    l_pkt_data->hdr.version = 1;
    l_pkt_data->hdr.srv_uid = a_srv_uid;
    l_pkt_data->hdr.usage_id = a_usage_id;
    memcpy( l_pkt_data->data, a_data, a_data_size);
    size_t l_ret  = dap_stream_ch_pkt_write_unsafe( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_DATA , l_pkt_data, l_pkt_data_size);
    DAP_DELETE(l_pkt_data);
    return l_ret;
}

/**
 * @brief dap_stream_ch_chain_net_pkt_write_f
 * @param a_ch
 * @param a_type
 * @param a_net_id
 * @param a_str
 * @return
 */
size_t dap_stream_ch_chain_net_pkt_write_f(dap_stream_ch_t *a_ch, dap_chain_net_srv_uid_t a_srv_uid, uint32_t a_usage_id, const char *a_str, ...)
{

    va_list ap;
    va_start(ap, a_str);

    size_t l_buf_size = dap_vsnprintf(NULL, 0, a_str, ap);
    char* l_buf = DAP_NEW_Z_SIZE(char, l_buf_size);
    dap_vsnprintf(l_buf, l_buf_size, a_str, ap);
    va_end(ap);
    size_t ret = dap_stream_ch_chain_net_srv_pkt_data_write(a_ch, a_srv_uid, a_usage_id, l_buf, strlen(l_buf));
    DAP_DELETE(l_buf);
    return ret;
}
