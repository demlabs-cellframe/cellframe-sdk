/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2022
 * All rights reserved.

 This file is part of AVReStream

 AVReStream is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 AVReStream is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any AVReStream based project.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <stdint.h>

#include "dap_common.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_worker.h"
#include "dap_tsd.h"
#include "dap_events_socket.h"

#include "avrs.h"
#include "avrs_ch_pkt.h"


#define LOG_TAG "avrs_ch_pkt"

/**
 * @brief avrs_ch_pkt_send_retcode
 * @param a_ch
 * @param a_code
 * @param a_text
 * @return
 */
int avrs_ch_pkt_send_retcode_unsafe(dap_stream_ch_t * a_ch, int a_code, const char * a_text)
{
    size_t l_text_size = strlen(a_text) + 1;
    avrs_ch_pkt_retcode_t * l_err = DAP_NEW_STACK_SIZE(avrs_ch_pkt_retcode_t, sizeof(avrs_ch_pkt_retcode_t)+l_text_size);
    l_err->msgnum = a_code;
    memcpy(l_err->msg, a_text, l_text_size);
    if (l_err->msgnum != AVRS_SUCCESS)
        log_it(L_WARNING,"Reply with error %s (%d) ", a_text, a_code);

    if ( dap_stream_ch_pkt_write_unsafe(a_ch, DAP_AVRS$K_CH_RETCODE,
                        l_err, sizeof(avrs_ch_pkt_retcode_t) + l_text_size) == sizeof(avrs_ch_pkt_retcode_t)+l_text_size)
        return 0;

    return -1;
}

/**
 * @brief avrs_ch_pkt_send_retcode_inter
 * @param a_es_input
 * @param a_ch_uuid
 * @param a_code
 * @param a_text
 * @return
 */
int avrs_ch_pkt_send_retcode_inter(dap_events_socket_t * a_es_input, dap_stream_ch_uuid_t a_ch_uuid, int a_code, const char * a_text)
{
    size_t l_text_size = strlen(a_text)+1;
    avrs_ch_pkt_retcode_t * l_err = DAP_NEW_STACK_SIZE(avrs_ch_pkt_retcode_t, sizeof(avrs_ch_pkt_retcode_t)+l_text_size);

    l_err->msgnum = a_code;
    memcpy(l_err->msg, a_text, l_text_size);

    if (dap_stream_ch_pkt_write_inter(a_es_input, a_ch_uuid, 'r', l_err, sizeof(avrs_ch_pkt_retcode_t) + l_text_size) == sizeof(avrs_ch_pkt_retcode_t)+l_text_size)
        return 0;

    return -EIO;
}


/**
 * @brief avrs_ch_pkt_send_cluster
 * @param a_ch
 * @param a_type
 * @param a_args
 * @param a_args_size
 * @return
 */
int avrs_ch_pkt_send_cluster_unsafe(dap_stream_ch_t * a_ch, uint8_t a_type, const void * a_args, size_t a_args_size )
{
size_t l_pkt_cluster_size = sizeof(avrs_ch_pkt_cluster_t) + a_args_size;
avrs_ch_pkt_cluster_t * l_pkt_cluster = DAP_NEW_STACK_SIZE(avrs_ch_pkt_cluster_t, l_pkt_cluster_size);

    memset(l_pkt_cluster,0, sizeof(avrs_ch_pkt_cluster_t));
    l_pkt_cluster->type = a_type;
    memcpy(l_pkt_cluster->args, a_args, a_args_size);

    if ( dap_stream_ch_pkt_write_unsafe(a_ch, DAP_AVRS$K_CH_CLUSTER, l_pkt_cluster, l_pkt_cluster_size) == l_pkt_cluster_size )
        return 0;

    return -EIO;
}

/**
 * @brief avrs_ch_pkt_send_cluster_inter
 * @param a_es_input
 * @param a_ch_uuid
 * @param a_type
 * @param a_args
 * @param a_args_size
 * @return
 */
int avrs_ch_pkt_send_cluster_inter(dap_events_socket_t * a_es_input, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type, const void * a_args, size_t a_args_size )
{
size_t  l_pkt_cluster_size = sizeof(avrs_ch_pkt_cluster_t) + a_args_size, l_rc;
avrs_ch_pkt_cluster_t * l_pkt_cluster = DAP_NEW_STACK_SIZE(avrs_ch_pkt_cluster_t, l_pkt_cluster_size);

    memset(l_pkt_cluster,0, sizeof(avrs_ch_pkt_cluster_t));
    l_pkt_cluster->type = a_type;
    memcpy(l_pkt_cluster->args, a_args, a_args_size);

    if ( dap_stream_ch_pkt_write_inter(a_es_input, a_ch_uuid, DAP_AVRS$K_CH_CLUSTER, l_pkt_cluster,l_pkt_cluster_size) == l_pkt_cluster_size )
        return 0;

    return -EIO;

}

/**
 * @brief avrs_ch_pkt_send_content
 * @param a_ch
 * @param a_flow_id
 * @param a_content_id
 * @param a_data
 * @param a_data_size
 * @return
 */
int avrs_ch_pkt_send_content_unsafe(dap_stream_ch_t * a_ch, uint8_t a_flow_id, uint32_t a_content_id, const void *a_data, size_t a_data_size)
{
size_t l_pkt_content_size = sizeof(avrs_ch_pkt_content_t) + a_data_size;
avrs_ch_pkt_content_t * l_pkt_content = DAP_NEW_STACK_SIZE(avrs_ch_pkt_content_t, l_pkt_content_size);

    memset(l_pkt_content,0, sizeof(avrs_ch_pkt_content_t));
    l_pkt_content->flow_id = a_flow_id;
    memcpy(l_pkt_content->data, a_data, a_data_size);

    if ( dap_stream_ch_pkt_write_unsafe(a_ch,'c',l_pkt_content,l_pkt_content_size) == l_pkt_content_size )
        return 0;

    return -EIO;
}

/**
 * @brief avrs_ch_pkt_send_content_inter
 * @param a_es_input
 * @param a_ch_uuid
 * @param a_flow_id
 * @param a_content_id
 * @param a_data
 * @param a_data_size
 * @return
 */
int avrs_ch_pkt_send_content_inter(dap_events_socket_t * a_es_input, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_flow_id, uint32_t a_content_id, const void *a_data, size_t a_data_size)
{
    size_t l_pkt_content_size = sizeof(avrs_ch_pkt_content_t) + a_data_size;
    avrs_ch_pkt_content_t * l_pkt_content = DAP_NEW_STACK_SIZE(avrs_ch_pkt_content_t, l_pkt_content_size);
    memset(l_pkt_content,0, sizeof(avrs_ch_pkt_content_t));
    l_pkt_content->flow_id = a_flow_id;
    memcpy(l_pkt_content->data, a_data, a_data_size);

    if ( dap_stream_ch_pkt_write_inter( a_es_input, a_ch_uuid ,'c',l_pkt_content,l_pkt_content_size) == l_pkt_content_size )
        return 0;

    return -EIO;
}
