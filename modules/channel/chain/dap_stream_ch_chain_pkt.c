#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include "dap_stream_ch.h"
#include "dap_stream_worker.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_chain.h"

#define LOG_TAG "dap_stream_ch_chain_pkt"


/**
 * @brief dap_stream_ch_chain_pkt_to_dap_stream_ch_chain_state
 * @param a_state
 * @return
 */
dap_stream_ch_chain_state_t dap_stream_ch_chain_pkt_type_to_dap_stream_ch_chain_state(char a_state)
{
    switch (a_state) {
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL:
        return CHAIN_STATE_SYNC_ALL;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB:
        return CHAIN_STATE_SYNC_GLOBAL_DB;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS:
        return CHAIN_STATE_SYNC_CHAINS;
    }
    return CHAIN_STATE_IDLE;
}

/**
 * @brief dap_stream_ch_net_pkt_write
 * @param sid
 * @param data
 * @param data_size
 * @return
 */
size_t dap_stream_ch_chain_pkt_write_unsafe(dap_stream_ch_t *a_ch, uint8_t a_type, uint64_t a_net_id,
                                            uint64_t a_chain_id, uint64_t a_cell_id,
                                            const void * a_data, size_t a_data_size)
{
    size_t l_chain_pkt_size = sizeof(dap_stream_ch_chain_pkt_hdr_t) + a_data_size;
    dap_stream_ch_chain_pkt_t *l_chain_pkt = DAP_NEW_Z_SIZE(dap_stream_ch_chain_pkt_t, l_chain_pkt_size);
    *l_chain_pkt = (dap_stream_ch_chain_pkt_t){
            .hdr = { .version = DAP_STREAM_CH_CHAIN_PKT_VERSION, .net_id.uint64 = a_net_id, .cell_id.uint64 = a_cell_id, .chain_id.uint64 = a_chain_id }
    };

    if (a_data_size && a_data)
        memcpy(l_chain_pkt->data, a_data, a_data_size);

    size_t l_ret = dap_stream_ch_pkt_write_unsafe(a_ch, a_type, l_chain_pkt, l_chain_pkt_size);
    DAP_DELETE(l_chain_pkt);
    return l_ret;
}


/**
 * @brief dap_stream_ch_chain_pkt_write_mt
 * @param a_worker
 * @param a_ch_uuid
 * @param a_type
 * @param a_net_id
 * @param a_chain_id
 * @param a_cell_id
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_stream_ch_chain_pkt_write_mt(dap_stream_worker_t *a_worker, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type,uint64_t a_net_id,
                                        uint64_t a_chain_id, uint64_t a_cell_id,
                                        const void * a_data, size_t a_data_size)
{
    size_t l_chain_pkt_size = sizeof(dap_stream_ch_chain_pkt_hdr_t) + a_data_size;
    dap_stream_ch_chain_pkt_t *l_chain_pkt = l_chain_pkt_size > 0x3FFF
            ? DAP_NEW_Z_SIZE(dap_stream_ch_chain_pkt_t, l_chain_pkt_size)
            : DAP_NEW_STACK_SIZE(dap_stream_ch_chain_pkt_t, l_chain_pkt_size);
    *l_chain_pkt = (dap_stream_ch_chain_pkt_t){
            .hdr = { .version = DAP_STREAM_CH_CHAIN_PKT_VERSION, .net_id.uint64 = a_net_id, .cell_id.uint64 = a_cell_id, .chain_id.uint64 = a_chain_id }
    };

    if (a_data_size && a_data)
        memcpy(l_chain_pkt->data, a_data, a_data_size);

    size_t l_ret = dap_stream_ch_pkt_write_mt(a_worker, a_ch_uuid, a_type, l_chain_pkt, l_chain_pkt_size);
    if (l_chain_pkt_size > 0x3FFF)
        DAP_DELETE(l_chain_pkt);
    return l_ret;
}

size_t dap_stream_ch_chain_pkt_write_multi_mt(dap_stream_ch_cachet_t *a_links, size_t a_count, uint8_t a_type,uint64_t a_net_id,
                                        uint64_t a_chain_id, uint64_t a_cell_id,
                                        const void * a_data, size_t a_data_size)
{
    size_t l_chain_pkt_size = sizeof(dap_stream_ch_chain_pkt_hdr_t) + a_data_size;
    dap_stream_ch_chain_pkt_t *l_chain_pkt = l_chain_pkt_size > 0x3FFF
            ? DAP_NEW_Z_SIZE(dap_stream_ch_chain_pkt_t, l_chain_pkt_size)
            : DAP_NEW_STACK_SIZE(dap_stream_ch_chain_pkt_t, l_chain_pkt_size);
    *l_chain_pkt = (dap_stream_ch_chain_pkt_t){
            .hdr = { .version = DAP_STREAM_CH_CHAIN_PKT_VERSION, .net_id.uint64 = a_net_id, .cell_id.uint64 = a_cell_id, .chain_id.uint64 = a_chain_id }
    };

    if (a_data_size && a_data)
        memcpy(l_chain_pkt->data, a_data, a_data_size);
    size_t l_ret = 0, l_tmp = 0, i;
    for (i = 0; i < a_count; ++i) {
        l_tmp = dap_stream_ch_pkt_write_mt(a_links[i].stream_worker, a_links[i].uuid, a_type, l_chain_pkt, l_chain_pkt_size);
        if (!l_tmp) {
            l_ret = 0;
            break;
        } else {
            l_ret += l_tmp;
        }
    }
    if (l_chain_pkt_size > 0x3FFF)
        DAP_DELETE(l_chain_pkt);
    return l_ret;
}

/**
 * @brief Write ch chain packet into the queue input
 * @param a_es_input,
 * @param a_worker
 * @param a_ch
 * @param a_type
 * @param a_net_id
 * @param a_chain_id
 * @param a_cell_id
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_stream_ch_chain_pkt_write_inter(dap_events_socket_t * a_es_input, dap_stream_ch_uuid_t a_ch_uuid,
                                           uint8_t a_type,uint64_t a_net_id,
                                        uint64_t a_chain_id, uint64_t a_cell_id,
                                        const void * a_data, size_t a_data_size)
{
    size_t l_chain_pkt_size = sizeof(dap_stream_ch_chain_pkt_hdr_t) + a_data_size;
    dap_stream_ch_chain_pkt_t *l_chain_pkt = DAP_NEW_Z_SIZE(dap_stream_ch_chain_pkt_t, l_chain_pkt_size );
    *l_chain_pkt = (dap_stream_ch_chain_pkt_t){
            .hdr = { .version = DAP_STREAM_CH_CHAIN_PKT_VERSION, .net_id.uint64 = a_net_id, .cell_id.uint64 = a_cell_id, .chain_id.uint64 = a_chain_id }
    };

    if (a_data_size && a_data)
        memcpy(l_chain_pkt->data, a_data, a_data_size);

    size_t l_ret = dap_stream_ch_pkt_write_inter(a_es_input, a_ch_uuid, a_type, l_chain_pkt, l_chain_pkt_size);
    DAP_DELETE(l_chain_pkt);
    return l_ret;
}
