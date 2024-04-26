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
#include "dap_chain_ch_pkt.h"
#include "dap_chain.h"

#define LOG_TAG "dap_chain_ch_pkt"

/**
 * @brief dap_stream_ch_net_pkt_write
 * @param sid
 * @param data
 * @param data_size
 * @return
 */
size_t dap_chain_ch_pkt_write_unsafe(dap_stream_ch_t *a_ch, uint8_t a_type,
                                     dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                     const void * a_data, size_t a_data_size)
{
    dap_chain_ch_pkt_t *l_chain_pkt = dap_chain_ch_pkt_new(a_net_id, a_chain_id, a_cell_id, a_data, a_data_size);
    size_t l_ret = dap_stream_ch_pkt_write_unsafe(a_ch, a_type, l_chain_pkt, dap_chain_ch_pkt_get_size(l_chain_pkt));
    DAP_DELETE(l_chain_pkt);
    return l_ret;
}

dap_chain_ch_pkt_t *dap_chain_ch_pkt_new(dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                         const void *a_data, size_t a_data_size)
{
    size_t l_chain_pkt_size = sizeof(dap_chain_ch_pkt_hdr_t) + a_data_size;
    dap_chain_ch_pkt_t *l_chain_pkt = DAP_NEW_Z_SIZE(dap_chain_ch_pkt_t, l_chain_pkt_size);
    if (l_chain_pkt) {
        *l_chain_pkt = (dap_chain_ch_pkt_t) {
                .hdr = { .version = DAP_CHAIN_CH_PKT_VERSION,
                         .data_size = a_data_size,
                         .net_id.uint64 = a_net_id,
                         .cell_id.uint64 = a_cell_id,
                         .chain_id.uint64 = a_chain_id }
        };
        if (a_data_size && a_data)
            memcpy(l_chain_pkt->data, a_data, a_data_size);
    } else
        log_it(L_CRITICAL, g_error_memory_alloc);
    return l_chain_pkt;
}
/**
 * @brief dap_chain_ch_pkt_write_mt
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
size_t dap_chain_ch_pkt_write_mt(dap_stream_worker_t *a_worker, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type,
                                 dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                 const void *a_data, size_t a_data_size)
{
    size_t l_chain_pkt_size = sizeof(dap_chain_ch_pkt_hdr_t) + a_data_size;
    dap_chain_ch_pkt_t *l_chain_pkt = l_chain_pkt_size > 0x3FFF
            ? DAP_NEW_Z_SIZE(dap_chain_ch_pkt_t, l_chain_pkt_size)
            : DAP_NEW_STACK_SIZE(dap_chain_ch_pkt_t, l_chain_pkt_size);
    *l_chain_pkt = (dap_chain_ch_pkt_t){
            .hdr = { .version = DAP_CHAIN_CH_PKT_VERSION, .net_id = a_net_id, .cell_id = a_cell_id, .chain_id = a_chain_id }
    };

    if (a_data_size && a_data)
        memcpy(l_chain_pkt->data, a_data, a_data_size);

    size_t l_ret = dap_stream_ch_pkt_write_mt(a_worker, a_ch_uuid, a_type, l_chain_pkt, l_chain_pkt_size);
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
size_t dap_chain_ch_pkt_write_inter(dap_events_socket_t *a_es_input, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type,
                                    dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                    const void * a_data, size_t a_data_size)
{
    size_t l_chain_pkt_size = sizeof(dap_chain_ch_pkt_hdr_t) + a_data_size;
    dap_chain_ch_pkt_t *l_chain_pkt = DAP_NEW_Z_SIZE(dap_chain_ch_pkt_t, l_chain_pkt_size );
    *l_chain_pkt = (dap_chain_ch_pkt_t){
            .hdr = { .version = DAP_CHAIN_CH_PKT_VERSION, .net_id.uint64 = a_net_id, .cell_id.uint64 = a_cell_id, .chain_id.uint64 = a_chain_id }
    };

    if (a_data_size && a_data)
        memcpy(l_chain_pkt->data, a_data, a_data_size);

    size_t l_ret = dap_stream_ch_pkt_write_inter(a_es_input, a_ch_uuid, a_type, l_chain_pkt, l_chain_pkt_size);
    DAP_DELETE(l_chain_pkt);
    return l_ret;
}
