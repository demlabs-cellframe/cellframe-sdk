#include <time.h>
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
#include "dap_serialize.h"

#define LOG_TAG "dap_chain_ch_pkt"

const dap_serialize_field_t g_dap_chain_ch_pkt_hdr_fields[] = {
    {
        .name = "version",
        .type = DAP_SERIALIZE_TYPE_UINT8,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_ch_pkt_hdr_mem_t, version),
        .size = sizeof(uint8_t),
    },
    {
        .name = "num_hi",
        .type = DAP_SERIALIZE_TYPE_UINT8,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_ch_pkt_hdr_mem_t, num_hi),
        .size = sizeof(uint8_t),
    },
    {
        .name = "num_lo",
        .type = DAP_SERIALIZE_TYPE_UINT16,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_ch_pkt_hdr_mem_t, num_lo),
        .size = sizeof(uint16_t),
    },
    {
        .name = "data_size",
        .type = DAP_SERIALIZE_TYPE_UINT32,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_ch_pkt_hdr_mem_t, data_size),
        .size = sizeof(uint32_t),
    },
    {
        .name = "net_id",
        .type = DAP_SERIALIZE_TYPE_BYTES_FIXED,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_ch_pkt_hdr_mem_t, net_id),
        .size = DAP_CHAIN_NET_ID_SIZE,
    },
    {
        .name = "chain_id",
        .type = DAP_SERIALIZE_TYPE_BYTES_FIXED,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_ch_pkt_hdr_mem_t, chain_id),
        .size = DAP_CHAIN_ID_SIZE,
    },
    {
        .name = "cell_id",
        .type = DAP_SERIALIZE_TYPE_BYTES_FIXED,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_ch_pkt_hdr_mem_t, cell_id),
        .size = DAP_CHAIN_SHARD_ID_SIZE,
    },
};

const dap_serialize_schema_t g_dap_chain_ch_pkt_hdr_schema = {
    .name = "chain_ch_pkt_hdr",
    .version = 1,
    .struct_size = sizeof(dap_chain_ch_pkt_hdr_mem_t),
    .field_count = sizeof(g_dap_chain_ch_pkt_hdr_fields) / sizeof(g_dap_chain_ch_pkt_hdr_fields[0]),
    .fields = g_dap_chain_ch_pkt_hdr_fields,
    .magic = DAP_CHAIN_CH_PKT_HDR_MAGIC,
    .validate_func = NULL,
};

static void s_chain_pkt_fill(dap_chain_ch_pkt_t *a_pkt, dap_chain_net_id_t a_net_id,
                             dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                             const void *a_data, size_t a_data_size, uint8_t a_version)
{
    *a_pkt = (dap_chain_ch_pkt_t) {
            .hdr = { .version = a_version,
                     .data_size = a_data_size,
                     .net_id = a_net_id,
                     .cell_id = a_cell_id,
                     .chain_id = a_chain_id }
    };
    if (a_data_size && a_data)
        memcpy(a_pkt->data, a_data, a_data_size);
}

/**
 * @brief dap_stream_ch_net_pkt_write
 * @param sid
 * @param data
 * @param data_size
 * @return
 */
size_t dap_chain_ch_pkt_write_unsafe(dap_stream_ch_t *a_ch, uint8_t a_type,
                                     dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                     const void *a_data, size_t a_data_size, uint8_t a_version)
{
    size_t l_chain_pkt_size = sizeof(dap_chain_ch_pkt_hdr_t) + a_data_size;
    dap_chain_ch_pkt_t *l_chain_pkt = l_chain_pkt_size > 0x3FFF
            ? DAP_NEW_Z_SIZE(dap_chain_ch_pkt_t, l_chain_pkt_size)
            : DAP_NEW_STACK_SIZE(dap_chain_ch_pkt_t, l_chain_pkt_size);

    if (!l_chain_pkt) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return 0;
    }
    s_chain_pkt_fill(l_chain_pkt, a_net_id, a_chain_id, a_cell_id, a_data, a_data_size, a_version);

    size_t l_ret = dap_stream_ch_pkt_write_unsafe(a_ch, a_type, l_chain_pkt, l_chain_pkt_size);
    if (l_chain_pkt_size > 0x3FFF)
        DAP_DELETE(l_chain_pkt);
    return l_ret;
}

dap_chain_ch_pkt_t *dap_chain_ch_pkt_new(dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                         const void *a_data, size_t a_data_size, uint8_t a_version)
{
    size_t l_chain_pkt_size = sizeof(dap_chain_ch_pkt_hdr_t) + a_data_size;
    dap_chain_ch_pkt_t *l_chain_pkt = DAP_NEW_Z_SIZE(dap_chain_ch_pkt_t, l_chain_pkt_size);
    if (l_chain_pkt)
        s_chain_pkt_fill(l_chain_pkt, a_net_id, a_chain_id, a_cell_id, a_data, a_data_size, a_version);
    else
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
    return l_chain_pkt;
}
/**
 * @brief dap_chain_ch_pkt_write
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
size_t dap_chain_ch_pkt_write(dap_stream_worker_t *a_worker, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type,
                                 dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                 const void *a_data, size_t a_data_size, uint8_t a_version)
{
    size_t l_chain_pkt_size = sizeof(dap_chain_ch_pkt_hdr_t) + a_data_size;
    dap_chain_ch_pkt_t *l_chain_pkt = l_chain_pkt_size > 0x3FFF
            ? DAP_NEW_Z_SIZE(dap_chain_ch_pkt_t, l_chain_pkt_size)
            : DAP_NEW_STACK_SIZE(dap_chain_ch_pkt_t, l_chain_pkt_size);

    if (!l_chain_pkt) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return 0;
    }
    s_chain_pkt_fill(l_chain_pkt, a_net_id, a_chain_id, a_cell_id, a_data, a_data_size, a_version);

    size_t l_ret = dap_stream_ch_pkt_write(a_worker, a_ch_uuid, a_type, l_chain_pkt, l_chain_pkt_size);
    if (l_chain_pkt_size > 0x3FFF)
        DAP_DELETE(l_chain_pkt);
    return l_ret;
}
