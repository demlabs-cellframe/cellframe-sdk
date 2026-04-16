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

#include <dap_common.h>
#include <dap_stream.h>
#include <dap_stream_pkt.h>
#include <dap_stream_ch_pkt.h>
#include "dap_chain_net_ch_pkt.h"
#include "dap_serialize.h"

#define LOG_TAG "dap_chain_net_ch_pkt"

const dap_serialize_field_t g_dap_chain_net_ch_pkt_hdr_fields[] = {
    {
        .name = "version",
        .type = DAP_SERIALIZE_TYPE_UINT8,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_net_ch_pkt_hdr_mem_t, version),
        .size = sizeof(uint8_t),
    },
    {
        .name = "padding",
        .type = DAP_SERIALIZE_TYPE_UINT8,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_net_ch_pkt_hdr_mem_t, padding),
        .size = sizeof(uint8_t),
    },
    {
        .name = "data_size",
        .type = DAP_SERIALIZE_TYPE_UINT16,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_net_ch_pkt_hdr_mem_t, data_size),
        .size = sizeof(uint16_t),
    },
    {
        .name = "net_id",
        .type = DAP_SERIALIZE_TYPE_BYTES_FIXED,
        .flags = DAP_SERIALIZE_FLAG_NONE,
        .offset = offsetof(dap_chain_net_ch_pkt_hdr_mem_t, net_id),
        .size = DAP_CHAIN_NET_ID_SIZE,
    },
};

const dap_serialize_schema_t g_dap_chain_net_ch_pkt_hdr_schema = {
    .name = "chain_net_ch_pkt_hdr",
    .version = 1,
    .struct_size = sizeof(dap_chain_net_ch_pkt_hdr_mem_t),
    .field_count = sizeof(g_dap_chain_net_ch_pkt_hdr_fields) / sizeof(g_dap_chain_net_ch_pkt_hdr_fields[0]),
    .fields = g_dap_chain_net_ch_pkt_hdr_fields,
    .magic = DAP_CHAIN_NET_CH_PKT_HDR_MAGIC,
    .validate_func = NULL,
};

/**
 * @brief dap_stream_ch_net_pkt_write
 * @param sid
 * @param data
 * @param data_size
 * @return
 */
size_t dap_chain_net_ch_pkt_write(dap_stream_ch_t *a_ch, uint8_t a_type,dap_chain_net_id_t a_net_id,
        const void * a_data, size_t a_data_size)
{
    dap_chain_net_ch_pkt_t * l_net_pkt;
    size_t l_net_pkt_size = sizeof (l_net_pkt->hdr) + a_data_size;
    l_net_pkt = DAP_NEW_Z_SIZE(dap_chain_net_ch_pkt_t, l_net_pkt_size );
    l_net_pkt->hdr.version = DAP_STREAM_CH_CHAIN_NET_PKT_VERSION;
    l_net_pkt->hdr.net_id.uint64 = a_net_id.uint64;
    l_net_pkt->hdr.data_size = a_data_size;
    memcpy( l_net_pkt->data, a_data, a_data_size);
    size_t l_ret  = dap_stream_ch_pkt_write_unsafe(a_ch, a_type , l_net_pkt, l_net_pkt_size);
    DAP_DELETE(l_net_pkt);
    return l_ret;
}

/**
 * @brief dap_chain_net_ch_pkt_write_f
 * @param a_ch
 * @param a_type
 * @param a_net_id
 * @param a_str
 * @return
 */
size_t dap_chain_net_ch_pkt_write_f(dap_stream_ch_t *a_ch, uint8_t a_type,dap_chain_net_id_t a_net_id, const char *a_str, ...)
{
    va_list ap, ap_copy;
    va_start(ap, a_str);
    va_copy(ap_copy, ap);
    size_t l_buf_size = vsnprintf(NULL, 0, a_str, ap);
    va_end(ap);

    l_buf_size++; // include trailing 0
    char *l_buf = DAP_NEW_Z_SIZE(char, l_buf_size);
    vsnprintf(l_buf, l_buf_size, a_str, ap_copy);
    va_end(ap_copy);
    size_t ret = dap_chain_net_ch_pkt_write(a_ch, a_type, a_net_id, l_buf, l_buf_size);
    DAP_DELETE(l_buf);
    return ret;
}
