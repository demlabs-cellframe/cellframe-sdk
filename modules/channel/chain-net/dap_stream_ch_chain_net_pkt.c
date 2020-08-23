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

#include <dap_common.h>
#include <dap_stream.h>
#include <dap_stream_pkt.h>
#include <dap_stream_ch_pkt.h>
#include "dap_stream_ch_chain_pkt.h"
#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_chain_net_pkt.h"

#define LOG_TAG "dap_stream_ch_chain_net_pkt"

/**
 * @brief dap_stream_ch_net_pkt_write
 * @param sid
 * @param data
 * @param data_size
 * @return
 */
size_t dap_stream_ch_chain_net_pkt_write(dap_stream_ch_t *a_ch, uint8_t a_type,dap_chain_net_id_t a_net_id,
        const void * a_data, size_t a_data_size)
{
    dap_stream_ch_chain_net_pkt_t * l_net_pkt;
    size_t l_net_pkt_size = sizeof (l_net_pkt->hdr) + a_data_size;
    l_net_pkt = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_pkt_t, l_net_pkt_size );
    l_net_pkt->hdr.version = 1;
    l_net_pkt->hdr.net_id.uint64 = a_net_id.uint64;
    memcpy( l_net_pkt->data, a_data, a_data_size);
    size_t l_ret  = dap_stream_ch_pkt_write_unsafe(a_ch, a_type , l_net_pkt, l_net_pkt_size);
    DAP_DELETE(l_net_pkt);
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
size_t dap_stream_ch_chain_net_pkt_write_f(dap_stream_ch_t *a_ch, uint8_t a_type,dap_chain_net_id_t a_net_id, const char *a_str, ...)
{
    char l_buf[4096];
    va_list ap;
    va_start(ap, a_str);
    dap_vsnprintf(l_buf, sizeof(l_buf), a_str, ap);
    va_end(ap);
    size_t ret = dap_stream_ch_chain_net_pkt_write(a_ch, a_type, a_net_id, l_buf, strlen(l_buf));
    return ret;
}
