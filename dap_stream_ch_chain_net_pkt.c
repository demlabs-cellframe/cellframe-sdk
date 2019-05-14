#include <stdarg.h>
#include <stdio.h>
#include <string.h>

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
size_t dap_stream_ch_chain_net_pkt_write(dap_stream_ch_t *a_ch, uint8_t a_type,
        const void * a_data, uint32_t a_data_size)
{
    dap_stream_ch_chain_net_pkt_t l_hdr;
    memset(&l_hdr, 0, sizeof(l_hdr));
    l_hdr.hdr.type = a_type;
    size_t l_buf_size = sizeof(l_hdr) + a_data_size;
    char *l_buf = DAP_NEW_SIZE(char, l_buf_size);
    memcpy(l_buf, &l_hdr, sizeof(l_hdr));
    memcpy(l_buf + sizeof(l_hdr), a_data, a_data_size);
    size_t l_ret  = dap_stream_ch_pkt_write(a_ch, a_type , l_buf, l_buf_size);
    DAP_DELETE(l_buf);
    return l_ret;
}

/**
 * @brief dap_stream_ch_chain_net_pkt_write_f
 * @param sid
 * @param str
 * @return
 */
size_t dap_stream_ch_chain_net_pkt_write_f(dap_stream_ch_t *a_ch, uint8_t a_type, const char *a_str, ...)
{
    char l_buf[4096];
    va_list ap;
    va_start(ap, a_str);
    vsnprintf(l_buf, sizeof(l_buf), a_str, ap);
    va_end(ap);
    size_t ret = dap_stream_ch_chain_net_pkt_write(a_ch, a_type, l_buf, strlen(l_buf));
    return ret;
}
