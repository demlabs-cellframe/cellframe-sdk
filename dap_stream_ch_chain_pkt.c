#include <string.h>
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_chain.h"

#define LOG_TAG "dap_stream_ch_chain_pkt"

/**
 * @brief dap_stream_ch_net_pkt_write
 * @param sid
 * @param data
 * @param data_size
 * @return
 */
size_t dap_stream_ch_chain_pkt_write(dap_stream_ch_t *a_ch, uint8_t a_type,dap_chain_net_id_t a_net_id,
                                     dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
        const void * a_data, size_t a_data_size)
{
    dap_stream_ch_chain_pkt_t * l_chain_pkt;
    size_t l_chain_pkt_size = sizeof (l_chain_pkt->hdr) + a_data_size;
    l_chain_pkt = DAP_NEW_Z_SIZE(dap_stream_ch_chain_pkt_t, l_chain_pkt_size );
    l_chain_pkt->hdr.version = 1;
    l_chain_pkt->hdr.net_id.uint64 = a_net_id.uint64;
    l_chain_pkt->hdr.cell_id.uint64 = a_cell_id.uint64;
    l_chain_pkt->hdr.chain_id.uint64 = a_chain_id.uint64;

    if (a_data_size && a_data)
        memcpy( l_chain_pkt->data, a_data, a_data_size);

    size_t l_ret  = dap_stream_ch_pkt_write(a_ch, a_type , l_chain_pkt, l_chain_pkt_size);
    DAP_DELETE(l_chain_pkt);
    return l_ret;
}
