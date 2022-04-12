

#pragma once

#include <pthread.h>

#include "dap_chain_common.h"
#include "dap_chain.h"
#include "dap_chain_global_db_remote.h"
#include "dap_chain_node_client.h"
#include "dap_list.h"
// #include "dap_stream_ch_chain_pkt.h"
#include "uthash.h"

#define DAP_STREAM_CH_CHAIN_VOTING_PKT_TYPE_TEST                     0x01
#define DAP_STREAM_CH_CHAIN_VOTING_PKT_TYPE_TEST_RES                 0x02

typedef void (*voting_ch_callback_t) (void*,dap_chain_node_addr_t*,dap_chain_hash_fast_t*,uint8_t*,size_t);

// typedef struct dap_stream_ch_chain_pkt_hdr{
//     union{
//         struct{
//             uint8_t version;
//             uint8_t padding[7];
//         } DAP_ALIGN_PACKED;
//         uint64_t ext_id;
//     }DAP_ALIGN_PACKED;
//     dap_chain_net_id_t net_id;
//     dap_chain_id_t chain_id;
//     dap_chain_cell_id_t cell_id;
// }  DAP_ALIGN_PACKED dap_stream_ch_chain_pkt_hdr_t;

typedef struct dap_stream_ch_chain_voting_pkt_hdr {
    uint8_t pkt_type;
    union{
        struct{
            uint8_t version;
            uint8_t padding[7];
        } DAP_ALIGN_PACKED;
        uint64_t ext_id;
    }DAP_ALIGN_PACKED;
    size_t data_size;
    dap_chain_hash_fast_t data_hash;
    dap_chain_net_id_t net_id;
    dap_chain_node_addr_t sender_node_addr;
    dap_chain_node_addr_t recipient_node_addr;
    // dap_chain_id_t chain_id;
    // dap_chain_cell_id_t cell_id;
}  DAP_ALIGN_PACKED dap_stream_ch_chain_voting_pkt_hdr_t;

typedef struct dap_stream_ch_chain_voting_pkt {
    dap_stream_ch_chain_voting_pkt_hdr_t hdr;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_stream_ch_chain_voting_pkt_t;


typedef struct dap_stream_ch_chain_voting dap_stream_ch_chain_voting_t;
typedef void (*dap_stream_ch_chain_voting_callback_packet_t)(dap_stream_ch_chain_voting_t*, uint8_t a_pkt_type,
                                                      dap_stream_ch_chain_voting_pkt_t *a_pkt, size_t a_pkt_data_size,
                                                      void * a_arg);

typedef struct dap_stream_ch_chain_voting {
    //void *_inheritor;
    dap_stream_ch_t * ch;
    //dap_stream_ch_chain_state_t state;
    dap_chain_node_client_t * node_client; // Node client associated with stream

    // request section
    //dap_stream_ch_chain_sync_request_t request;
    //dap_stream_ch_chain_pkt_hdr_t request_hdr;
    //dap_list_t *request_db_iter;

    //bool was_active;

    //dap_stream_ch_chain_voting_callback_packet_t callback_notify_packet_out;
    dap_stream_ch_chain_voting_callback_packet_t callback_notify;
    void *callback_notify_arg;
} dap_stream_ch_chain_voting_t;

#define DAP_STREAM_CH_CHAIN_VOTING(a) ((dap_stream_ch_chain_voting_t *) ((a)->internal) )

inline static uint8_t dap_stream_ch_chain_voting_get_id(void) { return (uint8_t) 'V'; }

void dap_stream_ch_chain_voting_in_callback_add(void* a_arg, voting_ch_callback_t packet_in_callback);

void dap_stream_ch_chain_voting_message_write(dap_chain_net_t * a_net, dap_list_t *a_sendto_nodes, 
                                                dap_chain_hash_fast_t * a_data_hash,
                                                    const void * a_data, size_t a_data_size);
void dap_stream_ch_chain_voting_pkt_broadcast(dap_chain_net_t * a_net, dap_list_t *a_sendto_nodes);

// size_t dap_stream_ch_chain_voting_pkt_write_mt(dap_stream_worker_t *a_worker, dap_stream_ch_uuid_t a_ch_uuid,
//                                         uint8_t a_type,uint64_t a_net_id,
//                                         const void * a_data, size_t a_data_size);

size_t dap_stream_ch_chain_voting_pkt_write_unsafe(dap_stream_ch_t *a_ch, uint8_t a_type, uint64_t a_net_id,
                                                    const void * a_data, size_t a_data_size);

int dap_stream_ch_chain_voting_init();
void dap_stream_ch_chain_voting_deinit();
