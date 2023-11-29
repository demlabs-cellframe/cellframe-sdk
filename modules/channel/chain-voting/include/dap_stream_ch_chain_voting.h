#pragma once

#include <pthread.h>

#include "dap_chain_common.h"
#include "dap_chain.h"
#include "dap_global_db_remote.h"
#include "dap_chain_node_client.h"
#include "dap_list.h"
// #include "dap_stream_ch_chain_pkt.h"
#include "uthash.h"

#define DAP_STREAM_CH_CHAIN_VOTING_PKT_TYPE_DATA        0x01
#define DAP_STREAM_CH_CHAIN_VOTING_PKT_TYPE_TEST        0x02

#define DAP_STREAM_CH_ID_VOTING 'V'

typedef void (*dap_chain_voting_ch_callback_t)(void *a_arg, dap_chain_node_addr_t *a_sender_addr, dap_chain_node_addr_t *a_receiver_addr,
                                               dap_chain_hash_fast_t *a_data_hash, uint8_t *a_data, size_t a_data_size);

typedef struct dap_stream_ch_chain_voting_pkt_hdr {
    uint8_t version;
    uint8_t padding[7];
    uint64_t data_size;
    dap_chain_hash_fast_t data_hash;
    dap_chain_net_id_t net_id;
    dap_chain_node_addr_t sender_node_addr;
    dap_chain_node_addr_t receiver_node_addr;
}  DAP_ALIGN_PACKED dap_stream_ch_chain_voting_pkt_hdr_t;

typedef struct dap_stream_ch_chain_voting_pkt {
    dap_stream_ch_chain_voting_pkt_hdr_t hdr;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_stream_ch_chain_voting_pkt_t;


typedef struct dap_stream_ch_chain_voting dap_stream_ch_chain_voting_t;
typedef void (*dap_stream_ch_chain_voting_callback_packet_t)(dap_stream_ch_chain_voting_t *a_ch_voting, uint8_t a_pkt_type,
                                                             dap_stream_ch_chain_voting_pkt_t *a_pkt, size_t a_pkt_data_size,
                                                             void * a_arg);

typedef struct dap_stream_ch_chain_voting {
    void *_inheritor;   // parent stream ch
    dap_stream_ch_chain_voting_callback_packet_t callback_notify;
    void *callback_notify_arg;
} dap_stream_ch_chain_voting_t;

#define DAP_STREAM_CH_CHAIN_VOTING(a) ((dap_stream_ch_chain_voting_t *) ((a)->internal) )

inline static uint8_t dap_stream_ch_chain_voting_get_id(void) { return (uint8_t) 'V'; }

void dap_stream_ch_chain_voting_in_callback_add(void* a_arg, dap_chain_voting_ch_callback_t packet_in_callback, dap_chain_node_addr_t a_my_addr);

void dap_stream_ch_chain_voting_message_write(dap_chain_net_t * a_net, dap_chain_node_addr_t *a_remote_node_addr,
                                              dap_stream_ch_chain_voting_pkt_t *a_voting_pkt);

dap_stream_ch_chain_voting_pkt_t *dap_stream_ch_chain_voting_pkt_new(uint64_t a_net_id,
                                                                     dap_chain_node_addr_t *a_sender_node_addr,
                                                                     dap_chain_node_addr_t *a_receiver_node_addr,
                                                                     const void *a_data, size_t a_data_size);

size_t dap_stream_ch_chain_voting_pkt_write_unsafe(dap_stream_ch_t *a_ch, uint8_t a_type, uint64_t a_net_id,
                                                   dap_chain_node_addr_t *a_sender_node_addr,
                                                   dap_chain_node_addr_t *a_receiver_node_addr,
                                                   const void * a_data, size_t a_data_size);

int dap_stream_ch_chain_voting_init();
void dap_stream_ch_chain_voting_deinit();

void dap_stream_ch_voting_queue_clear();
