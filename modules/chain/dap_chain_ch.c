/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dap_common.h"
#include "dap_config.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_worker.h"
#include "dap_proc_thread.h"
#include "dap_chain.h"
#include "dap_stream.h"
#include "dap_stream_pkt.h"
#include "dap_stream_worker.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_chain_ch.h"
#include "dap_chain_ch_pkt.h"
#include "dap_stream_ch_gossip.h"

#define LOG_TAG "dap_chain_ch"

#define DAP_CHAIN_PKT_EXPECT_SIZE   DAP_STREAM_PKT_FRAGMENT_SIZE

enum sync_context_state {
    SYNC_STATE_IDLE,
    SYNC_STATE_READY,
    SYNC_STATE_BUSY,
    SYNC_STATE_OVER
};

struct sync_context {
    atomic_uint_fast64_t allowed_num;
    atomic_uint_fast16_t state;
    dap_chain_atom_iter_t *iter;
    dap_stream_node_addr_t addr;
    dap_chain_net_id_t net_id;
    dap_chain_id_t chain_id;
    dap_chain_cell_id_t cell_id;
    uint64_t num_last;
    dap_time_t last_activity;
};

typedef struct dap_chain_ch_hash_item {
    dap_hash_fast_t hash;
    uint32_t size;
    UT_hash_handle hh;
} dap_chain_ch_hash_item_t;

typedef struct dap_chain_ch {
    void *_inheritor;
    dap_timerfd_t *sync_timer;
    struct sync_context *sync_context;
    int idle_ack_counter;
} dap_chain_ch_t;

#define DAP_CHAIN_CH(a) ((dap_chain_ch_t *) ((a)->internal) )
#define DAP_STREAM_CH(a) ((dap_stream_ch_t *)((a)->_inheritor))

static void s_ch_chain_go_idle(dap_chain_ch_t *a_ch_chain);

static void s_stream_ch_new(dap_stream_ch_t *a_ch, void *a_arg);
static void s_stream_ch_delete(dap_stream_ch_t *a_ch, void *a_arg);
static bool s_stream_ch_packet_in(dap_stream_ch_t * a_ch, void *a_arg);
static void s_stream_ch_io_complete(dap_events_socket_t *a_es, void *a_arg);

static bool s_sync_in_chains_callback(void *a_arg);
static bool s_sync_out_chains_proc_callback(void *a_arg);
static bool s_gdb_in_pkt_proc_callback(void *a_arg);
static bool s_sync_out_gdb_proc_callback(void *a_arg);

static void s_stream_ch_chain_pkt_write(dap_stream_ch_t *a_ch, uint8_t a_type, uint64_t a_net_id,
                                        uint64_t a_chain_id, uint64_t a_cell_id,
                                        const void * a_data, size_t a_data_size);

static void s_gossip_payload_callback(void *a_payload, size_t a_payload_size, dap_stream_node_addr_t a_sender_addr);
static bool s_chain_iter_callback(void *a_arg);
static bool s_chain_iter_delete_callback(void *a_arg);
static bool s_sync_timer_callback(void *a_arg);

static bool s_debug_more = false, s_debug_legacy = false;
static uint32_t s_sync_timeout = 30;
static uint32_t s_sync_packets_per_thread_call = 10;
static uint32_t s_sync_ack_window_size = 16; // atoms

// Legacy
static const uint_fast16_t s_update_pack_size = 100; // Number of hashes packed into the one packet

#ifdef  DAP_SYS_DEBUG

enum    {MEMSTAT$K_STM_CH_CHAIN, MEMSTAT$K_NR};
static  dap_memstat_rec_t   s_memstat [MEMSTAT$K_NR] = {
    {.fac_len = sizeof(LOG_TAG) - 1, .fac_name = {LOG_TAG}, .alloc_sz = sizeof(dap_chain_ch_t)},
};

#endif

const char* const s_error_type_to_string[] = {
    [DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS]= "SYNC_REQUEST_ALREADY_IN_PROCESS",
    [DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE]        = "INCORRECT_SYNC_SEQUENCE",
    [DAP_CHAIN_CH_ERROR_SYNC_TIMEOUT]                   = "SYNCHRONIZATION_TIMEOUT",
    [DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE]            = "INVALID_PACKET_SIZE",
    [DAP_CHAIN_CH_ERROR_LEGACY_PKT_DATA_SIZE]           = "INVALID_LEGACY_PACKET_SIZE",
    [DAP_CHAIN_CH_ERROR_NET_INVALID_ID]                 = "INVALID_NET_ID",
    [DAP_CHAIN_CH_ERROR_CHAIN_NOT_FOUND]                = "CHAIN_NOT_FOUND",
    [DAP_CHAIN_CH_ERROR_ATOM_NOT_FOUND]                 = "ATOM_NOT_FOUND",
    [DAP_CHAIN_CH_ERROR_UNKNOWN_CHAIN_PKT_TYPE]         = "UNKNOWN_CHAIN_PACKET_TYPE",
    [DAP_CHAIN_CH_ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED]   = "GLOBAL_DB_INTERNAL_SAVING_ERROR",
    [DAP_CHAIN_CH_ERROR_NET_IS_OFFLINE]                 = "NET_IS_OFFLINE",
    [DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY]                  = "OUT_OF_MEMORY",
    [DAP_CHAIN_CH_ERROR_INTERNAL]                       = "INTERNAL_ERROR"
};

/**
 * @brief dap_chain_ch_init
 * @return
 */
int dap_chain_ch_init()
{
    log_it(L_NOTICE, "Chains exchange channel initialized");
    dap_stream_ch_proc_add(DAP_CHAIN_CH_ID, s_stream_ch_new, s_stream_ch_delete, s_stream_ch_packet_in, NULL);
    s_sync_timeout = dap_config_get_item_uint32_default(g_config, "chain", "sync_timeout", s_sync_timeout);
    s_sync_ack_window_size = dap_config_get_item_uint32_default(g_config, "chain", "sync_ack_window_size", s_sync_ack_window_size);
    s_sync_packets_per_thread_call = dap_config_get_item_int16_default(g_config, "chain", "pack_size", s_sync_packets_per_thread_call);
    s_debug_more = dap_config_get_item_bool_default(g_config, "chain", "debug_more", false);
    s_debug_legacy = dap_config_get_item_bool_default(g_config, "chain", "debug_legacy", false);
#ifdef  DAP_SYS_DEBUG
    for (int i = 0; i < MEMSTAT$K_NR; i++)
        dap_memstat_reg(&s_memstat[i]);
#endif
    return dap_stream_ch_gossip_callback_add(DAP_CHAIN_CH_ID, s_gossip_payload_callback);
}

/**
 * @brief dap_chain_ch_deinit
 */
void dap_chain_ch_deinit()
{

}

/**
 * @brief s_stream_ch_new
 * @param a_ch
 * @param arg
 */
void s_stream_ch_new(dap_stream_ch_t *a_ch, void *a_arg)
{
    UNUSED(a_arg);
    if (!(a_ch->internal = DAP_NEW_Z(dap_chain_ch_t))) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return;
    };
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(a_ch);
    l_ch_chain->_inheritor = a_ch;

#ifdef  DAP_SYS_DEBUG
    atomic_fetch_add(&s_memstat[MEMSTAT$K_STM_CH_CHAIN].alloc_nr, 1);
#endif
    debug_if(s_debug_more, L_DEBUG, "[stm_ch_chain:%p] --- created chain:%p", a_ch, l_ch_chain);
}

/**
 * @brief s_stream_ch_delete
 * @param ch
 * @param arg
 */
static void s_stream_ch_delete(dap_stream_ch_t *a_ch, void *a_arg)
{
    UNUSED(a_arg);
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(a_ch);
    s_ch_chain_go_idle(l_ch_chain);
    debug_if(s_debug_more, L_DEBUG, "[stm_ch_chain:%p] --- deleted chain:%p", a_ch, l_ch_chain);
    DAP_DEL_Z(a_ch->internal);

#ifdef  DAP_SYS_DEBUG
    atomic_fetch_add(&s_memstat[MEMSTAT$K_STM_CH_CHAIN].free_nr, 1);
#endif
}

struct atom_processing_args {
    dap_stream_node_addr_t addr;
    bool ack_req;
    byte_t data[];
};

/**
 * @brief s_sync_in_chains_callback
 * @param a_thread dap_proc_thread_t
 * @param a_arg void
 * @return
 */
static bool s_sync_in_chains_callback(void *a_arg)
{
    assert(a_arg);
    struct atom_processing_args *l_args = a_arg;
    dap_chain_ch_pkt_t *l_chain_pkt = (dap_chain_ch_pkt_t *)l_args->data;
    if (!l_chain_pkt->hdr.data_size) {
        log_it(L_CRITICAL, "Proc thread received corrupted chain packet!");
        return false;
    }
    dap_chain_atom_ptr_t l_atom = (dap_chain_atom_ptr_t)l_chain_pkt->data;
    uint64_t l_atom_size = l_chain_pkt->hdr.data_size;
    dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
    if (!l_chain) {
        debug_if(s_debug_more, L_WARNING, "No chain found for DAP_CHAIN_CH_PKT_TYPE_CHAIN");
        DAP_DELETE(l_args);
        return false;
    }
    dap_hash_fast_t l_atom_hash = { }; 
    dap_hash_fast(l_atom, l_atom_size, &l_atom_hash);
    char *l_atom_hash_str = dap_hash_fast_to_str_static(&l_atom_hash);
    dap_chain_atom_verify_res_t l_atom_add_res = l_chain->callback_atom_add(l_chain, l_atom, l_atom_size, &l_atom_hash, false);
    bool l_ack_send = false;
    switch (l_atom_add_res) {
    case ATOM_PASS:
        debug_if(s_debug_more, L_WARNING, "Atom with hash %s for %s:%s not accepted (code ATOM_PASS, already present)",
                                          l_atom_hash_str, l_chain->net_name, l_chain->name);
        l_ack_send = true;
        break;
    case ATOM_MOVE_TO_THRESHOLD:
        debug_if(s_debug_more, L_INFO, "Thresholded atom with hash %s for %s:%s", l_atom_hash_str, l_chain->net_name, l_chain->name);
        break;
    case ATOM_ACCEPT:
        debug_if(s_debug_more, L_INFO, "Accepted atom with hash %s for %s:%s", l_atom_hash_str, l_chain->net_name, l_chain->name);
        l_ack_send = true;
        break;
    case ATOM_REJECT: {
        debug_if(s_debug_more, L_WARNING, "Atom with hash %s for %s:%s rejected", l_atom_hash_str, l_chain->net_name, l_chain->name);
        break;
    }
    case ATOM_FORK: {
        debug_if(s_debug_more, L_WARNING, "Atom with hash %s for %s:%s added to a fork branch.", l_atom_hash_str, l_chain->net_name, l_chain->name);
        l_ack_send = true;
        break;
    }
    default:
        log_it(L_CRITICAL, "Wtf is this ret code? %d", l_atom_add_res);
        break;
    }
    if ( l_ack_send && l_args->ack_req ) {
        uint64_t l_ack_num = ((uint32_t)l_chain_pkt->hdr.num_hi << 16) | l_chain_pkt->hdr.num_lo;
        dap_chain_ch_pkt_t *l_pkt = dap_chain_ch_pkt_new(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                                         &l_ack_num, sizeof(uint64_t), DAP_CHAIN_CH_PKT_VERSION_CURRENT);
        dap_stream_ch_pkt_send_by_addr(&l_args->addr, DAP_CHAIN_CH_ID, DAP_CHAIN_CH_PKT_TYPE_CHAIN_ACK, l_pkt, dap_chain_ch_pkt_get_size(l_pkt));
        DAP_DELETE(l_pkt);
        debug_if(s_debug_more, L_DEBUG, "Out: CHAIN_ACK %s for net %s to destination " NODE_ADDR_FP_STR " with num %" DAP_UINT64_FORMAT_U,
                                         l_chain->name, l_chain->net_name, NODE_ADDR_FP_ARGS_S(l_args->addr), l_ack_num);
    }
    DAP_DELETE(l_args);
    return false;
}

static void s_gossip_payload_callback(void *a_payload, size_t a_payload_size, dap_stream_node_addr_t a_sender_addr)
{
    assert(a_payload && a_payload_size);
    dap_chain_ch_pkt_t *l_chain_pkt = a_payload;
    if (a_payload_size <= sizeof(dap_chain_ch_pkt_t) ||
            a_payload_size != sizeof(dap_chain_ch_pkt_t) + l_chain_pkt->hdr.data_size) {
        log_it(L_WARNING, "Incorrect chain GOSSIP packet size");
        return;
    }
    struct atom_processing_args *l_args = DAP_NEW_Z_SIZE(struct atom_processing_args, a_payload_size + sizeof(struct atom_processing_args));
    if (!l_args) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return;
    }
    l_args->addr = a_sender_addr;
    l_args->ack_req = false;
    memcpy(l_args->data, a_payload, a_payload_size);
    dap_proc_thread_callback_add(NULL, s_sync_in_chains_callback, l_args);
}

void dap_stream_ch_write_error_unsafe(dap_stream_ch_t *a_ch, dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id, dap_chain_ch_error_type_t a_error)
{
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(a_ch);
    dap_return_if_fail(l_ch_chain);
    const char *l_err_str = a_error < DAP_CHAIN_CH_ERROR_LAST ? s_error_type_to_string[a_error] : "UNDEFINED ERROR";
    dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_ERROR, a_net_id, a_chain_id, a_cell_id, l_err_str, strlen(l_err_str) + 1, DAP_CHAIN_CH_PKT_VERSION_LEGACY);
    s_ch_chain_go_idle(l_ch_chain);
}

/**
 * @brief s_stream_ch_packet_in
 * @param a_ch
 * @param a_arg
 */
static bool s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg)
{
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(a_ch);
    if (!l_ch_chain || l_ch_chain->_inheritor != a_ch) {
        log_it(L_ERROR, "No chain in channel, returning");
        return false;
    }
    dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
    if (l_ch_pkt->hdr.data_size < sizeof(dap_chain_ch_pkt_t)) {
        log_it(L_ERROR, "Corrupted packet: too small size %u, smaller then header size %zu",
                                            l_ch_pkt->hdr.data_size, sizeof(dap_chain_ch_pkt_t));
        return false;
    }

    dap_chain_ch_pkt_t *l_chain_pkt = (dap_chain_ch_pkt_t *)l_ch_pkt->data;
    size_t l_chain_pkt_data_size = l_ch_pkt->hdr.data_size - sizeof(l_chain_pkt->hdr);

    if (!l_chain_pkt->hdr.version || l_chain_pkt->hdr.version > DAP_CHAIN_CH_PKT_VERSION_CURRENT) {
        debug_if(s_debug_more, L_ATT, "Unsupported protocol version %d, current version %d",
                 l_chain_pkt->hdr.version, DAP_CHAIN_CH_PKT_VERSION_CURRENT);
        return false;
    }
    if (l_chain_pkt->hdr.version > DAP_CHAIN_CH_PKT_VERSION_LEGACY &&
                l_chain_pkt_data_size != l_chain_pkt->hdr.data_size) {
        log_it(L_WARNING, "Incorrect chain packet size %zu, expected %u",
                            l_chain_pkt_data_size, l_chain_pkt->hdr.data_size);
        return false;
    }

    switch (l_ch_pkt->hdr.type) {

    case DAP_CHAIN_CH_PKT_TYPE_ERROR: {
        if (!l_chain_pkt_data_size || l_chain_pkt->data[l_chain_pkt_data_size - 1] != 0) {
            log_it(L_WARNING, "Incorrect format with data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            return false;
        }
        log_it(L_WARNING, "In: from remote addr %s chain id 0x%016" DAP_UINT64_FORMAT_x " got error on his side: '%s'",
               DAP_STREAM_CH(l_ch_chain)->stream->esocket->remote_addr_str,
               l_chain_pkt->hdr.chain_id.uint64, (char *)l_chain_pkt->data);
        s_ch_chain_go_idle(l_ch_chain);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN: {
        if (!l_chain_pkt_data_size || l_chain_pkt_data_size > sizeof(dap_chain_ch_pkt_t) + DAP_CHAIN_ATOM_MAX_SIZE
                                                                                         * 5) { // For legacy block sizes
            log_it(L_WARNING, "Incorrect data size %zu in packet %s", l_chain_pkt_data_size,
                                                    dap_chain_ch_pkt_type_to_str(l_ch_pkt->hdr.type));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        dap_cluster_t *l_cluster = dap_cluster_find(dap_guuid_compose(l_chain_pkt->hdr.net_id.uint64, 0));
        if (!l_cluster) {
            log_it(L_WARNING, "Can't find cluster with ID 0x%" DAP_UINT64_FORMAT_X, l_chain_pkt->hdr.net_id.uint64);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        dap_cluster_member_t *l_check = dap_cluster_member_find_unsafe(l_cluster, &a_ch->stream->node);
        if (!l_check) {
            log_it(L_WARNING, "Node with addr "NODE_ADDR_FP_STR" isn't a member of cluster %s",
                                        NODE_ADDR_FP_ARGS_S(a_ch->stream->node), l_cluster->mnemonim);
            return false;
        }
        struct atom_processing_args *l_args = DAP_NEW_Z_SIZE(struct atom_processing_args, l_ch_pkt->hdr.data_size + sizeof(struct atom_processing_args));
        if (!l_args) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            break;
        }
        l_args->addr = a_ch->stream->node;
        l_args->ack_req = true;
        memcpy(l_args->data, l_chain_pkt, l_ch_pkt->hdr.data_size);
        debug_if(s_debug_more, L_INFO, "In: CHAIN pkt: atom hash %s, size %zd, net id %" DAP_UINT64_FORMAT_U ", chain id %" DAP_UINT64_FORMAT_U ", atom id %" DAP_UINT64_FORMAT_U,
                                        dap_get_data_hash_str(l_chain_pkt->data, l_chain_pkt_data_size).s, l_chain_pkt_data_size,
                                        l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                                        (uint64_t)(((uint32_t)l_chain_pkt->hdr.num_hi << 16) | l_chain_pkt->hdr.num_lo));
        dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_sync_in_chains_callback, l_args);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_REQ: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_ch_sync_request_old_t) && l_chain_pkt_data_size != sizeof(dap_chain_ch_sync_request_t)) {
            log_it(L_WARNING, "DAP_CHAIN_CH_PKT_TYPE_CHAIN_REQ: Wrong chain packet size %zd when expected %zd",
                                                                            l_chain_pkt_data_size, sizeof(dap_chain_ch_sync_request_t));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        bool l_is_legacy = l_chain_pkt_data_size == sizeof(dap_chain_ch_sync_request_old_t);
        // CAUTION: Unsafe cast, must check 'l_is_legacy' variable before access 'generation' field
        dap_chain_ch_sync_request_t *l_request = (dap_chain_ch_sync_request_t *)l_chain_pkt->data;
        if (s_debug_more)
            log_it(L_INFO, "In: CHAIN_REQ pkt: net 0x%016" DAP_UINT64_FORMAT_x " chain 0x%016" DAP_UINT64_FORMAT_x
                            " cell 0x%016" DAP_UINT64_FORMAT_x ", hash from %s, num from %" DAP_UINT64_FORMAT_U,
                            l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                            dap_hash_fast_to_str_static(&l_request->hash_from), l_request->num_from);
        if (l_ch_chain->sync_context) {
            log_it(L_WARNING, "Can't process CHAIN_REQ request cause already busy with synchronization");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS);
            break;
        }
        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        if (!l_chain || l_chain->callback_load_from_gdb) {
            log_it(L_WARNING, "Not found valid chain with id 0x%016" DAP_UINT64_FORMAT_x " and net id 0x%016" DAP_UINT64_FORMAT_x,
                                                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.net_id.uint64);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_NOT_FOUND);
            break;
        }
        if (!dap_link_manager_get_net_condition(l_chain_pkt->hdr.net_id.uint64)) {
            log_it(L_WARNING, "Net id 0x%016" DAP_UINT64_FORMAT_x " is offline", l_chain_pkt->hdr.net_id.uint64);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_NET_IS_OFFLINE);
            break;
        }
        bool l_sync_from_begin = dap_hash_fast_is_blank(&l_request->hash_from) || (!l_is_legacy && l_request->generation < l_chain->generation);
        dap_chain_atom_iter_t *l_iter = l_chain->callback_atom_iter_create(l_chain, l_chain_pkt->hdr.cell_id, l_sync_from_begin
                                                                           ? NULL : &l_request->hash_from);
        if (!l_iter) {
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY);
            break;
        }
        if (l_sync_from_begin)
            l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_FIRST, NULL);
        bool l_missed_hash = false;
        uint64_t l_last_num = l_chain->callback_count_atom(l_chain);
        if (l_iter->cur) {
            if (l_sync_from_begin ||
                    (l_request->num_from == l_iter->cur_num &&
                    l_last_num > l_iter->cur_num)) {
                dap_chain_ch_summary_t l_sum = { .num_cur = l_iter->cur_num, .num_last = l_last_num };
                dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_CHAIN_SUMMARY,
                                                l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id,
                                                l_chain_pkt->hdr.cell_id, &l_sum, sizeof(l_sum),
                                                DAP_CHAIN_CH_PKT_VERSION_CURRENT);
                debug_if(s_debug_more, L_DEBUG, "Out: CHAIN_SUMMARY %s for net %s to destination " NODE_ADDR_FP_STR " value %"DAP_UINT64_FORMAT_U,
                                                        l_chain->name, l_chain->net_name, NODE_ADDR_FP_ARGS_S(a_ch->stream->node), l_last_num);
                struct sync_context *l_context = DAP_NEW_Z(struct sync_context);
                l_context->addr = a_ch->stream->node;
                l_context->iter = l_iter;
                l_context->net_id = l_chain_pkt->hdr.net_id;
                l_context->chain_id = l_chain_pkt->hdr.chain_id;
                l_context->cell_id = l_chain_pkt->hdr.cell_id;
                l_context->num_last = l_sum.num_last;
                atomic_store_explicit(&l_context->state, SYNC_STATE_READY, memory_order_relaxed);
                atomic_store(&l_context->allowed_num, l_sum.num_cur + s_sync_ack_window_size);
                dap_stream_ch_uuid_t *l_uuid = DAP_DUP(&a_ch->uuid);
                if (!l_uuid) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    DAP_DELETE(l_context);
                    break;
                }
                l_ch_chain->sync_context = l_context;
                l_ch_chain->idle_ack_counter = s_sync_ack_window_size;
                dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_chain_iter_callback, l_context);
                l_ch_chain->sync_timer = dap_timerfd_start_on_worker(a_ch->stream_worker->worker, 1000, s_sync_timer_callback, l_uuid);
                break;
            }
            if (l_request->num_from < l_iter->cur_num || l_last_num > l_iter->cur_num)
                l_missed_hash = true;
        } else if (!l_sync_from_begin && l_last_num >= l_request->num_from) {
            l_missed_hash = true;
            debug_if(s_debug_more, L_WARNING, "Requested atom with hash %s not found", dap_hash_fast_to_str_static(&l_request->hash_from));
        }
        if (l_missed_hash) {
            l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_LAST, NULL);
            dap_chain_ch_miss_info_t l_miss_info = { .missed_hash = l_request->hash_from,
                                                     .last_hash = l_iter->cur_hash ? *l_iter->cur_hash : (dap_hash_fast_t){ },
                                                     .last_num = l_iter->cur_num };
            dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS,
                                          l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id,
                                          l_chain_pkt->hdr.cell_id, &l_miss_info, sizeof(l_miss_info),
                                          DAP_CHAIN_CH_PKT_VERSION_CURRENT);
            if (s_debug_more) {
                char l_last_hash_str[DAP_HASH_FAST_STR_SIZE];
                dap_hash_fast_to_str(&l_miss_info.last_hash, l_last_hash_str, DAP_HASH_FAST_STR_SIZE);
                log_it(L_INFO, "Out: CHAIN_MISS %s for net %s to source " NODE_ADDR_FP_STR
                                             " with hash missed %s, hash last %s and num last %" DAP_UINT64_FORMAT_U,
                        l_chain ? l_chain->name : "(null)",
                                    l_chain ? l_chain->net_name : "(null)",
                                                    NODE_ADDR_FP_ARGS_S(a_ch->stream->node),
                        dap_hash_fast_to_str_static(&l_miss_info.missed_hash),
                        l_last_hash_str,
                        l_miss_info.last_num);
            }
        } else {
            dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN,
                                          l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id,
                                          l_chain_pkt->hdr.cell_id, NULL, 0,
                                          DAP_CHAIN_CH_PKT_VERSION_CURRENT);
            debug_if(s_debug_more, L_DEBUG, "Out: SYNCED_CHAIN %s for net %s to destination " NODE_ADDR_FP_STR,
                                    l_chain ? l_chain->name : "(null)",
                                                l_chain ? l_chain->net_name : "(null)",
                                                                NODE_ADDR_FP_ARGS_S(a_ch->stream->node));
        }
        l_chain->callback_atom_iter_delete(l_iter);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_SUMMARY: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_ch_summary_t)) {
            log_it(L_WARNING, "DAP_CHAIN_CH_PKT_TYPE_CHAIN_SUMMARY: Wrong chain packet size %zd when expected %zd",
                                                                            l_chain_pkt_data_size, sizeof(dap_chain_ch_summary_t));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        dap_chain_ch_summary_t *l_sum = (dap_chain_ch_summary_t *)l_chain_pkt->data;
        if(l_chain->atom_num_last < l_sum->num_last)
            l_chain->atom_num_last = l_sum->num_last;
        debug_if(s_debug_more, L_DEBUG, "In: CHAIN_SUMMARY of %s for net %s from source " NODE_ADDR_FP_STR
                                            " with %" DAP_UINT64_FORMAT_U " atoms to sync from %" DAP_UINT64_FORMAT_U " to %" DAP_UINT64_FORMAT_U,
                                l_chain ? l_chain->name : "(null)",
                                            l_chain ? l_chain->net_name : "(null)",
                                                            NODE_ADDR_FP_ARGS_S(a_ch->stream->node),
                                l_sum->num_last - l_sum->num_cur, l_sum->num_cur, l_sum->num_last);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_ACK: {
        if (l_chain_pkt_data_size != sizeof(uint64_t)) {
            log_it(L_WARNING, "DAP_CHAIN_CH_PKT_TYPE_CHAIN_ACK: Wrong chain packet size %zd when expected %zd",
                                                                            l_chain_pkt_data_size, sizeof(uint64_t));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        uint64_t l_ack_num = *(uint64_t *)l_chain_pkt->data;
        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        debug_if(s_debug_more, L_DEBUG, "In: CHAIN_ACK %s for net %s from source " NODE_ADDR_FP_STR " with num %" DAP_UINT64_FORMAT_U,
                                l_chain ? l_chain->name : "(null)",
                                            l_chain ? l_chain->net_name : "(null)",
                                                            NODE_ADDR_FP_ARGS_S(a_ch->stream->node),
                                l_ack_num);
        struct sync_context *l_context = l_ch_chain->sync_context;
        if (!l_context) {
            if (l_ch_chain->idle_ack_counter > 0) {
                debug_if(s_debug_more, L_DEBUG, "End of window wave");
                l_ch_chain->idle_ack_counter--;
            } else {
                log_it(L_WARNING, "CHAIN_ACK: No active sync context");
                dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                        l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                        DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            }
            break;
        }
        if (l_context->num_last == l_ack_num) {
            dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN,
                                                l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id,
                                                l_chain_pkt->hdr.cell_id, NULL, 0,
                                                DAP_CHAIN_CH_PKT_VERSION_CURRENT);
            s_ch_chain_go_idle(l_ch_chain);
            break;
        }
        l_context->last_activity = dap_time_now();
        if (atomic_load_explicit(&l_context->state, memory_order_relaxed) == SYNC_STATE_OVER)
            break;
        atomic_store_explicit(&l_context->allowed_num,
                              dap_min(l_ack_num + s_sync_ack_window_size, l_context->num_last),
                              memory_order_release);
        if (atomic_exchange(&l_context->state, SYNC_STATE_READY) == SYNC_STATE_IDLE)
            dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_chain_iter_callback, l_context);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN: {
        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        l_chain->atom_num_last = l_chain->callback_count_atom(l_chain);
        log_it(L_INFO, "In: SYNCED_CHAIN %s for net %s from source " NODE_ADDR_FP_STR,
                    l_chain ? l_chain->name : "(null)",
                                l_chain ? l_chain->net_name : "(null)",
                                                NODE_ADDR_FP_ARGS_S(a_ch->stream->node));
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_ch_miss_info_t)) {
            log_it(L_WARNING, "DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS: Wrong chain packet size %zd when expected %zd",
                                                                            l_chain_pkt_data_size, sizeof(dap_chain_ch_miss_info_t));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        dap_chain_ch_miss_info_t *l_miss_info = (dap_chain_ch_miss_info_t *)l_chain_pkt->data;
        if (s_debug_more) {
            char l_last_hash_str[DAP_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_miss_info->last_hash, l_last_hash_str, DAP_HASH_FAST_STR_SIZE);
            log_it(L_INFO, "In: CHAIN_MISS %s for net %s from source " NODE_ADDR_FP_STR
                                         " with hash missed %s, hash last %s and num last %" DAP_UINT64_FORMAT_U,
                    l_chain ? l_chain->name : "(null)",
                                l_chain ? l_chain->net_name : "(null)",
                                                NODE_ADDR_FP_ARGS_S(a_ch->stream->node),
                    dap_hash_fast_to_str_static(&l_miss_info->missed_hash),
                    l_last_hash_str,
                    l_miss_info->last_num);
        }
        // Will be processed upper in net packet notifier callback
    } break;

    default:
        dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id,
                                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                            DAP_CHAIN_CH_ERROR_UNKNOWN_CHAIN_PKT_TYPE);
        return false;

    }
    return true;
}

static bool s_sync_timer_callback(void *a_arg)
{
    dap_worker_t *l_worker = dap_worker_get_current();
    if (!l_worker) {
        DAP_DELETE(a_arg);
        return false;
    }
    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(l_worker), *(dap_stream_ch_uuid_t *)a_arg);
    if (!l_ch) {
        DAP_DELETE(a_arg);
        return false;
    }
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(l_ch);
    if (!l_ch_chain) {
        log_it(L_ERROR, "Channel without chain, dump it");
        DAP_DELETE(a_arg);
        return false;
    }

    bool l_timer_break = false;
    const char* l_err_str = s_error_type_to_string[DAP_CHAIN_CH_ERROR_SYNC_TIMEOUT];
    if (l_ch_chain->sync_context) {
        struct sync_context *l_context = l_ch_chain->sync_context;
        if (l_context->last_activity + s_sync_timeout <= dap_time_now()) {
            log_it(L_ERROR, "Sync timeout for node " NODE_ADDR_FP_STR " with net 0x%016" DAP_UINT64_FORMAT_x
                                " chain 0x%016" DAP_UINT64_FORMAT_x " cell 0x%016" DAP_UINT64_FORMAT_x,
                                            NODE_ADDR_FP_ARGS_S(l_context->addr), l_context->net_id.uint64,
                                            l_context->chain_id.uint64, l_context->cell_id.uint64);
            dap_chain_ch_pkt_write_unsafe(l_ch, DAP_CHAIN_CH_PKT_TYPE_ERROR, l_context->net_id,
                                          l_context->chain_id, l_context->cell_id, l_err_str, strlen(l_err_str) + 1,
                                          DAP_CHAIN_CH_PKT_VERSION_CURRENT);
            l_timer_break = true;
        }
    } else
        l_timer_break = true;

    if (l_timer_break) {
        l_ch_chain->sync_timer = NULL;      // Preserve timer removing from s_ch_chain_go_idle()
        s_ch_chain_go_idle(l_ch_chain);
        DAP_DELETE(a_arg);
        return false;
    }
    return true;
}

static bool s_chain_iter_callback(void *a_arg)
{
    assert(a_arg);
    struct sync_context *l_context = a_arg;
    dap_chain_atom_iter_t *l_iter = l_context->iter;
    assert(l_iter);
    dap_chain_t *l_chain = l_iter->chain;
    if (atomic_exchange(&l_context->state, SYNC_STATE_BUSY) == SYNC_STATE_OVER) {
        atomic_store(&l_context->state, SYNC_STATE_OVER);
        return false;
    }
    size_t l_atom_size = l_iter->cur_size;
    dap_chain_atom_ptr_t l_atom = l_iter->cur;
    uint32_t l_cycles_count = 0;
    l_context->last_activity = dap_time_now();
    while (l_atom && l_atom_size) {
        if (l_iter->cur_num > atomic_load_explicit(&l_context->allowed_num, memory_order_acquire))
            break;
        dap_chain_ch_pkt_t *l_pkt = dap_chain_ch_pkt_new(l_context->net_id, l_context->chain_id, l_context->cell_id,
                                                         l_atom, l_atom_size, DAP_CHAIN_CH_PKT_VERSION_CURRENT);
        // For master format binary complience
        l_pkt->hdr.num_lo = l_iter->cur_num & 0xFFFF;
        l_pkt->hdr.num_hi = (l_iter->cur_num >> 16) & 0xFF;
        dap_stream_ch_pkt_send_by_addr(&l_context->addr, DAP_CHAIN_CH_ID, DAP_CHAIN_CH_PKT_TYPE_CHAIN, l_pkt, dap_chain_ch_pkt_get_size(l_pkt));
        DAP_DELETE(l_pkt);
        debug_if(s_debug_more, L_DEBUG, "Out: CHAIN %s for net %s to destination " NODE_ADDR_FP_STR " with num %" DAP_UINT64_FORMAT_U
                                            " hash %s and size %zu",
                                l_chain ? l_chain->name : "(null)",
                                            l_chain ? l_chain->net_name : "(null)",
                                                            NODE_ADDR_FP_ARGS_S(l_context->addr),
                                l_iter->cur_num, dap_hash_fast_to_str_static(l_iter->cur_hash), l_iter->cur_size);
        l_atom = l_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size);
        if (!l_atom || !l_atom_size || l_iter->cur_num > l_context->num_last)
            break;
        if (atomic_exchange(&l_context->state, SYNC_STATE_BUSY) == SYNC_STATE_OVER) {
            atomic_store(&l_context->state, SYNC_STATE_OVER);
            return false;
        }
        if (++l_cycles_count >= s_sync_packets_per_thread_call)
            return true;
    }
    uint16_t l_state = l_atom && l_atom_size && l_iter->cur_num <= l_context->num_last
                ? SYNC_STATE_IDLE : SYNC_STATE_OVER;
    uint16_t l_prev_state = atomic_exchange(&l_context->state, l_state);
    if (l_prev_state == SYNC_STATE_OVER && l_state != SYNC_STATE_OVER)
        atomic_store(&l_context->state, SYNC_STATE_OVER);
    if (l_prev_state == SYNC_STATE_READY)   // Allowed num was changed since last state updating
        return true;
    return false;
}

static bool s_chain_iter_delete_callback(void *a_arg)
{
    struct sync_context *l_context = a_arg;
    assert(l_context->iter);
    l_context->iter->chain->callback_atom_iter_delete(l_context->iter);
    DAP_DELETE(l_context);
    return false;
}

/**
 * @brief s_ch_chain_go_idle
 * @param a_ch_chain
 */
static void s_ch_chain_go_idle(dap_chain_ch_t *a_ch_chain)
{
    debug_if(s_debug_more, L_INFO, "Going to chain's stream channel STATE_IDLE");

    // New protocol
    if (a_ch_chain->sync_context) {
        atomic_store(&((struct sync_context *)a_ch_chain->sync_context)->state, SYNC_STATE_OVER);
        dap_proc_thread_callback_add(DAP_STREAM_CH(a_ch_chain)->stream_worker->worker->proc_queue_input,
                                     s_chain_iter_delete_callback, a_ch_chain->sync_context);
        a_ch_chain->sync_context = NULL;
    }
    if (a_ch_chain->sync_timer) {
        dap_timerfd_delete_unsafe(a_ch_chain->sync_timer);
        a_ch_chain->sync_timer = NULL;
    }
}
