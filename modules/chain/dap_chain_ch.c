/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

 DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#endif

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"
#include "dap_config.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "utlist.h"

#include "dap_worker.h"
#include "dap_events.h"
#include "dap_proc_thread.h"
#include "dap_client_pvt.h"

#include "dap_chain.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"
#include "dap_chain_cell.h"

#include "dap_global_db.h"

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

struct sync_request
{
    dap_worker_t * worker;
    dap_stream_ch_uuid_t ch_uuid;
    dap_chain_ch_sync_request_old_t request;
    dap_chain_ch_pkt_hdr_t request_hdr;
    dap_chain_pkt_item_t pkt;

    dap_chain_ch_hash_item_t *remote_atoms; // Remote atoms
    dap_chain_ch_hash_item_t *remote_gdbs; // Remote gdbs

    uint64_t stats_request_elemets_processed;
    int last_err;
    union{
        struct{
            //dap_db_log_list_t *db_log; //  db log
            dap_list_t *db_iter;
            char *sync_group;
        } gdb;
        struct{
            dap_chain_atom_iter_t *request_atom_iter;
        } chain;
    };
};

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

static void s_ch_chain_go_idle(dap_chain_ch_t *a_ch_chain);
static inline bool s_ch_chain_get_idle(dap_chain_ch_t *a_ch_chain) { return a_ch_chain->state == DAP_CHAIN_CH_STATE_IDLE; }

static void s_stream_ch_new(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg);
static bool s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg);
static bool s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_io_complete(dap_events_socket_t *a_es, void *a_arg);

static bool s_sync_out_chains_proc_callback(void *a_arg);
static void s_sync_out_chains_last_worker_callback(dap_worker_t *a_worker, void *a_arg);
static void s_sync_out_chains_first_worker_callback(dap_worker_t *a_worker, void *a_arg);

static bool s_sync_out_gdb_proc_callback(void *a_arg);

static bool s_sync_in_chains_callback(void *a_arg);

static bool s_gdb_in_pkt_proc_callback(void *a_arg);
static bool s_gdb_in_pkt_proc_set_raw_callback(dap_global_db_instance_t *a_dbi,
                                               int a_rc, const char *a_group,
                                               const size_t a_values_total, const size_t a_values_count,
                                               dap_store_obj_t *a_values, void *a_arg);
static void s_gdb_in_pkt_error_worker_callback(dap_worker_t *a_thread, void *a_arg);

static void s_stream_ch_chain_pkt_write(dap_stream_ch_t *a_ch, uint8_t a_type, uint64_t a_net_id,
                                        uint64_t a_chain_id, uint64_t a_cell_id,
                                        const void * a_data, size_t a_data_size);
static void s_gossip_payload_callback(void *a_payload, size_t a_payload_size, dap_stream_node_addr_t a_sender_addr);
static bool s_chain_iter_callback(void *a_arg);
static bool s_chain_iter_delete_callback(void *a_arg);
static bool s_sync_timer_callback(void *a_arg);

static bool s_debug_more = false;
static uint32_t s_sync_timeout = 30;
static uint32_t s_sync_packets_per_thread_call = 10;
static uint32_t s_sync_ack_window_size = 100; // atoms

static uint_fast16_t s_update_pack_size=100; // Number of hashes packed into the one packet
static uint_fast16_t s_skip_in_reactor_count=50; // Number of hashes packed to skip in one reactor loop callback out packet

#ifdef  DAP_SYS_DEBUG

enum    {MEMSTAT$K_STM_CH_CHAIN, MEMSTAT$K_NR};
static  dap_memstat_rec_t   s_memstat [MEMSTAT$K_NR] = {
    {.fac_len = sizeof(LOG_TAG) - 1, .fac_name = {LOG_TAG}, .alloc_sz = sizeof(dap_chain_ch_t)},
};

#endif

static const char *s_error_type_to_string(dap_chain_ch_error_type_t a_error)
{
    switch (a_error) {
    case DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS:
        return "SYNC_REQUEST_ALREADY_IN_PROCESS";
    case DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE:
        return "INCORRECT_SYNC_SEQUENCE";
    case DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE:
        return "IVALID_PACKET_SIZE";
    case DAP_CHAIN_CH_ERROR_NET_INVALID_ID:
        return "INVALID_NET_ID";
    case DAP_CHAIN_CH_ERROR_CHAIN_NOT_FOUND:
        return "CHAIN_NOT_FOUND";
    case DAP_CHAIN_CH_ERROR_ATOM_NOT_FOUND:
        return "ATOM_NOT_FOUND";
    case DAP_CHAIN_CH_ERROR_UNKNOWN_CHAIN_PKT_TYPE:
        return "UNKNOWN_CHAIN_PACKET_TYPE";
    case DAP_CHAIN_CH_ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED:
        return "GLOBAL_DB_INTERNAL_SAVING_ERROR";
    case DAP_CHAIN_CH_ERROR_NET_IS_OFFLINE:
        return "NET_IS_OFFLINE";
    case DAP_CHAIN_CH_ERROR_OUT_OF_MEMORY:
        return "OUT_OF_MEMORY";
    case DAP_CHAIN_CH_ERROR_INTERNAL:
        return "INTERNAL_ERROR";
    default:
        return "UNKNOWN_ERROR";
    }
}

/**
 * @brief dap_chain_ch_init
 * @return
 */
int dap_chain_ch_init()
{
    log_it(L_NOTICE, "Chains exchange channel initialized");
    dap_stream_ch_proc_add(DAP_CHAIN_CH_ID, s_stream_ch_new, s_stream_ch_delete, s_stream_ch_packet_in,
            s_stream_ch_packet_out);
    s_sync_timeout = dap_config_get_item_uint32_default(g_config, "chain", "sync_timeout", s_sync_timeout);
    s_sync_ack_window_size = dap_config_get_item_uint32_default(g_config, "chain", "sync_ack_window_size", s_sync_ack_window_size);
    s_sync_packets_per_thread_call = dap_config_get_item_int16_default(g_config, "chain", "pack_size", s_sync_packets_per_thread_call);
    s_debug_more = dap_config_get_item_bool_default(g_config, "chain", "debug_more", false);
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
void s_stream_ch_new(dap_stream_ch_t* a_ch, void* a_arg)
{
    UNUSED(a_arg);
    if (!(a_ch->internal = DAP_NEW_Z(dap_chain_ch_t))) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    };
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(a_ch);
    l_ch_chain->_inheritor = a_ch;
    a_ch->stream->esocket->callbacks.write_finished_callback = s_stream_ch_io_complete;

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

/**
 * @brief s_stream_ch_chain_delete
 * @param a_ch_chain
 */
static void s_sync_request_delete(struct sync_request * a_sync_request)
{
    if (!a_sync_request) {
        //already NULL'ed
        return;
    }
    if (a_sync_request->pkt.pkt_data) {
        DAP_DEL_Z(a_sync_request->pkt.pkt_data);
    }

    if (a_sync_request->gdb.db_iter) {
        a_sync_request->gdb.db_iter = dap_list_first( a_sync_request->gdb.db_iter);
        dap_list_free_full( a_sync_request->gdb.db_iter, NULL);
        a_sync_request->gdb.db_iter = NULL;
    }
    DAP_DEL_Z(a_sync_request);
}

/**
 * @brief s_sync_out_chains_worker_callback
 * @param a_worker
 * @param a_arg
 */
static void s_sync_out_chains_first_worker_callback(dap_worker_t *a_worker, void *a_arg)
{
    struct sync_request * l_sync_request = (struct sync_request *) a_arg;
    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe( DAP_STREAM_WORKER(a_worker) , l_sync_request->ch_uuid);
    if( l_ch == NULL ){
        log_it(L_INFO,"Client disconnected before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return;
    }

    dap_chain_ch_t * l_ch_chain = DAP_CHAIN_CH(l_ch);
    if (!l_ch_chain) {
        log_it(L_CRITICAL, "Channel without chain, dump it");
        s_sync_request_delete(l_sync_request);
        return;
    }
    if (l_ch_chain->state != DAP_CHAIN_CH_STATE_UPDATE_CHAINS_REMOTE) {
        log_it(L_INFO, "Timeout fired before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return;
    }

    l_ch_chain->state = DAP_CHAIN_CH_STATE_SYNC_CHAINS;
    l_ch_chain->request_atom_iter = l_sync_request->chain.request_atom_iter;

    if (s_debug_more )
        log_it(L_INFO,"Out: DAP_CHAIN_CH_PKT_TYPE_FIRST_CHAIN");

    dap_chain_ch_pkt_write_unsafe(l_ch, DAP_CHAIN_CH_PKT_TYPE_FIRST_CHAIN,
            l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
            l_ch_chain->request_hdr.cell_id.uint64, &g_node_addr, sizeof(dap_chain_node_addr_t));
    DAP_DELETE(l_sync_request);

}

/**
 * @brief s_sync_out_chains_last_worker_callback
 * @param a_worker
 * @param a_arg
 */
static void s_sync_out_chains_last_worker_callback(dap_worker_t *a_worker, void *a_arg)
{
    struct sync_request * l_sync_request = (struct sync_request *) a_arg;
    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(a_worker), l_sync_request->ch_uuid);
    if( l_ch == NULL ){
        log_it(L_INFO,"Client disconnected before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return;
    }

    dap_chain_ch_t * l_ch_chain = DAP_CHAIN_CH(l_ch);
    if (!l_ch_chain) {
        log_it(L_CRITICAL, "Channel without chain, dump it");
        s_sync_request_delete(l_sync_request);
        return;
    }
    l_ch_chain->request_atom_iter = l_sync_request->chain.request_atom_iter;
    // last packet
    dap_chain_ch_sync_request_old_t l_request = {};
    if (s_debug_more )
        log_it(L_INFO,"Out: DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAINS");
    dap_chain_ch_pkt_write_unsafe(l_ch, DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAINS,
            l_sync_request->request_hdr.net_id.uint64, l_sync_request->request_hdr.chain_id.uint64,
            l_sync_request->request_hdr.cell_id.uint64, &l_request, sizeof(l_request));
    s_ch_chain_go_idle(l_ch_chain);
    DAP_DELETE(l_sync_request);
}
/**
 * @brief s_sync_chains_callback
 * @param a_thread
 * @param a_arg
 * @return
 */
static bool s_sync_out_chains_proc_callback(void *a_arg)
{
    struct sync_request * l_sync_request = (struct sync_request *) a_arg;

    dap_chain_t * l_chain = dap_chain_find_by_id(l_sync_request->request_hdr.net_id, l_sync_request->request_hdr.chain_id);
    assert(l_chain);
    l_sync_request->chain.request_atom_iter = l_chain->callback_atom_iter_create(l_chain, l_sync_request->request_hdr.cell_id, NULL);
    size_t l_first_size = 0;
    dap_chain_atom_ptr_t l_atom = l_chain->callback_atom_iter_get(l_sync_request->chain.request_atom_iter, DAP_CHAIN_ITER_OP_FIRST, &l_first_size);
    if (l_atom && l_first_size) {
        // first packet
        dap_chain_hash_fast_t l_hash_from = l_sync_request->request.hash_from;
        if (!dap_hash_fast_is_blank(&l_hash_from)) {
            (void ) l_chain->callback_atom_find_by_hash(l_sync_request->chain.request_atom_iter,
                                                          &l_hash_from, &l_first_size);
        }
         dap_worker_exec_callback_on(dap_events_worker_get(l_sync_request->worker->id), s_sync_out_chains_first_worker_callback, l_sync_request );
    } else {
         dap_worker_exec_callback_on(dap_events_worker_get(l_sync_request->worker->id),s_sync_out_chains_last_worker_callback, l_sync_request );
    }
    return false;
}


/**
 * @brief s_sync_out_gdb_first_gdb_worker_callback
 * @param a_worker
 * @param a_arg
 */
static void s_sync_out_gdb_first_worker_callback(dap_worker_t *a_worker, void *a_arg)
{
    struct sync_request *l_sync_request = (struct sync_request *) a_arg;

    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(l_sync_request->worker), l_sync_request->ch_uuid);
    if( l_ch == NULL ){
        log_it(L_INFO,"Client disconnected before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return;
    }

    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH( l_ch );

    if (!l_ch_chain) {
        log_it(L_CRITICAL, "Channel without chain, dump it");
        s_sync_request_delete(l_sync_request);
        return;
    }

    if (l_ch_chain->state != DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB_REMOTE) {
        log_it(L_INFO, "Timeout fired before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return;
    }

    // Add it to outgoing list
    l_ch_chain->state = DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB;
    if (s_debug_more )
        log_it(L_INFO,"Out: DAP_CHAIN_CH_PKT_TYPE_FIRST_GLOBAL_DB");
    dap_chain_ch_pkt_write_unsafe(DAP_STREAM_CH(l_ch_chain), DAP_CHAIN_CH_PKT_TYPE_FIRST_GLOBAL_DB,
            l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
            l_ch_chain->request_hdr.cell_id.uint64, &g_node_addr, sizeof(dap_chain_node_addr_t));

    if( a_worker){ // We send NULL to prevent delete
        s_sync_request_delete(l_sync_request);
    }
}

/**
 * @brief s_sync_out_gdb_synced_data_worker_callback
 * @param a_worker
 * @param a_arg
 */
static void s_sync_out_gdb_last_worker_callback(dap_worker_t *a_worker, void *a_arg)
{
    struct sync_request * l_sync_request = (struct sync_request *) a_arg;
    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(a_worker), l_sync_request->ch_uuid);
    if( l_ch == NULL ){
        log_it(L_INFO,"Client disconnected before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return;
    }

    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH( l_ch );
    if (!l_ch_chain) {
        log_it(L_CRITICAL, "Channel without chain, dump it");
        s_sync_request_delete(l_sync_request);
        return;
    }
    s_sync_out_gdb_first_worker_callback(NULL,a_arg); // NULL to say callback not to delete request

    if (s_debug_more )
        log_it(L_INFO,"Out: DAP_CHAIN_CH_PKT_TYPE_SYNCED_GLOBAL_DB");
    dap_chain_ch_pkt_write_unsafe(DAP_STREAM_CH(l_ch_chain), DAP_CHAIN_CH_PKT_TYPE_SYNCED_GLOBAL_DB,
                                         l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                         l_ch_chain->request_hdr.cell_id.uint64, NULL, 0);
    s_ch_chain_go_idle(l_ch_chain);
    s_sync_request_delete(l_sync_request);
}

/**
 * @brief s_sync_out_gdb_callback
 * @param a_thread
 * @param a_arg
 * @return
 */
static bool s_sync_out_gdb_proc_callback(void *a_arg)
{
    /*
    struct sync_request *l_sync_request = (struct sync_request *)a_arg;
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_sync_request->request_hdr.net_id);
    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(l_sync_request->worker), l_sync_request->ch_uuid);
    if (l_ch == NULL) {
        log_it(L_INFO, "Client disconnected before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return true;
    }
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(l_ch);
    if (!l_ch_chain) {
        log_it(L_CRITICAL, "Channel without chain, dump it");
        s_sync_request_delete(l_sync_request);
        return true;
    }
    int l_flags = 0;
    if (dap_chain_net_get_extra_gdb_group(l_net, l_sync_request->request.node_addr))
        l_flags |= F_DB_LOG_ADD_EXTRA_GROUPS;
    if (!l_sync_request->request.id_start)
        l_flags |= F_DB_LOG_SYNC_FROM_ZERO;
    if (l_ch_chain->request_db_log != NULL)
        dap_db_log_list_delete(l_ch_chain->request_db_log);
    l_ch_chain->request_db_log = dap_db_log_list_start(l_net->pub.name, l_sync_request->request.node_addr.uint64, l_flags);

    if (l_ch_chain->request_db_log) {
        if (s_debug_more)
            log_it(L_DEBUG, "Sync out gdb proc, requested %"DAP_UINT64_FORMAT_U" records from address "NODE_ADDR_FP_STR,
                             l_ch_chain->request_db_log->items_number, NODE_ADDR_FP_ARGS_S(l_sync_request->request.node_addr));
        l_sync_request->gdb.db_log = l_ch_chain->request_db_log;
         dap_worker_exec_callback_on(dap_events_worker_get(l_sync_request->worker->id), s_sync_out_gdb_first_worker_callback, l_sync_request );
    } else {
         dap_worker_exec_callback_on(dap_events_worker_get(l_sync_request->worker->id), s_sync_out_gdb_last_worker_callback, l_sync_request );
    } */
    return false;
}

static void s_sync_update_gdb_start_worker_callback(dap_worker_t *a_worker, void *a_arg)
{
    struct sync_request *l_sync_request = (struct sync_request *) a_arg;

    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(a_worker), l_sync_request->ch_uuid);
    if( l_ch == NULL ){
        log_it(L_INFO,"Client disconnected before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return;
    }
    dap_chain_ch_pkt_write_unsafe(l_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_START,
                                         l_sync_request->request_hdr.net_id.uint64, l_sync_request->request_hdr.chain_id.uint64,
                                         l_sync_request->request_hdr.cell_id.uint64, NULL, 0);
    if (s_debug_more)
        log_it(L_INFO, "Out: DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_START for net_id 0x%016"DAP_UINT64_FORMAT_x" "
                       "chain_id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x"",
                       l_sync_request->request_hdr.net_id.uint64, l_sync_request->request_hdr.chain_id.uint64, l_sync_request->request_hdr.cell_id.uint64);
    DAP_DELETE(l_sync_request);
}

static bool s_sync_update_gdb_proc_callback(void *a_arg)
{
    /*
    struct sync_request *l_sync_request = (struct sync_request *)a_arg;
    log_it(L_DEBUG, "Prepare request to gdb sync from %s", l_sync_request->request.id_start ? "last sync" : "zero");
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_sync_request->request_hdr.net_id);
    if (!l_net) {
        log_it(L_ERROR, "Network ID 0x%016"DAP_UINT64_FORMAT_x" not found", l_sync_request->request_hdr.net_id.uint64);
        DAP_DELETE(l_sync_request);
        return true;
    }
    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(l_sync_request->worker), l_sync_request->ch_uuid);
    if (!l_ch) {
        log_it(L_INFO, "Client disconnected before we sent the reply");
        DAP_DELETE(l_sync_request);
        return true;
    } else if (!DAP_CHAIN_CH(l_ch)) {
        log_it(L_CRITICAL, "Channel without chain, dump it");
        DAP_DELETE(l_sync_request);
        return true;
    }

    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(l_ch);
    int l_flags = 0;
    if (dap_chain_net_get_extra_gdb_group(l_net, l_sync_request->request.node_addr))
        l_flags |= F_DB_LOG_ADD_EXTRA_GROUPS;
    if (!l_sync_request->request.id_start)
        l_flags |= F_DB_LOG_SYNC_FROM_ZERO;
    if (l_ch_chain->request_db_log != NULL)
        dap_db_log_list_delete(l_ch_chain->request_db_log);
    l_ch_chain->request_db_log = dap_db_log_list_start(l_net->pub.name, l_sync_request->request.node_addr.uint64, l_flags);
    l_ch_chain->state = DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB;
    l_sync_request->gdb.db_log = l_ch_chain->request_db_log;
    l_sync_request->request.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
     dap_worker_exec_callback_on(dap_events_worker_get(l_sync_request->worker->id), s_sync_update_gdb_start_worker_callback, l_sync_request);
     */
    return false;
}

static bool s_gdb_in_pkt_proc_callback(void *a_arg)
{
    return false;
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
    char *l_atom_hash_str = NULL;
    if (s_debug_more)
        dap_get_data_hash_str_static(l_atom, l_atom_size, l_atom_hash_str);
    dap_chain_atom_verify_res_t l_atom_add_res = l_chain->callback_atom_add(l_chain, l_atom, l_atom_size);
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
        debug_if(s_debug_more, L_INFO,"Accepted atom with hash %s for %s:%s", l_atom_hash_str, l_chain->net_name, l_chain->name);
        if (dap_chain_atom_save(l_chain->cells, l_atom, l_atom_size, NULL) < 0)
            log_it(L_ERROR, "Can't save atom %s to the file", l_atom_hash_str);
        else
            l_ack_send = true;
        break;
    case ATOM_REJECT: {
        debug_if(s_debug_more, L_WARNING, "Atom with hash %s for %s:%s rejected", l_atom_hash_str, l_chain->net_name, l_chain->name);
        break;
    }
    default:
        log_it(L_CRITICAL, "Wtf is this ret code? %d", l_atom_add_res);
        break;
    }
    if (l_ack_send && l_args->ack_req) {
        uint64_t l_ack_num = (l_chain_pkt->hdr.num_hi << 16) | l_chain_pkt->hdr.num_lo;
        dap_chain_ch_pkt_t *l_pkt = dap_chain_ch_pkt_new(l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                                         &l_ack_num, sizeof(uint64_t));
        dap_stream_ch_pkt_send_by_addr(&l_args->addr, DAP_CHAIN_CH_ID, DAP_CHAIN_CH_PKT_TYPE_CHAIN_ACK, l_pkt, dap_chain_ch_pkt_get_size(l_pkt));
        DAP_DELETE(l_pkt);
        debug_if(s_debug_more, L_DEBUG, "Out: CHAIN_ACK %s for net %s to destination " NODE_ADDR_FP_STR " with num %" DAP_UINT64_FORMAT_U,
                                l_chain ? l_chain->name : "(null)",
                                            l_chain ? l_chain->net_name : "(null)",
                                                            NODE_ADDR_FP_ARGS_S(l_args->addr),
                                l_ack_num);
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
    struct atom_processing_args *l_args = DAP_NEW_SIZE(struct atom_processing_args, a_payload_size + sizeof(struct atom_processing_args));
    if (!l_args) {
        log_it(L_CRITICAL, g_error_memory_alloc);
        return;
    }
    l_args->addr = a_sender_addr;
    l_args->ack_req = false;
    memcpy(l_args->data, a_payload, a_payload_size);
    dap_proc_thread_callback_add(NULL, s_sync_in_chains_callback, l_args);
}

/**
 * @brief s_gdb_in_pkt_error_worker_callback
 * @param a_thread
 * @param a_arg
 */
static void s_gdb_in_pkt_error_worker_callback(dap_worker_t *a_worker, void *a_arg)
{
    struct sync_request *l_sync_request = (struct sync_request *) a_arg;

    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(a_worker), l_sync_request->ch_uuid);
    if (l_ch == NULL)
        log_it(L_INFO,"Client disconnected before we sent the reply");
    else
        dap_stream_ch_write_error_unsafe(l_ch, l_sync_request->request_hdr.net_id.uint64,
                                           l_sync_request->request_hdr.chain_id.uint64,
                                           l_sync_request->request_hdr.cell_id.uint64,
                                           DAP_CHAIN_CH_ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED);
    DAP_DELETE(l_sync_request);
}

/**
 * @brief dap_chain_ch_create_sync_request_gdb
 * @param a_ch_chain
 * @param a_net
 */
struct sync_request *dap_chain_ch_create_sync_request(dap_chain_ch_pkt_t *a_chain_pkt, dap_stream_ch_t* a_ch)
{
    dap_chain_ch_t * l_ch_chain = DAP_CHAIN_CH(a_ch);
    if (!l_ch_chain) {
        log_it(L_CRITICAL, "Channel without chain, dump it");
        return NULL;
    }
    struct sync_request *l_sync_request = DAP_NEW_Z(struct sync_request);
    if (!l_sync_request) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    *l_sync_request = (struct sync_request) {
            .worker         = a_ch->stream_worker->worker,
            .ch_uuid        = a_ch->uuid,
            .request        = l_ch_chain->request,
            .request_hdr    = a_chain_pkt->hdr,
            .remote_atoms   = l_ch_chain->remote_atoms,
            .remote_gdbs    = l_ch_chain->remote_gdbs };
    return l_sync_request;
}

void dap_stream_ch_write_error_unsafe(dap_stream_ch_t *a_ch, uint64_t a_net_id, uint64_t a_chain_id, uint64_t a_cell_id, dap_chain_ch_error_type_t a_error)
{
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(a_ch);
    if (!l_ch_chain) {
        log_it(L_CRITICAL, "Channel without chain, dump it");
        return;
    }
    s_ch_chain_go_idle(l_ch_chain);
    dap_chain_ch_pkt_write_error_unsafe(a_ch, a_net_id, a_chain_id, a_cell_id, "%s", s_error_type_to_string(a_error));
}

static bool s_chain_timer_callback(void *a_arg)
{
    dap_worker_t *l_worker = dap_worker_get_current();
    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(l_worker), *(dap_stream_ch_uuid_t*)a_arg);
    if (!l_ch) {
        DAP_DELETE(a_arg);
        return false;
    }
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(l_ch);
    if (!l_ch_chain) {
        log_it(L_CRITICAL, "Channel without chain, dump it");
        DAP_DELETE(a_arg);
        return false;
    }
    if (l_ch_chain->timer_shots++ >= DAP_SYNC_TICKS_PER_SECOND * s_sync_timeout) {
        if (!s_ch_chain_get_idle(l_ch_chain))
            s_ch_chain_go_idle(l_ch_chain);
        DAP_DELETE(a_arg);
        l_ch_chain->activity_timer = NULL;
        return false;
    }
    if (l_ch_chain->state != DAP_CHAIN_CH_STATE_WAITING && l_ch_chain->sent_breaks) {
        s_stream_ch_packet_out(l_ch, a_arg);
        if (l_ch_chain->activity_timer == NULL)
            return false;
    }
    // Sending dumb packet with nothing to inform remote thats we're just skiping atoms of GDB's, nothing freezed
    if (l_ch_chain->state == DAP_CHAIN_CH_STATE_SYNC_CHAINS && l_ch_chain->sent_breaks >= 3 * DAP_SYNC_TICKS_PER_SECOND) {
        debug_if(s_debug_more, L_INFO, "Send one chain TSD packet");
        dap_chain_ch_pkt_write_unsafe(l_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_TSD,
                                             l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                             l_ch_chain->request_hdr.cell_id.uint64, NULL, 0);
        l_ch_chain->sent_breaks = 0;
        l_ch_chain->timer_shots = 0;
    }
    return true;
}

static void s_chain_timer_reset(dap_chain_ch_t *a_ch_chain)
{
    a_ch_chain->timer_shots = 0;
    if (!a_ch_chain->activity_timer)
        dap_chain_ch_timer_start(a_ch_chain);
}

void dap_chain_ch_timer_start(dap_chain_ch_t *a_ch_chain)
{
    dap_stream_ch_uuid_t *l_uuid = DAP_DUP(&DAP_STREAM_CH(a_ch_chain)->uuid);
    a_ch_chain->activity_timer = dap_timerfd_start_on_worker(DAP_STREAM_CH(a_ch_chain)->stream_worker->worker,
                                                             1000 / DAP_SYNC_TICKS_PER_SECOND,
                                                             s_chain_timer_callback, (void *)l_uuid);
    a_ch_chain->sent_breaks = 0;
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

    if (l_chain_pkt->hdr.version > DAP_CHAIN_CH_PKT_VERSION) {
        debug_if(s_debug_more, L_ATT, "Unsupported protocol version %d, current version %d",
                 l_chain_pkt->hdr.version, DAP_CHAIN_CH_PKT_VERSION);
        return false;
    }
    if (l_chain_pkt->hdr.version >= 2 &&
                l_chain_pkt_data_size != l_chain_pkt->hdr.data_size) {
        log_it(L_WARNING, "Incorrect chain packet size %zu, expected %u",
                            l_chain_pkt_data_size, l_chain_pkt->hdr.data_size);
        return false;
    }

    s_chain_timer_reset(l_ch_chain);

    switch (l_ch_pkt->hdr.type) {

    /* *** New synchronization protocol *** */

    case DAP_CHAIN_CH_PKT_TYPE_ERROR:{
        char * l_error_str = (char*)l_chain_pkt->data;
        if(l_chain_pkt_data_size>1)
            l_error_str[l_chain_pkt_data_size-1]='\0'; // To be sure that nobody sends us garbage
                                                       // without trailing zero
        log_it(L_WARNING, "In: from remote addr %s chain id 0x%016"DAP_UINT64_FORMAT_x" got error on his side: '%s'",
               DAP_STREAM_CH(l_ch_chain)->stream->esocket->remote_addr_str,
               l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt_data_size ? l_error_str : "<empty>");
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN: {
        dap_cluster_t *l_cluster = dap_cluster_find(dap_guuid_compose(l_chain_pkt->hdr.net_id.uint64, 0));
        if (!l_cluster) {
            log_it(L_WARNING, "Can't find cluster with ID 0x%" DAP_UINT64_FORMAT_X, l_chain_pkt->hdr.net_id.uint64);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                    DAP_CHAIN_CH_ERROR_CHAIN_NOT_FOUND);
            return false;
        }
        dap_cluster_member_t *l_check = dap_cluster_member_find_unsafe(l_cluster, &a_ch->stream->node);
        if (!l_check) {
            log_it(L_WARNING, "Node with addr "NODE_ADDR_FP_STR" isn't a member of cluster %s",
                                        NODE_ADDR_FP_ARGS_S(a_ch->stream->node), l_cluster->mnemonim);
            return false;
        }
        struct atom_processing_args *l_args = DAP_NEW_SIZE(struct atom_processing_args, l_ch_pkt->hdr.data_size + sizeof(struct atom_processing_args));
        if (!l_args) {
            log_it(L_CRITICAL, g_error_memory_alloc);
            break;
        }
        l_args->addr = a_ch->stream->node;
        l_args->ack_req = true;
        if (l_chain_pkt->hdr.version < 2)
            l_chain_pkt->hdr.data_size = l_chain_pkt_data_size;
        memcpy(l_args->data, l_chain_pkt, l_ch_pkt->hdr.data_size);
        if (s_debug_more) {
            char *l_atom_hash_str;
            dap_get_data_hash_str_static(l_chain_pkt->data, l_chain_pkt_data_size, l_atom_hash_str);
            log_it(L_INFO, "In: CHAIN pkt: atom hash %s (size %zd)", l_atom_hash_str, l_chain_pkt_data_size);
        }
        dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_sync_in_chains_callback, l_args);
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_REQ: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_ch_sync_request_t)) {
            log_it(L_WARNING, "DAP_CHAIN_CH_PKT_TYPE_CHAIN_REQ: Wrong chain packet size %zd when expected %zd",
                                                                            l_chain_pkt_data_size, sizeof(dap_chain_ch_sync_request_t));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        dap_chain_ch_sync_request_t *l_request = (dap_chain_ch_sync_request_t *)l_chain_pkt->data;
        if (s_debug_more)
            log_it(L_INFO, "In: CHAIN_REQ pkt: net 0x%016" DAP_UINT64_FORMAT_x " chain 0x%016" DAP_UINT64_FORMAT_x
                            " cell 0x%016" DAP_UINT64_FORMAT_x ", hash from %s, num from %" DAP_UINT64_FORMAT_U,
                            l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                            dap_hash_fast_to_str_static(&l_request->hash_from), l_request->num_from);
        if (l_ch_chain->sync_context) {
            log_it(L_WARNING, "Can't process CHAIN_REQ request cause already busy with syncronization");
            dap_chain_ch_pkt_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                    DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS);
            return false;
        }
        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        if (!l_chain) {
            log_it(L_WARNING, "Not found chain id 0x%016" DAP_UINT64_FORMAT_x " with net id 0x%016" DAP_UINT64_FORMAT_x,
                                                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.net_id.uint64);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                    DAP_CHAIN_CH_ERROR_CHAIN_NOT_FOUND);
            return false;
        }
        if (!dap_link_manager_get_net_condition(l_chain_pkt->hdr.net_id.uint64)) {
            log_it(L_WARNING, "Net id 0x%016" DAP_UINT64_FORMAT_x " is offline", l_chain_pkt->hdr.net_id.uint64);
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                    DAP_CHAIN_CH_ERROR_NET_IS_OFFLINE);
            return false;
        }
        bool l_sync_from_begin = dap_hash_fast_is_blank(&l_request->hash_from);
        dap_chain_atom_iter_t *l_iter = l_chain->callback_atom_iter_create(l_chain, l_chain_pkt->hdr.cell_id, l_sync_from_begin
                                                                           ? NULL : &l_request->hash_from);
        if (!l_iter) {
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
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
                                                l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                                                l_chain_pkt->hdr.cell_id.uint64, &l_sum, sizeof(l_sum));
                debug_if(s_debug_more, L_DEBUG, "Out: CHAIN_SUMMARY %s for net %s to destination " NODE_ADDR_FP_STR,
                                        l_chain ? l_chain->name : "(null)",
                                                    l_chain ? l_chain->net_name : "(null)",
                                                                    NODE_ADDR_FP_ARGS_S(a_ch->stream->node));
                struct sync_context *l_context = DAP_NEW_Z(struct sync_context);
                l_context->addr = a_ch->stream->node;
                l_context->iter = l_iter;
                l_context->net_id = l_chain_pkt->hdr.net_id;
                l_context->chain_id = l_chain_pkt->hdr.chain_id;
                l_context->cell_id = l_chain_pkt->hdr.cell_id;
                l_context->num_last = l_sum.num_last;
                l_context->last_activity = dap_time_now();
                atomic_store_explicit(&l_context->state, SYNC_STATE_READY, memory_order_relaxed);
                atomic_store(&l_context->allowed_num, l_sum.num_cur + s_sync_ack_window_size);
                dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_chain_iter_callback, l_context);
                l_ch_chain->sync_context = l_context;
                l_ch_chain->sync_timer = dap_timerfd_start_on_worker(a_ch->stream_worker->worker, 1000, s_sync_timer_callback, l_ch_chain);
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
                                                     .last_hash = *l_iter->cur_hash,
                                                     .last_num = l_iter->cur_num };
            dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS,
                                          l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                                          l_chain_pkt->hdr.cell_id.uint64, &l_miss_info, sizeof(l_miss_info));
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
                                          l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                                          l_chain_pkt->hdr.cell_id.uint64, NULL, 0);
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
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                    DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            return false;
        }
        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        dap_chain_ch_summary_t *l_sum = (dap_chain_ch_summary_t *)l_chain_pkt->data;
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
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
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
            log_it(L_WARNING, "CHAIN_ACK: No active sync context");
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                    DAP_CHAIN_CH_ERROR_INCORRECT_SYNC_SEQUENCE);
            break;
        }
        if (l_context->num_last == l_ack_num) {
            dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN,
                                                 l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                                                 l_chain_pkt->hdr.cell_id.uint64, NULL, 0);
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
        log_it(L_INFO, "In: SYNCED_CHAIN %s for net %s from source " NODE_ADDR_FP_STR,
                    l_chain ? l_chain->name : "(null)",
                                l_chain ? l_chain->net_name : "(null)",
                                                NODE_ADDR_FP_ARGS_S(a_ch->stream->node));
    } break;

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS: {
        if (l_chain_pkt_data_size != sizeof(dap_chain_ch_miss_info_t)) {
            log_it(L_WARNING, "DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS: Wrong chain packet size %zd when expected %zd",
                                                                            l_chain_pkt_data_size, sizeof(dap_chain_ch_miss_info_t));
            dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
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
        dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                            l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                            DAP_CHAIN_CH_ERROR_UNKNOWN_CHAIN_PKT_TYPE);
        return false;

//    }
//}

    /* *** Legacy *** */

        /// --- GDB update ---
        // Request for gdbs list update
        case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_REQ:{
            if(l_ch_chain->state != DAP_CHAIN_CH_STATE_IDLE){
                log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB_REQ request because its already busy with syncronization");
                dap_chain_ch_pkt_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS);
                break;
            }
            log_it(L_INFO, "In:  UPDATE_GLOBAL_DB_REQ pkt: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                            l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
            if (l_chain_pkt_data_size == (size_t)sizeof(dap_chain_ch_sync_request_old_t))
                l_ch_chain->request = *(dap_chain_ch_sync_request_old_t*)l_chain_pkt->data;
            struct sync_request *l_sync_request = dap_chain_ch_create_sync_request(l_chain_pkt, a_ch);
            l_ch_chain->stats_request_gdb_processed = 0;
            l_ch_chain->request_hdr = l_chain_pkt->hdr;
            dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_sync_update_gdb_proc_callback, l_sync_request);
        } break;

        // Response with metadata organized in TSD
        case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_TSD: {
            if (s_debug_more)
                log_it(L_DEBUG, "Global DB TSD packet detected");
        } break;

        // If requested - begin to recieve record's hashes
        case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_START:{
            if (s_debug_more)
                log_it(L_INFO, "In:  UPDATE_GLOBAL_DB_START pkt net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                                l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
            if (l_ch_chain->state != DAP_CHAIN_CH_STATE_IDLE){
                log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB_START request because its already busy with syncronization");
                dap_chain_ch_pkt_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS);
                break;
            }
            l_ch_chain->request_hdr = l_chain_pkt->hdr;
            l_ch_chain->state = DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB_REMOTE;
        } break;
        // Response with gdb element hashes and sizes
        case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB:{
            if(s_debug_more)
                log_it(L_INFO, "In: UPDATE_GLOBAL_DB pkt data_size=%zu", l_chain_pkt_data_size);
            if (l_ch_chain->state != DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB_REMOTE ||
                    memcmp(&l_ch_chain->request_hdr.net_id, &l_chain_pkt->hdr.net_id,
                           sizeof(dap_chain_net_id_t) + sizeof(dap_chain_id_t) + sizeof(dap_chain_cell_id_t))) {
                log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB request because its already busy with syncronization");
                dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS);
                break;
            }
            for ( dap_chain_ch_update_element_t * l_element =(dap_chain_ch_update_element_t *) l_chain_pkt->data;
                   (size_t) (((byte_t*)l_element) - l_chain_pkt->data ) < l_chain_pkt_data_size;
                  l_element++){
                dap_chain_ch_hash_item_t * l_hash_item = NULL;
                unsigned l_hash_item_hashv;
                HASH_VALUE(&l_element->hash, sizeof(l_element->hash), l_hash_item_hashv);
                HASH_FIND_BYHASHVALUE(hh, l_ch_chain->remote_gdbs, &l_element->hash, sizeof(l_element->hash),
                                      l_hash_item_hashv, l_hash_item);
                if (!l_hash_item) {
                    l_hash_item = DAP_NEW_Z(dap_chain_ch_hash_item_t);
                    if (!l_hash_item) {
                        log_it(L_CRITICAL, "Memory allocation error");
                        break;
                    }
                    l_hash_item->hash = l_element->hash;
                    l_hash_item->size = l_element->size;
                    HASH_ADD_BYHASHVALUE(hh, l_ch_chain->remote_gdbs, hash, sizeof(l_hash_item->hash),
                                         l_hash_item_hashv, l_hash_item);
                    /*if (s_debug_more){
                        char l_hash_str[72]={ [0]='\0'};
                        dap_chain_hash_fast_to_str(&l_hash_item->hash,l_hash_str,sizeof (l_hash_str));
                        log_it(L_DEBUG,"In: Updated remote hash gdb list with %s ", l_hash_str);
                    }*/
                }
            }
        } break;
        // End of response with starting of DB sync
        case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_END: {
            if(l_chain_pkt_data_size == sizeof(dap_chain_ch_sync_request_old_t)) {
                if (l_ch_chain->state != DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB_REMOTE ||
                        memcmp(&l_ch_chain->request_hdr.net_id, &l_chain_pkt->hdr.net_id,
                               sizeof(dap_chain_net_id_t) + sizeof(dap_chain_id_t) + sizeof(dap_chain_cell_id_t))) {
                    log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB_END request because its already busy with syncronization");
                    dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                            l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                            DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS);
                    break;
                }
                debug_if(s_debug_more, L_INFO, "In: UPDATE_GLOBAL_DB_END pkt with total count %d hashes",
                                        HASH_COUNT(l_ch_chain->remote_gdbs));
                if (l_chain_pkt_data_size == sizeof(dap_chain_ch_sync_request_old_t))
                    l_ch_chain->request = *(dap_chain_ch_sync_request_old_t*)l_chain_pkt->data;
                struct sync_request *l_sync_request = dap_chain_ch_create_sync_request(l_chain_pkt, a_ch);
                dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_sync_out_gdb_proc_callback, l_sync_request);
            } else {
                log_it(L_WARNING, "DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_END: Wrong chain packet size %zd when expected %zd", l_chain_pkt_data_size, sizeof(l_ch_chain->request));
                dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            }
        } break;
        // first packet of data with source node address
        case DAP_CHAIN_CH_PKT_TYPE_FIRST_GLOBAL_DB: {
            if(l_chain_pkt_data_size == (size_t)sizeof(dap_chain_node_addr_t)){
               l_ch_chain->request.node_addr = *(dap_chain_node_addr_t*)l_chain_pkt->data;
               l_ch_chain->stats_request_gdb_processed = 0;
               log_it(L_INFO, "In: FIRST_GLOBAL_DB data_size=%zu net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x
                              " from address "NODE_ADDR_FP_STR, l_chain_pkt_data_size,   l_chain_pkt->hdr.net_id.uint64 ,
                              l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, NODE_ADDR_FP_ARGS_S(l_ch_chain->request.node_addr) );
            }else {
               log_it(L_WARNING,"Incorrect data size %zu in packet DAP_CHAIN_CH_PKT_TYPE_FIRST_GLOBAL_DB", l_chain_pkt_data_size);
               dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                       l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                       DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            }
        } break;

        case DAP_CHAIN_CH_PKT_TYPE_GLOBAL_DB: {
            if(s_debug_more)
                log_it(L_INFO, "In: GLOBAL_DB data_size=%zu", l_chain_pkt_data_size);
            // get transaction and save it to global_db
            if(l_chain_pkt_data_size > 0) {
                struct sync_request *l_sync_request = dap_chain_ch_create_sync_request(l_chain_pkt, a_ch);
                dap_chain_pkt_item_t *l_pkt_item = &l_sync_request->pkt;
                l_pkt_item->pkt_data = DAP_DUP_SIZE(l_chain_pkt->data, l_chain_pkt_data_size);
                l_pkt_item->pkt_data_size = l_chain_pkt_data_size;
                dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_gdb_in_pkt_proc_callback, l_sync_request);
            } else {
                log_it(L_WARNING, "Packet with GLOBAL_DB atom has zero body size");
                dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            }
        }  break;

        case DAP_CHAIN_CH_PKT_TYPE_SYNCED_GLOBAL_DB: {
                log_it(L_INFO, "In:  SYNCED_GLOBAL_DB: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                                l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
                // we haven't node client waitng, so reply to other side
                dap_chain_ch_sync_request_old_t l_sync_gdb = {};
                l_sync_gdb.node_addr.uint64 = g_node_addr.uint64;
                dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_REQ, l_chain_pkt->hdr.net_id.uint64,
                                              l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, &l_sync_gdb, sizeof(l_sync_gdb));
        } break;

        /// --- Chains update ---
        // Request for atoms list update
        case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_REQ:{
            if (l_ch_chain->state != DAP_CHAIN_CH_STATE_IDLE) {
                log_it(L_WARNING, "Can't process UPDATE_CHAINS_REQ request because its already busy with syncronization");
                dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS);
                break;
            }
            if(s_debug_more)
                log_it(L_INFO, "In: UPDATE_CHAINS_REQ pkt: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                                l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if (l_chain) {
                l_ch_chain->state = DAP_CHAIN_CH_STATE_UPDATE_CHAINS;
                if(s_debug_more)
                    log_it(L_INFO, "Out: UPDATE_CHAINS_START pkt: net %s chain %s cell 0x%016"DAP_UINT64_FORMAT_X, l_chain->name,
                                        l_chain->net_name, l_chain_pkt->hdr.cell_id.uint64);
                l_ch_chain->request_atom_iter = l_chain->callback_atom_iter_create(l_chain, l_chain_pkt->hdr.cell_id, NULL);
                l_chain->callback_atom_iter_get(l_ch_chain->request_atom_iter, DAP_CHAIN_ITER_OP_FIRST, NULL);
                l_ch_chain->request_hdr = l_chain_pkt->hdr;
                dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_START,
                                                     l_chain_pkt->hdr.net_id.uint64,l_chain_pkt->hdr.chain_id.uint64,
                                                     l_chain_pkt->hdr.cell_id.uint64, NULL, 0);
            }
        } break;
        // Response with metadata organized in TSD
        case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_TSD :{
            if (s_debug_more)
                log_it(L_DEBUG, "Chain TSD packet detected");
        } break;

        // If requested - begin to send atom hashes
        case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_START:{
            if (l_ch_chain->state != DAP_CHAIN_CH_STATE_IDLE) {
                log_it(L_WARNING, "Can't process UPDATE_CHAINS_START request because its already busy with syncronization");
                dap_chain_ch_pkt_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS);
                break;
            }
            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if (!l_chain) {
                log_it(L_ERROR, "Invalid UPDATE_CHAINS_START request from %s with net id 0x%016"DAP_UINT64_FORMAT_x
                                " chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet",
                                a_ch->stream->esocket->remote_addr_str, l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                                l_chain_pkt->hdr.cell_id.uint64);
                dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                                    DAP_CHAIN_CH_ERROR_NET_INVALID_ID);
                // Who are you? I don't know you! go away!
                a_ch->stream->esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
                break;
            }
            l_ch_chain->state = DAP_CHAIN_CH_STATE_UPDATE_CHAINS_REMOTE;
            l_ch_chain->request_hdr = l_chain_pkt->hdr;
            debug_if(s_debug_more, L_INFO, "In: UPDATE_CHAINS_START pkt");
        } break;

        // Response with atom hashes and sizes
        case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS: {
            unsigned int l_count_added=0;
            unsigned int l_count_total=0;

            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if (! l_chain){
                log_it(L_ERROR, "Invalid UPDATE_CHAINS packet from %s with net id 0x%016"DAP_UINT64_FORMAT_x
                                " chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet",
                                a_ch->stream->esocket->remote_addr_str,
                                l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                                l_chain_pkt->hdr.cell_id.uint64);
                dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                                    DAP_CHAIN_CH_ERROR_NET_INVALID_ID);
                // Who are you? I don't know you! go away!
                a_ch->stream->esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
                break;
            }
            for ( dap_chain_ch_update_element_t * l_element =(dap_chain_ch_update_element_t *) l_chain_pkt->data;
                   (size_t) (((byte_t*)l_element) - l_chain_pkt->data ) < l_chain_pkt_data_size;
                  l_element++){
                dap_chain_ch_hash_item_t * l_hash_item = NULL;
                unsigned l_hash_item_hashv;
                HASH_VALUE(&l_element->hash, sizeof(dap_hash_fast_t), l_hash_item_hashv);
                HASH_FIND_BYHASHVALUE(hh, l_ch_chain->remote_atoms, &l_element->hash, sizeof(dap_hash_fast_t),
                                      l_hash_item_hashv, l_hash_item);
                if( ! l_hash_item ){
                    l_hash_item = DAP_NEW_Z(dap_chain_ch_hash_item_t);
                    if (!l_hash_item) {
                        log_it(L_CRITICAL, "Memory allocation error");
                        break;
                    }
                    l_hash_item->hash = l_element->hash;
                    l_hash_item->size = l_element->size;
                    HASH_ADD_BYHASHVALUE(hh, l_ch_chain->remote_atoms, hash, sizeof(dap_hash_fast_t),
                                         l_hash_item_hashv, l_hash_item);
                    l_count_added++;
                    /*
                    if (s_debug_more){
                        char l_hash_str[72]={ [0]='\0'};
                        dap_chain_hash_fast_to_str(&l_hash_item->hash,l_hash_str,sizeof (l_hash_str));
                        log_it(L_DEBUG,"In: Updated remote atom hash list with %s ", l_hash_str);
                    }*/
                }
                l_count_total++;
            }
            if (s_debug_more)
                log_it(L_INFO,"In: Added %u from %u remote atom hash  in list",l_count_added,l_count_total);
        } break;

        case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_END: {
            if(l_chain_pkt_data_size == sizeof(dap_chain_ch_sync_request_old_t)) {
                if (l_ch_chain->state != DAP_CHAIN_CH_STATE_UPDATE_CHAINS_REMOTE ||
                        memcmp(&l_ch_chain->request_hdr.net_id, &l_chain_pkt->hdr.net_id,
                               sizeof(dap_chain_net_id_t) + sizeof(dap_chain_id_t) + sizeof(dap_chain_cell_id_t))) {
                    log_it(L_WARNING, "Can't process UPDATE_CHAINS_END request because its already busy with syncronization");
                    dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                            l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                            DAP_CHAIN_CH_ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS);
                    break;
                }
                dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
                if (!l_chain) {
                    log_it(L_ERROR, "Invalid UPDATE_CHAINS packet from %s with net id 0x%016"DAP_UINT64_FORMAT_x
                                    " chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet",
                                    a_ch->stream->esocket->remote_addr_str, l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                                    l_chain_pkt->hdr.cell_id.uint64);
                    dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                                        DAP_CHAIN_CH_ERROR_NET_INVALID_ID);
                    break;
                }
                debug_if(s_debug_more, L_INFO, "In: UPDATE_CHAINS_END pkt with total count %d hashes",
                               HASH_COUNT(l_ch_chain->remote_atoms));
                struct sync_request *l_sync_request = dap_chain_ch_create_sync_request(l_chain_pkt, a_ch);
                l_ch_chain->stats_request_atoms_processed = 0;
                l_ch_chain->request_hdr = l_chain_pkt->hdr;
                dap_proc_thread_callback_add(a_ch->stream_worker->worker->proc_queue_input, s_sync_out_chains_proc_callback, l_sync_request);
            } else {
                log_it(L_WARNING, "DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_END: Wrong chain packet size %zd when expected %zd",
                       l_chain_pkt_data_size, sizeof(l_ch_chain->request));
                dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            }
        } break;
        // first packet of data with source node address
        case DAP_CHAIN_CH_PKT_TYPE_FIRST_CHAIN: {
            if(l_chain_pkt_data_size == (size_t)sizeof(dap_chain_node_addr_t)){
                l_ch_chain->request_hdr = l_chain_pkt->hdr;
                l_ch_chain->request.node_addr = *(dap_chain_node_addr_t*)l_chain_pkt->data;
                log_it(L_INFO, "From "NODE_ADDR_FP_STR": FIRST_CHAIN data_size=%zu net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                               NODE_ADDR_FP_ARGS_S(l_ch_chain->request.node_addr),
                               l_chain_pkt_data_size, l_ch_chain->request_hdr.net_id.uint64 ,
                               l_ch_chain->request_hdr.chain_id.uint64, l_ch_chain->request_hdr.cell_id.uint64);
            }else{
                log_it(L_WARNING,"Incorrect data size %zd in packet DAP_CHAIN_CH_PKT_TYPE_FIRST_CHAIN", l_chain_pkt_data_size);
                dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        DAP_CHAIN_CH_ERROR_CHAIN_PKT_DATA_SIZE);
            }
        } break;

        case DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAINS: {
            if (dap_log_level_get() <= L_INFO) {
                dap_chain_hash_fast_t l_hash_from = l_ch_chain->request.hash_from;
                char l_hash_from_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' }, l_hash_to_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
                dap_chain_hash_fast_to_str(&l_hash_from, l_hash_from_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                dap_chain_hash_fast_to_str(&c_dap_chain_addr_blank.data.hash_fast, l_hash_to_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                log_it(L_INFO, "In:  SYNCED_CHAINS: between %s and %s",l_hash_from_str[0] ? l_hash_from_str : "(null)",
                       l_hash_to_str[0] ? l_hash_to_str: "(null)");

            }
            s_ch_chain_get_idle(l_ch_chain);
            if (l_ch_chain->activity_timer) {
                dap_timerfd_delete_unsafe(l_ch_chain->activity_timer);
                l_ch_chain->activity_timer = NULL;
            }
            // we haven't node client waitng, so reply to other side
            dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if (!l_chain) {
                log_it(L_ERROR, "Invalid SYNCED_CHAINS packet from %s with net id 0x%016"DAP_UINT64_FORMAT_x
                                " chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet",
                                a_ch->stream->esocket->remote_addr_str, l_chain_pkt->hdr.net_id.uint64,
                                l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
                dap_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                                    DAP_CHAIN_CH_ERROR_NET_INVALID_ID);
                break;
            }
            if (s_debug_more) {
                log_it(L_INFO, "Out: UPDATE_CHAINS_REQ pkt");
            }
            dap_chain_ch_sync_request_old_t l_request= {};
            dap_chain_ch_pkt_write_unsafe(a_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_REQ, l_chain_pkt->hdr.net_id.uint64,
                                          l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, &l_request, sizeof(l_request));
        } break;
    }
    return true;
}

static bool s_sync_timer_callback(void *a_arg)
{
    dap_chain_ch_t *l_ch_chain = a_arg;
    struct sync_context *l_context = l_ch_chain->sync_context;
    if (l_context->last_activity + s_sync_timeout <= dap_time_now()) {
        log_it(L_ERROR, "Sync timeout for node " NODE_ADDR_FP_STR " with net 0x%016" DAP_UINT64_FORMAT_x
                            " chain 0x%016" DAP_UINT64_FORMAT_x " cell 0x%016" DAP_UINT64_FORMAT_x,
                                        NODE_ADDR_FP_ARGS_S(l_context->addr), l_context->net_id.uint64,
                                        l_context->chain_id.uint64, l_context->cell_id.uint64);
        l_ch_chain->sync_timer = NULL;      // Preserve timer removing from s_ch_chain_go_idle()
        dap_stream_ch_write_error_unsafe(DAP_STREAM_CH(l_ch_chain), l_context->net_id.uint64,
                                         l_context->chain_id.uint64, l_context->cell_id.uint64,
                                         DAP_CHAIN_CH_ERROR_SYNC_TIMEOUT);

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
    while (l_atom && l_atom_size) {
        if (l_iter->cur_num > atomic_load_explicit(&l_context->allowed_num, memory_order_acquire))
            break;
        dap_chain_ch_pkt_t *l_pkt = dap_chain_ch_pkt_new(l_context->net_id.uint64, l_context->chain_id.uint64, l_context->cell_id.uint64,
                                                         l_atom, l_atom_size);
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
//}
    // Legacy
    if (a_ch_chain->state == DAP_CHAIN_CH_STATE_IDLE) {
        return;
    }
    a_ch_chain->state = DAP_CHAIN_CH_STATE_IDLE;

    if(s_debug_more)
        log_it(L_INFO, "Go in DAP_CHAIN_CH_STATE_IDLE");

    // Cleanup after request
    memset(&a_ch_chain->request, 0, sizeof(a_ch_chain->request));
    memset(&a_ch_chain->request_hdr, 0, sizeof(a_ch_chain->request_hdr));
    if (a_ch_chain->request_atom_iter && a_ch_chain->request_atom_iter->chain &&
            a_ch_chain->request_atom_iter->chain->callback_atom_iter_delete) {
        a_ch_chain->request_atom_iter->chain->callback_atom_iter_delete(a_ch_chain->request_atom_iter);
        a_ch_chain->request_atom_iter = NULL;
    }

    dap_chain_ch_hash_item_t *l_hash_item = NULL, *l_tmp = NULL;

    HASH_ITER(hh, a_ch_chain->remote_atoms, l_hash_item, l_tmp) {
        // Clang bug at this, l_hash_item should change at every loop cycle
        HASH_DEL(a_ch_chain->remote_atoms, l_hash_item);
        DAP_DELETE(l_hash_item);
    }
    a_ch_chain->remote_atoms = NULL;
    a_ch_chain->sent_breaks = 0;
}

struct chain_io_complete {
    dap_stream_ch_uuid_t ch_uuid;
    dap_chain_ch_state_t state;
    uint8_t type;
    uint64_t net_id;
    uint64_t chain_id;
    uint64_t cell_id;
    size_t data_size;
    byte_t data[];
};

static void s_stream_ch_io_complete(dap_events_socket_t *a_es, void *a_arg)
{
    dap_stream_t *l_stream = NULL;
    if (!a_es->server) {
        dap_client_t *l_client = DAP_ESOCKET_CLIENT(a_es);
        assert(l_client);
        dap_client_pvt_t *l_client_pvt = DAP_CLIENT_PVT(l_client);
        l_stream = l_client_pvt->stream;
    } else {
        dap_http_client_t *l_http_client = DAP_HTTP_CLIENT(a_es);
        if (l_http_client)
            l_stream = DAP_STREAM(l_http_client);
    }
    if (!l_stream)
        return;
    dap_stream_ch_t *l_ch = NULL;
    for (size_t i = 0; i < l_stream->channel_count; i++)
        if (l_stream->channel[i]->proc->id == DAP_CHAIN_CH_ID)
            l_ch = l_stream->channel[i];
    if (!l_ch || !DAP_CHAIN_CH(l_ch))
        return;
    if (a_arg) {
        struct chain_io_complete *l_arg = (struct chain_io_complete *)a_arg;
        if (DAP_CHAIN_CH(l_ch)->state == DAP_CHAIN_CH_STATE_WAITING)
            DAP_CHAIN_CH(l_ch)->state = l_arg->state;
        dap_chain_ch_pkt_write_unsafe(l_ch, l_arg->type, l_arg->net_id, l_arg->chain_id,
                                             l_arg->cell_id, l_arg->data, l_arg->data_size);
        a_es->callbacks.arg = NULL;
        DAP_DELETE(a_arg);
        return;
    }
    s_stream_ch_packet_out(l_ch, NULL);
}

static void s_stream_ch_chain_pkt_write(dap_stream_ch_t *a_ch, uint8_t a_type, uint64_t a_net_id,
                                        uint64_t a_chain_id, uint64_t a_cell_id,
                                        const void * a_data, size_t a_data_size)
{
    size_t l_free_buf_size = dap_events_socket_get_free_buf_size(a_ch->stream->esocket) -
                                sizeof(dap_chain_ch_pkt_t) - sizeof(dap_stream_ch_pkt_t) -
                                sizeof(dap_stream_pkt_t) - DAP_STREAM_PKT_ENCRYPTION_OVERHEAD;
    if (l_free_buf_size < a_data_size) {
        struct chain_io_complete *l_arg = DAP_NEW_Z_SIZE(struct chain_io_complete, sizeof(struct chain_io_complete) + a_data_size);
        l_arg->ch_uuid = a_ch->uuid;
        l_arg->state = DAP_CHAIN_CH(a_ch)->state;
        DAP_CHAIN_CH(a_ch)->state = DAP_CHAIN_CH_STATE_WAITING;
        l_arg->type = a_type;
        l_arg->net_id = a_net_id;
        l_arg->chain_id = a_chain_id;
        l_arg->cell_id = a_cell_id;
        l_arg->data_size = a_data_size;
        memcpy(l_arg->data, a_data, a_data_size);
        a_ch->stream->esocket->callbacks.arg = l_arg;
    }
    else
       dap_chain_ch_pkt_write_unsafe(a_ch, a_type, a_net_id, a_chain_id, a_cell_id, a_data, a_data_size);
}

/**
 * @brief s_stream_ch_packet_out
 * @param ch
 * @param arg
 */
static bool s_stream_ch_packet_out(dap_stream_ch_t *a_ch, void *a_arg)
{
    dap_chain_ch_t *l_ch_chain = DAP_CHAIN_CH(a_ch);
    if (!l_ch_chain) {
        log_it(L_CRITICAL, "Channel without chain, dump it");
        s_ch_chain_go_idle(l_ch_chain);
        return false;
    }
    bool l_go_idle = false, l_was_sent_smth = false;
    switch (l_ch_chain->state) {
        // Update list of global DB records to remote
    case DAP_CHAIN_CH_STATE_UPDATE_GLOBAL_DB: {
#if 0
        size_t i, q =
                // s_update_pack_size;
                0;
        //dap_db_log_list_obj_t **l_objs = dap_db_log_list_get_multiple(l_ch_chain->request_db_log, DAP_STREAM_PKT_SIZE_MAX, &q);
        dap_chain_ch_update_element_t *l_data = DAP_NEW_Z_SIZE(dap_chain_ch_update_element_t, q * sizeof(dap_chain_ch_update_element_t));
        for (i = 0; i < q; ++i) {
            l_data[i].hash = l_objs[i]->hash;
            l_data[i].size = l_objs[i]->pkt->data_size;
            DAP_DELETE(l_objs[i]->pkt);
            DAP_DELETE(l_objs[i]);
        }
        if (i) {
            l_was_sent_smth = true;
            s_stream_ch_chain_pkt_write(a_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB,
                                        l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                        l_ch_chain->request_hdr.cell_id.uint64,
                                        l_data, i * sizeof(dap_chain_ch_update_element_t));
            l_ch_chain->stats_request_gdb_processed += i;
            DAP_DELETE(l_data);
            DAP_DELETE(l_objs);
            debug_if(s_debug_more, L_INFO, "Out: DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB, %zu records", i);
        } else if (!l_objs) {
            l_was_sent_smth = true;
            l_ch_chain->request.node_addr.uint64 = dap_chain_net_get_cur_addr_int(dap_chain_net_by_id(
                                                                                      l_ch_chain->request_hdr.net_id));
            s_stream_ch_chain_pkt_write(a_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_END,
                                                 l_ch_chain->request_hdr.net_id.uint64,
                                                 l_ch_chain->request_hdr.chain_id.uint64,
                                                 l_ch_chain->request_hdr.cell_id.uint64,
                                                 &l_ch_chain->request, sizeof(dap_chain_ch_sync_request_old_t));
            debug_if(s_debug_more, L_INFO, "Out: DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_END");
            l_go_idle = true;
        }
            dap_chain_ch_update_element_t l_data[s_update_pack_size];
            uint_fast16_t i;
            dap_db_log_list_obj_t *l_obj = NULL;
            for (i = 0; i < s_update_pack_size; i++) {
                l_obj = dap_db_log_list_get(l_ch_chain->request_db_log);
                if (!l_obj || DAP_POINTER_TO_SIZE(l_obj) == 1)
                    break;
                l_data[i].hash = l_obj->hash;
                l_data[i].size = l_obj->pkt->data_size;
                DAP_DELETE(l_obj->pkt);
                DAP_DELETE(l_obj);
            }
            if (i) {
                l_was_sent_smth = true;
                s_stream_ch_chain_pkt_write(a_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB,
                                            l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                            l_ch_chain->request_hdr.cell_id.uint64,
                                            l_data, i * sizeof(dap_chain_ch_update_element_t));
                l_ch_chain->stats_request_gdb_processed += i;
                if (s_debug_more)
                    log_it(L_INFO, "Out: DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB");
            } else if (!l_obj) {
                l_was_sent_smth = true;
                l_ch_chain->request.node_addr.uint64 = dap_chain_net_get_cur_addr_int(dap_chain_net_by_id(
                                                                                          l_ch_chain->request_hdr.net_id));
                s_stream_ch_chain_pkt_write(a_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_END,
                                                     l_ch_chain->request_hdr.net_id.uint64,
                                                     l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64,
                                                     &l_ch_chain->request, sizeof(dap_chain_ch_sync_request_old_t));
                if (s_debug_more )
                    log_it(L_INFO, "Out: DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_END");
                l_go_idle = true;
            }
#endif
        } break;

        // Synchronize GDB
    case DAP_CHAIN_CH_STATE_SYNC_GLOBAL_DB: {
#if 0
        dap_global_db_pkt_t *l_pkt = NULL;
        size_t l_pkt_size = 0, i, q = 0;
        dap_db_log_list_obj_t **l_objs = dap_db_log_list_get_multiple(l_ch_chain->request_db_log, DAP_STREAM_PKT_SIZE_MAX, &q);
        for (i = 0; i < q; ++i) {
            dap_chain_ch_hash_item_t *l_hash_item = NULL;
            unsigned l_hash_item_hashv = 0;
            HASH_VALUE(&l_objs[i]->hash, sizeof(dap_chain_hash_fast_t), l_hash_item_hashv);
            HASH_FIND_BYHASHVALUE(hh, l_ch_chain->remote_gdbs, &l_objs[i]->hash,
                                  sizeof(dap_hash_fast_t), l_hash_item_hashv, l_hash_item);
            if (!l_hash_item) {
                l_hash_item = DAP_NEW_Z(dap_chain_ch_hash_item_t);
                *l_hash_item = (dap_chain_ch_hash_item_t) {
                        .hash   = l_objs[i]->hash, .size   = l_objs[i]->pkt->data_size
                };
                HASH_ADD_BYHASHVALUE(hh, l_ch_chain->remote_gdbs, hash, sizeof(dap_chain_hash_fast_t),
                                     l_hash_item_hashv, l_hash_item);
                l_pkt = dap_global_db_pkt_pack(l_pkt, l_objs[i]->pkt);
                l_ch_chain->stats_request_gdb_processed++;
                l_pkt_size = sizeof(dap_global_db_pkt_t) + l_pkt->data_size;
            }

            DAP_DELETE(l_objs[i]->pkt);
            DAP_DELETE(l_objs[i]);
        }

        if (l_pkt_size) {
            l_was_sent_smth = true;
            // If request was from defined node_addr we update its state
            s_stream_ch_chain_pkt_write(a_ch, DAP_CHAIN_CH_PKT_TYPE_GLOBAL_DB,
                                        l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                        l_ch_chain->request_hdr.cell_id.uint64, l_pkt, l_pkt_size);
            debug_if(s_debug_more, L_INFO, "Send one global_db packet, size %zu, rest %zu/%zu items", l_pkt_size,
                     l_ch_chain->request_db_log->items_rest,
                     l_ch_chain->request_db_log->items_number);
            DAP_DELETE(l_pkt);
            DAP_DELETE(l_objs);
        } else if (!l_objs) {
            l_was_sent_smth = true;
            // last message
            dap_chain_ch_sync_request_old_t l_request = { };
            s_stream_ch_chain_pkt_write(a_ch, DAP_CHAIN_CH_PKT_TYPE_SYNCED_GLOBAL_DB,
                                        l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                        l_ch_chain->request_hdr.cell_id.uint64, &l_request, sizeof(l_request));
            l_go_idle = true;
            if (l_ch_chain->callback_notify_packet_out)
                l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_CHAIN_CH_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                       NULL, 0, l_ch_chain->callback_notify_arg);
            log_it(L_INFO,"Syncronized database: items syncronyzed %"DAP_UINT64_FORMAT_U" of %zu",
                    l_ch_chain->stats_request_gdb_processed, l_ch_chain->request_db_log->items_number);
        }
            // Get global DB record
            dap_global_db_pkt_t *l_pkt = NULL;
            dap_db_log_list_obj_t *l_obj = NULL;
            size_t l_pkt_size = 0;
            for (uint_fast16_t l_skip_count = 0; l_skip_count < s_skip_in_reactor_count; ) {
                l_obj = dap_db_log_list_get(l_ch_chain->request_db_log);
                if (!l_obj || DAP_POINTER_TO_SIZE(l_obj) == 1) {
                    l_skip_count = s_skip_in_reactor_count;
                    break;
                }
                dap_chain_ch_hash_item_t *l_hash_item = NULL;
                unsigned l_hash_item_hashv = 0;
                HASH_VALUE(&l_obj->hash, sizeof(dap_chain_hash_fast_t), l_hash_item_hashv);
                HASH_FIND_BYHASHVALUE(hh, l_ch_chain->remote_gdbs, &l_obj->hash, sizeof(dap_hash_fast_t),
                                      l_hash_item_hashv, l_hash_item);
                if (l_hash_item) { // If found - skip it
                    /*if (s_debug_more) {
                        char l_request_atom_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                        dap_chain_hash_fast_to_str(&l_obj->hash, l_request_atom_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                        log_it(L_DEBUG, "Out CHAIN: skip GDB hash %s because its already present in remote GDB hash table",
                                        l_request_atom_hash_str);
                    }*/
                    l_skip_count++;
                } else {
                    l_hash_item = DAP_NEW_Z(dap_chain_ch_hash_item_t);
                    if (!l_hash_item) {
                        log_it(L_CRITICAL, "Memory allocation error");
                        return;
                    }
                    l_hash_item->hash = l_obj->hash;
                    l_hash_item->size = l_obj->pkt->data_size;
                    HASH_ADD_BYHASHVALUE(hh, l_ch_chain->remote_gdbs, hash, sizeof(dap_chain_hash_fast_t),
                                         l_hash_item_hashv, l_hash_item);
                    l_pkt = dap_global_db_pkt_pack(l_pkt, l_obj->pkt);
                    l_ch_chain->stats_request_gdb_processed++;
                    l_pkt_size = sizeof(dap_global_db_pkt_t) + l_pkt->data_size;
                }
                DAP_DELETE(l_obj->pkt);
                DAP_DELETE(l_obj);
                if (l_pkt_size >= DAP_CHAIN_PKT_EXPECT_SIZE)
                    break;
            }
            if (l_pkt_size) {
                l_was_sent_smth = true;
                // If request was from defined node_addr we update its state
                if (s_debug_more)
                    log_it(L_INFO, "Send one global_db packet len=%zu (rest=%zu/%zu items)", l_pkt_size,
                                    dap_db_log_list_get_count_rest(l_ch_chain->request_db_log),
                                    dap_db_log_list_get_count(l_ch_chain->request_db_log));
                s_stream_ch_chain_pkt_write(a_ch, DAP_CHAIN_CH_PKT_TYPE_GLOBAL_DB,
                                                     l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64, l_pkt, l_pkt_size);
                DAP_DELETE(l_pkt);
            } else if (!l_obj) {
                l_was_sent_smth = true;
                log_it( L_INFO,"Syncronized database: items syncronyzed %"DAP_UINT64_FORMAT_U" from %zu",
                        l_ch_chain->stats_request_gdb_processed, dap_db_log_list_get_count(l_ch_chain->request_db_log));
                // last message
                dap_chain_ch_sync_request_old_t l_request = {};
                s_stream_ch_chain_pkt_write(a_ch, DAP_CHAIN_CH_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                     l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64, &l_request, sizeof(l_request));
                l_go_idle = true;
                if (l_ch_chain->callback_notify_packet_out)
                    l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_CHAIN_CH_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                           NULL, 0, l_ch_chain->callback_notify_arg);
            }
#endif
    } break;

        // Update list of atoms to remote
        case DAP_CHAIN_CH_STATE_UPDATE_CHAINS:{
            dap_chain_ch_update_element_t *l_data = DAP_NEW_Z_SIZE(dap_chain_ch_update_element_t,
                                                                          sizeof(dap_chain_ch_update_element_t) * s_update_pack_size);
            size_t l_data_size=0;
            for(uint_fast16_t n=0; n<s_update_pack_size && (l_ch_chain->request_atom_iter && l_ch_chain->request_atom_iter->cur);n++){
                l_data[n].hash = *l_ch_chain->request_atom_iter->cur_hash;
                // Shift offset counter
                l_data_size += sizeof(dap_chain_ch_update_element_t);
                // Then get next atom
                l_ch_chain->request_atom_iter->chain->callback_atom_iter_get(l_ch_chain->request_atom_iter, DAP_CHAIN_ITER_OP_NEXT, NULL);
            }
            if (l_data_size){
                l_was_sent_smth = true;
                if(s_debug_more)
                    log_it(L_DEBUG,"Out: UPDATE_CHAINS with %zu hashes sent", l_data_size / sizeof(dap_chain_ch_update_element_t));
                s_stream_ch_chain_pkt_write(a_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS,
                                                     l_ch_chain->request_hdr.net_id.uint64,
                                                     l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64,
                                                     l_data,l_data_size);
            }
            if(!l_data_size  ||  !l_ch_chain->request_atom_iter){ // We over with all the hashes here
                l_was_sent_smth = true;
                if(s_debug_more)
                    log_it(L_INFO,"Out: UPDATE_CHAINS_END sent ");
                dap_chain_ch_sync_request_old_t l_request = {};
                s_stream_ch_chain_pkt_write(a_ch, DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_END,
                                                     l_ch_chain->request_hdr.net_id.uint64,
                                                     l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64,
                                                     &l_request, sizeof(dap_chain_ch_sync_request_old_t));
                l_go_idle = true;
                dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
            }
            DAP_DELETE(l_data);
        }break;

        // Synchronize chains
        case DAP_CHAIN_CH_STATE_SYNC_CHAINS: {
            // Process one chain from l_ch_chain->request_atom_iter
            // Pack loop to skip quicker
            for(uint_fast16_t k=0; k<s_skip_in_reactor_count     &&
                                   l_ch_chain->request_atom_iter &&
                                   l_ch_chain->request_atom_iter->cur; k++){
                // Check if present and skip if present
                dap_chain_ch_hash_item_t *l_hash_item = NULL;
                unsigned l_hash_item_hashv = 0;
                HASH_VALUE(l_ch_chain->request_atom_iter->cur_hash, sizeof(dap_chain_hash_fast_t), l_hash_item_hashv);
                HASH_FIND_BYHASHVALUE(hh, l_ch_chain->remote_atoms, l_ch_chain->request_atom_iter->cur_hash,
                                      sizeof(dap_chain_hash_fast_t), l_hash_item_hashv, l_hash_item);
                if( l_hash_item ){ // If found - skip it
                    /*if(s_debug_more){
                        char l_request_atom_hash_str[81]={[0]='\0'};
                        dap_chain_hash_fast_to_str(l_ch_chain->request_atom_iter->cur_hash,l_request_atom_hash_str,sizeof (l_request_atom_hash_str));
                        log_it(L_DEBUG, "Out CHAIN: skip atom hash %s because its already present in remote atom hash table",
                                        l_request_atom_hash_str);
                    }*/
                }else{
                    l_hash_item = DAP_NEW_Z(dap_chain_ch_hash_item_t);
                    if (!l_hash_item) {
                        log_it(L_CRITICAL, "Memory allocation error");
                        return false;
                    }
                    l_hash_item->hash = *l_ch_chain->request_atom_iter->cur_hash;
                    if(s_debug_more){
                        char l_atom_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                        dap_chain_hash_fast_to_str(&l_hash_item->hash, l_atom_hash_str, sizeof(l_atom_hash_str));
                        log_it(L_INFO, "Out CHAIN pkt: atom hash %s (size %zd) ", l_atom_hash_str, l_ch_chain->request_atom_iter->cur_size);
                    }
                    s_stream_ch_chain_pkt_write(a_ch, DAP_CHAIN_CH_PKT_TYPE_CHAIN, l_ch_chain->request_hdr.net_id.uint64,
                                                         l_ch_chain->request_hdr.chain_id.uint64, l_ch_chain->request_hdr.cell_id.uint64,
                                                         l_ch_chain->request_atom_iter->cur, l_ch_chain->request_atom_iter->cur_size);
                    l_was_sent_smth = true;
                    l_ch_chain->stats_request_atoms_processed++;

                    l_hash_item->size = l_ch_chain->request_atom_iter->cur_size;
                    // Because we sent this atom to remote - we record it to not to send it twice
                    HASH_ADD_BYHASHVALUE(hh, l_ch_chain->remote_atoms, hash, sizeof(dap_hash_fast_t), l_hash_item_hashv,
                                         l_hash_item);
                }
                // Then get next atom and populate new last
                l_ch_chain->request_atom_iter->chain->callback_atom_iter_get(l_ch_chain->request_atom_iter, DAP_CHAIN_ITER_OP_NEXT, NULL);
                if (l_was_sent_smth)
                    break;
            }
            if(!l_ch_chain->request_atom_iter || !l_ch_chain->request_atom_iter->cur)  { // All chains synced
                dap_chain_ch_sync_request_old_t l_request = {};
                // last message
                l_was_sent_smth = true;
                s_stream_ch_chain_pkt_write(a_ch, DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAINS,
                                                     l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64, &l_request, sizeof(l_request));
                log_it( L_INFO,"Synced: %"DAP_UINT64_FORMAT_U" atoms processed", l_ch_chain->stats_request_atoms_processed);
                l_go_idle = true;
            }
        } break;

        default:
            return false;
    }
    if (l_was_sent_smth) {
        s_chain_timer_reset(l_ch_chain);
        l_ch_chain->sent_breaks = 0;
    } else
        l_ch_chain->sent_breaks++;
    if (l_go_idle) {
        s_ch_chain_go_idle(l_ch_chain);
        if (l_ch_chain->activity_timer) {
            if (!a_arg)
                dap_timerfd_delete_unsafe(l_ch_chain->activity_timer);
            l_ch_chain->activity_timer = NULL;
        }
        return false;
    }
    return true;
}
