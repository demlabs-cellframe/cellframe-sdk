/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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
#include "dap_global_db_remote.h"

#include "dap_stream.h"
#include "dap_stream_pkt.h"
#include "dap_stream_worker.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_chain_net.h"

#define LOG_TAG "dap_stream_ch_chain"

struct sync_request
{
    dap_worker_t * worker;
    dap_stream_ch_uuid_t ch_uuid;
    dap_stream_ch_chain_sync_request_t request;
    dap_stream_ch_chain_pkt_hdr_t request_hdr;
    dap_chain_pkt_item_t pkt;

    dap_stream_ch_chain_hash_item_t *remote_atoms; // Remote atoms
    dap_stream_ch_chain_hash_item_t *remote_gdbs; // Remote gdbs

    uint64_t stats_request_elemets_processed;
    int last_err;
    union{
        struct{
            dap_db_log_list_t *db_log; //  db log
            dap_list_t *db_iter;
            char *sync_group;
        } gdb;
        struct{
            dap_chain_atom_iter_t *request_atom_iter;
        } chain;
    };
};

static void s_ch_chain_go_idle(dap_stream_ch_chain_t *a_ch_chain);
static inline bool s_ch_chain_get_idle(dap_stream_ch_chain_t *a_ch_chain) { return a_ch_chain->state == CHAIN_STATE_IDLE; }

static void s_stream_ch_new(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_io_complete(dap_events_socket_t *a_es, void *a_arg, int a_errno);
static void s_stream_ch_write_error_unsafe(dap_stream_ch_t *a_ch, uint64_t a_net_id, uint64_t a_chain_id, uint64_t a_cell_id, const char * a_err_string);

static bool s_sync_out_chains_proc_callback(dap_proc_thread_t *a_thread, void *a_arg);
static void s_sync_out_chains_last_worker_callback(dap_worker_t *a_worker, void *a_arg);
static void s_sync_out_chains_first_worker_callback(dap_worker_t *a_worker, void *a_arg);

static bool s_sync_out_gdb_proc_callback(dap_proc_thread_t *a_thread, void *a_arg);

static bool s_sync_in_chains_callback(dap_proc_thread_t *a_thread, void *a_arg);

static bool s_gdb_in_pkt_proc_callback(dap_proc_thread_t *a_thread, void *a_arg);
static void s_gdb_in_pkt_proc_set_raw_callback(dap_global_db_context_t *a_global_db_context,
                                               int a_rc, const char *a_group,
                                               const size_t a_values_total, const size_t a_values_count,
                                               dap_store_obj_t *a_values, void *a_arg);
static void s_gdb_in_pkt_error_worker_callback(dap_worker_t *a_thread, void *a_arg);
static void s_free_log_list_gdb ( dap_stream_ch_chain_t * a_ch_chain);

static void s_stream_ch_chain_pkt_write(dap_stream_ch_t *a_ch, uint8_t a_type, uint64_t a_net_id,
                                        uint64_t a_chain_id, uint64_t a_cell_id,
                                        const void * a_data, size_t a_data_size);

static bool s_debug_more=false;
static uint_fast16_t s_update_pack_size=100; // Number of hashes packed into the one packet
static uint_fast16_t s_skip_in_reactor_count=50; // Number of hashes packed to skip in one reactor loop callback out packet
static char **s_list_ban_groups = NULL;
static char **s_list_white_groups = NULL;
static uint16_t s_size_ban_groups = 0;
static uint16_t s_size_white_groups = 0;


#ifdef  DAP_SYS_DEBUG

enum    {MEMSTAT$K_STM_CH_CHAIN, MEMSTAT$K_NR};
static  dap_memstat_rec_t   s_memstat [MEMSTAT$K_NR] = {
    {.fac_len = sizeof(LOG_TAG) - 1, .fac_name = {LOG_TAG}, .alloc_sz = sizeof(dap_stream_ch_chain_t)},
};

#endif



/**
 * @brief dap_stream_ch_chain_init
 * @return
 */
int dap_stream_ch_chain_init()
{
    log_it(L_NOTICE, "Chains and global db exchange channel initialized");
    dap_stream_ch_proc_add(DAP_STREAM_CH_ID, s_stream_ch_new, s_stream_ch_delete, s_stream_ch_packet_in,
            s_stream_ch_packet_out);
    s_debug_more = dap_config_get_item_bool_default(g_config,"stream_ch_chain","debug_more",false);
    s_update_pack_size = dap_config_get_item_int16_default(g_config,"stream_ch_chain","update_pack_size",100);
    s_list_ban_groups = dap_config_get_array_str(g_config, "stream_ch_chain", "ban_list_sync_groups", &s_size_ban_groups);
    s_list_white_groups = dap_config_get_array_str(g_config, "stream_ch_chain", "white_list_sync_groups", &s_size_white_groups);

#ifdef  DAP_SYS_DEBUG
    for (int i = 0; i < MEMSTAT$K_NR; i++)
        dap_memstat_reg(&s_memstat[i]);
#endif

    return 0;
}

/**
 * @brief dap_stream_ch_chain_deinit
 */
void dap_stream_ch_chain_deinit()
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
    a_ch->internal = DAP_NEW_Z(dap_stream_ch_chain_t);
    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
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
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    if (l_ch_chain->callback_notify_packet_out)
        l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_DELETE, NULL, 0,
                                               l_ch_chain->callback_notify_arg);
    s_ch_chain_go_idle(l_ch_chain);
    debug_if(s_debug_more, L_DEBUG, "[stm_ch_chain:%p] --- deleted chain:%p", a_ch, l_ch_chain);
    DAP_DEL_Z(a_ch->internal);

#ifdef  DAP_SYS_DEBUG
    atomic_fetch_add(&s_memstat[MEMSTAT$K_STM_CH_CHAIN].free_nr, 1);
#endif
}

void dap_stream_ch_chain_reset_unsafe(dap_stream_ch_chain_t *a_ch_chain)
{
    if (!a_ch_chain)
        return;
    s_ch_chain_go_idle(a_ch_chain);
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

    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
    if (l_ch_chain->state != CHAIN_STATE_UPDATE_CHAINS_REMOTE) {
        log_it(L_INFO, "Timeout fired before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return;
    }

    l_ch_chain->state = CHAIN_STATE_SYNC_CHAINS;
    l_ch_chain->request_atom_iter = l_sync_request->chain.request_atom_iter;
    dap_chain_node_addr_t l_node_addr = {};
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_sync_request->request_hdr.net_id);
    l_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);

    if (s_debug_more )
        log_it(L_INFO,"Out: DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN");

    dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN,
            l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
            l_ch_chain->request_hdr.cell_id.uint64, &l_node_addr, sizeof(dap_chain_node_addr_t));
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

    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
    l_ch_chain->request_atom_iter = l_sync_request->chain.request_atom_iter;
    // last packet
    dap_stream_ch_chain_sync_request_t l_request = {};
    if (s_debug_more )
        log_it(L_INFO,"Out: DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS");
    dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS,
            l_sync_request->request_hdr.net_id.uint64, l_sync_request->request_hdr.chain_id.uint64,
            l_sync_request->request_hdr.cell_id.uint64, &l_request, sizeof(l_request));
    s_ch_chain_go_idle(l_ch_chain);
    if (l_ch_chain->callback_notify_packet_out)
        l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS,
                                                NULL, 0, l_ch_chain->callback_notify_arg);
    DAP_DELETE(l_sync_request);
}
/**
 * @brief s_sync_chains_callback
 * @param a_thread
 * @param a_arg
 * @return
 */
static bool s_sync_out_chains_proc_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    struct sync_request * l_sync_request = (struct sync_request *) a_arg;

    dap_chain_t * l_chain = dap_chain_find_by_id(l_sync_request->request_hdr.net_id, l_sync_request->request_hdr.chain_id);
    assert(l_chain);
    //pthread_rwlock_rdlock(&l_chain->atoms_rwlock);
    l_sync_request->chain.request_atom_iter = l_chain->callback_atom_iter_create(l_chain, l_sync_request->request_hdr.cell_id, 1);
    size_t l_first_size = 0;
    dap_chain_atom_ptr_t l_atom = l_chain->callback_atom_iter_get_first(l_sync_request->chain.request_atom_iter, &l_first_size);
    if (l_atom && l_first_size) {
        // first packet
        dap_chain_hash_fast_t l_hash_from = l_sync_request->request.hash_from;
        if (!dap_hash_fast_is_blank(&l_hash_from)) {
            (void ) l_chain->callback_atom_find_by_hash(l_sync_request->chain.request_atom_iter,
                                                          &l_hash_from, &l_first_size);
        }
        //pthread_rwlock_unlock(&l_chain->atoms_rwlock);
        dap_proc_thread_worker_exec_callback_inter(a_thread, l_sync_request->worker->id, s_sync_out_chains_first_worker_callback, l_sync_request );
    } else {
        //pthread_rwlock_unlock(&l_chain->atoms_rwlock);
        dap_proc_thread_worker_exec_callback_inter(a_thread, l_sync_request->worker->id,s_sync_out_chains_last_worker_callback, l_sync_request );
    }
    return true;
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

    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN( l_ch );
    if (l_ch_chain->state != CHAIN_STATE_UPDATE_GLOBAL_DB_REMOTE) {
        log_it(L_INFO, "Timeout fired before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return;
    }

    dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain->request_hdr.net_id);
    // Add it to outgoing list
    l_ch_chain->state = CHAIN_STATE_SYNC_GLOBAL_DB;
    dap_chain_node_addr_t l_node_addr = { 0 };
    l_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
    if (s_debug_more )
        log_it(L_INFO,"Out: DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB");
    dap_stream_ch_chain_pkt_write_unsafe(DAP_STREAM_CH(l_ch_chain), DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB,
            l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
            l_ch_chain->request_hdr.cell_id.uint64, &l_node_addr, sizeof(dap_chain_node_addr_t));
    if(l_ch_chain->callback_notify_packet_out)
        l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB,
                                                NULL, 0, l_ch_chain->callback_notify_arg);

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

    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN( l_ch );
    s_sync_out_gdb_first_worker_callback(NULL,a_arg); // NULL to say callback not to delete request

    if (s_debug_more )
        log_it(L_INFO,"Out: DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB");
    dap_stream_ch_chain_pkt_write_unsafe(DAP_STREAM_CH(l_ch_chain), DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                         l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                         l_ch_chain->request_hdr.cell_id.uint64, NULL, 0);
    s_ch_chain_go_idle(l_ch_chain);
    if(l_ch_chain->callback_notify_packet_out)
        l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                NULL, 0, l_ch_chain->callback_notify_arg);
    s_sync_request_delete(l_sync_request);
}

/**
 * @brief s_sync_out_gdb_callback
 * @param a_thread
 * @param a_arg
 * @return
 */
static bool s_sync_out_gdb_proc_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    struct sync_request *l_sync_request = (struct sync_request *)a_arg;
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_sync_request->request_hdr.net_id);
    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(l_sync_request->worker), l_sync_request->ch_uuid);
    if (l_ch == NULL) {
        log_it(L_INFO, "Client disconnected before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return true;
    }
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);

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
            log_it(L_DEBUG, "Sync out gdb proc, requested %"DAP_UINT64_FORMAT_U" transactions from address "NODE_ADDR_FP_STR,
                             l_ch_chain->request_db_log->items_number, NODE_ADDR_FP_ARGS_S(l_sync_request->request.node_addr));
        l_sync_request->gdb.db_log = l_ch_chain->request_db_log;
        dap_proc_thread_worker_exec_callback_inter(a_thread, l_sync_request->worker->id, s_sync_out_gdb_first_worker_callback, l_sync_request );
    } else {
        dap_proc_thread_worker_exec_callback_inter(a_thread, l_sync_request->worker->id, s_sync_out_gdb_last_worker_callback, l_sync_request );
    }
    return true;
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
    dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_START,
                                         l_sync_request->request_hdr.net_id.uint64, l_sync_request->request_hdr.chain_id.uint64,
                                         l_sync_request->request_hdr.cell_id.uint64, NULL, 0);
    if (s_debug_more)
        log_it(L_INFO, "Out: DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_START for net_id 0x%016"DAP_UINT64_FORMAT_x" "
                       "chain_id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x"",
                       l_sync_request->request_hdr.net_id.uint64, l_sync_request->request_hdr.chain_id.uint64, l_sync_request->request_hdr.cell_id.uint64);
    DAP_DELETE(l_sync_request);
}

static bool s_sync_update_gdb_proc_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
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
    }
    dap_chain_net_add_downlink(l_net, l_ch->stream_worker, l_ch->uuid, l_ch->stream->esocket_uuid,
                               l_ch->stream->esocket->hostaddr,
                               strtoll(l_ch->stream->esocket->service, NULL, 10));

    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
    int l_flags = 0;
    if (dap_chain_net_get_extra_gdb_group(l_net, l_sync_request->request.node_addr))
        l_flags |= F_DB_LOG_ADD_EXTRA_GROUPS;
    if (!l_sync_request->request.id_start)
        l_flags |= F_DB_LOG_SYNC_FROM_ZERO;
    if (l_ch_chain->request_db_log != NULL)
        dap_db_log_list_delete(l_ch_chain->request_db_log);
    l_ch_chain->request_db_log = dap_db_log_list_start(l_net->pub.name, l_sync_request->request.node_addr.uint64, l_flags);
    l_ch_chain->state = CHAIN_STATE_UPDATE_GLOBAL_DB;
    l_sync_request->gdb.db_log = l_ch_chain->request_db_log;
    l_sync_request->request.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
    dap_proc_thread_worker_exec_callback_inter(a_thread, l_sync_request->worker->id, s_sync_update_gdb_start_worker_callback, l_sync_request);
    return true;
}

/**
 * @brief s_sync_in_chains_callback
 * @param a_thread dap_proc_thread_t
 * @param a_arg void
 * @return
 */
static bool s_sync_in_chains_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    struct sync_request *l_sync_request = (struct sync_request *) a_arg;
    if (!l_sync_request) {
        log_it(L_CRITICAL, "Proc thread received corrupted chain packet!");
        return true;
    }
    dap_chain_pkt_item_t *l_pkt_item = &l_sync_request->pkt;
    dap_chain_hash_fast_t l_atom_hash = {};
    if (l_pkt_item->pkt_data_size == 0 || !l_pkt_item->pkt_data) {
        log_it(L_CRITICAL, "In proc thread got CHAINS stream ch packet with zero data");
        DAP_DEL_Z(l_pkt_item->pkt_data);
        DAP_DELETE(l_sync_request);
        return true;
    }
    dap_chain_t *l_chain = dap_chain_find_by_id(l_sync_request->request_hdr.net_id, l_sync_request->request_hdr.chain_id);
    if (!l_chain) {
        if (s_debug_more)
            log_it(L_WARNING, "No chain found for DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN");
        DAP_DEL_Z(l_pkt_item->pkt_data);
        DAP_DELETE(l_sync_request);
        return true;
    }
    dap_chain_atom_ptr_t l_atom_copy = (dap_chain_atom_ptr_t)l_pkt_item->pkt_data;
    uint64_t l_atom_copy_size = l_pkt_item->pkt_data_size;
    dap_hash_fast(l_atom_copy, l_atom_copy_size, &l_atom_hash);
    dap_chain_atom_verify_res_t l_atom_add_res = l_chain->callback_atom_add(l_chain, l_atom_copy, l_atom_copy_size);
    char l_atom_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = {[0]='\0'};
    dap_chain_hash_fast_to_str(&l_atom_hash,l_atom_hash_str,sizeof (l_atom_hash_str));
    switch (l_atom_add_res) {
    case ATOM_PASS:
        if (s_debug_more){
            log_it(L_WARNING, "Atom with hash %s for %s:%s not accepted (code ATOM_PASS, already present)",  l_atom_hash_str, l_chain->net_name, l_chain->name);
        }
        dap_chain_db_set_last_hash_remote(l_sync_request->request.node_addr.uint64, l_chain, &l_atom_hash);
        DAP_DELETE(l_atom_copy);
        break;
    case ATOM_MOVE_TO_THRESHOLD:
        if (s_debug_more) {
            log_it(L_INFO, "Thresholded atom with hash %s for %s:%s", l_atom_hash_str, l_chain->net_name, l_chain->name);
        }
        dap_chain_db_set_last_hash_remote(l_sync_request->request.node_addr.uint64, l_chain, &l_atom_hash);
        break;
    case ATOM_ACCEPT:
        if (s_debug_more) {
            log_it(L_INFO,"Accepted atom with hash %s for %s:%s", l_atom_hash_str, l_chain->net_name, l_chain->name);
        }
        int l_res = dap_chain_atom_save(l_chain, l_atom_copy, l_atom_copy_size, l_sync_request->request_hdr.cell_id);
        if(l_res < 0) {
            log_it(L_ERROR, "Can't save atom %s to the file", l_atom_hash_str);
        } else {
            dap_chain_db_set_last_hash_remote(l_sync_request->request.node_addr.uint64, l_chain, &l_atom_hash);
        }
        break;
    case ATOM_REJECT: {
        if (s_debug_more) {
            char l_atom_hash_str[72] = {'\0'};
            dap_chain_hash_fast_to_str(&l_atom_hash,l_atom_hash_str,sizeof (l_atom_hash_str)-1 );
            log_it(L_WARNING,"Atom with hash %s for %s:%s rejected", l_atom_hash_str, l_chain->net_name, l_chain->name);
        }
        DAP_DELETE(l_atom_copy);
        break;
    }
    default:
        DAP_DELETE(l_atom_copy);
        log_it(L_CRITICAL, "Wtf is this ret code? %d", l_atom_add_res);
        break;
    }
    DAP_DEL_Z(l_sync_request);
    return true;
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
    if( l_ch == NULL ) {
        log_it(L_INFO,"Client disconnected before we sent the reply");
    } else {
        dap_stream_ch_chain_pkt_write_error_unsafe(l_ch, l_sync_request->request_hdr.net_id.uint64,
                                                   l_sync_request->request_hdr.chain_id.uint64,
                                                   l_sync_request->request_hdr.cell_id.uint64,
                                                   "%s : err %d", "ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED", l_sync_request->last_err);
    }
    DAP_DELETE(l_sync_request);
}

/**
 * @brief s_gdb_sync_tsd_worker_callback
 * @param a_worker
 * @param a_arg
 */
static void s_gdb_sync_tsd_worker_callback(dap_worker_t *a_worker, void *a_arg)
{
    struct sync_request *l_sync_request = (struct sync_request *) a_arg;

    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(a_worker), l_sync_request->ch_uuid);
    if( l_ch == NULL ) {
        log_it(L_INFO,"Client disconnected before we sent the reply");
    } else {
        size_t l_gr_len = strlen(l_sync_request->gdb.sync_group) + 1;
        size_t l_data_size = 2 * sizeof(uint64_t) + l_gr_len;
        dap_tsd_t *l_tsd_rec = DAP_NEW_SIZE(dap_tsd_t, l_data_size + sizeof(dap_tsd_t));
        l_tsd_rec->type = DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_TSD_LAST_ID;
        l_tsd_rec->size = l_data_size;
        uint64_t l_node_addr = dap_chain_net_get_cur_addr_int(dap_chain_net_by_id(l_sync_request->request_hdr.net_id));
        void *l_data_ptr = l_tsd_rec->data;
        memcpy(l_data_ptr, &l_node_addr, sizeof(uint64_t));
        l_data_ptr += sizeof(uint64_t);
        memcpy(l_data_ptr, &l_sync_request->request.id_end, sizeof(uint64_t));
        l_data_ptr += sizeof(uint64_t);
        memcpy(l_data_ptr, l_sync_request->gdb.sync_group, l_gr_len);
        s_stream_ch_chain_pkt_write(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_TSD,
                                             l_sync_request->request_hdr.net_id.uint64,
                                             l_sync_request->request_hdr.chain_id.uint64,
                                             l_sync_request->request_hdr.cell_id.uint64,
                                             l_tsd_rec, l_tsd_rec->size + sizeof(dap_tsd_t));
        DAP_DELETE(l_tsd_rec);
    }
    DAP_DELETE(l_sync_request->gdb.sync_group);
    DAP_DELETE(l_sync_request);
}

/**
 * @brief s_gdb_in_pkt_proc_callback_get_ts_callback
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_len
 * @param value_ts
 * @param a_is_pinned
 * @param a_arg
 */

/**
 * @brief s_gdb_in_pkt_callback
 * @param a_thread
 * @param a_arg
 * @return
 */
static bool s_gdb_in_pkt_proc_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    struct sync_request *l_sync_request = (struct sync_request *) a_arg;
    dap_chain_pkt_item_t *l_pkt_item = &l_sync_request->pkt;

    if(l_pkt_item->pkt_data_size >= sizeof(dap_global_db_pkt_t)) {

        // Validate size of received packet
        dap_global_db_pkt_t *l_obj_pkt = (dap_global_db_pkt_t*)l_pkt_item->pkt_data;
        size_t l_obj_pkt_size = l_obj_pkt ? l_obj_pkt->data_size + sizeof(dap_global_db_pkt_t) : 0;
        if(l_pkt_item->pkt_data_size != l_obj_pkt_size) {
            log_it(L_WARNING, "In: s_gdb_in_pkt_proc_callback: received size=%zu is not equal to obj_pkt_size=%zu",
                    l_pkt_item->pkt_data_size, l_obj_pkt_size);
            DAP_DEL_Z(l_pkt_item->pkt_data);
            DAP_DELETE(l_sync_request);
            return true;
        }

        size_t l_data_obj_count = 0;
        // deserialize data & Parse data from dap_db_log_pack()
        dap_store_obj_t *l_store_obj = dap_global_db_pkt_deserialize(l_obj_pkt, &l_data_obj_count);
        if (!l_store_obj) {
            debug_if(s_debug_more, L_ERROR, "Invalid synchronization packet format");
            DAP_DEL_Z(l_pkt_item->pkt_data);
            DAP_DELETE(l_sync_request);
            return true;
        }
        if (s_debug_more){
            if (l_data_obj_count)
                log_it(L_INFO, "In: GLOBAL_DB parse: pkt_data_size=%"DAP_UINT64_FORMAT_U", l_data_obj_count = %zu",l_pkt_item->pkt_data_size, l_data_obj_count );
            else if (l_pkt_item->pkt_data){
                log_it(L_WARNING, "In: GLOBAL_DB parse: pkt_data_size=%"DAP_UINT64_FORMAT_U", error=\"No data objs after unpack\"", l_pkt_item->pkt_data_size);
            }else
                 log_it(L_WARNING, "In: GLOBAL_DB parse: packet in list with NULL data(pkt_data_size:%"DAP_UINT64_FORMAT_U")", l_pkt_item->pkt_data_size);
        }
        /*uint64_t l_last_id = l_store_obj->id;
        const char *l_last_group = l_store_obj->group;
        uint32_t l_last_type = l_store_obj->type;
        bool l_group_changed = false;*/
        uint32_t l_time_store_lim_hours = dap_config_get_item_uint32_default(g_config, "global_db", "time_store_limit", 72);
        dap_nanotime_t l_time_now = dap_nanotime_now();
        dap_nanotime_t l_time_alowed = l_time_now + dap_nanotime_from_sec(3600 * 24); // to be sure the timestamp is invalid
        for (size_t i = 0; i < l_data_obj_count; i++) {
            // obj to add
            dap_store_obj_t *l_obj = l_store_obj + i;
            if (l_obj->timestamp >> 32 == 0 ||
                    l_obj->timestamp > l_time_alowed ||
                    l_obj->group == NULL)
                continue;       // the object is broken
            if (s_list_white_groups) {
                int l_ret = -1;
                for (int i = 0; i < s_size_white_groups; i++) {
                    if (!dap_fnmatch(s_list_white_groups[i], l_obj->group, FNM_NOESCAPE)) {
                        l_ret = 0;
                        break;
                    }
                }
                if (l_ret == -1) continue;
            } else if (s_list_ban_groups) {
                int l_ret = 0;
                for (int i = 0; i < s_size_ban_groups; i++) {
                    if (!dap_fnmatch(s_list_ban_groups[i], l_obj->group, FNM_NOESCAPE)) {
                        l_ret = -1;
                        break;
                    }
                }
                if (l_ret == -1) continue;
            }
            /*l_group_changed = strcmp(l_last_group, l_obj->group) || l_last_type != l_obj->type;
            // Send remote side notification about received obj
            if (l_sync_request->request.node_addr.uint64 &&
                    (l_group_changed || i == l_data_obj_count - 1)) {
                struct sync_request *l_sync_req_tsd = DAP_DUP(l_sync_request);
                l_sync_req_tsd->request.id_end = l_last_id;
                l_sync_req_tsd->gdb.sync_group = l_obj->type == DAP_DB$K_OPTYPE_ADD ? dap_strdup(l_last_group) :
                                                                      dap_strdup_printf("%s.del", l_last_group);
                dap_proc_thread_worker_exec_callback_inter(a_thread, l_sync_request->worker->id,
                                                     s_gdb_sync_tsd_worker_callback, l_sync_req_tsd);
            }
            l_last_id = l_obj->id;
            l_last_group = l_obj->group;
            l_last_type = l_obj->type;
            */
            dap_global_db_remote_apply_obj(l_obj, s_gdb_in_pkt_proc_set_raw_callback, DAP_DUP(l_sync_request));
        }
        if (l_store_obj)
            dap_store_obj_free(l_store_obj, l_data_obj_count);
    } else {
        log_it(L_WARNING, "In proc thread got GDB stream ch packet with zero data");
    }
    if (l_pkt_item->pkt_data) {
        DAP_DELETE(l_pkt_item->pkt_data);
    }
    DAP_DELETE(l_sync_request);
    return true;
}

/**
 * @brief s_gdb_in_pkt_proc_set_raw_callback
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_values_current
 * @param a_values_shift
 * @param a_values_count
 * @param a_values
 * @param a_arg
 */
static void s_gdb_in_pkt_proc_set_raw_callback(dap_global_db_context_t *a_global_db_context,
                                               int a_rc, const char *a_group,
                                               const size_t a_values_total, const size_t a_values_count,
                                               dap_store_obj_t *a_values, void *a_arg)
{

    struct sync_request *l_sync_req = (struct sync_request*) a_arg;
    if( a_rc != 0){
        debug_if(s_debug_more, L_ERROR, "Can't save GlobalDB request, code %d", a_rc);
        l_sync_req->last_err = a_rc;
        dap_worker_exec_callback_inter(a_global_db_context->queue_worker_callback_input[l_sync_req->worker->id],
                                    s_gdb_in_pkt_error_worker_callback, l_sync_req);
    }else{
        debug_if(s_debug_more, L_DEBUG, "Added new GLOBAL_DB synchronization record");
        DAP_DELETE(l_sync_req);
    }
}


/**
 * @brief dap_stream_ch_chain_create_sync_request_gdb
 * @param a_ch_chain
 * @param a_net
 */
struct sync_request *dap_stream_ch_chain_create_sync_request(dap_stream_ch_chain_pkt_t *a_chain_pkt, dap_stream_ch_t* a_ch)
{
    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
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

static void s_stream_ch_write_error_unsafe(dap_stream_ch_t *a_ch, uint64_t a_net_id, uint64_t a_chain_id, uint64_t a_cell_id, const char * a_err_string)
{
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    s_ch_chain_go_idle(l_ch_chain);
    dap_stream_ch_chain_pkt_write_error_unsafe(a_ch, a_net_id, a_chain_id, a_cell_id, "%s", a_err_string);
}

static bool s_chain_timer_callback(void *a_arg)
{
    dap_worker_t *l_worker = dap_worker_get_current();
    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(l_worker), *(dap_stream_ch_uuid_t*)a_arg);
    if (!l_ch) {
        dap_chain_net_del_downlink(*(dap_stream_ch_uuid_t*)a_arg);
        DAP_DELETE(a_arg);
        return false;
    }
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
    if (l_ch_chain->timer_shots++ >= DAP_SYNC_TICKS_PER_SECOND * DAP_CHAIN_NODE_SYNC_TIMEOUT) {
        if (!s_ch_chain_get_idle(l_ch_chain)) {
            s_ch_chain_go_idle(l_ch_chain);
            if (l_ch_chain->callback_notify_packet_out)
                l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_TIMEOUT, NULL, 0,
                                                      l_ch_chain->callback_notify_arg);
        }
        DAP_DELETE(a_arg);
        l_ch_chain->activity_timer = NULL;
        return false;
    }
    if (l_ch_chain->state != CHAIN_STATE_WAITING && l_ch_chain->sent_breaks) {
        s_stream_ch_packet_out(l_ch, a_arg);
        if (l_ch_chain->activity_timer == NULL)
            return false;
    }
    // Sending dumb packet with nothing to inform remote thats we're just skiping atoms of GDB's, nothing freezed
    if (l_ch_chain->state == CHAIN_STATE_SYNC_CHAINS && l_ch_chain->sent_breaks >= 3 * DAP_SYNC_TICKS_PER_SECOND) {
        debug_if(s_debug_more, L_INFO, "Send one chain TSD packet");
        dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_TSD,
                                             l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                             l_ch_chain->request_hdr.cell_id.uint64, NULL, 0);
        l_ch_chain->sent_breaks = 0;
        l_ch_chain->timer_shots = 0;
    }
    if (l_ch_chain->state == CHAIN_STATE_SYNC_GLOBAL_DB && l_ch_chain->sent_breaks >= 3 * DAP_SYNC_TICKS_PER_SECOND) {
        debug_if(s_debug_more, L_INFO, "Send one global_db TSD packet (rest=%zu/%zu items)",
                            dap_db_log_list_get_count_rest(l_ch_chain->request_db_log),
                            dap_db_log_list_get_count(l_ch_chain->request_db_log));
        dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_TSD,
                                             l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                             l_ch_chain->request_hdr.cell_id.uint64, NULL, 0);
        l_ch_chain->sent_breaks = 0;
        l_ch_chain->timer_shots = 0;
    }
    return true;
}

static void s_chain_timer_reset(dap_stream_ch_chain_t *a_ch_chain)
{
    a_ch_chain->timer_shots = 0;
    if (!a_ch_chain->activity_timer)
        dap_stream_ch_chain_timer_start(a_ch_chain);
}

void dap_stream_ch_chain_timer_start(dap_stream_ch_chain_t *a_ch_chain)
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
void s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg)
{
    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    if (!l_ch_chain || l_ch_chain->_inheritor != a_ch) {
        log_it(L_ERROR, "No chain in channel, returning");
        return;
    }
    dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
    dap_stream_ch_chain_pkt_t * l_chain_pkt = (dap_stream_ch_chain_pkt_t *) l_ch_pkt->data;
    if (!l_chain_pkt) {
        log_it(L_ERROR, "No chain packet in channel packet, returning");
        return;
    }
    if (l_ch_pkt->hdr.data_size < sizeof (l_chain_pkt->hdr)){
        log_it(L_ERROR, "Corrupted packet: too small size %u, smaller then header size %zu", l_ch_pkt->hdr.data_size,
               sizeof(l_chain_pkt->hdr));
        return;
    }
    if (l_chain_pkt->hdr.version != DAP_STREAM_CH_CHAIN_PKT_VERSION) {
        debug_if(s_debug_more, L_ATT, "Unsupported protocol version %d, current version %d",
                 l_chain_pkt->hdr.version, DAP_STREAM_CH_CHAIN_PKT_VERSION);
        return;
    }
    size_t l_chain_pkt_data_size = l_ch_pkt->hdr.data_size - sizeof(l_chain_pkt->hdr);
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_chain_pkt->hdr.net_id);
    if (!l_net) {
        if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR) {
            if(l_ch_chain->callback_notify_packet_in) {
                l_ch_chain->callback_notify_packet_in(l_ch_chain, l_ch_pkt->hdr.type, l_chain_pkt,
                                                      l_chain_pkt_data_size, l_ch_chain->callback_notify_arg);
            }
        } else {
            log_it(L_ERROR, "Invalid request from %s with ext_id %016"DAP_UINT64_FORMAT_x" net id 0x%016"DAP_UINT64_FORMAT_x
                            " chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet",
                            a_ch->stream->esocket->hostaddr, l_chain_pkt->hdr.ext_id,
                            l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                            l_chain_pkt->hdr.cell_id.uint64);
            s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                                l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                                "ERROR_NET_INVALID_ID");
            // Who are you? I don't know you! go away!
            a_ch->stream->esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
        }
        return;
    }
    if (dap_chain_net_get_state(l_net) == NET_STATE_OFFLINE) {
        s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                            l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                            "ERROR_NET_IS_OFFLINE");
        a_ch->stream->esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
        return;
    }
    uint16_t l_acl_idx = dap_chain_net_get_acl_idx(l_net);
    uint8_t l_acl = a_ch->stream->session->acl ? a_ch->stream->session->acl[l_acl_idx] : 1;
    if (!l_acl) {
        log_it(L_WARNING, "Unauthorized request attempt from %s to network %s",
               a_ch->stream->esocket->hostaddr,
               dap_chain_net_by_id(l_chain_pkt->hdr.net_id)->pub.name);
        s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                            l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                            "ERROR_NET_NOT_AUTHORIZED");
        return;
    }
    s_chain_timer_reset(l_ch_chain);
    switch (l_ch_pkt->hdr.type) {
        /// --- GDB update ---
        // Request for gdbs list update
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_REQ:{
            if(l_ch_chain->state != CHAIN_STATE_IDLE){
                log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB_REQ request because its already busy with syncronization");
                dap_stream_ch_chain_pkt_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS");
                break;
            }
            log_it(L_INFO, "In:  UPDATE_GLOBAL_DB_REQ pkt: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                            l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
            if (l_chain_pkt_data_size == (size_t)sizeof(dap_stream_ch_chain_sync_request_t))
                l_ch_chain->request = *(dap_stream_ch_chain_sync_request_t*)l_chain_pkt->data;
            dap_chain_node_client_t *l_client = (dap_chain_node_client_t *)l_ch_chain->callback_notify_arg;
            if (l_client && l_client->resync_gdb)
                l_ch_chain->request.id_start = 0;
            else
                l_ch_chain->request.id_start = 1;   // incremental sync by default
            struct sync_request *l_sync_request = dap_stream_ch_chain_create_sync_request(l_chain_pkt, a_ch);
            l_ch_chain->stats_request_gdb_processed = 0;
            l_ch_chain->request_hdr = l_chain_pkt->hdr;
            dap_proc_queue_add_callback_inter(a_ch->stream_worker->worker->proc_queue_input, s_sync_update_gdb_proc_callback, l_sync_request);
        } break;

        // Response with metadata organized in TSD
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_TSD: {
            if (l_chain_pkt_data_size) {
                dap_tsd_t *l_tsd_rec = (dap_tsd_t *)l_chain_pkt->data;
                if (l_tsd_rec->type != DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_TSD_LAST_ID ||
                        l_tsd_rec->size < 2 * sizeof(uint64_t) + 2) {
                    break;
                }
                void *l_data_ptr = l_tsd_rec->data;
                uint64_t l_node_addr = *(uint64_t *)l_data_ptr;
                l_data_ptr += sizeof(uint64_t);
                uint64_t l_last_id = *(uint64_t *)l_data_ptr;
                l_data_ptr += sizeof(uint64_t);
                char *l_group = (char *)l_data_ptr;
                dap_db_set_last_id_remote(l_node_addr, l_last_id, l_group);
                if (s_debug_more) {
                    dap_chain_node_addr_t l_addr;
                    l_addr.uint64 = l_node_addr;
                    log_it(L_INFO, "Set last_id %"DAP_UINT64_FORMAT_U" for group %s for node "NODE_ADDR_FP_STR,
                                    l_last_id, l_group, NODE_ADDR_FP_ARGS_S(l_addr));
                }
            } else if (s_debug_more)
                log_it(L_DEBUG, "Global DB TSD packet detected");
        } break;

        // If requested - begin to recieve record's hashes
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_START:{
            if (s_debug_more)
                log_it(L_INFO, "In:  UPDATE_GLOBAL_DB_START pkt net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                                l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
            if (l_ch_chain->state != CHAIN_STATE_IDLE){
                log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB_START request because its already busy with syncronization");
                dap_stream_ch_chain_pkt_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS");
                break;
            }
            l_ch_chain->request_hdr = l_chain_pkt->hdr;
            l_ch_chain->state = CHAIN_STATE_UPDATE_GLOBAL_DB_REMOTE;
        } break;
        // Response with gdb element hashes and sizes
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB:{
            if(s_debug_more)
                log_it(L_INFO, "In: UPDATE_GLOBAL_DB pkt data_size=%zu", l_chain_pkt_data_size);
            if (l_ch_chain->state != CHAIN_STATE_UPDATE_GLOBAL_DB_REMOTE ||
                    memcmp(&l_ch_chain->request_hdr, &l_chain_pkt->hdr, sizeof(dap_stream_ch_chain_pkt_t))) {
                log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB request because its already busy with syncronization");
                s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS");
                break;
            }
            for ( dap_stream_ch_chain_update_element_t * l_element =(dap_stream_ch_chain_update_element_t *) l_chain_pkt->data;
                   (size_t) (((byte_t*)l_element) - l_chain_pkt->data ) < l_chain_pkt_data_size;
                  l_element++){
                dap_stream_ch_chain_hash_item_t * l_hash_item = NULL;
                unsigned l_hash_item_hashv;
                HASH_VALUE(&l_element->hash, sizeof(l_element->hash), l_hash_item_hashv);
                HASH_FIND_BYHASHVALUE(hh, l_ch_chain->remote_gdbs, &l_element->hash, sizeof(l_element->hash),
                                      l_hash_item_hashv, l_hash_item);
                if (!l_hash_item) {
                    l_hash_item = DAP_NEW_Z(dap_stream_ch_chain_hash_item_t);
                    if (!l_hash_item) {
                        log_it(L_CRITICAL, "Memory allocation error");
                        return;
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
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB:
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_END: {
            if(l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t)) {
                if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB && l_ch_chain->state != CHAIN_STATE_IDLE) {
                    log_it(L_WARNING, "Can't process SYNC_GLOBAL_DB request because not in idle state");
                    dap_stream_ch_chain_pkt_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                            l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                            "ERROR_STATE_NOT_IN_IDLE");
                    break;
                }
                if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_END &&
                        (l_ch_chain->state != CHAIN_STATE_UPDATE_GLOBAL_DB_REMOTE ||
                        memcmp(&l_ch_chain->request_hdr, &l_chain_pkt->hdr, sizeof(dap_stream_ch_chain_pkt_t)))) {
                    log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB_END request because its already busy with syncronization");
                    s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                            l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                            "ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS");
                    break;
                }
                if(s_debug_more)
                {
                    if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_END)
                        log_it(L_INFO, "In: UPDATE_GLOBAL_DB_END pkt with total count %d hashes",
                                        HASH_COUNT(l_ch_chain->remote_gdbs));
                    else
                        log_it(L_INFO, "In: SYNC_GLOBAL_DB pkt");
                }
                if (l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t))
                    l_ch_chain->request = *(dap_stream_ch_chain_sync_request_t*)l_chain_pkt->data;
                struct sync_request *l_sync_request = dap_stream_ch_chain_create_sync_request(l_chain_pkt, a_ch);
                dap_proc_queue_add_callback_inter(a_ch->stream_worker->worker->proc_queue_input, s_sync_out_gdb_proc_callback, l_sync_request);
            }else{
                log_it(L_WARNING, "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB: Wrong chain packet size %zd when expected %zd", l_chain_pkt_data_size, sizeof(l_ch_chain->request));
                s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_CHAIN_PKT_DATA_SIZE" );
            }
        } break;
        // first packet of data with source node address
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB: {
            if(l_chain_pkt_data_size == (size_t)sizeof(dap_chain_node_addr_t)){
               l_ch_chain->request.node_addr = *(dap_chain_node_addr_t*)l_chain_pkt->data;
               l_ch_chain->stats_request_gdb_processed = 0;
               log_it(L_INFO, "In: FIRST_GLOBAL_DB data_size=%zu net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x
                              " from address "NODE_ADDR_FP_STR, l_chain_pkt_data_size,   l_chain_pkt->hdr.net_id.uint64 ,
                              l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, NODE_ADDR_FP_ARGS_S(l_ch_chain->request.node_addr) );
            }else {
               log_it(L_WARNING,"Incorrect data size %zu in packet DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB", l_chain_pkt_data_size);
               s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                       l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                       "ERROR_CHAIN_PACKET_TYPE_FIRST_GLOBAL_DB_INCORRET_DATA_SIZE");
            }
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB: {
            if(s_debug_more)
                log_it(L_INFO, "In: GLOBAL_DB data_size=%zu", l_chain_pkt_data_size);
            // get transaction and save it to global_db
            if(l_chain_pkt_data_size > 0) {
                struct sync_request *l_sync_request = dap_stream_ch_chain_create_sync_request(l_chain_pkt, a_ch);
                dap_chain_pkt_item_t *l_pkt_item = &l_sync_request->pkt;
                l_pkt_item->pkt_data = DAP_DUP_SIZE(l_chain_pkt->data, l_chain_pkt_data_size);
                l_pkt_item->pkt_data_size = l_chain_pkt_data_size;
                dap_proc_queue_add_callback_inter(a_ch->stream_worker->worker->proc_queue_input, s_gdb_in_pkt_proc_callback, l_sync_request);
            } else {
                log_it(L_WARNING, "Packet with GLOBAL_DB atom has zero body size");
                s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_GLOBAL_DB_PACKET_EMPTY");
            }
        }  break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB: {
                log_it(L_INFO, "In:  SYNCED_GLOBAL_DB: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                                l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
                if (!l_ch_chain->callback_notify_packet_in) { // we haven't node client waitng, so reply to other side
                    dap_stream_ch_chain_sync_request_t l_sync_gdb = {};
                    dap_chain_net_t *l_net = dap_chain_net_by_id(l_chain_pkt->hdr.net_id);
                    l_sync_gdb.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
                    dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_REQ, l_chain_pkt->hdr.net_id.uint64,
                                                  l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, &l_sync_gdb, sizeof(l_sync_gdb));
                }
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB_RVRS: {
            dap_stream_ch_chain_sync_request_t l_sync_gdb = {};
            l_sync_gdb.id_start = 1;
            dap_chain_net_t *l_net = dap_chain_net_by_id(l_chain_pkt->hdr.net_id);
            l_sync_gdb.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
            log_it(L_INFO, "In:  SYNC_GLOBAL_DB_RVRS pkt: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x
                           ", request gdb sync from %"DAP_UINT64_FORMAT_U, l_chain_pkt->hdr.net_id.uint64 , l_chain_pkt->hdr.chain_id.uint64,
                           l_chain_pkt->hdr.cell_id.uint64, l_sync_gdb.id_start );
            dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB, l_chain_pkt->hdr.net_id.uint64,
                                          l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, &l_sync_gdb, sizeof(l_sync_gdb));
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB_GROUP: {
            if (s_debug_more)
                log_it(L_INFO, "In:  SYNCED_GLOBAL_DB_GROUP pkt net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                                l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
        } break;
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB_GROUP: {
            if (s_debug_more)
                log_it(L_INFO, "In:  FIRST_GLOBAL_DB_GROUP pkt net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                                l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
        } break;

        /// --- Chains update ---
        // Request for atoms list update
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_REQ:{
            if (l_ch_chain->state != CHAIN_STATE_IDLE) {
                log_it(L_WARNING, "Can't process UPDATE_CHAINS_REQ request because its already busy with syncronization");
                dap_stream_ch_chain_pkt_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS");
                break;
            }
            if(s_debug_more)
                log_it(L_INFO, "In: UPDATE_CHAINS_REQ pkt: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                                l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if (l_chain) {
                l_ch_chain->state = CHAIN_STATE_UPDATE_CHAINS;
                if(s_debug_more)
                    log_it(L_INFO, "Out: UPDATE_CHAINS_START pkt: net %s chain %s cell 0x%016"DAP_UINT64_FORMAT_X, l_chain->name,
                                        l_chain->net_name, l_chain_pkt->hdr.cell_id.uint64);
                l_ch_chain->request_atom_iter = l_chain->callback_atom_iter_create(l_chain, l_chain_pkt->hdr.cell_id, 1);
                l_chain->callback_atom_iter_get_first(l_ch_chain->request_atom_iter, NULL);
                l_ch_chain->request_hdr = l_chain_pkt->hdr;
                dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_START,
                                                     l_chain_pkt->hdr.net_id.uint64,l_chain_pkt->hdr.chain_id.uint64,
                                                     l_chain_pkt->hdr.cell_id.uint64, NULL, 0);
            }
        } break;
        // Response with metadata organized in TSD
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_TSD :{
            if (s_debug_more)
                log_it(L_DEBUG, "Chain TSD packet detected");
        } break;

        // If requested - begin to send atom hashes
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_START:{
            if (l_ch_chain->state != CHAIN_STATE_IDLE) {
                log_it(L_WARNING, "Can't process UPDATE_CHAINS_START request because its already busy with syncronization");
                dap_stream_ch_chain_pkt_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS");
                break;
            }
            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if (!l_chain) {
                log_it(L_ERROR, "Invalid UPDATE_CHAINS_START request from %s with ext_id %016"DAP_UINT64_FORMAT_x" net id 0x%016"DAP_UINT64_FORMAT_x
                                " chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet",
                                a_ch->stream->esocket->hostaddr, l_chain_pkt->hdr.ext_id,
                                l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                                l_chain_pkt->hdr.cell_id.uint64);
                s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                                    "ERROR_NET_INVALID_ID");
                // Who are you? I don't know you! go away!
                a_ch->stream->esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
                break;
            }
            l_ch_chain->state = CHAIN_STATE_UPDATE_CHAINS_REMOTE;
            l_ch_chain->request_hdr = l_chain_pkt->hdr;
            if(s_debug_more)
                log_it(L_INFO,"In: UPDATE_CHAINS_START pkt");
        } break;

        // Response with atom hashes and sizes
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS :{
            unsigned int l_count_added=0;
            unsigned int l_count_total=0;

            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if (! l_chain){
                log_it(L_ERROR, "Invalid UPDATE_CHAINS packet from %s with ext_id %016"DAP_UINT64_FORMAT_x" net id 0x%016"DAP_UINT64_FORMAT_x
                                " chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet",
                                a_ch->stream->esocket->remote_addr_str, l_chain_pkt->hdr.ext_id,
                                l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                                l_chain_pkt->hdr.cell_id.uint64);
                s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                                    "ERROR_NET_INVALID_ID");
                // Who are you? I don't know you! go away!
                a_ch->stream->esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
                break;
            }
            for ( dap_stream_ch_chain_update_element_t * l_element =(dap_stream_ch_chain_update_element_t *) l_chain_pkt->data;
                   (size_t) (((byte_t*)l_element) - l_chain_pkt->data ) < l_chain_pkt_data_size;
                  l_element++){
                dap_stream_ch_chain_hash_item_t * l_hash_item = NULL;
                unsigned l_hash_item_hashv;
                HASH_VALUE(&l_element->hash, sizeof(dap_hash_fast_t), l_hash_item_hashv);
                HASH_FIND_BYHASHVALUE(hh, l_ch_chain->remote_atoms, &l_element->hash, sizeof(dap_hash_fast_t),
                                      l_hash_item_hashv, l_hash_item);
                if( ! l_hash_item ){
                    l_hash_item = DAP_NEW_Z(dap_stream_ch_chain_hash_item_t);
                    if (!l_hash_item) {
                        log_it(L_CRITICAL, "Memory allocation error");
                        return;
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

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_END:
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS: {
            if(l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t)) {
                if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS && l_ch_chain->state != CHAIN_STATE_IDLE) {
                    log_it(L_WARNING, "Can't process SYNC_CHAINS request because not in idle state");
                    s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                            l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                            "ERROR_STATE_NOT_IN_IDLE");
                    break;
                }
                if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_END &&
                        (l_ch_chain->state != CHAIN_STATE_UPDATE_CHAINS_REMOTE ||
                        memcmp(&l_ch_chain->request_hdr, &l_chain_pkt->hdr, sizeof(dap_stream_ch_chain_pkt_t)))) {
                    log_it(L_WARNING, "Can't process UPDATE_CHAINS_END request because its already busy with syncronization");
                    s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                            l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                            "ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS");
                    break;
                }
                dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
                if (!l_chain) {
                    log_it(L_ERROR, "Invalid UPDATE_CHAINS packet from %s with ext_id %016"DAP_UINT64_FORMAT_x" net id 0x%016"DAP_UINT64_FORMAT_x
                                    " chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet",
                                    a_ch->stream->esocket->remote_addr_str, l_chain_pkt->hdr.ext_id,
                                    l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                                    l_chain_pkt->hdr.cell_id.uint64);
                    s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                                        "ERROR_NET_INVALID_ID");
                    break;
                }
                if(s_debug_more)
                {
                    if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_END)
                        log_it(L_INFO, "In: UPDATE_CHAINS_END pkt with total count %d hashes",
                               HASH_COUNT(l_ch_chain->remote_atoms));
                    else
                        log_it(L_INFO, "In: SYNC_CHAINS pkt");
                }
                struct sync_request *l_sync_request = dap_stream_ch_chain_create_sync_request(l_chain_pkt, a_ch);
                l_ch_chain->stats_request_atoms_processed = 0;
                l_ch_chain->request_hdr = l_chain_pkt->hdr;
                if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS) {
                    char l_hash_from_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' }, l_hash_to_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
                    dap_chain_hash_fast_t l_hash_from = l_ch_chain->request.hash_from,
                            l_hash_to = l_ch_chain->request.hash_to;
                    dap_chain_hash_fast_to_str(&l_hash_from, l_hash_from_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                    dap_chain_hash_fast_to_str(&l_hash_to, l_hash_to_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                    log_it(L_INFO, "In:  SYNC_CHAINS pkt: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x
                                   " between %s and %s", l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64, l_ch_chain->request_hdr.cell_id.uint64,
                                    l_hash_from_str[0] ? l_hash_from_str : "(null)", l_hash_to_str[0] ? l_hash_to_str : "(null)");
                }
                dap_proc_queue_add_callback_inter(a_ch->stream_worker->worker->proc_queue_input, s_sync_out_chains_proc_callback, l_sync_request);
            } else {
                log_it(L_WARNING, "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS: Wrong chain packet size %zd when expected %zd",
                       l_chain_pkt_data_size, sizeof(l_ch_chain->request));
                s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_CHAIN_PKT_DATA_SIZE" );
            }
        } break;
        // first packet of data with source node address
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN: {
            if(l_chain_pkt_data_size == (size_t)sizeof(dap_chain_node_addr_t)){
                l_ch_chain->request_hdr = l_chain_pkt->hdr;
                l_ch_chain->request.node_addr = *(dap_chain_node_addr_t*)l_chain_pkt->data;
                log_it(L_INFO, "From "NODE_ADDR_FP_STR": FIRST_CHAIN data_size=%zu net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                               NODE_ADDR_FP_ARGS_S(l_ch_chain->request.node_addr),
                               l_chain_pkt_data_size, l_ch_chain->request_hdr.net_id.uint64 ,
                               l_ch_chain->request_hdr.chain_id.uint64, l_ch_chain->request_hdr.cell_id.uint64);
            }else{
                log_it(L_WARNING,"Incorrect data size %zd in packet DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN", l_chain_pkt_data_size);
                s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_CHAIN_PACKET_TYPE_FIRST_CHAIN_INCORRET_DATA_SIZE");
            }
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN: {
            if(l_chain_pkt_data_size) {
                dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
                if(l_chain) {
                    // Expect atom element in
                    if(l_chain_pkt_data_size > 0) {
                        struct sync_request *l_sync_request = dap_stream_ch_chain_create_sync_request(l_chain_pkt, a_ch);
                        dap_chain_pkt_item_t *l_pkt_item = &l_sync_request->pkt;
                        l_pkt_item->pkt_data = DAP_DUP_SIZE(l_chain_pkt->data, l_chain_pkt_data_size);
                        if (!l_pkt_item->pkt_data) {
                            log_it(L_ERROR, "Not enough memory!");
                            DAP_DELETE(l_sync_request);
                            break;
                        }
                        l_pkt_item->pkt_data_size = l_chain_pkt_data_size;
                        if (s_debug_more){
                            dap_chain_hash_fast_t l_atom_hash={0};
                            dap_hash_fast(l_chain_pkt->data, l_chain_pkt_data_size ,&l_atom_hash);
                            char l_atom_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
                            dap_chain_hash_fast_to_str(&l_atom_hash, l_atom_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                            log_it(L_INFO, "In: CHAIN pkt: atom hash %s (size %zd)", l_atom_hash_str, l_chain_pkt_data_size);
                        }
                        if (dap_proc_queue_add_callback_inter(a_ch->stream_worker->worker->proc_queue_input, s_sync_in_chains_callback, l_sync_request))
                            log_it(L_ERROR, "System queue overflow with atom trying atom add. All following atoms will be rejected!");
                    } else {
                        log_it(L_WARNING, "Empty chain packet");
                        s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                "ERROR_CHAIN_PACKET_EMPTY");
                    }
                }
            }
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS: {
            if (dap_log_level_get() <= L_INFO) {
                dap_chain_hash_fast_t l_hash_from = l_ch_chain->request.hash_from,
                        l_hash_to = l_ch_chain->request.hash_to;
                char l_hash_from_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' }, l_hash_to_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
                dap_chain_hash_fast_to_str(&l_hash_from, l_hash_from_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                dap_chain_hash_fast_to_str(&l_hash_to, l_hash_to_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                log_it(L_INFO, "In:  SYNCED_CHAINS: between %s and %s",l_hash_from_str[0] ? l_hash_from_str : "(null)",
                       l_hash_to_str[0] ? l_hash_to_str: "(null)");

            }
            s_ch_chain_get_idle(l_ch_chain);
            if (l_ch_chain->activity_timer) {
                dap_timerfd_delete_unsafe(l_ch_chain->activity_timer);
                l_ch_chain->activity_timer = NULL;
            }
            if (!l_ch_chain->callback_notify_packet_in) { // we haven't node client waitng, so reply to other side
                dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
                if (!l_chain) {
                    log_it(L_ERROR, "Invalid SYNCED_CHAINS packet from %s with ext_id %016"DAP_UINT64_FORMAT_x" net id 0x%016"DAP_UINT64_FORMAT_x
                                    " chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet",
                                    a_ch->stream->esocket->remote_addr_str, l_chain_pkt->hdr.ext_id,
                                    l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                                    l_chain_pkt->hdr.cell_id.uint64);
                    s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                                        "ERROR_NET_INVALID_ID");
                    break;
                }
                if (s_debug_more) {
                    log_it(L_INFO, "Out: UPDATE_CHAINS_REQ pkt");
                }
                dap_stream_ch_chain_sync_request_t l_request= {};
                dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_REQ, l_chain_pkt->hdr.net_id.uint64,
                                              l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, &l_request, sizeof(l_request));
            }
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS_RVRS: {
            if(l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t)) {
                dap_stream_ch_chain_sync_request_t l_request = { };
                dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
                if (l_chain) {
                    dap_chain_hash_fast_t l_hash;
                    dap_chain_get_atom_last_hash(l_chain, &l_hash, l_chain_pkt->hdr.cell_id); // Move away from i/o reactor to callback processor
                    l_request.hash_from = l_hash;
                    if( dap_log_level_get()<= L_INFO){
                        char l_hash_from_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = {'\0'};
                        dap_chain_hash_fast_to_str(&l_hash, l_hash_from_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                        log_it(L_INFO, "In:  SYNC_CHAINS_RVRS pkt: net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x
                                       "request chains sync from %s", l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                        l_hash_from_str[0] ? l_hash_from_str : "(null)");
                    }
                    dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS, l_chain_pkt->hdr.net_id.uint64,
                                                  l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, &l_request, sizeof(l_request));
                }
            }else{
                log_it(L_WARNING, "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS_RVRS: Wrong chain packet size %zd when expected %zd", l_chain_pkt_data_size, sizeof(l_ch_chain->request));
                s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_CHAIN_PKT_DATA_SIZE" );
            }
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR:{
            char * l_error_str = (char*)l_chain_pkt->data;
            if(l_chain_pkt_data_size>1)
                l_error_str[l_chain_pkt_data_size-1]='\0'; // To be sure that nobody sends us garbage
                                                           // without trailing zero
            log_it(L_WARNING,"In from remote addr %s chain id 0x%016"DAP_UINT64_FORMAT_x" got error on his side: '%s'",
                   DAP_STREAM_CH(l_ch_chain)->stream->esocket->hostaddr,
                   l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt_data_size ? l_error_str : "<empty>");
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL: {
            log_it(L_INFO, "In from "NODE_ADDR_FP_STR":  SYNCED_ALL net 0x%016"DAP_UINT64_FORMAT_x" chain 0x%016"DAP_UINT64_FORMAT_x" cell 0x%016"DAP_UINT64_FORMAT_x,
                            NODE_ADDR_FP_ARGS_S(l_ch_chain->request.node_addr), l_chain_pkt->hdr.net_id.uint64,
                            l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
        } break;

        default: {
            s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                                l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                                "ERROR_UNKNOWN_CHAIN_PKT_TYPE");
            }
    }
    if(l_ch_chain->callback_notify_packet_in)
        l_ch_chain->callback_notify_packet_in(l_ch_chain, l_ch_pkt->hdr.type, l_chain_pkt,
                                              l_chain_pkt_data_size, l_ch_chain->callback_notify_arg);
}


/**
 * @brief s_ch_chain_go_idle_and_free_log_list
 * @param a_ch_chain
 */
static void s_free_log_list_gdb ( dap_stream_ch_chain_t * a_ch_chain)
{
    if (a_ch_chain->request_db_log) {
        // free log list
        debug_if(s_debug_more, L_INFO, "[stm_ch_chain:%p] a_ch_chain->request_db_log:%p --- cleanuping ...", a_ch_chain, a_ch_chain->request_db_log);
        dap_db_log_list_delete(a_ch_chain->request_db_log);
        a_ch_chain->request_db_log = NULL;
    }

    if (a_ch_chain->remote_gdbs) {
        dap_stream_ch_chain_hash_item_t *l_hash_item = NULL, *l_tmp = NULL;
        HASH_ITER(hh, a_ch_chain->remote_gdbs, l_hash_item, l_tmp) {
            // Clang bug at this, l_hash_item should change at every loop cycle
            HASH_DEL(a_ch_chain->remote_gdbs, l_hash_item);
            DAP_DELETE(l_hash_item);
        }
        a_ch_chain->remote_gdbs = NULL;
    }
}

/**
 * @brief s_ch_chain_go_idle
 * @param a_ch_chain
 */
static void s_ch_chain_go_idle(dap_stream_ch_chain_t *a_ch_chain)
{
    if (a_ch_chain->state == CHAIN_STATE_IDLE) {
        return;
    }
    a_ch_chain->state = CHAIN_STATE_IDLE;

    if(s_debug_more)
        log_it(L_INFO, "Go in CHAIN_STATE_IDLE");

    // Cleanup after request
    memset(&a_ch_chain->request, 0, sizeof(a_ch_chain->request));
    memset(&a_ch_chain->request_hdr, 0, sizeof(a_ch_chain->request_hdr));
    if (a_ch_chain->request_atom_iter && a_ch_chain->request_atom_iter->chain &&
            a_ch_chain->request_atom_iter->chain->callback_atom_iter_delete) {
        a_ch_chain->request_atom_iter->chain->callback_atom_iter_delete(a_ch_chain->request_atom_iter);
        a_ch_chain->request_atom_iter = NULL;
    }

    dap_stream_ch_chain_hash_item_t *l_hash_item = NULL, *l_tmp = NULL;

    HASH_ITER(hh, a_ch_chain->remote_atoms, l_hash_item, l_tmp) {
        // Clang bug at this, l_hash_item should change at every loop cycle
        HASH_DEL(a_ch_chain->remote_atoms, l_hash_item);
        DAP_DELETE(l_hash_item);
    }
    a_ch_chain->remote_atoms = NULL;
    a_ch_chain->sent_breaks = 0;
    s_free_log_list_gdb(a_ch_chain);
}

struct chain_io_complete {
    dap_stream_ch_uuid_t ch_uuid;
    dap_stream_ch_chain_state_t state;
    uint8_t type;
    uint64_t net_id;
    uint64_t chain_id;
    uint64_t cell_id;
    size_t data_size;
    byte_t data[];
};

static void s_stream_ch_io_complete(dap_events_socket_t *a_es, void *a_arg, int a_errno)
{
    if (a_errno)
        return;
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
        if (l_stream->channel[i]->proc->id == DAP_STREAM_CH_ID)
            l_ch = l_stream->channel[i];
    if (!l_ch)
        return;
    if (a_arg) {
        struct chain_io_complete *l_arg = (struct chain_io_complete *)a_arg;
        if (DAP_STREAM_CH_CHAIN(l_ch)->state == CHAIN_STATE_WAITING)
            DAP_STREAM_CH_CHAIN(l_ch)->state = l_arg->state;
        dap_stream_ch_chain_pkt_write_unsafe(l_ch, l_arg->type, l_arg->net_id, l_arg->chain_id,
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
                                sizeof(dap_stream_ch_chain_pkt_t) - sizeof(dap_stream_ch_pkt_t) -
                                sizeof(dap_stream_pkt_t) - DAP_STREAM_PKT_ENCRYPTION_OVERHEAD;
    if (l_free_buf_size < a_data_size) {
        struct chain_io_complete *l_arg = DAP_NEW_Z_SIZE(struct chain_io_complete, sizeof(struct chain_io_complete) + a_data_size);
        l_arg->ch_uuid = a_ch->uuid;
        l_arg->state = DAP_STREAM_CH_CHAIN(a_ch)->state;
        DAP_STREAM_CH_CHAIN(a_ch)->state = CHAIN_STATE_WAITING;
        l_arg->type = a_type;
        l_arg->net_id = a_net_id;
        l_arg->chain_id = a_chain_id;
        l_arg->cell_id = a_cell_id;
        l_arg->data_size = a_data_size;
        memcpy(l_arg->data, a_data, a_data_size);
        a_ch->stream->esocket->callbacks.arg = l_arg;
    }
    else
       dap_stream_ch_chain_pkt_write_unsafe(a_ch, a_type, a_net_id, a_chain_id, a_cell_id, a_data, a_data_size);
}

/**
 * @brief s_stream_ch_packet_out
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t *a_ch, void *a_arg)
{
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    bool l_go_idle = false, l_was_sent_smth = false;
    switch (l_ch_chain->state) {
        // Update list of global DB records to remote
        case CHAIN_STATE_UPDATE_GLOBAL_DB: {
            dap_stream_ch_chain_update_element_t l_data[s_update_pack_size];
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
                s_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB,
                                            l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                            l_ch_chain->request_hdr.cell_id.uint64,
                                            l_data, i * sizeof(dap_stream_ch_chain_update_element_t));
                l_ch_chain->stats_request_gdb_processed += i;
                if (s_debug_more)
                    log_it(L_INFO, "Out: DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB");
            } else if (!l_obj) {
                l_was_sent_smth = true;
                l_ch_chain->request.node_addr.uint64 = dap_chain_net_get_cur_addr_int(dap_chain_net_by_id(
                                                                                          l_ch_chain->request_hdr.net_id));
                s_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_END,
                                                     l_ch_chain->request_hdr.net_id.uint64,
                                                     l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64,
                                                     &l_ch_chain->request, sizeof(dap_stream_ch_chain_sync_request_t));
                if (s_debug_more )
                    log_it(L_INFO, "Out: DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_END");
                l_go_idle = true;
            }
        } break;

        // Synchronize GDB
        case CHAIN_STATE_SYNC_GLOBAL_DB: {
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
                dap_stream_ch_chain_hash_item_t *l_hash_item = NULL;
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
                    l_hash_item = DAP_NEW_Z(dap_stream_ch_chain_hash_item_t);
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
                s_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB,
                                                     l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64, l_pkt, l_pkt_size);
                DAP_DELETE(l_pkt);
            } else if (!l_obj) {
                l_was_sent_smth = true;
                log_it( L_INFO,"Syncronized database: items syncronyzed %"DAP_UINT64_FORMAT_U" from %zu",
                        l_ch_chain->stats_request_gdb_processed, dap_db_log_list_get_count(l_ch_chain->request_db_log));
                // last message
                dap_stream_ch_chain_sync_request_t l_request = {};
                s_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                     l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64, &l_request, sizeof(l_request));
                l_go_idle = true;
                if (l_ch_chain->callback_notify_packet_out)
                    l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                           NULL, 0, l_ch_chain->callback_notify_arg);
            }
        } break;

        // Update list of atoms to remote
        case CHAIN_STATE_UPDATE_CHAINS:{
            dap_stream_ch_chain_update_element_t *l_data = DAP_NEW_Z_SIZE(dap_stream_ch_chain_update_element_t,
                                                                          sizeof(dap_stream_ch_chain_update_element_t) * s_update_pack_size);
            size_t l_data_size=0;
            for(uint_fast16_t n=0; n<s_update_pack_size && (l_ch_chain->request_atom_iter && l_ch_chain->request_atom_iter->cur);n++){
                l_data[n].hash = *l_ch_chain->request_atom_iter->cur_hash;
                // Shift offset counter
                l_data_size += sizeof(dap_stream_ch_chain_update_element_t);
                // Then get next atom
                l_ch_chain->request_atom_iter->chain->callback_atom_iter_get_next(l_ch_chain->request_atom_iter, NULL);
            }
            if (l_data_size){
                l_was_sent_smth = true;
                if(s_debug_more)
                    log_it(L_DEBUG,"Out: UPDATE_CHAINS with %zu hashes sent", l_data_size / sizeof(dap_stream_ch_chain_update_element_t));
                s_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS,
                                                     l_ch_chain->request_hdr.net_id.uint64,
                                                     l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64,
                                                     l_data,l_data_size);
            }
            if(!l_data_size  ||  !l_ch_chain->request_atom_iter){ // We over with all the hashes here
                l_was_sent_smth = true;
                if(s_debug_more)
                    log_it(L_INFO,"Out: UPDATE_CHAINS_END sent ");
                dap_stream_ch_chain_sync_request_t l_request = {};
                s_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_END,
                                                     l_ch_chain->request_hdr.net_id.uint64,
                                                     l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64,
                                                     &l_request, sizeof(dap_stream_ch_chain_sync_request_t));
                l_go_idle = true;
                dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
            }
            DAP_DELETE(l_data);
        }break;

        // Synchronize chains
        case CHAIN_STATE_SYNC_CHAINS: {
            // Process one chain from l_ch_chain->request_atom_iter
            // Pack loop to skip quicker
            for(uint_fast16_t k=0; k<s_skip_in_reactor_count     &&
                                   l_ch_chain->request_atom_iter &&
                                   l_ch_chain->request_atom_iter->cur; k++){
                // Check if present and skip if present
                dap_stream_ch_chain_hash_item_t *l_hash_item = NULL;
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
                    l_hash_item = DAP_NEW_Z(dap_stream_ch_chain_hash_item_t);
                    if (!l_hash_item) {
                        log_it(L_CRITICAL, "Memory allocation error");
                        return;
                    }
                    l_hash_item->hash = *l_ch_chain->request_atom_iter->cur_hash;
                    if(s_debug_more){
                        char l_atom_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                        dap_chain_hash_fast_to_str(&l_hash_item->hash, l_atom_hash_str, sizeof(l_atom_hash_str));
                        log_it(L_INFO, "Out CHAIN pkt: atom hash %s (size %zd) ", l_atom_hash_str, l_ch_chain->request_atom_iter->cur_size);
                    }
                    s_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN, l_ch_chain->request_hdr.net_id.uint64,
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
                l_ch_chain->request_atom_iter->chain->callback_atom_iter_get_next(l_ch_chain->request_atom_iter, NULL);
                if (l_was_sent_smth)
                    break;
            }
            if(!l_ch_chain->request_atom_iter || !l_ch_chain->request_atom_iter->cur)  { // All chains synced
                dap_stream_ch_chain_sync_request_t l_request = {};
                // last message
                l_was_sent_smth = true;
                s_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS,
                                                     l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64, &l_request, sizeof(l_request));
                log_it( L_INFO,"Synced: %"DAP_UINT64_FORMAT_U" atoms processed", l_ch_chain->stats_request_atoms_processed);
                l_go_idle = true;
                if (l_ch_chain->callback_notify_packet_out)
                    l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS, NULL,
                                                           0, l_ch_chain->callback_notify_arg);
            }
        } break;
        default: break;
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
    }
}
