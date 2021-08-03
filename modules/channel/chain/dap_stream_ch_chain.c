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
#include <time.h>
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
#include "utlist.h"

#include "dap_worker.h"
#include "dap_events.h"
#include "dap_proc_thread.h"

#include "dap_chain.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"
#include "dap_chain_cell.h"

#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"

#include "dap_stream.h"
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

    dap_stream_ch_chain_update_element_t *local_gdbs;
    uint64_t local_gdbs_count;
    dap_stream_ch_chain_hash_item_t *remote_atoms; // Remote atoms
    dap_stream_ch_chain_hash_item_t *remote_gdbs; // Remote gdbs

    uint64_t stats_request_elemets_processed;
    union{
        struct{
            dap_db_log_list_t *db_log; //  db log
            dap_list_t *db_iter;
        } gdb;
        struct{
            dap_chain_atom_iter_t *request_atom_iter;
        } chain;
    };
};

static void s_stream_ch_new(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_write_error_unsafe(dap_stream_ch_t *a_ch, uint64_t a_net_id, uint64_t a_chain_id, uint64_t a_cell_id, const char * a_err_string);

static bool s_sync_out_chains_proc_callback(dap_proc_thread_t *a_thread, void *a_arg);
static void s_sync_out_chains_last_worker_callback(dap_worker_t *a_worker, void *a_arg);
static void s_sync_out_chains_first_worker_callback(dap_worker_t *a_worker, void *a_arg);

static bool s_sync_out_gdb_proc_callback(dap_proc_thread_t *a_thread, void *a_arg);
static void s_sync_out_gdb_synced_data_worker_callback(dap_worker_t *a_worker, void *a_arg);

static bool s_sync_in_chains_callback(dap_proc_thread_t *a_thread, void *a_arg);

static bool s_gdb_in_pkt_proc_callback(dap_proc_thread_t *a_thread, void *a_arg);
static void s_gdb_in_pkt_error_worker_callback(dap_worker_t *a_thread, void *a_arg);

static bool s_debug_more=false;
static uint_fast16_t s_update_pack_size=100; // Number of hashes packed into the one packet
static uint_fast16_t s_skip_in_reactor_count=50; // Number of hashes packed to skip in one reactor loop callback out packet
/**
 * @brief dap_stream_ch_chain_init
 * @return
 */
int dap_stream_ch_chain_init()
{
    log_it(L_NOTICE, "Chains and global db exchange channel initialized");
    dap_stream_ch_proc_add(dap_stream_ch_chain_get_id(), s_stream_ch_new, s_stream_ch_delete, s_stream_ch_packet_in,
            s_stream_ch_packet_out);
    s_debug_more = dap_config_get_item_bool_default(g_config,"stream_ch_chain","debug_more",false);
    s_update_pack_size = dap_config_get_item_int16_default(g_config,"stream_ch_chain","update_pack_size",100);

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
    l_ch_chain->ch = a_ch;
}

/**
 * @brief s_stream_ch_chain_delete
 * @param a_ch_chain
 */
static void s_sync_request_delete(struct sync_request * a_sync_request)
{
    if (a_sync_request->pkt.pkt_data) {
        DAP_DELETE(a_sync_request->pkt.pkt_data);
    }

    if (a_sync_request->gdb.db_iter) {
        a_sync_request->gdb.db_iter = dap_list_first( a_sync_request->gdb.db_iter);
        dap_list_free_full( a_sync_request->gdb.db_iter, free);
        a_sync_request->gdb.db_iter = NULL;
    }
    DAP_DELETE(a_sync_request);
}

/**
 * @brief s_stream_ch_delete_in_proc
 * @param a_thread
 * @param a_arg
 * @return
 */
static bool s_stream_ch_delete_in_proc(dap_proc_thread_t * a_thread, void * a_arg)
{
    (void) a_thread;
    dap_stream_ch_chain_t * l_ch_chain=(dap_stream_ch_chain_t*) a_arg;
    dap_stream_ch_chain_hash_item_t * l_item = NULL, *l_tmp = NULL;

    // Clear remote atoms
    HASH_ITER(hh, l_ch_chain->remote_atoms, l_item, l_tmp){
        HASH_DEL(l_ch_chain->remote_atoms, l_item);
        DAP_DELETE(l_item);
    }
    // Clear remote gdbs
    HASH_ITER(hh, l_ch_chain->remote_gdbs, l_item, l_tmp){
        HASH_DEL(l_ch_chain->remote_gdbs, l_item);
        DAP_DELETE(l_item);
    }
    DAP_DELETE(l_ch_chain);
    return true;
}

/**
 * @brief s_stream_ch_delete
 * @param ch
 * @param arg
 */
static void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg)
{
    (void) a_arg;
    dap_proc_queue_add_callback_inter(a_ch->stream_worker->worker->proc_queue_input,s_stream_ch_delete_in_proc,a_ch->internal );
    a_ch->internal = NULL; // To prevent its cleaning in worker
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
    l_ch_chain->state = CHAIN_STATE_SYNC_CHAINS;
    l_ch_chain->request_atom_iter = l_sync_request->chain.request_atom_iter;
    l_ch_chain->remote_atoms = l_sync_request->remote_atoms; /// TODO check if they were present here before

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
    dap_stream_ch_chain_sync_request_t l_request = {0};
    if (s_debug_more )
        log_it(L_INFO,"Out: DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS");
    dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS,
            l_sync_request->request_hdr.net_id.uint64, l_sync_request->request_hdr.chain_id.uint64,
            l_sync_request->request_hdr.cell_id.uint64, &l_request, sizeof(l_request));
    if (l_ch_chain->request_atom_iter)
        DAP_DEL_Z(l_ch_chain->request_atom_iter);

    l_ch_chain->state = CHAIN_STATE_IDLE;
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

    pthread_rwlock_rdlock(&l_chain->atoms_rwlock);

    l_sync_request->chain.request_atom_iter = l_chain->callback_atom_iter_create(l_chain);
    size_t l_first_size = 0;
    dap_chain_atom_ptr_t *l_iter = l_chain->callback_atom_iter_get_first(l_sync_request->chain.request_atom_iter, &l_first_size);


    if (l_iter && l_first_size) {
        // first packet
        if (!dap_hash_fast_is_blank(&l_sync_request->request.hash_from)) {
            (void ) l_chain->callback_atom_find_by_hash(l_sync_request->chain.request_atom_iter,
                                                          &l_sync_request->request.hash_from, &l_first_size);
        }


        pthread_rwlock_unlock(&l_chain->atoms_rwlock);
        dap_proc_thread_worker_exec_callback(a_thread, l_sync_request->worker->id,s_sync_out_chains_first_worker_callback, l_sync_request );
    } else {
        pthread_rwlock_unlock(&l_chain->atoms_rwlock);
        dap_proc_thread_worker_exec_callback(a_thread, l_sync_request->worker->id,s_sync_out_chains_last_worker_callback, l_sync_request );
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
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain->request_hdr.net_id);

    // Add it to outgoing list
    l_ch_chain->request_global_db_trs = l_sync_request->gdb.db_log;
    l_ch_chain->request_db_iter = NULL;
    l_ch_chain->state = CHAIN_STATE_SYNC_GLOBAL_DB;
    dap_chain_node_addr_t l_node_addr = { 0 };
    l_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
    if (s_debug_more )
        log_it(L_INFO,"Out: DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB");
    dap_stream_ch_chain_pkt_write_unsafe(l_ch_chain->ch , DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB,
            l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
            l_ch_chain->request_hdr.cell_id.uint64, &l_node_addr, sizeof(dap_chain_node_addr_t));
    if(l_ch_chain->callback_notify_packet_out)
        l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB,
                                                NULL, 0, l_ch_chain->callback_notify_arg);

    if( a_worker){ // We send NULL to prevent delete
        s_sync_request_delete(l_sync_request);
        l_ch_chain->is_on_request = false;
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

    dap_stream_ch_chain_sync_request_t l_request = {0};
    if (s_debug_more )
        log_it(L_INFO,"Out: DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB");
    dap_stream_ch_chain_pkt_write_unsafe(l_ch_chain->ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                         l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                         l_ch_chain->request_hdr.cell_id.uint64, &l_request, sizeof(l_request));
    l_ch_chain->state = CHAIN_STATE_IDLE;
    if(l_ch_chain->callback_notify_packet_out)
        l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                NULL, 0, l_ch_chain->callback_notify_arg);
    l_ch_chain->is_on_request = false;
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
    struct sync_request *l_sync_request = (struct sync_request *) a_arg;

    // Get log diff
    uint64_t l_local_last_id = dap_db_log_get_last_id();
    if (s_debug_more)
        log_it(L_DEBUG, "Sync out gdb proc, requested transactions %llu:%llu from address "NODE_ADDR_FP_STR,
                            l_sync_request->request.id_start, l_local_last_id, NODE_ADDR_FP_ARGS_S(l_sync_request->request.node_addr));
    uint64_t l_start_item = l_sync_request->request.id_start;
    // If the current global_db has been truncated, but the remote node has not known this
    if(l_sync_request->request.id_start > l_local_last_id) {
        l_start_item = 0;
    }
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_sync_request->request_hdr.net_id);
    dap_list_t *l_add_groups = dap_chain_net_get_add_gdb_group(l_net, l_sync_request->request.node_addr);
    dap_db_log_list_t *l_db_log = dap_db_log_list_start(l_start_item + 1, l_add_groups);

    if(l_db_log) {
        l_sync_request->gdb.db_log = l_db_log;
        dap_proc_thread_worker_exec_callback(a_thread, l_sync_request->worker->id, s_sync_out_gdb_first_worker_callback,l_sync_request );
    } else {
        dap_proc_thread_worker_exec_callback(a_thread, l_sync_request->worker->id, s_sync_out_gdb_last_worker_callback,l_sync_request );
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

static void s_sync_update_gdb_proc_callback(dap_worker_t  *a_worker, void *a_arg)
{
    struct sync_request *l_sync_request = (struct sync_request *) a_arg;

    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(DAP_STREAM_WORKER(a_worker), l_sync_request->ch_uuid);
    if( l_ch == NULL ){
        log_it(L_INFO,"Client disconnected before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return ;
    }
    // TODO make a local_gdbs hash table
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
    l_ch_chain->local_gdbs = l_sync_request->local_gdbs;
    l_ch_chain->local_gdbs_count = l_sync_request->local_gdbs_count;
    dap_worker_exec_callback_on( l_sync_request->worker, s_sync_update_gdb_start_worker_callback, l_sync_request);
}

/**
 * @brief s_chain_in_pkt_callback
 * @param a_thread
 * @param a_arg
 * @return
 */
static bool s_sync_in_chains_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    struct sync_request *l_sync_request = (struct sync_request *) a_arg;
    dap_chain_pkt_item_t *l_pkt_item = &l_sync_request->pkt;
    dap_chain_hash_fast_t l_atom_hash = {};

    if (l_pkt_item->pkt_data_size) {
        dap_chain_t *l_chain = dap_chain_find_by_id(l_sync_request->request_hdr.net_id, l_sync_request->request_hdr.chain_id);
        if (!l_chain) {
            if (s_debug_more)
                log_it(L_WARNING, "No chain found for DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN");
            return true;
        }
        dap_chain_atom_ptr_t l_atom_copy = (dap_chain_atom_ptr_t)l_pkt_item->pkt_data;
        uint64_t l_atom_copy_size = l_pkt_item->pkt_data_size;
        if ( l_atom_copy_size && l_pkt_item && l_atom_copy ){
            pthread_rwlock_wrlock(&l_chain->atoms_rwlock);
            dap_hash_fast(l_atom_copy, l_atom_copy_size, &l_atom_hash);
            dap_chain_atom_iter_t *l_atom_iter = l_chain->callback_atom_iter_create(l_chain);
            size_t l_atom_size =0;
            if ( l_chain->callback_atom_find_by_hash(l_atom_iter, &l_atom_hash, &l_atom_size) == NULL ) {
                dap_chain_atom_verify_res_t l_atom_add_res = l_chain->callback_atom_add(l_chain, l_atom_copy, l_atom_copy_size);
                if ( l_atom_add_res != ATOM_REJECT && dap_chain_has_file_store(l_chain)) {
                    if (s_debug_more){
                        char l_atom_hash_str[72]={[0]='\0'};
                        dap_chain_hash_fast_to_str(&l_atom_hash,l_atom_hash_str,sizeof (l_atom_hash_str)-1 );
                        log_it(L_INFO,"Accepted atom with hash %s for %s:%s", l_atom_hash_str, l_chain->net_name, l_chain->name);
                    }

                    // append to file
                    dap_chain_cell_t *l_cell = dap_chain_cell_create_fill(l_chain, l_sync_request->request_hdr.cell_id);
                    int l_res;
                    if (l_cell) {
                        // add one atom only
                        l_res = dap_chain_cell_file_append(l_cell, l_atom_copy, l_atom_copy_size);
                        // rewrite all file
                        //l_res = dap_chain_cell_file_update(l_cell);
                        if(l_res < 0) {
                            log_it(L_ERROR, "Can't save event 0x%x to the file '%s'", l_atom_hash,
                                    l_cell ? l_cell->file_storage_path : "[null]");
                        } else {
                            dap_db_set_last_hash_remote(l_sync_request->request.node_addr.uint64, l_chain, &l_atom_hash);
                        }
                        // add all atoms from treshold
                        if (l_chain->callback_atom_add_from_treshold){
                            dap_chain_atom_ptr_t l_atom_treshold;
                            do{
                                size_t l_atom_treshold_size;
                                // add into ledger
                                if (s_debug_more)
                                    log_it(L_DEBUG, "Try to add atom from treshold");
                                l_atom_treshold = l_chain->callback_atom_add_from_treshold(l_chain, &l_atom_treshold_size);
                                // add into file
                                if(l_atom_treshold) {
                                    l_res = dap_chain_cell_file_append(l_cell, l_atom_treshold, l_atom_treshold_size);
                                    log_it(L_INFO, "Added atom from treshold");
                                    if(l_res < 0) {
                                        log_it(L_ERROR, "Can't save event 0x%x from treshold to the file '%s'",
                                                l_atom_treshold, l_cell ? l_cell->file_storage_path : "[null]");
                                    }
                                }
                            }
                            while(l_atom_treshold);
                        }

                        // delete cell and close file
                        dap_chain_cell_delete(l_cell);
                    }
                    else{
                        log_it(L_ERROR, "Can't get cell for cell_id 0x%x for save event to file", l_sync_request->request_hdr.cell_id);

                    }
                }else if(l_atom_add_res == ATOM_PASS){
                    if (s_debug_more){
                        char l_atom_hash_str[72]={[0]='\0'};
                        dap_chain_hash_fast_to_str(&l_atom_hash,l_atom_hash_str,sizeof (l_atom_hash_str)-1 );
                        log_it(L_WARNING,"Not accepted atom (code ATOM_PASS) with hash %s for %s:%s and moved into the treshold",  l_atom_hash_str, l_chain->net_name, l_chain->name);
                    }
                }else{
                    if (s_debug_more){
                        char l_atom_hash_str[72]={[0]='\0'};
                        dap_chain_hash_fast_to_str(&l_atom_hash,l_atom_hash_str,sizeof (l_atom_hash_str)-1 );
                        log_it(L_WARNING,"Not accepted atom (code %d) with hash %s for %s:%s", l_atom_add_res, l_atom_hash_str, l_chain->net_name, l_chain->name);
                    }
                }
                DAP_DEL_Z(l_atom_copy);
            } else {
                if (s_debug_more){
                    char l_atom_hash_str[72]={[0]='\0'};
                    dap_chain_hash_fast_to_str(&l_atom_hash,l_atom_hash_str,sizeof (l_atom_hash_str)-1 );
                    log_it(L_WARNING,"Already has atom with hash %s ", l_atom_hash_str);
                }
                dap_db_set_last_hash_remote(l_sync_request->request.node_addr.uint64, l_chain, &l_atom_hash);
                DAP_DELETE(l_atom_copy);
            }
            l_chain->callback_atom_iter_delete(l_atom_iter);
            pthread_rwlock_unlock(&l_chain->atoms_rwlock);
        }else{
            if (!l_pkt_item)
                log_it(L_WARNING, "chain packet item is NULL");
            if (l_atom_copy_size)
                log_it(L_WARNING, "chain packet item data size is zero");
        }
    }else
        log_it(L_WARNING, "In proc thread got CHAINS stream ch packet with zero data");
    DAP_DELETE(l_sync_request);
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
    if( l_ch == NULL ){
        log_it(L_INFO,"Client disconnected before we sent the reply");
        s_sync_request_delete(l_sync_request);
        return;
    }

    dap_stream_ch_chain_pkt_write_error_unsafe(l_ch, l_sync_request->request_hdr.net_id.uint64,
                                               l_sync_request->request_hdr.chain_id.uint64,
                                               l_sync_request->request_hdr.cell_id.uint64,
                                               "ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED");
    DAP_DELETE(l_sync_request);
}


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

    if (l_pkt_item->pkt_data_size) {
        size_t l_data_obj_count = 0;
        // deserialize data & Parse data from dap_db_log_pack()
        dap_store_obj_t *l_store_obj = dap_db_log_unpack(l_pkt_item->pkt_data, l_pkt_item->pkt_data_size, &l_data_obj_count);
        if (s_debug_more){
            if (l_data_obj_count)
                log_it(L_INFO, "In: GLOBAL_DB parse: pkt_data_size=%zd, l_data_obj_count = %d",l_pkt_item->pkt_data_size, l_data_obj_count );
            else if (l_pkt_item->pkt_data){
                log_it(L_WARNING, "In: GLOBAL_DB parse: pkt_data_size=%zd, error=\"No data objs after unpack\"", l_pkt_item->pkt_data_size, l_data_obj_count );
            }else
                 log_it(L_WARNING, "In: GLOBAL_DB parse: packet in list with NULL data(pkt_data_size:%zd)", l_pkt_item->pkt_data_size);
        }

        for(size_t i = 0; i < l_data_obj_count; i++) {
            // timestamp for exist obj
            time_t l_timestamp_cur = 0;
            // obj to add
            dap_store_obj_t* l_obj = l_store_obj + i;
            // read item from base;
            size_t l_count_read = 0;
            dap_store_obj_t *l_read_obj = dap_chain_global_db_driver_read(l_obj->group,
                    l_obj->key, &l_count_read);
            // get timestamp for the exist entry
            if(l_read_obj)
                l_timestamp_cur = l_read_obj->timestamp;
            // get timestamp for the deleted entry
            else
            {
                l_timestamp_cur = global_db_gr_del_get_timestamp(l_obj->group, l_obj->key);
            }

            //check whether to apply the received data into the database
            bool l_apply = true;
            if(l_obj->timestamp < l_timestamp_cur)
                l_apply = false;
            else if(l_obj->type == 'd') {
                // already deleted
                if(!l_read_obj)
                    l_apply = false;
            }
            else if(l_obj->type == 'a') {
                bool l_is_the_same_present = false;
                if(l_read_obj &&
                        l_read_obj->value_len == l_obj->value_len &&
                        !memcmp(l_read_obj->value, l_obj->value, l_obj->value_len))
                    l_is_the_same_present = true;
                // this data already present in global_db and not obsolete (out of date)
                if(l_read_obj && (l_is_the_same_present || l_read_obj->timestamp >= l_store_obj->timestamp))
                    l_apply = false;
            }
            if(l_read_obj)
                dap_store_obj_free(l_read_obj, l_count_read);

            if (s_debug_more){
                char l_ts_str[50];
                dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), l_store_obj[i].timestamp);
                log_it(L_DEBUG, "Unpacked log history: type='%c' (0x%02hhX) group=\"%s\" key=\"%s\""
                        " timestamp=\"%s\" value_len=%u  ",
                        (char ) l_store_obj[i].type, l_store_obj[i].type, l_store_obj[i].group,
                        l_store_obj[i].key, l_ts_str, l_store_obj[i].value_len);
            }

            if(!l_apply) {
                // If request was from defined node_addr we update its state
                if(l_sync_request->request.node_addr.uint64) {
                    dap_db_set_last_id_remote(l_sync_request->request.node_addr.uint64, l_obj->id);
                }
                continue;
            }

            // apply received transaction
            dap_chain_t *l_chain = dap_chain_find_by_id(l_sync_request->request_hdr.net_id, l_sync_request->request_hdr.chain_id);
            if(l_chain) {
                if(l_chain->callback_add_datums_with_group){
                    void * restrict l_store_obj_value = l_store_obj->value;
                    l_chain->callback_add_datums_with_group(l_chain,
                            (dap_chain_datum_t** restrict) l_store_obj_value, 1,
                            l_store_obj[i].group);
                }
            }
            // save data to global_db
            if(!dap_chain_global_db_obj_save(l_obj, 1)) {
                if(l_store_obj)
                    dap_store_obj_free(l_store_obj, l_data_obj_count);
                dap_proc_thread_worker_exec_callback(a_thread, l_sync_request->worker->id, s_gdb_in_pkt_error_worker_callback, l_sync_request);
                return true;
            } else {
                // If request was from defined node_addr we update its state
                if(l_sync_request->request.node_addr.uint64) {
                    dap_db_set_last_id_remote(l_sync_request->request.node_addr.uint64, l_obj->id);
                }
                if (s_debug_more)
                    log_it(L_DEBUG, "Added new GLOBAL_DB history pack");
            }
        }
        if(l_store_obj)
            dap_store_obj_free(l_store_obj, l_data_obj_count);
    } else {
        log_it(L_WARNING, "In proc thread got GDB stream ch packet with zero data");
    }
    DAP_DELETE(l_sync_request);
    return true;
}

/**
 * @brief dap_stream_ch_chain_create_sync_request_gdb
 * @param a_ch_chain
 * @param a_net
 */
struct sync_request *dap_stream_ch_chain_create_sync_request(dap_stream_ch_chain_pkt_t *a_chain_pkt, dap_stream_ch_t* a_ch)
{
    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    memcpy(&l_ch_chain->request, a_chain_pkt->data, sizeof(l_ch_chain->request));
    memcpy(&l_ch_chain->request_hdr, &a_chain_pkt->hdr, sizeof(l_ch_chain->request_hdr));
    struct sync_request *l_sync_request = DAP_NEW_Z(struct sync_request);
    l_sync_request->ch_uuid = a_ch->uuid;
    l_sync_request->worker = a_ch->stream_worker->worker;
    l_sync_request->remote_gdbs = l_ch_chain->remote_gdbs;
    l_sync_request->remote_atoms = l_ch_chain->remote_atoms;
    memcpy(&l_sync_request->request, &l_ch_chain->request, sizeof(l_ch_chain->request));
    memcpy(&l_sync_request->request_hdr, &l_ch_chain->request_hdr, sizeof(l_ch_chain->request_hdr));
    return l_sync_request;
}

static void s_stream_ch_write_error_unsafe(dap_stream_ch_t *a_ch, uint64_t a_net_id, uint64_t a_chain_id, uint64_t a_cell_id, const char * a_err_string)
{
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    dap_stream_ch_chain_go_idle(l_ch_chain);
    dap_stream_ch_chain_pkt_write_error_unsafe(a_ch, a_net_id, a_chain_id, a_cell_id, a_err_string);
}

/**
 * @brief s_stream_ch_packet_in
 * @param a_ch
 * @param a_arg
 */
void s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg)
{
    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    if (!l_ch_chain) {
        return;
    }
    dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
    dap_stream_ch_chain_pkt_t * l_chain_pkt = (dap_stream_ch_chain_pkt_t *) l_ch_pkt->data;
    if (!l_chain_pkt) {
        return;
    }
    if (l_ch_pkt->hdr.size< sizeof (l_chain_pkt->hdr) ){
        log_it(L_ERROR, "Corrupted packet: too small size %zd, smaller then header size %zd", l_ch_pkt->hdr.size,
               sizeof(l_chain_pkt->hdr));

    }

    size_t l_chain_pkt_data_size = l_ch_pkt->hdr.size-sizeof (l_chain_pkt->hdr) ;
    uint16_t l_acl_idx = dap_chain_net_acl_idx_by_id(l_chain_pkt->hdr.net_id );
    if (l_acl_idx == (uint16_t)-1) {
        if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR) {
            if(l_ch_chain->callback_notify_packet_in) {
                l_ch_chain->callback_notify_packet_in(l_ch_chain, l_ch_pkt->hdr.type, l_chain_pkt,
                                                      l_chain_pkt_data_size, l_ch_chain->callback_notify_arg);
            }
        } else {

            log_it(L_ERROR, "Invalid request from %s with ext_id %016"DAP_UINT64_FORMAT_x" net id 0x%016"DAP_UINT64_FORMAT_x" chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet", a_ch->stream->esocket->remote_addr_str?
                       a_ch->stream->esocket->remote_addr_str: "<unknown>", l_chain_pkt->hdr.ext_id,
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
    if (a_ch->stream->session->acl && !a_ch->stream->session->acl[l_acl_idx]) {
        log_it(L_WARNING, "Unauthorized request attempt from %s to network %s", a_ch->stream->esocket->remote_addr_str?
                   a_ch->stream->esocket->remote_addr_str: "<unknown>",
               dap_chain_net_by_id(l_chain_pkt->hdr.net_id)->pub.name);
        s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                            l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                            "ERROR_NET_NOT_AUTHORIZED");
        return;
    }
    switch (l_ch_pkt->hdr.type) {
        /// --- GDB update ---
        // Request for gdbs list update
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_REQ:{
            if(l_ch_chain->state != CHAIN_STATE_IDLE){
                log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB_REQ request because its already busy with syncronization");
                s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS");
                break;
            }
            if(s_debug_more)
                log_it(L_INFO, "In:  UPDATE_GLOBAL_DB_REQ pkt: net 0x%016x chain 0x%016x cell 0x%016x", l_chain_pkt->hdr.net_id.uint64 ,
                                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
            l_ch_chain->state = CHAIN_STATE_UPDATE_GLOBAL_DB;
            struct sync_request *l_sync_request = dap_stream_ch_chain_create_sync_request(l_chain_pkt, a_ch);
            l_ch_chain->stats_request_gdb_processed = 0;
            dap_worker_exec_callback_on( a_ch->stream_worker->worker, s_sync_update_gdb_proc_callback, l_sync_request);
        }break;
        // Response with metadata organized in TSD
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_TSD:{

        }break;
        // If requested - begin to recieve record's hashes
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_START:{
            if (s_debug_more)
                log_it(L_INFO, "In:  UPDATE_GLOBAL_DB_START pkt net 0x%016x chain 0x%016x cell 0x%016x", l_chain_pkt->hdr.net_id.uint64 ,
                       l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
            if(l_ch_chain->state != CHAIN_STATE_IDLE){
                log_it(L_WARNING, "Can't process UPDATE_GLOBAL_DB_START request because its already busy with syncronization");
                s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS");
                break;
            }
            memcpy(&l_ch_chain->request_hdr, &l_chain_pkt->hdr, sizeof(dap_stream_ch_chain_pkt_t));
            l_ch_chain->state = CHAIN_STATE_UPDATE_GLOBAL_DB_REMOTE;
            dap_stream_ch_chain_hash_item_t *l_hash_item = NULL, *l_tmp = NULL;
            HASH_ITER(hh, l_ch_chain->remote_gdbs, l_hash_item, l_tmp) {
                HASH_DEL(l_ch_chain->remote_gdbs, l_hash_item);
                DAP_DELETE(l_hash_item);
            }
        }break;
        // Response with gdb element hashes and sizes
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB:{
            if(s_debug_more)
                log_it(L_INFO, "In: UPDATE_GLOBAL_DB pkt data_size=%d ", l_chain_pkt_data_size);
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
                HASH_FIND(hh,l_ch_chain->remote_gdbs, &l_element->hash, sizeof (l_element->hash), l_hash_item );
                if( ! l_hash_item ){
                    l_hash_item = DAP_NEW(dap_stream_ch_chain_hash_item_t);
                    memcpy(&l_hash_item->hash, &l_element->hash, sizeof (l_element->hash));
                    l_hash_item->size = l_element->size;
                    HASH_ADD(hh, l_ch_chain->remote_gdbs, hash, sizeof (l_hash_item->hash), l_hash_item);
                    if (s_debug_more){
                        char l_hash_str[72]={ [0]='\0'};
                        dap_chain_hash_fast_to_str(&l_hash_item->hash,l_hash_str,sizeof (l_hash_str));
                        log_it(L_INFO,"In: Updated remote hash gdb list with %s ", l_hash_str);
                    }
                }
            }
        }break;
        // End of response with starting of DB sync
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB:
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_END: {
            if(l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t)) {
                if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB && l_ch_chain->state != CHAIN_STATE_IDLE) {
                    log_it(L_WARNING, "Can't process SYNC_GLOBAL_DB request because not in idle state");
                    s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
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
                        log_it(L_INFO, "In: UPDATE_GLOBAL_DB_END pkt");
                    else
                        log_it(L_INFO, "In: SYNC_GLOBAL_DB pkt");
                }
                struct sync_request *l_sync_request = dap_stream_ch_chain_create_sync_request(l_chain_pkt, a_ch);
                l_ch_chain->state = CHAIN_STATE_SYNC_GLOBAL_DB;
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
            if(l_chain_pkt_data_size == sizeof(dap_chain_node_addr_t)){
               memcpy(&l_ch_chain->request.node_addr, l_chain_pkt->data, l_chain_pkt_data_size);
               l_ch_chain->stats_request_gdb_processed = 0;
               log_it(L_INFO, "In: FIRST_GLOBAL_DB data_size=%d net 0x%016x chain 0x%016x cell 0x%016x from address "NODE_ADDR_FP_STR,
                                                       l_chain_pkt_data_size,   l_chain_pkt->hdr.net_id.uint64 ,
                                                       l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, NODE_ADDR_FP_ARGS_S(l_ch_chain->request.node_addr) );
            }else {
               log_it(L_WARNING,"Incorrect data size %zd in packet DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB", l_chain_pkt_data_size);
               s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                       l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                       "ERROR_CHAIN_PACKET_TYPE_FIRST_GLOBAL_DB_INCORRET_DATA_SIZE");
            }
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB: {
            if(s_debug_more)
                log_it(L_INFO, "In: GLOBAL_DB data_size=%d ", l_chain_pkt_data_size);
            // get transaction and save it to global_db
            if(l_chain_pkt_data_size > 0) {
                struct sync_request *l_sync_request = dap_stream_ch_chain_create_sync_request(l_chain_pkt, a_ch);
                dap_chain_pkt_item_t *l_pkt_item = &l_sync_request->pkt;
                l_pkt_item->pkt_data = DAP_NEW_Z_SIZE(byte_t, l_chain_pkt_data_size);
                memcpy(l_pkt_item->pkt_data, l_chain_pkt->data, l_chain_pkt_data_size);
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
                log_it(L_INFO, "In:  SYNCED_GLOBAL_DB: net 0x%016x chain 0x%016x cell 0x%016x", l_chain_pkt->hdr.net_id.uint64 ,
                       l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
                if (!l_ch_chain->callback_notify_packet_in) { // we haven't node client waitng, so reply to other side
                    dap_stream_ch_chain_sync_request_t l_sync_gdb = {};
                    l_sync_gdb.id_start = dap_db_get_last_id_remote(l_sync_gdb.node_addr.uint64);
                    dap_chain_net_t *l_net = dap_chain_net_by_id(l_chain_pkt->hdr.net_id);
                    l_sync_gdb.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
                    dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_REQ, l_chain_pkt->hdr.net_id.uint64,
                                                  l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, &l_sync_gdb, sizeof(l_sync_gdb));
                }
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB_RVRS: {
            dap_stream_ch_chain_sync_request_t l_sync_gdb = {};
            l_sync_gdb.id_start = dap_db_get_last_id_remote(l_sync_gdb.node_addr.uint64);
            dap_chain_net_t *l_net = dap_chain_net_by_id(l_chain_pkt->hdr.net_id);
            l_sync_gdb.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
            log_it(L_INFO, "In:  SYNC_GLOBAL_DB_RVRS pkt: net 0x%016x chain 0x%016x cell 0x%016x, request gdb sync from %u", l_chain_pkt->hdr.net_id.uint64 ,
                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id, l_sync_gdb.id_start );
            dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB, l_chain_pkt->hdr.net_id.uint64,
                                          l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, &l_sync_gdb, sizeof(l_sync_gdb));
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB_GROUP: {
            if (s_debug_more)
                log_it(L_INFO, "In:  SYNCED_GLOBAL_DB_GROUP pkt net 0x%016x chain 0x%016x cell 0x%016x", l_chain_pkt->hdr.net_id.uint64 ,
                       l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
        } break;
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB_GROUP: {
            if (s_debug_more)
                log_it(L_INFO, "In:  SYNCED_GLOBAL_DB_GROUP pkt net 0x%016x chain 0x%016x cell 0x%016x", l_chain_pkt->hdr.net_id.uint64 ,
                       l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
        } break;

        /// --- Chains update ---
        // Request for atoms list update
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_REQ:{
            if (l_ch_chain->state != CHAIN_STATE_IDLE) {
                log_it(L_WARNING, "Can't process UPDATE_CHAINS_REQ request because its already busy with syncronization");
                s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS");
                break;
            }
            if(s_debug_more)
                log_it(L_INFO, "In: UPDATE_CHAINS_REQ pkt: net 0x%016x chain 0x%016x cell 0x%016x", l_chain_pkt->hdr.net_id.uint64 ,
                                    l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if (l_chain) {
                l_ch_chain->state = CHAIN_STATE_UPDATE_CHAINS;
                if(s_debug_more)
                    log_it(L_INFO, "Out: UPDATE_CHAINS_START pkt: net %s chain %s cell 0x%016x", l_chain->name,
                                        l_chain->net_name, l_chain_pkt->hdr.cell_id.uint64);
                l_ch_chain->request_atom_iter = l_chain->callback_atom_iter_create(l_chain);
                l_chain->callback_atom_iter_get_first(l_ch_chain->request_atom_iter, NULL);
                memcpy(&l_ch_chain->request_hdr, &l_chain_pkt->hdr, sizeof(dap_stream_ch_chain_pkt_hdr_t));
                dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_START,
                                                     l_chain_pkt->hdr.net_id.uint64,l_chain_pkt->hdr.chain_id.uint64,
                                                     l_chain_pkt->hdr.cell_id.uint64, NULL, 0);
            }
        }break;
        // Response with metadata organized in TSD
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_TSD :{

        }break;

        // If requested - begin to send atom hashes
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_START:{
            if (l_ch_chain->state != CHAIN_STATE_IDLE) {
                log_it(L_WARNING, "Can't process UPDATE_CHAINS_START request because its already busy with syncronization");
                s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                        "ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS");
                break;
            }
            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if (!l_chain) {
                log_it(L_ERROR, "Invalid UPDATE_CHAINS_START request from %s with ext_id %016"DAP_UINT64_FORMAT_x" net id 0x%016"DAP_UINT64_FORMAT_x" chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet", a_ch->stream->esocket->remote_addr_str?
                           a_ch->stream->esocket->remote_addr_str: "<unknown>", l_chain_pkt->hdr.ext_id,
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
            memcpy(&l_ch_chain->request_hdr, &l_chain_pkt->hdr, sizeof(dap_stream_ch_chain_pkt_hdr_t));
            dap_stream_ch_chain_hash_item_t *l_hash_item = NULL, *l_tmp = NULL;
            HASH_ITER(hh, l_ch_chain->remote_atoms, l_hash_item, l_tmp) {
                HASH_DEL(l_ch_chain->remote_atoms, l_hash_item);
                DAP_DELETE(l_hash_item);
            }
            if(s_debug_more)
                log_it(L_INFO,"In: UPDATE_CHAINS_START pkt");
        } break;

        // Response with atom hashes and sizes
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS :{
            uint l_count_added=0;
            uint l_count_total=0;

            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if (! l_chain){
                log_it(L_ERROR, "Invalid UPDATE_CHAINS packet from %s with ext_id %016"DAP_UINT64_FORMAT_x" net id 0x%016"DAP_UINT64_FORMAT_x" chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet", a_ch->stream->esocket->remote_addr_str?
                           a_ch->stream->esocket->remote_addr_str: "<unknown>", l_chain_pkt->hdr.ext_id,
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
                HASH_FIND(hh,l_ch_chain->remote_atoms , &l_element->hash, sizeof (l_element->hash), l_hash_item );
                if( ! l_hash_item ){
                    l_hash_item = DAP_NEW(dap_stream_ch_chain_hash_item_t);
                    memcpy(&l_hash_item->hash, &l_element->hash, sizeof (l_element->hash));
                    l_hash_item->size = l_element->size;
                    HASH_ADD(hh, l_ch_chain->remote_atoms, hash, sizeof (l_hash_item->hash), l_hash_item);
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
                    log_it(L_ERROR, "Invalid UPDATE_CHAINS packet from %s with ext_id %016"DAP_UINT64_FORMAT_x" net id 0x%016"DAP_UINT64_FORMAT_x" chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet", a_ch->stream->esocket->remote_addr_str?
                               a_ch->stream->esocket->remote_addr_str: "<unknown>", l_chain_pkt->hdr.ext_id,
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
                        log_it(L_INFO, "In: UPDATE_CHAINS_END pkt");
                    else
                        log_it(L_INFO, "In: SYNC_CHAINS pkt");
                }
                struct sync_request *l_sync_request = dap_stream_ch_chain_create_sync_request(l_chain_pkt, a_ch);
                l_ch_chain->state = CHAIN_STATE_SYNC_CHAINS;
                char *l_hash_from_str = dap_chain_hash_fast_to_str_new(&l_ch_chain->request.hash_from);
                char *l_hash_to_str = dap_chain_hash_fast_to_str_new(&l_ch_chain->request.hash_to);
                log_it(L_INFO, "In:  SYNC_CHAINS pkt: net 0x%016x chain 0x%016x cell 0x%016x between %s and %s", l_ch_chain->request_hdr.net_id.uint64 ,
                       l_ch_chain->request_hdr.chain_id.uint64, l_ch_chain->request_hdr.cell_id.uint64,
                       l_hash_from_str? l_hash_from_str: "(null)", l_hash_to_str?l_hash_to_str:"(null)");
                DAP_DELETE(l_hash_from_str);
                DAP_DELETE(l_hash_to_str);
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
            if(l_chain_pkt_data_size == sizeof(dap_chain_node_addr_t)){
                memcpy(&l_ch_chain->request_hdr, &l_chain_pkt->hdr, sizeof(dap_stream_ch_chain_pkt_hdr_t));
                memcpy(&l_ch_chain->request.node_addr, l_chain_pkt->data, sizeof(dap_chain_node_addr_t));
                log_it(L_INFO, "From "NODE_ADDR_FP_STR": FIRST_CHAIN data_size=%d net 0x%016x chain 0x%016x cell 0x%016x ",
                       NODE_ADDR_FP_ARGS_S(l_ch_chain->request.node_addr),
                       l_chain_pkt_data_size,      l_ch_chain->request_hdr.net_id.uint64 ,
                       l_ch_chain->request_hdr.chain_id.uint64, l_ch_chain->request_hdr.cell_id.uint64);
                l_ch_chain->stats_request_atoms_processed = 0;
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
                        l_pkt_item->pkt_data = DAP_NEW_Z_SIZE(byte_t, l_chain_pkt_data_size);
                        memcpy(l_pkt_item->pkt_data, l_chain_pkt->data, l_chain_pkt_data_size);
                        l_pkt_item->pkt_data_size = l_chain_pkt_data_size;
                        if (s_debug_more){
                            dap_chain_hash_fast_t l_atom_hash={0};
                            dap_hash_fast(l_chain_pkt->data, l_chain_pkt_data_size ,&l_atom_hash);
                            char *l_atom_hash_str= dap_chain_hash_fast_to_str_new(&l_atom_hash);
                            log_it(L_INFO, "In: CHAIN pkt: atom hash %s (size %zd)", l_atom_hash_str, l_chain_pkt_data_size);
                            DAP_DELETE(l_atom_hash_str);
                        }
                        dap_proc_queue_add_callback_inter(a_ch->stream_worker->worker->proc_queue_input, s_sync_in_chains_callback, l_sync_request);
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
            if (dap_log_level_get()<= L_INFO){
                char *l_hash_from_str = dap_chain_hash_fast_to_str_new(&l_ch_chain->request.hash_from);
                char *l_hash_to_str = dap_chain_hash_fast_to_str_new(&l_ch_chain->request.hash_to);
                log_it(L_INFO, "In:  SYNCED_CHAINS: between %s and %s",l_hash_from_str?l_hash_from_str:"(null)",
                       l_hash_to_str? l_hash_to_str: "(null)");
                if(l_hash_from_str)
                    DAP_DELETE(l_hash_from_str);
                if(l_hash_to_str)
                    DAP_DELETE(l_hash_to_str);
            }
            if (!l_ch_chain->callback_notify_packet_in) { // we haven't node client waitng, so reply to other side
                dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
                if (!l_chain) {
                    log_it(L_ERROR, "Invalid UPDATE_CHAINS packet from %s with ext_id %016"DAP_UINT64_FORMAT_x" net id 0x%016"DAP_UINT64_FORMAT_x" chain id 0x%016"DAP_UINT64_FORMAT_x" cell_id 0x%016"DAP_UINT64_FORMAT_x" in packet", a_ch->stream->esocket->remote_addr_str?
                               a_ch->stream->esocket->remote_addr_str: "<unknown>", l_chain_pkt->hdr.ext_id,
                           l_chain_pkt->hdr.net_id.uint64, l_chain_pkt->hdr.chain_id.uint64,
                           l_chain_pkt->hdr.cell_id.uint64);
                    s_stream_ch_write_error_unsafe(a_ch, l_chain_pkt->hdr.net_id.uint64,
                                                        l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                                                        "ERROR_NET_INVALID_ID");
                    break;
                }
                dap_stream_ch_chain_sync_request_t l_request= {};
                dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_REQ, l_chain_pkt->hdr.net_id.uint64,
                                              l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, &l_request, sizeof(l_request));
            }
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS_RVRS: {
            if(l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t)) {
                dap_stream_ch_chain_sync_request_t l_request={0};
                dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
                if( l_chain){
                    dap_chain_get_atom_last_hash(l_chain,& l_request.hash_from); // Move away from i/o reactor to callback processor
                    if( dap_log_level_get()<= L_INFO){
                        char l_hash_from_str[70]={[0]='\0'};
                        dap_chain_hash_fast_to_str(&l_request.hash_from,l_hash_from_str,sizeof (l_hash_from_str)-1);
                        log_it(L_INFO, "In:  SYNC_CHAINS_RVRS pkt: net 0x%016x chain 0x%016x cell 0x%016x request chains sync from %s",
                               l_chain_pkt->hdr.net_id.uint64 , l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                               l_hash_from_str[0] ? l_hash_from_str :"(null)");
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
            log_it(L_WARNING,"In from remote addr %s chain id 0x%016x got error on his side: '%s'",
                   l_ch_chain->ch->stream->esocket->remote_addr_str?
                                                                                    l_ch_chain->ch->stream->esocket->remote_addr_str: "<no addr>",
                   l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt_data_size>1? l_error_str:"<empty>");
        } break;

        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL: {
            log_it(L_INFO, "In from "NODE_ADDR_FP_STR":  SYNCED_ALL net 0x%016x chain 0x%016x cell 0x%016x",NODE_ADDR_FP_ARGS_S(l_ch_chain->node_client->remote_node_addr), l_chain_pkt->hdr.net_id.uint64 ,
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
 * @brief dap_stream_ch_chain_go_idle
 * @param a_ch_chain
 */
void dap_stream_ch_chain_go_idle ( dap_stream_ch_chain_t * a_ch_chain)
{
    a_ch_chain->state = CHAIN_STATE_IDLE;
    if(s_debug_more)
        log_it(L_INFO, "Go in CHAIN_STATE_IDLE");

    // Cleanup after request
    memset(&a_ch_chain->request, 0, sizeof(a_ch_chain->request));
    memset(&a_ch_chain->request_hdr, 0, sizeof(a_ch_chain->request_hdr));
    if(a_ch_chain->request_atom_iter) {
        if(a_ch_chain->request_atom_iter->chain)
            if(a_ch_chain->request_atom_iter->chain->callback_atom_iter_delete){
                a_ch_chain->request_atom_iter->chain->callback_atom_iter_delete(a_ch_chain->request_atom_iter);
                a_ch_chain->request_atom_iter = NULL;
                return;
            }
        DAP_DEL_Z(a_ch_chain->request_atom_iter);
    }
}

static void s_process_gdb_iter(dap_stream_ch_t *a_ch)
{
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    dap_db_log_list_t *l_db_list = l_ch_chain->request_global_db_trs;
    dap_store_obj_pkt_t *l_pkt = (dap_store_obj_pkt_t *)l_ch_chain->request_db_iter->data;
    uint32_t l_pkt_size = sizeof(dap_store_obj_pkt_t) + l_pkt->data_size;
    // TODO find current record hash and compare it with hash table
    if( s_debug_more)
        log_it(L_INFO, "Send one global_db record packet len=%d (rest=%d/%d items)", l_pkt_size,
           dap_db_log_list_get_count_rest(l_db_list), dap_db_log_list_get_count(l_db_list));
    dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB,
                                         l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                         l_ch_chain->request_hdr.cell_id.uint64, l_pkt, l_pkt_size);
    dap_list_t *l_iter = dap_list_next(l_ch_chain->request_db_iter);
    if (l_iter) {
        l_ch_chain->request_db_iter = l_iter;
    } else {
        l_ch_chain->stats_request_gdb_processed++;
        l_ch_chain->request_db_iter = dap_list_first(l_ch_chain->request_db_iter);
        dap_list_free_full(l_ch_chain->request_db_iter, free);
        l_ch_chain->request_db_iter = NULL;
    }
}

/**
 * @brief s_stream_ch_packet_out
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg)
{
    UNUSED(a_arg);

    if (a_ch->stream->esocket->buf_out_size >= a_ch->stream->esocket->buf_out_size_max / 2)
        return;
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);

    switch (l_ch_chain->state) {

        // Update list of global DB records to remote
        case CHAIN_STATE_UPDATE_GLOBAL_DB: {
            if (l_ch_chain->stats_request_gdb_processed == l_ch_chain->local_gdbs_count) {
                dap_stream_ch_chain_sync_request_t l_sync_gdb = {};
                l_sync_gdb.id_start = dap_db_get_last_id_remote(l_ch_chain->request.node_addr.uint64);
                dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain->request_hdr.net_id);
                l_sync_gdb.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
                dap_stream_ch_chain_pkt_write_unsafe(l_ch_chain->ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_END,
                                                     l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64, &l_sync_gdb, sizeof(dap_stream_ch_chain_sync_request_t));
                if (s_debug_more )
                    log_it(L_INFO, "Out: DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_END");
                dap_stream_ch_chain_go_idle(l_ch_chain);
            } else {
                uint_fast16_t l_count = l_ch_chain->local_gdbs_count - l_ch_chain->stats_request_gdb_processed;
                if (l_count > s_update_pack_size)
                    l_count = s_update_pack_size;
                dap_stream_ch_chain_pkt_write_unsafe(l_ch_chain->ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB,
                                                     l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64,
                                                     &l_ch_chain->local_gdbs[l_ch_chain->stats_request_gdb_processed],
                                                     l_count * sizeof(dap_stream_ch_chain_update_element_t));
                l_ch_chain->stats_request_gdb_processed += l_count;
                if (s_debug_more)
                    log_it(L_INFO, "Out: DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB");
            }
        } break;

        // Synchronize GDB
        case CHAIN_STATE_SYNC_GLOBAL_DB: {
            if (l_ch_chain->request_db_iter) {
                s_process_gdb_iter(a_ch);
            } else {
                dap_global_db_obj_t *l_obj;
                do { // Get log diff
                    size_t l_item_size_out = 0;
                    l_obj = dap_db_log_list_get(l_ch_chain->request_global_db_trs);
                    l_ch_chain->request_db_iter = dap_db_log_pack(l_obj, &l_item_size_out);
                    if (l_ch_chain->request_db_iter && l_item_size_out) {
                        break;
                    }
                    // Item not found, maybe it has deleted? Then go to the next item
                } while (l_obj);
                if (l_ch_chain->request_db_iter) {
                    s_process_gdb_iter(a_ch);
                } else {
                    // free log list
                    dap_db_log_list_delete(l_ch_chain->request_global_db_trs);
                    l_ch_chain->request_global_db_trs = NULL;
                    log_it( L_INFO,"Syncronized database:  last id %llu, items syncronyzed %llu ", dap_db_log_get_last_id(),
                        l_ch_chain->stats_request_gdb_processed );
                    // last message
                    dap_stream_ch_chain_sync_request_t l_request = {};
                    dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                         l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                                         l_ch_chain->request_hdr.cell_id.uint64, &l_request, sizeof(l_request));
                    dap_stream_ch_chain_go_idle(l_ch_chain);
                    if (l_ch_chain->callback_notify_packet_out)
                        l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                               NULL, 0, l_ch_chain->callback_notify_arg);
                }
            }
        } break;

        // Update list of atoms to remote
        case CHAIN_STATE_UPDATE_CHAINS:{
            dap_stream_ch_chain_update_element_t *l_data = DAP_NEW_Z_SIZE(dap_stream_ch_chain_update_element_t,
                                                                          sizeof(dap_stream_ch_chain_update_element_t) * s_update_pack_size);
            size_t l_data_size=0;
            for(uint_fast16_t n=0; n<s_update_pack_size && (l_ch_chain->request_atom_iter && l_ch_chain->request_atom_iter->cur);n++){
                memcpy(&l_data[n].hash, l_ch_chain->request_atom_iter->cur_hash, sizeof (l_data[n].hash));
                // Shift offset counter
                l_data_size += sizeof (dap_stream_ch_chain_update_element_t);
                // Then get next atom
                l_ch_chain->request_atom_iter->chain->callback_atom_iter_get_next(l_ch_chain->request_atom_iter, NULL);
            }
            if (l_data_size){
                if(s_debug_more)
                    log_it(L_DEBUG,"Out: UPDATE_CHAINS size %zd sent ",l_data_size);
                dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS,
                                                     l_ch_chain->request_hdr.net_id.uint64,
                                                     l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64,
                                                     l_data,l_data_size);
            }
            if(!l_data_size  ||  !l_ch_chain->request_atom_iter){ // We over with all the hashes here
                if(s_debug_more)
                    log_it(L_INFO,"Out: UPDATE_CHAINS_END sent ");
                dap_stream_ch_chain_sync_request_t l_request = {};
                dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_END,
                                                     l_ch_chain->request_hdr.net_id.uint64,
                                                     l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64,
                                                     &l_request, sizeof(dap_stream_ch_chain_sync_request_t));
                dap_stream_ch_chain_go_idle(l_ch_chain);
                dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
            }
            DAP_DELETE(l_data);
        }break;

        // Synchronize chains
        case CHAIN_STATE_SYNC_CHAINS: {
            bool l_was_sent_smth=false;
            // Process one chain from l_ch_chain->request_atom_iter
            // Pack loop to skip quicker
            for(uint_fast16_t k=0; k<s_skip_in_reactor_count     &&
                                   l_ch_chain->request_atom_iter &&
                                   l_ch_chain->request_atom_iter->cur; k++){
                // Check if present and skip if present
                dap_stream_ch_chain_hash_item_t * l_hash_item = NULL;
                HASH_FIND(hh,l_ch_chain->remote_atoms, l_ch_chain->request_atom_iter->cur_hash , sizeof (l_hash_item->hash), l_hash_item );
                if( l_hash_item ){ // If found - skip it
                    if(s_debug_more){
                        char l_request_atom_hash_str[81]={[0]='\0'};
                        dap_chain_hash_fast_to_str(l_ch_chain->request_atom_iter->cur_hash,l_request_atom_hash_str,sizeof (l_request_atom_hash_str));
                        log_it(L_DEBUG, "Out CHAIN: skip atom hash %s because its already present in remote atom hash table",
                                        l_request_atom_hash_str);
                    }
                }else{
                    l_hash_item = DAP_NEW_Z(dap_stream_ch_chain_hash_item_t);
                    dap_hash_fast(l_ch_chain->request_atom_iter->cur, l_ch_chain->request_atom_iter->cur_size,
                                  &l_hash_item->hash);
                    if(s_debug_more){
                        char *l_atom_hash_str= dap_chain_hash_fast_to_str_new(&l_hash_item->hash);
                        log_it(L_INFO, "Out CHAIN pkt: atom hash %s (size %zd) ", l_atom_hash_str, l_ch_chain->request_atom_iter->cur_size);
                        DAP_DELETE(l_atom_hash_str);
                    }
                    dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN, l_ch_chain->request_hdr.net_id.uint64,
                                                         l_ch_chain->request_hdr.chain_id.uint64, l_ch_chain->request_hdr.cell_id.uint64,
                                                         l_ch_chain->request_atom_iter->cur, l_ch_chain->request_atom_iter->cur_size);
                    l_was_sent_smth = true;
                    l_ch_chain->stats_request_atoms_processed++;

                    l_hash_item->size = l_ch_chain->request_atom_iter->cur_size;

                    unsigned l_hash_item_hashv =0;
                    dap_stream_ch_chain_hash_item_t *l_hash_item_check = NULL;

                    HASH_VALUE(&l_hash_item->hash ,sizeof (l_hash_item->hash),
                               l_hash_item_hashv);
                    HASH_FIND_BYHASHVALUE(hh, l_ch_chain->remote_atoms,&l_hash_item->hash ,sizeof (l_hash_item->hash),
                                          l_hash_item_hashv,  l_hash_item_check);
                    if (l_hash_item_check ==NULL ){
                        // Because we sent this atom to remote - we record it to not to send it twice
                        HASH_ADD_BYHASHVALUE(hh, l_ch_chain->remote_atoms, hash, sizeof (l_hash_item->hash),l_hash_item_hashv,
                                             l_hash_item);
                    }else
                        DAP_DELETE(l_hash_item);

                }
                // Then get next atom and populate new last
                l_ch_chain->request_atom_iter->chain->callback_atom_iter_get_next(l_ch_chain->request_atom_iter, NULL);
            }
            if(!l_ch_chain->request_atom_iter || !l_ch_chain->request_atom_iter->cur)  { // All chains synced
                dap_stream_ch_chain_sync_request_t l_request = {0};
                // last message
                l_was_sent_smth = true;
                dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS,
                                                     l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64, &l_request, sizeof(l_request));
                log_it( L_INFO,"Synced: %llu atoms processed", l_ch_chain->stats_request_atoms_processed);
                dap_stream_ch_chain_go_idle(l_ch_chain);
                if (l_ch_chain->callback_notify_packet_out)
                    l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS, NULL,
                                                           0, l_ch_chain->callback_notify_arg);
            }
            if (! l_was_sent_smth ){
                // Sending dumb packet with nothing to inform remote thats we're just skiping atoms, nothing freezed
                dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_TSD,
                                                     l_ch_chain->request_hdr.net_id.uint64, l_ch_chain->request_hdr.chain_id.uint64,
                                                     l_ch_chain->request_hdr.cell_id.uint64, NULL, 0);
            }
        } break;
        default: break;
    }
}
