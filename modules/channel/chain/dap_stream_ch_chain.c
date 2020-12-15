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

static void s_stream_ch_new(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg);
static void s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg);

static bool s_debug_chain_sync=false;
/**
 * @brief dap_stream_ch_chain_init
 * @return
 */
int dap_stream_ch_chain_init()
{
    log_it(L_NOTICE, "Chains and global db exchange channel initialized");
    dap_stream_ch_proc_add(dap_stream_ch_chain_get_id(), s_stream_ch_new, s_stream_ch_delete, s_stream_ch_packet_in,
            s_stream_ch_packet_out);
    s_debug_chain_sync = dap_config_get_item_bool_default(g_config,"general","debug_chain_sync",false);

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
    a_ch->internal = DAP_NEW_Z(dap_stream_ch_chain_t);
    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    l_ch_chain->ch = a_ch;
}

/**
 * @brief s_stream_ch_delete
 * @param ch
 * @param arg
 */
void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg)
{
    (void) a_arg;

    if(DAP_STREAM_CH_CHAIN(a_ch)->request_global_db_trs) {
        dap_db_log_list_delete(DAP_STREAM_CH_CHAIN(a_ch)->request_global_db_trs);
        DAP_STREAM_CH_CHAIN(a_ch)->request_global_db_trs = NULL;
    }

    if (DAP_STREAM_CH_CHAIN(a_ch)->pkt_copy_list) {
        dap_list_t *l_tmp_item = DAP_STREAM_CH_CHAIN(a_ch)->pkt_copy_list;
        while(l_tmp_item) {
            dap_chain_pkt_copy_t *l_pkt_copy = (dap_chain_pkt_copy_t *)l_tmp_item->data;
            DAP_DELETE(l_pkt_copy->pkt_data);
            DAP_DELETE(l_pkt_copy);
            dap_list_t *l_trash_item = l_tmp_item;
            l_tmp_item = dap_list_next(l_tmp_item);
            DAP_DELETE(l_trash_item);
        }
        DAP_STREAM_CH_CHAIN(a_ch)->pkt_copy_list = NULL;
    }
    if (DAP_STREAM_CH_CHAIN(a_ch)->db_iter) {
        DAP_STREAM_CH_CHAIN(a_ch)->db_iter = dap_list_first( DAP_STREAM_CH_CHAIN(a_ch)->db_iter);
        dap_list_free_full( DAP_STREAM_CH_CHAIN(a_ch)->db_iter, free);
        DAP_STREAM_CH_CHAIN(a_ch)->db_iter = NULL;
    }
}

/**
 * @brief s_sync_chains_callback
 * @param a_thread
 * @param a_arg
 * @return
 */
bool s_sync_chains_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    dap_stream_ch_t *l_ch = (dap_stream_ch_t *)a_arg;
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);

    dap_chain_t * l_chain = dap_chain_find_by_id(l_ch_chain->request_hdr.net_id, l_ch_chain->request_hdr.chain_id);
    l_ch_chain->request_atom_iter = l_chain->callback_atom_iter_create(l_chain);
    size_t l_first_size = 0;
    dap_chain_atom_ptr_t *l_first = l_chain->callback_atom_iter_get_first(l_ch_chain->request_atom_iter, &l_first_size);
    if (l_first && l_first_size) {
        // first packet
        if (!dap_hash_fast_is_blank(&l_ch_chain->request.hash_from)) {
            l_first = l_chain->callback_atom_find_by_hash(l_ch_chain->request_atom_iter,
                                                          &l_ch_chain->request.hash_from, &l_first_size);
        }
        l_ch_chain->state = CHAIN_STATE_SYNC_CHAINS;
        dap_chain_node_addr_t l_node_addr = {};
        dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain->request_hdr.net_id);
        l_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);

        dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN,
                l_ch_chain->request_hdr.net_id, l_ch_chain->request_hdr.chain_id,
                l_ch_chain->request_hdr.cell_id, &l_node_addr, sizeof(dap_chain_node_addr_t));
    }
    else {
        // last packet
        dap_stream_ch_chain_sync_request_t l_request = {};
        dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS,
                l_ch_chain->request_hdr.net_id, l_ch_chain->request_hdr.chain_id,
                l_ch_chain->request_hdr.cell_id, &l_request, sizeof(l_request));
        DAP_DEL_Z(l_ch_chain->request_atom_iter);
        l_ch_chain->state = CHAIN_STATE_IDLE;
        if (l_ch_chain->callback_notify_packet_out)
            l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS,
                                                    NULL, 0, l_ch_chain->callback_notify_arg);
    }
    dap_stream_ch_set_ready_to_write_unsafe(l_ch, true);
    dap_proc_thread_assign_on_worker_inter(a_thread, l_ch->stream_worker->worker, l_ch->stream->esocket );
    return true;
}

bool s_sync_gdb_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    dap_stream_ch_t *l_ch = (dap_stream_ch_t *)a_arg;
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);

    // Get log diff
    uint64_t l_local_last_id = dap_db_log_get_last_id();
    if (s_debug_chain_sync)
        log_it(L_DEBUG, "Requested transactions %llu:%llu", l_ch_chain->request.id_start, l_local_last_id);
    uint64_t l_start_item = l_ch_chain->request.id_start;
    // If the current global_db has been truncated, but the remote node has not known this
    if(l_ch_chain->request.id_start > l_local_last_id) {
        l_start_item = 0;
    }
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain->request_hdr.net_id);
    dap_list_t *l_add_groups = dap_chain_net_get_add_gdb_group(l_net, l_ch_chain->request.node_addr);
    dap_db_log_list_t *l_db_log = dap_db_log_list_start(l_start_item + 1, l_add_groups);
    dap_chain_node_addr_t l_node_addr = { 0 };
    l_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
    dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB,
            l_ch_chain->request_hdr.net_id, l_ch_chain->request_hdr.chain_id,
            l_ch_chain->request_hdr.cell_id, &l_node_addr, sizeof(dap_chain_node_addr_t));
    if(l_db_log) {
        // Add it to outgoing list
        l_ch_chain->request_global_db_trs = l_db_log;
        l_ch_chain->db_iter = NULL;
        l_ch_chain->state = CHAIN_STATE_SYNC_GLOBAL_DB;
    } else {
        dap_stream_ch_chain_sync_request_t l_request = {};
        dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                             l_ch_chain->request_hdr.net_id, l_ch_chain->request_hdr.chain_id,
                                             l_ch_chain->request_hdr.cell_id, &l_request, sizeof(l_request));
        l_ch_chain->state = CHAIN_STATE_IDLE;
        if(l_ch_chain->callback_notify_packet_out)
            l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                    NULL, 0, l_ch_chain->callback_notify_arg);
    }
    // go to send data from list [in s_stream_ch_packet_out()]
    // no data to send -> send one empty message DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB
    dap_stream_ch_set_ready_to_write_unsafe(l_ch, true);
    dap_proc_thread_assign_on_worker_inter(a_thread, l_ch->stream_worker->worker, l_ch->stream->esocket );
    return true;
}

bool s_chain_pkt_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    dap_stream_ch_t *l_ch = (dap_stream_ch_t *)a_arg;
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
    dap_chain_hash_fast_t l_atom_hash = {};
    dap_list_t *l_pkt_copy_list = l_ch_chain->pkt_copy_list;
    if (l_pkt_copy_list) {
        l_ch_chain->pkt_copy_list = l_ch_chain->pkt_copy_list->next;
        if ( l_ch_chain->pkt_copy_list ) {
            dap_chain_pkt_copy_t *l_pkt_copy = (dap_chain_pkt_copy_t *)l_pkt_copy_list->data;
            if (l_pkt_copy){
                dap_chain_t *l_chain = dap_chain_find_by_id(l_pkt_copy->pkt_hdr.net_id, l_pkt_copy->pkt_hdr.chain_id);
                if (!l_chain) {
                    if (s_debug_chain_sync)
                        log_it(L_WARNING, "No chain found for DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN");
                    return true;
                }
                dap_chain_atom_ptr_t l_atom_copy = (dap_chain_atom_ptr_t)l_pkt_copy->pkt_data;
                uint64_t l_atom_copy_size = l_pkt_copy->pkt_data_size;
                if ( l_atom_copy_size && l_pkt_copy && l_atom_copy ){
                    dap_hash_fast(l_atom_copy, l_atom_copy_size, &l_atom_hash);
                    dap_chain_atom_iter_t *l_atom_iter = l_chain->callback_atom_iter_create(l_chain);
                    size_t l_atom_size =0;
                    if ( l_chain->callback_atom_find_by_hash(l_atom_iter, &l_atom_hash, &l_atom_size) == NULL ) {
                        dap_chain_atom_verify_res_t l_atom_add_res = l_chain->callback_atom_add(l_chain, l_atom_copy, l_atom_copy_size);
                        if (l_atom_add_res == ATOM_ACCEPT && dap_chain_has_file_store(l_chain)) {
                            // append to file
                            dap_chain_cell_t *l_cell = dap_chain_cell_create_fill(l_chain, l_pkt_copy->pkt_hdr.cell_id);
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
                                    dap_db_set_last_hash_remote(l_ch_chain->request.node_addr.uint64, l_chain, &l_atom_hash);
                                }
                                // add all atoms from treshold
                                if (l_chain->callback_atom_add_from_treshold){
                                    dap_chain_atom_ptr_t l_atom_treshold;
                                    do{
                                        size_t l_atom_treshold_size;
                                        // add into ledger
                                        if (s_debug_chain_sync)
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
                                log_it(L_ERROR, "Can't get cell for cell_id 0x%x for save event to file", l_pkt_copy->pkt_hdr.cell_id);

                            }
                        }
                        if(l_atom_add_res == ATOM_PASS)
                            DAP_DELETE(l_atom_copy);
                    } else {
                        dap_db_set_last_hash_remote(l_ch_chain->request.node_addr.uint64, l_chain, &l_atom_hash);
                        DAP_DELETE(l_atom_copy);
                    }
                    l_chain->callback_atom_iter_delete(l_atom_iter);
                }else{
                    if (!l_pkt_copy)
                        log_it(L_WARNING, "packet copy is NULL");
                    if (!l_pkt_copy_list)
                        log_it(L_WARNING, "packet copy list is NULL");
                    if (l_atom_copy_size)
                        log_it(L_WARNING, "Atom copy size is zero");
                }
            }else{
                log_it(L_WARNING, "pkt copy is NULL");
            }
            if (l_pkt_copy)
                DAP_DELETE(l_pkt_copy);

            DAP_DELETE(l_pkt_copy_list);
        }else{
         //   log_it(L_WARNING, "Next pkt copy list is NULL");
        }
    }else
        log_it(L_WARNING, "In proc thread got CHAINS stream ch packet with zero data");
    dap_proc_thread_assign_on_worker_inter(a_thread, l_ch->stream_worker->worker, l_ch->stream->esocket );
    return true;
}

bool s_gdb_pkt_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    dap_stream_ch_t *l_ch = (dap_stream_ch_t *)a_arg;
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);

    dap_list_t *l_pkt_copy_list = l_ch_chain->pkt_copy_list;
    if (l_pkt_copy_list) {
        l_ch_chain->pkt_copy_list = l_ch_chain->pkt_copy_list->next;
        if (l_ch_chain->pkt_copy_list )
            l_ch_chain->pkt_copy_list->prev = NULL;

        dap_chain_pkt_copy_t *l_pkt_copy = (dap_chain_pkt_copy_t *)l_pkt_copy_list->data;
        size_t l_data_obj_count = 0;
        // deserialize data & Parse data from dap_db_log_pack()
        dap_store_obj_t *l_store_obj = dap_db_log_unpack(l_pkt_copy->pkt_data, l_pkt_copy->pkt_data_size, &l_data_obj_count);
        if (s_debug_chain_sync){
            if (l_data_obj_count)
                log_it(L_INFO, "In: l_data_obj_count = %d", l_data_obj_count );
            else if (l_pkt_copy->pkt_data){
                log_it(L_WARNING, "In: No data objs after unpack", l_data_obj_count );
            }else
                 log_it(L_WARNING, "In: packet in list with NULL data");
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

            if (s_debug_chain_sync){
                char l_ts_str[50];
                dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), l_store_obj[i].timestamp);
                log_it(L_DEBUG, "Unpacked log history: type='%c' (0x%02hhX) group=\"%s\" key=\"%s\""
                        " timestamp=\"%s\" value_len=%u  ",
                        (char ) l_store_obj[i].type, l_store_obj[i].type, l_store_obj[i].group,
                        l_store_obj[i].key, l_ts_str, l_store_obj[i].value_len);
            }

            if(!l_apply) {
                // If request was from defined node_addr we update its state
                if(l_ch_chain->request.node_addr.uint64) {
                    dap_db_set_last_id_remote(l_ch_chain->request.node_addr.uint64, l_obj->id);
                }
                continue;
            }

            // apply received transaction
            dap_chain_t *l_chain = dap_chain_find_by_id(l_pkt_copy->pkt_hdr.net_id, l_pkt_copy->pkt_hdr.chain_id);
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
                dap_stream_ch_chain_pkt_write_error(l_ch, l_pkt_copy->pkt_hdr.net_id,
                                                    l_pkt_copy->pkt_hdr.chain_id, l_pkt_copy->pkt_hdr.cell_id,
                                                    "ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED");
                dap_stream_ch_set_ready_to_write_unsafe(l_ch, true);
            } else {
                // If request was from defined node_addr we update its state
                if(l_ch_chain->request.node_addr.uint64) {
                    dap_db_set_last_id_remote(l_ch_chain->request.node_addr.uint64, l_obj->id);
                }
                if (s_debug_chain_sync)
                    log_it(L_DEBUG, "Added new GLOBAL_DB history pack");
            }
        }
        if(l_store_obj)
            dap_store_obj_free(l_store_obj, l_data_obj_count);
        if (l_pkt_copy)
            DAP_DELETE(l_pkt_copy);
        if (l_pkt_copy_list)
            DAP_DELETE(l_pkt_copy_list);
    } else {
        log_it(L_WARNING, "In proc thread got GDB stream ch packet with zero data");
    }
    dap_proc_thread_assign_on_worker_inter(a_thread, l_ch->stream_worker->worker, l_ch->stream->esocket );
    return true;
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
    size_t l_chain_pkt_data_size = l_ch_pkt->hdr.size - sizeof(l_chain_pkt->hdr);
    uint16_t l_acl_idx = dap_chain_net_acl_idx_by_id(l_chain_pkt->hdr.net_id);
    if (l_acl_idx == (uint16_t)-1) {
        log_it(L_ERROR, "Invalid net id 0x%016x in packet", l_chain_pkt->hdr.net_id);
        if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR) {
            if(l_ch_chain->callback_notify_packet_in) {
                l_ch_chain->callback_notify_packet_in(l_ch_chain, l_ch_pkt->hdr.type, l_chain_pkt,
                                                      l_chain_pkt_data_size, l_ch_chain->callback_notify_arg);
            }
        } else {
            dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                                                l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                                "ERROR_NET_INVALID_ID");
            dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
        }
        return;
    }
    if (a_ch->stream->session->acl && !a_ch->stream->session->acl[l_acl_idx]) {
        log_it(L_WARNING, "Unauthorized request attempt to network %s",
               dap_chain_net_by_id(l_chain_pkt->hdr.net_id)->pub.name);
        dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                            "ERROR_NET_NOT_AUTHORIZED");
        dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
        return;
    }
    switch (l_ch_pkt->hdr.type) {
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL: {
        log_it(L_INFO, "In:  SYNCED_ALL net 0x%016x chain 0x%016x cell 0x%016x", l_chain_pkt->hdr.net_id.uint64 ,
               l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB: {
            log_it(L_INFO, "In:  SYNCED_GLOBAL_DB: net 0x%016x chain 0x%016x cell 0x%016x", l_chain_pkt->hdr.net_id.uint64 ,
                   l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB_GROUP: {
        if (s_debug_chain_sync)
            log_it(L_INFO, "In:  SYNCED_GLOBAL_DB_GROUP pkt net 0x%016x chain 0x%016x cell 0x%016x", l_chain_pkt->hdr.net_id.uint64 ,
                   l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB_GROUP: {
        if (s_debug_chain_sync)
            log_it(L_INFO, "In:  SYNCED_GLOBAL_DB_GROUP pkt net 0x%016x chain 0x%016x cell 0x%016x", l_chain_pkt->hdr.net_id.uint64 ,
                   l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64);
    }
        break;

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
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS: {
        // fill ids
        if(l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t)) {
            memcpy(&l_ch_chain->request, l_chain_pkt->data, l_chain_pkt_data_size);
            memcpy(&l_ch_chain->request_hdr, &l_chain_pkt->hdr, sizeof(l_chain_pkt->hdr));
            char *l_hash_from_str = dap_chain_hash_fast_to_str_new(&l_ch_chain->request.hash_from);
            char *l_hash_to_str = dap_chain_hash_fast_to_str_new(&l_ch_chain->request.hash_to);
            log_it(L_INFO, "In:  SYNC_CHAINS pkt: net 0x%016x chain 0x%016x cell 0x%016x between %s and %s", l_ch_chain->request_hdr.net_id.uint64 ,
                   l_ch_chain->request_hdr.chain_id.uint64, l_ch_chain->request_hdr.cell_id.uint64,
                   l_hash_from_str? l_hash_from_str: "(null)", l_hash_to_str?l_hash_to_str:"(null)");
            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if(l_chain) {
                if(l_ch_chain->state != CHAIN_STATE_IDLE) {
                    log_it(L_INFO, "Can't process SYNC_CHAINS request between %s and %s because not in idle state",
                           l_hash_from_str? l_hash_from_str:"(null)",
                           l_hash_to_str?l_hash_to_str:"(null)");
                    dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                            "ERROR_STATE_NOT_IN_IDLE");
                    dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                } else {
                    dap_events_socket_remove_from_worker_unsafe(a_ch->stream->esocket, a_ch->stream_worker->worker);
#ifdef DAP_OS_WINDOWS
            if (a_ch->stream_worker->worker->proc_queue_input->buf_out_size == 0)
#endif
                    dap_proc_queue_add_callback_inter(  a_ch->stream_worker->worker->proc_queue_input, s_sync_chains_callback, a_ch);
                }
            }
            DAP_DELETE(l_hash_from_str);
            DAP_DELETE(l_hash_to_str);
        }else{
            log_it(L_WARNING, "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS: Wrong chain packet size %zd when expected %zd", l_chain_pkt_data_size, sizeof(l_ch_chain->request));
            dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    "ERROR_CHAIN_PKT_DATA_SIZE" );
        }
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB: {
        if(l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t)) {
            dap_stream_ch_chain_sync_request_t * l_request =
                    (dap_stream_ch_chain_sync_request_t *) l_chain_pkt->data;
            memcpy(&l_ch_chain->request, l_request, l_chain_pkt_data_size);
            memcpy(&l_ch_chain->request_hdr, &l_chain_pkt->hdr, sizeof(l_chain_pkt->hdr));
            log_it(L_INFO, "In:  SYNC_GLOBAL_DB pkt: net 0x%016x chain 0x%016x cell 0x%016x, range between %u and %u",
                   l_ch_chain->request_hdr.net_id.uint64 , l_ch_chain->request_hdr.chain_id.uint64,
                   l_ch_chain->request_hdr.cell_id.uint64, l_ch_chain->request.id_start, l_ch_chain->request.id_end );

            if(l_ch_chain->state != CHAIN_STATE_IDLE) {
                log_it(L_WARNING, "Can't process SYNC_GLOBAL_DB request because not in idle state");
                dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                        l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                        "ERROR_STATE_NOT_IN_IDLE");
                dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                break;
            }
            // receive the latest global_db revision of the remote node -> go to send mode
            else {
                log_it(L_INFO, "Got DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB request",
                        a_ch->stream->session->id);
                dap_events_socket_remove_from_worker_unsafe(a_ch->stream->esocket, a_ch->stream_worker->worker);
#ifdef DAP_OS_WINDOWS
            if (a_ch->stream_worker->worker->proc_queue_input->buf_out_size == 0)
#endif
                dap_proc_queue_add_callback_inter(a_ch->stream_worker->worker->proc_queue_input, s_sync_gdb_callback, a_ch);
            }
        }else{
            log_it(L_WARNING, "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB: Wrong chain packet size %zd when expected %zd", l_chain_pkt_data_size, sizeof(l_ch_chain->request));
            dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    "ERROR_CHAIN_PKT_DATA_SIZE" );
        }
    }
        break;
        // first packet of data with source node address
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN: {
        if(l_chain_pkt_data_size == sizeof(dap_chain_node_addr_t)){
                log_it(L_INFO, "From "NODE_ADDR_FP_STR": FIRST_CHAIN data_size=%d net 0x%016x chain 0x%016x cell 0x%016x ",
                       NODE_ADDR_FP_ARGS_S(l_ch_chain->request.node_addr),
                       l_chain_pkt_data_size,      l_ch_chain->request_hdr.net_id.uint64 ,
                       l_ch_chain->request_hdr.chain_id.uint64, l_ch_chain->request_hdr.cell_id.uint64);
        }else{
            log_it(L_WARNING,"Incorrect data size %zd in packet DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN", l_chain_pkt_data_size);
            dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    "ERROR_CHAIN_PACKET_TYPE_FIRST_CHAIN_INCORRET_DATA_SIZE(%zd/%zd)",l_chain_pkt_data_size, sizeof(dap_chain_node_addr_t));
        }
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN: {
        if(l_chain_pkt_data_size) {
            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if(l_chain) {
                // Expect atom element in
                if(l_chain_pkt_data_size > 0) {
                    dap_chain_pkt_copy_t *l_pkt_copy = DAP_NEW_Z(dap_chain_pkt_copy_t);
                    memcpy(&l_pkt_copy->pkt_hdr, &l_chain_pkt->hdr, sizeof(l_chain_pkt->hdr));
                    l_pkt_copy->pkt_data = DAP_NEW_Z_SIZE(byte_t, l_chain_pkt_data_size);
                    memcpy(l_pkt_copy->pkt_data, l_chain_pkt->data, l_chain_pkt_data_size);
                    l_pkt_copy->pkt_data_size = l_chain_pkt_data_size;
                    l_ch_chain->pkt_copy_list = dap_list_append(l_ch_chain->pkt_copy_list, l_pkt_copy);
                    if (s_debug_chain_sync){
                        dap_chain_hash_fast_t l_atom_hash={0};
                        dap_hash_fast(l_chain_pkt->data, l_chain_pkt_data_size ,&l_atom_hash);
                        char *l_atom_hash_str= dap_chain_hash_fast_to_str_new(&l_atom_hash);
                        log_it(L_INFO, "In: CHAIN pkt: atom hash %s (size %zd)", l_atom_hash_str, l_chain_pkt_data_size);
                        DAP_DELETE(l_atom_hash_str);
                    }

                    dap_events_socket_remove_from_worker_unsafe(a_ch->stream->esocket, a_ch->stream_worker->worker);
#ifdef DAP_OS_WINDOWS
            if (a_ch->stream_worker->worker->proc_queue_input->buf_out_size == 0)
#endif
                    dap_proc_queue_add_callback_inter(a_ch->stream_worker->worker->proc_queue_input, s_chain_pkt_callback, a_ch);
                } else {
                    log_it(L_WARNING, "Empty chain packet");
                    dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                            "ERROR_CHAIN_PACKET_EMPTY");
                    dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                }
            }
        }
    }
        break;
        // first packet of data with source node address
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB:
        if(l_chain_pkt_data_size == sizeof(dap_chain_node_addr_t)){
            memcpy(&l_ch_chain->request.node_addr, l_chain_pkt->data, l_chain_pkt_data_size);
           log_it(L_INFO, "In: FIRST_GLOBAL_DB data_size=%d net 0x%016x chain 0x%016x cell 0x%016x from address "NODE_ADDR_FP_STR,
                  l_chain_pkt_data_size,   l_chain_pkt->hdr.net_id.uint64 ,
                  l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64, NODE_ADDR_FP_ARGS_S(l_ch_chain->request.node_addr) );
        }else {
           log_it(L_WARNING,"Incorrect data size %zd in packet DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB", l_chain_pkt_data_size);
           dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                   l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                   "ERROR_CHAIN_PACKET_TYPE_FIRST_GLOBAL_DB_INCORRET_DATA_SIZE");
        }
    break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB: {
        if(s_debug_chain_sync)
            log_it(L_INFO, "In: GLOBAL_DB data_size=%d ", l_chain_pkt_data_size);
        // get transaction and save it to global_db
        if(l_chain_pkt_data_size > 0) {
            dap_chain_pkt_copy_t *l_pkt_copy = DAP_NEW_Z(dap_chain_pkt_copy_t);
            memcpy(&l_pkt_copy->pkt_hdr, &l_chain_pkt->hdr, sizeof(l_chain_pkt->hdr));
            l_pkt_copy->pkt_data = DAP_NEW_Z_SIZE(byte_t, l_chain_pkt_data_size);
            memcpy(l_pkt_copy->pkt_data, l_chain_pkt->data, l_chain_pkt_data_size);
            l_pkt_copy->pkt_data_size = l_chain_pkt_data_size;
            l_ch_chain->pkt_copy_list = dap_list_append(l_ch_chain->pkt_copy_list, l_pkt_copy);
            dap_events_socket_remove_from_worker_unsafe(a_ch->stream->esocket, a_ch->stream_worker->worker);
//#ifdef DAP_OS_WINDOWS
//            if (a_ch->stream_worker->worker->proc_queue_input->buf_out_size == 0)
//#endif
            dap_proc_queue_add_callback_inter(a_ch->stream_worker->worker->proc_queue_input, s_gdb_pkt_callback, a_ch);
        } else {
            log_it(L_WARNING, "Packet with GLOBAL_DB atom has zero body size");
            dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    "ERROR_GLOBAL_DB_PACKET_EMPTY");
            dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
        }
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB_RVRS: {
        dap_stream_ch_chain_sync_request_t l_sync_gdb = {0};
        memcpy(&l_sync_gdb, l_chain_pkt->data, l_chain_pkt_data_size);
        //l_sync_gdb.id_start = dap_db_get_last_id_remote(l_sync_gdb.node_addr.uint64);
        dap_chain_net_t *l_net = dap_chain_net_by_id(l_chain_pkt->hdr.net_id);
        l_sync_gdb.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
        log_it(L_INFO, "In:  SYNC_GLOBAL_DB_RVRS pkt: net 0x%016x chain 0x%016x cell 0x%016x, request gdb sync from %u", l_chain_pkt->hdr.net_id.uint64 ,
                l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id, l_sync_gdb.id_start );
        dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB, l_chain_pkt->hdr.net_id,
                                      l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id, &l_sync_gdb, sizeof(l_sync_gdb));
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS_RVRS: {
        if(l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t)) {
            dap_stream_ch_chain_sync_request_t l_request={0};
            dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
            if( l_chain){
                //dap_chain_get_atom_last_hash(l_chain,& l_request.hash_from);
                if( dap_log_level_get()<= L_INFO){
                    char l_hash_from_str[70]={[0]='\0'};
                    dap_chain_hash_fast_to_str(&l_request.hash_from,l_hash_from_str,sizeof (l_hash_from_str)-1);
                    log_it(L_INFO, "In:  SYNC_CHAINS_RVRS pkt: net 0x%016x chain 0x%016x cell 0x%016x request chains sync from %s",
                           l_chain_pkt->hdr.net_id.uint64 , l_chain_pkt->hdr.chain_id.uint64, l_chain_pkt->hdr.cell_id.uint64,
                           l_hash_from_str[0] ? l_hash_from_str :"(null)");
                }
                dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS, l_chain_pkt->hdr.net_id,
                                              l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id, &l_request, sizeof(l_request));
            }
        }else{
            log_it(L_WARNING, "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS_RVRS: Wrong chain packet size %zd when expected %zd", l_chain_pkt_data_size, sizeof(l_ch_chain->request));
            dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    "ERROR_CHAIN_PKT_DATA_SIZE" );
        }
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR:
        break;
    default: {
        dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
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
    //log_it(L_DEBUG, "CHAIN_STATE_IDLE");

    // Cleanup after request
    memset(&a_ch_chain->request, 0, sizeof(a_ch_chain->request));
    memset(&a_ch_chain->request_hdr, 0, sizeof(a_ch_chain->request_hdr));
    DAP_DEL_Z(a_ch_chain->request_atom_iter);
}

static void s_process_gdb_iter(dap_stream_ch_t *a_ch)
{
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    dap_db_log_list_t *l_db_list = l_ch_chain->request_global_db_trs;
    dap_store_obj_pkt_t *l_pkt = (dap_store_obj_pkt_t *)l_ch_chain->db_iter->data;
    uint32_t l_pkt_size = sizeof(dap_store_obj_pkt_t) + l_pkt->data_size;
    if( s_debug_chain_sync)
        log_it(L_INFO, "Send one global_db record packet len=%d (rest=%d/%d items)", l_pkt_size,
           dap_db_log_list_get_count_rest(l_db_list), dap_db_log_list_get_count(l_db_list));
    dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB,
                                         l_ch_chain->request_hdr.net_id, l_ch_chain->request_hdr.chain_id,
                                         l_ch_chain->request_hdr.cell_id, l_pkt, l_pkt_size);
    dap_list_t *l_iter = dap_list_next(l_ch_chain->db_iter);
    if (l_iter) {
        l_ch_chain->db_iter = l_iter;
    } else {
        l_ch_chain->stats_request_gdb_processed++;
        l_ch_chain->db_iter = dap_list_first(l_ch_chain->db_iter);
        dap_list_free_full(l_ch_chain->db_iter, free);
        l_ch_chain->db_iter = NULL;
    }
}

static bool s_out_pkt_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    dap_stream_ch_t *l_ch = (dap_stream_ch_t *)a_arg;
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);

    if(s_debug_chain_sync)
        log_it( L_DEBUG,"s_stream_ch_packet_out state=%d", l_ch_chain ? l_ch_chain->state : -1);
    switch (l_ch_chain->state) {

        case CHAIN_STATE_IDLE: {
            dap_stream_ch_chain_go_idle(l_ch_chain);
        } break;

        // Synchronize GDB
        case CHAIN_STATE_SYNC_GLOBAL_DB: {
            if (l_ch_chain->db_iter) {
                s_process_gdb_iter(l_ch);
            } else {
                dap_global_db_obj_t *l_obj;
                do { // Get log diff
                    size_t l_item_size_out = 0;
                    l_obj = dap_db_log_list_get(l_ch_chain->request_global_db_trs);
                    l_ch_chain->db_iter = dap_db_log_pack(l_obj, &l_item_size_out);
                    if (l_ch_chain->db_iter && l_item_size_out) {
                        break;
                    }
                    // Item not found, maybe it has deleted? Then go to the next item
                } while (l_obj);
                if (l_ch_chain->db_iter) {
                    s_process_gdb_iter(l_ch);
                } else {
                    // free log list
                    dap_db_log_list_delete(l_ch_chain->request_global_db_trs);
                    l_ch_chain->request_global_db_trs = NULL;
                    log_it( L_INFO,"Syncronized database:  last id %llu, items syncronyzed %llu ", dap_db_log_get_last_id(),
                        l_ch_chain->stats_request_gdb_processed );
                    // last message
                    dap_stream_ch_chain_sync_request_t l_request = {};
                    dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                         l_ch_chain->request_hdr.net_id, l_ch_chain->request_hdr.chain_id,
                                                         l_ch_chain->request_hdr.cell_id, &l_request, sizeof(l_request));
                    dap_stream_ch_chain_go_idle(l_ch_chain);
                    if (l_ch_chain->callback_notify_packet_out)
                        l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                               NULL, 0, l_ch_chain->callback_notify_arg);
                }
            }
        } break;

        // Synchronize chains
        case CHAIN_STATE_SYNC_CHAINS: {
            if (l_ch_chain->request_atom_iter->cur) { // Process one chain from l_ch_chain->request_atom_iter
                if(s_debug_chain_sync){
                    dap_chain_hash_fast_t l_atom_hash={0};
                    dap_hash_fast(l_ch_chain->request_atom_iter->cur, l_ch_chain->request_atom_iter->cur_size,&l_atom_hash);
                    char *l_atom_hash_str= dap_chain_hash_fast_to_str_new(&l_atom_hash);

                    log_it(L_INFO, "Out CHAIN pkt: atom hash %s (size %zd) ", l_atom_hash_str, l_ch_chain->request_atom_iter->cur_size);
                    DAP_DELETE(l_atom_hash_str);
                }
                dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN, l_ch_chain->request_hdr.net_id,
                                                     l_ch_chain->request_hdr.chain_id, l_ch_chain->request_hdr.cell_id,
                                                     l_ch_chain->request_atom_iter->cur, l_ch_chain->request_atom_iter->cur_size);
                l_ch_chain->stats_request_atoms_processed++;
                // Then get next atom and populate new last
                l_ch_chain->request_atom_iter->chain->callback_atom_iter_get_next(l_ch_chain->request_atom_iter, NULL);
            } else { // All chains synced
                dap_stream_ch_chain_sync_request_t l_request = {};
                // last message
                dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS,
                                                     l_ch_chain->request_hdr.net_id, l_ch_chain->request_hdr.chain_id,
                                                     l_ch_chain->request_hdr.cell_id, &l_request, sizeof(l_request));
                log_it( L_INFO,"Synced: %llu atoms processed", l_ch_chain->stats_request_atoms_processed);
                dap_stream_ch_chain_go_idle(l_ch_chain);
                if (l_ch_chain->callback_notify_packet_out)
                    l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS, NULL,
                                                           0, l_ch_chain->callback_notify_arg);
            }
        } break;
        default: break;
    }
    if (l_ch->stream->esocket->buf_out_size + DAP_CHAIN_PKT_MAX_SIZE > l_ch->stream->esocket->buf_out_size_max  ||
            l_ch_chain->state == CHAIN_STATE_IDLE) {
        if (l_ch->stream->esocket->buf_out_size) {
            dap_stream_ch_set_ready_to_write_unsafe(l_ch, true);
        }
        dap_proc_thread_assign_on_worker_inter(a_thread, l_ch->stream_worker->worker, l_ch->stream->esocket );
        return true;
    }
    return false;
}

/**
 * @brief s_stream_ch_packet_out
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg)
{
    (void) a_arg;

    /// That was for what?!
    ///
    /// if (a_ch->stream->esocket->buf_out_size > ( a_ch->stream->esocket->buf_out_size_max / 4 )) {
    ///        return;
    ///   }
    ///
    dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    if (l_ch_chain && l_ch_chain->state != CHAIN_STATE_IDLE) {
        dap_events_socket_remove_from_worker_unsafe(a_ch->stream->esocket, a_ch->stream_worker->worker);
        dap_proc_queue_add_callback_inter(a_ch->stream_worker->worker->proc_queue_input, s_out_pkt_callback, a_ch);
    }
}
