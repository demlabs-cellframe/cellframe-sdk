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

/**
 * @brief dap_stream_ch_chain_init
 * @return
 */
int dap_stream_ch_chain_init()
{
    log_it(L_NOTICE, "Chains and global db exchange channel initialized");
    dap_stream_ch_proc_add(dap_stream_ch_chain_get_id(), s_stream_ch_new, s_stream_ch_delete, s_stream_ch_packet_in,
            s_stream_ch_packet_out);

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
    pthread_mutex_init(&l_ch_chain->mutex, NULL);
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
        dap_db_log_list_delete(DAP_STREAM_CH_CHAIN(a_ch)->request_global_db_trs); //dap_list_free_full(DAP_STREAM_CH_CHAIN(a_ch)->request_global_db_trs, (dap_callback_destroyed_t) free);
        DAP_STREAM_CH_CHAIN(a_ch)->request_global_db_trs = NULL;
    }
    pthread_mutex_destroy(&DAP_STREAM_CH_CHAIN(a_ch)->mutex);
}


bool s_sync_chains_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    dap_stream_ch_t *l_ch = (dap_stream_ch_t *)a_arg;
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);

    dap_chain_t * l_chain = dap_chain_find_by_id(l_ch_chain->request_net_id, l_ch_chain->request_chain_id);
    l_ch_chain->request_atom_iter = l_chain->callback_atom_iter_create(l_chain);
    size_t l_first_size = 0;
    dap_chain_atom_ptr_t *l_first = l_chain->callback_atom_iter_get_first(l_ch_chain->request_atom_iter, &l_first_size);
    if (l_first && l_first_size) {
        // first packet
        l_ch_chain->state = CHAIN_STATE_SYNC_CHAINS;
        dap_chain_node_addr_t l_node_addr = { 0 };
        dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain->request_net_id);
        l_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
        dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN,
                l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                l_ch_chain->request_cell_id, &l_node_addr, sizeof(dap_chain_node_addr_t));
    }
    else {
        // last packet
        dap_stream_ch_chain_sync_request_t l_request = {};
        dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS,
                l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                l_ch_chain->request_cell_id, &l_request, sizeof(l_request));
        DAP_DEL_Z(l_ch_chain->request_atom_iter);
        l_ch_chain->state = CHAIN_STATE_IDLE;
        if (l_ch_chain->callback_notify_packet_out)
            l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS,
                                                    NULL, 0, l_ch_chain->callback_notify_arg);
    }
    dap_stream_ch_set_ready_to_write_unsafe(l_ch, true);
    dap_events_socket_assign_on_worker_mt(l_ch->stream->esocket, l_ch->stream_worker->worker);
    return true;
}

bool s_sync_gdb_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    dap_stream_ch_t *l_ch = (dap_stream_ch_t *)a_arg;
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);

    // Get log diff
    l_ch_chain->request_last_ts = dap_db_log_get_last_id();
    //log_it(L_DEBUG, "Requested transactions %llu:%llu", l_request->id_start, (uint64_t ) l_ch_chain->request_last_ts);
    uint64_t l_start_item = l_ch_chain->request.id_start;
    // If the current global_db has been truncated, but the remote node has not known this
    if(l_ch_chain->request.id_start > l_ch_chain->request_last_ts) {
        l_start_item = 0;
    }
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain->request_net_id);
    dap_list_t *l_add_groups = dap_chain_net_get_add_gdb_group(l_net, l_ch_chain->request.node_addr);
    dap_db_log_list_t *l_db_log = dap_db_log_list_start(l_start_item + 1, l_add_groups);
    dap_chain_node_addr_t l_node_addr = { 0 };
    l_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
    dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB,
            l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
            l_ch_chain->request_cell_id, &l_node_addr, sizeof(dap_chain_node_addr_t));
    if(l_db_log) {
        //log_it(L_DEBUG, "Start getting items %u:%u", l_request->id_start + 1,l_db_log->items_number);//dap_list_length(l_list));
        // Add it to outgoing list
        l_ch_chain->request_global_db_trs = l_db_log;
        l_ch_chain->db_iter = NULL;
        l_ch_chain->state = CHAIN_STATE_SYNC_GLOBAL_DB;
    } else {
        dap_stream_ch_chain_sync_request_t l_request = {};
        //log_it(L_DEBUG, "No items to sync from %u", l_request->id_start + 1);
        l_request.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
        l_request.id_start = dap_db_log_get_last_id_remote(l_ch_chain->request.node_addr.uint64);
        dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                             l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                                             l_ch_chain->request_cell_id, &l_request, sizeof(l_request));
        l_ch_chain->state = CHAIN_STATE_IDLE;
        if(l_ch_chain->callback_notify_packet_out)
            l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                                    NULL, 0, l_ch_chain->callback_notify_arg);
    }
    //log_it(L_INFO, "Prepared %u items for sync", l_db_log->items_number - l_request->id_start);
    // go to send data from list [in s_stream_ch_packet_out()]
    // no data to send -> send one empty message DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB_SYNCED
    dap_stream_ch_set_ready_to_write_unsafe(l_ch, true);
    dap_events_socket_assign_on_worker_mt(l_ch->stream->esocket, l_ch->stream_worker->worker);
    return true;
}

bool s_chain_pkt_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    dap_stream_ch_t *l_ch = (dap_stream_ch_t *)a_arg;
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
    dap_chain_t * l_chain = dap_chain_find_by_id(l_ch_chain->request_net_id, l_ch_chain->request_chain_id);
    if (!l_chain) {
        log_it(L_WARNING, "No chain found for DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN");
        return true;
    }

    dap_chain_hash_fast_t l_atom_hash = {};
    dap_chain_atom_ptr_t l_atom_copy = l_ch_chain->pkt_data;
    uint64_t l_atom_copy_size = l_ch_chain->pkt_data_size;
    l_ch_chain->pkt_data = NULL;
    l_ch_chain->pkt_data_size = 0;
    if( l_atom_copy && l_atom_copy_size){
        dap_hash_fast(l_atom_copy, l_atom_copy_size, &l_atom_hash);
        dap_chain_atom_iter_t *l_atom_iter = l_chain->callback_atom_iter_create(l_chain);
        size_t l_atom_size =0;
        if ( l_chain->callback_atom_find_by_hash(l_atom_iter, &l_atom_hash, &l_atom_size) == NULL ) {
            dap_chain_atom_verify_res_t l_atom_add_res = l_chain->callback_atom_add(l_chain, l_atom_copy, l_atom_copy_size);
            if(l_atom_add_res == ATOM_ACCEPT && dap_chain_has_file_store(l_chain)) {
                // append to file
                dap_chain_cell_t *l_cell = dap_chain_cell_create_fill(l_chain, l_ch_chain->request_cell_id);
                // add one atom only
                int l_res = dap_chain_cell_file_append(l_cell, l_atom_copy, l_atom_copy_size);
                // rewrite all file
                //l_res = dap_chain_cell_file_update(l_cell);
                if(!l_cell || l_res < 0) {
                    log_it(L_ERROR, "Can't save event 0x%x to the file '%s'", l_atom_hash,
                            l_cell ? l_cell->file_storage_path : "[null]");
                }
                // delete cell and close file
                dap_chain_cell_delete(l_cell);
            }
            if(l_atom_add_res == ATOM_PASS)
                DAP_DELETE(l_atom_copy);
        } else {
            DAP_DELETE(l_atom_copy);
        }
        l_chain->callback_atom_iter_delete(l_atom_iter);
    }else
        log_it(L_WARNING, "In proc thread got stream ch packet with pkt_size: %zd and pkt_data: %p", l_atom_copy_size, l_atom_copy);
    dap_events_socket_assign_on_worker_mt(l_ch->stream->esocket, l_ch->stream_worker->worker);
    return true;
}

bool s_gdb_pkt_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    dap_stream_ch_t *l_ch = (dap_stream_ch_t *)a_arg;
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
    dap_chain_t * l_chain = dap_chain_find_by_id(l_ch_chain->request_net_id, l_ch_chain->request_chain_id);

    size_t l_data_obj_count = 0;
    // deserialize data & Parse data from dap_db_log_pack()
    dap_store_obj_t *l_store_obj = dap_db_log_unpack(l_ch_chain->pkt_data,l_ch_chain->pkt_data_size, &l_data_obj_count);
    //log_it(L_INFO, "In: l_data_obj_count = %d", l_data_obj_count );

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

        if(!l_apply) {
            // If request was from defined node_addr we update its state
            if(l_ch_chain->request.node_addr.uint64) {
                dap_db_log_set_last_id_remote(l_ch_chain->request.node_addr.uint64, l_obj->id);
            }
            continue;
        }

        char l_ts_str[50];
        dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), l_store_obj[i].timestamp);
        /*log_it(L_DEBUG, "Unpacked log history: type='%c' (0x%02hhX) group=\"%s\" key=\"%s\""
                " timestamp=\"%s\" value_len=%u  ",
                (char ) l_store_obj[i].type, l_store_obj[i].type, l_store_obj[i].group,
                l_store_obj[i].key, l_ts_str, l_store_obj[i].value_len);*/
        // apply received transaction
        dap_chain_t *l_chain = dap_chain_find_by_id(l_ch_chain->request_net_id, l_ch_chain->request_chain_id);
        if(l_chain) {
            if(l_chain->callback_datums_pool_proc_with_group){
                void * restrict l_store_obj_value = l_store_obj->value;
                l_chain->callback_datums_pool_proc_with_group(l_chain,
                        (dap_chain_datum_t** restrict) l_store_obj_value, 1,
                        l_store_obj[i].group);
            }
        }
        // save data to global_db
        if(!dap_chain_global_db_obj_save(l_obj, 1)) {
            dap_stream_ch_chain_pkt_write_error(l_ch, l_ch_chain->request_net_id,
                                                l_ch_chain->request_chain_id, l_ch_chain->request_cell_id,
                                                "ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED");
            dap_stream_ch_set_ready_to_write_unsafe(l_ch, true);
        } else {
            // If request was from defined node_addr we update its state
            if(l_ch_chain->request.node_addr.uint64) {
                dap_db_log_set_last_id_remote(l_ch_chain->request.node_addr.uint64, l_obj->id);
            }
            //log_it(L_DEBUG, "Added new GLOBAL_DB history pack");
        }
    }
    if(l_store_obj)
        dap_store_obj_free(l_store_obj, l_data_obj_count);
    dap_events_socket_assign_on_worker_mt(l_ch->stream->esocket, l_ch->stream_worker->worker);
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
    uint8_t l_acl_idx = dap_chain_net_acl_idx_by_id(l_chain_pkt->hdr.net_id);
    if (l_acl_idx == (uint8_t)-1) {
        log_it(L_ERROR, "Invalid net id in packet");
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
        log_it(L_INFO, "In:  SYNCED_ALL pkt");
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB: {
        log_it(L_INFO, "In:  SYNCED_GLOBAL_DB pkt");
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB_GROUP: {
        log_it(L_INFO, "In:  SYNCED_GLOBAL_DB_GROUP pkt");
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB_GROUP: {
        log_it(L_INFO, "In:  SYNCED_GLOBAL_DB_GROUP pkt");
    }
        break;

    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS: {
        log_it(L_INFO, "In:  SYNCED_CHAINS pkt");
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS: {
        log_it(L_INFO, "In:  SYNC_CHAINS pkt");
        dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        if(l_chain) {
            if(l_ch_chain->state != CHAIN_STATE_IDLE) {
                log_it(L_INFO, "Can't process SYNC_CHAINS request because not in idle state");
                dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                        l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                        "ERROR_STATE_NOT_IN_IDLE");
                dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
            } else {
                // fill ids
                if(l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t)) {
                    dap_stream_ch_chain_sync_request_t * l_request =
                            (dap_stream_ch_chain_sync_request_t *) l_chain_pkt->data;
                    memcpy(&l_ch_chain->request, l_request, l_chain_pkt_data_size);
                    memcpy(&l_ch_chain->request_cell_id, &l_chain_pkt->hdr.cell_id, sizeof(dap_chain_cell_id_t));
                    memcpy(&l_ch_chain->request_net_id, &l_chain_pkt->hdr.net_id, sizeof(dap_chain_net_id_t));
                    memcpy(&l_ch_chain->request_chain_id, &l_chain_pkt->hdr.chain_id, sizeof(dap_chain_id_t));
            }
                dap_events_socket_remove_from_worker_unsafe(a_ch->stream->esocket, a_ch->stream_worker->worker);
                dap_proc_queue_add_callback(a_ch->stream_worker->worker->proc_queue, s_sync_chains_callback, a_ch);
            }
        }
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB: {
        log_it(L_INFO, "In:  SYNC_GLOBAL_DB pkt");
        if(l_ch_chain->state != CHAIN_STATE_IDLE) {
            log_it(L_INFO, "Can't process SYNC_GLOBAL_DB request because not in idle state");
            dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    "ERROR_STATE_NOT_IN_IDLE");
            dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
            break;
        }
        // receive the latest global_db revision of the remote node -> go to send mode
        if(l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t)) {
            dap_stream_ch_chain_sync_request_t * l_request =
                    (dap_stream_ch_chain_sync_request_t *) l_chain_pkt->data;
            memcpy(&l_ch_chain->request, l_request, l_chain_pkt_data_size);
            memcpy(&l_ch_chain->request_cell_id, &l_chain_pkt->hdr.cell_id, sizeof(dap_chain_cell_id_t));
            memcpy(&l_ch_chain->request_net_id, &l_chain_pkt->hdr.net_id, sizeof(dap_chain_net_id_t));
            memcpy(&l_ch_chain->request_chain_id, &l_chain_pkt->hdr.chain_id, sizeof(dap_chain_id_t));
            dap_events_socket_remove_from_worker_unsafe(a_ch->stream->esocket, a_ch->stream_worker->worker);
            dap_proc_queue_add_callback(a_ch->stream_worker->worker->proc_queue, s_sync_gdb_callback, a_ch);
        }
        else {
            log_it(L_ERROR, "Get DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB session_id=%u bad request",
                    a_ch->stream->session->id);
            dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                    "ERROR_SYNC_GLOBAL_DB_REQUEST_BAD");
            dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
        }
    }
        break;
        // first packet of data with source node address
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN: {
        log_it(L_INFO, "In: FIRST_CHAIN data_size=%d", l_chain_pkt_data_size);
        if(l_chain_pkt_data_size == sizeof(dap_chain_node_addr_t))
            memcpy(&l_ch_chain->request.node_addr, l_chain_pkt->data, l_chain_pkt_data_size);
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN: {
        log_it(L_INFO, "In: CHAIN pkt data_size=%d", l_chain_pkt_data_size);
        dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
        if(l_chain) {
            // Expect atom element in
            if(l_chain_pkt_data_size > 0) {
                memcpy(&l_ch_chain->request_net_id, &l_chain_pkt->hdr.net_id, sizeof(dap_chain_net_id_t));
                memcpy(&l_ch_chain->request_chain_id, &l_chain_pkt->hdr.chain_id, sizeof(dap_chain_id_t));
                memcpy(&l_ch_chain->request_cell_id, &l_chain_pkt->hdr.cell_id, sizeof(dap_chain_cell_id_t));
                l_ch_chain->pkt_data = DAP_CALLOC(1, l_chain_pkt_data_size);
                memcpy(l_ch_chain->pkt_data, l_chain_pkt->data, l_chain_pkt_data_size);
                l_ch_chain->pkt_data_size = l_chain_pkt_data_size;
                dap_events_socket_remove_from_worker_unsafe(a_ch->stream->esocket, a_ch->stream_worker->worker);
                dap_proc_queue_add_callback(a_ch->stream_worker->worker->proc_queue, s_chain_pkt_callback, a_ch);
            } else {
                log_it(L_WARNING, "Empty chain packet");
                dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                        l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                        "ERROR_CHAIN_PACKET_EMPTY");
                dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
            }
        }
    }
        break;
        // first packet of data with source node address
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB: {
        log_it(L_INFO, "In: FIRST_GLOBAL_DB data_size=%d", l_chain_pkt_data_size);
        if(l_chain_pkt_data_size == sizeof(dap_chain_node_addr_t))
            memcpy(&l_ch_chain->request.node_addr, l_chain_pkt->data, l_chain_pkt_data_size);
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB: {
        log_it(L_INFO, "In: GLOBAL_DB data_size=%d", l_chain_pkt_data_size);
        // get transaction and save it to global_db
        if(l_chain_pkt_data_size > 0) {
            memcpy(&l_ch_chain->request_net_id, &l_chain_pkt->hdr.net_id, sizeof(dap_chain_net_id_t));
            memcpy(&l_ch_chain->request_chain_id, &l_chain_pkt->hdr.chain_id, sizeof(dap_chain_id_t));
            memcpy(&l_ch_chain->request_cell_id, &l_chain_pkt->hdr.cell_id, sizeof(dap_chain_cell_id_t));
            l_ch_chain->pkt_data = DAP_CALLOC(1, l_chain_pkt_data_size);
            memcpy(l_ch_chain->pkt_data, l_chain_pkt->data, l_chain_pkt_data_size);
            l_ch_chain->pkt_data_size = l_chain_pkt_data_size;
            dap_events_socket_remove_from_worker_unsafe(a_ch->stream->esocket, a_ch->stream_worker->worker);
            dap_proc_queue_add_callback(a_ch->stream_worker->worker->proc_queue, s_gdb_pkt_callback, a_ch);
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
        dap_stream_ch_chain_sync_request_t l_sync_gdb = {};
        memcpy(&l_sync_gdb, l_chain_pkt->data, l_chain_pkt_data_size);
        dap_chain_net_t *l_net = dap_chain_net_by_id(l_chain_pkt->hdr.net_id);
        l_sync_gdb.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
        // Get last timestamp in log
        l_sync_gdb.id_start = (uint64_t) dap_db_log_get_last_id_remote(l_ch_chain->request.node_addr.uint64);
        // no limit
        l_sync_gdb.id_end = (uint64_t)0;
        dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB, l_chain_pkt->hdr.net_id,
                                      l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id, &l_sync_gdb, sizeof(l_sync_gdb));
    }
        break;
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS_RVRS: {
        dap_stream_ch_chain_sync_request_t l_sync_chains = {};
        dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS, l_chain_pkt->hdr.net_id,
                                      l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id, &l_sync_chains, sizeof(l_sync_chains));
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
    memset(&a_ch_chain->request_net_id, 0, sizeof(a_ch_chain->request_net_id));
    memset(&a_ch_chain->request_cell_id, 0, sizeof(a_ch_chain->request_cell_id));
    memset(&a_ch_chain->request_chain_id, 0, sizeof(a_ch_chain->request_chain_id));
    memset(&a_ch_chain->request_last_ts, 0, sizeof(a_ch_chain->request_last_ts));
    DAP_DEL_Z(a_ch_chain->request_atom_iter);
}

bool s_process_gdb_iter(dap_stream_ch_t *a_ch)
{
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    dap_db_log_list_t *l_db_list = l_ch_chain->request_global_db_trs;
    dap_store_obj_pkt_t *l_pkt = (dap_store_obj_pkt_t *)l_ch_chain->db_iter->data;
    uint32_t l_pkt_size = sizeof(dap_store_obj_pkt_t) + l_pkt->data_size;
    log_it(L_INFO, "Send one global_db record packet len=%d (rest=%d/%d items)", l_pkt_size,
           dap_db_log_list_get_count_rest(l_db_list), dap_db_log_list_get_count(l_db_list));
    dap_stream_ch_chain_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB,
                                         l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                                         l_ch_chain->request_cell_id, l_pkt, l_pkt_size);
    dap_list_t *l_iter = dap_list_next(l_ch_chain->db_iter);
    if (l_iter) {
        l_ch_chain->db_iter = l_iter;
    } else {
        l_ch_chain->stats_request_gdb_processed++;
        l_ch_chain->db_iter = dap_list_first(l_ch_chain->db_iter);
        dap_list_free_full(l_ch_chain->db_iter, free);
        l_ch_chain->db_iter = NULL;
    }
    return true;
}

bool s_out_pkt_callback(dap_proc_thread_t *a_thread, void *a_arg)
{
    UNUSED(a_thread);
    dap_stream_ch_t *l_ch = (dap_stream_ch_t *)a_arg;
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);

    //log_it( L_DEBUG,"s_stream_ch_packet_out state=%d", l_ch_chain ? l_ch_chain->state : -1);
    //  log_it( L_DEBUG,"l_ch_chain %X", l_ch_chain );
    bool l_packet_out = false;
    switch (l_ch_chain->state) {

        case CHAIN_STATE_IDLE: {
            dap_stream_ch_chain_go_idle(l_ch_chain);
        } break;

        case CHAIN_STATE_SYNC_GLOBAL_DB: {
            if (l_ch_chain->db_iter) {
                l_packet_out = s_process_gdb_iter(l_ch);
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
                    l_packet_out = s_process_gdb_iter(l_ch);
                } else {
                    //log_it(L_DEBUG, "l_obj == 0, STOP");
                    // free log list
                    dap_db_log_list_delete(l_ch_chain->request_global_db_trs);
                    l_ch_chain->request_global_db_trs = NULL;
                    // last message
                    dap_stream_ch_chain_sync_request_t l_request = {};
                    dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain->request_net_id);
                    l_request.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
                    l_request.id_start = dap_db_log_get_last_id_remote(l_ch_chain->request.node_addr.uint64);
                    l_request.id_end = 0;

                    log_it( L_DEBUG,"Syncronized database:  last id %llu, items syncronyzed %llu ", l_request.id_start,
                            l_ch_chain->stats_request_gdb_processed );

                    dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                            l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                            l_ch_chain->request_cell_id, &l_request, sizeof(l_request));
                    l_packet_out = true;

                    if(l_ch_chain->callback_notify_packet_out)
                        l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                        NULL, 0, l_ch_chain->callback_notify_arg);
                    dap_stream_ch_chain_go_idle(l_ch_chain);
                }
            }
        } break;

        // Synchronize chains
        case CHAIN_STATE_SYNC_CHAINS: {
            //log_it(L_DEBUG, "CHAIN_STATE_SYNC_CHAINS");
            if (l_ch_chain->request_atom_iter->cur == NULL) { // All chains synced
                dap_stream_ch_chain_sync_request_t l_request = {};
                // last message
                dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS,
                                                     l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                                                     l_ch_chain->request_cell_id, &l_request, sizeof(l_request));
                l_packet_out = true;
                log_it( L_DEBUG,"Synced: %llu atoms processed", l_ch_chain->stats_request_atoms_processed);
                dap_stream_ch_chain_go_idle(l_ch_chain);
                if (l_ch_chain->callback_notify_packet_out)
                    l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS, NULL,
                                                           0, l_ch_chain->callback_notify_arg);
            } else { // Process one chain from l_ch_chain->request_atom_iter
                dap_stream_ch_chain_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN, l_ch_chain->request_net_id,
                                                     l_ch_chain->request_chain_id, l_ch_chain->request_cell_id,
                                                     l_ch_chain->request_atom_iter->cur, l_ch_chain->request_atom_iter->cur_size);
                l_packet_out = true;
                l_ch_chain->stats_request_atoms_processed++;
                // Then get next atom and populate new last
                l_ch_chain->request_atom_iter->chain->callback_atom_iter_get_next(l_ch_chain->request_atom_iter, NULL);
            }
        } break;
        default: break;
    }
    if (l_packet_out) {
        dap_stream_ch_set_ready_to_write_unsafe(l_ch, true);
    }
    dap_events_socket_assign_on_worker_mt(l_ch->stream->esocket, l_ch->stream_worker->worker);
    return true;
}

/**
 * @brief s_stream_ch_packet_out
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg)
{
    (void) a_arg;
    if (a_ch->stream->esocket->buf_out_size > DAP_EVENTS_SOCKET_BUF / 2) {
        return;
    }
    dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    if (l_ch_chain && l_ch_chain->state != CHAIN_STATE_IDLE) {
        dap_events_socket_remove_from_worker_unsafe(a_ch->stream->esocket, a_ch->stream_worker->worker);
        dap_proc_queue_add_callback(a_ch->stream_worker->worker->proc_queue, s_out_pkt_callback, a_ch);
    }
}
