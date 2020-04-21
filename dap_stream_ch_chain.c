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

#include "dap_chain.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"
#include "dap_chain_cell.h"

#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"

#include "dap_stream.h"
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

/**
 * @brief s_stream_ch_packet_in
 * @param a_ch
 * @param a_arg
 */
void s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg)
{
    //static char *s_net_name = NULL;
    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    if(l_ch_chain) {
        dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
        dap_stream_ch_chain_pkt_t * l_chain_pkt = (dap_stream_ch_chain_pkt_t *) l_ch_pkt->data;
        size_t l_chain_pkt_data_size = l_ch_pkt->hdr.size - sizeof(l_chain_pkt->hdr);
        if(l_chain_pkt) {
            switch (l_ch_pkt->hdr.type) {
            case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL: {
                log_it(L_INFO, "In:  SYNCED_ALL pkt");
            }
                break;
            case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB: {
                log_it(L_INFO, "In:  SYNCED_GLOBAL_DB pkt");
                /*if(s_net_name) {
                 DAP_DELETE(s_net_name);
                 s_net_name = NULL; //"kelvin-testnet"
                 }*/
            }
                break;
            case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB_GROUP: {
                log_it(L_INFO, "In:  SYNCED_GLOBAL_DB_GROUP pkt");
                /*if(s_net_name) {
                 DAP_DELETE(s_net_name);
                 s_net_name = NULL; //"kelvin-testnet"
                 }*/
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
                    } else {
                        // fill ids
                        if(l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t)) {
                            dap_stream_ch_chain_sync_request_t * l_request =
                                    (dap_stream_ch_chain_sync_request_t *) l_chain_pkt->data;
                            memcpy(&l_ch_chain->request, l_request, l_chain_pkt_data_size);
                            memcpy(&l_ch_chain->request_cell_id, &l_chain_pkt->hdr.cell_id,
                                    sizeof(dap_chain_cell_id_t));
                            memcpy(&l_ch_chain->request_net_id, &l_chain_pkt->hdr.net_id, sizeof(dap_chain_net_id_t));
                            memcpy(&l_ch_chain->request_chain_id, &l_chain_pkt->hdr.chain_id, sizeof(dap_chain_id_t));
                        }

                        dap_chain_atom_ptr_t * l_lasts = NULL;
                        size_t l_lasts_size = 0;
                        dap_chain_atom_iter_t* l_iter = l_chain->callback_atom_iter_create(l_chain);
                        l_ch_chain->request_atom_iter = l_iter;
                        l_lasts = l_chain->callback_atom_iter_get_lasts(l_iter, &l_lasts_size);
                        if(l_lasts) {
                            for(size_t i = 0; i < l_lasts_size; i++) {
                                dap_chain_atom_item_t * l_item = NULL;
                                dap_chain_hash_fast_t l_atom_hash;
                                dap_hash_fast(l_lasts[i], l_chain->callback_atom_get_size(l_lasts[i]),
                                        &l_atom_hash);
                                HASH_FIND(hh, l_ch_chain->request_atoms_lasts, &l_atom_hash, sizeof(l_atom_hash),
                                        l_item);
                                if(l_item == NULL) { // Not found, add new lasts
                                    l_item = DAP_NEW_Z(dap_chain_atom_item_t);
                                    l_item->atom = l_lasts[i];
                                    memcpy(&l_item->atom_hash, &l_atom_hash, sizeof(l_atom_hash));
                                    HASH_ADD(hh, l_ch_chain->request_atoms_lasts, atom_hash, sizeof(l_atom_hash),
                                            l_item);
                                }
                                //else
                                //    DAP_DELETE(l_lasts[i]);
                            }
                            // first packet
                            l_ch_chain->state = CHAIN_STATE_SYNC_CHAINS;
                            dap_chain_node_addr_t l_node_addr = { 0 };
                            dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain->request_net_id);
                            l_node_addr.uint64 = l_net ? dap_db_get_cur_node_addr(l_net->pub.name) : 0;
                            dap_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN,
                                    l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                                    l_ch_chain->request_cell_id, &l_node_addr, sizeof(dap_chain_node_addr_t));
                        }
                        else {
                            // last packet
                            dap_stream_ch_chain_sync_request_t l_request = { { 0 } };
                            l_request.id_start = 0;//dap_db_log_get_last_id_remote(l_ch_chain->request.node_addr.uint64);
                            dap_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS,
                                    l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                                    l_ch_chain->request_cell_id, &l_request, sizeof(l_request));
                            l_ch_chain->state = CHAIN_STATE_IDLE;
                        }

                        DAP_DELETE(l_lasts);
                        DAP_DELETE(l_iter);
                    }
                    dap_stream_ch_set_ready_to_write(a_ch, true);
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
                    dap_stream_ch_set_ready_to_write(a_ch, true);
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

                    // Get log diff
                    l_ch_chain->request_last_ts = dap_db_log_get_last_id();
                    //log_it(L_DEBUG, "Requested transactions %llu:%llu", l_request->id_start,
                    //        (uint64_t ) l_ch_chain->request_last_ts);
                    //dap_list_t *l_list = dap_db_log_get_list(l_request->id_start + 1);
                    uint64_t l_start_item = l_request->id_start;
                    // If the current global_db has been truncated, but the remote node has not known this
                    if(l_request->id_start > l_ch_chain->request_last_ts) {
                        l_start_item = 0;
                    }
                    dap_chain_net_t *l_net = dap_chain_net_by_id(l_chain_pkt->hdr.net_id);
                    dap_list_t *l_add_groups = dap_chain_net_get_add_gdb_group(l_net, l_request->node_addr);
                    dap_db_log_list_t *l_db_log = dap_db_log_list_start(l_start_item + 1, l_add_groups);
                    if(l_db_log) {
                        //log_it(L_DEBUG, "Start getting items %u:%u", l_request->id_start + 1,l_db_log->items_number);//dap_list_length(l_list));
                        // Add it to outgoing list
                        l_ch_chain->request_global_db_trs = l_db_log;//l_list;
                        //dap_list_t *l_last = dap_list_last(l_list);
                        //if(l_last)
                        //    l_last->next = l_ch_chain->request_global_db_trs;
                        //l_ch_chain->request_global_db_trs = l_list;
                        l_ch_chain->state = CHAIN_STATE_SYNC_GLOBAL_DB;

                        dap_chain_node_addr_t l_node_addr = { 0 };
                        dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain->request_net_id);
                        l_node_addr.uint64 = l_net ? dap_db_get_cur_node_addr(l_net->pub.name) : 0;
                        dap_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB,
                                l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                                l_ch_chain->request_cell_id, &l_node_addr, sizeof(dap_chain_node_addr_t));

                    } else {
                        dap_chain_node_addr_t l_node_addr = { 0 };
                        dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain->request_net_id);
                        l_node_addr.uint64 = l_net ? dap_db_get_cur_node_addr(l_net->pub.name) : 0;
                        dap_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB,
                                l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                                l_ch_chain->request_cell_id, &l_node_addr, sizeof(dap_chain_node_addr_t));

                        dap_stream_ch_chain_sync_request_t l_request = { { 0 } };
                        //log_it(L_DEBUG, "No items to sync from %u", l_request->id_start + 1);
                        l_request.node_addr.uint64 = l_net ? dap_db_get_cur_node_addr(l_net->pub.name) : 0;
                        l_request.id_start = dap_db_log_get_last_id_remote(l_ch_chain->request.node_addr.uint64);
                        dap_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                                l_ch_chain->request_cell_id, &l_request, sizeof(l_request));
//                            dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB ,&l_request,
//                                                    sizeof (l_request));
                        l_ch_chain->state = CHAIN_STATE_IDLE;
                        if(l_ch_chain->callback_notify_packet_out)
                            l_ch_chain->callback_notify_packet_out(l_ch_chain,
                            DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                            NULL, 0, l_ch_chain->callback_notify_arg);
                    }
                    //log_it(L_INFO, "Prepared %u items for sync", l_db_log->items_number - l_request->id_start);//dap_list_length(l_ch_chain->request_global_db_trs));
                    // go to send data from list [in s_stream_ch_packet_out()]
                    // no data to send -> send one empty message DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB_SYNCED
                    dap_stream_ch_set_ready_to_write(a_ch, true);
                }
                else {
                    log_it(L_ERROR, "Get DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB session_id=%u bad request",
                            a_ch->stream->session->id);
                    dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                            l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                            "ERROR_SYNC_GLOBAL_DB_REQUEST_BAD");
                    dap_stream_ch_set_ready_to_write(a_ch, true);
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
                log_it(L_INFO, "In: CHAIN pkt");
                dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
                if(l_chain) {
                    // Expect atom element in
                    if(l_chain_pkt_data_size > 0) {
                        if(l_chain->callback_atom_add(l_chain, l_chain_pkt->data) == 0 &&
                                dap_chain_has_file_store(l_chain)) {
                            // append to file
                            dap_chain_cell_id_t l_cell_id;
                            l_cell_id.uint64 = l_chain_pkt->hdr.cell_id.uint64;
                            dap_chain_cell_t *l_cell = dap_chain_cell_create_fill(l_chain, l_cell_id);
                            // add one atom only
                            int l_res = dap_chain_cell_file_append(l_cell, l_chain_pkt->data, l_chain_pkt_data_size);
                            // rewrite all file
                            //l_res = dap_chain_cell_file_update(l_cell);
                            if(!l_cell || l_res < 0) {
                                log_it(L_ERROR, "Can't save event 0x%x to the file '%s'", l_chain_pkt->data,
                                        l_cell ? l_cell->file_storage_path : "[null]");
                            }
                            // delete cell and close file
                            dap_chain_cell_delete(l_cell);
                        }
                    } else {
                        log_it(L_WARNING, "Empty chain packet");
                        dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                                l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                "ERROR_CHAIN_PACKET_EMPTY");
                        dap_stream_ch_set_ready_to_write(a_ch, true);
                    }
                }
            }
                break;
                // first packet of data with source node address
            case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB: {
                log_it(L_INFO, "In: FIRST_GLOBAL_DB data_size=%d", l_chain_pkt_data_size);
                if(l_chain_pkt_data_size == sizeof(dap_chain_node_addr_t))
                    memcpy(&l_ch_chain->request.node_addr, l_chain_pkt->data, l_chain_pkt_data_size);
                //memcpy(&l_ch_chain->request_cell_id, &l_chain_pkt->hdr.cell_id, sizeof(dap_chain_cell_id_t));
                //memcpy(&l_ch_chain->request_net_id, &l_chain_pkt->hdr.net_id, sizeof(dap_chain_net_id_t));
                //memcpy(&l_ch_chain->request_chain_id, &l_chain_pkt->hdr.chain_id, sizeof(dap_chain_id_t));
            }
                break;
            case DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB: {
                log_it(L_INFO, "In: GLOBAL_DB data_size=%d", l_chain_pkt_data_size);
                // get transaction and save it to global_db
                if(l_chain_pkt_data_size > 0) {

                    //session_data_t *l_data = session_data_find(a_ch->stream->session->id);
                    size_t l_data_obj_count = 0;

                    // deserialize data
                    dap_store_obj_t *l_store_obj = dap_db_log_unpack((uint8_t*) l_chain_pkt->data,
                            l_chain_pkt_data_size, &l_data_obj_count); // Parse data from dap_db_log_pack()
                    //dap_store_obj_t * l_store_obj_reversed = NULL;
                    //if ( dap_log_level_get()== L_DEBUG  )
                    //if ( l_data_obj_count && l_store_obj )
                    //   l_store_obj_reversed = DAP_NEW_Z_SIZE(dap_store_obj_t,l_data_obj_count+1);


//                    log_it(L_INFO, "In: l_data_obj_count = %d", l_data_obj_count );

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
                                l_store_obj[i].key,
                                l_ts_str,
                                l_store_obj[i].value_len);*/

                        // apply received transaction
                        dap_chain_t *l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id, l_chain_pkt->hdr.chain_id);
                        if(l_chain) {
                            if(l_chain->callback_datums_pool_proc_with_group)
                                l_chain->callback_datums_pool_proc_with_group(l_chain,
                                        (dap_chain_datum_t**) &(l_store_obj->value), 1,
                                        l_store_obj[i].group);
                        }
                        /*else {
                         // read net_name
                         if(!s_net_name)
                         {
                         static dap_config_t *l_cfg = NULL;
                         if((l_cfg = dap_config_open("network/default")) == NULL) {
                         log_it(L_ERROR, "Can't open default network config");
                         } else {
                         s_net_name = dap_strdup(dap_config_get_item_str(l_cfg, "general", "name"));
                         dap_config_close(l_cfg);
                         }
                         }
                         // add datum in ledger if necessary
                         {
                         dap_chain_net_t *l_net = dap_chain_net_by_name(s_net_name);
                         dap_chain_t * l_chain;
                         if(l_net) {
                         DL_FOREACH(l_net->pub.chains, l_chain)
                         {
                         const char *l_chain_name = l_chain->name; //l_chain_name = dap_strdup("gdb");
                         dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_name);
                         //const char *l_group_name = "chain-gdb.kelvin-testnet.chain-F00000000000000F";//dap_chain_gdb_get_group(l_chain);
                         if(l_chain->callback_datums_pool_proc_with_group)
                         l_chain->callback_datums_pool_proc_with_group(l_chain,
                         (dap_chain_datum_t**) &(l_store_obj->value), 1,
                         l_store_obj[i].group);
                         }
                         }
                         }
                         }*/
                        // save data to global_db
                        if(!dap_chain_global_db_obj_save(l_obj, 1)) {
                            dap_stream_ch_chain_pkt_write_error(a_ch, l_chain_pkt->hdr.net_id,
                                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                    "ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED");
                            dap_stream_ch_set_ready_to_write(a_ch, true);
                        } else {
                            // If request was from defined node_addr we update its state
                            if(l_ch_chain->request.node_addr.uint64) {
                                dap_db_log_set_last_id_remote(l_ch_chain->request.node_addr.uint64,
                                        l_obj->id);
                            }
                            //log_it(L_DEBUG, "Added new GLOBAL_DB history pack");
                        }
                    }
                    if(l_store_obj)
                        dap_store_obj_free(l_store_obj, l_data_obj_count);

                } else {
                    log_it(L_WARNING, "Packet with GLOBAL_DB atom has zero body size");
                }
            }
                break;
                default:{
                    //log_it(L_INFO, "Get %s packet", c_dap_stream_ch_chain_pkt_type_str[l_ch_pkt->hdr.type]);
                }
            }
            if(l_ch_chain->callback_notify_packet_in)
                l_ch_chain->callback_notify_packet_in(l_ch_chain, l_ch_pkt->hdr.type, l_chain_pkt,
                        l_chain_pkt_data_size, //l_ch_pkt->hdr.size,
                        l_ch_chain->callback_notify_arg);
        }
    }
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

    dap_chain_atom_item_t *l_atom_item = NULL, *l_atom_item_tmp = NULL;

    HASH_ITER( hh,a_ch_chain->request_atoms_lasts, l_atom_item, l_atom_item_tmp)
        HASH_DEL(a_ch_chain->request_atoms_lasts, l_atom_item);

    HASH_ITER( hh, a_ch_chain->request_atoms_processed, l_atom_item, l_atom_item_tmp )
        HASH_DEL(a_ch_chain->request_atoms_processed, l_atom_item);
    dap_stream_ch_set_ready_to_write(a_ch_chain->ch, false);

}

/**
 * @brief s_stream_ch_packet_out
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg)
{
    (void) a_arg;

    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);

    //log_it( L_DEBUG,"s_stream_ch_packet_out state=%d", l_ch_chain ? l_ch_chain->state : -1);
    //  log_it( L_DEBUG,"l_ch_chain %X", l_ch_chain );

    switch (l_ch_chain->state) {
        case CHAIN_STATE_IDLE: {
            dap_stream_ch_chain_go_idle(l_ch_chain);
        } break;

        case CHAIN_STATE_SYNC_ALL:

        case CHAIN_STATE_SYNC_GLOBAL_DB: {

            // Get log diff
            //size_t l_data_size_out = 0;

            dap_db_log_list_t *l_db_list = l_ch_chain->request_global_db_trs; //dap_list_last( l_ch_chain->request_global_db_trs );
            dap_global_db_obj_t *l_obj = dap_db_log_list_get(l_db_list);

            if (1) {
                //dap_list_t *l_list = l_ch_chain->request_global_db_trs; //dap_list_last( l_ch_chain->request_global_db_trs );
                bool l_is_stop = true; //l_list ? false : true;
                while(l_obj) {

                    size_t l_items_total = dap_db_log_list_get_count(l_db_list);
                    size_t l_items_rest = dap_db_log_list_get_count_rest(l_db_list);

                    size_t l_item_size_out = 0;
                    uint8_t *l_item = dap_db_log_pack(l_obj, &l_item_size_out);
                    // Item not found, maybe it has deleted? Then go to the next item
                    if(!l_item || !l_item_size_out) {
                        //log_it(L_WARNING, "Log pack returned NULL??? data=0x%x (nothing to send) (rest=%d records)", l_obj,
                         //       l_items_rest);
                        l_item_size_out = 0;
                        //dap_stream_ch_set_ready_to_write(a_ch, false);

                        // go to next item
                        l_obj = dap_db_log_list_get(l_db_list);
                        //if(l_obj)
                        //    continue;
                        // stop global_db sync
                        //else
                        //    break;
                    }
                    else {
                        //log_it(L_INFO, "Send one global_db record data=0x%x len=%d (rest=%d/%d items)", l_item, l_item_size_out,
                        //        l_items_rest, l_items_total);
                        dap_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB,
                                l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                                l_ch_chain->request_cell_id, l_item, l_item_size_out);
                        l_ch_chain->stats_request_gdb_processed++;
                        //dap_stream_ch_set_ready_to_write(a_ch, true);
                        //sleep(1);

                        DAP_DELETE(l_item);
                        // sent the record, another will be sent
                        l_is_stop = false;
                        break;
                    }
                    // remove current item from list and go to next item
                    /*dap_chain_global_db_obj_delete((dap_global_db_obj_t *) l_list->data);
                    l_ch_chain->request_global_db_trs = dap_list_delete_link(l_ch_chain->request_global_db_trs, l_list);
                    // nothing was sent
                    if(!l_item_size_out) {
                        l_list = l_ch_chain->request_global_db_trs;
                        // go to next item
                        if(l_list)
                            continue;
                        // stop global_db sync
                        else
                            break;
                    }*/
                }

                if(l_is_stop){
                    //log_it(L_DEBUG, "l_obj == 0, STOP");
                    // If we don't need to send chains after
//                    if(l_ch_chain->state != CHAIN_STATE_SYNC_ALL){
//                        dap_stream_ch_chain_go_idle(l_ch_chain);
//                    }else if(l_ch_chain->state == CHAIN_STATE_SYNC_GLOBAL_DB)
                    {
                        // free log list
                        l_ch_chain->request_global_db_trs = NULL;
                        dap_db_log_list_delete(l_db_list);

                        // last message

                        dap_stream_ch_chain_sync_request_t l_request = { { 0 } };
                        dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain->request_net_id);
                        l_request.node_addr.uint64 = l_net ? dap_db_get_cur_node_addr(l_net->pub.name) : 0;
                        l_request.id_start = dap_db_log_get_last_id_remote(l_ch_chain->request.node_addr.uint64);
                        l_request.id_end = 0;

                        log_it( L_DEBUG,"Syncronized database:  last id %llu, items syncronyzed %llu ", l_request.id_start,
                                l_ch_chain->stats_request_gdb_processed );

                        dap_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                                l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                                l_ch_chain->request_cell_id, &l_request, sizeof(l_request));

                        if(l_ch_chain->callback_notify_packet_out)
                            l_ch_chain->callback_notify_packet_out(l_ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB,
                            NULL, 0, l_ch_chain->callback_notify_arg);

                        if(l_ch_chain->state != CHAIN_STATE_SYNC_ALL)
                            dap_stream_ch_chain_go_idle(l_ch_chain);
                    }
                }
            }

        }
        if(l_ch_chain->state != CHAIN_STATE_SYNC_ALL)
            break;

            // Synchronize chains
        case CHAIN_STATE_SYNC_CHAINS: {
            log_it(L_DEBUG, "CHAIN_STATE_SYNC_CHAINS");
            dap_chain_t * l_chain = dap_chain_find_by_id(l_ch_chain->request_net_id, l_ch_chain->request_chain_id);
            /*
            // alternative way to get l_chain
            if(!l_ch_chain->request_atom_iter) {
                log_it(L_ERROR, "CHAIN_STATE_SYNC_CHAINS not ready to send chains");
                l_ch_chain->state = CHAIN_STATE_IDLE;
                break;
            }
            //dap_chain_atom_iter_t* l_iter = l_chain->callback_atom_iter_create(l_chain);
            dap_chain_t * l_chain = l_ch_chain->request_atom_iter->chain;
            */

            dap_chain_atom_item_t * l_atom_item = NULL, *l_atom_item_tmp = NULL;//, *l_chains_lasts_new = NULL;
            if(l_ch_chain->request_atoms_lasts == NULL) { // All chains synced
                dap_stream_ch_chain_sync_request_t l_request = { { 0 } };
                uint8_t l_send_pkt_type = l_ch_chain->state == CHAIN_STATE_SYNC_CHAINS ?
                        DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS :
                        DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL;
                // last message
                dap_stream_ch_chain_pkt_write(a_ch,
                        l_send_pkt_type,
                        l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                        l_ch_chain->request_cell_id, &l_request, sizeof(l_request));
                log_it( L_DEBUG,"Synced: %llu atoms processed",
                                        l_ch_chain->stats_request_atoms_processed);
                dap_stream_ch_chain_go_idle(l_ch_chain);

                if(l_ch_chain->callback_notify_packet_out)
                    l_ch_chain->callback_notify_packet_out(l_ch_chain, l_send_pkt_type, NULL, 0, l_ch_chain->callback_notify_arg);
            }else{ // Process one chain from l_ch_chain->request_atoms_lasts
                HASH_ITER(hh,l_ch_chain->request_atoms_lasts, l_atom_item, l_atom_item_tmp) {
                    dap_chain_atom_item_t * l_atom_item_proc = NULL;
                    // Check if its processed already
                    HASH_FIND(hh, l_ch_chain->request_atoms_processed, &l_atom_item->atom_hash,
                            sizeof(l_atom_item->atom_hash), l_atom_item_proc);

                    if(l_atom_item_proc == NULL) { // If not processed we first store it in special table
                        l_atom_item_proc = DAP_NEW_Z(dap_chain_atom_item_t);
                        l_atom_item_proc->atom = l_atom_item->atom;
                        memcpy(&l_atom_item_proc->atom_hash, &l_atom_item->atom_hash, sizeof(l_atom_item->atom_hash));
                        HASH_ADD(hh, l_ch_chain->request_atoms_processed, atom_hash, sizeof(l_atom_item->atom_hash),
                                l_atom_item_proc);

                        // Then flush it out to the remote
                        size_t l_atom_size = l_chain->callback_atom_get_size(l_atom_item->atom);
                        dap_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN, l_ch_chain->request_net_id,
                                l_ch_chain->request_chain_id, l_ch_chain->request_cell_id,
                                l_atom_item->atom, l_atom_size);
                        l_ch_chain->stats_request_atoms_processed++;
                        // Then parse links and populate new lasts
                        size_t l_lasts_size = 0;
                        dap_chain_atom_ptr_t * l_links = NULL;

                        dap_chain_atom_iter_t* l_iter = l_chain->callback_atom_iter_create_from(l_chain, l_atom_item->atom);
                        l_links = l_chain->callback_atom_iter_get_links(l_iter, &l_lasts_size);
                        //DAP_DELETE(l_atom_item->atom);
                        DAP_DELETE(l_iter);
                        //l_links = l_chain->callback_atom_iter_get_links(l_atom_item->atom, &l_lasts_size);

                        for(size_t i = 0; i < l_lasts_size; i++) { // Find links
                            dap_chain_atom_item_t * l_link_item = NULL;
                            dap_chain_hash_fast_t l_link_hash;
                            dap_hash_fast(l_links[i], l_chain->callback_atom_get_size(l_links[i]),
                                    &l_link_hash);
                            // Check link in processed atims
                            HASH_FIND(hh, l_ch_chain->request_atoms_processed, &l_link_hash, sizeof(l_link_hash), l_link_item);
                            if(l_link_item == NULL) { // Not found, add new lasts
                                l_link_item = DAP_NEW_Z(dap_chain_atom_item_t);
                                l_link_item->atom = l_links[i];// do not use memory cause it will be deleted
                                memcpy(&l_link_item->atom_hash, &l_link_hash, sizeof(l_link_hash));
                                //HASH_ADD(hh, l_chains_lasts_new, atom_hash, sizeof(l_link_hash), l_link_item);
                                HASH_ADD(hh, l_ch_chain->request_atoms_lasts, atom_hash, sizeof(l_link_hash), l_link_item);
                            }
                            //else
                            //    DAP_DELETE(l_links[i]);
                        }
                        DAP_DELETE(l_links);
                        HASH_DEL(l_ch_chain->request_atoms_lasts, l_atom_item);
                        break;
                    }
                    else{
                        HASH_DEL(l_ch_chain->request_atoms_lasts, l_atom_item);
                    }
                }
            }
            //assert(l_ch_chain->request_atoms_lasts == NULL);
            //l_ch_chain->request_atoms_lasts = l_chains_lasts_new;
        }
        break;

    }

}
