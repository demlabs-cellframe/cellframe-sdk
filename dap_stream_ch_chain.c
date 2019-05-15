/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
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

#include "dap_common.h"
#include "dap_list.h"
#include "dap_config.h"
#include "dap_hash.h"

#include "dap_chain.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"

#include "dap_chain_global_db.h"
#include "dap_chain_global_db_hist.h"

#include "dap_stream.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"

#define LOG_TAG "dap_stream_ch_chain"



static void s_stream_ch_new(dap_stream_ch_t* a_ch , void* a_arg);
static void s_stream_ch_delete(dap_stream_ch_t* a_ch , void* a_arg);
static void s_stream_ch_packet_in(dap_stream_ch_t* a_ch , void* a_arg);
static void s_stream_ch_packet_out(dap_stream_ch_t* a_ch , void* a_arg);
/**
 * @brief dap_stream_ch_chain_init
 * @return
 */
int dap_stream_ch_chain_init()
{
    log_it(L_NOTICE,"Chain blocks and datums exchange channel initialized");
    dap_stream_ch_proc_add(dap_stream_ch_chain_get_id(),s_stream_ch_new,s_stream_ch_delete,s_stream_ch_packet_in,s_stream_ch_packet_out);

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
void s_stream_ch_new(dap_stream_ch_t* a_ch , void* a_arg)
{
    a_ch->internal=DAP_NEW_Z(dap_stream_ch_chain_t);
    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    pthread_mutex_init( &l_ch_chain->mutex,NULL);
}


/**
 * @brief s_stream_ch_delete
 * @param ch
 * @param arg
 */
void s_stream_ch_delete(dap_stream_ch_t* a_ch , void* a_arg)
{
    (void) a_arg;
    if (DAP_STREAM_CH_CHAIN(a_ch)->request_global_db_trs )
        dap_list_free_full(DAP_STREAM_CH_CHAIN(a_ch)->request_global_db_trs, (dap_callback_destroyed_t) free);
    pthread_mutex_destroy( &DAP_STREAM_CH_CHAIN(a_ch)->mutex);
}

/**
 * @brief s_stream_ch_packet_in
 * @param a_ch
 * @param a_arg
 */
void s_stream_ch_packet_in(dap_stream_ch_t* a_ch , void* a_arg)
{
    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    if ( l_ch_chain){
        dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
        dap_stream_ch_chain_pkt_t * l_chain_pkt =(dap_stream_ch_chain_pkt_t *) l_ch_pkt->data;
        size_t l_chain_pkt_data_size = l_ch_pkt->hdr.size - sizeof (l_chain_pkt->hdr);
        if( l_chain_pkt ){
            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id,  l_chain_pkt->hdr.chain_id);
            if ( l_chain ) {
                switch ( l_ch_pkt->hdr.type ) {
                    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS:{
                        if ( l_ch_chain->state != CHAIN_STATE_IDLE ){
                            log_it(L_INFO, "Can't process SYNC_CHAINS request because not in idle state");
                            dap_stream_ch_chain_pkt_write_error(a_ch,l_chain_pkt->hdr.net_id,
                                                                l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                                                "ERROR_STATE_NOT_IN_IDLE");
                        }else {
                            dap_chain_atom_ptr_t * l_lasts = NULL;
                            size_t l_lasts_size = 0;
                            dap_chain_atom_iter_t* l_iter = l_chain->callback_atom_iter_create(l_chain);
                            l_ch_chain->request_atom_iter = l_iter;
                            l_lasts = l_chain->callback_atom_iter_get_lasts(l_iter,&l_lasts_size);
                            for (size_t i=0; i< l_lasts_size; i++ ){
                                dap_chain_atom_item_t * l_item = NULL;
                                dap_chain_hash_fast_t l_atom_hash;
                                dap_hash_fast( l_lasts[i] , l_chain->callback_atom_get_size( l_lasts[i] ) ,
                                          &l_atom_hash);
                                HASH_FIND(hh, l_ch_chain->request_atoms_lasts, &l_atom_hash,sizeof(l_atom_hash),l_item );
                                if (l_item == NULL ) { // Not found, add new lasts
                                    l_item = DAP_NEW_Z(dap_chain_atom_item_t);
                                    l_item->atom = l_lasts[i];
                                    memcpy(&l_item->atom_hash,&l_atom_hash,sizeof (l_atom_hash) );
                                    HASH_ADD(hh,l_ch_chain->request_atoms_lasts, atom_hash,sizeof(l_atom_hash),l_item );
                                }
                                DAP_DELETE(l_lasts[i]);
                            }
                            DAP_DELETE(l_lasts);
                            DAP_DELETE(l_iter);
                        }
                        dap_stream_ch_set_ready_to_write(a_ch,true);
                    }break;
                    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB:{
                        if ( l_ch_chain->state != CHAIN_STATE_IDLE ){
                            log_it(L_INFO, "Can't process SYNC_GLOBAL_DB request because not in idle state");
                            dap_stream_ch_chain_pkt_write_error(a_ch,l_chain_pkt->hdr.net_id,
                                                                l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                                                "ERROR_STATE_NOT_IN_IDLE");
                            dap_stream_ch_set_ready_to_write(a_ch,true);
                            break;
                        }
                        // receive the latest global_db revision of the remote node -> go to send mode
                        if(l_chain_pkt_data_size == sizeof(dap_stream_ch_chain_sync_request_t)) {
                            dap_stream_ch_chain_sync_request_t * l_request = (dap_stream_ch_chain_sync_request_t *) l_chain_pkt->data;
                            memcpy(&l_ch_chain->request, l_request, l_chain_pkt_data_size );
                            // Get log diff
                            dap_list_t *l_list = dap_db_log_get_list((time_t) l_request->ts_start);
                            // Add it to outgoing list
                            l_list->next = l_ch_chain->request_global_db_trs;
                            l_ch_chain->request_global_db_trs = l_list;
                            l_ch_chain->state = CHAIN_STATE_SYNC_GLOBAL_DB;

                            log_it(L_INFO,
                                    "Get DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB tr_count=%d", dap_list_length(l_list));
                            // go to send data from list [in s_stream_ch_packet_out()]
                            // no data to send -> send one empty message DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB_SYNCED
                            dap_stream_ch_set_ready_to_write(a_ch, true);
                        }
                        else {
                            log_it(L_ERROR, "Get DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB session_id=%u bad request",
                                    a_ch->stream->session->id);
                            dap_stream_ch_chain_pkt_write_error(a_ch,l_chain_pkt->hdr.net_id,
                                                                l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                                                "ERROR_SYNC_GLOBAL_DB_REQUEST_BAD");
                            dap_stream_ch_set_ready_to_write(a_ch,true);
                        }
                    }break;
                    case DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN:{
                        // Expect atom element in
                        if (l_chain_pkt_data_size > 0 )
                            l_chain->callback_atom_add(l_chain, l_chain_pkt->data);
                        else{
                            log_it(L_WARNING,"Empty chain packet");
                            dap_stream_ch_chain_pkt_write_error(a_ch,l_chain_pkt->hdr.net_id,
                                                                l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                                                "ERROR_CHAIN_PACKET_EMPTY");
                            dap_stream_ch_set_ready_to_write(a_ch,true);
                        }
                    }break;
                    case DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB:{
                        log_it(L_INFO, "Get DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB data_size=%d", l_chain_pkt_data_size);
                        // get transaction and save it to global_db
                        if(l_chain_pkt_data_size > 0) {

                            //session_data_t *l_data = session_data_find(a_ch->stream->session->id);
                            size_t l_data_obj_count = 0;

                            // deserialize data
                            void *l_data_obj = dap_db_log_unpack((uint8_t*) l_chain_pkt->data, l_chain_pkt_data_size, &l_data_obj_count); // Parse data from dap_db_log_pack()
                            // save data to global_db
                            if(!dap_chain_global_db_obj_save(l_data_obj, l_data_obj_count)) {
                                log_it(L_ERROR, "Don't saved to global_db objs=0x%x count=%d", l_data_obj,
                                        l_data_obj_count);
                                dap_stream_ch_chain_pkt_write_error(a_ch,l_chain_pkt->hdr.net_id,
                                                                    l_chain_pkt->hdr.chain_id, l_chain_pkt->hdr.cell_id,
                                                                    "ERROR_GLOBAL_DB_INTERNAL_NOT_SAVED");
                                dap_stream_ch_set_ready_to_write(a_ch,true);

                            }else {
                                // TODO propagate changes
                                log_it(L_NOTICE,"!!!Added new GLOBAL_DB but not running sync action for others links. TODO.!!!");
                            }
                        }
                    }break;
                    default: log_it(L_INFO, "Get %s packet", c_dap_stream_ch_chain_pkt_type_str[l_ch_pkt->hdr.type ]);
                }
                if (l_ch_chain->notify_callback )
                    l_ch_chain->notify_callback(l_ch_chain, l_ch_pkt->hdr.type,l_chain_pkt,l_ch_pkt->hdr.size,
                                                l_ch_chain->notify_callback_arg);
            }
        }
    }
}
/**
 * @brief s_stream_ch_packet_out
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t* a_ch , void* a_arg)
{
    (void) a_arg;
    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);

    switch ( l_ch_chain->state ) {
        case CHAIN_STATE_IDLE:{
            dap_stream_ch_set_ready_to_write(a_ch, false);
        }break;
        case CHAIN_STATE_SYNC_ALL:
        case CHAIN_STATE_SYNC_GLOBAL_DB:{
            // Get log diff
            size_t l_data_size_out = 0;
            dap_list_t *l_list = l_ch_chain->request_global_db_trs;
            size_t len = dap_list_length(l_list);
            //printf("*len=%d\n", len);
            if(l_list) {
                size_t   l_item_size_out = 0;
                uint8_t *l_item = NULL;
                while(l_list && !l_item) {
                    l_item = dap_db_log_pack((dap_global_db_obj_t *) l_list->data, &l_item_size_out);
                    if(!l_item) {
                        // remove current item from list
                        dap_chain_global_db_obj_delete((dap_global_db_obj_t *) l_list->data);
                        l_list = dap_list_delete_link(l_list, l_list);
                    }
                }
                dap_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB,
                                              l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                                              l_ch_chain->request_cell_id, l_item, l_item_size_out) ;
                DAP_DELETE( l_item);
                // remove current item from list
                dap_chain_global_db_obj_delete((dap_global_db_obj_t *) l_list->data);

                l_list = dap_list_delete_link(l_list, l_list);
                l_ch_chain->request_global_db_trs = l_list;

            }else if ( l_ch_chain->state == CHAIN_STATE_SYNC_GLOBAL_DB){
            // last message
                dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB ,NULL,0);
                l_ch_chain->state = CHAIN_STATE_IDLE;
            }

        } if (l_ch_chain->state != CHAIN_STATE_SYNC_ALL ) break;

        // Syncronyze chains
        case CHAIN_STATE_SYNC_CHAINS:{
            dap_chain_t * l_chain = l_ch_chain->request_atom_iter->chain;
            dap_chain_atom_item_t * l_atom_item = NULL, * l_atom_item_tmp = NULL, *l_chains_lasts_new = NULL;
            if ( l_ch_chain->request_atoms_lasts == NULL) { // All chains synced
                dap_stream_ch_chain_pkt_write(a_ch, l_ch_chain->state == CHAIN_STATE_SYNC_CHAINS ?
                          DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS: DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL,
                          l_ch_chain->request_net_id, l_ch_chain->request_chain_id,
                          l_ch_chain->request_cell_id,NULL,0);
                l_ch_chain->state = CHAIN_STATE_IDLE;
            }
            // Process all chains lasts
            HASH_ITER(hh,l_ch_chain->request_atoms_lasts, l_atom_item, l_atom_item_tmp){
                dap_chain_atom_item_t * l_atom_item_proc = NULL;
                // Check if its processed already
                HASH_FIND(hh,l_ch_chain->request_atoms_processed, &l_atom_item->atom_hash,
                          sizeof ( l_atom_item->atom_hash),l_atom_item_proc);

                if ( l_atom_item_proc == NULL ){ // If not processed we first store it in special table
                    l_atom_item_proc = DAP_NEW_Z(dap_chain_atom_item_t);
                    l_atom_item_proc->atom = l_atom_item->atom;
                    memcpy(&l_atom_item_proc->atom_hash, &l_atom_item->atom_hash,sizeof (l_atom_item->atom_hash));
                    HASH_ADD(hh, l_ch_chain->request_atoms_processed,atom_hash,sizeof (l_atom_item->atom_hash),l_atom_item_proc );

                    // Then flush it out to the remote
                    size_t l_atom_size = l_chain->callback_atom_get_size(l_atom_item->atom);
                    dap_stream_ch_chain_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN, l_ch_chain->request_net_id,
                                                  l_ch_chain->request_chain_id, l_ch_chain->request_cell_id,
                                                  l_atom_item,l_atom_size);
                    // Then parse links and populate new lasts
                    size_t l_lasts_size = 0;
                    dap_chain_atom_ptr_t * l_links = NULL;
                    l_links =  l_chain->callback_atom_iter_get_links(l_atom_item->atom ,&l_lasts_size);
                    for (size_t i=0; i< l_lasts_size; i++ ){ // Find links
                        dap_chain_atom_item_t * l_link_item = NULL;
                        dap_chain_hash_fast_t l_link_hash;
                        dap_hash_fast( l_links[i] , l_chain->callback_atom_get_size( l_links[i] ) ,
                                  &l_link_hash);
                        // Check link in processed atims
                        HASH_FIND(hh, l_ch_chain->request_atoms_processed, &l_link_hash,sizeof(l_link_hash),l_link_item );
                        if (l_link_item == NULL ) { // Not found, add new lasts
                            l_link_item = DAP_NEW_Z(dap_chain_atom_item_t);
                            l_link_item->atom = l_links[i];
                            memcpy(&l_link_item->atom_hash,&l_link_hash,sizeof (l_link_hash) );
                            HASH_ADD(hh,l_chains_lasts_new, atom_hash,sizeof(l_link_hash),l_link_item );
                        }
                        DAP_DELETE(l_links[i]);
                    }
                    DAP_DELETE(l_links);

                }
                HASH_DEL(l_ch_chain->request_atoms_lasts,l_atom_item);
            }
            l_ch_chain->request_atoms_lasts = l_chains_lasts_new;


        }break;
    }
    if ( l_ch_chain->state == CHAIN_STATE_SYNC_ALL) {
        dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB ,NULL,0);
        dap_stream_ch_set_ready_to_write(a_ch, true);
        l_ch_chain->state = CHAIN_STATE_IDLE;
    }
}
