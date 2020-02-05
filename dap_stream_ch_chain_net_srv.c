/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2019
* All rights reserved.

This file is part of CellFrame SDK the open source project

CellFrame SDK is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CellFrame SDK is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "dap_common.h"

#include "dap_chain.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_datum_tx_out.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_chain_mempool.h"

#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_stream_session.h"


#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_stream_ch_chain_net_srv_pkt.h"

#include "dap_stream_ch_proc.h"

#define LOG_TAG "dap_stream_ch_chain_net_srv"

typedef struct dap_stream_ch_chain_net_srv {
    pthread_mutex_t mutex;
} dap_stream_ch_chain_net_srv_t;

#define DAP_STREAM_CH_CHAIN_NET_SRV(a) ((dap_stream_ch_chain_net_srv_t *) ((a)->internal) )

static void s_stream_ch_new(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_delete(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_packet_in(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_packet_out(dap_stream_ch_t* ch , void* arg);


/**
 * @brief dap_stream_ch_chain_net_init
 * @return
 */
int dap_stream_ch_chain_net_srv_init(void)
{
    log_it(L_NOTICE,"Chain network services channel initialized");
    dap_stream_ch_proc_add('R',s_stream_ch_new,s_stream_ch_delete,s_stream_ch_packet_in,s_stream_ch_packet_out);

    return 0;
}

/**
 * @brief dap_stream_ch_chain_deinit
 */
void dap_stream_ch_chain_net_srv_deinit(void)
{

}

/**
 * @brief s_stream_ch_new
 * @param a_ch
 * @param arg
 */
void s_stream_ch_new(dap_stream_ch_t* a_ch , void* arg)
{
    (void ) arg;
    a_ch->internal=DAP_NEW_Z(dap_stream_ch_chain_net_srv_t);
    dap_stream_ch_chain_net_srv_t * l_ch_chain_net_srv = DAP_STREAM_CH_CHAIN_NET_SRV(a_ch);
    pthread_mutex_init( &l_ch_chain_net_srv->mutex,NULL);
    if (a_ch->stream->session->_inheritor == NULL && a_ch->stream->session != NULL)
        dap_chain_net_srv_stream_session_create( a_ch->stream->session );
    else if ( a_ch->stream->session == NULL)
        log_it( L_ERROR, "No session at all!");
    else
        log_it(L_ERROR, "Session inheritor is already present!");
}


/**
 * @brief s_stream_ch_delete
 * @param ch
 * @param arg
 */
void s_stream_ch_delete(dap_stream_ch_t* a_ch , void* a_arg)
{
    (void) a_ch;
    (void) a_arg;
    log_it(L_DEBUG, "Stream ch chain net srv delete");
}

/**
 * @brief s_stream_ch_packet_in
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_in(dap_stream_ch_t* a_ch , void* a_arg)
{
    dap_stream_ch_chain_net_srv_t * l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET_SRV(a_ch);
    dap_stream_ch_pkt_t *l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg; // chain packet
    dap_chain_net_srv_stream_session_t * l_srv_session = a_ch && a_ch->stream && a_ch->stream->session ?
                                                                a_ch->stream->session->_inheritor : NULL;
    if ( ! l_srv_session ){
        log_it( L_ERROR, "Not defined service session, switching off packet input process");
        dap_stream_ch_set_ready_to_read(a_ch, false);
        return;
    }
    dap_stream_ch_chain_net_srv_pkt_error_t l_err={0};
    if(l_ch_pkt ) {
        switch (l_ch_pkt->hdr.type) {
            case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST:{
                if (l_ch_pkt->hdr.size < sizeof(dap_stream_ch_chain_net_srv_pkt_request_hdr_t) ){
                    log_it( L_WARNING, "Wrong request size, less than minimum");
                    break;
                }
                // Parse the request
                dap_stream_ch_chain_net_srv_pkt_request_t * l_request =(dap_stream_ch_chain_net_srv_pkt_request_t *) l_ch_pkt->data;
                //size_t l_request_size = l_ch_pkt->hdr.size;
                dap_chain_net_srv_t * l_srv = dap_chain_net_srv_get( l_request->hdr.srv_uid );
                dap_chain_net_t * l_net = dap_chain_net_by_id( l_request->hdr.net_id );

                l_err.net_id.uint64 = l_request->hdr.net_id.uint64;
                l_err.srv_uid.uint64 = l_request->hdr.srv_uid.uint64;

                if ( ! l_net ) // Network not found
                    l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_NOT_FOUND;

                if ( ! l_srv ) // Service not found
                    l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_NOT_FOUND;

                if ( l_err.code ){
                    dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                    if (l_srv->callback_response_error)
                        l_srv->callback_response_error(l_srv,0,NULL,&l_err,sizeof (l_err) );
                    break;
                }

                dap_ledger_t * l_ledger = dap_chain_ledger_by_net_name( l_net->pub.name);
                dap_chain_datum_tx_t * l_tx = NULL;
                dap_chain_tx_out_cond_t * l_tx_out_cond = NULL;
                if (l_srv->pricelist ){ // Is present pricelist, not free service

                    if ( !l_ledger ){ // No ledger
                        log_it( L_WARNING, "No Ledger");
                        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_NO_LEDGER ;
                        dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                        if (l_srv->callback_response_error)
                                l_srv->callback_response_error(l_srv,0,NULL,&l_err,sizeof (l_err) );
                        break;
                    }

                    l_tx = dap_chain_ledger_tx_find_by_hash( l_ledger,& l_request->hdr.tx_cond );
                    if ( ! l_tx ){ // No tx cond transaction
                        log_it( L_WARNING, "No tx cond transaction");
                        /// TODO Add tx cond treshold and ability to provide service before the transaction comes from CDB
                        ///
                        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND ;
                        dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                        if (l_srv->callback_response_error)
                                l_srv->callback_response_error(l_srv,0,NULL,&l_err,sizeof (l_err) );
                        break;
                    }
                    int l_tx_out_cond_size =0;
                    l_tx_out_cond = (dap_chain_tx_out_cond_t *)
                            dap_chain_datum_tx_item_get(l_tx, NULL, TX_ITEM_TYPE_OUT_COND, &l_tx_out_cond_size );

                    if ( ! l_tx_out_cond ) { // No conditioned output
                        log_it( L_WARNING, "No conditioned output");

                        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_COND_OUT ;
                        dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                        if (l_srv->callback_response_error)
                                l_srv->callback_response_error(l_srv,0,NULL,&l_err,sizeof (l_err) );
                        break;
                    }

                    // Check cond output if it equesl or not to request
                    if ( l_tx_out_cond->subtype.srv_pay.header.srv_uid.uint64 != l_request->hdr.srv_uid.uint64 ){
                        log_it( L_WARNING, "Wrong service uid in request, tx expect to close its output with 0x%016lX",
                                l_tx_out_cond->subtype.srv_pay.header.srv_uid );
                        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_WRONG_SRV_UID  ;
                        dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                        if (l_srv->callback_response_error)
                                l_srv->callback_response_error(l_srv,0,NULL,&l_err,sizeof (l_err) );
                        break;
                    }
                }
                dap_chain_net_srv_usage_t * l_usage = dap_chain_net_srv_usage_add( l_srv_session,
                                                                                                       l_net,l_srv );
                if ( !l_usage ){ // Usage can't add
                    log_it( L_WARNING, "Usage can't add");
                    l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_USAGE_CANT_ADD;
                    dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                    if (l_srv->callback_response_error)
                            l_srv->callback_response_error(l_srv,0,NULL,&l_err,sizeof (l_err) );
                    break;
                }

                l_err.usage_id = l_usage->id;

                // Create one client
                l_usage->clients = DAP_NEW_Z( dap_chain_net_srv_client_t);
                l_usage->clients->ch = a_ch;
                l_usage->clients->ts_created = time(NULL);
                l_usage->tx_cond = l_tx;
                memcpy(&l_usage->tx_cond_hash, &l_request->hdr.tx_cond,sizeof (l_usage->tx_cond_hash));
                l_usage->ts_created = time(NULL);

                dap_chain_net_srv_price_t * l_price = NULL;
                dap_chain_datum_tx_receipt_t * l_receipt = NULL;
                const char * l_ticker = NULL;
                if (l_srv->pricelist ){
                    l_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_request->hdr.tx_cond );
                    dap_stpcpy(l_usage->token_ticker, l_ticker);

                    dap_chain_net_srv_price_t *l_price_tmp;
                    DL_FOREACH(l_srv->pricelist, l_price_tmp) {
                        if (l_price_tmp->net->pub.id.uint64                 == l_request->hdr.net_id.uint64
                            && dap_strcmp(l_price_tmp->token, l_ticker)     == 0
                            && l_price_tmp->units_uid.enm                   == l_tx_out_cond->subtype.srv_pay.header.unit.enm
                            )//&& (l_price_tmp->value_datoshi/l_price_tmp->units)  < l_tx_out_cond->subtype.srv_pay.header.unit_price_max_datoshi)
                        {
                            l_price = l_price_tmp;
                            break;
                        }
                    }
                    if ( !l_price ) {
                        log_it( L_WARNING, "Request can't be processed because no acceptable price in pricelist for token %s in network %s",
                                l_ticker, l_net->pub.name );
                        dap_chain_net_srv_usage_delete(l_srv_session, l_usage);
                        l_err.code =DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ACCEPT_TOKEN;
                        dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                        if (l_srv->callback_response_error)
                                l_srv->callback_response_error(l_srv,l_usage->id,l_usage->clients,&l_err,sizeof (l_err) );
                        break;
                    }
                }
                int ret;
                if ( (ret= l_srv->callback_requested(l_srv,l_usage->id, l_usage->clients, l_request, l_ch_pkt->hdr.size  ) )!= 0 ){
                    log_it( L_WARNING, "Request canceled by service callback, return code %d", ret);
                    dap_chain_net_srv_usage_delete(l_srv_session, l_usage);
                    l_err.code = (uint32_t) ret ;
                    dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                    if (l_srv->callback_response_error)
                            l_srv->callback_response_error(l_srv,l_usage->id, NULL,&l_err,sizeof (l_err) );
                    break;
                }

                if ( l_srv->pricelist ){
                    if ( l_price ){
                        l_usage->price = l_price;
                        // TODO extend callback to pass ext and ext size from service callbacks
                        l_receipt = dap_chain_net_srv_issue_receipt( l_usage->service, l_usage, l_usage->price,NULL,0 );
                        dap_stream_ch_pkt_write( l_usage->clients->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST ,
                                                 l_receipt, l_receipt->size);

                    }else{
                        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_PRICE_NOT_FOUND ;
                        dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                        if (l_srv->callback_response_error)
                                l_srv->callback_response_error( l_srv, l_usage->id, NULL, &l_err, sizeof( l_err ) );
                    }
                // If we a here we passed all the checks, wow, now if we're not for free we request the signature.
                } else{
                    log_it( L_INFO, "Service provide for free");
                    l_usage->is_free = true;
                    size_t l_success_size = sizeof (dap_stream_ch_chain_net_srv_pkt_success_hdr_t );
                    dap_stream_ch_chain_net_srv_pkt_success_t *l_success = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_success_t,
                                                                                          l_success_size);
                    l_success->hdr.usage_id = l_usage->id;
                    l_success->hdr.net_id.uint64 = l_usage->net->pub.id.uint64;
                    l_success->hdr.srv_uid.uint64 = l_usage->service->uid.uint64;

                    if (dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS,
                                                 l_success, l_success_size)) {
                        dap_stream_ch_set_ready_to_write(a_ch, true);
                    }

                    if ( l_usage->service->callback_receipt_first_success )
                        l_usage->service->callback_receipt_first_success ( l_usage->service, l_usage->id,  l_usage->clients, NULL, 0 );
                    DAP_DELETE(l_success);

                }
                // l_receipt used in l_usage->receipt
                //if(l_receipt)
                //    DAP_DELETE(l_receipt);
            } break;
            case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST:{
                log_it( L_NOTICE, "Requested smth to sign");
                // TODO sign smth
            } break;
            case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_RESPONSE:{
                if ( l_ch_pkt->hdr.size > sizeof(dap_chain_receipt_info_t)+1 ){
                    dap_chain_datum_tx_receipt_t * l_receipt = (dap_chain_datum_tx_receipt_t *) l_ch_pkt->data;
                    size_t l_receipt_size = l_ch_pkt->hdr.size;
                    dap_chain_net_srv_usage_t * l_usage= NULL, *l_tmp= NULL;
                    bool l_is_found = false;
                    pthread_mutex_lock(& l_srv_session->parent->mutex );
                    HASH_ITER(hh, l_srv_session->usages, l_usage, l_tmp){
                        if ( l_usage->receipt_next ){ // If we have receipt next
                            if ( memcmp(&l_usage->receipt_next->receipt_info, &l_receipt->receipt_info,sizeof (l_receipt->receipt_info) )==0 ){
                                l_is_found = true;
                                break;
                            }
                        }else if (l_usage->receipt ){ // If we sign first receipt
                            if ( memcmp(&l_usage->receipt->receipt_info, &l_receipt->receipt_info,sizeof (l_receipt->receipt_info) )==0 ){
                                l_is_found = true;
                                break;
                            }
                        }
                    }
                    pthread_mutex_unlock(& l_srv_session->parent->mutex );

                    if ( !l_is_found || ! l_usage ){
                        log_it(L_WARNING, "Can't find receipt in usages thats equal to response receipt");
                        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_CANT_FIND ;
                        dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                        if (l_usage && l_usage->service && l_usage->service->callback_response_error)
                                l_usage->service->callback_response_error(l_usage->service,l_usage->id, l_usage->clients,&l_err,sizeof (l_err) );
                        break;
                    }
                    l_err.usage_id = l_usage->id;
                    l_err.net_id.uint64 = l_usage->net->pub.id.uint64;
                    l_err.srv_uid.uint64 = l_usage->service->uid.uint64;

                    if (! l_usage->tx_cond ){
                        log_it(L_WARNING, "No tx out in usage");
                        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND ;
                        dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                        if (l_usage->service->callback_response_error)
                                l_usage->service->callback_response_error( l_usage->service, l_usage->id, l_usage->clients,
                                                                          &l_err, sizeof (l_err) );
                        break;
                    }
                    int l_tx_out_cond_size =0;
                    dap_chain_tx_out_cond_t *l_tx_out_cond = (dap_chain_tx_out_cond_t *)
                            dap_chain_datum_tx_item_get(l_usage->tx_cond, NULL, TX_ITEM_TYPE_OUT_COND, &l_tx_out_cond_size );

                    if ( ! l_tx_out_cond ){ // No conditioned output
                        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_COND_OUT ;
                        dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                        if (l_usage->service->callback_response_error)
                                l_usage->service->callback_response_error( l_usage->service, l_usage->id, l_usage->clients,&l_err,sizeof (l_err) );
                        break;
                    }
                    // get a second signature - from the client (first sign in server, second sign in client)
                    dap_sign_t * l_receipt_sign = dap_chain_datum_tx_receipt_sign_get( l_receipt, l_receipt_size, 1);
                    if ( ! l_receipt_sign ){
                        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_CANT_FIND ;
                        dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                        if (l_usage->service->callback_response_error)
                                l_usage->service->callback_response_error( l_usage->service, l_usage->id, l_usage->clients,
                                                                           &l_err, sizeof (l_err) );
                        break;
                    }

                    // Check receipt signature pkey hash
                    dap_chain_hash_fast_t l_pkey_hash={0};
                    dap_sign_get_pkey_hash( l_receipt_sign, &l_pkey_hash);


                    if( memcmp ( l_pkey_hash.raw, l_tx_out_cond->subtype.srv_pay.header.pkey_hash.raw , sizeof(l_pkey_hash) ) != 0 ){
                        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_WRONG_PKEY_HASH ;
                        dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                        if (l_usage->service->callback_response_error)
                                l_usage->service->callback_response_error(l_usage->service,l_usage->id, l_usage->clients,&l_err,sizeof (l_err) );
                        break;
                    }

                    bool l_is_first_sign = false;
                    if (! l_usage->receipt_next && l_usage->receipt){
                        DAP_DELETE(l_usage->receipt);
                        l_usage->receipt = DAP_NEW_SIZE(dap_chain_datum_tx_receipt_t,l_receipt_size);
                        l_usage->receipt_size = l_receipt_size;
                        l_is_first_sign = true;
                        l_usage->is_active = true;
                        memcpy( l_usage->receipt, l_receipt, l_receipt_size);
                    } else if (l_usage->receipt_next ){
                        DAP_DELETE(l_usage->receipt_next);
                        l_usage->receipt_next = DAP_NEW_SIZE(dap_chain_datum_tx_receipt_t,l_receipt_size);
                        l_usage->receipt_next_size = l_receipt_size;
                        l_usage->is_active = true;
                        memcpy( l_usage->receipt_next, l_receipt, l_receipt_size);
                    }

                    // Update actual receipt
                    log_it(L_NOTICE, "Receipt with remote client sign is acceptible for. Now start the service's usage");


                    // Store receipt if any problems with transactions
                    dap_chain_hash_fast_t l_receipt_hash={0};
                    dap_hash_fast(l_receipt,l_receipt_size,&l_receipt_hash);
                    char * l_receipt_hash_str = dap_chain_hash_fast_to_str_new(&l_receipt_hash);
                    dap_chain_global_db_gr_set( l_receipt_hash_str,l_receipt,l_receipt_size,"local.receipts");
                    l_receipt_hash_str = NULL; // To prevent usage of this pointer when it will be free by GDB processor
                    // Form input transaction
                    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(l_usage->wallet, l_usage->net->pub.id);


                    dap_chain_hash_fast_t * l_tx_in_hash = dap_chain_mempool_tx_create_cond_input(
                                l_usage->net,&l_usage->tx_cond_hash,
                                l_wallet_addr,dap_chain_wallet_get_key( l_usage->wallet,0), l_receipt, l_receipt_size);

                    if ( l_tx_in_hash){
                        char * l_tx_in_hash_str = dap_chain_hash_fast_to_str_new(l_tx_in_hash);
                        log_it(L_NOTICE, "Formed tx %s for input with active receipt", l_tx_in_hash_str);


                        // We could put transaction directly to chains
                        if ( dap_chain_net_get_role( l_usage->net  ).enums == NODE_ROLE_MASTER ||
                              dap_chain_net_get_role( l_usage->net  ).enums == NODE_ROLE_CELL_MASTER ||
                             dap_chain_net_get_role( l_usage->net  ).enums == NODE_ROLE_ROOT ||
                             dap_chain_net_get_role( l_usage->net  ).enums == NODE_ROLE_ROOT_MASTER ){
                            dap_chain_net_proc_mempool( l_usage->net);
                        }
                        DAP_DELETE(l_tx_in_hash_str);
                    }else
                        log_it(L_ERROR, "Can't create input tx cond transaction!");
                    if (l_tx_in_hash)
                        DAP_DELETE(l_tx_in_hash);

                    size_t l_success_size = sizeof (dap_stream_ch_chain_net_srv_pkt_success_hdr_t );
                    dap_stream_ch_chain_net_srv_pkt_success_t *l_success = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_success_t,
                                                                                          l_success_size);
                    l_success->hdr.usage_id = l_usage->id;
                    l_success->hdr.net_id.uint64 = l_usage->net->pub.id.uint64;
                    l_success->hdr.srv_uid.uint64 = l_usage->service->uid.uint64;

                    dap_stream_ch_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS ,
                                                 l_success, l_success_size);
                    DAP_DELETE(l_success);

                    if ( l_is_first_sign && l_usage->service->callback_receipt_first_success){
                        if( l_usage->service->callback_receipt_first_success(l_usage->service,l_usage->id,  l_usage->clients,
                                                                    l_receipt, l_receipt_size ) !=0 ){
                            log_it(L_NOTICE, "No success by service callback, inactivating service usage");
                            l_usage->is_active = false;
                        }
                        // issue receipt next
                        l_usage->receipt_next = dap_chain_net_srv_issue_receipt( l_usage->service, l_usage, l_usage->price ,NULL,0);
                        l_usage->receipt_next_size = l_usage->receipt_next->size;
                        dap_stream_ch_pkt_write( l_usage->clients->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST ,
                                                 l_usage->receipt_next, l_usage->receipt_next->size);

                    }else if ( l_usage->service->callback_receipt_next_success){
                        if (l_usage->service->callback_receipt_next_success(l_usage->service,l_usage->id,  l_usage->clients,
                                                                    l_receipt, l_receipt_size ) != 0 ){
                            log_it(L_NOTICE, "No success by service callback, inactivating service usage");
                            l_usage->is_active = false;
                        }
                    }

                }else{
                    log_it(L_ERROR, "Wrong sign response size, %zd when expected at least %zd with smth", l_ch_pkt->hdr.size,
                           sizeof(dap_chain_receipt_info_t)+1 );
                }
            } break;
            case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS:{
                log_it( L_NOTICE, "Responsed with success");
                // TODO code for service client mode
            } break;
            case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR:{
                if ( l_ch_pkt->hdr.size == sizeof (dap_stream_ch_chain_net_srv_pkt_error_t) ){
                    dap_stream_ch_chain_net_srv_pkt_error_t * l_err = (dap_stream_ch_chain_net_srv_pkt_error_t *) l_ch_pkt->data;
                    log_it( L_NOTICE, "Remote responsed with error code 0x%08X", l_err->code );
                    // TODO code for service client mode
                }else{
                    log_it(L_ERROR, "Wrong error response size, %zd when expected %zd", l_ch_pkt->hdr.size,
                           sizeof ( dap_stream_ch_chain_net_srv_pkt_error_t) );
                }
            } break;
            default: log_it( L_WARNING, "Unknown packet type 0x%02X", l_ch_pkt->hdr.type);
        }
    }

}

/**
 * @brief s_stream_ch_packet_out
 * @param a_ch
 * @param a_arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t* a_ch , void* a_arg)
{
    (void) a_arg;
    log_it(L_WARNING,"We don't need anything special to write but for some reasons write flag was on and now we're in output callback. Why?");
    dap_stream_ch_set_ready_to_write(a_ch, false);
}
