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

#include <sys/time.h>
#include <time.h>
#include "dap_global_db.h"
#include "dap_time.h"
#include "dap_timerfd.h"
#include "dap_hash.h"
#include "rand/dap_rand.h"

//#include "dap_chain.h"
//#include "dap_chain_datum_tx.h"
//#include "dap_chain_datum_tx_in.h"
//#include "dap_chain_datum_tx_in_cond.h"
//#include "dap_chain_datum_tx_out.h"
//#include "dap_chain_datum_tx_out_cond.h"
//#include "dap_chain_datum_tx_receipt.h"
//#include "dap_chain_mempool.h"
//#include "dap_common.h"

#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_stream_session.h"


#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_stream_ch_chain_net_srv_pkt.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_chain_net_srv.h"

#define LOG_TAG "dap_stream_ch_chain_net_srv"

typedef struct usages_in_grace{
    dap_hash_fast_t tx_cond_hash;
    dap_chain_net_srv_grace_t *grace;
    UT_hash_handle hh;
} usages_in_grace_t;

uint8_t dap_stream_ch_chain_net_srv_get_id()
{
    return 'R';
}

static void s_stream_ch_new(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_delete(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_packet_in(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_packet_out(dap_stream_ch_t* ch , void* arg);

static bool s_unban_client(dap_chain_net_srv_banlist_item_t *a_item);

static void s_service_start(dap_stream_ch_t* a_ch , dap_stream_ch_chain_net_srv_pkt_request_t * a_request, size_t a_request_size);
static void s_grace_period_start(dap_chain_net_srv_grace_t *a_grace);
static bool s_grace_period_finish(usages_in_grace_t *a_grace);

static inline void s_grace_error(dap_chain_net_srv_grace_t *a_grace, dap_stream_ch_chain_net_srv_pkt_error_t a_err){
    dap_stream_ch_t * l_ch = a_grace->usage->client->ch;
    dap_chain_net_srv_stream_session_t *l_srv_session = l_ch && l_ch->stream && l_ch->stream->session ?
                                                        (dap_chain_net_srv_stream_session_t *)l_ch->stream->session->_inheritor : NULL;
    if (a_err.code) {
        if(l_ch)
            dap_stream_ch_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &a_err, sizeof (a_err));
        if (a_grace->usage->service && a_grace->usage->service->callbacks.response_error)
            a_grace->usage->service->callbacks.response_error(a_grace->usage->service, 0, NULL, &a_err, sizeof(a_err));
    }

    if (a_grace->usage) {   // add client pkey hash to banlist
        a_grace->usage->is_active = false;
        if (a_grace->usage->service) {
            dap_chain_net_srv_banlist_item_t *l_item = NULL;
            pthread_mutex_lock(&a_grace->usage->service->banlist_mutex);
            HASH_FIND(hh, a_grace->usage->service->ban_list, &a_grace->usage->client_pkey_hash, sizeof(dap_chain_hash_fast_t), l_item);
            if (l_item)
                pthread_mutex_unlock(&a_grace->usage->service->banlist_mutex);
            else {
                l_item = DAP_NEW_Z(dap_chain_net_srv_banlist_item_t);
                l_item->client_pkey_hash = a_grace->usage->client_pkey_hash;
                l_item->ht_mutex = &a_grace->usage->service->banlist_mutex;
                l_item->ht_head = &a_grace->usage->service->ban_list;
                HASH_ADD(hh, a_grace->usage->service->ban_list, client_pkey_hash, sizeof(dap_chain_hash_fast_t), l_item);
                pthread_mutex_unlock(&a_grace->usage->service->banlist_mutex);
                dap_timerfd_start(a_grace->usage->service->grace_period * 1000, (dap_timerfd_callback_t)s_unban_client, l_item);
            }
        }
    }    else if (a_grace->usage)
        dap_chain_net_srv_usage_delete(l_srv_session, l_srv_session->usage_active);
    DAP_DELETE(a_grace->request);
    DAP_DELETE(a_grace);
}

// TODO: move this to net_srv
static usages_in_grace_t * s_grace_table = NULL;
static pthread_mutex_t s_ht_grace_table_mutex;
/**
 * @brief dap_stream_ch_chain_net_init
 * @return
 */
int dap_stream_ch_chain_net_srv_init(void)
{
    log_it(L_NOTICE,"Chain network services channel initialized");
    dap_stream_ch_proc_add(dap_stream_ch_chain_net_srv_get_id(),s_stream_ch_new,s_stream_ch_delete,s_stream_ch_packet_in,s_stream_ch_packet_out);
    pthread_mutex_init(&s_ht_grace_table_mutex, NULL);

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
    l_ch_chain_net_srv->ch_uuid = a_ch->uuid;
    l_ch_chain_net_srv->ch = a_ch;
    if (a_ch->stream->session && !a_ch->stream->session->_inheritor)
        dap_chain_net_srv_stream_session_create( a_ch->stream->session );
    else if ( a_ch->stream->session == NULL)
        log_it( L_ERROR, "No session at all!");
    else
        log_it(L_ERROR, "Session inheritor is already present!");

    dap_chain_net_srv_call_opened_all( a_ch);
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
    dap_chain_net_srv_call_closed_all( a_ch);
    DAP_DEL_Z(a_ch->internal);
}

static bool s_unban_client(dap_chain_net_srv_banlist_item_t *a_item)
{
    pthread_mutex_lock(a_item->ht_mutex);
    HASH_DEL(*(a_item->ht_head), a_item);
    pthread_mutex_unlock(a_item->ht_mutex);
    DAP_DELETE(a_item);
    return false;
}

void dap_stream_ch_chain_net_srv_tx_cond_added_cb(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_prev_cond)
{
    UNUSED(a_ledger);
    UNUSED(a_prev_cond);
    // TODO: 1. Get net_srv by srv_uid from tx_cond
    // 2. Get usages in grace HT from service
    usages_in_grace_t *l_item = NULL;
    dap_hash_fast_t tx_cond_hash = {};
    dap_hash_fast((void*)a_tx, dap_chain_datum_tx_get_size(a_tx), &tx_cond_hash);
    pthread_mutex_lock(&s_ht_grace_table_mutex);
    HASH_FIND(hh, s_grace_table, &tx_cond_hash, sizeof(dap_hash_fast_t), l_item);
    if (l_item){
        log_it(L_INFO, "Found tx in ledger by notify. Finish grace.");
        l_item->grace->usage->tx_cond = a_tx;
        // Stop timer
        dap_timerfd_delete_mt(l_item->grace->stream_worker->worker, l_item->grace->timer_es_uuid);
        // finish grace
        s_grace_period_finish(l_item);
    }
    pthread_mutex_unlock(&s_ht_grace_table_mutex);
}

static void s_service_start(dap_stream_ch_t* a_ch , dap_stream_ch_chain_net_srv_pkt_request_t * a_request, size_t a_request_size)
{
    assert(a_ch);
    dap_stream_ch_chain_net_srv_pkt_error_t l_err;
    memset(&l_err, 0, sizeof(l_err));
    dap_chain_net_srv_t * l_srv = NULL;

    dap_chain_net_srv_stream_session_t *l_srv_session = a_ch->stream && a_ch->stream->session ?
                                                        (dap_chain_net_srv_stream_session_t *)a_ch->stream->session->_inheritor : NULL;
    l_srv = dap_chain_net_srv_get( a_request->hdr.srv_uid );
    dap_chain_net_t * l_net = dap_chain_net_by_id( a_request->hdr.net_id );

    l_err.net_id.uint64 = a_request->hdr.net_id.uint64;
    l_err.srv_uid.uint64 = a_request->hdr.srv_uid.uint64;

    if ( ! l_net ) // Network not found
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_NOT_FOUND;

    if ( ! l_srv ) // Service not found
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_NOT_FOUND;

    if ( l_err.code || !l_srv_session){
        if(a_ch)
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
        if (l_srv && l_srv->callbacks.response_error)
            l_srv->callbacks.response_error(l_srv, 0, NULL, &l_err, sizeof(l_err));
        return;
    }

    dap_chain_net_srv_usage_t *l_usage = NULL;
    l_usage = dap_chain_net_srv_usage_add(l_srv_session, l_net, l_srv);
    if ( !l_usage ){ // Usage can't add
        log_it( L_WARNING, "Can't add usage");
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_CANT_ADD_USAGE;
        if(a_ch)
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
        if (l_srv && l_srv->callbacks.response_error)
            l_srv->callbacks.response_error(l_srv, 0, NULL, &l_err, sizeof(l_err));
        return;
    }

    l_err.usage_id = l_usage->id;
    // Create one client
    l_usage->client = DAP_NEW_Z( dap_chain_net_srv_client_remote_t);
    l_usage->client->stream_worker = a_ch->stream_worker;
    l_usage->client->ch = a_ch;
    l_usage->client->session_id = a_ch->stream->session->id;
    l_usage->client->ts_created = time(NULL);
    l_usage->tx_cond_hash = a_request->hdr.tx_cond;
    l_usage->ts_created = time(NULL);
    l_usage->net = l_net;
    l_usage->service = l_srv;


    dap_chain_net_srv_grace_t *l_grace = DAP_NEW_Z(dap_chain_net_srv_grace_t);
    l_grace->request = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_request_t, a_request_size);
    memcpy(l_grace->request, a_request, a_request_size);
    l_grace->request_size = a_request_size;
    l_grace->ch_uuid = a_ch->uuid;
    l_grace->stream_worker = a_ch->stream_worker;
    l_grace->usage = l_usage;

    if (l_srv->pricelist){
        // not free service
        s_grace_period_start(l_grace);
    } else {
        // Start service for free
        log_it( L_INFO, "Service provide for free");
        l_grace->usage->is_free = true;
        size_t l_success_size = sizeof (dap_stream_ch_chain_net_srv_pkt_success_hdr_t );
        dap_stream_ch_chain_net_srv_pkt_success_t *l_success = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_success_t,
                                                                              l_success_size);
        l_success->hdr.usage_id = l_usage->id;
        l_success->hdr.net_id.uint64 = l_usage->net->pub.id.uint64;
        l_success->hdr.srv_uid.uint64 = l_usage->service->uid.uint64;
        dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS, l_success, l_success_size);
        if (l_usage->service->callbacks.response_success)
            l_usage->service->callbacks.response_success(l_usage->service, l_usage->id,  l_usage->client, NULL, 0);
        DAP_DELETE(l_success);
    }
    return;
}

static void s_grace_period_start(dap_chain_net_srv_grace_t *a_grace)
{
    assert(a_grace);
    dap_stream_ch_chain_net_srv_pkt_error_t l_err;
    memset(&l_err, 0, sizeof(l_err));
    dap_stream_ch_t *l_ch = a_grace->usage->client->ch;

    if (!l_ch){
        s_grace_error(a_grace, l_err);
        return;
    }

    dap_chain_net_t * l_net = a_grace->usage->net;

    l_err.net_id.uint64 = l_net->pub.id.uint64;
    l_err.srv_uid.uint64 = a_grace->usage->service->uid.uint64;

    dap_ledger_t * l_ledger = l_net->pub.ledger;
    dap_chain_datum_tx_t * l_tx = NULL;
    dap_chain_tx_out_cond_t * l_tx_out_cond = NULL;
    dap_chain_net_srv_price_t * l_price = NULL;
    if ( !l_ledger ){ // No ledger
        log_it( L_WARNING, "No Ledger");
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_NO_LEDGER ;
        s_grace_error(a_grace, l_err);
        return;
    }

    l_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &a_grace->usage->tx_cond_hash);
    if ( ! l_tx ){ // No tx cond transaction, start grace-period
        a_grace->usage->is_grace = true;

        l_price = DAP_NEW_Z(dap_chain_net_srv_price_t);
                        memcpy(l_price, a_grace->usage->service->pricelist, sizeof(*l_price));

        a_grace->usage->price = l_price;

        if (a_grace->usage->receipt_next){
            DAP_DEL_Z(a_grace->usage->receipt_next);
            a_grace->usage->receipt_next = dap_chain_net_srv_issue_receipt(a_grace->usage->service, a_grace->usage->price, NULL, 0);
        }else{
            a_grace->usage->receipt = dap_chain_net_srv_issue_receipt(a_grace->usage->service, a_grace->usage->price, NULL, 0);
            dap_stream_ch_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST,
                                       a_grace->usage->receipt, a_grace->usage->receipt->size);
        }
        usages_in_grace_t *l_item = DAP_NEW_Z_SIZE(usages_in_grace_t, sizeof(usages_in_grace_t));
        l_item->grace = a_grace;
        l_item->tx_cond_hash = a_grace->usage->tx_cond_hash;

        pthread_mutex_lock(&s_ht_grace_table_mutex);
        HASH_ADD(hh, s_grace_table, tx_cond_hash, sizeof(dap_hash_fast_t), l_item);
        pthread_mutex_unlock(&s_ht_grace_table_mutex);
        a_grace->timer_es_uuid = dap_timerfd_start_on_worker(a_grace->stream_worker->worker, a_grace->usage->service->grace_period * 1000,
                                                             (dap_timerfd_callback_t)s_grace_period_finish, l_item)->esocket_uuid;

    } else { // Start srvice in normal pay mode
        a_grace->usage->tx_cond = l_tx;

        int l_tx_out_cond_size =0;
        l_tx_out_cond = (dap_chain_tx_out_cond_t *)
                dap_chain_datum_tx_item_get(l_tx, NULL, TX_ITEM_TYPE_OUT_COND, &l_tx_out_cond_size );

        if ( ! l_tx_out_cond ) { // No conditioned output
            log_it( L_WARNING, "No conditioned output");
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_COND_OUT ;
            s_grace_error(a_grace, l_err);
            return;
        }

        // Check cond output if it equesl or not to request
        if (!dap_chain_net_srv_uid_compare(l_tx_out_cond->header.srv_uid, a_grace->usage->service->uid)) {
            log_it( L_WARNING, "Wrong service uid in request, tx expect to close its output with 0x%016"DAP_UINT64_FORMAT_X,
                    l_tx_out_cond->header.srv_uid.uint64 );
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_WRONG_SRV_UID  ;
            s_grace_error(a_grace, l_err);
            return;
        }

        const char * l_ticker = NULL;
        l_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(l_ledger, &a_grace->usage->tx_cond_hash);
        dap_stpcpy(a_grace->usage->token_ticker, l_ticker);

        dap_chain_net_srv_price_t *l_price_tmp;
        DL_FOREACH(a_grace->usage->service->pricelist, l_price_tmp) {
            if (l_price_tmp && l_price_tmp->net->pub.id.uint64                 == a_grace->usage->net->pub.id.uint64
                && dap_strcmp(l_price_tmp->token, l_ticker)     == 0
                && l_price_tmp->units_uid.enm                   == l_tx_out_cond->subtype.srv_pay.unit.enm
                )//&& (l_price_tmp->value_datoshi/l_price_tmp->units)  < l_tx_out_cond->subtype.srv_pay.header.unit_price_max_datoshi)
            {
                l_price = l_price_tmp;
                break;
            }
        }
        if ( !l_price ) {
            log_it( L_WARNING, "Request can't be processed because no acceptable price in pricelist for token %s in network %s",
                    l_ticker, l_net->pub.name );
            l_err.code =DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ACCEPT_TOKEN;
            s_grace_error(a_grace, l_err);
            return;
        }
        a_grace->usage->price = l_price;
        int ret;
        if ((ret = a_grace->usage->service->callbacks.requested(a_grace->usage->service, a_grace->usage->id, a_grace->usage->client, a_grace->request, a_grace->request_size)) != 0) {
            log_it( L_WARNING, "Request canceled by service callback, return code %d", ret);
            l_err.code = (uint32_t) ret ;
            s_grace_error(a_grace, l_err);
            return;
        }

        if (a_grace->usage->receipt_next){
            DAP_DEL_Z(a_grace->usage->receipt_next);
            a_grace->usage->receipt_next = dap_chain_net_srv_issue_receipt(a_grace->usage->service, a_grace->usage->price, NULL, 0);
        }else{
            a_grace->usage->receipt = dap_chain_net_srv_issue_receipt(a_grace->usage->service, a_grace->usage->price, NULL, 0);
            dap_stream_ch_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST,
                                       a_grace->usage->receipt, a_grace->usage->receipt->size);
        }

        DAP_DELETE(a_grace->request);
        DAP_DELETE(a_grace);

    }
}

static bool s_grace_period_finish(usages_in_grace_t *a_grace_item)
{
    log_it(L_INFO, "Grace period is over! Check tx in ledger.");
    assert(a_grace_item);
    dap_stream_ch_chain_net_srv_pkt_error_t l_err;
    memset(&l_err, 0, sizeof(l_err));
    dap_chain_net_srv_grace_t *l_grace = a_grace_item->grace;

    dap_stream_ch_t *l_ch = l_grace->usage->client->ch;

    if (!l_ch){
        s_grace_error(l_grace, l_err);
        return false;
    }

    dap_chain_net_t * l_net = l_grace->usage->net;

    l_err.net_id.uint64 = l_net->pub.id.uint64;
    l_err.srv_uid.uint64 = l_grace->usage->service->uid.uint64;

    dap_ledger_t * l_ledger = l_net->pub.ledger;
    dap_chain_datum_tx_t * l_tx = NULL;
    dap_chain_tx_out_cond_t * l_tx_out_cond = NULL;

    if ( !l_ledger ){ // No ledger
        log_it( L_WARNING, "No Ledger");
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_NO_LEDGER ;
        s_grace_error(l_grace, l_err);
        return false;
    }

    if (a_grace_item->grace->usage->tx_cond)
    {
        l_tx = a_grace_item->grace->usage->tx_cond;
    }else{
        l_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &l_grace->usage->tx_cond_hash);
    }

    if ( ! l_tx ){ // No tx cond transaction, start grace-period
        log_it( L_WARNING, "No tx cond transaction");
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND ;
        s_grace_error(l_grace, l_err);
        return false;
    } else { // Start srvice in normal pay mode
        log_it(L_INFO, "Tx is found in ledger.");
        l_grace->usage->tx_cond = l_tx;

        int l_tx_out_cond_size =0;
        l_tx_out_cond = (dap_chain_tx_out_cond_t *)
            dap_chain_datum_tx_item_get(l_tx, NULL, TX_ITEM_TYPE_OUT_COND, &l_tx_out_cond_size );

        if ( ! l_tx_out_cond ) { // No conditioned output
            log_it( L_WARNING, "No conditioned output");
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_COND_OUT ;
            s_grace_error(l_grace, l_err);
            return false;
        }

        // Check cond output if it equesl or not to request
        if (!dap_chain_net_srv_uid_compare(l_tx_out_cond->header.srv_uid, l_grace->usage->service->uid)) {
            log_it( L_WARNING, "Wrong service uid in request, tx expect to close its output with 0x%016"DAP_UINT64_FORMAT_X,
                   l_tx_out_cond->header.srv_uid.uint64 );
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_WRONG_SRV_UID  ;
            s_grace_error(l_grace, l_err);
            return false;
        }

        dap_chain_net_srv_price_t * l_price = NULL;
        const char * l_ticker = NULL;
        l_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_grace->usage->tx_cond_hash);
        dap_stpcpy(l_grace->usage->token_ticker, l_ticker);

        dap_chain_net_srv_price_t *l_price_tmp;
        DL_FOREACH(l_grace->usage->service->pricelist, l_price_tmp) {
            if (l_price_tmp && l_price_tmp->net->pub.id.uint64                 == l_grace->usage->net->pub.id.uint64
                && dap_strcmp(l_price_tmp->token, l_ticker)     == 0
                && l_price_tmp->units_uid.enm                   == l_tx_out_cond->subtype.srv_pay.unit.enm
                )//&& (l_price_tmp->value_datoshi/l_price_tmp->units)  < l_tx_out_cond->subtype.srv_pay.header.unit_price_max_datoshi)
            {
                l_price = l_price_tmp;
                break;
            }
        }
        if ( !l_price ) {
            log_it( L_WARNING, "Request can't be processed because no acceptable price in pricelist for token %s in network %s",
                   l_ticker, l_net->pub.name );
            l_err.code =DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ACCEPT_TOKEN;
            s_grace_error(l_grace, l_err);
            return false;
        }

        int ret;
        if ((ret = l_grace->usage->service->callbacks.requested(l_grace->usage->service, l_grace->usage->id, l_grace->usage->client, l_grace->request, l_grace->request_size)) != 0) {
            log_it( L_WARNING, "Request canceled by service callback, return code %d", ret);
            l_err.code = (uint32_t) ret ;
            s_grace_error(l_grace, l_err);
            return false;
        }

        // make receipt or tx
        char *l_receipt_hash_str;
        dap_chain_datum_tx_receipt_t *l_receipt = NULL;
        if (l_grace->usage->receipt_next){
            l_receipt = l_grace->usage->receipt_next;
        } else if (l_grace->usage->receipt){
            l_receipt = l_grace->usage->receipt;
        } else {
            // Send error???
        }
        size_t l_receipt_size = l_receipt->size;
        dap_get_data_hash_str_static(l_receipt, l_receipt_size, l_receipt_hash_str);
        dap_global_db_set("local.receipts", l_receipt_hash_str, l_receipt, l_receipt_size, false, NULL, NULL);
            // Form input transaction
        char *l_hash_str = dap_hash_fast_to_str_new(&l_grace->usage->tx_cond_hash);
        log_it(L_NOTICE, "Trying create input tx cond from tx %s with active receipt", l_hash_str);
        DAP_DEL_Z(l_hash_str);
        dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(l_grace->usage->price->wallet, l_grace->usage->net->pub.id);
        int ret_status = 0;
        char *l_tx_in_hash_str = dap_chain_mempool_tx_create_cond_input(l_grace->usage->net, &l_grace->usage->tx_cond_hash, l_wallet_addr,
                                                                        dap_chain_wallet_get_key(l_grace->usage->price->wallet, 0),
                                                                        l_receipt, "hex", &ret_status);
        if (!ret_status) {
            dap_chain_hash_fast_from_str(l_tx_in_hash_str, &l_grace->usage->tx_cond_hash);
            log_it(L_NOTICE, "Formed tx %s for input with active receipt", l_tx_in_hash_str);
            DAP_DELETE(l_tx_in_hash_str);

        }else{
            if(ret_status == DAP_CHAIN_MEMPOOl_RET_STATUS_NOT_ENOUGH){
                memset(&l_grace->usage->tx_cond_hash, 0, sizeof(l_grace->usage->tx_cond_hash));
                DAP_DEL_Z(l_grace->usage->receipt_next);
                log_it(L_ERROR, "Tx cond have not enough funds");
                l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ENOUGH;
                dap_stream_ch_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
            }else{
                log_it(L_ERROR, "Can't create input tx cond transaction!");
                memset(&l_grace->usage->tx_cond_hash, 0, sizeof(l_grace->usage->tx_cond_hash));
                if (l_grace->usage->receipt_next){
                    DAP_DEL_Z(l_grace->usage->receipt_next);
                } else if (l_grace->usage->receipt){
                    DAP_DEL_Z(l_grace->usage->receipt);
                }
                l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_NOT_FOUND;
                dap_stream_ch_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
                if (l_grace->usage->service->callbacks.response_error)
                    l_grace->usage->service->callbacks.response_error(l_grace->usage->service,l_grace->usage->id, l_grace->usage->client,&l_err,sizeof (l_err));
            }
        }
    }
    l_grace->usage->is_grace = false;
    DAP_DELETE(a_grace_item->grace->request);
    DAP_DEL_Z(a_grace_item->grace);
    HASH_DEL(s_grace_table, a_grace_item);
    return false;
}

/**
 * @brief s_stream_ch_packet_in
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_in(dap_stream_ch_t* a_ch , void* a_arg)
{
    dap_stream_ch_pkt_t *l_ch_pkt = (dap_stream_ch_pkt_t *)a_arg;
    if (!l_ch_pkt)
        return;
    dap_chain_net_srv_stream_session_t *l_srv_session = NULL;
    if (a_ch) {
        l_srv_session = a_ch->stream && a_ch->stream->session ? a_ch->stream->session->_inheritor : NULL;
    }
    if (!l_srv_session) {
        log_it( L_ERROR, "Not defined service session, switching off packet input process");
        dap_stream_ch_set_ready_to_read_unsafe(a_ch, false);
        return;
    }

    dap_stream_ch_chain_net_srv_t * l_ch_chain_net_srv = DAP_STREAM_CH_CHAIN_NET_SRV(a_ch);
    if (l_ch_chain_net_srv->notify_callback) {
        l_ch_chain_net_srv->notify_callback(l_ch_chain_net_srv, l_ch_pkt->hdr.type, l_ch_pkt, l_ch_chain_net_srv->notify_callback_arg);
        return; // It's a client behind this
    }
    dap_stream_ch_chain_net_srv_pkt_error_t l_err = { };
    switch (l_ch_pkt->hdr.type) {
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_REQUEST: {
        typedef dap_stream_ch_chain_net_srv_pkt_test_t pkt_test_t;
        pkt_test_t *l_request = (pkt_test_t*)l_ch_pkt->data;
        size_t l_request_size = l_request->data_size + sizeof(pkt_test_t);
        if (l_ch_pkt->hdr.data_size != l_request_size) {
            log_it(L_WARNING, "Wrong request size %u, must be %zu [pkt seq %"DAP_UINT64_FORMAT_U"]", l_ch_pkt->hdr.data_size, l_request_size, l_ch_pkt->hdr.seq_id);
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_WRONG_SIZE;
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof(l_err));
            break;
        }
        dap_chain_hash_fast_t l_data_hash;
        dap_hash_fast(l_request->data, l_request->data_size, &l_data_hash);
        if (l_request->data_size > 0 && !dap_hash_fast_compare(&l_data_hash, &l_request->data_hash)) {
            log_it(L_WARNING, "Wrong hash [pkt seq %"DAP_UINT64_FORMAT_U"]", l_ch_pkt->hdr.seq_id);
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_WRONG_HASH;
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof(l_err));
            break;
        }
        if(l_request->data_size_recv > UINT_MAX) {
            log_it(L_WARNING, "Too large payload %zu [pkt seq %"DAP_UINT64_FORMAT_U"]", l_request->data_size_recv, l_ch_pkt->hdr.seq_id);
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_BIG_SIZE;
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof(l_err));
            break;
        }
        /* No need for bare copying, resend it back modified */
        if (l_request->data_size_recv) {
            l_request->data_size = l_request->data_size_recv;
            if (!l_request->data_size_send){
                l_request = (pkt_test_t*)DAP_DUP_SIZE(l_request, sizeof(pkt_test_t));
                l_request = DAP_REALLOC(l_request, sizeof(pkt_test_t) + l_request->data_size);
            }

            randombytes(l_request->data, l_request->data_size);
            dap_hash_fast_t l_data_hash;
            dap_hash_fast(l_request->data, l_request->data_size, &l_data_hash);
            l_request->data_hash = l_data_hash;

        }
        l_request->err_code = 0;

        strncpy(l_request->ip_send, a_ch->stream->esocket->hostaddr, INET_ADDRSTRLEN - 1);
        l_request->ip_send[INET_ADDRSTRLEN - 1] = '\0'; // Compiler warning escape
        l_request->recv_time2 = dap_nanotime_now();

        dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_RESPONSE, l_request,
                                       l_request->data_size + sizeof(pkt_test_t));
        if(l_request != (pkt_test_t*)l_ch_pkt->data){
            DAP_DELETE(l_request);
        }

    } break; /* DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_REQUEST */

    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST: { //Service request
        if (l_ch_pkt->hdr.data_size < sizeof(dap_stream_ch_chain_net_srv_pkt_request_hdr_t) ){
            log_it( L_WARNING, "Wrong request size, less than minimum");
            break;
        }
        dap_stream_ch_chain_net_srv_pkt_request_t *l_request = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_request_t, l_ch_pkt->hdr.data_size);
        memcpy(l_request, l_ch_pkt->data, l_ch_pkt->hdr.data_size);
        l_ch_chain_net_srv->srv_uid.uint64 = l_request->hdr.srv_uid.uint64;
        s_service_start(a_ch, l_request, l_ch_pkt->hdr.data_size);
    } break; /* DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST */

    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_RESPONSE: { // Check receipt sign and make tx if success
        dap_chain_net_srv_usage_t * l_usage = l_srv_session->usage_active;
        if (l_ch_pkt->hdr.data_size < sizeof(dap_chain_receipt_info_t)) {
            log_it(L_ERROR, "Wrong sign response size, %u when expected at least %zu with smth", l_ch_pkt->hdr.data_size,
                   sizeof(dap_chain_receipt_info_t));
            if ( l_usage->receipt_next ){ // If we have receipt next
                DAP_DEL_Z(l_usage->receipt_next);
            }else if (l_usage->receipt ){ // If we sign first receipt
                DAP_DEL_Z(l_usage->receipt);
            }
            break;
        }
        dap_chain_datum_tx_receipt_t * l_receipt = (dap_chain_datum_tx_receipt_t *) l_ch_pkt->data;
        size_t l_receipt_size = l_ch_pkt->hdr.data_size;

        bool l_is_found = false;
        if ( l_usage->receipt_next ){ // If we have receipt next
            if ( memcmp(&l_usage->receipt_next->receipt_info, &l_receipt->receipt_info,sizeof (l_receipt->receipt_info) )==0 ){
                l_is_found = true;
            }
        }else if (l_usage->receipt ){ // If we sign first receipt
            if ( memcmp(&l_usage->receipt->receipt_info, &l_receipt->receipt_info,sizeof (l_receipt->receipt_info) )==0 ){
                l_is_found = true;
            }
        }

        if ( !l_is_found || ! l_usage ){
            log_it(L_WARNING, "Can't find receipt in usages thats equal to response receipt");
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_CANT_FIND;
            dap_stream_ch_pkt_write_unsafe( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
            if (l_usage && l_usage->service && l_usage->service->callbacks.response_error)
                    l_usage->service->callbacks.response_error(l_usage->service,l_usage->id, l_usage->client,&l_err,sizeof (l_err) );
            break;
        }
        l_err.usage_id = l_usage->id;
        l_err.net_id.uint64 = l_usage->net->pub.id.uint64;
        l_err.srv_uid.uint64 = l_usage->service->uid.uint64;

        dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
        if (!l_usage->is_grace) {
            if (! l_usage->tx_cond ){
                log_it(L_WARNING, "No tx out in usage");
                l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND ;
                dap_stream_ch_pkt_write_unsafe( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                if (l_usage->service->callbacks.response_error)
                        l_usage->service->callbacks.response_error( l_usage->service, l_usage->id, l_usage->client,
                                                                  &l_err, sizeof (l_err) );
                break;
            }
            int l_tx_out_cond_size =0;
            l_tx_out_cond = (dap_chain_tx_out_cond_t *)dap_chain_datum_tx_item_get(l_usage->tx_cond, NULL,
                                                                                   TX_ITEM_TYPE_OUT_COND, &l_tx_out_cond_size );
            if ( ! l_tx_out_cond ){ // No conditioned output
                l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_COND_OUT ;
                dap_stream_ch_pkt_write_unsafe( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                if (l_usage->service->callbacks.response_error)
                        l_usage->service->callbacks.response_error( l_usage->service, l_usage->id, l_usage->client,&l_err,sizeof (l_err) );
                break;
            }

        }
        // get a second signature - from the client (first sign in server, second sign in client)
        dap_sign_t * l_receipt_sign = dap_chain_datum_tx_receipt_sign_get( l_receipt, l_receipt_size, 1);
        if ( ! l_receipt_sign ){
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_CANT_FIND ;
            dap_stream_ch_pkt_write_unsafe( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
            if (l_usage->service->callbacks.response_error)
                    l_usage->service->callbacks.response_error( l_usage->service, l_usage->id, l_usage->client,
                                                               &l_err, sizeof (l_err) );
            break;
        }
        // Check receipt signature pkey hash
        dap_chain_net_srv_banlist_item_t *l_item = NULL;
        dap_chain_net_srv_t * l_srv = dap_chain_net_srv_get(l_receipt->receipt_info.srv_uid);
        dap_sign_get_pkey_hash(l_receipt_sign, &l_usage->client_pkey_hash);
        if (l_usage->is_grace) {
            pthread_mutex_lock(&l_srv->banlist_mutex);
            HASH_FIND(hh, l_srv->ban_list, &l_usage->client_pkey_hash, sizeof(dap_chain_hash_fast_t), l_item);
            pthread_mutex_unlock(&l_srv->banlist_mutex);
            if (l_item) {   // client banned
                    l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_BANNED_PKEY_HASH ;
                    dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof(l_err));
                    if (l_usage->service->callbacks.response_error)
                            l_usage->service->callbacks.response_error(l_usage->service,l_usage->id, l_usage->client, &l_err, sizeof(l_err));
                    break;
                }
        } else {
            if (memcmp(l_usage->client_pkey_hash.raw, l_tx_out_cond->subtype.srv_pay.pkey_hash.raw, sizeof(l_usage->client_pkey_hash)) != 0) {
                l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_WRONG_PKEY_HASH ;
                dap_stream_ch_pkt_write_unsafe( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
                if (l_usage->service->callbacks.response_error)
                        l_usage->service->callbacks.response_error(l_usage->service,l_usage->id, l_usage->client,&l_err,sizeof (l_err) );
                break;
            }
        }

        // Update actual receipt
        bool l_is_first_sign = false;
        if (! l_usage->receipt_next && l_usage->receipt){
            DAP_DELETE(l_usage->receipt);
            l_usage->receipt = DAP_NEW_SIZE(dap_chain_datum_tx_receipt_t,l_receipt_size);
            l_is_first_sign = true;
            l_usage->is_active = true;
            memcpy( l_usage->receipt, l_receipt, l_receipt_size);
        } else if (l_usage->receipt_next ){
            DAP_DELETE(l_usage->receipt_next);
            l_usage->receipt_next = DAP_NEW_SIZE(dap_chain_datum_tx_receipt_t,l_receipt_size);
            l_usage->is_active = true;
            memcpy( l_usage->receipt_next, l_receipt, l_receipt_size);
        }

        // Store receipt if any problems with transactions
        char *l_receipt_hash_str;
        dap_get_data_hash_str_static(l_receipt, l_receipt_size, l_receipt_hash_str);
        dap_global_db_set("local.receipts", l_receipt_hash_str, l_receipt, l_receipt_size, false, NULL, NULL);
        size_t l_success_size;
        if (!l_usage->is_grace) {
            // Form input transaction
            char *l_hash_str = dap_hash_fast_to_str_new(&l_usage->tx_cond_hash);
            log_it(L_NOTICE, "Trying create input tx cond from tx %s with active receipt", l_hash_str);
            DAP_DEL_Z(l_hash_str);
            dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(l_usage->price->wallet, l_usage->net->pub.id);
            int ret_status = 0;
            char *l_tx_in_hash_str = dap_chain_mempool_tx_create_cond_input(l_usage->net, &l_usage->tx_cond_hash, l_wallet_addr,
                                                                            dap_chain_wallet_get_key(l_usage->price->wallet, 0),
                                                                            l_receipt, "hex", &ret_status);
            if (!ret_status) {
                dap_chain_hash_fast_from_str(l_tx_in_hash_str, &l_usage->tx_cond_hash);
                log_it(L_NOTICE, "Formed tx %s for input with active receipt", l_tx_in_hash_str);
                DAP_DELETE(l_tx_in_hash_str);
            }else{
                // TODO add ret status handling/ if tx not found start grace again
                dap_chain_net_srv_grace_t *l_grace = NULL;
                switch(ret_status){
                case DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_FIND_FINAL_TX_HASH:
                    // TX not found in ledger and we not in grace, start grace
                    log_it(L_ERROR, "Can't find tx cond. Start grace!");
//                    l_grace = DAP_NEW_Z(dap_chain_net_srv_grace_t);
                    // Parse the request
//                    l_grace->request = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_request_t, sizeof(dap_stream_ch_chain_net_srv_pkt_request_t));
//                    l_grace->request->hdr.net_id = l_usage->net->pub.id;
//                    memcpy(l_grace->request->hdr.token, l_usage->token_ticker, strlen(l_usage->token_ticker));
//                    l_grace->request->hdr.srv_uid = l_usage->service->uid;
//                    l_grace->request->hdr.tx_cond = l_usage->tx_cond_hash;
//                    l_ch_chain_net_srv->srv_uid.uint64 = l_grace->request->hdr.srv_uid.uint64;
//                    l_grace->request_size = l_ch_pkt->hdr.data_size;
//                    l_grace->ch_uuid = a_ch->uuid;
//                    l_grace->stream_worker = a_ch->stream_worker;
//                    s_grace_period_control(l_grace);
                    memset(&l_usage->tx_cond_hash, 0, sizeof(l_usage->tx_cond_hash));
                    DAP_DEL_Z(l_usage->receipt_next);
                    break;
                case DAP_CHAIN_MEMPOOl_RET_STATUS_NOT_ENOUGH:
                    // TODO send new tx cond request
                    memset(&l_usage->tx_cond_hash, 0, sizeof(l_usage->tx_cond_hash));
                    DAP_DEL_Z(l_usage->receipt_next);
                    log_it(L_ERROR, "Tx cond have not enough funds");
                    l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ENOUGH;
                    dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
//                    if (l_usage->service->callbacks.response_error)
//                            l_usage->service->callbacks.response_error(l_usage->service,l_usage->id, l_usage->client,&l_err,sizeof (l_err));
                    break;
                case DAP_CHAIN_MEMPOOL_RET_STATUS_BAD_ARGUMENTS:
                case DAP_CHAIN_MEMPOOl_RET_STATUS_WRONG_ADDR:
                case DAP_CHAIN_MEMPOOl_RET_STATUS_NOT_NATIVE_TOKEN:
                case DAP_CHAIN_MEMPOOl_RET_STATUS_NO_COND_OUT:
                case DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_TX_OUT:
                case DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_SIGN:
                default:
                    log_it(L_ERROR, "Can't create input tx cond transaction!");
                    memset(&l_usage->tx_cond_hash, 0, sizeof(l_usage->tx_cond_hash));
                    DAP_DEL_Z(l_usage->receipt_next);
                    l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_NOT_FOUND;
                    dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
                    if (l_usage->service->callbacks.response_error)
                            l_usage->service->callbacks.response_error(l_usage->service,l_usage->id, l_usage->client,&l_err,sizeof (l_err));
                    break;
                }


                break;
            }
            l_success_size = sizeof(dap_stream_ch_chain_net_srv_pkt_success_hdr_t) + DAP_CHAIN_HASH_FAST_STR_SIZE;//sizeof(dap_chain_hash_fast_t);
        } else {
            l_success_size = sizeof(dap_stream_ch_chain_net_srv_pkt_success_hdr_t);
        }
        dap_stream_ch_chain_net_srv_pkt_success_t *l_success = DAP_NEW_STACK_SIZE(dap_stream_ch_chain_net_srv_pkt_success_t,
                                                                              l_success_size);
        memset(&l_success->hdr, 0, sizeof(l_success->hdr));

        l_success->hdr.usage_id         = l_usage->id;
        l_success->hdr.net_id.uint64    = l_usage->net->pub.id.uint64;
        l_success->hdr.srv_uid.uint64   = l_usage->service->uid.uint64;

        if (l_usage->is_grace){
            char *l_hash_str = dap_hash_fast_to_str_new(&l_usage->tx_cond_hash);
            log_it(L_NOTICE, "Receipt is OK, but transaction %s can't be found. Start the grace period for %d seconds", l_hash_str,
                   l_srv->grace_period);
            DAP_DEL_Z(l_hash_str);
        }else {
            char *l_hash_str = dap_hash_fast_to_str_new(&l_usage->tx_cond_hash);
            memcpy(l_success->custom_data, l_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            DAP_DEL_Z(l_hash_str);
            log_it(L_NOTICE, "Receipt with remote client sign is acceptible for. Now start the service's usage");
        }

        dap_stream_ch_pkt_write_unsafe( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS,
                                       l_success, l_success_size);

        if ( l_is_first_sign && l_usage->service->callbacks.response_success){
            if( l_usage->service->callbacks.response_success(l_usage->service,l_usage->id,  l_usage->client,
                                                        l_receipt, l_receipt_size ) !=0 ){
                log_it(L_NOTICE, "No success by service success callback, inactivating service usage");
                l_usage->is_active = false;
            }
        } else if (l_usage->service->callbacks.receipt_next_success) {
            if (l_usage->service->callbacks.receipt_next_success(l_usage->service, l_usage->id, l_usage->client,
                                                        l_receipt, l_receipt_size ) != 0 ){
                log_it(L_NOTICE, "No success by service receipt_next callback, inactivating service usage");
                l_usage->is_active = false;
            }
        }
    } break;

    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_DATA: {
        if (l_ch_pkt->hdr.data_size < sizeof(dap_stream_ch_chain_net_srv_pkt_data_hdr_t) ){
            log_it( L_WARNING, "Wrong request size, less than minimum");
            break;
        }
        typedef dap_stream_ch_chain_net_srv_pkt_data_t pkt_t;
        pkt_t * l_pkt =(pkt_t *) l_ch_pkt->data;
        size_t l_pkt_size = l_ch_pkt->hdr.data_size - sizeof(pkt_t);
        dap_chain_net_srv_t * l_srv = dap_chain_net_srv_get( l_pkt->hdr.srv_uid);
        dap_chain_net_srv_usage_t * l_usage = l_srv_session->usage_active;//dap_chain_net_srv_usage_find_unsafe( l_srv_session, l_pkt->hdr.usage_id );
        // If service not found
        if ( l_srv == NULL){
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_NOT_FOUND ;
            l_err.srv_uid = l_pkt->hdr.srv_uid;
            dap_stream_ch_pkt_write_unsafe( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err) );
            break;
        }
        if (!l_srv->callbacks.custom_data)
            break;
        size_t l_out_data_size = 0;
        void *l_out_data = l_srv->callbacks.custom_data(l_srv, l_usage, l_pkt->data, l_pkt_size, &l_out_data_size);
        if (l_out_data && l_out_data_size) {
            pkt_t *l_data = DAP_NEW_STACK_SIZE(pkt_t, sizeof(pkt_t) + l_out_data_size);
            l_data->hdr.version     = 1;
            l_data->hdr.srv_uid     = l_srv->uid;
            l_data->hdr.usage_id    = l_pkt->hdr.usage_id;
            l_data->hdr.data_size   = l_out_data_size;
            memcpy(l_data->data, l_out_data, l_out_data_size);
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_DATA, l_data, sizeof(pkt_t) + l_out_data_size);
        }
    } break;

    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR:{
        if ( l_ch_pkt->hdr.data_size == sizeof (dap_stream_ch_chain_net_srv_pkt_error_t) ){
            dap_stream_ch_chain_net_srv_pkt_error_t * l_err = (dap_stream_ch_chain_net_srv_pkt_error_t *) l_ch_pkt->data;
            log_it( L_NOTICE, "Remote responsed with error code 0x%08X", l_err->code );
            // TODO code for service client mode
        }else{
            log_it(L_ERROR, "Wrong error response size, %u when expected %zu", l_ch_pkt->hdr.data_size,
                   sizeof ( dap_stream_ch_chain_net_srv_pkt_error_t) );
        }
    } break;
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NEW_TX_COND_RESPONSE:{
        dap_chain_net_srv_usage_t * l_usage = NULL;
        l_usage = l_srv_session->usage_active;
        dap_stream_ch_chain_net_srv_pkt_request_t* l_responce = (dap_stream_ch_chain_net_srv_pkt_request_t*)l_ch_pkt->data;
        l_usage->tx_cond_hash = l_responce->hdr.tx_cond;
        char *l_tx_in_hash_str = dap_chain_hash_fast_to_str_new(&l_usage->tx_cond_hash);
        log_it(L_NOTICE, "Received new tx cond %s", l_tx_in_hash_str);
        DAP_DELETE(l_tx_in_hash_str);
        size_t l_success_size = sizeof (dap_stream_ch_chain_net_srv_pkt_success_hdr_t );
        dap_stream_ch_chain_net_srv_pkt_success_t *l_success = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_success_t,
                                                                              l_success_size);
        l_success->hdr.usage_id = l_usage->id;
        l_success->hdr.net_id.uint64 = l_usage->net->pub.id.uint64;
        l_success->hdr.srv_uid.uint64 = l_usage->service->uid.uint64;
        dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS, l_success, l_success_size);
        DAP_DELETE(l_success);
    }break;
    default: log_it( L_WARNING, "Unknown packet type 0x%02X", l_ch_pkt->hdr.type);
    }
    if(l_ch_chain_net_srv->notify_callback)
        l_ch_chain_net_srv->notify_callback(l_ch_chain_net_srv, l_ch_pkt->hdr.type, l_ch_pkt, l_ch_chain_net_srv->notify_callback_arg);
}

/**
 * @brief s_stream_ch_packet_out
 * @param a_ch
 * @param a_arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t* a_ch , void* a_arg)
{
    (void) a_arg;

    dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
    // Callback should note that after write action it should restore write flag if it has more data to send on next iteration
    dap_chain_net_srv_call_write_all( a_ch);
}
