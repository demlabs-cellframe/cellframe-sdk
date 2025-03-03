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

#include "dap_chain_net_srv_stream_session.h"

#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_stream_ch_chain_net_srv_pkt.h"
#include "dap_stream_ch_proc.h"


#define LOG_TAG "dap_stream_ch_chain_net_srv"
#define SRV_PAY_GDB_GROUP "local.srv_pay"
#define SRV_STATISTIC_GDB_GROUP "local.srv_statistic"
#define SRV_RECEIPTS_GDB_GROUP "local.receipts"

// client statistic key struct
typedef struct client_statistic_key{
    char  key[18 + DAP_CHAIN_HASH_FAST_STR_SIZE];
} client_statistic_key_t;

typedef enum {
    PAY_SERVICE_STATUS_SUCCESS = 0,
    PAY_SERVICE_STATUS_NOT_ENOUGH,
    PAY_SERVICE_STATUS_TX_ERROR,
    PAY_SERVICE_STATUS_TX_CANT_FIND,
    PAY_SERVICE_STATUS_MEMALLOC_ERROR,
} pay_service_status;


// client statistic value struct
typedef struct client_statistic_value{
    struct {
        uint64_t using_time;
        uint256_t datoshi_value;
        uint64_t bytes_received;
        uint64_t bytes_sent;
        uint64_t units;
    } payed;
    struct {
        uint64_t using_time;
        uint64_t bytes_received;
        uint64_t bytes_sent;
        uint64_t units;
    } free;
    struct {
        uint64_t using_time;
        uint256_t datoshi_value;
        uint64_t bytes_received;
        uint64_t bytes_sent;
        uint64_t units;
        uint64_t using_count;
    } grace;
} client_statistic_value_t;

typedef struct receipt_sign_waiting_args {
    dap_stream_worker_t *worker;
    dap_stream_ch_uuid_t uuid;
    dap_chain_net_srv_usage_t *usage;
} receipt_sign_waiting_args_t;

static void s_stream_ch_new(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_delete(dap_stream_ch_t* ch , void* arg);
static void s_start_receipt_timeout_timer(dap_chain_net_srv_usage_t *a_usage);
static bool s_stream_ch_packet_in(dap_stream_ch_t* ch , void* arg);
static bool s_stream_ch_packet_out(dap_stream_ch_t* ch , void* arg);

static bool s_unban_client(dap_chain_net_srv_banlist_item_t *a_item);

static int s_pay_service(dap_chain_net_srv_usage_t *a_usage, dap_chain_datum_tx_receipt_t *a_receipt);

static bool s_service_start(dap_stream_ch_t *a_ch , dap_stream_ch_chain_net_srv_pkt_request_t *a_request, size_t a_request_size);
static bool s_grace_period_finish(dap_chain_net_srv_grace_usage_t *a_grace);
static void s_set_usage_data_to_gdb(const dap_chain_net_srv_usage_t *a_usage);
static uint256_t s_calc_datoshi(const dap_chain_net_srv_usage_t *a_usage, uint256_t *a_prev);

static int s_check_tx_params(dap_chain_net_srv_usage_t *a_usage);

/** Service states handlers **/
static void s_service_state_go_to_grace(dap_chain_net_srv_usage_t *a_usage);
static void s_service_state_go_to_normal(dap_chain_net_srv_usage_t *a_usage);
static void s_service_state_go_to_error(dap_chain_net_srv_usage_t *a_usage);
/*****************************/

/** Service substates handlers **/
static void s_service_substate_go_to_normal(dap_chain_net_srv_usage_t *a_usage);
static void s_service_substate_pay_service(dap_chain_net_srv_usage_t *a_usage);
static void s_service_substate_go_to_waiting_prev_tx(dap_chain_net_srv_usage_t *a_usage);
static void s_service_substate_go_to_waiting_new_tx(dap_chain_net_srv_usage_t *a_usage);
static void s_service_substate_go_to_error(dap_chain_net_srv_usage_t *a_usage);
/********************************/

/**
 * @brief dap_stream_ch_chain_net_init
 * @param a_srv - inited service
 * @return
 */
int dap_stream_ch_chain_net_srv_init(dap_chain_net_srv_t *a_srv)
{
    log_it(L_NOTICE,"Chain network services channel initialized");
    dap_stream_ch_proc_add(DAP_STREAM_CH_NET_SRV_ID, s_stream_ch_new,s_stream_ch_delete, s_stream_ch_packet_in, s_stream_ch_packet_out);
    pthread_mutex_init(&a_srv->grace_mutex, NULL);

    return 0;
}

/**
 * @brief dap_chain_ch_deinit
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
void s_stream_ch_delete(dap_stream_ch_t* a_ch , UNUSED_ARG void *a_arg)
{
// sanity check
    dap_return_if_pass(!a_ch);
// func work
    log_it(L_DEBUG, "Stream ch chain net srv delete");

    dap_chain_net_srv_stream_session_t * l_srv_session = a_ch && a_ch->stream && a_ch->stream->session ? (dap_chain_net_srv_stream_session_t *) a_ch->stream->session->_inheritor : NULL;
    dap_chain_net_srv_t * l_srv = l_srv_session && l_srv_session->usage_active ? dap_chain_net_srv_get(l_srv_session->usage_active->service->uid) : NULL;

    if (l_srv) {
        dap_chain_net_srv_usage_t *l_usage = dap_chain_net_srv_usage_find_unsafe(l_srv_session, l_srv_session->usage_active->id);
        s_set_usage_data_to_gdb(l_usage);
        l_srv->callbacks.save_remain_service(l_srv, l_srv_session->usage_active->id, l_srv_session->usage_active->client);
    }

    dap_chain_net_srv_call_closed_all(a_ch);
    if (a_ch->stream->session && a_ch->stream->session->_inheritor)
        dap_chain_net_srv_stream_session_delete(a_ch->stream->session );
    DAP_DEL_Z(a_ch->internal);
}

static bool s_unban_client(dap_chain_net_srv_banlist_item_t *a_item)
{
// sanity check
    dap_return_val_if_pass(!a_item, false);
// func work
    log_it(L_DEBUG, "Unban client");
    pthread_mutex_lock(a_item->ht_mutex);
    HASH_DEL(*(a_item->ht_head), a_item);
    pthread_mutex_unlock(a_item->ht_mutex);
    DAP_DELETE(a_item);
    return false;
}

static bool s_receipt_timeout_handler(dap_chain_net_srv_usage_t *a_usage)
{
    log_it(L_WARNING, "Waiting receipt signing from client timeout!");
    if (a_usage->receipt_sign_req_cnt < RECEIPT_SIGN_MAX_ATTEMPT - 1){
        // New attempt
        a_usage->receipt_sign_req_cnt++;
        log_it(L_WARNING, "Try to send receipt again. Attempt %d", a_usage->receipt_sign_req_cnt+1);
        if (a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN){
            dap_stream_ch_pkt_write_unsafe(a_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST,
                                       a_usage->receipt, a_usage->receipt->size);
            return true;
        } else if (a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEXT_RECEIPT_SIGN){
            dap_stream_ch_pkt_write_unsafe(a_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST,
                                       a_usage->receipt_next, a_usage->receipt_next->size);
            return true;
        }
    }
    log_it(L_WARNING, "Receipt signing by client max attempt is reached!");
    a_usage->receipt_sign_req_cnt = 0;

    if (a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN){
        a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_NO_SIGN;
        s_service_substate_go_to_error(a_usage);
    } else if (a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEXT_RECEIPT_SIGN){
        a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_NO_SIGN;
        s_service_substate_go_to_error(a_usage);
    }
    return false;
}

static void s_start_receipt_timeout_timer(dap_chain_net_srv_usage_t *a_usage)
{
    a_usage->receipts_timeout_timer = dap_timerfd_start_on_worker(dap_worker_get_current(), 10000,
                                                             (dap_timerfd_callback_t)s_receipt_timeout_handler, a_usage);
}
/**
 * @brief create string with usage service statistic
 * @return string with staticstic
 */
char *dap_stream_ch_chain_net_srv_create_statistic_report()
{
    size_t l_objs_count = 0;
    dap_string_t *l_ret = dap_string_new("Service report:\n");
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(SRV_STATISTIC_GDB_GROUP, &l_objs_count);
    for (size_t i = 0; i < l_objs_count; ++i) {
        if(l_objs[i].value_len != sizeof(client_statistic_value_t)) {
            log_it(L_ERROR, "Error size check statistic in %zu raw of %zu, expected value len %zu received %zu",
                                                    i + 1, l_objs_count, sizeof(client_statistic_value_t), l_objs[i].value_len);
            continue;
        }
        client_statistic_value_t *l_value = (client_statistic_value_t *)l_objs[i].value;
        char *l_payed_datoshi = dap_chain_balance_print(l_value->payed.datoshi_value);
        char *l_grace_datoshi = dap_chain_balance_print(l_value->grace.datoshi_value);
        dap_string_append_printf(
            l_ret, "SRV UID: %.18s\nClient pkey hash: %s\n "
            "\tpayed:\n\t\tusing time:\t\t%"DAP_UINT64_FORMAT_U"\n\t\tbytes sent:\t\t%"DAP_UINT64_FORMAT_U
                   "\n\t\tbytes received:\t\t%"DAP_UINT64_FORMAT_U"\n\t\tunits used:\t\t%"DAP_UINT64_FORMAT_U"\n\t\tdatoshi value:\t\t%s\n"
            "\tgrace:\n\t\tusing time:\t\t%"DAP_UINT64_FORMAT_U"\n\t\tbytes sent:\t\t%"DAP_UINT64_FORMAT_U
                   "\n\t\tbytes received:\t\t%"DAP_UINT64_FORMAT_U"\n\t\tunits used:\t\t%"DAP_UINT64_FORMAT_U"\n\t\tdatoshi value:\t\t%s\n"
            "\tfree:\n\t\tusing time:\t\t%"DAP_UINT64_FORMAT_U"\n\t\tbytes sent:\t\t%"DAP_UINT64_FORMAT_U
                   "\n\t\tbytes received:\t\t%"DAP_UINT64_FORMAT_U"\n\t\tunits used:\t\t%"DAP_UINT64_FORMAT_U"\n",
            l_objs[i].key, l_objs[i].key + 18,
            l_value->payed.using_time, l_value->payed.bytes_sent, l_value->payed.bytes_received, l_value->payed.units, l_payed_datoshi,
            l_value->grace.using_time, l_value->grace.bytes_sent, l_value->grace.bytes_received, l_value->grace.units, l_grace_datoshi,
            l_value->free.using_time, l_value->free.bytes_sent, l_value->free.bytes_received, l_value->free.units
        );
        DAP_DEL_Z(l_payed_datoshi);
        DAP_DEL_Z(l_grace_datoshi);
    }
    dap_global_db_objs_delete(l_objs, l_objs_count);
    return dap_string_free(l_ret, false);
}

void dap_stream_ch_chain_net_srv_tx_cond_added_cb(UNUSED_ARG void *a_arg, UNUSED_ARG dap_ledger_t *a_ledger,
                                                    dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, dap_chan_ledger_notify_opcodes_t a_opcode)
{
// sanity check
    dap_return_if_pass(!a_tx);
// func work
    if(a_opcode != DAP_LEDGER_NOTIFY_OPCODE_ADDED)
        return;
        
    dap_chain_net_srv_grace_usage_t *l_item = NULL;
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, NULL);
    if (!l_out_cond) {
        // log_it(L_ERROR, "Can't find dap_chain_tx_out_cond_t in dap_chain_datum_tx_t");
        return;
    }
    dap_chain_net_srv_t *l_net_srv = dap_chain_net_srv_get(l_out_cond->header.srv_uid);
    if (!l_net_srv) {
        log_it(L_ERROR, "Can't find dap_chain_net_srv_t uid 0x%016"DAP_UINT64_FORMAT_X"", l_out_cond->header.srv_uid.uint64);
        return;
    }
    pthread_mutex_lock(&l_net_srv->grace_mutex);
    HASH_FIND(hh, l_net_srv->grace_hash_tab, a_tx_hash, sizeof(dap_hash_fast_t), l_item);
    pthread_mutex_unlock(&l_net_srv->grace_mutex);
    if (l_item){
        log_it(L_INFO, "Found tx in ledger by notify. Finish grace.");
        // Stop timer
        dap_timerfd_delete_mt(l_item->grace->timer->worker, l_item->grace->timer->esocket_uuid);
        // finish grace
        HASH_DEL(l_net_srv->grace_hash_tab, l_item);
        
        l_item->grace->usage->tx_cond = a_tx;

        s_service_substate_pay_service(l_item->grace->usage);
        
        s_set_usage_data_to_gdb(l_item->grace->usage);
        DAP_DELETE(l_item->grace);
        DAP_DELETE(l_item);
    }
}

static bool s_service_start(dap_stream_ch_t *a_ch , dap_stream_ch_chain_net_srv_pkt_request_t *a_request, size_t a_request_size)
{
    assert(a_ch);
    dap_stream_ch_chain_net_srv_pkt_error_t l_err;
    memset(&l_err, 0, sizeof(l_err));
    dap_chain_net_srv_t *l_srv = NULL;

    dap_chain_net_srv_stream_session_t *l_srv_session = a_ch->stream && a_ch->stream->session ?
                                                        (dap_chain_net_srv_stream_session_t *)a_ch->stream->session->_inheritor : NULL;
    l_srv = dap_chain_net_srv_get( a_request->hdr.srv_uid );
    dap_chain_net_t * l_net = dap_chain_net_by_id( a_request->hdr.net_id );

    l_err.net_id.uint64 = a_request->hdr.net_id.uint64;
    l_err.srv_uid.uint64 = a_request->hdr.srv_uid.uint64;

    log_it(L_DEBUG, "Got service request from user %s", dap_chain_hash_fast_to_str_static(&a_request->hdr.client_pkey_hash));

    if (dap_hash_fast_is_blank(&a_request->hdr.order_hash)){
        log_it( L_ERROR, "No order hash in request.");
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_PRICE_NO_ORDER_HASH;
        if(a_ch)
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
        if (l_srv && l_srv->callbacks.response_error)
            l_srv->callbacks.response_error(l_srv, 0, NULL, &l_err, sizeof(l_err));
        return false;
    }

    if (dap_hash_fast_is_blank(&a_request->hdr.tx_cond)){
        log_it( L_ERROR, "No transaction hash in request.");
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_PRICE_NO_TX_HASH;
        if(a_ch)
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
        if (l_srv && l_srv->callbacks.response_error)
            l_srv->callbacks.response_error(l_srv, 0, NULL, &l_err, sizeof(l_err));
        return false;
    }

    char l_order_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = {};
    dap_chain_hash_fast_to_str(&a_request->hdr.order_hash, l_order_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
    log_it(L_MSG, "Got order with hash %s.", l_order_hash_str);

    if ( ! l_net ) {
        // Network not found
        log_it( L_ERROR, "Can't find net with id 0x%016"DAP_UINT64_FORMAT_x"", a_request->hdr.srv_uid.uint64);
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_NOT_FOUND;
        if(a_ch)
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
        if (l_srv && l_srv->callbacks.response_error)
            l_srv->callbacks.response_error(l_srv, 0, NULL, &l_err, sizeof(l_err));
        return false;
    }

    bool l_check_role = dap_chain_net_get_role(l_net).enums > NODE_ROLE_MASTER;  // check role
    if ( ! l_srv || l_check_role) // Service not found
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_NODE_ROLE_ERROR;

    if ( l_err.code || !l_srv_session){
        debug_if(
            l_check_role, L_ERROR,
            "You can't provide service with ID %" DAP_UINT64_FORMAT_U " in net %s. Node role should be not lower than master\n", l_srv ?
            l_srv->uid.uint64 : 0, l_net->pub.name
            );
        if(a_ch)
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
        if (l_srv && l_srv->callbacks.response_error)
            l_srv->callbacks.response_error(l_srv, 0, NULL, &l_err, sizeof(l_err));
        return false;
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
        return false;
    }

    l_err.usage_id = l_usage->id;
    // Create one client
    l_usage->client = DAP_NEW_Z( dap_chain_net_srv_client_remote_t);
    if (!l_usage->client) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_ALLOC_MEMORY_ERROR;
        if(a_ch)
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
        if (l_srv && l_srv->callbacks.response_error)
            l_srv->callbacks.response_error(l_srv, 0, NULL, &l_err, sizeof(l_err));
        dap_chain_net_srv_usage_delete(l_srv_session);
        return false;
    }
    l_usage->client->stream_worker = a_ch->stream_worker;
    l_usage->client->ch = a_ch;
    l_usage->client->session_id = a_ch->stream->session->id;
    l_usage->client->ts_created = time(NULL);
    l_usage->tx_cond_hash = a_request->hdr.tx_cond;
    l_usage->ts_created = time(NULL);
    l_usage->net = l_net;
    l_usage->service = l_srv;
    l_usage->client_pkey_hash = a_request->hdr.client_pkey_hash;
    l_usage->receipt_timeout_timer_start_callback = s_start_receipt_timeout_timer;
    l_usage->service_state = DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_IDLE;
    l_usage->service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_IDLE;

    dap_chain_net_srv_price_t * l_price = NULL;
    bool l_specific_order_free = false;
    l_price = dap_chain_net_srv_get_price_from_order(l_srv, "srv_vpn", &a_request->hdr.order_hash);
    if (!l_price){
        log_it(L_ERROR, "Can't get price from order!");
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_PRICE_ERROR;
        if(a_ch)
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
        if (l_srv && l_srv->callbacks.response_error)
            l_srv->callbacks.response_error(l_srv, 0, NULL, &l_err, sizeof(l_err));
        DAP_DEL_Z(l_usage->client);
        DAP_DEL_Z(l_usage);
        return false;
    }

    if (IS_ZERO_256(l_price->value_datoshi)){
        l_specific_order_free = true;
    }

    l_usage->price = l_price;

    if (!l_specific_order_free){
        // not free service
        log_it( L_INFO, "Valid pricelist is founded. Start service in pay mode.");

        if (dap_chain_net_get_state(l_net) == NET_STATE_OFFLINE) {
            log_it(L_ERROR, "Can't start service because net %s is offline.", l_net->pub.name);
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_IS_OFFLINE;
            if(a_ch)
                dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
            if (l_srv && l_srv->callbacks.response_error)
                l_srv->callbacks.response_error(l_srv, 0, NULL, &l_err, sizeof(l_err));
            dap_chain_net_srv_usage_delete(l_srv_session);
            return false;
        }

        l_usage->static_order_hash = a_request->hdr.order_hash;

        dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_usage->tx_cond_hash);
        // Check tx
        if (!l_tx){
            // Start grace
            dap_chain_net_srv_banlist_item_t *l_item = NULL;
            pthread_mutex_lock(&l_srv->banlist_mutex);
            HASH_FIND(hh, l_srv->ban_list, &l_usage->client_pkey_hash, sizeof(dap_chain_hash_fast_t), l_item);
            pthread_mutex_unlock(&l_srv->banlist_mutex);
            if (l_item) {   // client banned
                log_it(L_DEBUG, "Client %s is banned!", dap_chain_hash_fast_to_str_static(&l_usage->client_pkey_hash));
                l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_BANNED_PKEY_HASH;
                if(a_ch)
                    dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
                if (l_usage->service && l_usage->service->callbacks.response_error)
                    l_usage->service->callbacks.response_error(l_usage->service, 0, NULL, &l_err, sizeof(l_err));
                return false;
            }
            s_service_state_go_to_grace(l_usage);
        } else {
            l_usage->tx_cond = l_tx;
            s_service_substate_pay_service(l_usage);
        }
    } else if (l_specific_order_free && l_srv->allow_free_srv){
        // Start service for free
        log_it( L_INFO, "Can't find a valid pricelist. Service provide for free");
        l_usage->service_state = DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_FREE;
        size_t l_success_size = sizeof (dap_stream_ch_chain_net_srv_pkt_success_hdr_t );
        dap_stream_ch_chain_net_srv_pkt_success_t *l_success = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_success_t,
                                                                              l_success_size);
        if(!l_success) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_ALLOC_MEMORY_ERROR;
            if(a_ch)
                dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
            if (l_srv && l_srv->callbacks.response_error)
                l_srv->callbacks.response_error(l_srv, 0, NULL, &l_err, sizeof(l_err));
            return false;
        }
        l_success->hdr.usage_id = l_usage->id;
        l_success->hdr.net_id.uint64 = l_usage->net->pub.id.uint64;
        l_success->hdr.srv_uid.uint64 = l_usage->service->uid.uint64;
        dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS, l_success, l_success_size);
        if (l_usage->service->callbacks.response_success)
            l_usage->service->callbacks.response_success(l_usage->service, l_usage->id,  l_usage->client, NULL, 0);
        DAP_DELETE(l_success);
    }else {
        l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_FREE_IS_NOT_ALLOWED;
        log_it( L_INFO, "Free service sharing is not allowed. Service stop. If you want to share service for free switch on this function in configuration file.");
        dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof(l_err));
        if (l_srv && l_srv->callbacks.response_error)
            l_srv->callbacks.response_error(l_srv, 0, NULL, &l_err, sizeof(l_err));
    }
    return true;
}

/**
 * @brief calculating used datoshi price by pricelist
 * @param a_usage - usage data
 * @param a_prev - prev value, calced add to prev
 */
uint256_t s_calc_datoshi(const dap_chain_net_srv_usage_t *a_usage, uint256_t *a_prev)
{
    uint256_t l_ret = {0}, l_prev = {0}, l_datosi_used = {0};
    uint64_t l_used = 0;
    if (a_prev)
        l_prev = *a_prev;
    dap_return_val_if_fail(a_usage && a_usage->price, l_prev);
    switch(a_usage->price->units_uid.enm){
        case SERV_UNIT_SEC:
            l_used = dap_time_now() - a_usage->ts_created;
            break;
        case SERV_UNIT_B:
            l_used = a_usage->client->bytes_received + a_usage->client->bytes_sent;
            break;
    }
    MULT_256_256(a_usage->price->value_datoshi, GET_256_FROM_64(l_used), &l_ret);
    DIV_256(l_ret, GET_256_FROM_64(a_usage->price->units), &l_datosi_used);
    SUM_256_256(l_prev, l_datosi_used, &l_ret);
    return l_ret;
}

/**
 * @brief set usage data to local GDB group
 * @param a_usage - usage data
 */
void s_set_usage_data_to_gdb(const dap_chain_net_srv_usage_t *a_usage)
{
// sanity check
    dap_return_if_pass(!a_usage);
// func work
    client_statistic_key_t l_bin_key = {0};
    client_statistic_value_t l_bin_value_new = {0};
    size_t l_value_size = 0;
    // forming key
    snprintf(l_bin_key.key, sizeof(l_bin_key.key), "0x%016"DAP_UINT64_FORMAT_X"", a_usage->service->uid.uint64);
    dap_chain_hash_fast_to_str_do(&a_usage->client_pkey_hash, l_bin_key.key + 18);
    // check writed value
    client_statistic_value_t *l_bin_value = (client_statistic_value_t *)dap_global_db_get_sync(SRV_STATISTIC_GDB_GROUP, l_bin_key.key, &l_value_size, NULL, NULL);
    if (l_bin_value && l_value_size != sizeof(client_statistic_value_t)) {
        log_it(L_ERROR, "Wrong srv client_statistic size in GDB. Expecting %zu, getted %zu", sizeof(client_statistic_value_t), l_value_size);
        //dap_global_db_set(SRV_STATISTIC_GDB_GROUP, l_bin_key.key, &l_bin_value_new, sizeof(client_statistic_value_t), false, NULL, NULL); value size update
        DAP_DEL_Z(l_bin_value);
        return;
    }
    if (l_bin_value) {
        l_bin_value_new = *l_bin_value;
    }
    // forming new data
    if (a_usage->service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE) {
        l_bin_value_new.grace.using_count += 1;
        l_bin_value_new.grace.using_time += dap_time_now() - a_usage->ts_created;
        l_bin_value_new.grace.bytes_received += a_usage->client->bytes_received;
        l_bin_value_new.grace.bytes_sent += a_usage->client->bytes_sent;
        l_bin_value_new.grace.datoshi_value = s_calc_datoshi(a_usage, l_bin_value ? &l_bin_value->grace.datoshi_value : NULL);
    } else if (a_usage->service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_FREE) {
        l_bin_value_new.free.using_time += dap_time_now() - a_usage->ts_created;
        l_bin_value_new.free.bytes_received += a_usage->client->bytes_received;
        l_bin_value_new.free.bytes_sent += a_usage->client->bytes_sent;
    } else if (a_usage->is_active) {
        l_bin_value_new.payed.using_time += dap_time_now() - a_usage->ts_created;
        l_bin_value_new.payed.bytes_received += a_usage->client->bytes_received;
        l_bin_value_new.payed.bytes_sent += a_usage->client->bytes_sent;
        l_bin_value_new.payed.datoshi_value = s_calc_datoshi(a_usage, l_bin_value ? &l_bin_value->payed.datoshi_value : NULL);
    }
    dap_global_db_set(SRV_STATISTIC_GDB_GROUP, l_bin_key.key, &l_bin_value_new, sizeof(client_statistic_value_t), false, NULL, NULL);

    DAP_DEL_Z(l_bin_value);
}

static bool s_grace_period_finish(dap_chain_net_srv_grace_usage_t *a_grace_item)
{
    dap_return_val_if_pass(!a_grace_item || !a_grace_item->grace, false);

    dap_chain_net_srv_t *l_srv = dap_chain_net_srv_get(a_grace_item->grace->usage->service->uid);
    pthread_mutex_lock(&l_srv->grace_mutex);
    HASH_DEL(l_srv->grace_hash_tab, a_grace_item);
    pthread_mutex_lock(&l_srv->grace_mutex);

    s_service_substate_pay_service(a_grace_item->grace->usage);
    DAP_DEL_Z(a_grace_item->grace);
    DAP_DEL_Z(a_grace_item);
    
    return false;
}

/**
 * @brief s_stream_ch_packet_in
 * @param ch
 * @param arg
 */
static bool s_stream_ch_packet_in(dap_stream_ch_t *a_ch, void *a_arg)
{
    dap_stream_ch_pkt_t *l_ch_pkt = (dap_stream_ch_pkt_t *)a_arg;
    if (!l_ch_pkt)
        return false;
    dap_chain_net_srv_stream_session_t *l_srv_session = NULL;
    if (a_ch) {
        l_srv_session = a_ch->stream && a_ch->stream->session ? a_ch->stream->session->_inheritor : NULL;
    }
    if (!l_srv_session) {
        log_it( L_ERROR, "Not defined service session, switching off packet input process");
        dap_stream_ch_set_ready_to_read_unsafe(a_ch, false);
        return false;
    }

    dap_stream_ch_chain_net_srv_t * l_ch_chain_net_srv = DAP_STREAM_CH_CHAIN_NET_SRV(a_ch);
    if (l_ch_chain_net_srv->notify_callback) {
        l_ch_chain_net_srv->notify_callback(l_ch_chain_net_srv, l_ch_pkt->hdr.type, l_ch_pkt, l_ch_chain_net_srv->notify_callback_arg);
        return false; // It's a client behind this
    }
    dap_stream_ch_chain_net_srv_pkt_error_t l_err = { };
    switch (l_ch_pkt->hdr.type) {
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_REQUEST: {
        typedef dap_stream_ch_chain_net_srv_pkt_test_t pkt_test_t;
        if (l_ch_pkt->hdr.data_size < sizeof(pkt_test_t)) {
            log_it(L_WARNING, "Wrong CHECK_REQUEST size %u, must be at least %zu", l_ch_pkt->hdr.data_size, sizeof(pkt_test_t));
            return false;
        }
        pkt_test_t *l_request = (pkt_test_t*)l_ch_pkt->data;
        if (dap_chain_net_srv_get(l_request->srv_uid) == NULL){
            log_it(L_WARNING, "Can't find service with id %"DAP_UINT64_FORMAT_U, l_request->srv_uid.uint64);
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_NOT_FOUND;
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof(l_err));
            return false;
        }

        if (l_request->data_size_recv > DAP_CHAIN_NET_SRV_CH_REQUEST_SIZE_MAX || l_request->data_size > DAP_CHAIN_NET_SRV_CH_REQUEST_SIZE_MAX) {
            log_it(L_WARNING, "Too large payload %zu [pkt seq %"DAP_UINT64_FORMAT_U"]", l_request->data_size_recv, l_ch_pkt->hdr.seq_id);
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_BIG_SIZE;
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof(l_err));
            return false;
        }
        size_t l_request_size = l_request->data_size + sizeof(pkt_test_t);
        if (l_ch_pkt->hdr.data_size != l_request_size) {
            log_it(L_WARNING, "Wrong CHECK_REQUEST size %u, must be %zu [pkt seq %"DAP_UINT64_FORMAT_U"]", l_ch_pkt->hdr.data_size, l_request_size, l_ch_pkt->hdr.seq_id);
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_WRONG_SIZE;
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof(l_err));
            return false;
        }
        dap_chain_hash_fast_t l_data_hash;
        dap_hash_fast(l_request->data, l_request->data_size, &l_data_hash); // TODO change it to less CPU consuming algorithm
        if (l_request->data_size > 0 && !dap_hash_fast_compare(&l_data_hash, &l_request->data_hash)) {
            log_it(L_WARNING, "Wrong hash [pkt seq %"DAP_UINT64_FORMAT_U"]", l_ch_pkt->hdr.seq_id);
            l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_WRONG_HASH;
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof(l_err));
            return false;
        }
        /* No need for bare copying, resend it back modified */
        if (l_request->data_size_recv) {
            l_request->data_size = l_request->data_size_recv;
            if (!l_request->data_size_send){
                l_request = DAP_NEW_Z_SIZE(pkt_test_t, sizeof(pkt_test_t) + l_request->data_size);
                *l_request = *(pkt_test_t*)l_ch_pkt->data;
            }

            randombytes(l_request->data, l_request->data_size);
            dap_hash_fast_t l_data_hash;
            dap_hash_fast(l_request->data, l_request->data_size, &l_data_hash);
            l_request->data_hash = l_data_hash;

        }
        l_request->err_code = 0;

        dap_strncpy(l_request->host_send, a_ch->stream->esocket->remote_addr_str, DAP_HOSTADDR_STRLEN);
        l_request->recv_time2 = dap_nanotime_now();

        dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_RESPONSE, l_request,
                                       l_request->data_size + sizeof(pkt_test_t));
        if(l_request != (pkt_test_t*)l_ch_pkt->data){
            DAP_DELETE(l_request);
        }

    } break; /* DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_REQUEST */

    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST: { //Service request
        if (l_ch_pkt->hdr.data_size < sizeof(dap_stream_ch_chain_net_srv_pkt_request_hdr_t) ){
            log_it( L_WARNING, "Wrong request size %u, less than minimum %zu", l_ch_pkt->hdr.data_size, sizeof(dap_stream_ch_chain_net_srv_pkt_request_hdr_t));
            return false;
        }
        dap_stream_ch_chain_net_srv_pkt_request_t *l_request = (dap_stream_ch_chain_net_srv_pkt_request_t*)l_ch_pkt->data;
        l_ch_chain_net_srv->srv_uid.uint64 = l_request->hdr.srv_uid.uint64;
        s_service_start(a_ch, l_request, l_ch_pkt->hdr.data_size);
    } break; /* DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST */

    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_RESPONSE: { // Check receipt sign and make tx if success
        dap_chain_net_srv_usage_t * l_usage = l_srv_session->usage_active;
        if (! l_usage ){
            log_it(L_WARNING, "No usage in srv.");
            l_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_NOT_FOUND;
            s_service_substate_go_to_error(l_usage);
            break;
        }

        if (l_usage->service_substate != DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN &&
            l_usage->service_substate != DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEXT_RECEIPT_SIGN){
            // wrong responce
            break;
        }

        if (l_usage->receipts_timeout_timer){
            log_it(L_INFO, "Delete receipt timeout timer.");
            dap_timerfd_delete_unsafe(l_usage->receipts_timeout_timer);
            l_usage->receipts_timeout_timer = NULL;
        } 

        if (dap_chain_net_get_state(l_usage->net) == NET_STATE_OFFLINE) {
            log_it(L_ERROR, "Can't pay service because net %s is offline.", l_usage->net->pub.name);
            l_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_IS_OFFLINE;
            s_service_substate_go_to_error(l_usage);
            return false;
        }

        if (l_ch_pkt->hdr.data_size < sizeof(dap_chain_receipt_info_t)) {
            log_it(L_ERROR, "Wrong sign response size, %u when expected at least %zu with smth", l_ch_pkt->hdr.data_size,
                   sizeof(dap_chain_receipt_info_t));
            if ( l_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEXT_RECEIPT_SIGN){ // If we have receipt next
                DAP_DEL_Z(l_usage->receipt_next);
            }else if (l_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN){ // If we sign first receipt
                DAP_DEL_Z(l_usage->receipt);
            }
            return false;
        }
        dap_chain_datum_tx_receipt_t * l_receipt = (dap_chain_datum_tx_receipt_t *) l_ch_pkt->data;
        // TODO calculate actual receipt size and compare it with provided packet size
        size_t l_receipt_size = l_ch_pkt->hdr.data_size;

        bool l_is_found = false;
        if (l_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEXT_RECEIPT_SIGN){ // If we have receipt next
            if ( memcmp(&l_usage->receipt_next->receipt_info, &l_receipt->receipt_info,sizeof (l_receipt->receipt_info) )==0 ){
                l_is_found = true;
            }
        }else if (l_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN){ // If we sign first receipt
            if ( memcmp(&l_usage->receipt->receipt_info, &l_receipt->receipt_info,sizeof (l_receipt->receipt_info) )==0 ){
                l_is_found = true;
            }
        }
        if ( !l_is_found || ! l_usage ){
            log_it(L_WARNING, "Can't find receipt in usages thats equal to response receipt");
            l_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_CANT_FIND;
            s_service_substate_go_to_error(l_usage);
            break;
        }
        l_err.usage_id = l_usage->id;
        l_err.net_id.uint64 = l_usage->net->pub.id.uint64;
        l_err.srv_uid.uint64 = l_usage->service->uid.uint64;

        dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
        if ( ! l_usage->tx_cond ){
            log_it(L_WARNING, "No tx cond in usage");
            l_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND;
            s_service_substate_go_to_error(l_usage);
            break;
        }
        l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_usage->tx_cond, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, NULL );
        if ( ! l_tx_out_cond ){ // No condition output
            l_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_COND_OUT;
            s_service_substate_go_to_error(l_usage);
            break;
        }
        // get a second signature - from the client (first sign in server, second sign in client)
        dap_sign_t * l_receipt_sign = dap_chain_datum_tx_receipt_sign_get( l_receipt, l_receipt_size, 1);
        if ( ! l_receipt_sign ){
            l_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_NO_SIGN;
            s_service_substate_go_to_error(l_usage);
            break;
        }
        // Check receipt signature pkey hash
        dap_chain_net_srv_t * l_srv = dap_chain_net_srv_get(l_receipt->receipt_info.srv_uid);
        if (memcmp(l_usage->client_pkey_hash.raw, l_tx_out_cond->subtype.srv_pay.pkey_hash.raw, sizeof(l_usage->client_pkey_hash)) != 0) {
            l_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_WRONG_PKEY_HASH;
            s_service_substate_go_to_error(l_usage);
            break;
        }

        // Update actual receipt
        if (l_usage->receipt && l_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN) {
            DAP_DELETE(l_usage->receipt);
            l_usage->receipt = DAP_DUP_SIZE(l_receipt, l_receipt_size);
            if (!l_usage->receipt) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_ALLOC_MEMORY_ERROR;
                s_service_substate_go_to_error(l_usage);
                break;
            }
        } else if (l_usage->receipt_next && l_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEXT_RECEIPT_SIGN) {
            DAP_DELETE(l_usage->receipt_next);
            l_usage->receipt_next = DAP_DUP_SIZE(l_receipt, l_receipt_size);
            if (!l_usage->receipt_next) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                l_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_ALLOC_MEMORY_ERROR;
                s_service_substate_go_to_error(l_usage);
                break;
            }
        }

        s_service_substate_pay_service(l_usage);
        size_t l_success_size;
        l_success_size = sizeof(dap_stream_ch_chain_net_srv_pkt_success_hdr_t) + DAP_CHAIN_HASH_FAST_STR_SIZE;
        dap_stream_ch_chain_net_srv_pkt_success_t *l_success = DAP_NEW_STACK_SIZE(dap_stream_ch_chain_net_srv_pkt_success_t, l_success_size);
        l_success->hdr = (dap_stream_ch_chain_net_srv_pkt_success_hdr_t) {
                .usage_id   = l_usage->id,
                .net_id     = l_usage->net->pub.id,
                .srv_uid    = l_usage->service->uid
        };


        // TODO move messages below to their handlers
        char *l_hash_str = NULL;
        char *l_user_key = NULL;
        switch (l_usage->service_substate){
            case DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_FROM_CLIENT:
                l_hash_str = dap_chain_hash_fast_to_str_new(&l_usage->tx_cond_hash);
                l_user_key = dap_chain_hash_fast_to_str_new(&l_usage->client_pkey_hash);
                log_it(L_NOTICE, "Receipt is OK, but tx %s have no enough funds. New tx cond requested. Start the grace period for %d seconds for user %s", l_hash_str,
                                                                                    l_srv->grace_period, l_user_key);
                DAP_DELETE(l_hash_str);
                DAP_DELETE(l_user_key);
            break;
            case DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_TX_FOR_PAYING:
                l_hash_str = dap_chain_hash_fast_to_str_new(&l_usage->tx_cond_hash);
                l_user_key = dap_chain_hash_fast_to_str_new(&l_usage->client_pkey_hash);
                log_it(L_NOTICE, "Receipt is OK, but tx %s can't be found. Start the grace period for %d seconds for user %s", l_hash_str,
                                                                                    l_srv->grace_period, l_user_key);
                DAP_DELETE(l_hash_str);
                DAP_DELETE(l_user_key);
            break;
            case DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_NORMAL:
                l_user_key = dap_chain_hash_fast_to_str_new(&l_usage->client_pkey_hash);
                log_it(L_NOTICE, "Receipt with client %s sign is accepted, start service providing", l_user_key);
                DAP_DELETE(l_user_key);
            break;
            default:
                return false;
        }

        dap_stream_ch_pkt_write_unsafe( a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS,
                                       l_success, l_success_size);

    } break;

    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_DATA: {
        typedef dap_stream_ch_chain_net_srv_pkt_data_t pkt_t;
        if (l_ch_pkt->hdr.data_size < sizeof(pkt_t)) {
            log_it( L_WARNING, "Wrong request size %u, less than minimum %zu", l_ch_pkt->hdr.data_size, sizeof(pkt_t));
            return false;
        }
        pkt_t * l_pkt =(pkt_t *) l_ch_pkt->data;
        size_t l_pkt_size = l_ch_pkt->hdr.data_size - sizeof(pkt_t);
        if (l_pkt_size != l_pkt->hdr.data_size) {
            log_it( L_WARNING, "Wrong request size %zu, expected %hu", l_pkt_size, l_pkt->hdr.data_size);
            return false;
        }
        dap_chain_net_srv_t * l_srv = dap_chain_net_srv_get( l_pkt->hdr.srv_uid);
        dap_chain_net_srv_usage_t * l_usage = l_srv_session->usage_active;
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
            l_data->hdr = (dap_stream_ch_chain_net_srv_pkt_data_hdr_t) {
                    .version    = 1,
                    .data_size  = l_out_data_size,
                    .usage_id   = l_pkt->hdr.usage_id,
                    .srv_uid    = l_srv->uid
            };
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
            return false;
        }
    } break;
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NEW_TX_COND_RESPONSE:{
        if (l_ch_pkt->hdr.data_size != sizeof(dap_stream_ch_chain_net_srv_pkt_request_hdr_t) ){
            log_it( L_WARNING, "Wrong request size %u, expected %zu",
                            l_ch_pkt->hdr.data_size, sizeof(dap_stream_ch_chain_net_srv_pkt_request_hdr_t));
            return false;
        }
        dap_chain_net_srv_usage_t * l_usage = NULL;
        l_usage = l_srv_session->usage_active;
        dap_stream_ch_chain_net_srv_pkt_request_t* l_responce = (dap_stream_ch_chain_net_srv_pkt_request_t*)l_ch_pkt->data;
        log_it(L_NOTICE, "Received new tx cond %s", dap_chain_hash_fast_to_str_static(&l_responce->hdr.tx_cond));

        if (l_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_FROM_CLIENT){
            dap_stream_ch_chain_net_srv_pkt_error_t l_err = { };
            dap_chain_net_srv_t *l_srv = dap_chain_net_srv_get(l_responce->hdr.srv_uid);
            dap_chain_net_srv_grace_usage_t *l_curr_grace_item = NULL;
            pthread_mutex_lock(&l_srv->grace_mutex);
            HASH_FIND(hh, l_srv->grace_hash_tab, &l_usage->tx_cond_hash, sizeof(dap_hash_fast_t), l_curr_grace_item);
            pthread_mutex_unlock(&l_srv->grace_mutex);

            if (l_curr_grace_item){
                if (dap_hash_fast_is_blank(&l_responce->hdr.tx_cond)){ //if new tx cond creation failed tx_cond in responce will be blank
                        HASH_DEL(l_srv->grace_hash_tab, l_curr_grace_item);
                        dap_timerfd_delete_mt(l_curr_grace_item->grace->timer->worker, l_curr_grace_item->grace->timer->esocket_uuid);
                        l_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_NEW_COND;
                        s_service_substate_go_to_error(l_usage);
                        DAP_DEL_Z(l_curr_grace_item);
                    break;
                }

                l_usage->tx_cond_hash = l_responce->hdr.tx_cond;
                if (dap_ledger_tx_find_by_hash(l_usage->net->pub.ledger, &l_usage->tx_cond_hash)){
                    pthread_mutex_lock(&l_srv->grace_mutex);
                    HASH_DEL(l_srv->grace_hash_tab, l_curr_grace_item);
                    DAP_DEL_Z(l_curr_grace_item->grace);
                    DAP_DEL_Z(l_curr_grace_item);
                    pthread_mutex_unlock(&l_srv->grace_mutex);
                    s_service_substate_pay_service(l_usage);
                } else {
                    l_usage->service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_IN_LEDGER;
                    log_it(L_NOTICE, "Can't find newtx cond %s in ledger. Waiting...", dap_chain_hash_fast_to_str_static(&l_responce->hdr.tx_cond));
                    pthread_mutex_lock(&l_srv->grace_mutex);
                    HASH_DEL(l_srv->grace_hash_tab, l_curr_grace_item);
                    l_curr_grace_item->tx_cond_hash = l_usage->tx_cond_hash;
                    HASH_ADD(hh, l_usage->service->grace_hash_tab, tx_cond_hash, sizeof(dap_hash_fast_t), l_curr_grace_item);
                    pthread_mutex_unlock(&l_srv->grace_mutex);
                }
            }
            
            size_t l_success_size = sizeof (dap_stream_ch_chain_net_srv_pkt_success_hdr_t );
            dap_stream_ch_chain_net_srv_pkt_success_t *l_success = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_success_t,
                                                                                l_success_size);
            if(!l_success) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                break;
            }
            l_success->hdr.usage_id = l_usage->id;
            l_success->hdr.net_id.uint64 = l_usage->net->pub.id.uint64;
            l_success->hdr.srv_uid.uint64 = l_usage->service->uid.uint64;
            dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS, l_success, l_success_size);
            DAP_DELETE(l_success);  
        } else {
            log_it(L_NOTICE, "No new transaction expected. Exit.");
        }

    } break;
    default:
        log_it( L_WARNING, "Unknown packet type 0x%02X", l_ch_pkt->hdr.type);
        return false;
    }
    if(l_ch_chain_net_srv->notify_callback)
        l_ch_chain_net_srv->notify_callback(l_ch_chain_net_srv, l_ch_pkt->hdr.type, l_ch_pkt, l_ch_chain_net_srv->notify_callback_arg);
    return true;
}

/**
 * @brief s_stream_ch_packet_out
 * @param a_ch
 * @param a_arg
 */
static bool s_stream_ch_packet_out(dap_stream_ch_t* a_ch , void* a_arg)
{
    dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
    // Callback should note that after write action it should restore write flag if it has more data to send on next iteration
    dap_chain_net_srv_call_write_all( a_ch);
    return false;
}


static int s_pay_service(dap_chain_net_srv_usage_t *a_usage, dap_chain_datum_tx_receipt_t *a_receipt)
{
    char *l_hash_str = dap_hash_fast_to_str_new(&a_usage->tx_cond_hash);
    log_it(L_NOTICE, "Trying create input tx cond from tx %s with active receipt", l_hash_str);
    DAP_DEL_Z(l_hash_str);
    int ret_status = 0;
    char *l_tx_in_hash_str = dap_chain_mempool_tx_create_cond_input(a_usage->net, &a_usage->tx_cond_hash, a_usage->price->wallet_addr,
                                                                        a_usage->price->receipt_sign_cert->enc_key, a_receipt, "hex", &ret_status);
    switch (ret_status){
        case DAP_CHAIN_MEMPOOl_RET_STATUS_SUCCESS:
            dap_chain_hash_fast_from_str(l_tx_in_hash_str, &a_usage->tx_cond_hash);
            log_it(L_NOTICE, "Formed tx %s for input with active receipt", l_tx_in_hash_str);
            DAP_DEL_Z(l_tx_in_hash_str);
            return PAY_SERVICE_STATUS_SUCCESS;
        case DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_FIND_FINAL_TX_HASH:
        case DAP_CHAIN_MEMPOOl_RET_STATUS_NO_COND_OUT:{
            dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_usage->net->pub.ledger, &a_usage->tx_cond_hash);
            if (l_tx){
                // TODO check tx have cont in with right service
                int l_out_cond_idx = 0;
                dap_chain_tx_out_cond_t *l_out_cond = NULL;
                dap_chain_tx_in_cond_t *l_in_cond = (dap_chain_tx_in_cond_t*)dap_chain_datum_tx_item_get(l_tx, &l_out_cond_idx, NULL, TX_ITEM_TYPE_IN_COND, NULL);
                if (l_in_cond){
                    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_usage->net->pub.ledger, &l_in_cond->header.tx_prev_hash);
                    if (l_prev_tx){
                        l_out_cond = (dap_chain_tx_out_cond_t*)dap_chain_datum_tx_item_get_nth(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, l_in_cond->header.tx_out_prev_idx);
                        if (l_out_cond && l_out_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY)
                            l_out_cond = NULL;
                    }
                }
                if (!l_out_cond) {
                    log_it(L_WARNING, "Requested conditioned transaction have no conditioned output for servcie paying.");
                    return PAY_SERVICE_STATUS_TX_ERROR;
                } else {
                    return PAY_SERVICE_STATUS_NOT_ENOUGH;
                }
            }else 
                return PAY_SERVICE_STATUS_TX_ERROR;
        }break;
        case DAP_CHAIN_MEMPOOl_RET_STATUS_NOT_ENOUGH:{
            return PAY_SERVICE_STATUS_NOT_ENOUGH;
        }break;
        case DAP_CHAIN_MEMPOOL_RET_STATUS_BAD_ARGUMENTS:
        case DAP_CHAIN_MEMPOOl_RET_STATUS_WRONG_ADDR:
        case DAP_CHAIN_MEMPOOl_RET_STATUS_NOT_NATIVE_TOKEN:
        case DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_TX_OUT:
        case DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_SIGN:
        default:  
            return PAY_SERVICE_STATUS_TX_ERROR;
    }
}

static void s_service_state_go_to_grace(dap_chain_net_srv_usage_t *a_usage)
{
    if (!a_usage)
        return;

    assert(a_usage->service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_IDLE);

    a_usage->service_state = DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE;
    if (a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_IDLE){
        char* l_hash_str = dap_chain_hash_fast_to_str_new(&a_usage->tx_cond_hash);
        char* l_user_key = dap_chain_hash_fast_to_str_new(&a_usage->client_pkey_hash);
        log_it(L_NOTICE, "Tx %s can't be found. Start the grace period for %d seconds for user %s", l_hash_str,
                                                                            a_usage->service->grace_period, l_user_key);
        DAP_DELETE(l_hash_str);
        DAP_DELETE(l_user_key);
        s_service_substate_go_to_waiting_prev_tx(a_usage);
        if(a_usage->client->ch){
            size_t l_success_size = sizeof (dap_stream_ch_chain_net_srv_pkt_success_hdr_t );
            dap_stream_ch_chain_net_srv_pkt_success_t *l_success = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_success_t,
                                                                                l_success_size);
            if(!l_success) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                s_service_substate_go_to_error(a_usage);
                return;
            }
            l_success->hdr.usage_id = a_usage->id;
            l_success->hdr.net_id.uint64 = a_usage->net->pub.id.uint64;
            l_success->hdr.srv_uid.uint64 = a_usage->service->uid.uint64;
            dap_stream_ch_pkt_write_unsafe(a_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS,
                                   l_success, l_success_size);
            DAP_DEL_Z(l_success);
        }
    } else if(a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN){
        char* l_hash_str = dap_chain_hash_fast_to_str_new(&a_usage->tx_cond_hash);
        char* l_user_key = dap_chain_hash_fast_to_str_new(&a_usage->client_pkey_hash);
        log_it(L_NOTICE, "Receipt is OK, but tx %s have no enough funds. New tx cond requested. Start the grace period for %d seconds for user %s", l_hash_str,
                                                                            a_usage->service->grace_period, l_user_key);
        DAP_DELETE(l_hash_str);
        DAP_DELETE(l_user_key);
        s_service_substate_go_to_waiting_new_tx(a_usage);
    } else {
        log_it(L_ERROR, "Wrong substate to start grace");
        a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_REQUEST_INTERNAL_ERROR;
        s_service_substate_go_to_error(a_usage);
    }

    if (a_usage->service->callbacks.response_success){
        if( a_usage->service->callbacks.response_success(a_usage->service,a_usage->id,  a_usage->client,
                        NULL, 0) !=0 ){
            log_it(L_NOTICE, "No success by service success callback, inactivating service usage");
            a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_REQUEST_INTERNAL_ERROR;
            s_service_substate_go_to_error(a_usage);
            return;
        }
    } else {
        a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_REQUEST_INTERNAL_ERROR;
        s_service_substate_go_to_error(a_usage);
        return;
    }
}

static void s_service_state_go_to_normal(dap_chain_net_srv_usage_t *a_usage)
{
    if (!a_usage)
        return;
   
    if (a_usage->service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_IDLE ||
        (a_usage->service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE && 
        a_usage->service_substate != DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_TX_FOR_PAYING)){
        // start with remain limits
        a_usage->service_state = DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_NORMAL;
        if (a_usage->service->callbacks.response_success){
            if( a_usage->service->callbacks.response_success(a_usage->service,a_usage->id,  a_usage->client,
                a_usage->receipt, a_usage->receipt->size) !=0 ){

                log_it(L_NOTICE, "No success by service success callback, inactivating service usage");
                a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_REQUEST_INTERNAL_ERROR;
                s_service_substate_go_to_error(a_usage);
                return;
            }
        } else {
            log_it(L_NOTICE, "No success callback in usage.");
            a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_REQUEST_INTERNAL_ERROR;
            s_service_substate_go_to_error(a_usage);
            return;
        }

    }  else if ((a_usage->service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE && 
        a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_TX_FOR_PAYING)) {
        a_usage->service_state = DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_NORMAL;
    } else {
        log_it(L_ERROR, "Wrong previous state for going to normal state.");
        a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_UNDEFINED;
        s_service_state_go_to_error(a_usage);
        return;
    }
    a_usage->service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_NORMAL;
}

static void s_service_state_go_to_error(dap_chain_net_srv_usage_t *a_usage)
{
    if (!a_usage){
        return;
    }

    a_usage->is_active = 0;

    dap_stream_ch_t * l_ch = dap_stream_ch_find_by_uuid_unsafe(a_usage->client->ch->stream_worker, a_usage->client->ch->uuid);
    dap_chain_net_srv_stream_session_t *l_srv_session = l_ch && l_ch->stream && l_ch->stream->session ?
                                        (dap_chain_net_srv_stream_session_t *)l_ch->stream->session->_inheritor : NULL;

    if (a_usage->last_err_code) {
        if(l_ch)
            dap_stream_ch_pkt_write_unsafe(l_ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &a_usage->last_err_code, sizeof (a_usage->last_err_code));
        if (a_usage->service && a_usage->service->callbacks.response_error)
            a_usage->service->callbacks.response_error(a_usage->service, 0, NULL, &a_usage->last_err_code, sizeof(a_usage->last_err_code));
    }

    if (a_usage && a_usage->service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE) {   // add client pkey hash to banlist
        a_usage->is_active = 0;
        if (a_usage->service) {
            dap_chain_net_srv_banlist_item_t *l_item = NULL;
            pthread_mutex_lock(&a_usage->service->banlist_mutex);
            HASH_FIND(hh, a_usage->service->ban_list, &a_usage->client_pkey_hash, sizeof(dap_chain_hash_fast_t), l_item);
            if (l_item)
                pthread_mutex_unlock(&a_usage->service->banlist_mutex);
            else {
                l_item = DAP_NEW_Z(dap_chain_net_srv_banlist_item_t);
                if (!l_item) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    pthread_mutex_unlock(&a_usage->service->banlist_mutex);
                    return;
                }
                log_it(L_DEBUG, "Add client to banlist");
                l_item->client_pkey_hash = a_usage->client_pkey_hash;
                l_item->ht_mutex = &a_usage->service->banlist_mutex;
                l_item->ht_head = &a_usage->service->ban_list;
                HASH_ADD(hh, a_usage->service->ban_list, client_pkey_hash, sizeof(dap_chain_hash_fast_t), l_item);
                pthread_mutex_unlock(&a_usage->service->banlist_mutex);
                dap_timerfd_start(a_usage->service->grace_period * 1000 * 10, (dap_timerfd_callback_t)s_unban_client, l_item);
            }
        }

    } else if (l_srv_session->usage_active)
        dap_chain_net_srv_usage_delete(l_srv_session);
}


static void s_service_substate_go_to_normal(dap_chain_net_srv_usage_t *a_usage)
{

    if (a_usage->service->callbacks.receipt_next_success) {
        if (a_usage->service->callbacks.receipt_next_success(a_usage->service, a_usage->id, a_usage->client,
                                                                a_usage->receipt, a_usage->receipt->size ) != 0 ){
            log_it(L_NOTICE, "No success by service receipt_next callback, inactivating service usage");
            a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_REQUEST_INTERNAL_ERROR;
            s_service_substate_go_to_error(a_usage);
        }
    }
    a_usage->service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_NORMAL;
}


static int s_check_tx_params(dap_chain_net_srv_usage_t *a_usage)
{
    dap_chain_tx_out_cond_t * l_tx_out_cond = NULL;
    dap_chain_net_srv_price_t * l_price = NULL;
    dap_chain_datum_tx_t *l_tx = a_usage->tx_cond;

    l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, NULL );

    if ( ! l_tx_out_cond ) { // No conditioned output
        log_it( L_WARNING, "No conditioned output");
        return DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_COND_OUT ;
    }

    // Check cond output if it equesl or not to request
    if (!dap_chain_net_srv_uid_compare(l_tx_out_cond->header.srv_uid, a_usage->service->uid)) {
        log_it( L_WARNING, "Wrong service uid in request, tx expect to close its output with 0x%016"DAP_UINT64_FORMAT_X,
                l_tx_out_cond->header.srv_uid.uint64 );
        return DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_WRONG_SRV_UID  ;
    }

    const char *l_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_usage->net->pub.ledger, &a_usage->tx_cond_hash);
    if (!l_ticker) {
        log_it( L_ERROR, "Token ticker not found for tx cond hash %s", dap_chain_hash_fast_to_str_static(&a_usage->tx_cond_hash));
        return DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_TICKER_ERROR;
    }
    dap_stpcpy(a_usage->token_ticker, l_ticker);

    log_it(L_MSG, "Using price from order %s.", dap_chain_hash_fast_to_str_static(&a_usage->static_order_hash));
    if ((l_price = a_usage->price)){
        if (l_price->net->pub.id.uint64  != a_usage->net->pub.id.uint64){
            log_it( L_WARNING, "Pricelist is not for net %s.", a_usage->net->pub.name);
            return DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ACCEPT_TOKEN;
        }

        if (dap_strcmp(l_price->token, l_ticker) != 0){
            log_it( L_WARNING, "Token ticker in the pricelist and tx do not match");
            return DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ACCEPT_TOKEN;
        }

        if (l_price->units_uid.enm != l_tx_out_cond->subtype.srv_pay.unit.enm){
            log_it( L_WARNING, "Unit ID in the pricelist and tx do not match");
            return DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_UNIT_TYPE_ERROR;
        }

        uint256_t l_unit_price = {};
        if (l_price->units != 0){
            DIV_256(l_price->value_datoshi, GET_256_FROM_64(l_price->units), &l_unit_price);
        } else {
            log_it( L_WARNING, "Units in pricelist is zero. ");
            return DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_UNITS_ERROR;
        }

        if(IS_ZERO_256(l_tx_out_cond->subtype.srv_pay.unit_price_max_datoshi) ||
            compare256(l_unit_price, l_tx_out_cond->subtype.srv_pay.unit_price_max_datoshi) <= 0){
        } else {
            log_it( L_WARNING, "Unit price in pricelist is greater than max allowable.");
            return DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_UNITS_ERROR;
        }
    } else  {
        log_it( L_WARNING, "Request can't be processed because no acceptable price in pricelist for token %s in network %s",
                l_ticker, a_usage->net->pub.name );
        return DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_PRICE_ERROR;
    }

    return 0;
}


static void s_service_substate_pay_service(dap_chain_net_srv_usage_t *a_usage)
{
    dap_stream_ch_chain_net_srv_pkt_error_t l_err;

    if (a_usage->service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_IDLE && 
        a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_IDLE
    ) {
        dap_stream_ch_chain_net_srv_remain_service_store_t* l_remain_service = NULL;
        l_remain_service = a_usage->service->callbacks.get_remain_service(a_usage->service, a_usage->id, a_usage->client);
        if (l_remain_service && ((l_remain_service->limits_ts &&  a_usage->price->units_uid.enm == SERV_UNIT_SEC)  || 
            (l_remain_service->limits_bytes && a_usage->price->units_uid.enm == SERV_UNIT_B))){

            //Start with remain service
            dap_chain_net_srv_stream_session_t * l_srv_session = (dap_chain_net_srv_stream_session_t *) a_usage->client->ch->stream->session->_inheritor;
            switch(a_usage->price->units_uid.enm){
                case SERV_UNIT_SEC:
                    l_srv_session->limits_ts = l_remain_service->limits_ts;
                    break;
                case SERV_UNIT_B:
                    l_srv_session->limits_bytes = l_remain_service->limits_bytes;
                    break;
            }
            log_it(L_INFO, "User %s has %ld %s remain service. Start service without paying.", dap_chain_hash_fast_to_str_static(&a_usage->client_pkey_hash), 
                            l_remain_service->limits_ts ? l_remain_service->limits_ts : l_remain_service->limits_bytes, 
                            dap_chain_srv_unit_enum_to_str(a_usage->price->units_uid.enm));
            size_t l_success_size = sizeof (dap_stream_ch_chain_net_srv_pkt_success_hdr_t );
            dap_stream_ch_chain_net_srv_pkt_success_t *l_success = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_success_t,
                                                                                    l_success_size);
            if(!l_success) {
                log_it(L_ERROR, "Memory allocation error in %s, line %d", __PRETTY_FUNCTION__, __LINE__);
                a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_ALLOC_MEMORY_ERROR;
                s_service_substate_go_to_error(a_usage);
            } else {
                l_success->hdr.usage_id = a_usage->id;
                l_success->hdr.net_id.uint64 = a_usage->net->pub.id.uint64;
                l_success->hdr.srv_uid.uint64 = a_usage->service->uid.uint64;
                dap_stream_ch_pkt_write_unsafe(a_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS, l_success, l_success_size);
                DAP_DELETE(l_success);
                // create and fill first receipt
                a_usage->receipt = dap_chain_datum_tx_receipt_create(a_usage->service->uid, a_usage->price->units_uid, a_usage->price->units, a_usage->price->value_datoshi, NULL, 0);
                s_service_state_go_to_normal(a_usage);               
            }                        
        } else {
            log_it(L_INFO, "Send first receipt to sign");
            a_usage->receipt = dap_chain_net_srv_issue_receipt(a_usage->service, a_usage->price, NULL, 0);
            dap_stream_ch_pkt_write_unsafe(a_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST,
                a_usage->receipt, a_usage->receipt->size);
                
            a_usage->service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN;

            //start timeout timer
            a_usage->receipt_timeout_timer_start_callback(a_usage);
        }
    } else if(a_usage->service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE && 
        a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_TX_FOR_PAYING){
            
        log_it(L_INFO, "Send first receipt to sign");
        a_usage->receipt = dap_chain_net_srv_issue_receipt(a_usage->service, a_usage->price, NULL, 0);
        dap_stream_ch_pkt_write_unsafe(a_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST,
            a_usage->receipt, a_usage->receipt->size);
            
        a_usage->service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN;

        //start timeout timer
        a_usage->receipt_timeout_timer_start_callback(a_usage);    
            
    }else {
        if (!a_usage->tx_cond) a_usage->tx_cond = dap_ledger_tx_find_by_hash(a_usage->net->pub.ledger, &a_usage->tx_cond_hash);

        if (a_usage->tx_cond){
            int ret = s_check_tx_params(a_usage);
            if (ret != 0){
                a_usage->last_err_code = ret;
                s_service_substate_go_to_error(a_usage);
                return;
            }
        }
        dap_chain_datum_tx_receipt_t *l_receipt = NULL;
        if (a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN)
            l_receipt = a_usage->receipt;
        else 
            l_receipt = a_usage->receipt_next;

        
        int l_ret = s_pay_service(a_usage, l_receipt);
        switch (l_ret){
            case PAY_SERVICE_STATUS_SUCCESS:
                // Store last receipt if any problems with transactions
                dap_global_db_set(SRV_RECEIPTS_GDB_GROUP, dap_chain_hash_fast_to_str_static(&a_usage->client_pkey_hash), l_receipt, l_receipt->size, false, NULL, NULL);
                if (a_usage->service_state != DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_NORMAL)
                    s_service_state_go_to_normal(a_usage);
                else 
                    s_service_substate_go_to_normal(a_usage);
                return;
            break;
            case PAY_SERVICE_STATUS_TX_CANT_FIND:
                // TX not found in ledger and we not in grace, start grace
                if (a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_FROM_CLIENT){
                    a_usage->service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_IN_LEDGER;
                } else if (a_usage->service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_NORMAL && 
                    a_usage->service_substate != DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_TX_FOR_PAYING &&
                    a_usage->service_substate != DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_IN_LEDGER ){
                    log_it(L_ERROR, "Can't find tx cond. Start grace!");
                    s_service_substate_go_to_waiting_prev_tx(a_usage);
                    return;
                } else {
                    if (a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_FROM_CLIENT){
                        log_it(L_INFO, "No new tx cond!");
                        a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_NEW_COND;
                    } else if (a_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_IN_LEDGER){
                        log_it(L_INFO, "Can't find new tx cond in ledger!");
                        a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND;
                    } else {
                        log_it(L_INFO, "Can't find tx in ledger! Remove receipt and wait for end of service.");
                        a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND;
                    }
                }
            break;
            case PAY_SERVICE_STATUS_NOT_ENOUGH:
                if (a_usage->service_substate != DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_IN_LEDGER &&
                    a_usage->service_substate != DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_FROM_CLIENT){
                    
                    log_it(L_ERROR, "Tx cond have not enough funds");
                    if (a_usage->service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_IDLE) {
                        a_usage->service_state = DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE;
                    } 
                    s_service_substate_go_to_waiting_new_tx(a_usage);
                    return;
                } else  {
                    log_it(L_ERROR, "New tx cond have not enough funds");
                    a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NEW_TX_COND_NOT_ENOUGH;
                } 
            break;
            case PAY_SERVICE_STATUS_MEMALLOC_ERROR:
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_ALLOC_MEMORY_ERROR;
                DAP_DEL_Z(a_usage->receipt_next);
                break;
            case PAY_SERVICE_STATUS_TX_ERROR:
            default: {
                log_it(L_ERROR, "Can't create input tx cond transaction!");
                memset(&a_usage->tx_cond_hash, 0, sizeof(a_usage->tx_cond_hash));
                DAP_DEL_Z(a_usage->receipt_next);
                a_usage->last_err_code  = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_CREATION_ERROR;
            }
        }
        s_service_substate_go_to_error(a_usage);   
    }
}

static void s_service_substate_go_to_waiting_prev_tx(dap_chain_net_srv_usage_t *a_usage)
{
    dap_chain_net_srv_grace_t *l_grace  = DAP_NEW_Z(dap_chain_net_srv_grace_t);
    if (!l_grace) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_ALLOC_MEMORY_ERROR;
        s_service_substate_go_to_error(a_usage);
        return;
    }
    l_grace->ch_uuid = a_usage->client->ch->uuid;
    l_grace->stream_worker = a_usage->client->ch->stream_worker;
    l_grace->usage = a_usage;
    
    // create and start grace-object 
    dap_chain_net_srv_grace_usage_t *l_item = DAP_NEW_Z(dap_chain_net_srv_grace_usage_t);
    if (!l_item) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_ALLOC_MEMORY_ERROR;
        s_service_substate_go_to_error(a_usage);
        return;
    }
    l_item->grace = l_grace;
    l_item->tx_cond_hash = a_usage->tx_cond_hash;

    a_usage->service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_TX_FOR_PAYING;
    char *l_user_key = dap_chain_hash_fast_to_str_static(&l_grace->usage->client_pkey_hash);

    pthread_mutex_lock(&a_usage->service->grace_mutex);
    HASH_ADD(hh, a_usage->service->grace_hash_tab, tx_cond_hash, sizeof(dap_hash_fast_t), l_item);
    pthread_mutex_unlock(&a_usage->service->grace_mutex);
    l_grace->timer = dap_timerfd_start_on_worker(l_grace->stream_worker->worker, l_grace->usage->service->grace_period * 1000,
                                                           (dap_timerfd_callback_t)s_grace_period_finish, l_item);
    log_it(L_INFO, "Start grace timer %s for user %s.", l_grace->timer ? "successfuly." : "failed.", l_user_key);
}

static void s_service_substate_go_to_waiting_new_tx(dap_chain_net_srv_usage_t *a_usage)
{
    
    dap_chain_net_srv_grace_t *l_grace = DAP_NEW_Z(dap_chain_net_srv_grace_t);
    if (!l_grace) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_ALLOC_MEMORY_ERROR;
        s_service_substate_go_to_error(a_usage);
        return;
    }
    l_grace->ch_uuid = a_usage->client->ch->uuid;
    l_grace->stream_worker = a_usage->client->ch->stream_worker;
    l_grace->usage = a_usage;

    // create and start grace-object 
    dap_chain_net_srv_grace_usage_t *l_item = DAP_NEW_Z(dap_chain_net_srv_grace_usage_t);
    if (!l_item) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        a_usage->last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_ALLOC_MEMORY_ERROR;
        s_service_substate_go_to_error(a_usage);
        return;
    }
    l_item->grace = l_grace;
    l_item->tx_cond_hash = a_usage->tx_cond_hash;

    a_usage->service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_FROM_CLIENT;
    char *l_user_key = dap_chain_hash_fast_to_str_static(&l_grace->usage->client_pkey_hash);

    pthread_mutex_lock(&a_usage->service->grace_mutex);
    HASH_ADD(hh, a_usage->service->grace_hash_tab, tx_cond_hash, sizeof(dap_hash_fast_t), l_item);
    pthread_mutex_unlock(&a_usage->service->grace_mutex);
    l_grace->timer = dap_timerfd_start_on_worker(l_grace->stream_worker->worker, l_grace->usage->service->grace_period * 1000,
                                                           (dap_timerfd_callback_t)s_grace_period_finish, l_item);
    
    log_it(L_INFO, "Start grace timer %s for user %s.", l_grace->timer ? "successfuly." : "failed.", l_user_key);
    dap_stream_ch_chain_net_srv_pkt_error_t l_err;
    l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ENOUGH;
    dap_stream_ch_pkt_write_unsafe(a_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &l_err, sizeof (l_err));
    if (a_usage->service->callbacks.response_error)
        a_usage->service->callbacks.response_error(a_usage->service,a_usage->id, a_usage->client, &l_err,sizeof (l_err));
}

static void s_service_substate_go_to_error(dap_chain_net_srv_usage_t *a_usage)
{
    if (!a_usage){
        s_service_state_go_to_error(a_usage);
        return;
    }  

    if (a_usage->service_state ==  DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_NORMAL){
        // wait until end of service in this substate
        DAP_DEL_Z(a_usage->receipt_next);
        a_usage->service_substate=DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_ERROR;
        dap_stream_ch_pkt_write_unsafe(a_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR, &a_usage->last_err_code, sizeof (a_usage->last_err_code));
        if (a_usage->service->callbacks.response_error)
            a_usage->service->callbacks.response_error(a_usage->service,a_usage->id, a_usage->client, &a_usage->last_err_code,sizeof (a_usage->last_err_code));
    } else {
        s_service_state_go_to_error(a_usage);
    }
}