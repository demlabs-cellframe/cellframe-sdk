/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
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

#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include "dap_chain_net.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_sig.h"
#include "dap_list.h"
#include "dap_sign.h"
#include "dap_time.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_ledger.h"
#include "dap_chain_node_cli.h"
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_math_ops.h"
#include "dap_string.h"
#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_chain_datum_decree.h"
#include "dap_tsd.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_xchange.h"
#include "uthash.h"

#define LOG_TAG "dap_chain_net_srv_xchange"

static dap_chain_net_srv_fee_item_t *s_service_fees = NULL; // Governance statements for networks
static pthread_rwlock_t s_service_fees_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static void s_callback_decree (dap_chain_net_srv_t * a_srv, dap_chain_net_t *a_net, dap_chain_t * a_chain, dap_chain_datum_decree_t * a_decree, size_t a_decree_size);
static bool s_xchange_verificator_callback(dap_ledger_t * a_ledger, dap_chain_tx_out_cond_t *a_cond,
                            dap_chain_datum_tx_t *a_tx_in, bool a_owner);
const dap_chain_net_srv_uid_t c_dap_chain_net_srv_xchange_uid = {.uint64= DAP_CHAIN_NET_SRV_XCHANGE_ID};


static int s_cli_srv_xchange(int a_argc, char **a_argv, char **a_str_reply);
static int s_callback_requested(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_error(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_receipt_next_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);

static int s_tx_check_for_open_close(dap_chain_net_t * a_net, dap_chain_datum_tx_t * a_tx);
static void s_string_append_tx_cond_info( dap_string_t * a_reply_str, dap_chain_net_t * a_net, dap_chain_datum_tx_t * a_tx );
static bool s_srv_xchange_get_fee(dap_chain_net_id_t a_net_id, uint256_t *a_fee, dap_chain_addr_t *a_addr, uint16_t *a_type);

static dap_chain_net_srv_xchange_t *s_srv_xchange;
static bool s_debug_more = true;

/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_xchange_init()
{
    dap_chain_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, s_xchange_verificator_callback, NULL);
    dap_cli_server_cmd_add("srv_xchange", s_cli_srv_xchange, "eXchange service commands",

    "srv_xchange order create -net <net_name> -token_sell <token_ticker> -token_buy <token_ticker> -wallet <wallet_name>"
                                            " -value <value> -rate <value> -fee <value>\n"
        "\tCreate a new order and tx with specified amount of datoshi to exchange with specified rate (buy / sell)\n"
    "srv_xchange order remove -net <net_name> -order <order_hash> -wallet <wallet_name>\n"
         "\tRemove order with specified order hash in specified net name\n"
    "srv_xchange order update -net <net_name> -order <order_hash> -wallet <wallet_name> [-token_sell <token_ticker>] "
                            "[-net_buy <net_name>] [-token_buy <token_ticker>] [-coins <value>] [-rate <value>]\n"
         "\tUpdate order with specified order hash in specified net name\n"
    "srv_xchange order history -net <net_name> {-order <order_hash> | -addr <wallet_addr>}"
         "\tShows transaction history for the selected order\n"
    "srv_xchange order status -net <net_name> -order <order_hash>"
         "\tShows current amount of unselled coins from the selected order and percentage of its completion\n"
    "srv_xchange orders -net <net_name>\n"
         "\tGet the exchange orders list within specified net name\n"

    "srv_xchange purchase -order <order hash> -net <net_name> -wallet <wallet_name> -value <value> -fee <value>\n"
         "\tExchange tokens with specified order within specified net name. Specify how many datoshies to sell with rate specified by order\n"

    "srv_xchange tx_list -net <net_name> [-time_from <yymmdd> -time_to <yymmdd>]"
        "[[-addr <wallet_addr>  [-status closed | open] ]\n"                /* @RRL:  #6294  */
        "\tList of exchange transactions\n"

    "srv_xchange token_pair -net <net_name> list all\n"
        "\tList of all token pairs\n"
    "srv_xchange token_pair -net <net_name> price average -token_from <token_ticker> -token_to <token_ticker> [-time_from <From time>] [-time_to <To time>]  \n"
        "\tGet average rate for token pair <token from>:<token to> from <From time> to <To time> \n"
        "\tAll times are in RFC822\n"
    "srv_xchange token_pair -net <net_name> price history -token_from <token_ticker> -token_to <token_ticker> [-time_from <From time>] [-time_to <To time>] \n"
        "\tPrint rate history for token pair <token from>:<token to> from <From time> to <To time>\n"
        "\tAll times are in RFC822\n"

    "srv_xchange enable\n"
         "\tEnable eXchange service\n"
    "srv_xchange disable\n"
         "\tDisable eXchange service\n"
    );
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
    dap_chain_net_srv_callbacks_t l_srv_callbacks = {};
    l_srv_callbacks.requested = s_callback_requested;
    l_srv_callbacks.response_success = s_callback_response_success;
    l_srv_callbacks.response_error = s_callback_response_error;
    l_srv_callbacks.receipt_next_success = s_callback_receipt_next_success;
    l_srv_callbacks.decree = s_callback_decree;

    dap_chain_net_srv_t* l_srv = dap_chain_net_srv_add(l_uid, "srv_xchange", &l_srv_callbacks);
    s_srv_xchange = DAP_NEW_Z(dap_chain_net_srv_xchange_t);
    if (!s_srv_xchange || !l_srv) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    l_srv->_internal = s_srv_xchange;
    s_srv_xchange->parent = l_srv;
    s_srv_xchange->enabled = false;
    s_debug_more = dap_config_get_item_bool_default(g_config, "srv_xchange", "debug_more", s_debug_more);

    return 0;
}

void dap_chain_net_srv_xchange_deinit()
{
    if(!s_srv_xchange)
        return;
    dap_chain_net_srv_del(s_srv_xchange->parent);
    DAP_DELETE(s_srv_xchange);
}

/**
 * @brief s_verificator_callback
 * @param a_ledger
 * @param a_tx_out_hash
 * @param a_cond
 * @param a_tx_in
 * @param a_owner
 * @return
 */
static bool s_xchange_verificator_callback(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_tx_out_cond,
                                           dap_chain_datum_tx_t *a_tx_in, bool a_owner)
{
    return true;//for tests
    if (a_owner)
        return true;
    if(!a_tx_in || !a_tx_out_cond)
        return false;

    dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t *)dap_chain_datum_tx_item_get(a_tx_in, 0, TX_ITEM_TYPE_IN_COND, 0);
    if (!l_tx_in_cond)
        return false;
    if (dap_hash_fast_is_blank(&l_tx_in_cond->header.tx_prev_hash))
        return false;
    const char *l_sell_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_in_cond->header.tx_prev_hash);
    if (!l_sell_ticker)
        return false;
    const char *l_buy_ticker = a_tx_out_cond->subtype.srv_xchange.buy_token;

    uint256_t l_buy_val = {}, l_fee_val = {},
              l_sell_again_val = {}, l_service_fee_val = {};
    int l_item_idx_start = 0;
    byte_t * l_tx_item;

    dap_chain_addr_t l_service_fee_addr, *l_seller_addr = &a_tx_out_cond->subtype.srv_xchange.seller_addr;
    uint16_t l_service_fee_type;
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_ledger->net_name);
    bool l_service_fee_used = s_srv_xchange_get_fee(l_net->pub.id, &l_service_fee_val, &l_service_fee_addr, &l_service_fee_type);
    const char *l_native_ticker = l_net->pub.native_ticker;
    const char *l_service_ticker = (l_service_fee_type == SERVICE_FEE_OWN_FIXED || l_service_fee_type == SERVICE_FEE_OWN_PERCENT) ?
                l_buy_ticker : l_native_ticker;
    while ((l_tx_item = dap_chain_datum_tx_item_get(a_tx_in, &l_item_idx_start, TX_ITEM_TYPE_OUT_ALL, NULL)) != NULL)
    {
        dap_chain_tx_item_type_t l_tx_out_type = dap_chain_datum_tx_item_get_type(l_tx_item);
        switch(l_tx_out_type){
            case TX_ITEM_TYPE_OUT_EXT: {
                dap_chain_tx_out_ext_t *l_tx_in_output = (dap_chain_tx_out_ext_t *)l_tx_item;
                const char * l_out_token = l_tx_in_output->token;
                const uint256_t *l_out_value = &l_tx_in_output->header.value;
                dap_chain_addr_t * l_out_addr = &l_tx_in_output->addr;
                // Out is with token to buy
                if (!strcmp(l_out_token, l_buy_ticker) &&
                        !memcmp(l_out_addr, l_seller_addr, sizeof(*l_out_addr)))
                    SUM_256_256(l_buy_val, *l_out_value, &l_buy_val);
                // Out is with token to fee
                if (l_service_fee_used && !strcmp(l_out_token, l_service_ticker) &&
                        !memcmp(l_out_addr, &l_service_fee_addr, sizeof(*l_out_addr)))
                    SUM_256_256(l_fee_val, *l_out_value, &l_fee_val);
            } break;
            case TX_ITEM_TYPE_OUT_COND: {
                dap_chain_tx_out_cond_t *l_tx_in_output = (dap_chain_tx_out_cond_t *)l_tx_item;
                if (l_tx_in_output->header.subtype == a_tx_out_cond->header.subtype &&                             // Same subtype
                        l_tx_in_output->header.srv_uid.uint64 == a_tx_out_cond->header.srv_uid.uint64 &&          // Same service uid
                        l_tx_in_output->header.ts_expires == a_tx_out_cond->header.ts_expires &&                  // Same expires time
                        l_tx_in_output->tsd_size == a_tx_out_cond->tsd_size &&                              // Same params size
                        memcmp(l_tx_in_output->tsd, a_tx_out_cond->tsd, l_tx_in_output->tsd_size) == 0 && // Same params itself
                        memcmp(&l_tx_in_output->subtype.srv_xchange, &a_tx_out_cond->subtype.srv_xchange,         // Same subtype header
                           sizeof(a_tx_out_cond->subtype.srv_xchange)) == 0) {
                    l_sell_again_val = l_tx_in_output->header.value;                                    // It is back to cond owner value
                }
            }break;
            default: break;
        }
        l_item_idx_start++;
    }

    /* Check the condition for rate verification success
     * seller rate >= buyer_rate
     * OR
     * a_cond.srv_xchange.rate (a_cond->header.value / a_cond->subtype.srv_xchange.buy_value) >=
     * a_tx.out.rate ((a_cond->header.value - new_cond->header.value) / out_ext.seller_addr(buy_ticker).value)
     * OR
     * a_cond->header.value * out_ext.seller_addr(buy_ticker).value >=
     * a_cond->subtype.srv_xchange.buy_value * (a_cond->header.value - new_cond->header.value)
     */

    uint256_t l_sell_val, l_buyer_mul, l_seller_mul;
    if (compare256(l_sell_again_val, a_tx_out_cond->header.value) >= 0)
        return false;
    SUBTRACT_256_256(a_tx_out_cond->header.value, l_sell_again_val, &l_sell_val);
    MULT_256_256(a_tx_out_cond->header.value, l_buy_val, &l_seller_mul);
    MULT_256_256(a_tx_out_cond->subtype.srv_xchange.buy_value, l_sell_val, &l_buyer_mul);
    if (compare256(l_seller_mul, l_buyer_mul) < 0)
        return false;

    /* Check the condition for fee verification success
     * out_ext.fee_addr(fee_ticker).value >= fee_value
     */
    if (l_service_fee_used) {
        if (l_service_fee_type == SERIVCE_FEE_NATIVE_PERCENT || l_service_fee_type == SERVICE_FEE_OWN_PERCENT)
            MULT_256_COIN(l_service_fee_val, l_sell_val, &l_service_fee_val);
        if (compare256(l_fee_val, l_service_fee_val) < 0)
            return false;
    }
    return true;
}

/**
 * @brief s_callback_decree
 * @param a_srv
 * @param a_net
 * @param a_chain
 * @param a_decree
 * @param a_decree_size
 */
static void s_callback_decree (dap_chain_net_srv_t * a_srv, dap_chain_net_t *a_net, dap_chain_t * a_chain, dap_chain_datum_decree_t * a_decree, size_t a_decree_size)
{

//    TODO: finish function
    pthread_rwlock_wrlock(&s_service_fees_rwlock);
    dap_chain_net_srv_fee_item_t *l_fee = NULL;
//    switch(a_decree->header.action){
//        case DAP_CHAIN_DATUM_DECREE_ACTION_UPDATE:{
//            HASH_FIND(hh,s_service_fees,&a_net->pub.id, sizeof(a_net->pub.id), l_fee);
//            if(l_fee == NULL){
//                log_it(L_WARNING,"Decree update for net id 0x%016" DAP_UINT64_FORMAT_X" when such id can't find in hash table", a_net->pub.id.uint64);
//                pthread_rwlock_unlock(&s_service_fees_rwlock);
//                return;
//            }
//        }break;
//        case DAP_CHAIN_DATUM_DECREE_ACTION_CREATE:{
//            HASH_FIND(hh,s_service_fees,&a_net->pub.id, sizeof(a_net->pub.id), l_fee);
//            if (l_fee) {
//                log_it(L_WARNING, "Decree create for net id 0x%016" DAP_UINT64_FORMAT_X" when such id already in hash table", a_net->pub.id.uint64);
//                pthread_rwlock_unlock(&s_service_fees_rwlock);
//                return;
//            }
//            l_fee = DAP_NEW_Z(dap_chain_net_srv_fee_item_t);
//            l_fee->net_id = a_net->pub.id;
//            HASH_ADD(hh, s_service_fees, net_id, sizeof(l_fee->net_id), l_fee);
//        } break;
//    }
//    size_t l_tsd_offset = 0;
//    TODO: move to ACTION_CREATE
//    while(l_tsd_offset < (a_decree_size - sizeof(a_decree->header)) ){
//        dap_tsd_t *l_tsd = (dap_tsd_t*) (a_decree->data_n_signs + l_tsd_offset);
//        switch((dap_chain_net_srv_fee_tsd_type_t)l_tsd->type) {
//        case TSD_FEE_TYPE:
//            l_fee->fee_type = dap_tsd_get_scalar(l_tsd, uint16_t);
//            break;
//        case TSD_FEE:
//            l_fee->fee = dap_tsd_get_scalar(l_tsd, uint256_t);
//            break;
//        case TSD_FEE_ADDR:
//            l_fee->fee_addr = dap_tsd_get_scalar(l_tsd, dap_chain_addr_t);
//        default:
//            break;
//        }
//        l_tsd_offset += dap_tsd_size(l_tsd);
//    }
//    pthread_rwlock_unlock(&s_service_fees_rwlock);
}

static bool s_srv_xchange_get_fee(dap_chain_net_id_t a_net_id, uint256_t *a_fee, dap_chain_addr_t *a_addr, uint16_t *a_type)
{
    pthread_rwlock_wrlock(&s_service_fees_rwlock);
    dap_chain_net_srv_fee_item_t *l_fee = NULL;
    HASH_FIND(hh,s_service_fees, &a_net_id, sizeof(a_net_id), l_fee);
    pthread_rwlock_unlock(&s_service_fees_rwlock);
    if (!l_fee || IS_ZERO_256(l_fee->fee))
        return false;
    if (a_type)
        *a_type = l_fee->fee_type;
    if (a_addr)
        *a_addr = l_fee->fee_addr;
    if (a_fee)
        *a_fee = l_fee->fee;
    return true;
}

static dap_chain_datum_tx_receipt_t *s_xchange_receipt_create(dap_chain_net_srv_xchange_price_t *a_price, uint256_t a_datoshi_buy)
{
    uint32_t l_ext_size = sizeof(uint256_t) + DAP_CHAIN_TICKER_SIZE_MAX;
    uint8_t *l_ext = DAP_NEW_STACK_SIZE(uint8_t, l_ext_size);
    if (!l_ext) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    memcpy(l_ext, &a_datoshi_buy, sizeof(uint256_t));
    strcpy((char *)&l_ext[sizeof(uint256_t)], a_price->token_buy);
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 = SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
    uint256_t l_datoshi_sell = {};
    if (!IS_ZERO_256(a_price->rate)){
        DIV_256_COIN(a_datoshi_buy, a_price->rate, &l_datoshi_sell);
        dap_chain_datum_tx_receipt_t *l_receipt =  dap_chain_datum_tx_receipt_create(l_uid, l_unit, 0, l_datoshi_sell,
                                                                                 l_ext, l_ext_size);
        return l_receipt;
    }
    return NULL;
}

static dap_chain_datum_tx_t *s_xchange_tx_create_request(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_wallet_t *a_wallet)
{
    if (!a_price || !a_price->net || !*a_price->token_sell || !*a_price->token_buy || !a_wallet) {
        return NULL;
    }
    const char *l_native_ticker = a_price->net->pub.native_ticker;
    bool l_single_channel = !dap_strcmp(a_price->token_sell, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer; // how many coins to transfer
    uint256_t l_value_need = a_price->datoshi_sell,
              l_net_fee,
              l_total_fee = a_price->fee,
              l_fee_transfer;
    dap_chain_addr_t l_addr_net_fee;
    dap_list_t *l_list_fee_out = NULL;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_price->net->pub.id, &l_net_fee, &l_addr_net_fee);
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);

    dap_ledger_t *l_ledger = a_price->net->pub.ledger;
    dap_chain_addr_t *l_seller_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_price->net->pub.id);
    if (l_single_channel)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else {
        l_list_fee_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                    l_seller_addr, l_total_fee, &l_fee_transfer);
        if (!l_list_fee_out) {
            log_it(L_WARNING, "Not enough funds to pay fee");
            return NULL;
        }
    }
    dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);
    // list of transaction with 'out' items to sell
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_price->token_sell,
                                                                             l_seller_addr, l_value_need, &l_value_transfer);
    if(!l_list_used_out) {
        DAP_DELETE(l_seller_addr);
        log_it(L_WARNING, "Nothing to change (not enough funds)");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_to_items, l_value_transfer) != 0) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_seller_addr);
        log_it(L_ERROR, "Can't compose the transaction input");
        return NULL;
    }
    if (!l_single_channel) {
        // add 'in' items to fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer) != 0) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_seller_addr);
            log_it(L_ERROR, "Can't compose the transaction input");
            return NULL;
        }
    }

    // add 'out_cond' & 'out' items

    {
        uint256_t l_datoshi_buy = uint256_0;
        MULT_256_COIN(a_price->datoshi_sell, a_price->rate, &l_datoshi_buy);
        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(l_uid, a_price->net->pub.id, a_price->datoshi_sell,
                                                                                                a_price->net->pub.id, a_price->token_buy, l_datoshi_buy,
                                                                                                l_seller_addr, NULL, 0);
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_seller_addr);
            log_it(L_ERROR, "Can't compose the transaction conditional output");
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_item(&l_tx, &l_addr_net_fee, l_net_fee) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                DAP_DELETE(l_seller_addr);
                log_it(L_ERROR, "Cant add network fee output");
                return NULL;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_price->fee) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                DAP_DELETE(l_seller_addr);
                log_it(L_ERROR, "Cant add validator's fee output");
                return NULL;
            }
        }
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_item(&l_tx, l_seller_addr, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                DAP_DELETE(l_seller_addr);
                log_it(L_ERROR, "Cant add coin back output");
                return NULL;
            }
        }
        // Fee coinback
        if (!l_single_channel) {
            SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_value_back);
            if (!IS_ZERO_256(l_value_back)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, l_value_back,
                                                        a_price->net->pub.native_ticker) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    DAP_DELETE(l_seller_addr);
                    log_it(L_ERROR, "Cant add fee back output");
                    return NULL;
                }
            }
        }
    }
    DAP_DELETE(l_seller_addr);

    // add 'sign' item
    if(dap_chain_datum_tx_add_sign_item(&l_tx, l_seller_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_ERROR, "Can't add sign output");
        return NULL;
    }

    return l_tx;
}

static dap_chain_datum_tx_t *s_xchange_tx_create_exchange(dap_chain_net_srv_xchange_price_t *a_price,
                                                          dap_chain_wallet_t *a_wallet, uint256_t a_datoshi_buy,
                                                          uint256_t a_datoshi_fee)
{
    if (!a_price || !a_price->net || !*a_price->token_sell || !*a_price->token_buy || !a_wallet) {
        return NULL;
    }
    const char *l_native_ticker = a_price->net->pub.native_ticker;
    const char *l_service_ticker = NULL;
    bool l_pay_with_native = !dap_strcmp(a_price->token_buy, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer, // how many coins to transfer
              l_value_need = a_price->datoshi_buy,
              l_net_fee,
              l_service_fee,
              l_total_fee = a_datoshi_fee,
              l_fee_transfer;
    dap_chain_addr_t l_net_fee_addr, l_service_fee_addr;
    dap_list_t *l_list_fee_out = NULL;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_price->net->pub.id, &l_net_fee, &l_net_fee_addr);
    if (l_net_fee_used)
        SUM_256_256(l_net_fee, a_price->fee, &l_total_fee);
    uint16_t l_service_fee_type;
    bool l_service_fee_used = s_srv_xchange_get_fee(a_price->net->pub.id, &l_service_fee, &l_service_fee_addr, &l_service_fee_type);
    if (l_service_fee_used) {
        switch (l_service_fee_type) {
        case SERIVCE_FEE_NATIVE_PERCENT:
            MULT_256_COIN(l_service_fee, a_price->datoshi_buy, &l_service_fee);
        case SERVICE_FEE_NATIVE_FIXED:
            SUM_256_256(l_total_fee, l_service_fee, &l_total_fee);
            l_service_ticker = l_native_ticker;
            break;
        case SERVICE_FEE_OWN_PERCENT:
            MULT_256_COIN(l_service_fee, a_price->datoshi_buy, &l_service_fee);
        case SERVICE_FEE_OWN_FIXED:
            SUM_256_256(l_value_need, l_service_fee, &l_value_need);
            l_service_ticker = a_price->token_buy;
        default:
            break;
        }
    }
    dap_ledger_t *l_ledger = a_price->net->pub.ledger;
    dap_chain_addr_t *l_buyer_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_price->net->pub.id);
    if (l_pay_with_native)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else {
        l_list_fee_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                    l_buyer_addr, l_total_fee, &l_fee_transfer);
        if (!l_list_fee_out) {
            log_it(L_WARNING, "Not enough funds to pay fee");
            return NULL;
        }
    }
    // list of transaction with 'out' items to sell
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_price->token_buy,
                                                                             l_buyer_addr, l_value_need, &l_value_transfer);
    if(!l_list_used_out) {
        DAP_DELETE(l_buyer_addr);
        log_it(L_WARNING, "Nothing to change (not enough funds)");
        return NULL;
    }

    dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // create and add reciept
    dap_chain_datum_tx_receipt_t *l_receipt = s_xchange_receipt_create(a_price, a_datoshi_buy);
    if( l_receipt == NULL){
        DAP_DELETE(l_buyer_addr);
        log_it(L_ERROR, "Can't compose the receipt");
        return NULL;
    }
    dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_receipt);
    DAP_DELETE(l_receipt);
    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_buyer_addr);
        log_it(L_ERROR, "Can't compose the transaction input");
        return NULL;
    }
    if (!l_pay_with_native) {
        // add 'in' items to fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_buyer_addr);
            log_it(L_ERROR, "Can't compose the transaction input");
            return NULL;
        }
    }
    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &a_price->tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return NULL;
    }
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                             &l_prev_cond_idx);
    if (!l_tx_out_cond) {
        log_it(L_WARNING, "Requested transaction has no conditional output");
        return NULL;
    }
    if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, &a_price->tx_hash, l_prev_cond_idx, NULL)) {
        log_it(L_WARNING, "Requested conditional transaction is already used out");
        return NULL;
    }
    const dap_chain_addr_t *l_seller_addr = &l_tx_out_cond->subtype.srv_xchange.seller_addr;
    dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_price->tx_hash, l_prev_cond_idx, 0);

    // add 'out' items
    // transfer selling coins
    uint256_t l_datoshi_sell,
              l_datoshi_buy,
              l_value_back;
    if (!IS_ZERO_256(a_price->rate)) {
        DIV_256_COIN(a_datoshi_buy, a_price->rate, &l_datoshi_sell);
        if (compare256(l_tx_out_cond->header.value, l_datoshi_sell) < 0) {
            l_datoshi_sell = l_tx_out_cond->header.value;
            MULT_256_COIN(l_datoshi_sell, a_price->rate, &l_datoshi_buy);
        } else
            l_datoshi_buy = a_datoshi_buy;
        debug_if(s_debug_more, L_NOTICE, "l_datoshi_sell = %s", dap_chain_balance_to_coins(l_datoshi_sell));
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_buyer_addr, l_datoshi_sell, a_price->token_sell) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_buyer_addr);
            log_it(L_ERROR, "Can't add selling coins output");
            return NULL;
        }
    }else{
        DAP_DELETE(l_buyer_addr);
        log_it(L_ERROR, "Can't add selling coins output because price rate is 0");
        return NULL;
    }
    // transfer unselling coins (partial exchange)
    debug_if(s_debug_more, L_NOTICE, "l_datoshi_cond = %s", dap_chain_balance_to_coins(l_tx_out_cond->header.value));
    if (compare256(l_tx_out_cond->header.value, l_datoshi_sell) == 1) {
        SUBTRACT_256_256(l_tx_out_cond->header.value, l_datoshi_sell, &l_value_back);
        debug_if(s_debug_more, L_NOTICE, "l_value_back = %s", dap_chain_balance_to_coins(l_value_back));
        uint256_t l_datoshi_buy_again;
        MULT_256_COIN(l_value_back, a_price->rate, &l_datoshi_buy_again);
        debug_if(s_debug_more, L_NOTICE, "l_datoshi_buy_again = %s", dap_chain_balance_to_coins(l_datoshi_buy_again));
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(
                    c_dap_chain_net_srv_xchange_uid, a_price->net->pub.id, l_value_back,
                    a_price->net->pub.id, a_price->token_buy, l_datoshi_buy_again,
                    l_seller_addr, NULL, 0);
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_seller_addr);
            log_it(L_WARNING, "Can't add selling coins back conditioned output (cond cashback)");
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
    } else // mark price order as ready
        memset(&a_price->order_hash, 0, sizeof(dap_hash_fast_t));

    // transfer buying coins
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, l_datoshi_buy, a_price->token_buy) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_buyer_addr);
        log_it(L_ERROR, "Can't add buying coins output");
        return NULL;
    }
    debug_if(s_debug_more, L_NOTICE, "l_datoshi_buy = %s", dap_chain_balance_to_coins(l_datoshi_buy));
    // transfer validator's fee
    if (!IS_ZERO_256(a_datoshi_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_datoshi_fee) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_buyer_addr);
            log_it(L_ERROR, "Can't add validator fee output");
            return NULL;
        }
        debug_if(s_debug_more, L_NOTICE, "l_validator_fee = %s", dap_chain_balance_to_coins(a_datoshi_fee));
    }
    // transfer net fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, l_native_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_buyer_addr);
            log_it(L_ERROR, "Can't add net fee output");
            return NULL;
        }
        debug_if(s_debug_more, L_NOTICE, "l_net_fee = %s", dap_chain_balance_to_coins(l_net_fee));
    }
    // transfer service fee
    if (l_service_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_service_fee_addr, l_service_fee, l_service_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_buyer_addr);
            log_it(L_ERROR, "Can't add net fee output");
            return NULL;
        }
        debug_if(s_debug_more, L_NOTICE, "l_service_fee = %s", dap_chain_balance_to_coins(l_net_fee));
    }
    // coin back
    SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_buyer_addr, l_value_back, a_price->token_buy) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_buyer_addr);
            log_it(L_ERROR, "Can't add buying coins back output");
            return NULL;
        }
    }
    debug_if(s_debug_more, L_NOTICE, "l_value_transfer = %s", dap_chain_balance_to_coins(l_value_transfer));
    debug_if(s_debug_more, L_NOTICE, "l_value_back = %s", dap_chain_balance_to_coins(l_value_back));
    // fee back
    if (!l_pay_with_native) {
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_buyer_addr, l_value_back, l_native_ticker) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                DAP_DELETE(l_buyer_addr);
                log_it(L_ERROR, "Can't add buying coins back output");
                return NULL;
            }
        }
        debug_if(s_debug_more, L_NOTICE, "l_fee_transfer = %s", dap_chain_balance_to_coins(l_fee_transfer));
        debug_if(s_debug_more, L_NOTICE, "l_value_back = %s", dap_chain_balance_to_coins(l_value_back));
    }
    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, l_seller_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        DAP_DELETE(l_buyer_addr);
        return NULL;
    }
    DAP_DELETE(l_buyer_addr);
    return l_tx;
}



// Put the transaction to mempool
static bool s_xchange_tx_put(dap_chain_datum_tx_t *a_tx, dap_chain_net_t *a_net)
{
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, a_tx, l_tx_size);
    DAP_DELETE(a_tx);
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    if (!l_chain) {
        DAP_DELETE(l_datum);
        return false;
    }
    // Processing will be made according to autoprocess policy
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");

    DAP_DELETE(l_datum);

    if (  !l_ret )
        return false;

    DAP_DELETE(l_ret);

    return true;
}

static bool s_xchange_tx_invalidate(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_wallet_t *a_wallet)
{
    if (!a_price) {
        log_it(L_WARNING, "An a_price NULL argument was passed to the s_xchange_tx_invalidate() function.");
        return false;
    }
    if (!a_wallet) {
        log_it(L_WARNING, "An a_wallet NULL argument was passed to the s_xchange_tx_invalidate() function.");
        return false;
    }
    const char *l_native_ticker = a_price->net->pub.native_ticker;
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_price->net->pub.name);
    dap_chain_addr_t *l_seller_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_price->net->pub.id);
    dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);

    // create and add reciept
    dap_chain_datum_tx_receipt_t *l_receipt = s_xchange_receipt_create(a_price, uint256_0);
    if (!l_receipt) {
        log_it(L_WARNING, "Can't create receipt");
        dap_chain_datum_tx_delete(l_tx);
        return false;
    }
    dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_receipt);
    DAP_DELETE(l_receipt);

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &a_price->tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        dap_chain_datum_tx_delete(l_tx);
        return false;
    }
    const char *l_tx_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(l_ledger, &a_price->tx_hash);
    bool l_single_channel = !dap_strcmp(l_tx_ticker, l_native_ticker);
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                             &l_prev_cond_idx);
    if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, &a_price->tx_hash, l_prev_cond_idx, NULL)) {
        log_it(L_WARNING, "Requested conditional transaction is already used out");
        dap_chain_datum_tx_delete(l_tx);
        return false;
    }
    dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_price->tx_hash, l_prev_cond_idx, 0);

    // check 'out_cond' item
    dap_chain_addr_t *l_cond_addr = &l_tx_out_cond->subtype.srv_xchange.seller_addr;
    if (dap_hash_fast_compare(&l_seller_addr->data.hash_fast, &l_cond_addr->data.hash_fast)) {
        log_it(L_WARNING, "Only owner can invalidate exchange transaction");
        dap_chain_datum_tx_delete(l_tx);
        return false;
    }
    uint256_t l_net_fee = {}, l_transfer_fee;
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_price->net->pub.id, &l_net_fee, &l_addr_fee);
    uint256_t l_total_fee = {};
    SUM_256_256(a_price->fee, l_net_fee, &l_total_fee);
    // list of transaction with 'out' items to get net fee
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                             l_seller_addr, l_total_fee, &l_transfer_fee);
    if(!l_list_used_out) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_WARNING, "Nothing to pay for network fee (not enough funds)");
        return false;
    }
    // add 'in' items to net fee
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_to_items, l_transfer_fee)) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_ERROR, "Can't compose the transaction input");
        return NULL;
    }

    // return coins to owner
    if (l_single_channel) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, l_seller_addr, l_tx_out_cond->header.value) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_seller_addr);
            log_it(L_ERROR, "Cant add returning coins output");
            return false;
        }
    } else {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, l_tx_out_cond->header.value,
                                                l_tx_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_seller_addr);
            log_it(L_ERROR, "Cant add returning coins output");
            return false;
        }
    }

    // Network fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, &l_addr_fee, l_net_fee) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_seller_addr);
            log_it(L_ERROR, "Cant add network fee output");
            return NULL;
        }
    }
    // Validator's fee
    if (!IS_ZERO_256(a_price->fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_price->fee) == 1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_seller_addr);
            log_it(L_ERROR, "Cant add validator's fee output");
            return NULL;
        }
    }

    // put the net fee cashback
    uint256_t l_fee_back = {};
    SUBTRACT_256_256(l_transfer_fee, l_total_fee, &l_fee_back);
    if (!IS_ZERO_256(l_fee_back) &&
            dap_chain_datum_tx_add_out_item(&l_tx, l_seller_addr, l_tx_out_cond->header.value) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_seller_addr);
        log_it(L_ERROR, "Cant add fee cachback output");
        return false;
    }
    DAP_DELETE(l_seller_addr);

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, l_seller_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        return false;
    }
    if (!s_xchange_tx_put(l_tx, a_price->net)) {
        return false;
    }
    return true;
}

/**
 * @brief s_xchange_order_create
 * @param a_price
 * @param a_tx
 * @return
 */
char *s_xchange_order_create(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_datum_tx_t *a_tx)
{
    dap_chain_hash_fast_t l_tx_hash = {};
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_tx_hash);
    a_price->tx_hash = l_tx_hash;
    dap_chain_node_addr_t *l_node_addr = dap_chain_net_get_cur_addr(a_price->net);
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 =  SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
    uint256_t l_datoshi_buy = uint256_0;
    MULT_256_COIN(a_price->datoshi_sell, a_price->rate, &l_datoshi_buy);
    dap_srv_xchange_order_ext_t l_ext={0};
    l_ext.datoshi_buy = l_datoshi_buy;
    strncpy(l_ext.token_buy, a_price->token_buy, DAP_CHAIN_TICKER_SIZE_MAX);
    uint32_t l_ext_size = sizeof(dap_srv_xchange_order_ext_t);
    char *l_order_hash_str = dap_chain_net_srv_order_create(a_price->net, SERV_DIR_SELL, l_uid, *l_node_addr,
                                                            l_tx_hash, &a_price->datoshi_sell, l_unit, a_price->token_sell, 0,
                                                            (uint8_t *)&l_ext, l_ext_size, 0, NULL, 0, a_price->wallet_key);
    return l_order_hash_str;
}

/**
 * @brief s_xchange_price_from_order
 * @param a_net
 * @param a_order
 * @return
 */
dap_chain_net_srv_xchange_price_t *s_xchange_price_from_order(dap_chain_net_t *a_net, dap_chain_net_srv_order_t *a_order,  bool a_ret_is_invalid)
{
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    if (!l_price) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    dap_srv_xchange_order_ext_t *l_ext = (dap_srv_xchange_order_ext_t *)a_order->ext_n_sign;
    strcpy(l_price->token_buy, l_ext->token_buy);
    l_price->datoshi_buy = l_ext->datoshi_buy;
    strcpy(l_price->token_sell, a_order->price_ticker);
    l_price->datoshi_sell = a_order->price;
    l_price->net = a_net;
    if (!IS_ZERO_256(l_price->datoshi_buy)) {
        DIV_256_COIN(l_price->datoshi_buy, l_price->datoshi_sell, &l_price->rate);
        dap_hash_fast_t *l_final_hash = dap_chain_ledger_get_final_chain_tx_hash(a_net->pub.ledger,
                                           DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &a_order->tx_cond_hash);
        if (l_final_hash) {
            l_price->tx_hash = *l_final_hash;
            return l_price;
        } else {
            log_it(L_WARNING, "This order have no active conditional transaction");
            if (a_ret_is_invalid) {
                dap_hash_fast_t l_tx_hash_zero = {0};
                l_price->tx_hash = l_tx_hash_zero;
                return l_price;
            }
        }
    } else
        log_it(L_WARNING, "Can't calculate price rate, because amount od datoshi sell is zero");
    DAP_DELETE(l_price);
    return NULL;
}

/**
 * @brief s_cli_srv_xchange_order
 * @param a_argc
 * @param a_argv
 * @param a_arg_index
 * @param a_str_reply
 * @return
 */
static int s_cli_srv_xchange_order(int a_argc, char **a_argv, int a_arg_index, char **a_str_reply)
{
    enum {
        CMD_NONE, CMD_CREATE, CMD_REMOVE, CMD_UPDATE, CMD_HISTORY, CMD_STATUS
    };
    int l_cmd_num = CMD_NONE;
    if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, MIN(a_argc, a_arg_index + 1), "create", NULL)) {
        l_cmd_num = CMD_CREATE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, MIN(a_argc, a_arg_index + 1), "remove", NULL)) {
        l_cmd_num = CMD_REMOVE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, MIN(a_argc, a_arg_index + 1), "update", NULL)) {
        l_cmd_num = CMD_UPDATE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, MIN(a_argc, a_arg_index + 1), "history", NULL)) {
        l_cmd_num = CMD_HISTORY;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, MIN(a_argc, a_arg_index + 1), "status", NULL)) {
        l_cmd_num = CMD_STATUS;
    }
    int l_arg_index = a_arg_index + 1;
    const char *l_net_str = NULL;
    const char *l_token_sell_str = NULL, *l_token_buy_str = NULL;
    const char *l_wallet_str = NULL;
    dap_chain_net_t *l_net = NULL;
    switch (l_cmd_num) {
        case CMD_CREATE: {
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order create' requires parameter -net");
                return -2;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -3;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_sell", &l_token_sell_str);
            if (!l_token_sell_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'price create' requires parameter -token_sell");
                return -5;
            }
            if (!dap_chain_ledger_token_ticker_check(l_net->pub.ledger, l_token_sell_str)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Token ticker %s not found", l_token_sell_str);
                return -6;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_buy", &l_token_buy_str);
            if (!l_token_buy_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'price create' requires parameter -token_buy");
                return -5;
            }
            if (!dap_chain_ledger_token_ticker_check(l_net->pub.ledger, l_token_buy_str)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Token ticker %s not found", l_token_buy_str);
                return -6;
            }
            const char *l_val_sell_str = NULL, *l_val_rate_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_val_sell_str);
            if (!l_val_sell_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'price create' requires parameter -value");
                return -8;
            }
            uint256_t l_datoshi_sell = dap_chain_balance_scan(l_val_sell_str);
            if (IS_ZERO_256(l_datoshi_sell)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Format -value <unsigned integer 256>");
                return -9;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-rate", &l_val_rate_str);
            if (!l_val_rate_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'price create' requires parameter -rate");
                return -8;
            }
            uint256_t l_rate = dap_chain_coins_to_balance(l_val_rate_str);
            if (IS_ZERO_256(l_rate)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Format -rate n.n = buy / sell (eg: 1.0, 1.135)");
                return -9;
            }
            const char *l_fee_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
            if (!l_fee_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'price create' requires parameter -fee");
                return -20;
            }
            uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
            if (IS_ZERO_256(l_fee)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Format -fee <unsigned integer 256>");
                return -21;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_wallet_str);
            if (!l_wallet_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'price create' requires parameter -wallet");
                return -10;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
            if (!l_wallet) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified wallet not found");
                return -11;
            }
            uint256_t l_value = dap_chain_wallet_get_balance(l_wallet, l_net->pub.id, l_token_sell_str);
            uint256_t l_value_sell = l_datoshi_sell;
            if (!dap_strcmp(l_net->pub.native_ticker, l_token_sell_str)) {
                if (SUM_256_256(l_value_sell, l_fee, &l_value_sell)) {
                    dap_chain_wallet_close(l_wallet);
                    log_it(L_ERROR, "Integer overflow with sum of value and fee");
                    return -22;
                }
            } else { // sell non-native ticker
                uint256_t l_fee_value = dap_chain_wallet_get_balance(l_wallet, l_net->pub.id, l_net->pub.native_ticker);
                if (compare256(l_fee_value, l_fee) == -1) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Not enough cash for fee in specified wallet");
                    dap_chain_wallet_close(l_wallet);
                    return -23;
                }
            }
            if (compare256(l_value, l_value_sell) == -1) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Not enough cash in specified wallet");
                dap_chain_wallet_close(l_wallet);
                return -12;
            }
            // Create the price
            dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
            if (!l_price) {
                log_it(L_CRITICAL, "Memory allocation error");
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Out of memory");
                dap_chain_wallet_close(l_wallet);
                return -1;
            }
            l_price->wallet_str = dap_strdup(l_wallet_str);
            dap_stpcpy(l_price->token_sell, l_token_sell_str);
            l_price->net = l_net;
            dap_stpcpy(l_price->token_buy, l_token_buy_str);
            l_price->datoshi_sell = l_datoshi_sell;
            l_price->rate = l_rate;
            l_price->fee = l_fee;
            // Create conditional transaction
            dap_chain_datum_tx_t *l_tx = s_xchange_tx_create_request(l_price, l_wallet);
            if (!l_tx) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't compose the conditional transaction");
                DAP_DELETE(l_price->wallet_str);
                DAP_DELETE(l_price);
                dap_chain_wallet_close(l_wallet);
                return -14;
            }
            // Create the order & put it to GDB
            l_price->wallet_key = dap_chain_wallet_get_key(l_wallet, 0);
            char *l_order_hash_str = s_xchange_order_create(l_price, l_tx);
            dap_chain_wallet_close(l_wallet);
            if (l_order_hash_str) {
                dap_chain_hash_fast_from_str(l_order_hash_str, &l_price->order_hash);
                if(!s_xchange_tx_put(l_tx, l_net)) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't put transaction to mempool");
                    dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_str);
                    DAP_DELETE(l_order_hash_str);
                    DAP_DELETE(l_price->wallet_str);
                    DAP_DELETE(l_price);
                    return -15;
                }
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_str);
                DAP_DELETE(l_order_hash_str);
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't compose the order");
                DAP_DELETE(l_price->wallet_str);
                DAP_DELETE(l_price);
                return -18;
            }
        } break;

        case CMD_HISTORY:{
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order history' requires parameter -net");
                return -2;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -3;
            }

            const char * l_order_hash_str = NULL;
            const char * l_addr_hash_str = NULL;

            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-addr", &l_addr_hash_str);

            if (!l_order_hash_str && ! l_addr_hash_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order history' requires parameter -order or -addr" );
                return -12;
            }
            if(l_addr_hash_str){
                dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_addr_hash_str);
                if (!l_addr) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Incorrect chain address");
                    return -14;
                }
                if (dap_chain_addr_check_sum(l_addr) != 1 ) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Incorrect chain address");
                    return -15;
                }
                dap_list_t *l_tx_list = dap_chain_net_get_tx_cond_all_for_addr(l_net,l_addr, c_dap_chain_net_srv_xchange_uid );
                dap_string_t * l_str_reply = dap_string_new("");
                while(l_tx_list ){
                    dap_chain_datum_tx_t * l_tx_cur = (dap_chain_datum_tx_t*) l_tx_list->data;
                    s_string_append_tx_cond_info(l_str_reply, l_net, l_tx_cur );

                    //INFINITE LOOP ????
                    
                }
                dap_list_free(l_tx_list);
                *a_str_reply = dap_string_free(l_str_reply, false);
                DAP_DELETE(l_addr);
            }
            if(l_order_hash_str){
                dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
                if (!l_order) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified order not found");
                    return -13;
                }

                dap_chain_datum_tx_t * l_tx = dap_chain_net_get_tx_by_hash(l_net,&l_order->tx_cond_hash, TX_SEARCH_TYPE_NET);
                if( l_tx){
                    int l_rc = s_tx_check_for_open_close(l_net,l_tx);
                    char *l_tx_hash = dap_chain_hash_fast_to_str_new(&l_order->tx_cond_hash);
                    if(l_rc == 0){
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "WRONG TX %s", l_tx_hash);
                    }else if(l_rc == 1){
                        dap_string_t * l_str_reply = dap_string_new("");
                        s_string_append_tx_cond_info(l_str_reply, l_net, l_tx);
                        *a_str_reply = dap_string_free(l_str_reply, false);
                    }else if(l_rc == 2){
                        dap_string_t * l_str_reply = dap_string_new("");
                        dap_list_t *l_tx_list = dap_chain_net_get_tx_cond_chain(l_net,&l_order->tx_cond_hash, c_dap_chain_net_srv_xchange_uid );
                        while(l_tx_list ){
                            dap_chain_datum_tx_t * l_tx_cur = (dap_chain_datum_tx_t*) l_tx_list->data;
                            s_string_append_tx_cond_info(l_str_reply, l_net, l_tx_cur );

                            //INFINITE LOOP ????

                        }
                        dap_list_free(l_tx_list);
                        *a_str_reply = dap_string_free(l_str_reply, false);
                    }else{
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Internal error!");
                    }
                }else{
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "No history");
                }
            }
        } break;

        case CMD_REMOVE:
        case CMD_UPDATE: {
            const char * l_order_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'price %s' requires parameter -net",
                                                                l_cmd_num == CMD_REMOVE ? "remove" : "update");
                return -2;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -3;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_wallet_str);
            if (!l_wallet_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'price %s' requires parameter -wallet",
                                                                l_cmd_num == CMD_REMOVE ? "remove" : "update");
                return -10;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
            if (!l_wallet) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified wallet not found");
                return -11;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'price %s' requires parameter -order",
                                                                l_cmd_num == CMD_REMOVE ? "remove" : "update");
                return -12;
            }
            dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
            if (!l_order) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified order not found");
                return -13;
            }
            dap_chain_net_srv_xchange_price_t *l_price = s_xchange_price_from_order(l_net, l_order, false);
            if (!l_order) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create price object from order");
                return -13;
            }

            if (l_cmd_num == CMD_REMOVE) {
                dap_string_t *l_str_reply = dap_string_new("");
                bool l_ret = s_xchange_tx_invalidate(l_price, l_wallet);
                dap_chain_wallet_close(l_wallet);
                if (!l_ret) {
                    if (!l_price) {
                        dap_string_append_printf(l_str_reply, "Can't get price for order %s\n", l_order_hash_str);
                    } else {
                        char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_price->tx_hash);
                        dap_string_append_printf(l_str_reply, "Can't invalidate transaction %s\n", l_tx_hash_str);
                        DAP_DELETE(l_tx_hash_str);
                    }
                }
                if (dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_str)) {
                    dap_string_append_printf(l_str_reply, "Can't remove order %s\n", l_order_hash_str);
                } else {
                    dap_string_append_printf(l_str_reply, "Remove order %s\n", l_order_hash_str);
                }
                DAP_DELETE(l_price);
                if (!l_str_reply->len) {
                    dap_string_append(l_str_reply, "Price successfully removed");
                }
                *a_str_reply = dap_string_free(l_str_reply, false);
            } else {    // CMD_UPDATE
                const char *l_val_sell_str = NULL, *l_val_rate_str = NULL, *l_wallet_str = NULL, *l_new_wallet_str = NULL;
                uint256_t l_datoshi_sell = {};
                uint256_t l_rate = uint256_0;
                dap_chain_wallet_t *l_wallet = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-coins", &l_val_sell_str);
                if (l_val_sell_str) {
                    l_datoshi_sell = dap_chain_balance_scan(l_val_sell_str);
                    if (IS_ZERO_256(l_datoshi_sell)) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Format -coins <unsigned long long>");
                        return -9;
                    }
                }
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-rate", &l_val_rate_str);
                if (l_val_rate_str) {
                    l_rate = dap_chain_coins_to_balance(l_val_rate_str);
                    if (IS_ZERO_256(l_rate)) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Format -rate <long double> = sell / buy");
                        return -9;
                    }
                }
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_new_wallet_str);
                l_wallet_str = l_new_wallet_str ? l_new_wallet_str : l_price->wallet_str;
                l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
                if (!l_wallet) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified wallet not found");
                    return -11;
                }
                if (!l_val_sell_str && !l_val_rate_str && !l_wallet_str) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "At least one of updating parameters is mandatory");
                    return -13;
                }
                uint256_t l_value = dap_chain_wallet_get_balance(l_wallet, l_net->pub.id, l_token_sell_str);
                if (!IS_ZERO_256(l_datoshi_sell) && compare256(l_value, l_datoshi_sell) == -1) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Not enough cash in specified wallet");
                        dap_chain_wallet_close(l_wallet);
                        return -12;
                }
                if (l_val_sell_str) {
                    l_price->datoshi_sell = l_datoshi_sell;
                }
                if (l_val_rate_str) {
                    l_price->rate = l_rate;
                }
                // Update the transaction
                dap_chain_datum_tx_t *l_tx = s_xchange_tx_create_request(l_price, l_wallet);
                if (l_new_wallet_str) {
                    dap_chain_wallet_close(l_wallet);
                    l_wallet = dap_chain_wallet_open(l_price->wallet_str, dap_chain_wallet_get_path(g_config));
                    DAP_DELETE(l_price->wallet_str);
                    l_price->wallet_str = dap_strdup(l_new_wallet_str);
                }
                if (!l_tx) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't compose the conditional transaction");
                    return -14;
                }
                bool l_ret = s_xchange_tx_invalidate(l_price, l_wallet); // may be changed to old price later
                dap_chain_wallet_close(l_wallet);
                if (!l_ret) {
                    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_price->tx_hash);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't invalidate transaction %s\n", l_tx_hash_str);
                    DAP_DELETE(l_tx_hash_str);
                    return -17;
                }
                // Update the order
                dap_chain_net_srv_order_delete_by_hash_str_sync(l_price->net, l_order_hash_str);
                DAP_DELETE(l_order_hash_str);
                l_order_hash_str = s_xchange_order_create(l_price, l_tx);
                if (l_order_hash_str) {
                    dap_chain_hash_fast_from_str(l_order_hash_str, &l_price->order_hash);
                    if(!s_xchange_tx_put(l_tx, l_net)) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't put transaction to mempool");
                        dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_str);
                        DAP_DELETE(l_order_hash_str);
                        return -15;
                    }
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_str);
                    DAP_DELETE(l_order_hash_str);
                } else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't compose the order");
                    DAP_DELETE(l_price->wallet_str);
                    DAP_DELETE(l_price);
                    return -18;
                }
            }
        } break;

        case CMD_STATUS: {
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order status' requires parameter -net");
                return -2;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -3;
            }
            const char * l_order_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order history' requires parameter -order or -addr" );
                return -12;
            }
            dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
            if (!l_order) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified order not found");
                return -13;
            }
            dap_hash_fast_t *l_final_hash = dap_chain_ledger_get_final_chain_tx_hash(l_net->pub.ledger,
                                                 DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_order->tx_cond_hash);
            if (!l_final_hash) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified order have no active tx (copmleted)");
                DAP_DELETE(l_order);
                return -18;
            }
            dap_chain_datum_tx_t *l_tx = dap_chain_ledger_tx_find_by_hash(l_net->pub.ledger, l_final_hash);
            if (!l_tx) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Internal error");
                DAP_DELETE(l_order);
                return -19;
            }
            dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                                  NULL);
            if (!l_out_cond) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified order have no active conditional tx (copmleted)");
                DAP_DELETE(l_order);
                return -20;
            }
            uint256_t l_filled, l_filled_percent, l_rate;
            dap_srv_xchange_order_ext_t *l_ext = (dap_srv_xchange_order_ext_t *)l_order->ext_n_sign;
            char *l_amount_str = dap_chain_balance_to_coins(l_order->price);
            char *l_current_str = dap_chain_balance_to_coins(l_out_cond->header.value);
            SUBTRACT_256_256(l_order->price, l_out_cond->header.value, &l_filled);
            DIV_256_COIN(l_filled, l_out_cond->header.value, &l_filled_percent);
            MULT_256_256(l_filled_percent, dap_chain_uint256_from(100), &l_filled_percent);
            char *l_filled_str = dap_chain_balance_to_coins(l_filled_percent);
            DIV_256_COIN(l_ext->datoshi_buy, l_order->price, &l_rate);
            char *l_rate_str = dap_chain_balance_to_coins(l_rate);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "tokenSell: %s, tokenBuy: %s, amount: %s, current %s, filled: %s%% rate(buy/sell): %s\n",
                                                            l_order->price_ticker, l_ext->token_buy,
                                                            l_amount_str, l_current_str,
                                                            l_filled_str, l_rate_str);
            DAP_DEL_Z(l_amount_str);
            DAP_DEL_Z(l_current_str);
            DAP_DEL_Z(l_filled_str);
            DAP_DEL_Z(l_rate_str);
            DAP_DELETE(l_order);
        } break;

        default: {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Subcommand %s not recognized", a_argv[a_arg_index]);
            return -4;
        }
    }
    return 0;
}

// Filter for find tx with DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE
static bool s_filter_tx_list(dap_chain_datum_t *a_datum, dap_chain_t *a_chain, void *a_filter_func_param)
{
    UNUSED(a_chain);
    // Datum type filter -> only tx
    if(!a_datum || a_datum->header.type_id != DAP_CHAIN_DATUM_TX)
        return false;
    dap_chain_datum_tx_t *l_datum_tx = (dap_chain_datum_tx_t*) a_datum->data;
    // Get time from parameters
    dap_time_t *l_time_mass = (dap_time_t*) a_filter_func_param;
    dap_time_t l_time_begin = 0;
    dap_time_t l_time_end = 0;
    if(l_time_mass) {
        l_time_begin = l_time_mass[0];
        l_time_end = l_time_mass[1];
    }
    // Time filter
    if(l_time_begin && l_datum_tx->header.ts_created < l_time_begin)
        return false;
    if(l_time_end && l_datum_tx->header.ts_created > l_time_end)
        return false;
    // Item filter -> if present tx_out_cond with subtype == SRV_XCHANGE
    dap_chain_tx_out_cond_t *l_out_cond_item = NULL;
    int l_item_idx = 0;
    do {
        l_out_cond_item = (dap_chain_tx_out_cond_t*) dap_chain_datum_tx_item_get(l_datum_tx, &l_item_idx, TX_ITEM_TYPE_OUT_COND, NULL);
        l_item_idx++;
        if(l_out_cond_item && l_out_cond_item->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE) {
            return true;
        }

    }
    while(l_out_cond_item);
    return false;
}

/**
 * @brief Check for open/close
 * @param a_net
 * @param a_tx
 * @return 0 if its not SRV_XCHANGE transaction, 1 if its closed, 2 if its open
 */
static int s_tx_check_for_open_close(dap_chain_net_t * a_net, dap_chain_datum_tx_t * a_tx)
{
    int l_cond_idx = 0;
    dap_hash_fast_t l_tx_hash = {0};
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_hash_fast(a_tx, l_tx_size, &l_tx_hash);
    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                               &l_cond_idx);
    if (l_out_cond_item) {
        if(dap_chain_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &l_tx_hash, l_cond_idx, NULL))
            return 1; // If its SRV_XCHANGE and spent its closed
        else
            return 2; // If its SRV_XCHANGE and not spent its open
    }
    return 0;
}

/**
 * @brief Append tx info to the reply string
 * @param a_reply_str
 * @param a_net
 * @param a_tx
 */
static void s_string_append_tx_cond_info( dap_string_t * a_reply_str, dap_chain_net_t * a_net, dap_chain_datum_tx_t * a_tx )
{
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);

    dap_hash_fast_t l_tx_hash = {0};
    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE+1];

    dap_hash_fast(a_tx, l_tx_size, &l_tx_hash);
    dap_chain_hash_fast_to_str(&l_tx_hash, l_tx_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE + 1);
//                    dap_string_append_printf(l_reply_str, "Hash: %s\n", l_hash_str);

    // Get input token ticker
    const char * l_tx_input_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(
                a_net->pub.ledger, &l_tx_hash);




    // Find SRV_XCHANGE out_cond item
    int l_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                               &l_cond_idx);
    bool l_is_cond_out = false;
    if ( l_out_cond_item && (l_out_cond_item->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE) )
    {
        bool l_is_closed = dap_chain_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &l_tx_hash, l_cond_idx, NULL);

        uint256_t l_value_from = l_out_cond_item->header.value;
        uint256_t l_value_to = l_out_cond_item->subtype.srv_xchange.buy_value;
        char *l_value_to_str = dap_chain_balance_to_coins(l_value_to);
        char *l_value_from_str = dap_chain_balance_to_coins(l_value_from);

        dap_string_append_printf(a_reply_str, "Hash: %s", l_tx_hash_str);
        dap_string_append_printf(a_reply_str, "  Status: %s", l_is_closed ? "closed" : "open");
        dap_string_append_printf(a_reply_str, "  From: %s %s", l_value_from_str, l_tx_input_ticker);
        dap_string_append_printf(a_reply_str, "  To: %s %s", l_value_to_str, l_out_cond_item->subtype.srv_xchange.buy_token);

        DAP_DELETE(l_value_from_str);
        DAP_DELETE(l_value_to_str);
        l_is_cond_out = true;
    }
    if(l_is_cond_out){
        // Get IN_COND items from transaction
        int l_item_idx = 0;
        byte_t *l_tx_item;
        while ((l_tx_item = dap_chain_datum_tx_item_get(a_tx, &l_item_idx, TX_ITEM_TYPE_IN_COND , NULL)) != NULL){
            dap_chain_tx_in_cond_t * l_in_cond = (dap_chain_tx_in_cond_t *) l_tx_item;
            char l_tx_prev_cond_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_in_cond->header.tx_prev_hash,l_tx_prev_cond_hash_str, sizeof(l_tx_prev_cond_hash_str));
            dap_string_append_printf(a_reply_str, "  Prev cond: %s", l_tx_prev_cond_hash_str);
            l_item_idx++;
        }
        dap_string_append_printf(a_reply_str, "\n");
    }

}


static int s_cli_srv_xchange_tx_list_addr (
                    dap_chain_net_t     *a_net,
                        dap_time_t      a_after,
                        dap_time_t      a_before,
                    dap_chain_addr_t    *a_addr,
                            int         a_opt_status,
                                char    **a_str_reply
                                          )
{
char l_hash_str [DAP_CHAIN_HASH_FAST_STR_SIZE + 8] = {0};
dap_chain_hash_fast_t l_tx_first_hash = {0};
dap_chain_datum_tx_t    *l_datum_tx;
size_t  l_datum_tx_size, l_tx_total;
int l_item_idx;
bool l_rc = false;
dap_string_t *l_reply_str;
dap_hash_fast_t l_hash;
dap_chain_tx_out_cond_t *l_out_cond_item;


    if ( !(l_reply_str = dap_string_new("")) )                              /* Prepare output string discriptor*/
        return  log_it(L_ERROR, "Cannot allocate a memory, errno=%d", errno), -ENOMEM;

    memset(&l_tx_first_hash, 0, sizeof(dap_chain_hash_fast_t));             /* Initial hash == zero */


    for (l_tx_total = 0;
            (l_datum_tx = dap_chain_ledger_tx_find_by_addr(a_net->pub.ledger, NULL, a_addr, &l_tx_first_hash));
                l_tx_total++)
    {
        /* Check time range (if need ) */
        if ( !(l_datum_tx->header.ts_created > a_after) )
            continue;

        if ( a_before && (l_datum_tx->header.ts_created > a_before) )
            continue;


        /* TX hash */
        l_datum_tx_size = dap_chain_datum_tx_get_size(l_datum_tx);

        if ( !dap_hash_fast(l_datum_tx, l_datum_tx_size, &l_hash) )
        {                                                                   /* Never must be happend, but ... */
            log_it(L_ERROR, "dap_hash_fast(..., %zu octets) return error", l_datum_tx_size);
            dump_it("l_datum_tx", l_datum_tx, l_datum_tx_size);
            continue;
        }


        /* Find SRV_XCHANGE out_cond item */
        for (l_out_cond_item = NULL, l_item_idx = 0;
            (l_out_cond_item = (dap_chain_tx_out_cond_t *) dap_chain_datum_tx_item_get(l_datum_tx, &l_item_idx, TX_ITEM_TYPE_OUT_COND, NULL));
                l_item_idx++)
        {
            if ( l_out_cond_item->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE )
                continue;

            if (a_opt_status)                                                   /* 1 - closed, 2 - open  */
            {
                l_rc = dap_chain_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &l_hash, l_item_idx, NULL);

                if ( a_opt_status )
                {
                    if ( (a_opt_status == 1) && l_rc )              /* Select close only */
                        {;}
                    else if ( (a_opt_status == 2) &&  (!l_rc) )     /* Select open only */
                        {;}
                    else continue;
                }
            }
            dap_chain_hash_fast_to_str(&l_hash, l_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE + 1);
            dap_string_append_printf(l_reply_str, "Hash: %s\n", l_hash_str);


            const char *l_tx_input_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &l_hash);

            uint256_t l_value_to = l_out_cond_item->subtype.srv_xchange.buy_value;
            uint256_t l_tx_input_values = dap_chain_net_get_tx_total_value(a_net, l_datum_tx);

            char *l_tx_input_values_str = dap_chain_balance_to_coins(l_tx_input_values);
            char *l_value_from_str = dap_chain_balance_to_coins(l_tx_input_values);
            char *l_value_to_str = dap_chain_balance_to_coins(l_value_to);

            dap_string_append_printf(l_reply_str, "  Status: %s,", l_rc ? "closed" : "open");
            dap_string_append_printf(l_reply_str, "  From: %s %s,", l_tx_input_values_str, l_tx_input_ticker);
            dap_string_append_printf(l_reply_str, "  To: %s %s\n", l_value_to_str, l_out_cond_item->subtype.srv_xchange.buy_token);

            DAP_DELETE(l_value_from_str);
            DAP_DELETE(l_value_to_str);
            dap_string_append(l_reply_str, "\n");
        }

    }


    *a_str_reply = dap_string_free(l_reply_str, false);                     /* Free string descriptor, but keep ASCIZ buffer itself */
    return  0;
}




static int s_cli_srv_xchange(int a_argc, char **a_argv, char **a_str_reply)
{
    enum {CMD_NONE = 0, CMD_ORDER, CMD_ORDERS, CMD_PURCHASE, CMD_ENABLE, CMD_DISABLE, CMD_TX_LIST, CMD_TOKEN_PAIR };
    int l_arg_index = 1, l_cmd_num = CMD_NONE;
    bool l_rc;

    if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, MIN(a_argc, l_arg_index + 1), "order", NULL)) {
        l_cmd_num = CMD_ORDER;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, MIN(a_argc, l_arg_index + 1), "orders", NULL)) {
        l_cmd_num = CMD_ORDERS;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, MIN(a_argc, l_arg_index + 1), "purchase", NULL)) {
        l_cmd_num = CMD_PURCHASE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, MIN(a_argc, l_arg_index + 1), "enable", NULL)) {
        l_cmd_num = CMD_ENABLE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, MIN(a_argc, l_arg_index + 1), "disable", NULL)) {
        l_cmd_num = CMD_DISABLE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, MIN(a_argc, l_arg_index + 1), "tx_list", NULL)) {
        l_cmd_num = CMD_TX_LIST;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, MIN(a_argc, l_arg_index + 1), "token_pair", NULL)) {
        l_cmd_num = CMD_TOKEN_PAIR;
    }


    switch (l_cmd_num) {
        case CMD_ORDER:
            return s_cli_srv_xchange_order(a_argc, a_argv, l_arg_index + 1, a_str_reply);
        case CMD_ORDERS: {
            const char *l_net_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'orders' requires parameter -net");
                return -2;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -3;
            }

            char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group(l_net);

            size_t l_orders_count = 0;
            dap_global_db_obj_t * l_orders = dap_global_db_get_all_sync(l_gdb_group_str, &l_orders_count);
            dap_chain_net_srv_xchange_price_t *l_price;
            dap_string_t *l_reply_str = dap_string_new("");


            for (size_t i = 0; i < l_orders_count; i++)
            {
                dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)l_orders[i].value;

                if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_XCHANGE_ID)
                    continue;

                // TODO add filters to list (tokens, network, etc.)
                l_price = s_xchange_price_from_order(l_net, l_order, true);
                if( !l_price ){
                    log_it(L_WARNING,"Can't create price from order");
                    continue;
                }

                uint256_t l_datoshi_buy;
                char *l_cp_buy_coins, *l_cp_buy_datoshi, *l_cp_sell_coins, *l_cp_sell_datoshi, *l_cp_rate;
                char* l_status_order;
                dap_hash_fast_t l_hash_fast_ref = {0};
                if (dap_hash_fast_compare(&l_price->tx_hash, &l_hash_fast_ref))
                    l_status_order  = "INVALID";
                else
                    l_status_order = "OPEN";

                MULT_256_COIN(l_price->datoshi_sell, l_price->rate, &l_datoshi_buy);  /* sell/buy computation */

                dap_string_append_printf(l_reply_str, "orderHash: %s (%s) tokSel: %s, net: %s, tokBuy: %s, sell: %s (%s), buy: %s (%s) buy/sell: %s\n", l_orders[i].key,
                                         l_status_order, l_price->token_sell, l_price->net->pub.name,
                                         l_price->token_buy,
                                         l_cp_sell_coins = dap_chain_balance_to_coins(l_price->datoshi_sell),
                                         l_cp_sell_datoshi = dap_chain_balance_print(l_price->datoshi_sell),
                                         l_cp_buy_coins = dap_chain_balance_to_coins(l_price->datoshi_buy),
                                         l_cp_buy_datoshi = dap_chain_balance_print(l_datoshi_buy),
                                         l_cp_rate = dap_chain_balance_to_coins(l_price->rate));

                DAP_DEL_Z(l_cp_buy_coins);
                DAP_DEL_Z(l_cp_buy_datoshi);
                DAP_DEL_Z(l_cp_sell_coins);
                DAP_DEL_Z(l_cp_sell_datoshi);
                DAP_DEL_Z(l_cp_rate);
                DAP_DEL_Z(l_price);
            }
            dap_global_db_objs_delete(l_orders, l_orders_count);
            DAP_DELETE( l_gdb_group_str);
            if (!l_reply_str->len) {
                dap_string_append(l_reply_str, "No orders found");
            }
            *a_str_reply = dap_string_free(l_reply_str, false);
        } break;


        case CMD_PURCHASE: {
            const char *l_net_str = NULL, *l_wallet_str = NULL, *l_order_hash_str = NULL, *l_val_buy_str = NULL, *l_val_fee_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'purchase' requires parameter -net");
                return -2;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -3;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_wallet_str);
            if (!l_wallet_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'purchase' requires parameter -wallet");
                return -10;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
            if (!l_wallet) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified wallet not found");
                return -11;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'purchase' requires parameter -order");
                return -12;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_val_buy_str);
            if (!l_val_buy_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'purchase' requires parameter -value");
                return -8;
            }
            uint256_t l_datoshi_buy = dap_chain_balance_scan(l_val_buy_str);
            if (IS_ZERO_256(l_datoshi_buy)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Format -value <unsigned int256>");
                return -9;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_val_fee_str);
            if (!l_val_fee_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'purchase' requires parameter -fee");
                return  -8;
            }
            uint256_t  l_datoshi_fee = dap_chain_balance_scan(l_val_fee_str);
            if (IS_ZERO_256(l_datoshi_fee)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Format -fee <unsigned int256>");
                return -9;
            }
            dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
            if (l_order) {
                dap_chain_net_srv_xchange_price_t *l_price = s_xchange_price_from_order(l_net, l_order, false);
                if(!l_price){
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create price from order");
                    return -13;
                }
                // Create conditional transaction
                dap_chain_hash_fast_from_str(l_order_hash_str, &l_price->order_hash);
                dap_chain_datum_tx_t *l_tx = s_xchange_tx_create_exchange(l_price, l_wallet, l_datoshi_buy, l_datoshi_fee);
                if (l_tx && s_xchange_tx_put(l_tx, l_net) &&
                        dap_hash_fast_is_blank(&l_price->order_hash))
                    dap_chain_net_srv_order_delete_by_hash_str_sync(l_price->net, l_order_hash_str);
                DAP_DELETE(l_price);
                DAP_DELETE(l_order);
                dap_cli_server_cmd_set_reply_text(a_str_reply, l_tx ? "Exchange transaction has done" :
                                                                      "Exchange transaction error");
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified order not found");
                return -13;
            }
        } break;
        case CMD_ENABLE: {
            s_srv_xchange->enabled = true;
        } break;
        case CMD_DISABLE: {
            s_srv_xchange->enabled = false;
        } break;
        case CMD_TX_LIST: {
            const char *l_net_str = NULL, *l_time_begin_str = NULL, *l_time_end_str = NULL;
            const char *l_status_str = NULL, *l_addr_str = NULL;  /* @RRL:  #6294 */
            int     l_opt_status, l_show_tx_nr = 0;
            dap_chain_addr_t *l_addr;

            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-time_from", &l_time_begin_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-time_to", &l_time_end_str);

            /*
             * @RRL:  #6294: [[-addr <addr> [-status closed | open]]
             * we should check for valid combination of the status and addr options
             */
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-addr", &l_addr_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-status", &l_status_str);


            /* Validate input arguments ... */
            l_opt_status = 0;   /* 0 - all */

            if ( l_status_str )
            {
                /* 1 - closed, 2 - open  */
                if ( dap_strcmp (l_status_str, "close") == 0 )
                    l_opt_status = 1;
                else if ( dap_strcmp (l_status_str, "open") == 0 )
                    l_opt_status = 2;
                else if ( dap_strcmp (l_status_str, "all") == 0 )
                    l_opt_status = 0;
                else  {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Unrecognized '-status %s'", l_status_str);
                    return -3;
                }
            }


            if(!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'tx_list' requires parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if(!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }

            dap_time_t l_time[2];
            l_time[0] = dap_time_from_str_rfc822(l_time_begin_str);
            l_time[1] = dap_time_from_str_rfc822(l_time_end_str);


            /* Dispatch request processing to ... */
            if ( l_addr_str )
            {
                if ( !(l_addr = dap_chain_addr_from_str(l_addr_str)) )
                    return  dap_cli_server_cmd_set_reply_text(a_str_reply, "Cannot convert -addr '%s' to internal representative", l_addr_str), -EINVAL;

                return  s_cli_srv_xchange_tx_list_addr (l_net, l_time[0], l_time[1], l_addr, l_opt_status, a_str_reply);
            }


            // Prepare output string
            dap_string_t *l_reply_str = dap_string_new("");

            // Find transactions using filter function s_filter_tx_list()
            dap_list_t *l_datum_list0 = dap_chain_datum_list(l_net, NULL, s_filter_tx_list, l_time);
            size_t l_datum_num = dap_list_length(l_datum_list0);

            if(l_datum_num > 0) {
                //dap_string_append_printf(l_reply_str, "Found %zu transactions:\n", l_datum_num);
                log_it(L_DEBUG,  "Found %zu transactions:\n", l_datum_num);

                dap_list_t *l_datum_list = l_datum_list0;
                char l_hash_str [DAP_CHAIN_HASH_FAST_STR_SIZE + 8] = {0};

                while(l_datum_list) {
#if 0
                    {/* @RRL */
                    dap_chain_datum_t *p1 = (dap_chain_datum_t *) l_datum_list->data;
                    log_it(L_CRITICAL, "l_datum: %p, [ver: %d, typ: %d, size: %d, ts: %llu]",
                        p1, p1->header.version_id, p1->header.type_id, p1->header.data_size, p1->header.ts_create);

                    dap_chain_datum_tx_t *p2 = (dap_chain_datum_tx_t*) p1->data;
                    log_it(L_CRITICAL, "l_datum_tx: %p, [ts_created: %llu, size: %d]",
                        p2, p2->header.ts_created, p2->header.tx_items_size);
                    }
#endif

                    dap_chain_datum_tx_t *l_datum_tx = (dap_chain_datum_tx_t*) ((dap_chain_datum_t*) l_datum_list->data)->data;
                    size_t l_datum_tx_size = dap_chain_datum_tx_get_size(l_datum_tx);

                    // Delimiter between tx
//                    if(l_datum_list != l_datum_list0) {
//                        dap_string_append(l_reply_str, "\n\n");
//                    }

                    // Tx hash
                    dap_hash_fast_t l_tx_hash = {0};

                    dap_hash_fast(l_datum_tx, l_datum_tx_size, &l_tx_hash);
                    dap_chain_hash_fast_to_str(&l_tx_hash, l_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE + 1);
//                    dap_string_append_printf(l_reply_str, "Hash: %s\n", l_hash_str);

                    // Get input token ticker
                    const char * l_tx_input_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(
                                l_net->pub.ledger, &l_tx_hash);

                    // Find SRV_XCHANGE out_cond item
                    int l_prev_cond_idx = 0;
                    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_out_cond_get(l_datum_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                                               &l_prev_cond_idx);
                    if (l_out_cond_item) {
                        uint256_t l_value_from = l_out_cond_item->header.value;
                        uint256_t l_value_to = l_out_cond_item->subtype.srv_xchange.buy_value;
                        char *l_value_to_str = dap_chain_balance_to_coins(l_value_to);
                        char *l_value_from_str = dap_chain_balance_to_coins(l_value_from);

                        l_rc = dap_chain_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &l_tx_hash, l_prev_cond_idx, NULL);

                        if ((l_opt_status == 1 && !l_rc) ||       /* Select close only */
                                (l_opt_status == 2 &&  l_rc))     /* Select open only */
                            continue;

                        l_show_tx_nr++;

                        dap_string_append_printf(l_reply_str, "Hash: %s,", l_hash_str);
                        dap_string_append_printf(l_reply_str, "  Status: %s,", l_rc ? "closed" : "open");
                        dap_string_append_printf(l_reply_str, "  From: %s %s,", l_value_from_str, l_tx_input_ticker);
                        dap_string_append_printf(l_reply_str, "  To: %s %s\n", l_value_to_str, l_out_cond_item->subtype.srv_xchange.buy_token);

                        DAP_DELETE(l_value_from_str);
                        DAP_DELETE(l_value_to_str);
                    }

                    l_datum_list = dap_list_next(l_datum_list);
                }
                dap_string_append_printf(l_reply_str, "Found %d transactions", l_show_tx_nr);
            }
            else{
                dap_string_append(l_reply_str, "Transactions not found");
            }
            dap_list_free_full(l_datum_list0, NULL);
            *a_str_reply = dap_string_free(l_reply_str, false);
        } break;
        // Token pair control
        case CMD_TOKEN_PAIR: {

            // Find and check the network
            const char *l_net_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if(!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'token_pair' requires parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if(!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }


            // Select subcommands

            // check for price subcommand
            const char * l_price_subcommand = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "price", &l_price_subcommand);

            // check for get subcommand
            if ( l_price_subcommand ){
                // Check for token1
                const char * l_token_from_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_from", &l_token_from_str);
                if(!l_token_from_str){
                    dap_cli_server_cmd_set_reply_text(a_str_reply,"No argument '-token_from'");
                    return -5;
                }
                dap_chain_datum_token_t * l_token_from_datum = dap_chain_ledger_token_ticker_check( l_net->pub.ledger, l_token_from_str);
                if(!l_token_from_datum){
                    dap_cli_server_cmd_set_reply_text(a_str_reply,"Can't find \"%s\" token in network \"%s\" for argument '-token_from' ", l_token_from_str, l_net->pub.name);
                    return -6;
                }

                // Check for token2
                const char * l_token_to_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_to", &l_token_to_str);
                if(!l_token_to_str){
                    dap_cli_server_cmd_set_reply_text(a_str_reply,"No argument '-token_to'");
                    return -5;
                }
                dap_chain_datum_token_t * l_token_to_datum = dap_chain_ledger_token_ticker_check( l_net->pub.ledger, l_token_to_str);
                if(!l_token_to_datum){
                    dap_cli_server_cmd_set_reply_text(a_str_reply,"Can't find \"%s\" token in network \"%s\" for argument '-token2' ", l_token_to_str, l_net->pub.name);
                    return -6;
                }

                // Read time_from
                dap_time_t l_time_from = 0;
                const char * l_time_from_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-time_from", &l_time_from_str);
                l_time_from = dap_time_from_str_rfc822(l_time_from_str);

                // Read time_to
                dap_time_t l_time_to = 0;
                const char * l_time_to_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-time_to", &l_time_to_str);
                l_time_to = dap_time_from_str_rfc822(l_time_to_str);

                // Check for price subcommand
                if (strcmp(l_price_subcommand,"average") == 0){
                    dap_string_t *l_reply_str = dap_string_new("");

                    dap_list_t *l_tx_cond_list = dap_chain_net_get_tx_cond_all_by_srv_uid(l_net, c_dap_chain_net_srv_xchange_uid,
                                                                                          l_time_from,l_time_to,TX_SEARCH_TYPE_NET );
                    dap_list_t * l_cur = l_tx_cond_list;
                    uint256_t l_total_rates = {0};
                    uint256_t l_total_rates_count = {0};
                    uint256_t l_rate = {};
                    while(l_cur){
                        dap_chain_datum_tx_t * l_tx =(dap_chain_datum_tx_t *) l_cur->data;
                        if(l_tx){
                            dap_hash_fast_t * l_tx_hash = dap_chain_node_datum_tx_calc_hash(l_tx);

                            // Get input token ticker
                            const char * l_tx_input_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(
                                        l_net->pub.ledger, l_tx_hash);

                            int l_direction = 0; //  1 - from/to,  -1  - to/from
                            // Compare with token_from and token_to
                            if(dap_strcmp(l_tx_input_ticker, l_token_from_str) == 0)
                                l_direction = 1;
                            else if (dap_strcmp(l_tx_input_ticker, l_token_to_str) == 0)
                                l_direction = -1;
                            else {
                                l_cur = dap_list_next(l_cur);
                                DAP_DEL_Z(l_tx_hash);
                                continue;
                            }
                            int l_cond_idx = 0;
                            dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                                                       &l_cond_idx);
                            if (l_out_cond_item &&
                                    dap_chain_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, l_tx_hash, l_cond_idx, NULL)) {
                                uint256_t l_value_sell = l_out_cond_item->header.value;
                                uint256_t l_value_buy = l_out_cond_item->subtype.srv_xchange.buy_value;
                                if( l_direction == 1){
                                    if (!IS_ZERO_256(l_value_sell)) {
                                        DIV_256_COIN(l_value_buy, l_value_sell, &l_rate);
                                        if(SUM_256_256(l_rate, l_total_rates, &l_total_rates )!= 0)
                                            log_it(L_ERROR, "Overflow on avarage price calculation (summing)");
                                        INCR_256(&l_total_rates_count);
                                    }else{
                                        log_it(L_ERROR, "Sell value is 0 in avarage price calculation (summing)");
                                    }
                                }else if (l_direction == -1){
                                    if (!IS_ZERO_256(l_value_buy)) {
                                        DIV_256_COIN(l_value_sell, l_value_buy, &l_rate);
                                        if(SUM_256_256(l_rate, l_total_rates, &l_total_rates )!= 0)
                                            log_it(L_ERROR, "Overflow on avarage price calculation (summing)");
                                        INCR_256(&l_total_rates_count);
                                    }else{
                                        log_it(L_ERROR, "Buy value is 0 in avarage price calculation (summing)");
                                    }
                                }else{
                                    log_it(L_ERROR,"Wrong direction, not buy nor send (%d)",l_direction);
                                }
                            }
                            DAP_DEL_Z(l_tx_hash);
                        }
                        l_cur = dap_list_next(l_cur);
                    }
                    dap_list_free_full(l_tx_cond_list, NULL);
                    uint256_t l_rate_average = {0};
                    if (!IS_ZERO_256(l_total_rates_count))
                        DIV_256(l_total_rates,l_total_rates_count,&l_rate_average);

                    if (!IS_ZERO_256(l_total_rates_count))
                        DIV_256(l_total_rates,l_total_rates_count,&l_rate_average);

                    char *l_rate_average_str = dap_chain_balance_to_coins(l_rate_average);
                    char *l_last_rate_str = dap_chain_balance_to_coins(l_rate);
                    dap_string_append_printf(l_reply_str,"Average price: %s   Last price: %s", l_rate_average_str, l_last_rate_str);
                    DAP_DELETE(l_rate_average_str);
                    DAP_DELETE(l_last_rate_str);
                    *a_str_reply = dap_string_free(l_reply_str, false);
                    break;
                }else if (strcmp(l_price_subcommand,"history") == 0){

                    dap_string_t *l_reply_str = dap_string_new("");

                    dap_chain_datum_tx_spends_items_t * l_tx_spends = dap_chain_net_get_tx_cond_all_with_spends_by_srv_uid(l_net, c_dap_chain_net_srv_xchange_uid,
                            l_time_from,l_time_to,TX_SEARCH_TYPE_NET);


                    dap_chain_datum_tx_spends_item_t * l_cur = NULL, *l_tmp = NULL;
                    HASH_ITER(hh, l_tx_spends->tx_outs, l_cur,l_tmp) {
                        dap_chain_datum_tx_t * l_tx =l_cur->tx;
                        if(l_tx){
                            dap_hash_fast_t * l_tx_hash = &l_cur->tx_hash;

                            // Get input token ticker
                            const char * l_tx_input_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(
                                        l_net->pub.ledger, l_tx_hash);

                            int l_direction = 0; //  1 - from/to,  -1  - to/from
                            // Compare with token_from and token_to
                            if(dap_strcmp(l_tx_input_ticker, l_token_from_str) == 0)
                                l_direction = 1;
                            else if (dap_strcmp(l_tx_input_ticker, l_token_to_str) == 0)
                                l_direction = -1;
                            else {
                                continue;
                            }

                            // Check if output is spent
                            dap_chain_tx_out_cond_t *l_out_cond_item = l_cur->out_cond;
                            if(l_out_cond_item && l_cur->tx_next) {

                                // Print tx_hash
                                char * l_tx_hash_str = dap_chain_hash_fast_to_str_new(l_tx_hash);
                                dap_string_append_printf(l_reply_str,"Tx hash: %s\n", l_tx_hash_str ? l_tx_hash_str : "(null)");
                                DAP_DEL_Z(l_tx_hash_str);

                                // Print tx_created
                                char l_tx_ts_str[92] = {0};
                                struct tm l_tm={0};                                             /* Convert ts to  Sat May 17 01:17:08 2014 */
                                uint64_t l_ts = l_tx->header.ts_created; // We take the next tx in chain to print close time, not the open one
                                if ( (localtime_r((time_t *) &l_ts, &l_tm )) )
                                    asctime_r (&l_tm, l_tx_ts_str);

                                dap_string_append_printf(l_reply_str,"\tts_created: %s", l_tx_ts_str);

                                // Print tx_closed
                                memset(l_tx_ts_str,0,sizeof(l_tx_ts_str));
                                memset(&l_tm,0,sizeof(l_tm));                                             /* Convert ts to  Sat May 17 01:17:08 2014 */
                                l_ts = l_cur->tx_next->header.ts_created; // We take the next tx in chain to print close time, not the open one
                                if ( (localtime_r((time_t *) &l_ts, &l_tm )) )
                                    asctime_r (&l_tm, l_tx_ts_str);

                                dap_string_append_printf(l_reply_str,"\tts_closed: %s", l_tx_ts_str);

                                // Print value_from/value_to

                                uint256_t l_value_from = l_out_cond_item->header.value;
                                uint256_t l_value_to = l_out_cond_item->subtype.srv_xchange.buy_value;
                                uint256_t l_rate = {};
                                if( l_direction == 1){
                                    if(compare256(l_value_from, uint256_0) != 0){
                                        DIV_256_COIN(l_value_to, l_value_from, &l_rate);
                                    }else
                                        log_it(L_ERROR,"Value_from is zero, can't calc rate");
                                }else if(l_direction == -1){
                                    if(compare256(l_value_to, uint256_0) != 0){
                                        DIV_256_COIN(l_value_from, l_value_to, &l_rate);
                                    }else
                                        log_it(L_ERROR,"Value_tois zero, can't calc rate");
                                }else{
                                    log_it(L_ERROR,"Wrong direction, not buy nor send (%d)",l_direction);
                                }
                                char * l_value_from_str = dap_chain_balance_to_coins(l_value_from);
                                char * l_value_to_str = dap_chain_balance_to_coins(l_value_to);
                                char *l_rate_str = dap_chain_balance_to_coins(l_rate);

                                dap_string_append_printf(l_reply_str, "  From: %s %s   ", l_value_from_str, l_tx_input_ticker);
                                dap_string_append_printf(l_reply_str, "  To: %s %s   ", l_value_to_str, l_out_cond_item->subtype.srv_xchange.buy_token );
                                dap_string_append_printf(l_reply_str, "  Price: %s", l_rate_str);
                                DAP_DELETE(l_value_from_str);
                                DAP_DELETE(l_value_to_str);
                                DAP_DELETE(l_rate_str);
                                // Delimiter between tx
                                dap_string_append_printf(l_reply_str,"\n\n");
                            }

                        }
                    }
                    dap_chain_datum_tx_spends_items_free(l_tx_spends);

                    *a_str_reply = dap_string_free(l_reply_str, false);
                    break;

                } else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Unrecognized subcommand '%s'",
                                                      l_price_subcommand);
                    return -38;
                }
            }

            const char * l_list_subcommand = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "list", &l_list_subcommand);
            if( l_list_subcommand ){
                if (strcmp(l_list_subcommand,"all") == 0){
                    dap_string_t *l_reply_str = dap_string_new("");
                    char ** l_tickers = NULL;
                    size_t l_tickers_count = 0;
                    dap_chain_ledger_addr_get_token_ticker_all( l_net->pub.ledger,NULL,&l_tickers,&l_tickers_count);

                    size_t l_pairs_count = 0;
                    if(l_tickers){
                        for(size_t i = 0; i< l_tickers_count; i++){
                            for(size_t j = i+1; j< l_tickers_count; j++){
                                if(l_tickers[i] && l_tickers[j]){
                                    dap_string_append_printf(l_reply_str,"%s:%s ", l_tickers[i], l_tickers[j]);
                                    l_pairs_count++;
                                }
                            }

                        }

                        // Free tickers array
                        for(size_t i = 0; i< l_tickers_count; i++){
                            DAP_DELETE(l_tickers[i]);
                        }
                        DAP_DELETE(l_tickers);
                    }
                    dap_string_prepend_printf( l_reply_str,"Tokens count pair: %zd\n", l_pairs_count);
                    *a_str_reply = dap_string_free(l_reply_str, false);
                    break;
                }
            }

            // No subcommand selected
            dap_cli_server_cmd_set_reply_text(a_str_reply,"Command 'token pair' requires proper subcommand, please read its manual with command 'help srv_xchange'");


        } break;

        default: {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Command %s not recognized", a_argv[l_arg_index]);
            return -1;
        }
    }
    return 0;
}

static int s_callback_requested(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size)
{
    return 0;
}

static int s_callback_response_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size)
{
    return 0;
}

static int s_callback_response_error(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size)
{
    return 0;
}

static int s_callback_receipt_next_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size)
{
    return 0;
}

void dap_chain_net_srv_xchange_print_fee(dap_chain_net_t *a_net, dap_string_t *a_string_ret){
    if (!a_net || !a_string_ret)
        return;
    uint256_t l_fee = {0};
    dap_chain_addr_t l_addr = {0};
    uint16_t l_type = 0;
    if (s_srv_xchange_get_fee(a_net->pub.id, &l_fee, &l_addr, &l_type)) {
        char *l_fee_balance = dap_chain_balance_print(l_fee);
        char *l_fee_coins = dap_chain_balance_to_coins(l_fee);
        char *l_addr_str = dap_chain_addr_to_str(&l_addr);
        const char *l_type_str = dap_chain_net_srv_fee_type_to_str((dap_chain_net_srv_fee_type_t)l_type);
        dap_string_append_printf(a_string_ret, "\txchange:\n"
                                               "\t\tFee: %s (%s)\n"
                                               "\t\tAddr: %s\n"
                                               "\t\tType: %s\n", l_fee_coins, l_fee_balance, l_addr_str, l_type_str);
    } else {
        dap_string_append_printf(a_string_ret, "\txchange:\n"
                                               "\t\tThe xchanger service has not announced a commission fee.\n");
    }
}
