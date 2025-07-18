/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_math_ops.h"
#include "dap_string.h"
#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_xchange.h"
#include "uthash.h"
#include "dap_cli_server.h"
#include "dap_chain_wallet_cache.h"

#define LOG_TAG "dap_chain_net_srv_xchange"

typedef enum tx_opt_status {
    TX_STATUS_ALL = 0,
    TX_STATUS_ACTIVE,
    TX_STATUS_INACTIVE
} tx_opt_status_t;

typedef enum xchange_cache_state{
    XCHANGE_CACHE_DISABLED = 0,
    XCHANGE_CACHE_ENABLED,
} xchange_cache_state_t;
 
typedef struct xchange_tx_list {
    dap_chain_datum_tx_t *tx;
    dap_hash_fast_t hash;
}xchange_tx_list_t;
typedef struct xchange_tx_cache {
    dap_chain_hash_fast_t hash;
    dap_chain_datum_tx_t *tx;
    xchange_tx_type_t tx_type;
    dap_chain_addr_t seller_addr;
    char buy_token[DAP_CHAIN_TICKER_SIZE_MAX];
    char sell_token[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t rate;
    union {
        struct {
            dap_chain_net_srv_xchange_order_status_t order_status;
            uint256_t value;
            uint256_t value_ammount;
            dap_hash_fast_t next_hash;
            uint64_t percent_completed;
        } order_info;
        struct {
            dap_hash_fast_t order_hash;
            dap_hash_fast_t prev_hash;
            dap_hash_fast_t next_hash;
            dap_chain_addr_t buyer_addr;
            uint256_t buy_value;
        } exchange_info;
        struct {
            dap_hash_fast_t order_hash;
            dap_hash_fast_t prev_hash;
            uint256_t returned_value;
        } invalidate_info;
    } tx_info;
    UT_hash_handle hh;
} xchange_tx_cache_t;

typedef struct xchange_orders_cache_net {
    dap_chain_net_id_t net_id;
    xchange_tx_cache_t *cache;
} xchange_orders_cache_net_t;

static dap_chain_net_srv_fee_item_t *s_service_fees = NULL; // Governance statements for networks
static pthread_rwlock_t s_service_fees_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static dap_list_t *s_net_cache = NULL;
static xchange_cache_state_t s_xchange_cache_state = XCHANGE_CACHE_DISABLED;

static void s_callback_decree (dap_chain_net_srv_t * a_srv, dap_chain_net_t *a_net, dap_chain_t * a_chain, dap_chain_datum_decree_t * a_decree, size_t a_decree_size);
static int s_xchange_verificator_callback(dap_ledger_t * a_ledger, dap_chain_tx_out_cond_t *a_cond,
                            dap_chain_datum_tx_t *a_tx_in, bool a_owner);
const dap_chain_net_srv_uid_t c_dap_chain_net_srv_xchange_uid = {.uint64= DAP_CHAIN_NET_SRV_XCHANGE_ID};


static int s_cli_srv_xchange(int a_argc, char **a_argv, void **a_str_reply, int a_version);
static int s_callback_requested(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_error(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_receipt_next_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);

static dap_chain_net_srv_xchange_order_status_t s_tx_check_for_open_close(dap_chain_net_t * a_net, dap_chain_datum_tx_t * a_tx);
static bool s_string_append_tx_cond_info_json(json_object * a_json_out, dap_chain_net_t *a_net, dap_chain_addr_t *a_owner_addr, dap_chain_addr_t *a_buyer_addr,
                                              dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, tx_opt_status_t a_filter_by_status,
                                              bool a_append_prev_hash, bool a_print_status, bool a_print_ts, int a_version);

dap_chain_net_srv_xchange_price_t *s_xchange_price_from_order(dap_chain_net_t *a_net, dap_chain_datum_tx_t *a_order, dap_hash_fast_t *a_order_hash, uint256_t *a_fee, bool a_ret_is_invalid);
static void s_ledger_tx_add_notify(void *a_arg, dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, dap_chan_ledger_notify_opcodes_t a_opcode);

static dap_chain_net_srv_xchange_t *s_srv_xchange;
static bool s_debug_more = false;

static xchange_orders_cache_net_t *s_get_xchange_cache_by_net_id(dap_chain_net_id_t a_net_id)
{
    xchange_orders_cache_net_t *l_cache = NULL;

    for (dap_list_t *l_temp = s_net_cache; l_temp; l_temp=l_temp->next){
        if (((xchange_orders_cache_net_t*)l_temp->data)->net_id.uint64 == a_net_id.uint64){
            l_cache = (xchange_orders_cache_net_t*)l_temp->data;
            break;
        }
    }

    return l_cache;
}

static bool s_tag_check_xchange(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{
    //check if we have in or out for xchange
    
    bool have_xchange_out = false;
    bool have_xchange_in = false;
    if (a_items_grp->items_out_cond_srv_xchange) {
        dap_chain_tx_out_cond_t *l_cond_out = a_items_grp->items_out_cond_srv_xchange->data; 
        if (l_cond_out->header.srv_uid.uint64 == DAP_CHAIN_NET_SRV_XCHANGE_ID)
            have_xchange_out = true;
    }
    
    if (a_items_grp->items_in_cond) {
       for (dap_list_t *it = a_items_grp->items_in_cond; it; it = it->next) {
            dap_chain_tx_in_cond_t *l_tx_in = it->data;
            dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_ledger_get_tx_out_cond_linked_to_tx_in_cond(a_ledger, l_tx_in);

            if (l_tx_out_cond && 
                l_tx_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE &&
                l_tx_out_cond->header.srv_uid.uint64 == DAP_CHAIN_NET_SRV_XCHANGE_ID) {
                    have_xchange_in = true;
            }
        }
    }

    if (have_xchange_in || have_xchange_out) {
        //xchange by xchange module
        dap_chain_tx_out_cond_t *l_out_cond_item = NULL;
        xchange_tx_type_t type = dap_chain_net_srv_xchange_tx_get_type(a_ledger, a_tx, &l_out_cond_item, NULL, NULL);
        switch(type)
        {
            case TX_TYPE_ORDER:
            { 
                if(a_action) *a_action = DAP_CHAIN_TX_TAG_ACTION_OPEN;
                return true;
            }

            case TX_TYPE_EXCHANGE:
            { 

                if(a_action) {
                    if(l_out_cond_item)
                        *a_action = DAP_CHAIN_TX_TAG_ACTION_USE;
                    else
                        *a_action = DAP_CHAIN_TX_TAG_ACTION_CLOSE;
                }
                return true;
            }

            case TX_TYPE_INVALIDATE:
            { 
                if(a_action) *a_action = DAP_CHAIN_TX_TAG_ACTION_CLOSE;
                return true;
            } 
            default:
            {
                if(a_action) *a_action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN;
                return false;
            }
        }
    }

    return false;
    
}

/**
 * @brief dap_chain_net_srv_xchange_init Init actions for xchanger stream channel
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_xchange_init()
{
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, s_xchange_verificator_callback, NULL, NULL);
    dap_cli_server_cmd_add("srv_xchange", s_cli_srv_xchange, "eXchange service commands",

    "srv_xchange order create -net <net_name> -token_sell <token_ticker> -token_buy <token_ticker> -w <wallet_name>"
                                            " -value <value> -rate <value> -fee <value>\n"
        "\tCreate a new order and tx with specified amount of datoshi to exchange with specified rate (buy / sell)\n"
    "srv_xchange order remove -net <net_name> -order <order_hash> -w <wallet_name> -fee <value_datoshi>\n"
         "\tRemove order with specified order hash in specified net name\n"
    "srv_xchange order history -net <net_name> {-order <order_hash> | -addr <wallet_addr>}\n"
         "\tShows transaction history for the selected order\n"
    "srv_xchange order status -net <net_name> -order <order_hash>\n"
         "\tShows current amount of unselled coins from the selected order and percentage of its completion\n"
    "srv_xchange orders -net <net_name> [-status {opened|closed|all}] [-token_from <token_ticker>] [-token_to <token_ticker>] [-addr <wallet_addr>] [-limit <limit>] [-offset <offset>] [-head]\n"
         "\tGet the exchange orders list within specified net name\n"

    "srv_xchange purchase -order <order hash> -net <net_name> -w <wallet_name> -value <value> -fee <value>\n"
         "\tExchange tokens with specified order within specified net name. Specify how many datoshies to sell with rate specified by order\n"

    "srv_xchange tx_list -net <net_name> [-time_from <From_time>] [-time_to <To_time>]"
        "[-addr <wallet_addr>]  [-status {inactive|active|all}]\n"                /* @RRL:  #6294  */
        "\tList of exchange transactions\n"
        "\tAll times are in RFC822. For example: \"7 Dec 2023 21:18:04\"\n"

    "srv_xchange token_pair -net <net_name> list all [-limit <limit>] [-offset <offset>]\n"
        "\tList of all token pairs\n"
    "srv_xchange token_pair -net <net_name> rate average -token_from <token_ticker> -token_to <token_ticker> [-time_from <From_time>] [-time_to <To_time>]\n"
        "\tGet average rate for token pair <token from>:<token to> from <From time> to <To time> \n"
    "srv_xchange token_pair -net <net_name> rate history -token_from <token_ticker> -token_to <token_ticker> [-time_from <From_time>] [-time_to <To_time>] [-limit <limit>] [-offset <offset>]\n"
        "\tPrint rate history for token pair <token from>:<token to> from <From time> to <To time>\n"
        "\tAll times are in RFC822. For example: \"7 Dec 2023 21:18:04\"\n"

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

    //register service for tagging
    dap_ledger_service_add(l_uid, "xchange", s_tag_check_xchange);


    dap_chain_net_srv_t* l_srv = dap_chain_net_srv_add(l_uid, "srv_xchange", &l_srv_callbacks);
    s_srv_xchange = DAP_NEW_Z(dap_chain_net_srv_xchange_t);
    if (!s_srv_xchange || !l_srv) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -1;
    }
    l_srv->_internal = s_srv_xchange;
    s_srv_xchange->parent = l_srv;
    s_srv_xchange->enabled = false;
    s_debug_more = dap_config_get_item_bool_default(g_config, "srv_xchange", "debug_more", s_debug_more);

    const char *l_cache_state_str = dap_config_get_item_str_default(g_config, "srv_xchange", "cache", "enable");

    if (!strcmp(l_cache_state_str, "disable"))
        s_xchange_cache_state = XCHANGE_CACHE_DISABLED;
    else if (!strcmp(l_cache_state_str, "enable"))
        s_xchange_cache_state = XCHANGE_CACHE_ENABLED;


    if (s_xchange_cache_state == XCHANGE_CACHE_ENABLED){
        for(dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net=dap_chain_net_iter_next(l_net)){
            xchange_orders_cache_net_t *l_net_cache = DAP_NEW_Z(xchange_orders_cache_net_t);
            l_net_cache->net_id.uint64 = l_net->pub.id.uint64;
            s_net_cache = dap_list_append(s_net_cache, l_net_cache);
            dap_ledger_tx_add_notify(l_net->pub.ledger, s_ledger_tx_add_notify, NULL);
        }
    }
    

    /*************************/
    /*int l_fee_type = dap_config_get_item_int64_default(g_config, "srv_xchange", "fee_type", (int)SERIVCE_FEE_NATIVE_PERCENT);
    uint256_t l_fee_value = dap_chain_coins_to_balance(dap_config_get_item_str_default(g_config, "srv_xchange", "fee_value", "0.02"));
    const char *l_wallet_addr = dap_config_get_item_str_default(g_config, "srv_xchange", "wallet_addr", NULL);
    if(!l_wallet_addr){
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -1;
    }
    const char *l_net_str = dap_config_get_item_str_default(g_config, "srv_xchange", "net", NULL);
    ///
    dap_chain_net_srv_fee_item_t *l_fee = NULL;
    l_fee = DAP_NEW_Z(dap_chain_net_srv_fee_item_t);
    l_fee->fee_type = l_fee_type;
    l_fee->fee = l_fee_value;
    l_fee->fee_addr = *dap_chain_addr_from_str(l_wallet_addr);
    l_fee->net_id = dap_chain_net_by_name(l_net_str)->pub.id;
    HASH_ADD(hh, s_service_fees, net_id, sizeof(l_fee->net_id), l_fee);*/

    return 0;
}

void dap_chain_net_srv_xchange_deinit()
{
    if(!s_srv_xchange)
        return;
    dap_chain_net_srv_del(s_srv_xchange->parent);
    DAP_DEL_Z(s_srv_xchange);
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
static int s_xchange_verificator_callback(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_tx_out_cond,
                                           dap_chain_datum_tx_t *a_tx_in, bool a_owner)
{
    if (a_owner)
        return 0;
    if(!a_tx_in || !a_tx_out_cond)
        return -1;

    dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t *)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL);
    if (!l_tx_in_cond)
        return -2;
    if (dap_hash_fast_is_blank(&l_tx_in_cond->header.tx_prev_hash))
        return -3;
    const char *l_sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_tx_in_cond->header.tx_prev_hash);
    if (!l_sell_ticker)
        return -4;
    const char *l_buy_ticker = a_tx_out_cond->subtype.srv_xchange.buy_token;

    uint256_t l_buy_val = {}, l_fee_val = {},
              l_sell_again_val = {}, l_service_fee_val = {};

    dap_chain_addr_t l_service_fee_addr, *l_seller_addr = &a_tx_out_cond->subtype.srv_xchange.seller_addr;
    uint16_t l_service_fee_type = 0;
    dap_chain_net_t *l_net = a_ledger->net;
    bool l_service_fee_used = dap_chain_net_srv_xchange_get_fee(l_net->pub.id, &l_service_fee_val, &l_service_fee_addr, &l_service_fee_type);
    const char *l_native_ticker = l_net->pub.native_ticker;
    const char *l_service_ticker = (l_service_fee_type == SERVICE_FEE_OWN_FIXED || l_service_fee_type == SERVICE_FEE_OWN_PERCENT) ?
                l_buy_ticker : l_native_ticker;
    byte_t *l_tx_item; size_t l_size;
    TX_ITEM_ITER_TX(l_tx_item, l_size, a_tx_in) {
        switch (*l_tx_item) {
        case TX_ITEM_TYPE_OUT_EXT:
        case TX_ITEM_TYPE_OUT_STD: {
            const char *l_out_token = *l_tx_item == TX_ITEM_TYPE_OUT_EXT ? ((dap_chain_tx_out_ext_t *)l_tx_item)->token
                                                                         : ((dap_chain_tx_out_std_t *)l_tx_item)->token;
            uint256_t l_out_value = *l_tx_item == TX_ITEM_TYPE_OUT_EXT ? ((dap_chain_tx_out_ext_t *)l_tx_item)->header.value
                                                                       : ((dap_chain_tx_out_std_t *)l_tx_item)->value;
            dap_chain_addr_t l_out_addr = *l_tx_item == TX_ITEM_TYPE_OUT_EXT ? ((dap_chain_tx_out_ext_t *)l_tx_item)->addr
                                                                             : ((dap_chain_tx_out_std_t *)l_tx_item)->addr;
            // Out is with token to buy
            if (!strcmp(l_out_token, l_buy_ticker) &&
                    !memcmp(&l_out_addr, l_seller_addr, sizeof(l_out_addr)) &&
                    SUM_256_256(l_buy_val, l_out_value, &l_buy_val)) {
                log_it(L_WARNING, "Integer overflow for buyer value of exchange tx");
                return -5;
            }
            // Out is with token to fee
            if (l_service_fee_used && !strcmp(l_out_token, l_service_ticker) &&
                    !memcmp(&l_out_addr, &l_service_fee_addr, sizeof(l_out_addr)) &&
                    SUM_256_256(l_fee_val, l_out_value, &l_fee_val)) {
                log_it(L_WARNING, "Integer overflow for fee value of exchange tx");
                return -5;
            }
        } break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *l_tx_in_output = (dap_chain_tx_out_cond_t*)l_tx_item;
            if (l_tx_in_output->header.subtype == a_tx_out_cond->header.subtype &&                             // Same subtype
                    l_tx_in_output->header.srv_uid.uint64 == a_tx_out_cond->header.srv_uid.uint64 &&          // Same service uid
                    l_tx_in_output->header.ts_expires == a_tx_out_cond->header.ts_expires &&                  // Same expires time
                    l_tx_in_output->tsd_size == a_tx_out_cond->tsd_size &&                              // Same params size
                    memcmp(l_tx_in_output->tsd, a_tx_out_cond->tsd, l_tx_in_output->tsd_size) == 0 && // Same params itself
                    memcmp(&l_tx_in_output->subtype.srv_xchange, &a_tx_out_cond->subtype.srv_xchange,         // Same subtype header
                        sizeof(a_tx_out_cond->subtype.srv_xchange)) == 0) {
                l_sell_again_val = l_tx_in_output->header.value;                                    // It is back to cond owner value
            }
        } break;
        default:
            break;
        }
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


    uint256_t l_sell_val, l_buyer_val_expected;
    if (SUBTRACT_256_256(a_tx_out_cond->header.value, l_sell_again_val, &l_sell_val)) {
        log_it(L_WARNING, "Integer overflow for resell value of exchange tx");
        return -5;
    }
    MULT_256_COIN(l_sell_val, a_tx_out_cond->subtype.srv_xchange.rate, &l_buyer_val_expected);
    if (s_debug_more) {
        const char *l_value_str;
        dap_uint256_to_char(a_tx_out_cond->header.value, &l_value_str);
        log_it(L_NOTICE, "Total sell %s %s from %s", l_value_str, l_sell_ticker, dap_hash_fast_to_str_static(&l_tx_in_cond->header.tx_prev_hash));
        dap_uint256_to_char(a_tx_out_cond->subtype.srv_xchange.rate, &l_value_str);
        log_it(L_NOTICE, "Rate is %s", l_value_str);
        dap_uint256_to_char(l_sell_again_val, &l_value_str);
        log_it(L_NOTICE, "Resell %s %s", l_value_str, l_sell_ticker);
        dap_uint256_to_char(l_buyer_val_expected, &l_value_str);
        log_it(L_NOTICE, "Expect to buy %s %s", l_value_str, l_buy_ticker);
        dap_uint256_to_char(l_buy_val, &l_value_str);
        log_it(L_NOTICE, "Buy %s %s", l_value_str, l_buy_ticker);
        dap_uint256_to_char(l_fee_val, &l_value_str);
        log_it(L_NOTICE, "Service fee is %s %s", l_value_str, l_service_ticker);
    }
    if (compare256(l_buyer_val_expected, l_buy_val) > 0)
        return -6;

    /* Check the condition for fee verification success
     * out_ext.fee_addr(fee_ticker).value >= fee_value
     */
    if (l_service_fee_used) {
        if (l_service_fee_type == SERIVCE_FEE_NATIVE_PERCENT || l_service_fee_type == SERVICE_FEE_OWN_PERCENT)
            MULT_256_COIN(l_service_fee_val, l_sell_val, &l_service_fee_val);
        if (compare256(l_fee_val, l_service_fee_val) < 0)
            return -7;
    }
    return 0;
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

bool dap_chain_net_srv_xchange_get_fee(dap_chain_net_id_t a_net_id, uint256_t *a_fee, dap_chain_addr_t *a_addr, uint16_t *a_type)
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
    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(a_wallet, a_price->net->pub.id);
    dap_chain_addr_t l_seller_addr = *l_wallet_addr;
    DAP_DELETE(l_wallet_addr);
    if (l_single_channel)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else {
        if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_native_ticker, &l_seller_addr, &l_list_fee_out, l_total_fee, &l_fee_transfer) == -101)
            l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                              &l_seller_addr, l_total_fee, &l_fee_transfer);
        if (!l_list_fee_out) {
            log_it(L_WARNING, "Not enough funds to pay fee");
            return NULL;
        }
    }
    // list of transaction with 'out' items to sell
    dap_list_t *l_list_used_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, a_price->token_sell, &l_seller_addr, &l_list_used_out, l_value_need, &l_value_transfer) == -101)
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_price->token_sell,
                                                                       &l_seller_addr, l_value_need, &l_value_transfer);
    if(!l_list_used_out) {
        log_it(L_WARNING, "Nothing to change from %s (not enough funds in %s (%s))",
               dap_chain_addr_to_str_static( &l_seller_addr), a_price->token_sell, dap_chain_balance_print(l_value_need));
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_to_items, l_value_transfer) != 0) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_ERROR, "Can't compose the transaction input");
        return NULL;
    }
    if (!l_single_channel) {
        // add 'in' items to fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer) != 0) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Can't compose the transaction input");
            return NULL;
        }
    }

    // add 'out_cond' & 'out' items

    {
        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(l_uid, a_price->net->pub.id, a_price->datoshi_sell,
                                                                                                a_price->net->pub.id, a_price->token_buy, a_price->rate,
                                                                                                &l_seller_addr, NULL, 0);
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Can't compose the transaction conditional output");
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
        // Network fee
        if (l_net_fee_used) {
            if ( dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_net_fee, l_net_fee, l_native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                log_it(L_ERROR, "Cant add network fee output");
                return NULL;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_price->fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_price->fee) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                log_it(L_ERROR, "Cant add validator's fee output");
                return NULL;
            }
        }
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if ((l_single_channel &&
                        dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_seller_addr, l_value_back, l_native_ticker) != 1) ||
                    (!l_single_channel &&
                        dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_seller_addr, l_value_back, a_price->token_sell) != 1)) {
                dap_chain_datum_tx_delete(l_tx);
                log_it(L_ERROR, "Cant add coin back output");
                return NULL;
            }
        }
        // Fee coinback
        if (!l_single_channel) {
            uint256_t l_fee_coinback = {};
            SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_fee_coinback);
            if (!IS_ZERO_256(l_fee_coinback)) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_seller_addr, l_fee_coinback, l_native_ticker) != 1) {
                    dap_chain_datum_tx_delete(l_tx);
                    log_it(L_ERROR, "Cant add fee back output");
                    return NULL;
                }
            }
        }
    }

    dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);
    // add 'sign' item
    if(dap_chain_datum_tx_add_sign_item(&l_tx, l_seller_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_seller_key);
        log_it(L_ERROR, "Can't add sign output");
        return NULL;
    }
    dap_enc_key_delete(l_seller_key);
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
    // find the transactions from which to take away coins
    uint256_t l_value_transfer, // how many coins to transfer
              l_value_need = a_datoshi_buy,
              l_net_fee,
              l_service_fee,
              l_total_fee = a_datoshi_fee,
              l_fee_transfer;
    dap_chain_addr_t l_net_fee_addr, l_service_fee_addr;
    dap_list_t *l_list_fee_out = NULL;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_price->net->pub.id, &l_net_fee, &l_net_fee_addr);
    if (l_net_fee_used)
        SUM_256_256(l_net_fee, a_price->fee, &l_total_fee);
    uint16_t l_service_fee_type  = 0;
    bool l_service_fee_used = dap_chain_net_srv_xchange_get_fee(a_price->net->pub.id, &l_service_fee, &l_service_fee_addr, &l_service_fee_type);
    if (l_service_fee_used) {
        switch (l_service_fee_type) {
        case SERIVCE_FEE_NATIVE_PERCENT:
            MULT_256_COIN(l_service_fee, a_datoshi_buy, &l_service_fee);
        case SERVICE_FEE_NATIVE_FIXED:
            SUM_256_256(l_total_fee, l_service_fee, &l_total_fee);
            l_service_ticker = l_native_ticker;
            break;
        case SERVICE_FEE_OWN_PERCENT:
            MULT_256_COIN(l_service_fee, a_datoshi_buy, &l_service_fee);
        case SERVICE_FEE_OWN_FIXED:
            SUM_256_256(l_value_need, l_service_fee, &l_value_need);
            l_service_ticker = a_price->token_buy;
        default:
            break;
        }
    }

    dap_ledger_t *l_ledger = a_price->net->pub.ledger;
    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(a_wallet, a_price->net->pub.id);
    dap_chain_addr_t l_buyer_addr = *l_wallet_addr;
    DAP_DELETE(l_wallet_addr);

    // list of transaction with 'out' items to sell
    dap_list_t *l_list_used_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, a_price->token_buy, &l_buyer_addr, &l_list_used_out, l_value_need, &l_value_transfer) == -101)
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_price->token_buy,
                                                                       &l_buyer_addr, l_value_need, &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_WARNING, "Nothing to change from %s (not enough funds in %s (%s))",
               dap_chain_addr_to_str_static( &l_buyer_addr), a_price->token_buy, dap_chain_balance_print(l_value_need));
        return NULL;
    }
    bool l_pay_with_native = !dap_strcmp(a_price->token_sell, l_native_ticker);
    bool l_buy_with_native = !dap_strcmp(a_price->token_buy, l_native_ticker);
    if (!l_pay_with_native) {
        if (l_buy_with_native)
            SUM_256_256(l_value_need, l_total_fee, &l_value_need);
        else {
            if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_native_ticker, &l_buyer_addr, &l_list_fee_out, l_total_fee, &l_fee_transfer) == -101)
                l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                        &l_buyer_addr, l_total_fee, &l_fee_transfer);
            if (!l_list_fee_out) {
                dap_list_free_full(l_list_used_out, NULL);
                log_it(L_WARNING, "Not enough funds to pay fee");
                return NULL;
            }
        }
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
        dap_list_free_full(l_list_fee_out, NULL);
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_ERROR, "Can't compose the transaction input");
        return NULL;
    }
    if (!l_pay_with_native && !l_buy_with_native) {
        // add 'in' items to fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Can't compose the transaction input");
            return NULL;
        }
    }
    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(l_ledger, &a_price->tx_hash);
    if (!l_cond_tx) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_WARNING, "Requested conditional transaction not found");
        return NULL;
    }
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                             &l_prev_cond_idx);
    if (!l_tx_out_cond) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_WARNING, "Requested transaction has no conditional output");
        return NULL;
    }
    if (dap_ledger_tx_hash_is_used_out_item(l_ledger, &a_price->tx_hash, l_prev_cond_idx, NULL)) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_WARNING, "Requested conditional transaction is already used out");
        return NULL;
    }
    const dap_chain_addr_t *l_seller_addr = &l_tx_out_cond->subtype.srv_xchange.seller_addr;
    if (1 != dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_price->tx_hash, l_prev_cond_idx, 0)) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_ERROR, "Can't add conditional input");
        return NULL;
    }

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
            uint256_t l_exceed = {}; // Correct requested transfer value
            SUBTRACT_256_256(a_datoshi_buy, l_datoshi_buy, &l_exceed);
            SUBTRACT_256_256(l_value_need, l_exceed, &l_value_need);
        } else
            l_datoshi_buy = a_datoshi_buy;
        
        if (s_debug_more) {
            const char *l_datoshi_sell_str; dap_uint256_to_char(l_datoshi_sell, &l_datoshi_sell_str);
            log_it(L_NOTICE, "l_value_sell = %s %s", l_datoshi_sell_str, a_price->token_sell);
        }
        
        uint256_t l_value_sell = l_datoshi_sell;
        if (l_pay_with_native) {
            if (compare256(l_datoshi_sell, l_total_fee) <= 0) {
                dap_chain_datum_tx_delete(l_tx);
                log_it(L_WARNING, "Fee is greater or equal than transfer value");
                return NULL;
            }
            SUBTRACT_256_256(l_datoshi_sell, l_total_fee, &l_value_sell);
        }
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_buyer_addr, l_value_sell, a_price->token_sell) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Can't add selling coins output");
            return NULL;
        }
    } else {
        log_it(L_ERROR, "Can't add selling coins output because price rate is 0");
        return NULL;
    }
    // transfer unselling coins (partial exchange)
    if (s_debug_more) {
        const char *l_value_str; dap_uint256_to_char(l_tx_out_cond->header.value, &l_value_str);
        log_it(L_NOTICE, "l_value_cond = %s", l_value_str);
    }
    
    if (compare256(l_tx_out_cond->header.value, l_datoshi_sell) == 1) {
        SUBTRACT_256_256(l_tx_out_cond->header.value, l_datoshi_sell, &l_value_back);
        if (s_debug_more) {
            const char *l_value_back_str; dap_uint256_to_char(l_value_back, &l_value_back_str);
            log_it(L_NOTICE, "l_value_unselled = %s", l_value_back_str);
        }
        
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(
                    c_dap_chain_net_srv_xchange_uid, a_price->net->pub.id, l_value_back,
                    a_price->net->pub.id, a_price->token_buy, a_price->rate,
                    l_seller_addr, NULL, 0);
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Can't add selling coins back conditioned output (cond cashback)");
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
    } 

    // transfer buying coins
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, l_datoshi_buy, a_price->token_buy) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_ERROR, "Can't add buying coins output");
        return NULL;
    }
    if (s_debug_more) {
        const char *l_buy_str; dap_uint256_to_char(l_datoshi_buy, &l_buy_str);
        log_it(L_NOTICE, "l_value_buy = %s %s", l_buy_str, a_price->token_buy);
    }
    
    // transfer validator's fee
    if (!IS_ZERO_256(a_datoshi_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_datoshi_fee) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Can't add validator fee output");
            return NULL;
        }
        if (s_debug_more) {
            const char *l_fee_str; dap_uint256_to_char(a_datoshi_fee, &l_fee_str);
            log_it (L_NOTICE, "l_validator_fee = %s", l_fee_str);
        }
    }
    // transfer net fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, l_native_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Can't add net fee output");
            return NULL;
        }
        if (s_debug_more) {
            const char *l_net_fee_str; dap_uint256_to_char(l_net_fee, &l_net_fee_str);
            log_it(L_NOTICE, "l_net_fee = %s", l_net_fee_str);
        }
    }
    // transfer service fee
    if (l_service_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_service_fee_addr, l_service_fee, l_service_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Can't add net fee output");
            return NULL;
        }
        if (s_debug_more) {
            const char *l_srv_fee_str; dap_uint256_to_char(l_service_fee, &l_srv_fee_str);
            log_it(L_NOTICE, "l_service_fee = %s %s", 
                             l_srv_fee_str, l_service_ticker ? l_service_ticker : "<undefined>");
        }
    }
    // coin back
    SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_buyer_addr, l_value_back, a_price->token_buy) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Can't add buying coins back output");
            return NULL;
        }
    }
    if (s_debug_more) {
        const char *l_value_transfer_str; dap_uint256_to_char(l_value_transfer, &l_value_transfer_str);
        log_it(L_NOTICE, "l_value_transfer = %s", l_value_transfer_str);
        const char *l_value_back_str; dap_uint256_to_char(l_value_back, &l_value_back_str);
        log_it(L_NOTICE, "l_value_back = %s", l_value_back_str);
    }
    // fee back
    if (!l_pay_with_native && !l_buy_with_native) {
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_buyer_addr, l_value_back, l_native_ticker) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                log_it(L_ERROR, "Can't add buying coins back output");
                return NULL;
            }
        }
        if (s_debug_more) {
            const char *l_fee_transfer_str; dap_uint256_to_char(l_fee_transfer, &l_fee_transfer_str);
            log_it(L_NOTICE, "l_fee_transfer = %s", l_fee_transfer_str);
            const char *l_val_back_str; dap_uint256_to_char(l_value_back, &l_val_back_str);
            log_it(L_NOTICE, "l_cashback = %s", l_val_back_str);
        }
    }

    // add 'sign' items
    dap_enc_key_t *l_buyer_key = dap_chain_wallet_get_key(a_wallet, 0);
    if (dap_chain_datum_tx_add_sign_item(&l_tx, l_buyer_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_buyer_key);
        log_it( L_ERROR, "Can't add sign output");
        return NULL;
    }
    dap_enc_key_delete(l_buyer_key);
    return l_tx;
}

uint64_t dap_chain_net_srv_xchange_get_order_completion_rate(dap_chain_net_t *a_net, dap_hash_fast_t a_order_tx_hash)
{

    dap_chain_datum_tx_t * l_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &a_order_tx_hash);
    if (!l_tx){
        log_it(L_ERROR, "Cant find such tx in ledger");
        return 0;
    }

    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE , NULL);
    if (!l_out_cond || l_out_cond->header.srv_uid.uint64 != DAP_CHAIN_NET_SRV_XCHANGE_ID){
        log_it(L_ERROR, "It's not an order");
        return 0;
    }

    // TODO add filters to list (tokens, network, etc.)
    dap_chain_net_srv_xchange_price_t * l_price = NULL;
    l_price = s_xchange_price_from_order(a_net, l_tx, &a_order_tx_hash, NULL, true);
    if( !l_price ){
        log_it(L_ERROR, "Can't get price from order");
        return 0;
    }

    dap_hash_fast_t l_last_tx_hash = dap_ledger_get_final_chain_tx_hash(a_net->pub.ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_price->tx_hash, false);
    if ( dap_hash_fast_is_blank(&l_last_tx_hash) ){
        log_it(L_ERROR, " Can't get last tx cond hash from order");
        return 0;
    }

    dap_chain_datum_tx_t * l_last_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_last_tx_hash);
    if(!l_last_tx){
        log_it(L_ERROR, "Can't find last tx");
        return 0;
    }

    uint256_t l_percent_completed = {};
    dap_chain_tx_out_cond_t *l_out_cond_last_tx = dap_chain_datum_tx_out_cond_get(l_last_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE , NULL);

    if(l_out_cond_last_tx){
        SUBTRACT_256_256(l_out_cond->header.value, l_out_cond_last_tx->header.value, &l_percent_completed);
        DIV_256_COIN(l_percent_completed, l_out_cond->header.value, &l_percent_completed);
        MULT_256_COIN(l_percent_completed, dap_chain_coins_to_balance("100.0"), &l_percent_completed);
    } else {
        dap_chain_tx_out_cond_t *l_out_prev_cond_item = NULL;
        xchange_tx_type_t tx_type = dap_chain_net_srv_xchange_tx_get_type(a_net->pub.ledger, l_last_tx, NULL, NULL, &l_out_prev_cond_item);
        if (tx_type == TX_TYPE_EXCHANGE){
            l_percent_completed = dap_chain_coins_to_balance("100.0");
        } else if (tx_type == TX_TYPE_INVALIDATE){
            SUBTRACT_256_256(l_out_cond->header.value, l_out_prev_cond_item->header.value, &l_percent_completed);
            DIV_256_COIN(l_percent_completed, l_out_cond->header.value, &l_percent_completed);
            MULT_256_COIN(l_percent_completed, dap_chain_coins_to_balance("100.0"), &l_percent_completed);
        }
    }
        
    return dap_chain_balance_to_coins_uint64(l_percent_completed);
}

dap_chain_net_srv_xchange_order_status_t dap_chain_net_srv_xchange_get_order_status(dap_chain_net_t *a_net, dap_hash_fast_t a_order_tx_hash)
{
    dap_chain_datum_tx_t * l_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &a_order_tx_hash);
    if (!l_tx){
        log_it(L_ERROR, "Cant find such tx in ledger");
        return XCHANGE_ORDER_STATUS_UNKNOWN;
    }
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE , NULL);
    if (!l_out_cond || l_out_cond->header.srv_uid.uint64 != DAP_CHAIN_NET_SRV_XCHANGE_ID){
        log_it(L_ERROR, "It's not an order");
        return XCHANGE_ORDER_STATUS_UNKNOWN;
    }
    // TODO add filters to list (tokens, network, etc.)
    dap_chain_net_srv_xchange_price_t * l_price = NULL;
    l_price = s_xchange_price_from_order(a_net, l_tx, &a_order_tx_hash, NULL, true);
    if( !l_price ){
        log_it(L_ERROR, "Can't get price from order");
        return XCHANGE_ORDER_STATUS_UNKNOWN;
    }

    dap_hash_fast_t l_last_tx_hash = dap_ledger_get_final_chain_tx_hash(a_net->pub.ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_price->tx_hash, false);
    if ( dap_hash_fast_is_blank(&l_last_tx_hash) ) {
        log_it(L_ERROR, " Can't get last tx cond hash from order");
        return XCHANGE_ORDER_STATUS_UNKNOWN;
    }

    dap_chain_datum_tx_t * l_last_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_last_tx_hash);
    if (!l_last_tx) {
        log_it(L_ERROR, "Can't find last tx");
        return XCHANGE_ORDER_STATUS_UNKNOWN;
    }

    dap_chain_tx_out_cond_t *l_out_cond_last_tx = dap_chain_datum_tx_out_cond_get(l_last_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE , NULL);
    if (!l_out_cond_last_tx || IS_ZERO_256(l_out_cond_last_tx->header.value)){
        DAP_DEL_Z(l_price);
        return XCHANGE_ORDER_STATUS_CLOSED;
    } else {
        DAP_DEL_Z(l_price);
        return XCHANGE_ORDER_STATUS_OPENED;
    }
    DAP_DEL_Z(l_price);
    return XCHANGE_ORDER_STATUS_UNKNOWN;

}

// Put the transaction to mempool
static char*  s_xchange_tx_put(dap_chain_datum_tx_t *a_tx, dap_chain_net_t *a_net)
{
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, a_tx, l_tx_size);
    DAP_DELETE(a_tx);
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    if (!l_chain) {
        DAP_DELETE(l_datum);
        return NULL;
    }
    // Processing will be made according to autoprocess policy
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");

    DAP_DELETE(l_datum);

    return l_ret;
}

static char* s_xchange_tx_invalidate(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_wallet_t *a_wallet)
{
    char * l_ret = NULL;

    if (!a_price) {
        log_it(L_WARNING, "An a_price NULL argument was passed to the s_xchange_tx_invalidate() function.");
        return l_ret;
    }
    if (!a_wallet) {
        log_it(L_WARNING, "An a_wallet NULL argument was passed to the s_xchange_tx_invalidate() function.");
        return l_ret;
    }
    const char *l_native_ticker = a_price->net->pub.native_ticker;

    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_price->net->pub.name);
    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(a_wallet, a_price->net->pub.id);
    dap_chain_addr_t l_seller_addr = *l_wallet_addr;
    DAP_DELETE(l_wallet_addr);

    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(l_ledger, &a_price->tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return l_ret;
    }
    const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &a_price->tx_hash);
    if (!l_tx_ticker) {
        log_it(L_WARNING, "Can't get ticker from tx");
        return l_ret;
    }
    bool l_single_channel = !dap_strcmp(l_tx_ticker, l_native_ticker);

    // check 'out_cond' item
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                             &l_prev_cond_idx);
    if (!l_tx_out_cond) {
        log_it(L_WARNING, "Requested conditional transaction has no XCHANGE output");
        return l_ret;
    }
    if (dap_ledger_tx_hash_is_used_out_item(l_ledger, &a_price->tx_hash, l_prev_cond_idx, NULL)) {
        log_it(L_WARNING, "Requested conditional transaction is already used out");
        return l_ret;
    }
    if (!dap_chain_addr_compare(&l_seller_addr, &l_tx_out_cond->subtype.srv_xchange.seller_addr)) {
        log_it(L_WARNING, "Only owner can invalidate exchange transaction");
        return l_ret;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_price->tx_hash, l_prev_cond_idx, 0);
    uint256_t l_net_fee = {};
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_price->net->pub.id, &l_net_fee, &l_addr_fee);
    uint256_t l_total_fee = a_price->fee;
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);

    if (!l_single_channel) {
        uint256_t l_transfer_fee = {}, l_fee_back = {};
        // list of transaction with 'out' items to get net fee
        dap_list_t *l_list_used_out = NULL;
        if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_native_ticker, &l_seller_addr, &l_list_used_out, l_total_fee, &l_transfer_fee) == -101)
            l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                           &l_seller_addr, l_total_fee, &l_transfer_fee);
        if (!l_list_used_out) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Nothing to pay for network fee (not enough funds)");
            return l_ret;
        }
        // add 'in' items to net fee
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        dap_list_free_full(l_list_used_out, NULL);
        if (!EQUAL_256(l_value_to_items, l_transfer_fee)) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Can't compose the transaction input");
            return l_ret;
        }
        // return coins to owner
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_seller_addr, l_tx_out_cond->header.value, l_tx_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Cant add returning coins output");
            return l_ret;
        }
        // Network fee
        if (l_net_fee_used &&
                dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Cant add network fee output");
            return l_ret;
        }
        // put fee coinback
        SUBTRACT_256_256(l_transfer_fee, l_total_fee, &l_fee_back);
        if (!IS_ZERO_256(l_fee_back) &&
                dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_seller_addr, l_fee_back, l_native_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Cant add fee cachback output");
            return l_ret;
        }
    } else {
        uint256_t l_coin_back = {};
        if (compare256(l_total_fee, l_tx_out_cond->header.value) >= 0) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Total fee is greater or equal than order liquidity");
            return l_ret;
        }
        SUBTRACT_256_256(l_tx_out_cond->header.value, l_total_fee, &l_coin_back);
        // return coins to owner
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_seller_addr, l_coin_back, l_native_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Cant add returning coins output");
            return l_ret;
        }
        // Network fee
        if (l_net_fee_used &&
            dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Cant add network fee output");
            return l_ret;
        }
    }
    // Validator's fee
    if (!IS_ZERO_256(a_price->fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_price->fee) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Cant add validator's fee output");
            return l_ret;
        }
    }
    // add 'sign' items
    dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);
    if(dap_chain_datum_tx_add_sign_item(&l_tx, l_seller_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_seller_key);
        log_it( L_ERROR, "Can't add sign output");
        return false;
    }
    dap_enc_key_delete(l_seller_key);
    l_ret = s_xchange_tx_put(l_tx, a_price->net);

    return l_ret;
}

/**
 * @brief s_xchange_price_from_order
 * @param a_net
 * @param a_order
 * @return
 */
dap_chain_net_srv_xchange_price_t *s_xchange_price_from_order(dap_chain_net_t *a_net, dap_chain_datum_tx_t *a_order, dap_hash_fast_t *a_order_hash, uint256_t *a_fee, bool a_ret_is_invalid)
{
    dap_return_val_if_pass(!a_net || !a_order, NULL);
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(a_order, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE , NULL);
    if (!l_out_cond)
        return NULL;
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_net_srv_xchange_price_t, NULL);
    l_price->creation_date = a_order->header.ts_created;
    dap_strncpy(l_price->token_buy, l_out_cond->subtype.srv_xchange.buy_token, sizeof(l_price->token_buy) - 1);

    l_price->order_hash = *a_order_hash;
    const char *l_token_sell = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &l_price->order_hash);
    if (!l_token_sell){
        log_it(L_CRITICAL, "Can't find tx token");
        DAP_DELETE(l_price);
        return NULL;
    }
    strncpy(l_price->token_sell, l_token_sell, sizeof(l_price->token_sell) - 1);

    if (a_fee)
        l_price->fee = *a_fee;

    l_price->datoshi_sell = l_out_cond->header.value;
    l_price->net = a_net;
    l_price->creator_addr = l_out_cond->subtype.srv_xchange.seller_addr;
    l_price->rate = l_out_cond->subtype.srv_xchange.rate;
    dap_hash_fast_t l_final_hash = dap_ledger_get_final_chain_tx_hash(a_net->pub.ledger,
                                        DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_price->order_hash, false);
    if ( !dap_hash_fast_is_blank(&l_final_hash) ) {
        l_price->tx_hash = l_final_hash;
        return l_price;
    } else {
        log_it(L_WARNING, "This order have no active conditional transaction");
        if (a_ret_is_invalid) {
            dap_hash_fast_t l_tx_hash_zero = {0};
            l_price->tx_hash = l_tx_hash_zero;
            return l_price;
        }
    }

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
static int s_cli_srv_xchange_order(int a_argc, char **a_argv, int a_arg_index, json_object **a_json_arr_reply, int a_version)
{
    enum {
        CMD_NONE, CMD_CREATE, CMD_REMOVE, CMD_UPDATE, CMD_HISTORY, CMD_STATUS
    };
    int l_cmd_num = CMD_NONE;
    if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, dap_min(a_argc, a_arg_index + 1), "create", NULL)) {
        l_cmd_num = CMD_CREATE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, dap_min(a_argc, a_arg_index + 1), "remove", NULL)) {
        l_cmd_num = CMD_REMOVE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, dap_min(a_argc, a_arg_index + 1), "history", NULL)) {
        l_cmd_num = CMD_HISTORY;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, dap_min(a_argc, a_arg_index + 1), "status", NULL)) {
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
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_REQ_PARAM_NET_ERR, "Command 'order create' requires parameter -net");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_REQ_PARAM_NET_ERR;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_NET_NOT_FOUND_ERR, "Command 'order create' requires parameter -net");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_NET_NOT_FOUND_ERR;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_sell", &l_token_sell_str);
            if (!l_token_sell_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_PARAM_TOKEN_SELL_ERR, 
                                                "Command 'order create' requires parameter -token_sell");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_PARAM_TOKEN_SELL_ERR;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_buy", &l_token_buy_str);
            if (!l_token_buy_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_PARAM_TOKEN_BUY_ERR, 
                                                "Command 'order create' requires parameter -token_buy");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_PARAM_TOKEN_BUY_ERR;
            }
            if (!dap_ledger_token_ticker_check(l_net->pub.ledger, l_token_buy_str)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_PARAM_TICKR_NOTF_ERR, 
                                                "Token ticker %s not found", l_token_buy_str);
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_PARAM_TICKR_NOTF_ERR;
            }

            if (!strcmp(l_token_sell_str, l_token_buy_str)){
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_TOKEN_EQUAL_ERR, 
                                                "token_buy and token_sell must be different!");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_TOKEN_EQUAL_ERR;
            }

            const char *l_val_sell_str = NULL, *l_val_rate_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_val_sell_str);
            if (!l_val_sell_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_REQ_PARAM_VALUE_ERR, 
                                                "Command 'order create' requires parameter -value");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_REQ_PARAM_VALUE_ERR;
            }
            uint256_t l_datoshi_sell = dap_chain_balance_scan(l_val_sell_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-rate", &l_val_rate_str);
            if (!l_val_rate_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_REQ_PARAM_RATE_ERR, 
                                                "Command 'order create' requires parameter -rate");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_REQ_PARAM_RATE_ERR;
            }
            uint256_t l_rate = dap_chain_coins_to_balance(l_val_rate_str);
            const char *l_fee_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
            if (!l_fee_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_REQ_PARAM_FEE_ERR, 
                                                "Command 'order create' requires parameter -fee");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_REQ_PARAM_FEE_ERR;
            }
            uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_str);
            if (!l_wallet_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_REQ_PARAM_W_ERR, 
                                                "Command 'order create' requires parameter -w");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_REQ_PARAM_W_ERR;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
            if (!l_wallet) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_WALLET_NOT_FOUND_ERR, 
                                                "Specified wallet not found");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CRTE_WALLET_NOT_FOUND_ERR;
            }
            const char* l_sign_str = dap_chain_wallet_check_sign(l_wallet);
            char *l_hash_ret = NULL;
            int ret_code = dap_chain_net_srv_xchange_create(l_net, l_token_buy_str, l_token_sell_str, l_datoshi_sell, l_rate, l_fee, l_wallet, &l_hash_ret);
            dap_chain_wallet_close(l_wallet);
            switch (ret_code) {
                case XCHANGE_CREATE_ERROR_OK: {
                    json_object* json_obj_order = json_object_new_object();
                    json_object_object_add(json_obj_order, "status", json_object_new_string(a_version == 1 ? "Successfully created" : "success"));
                    json_object_object_add(json_obj_order, "sign", json_object_new_string(l_sign_str));
                    json_object_object_add(json_obj_order, "hash", json_object_new_string(l_hash_ret));
                    json_object_array_add(*a_json_arr_reply, json_obj_order);
                    DAP_DELETE(l_hash_ret);
                    return DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_OK;
                }
                case XCHANGE_CREATE_ERROR_INVALID_ARGUMENT: {
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_CREATE_ERROR_INVALID_ARGUMENT, 
                                                "Some parameters could not be set during a function call");
                    return -XCHANGE_CREATE_ERROR_INVALID_ARGUMENT;
                }
                case XCHANGE_CREATE_ERROR_TOKEN_TICKER_SELL_IS_NOT_FOUND_LEDGER: {
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_CREATE_ERROR_TOKEN_TICKER_SELL_IS_NOT_FOUND_LEDGER, 
                                                "Token ticker %s not found", l_token_sell_str);
                    return -XCHANGE_CREATE_ERROR_TOKEN_TICKER_SELL_IS_NOT_FOUND_LEDGER;
                }
                case XCHANGE_CREATE_ERROR_TOKEN_TICKER_BUY_IS_NOT_FOUND_LEDGER: {
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_CREATE_ERROR_TOKEN_TICKER_BUY_IS_NOT_FOUND_LEDGER, 
                                                "Token ticker %s not found", l_token_buy_str);
                    return -XCHANGE_CREATE_ERROR_TOKEN_TICKER_BUY_IS_NOT_FOUND_LEDGER;
                }
                case XCHANGE_CREATE_ERROR_RATE_IS_ZERO: {
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_CREATE_ERROR_RATE_IS_ZERO, 
                                                "Format -rate n.n = buy / sell (eg: 1.0, 1.135)");
                    return -XCHANGE_CREATE_ERROR_RATE_IS_ZERO;
                }
                case XCHANGE_CREATE_ERROR_FEE_IS_ZERO: {
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_CREATE_ERROR_FEE_IS_ZERO, 
                                                "Format -value <unsigned integer 256>");
                    return -XCHANGE_CREATE_ERROR_FEE_IS_ZERO;
                }
                case XCHANGE_CREATE_ERROR_VALUE_SELL_IS_ZERO: {
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_CREATE_ERROR_VALUE_SELL_IS_ZERO, 
                                                "Format -value <unsigned integer 256>");
                    return -XCHANGE_CREATE_ERROR_VALUE_SELL_IS_ZERO;
                }
                case XCHANGE_CREATE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE: {
                    log_it(L_ERROR, "Integer overflow with sum of value and fee");
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_CREATE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE, 
                                                "Integer overflow with sum of value and fee");
                    return -XCHANGE_CREATE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE;
                }
                case XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET: {
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET, 
                                                "%s\nNot enough cash for fee in specified wallet", l_sign_str);
                    return -XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET;
                }
                case XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_IN_SPECIFIED_WALLET: {
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_IN_SPECIFIED_WALLET, 
                                                "%s\nNot enough cash in specified wallet", l_sign_str);
                    return -XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_IN_SPECIFIED_WALLET;
                }
                case XCHANGE_CREATE_ERROR_MEMORY_ALLOCATED: {
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_CREATE_ERROR_MEMORY_ALLOCATED, 
                                                "Out of memory");
                    return -XCHANGE_CREATE_ERROR_MEMORY_ALLOCATED;
                }
                case XCHANGE_CREATE_ERROR_CAN_NOT_COMPOSE_THE_CONDITIONAL_TRANSACTION: {
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_CREATE_ERROR_CAN_NOT_COMPOSE_THE_CONDITIONAL_TRANSACTION, 
                                                "%s\nCan't compose the conditional transaction", l_sign_str);
                    return -XCHANGE_CREATE_ERROR_CAN_NOT_COMPOSE_THE_CONDITIONAL_TRANSACTION;
                }
                case XCHANGE_CREATE_ERROR_CAN_NOT_PUT_TRANSACTION_TO_MEMPOOL: {
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_CREATE_ERROR_CAN_NOT_PUT_TRANSACTION_TO_MEMPOOL, 
                                                "%s\nCan't compose the conditional transaction", l_sign_str);
                    return -XCHANGE_CREATE_ERROR_CAN_NOT_PUT_TRANSACTION_TO_MEMPOOL;
                }
            }
        } break;

        case CMD_HISTORY:{
            json_object* l_json_obj_order = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_REQ_PARAM_NET_ERR, 
                                                "Command 'order history' requires parameter -net");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_REQ_PARAM_NET_ERR;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_NET_NOT_FOUND_ERR, 
                                                "Network %s not found", l_net_str);
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_NET_NOT_FOUND_ERR;
            }

            const char * l_order_hash_str = NULL;
            const char * l_addr_hash_str = NULL;

            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-addr", &l_addr_hash_str);

            if (!l_order_hash_str && ! l_addr_hash_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_REQ_PARAM_ORDER_ADDR_ERR, 
                                                "Command 'order history' requires parameter -order or -addr" );
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_REQ_PARAM_ORDER_ADDR_ERR;
            }


            if(l_addr_hash_str){
                dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_addr_hash_str);
                if (!l_addr) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_CAN_NOT_CONVERT_ERR, "Cannot convert "
                                                                   "string '%s' to binary address.", l_addr_hash_str);
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_CAN_NOT_CONVERT_ERR;
                }
                if (dap_chain_addr_check_sum(l_addr) != 0 ) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_INCORRECT_ADDR_ERR, "Incorrect address wallet");
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_INCORRECT_ADDR_ERR;
                }
                if (l_addr->net_id.uint64 != l_net->pub.id.uint64) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_DOES_NOT_BELONG_ERR, "Address %s does not belong to the %s network.",
                                                      l_addr_hash_str, l_net->pub.name);
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_DOES_NOT_BELONG_ERR;
                }

                dap_hash_fast_t l_hash_curr ={};
                bool l_from_wallet_cache = dap_chain_wallet_cache_tx_find(l_addr, NULL, NULL, &l_hash_curr, NULL) == 0 ? true : false;
                l_hash_curr = (dap_hash_fast_t){0};
                size_t l_total = 0;
                if(l_from_wallet_cache) {
                    xchange_orders_cache_net_t* l_cache = NULL;
                    if(s_xchange_cache_state == XCHANGE_CACHE_ENABLED){
                        l_cache = s_get_xchange_cache_by_net_id(l_net->pub.id);
                        if(!l_cache){
                            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_DOES_NO_HISTORY_ERR, "No history");
                            break;
                        }
                    }
                    l_json_obj_order = json_object_new_object();
                    dap_chain_wallet_cache_iter_t *l_iter = dap_chain_wallet_cache_iter_create(*l_addr);
                    for(dap_chain_datum_tx_t *l_datum_tx = dap_chain_wallet_cache_iter_get(l_iter, DAP_CHAIN_WALLET_CACHE_GET_FIRST);
                            l_datum_tx; l_datum_tx = dap_chain_wallet_cache_iter_get(l_iter, DAP_CHAIN_WALLET_CACHE_GET_NEXT))
                    {
                        if (l_iter->ret_code != 0)
                            continue; 

                        
                        if(s_xchange_cache_state == XCHANGE_CACHE_ENABLED){
                            xchange_tx_cache_t* l_item = NULL;
                            HASH_FIND(hh, l_cache->cache, l_iter->cur_hash, sizeof(dap_hash_fast_t), l_item); 
                            if (!l_item)
                                continue;

                            if (s_string_append_tx_cond_info_json(l_json_obj_order, l_net, &l_item->seller_addr, 
                                l_item->tx_type == TX_TYPE_EXCHANGE ?  &l_item->tx_info.exchange_info.buyer_addr : NULL, 
                                l_datum_tx, l_iter->cur_hash, TX_STATUS_ALL, true, true, false, a_version))
                                
                                l_total++;
                        } else {
                            if (s_string_append_tx_cond_info_json(l_json_obj_order, l_net, NULL, NULL, l_datum_tx, l_iter->cur_hash, TX_STATUS_ALL, true, true, false, a_version))
                                l_total++;
                        }
                    }
                    dap_chain_wallet_cache_iter_delete(l_iter);
                    
                    if(!l_total)
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_DOES_NO_HISTORY_ERR, "No history");
                    else {
                        if (a_version == 1) {
                            char *l_orders = dap_strdup_printf("Found %zu", l_total);
                            json_object_object_add(l_json_obj_order, "number of orders", json_object_new_string(l_orders));                        
                            DAP_DELETE(l_orders);
                        } else {
                            json_object_object_add(l_json_obj_order, "total_orders_count", json_object_new_uint64(l_total)); 
                        }
                    }
                    json_object_array_add(*a_json_arr_reply, l_json_obj_order);
                } else { 
                    dap_list_t *l_tx_list = dap_chain_net_get_tx_cond_all_for_addr(l_net,l_addr, c_dap_chain_net_srv_xchange_uid );

                    if (l_tx_list){
                        dap_list_t *l_tx_list_temp = l_tx_list;
                        l_json_obj_order = json_object_new_object();
                        json_object_object_add(l_json_obj_order, "wallet", json_object_new_string(l_addr_hash_str));
                        while(l_tx_list_temp ){
                            dap_chain_datum_tx_t * l_tx_cur = (dap_chain_datum_tx_t*) l_tx_list_temp->data;
                            dap_hash_fast_t l_hash = {};
                            dap_hash_fast(l_tx_cur, dap_chain_datum_tx_get_size(l_tx_cur), &l_hash);
                            if ( s_string_append_tx_cond_info_json(l_json_obj_order, l_net, NULL, NULL, l_tx_cur, &l_hash, TX_STATUS_ALL, true, true, false, a_version) )
                                l_total++;
                            l_tx_list_temp = l_tx_list_temp->next;
                        }
                        dap_list_free(l_tx_list);
                        if (a_version == 1) {
                            char *l_orders = dap_strdup_printf("Found %zu", l_total);
                            json_object_object_add(l_json_obj_order, "number of orders", json_object_new_string(l_orders));
                            DAP_DELETE(l_orders);
                        } else {
                            json_object_object_add(l_json_obj_order, "total_orders_count", json_object_new_uint64(l_total));
                        }
                        json_object_array_add(*a_json_arr_reply, l_json_obj_order);
                        
                    }else{
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_DOES_NO_HISTORY_ERR, "No history");
                    }
                }
                DAP_DELETE(l_addr);
                break;
            }

            if(l_order_hash_str){
                dap_hash_fast_t l_order_tx_hash = {};
                dap_chain_hash_fast_from_str(l_order_hash_str, &l_order_tx_hash);
                l_json_obj_order = json_object_new_object();
                if(s_xchange_cache_state == XCHANGE_CACHE_DISABLED){
                    dap_chain_datum_tx_t* l_tx = dap_chain_net_get_tx_by_hash(l_net, &l_order_tx_hash, TX_SEARCH_TYPE_NET);
                    if( l_tx){
                        xchange_tx_type_t l_tx_type = dap_chain_net_srv_xchange_tx_get_type(l_net->pub.ledger, l_tx, NULL, NULL, NULL);
                        char *l_tx_hash = dap_chain_hash_fast_to_str_new(&l_order_tx_hash);
                        if(l_tx_type != TX_TYPE_ORDER){
                            json_object_object_add(l_json_obj_order, a_version == 1 ? "datum status" : "datum_status", json_object_new_string(a_version == 1 ? "is not order" : "is_not_order"));
                            json_object_object_add(l_json_obj_order, a_version == 1 ? "datum hash" : "datum_hash", json_object_new_string(l_tx_hash));
                        } else {
                            dap_chain_net_srv_xchange_order_status_t l_rc = s_tx_check_for_open_close(l_net,l_tx);
                            if(l_rc == XCHANGE_ORDER_STATUS_UNKNOWN){
                                json_object_object_add(l_json_obj_order, a_version == 1 ? "WRONG TX" : "wrong_tx", json_object_new_string(l_tx_hash));
                            }else{
                                dap_list_t *l_tx_list = dap_chain_net_get_tx_cond_chain(l_net, &l_order_tx_hash, c_dap_chain_net_srv_xchange_uid );
                                dap_list_t *l_tx_list_temp = l_tx_list;
                                json_object* l_json_obj_tx_arr = json_object_new_array();
                                while(l_tx_list_temp ){
                                    json_object* l_json_obj_cur_tx = json_object_new_object();
                                    dap_chain_datum_tx_t * l_tx_cur = (dap_chain_datum_tx_t*) l_tx_list_temp->data;
                                    dap_hash_fast_t l_hash = {};
                                    dap_hash_fast(l_tx_cur, dap_chain_datum_tx_get_size(l_tx_cur), &l_hash);
                                    s_string_append_tx_cond_info_json(l_json_obj_cur_tx, l_net, NULL, NULL, l_tx_cur, &l_hash, TX_STATUS_ALL, true, true, false, a_version);
                                    json_object_array_add(l_json_obj_tx_arr, l_json_obj_cur_tx);
                                    l_tx_list_temp = l_tx_list_temp->next;
                                }
                                json_object_object_add(l_json_obj_order, a_version == 1 ? "history for order" : "history_for_order", l_json_obj_tx_arr);
                                dap_list_free(l_tx_list);
                            }
                        }
                        DAP_DELETE(l_tx_hash);
                    }else{
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_DOES_NO_HISTORY_ERR, "No history");
                    }
                } else {
                    xchange_orders_cache_net_t* l_cache = NULL;
                    dap_list_t *l_tx_cache_list = NULL;
                    l_cache = s_get_xchange_cache_by_net_id(l_net->pub.id);
                    xchange_tx_cache_t* l_item = NULL;
                    dap_hash_fast_t l_cur_hash = l_order_tx_hash;
                    l_json_obj_order = json_object_new_object();
                    HASH_FIND(hh, l_cache->cache, &l_cur_hash, sizeof(dap_hash_fast_t), l_item);
                    if (!l_item){
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_DOES_NO_HISTORY_ERR, "No history");
                        return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_HIST_DOES_NO_HISTORY_ERR;
                    }
                    json_object* l_json_obj_tx_arr = json_object_new_array();
                    while(l_item){
                        json_object* l_json_obj_cur_tx = json_object_new_object();
                        s_string_append_tx_cond_info_json(l_json_obj_cur_tx, l_net, &l_item->seller_addr, 
                                l_item->tx_type == TX_TYPE_EXCHANGE ?  &l_item->tx_info.exchange_info.buyer_addr : NULL, 
                                l_item->tx, &l_item->hash, TX_STATUS_ALL, true, true, false, a_version);
                        json_object_array_add(l_json_obj_tx_arr, l_json_obj_cur_tx);
                        switch(l_item->tx_type){
                            case TX_TYPE_ORDER:{
                                l_cur_hash = l_item->tx_info.order_info.next_hash;
                            } break;
                            case TX_TYPE_EXCHANGE:{
                                l_cur_hash = l_item->tx_info.exchange_info.next_hash;
                            } break;
                            case TX_TYPE_INVALIDATE:{
                                l_cur_hash = (dap_hash_fast_t){0};
                            } break;
                            default:break;
                        }
                        if (dap_hash_fast_is_blank(&l_cur_hash))
                            break;
                        HASH_FIND(hh, l_cache->cache, &l_cur_hash, sizeof(dap_hash_fast_t), l_item);
                    }
                    json_object_object_add(l_json_obj_order, a_version == 1 ? "history for order" : "history_for_order", l_json_obj_tx_arr);
                }
            }
            json_object_array_add(*a_json_arr_reply, l_json_obj_order);
        } break;

        case CMD_REMOVE:
        {
            const char * l_order_hash_str = NULL;
            const char * l_fee_str = NULL;
            json_object* json_obj_order = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_REQ_PARAM_NET_ERR, "Command 'order %s' requires parameter -net",
                                                                l_cmd_num == CMD_REMOVE ? "remove" : "update");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_REQ_PARAM_NET_ERR;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_NET_NOT_FOUND_ERR, 
                                                                            "Network %s not found", l_net_str);
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_NET_NOT_FOUND_ERR;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_str);
            if (!l_wallet_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_REQ_PARAM_W_ERR, 
                                                                            "Command 'order %s' requires parameter -w",
                                                                l_cmd_num == CMD_REMOVE ? "remove" : "update");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_REQ_PARAM_W_ERR;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
            if (!l_wallet) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_WALLET_NOT_FOUND_ERR,
                                                                            "Specified wallet not found");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_WALLET_NOT_FOUND_ERR;
            }
            const char* l_sign_str = dap_chain_wallet_check_sign(l_wallet);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_REQ_PARAM_ORDER_ADDR_ERR, 
                                                                            "Command 'order %s' requires parameter -order",
                                                                l_cmd_num == CMD_REMOVE ? "remove" : "update");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_REQ_PARAM_ORDER_ADDR_ERR;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
            if (!l_fee_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_REQ_PARAM_FEE_ERR, 
                                                                            "Command 'order %s' requires parameter -fee",
                                                  l_cmd_num == CMD_REMOVE ? "remove" : "update");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_REQ_PARAM_FEE_ERR;
            }
            uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
            dap_hash_fast_t l_tx_hash = {};
            dap_chain_hash_fast_from_str(l_order_hash_str, &l_tx_hash);
            char *l_tx_hash_ret = NULL;
            int l_ret_code = dap_chain_net_srv_xchange_remove(l_net, &l_tx_hash, l_fee, l_wallet, &l_tx_hash_ret);
            dap_chain_wallet_close(l_wallet);
            
            switch (l_ret_code) {
                case XCHANGE_REMOVE_ERROR_OK:
                    json_obj_order = json_object_new_object();
                    if (a_version == 1) {
                        json_object_object_add(json_obj_order, "status", json_object_new_string("Order successfully removed"));
                        json_object_object_add(json_obj_order, "Created inactivate tx with hash", json_object_new_string(l_tx_hash_ret));
                    } else {
                        json_object_object_add(json_obj_order, "status", json_object_new_string("success"));
                        json_object_object_add(json_obj_order, "tx_hash", json_object_new_string(l_tx_hash_ret));
                    }
                    json_object_array_add(*a_json_arr_reply, json_obj_order);
                    DAP_DELETE(l_tx_hash_ret);
                    break;
                case XCHANGE_REMOVE_ERROR_CAN_NOT_FIND_TX:
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_REMOVE_ERROR_CAN_NOT_FIND_TX, "%s\nSpecified order not found", l_sign_str);
                    break;
                case XCHANGE_REMOVE_ERROR_CAN_NOT_CREATE_PRICE:
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_REMOVE_ERROR_CAN_NOT_CREATE_PRICE, "%s\nCan't create price object from order", l_sign_str);
                    break;
                case XCHANGE_REMOVE_ERROR_FEE_IS_ZERO:
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_REMOVE_ERROR_FEE_IS_ZERO, "Can't get fee value.");
                    break;
                case XCHANGE_REMOVE_ERROR_CAN_NOT_INVALIDATE_TX: {
                    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_tx_hash);
                    dap_chain_net_srv_xchange_price_t *l_price = s_xchange_price_from_order(l_net, l_cond_tx, &l_tx_hash, &l_fee, false);
                    const char *l_final_tx_hash_str = dap_chain_hash_fast_to_str_static(&l_price->tx_hash);
                    dap_json_rpc_error_add(*a_json_arr_reply, XCHANGE_REMOVE_ERROR_CAN_NOT_INVALIDATE_TX, "Can't create invalidate transaction from: %s\n", l_final_tx_hash_str);
                    DAP_DELETE(l_price);
                } break;
                default:
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_RMOVE_UNKNOWN_ERR, "An error occurred with an unknown code: %d.", l_ret_code);
                    break;
            }
            return l_ret_code;
        } break;

        case CMD_STATUS: {
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_REQ_PARAM_NET_ERR, 
                                                            "Command 'order status' requires parameter -net");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_REQ_PARAM_NET_ERR;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_NET_NOT_FOUND_ERR, 
                                                            "Network %s not found", l_net_str);
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_NET_NOT_FOUND_ERR;
            }
            const char * l_order_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_REQ_PARAM_ORDER_ADDR_ERR, 
                                                            "Command 'order status' requires parameter -order or -addr" );
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_REQ_PARAM_ORDER_ADDR_ERR;
            }
            dap_hash_fast_t l_order_tx_hash = {};
            dap_chain_hash_fast_from_str(l_order_hash_str, &l_order_tx_hash);

            char *l_status_order = NULL, *l_token_buy = NULL, *l_token_sell = NULL, *l_owner_addr = NULL;
            const char *l_cp_rate, *l_amount_coins_str = NULL, *l_amount_datoshi_str = NULL, *l_proposed_coins_str = NULL, *l_proposed_datoshi_str = NULL;
            uint64_t l_percent_completed = 0;
            dap_chain_datum_tx_t *l_tx = NULL;
            uint256_t l_amount, l_rate, l_proposed;

            if (s_xchange_cache_state == XCHANGE_CACHE_ENABLED){
                xchange_orders_cache_net_t* l_cache = NULL;
                dap_list_t *l_tx_cache_list = NULL;
                l_cache = s_get_xchange_cache_by_net_id(l_net->pub.id);
                xchange_tx_cache_t* l_item = NULL;
                HASH_FIND(hh, l_cache->cache, &l_order_tx_hash, sizeof(dap_hash_fast_t), l_item);
                l_tx = l_item ? l_item->tx : NULL;
                if (!l_tx){
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_FIND_ORDER_ERR, 
                                                            "Can't find order %s", l_order_hash_str);
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_FIND_ORDER_ERR;
                }

                if (l_item->tx_type != TX_TYPE_ORDER){
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_ITS_NOT_ORDER_ERR,
                                            "Item is not an order");
                    return DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_ITS_NOT_ORDER_ERR;
                }

                switch (l_item->tx_info.order_info.order_status)
                {
                    case XCHANGE_ORDER_STATUS_OPENED:
                        l_status_order = "OPENED";
                        break;
                    case XCHANGE_ORDER_STATUS_CLOSED:
                        l_status_order = "CLOSED";
                        break;
                    default:
                        l_status_order = "UNKNOWN";
                        break;
                };

                l_amount = l_item->tx_info.order_info.value_ammount;
                l_rate = l_item->rate;
                
                l_token_sell = l_item->sell_token;
                l_token_buy = l_item->buy_token;
                l_proposed = l_item->tx_info.order_info.value;
                
                l_percent_completed = l_item->tx_info.order_info.percent_completed;
                l_owner_addr = dap_strdup(dap_chain_addr_to_str(&l_item->seller_addr));
            } else {
                l_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_order_tx_hash);
                if (!l_tx){
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_FIND_ORDER_ERR, 
                                                            "Can't find order %s", l_order_hash_str);
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_FIND_ORDER_ERR;
                }

                // Find SRV_XCHANGE in_cond item
                int l_item_idx = 0;
                byte_t *l_tx_item = dap_chain_datum_tx_item_get(l_tx, &l_item_idx, NULL, TX_ITEM_TYPE_IN_COND , NULL);
                dap_chain_tx_in_cond_t * l_in_cond = l_tx_item ? (dap_chain_tx_in_cond_t *) l_tx_item : NULL;
                int l_prev_cond_idx = 0;
                dap_chain_datum_tx_t * l_prev_tx = l_in_cond ? dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_in_cond->header.tx_prev_hash) : NULL;
                dap_chain_tx_out_cond_t *l_out_prev_cond_item = l_prev_tx ? dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                                                &l_prev_cond_idx) : NULL;
                if(l_out_prev_cond_item){
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_ITS_NOT_ORDER_ERR,
                                            "Item is not an order");
                    return DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_ITS_NOT_ORDER_ERR;
                }

                // TODO add filters to list (tokens, network, etc.)
                dap_chain_net_srv_xchange_price_t *l_price = s_xchange_price_from_order(l_net, l_tx, &l_order_tx_hash, NULL, true);
                if( !l_price ){
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_GET_PRICE_ERR, 
                                                            "Can't get price from order");
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_GET_PRICE_ERR;
                }

                dap_ledger_t * l_ledger = dap_ledger_by_net_name(l_net->pub.name);
                
                dap_hash_fast_t l_last_tx_hash = dap_ledger_get_final_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_price->tx_hash, false);
                if( dap_hash_fast_is_blank(&l_last_tx_hash) ){
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_GET_LAST_TX_ERR, 
                                                            "Can't get last tx cond hash from order");
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_GET_LAST_TX_ERR;
                }

                dap_chain_datum_tx_t * l_last_tx = dap_ledger_tx_find_by_hash(l_ledger, &l_last_tx_hash);
                log_it(L_INFO, "Last tx hash %s", dap_hash_fast_to_str_static(&l_last_tx_hash));
                if (!l_last_tx){
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_FIND_LAST_TX_ERR, 
                                                            "Can't find last tx");
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_STATUS_CANT_FIND_LAST_TX_ERR;
                }

                dap_chain_tx_out_cond_t *l_out_cond_last_tx = dap_chain_datum_tx_out_cond_get(l_last_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE , NULL);
            
                l_percent_completed = dap_chain_net_srv_xchange_get_order_completion_rate(l_net, l_order_tx_hash);

                l_token_sell = dap_strdup(l_price->token_sell);
                l_token_buy = dap_strdup(l_price->token_buy);

                l_proposed = l_price->datoshi_sell;
                l_amount = l_out_cond_last_tx ? l_out_cond_last_tx->header.value : uint256_0;
                l_rate = l_price->rate;

                switch (dap_chain_net_srv_xchange_get_order_status(l_net, l_order_tx_hash))
                {
                    case XCHANGE_ORDER_STATUS_OPENED:
                        l_status_order = "OPENED";
                        break;
                    case XCHANGE_ORDER_STATUS_CLOSED:
                        l_status_order = "CLOSED";
                        break;
                    default:
                        l_status_order = "UNKNOWN";
                        break;
                };

                l_owner_addr =  dap_strdup(dap_chain_addr_to_str(&l_price->creator_addr));
                DAP_DELETE(l_price);
            }

            char l_tmp_buf[DAP_TIME_STR_SIZE];
            dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_tx->header.ts_created);

            json_object* json_obj_order = json_object_new_object();
            json_object_object_add(json_obj_order, "order_hash", json_object_new_string(l_order_hash_str));
            json_object_object_add(json_obj_order, "ts_created", json_object_new_string(l_tmp_buf));
            json_object_object_add(json_obj_order, "status", json_object_new_string(l_status_order));

            l_proposed_datoshi_str = dap_uint256_to_char(l_proposed, &l_proposed_coins_str);
            json_object_object_add(json_obj_order, "proposed_coins", json_object_new_string(*l_proposed_coins_str ? l_proposed_coins_str : "0.0"));
            json_object_object_add(json_obj_order, "proposed_datoshi", json_object_new_string(*l_proposed_datoshi_str ? l_proposed_datoshi_str : "0"));
            
            l_amount_datoshi_str = dap_uint256_to_char(l_amount, &l_amount_coins_str);
            json_object_object_add(json_obj_order, "amount_coins", json_object_new_string(*l_amount_coins_str ? l_amount_coins_str : "0.0")); 
            json_object_object_add(json_obj_order, "amount_datoshi", json_object_new_string(*l_amount_datoshi_str ? l_amount_datoshi_str : "0")); 
            json_object_object_add(json_obj_order, "filled_percent", json_object_new_uint64(l_percent_completed));
            json_object_object_add(json_obj_order, "token_buy", json_object_new_string(l_token_buy));
            json_object_object_add(json_obj_order, "token_sell", json_object_new_string(l_token_sell));

            dap_uint256_to_char(l_rate, &l_cp_rate);
            json_object_object_add(json_obj_order, "rate", json_object_new_string(l_cp_rate));

            json_object_object_add(json_obj_order, "net", json_object_new_string(l_net->pub.name));
            json_object_object_add(json_obj_order, "owner_addr", json_object_new_string(l_owner_addr));
            json_object_array_add(*a_json_arr_reply, json_obj_order);
            DAP_DELETE(l_owner_addr);
            if ( s_xchange_cache_state != XCHANGE_CACHE_ENABLED ) 
                DAP_DEL_MULTY(l_token_buy, l_token_sell);
        } break;

        default: {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_SUB_NOT_FOUND_ERR, 
                                                            "Subcommand %s not recognized", a_argv[a_arg_index]);
            return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_SUB_NOT_FOUND_ERR;
        }
    }
    return 0;
}

// Filter for find tx with DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE
static bool s_filter_tx_list(dap_chain_datum_t *a_datum, dap_chain_t *a_chain, void *a_filter_func_param)
{
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
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    // Time filter
    if(l_time_begin && l_datum_tx->header.ts_created < l_time_begin)
        return false;
    if(l_time_end && l_datum_tx->header.ts_created > l_time_end)
        return false;
    // Find SRV_XCHANGE out_cond item
    int l_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_out_cond_get(l_datum_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                               &l_cond_idx);
    if (l_out_cond_item)
        return true;
    // Find SRV_XCHANGE in_cond item
    int l_item_idx = 0;
    dap_chain_tx_in_cond_t * l_in_cond = (dap_chain_tx_in_cond_t *)dap_chain_datum_tx_item_get(l_datum_tx, &l_item_idx, NULL, TX_ITEM_TYPE_IN_COND , NULL);
    int l_prev_cond_idx = 0;
    dap_chain_datum_tx_t * l_prev_tx = l_in_cond ? dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_in_cond->header.tx_prev_hash) : NULL;
    dap_chain_tx_out_cond_t *l_out_prev_cond_item = l_prev_tx ? dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                                                &l_prev_cond_idx) : NULL;
    if(l_out_prev_cond_item)
        return true;
    return false;
}

xchange_tx_type_t dap_chain_net_srv_xchange_tx_get_type (dap_ledger_t * a_ledger, dap_chain_datum_tx_t * a_tx, dap_chain_tx_out_cond_t **a_out_cond_item, 
                                                            int *a_item_idx, dap_chain_tx_out_cond_t **a_out_prev_cond_item)
{
    int l_tx_type = TX_TYPE_UNDEFINED;

    // Find SRV_XCHANGE out_cond item
    int l_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                               &l_cond_idx);
    // Find SRV_XCHANGE in_cond item
    int l_item_idx = 0;
    byte_t *l_tx_item = dap_chain_datum_tx_item_get(a_tx, &l_item_idx, NULL, TX_ITEM_TYPE_IN_COND , NULL);
    dap_chain_tx_in_cond_t * l_in_cond = l_tx_item ? (dap_chain_tx_in_cond_t *) l_tx_item : NULL;
    int l_prev_cond_idx = 0;
    dap_chain_datum_tx_t * l_prev_tx = l_in_cond ? dap_ledger_tx_find_by_hash(a_ledger, &l_in_cond->header.tx_prev_hash) : NULL;
    dap_chain_tx_out_cond_t *l_out_prev_cond_item = l_prev_tx ? dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
                                                                                                &l_prev_cond_idx) : NULL;

    if(l_out_prev_cond_item && l_out_prev_cond_item->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE)
        return l_tx_type;
    
    if (l_in_cond && l_prev_cond_idx >= 0 && (uint32_t)l_prev_cond_idx != l_in_cond->header.tx_out_prev_idx)
        return l_tx_type;
    
    if (l_out_cond_item && !l_out_prev_cond_item)
        l_tx_type = TX_TYPE_ORDER;
    else if (l_out_cond_item && l_out_prev_cond_item) {
        l_tx_type = TX_TYPE_EXCHANGE;
    }
    else if (!l_out_cond_item && l_out_prev_cond_item)
    {
        dap_chain_datum_tx_t * l_prev_tx_temp = a_tx;
        byte_t *l_tx_item_temp = NULL;
        while((l_tx_item_temp = dap_chain_datum_tx_item_get(l_prev_tx_temp, &l_item_idx, NULL, TX_ITEM_TYPE_IN_COND , NULL)) != NULL)
        {
                dap_chain_tx_in_cond_t * l_in_cond_temp = (dap_chain_tx_in_cond_t *) l_tx_item_temp;
                l_prev_tx_temp = dap_ledger_tx_find_by_hash(a_ledger, &l_in_cond_temp->header.tx_prev_hash);
        }
        dap_chain_tx_sig_t *l_tx_prev_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_prev_tx_temp, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
        dap_sign_t *l_prev_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_prev_sig);
        dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
        dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);

        bool l_owner = false;
        l_owner = dap_sign_compare_pkeys(l_prev_sign,l_sign);
        if (l_owner)
                l_tx_type = TX_TYPE_INVALIDATE;
        else
                l_tx_type = TX_TYPE_EXCHANGE;
    }
    if(a_out_cond_item)
        *a_out_cond_item = l_out_cond_item;
    if(a_out_prev_cond_item)
        *a_out_prev_cond_item = l_out_prev_cond_item;
    if (a_item_idx)
        *a_item_idx = l_cond_idx;
    return l_tx_type;
}

/**
 * @brief Check for open/close
 * @param a_net
 * @param a_tx
 * @return 0 if its not SRV_XCHANGE transaction, 1 if its closed, 2 if its open
 */
static dap_chain_net_srv_xchange_order_status_t s_tx_check_for_open_close(dap_chain_net_t * a_net, dap_chain_datum_tx_t * a_tx)
{
    dap_ledger_t * l_ledger = dap_ledger_by_net_name(a_net->pub.name);

    dap_hash_fast_t l_tx_hash = {};
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_tx_hash);
    dap_hash_fast_t l_last_tx_hash = dap_ledger_get_final_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_tx_hash, false);
    if ( dap_hash_fast_is_blank(&l_last_tx_hash) ) {
        log_it(L_WARNING,"Can't get last tx cond hash from order");
        return XCHANGE_ORDER_STATUS_UNKNOWN;
    }

    dap_chain_datum_tx_t * l_last_tx = dap_ledger_tx_find_by_hash(l_ledger, &l_last_tx_hash);
    if (!l_last_tx) {
        log_it(L_WARNING,"Can't find last tx");
        return XCHANGE_ORDER_STATUS_UNKNOWN;
    }

    dap_chain_tx_out_cond_t *l_out_cond_last_tx = dap_chain_datum_tx_out_cond_get(l_last_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE , NULL);
    if (!l_out_cond_last_tx || IS_ZERO_256(l_out_cond_last_tx->header.value)){
        return XCHANGE_ORDER_STATUS_CLOSED;
    } else {
        return XCHANGE_ORDER_STATUS_OPENED;
    }
    return XCHANGE_ORDER_STATUS_UNKNOWN;
}

/**
 * @brief Append tx info to the reply string
 * @param a_reply_str
 * @param a_net
 * @param a_tx
 */
#if 0
static bool s_string_append_tx_cond_info( dap_string_t * a_reply_str, dap_chain_net_t * a_net,
                                         dap_chain_addr_t *a_owner_addr, dap_chain_addr_t *a_buyer_addr,
                                         dap_chain_datum_tx_t * a_tx, dap_hash_fast_t *a_tx_hash,
                                         tx_opt_status_t a_filter_by_status,
                                         bool a_print_prev_hash, bool a_print_status, bool a_print_ts)
{
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    const char *l_tx_hash_str = dap_chain_hash_fast_to_str_static(a_tx_hash);
    // Get input token ticker
    const char * l_tx_input_ticker = dap_ledger_tx_get_token_ticker_by_hash(
                a_net->pub.ledger, a_tx_hash);
    if(!l_tx_input_ticker){
        log_it(L_WARNING, "Can't get ticker from tx");
        return false;
    }
    dap_chain_tx_out_cond_t *l_out_prev_cond_item = NULL;
    dap_chain_tx_out_cond_t *l_out_cond_item = NULL;
    int l_cond_idx = 0;

    xchange_tx_type_t l_tx_type = dap_chain_net_srv_xchange_tx_get_type(a_net->pub.ledger, a_tx, &l_out_cond_item, &l_cond_idx, &l_out_prev_cond_item);

    bool l_is_closed = dap_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, a_tx_hash, l_cond_idx, NULL);
    if ((a_filter_by_status == TX_STATUS_ACTIVE && l_is_closed) || (a_filter_by_status == TX_STATUS_INACTIVE && !l_is_closed)
     || (a_filter_by_status == TX_STATUS_ACTIVE && l_tx_type == TX_TYPE_INVALIDATE))
        return false;

    if(l_out_prev_cond_item && l_out_prev_cond_item->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE)
        return false;

    switch(l_tx_type){
        case TX_TYPE_ORDER:{
            if (!l_out_cond_item) {
                log_it(L_ERROR, "Can't find conditional output");
                return false;
            }
            char *l_rate_str = dap_chain_balance_to_coins(l_out_cond_item->subtype.srv_xchange.rate);
            const char *l_amount_str, *l_amount_datoshi_str = dap_uint256_to_char(l_out_cond_item->header.value, &l_amount_str);

            dap_string_append_printf(a_reply_str, "Hash: %s\n", l_tx_hash_str);
            if(a_print_ts){
                char l_tmp_buf[DAP_TIME_STR_SIZE];
                dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, a_tx->header.ts_created);
                dap_string_append_printf(a_reply_str, "  ts_created: %s", l_tmp_buf);
            }
            if( a_print_status)
                dap_string_append_printf(a_reply_str, "  Status: %s,", l_is_closed ? "inactive" : "active");
            dap_string_append_printf(a_reply_str, "  proposed %s (%s) %s for exchange to %s,", l_amount_str, l_amount_datoshi_str, l_tx_input_ticker, l_out_cond_item->subtype.srv_xchange.buy_token);
            dap_string_append_printf(a_reply_str, "  rate (%s/%s): %s, net: %s", l_out_cond_item->subtype.srv_xchange.buy_token, l_tx_input_ticker, l_rate_str, a_net->pub.name);
            dap_chain_addr_t l_owner_addr = {};
            if (!a_owner_addr){
                l_owner_addr = l_out_cond_item ? l_out_cond_item->subtype.srv_xchange.seller_addr : (l_out_prev_cond_item ? l_out_prev_cond_item->subtype.srv_xchange.seller_addr : (dap_chain_addr_t){0});
            } else {
                l_owner_addr = *a_owner_addr;
            }

            dap_string_append_printf(a_reply_str, "\nowner addr %s \n", dap_chain_addr_to_str_static(&l_owner_addr));

            DAP_DELETE(l_rate_str);
        } break;
        case TX_TYPE_EXCHANGE:{
            dap_chain_tx_in_cond_t *l_in_cond 
                = (dap_chain_tx_in_cond_t*)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND , NULL);
            char l_tx_prev_cond_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_in_cond->header.tx_prev_hash, l_tx_prev_cond_hash_str, sizeof(l_tx_prev_cond_hash_str));

            if (!l_out_prev_cond_item) {
                log_it(L_ERROR, "Can't find previous transaction");
                return false;
            }

            uint256_t l_rate = l_out_cond_item 
                ? l_out_cond_item->subtype.srv_xchange.rate
                : l_out_prev_cond_item->subtype.srv_xchange.rate,
                     l_value_from = {}, l_value_to = {};

            if (l_out_cond_item)
                SUBTRACT_256_256(l_out_prev_cond_item->header.value, l_out_cond_item->header.value, &l_value_from);
            else
                l_value_from = l_out_prev_cond_item->header.value;
            MULT_256_COIN(l_value_from, l_rate, &l_value_to);

            char *l_buy_ticker = l_out_cond_item 
                ? l_out_cond_item->subtype.srv_xchange.buy_token
                : l_out_prev_cond_item->subtype.srv_xchange.buy_token;

            dap_string_append_printf(a_reply_str, "Hash: %s\n", l_tx_hash_str);
            if(a_print_ts){
                char l_tmp_buf[DAP_TIME_STR_SIZE];
                dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, a_tx->header.ts_created);
                dap_string_append_printf(a_reply_str, "  ts_created: %s", l_tmp_buf);
            }
            if(a_print_status)
                dap_string_append_printf(a_reply_str, "  Status: %s,", l_is_closed ? "inactive" : "active");
            
            const char *l_value_from_str, *l_value_from_datoshi_str = dap_uint256_to_char(l_value_from, &l_value_from_str);
            dap_string_append_printf(a_reply_str, "  changed %s (%s) %s", l_value_from_str, l_value_from_datoshi_str, l_tx_input_ticker);

            const char *l_value_to_str, *l_value_to_datoshi_str = dap_uint256_to_char(l_value_to, &l_value_to_str);
            dap_string_append_printf(a_reply_str, " for %s (%s) %s,", l_value_to_str, l_value_to_datoshi_str, l_buy_ticker);

            const char *l_rate_str; dap_uint256_to_char(l_rate, &l_rate_str);
            dap_string_append_printf(a_reply_str, "  rate (%s/%s): %s,", l_buy_ticker, l_tx_input_ticker, l_rate_str);

            const char *l_amount_str = NULL,
                 *l_amount_datoshi_str = l_out_cond_item ? dap_uint256_to_char(l_out_cond_item->header.value, &l_amount_str) : "0";
            dap_string_append_printf(a_reply_str, "  remain amount %s (%s) %s, net: %s", l_amount_str ? l_amount_str : "0.0",
                                                                        l_amount_datoshi_str, l_tx_input_ticker, a_net->pub.name);
            if (a_print_prev_hash)
                dap_string_append_printf(a_reply_str, "\n  Prev cond: %s", l_tx_prev_cond_hash_str);

            dap_chain_tx_out_cond_subtype_t l_cond_type = l_out_cond_item ? l_out_cond_item->header.subtype : l_out_prev_cond_item->header.subtype;
            dap_hash_fast_t l_order_hash = dap_ledger_get_first_chain_tx_hash(a_net->pub.ledger, a_tx, l_cond_type);
            if ( dap_hash_fast_is_blank(&l_order_hash) )
                l_order_hash = l_in_cond->header.tx_prev_hash;
            char l_order_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_order_hash, l_order_hash_str, sizeof(l_order_hash_str));            
            dap_string_append_printf(a_reply_str, "\norder hash: %s\n", l_order_hash_str);

            dap_chain_addr_t l_owner_addr = {};
            if (!a_owner_addr){
                l_owner_addr = l_out_cond_item ? l_out_cond_item->subtype.srv_xchange.seller_addr : (l_out_prev_cond_item ? l_out_prev_cond_item->subtype.srv_xchange.seller_addr : (dap_chain_addr_t){0});
            } else {
                l_owner_addr = *a_owner_addr;
            }
            dap_string_append_printf(a_reply_str, "owner addr: %s \n", dap_chain_addr_to_str_static(&l_owner_addr));

            dap_chain_addr_t l_buyer_addr = {};
            if(!a_buyer_addr){
                dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
                dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
                dap_enc_key_t *l_key_buyer = dap_sign_to_enc_key(l_sign);
                dap_chain_addr_fill_from_key(&l_buyer_addr, l_key_buyer, a_net->pub.id);
                dap_enc_key_delete(l_key_buyer);
            } else 
                l_buyer_addr = *a_buyer_addr;
            dap_string_append_printf(a_reply_str, "buyer addr: %s \n", dap_chain_addr_to_str_static(&l_buyer_addr));

        } break;
        case TX_TYPE_INVALIDATE:{
            dap_chain_tx_in_cond_t * l_in_cond = (dap_chain_tx_in_cond_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND , NULL);
            char l_tx_prev_cond_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_in_cond->header.tx_prev_hash,l_tx_prev_cond_hash_str, sizeof(l_tx_prev_cond_hash_str));

            if (!l_out_prev_cond_item) {
                log_it(L_ERROR, "Can't find previous transaction");
                return false;
            }

            dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_in_cond->header.tx_prev_hash);
            if (!l_prev_tx)
                return false;

            int l_out_num = l_in_cond->header.tx_out_prev_idx;
            dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_out_num);
            if (!l_out_cond) {
                log_it(L_ERROR, "Can't find datum tx");
                return false;
            }
            dap_hash_fast_t l_order_hash = dap_ledger_get_first_chain_tx_hash(a_net->pub.ledger, a_tx, l_out_cond->header.subtype);
            if ( dap_hash_fast_is_blank(&l_order_hash) )
                l_order_hash = l_in_cond->header.tx_prev_hash;

            char *l_value_from_str = dap_chain_balance_to_coins(l_out_prev_cond_item->header.value);
            char *l_value_from_datoshi_str = dap_chain_balance_print(l_out_prev_cond_item->header.value);

            dap_string_append_printf(a_reply_str, "Hash: %s\n", l_tx_hash_str);
            if(a_print_ts){
                char l_tmp_buf[DAP_TIME_STR_SIZE];
                dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, a_tx->header.ts_created);
                dap_string_append_printf(a_reply_str, "  ts_created: %s", l_tmp_buf);
            }
            if (a_print_status)
                dap_string_append_printf(a_reply_str, "  Status: inactive,");

            char l_order_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_order_hash, l_order_hash_str, sizeof(l_order_hash_str));
            dap_string_append_printf(a_reply_str, "  returned %s(%s) %s to owner from order %s\n", l_value_from_str, l_value_from_datoshi_str, l_tx_input_ticker, l_order_hash_str);
            if(a_print_prev_hash)
                dap_string_append_printf(a_reply_str, "\n  Prev cond: %s", l_tx_prev_cond_hash_str);

            dap_chain_addr_t l_owner_addr = {};
            if (!a_owner_addr){
                l_owner_addr = l_out_cond_item ? l_out_cond_item->subtype.srv_xchange.seller_addr : (l_out_prev_cond_item ? l_out_prev_cond_item->subtype.srv_xchange.seller_addr : (dap_chain_addr_t){0});
            } else {
                l_owner_addr = *a_owner_addr;
            }
            dap_string_append_printf(a_reply_str, "owner addr %s \n", dap_chain_addr_to_str_static(&l_owner_addr));

            DAP_DELETE(l_value_from_str);
            DAP_DELETE(l_value_from_datoshi_str);
        } break;
        default: return false;
    }

    dap_string_append_printf(a_reply_str, "\n\n");
    return true;
}
#endif

/**
 * @brief Append tx info to the reply string
 * @param a_json_out
 * @param a_net
 * @param a_tx
 */

static bool s_string_append_tx_cond_info_json(json_object * a_json_out, dap_chain_net_t *a_net, dap_chain_addr_t *a_owner_addr, dap_chain_addr_t *a_buyer_addr,
                                              dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, tx_opt_status_t a_filter_by_status,
                                              bool a_print_prev_hash, bool a_print_status, bool a_print_ts, int a_version)
{
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    const char *l_tx_hash_str = dap_chain_hash_fast_to_str_static(a_tx_hash);

    // Get input token ticker
    const char *l_tx_input_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, a_tx_hash);
    if (!l_tx_input_ticker)
        return log_it(L_WARNING, "Can't get ticker from TX %s", l_tx_hash_str), false;

    dap_chain_tx_out_cond_t *l_out_prev_cond_item = NULL, *l_out_cond_item = NULL;
    int l_cond_idx = 0;

    xchange_tx_type_t l_tx_type = dap_chain_net_srv_xchange_tx_get_type(a_net->pub.ledger, a_tx, &l_out_cond_item, &l_cond_idx, &l_out_prev_cond_item);

    bool l_is_closed = dap_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, a_tx_hash, l_cond_idx, NULL);
    if ((a_filter_by_status == TX_STATUS_ACTIVE && l_is_closed) || (a_filter_by_status == TX_STATUS_INACTIVE && !l_is_closed)
     || (a_filter_by_status == TX_STATUS_ACTIVE && l_tx_type == TX_TYPE_INVALIDATE))
        return false;

    if (l_out_prev_cond_item && l_out_prev_cond_item->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE)
        return false;

    switch(l_tx_type){
        case TX_TYPE_ORDER:{
            if (!l_out_cond_item)
                return log_it(L_ERROR, "Can't find conditional output in TX %s", l_tx_hash_str), false;

            json_object_object_add(a_json_out, "hash", json_object_new_string(l_tx_hash_str));
            if (a_print_ts){
                char l_tmp_buf[DAP_TIME_STR_SIZE];
                dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, a_tx->header.ts_created);
                json_object_object_add(a_json_out, "ts_created", json_object_new_string(l_tmp_buf));
            }
            if (a_print_status)
                json_object_object_add(a_json_out, "status", json_object_new_string(l_is_closed ? "inactive" : "active"));

            const char *l_rate_str, *l_amount_str, *l_amount_datoshi_str = dap_uint256_to_char(l_out_cond_item->header.value, &l_amount_str);
            json_object_object_add(a_json_out, "proposed_coins", json_object_new_string(l_amount_str));
            json_object_object_add(a_json_out, "proposed_datoshi", json_object_new_string(l_amount_datoshi_str));
            json_object_object_add(a_json_out, "ticker", json_object_new_string(l_tx_input_ticker));
            json_object_object_add(a_json_out, "buy_token", json_object_new_string(l_out_cond_item->subtype.srv_xchange.buy_token));
            dap_uint256_to_char(l_out_cond_item->subtype.srv_xchange.rate, &l_rate_str);
            json_object_object_add(a_json_out, "rate", json_object_new_string(l_rate_str));
            json_object_object_add(a_json_out, "net", json_object_new_string(a_net->pub.name));
            dap_chain_addr_t l_owner_addr = a_owner_addr ? *a_owner_addr :
                l_out_cond_item ? l_out_cond_item->subtype.srv_xchange.seller_addr :
                    l_out_prev_cond_item ? l_out_prev_cond_item->subtype.srv_xchange.seller_addr : (dap_chain_addr_t){ };
            json_object_object_add(a_json_out, "owner_addr", json_object_new_string(dap_chain_addr_to_str_static(&l_owner_addr)));
        } break;
        case TX_TYPE_EXCHANGE:{
            dap_chain_tx_in_cond_t *l_in_cond 
                = (dap_chain_tx_in_cond_t*)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND , NULL);
            char *l_tx_prev_cond_hash_str = dap_hash_fast_to_str_static(&l_in_cond->header.tx_prev_hash);

            if (!l_out_prev_cond_item)
                return log_it(L_ERROR, "Can't find previous cond item for tx %s", l_tx_hash_str), false;

            uint256_t l_rate = l_out_cond_item 
                ? l_out_cond_item->subtype.srv_xchange.rate
                : l_out_prev_cond_item->subtype.srv_xchange.rate,
                     l_value_from = {}, l_value_to = {};

            if (l_out_cond_item)
                SUBTRACT_256_256(l_out_prev_cond_item->header.value, l_out_cond_item->header.value, &l_value_from);
            else
                l_value_from = l_out_prev_cond_item->header.value;
            MULT_256_COIN(l_value_from, l_rate, &l_value_to);

            char *l_buy_ticker = l_out_cond_item 
                ? l_out_cond_item->subtype.srv_xchange.buy_token
                : l_out_prev_cond_item->subtype.srv_xchange.buy_token;

            json_object_object_add(a_json_out, "hash", json_object_new_string(l_tx_hash_str));
            if(a_print_ts){
                char l_tmp_buf[DAP_TIME_STR_SIZE];
                dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, a_tx->header.ts_created);
                json_object_object_add(a_json_out, "ts_created", json_object_new_string(l_tmp_buf));
            }
            if(a_print_status)
                json_object_object_add(a_json_out, "status", json_object_new_string(l_is_closed ? "inactive" : "active"));
            
            const char *l_value_from_str, *l_value_from_datoshi_str = dap_uint256_to_char(l_value_from, &l_value_from_str);
            json_object_object_add(a_json_out, "changed_coins", json_object_new_string(l_value_from_str));
            json_object_object_add(a_json_out, "changed_datoshi", json_object_new_string(l_value_from_datoshi_str));
            json_object_object_add(a_json_out, "ticker", json_object_new_string(l_tx_input_ticker));

            const char *l_value_to_str, *l_value_to_datoshi_str = dap_uint256_to_char(l_value_to, &l_value_to_str);
            json_object_object_add(a_json_out, "for_coins", json_object_new_string(l_value_to_str));
            json_object_object_add(a_json_out, "for_datoshi", json_object_new_string(l_value_to_datoshi_str));
            json_object_object_add(a_json_out, "ticker", json_object_new_string(l_buy_ticker));

            const char *l_rate_str; dap_uint256_to_char(l_rate, &l_rate_str);
            json_object_object_add(a_json_out, "rate", json_object_new_string(l_rate_str));

            const char *l_amount_str = NULL,
                 *l_amount_datoshi_str = l_out_cond_item ? dap_uint256_to_char(l_out_cond_item->header.value, &l_amount_str) : "0";
            json_object_object_add(a_json_out, "remain_coins", json_object_new_string(l_amount_str ? l_amount_str : "0.0"));
            json_object_object_add(a_json_out, "remain_datoshi", json_object_new_string(l_amount_datoshi_str));
            json_object_object_add(a_json_out, "ticker", json_object_new_string(l_tx_input_ticker));
            json_object_object_add(a_json_out, "net", json_object_new_string(a_net->pub.name));
            if (a_print_prev_hash)
                json_object_object_add(a_json_out, "prev_tx", json_object_new_string(l_tx_prev_cond_hash_str));
            
            dap_chain_addr_t l_owner_addr = a_owner_addr ? *a_owner_addr :
                l_out_cond_item ? l_out_cond_item->subtype.srv_xchange.seller_addr :
                    l_out_prev_cond_item ? l_out_prev_cond_item->subtype.srv_xchange.seller_addr : (dap_chain_addr_t){ };
            json_object_object_add(a_json_out, "owner_addr", json_object_new_string(dap_chain_addr_to_str_static(&l_owner_addr)));
            dap_chain_addr_t l_buyer_addr;
            if (a_buyer_addr)
                l_buyer_addr = *a_buyer_addr;
            else {
                dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t*)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL));
                dap_enc_key_t *l_key_buyer = dap_sign_to_enc_key(l_sign);
                dap_chain_addr_fill_from_key(&l_buyer_addr, l_key_buyer, a_net->pub.id);
                dap_enc_key_delete(l_key_buyer);
            }
            json_object_object_add(a_json_out, "buyer_addr", json_object_new_string(dap_chain_addr_to_str_static(&l_buyer_addr)));
        } break;
        case TX_TYPE_INVALIDATE:{
            dap_chain_tx_in_cond_t * l_in_cond = (dap_chain_tx_in_cond_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND , NULL);
            char l_tx_prev_cond_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_in_cond->header.tx_prev_hash,l_tx_prev_cond_hash_str, sizeof(l_tx_prev_cond_hash_str));

            if (!l_out_prev_cond_item)
                return log_it(L_ERROR, "Can't find previous cond item for tx %s", l_tx_hash_str), false;

            dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_in_cond->header.tx_prev_hash);
            if (!l_prev_tx)
                return false;

            int l_out_num = l_in_cond->header.tx_out_prev_idx;
            dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_out_num);
            if (!l_out_cond)
                return log_it(L_ERROR, "Can't find OUT_COND in prev tx"), false;

            dap_hash_fast_t l_order_hash = dap_ledger_get_first_chain_tx_hash(a_net->pub.ledger, a_tx, l_out_cond->header.subtype);
            if ( dap_hash_fast_is_blank(&l_order_hash) )
                l_order_hash = l_in_cond->header.tx_prev_hash;

            json_object_object_add(a_json_out, "hash", json_object_new_string(l_tx_hash_str));
            if(a_print_ts){
                char l_tmp_buf[DAP_TIME_STR_SIZE];
                dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, a_tx->header.ts_created);
                json_object_object_add(a_json_out, "ts_created", json_object_new_string(l_tmp_buf));
            }
            if (a_print_status)
                json_object_object_add(a_json_out, "status", json_object_new_string("inactive"));

            const char *l_value_from_str, *l_value_from_datoshi_str = dap_uint256_to_char(l_out_prev_cond_item->header.value, &l_value_from_str);
            json_object_object_add(a_json_out, "returned_coins", json_object_new_string(l_value_from_str));
            json_object_object_add(a_json_out, "returned_datoshi", json_object_new_string(l_value_from_datoshi_str));
            json_object_object_add(a_json_out, "ticker", json_object_new_string(l_tx_input_ticker));
            json_object_object_add(a_json_out, "order_hash", json_object_new_string( dap_hash_fast_to_str_static(&l_order_hash) ));
            if(a_print_prev_hash)
                json_object_object_add(a_json_out, a_version == 1 ? "prev cond hash" : "prev_cond_hash", json_object_new_string(l_tx_prev_cond_hash_str));
            dap_chain_addr_t l_owner_addr = a_owner_addr ? *a_owner_addr :
                l_out_cond_item ? l_out_cond_item->subtype.srv_xchange.seller_addr :
                    l_out_prev_cond_item ? l_out_prev_cond_item->subtype.srv_xchange.seller_addr : (dap_chain_addr_t){ };
            json_object_object_add(a_json_out, "owner_addr", json_object_new_string(dap_chain_addr_to_str_static(&l_owner_addr)));
        } break;
        default:
            return false;
    }
    return true;
}


static int s_cli_srv_xchange_tx_list_addr_json(dap_chain_net_t *a_net, dap_time_t a_after, dap_time_t a_before,
                                          dap_chain_addr_t *a_addr, int a_opt_status, json_object* json_obj_out, int a_version)
{
    dap_chain_hash_fast_t l_tx_first_hash = {0};    
    size_t l_tx_total;

    memset(&l_tx_first_hash, 0, sizeof(dap_chain_hash_fast_t));             /* Initial hash == zero */
    json_object* json_arr_datum_out = json_object_new_array();

    size_t l_tx_count = 0;
    dap_hash_fast_t l_hash_curr = {};
    bool l_from_wallet_cache = dap_chain_wallet_cache_tx_find(a_addr, NULL, NULL, &l_hash_curr, NULL) == 0 ? true : false;
    l_hash_curr = (dap_hash_fast_t){0};

    if(!l_from_wallet_cache){  
        dap_chain_datum_tx_t *l_datum_tx = NULL;
        for (l_tx_total = 0;
                (l_datum_tx = dap_ledger_tx_find_by_addr(a_net->pub.ledger, NULL, a_addr, &l_hash_curr, false));
                    l_tx_total++)
        {
            /* Check time range (if need ) */
            if ( a_after && !(l_datum_tx->header.ts_created > a_after) )
                continue;

            if ( a_before && (l_datum_tx->header.ts_created > a_before) )
                continue;

            json_object* json_obj_tx = json_object_new_object();
            if (s_string_append_tx_cond_info_json(json_obj_tx, a_net, NULL, NULL, l_datum_tx, &l_hash_curr, a_opt_status, false, true, true, a_version)) {
                json_object_array_add(json_arr_datum_out, json_obj_tx);
                l_tx_count++;
            }
        }
    } else {
        int l_ret_code = 0;
        dap_chain_wallet_cache_iter_t *l_iter = dap_chain_wallet_cache_iter_create(*a_addr);
        if(!l_iter){
            log_it(L_ERROR, "Can't create iterator item for wallet %s", dap_chain_addr_to_str_static(a_addr));
            return -1;
        }
        for(dap_chain_datum_tx_t *l_datum_tx = dap_chain_wallet_cache_iter_get(l_iter, DAP_CHAIN_WALLET_CACHE_GET_FIRST);
            l_datum_tx; l_datum_tx = dap_chain_wallet_cache_iter_get(l_iter, DAP_CHAIN_WALLET_CACHE_GET_NEXT))
        {
            if (l_iter->ret_code != 0)
                continue; 
            /* Check time range (if need ) */
            if ( a_after && !(l_datum_tx->header.ts_created > a_after) )
                continue;

            if ( a_before && (l_datum_tx->header.ts_created > a_before) )
                continue;
            json_object* json_obj_tx = json_object_new_object();
            if (s_string_append_tx_cond_info_json(json_obj_tx, a_net, NULL, NULL, l_datum_tx, l_iter->cur_hash, a_opt_status, false, true, true, a_version)) {
                json_object_array_add(json_arr_datum_out, json_obj_tx);
                l_tx_count++;
            }
        }
        dap_chain_wallet_cache_iter_delete(l_iter);
    }

    json_object_object_add(json_obj_out, "transactions", json_arr_datum_out);
    if (a_version == 1) {
        char *l_transactions = dap_strdup_printf("\nFound %zu transactions", l_tx_count);
        json_object_object_add(json_obj_out, "number of transactions", json_object_new_string(l_transactions));
        DAP_DELETE(l_transactions);                 /* Free string descriptor, but keep ASCIZ buffer itself */
    } else {
        json_object_object_add(json_obj_out, "total_tx_count", json_object_new_uint64(l_tx_count)); 
    }
    return  0;
}

void s_tx_is_order_check(UNUSED_ARG dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_tx, UNUSED_ARG dap_hash_fast_t *a_tx_hash, void *a_arg)
{
    dap_list_t **l_tx_list_ptr = a_arg;
    if ( dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, NULL) &&
        !dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL)){

        xchange_tx_list_t *l_list_item = DAP_NEW_Z(xchange_tx_list_t);
        l_list_item->hash = *a_tx_hash;
        l_list_item->tx = a_tx;
        *l_tx_list_ptr = dap_list_append(*l_tx_list_ptr, l_list_item);
    }
       
}

static int s_cli_srv_xchange(int a_argc, char **a_argv, void **a_str_reply, int a_version)
{
    json_object **json_arr_reply = (json_object **)a_str_reply;

    enum {CMD_NONE = 0, CMD_ORDER, CMD_ORDERS, CMD_PURCHASE, CMD_ENABLE, CMD_DISABLE, CMD_TX_LIST, CMD_TOKEN_PAIR };
    int l_arg_index = 1, l_cmd_num = CMD_NONE;

    if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "order", NULL)) {
        l_cmd_num = CMD_ORDER;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "orders", NULL)) {
        l_cmd_num = CMD_ORDERS;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "purchase", NULL)) {
        l_cmd_num = CMD_PURCHASE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "enable", NULL)) {
        l_cmd_num = CMD_ENABLE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "disable", NULL)) {
        l_cmd_num = CMD_DISABLE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "tx_list", NULL)) {
        l_cmd_num = CMD_TX_LIST;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "token_pair", NULL)) {
        l_cmd_num = CMD_TOKEN_PAIR;
    }


    switch (l_cmd_num) {
        case CMD_ORDER: {
            int res = s_cli_srv_xchange_order(a_argc, a_argv, l_arg_index + 1, json_arr_reply, a_version);
            return res;
        }
        case CMD_ORDERS: {
            const char *l_net_str = NULL;
            const char *l_status_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_REQ_PARAM_NET_ERR, "Command 'orders' requires parameter -net");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_REQ_PARAM_NET_ERR;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_NET_NOT_FOUND_ERR, "Network %s not found", l_net_str);
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_NET_NOT_FOUND_ERR;
            }
       
            dap_list_t *l_list = NULL;
            if (s_xchange_cache_state == XCHANGE_CACHE_ENABLED){
                xchange_orders_cache_net_t* l_cache = NULL;
                dap_list_t *l_tx_cache_list = NULL;
                l_cache = s_get_xchange_cache_by_net_id(l_net->pub.id);
                xchange_tx_cache_t* l_temp, *l_item;
                HASH_ITER(hh, l_cache->cache, l_item, l_temp){
                    if (l_item->tx_type == TX_TYPE_ORDER)
                        l_tx_cache_list = dap_list_append(l_tx_cache_list, l_item);
                }
                l_list = l_tx_cache_list;
            } else {
                dap_list_t *l_tx_list = NULL;
                dap_chain_net_get_tx_all(l_net, TX_SEARCH_TYPE_NET, s_tx_is_order_check, &l_tx_list);
                l_list = l_tx_list;
            }

            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-status", &l_status_str);

            /* Validate input arguments ... */
            int l_opt_status = 0;   /* 0 - all */

            if ( l_status_str )
            {
                /* 1 - closed, 2 - open  */
                if ( dap_strcmp (l_status_str, "opened") == 0 )
                    l_opt_status = 1;
                else if ( dap_strcmp (l_status_str, "closed") == 0 )
                    l_opt_status = 2;
                else if ( dap_strcmp (l_status_str, "all") == 0 )
                    l_opt_status = 0;
                else  {
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_UNREC_STATUS_ERR, "Unrecognized '-status %s'", l_status_str);
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_UNREC_STATUS_ERR;
                }
            }

            const char * l_token_from_str = NULL;
            const char * l_token_to_str = NULL;
            const char * l_head_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_from", &l_token_from_str);
            if(l_token_from_str){
                dap_chain_datum_token_t * l_token_from_datum = dap_ledger_token_ticker_check( l_net->pub.ledger, l_token_from_str);
                if(!l_token_from_datum){
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CANT_FIND_TOKEN_FROM_ERR, 
                                            "Can't find \"%s\" token in network \"%s\" for argument '-token_from' ", l_token_from_str, l_net->pub.name);
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CANT_FIND_TOKEN_FROM_ERR;
                }
            }

            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_to", &l_token_to_str);
            if(l_token_to_str){
                dap_chain_datum_token_t * l_token_to_datum = dap_ledger_token_ticker_check( l_net->pub.ledger, l_token_to_str);
                if(!l_token_to_datum){
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CANT_FIND_TOKEN_TO_ERR, 
                                            "Can't find \"%s\" token in network \"%s\" for argument '-token_to' ", l_token_to_str, l_net->pub.name);
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_CANT_FIND_TOKEN_TO_ERR;
                }
            }

            bool l_head = dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-head", &l_head_str) ? true : false;
            
            dap_chain_addr_t *l_addr = NULL;
            const char *l_addr_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-addr", &l_addr_str);
            if (l_addr_str) 
                l_addr = dap_chain_addr_from_str(l_addr_str);

            uint64_t l_printed_orders_count = 0;
            const char *l_limit_str = NULL;
            const char *l_offset_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-limit", &l_limit_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-offset", &l_offset_str);
            size_t l_limit = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 1000;
            size_t l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;
            size_t l_arr_start = 0;            
            size_t l_arr_end = 0;
            json_object* json_obj_order = json_object_new_object();
            json_object* json_arr_orders_out = json_object_new_array();
            dap_chain_set_offset_limit_json(json_arr_orders_out, &l_arr_start, &l_arr_end, l_limit, l_offset, dap_list_length(l_list),true);
            size_t i_tmp = 0;

            // Print all txs
            for (dap_list_t *it = l_head ? dap_list_last(l_list) : dap_list_first(l_list);
                    it; it = l_head ? it->prev : it->next) {
                dap_chain_datum_tx_t *l_tx = NULL;
                char l_buy_token[DAP_CHAIN_TICKER_SIZE_MAX] = {0};
                char l_sell_token[DAP_CHAIN_TICKER_SIZE_MAX] = {0};
                uint256_t l_rate = uint256_0;
                char* l_status_order_str = NULL;
                dap_chain_net_srv_xchange_order_status_t l_order_status = XCHANGE_ORDER_STATUS_UNKNOWN;
                dap_hash_fast_t l_tx_hash = {};
                uint64_t l_percent_completed = 0;
                char *l_owner_addr = NULL;
                uint256_t l_amount = {}, l_proposed;
                const char *l_amount_coins_str = NULL, *l_amount_datoshi_str = NULL, 
                        *l_proposed_coins_str = NULL, *l_proposed_datoshi_str = NULL;

                if (s_xchange_cache_state == XCHANGE_CACHE_ENABLED){
                    xchange_tx_cache_t *l_item = (xchange_tx_cache_t*)it->data;
                    if (l_item->tx_type != TX_TYPE_ORDER)
                        continue;

                    if (l_addr && dap_chain_addr_compare(&l_item->seller_addr, l_addr) == 0)
                        continue;
                    
                    l_owner_addr = dap_strdup(dap_chain_addr_to_str(&l_item->seller_addr));
                    l_tx = l_item->tx;
                    l_tx_hash = l_item->hash;
                    memcpy(l_buy_token, l_item->buy_token, strlen(l_item->buy_token));
                    memcpy(l_sell_token, l_item->sell_token, strlen(l_item->sell_token));
                    l_order_status = l_item->tx_info.order_info.order_status;
                    l_rate = l_item->rate;
                    l_amount = l_item->tx_info.order_info.value_ammount;
                    l_proposed = l_item->tx_info.order_info.value;
                    l_percent_completed = l_item->tx_info.order_info.percent_completed;
                } else {
                    xchange_tx_list_t *l_tx_item = (xchange_tx_list_t*)it->data;
                    l_tx = l_tx_item->tx;
                    l_tx_hash = l_tx_item->hash;
                    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE , NULL);
                    if (!l_out_cond || l_out_cond->header.srv_uid.uint64 != DAP_CHAIN_NET_SRV_XCHANGE_ID)
                        continue;

                    dap_chain_net_srv_xchange_price_t * l_price = NULL;
                    l_price = s_xchange_price_from_order(l_net, l_tx, &l_tx_hash, NULL, true);
                    if( !l_price ){
                        log_it(L_WARNING,"Can't create price from order");
                        continue;
                    }

                    if(l_addr && dap_chain_addr_compare(&l_price->creator_addr, l_addr) == 0)
                        continue;

                    memcpy(l_buy_token, l_price->token_buy, strlen(l_price->token_buy));
                    memcpy(l_sell_token, l_price->token_sell, strlen(l_price->token_sell));

                    dap_ledger_t * l_ledger = dap_ledger_by_net_name(l_net->pub.name);
                    
                    dap_hash_fast_t l_last_tx_hash = dap_ledger_get_final_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_price->tx_hash, false);
                    if ( dap_hash_fast_is_blank(&l_last_tx_hash) ) {
                        log_it(L_WARNING,"Can't get last tx cond hash from order");
                        continue;
                    }

                    dap_chain_datum_tx_t * l_last_tx = dap_ledger_tx_find_by_hash(l_ledger, &l_last_tx_hash);
                    if(!l_last_tx){
                        log_it(L_WARNING,"Can't find last tx");
                        continue;
                    }

                    dap_chain_tx_out_cond_t *l_out_cond_last_tx = dap_chain_datum_tx_out_cond_get(l_last_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE , NULL);
                    if (!l_out_cond_last_tx || IS_ZERO_256(l_out_cond_last_tx->header.value)){
                        if (l_opt_status == 1)
                            continue;
                        l_order_status  = XCHANGE_ORDER_STATUS_CLOSED;
                    } else {
                        if (l_opt_status == 2)
                            continue;
                        l_order_status = XCHANGE_ORDER_STATUS_OPENED;
                    }

                    l_rate = l_price->rate;
                    l_percent_completed = dap_chain_net_srv_xchange_get_order_completion_rate(l_net, l_tx_hash);
                    l_amount = l_out_cond_last_tx ? l_out_cond_last_tx->header.value : uint256_0;
                    l_owner_addr = dap_strdup(dap_chain_addr_to_str(&l_price->creator_addr));
                    l_proposed = l_price->datoshi_sell;
                    DAP_DEL_Z(l_price);
                }

                if (l_token_from_str && strcmp(l_sell_token, l_token_from_str))
                    continue;

                if (l_token_to_str && strcmp(l_buy_token, l_token_to_str))
                    continue;

                if (l_order_status == XCHANGE_ORDER_STATUS_OPENED){
                    if (l_opt_status == 2)
                        continue;
                    l_status_order_str = "OPENED";
                } else if (l_order_status == XCHANGE_ORDER_STATUS_CLOSED) {
                    if (l_opt_status == 1)
                        continue;
                    l_status_order_str = "CLOSED";
                } else {
                    continue;
                }

                if (i_tmp < l_arr_start) {
                    i_tmp++;
                    continue;
                }

                if (i_tmp >= l_arr_end) {
                    break;
                }
                i_tmp++;

                char l_tmp_buf[DAP_TIME_STR_SIZE];
                dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_tx->header.ts_created);

                json_object* l_json_obj_order = json_object_new_object();
                json_object_object_add(l_json_obj_order, "order_hash", json_object_new_string(dap_chain_hash_fast_to_str_static(&l_tx_hash)));
                json_object_object_add(l_json_obj_order, "ts_created", json_object_new_string(l_tmp_buf));
                json_object_object_add(l_json_obj_order, "status", json_object_new_string(l_status_order_str));

                l_proposed_datoshi_str = dap_uint256_to_char(l_proposed, &l_proposed_coins_str);
                json_object_object_add(l_json_obj_order, "proposed_coins", json_object_new_string(*l_proposed_coins_str ? l_proposed_coins_str : "0.0"));
                json_object_object_add(l_json_obj_order, "proposed_datoshi", json_object_new_string(*l_proposed_datoshi_str ? l_proposed_datoshi_str : "0"));
                
                l_amount_datoshi_str = dap_uint256_to_char(l_amount, &l_amount_coins_str);
                json_object_object_add(l_json_obj_order, "amount_coins", json_object_new_string(*l_amount_coins_str ? l_amount_coins_str : "0.0")); 
                json_object_object_add(l_json_obj_order, "amount_datoshi", json_object_new_string(*l_amount_datoshi_str ? l_amount_datoshi_str : "0")); 
                json_object_object_add(l_json_obj_order, "filled_percent", json_object_new_uint64(l_percent_completed));
                json_object_object_add(l_json_obj_order, "token_buy", json_object_new_string(l_buy_token));
                json_object_object_add(l_json_obj_order, "token_sell", json_object_new_string(l_sell_token));

                const char *l_cp_rate;
                dap_uint256_to_char(l_rate, &l_cp_rate);
                json_object_object_add(l_json_obj_order, "rate", json_object_new_string(l_cp_rate));

                json_object_object_add(l_json_obj_order, "net", json_object_new_string(l_net->pub.name));
                json_object_object_add(l_json_obj_order, "owner_addr", json_object_new_string(l_owner_addr));
                json_object_array_add(json_arr_orders_out, l_json_obj_order);
                DAP_DELETE(l_owner_addr);
                l_printed_orders_count++; 
                if (l_head && (it->prev->next == NULL)) break;              
            }
            json_object_object_add(json_obj_order, a_version == 1 ? "ORDERS" : "orders", json_arr_orders_out);
            json_object_array_add(*json_arr_reply, json_obj_order); 
            if (s_xchange_cache_state == XCHANGE_CACHE_ENABLED){
                dap_list_free(l_list);
            } else {
                dap_list_free_full(l_list, NULL);
            }
            if (a_version == 1) {
                char *l_total = dap_strdup_printf("Total %zu orders.\n\r", i_tmp);
                json_object_object_add(json_obj_order, "number of transactions", json_object_new_string(l_total));
                DAP_DELETE(l_total);
            } else {
                json_object_object_add(json_obj_order, a_version == 1 ? "ORDERS" : "orders", json_arr_orders_out);
                json_object_object_add(json_obj_order, "total", json_object_new_uint64(i_tmp));
                json_object_array_add(*json_arr_reply, json_obj_order);
            }

            if (!json_object_array_length(json_arr_orders_out)) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_UNREC_STATUS_ERR, "No orders found");
            }
        } break;

        case CMD_PURCHASE: {
            const char *l_net_str = NULL, *l_wallet_str = NULL, *l_order_hash_str = NULL, *l_val_buy_str = NULL, *l_val_fee_str = NULL;
            l_arg_index++;            
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_NET_ERR, "Command 'purchase' requires parameter -net");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_NET_ERR;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_NET_NOT_FOUND_ERR, "Network %s not found", l_net_str);
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_NET_NOT_FOUND_ERR;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_str);
            if (!l_wallet_str) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_W_ERR, "Command 'purchase' requires parameter -w");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_W_ERR;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
            if (!l_wallet) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_WALLET_NOT_FOUND_ERR, "Specified wallet not found");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_WALLET_NOT_FOUND_ERR;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_ORDER_ERR, 
                                            "Command 'purchase' requires parameter -order");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_ORDER_ERR;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_val_buy_str);
            if (!l_val_buy_str) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_VALUE_ERR, 
                                            "Command 'purchase' requires parameter -value");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_VALUE_ERR;
            }
            uint256_t l_datoshi_buy = dap_chain_balance_scan(l_val_buy_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_val_fee_str);
            if (!l_val_fee_str) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_FEE_ERR, 
                                            "Command 'purchase' requires parameter -fee");
                return  -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_REQ_PARAM_FEE_ERR;
            }
            uint256_t  l_datoshi_fee = dap_chain_balance_scan(l_val_fee_str);
            dap_hash_fast_t l_tx_hash = {};
            dap_chain_hash_fast_from_str(l_order_hash_str, &l_tx_hash);
            char *l_str_ret_hash = NULL;
            int l_ret_code = dap_chain_net_srv_xchange_purchase(l_net, &l_tx_hash, l_datoshi_buy, l_datoshi_fee,
                                                                l_wallet, &l_str_ret_hash);
            switch (l_ret_code) {
                case XCHANGE_PURCHASE_ERROR_OK: {
                    json_object* json_obj_orders = json_object_new_object();
                    json_object_object_add(json_obj_orders, "status", json_object_new_string("Exchange transaction has done"));
                    json_object_object_add(json_obj_orders, "hash", json_object_new_string(l_str_ret_hash));
                    json_object_array_add(*json_arr_reply, json_obj_orders);
                    DAP_DELETE(l_str_ret_hash);
                    return 0;
                }
                case XCHANGE_PURCHASE_ERROR_SPECIFIED_ORDER_NOT_FOUND: {
                    dap_json_rpc_error_add(*json_arr_reply, XCHANGE_PURCHASE_ERROR_SPECIFIED_ORDER_NOT_FOUND,"Specified order not found");
                    return -XCHANGE_PURCHASE_ERROR_SPECIFIED_ORDER_NOT_FOUND;
                }
                case XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_PRICE: {
                    dap_json_rpc_error_add(*json_arr_reply, XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_PRICE, "Can't create price from order");
                    return -XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_PRICE;
                }
                case XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_EXCHANGE_TX: {
                    dap_json_rpc_error_add(*json_arr_reply, XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_EXCHANGE_TX, "Exchange transaction error");
                    return -XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_EXCHANGE_TX;
                }
                default: {
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_UNKNOWN_ERR, 
                                                                "An error occurred with an unknown code: %d.", l_ret_code);
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PURCHASE_UNKNOWN_ERR;
                }
            }
        } break;
        case CMD_ENABLE: {
            json_object* json_obj_orders_enable = json_object_new_object();
            s_srv_xchange->enabled = true;
            json_object_object_add(json_obj_orders_enable, "status", json_object_new_string("enable"));
            json_object_array_add(*json_arr_reply, json_obj_orders_enable);
        } break;
        case CMD_DISABLE: {
            json_object* json_obj_orders_enable = json_object_new_object();
            s_srv_xchange->enabled = false;
            json_object_object_add(json_obj_orders_enable, "status", json_object_new_string("disable"));
            json_object_array_add(*json_arr_reply, json_obj_orders_enable);
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
            l_opt_status = TX_STATUS_ALL;   /* 0 - all */

            if ( l_status_str )
            {
                /* 1 - closed, 2 - open  */
                if ( dap_strcmp (l_status_str, "inactive") == 0 )
                    l_opt_status = TX_STATUS_INACTIVE;
                else if ( dap_strcmp (l_status_str, "active") == 0 )
                    l_opt_status = TX_STATUS_ACTIVE;
                else if ( dap_strcmp (l_status_str, "all") == 0 )
                    l_opt_status = TX_STATUS_ALL;
                else  {
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_LIST_UNREC_STATUS_ERR, 
                                                                "Unrecognized '-status %s'", l_status_str);
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_LIST_UNREC_STATUS_ERR;
                }
            }

            if(!l_net_str) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_LIST_REQ_PARAM_NET_ERR, 
                                                                "Command 'tx_list' requires parameter -net");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_LIST_REQ_PARAM_NET_ERR;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if(!l_net) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_LIST_NET_NOT_FOUND_ERR, 
                                                                "Network %s not found", l_net_str);
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_LIST_NET_NOT_FOUND_ERR;
            }

            dap_time_t l_time[2];
            l_time[0] = dap_time_from_str_rfc822(l_time_begin_str);
            l_time[1] = dap_time_from_str_rfc822(l_time_end_str);

            /* Dispatch request processing to ... */
            if ( l_addr_str )
            {
                if ( !(l_addr = dap_chain_addr_from_str(l_addr_str)) ) {
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_ORDRS_LIST_CAN_NOT_CONVERT_ERR,
                                           "Cannot convert -addr '%s' to internal representative", l_addr_str);
                    return -EINVAL;
                }
                json_object* json_obj_order = json_object_new_object();
                s_cli_srv_xchange_tx_list_addr_json(l_net, l_time[0], l_time[1], l_addr, l_opt_status, json_obj_order, a_version);
                json_object_array_add(*json_arr_reply, json_obj_order);
                return 0;
            }

            // Find transactions using filter function s_filter_tx_list()
            if (s_xchange_cache_state == XCHANGE_CACHE_ENABLED){
                xchange_orders_cache_net_t* l_cache = NULL;
                dap_list_t *l_tx_cache_list = NULL;
                json_object* json_arr_bl_out = json_object_new_array();                
                l_cache = s_get_xchange_cache_by_net_id(l_net->pub.id);
                xchange_tx_cache_t* l_temp, *l_item;
                HASH_ITER(hh, l_cache->cache, l_item, l_temp){
                    if (l_time[0] && l_item->tx->header.ts_created < l_time[0])
                        continue;

                    if (l_time[1] && l_item->tx->header.ts_created > l_time[1])
                        break;
                    json_object* json_obj_order = json_object_new_object();
                    if (s_string_append_tx_cond_info_json(json_obj_order, l_net,  &l_item->seller_addr, 
                            l_item->tx_type == TX_TYPE_EXCHANGE ?  &l_item->tx_info.exchange_info.buyer_addr : NULL,
                            l_item->tx, &l_item->hash, l_opt_status, false, true, true, a_version)){

                        json_object_array_add(json_arr_bl_out, json_obj_order);
                        l_show_tx_nr++;
                    }
                }
                json_object_array_add(*json_arr_reply, json_arr_bl_out);
            } else {
                dap_list_t *l_datum_list0 = dap_chain_datum_list(l_net,  NULL, s_filter_tx_list, l_time);
                size_t l_datum_num = dap_list_length(l_datum_list0);
                json_object* json_arr_bl_out = json_object_new_array(); 
                if (l_datum_num > 0) {
                    dap_list_t *l_datum_list = l_datum_list0;
                    while(l_datum_list) {
                        dap_chain_datum_tx_t *l_datum_tx = (dap_chain_datum_tx_t*) ((dap_chain_datum_t*) l_datum_list->data)->data;
                        if (l_time[0] && l_datum_tx->header.ts_created < l_time[0])
                            continue;

                        if (l_time[1] && l_datum_tx->header.ts_created > l_time[1])
                            break;
                        json_object* json_obj_order = json_object_new_object();
                        dap_hash_fast_t l_hash = {};
                        dap_hash_fast(l_datum_tx, dap_chain_datum_tx_get_size(l_datum_tx), &l_hash);
                        if (s_string_append_tx_cond_info_json(json_obj_order, l_net, NULL, NULL, l_datum_tx, &l_hash, l_opt_status, false, true, true, a_version)) {
                            json_object_array_add(json_arr_bl_out, json_obj_order);
                            l_show_tx_nr++;
                        }
                        l_datum_list = dap_list_next(l_datum_list);
                    } 
                    json_object_array_add(*json_arr_reply, json_arr_bl_out);
                }
                dap_list_free_full(l_datum_list0, NULL);
            }
            json_object* json_obj_orders = json_object_new_object();
            if (a_version == 1) {
                if(l_show_tx_nr)
                    json_object_object_add(json_obj_orders, "number of transactions", json_object_new_int(l_show_tx_nr));
                else
                    json_object_object_add(json_obj_orders, "number of transactions", json_object_new_string("Transactions not found"));
            } else {
                json_object_object_add(json_obj_orders, "total_tx_count", json_object_new_int(l_show_tx_nr));
            }
            json_object_array_add(*json_arr_reply, json_obj_orders);
        } break;
        // Token pair control
        case CMD_TOKEN_PAIR: {

            // Find and check the network
            const char *l_net_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if(!l_net_str) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_REQ_PARAM_NET_ERR,
                                       "Command 'token_pair' requires parameter -net");
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_REQ_PARAM_NET_ERR;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if(!l_net) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_NET_NOT_FOUND_ERR,
                                       "Network %s not found", l_net_str);
                return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_NET_NOT_FOUND_ERR;
            }

            // Select subcommands

            // check for price subcommand
            const char * l_price_subcommand = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "rate", &l_price_subcommand);
            if ( l_price_subcommand ){
                // Check for token_from
                const char * l_token_from_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_from", &l_token_from_str);
                if(!l_token_from_str){
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_TOKEN_FROM_ARG_ERR,
                                           "No argument '-token_from'");
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_TOKEN_FROM_ARG_ERR;
                }
                dap_chain_datum_token_t * l_token_from_datum = dap_ledger_token_ticker_check( l_net->pub.ledger, l_token_from_str);
                if(!l_token_from_datum){
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_TOKEN_FROM_ERR,
                                           "Can't find \"%s\" token in network \"%s\" for argument '-token_from' ", l_token_from_str, l_net->pub.name);
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_TOKEN_FROM_ERR;
                }

                // Check for token_to
                const char * l_token_to_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_to", &l_token_to_str);
                if(!l_token_to_str){
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_TOKEN_TO_ERR,
                                           "No argument '-token_to'");
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_TOKEN_TO_ERR;
                }
                dap_chain_datum_token_t * l_token_to_datum = dap_ledger_token_ticker_check( l_net->pub.ledger, l_token_to_str);
                if(!l_token_to_datum){
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_CANT_FIND_TOKEN_ERR,
                                           "Can't find \"%s\" token in network \"%s\" for argument '-token_to' ", l_token_to_str, l_net->pub.name);
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_CANT_FIND_TOKEN_ERR;
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

                    dap_list_t *l_list = NULL;
                    if (s_xchange_cache_state == XCHANGE_CACHE_ENABLED){
                        xchange_orders_cache_net_t* l_cache = NULL;
                        dap_list_t *l_tx_cache_list = NULL;
                        l_cache = s_get_xchange_cache_by_net_id(l_net->pub.id);
                        xchange_tx_cache_t* l_temp, *l_item;
                        HASH_ITER(hh, l_cache->cache, l_item, l_temp){
                            if (l_item->tx_type != TX_TYPE_EXCHANGE)
                                continue;

                            if (l_time_from && l_item->tx->header.ts_created < l_time_from)
                                continue;
                            
                            if (l_time_to && l_item->tx->header.ts_created > l_time_to)
                                break;

                            l_tx_cache_list = dap_list_append(l_tx_cache_list, l_item);
                        }
                        l_list = l_tx_cache_list;
                    } else {
                        dap_list_t *l_tx_list = NULL;
                        l_list = dap_chain_net_get_tx_cond_all_by_srv_uid(l_net, c_dap_chain_net_srv_xchange_uid, l_time_from,l_time_to,TX_SEARCH_TYPE_NET);
                    }


                    dap_list_t * l_cur = l_list;
                    
                    uint256_t l_total_rates = {0};
                    uint256_t l_total_rates_count = {0};
                    dap_time_t l_last_rate_time = 0;
                    uint256_t l_rate = {};
                    while(l_cur){
                        dap_chain_datum_tx_t * l_tx = NULL;
                        dap_hash_fast_t l_tx_hash = {};
                        const char * l_tx_input_ticker = NULL;
                        const char * l_tx_out_ticker = NULL;
                        uint256_t l_b_rate = {};
                        
                        if (s_xchange_cache_state == XCHANGE_CACHE_ENABLED){
                            xchange_tx_cache_t* l_item = (xchange_tx_cache_t*)l_cur->data;
                            l_tx = l_item->tx;
                            l_tx_hash = l_item->hash;
                            l_tx_input_ticker = l_item->sell_token;
                            l_tx_out_ticker = l_item->buy_token;
                            l_b_rate = l_item->rate;
                        } else {
                            dap_chain_datum_tx_cond_list_item_t *l_item = (dap_chain_datum_tx_cond_list_item_t *)l_cur->data;
                            l_tx_hash = l_item->hash;
                            l_tx = l_item->tx;
                            int l_cond_idx = 0;
                            dap_chain_tx_out_cond_t *l_out_cond_item = NULL;
                            if (dap_chain_net_srv_xchange_tx_get_type(l_net->pub.ledger, l_tx, &l_out_cond_item, &l_cond_idx, NULL) != TX_TYPE_EXCHANGE){
                                l_cur = dap_list_next(l_cur);
                                continue;
                            }
                            
                            l_tx_input_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &l_tx_hash);
                            l_tx_out_ticker = l_out_cond_item->subtype.srv_xchange.buy_token;
                            l_b_rate = l_out_cond_item->subtype.srv_xchange.rate;
                        }
                        
                        if (!l_tx_input_ticker || strcmp(l_tx_input_ticker, l_token_from_str)){
                            l_cur = dap_list_next(l_cur);
                            continue;
                        }

                        if (!l_tx_out_ticker || strcmp(l_tx_out_ticker, l_token_to_str)){
                            l_cur = dap_list_next(l_cur);
                            continue;
                        }
                      
                        l_rate = l_b_rate;
                        l_last_rate_time = l_tx->header.ts_created;
                        if(SUM_256_256(l_rate, l_total_rates, &l_total_rates )!= 0)
                            log_it(L_ERROR, "Overflow on average price calculation (summing)");
                        INCR_256(&l_total_rates_count);

                        l_cur = dap_list_next(l_cur);
                    }

                    dap_list_free(l_list);

                    if (IS_ZERO_256(l_total_rates) || IS_ZERO_256(l_rate) || !l_last_rate_time){
                        dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_CANT_FIND_ORDER_ERR,
                                       "Can't find orders for specified token pair\n");
                    } else {
                        uint256_t l_rate_average = {0};
                        if (!IS_ZERO_256(l_total_rates_count))
                            DIV_256(l_total_rates,l_total_rates_count,&l_rate_average);

                        char l_tmp_buf[DAP_TIME_STR_SIZE];
                        dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, l_last_rate_time);
                        const char *l_rate_average_str; dap_uint256_to_char(l_rate_average, &l_rate_average_str);
                        json_object* json_obj_order = json_object_new_object();
                        json_object_object_add(json_obj_order, a_version == 1 ? "Average rate" : "average_rate", json_object_new_string(l_rate_average_str));
                        const char *l_last_rate_str; dap_uint256_to_char(l_rate, &l_last_rate_str);
                        json_object_object_add(json_obj_order, a_version == 1 ? "Last rate" : "last_rate", json_object_new_string(l_last_rate_str));
                        json_object_object_add(json_obj_order, a_version == 1 ? "Last rate time" : "last_rate_time", json_object_new_string(l_tmp_buf));
                        json_object_array_add(*json_arr_reply, json_obj_order);
                    }
                    break;
                }else if (strcmp(l_price_subcommand,"history") == 0){
                    const char *l_limit_str = NULL, *l_offset_str = NULL;
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-limit", &l_limit_str);
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-offset", &l_offset_str);
                    size_t l_limit = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 1000;
                    size_t l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;

                    uint256_t l_token_from_value = {}, l_token_to_value = {};
                    dap_list_t *l_list = NULL;
                    dap_time_t l_time[2];
                    l_time[0] = l_time_from;
                    l_time[1] = l_time_to;

                    if (s_xchange_cache_state == XCHANGE_CACHE_ENABLED){
                        xchange_orders_cache_net_t* l_cache = NULL;
                        dap_list_t *l_tx_cache_list = NULL;
                        l_cache = s_get_xchange_cache_by_net_id(l_net->pub.id);
                        xchange_tx_cache_t* l_temp, *l_item;
                        HASH_ITER(hh, l_cache->cache, l_item, l_temp){
                            if (l_time_from && l_item->tx->header.ts_created < l_time_from)
                                continue;
                            
                            if (l_time_to && l_item->tx->header.ts_created > l_time_to)
                                break;

                            l_tx_cache_list = dap_list_append(l_tx_cache_list, l_item);
                        }
                        l_list = l_tx_cache_list;
                    } else {
                        dap_list_t *l_tx_list = NULL;
                        l_list = dap_chain_datum_list(l_net, NULL, s_filter_tx_list, l_time);
                    }

                    size_t l_datum_num = dap_list_length(l_list);

                    if (l_datum_num == 0){
                        dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_CANT_FIND_TX_ERR,
                                           "Can't find transactions");
                        return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_CANT_FIND_TX_ERR;
                    }
                    json_object* json_arr_bl_cache_out = json_object_new_array();
                    size_t l_arr_start = 0;
                    size_t l_arr_end  = 0;
                    dap_chain_set_offset_limit_json(json_arr_bl_cache_out, &l_arr_start, &l_arr_end, l_limit, l_offset, l_datum_num, false);
                    
                    size_t i_tmp = 0;

                    size_t l_total = 0;
                    dap_list_t * l_cur = l_list;
                    while(l_cur){
                        dap_hash_fast_t l_tx_hash = {};
                        dap_chain_datum_tx_t *l_tx = NULL;
                        const char * l_tx_sell_ticker = NULL;
                        const char * l_tx_buy_ticker = NULL;

                        uint256_t l_token_curr_from_value = {}, l_token_curr_to_value = {};

                        if (s_xchange_cache_state == XCHANGE_CACHE_ENABLED){
                            xchange_tx_cache_t* l_item = (xchange_tx_cache_t*)l_cur->data;
                            l_tx_hash = l_item->hash;
                            l_tx = l_item->tx;
                            l_tx_sell_ticker = l_item->sell_token;
                            l_tx_buy_ticker = l_item->buy_token;

                            if (l_item->tx_type == TX_TYPE_EXCHANGE){
                                l_token_curr_from_value = l_item->tx_info.exchange_info.buy_value;
                                MULT_256_COIN(l_item->rate, l_item->tx_info.exchange_info.buy_value, &l_token_curr_to_value);
                            }
                        } else {
                            l_tx = (dap_chain_datum_tx_t*) ((dap_chain_datum_t*) l_cur->data)->data;
                            if(!l_tx){
                                l_cur = dap_list_next(l_cur);
                                continue;
                            }
                            dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
                            l_tx_sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &l_tx_hash);
                            dap_chain_tx_out_cond_t *l_out_cond_item = NULL;
                            dap_chain_tx_out_cond_t *l_out_prev_cond_item = NULL;

                            xchange_tx_type_t tx_type = dap_chain_net_srv_xchange_tx_get_type(l_net->pub.ledger, l_tx, &l_out_cond_item, NULL, &l_out_prev_cond_item);
                            
                            if(!l_out_cond_item && l_out_prev_cond_item){
                                l_tx_buy_ticker = l_out_prev_cond_item->subtype.srv_xchange.buy_token;
                                if (tx_type == TX_TYPE_EXCHANGE){
                                    l_token_curr_from_value = l_out_prev_cond_item->header.value;
                                    MULT_256_COIN(l_out_prev_cond_item->subtype.srv_xchange.rate, l_out_prev_cond_item->header.value, &l_token_curr_to_value);
                                }
                            } else if (l_out_cond_item) {
                                l_tx_buy_ticker = l_out_cond_item->subtype.srv_xchange.buy_token;
                                if (tx_type == TX_TYPE_EXCHANGE){
                                    uint256_t l_b_buy_value = {};
                                    SUBTRACT_256_256(l_out_prev_cond_item->header.value, l_out_cond_item->header.value, &l_b_buy_value);
                                    l_token_curr_from_value = l_b_buy_value;
                                    MULT_256_COIN(l_out_cond_item->subtype.srv_xchange.rate, l_b_buy_value, &l_token_curr_to_value);
                                }
                            }
                        }   


                        if (!l_tx_sell_ticker || strcmp(l_tx_sell_ticker, l_token_from_str)){
                            l_cur = dap_list_next(l_cur);
                            continue;
                        }

                        if (!l_tx_buy_ticker || strcmp(l_tx_buy_ticker, l_token_to_str)){
                            l_cur = dap_list_next(l_cur);
                            continue;
                        }

                        if (i_tmp < l_arr_start) {
                            i_tmp++;
                            l_cur = dap_list_next(l_cur);
                            continue;
                        }
                        if (i_tmp >= l_arr_end)
                            break;

                        i_tmp++;  

                        json_object* json_obj_out = json_object_new_object();
                        if(s_string_append_tx_cond_info_json(json_obj_out, l_net, NULL, NULL, l_tx, &l_tx_hash, TX_STATUS_ALL, false, false, true, a_version)){
                            l_total++;
                            SUM_256_256(l_token_to_value, l_token_curr_to_value, &l_token_to_value);
                            SUM_256_256(l_token_from_value, l_token_curr_from_value, &l_token_from_value);
                            json_object_array_add(json_arr_bl_cache_out, json_obj_out);
                        }
                        l_cur = dap_list_next(l_cur);
                    }

                    json_object_array_add(*json_arr_reply, json_arr_bl_cache_out);
                    dap_list_free(l_list);
                    json_object* json_obj_order = json_object_new_object();
                    json_object_object_add(json_obj_order, "tx_count", json_object_new_uint64(l_total));

                    const char *l_token_from_value_coins_str = NULL, *l_token_from_value_datoshi_str = dap_uint256_to_char(l_token_from_value, &l_token_from_value_coins_str);
                    json_object_object_add(json_obj_order, "trading_val_from_coins", json_object_new_string(l_token_from_value_coins_str));
                    json_object_object_add(json_obj_order, "trading_val_from_datoshi", json_object_new_string(l_token_from_value_datoshi_str));

                    const char *l_token_to_value_coins_str = NULL, *l_token_to_value_datoshi_str = dap_uint256_to_char(l_token_to_value, &l_token_to_value_coins_str);
                    json_object_object_add(json_obj_order, "trading_val_to_coins", json_object_new_string(l_token_to_value_coins_str));
                    json_object_object_add(json_obj_order, "trading_val_to_datoshi", json_object_new_string(l_token_to_value_datoshi_str));
                    
                    json_object_array_add(*json_arr_reply, json_obj_order);
                    break;

                } else {
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_UNKNOWN_ERR,
                                           "Unrecognized subcommand '%s'", l_price_subcommand);                    
                    return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_PAIR_UNKNOWN_ERR;
                }
            }

            const char * l_list_subcommand = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "list", &l_list_subcommand);
            if( l_list_subcommand ){
                if (strcmp(l_list_subcommand,"all") == 0){
                    const char *l_limit_str = NULL, *l_offset_str = NULL;
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-limit", &l_limit_str);
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-offset", &l_offset_str);
                    size_t l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;
                    size_t l_limit  = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 1000;
                    
                    char ** l_tickers = NULL;
                    size_t l_tickers_count = 0;
                    dap_ledger_addr_get_token_ticker_all( l_net->pub.ledger,NULL,&l_tickers,&l_tickers_count);
                    json_object* json_obj_out = json_object_new_object();
                    size_t l_pairs_count = 0;
                    if(l_tickers){
                        size_t l_arr_start = 0;
                        size_t l_arr_end  = 0;
                        json_object* json_arr_bl_cache_out = json_object_new_array();
                        dap_chain_set_offset_limit_json(json_arr_bl_cache_out, &l_arr_start, &l_arr_end, l_limit, l_offset, l_tickers_count*l_tickers_count, false); 

                        size_t i_tmp = 0;
                        for(size_t i = 0; i< l_tickers_count; i++){
                            for(size_t j = i+1; j< l_tickers_count; j++){
                                if(l_tickers[i] && l_tickers[j] && i != j){
                                    if ((l_arr_start && i_tmp < l_arr_start) || 
                                        (l_arr_end &&i_tmp > l_arr_end)) {
                                        i_tmp++;
                                        continue;
                                    }
                                    i_tmp++;
                                    json_object* json_obj_bl = json_object_new_object();
                                    json_object_object_add(json_obj_bl, "ticker_1",json_object_new_string(l_tickers[i]));
                                    json_object_object_add(json_obj_bl, "ticker_2",json_object_new_string(l_tickers[j]));
                                    json_object_array_add(json_arr_bl_cache_out, json_obj_bl);
                                    l_pairs_count++;
                                }
                            }

                        }
                        json_object_object_add(json_obj_out, a_version == 1 ? "TICKERS PAIR" : "tickers_pair", json_arr_bl_cache_out);

                        // Free tickers array
                        for(size_t i = 0; i< l_tickers_count; i++){
                            DAP_DELETE(l_tickers[i]);
                        }
                        DAP_DELETE(l_tickers);
                    }
                    json_object_object_add(json_obj_out, a_version == 1 ? "pair count" : "pair_count", json_object_new_uint64(l_pairs_count));
                    json_object_array_add(*json_arr_reply, json_obj_out);
                    break;
                }
            }

            // No subcommand selected
            json_object* json_obj_out = json_object_new_object();
            json_object_object_add(json_obj_out, a_version == 1 ? "token pair status" : "token_pair_status", json_object_new_string("Command 'token pair' requires proper subcommand," 
                                                                                        "please read its manual with command 'help srv_xchange'"));
            json_object_array_add(*json_arr_reply, json_obj_out);

        } break;

        default: {
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_UNKNOWN_COMMAND_ERR,
                                           "Command %s not recognized", a_argv[l_arg_index]);
            return -DAP_CHAIN_NODE_CLI_COM_NET_SRV_XCNGE_UNKNOWN_COMMAND_ERR;
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

json_object *dap_chain_net_srv_xchange_print_fee_json(dap_chain_net_t *a_net) {
    if (!a_net)
        return NULL;
    uint256_t l_fee = {0};
    dap_chain_addr_t l_addr = {0};
    uint16_t l_type = 0;
    if (dap_chain_net_srv_xchange_get_fee(a_net->pub.id, &l_fee, &l_addr, &l_type)) {
        const char *l_fee_coins, *l_fee_balance = dap_uint256_to_char(l_fee, &l_fee_coins);
        json_object *l_jobj_xchange = json_object_new_object();
        json_object_object_add(l_jobj_xchange, "coin",      json_object_new_string(l_fee_coins));
        json_object_object_add(l_jobj_xchange, "balance",   json_object_new_string(l_fee_balance));
        json_object_object_add(l_jobj_xchange, "addr",      json_object_new_string(dap_chain_addr_to_str_static(&l_addr)));
        json_object_object_add(l_jobj_xchange, "type",      json_object_new_string(dap_chain_net_srv_fee_type_to_str((dap_chain_net_srv_fee_type_t)l_type)));
        return l_jobj_xchange;
    } else {
        return json_object_new_string("service has not announced a commission fee");
    }
}

void dap_chain_net_srv_xchange_print_fee(dap_chain_net_t *a_net, dap_string_t *a_string_ret){
    if (!a_net || !a_string_ret)
        return;
    uint256_t l_fee = {0};
    dap_chain_addr_t l_addr = {0};
    uint16_t l_type = 0;
    if (dap_chain_net_srv_xchange_get_fee(a_net->pub.id, &l_fee, &l_addr, &l_type)) {
        const char *l_fee_coins, *l_fee_balance = dap_uint256_to_char(l_fee, &l_fee_coins);
        dap_string_append_printf(a_string_ret, "\txchange:\n"
                                               "\t\tFee: %s (%s)\n"
                                               "\t\tAddr: %s\n"
                                               "\t\tType: %s\n",
                                l_fee_coins, l_fee_balance, dap_chain_addr_to_str_static(&l_addr),
                                dap_chain_net_srv_fee_type_to_str((dap_chain_net_srv_fee_type_t)l_type));
    } else {
        dap_string_append_printf(a_string_ret, "\txchange:\n"
                                               "\t\tThe xchanger service has not announced a commission fee.\n");
    }
}

dap_list_t *dap_chain_net_srv_xchange_get_prices(dap_chain_net_t *a_net) {
    dap_list_t *l_list_prices = NULL;
    dap_list_t *l_list_tx =  dap_chain_net_get_tx_cond_all_by_srv_uid(a_net, c_dap_chain_net_srv_xchange_uid, 0, 0,TX_SEARCH_TYPE_NET);
    dap_list_t *l_temp = l_list_tx;
    while(l_temp)
    {


        // TODO: getting from cache too
        dap_chain_datum_tx_cond_list_item_t *l_item = (dap_chain_datum_tx_cond_list_item_t*)l_temp->data;
        dap_chain_net_srv_xchange_price_t *l_price = s_xchange_price_from_order(a_net, l_item->tx, &l_item->hash, NULL, true);
        if(!l_price ){
            log_it(L_WARNING,"Can't create price from order");
            l_temp = l_temp->next;
            continue;
        }
        l_list_prices = dap_list_append(l_list_prices, l_price);
        l_temp = l_temp->next;
    }
    dap_list_free(l_list_tx);
    return l_list_prices;
}

dap_chain_net_srv_xchange_create_error_t dap_chain_net_srv_xchange_create(dap_chain_net_t *a_net, const char *a_token_buy,
                                     const char *a_token_sell, uint256_t a_datoshi_sell,
                                     uint256_t a_rate, uint256_t a_fee, dap_chain_wallet_t *a_wallet,
                                     char **a_out_tx_hash){
    if (!a_net || !a_token_buy || !a_token_sell || !a_wallet || !a_out_tx_hash) {
        return XCHANGE_CREATE_ERROR_INVALID_ARGUMENT;
    }
    if (!dap_ledger_token_ticker_check(a_net->pub.ledger, a_token_sell)) {
        return XCHANGE_CREATE_ERROR_TOKEN_TICKER_SELL_IS_NOT_FOUND_LEDGER;
    }
    if (!dap_ledger_token_ticker_check(a_net->pub.ledger, a_token_buy)) {
        return XCHANGE_CREATE_ERROR_TOKEN_TICKER_BUY_IS_NOT_FOUND_LEDGER;
    }
    if (IS_ZERO_256(a_rate)) {
        return XCHANGE_CREATE_ERROR_RATE_IS_ZERO;
    }
    if (IS_ZERO_256(a_fee)) {
        return XCHANGE_CREATE_ERROR_FEE_IS_ZERO;
    }
    if (IS_ZERO_256(a_datoshi_sell)) {
        return XCHANGE_CREATE_ERROR_VALUE_SELL_IS_ZERO;
    }
    const char* l_sign_str = dap_chain_wallet_check_sign(a_wallet);
    uint256_t l_value = dap_chain_wallet_get_balance(a_wallet, a_net->pub.id, a_token_sell);
    uint256_t l_value_sell = a_datoshi_sell;
    if (!dap_strcmp(a_net->pub.native_ticker, a_token_sell)) {
        if (SUM_256_256(l_value_sell, a_fee, &l_value_sell)) {
            log_it(L_ERROR, "Integer overflow with sum of value and fee");
            return XCHANGE_CREATE_ERROR_INTEGER_OVERFLOW_WITH_SUM_OF_VALUE_AND_FEE;
        }
    } else { // sell non-native ticker
        uint256_t l_fee_value = dap_chain_wallet_get_balance(a_wallet, a_net->pub.id, a_net->pub.native_ticker);
        if (compare256(l_fee_value, a_fee) == -1) {
            return XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE_IN_SPECIFIED_WALLET;
        }
    }
    if (compare256(l_value, l_value_sell) == -1) {
        return XCHANGE_CREATE_ERROR_NOT_ENOUGH_CASH_IN_SPECIFIED_WALLET;
    }
    // Create the price
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    if (!l_price) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return XCHANGE_CREATE_ERROR_MEMORY_ALLOCATED;
    }
    dap_stpcpy(l_price->token_sell, a_token_sell);
    l_price->net = a_net;
    dap_stpcpy(l_price->token_buy, a_token_buy);
    l_price->datoshi_sell = a_datoshi_sell;
    l_price->rate = a_rate;
    l_price->fee = a_fee;
    // Create conditional transaction
    dap_chain_datum_tx_t *l_tx = s_xchange_tx_create_request(l_price, a_wallet);
    if (!l_tx) {
        DAP_DELETE(l_price);
        return XCHANGE_CREATE_ERROR_CAN_NOT_COMPOSE_THE_CONDITIONAL_TRANSACTION;
    }
    dap_hash_fast_t l_tx_hash ={};
    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
    char* l_ret = NULL;
    if(!(l_ret = s_xchange_tx_put(l_tx, a_net))) {
        DAP_DELETE(l_price);
        return XCHANGE_CREATE_ERROR_CAN_NOT_PUT_TRANSACTION_TO_MEMPOOL;
    }
    // To avoid confusion, the term "order" will apply to the original conditional exchange offer transactions.
    *a_out_tx_hash = l_ret;
    return XCHANGE_CREATE_ERROR_OK;
}

dap_chain_net_srv_xchange_remove_error_t dap_chain_net_srv_xchange_remove(dap_chain_net_t *a_net, dap_hash_fast_t *a_hash_tx, uint256_t a_fee,
                                     dap_chain_wallet_t *a_wallet, char **a_out_hash_tx) {
    if (!a_net || !a_hash_tx || !a_wallet) {
        return XCHANGE_REMOVE_ERROR_INVALID_ARGUMENT;
    }
    if(IS_ZERO_256(a_fee)){
        return XCHANGE_REMOVE_ERROR_FEE_IS_ZERO;
    }
    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, a_hash_tx);
    if (!l_cond_tx) {
        return XCHANGE_REMOVE_ERROR_CAN_NOT_FIND_TX;
    }
    dap_chain_net_srv_xchange_price_t *l_price = s_xchange_price_from_order(a_net, l_cond_tx, a_hash_tx, &a_fee, false);
    if (!l_price) {
        return XCHANGE_REMOVE_ERROR_CAN_NOT_CREATE_PRICE;
    }
    char*  l_ret = s_xchange_tx_invalidate(l_price, a_wallet);
    if (!l_ret){
        DAP_DELETE(l_price);
        return XCHANGE_REMOVE_ERROR_CAN_NOT_INVALIDATE_TX;
    }
    *a_out_hash_tx = l_ret;
    DAP_DELETE(l_price);
    return XCHANGE_REMOVE_ERROR_OK;
}

dap_chain_net_srv_xchange_purchase_error_t dap_chain_net_srv_xchange_purchase(dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash, uint256_t a_value,
                                       uint256_t a_fee, dap_chain_wallet_t *a_wallet, char **a_hash_out){
    if (!a_net || !a_order_hash || !a_wallet || !a_hash_out) {
        return XCHANGE_PURCHASE_ERROR_INVALID_ARGUMENT;
    }
    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, a_order_hash);
    if (l_cond_tx) {
        dap_chain_net_srv_xchange_price_t *l_price = s_xchange_price_from_order(a_net, l_cond_tx, a_order_hash, &a_fee, false);
        if(!l_price){
            return XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_PRICE;
        }
        // Create conditional transaction
        char *l_ret = NULL;
        dap_chain_datum_tx_t *l_tx = s_xchange_tx_create_exchange(l_price, a_wallet, a_value, a_fee);
        if (l_tx ) {
            l_ret = s_xchange_tx_put(l_tx, a_net);
        }
        DAP_DELETE(l_price);
        if (l_tx && l_ret){
            *a_hash_out = l_ret;
            return XCHANGE_PURCHASE_ERROR_OK;
        } else
            return XCHANGE_PURCHASE_ERROR_CAN_NOT_CREATE_EXCHANGE_TX;
    } else {
        return XCHANGE_PURCHASE_ERROR_SPECIFIED_ORDER_NOT_FOUND;
    }
}

static dap_hash_fast_t s_get_order_from_cache(xchange_tx_cache_t *a_cache_head, dap_hash_fast_t *a_curr_tx_hash)
{   
    dap_hash_fast_t l_prev_hash = {0};

    xchange_tx_cache_t *l_cur_cache = NULL;
    HASH_FIND(hh, a_cache_head, a_curr_tx_hash, sizeof(dap_hash_fast_t), l_cur_cache);
    if (!l_cur_cache){
        log_it(L_ERROR, "Can't find previous in cache. Hash : %s", dap_hash_fast_to_str_static(a_curr_tx_hash));
        return l_prev_hash;
    }
        

    if (l_cur_cache->tx_type == TX_TYPE_ORDER)
        return l_cur_cache->hash;
    else if (l_cur_cache->tx_type == TX_TYPE_EXCHANGE){
        l_prev_hash = l_cur_cache->tx_info.exchange_info.prev_hash;
    } else {
        l_prev_hash = l_cur_cache->tx_info.invalidate_info.prev_hash;
    }
    
    do {
        l_prev_hash = l_cur_cache->tx_info.exchange_info.prev_hash;
        HASH_FIND(hh, a_cache_head, &l_prev_hash, sizeof(dap_hash_fast_t), l_cur_cache);
    } while (l_cur_cache && l_cur_cache->tx_type != TX_TYPE_ORDER);
    
    if (l_cur_cache)
        l_prev_hash = l_cur_cache->hash;

    return l_prev_hash;
}


static void s_ledger_tx_add_notify(void *a_arg, dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, dap_chan_ledger_notify_opcodes_t a_opcode)
{
    if (a_opcode == 'a'){
        // check and add tx into cache
        dap_chain_tx_out_cond_t *l_out_cond_item = NULL;
        int l_item_idx = 0;
        dap_chain_tx_out_cond_t *l_out_prev_cond_item = NULL;
        dap_hash_fast_t l_prev_tx_hash = {};
        xchange_tx_type_t l_tx_type = dap_chain_net_srv_xchange_tx_get_type(a_ledger, a_tx, &l_out_cond_item, &l_item_idx, &l_out_prev_cond_item);
        if (l_tx_type == TX_TYPE_UNDEFINED)
            return;

        xchange_orders_cache_net_t* l_cache_net = s_get_xchange_cache_by_net_id(a_ledger->net->pub.id);
        if(!l_cache_net)
            return;

        xchange_tx_cache_t* l_cache = DAP_NEW_Z_RET_IF_FAIL(xchange_tx_cache_t);
        l_cache->hash = *a_tx_hash;
        l_cache->tx = a_tx;
        l_cache->tx_type = l_tx_type;

        const char *l_sell_token = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tx_hash);
        if (l_sell_token)
            dap_strncpy(l_cache->sell_token, l_sell_token, sizeof(l_cache->sell_token));

        dap_strncpy(l_cache->buy_token, 
                    l_out_cond_item  ?  l_out_cond_item->subtype.srv_xchange.buy_token : 
                                        l_out_prev_cond_item->subtype.srv_xchange.buy_token,
                                        sizeof(l_cache->buy_token));

        l_cache->seller_addr = l_out_cond_item ? l_out_cond_item->subtype.srv_xchange.seller_addr : (l_out_prev_cond_item ? l_out_prev_cond_item->subtype.srv_xchange.seller_addr : (dap_chain_addr_t){0});
        
        if (l_tx_type == TX_TYPE_ORDER){
            l_cache->rate = l_out_cond_item->subtype.srv_xchange.rate;
            l_cache->tx_info.order_info.order_status = XCHANGE_ORDER_STATUS_OPENED;
            l_cache->tx_info.order_info.value = l_out_cond_item->header.value;
            l_cache->tx_info.order_info.value_ammount = l_cache->tx_info.order_info.value;
            l_cache->tx_info.order_info.percent_completed = 0;
        } else if (l_tx_type == TX_TYPE_EXCHANGE){
            l_cache->rate = l_out_prev_cond_item->subtype.srv_xchange.rate;
            dap_strncpy(l_cache->buy_token, l_out_prev_cond_item->subtype.srv_xchange.buy_token, sizeof(l_cache->buy_token));
            SUBTRACT_256_256(l_out_prev_cond_item->header.value, l_out_cond_item ? l_out_cond_item->header.value : uint256_0, &l_cache->tx_info.exchange_info.buy_value);
            
            byte_t *l_tx_item = dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND , NULL);
            dap_chain_tx_in_cond_t * l_in_cond = l_tx_item ? (dap_chain_tx_in_cond_t *) l_tx_item : NULL;

            if (l_in_cond)
                l_cache->tx_info.exchange_info.prev_hash = l_in_cond->header.tx_prev_hash;
            
            l_cache->tx_info.exchange_info.order_hash = s_get_order_from_cache(l_cache_net->cache, &l_cache->tx_info.exchange_info.prev_hash);
            dap_hash_fast_is_blank(&l_cache->tx_info.exchange_info.order_hash);

            dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
            dap_enc_key_t *l_key_buyer = dap_sign_to_enc_key(l_sign);
            dap_chain_addr_fill_from_key(&l_cache->tx_info.exchange_info.buyer_addr, l_key_buyer, a_ledger->net->pub.id);
            dap_enc_key_delete(l_key_buyer);
            // find order in cache and change it state
            xchange_tx_cache_t* l_cache_order = NULL;
            HASH_FIND(hh, l_cache_net->cache, &l_cache->tx_info.exchange_info.order_hash, sizeof(dap_hash_fast_t), l_cache_order);
            if(l_cache_order){
                if (l_cache_order->tx_type == TX_TYPE_ORDER){
                    l_cache_order->tx_info.order_info.value_ammount = l_out_cond_item && !IS_ZERO_256(l_out_cond_item->header.value) ? l_out_cond_item->header.value : uint256_0;
                    if (l_out_cond_item && !IS_ZERO_256(l_out_cond_item->header.value)){
                        uint256_t l_percent_completed = {};
                        SUBTRACT_256_256(l_cache_order->tx_info.order_info.value, l_cache_order->tx_info.order_info.value_ammount, &l_percent_completed);
                        DIV_256_COIN(l_percent_completed, l_cache_order->tx_info.order_info.value, &l_percent_completed);
                        MULT_256_COIN(l_percent_completed, dap_chain_coins_to_balance("100.0"), &l_percent_completed);
                        l_cache_order->tx_info.order_info.percent_completed = dap_chain_balance_to_coins_uint64(l_percent_completed);
                    } else {
                        l_cache_order->tx_info.order_info.percent_completed = dap_chain_balance_to_coins_uint64(dap_chain_coins_to_balance("100.0"));
                    }
                    l_cache_order->tx_info.order_info.order_status = IS_ZERO_256(l_cache_order->tx_info.order_info.value_ammount) ? XCHANGE_ORDER_STATUS_CLOSED : XCHANGE_ORDER_STATUS_OPENED;
                    if (dap_hash_fast_is_blank(&l_cache_order->tx_info.order_info.next_hash))
                        l_cache_order->tx_info.order_info.next_hash = *a_tx_hash;
                }
            }

            xchange_tx_cache_t* l_cache_prev_tx = NULL;
            HASH_FIND(hh, l_cache_net->cache, &l_cache->tx_info.exchange_info.prev_hash, sizeof(dap_hash_fast_t), l_cache_prev_tx);
            if(l_cache_prev_tx){
                if (l_cache_prev_tx->tx_type == TX_TYPE_EXCHANGE){
                        l_cache_prev_tx->tx_info.exchange_info.next_hash = *a_tx_hash;
                }
            }

        } else if (l_tx_type == TX_TYPE_INVALIDATE){
            l_cache->rate = l_out_prev_cond_item->subtype.srv_xchange.rate;
            dap_strncpy(l_cache->buy_token, l_out_prev_cond_item->subtype.srv_xchange.buy_token, sizeof(l_cache->buy_token));
            l_cache->tx_info.invalidate_info.returned_value = l_out_prev_cond_item->header.value;

            // find order in cache and change it state
            byte_t *l_tx_item = dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND , NULL);
            dap_chain_tx_in_cond_t * l_in_cond = l_tx_item ? (dap_chain_tx_in_cond_t *) l_tx_item : NULL;

            if (l_in_cond)
                l_cache->tx_info.invalidate_info.prev_hash = l_in_cond->header.tx_prev_hash;

            l_cache->tx_info.invalidate_info.order_hash = s_get_order_from_cache(l_cache_net->cache, &l_cache->tx_info.invalidate_info.prev_hash);
            xchange_tx_cache_t* l_cache_order = NULL;
            HASH_FIND(hh, l_cache_net->cache, &l_cache->tx_info.exchange_info.order_hash, sizeof(dap_hash_fast_t), l_cache_order);
            if(l_cache_order){
                if (l_cache_order->tx_type == TX_TYPE_ORDER){
                    l_cache_order->tx_info.order_info.value_ammount = uint256_0;
                    l_cache_order->tx_info.order_info.order_status = XCHANGE_ORDER_STATUS_CLOSED;
                    if (dap_hash_fast_is_blank(&l_cache_order->tx_info.order_info.next_hash))
                        l_cache_order->tx_info.order_info.next_hash = *a_tx_hash;
                }
            }

            xchange_tx_cache_t* l_cache_prev_tx = NULL;
            HASH_FIND(hh, l_cache_net->cache, &l_cache->tx_info.invalidate_info.prev_hash, sizeof(dap_hash_fast_t), l_cache_prev_tx);
            if(l_cache_prev_tx){
                if (l_cache_prev_tx->tx_type == TX_TYPE_EXCHANGE){
                        l_cache_prev_tx->tx_info.exchange_info.next_hash = *a_tx_hash;
                }
            }
        }
        HASH_ADD(hh, l_cache_net->cache, hash, sizeof(dap_hash_fast_t), l_cache);
    } else if (a_opcode == 'd') {
        // delete tx from cache if present
        xchange_orders_cache_net_t* l_cache = s_get_xchange_cache_by_net_id(a_ledger->net->pub.id);
        xchange_tx_cache_t* l_cache_found = NULL;
        if (l_cache){
            HASH_FIND(hh, l_cache->cache, a_tx_hash, sizeof(dap_hash_fast_t), l_cache_found);
            if (l_cache_found){
                xchange_tx_type_t l_tx_type = l_cache_found->tx_type;
                if (l_tx_type == TX_TYPE_EXCHANGE){
                    xchange_tx_cache_t* l_cache_prev_tx = NULL;
                    HASH_FIND(hh, l_cache->cache, &l_cache_found->tx_info.exchange_info.prev_hash, sizeof(dap_hash_fast_t), l_cache_prev_tx);
                    if(l_cache_prev_tx){
                        if (l_cache_prev_tx->tx_type == TX_TYPE_EXCHANGE){
                            xchange_tx_cache_t* l_cache_order = NULL;
                            HASH_FIND(hh, l_cache->cache, &l_cache_found->tx_info.exchange_info.order_hash, sizeof(dap_hash_fast_t), l_cache_order);
                            l_cache_prev_tx->tx_info.exchange_info.next_hash = (dap_hash_fast_t){0};
                            SUM_256_256(l_cache_order->tx_info.order_info.value_ammount, l_cache_found->tx_info.exchange_info.buy_value, &l_cache_order->tx_info.order_info.value_ammount);
                            uint256_t l_percent_completed = {};
                            SUBTRACT_256_256(l_cache_order->tx_info.order_info.value, l_cache_order->tx_info.order_info.value_ammount, &l_percent_completed);
                            DIV_256_COIN(l_percent_completed, l_cache_order->tx_info.order_info.value, &l_percent_completed);
                            MULT_256_COIN(l_percent_completed, dap_chain_coins_to_balance("100.0"), &l_percent_completed);
                            l_cache_order->tx_info.order_info.percent_completed = dap_chain_balance_to_coins_uint64(l_percent_completed);
                        } else if (l_cache_prev_tx->tx_type == TX_TYPE_ORDER){
                            l_cache_prev_tx->tx_info.order_info.next_hash = (dap_hash_fast_t){0};
                            l_cache_prev_tx->tx_info.order_info.value_ammount = l_cache_prev_tx->tx_info.order_info.value;
                            l_cache_prev_tx->tx_info.order_info.percent_completed = 0;
                        }
                    }
                } else if (l_tx_type == TX_TYPE_INVALIDATE){
                    xchange_tx_cache_t* l_cache_prev_tx = NULL;
                    HASH_FIND(hh, l_cache->cache, &l_cache_found->tx_info.exchange_info.prev_hash, sizeof(dap_hash_fast_t), l_cache_prev_tx);
                    if(l_cache_prev_tx){
                        if (l_cache_prev_tx->tx_type == TX_TYPE_EXCHANGE){
                            xchange_tx_cache_t* l_cache_order = NULL;
                            HASH_FIND(hh, l_cache->cache, &l_cache_found->tx_info.exchange_info.order_hash, sizeof(dap_hash_fast_t), l_cache_order);
                            l_cache_prev_tx->tx_info.exchange_info.next_hash = (dap_hash_fast_t){0};
                            l_cache_order->tx_info.order_info.value_ammount = l_cache_found->tx_info.invalidate_info.returned_value;
                        } else if (l_cache_prev_tx->tx_type == TX_TYPE_ORDER){
                            l_cache_prev_tx->tx_info.order_info.next_hash = (dap_hash_fast_t){0};
                            l_cache_prev_tx->tx_info.order_info.value_ammount = l_cache_prev_tx->tx_info.order_info.value;
                        }
                    }
                }

                HASH_DEL(l_cache->cache, l_cache_found);
                DAP_DELETE(l_cache_found);
            }
        }
    } 
}
