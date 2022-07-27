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
#include "dap_chain_datum_tx.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "dap_chain_node_cli.h"
#include "dap_hash.h"
#include "dap_math_ops.h"
#include "dap_string.h"
#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_xchange.h"
#include "uthash.h"

#define LOG_TAG "dap_chain_net_srv_xchange"

const dap_chain_net_srv_uid_t c_dap_chain_net_srv_xchange_uid = {.uint64= DAP_CHAIN_NET_SRV_XCHANGE_ID};


static int s_cli_srv_xchange(int a_argc, char **a_argv, char **a_str_reply);
static int s_callback_requested(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_error(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_receipt_next_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static dap_chain_net_srv_xchange_price_t *s_xchange_db_load(char *a_key, uint8_t *a_item);

static int s_tx_check_for_open_close(dap_chain_net_t * a_net, dap_chain_datum_tx_t * a_tx);
static void s_string_append_tx_info( dap_string_t * a_reply_str, dap_chain_net_t * a_net, dap_chain_datum_tx_t * a_tx );


static dap_chain_net_srv_xchange_t *s_srv_xchange;




/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @param vpn_addr Zero if only client mode. Address if the node shares its local VPN
 * @param vpn_mask Zero if only client mode. Mask if the node shares its local VPN
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_xchange_init()
{
    dap_chain_node_cli_cmd_item_create("srv_xchange", s_cli_srv_xchange, "eXchange service commands",
    "srv_xchange order create -net_sell <net_name> -token_sell <token ticker> -net_buy <net_name> -token_buy <token_ticker> -wallet <name> -coins <value> -rate <value>\n"
        "\tCreate a new order and tx with specified amount of datoshi to exchange with specified rate (buy / sell)\n"
    "srv_xchange order remove -net <net_name> -order <order_hash> -wallet <wallet_name>\n"
         "\tRemove order with specified order hash in specified net name\n"
    "srv_xchange order update -net <net_name> -order <order_hash> -wallet <wallet_name> [-token_sell <token ticker>] "
                            "[-net_buy <net_name>] [-token_buy <token ticker>] [-coins <value>] [-rate <value>]\n"
         "\tUpdate order with specified order hash in specified net name\n"
    "srv_xchange orders -net <net_name>\n"
         "\tGet the exchange orders list within specified net name\n"
    "srv_xchange purchase -order <order hash> -net <net_name> -wallet <wallet_name> -coins <value>\n"
         "\tExchange tokens with specified order within specified net name. Specify how many datoshies to sell with rate specified by order\n"

    "srv_xchange tx_list -net <net name> [-time_from <yymmdd> -time_to <yymmdd>]"
        "[[-addr <wallet_addr>  [-status closed | open] ]\n"                /* @RRL:  #6294  */
        "\tList of exchange transactions\n"

    "srv_xchange token_pair -net <net name> list all\n"
        "\tList of all token pairs\n"
    "srv_xchange token_pair -net <net name> price average -token1 <token 1> -token2 <token 2> [-time_from <From time>] [-time_to <To time>]  \n"
        "\tGet average price for token pair <token 1>:<token 2> from <From time> to <To time> \n"
        "\tAll times are in RFC822\n"
    "srv_xchange token_pair -net <net name> price history -token1 <token 1> -token2 <token 2> [-time_from <From time>] [-time_to <To time>] \n"
        "\tPrint price history for token pair <token 1>:<token 2> from <From time> to <To time>\n"
        "\tAll times are in RFC822\n"

    "srv_xchange enable\n"
         "\tEnable eXchange service\n"
    "srv_xchange disable\n"
         "\tDisable eXchange service\n"
    );
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
    dap_chain_net_srv_t* l_srv = dap_chain_net_srv_add(l_uid, "srv_xchange", s_callback_requested,
                                                       s_callback_response_success, s_callback_response_error,
                                                       s_callback_receipt_next_success, NULL);
    s_srv_xchange = DAP_NEW_Z(dap_chain_net_srv_xchange_t);
    l_srv->_internal = s_srv_xchange;
    s_srv_xchange->parent = l_srv;
    s_srv_xchange->enabled = false;
    return 1;
}

void dap_chain_net_srv_xchange_deinit()
{
    if(!s_srv_xchange)
        return;
    dap_chain_net_srv_del(s_srv_xchange->parent);
    DAP_DELETE(s_srv_xchange);
}

bool dap_chain_net_srv_xchange_verificator(dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx, bool a_owner)
{
    if (a_owner)
        return true;
    /* Check the condition for verification success
     * a_cond.srv_xchange.rate (a_cond->header.value / a_cond->subtype.srv_xchange.buy_value) >=
     * a_tx.out.rate ((a_cond->header.value - l_back_val) / l_out_val)
     */
    dap_list_t *l_list_out = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT_EXT, NULL);
    uint256_t l_out_val = {}, l_back_val = {};
    char *l_ticker_ctrl = NULL;
    for (dap_list_t *l_list_tmp = l_list_out; l_list_tmp;  l_list_tmp = l_list_tmp->next) {
        dap_chain_tx_out_ext_t *l_tx_out = (dap_chain_tx_out_ext_t *)l_list_tmp->data;
        if (memcmp(&l_tx_out->addr, &a_cond->params, sizeof(dap_chain_addr_t))) {
            continue;
        }
        if (strcmp(l_tx_out->token, a_cond->subtype.srv_xchange.buy_token)) {
            if (l_ticker_ctrl && strcmp(l_ticker_ctrl, l_tx_out->token)) {
                return false;   // too many tokens
            }
            l_ticker_ctrl = l_tx_out->token;
            SUM_256_256(l_back_val, l_tx_out->header.value, &l_back_val);
        } else {                // buying token
            SUM_256_256(l_out_val, l_tx_out->header.value, &l_out_val);
        }
    }
    //long double l_buyer_rate = (a_cond->header.value - l_back_val) / (long double)l_out_val;
    //long double l_seller_rate =
    uint256_t l_buyer_val = {}, l_buyer_mul = {}, l_seller_mul = {};
    SUBTRACT_256_256(a_cond->header.value, l_back_val, &l_buyer_val);
    MULT_256_256(l_buyer_val, a_cond->subtype.srv_xchange.buy_value, &l_buyer_mul);
    MULT_256_256(l_out_val, a_cond->header.value, &l_seller_mul);
    if (compare256(l_seller_mul, l_buyer_mul) == -1) {
        return false;           // wrong changing rate
    }
    return true;
}



static dap_chain_datum_tx_receipt_t *s_xchage_receipt_create(dap_chain_net_srv_xchange_price_t *a_price, uint256_t a_datoshi_buy)
{
    uint32_t l_ext_size = sizeof(uint256_t) + DAP_CHAIN_TICKER_SIZE_MAX;
    uint8_t *l_ext = DAP_NEW_S_SIZE(uint8_t, l_ext_size);
    memcpy(l_ext, &a_datoshi_buy, sizeof(uint256_t));
    strcpy((char *)&l_ext[sizeof(uint256_t)], a_price->token_buy);
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 = SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
    uint256_t l_datoshi_sell = {};
    if (compare256(a_price->rate, uint256_0)!=0){
        DIV_256_COIN(a_datoshi_buy, a_price->rate, &l_datoshi_sell);
        dap_chain_datum_tx_receipt_t *l_receipt =  dap_chain_datum_tx_receipt_create(l_uid, l_unit, 0, l_datoshi_sell,
                                                                                 l_ext, l_ext_size);
        return l_receipt;
    }else{
        DAP_DELETE(l_ext);
        return NULL;
    }
}

static dap_chain_datum_tx_t *s_xchange_tx_create_request(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_wallet_t *a_wallet)
{
    if (!a_price || !a_price->net || !*a_price->token_sell || !*a_price->token_buy || !a_wallet) {
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_price->net->pub.name);
    dap_chain_addr_t *l_seller_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_price->net->pub.id);
    dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);
    uint256_t l_value_sell = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_price->token_sell,
                                                                             l_seller_addr, a_price->datoshi_sell, &l_value_sell);
    if(!l_list_used_out) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_seller_addr);
        log_it(L_WARNING, "Nothing to change (not enough funds)");
        return NULL;
    }

    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, free);
    if (compare256(l_value_to_items, l_value_sell) != 0) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_seller_addr);
        log_it(L_ERROR, "Can't compose the transaction input");
        return NULL;
    }

    // add 'out_cond' & 'out' items
    {
        uint256_t l_datoshi_buy = uint256_0;
        MULT_256_COIN(a_price->datoshi_sell, a_price->rate, &l_datoshi_buy);
        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(l_uid, a_price->net->pub.id, a_price->datoshi_sell,
                                                                                                a_price->net->pub.id, a_price->token_buy, l_datoshi_buy,
                                                                                                (void *)l_seller_addr, sizeof(dap_chain_addr_t));
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_seller_addr);
            log_it(L_ERROR, "Can't compose the transaction conditional output");
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_sell, a_price->datoshi_sell, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_item(&l_tx, l_seller_addr, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                DAP_DELETE(l_seller_addr);
                log_it(L_ERROR, "Cant add coin back output");
                return NULL;
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
                                                          dap_chain_wallet_t *a_wallet, uint256_t a_datoshi_buy)
{
    if (!a_price || !a_price->net || !*a_price->token_sell || !*a_price->token_buy || !a_wallet) {
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_price->net->pub.name);
    dap_chain_addr_t *l_buyer_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_price->net->pub.id);
    dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);
    uint256_t l_value_buy = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_price->token_buy,
                                                                             l_buyer_addr, a_datoshi_buy, &l_value_buy);
    if(!l_list_used_out) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_WARNING, "Nothing to change (not enough funds)");
        return NULL;
    }

    // create and add reciept
    dap_chain_datum_tx_receipt_t *l_receipt = s_xchage_receipt_create(a_price, a_datoshi_buy);
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
    if (compare256(l_value_to_items, l_value_buy) != 0) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_buyer_addr);
        log_it(L_ERROR, "Can't compose the transaction input");
        return NULL;
    }
    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &a_price->tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return NULL;
    }
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, &l_prev_cond_idx);
    if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, &a_price->tx_hash, l_prev_cond_idx)) {
        log_it(L_WARNING, "Requested conditional transaction is already used out");
        return false;
    }
    dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_price->tx_hash, l_prev_cond_idx, 0);
    // add 'out' items
    {
        // transfer buying coins
        const dap_chain_addr_t *l_seller_addr = (dap_chain_addr_t *)l_tx_out_cond->params;
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, a_datoshi_buy, a_price->token_buy) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_buyer_addr);
            log_it(L_ERROR, "Can't add buying coins output");
            return NULL;
        }
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_buy, a_datoshi_buy, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_buyer_addr, l_value_back, a_price->token_buy) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                DAP_DELETE(l_buyer_addr);
                log_it(L_ERROR, "Can't add buying coins back output");
                return NULL;
            }
        }
        //transfer selling coins
        uint256_t l_datoshi_sell = {};
        if (compare256(a_price->rate, uint256_0)!=0){
            DIV_256_COIN(a_datoshi_buy, a_price->rate, &l_datoshi_sell);

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
        DAP_DELETE(l_buyer_addr);
        //transfer unselling coins (partial exchange)
        SUBTRACT_256_256(l_tx_out_cond->header.value, l_datoshi_sell, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, l_value_back, a_price->token_sell) == -1) {
                log_it(L_WARNING, "Can't add selling coins back output (cashback)");
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, l_seller_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        return NULL;
    }

    return l_tx;
}



// Put the transaction to mempool or directly to chains & write transaction's hash to the price
static bool s_xchange_tx_put(dap_chain_datum_tx_t *a_tx, dap_chain_net_t *a_net)
{
    // Put the transaction to mempool or directly to chains
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, a_tx, l_tx_size);
    DAP_DELETE(a_tx);
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    if (!l_chain) {
        DAP_DELETE(l_datum);
        return false;
    }
    // Processing will be made according to autoprocess policy
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain);

    DAP_DELETE(l_datum);

    if (  !l_ret )
        return false;

    DAP_DELETE(l_ret);

    return true;
}

static bool s_xchage_tx_invalidate(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_wallet_t *a_wallet)
{
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_price->net->pub.name);
    dap_chain_addr_t *l_seller_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_price->net->pub.id);
    dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);

    // create and add reciept
    dap_chain_datum_tx_receipt_t *l_receipt = s_xchage_receipt_create(a_price, uint256_0);
    if (!l_receipt) {
        log_it(L_WARNING, "Can't create receipt");
        return false;
    }
    dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_receipt);
    DAP_DELETE(l_receipt);

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &a_price->tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return false;
    }
    int l_prev_cond_idx;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, &l_prev_cond_idx);
    if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, &a_price->tx_hash, l_prev_cond_idx)) {
        log_it(L_WARNING, "Requested conditional transaction is already used out");
        return false;
    }
    dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_price->tx_hash, l_prev_cond_idx, 0);

    // add 'out' item
    const dap_chain_addr_t *l_buyer_addr = (dap_chain_addr_t *)l_tx_out_cond->params;
    if (memcmp(l_seller_addr->data.hash, l_buyer_addr->data.hash, sizeof(dap_chain_hash_fast_t))) {
        log_it(L_WARNING, "Only owner can invalidate exchange transaction");
        return false;
    }
    if (dap_chain_datum_tx_add_out_item(&l_tx, l_seller_addr, l_tx_out_cond->header.value) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_seller_addr);
        log_it(L_ERROR, "Cant add returning coins output");
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


char *s_xchange_order_create(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_datum_tx_t *a_tx)
{
    dap_chain_hash_fast_t l_tx_hash = {};
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_tx_hash);
    memcpy(&a_price->tx_hash, &l_tx_hash, sizeof(dap_chain_hash_fast_t));
    dap_srv_xchange_order_ext_t l_ext={0};
    l_ext.datoshi_sell = a_price->datoshi_sell;
    strncpy(l_ext.token_sell, a_price->token_sell, DAP_CHAIN_TICKER_SIZE_MAX);
    uint32_t l_ext_size = sizeof(dap_srv_xchange_order_ext_t);
    dap_chain_node_addr_t *l_node_addr = dap_chain_net_get_cur_addr(a_price->net);
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 =  SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
    uint256_t l_datoshi_buy = uint256_0;
    MULT_256_COIN(a_price->datoshi_sell, a_price->rate, &l_datoshi_buy);

    char *l_order_hash_str = dap_chain_net_srv_order_create(a_price->net, SERV_DIR_BUY, l_uid, *l_node_addr,
                                                            l_tx_hash, &l_datoshi_buy, l_unit, a_price->token_buy, 0,
                                                            (uint8_t *)&l_ext, l_ext_size, NULL, 0, a_price->wallet_key);
    return l_order_hash_str;
}



dap_chain_net_srv_xchange_price_t *s_xchange_price_from_order(dap_chain_net_t *a_net, dap_chain_net_srv_order_t *a_order)
{
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    dap_srv_xchange_order_ext_t *l_ext = (dap_srv_xchange_order_ext_t *)a_order->ext_n_sign;
    l_price->datoshi_sell = l_ext->datoshi_sell;
    strcpy(l_price->token_sell, l_ext->token_sell);
    l_price->net = a_net;
    strcpy(l_price->token_buy, a_order->price_ticker);
    if( compare256(l_price->datoshi_sell, uint256_0) !=0 ){
        DIV_256_COIN(a_order->price, l_price->datoshi_sell, &l_price->rate);
        memcpy(&l_price->tx_hash, &a_order->tx_cond_hash, sizeof(dap_chain_hash_fast_t));
        return l_price;
    }else{
        DAP_DELETE(l_price);
        return NULL;
    }
}

static int s_cli_srv_xchange_order(int a_argc, char **a_argv, int a_arg_index, char **a_str_reply)
{
    enum {
        CMD_NONE, CMD_CREATE, CMD_REMOVE, CMD_UPDATE, CMD_HISTORY
    };
    int l_cmd_num = CMD_NONE;
    if(dap_chain_node_cli_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "create", NULL)) {
        l_cmd_num = CMD_CREATE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "remove", NULL)) {
        l_cmd_num = CMD_REMOVE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "update", NULL)) {
        l_cmd_num = CMD_UPDATE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "history", NULL)) {
        l_cmd_num = CMD_HISTORY;
    }
    int l_arg_index = a_arg_index + 1;
    const char *l_net_str = NULL;
    const char *l_token_sell_str = NULL, *l_token_buy_str = NULL;
    const char *l_wallet_str = NULL;
    dap_chain_net_t *l_net = NULL;
    switch (l_cmd_num) {
        case CMD_CREATE: {
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order create' required parameter -net");
                return -2;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -3;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-token_sell", &l_token_sell_str);
            if (!l_token_sell_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price create' required parameter -token_sell");
                return -5;
            }
            if (!dap_chain_ledger_token_ticker_check(l_net->pub.ledger, l_token_sell_str)) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Token ticker %s not found", l_token_sell_str);
                return -6;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-token_buy", &l_token_buy_str);
            if (!l_token_buy_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price create' required parameter -token_buy");
                return -5;
            }
            if (!dap_chain_ledger_token_ticker_check(l_net->pub.ledger, l_token_buy_str)) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Token ticker %s not found", l_token_buy_str);
                return -6;
            }
            const char *l_val_sell_str = NULL, *l_val_rate_str = NULL;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-coins", &l_val_sell_str);
            if (!l_val_sell_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price create' required parameter -coins");
                return -8;
            }
            uint256_t l_datoshi_sell = dap_chain_balance_scan(l_val_sell_str);
            if (IS_ZERO_256(l_datoshi_sell)) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Format -coins <unsigned long long>");
                return -9;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-rate", &l_val_rate_str);
            if (!l_val_rate_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price create' required parameter -rate");
                return -8;
            }
            uint256_t l_rate = dap_chain_coins_to_balance(l_val_rate_str);
            if (!compare256(l_rate, uint256_0)) { // if (l_rate == 0)
                dap_chain_node_cli_set_reply_text(a_str_reply, "Format -rate n.n = buy / sell (eg: 1.0, 1.135)");
                return -9;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_wallet_str);
            if (!l_wallet_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price create' required parameter -wallet");
                return -10;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
            if (!l_wallet) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Specified wallet not found");
                return -11;
            }
            uint256_t l_value = dap_chain_wallet_get_balance(l_wallet, l_net->pub.id, l_token_sell_str);
            if (compare256(l_value, l_datoshi_sell) == -1) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Not enough cash in specified wallet");
                dap_chain_wallet_close(l_wallet);
                return -12;
            }
            // Create the price
            dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
            l_price->wallet_str = dap_strdup(l_wallet_str);
            dap_stpcpy(l_price->token_sell, l_token_sell_str);
            l_price->net = l_net;
            dap_stpcpy(l_price->token_buy, l_token_buy_str);
            l_price->datoshi_sell = l_datoshi_sell;
            l_price->rate = l_rate;
            // Create conditional transaction
            dap_chain_datum_tx_t *l_tx = s_xchange_tx_create_request(l_price, l_wallet);
            if (!l_tx) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't compose the conditional transaction");
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
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Can't put transaction to mempool");
                    dap_chain_net_srv_order_delete_by_hash_str(l_net, l_order_hash_str);
                    DAP_DELETE(l_order_hash_str);
                    DAP_DELETE(l_price->wallet_str);
                    DAP_DELETE(l_price);
                    return -15;
                }
                dap_chain_node_cli_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_str);
                DAP_DELETE(l_order_hash_str);
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't compose the order");
                DAP_DELETE(l_price->wallet_str);
                DAP_DELETE(l_price);
                return -18;
            }
        } break;
        case CMD_HISTORY:{
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order create' required parameter -net");
                return -2;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -3;
            }

            } break;

            const char * l_order_hash_str = NULL;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price %s' required parameter -order",
                                                                l_cmd_num == CMD_REMOVE ? "remove" : "update");
                return -12;
            }
            dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
            if (!l_order) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Specified order not found");
                return -13;
            }

            dap_chain_datum_tx_t * l_tx = dap_chain_net_get_tx_by_hash(l_net,&l_order->tx_cond_hash, TX_SEARCH_TYPE_NET);
            if( l_tx){
                int l_rc = s_tx_check_for_open_close(l_net,l_tx);
                char *l_tx_hash = dap_chain_hash_fast_to_str_new(&l_order->tx_cond_hash);
                if(l_rc == 0){
                    dap_chain_node_cli_set_reply_text(a_str_reply, "WRONG TX %s", l_tx_hash);
                }else if(l_rc == 1){
                    dap_string_t * l_str_reply = dap_string_new("");
                    s_string_append_tx_info(l_str_reply, l_net, l_tx);
                    *a_str_reply = dap_string_free(l_str_reply, false);
                }else if(l_rc == 2){
                    dap_string_t * l_str_reply = dap_string_new("");
                    while(l_tx){
                        s_string_append_tx_info(l_str_reply, l_net, l_tx);

                    }
                    *a_str_reply = dap_string_free(l_str_reply, false);
                }else{
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Internal error!");
                }
            }else{
                dap_chain_node_cli_set_reply_text(a_str_reply, "No history");
            }

        case CMD_REMOVE:
        case CMD_UPDATE: {
            const char * l_order_hash_str = NULL;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price %s' required parameter -net",
                                                                l_cmd_num == CMD_REMOVE ? "remove" : "update");
                return -2;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -3;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_wallet_str);
            if (!l_wallet_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price %s' required parameter -wallet",
                                                                l_cmd_num == CMD_REMOVE ? "remove" : "update");
                return -10;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
            if (!l_wallet) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Specified wallet not found");
                return -11;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price %s' required parameter -order",
                                                                l_cmd_num == CMD_REMOVE ? "remove" : "update");
                return -12;
            }
            dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
            if (!l_order) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Specified order not found");
                return -13;
            }
            dap_chain_net_srv_xchange_price_t *l_price = s_xchange_price_from_order(l_net, l_order);
            if (!l_order) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't create price object from order");
                return -13;
            }

            if (l_cmd_num == CMD_REMOVE) {
                dap_string_t *l_str_reply = dap_string_new("");
                bool l_ret = s_xchage_tx_invalidate(l_price, l_wallet);
                dap_chain_wallet_close(l_wallet);
                if (!l_ret) {
                    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_price->tx_hash);
                    dap_string_append_printf(l_str_reply, "Can't invalidate transaction %s\n", l_tx_hash_str);
                    DAP_DELETE(l_tx_hash_str);
                }
                char *l_order_hash_str = dap_chain_hash_fast_to_str_new(&l_price->order_hash);
                if (dap_chain_net_srv_order_delete_by_hash_str(l_price->net, l_order_hash_str)) {
                    dap_string_append_printf(l_str_reply, "Can't remove order %s\n", l_order_hash_str);
                }
                DAP_DELETE(l_order_hash_str);
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
                dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-coins", &l_val_sell_str);
                if (l_val_sell_str) {
                    l_datoshi_sell = dap_chain_balance_scan(l_val_sell_str);
                    if (IS_ZERO_256(l_datoshi_sell)) {
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Format -coins <unsigned long long>");
                        return -9;
                    }
                }
                dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-rate", &l_val_rate_str);
                if (l_val_rate_str) {
                    l_rate = dap_chain_coins_to_balance(l_val_rate_str);
                    if (!compare256(l_rate, uint256_0)) { // if (l_rate == 0)
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Format -rate <long double> = sell / buy");
                        return -9;
                    }
                }
                dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_new_wallet_str);
                l_wallet_str = l_new_wallet_str ? l_new_wallet_str : l_price->wallet_str;
                l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
                if (!l_wallet) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Specified wallet not found");
                    return -11;
                }
                if (!l_val_sell_str && !l_val_rate_str && !l_wallet_str) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "At least one of updating parameters is mandatory");
                    return -13;
                }
                uint256_t l_value = dap_chain_wallet_get_balance(l_wallet, l_net->pub.id, l_token_sell_str);
                if (!IS_ZERO_256(l_datoshi_sell) && compare256(l_value, l_datoshi_sell) == -1) {
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Not enough cash in specified wallet");
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
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Can't compose the conditional transaction");
                    return -14;
                }
                bool l_ret = s_xchage_tx_invalidate(l_price, l_wallet); // may be changed to old price later
                dap_chain_wallet_close(l_wallet);
                if (!l_ret) {
                    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_price->tx_hash);
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Can't invalidate transaction %s\n", l_tx_hash_str);
                    DAP_DELETE(l_tx_hash_str);
                    return -17;
                }
                // Update the order
                char *l_order_hash_str = dap_chain_hash_fast_to_str_new(&l_price->order_hash);
                dap_chain_net_srv_order_delete_by_hash_str(l_price->net, l_order_hash_str);
                DAP_DELETE(l_order_hash_str);
                l_order_hash_str = s_xchange_order_create(l_price, l_tx);
                if (l_order_hash_str) {
                    dap_chain_hash_fast_from_str(l_order_hash_str, &l_price->order_hash);
                    if(!s_xchange_tx_put(l_tx, l_net)) {
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't put transaction to mempool");
                        dap_chain_net_srv_order_delete_by_hash_str(l_net, l_order_hash_str);
                        DAP_DELETE(l_order_hash_str);
                        return -15;
                    }
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_str);
                    DAP_DELETE(l_order_hash_str);
                } else {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Can't compose the order");
                    DAP_DELETE(l_price->wallet_str);
                    DAP_DELETE(l_price);
                    return -18;
                }
            }
        } break;
        default: {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Subcommand %s not recognized", a_argv[a_arg_index]);
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
    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_out_cond_get(a_tx, &l_cond_idx);
    if ( l_out_cond_item && (l_out_cond_item->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE) )
    {
        if(dap_chain_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &l_tx_hash, l_cond_idx))
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
static void s_string_append_tx_info( dap_string_t * a_reply_str, dap_chain_net_t * a_net, dap_chain_datum_tx_t * a_tx )
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
    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_out_cond_get(a_tx, &l_cond_idx);
    if ( l_out_cond_item && (l_out_cond_item->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE) )
    {
        bool l_is_closed = dap_chain_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &l_tx_hash, l_cond_idx);

        uint256_t l_value_from = l_out_cond_item->header.value;
        uint256_t l_value_to = l_out_cond_item->subtype.srv_xchange.buy_value;
        char *l_value_to_str = dap_chain_balance_to_coins(l_value_to);
        char *l_value_from_str = dap_chain_balance_to_coins(l_value_from);

        dap_string_append_printf(a_reply_str, "Hash: %s,", l_tx_hash_str);
        dap_string_append_printf(a_reply_str, "  Status: %s,", l_is_closed ? "closed" : "open");
        dap_string_append_printf(a_reply_str, "  From: %s %s,", l_value_from_str, l_tx_input_ticker);
        dap_string_append_printf(a_reply_str, "  To: %s %s\n", l_value_to_str, l_out_cond_item->subtype.srv_xchange.buy_token);

        DAP_DELETE(l_value_from_str);
        DAP_DELETE(l_value_to_str);
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
size_t  l_datum_tx_size, l_tx_total, l_tx_count;
int l_item_idx, l_rc;
dap_string_t *l_reply_str;
dap_hash_fast_t l_hash;
dap_chain_tx_out_cond_t *l_out_cond_item;


    if ( !(l_reply_str = dap_string_new("")) )                              /* Prepare output string discriptor*/
        return  log_it(L_ERROR, "Cannot allocate a memory, errno=%d", errno), -ENOMEM;

    memset(&l_tx_first_hash, 0, sizeof(dap_chain_hash_fast_t));             /* Initial hash == zero */


    for ( l_tx_count = l_tx_total = 0;
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
                l_rc = dap_chain_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &l_hash, l_item_idx);

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
    int l_arg_index = 1, l_cmd_num = CMD_NONE, l_rc;

    if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "order", NULL)) {
        l_cmd_num = CMD_ORDER;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "orders", NULL)) {
        l_cmd_num = CMD_ORDERS;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "purchase", NULL)) {
        l_cmd_num = CMD_PURCHASE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "enable", NULL)) {
        l_cmd_num = CMD_ENABLE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "disable", NULL)) {
        l_cmd_num = CMD_DISABLE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "tx_list", NULL)) {
        l_cmd_num = CMD_TX_LIST;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "token_pair", NULL)) {
        l_cmd_num = CMD_TOKEN_PAIR;
    }


    switch (l_cmd_num) {
        case CMD_ORDER:
            return s_cli_srv_xchange_order(a_argc, a_argv, l_arg_index + 1, a_str_reply);
        case CMD_ORDERS: {
            const char *l_net_str = NULL;
            l_arg_index++;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'orders' required parameter -net");
                return -2;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -3;
            }

            char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group(l_net);

            size_t l_orders_count = 0;
            dap_global_db_obj_t * l_orders = dap_chain_global_db_gr_load(l_gdb_group_str, &l_orders_count);
            dap_chain_net_srv_xchange_price_t *l_price;
            dap_string_t *l_reply_str = dap_string_new("");


            for (size_t i = 0; i < l_orders_count; i++)
            {
                dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)l_orders[i].value;

                if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_XCHANGE_ID)
                    continue;

                // TODO add filters to list (tokens, network, etc.)
                l_price = s_xchange_price_from_order(l_net, l_order);
                if( !l_price ){
                    log_it(L_WARNING,"Can't create price from order");
                    continue;
                }

                uint256_t l_datoshi_buy;
                char *l_cp1, *l_cp2, *l_cp3;

                MULT_256_COIN(l_price->datoshi_sell, l_price->rate, &l_datoshi_buy);  /* sell/buy computation */

                dap_string_append_printf(l_reply_str, "orderHash: %s tokSel: %s, net: %s, tokBuy: %s, sell: %s, buy: %s buy/sell: %s\n", l_orders[i].key,
                                         l_price->token_sell, l_price->net->pub.name,
                                         l_price->token_buy,
                                         l_cp1 = dap_chain_balance_print(l_price->datoshi_sell), l_cp2 = dap_chain_balance_print(l_datoshi_buy),
                                         l_cp3 = dap_chain_balance_to_coins(l_price->rate));

                DAP_DEL_Z(l_cp1);
                DAP_DEL_Z(l_cp2);
                DAP_DEL_Z(l_cp3);
                DAP_DEL_Z(l_price);
            }
            dap_chain_global_db_objs_delete(l_orders, l_orders_count);
            DAP_DELETE( l_gdb_group_str);
            if (!l_reply_str->len) {
                dap_string_append(l_reply_str, "No orders found");
            }
            *a_str_reply = dap_string_free(l_reply_str, false);
        } break;


        case CMD_PURCHASE: {
            const char *l_net_str = NULL, *l_wallet_str = NULL, *l_order_hash_str = NULL, *l_val_buy_str = NULL;
            l_arg_index++;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'purchase' required parameter -net");
                return -2;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -3;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_wallet_str);
            if (!l_wallet_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'purchase' required parameter -wallet");
                return -10;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
            if (!l_wallet) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Specified wallet not found");
                return -11;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'purchase' required parameter -order");
                return -12;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-coins", &l_val_buy_str);
            if (!l_val_buy_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'purchase' required parameter -coins");
                return -8;
            }
            uint256_t l_datoshi_buy = dap_chain_balance_scan(l_val_buy_str);
            if (IS_ZERO_256(l_datoshi_buy)) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Format -coins <unsigned long long>");
                return -9;
            }
            dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
            if (l_order) {
                dap_chain_net_srv_xchange_price_t *l_price = s_xchange_price_from_order(l_net, l_order);
                if(!l_price){
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Can't create price from order");
                    return -13;
                }
                // Create conditional transaction
                dap_chain_datum_tx_t *l_tx = s_xchange_tx_create_exchange(l_price, l_wallet, l_datoshi_buy);
                if (l_tx && s_xchange_tx_put(l_tx, l_net)) {
                    // TODO send request to seller to update / delete order & price
                    dap_chain_net_srv_order_delete_by_hash_str(l_price->net, l_order_hash_str);
                }
                DAP_DELETE(l_price);
                DAP_DELETE(l_order);
                dap_chain_node_cli_set_reply_text(a_str_reply, l_tx ? "Exchange transaction has done" :
                                                                      "Exchange transaction error");
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Specified order not found");
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
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-time_from", &l_time_begin_str);
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-time_to", &l_time_end_str);

            /*
             * @RRL:  #6294: [[-addr <addr> [-status closed | open]]
             * we should check for valid combination of the status and addr options
             */
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-addr", &l_addr_str);
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-status", &l_status_str);


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
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Unrecognized '-status %s'", l_status_str);
                    return -3;
                }
            }


            if(!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'tx_list' required parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if(!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }

            dap_time_t l_time[2];
            l_time[0] = dap_time_from_str_rfc822(l_time_begin_str);
            l_time[1] = dap_time_from_str_rfc822(l_time_end_str);


            /* Dispatch request processing to ... */
            if ( l_addr_str )
            {
                if ( !(l_addr = dap_chain_addr_from_str(l_addr_str)) )
                    return  dap_chain_node_cli_set_reply_text(a_str_reply, "Cannot convert -addr '%s' to internal representative", l_addr_str), -EINVAL;

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
                    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_out_cond_get(l_datum_tx, &l_prev_cond_idx);
                    if ( l_out_cond_item && (l_out_cond_item->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE) )
                    {
                        uint256_t l_value_from = l_out_cond_item->header.value;
                        uint256_t l_value_to = l_out_cond_item->subtype.srv_xchange.buy_value;
                        char *l_value_to_str = dap_chain_balance_to_coins(l_value_to);
                        char *l_value_from_str = dap_chain_balance_to_coins(l_value_from);

                        l_rc = dap_chain_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &l_tx_hash, l_prev_cond_idx);

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
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if(!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'token_pair' required parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if(!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }


            // Select subcommands

            // check for price subcommand
            const char * l_price_subcommand = NULL;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "price", &l_price_subcommand);

            // check for get subcommand
            if ( l_price_subcommand ){
                // Check for token1
                const char * l_token1 = NULL;
                dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-token1", &l_token1);
                if(!l_token1){
                    dap_chain_node_cli_set_reply_text(a_str_reply,"No argument '-token1'");
                    return -5;
                }
                dap_chain_datum_token_t * l_token1_datum = dap_chain_ledger_token_ticker_check( l_net->pub.ledger, l_token1);
                if(!l_token1_datum){
                    dap_chain_node_cli_set_reply_text(a_str_reply,"Can't find \"%s\" token in network \"%s\" for argument '-token1' ", l_token1, l_net->pub.name);
                    return -6;
                }

                // Check for token2
                const char * l_token2 = NULL;
                dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-token2", &l_token2);
                if(!l_token2){
                    dap_chain_node_cli_set_reply_text(a_str_reply,"No argument '-token2'");
                    return -5;
                }
                dap_chain_datum_token_t * l_token2_datum = dap_chain_ledger_token_ticker_check( l_net->pub.ledger, l_token2);
                if(!l_token2_datum){
                    dap_chain_node_cli_set_reply_text(a_str_reply,"Can't find \"%s\" token in network \"%s\" for argument '-token2' ", l_token2, l_net->pub.name);
                    return -6;
                }

                // Read time_from
                dap_time_t l_time_from = 0;
                const char * l_time_from_str = NULL;
                dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-time_from", &l_time_from_str);
                l_time_from = dap_time_from_str_rfc822(l_time_from_str);

                // Read time_to
                dap_time_t l_time_to = 0;
                const char * l_time_to_str = NULL;
                dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-time_to", &l_time_to_str);
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

                            // Compare with token1 and token2
                            if( dap_strcmp(l_tx_input_ticker, l_token1) != 0 &&
                                    dap_strcmp(l_tx_input_ticker, l_token2) != 0) {
                                l_cur = dap_list_next(l_cur);
                                DAP_DEL_Z(l_tx_hash);
                                continue;
                            }
                            int l_cond_idx = 0;
                            dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_out_cond_get(l_tx, &l_cond_idx);
                            if(l_out_cond_item && l_out_cond_item->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE &&
                                    dap_chain_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, l_tx_hash, l_cond_idx)) {
                                uint256_t l_value_sell = l_out_cond_item->header.value;
                                uint256_t l_value_buy = l_out_cond_item->subtype.srv_xchange.buy_value;
                                if(compare256(l_value_sell,uint256_0) !=0 ){
                                    DIV_256_COIN(l_value_buy, l_value_sell, &l_rate);
                                    if(SUM_256_256(l_rate, l_total_rates, &l_total_rates )!= 0)
                                        log_it(L_ERROR, "Overflow on avarage price calculation (summing)");
                                    INCR_256(&l_total_rates_count);
                                }else{
                                    log_it(L_ERROR, "Sell value is 0 in avarage price calculation (summing)");
                                }
                            }
                            DAP_DEL_Z(l_tx_hash);
                        }
                        l_cur = dap_list_next(l_cur);
                    }
                    dap_list_free_full(l_tx_cond_list, NULL);
                    uint256_t l_rate_average = {0};
                    if( compare256(l_total_rates_count, uint256_0) != 0 )
                        DIV_256(l_total_rates,l_total_rates_count,&l_rate_average);
                    char *l_rate_average_str = dap_chain_balance_to_coins(l_rate_average);
                    char *l_last_rate_str = dap_chain_balance_to_coins(l_rate);
                    dap_string_append_printf(l_reply_str,"Average rate: %s   Last rate: %s", l_rate_average_str, l_last_rate_str);
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

                            // Compare with token1 and token2
                            if( dap_strcmp(l_tx_input_ticker, l_token1) != 0 &&
                                    dap_strcmp(l_tx_input_ticker, l_token2) != 0) {
                                continue;
                            }

                            // Check if output is spent
                            int l_cond_idx = 0;
                            dap_chain_tx_out_cond_t *l_out_cond_item = l_cur->out_cond;
                            if(l_out_cond_item && l_cur->tx_next) {

                                // Print tx_hash
                                char * l_tx_hash_str = dap_chain_hash_fast_to_str_new(l_tx_hash);
                                dap_string_append_printf(l_reply_str,"Tx hash: %s\n", l_tx_hash_str);
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
                                if(compare256(l_value_from, uint256_0) != 0)
                                    DIV_256_COIN(l_value_to, l_value_from, &l_rate);
                                char * l_value_from_str = dap_chain_balance_to_coins(l_value_from);
                                char * l_value_to_str = dap_chain_balance_to_coins(l_value_to);
                                char *l_rate_str = dap_chain_balance_to_coins(l_rate);

                                dap_string_append_printf(l_reply_str, "  From: %s %s   ", l_value_from_str, l_tx_input_ticker);
                                dap_string_append_printf(l_reply_str, "  To: %s %s   ", l_value_to_str, l_out_cond_item->subtype.srv_xchange.buy_token );
                                dap_string_append_printf(l_reply_str, "  Rate: %s", l_rate_str);
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

                }break;
            }

            const char * l_list_subcommand = NULL;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "list", &l_list_subcommand);
            if( l_list_subcommand ){
                if (strcmp(l_list_subcommand,"all") == 0){
                    dap_string_t *l_reply_str = dap_string_new("");
                    char ** l_tickers = NULL;
                    size_t l_tickers_count = 0;
                    dap_chain_ledger_addr_get_token_ticker_all_fast( l_net->pub.ledger,NULL,&l_tickers,&l_tickers_count);

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
            dap_chain_node_cli_set_reply_text(a_str_reply,"Command 'token pair' required proper subcommand, please read its manual with command 'help srv_xchange'");


        } break;

        default: {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Command %s not recognized", a_argv[l_arg_index]);
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
