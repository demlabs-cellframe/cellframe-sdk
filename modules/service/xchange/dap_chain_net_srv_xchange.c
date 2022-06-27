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
#include "dap_chain_node_cli.h"
#include "dap_string.h"
#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_xchange.h"

#define LOG_TAG "dap_chain_net_srv_xchange"

static int s_cli_srv_xchange(int a_argc, char **a_argv, char **a_str_reply);
static int s_callback_requested(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_error(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_receipt_next_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static dap_chain_net_srv_xchange_price_t *s_xchange_db_load(char *a_key, uint8_t *a_item);

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
    "srv_xchange price create -net_sell <net name> -token_sell <token ticker> -net_buy <net_name> -token_buy <token ticker> -wallet <name> -coins <value> -rate <value>\n"
        "\tCreate a new price with specified amount of datoshi to exchange with specified rate (sell : buy)\n"
    "srv_xchange price remove -net_sell <net name> -token_sell <token ticker> -net_buy <net_name> -token_buy <token ticker>\n"
         "\tRemove price with specified tickers within specified net names\n"
    "srv_xchange price list\n"
         "\tList all active prices\n"
    "srv_xchange price update -net_sell <net name> -token_sell <token ticker> -net_buy <net_name> -token_buy <token ticker> {-coins <value> | -rate <value> | -wallet <name>}\n"
         "\tUpdate price with specified tickers within specified net names\n"
    "srv_xchange orders -net <net name>\n"
         "\tGet the exchange orders list within specified net name\n"
    "srv_xchange purchase -order <order hash> -net <net name> -wallet <wallet_name> -coins <value>\n"
         "\tExchange tokens with specified order within specified net name. Specify how datoshies to buy\n"
    "srv_xchange tx_list -net <net name> [-time_from <yymmdd> -time_to <yymmdd>]\n"
        "\tList of exchange transactions\n"
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
    size_t l_prices_count = 0;
    dap_global_db_obj_t *l_prices = dap_chain_global_db_gr_load(GROUP_LOCAL_XCHANGE, &l_prices_count);
    for (size_t i = 0; i < l_prices_count; i++) {
        dap_chain_net_srv_xchange_price_t *l_price = s_xchange_db_load(l_prices[i].key, l_prices[i].value);
        HASH_ADD_KEYPTR(hh, s_srv_xchange->pricelist, l_price->key_ptr, strlen(l_price->key_ptr), l_price);
    }
    dap_chain_global_db_objs_delete(l_prices, l_prices_count);
    return 1;
}

void dap_chain_net_srv_xchange_deinit()
{
    if(!s_srv_xchange)
        return;
    dap_chain_net_srv_xchange_price_t *l_price = NULL, *l_tmp;
    HASH_ITER(hh, s_srv_xchange->pricelist, l_price, l_tmp) {
        // Clang bug at this, l_price should change at every loop cycle
        HASH_DEL(s_srv_xchange->pricelist, l_price);
        DAP_DELETE(l_price->wallet_str);
        DAP_DELETE(l_price->key_ptr);
        DAP_DELETE(l_price);
    }
    dap_chain_net_srv_del(s_srv_xchange->parent);
    DAP_DELETE(s_srv_xchange);
}

bool dap_chain_net_srv_xchange_verificator(dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx, bool a_owner)
{
    if (a_owner)
        return true;
    /* Check the condition for verification success
     * a_cond.srv_xchange.rate >= a_tx.out.rate
     */
    dap_list_t *l_list_out = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT_EXT, NULL);
    uint256_t l_out_val = {}, l_back_val = {};
    char *l_ticker_ctrl = NULL;
    for (dap_list_t *l_list_tmp = l_list_out; l_list_tmp;  l_list_tmp = l_list_tmp->next) {
        dap_chain_tx_out_ext_t *l_tx_out = (dap_chain_tx_out_ext_t *)l_list_tmp->data;
        if (memcmp(&l_tx_out->addr, &a_cond->params, sizeof(dap_chain_addr_t))) {
            continue;
        }
        if (strcmp(l_tx_out->token, a_cond->subtype.srv_xchange.token)) {
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
    //long double l_seller_rate = (long double)a_cond->header.value / a_cond->subtype.srv_xchange.value;
    uint256_t l_buyer_val = {}, l_buyer_mul = {}, l_seller_mul = {};
    SUBTRACT_256_256(a_cond->header.value, l_back_val, &l_buyer_val);
    MULT_256_256(l_buyer_val, a_cond->subtype.srv_xchange.value, &l_buyer_mul);
    MULT_256_256(l_out_val, a_cond->header.value, &l_seller_mul);
    if (compare256(l_seller_mul, l_buyer_mul) == -1) {
        return false;           // wrong changing rate
    }
    return true;
}

static dap_chain_datum_tx_receipt_t *s_xchage_receipt_create(dap_chain_net_srv_xchange_price_t *a_price)
{
    uint32_t l_ext_size = sizeof(uint256_t) + DAP_CHAIN_TICKER_SIZE_MAX;
    uint8_t *l_ext = DAP_NEW_S_SIZE(uint8_t, l_ext_size);
    uint256_t l_datoshi_buy = uint256_0; // TODO rework it with fixed point MULT_256_FRAC_FRAC(a_price->datoshi_sell, 1 / a_price->rate); +++
	DIV_256(dap_chain_coins_to_balance("1.0"), a_price->rate, &l_datoshi_buy);
	if (MULT_256_COIN(a_price->datoshi_sell, l_datoshi_buy, &l_datoshi_buy)) {
		log_it(L_WARNING, "DANGER: MULT_256_COIN overflow! in s_xchage_receipt_create()");
		l_datoshi_buy = uint256_0;
	}
    memcpy(l_ext, &l_datoshi_buy, sizeof(uint256_t));
    strcpy((char *)&l_ext[sizeof(uint256_t)], a_price->token_buy);
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 = SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
    dap_chain_datum_tx_receipt_t *l_receipt =  dap_chain_datum_tx_receipt_create(l_uid, l_unit, 0, a_price->datoshi_sell,
                                                                                 l_ext, l_ext_size);
    return l_receipt;
}

static dap_chain_datum_tx_t *s_xchange_tx_create_request(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_wallet_t *a_wallet)
{
    if (!a_price || !a_price->net_sell || !a_price->net_buy || !*a_price->token_sell || !*a_price->token_buy || !a_wallet) {
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_price->net_sell->pub.name);
    dap_chain_addr_t *l_seller_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_price->net_sell->pub.id);
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
    dap_list_free_full(l_list_used_out, NULL);
    if (compare256(l_value_to_items, l_value_sell) != 0) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_seller_addr);
        log_it(L_ERROR, "Can't compose the transaction input");
        return NULL;
    }

    // add 'out_cond' & 'out' items
    {
        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(l_uid, a_price->net_sell->pub.id,
                                                                                                a_price->token_sell, a_price->datoshi_sell,
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

static dap_chain_datum_tx_t *s_xchange_tx_create_exchange(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_hash_fast_t *a_tx_cond_hash, dap_chain_wallet_t *a_wallet)
{
    if (!a_price || !a_price->net_sell || !a_price->net_buy || !*a_price->token_sell || !*a_price->token_buy || !a_wallet) {
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_price->net_buy->pub.name);
    dap_chain_addr_t *l_seller_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_price->net_buy->pub.id);
    dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);
    uint256_t l_value_buy = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
	uint256_t l_datoshi_buy = uint256_0; // TODO rework it with fixed point MULT_256_FRAC_FRAC(a_price->datoshi_sell, 1 / a_price->rate); +++
	DIV_256(dap_chain_coins_to_balance("1.0"), a_price->rate, &l_datoshi_buy);
	if (MULT_256_COIN(a_price->datoshi_sell, l_datoshi_buy, &l_datoshi_buy)) {
		log_it(L_WARNING, "DANGER: MULT_256_COIN overflow! in s_xchange_tx_create_exchange()");
		l_datoshi_buy = uint256_0;
	}
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_price->token_buy,
                                                                             l_seller_addr, l_datoshi_buy, &l_value_buy);
    if(!l_list_used_out) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_WARNING, "Nothing to change (not enough funds)");
        return NULL;
    }

    // create and add reciept
    dap_chain_datum_tx_receipt_t *l_receipt = s_xchage_receipt_create(a_price);
    dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_receipt);
    DAP_DELETE(l_receipt);
    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (compare256(l_value_to_items, l_value_buy) != 0) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_seller_addr);
        log_it(L_ERROR, "Can't compose the transaction input");
        return NULL;
    }
    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, a_tx_cond_hash);
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
    dap_chain_datum_tx_add_in_cond_item(&l_tx, a_tx_cond_hash, l_prev_cond_idx, 0);
    // add 'out' items
    {
        // transfer selling coins
        const dap_chain_addr_t *l_buyer_addr = (dap_chain_addr_t *)l_tx_out_cond->params;
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_buyer_addr, l_datoshi_buy, a_price->token_buy) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_seller_addr);
            log_it(L_ERROR, "Can't add selling coins output");
            return NULL;
        }
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_buy, l_datoshi_buy, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, l_value_back, a_price->token_buy) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                DAP_DELETE(l_seller_addr);
                log_it(L_ERROR, "Can't add selling coins back output");
                return NULL;
            }
        }
        //transfer buying coins
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, a_price->datoshi_sell, a_price->token_sell) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_seller_addr);
            log_it(L_ERROR, "Can't add buying coins output");
            return NULL;
        }
        DAP_DELETE(l_seller_addr);
        //transfer unbuying coins (partial exchange)
        SUBTRACT_256_256(l_tx_out_cond->header.value, a_price->datoshi_sell, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_buyer_addr, l_value_back, a_price->token_sell) == -1) {
                log_it(L_WARNING, "Can't add buying coins back output (cashback)");
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

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_price->net_buy->pub.name);
    dap_chain_addr_t *l_seller_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_price->net_buy->pub.id);
    dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);

    // create and add reciept
    dap_chain_datum_tx_receipt_t *l_receipt = s_xchage_receipt_create(a_price);
    dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_receipt);
    DAP_DELETE(l_receipt);

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &a_price->tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return false;
    }
    int l_prev_cond_idx = 0;
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
    if (!s_xchange_tx_put(l_tx, a_price->net_buy)) {
        return false;
    }
    return true;
}

char *s_xchange_order_create(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_datum_tx_t *a_tx)
{
    dap_chain_hash_fast_t l_tx_hash = {};
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_tx_hash);
    memcpy(&a_price->tx_hash, &l_tx_hash, sizeof(dap_chain_hash_fast_t));
    dap_srv_xchange_order_ext_t l_ext;
    l_ext.net_sell_id = a_price->net_sell->pub.id.uint64;
    l_ext.datoshi_sell = a_price->datoshi_sell;
    strcpy(l_ext.token_sell, a_price->token_sell);
    uint32_t l_ext_size = sizeof(dap_srv_xchange_order_ext_t);
    dap_chain_node_addr_t *l_node_addr = dap_chain_net_get_cur_addr(a_price->net_sell);
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 =  SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
	uint256_t l_datoshi_buy = uint256_0; // TODO rework it with fixed point MULT_256_FRAC_FRAC(a_price->datoshi_sell, 1 / a_price->rate); +++
	DIV_256(dap_chain_coins_to_balance("1.0"), a_price->rate, &l_datoshi_buy);
	if (MULT_256_COIN(a_price->datoshi_sell, l_datoshi_buy, &l_datoshi_buy)) {
		log_it(L_WARNING, "DANGER: MULT_256_COIN overflow! in s_xchange_order_create()");
		l_datoshi_buy = uint256_0;
	}
    char *l_order_hash_str = dap_chain_net_srv_order_create(a_price->net_buy, SERV_DIR_SELL, l_uid, *l_node_addr,
                                                            l_tx_hash, l_datoshi_buy, l_unit, a_price->token_buy, 0,
                                                            (uint8_t *)&l_ext, l_ext_size, NULL, 0, a_price->wallet_key);
    return l_order_hash_str;
}

dap_chain_net_srv_xchange_price_t *s_xchange_price_from_order(dap_chain_net_t *a_net, dap_chain_net_srv_order_t *a_order)
{
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    dap_srv_xchange_order_ext_t *l_ext = (dap_srv_xchange_order_ext_t *)a_order->ext_n_sign;
    dap_chain_net_id_t l_net_buy_id = { .uint64 = l_ext->net_sell_id };
    l_price->net_sell = dap_chain_net_by_id(l_net_buy_id);
    l_price->datoshi_sell = l_ext->datoshi_sell;
    strcpy(l_price->token_sell, l_ext->token_sell);
    l_price->net_buy = a_net;
    strcpy(l_price->token_buy, a_order->price_ticker);
    DIV_256(l_price->datoshi_sell, a_order->price, &l_price->rate);//l_price->rate = dap_chain_coins_to_balance("1.0");//1; // TODO (long double)l_price->datoshi_sell / a_order->price;
    return l_price;
}

static bool s_xchange_db_add(dap_chain_net_srv_xchange_price_t *a_price)
{
    int rc;

    size_t l_size = sizeof(dap_chain_net_srv_xchange_db_item_t) + strlen(a_price->wallet_str) + 1;
    dap_chain_net_srv_xchange_db_item_t *l_item = DAP_NEW_Z_SIZE(dap_chain_net_srv_xchange_db_item_t, l_size);
    strcpy(l_item->token_sell, a_price->token_sell);
    strcpy(l_item->token_buy, a_price->token_buy);
    l_item->net_sell_id = a_price->net_sell->pub.id.uint64;
    l_item->net_buy_id = a_price->net_buy->pub.id.uint64;
    l_item->datoshi_sell = a_price->datoshi_sell;
    l_item->rate = a_price->rate;
    memcpy(&l_item->tx_hash, &a_price->tx_hash, sizeof(dap_chain_hash_fast_t));
    memcpy(&l_item->order_hash, &a_price->order_hash, sizeof(dap_chain_hash_fast_t));
    strcpy(l_item->wallet_str, a_price->wallet_str);

    rc = dap_chain_global_db_gr_set(a_price->key_ptr, l_item, l_size, GROUP_LOCAL_XCHANGE);
    DAP_DELETE(l_item);

    return  rc;
}

static dap_chain_net_srv_xchange_price_t *s_xchange_db_load(char *a_key, uint8_t *a_item)
{
    dap_chain_net_srv_xchange_db_item_t *l_item = (dap_chain_net_srv_xchange_db_item_t *)a_item;
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    l_price->key_ptr = dap_strdup(a_key);
    strcpy(l_price->token_sell, l_item->token_sell);
    strcpy(l_price->token_buy, l_item->token_buy);
    dap_chain_net_id_t l_id = { .uint64 = l_item->net_sell_id};
    l_price->net_sell = dap_chain_net_by_id(l_id);
    l_id.uint64 = l_item->net_buy_id;
    l_price->net_buy = dap_chain_net_by_id(l_id);
    l_price->datoshi_sell = l_item->datoshi_sell;
    l_price->rate = l_item->rate;
    memcpy(&l_price->tx_hash, &l_item->tx_hash, sizeof(dap_chain_hash_fast_t));
    memcpy(&l_price->order_hash, &l_item->order_hash, sizeof(dap_chain_hash_fast_t));
    l_price->wallet_str = dap_strdup(l_item->wallet_str);
    return l_price;
}

static int s_cli_srv_xchange_price(int a_argc, char **a_argv, int a_arg_index, char **a_str_reply)
{
    enum {
        CMD_NONE, CMD_CREATE, CMD_REMOVE, CMD_LIST, CMD_UPDATE
    };
    int l_cmd_num = CMD_NONE;
    if(dap_chain_node_cli_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "create", NULL)) {
        l_cmd_num = CMD_CREATE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "remove", NULL)) {
        l_cmd_num = CMD_REMOVE;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "list", NULL)) {
        l_cmd_num = CMD_LIST;
    }
    else if(dap_chain_node_cli_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "update", NULL)) {
        l_cmd_num = CMD_UPDATE;
    }
    int l_arg_index = a_arg_index + 1;
    const char *l_net_sell_str = NULL, *l_net_buy_str = NULL;
    const char *l_token_sell_str = NULL, *l_token_buy_str = NULL;
    dap_chain_net_t *l_net_sell = NULL, *l_net_buy = NULL;
    char *l_strkey;
    if (l_cmd_num == CMD_CREATE || l_cmd_num == CMD_REMOVE || l_cmd_num == CMD_UPDATE) {
        dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net_sell", &l_net_sell_str);
        if (!l_net_sell_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price %s' required parameter -net_sell",
                                                            l_cmd_num == CMD_CREATE ? "create" : (l_cmd_num == CMD_REMOVE ? "remove" : "update"));
            return -2;
        }
        l_net_sell = dap_chain_net_by_name(l_net_sell_str);
        if (!l_net_sell) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_sell_str);
            return -3;
        }
        dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net_buy", &l_net_buy_str);
        if (!l_net_buy_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price %s' required parameter -net_buy",
                                                            l_cmd_num == CMD_CREATE ? "create" : (l_cmd_num == CMD_REMOVE ? "remove" : "update"));
            return -2;
        }
        l_net_buy = dap_chain_net_by_name(l_net_buy_str);
        if (!l_net_sell) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_buy_str);
            return -3;
        }
        dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-token_sell", &l_token_sell_str);
        if (!l_token_sell_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price %s' required parameter -token_sell",
                                                            l_cmd_num == CMD_CREATE ? "create" : (l_cmd_num == CMD_REMOVE ? "remove" : "update"));
            return -5;
        }
        if (!dap_chain_ledger_token_ticker_check(l_net_sell->pub.ledger, l_token_sell_str)) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Token ticker %s not found", l_token_sell_str);
            return -6;
        }
        dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-token_buy", &l_token_buy_str);
        if (!l_token_buy_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price %s' required parameter -token_buy",
                                                            l_cmd_num == CMD_CREATE ? "create" : (l_cmd_num == CMD_REMOVE ? "remove" : "update"));
            return -5;
        }
        if (!dap_chain_ledger_token_ticker_check(l_net_buy->pub.ledger, l_token_buy_str)) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Token ticker %s not found", l_token_buy_str);
            return -6;
        }
        l_strkey = DAP_NEW_SIZE(char, dap_strlen(l_token_sell_str) + dap_strlen(l_net_sell_str) +
                                dap_strlen(l_token_buy_str) + dap_strlen(l_net_buy_str) + 1);
        dap_stpcpy(l_strkey, l_token_sell_str);
        strcat(l_strkey, l_net_sell_str);
        strcat(l_strkey, l_token_buy_str);
        strcat(l_strkey, l_net_buy_str);
    }
    switch (l_cmd_num) {
        case CMD_CREATE: {
            dap_chain_net_srv_xchange_price_t *l_price = NULL;
            HASH_FIND_STR(s_srv_xchange->pricelist, l_strkey, l_price);
            if (l_price) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Price with provided pair of token ticker + net name already exist");
                return -7;
            }
            const char *l_val_sell_str = NULL, *l_val_rate_str = NULL, *l_wallet_str = NULL;
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
                dap_chain_node_cli_set_reply_text(a_str_reply, "Format -rate <long double> = sell / buy");
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
            uint256_t l_value = dap_chain_wallet_get_balance(l_wallet, l_net_sell->pub.id, l_token_sell_str);
            if (compare256(l_value, l_datoshi_sell) == -1) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Not enough cash in specified wallet");
                dap_chain_wallet_close(l_wallet);
                return -12;
            }
            // Create the price
            l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
            l_price->wallet_str = dap_strdup(l_wallet_str);
            dap_stpcpy(l_price->token_sell, l_token_sell_str);
            l_price->net_sell = l_net_sell;
            dap_stpcpy(l_price->token_buy, l_token_buy_str);
            l_price->net_buy = l_net_buy;
            l_price->key_ptr = l_strkey;
            l_price->datoshi_sell = l_datoshi_sell;
            l_price->rate = l_rate;
            // Create conditional transaction
            dap_chain_datum_tx_t *l_tx = s_xchange_tx_create_request(l_price, l_wallet);
            if (!l_tx) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't compose the conditional transaction");
                DAP_DELETE(l_price->key_ptr);
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
                if(!s_xchange_tx_put(l_tx, l_net_buy)) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Can't put transaction to mempool");
                    dap_chain_net_srv_order_delete_by_hash_str(l_net_buy, l_order_hash_str);
                    DAP_DELETE(l_order_hash_str);
                    DAP_DELETE(l_price->key_ptr);
                    DAP_DELETE(l_price->wallet_str);
                    DAP_DELETE(l_price);
                    return -15;
                }
                if (!s_xchange_db_add(l_price)) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Can't save price in database");
                    dap_chain_net_srv_order_delete_by_hash_str(l_net_buy, l_order_hash_str);
                    DAP_DELETE(l_order_hash_str);
                    DAP_DELETE(l_price->key_ptr);
                    DAP_DELETE(l_price->wallet_str);
                    DAP_DELETE(l_price);
                    return -16;
                }
                dap_chain_node_cli_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_str);
                DAP_DELETE(l_order_hash_str);
                // Add active price to pricelist
                HASH_ADD_KEYPTR(hh, s_srv_xchange->pricelist, l_price->key_ptr, strlen(l_price->key_ptr), l_price);
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't compose the order");
                DAP_DELETE(l_price->key_ptr);
                DAP_DELETE(l_price->wallet_str);
                DAP_DELETE(l_price);
                return -18;
            }
        } break;
        case CMD_REMOVE:
        case CMD_UPDATE: {
            dap_chain_net_srv_xchange_price_t *l_price = NULL;
            HASH_FIND_STR(s_srv_xchange->pricelist, l_strkey, l_price);
            if (!l_price) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Price with provided pair of token ticker + net name is not exist");
                return -1;
            }
            if (l_cmd_num == CMD_REMOVE) {
                dap_string_t *l_str_reply = dap_string_new("");
                HASH_DEL(s_srv_xchange->pricelist, l_price);
                dap_chain_global_db_gr_del(l_price->key_ptr, GROUP_LOCAL_XCHANGE);
                dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_price->wallet_str, dap_chain_wallet_get_path(g_config));
                bool l_ret = s_xchage_tx_invalidate(l_price, l_wallet);
                dap_chain_wallet_close(l_wallet);
                if (!l_ret) {
                    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_price->tx_hash);
                    dap_string_append_printf(l_str_reply, "Can't invalidate transaction %s\n", l_tx_hash_str);
                    DAP_DELETE(l_tx_hash_str);
                }
                char *l_order_hash_str = dap_chain_hash_fast_to_str_new(&l_price->order_hash);
                if (dap_chain_net_srv_order_delete_by_hash_str(l_price->net_buy, l_order_hash_str)) {
                    dap_string_append_printf(l_str_reply, "Can't remove order %s\n", l_order_hash_str);
                }
                DAP_DELETE(l_order_hash_str);
                DAP_DELETE(l_price->wallet_str);
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
                uint256_t l_value = dap_chain_wallet_get_balance(l_wallet, l_net_sell->pub.id, l_token_sell_str);
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
                HASH_DEL(s_srv_xchange->pricelist, l_price);
                dap_chain_global_db_gr_del( l_price->key_ptr, GROUP_LOCAL_XCHANGE);
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
                dap_chain_net_srv_order_delete_by_hash_str(l_price->net_buy, l_order_hash_str);
                DAP_DELETE(l_order_hash_str);
                l_order_hash_str = s_xchange_order_create(l_price, l_tx);
                if (l_order_hash_str) {
                    dap_chain_hash_fast_from_str(l_order_hash_str, &l_price->order_hash);
                    if(!s_xchange_tx_put(l_tx, l_net_buy)) {
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't put transaction to mempool");
                        dap_chain_net_srv_order_delete_by_hash_str(l_net_buy, l_order_hash_str);
                        DAP_DELETE(l_order_hash_str);
                        return -15;
                    }
                    if (!s_xchange_db_add(l_price)) {
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't save price in database");
                        dap_chain_net_srv_order_delete_by_hash_str(l_net_buy, l_order_hash_str);
                        DAP_DELETE(l_order_hash_str);
                        return -16;
                    }
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_str);
                    DAP_DELETE(l_order_hash_str);
                } else {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Can't compose the order");
                    DAP_DELETE(l_price->wallet_str);
                    DAP_DELETE(l_price->key_ptr);
                    DAP_DELETE(l_price);
                    return -18;
                }
                // Update the pricelist
                HASH_ADD_KEYPTR(hh, s_srv_xchange->pricelist, l_price->key_ptr, strlen(l_price->key_ptr), l_price);
            }
        } break;
        case CMD_LIST: {
            dap_chain_net_srv_xchange_price_t *l_price = NULL, *l_tmp;
            dap_string_t *l_reply_str = dap_string_new("");
            HASH_ITER(hh, s_srv_xchange->pricelist, l_price, l_tmp) {
                char *l_order_hash_str = dap_chain_hash_fast_to_str_new(&l_price->order_hash);
                dap_string_append_printf(l_reply_str, "%s %s %s %s %s %s %s %s\n", l_order_hash_str, l_price->token_sell,
                                         l_price->net_sell->pub.name, l_price->token_buy, l_price->net_buy->pub.name,
                                         dap_chain_balance_print(l_price->datoshi_sell), dap_chain_balance_print(l_price->rate), l_price->wallet_str);
                DAP_DELETE(l_order_hash_str);
            }
            if (!l_reply_str->len) {
                dap_string_append(l_reply_str, "Pricelist is empty");
            }
            *a_str_reply = dap_string_free(l_reply_str, false);
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

static int s_cli_srv_xchange(int a_argc, char **a_argv, char **a_str_reply)
{
    enum {
        CMD_NONE, CMD_PRICE, CMD_ORDERS, CMD_PURCHASE, CMD_ENABLE, CMD_DISABLE, CMD_TX_LIST
    };
    int l_arg_index = 1;
    int l_cmd_num = CMD_NONE;
    if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "price", NULL)) {
        l_cmd_num = CMD_PRICE;
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
    switch (l_cmd_num) {
        case CMD_PRICE:
            return s_cli_srv_xchange_price(a_argc, a_argv, l_arg_index + 1, a_str_reply);
        case CMD_ORDERS: {
            const char *l_net_str = NULL;
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
            char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group(l_net);
            size_t l_orders_count = 0;
            dap_global_db_obj_t * l_orders = dap_chain_global_db_gr_load(l_gdb_group_str, &l_orders_count);
            dap_chain_net_srv_xchange_price_t *l_price;
            dap_string_t *l_reply_str = dap_string_new("");
            for (size_t i = 0; i < l_orders_count; i++) {
                dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)l_orders[i].value;
                if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_XCHANGE_ID)
                    continue;
                // TODO add filters to list (tokens, network, etc.)
                l_price = s_xchange_price_from_order(l_net, l_order);
                dap_string_append_printf(l_reply_str, "%s %s %s %s %s %s %s\n", l_orders[i].key, l_price->token_sell,
                                         l_price->net_sell->pub.name, l_price->token_buy, l_price->net_buy->pub.name,
                                         dap_chain_balance_print(l_price->datoshi_sell), dap_chain_balance_print(l_price->rate));
                DAP_DELETE(l_price);
            }
            dap_chain_global_db_objs_delete(l_orders, l_orders_count);
            DAP_DELETE( l_gdb_group_str);
            if (!l_reply_str->len) {
                dap_string_append(l_reply_str, "No orders found");
            }
            *a_str_reply = dap_string_free(l_reply_str, false);
        } break;
        case CMD_PURCHASE: {
            const char *l_net_str = NULL, *l_wallet_str = NULL, *l_order_hash_str = NULL, *l_val_sell_str = NULL;
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
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-coins", &l_val_sell_str);
            if (!l_val_sell_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'purchase' required parameter -coins");
                return -8;
            }
            uint256_t l_datoshi_sell = dap_chain_balance_scan(l_val_sell_str);
            if (IS_ZERO_256(l_datoshi_sell)) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Format -coins <unsigned long long>");
                return -9;
            }
            dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
            if (l_order) {
                dap_chain_net_srv_xchange_price_t *l_price = s_xchange_price_from_order(l_net, l_order);
                l_price->datoshi_sell = l_datoshi_sell;
                // Create conditional transaction
                dap_chain_datum_tx_t *l_tx = s_xchange_tx_create_exchange(l_price, &l_order->tx_cond_hash, l_wallet);
                if (l_tx && s_xchange_tx_put(l_tx, l_net)) {
                    // TODO send request to seller to update / delete order & price
                    dap_chain_net_srv_order_delete_by_hash_str(l_price->net_buy, l_order_hash_str);
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
            const char *l_net_str = NULL;
            const char *l_time_begin_str = NULL;
            const char *l_time_end_str = NULL;
            l_arg_index++;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-time_from", &l_time_begin_str);
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-time_to", &l_time_end_str);
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
            // Prepare output string
            dap_string_t *l_reply_str = dap_string_new("");
            // Find transactions using filter function s_filter_tx_list()
            dap_list_t *l_datum_list0 = dap_chain_datum_list(l_net, NULL, s_filter_tx_list, l_time);
            size_t l_datum_num = dap_list_length(l_datum_list0);
            if(l_datum_num > 0) {
                dap_string_append_printf(l_reply_str, "Found %zu transactions:\n", l_datum_num);
                dap_list_t *l_datum_list = l_datum_list0;
                char *l_hash_str = DAP_NEW_SIZE(char, DAP_CHAIN_HASH_FAST_STR_SIZE+1);
                while(l_datum_list) {
                    dap_chain_datum_tx_t *l_datum_tx = (dap_chain_datum_tx_t*) ((dap_chain_datum_t*) l_datum_list->data)->data;
                    size_t l_datum_tx_size = dap_chain_datum_tx_get_size(l_datum_tx);
                    // Delimiter between tx
                    if(l_datum_list != l_datum_list0) {
                        dap_string_append(l_reply_str, "\n\n");
                    }
                    // Tx hash
                    dap_hash_fast_t l_hash;
                    memset(&l_hash, 0, sizeof(dap_hash_fast_t));
                    dap_hash_fast(l_datum_tx, l_datum_tx_size, &l_hash);
                    dap_chain_hash_fast_to_str(&l_hash, l_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE + 1);
                    dap_string_append_printf(l_reply_str, "hash: %s\n", l_hash_str);
                    // Find SRV_XCHANGE out_cond item
                    dap_chain_tx_out_cond_t *l_out_cond_item = NULL;
                    int l_item_idx = 0;
                    do {
                        l_out_cond_item = (dap_chain_tx_out_cond_t*) dap_chain_datum_tx_item_get(l_datum_tx, &l_item_idx, TX_ITEM_TYPE_OUT_COND, NULL);
                        l_item_idx++;
                        if(l_out_cond_item && l_out_cond_item->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE) {
                            const char *token = l_out_cond_item->subtype.srv_xchange.token;
                            uint256_t value = l_out_cond_item->subtype.srv_xchange.value;
                            char *value_str = dap_cvt_uint256_to_str(value);
                            dap_string_append_printf(l_reply_str, "value: %s %s", value_str, token);
                            DAP_DELETE(value_str);
                        }
                    }
                    while(l_out_cond_item);
                    l_datum_list = dap_list_next(l_datum_list);
                }
                DAP_DELETE(l_hash_str);
            }
            else{
                dap_string_append(l_reply_str, "Transactions not found");
            }
            dap_list_free(l_datum_list0);
            *a_str_reply = dap_string_free(l_reply_str, false);
        }
            break;
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
