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

#include "dap_string.h"
#include "dap_chain_common.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_mempool.h"
#include "dap_chain_net_srv_common.h"
#include "dap_chain_net_srv_xchange.h"

#define LOG_TAG "dap_chain_net_srv_xchange"

static int s_cli_srv_xchange(int a_argc, char **a_argv, void *a_arg_func, char **a_str_reply);
static int s_callback_requested(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_error(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_receipt_next_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size);

static dap_chain_net_srv_xchange_t *s_srv_xchange;

/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @param vpn_addr Zero if only client mode. Address if the node shares its local VPN
 * @param vpn_mask Zero if only client mode. Mask if the node shares its local VPN
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_xchange_init()
{
        dap_chain_node_cli_cmd_item_create("srv_xchange", s_cli_srv_xchange, NULL, "eXchange service commands",
        "srv_xchange price create -net_sell <net name> -token_sell <token ticker> -net_buy <net_name> -token_buy <token ticker>"
                                            "-wallet <name> -datoshi_sell <value> -datoshi_buy <value>\n"
            "\tCreate a new price with specified amounts of datoshi to exchange\n"
        "srv_xchange price remove -net_sell <net name> -token_sell <token ticker> -net_buy <net_name> -token_buy <token ticker>\n"
             "\tRemove price with specified tickers within specified net names\n"
        "srv_xchange price list\n"
             "\tList all active prices\n"
        "srv_xchange price update -net_sell <net name> -token_sell <token ticker> -net_buy <net_name> -token_buy <token ticker>"
                                            "{-datoshi_sell <value> | datoshi_buy <value> | -wallet <name>}\n"
             "\tUpdate price with specified tickers within specified net names\n"
        "srv_xchange purchase <order hash> -net <net name> -wallet <wallet_name>\n"
             "\tExchange tokens with specified order within specified net name\n"
        "srv_xchange enable\n"
             "\tEnable eXchange service\n"
        "srv_xchange disable\n"
             "\tDisable eXchange service\n"
        );
        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
        dap_chain_net_srv_t* l_srv = dap_chain_net_srv_add(l_uid, s_callback_requested, s_callback_response_success,
                                                           s_callback_response_error, s_callback_receipt_next_success);
        s_srv_xchange  = DAP_NEW_Z(dap_chain_net_srv_xchange_t);
        l_srv->_inhertor = s_srv_xchange;
        s_srv_xchange->enabled = false;
        return 0;
}

void dap_chain_net_srv_xchange_deinit()
{
    dap_chain_net_srv_xchange_price_t *l_price = NULL, *l_tmp;
    HASH_ITER(hh, s_srv_xchange->pricelist, l_price, l_tmp) {
        HASH_DEL(s_srv_xchange->pricelist, l_price);
        DAP_DELETE(l_price->key_ptr);
        DAP_DELETE(l_price);
    }
    dap_chain_net_srv_del(s_srv_xchange->parent);
    DAP_DELETE(s_srv_xchange);
}

bool dap_chain_net_srv_xchange_verificator(dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx)
{
    /* Check only one of following conditions for verification success
     * 1. addr(a_cond.params).data.key == a_tx.sign.pkey -- for condition owner
     * 2. a_cond.srv_xchange.(value && token && addr) == a_tx.out.(value && token && addr) -- for exchange
     */
    dap_chain_addr_t *l_seller_addr = (dap_chain_addr_t *)a_cond->params;
    dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
    size_t l_pkey_ser_size = 0;
    const uint8_t *l_pkey_ser = dap_sign_get_pkey(l_sign, &l_pkey_ser_size);
    if (!memcmp(l_seller_addr->data.key, l_pkey_ser, l_pkey_ser_size)) {
        // it's the condition owner, let the transaction to be performed
        return true;
    } else {
        dap_list_t *l_list_out = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT, NULL);

        uint64_t l_out_val = 0;
        for (dap_list_t *l_list_tmp = l_list_out;l_list_tmp;  l_list_tmp = l_list_tmp->next) {
            dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t *)l_list_tmp->data;
            if (memcmp(&l_tx_out->addr, &a_cond->params, sizeof(dap_chain_addr_t)) ||
                    strcmp(l_tx_out->token, a_cond->subtype.srv_xchange.token)) {
                continue;
            }
            l_out_val += l_tx_out->header.value;
        }
        if (l_out_val != a_cond->subtype.srv_xchange.value) {
            return false;
        }
    }
    return true;
}

static dap_chain_datum_tx_receipt_t *s_xchage_receipt_create(dap_chain_net_srv_xchange_price_t *a_price)
{
    uint32_t l_ext_size = sizeof(uint64_t) + DAP_CHAIN_TICKER_SIZE_MAX;
    uint8_t *l_ext = DAP_NEW_SIZE(uint8_t, l_ext_size);
    dap_lendian_put64(l_ext, a_price->datoshi_sell);
    strcpy((char *)&l_ext[sizeof(uint64_t)], a_price->token_sell);
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 = SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
    dap_chain_datum_tx_receipt_t *l_receipt =  dap_chain_datum_tx_receipt_create(l_uid, l_unit, 0, a_price->datoshi_buy,
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
    uint64_t l_value_sell = 0; // how many coins to transfer
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
    uint64_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, free);
    if (l_value_to_items != l_value_sell) {
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
        uint64_t l_value_back = l_value_sell - a_price->datoshi_sell;
        if (l_value_back) {
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

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_price->net_sell->pub.name);
    dap_chain_addr_t *l_seller_addr = (dap_chain_addr_t *) dap_chain_wallet_get_addr(a_wallet, a_price->net_sell->pub.id);
    dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);
    uint64_t l_value_sell = 0; // how many coins to transfer
    // list of transaction with 'out' items to sell
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_price->token_sell,
                                                                             l_seller_addr, a_price->datoshi_sell, &l_value_sell);
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
    uint64_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, free);
    if (l_value_to_items != l_value_sell) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_seller_addr);
        log_it(L_ERROR, "Can't compose the transaction input");
        return NULL;
    }
    // add 'in' item to buy from conditional transaction
    int l_prev_cond_idx = 0;
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, a_tx_cond_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return NULL;
    }
    dap_chain_tx_out_cond_t *l_tx_out_cond  = (dap_chain_tx_out_cond_t *)dap_chain_datum_tx_item_get(
                                               l_cond_tx, &l_prev_cond_idx, TX_ITEM_TYPE_OUT_COND, NULL);
    dap_chain_datum_tx_add_in_cond_item(&l_tx, a_tx_cond_hash, l_prev_cond_idx, 0);

    // add 'out' items
    {
        // transfer selling coins
        const dap_chain_addr_t *l_buyer_addr = (dap_chain_addr_t *)l_tx_out_cond->params;
        dap_chain_tx_out_t *l_tx_out = dap_chain_datum_tx_item_out_create(l_buyer_addr, a_price->datoshi_sell, a_price->token_sell);
        if (l_tx_out) {
            dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
            DAP_DELETE(l_tx_out);
        } else {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_seller_addr);
            log_it(L_ERROR, "Can't add selling coins output");
            return NULL;
        }
        // coin back
        uint64_t l_value_back = l_value_sell - a_price->datoshi_sell;
        if (l_value_back) {
            l_tx_out = dap_chain_datum_tx_item_out_create(l_seller_addr, l_value_back, a_price->token_sell);
            if (l_tx_out) {
                dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
                DAP_DELETE(l_tx_out);
            } else {
                dap_chain_datum_tx_delete(l_tx);
                DAP_DELETE(l_seller_addr);
                log_it(L_ERROR, "Can't add selling coins back output");
                return NULL;
            }
        }
        //transfer buying coins
        l_tx_out = dap_chain_datum_tx_item_out_create(l_seller_addr, a_price->datoshi_buy, a_price->token_buy);
        if (l_tx_out) {
            dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
            DAP_DELETE(l_tx_out);
        } else {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_seller_addr);
            log_it(L_ERROR, "Cant add buying coins output");
            return NULL;
        }
        DAP_DELETE(l_seller_addr);
        //transfer unbuying coins (partial exchange)
        uint64_t l_buying_value = l_tx_out_cond->header.value;
        l_value_back = l_buying_value - a_price->datoshi_buy;
        if (l_value_back) {
            /*l_tx_out = dap_chain_datum_tx_item_out_create(l_buyer_addr, l_value_back, a_price->token_buy);
            if (l_tx_out) {
                dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
                DAP_DELETE(l_tx_out);
            } else {
                dap_chain_datum_tx_delete(l_tx);*/
                log_it(L_WARNING, "Partial exchange not allowed");
                return NULL;
            //}
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
        return false;
    }
    dap_chain_node_role_t l_role = dap_chain_net_get_role(a_net);
    size_t l_datums_number;
    switch (l_role.enums) {
        case NODE_ROLE_ROOT:
        case NODE_ROLE_MASTER:
        case NODE_ROLE_ROOT_MASTER:
        case NODE_ROLE_CELL_MASTER:
            l_datums_number = l_chain->callback_datums_pool_proc(l_chain, &l_datum, 1);
            break;
        default:
            l_datums_number = dap_chain_mempool_datum_add(l_datum, l_chain);
    }
    if(!l_datums_number) {
        DAP_DELETE(l_datum);
        return false;
    }
    return true;
}

static bool s_xchage_tx_invalidate(dap_chain_net_srv_xchange_price_t *a_price, dap_chain_wallet_t *a_wallet)
{
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_price->net_sell->pub.name);
    dap_chain_addr_t *l_seller_addr = (dap_chain_addr_t *) dap_chain_wallet_get_addr(a_wallet, a_price->net_sell->pub.id);
    dap_enc_key_t *l_seller_key = dap_chain_wallet_get_key(a_wallet, 0);

    // create and add reciept
    dap_chain_datum_tx_receipt_t *l_receipt = s_xchage_receipt_create(a_price);
    dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_receipt);
    DAP_DELETE(l_receipt);

    // add 'in' item to buy from conditional transaction
    int l_prev_cond_idx = 0;
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &a_price->tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return false;
    }
    dap_chain_tx_out_cond_t *l_tx_out_cond  = (dap_chain_tx_out_cond_t *)dap_chain_datum_tx_item_get(
                                               l_cond_tx, &l_prev_cond_idx, TX_ITEM_TYPE_OUT_COND, NULL);
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
    if (!s_xchange_tx_put(l_tx, a_price->net_sell)) {
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
    dap_lendian_put64((uint8_t *)&l_ext.net_sell_id, a_price->net_sell->pub.id.uint64);
    dap_lendian_put64((uint8_t *)&l_ext.datoshi_sell, a_price->datoshi_sell);
    strcpy(l_ext.token_sell, a_price->token_sell);
    uint32_t l_ext_size = sizeof(dap_srv_xchange_order_ext_t);
    dap_chain_node_addr_t *l_node_addr = dap_chain_net_get_cur_addr(a_price->net_sell);
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 =  SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID };
    char *l_order_hash_str = dap_chain_net_srv_order_create(a_price->net_buy, SERV_DIR_SELL, l_uid, *l_node_addr,
                                                            l_tx_hash, a_price->datoshi_buy, l_unit, a_price->token_buy, 0,
                                                            (uint8_t *)&l_ext, l_ext_size, NULL, 0);
    return l_order_hash_str;
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
            const char *l_val_sell_str = NULL, *l_val_buy_str = NULL, *l_wallet_str = NULL;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-datoshi_sell", &l_val_sell_str);
            if (!l_val_sell_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price create' required parameter -datoshi_sell");
                return -8;
            }
            uint64_t l_datoshi_sell = strtoull(l_val_sell_str, NULL, 10);
            if (!l_datoshi_sell) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Format -datoshi_sell <unsigned long long>");
                return -9;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-datoshi_buy", &l_val_buy_str);
            if (!l_val_buy_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'price create' required parameter -datoshi_buy");
                return -8;
            }
            uint64_t l_datoshi_buy = strtoull(l_val_buy_str, NULL, 10);
            if (!l_datoshi_buy) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Format -datoshi_buy <unsigned long long>");
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
            if (dap_chain_wallet_get_balance(l_wallet, l_net_sell->pub.id, l_token_sell_str) < l_datoshi_sell) {
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
            l_price->datoshi_buy = l_datoshi_buy;
            // Create conditional transaction
            dap_chain_datum_tx_t *l_tx = s_xchange_tx_create_request(l_price, l_wallet);
            dap_chain_wallet_close(l_wallet);
            if (!l_tx) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't compose the conditional transaction");
                DAP_DELETE(l_price);
                break;
            }
            // Create the order & put it to GDB
            char *l_order_hash_str = s_xchange_order_create(l_price, l_tx);
            if (l_order_hash_str) {
                dap_chain_str_to_hash_fast(l_order_hash_str, &l_price->order_hash);
                if(!s_xchange_tx_put(l_tx, l_net_buy)) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Can't put transaction to mempool/chains");
                    dap_chain_net_srv_order_delete_by_hash_str(l_net_buy, l_order_hash_str);
                    DAP_DELETE(l_order_hash_str);
                    break;
                }
                dap_chain_node_cli_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_str);
                DAP_DELETE(l_order_hash_str);
                // Add active price to pricelist
                HASH_ADD_KEYPTR(hh, s_srv_xchange->pricelist, l_price->key_ptr, strlen(l_price->key_ptr), l_price);
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't compose the order");
                DAP_DELETE(l_price->key_ptr);
                DAP_DELETE(l_price);
            }
        } break;
        case CMD_REMOVE:
        case CMD_UPDATE: {
            dap_chain_net_srv_xchange_price_t *l_price = NULL;
            HASH_FIND_STR(s_srv_xchange->pricelist, l_strkey, l_price);
            if (l_price) {
                if (l_cmd_num == CMD_REMOVE) {
                    dap_string_t *l_str_reply = dap_string_new("");
                    HASH_DEL(s_srv_xchange->pricelist, l_price);
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
                    DAP_DELETE(l_price->key_ptr);
                    DAP_DELETE(l_price->wallet_str);
                    DAP_DELETE(l_price);
                    if (!l_str_reply->len) {
                        dap_string_append(l_str_reply, "Price successfully removed");
                    }
                    *a_str_reply = dap_string_free(l_str_reply, false);
                } else {    // CMD_UPDATE
                    const char *l_val_sell_str = NULL, *l_val_buy_str = NULL, *l_wallet_str = NULL, *l_new_wallet_str = NULL;
                    uint64_t l_datoshi_sell = 0, l_datoshi_buy = 0;
                    dap_chain_wallet_t *l_wallet = NULL;
                    dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-datoshi_sell", &l_val_sell_str);
                    if (l_val_sell_str) {
                        l_datoshi_sell = strtoull(l_val_sell_str, NULL, 10);
                        if (!l_datoshi_sell) {
                            dap_chain_node_cli_set_reply_text(a_str_reply, "Format -datoshi_sell <unsigned long long>");
                            return -9;
                        }
                    }
                    dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-datoshi_buy", &l_val_buy_str);
                    if (l_val_buy_str) {
                        l_datoshi_buy = strtoull(l_val_buy_str, NULL, 10);
                        if (!l_datoshi_buy) {
                            dap_chain_node_cli_set_reply_text(a_str_reply, "Format -datoshi_buy <unsigned long long>");
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
                    if (!l_val_sell_str && !l_val_buy_str && !l_wallet_str) {
                        dap_chain_node_cli_set_reply_text(a_str_reply, "At least one of updating parameters is mandatory");
                        return -13;
                    }
                    if (l_datoshi_sell && dap_chain_wallet_get_balance(l_wallet, l_net_sell->pub.id, l_token_sell_str) < l_datoshi_sell) {
                            dap_chain_node_cli_set_reply_text(a_str_reply, "Not enough cash in specified wallet");
                            dap_chain_wallet_close(l_wallet);
                            return -12;
                    }
                    if (l_val_sell_str) {
                        l_price->datoshi_sell = l_datoshi_sell;
                    }
                    if (l_val_buy_str) {
                        l_price->datoshi_buy = l_datoshi_buy;
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
                        break;
                    }
                    HASH_DEL(s_srv_xchange->pricelist, l_price);
                    bool l_ret = s_xchage_tx_invalidate(l_price, l_wallet); // may be changed to old price later
                    dap_chain_wallet_close(l_wallet);
                    if (!l_ret) {
                        char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_price->tx_hash);
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't invalidate transaction %s\n", l_tx_hash_str);
                        DAP_DELETE(l_tx_hash_str);
                        break;
                    }
                    // Update the order
                    char *l_order_hash_str = dap_chain_hash_fast_to_str_new(&l_price->order_hash);
                    dap_chain_net_srv_order_delete_by_hash_str(l_price->net_buy, l_order_hash_str);
                    DAP_DELETE(l_order_hash_str);
                    l_order_hash_str = s_xchange_order_create(l_price, l_tx);
                    if (l_order_hash_str) {
                        dap_chain_str_to_hash_fast(l_order_hash_str, &l_price->order_hash);
                        if(!s_xchange_tx_put(l_tx, l_net_buy)) {
                            dap_chain_node_cli_set_reply_text(a_str_reply, "Can't put transaction to mempool/chains");
                            dap_chain_net_srv_order_delete_by_hash_str(l_net_buy, l_order_hash_str);
                            break;
                        } else {
                            dap_chain_node_cli_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_str);
                        }
                        DAP_DELETE(l_order_hash_str);
                    } else {
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't compose the order");
                        DAP_DELETE(l_price->key_ptr);
                        DAP_DELETE(l_price);
                        break;
                    }
                    // Update the pricelist
                    HASH_ADD_KEYPTR(hh, s_srv_xchange->pricelist, l_price->key_ptr, strlen(l_price->key_ptr), l_price);
                }
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Price with provided pair of token ticker + net name is not exist");
                return -1;
            }
        } break;
        case CMD_LIST: {
            dap_chain_net_srv_xchange_price_t *l_price = NULL, *l_tmp;
            dap_string_t *l_reply_str = dap_string_new("");
            HASH_ITER(hh, s_srv_xchange->pricelist, l_price, l_tmp) {
                char *l_order_hash_str = dap_chain_hash_fast_to_str_new(&l_price->order_hash);
                dap_string_append_printf(l_reply_str, "%s\t%s\t%s\t%s\t%lu\t%lu\t%s\t%s\n", l_price->token_sell, l_price->net_sell->pub.name,
                                         l_price->token_buy, l_price->net_buy->pub.name, l_price->datoshi_sell,
                                         l_price->datoshi_buy, l_price->wallet_str, l_order_hash_str);
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

static int s_cli_srv_xchange(int a_argc, char **a_argv, void *a_arg_func, char **a_str_reply)
{
    UNUSED(a_arg_func);
    enum {
        CMD_NONE, CMD_PRICE, CMD_PURCHASE, CMD_ENABLE, CMD_DISABLE
    };
    int l_arg_index = 1;
    int l_cmd_num = CMD_NONE;
    if(dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "price", NULL)) {
        l_cmd_num = CMD_PRICE;
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
    switch (l_cmd_num) {
        case CMD_PRICE:
            return s_cli_srv_xchange_price(a_argc, a_argv, l_arg_index + 1, a_str_reply);
        case CMD_PURCHASE: {
            const char *l_net_str = NULL, *l_wallet_str = 0;
            dap_chain_node_cli_find_option_val(a_argv, ++l_arg_index + 1, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'purchase' required parameter -net");
                return -2;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -3;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index + 1, a_argc, "-wallet", &l_wallet_str);
            if (!l_wallet_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'purchase' required parameter -wallet");
                return -10;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
            if (!l_wallet) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Specified wallet not found");
                return -11;
            }
            char *l_order_hash_str = a_argv[l_arg_index];
            dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
            if (l_order) {
                dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW(dap_chain_net_srv_xchange_price_t);
                l_price->net_sell = l_net;
                strcpy(l_price->token_sell, l_order->price_ticker);
                l_price->datoshi_sell = l_order->price;
                dap_srv_xchange_order_ext_t *l_ext = (dap_srv_xchange_order_ext_t *)l_order->ext;
                dap_chain_net_id_t l_net_buy_id = { .uint64 = dap_lendian_get64((uint8_t *)&l_ext->net_sell_id) };
                l_price->net_buy = dap_chain_net_by_id(l_net_buy_id);
                l_price->datoshi_buy = dap_lendian_get64((uint8_t *)&l_ext->datoshi_sell);
                strcpy(l_price->token_buy, l_ext->token_sell);
                // Create conditional transaction
                dap_chain_datum_tx_t *l_tx = s_xchange_tx_create_exchange(l_price, &l_order->tx_cond_hash, l_wallet);
                if (l_tx && s_xchange_tx_put(l_tx, l_net)) {
                    // TODO send request to seller to delete order & price
                    dap_chain_net_srv_order_delete_by_hash_str(l_price->net_buy, l_order_hash_str);
                }
                DAP_DELETE(l_price);
                DAP_DELETE(l_order);
                dap_chain_node_cli_set_reply_text(a_str_reply, l_tx ? "Exchange transaction has done" :
                                                                      "Exchange transaction error");
            }
        } break;
        case CMD_ENABLE: {
            s_srv_xchange->enabled = true;
        } break;
        case CMD_DISABLE: {
            s_srv_xchange->enabled = false;
        } break;
        default: {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Command %s not recognized", a_argv[l_arg_index]);
            return -1;
        }
    }
    return 0;
}

static int s_callback_requested(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size)
{
    return 0;
}

static int s_callback_response_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size)
{
    return 0;
}

static int s_callback_response_error(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size)
{
    return 0;
}

static int s_callback_receipt_next_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_t *a_srv_client, const void *a_data, size_t a_data_size)
{
    return 0;
}
