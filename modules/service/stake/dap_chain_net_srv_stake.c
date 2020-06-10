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
#include "dap_string.h"
#include "dap_chain_common.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_mempool.h"
#include "dap_chain_net_srv_common.h"
#include "dap_chain_net_srv_stake.h"

#define LOG_TAG "dap_chain_net_srv_stake"

static int s_cli_srv_stake(int a_argc, char **a_argv, void *a_arg_func, char **a_str_reply);

static dap_chain_net_srv_stake_t *s_srv_stake;

/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @param vpn_addr Zero if only client mode. Address if the node shares its local VPN
 * @param vpn_mask Zero if only client mode. Mask if the node shares its local VPN
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_stake_init()
{
    dap_chain_node_cli_cmd_item_create("srv_stake", s_cli_srv_stake, NULL, "Delegated stake service commands",
    "srv_stake order create -net <net name> -from_addr <addr> -token <ticker> -coins <value> -to_addr <addr> -fee_percent <value>\n"
        "\tCreate a new order with specified amount of datoshi to delegate it to the specified address."
        "The fee with specified percent with this delagation will be returned to the fee address pointed by delegator\n"
    "srv_stake order remove -net <net name> -order <order hash>\n"
         "\tRemove order with specified hash\n"
    "srv_stake order update -net <net name> -order <order hash> {-from_addr <addr> | -token <ticker> -coins <value> | "
                                                                "-to_addr <addr> | -fee_percent <value>}\n"
         "\tUpdate order with specified hash\n"
    "srv_stake order list -net <net name>\n"
         "\tGet the stake orders list within specified net name\n"
    "srv_stake delegate -order <order hash> -net <net name> -wallet <wallet_name> -fee_addr <addr>\n"
         "\tDelegate tokens with specified order within specified net name. Specify fee address\n"
    "srv_stake transactions -net <net name> {-addr <addr from>}"
         "\tShow the list of active stake transactions (optional delegated from addr)"
    "srv_stake invalidate -net <net name> -tx <transaction hash> -wallet <wallet name>"
         "\tInvalidate stake transaction by hash within net name and return stake to specified wallet"
    );
    s_srv_stake = DAP_NEW_Z(dap_chain_net_srv_stake_t);
    uint16_t l_net_count;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    for (uint16_t i = 0; i < l_net_count; i++) {
        dap_ledger_t *l_ledger = l_net_list[i]->pub.ledger;
        dap_chain_datum_tx_t *l_tx_tmp;
        dap_chain_hash_fast_t l_tx_cur_hash = { 0 }; // start hash
        dap_chain_tx_out_cond_t *l_out_cond;
        int l_out_cond_idx;
        char l_token[DAP_CHAIN_TICKER_SIZE_MAX];
        // Find all transactions
        do {
            l_tx_tmp = dap_chain_ledger_tx_cache_find_out_cond(l_ledger, &l_tx_cur_hash, &l_out_cond, &l_out_cond_idx, l_token);
            if (!l_tx_tmp) {
                break;
            }
            if (l_out_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE)
                continue;
            if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, &l_tx_cur_hash, l_out_cond_idx))
                continue;
            // Create the stake item
            dap_chain_net_srv_stake_item_t *l_stake = DAP_NEW_Z(dap_chain_net_srv_stake_item_t);
            l_stake->net = l_net_list[i];
            dap_stpcpy(l_stake->token, l_token);
            l_stake->value = l_out_cond->header.value;
            dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_tx_tmp, NULL,
                    TX_ITEM_TYPE_SIG, NULL);
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
            dap_chain_hash_fast_t l_pkey_hash;
            if (!dap_sign_get_pkey_hash(l_sign, &l_pkey_hash)) {
                continue;
            }
            dap_chain_addr_fill(&l_stake->addr_from, l_sign->header.type, &l_pkey_hash, &l_net_list[i]->pub.id);
            memcpy(&l_stake->addr_to, l_out_cond->params, sizeof(dap_chain_addr_t));
            memcpy(&l_stake->addr_fee, &l_out_cond->subtype.srv_stake.fee_addr, sizeof(dap_chain_addr_t));
            l_stake->fee_value = l_out_cond->subtype.srv_stake.fee_value;
            memcpy(&l_stake->tx_hash, &l_tx_cur_hash, sizeof(dap_chain_hash_fast_t));
            HASH_ADD(hh, s_srv_stake->itemlist, tx_hash, sizeof(dap_chain_hash_fast_t), l_stake);
        } while (l_tx_tmp);
    }
    DAP_DELETE(l_net_list);
    return 0;
}

void dap_chain_net_srv_stake_deinit()
{
    dap_chain_net_srv_stake_item_t *l_stake = NULL, *l_tmp;
    HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp) {
        HASH_DEL(s_srv_stake->itemlist, l_stake);
        DAP_DELETE(l_stake);
    }
    DAP_DELETE(s_srv_stake);
}

bool dap_chain_net_srv_stake_verificator(dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx)
{
    UNUSED(a_cond);
    UNUSED(a_tx);
    return false;
}

bool dap_chain_net_srv_stake_validator(dap_chain_net_t *a_net, dap_chain_datum_tx_t *a_tx)
{
    dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL,
            TX_ITEM_TYPE_SIG, NULL);
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
    dap_chain_hash_fast_t l_pkey_hash;
    if (!dap_sign_get_pkey_hash(l_sign, &l_pkey_hash)) {    // invalid tx
        return false;
    }
    dap_chain_addr_t l_addr_to;
    dap_chain_addr_fill(&l_addr_to, l_sign->header.type, &l_pkey_hash, &a_net->pub.id);
    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    HASH_FIND(hh, s_srv_stake->itemlist, &l_addr_to, sizeof(dap_chain_addr_t), l_stake);
    if (l_stake == NULL) { // public key not delegated for this network
        return true;
    }
    uint64_t l_outs_sum = 0, l_fee_sum = 0;
    dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
    uint32_t l_out_idx_tmp = 0; // current index of 'out' item
    for (dap_list_t *l_list_tmp = l_list_out_items; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), l_out_idx_tmp++) {
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_list_tmp->data;
        if (l_type == TX_ITEM_TYPE_OUT_COND) {
            dap_chain_tx_out_cond_t *l_out_cond = (dap_chain_tx_out_cond_t *)l_list_tmp->data;
            l_outs_sum += l_out_cond->header.value;
        }
        if (l_type == TX_ITEM_TYPE_OUT) {
            dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t *)l_list_tmp->data;
            if (memcmp(&l_stake->addr_fee, &l_out->addr, sizeof(dap_chain_addr_t))) {
                l_fee_sum += l_out->header.value;
            } else {
                l_outs_sum += l_out->header.value;
            }
        } else { // TX_ITEM_TYPE_OUT_EXT
            dap_chain_tx_out_ext_t *l_out_ext = (dap_chain_tx_out_ext_t *)l_list_tmp->data;
            if (memcmp(&l_stake->addr_fee, &l_out_ext->addr, sizeof(dap_chain_addr_t))) {
                l_fee_sum += l_out_ext->header.value;
            } else {
                l_outs_sum += l_out_ext->header.value;
            }
        }
    }
    dap_list_free(l_list_out_items);
    if (l_outs_sum * l_stake->fee_value / 100.0 < l_fee_sum) {
        return false;
    }
    return true;
}

static dap_chain_datum_tx_t *s_stake_tx_create(dap_chain_net_srv_stake_item_t *a_stake, dap_chain_wallet_t *a_wallet)
{
    if (!a_stake || !a_stake->net || !a_stake->addr_to.addr_ver || !a_stake->addr_from.addr_ver ||
            !a_stake->addr_fee.addr_ver || !*a_stake->token || !a_wallet) {
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_stake->net->pub.name);
    dap_chain_addr_t *l_owner_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_stake->net->pub.id);
    if (memcmp(l_owner_addr, &a_stake->addr_from, sizeof(dap_chain_addr_t))) {
        log_it(L_WARNING, "Odree and wallet address do not match");
        return NULL;
    }
    dap_enc_key_t *l_owner_key = dap_chain_wallet_get_key(a_wallet, 0);
    uint64_t l_value_sell = 0; // how many coins to transfer
    // list of transaction with 'out' items to sell
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_stake->token, l_owner_addr, a_stake->value, &l_value_sell);
    if(!l_list_used_out) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_owner_addr);
        log_it(L_WARNING, "Nothing to change (not enough funds)");
        return NULL;
    }

    // add 'in' items to sell
    uint64_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, free);
    if (l_value_to_items != l_value_sell) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_owner_addr);
        log_it(L_ERROR, "Can't compose the transaction input");
        return NULL;
    }

    // add 'out_cond' & 'out' items
    {
        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_ID };
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_stake(l_uid, a_stake->value, a_stake->fee_value, &a_stake->addr_fee,
                                                                                              (void *)&a_stake->addr_to, sizeof(dap_chain_addr_t));
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_owner_addr);
            log_it(L_ERROR, "Can't compose the transaction conditional output");
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
        // coin back
        uint64_t l_value_back = l_value_sell - a_stake->value;
        if (l_value_back) {
            if (dap_chain_datum_tx_add_out_item(&l_tx, l_owner_addr, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                DAP_DELETE(l_owner_addr);
                log_it(L_ERROR, "Cant add coin back output");
                return NULL;
            }
        }
    }
    DAP_DELETE(l_owner_addr);

    // add 'sign' item
    if(dap_chain_datum_tx_add_sign_item(&l_tx, l_owner_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_ERROR, "Can't add sign output");
        return NULL;
    }

    return l_tx;
}

// Put the transaction to mempool or directly to chains & write transaction's hash to the price
static bool s_stake_tx_put(dap_chain_datum_tx_t *a_tx, dap_chain_net_t *a_net)
{
    // Put the transaction to mempool or directly to chains
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, a_tx, l_tx_size);
    DAP_DELETE(a_tx);
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    if (!l_chain) {
        return false;
    }
    // Processing will be made according to autoprocess policy
    if (dap_chain_mempool_datum_add(l_datum, l_chain)) {
        DAP_DELETE(l_datum);
        return false;
    }
    return true;
}

static bool s_stake_tx_invalidate(dap_chain_net_srv_stake_item_t *a_stake, dap_chain_wallet_t *a_wallet)
{
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_stake->net->pub.name);
    dap_chain_addr_t *l_owner_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_stake->net->pub.id);
    dap_enc_key_t *l_owner_key = dap_chain_wallet_get_key(a_wallet, 0);

    // create and add reciept
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 = SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_ID };
    dap_chain_datum_tx_receipt_t *l_receipt =  dap_chain_datum_tx_receipt_create(l_uid, l_unit, 0, a_stake->value, NULL, 0);
    dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_receipt);
    DAP_DELETE(l_receipt);

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &a_stake->tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return false;
    }   
    int l_prev_cond_idx;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, &l_prev_cond_idx);
    if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, &a_stake->tx_hash, l_prev_cond_idx)) {
        log_it(L_WARNING, "Requested conditional transaction is already used out");
        return false;
    }
    dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_stake->tx_hash, l_prev_cond_idx, 0);

    // add 'out' item
    if (dap_chain_datum_tx_add_out_item(&l_tx, l_owner_addr, l_tx_out_cond->header.value) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_owner_addr);
        log_it(L_ERROR, "Cant add returning coins output");
        return false;
    }
    DAP_DELETE(l_owner_addr);

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, l_owner_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        return false;
    }
    if (!s_stake_tx_put(l_tx, a_stake->net)) {
        return false;
    }
    return true;
}

char *s_stake_order_create(dap_chain_net_srv_stake_item_t *a_item)
{
    dap_chain_hash_fast_t l_tx_hash = {};
    dap_srv_stake_order_ext_t l_ext;
    memcpy(&l_ext.addr_from, &a_item->addr_from, sizeof(dap_chain_addr_t));
    memcpy(&l_ext.addr_to, &a_item->addr_to, sizeof(dap_chain_addr_t));
    l_ext.fee_value = a_item->fee_value;
    uint32_t l_ext_size = sizeof(dap_srv_stake_order_ext_t);
    dap_chain_node_addr_t *l_node_addr = dap_chain_net_get_cur_addr(a_item->net);
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 =  SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_ID };
    char *l_order_hash_str = dap_chain_net_srv_order_create(a_item->net, SERV_DIR_BUY, l_uid, *l_node_addr,
                                                            l_tx_hash, a_item->value, l_unit, a_item->token, 0,
                                                            (uint8_t *)&l_ext, l_ext_size, NULL, 0, NULL);
    return l_order_hash_str;
}

dap_chain_net_srv_stake_item_t *s_stake_item_from_order(dap_chain_net_t *a_net, dap_chain_net_srv_order_t *a_order)
{
    dap_chain_net_srv_stake_item_t *l_item = DAP_NEW_Z(dap_chain_net_srv_stake_item_t);
    dap_srv_stake_order_ext_t *l_ext = (dap_srv_stake_order_ext_t *)a_order->ext;
    memcpy(&l_item->addr_from, &l_ext->addr_from, sizeof(dap_chain_addr_t));
    memcpy(&l_item->addr_to, &l_ext->addr_to, sizeof(dap_chain_addr_t));
    l_item->fee_value = l_ext->fee_value;
    l_item->net = a_net;
    l_item->value = a_order->price;
    strcpy(l_item->token, a_order->price_ticker);
    return l_item;
}

static int s_cli_srv_stake_order(int a_argc, char **a_argv, int a_arg_index, char **a_str_reply)
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
    switch (l_cmd_num) {
        case CMD_CREATE: {
            const char *l_net_str = NULL, *l_token_str = NULL, *l_coins_str = NULL;
            const char *l_addr_from_str = NULL, *l_addr_to_str = NULL, *l_fee_str = NULL;
            dap_chain_net_t *l_net = NULL;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order create' required parameter -net");
                return -3;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_token_str);
            if (!l_token_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order create' required parameter -token");
                return -5;
            }
            if (!dap_chain_ledger_token_ticker_check(l_net->pub.ledger, l_token_str)) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Token ticker %s not found", l_token_str);
                return -6;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-coins", &l_coins_str);
            if (!l_coins_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order create' required parameter -coins");
                return -7;
            }
            uint64_t l_value = strtoull(l_coins_str, NULL, 10);
            if (!l_value) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Format -coins <unsigned long long>");
                return -8;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-addr_from", &l_addr_from_str);
            if (!l_addr_from_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order create' required parameter -addr_from");
                return -9;
            }
            dap_chain_addr_t *l_addr_from = dap_chain_addr_from_str(l_addr_from_str);
            if (!l_addr_from) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Wrong address format");
                return -10;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-addr_to", &l_addr_to_str);
            if (!l_addr_to_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order create' required parameter -addr_to");
                return -9;
            }
            dap_chain_addr_t *l_addr_to = dap_chain_addr_from_str(l_addr_to_str);
            if (!l_addr_to) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Wrong address format");
                return -10;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-fee_percent", &l_fee_str);
            if (!l_fee_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order create' required parameter -fee_percent");
                return -11;
            }
            long double l_fee = strtold(l_fee_str, NULL);
            if (!l_fee) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Format -fee_percent <long double> %");
                return -12;
            }
            // Create the stake item
            dap_chain_net_srv_stake_item_t *l_stake = DAP_NEW_Z(dap_chain_net_srv_stake_item_t);
            l_stake->net = l_net;
            dap_stpcpy(l_stake->token, l_token_str);
            l_stake->value = l_value;
            memcpy(&l_stake->addr_from, l_addr_from, sizeof(dap_chain_addr_t));
            memcpy(&l_stake->addr_to, l_addr_to, sizeof(dap_chain_addr_t));
            DAP_DELETE(l_addr_from);
            DAP_DELETE(l_addr_to);
            l_stake->fee_value = l_fee;
            // Create the order & put it to GDB
            char *l_order_hash_str = s_stake_order_create(l_stake);
            if (l_order_hash_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_str);
                DAP_DELETE(l_order_hash_str);
                DAP_DELETE(l_stake);
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't compose the order");
                DAP_DELETE(l_stake);
                return -15;
            }
        } break;
        case CMD_REMOVE: {
            const char *l_net_str = NULL, *l_order_hash_str = NULL;
            dap_chain_net_t *l_net = NULL;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order remove' requires parameter -net");
                return -3;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order remove' requires parameter -order");
                return -13;
            }
            if (dap_chain_net_srv_order_delete_by_hash_str(l_net, l_order_hash_str)) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't remove order %s\n", l_order_hash_str);
                return -14;
            }
            dap_chain_node_cli_set_reply_text(a_str_reply, "Stake order successfully removed");
        } break;
        case CMD_UPDATE: {
            const char *l_net_str = NULL, *l_token_str = NULL, *l_coins_str = NULL;
            const char *l_addr_from_str = NULL, *l_addr_to_str = NULL, *l_fee_str = NULL;
            char *l_order_hash_str = NULL;
            dap_chain_net_t *l_net = NULL;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order update' required parameter -net");
                return -3;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order update' requires parameter -order");
                return -13;
            }
            dap_chain_net_srv_order_t *l_order =  dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
            if (!l_order) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't find order %s\n", l_order_hash_str);
                return -14;
            }
            dap_chain_net_srv_stake_item_t *l_stake = s_stake_item_from_order(l_net, l_order);
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_token_str);
            if (l_token_str) {
                if (!dap_chain_ledger_token_ticker_check(l_net->pub.ledger, l_token_str)) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Token ticker %s not found", l_token_str);
                    return -6;
                }
                strcpy(l_stake->token, l_token_str);
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-coins", &l_coins_str);
            if (l_coins_str) {
                uint64_t l_value = strtoull(l_coins_str, NULL, 10);
                if (!l_value) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Format -coins <unsigned long long>");
                    return -8;
                }
                l_stake->value = l_value;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-addr_from", &l_addr_from_str);
            if (l_addr_from_str) {
                dap_chain_addr_t *l_addr_from = dap_chain_addr_from_str(l_addr_from_str);
                if (!l_addr_from) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Wrong address format");
                    return -10;
                }
                memcpy(&l_stake->addr_from, l_addr_from, sizeof(dap_chain_addr_t));
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-addr_to", &l_addr_to_str);
            if (l_addr_to_str) {
                dap_chain_addr_t *l_addr_to = dap_chain_addr_from_str(l_addr_to_str);
                if (!l_addr_to) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Wrong address format");
                    return -10;
                }
                memcpy(&l_stake->addr_to, l_addr_to, sizeof(dap_chain_addr_t));
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-fee_percent", &l_fee_str);
            if (l_fee_str) {
                long double l_fee = strtold(l_fee_str, NULL);
                if (!l_fee) {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Format -fee_percent <long double> %");
                    return -12;
                }
            }
            if (!l_token_str && !l_coins_str && !l_addr_from_str && !l_addr_to_str && !l_fee_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "At least one of updating parameters is mandatory");
                return -16;
            }
            // Create the order & put it to GDB
            dap_chain_net_srv_order_delete_by_hash_str(l_net, l_order_hash_str);
            l_order_hash_str = s_stake_order_create(l_stake);
            if (l_order_hash_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_str);
                DAP_DELETE(l_order_hash_str);
                DAP_DELETE(l_stake);
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't compose the order");
                DAP_DELETE(l_stake);
                return -15;
            }
        } break;
        case CMD_LIST: {
            const char *l_net_str = NULL;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'order list' required parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group(l_net);
            size_t l_orders_count = 0;
            dap_global_db_obj_t * l_orders = dap_chain_global_db_gr_load(l_gdb_group_str, &l_orders_count);
            dap_chain_net_srv_stake_item_t *l_stake;
            dap_string_t *l_reply_str = dap_string_new("");
            for (size_t i = 0; i < l_orders_count; i++) {
                dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)l_orders[i].value;
                if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_ID)
                    continue;
                // TODO add filters to list (token, address, etc.)
                l_stake = s_stake_item_from_order(l_net, l_order);
                char *l_addr = dap_chain_addr_to_str(&l_stake->addr_to);
                dap_string_append_printf(l_reply_str, "%s %lu %s %s %llf\n", l_orders[i].key, l_stake->value, l_stake->token,
                                         l_addr, l_stake->fee_value);
                DAP_DELETE(l_addr);
                DAP_DELETE(l_stake);
            }
            dap_chain_global_db_objs_delete(l_orders, l_orders_count);
            DAP_DELETE( l_gdb_group_str);
            if (!l_reply_str->len) {
                dap_string_append(l_reply_str, "No orders found");
            }
            *a_str_reply = dap_string_free(l_reply_str, false);
        } break;
        default: {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Subcommand %s not recognized", a_argv[a_arg_index]);
            return -2;
        }
    }
    return 0;
}

static int s_cli_srv_stake(int a_argc, char **a_argv, void *a_arg_func, char **a_str_reply)
{
    UNUSED(a_arg_func);
    enum {
        CMD_NONE, CMD_ORDER, CMD_DELEGATE, CMD_TX, CMD_INVALIDATE
    };
    int l_arg_index = 1;
    int l_cmd_num = CMD_NONE;
    if (dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "order", NULL)) {
        l_cmd_num = CMD_ORDER;
    }
    else if (dap_chain_node_cli_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "delegate", NULL)) {
        l_cmd_num = CMD_DELEGATE;
    }
    switch (l_cmd_num) {
        case CMD_ORDER:
            return s_cli_srv_stake_order(a_argc, a_argv, l_arg_index + 1, a_str_reply);
        case CMD_DELEGATE: {
            const char *l_net_str = NULL, *l_wallet_str = NULL, *l_order_hash_str = NULL, *l_addr_fee_str = NULL;
            l_arg_index++;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'delegate' required parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_wallet_str);
            if (!l_wallet_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'delegate' required parameter -wallet");
                return -17;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
            if (!l_wallet) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Specified wallet not found");
                return -18;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'delegate' required parameter -order");
                return -13;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-fee_addr", &l_addr_fee_str);
            if (!l_addr_fee_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'delegate' required parameter -fee_addr");
                return -9;
            }
            dap_chain_addr_t *l_addr_fee = dap_chain_addr_from_str(l_addr_fee_str);
            if (!l_addr_fee) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Wrong address format");
                return -10;
            }
            dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
            if (l_order) {
                dap_chain_net_srv_stake_item_t *l_stake = s_stake_item_from_order(l_net, l_order);
                memcpy(&l_stake->addr_fee, l_addr_fee, sizeof(dap_chain_addr_t));
                DAP_DELETE(l_addr_fee);
                // Create conditional transaction
                dap_chain_datum_tx_t *l_tx = s_stake_tx_create(l_stake, l_wallet);
                dap_chain_wallet_close(l_wallet);
                if (l_tx && s_stake_tx_put(l_tx, l_net)) {
                    // TODO send request to order owner to delete it
                    dap_chain_net_srv_order_delete_by_hash_str(l_net, l_order_hash_str);
                }
                DAP_DELETE(l_order);
                dap_chain_node_cli_set_reply_text(a_str_reply, l_tx ? "Stake transaction has done" :
                                                                      "Stake transaction error");
                if (!l_tx) {
                    DAP_DELETE(l_stake);
                    return -19;
                }
                HASH_ADD(hh, s_srv_stake->itemlist, addr_to, sizeof(dap_chain_addr_t), l_stake);
            } else {
                DAP_DELETE(l_addr_fee);
                dap_chain_node_cli_set_reply_text(a_str_reply, "Specified order not found");
                return -14;
            }
        } break;
        case CMD_TX: {
            const char *l_net_str = NULL;
            l_arg_index++;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'transactions' required parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_chain_net_srv_stake_item_t *l_stake = NULL, *l_tmp;
            dap_string_t *l_reply_str = dap_string_new("");
            HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp) {
                if (l_stake->net->pub.id.uint64 != l_net->pub.id.uint64) {
                    continue;
                }
                char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_stake->tx_hash);
                char *l_addr_from_str = dap_chain_addr_to_str(&l_stake->addr_from);
                char *l_addr_to_str = dap_chain_addr_to_str(&l_stake->addr_to);
                char *l_addr_fee_str = dap_chain_addr_to_str(&l_stake->addr_fee);
                dap_string_append_printf(l_reply_str, "%s %s %lu %s %s %s %llf\n", l_tx_hash_str, l_stake->token,
                                         l_stake->value, l_addr_from_str, l_addr_to_str,
                                         l_addr_fee_str, l_stake->fee_value);
                DAP_DELETE(l_tx_hash_str);
                DAP_DELETE(l_addr_from_str);
                DAP_DELETE(l_addr_to_str);
                DAP_DELETE(l_addr_fee_str);
            }
            if (!l_reply_str->len) {
                dap_string_append(l_reply_str, "Pricelist is empty");
            }
            *a_str_reply = dap_string_free(l_reply_str, false);
        } break;
        case CMD_INVALIDATE: {
            const char *l_net_str = NULL, *l_wallet_str = NULL, *l_tx_hash_str = NULL;
            l_arg_index++;
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'delegate' required parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_wallet_str);
            if (!l_wallet_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'delegate' required parameter -wallet");
                return -17;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
            if (!l_wallet) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Specified wallet not found");
                return -18;
            }
            dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
            if (!l_tx_hash_str) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Command 'delegate' required parameter -tx");
                return -13;
            }
            dap_chain_hash_fast_t l_tx_hash = {};
            dap_chain_str_to_hash_fast(l_tx_hash_str, &l_tx_hash);
            dap_chain_net_srv_stake_item_t *l_stake = NULL, *l_tmp;
            HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp) {
                if (!memcmp(&l_stake->tx_hash, &l_tx_hash, sizeof(dap_chain_hash_fast_t))) {
                    break;
                }
            }
            if (!l_stake) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Transaction %s not found", l_tx_hash_str);
                dap_chain_wallet_close(l_wallet);
                return -20;
            }
            bool l_success = s_stake_tx_invalidate(l_stake, l_wallet);
            dap_chain_wallet_close(l_wallet);
            if (l_success) {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Stake successfully returned to owner");
                HASH_DEL(s_srv_stake->itemlist, l_stake);
            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Can't invalidate transaction %s", l_tx_hash_str);
                return -21;
            }
        } break;
        default: {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Command %s not recognized", a_argv[l_arg_index]);
            return -1;
        }
    }
    return 0;
}
