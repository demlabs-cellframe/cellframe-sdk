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
#include "dap_config.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_enc_base58.h"
#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "json_object.h"

#include "rand/dap_rand.h"
#include "dap_chain_node_client.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_chain_node_cli_cmd.h"

#define LOG_TAG "dap_chain_net_srv_stake_pos_delegate"

#define DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_GDB_GROUP "delegate_keys"

static int s_cli_srv_stake(int a_argc, char **a_argv, void **reply);

static bool s_stake_verificator_callback(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond,
                                                      dap_chain_datum_tx_t *a_tx_in, bool a_owner);
static void s_stake_updater_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_cond);

static void s_cache_data(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_addr_t *a_signing_addr);

static void s_stake_clear();

static void s_stake_net_clear(dap_chain_net_t *a_net);

static dap_chain_net_srv_stake_t *s_srv_stake = NULL;

/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_stake_pos_delegate_init()
{
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, s_stake_verificator_callback, s_stake_updater_callback);
    dap_cli_server_cmd_add("srv_stake", s_cli_srv_stake, "Delegated stake service commands",
    "\t\t=== Commands for work with orders ===\n"
    "srv_stake order create -net <net_name> -value <value> -cert <priv_cert_name> \n"
        "\tCreates a new order signed with a delegated key, which declares the commission for which \n"
        "\tthe node agrees to conduct the transaction.\n"
    "srv_stake order remove -net <net_name> -order <ip_addr> [-H {hex | base58(default)}]\n"
         "\tRemove order with specified hash\n"
    "srv_stake order update -net <net_name> -order <ip_addr> [-H {hex | base58(default)}] -cert <priv_cert_name>  -value <value>\n"
         "\tUpdate order with specified hash\n"
    "srv_stake order list -net <net_name>\n"
         "\tGet the fee orders list within specified net name\n"
     "\t\t === Commands for work with stake delegate ===\n"
    "srv_stake delegate -cert <pub_cert_name> -net <net_name> -w <wallet_name> -value <datoshi> [-node_addr <node_addr>] -fee <value> \n"
         "\tDelegate public key in specified certificate with specified net name. Pay with specified value of m-tokens of native net token.\n"
    "srv_stake approve -net <net_name> -tx <transaction_hash> -poa_cert <priv_cert_name>\n"
         "\tApprove stake transaction by root node certificate within specified net name\n"
    "srv_stake list keys -net <net_name> [-cert <delegated_cert> | -pkey <pkey_hash_str>]\n"
         "\tShow the list of active stake keys (optional delegated with specified cert).\n"
    "srv_stake list tx -net <net_name> \n"
         "\tShow the list of key delegation transactions.\n"
    "srv_stake invalidate -net <net_name> {-tx <transaction_hash> | -cert <delegated_cert> | -cert_pkey_hash <pkey_hash>}"
                            " {-w <wallet_name> -fee <value> | -poa_cert <cert_name>}\n"
         "\tInvalidate requested delegated stake transaction by hash or cert name or cert pkey hash within net name and"
         " return m-tokens to specified wallet (if any)\n"
    "srv_stake min_value -net <net_name> -cert <cert_name> -value <value>\n"
         "\tSets the minimum stake value\n"
    "srv_stake check -net <net_name> -tx <tx_hash>\n"
         "\tCheck remote validator"
    );

    s_srv_stake = DAP_NEW_Z(dap_chain_net_srv_stake_t);
    if (!s_srv_stake) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    s_srv_stake->delegate_allowed_min = dap_chain_coins_to_balance("1.0");

    return 0;
}

/**
 * @brief delete ht and hh concretic net from s_srv_stake 
 */
void s_stake_net_clear(dap_chain_net_t *a_net)
{
    dap_chain_net_srv_stake_item_t *l_stake = NULL, *l_tmp = NULL;
    HASH_ITER(ht, s_srv_stake->tx_itemlist, l_stake, l_tmp) {
        // Clang bug at this, l_stake should change at every loop cycle
        if (l_stake->net->pub.id.uint64 == a_net->pub.id.uint64)
            HASH_DELETE(ht, s_srv_stake->tx_itemlist, l_stake);
    }
    HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp) {
        // Clang bug at this, l_stake should change at every loop cycle
        if (l_stake->net->pub.id.uint64 == a_net->pub.id.uint64) {
            HASH_DEL(s_srv_stake->itemlist, l_stake);
            DAP_DELETE(l_stake);
        }
    }
    dap_chain_net_srv_stake_cache_item_t *l_cache_item = NULL, *l_cache_tmp = NULL;
    HASH_ITER(hh, s_srv_stake->cache, l_cache_item, l_cache_tmp) {
        // Clang bug at this, l_stake should change at every loop cycle
        if (l_cache_item->signing_addr.net_id.uint64 == a_net->pub.id.uint64) {
            HASH_DEL(s_srv_stake->cache, l_cache_item);
            DAP_DELETE(l_cache_item);
        }
    }
}

/**
 * @brief delete all nets ht and hh from s_srv_stake 
 */
void s_stake_clear()
{
    uint16_t l_net_count;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    for (uint16_t i = 0; i < l_net_count; i++) {
        s_stake_net_clear(l_net_list[i]);
    }
}

void dap_chain_net_srv_stake_pos_delegate_deinit()
{
    s_stake_clear();
    DAP_DEL_Z(s_srv_stake);
}

static bool s_stake_verificator_callback(dap_ledger_t UNUSED_ARG *a_ledger, dap_chain_tx_out_cond_t UNUSED_ARG *a_cond,
                                         dap_chain_datum_tx_t UNUSED_ARG *a_tx_in, bool a_owner)
{
    assert(s_srv_stake);
    if (!a_owner)
        return false;
    return true;
}

static void s_stake_updater_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_cond)
{
    assert(s_srv_stake);
    if (!a_cond)
        return;
    dap_chain_addr_t *l_signing_addr = &a_cond->subtype.srv_stake_pos_delegate.signing_addr;
    dap_chain_net_srv_stake_key_invalidate(l_signing_addr);
    s_cache_data(a_ledger, a_tx, l_signing_addr);
}

static bool s_srv_stake_is_poa_cert(dap_chain_net_t *a_net, dap_enc_key_t *a_key)
{
    bool l_is_poa_cert = false;
    dap_pkey_t *l_pkey = dap_pkey_from_enc_key(a_key);
    for (dap_list_t *it = a_net->pub.decree->pkeys; it; it = it->next)
        if (dap_pkey_compare(l_pkey, (dap_pkey_t *)it->data)) {
            l_is_poa_cert = true;
            break;
        }
    DAP_DELETE(l_pkey);
    return l_is_poa_cert;
}

void dap_chain_net_srv_stake_key_delegate(dap_chain_net_t *a_net, dap_chain_addr_t *a_signing_addr, dap_hash_fast_t *a_stake_tx_hash,
                                          uint256_t a_value, dap_chain_node_addr_t *a_node_addr)
{
    assert(s_srv_stake);
    if (!a_signing_addr || !a_node_addr || !a_stake_tx_hash)
        return;
    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    bool l_found = false;
    HASH_FIND(hh, s_srv_stake->itemlist, a_signing_addr, sizeof(dap_chain_addr_t), l_stake);
    if (!l_stake)
        l_stake = DAP_NEW_Z(dap_chain_net_srv_stake_item_t);
    else {
        l_found = true;
        HASH_DELETE(ht, s_srv_stake->tx_itemlist, l_stake);
    }
    l_stake->net = a_net;
    l_stake->node_addr = *a_node_addr;
    l_stake->signing_addr = *a_signing_addr;
    l_stake->value = a_value;
    l_stake->tx_hash = *a_stake_tx_hash;
    l_stake->is_active = true;
    if (!l_found)
        HASH_ADD(hh, s_srv_stake->itemlist, signing_addr, sizeof(dap_chain_addr_t), l_stake);
    if (!dap_hash_fast_is_blank(a_stake_tx_hash))
        HASH_ADD(ht, s_srv_stake->tx_itemlist, tx_hash, sizeof(dap_chain_hash_fast_t), l_stake);
    char l_key_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&a_signing_addr->data.hash_fast,
                               l_key_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
    char *l_value_str = dap_chain_balance_to_coins(a_value);
    log_it(L_NOTICE, "Added key with fingerprint %s and value %s for node "NODE_ADDR_FP_STR,
                        l_key_hash_str, l_value_str, NODE_ADDR_FP_ARGS(a_node_addr));
    DAP_DELETE(l_value_str);
}

void dap_chain_net_srv_stake_key_invalidate(dap_chain_addr_t *a_signing_addr)
{
    assert(s_srv_stake);
    if (!a_signing_addr)
        return;
    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    HASH_FIND(hh, s_srv_stake->itemlist, a_signing_addr, sizeof(dap_chain_addr_t), l_stake);
    if (l_stake) {
        HASH_DEL(s_srv_stake->itemlist, l_stake);
        HASH_DELETE(ht, s_srv_stake->tx_itemlist, l_stake);
        char l_key_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(&a_signing_addr->data.hash_fast,
                                   l_key_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
        char *l_value_str = dap_chain_balance_to_coins(l_stake->value);
        log_it(L_NOTICE, "Removed key with fingerprint %s and value %s for node "NODE_ADDR_FP_STR,
                            l_key_hash_str, l_value_str, NODE_ADDR_FP_ARGS_S(l_stake->node_addr));
        DAP_DELETE(l_value_str);
        DAP_DELETE(l_stake);
    }
}

void dap_chain_net_srv_stake_set_allowed_min_value(uint256_t a_value)
{
    assert(s_srv_stake);
    s_srv_stake->delegate_allowed_min = a_value;
    for (dap_chain_net_srv_stake_item_t *it = s_srv_stake->itemlist; it; it = it->hh.next)
        if (dap_hash_fast_is_blank(&it->tx_hash))
            it->value = a_value;
}

uint256_t dap_chain_net_srv_stake_get_allowed_min_value()
{
    assert(s_srv_stake);
    return s_srv_stake->delegate_allowed_min;
}

int dap_chain_net_srv_stake_key_delegated(dap_chain_addr_t *a_signing_addr)
{
    assert(s_srv_stake);
    if (!a_signing_addr)
        return 0;

    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    HASH_FIND(hh, s_srv_stake->itemlist, a_signing_addr, sizeof(dap_chain_addr_t), l_stake);
    if (l_stake) // public key delegated for this network
        return l_stake->is_active ? 1 : -1;
    return 0;
}

dap_list_t *dap_chain_net_srv_stake_get_validators(dap_chain_net_id_t a_net_id, bool a_is_active)
{
    dap_list_t *l_ret = NULL;
    if (!s_srv_stake || !s_srv_stake->itemlist)
        return l_ret;
    for (dap_chain_net_srv_stake_item_t *l_stake = s_srv_stake->itemlist; l_stake; l_stake = l_stake->hh.next)
        if (a_net_id.uint64 == l_stake->signing_addr.net_id.uint64 &&
                l_stake->is_active == a_is_active)
            l_ret = dap_list_append(l_ret, DAP_DUP(l_stake));
    return l_ret;
}

dap_chain_node_addr_t *dap_chain_net_srv_stake_key_get_node_addr(dap_chain_addr_t *a_signing_addr)
{
    assert(s_srv_stake);
    if (!a_signing_addr)
        NULL;

    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    HASH_FIND(hh, s_srv_stake->itemlist, a_signing_addr, sizeof(dap_chain_addr_t), l_stake);
    if (l_stake) // public key delegated for this network
        return &l_stake->node_addr;
    return NULL;
}

int dap_chain_net_srv_stake_mark_validator_active(dap_chain_addr_t *a_signing_addr, bool a_on_off)
{
    assert(s_srv_stake);
    if (!a_signing_addr)
        return -1;

    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    HASH_FIND(hh, s_srv_stake->itemlist, a_signing_addr, sizeof(dap_chain_addr_t), l_stake);
    if (l_stake) { // public key delegated for this network
        l_stake->is_active = a_on_off;
        return 0;
    }
    return -2;
}

int dap_chain_net_srv_stake_verify_key_and_node(dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_node_addr)
{
    assert(s_srv_stake);
    if (!a_signing_addr || !a_node_addr){
        log_it(L_WARNING, "Bad srv_stake_verify arguments");
        return -100;
    }

    dap_chain_net_srv_stake_item_t *l_stake = NULL, *l_tmp = NULL;
    HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp){
        //check key not activated for other node
        if(dap_chain_addr_compare(a_signing_addr, &l_stake->signing_addr)){
            char l_key_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&a_signing_addr->data.hash_fast,
                                       l_key_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            log_it(L_WARNING, "Key %s already active for node "NODE_ADDR_FP_STR,
                                l_key_hash_str, NODE_ADDR_FP_ARGS_S(l_stake->node_addr));
            return -101;
        }

        //chek node have not other delegated key
        if(a_node_addr->uint64 == l_stake->node_addr.uint64){
            char l_key_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_stake->signing_addr.data.hash_fast,
                                       l_key_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            log_it(L_WARNING, "Node "NODE_ADDR_FP_STR" already have active key %s",
                                NODE_ADDR_FP_ARGS(a_node_addr), l_key_hash_str);
            return -102;
        }
    }

    return 0;
}

static bool s_stake_cache_check_tx(dap_hash_fast_t *a_tx_hash)
{
    dap_chain_net_srv_stake_cache_item_t *l_stake;
    HASH_FIND(hh, s_srv_stake->cache, a_tx_hash, sizeof(*a_tx_hash), l_stake);
    if (l_stake) {
        dap_chain_net_srv_stake_key_invalidate(&l_stake->signing_addr);
        return true;
    }
    return false;
}

int dap_chain_net_srv_stake_load_cache(dap_chain_net_t *a_net)
{
    if (!a_net) {
        log_it(L_ERROR, "Invalid argument a_net in dap_chain_net_srv_stake_load_cache");
        return -1;
    }
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    if(!l_ledger) {
        log_it(L_ERROR, "Invalid arguments l_ledger in dap_chain_net_srv_stake_load_cache");
        return -1;
    }
    if (!dap_ledger_cache_enabled(l_ledger))
        return 0;
    char *l_gdb_group = dap_ledger_get_gdb_group(l_ledger, DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_GDB_GROUP);
    size_t l_objs_count = 0;
    dap_store_obj_t *l_store_obj = dap_global_db_get_all_raw_sync(l_gdb_group, 0, &l_objs_count);
    if (!l_objs_count || !l_store_obj) {
        log_it(L_ATT, "Stake cache data not found");
        return -1;
    }
    for (size_t i = 0; i < l_objs_count; i++){
        dap_chain_net_srv_stake_cache_data_t *l_cache_data =
                (dap_chain_net_srv_stake_cache_data_t *)l_store_obj[i].value;
        dap_chain_net_srv_stake_cache_item_t *l_cache = DAP_NEW_Z(dap_chain_net_srv_stake_cache_item_t);
        if (!l_cache) {
            log_it(L_CRITICAL, "Memory allocation error");
            return -1;
        }
        l_cache->signing_addr   = l_cache_data->signing_addr;
        l_cache->tx_hash        = l_cache_data->tx_hash;
        HASH_ADD(hh, s_srv_stake->cache, tx_hash, sizeof(dap_hash_fast_t), l_cache);
    }
    dap_store_obj_free(l_store_obj, l_objs_count);
    dap_ledger_set_cache_tx_check_callback(l_ledger, s_stake_cache_check_tx);
    return 0;
}

void dap_chain_net_srv_stake_purge(dap_chain_net_t *a_net)
{
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    char *l_gdb_group = dap_ledger_get_gdb_group(l_ledger, DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_GDB_GROUP);
    dap_global_db_del(l_gdb_group, NULL, NULL, NULL);
    DAP_DELETE(l_gdb_group);
    s_stake_net_clear(a_net);
}


// Freeze staker's funds when delegating a key
static dap_chain_datum_tx_t *s_stake_tx_create(dap_chain_net_t * a_net, dap_chain_wallet_t *a_wallet,
                                               uint256_t a_value, uint256_t a_fee,
                                               dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_node_addr)
{
    if (!a_net || !a_wallet || IS_ZERO_256(a_value) || !a_signing_addr || !a_node_addr)
        return NULL;



    const char *l_native_ticker = a_net->pub.native_ticker;
    char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, l_native_ticker);
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);
    uint256_t l_value_transfer = {}, l_fee_transfer = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
    dap_chain_addr_t *l_owner_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t l_net_fee_addr;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_fee_addr);
    if (l_net_fee_used)
        SUM_256_256(l_fee_total, l_net_fee, &l_fee_total);
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_delegated_ticker,
                                                                             l_owner_addr, a_value, &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_WARNING, "Nothing to pay for delegate (not enough funds)");
        DAP_DELETE(l_owner_addr);
        return NULL;
    }
    dap_list_t *l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                            l_owner_addr, l_fee_total, &l_fee_transfer);
    if (!l_list_fee_out) {
        log_it(L_WARNING, "Nothing to pay for fee (not enough funds)");
        DAP_DELETE(l_owner_addr);
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in' items to pay for delegate
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
        log_it(L_ERROR, "Can't compose the transaction input");
        goto tx_fail;
    }
    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        log_it(L_ERROR, "Can't compose the transaction input");
        goto tx_fail;
    }

    // add 'out_cond' & 'out_ext' items
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
    dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_stake(l_uid, a_value, a_signing_addr, a_node_addr);
    if (!l_tx_out) {
        log_it(L_ERROR, "Can't compose the transaction conditional output");
        goto tx_fail;
    }
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
    DAP_DELETE(l_tx_out);
    // coin back
    uint256_t l_value_back = {};
    SUBTRACT_256_256(l_value_transfer, a_value, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_owner_addr, l_value_back, l_delegated_ticker) != 1) {
            log_it(L_ERROR, "Cant add coin back output");
            goto tx_fail;
        }
    }

    // add fee items
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    uint256_t l_fee_back = {};
    // fee coin back
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if(!IS_ZERO_256(l_fee_back)) {
        if(dap_chain_datum_tx_add_out_ext_item(&l_tx, l_owner_addr, l_fee_back, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }

    // add 'sign' item
    if(dap_chain_datum_tx_add_sign_item(&l_tx, dap_chain_wallet_get_key(a_wallet, 0)) != 1) {
        log_it(L_ERROR, "Can't add sign output");
        goto tx_fail;
    }
    DAP_DELETE(l_owner_addr);
    return l_tx;

tx_fail:
    dap_chain_datum_tx_delete(l_tx);
    DAP_DELETE(l_owner_addr);
    return NULL;
}

// Put the transaction to mempool
static char *s_stake_tx_put(dap_chain_datum_tx_t *a_tx, dap_chain_net_t *a_net)
{
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, a_tx, l_tx_size);
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    if (!l_chain) {
        return NULL;
    }
    // Processing will be made according to autoprocess policy
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    return l_ret;
}

dap_chain_datum_decree_t *dap_chain_net_srv_stake_decree_approve(dap_chain_net_t *a_net, dap_hash_fast_t *a_stake_tx_hash, dap_cert_t *a_cert)
{
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);

    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(l_ledger, a_stake_tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return NULL;
    }
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx,
                                                  DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_prev_cond_idx);
    if (!l_tx_out_cond) {
        log_it(L_CRITICAL, "Requested conditional transaction has no requires conditional output");
        return NULL;
    }
    dap_hash_fast_t l_spender_hash = { };
    if (dap_ledger_tx_hash_is_used_out_item(l_ledger, a_stake_tx_hash, l_prev_cond_idx, &l_spender_hash)) {
        char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(&l_spender_hash, l_hash_str, sizeof(l_hash_str));
        log_it(L_WARNING, "Requested conditional transaction is already used out by %s", l_hash_str);
        return NULL;
    }
    char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, a_net->pub.native_ticker);
    const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, a_stake_tx_hash);
    if (dap_strcmp(l_tx_ticker, l_delegated_ticker)) {
        log_it(L_WARNING, "Requested conditional transaction have another ticker (not %s)", l_delegated_ticker);
        return NULL;
    }
    if (compare256(l_tx_out_cond->header.value, s_srv_stake->delegate_allowed_min) == -1) {
        log_it(L_WARNING, "Requested conditional transaction have not enough funds");
        return NULL;
    }

    if(dap_chain_net_srv_stake_verify_key_and_node(&l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr, &l_tx_out_cond->subtype.srv_stake_pos_delegate.signer_node_addr)){
        log_it(L_WARNING, "Key and node verification error");
        return NULL;
    }

    // create approve decree
    size_t l_total_tsd_size = 0;
    dap_chain_datum_decree_t *l_decree = NULL;
    dap_list_t *l_tsd_list = NULL;
    dap_tsd_t *l_tsd = NULL;

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(dap_hash_fast_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    if (!l_tsd) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_TX_HASH;
    l_tsd->size = sizeof(dap_hash_fast_t);
    *(dap_hash_fast_t*)(l_tsd->data) = *a_stake_tx_hash;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(uint256_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    if (!l_tsd) {
        log_it(L_CRITICAL, "Memory allocation error");
        dap_list_free_full(l_tsd_list, NULL);
        return NULL;
    }
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE;
    l_tsd->size = sizeof(uint256_t);
    *(uint256_t*)(l_tsd->data) = l_tx_out_cond->header.value;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(dap_chain_addr_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    if (!l_tsd) {
        log_it(L_CRITICAL, "Memory allocation error");
        dap_list_free_full(l_tsd_list, NULL);
        return NULL;
    }
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR;
    l_tsd->size = sizeof(dap_chain_addr_t);
    *(dap_chain_addr_t*)(l_tsd->data) = l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(dap_chain_node_addr_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    if (!l_tsd) {
        log_it(L_CRITICAL, "Memory allocation error");
        dap_list_free_full(l_tsd_list, NULL);
        return NULL;
    }
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNER_NODE_ADDR;
    l_tsd->size = sizeof(dap_chain_node_addr_t);
    *(dap_chain_node_addr_t*)(l_tsd->data) = l_tx_out_cond->subtype.srv_stake_pos_delegate.signer_node_addr;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
    if (!l_decree) {
        log_it(L_CRITICAL, "Memory allocation error");
        dap_list_free_full(l_tsd_list, NULL);
        return NULL;
    }
    l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
    l_decree->header.ts_created = dap_time_now();
    l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
    l_decree->header.common_decree_params.net_id = a_net->pub.id;
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_ANCHOR);
    if (!l_chain)
        l_chain =  dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_ANCHOR);
    if (!l_chain) {
        log_it(L_ERROR, "No chain supported anchor datum type");
        DAP_DEL_Z(l_decree);
        return NULL;
    }
    l_decree->header.common_decree_params.chain_id = l_chain->id;
    l_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(a_net);
    l_decree->header.sub_type = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE;
    l_decree->header.data_size = l_total_tsd_size;
    l_decree->header.signs_size = 0;

    size_t l_data_tsd_offset = 0;
    for ( dap_list_t* l_iter=dap_list_first(l_tsd_list); l_iter; l_iter=l_iter->next){
        dap_tsd_t * l_b_tsd = (dap_tsd_t *) l_iter->data;
        size_t l_tsd_size = dap_tsd_size(l_b_tsd);
        memcpy((byte_t*)l_decree->data_n_signs + l_data_tsd_offset, l_b_tsd, l_tsd_size);
        l_data_tsd_offset += l_tsd_size;
    }
    dap_list_free_full(l_tsd_list, NULL);

    size_t l_cur_sign_offset = l_decree->header.data_size + l_decree->header.signs_size;
    size_t l_total_signs_size = l_decree->header.signs_size;

    dap_sign_t * l_sign = dap_cert_sign(a_cert,  l_decree,
       sizeof(dap_chain_datum_decree_t) + l_decree->header.data_size, 0);

    if (l_sign) {
        size_t l_sign_size = dap_sign_get_size(l_sign);
        l_decree = DAP_REALLOC(l_decree, sizeof(dap_chain_datum_decree_t) + l_cur_sign_offset + l_sign_size);
        memcpy((byte_t*)l_decree->data_n_signs + l_cur_sign_offset, l_sign, l_sign_size);
        l_total_signs_size += l_sign_size;
        l_cur_sign_offset += l_sign_size;
        l_decree->header.signs_size = l_total_signs_size;
        DAP_DELETE(l_sign);
        log_it(L_DEBUG,"<-- Signed with '%s'", a_cert->name);
    }else{
        log_it(L_ERROR, "Decree signing failed");
        DAP_DELETE(l_decree);
        return NULL;
    }

    return l_decree;
}

// Put the decree to mempool
static char *s_stake_decree_put(dap_chain_datum_decree_t *a_decree, dap_chain_net_t *a_net)
{
    size_t l_decree_size = dap_chain_datum_decree_get_size(a_decree);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE, a_decree, l_decree_size);
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_DECREE);
    if (!l_chain)
        l_chain =  dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_DECREE);
    if (!l_chain) {
        log_it(L_ERROR, "No chain supported decree datum type");
        return NULL;
    }
    // Processing will be made according to autoprocess policy
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    return l_ret;
}

static dap_chain_datum_tx_t *s_stake_tx_invalidate(dap_chain_net_t *a_net, dap_hash_fast_t *a_tx_hash, uint256_t a_fee, dap_enc_key_t *a_key)
{
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);

    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(l_ledger, a_tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return NULL;
    }
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx,
                                                  DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_prev_cond_idx);
    if (!l_tx_out_cond) {
        log_it(L_CRITICAL, "Requested conditional transaction has no requires conditional output");
        return NULL;
    }
    dap_hash_fast_t l_spender_hash = { };
    if (dap_ledger_tx_hash_is_used_out_item(l_ledger, a_tx_hash, l_prev_cond_idx, &l_spender_hash)) {
        char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(&l_spender_hash, l_hash_str, sizeof(l_hash_str));
        log_it(L_WARNING, "Requested conditional transaction is already used out by %s", l_hash_str);
        return NULL;
    }
    // Get sign item
    dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get(l_cond_tx, NULL,
            TX_ITEM_TYPE_SIG, NULL);
    // Get sign from sign item
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_sign(&l_owner_addr, l_sign, a_net->pub.id);
    dap_chain_addr_t l_wallet_addr;
    dap_chain_addr_fill_from_key(&l_wallet_addr, a_key, a_net->pub.id);
    if (!dap_chain_addr_compare(&l_owner_addr, &l_wallet_addr)) {
        log_it(L_WARNING, "Trying to invalidate delegating tx with not a owner wallet");
        return NULL;
    }
    const char *l_native_ticker = a_net->pub.native_ticker;
    const char *l_delegated_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, a_tx_hash);
    uint256_t l_fee_transfer = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t l_net_fee_addr;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_fee_addr);
    if (l_net_fee_used)
        SUM_256_256(l_fee_total, l_net_fee, &l_fee_total);
    dap_list_t *l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                            &l_owner_addr, l_fee_total, &l_fee_transfer);
    if (!l_list_fee_out) {
        log_it(L_WARNING, "Nothing to pay for fee (not enough funds)");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_add_in_cond_item(&l_tx, a_tx_hash, l_prev_cond_idx, 0);

    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        log_it(L_ERROR, "Can't compose the transaction input");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // add 'out_ext' item
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_tx_out_cond->header.value, l_delegated_ticker) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_ERROR, "Cant add returning coins output");
        return NULL;
    }
    // add fee items
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    // fee coin back
    uint256_t l_fee_back = {};
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if(!IS_ZERO_256(l_fee_back)) {
        if(dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_fee_back, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        return NULL;
    }
    return l_tx;
}

static dap_chain_datum_decree_t *s_stake_decree_invalidate(dap_chain_net_t *a_net, dap_hash_fast_t *a_stake_tx_hash, dap_cert_t *a_cert)
{
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(l_ledger, a_stake_tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return NULL;
    }
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx,
                                                  DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_prev_cond_idx);
    if (!l_tx_out_cond) {
        log_it(L_CRITICAL, "Requested conditional transaction has no requires conditional output");
        return NULL;
    }

    // create invalidate decree
    size_t l_total_tsd_size = 0;
    dap_chain_datum_decree_t *l_decree = NULL;
    dap_list_t *l_tsd_list = NULL;
    dap_tsd_t *l_tsd = NULL;

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(dap_chain_addr_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    if (!l_tsd) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR;
    l_tsd->size = sizeof(dap_chain_addr_t);
    *(dap_chain_addr_t*)(l_tsd->data) = l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
    if (!l_decree) {
        log_it(L_CRITICAL, "Memory allocation error");
        dap_list_free_full(l_tsd_list, NULL);
        return NULL;
    }
    l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
    l_decree->header.ts_created = dap_time_now();
    l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
    l_decree->header.common_decree_params.net_id = a_net->pub.id;
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_ANCHOR);
    if (!l_chain)
        l_chain =  dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_ANCHOR);
    if (!l_chain) {
        log_it(L_ERROR, "No chain supported anchor datum type");
        DAP_DEL_Z(l_decree);
        dap_list_free_full(l_tsd_list, NULL);
        return NULL;
    }
    l_decree->header.common_decree_params.chain_id = l_chain->id;
    l_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(a_net);
    l_decree->header.sub_type = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE;
    l_decree->header.data_size = l_total_tsd_size;
    l_decree->header.signs_size = 0;

    size_t l_data_tsd_offset = 0;
    for ( dap_list_t* l_iter=dap_list_first(l_tsd_list); l_iter; l_iter=l_iter->next){
        dap_tsd_t * l_b_tsd = (dap_tsd_t *) l_iter->data;
        size_t l_tsd_size = dap_tsd_size(l_b_tsd);
        memcpy((byte_t*)l_decree->data_n_signs + l_data_tsd_offset, l_b_tsd, l_tsd_size);
        l_data_tsd_offset += l_tsd_size;
    }
    dap_list_free_full(l_tsd_list, NULL);

    size_t l_cur_sign_offset = l_decree->header.data_size + l_decree->header.signs_size;
    size_t l_total_signs_size = l_decree->header.signs_size;

    dap_sign_t * l_sign = dap_cert_sign(a_cert,  l_decree,
       sizeof(dap_chain_datum_decree_t) + l_decree->header.data_size, 0);

    if (l_sign) {
        size_t l_sign_size = dap_sign_get_size(l_sign);
        l_decree = DAP_REALLOC(l_decree, sizeof(dap_chain_datum_decree_t) + l_cur_sign_offset + l_sign_size);
        memcpy((byte_t*)l_decree->data_n_signs + l_cur_sign_offset, l_sign, l_sign_size);
        l_total_signs_size += l_sign_size;
        l_cur_sign_offset += l_sign_size;
        l_decree->header.signs_size = l_total_signs_size;
        DAP_DELETE(l_sign);
        log_it(L_DEBUG,"<-- Signed with '%s'", a_cert->name);
    }else{
        log_it(L_ERROR, "Decree signing failed");
        DAP_DELETE(l_decree);
        return NULL;
    }

    return l_decree;
}

static dap_chain_datum_decree_t *s_stake_decree_set_min_stake(dap_chain_net_t *a_net, uint256_t a_value, dap_cert_t *a_cert)
{
    size_t l_total_tsd_size = 0;
    dap_chain_datum_decree_t *l_decree = NULL;
    dap_list_t *l_tsd_list = NULL;
    dap_tsd_t *l_tsd = NULL;

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(uint256_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    if (!l_tsd) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE;
    l_tsd->size = sizeof(uint256_t);
    *(uint256_t*)(l_tsd->data) = a_value;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
    if (!l_decree) {
        log_it(L_CRITICAL, "Memory allocation error");
        dap_list_free_full(l_tsd_list, NULL);
        return NULL;
    }
    l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
    l_decree->header.ts_created = dap_time_now();
    l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
    l_decree->header.common_decree_params.net_id = a_net->pub.id;
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_ANCHOR);
    if (!l_chain)
        l_chain =  dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_ANCHOR);
    if (!l_chain) {
        log_it(L_ERROR, "No chain supported anchor datum type");
        DAP_DEL_Z(l_decree);
        dap_list_free_full(l_tsd_list, NULL);
        return NULL;
    }
    l_decree->header.common_decree_params.chain_id = l_chain->id;
    l_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(a_net);
    l_decree->header.sub_type = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE;
    l_decree->header.data_size = l_total_tsd_size;
    l_decree->header.signs_size = 0;

    size_t l_data_tsd_offset = 0;
    for ( dap_list_t* l_iter=dap_list_first(l_tsd_list); l_iter; l_iter=l_iter->next){
        dap_tsd_t * l_b_tsd = (dap_tsd_t *) l_iter->data;
        size_t l_tsd_size = dap_tsd_size(l_b_tsd);
        memcpy((byte_t*)l_decree->data_n_signs + l_data_tsd_offset, l_b_tsd, l_tsd_size);
        l_data_tsd_offset += l_tsd_size;
    }
    dap_list_free_full(l_tsd_list, NULL);

    size_t l_cur_sign_offset = l_decree->header.data_size + l_decree->header.signs_size;
    size_t l_total_signs_size = l_decree->header.signs_size;

    dap_sign_t * l_sign = dap_cert_sign(a_cert,  l_decree,
       sizeof(dap_chain_datum_decree_t) + l_decree->header.data_size, 0);

    if (l_sign) {
        size_t l_sign_size = dap_sign_get_size(l_sign);
        l_decree = DAP_REALLOC(l_decree, sizeof(dap_chain_datum_decree_t) + l_cur_sign_offset + l_sign_size);
        memcpy((byte_t*)l_decree->data_n_signs + l_cur_sign_offset, l_sign, l_sign_size);
        l_total_signs_size += l_sign_size;
        l_cur_sign_offset += l_sign_size;
        l_decree->header.signs_size = l_total_signs_size;
        DAP_DELETE(l_sign);
        log_it(L_DEBUG,"<-- Signed with '%s'", a_cert->name);
    }else{
        log_it(L_ERROR, "Decree signing failed");
        DAP_DELETE(l_decree);
        return NULL;
    }

    return l_decree;
}

char *s_stake_order_create(dap_chain_net_t *a_net, uint256_t *a_fee, dap_enc_key_t *a_key)
{
    dap_chain_hash_fast_t l_tx_hash = {};
    dap_chain_net_srv_order_direction_t l_dir = SERV_DIR_SELL;
    const char *l_native_ticker = a_net->pub.native_ticker;
    dap_chain_node_addr_t *l_node_addr = dap_chain_net_get_cur_addr(a_net);
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 =  SERV_UNIT_PCS};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
    char *l_order_hash_str = dap_chain_net_srv_order_create(a_net, l_dir, l_uid, *l_node_addr,
                                                            l_tx_hash, a_fee, l_unit, l_native_ticker, 0,
                                                            NULL, 0, 1, NULL, 0, a_key);
    return l_order_hash_str;
}

static int s_cli_srv_stake_order(int a_argc, char **a_argv, int a_arg_index, char **a_str_reply, const char *a_hash_out_type)
{
    enum {
        CMD_NONE, CMD_CREATE, CMD_DECLARE, CMD_REMOVE, CMD_LIST, CMD_UPDATE
    };
    int l_cmd_num = CMD_NONE;
    if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, dap_min(a_argc, a_arg_index + 1), "create", NULL)) {
        l_cmd_num = CMD_CREATE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, dap_min(a_argc, a_arg_index + 1), "remove", NULL)) {
        l_cmd_num = CMD_REMOVE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, dap_min(a_argc, a_arg_index + 1), "list", NULL)) {
        l_cmd_num = CMD_LIST;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, dap_min(a_argc, a_arg_index + 1), "update", NULL)) {
        l_cmd_num = CMD_UPDATE;
    }
    int l_arg_index = a_arg_index + 1;
    switch (l_cmd_num) {
        case CMD_CREATE: {
            const char *l_net_str = NULL,
                       *l_value_str = NULL,
                       *l_cert_str = NULL;
            dap_chain_net_t *l_net = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order create' requires parameter -net");
                return -3;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
            if (!l_value_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order create' requires parameter -value");
                return -5;
            }
            uint256_t l_value = dap_chain_balance_scan(l_value_str);
            if (IS_ZERO_256(l_value)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Format -value <256 bit integer>");
                return -6;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
            if (!l_cert_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order create' requires parameter -cert");
                return -7;
            }
            dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_cert) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't load cert %s", l_cert_str);
                return -8;
            }
            // Create the order & put it in GDB
            char *l_order_hash_str = s_stake_order_create(l_net, &l_value, l_cert->enc_key);
            if (l_order_hash_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_str);
                DAP_DELETE(l_order_hash_str);
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't compose the order");
                return -9;
            }
        } break;
        case CMD_REMOVE: {
            const char *l_net_str = NULL, *l_order_hash_str = NULL;
            dap_chain_net_t *l_net = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order remove' requires parameter -net");
                return -3;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);

            char *l_order_hash_hex_str;
            char *l_order_hash_base58_str;
            // datum hash may be in hex or base58 format
            if(!dap_strncmp(l_order_hash_str, "0x", 2) || !dap_strncmp(l_order_hash_str, "0X", 2)) {
                l_order_hash_hex_str = dap_strdup(l_order_hash_str);
                l_order_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_order_hash_str);
            }
            else {
                l_order_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_order_hash_str);
                l_order_hash_base58_str = dap_strdup(l_order_hash_str);
            }

            dap_chain_net_srv_order_t *l_order =  dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
            if (!l_order) {
                if(!dap_strcmp(a_hash_out_type,"hex"))
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find order %s\n", l_order_hash_hex_str);
                else
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find order %s\n", l_order_hash_base58_str);
                return -5;
            }

            if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID) {
                if(!dap_strcmp(a_hash_out_type,"hex"))
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Order %s is not a delegated stake order.\n",
                                                      l_order_hash_hex_str);
                else
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                      "Order %s is not a delegated stake order.\n", l_order_hash_base58_str);
                return -6;
            }

            if (dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_hex_str)) {
                if(!dap_strcmp(a_hash_out_type,"hex"))
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't remove order %s\n", l_order_hash_hex_str);
                else
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't remove order %s\n", l_order_hash_base58_str);
                return -14;
            }
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Stake order successfully removed");
        } break;
        case CMD_UPDATE: {
            const char *l_net_str = NULL, *l_value_str = NULL;
            const char *l_cert_str = NULL, *l_order_hash_str = NULL;
            dap_chain_net_t *l_net = NULL;
            dap_enc_key_t *l_key = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order update' requires parameter -net");
                return -3;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order update' requires parameter -order");
                return -5;
            }
            dap_chain_net_srv_order_t *l_order =  dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);

            char *l_order_hash_hex_str;
            char *l_order_hash_base58_str;
            // datum hash may be in hex or base58 format
            if(!dap_strncmp(l_order_hash_str, "0x", 2) || !dap_strncmp(l_order_hash_str, "0X", 2)) {
                l_order_hash_hex_str = dap_strdup(l_order_hash_str);
                l_order_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_order_hash_str);
            } else {
                l_order_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_order_hash_str);
                l_order_hash_base58_str = dap_strdup(l_order_hash_str);
            }

            if (!l_order) {
                if(!dap_strcmp(a_hash_out_type,"hex"))
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find order %s\n", l_order_hash_hex_str);
                else
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find order %s\n", l_order_hash_base58_str);
                return -6;
            }

            if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID) {
                if(!dap_strcmp(a_hash_out_type,"hex"))
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Order %s is not a delegated stake order.\n",
                                                      l_order_hash_hex_str);
                else
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                      "Order %s is not a delegated stake order.\n", l_order_hash_base58_str);
                return -7;
            }

            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
            uint256_t l_value = {0};
            if (l_value_str) {
                l_value = dap_chain_balance_scan(l_value_str);
                if (IS_ZERO_256(l_value)) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Format -value <uint256_t>");
                    return -8;
                }
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
            if (!l_cert_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order update' requires parameter -cert");
                return -7;
            }
            dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_cert) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't load cert %s", l_cert_str);
                return -9;
            }
            l_key = l_cert->enc_key;
            // Remove old order and create the order & put it to GDB
            dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_hex_str);
            DAP_DELETE(l_order_hash_hex_str);
            DAP_DELETE(l_order_hash_base58_str);
            l_order_hash_hex_str = s_stake_order_create(l_net, &l_value, l_key);
            if(!l_order_hash_hex_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create new order");
                return -15;
            }
            if(!dap_strcmp(a_hash_out_type, "hex")) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_hex_str);
            } else {
                l_order_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_order_hash_hex_str);
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Successfully created order %s", l_order_hash_base58_str);
                DAP_DELETE(l_order_hash_base58_str);
            }
            DAP_DELETE(l_order_hash_hex_str);
        } break;
        case CMD_LIST: {
            const char *l_net_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order list' requires parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group(l_net);
            size_t l_orders_count = 0;
            dap_global_db_obj_t * l_orders = dap_global_db_get_all_sync(l_gdb_group_str, &l_orders_count);
            dap_string_t *l_reply_str = dap_string_new("");
            for (size_t i = 0; i < l_orders_count; i++) {
                dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)l_orders[i].value;
                if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID)
                    continue;
                // TODO add filters to list (token, address, etc.)
                char *l_price_coins = dap_chain_balance_to_coins(l_order->price);
                char *l_price_datoshi = dap_chain_balance_print(l_order->price);
                char *l_node_addr = dap_strdup_printf(NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_order->node_addr));
                char l_created[80] = {'\0'};
                dap_time_t l_ts_created = l_order->ts_created;
                dap_ctime_r(&l_ts_created, l_created);
                dap_string_append_printf(l_reply_str, "Order: %s\n"
                                                      "\tCreated: %s"
                                                      "\tPrice: %s (%s) %s\n"
                                                      "\tNode addr: %s\n",
                                                      l_orders[i].key, l_created, l_price_coins, l_price_datoshi, l_order->price_ticker, l_node_addr);
                DAP_DELETE(l_price_coins);
                DAP_DELETE(l_price_datoshi);
                DAP_DELETE(l_node_addr);
            }
            dap_global_db_objs_delete(l_orders, l_orders_count);
            DAP_DELETE( l_gdb_group_str);
            if (!l_reply_str->len) {
                dap_string_append(l_reply_str, "No orders found");
            }
            *a_str_reply = dap_string_free(l_reply_str, false);
        } break;
        default: {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Subcommand %s not recognized", a_argv[a_arg_index]);
            return -2;
        }
    }
    return 0;
}

DAP_STATIC_INLINE bool s_chain_esbocs_started(dap_chain_net_t *a_net)
{
    dap_chain_t *l_chain;
    DL_FOREACH(a_net->pub.chains, l_chain) {
        if (!strcmp(DAP_CHAIN_PVT(l_chain)->cs_name, "esbocs") &&
                DAP_CHAIN_PVT(l_chain)->cs_started)
            return true;
    }
    return false;
}

static void s_srv_stake_print(dap_chain_net_srv_stake_item_t *a_stake, uint256_t a_total_weight, dap_string_t *a_string)
{
    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE], l_pkey_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&a_stake->tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
    dap_chain_hash_fast_to_str(&a_stake->signing_addr.data.hash_fast, l_pkey_hash_str, sizeof(l_pkey_hash_str));
    char *l_balance = dap_chain_balance_to_coins(a_stake->value);
    uint256_t l_rel_weight, l_tmp;
    MULT_256_256(a_stake->value, GET_256_FROM_64(100), &l_tmp);
    DIV_256_COIN(l_tmp, a_total_weight, &l_rel_weight);
    char *l_rel_weight_str = dap_chain_balance_to_coins(l_rel_weight);
    char l_active_str[32] = {};
    if (s_chain_esbocs_started(a_stake->net))
        snprintf(l_active_str, 32, "\tActive: %s\n", a_stake->is_active ? "true" : "false");
    dap_string_append_printf(a_string, "Pkey hash: %s\n"
                                        "\tStake value: %s\n"
                                        "\tRelated weight: %s%%\n"
                                        "\tTx hash: %s\n"
                                        "\tNode addr: "NODE_ADDR_FP_STR"\n"
                                        "%s\n",
                             l_pkey_hash_str, l_balance, l_rel_weight_str,
                             l_tx_hash_str, NODE_ADDR_FP_ARGS_S(a_stake->node_addr),
                             l_active_str);
    DAP_DELETE(l_balance);
    DAP_DELETE(l_rel_weight_str);
}

/**
 * @brief The get_tx_cond_pos_del_from_tx struct
 */
struct get_tx_cond_pos_del_from_tx
{
    dap_list_t * ret;

};

/**
 * @brief s_get_tx_filter_callback
 * @param a_net
 * @param a_tx
 * @param a_arg
 */
static void s_get_tx_filter_callback(dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, void *a_arg)
{
    struct get_tx_cond_pos_del_from_tx * l_args = (struct get_tx_cond_pos_del_from_tx* ) a_arg;
    int l_out_idx_tmp = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    dap_hash_fast_t l_datum_hash = *a_tx_hash;

    if (NULL != (l_tx_out_cond = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE,
                                                                 &l_out_idx_tmp)))
    {
        if (!dap_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &l_datum_hash, l_out_idx_tmp, NULL)) {
            dap_chain_net_srv_stake_item_t *l_stake = NULL;
            HASH_FIND(ht, s_srv_stake->tx_itemlist, &l_datum_hash, sizeof(dap_hash_fast_t), l_stake);
            if(!l_stake){
                l_args->ret = dap_list_append(l_args->ret,a_tx);
            }
        }
    }
    return;
}

static int callback_compare_tx_list(const void *a_datum1, const void *a_datum2)
{
    dap_chain_datum_tx_t    *l_datum1 = (dap_chain_datum_tx_t*)((dap_list_t*)a_datum1)->data,
                            *l_datum2 = (dap_chain_datum_tx_t*)((dap_list_t*)a_datum2)->data;
    if (!l_datum1 || !l_datum2) {
        log_it(L_CRITICAL, "Invalid element");
        return 0;
    }
    return l_datum1->header.ts_created == l_datum2->header.ts_created
            ? 0 : l_datum1->header.ts_created > l_datum2->header.ts_created ? 1 : -1;
}

int dap_chain_net_srv_stake_check_validator(dap_chain_net_t * a_net, dap_hash_fast_t *a_tx_hash, dap_stream_ch_chain_validator_test_t * out_data,
                                             int a_time_connect, int a_time_respone)
{
    char *l_key = NULL;
    size_t l_node_info_size = 0;
    uint8_t l_test_data[1024] = {0};
    dap_chain_node_client_t *l_node_client = NULL;
    dap_chain_node_info_t *l_remote_node_info = NULL;
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(l_ledger, a_tx_hash);
    dap_chain_node_addr_t *l_signer_node_addr = NULL;
    int l_overall_correct = false;

    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_tx,
                                                  DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_prev_cond_idx);
    if (!l_tx_out_cond) {
        return -4;
    }
    l_signer_node_addr = &l_tx_out_cond->subtype.srv_stake_pos_delegate.signer_node_addr;

    l_key = dap_chain_node_addr_to_hash_str(l_signer_node_addr);
    if(!l_key)
    {
        return -5;
    }
    // read node
    l_remote_node_info = (dap_chain_node_info_t *) dap_global_db_get_sync(a_net->pub.gdb_nodes, l_key, &l_node_info_size, NULL, NULL);

    if(!l_remote_node_info) {
        DAP_DELETE(l_key);
        return -6;
    }

    DAP_DELETE(l_key);
    // start connect
    l_node_client = dap_chain_node_client_connect_channels(a_net,l_remote_node_info,"N");
    if(!l_node_client) {
        DAP_DELETE(l_remote_node_info);
        return -8;
    }
    // wait connected
    size_t rc = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_ESTABLISHED, a_time_connect);
    if (rc) {
        // clean client struct
        dap_chain_node_client_close_mt(l_node_client);
        DAP_DELETE(l_remote_node_info);
        return -9;
    }
    log_it(L_NOTICE, "Stream connection established");

    uint8_t l_ch_id = DAP_STREAM_CH_ID_NET;
    dap_stream_ch_t * l_ch_chain = dap_client_get_stream_ch_unsafe(l_node_client->client, l_ch_id);

    randombytes(l_test_data, sizeof(l_test_data));
    rc = dap_stream_ch_chain_net_pkt_write(l_ch_chain,
                                            DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY_REQUEST,
                                            a_net->pub.id,
                                            l_test_data, sizeof(l_test_data));
    if (rc == 0) {
        dap_chain_node_client_close_mt(l_node_client);
        DAP_DELETE(l_remote_node_info);
        return -10;
    }

    rc = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_VALID_READY, a_time_respone);
    if (!rc) {
        dap_stream_ch_chain_validator_test_t *validators_data = (dap_stream_ch_chain_validator_test_t*)l_node_client->callbacks_arg;

        dap_sign_t *l_sign = NULL;        
        bool l_sign_correct = false;
        if(validators_data->header.sign_size){
            l_sign = (dap_sign_t*)(l_node_client->callbacks_arg + sizeof(dap_stream_ch_chain_validator_test_t));
            dap_hash_fast_t l_sign_pkey_hash;
            dap_sign_get_pkey_hash(l_sign, &l_sign_pkey_hash);
            l_sign_correct = dap_hash_fast_compare(&l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr.data.hash_fast, &l_sign_pkey_hash);
            if (l_sign_correct)
                l_sign_correct = !dap_sign_verify_all(l_sign, validators_data->header.sign_size, l_test_data, sizeof(l_test_data));
        }
        l_overall_correct = l_sign_correct && validators_data->header.flags == 0xCF;
        *out_data = *validators_data;
        out_data->header.sign_correct = l_sign_correct ? 1 : 0;
        out_data->header.overall_correct = l_overall_correct ? 1 : 0;
    }
    DAP_DELETE(l_node_client->callbacks_arg);
    dap_chain_node_client_close_mt(l_node_client);
    DAP_DELETE(l_remote_node_info);
    return l_overall_correct;
}

uint256_t dap_chain_net_srv_stake_get_total_weight(dap_chain_net_id_t a_net_id)
{
    uint256_t l_total_weight = uint256_0;
    for (dap_chain_net_srv_stake_item_t *it = s_srv_stake->itemlist; it; it = it->hh.next) {
        if (it->net->pub.id.uint64 != a_net_id.uint64)
            continue;
        SUM_256_256(l_total_weight, it->value, &l_total_weight);
    }
    return l_total_weight;
}

static int s_cli_srv_stake(int a_argc, char **a_argv, void **reply)
{
    char ** a_str_reply = (char **) reply;
    enum {
        CMD_NONE, CMD_ORDER, CMD_DELEGATE, CMD_APPROVE, CMD_LIST, CMD_INVALIDATE, CMD_MIN_VALUE, CMD_CHECK
    };
    int l_arg_index = 1;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "base58";
    if(dap_strcmp(l_hash_out_type," hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }
    int l_cmd_num = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "order", NULL)) {
        l_cmd_num = CMD_ORDER;
    }
    // Create tx to freeze staker's funds and delete order
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "delegate", NULL)) {
        l_cmd_num = CMD_DELEGATE;
    }
    // Create tx to approve staker's funds freeze
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "approve", NULL)) {
        l_cmd_num = CMD_APPROVE;
    }
    // Show the tx list with frozen staker funds
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "list", NULL)) {
        l_cmd_num = CMD_LIST;
    }
    // Return staker's funds
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "invalidate", NULL)) {
        l_cmd_num = CMD_INVALIDATE;
    }
    // RSetss stake minimum value
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "min_value", NULL)) {
        l_cmd_num = CMD_MIN_VALUE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "check", NULL)) {
        l_cmd_num = CMD_CHECK;
    }

    switch (l_cmd_num) {
        case CMD_CHECK:
        {
            const char * l_netst = NULL;
            const char * str_tx_hash = NULL;
            dap_chain_net_t * l_net = NULL;
            dap_hash_fast_t l_tx = {};
            dap_stream_ch_chain_validator_test_t l_out = {0};

            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_netst);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &str_tx_hash);
            l_net = dap_chain_net_by_name(l_netst);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_netst);
                return -1;
            }
            if (!str_tx_hash) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command check requires parameter -tx");
                return -2;
            }
            if (dap_chain_hash_fast_from_str(str_tx_hash, &l_tx)){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't get hash_fast from %s, check that the hash is correct", str_tx_hash);
                return -3;
            }
            int res = dap_chain_net_srv_stake_check_validator(l_net, &l_tx, &l_out, 10000, 15000);
            switch (res) {
            case -4:
                dap_cli_server_cmd_set_reply_text(a_str_reply,"Requested conditional transaction has no requires conditional output");
                return -30;
                break;
            case -5:
                dap_cli_server_cmd_set_reply_text(a_str_reply,"Can't calculate hash of addr");
                return -31;
                break;
            case -6:
                dap_cli_server_cmd_set_reply_text(a_str_reply,"Node not found in base");
                return -32;
                break;
            case -7:
                dap_cli_server_cmd_set_reply_text(a_str_reply,"Node has bad size in base, see log file");
                return -33;
                break;
            case -8:
                dap_cli_server_cmd_set_reply_text(a_str_reply,"Can't connect to remote node");
                return -34;
                break;
            case -9:
                dap_cli_server_cmd_set_reply_text(a_str_reply,"No response from node");
                return -35;
                break;
            case -10:
                dap_cli_server_cmd_set_reply_text(a_str_reply,"Can't send DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY_REQUEST packet");
                return -36;
                break;
            default:
                break;
            }
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                              "-------------------------------------------------\n"
                                              "VERSION \t |  %s \n"
                                              "AUTO_PROC \t |  %s \n"
                                              "ORDER \t\t |  %s \n"
                                              "AUTO_ONLINE \t |  %s \n"
                                              "AUTO_UPDATE \t |  %s \n"
                                              "DATA_SIGNED \t |  %s \n"
                                              "FOUND CERT \t |  %s\n"
                                              "SIGN CORRECT \t |  %s\n"
                                              "SUMMARY \t |  %s\n",
                     l_out.header.version,
                    (l_out.header.flags & A_PROC)?"true":"false",
                    (l_out.header.flags & F_ORDR)?"true":"false",
                    (l_out.header.flags & A_ONLN)?"true":"false",
                    (l_out.header.flags & A_UPDT)?"true":"false",
                    (l_out.header.flags & D_SIGN)?"true":"false",
                    (l_out.header.flags & F_CERT)?"true":"false",
                     l_out.header.sign_correct ?  "true":"false",
                     l_out.header.overall_correct ? "Validator ready" : "There are unresolved issues");

        }
        break;
        case CMD_ORDER:
            return s_cli_srv_stake_order(a_argc, a_argv, l_arg_index + 1, a_str_reply, l_hash_out_type);
        case CMD_DELEGATE: {
            const char *l_net_str = NULL,
                       *l_wallet_str = NULL,
                       *l_cert_str = NULL,
                       *l_value_str = NULL,
                       *l_fee_str = NULL,
                       *l_node_addr_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' requires parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_str);
            if (!l_wallet_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' requires parameter -w");
                return -17;
            }
            const char* l_sign_str = "";
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
            if (!l_wallet) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified wallet not found");
                return -18;
            } else {
                l_sign_str = dap_chain_wallet_check_bliss_sign(l_wallet);
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
            if (!l_cert_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' requires parameter -cert");
                return -13;
            }
            dap_cert_t *l_signing_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_signing_cert) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate not found");
                return -19;
            }
            dap_chain_addr_t l_signing_addr;
            if (dap_chain_addr_fill_from_key(&l_signing_addr, l_signing_cert->enc_key, l_net->pub.id)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate is wrong");
                return -20;
            }
            if (dap_chain_net_srv_stake_key_delegated(&l_signing_addr)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate is already delegated");
                return -21;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
            if (!l_value_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' requires parameter -value");
                return -9;
            }
            uint256_t l_value = dap_chain_balance_scan(l_value_str);
            if (IS_ZERO_256(l_value)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Unrecognized number in '-value' param");
                return -10;
            }
            if (compare256(l_value, s_srv_stake->delegate_allowed_min) == -1) {
                char *l_coin_str = dap_chain_balance_to_coins(l_value);
                char *l_value_min_str = dap_chain_balance_print(s_srv_stake->delegate_allowed_min);
                char *l_coin_min_str = dap_chain_balance_to_coins(s_srv_stake->delegate_allowed_min);
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Number in '-value' param %s(%s) is lower than minimum allowed value %s(%s)",
                                                  l_coin_str, l_value_str, l_coin_min_str, l_value_min_str);
                DAP_DELETE(l_coin_str);
                DAP_DELETE(l_value_min_str);
                DAP_DELETE(l_coin_min_str);
                return -11;
            }
            dap_chain_node_addr_t l_node_addr;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-node_addr", &l_node_addr_str);
            if (l_node_addr_str) {
                if (dap_chain_node_addr_from_str(&l_node_addr, l_node_addr_str)) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Unrecognized node addr %s", l_node_addr_str);
                    return -14;
                }
            } else
                l_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
            if (!l_fee_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' requires parameter -fee");
                return -15;
            }
            uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
            if (IS_ZERO_256(l_fee)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Unrecognized number in '-fee' param");
                return -16;
            }
            int ret_val = 0;
            if((ret_val = dap_chain_net_srv_stake_verify_key_and_node(&l_signing_addr, &l_node_addr)) != 0){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Key and node verification error");
                return ret_val;
            }
            // Create conditional transaction
            dap_chain_datum_tx_t *l_tx = s_stake_tx_create(l_net, l_wallet, l_value, l_fee, &l_signing_addr, &l_node_addr);
            dap_chain_wallet_close(l_wallet);
            if (!l_tx || !s_stake_tx_put(l_tx, l_net)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Stake transaction error");
                return -12;
            }
            dap_hash_fast_t l_tx_hash;
            dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
            DAP_DELETE(l_tx);
            char *l_tx_hash_str = dap_hash_fast_to_str_new(&l_tx_hash);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s\nSAVE TO TAKE ===>>> Stake transaction %s has done", l_sign_str, l_tx_hash_str);
            DAP_DELETE(l_tx_hash_str);
        } break;
        case CMD_APPROVE: {
            const char *l_net_str = NULL, *l_tx_hash_str = NULL, *l_cert_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'approve' requires parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-poa_cert", &l_cert_str);
            if (!l_cert_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'approve' requires parameter -poa_cert");
                return -17;
            }
            dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_cert) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate not found");
                return -18;
            }
            if (!s_srv_stake_is_poa_cert(l_net, l_cert->enc_key)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate is not PoA root one");
                return -21;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
            if (!l_tx_hash_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'approve' requires parameter -tx");
                return -13;
            }
            dap_chain_hash_fast_t l_tx_hash = {};
            if (dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid transaction hash format");
                return -14;
            }
            dap_chain_datum_decree_t *l_decree = dap_chain_net_srv_stake_decree_approve(l_net, &l_tx_hash, l_cert);
            char *l_decree_hash_str = NULL;
            if (!l_decree || !(l_decree_hash_str = s_stake_decree_put(l_decree, l_net))) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Approve decree error");
                return -12;
            }
            DAP_DELETE(l_decree);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Approve decree %s successfully created",
                                              l_decree_hash_str);

            DAP_DELETE(l_decree_hash_str);
        } break;
        case CMD_LIST: {
            l_arg_index++;            
            if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "keys", NULL)) {
                const char *l_net_str = NULL,
                           *l_cert_str = NULL,
                           *l_pkey_hash_str = NULL;
                l_arg_index++;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
                if (!l_net_str) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'list keys' requires parameter -net");
                    return -3;
                }
                dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
                if (!l_net) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                    return -4;
                }
                dap_chain_net_srv_stake_item_t *l_stake = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
                if (l_cert_str) {
                    dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
                    if (!l_cert) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate not found");
                        return -18;
                    }
                    dap_chain_addr_t l_signing_addr;
                    if (dap_chain_addr_fill_from_key(&l_signing_addr, l_cert->enc_key, l_net->pub.id)) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate is wrong");
                        return -20;
                    }
                    HASH_FIND(hh, s_srv_stake->itemlist, &l_signing_addr, sizeof(dap_chain_addr_t), l_stake);
                    if (!l_stake) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate isn't delegated nor approved");
                        return -21;
                    }
                }
                if (!l_cert_str)
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-pkey", &l_pkey_hash_str);
                if (l_pkey_hash_str) {
                    dap_hash_fast_t l_pkey_hash;
                    if (dap_chain_hash_fast_from_str(l_pkey_hash_str, &l_pkey_hash)) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified pkey hash is wrong");
                        return -20;
                    }
                    l_stake = dap_chain_net_srv_stake_check_pkey_hash(&l_pkey_hash);
                    if (!l_stake) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified pkey hash isn't delegated nor approved");
                        return -21;
                    }
                }

                dap_string_t *l_reply_str = dap_string_new("");
                size_t l_inactive_count = 0, l_total_count = 0;
                uint256_t l_total_weight = dap_chain_net_srv_stake_get_total_weight(l_net->pub.id);
                if (l_stake)
                    s_srv_stake_print(l_stake, l_total_weight, l_reply_str);
                else
                    for (l_stake = s_srv_stake->itemlist; l_stake; l_stake = l_stake->hh.next) {
                        if (l_stake->net->pub.id.uint64 != l_net->pub.id.uint64)
                            continue;
                        l_total_count++;
                        if (!l_stake->is_active)
                            l_inactive_count++;
                        s_srv_stake_print(l_stake, l_total_weight, l_reply_str);
                    }
                if (!HASH_CNT(hh, s_srv_stake->itemlist)) {
                    dap_string_append(l_reply_str, "No keys found\n");
                } else {
                    if (!l_cert_str && !l_pkey_hash_str)
                        dap_string_append_printf(l_reply_str, "Total keys count: %zu\n", l_total_count);
                    if (s_chain_esbocs_started(l_net))
                        dap_string_append_printf(l_reply_str, "Inactive keys count: %zu\n", l_inactive_count);
                    char *l_total_weight_str = dap_chain_balance_print(l_total_weight);
                    char *l_total_weight_coins = dap_chain_balance_to_coins(l_total_weight);
                    dap_string_append_printf(l_reply_str, "Total weight: %s (%s)\n", l_total_weight_coins, l_total_weight_str);
                    DAP_DELETE(l_total_weight_coins);
                    DAP_DELETE(l_total_weight_str);
                }

                char *l_delegate_min_str = dap_chain_balance_to_coins(s_srv_stake->delegate_allowed_min);
                char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
                dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, l_net->pub.native_ticker);
                dap_string_append_printf(l_reply_str, "Minimum value for key delegating: %s %s",
                                         l_delegate_min_str, l_delegated_ticker);
                DAP_DELETE(l_delegate_min_str);
                *a_str_reply = dap_string_free(l_reply_str, false);
            } else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "tx", NULL)) {
                const char *l_net_str = NULL;
                l_arg_index++;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
                if (!l_net_str) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'list tx' requires parameter -net");
                    return -3;
                }
                dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
                if (!l_net) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                    return -4;
                }
                struct get_tx_cond_pos_del_from_tx * l_args = DAP_NEW_Z(struct get_tx_cond_pos_del_from_tx);
                if(!l_args) {
                    log_it(L_CRITICAL, "Memory allocation error");
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Out of memory");
                    return -1;
                }
                dap_string_t * l_str_tmp = dap_string_new(NULL);
                dap_hash_fast_t l_datum_hash;
                dap_chain_datum_tx_t *l_datum_tx = NULL;
                dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
                int l_out_idx_tmp = 0;
                char *spaces = {"--------------------------------------------------------------------------------------------------------------------"};
                char *l_signing_addr_str = NULL;
                char *l_balance = NULL;
                char *l_coins = NULL;
                char* l_node_address_text_block = NULL;
                dap_chain_net_get_tx_all(l_net,TX_SEARCH_TYPE_NET, s_get_tx_filter_callback, l_args);
                l_args->ret = dap_list_sort(l_args->ret, callback_compare_tx_list);
                for(dap_list_t *tx = l_args->ret; tx; tx = tx->next)
                {
                    l_datum_tx = (dap_chain_datum_tx_t*)tx->data;
                    dap_time_t l_ts_create = (dap_time_t)l_datum_tx->header.ts_created;
                    char buf[50] = {[0]='\0'};
                    dap_hash_fast(l_datum_tx, dap_chain_datum_tx_get_size(l_datum_tx), &l_datum_hash);
                    l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_datum_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE,
                                                                                     &l_out_idx_tmp);
                    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                    dap_chain_hash_fast_to_str(&l_datum_hash, l_hash_str, sizeof(l_hash_str));
                    dap_string_append_printf(l_str_tmp,"%s \n",spaces);
                    dap_string_append_printf(l_str_tmp,"%s \n",dap_ctime_r(&l_ts_create, buf));
                    dap_string_append_printf(l_str_tmp,"tx_hash:\t%s \n",l_hash_str);

                    l_signing_addr_str = dap_chain_addr_to_str(&l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr);
                    char l_pkey_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                    dap_chain_hash_fast_to_str(&l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr.data.hash_fast, l_pkey_hash_str, sizeof(l_pkey_hash_str));
                    l_coins = dap_chain_balance_to_coins(l_tx_out_cond->header.value);
                    l_balance = dap_chain_balance_print(l_tx_out_cond->header.value);

                    dap_string_append_printf(l_str_tmp,"signing_addr:\t%s \n",l_signing_addr_str);
                    dap_string_append_printf(l_str_tmp,"signing_hash:\t%s \n",l_pkey_hash_str);
                    l_node_address_text_block = dap_strdup_printf("node_address:\t" NODE_ADDR_FP_STR,NODE_ADDR_FP_ARGS_S(l_tx_out_cond->subtype.srv_stake_pos_delegate.signer_node_addr));
                    dap_string_append_printf(l_str_tmp,"%s \n",l_node_address_text_block);
                    dap_string_append_printf(l_str_tmp,"value:\t\t%s (%s) \n",l_coins,l_balance);

                    DAP_DELETE(l_node_address_text_block);
                    DAP_DELETE(l_signing_addr_str);
                    DAP_DELETE(l_balance);
                    DAP_DEL_Z(l_coins);
                }

                dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_tmp->str);
                dap_string_free(l_str_tmp, true);
               DAP_DELETE(l_args);
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Subcommand '%s' not recognized", a_argv[l_arg_index]);
                return -2;
            }
        } break;
        case CMD_INVALIDATE: {
            const char *l_net_str = NULL,
                       *l_wallet_str = NULL,
                       *l_fee_str = NULL,
                       *l_tx_hash_str = NULL,
                       *l_cert_str = NULL,
                       *l_poa_cert_str = NULL,
                       *l_signing_pkey_hash_str = NULL,
                       *l_signing_pkey_type_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'invalidate' requires parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            uint256_t l_fee = {};
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_str);
            if (!l_wallet_str) {
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-poa_cert", &l_poa_cert_str);
                if (!l_poa_cert_str) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'invalidate' requires parameter -w or -poa_cert");
                    return -17;
                }
            } else {
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
                if (!l_fee_str) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' requires parameter -fee");
                    return -5;
                }
                l_fee = dap_chain_balance_scan(l_fee_str);
                if (IS_ZERO_256(l_fee)) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Unrecognized number in '-fee' param");
                    return -6;
                }
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
            if (!l_tx_hash_str) {
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
                if (!l_cert_str) {
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-signing_pkey_hash", &l_signing_pkey_hash_str);
                    if (!l_signing_pkey_hash_str) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'invalidate' requires parameter -tx or -cert or -signing_pkey_hash");
                        return -13;
                    }
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-signing_pkey_type", &l_signing_pkey_type_str);
                    if (!l_signing_pkey_type_str) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'invalidate' requires parameter -signing_pkey_type");
                        return -14;
                    }
                    if (dap_sign_type_from_str(l_signing_pkey_type_str).type == SIG_TYPE_NULL) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid signing_pkey_type %s", l_signing_pkey_type_str);
                        return -15;
                    }
                }
            }

            dap_hash_fast_t *l_final_tx_hash = NULL;
            if (l_tx_hash_str) {
                l_final_tx_hash = DAP_NEW(dap_hash_fast_t);
                dap_chain_hash_fast_from_str(l_tx_hash_str, l_final_tx_hash);
                if(!dap_ledger_tx_find_by_hash(l_net->pub.ledger, l_final_tx_hash)) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Transaction %s is not found.", l_tx_hash_str);
                    return -20;
                }
            } else {
                dap_chain_addr_t l_signing_addr;
                if (l_cert_str) {
                    dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
                    if (!l_cert) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate not found");
                        return -18;
                    }
                    if (dap_chain_addr_fill_from_key(&l_signing_addr, l_cert->enc_key, l_net->pub.id)) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate is wrong");
                        return -22;
                    }
                } else {
                    dap_hash_fast_t l_pkey_hash = {};
                    if (dap_chain_hash_fast_from_str(l_tx_hash_str, &l_pkey_hash)) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid pkey hash format");
                        return -23;
                    }
                    dap_chain_addr_fill(&l_signing_addr, dap_sign_type_from_str(l_signing_pkey_type_str), &l_pkey_hash, l_net->pub.id);
                }
                dap_chain_net_srv_stake_item_t *l_stake;
                HASH_FIND(hh, s_srv_stake->itemlist, &l_signing_addr, sizeof(dap_chain_addr_t), l_stake);
                if (!l_stake) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate/pkey hash is not delegated nor this delegating is approved."
                                                                   " Try to invalidate with tx hash instead");
                    return -24;
                }
                l_final_tx_hash = &l_stake->tx_hash;
            }
            if (l_wallet_str) {
                const char* l_sign_str = "";
                dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
                if (!l_wallet) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified wallet not found");
                    return -18;
                } else {
                    l_sign_str = dap_chain_wallet_check_bliss_sign(l_wallet);
                }
                dap_chain_datum_tx_t *l_tx = s_stake_tx_invalidate(l_net, l_final_tx_hash, l_fee, dap_chain_wallet_get_key(l_wallet, 0));
                if (l_tx_hash_str) {
                    DAP_DELETE(l_final_tx_hash);
                }
                dap_chain_wallet_close(l_wallet);
                char *l_decree_hash_str = NULL;
                if (l_tx && (l_decree_hash_str = s_stake_tx_put(l_tx, l_net))) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s\nAll m-tokens successfully returned to "
                                                                   "owner. Returning tx hash %s.", l_sign_str, l_decree_hash_str);
                    DAP_DEL_Z(l_decree_hash_str);
                    DAP_DELETE(l_tx);
                } else {
                    char *l_final_tx_hash_str = dap_chain_hash_fast_to_str_new(l_final_tx_hash);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s\nCan't invalidate transaction %s, examine log files for details", l_sign_str, l_final_tx_hash_str);
                    DAP_DELETE(l_final_tx_hash_str);
                    DAP_DELETE(l_tx);
                    return -21;
                }
            } else {
                dap_cert_t *l_poa_cert = dap_cert_find_by_name(l_poa_cert_str);
                if (!l_poa_cert) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate not found");
                    return -25;
                }
                if (!s_srv_stake_is_poa_cert(l_net, l_poa_cert->enc_key)) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate is not PoA root one");
                    return -26;
                }
                dap_chain_datum_decree_t *l_decree = s_stake_decree_invalidate(l_net, l_final_tx_hash, l_poa_cert);
                char *l_decree_hash_str = NULL;
                if (l_decree && (l_decree_hash_str = s_stake_decree_put(l_decree, l_net))) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified delageted key invalidated. "
                                                                   "Created key invalidation decree %s."
                                                                   "Try to execute this command with -w to return m-tokens to owner", l_decree_hash_str);
                    DAP_DELETE(l_decree);
                    DAP_DELETE(l_decree_hash_str);
                } else {
                    char l_final_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                    dap_chain_hash_fast_to_str(l_final_tx_hash, l_final_tx_hash_str, sizeof(l_final_tx_hash_str));
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't invalidate transaction %s, examine log files for details", l_final_tx_hash_str);
                    DAP_DELETE(l_decree);
                    return -21;
                }
            }
        } break;
        case CMD_MIN_VALUE: {
            const char *l_net_str = NULL,
                       *l_cert_str = NULL,
                       *l_value_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'min_value' requires parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }

            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
            if (!l_cert_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'min_value' requires parameter -cert");
                return -3;
            }
            dap_cert_t *l_poa_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_poa_cert) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate not found");
                return -25;
            }
            if (!s_srv_stake_is_poa_cert(l_net, l_poa_cert->enc_key)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate is not PoA root one");
                return -26;
            }

            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
            if (!l_value_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'min_value' requires parameter -value");
                return -9;
            }
            uint256_t l_value = dap_chain_balance_scan(l_value_str);
            if (IS_ZERO_256(l_value)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Unrecognized number in '-value' param");
                return -10;
            }

            dap_chain_datum_decree_t *l_decree = s_stake_decree_set_min_stake(l_net, l_value, l_poa_cert);
            char *l_decree_hash_str = NULL;
            if (l_decree && (l_decree_hash_str = s_stake_decree_put(l_decree, l_net))) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Minimum stake value has been set."
                                                                " Decree hash %s", l_decree_hash_str);
                DAP_DELETE(l_decree);
                DAP_DELETE(l_decree_hash_str);
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Minimum stake value setting failed");
                DAP_DEL_Z(l_decree);
                return -21;
            }
        } break;        
        default: {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Command %s not recognized", a_argv[l_arg_index]);
            return -1;
        }
    }
    return 0;
}

bool dap_chain_net_srv_stake_get_fee_validators(dap_chain_net_t *a_net,
                                                uint256_t *a_max_fee, uint256_t *a_average_fee, uint256_t *a_min_fee, uint256_t *a_median_fee)
{
    if (!a_net)
        return false;
    char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group(a_net);
    size_t l_orders_count = 0;
    dap_global_db_obj_t * l_orders = dap_global_db_get_all_sync(l_gdb_group_str, &l_orders_count);
    DAP_DELETE( l_gdb_group_str);
    uint256_t l_min = uint256_0, l_max = uint256_0, l_average = uint256_0, l_median = uint256_0;
    uint64_t l_order_fee_count = 0;
    uint256_t l_all_fees[l_orders_count * sizeof(uint256_t)];
    for (size_t i = 0; i < l_orders_count; i++) {
        dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)l_orders[i].value;
        if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID)
            continue;
        if (l_order_fee_count == 0) {
            l_min = l_max = l_order->price;
        }
        l_all_fees[l_order_fee_count] = l_order->price;
        for(int j = l_order_fee_count; j > 0 && compare256(l_all_fees[j], l_all_fees[j - 1]) == -1; --j) {
            uint256_t l_temp = l_all_fees[j];
            l_all_fees[j] = l_all_fees[j - 1];
            l_all_fees[j - 1] = l_temp;
        }
        l_order_fee_count++;
        uint256_t t = uint256_0;
        SUM_256_256(l_order->price, l_average, &t);
        l_average = t;
        if (compare256(l_min, l_order->price) == 1) {
            l_min = l_order->price;
        }
        if (compare256(l_max, l_order->price) == -1) {
            l_max = l_order->price;
        }
    }
    uint256_t t = uint256_0;
    if (!IS_ZERO_256(l_average)) DIV_256(l_average, dap_chain_uint256_from(l_order_fee_count), &t);
    l_average = t;

    if (l_order_fee_count) {
        l_median = l_all_fees[(size_t)(l_order_fee_count * 2 / 3)];
    }

    dap_global_db_objs_delete(l_orders, l_orders_count);
    if (a_min_fee)
        *a_min_fee = l_min;
    if (a_average_fee)
        *a_average_fee = l_average;
    if (a_median_fee)
        *a_median_fee = l_median;
    if (a_max_fee)
        *a_max_fee = l_max;
    return true;
}

json_object *dap_chain_net_srv_stake_get_fee_validators_json(dap_chain_net_t  *a_net) {
    if (!a_net)
        return NULL;
    uint256_t l_min = uint256_0, l_max = uint256_0, l_average = uint256_0, l_median = uint256_0;
    dap_chain_net_srv_stake_get_fee_validators(a_net, &l_max, &l_average, &l_min, &l_median);
    const char *l_native_token  = a_net->pub.native_ticker;
    char    *l_min_balance      = dap_chain_balance_print(l_min),
            *l_min_coins        = dap_chain_balance_to_coins(l_min),
            *l_max_balance      = dap_chain_balance_print(l_max),
            *l_max_coins        = dap_chain_balance_to_coins(l_max),
            *l_average_balance  = dap_chain_balance_print(l_average),
            *l_average_coins    = dap_chain_balance_to_coins(l_average),
            *l_median_balance   = dap_chain_balance_print(l_median),
            *l_median_coins     = dap_chain_balance_to_coins(l_median);
    json_object *l_jobj_ret = json_object_new_object();
    json_object *l_jobj_min = json_object_new_object();
    json_object *l_jobj_min_coins = json_object_new_string(l_min_coins);
    json_object *l_jobj_min_balance = json_object_new_string(l_min_balance);
    json_object *l_jobj_max = json_object_new_object();
    json_object *l_jobj_max_coins = json_object_new_string(l_max_coins);
    json_object *l_jobj_max_balance = json_object_new_string(l_max_balance);
    json_object *l_jobj_average = json_object_new_object();
    json_object *l_jobj_average_coins = json_object_new_string(l_average_coins);
    json_object *l_jobj_average_balance = json_object_new_string(l_average_balance);
    json_object *l_jobj_median = json_object_new_object();
    json_object *l_jobj_median_coins = json_object_new_string(l_median_coins);
    json_object *l_jobj_median_balance = json_object_new_string(l_median_balance);
    json_object *l_jobj_ticker = json_object_new_string(l_native_token);
    if (!l_jobj_ret || !l_jobj_min || !l_jobj_min_coins || !l_jobj_min_balance || !l_jobj_max || !l_jobj_max_coins ||
        !l_jobj_max_balance || !l_jobj_average || !l_jobj_average_coins || !l_jobj_average_balance || !l_jobj_median ||
        !l_jobj_median_coins || !l_jobj_median_balance || !l_jobj_ticker) {
        json_object_put(l_jobj_ret);
        json_object_put(l_jobj_min);
        json_object_put(l_jobj_min_coins);
        json_object_put(l_jobj_min_balance);
        json_object_put(l_jobj_max);
        json_object_put(l_jobj_max_coins);
        json_object_put(l_jobj_max_balance);
        json_object_put(l_jobj_average);
        json_object_put(l_jobj_average_coins);
        json_object_put(l_jobj_average_balance);
        json_object_put(l_jobj_median);
        json_object_put(l_jobj_median_coins);
        json_object_put(l_jobj_median_balance);
        json_object_put(l_jobj_ticker);
        return NULL;
    }
    json_object_object_add(l_jobj_min, "coin", l_jobj_min_coins);
    json_object_object_add(l_jobj_min, "balance", l_jobj_min_balance);
    json_object_object_add(l_jobj_max, "coin", l_jobj_max_coins);
    json_object_object_add(l_jobj_max, "balance", l_jobj_max_balance);
    json_object_object_add(l_jobj_average, "coin", l_jobj_average_coins);
    json_object_object_add(l_jobj_average, "balance", l_jobj_average_balance);
    json_object_object_add(l_jobj_median, "coin", l_jobj_median_coins);
    json_object_object_add(l_jobj_median, "balance", l_jobj_median_balance);
    json_object_object_add(l_jobj_ret, "min", l_jobj_min);
    json_object_object_add(l_jobj_ret, "max", l_jobj_max);
    json_object_object_add(l_jobj_ret, "average", l_jobj_average);
    json_object_object_add(l_jobj_ret, "median", l_jobj_median);
    json_object_object_add(l_jobj_ret, "token", l_jobj_ticker);
    DAP_DELETE(l_min_balance);
    DAP_DELETE(l_min_coins);
    DAP_DELETE(l_max_balance);
    DAP_DELETE(l_max_coins);
    DAP_DELETE(l_average_balance);
    DAP_DELETE(l_average_coins);
    DAP_DELETE(l_median_balance);
    DAP_DELETE(l_median_coins);
    return l_jobj_ret;
}

void dap_chain_net_srv_stake_get_fee_validators_str(dap_chain_net_t *a_net, dap_string_t *a_string_ret)
{
    if (!a_net || !a_string_ret)
        return;
    uint256_t l_min = uint256_0, l_max = uint256_0, l_average = uint256_0, l_median = uint256_0;
    dap_chain_net_srv_stake_get_fee_validators(a_net, &l_max, &l_average, &l_min, &l_median);
    const char *l_native_token  = a_net->pub.native_ticker;
    char    *l_min_balance      = dap_chain_balance_print(l_min),
            *l_min_coins        = dap_chain_balance_to_coins(l_min),
            *l_max_balance      = dap_chain_balance_print(l_max),
            *l_max_coins        = dap_chain_balance_to_coins(l_max),
            *l_average_balance  = dap_chain_balance_print(l_average),
            *l_average_coins    = dap_chain_balance_to_coins(l_average),
            *l_median_balance   = dap_chain_balance_print(l_median),
            *l_median_coins     = dap_chain_balance_to_coins(l_median);
    dap_string_append_printf(a_string_ret, "Validator fee: \n"
                                           "\t MIN: %s (%s) %s\n"
                                           "\t MAX: %s (%s) %s\n"
                                           "\t Average: %s (%s) %s \n"
                                           "\t Median: %s (%s) %s \n", l_min_coins, l_min_balance, l_native_token,
                                           l_max_coins, l_max_balance, l_native_token,
                                           l_average_coins, l_average_balance, l_native_token,
                                           l_median_coins, l_median_balance, l_native_token);
    DAP_DELETE(l_min_balance);
    DAP_DELETE(l_min_coins);
    DAP_DELETE(l_max_balance);
    DAP_DELETE(l_max_coins);
    DAP_DELETE(l_average_balance);
    DAP_DELETE(l_average_coins);
    DAP_DELETE(l_median_balance);
    DAP_DELETE(l_median_coins);
}

static void s_cache_data(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_addr_t *a_signing_addr)
{
    if (!dap_ledger_cache_enabled(a_ledger))
        return;
    dap_chain_net_srv_stake_cache_data_t l_cache_data;
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_cache_data.tx_hash);
    char l_data_key[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_cache_data.tx_hash, l_data_key, sizeof(l_data_key));
    l_cache_data.signing_addr = *a_signing_addr;
    char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_GDB_GROUP);
    if (dap_global_db_set(l_gdb_group, l_data_key, &l_cache_data, sizeof(l_cache_data), false, NULL, NULL))
        log_it(L_WARNING, "Stake service cache mismatch");
}

dap_chain_net_srv_stake_item_t *dap_chain_net_srv_stake_check_pkey_hash(dap_hash_fast_t *a_pkey_hash)
{
    dap_chain_net_srv_stake_item_t *l_stake, *l_tmp;
    HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp) {
        if (dap_hash_fast_compare(&l_stake->signing_addr.data.hash_fast, a_pkey_hash))
            return l_stake;
    }
    return NULL;
}
