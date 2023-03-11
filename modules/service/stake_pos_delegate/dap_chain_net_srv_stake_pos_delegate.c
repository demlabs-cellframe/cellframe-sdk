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
#include "dap_list.h"
#include "dap_enc_base58.h"
#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_cs_block_poa.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"

#define LOG_TAG "dap_chain_net_srv_stake"

static int s_cli_srv_stake(int a_argc, char **a_argv, char **a_str_reply);

static bool s_stake_verificator_callback(dap_ledger_t * a_ledger,dap_hash_fast_t *a_tx_out_hash, dap_chain_tx_out_cond_t *a_cond,
                                                      dap_chain_datum_tx_t *a_tx_in, bool a_owner);
static void s_stake_updater_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_cond);

static dap_chain_net_srv_stake_t *s_srv_stake = NULL;
typedef struct dap_chain_net_srv_stake_cache_data
{
    uint256_t value;
    dap_chain_addr_t signing_addr;
    dap_chain_hash_fast_t tx_hash;
    dap_chain_node_addr_t node_addr;
} DAP_ALIGN_PACKED dap_chain_net_srv_stake_cache_data_t;

/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @param vpn_addr Zero if only client mode. Address if the node shares its local VPN
 * @param vpn_mask Zero if only client mode. Mask if the node shares its local VPN
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_stake_pos_delegate_init()
{
    dap_chain_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, s_stake_verificator_callback, s_stake_updater_callback);
    dap_cli_server_cmd_add("srv_stake", s_cli_srv_stake, "Delegated stake service commands",
    "\t\t=== Commands for work with orders ===\n"
    "srv_stake order create -net <net_name> -value <value> -cert <priv_cert_name> \n"
        "\tCreates a new order signed with a delegated key, which declares the commission for which \n"
        "\tthe node agrees to conduct the transaction.\n"
    "srv_stake order remove -net <net_name> -order <order_hash> [-H {hex | base58(default)}]\n"
         "\tRemove order with specified hash\n"
    "srv_stake order update -net <net_name> -order <order_hash> [-H {hex | base58(default)}] -cert <priv_cert_name>  -value <value>\n"
         "\tUpdate order with specified hash\n"
    "srv_stake order list -net <net_name>\n"
         "\tGet the fee orders list within specified net name\n"
     "\t\t === Commands for work with stake delegate ===\n"
    "srv_stake delegate -cert <pub_cert_name> -net <net_name> -wallet <wallet_name> -value <datoshi> [-node_addr <node_addr>] -fee <value> \n"
         "\tDelegate public key in specified certificate with specified net name. Pay with specified value of m-tokens of native net token.\n"
    "srv_stake approve -net <net_name> -tx <transaction_hash> -poa_cert <priv_cert_name>\n"
         "\tApprove stake transaction by root node certificate within specified net name\n"
    "srv_stake transactions -net <net_name> [-cert <delegated_cert>]\n"
         "\tShow the list of requested, active and canceled stake transactions (optional delegated from addr).\n"
    "srv_stake invalidate -net <net_name> {-tx <transaction_hash> | -cert <delegated_cert> | -cert_pkey_hash <pkey_hash>}"
                            " {-wallet <wallet_name> -fee <value> | -poa_cert <cert_name>}\n"
         "\tInvalidate requested delegated stake transaction by hash or cert name or cert pkey hash within net name and"
         " return m-tokens to specified wallet (if any)\n"
    );

    s_srv_stake = DAP_NEW_Z(dap_chain_net_srv_stake_t);

    uint16_t l_net_count;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    for (uint16_t i = 0; i < l_net_count; i++) {
        size_t l_auth_certs_count = 0;
        for (dap_chain_t *l_chain = l_net_list[i]->pub.chains; l_chain; l_chain = l_chain->next)
            if ( (s_srv_stake->auth_cert_pkeys = l_chain->callback_get_poa_certs(l_chain, &l_auth_certs_count, NULL)) )
                break;
    }
    DAP_DELETE(l_net_list);
    s_srv_stake->delegate_allowed_min = dap_chain_coins_to_balance("1.0");
    s_srv_stake->initialized = true;

    return 0;
}

void dap_chain_net_srv_stake_pos_delegate_deinit()
{
    dap_chain_net_srv_stake_item_t *l_stake = NULL, *l_tmp;
    HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp) {
        // Clang bug at this, l_stake should change at every loop cycle
        HASH_DEL(s_srv_stake->itemlist, l_stake);
        DAP_DELETE(l_stake);
    }
    DAP_DEL_Z(s_srv_stake);
}

static bool s_stake_verificator_callback(dap_ledger_t UNUSED_ARG *a_ledger, dap_hash_fast_t UNUSED_ARG *a_tx_out_hash,
                                         dap_chain_tx_out_cond_t UNUSED_ARG *a_cond, dap_chain_datum_tx_t UNUSED_ARG *a_tx_in,
                                         bool a_owner)
{
    assert(s_srv_stake);
    if (!a_owner)
        return false;
    return true;
}

static void s_stake_updater_callback(dap_ledger_t UNUSED_ARG *a_ledger, dap_chain_datum_tx_t UNUSED_ARG *a_tx, dap_chain_tx_out_cond_t *a_cond)
{
    assert(s_srv_stake);
    if (!a_cond)
        return;
    dap_chain_net_srv_stake_key_invalidate(&a_cond->subtype.srv_stake_pos_delegate.signing_addr);
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
    dap_chain_net_srv_stake_item_t *l_stake = DAP_NEW_Z(dap_chain_net_srv_stake_item_t);
    l_stake->net = a_net;
    l_stake->node_addr = *a_node_addr;
    l_stake->signing_addr = *a_signing_addr;
    l_stake->value = a_value;
    l_stake->tx_hash = *a_stake_tx_hash;
    HASH_ADD(hh, s_srv_stake->itemlist, signing_addr, sizeof(dap_chain_addr_t), l_stake);

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
        DAP_DELETE(l_stake);
    }
}

void dap_chain_net_srv_stake_set_allowed_min_value(uint256_t a_value)
{
    assert(s_srv_stake);
    s_srv_stake->delegate_allowed_min = a_value;
}

bool dap_chain_net_srv_stake_key_delegated(dap_chain_addr_t *a_signing_addr)
{
    assert(s_srv_stake);
    if (!a_signing_addr)
        return false;
    while (!s_srv_stake->initialized);

    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    HASH_FIND(hh, s_srv_stake->itemlist, a_signing_addr, sizeof(dap_chain_addr_t), l_stake);
    if (l_stake) // public key delegated for this network
        return true;
    return false;
}

dap_list_t *dap_chain_net_srv_stake_get_validators()
{
    dap_list_t *l_ret = NULL;
    if (!s_srv_stake || !s_srv_stake->itemlist)
        return l_ret;
    dap_chain_net_srv_stake_item_t *l_stake, *l_tmp;
    HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp)
        l_ret = dap_list_append(l_ret, DAP_DUP(l_stake));
    return l_ret;
}

// Freeze staker's funds when delegating a key
static dap_chain_datum_tx_t *s_stake_tx_create(dap_chain_net_t * a_net, dap_chain_wallet_t *a_wallet,
                                               uint256_t a_value, dap_chain_addr_t *a_signing_addr,
                                               dap_chain_node_addr_t *a_node_addr)
{
    if (!a_net || !a_wallet || IS_ZERO_256(a_value) || !a_signing_addr || !a_node_addr)
        return NULL;

    char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, a_net->pub.native_ticker);
    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_net->pub.name);
    uint256_t l_value_sell = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
    dap_chain_addr_t *l_owner_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, l_delegated_ticker, l_owner_addr, a_value, &l_value_sell);
    if (!l_list_used_out) {
        log_it(L_WARNING, "Nothing to delegate (not enough funds)");
        DAP_DELETE(l_owner_addr);
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_to_items, l_value_sell)) {
        log_it(L_ERROR, "Can't compose the transaction input");
        goto tx_fail;
    }

    // add 'out_cond' & 'out' items
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
    SUBTRACT_256_256(l_value_sell, a_value, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, l_owner_addr, l_value_back) != 1) {
            log_it(L_ERROR, "Cant add coin back output");
            goto tx_fail;
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

// Put the transaction to mempool or
static char *s_stake_tx_put(dap_chain_datum_tx_t *a_tx, dap_chain_net_t *a_net)
{
    // Put the transaction to mempool or directly to chains
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

static dap_chain_datum_decree_t *s_stake_decree_approve(dap_chain_net_t *a_net, dap_hash_fast_t *a_stake_tx_hash, dap_cert_t *a_cert)
{
    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_net->pub.name);

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, a_stake_tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return NULL;
    }
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx,
                                                  DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_prev_cond_idx);
    if (!l_tx_out_cond) {
        log_it(L_WARNING, "Requested conditional transaction has no required conditional output");
        return NULL;
    }
    if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, a_stake_tx_hash, l_prev_cond_idx)) {
        log_it(L_WARNING, "Requested conditional transaction is already used out");
        return NULL;
    }
    char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, a_net->pub.native_ticker);
    const char *l_tx_ticker = dap_chain_ledger_tx_get_token_ticker_by_hash(l_ledger, a_stake_tx_hash);
    if (dap_strcmp(l_tx_ticker, l_delegated_ticker)) {
        log_it(L_WARNING, "Requested conditional transaction have another ticker (not %s)", l_delegated_ticker);
        return NULL;
    }
    if (compare256(l_tx_out_cond->header.value, s_srv_stake->delegate_allowed_min) == -1) {
        log_it(L_WARNING, "Requested conditional transaction have not enough funds");
        return NULL;
    }

    // create approve decree
    size_t l_total_tsd_size = 0;
    dap_chain_datum_decree_t *l_decree = NULL;
    dap_list_t *l_tsd_list = NULL;
    dap_tsd_t *l_tsd = NULL;

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(dap_hash_fast_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_TX_HASH;
    l_tsd->size = sizeof(dap_hash_fast_t);
    *(dap_hash_fast_t*)(l_tsd->data) = *a_stake_tx_hash;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(uint256_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE;
    l_tsd->size = sizeof(uint256_t);
    *(uint256_t*)(l_tsd->data) = l_tx_out_cond->header.value;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(dap_chain_addr_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR;
    l_tsd->size = sizeof(dap_chain_addr_t);
    *(dap_chain_addr_t*)(l_tsd->data) = l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(dap_chain_node_addr_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNER_NODE_ADDR;
    l_tsd->size = sizeof(dap_chain_node_addr_t);
    *(dap_chain_node_addr_t*)(l_tsd->data) = l_tx_out_cond->subtype.srv_stake_pos_delegate.signer_node_addr;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
    l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
    l_decree->header.ts_created = dap_time_now();
    l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
    l_decree->header.common_decree_params.net_id = a_net->pub.id;
    l_decree->header.common_decree_params.chain_id = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_DECREE)->id;
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

    //TODO: form decree for key delegating
    /*  Used sections
    a_stake_tx_hash
    l_tx_out_cond->header.value,
    l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr,
    l_tx_out_cond->subtype.srv_stake_pos_delegate.signer_node_addr

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_cert->enc_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        return NULL;
    } */

    return l_decree;
}

// Put the decree to mempool
static char *s_stake_decree_put(dap_chain_datum_decree_t *a_decree, dap_chain_net_t *a_net)
{
    // Put the transaction to mempool or directly to chains
    size_t l_decree_size = dap_chain_datum_decree_get_size(a_decree);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE, a_decree, l_decree_size);
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_DECREE);
    if (!l_chain) {
        return NULL;
    }
    // Processing will be made according to autoprocess policy
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    return l_ret;
}

static dap_chain_datum_tx_t *s_stake_tx_invalidate(dap_chain_net_t *a_net, dap_hash_fast_t *a_tx_hash, dap_enc_key_t *a_key)
{
    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_net->pub.name);

    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, a_tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return NULL;
    }
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx,
                                                  DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_prev_cond_idx);
    if (!l_tx_out_cond) {
        log_it(L_WARNING, "Requested conditional transaction has no required conditional output");
        return NULL;
    }
    if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, a_tx_hash, l_prev_cond_idx)) {
        log_it(L_WARNING, "Requested conditional transaction is already used out");
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
        log_it(L_WARNING, "Try to invalidate delegating tx with not a owner wallet");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_add_in_cond_item(&l_tx, a_tx_hash, l_prev_cond_idx, 0);

    // add 'out' item
    if (dap_chain_datum_tx_add_out_item(&l_tx, &l_owner_addr, l_tx_out_cond->header.value) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_ERROR, "Cant add returning coins output");
        return NULL;
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
    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_net->pub.name);

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, a_stake_tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return NULL;
    }
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx,
                                                  DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_prev_cond_idx);
    if (!l_tx_out_cond) {
        log_it(L_WARNING, "Requested conditional transaction has no required conditional output");
        return NULL;
    }

    // create invalidate decree
    size_t l_total_tsd_size = 0;
    dap_chain_datum_decree_t *l_decree = NULL;
    dap_list_t *l_tsd_list = NULL;
    dap_tsd_t *l_tsd = NULL;

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(dap_chain_addr_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR;
    l_tsd->size = sizeof(dap_chain_addr_t);
    *(dap_chain_addr_t*)(l_tsd->data) = l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
    l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
    l_decree->header.ts_created = dap_time_now();
    l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
    l_decree->header.common_decree_params.net_id = a_net->pub.id;
    l_decree->header.common_decree_params.chain_id = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_DECREE)->id;
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

    /*  Used sections

    l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr,

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        return NULL;
    } */
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
                                                            NULL, 0, NULL, 0, a_key);
    return l_order_hash_str;
}

static int s_cli_srv_stake_order(int a_argc, char **a_argv, int a_arg_index, char **a_str_reply, const char *a_hash_out_type)
{
    enum {
        CMD_NONE, CMD_CREATE, CMD_DECLARE, CMD_REMOVE, CMD_LIST, CMD_UPDATE
    };
    int l_cmd_num = CMD_NONE;
    if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "create", NULL)) {
        l_cmd_num = CMD_CREATE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "remove", NULL)) {
        l_cmd_num = CMD_REMOVE;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "list", NULL)) {
        l_cmd_num = CMD_LIST;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, min(a_argc, a_arg_index + 1), "update", NULL)) {
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
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order create' required parameter -net");
                return -3;
            }
            l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
            if (!l_value_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order create' required parameter -coins");
                return -5;
            }
            uint256_t l_value = dap_chain_balance_scan(l_value_str);
            if (IS_ZERO_256(l_value)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Format -value <256 bit integer>");
                return -6;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
            if (!l_cert_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order create' required parameter -cert");
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
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order update' required parameter -net");
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
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'order list' required parameter -net");
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
                char *l_price = dap_chain_balance_print(l_order->price);
                char *l_node_addr = dap_strdup_printf(NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_order->node_addr));
                char l_created[80] = {'\0'};
                dap_time_t l_ts_created = l_order->ts_created;
                dap_ctime_r(&l_ts_created, l_created);
                dap_string_append_printf(l_reply_str, "Order: %s\n"
                                                      "\tCreated: %s"
                                                      "\tPrice: %s %s\n"
                                                      "\tNode addr: %s\n",
                                                      l_orders[i].key, l_created, l_price, l_order->price_ticker, l_node_addr);
                DAP_DELETE(l_price);
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

static void s_srv_stake_print(dap_chain_net_srv_stake_item_t *a_stake, dap_string_t *a_string)
{
    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&a_stake->tx_hash);
    char *l_signing_addr_str = dap_chain_addr_to_str(&a_stake->signing_addr);
    char *l_balance = dap_chain_balance_print(a_stake->value);
    dap_string_append_printf(a_string, "%s %s %s\n", l_tx_hash_str, l_balance, l_signing_addr_str);
    DAP_DELETE(l_balance);
    DAP_DELETE(l_tx_hash_str);
    DAP_DELETE(l_signing_addr_str);
}

static int s_cli_srv_stake(int a_argc, char **a_argv, char **a_str_reply)
{
    enum {
        CMD_NONE, CMD_ORDER, CMD_DELEGATE, CMD_APPROVE, CMD_TX_LIST, CMD_INVALIDATE
    };
    int l_arg_index = 1;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "base58";
    if(dap_strcmp(l_hash_out_type," hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }
    int l_cmd_num = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "order", NULL)) {
        l_cmd_num = CMD_ORDER;
    }
    // Create tx to freeze staker's funds and delete order
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "delegate", NULL)) {
        l_cmd_num = CMD_DELEGATE;
    }
    // Create tx to approve staker's funds freeze
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "approve", NULL)) {
        l_cmd_num = CMD_APPROVE;
    }
    // Show the tx list with frozen staker funds
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "transactions", NULL)) {
        l_cmd_num = CMD_TX_LIST;
    }
    // Return staker's funds
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "invalidate", NULL)) {
        l_cmd_num = CMD_INVALIDATE;
    }
    switch (l_cmd_num) {
        case CMD_ORDER:
            return s_cli_srv_stake_order(a_argc, a_argv, l_arg_index + 1, a_str_reply, l_hash_out_type);
        case CMD_DELEGATE: {
        //     "srv_stake delegate -cert <pub_cert_name> -net <net_name> -wallet <wallet_name> -value <addr> [-node_addr <node_addr>]\n"
        //     "\tDelegate tokens with specified order within specified net name. Specify fee address.\n"
            const char *l_net_str = NULL,
                       *l_wallet_str = NULL,
                       *l_cert_str = NULL,
                       *l_value_str = NULL,
                       *l_node_addr_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' required parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_wallet_str);
            if (!l_wallet_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' required parameter -wallet");
                return -17;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
            if (!l_wallet) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified wallet not found");
                return -18;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
            if (!l_cert_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' required parameter -cert");
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
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' required parameter -value");
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

            // Create conditional transaction
            dap_chain_datum_tx_t *l_tx = s_stake_tx_create(l_net, l_wallet, l_value, &l_signing_addr, &l_node_addr);
            dap_chain_wallet_close(l_wallet);
            if (!l_tx || !s_stake_tx_put(l_tx, l_net)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Stake transaction error");
                return -12;
            }
            dap_hash_fast_t l_tx_hash;
            dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
            DAP_DELETE(l_tx);
            char *l_tx_hash_str = dap_hash_fast_to_str_new(&l_tx_hash);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "SAVE TO TAKE ===>>> Stake transaction %s has done", l_tx_hash_str);
            DAP_DELETE(l_tx_hash_str);
        } break;
        case CMD_APPROVE: {
            const char *l_net_str = NULL, *l_tx_hash_str = NULL, *l_cert_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'approve' required parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-poa_cert", &l_cert_str);
            if (!l_cert_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'approve' required parameter -poa_cert");
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
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'approve' required parameter -tx");
                return -13;
            }
            dap_chain_hash_fast_t l_tx_hash = {};
            if (dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid transaction hash format");
                return -14;
            }
            dap_chain_datum_decree_t *l_decree = s_stake_decree_approve(l_net, &l_tx_hash, l_cert);
            if (!l_decree || !s_stake_decree_put(l_decree, l_net)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Approve decree error");
                return -12;
            }
            DAP_DELETE(l_decree);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Approve decree successfully created");
        } break;
        case CMD_TX_LIST: {
            const char *l_net_str = NULL,
                       *l_cert_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'transactions' required parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_chain_net_srv_stake_item_t *l_stake = NULL, *l_tmp;
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
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate isn't delegated or it's delegating isn't approved");
                    return -21;
                }
            }
            dap_string_t *l_reply_str = dap_string_new("");
            if (l_stake)
                s_srv_stake_print(l_stake, l_reply_str);
            else
                HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp) {
                    if (l_stake->net->pub.id.uint64 != l_net->pub.id.uint64) {
                        continue;
                    }
                    s_srv_stake_print(l_stake, l_reply_str);
                }
            if (!l_reply_str->len) {
                dap_string_append(l_reply_str, "No transaction found");
            }
            *a_str_reply = dap_string_free(l_reply_str, false);
        } break;
        case CMD_INVALIDATE: {
            const char *l_net_str = NULL,
                       *l_wallet_str = NULL,
                       *l_tx_hash_str = NULL,
                       *l_cert_str = NULL,
                       *l_poa_cert_str = NULL,
                       *l_signing_pkey_hash_str = NULL,
                       *l_signing_pkey_type_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'invalidate' required parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-wallet", &l_wallet_str);
            if (!l_wallet_str) {
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-poa_cert", &l_poa_cert_str);
                if (!l_poa_cert_str) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'invalidate' required parameter -wallet or -poa_cert");
                    return -17;
                }
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
            if (!l_tx_hash_str) {
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
                if (!l_cert_str) {
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-signing_pkey_hash", &l_signing_pkey_hash_str);
                    if (!l_signing_pkey_hash_str) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'invalidate' required parameter -tx or -cert or -signing_pkey_hash");
                        return -13;
                    }
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-signing_pkey_type", &l_signing_pkey_type_str);
                    if (!l_signing_pkey_type_str) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'invalidate' required parameter -signing_pkey_type");
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
                dap_hash_fast_t l_tx_hash = {};
                dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash);
                l_final_tx_hash = dap_chain_ledger_get_final_chain_tx_hash(l_net->pub.ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_tx_hash);
                if (!l_final_tx_hash) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Transaction %s is not found or already used", l_tx_hash_str);
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
                dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
                if (!l_wallet) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified wallet not found");
                    return -18;
                }
                dap_chain_datum_tx_t *l_tx = s_stake_tx_invalidate(l_net, l_final_tx_hash, dap_chain_wallet_get_key(l_wallet, 0));
                dap_chain_wallet_close(l_wallet);
                if (l_tx && s_stake_tx_put(l_tx, l_net)) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "All m-tokens successfully returned to owner");
                    DAP_DELETE(l_tx);
                } else {
                    char *l_final_tx_hash_str = dap_chain_hash_fast_to_str_new(l_final_tx_hash);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't invalidate transaction %s, examine log files for details", l_final_tx_hash_str);
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
                if (l_decree && s_stake_decree_put(l_decree, l_net)) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified delageted key invalidated. Try to execute this command with -wallet to return m-tokens to owner");
                    DAP_DELETE(l_decree);
                } else {
                    char *l_final_tx_hash_str = dap_chain_hash_fast_to_str_new(l_final_tx_hash);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't invalidate transaction %s, examine log files for details", l_final_tx_hash_str);
                    DAP_DELETE(l_final_tx_hash_str);
                    DAP_DELETE(l_decree);
                    return -21;
                }
            }
        } break;

        default: {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Command %s not recognized", a_argv[l_arg_index]);
            return -1;
        }
    }
    return 0;
}

void dap_chain_net_srv_stake_get_fee_validators(dap_chain_net_t *a_net, dap_string_t *a_string_ret){
    if (!a_net || !a_string_ret)
        return;
    char * l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group(a_net);
    size_t l_orders_count = 0;
    dap_global_db_obj_t * l_orders = dap_global_db_get_all_sync(l_gdb_group_str, &l_orders_count);
    uint256_t l_max = {0};
    uint256_t l_min = {0};
    uint256_t l_average = {0};
//    bool setMinimal = false;
    uint64_t l_order_fee_count = 0;
    for (size_t i = 0; i < l_orders_count; i++) {
        dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)l_orders[i].value;
        if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID)
            continue;
        if (l_orders_count == 0) {
            l_min = l_order->price;
            l_max = l_order->price;
        }
        l_order_fee_count++;
        uint256_t t = {0};
        SUM_256_256(l_order->price, l_average, &t);
        l_average = t;
        int res = compare256(l_min, l_order->price);
        if (res == 1) {
            l_min = l_order->price;
        }
        res = compare256(l_max, l_order->price);
        if (res == -1) {
            l_max = l_order->price;
        }
    }
    uint256_t t = {0};
    if (!IS_ZERO_256(l_average)) DIV_256(l_average, dap_chain_uint256_from(l_order_fee_count), &t);
    dap_global_db_objs_delete(l_orders, l_orders_count);
    DAP_DELETE( l_gdb_group_str);
    const char *l_native_token  =  a_net->pub.native_ticker;
    char *l_min_balance = dap_chain_balance_print(l_min);
    char *l_min_coins = dap_chain_balance_to_coins(l_min);
    char *l_max_balance = dap_chain_balance_print(l_max);
    char *l_max_coins = dap_chain_balance_to_coins(l_max);
    char *l_average_balance = dap_chain_balance_print(t);
    char *l_average_coins = dap_chain_balance_to_coins(t);
    dap_string_append_printf(a_string_ret, "Validator fee: \n"
                                           "\t MIN: %s (%s) %s\n"
                                           "\t MAX: %s (%s) %s\n"
                                           "\t Average: %s (%s) %s \n", l_min_coins, l_min_balance, l_native_token,
                                           l_max_coins, l_max_balance, l_native_token,
                                           l_average_coins, l_average_balance, l_native_token);
    DAP_DELETE(l_min_balance);
    DAP_DELETE(l_min_coins);
    DAP_DELETE(l_max_balance);
    DAP_DELETE(l_max_coins);
    DAP_DELETE(l_average_balance);
    DAP_DELETE(l_average_coins);
}

