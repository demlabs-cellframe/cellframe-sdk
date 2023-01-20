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
static int s_callback_requested(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_response_error(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static int s_callback_receipt_next_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_data, size_t a_data_size);
static bool s_verificator_stake_callback(dap_ledger_t * a_ledger,dap_hash_fast_t *a_tx_out_hash, dap_chain_tx_out_cond_t *a_cond,
                                                      dap_chain_datum_tx_t *a_tx_in, bool a_owner);
static bool s_verificator_stake_updater_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_cond);

static dap_chain_net_srv_stake_t *s_srv_stake = NULL;

/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @param vpn_addr Zero if only client mode. Address if the node shares its local VPN
 * @param vpn_mask Zero if only client mode. Mask if the node shares its local VPN
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_stake_pos_delegate_init()
{
    dap_chain_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, s_verificator_stake_callback, s_verificator_stake_updater_callback);
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
         "\tGet the stake orders list within specified net name\n"
     "\t\t === Commands for work with stake delegate ===\n"
    "srv_stake delegate -order <order_hash> -net <net_name> -wallet <wallet_name> -fee_addr <addr>\n"
         "\tDelegate tokens with specified order within specified net name. Specify fee address.\n"
    "srv_stake approve -net <net_name> -tx <transaction_hash> -cert <priv_cert_name>\n"
         "\tApprove stake transaction by root node certificate within specified net name.\n"
    "srv_stake transactions -net <net_name> [-addr <addr_from>]\n"
         "\tShow the list of requested, active and canceled stake transactions (optional delegated from addr).\n"
    "srv_stake invalidate -net <net_name> -tx <transaction_hash> -wallet <wallet_name>\n"
         "\tInvalidate requested stake transaction by hash within net name and return stake to specified wallet.\n"
    "srv_stake commit -net <net_name> [-block <block_hash> | [-tx <transaction_hash>]\n"
         "\tSend a staker fee from the block or transaction to the holder.\n"
    );

    s_srv_stake = DAP_NEW_Z(dap_chain_net_srv_stake_t);

//    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRVDAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID _STAKE_ID };
//    dap_chain_net_srv_t* l_srv = dap_chain_net_srv_add(l_uid, "srv_stake", s_callback_requested,
//                                                       s_callback_response_success, s_callback_response_error,
//                                                       s_callback_receipt_next_success, NULL);
//    l_srv->_internal = s_srv_stake;

    uint16_t l_net_count;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    for (uint16_t i = 0; i < l_net_count; i++) {
        dap_ledger_t *l_ledger = l_net_list[i]->pub.ledger;
        dap_chain_datum_tx_t *l_tx_tmp;
        dap_chain_hash_fast_t l_tx_cur_hash = {}; // start hash
        dap_chain_tx_out_cond_t *l_out_cond;
        int l_out_cond_idx;
        char l_token[DAP_CHAIN_TICKER_SIZE_MAX];
        size_t l_auth_certs_count = 0;
        dap_cert_t **l_auth_certs = NULL;
        for (dap_chain_t *l_chain = l_net_list[i]->pub.chains; l_chain; l_chain = l_chain->next) {
            l_auth_certs = dap_chain_cs_dag_poa_get_auth_certs(l_chain, &l_auth_certs_count);
            if (l_auth_certs)
                break;
            l_auth_certs = dap_chain_cs_block_poa_get_auth_certs(l_chain, &l_auth_certs_count);
            if (l_auth_certs)
                break;
        }
        // Find all stake transactions
        do {
            l_tx_tmp = dap_chain_ledger_tx_cache_find_out_cond(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE,
                                                               &l_tx_cur_hash, &l_out_cond, &l_out_cond_idx, l_token);
            if (!l_tx_tmp) {
                break;
            }
            if (l_out_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE)
                continue;
            if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, &l_tx_cur_hash, l_out_cond_idx))
                continue;
            dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_tx_tmp, NULL,
                                                                                             TX_ITEM_TYPE_SIG, NULL);
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
            if (!l_sign) {
                continue;
            }
            // Create the stake item
            dap_chain_net_srv_stake_item_t *l_stake;
            bool l_is_new = false;
            HASH_FIND(hh, s_srv_stake->itemlist, &l_out_cond->subtype.srv_stake.signing_addr, sizeof(dap_chain_addr_t), l_stake);
            if (!l_stake) {
                l_stake = DAP_NEW_Z(dap_chain_net_srv_stake_item_t);
                l_is_new = true;
            }
            l_stake->net = l_net_list[i];
            dap_stpcpy(l_stake->token, l_token);
            l_stake->value = l_out_cond->header.value;
            for (size_t i = 0; i < l_auth_certs_count; i++) {
                if (!dap_cert_compare_with_sign(l_auth_certs[i], l_sign)) {
                    l_stake->is_active = true;
                    break;
                }
            }
            l_stake->signing_addr   = l_out_cond->subtype.srv_stake.signing_addr;
            l_stake->addr_hldr      = l_out_cond->subtype.srv_stake.hldr_addr;
            l_stake->addr_fee       = l_out_cond->subtype.srv_stake.fee_addr;
            l_stake->fee_value      = l_out_cond->subtype.srv_stake.fee_value;
            l_stake->node_addr      = l_out_cond->subtype.srv_stake.signer_node_addr;
            l_stake->tx_hash        = l_tx_cur_hash;
            if (l_is_new)
                HASH_ADD(hh, s_srv_stake->itemlist, signing_addr, sizeof(dap_chain_addr_t), l_stake);
        } while (l_tx_tmp);
    }
    DAP_DELETE(l_net_list);
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

static void s_stake_update(dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx, bool a_authorized)
{
    dap_chain_net_srv_stake_item_t *l_stake;
    if (a_cond) {
        HASH_FIND(hh, s_srv_stake->itemlist, &a_cond->subtype.srv_stake.signing_addr, sizeof(dap_chain_addr_t), l_stake);
    }
    else {
        l_stake = DAP_NEW_Z(dap_chain_net_srv_stake_item_t);
    }
    // assert(l_stake);
    if (!l_stake) {
        return;
    }
    dap_chain_tx_out_cond_t *l_out_cond = (dap_chain_tx_out_cond_t *)dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_OUT_COND, NULL);
    if (!l_out_cond || l_out_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE) {
        // Stake tx is used out
        HASH_DEL(s_srv_stake->itemlist, l_stake);
        DAP_DELETE(l_stake);
        return;
    }
    // Update stake parameters
    if (!a_cond) {
        // New stake transaction
        l_stake->signing_addr = l_out_cond->subtype.srv_stake.signing_addr;
        HASH_ADD(hh, s_srv_stake->itemlist, signing_addr, sizeof(dap_chain_addr_t), l_stake);
    }
    else if (memcmp(&a_cond->subtype.srv_stake.signing_addr, &l_out_cond->subtype.srv_stake.signing_addr, sizeof(dap_chain_addr_t))) {
        HASH_DEL(s_srv_stake->itemlist, l_stake);
        dap_chain_net_srv_stake_item_t *l_stake_cur = NULL;
        HASH_FIND(hh, s_srv_stake->itemlist, &l_out_cond->subtype.srv_stake.signing_addr, sizeof(dap_chain_addr_t), l_stake_cur);
        if (l_stake_cur) {
            DAP_DELETE(l_stake);
            l_stake = l_stake_cur;
        }
        l_stake->signing_addr = l_out_cond->subtype.srv_stake.signing_addr;
        if (l_stake_cur)
            HASH_ADD(hh, s_srv_stake->itemlist, signing_addr, sizeof(dap_chain_addr_t), l_stake);
    }
    if (a_authorized) {
        l_stake->is_active = true;
    }
    l_stake->addr_hldr  = l_out_cond->subtype.srv_stake.hldr_addr;
    l_stake->addr_fee   = l_out_cond->subtype.srv_stake.fee_addr;
    l_stake->fee_value  = l_out_cond->subtype.srv_stake.fee_value;
    l_stake->node_addr  = l_out_cond->subtype.srv_stake.signer_node_addr;
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_stake->tx_hash);
}

static bool s_stake_conditions_calc(dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx, bool a_owner, bool a_update)
{
    dap_chain_tx_out_cond_t *l_out_cond = NULL;
    if (!a_cond) {
        int l_out_num = 0;
        // New stake tx
        l_out_cond = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, &l_out_num);
    } else
        l_out_cond = a_cond;
    dap_chain_net_id_t l_cur_net_id = l_out_cond->subtype.srv_stake.hldr_addr.net_id;
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_cur_net_id);
    if (!l_net)
        return false;
    size_t l_auth_certs_count = 0;
    dap_cert_t **l_auth_certs = NULL;
    for (dap_chain_t *l_chain = l_net->pub.chains; l_chain; l_chain = l_chain->next) {
        l_auth_certs = dap_chain_cs_dag_poa_get_auth_certs(l_chain, &l_auth_certs_count);
        if (l_auth_certs)
            break;
        l_auth_certs = dap_chain_cs_block_poa_get_auth_certs(l_chain, &l_auth_certs_count);
        if (l_auth_certs)
            break;
    }
    if (!l_auth_certs || !l_auth_certs_count)   // Can't validate stake tx authority for this net
        return false;
    dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
    if (!l_sign)
        return false;
    for (size_t i = 0; i < l_auth_certs_count; i++) {
        if (!dap_cert_compare_with_sign(l_auth_certs[i], l_sign)) {
            if (a_update)
                s_stake_update(a_cond, a_tx, true);
            return true;
        }
    }
    if (a_owner) {
        if (a_update)
            s_stake_update(a_cond, a_tx, false);
        return true;
    }
    return false;
}

bool dap_chain_net_srv_stake_key_delegated(dap_chain_addr_t *a_addr)
{
    if (!s_srv_stake) {
        return false;
    }
    while (!s_srv_stake->initialized);

    if (!a_addr) {
        return false;
    }
    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    HASH_FIND(hh, s_srv_stake->itemlist, a_addr, sizeof(dap_chain_addr_t), l_stake);
    if (l_stake && l_stake->is_active) { // public key delegated for this network
        return true;
    }
    return false;
}

dap_list_t *dap_chain_net_srv_stake_get_validators()
{
    dap_list_t *l_ret = NULL;
    if (!s_srv_stake || !s_srv_stake->itemlist) {
        return l_ret;
    }
    dap_chain_net_srv_stake_item_t *l_stake, *l_tmp;
    HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp) {
        if (l_stake->is_active)
            l_ret = dap_list_append(l_ret, DAP_DUP(l_stake));
    }
    return l_ret;
}

bool dap_chain_net_srv_stake_validator(dap_chain_addr_t *a_addr, dap_chain_datum_t *a_datum)
{
    if (!s_srv_stake) { // Drop all atoms if stake service inactivated
        return false;
    }
    while (!s_srv_stake->initialized);

    if (!a_addr || !a_datum) {
        return false;
    }
    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    HASH_FIND(hh, s_srv_stake->itemlist, a_addr, sizeof(dap_chain_addr_t), l_stake);
    if (!l_stake || !l_stake->is_active) { // public key not delegated for this network
        return false;
    }
    if (a_datum->header.type_id != DAP_CHAIN_DATUM_TX)
        return true;
    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)a_datum->data;
    dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_tx, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_tx_sig);
    dap_chain_hash_fast_t l_pkey_hash = {};
    dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
    dap_chain_addr_t l_owner_addr = {};
    dap_chain_addr_fill(&l_owner_addr, l_sign->header.type, &l_pkey_hash, a_addr->net_id);
    uint256_t l_outs_sum = {}, l_fee_sum = {};
    dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
    uint32_t l_out_idx_tmp = 0; // current index of 'out' item
    for (dap_list_t *l_list_tmp = l_list_out_items; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), l_out_idx_tmp++) {
        dap_chain_tx_item_type_t l_type = *(uint8_t *)l_list_tmp->data;
        if (l_type == TX_ITEM_TYPE_OUT_OLD) {
            dap_chain_tx_out_old_t *l_out = (dap_chain_tx_out_old_t *)l_list_tmp->data;
            if (!memcmp(&l_stake->addr_fee, &l_out->addr, sizeof(dap_chain_addr_t))) {
                SUM_256_256(l_fee_sum, dap_chain_uint256_from(l_out->header.value), &l_fee_sum);
            } else if (memcmp(&l_owner_addr, &l_out->addr, sizeof(dap_chain_addr_t))) {
                SUM_256_256(l_outs_sum, dap_chain_uint256_from(l_out->header.value), &l_outs_sum);
            }
        }
        if (l_type == TX_ITEM_TYPE_OUT) {
            dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t *)l_list_tmp->data;
            if (!memcmp(&l_stake->addr_fee, &l_out->addr, sizeof(dap_chain_addr_t))) {
                SUM_256_256(l_fee_sum, l_out->header.value, &l_fee_sum);
            } else if (memcmp(&l_owner_addr, &l_out->addr, sizeof(dap_chain_addr_t))) {
                SUM_256_256(l_outs_sum, l_out->header.value, &l_outs_sum);
            }
        }
        if (l_type == TX_ITEM_TYPE_OUT_EXT) {
            dap_chain_tx_out_ext_t *l_out_ext = (dap_chain_tx_out_ext_t *)l_list_tmp->data;
            if (!memcmp(&l_stake->addr_fee, &l_out_ext->addr, sizeof(dap_chain_addr_t))) {
                SUM_256_256(l_fee_sum, l_out_ext->header.value, &l_fee_sum);
            } else if (memcmp(&l_owner_addr, &l_out_ext->addr, sizeof(dap_chain_addr_t))) {
                SUM_256_256(l_outs_sum, l_out_ext->header.value, &l_outs_sum);
            }
        }
    }
    dap_list_free(l_list_out_items);
    uint256_t l_fee = uint256_0; // TODO replace with fractional mult MULT_256_FRAC_FRAC(l_outs_sum, l_stake->fee_value / 100.0); +++
    DIV_256(l_stake->fee_value, dap_chain_coins_to_balance("100.0"), &l_fee);
    if (MULT_256_COIN(l_outs_sum, l_fee, &l_fee)) {
        log_it(L_WARNING, "DANGER: MULT_256_COIN overflow! in dap_chain_net_srv_stake_validator()");
        l_fee = uint256_0;
    }
    if (compare256(l_fee_sum, l_fee) == -1) {
        return false;
    }
    return true;
}

// Freeze staker's funds when delegating an order
static dap_chain_datum_tx_t *s_stake_tx_create(dap_chain_net_srv_stake_item_t *a_stake, dap_chain_wallet_t *a_wallet)
{
    if (!a_stake || !a_stake->net || !a_stake->signing_addr.addr_ver || !a_stake->addr_hldr.addr_ver ||
            !a_stake->addr_fee.addr_ver || !*a_stake->token || !a_wallet) {
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_stake->net->pub.name);
    dap_chain_addr_t *l_owner_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_stake->net->pub.id);
    if (memcmp(l_owner_addr, &a_stake->addr_hldr, sizeof(dap_chain_addr_t))) {
        log_it(L_WARNING, "Order and wallet address do not match");
        return NULL;
    }
    dap_enc_key_t *l_owner_key = dap_chain_wallet_get_key(a_wallet, 0);
    uint256_t l_value_sell = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
    dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_ledger, a_stake->token, l_owner_addr, a_stake->value, &l_value_sell);
    if(!l_list_used_out) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_owner_addr);
        log_it(L_WARNING, "Nothing to delegate (not enough funds)");
        return NULL;
    }

    // add 'in' items to sell
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_to_items,l_value_sell)) {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_owner_addr);
        log_it(L_ERROR, "Can't compose the transaction input");
        return NULL;
    }

    // add 'out_cond' & 'out' items
    {
        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_stake(l_uid, a_stake->value, a_stake->fee_value,
                                                                                              &a_stake->addr_fee, &a_stake->addr_hldr,
                                                                                              &a_stake->signing_addr, &a_stake->node_addr);
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_owner_addr);
            log_it(L_ERROR, "Can't compose the transaction conditional output");
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_sell, a_stake->value, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
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
    // don't delete a_tx because in s_cli_srv_stake() after this function calc hash this tx
    // DAP_DELETE(a_tx);
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    if (!l_chain) {
        return false;
    }
    // Processing will be made according to autoprocess policy
    char *l_ret = NULL;
    if ((l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex")) == NULL) {
        DAP_DELETE(l_datum);
        return false;
    }
    return true;
}

static dap_chain_datum_tx_t *s_stake_tx_approve(dap_chain_net_srv_stake_item_t *a_stake, dap_cert_t *a_cert)
{
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_stake->net->pub.name);

    // create and add reciept
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 = SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
    dap_chain_datum_tx_receipt_t *l_receipt = dap_chain_datum_tx_receipt_create(l_uid, l_unit, 0, a_stake->value, NULL, 0);
    dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_receipt);
    DAP_DELETE(l_receipt);

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &a_stake->tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return NULL;
    }
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx,
                                                  DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_prev_cond_idx);
    if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, &a_stake->tx_hash, l_prev_cond_idx)) {
        log_it(L_WARNING, "Requested conditional transaction is already used out");
        return NULL;
    }
    assert(EQUAL_256(l_tx_out_cond->header.value, a_stake->value));
    dap_chain_datum_tx_add_in_cond_item(&l_tx, &a_stake->tx_hash, l_prev_cond_idx, 0);

    // add 'out_cond' item
    {
        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_stake(l_uid, a_stake->value, a_stake->fee_value,
                                                                                              &a_stake->addr_fee, &a_stake->addr_hldr,
                                                                                              &a_stake->signing_addr, &a_stake->node_addr);
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Can't compose the transaction conditional output");
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_cert->enc_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        return NULL;
    }
    return l_tx;
}

static bool s_stake_tx_invalidate(dap_chain_net_srv_stake_item_t *a_stake, dap_chain_wallet_t *a_wallet)
{
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_stake->net->pub.name);
    dap_chain_addr_t *l_owner_addr = (dap_chain_addr_t *)dap_chain_wallet_get_addr(a_wallet, a_stake->net->pub.id);
    dap_enc_key_t *l_owner_key = dap_chain_wallet_get_key(a_wallet, 0);

    // create and add receipt
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 = SERV_UNIT_UNDEFINED};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
    dap_chain_datum_tx_receipt_t *l_receipt =  dap_chain_datum_tx_receipt_create(l_uid, l_unit, 0, a_stake->value, NULL, 0);
    dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_receipt);
    DAP_DELETE(l_receipt);

    // add 'in' item to buy from conditional transaction
    dap_chain_datum_tx_t *l_cond_tx = dap_chain_ledger_tx_find_by_hash(l_ledger, &a_stake->tx_hash);
    if (!l_cond_tx) {
        log_it(L_WARNING, "Requested conditional transaction not found");
        return false;
    }
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx,
                                                DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_prev_cond_idx);
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

dap_chain_net_srv_stake_item_t *s_stake_item_from_order(dap_chain_net_t *a_net, dap_chain_net_srv_order_t *a_order)
{
    if (a_order->version < 2) {
        log_it(L_WARNING, "Order is unsigned");
        return NULL;
    }
    dap_srv_stake_order_ext_t *l_ext = (dap_srv_stake_order_ext_t *)a_order->ext_n_sign;
    dap_sign_t *l_sign = (dap_sign_t *)(a_order->ext_n_sign + a_order->ext_size);
    if (dap_sign_verify(l_sign, a_order, sizeof(dap_chain_net_srv_order_t) + a_order->ext_size) != 1) {
        log_it(L_WARNING, "Order sign is invalid");
        return NULL;
    } /* no need to check size here */
    dap_hash_fast_t l_pkey_hash;
    dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
    dap_chain_addr_t l_cert_addr;
    dap_chain_addr_fill(&l_cert_addr, l_sign->header.type, &l_pkey_hash, a_net->pub.id);
    dap_chain_net_srv_stake_item_t *l_item = DAP_NEW_Z(dap_chain_net_srv_stake_item_t);
    if (!l_item) {
        log_it(L_CRITICAL, "Can't allocate item");
        return NULL;
    }
    if (memcmp(&l_cert_addr, &l_ext->signing_addr, sizeof(dap_chain_addr_t))) {
        log_it(L_WARNING, "Order sign addr & signing_addr are different");
        DAP_DELETE(l_item);
        return NULL;
    }
    l_item->addr_hldr = l_ext->addr_hldr;
    l_item->signing_addr = l_ext->signing_addr;
    l_item->fee_value = l_ext->fee_value;
    l_item->net = a_net;
    l_item->value = a_order->price;
    strcpy(l_item->token, a_order->price_ticker);
    l_item->node_addr = a_order->node_addr;
    return l_item;
}

static bool s_stake_block_commit(dap_chain_net_t *a_net, dap_list_t *a_tx_hash_list)
{
    size_t l_all_tx = 0, l_process_tx = 0;
    // find all stake
    dap_list_t *l_staker_list0 = dap_chain_net_srv_stake_get_validators();
    if(!l_staker_list0){
        return false;
    }
    // find all certs
    size_t l_auth_certs_count = 0;
    dap_cert_t **l_auth_certs = NULL;
    for(dap_chain_t *l_chain = a_net->pub.chains; l_chain; l_chain = l_chain->next) {
        l_auth_certs = dap_chain_cs_dag_poa_get_auth_certs(l_chain, &l_auth_certs_count);
        if(l_auth_certs)
            break;
        l_auth_certs = dap_chain_cs_block_poa_get_auth_certs(l_chain, &l_auth_certs_count);
        if(l_auth_certs)
            break;
    }
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    uint256_t l_fee_sum_total = {};
    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    dap_enc_key_t *l_owner_key = NULL;
    while(a_tx_hash_list)
    {
        l_all_tx++;
        dap_chain_hash_fast_t *tx_hash = a_tx_hash_list->data;// = NULL;
        // Get tx by hash
        dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(a_net->pub.name);
        dap_chain_datum_tx_t *l_tx_with_cond = l_ledger ? dap_chain_ledger_tx_find_by_hash(l_ledger, tx_hash) : NULL;
        if(!l_tx_with_cond) {
            // go to the next tx
            a_tx_hash_list = dap_list_next(a_tx_hash_list);
            continue;
        }
        // Get cond out with type=DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE_STAKE within tx ???
        dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
        int l_prev_cond_idx = 0;
        l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_tx_with_cond,
                                                        DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_prev_cond_idx);

        if(!l_tx_out_cond) {
            // go to the next tx
            a_tx_hash_list = dap_list_next(a_tx_hash_list);
            continue;
        }

        // Find stake
        //dap_chain_net_srv_stake_item_t *l_stake = NULL;/
        // Get all sig within tx
        dap_list_t *l_sig_item_list0 = dap_chain_datum_tx_items_get(l_tx_with_cond, TX_ITEM_TYPE_SIG, NULL);
        dap_list_t *l_sig_item_list = l_sig_item_list0;
        while(l_sig_item_list) {
            dap_chain_tx_sig_t *l_sign_item = (dap_chain_tx_sig_t*) l_sig_item_list->data;
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig(l_sign_item);
            // find stake by l_sign
            for(size_t i = 0; i < l_auth_certs_count; i++) {
                // if the tx is signed with a key from the l_auth_certs list
                if(!dap_cert_compare_with_sign(l_auth_certs[i], l_sign)) {
                    dap_chain_addr_t *l_signing_addr = dap_cert_to_addr(l_auth_certs[i], a_net->pub.id);
                    HASH_FIND(hh, s_srv_stake->itemlist, l_signing_addr, sizeof(dap_chain_addr_t), l_stake);
                    DAP_DELETE(l_signing_addr);
                    if(l_stake)
                        break;
                    else{
                        l_owner_key = l_auth_certs[i]->enc_key;
                    }
                }
            }
            l_sig_item_list = dap_list_next(l_sig_item_list);
        }
        dap_list_free(l_sig_item_list0);

        // tmp
        //l_stake = (dap_chain_net_srv_stake_item_t*)l_staker_list0->data;
        if(!l_stake || !l_stake->is_active) {
            // go to the next tx
            a_tx_hash_list = dap_list_next(a_tx_hash_list);
            continue;
        }

        // add 'in' item from cond transaction
        if (dap_chain_ledger_tx_hash_is_used_out_item(l_ledger, tx_hash, l_prev_cond_idx)) {
            log_it(L_WARNING, "Requested conditional transaction is already used out");
            // go to the next tx
            a_tx_hash_list = dap_list_next(a_tx_hash_list);
            continue;
        }
        dap_chain_datum_tx_add_in_cond_item(&l_tx, tx_hash, l_prev_cond_idx, 0);
        // Summ funds from all in items
        uint256_t l_fee_sum = l_fee_sum_total;
        SUM_256_256(l_fee_sum, l_tx_out_cond->header.value, &l_fee_sum_total);

        l_process_tx++;
        a_tx_hash_list = dap_list_next(a_tx_hash_list);
    }
    dap_list_free_full(l_staker_list0, free);
    log_it(L_INFO, "Processed %ld tx from %ld", l_process_tx, l_all_tx);

    if(!IS_ZERO_256(l_fee_sum_total)) {
        dap_chain_addr_t l_holder_addr = l_stake->addr_hldr;

        // add a 'out' item
        if(dap_chain_datum_tx_add_out_item(&l_tx, &l_holder_addr, l_fee_sum_total) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Cant add returning coins output");
            return false;
        }
        // add 'sign' items
        if(dap_chain_datum_tx_add_sign_item(&l_tx, l_owner_key) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_ERROR, "Can't add sign output");
            return false;
        }
        if(!s_stake_tx_put(l_tx, a_net)) {
            dap_chain_datum_tx_delete(l_tx);
            return false;
        }
    }
    dap_chain_datum_tx_delete(l_tx);
    if(l_process_tx > 0)
        return true;
    return false;
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
            const char *l_net_str = NULL, *l_token_str = NULL, *l_value_str = NULL;
            const char *l_cert_str = NULL, *l_fee_str = NULL;
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

static int s_cli_srv_stake(int a_argc, char **a_argv, char **a_str_reply)
{
    enum {
        CMD_NONE, CMD_ORDER, CMD_DELEGATE, CMD_APPROVE, CMD_TX_LIST, CMD_INVALIDATE, CMD_COMMIT
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
    // Send a staker fee to staker
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, min(a_argc, l_arg_index + 1), "commit", NULL)) {
        l_cmd_num = CMD_COMMIT;
    }
    switch (l_cmd_num) {
        case CMD_ORDER:
            return s_cli_srv_stake_order(a_argc, a_argv, l_arg_index + 1, a_str_reply, l_hash_out_type);
        case CMD_DELEGATE: {
            const char *l_net_str = NULL, *l_wallet_str = NULL, *l_order_hash_str = NULL, *l_addr_fee_str = NULL;
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
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' required parameter -order");
                return -13;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee_addr", &l_addr_fee_str);
            if (!l_addr_fee_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' required parameter -fee_addr");
                return -9;
            }
            dap_chain_addr_t *l_addr_fee = dap_chain_addr_from_str(l_addr_fee_str);
            if (!l_addr_fee) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Wrong address format");
                return -10;
            }
            dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
            if (l_order) {
                dap_chain_net_srv_stake_item_t *l_stake = s_stake_item_from_order(l_net, l_order);
                if (!l_stake) {
                    DAP_DELETE(l_order);
                    DAP_DELETE(l_addr_fee);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified order is invalid");
                    return -22;
                }
                l_stake->addr_fee = *l_addr_fee;
                DAP_DELETE(l_addr_fee);
                dap_chain_addr_t *l_hldr_addr = dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);
                l_stake->addr_hldr = *l_hldr_addr;
                DAP_DELETE(l_hldr_addr);
                // Create conditional transaction
                dap_chain_datum_tx_t *l_tx = s_stake_tx_create(l_stake, l_wallet);
                dap_chain_wallet_close(l_wallet);
                if (l_tx && s_stake_tx_put(l_tx, l_net)) {
                    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_stake->tx_hash);
                    // TODO send a notification to order owner to delete it
                    dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_str);
                }
                DAP_DELETE(l_order);
                dap_cli_server_cmd_set_reply_text(a_str_reply, l_tx ? "Stake transaction has done" :
                                                                      "Stake transaction error");
                if (!l_tx) {
                    DAP_DELETE(l_stake);
                    return -19;
                }
                HASH_ADD(hh, s_srv_stake->itemlist, signing_addr, sizeof(dap_chain_addr_t), l_stake);
            } else {
                DAP_DELETE(l_addr_fee);
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified order not found");
                return -14;
            }
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
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
            if (!l_cert_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'approve' required parameter -cert");
                return -17;
            }
            dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_cert) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate not found");
                return -18;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
            if (!l_tx_hash_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'delegate' required parameter -tx");
                return -13;
            }
            dap_chain_hash_fast_t l_tx_hash = {};
            int l_result = dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash);
            if (l_result)
                l_result = dap_enc_base58_decode(l_tx_hash_str, &l_tx_hash) - sizeof(dap_chain_hash_fast_t);
            if (l_result) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid transaction hash format");
                return -14;
            }
            dap_chain_net_srv_stake_item_t *l_stake = NULL, *l_tmp;
            HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp) {
                if (!memcmp(&l_stake->tx_hash, &l_tx_hash, sizeof(dap_chain_hash_fast_t))) {
                    break;
                }
            }
            if (!l_stake) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Transaction %s not found", l_tx_hash_str);
                return -20;
            }
            dap_chain_datum_tx_t *l_tx = s_stake_tx_approve(l_stake, l_cert);
            if (l_tx && s_stake_tx_put(l_tx, l_net)) {
                dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_stake->tx_hash);
                l_stake->is_active = true;
            }
        } break;
        case CMD_TX_LIST: {
            const char *l_net_str = NULL;
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
            dap_string_t *l_reply_str = dap_string_new("");
            HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp) {
                if (l_stake->net->pub.id.uint64 != l_net->pub.id.uint64) {
                    continue;
                }
                char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_stake->tx_hash);
                char *l_addr_hldr_str = dap_chain_addr_to_str(&l_stake->addr_hldr);
                char *l_signing_addr_str = dap_chain_addr_to_str(&l_stake->signing_addr);
                char *l_addr_fee_str = dap_chain_addr_to_str(&l_stake->addr_fee);
                char *l_balance = dap_chain_balance_print(l_stake->value);
                char *l_fee = dap_chain_balance_to_coins(l_stake->fee_value);
                dap_string_append_printf(l_reply_str, "%s %s %s %s %s %s %s\n", l_tx_hash_str, l_stake->token,
                                                                                l_balance, l_addr_hldr_str,
                                                                                l_signing_addr_str, l_addr_fee_str,
                                                                                l_fee);
                DAP_DELETE(l_balance);
                DAP_DELETE(l_fee);
                DAP_DELETE(l_tx_hash_str);
                DAP_DELETE(l_addr_hldr_str);
                DAP_DELETE(l_signing_addr_str);
                DAP_DELETE(l_addr_fee_str);
            }
            if (!l_reply_str->len) {
                dap_string_append(l_reply_str, "No transaction found");
            }
            *a_str_reply = dap_string_free(l_reply_str, false);
        } break;
        case CMD_INVALIDATE: {
            const char *l_net_str = NULL, *l_wallet_str = NULL, *l_tx_hash_str = NULL;
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
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'invalidate' required parameter -wallet");
                return -17;
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config));
            if (!l_wallet) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified wallet not found");
                return -18;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
            if (!l_tx_hash_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'invalidate' required parameter -tx");
                return -13;
            }
            dap_chain_hash_fast_t l_tx_hash = {};
            dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash);
            dap_chain_net_srv_stake_item_t *l_stake = NULL, *l_tmp;
            HASH_ITER(hh, s_srv_stake->itemlist, l_stake, l_tmp) {
                if (!memcmp(&l_stake->tx_hash, &l_tx_hash, sizeof(dap_chain_hash_fast_t))) {
                    break;
                }
            }
            if (!l_stake) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Transaction %s not found", l_tx_hash_str);
                dap_chain_wallet_close(l_wallet);
                return -20;
            }
            bool l_success = s_stake_tx_invalidate(l_stake, l_wallet);
            dap_chain_wallet_close(l_wallet);
            if (l_success) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Stake successfully returned to owner");
                // don't delete stake here because it delete in s_stake_update after invalidate tx approve
                // HASH_DEL(s_srv_stake->itemlist, l_stake);
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't invalidate transaction %s", l_tx_hash_str);
                return -21;
            }
        } break;
        case CMD_COMMIT: {
            const char *l_net_str = NULL, *l_tx_hash_str = NULL, *l_block_hash_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if(!l_net_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'commit' required parameter -net");
                return -3;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if(!l_net) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Network %s not found", l_net_str);
                return -4;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-block", &l_block_hash_str);
            if(!l_tx_hash_str && !l_block_hash_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'commit' required parameter -block or -tx");
                return -22;
            }
            // list of tx hash
            dap_list_t *l_tx_list = NULL;
            if(l_block_hash_str) {
                dap_chain_hash_fast_t l_block_hash = { };
                dap_chain_hash_fast_from_str(l_block_hash_str, &l_block_hash);
                // TODO add tx from block to tx_list
            }
            if(l_tx_hash_str) {
                dap_chain_hash_fast_t *l_tx_hash = DAP_NEW_Z(dap_chain_hash_fast_t);
                dap_chain_hash_fast_from_str(l_tx_hash_str, l_tx_hash);
                l_tx_list = dap_list_append(l_tx_list, l_tx_hash);
            }
            bool l_success = s_stake_block_commit(l_net, l_tx_list);
            dap_list_free_full(l_tx_list, free);
            if(l_success) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Stake successfully transfered to holder");
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't transfered to holder");
                return -23;
            }
        }

        default: {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Command %s not recognized", a_argv[l_arg_index]);
            return -1;
        }
    }
    return 0;
}

static bool s_verificator_stake_callback(dap_ledger_t * a_ledger, dap_hash_fast_t *a_tx_out_hash, dap_chain_tx_out_cond_t *a_cond,
                                                      dap_chain_datum_tx_t *a_tx_in, bool a_owner)
{
    UNUSED(a_ledger);
    UNUSED(a_tx_out_hash);
    if (!s_srv_stake) {
        return false;
    }
    return s_stake_conditions_calc(a_cond, a_tx_in, a_owner, false);
}

/**
 * @brief s_verificator_stake_updater_callback
 * @param a_ledger
 * @param a_tx_out
 * @param a_cond
 * @param a_tx_in
 * @param a_owner
 * @return
 */
static bool s_verificator_stake_updater_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_cond)
{
    UNUSED(a_ledger);
    if (!s_srv_stake) {
        return false;
    }
    return s_stake_conditions_calc(a_cond, a_tx, true, true);
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
