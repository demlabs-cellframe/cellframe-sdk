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
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_cache.h"
#include "dap_config.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_enc_base58.h"
#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_chain_net_decree.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_cs_esbocs.h"
#include "rand/dap_rand.h"
#include "dap_chain_node_client.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "json_object.h"
#include "dap_json_rpc_errors.h"
#include "dap_cli_server.h"
#include "dap_chain_net_srv_order.h"

#define LOG_TAG "dap_chain_net_srv_stake_pos_delegate"

#define DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_GDB_GROUP "delegate_keys"

typedef enum s_cli_srv_stake_err{
    DAP_CHAIN_NODE_CLI_SRV_STAKE_OK = 0,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_MEMORY_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_HASH_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_WRONG_HASH_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_NEED_TX_NOT_OUTPUT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_TX_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_HASH_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_NODE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_NODE_BAD_SIZE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_CON_TO_NODE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_RES_FROM_NODE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_SEND_PKT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_CERT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_WRONG_CERT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_CERT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_NOT_POA_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DECREE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_STAKE_IN_NET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_WRONG_SUB_COMMAND_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ANCHOR_NOT_SUPPORT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_MIN_STAKE_SET_FAILED_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_MAX_WEIGHT_SET_FAILED_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_PERCENT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UNRECOGNIZE_COM_ERR,

    DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_NET_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_NODE_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_ID_NET_ADDR_DIF_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_ADDR_WALLET_DIF_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_WALLET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_NET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_CHAIN_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_INVALID_PKEY_ERR,

    /* add custom codes here */

    //DAP_CHAIN_NODE_CLI_COM_TX_UNKNOWN /* MAX */
} s_cli_srv_stake_err_t;
static int s_cli_srv_stake(int a_argc, char **a_argv, void **a_str_reply);

static int s_stake_verificator_callback(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond,
                                                      dap_chain_datum_tx_t *a_tx_in, bool a_owner);
static void s_stake_updater_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_cond);

static void s_stake_deleted_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_cond);

static void s_cache_data(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_addr_t *a_signing_addr);
static void s_uncache_data(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_addr_t *a_signing_addr);
static json_object* s_dap_chain_net_srv_stake_reward_all(json_object* a_json_arr_reply, dap_chain_node_info_t *a_node_info, dap_chain_t *a_chain,
                                 dap_chain_net_t *a_net, dap_time_t a_time_form, dap_time_t a_time_to,
                                 size_t a_limit, size_t a_offset, bool a_brief, bool a_head);

static dap_list_t *s_srv_stake_list = NULL;

static bool s_debug_more = false;

static bool s_tag_check_key_delegation(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{
    // keydelegation open: have STAK_POS_DELEGATE out
    
    if (a_items_grp->items_out_cond_srv_stake_pos_delegate) {
        if (a_action) *a_action = DAP_CHAIN_TX_TAG_ACTION_OPEN;
        return true;
    }

    //key delegation invalidation (close): have IN_COND linked with STAKE_POS_DELEGATE out
    if (a_items_grp->items_in_cond) 
    {
       for (dap_list_t *it = a_items_grp->items_in_cond; it; it = it->next) {
            dap_chain_tx_in_cond_t *l_tx_in = it->data;
            dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_ledger_get_tx_out_cond_linked_to_tx_in_cond(a_ledger, l_tx_in);

            if (l_tx_out_cond && l_tx_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE) {
                if (a_action) *a_action = DAP_CHAIN_TX_TAG_ACTION_CLOSE;
                return true;
            }   
        }
    }

    return false;
}

/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_stake_pos_delegate_init()
{
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, s_stake_verificator_callback, s_stake_updater_callback, s_stake_deleted_callback);
    dap_cli_server_cmd_add("srv_stake", s_cli_srv_stake, "Delegated stake service commands",
            "\t\t=== Commands for work with orders ===\n"
    "srv_stake order create [fee] -net <net_name> -value <value> -cert <priv_cert_name> [-H {hex(default) | base58}]\n"
        "\tCreates an order declaring the minimum fee that the validator agrees to for process a transaction.\n"
    "srv_stake order create validator -net <net_name> -value_min <minimum_stake_value> -value_max <maximum_stake_value>"
                        " -tax <percent> -cert <priv_cert_name> [-node_addr <for_validator_node>] [-H {hex(default) | base58}]\n"
        "\tCreates an order declaring wanted tax and minimum/maximum stake value that the validator agrees to work.\n"
    "srv_stake order create staker -net <net_name> -w <wallet_with_m_tokens> -value <stake_value> -fee <value> -tax <percent>"
                        " [-addr <for_tax_collecting>]  [-cert <for_order_signing>] [-H {hex(default) | base58}]\n"
        "\tCreates an order allowing the validator to delegate it's key with specified params\n"
    "srv_stake order list [fee | validator | staker] -net <net_name>\n"
        "\tGet orders list of specified type within specified net name\n"
    "srv_stake order remove -net <net_name> -order <order_hash>\n"
        "\tRemove order with specified hash\n"
            "\t\t === Commands for work with stake delegate ===\n"
    "srv_stake delegate {[-cert <pub_cert_name> | -pkey <pkey> -sign_type <sign_type>] -value <datoshi> | "
                                "-order <order_hash> {[-tax_addr <wallet_addr_for_tax_collecting>] | "
                                        "-cert <priv_cert_name> [-node_addr <for_validator_node>]}}"
                        " -net <net_name> -w <wallet_name> -fee <value>\n"
        "\tDelegate public key in specified certificate or order with specified net name. Pay with specified value of m-tokens of native net token.\n"
    "srv_stake update -net <net_name> {-tx <transaction_hash> | -cert <delegated_cert>} -w <wallet_name> -value <new_delegation_value> -fee <value>\n"
        "\tUpdate public key delegation value for specified certificate or transaction hash with specified net name. Pay or cacheback the difference of m-tokens of native net token.\n"
    "srv_stake invalidate -net <net_name> {-tx <transaction_hash> -w <wallet_name> -fee <value> | -siging_pkey_hash <pkey_hash> -signing_pkey_type <pkey_type> -poa_cert <cert_name>}\n"
        "\tInvalidate requested delegated stake transaction by hash or cert name or cert pkey hash within net name and"
        " return m-tokens to specified wallet (if any)\n"
    "srv_stake approve -net <net_name> -tx <transaction_hash> -poa_cert <priv_cert_name>\n"
        "\tApprove stake transaction by root node certificate within specified net name\n"
    "srv_stake list keys -net <net_name> [-cert <delegated_cert> | -pkey <pkey_hash_str>]\n"
        "\tShow the list of active stake keys (optional delegated with specified cert).\n"
    "srv_stake list tx -net <net_name> \n"
        "\tShow the list of key delegation transactions.\n"
    "srv_stake min_value -net <net_name> [-chain <chain_name>] -poa_cert <poa_cert_name> -value <value>\n"
        "\tSets the minimum stake value\n"
    "srv_stake max_weight -net <net_name> [-chain <chain_name>] -poa_cert <poa_cert_name> -percent <value>\n"
        "\tSets maximum validator related weight (in percent)\n"
    "srv_stake check -net <net_name> -tx <tx_hash>\n"
        "\tCheck remote validator\n"
    "srv_stake reward -net <net_name> {-node_addr <node_address> | -all} [-date_from <YYMMDD> -date_to <YYMMDD>] [-brief] [-limit] [-offset] [-head]\n"
        "\tShow the number of rewards for the validators\n"
    );

    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
    dap_ledger_service_add(l_uid, "pos_delegate", s_tag_check_key_delegation);
    return 0;
}

static dap_chain_net_srv_stake_t *s_srv_stake_by_net_id(dap_chain_net_id_t a_net_id)
{
    for (dap_list_t *it = s_srv_stake_list; it; it = it->next) {
        dap_chain_net_srv_stake_t *l_srv_stake = it->data;
        if (l_srv_stake->net_id.uint64 == a_net_id.uint64)
            return l_srv_stake;
    }
    return NULL;
}

int dap_chain_net_srv_stake_net_add(dap_chain_net_id_t a_net_id)
{
    dap_chain_net_srv_stake_t *l_srv_stake = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_net_srv_stake_t, -1);
    l_srv_stake->net_id = a_net_id;
    l_srv_stake->delegate_allowed_min = dap_chain_coins_to_balance("1.0");
    dap_list_t *l_list_last = dap_list_last(s_srv_stake_list);
    s_srv_stake_list = dap_list_append(s_srv_stake_list, l_srv_stake);
    if (l_list_last == dap_list_last(s_srv_stake_list)) {
        log_it(L_ERROR, "Can't add net %" DAP_UINT64_FORMAT_X " to stake service net list", a_net_id.uint64);
        DAP_DELETE(l_srv_stake);
        return -2;
    }
    log_it(L_NOTICE, "Successfully added net ID 0x%016" DAP_UINT64_FORMAT_x, a_net_id.uint64);
    return 0;
}

/**
 * @brief delete ht and hh concretic net from s_srv_stake 
 */
static void s_stake_net_clear(dap_chain_net_t *a_net)
{
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_net->pub.id);
    dap_return_if_fail(l_srv_stake);
    dap_chain_net_srv_stake_item_t *l_stake = NULL, *l_tmp = NULL;
    HASH_ITER(ht, l_srv_stake->tx_itemlist, l_stake, l_tmp) {
        // Clang bug at this, l_stake should change at every loop cycle
        HASH_DELETE(ht, l_srv_stake->tx_itemlist, l_stake);
    }
    HASH_ITER(hh, l_srv_stake->itemlist, l_stake, l_tmp) {
        // Clang bug at this, l_stake should change at every loop cycle
        HASH_DEL(l_srv_stake->itemlist, l_stake);
        DAP_DELETE(l_stake);
    }
    dap_chain_net_srv_stake_cache_item_t *l_cache_item = NULL, *l_cache_tmp = NULL;
    HASH_ITER(hh, l_srv_stake->cache, l_cache_item, l_cache_tmp) {
        // Clang bug at this, l_stake should change at every loop cycle
        HASH_DEL(l_srv_stake->cache, l_cache_item);
        DAP_DELETE(l_cache_item);
    }
}

void dap_chain_net_srv_stake_pos_delegate_deinit()
{
    for (dap_chain_net_t *it = dap_chain_net_iter_start(); it; it = dap_chain_net_iter_next(it))
        s_stake_net_clear(it);
    dap_list_free_full(s_srv_stake_list, NULL);
    s_srv_stake_list = NULL;
}

static int s_stake_verificator_callback(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond,
                                         dap_chain_datum_tx_t *a_tx_in, bool a_owner)
{
    dap_return_val_if_fail(a_ledger && a_cond && a_tx_in, -1);
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_ledger->net->pub.id);
    dap_return_val_if_fail(l_srv_stake, -2);

#define m_cond_check()                                                                              \
(                                                                                                   \
    {                                                                                               \
        if (l_tx_new_cond->header.subtype != a_cond->header.subtype ||                              \
                l_tx_new_cond->header.ts_expires != a_cond->header.ts_expires ||                    \
                !dap_chain_net_srv_uid_compare(l_tx_new_cond->header.srv_uid,                       \
                                               a_cond->header.srv_uid)                              \
                ) {                                                                                 \
            log_it(L_WARNING, "Conditional out and conditional in have different headers");         \
            return -3;                                                                              \
        }                                                                                           \
        if (l_tx_new_cond->tsd_size != a_cond->tsd_size ||                                          \
                memcmp(l_tx_new_cond->tsd, a_cond->tsd, a_cond->tsd_size)) {                        \
            log_it(L_WARNING, "Conditional out and conditional in have different TSD sections");    \
            return -4;                                                                              \
        }                                                                                           \
        if (dap_chain_addr_is_blank(&l_tx_new_cond->subtype.srv_stake_pos_delegate.signing_addr) || \
                l_tx_new_cond->subtype.srv_stake_pos_delegate.signer_node_addr.uint64 == 0) {       \
            log_it(L_WARNING, "Not blank address or key fields in order conditional tx");           \
            return -5;                                                                              \
        }                                                                                           \
    }                                                                                               \
)
    int l_out_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_new_cond = dap_chain_datum_tx_out_cond_get(
                                                a_tx_in, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_out_idx);
    // It's a order conditional TX
    if (dap_chain_addr_is_blank(&a_cond->subtype.srv_stake_pos_delegate.signing_addr) ||
            a_cond->subtype.srv_stake_pos_delegate.signer_node_addr.uint64 == 0) {
        if (a_owner)
            return 0;
        if (!l_tx_new_cond) {
            log_it(L_ERROR, "Condition not found in conditional tx");
            return -13;
        }
        m_cond_check();

        if (compare256(l_tx_new_cond->header.value, a_cond->header.value)) {
            log_it(L_WARNING, "Conditional out and conditional in have different values");
            return -14;
        }
        return 0;
    }
    if (!a_owner) {
        log_it(L_WARNING, "Trying to spend conditional tx by not a owner");
        return -11;
    }
    // Delegation value update (dynamic weight feature)
    if (l_tx_new_cond) {

        m_cond_check();

        if (!dap_chain_addr_compare(&l_tx_new_cond->subtype.srv_stake_pos_delegate.signing_addr,
                                    &a_cond->subtype.srv_stake_pos_delegate.signing_addr)) {
            log_it(L_WARNING, "Conditional out and conditional in have different signer key hashes");
            return -15;
        }
        if (l_tx_new_cond->subtype.srv_stake_pos_delegate.signer_node_addr.uint64 !=
                a_cond->subtype.srv_stake_pos_delegate.signer_node_addr.uint64) {
            log_it(L_WARNING, "Conditional out and conditional in have different node addresses");
            return -16;
        }
        if (compare256(l_tx_new_cond->header.value,
                       dap_chain_net_srv_stake_get_allowed_min_value(a_ledger->net->pub.id)) == -1) {
            log_it(L_WARNING, "New conditional out have value %s lower than minimum service required",
                                                    dap_uint256_to_char(l_tx_new_cond->header.value, NULL));
            return -17;
        }
    } else {
        // It's a delegation conitional TX
        dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t *)
                                                dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL);
        if (!l_tx_in_cond) {
            log_it(L_ERROR, "Conditional in item not found in current tx");
            return -6;
        }
        // ATTENTION: It's correct only with single IN_COND TX item
        dap_hash_fast_t *l_prev_hash = &l_tx_in_cond->header.tx_prev_hash;
        if (dap_hash_fast_is_blank(l_prev_hash)) {
            log_it(L_ERROR, "Blank hash of prev tx in tx_in_cond");
            return -7;
        }
        if (a_tx_in->header.ts_created < 1706227200) // Jan 26 2024 00:00:00 GMT, old policy rules
            return 0;
        dap_chain_net_srv_stake_item_t *l_stake = NULL;
        HASH_FIND(ht, l_srv_stake->tx_itemlist, l_prev_hash, sizeof(dap_hash_t), l_stake);
        if (l_stake) {
            log_it(L_WARNING, "Key %s is empowered for now, need to revoke it first",
                                    dap_hash_fast_to_str_static(&l_stake->signing_addr.data.hash_fast));
            return -12;
        }
    }
    return 0;
}

static void s_stake_updater_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_cond)
{
    dap_return_if_fail(a_ledger && a_tx_in);
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_ledger->net->pub.id);
    dap_return_if_fail(l_srv_stake);
    if (!a_cond)
        return;
    dap_chain_tx_out_cond_t *l_tx_new_cond = dap_chain_datum_tx_out_cond_get(a_tx_in, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, NULL);
    dap_chain_addr_t *l_signing_addr = &a_cond->subtype.srv_stake_pos_delegate.signing_addr;
    if (l_tx_new_cond)
        dap_chain_net_srv_stake_key_update(l_signing_addr, l_tx_new_cond->header.value, a_tx_in_hash);
    else
        dap_chain_net_srv_stake_key_invalidate(l_signing_addr);
    s_cache_data(a_ledger, a_tx_in, l_signing_addr);
}

static void s_stake_deleted_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_cond)
{
    if (!a_cond)
        return;
    dap_chain_addr_t *l_signing_addr = &a_cond->subtype.srv_stake_pos_delegate.signing_addr;
    dap_chain_net_srv_stake_key_invalidate(l_signing_addr);
    s_uncache_data(a_ledger, a_tx, l_signing_addr);
}

static bool s_srv_stake_is_poa_cert(dap_chain_net_t *a_net, dap_enc_key_t *a_key)
{
    bool l_is_poa_cert = false;
    dap_pkey_t *l_pkey = dap_pkey_from_enc_key(a_key);
    dap_list_t *l_pkeys = dap_chain_net_get_net_decree(a_net)->pkeys;
    for (dap_list_t *it = l_pkeys; it; it = it->next)
        if (dap_pkey_compare(l_pkey, (dap_pkey_t *)it->data)) {
            l_is_poa_cert = true;
            break;
        }
    DAP_DELETE(l_pkey);
    return l_is_poa_cert;
}

#define LIMIT_DELTA UINT64_C(1000000000000) // 1.0e-6
static bool s_weights_truncate(dap_chain_net_srv_stake_t *l_srv_stake, const uint256_t a_limit)
{
    uint256_t l_sum = uint256_0;
    for (dap_chain_net_srv_stake_item_t *it = l_srv_stake->itemlist; it; it = it->hh.next)
        SUM_256_256(l_sum, it->value, &l_sum);
    uint256_t l_weight_max;
    MULT_256_COIN(l_sum, a_limit, &l_weight_max);
    size_t l_exceeds_count = 0;
    uint256_t l_sum_others = l_sum;
    for (dap_chain_net_srv_stake_item_t *it = l_srv_stake->itemlist; it; it = it->hh.next) {
        uint256_t l_weight_with_delta;
        SUBTRACT_256_256(it->value, GET_256_FROM_64(LIMIT_DELTA), &l_weight_with_delta);
        if (compare256(l_weight_with_delta, l_weight_max) == 1) {
            SUBTRACT_256_256(l_sum_others, it->value, &l_sum_others);
            it->value = uint256_0;
            l_exceeds_count++;
        }
    }
    if (l_exceeds_count) {
        uint256_t delta = dap_uint256_decimal_from_uint64(l_exceeds_count);
        uint256_t kappa;
        DIV_256_COIN(dap_uint256_decimal_from_uint64(1), a_limit, &kappa);
        SUBTRACT_256_256(kappa, delta, &kappa);
        DIV_256_COIN(l_sum_others, kappa, &kappa);
        for (dap_chain_net_srv_stake_item_t *it = l_srv_stake->itemlist; it; it = it->hh.next)
            if (IS_ZERO_256(it->value))
                it->value = kappa;
    }
    return l_exceeds_count;
}
#undef LIMIT_DELTA

static void s_stake_recalculate_weights(dap_chain_net_id_t a_net_id)
{
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_net_id);
    dap_return_if_fail(l_srv_stake);
    if (IS_ZERO_256(l_srv_stake->delegate_percent_max))
        return;
    size_t l_validators_count = HASH_COUNT(l_srv_stake->itemlist);
    uint256_t l_limit_min;
    DIV_256(dap_uint256_decimal_from_uint64(1), GET_256_FROM_64(l_validators_count), &l_limit_min);
    if (compare256(l_srv_stake->delegate_percent_max, l_limit_min) == 1)
        l_limit_min = l_srv_stake->delegate_percent_max;
    for (dap_chain_net_srv_stake_item_t *it = l_srv_stake->itemlist; it; it = it->hh.next)
        it->value = it->locked_value;       // restore original locked values
    while (s_weights_truncate(l_srv_stake, l_limit_min));
}

void dap_chain_net_srv_stake_key_delegate(dap_chain_net_t *a_net, dap_chain_addr_t *a_signing_addr, dap_hash_fast_t *a_stake_tx_hash,
                                          uint256_t a_value, dap_chain_node_addr_t *a_node_addr)
{
    dap_return_if_fail(a_net && a_signing_addr && a_node_addr && a_stake_tx_hash);
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_net->pub.id);
    if (!l_srv_stake)
        return log_it(L_ERROR, "Can't delegate key: no stake service found by net id %"DAP_UINT64_FORMAT_U" from address %s",
                                a_signing_addr->net_id.uint64, dap_chain_addr_to_str_static(a_signing_addr));
    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    bool l_found = false;
    HASH_FIND(hh, l_srv_stake->itemlist, &a_signing_addr->data.hash_fast, sizeof(dap_hash_fast_t), l_stake);
    if (!l_stake)
        l_stake = DAP_NEW_Z(dap_chain_net_srv_stake_item_t);
    else {
        l_found = true;
        HASH_DELETE(ht, l_srv_stake->tx_itemlist, l_stake);
    }
    l_stake->net = a_net;
    l_stake->node_addr = *a_node_addr;
    l_stake->signing_addr = *a_signing_addr;
    l_stake->value = l_stake->locked_value = a_value;
    l_stake->tx_hash = *a_stake_tx_hash;
    l_stake->is_active = true;
    if (!l_found)
        HASH_ADD(hh, l_srv_stake->itemlist, signing_addr.data.hash_fast, sizeof(dap_hash_fast_t), l_stake);
    if (!dap_hash_fast_is_blank(a_stake_tx_hash)) {
        HASH_ADD(ht, l_srv_stake->tx_itemlist, tx_hash, sizeof(dap_hash_fast_t), l_stake);
        dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, a_stake_tx_hash);
        if (l_tx) {
            dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, NULL);
            if (l_cond && l_cond->tsd_size == dap_chain_datum_tx_item_out_cond_create_srv_stake_get_tsd_size()) {
                dap_tsd_t *l_tsd = dap_tsd_find(l_cond->tsd, l_cond->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_ADDR);
                l_stake->sovereign_addr = dap_tsd_get_scalar(l_tsd, dap_chain_addr_t);
                l_tsd = dap_tsd_find(l_cond->tsd, l_cond->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_VALUE);
                l_stake->sovereign_tax = dap_tsd_get_scalar(l_tsd, uint256_t);
                if (compare256(l_stake->sovereign_tax, dap_chain_coins_to_balance("1.0")) == 1)
                    l_stake->sovereign_tax = dap_chain_coins_to_balance("1.0");
            }
        }
    }
    dap_chain_esbocs_add_validator_to_clusters(a_net->pub.id, a_node_addr);
    const char *l_value_str; dap_uint256_to_char(a_value, &l_value_str);
    log_it(L_NOTICE, "Added key with fingerprint %s and locked value %s for node " NODE_ADDR_FP_STR,
                            dap_chain_hash_fast_to_str_static(&a_signing_addr->data.hash_fast), l_value_str, NODE_ADDR_FP_ARGS(a_node_addr));
    s_stake_recalculate_weights(a_signing_addr->net_id);
}

void dap_chain_net_srv_stake_key_invalidate(dap_chain_addr_t *a_signing_addr)
{
    dap_return_if_fail(a_signing_addr);
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_signing_addr->net_id);
    if (!l_srv_stake)
        return log_it(L_ERROR, "Can't invalidate key: no stake service found by net id%"DAP_UINT64_FORMAT_U" from address %s",
                                a_signing_addr->net_id.uint64, dap_chain_addr_to_str_static(a_signing_addr));
    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    HASH_FIND(hh, l_srv_stake->itemlist, &a_signing_addr->data.hash_fast, sizeof(dap_hash_fast_t), l_stake);
    if (!l_stake)
        return log_it(L_INFO, "No delegated stake found by addr %s to invalidate", dap_chain_addr_to_str_static(a_signing_addr));
    dap_return_if_fail(l_stake);
    dap_chain_esbocs_remove_validator_from_clusters(l_stake->signing_addr.net_id, &l_stake->node_addr);
    HASH_DEL(l_srv_stake->itemlist, l_stake);
    HASH_DELETE(ht, l_srv_stake->tx_itemlist, l_stake);
    const char *l_value_str; dap_uint256_to_char(l_stake->locked_value, &l_value_str);
    log_it(L_NOTICE, "Removed key with fingerprint %s and locked value %s for node " NODE_ADDR_FP_STR,
                            dap_chain_hash_fast_to_str_static(&a_signing_addr->data.hash_fast), l_value_str, NODE_ADDR_FP_ARGS_S(l_stake->node_addr));
    DAP_DELETE(l_stake);
    s_stake_recalculate_weights(a_signing_addr->net_id);
}

void dap_chain_net_srv_stake_key_update(dap_chain_addr_t *a_signing_addr, uint256_t a_new_value, dap_hash_fast_t *a_new_tx_hash)
{
    dap_return_if_fail(a_signing_addr && a_new_tx_hash);
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_signing_addr->net_id);
    if (!l_srv_stake)
        return log_it(L_ERROR, "Can't update key: no stake service found by net id %"DAP_UINT64_FORMAT_U" from address %s",
                                a_signing_addr->net_id.uint64, dap_chain_addr_to_str_static(a_signing_addr));
    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    HASH_FIND(hh, l_srv_stake->itemlist, &a_signing_addr->data.hash_fast, sizeof(dap_hash_fast_t), l_stake);
    if (!l_stake)
        return log_it(L_INFO, "No delegated found by addr %s to update", dap_chain_addr_to_str_static(a_signing_addr));
    HASH_DELETE(ht, l_srv_stake->tx_itemlist, l_stake);
    char *l_old_value_str = dap_chain_balance_to_coins(l_stake->locked_value);
    l_stake->locked_value = l_stake->value = a_new_value;
    l_stake->tx_hash = *a_new_tx_hash;
    HASH_ADD(ht, l_srv_stake->tx_itemlist, tx_hash, sizeof(dap_hash_fast_t), l_stake);
    const char *l_new_value_str; dap_uint256_to_char(a_new_value, &l_new_value_str);
    log_it(L_NOTICE, "Updated key with fingerprint %s and locked value %s to new locked value %s for node " NODE_ADDR_FP_STR,
                            dap_chain_hash_fast_to_str_static(&a_signing_addr->data.hash_fast), l_old_value_str,
                                l_new_value_str, NODE_ADDR_FP_ARGS_S(l_stake->node_addr));
    DAP_DELETE(l_old_value_str);
    s_stake_recalculate_weights(a_signing_addr->net_id);
}

void dap_chain_net_srv_stake_set_allowed_min_value(dap_chain_net_id_t a_net_id, uint256_t a_value)
{
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_net_id);
    dap_return_if_fail(l_srv_stake);
    l_srv_stake->delegate_allowed_min = a_value;
    for (dap_chain_net_srv_stake_item_t *it = l_srv_stake->itemlist; it; it = it->hh.next)
        if (dap_hash_fast_is_blank(&it->tx_hash))
            it->locked_value = it->value = a_value;
}

void dap_chain_net_srv_stake_set_percent_max(dap_chain_net_id_t a_net_id, uint256_t a_value)
{
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_net_id);
    dap_return_if_fail(l_srv_stake);
    l_srv_stake->delegate_percent_max = a_value;
    s_stake_recalculate_weights(a_net_id);
}

uint256_t dap_chain_net_srv_stake_get_allowed_min_value(dap_chain_net_id_t a_net_id)
{
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_net_id);
    dap_return_val_if_fail(l_srv_stake, uint256_0);
    return l_srv_stake->delegate_allowed_min;
}

uint256_t dap_chain_net_srv_stake_get_percent_max(dap_chain_net_id_t a_net_id)
{
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_net_id);
    dap_return_val_if_fail(l_srv_stake, uint256_0);
    return l_srv_stake->delegate_percent_max;
}

int dap_chain_net_srv_stake_key_delegated(dap_chain_addr_t *a_signing_addr)
{
    dap_return_val_if_fail(a_signing_addr, 0);
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_signing_addr->net_id);
    dap_return_val_if_fail(l_srv_stake, 0);
    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    HASH_FIND(hh, l_srv_stake->itemlist, &a_signing_addr->data.hash_fast, sizeof(dap_hash_fast_t), l_stake);
    if (l_stake) // public key delegated for this network
        return l_stake->is_active ? 1 : -1;
    return 0;
}

dap_list_t *dap_chain_net_srv_stake_get_validators(dap_chain_net_id_t a_net_id, bool a_only_active, uint16_t **a_excluded_list)
{
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_net_id);
    dap_return_val_if_fail(l_srv_stake, NULL);
    if (!l_srv_stake->itemlist)
        return NULL;
    dap_list_t *l_ret = NULL;
    const uint16_t l_arr_resize_step = 64;
    size_t l_arr_size = l_arr_resize_step, l_arr_idx = 1, l_list_idx = 0;
    if (a_excluded_list)
        *a_excluded_list = DAP_NEW_Z_COUNT_RET_VAL_IF_FAIL(uint16_t, l_arr_size, NULL);
    for (dap_chain_net_srv_stake_item_t *l_stake = l_srv_stake->itemlist; l_stake; l_stake = l_stake->hh.next) {
        if (l_stake->is_active || !a_only_active) {
            void *l_data = DAP_DUP(l_stake);
            if (!l_data)
                goto fail_ret;
            l_ret = dap_list_append(l_ret, l_data);
        }
        if (!l_stake->is_active && a_excluded_list) {
            (*a_excluded_list)[l_arr_idx++] = l_list_idx;
            if (l_arr_idx == l_arr_size) {
                l_arr_size += l_arr_resize_step;
                void *l_new_arr = DAP_REALLOC_COUNT(*a_excluded_list, l_arr_size);
                if (!l_new_arr)
                    goto fail_ret;
                else
                    *a_excluded_list = l_new_arr;
            }
        }
        l_list_idx++;
    }
    return l_ret;
fail_ret:
    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
    dap_list_free_full(l_ret, NULL);
    if (a_excluded_list)
        DAP_DELETE(*a_excluded_list);
    return NULL;
}

int dap_chain_net_srv_stake_mark_validator_active(dap_chain_addr_t *a_signing_addr, bool a_on_off)
{
    dap_return_val_if_fail(a_signing_addr, -1);
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_signing_addr->net_id);
    dap_return_val_if_fail(l_srv_stake, -3);
    dap_chain_net_srv_stake_item_t *l_stake = NULL, *l_tmp;
    if (!dap_hash_fast_is_blank(&a_signing_addr->data.hash_fast)) {
        // Mark a single validator
        HASH_FIND(hh, l_srv_stake->itemlist, &a_signing_addr->data.hash_fast, sizeof(dap_hash_fast_t), l_stake);
        if (!l_stake) // public key isn't delegated for this network
            return -2;
        l_stake->is_active = a_on_off;
    } else // Mark all validators
        HASH_ITER(hh, l_srv_stake->itemlist, l_stake, l_tmp)
            l_stake->is_active = a_on_off;
    return 0;
}

int dap_chain_net_srv_stake_verify_key_and_node(dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_node_addr)
{
    dap_return_val_if_fail(a_signing_addr && a_node_addr, -100);
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_signing_addr->net_id);
    dap_return_val_if_fail(l_srv_stake, -104);

    if (dap_chain_addr_is_blank(a_signing_addr) || a_node_addr->uint64 == 0) {
        log_it(L_WARNING, "Trying to approve bad delegating TX. Node or key addr is blank");
        return -103;
    }

    dap_chain_net_srv_stake_item_t *l_stake = NULL, *l_tmp = NULL;
    HASH_ITER(hh, l_srv_stake->itemlist, l_stake, l_tmp){
        //check key not activated for other node
        if(dap_chain_addr_compare(a_signing_addr, &l_stake->signing_addr)){
            char l_key_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&a_signing_addr->data.hash_fast,
                                       l_key_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            debug_if(s_debug_more, L_WARNING, "Key %s already active for node "NODE_ADDR_FP_STR,
                                l_key_hash_str, NODE_ADDR_FP_ARGS_S(l_stake->node_addr));
            return -101;
        }

        //chek node have not other delegated key
        if(a_node_addr->uint64 == l_stake->node_addr.uint64){
            char l_key_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_stake->signing_addr.data.hash_fast,
                                       l_key_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            debug_if(s_debug_more, L_WARNING, "Node "NODE_ADDR_FP_STR" already have active key %s",
                                NODE_ADDR_FP_ARGS(a_node_addr), l_key_hash_str);
            return -102;
        }
    }

    return 0;
}

static bool s_stake_cache_check_tx(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash)
{
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_ledger->net->pub.id);
    dap_return_val_if_fail(l_srv_stake, false);
    dap_chain_net_srv_stake_cache_item_t *l_stake = NULL;
    HASH_FIND(hh, l_srv_stake->cache, a_tx_hash, sizeof(*a_tx_hash), l_stake);
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
    if (!dap_ledger_cache_enabled(l_ledger))
        return 0;

    char *l_gdb_group = dap_ledger_get_gdb_group(l_ledger, DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_GDB_GROUP);
    size_t l_objs_count = 0;
    
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group, &l_objs_count);

    if (!l_objs_count || !l_objs) {
        log_it(L_DEBUG, "Stake cache data not found");
        return -2;
    }
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_net->pub.id);
    dap_return_val_if_fail(l_srv_stake, -4);

    for (size_t i = 0; i < l_objs_count; i++){
        dap_chain_net_srv_stake_cache_data_t *l_cache_data =
                (dap_chain_net_srv_stake_cache_data_t *)l_objs[i].value;
        dap_chain_net_srv_stake_cache_item_t *l_cache = DAP_NEW_Z(dap_chain_net_srv_stake_cache_item_t);
        if (!l_cache) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return -3;
        }
        l_cache->signing_addr   = l_cache_data->signing_addr;
        l_cache->tx_hash        = l_cache_data->tx_hash;
        HASH_ADD(hh, l_srv_stake->cache, tx_hash, sizeof(dap_hash_fast_t), l_cache);
    }
    dap_global_db_objs_delete(l_objs, l_objs_count);
    dap_ledger_set_cache_tx_check_callback(l_ledger, s_stake_cache_check_tx);
    return 0;
}

void dap_chain_net_srv_stake_purge(dap_chain_net_t *a_net)
{
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    char *l_gdb_group = dap_ledger_get_gdb_group(l_ledger, DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_GDB_GROUP);
    dap_global_db_erase_table(l_gdb_group, NULL, NULL);
    DAP_DELETE(l_gdb_group);
    s_stake_net_clear(a_net);
}


// Freeze staker's funds when delegating a key
static dap_chain_datum_tx_t *s_stake_tx_create(dap_chain_net_t * a_net, dap_enc_key_t *a_key,
                                               uint256_t a_value, uint256_t a_fee,
                                               dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_node_addr,
                                               dap_chain_addr_t *a_sovereign_addr, uint256_t a_sovereign_tax,
                                               dap_chain_datum_tx_t *a_prev_tx)
{
    if (!a_net || !a_key || IS_ZERO_256(a_value) || !a_signing_addr || !a_node_addr)
        return NULL;

    const char *l_native_ticker = a_net->pub.native_ticker;
    char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, l_native_ticker);
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);
    uint256_t l_value_transfer = {}, l_fee_transfer = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, a_key, a_net->pub.id);
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t l_net_fee_addr;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_fee_addr);
    if (l_net_fee_used)
        SUM_256_256(l_fee_total, l_net_fee, &l_fee_total);

    dap_list_t *l_list_fee_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_native_ticker, &l_owner_addr, &l_list_fee_out, l_fee_total, &l_fee_transfer) == -101)
        l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                      &l_owner_addr, l_fee_total, &l_fee_transfer);
    if (!l_list_fee_out) {
        log_it(L_WARNING, "Nothing to pay for fee (not enough funds)");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    if (!a_prev_tx) {
        dap_list_t *l_list_used_out = NULL  ;
        if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_delegated_ticker, &l_owner_addr, &l_list_used_out, a_value, &l_value_transfer) == -101)
            l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_delegated_ticker,
                                                                           &l_owner_addr, a_value, &l_value_transfer);
        if (!l_list_used_out) {
            log_it(L_WARNING, "Nothing to pay for delegate (not enough funds)");
            goto tx_fail;
        }
        // add 'in' items to pay for delegate
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        dap_list_free_full(l_list_used_out, NULL);
        if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
            log_it(L_ERROR, "Can't compose the transaction input");
            goto tx_fail;
        }
    } else {
        dap_hash_fast_t l_prev_tx_hash;
        dap_hash_fast(a_prev_tx, dap_chain_datum_tx_get_size(a_prev_tx), &l_prev_tx_hash);
        int l_out_num = 0;
        dap_chain_datum_tx_out_cond_get(a_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_out_num);
        // add 'in' item to buy from conditional transaction
        if (1 != dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_prev_tx_hash, l_out_num, -1)) {
            log_it(L_ERROR, "Can't compose the transaction conditional input");
            goto tx_fail;
        }
    }
    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        log_it(L_ERROR, "Can't compose the fee transaction input");
        goto tx_fail;
    }

    // add 'out_cond' & 'out_ext' items
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
    dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_stake(l_uid, a_value, a_signing_addr, a_node_addr,
                                                                                          a_sovereign_addr, a_sovereign_tax);
    if (!l_tx_out) {
        log_it(L_ERROR, "Can't compose the transaction conditional output");
        goto tx_fail;
    }
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
    DAP_DELETE(l_tx_out);
    if (!a_prev_tx) {
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, a_value, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_value_back, l_delegated_ticker) != 1) {
                log_it(L_ERROR, "Cant add coin back output");
                goto tx_fail;
            }
        }
    }

    // add fee items
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            log_it(L_ERROR, "Cant add net fee output");
            goto tx_fail;
        }
    }
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            log_it(L_ERROR, "Cant add validator fee output");
            goto tx_fail;
        }
    }
    uint256_t l_fee_back = {};
    // fee coin back
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if (!IS_ZERO_256(l_fee_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_fee_back, l_native_ticker) != 1) {
            log_it(L_ERROR, "Cant add fee back output");
            goto tx_fail;
        }
    }

    // add 'sign' item
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_key) != 1) {
        log_it(L_ERROR, "Can't add sign output");
        goto tx_fail;
    }

    return l_tx;

tx_fail:
    dap_chain_datum_tx_delete(l_tx);
    return NULL;
}

// Updates staker's funds with delegated key
static dap_chain_datum_tx_t *s_stake_tx_update(dap_chain_net_t *a_net, dap_hash_fast_t *a_prev_tx_hash, uint256_t a_new_value, uint256_t a_fee, dap_enc_key_t *a_key)
{
    dap_return_val_if_fail(a_net && a_key && a_prev_tx_hash && !IS_ZERO_256(a_new_value), NULL);

    const char *l_native_ticker = a_net->pub.native_ticker;
    char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, l_native_ticker);
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);
    uint256_t l_value_transfer = {}, l_fee_transfer = {}; // how many coins to transfer
    // list of transaction with 'out' items to sell
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, a_key, a_net->pub.id);
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t l_net_fee_addr;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_fee_addr);
    if (l_net_fee_used)
        SUM_256_256(l_fee_total, l_net_fee, &l_fee_total);
    dap_list_t *l_list_fee_out = NULL; 
    if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_native_ticker, &l_owner_addr, &l_list_fee_out, l_fee_total, &l_fee_transfer) == -101)
        l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                      &l_owner_addr, l_fee_total, &l_fee_transfer);
    if (!l_list_fee_out) {
        log_it(L_WARNING, "Nothing to pay for fee (not enough funds)");
        return NULL;
    }
    dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(l_ledger, a_prev_tx_hash);
    if (!l_tx_prev) {
        log_it(L_ERROR, "Transaction %s not found", dap_hash_fast_to_str_static(a_prev_tx_hash));
        return NULL;
    }
    int l_out_num = 0;
    dap_chain_tx_out_cond_t *l_cond_prev = dap_chain_datum_tx_out_cond_get(l_tx_prev, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_out_num);
    if (!l_cond_prev) {
        log_it(L_ERROR, "Transaction %s is invalid", dap_hash_fast_to_str_static(a_prev_tx_hash));
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    // add 'in' item to buy from conditional transaction
    if (1 != dap_chain_datum_tx_add_in_cond_item(&l_tx, a_prev_tx_hash, l_out_num, -1)) {
        log_it(L_ERROR, "Can't compose the transaction conditional input");
        goto tx_fail;
    }

    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer)) {
        log_it(L_ERROR, "Can't compose the fee transaction input");
        goto tx_fail;
    }
    uint256_t l_value_prev = l_cond_prev->header.value, l_value_back = {};
    bool l_increasing = compare256(a_new_value, l_value_prev) == 1;
    if (l_increasing) {
        uint256_t l_refund_value = {};
        SUBTRACT_256_256(a_new_value, l_value_prev, &l_refund_value);
        dap_list_t *l_list_used_out = NULL;
        if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_delegated_ticker, &l_owner_addr, &l_list_used_out, l_refund_value, &l_value_transfer) == -101)
            l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_delegated_ticker,
                                                                           &l_owner_addr, l_refund_value, &l_value_transfer);
        if (!l_list_used_out) {
            log_it(L_WARNING, "Nothing to pay for delegate (not enough funds)");
            return NULL;
        }
        // add 'in' items to pay for delegate
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        dap_list_free_full(l_list_used_out, NULL);
        if (!EQUAL_256(l_value_to_items, l_value_transfer)) {
            log_it(L_ERROR, "Can't compose the transaction input");
            goto tx_fail;
        }
        SUBTRACT_256_256(l_value_transfer, l_refund_value, &l_value_back);
    } else
        SUBTRACT_256_256(l_value_prev, a_new_value, &l_value_back);

    // add 'out_cond' & 'out_ext' items
    dap_chain_tx_out_cond_t *l_out_cond = DAP_DUP_SIZE(l_cond_prev, sizeof(dap_chain_tx_out_cond_t) + l_cond_prev->tsd_size);
    if (!l_out_cond) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        goto tx_fail;
    }
    l_out_cond->header.value = a_new_value;
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out_cond);
    DAP_DELETE(l_out_cond);

    // coin back
    if (!IS_ZERO_256(l_value_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_value_back, l_delegated_ticker) != 1) {
            log_it(L_ERROR, "Cant add coin back output");
            goto tx_fail;
        }
    }

    // add fee items
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, l_native_ticker) != 1) {
            log_it(L_ERROR, "Cant add net fee output");
            goto tx_fail;
        }
    }
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            log_it(L_ERROR, "Cant add validator fee output");
            goto tx_fail;
        }
    }
    uint256_t l_fee_back = {};
    // fee coin back
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if (!IS_ZERO_256(l_fee_back)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_fee_back, l_native_ticker) != 1) {
            log_it(L_ERROR, "Cant add fee back output");
            goto tx_fail;
        }
    }

    // add 'sign' item
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_key) != 1) {
        log_it(L_ERROR, "Can't add sign output");
        goto tx_fail;
    }

    return l_tx;

tx_fail:
    dap_chain_datum_tx_delete(l_tx);
    return NULL;
}

static dap_chain_datum_tx_t *s_order_tx_create(dap_chain_net_t * a_net, dap_enc_key_t *a_key,
                                               uint256_t a_value, uint256_t a_fee,
                                                uint256_t a_sovereign_tax, dap_chain_addr_t *a_sovereign_addr)
{
    dap_chain_node_addr_t l_node_addr = {};
    return s_stake_tx_create(a_net, a_key, a_value, a_fee,
                             (dap_chain_addr_t *)&c_dap_chain_addr_blank, &l_node_addr,
                             a_sovereign_addr, a_sovereign_tax, NULL);
}

// Put the transaction to mempool
static char *s_stake_tx_put(dap_chain_datum_tx_t *a_tx, dap_chain_net_t *a_net, const char *a_hash_out_type)
{
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    if (!l_chain)
        return NULL;
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, a_tx, l_tx_size);
    if (!l_datum) {
        log_it(L_CRITICAL, "Not enough memory");
        return NULL;
    }
    // Processing will be made according to autoprocess policy
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, a_hash_out_type);
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
        log_it(L_WARNING, "Requested conditional transaction has no requires conditional output");
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
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HASH;
    l_tsd->size = sizeof(dap_hash_fast_t);
    *(dap_hash_fast_t*)(l_tsd->data) = *a_stake_tx_hash;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(uint256_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    if (!l_tsd) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
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
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
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
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_list_free_full(l_tsd_list, NULL);
        return NULL;
    }
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_NODE_ADDR;
    l_tsd->size = sizeof(dap_chain_node_addr_t);
    *(dap_chain_node_addr_t*)(l_tsd->data) = l_tx_out_cond->subtype.srv_stake_pos_delegate.signer_node_addr;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
    if (!l_decree) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
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
        dap_chain_datum_decree_t *l_new_decree
            = DAP_REALLOC_RET_VAL_IF_FAIL(l_decree, sizeof(dap_chain_datum_decree_t) + l_cur_sign_offset + l_sign_size, NULL, l_decree, l_sign);
        l_decree = l_new_decree;
        memcpy((byte_t*)l_decree->data_n_signs + l_cur_sign_offset, l_sign, l_sign_size);
        l_total_signs_size += l_sign_size;
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
        log_it(L_WARNING, "Requested conditional transaction requires conditional output");
        return NULL;
    }
    dap_hash_fast_t l_spender_hash = { };
    if (dap_ledger_tx_hash_is_used_out_item(l_ledger, a_tx_hash, l_prev_cond_idx, &l_spender_hash)) {
        char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str(&l_spender_hash, l_hash_str, sizeof(l_hash_str));
        log_it(L_WARNING, "Requested conditional transaction is already used out by %s", l_hash_str);
        return NULL;
    }
    dap_chain_tx_in_cond_t *l_in_cond = (dap_chain_tx_in_cond_t *)dap_chain_datum_tx_item_get(l_cond_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL);
    if (l_in_cond) {
        l_cond_tx = dap_ledger_tx_find_by_hash(l_ledger, &l_in_cond->header.tx_prev_hash);
        if (!l_cond_tx) {
            log_it(L_ERROR, "Requested conditional transaction is unchained");
            return NULL;
        }
    }
    // Get sign item
    dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get(l_cond_tx, NULL, NULL,
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
    dap_list_t *l_list_fee_out = NULL; 
    if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_native_ticker, &l_owner_addr, &l_list_fee_out, l_fee_total, &l_fee_transfer) == -101)
        l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
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
        log_it(L_WARNING, "Requested conditional transaction has no requires conditional output");
        return NULL;
    }

    // create invalidate decree
    size_t l_total_tsd_size = 0;
    dap_chain_datum_decree_t *l_decree = NULL;
    dap_list_t *l_tsd_list = NULL;
    dap_tsd_t *l_tsd = NULL;

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(dap_chain_addr_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, sizeof(dap_tsd_t) + sizeof(dap_chain_addr_t));
    if (!l_tsd) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR;
    l_tsd->size = sizeof(dap_chain_addr_t);
    *(dap_chain_addr_t*)(l_tsd->data) = l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(dap_chain_node_addr_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, sizeof(dap_tsd_t) + sizeof(dap_chain_node_addr_t));
    if (!l_tsd) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_NODE_ADDR;
    l_tsd->size = sizeof(dap_chain_node_addr_t);
    *(dap_chain_node_addr_t*)(l_tsd->data) = l_tx_out_cond->subtype.srv_stake_pos_delegate.signer_node_addr;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
    if (!l_decree) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
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
        dap_chain_datum_decree_t *l_new_decree
            = DAP_REALLOC_RET_VAL_IF_FAIL(l_decree, sizeof(dap_chain_datum_decree_t) + l_cur_sign_offset + l_sign_size, NULL, l_decree, l_sign);
        l_decree = l_new_decree;
        memcpy((byte_t*)l_decree->data_n_signs + l_cur_sign_offset, l_sign, l_sign_size);
        l_total_signs_size += l_sign_size;
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

static dap_chain_datum_decree_t *s_stake_decree_set_max_weight(dap_chain_net_t *a_net, dap_chain_t *a_chain,
                                                                uint256_t a_value, dap_cert_t *a_cert)
{
    size_t l_total_tsd_size = sizeof(dap_tsd_t) + sizeof(uint256_t);
    dap_chain_datum_decree_t *l_decree = dap_chain_datum_decree_new(a_net->pub.id, a_chain->id,
                                                                    *dap_chain_net_get_cur_cell(a_net), l_total_tsd_size);
    if (!l_decree)
        return NULL;
    l_decree->header.sub_type = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_MAX_WEIGHT;
    dap_tsd_write(l_decree->data_n_signs, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_VALUE, &a_value, sizeof(uint256_t));
    return dap_chain_datum_decree_sign_in_cycle(&a_cert, l_decree, 1, NULL);
}


static dap_chain_datum_decree_t *s_stake_decree_set_min_stake(dap_chain_net_t *a_net, dap_chain_t *a_chain,
                                                              uint256_t a_value, dap_cert_t *a_cert)
{
    size_t l_total_tsd_size = sizeof(dap_tsd_t) + sizeof(uint256_t);
    dap_chain_datum_decree_t *l_decree = dap_chain_datum_decree_new(a_net->pub.id, a_chain->id,
                                                                    *dap_chain_net_get_cur_cell(a_net), l_total_tsd_size);
    if (!l_decree)
        return NULL;
    l_decree->header.sub_type = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE;
    dap_tsd_write(l_decree->data_n_signs, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE, &a_value, sizeof(uint256_t));
    return dap_chain_datum_decree_sign_in_cycle(&a_cert, l_decree, 1, NULL);
}

char *s_fee_order_create(dap_chain_net_t *a_net, uint256_t *a_fee, dap_enc_key_t *a_key, const char *a_hash_out_type)
{
    dap_chain_hash_fast_t l_tx_hash = {};
    dap_chain_net_srv_order_direction_t l_dir = SERV_DIR_SELL;
    const char *l_native_ticker = a_net->pub.native_ticker;
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 =  SERV_UNIT_PCS};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
    char *l_order_hash_str = dap_chain_net_srv_order_create(a_net, l_dir, l_uid, g_node_addr,
                                                            l_tx_hash, a_fee, l_unit, l_native_ticker, 0,
                                                            NULL, 0, 1, NULL, 0, a_key);
    if (l_order_hash_str && !dap_strcmp(a_hash_out_type, "base58")) {
        char *l_base58_str = dap_enc_base58_from_hex_str_to_str(l_order_hash_str);
        DAP_DELETE(l_order_hash_str);
        l_order_hash_str = l_base58_str;
    }
    return l_order_hash_str;
}

struct validator_odrer_ext {
    uint256_t tax;
    uint256_t value_max;
} DAP_ALIGN_PACKED;

char *s_validator_order_create(dap_chain_net_t *a_net, uint256_t a_value_min, uint256_t a_value_max, uint256_t a_tax,
                               dap_enc_key_t *a_key, const char *a_hash_out_type, dap_chain_node_addr_t a_node_addr)
{
    dap_chain_hash_fast_t l_tx_hash = {};
    dap_chain_net_srv_order_direction_t l_dir = SERV_DIR_SELL;
    char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, a_net->pub.native_ticker);
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 =  SERV_UNIT_PCS};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ORDERS };
    struct validator_odrer_ext l_order_ext = { a_tax, a_value_max };
    dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_compose(a_net, l_dir, l_uid, a_node_addr,
                                                            l_tx_hash, &a_value_min, l_unit, l_delegated_ticker, 0,
                                                            (const uint8_t *)&l_order_ext, sizeof(l_order_ext),
                                                            1, NULL, 0, a_key);
    if (!l_order)
        return NULL;
    char *l_order_hash_str = dap_chain_net_srv_order_save(a_net, l_order, true);
    DAP_DELETE(l_order);
    if (l_order_hash_str && !dap_strcmp(a_hash_out_type, "base58")) {
        char *l_base58_str = dap_enc_base58_from_hex_str_to_str(l_order_hash_str);
        DAP_DELETE(l_order_hash_str);
        l_order_hash_str = l_base58_str;
    }
    return l_order_hash_str;
}

char *s_staker_order_create(dap_chain_net_t *a_net, uint256_t a_value, dap_hash_fast_t *a_tx_hash, dap_enc_key_t *a_key, const char *a_hash_out_type)
{
    dap_chain_net_srv_order_direction_t l_dir = SERV_DIR_BUY;
    char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, a_net->pub.native_ticker);
    dap_chain_net_srv_price_unit_uid_t l_unit = { .uint32 =  SERV_UNIT_PCS};
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ORDERS };
    dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_compose(a_net, l_dir, l_uid, g_node_addr,
                                                            *a_tx_hash, &a_value, l_unit, l_delegated_ticker, 0,
                                                            NULL, 0, 1, NULL, 0, a_key);
    if (!l_order)
        return NULL;
    char *l_order_hash_str = dap_chain_net_srv_order_save(a_net, l_order, true);
    DAP_DELETE(l_order);
    if (l_order_hash_str && !dap_strcmp(a_hash_out_type, "base58")) {
        char *l_base58_str = dap_enc_base58_from_hex_str_to_str(l_order_hash_str);
        DAP_DELETE(l_order_hash_str);
        l_order_hash_str = l_base58_str;
    }
    return l_order_hash_str;
}

static int time_compare_orders(const void *a, const void *b) {
    dap_global_db_obj_t *obj_a = (dap_global_db_obj_t*)a;
    dap_global_db_obj_t *obj_b = (dap_global_db_obj_t*)b;

    if (obj_a->timestamp < obj_b->timestamp) return -1;
    if (obj_a->timestamp > obj_b->timestamp) return 1;
    return 0;
}

int json_object_compare_by_timestamp(const void *a, const void *b) {
    struct json_object *obj_a = *(struct json_object **)a;
    struct json_object *obj_b = *(struct json_object **)b;

    struct json_object *timestamp_a = json_object_object_get(obj_a, "timestamp");
    struct json_object *timestamp_b = json_object_object_get(obj_b, "timestamp");

    int64_t time_a = json_object_get_int64(timestamp_a);
    int64_t time_b = json_object_get_int64(timestamp_b);

    return time_a - time_b;
}

typedef enum s_cli_srv_stake_order_err{
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_OK = 0,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_MEMORY_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_FORMAT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_CERT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_PKEY_IN_CERT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_CREATE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_CREATE_VAL_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_TAX_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_WALLET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_UNRECOGNIZED_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_CREATE_STAKER_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_ORDER_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_ORDER_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_REMOVE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_SUB_COM_ERR,


    /* add custom codes here */

    //DAP_CHAIN_NODE_CLI_COM_TX_UNKNOWN /* MAX */
} s_cli_srv_stake_order_err_t;
static int s_cli_srv_stake_order(int a_argc, char **a_argv, int a_arg_index, void **a_str_reply, const char *a_hash_out_type)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    enum {
        CMD_NONE, CMD_CREATE_FEE, CMD_CREATE_VALIDATOR, CMD_CREATE_STAKER, CMD_LIST,
        CMD_LIST_STAKER, CMD_LIST_VALIDATOR, CMD_LIST_FEE, CMD_REMOVE
    };
    int l_cmd_num = CMD_NONE;
    const char *l_create_type = NULL;
    if (dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, dap_min(a_argc, a_arg_index + 1), "create", &l_create_type)) {
        if (!dap_strcmp(l_create_type, "validator"))
            l_cmd_num = CMD_CREATE_VALIDATOR;
        else if (!dap_strcmp(l_create_type, "staker"))
            l_cmd_num = CMD_CREATE_STAKER;
        else
            l_cmd_num = CMD_CREATE_FEE;
    }
    else if (dap_cli_server_cmd_check_option(a_argv, a_arg_index, dap_min(a_argc, a_arg_index + 1), "list") >= 0)
        l_cmd_num = CMD_LIST;
    else if (dap_cli_server_cmd_check_option(a_argv, a_arg_index, dap_min(a_argc, a_arg_index + 1), "remove") >= 0)
        l_cmd_num = CMD_REMOVE;

    int l_arg_index = a_arg_index + 1;
    const char *l_net_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
    if (!l_net_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Command 'order' requires parameter -net");
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
    }
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
    if (!l_net) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NET_ERR, "Network %s not found", l_net_str);
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NET_ERR;
    }

    switch (l_cmd_num) {
    case CMD_CREATE_FEE: {
        const char *l_value_str = NULL,
                   *l_cert_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
        if (!l_value_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Fee order creation requires parameter -value");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        uint256_t l_value = dap_chain_balance_scan(l_value_str);
        if (IS_ZERO_256(l_value)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_FORMAT_ERR, "Format -value <256 bit integer>");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_FORMAT_ERR;
        }
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
        if (!l_cert_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Fee order creation requires parameter -cert");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
        if (!l_cert) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_CERT_ERR, "Can't load cert %s", l_cert_str);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_CERT_ERR;
        }
        if (!l_cert->enc_key || !l_cert->enc_key->priv_key_data || !l_cert->enc_key->priv_key_data_size) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_PKEY_IN_CERT_ERR, "Certificate \"%s\" has no private key", l_cert_str);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_PKEY_IN_CERT_ERR;
        }
        // Create the order & put it in GDB
        char *l_order_hash_str = s_fee_order_create(l_net, &l_value, l_cert->enc_key, a_hash_out_type);
        if (l_order_hash_str) {
            json_object * l_json_obj_create = json_object_new_object();
            json_object_object_add(l_json_obj_create, "status", json_object_new_string("success"));
            json_object_object_add(l_json_obj_create, "order_hash", json_object_new_string(l_order_hash_str));
            json_object_array_add(*a_json_arr_reply, l_json_obj_create);
            DAP_DELETE(l_order_hash_str);
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_CREATE_ERR, "Can't compose the order");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_CREATE_ERR;
        }
    } break;

    case CMD_CREATE_VALIDATOR: {
        const char *l_value_min_str = NULL,
                   *l_value_max_str = NULL,
                   *l_tax_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value_min", &l_value_min_str);
        if (!l_value_min_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Validator order creation requires parameter -value_min");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        uint256_t l_value_min = dap_chain_balance_scan(l_value_min_str);
        if (IS_ZERO_256(l_value_min)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_FORMAT_ERR, "Format -value_min <256 bit integer>");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_FORMAT_ERR;
        }
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value_max", &l_value_max_str);
        if (!l_value_max_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Validator order creation requires parameter -value_max");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        uint256_t l_value_max = dap_chain_balance_scan(l_value_max_str);
        if (IS_ZERO_256(l_value_max)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_FORMAT_ERR, "Format -value_max <256 bit integer>");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_FORMAT_ERR;
        }
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tax", &l_tax_str);
        if (!l_tax_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Validator order creation requires parameter -tax");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        uint256_t l_tax = dap_chain_coins_to_balance(l_tax_str);
        if (compare256(l_tax, dap_chain_coins_to_balance("100.0")) == 1 ||
                compare256(l_tax, GET_256_FROM_64(100)) == -1) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_TAX_ERR, "Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_TAX_ERR;
        }
        const char *l_cert_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
        if (!l_cert_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Validator order creation requires parameter -cert");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
        if (!l_cert) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_CERT_ERR, "Can't load cert %s", l_cert_str);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_CERT_ERR;
        }
        if (!l_cert->enc_key || !l_cert->enc_key->priv_key_data || !l_cert->enc_key->priv_key_data_size) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_PKEY_IN_CERT_ERR, "Certificate \"%s\" has no private key", l_cert_str);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_PKEY_IN_CERT_ERR;
        }
        dap_chain_addr_t l_signing_addr;
        dap_chain_addr_fill_from_key(&l_signing_addr, l_cert->enc_key, l_net->pub.id);
        dap_chain_node_addr_t l_node_addr = g_node_addr;
        const char *l_node_addr_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-node_addr", &l_node_addr_str);
        if (l_node_addr_str) {
            if (dap_chain_node_addr_from_str(&l_node_addr, l_node_addr_str)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_UNRECOGNIZED_ADDR_ERR, "Unrecognized node addr %s", l_node_addr_str);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_UNRECOGNIZED_ADDR_ERR;
            }
        }
        int l_result = dap_chain_net_srv_stake_verify_key_and_node(&l_signing_addr, &l_node_addr);
        if (l_result) {
            dap_json_rpc_error_add(*a_json_arr_reply, l_result, "Key and node verification error");
            return l_result;
        }
        // Create the order & put it in GDB
        char *l_order_hash_str = s_validator_order_create(l_net, l_value_min, l_value_max, l_tax, l_cert->enc_key, a_hash_out_type, l_node_addr);
        if (l_order_hash_str) {
            json_object * l_json_obj_create_val = json_object_new_object();
            json_object_object_add(l_json_obj_create_val, "status", json_object_new_string("success"));
            json_object_object_add(l_json_obj_create_val, "order_hash", json_object_new_string(l_order_hash_str));
            json_object_array_add(*a_json_arr_reply, l_json_obj_create_val);
            DAP_DELETE(l_order_hash_str);
        } else {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_CREATE_VAL_ERR, "Can't compose the order");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_CREATE_VAL_ERR;
        }
    } break;

    case CMD_CREATE_STAKER: {
        const char *l_value_str = NULL,
                   *l_wallet_str = NULL,
                   *l_tax_str = NULL,
                   *l_addr_str = NULL,
                   *l_fee_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
        if (!l_value_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Staker order creation requires parameter -value");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        uint256_t l_value = dap_chain_balance_scan(l_value_str);
        if (IS_ZERO_256(l_value)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Format -value <256 bit integer>");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
        if (!l_fee_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Staker order creation requires parameter -fee");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
        if (IS_ZERO_256(l_fee)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_FORMAT_ERR, "Format -fee <256 bit integer>");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_FORMAT_ERR;
        }
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tax", &l_tax_str);
        if (!l_tax_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Staker order creation requires parameter -tax");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        uint256_t l_tax = dap_chain_coins_to_balance(l_tax_str);
        if (compare256(l_tax, dap_chain_coins_to_balance("100.0")) == 1 ||
                compare256(l_tax, GET_256_FROM_64(100)) == -1) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_TAX_ERR, "Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_TAX_ERR;
        }
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_str);
        if (!l_wallet_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Staker order creation requires parameter -w");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config),NULL);
        if (!l_wallet) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_WALLET_ERR, "Specified wallet not found");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_WALLET_ERR;
        }
        // Create conditional transaction for order
        const char *l_sign_str = dap_chain_wallet_check_sign(l_wallet);
        dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
        dap_chain_wallet_close(l_wallet);
        dap_chain_addr_t l_addr = {};
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-addr", &l_addr_str);
        if (l_addr_str) {
            dap_chain_addr_t *l_spec_addr = dap_chain_addr_from_str(l_addr_str);
            if (!l_spec_addr) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_ADDR_ERR, "Specified address is ivalid");
                DAP_DELETE(l_enc_key);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_ADDR_ERR;
            }
            l_addr = *l_spec_addr;
            DAP_DELETE(l_spec_addr);
        } else
            dap_chain_addr_fill_from_key(&l_addr, l_enc_key, l_net->pub.id);
        DIV_256(l_tax, GET_256_FROM_64(100), &l_tax);
        dap_chain_datum_tx_t *l_tx = s_order_tx_create(l_net, l_enc_key, l_value, l_fee, l_tax, &l_addr);
        DAP_DEL_Z(l_enc_key);
        char *l_tx_hash_str = NULL;
        if (!l_tx || !(l_tx_hash_str = s_stake_tx_put(l_tx, l_net, a_hash_out_type))) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_CREATE_STAKER_ERR, "Can't compose transaction for order, examine log files for details");
            DAP_DEL_Z(l_tx);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_CREATE_STAKER_ERR;
        }
        DAP_DELETE(l_tx);
        // Create the order & put it in GDB
        dap_hash_fast_t l_tx_hash = {};
        dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash);
        char *l_cert_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", (const char **)&l_cert_str);
        if (!l_cert_str)
            l_cert_str = "node-addr";
        dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
        if (!l_cert) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_CERT_ERR, "Can't load cert %s", l_cert_str);
            DAP_DELETE(l_tx_hash_str);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_CERT_ERR;
        }
        if (!l_cert->enc_key || !l_cert->enc_key->priv_key_data || !l_cert->enc_key->priv_key_data_size) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_PKEY_IN_CERT_ERR, "Certificate \"%s\" has no private key", l_cert_str);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_PKEY_IN_CERT_ERR;
        }
        char *l_order_hash_str = s_staker_order_create(l_net, l_value, &l_tx_hash, l_cert->enc_key, a_hash_out_type);
        if (!l_order_hash_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_CREATE_STAKER_ERR, "Can't compose the order");
            DAP_DELETE(l_tx_hash_str);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_CREATE_STAKER_ERR;
        }
        json_object * l_json_obj_create_val = json_object_new_object();
        json_object_object_add(l_json_obj_create_val, "status", json_object_new_string("success"));
        if (dap_strcmp(l_sign_str, ""))
            json_object_object_add(l_json_obj_create_val, "sign", json_object_new_string(l_sign_str));
        json_object_object_add(l_json_obj_create_val, "order_hash", json_object_new_string(l_order_hash_str));
        json_object_object_add(l_json_obj_create_val, "tx_hash", json_object_new_string(l_tx_hash_str));
        json_object_array_add(*a_json_arr_reply, l_json_obj_create_val);
        DAP_DELETE(l_order_hash_str);
        DAP_DELETE(l_tx_hash_str);
    } break;

    case CMD_REMOVE: {
        const char *l_order_hash_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
        if (!l_order_hash_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Command 'srv_stake order remove' requires prameter -order\n");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        char *l_order_hash_hex_str;
        // datum hash may be in hex or base58 format
        if(!dap_strncmp(l_order_hash_str, "0x", 2) || !dap_strncmp(l_order_hash_str, "0X", 2))
            l_order_hash_hex_str = dap_strdup(l_order_hash_str);
        else
            l_order_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_order_hash_str);
        dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_hex_str);
        if (!l_order) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_ORDER_ERR, "Can't find order %s\n", l_order_hash_str);
            DAP_DELETE(l_order_hash_hex_str);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_ORDER_ERR;
        }
        if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID &&
                l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ORDERS) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_ORDER_ERR, "Order %s is not a delegated stake order\n", l_order_hash_str);
            DAP_DELETE(l_order_hash_hex_str);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_ORDER_ERR;
        }
        if (dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_hex_str)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_REMOVE_ERR, "Can't remove order %s\n", l_order_hash_str);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_REMOVE_ERR;
        }
        json_object * l_json_obj_create_val = json_object_new_object();
        json_object_object_add(l_json_obj_create_val, "status", json_object_new_string("success"));
        json_object_array_add(*a_json_arr_reply, l_json_obj_create_val);
        DAP_DELETE(l_order_hash_hex_str);
    } break;

    case CMD_LIST: {
        const char *l_net_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
        if (!l_net_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR, "Command 'order list' requires parameter -net");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_PARAM_ERR;
        }
        const char * l_list_type = NULL;
        int l_list_filter = 0;
        if (dap_cli_server_cmd_check_option(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "staker") >= 0)
            l_list_filter = CMD_LIST_STAKER;
        else if (dap_cli_server_cmd_check_option(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "validator") >= 0)
            l_list_filter = CMD_LIST_VALIDATOR;
        else if (dap_cli_server_cmd_check_option(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "fee") >= 0)
            l_list_filter = CMD_LIST_FEE;

        dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
        if (!l_net) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NET_ERR, "Network %s not found", l_net_str);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NET_ERR;
        }
        json_object* l_json_arr_reply = json_object_new_array();
        for (int i = 0; i < 2; i++) {
            char *l_gdb_group_str = i ? dap_chain_net_srv_order_get_gdb_group(l_net) :
                                        dap_chain_net_srv_order_get_common_group(l_net);
            size_t l_orders_count = 0;
            dap_global_db_obj_t * l_orders = dap_global_db_get_all_sync(l_gdb_group_str, &l_orders_count);
            qsort(l_orders, l_orders_count, sizeof(dap_global_db_obj_t), time_compare_orders);
            for (size_t i = 0; i < l_orders_count; i++) {
                const dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_check(l_orders[i].key, l_orders[i].value, l_orders[i].value_len);
                if (!l_order) {
                    log_it(L_WARNING, "Unreadable order %s", l_orders[i].key);
                    continue;
                }
                if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID &&
                        l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ORDERS)
                    continue;

                switch (l_list_filter) {
                    case CMD_LIST_STAKER:
                        if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ORDERS || l_order->direction != SERV_DIR_BUY )
                            continue;
                        break;
                    case CMD_LIST_VALIDATOR:
                        if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ORDERS || l_order->direction != SERV_DIR_SELL)
                            continue;
                        break;
                    case CMD_LIST_FEE:
                        if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID)
                            continue;
                        break;
                    default:
                        break;
                }
                // TODO add filters to list (token, address, etc.)
                json_object* l_json_obj_order = json_object_new_object();
                dap_chain_net_srv_order_dump_to_json(l_order, l_json_obj_order, a_hash_out_type, l_net->pub.native_ticker);
                if (l_order->srv_uid.uint64 == DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ORDERS) {
                    if (l_order->direction == SERV_DIR_SELL) {
                        json_object_object_add(l_json_obj_order, "message", 
                          json_object_new_string("Value in this order type means minimum value of m-tokens for validator acceptable for key delegation with supplied tax"));
                        struct validator_odrer_ext *l_ext = (struct validator_odrer_ext *)l_order->ext_n_sign;
                        json_object* l_json_obj_ext_params = json_object_new_object();
                        const char *l_coins_str;
                        dap_uint256_to_char(l_ext->tax, &l_coins_str);
                        json_object_object_add(l_json_obj_ext_params, "tax", json_object_new_string(l_coins_str));
                        dap_uint256_to_char(l_ext->value_max, &l_coins_str);
                        json_object_object_add(l_json_obj_ext_params, "maximum_value", json_object_new_string(l_coins_str));
                        json_object_object_add(l_json_obj_order, "external_params", l_json_obj_ext_params);
                    } else { // l_order->direction = SERV_DIR_BUY
                        json_object_object_add(l_json_obj_order, "message", 
                          json_object_new_string("Value in this order type means value of m-tokens locked in conditional transaction attached to the order"));
                        bool l_error = true;
                        dap_chain_addr_t l_addr = {};
                        uint256_t l_tax = uint256_0;
                        dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_order->tx_cond_hash);
                        if (l_tx) {
                            dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, NULL);
                            if (l_cond && l_cond->tsd_size == dap_chain_datum_tx_item_out_cond_create_srv_stake_get_tsd_size()) {
                                dap_tsd_t *l_tsd = dap_tsd_find(l_cond->tsd, l_cond->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_ADDR);
                                l_addr = dap_tsd_get_scalar(l_tsd, dap_chain_addr_t);
                                l_tsd = dap_tsd_find(l_cond->tsd, l_cond->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_VALUE);
                                l_tax = dap_tsd_get_scalar(l_tsd, uint256_t);
                                MULT_256_256(l_tax, GET_256_FROM_64(100), &l_tax);
                                l_error = false;
                            }
                        }                   
                        if (!l_error) {
                            const char *l_tax_str; dap_uint256_to_char(l_tax, &l_tax_str);
                            json_object* l_json_obj_cond_tx_params = json_object_new_object();
                            json_object_object_add(l_json_obj_cond_tx_params, "sovereign_tax", json_object_new_string(l_tax_str));
                            json_object_object_add(l_json_obj_cond_tx_params, "sovereign_addr", json_object_new_string(dap_chain_addr_to_str_static(&l_addr)));
                            json_object_object_add(l_json_obj_order, "conditional_tx_params", l_json_obj_cond_tx_params);
                        } else
                            json_object_object_add(l_json_obj_order, "conditional_tx_params", json_object_new_string("Conditional tx not found or illegal"));
                    }
                } else
                        json_object_object_add(l_json_obj_order, "message", 
                          json_object_new_string("Value in this order type means minimum fee for validator acceptable for process transactions"));
                json_object_array_add(l_json_arr_reply, l_json_obj_order);
            }
            dap_global_db_objs_delete(l_orders, l_orders_count);
            DAP_DELETE(l_gdb_group_str);
        }
        size_t json_array_lenght = json_object_array_length(l_json_arr_reply);
        if (!json_array_lenght)
            json_object_array_add(l_json_arr_reply, json_object_new_string( "No orders found"));
        else {
            //sort by time
            json_object_array_sort(l_json_arr_reply, json_object_compare_by_timestamp);
            // Remove the timestamp
            for (size_t i = 0; i < json_array_lenght; i++) {
                struct json_object *obj = json_object_array_get_idx(l_json_arr_reply, i);
                json_object_object_del(obj, "timestamp");
            }
        }
        json_object_array_add(*a_json_arr_reply, l_json_arr_reply);
    } break;

    default:
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_SUB_COM_ERR, "Subcommand %s not recognized", a_argv[a_arg_index]);
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_ORDER_NO_SUB_COM_ERR;
    }
    return 0;
}

typedef enum s_cli_srv_stake_delegate_err{
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_OK = 0,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_MEMORY_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_FORMAT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_NET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_WALLET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_NO_CERT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_WRONG_CERT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_WRONG_SIGN_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_INVALID_PKEY_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_UNRECOGNIZED_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_NO_ORDER_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_INVALID_ORDER_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_ORDER_SIZE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_NO_TX_IN_LEDGER_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_INVALID_COND_TX_TYPE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_INVALID_COND_TX_FORMAT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_COND_TX_DIF_VALUE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_COND_TX_NO_ADDR_OR_KEY_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_TX_ALREADY_SENT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_ANOTHER_TICKER_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_ADDR_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_LOW_VALUE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_HIGH_VALUE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_UNSIGNED_ORDER_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_TAX_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_VERIFICATION_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_STAKE_ERR,

    /* add custom codes here */

    //DAP_CHAIN_NODE_CLI_COM_TX_UNKNOWN /* MAX */
} s_cli_srv_stake_delegate_err_t;
static int s_cli_srv_stake_delegate(int a_argc, char **a_argv, int a_arg_index, void **a_str_reply, const char *a_hash_out_type)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    const char *l_net_str = NULL,
               *l_wallet_str = NULL,
               *l_cert_str = NULL,
               *l_pkey_str = NULL,
               *l_sign_type_str = NULL,
               *l_value_str = NULL,
               *l_fee_str = NULL,
               *l_node_addr_str = NULL,
               *l_order_hash_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-net", &l_net_str);
    if (!l_net_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR, "Command 'delegate' requires parameter -net");
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR;
    }
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
    if (!l_net) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_NET_ERR, "Network %s not found", l_net_str);
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_NET_ERR;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR, "Command 'delegate' requires parameter -w");
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR;
    }
    const char* l_sign_str = "";
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
    if (!l_wallet) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_WALLET_ERR, "Specified wallet not found");
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_WALLET_ERR;
    } else
        l_sign_str = dap_chain_wallet_check_sign(l_wallet);
    dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_wallet_close(l_wallet);
    dap_chain_addr_t l_signing_addr, l_sovereign_addr = {};
    uint256_t l_sovereign_tax = uint256_0;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-cert", &l_cert_str);
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-pkey", &l_pkey_str);
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-sign_type", &l_sign_type_str);
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-order", &l_order_hash_str);
    if (!l_cert_str && !l_order_hash_str && !l_pkey_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR, "Command 'delegate' requires parameter -cert and/or -order and/or -pkey");
        dap_enc_key_delete(l_enc_key);
        return -13;
    }
    if (l_pkey_str && !l_sign_type_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR, "Command 'delegate' requires parameter -sign_type for pkey");
        dap_enc_key_delete(l_enc_key);
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR;
    }
    uint256_t l_value = uint256_0;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-value", &l_value_str);
    if (!l_value_str) {
        if (!l_order_hash_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR, "Command 'delegate' requires parameter -value");
            dap_enc_key_delete(l_enc_key);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR;
        }
    } else {
        l_value = dap_chain_balance_scan(l_value_str);
        if (IS_ZERO_256(l_value)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR, "Unrecognized number in '-value' param");
            dap_enc_key_delete(l_enc_key);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR;
        }
    }
    dap_chain_datum_tx_t *l_prev_tx = NULL;
    if (l_cert_str) {
        dap_cert_t *l_signing_cert = dap_cert_find_by_name(l_cert_str);
        if (!l_signing_cert) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_NO_CERT_ERR, "Specified certificate not found");
            dap_enc_key_delete(l_enc_key);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_NO_CERT_ERR;
        }
        if (dap_chain_addr_fill_from_key(&l_signing_addr, l_signing_cert->enc_key, l_net->pub.id)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_WRONG_CERT_ERR, "Specified certificate is wrong");
            dap_enc_key_delete(l_enc_key);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_WRONG_CERT_ERR;
        }
        dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-node_addr", &l_node_addr_str);
    } else if (l_pkey_str) {
        dap_chain_hash_fast_t l_hash_public_key = {0};
        dap_sign_type_t l_type = dap_sign_type_from_str(l_sign_type_str);
        if (l_type.type == SIG_TYPE_NULL) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_WRONG_SIGN_ERR, "Wrong sign type");
            dap_enc_key_delete(l_enc_key);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_WRONG_SIGN_ERR;
        }
        if (dap_chain_hash_fast_from_str(l_pkey_str, &l_hash_public_key)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_INVALID_PKEY_ERR, "Invalid pkey hash format");
            dap_enc_key_delete(l_enc_key);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_INVALID_PKEY_ERR;
        }
        dap_chain_addr_fill(&l_signing_addr, l_type, &l_hash_public_key, l_net->pub.id);
        dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-node_addr", &l_node_addr_str);
    }
    dap_chain_node_addr_t l_node_addr = g_node_addr;
    if (l_node_addr_str) {
        if (dap_chain_node_addr_from_str(&l_node_addr, l_node_addr_str)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_UNRECOGNIZED_ADDR_ERR, "Unrecognized node addr %s", l_node_addr_str);
            dap_enc_key_delete(l_enc_key);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_UNRECOGNIZED_ADDR_ERR;
        }
    }
    if (l_order_hash_str) {
        dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_str);
        if (!l_order) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_NO_ORDER_ERR, "Specified order not found");
            dap_enc_key_delete(l_enc_key);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_NO_ORDER_ERR;
        }
        if (l_order->direction == SERV_DIR_BUY) { // Staker order
            if (!l_cert_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR, "Command 'delegate' requires parameter -cert with this order type");
                dap_enc_key_delete(l_enc_key);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR;
            }
            if (l_order->ext_size != 0) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_ORDER_SIZE_ERR, "Specified order has invalid size");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_ORDER_SIZE_ERR;
            }
            l_prev_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_order->tx_cond_hash);
            if (!l_prev_tx) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_NO_TX_IN_LEDGER_ERR, "The order's conditional transaction not found in ledger");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_NO_TX_IN_LEDGER_ERR;
            }
            int l_out_num = 0;
            dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_out_num);
            if (!l_cond) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_INVALID_COND_TX_TYPE_ERR, "The order's conditional transaction has invalid type");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_INVALID_COND_TX_TYPE_ERR;
            }
            if (dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &l_order->tx_cond_hash, l_out_num, NULL)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_TX_ALREADY_SENT_ERR, "The order's conditional transaction is already spent");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_TX_ALREADY_SENT_ERR;
            }
            char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, l_net->pub.native_ticker);
            const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &l_order->tx_cond_hash);
            if (dap_strcmp(l_tx_ticker, l_delegated_ticker)) {
                log_it(L_WARNING, "Requested conditional transaction have another ticker (not %s)", l_delegated_ticker);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_ANOTHER_TICKER_ERR;
            }
            if (l_cond->tsd_size != dap_chain_datum_tx_item_out_cond_create_srv_stake_get_tsd_size()) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_INVALID_COND_TX_FORMAT_ERR, "The order's conditional transaction has invalid format");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_INVALID_COND_TX_FORMAT_ERR;
            }
            if (compare256(l_cond->header.value, l_order->price)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_COND_TX_DIF_VALUE_ERR, "The order's conditional transaction has different value");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_COND_TX_DIF_VALUE_ERR;
            }
            if (!dap_chain_addr_is_blank(&l_cond->subtype.srv_stake_pos_delegate.signing_addr) ||
                    l_cond->subtype.srv_stake_pos_delegate.signer_node_addr.uint64) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_COND_TX_NO_ADDR_OR_KEY_ERR, "The order's conditional transaction gas not blank address or key");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_COND_TX_NO_ADDR_OR_KEY_ERR;
            }
            l_value = l_order->price;
            dap_tsd_t *l_tsd = dap_tsd_find(l_cond->tsd, l_cond->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_ADDR);
            l_sovereign_addr = dap_tsd_get_scalar(l_tsd, dap_chain_addr_t);
            l_tsd = dap_tsd_find(l_cond->tsd, l_cond->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_VALUE);
            l_sovereign_tax = dap_tsd_get_scalar(l_tsd, uint256_t);
            MULT_256_256(l_sovereign_tax, GET_256_FROM_64(100), &l_sovereign_tax);
#if EXTENDED_SRV_DEBUG
            {
                char *l_tax_str = dap_chain_balance_to_coins(l_sovereign_tax);
                char *l_addr_str = dap_chain_addr_to_str_static(&l_sovereign_addr);
                log_it(L_NOTICE, "Delegation tx params: tax = %s%%, addr = %s", l_tax_str, l_addr_str);
                DAP_DEL_Z(l_tax_str);
                DAP_DEL_Z(l_addr_str);
            }
#endif
        } else {
            if (!l_value_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR, "Command 'delegate' requires parameter -value with this order type");
                dap_enc_key_delete(l_enc_key);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR;
            }
            const char *l_sovereign_addr_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-tax_addr", &l_sovereign_addr_str);
            if (l_sovereign_addr_str) {
                dap_chain_addr_t *l_spec_addr = dap_chain_addr_from_str(l_sovereign_addr_str);
                if (!l_spec_addr) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_ADDR_ERR, "Specified address is ivalid");
                    return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_ADDR_ERR;
                }
                l_sovereign_addr = *l_spec_addr;
                DAP_DELETE(l_spec_addr);
            } else
                dap_chain_addr_fill_from_key(&l_sovereign_addr, l_enc_key, l_net->pub.id);

            if (l_order->ext_size != sizeof(struct validator_odrer_ext)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_ORDER_SIZE_ERR, "Specified order has invalid size");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_ORDER_SIZE_ERR;
            }
            struct validator_odrer_ext *l_ext = (struct validator_odrer_ext *)l_order->ext_n_sign;
            l_sovereign_tax = l_ext->tax;
            if (l_order_hash_str && compare256(l_value, l_order->price) == -1) {
                const char *l_coin_min_str, *l_value_min_str =
                    dap_uint256_to_char(l_order->price, &l_coin_min_str);
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_LOW_VALUE_ERR, "Number in '-value' param %s is lower than order minimum allowed value %s(%s)",
                                                  l_value_str, l_coin_min_str, l_value_min_str);
                dap_enc_key_delete(l_enc_key);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_LOW_VALUE_ERR;
            }
            if (l_order_hash_str && compare256(l_value, l_ext->value_max) == 1) {
                const char *l_coin_max_str, *l_value_max_str =
                    dap_uint256_to_char(l_ext->value_max, &l_coin_max_str);
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_HIGH_VALUE_ERR, "Number in '-value' param %s is higher than order minimum allowed value %s(%s)",
                                                  l_value_str, l_coin_max_str, l_value_max_str);
                dap_enc_key_delete(l_enc_key);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_HIGH_VALUE_ERR;
            }
            dap_sign_t *l_sign = (dap_sign_t *)(l_order->ext_n_sign + l_order->ext_size);
            if (l_sign->header.type.type == SIG_TYPE_NULL) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_UNSIGNED_ORDER_ERR, "Specified order is unsigned");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_UNSIGNED_ORDER_ERR;
            }
            dap_chain_addr_fill_from_sign(&l_signing_addr, l_sign, l_net->pub.id);
            char l_delegated_ticker_str[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker_str, l_net->pub.native_ticker);
            if (dap_strcmp(l_order->price_ticker, l_delegated_ticker_str)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_INVALID_ORDER_ERR, "Specified order is invalid");
                dap_enc_key_delete(l_enc_key);
                DAP_DELETE(l_order);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_INVALID_ORDER_ERR;
            }
            l_node_addr = l_order->node_addr;
        }
        DAP_DELETE(l_order);
        if (compare256(l_sovereign_tax, dap_chain_coins_to_balance("100.0")) == 1 ||
                compare256(l_sovereign_tax, GET_256_FROM_64(100)) == -1) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_TAX_ERR, "Tax must be lower or equal than 100%% and higher or equal than 1.0e-16%%");
            dap_enc_key_delete(l_enc_key);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_TAX_ERR;
        }
        DIV_256(l_sovereign_tax, GET_256_FROM_64(100), &l_sovereign_tax);
    }

    int l_check_result = dap_chain_net_srv_stake_verify_key_and_node(&l_signing_addr, &l_node_addr);
    if (l_check_result) {
        dap_json_rpc_error_add(*a_json_arr_reply, l_check_result, "Key and node verification error");
        dap_enc_key_delete(l_enc_key);
        return l_check_result;
    }
    uint256_t l_allowed_min = dap_chain_net_srv_stake_get_allowed_min_value(l_net->pub.id);
    if (compare256(l_value, l_allowed_min) == -1) {
        const char *l_coin_min_str, *l_value_min_str = dap_uint256_to_char(l_allowed_min, &l_coin_min_str);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_LOW_VALUE_ERR, "Number in '-value' param %s is lower than minimum allowed value %s(%s)",
                                          l_value_str, l_coin_min_str, l_value_min_str);
        dap_enc_key_delete(l_enc_key);
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_LOW_VALUE_ERR;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR, "Command 'delegate' requires parameter -fee");
        dap_enc_key_delete(l_enc_key);
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR;
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR, "Unrecognized number in '-fee' param");
        dap_enc_key_delete(l_enc_key);
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_PARAM_ERR;
    }

    // Create conditional transaction
    dap_chain_datum_tx_t *l_tx = s_stake_tx_create(l_net, l_enc_key, l_value, l_fee, &l_signing_addr, &l_node_addr,
                                                   l_order_hash_str ? &l_sovereign_addr : NULL, l_sovereign_tax, l_prev_tx);
    dap_enc_key_delete(l_enc_key);
    char *l_tx_hash_str;
    if (!l_tx || !(l_tx_hash_str = s_stake_tx_put(l_tx, l_net, a_hash_out_type))) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_STAKE_ERR, "Stake transaction error");
        DAP_DEL_Z(l_tx);
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_DELEGATE_STAKE_ERR;
    }
    DAP_DELETE(l_tx);
    json_object* l_json_obj_deligate = json_object_new_object();
    json_object_object_add(l_json_obj_deligate, "status", json_object_new_string("success"));
    if (dap_strcmp(l_sign_str, ""))
        json_object_object_add(l_json_obj_deligate, "sign", json_object_new_string(l_sign_str));  // deprecated signs error
    json_object_object_add(l_json_obj_deligate, "tx_hash", json_object_new_string(l_tx_hash_str));
    json_object_array_add(*a_json_arr_reply, l_json_obj_deligate);
    DAP_DELETE(l_tx_hash_str);
    return 0;
}


typedef enum s_cli_srv_stake_update_err{
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_OK = 0,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_MEMORY_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_PARAM_FORMAT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_NET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_FEE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_NO_CERT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_WRONG_CERT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_PKEY_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_NO_STAKE_IN_NET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_NOT_DELGATED_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_NO_TX_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_INVALID_TX_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_TX_SPENT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_NO_WALLET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_CANT_COMPOSE_ERR,
} s_cli_srv_stake_update_err_t;
static int s_cli_srv_stake_update(int a_argc, char **a_argv, int a_arg_index, void **a_str_reply, const char *a_hash_out_type)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    const char *l_net_str = NULL,
               *l_wallet_str = NULL,
               *l_value_str,
               *l_fee_str = NULL,
               *l_tx_hash_str = NULL,
               *l_cert_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-net", &l_net_str);
    if (!l_net_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_PARAM_ERR, "Command 'update' requires parameter -net");
        return -3;
    }
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
    if (!l_net) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_NET_ERR, "Network %s not found", l_net_str);
        return -4;
    }
    uint256_t l_fee = {};
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_PARAM_ERR, "Command 'update' requires parameter -w");
        return -17;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_PARAM_ERR, "Command 'update' requires parameter -fee");
        return -5;
    }
    l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_FEE_ERR, "Unrecognized number in '-fee' param");
        return -6;
    }
    uint256_t l_value = {};
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-value", &l_value_str);
    if (!l_value_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_PARAM_ERR, "Command 'update' requires parameter -value");
        return -7;
    }
    l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_PARAM_FORMAT_ERR, "Unrecognized number in '-value' param");
        return -8;
    }
    uint256_t l_value_min = dap_chain_net_srv_stake_get_allowed_min_value(l_net->pub.id);
    if (compare256(l_value, l_value_min) == -1) {
        const char *l_value_min_str; dap_uint256_to_char(l_value_min, &l_value_min_str);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_PARAM_FORMAT_ERR, "New delegation value should be not less than service required minimum %s", l_value_min_str);
        return -25;
    }

    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-tx", &l_tx_hash_str);
    if (!l_tx_hash_str) {
        dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-cert", &l_cert_str);
        if (!l_cert_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_PARAM_ERR, "Command 'update' requires parameter -tx or -cert");
            return -13;
        }
    }
    dap_hash_fast_t l_tx_hash = {};
    if (l_tx_hash_str) {
        dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash);
    } else {
        dap_chain_addr_t l_signing_addr;
        dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
        if (!l_cert) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_NO_CERT_ERR, "Specified certificate not found");
            return -18;
        }
        if (!l_cert->enc_key->priv_key_data || l_cert->enc_key->priv_key_data_size == 0) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_PKEY_ERR, "It is not possible to update a stake using a public key.");
            return -31;
        }
        if (dap_chain_addr_fill_from_key(&l_signing_addr, l_cert->enc_key, l_net->pub.id)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_WRONG_CERT_ERR, "Specified certificate is wrong");
            return -22;
        }
        dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(l_net->pub.id);
        if (!l_srv_stake) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_NO_STAKE_IN_NET_ERR, "Specified net have no stake service activated");
            return -25;
        }
        dap_chain_net_srv_stake_item_t *l_stake = NULL;
        HASH_FIND(hh, l_srv_stake->itemlist, &l_signing_addr.data.hash_fast, sizeof(dap_hash_fast_t), l_stake);
        if (!l_stake) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_NOT_DELGATED_ERR, "Specified certificate/pkey hash is not delegated nor this delegating is approved."
                                                           " Try to update with tx hash instead");
            return -24;
        }
        l_tx_hash = l_stake->tx_hash;
    }

    const char *l_tx_hash_str_tmp = l_tx_hash_str ? l_tx_hash_str : dap_hash_fast_to_str_static(&l_tx_hash);
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_tx_hash);
    if (!l_tx) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_NO_TX_ERR, "Transaction %s not found", l_tx_hash_str_tmp);
        return -21;
    }
    int l_out_num = 0;
    if (!dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_out_num)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_INVALID_TX_ERR, "Transaction %s is invalid", l_tx_hash_str_tmp);
        return -22;
    }
    dap_hash_fast_t l_spender_hash = {};
    if (dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &l_tx_hash, l_out_num, &l_spender_hash)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_TX_SPENT_ERR, "Transaction %s is spent", l_tx_hash_str_tmp);
        return -23;
    }

    const char* l_sign_str = "";
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
    if (!l_wallet) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_NO_WALLET_ERR, "Specified wallet %s not found", l_wallet_str);
        return -18;
    } else {
        l_sign_str = dap_chain_wallet_check_sign(l_wallet);
    }
    dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_datum_tx_t *l_tx_new = s_stake_tx_update(l_net, &l_tx_hash, l_value, l_fee, l_enc_key);
    dap_chain_wallet_close(l_wallet);
    dap_enc_key_delete(l_enc_key);
    char *l_out_hash_str = NULL;
    if (l_tx_new && (l_out_hash_str = s_stake_tx_put(l_tx_new, l_net, a_hash_out_type))) {
        json_object* l_json_object_ret = json_object_new_object();
        if (l_sign_str)
            json_object_object_add(l_json_object_ret, "sign", json_object_new_string(l_sign_str));
        json_object_object_add(l_json_object_ret, "hash", json_object_new_string(l_out_hash_str));
        json_object_object_add(l_json_object_ret, "message", json_object_new_string("Delegated m-tokens value will change"));
        json_object_array_add(*a_json_arr_reply, l_json_object_ret);
        DAP_DELETE(l_out_hash_str);
        DAP_DELETE(l_tx_new);
    } else {
        l_tx_hash_str = dap_chain_hash_fast_to_str_static(&l_tx_hash);
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UPDATE_CANT_COMPOSE_ERR, "Can't compose updating transaction %s, examine log files for details", l_tx_hash_str);
        DAP_DEL_Z(l_tx_new);
        return -21;
    }
    return 0;
}


typedef enum s_cli_srv_stake_invalidate_err{
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_OK = 0,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_MEMORY_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_INVALID_PKEY_TYPE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NO_CERT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_POA_CERT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_WRONG_CERT_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PKEY_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_INVALID_PKEY_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NET_NO_STAKE_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_CERT_PKEY_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NO_TX_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_INVALID_TX_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NO_PREV_TX_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_DELEGATED_TX_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_WALLET_ERR,
    DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_TX_INVALIDATE_ERR,
    /* add custom codes here */

    //DAP_CHAIN_NODE_CLI_COM_TX_UNKNOWN /* MAX */
} s_cli_srv_stake_invalidate_err_t;
static int s_cli_srv_stake_invalidate(int a_argc, char **a_argv, int a_arg_index, void **a_str_reply, const char *a_hash_out_type)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    const char *l_net_str = NULL,
               *l_wallet_str = NULL,
               *l_cert_str = NULL,
               *l_fee_str = NULL,
               *l_tx_hash_str = NULL,
               *l_poa_cert_str = NULL,
               *l_signing_pkey_hash_str = NULL,
               *l_signing_pkey_type_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-net", &l_net_str);
    if (!l_net_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR, "Command 'invalidate' requires parameter -net");
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR;
    }
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
    if (!l_net) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NET_ERR, "Network %s not found", l_net_str);
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NET_ERR;
    }
    uint256_t l_fee = {};
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str) {
        dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-poa_cert", &l_poa_cert_str);
        if (!l_poa_cert_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR, "Command 'invalidate' requires parameter -w or -poa_cert");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR;
        }
    } else {
        dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-fee", &l_fee_str);
        if (!l_fee_str) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR, "Command 'delegate' requires parameter -fee");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR;
        }
        l_fee = dap_chain_balance_scan(l_fee_str);
        if (IS_ZERO_256(l_fee)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR, "Unrecognized number in '-fee' param");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR;
        }
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-tx", &l_tx_hash_str);
    if (!l_tx_hash_str) {
        dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-cert", &l_cert_str);
        if (!l_cert_str) {
            dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-signing_pkey_hash", &l_signing_pkey_hash_str);
            if (!l_signing_pkey_hash_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR, "Command 'invalidate' requires parameter -tx or -cert or -signing_pkey_hash");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR;
            }
            dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-signing_pkey_type", &l_signing_pkey_type_str);
            if (!l_signing_pkey_type_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR, "Command 'invalidate' requires parameter -signing_pkey_type");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PARAM_ERR;
            }
            if (dap_sign_type_from_str(l_signing_pkey_type_str).type == SIG_TYPE_NULL) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_INVALID_PKEY_TYPE_ERR, "Invalid signing_pkey_type %s", l_signing_pkey_type_str);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_INVALID_PKEY_TYPE_ERR;
            }
        }
    }

    dap_hash_fast_t l_tx_hash = {};
    if (l_tx_hash_str) {
        dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash);
    } else {
        dap_chain_addr_t l_signing_addr;
        if (l_cert_str) {
            dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_cert) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NO_CERT_ERR, "Specified certificate not found");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NO_CERT_ERR;
            }
            if (!l_cert->enc_key->priv_key_data || l_cert->enc_key->priv_key_data_size == 0) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PKEY_ERR, "It is not possible to invalidate a stake using a public key.");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_PKEY_ERR;
            }
            if (dap_chain_addr_fill_from_key(&l_signing_addr, l_cert->enc_key, l_net->pub.id)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_WRONG_CERT_ERR, "Specified certificate is wrong");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_WRONG_CERT_ERR;
            }
        } else {
            dap_hash_fast_t l_pkey_hash = {};
            if (dap_chain_hash_fast_from_str(l_signing_pkey_hash_str, &l_pkey_hash)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_INVALID_PKEY_ERR, "Invalid pkey hash format");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_INVALID_PKEY_ERR;
            }
            dap_chain_addr_fill(&l_signing_addr, dap_sign_type_from_str(l_signing_pkey_type_str), &l_pkey_hash, l_net->pub.id);
        }
        dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(l_net->pub.id);
        if (!l_srv_stake) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NET_NO_STAKE_ERR, "Specified net have no stake service activated");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NET_NO_STAKE_ERR;
        }
        dap_chain_net_srv_stake_item_t *l_stake = NULL;
        HASH_FIND(hh, l_srv_stake->itemlist, &l_signing_addr.data.hash_fast, sizeof(dap_hash_fast_t), l_stake);
        if (!l_stake) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_CERT_PKEY_ERR, "Specified certificate/pkey hash is not delegated nor this delegating is approved."
                                                           " Try to invalidate with tx hash instead");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_CERT_PKEY_ERR;
        }
        l_tx_hash = l_stake->tx_hash;
    }

    const char *l_tx_hash_str_tmp = l_tx_hash_str ? l_tx_hash_str : dap_hash_fast_to_str_static(&l_tx_hash);
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_tx_hash);
    if (!l_tx) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NO_TX_ERR, "Transaction %s not found", l_tx_hash_str_tmp);
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NO_TX_ERR;
    }

    int l_out_num = 0;
    if (!dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_out_num)) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_INVALID_TX_ERR, "Transaction %s is invalid", l_tx_hash_str_tmp);
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_INVALID_TX_ERR;
    }
    dap_hash_fast_t l_spender_hash = {};
    if (dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &l_tx_hash, l_out_num, &l_spender_hash)) {
        l_tx_hash = l_spender_hash;
        l_tx_hash_str_tmp = dap_hash_fast_to_str_static(&l_spender_hash);
        if (!dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_tx_hash)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NO_PREV_TX_ERR, "Previous transaction %s is not found", l_tx_hash_str_tmp);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NO_PREV_TX_ERR;
        }
    }
    if (l_tx_hash_str) {
        dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(l_net->pub.id);
        if (!l_srv_stake) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NET_NO_STAKE_ERR, "Specified net have no stake service activated");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NET_NO_STAKE_ERR;
        }
        dap_chain_net_srv_stake_item_t *l_stake = NULL;
        HASH_FIND(ht, l_srv_stake->tx_itemlist, &l_tx_hash, sizeof(dap_hash_t), l_stake);
        if (l_stake) {
            char l_pkey_hash_str[DAP_HASH_FAST_STR_SIZE]; 
            dap_hash_fast_to_str(&l_stake->signing_addr.data.hash_fast, l_pkey_hash_str, DAP_HASH_FAST_STR_SIZE);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_DELEGATED_TX_ERR, "Transaction %s has active delegated key %s, need to revoke it first",
                                              l_tx_hash_str_tmp, l_pkey_hash_str);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_DELEGATED_TX_ERR;
        }
    }

    if (l_wallet_str) {
        const char* l_sign_str = "";
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config),NULL);
        if (!l_wallet) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_WALLET_ERR, "Specified wallet not found");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_WALLET_ERR;
        } else {
            l_sign_str = dap_chain_wallet_check_sign(l_wallet);
        }
        dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
        dap_chain_datum_tx_t *l_tx = s_stake_tx_invalidate(l_net, &l_tx_hash, l_fee, l_enc_key);
        dap_chain_wallet_close(l_wallet);
        dap_enc_key_delete(l_enc_key);
        char *l_out_hash_str = NULL;
        if (l_tx && (l_out_hash_str = s_stake_tx_put(l_tx, l_net, a_hash_out_type))) {
            json_object* l_json_object_invalidate = json_object_new_object();
            json_object_object_add(l_json_object_invalidate, "status", json_object_new_string("success"));
            json_object_object_add(l_json_object_invalidate, "sign", json_object_new_string(l_sign_str));
            json_object_object_add(l_json_object_invalidate, "tx_hash", json_object_new_string(l_out_hash_str));
            json_object_object_add(l_json_object_invalidate, "message", json_object_new_string("All m-tokens successfully returned to owner"));
            json_object_array_add(*a_json_arr_reply, l_json_object_invalidate);
            DAP_DELETE(l_out_hash_str);
            DAP_DELETE(l_tx);
        } else {
            l_tx_hash_str = dap_chain_hash_fast_to_str_static(&l_tx_hash);
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_TX_INVALIDATE_ERR, "Can't invalidate transaction %s, examine log files for details", l_tx_hash_str);
            DAP_DEL_Z(l_tx);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_TX_INVALIDATE_ERR;
        }
    } else {
        dap_cert_t *l_poa_cert = dap_cert_find_by_name(l_poa_cert_str);
        if (!l_poa_cert) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NO_CERT_ERR, "Specified certificate not found");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_NO_CERT_ERR;
        }
        if (!s_srv_stake_is_poa_cert(l_net, l_poa_cert->enc_key)) {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_POA_CERT_ERR, "Specified certificate is not PoA root one");
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_POA_CERT_ERR;
        }
        dap_chain_datum_decree_t *l_decree = s_stake_decree_invalidate(l_net, &l_tx_hash, l_poa_cert);
        char *l_decree_hash_str = NULL;
        if (l_decree && (l_decree_hash_str = s_stake_decree_put(l_decree, l_net))) {
            json_object* l_json_object_invalidate = json_object_new_object();
            json_object_object_add(l_json_object_invalidate, "status", json_object_new_string("success"));
            json_object_object_add(l_json_object_invalidate, "decree", json_object_new_string(l_decree_hash_str));
            json_object_object_add(l_json_object_invalidate, "message", json_object_new_string("Specified delegated key invalidated."
                                                                                               "Try to execute this command with -w to return m-tokens to owner"));
            json_object_array_add(*a_json_arr_reply, l_json_object_invalidate);
            DAP_DELETE(l_decree);
            DAP_DELETE(l_decree_hash_str);
        } else {
            char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_TX_INVALIDATE_ERR, "Can't invalidate transaction %s, examine log files for details", l_tx_hash_str);
            DAP_DEL_Z(l_decree);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_INVALIDATE_TX_INVALIDATE_ERR;
        }
    }
    return 0;
}

static void s_srv_stake_print(dap_chain_net_srv_stake_item_t *a_stake, uint256_t a_total_weight, json_object *a_json_arr)
{
    json_object * l_json_obj_stake = json_object_new_object();
    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE], l_pkey_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&a_stake->tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
    dap_chain_hash_fast_to_str(&a_stake->signing_addr.data.hash_fast, l_pkey_hash_str, sizeof(l_pkey_hash_str));
    char *l_balance = dap_chain_balance_to_coins(a_stake->locked_value);
    char *l_effective_weight = dap_chain_balance_to_coins(a_stake->value);
    uint256_t l_rel_weight, l_tmp;
    MULT_256_256(a_stake->value, GET_256_FROM_64(100), &l_tmp);
    DIV_256_COIN(l_tmp, a_total_weight, &l_rel_weight);
    char *l_rel_weight_str = dap_chain_balance_to_coins(l_rel_weight);
        // snprintf(l_active_str, 32, "\tActive: %s\n", a_stake->is_active ? "true" : "false");
    const char *l_sov_addr_str = dap_chain_addr_is_blank(&a_stake->sovereign_addr) ?
                "null" : dap_chain_addr_to_str_static(&a_stake->sovereign_addr);
    uint256_t l_sov_tax_percent = uint256_0;
    MULT_256_256(a_stake->sovereign_tax, GET_256_FROM_64(100), &l_sov_tax_percent);
    char *l_sov_tax_str = dap_chain_balance_to_coins(l_sov_tax_percent);
    char l_node_addr[32];
    snprintf(l_node_addr, 32, ""NODE_ADDR_FP_STR"", NODE_ADDR_FP_ARGS_S(a_stake->node_addr));
    json_object_object_add(l_json_obj_stake, "pkey_hash", json_object_new_string(l_pkey_hash_str));
    json_object_object_add(l_json_obj_stake, "stake_value", json_object_new_string(l_balance));
    json_object_object_add(l_json_obj_stake, "effective_value", json_object_new_string(l_effective_weight));
    json_object_object_add(l_json_obj_stake, "related_weight", json_object_new_string(l_rel_weight_str));
    json_object_object_add(l_json_obj_stake, "tx_hash", json_object_new_string(l_tx_hash_str));
    json_object_object_add(l_json_obj_stake, "node_addr", json_object_new_string(l_node_addr));
    json_object_object_add(l_json_obj_stake, "sovereign_addr", json_object_new_string(l_sov_addr_str));
    json_object_object_add(l_json_obj_stake, "sovereign_tax", json_object_new_string(l_sov_tax_str));
    if (dap_chain_esbocs_started(a_stake->signing_addr.net_id))
        json_object_object_add(l_json_obj_stake, "active", json_object_new_string(a_stake->is_active ? "true" : "false"));
    json_object_array_add(a_json_arr, l_json_obj_stake);
    DAP_DELETE(l_balance);
    DAP_DELETE(l_effective_weight);
    DAP_DELETE(l_rel_weight_str);
    DAP_DELETE(l_sov_tax_str);
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
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE,
                                                                             &l_out_idx_tmp);
    if (!l_tx_out_cond)
        return;
    if (dap_chain_addr_is_blank(&l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr) ||
            l_tx_out_cond->subtype.srv_stake_pos_delegate.signer_node_addr.uint64 == 0)
        return;
    dap_hash_fast_t l_datum_hash = *a_tx_hash;
    if (dap_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &l_datum_hash, l_out_idx_tmp, NULL))
        return;
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_net->pub.id);
    if (!l_srv_stake)
        return;
    dap_chain_net_srv_stake_item_t *l_stake = NULL;
    HASH_FIND(ht, l_srv_stake->tx_itemlist, &l_datum_hash, sizeof(dap_hash_fast_t), l_stake);
    if (!l_stake)
        l_args->ret = dap_list_append(l_args->ret,a_tx);
}

static int s_callback_compare_tx_list(dap_list_t *a_datum1, dap_list_t *a_datum2)
{
    dap_chain_datum_tx_t    *l_datum1 = a_datum1->data,
                            *l_datum2 = a_datum2->data;
    if (!l_datum1 || !l_datum2) {
        log_it(L_CRITICAL, "Invalid element");
        return 0;
    }
    return l_datum1->header.ts_created == l_datum2->header.ts_created
            ? 0 : l_datum1->header.ts_created > l_datum2->header.ts_created ? 1 : -1;
}

int dap_chain_net_srv_stake_check_validator(dap_chain_net_t * a_net, dap_hash_fast_t *a_tx_hash, dap_chain_ch_validator_test_t * out_data,
                                             int a_time_connect, int a_time_respone)
{
    size_t l_node_info_size = 0;
    uint8_t l_test_data[DAP_CHAIN_NET_CH_VALIDATOR_READY_REQUEST_SIZE] = {0};
    dap_chain_node_client_t *l_node_client = NULL;
    dap_chain_node_info_t *l_remote_node_info = NULL;
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(l_ledger, a_tx_hash);
    if (!l_tx) {
        return -11;
    }
    int l_overall_correct = false;

    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_tx,
                                                  DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE, &l_prev_cond_idx);
    if (!l_tx_out_cond) {
        return -4;
    }
    // read node
    l_remote_node_info = (dap_chain_node_info_t*) dap_global_db_get_sync(a_net->pub.gdb_nodes,
        dap_stream_node_addr_to_str_static(l_tx_out_cond->subtype.srv_stake_pos_delegate.signer_node_addr),
        &l_node_info_size, NULL, NULL);
    

    if(!l_remote_node_info) {
        return -6;
    }

    size_t node_info_size_must_be = dap_chain_node_info_get_size(l_remote_node_info);
    if(node_info_size_must_be != l_node_info_size) {
        log_it(L_WARNING, "node has bad size in base=%zu (must be %zu)", l_node_info_size, node_info_size_must_be);
        DAP_DELETE(l_remote_node_info);
        return -7;
    }
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

    uint8_t l_ch_id = DAP_STREAM_CH_CHAIN_NET_ID;
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
        dap_chain_ch_validator_test_t *validators_data = (dap_chain_ch_validator_test_t*)l_node_client->callbacks_arg;

        dap_sign_t *l_sign = NULL;        
        bool l_sign_correct = false;
        if(validators_data->header.sign_size){
            l_sign = (dap_sign_t*)(l_node_client->callbacks_arg + sizeof(dap_chain_ch_validator_test_t));
            dap_hash_fast_t l_sign_pkey_hash;
            dap_sign_get_pkey_hash(l_sign, &l_sign_pkey_hash);
            l_sign_correct = dap_hash_fast_compare(&l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr.data.hash_fast, &l_sign_pkey_hash);
            if (l_sign_correct)
                l_sign_correct = !dap_sign_verify_all(l_sign, validators_data->header.sign_size, l_test_data, sizeof(l_test_data));
        }
        l_overall_correct = l_sign_correct && (validators_data->header.flags & A_PROC) && (validators_data->header.flags & F_ORDR) &&
                                              (validators_data->header.flags & D_SIGN) && (validators_data->header.flags & F_CERT);
        *out_data = *validators_data;
        out_data->header.sign_correct = l_sign_correct ? 1 : 0;
        out_data->header.overall_correct = l_overall_correct ? 1 : 0;
    }
    DAP_DELETE(l_node_client->callbacks_arg);
    dap_chain_node_client_close_mt(l_node_client);
    DAP_DELETE(l_remote_node_info);
    return l_overall_correct;
}

uint256_t dap_chain_net_srv_stake_get_total_weight(dap_chain_net_id_t a_net_id, uint256_t *a_locked_weight)
{
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_net_id);
    dap_return_val_if_fail(l_srv_stake, uint256_0);
    uint256_t l_total_weight = uint256_0;
    for (dap_chain_net_srv_stake_item_t *it = l_srv_stake->itemlist; it; it = it->hh.next) {
        if (it->signing_addr.net_id.uint64 != a_net_id.uint64)
            continue;
        SUM_256_256(l_total_weight, it->value, &l_total_weight);
        if (a_locked_weight)
            SUM_256_256(*a_locked_weight, it->locked_value, a_locked_weight);
    }
    return l_total_weight;
}

static int s_cli_srv_stake(int a_argc, char **a_argv, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    enum {
        CMD_NONE, CMD_ORDER, CMD_DELEGATE, CMD_UPDATE, CMD_APPROVE, CMD_LIST, CMD_INVALIDATE, CMD_MIN_VALUE, CMD_CHECK, CMD_MAX_WEIGHT, CMD_REWARD 
    };
    int l_arg_index = 1;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    else if (dap_strcmp(l_hash_out_type," hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR,
                                "Invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
    }
    int l_cmd_num = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "order", NULL)) {
        l_cmd_num = CMD_ORDER;
    }
    // Create tx to freeze staker's funds and delete order
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "delegate", NULL)) {
        l_cmd_num = CMD_DELEGATE;
    }
    // Create tx to change staker's funds for delegated key (if any)
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "update", NULL)) {
        l_cmd_num = CMD_UPDATE;
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
    // Set stake minimum value
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "min_value", NULL)) {
        l_cmd_num = CMD_MIN_VALUE;
    }
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "max_weight", NULL)) {
        l_cmd_num = CMD_MAX_WEIGHT;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "check", NULL)) {
        l_cmd_num = CMD_CHECK;
    }
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "reward", NULL)) {
        l_cmd_num = CMD_REWARD;
    }

    switch (l_cmd_num) {

        case CMD_ORDER:
            return s_cli_srv_stake_order(a_argc, a_argv, l_arg_index + 1, a_str_reply, l_hash_out_type);

        case CMD_DELEGATE:
            return s_cli_srv_stake_delegate(a_argc, a_argv, l_arg_index + 1, a_str_reply, l_hash_out_type);

        case CMD_UPDATE:
            return s_cli_srv_stake_update(a_argc, a_argv, l_arg_index + 1, a_str_reply, l_hash_out_type);

        case CMD_INVALIDATE:
            return s_cli_srv_stake_invalidate(a_argc, a_argv, l_arg_index + 1, a_str_reply, l_hash_out_type);

        case CMD_CHECK:
        {
            const char * l_netst = NULL;
            const char * str_tx_hash = NULL;
            dap_chain_net_t * l_net = NULL;
            dap_hash_fast_t l_tx = {};
            dap_chain_ch_validator_test_t l_out = {0};

            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_netst);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &str_tx_hash);
            l_net = dap_chain_net_by_name(l_netst);
            if (!l_net) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR, "Network %s not found", l_netst);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR;
            }
            if (!str_tx_hash) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Command check requires parameter -tx");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
            }
            if (dap_chain_hash_fast_from_str(str_tx_hash, &l_tx)){
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_HASH_ERR, "Can't get hash_fast from %s, check that the hash is correct", str_tx_hash);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_HASH_ERR;
            }
            int res = dap_chain_net_srv_stake_check_validator(l_net, &l_tx, &l_out, 10000, 15000);
            switch (res) {
            case -4:
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NEED_TX_NOT_OUTPUT_ERR,"Requested conditional transaction has no required conditional output");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NEED_TX_NOT_OUTPUT_ERR;
                break;
            case -5:
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_HASH_ADDR_ERR,"Can't calculate hash of addr");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_HASH_ADDR_ERR;
                break;
            case -6:
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_NODE_ERR,"Node not found in base");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_NODE_ERR;
                break;
            case -7:
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NODE_BAD_SIZE_ERR,"Node has bad size in base, see log file");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NODE_BAD_SIZE_ERR;
                break;
            case -8:
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_CON_TO_NODE_ERR,"Can't connect to remote node");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_CON_TO_NODE_ERR;
                break;
            case -9:
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_RES_FROM_NODE_ERR,"No response from node");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_RES_FROM_NODE_ERR;
                break;
            case -10:
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_SEND_PKT_ERR,"Can't send DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY_REQUEST packet");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_SEND_PKT_ERR;
                break;
            case -11:
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_TX_ERR,"Can't find conditional tx");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_TX_ERR;
                break;
            default:
                break;
            }

            json_object* json_obj_order = json_object_new_object();
            json_object_object_add(json_obj_order, "VERSION", json_object_new_string((char*)l_out.header.version));
            json_object_object_add(json_obj_order, "AUTO_PROC", json_object_new_string((l_out.header.flags & A_PROC)?"true":"false"));
            json_object_object_add(json_obj_order, "ORDER", json_object_new_string((l_out.header.flags & F_ORDR)?"true":"false"));
            json_object_object_add(json_obj_order, "AUTO_ONLINE", json_object_new_string((l_out.header.flags & A_ONLN)?"true":"false"));
            json_object_object_add(json_obj_order, "AUTO_UPDATE", json_object_new_string((l_out.header.flags & A_UPDT)?"true":"false"));
            json_object_object_add(json_obj_order, "DATA_SIGNED", json_object_new_string((l_out.header.flags & D_SIGN)?"true":"false"));
            json_object_object_add(json_obj_order, "FOUND_CERT", json_object_new_string((l_out.header.flags & F_CERT)?"true":"false"));
            json_object_object_add(json_obj_order, "SIGN_CORRECT", json_object_new_string(l_out.header.sign_correct ?  "true":"false"));
            json_object_object_add(json_obj_order, "SUMMARY", json_object_new_string(l_out.header.overall_correct ? "Validator ready" : "There are unresolved issues"));
            json_object_array_add(*a_json_arr_reply, json_obj_order);
        }
        break;

        case CMD_APPROVE: {
            const char *l_net_str = NULL, *l_tx_hash_str = NULL, *l_cert_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Command 'approve' requires parameter -net");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR, "Network %s not found", l_net_str);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-poa_cert", &l_cert_str);
            if (!l_cert_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Command 'approve' requires parameter -poa_cert");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
            }
            dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_cert) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_CERT_ERR, "Specified certificate not found");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_CERT_ERR;
            }
            if (!s_srv_stake_is_poa_cert(l_net, l_cert->enc_key)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NOT_POA_ERR, "Specified certificate is not PoA root one");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NOT_POA_ERR;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
            if (!l_tx_hash_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Command 'approve' requires parameter -tx");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
            }
            dap_chain_hash_fast_t l_tx_hash = {};
            if (dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_HASH_ERR, "Invalid transaction hash format");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_HASH_ERR;
            }
            dap_chain_datum_decree_t *l_decree = dap_chain_net_srv_stake_decree_approve(l_net, &l_tx_hash, l_cert);
            char *l_decree_hash_str = NULL;
            if (!l_decree || !(l_decree_hash_str = s_stake_decree_put(l_decree, l_net))) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_DECREE_ERR, "Approve decree error");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_DECREE_ERR;
            }
            DAP_DELETE(l_decree);
            char l_approve_str[128];
            snprintf(l_approve_str, sizeof(l_approve_str), "Approve decree %s successfully created", l_decree_hash_str);
            json_object_array_add(*a_json_arr_reply, json_object_new_string(l_approve_str));
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
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Command 'list keys' requires parameter -net");
                    return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
                }
                dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
                if (!l_net) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR, "Network %s not found", l_net_str);
                    return DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR;
                }
                dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(l_net->pub.id);
                if (!l_srv_stake) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_STAKE_IN_NET_ERR, "Specified net have no stake service activated");
                    return DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_STAKE_IN_NET_ERR;
                }
                dap_chain_net_srv_stake_item_t *l_stake = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
                if (l_cert_str) {
                    dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
                    if (!l_cert) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_CERT_ERR, "Specified certificate not found");
                        return DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_CERT_ERR;
                    }
                    dap_chain_addr_t l_signing_addr;
                    if (dap_chain_addr_fill_from_key(&l_signing_addr, l_cert->enc_key, l_net->pub.id)) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_WRONG_CERT_ERR,"Specified certificate is wrong");
                        return DAP_CHAIN_NODE_CLI_SRV_STAKE_WRONG_CERT_ERR;
                    }
                    HASH_FIND(hh, l_srv_stake->itemlist, &l_signing_addr.data.hash_fast, sizeof(dap_hash_fast_t), l_stake);
                    if (!l_stake) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_CERT_ERR, "Specified certificate isn't delegated nor approved");
                        return DAP_CHAIN_NODE_CLI_SRV_STAKE_CERT_ERR;
                    }
                }
                if (!l_cert_str)
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-pkey", &l_pkey_hash_str);
                if (l_pkey_hash_str) {
                    dap_hash_fast_t l_pkey_hash;
                    if (dap_chain_hash_fast_from_str(l_pkey_hash_str, &l_pkey_hash)) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_WRONG_HASH_ERR, "Specified pkey hash is wrong");
                        return DAP_CHAIN_NODE_CLI_SRV_STAKE_WRONG_HASH_ERR;
                    }
                    l_stake = dap_chain_net_srv_stake_check_pkey_hash(l_net->pub.id, &l_pkey_hash);
                    if (!l_stake) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_HASH_ERR, "Specified pkey hash isn't delegated nor approved");
                        return DAP_CHAIN_NODE_CLI_SRV_STAKE_HASH_ERR;
                    }
                }

                json_object* l_json_arr_list = json_object_new_array();
                size_t l_inactive_count = 0, l_total_count = 0;
                uint256_t l_total_locked_weight = {}, l_total_weight = dap_chain_net_srv_stake_get_total_weight(l_net->pub.id, &l_total_locked_weight);
                if (l_stake)
                    s_srv_stake_print(l_stake, l_total_weight, l_json_arr_list);
                else
                    for (l_stake = l_srv_stake->itemlist; l_stake; l_stake = l_stake->hh.next) {
                        l_total_count++;
                        if (!l_stake->is_active)
                            l_inactive_count++;
                        s_srv_stake_print(l_stake, l_total_weight, l_json_arr_list);
                    }
                json_object* l_json_obj_keys_count = json_object_new_object();
                if (!HASH_CNT(hh, l_srv_stake->itemlist)) {
                    json_object_object_add(l_json_obj_keys_count, "total_keys", json_object_new_int(0));
                } else {
                    if (!l_cert_str && !l_pkey_hash_str)
                        json_object_object_add(l_json_obj_keys_count, "total_keys", json_object_new_int(l_total_count));
                    if (dap_chain_esbocs_started(l_net->pub.id))
                        json_object_object_add(l_json_obj_keys_count, "inactive_keys", json_object_new_int(l_inactive_count));


                    const char *l_total_weight_coins, *l_total_weight_str = dap_uint256_to_char(l_total_locked_weight, &l_total_weight_coins);
                    json_object_object_add(l_json_obj_keys_count, "total_weight_coins", json_object_new_string(l_total_weight_coins));
                    json_object_object_add(l_json_obj_keys_count, "total_weight_str", json_object_new_string(l_total_weight_str));
                    l_total_weight_str = dap_uint256_to_char(l_total_weight, &l_total_weight_coins);
                    json_object_object_add(l_json_obj_keys_count, "total_effective_weight_coins", json_object_new_string(l_total_weight_coins));
                    json_object_object_add(l_json_obj_keys_count, "total_effective_weight", json_object_new_string(l_total_weight_str));
                }

                const char *l_delegate_min_str; dap_uint256_to_char(dap_chain_net_srv_stake_get_allowed_min_value(l_net->pub.id),
                                                                    &l_delegate_min_str);
                char l_delegated_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
                dap_chain_datum_token_get_delegated_ticker(l_delegated_ticker, l_net->pub.native_ticker);
                json_object_object_add(l_json_obj_keys_count, "key_delegating_min_value", json_object_new_string(l_delegate_min_str));
                json_object_object_add(l_json_obj_keys_count, "key_delegating_min_value_ticker", json_object_new_string(l_delegated_ticker));
                uint256_t l_percent_max = dap_chain_net_srv_stake_get_percent_max(l_net->pub.id);
                const char *l_percent_max_str = NULL;
                if (!IS_ZERO_256(l_percent_max)) {
                    MULT_256_256(l_percent_max, GET_256_FROM_64(100), &l_percent_max);
                    dap_uint256_to_char(l_percent_max, &l_percent_max_str);
                }
                json_object_object_add(l_json_obj_keys_count, "each_validator_max_related_weight", json_object_new_string(IS_ZERO_256(l_percent_max) ? "100" : l_percent_max_str));
                json_object_array_add(l_json_arr_list, l_json_obj_keys_count);
                json_object_array_add(*a_json_arr_reply, l_json_arr_list);
            } else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "tx", NULL)) {
                const char *l_net_str = NULL;
                l_arg_index++;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
                if (!l_net_str) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Command 'list tx' requires parameter -net");
                    return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
                }
                dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
                if (!l_net) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR, "Network %s not found", l_net_str);
                    return DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR;
                }
                struct get_tx_cond_pos_del_from_tx * l_args = DAP_NEW_Z(struct get_tx_cond_pos_del_from_tx);
                if(!l_args) {
                    log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_MEMORY_ERR, "Out of memory");
                    return DAP_CHAIN_NODE_CLI_SRV_STAKE_MEMORY_ERR;
                }
                json_object * l_json_arr_tx = json_object_new_array();
                dap_hash_fast_t l_datum_hash;
                dap_chain_datum_tx_t *l_datum_tx = NULL;
                dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
                int l_out_idx_tmp = 0;
                const char *l_signing_addr_str = NULL, *l_balance = NULL, *l_coins = NULL;
                char* l_node_address_text_block = NULL;
                dap_chain_net_get_tx_all(l_net,TX_SEARCH_TYPE_NET,s_get_tx_filter_callback, l_args);
                l_args->ret = dap_list_sort(l_args->ret, s_callback_compare_tx_list);
                for(dap_list_t *tx = l_args->ret; tx; tx = tx->next)
                {
                    json_object* l_json_obj_tx = json_object_new_object();
                    l_datum_tx = (dap_chain_datum_tx_t*)tx->data;
                    char buf[DAP_TIME_STR_SIZE];
                    dap_hash_fast(l_datum_tx, dap_chain_datum_tx_get_size(l_datum_tx), &l_datum_hash);
                    l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_datum_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE,
                                                                                     &l_out_idx_tmp);
                    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                    dap_chain_hash_fast_to_str(&l_datum_hash, l_hash_str, sizeof(l_hash_str));
                    dap_time_to_str_rfc822(buf, DAP_TIME_STR_SIZE, l_datum_tx->header.ts_created);
                    json_object_object_add(l_json_obj_tx, "date", json_object_new_string(buf));
                    json_object_object_add(l_json_obj_tx, "tx_hash", json_object_new_string(l_hash_str));

                    char l_pkey_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                    dap_chain_hash_fast_to_str(&l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr.data.hash_fast, l_pkey_hash_str, sizeof(l_pkey_hash_str));
                    l_balance = dap_uint256_to_char(l_tx_out_cond->header.value, &l_coins);
                    
                    l_signing_addr_str = dap_chain_addr_to_str_static(&l_tx_out_cond->subtype.srv_stake_pos_delegate.signing_addr);
                    json_object_object_add(l_json_obj_tx, "signing_addr", json_object_new_string(l_signing_addr_str));
                    json_object_object_add(l_json_obj_tx, "signing_hash", json_object_new_string(l_pkey_hash_str));
                    l_node_address_text_block = dap_strdup_printf("node_address:\t" NODE_ADDR_FP_STR,NODE_ADDR_FP_ARGS_S(l_tx_out_cond->subtype.srv_stake_pos_delegate.signer_node_addr));
                    json_object_object_add(l_json_obj_tx, "node_address", json_object_new_string(l_node_address_text_block));
                    json_object_object_add(l_json_obj_tx, "value_coins", json_object_new_string(l_coins));
                    json_object_object_add(l_json_obj_tx, "value_datoshi", json_object_new_string(l_balance));
                    json_object_array_add(l_json_arr_tx, l_json_obj_tx);
                    DAP_DELETE(l_node_address_text_block);
                }

                json_object_array_add(*a_json_arr_reply, l_json_arr_tx);
                DAP_DELETE(l_args);
            } else {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_WRONG_SUB_COMMAND_ERR, "Subcommand '%s' not recognized", a_argv[l_arg_index]);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_WRONG_SUB_COMMAND_ERR;
            }
        } break;

        case CMD_MIN_VALUE: {
            const char *l_net_str = NULL,
                       *l_cert_str = NULL,
                       *l_value_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Command 'min_value' requires parameter -net");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR, "Network %s not found", l_net_str);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR;
            }
            dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR);
            if (!l_chain)
                l_chain =  dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR);
            if (!l_chain) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ANCHOR_NOT_SUPPORT_ERR, "No chain supported anchor datum type");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_ANCHOR_NOT_SUPPORT_ERR;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-poa_cert", &l_cert_str);
            if (!l_cert_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Command 'min_value' requires parameter -poa_cert");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
            }
            dap_cert_t *l_poa_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_poa_cert) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_CERT_ERR, "Specified certificate not found");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_CERT_ERR;
            }
            if (!s_srv_stake_is_poa_cert(l_net, l_poa_cert->enc_key)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NOT_POA_ERR, "Specified certificate is not PoA root one");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NOT_POA_ERR;
            }

            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
            if (!l_value_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Command 'min_value' requires parameter -value");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
            }
            uint256_t l_value = dap_chain_balance_scan(l_value_str);
            if (IS_ZERO_256(l_value)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Unrecognized number in '-value' param");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
            }

            dap_chain_datum_decree_t *l_decree = s_stake_decree_set_min_stake(l_net, l_chain, l_value, l_poa_cert);
            char *l_decree_hash_str = NULL;
            if (l_decree && (l_decree_hash_str = s_stake_decree_put(l_decree, l_net))) {
                json_object* l_json_obj_min_val = json_object_new_object();
                json_object_object_add(l_json_obj_min_val, "status", json_object_new_string("success"));
                json_object_object_add(l_json_obj_min_val, "decree_hash", json_object_new_string(l_decree_hash_str));
                json_object_array_add(*a_json_arr_reply, l_json_obj_min_val);
                DAP_DELETE(l_decree);
                DAP_DELETE(l_decree_hash_str);
            } else {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_MIN_STAKE_SET_FAILED_ERR, "Minimum stake value setting failed");
                DAP_DEL_Z(l_decree);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_MIN_STAKE_SET_FAILED_ERR;
            }
        } break;

        case CMD_MAX_WEIGHT: {
            const char *l_net_str = NULL,
                       *l_cert_str = NULL,
                       *l_value_str = NULL;
            l_arg_index++;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            if (!l_net_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Command 'max_weight' requires parameter -net");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
            }
            dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
            if (!l_net) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR, "Network %s not found", l_net_str);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NET_ERR;
            }
            dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR);
            if (!l_chain)
                l_chain =  dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_ANCHOR);
            if (!l_chain) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_ANCHOR_NOT_SUPPORT_ERR, "No chain supported anchor datum type");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_ANCHOR_NOT_SUPPORT_ERR;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-poa_cert", &l_cert_str);
            if (!l_cert_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Command 'max_weight' requires parameter -poa_cert");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
            }
            dap_cert_t *l_poa_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_poa_cert) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_CERT_ERR, "Specified certificate not found");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NO_CERT_ERR;
            }
            if (!s_srv_stake_is_poa_cert(l_net, l_poa_cert->enc_key)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_NOT_POA_ERR, "Specified certificate is not PoA root one");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_NOT_POA_ERR;
            }

            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-percent", &l_value_str);
            if (!l_value_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Command 'max_weight' requires parameter -percent");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
            }
            uint256_t l_value = dap_chain_coins_to_balance(l_value_str);
            if (IS_ZERO_256(l_value)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR, "Unrecognized number in '-percent' param");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PARAM_ERR;
            }
            if (compare256(l_value, dap_chain_coins_to_balance("100.0")) >= 0) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_PERCENT_ERR, "Percent must be lower than 100%%");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_PERCENT_ERR;
            }
            DIV_256(l_value, GET_256_FROM_64(100), &l_value);
            dap_chain_datum_decree_t *l_decree = s_stake_decree_set_max_weight(l_net, l_chain, l_value, l_poa_cert);
            char *l_decree_hash_str = NULL;
            if (l_decree && (l_decree_hash_str = s_stake_decree_put(l_decree, l_net))) {
                json_object* l_json_obj_max_weight = json_object_new_object();
                json_object_object_add(l_json_obj_max_weight, "status", json_object_new_string("success"));
                json_object_object_add(l_json_obj_max_weight, "decree_hash", json_object_new_string(l_decree_hash_str));
                json_object_array_add(*a_json_arr_reply, l_json_obj_max_weight);
                DAP_DELETE(l_decree);
                DAP_DELETE(l_decree_hash_str);
            } else {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_MAX_WEIGHT_SET_FAILED_ERR, "Maximum weight setting failed");
                DAP_DEL_Z(l_decree);
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_MAX_WEIGHT_SET_FAILED_ERR;
            }
        } break;

        case CMD_REWARD: {
            const char *l_net_str = NULL,
                       *l_addr_str = NULL,
                       *l_limit_str = NULL,
                       *l_pkey_str = NULL,
                       *l_offset_str = NULL,
                       *l_d_from_str = NULL,
                       *l_d_to_str = NULL,
                       *l_head_str = NULL;

            dap_chain_t * l_chain = NULL;
            dap_chain_net_t * l_net = NULL;
            dap_time_t l_from_time = 0, l_to_time = 0;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-node_addr", &l_addr_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-pkey", &l_pkey_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-limit", &l_limit_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-offset", &l_offset_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-date_from", &l_d_from_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-date_to", &l_d_to_str);
            bool l_head = dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-head", &l_head_str) ? true : false;
            size_t l_limit = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 0;
            size_t l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;

            bool l_brief = (dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-brief") != -1) ? true : false;

            bool l_is_tx_all = dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-all", NULL);

            uint32_t l_info_size = sizeof(dap_chain_node_info_t);
            dap_chain_node_info_t *l_node_info = NULL;

            if (!l_addr_str  && !l_is_tx_all ) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_PARAM_ERR,
                                "reward requires parameter '-addr' or '-w' or '-all'");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_PARAM_ERR;
            }

            if (!l_net_str && !l_addr_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_PARAM_ERR,
                                "reward requires parameter '-net' or '-addr' or '-w'");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_PARAM_ERR;
            }
            
            // Select chain network
            if (l_net_str) {
                l_net = dap_chain_net_by_name(l_net_str);
                if (!l_net) { // Can't find such network
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_NET_PARAM_ERR,
                                            "reward requires parameter '-net' to be valid chain network name");
                    return DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_NET_PARAM_ERR;
                }
            }

            if (l_d_from_str) {
                l_from_time = dap_time_from_str_simplified(l_d_from_str);
                if (!l_from_time) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_ERR, "Can't convert \"%s\" to date", l_d_from_str);
                    return DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_ERR;
                }
            }

            if (l_d_to_str) {
                l_to_time = dap_time_from_str_simplified(l_d_to_str);
                if (!l_to_time) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_ERR, "Can't convert \"%s\" to date", l_d_to_str);
                    return DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_ERR;
                }
                struct tm *l_localtime = localtime((time_t *)&l_to_time);
                l_localtime->tm_mday += 1;  // + 1 day to end date, got it inclusive
                l_to_time = mktime(l_localtime);
            } 

            // Get chain address
            if (l_addr_str) {
                l_node_info = DAP_NEW_STACK_SIZE(dap_chain_node_info_t, l_info_size);
                memset(l_node_info, 0, l_info_size);
                if (dap_chain_node_addr_from_str(&l_node_info->address, l_addr_str)) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_NODE_ADDR_ERR,
                                                                "Can't parse node address %s", l_addr_str);
                    return DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_NODE_ADDR_ERR;
                }

            }

            dap_chain_hash_fast_t l_hash_public_key = {0};
            /*
            if (!l_addr && l_pkey_str)
                if (dap_chain_hash_fast_from_str(l_pkey_str, &l_hash_public_key)) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_INVALID_PKEY_ERR, "Invalid pkey hash format");
                    return DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_INVALID_PKEY_ERR;
                }*/

            if (!l_net) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_NET_ERR, "Could not determine the network from which to "
                                                       "extract data for the reward command to work.");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_NET_ERR;
            }

            l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);

            if (!l_chain) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_CHAIN_PARAM_ERR,
                                "can't find the required chain");
                return DAP_CHAIN_NODE_CLI_SRV_STAKE_REWARD_CHAIN_PARAM_ERR;
            }
            json_object* l_json_arr_reply = s_dap_chain_net_srv_stake_reward_all(*a_json_arr_reply, l_node_info, l_chain,
                                 l_net, l_from_time, l_to_time, l_limit, l_offset, l_brief, l_head);
            json_object_array_add(*a_json_arr_reply, l_json_arr_reply);                                    
        } break;

        default: {
            dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_SRV_STAKE_UNRECOGNIZE_COM_ERR, "Command %s not recognized", a_argv[l_arg_index]);
            return DAP_CHAIN_NODE_CLI_SRV_STAKE_UNRECOGNIZE_COM_ERR;
        }
    }
    return 0;
}


static json_object* s_dap_chain_net_srv_stake_reward_all(json_object* a_json_arr_reply, dap_chain_node_info_t *a_node_info, dap_chain_t *a_chain,
                                 dap_chain_net_t *a_net, dap_time_t a_time_form, dap_time_t a_time_to,
                                 size_t a_limit, size_t a_offset, bool a_brief, bool a_head)
{
    json_object* json_obj_reward = json_object_new_array();
    if (!json_obj_reward){
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_json_rpc_error_add(a_json_arr_reply, -44, "Memory allocation error");
        return NULL;
    }
    const char *l_native_ticker = a_net->pub.native_ticker;
    if (!a_chain->callback_datum_iter_create) {
        log_it(L_WARNING, "Not defined callback_datum_iter_create for chain \"%s\"", a_chain->name);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Not defined callback_datum_iter_create for chain \"%s\"", a_chain->name);
        json_object_put(json_obj_reward);
        return NULL;
    }

    size_t l_arr_start = 0;
    size_t l_arr_end = 0;
    s_set_offset_limit_json(json_obj_reward, &l_arr_start, &l_arr_end, a_limit, a_offset, 0);  

    size_t i_tmp = 0;
    uint256_t l_value_total = uint256_0;
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_chain->net_id);

    // load transactions
    dap_chain_datum_iter_t *l_datum_iter = a_chain->callback_datum_iter_create(a_chain);
    
    dap_chain_datum_callback_iters  iter_begin;
    dap_chain_datum_callback_iters  iter_direc;
    iter_begin = a_head ? a_chain->callback_datum_iter_get_first
                        : a_chain->callback_datum_iter_get_last;
    iter_direc = a_head ? a_chain->callback_datum_iter_get_next
                        : a_chain->callback_datum_iter_get_prev;
        
    for (dap_chain_datum_t *l_datum = iter_begin(l_datum_iter);
                            l_datum;
                            l_datum = iter_direc(l_datum_iter))
    {
        dap_hash_fast_t l_ttx_hash = {0};
        dap_chain_hash_fast_t l_datum_hash;        
        if (a_limit && i_tmp >= l_arr_end)
            break;
        if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
            // go to next datum
            continue;
        
        if (a_time_form && l_datum->header.ts_create < a_time_form)
            continue;
        if (a_time_to && l_datum->header.ts_create >= a_time_to)
            continue;
        if (i_tmp >= l_arr_end)
            break;
        
        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
        dap_list_t *l_list_in_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_IN_REWARD, NULL);
        if (!l_list_in_items) // a bad tx
            continue;
        if (i_tmp < l_arr_start) {
            i_tmp++;
            continue;
        }
        // all in items should be from the same address
        dap_hash_fast(l_tx, l_datum->header.data_size, &l_ttx_hash);
        dap_hash_fast(l_datum, dap_chain_datum_size(l_datum), &l_datum_hash);
        json_object* json_obj_hash = json_object_new_object();
        json_object_object_add(json_obj_hash, "tx_hash",
                                        json_object_new_string(dap_chain_hash_fast_to_str_static(&l_ttx_hash)));
        json_object_array_add(json_obj_reward, json_obj_hash);

        /*
        const char * l_tx_token_ticker = l_datum_iter ? l_datum_iter->token_ticker
                                     : dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_datum_hash);*/
        json_object* json_arr_sign_out = NULL;
        json_object* json_block_hash = NULL;
        uint256_t l_value_reward = uint256_0, l_value_out = uint256_0;
        if (!a_brief && !a_node_info) {
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT, NULL);
            dap_list_t *l_list_out_cond_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_COND, NULL);
            for(dap_list_t *it = l_list_out_items; it; it = it->next) {
                 dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t *)it->data;
                 SUM_256_256(l_value_out, l_tx_out->header.value, &l_value_out);
            }
            for(dap_list_t *it = l_list_out_cond_items; it; it = it->next) {
                 dap_chain_tx_out_cond_t *l_tx_out_cound = (dap_chain_tx_out_cond_t *)it->data;
                 SUM_256_256(l_value_out, l_tx_out_cound->header.value, &l_value_out);
            }
            dap_list_free(l_list_out_items);
            dap_list_free(l_list_out_cond_items);
        }
        for(dap_list_t *it = l_list_in_items; it; it = it->next)
        {
            dap_chain_tx_in_reward_t *l_in_reward = (dap_chain_tx_in_reward_t *) it->data;            
            dap_chain_block_cache_t *l_block_cache = dap_chain_block_cache_get_by_hash(DAP_CHAIN_CS_BLOCKS(a_chain), &l_in_reward->block_hash);
            char *l_block_hash = NULL;
            json_arr_sign_out = json_object_new_array();
            l_block_hash = dap_chain_hash_fast_to_str_new(&l_in_reward->block_hash);
            json_block_hash = json_object_new_object();
            json_object_object_add(json_block_hash, "block hash", json_object_new_string(l_block_hash));
            DAP_DELETE(l_block_hash);


            for (uint32_t i=0; i < l_block_cache->sign_count ; i++) {
                if (!json_arr_sign_out) {
                    json_arr_sign_out = json_object_new_array();
                    l_block_hash = dap_chain_hash_fast_to_str_new(&l_in_reward->block_hash);
                    json_block_hash = json_object_new_object();
                    json_object_object_add(json_block_hash, "block hash", json_object_new_string(l_block_hash));
                    DAP_DELETE(l_block_hash);
                }
                            
                dap_sign_t * l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, i);
                size_t l_sign_size = dap_sign_get_size(l_sign);
                dap_chain_hash_fast_t l_pkey_hash;
                dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
                char l_pkey_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(&l_pkey_hash, l_pkey_hash_str, sizeof(l_pkey_hash_str));
                dap_chain_net_srv_stake_item_t *l_stake = NULL;
                HASH_FIND(hh, l_srv_stake->itemlist, &l_pkey_hash, sizeof(dap_hash_fast_t), l_stake);

                if (a_node_info) {
                    if (!l_stake || a_node_info->address.uint64 != l_stake->node_addr.uint64) {
                        if (json_object_array_length(json_arr_sign_out) == 0) {
                            json_object_put(json_arr_sign_out);
                            json_object_put(json_block_hash);
                            json_arr_sign_out = NULL;
                            json_block_hash = NULL;
                        }
                        continue;
                    }

                }

                json_object* json_obj_sign = json_object_new_object();
                if (l_stake && !a_brief) {
                    char *l_addr = dap_strdup_printf(""NODE_ADDR_FP_STR"",NODE_ADDR_FP_ARGS_S(l_stake->node_addr));
                    json_object_object_add(json_obj_sign, "validator addr", json_object_new_string(l_addr));
                    DAP_DELETE(l_addr);
                }
                json_object_object_add(json_obj_sign, "pkey_hash",json_object_new_string(l_pkey_hash_str));
                dap_pkey_t * l_block_sign_pkey = dap_pkey_get_from_sign(l_sign);
                l_value_reward = a_chain->callback_calc_reward(a_chain, &l_block_cache->block_hash,
                                                             l_block_sign_pkey);
                DAP_DELETE(l_block_sign_pkey);
                const char  *l_coins_str,
                    *l_value_str = dap_uint256_to_char(l_value_reward, &l_coins_str);
                json_object_object_add(json_obj_sign, "reward value", json_object_new_string(l_value_str));
                json_object_object_add(json_obj_sign, "reward coins", json_object_new_string(l_coins_str));
                json_object_array_add(json_arr_sign_out, json_obj_sign);
            }
            SUM_256_256(l_value_total, l_value_reward, &l_value_total);
            l_value_reward = uint256_0;
            if (json_arr_sign_out && json_object_array_length(json_arr_sign_out) > 0) {
                if (!a_brief)
                    json_object_object_add(json_block_hash, "Tx_hash", 
                                                json_object_new_string(dap_chain_hash_fast_to_str_static(&l_ttx_hash)));
                json_object_object_add(json_block_hash, "REWARDS", json_arr_sign_out);
                json_object_array_add(json_obj_reward, json_block_hash);
            }                        
        }
        if (!a_node_info) {
            const char  *l_coins_out_str, *l_value_str;
            json_object* json_value_out = json_object_new_object();
            l_value_str = dap_uint256_to_char(l_value_out, &l_coins_out_str);
            json_object_object_add(json_value_out, "Rewards value (calculated)", json_object_new_string(l_value_str));
            json_object_object_add(json_value_out, "Rewards coins (calculated)", json_object_new_string(l_coins_out_str));
            json_object_array_add(json_obj_reward, json_value_out);
        }
        i_tmp++;
        dap_list_free(l_list_in_items);
    }
    if (a_node_info) {
        const char  *l_coins_out_str, *l_value_str;
        json_object* json_value_out = json_object_new_object();
        l_value_str = dap_uint256_to_char(l_value_total, &l_coins_out_str);
        json_object_object_add(json_value_out, "Rewards value (total)", json_object_new_string(l_value_str));
        json_object_object_add(json_value_out, "Rewards coins (total)", json_object_new_string(l_coins_out_str));
        json_object_array_add(json_obj_reward, json_value_out);
    }    
    a_chain->callback_datum_iter_delete(l_datum_iter);
    return json_obj_reward;
}


bool dap_chain_net_srv_stake_get_fee_validators(dap_chain_net_t *a_net,
                                                uint256_t *a_max_fee, uint256_t *a_average_fee, uint256_t *a_min_fee, uint256_t *a_median_fee)
{
    dap_return_val_if_fail(a_net, false);
    char *l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group(a_net);
    size_t l_orders_count = 0;
    dap_global_db_obj_t *l_orders = dap_global_db_get_all_sync(l_gdb_group_str, &l_orders_count);
    DAP_DELETE(l_gdb_group_str);
    uint256_t l_min = uint256_0, l_max = uint256_0, l_average = uint256_0, l_median = uint256_0;
    uint64_t l_order_fee_count = 0;
    uint256_t l_all_fees[l_orders_count * sizeof(uint256_t)];
    for (size_t i = 0; i < l_orders_count; i++) {
        const dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_check(l_orders[i].key, l_orders[i].value, l_orders[i].value_len);
        if (!l_order) {
            log_it(L_WARNING, "Unreadable order %s", l_orders[i].key);
            continue;
        }
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
    dap_global_db_objs_delete(l_orders, l_orders_count);
    uint256_t t = uint256_0;
    if (!IS_ZERO_256(l_average))
        DIV_256(l_average, dap_chain_uint256_from(l_order_fee_count), &t);
    l_average = t;

    if (l_order_fee_count) {
        l_median = l_all_fees[(size_t)(l_order_fee_count * 2 / 3)];
    }

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

void dap_chain_net_srv_stake_get_fee_validators_str(dap_chain_net_t *a_net, dap_string_t *a_string_ret)
{
    if (!a_net || !a_string_ret)
        return;
    uint256_t l_min = uint256_0, l_max = uint256_0, l_average = uint256_0, l_median = uint256_0;
    dap_chain_net_srv_stake_get_fee_validators(a_net, &l_max, &l_average, &l_min, &l_median);
    const char *l_native_token  = a_net->pub.native_ticker, *l_coins_str;
    char *l_min_balance = dap_strdup(dap_uint256_to_char(l_min, &l_coins_str)),     *l_min_coins    = dap_strdup(l_coins_str),
    *l_max_balance      = dap_strdup(dap_uint256_to_char(l_max, &l_coins_str)),     *l_max_coins    = dap_strdup(l_coins_str),
    *l_average_balance  = dap_strdup(dap_uint256_to_char(l_average, &l_coins_str)), *l_average_coins= dap_strdup(l_coins_str),
    *l_median_balance   = dap_strdup(dap_uint256_to_char(l_median, &l_coins_str)),  *l_median_coins = dap_strdup(l_coins_str);

    dap_string_append_printf(a_string_ret, "Validator fee: \n"
                                           "\t MIN: %s (%s) %s\n"
                                           "\t MAX: %s (%s) %s\n"
                                           "\t Average: %s (%s) %s \n"
                                           "\t Median: %s (%s) %s \n", l_min_coins, l_min_balance, l_native_token,
                                           l_max_coins, l_max_balance, l_native_token,
                                           l_average_coins, l_average_balance, l_native_token,
                                           l_median_coins, l_median_balance, l_native_token);
    DAP_DEL_MULTY(l_min_balance, l_min_coins, l_max_balance, l_max_coins, l_average_balance, l_average_coins, l_median_balance, l_median_coins);
}

json_object *dap_chain_net_srv_stake_get_fee_validators_json(dap_chain_net_t  *a_net) {
    if (!a_net)
        return NULL;
    uint256_t l_min = uint256_0, l_max = uint256_0, l_average = uint256_0, l_median = uint256_0;
    dap_chain_net_srv_stake_get_fee_validators(a_net, &l_max, &l_average, &l_min, &l_median);
    const char *l_native_token  = a_net->pub.native_ticker;
    json_object *l_jobj_min     = json_object_new_object(), *l_jobj_max     = json_object_new_object(),
                *l_jobj_average = json_object_new_object(), *l_jobj_median  = json_object_new_object(),
                *l_jobj_ret     = json_object_new_object();
                
    const char *l_coins_str;
    json_object_object_add( l_jobj_min,     "balance",  json_object_new_string(dap_uint256_to_char(l_min, &l_coins_str)) );
    json_object_object_add( l_jobj_min,     "coin",     json_object_new_string(l_coins_str) );

    json_object_object_add( l_jobj_max,     "balance",  json_object_new_string(dap_uint256_to_char(l_max, &l_coins_str)) );
    json_object_object_add( l_jobj_max,     "coin",     json_object_new_string(l_coins_str) );

    json_object_object_add( l_jobj_average, "balance",  json_object_new_string(dap_uint256_to_char(l_average, &l_coins_str)) );
    json_object_object_add( l_jobj_average, "coin",     json_object_new_string(l_coins_str) );
    
    json_object_object_add( l_jobj_median, "balance",   json_object_new_string(dap_uint256_to_char(l_median, &l_coins_str)) );
    json_object_object_add( l_jobj_median, "coin",      json_object_new_string(l_coins_str) );

    json_object_object_add(l_jobj_ret, "min",       l_jobj_min);
    json_object_object_add(l_jobj_ret, "max",       l_jobj_max);
    json_object_object_add(l_jobj_ret, "average",   l_jobj_average);
    json_object_object_add(l_jobj_ret, "median",    l_jobj_median);
    json_object_object_add(l_jobj_ret, "token",     json_object_new_string(a_net->pub.native_ticker));

    return l_jobj_ret;
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

static void s_uncache_data(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_addr_t *a_signing_addr)
{
    if (!dap_ledger_cache_enabled(a_ledger))
        return;
    dap_chain_hash_fast_t l_hash = {};
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_hash);
    char l_data_key[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_hash, l_data_key, sizeof(l_data_key));
    char *l_gdb_group = dap_ledger_get_gdb_group(a_ledger, DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_GDB_GROUP);
    if (dap_global_db_del_sync(l_gdb_group, l_data_key))
        log_it(L_WARNING, "Stake service cache mismatch");
}

dap_chain_net_srv_stake_item_t *dap_chain_net_srv_stake_check_pkey_hash(dap_chain_net_id_t a_net_id, dap_hash_fast_t *a_pkey_hash)
{
    dap_chain_net_srv_stake_t *l_srv_stake = s_srv_stake_by_net_id(a_net_id);
    if (!l_srv_stake)
        return NULL;
    dap_chain_net_srv_stake_item_t *l_stake, *l_tmp;
    HASH_ITER(hh, l_srv_stake->itemlist, l_stake, l_tmp) {
        if (dap_hash_fast_compare(&l_stake->signing_addr.data.hash_fast, a_pkey_hash))
            return l_stake;
    }
    return NULL;
}

size_t dap_chain_net_srv_stake_get_total_keys(dap_chain_net_id_t a_net_id, size_t *a_in_active_count)
{
    dap_chain_net_srv_stake_t *l_stake_rec = s_srv_stake_by_net_id(a_net_id);
    if (!l_stake_rec)
        return 0;
    size_t l_total_count = 0, l_inactive_count = 0;
    dap_chain_net_srv_stake_item_t *l_item = NULL;
    for (l_item = l_stake_rec->itemlist; l_item; l_item = l_item->hh.next) {
        if (l_item->net->pub.id.uint64 != a_net_id.uint64)
            continue;
        l_total_count++;
        if (!l_item->is_active)
            l_inactive_count++;
    }
    if (a_in_active_count) {
        *a_in_active_count = l_inactive_count;
    }
    return l_total_count;
}
