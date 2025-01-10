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

#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_ledger.h"
#include "dap_chain_wallet.h"
#include "dap_chain_mempool.h"
#include "dap_cli_server.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv_emit_delegate.h"
#include "dap_chain_node_cli_cmd.h"


enum emit_delegation_error {
    DAP_NO_ERROR = 0,
    ERROR_MEMORY,
    ERROR_OVERFLOW,
    ERROR_PARAM,
    ERROR_VALUE,
    ERROR_WRONG_HASH,
    ERROR_FUNDS,
    ERROR_TX_MISMATCH,
    ERROR_COMPOSE,
    ERROR_CREATE,
    ERROR_PLACE,
    ERROR_SUBCOMMAND
};

#define LOG_TAG "dap_chain_net_srv_emit_delegate"

static int s_emit_delegate_verificator(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx_in, bool UNUSED_ARG a_owner)
{
    size_t l_tsd_hashes_count = a_cond->tsd_size / (sizeof(dap_tsd_t) + sizeof(dap_hash_fast_t));
    dap_sign_t *l_signs[l_tsd_hashes_count * 2];
    uint32_t l_signs_counter = 0, l_signs_verified = 0;
    uint256_t l_writeoff_value = uint256_0;
    dap_chain_tx_out_cond_t *l_cond_out = NULL;
    dap_chain_addr_t l_net_fee_addr;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_ledger->net->pub.id, NULL, &l_net_fee_addr);
    byte_t *l_item; size_t l_tx_item_size;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx_in) {
        switch (*l_item) {
        // Verify change
        case TX_ITEM_TYPE_OUT_COND:
            if (a_cond->header.subtype == ((dap_chain_tx_out_cond_t *)l_item)->header.subtype) {
                if (l_cond_out) {
                    log_it(L_ERROR, "Only the condional output allowed for target subtype");
                    return -3;
                }
                l_cond_out = (dap_chain_tx_out_cond_t *)l_item;
            }
            break;
        case TX_ITEM_TYPE_TSD: {
            dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t *)l_item)->tsd;
            if (l_tsd->type != DAP_CHAIN_NET_SRV_EMIT_DELEGATE_TSD_WRITEOFF)
                break; // Skip it
            if (l_tsd->size != sizeof(uint256_t)) {
                log_it(L_ERROR, "TSD section size control error");
                return -4;
            }
            if (!IS_ZERO_256(l_writeoff_value)) {
                log_it(L_ERROR, "More than one TSD section is forbidden");
                return -5;
            }
            l_writeoff_value = dap_tsd_get_scalar(l_tsd, uint256_t);
            break;
        }
        // Verify signs
        case TX_ITEM_TYPE_SIG: {
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_item);
            bool l_dup = false;
            for (uint32_t i = 0; i < l_signs_counter; i++)
                if (dap_sign_compare_pkeys(l_sign, l_signs[i])) {
                    l_dup = true;
                    break;
                }
            if (l_dup)
                continue;
            l_signs[l_signs_counter] = l_sign;
            if (l_signs_counter >= l_tsd_hashes_count * 2) {
                log_it(L_WARNING, "Too many signs in tx, can't process more than %zu", l_tsd_hashes_count);
                return -1;
            }
            dap_hash_fast_t l_pkey_hash;
            dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
            dap_tsd_t *l_tsd; size_t l_tsd_size;
            dap_tsd_iter(l_tsd, l_tsd_size, a_cond->tsd, a_cond->tsd_size) {
                if (l_tsd->type == DAP_CHAIN_TX_OUT_COND_TSD_HASH && l_tsd->size == sizeof(dap_hash_fast_t) &&
                        dap_hash_fast_compare(&l_pkey_hash, (dap_hash_fast_t *)l_tsd->data) &&
                        !dap_chain_datum_tx_verify_sign(a_tx_in, l_signs_counter++))
                    l_signs_verified++;
            }
        }
        default:
            break;
        }
    }
    if (IS_ZERO_256(l_writeoff_value)) {
        log_it(L_ERROR, "Write-off value not found, can't process");
        return -6;
    }

    uint256_t l_change_value;
    if (SUBTRACT_256_256(a_cond->header.value, l_writeoff_value, &l_change_value)) {
        char *l_balance = dap_uint256_decimal_to_char(a_cond->header.value);
        const char *l_writeoff; dap_uint256_to_char(l_writeoff_value, &l_writeoff);
        log_it(L_ERROR, "Write-off value %s is greater than account balance %s", l_writeoff, l_balance);
        DAP_DELETE(l_balance);
        return -7;
    }
    if (!IS_ZERO_256(l_change_value)) {
        if (!l_cond_out) {
            log_it(L_ERROR, "Changeback on conditional output is need but not found");
            return -8;
        }
        if (compare256(l_change_value, l_cond_out->header.value) != 0) {
            char *l_change = dap_uint256_decimal_to_char(l_change_value);
            const char *l_cond_out_value; dap_uint256_to_char(l_cond_out->header.value, &l_cond_out_value);
            log_it(L_ERROR, "Changeback on conditional output is %s but not is expected %s", l_cond_out_value, l_change);
            return -9;
        }
        if (a_cond->tsd_size != l_cond_out->tsd_size ||
                memcmp(l_cond_out->tsd, a_cond->tsd, a_cond->tsd_size)) {
            log_it(L_ERROR, "Condtional output in current TX have different TSD sections vs previous TX's one");
            return -11;
        }
    } else if (l_cond_out) {
        log_it(L_ERROR, "Changeback on conditional output is not need but found");
        return -10;
    }

    if (l_signs_verified < a_cond->subtype.srv_emit_delegate.signers_minimum) {
        log_it(L_WARNING, "Not enough valid signs (%u from %u) for delegated emission",
                                    l_signs_verified, a_cond->subtype.srv_emit_delegate.signers_minimum);
        return DAP_CHAIN_CS_VERIFY_CODE_NOT_ENOUGH_SIGNS;
    }
    return 0;
}

static bool s_tag_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,  dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{   
    return a_items_grp->items_out_cond_srv_emit_delegate;
}

// Put a transaction to the mempool
static char *s_tx_put(dap_chain_datum_tx_t *a_tx, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, a_tx, l_tx_size);
    if (!l_datum) {
        log_it(L_CRITICAL, "Not enough memory");
        return NULL;
    }
    // Processing will be made according to autoprocess policy
    char *l_ret = dap_chain_mempool_datum_add(l_datum, a_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    return l_ret;
}

#define m_sign_fail(e,s) { dap_json_rpc_error_add(a_json_arr_reply, e, s); log_it(L_ERROR, "%s", s); return NULL; }

#define m_tx_fail(e,s) { DAP_DELETE(l_tx); m_sign_fail(e,s) }

static dap_chain_datum_tx_t *s_emitting_tx_create(json_object *a_json_arr_reply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key,
                                                  const char *a_token_ticker, uint256_t a_value, uint256_t a_fee,
                                                  uint32_t a_signs_min, dap_hash_fast_t *a_pkey_hashes, size_t a_pkey_hashes_count)
{
    const char *l_native_ticker = a_net->pub.native_ticker;
    bool l_delegate_native = !dap_strcmp(l_native_ticker, a_token_ticker);
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    uint256_t l_value = a_value, l_value_transfer = {}, l_fee_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t l_net_fee_addr;
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_fee_addr);
    if (l_net_fee_used && SUM_256_256(l_fee_total, l_net_fee, &l_fee_total))
        m_tx_fail(ERROR_OVERFLOW, "Integer overflow in TX composer");
    if (l_delegate_native && SUM_256_256(l_value, l_fee_total, &l_value))
        m_tx_fail(ERROR_OVERFLOW, "Integer overflow in TX composer");

    // list of transaction with 'out' items to sell
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, a_enc_key, a_net->pub.id);
    dap_list_t *l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_token_ticker,
                                                                       &l_owner_addr, l_value, &l_value_transfer);
    if (!l_list_used_out)
        m_tx_fail(ERROR_FUNDS, "Nothing to pay for delegate (not enough funds)");

    // add 'in' items to pay for delegate
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_to_items, l_value_transfer))
        m_tx_fail(ERROR_COMPOSE, "Can't compose the transaction input");

    if (!l_delegate_native) {
        dap_list_t *l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                          &l_owner_addr, l_fee_total, &l_fee_transfer);
        if (!l_list_fee_out)
            m_tx_fail(ERROR_FUNDS, "Nothing to pay for fee (not enough funds)");
        // add 'in' items to pay fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer))
            m_tx_fail(ERROR_COMPOSE, "Can't compose the fee transaction input");
    }

    // add 'out_cond' & 'out_ext' items
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_EMIT_DELEGATE_ID };
    dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_emit_delegate(
                                                l_uid, a_value, a_signs_min, a_pkey_hashes, a_pkey_hashes_count);
    if (!l_tx_out)
        m_tx_fail(ERROR_COMPOSE, "Can't compose the transaction conditional output");
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
    DAP_DELETE(l_tx_out);

    // coin back
    uint256_t l_value_back = {};
    SUBTRACT_256_256(l_value_transfer, l_value, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        int rc = l_delegate_native ? dap_chain_datum_tx_add_out_item(&l_tx, &l_owner_addr, l_value_back)
                                   : dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_value_back, a_token_ticker);
        if (rc != 1)
            m_tx_fail(ERROR_COMPOSE, "Cant add coin back output");
    }

    // add fee items
    if (l_net_fee_used) {
        int rc = l_delegate_native ? dap_chain_datum_tx_add_out_item(&l_tx, &l_net_fee_addr, l_net_fee)
                                   : dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, l_native_ticker);
        if (rc != 1)
            m_tx_fail(ERROR_COMPOSE, "Cant add net fee output");
    }
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1)
        m_tx_fail(ERROR_COMPOSE, "Cant add validator fee output");

    if (!l_delegate_native) {
        uint256_t l_fee_back = {};
        // fee coin back
        SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
        if (!IS_ZERO_256(l_fee_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_fee_back, l_native_ticker) != 1)
            m_tx_fail(ERROR_COMPOSE, "Cant add fee back output");
    }

    // add 'sign' item
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_enc_key) != 1)
        m_tx_fail(ERROR_COMPOSE, "Can't add sign output");

    return l_tx;
}

static bool s_is_key_present(dap_chain_tx_out_cond_t *a_cond, dap_enc_key_t *a_enc_key)
{
    if (!a_cond->tsd_size || !a_enc_key->pub_key_data_size)
        return false;
    dap_hash_fast_t l_pub_key_hash;
    if (dap_enc_key_get_pkey_hash(a_enc_key, &l_pub_key_hash))
        return false;
    dap_tsd_t *l_tsd; size_t l_tsd_size;
    dap_tsd_iter(l_tsd, l_tsd_size, a_cond->tsd, a_cond->tsd_size)
        if (l_tsd->type == DAP_CHAIN_TX_OUT_COND_TSD_HASH && l_tsd->size == sizeof(dap_hash_fast_t) &&
                dap_hash_fast_compare(&l_pub_key_hash, (dap_hash_fast_t *)l_tsd->data))
            return true;
    return false;
}

dap_chain_datum_tx_t *dap_chain_net_srv_emit_delegate_taking_tx_create(json_object *a_json_arr_reply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key,
                                                dap_chain_addr_t *a_addr_to, uint256_t a_value, uint256_t a_fee, dap_hash_fast_t *a_tx_in_hash)
{
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = a_net->pub.ledger;
    const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, a_tx_in_hash);
    bool l_taking_native = !dap_strcmp(a_net->pub.native_ticker, l_tx_ticker);

    uint256_t l_value = a_value, l_fee_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t l_net_fee_addr;

    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_fee_addr);
    if (l_net_fee_used && SUM_256_256(l_fee_total, l_net_fee, &l_fee_total))
        m_tx_fail(ERROR_OVERFLOW, "Integer overflow in TX composer");

    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, a_enc_key, a_net->pub.id);
    dap_list_t *l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_net->pub.native_ticker,
                                                                      &l_owner_addr, l_fee_total, &l_fee_transfer);
    if (!l_list_fee_out)
        m_tx_fail(ERROR_FUNDS, "Nothing to pay for fee (not enough funds)");
    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer))
        m_tx_fail(ERROR_COMPOSE, "Can't compose the fee transaction input");

    dap_hash_fast_t l_final_tx_hash = dap_ledger_get_final_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_EMIT_DELEGATE, a_tx_in_hash, true);
    if (dap_hash_fast_is_blank(&l_final_tx_hash))
        m_tx_fail(ERROR_FUNDS, "Nothing to emit (not enough funds)");

    log_it(L_NOTICE, "Actual TX hash with unspent output %s will be used for taking TX composing", dap_hash_fast_to_str_static(&l_final_tx_hash));
    dap_chain_datum_tx_t *l_tx_in = dap_ledger_tx_find_by_hash(l_ledger, &l_final_tx_hash);
    assert(l_tx_in);
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_cond_prev = dap_chain_datum_tx_out_cond_get(l_tx_in, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_EMIT_DELEGATE, &l_prev_cond_idx);
    if (!l_cond_prev)
        m_tx_fail(ERROR_TX_MISMATCH, "Requested conditional transaction requires conditional output");

    if (dap_ledger_tx_hash_is_used_out_item(l_ledger, &l_final_tx_hash, l_prev_cond_idx, NULL))
        m_tx_fail(ERROR_TX_MISMATCH, "Requested conditional transaction is already used out");

    if (compare256(l_cond_prev->header.value, l_value) == -1)
        m_tx_fail(ERROR_FUNDS, "Conditional output of requested TX have not enough funs");

    // add 'in_cond' item
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_final_tx_hash, l_prev_cond_idx, -1) != 1) {
        log_it(L_ERROR, "Can't compose the transaction conditional input");
        m_tx_fail(ERROR_COMPOSE, "Cant add conditionsl input");
    }

    // add 'out' or 'out_ext' item for emission
    int rc = l_taking_native ? dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to, a_value) :
                               dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, a_value, l_tx_ticker);
    if (rc != 1)
        m_tx_fail(ERROR_COMPOSE, "Cant add emission output");

    // coin back
    uint256_t l_value_back = {};
    SUBTRACT_256_256(l_cond_prev->header.value, l_value, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        dap_chain_tx_out_cond_t *l_out_cond = DAP_DUP_SIZE(l_cond_prev, sizeof(dap_chain_tx_out_cond_t) + l_cond_prev->tsd_size);
        if (!l_out_cond)
            m_tx_fail(ERROR_COMPOSE, c_error_memory_alloc);
        l_out_cond->header.value = l_value_back;
        if (-1 == dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out_cond))
            m_tx_fail(ERROR_COMPOSE, "Cant add emission cond output");
        DAP_DELETE(l_out_cond);
    }

    // add track for takeoff from conditional value
    dap_chain_tx_tsd_t *l_takeoff_tsd = dap_chain_datum_tx_item_tsd_create(&l_value, DAP_CHAIN_NET_SRV_EMIT_DELEGATE_TSD_WRITEOFF, sizeof(uint256_t));
    if (!l_takeoff_tsd || dap_chain_datum_tx_add_item(&l_tx, l_takeoff_tsd) != 1)
        m_tx_fail(ERROR_COMPOSE, "Can't add TSD section item with withdraw value");
    DAP_DELETE(l_takeoff_tsd);

    // add fee items
    if (l_net_fee_used) {
        int rc = l_taking_native ? dap_chain_datum_tx_add_out_item(&l_tx, &l_net_fee_addr, l_net_fee)
                                 : dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, a_net->pub.native_ticker);
        if (rc != 1)
            m_tx_fail(ERROR_COMPOSE, "Cant add net fee output");
    }
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1)
        m_tx_fail(ERROR_COMPOSE, "Cant add validator fee output");

    uint256_t l_fee_back = {};
    // fee coin back
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if (!IS_ZERO_256(l_fee_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_fee_back, a_net->pub.native_ticker) != 1)
        m_tx_fail(ERROR_COMPOSE, "Cant add fee back output");

    // add 'sign' item
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_enc_key) != 1)
        m_tx_fail(ERROR_COMPOSE, "Can't add sign output");

    return l_tx;
}

#undef m_tx_fail

dap_chain_datum_tx_t *dap_chain_net_srv_emit_delegate_taking_tx_sign(json_object *a_json_arr_reply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key, dap_chain_datum_tx_t *a_tx_in)
{
    int l_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_out_cond_get(a_tx_in, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_EMIT_DELEGATE, &l_cond_idx);
    if (!l_cond)
        m_sign_fail(ERROR_TX_MISMATCH, "Requested conditional transaction requires conditional output");
    if (!dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL))
        m_sign_fail(ERROR_TX_MISMATCH, "No need to sign holding TX");
    if (!s_is_key_present(l_cond, a_enc_key))
        m_sign_fail(ERROR_TX_MISMATCH, "Requested conditional transaction restrict provided sign key");
    size_t l_my_pkey_size = 0;
    byte_t *l_my_pkey = dap_enc_key_serialize_pub_key(a_enc_key, &l_my_pkey_size);
    if (!l_my_pkey)
        m_sign_fail(ERROR_COMPOSE, "Can't serialize sign public key");
    size_t l_tsd_hashes_count = l_cond->tsd_size / (sizeof(dap_tsd_t) + sizeof(dap_hash_fast_t));
    size_t l_signs_limit = l_tsd_hashes_count * 2;
    byte_t *l_item; size_t l_tx_item_size;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx_in) {
        if (*l_item != TX_ITEM_TYPE_SIG)
            continue;
        dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_item);
        size_t l_sign_pkey_size = 0;
        byte_t *l_sign_pkey = dap_sign_get_pkey(l_sign, &l_sign_pkey_size);
        if (l_sign_pkey_size == l_my_pkey_size && !memcmp(l_sign_pkey, l_my_pkey, l_my_pkey_size))
            m_sign_fail(ERROR_TX_MISMATCH, "Sign is already present in taking tx");
        if (--l_signs_limit == 0)
            m_sign_fail(ERROR_TX_MISMATCH, "Too many signs in taking tx");
    }
    dap_chain_datum_tx_t *l_tx = DAP_DUP_SIZE(a_tx_in, dap_chain_datum_tx_get_size(a_tx_in));
    if (!l_tx)
        m_sign_fail(ERROR_FUNDS, c_error_memory_alloc);
    // add 'sign' item
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_enc_key) != 1)
        m_sign_fail(ERROR_COMPOSE, "Can't add sign output");
    return l_tx;
}

#undef m_sign_fail

static int s_cli_hold(int a_argc, char **a_argv, int a_arg_index, json_object **a_json_arr_reply, dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    const char *l_token_str = NULL, *l_value_str = NULL, *l_wallet_str = NULL, *l_fee_str = NULL, *l_signs_min_str = NULL, *l_pkeys_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-token", &l_token_str);
    if (!l_token_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -token");
        return ERROR_PARAM;
    }
    if (!dap_ledger_token_ticker_check(a_net->pub.ledger, l_token_str)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Token %s not found in ledger", l_token_str);
        return ERROR_VALUE;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-value", &l_value_str);
    if (!l_value_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -value");
        return ERROR_PARAM;
    }
    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -value <256 bit integer>");
        return ERROR_VALUE;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -fee");
        return ERROR_PARAM;
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -fee <256 bit integer>");
        return ERROR_VALUE;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-signs_minimum", &l_signs_min_str);
    if (!l_signs_min_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -signs_minimum");
        return ERROR_PARAM;
    }
    uint32_t l_signs_min = atoi(l_signs_min_str);
    if (!l_signs_min) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -signs_minimum <32-bit unsigned integer>");
        return ERROR_VALUE;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -w");
        return ERROR_PARAM;
    }
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
    if (!l_wallet) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Specified wallet %s not found", l_wallet_str);
        return ERROR_VALUE;
    }
    const char *l_sign_str = dap_chain_wallet_check_sign(l_wallet);
    dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_wallet_close(l_wallet);

    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-pkey_hashes", &l_pkeys_str);
    if (!l_pkeys_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -pkey_hashes");
        return ERROR_PARAM;
    }
    size_t l_pkeys_str_size = strlen(l_pkeys_str);
    size_t l_hashes_count_max = l_pkeys_str_size / DAP_ENC_BASE58_ENCODE_SIZE(sizeof(dap_chain_hash_fast_t)),
           l_hashes_count = 0;
    dap_chain_hash_fast_t *l_pkey_hashes = DAP_NEW_Z_COUNT(dap_chain_hash_fast_t, l_hashes_count_max);
    if (!l_pkey_hashes) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_MEMORY, c_error_memory_alloc);
        DAP_DELETE(l_enc_key);
        return ERROR_MEMORY;
    }
    char l_hash_str_buf[DAP_HASH_FAST_STR_SIZE];
    const char *l_token_ptr = l_pkeys_str;
    for (size_t i = 0; i < l_hashes_count_max; i++) {
        const char *l_cur_ptr = strchr(l_token_ptr, ',');
        if (!l_cur_ptr)
            l_cur_ptr = l_pkeys_str + l_pkeys_str_size;
        dap_strncpy(l_hash_str_buf, l_token_ptr, dap_min(DAP_HASH_FAST_STR_SIZE, l_cur_ptr - l_token_ptr));
        if (dap_chain_hash_fast_from_str(l_hash_str_buf, l_pkey_hashes + i)) {
            dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Can't recognize %s as a hex or base58 format hash", l_hash_str_buf);
            DAP_DEL_MULTY(l_enc_key, l_pkey_hashes);
            return ERROR_VALUE;
        }
        if (*l_cur_ptr == 0) {
            l_hashes_count = i + 1;
            break;
        }
        l_token_ptr = l_cur_ptr + 1;
    }
    if (!l_hashes_count) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Can't recognize %s as a hex or base58 format hash", l_hash_str_buf);
        DAP_DEL_MULTY(l_enc_key, l_pkey_hashes);
        return ERROR_VALUE;
    }
    if (l_hashes_count < l_signs_min) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Quantity of pkey_hashes %zu should not be less than signs_minimum (%zu)", l_hashes_count, l_signs_min);
        DAP_DEL_MULTY(l_enc_key, l_pkey_hashes);
        return ERROR_VALUE;
    }
    // Create conditional transaction for delegated emissions
    dap_chain_datum_tx_t *l_tx = s_emitting_tx_create(*a_json_arr_reply, a_net, l_enc_key, l_token_str, l_value, l_fee, l_signs_min, l_pkey_hashes, l_hashes_count);
    DAP_DEL_MULTY(l_enc_key, l_pkey_hashes);
    if (!l_tx) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_CREATE, "Can't compose transaction for delegated emission");
        return ERROR_CREATE;
    }
    char *l_tx_hash_str = s_tx_put(l_tx, a_chain, a_hash_out_type);
    DAP_DELETE(l_tx);
    if (!l_tx_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PLACE, "Can't place transaction for delegated emission in mempool");
        return ERROR_PLACE;
    }
    json_object * l_json_obj_create_val = json_object_new_object();
    json_object_object_add(l_json_obj_create_val, "status", json_object_new_string("success"));
    if (dap_strcmp(l_sign_str, ""))
        json_object_object_add(l_json_obj_create_val, "sign", json_object_new_string(l_sign_str));
    json_object_object_add(l_json_obj_create_val, "tx_hash", json_object_new_string(l_tx_hash_str));
    json_object_array_add(*a_json_arr_reply, l_json_obj_create_val);
    DAP_DELETE(l_tx_hash_str);
    return DAP_NO_ERROR;
}

static int s_cli_take(int a_argc, char **a_argv, int a_arg_index, json_object **a_json_arr_reply, dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    const char *l_tx_in_hash_str = NULL, *l_addr_str = NULL, *l_value_str = NULL, *l_wallet_str = NULL, *l_fee_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-tx", &l_tx_in_hash_str);
    if (!l_tx_in_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation taking requires parameter -tx");
        return ERROR_PARAM;
    }
    dap_hash_fast_t l_tx_in_hash;
    if (dap_chain_hash_fast_from_str(l_tx_in_hash_str, &l_tx_in_hash)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Can't recognize %s as a hex or base58 format hash", l_tx_in_hash_str);
        return ERROR_VALUE;
    }
    if (!dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_tx_in_hash)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "TX %s not found in ledger", l_tx_in_hash_str);
        return ERROR_VALUE;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-value", &l_value_str);
    if (!l_value_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation taking requires parameter -value");
        return ERROR_PARAM;
    }
    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -value <256 bit integer>");
        return ERROR_VALUE;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation taking requires parameter -fee");
        return ERROR_PARAM;
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -fee <256 bit integer>");
        return ERROR_VALUE;
    }

    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation taking requires parameter -w");
        return ERROR_PARAM;
    }
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
    if (!l_wallet) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Specified wallet %s not found", l_wallet_str);
        return ERROR_VALUE;
    }
    const char *l_sign_str = dap_chain_wallet_check_sign(l_wallet);
    dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_wallet_close(l_wallet);
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-addr_to", &l_addr_str);
    if (!l_value_str) {
        DAP_DELETE(l_enc_key);
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation taking requires parameter -addr_to");
        return ERROR_PARAM;
    }
    dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_addr_str);
    if (!l_addr) {
        DAP_DELETE(l_enc_key);
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Incorrect addr format for string %s", l_addr_str);
        return ERROR_VALUE;
    }
     // Create emission from conditional transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_emit_delegate_taking_tx_create(*a_json_arr_reply, a_net, l_enc_key, l_addr, l_value, l_fee, &l_tx_in_hash);
    DAP_DEL_MULTY(l_enc_key, l_addr);
    if (!l_tx) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_CREATE, "Can't compose transaction for delegated emission");
        return ERROR_CREATE;
    }
    char *l_tx_hash_str = s_tx_put(l_tx, a_chain, a_hash_out_type);
    DAP_DELETE(l_tx);
    if (!l_tx_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PLACE, "Can't place transaction for delegated emission in mempool");
        return ERROR_PLACE;
    }
    json_object * l_json_obj_create_val = json_object_new_object();
    json_object_object_add(l_json_obj_create_val, "status", json_object_new_string("success"));
    if (dap_strcmp(l_sign_str, ""))
        json_object_object_add(l_json_obj_create_val, "sign", json_object_new_string(l_sign_str));
    json_object_object_add(l_json_obj_create_val, "tx_hash", json_object_new_string(l_tx_hash_str));
    json_object_array_add(*a_json_arr_reply, l_json_obj_create_val);
    DAP_DELETE(l_tx_hash_str);
    return DAP_NO_ERROR;
}

static int s_cli_sign(int a_argc, char **a_argv, int a_arg_index, json_object **a_json_arr_reply, dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    const char *l_tx_in_hash_str = NULL, *l_wallet_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-tx", &l_tx_in_hash_str);
    if (!l_tx_in_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation taking requires parameter -tx");
        return ERROR_PARAM;
    }
    dap_hash_fast_t l_tx_hash;
    if (dap_chain_hash_fast_from_str(l_tx_in_hash_str, &l_tx_hash)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Can't recognize %s as a hex or base58 format hash", l_tx_in_hash_str);
        return ERROR_VALUE;
    }
    dap_chain_datum_t *l_tx_in = dap_chain_mempool_datum_get(a_chain, l_tx_in_hash_str);
    if (!l_tx_in || l_tx_in->header.type_id != DAP_CHAIN_DATUM_TX) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "TX %s not found in mempool", l_tx_in_hash_str);
        return ERROR_VALUE;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation taking requires parameter -w");
        return ERROR_PARAM;
    }
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
    if (!l_wallet) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Specified wallet %s not found", l_wallet_str);
        return ERROR_VALUE;
    }
    const char *l_sign_str = dap_chain_wallet_check_sign(l_wallet);
    dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_wallet_close(l_wallet);

     // Create emission from conditional transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_net_srv_emit_delegate_taking_tx_sign(*a_json_arr_reply, a_net, l_enc_key, (dap_chain_datum_tx_t *)l_tx_in->data);
    DAP_DELETE(l_enc_key);
    if (!l_tx) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_CREATE, "Can't compose transaction for delegated emission");
        return ERROR_CREATE;
    }
    char *l_tx_hash_str = s_tx_put(l_tx, a_chain, a_hash_out_type);
    DAP_DELETE(l_tx);
    if (!l_tx_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PLACE, "Can't place transaction for delegated emission in mempool");
        return ERROR_PLACE;
    }
    char *l_mempool_group = dap_chain_net_get_gdb_group_mempool_new(a_chain);
    dap_global_db_del_sync(l_mempool_group, l_tx_in_hash_str);
    DAP_DELETE(l_mempool_group);
    json_object * l_json_obj_create_val = json_object_new_object();
    json_object_object_add(l_json_obj_create_val, "status", json_object_new_string("success"));
    if (dap_strcmp(l_sign_str, ""))
        json_object_object_add(l_json_obj_create_val, "sign", json_object_new_string(l_sign_str));
    json_object_object_add(l_json_obj_create_val, "tx_hash", json_object_new_string(l_tx_hash_str));
    json_object_array_add(*a_json_arr_reply, l_json_obj_create_val);
    DAP_DELETE(l_tx_hash_str);
    return DAP_NO_ERROR;
}

/**
 * @brief s_cli_stake_lock
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return
 */
static int s_cli_emit_delegate(int a_argc, char **a_argv, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    enum {
        CMD_NONE, CMD_HOLD, CMD_TAKE, CMD_SIGN
    };
    int l_arg_index = 1;
    dap_chain_net_t *l_net = NULL;
    dap_chain_t *l_chain = NULL;
    const char *l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    else if (dap_strcmp(l_hash_out_type," hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM,
                                "Invalid parameter -H, valid values: -H <hex | base58>");
        return ERROR_PARAM;
    }
    int l_err_net_chain = dap_chain_node_cli_cmd_values_parse_net_chain_for_json(*a_json_arr_reply, &l_arg_index, a_argc, a_argv, &l_chain, &l_net, CHAIN_TYPE_TX);
    if (l_err_net_chain)
        return l_err_net_chain;

    int l_cmd_num = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "hold", NULL))
        return s_cli_hold(a_argc, a_argv, l_arg_index + 1, a_json_arr_reply, l_net, l_chain, l_hash_out_type);
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "take", NULL))
        return s_cli_take(a_argc, a_argv, l_arg_index + 1, a_json_arr_reply, l_net, l_chain, l_hash_out_type);
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "sign", NULL))
        return s_cli_sign(a_argc, a_argv, l_arg_index + 1, a_json_arr_reply, l_net, l_chain, l_hash_out_type);
    else {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_SUBCOMMAND, "Subcommand %s not recognized", a_argv[l_arg_index]);
        return ERROR_SUBCOMMAND;
    }
}

int dap_chain_net_srv_emit_delegate_init()
{
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_EMIT_DELEGATE, s_emit_delegate_verificator, NULL, NULL);
    dap_cli_server_cmd_add("emit_delegate", s_cli_emit_delegate, "Emitting delegation service commands",
                "emit_delegate hold -net <net_name> -w <wallet_name> -token <ticker> -value <value> -fee <value>"
                            "-signs_minimum <value_int> -pkey_hashes <hash1[,hash2,...,hashN]> [-chain <chain_name>] [-H {hex(default) | base58}]\n"
                "emit_delegate take -net <net_name> -w <wallet_name> -tx <transaction_hash> -addr_to <addr> -value <value> -fee <value> [-chain <chain_name>] [-H {hex(default) | base58}]\n"
                "emit_delegate sign -net <net_name> -w <wallet_name> -tx <transaction_hash> [-chain <chain_name>] [-H {hex(default) | base58}]\n\n"
                            "Hint:\n"
                            "\texample value_coins (only natural) 1.0 123.4567\n"
                            "\texample value_datoshi (only integer) 1 20 0.4321e+4\n"
    );

    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_EMIT_DELEGATE_ID };
    dap_ledger_service_add(l_uid, "emit-delegate", s_tag_check);

    return 0;
}
