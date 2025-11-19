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
#include "dap_chain_wallet_shared.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_list.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_global_db.h"
#include "dap_tsd.h"
#include "dap_sign.h"
#include "dap_chain_datum_tx_items.h"
#include <dirent.h>

static char s_wallet_shared_gdb_group[] = "local.wallet_shared";
static char s_wallet_shared_gdb_pkeys[] = "local.wallet_shared_pkeys";

typedef enum hash_file_type {
    HASH_FILE_TYPE_WALLET = 0,
    HASH_FILE_TYPE_CERT = 1,
} hash_file_type_t;

typedef enum tx_role {
    TX_ROLE_CREATOR = 0,
    TX_ROLE_OWNER = 1,
} tx_role_t;

typedef struct hold_tx_hash_item {
    tx_role_t role;
    dap_hash_fast_t hash;
} hold_tx_hash_item_t;
#include "dap_chain_wallet_cache.h"


/**
 * @brief Structure for storing public key hashes collection
 * @details Used for storing multiple public key hashes with versioning support
 */
typedef struct hold_tx_hashes {
    hash_file_type_t type;  // wallet or cert
    char name[DAP_CERT_ITEM_NAME_MAX];
    size_t tx_count;               // Number of hashes in the collection
    hold_tx_hash_item_t tx[];           // Pointer to array of public key hashes
} hold_tx_hashes_t;

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
    ERROR_SUBCOMMAND,
    ERROR_NETWORK
};

#define LOG_TAG "dap_chain_wallet_shared"


static int s_wallet_shared_verificator(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx_in, bool UNUSED_ARG a_owner, bool a_check_for_apply)
{
    size_t l_tsd_hashes_count = a_cond->tsd_size / (sizeof(dap_tsd_t) + sizeof(dap_hash_fast_t));
    dap_sign_t *l_signs[l_tsd_hashes_count * 2];
    uint32_t l_signs_counter = 0, l_signs_verified = 0;
    uint256_t l_writeoff_value = uint256_0;
    dap_chain_tx_out_cond_t *l_cond_out = NULL;
    dap_chain_addr_t l_net_fee_addr;
    uint16_t l_change_type = 0;
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
            if (l_tsd->type != DAP_CHAIN_WALLET_SHARED_TSD_WRITEOFF && l_tsd->type != DAP_CHAIN_WALLET_SHARED_TSD_REFILL)
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
            l_change_type = l_tsd->type;
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
            break;
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
    if (l_change_type == DAP_CHAIN_WALLET_SHARED_TSD_WRITEOFF && SUBTRACT_256_256(a_cond->header.value, l_writeoff_value, &l_change_value)) {
        char *l_balance = dap_uint256_decimal_to_char(a_cond->header.value);
        const char *l_writeoff = NULL;
        dap_uint256_to_char(l_change_value, &l_writeoff);
        log_it(L_ERROR, "Write-off value %s is greater than account balance %s", l_writeoff, l_balance);
        DAP_DELETE(l_balance);
        return -7;
    }
    if (l_change_type == DAP_CHAIN_WALLET_SHARED_TSD_REFILL && SUM_256_256(a_cond->header.value, l_writeoff_value, &l_change_value)) {
        char *l_balance = dap_uint256_decimal_to_char(a_cond->header.value);
        const char *l_refill = NULL;
        dap_uint256_to_char(l_change_value, &l_refill);
        log_it(L_ERROR, "Sum of re-fill value %s and account balance %s is owerflow 256 bit num", l_refill, l_balance);
        DAP_DELETE(l_balance);
        return -9;
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
    }
    if (l_change_type == DAP_CHAIN_WALLET_SHARED_TSD_WRITEOFF && l_signs_verified < a_cond->subtype.wallet_shared.signers_minimum) {
        log_it(L_WARNING, "Not enough valid signs (%u from %u) for shared funds tx",
                                    l_signs_verified, a_cond->subtype.wallet_shared.signers_minimum);
        return DAP_CHAIN_CS_VERIFY_CODE_NOT_ENOUGH_SIGNS;
    }
    return 0;
}

static bool s_tag_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,  dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{   
    if (!a_items_grp->items_out_cond_wallet_shared)
        return false;
    if (a_action) {
        if (dap_chain_datum_tx_item_get_tsd_by_type(a_tx, DAP_CHAIN_WALLET_SHARED_TSD_WRITEOFF))
            *a_action = DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_TAKE;
        else if (dap_chain_datum_tx_item_get_tsd_by_type(a_tx, DAP_CHAIN_WALLET_SHARED_TSD_REFILL))
            *a_action = DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_REFILL;
        else
            *a_action = DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_HOLD;
    }
    return true;
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

#define m_tx_fail(e,s) { DAP_DELETE(l_tx); m_sign_fail(e,s); log_it(L_ERROR, "%s", s); }

static dap_chain_datum_tx_t *s_emitting_tx_create(json_object *a_json_arr_reply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key,
                                                  const char *a_token_ticker, uint256_t a_value, uint256_t a_fee,
                                                  uint32_t a_signs_min, dap_hash_fast_t *a_pkey_hashes, size_t a_pkey_hashes_count, const char *a_tag_str)
{
    const char *l_native_ticker = a_net->pub.native_ticker;
    bool l_share_native = !dap_strcmp(l_native_ticker, a_token_ticker);
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    uint256_t l_value = a_value, l_value_transfer = {}, l_fee_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t l_net_fee_addr;
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_fee_addr);
    if (l_net_fee_used && SUM_256_256(l_fee_total, l_net_fee, &l_fee_total))
        m_tx_fail(ERROR_OVERFLOW, "Integer overflow in TX composer");
    if (l_share_native && SUM_256_256(l_value, l_fee_total, &l_value))
        m_tx_fail(ERROR_OVERFLOW, "Integer overflow in TX composer");

    // list of transaction with 'out' items to sell
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, a_enc_key, a_net->pub.id);
    dap_list_t *l_list_used_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, a_token_ticker, &l_owner_addr, &l_list_used_out, l_value, &l_value_transfer))
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_token_ticker,
                                                                       &l_owner_addr, l_value, &l_value_transfer);
    if (!l_list_used_out)
        m_tx_fail(ERROR_FUNDS, "Nothing to pay for share (not enough funds)");

    // add 'in' items to pay for share
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_to_items, l_value_transfer))
        m_tx_fail(ERROR_COMPOSE, "Can't compose the transaction input");

    if (!l_share_native) {
        dap_list_t *l_list_fee_out = NULL;
        if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_native_ticker, &l_owner_addr, &l_list_fee_out, l_fee_total, &l_fee_transfer))
            l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
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
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_WALLET_SHARED_ID };
    dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_wallet_shared(
                                                l_uid, a_value, a_signs_min, a_pkey_hashes, a_pkey_hashes_count, a_tag_str);
    if (!l_tx_out)
        m_tx_fail(ERROR_COMPOSE, "Can't compose the transaction conditional output");
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
    DAP_DELETE(l_tx_out);

    // coin back
    uint256_t l_value_back = {};
    SUBTRACT_256_256(l_value_transfer, l_value, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        int rc = l_share_native ? dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_value_back, l_native_ticker)
                                   : dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_value_back, a_token_ticker);
        if (rc != 1)
            m_tx_fail(ERROR_COMPOSE, "Cant add coin back output");
    }

    // add fee items
    if (l_net_fee_used) {
        int rc = dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, l_native_ticker);
        if (rc != 1)
            m_tx_fail(ERROR_COMPOSE, "Cant add net fee output");
    }
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1)
        m_tx_fail(ERROR_COMPOSE, "Cant add validator fee output");

    if (!l_share_native) {
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

/**
 * @brief Collect public key hashes from local wallet files
 * @return 0 on success, negative value on error
 */
static int s_collect_wallet_pkey_hashes()
{
    const char *l_wallets_path = dap_chain_wallet_get_path(g_config);
    if (!l_wallets_path) {
        log_it(L_WARNING, "Wallet path not configured");
        return -2;
    }
    // Open wallet directory
    DIR *l_dir = opendir(l_wallets_path);
    if (!l_dir) {
        log_it(L_DEBUG, "Cannot open wallet directory: %s", l_wallets_path);
        return 0; // Not an error, just no wallets
    }
    
    // Count wallet files first
    size_t l_wallet_count = 0;
    struct dirent *l_dir_entry;
    while ((l_dir_entry = readdir(l_dir)) != NULL) {
        if (strstr(l_dir_entry->d_name, ".dwallet")) {
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_dir_entry->d_name, l_wallets_path, NULL);
            if (l_wallet) {
                dap_hash_fast_t l_pkey_hash;
                if (dap_chain_wallet_get_pkey_hash(l_wallet, &l_pkey_hash) != 0) {
                    log_it(L_WARNING, "Failed to get public key hash from wallet '%s/%s'", l_wallets_path, l_dir_entry->d_name);
                    continue;
                }
                hold_tx_hashes_t *l_shared_hashes = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(hold_tx_hashes_t, sizeof(hold_tx_hashes_t), -1);
                l_shared_hashes->type = HASH_FILE_TYPE_WALLET;
                dap_strncpy(l_shared_hashes->name, l_dir_entry->d_name, dap_min(sizeof(l_shared_hashes->name) - 1, strlen(l_dir_entry->d_name) - 8));
                log_it(L_DEBUG, "Added wallet '%s' hash: %s", l_dir_entry->d_name, dap_hash_fast_to_str_static(&l_pkey_hash));
                dap_global_db_set_sync(s_wallet_shared_gdb_group, dap_hash_fast_to_str_static(&l_pkey_hash), 
                    l_shared_hashes, sizeof(hold_tx_hashes_t), false);
            } else {
                log_it(L_WARNING, "Cannot open wallet '%s/%s'", l_wallets_path, l_dir_entry->d_name);
            }
        }
    }
    return 0;
}

/**
 * @brief Collect public key hashes from certificates in memory
 * @return 0 on success, negative value on error
 */
static int s_collect_cert_pkey_hashes()
{
    // Get all certificates from memory
    dap_list_t *l_certs_list = dap_cert_get_all_mem();
    if (!l_certs_list) {
        log_it(L_DEBUG, "No certificates found in memory");
        return 0;
    }
    // Extract hashes from certificates
    for (dap_list_t *l_item = l_certs_list; l_item; l_item = l_item->next) {
        dap_cert_t *l_cert = (dap_cert_t *)l_item->data;
        if (!l_cert || !l_cert->enc_key) {
            log_it(L_WARNING, "Invalid certificate or encryption key in certificate %s", l_cert->name);
            continue;
        }
        if (!l_cert->enc_key->priv_key_data_size || !l_cert->enc_key->priv_key_data) {
            log_it(L_DEBUG, "Certificate %s without private data ignored", l_cert->name);
            continue;
        }
        dap_hash_fast_t l_pkey_hash;
        if (dap_cert_get_pkey_hash(l_cert, &l_pkey_hash)) {
            log_it(L_WARNING, "Failed to get public key hash from certificate '%s'", l_cert->name);
            continue;
        }
        hold_tx_hashes_t *l_shared_hashes = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(hold_tx_hashes_t, sizeof(hold_tx_hashes_t), -1);
        l_shared_hashes->type = HASH_FILE_TYPE_CERT;
        dap_strncpy(l_shared_hashes->name, l_cert->name, dap_min(sizeof(l_shared_hashes->name) - 1, strlen(l_cert->name)));
        dap_global_db_set_sync(s_wallet_shared_gdb_group, dap_hash_fast_to_str_static(&l_pkey_hash), 
                    l_shared_hashes, sizeof(hold_tx_hashes_t), false);
        log_it(L_DEBUG, "Added certificate '%s' hash: %s", l_cert->name, dap_hash_fast_to_str_static(&l_pkey_hash));
    }  
    dap_list_free(l_certs_list);
    return 0;
}


dap_chain_datum_tx_t *dap_chain_wallet_shared_refilling_tx_create(json_object *a_json_arr_reply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key,
    uint256_t a_value, uint256_t a_fee, dap_hash_fast_t *a_tx_in_hash, dap_list_t* tsd_items)
{
    dap_return_val_if_pass(!a_net || IS_ZERO_256(a_value) || IS_ZERO_256(a_fee), NULL);
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, a_tx_in_hash);
    bool l_refill_native = !dap_strcmp(a_net->pub.native_ticker, l_tx_ticker);
    uint256_t l_value = a_value, l_value_transfer = {}, l_fee_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t l_net_fee_addr;
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_fee_addr);
    if (l_net_fee_used && SUM_256_256(l_fee_total, l_net_fee, &l_fee_total))
        m_tx_fail(ERROR_OVERFLOW, "Integer overflow in TX composer");
    if (l_refill_native && SUM_256_256(l_value, l_fee_total, &l_value))
        m_tx_fail(ERROR_OVERFLOW, "Integer overflow in TX composer");

    // list of transaction with 'out' items to sell
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, a_enc_key, a_net->pub.id);
    dap_list_t *l_list_used_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_tx_ticker, &l_owner_addr, &l_list_used_out, l_value, &l_value_transfer))
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_tx_ticker,
                                                                       &l_owner_addr, l_value, &l_value_transfer);
    if (!l_list_used_out)
        m_tx_fail(ERROR_FUNDS, "Nothing to pay for refill (not enough funds)");

    // add 'in' items to pay for share
    uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_to_items, l_value_transfer))
        m_tx_fail(ERROR_COMPOSE, "Can't compose the transaction input");

    if (!l_refill_native) {
        dap_list_t *l_list_fee_out = NULL;
        if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, a_net->pub.native_ticker, &l_owner_addr, &l_list_fee_out, l_fee_total, &l_fee_transfer))
            l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_net->pub.native_ticker,
                                                                          &l_owner_addr, l_fee_total, &l_fee_transfer);
        if (!l_list_fee_out)
            m_tx_fail(ERROR_FUNDS, "Nothing to pay for fee (not enough funds)");
        // add 'in' items to pay fee
        uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
        if (!EQUAL_256(l_value_fee_items, l_fee_transfer))
            m_tx_fail(ERROR_COMPOSE, "Can't compose the fee transaction input");
    }

    dap_hash_fast_t l_final_tx_hash = dap_ledger_get_final_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, a_tx_in_hash, false);
    if (dap_hash_fast_is_blank(&l_final_tx_hash))
        m_tx_fail(ERROR_FUNDS, "Nothing to refill, can't find tx");

    log_it(L_NOTICE, "Actual TX hash %s will be used for refill TX composing", dap_hash_fast_to_str_static(&l_final_tx_hash));
    dap_chain_datum_tx_t *l_tx_in = dap_ledger_tx_find_by_hash(l_ledger, &l_final_tx_hash);
    assert(l_tx_in);
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_cond_prev = dap_chain_datum_tx_out_cond_get(l_tx_in, DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, &l_prev_cond_idx);
    if (!l_cond_prev)
        m_tx_fail(ERROR_TX_MISMATCH, "Requested conditional transaction requires conditional output");

    if (dap_ledger_tx_hash_is_used_out_item(l_ledger, &l_final_tx_hash, l_prev_cond_idx, NULL))
        m_tx_fail(ERROR_TX_MISMATCH, "Requested conditional transaction is already used out");

    // add 'in_cond' item
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_final_tx_hash, l_prev_cond_idx, -1) != 1) {
        log_it(L_ERROR, "Can't compose the transaction conditional input");
        m_tx_fail(ERROR_COMPOSE, "Cant add conditionsl input");
    }

    uint256_t l_value_back = {};
    if(SUM_256_256(l_cond_prev->header.value, a_value, &l_value_back)) {
        m_tx_fail(ERROR_OVERFLOW, "Integer overflow in TX composer");
    }

    dap_chain_tx_out_cond_t *l_out_cond = DAP_DUP_SIZE(l_cond_prev, sizeof(dap_chain_tx_out_cond_t) + l_cond_prev->tsd_size);
    if (!l_out_cond)
        m_tx_fail(ERROR_MEMORY, c_error_memory_alloc);
    l_out_cond->header.value = l_value_back;
    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out_cond) < 0) {
        m_tx_fail(ERROR_COMPOSE, "Cant add refill cond output");
        DAP_DELETE(l_out_cond);
    }
    DAP_DELETE(l_out_cond);

    // add track for refill from conditional value
    dap_chain_tx_tsd_t *l_refill_tsd = dap_chain_datum_tx_item_tsd_create(&a_value, DAP_CHAIN_WALLET_SHARED_TSD_REFILL, sizeof(uint256_t));
    if (dap_chain_datum_tx_add_item(&l_tx, l_refill_tsd) != 1) {
        DAP_DELETE(l_refill_tsd);
        m_tx_fail(ERROR_COMPOSE, "Can't add TSD section item with withdraw value");
    }
    DAP_DELETE(l_refill_tsd);

    //add other tsd if available
    for ( dap_list_t *l_tsd = tsd_items; l_tsd; l_tsd = l_tsd->next ) {
        if ( dap_chain_datum_tx_add_item(&l_tx, l_tsd->data) != 1 )
        m_tx_fail(ERROR_COMPOSE, "Can't add custom TSD section item ");
    }

    // coin back
    SUBTRACT_256_256(l_value_transfer, l_value, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        int rc = l_refill_native ? dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_value_back, a_net->pub.native_ticker)
                                   : dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_value_back, l_tx_ticker);
        if (rc != 1)
            m_tx_fail(ERROR_COMPOSE, "Cant add coin back output");
    }

    // add fee items
    if (l_net_fee_used) {
        int rc = dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, a_net->pub.native_ticker);
        if (rc != 1)
            m_tx_fail(ERROR_COMPOSE, "Cant add net fee output");
    }
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1)
        m_tx_fail(ERROR_COMPOSE, "Cant add validator fee output");

    if (!l_refill_native) {
        uint256_t l_fee_back = {};
        // fee coin back
        SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
        if (!IS_ZERO_256(l_fee_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_fee_back, a_net->pub.native_ticker) != 1)
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

dap_chain_datum_tx_t *dap_chain_wallet_shared_taking_tx_create(json_object *a_json_arr_reply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key,
    dap_chain_addr_t *a_to_addr, uint256_t *a_value, uint32_t a_addr_count /*!not change type!*/, uint256_t a_fee, dap_hash_fast_t *a_tx_in_hash, dap_list_t* tsd_items)
{
    dap_return_val_if_pass(!a_to_addr, NULL);
    dap_return_val_if_pass(!a_value, NULL);
    dap_return_val_if_pass(!a_addr_count, NULL);
    dap_return_val_if_pass(!a_enc_key, NULL);
    dap_return_val_if_pass(!a_tx_in_hash, NULL);
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();

    dap_ledger_t *l_ledger = a_net->pub.ledger;
    const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, a_tx_in_hash);
    bool l_taking_native = !dap_strcmp(a_net->pub.native_ticker, l_tx_ticker);

    uint256_t l_value = {}, l_fee_transfer = {}; // how many coins to transfer
    uint256_t l_net_fee, l_fee_total = a_fee;
    dap_chain_addr_t l_net_fee_addr;

    for (size_t i = 0; i < a_addr_count; ++i) {
        if(IS_ZERO_256(a_value[i])) {
            m_tx_fail(ERROR_VALUE, "Format -value <256 bit integer> and not equal zero");
        }
        if (SUM_256_256(l_value, a_value[i], &l_value))
            m_tx_fail(ERROR_OVERFLOW, "Integer overflow in TX composer");
    }

    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_fee_addr);
    if (l_net_fee_used && SUM_256_256(l_fee_total, l_net_fee, &l_fee_total))
        m_tx_fail(ERROR_OVERFLOW, "Integer overflow in TX composer");

    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, a_enc_key, a_net->pub.id);
    dap_list_t *l_list_fee_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, a_net->pub.native_ticker, &l_owner_addr, &l_list_fee_out, l_fee_total, &l_fee_transfer))
        l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_net->pub.native_ticker,
                        &l_owner_addr, l_fee_total, &l_fee_transfer);
    if (!l_list_fee_out)
        m_tx_fail(ERROR_FUNDS, "Nothing to pay for fee (not enough funds)");
    // add 'in' items to pay fee
    uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
    dap_list_free_full(l_list_fee_out, NULL);
    if (!EQUAL_256(l_value_fee_items, l_fee_transfer))
        m_tx_fail(ERROR_COMPOSE, "Can't compose the fee transaction input");

    dap_hash_fast_t l_final_tx_hash = dap_ledger_get_final_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, a_tx_in_hash, true);
    if (dap_hash_fast_is_blank(&l_final_tx_hash))
        m_tx_fail(ERROR_FUNDS, "Nothing to emit (not enough funds)");

    log_it(L_NOTICE, "Actual TX hash with unspent output %s will be used for taking TX composing", dap_hash_fast_to_str_static(&l_final_tx_hash));
    dap_chain_datum_tx_t *l_tx_in = dap_ledger_tx_find_by_hash(l_ledger, &l_final_tx_hash);
    assert(l_tx_in);
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_cond_prev = dap_chain_datum_tx_out_cond_get(l_tx_in, DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, &l_prev_cond_idx);
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
    for (size_t i = 0; i < a_addr_count; ++i) {
        int rc = l_taking_native ? dap_chain_datum_tx_add_out_ext_item(&l_tx, a_to_addr + i, a_value[i], a_net->pub.native_ticker) :
            dap_chain_datum_tx_add_out_ext_item(&l_tx, a_to_addr + i, a_value[i], l_tx_ticker);
        if (rc != 1)
            m_tx_fail(ERROR_COMPOSE, "Cant add tx output");
    }

    // coin back
    uint256_t l_value_back = {};
    SUBTRACT_256_256(l_cond_prev->header.value, l_value, &l_value_back);
    dap_chain_tx_out_cond_t *l_out_cond = DAP_DUP_SIZE(l_cond_prev, sizeof(dap_chain_tx_out_cond_t) + l_cond_prev->tsd_size);
    if (!l_out_cond)
        m_tx_fail(ERROR_MEMORY, c_error_memory_alloc);
    l_out_cond->header.value = l_value_back;
    
    if (-1 == dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out_cond)) {
        DAP_DELETE(l_out_cond);
        m_tx_fail(ERROR_COMPOSE, "Cant add emission cond output");
    }
    DAP_DELETE(l_out_cond);

    if (a_addr_count > 1) {
        dap_chain_tx_tsd_t * l_addr_cnt_tsd = dap_chain_datum_tx_item_tsd_create(&a_addr_count, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT, sizeof(uint32_t));
        if (!l_addr_cnt_tsd || dap_chain_datum_tx_add_item(&l_tx, l_addr_cnt_tsd) != 1 )
            m_tx_fail(ERROR_COMPOSE, "Can't add TSD section item with addr count");
    }

    // add track for takeoff from conditional value
    dap_chain_tx_tsd_t *l_takeoff_tsd = dap_chain_datum_tx_item_tsd_create(&l_value, DAP_CHAIN_WALLET_SHARED_TSD_WRITEOFF, sizeof(uint256_t));
    if (!l_takeoff_tsd || dap_chain_datum_tx_add_item(&l_tx, l_takeoff_tsd) != 1)
        m_tx_fail(ERROR_COMPOSE, "Can't add TSD section item with withdraw value");
    DAP_DELETE(l_takeoff_tsd);

    //add other tsd if available
    for ( dap_list_t *l_tsd = tsd_items; l_tsd; l_tsd = l_tsd->next ) {
        if ( dap_chain_datum_tx_add_item(&l_tx, l_tsd->data) != 1 )
            m_tx_fail(ERROR_COMPOSE, "Can't add custom TSD section item ");
    }

    // add fee items
    if (l_net_fee_used) {
        int rc = dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, a_net->pub.native_ticker);
        if (rc != 1)
            m_tx_fail(ERROR_COMPOSE, "Cant add net fee output");
    }
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1)
        m_tx_fail(ERROR_COMPOSE, "Cant add validator fee output");

    uint256_t l_fee_back = {};
    // fee coin back
    SUBTRACT_256_256(l_fee_transfer, l_fee_total, &l_fee_back);
    if (!IS_ZERO_256(l_fee_back)) {
        int rc = dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_fee_back, a_net->pub.native_ticker);
        if (rc != 1)
            m_tx_fail(ERROR_COMPOSE, "Cant add fee back output");
    }

    // add 'sign' item
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_enc_key) != 1)
        m_tx_fail(ERROR_COMPOSE, "Can't add sign output");

    return l_tx;
}


#undef m_tx_fail

dap_chain_datum_tx_t *dap_chain_wallet_shared_taking_tx_sign(json_object *a_json_arr_reply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key, dap_chain_datum_tx_t *a_tx_in)
{
    int l_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_out_cond_get(a_tx_in, DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, &l_cond_idx);
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
        m_sign_fail(ERROR_MEMORY, c_error_memory_alloc);
    // add 'sign' item
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_enc_key) != 1)
        m_sign_fail(ERROR_COMPOSE, "Can't add sign output");
    return l_tx;
}

#undef m_sign_fail

static int s_cli_hold(int a_argc, char **a_argv, int a_arg_index, json_object **a_json_arr_reply, dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    const char *l_token_str = NULL, 
                *l_value_str = NULL, 
                *l_wallet_str = NULL, 
                *l_fee_str = NULL, 
                *l_signs_min_str = NULL, 
                *l_pkeys_str = NULL,
                *l_tag_str = NULL;

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
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -fee");
        return ERROR_PARAM;
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -fee <256 bit integer> and not equal zer");
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

    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-tag", &l_tag_str);

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
        for (size_t j = 0; j < i; ++j) {
            if (!memcmp(l_pkey_hashes + j, l_pkey_hashes + i, sizeof(dap_chain_hash_fast_t))){
                dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Find pkey hash %s dublicate", l_hash_str_buf);
                DAP_DEL_MULTY(l_enc_key, l_pkey_hashes);
                return ERROR_VALUE;
            }
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
    // Create conditional transaction for shared fundss
    dap_chain_datum_tx_t *l_tx = s_emitting_tx_create(*a_json_arr_reply, a_net, l_enc_key, l_token_str, l_value, l_fee, l_signs_min, l_pkey_hashes, l_hashes_count, l_tag_str);
    DAP_DEL_MULTY(l_enc_key, l_pkey_hashes);
    if (!l_tx) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_CREATE, "Can't compose transaction for shared funds");
        return ERROR_CREATE;
    }
    char *l_tx_hash_str = s_tx_put(l_tx, a_chain, a_hash_out_type);
    DAP_DELETE(l_tx);
    if (!l_tx_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PLACE, "Can't place transaction for shared funds in mempool");
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

static int s_cli_refill(int a_argc, char **a_argv, int a_arg_index, json_object **a_json_arr_reply, dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    const char *l_token_str = NULL, *l_value_str = NULL, *l_wallet_str = NULL, *l_fee_str = NULL, *l_tx_in_hash_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-value", &l_value_str);
    if (!l_value_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Refill command requires parameter -value");
        return ERROR_PARAM;
    }
    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -value <256 bit integer> and not equal zero");
        return ERROR_VALUE;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Refill command requires parameter -fee");
        return ERROR_PARAM;
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -fee <256 bit integer> and not equal zer");
        return ERROR_VALUE;
    }

    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Refill command requires parameter -w");
        return ERROR_PARAM;
    }

    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-tx", &l_tx_in_hash_str);
    if (!l_tx_in_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Refill command requires parameter -tx");
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


    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
    if (!l_wallet) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Specified wallet %s not found", l_wallet_str);
        return ERROR_VALUE;
    }
    const char *l_sign_str = dap_chain_wallet_check_sign(l_wallet);
    dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_wallet_close(l_wallet);

    // Create conditional transaction for refill
    dap_chain_datum_tx_t *l_tx = dap_chain_wallet_shared_refilling_tx_create(*a_json_arr_reply, a_net, l_enc_key, l_value, l_fee, &l_tx_in_hash, NULL);
    DAP_DELETE(l_enc_key);
    if (!l_tx) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_CREATE, "Can't compose transaction for refill shared funds tx");
        return ERROR_CREATE;
    }
    char *l_tx_hash_str = s_tx_put(l_tx, a_chain, a_hash_out_type);
    DAP_DELETE(l_tx);
    if (!l_tx_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PLACE, "Can't place transaction for refill shared funds tx in mempool");
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
    
    uint256_t *l_value = NULL;
    dap_chain_addr_t *l_to_addr = NULL;
    uint32_t
        l_addr_el_count = 0,  // not change type! use in batching TSD section
        l_value_el_count = 0;
    dap_list_t *l_tsd_list = NULL;
    
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

    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation taking requires parameter -fee");
        return ERROR_PARAM;
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -fee <256 bit integer> and not equal zer");
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

    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-value", &l_value_str);
    if (!l_value_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation taking requires parameter -value");
        return ERROR_PARAM;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-to_addr", &l_addr_str);
    if (!l_addr_str) {
        dap_enc_key_delete(l_enc_key);
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation taking requires parameter -to_addr");
        return ERROR_PARAM;
    }

    l_addr_el_count = dap_chain_addr_from_str_array(l_addr_str, &l_to_addr);
    l_value_el_count = dap_str_symbol_count(l_value_str, ',') + 1;

    if (l_addr_el_count != l_value_el_count) {
        DAP_DELETE(l_to_addr);
        dap_enc_key_delete(l_enc_key);
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "num of '-to_addr' and '-value' should be equal");
        return ERROR_VALUE;
    }

    l_value = DAP_NEW_Z_COUNT(uint256_t, l_value_el_count);
    if (!l_value) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_MEMORY, c_error_memory_alloc);
        DAP_DELETE(l_to_addr);
        dap_enc_key_delete(l_enc_key);
        return ERROR_MEMORY;
    }
    char **l_value_array = dap_strsplit(l_value_str, ",", l_value_el_count);
    if (!l_value_array) {
        DAP_DELETE(l_value);
        DAP_DELETE(l_to_addr);
        dap_enc_key_delete(l_enc_key);
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Can't read '-to_addr' arg");
        return ERROR_PARAM;
    }
    for (size_t i = 0; i < l_value_el_count; ++i) {
        l_value[i] = dap_chain_balance_scan(l_value_array[i]);
        if(IS_ZERO_256(l_value[i])) {
            DAP_DELETE(l_value);
            DAP_DELETE(l_to_addr);
            dap_strfreev(l_value_array);
            dap_enc_key_delete(l_enc_key);
            dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -value <256 bit integer> and not equal zero");
            return ERROR_VALUE;
        }
    }
    dap_strfreev(l_value_array);

    // Create emission from conditional transaction
    
    dap_chain_datum_tx_t *l_tx = dap_chain_wallet_shared_taking_tx_create(*a_json_arr_reply, a_net, l_enc_key, l_to_addr, l_value, l_addr_el_count, l_fee, &l_tx_in_hash, l_tsd_list);
    DAP_DEL_MULTY(l_value, l_to_addr);
    dap_enc_key_delete(l_enc_key);
    dap_list_free_full(l_tsd_list, NULL);
    if (!l_tx) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_CREATE, "Can't compose transaction for shared funds");
        return ERROR_CREATE;
    }
    char *l_tx_hash_str = s_tx_put(l_tx, a_chain, a_hash_out_type);
    DAP_DELETE(l_tx);
    if (!l_tx_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PLACE, "Can't place transaction for shared funds in mempool");
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
    const char *l_tx_in_hash_str = NULL, *l_wallet_str = NULL, *l_cert_str = NULL;
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

    dap_enc_key_t *l_enc_key = NULL;
    const char *l_sign_str = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-w", &l_wallet_str);
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-cert", &l_cert_str);
    if (!l_wallet_str && !l_cert_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation sign requires parameter -w or -cert");
        return ERROR_PARAM;
    }
    if (l_wallet_str) {
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
        if (!l_wallet) {
            dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Specified wallet %s not found", l_wallet_str);
            return ERROR_VALUE;
        }
        l_sign_str = dap_chain_wallet_check_sign(l_wallet);
        l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
        dap_chain_wallet_close(l_wallet);
    } else if (l_cert_str) {
        dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
        if (!l_cert) {
            dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Specified certificate %s not found", l_cert_str);
            return ERROR_VALUE;
        }
        if (dap_sign_type_is_deprecated(dap_sign_type_from_key_type(l_cert->enc_key->type)))
            l_sign_str = "The Bliss, Picnic and Tesla signatures is deprecated. We recommend you to create a new wallet with another available signature and transfer funds there.\n";
        else
            l_sign_str = "";
        l_enc_key = dap_cert_get_keys_from_certs(&l_cert, 1, 0);
    }

     // Create emission from conditional transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_wallet_shared_taking_tx_sign(*a_json_arr_reply, a_net, l_enc_key, (dap_chain_datum_tx_t *)l_tx_in->data);
    DAP_DELETE(l_enc_key);
    if (!l_tx) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_CREATE, "Can't compose transaction for shared funds");
        return ERROR_CREATE;
    }
    char *l_tx_hash_str = s_tx_put(l_tx, a_chain, a_hash_out_type);
    DAP_DELETE(l_tx);
    if (!l_tx_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PLACE, "Can't place transaction for shared funds in mempool");
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

int dap_chain_shared_tx_find_in_mempool(dap_chain_t *a_chain, dap_hash_fast_t *a_final_tx_hash, json_object *a_jobj_waiting_operations_hashes) {
    int l_waiting_operations_count = 0;
    char *l_mempool_group = dap_chain_net_get_gdb_group_mempool_new(a_chain);
    size_t l_objs_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_mempool_group, &l_objs_count);
    DAP_DELETE(l_mempool_group);

    for (size_t i = 0; i < l_objs_count; ++i) {
        if (!l_objs[i].value || l_objs[i].value_len < sizeof(dap_chain_datum_t))
            continue;
            
        dap_chain_datum_t *l_datum = (dap_chain_datum_t *)l_objs[i].value;
        if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
            continue;
            
        dap_chain_datum_tx_t *l_tx_mempool = (dap_chain_datum_tx_t *)l_datum->data;
        bool l_found_matching_input = false;
        
        // Check if transaction has conditional input referencing our output
        byte_t *l_item; 
        size_t l_item_size;
        TX_ITEM_ITER_TX(l_item, l_item_size, l_tx_mempool) {
            if (*l_item == TX_ITEM_TYPE_IN_COND) {
                dap_chain_tx_in_cond_t *l_in_cond = (dap_chain_tx_in_cond_t *)l_item;
                if (
                    dap_hash_fast_compare(&l_in_cond->header.tx_prev_hash, a_final_tx_hash) &&
                    dap_chain_datum_tx_item_get_tsd_by_type(l_tx_mempool, DAP_CHAIN_WALLET_SHARED_TSD_WRITEOFF)
                ) {
                    l_found_matching_input = true;
                    break;
                }
            }
        }
        
        if (l_found_matching_input) {
            dap_hash_fast_t l_tx_hash = dap_chain_node_datum_tx_calc_hash(l_tx_mempool);
            json_object_array_add(a_jobj_waiting_operations_hashes, json_object_new_string(dap_hash_fast_to_str_static(&l_tx_hash)));
            ++l_waiting_operations_count;
        }
    }
    dap_global_db_objs_delete(l_objs, l_objs_count);
    return l_waiting_operations_count;
}

static int s_cli_info(int a_argc, char **a_argv, int a_arg_index, json_object **a_json_arr_reply, dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    const char *l_tx_hash_str = NULL, *l_wallet_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-tx", &l_tx_hash_str);
    if (!l_tx_hash_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation taking requires parameter -tx");
        return ERROR_PARAM;
    }
    dap_hash_fast_t l_tx_hash;
    if (dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Can't recognize %s as a hex or base58 format hash", l_tx_hash_str);
        return ERROR_VALUE;
    }
    dap_hash_fast_t l_final_tx_hash = dap_ledger_get_final_chain_tx_hash(a_net->pub.ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, &l_tx_hash, false);
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_final_tx_hash);
    if (!l_tx) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_TX_MISMATCH, "Can't find final datum %s", dap_hash_fast_to_str_static(&l_final_tx_hash));
        return ERROR_TX_MISMATCH;
    }
    dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, NULL);
    if (!l_cond) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_TX_MISMATCH, "Can't find final tx_out_cond");
        return ERROR_TX_MISMATCH;
    }

    const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &l_final_tx_hash);
    const char *l_balance_coins, *l_balance_datoshi = dap_uint256_to_char(l_cond->header.value, &l_balance_coins);
    
    // Search for mempool transactions with conditional inputs referencing this output
    json_object *l_jobj_waiting_operations_hashes = json_object_new_array();
    int l_waiting_operations_count = dap_chain_shared_tx_find_in_mempool(a_chain, &l_final_tx_hash, l_jobj_waiting_operations_hashes);
    
    json_object *l_jobj_balance = json_object_new_object();
    json_object *l_jobj_token = json_object_new_object();
    json_object *l_jobj_take_verify = json_object_new_object();
    json_object *l_jobj_pkey_hashes = json_object_new_array();
    json_object *l_jobj_tags = json_object_new_array();
    json_object *l_json_jobj_info = json_object_new_object();

    bool l_is_base_hash_type = dap_strcmp(a_hash_out_type, "hex");
    // token block
    const char *l_description = dap_ledger_get_description_by_ticker(a_net->pub.ledger, l_tx_ticker);
    json_object *l_jobj_description = l_description ? json_object_new_string(l_description)
                                                    : json_object_new_null();
    json_object_object_add(l_jobj_token, "ticker", json_object_new_string(l_tx_ticker));
    json_object_object_add(l_jobj_token, "description", l_jobj_description);
    // balance block
    json_object_object_add(l_jobj_balance, "coins", json_object_new_string(l_balance_coins));
    json_object_object_add(l_jobj_balance, "datoshi", json_object_new_string(l_balance_datoshi));
    // verify block
    json_object_object_add(l_jobj_take_verify, "signs_minimum", json_object_new_uint64(l_cond->subtype.wallet_shared.signers_minimum));
    dap_tsd_t *l_tsd = NULL; size_t l_tsd_size = 0;
    dap_tsd_iter(l_tsd, l_tsd_size, l_cond->tsd, l_cond->tsd_size) {
        if (l_tsd->type == DAP_CHAIN_TX_OUT_COND_TSD_HASH && l_tsd->size == sizeof(dap_hash_fast_t)) {
            json_object_array_add(l_jobj_pkey_hashes, json_object_new_string(l_is_base_hash_type ? dap_enc_base58_encode_hash_to_str_static((const dap_chain_hash_fast_t *)l_tsd->data) : dap_hash_fast_to_str_static((const dap_chain_hash_fast_t *)l_tsd->data)));
        }
        if (l_tsd->type == DAP_CHAIN_TX_OUT_COND_TSD_STR) {
            json_object_array_add(l_jobj_tags, json_object_new_string((char*)(l_tsd->data)));
        }
    }
    json_object_object_add(l_jobj_take_verify, "owner_hashes", l_jobj_pkey_hashes);
    // result block
    dap_hash_fast_t l_creator_hash = {0};
    dap_sign_t *l_sig = dap_chain_datum_tx_get_sign(l_tx, 0);
    dap_sign_get_pkey_hash(l_sig, &l_creator_hash);
    json_object_object_add(l_json_jobj_info, "tx_hash", json_object_new_string(l_is_base_hash_type ? dap_enc_base58_encode_hash_to_str_static(&l_tx_hash) : dap_hash_fast_to_str_static(&l_tx_hash)));
    json_object_object_add(l_json_jobj_info, "tx_hash_final", json_object_new_string(l_is_base_hash_type ? dap_enc_base58_encode_hash_to_str_static(&l_final_tx_hash) : dap_hash_fast_to_str_static(&l_final_tx_hash)));
    json_object_object_add(l_json_jobj_info, "tags", l_jobj_tags);
    json_object_object_add(l_json_jobj_info, "balance", l_jobj_balance);
    json_object_object_add(l_json_jobj_info, "token", l_jobj_token);
    json_object_object_add(l_json_jobj_info, "creator", json_object_new_string(l_is_base_hash_type ? dap_enc_base58_encode_hash_to_str_static(&l_creator_hash) : dap_hash_fast_to_str_static(&l_creator_hash)));
    json_object_object_add(l_json_jobj_info, "take_verify", l_jobj_take_verify);
    json_object_object_add(l_json_jobj_info, "waiting_operations_count", json_object_new_int(l_waiting_operations_count));
    json_object_object_add(l_json_jobj_info, "waiting_operations_hashes", l_jobj_waiting_operations_hashes);
    
    json_object_array_add(*a_json_arr_reply, l_json_jobj_info);
    return DAP_NO_ERROR;
}

/**
 * @brief s_cli_list - List wallet shared public key hashes from GDB
 * @details By default shows only valid pkey_hashes structures. With -all shows all entries.
 *          Supports filtering by public key hash (-pkey), address (-addr), wallet (-w), or certificate (-cert).
 *          These filter parameters are mutually exclusive.
 * @param a_argc
 * @param a_argv
 * @param a_arg_index
 * @param a_json_arr_reply
 * @param a_net
 * @param a_chain
 * @param a_hash_out_type
 * @return
 */
static int s_cli_list(int a_argc, char **a_argv, int a_arg_index, json_object **a_json_arr_reply, dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    const char *l_pkey_hash_str = NULL;
    const char *l_addr_str = NULL;
    const char *l_wallet_name = NULL;
    const char *l_cert_name = NULL;
    const char *l_net_name = NULL;
    
    // Check for optional filter parameters
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-pkey", &l_pkey_hash_str);
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-addr", &l_addr_str);
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-w", &l_wallet_name);
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-cert", &l_cert_name);
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-net", &l_net_name);
    bool l_local = dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-local", NULL);

    // Check for mutually exclusive parameters
    int l_filter_count = (bool)l_pkey_hash_str + (bool)l_addr_str + (bool)l_wallet_name + (bool)l_cert_name;
    if (l_filter_count > 1) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, 
            "Parameters -pkey, -addr, -w, and -cert are mutually exclusive");
        return ERROR_PARAM;
    }

    dap_chain_net_t *l_net = NULL;
    if (l_net_name && !(l_net = dap_chain_net_by_name(l_net_name)) ) { // Can't find such network
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Network %s not found", l_net_name);
        return ERROR_PARAM;
    }
    
    dap_hash_fast_t l_pkey_hash = {0};
    
    // Process different filter types
    if (l_pkey_hash_str) {
        if (dap_chain_hash_fast_from_str(l_pkey_hash_str, &l_pkey_hash)) {
            dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, 
                "Can't recognize %s as a hex format public key hash", l_pkey_hash_str);
            return ERROR_VALUE;
        }
    } else if (l_addr_str) {
        // Convert address to public key hash
        dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_addr_str);
        if (!l_addr) {
            dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, 
                "Can't parse address %s", l_addr_str);
            return ERROR_VALUE;
        }
        // Extract public key hash from address
        memcpy(&l_pkey_hash, &l_addr->data.hash, sizeof(dap_hash_fast_t));
        DAP_DELETE(l_addr);
    } else if (l_wallet_name) {
        // Get public key hash from wallet
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_name, 
            dap_chain_wallet_get_path(g_config), NULL);
        if (!l_wallet) {
            dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, 
                "Can't open wallet %s", l_wallet_name);
            return ERROR_VALUE;
        }
        
        dap_hash_fast_t l_wallet_pkey_hash = {0};         
        if (dap_chain_wallet_get_pkey_hash(l_wallet, &l_wallet_pkey_hash)) {
            dap_chain_wallet_close(l_wallet);
            dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, 
                "Can't get public key hash from wallet %s", l_wallet_name);
            return ERROR_VALUE;
        }
        
        l_pkey_hash = l_wallet_pkey_hash;
        dap_chain_wallet_close(l_wallet);
    } else if (l_cert_name) {
        // Get public key hash from certificate
        dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_name);
        if (!l_cert) {
            dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, 
                "Can't find certificate %s", l_cert_name);
            return ERROR_VALUE;
        }
        
        if (!l_cert->enc_key) {
            dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, 
                "Certificate %s has no encryption key", l_cert_name);
            return ERROR_VALUE;
        }
        
        if (dap_enc_key_get_pkey_hash(l_cert->enc_key, &l_pkey_hash) != 0) {
            dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, 
                "Can't get public key hash from certificate %s", l_cert_name);
            return ERROR_VALUE;
        }
    }
    
    // Read wallet shared pkey hashes from GDB
    size_t l_values_count = 0;
    dap_store_obj_t *l_values = NULL;
    if (l_filter_count) {
        l_values_count = 1;
    } else if (l_local) {
        l_values = dap_global_db_get_all_raw_sync(s_wallet_shared_gdb_group, &l_values_count);
    } else {
        l_values = dap_global_db_get_all_raw_sync(s_wallet_shared_gdb_pkeys, &l_values_count);
    }
    if (!l_values_count) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, 
            "No wallet shared data found in GDB group %s", s_wallet_shared_gdb_group);
        return ERROR_VALUE;
    }
    dap_list_t *l_groups_list = dap_global_db_driver_get_groups_by_mask(s_wallet_shared_gdb_group);
    if (!l_groups_list) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Can't get groups from GDB bymask %s", s_wallet_shared_gdb_group);
        return ERROR_VALUE;
    }

    for (size_t i = 0; i < l_values_count; i++) {
        json_object *l_jobj_item = json_object_new_object();
        if (!l_filter_count) {
            json_object_object_add(l_jobj_item, "pkey_hash", json_object_new_string(l_values[i].key));
        } else {
            json_object_object_add(l_jobj_item, "pkey_hash", json_object_new_string(dap_hash_fast_to_str_static(&l_pkey_hash)));
        }
        json_object *l_jobj_nets_hashes = json_object_new_object();
        for (dap_list_t *l_item = l_groups_list; l_item; l_item = l_item->next) {
            if (!dap_strcmp(l_item->data, s_wallet_shared_gdb_group))
                continue;
            if (l_net && dap_strcmp((char *)l_item->data + sizeof(s_wallet_shared_gdb_group), l_net_name))
                continue;
            hold_tx_hashes_t *l_hold_hashes_by_name = (hold_tx_hashes_t *)dap_global_db_get_sync(l_item->data, l_filter_count ? dap_hash_fast_to_str_static(&l_pkey_hash) : l_values[i].key, NULL, NULL, NULL);
            if (l_hold_hashes_by_name) {
                json_object *l_jobj_owned_tx = json_object_new_array();
                for (size_t j = 0; j < l_hold_hashes_by_name->tx_count; j++) {
                    if (l_hold_hashes_by_name->tx[j].role == TX_ROLE_OWNER)
                        json_object_array_add(l_jobj_owned_tx, json_object_new_string(dap_hash_fast_to_str_static(&l_hold_hashes_by_name->tx[j].hash)));
                }
                json_object_object_add(l_jobj_nets_hashes, (char *)l_item->data + sizeof(s_wallet_shared_gdb_group), l_jobj_owned_tx);
            }
        }
        json_object_object_add(l_jobj_item, "tx_hashes", l_jobj_nets_hashes);
        json_object_array_add(*a_json_arr_reply, l_jobj_item);
    }
    dap_store_obj_free(l_values, l_values_count);
    DAP_DELETE(l_groups_list);
    return DAP_NO_ERROR;
}


/**
 * @brief s_cli_stake_lock
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return
 */
int dap_chain_wallet_shared_cli(int a_argc, char **a_argv, void **a_str_reply, UNUSED_ARG int a_version)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    int l_arg_index = 2;
    dap_chain_net_t *l_net = NULL;
    dap_chain_t *l_chain = NULL;
    const char *l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    else if (dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM,
                                "Invalid parameter -H, valid values: -H <hex | base58>");
        return ERROR_PARAM;
    }

    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "list", NULL))
        return s_cli_list(a_argc, a_argv, l_arg_index + 1, a_json_arr_reply, NULL, NULL, l_hash_out_type);

    int l_err_net_chain = dap_chain_node_cli_cmd_values_parse_net_chain_for_json(*a_json_arr_reply, &l_arg_index, a_argc, a_argv, &l_chain, &l_net, CHAIN_TYPE_TX);
    if (l_err_net_chain)
        return l_err_net_chain;

    if (dap_chain_net_get_load_mode(l_net)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_NETWORK, "Can't apply command while network in load mode");
        return ERROR_NETWORK;
    }

    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "hold", NULL))
        return s_cli_hold(a_argc, a_argv, l_arg_index + 1, a_json_arr_reply, l_net, l_chain, l_hash_out_type);
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "refill", NULL))
        return s_cli_refill(a_argc, a_argv, l_arg_index + 1, a_json_arr_reply, l_net, l_chain, l_hash_out_type);
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "take", NULL))
        return s_cli_take(a_argc, a_argv, l_arg_index + 1, a_json_arr_reply, l_net, l_chain, l_hash_out_type);
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "sign", NULL))
        return s_cli_sign(a_argc, a_argv, l_arg_index + 1, a_json_arr_reply, l_net, l_chain, l_hash_out_type);
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "info", NULL))
        return s_cli_info(a_argc, a_argv, l_arg_index + 1, a_json_arr_reply, l_net, l_chain, l_hash_out_type);
    else {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_SUBCOMMAND, "Subcommand %s not recognized", a_argv[l_arg_index]);
        return ERROR_SUBCOMMAND;
    }
}

static void s_hold_tx_add(dap_chain_datum_tx_t *a_tx, const char *a_group, dap_hash_fast_t *a_pkey_hash, tx_role_t a_role)
{
    size_t l_tx_hashes_count = 0;
    size_t l_shared_hashes_size = 0;
    char *l_pkey_hash_str = dap_hash_fast_to_str_new(a_pkey_hash);
    hold_tx_hashes_t *l_shared_hashes = (hold_tx_hashes_t *)dap_global_db_get_sync(a_group, l_pkey_hash_str, &l_shared_hashes_size, 0, false);
    if (!l_shared_hashes) {
        l_shared_hashes_size = sizeof(hold_tx_hashes_t) + sizeof(hold_tx_hash_item_t);
        l_shared_hashes = DAP_NEW_Z_SIZE_RET_IF_FAIL(hold_tx_hashes_t, l_shared_hashes_size);
    } else {
        l_shared_hashes_size += sizeof(hold_tx_hash_item_t);
        l_shared_hashes = DAP_REALLOC(l_shared_hashes, l_shared_hashes_size);
    }
    l_shared_hashes->tx[l_shared_hashes->tx_count].hash = dap_chain_node_datum_tx_calc_hash(a_tx);
    l_shared_hashes->tx[l_shared_hashes->tx_count].role = a_role;
    l_shared_hashes->tx_count++;
    log_it(L_DEBUG, "Added pkey hash %s as %s to shared hashes: %s", l_pkey_hash_str,a_role == TX_ROLE_CREATOR ? "creator" : "owner", dap_hash_fast_to_str_static(&l_shared_hashes->tx[l_shared_hashes->tx_count - 1].hash));
    dap_global_db_set_sync(a_group, l_pkey_hash_str, l_shared_hashes, l_shared_hashes_size, false);
    DAP_DEL_MULTY(l_pkey_hash_str, l_shared_hashes);
}

int dap_chain_wallet_shared_hold_tx_add(dap_chain_datum_tx_t *a_tx, const char *a_net_name)
{
    dap_return_val_if_pass(!a_net_name || !a_tx, ERROR_PARAM);
    dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, NULL);
    if (!l_cond) {
        return ERROR_TX_MISMATCH;
    }
    dap_tsd_t *l_tsd = NULL; size_t l_tsd_size = 0;
    char *l_group = dap_strdup_printf("%s.%s", s_wallet_shared_gdb_group, a_net_name);

    dap_sign_t *l_sig = dap_chain_datum_tx_get_sign(a_tx, 0);
    dap_hash_fast_t l_hash = {0};
    //  add creator hash
    dap_sign_get_pkey_hash(l_sig, &l_hash);
    s_hold_tx_add(a_tx, l_group, &l_hash, TX_ROLE_CREATOR);
    //  add owner hashes
    dap_tsd_iter(l_tsd, l_tsd_size, l_cond->tsd, l_cond->tsd_size) {
        if (l_tsd->type == DAP_CHAIN_TX_OUT_COND_TSD_HASH && l_tsd->size == sizeof(dap_hash_fast_t)) {
            s_hold_tx_add(a_tx, l_group, (dap_hash_fast_t *)l_tsd->data, TX_ROLE_OWNER);
            dap_global_db_set_sync(s_wallet_shared_gdb_pkeys, dap_hash_fast_to_str_static((dap_hash_fast_t *)l_tsd->data), NULL, 0, false);
        }
    }
    DAP_DELETE(l_group);
    return 0;
}

json_object *dap_chain_wallet_shared_get_tx_hashes_json(dap_hash_fast_t *a_pkey_hash, const char *a_net_name)
{
    json_object *l_json_ret = json_object_new_array();
    char *l_group = dap_strdup_printf("%s.%s", s_wallet_shared_gdb_group, a_net_name);
    hold_tx_hashes_t *l_item = (hold_tx_hashes_t *)dap_global_db_get_sync(l_group, dap_hash_fast_to_str_static(a_pkey_hash), NULL, NULL, false);
    DAP_DELETE(l_group);
    if (!l_item) {
        return NULL;
    }
    for (size_t i = 0; i < l_item->tx_count; i++) {
        if (l_item->tx[i].role == TX_ROLE_OWNER) {
            json_object_array_add(l_json_ret, json_object_new_string(dap_hash_fast_to_str_static(&l_item->tx[i].hash)));
        }
    }
    DAP_DELETE(l_item);
    return l_json_ret;
}

static uint32_t s_wallet_shared_get_valid_signs(dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx)
{
    if (!a_cond || !a_tx || !a_cond->tsd_size)
        return 0;
    size_t l_tsd_hashes_count = a_cond->tsd_size / (sizeof(dap_tsd_t) + sizeof(dap_hash_fast_t));
    if (!l_tsd_hashes_count)
        return 0;
    dap_sign_t *l_signs[l_tsd_hashes_count * 2];
    uint32_t l_signs_counter = 0, l_signs_verified = 0;
    byte_t *l_item; size_t l_tx_item_size;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        if (*l_item != TX_ITEM_TYPE_SIG)
            continue;
        dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_item);
        bool l_dup = false;
        for (uint32_t i = 0; i < l_signs_counter; i++)
            if (dap_sign_compare_pkeys(l_sign, l_signs[i])) {
                l_dup = true;
                break;
            }
        if (l_dup)
            continue;
        if (l_signs_counter >= l_tsd_hashes_count * 2) {
            log_it(L_WARNING, "Too many signs in tx, can't process more than %zu", l_tsd_hashes_count);
            break;
        }
        l_signs[l_signs_counter] = l_sign;
        dap_hash_fast_t l_pkey_hash;
        dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
        dap_tsd_t *l_tsd; size_t l_tsd_size;
        dap_tsd_iter(l_tsd, l_tsd_size, a_cond->tsd, a_cond->tsd_size) {
            if (l_tsd->type == DAP_CHAIN_TX_OUT_COND_TSD_HASH && l_tsd->size == sizeof(dap_hash_fast_t) &&
                    dap_hash_fast_compare(&l_pkey_hash, (dap_hash_fast_t *)l_tsd->data) &&
                    !dap_chain_datum_tx_verify_sign(a_tx, l_signs_counter++))
                l_signs_verified++;
        }
    }
    return l_signs_verified;
}

static void s_shared_tx_mempool_notify(dap_store_obj_t *a_obj, void *a_arg)
{
    dap_return_if_fail(a_obj && a_arg);
    if (dap_store_obj_get_type(a_obj) != DAP_GLOBAL_DB_OPTYPE_ADD || !a_obj->value)
        return;

    dap_chain_t *l_chain = (dap_chain_t *)a_arg;
    // Value in mempool is a dap_chain_datum_t, need to unwrap TX data
    if (a_obj->value_len < sizeof(dap_chain_datum_t))
        return;
    dap_chain_datum_t *l_datum = (dap_chain_datum_t *)a_obj->value;
    if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
        return;
    if (a_obj->value_len < sizeof(dap_chain_datum_t) + l_datum->header.data_size)
        return;
    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
    int l_count_num = 0;
    dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, &l_count_num);
    if (!l_cond) {
        return;
    }
    dap_hash_fast_t l_in_cond_hash = {0};
    byte_t *l_item; size_t l_tx_item_size;
    uint16_t l_change_type = 0;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, l_tx) {
        switch (*l_item) {
        case TX_ITEM_TYPE_TSD: {
            dap_tsd_t *l_tsd = (dap_tsd_t *)((dap_chain_tx_tsd_t *)l_item)->tsd;
            l_change_type = l_tsd->type;
            break;
        }
        case TX_ITEM_TYPE_IN_COND: {
            dap_chain_tx_in_cond_t *l_in_cond = (dap_chain_tx_in_cond_t *)l_item;
            l_in_cond_hash = l_in_cond->header.tx_prev_hash;
            break;
        }
        default:
            break;
        }
    }

    if (l_change_type != DAP_CHAIN_WALLET_SHARED_TSD_WRITEOFF) {
        return;
    }

    uint32_t l_valid_signs = s_wallet_shared_get_valid_signs(l_cond, l_tx);
    if (l_valid_signs < l_cond->subtype.wallet_shared.signers_minimum) {
        return;
    }

    json_object *l_jarray_remove_txs = json_object_new_array();
    if (!l_jarray_remove_txs)
        return;

    char *l_mempool_group = dap_chain_net_get_gdb_group_mempool_new(l_chain);
    if (!l_mempool_group) {
        json_object_put(l_jarray_remove_txs);
        return;
    }

    char *l_current_tx_hash_str = a_obj->key ? dap_strdup(a_obj->key) : NULL;
    if (!l_current_tx_hash_str) {
        DAP_DELETE(l_mempool_group);
        json_object_put(l_jarray_remove_txs);
        return;
    }

    dap_time_t l_best_ts = l_tx->header.ts_created;
    const char *l_best_hash_str = l_current_tx_hash_str;
    bool l_best_is_current = true;
    uint32_t l_best_signs = l_valid_signs;

    int l_tx_count = dap_chain_shared_tx_find_in_mempool(l_chain, &l_in_cond_hash, l_jarray_remove_txs);
    for (int i = 0; i < l_tx_count; i++) {
        json_object *l_jobj_tx_hash = json_object_array_get_idx(l_jarray_remove_txs, i);
        const char *l_tx_hash_str = json_object_get_string(l_jobj_tx_hash);
        if (!l_tx_hash_str)
            continue;
        size_t l_datum_size = 0;
        dap_chain_datum_t *l_datum = (dap_chain_datum_t *)dap_global_db_get_sync(l_mempool_group, l_tx_hash_str, &l_datum_size, NULL, NULL);
        if (!l_datum || l_datum_size < sizeof(dap_chain_datum_t)) {
            DAP_DELETE(l_datum);
            continue;
        }
        if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX) {
            DAP_DELETE(l_datum);
            continue;
        }
        dap_chain_datum_tx_t *l_tx_mempool = (dap_chain_datum_tx_t *)l_datum->data;
        uint32_t l_candidate_signs = s_wallet_shared_get_valid_signs(l_cond, l_tx_mempool);
        dap_time_t l_candidate_ts = l_tx_mempool->header.ts_created;
        DAP_DELETE(l_datum);
        bool l_is_better = false;
        if (l_candidate_signs > l_best_signs)
            l_is_better = true;
        else if (l_candidate_signs == l_best_signs) {
            if (l_candidate_ts > l_best_ts)
                l_is_better = true;
            else if (l_candidate_ts == l_best_ts && l_best_hash_str && dap_strcmp(l_tx_hash_str, l_best_hash_str) > 0)
                l_is_better = true;
        }
        if (l_is_better) {
            l_best_signs = l_candidate_signs;
            l_best_ts = l_candidate_ts;
            l_best_hash_str = l_tx_hash_str;
            l_best_is_current = false;
        }
    }
    for (int i = 0; i < l_tx_count; i++) {
        json_object *l_jobj_tx_hash = json_object_array_get_idx(l_jarray_remove_txs, i);
        const char *l_tx_hash_str = json_object_get_string(l_jobj_tx_hash);
        if (l_best_hash_str && l_tx_hash_str && !dap_strcmp(l_tx_hash_str, l_best_hash_str))
            continue;
        if (l_tx_hash_str && dap_global_db_del_sync(l_mempool_group, l_tx_hash_str)) {
            log_it(L_ERROR, "Can't remove previous shared funds tx from mempool: %s", l_tx_hash_str);
            goto cleanup;
        }
    }
    if (!l_best_is_current) {
        log_it(L_DEBUG, "Shared funds tx %s rejected, better candidate %s already in mempool with %u signs",
                l_current_tx_hash_str, l_best_hash_str ? l_best_hash_str : "unknown", l_best_signs);
        goto cleanup;
    }

cleanup:
    DAP_DELETE(l_current_tx_hash_str);
    json_object_put(l_jarray_remove_txs);
    DAP_DELETE(l_mempool_group);
}

int dap_chain_wallet_shared_init()
{
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, s_wallet_shared_verificator, NULL, NULL);
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_WALLET_SHARED_ID };
    dap_ledger_service_add(l_uid, "wallet_shared", s_tag_check);

    dap_list_t *l_groups_list = dap_global_db_driver_get_groups_by_mask(s_wallet_shared_gdb_group);
    for (dap_list_t *l_item = l_groups_list; l_item; l_item = l_item->next) {
        dap_global_db_erase_table_sync(l_item->data);
    }
    
    dap_list_free(l_groups_list);
    s_collect_wallet_pkey_hashes();
    s_collect_cert_pkey_hashes();
    return 0;
}

int dap_chain_wallet_shared_notify_init() {
    dap_chain_net_t *l_net = dap_chain_net_iter_start();
    for (; l_net; l_net = dap_chain_net_iter_next(l_net)) {
        for (dap_chain_t *l_chain = l_net->pub.chains; l_chain; l_chain = l_chain->next) {
            dap_chain_add_mempool_notify_callback(l_chain, s_shared_tx_mempool_notify, l_chain);
        }
    }
    return 0;
}
