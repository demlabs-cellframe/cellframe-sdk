/*
 * Authors:
 * Constantin Papizh <pa3.14zh@gmail.com>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
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

 *
 * DEX v2 service (SRV_DEX)
 */

#include <pthread.h>
#include <stdbool.h>
#include "dap_chain_common.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_net.h"
#include <stdio.h>
#include <stdlib.h>
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_wallet_cache.h"
#include "dap_chain_ledger.h"
#include "dap_common.h"
#include <stddef.h>
#include <string.h>
#include "dap_math_convert.h"
#include "dap_math_ops.h"
#include "dap_hash.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv_dex.h"
#include "dap_config.h"
#include "dap_cli_server.h"
#include "dap_chain_mempool.h"
#include "dap_cert.h"
#include "dap_strfuncs.h"
#include "dap_tsd.h"
#include "uthash.h"
#include "dap_time.h"
#include "utlist.h"
#include "utarray.h"
#include "json-c/arraylist.h"

#define LOG_TAG "dap_chain_net_srv_dex"

#ifdef RET_ERR
#undef RET_ERR
#endif

/* ============================================================================
 * Types, Defines & Global State
 * Order cache structures, match criteria, TX requirements
 * ============================================================================ */

typedef struct dex_pair_key {
    dap_chain_net_id_t net_id_base, net_id_quote;
    char token_base[DAP_CHAIN_TICKER_SIZE_MAX], token_quote[DAP_CHAIN_TICKER_SIZE_MAX];
    uint8_t fee_config; // bit7: 0=native, 1=QUOTE; bits[6:0]: percent(0-100) for QUOTE or unused for native
} dex_pair_key_t;

// Size of dex_pair_key_t without fee_config field (for hash table comparison)
#define DEX_PAIR_KEY_CMP_SIZE offsetof(dex_pair_key_t, fee_config)

typedef struct dex_order_match {
    uint256_t value, rate;      // remaining sell amount, canonical QUOTE/BASE price
    dap_hash_fast_t root, tail; // order chain root, current tail tx hash
    uint8_t min_fill;           // combined: low7=pct (0..100), bit7=from_origin
    int prev_idx;               // index of SRV_DEX OUT in tail tx (optional, -1 if unknown)
} dex_order_match_t;

// Unified lightweight order view for matching/simulation (cache and ledger)
typedef struct dex_order_level {
    dex_order_match_t match;
    UT_hash_handle hh, hh_tail;
} dex_order_level_t;

// Level comparators for HASH_SORT over dex_order_level_t
static inline int s_cmp_level_entries_ask(dex_order_level_t *a, dex_order_level_t *b)
{
    return compare256_ptr(&a->match.rate, &b->match.rate);
}
static inline int s_cmp_level_entries_bid(dex_order_level_t *a, dex_order_level_t *b)
{
    return compare256_ptr(&b->match.rate, &a->match.rate);
}

typedef struct dex_order_cache_entry {
    dex_order_level_t level; // unified order state
    uint256_t value_base;    // last update value for fill_pct
    // Pointer-only references to parent bucket keys (no duplication in entries)
    const dex_pair_key_t *pair_key_ptr;      // points to dex_pair_index_t.key
    const dap_chain_addr_t *seller_addr_ptr; // points to dex_seller_index_t.seller_addr
    UT_hash_handle hh_pair_bucket, hh_seller_bucket;
    dap_time_t ts_created, ts_expires;
    uint32_t flags;
    uint8_t side_version; // bit0 = side; bits1..7 = version
} dex_order_cache_entry_t;

/*
 * s_dex_orders_cache: primary UTHash keyed by order root hash -> dex_order_cache_entry_t
 * Holds all active orders; main anchor table using entry->hh handle.
 *
 * s_dex_index_by_tail: secondary UTHash keyed by current tail hash -> dex_order_cache_entry_t
 * Provides O(1) lookup by tail for updates/removals; uses entry->hh_tail handle.
 * Pair/seller bucket indices are declared below separately.
 */
static dex_order_cache_entry_t *s_dex_orders_cache = NULL, *s_dex_index_by_tail = NULL;

/* Unified RW-lock guarding all DEX caches and indices (orders + history) */
static pthread_rwlock_t s_dex_cache_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static bool s_dex_cache_enabled = false, s_debug_more = false; // global switch from config

typedef struct dex_pair_index {
    dex_pair_key_t key;
    dex_order_cache_entry_t *asks, *bids;           // heads keyed by hh_pair_bucket; best = head->rate
    uint256_t snapshot_best_ask, snapshot_best_bid; // snapshot of best prices BEFORE current block
    UT_hash_handle hh;
} dex_pair_index_t;

typedef struct dex_seller_index {
    dap_chain_addr_t seller_addr;
    dex_order_cache_entry_t *entries; // head keyed by hh_seller_bucket
    UT_hash_handle hh;
} dex_seller_index_t;

static dex_pair_index_t *s_dex_pair_index = NULL;
static dex_seller_index_t *s_dex_seller_index = NULL;

// Matched entry: compact snapshot + executed BASE
typedef struct dex_match_table_entry {
    dex_order_match_t match;      // match snapshot
    dex_pair_key_t *pair_key;     // pair key (sell/buy tickers + nets)
    dap_chain_addr_t seller_addr; // inline seller address
    uint8_t side_version;         // from cache payload
    uint32_t flags;               // from cache payload
    dap_time_t ts_created, ts_expires;
    uint256_t exec_sell, exec_min;
    uint256_t exec_quote; // exact QUOTE amount for partial fills (avoids div-mult round-trip)
    UT_hash_handle hh;    // keyed by match.tail
} dex_match_table_entry_t;

// Match criteria
typedef struct dex_match_criteria {
    const char *token_sell, *token_buy; // what taker sells (pays) // what taker buys (receives)
    dap_chain_net_id_t net_id_sell, net_id_buy;
    uint256_t rate_cap;                 // price limit in canonical QUOTE/BASE (BID: rate<=cap, ASK: rate>=cap; 0 - disabled)
    uint256_t budget;                   // amount limit
    bool is_budget_buy;                 // true: budget in token buyer wants to buy, false: budget in token buyer sells
    const dap_chain_addr_t *buyer_addr; // to skip self-purchase
} dex_match_criteria_t;

// Match table sort helpers (by price, then FIFO: ts_created, root)
static inline int s_cmp_match_entries_ask(dex_match_table_entry_t *a, dex_match_table_entry_t *b)
{
    int l_rc = compare256_ptr(&a->match.rate, &b->match.rate);
    return l_rc                            ? l_rc
           : a->ts_created < b->ts_created ? -1
           : a->ts_created > b->ts_created ? 1
                                           : memcmp(&a->match.root, &b->match.root, sizeof(a->match.root));
}

static inline int s_cmp_match_entries_bid(dex_match_table_entry_t *a, dex_match_table_entry_t *b)
{
    int l_rc = compare256_ptr(&b->match.rate, &a->match.rate);
    return l_rc                            ? l_rc
           : a->ts_created < b->ts_created ? -1
           : a->ts_created > b->ts_created ? 1
                                           : memcmp(&a->match.root, &b->match.root, sizeof(a->match.root));
}

// UTXO requirement per token for universal aggregator
typedef struct dex_utxo_requirement {
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t amount;   // Required amount
    uint256_t transfer; // Actually collected from UTXO (for cashback calculation)
    UT_hash_handle hh;  // keyed by ticker
} dex_utxo_requirement_t;

// Aggregated transaction requirements (with fees always payed by taker in QUOTE)
typedef struct dex_tx_requirements {
    // Direction
    uint8_t side; // ASK (taker buys BASE, pays QUOTE) or BID (taker sells BASE, receives QUOTE)

    // Canonical pair (from s_pair_normalize: pair_key always has token_base < token_quote lexicographically)
    const char *ticker_base;  // BASE (pair_key->token_base, lexicographically smaller)
    const char *ticker_quote; // QUOTE (pair_key->token_quote, lexicographically larger)
    const char *ticker_native;

    // Executed volumes
    uint256_t exec_sell;            // Total executed BASE (to taker in ASK, from taker in BID)
    uint256_t sellers_payout_quote; // Total QUOTE to makers (sellers in trade sense)

    // Fees
    uint256_t fee_srv;             // Service fee amount
    bool fee_pct_mode;             // true: % of INPUT (ASK→QUOTE, BID→BASE), false: NATIVE absolute
    uint256_t validator_fee;       // Validator fee in native
    uint256_t network_fee;         // Network fee in native
    dap_chain_addr_t service_addr; // Service fee destination
    dap_chain_addr_t network_addr; // Network fee destination (if used)

    // UTXO requirements aggregated by token
    dex_utxo_requirement_t *utxo_reqs; // Hash table: ticker -> amount
} dex_tx_requirements_t;

// UX helpers
static bool s_parse_natural_time(dap_ledger_t *a_ledger, const char *a_str, dap_time_t *a_out_ts)
{
    dap_ret_val_if_any(false, !a_str, a_str && !*a_str, !a_out_ts, !a_ledger);

    /* "now" */
    if (!dap_strcmp(a_str, "now")) {
        *a_out_ts = dap_time_now();
        return true;
    }
    /* "-1h", "-30m", "-2d" */
    if (*a_str == '-') {
        int l_val;
        for (l_val = 0; dap_is_digit(*a_str); l_val = l_val * 10 + (*a_str - '0'), a_str++)
            ;
        if (!l_val)
            return false;
        dap_time_t delta = l_val, l_now = dap_time_now();
        switch (*a_str) {
        case 'm':
            delta *= 60;
            break;
        case 'h':
            delta *= 3600;
            break;
        case 'd':
            delta *= DAP_SEC_PER_DAY;
            break;
        default:
            return false;
        }
        *a_out_ts = (dap_time_t)(l_now > delta ? l_now - delta : 0);
        return true;
    }
    /* RFC822 absolute time */
    dap_time_t l_ts = dap_time_from_str_rfc822(a_str);
    if (l_ts) {
        *a_out_ts = l_ts;
        return true;
    }
    return false;
}

static void s_add_units(json_object *a_obj, const char *a_base, const char *a_quote)
{
    dap_ret_if_any(!a_obj, !a_base, !a_quote);
    json_object *u = json_object_new_object();
    char buf[2 * DAP_CHAIN_TICKER_SIZE_MAX];
    snprintf(buf, sizeof(buf), "%s/%s", a_quote, a_base);
    json_object_object_add(u, "price", json_object_new_string(buf));
    json_object_object_add(u, "volume_base", json_object_new_string(a_base));
    json_object_object_add(u, "volume_quote", json_object_new_string(a_quote));
    json_object_object_add(a_obj, "units", u);
}

static void s_ledger_tx_add_notify_dex(void *a_arg, dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash,
                                       dap_chan_ledger_notify_opcodes_t a_opcode, dap_hash_fast_t *a_atom_hash);
static dex_tx_type_t s_dex_tx_classify(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_in_cond_t **a_in_cond,
                                       dap_chain_tx_out_cond_t **a_out_cond, int *a_out_idx);
static char *s_dex_tx_put(dap_chain_datum_tx_t *a_tx, dap_chain_net_t *a_net);

static dex_match_table_entry_t *s_dex_matches_build_by_criteria(dap_chain_net_t *a_net, const dex_match_criteria_t *a_criteria,
                                                                uint256_t *a_out_leftover_budget);
static int s_dex_match_snapshot_by_tail(dap_chain_net_t *a_net, const dap_hash_fast_t *a_tail, dex_match_table_entry_t *a_out,
                                        dex_pair_key_t *a_out_key);
static dex_match_table_entry_t *s_dex_matches_build_by_hashes(dap_chain_net_t *a_net, const dap_hash_fast_t *a_hashes, size_t a_count,
                                                              uint256_t a_budget, bool a_is_budget_buy,
                                                              const dap_chain_addr_t *a_buyer_addr,
                                                              dap_chain_net_srv_dex_purchase_error_t *a_out_err,
                                                              uint256_t *a_out_leftover_quote);

// Forward decl for cleanup helper
static inline void s_dex_matches_clear(dex_match_table_entry_t **a_head)
{
    dex_match_table_entry_t *e = NULL, *t = NULL;
    HASH_ITER(hh, *a_head, e, t)
    {
        HASH_DEL(*a_head, e);
        DAP_DELETE(e);
    }
}

static inline void s_dex_match_pair_index_clear(dex_match_table_entry_t **a_idx)
{
    if (*a_idx) {
        DAP_DELETE((*a_idx)->pair_key);
        s_dex_matches_clear(a_idx);
    }
}

#define DEX_MAX_IN 64
// Cross-net policy: soft control outside consensus
typedef enum { CROSS_NET_REJECT = 0, CROSS_NET_WARN = 1, CROSS_NET_ALLOW = 2 } cross_net_policy_t;
static cross_net_policy_t s_cross_net_policy = CROSS_NET_REJECT; // default

static inline const char *s_cross_net_policy_str(cross_net_policy_t p)
{
    return p == CROSS_NET_ALLOW ? "allow" : p == CROSS_NET_WARN ? "warn" : "reject";
}

// Verificator error codes (positive) and messages; return values remain negative (-code)
typedef enum {
    DEXV_OK,
    DEXV_INVALID_PARAMS,
    DEXV_INVALID_TX_ITEM,
    DEXV_MULTIPLE_SRV_DEX_OUT,
    DEXV_NO_IN,
    DEXV_PREV_TX_NOT_FOUND,
    DEXV_PREV_OUT_NOT_FOUND,
    DEXV_EXPIRED,
    DEXV_BASELINE_BUY_TOKEN,
    DEXV_BASELINE_TUPLE,
    DEXV_PAIR_NOT_ALLOWED,
    DEXV_INVALID_FEE_CONFIG,
    DEXV_SERVICE_FEE_ADDR_BLANK,
    DEXV_INVALID_RESIDUAL,
    DEXV_MIN_FILL_AON,
    DEXV_MIN_FILL_NOT_REACHED,
    DEXV_TX_TYPE_MISMATCH,
    DEXV_IMMUTABLES_VIOLATION,
    DEXV_SERVICE_FEE_UNDERPAID,
    DEXV_FEE_NOT_FROM_BUYER,
    DEXV_SERVICE_FEE_MISMATCH,
    DEXV_NETWORK_FEE_UNDERPAID,
    DEXV_BUY_TOKEN_LEAK,
    DEXV_SELL_TOKEN_LEAK,
    DEXV_SELLER_PAID_IN_UPDATE,
    DEXV_SELLER_PAYOUT_MISMATCH,
    DEXV_BUYER_ADDR_MISSING,
    DEXV_BUYER_MISMATCH,
    DEXV_SELF_PURCHASE,
    DEXV_MULTI_BUYER_DEST,
    DEXV_FINAL_NATIVE_MISMATCH,
    DEXV_FINAL_NONNATIVE_MISMATCH,
    DEXV_REFUND_MISMATCH,
    DEXV_BUYER_PAYOUT_ADDR_MISMATCH,
    DEXV_INVALIDATE_MULTI_SELLER,
    DEXV_INVALIDATE_NOT_OWNER,
    DEXV_UPDATE_NOT_OWNER,
    DEXV_LEFTOVER_STRUCTURE_VIOLATION,
    DEXV_ROOT_CHAIN_MISMATCH,
    DEXV_CANONICAL_LEFTOVER_MISMATCH,
} dex_verif_code_t;

static const char *s_dex_verif_err_strs[] = {
    [DEXV_INVALID_PARAMS] = "Invalid parameters",
    [DEXV_INVALID_TX_ITEM] = "Invalid TX item",
    [DEXV_MULTIPLE_SRV_DEX_OUT] = "More than one SRV_DEX out",
    [DEXV_NO_IN] = "No IN_COND",
    [DEXV_PREV_TX_NOT_FOUND] = "Previous tx not found",
    [DEXV_PREV_OUT_NOT_FOUND] = "Previous SRV_DEX out not found",
    [DEXV_EXPIRED] = "Previous order expired",
    [DEXV_BASELINE_BUY_TOKEN] = "Baseline buy token mismatch",
    [DEXV_BASELINE_TUPLE] = "Baseline market tuple mismatch",
    [DEXV_PAIR_NOT_ALLOWED] = "Pair not allowed",
    [DEXV_INVALID_FEE_CONFIG] = "Invalid fee_config (percent > 100)",
    [DEXV_SERVICE_FEE_ADDR_BLANK] = "Service fee address is blank (would burn tokens)",
    [DEXV_INVALID_RESIDUAL] = "Invalid residual (leftover) value",
    [DEXV_MIN_FILL_AON] = "AON min_fill disallowed for partial update",
    [DEXV_MIN_FILL_NOT_REACHED] = "Min_fill threshold not satisfied",
    [DEXV_TX_TYPE_MISMATCH] = "SRV_DEX tx_type mismatch to scenario",
    [DEXV_IMMUTABLES_VIOLATION] = "Immutable order fields changed",
    [DEXV_SERVICE_FEE_UNDERPAID] = "Service fee underpaid or misrouted",
    [DEXV_FEE_NOT_FROM_BUYER] = "Network fee not contributed by buyer",
    [DEXV_SERVICE_FEE_MISMATCH] = "Service fee canonical/preliminary mismatch",
    [DEXV_NETWORK_FEE_UNDERPAID] = "Network fee underpaid",
    [DEXV_BUY_TOKEN_LEAK] = "Unexpected buy-token payouts (non-seller/non-service)",
    [DEXV_SELL_TOKEN_LEAK] = "Unexpected sell-token payouts (non-buyer/non-seller)",
    [DEXV_SELLER_PAID_IN_UPDATE] = "Seller paid in owner update",
    [DEXV_SELLER_PAYOUT_MISMATCH] = "Seller payout in buy token mismatch",
    [DEXV_BUYER_ADDR_MISSING] = "Buyer address not found",
    [DEXV_BUYER_MISMATCH] = "Buyer-leftover seller mismatch",
    [DEXV_SELF_PURCHASE] = "Self-purchase not allowed",
    [DEXV_MULTI_BUYER_DEST] = "Multiple buyer destinations",
    [DEXV_FINAL_NATIVE_MISMATCH] = "Final sell payout mismatch (native)",
    [DEXV_FINAL_NONNATIVE_MISMATCH] = "Final sell payout mismatch (non-native)",
    [DEXV_REFUND_MISMATCH] = "Seller refund mismatch (INVALIDATE)",
    [DEXV_BUYER_PAYOUT_ADDR_MISMATCH] = "Buyer address payout mismatch",
    [DEXV_INVALIDATE_MULTI_SELLER] = "INVALIDATE: multiple sellers not allowed",
    [DEXV_INVALIDATE_NOT_OWNER] = "INVALIDATE: non-owner cannot cancel order",
    [DEXV_UPDATE_NOT_OWNER] = "UPDATE: non-owner cannot update order",
    [DEXV_LEFTOVER_STRUCTURE_VIOLATION] = "Leftover structure violation",
    [DEXV_ROOT_CHAIN_MISMATCH] = "Order root chain mismatch",
    [DEXV_CANONICAL_LEFTOVER_MISMATCH] = "Canonical leftover validation failed",
};

static inline const char *s_dex_verify_err_str(int a_ret)
{
    int l_code = dap_abs(a_ret);
    return l_code > 0 && (size_t)l_code < sizeof(s_dex_verif_err_strs) / sizeof(s_dex_verif_err_strs[0]) ? s_dex_verif_err_strs[l_code]
                                                                                                         : "unknown error";
}

// CLI error strings for API return codes
static const char *const s_create_error_str[] = {
    [DEX_CREATE_ERROR_OK] = "ok",
    [DEX_CREATE_ERROR_INVALID_ARGUMENT] = "invalid argument",
    [DEX_CREATE_ERROR_TOKEN_TICKER_SELL_NOT_FOUND] = "sell token not found",
    [DEX_CREATE_ERROR_TOKEN_TICKER_BUY_NOT_FOUND] = "buy token not found",
    [DEX_CREATE_ERROR_PAIR_NOT_ALLOWED] = "pair not allowed",
    [DEX_CREATE_ERROR_RATE_IS_ZERO] = "rate is zero",
    [DEX_CREATE_ERROR_FEE_IS_ZERO] = "fee is zero",
    [DEX_CREATE_ERROR_VALUE_SELL_IS_ZERO] = "sell value is zero",
    [DEX_CREATE_ERROR_INTEGER_OVERFLOW] = "integer overflow",
    [DEX_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE] = "not enough funds for fee",
    [DEX_CREATE_ERROR_NOT_ENOUGH_CASH] = "not enough funds",
    [DEX_CREATE_ERROR_COMPOSE_TX] = "TX compose failed",
};

static const char *const s_remove_error_str[] = {
    [DEX_REMOVE_ERROR_OK] = "ok",
    [DEX_REMOVE_ERROR_INVALID_ARGUMENT] = "invalid argument",
    [DEX_REMOVE_ERROR_FEE_IS_ZERO] = "fee is zero",
    [DEX_REMOVE_ERROR_TX_NOT_FOUND] = "order not found",
    [DEX_REMOVE_ERROR_INVALID_OUT] = "invalid order output",
    [DEX_REMOVE_ERROR_NOT_OWNER] = "not order owner",
    [DEX_REMOVE_ERROR_COMPOSE_TX] = "TX compose failed",
};

static const char *const s_update_error_str[] = {
    [DEX_UPDATE_ERROR_OK] = "ok",
    [DEX_UPDATE_ERROR_INVALID_ARGUMENT] = "invalid argument",
    [DEX_UPDATE_ERROR_NOT_FOUND] = "order not found",
    [DEX_UPDATE_ERROR_NOT_OWNER] = "not order owner",
    [DEX_UPDATE_ERROR_COMPOSE_TX] = "TX compose failed",
};

static const char *const s_purchase_error_str[] = {
    [DEX_PURCHASE_ERROR_OK] = "ok",
    [DEX_PURCHASE_ERROR_INVALID_ARGUMENT] = "invalid argument",
    [DEX_PURCHASE_ERROR_ORDER_NOT_FOUND] = "order not found",
    [DEX_PURCHASE_ERROR_ORDER_SPENT] = "order already spent",
    [DEX_PURCHASE_MULTI_ERROR_ORDERS_EMPTY] = "no orders specified",
    [DEX_PURCHASE_MULTI_ERROR_PAIR_MISMATCH] = "orders pair mismatch",
    [DEX_PURCHASE_MULTI_ERROR_SIDE_MISMATCH] = "orders side mismatch",
    [DEX_PURCHASE_AUTO_ERROR_NO_MATCHES] = "no matching orders found",
    [DEX_PURCHASE_ERROR_COMPOSE_TX] = "TX compose failed",
};

static const char *const s_migrate_error_str[] = {
    [DEX_MIGRATE_ERROR_OK] = "ok",
    [DEX_MIGRATE_ERROR_INVALID_ARGUMENT] = "invalid argument",
    [DEX_MIGRATE_ERROR_PREV_NOT_FOUND] = "XCHANGE order not found",
    [DEX_MIGRATE_ERROR_PREV_NOT_XCHANGE] = "not an XCHANGE order",
    [DEX_MIGRATE_ERROR_NOT_OWNER] = "not order owner",
    [DEX_MIGRATE_ERROR_COMPOSE_TX] = "TX compose failed",
};

static const char *const s_cancel_all_error_str[] = {
    [DEX_CANCEL_ALL_ERROR_OK] = "ok",
    [DEX_CANCEL_ALL_ERROR_INVALID_ARGUMENT] = "invalid argument",
    [DEX_CANCEL_ALL_ERROR_WALLET] = "wallet error",
    [DEX_CANCEL_ALL_ERROR_ORDERS_EMPTY] = "no orders to cancel",
    [DEX_CANCEL_ALL_ERROR_WALLET_MISMATCH] = "wallet mismatch",
    [DEX_CANCEL_ALL_NOT_ENOUGH_CASH_FOR_FEE] = "not enough funds for fee",
    [DEX_CANCEL_ALL_ERROR_COMPOSE_TX] = "TX compose failed",
};

// Per-pair service fee configuration (uses s_dex_cache_rwlock for synchronization)
static uint256_t s_dex_native_fee_amount;
static dap_chain_addr_t s_dex_service_fee_addr;

/* History cache (OHLCV) switches */
static bool s_dex_history_enabled = false;                  // enabled via config
static uint64_t s_dex_history_bucket_sec = DAP_SEC_PER_DAY; // default bucket size (daily)

static inline uint256_t s_calc_pct(const uint256_t a, const uint64_t b)
{
    uint256_t l_ret = uint256_0;
    if (b && !IS_ZERO_256(a)) {
        MULT_256_256(a, GET_256_FROM_64(b), &l_ret);
        DIV_256(l_ret, GET_256_FROM_64(100ULL), &l_ret);
    }
    return l_ret;
}

// Calculate service fee (must be called under s_dex_cache_rwlock)
static inline uint256_t s_dex_get_srv_fee(uint8_t a_fee_config)
{
    if (a_fee_config & 0x80)
        return uint256_0; // % mode has no fixed service fee
    uint8_t l_mult = a_fee_config & 0x7F;
    return l_mult > 0 ? GET_256_FROM_64((uint64_t)l_mult * DAP_DEX_FEE_UNIT_NATIVE) : s_dex_native_fee_amount;
}

/**
 * @brief Adjust executed amount for dust refund (subtract dust from executed if present)
 */
static void s_adjust_exec_for_dust_refund(dap_chain_datum_tx_t *a_tx, const dap_chain_addr_t *a_seller_addr, const char *a_sell_token,
                                          const dap_chain_addr_t *a_srv_addr, uint256_t a_srv_fee_req, uint256_t *a_executed)
{
    uint256_t l_dust = uint256_0;
    bool l_check_fee = a_srv_addr && !IS_ZERO_256(a_srv_fee_req) && dap_chain_addr_compare(a_seller_addr, a_srv_addr);
    bool l_fee_out_found = false;
    byte_t *it;
    size_t sz = 0;
    TX_ITEM_ITER_TX(it, sz, a_tx)
    {
        const dap_chain_addr_t *l_addr = NULL;
        const char *l_token = NULL;
        uint256_t l_value = uint256_0;
        if (*it == TX_ITEM_TYPE_OUT_STD) {
            dap_chain_tx_out_std_t *o = (dap_chain_tx_out_std_t *)it;
            l_addr = &o->addr;
            l_token = o->token;
            l_value = o->value;
        } else if (*it == TX_ITEM_TYPE_OUT_EXT) {
            dap_chain_tx_out_ext_t *o = (dap_chain_tx_out_ext_t *)it;
            l_addr = &o->addr;
            l_token = o->token;
            l_value = o->header.value;
        } else
            continue;
        if (!l_addr || !dap_chain_addr_compare(l_addr, a_seller_addr) || dap_strcmp(l_token, a_sell_token) || IS_ZERO_256(l_value))
            continue;
        SUM_256_256(l_dust, l_value, &l_dust);
        if (l_check_fee && !l_fee_out_found && !compare256(l_value, a_srv_fee_req))
            l_fee_out_found = true;
    }
    if (l_fee_out_found && compare256(l_dust, a_srv_fee_req) >= 0)
        SUBTRACT_256_256(l_dust, a_srv_fee_req, &l_dust);
    if (!IS_ZERO_256(l_dust) && compare256(*a_executed, l_dust) > 0)
        SUBTRACT_256_256(*a_executed, l_dust, a_executed);
}

/**
 * @brief Compute dynamic dust threshold for a given sell_token (0 = disabled)
 *
 * Threshold is defined as the maximum residual in sell_token considered uneconomical to continue as a new order:
 *   residual <= total_fees_in_sell_token
 * where total fees are derived deterministically from:
 *   - validator/network fees in native (fixed)
 *   - native service fee (fixed, native mode)
 *   - percent service fee (proportional, percent mode)
 *
 * If fixed native fees are non-zero but cannot be converted to sell_token via the order rate
 * (i.e., neither sell nor buy token is native), threshold is disabled (0).
 *
 * @param a_fixed_native Fixed native fees total (validator + network + native service fee if applicable)
 */
static uint256_t s_dex_calc_dust_threshold(const char *a_sell_ticker, const char *a_buy_ticker, const char *a_native_ticker,
                                           uint8_t a_fee_cfg, uint256_t a_rate, bool a_is_bid, uint256_t a_fixed_native)
{
    dap_ret_val_if_any(uint256_0, !a_sell_ticker, !a_buy_ticker, !a_native_ticker, IS_ZERO_256(a_fixed_native));

    uint256_t l_fixed_sell = uint256_0;
    if (!dap_strcmp(a_sell_ticker, a_native_ticker))
        l_fixed_sell = a_fixed_native;
    else if (!dap_strcmp(a_buy_ticker, a_native_ticker) && !IS_ZERO_256(a_rate))
        a_is_bid ? MULT_256_COIN(a_fixed_native, a_rate, &l_fixed_sell) // BASE(native) → QUOTE(sell)
                 : DIV_256_COIN(a_fixed_native, a_rate, &l_fixed_sell); // QUOTE(native) → BASE(sell)
    else
        return uint256_0;

    if (IS_ZERO_256(l_fixed_sell))
        return uint256_0;

    if ((a_fee_cfg & 0x80) != 0) {
        uint8_t l_pct = a_fee_cfg & 0x7F;
        if (!l_pct)
            return l_fixed_sell;
        uint256_t l_num = uint256_0;
        MULT_256_256(l_fixed_sell, GET_256_FROM_64(1000), &l_num);
        DIV_256(l_num, GET_256_FROM_64(1000 - l_pct), &l_fixed_sell);
    }
    return l_fixed_sell;
}

// Compute absolute min fill from percentage against original order value.
// Returns 0 on success, -1 on failure.
static int s_dex_fetch_min_abs(dap_ledger_t *a_ledger, const dap_hash_fast_t *a_hash, uint256_t *a_out)
{
    dap_ret_val_if_any(-1, !a_hash, !a_out);
    *a_out = uint256_0;
    if (s_dex_cache_enabled) {
        int l_ret = -1;
        dex_order_cache_entry_t *e = NULL;
        HASH_FIND(level.hh, s_dex_orders_cache, a_hash, sizeof(*a_hash), e);
        if (!e) {
            log_it(L_INFO, "Tx %s not found in cache", dap_hash_fast_to_str_static(a_hash));
            return -1;
        } else if (dap_hash_fast_compare(a_hash, &e->level.match.tail)) {
            *a_out = s_calc_pct(e->level.match.value, e->level.match.min_fill & 0x7F);
            return 0;
        } else
            debug_if(s_debug_more, L_DEBUG, "%s(): Cached tx %s is TAIL for root %s (value: %s), fallback to ledger for ROOT value",
                     __FUNCTION__, dap_hash_fast_to_str_static(&e->level.match.tail), dap_hash_fast_to_str_static(a_hash),
                     dap_uint256_to_char_ex(e->level.match.value).frac);
    }
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_ledger, a_hash);
    if (l_tx) {
        dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
        if (l_out_cond) {
            *a_out = s_calc_pct(l_out_cond->header.value, l_out_cond->subtype.srv_dex.min_fill & 0x7F);
            return 0;
        }
    }
    return -1;
}

// Invariants required for pointer arithmetic container-of access
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(offsetof(dex_pair_index_t, key) == 0, "dex_pair_index_t.key must be first field");
_Static_assert(offsetof(dex_seller_index_t, seller_addr) == 0, "dex_seller_index_t.seller_addr must be first field");
#endif

// Canonical side markers for pair indices
#define DEX_SIDE_ASK 0 // seller sells BASE, price = QUOTE/BASE (canonical)
#define DEX_SIDE_BID 1 // seller sells QUOTE, price = QUOTE/BASE (canonical), effective match rate is BASE/QUOTE

// Trade classification flags
#define DEX_OP_CREATE 0x01 // order creation
#define DEX_OP_MARKET 0x04 // executed at best price (automatch)
#define DEX_OP_TARGET 0x02 // off-market (direct hash purchase)
#define DEX_OP_CANCEL 0x08 // order cancellation
#define DEX_OP_UPDATE 0x10 // order parameters update
#define DEX_OP_ANY 0xff

/*
 * Compute executed percent from base and remaining values.
 */
static inline uint8_t s_calc_fill_pct(const uint256_t a_base, const uint256_t a_remaining)
{
    if (IS_ZERO_256(a_base) || compare256(a_remaining, a_base) >= 0)
        return 0;
    uint256_t l_exec = uint256_0;
    SUBTRACT_256_256(a_base, a_remaining, &l_exec);
    MULT_256_256(l_exec, GET_256_FROM_64(100ULL), &l_exec);
    DIV_256(l_exec, a_base, &l_exec);
    uint64_t l_pct = dap_chain_uint256_to(l_exec);
    return (uint8_t)(l_pct > 100 ? 100 : l_pct);
}

static const char *s_dex_op_flags_to_str(uint8_t a_flags)
{
    if (a_flags & DEX_OP_CANCEL)
        return "cancellation";
    else if (a_flags & DEX_OP_UPDATE)
        return "update";
    else if (a_flags & DEX_OP_CREATE) {
        return (a_flags & DEX_OP_MARKET)   ? "market trade | new order"
               : (a_flags & DEX_OP_TARGET) ? "targeted trade | new order"
                                           : "new order";
    } else if (a_flags & DEX_OP_MARKET)
        return "market trade";
    else if (a_flags & DEX_OP_TARGET)
        return "targeted trade";
    else
        return "undefined";
}

/**
 * Extract fee value from fee_config byte as uint256_t.
 * Caller checks mode via (a_fee_config & 0x80): 0 = native, 1 = percent.
 *
 * Native mode (bit7=0):
 *   value = 0   → global fallback (s_dex_native_fee_amount)
 *   value > 0   → value × 0.01 native (absolute amount)
 * Percent mode (bit7=1):
 *   Returns value × 0.1 (for display: dap_uint256_to_char gives "N.M" → append "%")
 */
static inline uint256_t s_dex_fee_config_to_val(uint8_t a_fee_config)
{
    uint8_t l_val = a_fee_config & 0x7F;
    return (a_fee_config & 0x80)
               ? GET_256_FROM_64((uint64_t)l_val * 100000000000000000ULL) // Percent: value × 0.1 (in 256-bit: value × 10^17)
           : l_val ? GET_256_FROM_64((uint64_t)l_val * DAP_DEX_FEE_UNIT_NATIVE)
                   : s_dex_native_fee_amount; // Native: value × 0.01 or global fallback
}

// Classify trade: market (at best price or better) or targeted (off-market)
static inline uint8_t s_dex_trade_classify(uint256_t a_price, uint256_t a_best, uint8_t a_side)
{
    // Empty book (best=0) → market (first trade)
    if (IS_ZERO_256(a_best))
        return DEX_OP_MARKET;

    if (a_side == DEX_SIDE_ASK) {
        // ASK side: buyer wants MIN price. MARKET if trade_price <= best_ask
        return compare256(a_price, a_best) <= 0 ? DEX_OP_MARKET : DEX_OP_TARGET;
    } else {
        // BID side: seller wants MAX price. MARKET if trade_price >= best_bid
        return compare256(a_price, a_best) >= 0 ? DEX_OP_MARKET : DEX_OP_TARGET;
    }
}

static inline bool s_dex_rate_cap_ok(uint8_t a_taker_side, const uint256_t a_rate, const uint256_t a_cap)
{
    return IS_ZERO_256(a_cap) ? true : a_taker_side == DEX_SIDE_ASK ? compare256(a_rate, a_cap) >= 0 : compare256(a_rate, a_cap) <= 0;
}

static int s_token_tuple_cmp(dap_chain_net_id_t a_net, const char *a_tok, dap_chain_net_id_t b_net, const char *b_tok)
{
    return a_net.uint64 < b_net.uint64 ? -1 : a_net.uint64 > b_net.uint64 ? 1 : strcmp(a_tok, b_tok);
}

/* ============================================================================
 * Order Cache Index Operations
 * Pair/seller index management, cache entry insert/remove
 * ============================================================================ */

/*
 * s_dex_seller_index_get_or_create
 * Lookup seller bucket by address or create a new one.
 * Inputs: a_addr — seller address.
 * On miss: allocate bucket, copy address, add to top-level hash.
 * Returns pointer to bucket or NULL on allocation failure.
 */
static dex_seller_index_t *s_dex_seller_index_get_or_create(const dap_chain_addr_t *a_addr)
{
    dap_ret_val_if_any(NULL, !a_addr);
    unsigned l_hash = 0;
    HASH_VALUE(a_addr, sizeof(*a_addr), l_hash);
    dex_seller_index_t *l_ret = NULL;
    HASH_FIND_BYHASHVALUE(hh, s_dex_seller_index, a_addr, sizeof(*a_addr), l_hash, l_ret);
    if (!l_ret) {
        l_ret = DAP_NEW_Z_RET_VAL_IF_FAIL(dex_seller_index_t, NULL);
        l_ret->seller_addr = *a_addr;
        HASH_ADD_BYHASHVALUE(hh, s_dex_seller_index, seller_addr, sizeof(l_ret->seller_addr), l_hash, l_ret);
    }
    return l_ret;
}

static inline int s_cmp_entries_ts(dex_order_cache_entry_t *a, dex_order_cache_entry_t *b)
{
    return a->ts_created < b->ts_created ? -1 : a->ts_created > b->ts_created ? 1 : 0;
}

// Strict version with deterministic tie-break by root hash
static inline int s_cmp_entries_ts_strict(dex_order_cache_entry_t *a, dex_order_cache_entry_t *b)
{
    int l_rc = a->ts_created < b->ts_created ? -1 : (a->ts_created > b->ts_created ? 1 : 0);
    return l_rc ? l_rc : memcmp(&a->level.match.root, &b->level.match.root, sizeof(a->level.match.root));
}

// Comparator for ASK bucket: rate ASC, ts_created ASC
static inline int s_cmp_entries_ask(dex_order_cache_entry_t *a, dex_order_cache_entry_t *b)
{
    int l_rc = compare256(a->level.match.rate, b->level.match.rate);
    return l_rc ? l_rc : s_cmp_entries_ts(a, b);
}

// Strict comparator for ASK bucket: rate ASC, ts_created ASC, root ASC (deterministic)
static inline int s_cmp_entries_ask_strict(dex_order_cache_entry_t *a, dex_order_cache_entry_t *b)
{
    int l_rc = compare256(a->level.match.rate, b->level.match.rate);
    return l_rc ? l_rc : s_cmp_entries_ts_strict(a, b);
}

// Comparator for BID bucket: rate DESC, ts_created ASC
static inline int s_cmp_entries_bid(dex_order_cache_entry_t *a, dex_order_cache_entry_t *b)
{
    int l_rc = compare256(b->level.match.rate, a->level.match.rate); // DESC!
    return l_rc ? l_rc : s_cmp_entries_ts(a, b);
}

// Strict comparator for BID bucket: rate DESC, ts_created ASC, root ASC (deterministic)
static inline int s_cmp_entries_bid_strict(dex_order_cache_entry_t *a, dex_order_cache_entry_t *b)
{
    int l_rc = compare256(b->level.match.rate, a->level.match.rate); // DESC!
    return l_rc ? l_rc : s_cmp_entries_ts_strict(a, b);
}

/*
 * s_dex_pair_index_get
 * Lookup pair bucket by canonical key (whitelist check).
 * Inputs: a_key — canonical pair (BASE/QUOTE).
 * Returns pointer to bucket or NULL if pair not whitelisted.
 * Note: pairs are added only via decree, not dynamically.
 */
static inline dex_pair_index_t *s_dex_pair_index_get(const dex_pair_key_t *a_key)
{
    dap_ret_val_if_any(NULL, !a_key);
    dex_pair_index_t *l_ret = NULL;
    HASH_FIND(hh, s_dex_pair_index, a_key, DEX_PAIR_KEY_CMP_SIZE, l_ret);
    return l_ret;
}

/*
 * s_dex_pair_index_add
 * Add pair to whitelist (called only from decree callback).
 * Inputs: a_key — canonical pair (BASE/QUOTE).
 * Returns 0 on success, negative on error.
 */
static inline int s_dex_pair_index_add(const dex_pair_key_t *a_key)
{
    dap_ret_val_if_any(-1, !a_key);
    if (s_dex_pair_index_get(a_key))
        return 1;

    dex_pair_index_t *l_new = DAP_NEW_Z_RET_VAL_IF_FAIL(dex_pair_index_t, -2);
    l_new->key = *a_key;
    HASH_ADD(hh, s_dex_pair_index, key, DEX_PAIR_KEY_CMP_SIZE, l_new);
    return 0;
}

// Remove entry from all secondary indices (tail, pair, seller) using back-pointers.
static void s_dex_indexes_remove(dex_order_cache_entry_t *a_entry)
{
    dap_ret_if_any(!a_entry);
    // tail index
    if (a_entry->level.hh_tail.tbl)
        HASH_DELETE(level.hh_tail, s_dex_index_by_tail, a_entry);
    // pair index
    if (a_entry->pair_key_ptr) {
        dex_pair_index_t *pb = (dex_pair_index_t *)a_entry->pair_key_ptr;
        if ((a_entry->side_version & 0x1) == DEX_SIDE_ASK)
            HASH_DELETE(hh_pair_bucket, pb->asks, a_entry);
        else
            HASH_DELETE(hh_pair_bucket, pb->bids, a_entry);
        // Empty asks/bids buckets are OK - pair remains whitelisted until decree removal.
        a_entry->pair_key_ptr = NULL;
    }
    // seller index
    if (a_entry->seller_addr_ptr) {
        dex_seller_index_t *sb = (dex_seller_index_t *)a_entry->seller_addr_ptr;
        HASH_DELETE(hh_seller_bucket, sb->entries, a_entry);
        if (!sb->entries) {
            HASH_DELETE(hh, s_dex_seller_index, sb);
            DAP_DELETE(sb);
        }
        a_entry->seller_addr_ptr = NULL;
    }
}

// Remove pair from whitelist (decree callback). Also removes all orders of this pair.
static int s_dex_pair_index_remove(const dex_pair_key_t *a_key)
{
    dex_pair_index_t *l_entry = NULL;
    if (a_key) {
        l_entry = s_dex_pair_index_get(a_key);
        dap_ret_val_if_any(-1, !l_entry);
    }
    // Remove all orders of this pair from hot cache
    dex_order_cache_entry_t *e, *tmp;
    HASH_ITER(level.hh, s_dex_orders_cache, e, tmp)
    {
        if (l_entry && e->pair_key_ptr != &l_entry->key)
            continue;

        s_dex_indexes_remove(e);
        HASH_DELETE(level.hh, s_dex_orders_cache, e);
        DAP_DELETE(e);
    }
    if (!a_key) {
        dex_pair_index_t *l_pair_idx, *tmp;
        HASH_ITER(hh, s_dex_pair_index, l_pair_idx, tmp)
        {
            HASH_DELETE(hh, s_dex_pair_index, l_pair_idx);
            DAP_DELETE(l_pair_idx);
        }
        return 0;
    }
    HASH_DELETE(hh, s_dex_pair_index, l_entry);
    DAP_DELETE(l_entry);
    return 0;
}

// Insert entry into all secondary indices (tail, pair, seller). Sorts by rate/ts.
static void s_dex_indexes_upsert(dex_pair_index_t *a_pair_idx, unsigned a_entry_root_hashv, const dap_chain_addr_t *a_seller_addr,
                                 dex_order_cache_entry_t *a_entry)
{
    a_entry->pair_key_ptr = &a_pair_idx->key;
    dex_seller_index_t *l_sb = s_dex_seller_index_get_or_create(a_seller_addr);
    /* Check for tail collision and remove old entry if exists */
    dex_order_cache_entry_t *l_replaced = NULL;
    HASH_REPLACE(level.hh_tail, s_dex_index_by_tail, level.match.tail, sizeof(dap_hash_fast_t), a_entry, l_replaced);
    if (l_replaced) {
        log_it(L_WARNING, "%s(): Hash collision for tail %s, replacing stale root %s → %s", __FUNCTION__,
               dap_hash_fast_to_str_static(&a_entry->level.match.tail), dap_hash_fast_to_str_static(&l_replaced->level.match.root),
               dap_hash_fast_to_str_static(&a_entry->level.match.root));
        // Remove from primary cache and pair/seller buckets
        HASH_DELETE(level.hh, s_dex_orders_cache, l_replaced);
        s_dex_indexes_remove(l_replaced);
        DAP_DELETE(l_replaced);
    }
    a_entry->seller_addr_ptr = &l_sb->seller_addr;
    if ((a_entry->side_version & 0x1) == DEX_SIDE_ASK)
        HASH_ADD_BYHASHVALUE_INORDER(hh_pair_bucket, a_pair_idx->asks, level.match.root, sizeof(a_entry->level.match.root),
                                     a_entry_root_hashv, a_entry, s_cmp_entries_ask_strict);
    else
        HASH_ADD_BYHASHVALUE_INORDER(hh_pair_bucket, a_pair_idx->bids, level.match.root, sizeof(a_entry->level.match.root),
                                     a_entry_root_hashv, a_entry, s_cmp_entries_bid_strict);
    HASH_ADD_BYHASHVALUE_INORDER(hh_seller_bucket, l_sb->entries, level.match.root, sizeof(a_entry->level.match.root), a_entry_root_hashv,
                                 a_entry, s_cmp_entries_ts_strict);
}

// Normalize pair to canonical base/quote ordering and compute side and canonical price
/*
 * s_pair_normalize
 * Canonicalize an order pair and compute canonical side and QUOTE/BASE price.
 * Inputs:
 *   - a_sell_tok/a_sell_net: order's sell token and net (as submitted)
 *   - a_buy_tok/a_buy_net:   buy token and net (as submitted)
 *   - a_rate_buy_per_sell:   price in units of BUY per 1 SELL (scaled 1e18)
 *   - a_canon_key:           output canonical key (BASE=lexicographically smaller, QUOTE=larger)
 *   - a_side:                output side (ASK if seller sells BASE; BID if seller sells QUOTE)
 *   - a_price_canon:         output price QUOTE/BASE (inverted if BID)
 * Logic:
 *   - Compare sell_tok vs buy_tok lexicographically.
 *   - If sell < buy: BASE=sell, QUOTE=buy → seller sells BASE → ASK
 *   - If sell >= buy: BASE=buy, QUOTE=sell → seller sells QUOTE → BID (invert rate)
 * NOTE: Does NOT populate fee_config - caller must do whitelist lookup if needed!
 * Returns: void; no output if required pointers are NULL.
 */
static inline void s_dex_pair_normalize(const char *a_sell_tok, dap_chain_net_id_t a_sell_net, const char *a_buy_tok,
                                        dap_chain_net_id_t a_buy_net, const uint256_t a_rate_canonical, dex_pair_key_t *a_canon_key,
                                        uint8_t *a_side, uint256_t *a_price_canon)
{
    dap_ret_if_any(!a_sell_tok, a_sell_tok && !*a_sell_tok, !a_buy_tok, a_buy_tok && !*a_buy_tok, !a_canon_key);
    if (strcmp(a_sell_tok, a_buy_tok) < 0) {
        // sell < buy: canonical BASE=sell, QUOTE=buy → seller sells BASE → ASK
        a_canon_key->net_id_base = a_sell_net;
        a_canon_key->net_id_quote = a_buy_net;
        dap_strncpy(a_canon_key->token_base, a_sell_tok, sizeof(a_canon_key->token_base) - 1);
        dap_strncpy(a_canon_key->token_quote, a_buy_tok, sizeof(a_canon_key->token_quote) - 1);
        if (a_side)
            *a_side = DEX_SIDE_ASK;
    } else {
        // sell >= buy: canonical BASE=buy, QUOTE=sell → seller sells QUOTE → BID
        a_canon_key->net_id_base = a_buy_net;
        a_canon_key->net_id_quote = a_sell_net;
        dap_strncpy(a_canon_key->token_base, a_buy_tok, sizeof(a_canon_key->token_base) - 1);
        dap_strncpy(a_canon_key->token_quote, a_sell_tok, sizeof(a_canon_key->token_quote) - 1);
        if (a_side)
            *a_side = DEX_SIDE_BID;
    }
    // Rate is ALWAYS stored in canonical form (QUOTE/BASE) - no inversion needed
    if (a_price_canon)
        *a_price_canon = a_rate_canonical;
}

static inline bool s_dex_rate_legacy_to_canon(const char *a_sell_tok, const char *a_buy_tok, uint256_t a_rate, uint256_t *a_out)
{
    dap_ret_val_if_any(false, !a_out, !a_sell_tok, a_sell_tok && !*a_sell_tok, !a_buy_tok, a_buy_tok && !*a_buy_tok, IS_ZERO_256(a_rate));
    *a_out = a_rate;
    if (strcmp(a_sell_tok, a_buy_tok) > 0) {
        DIV_256_COIN(GET_256_FROM_64(1000000000000000000ULL), a_rate, a_out);
        if (IS_ZERO_256(*a_out))
            return false;
    }
    return true;
}

// Comparator for JSON order objects by "ts" field (for array_list_sort)
static int s_cmp_json_orders_by_ts(const void *a, const void *b)
{
    json_object *ja = *(json_object **)a, *jb = *(json_object **)b;
    json_object *ta = NULL, *tb = NULL;
    json_object_object_get_ex(ja, "ts", &ta);
    json_object_object_get_ex(jb, "ts", &tb);
    uint64_t tsa = ta ? json_object_get_uint64(ta) : 0;
    uint64_t tsb = tb ? json_object_get_uint64(tb) : 0;
    return tsa < tsb ? -1 : tsa > tsb ? 1 : 0;
}

// Sort pair buckets: ASK by rate ASC, BID by rate DESC. FIFO tie-breaker for orders with same rate.
static void s_dex_pair_bucket_sort(dex_pair_index_t *a_bucket)
{
    dap_ret_if_any(!a_bucket);
    if (a_bucket->asks)
        HASH_SRT(hh_pair_bucket, a_bucket->asks, s_cmp_entries_ask_strict);
    if (a_bucket->bids)
        HASH_SRT(hh_pair_bucket, a_bucket->bids, s_cmp_entries_bid_strict);
}

/* ============================================================================
 * Matching Engine
 * Order snapshot building, criteria-based matching, budget allocation
 * ============================================================================ */

// Add single hash (root or tail) to transient table
static int s_dex_match_snapshot_by_tail(dap_chain_net_t *a_net, const dap_hash_fast_t *a_tail, dex_match_table_entry_t *a_out,
                                        dex_pair_key_t *a_out_key)
{
    dap_ret_val_if_any(-1, !a_net, !a_tail, !a_out);
    // Cache first
    if (s_dex_cache_enabled) {
        pthread_rwlock_rdlock(&s_dex_cache_rwlock);
        dex_order_cache_entry_t *e = NULL;
        HASH_FIND(level.hh_tail, s_dex_index_by_tail, a_tail, sizeof(*a_tail), e);
        if (e) {
            // Skip spent tails (stale cache entries may remain on rare cache desyncs)
            if (e->level.match.prev_idx >= 0 &&
                dap_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, (dap_chain_hash_fast_t *)a_tail, e->level.match.prev_idx, NULL))
                return pthread_rwlock_unlock(&s_dex_cache_rwlock), -5;
            *a_out = (dex_match_table_entry_t){.match = e->level.match,
                                               .seller_addr = *(dap_chain_addr_t *)e->seller_addr_ptr,
                                               .side_version = e->side_version,
                                               .flags = e->flags,
                                               .ts_created = e->ts_created,
                                               .ts_expires = e->ts_expires};
            if (a_out_key)
                *a_out_key = *e->pair_key_ptr;
        }
        if (!e)
            return pthread_rwlock_unlock(&s_dex_cache_rwlock), -2;
    } else {
        // Ledger fallback
        dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, (dap_chain_hash_fast_t *)a_tail);
        if (!l_tx)
            return -2;
        int l_out_idx = 0;
        dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
        if (!l_out_cond)
            return -3;
        const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, (dap_chain_hash_fast_t *)a_tail);
        if (!l_sell_tok)
            return -4;
        dex_pair_key_t l_key = {};
        uint8_t l_side = 0;
        uint256_t l_price = uint256_0;
        s_dex_pair_normalize(l_sell_tok, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                             l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key, &l_side, &l_price);
        // Populate fee_config from whitelist
        pthread_rwlock_rdlock(&s_dex_cache_rwlock);
        dex_pair_index_t *l_pair_for_fee = s_dex_pair_index_get(&l_key);
        if (l_pair_for_fee)
            l_key.fee_config = l_pair_for_fee->key.fee_config;
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
        dap_hash_fast_t l_root = dap_ledger_get_first_chain_tx_hash(a_net->pub.ledger, l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
        // If root is blank (ORDER without IN_COND), use tail (this TX hash) as root
        if (dap_hash_fast_is_blank(&l_root))
            l_root = *a_tail;
        *a_out = (dex_match_table_entry_t){.match = (dex_order_match_t){.value = l_out_cond->header.value,
                                                                        .rate = l_price,
                                                                        .root = l_root,
                                                                        .tail = *a_tail,
                                                                        .min_fill = l_out_cond->subtype.srv_dex.min_fill,
                                                                        .prev_idx = l_out_idx},
                                           .seller_addr = l_out_cond->subtype.srv_dex.seller_addr,
                                           .side_version = (uint8_t)((l_out_cond->subtype.srv_dex.version & 0x7F) << 1) | (l_side & 0x1),
                                           .flags = l_out_cond->subtype.srv_dex.flags,
                                           .ts_created = l_tx->header.ts_created,
                                           .ts_expires = l_out_cond->header.ts_expires};
        if (a_out_key)
            *a_out_key = l_key;
    }
    // Precompute exec_min once per snapshot (normalize to BASE units)
    uint8_t l_min_raw = a_out->match.min_fill, l_pct = l_min_raw & 0x7F;
    bool l_from_origin = (l_min_raw & 0x80) != 0 && l_pct < 100;
    if (l_pct) {
        if (l_from_origin) {
            // from origin (uses cache-first inside s_dex_fetch_min_abs)
            if (s_dex_fetch_min_abs(a_net->pub.ledger, &a_out->match.root, &a_out->exec_min))
                a_out->exec_min = uint256_0;
        } else
            a_out->exec_min = s_calc_pct(a_out->match.value, l_pct); // percent of match.value
        // If BID, match.value is QUOTE; convert exec_min from QUOTE → BASE via canonical rate
        if (!IS_ZERO_256(a_out->exec_min) && ((a_out->side_version & 0x1) == DEX_SIDE_BID))
            DIV_256_COIN(a_out->exec_min, a_out->match.rate, &a_out->exec_min);
    }
    if (s_dex_cache_enabled)
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
    return 0;
}

// Resolve any SRV_DEX order hash (root, current tail; intermediate tails are ledger-only) to the current tail hash.
// Cache can resolve only:
//   - current tail (s_dex_index_by_tail)
//   - chain root (s_dex_orders_cache)
// Everything else must be resolved via ledger.
static int s_dex_resolve_order_tail(dap_chain_net_t *a_net, const dap_hash_fast_t *a_hash, dap_hash_fast_t *a_out_tail)
{
    dap_ret_val_if_any(-1, !a_net, !a_hash, !a_out_tail, dap_hash_fast_is_blank(a_hash));
    *a_out_tail = (dap_hash_fast_t){};
    if (s_dex_cache_enabled) {
        unsigned l_hashv;
        HASH_VALUE(a_hash, sizeof(*a_hash), l_hashv);
        pthread_rwlock_rdlock(&s_dex_cache_rwlock);
        dex_order_cache_entry_t *l_e = NULL;
        HASH_FIND_BYHASHVALUE(level.hh_tail, s_dex_index_by_tail, a_hash, sizeof(*a_hash), l_hashv, l_e);
        if (!l_e)
            HASH_FIND_BYHASHVALUE(level.hh, s_dex_orders_cache, a_hash, sizeof(*a_hash), l_hashv, l_e);
        if (l_e)
            *a_out_tail = l_e->level.match.tail;
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
        if (!dap_hash_fast_is_blank(a_out_tail))
            return 0;
    }
    *a_out_tail = dap_ledger_get_final_chain_tx_hash(a_net->pub.ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX,
                                                     (dap_chain_hash_fast_t *)a_hash, false);
    return dap_hash_fast_is_blank(a_out_tail) ? -2 : 0;
}

// Build transient table from hashes (roots or tails). Uses cache when available; otherwise reads ledger once per hash.
static dex_match_table_entry_t *s_dex_matches_build_by_hashes(dap_chain_net_t *a_net, const dap_hash_fast_t *a_hashes, size_t a_count,
                                                              uint256_t a_budget, bool a_is_budget_buy,
                                                              const dap_chain_addr_t *a_buyer_addr,
                                                              dap_chain_net_srv_dex_purchase_error_t *a_out_err,
                                                              uint256_t *a_out_leftover_quote)
{
    dap_do_if_any(if (a_out_err) *a_out_err = DEX_PURCHASE_ERROR_INVALID_ARGUMENT; return NULL;, !a_net, !a_hashes, !a_count);
    int l_err = DEX_PURCHASE_ERROR_OK;
    dex_match_table_entry_t *l_entries = NULL, *l_cur = DAP_NEW_STACK(dex_match_table_entry_t), *l_tmp;
    dex_pair_key_t *l_key_common = NULL;
    uint8_t l_side0 = ~0;
    for (const dap_hash_fast_t *l_cur_hash = a_hashes; a_count; ++l_cur_hash, --a_count) {
        dap_hash_fast_t l_tail;
        if (s_dex_resolve_order_tail(a_net, l_cur_hash, &l_tail)) {
            debug_if(s_debug_more, L_ERROR, "%s(): Can't resolve tail for hash %s, skipping", __FUNCTION__,
                     dap_hash_fast_to_str_static(l_cur_hash));
            continue;
        }
        debug_if(s_debug_more && !dap_hash_fast_compare(l_cur_hash, &l_tail), L_ERROR, "%s(): Resolved tail %s -> %s", __FUNCTION__,
                 dap_hash_fast_to_str_static(l_cur_hash), dap_hash_fast_to_str_static(&l_tail));
        unsigned l_hashv;
        HASH_VALUE(&l_tail, sizeof(l_tail), l_hashv);
        // Skip duplicate tails (avoid double spend)
        if (l_entries) {
            dex_match_table_entry_t *l_dup = NULL;
            HASH_FIND_BYHASHVALUE(hh, l_entries, &l_tail, sizeof(l_tail), l_hashv, l_dup);
            if (l_dup)
                continue;
        }
        dex_pair_key_t l_cur_key;
        if (s_dex_match_snapshot_by_tail(a_net, &l_tail, l_cur, &l_cur_key))
            continue;
        if (IS_ZERO_256(l_cur->match.value) || IS_ZERO_256(l_cur->match.rate))
            continue;
        // Skip self-purchase
        if (a_buyer_addr && dap_chain_addr_compare(a_buyer_addr, &l_cur->seller_addr))
            continue;
        // Enforce single-side: fix by the first entry and require all others to match
        uint8_t l_side_cur = l_cur->side_version & 0x1;
        if (l_side0 == (uint8_t)~0)
            l_side0 = l_side_cur;
        else if (l_side_cur != l_side0) {
            l_err = DEX_PURCHASE_MULTI_ERROR_SIDE_MISMATCH;
            break;
        }
        // Enforce single-pair: first mismatch aborts with error
        if (!l_key_common)
            l_key_common = DAP_DUP(&l_cur_key);
        else if (memcmp(l_key_common, &l_cur_key, sizeof(l_cur_key))) {
            l_err = DEX_PURCHASE_MULTI_ERROR_PAIR_MISMATCH;
            break;
        }

        l_cur->pair_key = l_key_common;
        dex_match_table_entry_t *l_new = DAP_DUP(l_cur);
        if (!l_new) {
            l_err = DEX_PURCHASE_ERROR_COMPOSE_TX;
            break;
        }
        HASH_ADD_BYHASHVALUE(hh, l_entries, match.tail, sizeof(l_new->match.tail), l_hashv, l_new);
    }
    if (!l_entries)
        l_err = DEX_PURCHASE_MULTI_ERROR_ORDERS_EMPTY;

    if (l_err != DEX_PURCHASE_ERROR_OK) {
        DAP_DELETE(l_key_common);
        s_dex_matches_clear(&l_entries);
        if (a_out_err)
            *a_out_err = l_err;
        return NULL;
    }

    // Translate ORDER budget to CANONICAL context
    // Unified semantics: is_budget_buy=true means budget in token buyer wants to buy
    // l_side0 is MAKER's side (ASK/BID), buyer's side is inverted:
    //   Buying from ASK → buyer is BID (buys BASE)
    //   Buying from BID → buyer is ASK (buys QUOTE)
    // Formula: budget_in_base = is_budget_buy == (buyer_side == BID)
    //                         = is_budget_buy == (l_side0 == ASK)
    bool l_budget_in_base = a_is_budget_buy == (l_side0 == DEX_SIDE_ASK);

    // Sort by better price: ASK asc (cheaper quote), BID desc (higher quote)
    if (l_side0 == DEX_SIDE_ASK)
        HASH_SORT(l_entries, s_cmp_match_entries_ask);
    else
        HASH_SORT(l_entries, s_cmp_match_entries_bid);

    if (IS_ZERO_256(a_budget)) {
        // Unlimited budget: full fill all matches
        HASH_ITER(hh, l_entries, l_cur, l_tmp)
        {
            if (l_side0 == DEX_SIDE_ASK)
                l_cur->exec_sell = l_cur->match.value; // BASE
            else
                DIV_256_COIN(l_cur->match.value, l_cur->match.rate, &l_cur->exec_sell); // QUOTE→BASE
            debug_if(s_debug_more, L_DEBUG, "%s(): Full fill; Tail: %s; Exec sell: %s %s; Rate: %s; Budget: ∞", __FUNCTION__,
                     dap_hash_fast_to_str_static(&l_cur->match.tail), dap_uint256_to_char_ex(l_cur->exec_sell).frac,
                     l_cur->pair_key->token_base, dap_uint256_to_char_ex(l_cur->match.rate).frac);
        }
    } else if (l_budget_in_base) {
        // BASE budget: limit exec_sell directly (direction-independent)
        HASH_ITER(hh, l_entries, l_cur, l_tmp)
        {
            if (IS_ZERO_256(a_budget)) {
                HASH_DEL(l_entries, l_cur);
                DAP_DELETE(l_cur);
                continue;
            }
            uint8_t l_pct = l_cur->match.min_fill & 0x7F;
            uint256_t l_available_base;
            // Available BASE in this order
            if (l_side0 == DEX_SIDE_ASK)
                l_available_base = l_cur->match.value; // Order value is in BASE
            else
                DIV_256_COIN(l_cur->match.value, l_cur->match.rate, &l_available_base); // QUOTE→BASE

            // Dust order: available < min_fill (treated as AON, no partial fills)
            bool l_order_exhausted = (l_pct > 0 && compare256(l_available_base, l_cur->exec_min) < 0);

            if (compare256(a_budget, l_available_base) >= 0) {
                // Full fill: take entire order
                l_cur->exec_sell = l_available_base;
                SUBTRACT_256_256(a_budget, l_available_base, &a_budget);
                debug_if(s_debug_more, L_DEBUG,
                         "%s(): Full fill; Tail: %s; Exec: min %s (%d%%), sell %s %s; Rate: %s; "
                         "Budget: %s %s; Available B: %s %s",
                         __FUNCTION__, dap_hash_fast_to_str_static(&l_cur->match.tail), dap_uint256_to_char_ex(l_cur->exec_min).frac, l_pct,
                         dap_uint256_to_char_ex(l_cur->exec_sell).frac, l_cur->pair_key->token_base,
                         dap_uint256_to_char_ex(l_cur->match.rate).frac, dap_uint256_to_char_ex(a_budget).frac, l_cur->pair_key->token_base,
                         dap_uint256_to_char_ex(l_available_base).frac, l_cur->pair_key->token_base);
                continue;
            } else if (l_pct != 100 && !l_order_exhausted) {
                // Partial fill: skip AON and dust orders
                l_cur->exec_sell = a_budget;
                // Canonical exec_sell: ensures verifier computes same expected_buy
                // exec_quote = exec_sell * rate → exec_sell_canonical = exec_quote / rate
                // This eliminates round-trip error between composer and verifier
                MULT_256_COIN(l_cur->exec_sell, l_cur->match.rate, &l_cur->exec_quote);
                DIV_256_COIN(l_cur->exec_quote, l_cur->match.rate, &l_cur->exec_sell); // canonical
                if (l_pct == 0 || (!IS_ZERO_256(l_cur->exec_sell) && compare256(l_cur->exec_sell, l_cur->exec_min) >= 0)) {
                    a_budget = uint256_0;
                    debug_if(s_debug_more, L_DEBUG,
                             "%s(): Partial fill; Tail: %s; Exec: min %s (%d%%), sell %s %s; Rate: %s; "
                             "Budget drained; Available B: %s %s",
                             __FUNCTION__, dap_hash_fast_to_str_static(&l_cur->match.tail), dap_uint256_to_char_ex(l_cur->exec_min).frac,
                             l_pct, dap_uint256_to_char_ex(l_cur->exec_sell).frac, l_cur->pair_key->token_base,
                             dap_uint256_to_char_ex(l_cur->match.rate).frac, dap_uint256_to_char_ex(l_available_base).frac,
                             l_cur->pair_key->token_base);
                    continue;
                }
            }
            // Reject: AON/dust without full budget, or min_fill not met
            debug_if(s_debug_more, L_DEBUG,
                     "%s(): Rejected; Tail: %s%s; Exec min %s (%d%%); "
                     "Budget: %s %s, Available B: %s %s",
                     __FUNCTION__, dap_hash_fast_to_str_static(&l_cur->match.tail), l_order_exhausted ? " (exhausted)" : "",
                     dap_uint256_to_char_ex(l_cur->exec_min).frac, l_pct, dap_uint256_to_char_ex(a_budget).frac,
                     l_cur->pair_key->token_base, dap_uint256_to_char_ex(l_available_base).frac, l_cur->pair_key->token_base);
            HASH_DEL(l_entries, l_cur);
            DAP_DELETE(l_cur);
        }
        if (a_out_leftover_quote)
            *a_out_leftover_quote = a_budget;
    } else {
        // QUOTE budget: direction-dependent conversion
        HASH_ITER(hh, l_entries, l_cur, l_tmp)
        {
            if (IS_ZERO_256(a_budget)) {
                HASH_DEL(l_entries, l_cur);
                DAP_DELETE(l_cur);
                continue;
            }
            uint8_t l_pct = l_cur->match.min_fill & 0x7F;
            // Calculate required QUOTE for this order and available in BASE for exhaustion check
            uint256_t l_available_base, l_need_q;
            if (l_side0 == DEX_SIDE_ASK) {
                MULT_256_COIN(l_cur->match.value, l_cur->match.rate, &l_need_q); // ASK: BASE * rate
                l_available_base = l_cur->match.value;
            } else {
                l_need_q = l_cur->match.value; // BID: already QUOTE
                DIV_256_COIN(l_cur->match.value, l_cur->match.rate, &l_available_base);
            }

            // Dust order: available < min_fill (treated as AON, no partial fills)
            bool l_order_exhausted = (l_pct > 0 && compare256(l_available_base, l_cur->exec_min) < 0);

            if (compare256(a_budget, l_need_q) >= 0) {
                // Full fill: take entire order
                if (l_side0 == DEX_SIDE_ASK)
                    l_cur->exec_sell = l_cur->match.value; // ASK: order value is BASE
                else
                    DIV_256_COIN(l_cur->match.value, l_cur->match.rate, &l_cur->exec_sell); // BID: QUOTE→BASE
                SUBTRACT_256_256(a_budget, l_need_q, &a_budget);
                debug_if(s_debug_more, L_DEBUG,
                         "%s(): Full fill; Tail: %s; Exec: min %s (%d%%), sell %s %s; Rate: %s; "
                         "Budget: %s %s; Available B: %s %s; Required Q: %s %s",
                         __FUNCTION__, dap_hash_fast_to_str_static(&l_cur->match.tail), dap_uint256_to_char_ex(l_cur->exec_min).frac, l_pct,
                         dap_uint256_to_char_ex(l_cur->exec_sell).frac, l_cur->pair_key->token_base,
                         dap_uint256_to_char_ex(l_cur->match.rate).frac, dap_uint256_to_char_ex(a_budget).frac,
                         l_cur->pair_key->token_quote, dap_uint256_to_char_ex(l_available_base).frac, l_cur->pair_key->token_base,
                         dap_uint256_to_char_ex(l_need_q).frac, l_cur->pair_key->token_quote);
                continue;
            } else if (l_pct != 100 && !l_order_exhausted) {
                // Partial fill: skip AON and dust orders
                // QUOTE budget: convert to BASE
                // For both ASK and BID: canonical rate = QUOTE/BASE, so BASE = QUOTE/rate
                l_cur->exec_quote = a_budget; // save exact QUOTE before division (for residual calc)
                DIV_256_COIN(a_budget, l_cur->match.rate, &l_cur->exec_sell);

                // exec_sell cannot exceed available order size
                if (compare256(l_cur->exec_sell, l_available_base) > 0) {
                    l_cur->exec_sell = l_available_base;
                    // Recalculate exec_quote for capped exec_sell (round-trip)
                    MULT_256_COIN(l_cur->exec_sell, l_cur->match.rate, &l_cur->exec_quote);
                }

                if (l_pct == 0 || (!IS_ZERO_256(l_cur->exec_sell) && compare256(l_cur->exec_sell, l_cur->exec_min) >= 0)) {
                    a_budget = uint256_0;
                    debug_if(s_debug_more, L_DEBUG,
                             "%s(): Partial fill; Tail: %s; Exec: min %s (%d%%), sell %s %s; Rate: %s; "
                             "Budget drained; Available B: %s %s; Required Q: %s %s",
                             __FUNCTION__, dap_hash_fast_to_str_static(&l_cur->match.tail), dap_uint256_to_char_ex(l_cur->exec_min).frac,
                             l_pct, dap_uint256_to_char_ex(l_cur->exec_sell).frac, l_cur->pair_key->token_base,
                             dap_uint256_to_char_ex(l_cur->match.rate).frac, dap_uint256_to_char_ex(l_available_base).frac,
                             l_cur->pair_key->token_base, dap_uint256_to_char_ex(l_need_q).frac, l_cur->pair_key->token_quote);
                    continue;
                }
            }
            // Reject: AON/dust without full budget, or min_fill not met
            debug_if(s_debug_more, L_DEBUG,
                     "%s(): Rejected; Tail: %s%s; Exec min %s (%d%%); "
                     "Budget: %s %s, Available B: %s %s; Required Q: %s %s",
                     __FUNCTION__, dap_hash_fast_to_str_static(&l_cur->match.tail), l_order_exhausted ? " (exhausted)" : "",
                     dap_uint256_to_char_ex(l_cur->exec_min).frac, l_pct, dap_uint256_to_char_ex(a_budget).frac,
                     l_cur->pair_key->token_quote, dap_uint256_to_char_ex(l_available_base).frac, l_cur->pair_key->token_base,
                     dap_uint256_to_char_ex(l_need_q).frac, l_cur->pair_key->token_quote);
            HASH_DEL(l_entries, l_cur);
            DAP_DELETE(l_cur);
        }
        if (a_out_leftover_quote)
            *a_out_leftover_quote = a_budget;
    }
    if (a_out_err)
        *a_out_err = DEX_PURCHASE_ERROR_OK;
    return l_entries;
}

// Allocate matches into execution index: greedily consume QUOTE budget across ASK entries
// Build final matched table from a temporary snapshot set; result entries are independent snapshots

// Build matches by criteria (one stage): cache-first over pair buckets; ledger fallback builds a temp snapshot table
static dex_match_table_entry_t *s_dex_matches_build_by_criteria(dap_chain_net_t *a_net, const dex_match_criteria_t *a_criteria,
                                                                uint256_t *a_out_leftover_budget)
{
    dap_ret_val_if_any(NULL, !a_net, !a_criteria);
    dex_match_table_entry_t *l_res = NULL;

    // Convert ORDER context (taker's perspective) to CANONICAL context (BASE/QUOTE for indexing)
    // a_criteria: ORDER context - sell_token = what taker sells, buy_token = what taker buys
    // l_key:      CANONICAL context - quote_token = QUOTE, base_token = BASE (from s_pair_normalize)

    // Prepare common pair key for all matches
    dex_pair_key_t *l_common_key = DAP_NEW_Z(dex_pair_key_t);
    uint8_t l_side = 0;
    s_dex_pair_normalize(a_criteria->token_sell, a_criteria->net_id_sell, a_criteria->token_buy, a_criteria->net_id_buy,
                         GET_256_FROM_64(1000000000000000000ULL), l_common_key, &l_side, NULL);

    // Translate ORDER budget to CANONICAL context
    // Unified semantics: is_budget_buy=true means budget in token buyer wants to buy
    // Taker side: BID (buys BASE, sells QUOTE), ASK (buys QUOTE, sells BASE)
    // Formula: budget_in_base = is_budget_buy == (buyer_side == BID)
    // Example: buyer wants KEL (BASE) → BID side → is_budget_buy=true → budget_in_base=TRUE
    bool l_budget_in_base = a_criteria->is_budget_buy == (l_side == DEX_SIDE_BID);
    uint256_t l_budget = a_criteria->budget;

    debug_if(s_debug_more, L_DEBUG, "%s(): Taker's %s intent to swap %s for %s, providing %s %s budget", __FUNCTION__,
             l_side == DEX_SIDE_ASK ? "ASK" : "BID", a_criteria->token_sell, a_criteria->token_buy,
             !IS_ZERO_256(l_budget) ? dap_uint256_to_char_ex(l_budget).frac : "∞",
             !IS_ZERO_256(l_budget) ? l_budget_in_base ? l_common_key->token_base : l_common_key->token_quote : "");
    // Cache path
    if (s_dex_cache_enabled) {
        pthread_rwlock_rdlock(&s_dex_cache_rwlock);
        dex_pair_index_t *l_pair_bucket = NULL;
        HASH_FIND(hh, s_dex_pair_index, l_common_key, DEX_PAIR_KEY_CMP_SIZE, l_pair_bucket);
        if (l_pair_bucket) {
            // Populate fee_config from found pair (needed for requirements builder)
            l_common_key->fee_config = l_pair_bucket->key.fee_config;
            dap_time_t l_now_ts = dap_ledger_get_blockchain_time(a_net->pub.ledger);
            // INVERTED: buyer's BID matches sellers' ASKs, buyer's ASK matches sellers' BIDs
            dex_order_cache_entry_t *l_head = (l_side == DEX_SIDE_ASK) ? l_pair_bucket->bids : l_pair_bucket->asks, *l_entry, *l_tmp;
            uint8_t l_order_side = (l_side == DEX_SIDE_ASK) ? DEX_SIDE_BID : DEX_SIDE_ASK; // opposite side
            HASH_ITER(hh_pair_bucket, l_head, l_entry, l_tmp)
            {
                if (IS_ZERO_256(l_budget) && !IS_ZERO_256(a_criteria->budget))
                    break;
                if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires)
                    continue;
                if (!s_dex_rate_cap_ok(l_side, l_entry->level.match.rate, a_criteria->rate_cap))
                    continue;
                // Skip self-purchase
                if (a_criteria->buyer_addr && dap_chain_addr_compare(a_criteria->buyer_addr, l_entry->seller_addr_ptr))
                    continue;
                // Skip spent tails (stale cache entries may remain on rare cache desyncs)
                if (l_entry->level.match.prev_idx >= 0 &&
                    dap_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &l_entry->level.match.tail, l_entry->level.match.prev_idx, NULL))
                    continue;
                // Decide execution against current budget
                uint256_t l_exec_sell = uint256_0, l_exec_quote_exact = uint256_0;
                if (IS_ZERO_256(a_criteria->budget)) {
                    // Unlimited budget: full fill
                    if (l_order_side == DEX_SIDE_ASK)
                        l_exec_sell = l_entry->level.match.value; // ASK: value is BASE
                    else
                        DIV_256_COIN(l_entry->level.match.value, l_entry->level.match.rate, &l_exec_sell); // BID: QUOTE→BASE
                    debug_if(s_debug_more, L_DEBUG, "{ %s, cache path } Full fill; Tail: %s; Exec sell: %s %s; Rate: %s; Budget: ∞",
                             __FUNCTION__, dap_hash_fast_to_str_static(&l_entry->level.match.tail),
                             dap_uint256_to_char_ex(l_exec_sell).frac, l_common_key->token_base,
                             dap_uint256_to_char_ex(l_entry->level.match.rate).frac);
                } else if (l_budget_in_base) {
                    // BASE budget: limit exec_sell directly (direction-independent)
                    uint8_t l_min_raw = l_entry->level.match.min_fill, l_pct = l_min_raw & 0x7F;
                    uint256_t l_available_base;
                    if (l_order_side == DEX_SIDE_ASK)
                        l_available_base = l_entry->level.match.value; // ASK: value is BASE
                    else
                        DIV_256_COIN(l_entry->level.match.value, l_entry->level.match.rate, &l_available_base); // BID: QUOTE→BASE

                    // Compute min_fill threshold (in BASE) once for both exhaustion and partial checks
                    uint256_t l_exec_min = uint256_0;
                    int l_fetch_min = 0;
                    bool l_order_exhausted = false;
                    if (l_pct > 0) {
                        bool l_from_origin = (l_min_raw & 0x80) != 0 && l_pct < 100;
                        if (l_from_origin) {
                            l_fetch_min = s_dex_fetch_min_abs(a_net->pub.ledger, &l_entry->level.match.root, &l_exec_min);
                        } else {
                            uint256_t l_min_value = s_calc_pct(l_entry->level.match.value, l_pct);
                            if (l_order_side == DEX_SIDE_ASK)
                                l_exec_min = l_min_value; // ASK: Already in BASE
                            else
                                DIV_256_COIN(l_min_value, l_entry->level.match.rate, &l_exec_min); // BID: QUOTE→BASE
                        }
                        // Dust order: available < min_fill (treated as AON, no partial fills)
                        l_order_exhausted = (!l_fetch_min && compare256(l_available_base, l_exec_min) < 0);
                    }

                    if (compare256(l_budget, l_available_base) >= 0) {
                        // Full fill: take entire order
                        l_exec_sell = l_available_base;
                        SUBTRACT_256_256(l_budget, l_available_base, &l_budget);
                        debug_if(s_debug_more, L_DEBUG,
                                 "{ %s, cache path } Full fill; Tail: %s; Exec: min %s (%d%%), sell %s %s; Rate: %s; "
                                 "Budget: %s %s; Available B: %s %s",
                                 __FUNCTION__, dap_hash_fast_to_str_static(&l_entry->level.match.tail),
                                 dap_uint256_to_char_ex(l_exec_min).frac, l_pct, dap_uint256_to_char_ex(l_exec_sell).frac,
                                 l_common_key->token_base, dap_uint256_to_char_ex(l_entry->level.match.rate).frac,
                                 dap_uint256_to_char_ex(l_budget).frac, l_common_key->token_base,
                                 dap_uint256_to_char_ex(l_available_base).frac, l_common_key->token_base);
                    } else if (l_pct != 100 && !l_order_exhausted) {
                        // Partial fill: skip AON and dust orders
                        l_exec_sell = l_budget;
                        // Canonical exec_sell (same as main path)
                        MULT_256_COIN(l_exec_sell, l_entry->level.match.rate, &l_exec_quote_exact);
                        DIV_256_COIN(l_exec_quote_exact, l_entry->level.match.rate, &l_exec_sell); // canonical
                        if (l_pct == 0 || (!l_fetch_min && compare256(l_exec_sell, l_exec_min) >= 0)) {
                            l_budget = uint256_0;
                            debug_if(s_debug_more, L_DEBUG,
                                     "{ %s, cache path } Partial fill; Tail: %s; Exec: min %s (%d%%), sell %s %s; Rate: %s; "
                                     "Budget drained; Available B: %s %s",
                                     __FUNCTION__, dap_hash_fast_to_str_static(&l_entry->level.match.tail),
                                     dap_uint256_to_char_ex(l_exec_min).frac, l_pct, dap_uint256_to_char_ex(l_exec_sell).frac,
                                     l_common_key->token_base, dap_uint256_to_char_ex(l_entry->level.match.rate).frac,
                                     dap_uint256_to_char_ex(l_available_base).frac, l_common_key->token_base);
                        } else {
                            debug_if(s_debug_more, L_DEBUG,
                                     "{ %s, cache path } Min-fill violation, skip; Tail: %s%s; Exec min %s (%d%%); "
                                     "Budget: %s %s, Available B: %s %s",
                                     __FUNCTION__, dap_hash_fast_to_str_static(&l_entry->level.match.tail),
                                     l_order_exhausted ? " (exhausted)" : "", dap_uint256_to_char_ex(l_exec_min).frac, l_pct,
                                     dap_uint256_to_char_ex(l_budget).frac, l_common_key->token_base,
                                     dap_uint256_to_char_ex(l_available_base).frac, l_common_key->token_base);
                            continue;
                        }
                    } else {
                        debug_if(s_debug_more, L_DEBUG,
                                 "{ %s, cache path } AON/dust order, skip; Tail: %s%s; Exec min %s (%d%%); "
                                 "Budget: %s %s, Available B: %s %s",
                                 __FUNCTION__, dap_hash_fast_to_str_static(&l_entry->level.match.tail),
                                 l_order_exhausted ? " (exhausted)" : "", dap_uint256_to_char_ex(l_exec_min).frac, l_pct,
                                 dap_uint256_to_char_ex(l_budget).frac, l_common_key->token_base,
                                 dap_uint256_to_char_ex(l_available_base).frac, l_common_key->token_base);
                        continue;
                    }
                } else {
                    // QUOTE budget: convert available BASE to required QUOTE
                    uint8_t l_min_raw = l_entry->level.match.min_fill, l_pct = l_min_raw & 0x7F;
                    uint256_t l_available_base;
                    if (l_order_side == DEX_SIDE_ASK)
                        l_available_base = l_entry->level.match.value; // ASK: value is BASE
                    else
                        DIV_256_COIN(l_entry->level.match.value, l_entry->level.match.rate,
                                     &l_available_base); // BID: value is QUOTE, convert to BASE

                    // Calculate required QUOTE for available BASE
                    // Always: QUOTE = BASE * rate (rate is QUOTE/BASE in canonical form)
                    uint256_t l_need_q;
                    MULT_256_COIN(l_available_base, l_entry->level.match.rate, &l_need_q);

                    // Compute min_fill threshold (in BASE) once for both exhaustion and partial checks
                    uint256_t l_exec_min = uint256_0;
                    int l_fetch_min = 0;
                    bool l_order_exhausted = false;
                    if (l_pct > 0) {
                        bool l_from_origin = (l_min_raw & 0x80) != 0 && l_pct < 100;
                        if (l_from_origin)
                            l_fetch_min = s_dex_fetch_min_abs(a_net->pub.ledger, &l_entry->level.match.root, &l_exec_min);
                        else
                            l_exec_min = s_calc_pct(l_entry->level.match.value, l_pct);
                        if (l_order_side == DEX_SIDE_BID)
                            DIV_256_COIN(l_exec_min, l_entry->level.match.rate, &l_exec_min); // BID: QUOTE→BASE
                        // Dust order: available < min_fill (treated as AON, no partial fills)
                        l_order_exhausted = (!l_fetch_min && compare256(l_available_base, l_exec_min) < 0);
                    }

                    if (compare256(l_budget, l_need_q) >= 0) {
                        // Full fill: take entire order (already have l_available_base)
                        l_exec_sell = l_available_base;
                        SUBTRACT_256_256(l_budget, l_need_q, &l_budget);
                        debug_if(s_debug_more, L_DEBUG,
                                 "{ %s, cache path } Full fill; Tail: %s; Exec: min %s (%d%%), sell %s %s; Rate: %s; "
                                 "Budget: %s %s; Available B: %s %s; Required Q: %s %s",
                                 __FUNCTION__, dap_hash_fast_to_str_static(&l_entry->level.match.tail),
                                 dap_uint256_to_char_ex(l_exec_min).frac, l_pct, dap_uint256_to_char_ex(l_exec_sell).frac,
                                 l_common_key->token_base, dap_uint256_to_char_ex(l_entry->level.match.rate).frac,
                                 dap_uint256_to_char_ex(l_budget).frac, l_common_key->token_quote,
                                 dap_uint256_to_char_ex(l_available_base).frac, l_common_key->token_base,
                                 dap_uint256_to_char_ex(l_need_q).frac, l_common_key->token_quote);
                    } else if (l_pct != 100 && !l_order_exhausted) {
                        // Partial fill: skip AON and dust orders
                        // Convert QUOTE budget to BASE
                        // For both ASK and BID: canonical rate = QUOTE/BASE, so BASE = QUOTE/rate
                        l_exec_quote_exact = l_budget; // save exact QUOTE before division (for residual calc)
                        DIV_256_COIN(l_budget, l_entry->level.match.rate, &l_exec_sell);

                        // exec_sell cannot exceed available order size
                        if (compare256(l_exec_sell, l_available_base) > 0) {
                            l_exec_sell = l_available_base;
                            // Recalculate exec_quote for capped exec_sell (round-trip)
                            MULT_256_COIN(l_exec_sell, l_entry->level.match.rate, &l_exec_quote_exact);
                        }

                        if (l_pct == 0 || (!IS_ZERO_256(l_exec_sell) && !l_fetch_min && compare256(l_exec_sell, l_exec_min) >= 0)) {
                            l_budget = uint256_0;
                            debug_if(s_debug_more, L_DEBUG,
                                     "{ %s, cache path } Partial fill; Tail: %s; Exec: min %s (%d%%), sell %s %s; Rate: %s; "
                                     "Budget drained; Available B: %s %s; Required Q: %s %s",
                                     __FUNCTION__, dap_hash_fast_to_str_static(&l_entry->level.match.tail),
                                     dap_uint256_to_char_ex(l_exec_min).frac, l_pct, dap_uint256_to_char_ex(l_exec_sell).frac,
                                     l_common_key->token_base, dap_uint256_to_char_ex(l_entry->level.match.rate).frac,
                                     dap_uint256_to_char_ex(l_available_base).frac, l_common_key->token_base,
                                     dap_uint256_to_char_ex(l_need_q).frac, l_common_key->token_quote);
                        } else {
                            debug_if(s_debug_more, L_DEBUG,
                                     "{ %s, cache path } Min fill violation, skip; Tail: %s%s; Exec min %s (%d%%); "
                                     "Budget: %s %s, Available B: %s %s; Required Q: %s %s",
                                     __FUNCTION__, dap_hash_fast_to_str_static(&l_entry->level.match.tail),
                                     l_order_exhausted ? " (exhausted)" : "", dap_uint256_to_char_ex(l_exec_min).frac, l_pct,
                                     dap_uint256_to_char_ex(l_budget).frac, l_common_key->token_quote,
                                     dap_uint256_to_char_ex(l_available_base).frac, l_common_key->token_base,
                                     dap_uint256_to_char_ex(l_need_q).frac, l_common_key->token_quote);
                            continue;
                        }
                    } else {
                        debug_if(s_debug_more, L_DEBUG,
                                 "{ %s, cache path } AON/dust order, skip; Tail: %s%s; Exec min %s (%d%%); "
                                 "Budget: %s %s, Available B: %s %s; Required Q: %s %s",
                                 __FUNCTION__, dap_hash_fast_to_str_static(&l_entry->level.match.tail),
                                 l_order_exhausted ? " (exhausted)" : "", dap_uint256_to_char_ex(l_exec_min).frac, l_pct,
                                 dap_uint256_to_char_ex(l_budget).frac, l_common_key->token_quote,
                                 dap_uint256_to_char_ex(l_available_base).frac, l_common_key->token_base,
                                 dap_uint256_to_char_ex(l_need_q).frac, l_common_key->token_quote);
                        continue;
                    }
                }
                if (IS_ZERO_256(l_exec_sell))
                    continue;
                // Snapshot entry for composer (attach common pair key)
                dex_match_table_entry_t *l_match = DAP_NEW(dex_match_table_entry_t);
                *l_match = (dex_match_table_entry_t){
                    l_entry->level.match, l_common_key,        *l_entry->seller_addr_ptr, l_entry->side_version,           l_entry->flags,
                    l_entry->ts_created,  l_entry->ts_expires, .exec_sell = l_exec_sell,  .exec_quote = l_exec_quote_exact};
                debug_if(s_debug_more, L_DEBUG,
                         "{ %s, cache path } Added match %s; Root: %s; Tail: %s; "
                         "Value: %s %s; Rate: %s; Exec sell: %s %s",
                         __FUNCTION__, (l_entry->side_version & 0x1) ? "BID" : "ASK",
                         dap_chain_hash_fast_to_str_static(&l_entry->level.match.root),
                         dap_chain_hash_fast_to_str_static(&l_entry->level.match.tail),
                         dap_uint256_to_char_ex(l_entry->level.match.value).frac, l_common_key->token_base,
                         dap_uint256_to_char_ex(l_entry->level.match.rate).frac, dap_uint256_to_char_ex(l_exec_sell).frac,
                         l_common_key->token_base);
                HASH_ADD(hh, l_res, match.tail, sizeof(l_match->match.tail), l_match);
            }
        }
        pthread_rwlock_unlock(&s_dex_cache_rwlock);

        // Sort result: INVERTED (buyer's side → opposite orders)
        if (l_res) {
            if (l_side == DEX_SIDE_ASK)
                HASH_SORT(l_res, s_cmp_match_entries_bid); // ASK buyer → BID sellers (rate DESC)
            else
                HASH_SORT(l_res, s_cmp_match_entries_ask); // BID buyer → ASK sellers (rate ASC)
        } else
            DAP_DELETE(l_common_key);
        if (a_out_leftover_budget)
            *a_out_leftover_budget = l_budget;
        return l_res;
    }
    // Ledger fallback: check pair whitelist first, then collect snapshots
    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    dex_pair_index_t *l_pb_check = NULL;
    HASH_FIND(hh, s_dex_pair_index, l_common_key, DEX_PAIR_KEY_CMP_SIZE, l_pb_check);
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    if (!l_pb_check) {
        log_it(L_WARNING, "Pair %s/%s (net %" DAP_UINT64_FORMAT_U "/%" DAP_UINT64_FORMAT_U ") not whitelisted!", l_common_key->token_base,
               l_common_key->token_quote, l_common_key->net_id_base.uint64, l_common_key->net_id_quote.uint64);
        DAP_DELETE(l_common_key);
        if (a_out_leftover_budget)
            *a_out_leftover_budget = a_criteria->budget;
        return NULL; // Pair not whitelisted
    }
    // Populate fee_config from found pair (needed for requirements builder)
    l_common_key->fee_config = l_pb_check->key.fee_config;

    dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(a_net);
    int l_orders_found = 0, l_orders_matched = 0;
    for (dap_chain_datum_tx_t *tx = dap_ledger_datum_iter_get_first(it); tx; tx = dap_ledger_datum_iter_get_next(it)) {
        int l_out_idx = 0;
        dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_out_cond_get(tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
        if (!l_out || dap_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &it->cur_hash, l_out_idx, NULL))
            continue;
        if (l_out->header.ts_expires && dap_ledger_get_blockchain_time(a_net->pub.ledger) > l_out->header.ts_expires)
            continue;
        const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &it->cur_hash);
        if (!l_sell_tok)
            continue;
        dex_pair_key_t l_key_cur;
        uint8_t l_side_cur = 0;
        uint256_t l_price = uint256_0;
        s_dex_pair_normalize(l_sell_tok, l_out->subtype.srv_dex.sell_net_id, l_out->subtype.srv_dex.buy_token,
                             l_out->subtype.srv_dex.buy_net_id, l_out->subtype.srv_dex.rate, &l_key_cur, &l_side_cur, &l_price);

        l_orders_found++;
        bool l_pair_match = !strcmp(l_key_cur.token_quote, l_common_key->token_quote) &&
                            !strcmp(l_key_cur.token_base, l_common_key->token_base) &&
                            l_key_cur.net_id_quote.uint64 == l_common_key->net_id_quote.uint64 &&
                            l_key_cur.net_id_base.uint64 == l_common_key->net_id_base.uint64;
        bool l_side_match = l_side_cur != l_side; // INVERTED: match opposite sides (BID↔ASK)

        if (!l_pair_match || !l_side_match) {
            debug_if(s_debug_more, L_DEBUG, "{ %s, ledger path } Skip %s order %d: %s mismatch; Tx: %s; Sell: %s; Buy: %s", __FUNCTION__,
                     l_side_cur == DEX_SIDE_ASK ? "ASK" : "BID", l_orders_found,
                     l_pair_match   ? "side"
                     : l_side_match ? "pair"
                                    : "pair and side",
                     dap_chain_hash_fast_to_str_static(&it->cur_hash), l_sell_tok, l_out->subtype.srv_dex.buy_token);
            continue;
        }

        // Skip self-purchase
        if (a_criteria->buyer_addr && dap_chain_addr_compare(a_criteria->buyer_addr, &l_out->subtype.srv_dex.seller_addr))
            continue;

        l_orders_matched++;
        debug_if(s_debug_more, L_DEBUG, "{ %s, ledger path } Matched %s order %d; Tx: %s", __FUNCTION__,
                 l_side_cur == DEX_SIDE_ASK ? "ASK" : "BID", l_orders_matched, dap_chain_hash_fast_to_str_static(&it->cur_hash));
        if (!s_dex_rate_cap_ok(l_side, l_price, a_criteria->rate_cap))
            continue;
        // Always set exec_sell to full fill value (direction-dependent)
        uint256_t l_exec_sell = uint256_0;
        if (l_side_cur == DEX_SIDE_ASK) {
            l_exec_sell = l_out->header.value; // ASK: value is in BASE
        } else {
            // BID: value is in QUOTE, convert to BASE
            DIV_256_COIN(l_out->header.value, l_price, &l_exec_sell); // QUOTE→BASE
        }
        if (s_debug_more) {
            char l_ts[64];
            dap_time_to_str_rfc822(l_ts, sizeof(l_ts), tx->header.ts_created);
            log_it(L_DEBUG,
                   "{ %s, ledger path } %s order snapshot; Tx: %s; Root: %s; Seller: %s; "
                   "Value: %s; Rate: %s; Exec sell: %s; Ts created: %s",
                   __FUNCTION__, l_side_cur == DEX_SIDE_ASK ? "ASK" : "BID", dap_chain_hash_fast_to_str_static(&it->cur_hash),
                   dap_chain_hash_fast_to_str_static(&l_out->subtype.srv_dex.order_root_hash),
                   dap_chain_addr_to_str_static(&l_out->subtype.srv_dex.seller_addr), dap_uint256_to_char_ex(l_out->header.value).frac,
                   dap_uint256_to_char_ex(l_price).frac, dap_uint256_to_char_ex(l_exec_sell).frac, l_ts);
        }

        // Compute exec_min for ALL orders (before budget filters)
        uint256_t l_exec_min = uint256_0;
        uint8_t l_min_raw = l_out->subtype.srv_dex.min_fill, l_pct = l_min_raw & 0x7F;
        bool l_from_origin = (l_min_raw & 0x80) != 0 && l_pct < 100;
        if (l_pct > 0) {
            if (l_from_origin) {
                dap_hash_fast_t l_root_hash = l_out->subtype.srv_dex.order_root_hash;
                if (dap_hash_fast_is_blank(&l_root_hash))
                    l_root_hash = it->cur_hash;
                pthread_rwlock_rdlock(&s_dex_cache_rwlock);
                int l_fetch_min = s_dex_fetch_min_abs(a_net->pub.ledger, &l_root_hash, &l_exec_min);
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
                if (l_fetch_min)
                    continue; // Failed to fetch min_fill, skip order
            } else {
                uint256_t l_min_value = s_calc_pct(l_out->header.value, l_pct);
                // Convert to BASE for universal comparison
                if (l_side_cur == DEX_SIDE_ASK)
                    l_exec_min = l_min_value; // ASK: Already in BASE
                else
                    DIV_256_COIN(l_min_value, l_price, &l_exec_min); // BID: QUOTE→BASE
            }
        }

        // Apply budget filters if limited budget (using already-computed l_exec_min)
        if (!IS_ZERO_256(a_criteria->budget)) {
            if (l_budget_in_base) {
                // BASE budget filter: check against exec_sell directly
                if (l_pct == 100 && compare256(a_criteria->budget, l_exec_sell) < 0) {
                    debug_if(s_debug_more, L_DEBUG,
                             "{ %s, ledger path } Filter: skip order (AON violation); "
                             "Tx: %s; Exec sell: %s %s; Budget in B: %s %s",
                             __FUNCTION__, dap_chain_hash_fast_to_str_static(&it->cur_hash), dap_uint256_to_char_ex(l_exec_sell).frac,
                             l_common_key->token_base, dap_uint256_to_char_ex(a_criteria->budget).frac, l_common_key->token_base);
                    continue;
                }
                if (l_pct > 0 && compare256(a_criteria->budget, l_exec_min) < 0) {
                    debug_if(s_debug_more, L_DEBUG,
                             "{ %s, ledger path } Filter: skip order (min fill violation); "
                             "Tx: %s; Exec min: %s (%d%%); Budget in B: %s %s",
                             __FUNCTION__, dap_chain_hash_fast_to_str_static(&it->cur_hash), dap_uint256_to_char_ex(l_exec_min).frac, l_pct,
                             dap_uint256_to_char_ex(a_criteria->budget).frac, l_common_key->token_base);
                    continue;
                }
            } else {
                // QUOTE budget filter: calculate required QUOTE for this order
                // l_exec_sell is in BASE, need to convert to QUOTE via rate
                // Always: QUOTE = BASE * rate (rate == QUOTE/BASE in canonical form)
                uint256_t l_need_q;
                MULT_256_COIN(l_exec_sell, l_price, &l_need_q);

                if (compare256(a_criteria->budget, l_need_q) < 0) {
                    if (l_pct == 100) {
                        debug_if(s_debug_more, L_DEBUG,
                                 "{ %s, ledger path } Filter: skip order (AON violation); "
                                 "Tx: %s; Need Q: %s %s; Budget in Q: %s %s",
                                 __FUNCTION__, dap_chain_hash_fast_to_str_static(&it->cur_hash), dap_uint256_to_char_ex(l_need_q).frac,
                                 l_common_key->token_quote, dap_uint256_to_char_ex(a_criteria->budget).frac, l_common_key->token_quote);
                        continue;
                    }
                    if (l_pct > 0) {
                        // Partial fill: check if min_fill achievable with initial budget
                        uint256_t l_affordable_base = uint256_0;
                        DIV_256_COIN(a_criteria->budget, l_price, &l_affordable_base);
                        if (compare256(l_affordable_base, l_exec_min) < 0) {
                            debug_if(s_debug_more, L_DEBUG,
                                     "{ %s, ledger path } Filter: skip order (min fill violation); "
                                     "Tx: %s; Affordable B: %s %s < Exec min: %s (%d%%)",
                                     __FUNCTION__, dap_chain_hash_fast_to_str_static(&it->cur_hash),
                                     dap_uint256_to_char_ex(l_affordable_base).frac, l_common_key->token_base,
                                     dap_uint256_to_char_ex(l_exec_min).frac, l_pct);
                            continue;
                        }
                    }
                }
            }
        }
        // Compaction pass will apply actual budget constraints and trim if needed
        /* do not skip zero-exec candidates; final exec assigned after sorting */
        dap_hash_fast_t l_root = dap_ledger_get_first_chain_tx_hash(a_net->pub.ledger, tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
        if (dap_hash_fast_is_blank(&l_root))
            l_root = it->cur_hash; // ORDER: root=tail
        dex_match_table_entry_t *l_match = DAP_NEW_Z(dex_match_table_entry_t);
        *l_match =
            (dex_match_table_entry_t){{l_out->header.value, l_price, l_root, it->cur_hash, l_out->subtype.srv_dex.min_fill, l_out_idx},
                                      l_common_key,
                                      l_out->subtype.srv_dex.seller_addr,
                                      (uint8_t)((l_out->subtype.srv_dex.version & 0x7F) << 1) | (l_side_cur & 0x1),
                                      l_out->subtype.srv_dex.flags,
                                      tx->header.ts_created,
                                      l_out->header.ts_expires,
                                      l_exec_sell,
                                      .exec_min = l_exec_min};
        HASH_ADD(hh, l_res, match.tail, sizeof(l_match->match.tail), l_match);
    }
    dap_ledger_datum_iter_delete(it);
    debug_if(s_debug_more, L_DEBUG, "{ %s, ledger path } Ledger scan complete; Found: %d; Matched: %d; Res table size: %d", __FUNCTION__,
             l_orders_found, l_orders_matched, HASH_COUNT(l_res));
    // Ledger fallback: enforce best→worse by sorting and greedily reallocating budget
    if (l_res) {
        // Sort by price: INVERTED (buyer's BID matches sellers' ASK, sort as ASK)
        if (l_side == DEX_SIDE_ASK)
            HASH_SORT(l_res, s_cmp_match_entries_bid); // ASK buyer → BID sellers (rate DESC)
        else
            HASH_SORT(l_res, s_cmp_match_entries_ask); // BID buyer → ASK sellers (rate ASC)
        if (IS_ZERO_256(a_criteria->budget)) {
            if (a_out_leftover_budget)
                *a_out_leftover_budget = uint256_0;
            return l_res;
        }
        // Compact filter: consume budget level-by-level, trim if needed
        dex_match_table_entry_t *l_cur, *l_tmp;
        HASH_ITER(hh, l_res, l_cur, l_tmp)
        {
            if (IS_ZERO_256(l_budget)) {
                debug_if(s_debug_more, L_DEBUG, "{ %s, compaction } Skip order; Reason: budget exhausted; Tail: %s", __FUNCTION__,
                         dap_chain_hash_fast_to_str_static(&l_cur->match.tail));
                HASH_DEL(l_res, l_cur);
                DAP_DELETE(l_cur);
                continue;
            }

            // BASE budget: simple check
            // QUOTE budget: avoid double rounding (DIV+MULT) by checking order cost directly
            if (l_budget_in_base) {
                // BASE budget path
                debug_if(s_debug_more, L_DEBUG,
                         "{ %s, compaction } Order; Tail: %s; Value: %s BASE; Rate: %s; "
                         "Exec sell: %s BASE; Budget in B: %s %s; Exec min in B: %s %s",
                         __FUNCTION__, dap_chain_hash_fast_to_str_static(&l_cur->match.tail),
                         dap_uint256_to_char_ex(l_cur->match.value).frac, dap_uint256_to_char_ex(l_cur->match.rate).frac,
                         dap_uint256_to_char_ex(l_cur->exec_sell).frac, dap_uint256_to_char_ex(l_budget).frac, l_cur->pair_key->token_base,
                         dap_uint256_to_char_ex(l_cur->exec_min).frac, l_cur->pair_key->token_base);

                uint8_t l_pct = l_cur->match.min_fill & 0x7F;
                if (compare256(l_budget, l_cur->exec_sell) >= 0) {
                    // Full fill
                    SUBTRACT_256_256(l_budget, l_cur->exec_sell, &l_budget);
                    debug_if(s_debug_more, L_DEBUG,
                             "{ %s, compaction } Full fill; Tail: %s; Exec sell in B: %s %s; "
                             "Budget remaining in B: %s %s",
                             __FUNCTION__, dap_chain_hash_fast_to_str_static(&l_cur->match.tail),
                             dap_uint256_to_char_ex(l_cur->exec_sell).frac, l_cur->pair_key->token_base,
                             dap_uint256_to_char_ex(l_budget).frac, l_cur->pair_key->token_base);
                } else if (l_pct != 100 && compare256(l_budget, l_cur->exec_min) >= 0) {
                    // Partial fill (skip AON)
                    l_cur->exec_sell = l_budget;
                    // Calculate exec_quote for BID partial fill residual calc
                    MULT_256_COIN(l_cur->exec_sell, l_cur->match.rate, &l_cur->exec_quote);
                    l_budget = uint256_0;
                    debug_if(s_debug_more, L_DEBUG,
                             "{ %s, compaction } Partial fill; Tail: %s; Exec sell in B: %s %s; "
                             "Budget drained",
                             __FUNCTION__, dap_chain_hash_fast_to_str_static(&l_cur->match.tail),
                             dap_uint256_to_char_ex(l_cur->exec_sell).frac, l_cur->pair_key->token_base);
                } else {
                    // Reject: AON or min_fill not met
                    debug_if(s_debug_more, L_DEBUG,
                             "{ %s, compaction } Reject; Reason: %s; Tail: %s; "
                             "Exec min: %s; Budget in B: %s %s",
                             __FUNCTION__, l_pct == 100 ? "AON, budget insufficient" : "budget < exec_min",
                             dap_chain_hash_fast_to_str_static(&l_cur->match.tail), dap_uint256_to_char_ex(l_cur->exec_min).frac,
                             dap_uint256_to_char_ex(l_budget).frac, l_cur->pair_key->token_base);
                    HASH_DEL(l_res, l_cur);
                    DAP_DELETE(l_cur);
                    continue;
                }
            } else {
                // QUOTE budget path: check order cost FIRST to avoid DIV+MULT rounding loss
                uint256_t l_order_cost_quote;
                MULT_256_COIN(l_cur->exec_sell, l_cur->match.rate, &l_order_cost_quote);

                debug_if(s_debug_more, L_DEBUG,
                         "{ %s, compaction } Order; Tail: %s; Value in B: %s %s; Rate: %s; "
                         "Exec sell in B: %s %s; Cost in Q: %s %s; Budget in Q: %s %s; Exec min in B: %s %s",
                         __FUNCTION__, dap_chain_hash_fast_to_str_static(&l_cur->match.tail),
                         dap_uint256_to_char_ex(l_cur->match.value).frac, l_cur->pair_key->token_base,
                         dap_uint256_to_char_ex(l_cur->match.rate).frac, dap_uint256_to_char_ex(l_cur->exec_sell).frac,
                         l_cur->pair_key->token_base, dap_uint256_to_char_ex(l_order_cost_quote).frac, l_cur->pair_key->token_quote,
                         dap_uint256_to_char_ex(l_budget).frac, l_cur->pair_key->token_quote, dap_uint256_to_char_ex(l_cur->exec_min).frac,
                         l_cur->pair_key->token_base);

                uint8_t l_pct_q = l_cur->match.min_fill & 0x7F;
                if (compare256(l_budget, l_order_cost_quote) >= 0) {
                    // Full fill: deduct EXACT cost
                    SUBTRACT_256_256(l_budget, l_order_cost_quote, &l_budget);
                    debug_if(s_debug_more, L_DEBUG,
                             "{ %s, compaction } Full fill; Tail: %s; Exec sell in B: %s %s; "
                             "Cost in Q: %s %s; Budget remaining in Q: %s %s",
                             __FUNCTION__, dap_chain_hash_fast_to_str_static(&l_cur->match.tail),
                             dap_uint256_to_char_ex(l_cur->exec_sell).frac, l_cur->pair_key->token_base,
                             dap_uint256_to_char_ex(l_order_cost_quote).frac, l_cur->pair_key->token_quote,
                             dap_uint256_to_char_ex(l_budget).frac, l_cur->pair_key->token_quote);
                } else if (l_pct_q != 100) {
                    // Partial fill: budget < order_cost (skip AON)
                    // Calculate affordable BASE: this is where rounding happens (unavoidable)
                    uint256_t l_affordable_base;
                    DIV_256_COIN(l_budget, l_cur->match.rate, &l_affordable_base);
                    // Cap at order's available BASE (l_cur->exec_sell from snapshot)
                    // Note: match.value is QUOTE for BID, so can't compare directly
                    if (compare256(l_affordable_base, l_cur->exec_sell) > 0)
                        l_affordable_base = l_cur->exec_sell;

                    if (compare256(l_affordable_base, l_cur->exec_min) >= 0) {
                        l_cur->exec_sell = l_affordable_base;
                        l_cur->exec_quote = l_budget; // exact QUOTE spent (for BID partial fill residual calc)
                        // Spend ALL remaining budget (not exec_sell*rate which would lose wei)
                        l_budget = uint256_0;
                        debug_if(s_debug_more, L_DEBUG,
                                 "{ %s, compaction } Partial fill; Tail: %s; Exec sell in B: %s %s; "
                                 "Spent all remaining budget",
                                 __FUNCTION__, dap_chain_hash_fast_to_str_static(&l_cur->match.tail),
                                 dap_uint256_to_char_ex(l_cur->exec_sell).frac, l_cur->pair_key->token_base);
                    } else {
                        // Reject: min_fill not met
                        debug_if(s_debug_more, L_DEBUG,
                                 "{ %s, compaction } Reject; Reason: min fill violation; Tail: %s; "
                                 "Affordable base: %s < Exec min in B: %s %s",
                                 __FUNCTION__, dap_chain_hash_fast_to_str_static(&l_cur->match.tail),
                                 dap_uint256_to_char_ex(l_affordable_base).frac, dap_uint256_to_char_ex(l_cur->exec_min).frac,
                                 l_cur->pair_key->token_base);
                        HASH_DEL(l_res, l_cur);
                        DAP_DELETE(l_cur);
                        continue;
                    }
                } else {
                    // Reject: AON and budget insufficient
                    debug_if(s_debug_more, L_DEBUG,
                             "{ %s, compaction } Reject; Reason: AON, budget insufficient; "
                             "Tail: %s; Budget in Q: %s %s; Cost in Q: %s %s",
                             __FUNCTION__, dap_chain_hash_fast_to_str_static(&l_cur->match.tail), dap_uint256_to_char_ex(l_budget).frac,
                             l_cur->pair_key->token_quote, dap_uint256_to_char_ex(l_order_cost_quote).frac, l_cur->pair_key->token_quote);
                    HASH_DEL(l_res, l_cur);
                    DAP_DELETE(l_cur);
                    continue;
                }
            }
        }
        if (a_out_leftover_budget)
            *a_out_leftover_budget = l_budget;
    }
    if (!l_res)
        DAP_DELETE(l_common_key);
    return l_res;
}

// Add or update UTXO requirement for a token
static void s_dex_requirements_add_utxo(dex_tx_requirements_t *a_reqs, const char *a_ticker, uint256_t a_amount)
{
    dap_ret_if_any(!a_reqs, !a_ticker, IS_ZERO_256(a_amount));

    dex_utxo_requirement_t *l_req = NULL;
    HASH_FIND_STR(a_reqs->utxo_reqs, a_ticker, l_req);
    if (l_req) {
        SUM_256_256(l_req->amount, a_amount, &l_req->amount);
    } else {
        l_req = DAP_NEW_Z(dex_utxo_requirement_t);
        dap_stpcpy(l_req->ticker, a_ticker);
        l_req->amount = a_amount;
        HASH_ADD_STR(a_reqs->utxo_reqs, ticker, l_req);
    }
}

// Free resources allocated for requirements
static void s_dex_requirements_free(dex_tx_requirements_t *a_reqs)
{
    dap_ret_if_any(!a_reqs);
    dex_utxo_requirement_t *l_req, *l_tmp;
    HASH_ITER(hh, a_reqs->utxo_reqs, l_req, l_tmp)
    {
        HASH_DEL(a_reqs->utxo_reqs, l_req);
        DAP_DELETE(l_req);
    }
}

/* ============================================================================
 * TX Composition
 * UTXO collection, fee handling, seller payouts, TX building primitives
 * ============================================================================ */

// Collect UTXO inputs for a single token with cache fallback
// Returns 0 on success, negative on error
// a_out_transfer: actual amount collected (may exceed a_amount due to UTXO granularity)
static int s_dex_collect_utxo_for_ticker(dap_chain_net_t *a_net, const char *a_ticker, const dap_chain_addr_t *a_addr, uint256_t a_amount,
                                         dap_chain_datum_tx_t **a_tx, uint256_t *a_out_transfer)
{
    dap_ret_val_if_any(-1, !a_net, !a_ticker, !a_addr, !a_tx || !*a_tx, IS_ZERO_256(a_amount));

    dap_ledger_t *l_ledger = a_net->pub.ledger;
    dap_list_t *l_list_outs = NULL;
    uint256_t l_transfer = uint256_0;

    // Try cache first, fallback to ledger scan
    if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, a_ticker, a_addr, &l_list_outs, a_amount, &l_transfer) == -101)
        l_list_outs = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_ticker, a_addr, a_amount, &l_transfer);

    if (!l_list_outs)
        return log_it(L_WARNING, "Insufficient %s: need %s, no UTXOs found", a_ticker, dap_uint256_to_char_ex(a_amount).frac), -3;

    // Verify collected amount is sufficient
    if (compare256(l_transfer, a_amount) < 0) {
        dap_list_free_full(l_list_outs, NULL);
        return log_it(L_WARNING, "Insufficient %s: need %s, have %s", a_ticker, dap_uint256_to_char_ex(a_amount).frac,
                      dap_uint256_to_char_ex(l_transfer).frac),
               -3;
    }

    uint256_t l_added = dap_chain_datum_tx_add_in_item_list(a_tx, l_list_outs);
    dap_list_free_full(l_list_outs, NULL);

    if (!EQUAL_256(l_added, l_transfer))
        return log_it(L_ERROR, "Failed to add %s inputs to TX", a_ticker), -4;

    if (a_out_transfer)
        *a_out_transfer = l_transfer;

    return 0;
}

// Add validator fee item and network fee OUT to TX
// Returns 0 on success, negative on error
static int s_dex_add_fees_to_tx(dap_chain_datum_tx_t **a_tx, uint256_t a_validator_fee, uint256_t a_network_fee,
                                const dap_chain_addr_t *a_network_addr, const char *a_native_ticker)
{
    dap_ret_val_if_any(-1, !a_tx || !*a_tx);

    // Validator fee item (FEE_ITEM)
    if (!IS_ZERO_256(a_validator_fee) && dap_chain_datum_tx_add_fee_item(a_tx, a_validator_fee) != 1)
        return log_it(L_ERROR, "Failed to add validator fee item"), -2;

    // Network fee OUT (OUT_EXT to network address)
    if (!IS_ZERO_256(a_network_fee)) {
        dap_ret_val_if_any(-3, !a_network_addr || !a_native_ticker);
        if (dap_chain_datum_tx_add_out_std_item(a_tx, a_network_addr, a_network_fee, a_native_ticker, 0) != 1)
            return log_it(L_ERROR, "Failed to add network fee OUT"), -4;
    }
    return 0;
}

// Add cashback OUT if overpayment exists (transfer > needed)
// Returns 0 on success (including no cashback case), negative on error
static int s_dex_add_cashback(dap_chain_datum_tx_t **a_tx, uint256_t a_transfer, uint256_t a_needed, const dap_chain_addr_t *a_addr,
                              const char *a_ticker)
{
    dap_ret_val_if_any(-1, !a_tx || !*a_tx, !a_addr, !a_ticker);

    if (compare256(a_transfer, a_needed) <= 0)
        return 0; // No cashback needed

    uint256_t l_cashback = uint256_0;
    SUBTRACT_256_256(a_transfer, a_needed, &l_cashback);

    if (!IS_ZERO_256(l_cashback) && dap_chain_datum_tx_add_out_std_item(a_tx, a_addr, l_cashback, a_ticker, 0) == -1)
        return log_it(L_ERROR, "Failed to add cashback OUT"), -2;
    return 0;
}

// Sign TX with wallet key
// Returns 0 on success, negative on error
static int s_dex_sign_tx(dap_chain_datum_tx_t **a_tx, dap_chain_wallet_t *a_wallet)
{
    dap_return_val_if_fail_err(a_tx && *a_tx && a_wallet, -1, "Invalid parameters");

    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    if (!l_key)
        return log_it(L_ERROR, "Failed to get wallet key"), -2;

    int l_sign_res = dap_chain_datum_tx_add_sign_item(a_tx, l_key);
    dap_enc_key_delete(l_key);

    if (l_sign_res != 1)
        return log_it(L_ERROR, "Failed to sign TX"), -3;

    return 0;
}

// Add aggregated seller payouts from match table (+ optional service fee)
// Aggregates by address using linear search (optimal for typical N ≤ 10)
// Returns 0 on success, negative on error
static int s_dex_add_seller_payouts(dap_chain_datum_tx_t **a_tx, dex_match_table_entry_t *a_matches, const dap_chain_addr_t *a_service_addr,
                                    uint256_t a_service_fee, const char *a_token, bool a_apply_rate)
{
    dap_ret_val_if_any(-1, !a_tx || !*a_tx, !a_matches, !a_token);

    size_t l_match_count = HASH_COUNT(a_matches);
    size_t l_total_count = l_match_count + (a_service_addr && !IS_ZERO_256(a_service_fee) ? 1 : 0);

    if (l_total_count == 0)
        return 0;

    // Pre-allocate for worst case (all unique addresses)
    typedef struct {
        dap_chain_addr_t addr;
        uint256_t total;
    } aggregated_payout_t;

    aggregated_payout_t *l_aggregated = DAP_NEW_Z_COUNT(aggregated_payout_t, l_total_count);
    if (!l_aggregated)
        return log_it(L_ERROR, "Failed to allocate aggregated payouts"), -2;

    size_t l_aggregated_count = 0;

    // Aggregate sellers from match table
    dex_match_table_entry_t *l_cur, *l_tmp;
    HASH_ITER(hh, a_matches, l_cur, l_tmp)
    {
        uint256_t l_payout = l_cur->exec_sell;
        if (a_apply_rate)
            MULT_256_COIN(l_cur->exec_sell, l_cur->match.rate, &l_payout);
        debug_if(s_debug_more, L_DEBUG, "%s(): Payout for order %s: %s %s, exec sell: %s, rate %s %sapplied", __FUNCTION__,
                 dap_hash_fast_to_str_static(&l_cur->match.tail), dap_uint256_to_char_ex(l_payout).frac, a_token,
                 dap_uint256_to_char_ex(l_cur->exec_sell).frac, dap_uint256_to_char_ex(l_cur->match.rate).frac, a_apply_rate ? "" : "not ");

        // Linear search for existing address
        int l_found_idx = -1;
        for (size_t j = 0; j < l_aggregated_count; j++) {
            if (dap_chain_addr_compare(&l_cur->seller_addr, &l_aggregated[j].addr)) {
                l_found_idx = j;
                break;
            }
        }

        if (l_found_idx < 0) {
            // New address
            l_aggregated[l_aggregated_count].addr = l_cur->seller_addr;
            l_aggregated[l_aggregated_count].total = l_payout;
            l_aggregated_count++;
        } else {
            // Existing address: aggregate
            SUM_256_256(l_aggregated[l_found_idx].total, l_payout, &l_aggregated[l_found_idx].total);
        }
    }

    // Add service fee (if any)
    if (a_service_addr && !IS_ZERO_256(a_service_fee)) {
        int l_found_idx = -1;
        for (size_t j = 0; j < l_aggregated_count; j++) {
            if (dap_chain_addr_compare(a_service_addr, &l_aggregated[j].addr)) {
                l_found_idx = j;
                break;
            }
        }

        if (l_found_idx < 0) {
            l_aggregated[l_aggregated_count].addr = *a_service_addr;
            l_aggregated[l_aggregated_count].total = a_service_fee;
            l_aggregated_count++;
        } else
            SUM_256_256(l_aggregated[l_found_idx].total, a_service_fee, &l_aggregated[l_found_idx].total);
    }

    // Create OUTs from aggregated payouts
    int l_ret = 0;
    for (size_t i = 0; i < l_aggregated_count; i++) {
        if (dap_chain_datum_tx_add_out_std_item(a_tx, &l_aggregated[i].addr, l_aggregated[i].total, a_token, 0) == -1) {
            log_it(L_ERROR, "Failed to add aggregated seller payout OUT");
            l_ret = -3;
            break;
        }
    }

    DAP_DELETE(l_aggregated);
    return l_ret;
}

// Build transaction requirements (unified for ASK/BID)
// Direction extracted from matches->side_version (bit0: 0=BID, 1=ASK)
// Returns 0 on success, error code otherwise
static int s_dex_requirements_build(dap_chain_net_t *a_net, dex_match_table_entry_t *a_matches, uint256_t a_validator_fee,
                                    const dap_chain_addr_t *a_buyer_addr, dex_match_table_entry_t *a_partial_match,
                                    dex_tx_requirements_t *a_out_reqs)
{
    dap_ret_val_if_any(-1, !a_net, !a_matches, !a_out_reqs);

    // Extract pair and direction from first match (all matches share same pair/side)
    dex_match_table_entry_t *l_first = a_matches;
    uint8_t l_side = l_first->side_version & 0x1;
    debug_if(s_debug_more, L_DEBUG, "%s(): %s, %s / %s", __FUNCTION__, l_side == DEX_SIDE_ASK ? "ASK" : "BID",
             l_first->pair_key->token_base, l_first->pair_key->token_quote);
    *a_out_reqs = (dex_tx_requirements_t){(l_first->side_version & 0x1), l_first->pair_key->token_base, l_first->pair_key->token_quote,
                                          a_net->pub.native_ticker, .validator_fee = a_validator_fee};

    // Get service address first (needed for seller participation check in aggregation loop)
    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    dap_chain_addr_t l_service_addr = s_dex_service_fee_addr;
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    // bool l_seller_is_service = false;

    // Aggregate exec_sell and sellers_payout_quote from matches, check seller participation
    dex_match_table_entry_t *l_cur, *l_tmp;
    HASH_ITER(hh, a_matches, l_cur, l_tmp)
    {
        SUM_256_256(a_out_reqs->exec_sell, l_cur->exec_sell, &a_out_reqs->exec_sell);
        uint256_t l_buy_i = uint256_0;
        if (l_side == DEX_SIDE_BID) {
            // BID: Use exact QUOTE values to match verifier's l_executed_i calculation
            // For full fill: match.value (original QUOTE, no rounding)
            // For partial fill: exec_quote (set by matcher, no round-trip)
            if (l_cur == a_partial_match) {
                if (IS_ZERO_256(l_cur->exec_quote))
                    return log_it(L_ERROR, "%s(): exec_quote not set for BID partial fill!", __FUNCTION__), -5;
                l_buy_i = l_cur->exec_quote;
            } else
                l_buy_i = l_cur->match.value;
        } else
            // ASK: exec_sell (BASE) * rate → QUOTE
            MULT_256_COIN(l_cur->exec_sell, l_cur->match.rate, &l_buy_i);
        SUM_256_256(a_out_reqs->sellers_payout_quote, l_buy_i, &a_out_reqs->sellers_payout_quote);

        // Check if this seller is the service fee collector (for fee waiver)
        /* if (!l_seller_is_service && dap_chain_addr_compare(&l_cur->seller_addr, &l_service_addr))
            l_seller_is_service = true; */
    }

    // Get service fee from pair's fee_config
    uint8_t l_fee_cfg = l_first->pair_key->fee_config;
    a_out_reqs->fee_pct_mode = (l_fee_cfg & 0x80) != 0;

    // Set service address (already fetched above for seller check)
    a_out_reqs->service_addr = l_service_addr;

    if (a_out_reqs->fee_pct_mode) {
        // % fee from INPUT: ASK→QUOTE, BID→BASE (0.1% step)
        uint8_t l_pct = l_fee_cfg & 0x7F;
        if (l_pct > 127) {
            log_it(L_ERROR, "%s(): Invalid fee_config percentage: %d > 127", __FUNCTION__, l_pct);
            return -3;
        }
        // Check for blank service address (would burn tokens!)
        if (l_pct > 0 && dap_chain_addr_is_blank(&a_out_reqs->service_addr)) {
            log_it(L_ERROR, "%s(): Service fee address is blank, cannot create service fee OUT", __FUNCTION__);
            return -4;
        }

        if (l_pct > 0) {
            // INPUT = buyer's spend: QUOTE for ASK, BASE for BID
            uint256_t l_input = (l_side == DEX_SIDE_ASK) ? a_out_reqs->sellers_payout_quote // ASK: buyer spends QUOTE
                                                         : a_out_reqs->exec_sell;           // BID: buyer spends BASE
            uint256_t l_pct_256 = GET_256_FROM_64(l_pct);
            MULT_256_256(l_pct_256, l_input, &a_out_reqs->fee_srv);
            DIV_256(a_out_reqs->fee_srv, GET_256_FROM_64(1000), &a_out_reqs->fee_srv); // 0.1% step
        }
    } else {
        // NATIVE fee: per-pair or global fallback (0.01 token step)
        uint8_t l_mult = l_fee_cfg & 0x7F;
        if (l_mult > 0) {
            // Per-pair: multiplier × 0.01 native token
            a_out_reqs->fee_srv = GET_256_FROM_64((uint64_t)l_mult * DAP_DEX_FEE_UNIT_NATIVE);
        } else {
            // Global fallback
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            a_out_reqs->fee_srv = s_dex_native_fee_amount;
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
        }
        // Check for blank service address (would burn tokens!)
        if (!IS_ZERO_256(a_out_reqs->fee_srv) && dap_chain_addr_is_blank(&a_out_reqs->service_addr)) {
            log_it(L_ERROR, "%s(): Service fee address is blank, cannot create NATIVE service fee OUT", __FUNCTION__);
            return -4;
        }
    }

    // Waive only if service collector is BUYER; if SELLER, do not waive here
    if (!IS_ZERO_256(a_out_reqs->fee_srv) && !dap_chain_addr_is_blank(&a_out_reqs->service_addr))
        if (a_buyer_addr && dap_chain_addr_compare(a_buyer_addr, &a_out_reqs->service_addr)) {
            debug_if(s_debug_more, L_DEBUG, "%s(): Service fee waived: service collector is buyer", __FUNCTION__);
            a_out_reqs->fee_srv = uint256_0;
        }

    // Network fee
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &a_out_reqs->network_fee, &a_out_reqs->network_addr);

    if (l_side == DEX_SIDE_ASK) {
        // ASK: taker pays QUOTE + service_fee (if % mode, fee is in QUOTE)
        uint256_t l_quote_need = a_out_reqs->sellers_payout_quote;
        if (a_out_reqs->fee_pct_mode)
            SUM_256_256(l_quote_need, a_out_reqs->fee_srv, &l_quote_need);
        s_dex_requirements_add_utxo(a_out_reqs, a_out_reqs->ticker_quote, l_quote_need);

        // Native fees (validator + network + service_native)
        if (dap_strcmp(a_out_reqs->ticker_quote, a_out_reqs->ticker_native)) {
            uint256_t l_native_need = a_validator_fee;
            if (l_net_fee_used)
                SUM_256_256(l_native_need, a_out_reqs->network_fee, &l_native_need);
            if (!a_out_reqs->fee_pct_mode)
                SUM_256_256(l_native_need, a_out_reqs->fee_srv, &l_native_need);
            if (!IS_ZERO_256(l_native_need))
                s_dex_requirements_add_utxo(a_out_reqs, a_out_reqs->ticker_native, l_native_need);
        } else {
            // QUOTE==NATIVE: fold native fees into QUOTE
            uint256_t l_native_fees = a_validator_fee;
            if (l_net_fee_used)
                SUM_256_256(l_native_fees, a_out_reqs->network_fee, &l_native_fees);
            if (!a_out_reqs->fee_pct_mode)
                SUM_256_256(l_native_fees, a_out_reqs->fee_srv, &l_native_fees);
            if (!IS_ZERO_256(l_native_fees))
                s_dex_requirements_add_utxo(a_out_reqs, a_out_reqs->ticker_quote, l_native_fees);
        }

        debug_if(s_debug_more, L_DEBUG,
                 "%s(): Built requirement for ASK; Exec sell in B: %s %s; "
                 "Sellers payout in Q: %s %s; Service fee in %s: %s",
                 __FUNCTION__, dap_uint256_to_char_ex(a_out_reqs->exec_sell).frac, a_out_reqs->ticker_base,
                 dap_uint256_to_char_ex(a_out_reqs->sellers_payout_quote).frac, a_out_reqs->ticker_quote,
                 a_out_reqs->fee_pct_mode ? "Q" : "native", dap_uint256_to_char_ex(a_out_reqs->fee_srv).frac);
    } else {
        // BID: taker spends BASE + service_fee (if % mode, fee is in BASE), receives QUOTE

        // Taker provides BASE + service fee (if % mode)
        uint256_t l_base_need = a_out_reqs->exec_sell;
        if (a_out_reqs->fee_pct_mode)
            SUM_256_256(l_base_need, a_out_reqs->fee_srv, &l_base_need);
        s_dex_requirements_add_utxo(a_out_reqs, a_out_reqs->ticker_base, l_base_need);

        // Native fees (validator + network + service_native)
        if (dap_strcmp(a_out_reqs->ticker_base, a_out_reqs->ticker_native)) {
            uint256_t l_native_need = a_validator_fee;
            if (l_net_fee_used)
                SUM_256_256(l_native_need, a_out_reqs->network_fee, &l_native_need);
            if (!a_out_reqs->fee_pct_mode)
                SUM_256_256(l_native_need, a_out_reqs->fee_srv, &l_native_need);
            if (!IS_ZERO_256(l_native_need))
                s_dex_requirements_add_utxo(a_out_reqs, a_out_reqs->ticker_native, l_native_need);
        } else {
            // BASE==NATIVE: fold native fees into BASE (already in l_base_need if % mode)
            uint256_t l_native_fees = a_validator_fee;
            if (l_net_fee_used)
                SUM_256_256(l_native_fees, a_out_reqs->network_fee, &l_native_fees);
            if (!a_out_reqs->fee_pct_mode)
                SUM_256_256(l_native_fees, a_out_reqs->fee_srv, &l_native_fees);
            if (!IS_ZERO_256(l_native_fees))
                s_dex_requirements_add_utxo(a_out_reqs, a_out_reqs->ticker_base, l_native_fees);
        }

        debug_if(s_debug_more, L_DEBUG,
                 "%s(): Built requirement for BID; Taker spends B: %s %s; Sellers payout in Q: %s %s; "
                 "Service fee in %s: %s; Taker gets Q: %s %s",
                 __FUNCTION__, dap_uint256_to_char_ex(l_base_need).frac, a_out_reqs->ticker_base,
                 dap_uint256_to_char_ex(a_out_reqs->sellers_payout_quote).frac, a_out_reqs->ticker_quote,
                 a_out_reqs->fee_pct_mode ? "B" : "native", dap_uint256_to_char_ex(a_out_reqs->fee_srv).frac,
                 dap_uint256_to_char_ex(a_out_reqs->sellers_payout_quote).frac, a_out_reqs->ticker_quote);
    }
    return 0;
}

// Collect UTXO inputs per token requirements
// Returns 0 on success, negative on error
// Updates l_req->transfer with actually collected amount
static int s_dex_collect_inputs_by_requirements(dap_chain_net_t *a_net, dap_chain_wallet_t *a_wallet, dex_tx_requirements_t *a_reqs,
                                                dap_chain_datum_tx_t **a_tx)
{
    dap_ret_val_if_any(-1, !a_net, !a_reqs, a_reqs && !a_reqs->utxo_reqs, !a_tx || !*a_tx);
    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_wallet_addr)
        return log_it(L_ERROR, "Can't get wallet address"), -2;
    dap_chain_addr_t l_addr = *l_wallet_addr;
    DAP_DELETE(l_wallet_addr);

    dex_utxo_requirement_t *l_req, *l_tmp;
    HASH_ITER(hh, a_reqs->utxo_reqs, l_req, l_tmp)
    {
        if (IS_ZERO_256(l_req->amount))
            continue;

        dap_list_t *l_list_outs = NULL;
        l_req->transfer = uint256_0;
        if (s_dex_collect_utxo_for_ticker(a_net, l_req->ticker, &l_addr, l_req->amount, a_tx, &l_req->transfer) < 0)
            return log_it(L_WARNING, "Failed to collect %s %s", dap_uint256_to_char_ex(l_req->amount).frac, l_req->ticker), -3;

        log_it(L_DEBUG, "Added %s %s inputs, needed %s", dap_uint256_to_char_ex(l_req->transfer).frac, l_req->ticker,
               dap_uint256_to_char_ex(l_req->amount).frac);
    }
    return 0;
}

static dap_chain_datum_tx_t *s_dex_compose_from_match_table(dap_chain_net_t *a_net, dap_chain_wallet_t *a_wallet, uint256_t a_fee,
                                                            uint256_t a_leftover_budget, bool a_is_budget_buy,
                                                            bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate,
                                                            dex_match_table_entry_t *a_matches)
{
    dap_ret_val_if_any(NULL, !a_net, !a_wallet, !a_matches);

    // Get taker (buyer) address
    dap_chain_addr_t *l_wal_tmp = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_wal_tmp)
        return NULL;
    dap_chain_addr_t l_buyer_addr = *l_wal_tmp;
    DAP_DELETE(l_wal_tmp);

    // Extract pair info from first match (all matches share same pair)
    dex_match_table_entry_t *l_match0 = a_matches, *l_last = HASH_LAST(a_matches);
    dex_pair_key_t *l_key0 = l_match0->pair_key;
    // pair_key is CANONICAL: token_base < token_quote lexicographically (from s_pair_normalize)
    const char *l_token_quote = l_key0->token_quote, *l_token_base = l_key0->token_base;

    // Detect partial match and best rate (needed for UPDATE ordering and leftover)
    // After both aggregator functions, table is guaranteed sorted by price (best→worse)
    // Partial match (if exists) is guaranteed to be the LAST entry (budget exhaustion point)
    dex_match_table_entry_t *l_partial_match = NULL, *l_cur_match, *l_tmp;

    // Best rate is the first entry (table sorted by price best→worse)
    uint256_t l_best_rate = l_match0->match.rate;

    // Check ALL matches for partial fills (exec_sell < full_exec_sell indicates budget trim)
    // Convert match.value to BASE for comparison (match.value is ORDER context: BASE for ASK, QUOTE for BID)
    HASH_ITER(hh, a_matches, l_cur_match, l_tmp)
    {
        uint256_t l_full_base = uint256_0;
        if (l_match0->side_version & 0x1)                                                  // BID
            DIV_256_COIN(l_cur_match->match.value, l_cur_match->match.rate, &l_full_base); // QUOTE→BASE
        else                                                                               // ASK
            l_full_base = l_cur_match->match.value;                                        // Already BASE

        if (compare256(l_full_base, l_cur_match->exec_sell) > 0) {
            if (l_partial_match) {
                log_it(L_CRITICAL, "Multiple partial matches detected!");
                return NULL;
            }
            l_partial_match = l_cur_match;
            debug_if(s_debug_more, L_DEBUG,
                     "%s(): Got partial fill: %s; Tx %s; Value: %s; Rate: %s; Full B: %s; Exec sell: %s, Token B: %s", __FUNCTION__,
                     (l_match0->side_version & 0x1) == DEX_SIDE_ASK ? "ASK" : "BID", dap_hash_fast_to_str_static(&l_cur_match->match.tail),
                     dap_uint256_to_char_ex(l_cur_match->match.value).frac, dap_uint256_to_char_ex(l_cur_match->match.rate).frac,
                     dap_uint256_to_char_ex(l_full_base).frac, dap_uint256_to_char_ex(l_cur_match->exec_sell).frac,
                     l_cur_match->pair_key->token_base);
        }
    }

    // Get buyer address (needed for requirements_build to check fee waiver)
    dap_chain_addr_t *l_buyer_addr_tmp = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_buyer_addr_tmp)
        return log_it(L_ERROR, "Failed to get buyer address from wallet"), NULL;
    dap_chain_addr_t l_buyer_addr_val = *l_buyer_addr_tmp;
    DAP_DELETE(l_buyer_addr_tmp);

    // Self-purchase check: buyer cannot be any of the sellers
    HASH_ITER(hh, a_matches, l_cur_match, l_tmp)
    {
        if (dap_chain_addr_compare(&l_buyer_addr_val, &l_cur_match->seller_addr))
            return log_it(L_ERROR, "Self-purchase not allowed: buyer is seller %s", dap_chain_addr_to_str_static(&l_buyer_addr_val)), NULL;
    }

    // Build requirements (includes fee waiver check internally)
    dex_tx_requirements_t l_reqs;
    if (s_dex_requirements_build(a_net, a_matches, a_fee, &l_buyer_addr_val, l_partial_match, &l_reqs))
        return log_it(L_ERROR, "Failed to build requirements"), NULL;

    // Validate budget: check if wallet has enough funds before collecting inputs
    // Use utxo_reqs to determine actual required amounts (already computed by s_dex_requirements_build)
    // This check is redundant with collection failure, but provides early error with clearer message
    // NOTE: We only check the primary payment token here; collection will verify all tokens

    // Determine primary payment token (ASK: taker pays QUOTE, BID: taker pays BASE)
    const char *l_payment_ticker = (l_reqs.side == DEX_SIDE_ASK) ? l_reqs.ticker_quote : l_reqs.ticker_base;
    dap_chain_datum_tx_t *l_tx = NULL;
    int l_err_line = 0;
#define RET_ERR                                                                                                                            \
    do {                                                                                                                                   \
        l_err_line = __LINE__;                                                                                                             \
        goto dex_compose_ret;                                                                                                              \
    } while (0)
    // Get required amount from utxo_reqs (already includes leftover if flag=true)
    dex_utxo_requirement_t *l_payment_req = NULL;
    HASH_FIND_STR(l_reqs.utxo_reqs, l_payment_ticker, l_payment_req);

    if (l_payment_req && !IS_ZERO_256(l_payment_req->amount)) {
        uint256_t l_wallet_balance = dap_ledger_calc_balance(a_net->pub.ledger, &l_buyer_addr_val, l_payment_ticker);

        if (compare256(l_payment_req->amount, l_wallet_balance) > 0) {
            log_it(L_WARNING, "Insufficient funds: need %s %s, wallet has %s", dap_uint256_to_char_ex(l_payment_req->amount).frac,
                   l_payment_ticker, dap_uint256_to_char_ex(l_wallet_balance).frac);
            RET_ERR;
        }
    }

    // Create TX and collect inputs using universal collector
    l_tx = dap_chain_datum_tx_create();
    if (!l_tx)
        RET_ERR;

    // Add buyer-leftover to utxo_reqs if creating order from leftover
    // Leftover order continues Bob's intent:
    //   Matched ASK → Bob buys BASE → leftover BID (sell QUOTE)
    //   Matched BID → Bob sells BASE → leftover ASK (sell BASE)
    bool l_leftover_in_quote = (l_reqs.side == DEX_SIDE_ASK) != a_is_budget_buy;
    uint256_t l_leftover_rate = !IS_ZERO_256(a_leftover_rate) ? a_leftover_rate : l_best_rate;
    bool l_create_buyer_leftover = a_create_buyer_order_on_leftover && !IS_ZERO_256(a_leftover_budget);
    if (l_create_buyer_leftover) {
        // Collect the SELL token for leftover order (may need conversion)
        const char *l_leftover_sell_ticker = (l_reqs.side == DEX_SIDE_ASK) ? l_token_quote : l_token_base;
        uint256_t l_leftover_sell_amount = uint256_0;
        if (l_reqs.side == DEX_SIDE_ASK) {
            // BID leftover needs QUOTE; convert from BASE if budget was in BASE
            if (l_leftover_in_quote)
                l_leftover_sell_amount = a_leftover_budget;
            else
                MULT_256_COIN(a_leftover_budget, l_leftover_rate, &l_leftover_sell_amount);
        } else {
            // ASK leftover needs BASE; convert from QUOTE if budget was in QUOTE
            if (!l_leftover_in_quote)
                l_leftover_sell_amount = a_leftover_budget;
            else
                DIV_256_COIN(a_leftover_budget, l_leftover_rate, &l_leftover_sell_amount);
        }
        // Skip dust buyer-leftover: don't collect tokens, don't create OUT_COND
        uint256_t l_fixed_native = a_fee;
        if (!IS_ZERO_256(l_reqs.network_fee))
            SUM_256_256(l_fixed_native, l_reqs.network_fee, &l_fixed_native);
        if (!l_reqs.fee_pct_mode && !IS_ZERO_256(l_reqs.fee_srv))
            SUM_256_256(l_fixed_native, l_reqs.fee_srv, &l_fixed_native);
        uint8_t l_fee_cfg_eff = l_key0->fee_config;
        if (dap_chain_addr_compare(&l_buyer_addr_val, &l_reqs.service_addr))
            l_fee_cfg_eff &= 0x80; // percent fee waived (pct=0), native fee waived (abs=0 via fee_srv)
        const char *l_leftover_buy_ticker = (l_reqs.side == DEX_SIDE_ASK) ? l_token_base : l_token_quote;
        bool l_leftover_is_bid = (l_reqs.side == DEX_SIDE_ASK);
        uint256_t l_leftover_thr = s_dex_calc_dust_threshold(l_leftover_sell_ticker, l_leftover_buy_ticker, l_reqs.ticker_native,
                                                             l_fee_cfg_eff, l_leftover_rate, l_leftover_is_bid, l_fixed_native);
        if (!IS_ZERO_256(l_leftover_thr) && compare256(l_leftover_sell_amount, l_leftover_thr) <= 0) {
            debug_if(s_debug_more, L_DEBUG, "%s(): Buyer-leftover %s %s below dust threshold %s, skipping", __FUNCTION__,
                     dap_uint256_to_char_ex(l_leftover_sell_amount).frac, l_leftover_sell_ticker,
                     dap_uint256_to_char_ex(l_leftover_thr).frac);
            l_create_buyer_leftover = false;
        } else {
            s_dex_requirements_add_utxo(&l_reqs, l_leftover_sell_ticker, l_leftover_sell_amount);
            debug_if(s_debug_more, L_DEBUG, "%s(): Added buyer-leftover %s %s to UTXO requirements", __FUNCTION__,
                     dap_uint256_to_char_ex(l_leftover_sell_amount).frac, l_leftover_sell_ticker);
        }
    }

    if (s_dex_collect_inputs_by_requirements(a_net, a_wallet, &l_reqs, &l_tx) != 0) {
        log_it(L_ERROR, "%s(): Failed to collect inputs", __FUNCTION__);
        RET_ERR;
    }
    // IN_COND: partial first only!
    // Spend sellers' SRV_DEX outs: partial (if any) first so that its residual UPDATE is appended after payouts
    if (l_partial_match) {
        int l_idx = l_partial_match->match.prev_idx;
        if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_partial_match->match.tail, l_idx < 0 ? 0 : l_idx, 0) != 1) {
            RET_ERR;
        }
        debug_if(s_debug_more, L_DEBUG, "%s(): Added partial IN_COND, Root: %s, Tail: %s, Prev idx: %d, Value: %s", __FUNCTION__,
                 dap_hash_fast_to_str_static(&l_partial_match->match.root), dap_hash_fast_to_str_static(&l_partial_match->match.tail),
                 l_idx, dap_uint256_to_char_ex(l_partial_match->match.value).str);
    }
    HASH_ITER(hh, a_matches, l_cur_match, l_tmp)
    {
        if (l_partial_match == l_cur_match)
            continue;
        int l_idx = l_cur_match->match.prev_idx;
        if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_cur_match->match.tail, l_idx < 0 ? 0 : l_idx, 0) != 1)
            RET_ERR;
        debug_if(s_debug_more, L_DEBUG, "%s(): Added full IN_COND, Root: %s, Tail: %s, Prev idx: %d, Value: %s", __FUNCTION__,
                 dap_hash_fast_to_str_static(&l_cur_match->match.root), dap_hash_fast_to_str_static(&l_cur_match->match.tail), l_idx,
                 dap_uint256_to_char_ex(l_cur_match->match.value).str);
    }

    // OUTs depend on direction (ASK vs BID)
    // Service fee aggregation: when seller == service_addr AND fee_token == seller's payout token
    // Service fee aggregation:
    // - % mode: fee token = INPUT token (ASK→QUOTE, BID→BASE)
    // - Native mode: fee token = NATIVE
    // Aggregation happens when seller == service_addr AND seller's payout token == fee token
    bool l_srv_fee_used = !IS_ZERO_256(l_reqs.fee_srv), l_native_is_quote = !strcmp(l_reqs.ticker_native, l_token_quote),
         l_native_is_base = !strcmp(l_reqs.ticker_native, l_token_base);

    if (l_reqs.side == DEX_SIDE_ASK) {
        // ASK: taker buys BASE, pays QUOTE
        // Fee in QUOTE (% mode) or NATIVE

        // 1. Buyer receives BASE
        if (dap_chain_datum_tx_add_out_std_item(&l_tx, &l_buyer_addr, l_reqs.exec_sell, l_token_base, 0) == -1)
            RET_ERR;

        // 2. Sellers receive QUOTE + Service fee (aggregated if fee token == QUOTE)
        // % mode: fee in QUOTE → always aggregate; Native mode: aggregate if NATIVE==QUOTE
        bool l_can_agg_ask = l_reqs.fee_pct_mode || l_native_is_quote;
        const dap_chain_addr_t *l_srv_addr = (l_can_agg_ask && l_srv_fee_used) ? &l_reqs.service_addr : NULL;
        uint256_t l_srv_fee_agg = l_srv_addr ? l_reqs.fee_srv : uint256_0;
        if (s_dex_add_seller_payouts(&l_tx, a_matches, l_srv_addr, l_srv_fee_agg, l_token_quote, true) < 0)
            RET_ERR;
    } else {
        // BID: taker spends BASE, receives QUOTE
        // Fee in BASE (% mode) or NATIVE

        // 1. Buyer receives QUOTE (full amount, no deduction — fee is in BASE now)
        if (dap_chain_datum_tx_add_out_std_item(&l_tx, &l_buyer_addr, l_reqs.sellers_payout_quote, l_token_quote, 0) == -1)
            RET_ERR;

        // 2. Sellers receive BASE + Service fee (aggregated if fee token == BASE)
        // % mode: fee in BASE → always aggregate; Native mode: aggregate if NATIVE==BASE
        bool l_can_agg_bid = l_reqs.fee_pct_mode || l_native_is_base;
        const dap_chain_addr_t *l_srv_addr_bid = (l_can_agg_bid && l_srv_fee_used) ? &l_reqs.service_addr : NULL;
        uint256_t l_srv_fee_agg_bid = l_srv_addr_bid ? l_reqs.fee_srv : uint256_0;
        if (s_dex_add_seller_payouts(&l_tx, a_matches, l_srv_addr_bid, l_srv_fee_agg_bid, l_token_base, false) < 0)
            RET_ERR;
    }

    // 3. Add fees (validator + network)
    if (s_dex_add_fees_to_tx(&l_tx, a_fee, l_reqs.network_fee, &l_reqs.network_addr, l_reqs.ticker_native) < 0)
        RET_ERR;
    debug_if(s_debug_more, L_DEBUG, "%s(): Added net fee and validator's fee %s %s", __FUNCTION__,
             dap_uint256_to_char_ex(l_reqs.network_fee).frac, l_reqs.ticker_native);

    // 4. Service fee in NATIVE (if not aggregated above)
    // % mode: always aggregated to seller payout; Native mode: separate OUT if not aggregated
    bool l_srv_fee_aggregated =
        l_reqs.fee_pct_mode || (l_reqs.side == DEX_SIDE_ASK && l_native_is_quote) || (l_reqs.side == DEX_SIDE_BID && l_native_is_base);
    if (!l_srv_fee_aggregated && l_srv_fee_used) {
        if (dap_chain_datum_tx_add_out_std_item(&l_tx, &l_reqs.service_addr, l_reqs.fee_srv, l_reqs.ticker_native, 0) == -1)
            RET_ERR;
        debug_if(s_debug_more, L_DEBUG, "%s(): Added service fee OUT in native: %s %s", __FUNCTION__,
                 dap_uint256_to_char_ex(l_reqs.fee_srv).frac, l_reqs.ticker_native);
    }

    // 5. Cashback (per token from UTXO overpayment) — always separate OUTs for uniformity
    dex_utxo_requirement_t *l_req, *l_req_tmp;
    HASH_ITER(hh, l_reqs.utxo_reqs, l_req, l_req_tmp)
    {
        if (compare256(l_req->transfer, l_req->amount) <= 0)
            continue; // No overpayment

        uint256_t l_cashback;
        SUBTRACT_256_256(l_req->transfer, l_req->amount, &l_cashback);

        if (dap_chain_datum_tx_add_out_std_item(&l_tx, &l_buyer_addr, l_cashback, l_req->ticker, 0) == -1)
            RET_ERR;
        debug_if(s_debug_more, L_DEBUG, "%s(): Added cashback %s %s to buyer", __FUNCTION__, dap_uint256_to_char_ex(l_cashback).frac,
                 l_req->ticker);
    }
    // Buyer leftover and seller residual are mutually exclusive:
    // - leftover: budget NOT exhausted, all matches fully executed → no partial match
    // - residual: budget exhausted on partial match → no leftover
    // Only ONE OUT_COND (EXCHANGE or UPDATE) can be created per TX
    if (!IS_ZERO_256(a_leftover_budget)) {
        // Buyer leftover: budget not exhausted
        if (l_partial_match) {
            log_it(L_ERROR, "Invalid state: buyer leftover and partial match are mutually exclusive!");
            RET_ERR;
        }

        if (l_create_buyer_leftover) {
            // Create EXCHANGE order from leftover that CONTINUES Bob's intent:
            //   Matched ASK → Bob buys BASE → leftover BID (sell QUOTE, buy BASE)
            //   Matched BID → Bob sells BASE → leftover ASK (sell BASE, buy QUOTE)
            uint256_t l_rate_new = !IS_ZERO_256(a_leftover_rate) ? a_leftover_rate : l_best_rate;
            if (IS_ZERO_256(l_rate_new))
                RET_ERR;

            // Calculate sell value (may need conversion if budget token != sell token)
            uint256_t l_leftover_sell_value = uint256_0;
            dap_chain_tx_out_cond_t *l_out_cond = NULL;

            if (l_reqs.side == DEX_SIDE_ASK) {
                // Matched ASK → create BID: sell QUOTE, buy BASE
                if (l_leftover_in_quote)
                    l_leftover_sell_value = a_leftover_budget; // already in QUOTE
                else
                    MULT_256_COIN(a_leftover_budget, l_rate_new, &l_leftover_sell_value); // BASE→QUOTE
                l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_dex((dap_chain_net_srv_uid_t){.uint64 = DAP_CHAIN_NET_SRV_DEX_ID},
                                                                             l_key0->net_id_quote, l_leftover_sell_value, // sell QUOTE
                                                                             l_key0->net_id_base, l_token_base,           // buy BASE
                                                                             l_rate_new, &l_buyer_addr, NULL, 0, 1, 0, DEX_TX_TYPE_EXCHANGE,
                                                                             NULL, 0);
            } else {
                // Matched BID → create ASK: sell BASE, buy QUOTE
                if (!l_leftover_in_quote)
                    l_leftover_sell_value = a_leftover_budget; // already in BASE
                else
                    DIV_256_COIN(a_leftover_budget, l_rate_new, &l_leftover_sell_value); // QUOTE→BASE
                l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_dex(
                    (dap_chain_net_srv_uid_t){.uint64 = DAP_CHAIN_NET_SRV_DEX_ID}, l_key0->net_id_base, l_leftover_sell_value, // sell BASE
                    l_key0->net_id_quote, l_token_quote,                                                                       // buy QUOTE
                    l_rate_new, &l_buyer_addr, NULL, 0, 1, 0, DEX_TX_TYPE_EXCHANGE, NULL, 0);
            }

            if (!l_out_cond || dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out_cond) == -1) {
                DAP_DEL_Z(l_out_cond);
                RET_ERR;
            }
            debug_if(s_debug_more, L_DEBUG, "%s(): Adding buyer-leftover OUT_COND; Side: %s; Sell: %s %s; Buy: %s; Rate: %s", __FUNCTION__,
                     l_reqs.side == DEX_SIDE_ASK ? "BID" : "ASK", dap_uint256_to_char_ex(l_leftover_sell_value).frac,
                     l_reqs.side == DEX_SIDE_ASK ? l_token_quote : l_token_base, l_reqs.side == DEX_SIDE_ASK ? l_token_base : l_token_quote,
                     dap_uint256_to_char_ex(l_rate_new).frac);
            DAP_DELETE(l_out_cond);
        }
        // flag=false: leftover is ignored (neither collected, nor refunded)
    } else if (l_partial_match) {
        // Seller residual (partial fill): budget exhausted, remaining liquidity re-issued as EXCHANGE
        // This is mutually exclusive with buyer leftover (checked above)
        // Calculate residual in ORDER context (seller's token):
        //   ASK: match.value (BASE) - exec_sell (BASE) → BASE
        //   BID: match.value (QUOTE) - exec_sell*rate (QUOTE) → QUOTE
        uint256_t l_residual = uint256_0;
        if (l_reqs.side == DEX_SIDE_ASK) {
            // ASK: both in BASE, no conversion needed
            SUBTRACT_256_256(l_partial_match->match.value, l_partial_match->exec_sell, &l_residual);
        } else {
            // BID: use exec_quote directly (set by matcher for all partial fills)
            // This avoids round-trip error from exec_sell * rate
            // Verifier computes: expected = exec_quote / rate = exec_sell (same division as matcher)
            if (IS_ZERO_256(l_partial_match->exec_quote)) {
                log_it(L_ERROR, "%s(): exec_quote not set for BID partial fill!", __FUNCTION__);
                RET_ERR;
            }
            SUBTRACT_256_256(l_partial_match->match.value, l_partial_match->exec_quote, &l_residual);
            debug_if(s_debug_more, L_DEBUG, "{ %s, residual } BID; Exec Q: %s %s; Residual: %s %s", __FUNCTION__,
                     dap_uint256_to_char_ex(l_partial_match->exec_quote).str, l_token_quote, dap_uint256_to_char_ex(l_residual).str,
                     l_token_quote);
        }
        const char *l_residual_ticker = (l_reqs.side == DEX_SIDE_ASK) ? l_token_base : l_token_quote;
        debug_if(s_debug_more, L_DEBUG,
                 "{ %s, residual } Seller residual; Side: %s; Tail: %s; "
                 "Value: %s %s; Exec sell in B: %s %s; Residual: %s %s",
                 __FUNCTION__, l_reqs.side == DEX_SIDE_ASK ? "ASK" : "BID", dap_chain_hash_fast_to_str_static(&l_partial_match->match.tail),
                 dap_uint256_to_char_ex(l_partial_match->match.value).str, l_residual_ticker,
                 dap_uint256_to_char_ex(l_partial_match->exec_sell).str, l_token_base, dap_uint256_to_char_ex(l_residual).str,
                 l_residual_ticker);
        if (!IS_ZERO_256(l_residual)) {
            uint256_t l_fixed_native = a_fee;
            if (!IS_ZERO_256(l_reqs.network_fee))
                SUM_256_256(l_fixed_native, l_reqs.network_fee, &l_fixed_native);
            if (!l_reqs.fee_pct_mode && !IS_ZERO_256(l_reqs.fee_srv))
                SUM_256_256(l_fixed_native, l_reqs.fee_srv, &l_fixed_native);
            uint8_t l_fee_cfg_eff = l_key0->fee_config;
            if (dap_chain_addr_compare(&l_buyer_addr_val, &l_reqs.service_addr))
                l_fee_cfg_eff &= 0x80;
            const char *l_buy_ticker = (l_reqs.side == DEX_SIDE_ASK) ? l_token_quote : l_token_base;
            bool l_is_bid = (l_reqs.side == DEX_SIDE_BID);
            uint256_t l_dust_thr = s_dex_calc_dust_threshold(l_residual_ticker, l_buy_ticker, l_reqs.ticker_native, l_fee_cfg_eff,
                                                             l_partial_match->match.rate, l_is_bid, l_fixed_native);
            if (!IS_ZERO_256(l_dust_thr) && compare256(l_residual, l_dust_thr) <= 0) {
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_partial_match->seller_addr, l_residual, l_residual_ticker) != 1)
                    RET_ERR;
                debug_if(s_debug_more, L_DEBUG, "{ %s, residual } Dust refund OUT_EXT; Seller: %s; Value: %s %s; Threshold: %s",
                         __FUNCTION__, dap_chain_addr_to_str_static(&l_partial_match->seller_addr), dap_uint256_to_char_ex(l_residual).frac,
                         l_residual_ticker, dap_uint256_to_char_ex(l_dust_thr).frac);
                goto dex_compose_sign;
            }
            // Re-issue EXCHANGE (seller residual) preserving order parameters (root/min_fill/version/flags)
            // Direction matters: ASK sells BASE, BID sells QUOTE
            // Rate is ALWAYS stored in canonical form (QUOTE/BASE) for both ASK and BID
            uint256_t l_rate = l_partial_match->match.rate;
            dap_chain_tx_out_cond_t *l_out_cond = NULL;
            if (l_reqs.side == DEX_SIDE_ASK) {
                // ASK residual: seller still sells BASE, buys QUOTE
                l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_dex(
                    (dap_chain_net_srv_uid_t){.uint64 = DAP_CHAIN_NET_SRV_DEX_ID}, l_key0->net_id_base, l_residual, l_key0->net_id_quote,
                    l_token_quote, l_rate, &l_partial_match->seller_addr, &l_partial_match->match.root, l_partial_match->match.min_fill,
                    (l_partial_match->side_version >> 1), l_partial_match->flags, DEX_TX_TYPE_EXCHANGE, NULL, 0);
            } else {
                // BID residual: seller still sells QUOTE, buys BASE
                l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_dex(
                    (dap_chain_net_srv_uid_t){.uint64 = DAP_CHAIN_NET_SRV_DEX_ID}, l_key0->net_id_quote, l_residual, l_key0->net_id_base,
                    l_token_base, l_rate, &l_partial_match->seller_addr, &l_partial_match->match.root, l_partial_match->match.min_fill,
                    (l_partial_match->side_version >> 1), l_partial_match->flags, DEX_TX_TYPE_EXCHANGE, NULL, 0);
            }
            int l_add_out_cond_res = -1;
            if (l_out_cond) {
                debug_if(s_debug_more, L_DEBUG,
                         "{ %s, residual } Adding seller-leftover OUT_COND; Side: %s; "
                         "Root: %s; Seller: %s; Sell: %s %s; Buy: %s; Rate: %s",
                         __FUNCTION__, l_reqs.side == DEX_SIDE_ASK ? "ASK" : "BID",
                         dap_chain_hash_fast_to_str_static(&l_partial_match->match.root),
                         dap_chain_addr_to_str_static(&l_partial_match->seller_addr), dap_uint256_to_char_ex(l_residual).frac,
                         (l_reqs.side == DEX_SIDE_ASK) ? l_token_base : l_token_quote,
                         (l_reqs.side == DEX_SIDE_ASK) ? l_token_quote : l_token_base, dap_uint256_to_char_ex(l_rate).frac);
                l_add_out_cond_res = dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out_cond);
                DAP_DELETE(l_out_cond);
            }
            if (l_add_out_cond_res == -1)
                RET_ERR;
        }
    }

dex_compose_sign:
    // Finalize and sign with buyer's key
    if (s_dex_sign_tx(&l_tx, a_wallet) < 0)
        RET_ERR;
#undef RET_ERR
dex_compose_ret:
    s_dex_requirements_free(&l_reqs);
    if (l_err_line) {
        log_it(L_ERROR, "%s(): Error at line %d, datum was not composed", __FUNCTION__, l_err_line);
        dap_chain_datum_tx_delete(l_tx);
        l_tx = NULL;
    }
    return l_tx;
}

static void s_dex_dump_order_entry(const char *a_side, const dex_order_cache_entry_t *a_entry, dap_time_t a_now, const char *a_base,
                                   const char *a_quote)
{
    char l_ts_created[64] = {0}, l_ts_expires[64] = {0};
    const char *l_status = (a_entry->ts_expires && a_now > a_entry->ts_expires) ? "EXPIRED" : "ACTIVE",
               *l_from_origin = (a_entry->level.match.min_fill & 0x80) ? " (from_origin)" : "", *l_expires_str = "";

    dap_time_to_str_rfc822(l_ts_created, sizeof(l_ts_created), a_entry->ts_created);
    if (a_entry->ts_expires)
        dap_time_to_str_rfc822(l_ts_expires, sizeof(l_ts_expires), a_entry->ts_expires), l_expires_str = l_ts_expires;

    log_it(L_INFO,
           "Order %s %s/%s %s\n"
           "    Root:    %s\n"
           "    Tail:    %s\n"
           "    Seller:  %s\n"
           "    Price:   %s %s/%s\n"
           "    Value:   %s %s (sell)\n"
           "    MinFill: %u%%%s\n"
           "    Flags:   0x%08X, Version: %u\n"
           "    Created: %s%s%s",
           a_side, a_base, a_quote, l_status, dap_chain_hash_fast_to_str_static(&a_entry->level.match.root),
           dap_chain_hash_fast_to_str_static(&a_entry->level.match.tail),
           a_entry->seller_addr_ptr ? dap_chain_addr_to_str_static(a_entry->seller_addr_ptr) : "<unknown>",
           dap_uint256_to_char_ex(a_entry->level.match.rate).frac, a_quote, a_base, dap_uint256_to_char_ex(a_entry->level.match.value).frac,
           (a_entry->side_version & 0x1) == DEX_SIDE_ASK ? a_base : a_quote, a_entry->level.match.min_fill & 0x7F, l_from_origin,
           a_entry->flags, a_entry->side_version >> 1, l_ts_created, l_expires_str[0] ? " | Expires: " : "", l_expires_str);
}

void dap_chain_net_srv_dex_dump_orders_cache()
{
    if (!s_dex_cache_enabled)
        return log_it(L_INFO, "Cache is disabled, nothing to dump");

    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    size_t l_pairs = 0, l_orders = 0;
    dex_pair_index_t *l_pb, *l_pb_tmp;
    HASH_ITER(hh, s_dex_pair_index, l_pb, l_pb_tmp)
    {
        const char *l_token_base = l_pb->key.token_base, *l_token_quote = l_pb->key.token_quote;
        ++l_pairs;

        log_it(L_INFO, "== DEX CACHE: Pair %s/%s ==", l_token_base, l_token_quote);
        dap_chain_net_t *l_net = dap_chain_net_by_id(l_pb->key.net_id_base);
        dap_time_t l_now = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        dex_order_cache_entry_t *e, *tmp;
        // ASKS bucket
        if (l_pb->asks) {
            log_it(L_INFO, "  ASKS:");
            HASH_ITER(hh_pair_bucket, l_pb->asks, e, tmp)
            {
                ++l_orders;
                s_dex_dump_order_entry("ASK", e, l_now, l_token_base, l_token_quote);
            }
        } else
            log_it(L_INFO, "  ASKS: <empty>");

        // BIDS bucket
        if (l_pb->bids) {
            log_it(L_INFO, "  BIDS:");
            HASH_ITER(hh_pair_bucket, l_pb->bids, e, tmp)
            {
                ++l_orders;
                s_dex_dump_order_entry("BID", e, l_now, l_token_base, l_token_quote);
            }
        } else
            log_it(L_INFO, "  BIDS: <empty>");
    }
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    log_it(L_INFO, "\nCache dump complete: %zu pairs, %zu orders", l_pairs, l_orders);
}

int dap_chain_net_srv_dex_cache_adjust_minfill(dap_chain_net_t *a_net, const dap_hash_fast_t *a_order_tail, uint8_t a_new_minfill,
                                               uint8_t *a_out_old_minfill)
{
    dap_return_val_if_fail(a_net && a_order_tail, -1);
    if (!s_dex_cache_enabled)
        return -1;

    pthread_rwlock_wrlock(&s_dex_cache_rwlock);
    dex_order_cache_entry_t *l_entry = NULL;
    HASH_FIND(level.hh_tail, s_dex_index_by_tail, a_order_tail, sizeof(*a_order_tail), l_entry);
    if (l_entry) {
        if (a_out_old_minfill)
            *a_out_old_minfill = l_entry->level.match.min_fill;
        l_entry->level.match.min_fill = a_new_minfill;
    }
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    return l_entry ? 0 : -2;
}

/* ============================================================================
 * Trade History & Orderbook
 * History cache types, OHLCV aggregation, orderbook level structures
 * ============================================================================ */

/*
 * dex_orderbook_level_t — aggregated orderbook "price level" (optionally binned by tick).
 * Used by:
 *   - CMD_ORDERBOOK: when cache is on — filled from pair buckets (pb->asks/pb->bids) with price binning;
 *                    when cache is off — built from active (unspent, not expired) SRV_DEX outs in the ledger.
 * Fields:
 *   price     — QUOTE/BASE price in canonical pair; when binning is enabled, rounded to the tick
 *   vol_base  — sum volume in BASE at this level (ASK: sum(value); BID: sum(value/rate))
 *   vol_quote — sum volume in QUOTE at this level (ASK: sum(value*rate); BID: sum(value))
 *   orders    — number of active orders aggregated into the level
 *   hh        — local UTHash handle used only for the transient level table inside the command execution
 */
typedef struct dex_orderbook_level {
    uint256_t price, vol_base, vol_quote;
    uint32_t orders;
    UT_hash_handle hh;
} dex_orderbook_level_t;

static inline int s_cmp_agg_level_price_asc(dex_orderbook_level_t *a, dex_orderbook_level_t *b)
{
    return compare256(a->price, b->price);
}

static inline int s_cmp_agg_level_price_desc(dex_orderbook_level_t *a, dex_orderbook_level_t *b)
{
    return compare256(b->price, a->price);
}

/*
 * OHLCV aggregate for on-the-fly computation and JSON output.
 */
typedef struct dex_ohlcv {
    uint64_t ts;
    uint256_t open, high, low, close;
    uint256_t volume_base, volume_quote;
    uint32_t trades;
} dex_ohlcv_t;

/*
 * dex_bucket_agg_t — OHLCV aggregator for ledger fallback queries.
 */
typedef struct dex_bucket_agg {
    dex_ohlcv_t ohlcv;
    uint64_t first_ts, last_ts;
    UT_hash_handle hh;
} dex_bucket_agg_t;

// Helper to emit bucket to JSON (ledger fallback only)
static inline void s_hist_json_emit_bucket(json_object *a_arr, const dex_bucket_agg_t *a_b, bool a_with_ohlc)
{
    dap_ret_if_any(!a_arr, !a_b);
    json_object *o = json_object_new_object();
    json_object_object_add(o, "ts", json_object_new_uint64(a_b->ohlcv.ts));
    char l_ts_str[DAP_TIME_STR_SIZE];
    dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), a_b->ohlcv.ts);
    json_object_object_add(o, "ts_str", json_object_new_string(l_ts_str));
    json_object_object_add(o, "first_ts", json_object_new_uint64(a_b->first_ts));
    json_object_object_add(o, "last_ts", json_object_new_uint64(a_b->last_ts));
    if (a_with_ohlc) {
        json_object_object_add(o, "open", json_object_new_string(dap_uint256_to_char_ex(a_b->ohlcv.open).frac));
        json_object_object_add(o, "high", json_object_new_string(dap_uint256_to_char_ex(a_b->ohlcv.high).frac));
        json_object_object_add(o, "low", json_object_new_string(dap_uint256_to_char_ex(a_b->ohlcv.low).frac));
        json_object_object_add(o, "close", json_object_new_string(dap_uint256_to_char_ex(a_b->ohlcv.close).frac));
    }
    json_object_object_add(o, "volume_base", json_object_new_string(dap_uint256_to_char_ex(a_b->ohlcv.volume_base).frac));
    json_object_object_add(o, "volume_quote", json_object_new_string(dap_uint256_to_char_ex(a_b->ohlcv.volume_quote).frac));
    json_object_object_add(o, "trades", json_object_new_uint64(a_b->ohlcv.trades));
    json_object_array_add(a_arr, o);
}

static int s_cmp_agg_bucket_ts(dex_bucket_agg_t *a, dex_bucket_agg_t *b)
{
    return a->ohlcv.ts < b->ohlcv.ts ? -1 : a->ohlcv.ts > b->ohlcv.ts ? 1 : 0;
}

typedef struct dex_event_key {
    dap_hash_fast_t tx_hash, prev_tail;
} DAP_ALIGN_PACKED dex_event_key_t;

/*
 * Trade record with seller/buyer/order index support.
 * OHLCV values are computed on-the-fly, no pre-aggregation.
 */
typedef struct dex_event_rec {
    dex_event_key_t key;                     // unique key for uthash in bucket
    const dap_hash_fast_t *order_root_ptr;   // pointer to order root hash (in order_idx)
    const dap_chain_addr_t *seller_addr_ptr; // pointer to seller addr (in seller_idx)
    const dap_chain_addr_t *buyer_addr_ptr;  // pointer to buyer addr (in buyer_idx)
    uint64_t ts;                             // event timestamp
    const uint256_t *price;                  // pointer to per-order price (immutable)
    const uint256_t *val_b_full;             // pointer to per-order base total at last CREATE/UPDATE
    union {
        uint256_t trade_b;      // executed base for trade events
        uint256_t val_b_remain; // order value/remaining for create/update/cancel
    };
    struct dex_event_rec *next, *prev, // utlist DL for seller index
        *buyer_next, *buyer_prev,      // utlist DL for buyer index
        *order_next, *order_prev,      // utlist DL for order index
        *val_upd_next, *val_upd_prev;  // create/update chain for base_total rollback
    UT_hash_handle hh;                 // uthash in bucket
    uint8_t flags;                     // DEX_TRADE_FLAG_*
    uint8_t side;                      // DEX_SIDE_ASK or DEX_SIDE_BID
    uint8_t filled_pct;                // fill percent at event time (0-100)
} dex_event_rec_t;

/*
 * Lite bucket: stores only timestamp and trade index.
 * OHLCV is computed on-the-fly from trade records during queries.
 */
typedef struct dex_hist_bucket {
    uint64_t ts;                 // bucket start (aligned by s_hist_bucket_ts)
    dex_event_rec_t *events_idx; // uthash: (tx_hash, prev_tail) -> trade
    UT_hash_handle hh;           // per-pair bucket hash (key: ts)
} dex_hist_bucket_t;

/*
 * Unified trader index: hash by address for both seller and buyer roles.
 * One entry per unique address; shared if address acts as both seller and buyer.
 */
typedef struct dex_hist_trader_idx {
    dap_chain_addr_t addr;          // trader address (shared key)
    dex_event_rec_t *seller_events; // DL head for seller role (via next/prev)
    dex_event_rec_t *buyer_events;  // DL head for buyer role (via buyer_next/prev)
    UT_hash_handle hh_seller;       // hash handle for seller_idx
    UT_hash_handle hh_buyer;        // hash handle for buyer_idx
} dex_hist_trader_idx_t;

/*
 * Order index: hash by order_root for efficient order history queries.
 */
typedef struct dex_hist_order_idx {
    dap_hash_fast_t order_root; // order root hash (key)
    uint256_t price;            // canonical QUOTE/BASE price (immutable for order)
    uint256_t val_b_full;       // full value at last CREATE/UPDATE
    dex_event_rec_t *val_upd_ev;
    dex_event_rec_t *events; // DL head for trades (via order_next/prev)
    UT_hash_handle hh;
} dex_hist_order_idx_t;

/*
 * Per-pair history container (lite version).
 */
typedef struct dex_hist_pair {
    dex_pair_key_t key;                // canonical BASE/QUOTE
    dex_hist_bucket_t *buckets;        // uthash ts -> bucket
    dex_hist_trader_idx_t *seller_idx; // uthash by hh_seller -> seller trades
    dex_hist_trader_idx_t *buyer_idx;  // uthash by hh_buyer -> buyer trades
    dex_hist_order_idx_t *order_idx;   // uthash by order_root -> order trades
    UT_hash_handle hh;                 // top-level hash by pair
} dex_hist_pair_t;

/*
 * Lite history cache: trades indexed by time buckets with on-the-fly OHLCV computation.
 * Buckets are aligned by s_hist_bucket_ts(..., history_bucket_sec); default is 86400 seconds (1 day)
 */

static dex_hist_pair_t *s_dex_history = NULL;

/*
 * Compute fill percent from history order list.
 * Requires a_new already linked into a_oi list.
 */
static inline uint8_t s_hist_calc_fill_pct(dex_hist_order_idx_t *a_oi, dex_event_rec_t *a_new)
{
    dap_ret_val_if_any(0, !a_oi, !a_new);
    if (a_new->flags & (DEX_OP_CREATE | DEX_OP_UPDATE))
        return a_oi->val_b_full = a_new->val_b_remain, 0;
    uint256_t l_exec = uint256_0, l_val = uint256_0;
    if (!(a_new->flags & DEX_OP_CANCEL))
        l_exec = a_new->trade_b;
    for (dex_event_rec_t *l_it = a_new->order_prev; l_it; l_it = l_it->order_prev) {
        if (l_it->flags & (DEX_OP_CREATE | DEX_OP_UPDATE)) {
            l_val = l_it->val_b_remain;
            break;
        }
        if ((l_it->flags & DEX_OP_CANCEL) == 0)
            SUM_256_256(l_exec, l_it->trade_b, &l_exec);
    }
    if (IS_ZERO_256(l_val))
        return 0;
    a_oi->val_b_full = l_val;
    if (compare256(l_exec, l_val) >= 0)
        return 100;
    uint256_t l_remaining = uint256_0;
    SUBTRACT_256_256(l_val, l_exec, &l_remaining);
    return s_calc_fill_pct(l_val, l_remaining);
}

static inline uint256_t s_hist_event_price(const dex_event_rec_t *a_ev)
{
    return a_ev->price ? *a_ev->price : uint256_0;
}

static inline uint256_t s_hist_event_base_total(const dex_event_rec_t *a_ev)
{
    return a_ev->val_b_full ? *a_ev->val_b_full : uint256_0;
}

static inline void s_hist_debug_val_chain(const dex_hist_order_idx_t *a_oi)
{
    if (!a_oi)
        return;
    const dex_event_rec_t *l_it = a_oi->val_upd_ev;
    if (l_it && compare256(a_oi->val_b_full, l_it->val_b_remain) != 0)
        log_it(L_WARNING, "%s(): val_b_full mismatch for order %s", __FUNCTION__, dap_hash_fast_to_str_static(&a_oi->order_root));
    for (const dex_event_rec_t *l_prev = NULL; l_it; l_prev = l_it, l_it = l_it->val_upd_prev) {
        if (!(l_it->flags & (DEX_OP_CREATE | DEX_OP_UPDATE)))
            log_it(L_WARNING, "%s(): Non-update node in val chain for order %s", __FUNCTION__,
                   dap_hash_fast_to_str_static(&a_oi->order_root));
        if (l_it->val_upd_next != l_prev)
            log_it(L_WARNING, "%s(): val chain next mismatch for order %s", __FUNCTION__, dap_hash_fast_to_str_static(&a_oi->order_root));
        if (l_it->val_upd_prev && l_it->val_upd_prev->val_upd_next != l_it)
            log_it(L_WARNING, "%s(): val chain prev link broken for order %s", __FUNCTION__,
                   dap_hash_fast_to_str_static(&a_oi->order_root));
        if (l_it->val_upd_next && l_it->val_upd_next->val_upd_prev != l_it)
            log_it(L_WARNING, "%s(): val chain next link broken for order %s", __FUNCTION__,
                   dap_hash_fast_to_str_static(&a_oi->order_root));
    }
}

// Align timestamp to calendar day boundary (00:00:00 UTC)
static inline uint64_t s_hist_day_start(uint64_t a_ts)
{
    return (a_ts / DAP_SEC_PER_DAY) * DAP_SEC_PER_DAY;
}

void dap_chain_net_srv_dex_dump_history_cache()
{
    if (!s_dex_history_enabled)
        return log_it(L_INFO, "History cache is disabled, nothing to dump");

    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    size_t l_pairs = 0, l_buckets = 0, l_events = 0, l_sellers = 0, l_buyers = 0;
    dex_hist_pair_t *l_pair, *l_pair_tmp;
    HASH_ITER(hh, s_dex_history, l_pair, l_pair_tmp)
    {
        ++l_pairs;
        log_it(L_INFO, "== HISTORY: Pair %s/%s ==", l_pair->key.token_base, l_pair->key.token_quote);

        dex_hist_bucket_t *l_bucket, *l_bucket_tmp;
        HASH_ITER(hh, l_pair->buckets, l_bucket, l_bucket_tmp)
        {
            ++l_buckets;
            char l_ts_str[DAP_TIME_STR_SIZE];
            dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), l_bucket->ts);

            size_t l_bucket_events = HASH_COUNT(l_bucket->events_idx);
            log_it(L_INFO, "  Bucket ts: %s, %zu trades", l_ts_str, l_bucket_events);

            dex_event_rec_t *l_rec, *l_rec_tmp;
            HASH_ITER(hh, l_bucket->events_idx, l_rec, l_rec_tmp)
            {
                ++l_events;
                uint256_t l_quote;
                uint256_t l_price = s_hist_event_price(l_rec);
                uint256_t l_base = (l_rec->flags & (DEX_OP_CREATE | DEX_OP_UPDATE | DEX_OP_CANCEL)) ? l_rec->val_b_remain : l_rec->trade_b;
                MULT_256_COIN(l_base, l_price, &l_quote);
                log_it(L_INFO, "      Tx %s: %s; Rate: %s ( Q %s / B %s )", dap_chain_hash_fast_to_str_static(&l_rec->key.tx_hash),
                       s_dex_op_flags_to_str(l_rec->flags), dap_uint256_to_char_ex(l_price).frac, dap_uint256_to_char_ex(l_quote).frac,
                       dap_uint256_to_char_ex(l_base).frac);
            }
        }
        // Dump seller index
        dex_hist_trader_idx_t *l_ti, *l_ti_tmp;
        HASH_ITER(hh_seller, l_pair->seller_idx, l_ti, l_ti_tmp)
        {
            ++l_sellers;
            size_t l_cnt = 0;
            dex_event_rec_t *l_tr;
            DL_COUNT(l_ti->seller_events, l_tr, l_cnt);
            log_it(L_INFO, "  Seller %s: %zu trades", dap_chain_addr_to_str_static(&l_ti->addr), l_cnt);
        }
        // Dump buyer index
        HASH_ITER(hh_buyer, l_pair->buyer_idx, l_ti, l_ti_tmp)
        {
            ++l_buyers;
            size_t l_cnt = 0;
            dex_event_rec_t *l_tr;
            DL_COUNT2(l_ti->buyer_events, l_tr, l_cnt, buyer_next);
            log_it(L_INFO, "  Buyer %s: %zu trades", dap_chain_addr_to_str_static(&l_ti->addr), l_cnt);
        }
    }
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    log_it(L_INFO, "History dump complete: %zu pairs, %zu buckets, %zu trades, %zu sellers, %zu buyers", l_pairs, l_buckets, l_events,
           l_sellers, l_buyers);
}

/*
 * Trader index helper: get or create trader entry for a pair.
 * Searches both hashes; creates single entry for shared address.
 * a_as_seller: if true, ensures entry is in seller_idx; if false, ensures in buyer_idx.
 */
static inline dex_hist_trader_idx_t *s_hist_trader_idx_get_or_create(dex_hist_pair_t *a_pair, const dap_chain_addr_t *a_addr,
                                                                     bool a_as_seller)
{
    dap_ret_val_if_any(NULL, !a_pair, !a_addr);
    // Compute hash once, reuse for all operations
    unsigned l_hash = 0;
    HASH_VALUE(a_addr, sizeof(dap_chain_addr_t), l_hash);
    dex_hist_trader_idx_t *l_ti = NULL;
    if (a_as_seller) {
        HASH_FIND_BYHASHVALUE(hh_seller, a_pair->seller_idx, a_addr, sizeof(dap_chain_addr_t), l_hash, l_ti);
        if (l_ti)
            return l_ti;
        HASH_FIND_BYHASHVALUE(hh_buyer, a_pair->buyer_idx, a_addr, sizeof(dap_chain_addr_t), l_hash, l_ti);
        if (!l_ti) {
            l_ti = DAP_NEW_Z_RET_VAL_IF_FAIL(dex_hist_trader_idx_t, NULL);
            l_ti->addr = *a_addr;
        }
        HASH_ADD_BYHASHVALUE(hh_seller, a_pair->seller_idx, addr, sizeof(dap_chain_addr_t), l_hash, l_ti);
    } else {
        HASH_FIND_BYHASHVALUE(hh_buyer, a_pair->buyer_idx, a_addr, sizeof(dap_chain_addr_t), l_hash, l_ti);
        if (l_ti)
            return l_ti;
        HASH_FIND_BYHASHVALUE(hh_seller, a_pair->seller_idx, a_addr, sizeof(dap_chain_addr_t), l_hash, l_ti);
        if (!l_ti) {
            l_ti = DAP_NEW_Z_RET_VAL_IF_FAIL(dex_hist_trader_idx_t, NULL);
            l_ti->addr = *a_addr;
        }
        HASH_ADD_BYHASHVALUE(hh_buyer, a_pair->buyer_idx, addr, sizeof(dap_chain_addr_t), l_hash, l_ti);
    }
    return l_ti;
}

/*
 * Get tail event of order list.
 */
static inline const dex_event_rec_t *s_hist_order_tail(const dex_hist_order_idx_t *a_oi)
{
    return a_oi && a_oi->events ? a_oi->events->order_prev ? a_oi->events->order_prev : a_oi->events : NULL;
}

static int s_cmp_order_idx_tail_ts(const void *a, const void *b)
{
    const dex_hist_order_idx_t *x = a, *y = b;
    const dex_event_rec_t *l_tx = s_hist_order_tail(x), *l_ty = s_hist_order_tail(y);
    uint64_t l_x = l_tx ? l_tx->ts : 0;
    uint64_t l_y = l_ty ? l_ty->ts : 0;
    return l_x < l_y ? -1 : l_x > l_y ? 1 : 0;
}

/*
 * s_hist_idx_add_rec
 * Add a trade record into bucket hash, seller index, buyer index and order index.
 * Lite version: no OHLC aggregation, just stores the trade for on-the-fly computation.
 */
static dex_hist_order_idx_t *s_hist_indexes_append(dex_hist_bucket_t *a_bucket, dex_hist_pair_t *a_pair, dex_event_rec_t *a_ev,
                                                   const dap_chain_addr_t *a_seller_addr, const dap_chain_addr_t *a_buyer_addr,
                                                   const dap_hash_fast_t *a_order_root, const uint256_t a_rate)
{
    // Add to bucket uthash
    HASH_ADD(hh, a_bucket->events_idx, key, sizeof(a_ev->key), a_ev);
    // Add to seller index if seller address provided
    if (a_seller_addr) {
        dex_hist_trader_idx_t *l_ti = s_hist_trader_idx_get_or_create(a_pair, a_seller_addr, true);
        a_ev->seller_addr_ptr = &l_ti->addr;
        DL_APPEND(l_ti->seller_events, a_ev);
    }
    // Add to buyer index if buyer address provided
    if (a_buyer_addr) {
        dex_hist_trader_idx_t *l_ti = s_hist_trader_idx_get_or_create(a_pair, a_buyer_addr, false);
        a_ev->buyer_addr_ptr = &l_ti->addr;
        DL_APPEND2(l_ti->buyer_events, a_ev, buyer_prev, buyer_next);
    }
    // Add to order index if order root provided
    if (a_order_root) {
        if (dap_hash_fast_is_blank(a_order_root))
            return NULL;
        dex_hist_order_idx_t *l_oi = NULL;
        unsigned l_hashv;
        HASH_VALUE(a_order_root, sizeof(dap_hash_fast_t), l_hashv);
        HASH_FIND_BYHASHVALUE(hh, a_pair->order_idx, a_order_root, sizeof(dap_hash_fast_t), l_hashv, l_oi);
        if (l_oi)
            HASH_DEL(a_pair->order_idx, l_oi);
        else {
            l_oi = DAP_NEW_Z_RET_VAL_IF_FAIL(dex_hist_order_idx_t, NULL);
            l_oi->order_root = *a_order_root;
        }
        a_ev->order_root_ptr = &l_oi->order_root;
        a_ev->price = &l_oi->price;
        a_ev->val_b_full = &l_oi->val_b_full;
        if (IS_ZERO_256(l_oi->price))
            l_oi->price = a_rate;
        else if (compare256(l_oi->price, a_rate) != 0)
            log_it(L_WARNING, "%s(): Order %s price mismatch: %s vs %s", __FUNCTION__, dap_hash_fast_to_str_static(&l_oi->order_root),
                   dap_uint256_to_char_ex(l_oi->price).frac, dap_uint256_to_char_ex(a_rate).frac);
        if (a_ev->flags & (DEX_OP_CREATE | DEX_OP_UPDATE)) {
            a_ev->val_upd_prev = l_oi->val_upd_ev;
            if (l_oi->val_upd_ev)
                l_oi->val_upd_ev->val_upd_next = a_ev;
            l_oi->val_upd_ev = a_ev;
            l_oi->val_b_full = a_ev->val_b_remain;
            if (s_debug_more)
                s_hist_debug_val_chain(l_oi);
        }
        DL_APPEND2(l_oi->events, a_ev, order_prev, order_next);
        HASH_ADD_BYHASHVALUE_INORDER(hh, a_pair->order_idx, order_root, sizeof(dap_hash_fast_t), l_hashv, l_oi, s_cmp_order_idx_tail_ts);
        return l_oi;
    }
    return NULL;
}

/*
 * s_hist_idx_remove_rec_apply
 * Remove a trade record from bucket hash, seller/buyer/order indices.
 * If bucket becomes empty, removes bucket. If pair becomes empty, removes pair.
 */
static void s_hist_indexes_remove(dex_hist_pair_t *a_pair, dex_hist_bucket_t *a_bucket, const dap_hash_fast_t *a_tx_hash,
                                  const dap_hash_fast_t *a_prev_tail)
{
    if (!a_pair || !a_bucket || !a_tx_hash)
        return;
    dex_event_key_t l_key = {.tx_hash = *a_tx_hash, .prev_tail = a_prev_tail ? *a_prev_tail : (dap_hash_fast_t){}};
    dex_event_rec_t *l_rec = NULL;
    HASH_FIND(hh, a_bucket->events_idx, &l_key, sizeof(l_key), l_rec);
    if (!l_rec)
        return;
    // Remove from seller index (O(1) with DL)
    if (l_rec->seller_addr_ptr) {
        dex_hist_trader_idx_t *l_ti = NULL;
        HASH_FIND(hh_seller, a_pair->seller_idx, l_rec->seller_addr_ptr, sizeof(dap_chain_addr_t), l_ti);
        if (l_ti) {
            DL_DELETE(l_ti->seller_events, l_rec);
            if (!l_ti->seller_events) {
                HASH_DELETE(hh_seller, a_pair->seller_idx, l_ti);
                // Only free if also not in buyer_idx
                if (!l_ti->buyer_events)
                    DAP_DELETE(l_ti);
            }
        }
    }
    // Remove from buyer index (O(1) with DL)
    if (l_rec->buyer_addr_ptr) {
        dex_hist_trader_idx_t *l_ti = NULL;
        HASH_FIND(hh_buyer, a_pair->buyer_idx, l_rec->buyer_addr_ptr, sizeof(dap_chain_addr_t), l_ti);
        if (l_ti) {
            DL_DELETE2(l_ti->buyer_events, l_rec, buyer_prev, buyer_next);
            if (!l_ti->buyer_events) {
                HASH_DELETE(hh_buyer, a_pair->buyer_idx, l_ti);
                // Only free if also not in seller_idx
                if (!l_ti->seller_events)
                    DAP_DELETE(l_ti);
            }
        }
    }
    // Remove from order index (O(1) with DL)
    if (l_rec->order_root_ptr) {
        dex_hist_order_idx_t *l_oi = NULL;
        unsigned l_hashv;
        HASH_VALUE(l_rec->order_root_ptr, sizeof(dap_hash_fast_t), l_hashv);
        HASH_FIND_BYHASHVALUE(hh, a_pair->order_idx, l_rec->order_root_ptr, sizeof(dap_hash_fast_t), l_hashv, l_oi);
        if (l_oi) {
            bool l_reorder = s_hist_order_tail(l_oi) == l_rec;
            DL_DELETE2(l_oi->events, l_rec, order_prev, order_next);
            if (!l_oi->events) {
                HASH_DEL(a_pair->order_idx, l_oi);
                DAP_DELETE(l_oi);
            } else {
                if (l_rec->flags & (DEX_OP_CREATE | DEX_OP_UPDATE)) {
                    if (l_rec->val_upd_prev)
                        l_rec->val_upd_prev->val_upd_next = l_rec->val_upd_next;
                    if (l_rec->val_upd_next)
                        l_rec->val_upd_next->val_upd_prev = l_rec->val_upd_prev;
                    if (l_oi->val_upd_ev == l_rec) {
                        l_oi->val_upd_ev = l_rec->val_upd_prev;
                        l_oi->val_b_full = l_oi->val_upd_ev ? l_oi->val_upd_ev->val_b_remain : uint256_0;
                    }
                    if (s_debug_more)
                        s_hist_debug_val_chain(l_oi);
                }
                if (l_reorder) {
                    HASH_DEL(a_pair->order_idx, l_oi);
                    HASH_ADD_BYHASHVALUE_INORDER(hh, a_pair->order_idx, order_root, sizeof(dap_hash_fast_t), l_hashv, l_oi,
                                                 s_cmp_order_idx_tail_ts);
                }
            }
        }
    }
    // Remove from bucket hash
    HASH_DELETE(hh, a_bucket->events_idx, l_rec);
    DAP_DELETE(l_rec);
    // If bucket empty, remove it
    if (!HASH_COUNT(a_bucket->events_idx)) {
        HASH_DELETE(hh, a_pair->buckets, a_bucket);
        DAP_DELETE(a_bucket);
    }
    // If pair empty, remove it
    if (!a_pair->buckets && !a_pair->seller_idx && !a_pair->buyer_idx && !a_pair->order_idx) {
        HASH_DELETE(hh, s_dex_history, a_pair);
        DAP_DELETE(a_pair);
    }
}

static int s_cmp_bucket_ts(dex_hist_bucket_t *a, dex_hist_bucket_t *b)
{
    return a->ts < b->ts ? -1 : a->ts > b->ts ? 1 : 0;
}

/*
 * s_hist_bucket_ts
 * Normalize timestamp to the start of its aggregation bucket with calendar alignment.
 * - Sub-daily periods: simple floor division (aligned to UTC naturally)
 * - Weekly (604800): align to Monday 00:00 UTC
 * - Monthly (>=28 days): align to 1st of month 00:00 UTC
 * - Yearly (>=365 days): align to Jan 1st 00:00 UTC
 */
static inline uint64_t s_hist_bucket_ts(dap_time_t a_ts, uint64_t a_bucket_sec)
{
    if (!a_bucket_sec)
        return 0;
    // Sub-daily: simple division works (epoch is at 00:00 UTC)
    if (a_bucket_sec < DAP_SEC_PER_DAY)
        return (uint64_t)(a_ts / (dap_time_t)a_bucket_sec) * a_bucket_sec;

    // Daily: align to 00:00 UTC
    if (a_bucket_sec == DAP_SEC_PER_DAY)
        return s_hist_day_start((uint64_t)a_ts);

    // Weekly (604800): align to Monday 00:00 UTC
    // Unix epoch 1970-01-01 was Thursday = day 3 (Mon=0..Sun=6)
    if (a_bucket_sec == 604800) {
        uint64_t l_days = a_ts / DAP_SEC_PER_DAY;
        uint64_t l_dow = (l_days + 3) % 7; // 0=Mon..6=Sun
        return (l_dow <= l_days) ? (l_days - l_dow) * DAP_SEC_PER_DAY : 0;
    }

    // Multi-day (2..27 days): align to epoch multiples of days
    if (a_bucket_sec < 28 * DAP_SEC_PER_DAY && (a_bucket_sec % DAP_SEC_PER_DAY) == 0) {
        uint64_t l_days = a_ts / DAP_SEC_PER_DAY;
        uint64_t l_step = a_bucket_sec / DAP_SEC_PER_DAY;
        return (l_days / l_step) * l_step * DAP_SEC_PER_DAY;
    }

    // Monthly/Yearly: need calendar functions
    struct tm l_tm = {};
    time_t l_time = (time_t)a_ts;
#ifdef DAP_OS_WINDOWS
    gmtime_s(&l_tm, &l_time);
#else
    gmtime_r(&l_time, &l_tm);
#endif

    if (a_bucket_sec >= 365 * DAP_SEC_PER_DAY) {
        // Yearly: align to Jan 1st
        l_tm.tm_mon = 0;
        l_tm.tm_mday = 1;
    } else if (a_bucket_sec >= 28 * DAP_SEC_PER_DAY) {
        // Monthly: align to 1st of month
        l_tm.tm_mday = 1;
    }
    l_tm.tm_hour = l_tm.tm_min = l_tm.tm_sec = 0;

#ifdef DAP_OS_WINDOWS
    return (uint64_t)_mkgmtime(&l_tm);
#else
    return (uint64_t)timegm(&l_tm);
#endif
}

/*
 * s_dex_extract_buyer_addr
 * Extract buyer address from TX: the spender of OUT_COND (first signer of the TX).
 */
static inline dap_chain_addr_t s_dex_extract_buyer_addr(dap_chain_datum_tx_t *a_tx, dap_chain_net_id_t a_net_id)
{
    dap_sign_t *l_sig = dap_chain_datum_tx_get_sign(a_tx, 0);
    dap_ret_val_if_any(c_dap_chain_addr_blank, !l_sig);
    dap_chain_addr_t l_ret = {};
    return dap_chain_addr_fill_from_sign(&l_ret, l_sig, a_net_id), l_ret;
}

/*
 * s_dex_verify_payout
 * Verifies that a DEX TX contains a payout to the seller in the specified token.
 * Checks OUT (native token), OUT_EXT, and OUT_STD items.
 * Returns true only for non-owner transactions.
 */
static inline bool s_dex_verify_payout(dap_chain_datum_tx_t *a_tx, dap_chain_net_t *a_net, const char *a_buy_token,
                                       const dap_chain_addr_t *a_seller_addr)
{
    dap_ret_val_if_any(false, !a_tx, !a_net, !a_buy_token || !*a_buy_token, !a_seller_addr);
    dap_chain_addr_t l_addr = s_dex_extract_buyer_addr(a_tx, a_net->pub.id);
    // TODO: Owner detection uses first SIG only (ledger behavior). Revisit if multi-sign ordering changes.
    if (dap_chain_addr_compare(a_seller_addr, &l_addr))
        return false;
    byte_t *l_it;
    size_t l_sz = 0;
    const char *l_token;
    TX_ITEM_ITER_TX(l_it, l_sz, a_tx)
    {
        switch (*l_it) {
        case TX_ITEM_TYPE_OUT: {
            dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t *)l_it;
            l_token = a_net->pub.native_ticker;
            l_addr = l_out->addr;
            break;
        }
        case TX_ITEM_TYPE_OUT_EXT: {
            dap_chain_tx_out_ext_t *l_out = (dap_chain_tx_out_ext_t *)l_it;
            l_token = l_out->token;
            l_addr = l_out->addr;
            break;
        }
        case TX_ITEM_TYPE_OUT_STD: {
            dap_chain_tx_out_std_t *l_out = (dap_chain_tx_out_std_t *)l_it;
            l_token = l_out->token;
            l_addr = l_out->addr;
            break;
        }
        default:
            continue;
        }
        if (!dap_strcmp(l_token, a_buy_token) && dap_chain_addr_compare(&l_addr, a_seller_addr))
            return true;
    }
    return false;
}

/*
 * s_dex_calc_executed_amount
 * Calculates executed amount for a DEX order, accounting for residual (leftover).
 * If a_in_idx == 0 and order_root_hash matches, subtracts residual from prev_value.
 */
static inline uint256_t s_dex_calc_executed_amount(dap_chain_tx_out_cond_t *a_prev, dap_chain_tx_out_cond_t *a_out_cond, int a_in_idx,
                                                   dap_chain_datum_tx_t *a_prev_tx, const dap_hash_fast_t *a_prev_hash,
                                                   dap_ledger_t *a_ledger)
{
    uint256_t l_executed = a_prev->header.value;
    if (a_out_cond && !dap_hash_fast_is_blank(&a_out_cond->subtype.srv_dex.order_root_hash) && a_in_idx == 0 &&
        compare256(a_prev->header.value, a_out_cond->header.value) > 0) {
        dap_hash_fast_t l_root0 = dap_ledger_get_first_chain_tx_hash(a_ledger, a_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
        if (dap_hash_fast_is_blank(&l_root0) && a_prev_hash)
            l_root0 = *a_prev_hash;
        if (dap_hash_fast_compare(&l_root0, &a_out_cond->subtype.srv_dex.order_root_hash))
            SUBTRACT_256_256(a_prev->header.value, a_out_cond->header.value, &l_executed);
    }
    return l_executed;
}

/*
 * s_hist_pair_get_or_create
 * Lookup or create a history entry for the canonical pair (BASE/QUOTE).
 * Returns a pointer to the per-pair container that owns the per-bucket hash table.
 */
static inline dex_hist_pair_t *s_hist_pair_get_or_create(const dex_pair_key_t *a_key)
{
    unsigned l_hash = 0;
    HASH_VALUE(a_key, DEX_PAIR_KEY_CMP_SIZE, l_hash);
    dex_hist_pair_t *p = NULL;
    HASH_FIND_BYHASHVALUE(hh, s_dex_history, a_key, DEX_PAIR_KEY_CMP_SIZE, l_hash, p);
    if (!p) {
        p = DAP_NEW_Z_RET_VAL_IF_FAIL(dex_hist_pair_t, NULL);
        p->key = *a_key;
        HASH_ADD_BYHASHVALUE(hh, s_dex_history, key, DEX_PAIR_KEY_CMP_SIZE, l_hash, p);
    }
    return p;
}

static inline bool s_history_check_flags(uint8_t a_rec_flags, uint8_t a_filter);
static inline bool s_history_check_trade_flags(uint8_t a_rec_flags, uint8_t a_filter);

/*
 * Compute OHLCV from trades in a bucket for given time range.
 * Only MARKET trades contribute to OHLC; MARKET|TARGETED contribute to volume (ORDER, CANCELLED, UPDATED records are excluded).
 */
static void s_calc_ohlcv_from_bucket(dex_hist_bucket_t *a_bucket, uint64_t a_ts_from, uint64_t a_ts_to,
                                     const dap_chain_addr_t *a_seller_filter, const dap_chain_addr_t *a_buyer_filter,
                                     const dap_hash_fast_t *a_order_root, uint8_t a_filter_flags, dex_ohlcv_t *a_out)
{
    if (!a_bucket || !a_out)
        return;
    *a_out = (dex_ohlcv_t){.ts = a_bucket->ts};
    uint64_t l_min_ts = UINT64_MAX, l_max_ts = 0;
    dex_event_rec_t *l_rec, *l_tmp;
    HASH_ITER(hh, a_bucket->events_idx, l_rec, l_tmp)
    {
        if (l_rec->ts < a_ts_from || l_rec->ts > a_ts_to)
            continue;
        if ((a_seller_filter && (!l_rec->seller_addr_ptr || !dap_chain_addr_compare(l_rec->seller_addr_ptr, a_seller_filter))) ||
            (a_buyer_filter && (!l_rec->buyer_addr_ptr || !dap_chain_addr_compare(l_rec->buyer_addr_ptr, a_buyer_filter))))
            continue;
        if (!s_history_check_trade_flags(l_rec->flags, a_filter_flags))
            continue;
        if (a_order_root && !dap_hash_fast_compare(l_rec->order_root_ptr, a_order_root))
            continue;
        // Volume: all non-ORDER records (quote = price × base)
        uint256_t l_quote;
        uint256_t l_price = s_hist_event_price(l_rec);
        MULT_256_COIN(l_rec->trade_b, l_price, &l_quote);
        SUM_256_256(a_out->volume_base, l_rec->trade_b, &a_out->volume_base);
        SUM_256_256(a_out->volume_quote, l_quote, &a_out->volume_quote);
        ++a_out->trades;
        // OHLC: market trades only
        if (!(l_rec->flags & DEX_OP_MARKET))
            continue;
        if (IS_ZERO_256(a_out->high) || compare256(l_price, a_out->high) > 0)
            a_out->high = l_price;
        if (IS_ZERO_256(a_out->low) || compare256(l_price, a_out->low) < 0)
            a_out->low = l_price;
        if (l_rec->ts < l_min_ts) {
            l_min_ts = l_rec->ts;
            a_out->open = l_price;
        }
        if (l_rec->ts > l_max_ts) {
            l_max_ts = l_rec->ts;
            a_out->close = l_price;
        }
    }
}

/*
 * Emit JSON for OHLCV entry.
 */
static inline void s_ohlcv_to_json(json_object *a_arr, const dex_ohlcv_t *a_ohlcv, bool a_with_ohlc)
{
    if (!a_arr || !a_ohlcv)
        return;
    json_object *o = json_object_new_object();
    json_object_object_add(o, "ts", json_object_new_uint64(a_ohlcv->ts));
    char l_ts_str[DAP_TIME_STR_SIZE];
    dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), a_ohlcv->ts);
    json_object_object_add(o, "ts_str", json_object_new_string(l_ts_str));
    if (a_with_ohlc) {
        json_object_object_add(o, "open", json_object_new_string(dap_uint256_to_char_ex(a_ohlcv->open).frac));
        json_object_object_add(o, "high", json_object_new_string(dap_uint256_to_char_ex(a_ohlcv->high).frac));
        json_object_object_add(o, "low", json_object_new_string(dap_uint256_to_char_ex(a_ohlcv->low).frac));
        json_object_object_add(o, "close", json_object_new_string(dap_uint256_to_char_ex(a_ohlcv->close).frac));
    }
    json_object_object_add(o, "volume_base", json_object_new_string(dap_uint256_to_char_ex(a_ohlcv->volume_base).frac));
    json_object_object_add(o, "volume_quote", json_object_new_string(dap_uint256_to_char_ex(a_ohlcv->volume_quote).frac));
    json_object_object_add(o, "trades", json_object_new_uint64(a_ohlcv->trades));
    json_object_array_add(a_arr, o);
}

static int s_cmp_bucket_ptr_ts(const void *a, const void *b)
{
    const dex_hist_bucket_t *aa = *(dex_hist_bucket_t *const *)a, *bb = *(dex_hist_bucket_t *const *)b;
    return aa->ts < bb->ts ? -1 : aa->ts > bb->ts ? 1 : 0;
}

static int s_cmp_event_ptr_ts(const void *a, const void *b)
{
    const dex_event_rec_t *aa = *(dex_event_rec_t *const *)a, *bb = *(dex_event_rec_t *const *)b;
    return aa->ts < bb->ts ? -1 : aa->ts > bb->ts ? 1 : memcmp(&aa->key, &bb->key, sizeof(aa->key));
}

/*
 * Match event flags to filter.
 * If filter is zero, accept any event; CREATE/CANCEL/UPDATE require explicit filter.
 */
static inline bool s_history_check_flags(uint8_t a_rec_flags, uint8_t a_filter)
{
    if (!a_filter)
        return true;
    uint8_t l_special = a_rec_flags & (DEX_OP_CREATE | DEX_OP_CANCEL | DEX_OP_UPDATE);
    return (!l_special || (a_filter & l_special)) && (a_rec_flags & a_filter);
}

/*
 * Match trade flags to filter.
 * Always excludes CREATE/CANCEL/UPDATE events.
 */
static inline bool s_history_check_trade_flags(uint8_t a_rec_flags, uint8_t a_filter)
{
    if (a_rec_flags & (DEX_OP_CREATE | DEX_OP_CANCEL | DEX_OP_UPDATE))
        return false;
    return s_history_check_flags(a_rec_flags, a_filter);
}

/*
 * Order summary state by last event.
 */
static inline const char *s_hist_summary_state(const dex_event_rec_t *a_tail)
{
    if (a_tail->flags & DEX_OP_CREATE)
        return "open";
    if (a_tail->flags & DEX_OP_CANCEL)
        return "cancelled";
    if (a_tail->flags & DEX_OP_UPDATE)
        return "updated";
    return (a_tail->filled_pct >= 100) ? "fully filled" : "partially filled";
}

/*
 * Build JSON summary for an order.
 */
static json_object *s_hist_order_summary_to_json(const dex_pair_key_t *a_key, const dap_hash_fast_t *a_order_root,
                                                 const dex_event_rec_t *a_head, const dex_event_rec_t *a_tail)
{
    json_object *o = json_object_new_object();
    const char *l_base_token = NULL, *l_quote_token = NULL;
    if (a_key) {
        char l_pair[DAP_CHAIN_TICKER_SIZE_MAX * 2 + 2] = {};
        l_base_token = a_key->token_base;
        l_quote_token = a_key->token_quote;
        snprintf(l_pair, sizeof(l_pair), "%s/%s", l_base_token, l_quote_token);
        json_object_object_add(o, "pair", json_object_new_string(l_pair));
    }
    json_object_object_add(o, "order_root", json_object_new_string(dap_hash_fast_to_str_static(a_order_root)));
    json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&a_tail->key.tx_hash)));
    json_object_object_add(o, "state", json_object_new_string(s_hist_summary_state(a_tail)));
    json_object_object_add(o, "filled_pct", json_object_new_int(a_tail->filled_pct));
    json_object_object_add(o, "side", json_object_new_string(a_head->side == DEX_SIDE_ASK ? "ask" : "bid"));
    json_object_object_add(o, "ts_created", json_object_new_uint64(a_head->ts));
    char l_ts_str[DAP_TIME_STR_SIZE];
    dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), a_head->ts);
    json_object_object_add(o, "time_created", json_object_new_string(l_ts_str));
    json_object_object_add(o, "ts_last", json_object_new_uint64(a_tail->ts));
    dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), a_tail->ts);
    json_object_object_add(o, "time_last", json_object_new_string(l_ts_str));
    if (a_head->seller_addr_ptr)
        json_object_object_add(o, "seller", json_object_new_string(dap_chain_addr_to_str_static(a_head->seller_addr_ptr)));
    json_object_object_add(o, "last_event", json_object_new_string(s_dex_op_flags_to_str(a_tail->flags)));

    const bool l_is_trade =
        (a_tail->flags & (DEX_OP_MARKET | DEX_OP_TARGET)) && !(a_tail->flags & (DEX_OP_CREATE | DEX_OP_UPDATE | DEX_OP_CANCEL));
    uint256_t l_price = s_hist_event_price(a_tail), l_base_total = s_hist_event_base_total(a_tail),
              l_exec_base = s_calc_pct(l_base_total, a_tail->filled_pct), l_exec_quote = uint256_0;
    MULT_256_COIN(l_exec_base, l_price, &l_exec_quote);
    struct summary_snap {
        uint256_t *price, *spent, *recv, *rem;
        const char *spent_tok, *recv_tok, *rem_tok;
    } l_summary_snap;
    char l_amount_buf[DATOSHI_POW256 + DAP_CHAIN_TICKER_SIZE_MAX + 4];
    if (l_is_trade) {
        uint256_t l_remaining_base = uint256_0, l_remaining_quote = uint256_0;
        if (a_tail->filled_pct < 100 && compare256(l_exec_base, l_base_total) < 0) {
            SUBTRACT_256_256(l_base_total, l_exec_base, &l_remaining_base);
            MULT_256_COIN(l_remaining_base, l_price, &l_remaining_quote);
        }
        l_summary_snap = a_head->side == DEX_SIDE_ASK
            ? (struct summary_snap){
                .price = &l_price, .spent = &l_exec_base, .recv = &l_exec_quote, .rem = &l_remaining_base,
                .spent_tok = l_base_token, .recv_tok = l_quote_token, .rem_tok = l_base_token
            } : (struct summary_snap){
                .price = &l_price, .spent = &l_exec_quote, .recv = &l_exec_base, .rem = &l_remaining_quote,
                .spent_tok = l_quote_token, .recv_tok = l_base_token, .rem_tok = l_quote_token
            };
        json_object_object_add(o, "rate", json_object_new_string(dap_uint256_to_char_ex(l_price).frac));
        snprintf(l_amount_buf, sizeof(l_amount_buf), "%s %s", dap_uint256_to_char_ex(*l_summary_snap.spent).frac, l_summary_snap.spent_tok);
        json_object_object_add(o, "spent", json_object_new_string(l_amount_buf));
        snprintf(l_amount_buf, sizeof(l_amount_buf), "%s %s", dap_uint256_to_char_ex(*l_summary_snap.recv).frac, l_summary_snap.recv_tok);
        json_object_object_add(o, "received", json_object_new_string(l_amount_buf));
        if (a_tail->filled_pct < 100 && !IS_ZERO_256(*l_summary_snap.rem)) {
            snprintf(l_amount_buf, sizeof(l_amount_buf), "%s %s", dap_uint256_to_char_ex(*l_summary_snap.rem).frac, l_summary_snap.rem_tok);
            json_object_object_add(o, "remained", json_object_new_string(l_amount_buf));
        }
    } else if (a_tail->flags & DEX_OP_CREATE) {
        json_object_object_add(o, "rate", json_object_new_string(dap_uint256_to_char_ex(l_price).frac));
        uint256_t l_quote_total = uint256_0;
        MULT_256_COIN(l_base_total, l_price, &l_quote_total);
        l_summary_snap = a_head->side == DEX_SIDE_ASK ? (struct summary_snap){.spent = &l_base_total, .spent_tok = l_base_token}
                                                      : (struct summary_snap){.spent = &l_quote_total, .spent_tok = l_quote_token};
        snprintf(l_amount_buf, sizeof(l_amount_buf), "%s %s", dap_uint256_to_char_ex(*l_summary_snap.spent).frac, l_summary_snap.spent_tok);
        json_object_object_add(o, "locked", json_object_new_string(l_amount_buf));
    } else if (a_tail->flags & DEX_OP_UPDATE) {
        json_object_object_add(o, "rate", json_object_new_string(dap_uint256_to_char_ex(l_price).frac));
        uint256_t l_quote_total = uint256_0;
        MULT_256_COIN(l_base_total, l_price, &l_quote_total);
        l_summary_snap = a_head->side == DEX_SIDE_ASK ? (struct summary_snap){.spent = &l_base_total, .spent_tok = l_base_token}
                                                      : (struct summary_snap){.spent = &l_quote_total, .spent_tok = l_quote_token};
        snprintf(l_amount_buf, sizeof(l_amount_buf), "%s %s", dap_uint256_to_char_ex(*l_summary_snap.spent).frac, l_summary_snap.spent_tok);
        json_object_object_add(o, "updated", json_object_new_string(l_amount_buf));
    } else if (a_tail->flags & DEX_OP_CANCEL) {
        json_object_object_add(o, "rate", json_object_new_string(dap_uint256_to_char_ex(l_price).frac));
        uint256_t l_remaining_base = uint256_0;
        if (compare256(l_exec_base, l_base_total) < 0)
            SUBTRACT_256_256(l_base_total, l_exec_base, &l_remaining_base);
        uint256_t l_remaining_quote = uint256_0;
        MULT_256_COIN(l_remaining_base, l_price, &l_remaining_quote);
        l_summary_snap =
            a_head->side == DEX_SIDE_ASK
                ? (struct summary_snap){.spent = &l_exec_base, .recv = &l_exec_quote, .spent_tok = l_base_token, .recv_tok = l_quote_token}
                : (struct summary_snap){.spent = &l_exec_quote, .recv = &l_exec_base, .spent_tok = l_quote_token, .recv_tok = l_base_token};
        snprintf(l_amount_buf, sizeof(l_amount_buf), "%s %s", dap_uint256_to_char_ex(*l_summary_snap.spent).frac, l_summary_snap.spent_tok);
        json_object_object_add(o, "spent", json_object_new_string(l_amount_buf));
        snprintf(l_amount_buf, sizeof(l_amount_buf), "%s %s", dap_uint256_to_char_ex(*l_summary_snap.recv).frac, l_summary_snap.recv_tok);
        json_object_object_add(o, "received", json_object_new_string(l_amount_buf));
        l_summary_snap.spent = a_head->side == DEX_SIDE_ASK ? &l_remaining_base : &l_remaining_quote;

        snprintf(l_amount_buf, sizeof(l_amount_buf), "%s %s", dap_uint256_to_char_ex(*l_summary_snap.spent).frac, l_summary_snap.spent_tok);
        json_object_object_add(o, "unlocked", json_object_new_string(l_amount_buf));
    }
    return o;
}

/*
 * Order summary iterator for JSON output.
 */
static int s_history_get_summary(dap_chain_net_t *a_net, const dex_pair_key_t *a_key, uint8_t a_filter_flags, int a_limit, int a_offset,
                                 const dap_chain_addr_t *a_seller_addr, const dap_hash_fast_t *a_order_root, json_object *a_arr)
{
    dap_ret_val_if_any(-1, !a_net, !a_key, !a_arr);
    int l_ret = 0;
    dex_hist_pair_t *l_pair = NULL;
    dex_hist_order_idx_t *l_oi = NULL;
    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    HASH_FIND(hh, s_dex_history, a_key, DEX_PAIR_KEY_CMP_SIZE, l_pair);
    if (l_pair) {
        if (a_order_root) {
            HASH_FIND(hh, l_pair->order_idx, a_order_root, sizeof(dap_hash_fast_t), l_oi);
            if (l_oi) do {
                const dex_event_rec_t *l_head = l_oi->events, *l_tail = s_hist_order_tail(l_oi);
                if (!l_head || !l_tail || !s_history_check_flags(l_tail->flags, a_filter_flags))
                    break;
                if (a_seller_addr && (!l_head->seller_addr_ptr || !dap_chain_addr_compare(l_head->seller_addr_ptr, a_seller_addr)))
                    break;
                json_object_array_add(a_arr, s_hist_order_summary_to_json(a_key, a_order_root, l_head, l_tail));
                l_ret = 1;
            } while (0);
        } else {
            int l_off = a_offset, l_lim = a_limit;
            dex_hist_order_idx_t *l_tmp;
            HASH_ITER(hh, l_pair->order_idx, l_oi, l_tmp)
            {
                const dex_event_rec_t *l_head = l_oi->events, *l_tail = s_hist_order_tail(l_oi);
                if (!l_head || !l_tail || !s_history_check_flags(l_tail->flags, a_filter_flags))
                    continue;
                if (a_seller_addr && (!l_head->seller_addr_ptr || !dap_chain_addr_compare(l_head->seller_addr_ptr, a_seller_addr)))
                    continue;
                if (l_off > 0) {
                    --l_off;
                    continue;
                }
                if (a_limit && !l_lim--)
                    break;
                json_object_array_add(a_arr, s_hist_order_summary_to_json(a_key, &l_oi->order_root, l_head, l_tail));
                ++l_ret;
            }
        }
    }
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    return l_ret;
}

/*
 * Get history totals and last price from cache (without building series).
 * Returns: trades count, out_sum_base, out_sum_quote, out_last_price, out_last_ts.
 */
static int s_history_get_totals(const dex_pair_key_t *a_key, uint64_t a_ts_from, uint64_t a_ts_to, const dap_chain_addr_t *a_seller_filter,
                                const dap_chain_addr_t *a_buyer_filter, const dap_hash_fast_t *a_order_root, uint8_t a_filter_flags,
                                uint256_t *a_sum_base, uint256_t *a_sum_quote, uint256_t *a_last_price, uint64_t *a_last_ts)
{
    dap_ret_val_if_any(0, !a_key);
    uint64_t l_to_req = (!a_ts_to || a_ts_to == UINT64_MAX) ? (uint64_t)dap_time_now() : a_ts_to;
    int l_trades = 0;
    uint256_t l_sum_base = uint256_0, l_sum_quote = uint256_0, l_last_price = uint256_0;
    uint64_t l_last_ts = 0;
    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    dex_hist_pair_t *l_pair = NULL;
    HASH_FIND(hh, s_dex_history, a_key, DEX_PAIR_KEY_CMP_SIZE, l_pair);
    if (l_pair) {
        // Use order index if order_root specified, otherwise full scan
        if (a_order_root) {
            dex_hist_order_idx_t *l_oi = NULL;
            HASH_FIND(hh, l_pair->order_idx, a_order_root, sizeof(dap_hash_fast_t), l_oi);
            if (l_oi) {
                dex_event_rec_t *l_rec;
                DL_FOREACH2(l_oi->events, l_rec, order_next)
                {
                    if (l_rec->ts < a_ts_from || l_rec->ts > l_to_req)
                        continue;
                    if ((a_seller_filter &&
                         (!l_rec->seller_addr_ptr || !dap_chain_addr_compare(l_rec->seller_addr_ptr, a_seller_filter))) ||
                        (a_buyer_filter && (!l_rec->buyer_addr_ptr || !dap_chain_addr_compare(l_rec->buyer_addr_ptr, a_buyer_filter))))
                        continue;
                    if (!s_history_check_trade_flags(l_rec->flags, a_filter_flags))
                        continue;
                    uint256_t l_quote;
                    uint256_t l_price = s_hist_event_price(l_rec);
                    MULT_256_COIN(l_rec->trade_b, l_price, &l_quote);
                    SUM_256_256(l_sum_base, l_rec->trade_b, &l_sum_base);
                    SUM_256_256(l_sum_quote, l_quote, &l_sum_quote);
                    ++l_trades;
                    if ((l_rec->flags & DEX_OP_MARKET) && l_rec->ts > l_last_ts) {
                        l_last_ts = l_rec->ts;
                        l_last_price = l_price;
                    }
                }
            }
        } else {
            dex_hist_bucket_t *l_buck = NULL, *l_buck_tmp = NULL;
            HASH_ITER(hh, l_pair->buckets, l_buck, l_buck_tmp)
            {
                dex_event_rec_t *l_rec, *l_rec_tmp;
                HASH_ITER(hh, l_buck->events_idx, l_rec, l_rec_tmp)
                {
                    if (l_rec->ts < a_ts_from || l_rec->ts > l_to_req)
                        continue;
                    if ((a_seller_filter &&
                         (!l_rec->seller_addr_ptr || !dap_chain_addr_compare(l_rec->seller_addr_ptr, a_seller_filter))) ||
                        (a_buyer_filter && (!l_rec->buyer_addr_ptr || !dap_chain_addr_compare(l_rec->buyer_addr_ptr, a_buyer_filter))))
                        continue;
                    if (!s_history_check_trade_flags(l_rec->flags, a_filter_flags))
                        continue;
                    uint256_t l_price = s_hist_event_price(l_rec), l_quote;
                    MULT_256_COIN(l_rec->trade_b, l_price, &l_quote);
                    SUM_256_256(l_sum_base, l_rec->trade_b, &l_sum_base);
                    SUM_256_256(l_sum_quote, l_quote, &l_sum_quote);
                    ++l_trades;
                    if ((l_rec->flags & DEX_OP_MARKET) && l_rec->ts > l_last_ts) {
                        l_last_ts = l_rec->ts;
                        l_last_price = l_price;
                    }
                }
            }
        }
    }
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    if (a_sum_base)
        *a_sum_base = l_sum_base;
    if (a_sum_quote)
        *a_sum_quote = l_sum_quote;
    if (a_last_price)
        *a_last_price = l_last_price;
    if (a_last_ts)
        *a_last_ts = l_last_ts;
    return l_trades;
}

/*
 * Build OHLCV series from history cache with on-the-fly aggregation.
 * a_bucket_sec: desired candle size (can differ from storage bucket size)
 * a_fill_missing: if true, emit zero-trade candles with propagated close price
 * Returns number of candles emitted.
 */
static int s_history_build_ohlcv_series(const dex_pair_key_t *a_key, uint64_t a_ts_from, uint64_t a_ts_to, uint64_t a_bucket_sec,
                                        bool a_with_ohlc, bool a_fill_missing, const dap_chain_addr_t *a_seller_filter,
                                        const dap_chain_addr_t *a_buyer_filter, const dap_hash_fast_t *a_order_root, uint8_t a_filter_flags,
                                        json_object *a_arr)
{
    dap_ret_val_if_any(-1, !a_key, !a_bucket_sec, !a_arr);
    uint64_t l_to_req = (!a_ts_to || a_ts_to == UINT64_MAX) ? (uint64_t)dap_time_now() : a_ts_to;
    dap_ret_val_if_any(-1, l_to_req < a_ts_from);
    int l_ret = 0;
    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    dex_hist_pair_t *l_pair = NULL;
    HASH_FIND(hh, s_dex_history, a_key, DEX_PAIR_KEY_CMP_SIZE, l_pair);
    if (l_pair) {
        // Collect all buckets that overlap with time range
        size_t l_cap = HASH_CNT(hh, l_pair->buckets);
        dex_hist_bucket_t **l_buckets = DAP_NEW_Z_COUNT(dex_hist_bucket_t *, l_cap);
        if (!l_buckets) {
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
            return -2;
        }
        size_t l_used = 0;
        dex_hist_bucket_t *l_buck = NULL, *l_buck_tmp = NULL;
        HASH_ITER(hh, l_pair->buckets, l_buck, l_buck_tmp)
        l_buckets[l_used++] = l_buck;

        if (l_used) {
            qsort(l_buckets, l_used, sizeof(*l_buckets), s_cmp_bucket_ptr_ts);
            // Build output candles at requested granularity
            // If no start time specified, use first bucket's ts for proper calendar alignment
            uint64_t l_candle_start =
                         s_hist_bucket_ts((a_ts_from && a_ts_from > l_buckets[0]->ts) ? a_ts_from : l_buckets[0]->ts, a_bucket_sec),
                     l_prev_candle = 0;
            uint256_t l_last_close = uint256_0;
            for (uint64_t l_cs = l_candle_start; l_cs <= l_to_req; l_cs += a_bucket_sec) {
                uint64_t l_from = l_cs < a_ts_from ? a_ts_from : l_cs, l_ce_full = l_cs + a_bucket_sec - 1,
                         l_to = l_ce_full < l_cs || l_ce_full > l_to_req ? l_to_req : l_ce_full;
                if (l_to < l_from)
                    continue;
                dex_ohlcv_t l_ohlcv = {.ts = l_cs};
                // Aggregate all overlapping storage buckets
                for (size_t i = 0; i < l_used; i++) {
                    if (l_buckets[i]->ts > l_to)
                        break;
                    if (l_buckets[i]->ts + s_dex_history_bucket_sec <= l_from)
                        continue;
                    dex_ohlcv_t l_part = {};
                    s_calc_ohlcv_from_bucket(l_buckets[i], l_from, l_to, a_seller_filter, a_buyer_filter, a_order_root, a_filter_flags,
                                             &l_part);
                    // Merge partial into candle
                    SUM_256_256(l_ohlcv.volume_base, l_part.volume_base, &l_ohlcv.volume_base);
                    SUM_256_256(l_ohlcv.volume_quote, l_part.volume_quote, &l_ohlcv.volume_quote);
                    l_ohlcv.trades += l_part.trades;
                    if (!IS_ZERO_256(l_part.open)) {
                        if (IS_ZERO_256(l_ohlcv.open)) {
                            l_ohlcv.open = l_part.open;
                            l_ohlcv.high = l_part.high;
                            l_ohlcv.low = l_part.low;
                        } else {
                            if (compare256(l_part.high, l_ohlcv.high) > 0)
                                l_ohlcv.high = l_part.high;
                            if (compare256(l_part.low, l_ohlcv.low) < 0)
                                l_ohlcv.low = l_part.low;
                        }
                        l_ohlcv.close = l_part.close;
                    }
                }
                // Fill missing candles with last close price
                if (a_fill_missing && l_prev_candle && l_cs > l_prev_candle + a_bucket_sec && !IS_ZERO_256(l_last_close)) {
                    for (uint64_t t = l_prev_candle + a_bucket_sec; t < l_cs; t += a_bucket_sec) {
                        dex_ohlcv_t l_gap = {
                            .ts = t, .open = l_last_close, .high = l_last_close, .low = l_last_close, .close = l_last_close};
                        s_ohlcv_to_json(a_arr, &l_gap, a_with_ohlc);
                        ++l_ret;
                    }
                }
                // Emit candle only if has trades or fill_missing with known close
                if (l_ohlcv.trades || (a_fill_missing && !IS_ZERO_256(l_last_close))) {
                    if (l_ohlcv.trades) {
                        if (!IS_ZERO_256(l_ohlcv.close))
                            l_last_close = l_ohlcv.close;
                    } else
                        l_ohlcv.open = l_ohlcv.high = l_ohlcv.low = l_ohlcv.close = l_last_close;
                    s_ohlcv_to_json(a_arr, &l_ohlcv, a_with_ohlc);
                    ++l_ret;
                    l_prev_candle = l_cs;
                }
            }
        }
        DAP_DELETE(l_buckets);
    }
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    return l_ret;
}

/*
 * Compute order fill percent by ledger chain.
 */
static int s_dex_calc_order_fill_pct_ledger(dap_chain_net_t *a_net, const dap_hash_fast_t *a_hash, uint8_t *a_out_pct)
{
    dap_ret_val_if_any(-1, !a_net, !a_hash, !a_out_pct, dap_hash_fast_is_blank(a_hash));
    *a_out_pct = 0;
    dap_chain_datum_tx_t *l_hash_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, (dap_chain_hash_fast_t *)a_hash);
    if (!l_hash_tx)
        return -2;
    dap_chain_tx_out_cond_t *l_out = NULL;
    dap_hash_fast_t l_root =
        dap_ledger_get_first_chain_tx_hash_ex(a_net->pub.ledger, l_hash_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out);
    if (dap_hash_fast_is_blank(&l_root)) {
        if (!l_out)
            return -2;
        l_root = *a_hash;
    }
    dap_chain_datum_tx_t *l_root_tx =
        dap_hash_fast_compare(a_hash, &l_root) ? l_hash_tx : dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_root);
    if (!l_root_tx)
        return -2;
    int l_out_idx = 0;
    l_out = dap_chain_datum_tx_out_cond_get(l_root_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
    if (!l_out || (!dap_hash_fast_is_blank(&l_out->subtype.srv_dex.order_root_hash) &&
                   !dap_hash_fast_compare(&l_out->subtype.srv_dex.order_root_hash, &l_root)))
        return -2;
    uint256_t l_base = l_out->header.value, l_remaining = uint256_0;
    dap_hash_fast_t l_cur_hash = l_root;
    for (;;) {
        dap_hash_fast_t l_spender = {};
        if (!dap_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &l_cur_hash, l_out_idx, &l_spender) ||
            dap_hash_fast_is_blank(&l_spender)) {
            l_remaining = l_out->header.value;
            break;
        }
        dap_chain_datum_tx_t *l_spender_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_spender);
        if (!l_spender_tx) {
            l_remaining = l_out->header.value;
            break;
        }
        int l_next_idx = 0;
        dap_chain_tx_out_cond_t *l_next_out =
            dap_chain_datum_tx_out_cond_get(l_spender_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_next_idx);
        if (l_next_out && !dap_hash_fast_is_blank(&l_next_out->subtype.srv_dex.order_root_hash) &&
            dap_hash_fast_compare(&l_next_out->subtype.srv_dex.order_root_hash, &l_root)) {
            if ((dex_tx_type_t)l_next_out->subtype.srv_dex.tx_type == DEX_TX_TYPE_UPDATE)
                l_base = l_next_out->header.value;
            l_cur_hash = l_spender;
            l_out = l_next_out;
            l_out_idx = l_next_idx;
            continue;
        }
        bool l_is_trade = s_dex_verify_payout(l_spender_tx, a_net, l_out->subtype.srv_dex.buy_token, &l_out->subtype.srv_dex.seller_addr);
        l_remaining = l_is_trade ? uint256_0 : l_out->header.value;
        break;
    }
    if (IS_ZERO_256(l_base))
        l_base = l_remaining;
    if (IS_ZERO_256(l_base) || compare256(l_remaining, l_base) >= 0)
        return 0;
    uint256_t l_exec = uint256_0;
    SUBTRACT_256_256(l_base, l_remaining, &l_exec);
    MULT_256_256(l_exec, GET_256_FROM_64(100ULL), &l_exec);
    DIV_256(l_exec, l_base, &l_exec);
    uint64_t l_pct = dap_chain_uint256_to(l_exec);
    *a_out_pct = (uint8_t)(l_pct > 100 ? 100 : l_pct);
    return 0;
}

// ---- Raw trades iterator for JSON output ----
// a_filter_flags: if non-zero, only records with (flags & a_filter_flags) != 0 are included
// a_seller_addr: if non-NULL, only trades from this seller are included
static int s_history_get_raw_events(dap_chain_net_t *a_net, const dex_pair_key_t *a_key, uint64_t a_ts_from, uint64_t a_ts_to,
                                    uint8_t a_filter_flags, int a_limit, int a_offset, const dap_chain_addr_t *a_seller_addr,
                                    const dap_chain_addr_t *a_buyer_addr, const dap_hash_fast_t *a_order_root, json_object *a_arr)
{
    dap_ret_val_if_any(-1, !a_net, !a_key, !a_arr);
    uint64_t l_to_req = (!a_ts_to || a_ts_to == UINT64_MAX) ? (uint64_t)dap_time_now() : a_ts_to;
    int l_ret = 0;
    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    dex_hist_pair_t *l_pair = NULL;
    HASH_FIND(hh, s_dex_history, a_key, DEX_PAIR_KEY_CMP_SIZE, l_pair);
    if (l_pair) {
        // Collect trades: use order index if a_order_root specified, otherwise full scan
        size_t l_cap = 0;
        dex_hist_order_idx_t *l_oi = NULL;
        if (a_order_root) {
            HASH_FIND(hh, l_pair->order_idx, a_order_root, sizeof(dap_hash_fast_t), l_oi);
            if (l_oi) {
                dex_event_rec_t *l_rec;
                DL_COUNT2(l_oi->events, l_rec, l_cap, order_next);
            }
        } else {
            dex_hist_bucket_t *l_buck = NULL, *l_buck_tmp = NULL;
            HASH_ITER(hh, l_pair->buckets, l_buck, l_buck_tmp)
            {
                l_cap += HASH_CNT(hh, l_buck->events_idx);
            }
        }

        if (l_cap) {
            dex_event_rec_t **l_trades = DAP_NEW_Z_COUNT(dex_event_rec_t *, l_cap);
            if (l_trades) {
                size_t l_used = 0;
                if (l_oi) {
                    dex_event_rec_t *l_rec;
                    DL_FOREACH2(l_oi->events, l_rec, order_next)
                    {
                        if (l_rec->ts >= a_ts_from && l_rec->ts <= l_to_req && s_history_check_flags(l_rec->flags, a_filter_flags) &&
                            !(a_seller_addr &&
                              (!l_rec->seller_addr_ptr || !dap_chain_addr_compare(l_rec->seller_addr_ptr, a_seller_addr))) &&
                            !(a_buyer_addr && (!l_rec->buyer_addr_ptr || !dap_chain_addr_compare(l_rec->buyer_addr_ptr, a_buyer_addr))))
                            l_trades[l_used++] = l_rec;
                    }
                } else {
                    dex_hist_bucket_t *l_buck = NULL, *l_buck_tmp = NULL;
                    HASH_ITER(hh, l_pair->buckets, l_buck, l_buck_tmp)
                    {
                        dex_event_rec_t *l_rec, *l_rec_tmp;
                        HASH_ITER(hh, l_buck->events_idx, l_rec, l_rec_tmp)
                        {
                            if (l_rec->ts >= a_ts_from && l_rec->ts <= l_to_req && s_history_check_flags(l_rec->flags, a_filter_flags) &&
                                !(a_seller_addr &&
                                  (!l_rec->seller_addr_ptr || !dap_chain_addr_compare(l_rec->seller_addr_ptr, a_seller_addr))) &&
                                !(a_buyer_addr && (!l_rec->buyer_addr_ptr || !dap_chain_addr_compare(l_rec->buyer_addr_ptr, a_buyer_addr))))
                                l_trades[l_used++] = l_rec;
                        }
                    }
                }
                // Sort by timestamp ascending
                qsort(l_trades, l_used, sizeof(*l_trades), s_cmp_event_ptr_ts);
                // Apply offset/limit and emit JSON
                int l_offset = a_offset, l_limit = a_limit;
                for (size_t i = 0; i < l_used; i++) {
                    if (l_offset > 0) {
                        --l_offset;
                        continue;
                    }
                    if (a_limit && !l_limit--)
                        break;
                    dex_event_rec_t *r = l_trades[i];
                    uint256_t l_base = (r->flags & (DEX_OP_CREATE | DEX_OP_UPDATE | DEX_OP_CANCEL)) ? r->val_b_remain : r->trade_b,
                              l_price = s_hist_event_price(r), l_quote;
                    MULT_256_COIN(l_base, l_price, &l_quote);
                    json_object *o = json_object_new_object();
                    json_object_object_add(o, "ts", json_object_new_uint64(r->ts));
                    char l_ts_str[DAP_TIME_STR_SIZE];
                    dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), r->ts);
                    json_object_object_add(o, "ts_str", json_object_new_string(l_ts_str));
                    json_object_object_add(o, "price", json_object_new_string(dap_uint256_to_char_ex(l_price).frac));
                    json_object_object_add(o, "base", json_object_new_string(dap_uint256_to_char_ex(l_base).frac));
                    if (r->flags & (DEX_OP_CREATE | DEX_OP_UPDATE | DEX_OP_CANCEL)) {
                        json_object_object_add(o, "base_kind", json_object_new_string("order"));
                        json_object_object_add(o, "order_value", json_object_new_string(dap_uint256_to_char_ex(r->val_b_remain).frac));
                    } else {
                        json_object_object_add(o, "base_kind", json_object_new_string("trade"));
                        json_object_object_add(o, "trade_base", json_object_new_string(dap_uint256_to_char_ex(r->trade_b).frac));
                    }
                    json_object_object_add(o, "quote", json_object_new_string(dap_uint256_to_char_ex(l_quote).frac));
                    json_object_object_add(o, "tx_hash", json_object_new_string(dap_hash_fast_to_str_static(&r->key.tx_hash)));
                    json_object_object_add(o, "prev_tail", json_object_new_string(dap_hash_fast_to_str_static(&r->key.prev_tail)));
                    json_object_object_add(o, "side", json_object_new_string(r->side == DEX_SIDE_ASK ? "ask" : "bid"));
                    if (r->seller_addr_ptr)
                        json_object_object_add(o, "seller", json_object_new_string(dap_chain_addr_to_str_static(r->seller_addr_ptr)));
                    if (r->buyer_addr_ptr)
                        json_object_object_add(o, "buyer", json_object_new_string(dap_chain_addr_to_str_static(r->buyer_addr_ptr)));
                    if (r->order_root_ptr) {
                        json_object_object_add(o, "order_root", json_object_new_string(dap_hash_fast_to_str_static(r->order_root_ptr)));
                        json_object_object_add(o, "filled_pct", json_object_new_int(r->filled_pct));
                    }
                    json_object_object_add(o, "type", json_object_new_string(s_dex_op_flags_to_str(r->flags)));
                    json_object_array_add(a_arr, o);
                    ++l_ret;
                }
                DAP_DELETE(l_trades);
            }
        }
    }
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    return l_ret;
}

/* ============================================================================
 * Order Cache Upsert/Remove
 * Cache entry lifecycle, index insert/remove implementations
 * ============================================================================ */

/*
 * Upsert (insert or update) a DEX order entry in the hot cache and all indices.
 *
 * Inputs:
 * - a_ledger: ledger to resolve optional sell token by tail when a_sell_token is NULL
 * - a_sell_token: optional explicit sell token ticker (faster path); if NULL, resolved from a_tail
 * - a_root: order root hash (stable across residual updates)
 * - a_tail: current tail hash (changes on residual/updates)
 * - a_cond: SRV_DEX conditional output describing current order state
 *
 * Behavior (under WR lock):
 * 1) Find or create primary entry keyed by root; initialize ts_created on first insert
 * 2) Derive canonical pair (BASE/QUOTE), side and canonical price (QUOTE/BASE) via s_pair_normalize()
 * 3) Remove entry from all secondary indices via back-pointers (O(1))
 * 4) Update entry fields (pair_key, tail, price, side, value, seller_addr, ts_expires, flags, version/fill)
 * 5) Insert entry into all indices (tail, pair bucket, seller bucket); store back-pointers
 */
static void s_dex_cache_upsert(dap_ledger_t *a_ledger, const char *a_sell_token, dap_chain_hash_fast_t *a_root,
                               dap_chain_hash_fast_t *a_tail, dap_chain_tx_out_cond_t *a_cond, int a_prev_idx, dap_time_t a_ts_created,
                               const char *a_type_str)
{
    dap_ret_if_any(!a_root, !a_tail, !a_cond);
    /*
     * PHASE 1 (no lock): fast validation and canonicalization
     * - resolve ORDER's sell_token (arg or by tail from ledger)
     * - validate ORDER's buy_token
     * - normalize pair to canonical BASE/QUOTE and compute canonical price (QUOTE/BASE)
     * Any failure: early return without touching cache/indices.
     */
    char l_hashes_str[2 * DAP_HASH_FAST_STR_SIZE + sizeof(" → ") + 1];
    dap_hash_fast_compare(a_root, a_tail)
        ? snprintf(l_hashes_str, sizeof(l_hashes_str), "%s", dap_hash_fast_to_str_static(a_root))
        : snprintf(l_hashes_str, sizeof(l_hashes_str), "%s → %s", dap_hash_fast_to_str_static(a_root), dap_hash_fast_to_str_static(a_tail));
    const char *l_sell_ticker =
        (a_sell_token && *a_sell_token) ? a_sell_token : (a_ledger ? dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tail) : NULL);
    if (!l_sell_ticker || !*l_sell_ticker)
        return log_it(L_ERROR, "%s(): Skip order %s: sell token not resolved", __FUNCTION__, l_hashes_str);
    if (!*a_cond->subtype.srv_dex.buy_token)
        return log_it(L_ERROR, "%s(): Skip order %s: invalid buy token", __FUNCTION__, l_hashes_str);

    dex_pair_key_t l_new_key = {};
    uint8_t side = 0;
    uint256_t l_price_canon = uint256_0;
    s_dex_pair_normalize(l_sell_ticker, a_cond->subtype.srv_dex.sell_net_id, a_cond->subtype.srv_dex.buy_token,
                         a_cond->subtype.srv_dex.buy_net_id, a_cond->subtype.srv_dex.rate, &l_new_key, &side, &l_price_canon);
    if (!*l_new_key.token_quote || !*l_new_key.token_base)
        return log_it(L_ERROR, "%s(): Skip order %s: pair normalization failed", __FUNCTION__, l_hashes_str);

    /*
     * PHASE 2 (with WR lock): atomically update primary table and all indices
     * Strict order: find/create → update non-index fields → remove → apply indexed fields → insert → log
     */
    dex_pair_index_t *l_pair_idx = s_dex_pair_index_get(&l_new_key);
    if (!l_pair_idx)
        return log_it(L_ERROR, "%s(): Skip order %s: pair %s/%s not whitelisted", __FUNCTION__, l_hashes_str, l_new_key.token_base,
                      l_new_key.token_quote);

    unsigned l_hashv;
    HASH_VALUE(a_root, sizeof(*a_root), l_hashv);
    dex_order_cache_entry_t *e = NULL;
    HASH_FIND_BYHASHVALUE(level.hh, s_dex_orders_cache, a_root, sizeof(*a_root), l_hashv, e);
    bool l_is_new = !e;
    if (l_is_new) {
        /* First appearance for this root: create entry and set ts_created */
        e = DAP_NEW_Z(dex_order_cache_entry_t);
        e->level.match.root = *a_root;
        e->ts_created = a_ts_created;
    } else
        /*
         * Existing entry: detach from indices first (back-pointer removal, O(1))
         * New entries are not indexed yet, so removal would be a no-op — we do it only for existing ones for efficiency.
         */
        s_dex_indexes_remove(e);

    /* Apply indexed fields and current state */
    e->level.match.value = a_cond->header.value;
    if (l_is_new || dap_hash_fast_compare(a_root, a_tail) || (dex_tx_type_t)a_cond->subtype.srv_dex.tx_type == DEX_TX_TYPE_UPDATE)
        e->value_base = a_cond->header.value;
    e->ts_expires = a_cond->header.ts_expires;
    e->flags = a_cond->subtype.srv_dex.flags;
    e->level.match.tail = *a_tail;
    e->level.match.rate = l_price_canon;
    e->side_version = (uint8_t)((a_cond->subtype.srv_dex.version & 0x7F) << 1) | (side & 0x1);
    e->level.match.min_fill = a_cond->subtype.srv_dex.min_fill;
    e->level.match.prev_idx = a_prev_idx;
    if (l_is_new)
        HASH_ADD_BYHASHVALUE(level.hh, s_dex_orders_cache, level.match.root, sizeof(e->level.match.root), l_hashv, e);
    /* Insert into indices (tail, pair, seller); back-pointers are set inside */
    s_dex_indexes_upsert(l_pair_idx, l_hashv, &a_cond->subtype.srv_dex.seller_addr, e);

    debug_if(s_debug_more, L_DEBUG, "%s(): Added %s order %s, type: %s, pair: %s/%s @ %s, value: %s, seller addr: %s", __FUNCTION__,
             (e->side_version & 0x1) == DEX_SIDE_ASK ? "ASK" : "BID", l_hashes_str, a_type_str,
             e->pair_key_ptr ? e->pair_key_ptr->token_base : "?", e->pair_key_ptr ? e->pair_key_ptr->token_quote : "?",
             dap_uint256_to_char_ex(e->level.match.rate).frac, dap_uint256_to_char_ex(e->level.match.value).frac,
             dap_chain_addr_to_str_static((dap_chain_addr_t *)e->seller_addr_ptr));
}

static inline void s_dex_cache_remove(dex_order_cache_entry_t *a_entry)
{
    dap_ret_if_any(!a_entry);
    s_dex_indexes_remove(a_entry);
    HASH_DELETE(level.hh, s_dex_orders_cache, a_entry);
    debug_if(s_debug_more, L_DEBUG,
             dap_hash_fast_compare(&a_entry->level.match.root, &a_entry->level.match.tail) ? "%s(): removed order %s"
                                                                                           : "%s(): removed order %s → %s",
             __FUNCTION__, dap_hash_fast_to_str_static(&a_entry->level.match.root),
             dap_hash_fast_to_str_static(&a_entry->level.match.tail));
    DAP_DELETE(a_entry);
}

static inline void s_dex_cache_remove_by_root(dap_chain_hash_fast_t *a_root)
{
    dap_ret_if_any(!a_root);
    dex_order_cache_entry_t *e = NULL;
    HASH_FIND(level.hh, s_dex_orders_cache, a_root, sizeof(*a_root), e);
    s_dex_cache_remove(e);
}

/* ============================================================================
 * Verificator
 * SRV_DEX transaction verification callback
 * ============================================================================ */

/*
 * s_dex_verificator_callback
 * -----------------------------------------------------------------------------
 * Purpose:
 *   Verify SRV_DEX semantics for a transaction:
 *     - Distinguish SELLER leftover update (seller reduces own order) vs BUYER leftover (buyer creates new order)
 *     - Validate per-seller payouts in buy token (exact match to executed * rate)
 *     - Validate network/service/validator fees
 *     - Validate final payout in sell token (with/without native fees)
 *
 * Inputs:
 *   a_ledger     - ledger context
 *   a_tx_out_cond- SRV_DEX OUT condition of current TX (if any) used for context
 *   a_tx_in      - full TX to verify
 *   a_owner      - whether the TX is signed by the order owner (enables fast-path update)
 *
 */
static int s_dex_verificator_callback(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_tx_out_cond, dap_chain_datum_tx_t *a_tx_in,
                                      bool a_owner, UNUSED_ARG bool a_check_for_apply)
{
    // a_tx_out_cond may be NULL for ORDER (new OUT_COND creation, not consumption)
    dap_ret_val_if_any(DEXV_INVALID_PARAMS, !a_ledger, !a_tx_in);

    int l_err = 0, l_err_line = 0;
#define RET_ERR(_err)                                                                                                                      \
    do {                                                                                                                                   \
        l_err = _err;                                                                                                                      \
        l_err_line = __LINE__;                                                                                                             \
        goto dex_verif_ret_err;                                                                                                            \
    } while (0)
    // Phase 0: Pre-scan TX items (O(n))
    //  - Count IN_COND items
    //  - Locate a SINGLE SRV_DEX OUT (enforce at most one)
    //  - Cache the very first IN_COND (l_in0) and resolve its previous SRV_DEX OUT
    //    to enable:
    //      * fast-path owner update (1 IN + SRV_DEX OUT with non-blank root)
    //      * baseline extraction for Phase 2
    struct dex_seller_info {
        dap_chain_addr_t addr;
        uint256_t expected_buy, paid_buy, paid_sell;
    } *l_sellers = NULL;

    typedef struct {
        const dap_chain_addr_t *addr;
        const char *token;
        uint256_t value;
        int seller_idx;   // -1 if not a seller, [0..S) if seller
        uint8_t out_type; // TX_ITEM_TYPE_OUT_EXT, etc.
    } dex_out_t;
    dex_out_t *l_outs = NULL;

    dap_chain_tx_out_cond_t **l_prev_outs = NULL;
    uint256_t l_fee_native = uint256_0;
    // Canonical reconstruction entries (built later if needed)
    typedef struct {
        int idx; // Original IN_COND index (before sorting)
        dap_chain_addr_t seller;
        uint256_t price_normal; // QUOTE / BASE price (normalized)
        uint256_t base_full;    // Full tradable BASE amount for this IN
    } dex_canon_in_t;
    dex_canon_in_t *l_canon_ins = NULL;
    // Structure for regular IN data (resolved for fee verification and cashback)
    typedef struct {
        dap_chain_addr_t addr; // Owner of the spent OUT
        const char *token;     // Token ticker (NULL for legacy OUT without token)
        uint256_t value;       // Value of the spent OUT
    } dex_in_t;
    dex_in_t *l_ins = NULL;

    int l_in_cond_cnt = 0, l_out_cnt = 0, l_in_cnt = 0;
    dap_chain_tx_out_cond_t *l_out_cond = NULL;

    byte_t *it;
    size_t sz;
    TX_ITEM_ITER_TX(it, sz, a_tx_in)
    {
        switch (*it) {
        case TX_ITEM_TYPE_IN:
            ++l_in_cnt;
            continue;
        case TX_ITEM_TYPE_SIG:
        case TX_ITEM_TYPE_PKEY:
            continue;
        case TX_ITEM_TYPE_IN_COND:
            ++l_in_cond_cnt;
            break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *l_out = (dap_chain_tx_out_cond_t *)it;
            if (l_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                SUM_256_256(l_fee_native, l_out->header.value, &l_fee_native);
            else if (l_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX) {
                if (l_out_cond)
                    RET_ERR(DEXV_MULTIPLE_SRV_DEX_OUT);
                else
                    l_out_cond = l_out;
            } else
                RET_ERR(DEXV_INVALID_TX_ITEM);
        } break;
        case TX_ITEM_TYPE_OUT_EXT:
        case TX_ITEM_TYPE_OUT_STD:
        case TX_ITEM_TYPE_OUT:
            ++l_out_cnt;
            break;
        default:
            log_it(L_ERROR, "Unexpected TX item type: %d", *it);
            RET_ERR(DEXV_INVALID_TX_ITEM);
        }
    }
    // Diagnostics: INs and SRV_DEX OUT presence
    if (s_debug_more) {
        const char *l_tx_type_str = "n/a";
        if (l_out_cond) {
            switch (l_out_cond->subtype.srv_dex.tx_type) {
            case DEX_TX_TYPE_UPDATE:
                l_tx_type_str = "UPDATE";
                break;
            case DEX_TX_TYPE_EXCHANGE:
                l_tx_type_str = "EXCHANGE";
                break;
            case DEX_TX_TYPE_ORDER:
                l_tx_type_str = "ORDER";
                break;
            case DEX_TX_TYPE_INVALIDATE:
                l_tx_type_str = "INVALIDATE";
                break;
            default:
                break;
            }
        }
        const char *l_root_hash_str = l_out_cond ? (!dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash)
                                                        ? dap_chain_hash_fast_to_str_static(&l_out_cond->subtype.srv_dex.order_root_hash)
                                                        : "0x0")
                                                 : "undefined";
        const char *l_left_val = l_out_cond ? dap_uint256_to_char_ex(l_out_cond->header.value).frac : "undefined";

        debug_if(s_debug_more, L_DEBUG,
                 "{ %s, phase 0 } Pre-scan; %d IN_COND's; %d OUT_STD/EXT's; DEX OUT_COND: %s; Preliminary type: %s; Root tx: %s; Leftover "
                 "value: %s",
                 __FUNCTION__, l_in_cond_cnt, l_out_cnt, l_out_cond ? "yes" : "no", l_tx_type_str, l_root_hash_str, l_left_val);
    }

    // Phase 1: Fast-paths based on IN count
    //   - ORDER (create): 0 IN_COND + SRV_DEX OUT with tx_type=ORDER is allowed
    //  - 0 IN: invalid (-3)
    //  - 1 IN + SRV_DEX OUT with non-blank root + a_owner==true:
    //      owner UPDATE (no trade) — verify immutables and ensure seller gets no payout in buy token
    switch (l_in_cond_cnt) {
    case 0:
        if (!l_out_cond || l_out_cond->subtype.srv_dex.tx_type != DEX_TX_TYPE_ORDER ||
            !dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash))
            RET_ERR(DEXV_TX_TYPE_MISMATCH);

        // ORDER path: structural validation
        // Note: sell_ticker not available yet (determined by ledger when TX is added)
        // Network fee will be validated at the common check (line 3031)
        if (!*l_out_cond->subtype.srv_dex.buy_token)
            RET_ERR(DEXV_BASELINE_BUY_TOKEN);

        debug_if(s_debug_more, L_DEBUG, "{ %s, phase 1 } ORDER validated; Buy token: %s", __FUNCTION__,
                 l_out_cond->subtype.srv_dex.buy_token);
        // Fall-through: ORDER continues to Phase 2 for network fee OUT aggregation
    case 1:
        if (a_tx_out_cond && l_out_cond && (l_out_cond->subtype.srv_dex.tx_type == DEX_TX_TYPE_UPDATE) &&
            (!a_owner || dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash)))
            RET_ERR(DEXV_TX_TYPE_MISMATCH);
    default:
        // Validate residual value/rate
        if (l_out_cond && (IS_ZERO_256(l_out_cond->header.value) || IS_ZERO_256(l_out_cond->subtype.srv_dex.rate)))
            RET_ERR(DEXV_INVALID_RESIDUAL);
        break;
    }

    // Phase 2: Combined scan - process INs inline, classify OUTs to array
    const char *l_buy_ticker = NULL, *l_sell_ticker = NULL, *l_native_ticker = a_ledger->net->pub.native_ticker;
    dap_chain_net_id_t l_sell_net_id = {}, l_buy_net_id = {};
    dap_time_t l_now = dap_ledger_get_blockchain_time(a_ledger);
    bool l_is_leftover = l_out_cond && !dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash), l_is_invalidate = !l_out_cond,
         l_is_update = false;
    int l_uniq_sllrs_cnt = 0, l_in_idx = 0, l_in_cond_idx = 0, l_out_idx = 0;
    uint256_t l_executed_total = uint256_0;
    dex_pair_index_t *l_pair_idx = NULL;       // Pair whitelist entry (set on first IN/IN_COND)
    uint8_t l_fee_cfg = 0,                     // Cached fee config (read once under lock)
        l_baseline_side = 0xFF;                // Baseline side (ASK/BID), set from first IN_COND
    uint256_t l_native_fee_cached = uint256_0; // Cached native fee amount (read once under lock)
    dap_hash_fast_t l_first_in_prev_hash = {}; // prev_hash from first IN_COND (for seller-leftover validation)

    // Allocate arrays for processing
    l_sellers = DAP_NEW_Z_COUNT(struct dex_seller_info, l_in_cond_cnt);
    l_prev_outs = DAP_NEW_Z_COUNT(dap_chain_tx_out_cond_t *, l_in_cond_cnt);
    l_outs = DAP_NEW_Z_COUNT(dex_out_t, l_out_cnt);
    l_ins = DAP_NEW_Z_COUNT(dex_in_t, l_in_cnt);

    TX_ITEM_ITER_TX(it, sz, a_tx_in)
    {
        switch (*it) {
        case TX_ITEM_TYPE_IN_COND: {
            dap_chain_tx_in_cond_t *l_in = (dap_chain_tx_in_cond_t *)it;
            dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_in->header.tx_prev_hash);
            if (!l_prev_tx)
                RET_ERR(DEXV_PREV_TX_NOT_FOUND);

            dap_chain_tx_out_cond_t *l_prev = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
            if (!l_prev)
                RET_ERR(DEXV_PREV_OUT_NOT_FOUND);
            l_prev_outs[l_in_cond_idx] = l_prev;

            // Save first IN_COND's prev_hash for seller-leftover validation
            if (l_in_cond_idx == 0)
                l_first_in_prev_hash = l_in->header.tx_prev_hash;
            else if (l_is_leftover &&
                     dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_prev->subtype.srv_dex.seller_addr)) {
                // Seller-leftover detected on non-first position: verify it's a different order (different chain)
                dap_hash_fast_t l_this_root =
                    dap_ledger_get_first_chain_tx_hash(a_ledger, l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                if (dap_hash_fast_is_blank(&l_this_root))
                    l_this_root = l_in->header.tx_prev_hash;

                if (dap_hash_fast_compare(&l_out_cond->subtype.srv_dex.order_root_hash, &l_this_root)) {
                    log_it(L_ERROR, "%s(): Protocol violation: seller-leftover found at IN_COND #%d != 0", __FUNCTION__, l_in_cond_idx);
                    RET_ERR(DEXV_LEFTOVER_STRUCTURE_VIOLATION);
                }
            }
            // Expiry check (skip for UPDATE/INVALIDATE)
            if (l_out_cond && l_out_cond->subtype.srv_dex.tx_type != DEX_TX_TYPE_UPDATE &&
                l_out_cond->subtype.srv_dex.tx_type != DEX_TX_TYPE_INVALIDATE) {
                if (l_prev->header.ts_expires && l_now > l_prev->header.ts_expires)
                    RET_ERR(DEXV_EXPIRED);
            }

            // Establish baseline from first IN
            const char *l_sell_cur = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_in->header.tx_prev_hash);
            if (!l_sell_cur)
                RET_ERR(DEXV_BASELINE_BUY_TOKEN);

            if (!l_sell_ticker) {
                l_sell_ticker = l_sell_cur;
                l_buy_ticker = l_prev->subtype.srv_dex.buy_token;
                l_sell_net_id = l_prev->subtype.srv_dex.sell_net_id;
                l_buy_net_id = l_prev->subtype.srv_dex.buy_net_id;

                // Whitelist check: pair must be whitelisted via decree
                // Also save l_pair_idx and l_pair_baseline_side for all IN_COND
                dex_pair_key_t l_check_key = {};
                s_dex_pair_normalize(l_sell_ticker, l_sell_net_id, l_buy_ticker, l_buy_net_id, l_prev->subtype.srv_dex.rate, &l_check_key,
                                     &l_baseline_side, NULL);
                pthread_rwlock_rdlock(&s_dex_cache_rwlock);
                l_pair_idx = s_dex_pair_index_get(&l_check_key);
                if (l_pair_idx) {
                    l_fee_cfg = l_pair_idx->key.fee_config;
                    l_native_fee_cached = s_dex_native_fee_amount;
                }
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
                debug_if(s_debug_more, L_DEBUG,
                         "{ %s, phase 2 } Baseline IN_COND; %s; Sell %s in net id %" DAP_UINT64_FORMAT_U
                         "; Buy %s in net id %" DAP_UINT64_FORMAT_U "; "
                         "Rate %s; Canonical pair: %s/%s; %swhitelisted",
                         __FUNCTION__, l_baseline_side == DEX_SIDE_ASK ? "ASK" : "BID", l_sell_ticker, l_sell_net_id.uint64, l_buy_ticker,
                         l_buy_net_id.uint64, dap_uint256_to_char_ex(l_prev->subtype.srv_dex.rate).frac, l_check_key.token_base,
                         l_check_key.token_quote, l_pair_idx ? " " : "not ");
                if (!l_pair_idx)
                    RET_ERR(DEXV_PAIR_NOT_ALLOWED);
            } else {
                // Validate baseline consistency (token/net match)
                dap_do_if_any(RET_ERR(DEXV_BASELINE_TUPLE), strcmp(l_buy_ticker, l_prev->subtype.srv_dex.buy_token),
                              strcmp(l_sell_ticker, l_sell_cur), l_sell_net_id.uint64 != l_prev->subtype.srv_dex.sell_net_id.uint64,
                              l_buy_net_id.uint64 != l_prev->subtype.srv_dex.buy_net_id.uint64);
                // Verify side consistency (all IN_COND must have same side)
                dex_pair_key_t l_cur_key = {};
                uint8_t l_cur_side = 0;
                s_dex_pair_normalize(l_sell_cur, l_prev->subtype.srv_dex.sell_net_id, l_prev->subtype.srv_dex.buy_token,
                                     l_prev->subtype.srv_dex.buy_net_id, l_prev->subtype.srv_dex.rate, &l_cur_key, &l_cur_side, NULL);
                if (l_cur_side != l_baseline_side)
                    RET_ERR(DEXV_BASELINE_TUPLE);
            }

            // Deduplicate sellers
            int l_seller_idx = -1;
            for (int j = 0; j < l_uniq_sllrs_cnt; ++j) {
                if (dap_chain_addr_compare(&l_sellers[j].addr, &l_prev->subtype.srv_dex.seller_addr)) {
                    l_seller_idx = j;
                    break;
                }
            }
            if (l_seller_idx < 0) {
                l_seller_idx = l_uniq_sllrs_cnt++;
                l_sellers[l_seller_idx].addr = l_prev->subtype.srv_dex.seller_addr;
            }

            // Compute executed amount (handle seller-leftover for first IN)
            uint256_t l_executed_i = l_prev->header.value;
            // Seller-leftover detection: first IN_COND + OUT_COND + seller matches + non-blank root
            // Note: partial fill check moved to Phase 3.1 after canonicalization (sum of all INs needed)
            bool l_in_is_leftover =
                (l_in_cond_idx == 0 && l_out_cond && !dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash) &&
                 dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_prev->subtype.srv_dex.seller_addr));
            debug_if(s_debug_more, L_DEBUG, "{ %s, phase 2 } IN_COND #%d; %sValue prev: %s, new: %s", __FUNCTION__, l_in_cond_idx,
                     l_in_is_leftover ? "Seller leftover detected; " : "", dap_uint256_to_char_ex(l_prev->header.value).frac,
                     l_out_cond ? dap_uint256_to_char_ex(l_out_cond->header.value).frac : "undefined");
            if (l_in_is_leftover) {
                // Seller-leftover: partial fill (EXCHANGE) or self-update (UPDATE)
                // For EXCHANGE: new_value MUST be < prev_value (partial fill)
                // For UPDATE: new_value can be >, <, or == prev_value (increase/decrease/rate-only change)

                // Validate tx_type consistency with owner signature (defense against tx_type forgery)
                // UPDATE MUST have owner signature (checked again on line 2648, but we need it here for residual logic)
                if (l_out_cond->subtype.srv_dex.tx_type == DEX_TX_TYPE_UPDATE && !a_owner)
                    RET_ERR(DEXV_UPDATE_NOT_OWNER);

                // Determine actual type: UPDATE requires both owner signature AND declared tx_type
                l_is_update = (a_owner && l_out_cond->subtype.srv_dex.tx_type == DEX_TX_TYPE_UPDATE);
                int l_cmp = compare256(l_prev->header.value, l_out_cond->header.value);

                if (!l_is_update && l_cmp <= 0)
                    // EXCHANGE: residual must be less than previous (partial fill)
                    RET_ERR(DEXV_INVALID_RESIDUAL);

                // For UPDATE: compute delta (can be positive, negative, or zero)
                // For EXCHANGE: compute executed amount (always positive)
                if (l_cmp > 0)
                    SUBTRACT_256_256(l_prev->header.value, l_out_cond->header.value, &l_executed_i);
                else if (l_cmp < 0)
                    // UPDATE with increase: l_executed_i = 0 (no sell, only additional lock)
                    l_executed_i = uint256_0;
                else
                    // UPDATE with same value (rate-only change): l_executed_i = 0
                    l_executed_i = uint256_0;

                // Validate immutables (must not change for seller-leftover: EXCHANGE or UPDATE)
                dap_hash_fast_t l_root_hash =
                    dap_ledger_get_first_chain_tx_hash(a_ledger, l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                if (dap_hash_fast_is_blank(&l_root_hash))
                    l_root_hash = l_in->header.tx_prev_hash; // ORDER: root=tail

                debug_if(s_debug_more, L_DEBUG,
                         "{ %s, phase 2 } Check seller-leftover immutables; Root %s; Seller OUT: %s / PREV: %s; "
                         "Buy token OUT: %s / PREV: %s; Rate OUT: %s / PREV: %s; "
                         "Min fill OUT: %u / PREV: %u; Flags OUT: 0x%08X / PREV: 0x%08X",
                         __FUNCTION__, dap_chain_hash_fast_to_str_static(&l_root_hash),
                         dap_chain_addr_to_str_static(&l_out_cond->subtype.srv_dex.seller_addr),
                         dap_chain_addr_to_str_static(&l_prev->subtype.srv_dex.seller_addr), l_out_cond->subtype.srv_dex.buy_token,
                         l_prev->subtype.srv_dex.buy_token, dap_uint256_to_char_ex(l_out_cond->subtype.srv_dex.rate).frac,
                         dap_uint256_to_char_ex(l_prev->subtype.srv_dex.rate).frac, l_out_cond->subtype.srv_dex.min_fill,
                         l_prev->subtype.srv_dex.min_fill, l_out_cond->subtype.srv_dex.flags, l_prev->subtype.srv_dex.flags);

                dap_do_if_any(RET_ERR(DEXV_IMMUTABLES_VIOLATION),
                              !dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_prev->subtype.srv_dex.seller_addr),
                              l_out_cond->subtype.srv_dex.buy_net_id.uint64 != l_prev->subtype.srv_dex.buy_net_id.uint64,
                              l_out_cond->subtype.srv_dex.sell_net_id.uint64 != l_prev->subtype.srv_dex.sell_net_id.uint64,
                              strcmp(l_out_cond->subtype.srv_dex.buy_token, l_prev->subtype.srv_dex.buy_token),
                              compare256(l_out_cond->subtype.srv_dex.rate, l_prev->subtype.srv_dex.rate) != 0,
                              l_out_cond->subtype.srv_dex.version != l_prev->subtype.srv_dex.version,
                              l_out_cond->subtype.srv_dex.min_fill != l_prev->subtype.srv_dex.min_fill,
                              l_out_cond->subtype.srv_dex.flags != l_prev->subtype.srv_dex.flags);

                // Root validation: OUT_COND.root must equal first-chain root (or prev hash if root is blank)
                if (!dap_hash_fast_compare(&l_out_cond->subtype.srv_dex.order_root_hash, &l_root_hash))
                    dap_do_if_any(RET_ERR(DEXV_ROOT_CHAIN_MISMATCH), !dap_hash_fast_is_blank(&l_root_hash),
                                  !dap_hash_fast_compare(&l_out_cond->subtype.srv_dex.order_root_hash, &l_in->header.tx_prev_hash));

                // Min_fill validation
                uint8_t l_min_raw = l_prev->subtype.srv_dex.min_fill, l_pct = l_min_raw & 0x7F;
                bool l_from_origin = (l_min_raw & 0x80) != 0;
                if (l_pct == 100) {
                    // AON semantics:
                    // - For EXCHANGE: any seller-leftover is forbidden (AON cannot produce leftover)
                    // - For UPDATE (owner-only): allowed, min_fill checked later only at trade time
                    if (!l_is_update)
                        RET_ERR(DEXV_MIN_FILL_AON);
                } else if (l_pct > 0) {
                    uint256_t l_val_base;
                    if (l_from_origin) {
                        // Base = original order value (root)
                        dap_chain_datum_tx_t *l_root_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_root_hash);
                        if (!l_root_tx)
                            RET_ERR(DEXV_MIN_FILL_NOT_REACHED);
                        dap_chain_tx_out_cond_t *l_root_out =
                            dap_chain_datum_tx_out_cond_get(l_root_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
                        if (!l_root_out)
                            RET_ERR(DEXV_MIN_FILL_NOT_REACHED);
                        l_val_base = l_root_out->header.value;
                    } else
                        // Base = current remain
                        l_val_base = l_prev->header.value;
                    // executed_i must be >= pct% of base
                    // EXCEPTIONS: 1) Full close (no OUT_COND) handled outside this block
                    //             2) UPDATE (owner liquidity management) — min_fill not enforced here
                    uint256_t l_min_exec = s_calc_pct(l_val_base, l_pct);

                    if (!l_is_update && compare256(l_executed_i, l_min_exec) < 0 && !IS_ZERO_256(l_executed_i))
                        RET_ERR(DEXV_MIN_FILL_NOT_REACHED);
                }

                // tx_type validation for seller-leftover
                if (l_out_cond->subtype.srv_dex.tx_type == DEX_TX_TYPE_UPDATE) {
                    // UPDATE: seller self-modification, requires owner signature
                    if (!a_owner)
                        RET_ERR(DEXV_UPDATE_NOT_OWNER);
                } else if (l_out_cond->subtype.srv_dex.tx_type != DEX_TX_TYPE_EXCHANGE)
                    // EXCHANGE: buyer-caused partial fill, no owner check
                    RET_ERR(DEXV_TX_TYPE_MISMATCH);

            } else if (l_is_leftover && l_in_cond_idx > 0) {
                // Composer places partially-filled order as first IN_COND
                // Verify OUT_COND.root matches first IN_COND's order
                // (other IN_CONDs can exist for different orders, e.g. multiple matched orders)
                dap_chain_datum_tx_t *l_first_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_first_in_prev_hash);
                if (!l_first_prev_tx)
                    RET_ERR(DEXV_PREV_TX_NOT_FOUND);
                dap_hash_fast_t l_first_root =
                    dap_ledger_get_first_chain_tx_hash(a_ledger, l_first_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                if (dap_hash_fast_is_blank(&l_first_root))
                    l_first_root = l_first_in_prev_hash; // ORDER: root=tail
                if (!dap_hash_fast_compare(&l_out_cond->subtype.srv_dex.order_root_hash, &l_first_root))
                    RET_ERR(DEXV_ROOT_CHAIN_MISMATCH);
            }

            // Compute expected_buy for this IN (skip UPDATE only)
            // Note: INVALIDATE is detected in Phase 3; expected_buy computed here, service fee waived later
            // Note: For EXCHANGE, this is preliminary calculation for service fee computation;
            // Phase 3.1 will recompute canonical expected_buy and verify consistency
            if (!(l_in_is_leftover && l_is_update)) {
                uint256_t l_buy_i = uint256_0;
                // Use baseline_side (already determined and verified for all IN_COND)
                // l_executed_i is in ORDER context: BASE for ASK, QUOTE for BID
                if (l_baseline_side == DEX_SIDE_BID) {
                    // BID: rate is canonical (QUOTE/BASE), expected_buy (BASE) = executed (QUOTE) / rate
                    // Composer now uses canonical exec_sell = exec_quote / rate (same calculation)
                    uint256_t l_canonical_rate = l_prev->subtype.srv_dex.rate;
                    DIV_256_COIN(l_executed_i, l_canonical_rate, &l_buy_i);
                } else {
                    // ASK: l_executed_i is BASE, rate stored as QUOTE/BASE (canonical)
                    // expected_buy_QUOTE = l_executed_i_BASE * rate
                    MULT_256_COIN(l_executed_i, l_prev->subtype.srv_dex.rate, &l_buy_i);
                }
                SUM_256_256(l_sellers[l_seller_idx].expected_buy, l_buy_i, &l_sellers[l_seller_idx].expected_buy);
                SUM_256_256(l_executed_total, l_executed_i, &l_executed_total);
                debug_if(s_debug_more, L_DEBUG,
                         "{ %s, phase 2 } Expected buy for %s at IN_COND #%d: %s; "
                         "Executed: %s at rate: %s",
                         __FUNCTION__, (l_baseline_side == DEX_SIDE_BID) ? "BID" : "ASK", l_in_cond_idx,
                         dap_uint256_to_char_ex(l_buy_i).frac, dap_uint256_to_char_ex(l_executed_i).frac,
                         dap_uint256_to_char_ex(l_prev->subtype.srv_dex.rate).frac);
            }
            ++l_in_cond_idx;
        } break;

        case TX_ITEM_TYPE_IN: {
            dap_chain_tx_in_t *l_in = (dap_chain_tx_in_t *)it;
            // Resolve IN data for fee verification and cashback calculation
            if (l_ins && l_in_idx < l_in_cnt) {
                dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_in->header.tx_prev_hash);
                if (l_prev_tx) {
                    byte_t *l_prev_out = dap_chain_datum_tx_out_get_by_out_idx(l_prev_tx, l_in->header.tx_out_prev_idx);
                    if (l_prev_out) {
                        switch (*l_prev_out) {
                        case TX_ITEM_TYPE_OUT_OLD:
                        case TX_ITEM_TYPE_OUT: {
                            dap_chain_tx_out_old_t *o = (dap_chain_tx_out_old_t *)l_prev_out;
                            l_ins[l_in_idx].addr = o->addr;
                            l_ins[l_in_idx].token = NULL; // Legacy OUT, no token field
                            l_ins[l_in_idx].value = GET_256_FROM_64(o->header.value);
                        } break;
                        case TX_ITEM_TYPE_OUT_STD: {
                            dap_chain_tx_out_std_t *o = (dap_chain_tx_out_std_t *)l_prev_out;
                            l_ins[l_in_idx].addr = o->addr;
                            l_ins[l_in_idx].token = o->token;
                            l_ins[l_in_idx].value = o->value;
                        } break;
                        case TX_ITEM_TYPE_OUT_EXT: {
                            dap_chain_tx_out_ext_t *o = (dap_chain_tx_out_ext_t *)l_prev_out;
                            l_ins[l_in_idx].addr = o->addr;
                            l_ins[l_in_idx].token = o->token;
                            l_ins[l_in_idx].value = o->header.value;
                        } break;
                        default:
                            break;
                        }
                    }
                }
                // ORDER path: extract sell_ticker from first IN and check whitelist (reuse l_ins data)
                if (l_in_cond_cnt == 0 && !l_sell_ticker && l_out_cond) {
                    l_sell_ticker = l_ins[l_in_idx].token;
                    // Legacy OUT types have NULL token, fall back to TX main ticker
                    if (!l_sell_ticker)
                        l_sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_in->header.tx_prev_hash);
                    if (!l_sell_ticker || !*l_sell_ticker)
                        RET_ERR(DEXV_BASELINE_BUY_TOKEN);
                    // Set baseline (ORDER uses OUT_COND for buy_token, sell_net_id, buy_net_id)
                    l_buy_ticker = l_out_cond->subtype.srv_dex.buy_token;
                    l_sell_net_id = l_out_cond->subtype.srv_dex.sell_net_id;
                    l_buy_net_id = l_out_cond->subtype.srv_dex.buy_net_id;

                    // Whitelist check: pair must be whitelisted via decree
                    dex_pair_key_t l_order_pair = {};
                    s_dex_pair_normalize(l_sell_ticker, l_sell_net_id, l_buy_ticker, l_buy_net_id, l_out_cond->subtype.srv_dex.rate,
                                         &l_order_pair, NULL, NULL);
                    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
                    l_pair_idx = s_dex_pair_index_get(&l_order_pair);
                    if (l_pair_idx) {
                        l_fee_cfg = l_pair_idx->key.fee_config;
                        l_native_fee_cached = s_dex_native_fee_amount;
                    }
                    pthread_rwlock_unlock(&s_dex_cache_rwlock);

                    if (!l_pair_idx) {
                        debug_if(s_debug_more, L_ERROR,
                                 "%s(): Pair %s (net %" DAP_UINT64_FORMAT_U ") / %s (net %" DAP_UINT64_FORMAT_U ") not whitelisted",
                                 __FUNCTION__, l_order_pair.token_base, l_order_pair.net_id_base.uint64, l_order_pair.token_quote,
                                 l_order_pair.net_id_quote.uint64);
                        RET_ERR(DEXV_PAIR_NOT_ALLOWED);
                    }
                    log_it(L_DEBUG, "%s(): ORDER whitelist validated: %s/%s", __FUNCTION__, l_sell_ticker, l_buy_ticker);
                }
                l_in_idx++;
            }
        } break;

        case TX_ITEM_TYPE_OUT_EXT:
        case TX_ITEM_TYPE_OUT_STD:
        case TX_ITEM_TYPE_OUT: {
            // Extract common fields based on OUT type
            const dap_chain_addr_t *l_addr;
            const char *l_token;
            uint256_t l_value;

            if (*it == TX_ITEM_TYPE_OUT_EXT) {
                dap_chain_tx_out_ext_t *o = (dap_chain_tx_out_ext_t *)it;
                l_addr = &o->addr;
                l_token = o->token;
                l_value = o->header.value;
            } else if (*it == TX_ITEM_TYPE_OUT_STD) {
                dap_chain_tx_out_std_t *o = (dap_chain_tx_out_std_t *)it;
                l_addr = &o->addr;
                l_token = o->token;
                l_value = o->value;
            } else {
                dap_chain_tx_out_t *o = (dap_chain_tx_out_t *)it;
                l_addr = &o->addr;
                l_token = l_native_ticker;
                l_value = o->header.value;
            }

            // Classify OUT: find seller match once
            int l_seller_idx = -1;
            for (int j = 0; j < l_uniq_sllrs_cnt; ++j) {
                if (dap_chain_addr_compare(l_addr, &l_sellers[j].addr)) {
                    l_seller_idx = j;
                    break;
                }
            }

            l_outs[l_out_idx++] = (dex_out_t){l_addr, l_token, l_value, l_seller_idx, *it};
        };

        default:
            break;
        }
    }

    if (!l_pair_idx)
        RET_ERR(DEXV_PAIR_NOT_ALLOWED); // Should never happen (defensive check)

    // Configure network fee early (needed for dynamic dust threshold)
    dap_chain_addr_t l_net_addr = {};
    uint256_t l_net_fee_req = uint256_0;
    bool l_net_used = dap_chain_net_tx_get_fee(a_ledger->net->pub.id, &l_net_fee_req, &l_net_addr);

    // Configure service fee early (needed for dust-refund detection and Phase 3)
    dap_chain_addr_t l_srv_addr = {};
    uint256_t l_srv_fee_req = uint256_0;
    const char *l_srv_ticker = NULL;
    bool l_srv_used = false, l_srv_addr_blank = false;

    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    l_srv_addr = s_dex_service_fee_addr;
    l_srv_addr_blank = dap_chain_addr_is_blank(&s_dex_service_fee_addr);
    if ((l_fee_cfg & 0x80) == 0) { // Native mode: compute fixed fee now
        uint8_t l_mult = l_fee_cfg & 0x7F;
        l_srv_fee_req = l_mult > 0 ? GET_256_FROM_64((uint64_t)l_mult * DAP_DEX_FEE_UNIT_NATIVE) : l_native_fee_cached;
        l_srv_ticker = l_native_ticker;
        l_srv_used = !IS_ZERO_256(l_srv_fee_req);
    }
    pthread_rwlock_unlock(&s_dex_cache_rwlock);

    uint256_t l_dust_refund = uint256_0;
    // Dust-refund (full close without SRV_DEX OUT_COND): refund in sell_token to the boundary seller (IN_COND #0)
    // Must be applied before fee computation because % fee depends on input volume.
    if (!l_out_cond && !a_owner && l_in_cond_cnt > 0 && l_sell_ticker) {
        int l_seller0_idx = -1;
        for (int j = 0; j < l_uniq_sllrs_cnt && l_seller0_idx < 0; ++j)
            if (dap_chain_addr_compare(&l_sellers[j].addr, &l_prev_outs[0]->subtype.srv_dex.seller_addr))
                l_seller0_idx = j;
        if (l_seller0_idx < 0)
            RET_ERR(DEXV_INVALID_PARAMS);

        // Service fee split (native mode only): if seller0 is the service beneficiary and sell==native,
        // subtract the native service fee output from seller's sell_token total to isolate dust.
        bool l_check_fee = l_srv_used && l_srv_ticker && !strcmp(l_srv_ticker, l_native_ticker) &&
                           dap_chain_addr_compare(&l_sellers[l_seller0_idx].addr, &l_srv_addr);

        // Single pass: aggregate dust + detect fee OUT
        uint256_t l_seller_sell_total = uint256_0, l_dust_other = uint256_0;
        bool l_fee_out_found = false, l_net_fee_out_skipped = false;
        for (int i = 0; i < l_out_cnt; ++i) {
            dex_out_t *o = &l_outs[i];
            if ((o->out_type != TX_ITEM_TYPE_OUT_STD && o->out_type != TX_ITEM_TYPE_OUT_EXT) || !o->token ||
                strcmp(o->token, l_sell_ticker))
                continue;
            // Skip net_fee OUT: not a dust refund (prevents false positive when seller == net_fee_collector)
            if (l_net_used && !strcmp(o->token, l_native_ticker) && dap_chain_addr_compare(o->addr, &l_net_addr) &&
                compare256(o->value, l_net_fee_req) == 0) {
                if (!l_net_fee_out_skipped) {
                    l_net_fee_out_skipped = true;
                    continue;
                } else
                    RET_ERR(DEXV_INVALID_RESIDUAL);
            }
            if (o->seller_idx == l_seller0_idx)
                SUM_256_256(l_seller_sell_total, o->value, &l_seller_sell_total);
            else if (o->seller_idx >= 0)
                SUM_256_256(l_dust_other, o->value, &l_dust_other);
            if (l_check_fee && !l_fee_out_found && dap_chain_addr_compare(o->addr, &l_srv_addr) && compare256(o->value, l_srv_fee_req) == 0)
                l_fee_out_found = true;
        }
        if (!IS_ZERO_256(l_dust_other))
            RET_ERR(DEXV_INVALID_RESIDUAL);

        // Subtract service fee if detected
        if (l_fee_out_found && compare256(l_seller_sell_total, l_srv_fee_req) >= 0)
            SUBTRACT_256_256(l_seller_sell_total, l_srv_fee_req, &l_seller_sell_total);

        // Dynamic dust threshold (0 = disabled)
        uint256_t l_fixed_native = l_fee_native;
        if (l_net_used && !IS_ZERO_256(l_net_fee_req))
            SUM_256_256(l_fixed_native, l_net_fee_req, &l_fixed_native);
        bool l_is_buyer_service = false;
        for (int i = 0; i < l_out_cnt && !l_is_buyer_service; ++i) {
            dex_out_t *o = &l_outs[i];
            if ((o->out_type != TX_ITEM_TYPE_OUT_STD && o->out_type != TX_ITEM_TYPE_OUT_EXT) || !o->token ||
                strcmp(o->token, l_sell_ticker) || o->seller_idx >= 0)
                continue;
            if (l_net_used && !strcmp(l_sell_ticker, l_native_ticker) && dap_chain_addr_compare(o->addr, &l_net_addr) &&
                compare256(o->value, l_net_fee_req) == 0)
                continue;
            if (!IS_ZERO_256(l_srv_fee_req) && dap_chain_addr_compare(o->addr, &l_srv_addr) && compare256(o->value, l_srv_fee_req) == 0)
                continue;
            l_is_buyer_service = dap_chain_addr_compare(o->addr, &l_srv_addr);
        }
        uint8_t l_fee_cfg_eff = l_is_buyer_service ? (l_fee_cfg & 0x80) : l_fee_cfg;
        if (!l_is_buyer_service && (l_fee_cfg_eff & 0x80) == 0) {
            uint8_t l_mult = l_fee_cfg & 0x7F;
            uint256_t l_srv_abs = l_mult > 0 ? GET_256_FROM_64((uint64_t)l_mult * DAP_DEX_FEE_UNIT_NATIVE) : l_native_fee_cached;
            if (!IS_ZERO_256(l_srv_abs))
                SUM_256_256(l_fixed_native, l_srv_abs, &l_fixed_native);
        }
        bool l_is_bid = (l_baseline_side == DEX_SIDE_BID);
        uint256_t l_dust_thr = s_dex_calc_dust_threshold(l_sell_ticker, l_buy_ticker, l_native_ticker, l_fee_cfg_eff,
                                                         l_prev_outs[0]->subtype.srv_dex.rate, l_is_bid, l_fixed_native);

        if (!IS_ZERO_256(l_seller_sell_total)) {
            l_dust_refund = l_seller_sell_total;
            if (IS_ZERO_256(l_dust_thr) || compare256(l_dust_refund, l_dust_thr) > 0 ||
                compare256(l_prev_outs[0]->header.value, l_dust_refund) <= 0)
                RET_ERR(DEXV_INVALID_RESIDUAL);

            uint256_t l_exec0 = uint256_0;
            SUBTRACT_256_256(l_prev_outs[0]->header.value, l_dust_refund, &l_exec0);

            // Inline min_fill check (avoid redundant ledger lookups)
            uint8_t l_min_raw = l_prev_outs[0]->subtype.srv_dex.min_fill, l_pct = l_min_raw & 0x7F;
            if (l_pct >= 100)
                RET_ERR(DEXV_MIN_FILL_AON);
            if (l_pct > 0) {
                uint256_t l_min_base = l_prev_outs[0]->header.value;
                if ((l_min_raw & 0x80) != 0) { // from_origin: use root order value
                    dap_hash_fast_t l_root_hash = l_prev_outs[0]->subtype.srv_dex.order_root_hash;
                    if (!dap_hash_fast_is_blank(&l_root_hash)) {
                        dap_chain_datum_tx_t *l_root_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_root_hash);
                        dap_chain_tx_out_cond_t *l_root_out =
                            l_root_tx ? dap_chain_datum_tx_out_cond_get(l_root_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL) : NULL;
                        if (l_root_out)
                            l_min_base = l_root_out->header.value;
                        else
                            RET_ERR(DEXV_MIN_FILL_NOT_REACHED); // from_origin requires valid root
                    }
                }
                if (compare256(l_exec0, s_calc_pct(l_min_base, l_pct)) < 0)
                    RET_ERR(DEXV_MIN_FILL_NOT_REACHED);
            }

            SUBTRACT_256_256(l_executed_total, l_dust_refund, &l_executed_total);

            // Adjust expected_buy for the first seller (refunded part)
            uint256_t l_buy_full = uint256_0, l_buy_part = uint256_0;
            if (l_baseline_side == DEX_SIDE_BID) {
                DIV_256_COIN(l_prev_outs[0]->header.value, l_prev_outs[0]->subtype.srv_dex.rate, &l_buy_full);
                DIV_256_COIN(l_exec0, l_prev_outs[0]->subtype.srv_dex.rate, &l_buy_part);
            } else {
                MULT_256_COIN(l_prev_outs[0]->header.value, l_prev_outs[0]->subtype.srv_dex.rate, &l_buy_full);
                MULT_256_COIN(l_exec0, l_prev_outs[0]->subtype.srv_dex.rate, &l_buy_part);
            }
            if (compare256(l_buy_full, l_buy_part) > 0) {
                uint256_t l_delta_buy = uint256_0;
                SUBTRACT_256_256(l_buy_full, l_buy_part, &l_delta_buy);
                if (compare256(l_sellers[l_seller0_idx].expected_buy, l_delta_buy) >= 0)
                    SUBTRACT_256_256(l_sellers[l_seller0_idx].expected_buy, l_delta_buy, &l_sellers[l_seller0_idx].expected_buy);
                else
                    l_sellers[l_seller0_idx].expected_buy = uint256_0;
            }
            debug_if(s_debug_more, L_DEBUG, "%s(): Dust refund detected; Seller: %s; Refund: %s %s; Threshold: %s; Executed total: %s",
                     __FUNCTION__, dap_chain_addr_to_str_static(&l_prev_outs[0]->subtype.srv_dex.seller_addr),
                     dap_uint256_to_char_ex(l_dust_refund).frac, l_sell_ticker, dap_uint256_to_char_ex(l_dust_thr).frac,
                     dap_uint256_to_char_ex(l_executed_total).frac);
        }
    }

    // Save sum of expected_buy BEFORE fee aggregation (needed for Phase 3 BID canonical check)
    uint256_t l_expected_buy_total_no_fee = uint256_0;
    for (int j = 0; j < l_uniq_sllrs_cnt; ++j)
        SUM_256_256(l_expected_buy_total_no_fee, l_sellers[j].expected_buy, &l_expected_buy_total_no_fee);

    // Compute percent fee after dust-refund (depends on corrected expected_buy)
    if ((l_fee_cfg & 0x80) != 0) {
        bool l_is_bid = (l_sell_ticker && !strcmp(l_sell_ticker, l_pair_idx->key.token_quote));
        uint8_t l_pct = l_fee_cfg & 0x7F;
        if (l_pct > 127)
            RET_ERR(DEXV_INVALID_FEE_CONFIG);
        l_srv_ticker = l_is_bid ? l_pair_idx->key.token_base : l_pair_idx->key.token_quote;
        if (l_pct > 0) {
            uint256_t l_input_amount = uint256_0;
            for (int j = 0; j < l_uniq_sllrs_cnt; ++j)
                SUM_256_256(l_input_amount, l_sellers[j].expected_buy, &l_input_amount);
            uint256_t l_pct_256 = GET_256_FROM_64(l_pct);
            MULT_256_256(l_pct_256, l_input_amount, &l_srv_fee_req);
            DIV_256(l_srv_fee_req, GET_256_FROM_64(1000), &l_srv_fee_req); // 0.1% step
            l_srv_used = true;
        }
    }

    // Reject TX if service fee is required but address is blank (would burn tokens!)
    if (l_srv_used && l_srv_addr_blank)
        RET_ERR(DEXV_SERVICE_FEE_ADDR_BLANK);

    // Phase 3: Aggregate OUTs
    uint256_t l_paid_sell_total = uint256_0;
    const dap_chain_addr_t *l_buyer_addr = NULL;
    bool l_buyer_addr_uniq = true;
    uint256_t l_paid_net_fee = uint256_0, l_paid_srv_fee = uint256_0;
    uint256_t l_buyer_received = uint256_0, l_buy_others = uint256_0, l_sell_others = uint256_0, l_buyer_buy_cashback = uint256_0;

    for (int i = 0; i < l_out_cnt; ++i) {
        dex_out_t *o = &l_outs[i];

        // Check if this is a fee address
        bool is_net_fee = l_net_used && !strcmp(o->token, l_native_ticker) && dap_chain_addr_compare(o->addr, &l_net_addr);
        bool is_srv_fee = l_srv_used && l_srv_ticker && !strcmp(o->token, l_srv_ticker) && dap_chain_addr_compare(o->addr, &l_srv_addr);

        // Net fee: use exact match to distinguish from seller payout when seller == net_collector
        // Pick ONLY ONE net_fee OUT per TX (first one matching value == net_fee_req)
        if (is_net_fee && IS_ZERO_256(l_paid_net_fee) && compare256(o->value, l_net_fee_req) == 0) {
            SUM_256_256(l_paid_net_fee, o->value, &l_paid_net_fee);
            // Skip further processing if not also service fee
            if (!is_srv_fee)
                continue;
        }

        // ORDER (l_in_cond_cnt==0): skip seller/buyer logic and service fee logic (no tickers, no sellers, no service fee)
        if (l_in_cond_cnt == 0)
            continue;

        if (is_srv_fee) {
            debug_if(s_debug_more, L_DEBUG, "%s(): Service fee candidate OUT #%d; Token: %s; Addr: %s; Value: %s; Fee required: %s",
                     __FUNCTION__, i, o->token, dap_chain_addr_to_str_static(o->addr), dap_uint256_to_char_ex(o->value).frac,
                     dap_uint256_to_char_ex(l_srv_fee_req).frac);
            // Distinguish service fee OUT from buyer payout by value (when service==buyer)
            // Service fee OUT: value == l_srv_fee_req (exact match), pick ONLY ONE such OUT per TX
            // Buyer payout OUT: value != l_srv_fee_req (will be aggregated in buyer_received)
            if (!IS_ZERO_256(l_srv_fee_req) && IS_ZERO_256(l_paid_srv_fee) && (compare256(o->value, l_srv_fee_req) == 0)) {
                // Exact match → this is service fee OUT
                SUM_256_256(l_paid_srv_fee, o->value, &l_paid_srv_fee);
                debug_if(s_debug_more, L_DEBUG, "%s(): Service fee OUT #%d accumulated: %s", __FUNCTION__, i,
                         dap_uint256_to_char_ex(l_paid_srv_fee).frac);
                continue; // Don't fall through to buyer detection
            }
            // else: value != l_srv_fee_req → might be buyer payout, fall through
            debug_if(s_debug_more, L_DEBUG, "%s(): Service fee OUT #%d value mismatch: actual %s != required %s", __FUNCTION__, i,
                     dap_uint256_to_char_ex(o->value).frac, dap_uint256_to_char_ex(l_srv_fee_req).frac);
        }

        if (o->seller_idx >= 0) {
            // Seller payout aggregation
            if (!strcmp(o->token, l_buy_ticker)) {
                SUM_256_256(l_sellers[o->seller_idx].paid_buy, o->value, &l_sellers[o->seller_idx].paid_buy);
                // Reset l_is_invalidate only for non-owner (EXCHANGE scenario).
                // For owner (UPDATE/INVALIDATE), buy_token output is cashback, not payout.
                if (!a_owner)
                    l_is_invalidate = false;
            } else if (!strcmp(o->token, l_sell_ticker)) {
                SUM_256_256(l_sellers[o->seller_idx].paid_sell, o->value, &l_sellers[o->seller_idx].paid_sell);
                SUM_256_256(l_paid_sell_total, o->value, &l_paid_sell_total);
            }
        }

        // Buyer detection (skip seller payouts — they can include dust-refund)
        if (!strcmp(o->token, l_sell_ticker) && o->seller_idx < 0) {
            // Buyer detection: first OUT in sell_token to non-seller addr
            if (!l_buyer_addr) {
                l_buyer_addr = o->addr;
                debug_if(s_debug_more, L_DEBUG, "%s(): Buyer candidate OUT #%d; Addr %s; Value in sell token: %s %s", __FUNCTION__, i,
                         dap_chain_addr_to_str_static(o->addr), dap_uint256_to_char_ex(o->value).frac, l_sell_ticker);
            } else if (!dap_chain_addr_compare(l_buyer_addr, o->addr)) {
                l_buyer_addr_uniq = false;
                debug_if(s_debug_more, L_DEBUG, "%s(): Another buyer destination OUT #%d; Addr: %s; Value in sell token: %s %s",
                         __FUNCTION__, i, dap_chain_addr_to_str_static(o->addr), dap_uint256_to_char_ex(o->value).frac, l_sell_ticker);
            }

            // Aggregate buyer received amount (for EXCHANGE validation)
            if (l_buyer_addr && dap_chain_addr_compare(o->addr, l_buyer_addr)) {
                SUM_256_256(l_buyer_received, o->value, &l_buyer_received);
                debug_if(s_debug_more, L_DEBUG, "%s(): Buyer received sell token at OUT #%d; Addr: %s; Value current / total: %s / %s %s",
                         __FUNCTION__, i, dap_chain_addr_to_str_static(o->addr), dap_uint256_to_char_ex(o->value).frac,
                         dap_uint256_to_char_ex(l_buyer_received).frac, l_sell_ticker);
            } else {
                // sell_token OUT to non-buyer → leak!
                log_it(L_WARNING, "%s(): Sell token leak at OUT #%d; Addr: %s; Value: %s %s", __FUNCTION__, i,
                       dap_chain_addr_to_str_static(o->addr), dap_uint256_to_char_ex(o->value).frac, l_sell_ticker);
                SUM_256_256(l_sell_others, o->value, &l_sell_others);
            }
        } else if (!strcmp(o->token, l_buy_ticker) && o->out_type != TX_ITEM_TYPE_OUT_COND) {
            // buy_token payout: seller payout, buyer cashback, or leak
            if (l_buyer_addr && dap_chain_addr_compare(l_buyer_addr, o->addr)) {
                // Buyer cashback in buy_token (budget refund)
                debug_if(s_debug_more, L_DEBUG, "%s(): Buyer cashback OUT #%d in buy token: %s %s", __FUNCTION__, i,
                         dap_uint256_to_char_ex(o->value).frac, l_buy_ticker);
                SUM_256_256(l_buyer_buy_cashback, o->value, &l_buyer_buy_cashback);
            } else if (o->seller_idx < 0) {
                // Leak detection: unexpected buy_token to non-buyer, non-seller
                log_it(L_WARNING, "%s(): Buy token leak at OUT #%d; Addr: %s; Value: %s %s", __FUNCTION__, i,
                       dap_chain_addr_to_str_static(o->addr), dap_uint256_to_char_ex(o->value).frac, l_buy_ticker);
                SUM_256_256(l_buy_others, o->value, &l_buy_others);
            }
        }
    }

    // Validate network fee (unified for all TX types: ORDER, INVALIDATE, EXCHANGE, UPDATE)
    if (l_net_used && !IS_ZERO_256(l_net_fee_req) && compare256(l_paid_net_fee, l_net_fee_req) < 0)
        RET_ERR(DEXV_NETWORK_FEE_UNDERPAID);

    // ORDER (l_in_cond_cnt == 0): network fee validated, exit early
    if (l_in_cond_cnt == 0)
        goto dex_verif_ret_err;

    // Waive service fee for UPDATE and INVALIDATE (not sales)
    // Note: l_is_invalidate is now reliable after Phase 3 (set to false if buy_token payouts found)
    if (l_is_update || l_is_invalidate) {
        l_srv_fee_req = uint256_0;
        l_srv_used = false;
    }

    // Waive/Aggregate service fee according to matrix:
    // - buyer == service: waive (l_srv_fee_req=0)
    // - seller == service AND fee_ticker==buy_token (ASK+QUOTE): aggregate (increase expected_buy, then set l_srv_fee_req=0)
    // - otherwise: require separate service fee OUT
    if (l_srv_used && !IS_ZERO_256(l_srv_fee_req)) {
        int l_srv_seller_idx = -1;
        for (int i = 0; i < l_uniq_sllrs_cnt && l_srv_seller_idx < 0; ++i)
            if (dap_chain_addr_compare(&l_sellers[i].addr, &l_srv_addr))
                l_srv_seller_idx = i;
        bool l_is_buyer_service = (l_buyer_addr && dap_chain_addr_compare(l_buyer_addr, &l_srv_addr));
        if (l_is_buyer_service) {
            debug_if(s_debug_more, L_DEBUG, "%s(): Service fee %s %s waived: buyer is service beneficiary", __FUNCTION__,
                     dap_uint256_to_char_ex(l_srv_fee_req).frac, l_srv_ticker ? l_srv_ticker : "");
            l_srv_fee_req = uint256_0;
            l_paid_srv_fee = uint256_0;
        } else if (l_srv_seller_idx >= 0 && l_srv_ticker && !strcmp(l_srv_ticker, l_buy_ticker)) {
            SUM_256_256(l_sellers[l_srv_seller_idx].expected_buy, l_srv_fee_req, &l_sellers[l_srv_seller_idx].expected_buy);
            debug_if(s_debug_more, L_DEBUG, "%s(): Service fee %s %s aggregated to seller %d payout", __FUNCTION__,
                     dap_uint256_to_char_ex(l_srv_fee_req).frac, l_srv_ticker ? l_srv_ticker : "", l_srv_seller_idx);
            l_srv_fee_req = uint256_0;
            l_paid_srv_fee = uint256_0;
        }
    }

    // Self-purchase not allowed: buyer cannot be any of the sellers
    // Exception: UPDATE and INVALIDATE have no buyer - l_buyer_addr points to owner's refund, not a trade
    if (l_buyer_addr && !l_is_update && !l_is_invalidate) {
        for (int i = 0; i < l_uniq_sllrs_cnt; ++i)
            if (dap_chain_addr_compare(l_buyer_addr, &l_sellers[i].addr))
                RET_ERR(DEXV_SELF_PURCHASE);
    }

    // Validate service fee (INVALIDATE, EXCHANGE, UPDATE only — after waive logic)
    if (l_srv_used && compare256(l_paid_srv_fee, l_srv_fee_req) < 0)
        RET_ERR(DEXV_SERVICE_FEE_UNDERPAID);

    // Compute buyer's sell_token cashback (needed for canonical validation when sell_token == native)
    // Also verify fee contribution if buyer != fee_collector
    uint256_t l_buyer_sell_cashback = uint256_0;
    bool l_buyer_is_fee_collector = l_buyer_addr && dap_chain_addr_compare(l_buyer_addr, &l_net_addr);
    if (l_buyer_addr && l_ins && l_sell_ticker && !strcmp(l_sell_ticker, l_native_ticker)) {
        // Sum buyer's inputs in native token using pre-resolved IN data
        uint256_t l_buyer_native_inputs = uint256_0;
        for (int i = 0; i < l_in_cnt; ++i) {
            bool l_is_native = l_ins[i].token ? !strcmp(l_ins[i].token, l_native_ticker) : true;
            if (l_is_native && dap_chain_addr_compare(&l_ins[i].addr, l_buyer_addr))
                SUM_256_256(l_buyer_native_inputs, l_ins[i].value, &l_buyer_native_inputs);
        }

        // Total fee = net_fee + validator_fee (buyer pays both even if fee_collector)
        uint256_t l_total_fee = uint256_0;
        SUM_256_256(l_net_fee_req, l_fee_native, &l_total_fee);
        // Add service fee to native total if fee token == native token
        if (l_srv_used && l_srv_ticker && !strcmp(l_srv_ticker, l_native_ticker))
            SUM_256_256(l_total_fee, l_srv_fee_req, &l_total_fee);

        // Verify buyer contributed enough for fees (skip if buyer is fee collector)
        if (!l_buyer_is_fee_collector && l_net_used && !IS_ZERO_256(l_paid_net_fee)) {
            if (compare256(l_buyer_native_inputs, l_total_fee) < 0) {
                log_it(L_WARNING, "%s(): Buyer native inputs %s < required fee %s", __FUNCTION__,
                       dap_uint256_to_char_ex(l_buyer_native_inputs).frac, dap_uint256_to_char_ex(l_total_fee).frac);
                RET_ERR(DEXV_FEE_NOT_FROM_BUYER);
            }
        }

        // Compute cashback = inputs - fees (always needed for canonical validation)
        if (compare256(l_buyer_native_inputs, l_total_fee) > 0) {
            SUBTRACT_256_256(l_buyer_native_inputs, l_total_fee, &l_buyer_sell_cashback);
            debug_if(s_debug_more, L_DEBUG, "%s(): Buyer sell_token cashback: inputs=%s, fee=%s, cashback=%s", __FUNCTION__,
                     dap_uint256_to_char_ex(l_buyer_native_inputs).frac, dap_uint256_to_char_ex(l_total_fee).frac,
                     dap_uint256_to_char_ex(l_buyer_sell_cashback).frac);
        }
    }

    // Phase 3.1: Canonical validation for ALL EXCHANGE (defense-in-depth against fake l_executed_i)
    // Preconditions:
    //  - SRV_DEX OUT exists and is EXCHANGE (or no OUT_COND for full match)
    //  - Not INVALIDATE (waived in Phase 3)
    //  - Not UPDATE (expected_buy already computed in Phase 2)
    //
    // Purpose: Recompute expected_buy from REAL OUTs (Phase 3) instead of TX data (Phase 2)
    if (l_out_cond && l_out_cond->subtype.srv_dex.tx_type == DEX_TX_TYPE_EXCHANGE && !l_is_invalidate && !l_is_update) {
        // Compute B_total (executed BASE):
        //  - ASK: buyer receives BASE in sell_token, minus cashback if sell_token == native
        //  - BID: sum of expected_buy from Phase 2 (already in BASE)
        uint256_t l_total_base = uint256_0;
        if (l_baseline_side == DEX_SIDE_ASK) {
            // Subtract buyer's sell_token cashback (only relevant when sell_token == native)
            if (!IS_ZERO_256(l_buyer_sell_cashback) && compare256(l_buyer_received, l_buyer_sell_cashback) > 0)
                SUBTRACT_256_256(l_buyer_received, l_buyer_sell_cashback, &l_total_base);
            else
                l_total_base = l_buyer_received;
        } else {
            // For BID: use expected_buy sum saved BEFORE fee aggregation
            l_total_base = l_expected_buy_total_no_fee;
        }
        // If nothing was traded in BASE, skip canonical check
        if (!IS_ZERO_256(l_total_base) && l_in_cond_idx > 0) {
            // Build canonical entries for each IN
            l_canon_ins = DAP_NEW_Z_COUNT(dex_canon_in_t, l_in_cond_idx);
            for (int i = 0; i < l_in_cond_idx; ++i) {
                dap_chain_tx_out_cond_t *l_prev = l_prev_outs[i];
                l_canon_ins[i].idx = i;
                l_canon_ins[i].seller = l_prev->subtype.srv_dex.seller_addr;
                // Rate is ALWAYS stored in canonical form (QUOTE/BASE) for both ASK and BID
                l_canon_ins[i].price_normal = l_prev->subtype.srv_dex.rate;
                if (l_baseline_side == DEX_SIDE_BID) {
                    // BID: value is in QUOTE, convert to BASE
                    DIV_256_COIN(l_prev->header.value, l_canon_ins[i].price_normal, &l_canon_ins[i].base_full);
                } else {
                    // ASK: value is already in BASE
                    l_canon_ins[i].base_full = l_prev->header.value;
                }
            }
            // Sort by best price first to reconstruct matcher order:
            //  - ASK: ascending (lower QUOTE/BASE is better)
            //  - BID: descending (higher QUOTE/BASE is better)
            // Note: Composer adds partial match FIRST (IN_COND #0), but matcher processes it LAST (boundary).
            // We need to restore matcher order: sort by price, then move partial match (idx=0) to the end.
            for (int i = 0; i + 1 < l_in_cond_idx; ++i) {
                for (int j = i + 1; j < l_in_cond_idx; ++j) {
                    int l_cmp = compare256(l_canon_ins[i].price_normal, l_canon_ins[j].price_normal);
                    bool l_swap = false;
                    if (l_baseline_side == DEX_SIDE_ASK) {
                        if (l_cmp > 0)
                            l_swap = true;
                        else if (l_cmp == 0 && l_canon_ins[i].idx == 0 && l_canon_ins[j].idx != 0)
                            l_swap = true; // push idx==0 to the end of tie-group
                    } else {
                        if (l_cmp < 0)
                            l_swap = true;
                        else if (l_cmp == 0 && l_canon_ins[i].idx == 0 && l_canon_ins[j].idx != 0)
                            l_swap = true; // push idx==0 to the end of tie-group
                    }
                    if (l_swap) {
                        dex_canon_in_t t = l_canon_ins[i];
                        l_canon_ins[i] = l_canon_ins[j];
                        l_canon_ins[j] = t;
                    }
                }
            }
            // Tie-handling integrated in sorting: idx==0 is pushed to the end of its tie-group only (no cross-price movement)
            // Locate leftover IN_COND for seller-leftover scenario:
            // - Composer encodes seller-leftover as IN_COND with idx==0
            // - Buyer-leftover creates a brand new order (OUT only, blank root, seller != any IN seller)
            int l_leftover_in_idx = -1;
            for (int i = 0; i < l_in_cond_idx; ++i) {
                if (l_canon_ins[i].idx == 0) {
                    l_leftover_in_idx = i;
                    break;
                }
            }

            // Seller-leftover: seller matches (self-purchase is forbidden, so seller match = seller-leftover)
            bool l_is_seller_leftover =
                l_leftover_in_idx >= 0 && l_out_cond &&
                dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_canon_ins[l_leftover_in_idx].seller);
            // Seller-leftover MUST have non-blank root
            if (l_is_seller_leftover && dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash)) {
                log_it(L_ERROR, "%s(): Blank root in seller-leftover!", __FUNCTION__);
                RET_ERR(DEXV_LEFTOVER_STRUCTURE_VIOLATION);
            }

            // Boundary (partial) position is determined by leftover position (seller-leftover only)
            int l_partial_pos = l_is_seller_leftover ? l_leftover_in_idx : -1;

            // Validate boundary position
            if (l_is_seller_leftover) {
                // Seller-leftover present: must have partial position
                if (l_partial_pos < 0) {
                    RET_ERR(DEXV_LEFTOVER_STRUCTURE_VIOLATION);
                } else {
                    uint256_t l_price_boundary = l_canon_ins[l_partial_pos].price_normal;
                    uint256_t l_price_leftover = l_canon_ins[l_leftover_in_idx].price_normal;
                    int l_price_cmp = compare256(l_price_leftover, l_price_boundary);
                    // Fast boundary check: no fully executed order with worse price than leftover
                    for (int i = 0; i < l_partial_pos; ++i) {
                        int l_cmp = compare256(l_canon_ins[i].price_normal, l_price_leftover);
                        if ((l_baseline_side == DEX_SIDE_ASK && l_cmp > 0) || (l_baseline_side == DEX_SIDE_BID && l_cmp < 0))
                            RET_ERR(DEXV_CANONICAL_LEFTOVER_MISMATCH);
                    }
                    // If leftover seller is NOT the boundary seller and prices differ → invalid
                    if (l_leftover_in_idx != l_partial_pos && l_price_cmp != 0)
                        RET_ERR(DEXV_CANONICAL_LEFTOVER_MISMATCH);
                    // If same seller (strict case), validate leftover amount equals reconstructed remainder
                    if (l_leftover_in_idx == l_partial_pos) {
                        // Compute l_pair_base_accum_before_boundary (accumulated BASE before boundary order)
                        uint256_t l_pre_base_acc = uint256_0;
                        for (int j = 0; j < l_partial_pos; ++j) {
                            SUM_256_256(l_pre_base_acc, l_canon_ins[j].base_full, &l_pre_base_acc);
                        }
                        // base_executed on partial = B_total - base_acc_before
                        uint256_t l_exec_base_partial = uint256_0, l_expected_leftover_sell = uint256_0;
                        SUBTRACT_256_256(l_total_base, l_pre_base_acc, &l_exec_base_partial);
                        if (l_baseline_side == DEX_SIDE_ASK) {
                            // ASK: leftover = base_leftover (BASE stays BASE) - no round-trip error
                            // Guard: exec cannot exceed order size (would cause underflow or indicate full fill with fake leftover)
                            if (compare256(l_exec_base_partial, l_canon_ins[l_partial_pos].base_full) >= 0) {
                                log_it(L_ERROR, "%s(): Canonical check failed: exec %s >= order size %s (no leftover possible)",
                                       __FUNCTION__, dap_uint256_to_char_ex(l_exec_base_partial).frac,
                                       dap_uint256_to_char_ex(l_canon_ins[l_partial_pos].base_full).frac);
                                RET_ERR(DEXV_CANONICAL_LEFTOVER_MISMATCH);
                            }
                            uint256_t l_leftover_base = uint256_0;
                            SUBTRACT_256_256(l_canon_ins[l_partial_pos].base_full, l_exec_base_partial, &l_leftover_base);
                            l_expected_leftover_sell = l_leftover_base;
                            debug_if(s_debug_more, L_DEBUG,
                                     "%s(): Canonical leftover validation (ASK); "
                                     "Base total: %s, accum before partial: %s, exec partial: %s; "
                                     "IN_COND[%d] base_full: %s; Expected leftover: %s, actual: %s, match: %s",
                                     __FUNCTION__, dap_uint256_to_char_ex(l_total_base).str, dap_uint256_to_char_ex(l_pre_base_acc).str,
                                     dap_uint256_to_char_ex(l_exec_base_partial).str, l_partial_pos,
                                     dap_uint256_to_char_ex(l_canon_ins[l_partial_pos].base_full).str,
                                     dap_uint256_to_char_ex(l_expected_leftover_sell).str,
                                     dap_uint256_to_char_ex(l_out_cond->header.value).str,
                                     compare256(l_out_cond->header.value, l_expected_leftover_sell) == 0 ? "yes" : "NO");
                            if (compare256(l_out_cond->header.value, l_expected_leftover_sell) != 0)
                                RET_ERR(DEXV_CANONICAL_LEFTOVER_MISMATCH);
                        } else {
                            // BID: skip round-trip leftover check (div-mult causes rounding errors)
                            // Leftover already validated in Phase 2 via exec_quote = prev - leftover
                            // Phase 3 payout checks ensure consistency
                            debug_if(s_debug_more, L_DEBUG,
                                     "%s(): Canonical leftover validation (BID); "
                                     "Base total: %s, accum before partial: %s, exec partial: %s; "
                                     "IN_COND[%d] base_full: %s; Skipping round-trip check (validated in Phase 2)",
                                     __FUNCTION__, dap_uint256_to_char_ex(l_total_base).str, dap_uint256_to_char_ex(l_pre_base_acc).str,
                                     dap_uint256_to_char_ex(l_exec_base_partial).str, l_partial_pos,
                                     dap_uint256_to_char_ex(l_canon_ins[l_partial_pos].base_full).str);
                        }
                        // min_fill is still validated in the original block for first IN (rule #0 not weakened)
                    }
                }
            }
            // Note: buyer-leftover (blank root + seller != original) is validated later in buyer-leftover section

            // Canonical per-seller expected_buy computation (defense-in-depth):
            // Recompute expected_buy from canonical reconstruction (based on real OUTs)
            // and verify consistency with preliminary expected_buy (from Phase 2, based on TX data)

            // Step 1: Compute canonical expected_buy for each seller
            uint256_t *l_canon_expected_buy = DAP_NEW_Z_COUNT(uint256_t, l_uniq_sllrs_cnt);

            // Compute accumulated BASE before boundary (for partial exec calculation)
            uint256_t l_base_acc = uint256_0;
            if (l_partial_pos > 0) {
                for (int j = 0; j < l_partial_pos; ++j) {
                    SUM_256_256(l_base_acc, l_canon_ins[j].base_full, &l_base_acc);
                }
            }

            for (int i = 0; i < l_in_cond_idx; ++i) {
                uint256_t l_exec_base_i = uint256_0;
                if (l_partial_pos < 0) {
                    // No boundary: ALL orders fully filled
                    l_exec_base_i = l_canon_ins[i].base_full;
                } else if (i < l_partial_pos) {
                    // Before boundary: fully filled
                    l_exec_base_i = l_canon_ins[i].base_full;
                } else if (i == l_partial_pos) {
                    // AT boundary: partially filled
                    SUBTRACT_256_256(l_total_base, l_base_acc, &l_exec_base_i);
                } else {
                    // BEYOND boundary: not filled
                }
                if (IS_ZERO_256(l_exec_base_i))
                    continue;

                // Map seller address to seller index
                int l_seller_idx = -1;
                for (int j = 0; j < l_uniq_sllrs_cnt; ++j) {
                    if (dap_chain_addr_compare(&l_sellers[j].addr, &l_canon_ins[i].seller)) {
                        l_seller_idx = j;
                        break;
                    }
                }
                if (l_seller_idx < 0)
                    continue; // defensive

                if (l_baseline_side == DEX_SIDE_ASK) {
                    // ASK: sellers receive QUOTE = BASE * rate
                    uint256_t l_quote_expect = uint256_0;
                    MULT_256_COIN(l_exec_base_i, l_canon_ins[i].price_normal, &l_quote_expect);
                    SUM_256_256(l_canon_expected_buy[l_seller_idx], l_quote_expect, &l_canon_expected_buy[l_seller_idx]);
                } else {
                    // BID: sellers receive BASE directly (no conversion needed)
                    SUM_256_256(l_canon_expected_buy[l_seller_idx], l_exec_base_i, &l_canon_expected_buy[l_seller_idx]);
                }
            }

            // Step 2: Compute canonical service fee (if applicable)
            uint256_t l_srv_fee_req_canon = uint256_0;
            bool l_fee_pct_mode_canon = (l_fee_cfg & 0x80) != 0;
            if (l_fee_pct_mode_canon) {
                // % fee from INPUT: ASK→QUOTE, BID→BASE (0.1% step)
                uint8_t l_pct = l_fee_cfg & 0x7F;
                if (l_pct > 0 && l_pct <= 127) {
                    // INPUT = sum of canonical expected_buy (what buyer spends)
                    // For both ASK and BID, l_canon_expected_buy[j] is seller's payout
                    // which equals buyer's INPUT in the respective token
                    uint256_t l_input_amount_canon = uint256_0;
                    for (int j = 0; j < l_uniq_sllrs_cnt; ++j)
                        SUM_256_256(l_input_amount_canon, l_canon_expected_buy[j], &l_input_amount_canon);

                    uint256_t l_pct_256 = GET_256_FROM_64(l_pct);
                    MULT_256_256(l_pct_256, l_input_amount_canon, &l_srv_fee_req_canon);
                    DIV_256(l_srv_fee_req_canon, GET_256_FROM_64(1000), &l_srv_fee_req_canon); // 0.1% step
                }
            } else {
                // Native absolute fee: per-pair multiplier or global fallback
                uint8_t l_mult = l_fee_cfg & 0x7F;
                l_srv_fee_req_canon = l_mult > 0 ? GET_256_FROM_64((uint64_t)l_mult * DAP_DEX_FEE_UNIT_NATIVE) : l_native_fee_cached;
            }

            // Step 3: Verify canonical service fee matches preliminary fee (from Phase 2)
            // This prevents attacks where composer manipulates l_executed_i to reduce service fee
            if (l_srv_used && !IS_ZERO_256(l_srv_fee_req) && compare256(l_srv_fee_req_canon, l_srv_fee_req) != 0) {
                log_it(L_ERROR, "%s(): Service fee mismatch: canonical %s != preliminary %s", __FUNCTION__,
                       dap_uint256_to_char_ex(l_srv_fee_req_canon).frac, dap_uint256_to_char_ex(l_srv_fee_req).frac);
                DAP_DEL_Z(l_canon_expected_buy);
                RET_ERR(DEXV_SERVICE_FEE_MISMATCH);
            }

            // Step 4: Account for service fee aggregation (if seller == service)
            // In Phase 3, if seller == service and fee_ticker == buy_token,
            // preliminary expected_buy was increased by l_srv_fee_req.
            // We need to add l_srv_fee_req_canon to canonical expected_buy before comparison.
            // With % mode: ASK→fee in QUOTE (=buy_token), BID→fee in BASE (=buy_token)
            // Both cases aggregate if seller == service.
            int l_srv_seller_idx = -1;
            for (int i = 0; i < l_uniq_sllrs_cnt; i++) {
                if (dap_chain_addr_compare(&l_sellers[i].addr, &l_srv_addr)) {
                    l_srv_seller_idx = i;
                    break;
                }
            }
            bool l_is_buyer_service = (l_buyer_addr && dap_chain_addr_compare(l_buyer_addr, &l_srv_addr));
            bool l_fee_was_aggregated =
                (l_srv_seller_idx >= 0 && l_srv_ticker && !strcmp(l_srv_ticker, l_buy_ticker) && !l_is_buyer_service);
            if (l_fee_was_aggregated && !IS_ZERO_256(l_srv_fee_req_canon)) {
                SUM_256_256(l_canon_expected_buy[l_srv_seller_idx], l_srv_fee_req_canon, &l_canon_expected_buy[l_srv_seller_idx]);
            }

            // Step 5: Verify canonical expected_buy matches preliminary expected_buy (from Phase 2)
            // This prevents attacks where composer manipulates l_executed_i to misdirect seller payouts
            for (int j = 0; j < l_uniq_sllrs_cnt; ++j) {
                if (compare256(l_canon_expected_buy[j], l_sellers[j].expected_buy) != 0) {
                    log_it(L_ERROR, "%s(): Seller %d expected buy mismatch: canonical %s != preliminary %s", __FUNCTION__, j,
                           dap_uint256_to_char_ex(l_canon_expected_buy[j]).frac, dap_uint256_to_char_ex(l_sellers[j].expected_buy).frac);
                    DAP_DEL_Z(l_canon_expected_buy);
                    RET_ERR(DEXV_SELLER_PAYOUT_MISMATCH);
                }
            }

            // Cleanup
            DAP_DEL_Z(l_canon_expected_buy);

            // Note: We keep preliminary expected_buy from Phase 2 (no replacement needed)
            // because canonical verification passed → preliminary values are correct
        }
    }

    // TX-type specific validation (INVALIDATE, EXCHANGE, UPDATE)

    // INVALIDATE path: no OUT_COND and no seller received buy_token (only refunds in sell_token)
    if (l_is_invalidate) {
        // INVALIDATE: seller cancels orders, receives refunds
        if (!a_owner)
            RET_ERR(DEXV_INVALIDATE_NOT_OWNER);

        if (l_uniq_sllrs_cnt != 1)
            RET_ERR(DEXV_INVALIDATE_MULTI_SELLER);

        // No unexpected buy_token payouts (leak detection)
        if (!IS_ZERO_256(l_buy_others))
            RET_ERR(DEXV_BUY_TOKEN_LEAK);

        // No unexpected sell_token payouts (refund must go to seller only)
        if (!IS_ZERO_256(l_sell_others))
            RET_ERR(DEXV_SELL_TOKEN_LEAK);

        // Calculate expected refund = sum of consumed order values
        uint256_t l_expected_refund = uint256_0;
        for (int i = 0; i < l_in_cond_idx; ++i)
            SUM_256_256(l_expected_refund, l_prev_outs[i]->header.value, &l_expected_refund);

        // Warn if service fee paid during INVALIDATE (no trade)
        if (!IS_ZERO_256(l_paid_srv_fee))
            log_it(L_WARNING, "%s(): Service fee %s %s paid for INVALIDATE", __FUNCTION__, dap_uint256_to_char_ex(l_paid_srv_fee).frac,
                   l_srv_ticker ? l_srv_ticker : l_native_ticker);

        // Final conservation: refund - fees (only if sell_token is NATIVE)
        if (!strcmp(l_sell_ticker, l_native_ticker)) {
            // Native sell_token: deduct validator + network fees from refund
            // Guard against underflow if refund < fees (edge case: tiny order)
            if (!IS_ZERO_256(l_fee_native)) {
                if (compare256(l_expected_refund, l_fee_native) >= 0)
                    SUBTRACT_256_256(l_expected_refund, l_fee_native, &l_expected_refund);
                else
                    l_expected_refund = uint256_0;
            }
            if (l_net_used && !IS_ZERO_256(l_net_fee_req)) {
                if (compare256(l_expected_refund, l_net_fee_req) >= 0)
                    SUBTRACT_256_256(l_expected_refund, l_net_fee_req, &l_expected_refund);
                else
                    l_expected_refund = uint256_0;
            }
        }
        // Non-native sell_token: fees paid separately in NATIVE, no deduction from refund

        if (compare256(l_paid_sell_total, l_expected_refund))
            RET_ERR(DEXV_FINAL_NATIVE_MISMATCH);

        goto dex_verif_ret_err; // INVALIDATE validated (l_err=0 means success)
    }

    // UPDATE path: owner modifies order value (increase/decrease), no trade occurs
    // expected_buy=0 (skipped on line 3411), but paid_buy may include native cashback
    if (l_is_update) {
        // a_owner already verified at line 3295, but explicit check for clarity
        if (!a_owner)
            RET_ERR(DEXV_UPDATE_NOT_OWNER);

        // UPDATE must have single seller (the owner)
        if (l_uniq_sllrs_cnt != 1)
            RET_ERR(DEXV_INVALIDATE_MULTI_SELLER);

        // Leak detection: no unexpected token flows to third parties
        if (!IS_ZERO_256(l_buy_others))
            RET_ERR(DEXV_BUY_TOKEN_LEAK);

        if (!IS_ZERO_256(l_sell_others))
            RET_ERR(DEXV_SELL_TOKEN_LEAK);

        goto dex_verif_ret_err; // UPDATE validated
    }

    // EXCHANGE: validate per-seller expected_buy == paid_buy
    // Validate seller payouts (self-purchase is now forbidden, so exact match required)
    for (int j = 0; j < l_uniq_sllrs_cnt; ++j) {
        debug_if(s_debug_more, L_DEBUG, "%s(): Seller #%d; Buy expected / paid: %s / %s %s; to addr %s", __FUNCTION__, j,
                 dap_uint256_to_char_ex(l_sellers[j].expected_buy).frac, dap_uint256_to_char_ex(l_sellers[j].paid_buy).frac, l_buy_ticker,
                 dap_chain_addr_to_str_static(&l_sellers[j].addr));

        // Verify paid_buy == expected_buy (both computed via same division path)
        if (compare256(l_sellers[j].paid_buy, l_sellers[j].expected_buy) != 0) {
            log_it(L_ERROR, "%s(): Seller %d payout mismatch; Buy paid / expected: %s / %s %s", __FUNCTION__, j,
                   dap_uint256_to_char_ex(l_sellers[j].paid_buy).frac, dap_uint256_to_char_ex(l_sellers[j].expected_buy).frac,
                   l_buy_ticker);
            RET_ERR(DEXV_SELLER_PAYOUT_MISMATCH);
        }
    }

    // EXCHANGE partial: validate buyer payout
    if (l_out_cond && l_out_cond->subtype.srv_dex.tx_type == DEX_TX_TYPE_EXCHANGE) {
        if (!l_buyer_addr)
            RET_ERR(DEXV_BUYER_ADDR_MISSING);
        if (!l_buyer_addr_uniq)
            RET_ERR(DEXV_MULTI_BUYER_DEST);

        uint256_t l_buyer_expected = l_executed_total;
        if (l_srv_used && l_srv_ticker && !strcmp(l_sell_ticker, l_srv_ticker)) {
            if (compare256(l_executed_total, l_srv_fee_req) >= 0)
                SUBTRACT_256_256(l_buyer_expected, l_srv_fee_req, &l_buyer_expected);
            else
                l_buyer_expected = uint256_0;
        }
        if (compare256(l_buyer_received, l_buyer_expected) < 0)
            RET_ERR(DEXV_BUYER_PAYOUT_ADDR_MISMATCH);

        if (!IS_ZERO_256(l_buy_others))
            RET_ERR(DEXV_BUY_TOKEN_LEAK);

        if (!IS_ZERO_256(l_sell_others))
            RET_ERR(DEXV_SELL_TOKEN_LEAK);
    }

    // Buyer-/Seller-leftover classification (root-based):
    //  - Seller-leftover: OUT_COND has non-blank root that MUST equal the first-chain root of the first IN_COND
    //  - Buyer-leftover: OUT_COND has blank root, seller_addr must be the buyer, no buy_token leaks
    //
    // Note: ORDER (l_in_cond_cnt=0) is excluded by the l_uniq_sllrs_cnt>0 condition below
    if (l_out_cond && l_uniq_sllrs_cnt > 0) {
        if (!dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash)) {
            // Seller-leftover: validate OUT_COND.root matches first IN_COND chain root
            // This prevents composer from creating fake seller-leftover with arbitrary root
            dap_chain_datum_tx_t *l_first_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_first_in_prev_hash);
            if (!l_first_prev_tx)
                RET_ERR(DEXV_PREV_TX_NOT_FOUND);
            dap_hash_fast_t l_first_root =
                dap_ledger_get_first_chain_tx_hash(a_ledger, l_first_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
            if (dap_hash_fast_is_blank(&l_first_root))
                l_first_root = l_first_in_prev_hash; // ORDER: root=tail
            if (!dap_hash_fast_compare(&l_out_cond->subtype.srv_dex.order_root_hash, &l_first_root))
                RET_ERR(DEXV_ROOT_CHAIN_MISMATCH);
            // Seller-leftover: verify seller_addr matches first IN_COND (prevents ownership hijack via fake root)
            if (!dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_prev_outs[0]->subtype.srv_dex.seller_addr))
                RET_ERR(DEXV_ROOT_CHAIN_MISMATCH);
            // Seller-leftover: l_buy_others check is not applicable (seller can be paid in buy_token)
        } else {
            // Buyer-leftover: validate OUT_COND seller_addr matches buyer
            if (!l_buyer_addr)
                RET_ERR(DEXV_BUYER_ADDR_MISSING);
            if (!l_buyer_addr_uniq)
                RET_ERR(DEXV_MULTI_BUYER_DEST);
            if (!dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, l_buyer_addr))
                RET_ERR(DEXV_BUYER_MISMATCH);
            // Buyer-leftover: reject dust-sized orders (dynamic threshold; 0 = disabled)
            uint256_t l_fixed_native = l_fee_native;
            if (l_net_used && !IS_ZERO_256(l_net_fee_req))
                SUM_256_256(l_fixed_native, l_net_fee_req, &l_fixed_native);
            bool l_is_buyer_service = (l_buyer_addr && dap_chain_addr_compare(l_buyer_addr, &l_srv_addr));
            uint8_t l_fee_cfg_eff = l_is_buyer_service ? (l_fee_cfg & 0x80) : l_fee_cfg;
            if (!l_is_buyer_service && (l_fee_cfg_eff & 0x80) == 0) {
                uint8_t l_mult = l_fee_cfg_eff & 0x7F;
                uint256_t l_srv_abs = l_mult > 0 ? GET_256_FROM_64((uint64_t)l_mult * DAP_DEX_FEE_UNIT_NATIVE) : l_native_fee_cached;
                if (!IS_ZERO_256(l_srv_abs))
                    SUM_256_256(l_fixed_native, l_srv_abs, &l_fixed_native);
            }
            bool l_leftover_is_bid = (l_baseline_side == DEX_SIDE_ASK);
            uint256_t l_leftover_thr = s_dex_calc_dust_threshold(l_buy_ticker, l_sell_ticker, l_native_ticker, l_fee_cfg_eff,
                                                                 l_out_cond->subtype.srv_dex.rate, l_leftover_is_bid, l_fixed_native);
            if (!IS_ZERO_256(l_leftover_thr) && compare256(l_out_cond->header.value, l_leftover_thr) <= 0)
                RET_ERR(DEXV_INVALID_RESIDUAL);
            // Buyer-leftover: no unexpected buy_token payouts (only sellers and service fee)
            if (!IS_ZERO_256(l_buy_others))
                RET_ERR(DEXV_BUY_TOKEN_LEAK);
        }
    }

    // EXCHANGE full close: validate buyer received expected amount
    if (!l_out_cond) {
        if (!l_buyer_addr)
            RET_ERR(DEXV_BUYER_ADDR_MISSING);
        if (!l_buyer_addr_uniq)
            RET_ERR(DEXV_MULTI_BUYER_DEST);

        // Calculate expected buyer payout
        // Buyer receives: executed_total - service_fee (if sell==srv) - dust_refund
        // Edge case: if fee > executed, buyer pays fee entirely from inputs (expected = 0)
        uint256_t l_buyer_expected = l_executed_total;
        // Subtract service fee if in sell_token
        if (l_srv_used && l_srv_ticker && !strcmp(l_sell_ticker, l_srv_ticker)) {
            if (compare256(l_buyer_expected, l_srv_fee_req) >= 0)
                SUBTRACT_256_256(l_buyer_expected, l_srv_fee_req, &l_buyer_expected);
            else
                l_buyer_expected = uint256_0;
        }
        // Subtract dust-refund (goes to seller, not buyer)
        if (!IS_ZERO_256(l_dust_refund)) {
            if (compare256(l_buyer_expected, l_dust_refund) >= 0)
                SUBTRACT_256_256(l_buyer_expected, l_dust_refund, &l_buyer_expected);
            else
                l_buyer_expected = uint256_0;
        }

        // Critical: buyer MUST receive AT LEAST the expected amount (overpayment allowed for cashback)
        // Cashback possible in sell_token if sell_token==NATIVE (fee overpayment)
        // Overpayment: ASK+NATIVE==BASE or BID+NATIVE==QUOTE → cashback in NATIVE (sell_token)
        // Global ledger conservation (SUM(INs) == SUM(OUTs) + fees) prevents theft
        if (compare256(l_buyer_received, l_buyer_expected) < 0)
            RET_ERR(DEXV_BUYER_PAYOUT_ADDR_MISMATCH);

        // No unexpected buy_token payouts (only sellers, service fee, and buyer cashback)
        if (!IS_ZERO_256(l_buy_others))
            RET_ERR(DEXV_BUY_TOKEN_LEAK);

        // No unexpected sell_token payouts
        if (!IS_ZERO_256(l_sell_others))
            RET_ERR(DEXV_SELL_TOKEN_LEAK);
    }

    // Final conservation check: sellers' payouts in sell_token (ONLY for UPDATE)
    // l_paid_sell_total = sum of ALL sellers' OUTs in sell_token (EXCLUDES buyer)
    //
    // Applies to UPDATE (self-modification):
    //
    // 1. UPDATE with value decrease (prev_value > new_value):
    //    - Composer creates refund OUT: delta = prev_value - new_value in sell_token to seller
    //    - l_executed_total = delta (computed on line 2594: prev - new)
    //    - l_paid_sell_total = delta (refund OUT)
    //    - Check: l_paid_sell_total >= l_expected_seller_total (delta minus fees if native)
    //
    // 2. UPDATE with value increase (prev_value < new_value):
    //    - Composer collects additional INs (wallet UTXO: delta = new - prev)
    //    - Cashback OUT if overpaid (l_sell_transfer > delta)
    //    - l_executed_total = 0 (no delta, only additional lock)
    //    - l_paid_sell_total = cashback (if any)
    //    - Check: l_paid_sell_total >= 0 (always PASS, cashback verified by ledger conservation)
    //
    // 3. UPDATE with same value (prev_value == new_value, rate-only change):
    //    - No OUTs in sell_token
    //    - l_executed_total = 0, l_paid_sell_total = 0
    //    - Check: 0 >= 0 (always PASS)
    //
    // NOT applicable to:
    // - EXCHANGE: sellers receive buy_token, not sell_token (skipped by tx_type check)
    // - INVALIDATE: separate validation (line 2867), never reaches here
    //
    if (l_out_cond && a_owner && l_out_cond->subtype.srv_dex.tx_type == DEX_TX_TYPE_UPDATE) {
        uint256_t l_expected_seller_total = l_executed_total;
        if (!strcmp(l_sell_ticker, l_native_ticker)) {
            // Native token: deduct validator + network fees
            if (!IS_ZERO_256(l_fee_native))
                SUBTRACT_256_256(l_expected_seller_total, l_fee_native, &l_expected_seller_total);
            if (l_net_used && !IS_ZERO_256(l_net_fee_req))
                SUBTRACT_256_256(l_expected_seller_total, l_net_fee_req, &l_expected_seller_total);
        }
        // Service fee: buyer pays it, NEVER deduct from seller

        // Critical: sellers MUST receive AT LEAST the expected amount in sell_token (overpayment allowed)
        // Overpayment possible if sell_token==NATIVE (cashback from fee UTXO overpayment)
        // Global ledger conservation (SUM(INs) == SUM(OUTs) + fees) prevents theft
        if (compare256(l_paid_sell_total, l_expected_seller_total) < 0)
            RET_ERR(!strcmp(l_sell_ticker, l_native_ticker) ? DEXV_FINAL_NATIVE_MISMATCH : DEXV_FINAL_NONNATIVE_MISMATCH);

        // No unexpected sell_token payouts (except seller cashback)
        if (!IS_ZERO_256(l_sell_others))
            RET_ERR(DEXV_SELL_TOKEN_LEAK);
    }

dex_verif_ret_err:
    DAP_DEL_MULTY(l_sellers, l_prev_outs, l_outs, l_canon_ins, l_ins);
    if (l_err)
        log_it(L_WARNING, "%s(): Verification error %d: %s at line %d", __FUNCTION__, -l_err, s_dex_verify_err_str(l_err), l_err_line);
    return -l_err;
#undef RET_ERR
}

/* ============================================================================
 * Decree Handling
 * DEX governance decrees (fee_set, pair_add/remove, pair_fee_set)
 * ============================================================================ */

// TSD section types for decree parameters
#define DEX_DECREE_TSD_METHOD 0x0000 // uint8_t decree method
#define DEX_DECREE_TSD_TOKEN_BASE 0x0001
#define DEX_DECREE_TSD_TOKEN_QUOTE 0x0002
#define DEX_DECREE_TSD_NET_BASE 0x0003
#define DEX_DECREE_TSD_NET_QUOTE 0x0004
#define DEX_DECREE_TSD_FEE_CONFIG 0x0005
#define DEX_DECREE_TSD_FEE_AMOUNT 0x0020
#define DEX_DECREE_TSD_FEE_ADDR 0x0021

// Decree method types
typedef enum {
    DEX_DECREE_UNKNOWN,
    DEX_DECREE_FEE_SET,
    DEX_DECREE_PAIR_ADD,
    DEX_DECREE_PAIR_REMOVE,
    DEX_DECREE_PAIR_FEE_SET,
    DEX_DECREE_PAIR_FEE_SET_ALL
} dex_decree_method_t;

int dap_chain_net_srv_dex_decree_callback(dap_ledger_t *a_ledger, bool a_apply, dap_tsd_t *a_params, size_t a_params_size)
{
    dap_ret_val_if_any(-1, !a_params);

    // Collect all TSD sections in one pass (including method)
    dap_tsd_t *l_tsd_method = NULL, *l_tsd_token_base = NULL, *l_tsd_token_quote = NULL, *l_tsd_net_base = NULL, *l_tsd_net_quote = NULL,
              *l_tsd_fee_config = NULL, *l_tsd_fee_amount = NULL, *l_tsd_fee_addr = NULL, *l_tsd = NULL;
    size_t l_tsd_size = 0;
    dap_tsd_iter(l_tsd, l_tsd_size, a_params, a_params_size)
    {
        switch (l_tsd->type) {
        case DEX_DECREE_TSD_METHOD:
            l_tsd_method = l_tsd;
            break;
        case DEX_DECREE_TSD_TOKEN_BASE:
            l_tsd_token_base = l_tsd;
            break;
        case DEX_DECREE_TSD_TOKEN_QUOTE:
            l_tsd_token_quote = l_tsd;
            break;
        case DEX_DECREE_TSD_NET_BASE:
            l_tsd_net_base = l_tsd;
            break;
        case DEX_DECREE_TSD_NET_QUOTE:
            l_tsd_net_quote = l_tsd;
            break;
        case DEX_DECREE_TSD_FEE_CONFIG:
            l_tsd_fee_config = l_tsd;
            break;
        case DEX_DECREE_TSD_FEE_AMOUNT:
            l_tsd_fee_amount = l_tsd;
            break;
        case DEX_DECREE_TSD_FEE_ADDR:
            l_tsd_fee_addr = l_tsd;
            break;
        }
    }

    // Extract method from first TSD section
    dap_ret_val_if_any(-1, !l_tsd_method);
    dex_decree_method_t l_method = (dex_decree_method_t)dap_tsd_get_scalar(l_tsd_method, uint8_t);

    int l_ret = 0;
    switch (l_method) {
    case DEX_DECREE_FEE_SET:
        // Required: FEE_AMOUNT, FEE_ADDR; prohibited: tokens, net-ids, fee_config
        dap_ret_val_if_any(-1, !l_tsd_fee_amount, !l_tsd_fee_addr, l_tsd_fee_config, l_tsd_token_base, l_tsd_token_quote, l_tsd_net_base,
                           l_tsd_net_quote);
        if (a_apply) {
            pthread_rwlock_wrlock(&s_dex_cache_rwlock);
            memcpy(&s_dex_native_fee_amount, l_tsd_fee_amount->data, sizeof(uint256_t));
            memcpy(&s_dex_service_fee_addr, l_tsd_fee_addr->data, sizeof(dap_chain_addr_t));
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
            log_it(L_NOTICE, "Service fee set: %s %s to %s", a_ledger->net->pub.native_ticker,
                   dap_uint256_to_char_ex(s_dex_native_fee_amount).frac, dap_chain_addr_to_str_static(&s_dex_service_fee_addr));
        }
        return 0;

    case DEX_DECREE_PAIR_FEE_SET_ALL: {
        // Required: FEE_CONFIG
        dap_ret_val_if_any(-1, !l_tsd_fee_config, l_tsd_fee_amount, l_tsd_fee_addr, l_tsd_token_base, l_tsd_token_quote, l_tsd_net_base,
                           l_tsd_net_quote);
        if (a_apply) {
            uint8_t l_new_cfg = dap_tsd_get_scalar(l_tsd_fee_config, uint8_t);
            pthread_rwlock_wrlock(&s_dex_cache_rwlock);
            dex_pair_index_t *l_it, *l_tmp;
            int l_count = 0;
            HASH_ITER(hh, s_dex_pair_index, l_it, l_tmp)
            {
                l_it->key.fee_config = l_new_cfg;
                l_count++;
            }
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
            l_ret = l_count ? 0 : -3;
            log_it(L_NOTICE, "Updated fee for %d pairs: 0x%02x", l_count, l_new_cfg);
        }
        return l_ret;
    } break;

    case DEX_DECREE_PAIR_ADD:
    case DEX_DECREE_PAIR_REMOVE:
    case DEX_DECREE_PAIR_FEE_SET: {
        // Common validation: required tokens/nets, prohibited fee_amount/fee_addr
        dap_ret_val_if_any(-1, !l_tsd_token_base, !l_tsd_token_quote, !l_tsd_net_base, !l_tsd_net_quote, l_tsd_fee_amount, l_tsd_fee_addr);
        const char *l_token_base = dap_tsd_get_string_const(l_tsd_token_base), *l_token_quote = dap_tsd_get_string_const(l_tsd_token_quote);
        dap_ret_val_if_any(-2, !dap_strcmp(l_token_base, l_token_quote), !dap_isstralnum(l_token_base), !dap_isstralnum(l_token_quote));
        dap_chain_net_id_t l_net_base = {.uint64 = dap_tsd_get_scalar(l_tsd_net_base, uint64_t)},
                           l_net_quote = {.uint64 = dap_tsd_get_scalar(l_tsd_net_quote, uint64_t)};

        dex_pair_key_t l_key = {};
        s_dex_pair_normalize(l_token_base, l_net_base, l_token_quote, l_net_quote, uint256_0, &l_key, NULL, NULL);

        // Method-specific validation and operations
        switch (l_method) {
        case DEX_DECREE_PAIR_ADD:
            // FEE_CONFIG is optional
            l_key.fee_config = l_tsd_fee_config ? dap_tsd_get_scalar(l_tsd_fee_config, uint8_t) : 0;
            if (a_apply) {
                pthread_rwlock_wrlock(&s_dex_cache_rwlock);
                l_ret = s_dex_pair_index_add(&l_key);
                uint256_t l_srv_fee = s_dex_fee_config_to_val(l_key.fee_config);
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
                switch (l_ret) {
                case 0:
                    log_it(L_INFO, "Pair %s/%s with fee %s%s added to DEX in net %" DAP_UINT64_FORMAT_x, l_key.token_base,
                           l_key.token_quote, dap_uint256_to_char_ex(l_srv_fee).frac,
                           l_key.fee_config & 0x80 ? "% of input" : " native coin", l_key.net_id_base.uint64);
                    break;
                case -1:
                    log_it(L_ERROR, "Pair %s/%s has already been added to DEX in net %" DAP_UINT64_FORMAT_x, l_key.token_base,
                           l_key.token_quote, l_key.net_id_base.uint64);
                    l_ret = 0;
                    break;
                default:
                    log_it(L_ERROR, "Failed to add pair %s/%s to DEX, error %d", l_key.token_base, l_key.token_quote, l_ret);
                    break;
                }
            }
            break;

        case DEX_DECREE_PAIR_REMOVE:
            // FEE_CONFIG is forbidden
            dap_ret_val_if_any(-1, l_tsd_fee_config);
            if (a_apply) {
                pthread_rwlock_wrlock(&s_dex_cache_rwlock);
                s_dex_pair_index_remove(&l_key);
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
            }
            break;

        case DEX_DECREE_PAIR_FEE_SET:
            // FEE_CONFIG is required
            dap_ret_val_if_any(-1, !l_tsd_fee_config);
            if (a_apply) {
                uint8_t l_fee_cfg = dap_tsd_get_scalar(l_tsd_fee_config, uint8_t);
                pthread_rwlock_wrlock(&s_dex_cache_rwlock);
                uint256_t l_srv_fee = s_dex_fee_config_to_val(l_fee_cfg);
                dex_pair_index_t *l_pair = s_dex_pair_index_get(&l_key);
                if (l_pair)
                    l_pair->key.fee_config = l_fee_cfg;
                else
                    l_ret = -3;
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
                if (!l_ret) {
                    log_it(L_INFO, "Fee %s%s set for pair %s/%s in net %" DAP_UINT64_FORMAT_x, dap_uint256_to_char_ex(l_srv_fee).frac,
                           l_key.fee_config & 0x80 ? "% of input" : " native coin", l_key.token_base, l_key.token_quote,
                           l_key.net_id_base.uint64);
                }
            }
        default:
            break;
        }
    } break;

    default:
        return log_it(L_WARNING, "Unknown decree method for DEX service: %u", (unsigned)l_method), -2;
    }
    return l_ret;
}

/* ============================================================================
 * Service Lifecycle
 * Initialization, deinitialization, config loading
 * ============================================================================ */

static int s_cli_srv_dex(int a_argc, char **a_argv, void **a_str_reply, int a_version);

// Tag check callback for mempool list / tx history display
static bool s_tag_check_dex(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_datum_tx_item_groups_t *a_items_grp,
                            dap_chain_tx_tag_action_type_t *a_action)
{
    if (!a_items_grp->items_out_cond_srv_dex && !a_items_grp->items_in_cond)
        return false;

    dex_tx_type_t l_type = s_dex_tx_classify(a_ledger, a_tx, NULL, NULL, NULL);
    if (l_type == DEX_TX_TYPE_UNDEFINED)
        return false;
    else if (a_action) {
        switch (l_type) {
        case DEX_TX_TYPE_ORDER:
            *a_action = DAP_CHAIN_TX_TAG_ACTION_OPEN;
            break;
        case DEX_TX_TYPE_UPDATE:
            *a_action = DAP_CHAIN_TX_TAG_ACTION_CHANGE;
            break;
        case DEX_TX_TYPE_INVALIDATE:
            *a_action = DAP_CHAIN_TX_TAG_ACTION_CLOSE;
            break;
        default: // EXCHANGE and any future types
            *a_action = DAP_CHAIN_TX_TAG_ACTION_USE;
            break;
        }
    }
    return true;
}

int dap_chain_net_srv_dex_init()
{
    s_debug_more = dap_config_get_item_bool_default(g_config, "srv_dex", "debug_more", true);
    // Register verificator for SRV_DEX
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, s_dex_verificator_callback, NULL, NULL);
    // Register service for tagging (mempool list, tx history)
    dap_ledger_service_add((dap_chain_net_srv_uid_t){.uint64 = DAP_CHAIN_NET_SRV_DEX_ID}, "dex", s_tag_check_dex);

    // Load soft policy for cross-net matching (outside consensus)
    const char *l_policy = dap_config_get_item_str_default(g_config, "srv_dex", "cross_net_policy", "reject");
    s_cross_net_policy = !dap_strcmp(l_policy, "allow")  ? CROSS_NET_ALLOW
                         : !dap_strcmp(l_policy, "warn") ? CROSS_NET_WARN
                                                         : CROSS_NET_REJECT;

    log_it(L_INFO, "Cross-net policy: %s", s_cross_net_policy_str(s_cross_net_policy));
    // Read cache switch from config
    s_dex_cache_enabled = dap_config_get_item_bool_default(g_config, "srv_dex", "cache_enabled", true);
    log_it(L_INFO, "Memory cache: %s", s_dex_cache_enabled ? "on" : "off");
    // Read history cache switch and bucket size (default: daily buckets for storage efficiency)
    s_dex_history_enabled = dap_config_get_item_bool_default(g_config, "srv_dex", "history_cache", true);
    s_dex_history_bucket_sec = (uint64_t)dap_config_get_item_uint32_default(g_config, "srv_dex", "history_bucket_sec", DAP_SEC_PER_DAY);
    if (!s_dex_history_bucket_sec)
        s_dex_history_bucket_sec = DAP_SEC_PER_DAY;
    log_it(L_INFO, "History cache: %s, bucket %us", s_dex_history_enabled ? "on" : "off", (unsigned)s_dex_history_bucket_sec);

    // Subscribe cache to ledger notifications for all nets
    for (dap_chain_net_t *net = dap_chain_net_iter_start(); net; net = dap_chain_net_iter_next(net)) {
        dap_ledger_srv_callback_decree_add(net->pub.ledger, (dap_chain_net_srv_uid_t){.uint64 = DAP_CHAIN_NET_SRV_DEX_ID},
                                           dap_chain_net_srv_dex_decree_callback);
        if (s_dex_cache_enabled || s_dex_history_enabled) {
            dap_ledger_tx_add_notify(net->pub.ledger, s_ledger_tx_add_notify_dex, NULL);
        }
    }

    // CLI: register handler
    dap_cli_server_cmd_add(
        "srv_dex", s_cli_srv_dex, NULL, "DEX v2 service commands",
        // === Order Management ===
        "srv_dex order create -net <net_name> -token_sell <ticker> -token_buy <ticker>\n"
        "    -w <wallet> -value <amount> -rate <price> -fee <fee>\n"
        "    [-fill_policy AON|min|min_from_origin] [-min_fill_pct <0-100>] [-min_fill_value <amount>]\n"
        "srv_dex order remove -net <net_name> -order <hash> -w <wallet> -fee <fee>\n"
        "srv_dex order update -net <net_name> -order <root_hash> -w <wallet> -value <amount> -fee <fee>\n"
        // === Query ===
        "srv_dex orders -net <net_name> [-pair <BASE/QUOTE>] [-seller <addr>] [-limit <N>] [-offset <N>]\n"
        "srv_dex orderbook -net <net_name> -pair <BASE/QUOTE>\n"
        "    [-depth <N>] [-tick_price <step>] [-tick <decimals>] [-cumulative]\n"
        "srv_dex status -net <net_name> -pair <BASE/QUOTE> [-seller <addr>]\n"
        "srv_dex pairs -net <net_name>\n"
        // === Analytics ===
        "srv_dex tvl -net <net_name> [-token <ticker>] [-by pair] [-top <N>]\n"
        "srv_dex spread -net <net_name> -pair <BASE/QUOTE> [-verbose]\n"
        "srv_dex slippage -net <net_name> -pair <BASE/QUOTE>\n"
        "    -value <amount> -side buy|sell -unit base|quote [-max_slippage_pct <pct>]\n"
        "srv_dex find_matches -net <net_name> -order <hash> -addr <wallet_addr>\n"
        "srv_dex history -net <net_name> [-pair <BASE/QUOTE> | -order <hash>] [-from <ts>] [-to <ts>] [-seller <addr>] [-buyer <addr>]\n"
        "    [-view events|summary|ohlc|volume]\n"
        "      events(default):  [-type all|trade|market|targeted|order|update|cancel] [-limit <N>] [-offset <N>]\n"
        "      summary:          [-type all|trade|market|targeted|order|update|cancel] [-limit <N>] [-offset <N>]\n"
        "      ohlc:            [-type market|trade] [-bucket <sec>] [-fill]\n"
        "      volume:          [-type market|targeted|trade] [-bucket <sec> [-fill]]\n"
        "    Timestamp <ts>: unix | RFC822 | now | -30m | -1h | -2d\n"
        "    -fill without -bucket uses history_bucket_sec\n"
        // === Trading ===
        "srv_dex purchase -net <net_name> -order <hash> -w <wallet> -value <amount> -fee <fee>\n"
        "    [-unit sell|buy] [-create_leftover_order [-leftover_rate <rate>]]\n"
        "srv_dex purchase_multi -net <net_name> -orders <hash1,hash2,...> -w <wallet> -value <amount> -fee <fee>\n"
        "    [-unit sell|buy] [-create_leftover_order [-leftover_rate <rate>]]\n"
        "srv_dex purchase_auto -net <net_name> -token_sell <ticker> -token_buy <ticker>\n"
        "    -w <wallet> -value <amount> -fee <fee>\n"
        "    [-unit sell|buy] [-rate_cap <price>] [-create_leftover_order [-leftover_rate <rate>]] [-dry-run]\n"
        "srv_dex cancel_all_by_seller -net <net_name> -pair <BASE/QUOTE> -seller <addr>\n"
        "    -w <wallet> -fee <fee> [-limit <N>] [-dry-run]\n"
        // === Migration ===
        "srv_dex migrate -net <net_name> -from <tx> -rate <price> -fee <fee> -w <wallet>\n"
        // === Governance ===
        "srv_dex decree -net <net_name> -w <wallet> -service_key <cert> -fee <fee>\n"
        "    -method fee_set|pair_add|pair_remove|pair_fee_set|pair_fee_set_all\n"
        "      fee_set:         -fee_amount <amount> -fee_addr <addr>\n"
        "      pair_add:        -token_base <ticker> -token_quote <ticker>\n"
        "                       [-net_base <net>] [-net_quote <net>] [<fee_opt>]\n"
        "      pair_remove:     -token_base <ticker> -token_quote <ticker>\n"
        "                       [-net_base <net>] [-net_quote <net>]\n"
        "      pair_fee_set:    -token_base <ticker> -token_quote <ticker>\n"
        "                       [-net_base <net>] [-net_quote <net>] <fee_opt>\n"
        "      pair_fee_set_all: <fee_opt>\n"
        "    <fee_opt>: -fee_pct <pct> | -fee_native <amount> | -fee_config <byte>\n"
        "               -fee_pct 2.0 = 2%% of INPUT, -fee_native 0.05 = 0.05 native\n");
    return 0;
}

void dap_chain_net_srv_dex_deinit()
{
    pthread_rwlock_wrlock(&s_dex_cache_rwlock);

    // Free orders cache (also cleans up pair/seller indices via back-pointers)
    /*dex_order_cache_entry_t *e_it, *e_tmp;
    HASH_ITER(level.hh, s_dex_orders_cache, e_it, e_tmp)
    {
        s_dex_indexes_remove(e_it); // Removes from tail, pair, seller indices
        HASH_DELETE(level.hh, s_dex_orders_cache, e_it);
        DAP_DELETE(e_it);
    }

    // Cleanup pair whitelist (managed by decrees, persists independent of hot cache)
    dex_pair_index_t *pb_it, *pb_tmp;
    HASH_ITER(hh, s_dex_pair_index, pb_it, pb_tmp)
    {
        HASH_DELETE(hh, s_dex_pair_index, pb_it);
        DAP_DELETE(pb_it);
    }
    dex_seller_index_t *sb_it, *sb_tmp;
    HASH_ITER(hh, s_dex_seller_index, sb_it, sb_tmp)
    {
        HASH_DELETE(hh, s_dex_seller_index, sb_it);
        DAP_DELETE(sb_it);
    }*/
    s_dex_pair_index_remove(NULL);

    // Free history cache (buckets, trades, seller index, pairs)
    dex_hist_pair_t *hp_it, *hp_tmp;
    HASH_ITER(hh, s_dex_history, hp_it, hp_tmp)
    {
        // Free per-pair buckets and trades
        dex_hist_bucket_t *b_it, *b_tmp;
        HASH_ITER(hh, hp_it->buckets, b_it, b_tmp)
        {
            dex_event_rec_t *tr_it, *tr_tmp;
            HASH_ITER(hh, b_it->events_idx, tr_it, tr_tmp)
            {
                HASH_DELETE(hh, b_it->events_idx, tr_it);
                DAP_DELETE(tr_it);
            }
            HASH_DELETE(hh, hp_it->buckets, b_it);
            DAP_DELETE(b_it);
        }
        // Free trader indices (unified structure may be in both seller and buyer hashes)
        dex_hist_trader_idx_t *ti_it, *ti_tmp;
        HASH_ITER(hh_seller, hp_it->seller_idx, ti_it, ti_tmp)
        {
            HASH_DELETE(hh_seller, hp_it->seller_idx, ti_it);
            // Remove from buyer hash too if present, then free
            dex_hist_trader_idx_t *l_buyer_it = NULL;
            HASH_FIND(hh_buyer, hp_it->buyer_idx, &ti_it->addr, sizeof(dap_chain_addr_t), l_buyer_it);
            if (l_buyer_it)
                HASH_DELETE(hh_buyer, hp_it->buyer_idx, l_buyer_it);
            DAP_DELETE(ti_it);
        }
        // Free remaining buyer-only entries
        HASH_ITER(hh_buyer, hp_it->buyer_idx, ti_it, ti_tmp)
        {
            HASH_DELETE(hh_buyer, hp_it->buyer_idx, ti_it);
            DAP_DELETE(ti_it);
        }
        // Free order index
        dex_hist_order_idx_t *oi_it, *oi_tmp;
        HASH_ITER(hh, hp_it->order_idx, oi_it, oi_tmp)
        {
            HASH_DELETE(hh, hp_it->order_idx, oi_it);
            DAP_DELETE(oi_it);
        }
        HASH_DELETE(hh, s_dex_history, hp_it);
        DAP_DELETE(hp_it);
    }
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    pthread_rwlock_destroy(&s_dex_cache_rwlock);
}

/* ============================================================================
 * Ledger Notifications
 * TX classification, cache/history update on ledger commits
 * ============================================================================ */

/*
 * s_dex_tx_classify
 * -----------------
 * Classify DEX transaction type for post-commit notifier (cache/history maintenance).
 *
 * Classification logic:
 *  - If OUT_COND present → type from OUT_COND (ORDER/EXCHANGE/UPDATE)
 *  - If no OUT_COND but has IN_COND:
 *    - If seller payout exists in non-owner TX → EXCHANGE (full execution)
 *    - Otherwise → INVALIDATE (order cancellation)
 *  - If neither → UNDEFINED (not a DEX tx)
 */
static dex_tx_type_t s_dex_tx_classify(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_in_cond_t **a_in_cond,
                                       dap_chain_tx_out_cond_t **a_out_cond, int *a_out_idx)
{
    int l_out_idx = 0;
    dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
    if (a_out_cond)
        *a_out_cond = l_out;
    if (a_out_idx)
        *a_out_idx = l_out_idx;
    // Fast-path: OUT_COND fully defines TX type; skip IN_COND scan unless caller explicitly requested first DEX IN_COND
    if (l_out && !a_in_cond)
        return (dex_tx_type_t)l_out->subtype.srv_dex.tx_type;

    dap_chain_tx_in_cond_t *l_in0 = NULL;
    dap_chain_tx_out_cond_t *l_prev_cond = NULL;
    byte_t *it;
    size_t sz;
    // Find first IN_COND that actually spends SRV_DEX OUT_COND
    TX_ITEM_ITER_TX(it, sz, a_tx) if (*it == TX_ITEM_TYPE_IN_COND)
    {
        dap_chain_tx_in_cond_t *l_in = (dap_chain_tx_in_cond_t *)it;
        dap_chain_datum_tx_t *l_prev = dap_ledger_tx_find_by_hash(a_ledger, &l_in->header.tx_prev_hash);
        int l_prev_dex_idx = 0;
        dap_chain_tx_out_cond_t *l_cond =
            l_prev ? dap_chain_datum_tx_out_cond_get(l_prev, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_dex_idx) : NULL;
        if (l_cond && (int)l_in->header.tx_out_prev_idx == l_prev_dex_idx) {
            l_in0 = l_in;
            l_prev_cond = l_cond;
            break;
        }
    }
    if (a_in_cond)
        *a_in_cond = l_in0;

    return l_out    ? (dex_tx_type_t)l_out->subtype.srv_dex.tx_type
           : !l_in0 ? DEX_TX_TYPE_UNDEFINED
           // TODO: Classification depends on owner signature check (first SIG). Revisit for multi-sign changes.
           : s_dex_verify_payout(a_tx, a_ledger->net, l_prev_cond->subtype.srv_dex.buy_token, &l_prev_cond->subtype.srv_dex.seller_addr)
               ? DEX_TX_TYPE_EXCHANGE
               : DEX_TX_TYPE_INVALIDATE;
}

typedef struct dex_bq {
    uint256_t base, quote;
} dex_bq_t;

static inline dex_bq_t s_exec_to_canon_base_quote(uint256_t a_exec, uint256_t a_rate, uint8_t a_side)
{
    dex_bq_t l_bq = {};
    if (a_side == DEX_SIDE_ASK) {
        l_bq.base = a_exec;
        MULT_256_COIN(l_bq.base, a_rate, &l_bq.quote);
    } else {
        l_bq.quote = a_exec;
        DIV_256_COIN(l_bq.quote, a_rate, &l_bq.base);
    }
    return l_bq;
}

static char *s_dex_tx_put(dap_chain_datum_tx_t *a_tx, dap_chain_net_t *a_net)
{
    char *l_ret = NULL;
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, a_tx, l_tx_size);
    DAP_DELETE(a_tx);
    if (!l_datum)
        return log_it(L_ERROR, "Failed to create datum"), NULL;
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    if (l_chain)
        l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    return l_ret;
}

/*
 * s_calc_executed_amount
 * ----------------------
 * Calculate actual executed amount for an order, accounting for seller residual.
 * If this is the first IN with residual (root matches) → subtract leftover from order value.
 */
static inline uint256_t s_calc_executed_amount(uint256_t a_order_value, bool a_is_first_in, bool a_is_residual_update,
                                               const dap_hash_fast_t *a_order_root, const dap_hash_fast_t *a_residual_root,
                                               uint256_t a_residual_value)
{
    uint256_t l_executed = a_order_value;
    if (a_is_first_in && a_is_residual_update && dap_hash_fast_compare(a_order_root, a_residual_root) &&
        compare256(a_order_value, a_residual_value) > 0)
        SUBTRACT_256_256(a_order_value, a_residual_value, &l_executed);
    return l_executed;
}

/*
 * dex_history_append_event
 * Lite version: stores DEX event record in daily bucket and seller index.
 * OHLCV is computed on-the-fly during queries, not stored in buckets.
 *
 * - a_key: canonical pair key (BASE/QUOTE)
 * - a_ts: event timestamp (blockchain time)
 * - a_price_q_per_b: QUOTE/BASE price in canonical terms
 * - a_qty_base / a_qty_quote: event amounts (trade executed or order value/remaining)
 * - a_tx_hash / a_prev_tail: unique key for idempotency and reorg deletes
 * - a_order_root: order root hash for filtering by order
 * - a_seller_addr: seller address for seller index (optional)
 * - a_buyer_addr: buyer (taker) address
 * - a_flags: DEX_TRADE_FLAG_* classification
 * - a_side: DEX_SIDE_ASK or DEX_SIDE_BID (seller's side)
 */
static void s_dex_history_append(dap_ledger_t *a_ledger, const dex_pair_key_t *a_pair, uint64_t a_ts, uint256_t a_rate, uint256_t a_base,
                                 uint256_t a_quote, dap_hash_fast_t *a_tx_hash, dap_hash_fast_t *a_prev_hash,
                                 const dap_hash_fast_t *a_order_root, const dap_chain_addr_t *a_seller_addr,
                                 const dap_chain_addr_t *a_buyer_addr, uint8_t a_flags, uint8_t a_side)
{
    if ((a_pair->net_id_quote.uint64 != a_ledger->net->pub.id.uint64) || (a_pair->net_id_base.uint64 != a_ledger->net->pub.id.uint64)) {
        switch (s_cross_net_policy) {
        case CROSS_NET_REJECT:
            log_it(L_ERROR, "%s(): Cross-net trades are not allowed, skip tx %s, %s #%" DAP_UINT64_FORMAT_x " / %s #%" DAP_UINT64_FORMAT_U,
                   __FUNCTION__, a_pair->token_base, dap_hash_fast_to_str_static(a_tx_hash), a_pair->net_id_base.uint64,
                   a_pair->token_quote, a_pair->net_id_quote.uint64);
            return;
        case CROSS_NET_WARN:
            log_it(L_WARNING, "%s(): Cross-net trade %s #%" DAP_UINT64_FORMAT_x " / %s #%" DAP_UINT64_FORMAT_U, __FUNCTION__,
                   a_pair->token_base, a_pair->net_id_base.uint64, a_pair->token_quote, a_pair->net_id_quote.uint64);
        default:
            break;
        }
    }

    dex_hist_pair_t *l_pair = s_hist_pair_get_or_create(a_pair);
    if (!l_pair)
        return log_it(L_ERROR, "%s(): Can't create historical pair %s / %s index!", __FUNCTION__, a_pair->token_base, a_pair->token_quote);

    uint64_t l_ts = s_hist_bucket_ts(a_ts, s_dex_history_bucket_sec);
    dex_hist_bucket_t *l_bucket = NULL;
    HASH_FIND(hh, l_pair->buckets, &l_ts, sizeof(l_ts), l_bucket);

    if (l_bucket) {
        // Idempotency guard
        dex_event_key_t l_key = {.tx_hash = *a_tx_hash, .prev_tail = a_prev_hash ? *a_prev_hash : (dap_hash_fast_t){}};
        dex_event_rec_t *l_exists = NULL;
        HASH_FIND(hh, l_bucket->events_idx, &l_key, sizeof(l_key), l_exists);
        if (l_exists) {
            debug_if(s_debug_more, L_DEBUG, "%s(): Event already exists, skip tx %s", __FUNCTION__, dap_hash_fast_to_str_static(a_tx_hash));
            return;
        }
    } else {
        l_bucket = DAP_NEW_Z_RET_IF_FAIL(dex_hist_bucket_t);
        l_bucket->ts = l_ts;
        HASH_ADD(hh, l_pair->buckets, ts, sizeof(l_bucket->ts), l_bucket);
    }
    // Add event record to bucket and seller index
    dex_event_rec_t *l_rec = DAP_NEW_Z_RET_IF_FAIL(dex_event_rec_t);
    *l_rec = (dex_event_rec_t){.key = {.tx_hash = *a_tx_hash, .prev_tail = a_prev_hash ? *a_prev_hash : (dap_hash_fast_t){}},
                               .ts = a_ts,
                               .flags = a_flags,
                               .side = a_side};
    if (a_flags & (DEX_OP_CREATE | DEX_OP_UPDATE | DEX_OP_CANCEL))
        l_rec->val_b_remain = a_base;
    else
        l_rec->trade_b = a_base;
    dex_hist_order_idx_t *l_oi = s_hist_indexes_append(l_bucket, l_pair, l_rec, a_seller_addr, a_buyer_addr, a_order_root, a_rate);
    if (l_oi)
        l_rec->filled_pct = s_hist_calc_fill_pct(l_oi, l_rec);
    debug_if(s_debug_more, L_DEBUG, "%s(): Added %s event %s, type: %s, pair: %s/%s @ %s, value: %s, seller: %s", __FUNCTION__,
             a_side == DEX_SIDE_ASK ? "ASK" : "BID", dap_hash_fast_to_str_static(a_tx_hash), s_dex_op_flags_to_str(a_flags),
             a_pair->token_base, a_pair->token_quote, dap_uint256_to_char_ex(a_rate).frac, dap_uint256_to_char_ex(a_base).frac,
             a_seller_addr ? dap_chain_addr_to_str_static(a_seller_addr) : "(none)");
}

/*
 * s_ledger_tx_add_notify_dex
 * ---------------------------
 * Post-commit/reorg notifier for SRV_DEX.
 *
 * Responsibilities:
 *  - Maintain order cache: add fresh orders, remove spent, update seller residual on the first IN
 *  - Maintain trade history buckets: append on commit, rollback on reorg
 *
 * Classification & policy:
 *  - Type comes from s_dex_tx_classify() (ORDER / EXCHANGE / UPDATE / UNDEFINED)
 *  - Buyer-leftover: EXCHANGE with blank root → creates fresh order (root=tail=a_tx_hash)
 *  - Seller residual: UPDATE with non-blank root → only first IN can carry residual
 *  - When history is enabled but cache is disabled/missed, derive previous order state from ledger
 */
static void s_ledger_tx_add_notify_dex(void *UNUSED_ARG a_arg, dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,
                                       dap_hash_fast_t *a_tx_hash, dap_chan_ledger_notify_opcodes_t a_opcode, dap_hash_fast_t *a_atom_hash)
{
    if (a_opcode != 'a' && a_opcode != 'd')
        return;
    dap_chain_tx_in_cond_t *l_in_cond = NULL;
    dap_chain_tx_out_cond_t *l_out_cond = NULL;
    int l_out_idx = 0;
    dex_tx_type_t l_tx_type = s_dex_tx_classify(a_ledger, a_tx, &l_in_cond, &l_out_cond, &l_out_idx);
    if (l_tx_type == DEX_TX_TYPE_UNDEFINED)
        return;
    // Block-aware snapshot: update snapshots when atom changes (for accurate market/targeted classification)
    // Thread-local to avoid cross-net interference in multi-threaded scenarios
    static _Thread_local struct {
        dap_hash_fast_t atom;
        dap_chain_net_id_t net_id;
    } s_current_block = {};
    dap_chain_net_id_t l_net_id = a_ledger->net->pub.id;
    bool l_new_block = a_atom_hash && !dap_hash_fast_is_blank(a_atom_hash) &&
                       (!dap_hash_fast_compare(&s_current_block.atom, a_atom_hash) || s_current_block.net_id.uint64 != l_net_id.uint64);
    if (l_new_block) {
        // New block detected: snapshot current best prices for all pairs BEFORE processing this block's transactions
        pthread_rwlock_wrlock(&s_dex_cache_rwlock);
        dex_pair_index_t *l_pair, *l_tmp;
        int l_snap_count = 0;
        HASH_ITER(hh, s_dex_pair_index, l_pair, l_tmp)
        {
            l_pair->snapshot_best_ask = l_pair->asks ? l_pair->asks->level.match.rate : uint256_0;
            l_pair->snapshot_best_bid = l_pair->bids ? l_pair->bids->level.match.rate : uint256_0;
            l_snap_count++;
            debug_if(s_debug_more, L_DEBUG, "%s(): Snapshot pair %s/%s: best ask: %s; best bid: %s", __FUNCTION__, l_pair->key.token_base,
                     l_pair->key.token_quote, dap_uint256_to_char_ex(l_pair->snapshot_best_ask).frac,
                     dap_uint256_to_char_ex(l_pair->snapshot_best_bid).frac);
        }
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
        s_current_block.atom = *a_atom_hash;
        s_current_block.net_id = l_net_id;
        debug_if(s_debug_more, L_DEBUG, "%s(): Updated snapshot with %d pair%s for new block %s", __FUNCTION__, l_snap_count,
                 l_snap_count > 1 ? "s" : "", dap_hash_fast_to_str_static(a_atom_hash));
    }

    switch (l_tx_type) {
    case DEX_TX_TYPE_ORDER: {
        // Get pair info for best price update
        const char *l_sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tx_hash);
        dex_pair_key_t l_key = {};
        uint8_t l_side = 0;
        uint256_t l_price_canon = uint256_0;
        s_dex_pair_normalize(l_sell_ticker, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                             l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key, &l_side, &l_price_canon);

        pthread_rwlock_wrlock(&s_dex_cache_rwlock);
        if (s_dex_cache_enabled) {
            // Cache operations update best_ask/best_bid via s_dex_indexes_*
            a_opcode == 'a'
                ? s_dex_cache_upsert(a_ledger, l_sell_ticker, a_tx_hash, a_tx_hash, l_out_cond, l_out_idx, a_tx->header.ts_created, "new")
                : s_dex_cache_remove_by_root(a_tx_hash);
        }
        if (s_dex_history_enabled) {
            dap_hash_fast_t l_blank = {};
            if (a_opcode == 'a') {
                dex_bq_t l_bq = s_exec_to_canon_base_quote(l_out_cond->header.value, l_price_canon, l_side);
                s_dex_history_append(a_ledger, &l_key, a_tx->header.ts_created, l_price_canon, l_bq.base, l_bq.quote, a_tx_hash, &l_blank,
                                     a_tx_hash, &l_out_cond->subtype.srv_dex.seller_addr, NULL, DEX_OP_CREATE, l_side);
            } else {
                uint64_t l_bts = s_hist_bucket_ts(a_tx->header.ts_created, s_dex_history_bucket_sec);
                dex_hist_pair_t *l_pair = NULL;
                HASH_FIND(hh, s_dex_history, &l_key, DEX_PAIR_KEY_CMP_SIZE, l_pair);
                if (l_pair) {
                    dex_hist_bucket_t *l_bucket = NULL;
                    HASH_FIND(hh, l_pair->buckets, &l_bts, sizeof(l_bts), l_bucket);
                    if (l_bucket)
                        s_hist_indexes_remove(l_pair, l_bucket, a_tx_hash, &l_blank);
                }
            }
        }
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
        break;
    }
    default: {
        pthread_rwlock_wrlock(&s_dex_cache_rwlock);
        if (a_opcode == 'a') {
            const char *l_prev0_sell_token = NULL, *l_prev0_buy_token = NULL;
            // Residual update context:
            //  - non-blank root in OUT means seller's leftover should persist under the original root
            //  - per protocol, residual is allowed only for the first IN in the TX
            bool l_residual_update = l_out_cond && !dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash);
            dap_hash_fast_t l_residual_root = l_residual_update ? l_out_cond->subtype.srv_dex.order_root_hash : (dap_hash_fast_t){};
            // l_prev0_* will be filled on first IN iteration (no separate lookup needed)
            int l_in_idx = 0;
            uint8_t l_last_event_flags = 0; // for buyer-leftover history
            // Snapshot best prices BEFORE processing: for market/targeted classification in multi-purchase
            // All trades in same TX should be classified against the ORIGINAL orderbook state
            uint256_t l_best_ask = uint256_0, l_best_bid = uint256_0;
            dex_pair_index_t *l_pair_idx = NULL; // will be set on first IN

            // Pre-scan: count DEX IN_CONDs per side and compute ranks for strict position-based classification
            // For multi-purchase MARKET: each order must be in top-N of orderbook (N = count of same-side INs)
            // Ranks are computed here BEFORE any orders are removed from cache during main loop
            typedef struct {
                dap_hash_fast_t tail;
                int rank;
            } dex_order_rank_t;
            static const UT_icd s_order_rank_icd = {sizeof(dex_order_rank_t), NULL, NULL, NULL};
            UT_array *l_order_ranks = NULL;
            int l_ask_in_count = 0, l_bid_in_count = 0;
            byte_t *it;
            size_t sz;
            if (s_dex_history_enabled && l_tx_type == DEX_TX_TYPE_EXCHANGE) {
                utarray_new(l_order_ranks, &s_order_rank_icd);
                TX_ITEM_ITER_TX(it, sz, a_tx) if (*it == TX_ITEM_TYPE_IN_COND)
                {
                    dap_chain_tx_in_cond_t *l_pre_in = (dap_chain_tx_in_cond_t *)it;
                    // Verify this IN_COND spends a DEX OUT_COND (not FEE or other service)
                    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_pre_in->header.tx_prev_hash);
                    if (!l_prev_tx)
                        continue;
                    byte_t *l_prev_out = dap_chain_datum_tx_out_get_by_out_idx(l_prev_tx, l_pre_in->header.tx_out_prev_idx);
                    dap_chain_tx_out_cond_t *l_prev_out_cond =
                        (l_prev_out && *l_prev_out == TX_ITEM_TYPE_OUT_COND) ? (dap_chain_tx_out_cond_t *)l_prev_out : NULL;
                    if (!l_prev_out_cond || l_prev_out_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX)
                        continue;
                    // Determine side from prev OUT_COND for counting
                    const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_pre_in->header.tx_prev_hash);
                    dex_pair_key_t l_pre_key = {};
                    uint8_t l_pre_side = 0;
                    uint256_t l_pre_price = {};
                    if (l_sell_tok)
                        s_dex_pair_normalize(l_sell_tok, l_prev_out_cond->subtype.srv_dex.sell_net_id,
                                             l_prev_out_cond->subtype.srv_dex.buy_token, l_prev_out_cond->subtype.srv_dex.buy_net_id,
                                             l_prev_out_cond->subtype.srv_dex.rate, &l_pre_key, &l_pre_side, &l_pre_price);
                    else
                        continue; // can't determine side without sell token
                    // Count by side
                    if (l_pre_side == DEX_SIDE_ASK)
                        l_ask_in_count++;
                    else
                        l_bid_in_count++;
                    // Cache lookup for rank computation (rank requires orderbook from cache)
                    const dex_order_cache_entry_t *l_pre_e = NULL;
                    if (s_dex_cache_enabled)
                        HASH_FIND(level.hh_tail, s_dex_index_by_tail, &l_pre_in->header.tx_prev_hash, sizeof(dap_hash_fast_t), l_pre_e);
                    if (l_pre_e && l_pre_e->level.match.prev_idx >= 0 &&
                        (int)l_pre_in->header.tx_out_prev_idx == l_pre_e->level.match.prev_idx) {
                        if (!l_pair_idx) {
                            l_pair_idx = (dex_pair_index_t *)l_pre_e->pair_key_ptr;
                            l_best_ask = l_pair_idx->snapshot_best_ask;
                            l_best_bid = l_pair_idx->snapshot_best_bid;
                        }
                        // Compute rank (position in orderbook) for this order
                        if (l_pair_idx) {
                            dex_order_cache_entry_t *l_ob_head = (l_pre_side == DEX_SIDE_ASK) ? l_pair_idx->asks : l_pair_idx->bids, *l_e,
                                                    *l_tmp;
                            int l_rank = 0;
                            HASH_ITER(hh_pair_bucket, l_ob_head, l_e, l_tmp)
                            {
                                l_rank++;
                                if (dap_hash_fast_compare(&l_e->level.match.tail, &l_pre_in->header.tx_prev_hash)) {
                                    dex_order_rank_t l_rank_entry = {.tail = l_pre_in->header.tx_prev_hash, .rank = l_rank};
                                    utarray_push_back(l_order_ranks, &l_rank_entry);
                                    debug_if(s_debug_more, L_DEBUG, "%s(): Pre-computed %s %s rank: %d", __FUNCTION__,
                                             l_pre_side == DEX_SIDE_ASK ? "ASK" : "BID",
                                             dap_hash_fast_to_str_static(&l_pre_in->header.tx_prev_hash), l_rank);
                                    break;
                                }
                            }
                        }
                    }
                }
                debug_if(s_debug_more && (l_ask_in_count + l_bid_in_count) > 1, L_DEBUG,
                         "%s(): Tx %s is multi-purchase: %d ASK IN%s, %d BID IN%s", __FUNCTION__, dap_hash_fast_to_str_static(a_tx_hash),
                         l_ask_in_count, l_ask_in_count > 1 ? "s" : "", l_bid_in_count, l_bid_in_count > 1 ? "s" : "");
            }
            TX_ITEM_ITER_TX(it, sz, a_tx) if (*it == TX_ITEM_TYPE_IN_COND)
            {
                dap_chain_tx_in_cond_t *l_in_cond_it = (dap_chain_tx_in_cond_t *)it;
                dap_hash_fast_t l_prev_hash = l_in_cond_it->header.tx_prev_hash;

                // Cache lookup by tail
                const dex_order_cache_entry_t *e = NULL;
                if (s_dex_cache_enabled)
                    HASH_FIND(level.hh_tail, s_dex_index_by_tail, &l_prev_hash, sizeof(l_prev_hash), e);
                // Skip if IN_COND doesn't spend DEX OUT (e.g., FEE collection tx)
                if (e && e->level.match.prev_idx >= 0 && (int)l_in_cond_it->header.tx_out_prev_idx != e->level.match.prev_idx)
                    e = NULL;

                if (e) {
                    // First IN: extract tokens for buyer-leftover determination
                    if (l_in_idx == 0) {
                        if (!l_pair_idx && e->pair_key_ptr) {
                            l_pair_idx = (dex_pair_index_t *)e->pair_key_ptr;
                            l_best_ask = l_pair_idx->snapshot_best_ask;
                            l_best_bid = l_pair_idx->snapshot_best_bid;
                        }
                        if ((e->side_version & 0x1) == DEX_SIDE_BID) {
                            l_prev0_sell_token = e->pair_key_ptr->token_quote;
                            l_prev0_buy_token = e->pair_key_ptr->token_base;
                        } else {
                            l_prev0_sell_token = e->pair_key_ptr->token_base;
                            l_prev0_buy_token = e->pair_key_ptr->token_quote;
                        }
                        debug_if(s_debug_more, L_DEBUG, "%s(): Snapshot tx %s: pair %s/%s best ask: %s, best bid: %s", __FUNCTION__,
                                 dap_hash_fast_to_str_static(a_tx_hash), l_pair_idx ? l_pair_idx->key.token_base : "?",
                                 l_pair_idx ? l_pair_idx->key.token_quote : "?", dap_uint256_to_char_ex(l_best_ask).frac,
                                 dap_uint256_to_char_ex(l_best_bid).frac);
                    }
                    if (s_dex_history_enabled && l_tx_type == DEX_TX_TYPE_EXCHANGE) {
                        // Verify actual trade: seller must receive buy_token (UPDATE returns sell_token instead)
                        uint8_t l_side = e->side_version & 0x1;
                        const char *l_sell_tok = (l_side == DEX_SIDE_BID) ? e->pair_key_ptr->token_quote : e->pair_key_ptr->token_base;
                        const char *l_buy_tok = (l_side == DEX_SIDE_BID) ? e->pair_key_ptr->token_base : e->pair_key_ptr->token_quote;
                        if (e->seller_addr_ptr && s_dex_verify_payout(a_tx, a_ledger->net, l_buy_tok, e->seller_addr_ptr)) {
                            // Calculate executed amount (for full execution, entire order value is executed)
                            uint256_t l_residual_val = l_out_cond ? l_out_cond->header.value : uint256_0;
                            uint256_t l_executed_i = s_calc_executed_amount(e->level.match.value, l_in_idx == 0, l_residual_update,
                                                                            &e->level.match.root, &l_residual_root, l_residual_val);
                            // Dust refund: OUT_STD to seller in sell_token on full-close
                            if (!l_out_cond && l_in_idx == 0 && e->seller_addr_ptr) {
                                uint256_t l_srv_fee_req = uint256_0;
                                const dap_chain_addr_t *l_srv_addr_ptr = NULL;
                                if (l_sell_tok && !dap_strcmp(l_sell_tok, a_ledger->net->pub.native_ticker) &&
                                    dap_chain_addr_compare(e->seller_addr_ptr, &s_dex_service_fee_addr)) {
                                    l_srv_fee_req = s_dex_get_srv_fee(e->pair_key_ptr->fee_config);
                                    if (!IS_ZERO_256(l_srv_fee_req))
                                        l_srv_addr_ptr = &s_dex_service_fee_addr;
                                }
                                s_adjust_exec_for_dust_refund(a_tx, e->seller_addr_ptr, l_sell_tok, l_srv_addr_ptr, l_srv_fee_req,
                                                              &l_executed_i);
                            }
                            dex_bq_t l_bq = s_exec_to_canon_base_quote(l_executed_i, e->level.match.rate, l_side);
                            // Strict classification: for multi-purchase, use pre-computed ranks
                            // MARKET only if order is in top-N (N = count of same-side INs in this tx)
                            uint256_t l_best = (l_side == DEX_SIDE_ASK) ? l_best_ask : l_best_bid;
                            int l_side_in_count = (l_side == DEX_SIDE_ASK) ? l_ask_in_count : l_bid_in_count;
                            uint8_t l_flags = DEX_OP_TARGET;
                            if (l_side_in_count <= 1) {
                                // Single purchase: standard classification
                                l_flags = s_dex_trade_classify(e->level.match.rate, l_best, l_side);
                            } else {
                                // Multi-purchase: lookup pre-computed rank from pre-scan
                                int l_found_rank = 0;
                                for (unsigned i = 0; i < utarray_len(l_order_ranks); i++) {
                                    dex_order_rank_t *l_r = (dex_order_rank_t *)utarray_eltptr(l_order_ranks, i);
                                    if (dap_hash_fast_compare(&l_r->tail, &l_prev_hash)) {
                                        l_found_rank = l_r->rank;
                                        l_flags = (l_found_rank <= l_side_in_count) ? DEX_OP_MARKET : DEX_OP_TARGET;
                                        break;
                                    }
                                }
                                debug_if(s_debug_more, L_DEBUG, "%s(): Multi-trade %s classify: rank %d/%d → %s", __FUNCTION__,
                                         dap_hash_fast_to_str_static(&l_prev_hash), l_found_rank, l_side_in_count,
                                         (l_flags & DEX_OP_MARKET) ? "MARKET" : "TARGETED");
                            }
                            debug_if(s_debug_more, L_DEBUG, "%s(): Trade %s %s @ %s → %s", __FUNCTION__,
                                     dap_hash_fast_to_str_static(a_tx_hash), l_side == DEX_SIDE_ASK ? "ASK" : "BID",
                                     dap_uint256_to_char_ex(e->level.match.rate).frac, (l_flags & DEX_OP_MARKET) ? "MARKET" : "TARGETED");
                            dap_chain_addr_t l_buyer = s_dex_extract_buyer_addr(a_tx, a_ledger->net->pub.id);
                            s_dex_history_append(a_ledger, e->pair_key_ptr, a_tx->header.ts_created, e->level.match.rate, l_bq.base,
                                                 l_bq.quote, a_tx_hash, &l_prev_hash, &e->level.match.root, e->seller_addr_ptr, &l_buyer,
                                                 l_flags, l_side);
                            l_last_event_flags = l_flags;
                        }
                    }
                } else if (s_dex_history_enabled) {
                    dap_chain_datum_tx_t *l_tx_i = dap_ledger_tx_find_by_hash(a_ledger, &l_prev_hash);
                    int l_prev_dex_idx = 0;
                    dap_chain_tx_out_cond_t *l_prev_cond_i =
                        l_tx_i ? dap_chain_datum_tx_out_cond_get(l_tx_i, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_dex_idx) : NULL;
                    const char *l_sell_ticker = l_prev_cond_i ? dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_prev_hash) : NULL;

                    // History for UPDATE/CANCELLED on cache miss (cache hit is recorded below in cache maintenance)
                    if (l_tx_type == DEX_TX_TYPE_INVALIDATE || l_tx_type == DEX_TX_TYPE_UPDATE) {
                        if (l_prev_cond_i && l_sell_ticker && (int)l_in_cond_it->header.tx_out_prev_idx == l_prev_dex_idx) {
                            dex_pair_key_t l_key = {};
                            uint8_t l_side = 0;
                            uint256_t l_price_canon = uint256_0;
                            dap_hash_fast_t l_order_root = dap_hash_fast_is_blank(&l_prev_cond_i->subtype.srv_dex.order_root_hash)
                                                               ? l_prev_hash
                                                               : l_prev_cond_i->subtype.srv_dex.order_root_hash;
                            if (l_tx_type == DEX_TX_TYPE_INVALIDATE) {
                                s_dex_pair_normalize(l_sell_ticker, l_prev_cond_i->subtype.srv_dex.sell_net_id,
                                                     l_prev_cond_i->subtype.srv_dex.buy_token, l_prev_cond_i->subtype.srv_dex.buy_net_id,
                                                     l_prev_cond_i->subtype.srv_dex.rate, &l_key, &l_side, &l_price_canon);
                                dex_bq_t l_bq = s_exec_to_canon_base_quote(l_prev_cond_i->header.value, l_price_canon, l_side);
                                s_dex_history_append(a_ledger, &l_key, a_tx->header.ts_created, l_price_canon, l_bq.base, l_bq.quote,
                                                     a_tx_hash, &l_prev_hash, &l_order_root, &l_prev_cond_i->subtype.srv_dex.seller_addr,
                                                     NULL, DEX_OP_CANCEL, l_side);
                            } else if (l_out_cond) {
                                // UPDATE: record new price/value from OUT_COND
                                s_dex_pair_normalize(l_sell_ticker, l_out_cond->subtype.srv_dex.sell_net_id,
                                                     l_out_cond->subtype.srv_dex.buy_token, l_out_cond->subtype.srv_dex.buy_net_id,
                                                     l_out_cond->subtype.srv_dex.rate, &l_key, &l_side, &l_price_canon);
                                dex_bq_t l_bq = s_exec_to_canon_base_quote(l_out_cond->header.value, l_price_canon, l_side);
                                dap_hash_fast_t l_root_upd = dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash)
                                                                 ? l_order_root
                                                                 : l_out_cond->subtype.srv_dex.order_root_hash;
                                s_dex_history_append(a_ledger, &l_key, a_tx->header.ts_created, l_price_canon, l_bq.base, l_bq.quote,
                                                     a_tx_hash, &l_prev_hash, &l_root_upd, &l_prev_cond_i->subtype.srv_dex.seller_addr,
                                                     NULL, DEX_OP_UPDATE, l_side);
                            }
                        }
                    } else if (l_tx_type == DEX_TX_TYPE_EXCHANGE) {
                        // Fallback: derive previous order from ledger (heavier but necessary when cache disabled/missed)
                        // Verify actual trade: seller must receive buy_token (UPDATE returns sell_token instead)
                        if (l_sell_ticker && s_dex_verify_payout(a_tx, a_ledger->net, l_prev_cond_i->subtype.srv_dex.buy_token,
                                                                 &l_prev_cond_i->subtype.srv_dex.seller_addr)) {
                            // Calculate executed amount (for full execution, entire prev value is executed)
                            dap_hash_fast_t root_hash_i =
                                dap_ledger_get_first_chain_tx_hash(a_ledger, l_tx_i, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                            uint256_t l_residual_val = l_out_cond ? l_out_cond->header.value : uint256_0;
                            uint256_t executed_i = s_calc_executed_amount(l_prev_cond_i->header.value, l_in_idx == 0, l_residual_update,
                                                                          &root_hash_i, &l_residual_root, l_residual_val);
                            // Normalize pair and price to canonical units
                            dex_pair_key_t l_key = {};
                            uint8_t l_side = 0;
                            uint256_t l_price_canon = uint256_0;
                            s_dex_pair_normalize(l_sell_ticker, l_prev_cond_i->subtype.srv_dex.sell_net_id,
                                                 l_prev_cond_i->subtype.srv_dex.buy_token, l_prev_cond_i->subtype.srv_dex.buy_net_id,
                                                 l_prev_cond_i->subtype.srv_dex.rate, &l_key, &l_side, &l_price_canon);
                            dex_pair_index_t *l_pi = s_dex_pair_index_get(&l_key);
                            // First IN via ledger fallback: use SNAPSHOT of best prices for consistent classification
                            if (!l_pair_idx && l_pi && l_in_idx == 0) {
                                l_pair_idx = l_pi;
                                l_best_ask = l_pi->snapshot_best_ask;
                                l_best_bid = l_pi->snapshot_best_bid;
                                debug_if(s_debug_more, L_DEBUG, "%s(): Snapshot pair %s/%s: best ask: %s; best bid: %s", __FUNCTION__,
                                         l_pi->key.token_base, l_pi->key.token_quote, dap_uint256_to_char_ex(l_best_ask).frac,
                                         dap_uint256_to_char_ex(l_best_bid).frac);
                            }
                            // Dust refund: OUT_STD/EXT to seller in sell_token on full-close
                            if (!l_out_cond && l_in_idx == 0) {
                                uint256_t l_srv_fee_req = uint256_0;
                                const dap_chain_addr_t *l_srv_addr_ptr = NULL;
                                if (l_pi && !dap_strcmp(l_sell_ticker, a_ledger->net->pub.native_ticker) &&
                                    dap_chain_addr_compare(&l_prev_cond_i->subtype.srv_dex.seller_addr, &s_dex_service_fee_addr)) {
                                    l_srv_fee_req = s_dex_get_srv_fee(l_pi->key.fee_config);
                                    if (!IS_ZERO_256(l_srv_fee_req))
                                        l_srv_addr_ptr = &s_dex_service_fee_addr;
                                }
                                s_adjust_exec_for_dust_refund(a_tx, &l_prev_cond_i->subtype.srv_dex.seller_addr, l_sell_ticker,
                                                              l_srv_addr_ptr, l_srv_fee_req, &executed_i);
                            }
                            dex_bq_t l_bq = s_exec_to_canon_base_quote(executed_i, l_price_canon, l_side);
                            // Strict classification: for multi-purchase, check order's position in orderbook
                            uint8_t l_flags = DEX_OP_TARGET;
                            int l_side_in_count = (l_side == DEX_SIDE_ASK) ? l_ask_in_count : l_bid_in_count;
                            if (l_pair_idx) {
                                uint256_t l_best_snap = (l_side == DEX_SIDE_ASK) ? l_best_ask : l_best_bid;
                                if (l_side_in_count <= 1) {
                                    l_flags = s_dex_trade_classify(l_price_canon, l_best_snap, l_side);
                                } else {
                                    // Multi-purchase: lookup pre-computed rank from pre-scan
                                    int l_found_rank = 0;
                                    for (unsigned i = 0; i < utarray_len(l_order_ranks); i++) {
                                        dex_order_rank_t *l_r = (dex_order_rank_t *)utarray_eltptr(l_order_ranks, i);
                                        if (dap_hash_fast_compare(&l_r->tail, &l_prev_hash)) {
                                            l_found_rank = l_r->rank;
                                            l_flags = (l_found_rank <= l_side_in_count) ? DEX_OP_MARKET : DEX_OP_TARGET;
                                            break;
                                        }
                                    }
                                    debug_if(s_debug_more, L_DEBUG, "%s(): Multi-trade %s classify: rank %d/%d → %s", __FUNCTION__,
                                             dap_hash_fast_to_str_static(&l_prev_hash), l_found_rank, l_side_in_count,
                                             (l_flags & DEX_OP_MARKET) ? "MARKET" : "TARGETED");
                                }
                                debug_if(s_debug_more, L_DEBUG, "%s(): Trade %s %s @ %s → %s", __FUNCTION__,
                                         dap_hash_fast_to_str_static(a_tx_hash), l_side == DEX_SIDE_ASK ? "ASK" : "BID",
                                         dap_uint256_to_char_ex(l_price_canon).frac, (l_flags & DEX_OP_MARKET) ? "MARKET" : "TARGETED");
                            } else {
                                debug_if(s_debug_more, L_DEBUG, "%s(): Trade %s → TARGETED (no snapshot)", __FUNCTION__,
                                         dap_hash_fast_to_str_static(a_tx_hash));
                            }
                            dap_chain_addr_t l_buyer = s_dex_extract_buyer_addr(a_tx, a_ledger->net->pub.id);
                            dap_hash_fast_t l_order_root = dap_hash_fast_is_blank(&l_prev_cond_i->subtype.srv_dex.order_root_hash)
                                                               ? l_prev_hash
                                                               : l_prev_cond_i->subtype.srv_dex.order_root_hash;
                            s_dex_history_append(a_ledger, &l_key, a_tx->header.ts_created, l_price_canon, l_bq.base, l_bq.quote, a_tx_hash,
                                                 &l_prev_hash, &l_order_root, &l_prev_cond_i->subtype.srv_dex.seller_addr, &l_buyer,
                                                 l_flags, l_side);
                            l_last_event_flags = l_flags;
                        }
                    }
                }

                // Cache maintenance:
                //  - if residual on the first IN (non-blank root in OUT) — update order under original root
                //  - otherwise current tail is fully spent and must be removed from cache
                if (s_dex_cache_enabled) {
                    if (l_residual_update && l_in_idx == 0) {
                        // Seller-leftover or owner UPDATE: re-upsert under original root with new tail (current TX)
                        // Use cached ticker when available to avoid ledger lookup
                        const char *l_sell_ticker =
                            e ? (((e->side_version & 0x1) == DEX_SIDE_BID) ? e->pair_key_ptr->token_quote : e->pair_key_ptr->token_base)
                              : dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tx_hash);
                        if (e && !dap_hash_fast_compare(&e->level.match.root, &l_out_cond->subtype.srv_dex.order_root_hash))
                            log_it(L_WARNING, "%s(): Root mismatch on residual; Prev root: %s; OUT root: %s; Prev tail: %s; Tx: %s",
                                   __FUNCTION__, dap_hash_fast_to_str_static(&e->level.match.root),
                                   dap_hash_fast_to_str_static(&l_out_cond->subtype.srv_dex.order_root_hash),
                                   dap_hash_fast_to_str_static(&l_prev_hash), dap_hash_fast_to_str_static(a_tx_hash));
                        // Record UPDATE event in history (owner's price/value change)
                        if (s_dex_history_enabled && l_tx_type == DEX_TX_TYPE_UPDATE && e) {
                            uint8_t l_side = e->side_version & 0x1;
                            dex_pair_key_t l_key = {};
                            uint256_t l_new_price = uint256_0;
                            s_dex_pair_normalize(l_sell_ticker, l_out_cond->subtype.srv_dex.sell_net_id,
                                                 l_out_cond->subtype.srv_dex.buy_token, l_out_cond->subtype.srv_dex.buy_net_id,
                                                 l_out_cond->subtype.srv_dex.rate, &l_key, &l_side, &l_new_price);
                            dex_bq_t l_bq = s_exec_to_canon_base_quote(l_out_cond->header.value, l_new_price, l_side);
                            s_dex_history_append(a_ledger, e->pair_key_ptr, a_tx->header.ts_created, l_new_price, l_bq.base, l_bq.quote,
                                                 a_tx_hash, &l_prev_hash, &e->level.match.root, e->seller_addr_ptr, NULL, DEX_OP_UPDATE,
                                                 l_side);
                        }
                        s_dex_cache_upsert(a_ledger, l_sell_ticker, &l_out_cond->subtype.srv_dex.order_root_hash, a_tx_hash, l_out_cond,
                                           l_out_idx, a_tx->header.ts_created, "seller-leftover");
                    } else if (e) {
                        const char *l_reason = (l_tx_type == DEX_TX_TYPE_INVALIDATE) ? "cancelled"
                                               : (l_in_idx > 0)                      ? "consumed (multi-IN)"
                                                                                     : "fullfilled";
                        // Record cancellation event in history before removing from cache
                        if (s_dex_history_enabled && l_tx_type == DEX_TX_TYPE_INVALIDATE) {
                            uint8_t l_side = e->side_version & 0x1;
                            dex_bq_t l_bq = s_exec_to_canon_base_quote(e->level.match.value, e->level.match.rate, l_side);
                            s_dex_history_append(a_ledger, e->pair_key_ptr, a_tx->header.ts_created, e->level.match.rate, l_bq.base,
                                                 l_bq.quote, a_tx_hash, &l_prev_hash, &e->level.match.root, e->seller_addr_ptr, NULL,
                                                 DEX_OP_CANCEL, l_side);
                        }
                        debug_if(s_debug_more, L_DEBUG, "%s(): Order tail %s %s, removing from cache", __FUNCTION__,
                                 dap_hash_fast_to_str_static(&l_prev_hash), l_reason);
                        s_dex_cache_remove((dex_order_cache_entry_t *)e);
                    } else if (l_tx_type == DEX_TX_TYPE_INVALIDATE || l_tx_type == DEX_TX_TYPE_EXCHANGE) {
                        // Cache miss: try to resolve order root from ledger and remove by root to avoid orphans
                        dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_prev_hash);
                        int l_prev_out_idx = 0;
                        dap_chain_tx_out_cond_t *l_prev_cout =
                            l_prev_tx ? dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_out_idx)
                                      : NULL;
                        // Skip if IN_COND doesn't spend DEX OUT
                        if (l_prev_cout && (int)l_in_cond_it->header.tx_out_prev_idx == l_prev_out_idx) {
                            dap_hash_fast_t l_root = dap_hash_fast_is_blank(&l_prev_cout->subtype.srv_dex.order_root_hash)
                                                         ? l_prev_hash
                                                         : l_prev_cout->subtype.srv_dex.order_root_hash;
                            dex_order_cache_entry_t *l_root_e = NULL;
                            HASH_FIND(level.hh, s_dex_orders_cache, &l_root, sizeof(l_root), l_root_e);
                            if (l_root_e) {
                                debug_if(s_debug_more, L_DEBUG, "%s(): Cache miss by tail %s, removing by root %s", __FUNCTION__,
                                         dap_hash_fast_to_str_static(&l_prev_hash), dap_hash_fast_to_str_static(&l_root));
                                s_dex_cache_remove(l_root_e);
                            }
                        }
                    }
                }
                l_in_idx++;
            }
            // NOTE: On cache miss we try to remove by root via ledger (INVALIDATE and full-close EXCHANGE).
            // If prev tx can't be loaded or root isn't present in cache, orphan entries may remain on rare cache desyncs.

            // Buyer-leftover (blank root) always creates a new order (root=tail=a_tx_hash).
            // Determination of sell_token is based on OUT buy_token versus previous ORDER tuple:
            //  - If OUT buy_token == prev sell_token → buyer sells prev buy_token
            //  - If OUT buy_token == prev buy_token → buyer sells prev sell_token
            if (l_out_cond && dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash)) {
                const char *l_out_buy_token = l_out_cond->subtype.srv_dex.buy_token, *l_sell_ticker_new = NULL;
                // Try cache-derived tokens first (available only on cache hit)
                if (l_prev0_sell_token && l_prev0_buy_token) {
                    if (!dap_strcmp(l_out_buy_token, l_prev0_sell_token))
                        l_sell_ticker_new = l_prev0_buy_token;
                    else if (!dap_strcmp(l_out_buy_token, l_prev0_buy_token))
                        l_sell_ticker_new = l_prev0_sell_token;
                }
                // Fallback: derive from first IN via ledger if cache missed or disabled
                if (!l_sell_ticker_new && l_in_cond) {
                    dap_chain_datum_tx_t *l_prev0_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_in_cond->header.tx_prev_hash);
                    int l_prev0_dex_idx = 0;
                    dap_chain_tx_out_cond_t *l_prev0_cond =
                        l_prev0_tx ? dap_chain_datum_tx_out_cond_get(l_prev0_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev0_dex_idx)
                                   : NULL;
                    // Validate that IN_COND actually spends this SRV_DEX OUT
                    if (l_prev0_cond && (int)l_in_cond->header.tx_out_prev_idx == l_prev0_dex_idx) {
                        const char *l_prev_sell = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_in_cond->header.tx_prev_hash);
                        const char *l_prev_buy = l_prev0_cond->subtype.srv_dex.buy_token;
                        if (l_prev_sell && l_prev_buy) {
                            if (!dap_strcmp(l_out_buy_token, l_prev_sell))
                                l_sell_ticker_new = l_prev_buy;
                            else if (!dap_strcmp(l_out_buy_token, l_prev_buy))
                                l_sell_ticker_new = l_prev_sell;
                        }
                    }
                }
                if (l_sell_ticker_new && *l_sell_ticker_new) {
                    if (s_dex_cache_enabled)
                        s_dex_cache_upsert(a_ledger, l_sell_ticker_new, a_tx_hash, a_tx_hash, l_out_cond, l_out_idx,
                                           a_tx->header.ts_created, "buyer-leftover");
                    // Add buyer-leftover to history with combined ORDER + last trade flags
                    if (s_dex_history_enabled && l_last_event_flags) {
                        dex_pair_key_t l_leftover_key = {};
                        uint8_t l_leftover_side = 0;
                        uint256_t l_leftover_price = uint256_0;
                        s_dex_pair_normalize(l_sell_ticker_new, a_ledger->net->pub.id, l_out_buy_token, a_ledger->net->pub.id,
                                             l_out_cond->subtype.srv_dex.rate, &l_leftover_key, &l_leftover_side, &l_leftover_price);
                        dex_bq_t l_leftover_bq = s_exec_to_canon_base_quote(l_out_cond->header.value, l_leftover_price, l_leftover_side);
                        dap_hash_fast_t l_blank = {};
                        s_dex_history_append(a_ledger, &l_leftover_key, a_tx->header.ts_created, l_leftover_price, l_leftover_bq.base,
                                             l_leftover_bq.quote, a_tx_hash, &l_blank, a_tx_hash, &l_out_cond->subtype.srv_dex.seller_addr,
                                             NULL, l_last_event_flags | DEX_OP_CREATE, l_leftover_side);
                    }
                } else
                    log_it(L_ERROR, "%s(): Failed to resolve sell token for buyer-leftover %s", __FUNCTION__,
                           dap_hash_fast_to_str_static(a_tx_hash));
            }
            if (l_order_ranks)
                utarray_free(l_order_ranks);
        } else { // 'd' reorg
            if (l_out_cond && dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash)) {
                // Reorg handling: remove buyer-leftover (if any), restore all prev_tail into cache and adjust history
                if (s_dex_cache_enabled) {
                    s_dex_cache_remove_by_root(a_tx_hash);
                    debug_if(s_debug_more, L_DEBUG, "%s(): Buyer-leftover removed from cache; root = tail = %s", __FUNCTION__,
                             dap_chain_hash_fast_to_str_static(a_tx_hash));
                }

                // Rollback buyer-leftover ORDER record in history (key: tx_hash + blank prev_tail)
                if (s_dex_history_enabled) {
                    const char *l_sell_ticker_new = NULL;
                    const char *l_out_buy_token = l_out_cond->subtype.srv_dex.buy_token;
                    if (l_in_cond) {
                        dap_hash_fast_t l_prev0_hash = l_in_cond->header.tx_prev_hash;
                        dap_chain_datum_tx_t *l_prev0_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_prev0_hash);
                        int l_prev0_dex_idx = 0;
                        dap_chain_tx_out_cond_t *l_prev0_cond =
                            l_prev0_tx
                                ? dap_chain_datum_tx_out_cond_get(l_prev0_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev0_dex_idx)
                                : NULL;
                        if (l_prev0_cond && (int)l_in_cond->header.tx_out_prev_idx == l_prev0_dex_idx) {
                            const char *l_prev_sell = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_prev0_hash);
                            const char *l_prev_buy = l_prev0_cond->subtype.srv_dex.buy_token;
                            if (l_prev_sell && l_prev_buy) {
                                if (!dap_strcmp(l_out_buy_token, l_prev_sell))
                                    l_sell_ticker_new = l_prev_buy;
                                else if (!dap_strcmp(l_out_buy_token, l_prev_buy))
                                    l_sell_ticker_new = l_prev_sell;
                            }
                        }
                    }
                    if (l_sell_ticker_new && *l_sell_ticker_new) {
                        dex_pair_key_t l_key = {};
                        uint8_t l_side = 0;
                        uint256_t l_price_canon = uint256_0;
                        s_dex_pair_normalize(l_sell_ticker_new, a_ledger->net->pub.id, l_out_buy_token, a_ledger->net->pub.id,
                                             l_out_cond->subtype.srv_dex.rate, &l_key, &l_side, &l_price_canon);

                        uint64_t l_bts = s_hist_bucket_ts(a_tx->header.ts_created, s_dex_history_bucket_sec);
                        dex_hist_pair_t *l_pair = NULL;
                        HASH_FIND(hh, s_dex_history, &l_key, DEX_PAIR_KEY_CMP_SIZE, l_pair);
                        if (l_pair) {
                            dex_hist_bucket_t *l_bucket = NULL;
                            HASH_FIND(hh, l_pair->buckets, &l_bts, sizeof(l_bts), l_bucket);
                            if (l_bucket) {
                                dap_hash_fast_t l_blank = {};
                                s_hist_indexes_remove(l_pair, l_bucket, a_tx_hash, &l_blank);
                            }
                        }
                    }
                }
            }

            // Restore previous orders (early exits for cleaner flow)
            byte_t *it;
            size_t sz = 0;
            TX_ITEM_ITER_TX(it, sz, a_tx) if (*it == TX_ITEM_TYPE_IN_COND)
            {
                dap_chain_tx_in_cond_t *l_in_it = (dap_chain_tx_in_cond_t *)it;
                dap_hash_fast_t l_prev_hash = l_in_it->header.tx_prev_hash;
                dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_prev_hash);
                if (!l_prev_tx)
                    continue;

                int l_prev_out_idx = 0;
                dap_chain_tx_out_cond_t *l_prev_cout =
                    dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_out_idx);
                // Skip if IN_COND doesn't spend DEX OUT
                if (!l_prev_cout || (int)l_in_it->header.tx_out_prev_idx != l_prev_out_idx)
                    continue;

                const char *l_sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_prev_hash);
                if (!l_sell_ticker)
                    continue;

                // Restore to cache
                if (s_dex_cache_enabled) {
                    // For SRV_DEX, blank root means head-of-chain at this tx (ORDER or buyer-leftover):
                    // logical chain root is l_prev_hash itself; non-blank root persists across residual/UPDATE.
                    dap_hash_fast_t root_hash_i =
                        dap_ledger_get_first_chain_tx_hash(a_ledger, l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                    if (dap_hash_fast_is_blank(&root_hash_i))
                        root_hash_i = l_prev_hash;
                    const char *l_rollback_type = (l_tx_type == DEX_TX_TYPE_INVALIDATE) ? "rollback cancel"
                                                  : (l_tx_type == DEX_TX_TYPE_UPDATE)   ? "rollback update"
                                                                                        : "rollback trade";
                    s_dex_cache_upsert(a_ledger, l_sell_ticker, &root_hash_i, &l_prev_hash, l_prev_cout, l_prev_out_idx,
                                       l_prev_tx->header.ts_created, l_rollback_type);
                }
                // Rollback history (trades, updates and cancellations)
                if (s_dex_history_enabled &&
                    (l_tx_type == DEX_TX_TYPE_EXCHANGE || l_tx_type == DEX_TX_TYPE_UPDATE || l_tx_type == DEX_TX_TYPE_INVALIDATE)) {
                    dex_pair_key_t l_key = {};
                    uint8_t l_side = 0;
                    uint256_t l_price_canon = uint256_0;
                    s_dex_pair_normalize(l_sell_ticker, l_prev_cout->subtype.srv_dex.sell_net_id, l_prev_cout->subtype.srv_dex.buy_token,
                                         l_prev_cout->subtype.srv_dex.buy_net_id, l_prev_cout->subtype.srv_dex.rate, &l_key, &l_side,
                                         &l_price_canon);

                    uint64_t l_bts = s_hist_bucket_ts(a_tx->header.ts_created, s_dex_history_bucket_sec);
                    dex_hist_pair_t *l_pair = NULL;
                    HASH_FIND(hh, s_dex_history, &l_key, DEX_PAIR_KEY_CMP_SIZE, l_pair);
                    if (l_pair) {
                        dex_hist_bucket_t *l_bucket = NULL;
                        HASH_FIND(hh, l_pair->buckets, &l_bts, sizeof(l_bts), l_bucket);
                        if (l_bucket) {
                            const char *l_event_type = (l_tx_type == DEX_TX_TYPE_INVALIDATE) ? "cancel"
                                                       : (l_tx_type == DEX_TX_TYPE_UPDATE)   ? "update"
                                                                                             : "trade";
                            debug_if(s_debug_more, L_DEBUG, "%s(): Rollback %s %s/%s tx %s", __FUNCTION__, l_event_type, l_key.token_base,
                                     l_key.token_quote, dap_chain_hash_fast_to_str_static(a_tx_hash));
                            s_hist_indexes_remove(l_pair, l_bucket, a_tx_hash, &l_prev_hash);
                        }
                    }
                }
            }
        }
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
    }
    }
}

/*
 * Matching (criteria path, cache or ledger):
 * - Normalize to canonical pair and price: rate == QUOTE/BASE.
 * - Filters: not expired, opposite side, optional price limit (rate_cap > 0 -> BID: rate<=cap, ASK: rate>=cap), optional self-purchase
 * skip.
 * - Budget is translated to canonical BASE/QUOTE context via is_budget_buy and taker side.
 * - exec_sell is always BASE; exec_quote holds exact QUOTE for partial fills.
 * - Min-fill: low 7 bits = percent, 0x80 = from origin (root).
 */
dap_hash_fast_t *dap_chain_net_srv_dex_match_hashes(dap_chain_net_t *a_net, const char *a_sell_token, const char *a_buy_token,
                                                    dap_chain_net_id_t *a_sell_net_id, dap_chain_net_id_t *a_buy_net_id,
                                                    uint256_t *a_max_value, uint256_t *a_rate_cap, size_t *a_num_matches,
                                                    bool a_is_budget_buy)
{
    dap_ret_val_if_any(NULL, !a_net, !a_sell_token, !a_buy_token, !a_num_matches);
    dex_match_criteria_t l_crit = {
        a_sell_token,
        a_buy_token,
        a_sell_net_id ? *a_sell_net_id : (dap_chain_net_id_t){},
        a_buy_net_id ? *a_buy_net_id : (dap_chain_net_id_t){},
        a_rate_cap ? *a_rate_cap : uint256_0,
        a_max_value ? *a_max_value : uint256_0,
        a_is_budget_buy,
        NULL // buyer_addr = NULL: no self-purchase filter for listing
    };
    uint256_t l_leftover_quote = uint256_0;
    *a_num_matches = 0;
    dex_match_table_entry_t *l_matches = s_dex_matches_build_by_criteria(a_net, &l_crit, &l_leftover_quote);
    if (!l_matches)
        return NULL; // No matches found (normal case, not an error)

    size_t q = HASH_CNT(hh, l_matches), i = 0;
    dap_hash_fast_t *l_hashes = DAP_NEW_Z_COUNT(dap_hash_fast_t, q);
    if (l_hashes) {
        dex_match_table_entry_t *l_cur, *l_tmp;
        HASH_ITER(hh, l_matches, l_cur, l_tmp)
        l_hashes[i++] = l_cur->match.tail;
        *a_num_matches = q;
    }
    s_dex_match_pair_index_clear(&l_matches);
    return l_hashes;
}

/* ============================================================================
 * Public API
 * create, update, purchase, purchase_multi, purchase_auto, remove, migrate, cancel_all
 * ============================================================================ */

bool dap_chain_net_srv_dex_pair_is_whitelisted(const char *a_sell_token, dap_chain_net_id_t a_sell_net_id,
                                               const char *a_buy_token, dap_chain_net_id_t a_buy_net_id)
{
    dap_ret_val_if_any(false, !a_sell_token, a_sell_token && !*a_sell_token, !a_buy_token, a_buy_token && !*a_buy_token);
    dex_pair_key_t l_pair_check = {};
    s_dex_pair_normalize(a_sell_token, a_sell_net_id, a_buy_token, a_buy_net_id, uint256_0, &l_pair_check, NULL, NULL);
    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    bool l_allowed = s_dex_pair_index_get(&l_pair_check) != NULL;
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    return l_allowed;
}

dap_chain_net_srv_dex_create_error_t dap_chain_net_srv_dex_create(dap_chain_net_t *a_net, const char *a_token_buy, const char *a_token_sell,
                                                                  uint256_t a_value_sell, uint256_t a_rate, uint8_t a_min_fill_combined,
                                                                  uint256_t a_fee, dap_chain_wallet_t *a_wallet,
                                                                  dap_chain_datum_tx_t **a_tx)
{
    dap_ret_val_if_any(DEX_CREATE_ERROR_INVALID_ARGUMENT, !a_net, !a_token_buy, !a_token_sell, !a_wallet, !a_tx);
    *a_tx = NULL;
    if (!dap_ledger_token_ticker_check(a_net->pub.ledger, a_token_sell))
        return DEX_CREATE_ERROR_TOKEN_TICKER_SELL_NOT_FOUND;
    if (!dap_ledger_token_ticker_check(a_net->pub.ledger, a_token_buy))
        return DEX_CREATE_ERROR_TOKEN_TICKER_BUY_NOT_FOUND;
    if (s_debug_more) {
        uint8_t l_min_pct = a_min_fill_combined & 0x7F;
        ;
        const char *l_min_policy = l_min_pct == 0                      ? "PARTIAL_OK"
                                   : l_min_pct == 100                  ? "AON (all-or-none)"
                                   : (a_min_fill_combined & 0x80) != 0 ? "MIN_FROM_ORIGIN"
                                                                       : "MIN_FROM_CURRENT";
        log_it(L_DEBUG,
               "%s(): Args; sell = %s; buy = %s; value_sell = %s; rate = %s; "
               "min_fill: pct = %u, %s policy; fee = %s %s",
               __FUNCTION__, a_token_sell, a_token_buy, dap_uint256_to_char_ex(a_value_sell).frac, dap_uint256_to_char_ex(a_rate).frac,
               (unsigned)l_min_pct, l_min_policy, dap_uint256_to_char_ex(a_fee).frac, a_net->pub.native_ticker);
    }

    // Whitelist check: pair must be whitelisted via decree
    // Rate is expected in canonical form (QUOTE/BASE) for both ASK and BID
    dex_pair_key_t l_pair_check = {};
    s_dex_pair_normalize(a_token_sell, a_net->pub.id, a_token_buy, a_net->pub.id, a_rate, &l_pair_check, NULL, NULL);
    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    dex_pair_index_t *l_pair_whitelist = s_dex_pair_index_get(&l_pair_check);
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    if (!l_pair_whitelist)
        return DEX_CREATE_ERROR_PAIR_NOT_ALLOWED;

    if (IS_ZERO_256(a_rate))
        return DEX_CREATE_ERROR_RATE_IS_ZERO;
    if (IS_ZERO_256(a_fee))
        return DEX_CREATE_ERROR_FEE_IS_ZERO;
    if (IS_ZERO_256(a_value_sell))
        return DEX_CREATE_ERROR_VALUE_SELL_IS_ZERO;

    const char *l_native = a_net->pub.native_ticker;
    bool l_sell_native = !dap_strcmp(a_token_sell, l_native);
    uint256_t l_balance_sell = dap_chain_wallet_get_balance(a_wallet, a_net->pub.id, a_token_sell), l_need_sell = a_value_sell;
    if (l_sell_native) {
        if (SUM_256_256(l_need_sell, a_fee, &l_need_sell))
            return DEX_CREATE_ERROR_INTEGER_OVERFLOW;
    } else {
        if (compare256(dap_chain_wallet_get_balance(a_wallet, a_net->pub.id, l_native), a_fee) < 0)
            return DEX_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE;
    }
    if (compare256(l_balance_sell, l_need_sell) < 0)
        return DEX_CREATE_ERROR_NOT_ENOUGH_CASH;
    // Network fee
    uint256_t l_net_fee = uint256_0, l_total_native_fee = a_fee;
    dap_chain_addr_t l_net_addr;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_addr);
    if (l_net_fee_used)
        SUM_256_256(l_total_native_fee, l_net_fee, &l_total_native_fee);

    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_wallet_addr)
        return DEX_CREATE_ERROR_COMPOSE_TX;
    dap_chain_addr_t l_owner_addr = *l_wallet_addr;
    DAP_DELETE(l_wallet_addr);

    // Collect inputs
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    int l_err = DEX_CREATE_ERROR_OK, l_err_line = 0;
#define RET_ERR(_err)                                                                                                                      \
    do {                                                                                                                                   \
        l_err = _err;                                                                                                                      \
        l_err_line = __LINE__;                                                                                                             \
        goto dex_create_ret;                                                                                                               \
    } while (0)
    uint256_t l_sell_transfer = uint256_0, l_fee_transfer = uint256_0;
    if (l_sell_native) {
        // Single channel: native sell covers both value and fees
        uint256_t l_need = a_value_sell;
        if (!IS_ZERO_256(l_total_native_fee))
            SUM_256_256(l_need, l_total_native_fee, &l_need);
        if (s_dex_collect_utxo_for_ticker(a_net, l_native, &l_owner_addr, l_need, &l_tx, &l_sell_transfer) < 0)
            RET_ERR(DEX_CREATE_ERROR_COMPOSE_TX);
    } else {
        // Dual channel: collect sell token + native for fees
        if (s_dex_collect_utxo_for_ticker(a_net, a_token_sell, &l_owner_addr, a_value_sell, &l_tx, &l_sell_transfer) < 0)
            RET_ERR(DEX_CREATE_ERROR_COMPOSE_TX);
        if (!IS_ZERO_256(l_total_native_fee)) {
            if (s_dex_collect_utxo_for_ticker(a_net, l_native, &l_owner_addr, l_total_native_fee, &l_tx, &l_fee_transfer) < 0)
                RET_ERR(DEX_CREATE_ERROR_COMPOSE_TX);
        }
    }

    // Add SRV_DEX out (locks sell funds)
    // Rate is stored in canonical form (QUOTE/BASE) for both ASK and BID
    uint8_t l_min_fill = a_min_fill_combined, l_version = 1;
    uint32_t l_flags = 0;
    dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_item_out_cond_create_srv_dex(
        (dap_chain_net_srv_uid_t){.uint64 = DAP_CHAIN_NET_SRV_DEX_ID}, a_net->pub.id, a_value_sell, a_net->pub.id, a_token_buy, a_rate,
        &l_owner_addr, NULL, l_min_fill, l_version, l_flags, DEX_TX_TYPE_ORDER, NULL, 0);
    if (!l_out)
        RET_ERR(DEX_CREATE_ERROR_COMPOSE_TX);
    dap_chain_datum_tx_add_item(&l_tx, l_out);
    DAP_DELETE(l_out);

    // Add fees
    if (s_dex_add_fees_to_tx(&l_tx, a_fee, l_net_fee_used ? l_net_fee : uint256_0, &l_net_addr, l_native) < 0)
        RET_ERR(DEX_CREATE_ERROR_COMPOSE_TX);

    // Add cashback
    if (l_sell_native) {
        // Single channel: cashback in native
        uint256_t l_needed = a_value_sell;
        if (!IS_ZERO_256(l_total_native_fee))
            SUM_256_256(l_needed, l_total_native_fee, &l_needed);
        if (s_dex_add_cashback(&l_tx, l_sell_transfer, l_needed, &l_owner_addr, l_native) < 0)
            RET_ERR(DEX_CREATE_ERROR_COMPOSE_TX);
    } else {
        // Dual channel: cashback in sell token + native
        if (s_dex_add_cashback(&l_tx, l_sell_transfer, a_value_sell, &l_owner_addr, a_token_sell) < 0)
            RET_ERR(DEX_CREATE_ERROR_COMPOSE_TX);
        if (!IS_ZERO_256(l_total_native_fee)) {
            if (s_dex_add_cashback(&l_tx, l_fee_transfer, l_total_native_fee, &l_owner_addr, l_native) < 0)
                RET_ERR(DEX_CREATE_ERROR_COMPOSE_TX);
        }
    }

    // Sign TX
    if (s_dex_sign_tx(&l_tx, a_wallet) < 0)
        RET_ERR(DEX_CREATE_ERROR_COMPOSE_TX);
#undef RET_ERR
dex_create_ret:
    if (l_err) {
        log_it(L_ERROR, "%s(): Error %d at line %d", __FUNCTION__, l_err, l_err_line);
        dap_chain_datum_tx_delete(l_tx);
        l_tx = NULL;
    }
    *a_tx = l_tx;
    return l_err;
}

/*
 * Update existing order by owner (seller-leftover update):
 * - Finds the current tail of the order chain via the ledger (source of truth)
 * - Verifies that wallet addr matches order's seller_addr
 * - Composes 1-TX update: IN_COND(tail[idx]) + OUT_COND(SRV_DEX new state) with tx_type=UPDATE
 * - Pays native network fee (and optionally validator fee) from wallet UTXOs
 * - Signs and submits to mempool
 */
dap_chain_net_srv_dex_update_error_t dap_chain_net_srv_dex_update(dap_chain_net_t *a_net, dap_hash_fast_t *a_order_root,
                                                                  bool a_has_new_value, uint256_t a_new_value, uint256_t a_fee,
                                                                  dap_chain_wallet_t *a_wallet, dap_chain_datum_tx_t **a_tx)
{
    // Parameter validation: must have net, order root, wallet, out ptr, and new value flag
    dap_ret_val_if_any(DEX_UPDATE_ERROR_INVALID_ARGUMENT, !a_net, !a_order_root || dap_hash_fast_is_blank(a_order_root), !a_wallet, !a_tx,
                       !a_has_new_value);
    *a_tx = NULL;
    // Find actual tail (cache-first, ledger fallback)
    dap_hash_fast_t l_tail;
    if (s_dex_resolve_order_tail(a_net, a_order_root, &l_tail))
        return DEX_UPDATE_ERROR_NOT_FOUND;

    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_tail);
    if (!l_prev_tx)
        return DEX_UPDATE_ERROR_NOT_FOUND;

    int l_prev_idx = 0;
    dap_chain_tx_out_cond_t *l_prev = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_idx);
    if (!l_prev)
        return DEX_UPDATE_ERROR_NOT_FOUND;

    // Determine correct order_root_hash: if l_prev has blank root, it's the ORDER (use l_tail as root); otherwise use l_prev's root
    dap_hash_fast_t l_order_root =
        dap_hash_fast_is_blank(&l_prev->subtype.srv_dex.order_root_hash) ? l_tail : l_prev->subtype.srv_dex.order_root_hash;

    const char *l_sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &l_tail);
    if (!l_sell_ticker)
        return DEX_UPDATE_ERROR_NOT_FOUND;

    const char *l_buy_ticker = l_prev->subtype.srv_dex.buy_token;

    // Owner check: wallet addr must be equal to order's seller_addr
    dap_chain_addr_t l_wallet_addr;
    {
        dap_chain_addr_t *l_tmp = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
        if (!l_tmp)
            return DEX_UPDATE_ERROR_COMPOSE_TX;
        l_wallet_addr = *l_tmp;
        DAP_DELETE(l_tmp);
    }

    if (!dap_chain_addr_compare(&l_wallet_addr, &l_prev->subtype.srv_dex.seller_addr))
        return DEX_UPDATE_ERROR_NOT_OWNER;

    // New parameters: rate is immutable, value can change
    uint256_t l_new_rate = l_prev->subtype.srv_dex.rate, l_new_value = a_has_new_value ? a_new_value : l_prev->header.value;

    // Validate new parameters: value must be non-zero
    // UPDATE with value=0 is not allowed (use INVALIDATE for full closure)
    dap_ret_val_if_any(DEX_UPDATE_ERROR_INVALID_ARGUMENT, IS_ZERO_256(l_new_value));

    dap_chain_net_srv_dex_update_error_t l_err = DEX_UPDATE_ERROR_OK;
    int l_err_line = 0;
#define RET_ERR(_err)                                                                                                                      \
    do {                                                                                                                                   \
        l_err = (_err);                                                                                                                    \
        l_err_line = __LINE__;                                                                                                             \
        goto update_ret;                                                                                                                   \
    } while (0)

    // Compose 1-TX update: IN_COND(l_tail[idx]) + OUT_COND(SRV_DEX new state)
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx)
        RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);

    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_tail, l_prev_idx, 0) != 1)
        RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);
    dap_chain_net_srv_uid_t l_uid = {.uint64 = DAP_CHAIN_NET_SRV_DEX_ID};
    dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_item_out_cond_create_srv_dex(
        l_uid, a_net->pub.id, l_new_value, a_net->pub.id, l_buy_ticker, l_new_rate, &l_wallet_addr, &l_order_root,
        l_prev->subtype.srv_dex.min_fill, l_prev->subtype.srv_dex.version, l_prev->subtype.srv_dex.flags, DEX_TX_TYPE_UPDATE, NULL, 0);
    if (!l_out)
        RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);
    // Explicitly mark composer-declared type to be verified later by the verificator
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out);
    DAP_DELETE(l_out);

    // Fees: pay validator/network in native token
    uint256_t l_net_fee = {}, l_total_native_fee = a_fee;
    dap_chain_addr_t l_net_addr = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_addr);
    if (l_net_fee_used)
        SUM_256_256(l_total_native_fee, l_net_fee, &l_total_native_fee);

    // Delta handling: lock additional sell if increased, or return surplus if decreased
    uint256_t l_delta = uint256_0, l_sell_transfer = uint256_0, l_fee_transfer = uint256_0;
    int l_cmp = compare256(l_new_value, l_prev->header.value);
    bool l_sell_native = !strcmp(l_sell_ticker, a_net->pub.native_ticker);

    if (l_cmp > 0) {
        // Increase: need extra inputs in sell token
        SUBTRACT_256_256(l_new_value, l_prev->header.value, &l_delta);
        if (l_sell_native) {
            // Single channel: collect delta + fees together to avoid double-spend
            uint256_t l_need = l_delta;
            if (!IS_ZERO_256(l_total_native_fee))
                SUM_256_256(l_need, l_total_native_fee, &l_need);
            if (s_dex_collect_utxo_for_ticker(a_net, l_sell_ticker, &l_wallet_addr, l_need, &l_tx, &l_sell_transfer) < 0)
                RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);
        } else {
            // Dual channel: collect delta and fees separately
            if (s_dex_collect_utxo_for_ticker(a_net, l_sell_ticker, &l_wallet_addr, l_delta, &l_tx, &l_sell_transfer) < 0)
                RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);
            if (!IS_ZERO_256(l_total_native_fee)) {
                if (s_dex_collect_utxo_for_ticker(a_net, a_net->pub.native_ticker, &l_wallet_addr, l_total_native_fee, &l_tx,
                                                  &l_fee_transfer) < 0)
                    RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);
            }
        }
    } else if (l_cmp < 0) {
        // Decrease: refund delta = prev - new in sell token to seller
        SUBTRACT_256_256(l_prev->header.value, l_new_value, &l_delta);
        if (dap_chain_datum_tx_add_out_std_item(&l_tx, &l_wallet_addr, l_delta, l_sell_ticker, 0) == -1)
            RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);
        // Still need to collect fees
        if (!IS_ZERO_256(l_total_native_fee)) {
            if (s_dex_collect_utxo_for_ticker(a_net, a_net->pub.native_ticker, &l_wallet_addr, l_total_native_fee, &l_tx, &l_fee_transfer) <
                0)
                RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);
        }
    } else {
        // No value change, just collect fees
        if (!IS_ZERO_256(l_total_native_fee)) {
            if (s_dex_collect_utxo_for_ticker(a_net, a_net->pub.native_ticker, &l_wallet_addr, l_total_native_fee, &l_tx, &l_fee_transfer) <
                0)
                RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);
        }
    }

    // Add fee items
    if (s_dex_add_fees_to_tx(&l_tx, a_fee, l_net_fee_used ? l_net_fee : uint256_0, &l_net_addr, a_net->pub.native_ticker) < 0)
        RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);

    // Cashback handling
    if (l_sell_native && l_cmp > 0) {
        // Single channel: combined cashback for delta + fees
        uint256_t l_needed = l_delta;
        if (!IS_ZERO_256(l_total_native_fee))
            SUM_256_256(l_needed, l_total_native_fee, &l_needed);
        if (s_dex_add_cashback(&l_tx, l_sell_transfer, l_needed, &l_wallet_addr, l_sell_ticker) < 0)
            RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);
    } else {
        // Dual channel or decrease: separate cashbacks
        if (l_cmp > 0 && !IS_ZERO_256(l_sell_transfer)) {
            if (s_dex_add_cashback(&l_tx, l_sell_transfer, l_delta, &l_wallet_addr, l_sell_ticker) < 0)
                RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);
        }
        if (!IS_ZERO_256(l_total_native_fee) && !IS_ZERO_256(l_fee_transfer)) {
            if (s_dex_add_cashback(&l_tx, l_fee_transfer, l_total_native_fee, &l_wallet_addr, a_net->pub.native_ticker) < 0)
                RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);
        }
    }

    // Sign TX
    if (s_dex_sign_tx(&l_tx, a_wallet) < 0)
        RET_ERR(DEX_UPDATE_ERROR_COMPOSE_TX);
#undef RET_ERR
update_ret:
    if (l_err != DEX_UPDATE_ERROR_OK) {
        log_it(L_ERROR, "%s(): Error %d at line %d", __FUNCTION__, l_err, l_err_line);
        dap_chain_datum_tx_delete(l_tx);
        l_tx = NULL;
    }
    *a_tx = l_tx;
    return l_err;
}

// Single order purchase: build single-entry match table and delegate to universal composer (supports leftover orders)
static dap_chain_datum_tx_t *s_dex_tx_create_exchange(dap_chain_net_t *a_net, dap_chain_wallet_t *a_wallet,
                                                      const dap_chain_addr_t *a_buyer_addr, dap_hash_fast_t *a_prev_hash, uint256_t a_value,
                                                      bool a_is_budget_buy, uint256_t a_fee, bool a_create_buyer_order_on_leftover,
                                                      uint256_t a_leftover_rate)
{
    dap_ret_val_if_any(NULL, !a_net, !a_wallet, !a_prev_hash);

    // Build single-entry match table with self-purchase filter
    dap_chain_net_srv_dex_purchase_error_t l_err = DEX_PURCHASE_ERROR_OK;
    uint256_t l_leftover_quote = uint256_0;
    dex_match_table_entry_t *l_matches =
        s_dex_matches_build_by_hashes(a_net, a_prev_hash, 1, a_value, a_is_budget_buy, a_buyer_addr, &l_err, &l_leftover_quote);
    if (!l_matches)
        return NULL;

    debug_if(s_debug_more, L_DEBUG, "%s(): After match found, leftover in Q: %s; Budget in %s token%s%s", __FUNCTION__,
             dap_uint256_to_char_ex(l_leftover_quote).str, a_is_budget_buy ? "buy" : "sell",
             a_create_buyer_order_on_leftover ? "; Buyer-leftover requested with rate: " : "",
             a_create_buyer_order_on_leftover ? dap_uint256_to_char_ex(a_leftover_rate).frac : "");

    // Use universal composer with leftover parameters
    dap_chain_datum_tx_t *l_tx = s_dex_compose_from_match_table(a_net, a_wallet, a_fee, l_leftover_quote, a_is_budget_buy,
                                                                a_create_buyer_order_on_leftover, a_leftover_rate, l_matches);
    s_dex_match_pair_index_clear(&l_matches);
    return l_tx;
}

dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase(dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash,
                                                                      uint256_t a_value, bool a_is_budget_buy, uint256_t a_fee,
                                                                      dap_chain_wallet_t *a_wallet, bool a_create_buyer_order_on_leftover,
                                                                      uint256_t a_leftover_rate, dap_chain_datum_tx_t **a_tx)
{
    dap_ret_val_if_any(DEX_PURCHASE_ERROR_INVALID_ARGUMENT, !a_net, !a_order_hash || dap_hash_fast_is_blank(a_order_hash), !a_wallet,
                       !a_tx/*, IS_ZERO_256(a_value)*/);
    *a_tx = NULL;
    debug_if(s_debug_more, L_DEBUG, "%s(): Args: order_hash = %s; budget = %s in %s tokens; fee = %s %s%s%s", __FUNCTION__,
             dap_chain_hash_fast_to_str_static(a_order_hash), dap_uint256_to_char_ex(a_value).frac, a_is_budget_buy ? "buy" : "sell",
             dap_uint256_to_char_ex(a_fee).frac, a_net->pub.native_ticker,
             a_create_buyer_order_on_leftover ? "; Buyer-leftover requested with rate: " : "",
             a_create_buyer_order_on_leftover ? dap_uint256_to_char_ex(a_leftover_rate).frac : "");

    dap_hash_fast_t l_tail;
    if (s_dex_resolve_order_tail(a_net, a_order_hash, &l_tail))
        return DEX_PURCHASE_ERROR_ORDER_NOT_FOUND;

    dap_chain_datum_tx_t *l_tail_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_tail);
    if (!l_tail_tx)
        return DEX_PURCHASE_ERROR_ORDER_NOT_FOUND;

    int l_prev_idx = 0;
    dap_chain_tx_out_cond_t *l_prev_cond = dap_chain_datum_tx_out_cond_get(l_tail_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_idx);
    if (!l_prev_cond)
        return DEX_PURCHASE_ERROR_ORDER_NOT_FOUND;
    if (dap_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &l_tail, l_prev_idx, NULL))
        return DEX_PURCHASE_ERROR_ORDER_SPENT;

    // Get buyer address for self-purchase filter
    dap_chain_addr_t *l_buyer_addr = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_buyer_addr)
        return DEX_PURCHASE_ERROR_INVALID_ARGUMENT;

    debug_if(s_debug_more, L_DEBUG, "%s(): Resolved purchase tail: %s", __FUNCTION__, dap_chain_hash_fast_to_str_static(&l_tail));

    // Self-purchase check inside s_dex_matches_build_by_hashes (called by s_dex_tx_create_exchange)
    *a_tx = s_dex_tx_create_exchange(a_net, a_wallet, l_buyer_addr, &l_tail, a_value, a_is_budget_buy, a_fee,
                                     a_create_buyer_order_on_leftover, a_leftover_rate);
    DAP_DELETE(l_buyer_addr);
    debug_if(s_debug_more, *a_tx ? L_DEBUG : L_ERROR, "%s(): Purchase %s; Tail: %s", __FUNCTION__, *a_tx ? "composed" : "failed",
             dap_chain_hash_fast_to_str_static(&l_tail));
    return *a_tx ? DEX_PURCHASE_ERROR_OK : DEX_PURCHASE_ERROR_COMPOSE_TX;
}

dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase_multi(dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hashes,
                                                                            size_t a_orders_count, uint256_t a_value, bool a_is_budget_buy,
                                                                            uint256_t a_fee, dap_chain_wallet_t *a_wallet,
                                                                            bool a_create_buyer_order_on_leftover,
                                                                            uint256_t a_leftover_rate, dap_chain_datum_tx_t **a_tx)
{
    dap_ret_val_if_any(DEX_PURCHASE_ERROR_INVALID_ARGUMENT, !a_net, !a_order_hashes, !a_orders_count, !a_wallet, !a_tx,
                       IS_ZERO_256(a_value));
    *a_tx = NULL;
    if (a_orders_count == 0)
        return DEX_PURCHASE_MULTI_ERROR_ORDERS_EMPTY;
    if (s_debug_more) {
        log_it(L_DEBUG, "%s(): Args: orders count = %zu; budget = %s in %s tokens; fee = %s %s%s%s", __FUNCTION__, a_orders_count,
               dap_uint256_to_char_ex(a_value).frac, a_is_budget_buy ? "buy" : "sell", dap_uint256_to_char_ex(a_fee).frac,
               a_net->pub.native_ticker, a_create_buyer_order_on_leftover ? "; Buyer-leftover requested with rate: " : "",
               a_create_buyer_order_on_leftover ? dap_uint256_to_char_ex(a_leftover_rate).frac : "");
        for (size_t i = 0; i < a_orders_count; ++i) {
            log_it(L_DEBUG, "%s():   order[%zu/%zu]: %s", __FUNCTION__, i + 1, a_orders_count,
                   dap_chain_hash_fast_to_str_static(&a_order_hashes[i]));
        }
    }
    // Get buyer address for self-purchase filter
    dap_chain_addr_t *l_buyer_addr = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_buyer_addr)
        return DEX_PURCHASE_ERROR_INVALID_ARGUMENT;

    // Build matches directly from hashes (cache-first, then ledger)
    dap_chain_net_srv_dex_purchase_error_t l_err = DEX_PURCHASE_ERROR_OK;
    uint256_t l_leftover_quote = uint256_0;
    dex_match_table_entry_t *l_matches = s_dex_matches_build_by_hashes(a_net, a_order_hashes, a_orders_count, a_value, a_is_budget_buy,
                                                                       l_buyer_addr, &l_err, &l_leftover_quote);
    DAP_DELETE(l_buyer_addr);
    if (!l_matches)
        return l_err ? l_err : DEX_PURCHASE_ERROR_COMPOSE_TX;
    dap_chain_datum_tx_t *l_tx = s_dex_compose_from_match_table(a_net, a_wallet, a_fee, l_leftover_quote, a_is_budget_buy,
                                                                a_create_buyer_order_on_leftover, a_leftover_rate, l_matches);
    debug_if(s_debug_more, L_DEBUG, "%s(): Purchase %s; Orders count: %zu; Matches: %u; Leftover in Q: %s", __FUNCTION__,
             l_tx ? "composed" : "failed", a_orders_count, HASH_CNT(hh, l_matches), dap_uint256_to_char_ex(l_leftover_quote).frac);
    s_dex_match_pair_index_clear(&l_matches);
    *a_tx = l_tx;
    return l_tx ? DEX_PURCHASE_ERROR_OK : DEX_PURCHASE_ERROR_COMPOSE_TX;
}

static dap_chain_net_srv_dex_purchase_error_t
dap_chain_net_srv_dex_purchase_auto_ex(dap_chain_net_t *a_net, const char *a_sell_token, const char *a_buy_token, uint256_t a_value,
                                       bool a_is_budget_buy, uint256_t a_fee, uint256_t a_rate_cap, dap_chain_wallet_t *a_wallet,
                                       bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate, dap_chain_datum_tx_t **a_tx,
                                       dex_match_table_entry_t **a_matches)
{
    // a_tx == NULL is allowed for dry-run mode (matching only, no TX composition)
    dap_ret_val_if_any(DEX_PURCHASE_ERROR_INVALID_ARGUMENT, !a_net, !a_sell_token, !a_buy_token, !a_wallet, IS_ZERO_256(a_fee),
                       /*IS_ZERO_256(a_value)*/);
    if (a_tx)
        *a_tx = NULL;
    if (a_matches)
        *a_matches = NULL;
    debug_if(s_debug_more, L_DEBUG, "%s(): Args: sell = %s; buy = %s; rate_cap = %s; budget = %s in %s tokens; fee = %s %s%s%s%s",
             __FUNCTION__, a_sell_token, a_buy_token, dap_uint256_to_char_ex(a_rate_cap).frac, dap_uint256_to_char_ex(a_value).frac,
             a_is_budget_buy ? "buy" : "sell", dap_uint256_to_char_ex(a_fee).frac, a_net->pub.native_ticker,
             a_create_buyer_order_on_leftover ? "; Buyer-leftover requested with rate: " : "",
             a_create_buyer_order_on_leftover ? dap_uint256_to_char_ex(a_leftover_rate).frac : "", a_tx ? "" : " [DRY-RUN]");
    dap_chain_addr_t *l_buyer_addr = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_buyer_addr)
        return DEX_PURCHASE_ERROR_INVALID_ARGUMENT;
    dex_match_criteria_t l_crit = {a_sell_token, a_buy_token, a_net->pub.id,   a_net->pub.id,
                                   a_rate_cap,   a_value,     a_is_budget_buy, l_buyer_addr};
    uint256_t l_leftover_quote = uint256_0;
    dex_match_table_entry_t *l_matches = s_dex_matches_build_by_criteria(a_net, &l_crit, &l_leftover_quote);
    DAP_DELETE(l_buyer_addr);
    dap_chain_datum_tx_t *l_tx = NULL;

    if (!l_matches) {
        if (!a_create_buyer_order_on_leftover || IS_ZERO_256(a_leftover_rate))
            return DEX_PURCHASE_AUTO_ERROR_NO_MATCHES;
        // No matches found but leftover order requested: create fresh ORDER with full budget
        if (!a_tx)
            return DEX_PURCHASE_ERROR_OK; // Dry-run: just report success (would create order)
        uint256_t l_value_sell = uint256_0;
        if (a_is_budget_buy)
            DIV_256_COIN(a_value, a_leftover_rate, &l_value_sell);
        else
            l_value_sell = a_value;
        uint8_t l_min_fill_combined = 0; // default PARTIAL_OK policy
        dap_chain_net_srv_dex_create_error_t l_err = dap_chain_net_srv_dex_create(
            a_net, a_buy_token, a_sell_token, l_value_sell, a_leftover_rate, l_min_fill_combined, a_fee, a_wallet, &l_tx);
        if (!l_tx)
            log_it(L_ERROR, "%s(): Leftover order creation failed, err %d", __FUNCTION__, l_err);
        *a_tx = l_tx;
        return l_err ? DEX_PURCHASE_ERROR_COMPOSE_TX : DEX_PURCHASE_ERROR_OK;
    }

    if (a_tx)
        *a_tx = l_tx = s_dex_compose_from_match_table(a_net, a_wallet, a_fee, l_leftover_quote, a_is_budget_buy,
                                                      a_create_buyer_order_on_leftover, a_leftover_rate, l_matches);
    if (a_matches)
        *a_matches = l_matches;
    else
        s_dex_match_pair_index_clear(&l_matches);
    return (a_tx && !l_tx) ? DEX_PURCHASE_ERROR_COMPOSE_TX : DEX_PURCHASE_ERROR_OK;
}

dap_chain_net_srv_dex_purchase_error_t
dap_chain_net_srv_dex_purchase_auto(dap_chain_net_t *a_net, const char *a_sell_token, const char *a_buy_token, uint256_t a_value,
                                    bool a_is_budget_buy, uint256_t a_fee, uint256_t a_rate_cap, dap_chain_wallet_t *a_wallet,
                                    bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate, dap_chain_datum_tx_t **a_tx)
{
    return dap_chain_net_srv_dex_purchase_auto_ex(a_net, a_sell_token, a_buy_token, a_value, a_is_budget_buy, a_fee, a_rate_cap, a_wallet,
                                                  a_create_buyer_order_on_leftover, a_leftover_rate, a_tx, NULL);
}

dap_chain_net_srv_dex_remove_error_t dap_chain_net_srv_dex_remove(dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash, uint256_t a_fee,
                                                                  dap_chain_wallet_t *a_wallet, dap_chain_datum_tx_t **a_tx)
{
    dap_ret_val_if_any(DEX_REMOVE_ERROR_INVALID_ARGUMENT, !a_net, !a_order_hash || dap_hash_fast_is_blank(a_order_hash), !a_wallet, !a_tx);
    *a_tx = NULL;
    if (IS_ZERO_256(a_fee))
        return DEX_REMOVE_ERROR_FEE_IS_ZERO;
    const char *l_native_ticker = a_net->pub.native_ticker;
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    dap_hash_fast_t l_tail = {};
    if (s_dex_resolve_order_tail(a_net, a_order_hash, &l_tail))
        return DEX_REMOVE_ERROR_TX_NOT_FOUND;
    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(l_ledger, &l_tail);
    if (!l_cond_tx)
        return DEX_REMOVE_ERROR_TX_NOT_FOUND;
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_prev_cond =
        dap_chain_datum_tx_out_cond_get(l_cond_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_cond_idx);
    if (!l_prev_cond || dap_ledger_tx_hash_is_used_out_item(l_ledger, &l_tail, l_prev_cond_idx, NULL))
        return DEX_REMOVE_ERROR_INVALID_OUT;
    // Owner check via address compare
    dap_chain_addr_t *l_wallet_addr_tmp = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id), l_wallet_addr;
    if (!l_wallet_addr_tmp)
        return DEX_REMOVE_ERROR_COMPOSE_TX;
    l_wallet_addr = *l_wallet_addr_tmp;
    DAP_DELETE(l_wallet_addr_tmp);
    bool l_is_owner = dap_chain_addr_compare(&l_wallet_addr, &l_prev_cond->subtype.srv_dex.seller_addr);
    if (!l_is_owner)
        return DEX_REMOVE_ERROR_NOT_OWNER;

    // Fees
    uint256_t l_net_fee = {}, l_total_fee = a_fee, l_fee_transfer = {}, l_value_transfer = {};
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_addr_fee);
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);
    const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_tail);
    bool l_single_channel = l_tx_ticker && !dap_strcmp(l_tx_ticker, l_native_ticker);

    dap_chain_net_srv_dex_remove_error_t l_err = DEX_REMOVE_ERROR_OK;
    int l_err_line = 0;
#define RET_ERR(_err)                                                                                                                      \
    do {                                                                                                                                   \
        l_err = (_err);                                                                                                                    \
        l_err_line = __LINE__;                                                                                                             \
        goto remove_ret;                                                                                                                   \
    } while (0)

    // Create tx
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx)
        RET_ERR(DEX_REMOVE_ERROR_COMPOSE_TX);

    // IN_COND (spend previous order)
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_tail, l_prev_cond_idx, 0) != 1)
        RET_ERR(DEX_REMOVE_ERROR_COMPOSE_TX);

    if (!l_single_channel) {
        // Dual channel: collect native for fees
        if (s_dex_collect_utxo_for_ticker(l_ledger->net, l_native_ticker, &l_wallet_addr, l_total_fee, &l_tx, &l_value_transfer) < 0)
            RET_ERR(DEX_REMOVE_ERROR_COMPOSE_TX);

        // Add fees
        if (s_dex_add_fees_to_tx(&l_tx, a_fee, l_net_fee_used ? l_net_fee : uint256_0, &l_addr_fee, l_native_ticker) < 0)
            RET_ERR(DEX_REMOVE_ERROR_COMPOSE_TX);

        // Return locked coins to owner
        if (dap_chain_datum_tx_add_out_std_item(&l_tx, &l_wallet_addr, l_prev_cond->header.value, l_tx_ticker, 0) == -1)
            RET_ERR(DEX_REMOVE_ERROR_COMPOSE_TX);

        // Fee cashback
        if (s_dex_add_cashback(&l_tx, l_value_transfer, l_total_fee, &l_wallet_addr, l_native_ticker) < 0)
            RET_ERR(DEX_REMOVE_ERROR_COMPOSE_TX);
    } else {
        // Single channel: fee deducted from locked value
        if (compare256(l_prev_cond->header.value, l_total_fee) <= 0)
            RET_ERR(DEX_REMOVE_ERROR_COMPOSE_TX);

        // Add fees
        if (s_dex_add_fees_to_tx(&l_tx, a_fee, l_net_fee_used ? l_net_fee : uint256_0, &l_addr_fee, l_native_ticker) < 0)
            RET_ERR(DEX_REMOVE_ERROR_COMPOSE_TX);

        // Return remainder to owner
        uint256_t l_coin_back = {};
        SUBTRACT_256_256(l_prev_cond->header.value, l_total_fee, &l_coin_back);
        if (dap_chain_datum_tx_add_out_std_item(&l_tx, &l_wallet_addr, l_coin_back, l_native_ticker, 0) == -1)
            RET_ERR(DEX_REMOVE_ERROR_COMPOSE_TX);
    }

    // Sign TX
    if (s_dex_sign_tx(&l_tx, a_wallet) < 0)
        RET_ERR(DEX_REMOVE_ERROR_COMPOSE_TX);
#undef RET_ERR
remove_ret:
    if (l_err != DEX_REMOVE_ERROR_OK) {
        log_it(L_ERROR, "%s(): Error %d at line %d", __FUNCTION__, l_err, l_err_line);
        dap_chain_datum_tx_delete(l_tx);
        l_tx = NULL;
    }
    *a_tx = l_tx;
    return l_err;
}

// Compose migration TX: IN_COND on SRV_XCHANGE prev + OUT_COND(SRV_DEX)
dap_chain_net_srv_dex_migrate_error_t dap_chain_net_srv_dex_migrate(dap_chain_net_t *a_net, dap_hash_fast_t *a_prev_hash,
                                                                    uint256_t a_rate_new, uint256_t a_fee, dap_chain_wallet_t *a_wallet,
                                                                    dap_chain_datum_tx_t **a_tx)
{
    dap_ret_val_if_any(DEX_MIGRATE_ERROR_INVALID_ARGUMENT, !a_net, !a_prev_hash || dap_hash_fast_is_blank(a_prev_hash), !a_wallet, !a_tx,
                       IS_ZERO_256(a_rate_new), IS_ZERO_256(a_fee));
    *a_tx = NULL;
    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, a_prev_hash);
    if (!l_prev_tx)
        return DEX_MIGRATE_ERROR_PREV_NOT_FOUND;
    int l_prev_idx = 0;
    dap_chain_tx_out_cond_t *l_prev_out =
        dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_prev_idx);
    if (!l_prev_out)
        return DEX_MIGRATE_ERROR_PREV_NOT_XCHANGE;
    // seller and tokens
    const char *sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, a_prev_hash);
    if (!sell_ticker)
        return DEX_MIGRATE_ERROR_PREV_NOT_FOUND;
    const char *buy_ticker = l_prev_out->subtype.srv_xchange.buy_token;
    uint256_t l_rate_canon = uint256_0;
    if (!s_dex_rate_legacy_to_canon(sell_ticker, buy_ticker, a_rate_new, &l_rate_canon))
        return DEX_MIGRATE_ERROR_INVALID_ARGUMENT;
    // owner wallet addr
    dap_chain_addr_t *l_addr_tmp = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_addr_tmp)
        return DEX_MIGRATE_ERROR_COMPOSE_TX;
    dap_chain_addr_t l_addr = *l_addr_tmp;
    DAP_DELETE(l_addr_tmp);
    bool l_is_owner = dap_chain_addr_compare(&l_addr, &l_prev_out->subtype.srv_xchange.seller_addr);
    if (!l_is_owner)
        return DEX_MIGRATE_ERROR_NOT_OWNER;

    dap_chain_net_srv_dex_migrate_error_t l_err = DEX_MIGRATE_ERROR_OK;
    int l_err_line = 0;
#define RET_ERR(_err)                                                                                                                      \
    do {                                                                                                                                   \
        l_err = (_err);                                                                                                                    \
        l_err_line = __LINE__;                                                                                                             \
        goto migrate_ret;                                                                                                                  \
    } while (0)

    // Compose TX with proper fee inputs from wallet (no funds appear from nowhere)
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx)
        RET_ERR(DEX_MIGRATE_ERROR_COMPOSE_TX);
    // 1) Spend previous SRV_XCHANGE conditional out
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, a_prev_hash, l_prev_idx, 0) != 1)
        RET_ERR(DEX_MIGRATE_ERROR_COMPOSE_TX);

    // 2) Collect native inputs for fees (validator + optional network)
    const char *l_native = a_net->pub.native_ticker;
    uint256_t l_net_fee = uint256_0, l_total_native_fee = a_fee, l_fee_transfer = uint256_0;
    dap_chain_addr_t l_net_addr = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_addr);
    if (l_net_fee_used)
        SUM_256_256(l_total_native_fee, l_net_fee, &l_total_native_fee);
    dap_list_t *l_list_fee_in = NULL;
    if (!IS_ZERO_256(l_total_native_fee)) {
        if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_native, &l_addr, &l_list_fee_in, l_total_native_fee, &l_fee_transfer) ==
            -101)
            l_list_fee_in = dap_ledger_get_list_tx_outs_with_val(a_net->pub.ledger, l_native, &l_addr, l_total_native_fee, &l_fee_transfer);
        if (!l_list_fee_in)
            RET_ERR(DEX_MIGRATE_ERROR_COMPOSE_TX);
        uint256_t l_added_fee = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_in);
        dap_list_free_full(l_list_fee_in, NULL);
        if (!EQUAL_256(l_added_fee, l_fee_transfer))
            RET_ERR(DEX_MIGRATE_ERROR_COMPOSE_TX);
    }

    // 3) Add SRV_DEX out (lock XCHANGE sell amount with new rate)
    dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_item_out_cond_create_srv_dex(
        (dap_chain_net_srv_uid_t){.uint64 = DAP_CHAIN_NET_SRV_DEX_ID}, l_prev_out->subtype.srv_xchange.sell_net_id,
        l_prev_out->header.value, l_prev_out->subtype.srv_xchange.buy_net_id, buy_ticker, l_rate_canon, &l_addr, NULL, 0, 1, 0,
        DEX_TX_TYPE_ORDER, NULL, 0);
    if (!l_out)
        RET_ERR(DEX_MIGRATE_ERROR_COMPOSE_TX);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out);
    DAP_DELETE(l_out);

    // 4) Add validator fee item and optional network fee output
    if (!IS_ZERO_256(a_fee))
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1)
            RET_ERR(DEX_MIGRATE_ERROR_COMPOSE_TX);
    if (l_net_fee_used)
        if (dap_chain_datum_tx_add_out_std_item(&l_tx, &l_net_addr, l_net_fee, l_native, 0) == -1)
            RET_ERR(DEX_MIGRATE_ERROR_COMPOSE_TX);
    // 5) Native cashback (change) back to wallet if fee inputs exceed required total
    if (!IS_ZERO_256(l_fee_transfer) && compare256(l_fee_transfer, l_total_native_fee) == 1) {
        uint256_t l_cashback = uint256_0;
        SUBTRACT_256_256(l_fee_transfer, l_total_native_fee, &l_cashback);
        if (!IS_ZERO_256(l_cashback) && (dap_chain_datum_tx_add_out_std_item(&l_tx, &l_addr, l_cashback, l_native, 0) == -1))
            RET_ERR(DEX_MIGRATE_ERROR_COMPOSE_TX);
    }

    // 6) Sign and submit
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    int l_sign_res = dap_chain_datum_tx_add_sign_item(&l_tx, l_key);
    dap_enc_key_delete(l_key);
    if (l_sign_res != 1)
        RET_ERR(DEX_MIGRATE_ERROR_COMPOSE_TX);
#undef RET_ERR
migrate_ret:
    if (l_err != DEX_MIGRATE_ERROR_OK) {
        log_it(L_ERROR, "%s(): Error %d at line %d", __FUNCTION__, l_err, l_err_line);
        dap_chain_datum_tx_delete(l_tx);
        l_tx = NULL;
    }
    *a_tx = l_tx;
    return l_err;
}

// Compose aggregated cancel-all transaction: spend multiple SRV_DEX outs by seller and return SELL tokens back
dap_chain_net_srv_dex_cancel_all_error_t
dap_chain_net_srv_dex_cancel_all_by_seller(dap_chain_net_t *a_net, const dap_chain_addr_t *a_seller, const char *a_base_token,
                                           const char *a_quote_token, int a_limit, uint256_t a_fee, dap_chain_wallet_t *a_wallet,
                                           dap_chain_datum_tx_t **a_tx)
{
    // Both base_token and quote_token must be provided (verificator requires single pair per TX)
    dap_ret_val_if_any(DEX_CANCEL_ALL_ERROR_INVALID_ARGUMENT, !a_net, !a_seller, !a_wallet, !a_tx, IS_ZERO_256(a_fee),
                       !a_base_token || !*a_base_token, !a_quote_token || !*a_quote_token);
    *a_tx = NULL;
    dap_chain_addr_t *l_wallet_addr_tmp = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_wallet_addr_tmp)
        return DEX_CANCEL_ALL_ERROR_WALLET;
    dap_chain_addr_t l_wallet_addr = *l_wallet_addr_tmp, l_net_addr = {};
    DAP_DELETE(l_wallet_addr_tmp);
    // Ensure wallet address matches provided seller address
    if (!dap_chain_addr_compare(&l_wallet_addr, a_seller))
        return DEX_CANCEL_ALL_ERROR_WALLET_MISMATCH;
    typedef struct cancel_entry {
        dap_hash_fast_t tail;
        int prev_idx;
        char sell_token[DAP_CHAIN_TICKER_SIZE_MAX];
        uint256_t value;
        struct cancel_entry *next;
    } cancel_entry_t;
    cancel_entry_t *l_head = NULL, *l_entry = NULL, *l_tmp;
    int l_count = 0;
    if (a_limit < 0)
        return DEX_CANCEL_ALL_ERROR_INVALID_ARGUMENT;
    if (a_limit == 0)
        a_limit = INT_MAX;
    if (s_dex_cache_enabled) {
        pthread_rwlock_rdlock(&s_dex_cache_rwlock);
        dex_seller_index_t *l_seller_bucket = NULL;
        HASH_FIND(hh, s_dex_seller_index, a_seller, sizeof(*a_seller), l_seller_bucket);
        if (l_seller_bucket && l_seller_bucket->entries) {
            dap_time_t l_now = dap_ledger_get_blockchain_time(a_net->pub.ledger);
            dex_order_cache_entry_t *e = NULL, *tmp = NULL;
            HASH_ITER(hh_seller_bucket, l_seller_bucket->entries, e, tmp)
            {
                if (e->ts_expires && l_now > e->ts_expires)
                    continue;
                if (a_base_token && dap_strcmp(e->pair_key_ptr->token_base, a_base_token))
                    continue;
                if (a_quote_token && dap_strcmp(e->pair_key_ptr->token_quote, a_quote_token))
                    continue;
                l_entry = DAP_NEW(cancel_entry_t);
                *l_entry =
                    (cancel_entry_t){.tail = e->level.match.tail, .prev_idx = e->level.match.prev_idx, .value = e->level.match.value};
                // side=0 (ASK): seller sells BASE → refund BASE; side=1 (BID): seller sells QUOTE → refund QUOTE
                const char *l_refund_tok = (e->side_version & 0x1) ? e->pair_key_ptr->token_quote : e->pair_key_ptr->token_base;
                dap_strncpy(l_entry->sell_token, l_refund_tok, sizeof(l_entry->sell_token) - 1);
                LL_PREPEND(l_head, l_entry);
                if (++l_count == a_limit)
                    break;
            }
        }
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
    } else {
        // Check pair whitelist before scanning ledger
        dex_pair_key_t l_key = {.net_id_quote = a_net->pub.id, .net_id_base = a_net->pub.id};
        dap_strncpy(l_key.token_quote, a_quote_token, sizeof(l_key.token_quote) - 1);
        dap_strncpy(l_key.token_base, a_base_token, sizeof(l_key.token_base) - 1);
        pthread_rwlock_rdlock(&s_dex_cache_rwlock);
        dex_pair_index_t *l_pb_check = NULL;
        HASH_FIND(hh, s_dex_pair_index, &l_key, DEX_PAIR_KEY_CMP_SIZE, l_pb_check);
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
        if (!l_pb_check)
            return DEX_CANCEL_ALL_ERROR_ORDERS_EMPTY; // Pair not whitelisted

        dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(a_net);
        if (!it)
            return DEX_CANCEL_ALL_ERROR_ORDERS_EMPTY;
        dap_time_t l_now = dap_ledger_get_blockchain_time(a_net->pub.ledger);
        // TODO: USE dap_ledger_get_list_tx_cond_outs
        for (dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it)) {
            int l_out_idx = 0;
            dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
            if (!l_out_cond)
                continue;
            if (l_out_cond->header.ts_expires && l_now > l_out_cond->header.ts_expires)
                continue;
            if (!dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, a_seller))
                continue;
            if (dap_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &it->cur_hash, l_out_idx, NULL))
                continue;
            const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &it->cur_hash);
            if (!l_sell_tok)
                continue;
            uint8_t l_side = 0;
            uint256_t l_price = uint256_0;
            s_dex_pair_normalize(l_sell_tok, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                                 l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key, &l_side, &l_price);
            if (dap_strcmp(l_key.token_base, a_base_token) || dap_strcmp(l_key.token_quote, a_quote_token))
                continue;

            // Find tail of order chain (for UPDATE/residual chains)
            dap_hash_fast_t l_tail =
                dap_ledger_get_final_chain_tx_hash(a_net->pub.ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &it->cur_hash, false);
            if (dap_hash_fast_is_blank(&l_tail))
                l_tail = it->cur_hash; // Fallback: no chain, use current hash

            // Load tail TX to get current value and prev_idx
            dap_chain_datum_tx_t *l_tail_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_tail);
            if (!l_tail_tx)
                continue;
            int l_tail_out_idx = 0;
            dap_chain_tx_out_cond_t *l_tail_out_cond =
                dap_chain_datum_tx_out_cond_get(l_tail_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_tail_out_idx);
            if (!l_tail_out_cond)
                continue;

            l_entry = DAP_NEW(cancel_entry_t);
            *l_entry = (cancel_entry_t){.tail = l_tail, .prev_idx = l_tail_out_idx, .value = l_tail_out_cond->header.value};
            dap_strncpy(l_entry->sell_token, l_sell_tok, sizeof(l_entry->sell_token) - 1);
            LL_PREPEND(l_head, l_entry);
            if (++l_count == a_limit)
                break;
        }
        dap_ledger_datum_iter_delete(it);
    }
    if (!l_head)
        return DEX_CANCEL_ALL_ERROR_ORDERS_EMPTY;

    dap_chain_net_srv_dex_cancel_all_error_t l_err = DEX_CANCEL_ALL_ERROR_OK;
    int l_err_line;
#define RET_ERR(_err)                                                                                                                      \
    do {                                                                                                                                   \
        l_err = (_err);                                                                                                                    \
        l_err_line = __LINE__;                                                                                                             \
        goto cancel_all_ret;                                                                                                               \
    } while (0)

    const char *l_native = a_net->pub.native_ticker;
    uint256_t l_net_fee = uint256_0, l_total_native_fee = a_fee, l_fee_transfer = uint256_0;
    bool l_net_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_addr);
    if (l_net_used)
        SUM_256_256(l_total_native_fee, l_net_fee, &l_total_native_fee);

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx)
        RET_ERR(DEX_CANCEL_ALL_ERROR_COMPOSE_TX);

    if (!IS_ZERO_256(l_total_native_fee)) {
        dap_list_t *l_list_fee_in = NULL;
        if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_native, &l_wallet_addr, &l_list_fee_in, l_total_native_fee,
                                                         &l_fee_transfer) == -101)
            l_list_fee_in =
                dap_ledger_get_list_tx_outs_with_val(a_net->pub.ledger, l_native, &l_wallet_addr, l_total_native_fee, &l_fee_transfer);
        if (!l_list_fee_in)
            RET_ERR(DEX_CANCEL_ALL_NOT_ENOUGH_CASH_FOR_FEE);
        uint256_t l_added = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_in);
        dap_list_free_full(l_list_fee_in, NULL);

        if (!EQUAL_256(l_added, l_fee_transfer))
            RET_ERR(DEX_CANCEL_ALL_NOT_ENOUGH_CASH_FOR_FEE);
    }

    // Add IN_COND items and aggregate refunds by token
    typedef struct {
        char token[DAP_CHAIN_TICKER_SIZE_MAX];
        uint256_t total;
    } token_sum_t;

    // Allocate exactly as many slots as orders (max possible unique tokens)
    token_sum_t *l_sums = DAP_NEW_Z_COUNT(token_sum_t, l_count);
    if (!l_sums)
        RET_ERR(DEX_CANCEL_ALL_ERROR_COMPOSE_TX);

    int l_token_count = 0;
    LL_FOREACH(l_head, l_entry)
    {
        if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_entry->tail, l_entry->prev_idx, 0) != 1) {
            DAP_DELETE(l_sums);
            RET_ERR(DEX_CANCEL_ALL_ERROR_COMPOSE_TX);
        }

        // Aggregate refund by token
        int l_tok_idx = -1;
        for (int i = 0; i < l_token_count; i++) {
            if (!dap_strcmp(l_sums[i].token, l_entry->sell_token)) {
                l_tok_idx = i;
                break;
            }
        }
        if (l_tok_idx < 0) {
            dap_strncpy(l_sums[l_token_count].token, l_entry->sell_token, sizeof(l_sums[0].token) - 1);
            l_tok_idx = l_token_count++;
        }
        SUM_256_256(l_sums[l_tok_idx].total, l_entry->value, &l_sums[l_tok_idx].total);
    }

    // Add aggregated refund OUTs
    for (int i = 0; i < l_token_count; i++) {
        if (dap_chain_datum_tx_add_out_std_item(&l_tx, a_seller, l_sums[i].total, l_sums[i].token, 0) != 1) {
            l_err = DEX_CANCEL_ALL_ERROR_COMPOSE_TX;
            break;
        }
    }
    DAP_DELETE(l_sums);
    if (l_err != DEX_CANCEL_ALL_ERROR_OK)
        RET_ERR(l_err);

    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1)
        RET_ERR(DEX_CANCEL_ALL_ERROR_COMPOSE_TX);

    if (l_net_used && dap_chain_datum_tx_add_out_std_item(&l_tx, &l_net_addr, l_net_fee, l_native, 0) != 1)
        RET_ERR(DEX_CANCEL_ALL_ERROR_COMPOSE_TX);

    if (!IS_ZERO_256(l_fee_transfer)) {
        uint256_t l_back = uint256_0;
        SUBTRACT_256_256(l_fee_transfer, l_total_native_fee, &l_back);
        if (!IS_ZERO_256(l_back) && dap_chain_datum_tx_add_out_std_item(&l_tx, &l_wallet_addr, l_back, l_native, 0) != 1)
            RET_ERR(DEX_CANCEL_ALL_ERROR_COMPOSE_TX);
    }
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    int l_sign_res = dap_chain_datum_tx_add_sign_item(&l_tx, l_key);
    dap_enc_key_delete(l_key);
    if (l_sign_res != 1)
        RET_ERR(DEX_CANCEL_ALL_ERROR_COMPOSE_TX);
#undef RET_ERR
cancel_all_ret:
    LL_FOREACH_SAFE(l_head, l_entry, l_tmp)
    {
        LL_DELETE(l_head, l_entry);
        DAP_DELETE(l_entry);
    }
    if (l_err) {
        log_it(L_ERROR, "%s(): Error %d at line %d", __FUNCTION__, l_err, l_err_line);
        dap_chain_datum_tx_delete(l_tx);
        l_tx = NULL;
    }
    *a_tx = l_tx;
    return l_err;
}

/* ============================================================================
 * CLI Handler
 * srv_dex command implementation
 * ============================================================================ */

// CLI helpers: TVL aggregation, slippage calculation, fee config parsing

#define TVL_PAIR_LEN (2 * DAP_CHAIN_TICKER_SIZE_MAX + 2)
typedef struct l_tvl_pair_sum {
    char pair[TVL_PAIR_LEN];
    uint256_t tvl;
    UT_hash_handle hh;
} l_tvl_pair_sum_t;

static inline int s_cmp_tvl_desc(l_tvl_pair_sum_t *a, l_tvl_pair_sum_t *b)
{
    return compare256(b->tvl, a->tvl);
}

// Slippage early-exit guard: check if current slippage exceeds limit
static inline bool s_slippage_exceeds_limit(uint256_t a_total_base, uint256_t a_total_quote, uint256_t a_best_ref, uint256_t a_max_sl,
                                            bool a_side_buy)
{
    if (IS_ZERO_256(a_total_base) || IS_ZERO_256(a_best_ref) || IS_ZERO_256(a_max_sl))
        return false;
    uint256_t l_vwap = uint256_0;
    DIV_256_COIN(a_total_quote, a_total_base, &l_vwap);
    uint256_t l_ratio = uint256_0;
    if (a_side_buy)
        DIV_256(l_vwap, a_best_ref, &l_ratio);
    else
        DIV_256(a_best_ref, l_vwap, &l_ratio);
    uint256_t l_one = GET_256_FROM_64(1000000000000000000ULL);
    if (compare256(l_ratio, l_one) < 0)
        return false;
    uint256_t l_delta = uint256_0;
    SUBTRACT_256_256(l_ratio, l_one, &l_delta);
    uint256_t l_pct = uint256_0;
    MULT_256_256(l_delta, GET_256_FROM_64(100ULL), &l_pct);
    return compare256(l_pct, a_max_sl) > 0;
}

// Slippage budget consumption helpers
static inline void s_consume_buy_base(uint256_t *a_budget, uint256_t a_rate, uint256_t a_value, uint256_t *a_total_base,
                                      uint256_t *a_total_quote, int *a_levels)
{
    uint256_t l_max_b = a_value, l_add_q = uint256_0;
    if (compare256(*a_budget, l_max_b) >= 0) {
        SUM_256_256(*a_total_base, l_max_b, a_total_base);
        MULT_256_COIN(l_max_b, a_rate, &l_add_q);
        SUM_256_256(*a_total_quote, l_add_q, a_total_quote);
        SUBTRACT_256_256(*a_budget, l_max_b, a_budget);
        (*a_levels)++;
    } else {
        MULT_256_COIN(*a_budget, a_rate, &l_add_q);
        if (!IS_ZERO_256(*a_budget))
            (*a_levels)++;
        SUM_256_256(*a_total_base, *a_budget, a_total_base);
        SUM_256_256(*a_total_quote, l_add_q, a_total_quote);
        *a_budget = uint256_0;
    }
}

static inline void s_consume_buy_quote(uint256_t *a_budget, uint256_t a_rate, uint256_t a_value, uint256_t *a_total_base,
                                       uint256_t *a_total_quote, int *a_levels)
{
    uint256_t l_max_q = uint256_0;
    MULT_256_COIN(a_value, a_rate, &l_max_q);
    if (compare256(*a_budget, l_max_q) >= 0) {
        SUM_256_256(*a_total_base, a_value, a_total_base);
        SUM_256_256(*a_total_quote, l_max_q, a_total_quote);
        SUBTRACT_256_256(*a_budget, l_max_q, a_budget);
        (*a_levels)++;
    } else {
        uint256_t l_take_b = uint256_0;
        DIV_256_COIN(*a_budget, a_rate, &l_take_b);
        if (!IS_ZERO_256(*a_budget))
            (*a_levels)++;
        SUM_256_256(*a_total_base, l_take_b, a_total_base);
        SUM_256_256(*a_total_quote, *a_budget, a_total_quote);
        *a_budget = uint256_0;
    }
}

static inline void s_consume_sell_pair_base(uint256_t *a_budget, uint256_t a_rate, uint256_t a_value, uint256_t *a_total_base,
                                            uint256_t *a_total_quote, int *a_levels)
{
    uint256_t l_max_b = uint256_0;
    DIV_256_COIN(a_value, a_rate, &l_max_b);
    if (compare256(*a_budget, l_max_b) >= 0) {
        SUM_256_256(*a_total_base, l_max_b, a_total_base);
        SUM_256_256(*a_total_quote, a_value, a_total_quote);
        SUBTRACT_256_256(*a_budget, l_max_b, a_budget);
        (*a_levels)++;
    } else {
        uint256_t l_take_q = uint256_0;
        MULT_256_COIN(*a_budget, a_rate, &l_take_q);
        if (!IS_ZERO_256(*a_budget))
            (*a_levels)++;
        SUM_256_256(*a_total_base, *a_budget, a_total_base);
        SUM_256_256(*a_total_quote, l_take_q, a_total_quote);
        *a_budget = uint256_0;
    }
}

static inline void s_consume_sell_pair_quote(uint256_t *a_budget, uint256_t a_rate, uint256_t a_value, uint256_t *a_total_base,
                                             uint256_t *a_total_quote, int *a_levels)
{
    uint256_t l_max_q = a_value, l_add_b = uint256_0;
    if (compare256(*a_budget, l_max_q) >= 0) {
        SUM_256_256(*a_total_quote, l_max_q, a_total_quote);
        DIV_256_COIN(l_max_q, a_rate, &l_add_b);
        SUM_256_256(*a_total_base, l_add_b, a_total_base);
        SUBTRACT_256_256(*a_budget, l_max_q, a_budget);
        (*a_levels)++;
    } else {
        DIV_256_COIN(*a_budget, a_rate, &l_add_b);
        if (!IS_ZERO_256(*a_budget))
            (*a_levels)++;
        SUM_256_256(*a_total_quote, *a_budget, a_total_quote);
        SUM_256_256(*a_total_base, l_add_b, a_total_base);
        *a_budget = uint256_0;
    }
}

// Parse fee_config from human-readable params (-fee_pct or -fee_native)
// Returns: 0 = not specified, 1 = valid config, -1 = error
// Uses uint256 math to avoid floating point
static int s_parse_fee_config_cli(int a_argc, char **a_argv, int a_arg_idx, uint8_t *a_out_cfg, const char **a_err_msg)
{
    const char *l_pct_str = NULL, *l_native_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_idx, a_argc, "-fee_pct", &l_pct_str);
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_idx, a_argc, "-fee_native", &l_native_str);
    if (l_pct_str && l_native_str) {
        *a_err_msg = "cannot use both -fee_pct and -fee_native";
        return -1;
    }
    if (l_pct_str) {
        // Parse percent (0 .. 12.7%, step 0.1%): "2.0" → 2×10^18 → /10^17 → 20
        uint256_t l_pct = dap_chain_balance_scan(l_pct_str);
        if (IS_ZERO_256(l_pct)) {
            *a_err_msg = "invalid -fee_pct value; expected decimal like '2.0' for 2%";
            return -1;
        }
        uint256_t l_mult = uint256_0;
        DIV_256(l_pct, GET_256_FROM_64(100000000000000000ULL), &l_mult); // /10^17 → "2.0" → 20
        if (compare256(l_mult, GET_256_FROM_64(127ULL)) > 0) {
            *a_err_msg = "-fee_pct must be [0 .. 12.7] (step 0.1)";
            return -1;
        }
        *a_out_cfg = 0x80 | (uint8_t)dap_chain_uint256_to(l_mult); // bit7=1 → QUOTE mode
        return 1;
    }
    if (l_native_str) {
        // Parse native multiplier (0 .. 1.27, step 0.01): "1.0" → 1×10^18 → /10^16 → 100
        uint256_t l_nat = dap_chain_balance_scan(l_native_str);
        if (IS_ZERO_256(l_nat)) {
            *a_err_msg = "invalid -fee_native value; expected decimal like '1.0' for 100% of global fee";
            return -1;
        }
        uint256_t l_mult_256 = uint256_0;
        DIV_256(l_nat, GET_256_FROM_64(10000000000000000ULL), &l_mult_256); // /10^16 → "1.0" → 100
        uint64_t l_mult = dap_chain_uint256_to(l_mult_256);
        if (l_mult > 127) {
            *a_err_msg = "-fee_native must be [0 .. 1.27] (step 0.01, 0 = use global fallback)";
            return -1;
        }
        *a_out_cfg = (uint8_t)l_mult;
        return 1;
    }
    return 0;
}

static int s_cli_srv_dex(int a_argc, char **a_argv, void **a_str_reply, int a_version)
{
    json_object **json_arr_reply = (json_object **)a_str_reply;
    int l_arg_index = 1;
    if (!*json_arr_reply || !json_object_is_type(*json_arr_reply, json_type_array))
        *json_arr_reply = json_object_new_array();
    if (a_argc < 3)
        return dap_json_rpc_error_add(*json_arr_reply, -1, "too few arguments"), -1;
    enum {
        CMD_ORDER,
        CMD_ORDERS,
        CMD_ORDERBOOK,
        CMD_STATUS,
        CMD_HISTORY,
        CMD_PURCHASE,
        CMD_PURCHASE_MULTI,
        CMD_PURCHASE_AUTO,
        CMD_CANCEL_ALL_BY_SELLER,
        CMD_TVL,
        CMD_SPREAD,
        CMD_SLIPPAGE,
        CMD_FIND_MATCHES,
        CMD_MIGRATE,
        CMD_PAIRS,
        CMD_DECREE,
        CMD_MAX_NUM
    } l_cmd = CMD_MAX_NUM;
    static const char *l_cmd_str[CMD_MAX_NUM] = {[CMD_ORDER] = "order",
                                                 [CMD_ORDERS] = "orders",
                                                 [CMD_ORDERBOOK] = "orderbook",
                                                 [CMD_STATUS] = "status",
                                                 [CMD_HISTORY] = "history",
                                                 [CMD_PURCHASE] = "purchase",
                                                 [CMD_PURCHASE_MULTI] = "purchase_multi",
                                                 [CMD_PURCHASE_AUTO] = "purchase_auto",
                                                 [CMD_CANCEL_ALL_BY_SELLER] = "cancel_all_by_seller",
                                                 [CMD_TVL] = "tvl",
                                                 [CMD_SPREAD] = "spread",
                                                 [CMD_SLIPPAGE] = "slippage",
                                                 [CMD_FIND_MATCHES] = "find_matches",
                                                 [CMD_MIGRATE] = "migrate",
                                                 [CMD_PAIRS] = "pairs",
                                                 [CMD_DECREE] = "decree"};

    if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "order") >= 0)
        l_cmd = CMD_ORDER;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "orders") >= 0)
        l_cmd = CMD_ORDERS;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "status") >= 0)
        l_cmd = CMD_STATUS;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "history") >= 0)
        l_cmd = CMD_HISTORY;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "purchase_multi") >= 0)
        l_cmd = CMD_PURCHASE_MULTI;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "purchase") >= 0)
        l_cmd = CMD_PURCHASE;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "purchase_auto") >= 0)
        l_cmd = CMD_PURCHASE_AUTO;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "orderbook") >= 0)
        l_cmd = CMD_ORDERBOOK;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "tvl") >= 0)
        l_cmd = CMD_TVL;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "spread") >= 0)
        l_cmd = CMD_SPREAD;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "slippage") >= 0)
        l_cmd = CMD_SLIPPAGE;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "find_matches") >= 0)
        l_cmd = CMD_FIND_MATCHES;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "migrate") >= 0)
        l_cmd = CMD_MIGRATE;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "cancel_all_by_seller") >= 0)
        l_cmd = CMD_CANCEL_ALL_BY_SELLER;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "pairs") >= 0)
        l_cmd = CMD_PAIRS;
    else if (dap_cli_server_cmd_check_option(a_argv, 1, 2, "decree") >= 0)
        l_cmd = CMD_DECREE;

    if (l_cmd == CMD_MAX_NUM)
        return dap_json_rpc_error_add(*json_arr_reply, -2, "unknown command %s", a_argv[l_arg_index]), -2;

    const char *l_net_str = NULL, *l_wallet_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, ++l_arg_index, a_argc, "-net", &l_net_str);
    if (!l_net_str)
        return dap_json_rpc_error_add(*json_arr_reply, -2, "-net required"), -2;

    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
    if (!l_net)
        return dap_json_rpc_error_add(*json_arr_reply, -3, "net not found"), -3;
    else if (dap_chain_net_get_load_mode(l_net))
        return dap_json_rpc_error_add(*json_arr_reply, -3, "command prohibited unless net %s is fully loaded", l_net_str), -3;

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_str);

    // Optional pair parsing and canonicalization (if -pair is provided)
    const char *l_pair_str = NULL, *l_ticker_base = NULL, *l_ticker_quote = NULL;
    char l_pair_storage[DAP_CHAIN_TICKER_SIZE_MAX * 2 + 4] = "";
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-pair", &l_pair_str);
    if (l_pair_str) {
        dap_strncpy(l_pair_storage, l_pair_str, sizeof(l_pair_storage) - 1);
        char *l_slash = strchr(l_pair_storage, '/'), *l_storage_end = l_pair_storage + sizeof(l_pair_storage) - 1;
        if (!l_slash || l_slash == l_pair_storage || l_slash >= l_storage_end)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad -pair \"%s\": missing or malformed separator", l_pair_str), -2;

        *l_slash++ = '\0';
        while (l_slash < l_storage_end && *l_slash == ' ')
            ++l_slash;
        if (*l_slash == '\0' || l_slash >= l_storage_end)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad -pair \"%s\": empty or invalid quote token", l_pair_str), -2;

        char *l_pair_base_end = l_pair_storage + strlen(l_pair_storage);
        while (l_pair_base_end > l_pair_storage && *(l_pair_base_end - 1) == ' ')
            *--l_pair_base_end = '\0';
        if (l_pair_base_end == l_pair_storage)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad -pair \"%s\": empty base token", l_pair_str), -2;

        int l_cmp = strcmp(l_pair_storage, l_slash);
        if (l_cmp == 0)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad -pair \"%s\": same token", l_pair_str), -2;
        if (l_cmp < 0) {
            l_ticker_base = l_pair_storage;
            l_ticker_quote = l_slash;
        } else {
            l_ticker_base = l_slash;
            l_ticker_quote = l_pair_storage;
        }
    }
    // Canonical pair string for output (BASE/QUOTE)
    char l_pair_canon_str[DAP_CHAIN_TICKER_SIZE_MAX * 2 + 4] = "";
    if (l_ticker_base && l_ticker_quote)
        snprintf(l_pair_canon_str, sizeof(l_pair_canon_str), "%s/%s", l_ticker_base, l_ticker_quote);

    // Optional fee parsing (if -fee is provided)
    const char *l_fee_str = NULL;
    uint256_t l_fee = uint256_0;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
    if (l_fee_str)
        l_fee = dap_chain_balance_scan(l_fee_str);

    // Optional value parsing (if -value is provided)
    const char *l_value_str = NULL;
    uint256_t l_value = uint256_0;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
    if (l_value_str)
        l_value = dap_chain_balance_scan(l_value_str);

    // Optional seller address parsing (if -seller is provided)
    const char *l_seller_str = NULL;
    dap_chain_addr_t l_seller_addr = {};
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-seller", &l_seller_str);
    if (l_seller_str) {
        dap_chain_addr_t *l_seller_tmp = dap_chain_addr_from_str(l_seller_str);
        if (!l_seller_tmp)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad seller address %s", l_seller_str), -2;
        l_seller_addr = *l_seller_tmp;
        DAP_DELETE(l_seller_tmp);
    }

    ++l_arg_index;
    int l_ret = 0;
    const char *l_err_str = "unknown error";
    dap_chain_datum_tx_t *l_datum = NULL;
    json_object *l_json_reply = NULL;
#define DEX_ERROR_STR(arr, code) ((size_t)(code) < sizeof(arr) / sizeof(arr[0]) && (arr)[code] ? (arr)[code] : "unknown error")
    switch (l_cmd) {
    case CMD_ORDER: {
        enum { SUBCMD_CREATE, SUBCMD_REMOVE, SUBCMD_UPDATE, SUBCMD_NONE } l_subcmd = SUBCMD_NONE;
        const char *l_order_hash_str = NULL;
        const int l_subcmd_idx = 2; // Position of subcommand after "srv_dex order"
        if (dap_cli_server_cmd_check_option(a_argv, l_subcmd_idx, a_argc, "create") >= l_subcmd_idx)
            l_subcmd = SUBCMD_CREATE;
        else if (dap_cli_server_cmd_check_option(a_argv, l_subcmd_idx, a_argc, "remove") >= l_subcmd_idx)
            l_subcmd = SUBCMD_REMOVE;
        else if (dap_cli_server_cmd_check_option(a_argv, l_subcmd_idx, a_argc, "update") >= l_subcmd_idx)
            l_subcmd = SUBCMD_UPDATE;

        switch (l_subcmd) {
        case SUBCMD_CREATE: {
            if (!l_value_str)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -value"), -2;
            if (!l_fee_str)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -fee"), -2;
            const char *l_sell = NULL, *l_buy = NULL, *l_rate_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_sell", &l_sell);
            if (!l_sell)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -token_sell"), -2;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_buy", &l_buy);
            if (!l_buy)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -token_buy"), -2;
            uint256_t l_rate = uint256_0;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-rate", &l_rate_str);
            if (l_rate_str)
                l_rate = dap_chain_balance_scan(l_rate_str);
            else
                return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -rate"), -2;

            const char *l_min_fill_pct_str = NULL, *l_min_fill_value_str = NULL, *l_fill_policy_str = NULL;
            int l_min_fill_pct = 0;
            uint8_t l_policy = 0;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-min_fill_pct", &l_min_fill_pct_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-min_fill_value", &l_min_fill_value_str);
            if (l_min_fill_pct_str && l_min_fill_value_str)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "-min_fill_pct and -min_fill_value are mutually exclusive"), -2;
            if (l_min_fill_value_str) {
                if (IS_ZERO_256(l_value))
                    return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -value \"%s\"", l_value_str), -2;
                // Absolute min_fill in sell token: compute percentage from l_value
                uint256_t l_min_fill_abs = dap_chain_balance_scan(l_min_fill_value_str);
                if (IS_ZERO_256(l_min_fill_abs))
                    return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -min_fill_value \"%s\"", l_min_fill_value_str), -2;
                if (compare256(l_min_fill_abs, l_value) < 0) {
                    // pct = ceil(min_fill_abs * 100 / l_value) to guarantee s_calc_pct(value, pct) >= min_fill_abs
                    uint256_t l_num = uint256_0, l_pct_256 = uint256_0;
                    MULT_256_256(l_min_fill_abs, GET_256_FROM_64(100ULL), &l_num);
                    SUM_256_256(l_num, l_value, &l_num);
                    SUBTRACT_256_256(l_num, uint256_1, &l_num); // (min_fill_abs * 100 + l_value - 1)
                    DIV_256(l_num, l_value, &l_pct_256);
                    l_min_fill_pct = (int)dap_chain_uint256_to(l_pct_256);
                }
                if (l_min_fill_pct > 100 || compare256(l_min_fill_abs, l_value) >= 0)
                    l_min_fill_pct = 100;
                // Auto-set policy to min_from_origin (bit 7)
                l_policy = (uint8_t)(0x80 | l_min_fill_pct);
                l_fill_policy_str = "min_from_origin";
            } else if (l_min_fill_pct_str) {
                l_min_fill_pct = atoi(l_min_fill_pct_str);
                if (l_min_fill_pct < 0)
                    l_min_fill_pct = 0;
                if (l_min_fill_pct > 100)
                    l_min_fill_pct = 100;
            }
            if (!l_min_fill_value_str) {
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fill_policy", &l_fill_policy_str);
                if (l_fill_policy_str) {
                    if (!strcasecmp(l_fill_policy_str, "AON")) {
                        if (l_min_fill_pct_str && l_min_fill_pct != 100)
                            return dap_json_rpc_error_add(*json_arr_reply, -2, "incompatible -fill_policy and -min_fill_pct"), -2;
                        l_policy = 100;
                        if (!l_min_fill_pct_str)
                            l_min_fill_pct = 100;
                    } else if (!strcasecmp(l_fill_policy_str, "min"))
                        l_policy = (uint8_t)l_min_fill_pct;
                    else if (!strcasecmp(l_fill_policy_str, "min_from_origin"))
                        l_policy = (uint8_t)(0x80 | l_min_fill_pct);
                    else
                        return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -fill_policy"), -2;
                } else {
                    if (l_min_fill_pct_str)
                        return dap_json_rpc_error_add(*json_arr_reply, -2, "unspecified -fill_policy for -min_fill_pct"), -2;
                    l_fill_policy_str = "PARTIAL_OK";
                }
            }
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
            if (!l_wallet)
                return dap_json_rpc_error_add(*json_arr_reply, -3, "wallet open failed"), -3;
            l_ret = dap_chain_net_srv_dex_create(l_net, l_buy, l_sell, l_value, l_rate, l_policy, l_fee, l_wallet, &l_datum);
            dap_chain_wallet_close(l_wallet);
            if (l_ret != DEX_CREATE_ERROR_OK) {
                l_err_str = DEX_ERROR_STR(s_create_error_str, l_ret);
                break;
            }

            l_json_reply = json_object_new_object();
            json_object_object_add(l_json_reply, "min_fill_pct", json_object_new_int(l_min_fill_pct));
            json_object_object_add(l_json_reply, "fill_policy", json_object_new_string(l_fill_policy_str));
        } break;
        case SUBCMD_REMOVE: {
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -order"), -2;
            dap_hash_fast_t l_order_hash = {};
            if (dap_chain_hash_fast_from_str(l_order_hash_str, &l_order_hash))
                return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -order \"%s\"", l_order_hash_str), -2;
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
            if (!l_wallet)
                return dap_json_rpc_error_add(*json_arr_reply, -3, "wallet open failed"), -3;
            l_ret = dap_chain_net_srv_dex_remove(l_net, &l_order_hash, l_fee, l_wallet, &l_datum);
            dap_chain_wallet_close(l_wallet);
            if (l_ret != DEX_REMOVE_ERROR_OK) {
                l_err_str = DEX_ERROR_STR(s_remove_error_str, l_ret);
                break;
            }
        } break;
        case SUBCMD_UPDATE: {
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -order"), -2;
            if (!l_value_str)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -value"), -2;
            dap_hash_fast_t l_root = {};
            if (dap_chain_hash_fast_from_str(l_order_hash_str, &l_root))
                return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -order \"%s\"", l_order_hash_str), -2;
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
            if (!l_wallet)
                return dap_json_rpc_error_add(*json_arr_reply, -3, "wallet \"%s\" open failed", l_wallet_str), -3;
            l_ret = dap_chain_net_srv_dex_update(l_net, &l_root, !IS_ZERO_256(l_value), l_value, l_fee, l_wallet, &l_datum);
            dap_chain_wallet_close(l_wallet);
            if (l_ret != DEX_UPDATE_ERROR_OK) {
                l_err_str = DEX_ERROR_STR(s_update_error_str, l_ret);
                break;
            }
        } break;
        default:
            return dap_json_rpc_error_add(*json_arr_reply, -1, "unknown subcommand %s", a_argv[l_subcmd_idx]), -1;
        }
    } break; // CMD_ORDER

    case CMD_ORDERS: {
        l_json_reply = json_object_new_object();
        json_object *l_arr = json_object_new_array();
        const char *l_limit_str = NULL, *l_offset_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-limit", &l_limit_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-offset", &l_offset_str);
        int l_limit = l_limit_str ? atoi(l_limit_str) : 0, l_offset = l_offset_str ? atoi(l_offset_str) : 0;

        dap_time_t l_now_ts = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        if (s_dex_cache_enabled) {
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            dex_pair_index_t *l_pi = NULL, *l_pi_tmp = NULL;
            HASH_ITER(hh, s_dex_pair_index, l_pi, l_pi_tmp)
            {
                if (l_pi->key.net_id_base.uint64 != l_net->pub.id.uint64 || l_pi->key.net_id_quote.uint64 != l_net->pub.id.uint64)
                    continue;
                if (l_pair_str && (dap_strcmp(l_pi->key.token_quote, l_ticker_quote) || dap_strcmp(l_pi->key.token_base, l_ticker_base)))
                    continue;
                char l_pair_buf[DAP_CHAIN_TICKER_SIZE_MAX * 2 + 2];
                if (!l_pair_str)
                    snprintf(l_pair_buf, sizeof(l_pair_buf), "%s/%s", l_pi->key.token_base, l_pi->key.token_quote);
                dex_order_cache_entry_t *l_entry = NULL, *l_tmp;
                HASH_ITER(hh_pair_bucket, l_pi->asks, l_entry, l_tmp)
                {
                    if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires)
                        continue;
                    if (l_seller_str && !dap_chain_addr_compare(l_entry->seller_addr_ptr, &l_seller_addr))
                        continue;
                    if (l_offset > 0) {
                        --l_offset;
                        continue;
                    }
                    json_object *o = json_object_new_object();
                    if (!l_pair_str)
                        json_object_object_add(o, "pair", json_object_new_string(l_pair_buf));
                    json_object_object_add(o, "side", json_object_new_string("ASK"));
                    json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&l_entry->level.match.root)));
                    json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&l_entry->level.match.tail)));
                    json_object_object_add(o, "price", json_object_new_string(dap_uint256_to_char_ex(l_entry->level.match.rate).frac));
                    json_object_object_add(o, "value_sell",
                                           json_object_new_string(dap_uint256_to_char_ex(l_entry->level.match.value).frac));
                    json_object_object_add(o, "filled_pct",
                                           json_object_new_int(s_calc_fill_pct(l_entry->value_base, l_entry->level.match.value)));
                    uint8_t l_mf = l_entry->level.match.min_fill;
                    json_object_object_add(o, "min_fill_pct", json_object_new_int(l_mf & 0x7F));
                    if (l_mf & 0x80)
                        json_object_object_add(o, "min_fill_from_origin", json_object_new_boolean(true));
                    json_object_object_add(o, "seller", json_object_new_string(dap_chain_addr_to_str_static(l_entry->seller_addr_ptr)));
                    json_object_object_add(o, "ts", json_object_new_uint64(l_entry->ts_created));
                    char l_ts_str[DAP_TIME_STR_SIZE];
                    dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), l_entry->ts_created);
                    json_object_object_add(o, "created", json_object_new_string(l_ts_str));
                    if (l_entry->ts_expires) {
                        dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), l_entry->ts_expires);
                        json_object_object_add(o, "expires", json_object_new_string(l_ts_str));
                    }
                    json_object_array_add(l_arr, o);
                    if (l_limit > 0 && !--l_limit)
                        goto cache_limit_reached;
                }
                HASH_ITER(hh_pair_bucket, l_pi->bids, l_entry, l_tmp)
                {
                    if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires)
                        continue;
                    if (l_seller_str && !dap_chain_addr_compare(l_entry->seller_addr_ptr, &l_seller_addr))
                        continue;
                    if (l_offset > 0) {
                        --l_offset;
                        continue;
                    }
                    json_object *o = json_object_new_object();
                    if (!l_pair_str)
                        json_object_object_add(o, "pair", json_object_new_string(l_pair_buf));
                    json_object_object_add(o, "side", json_object_new_string("BID"));
                    json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&l_entry->level.match.root)));
                    json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&l_entry->level.match.tail)));
                    json_object_object_add(o, "price", json_object_new_string(dap_uint256_to_char_ex(l_entry->level.match.rate).frac));
                    json_object_object_add(o, "value_sell",
                                           json_object_new_string(dap_uint256_to_char_ex(l_entry->level.match.value).frac));
                    json_object_object_add(o, "filled_pct",
                                           json_object_new_int(s_calc_fill_pct(l_entry->value_base, l_entry->level.match.value)));
                    uint8_t l_mf = l_entry->level.match.min_fill;
                    json_object_object_add(o, "min_fill_pct", json_object_new_int(l_mf & 0x7F));
                    if (l_mf & 0x80)
                        json_object_object_add(o, "min_fill_from_origin", json_object_new_boolean(true));
                    json_object_object_add(o, "seller", json_object_new_string(dap_chain_addr_to_str_static(l_entry->seller_addr_ptr)));
                    json_object_object_add(o, "ts", json_object_new_uint64(l_entry->ts_created));
                    char l_ts_str[DAP_TIME_STR_SIZE];
                    dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), l_entry->ts_created);
                    json_object_object_add(o, "created", json_object_new_string(l_ts_str));
                    if (l_entry->ts_expires) {
                        dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), l_entry->ts_expires);
                        json_object_object_add(o, "expires", json_object_new_string(l_ts_str));
                    }
                    json_object_array_add(l_arr, o);
                    if (l_limit > 0 && !--l_limit)
                        goto cache_limit_reached;
                }
            }
        cache_limit_reached:
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
            array_list_sort(json_object_get_array(l_arr), s_cmp_json_orders_by_ts);
        } else {
            // Check pair whitelist before scanning ledger (only if pair specified)
            if (l_pair_str) {
                dex_pair_key_t l_key_check = {.net_id_quote = l_net->pub.id, .net_id_base = l_net->pub.id};
                dap_strncpy(l_key_check.token_quote, l_ticker_quote, sizeof(l_key_check.token_quote) - 1);
                dap_strncpy(l_key_check.token_base, l_ticker_base, sizeof(l_key_check.token_base) - 1);
                pthread_rwlock_rdlock(&s_dex_cache_rwlock);
                dex_pair_index_t *l_pb_check = NULL;
                HASH_FIND(hh, s_dex_pair_index, &l_key_check, DEX_PAIR_KEY_CMP_SIZE, l_pb_check);
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
                if (!l_pb_check) {
                    json_object_object_add(l_json_reply, "orders", l_arr);
                    break; // Pair not whitelisted
                }
            }

            dap_chain_tx_out_cond_t *l_out_cond = NULL;
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            if (!it) {
                json_object_put(l_json_reply);
                json_object_put(l_arr);
                return dap_json_rpc_error_add(*json_arr_reply, -3, "ledger iterator failed"), -3;
            }
            for (dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it)) {
                int l_out_idx = 0;
                l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                if (!l_out_cond ||
                    /* dap_ledger_tx_is_used_out_item(l_ledger, it, l_out_idx, NULL) */ // FASTER, BUT UNSAFE DUE TO RACES ON LEDGER_ITEMS!
                    dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL))
                    continue;
                if (l_out_cond->header.ts_expires && l_now_ts > l_out_cond->header.ts_expires)
                    continue;
                if (l_seller_str && !dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_seller_addr))
                    continue;
                const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &it->cur_hash);
                if (!l_sell_tok)
                    continue;
                dex_pair_key_t l_key_o = {};
                uint8_t l_side_o = 0;
                uint256_t l_price = {};
                s_dex_pair_normalize(l_sell_tok, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                                     l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key_o, &l_side_o,
                                     &l_price);
                // Filter by pair if specified
                if (l_pair_str &&
                    (strcmp(l_key_o.token_quote, l_ticker_quote) || strcmp(l_key_o.token_base, l_ticker_base) ||
                     l_key_o.net_id_quote.uint64 != l_net->pub.id.uint64 || l_key_o.net_id_base.uint64 != l_net->pub.id.uint64))
                    continue;
                if (l_offset > 0) {
                    --l_offset;
                    continue;
                }
                json_object *o = json_object_new_object();
                if (!l_pair_str) {
                    char l_pair_buf[DAP_CHAIN_TICKER_SIZE_MAX * 2 + 2];
                    snprintf(l_pair_buf, sizeof(l_pair_buf), "%s/%s", l_key_o.token_base, l_key_o.token_quote);
                    json_object_object_add(o, "pair", json_object_new_string(l_pair_buf));
                }
                json_object_object_add(o, "side", json_object_new_string(l_side_o ? "BID" : "ASK"));
                dap_hash_fast_t l_root_hash = dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash)
                                                  ? it->cur_hash
                                                  : l_out_cond->subtype.srv_dex.order_root_hash;
                json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&l_root_hash)));
                json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&it->cur_hash)));
                json_object_object_add(o, "price", json_object_new_string(dap_uint256_to_char_ex(l_price).frac));
                json_object_object_add(o, "value_sell", json_object_new_string(dap_uint256_to_char_ex(l_out_cond->header.value).frac));
                uint8_t l_fill_pct = 0;
                s_dex_calc_order_fill_pct_ledger(l_net, &l_root_hash, &l_fill_pct);
                json_object_object_add(o, "filled_pct", json_object_new_int(l_fill_pct));
                uint8_t l_mf = l_out_cond->subtype.srv_dex.min_fill;
                json_object_object_add(o, "min_fill_pct", json_object_new_int(l_mf & 0x7F));
                if (l_mf & 0x80)
                    json_object_object_add(o, "min_fill_from_origin", json_object_new_boolean(true));
                json_object_object_add(o, "seller",
                                       json_object_new_string(dap_chain_addr_to_str_static(&l_out_cond->subtype.srv_dex.seller_addr)));
                json_object_object_add(o, "ts", json_object_new_uint64(l_tx->header.ts_created));
                char l_ts_str[DAP_TIME_STR_SIZE];
                dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), l_tx->header.ts_created);
                json_object_object_add(o, "created", json_object_new_string(l_ts_str));
                if (l_out_cond->header.ts_expires) {
                    dap_time_to_str_rfc822(l_ts_str, sizeof(l_ts_str), l_out_cond->header.ts_expires);
                    json_object_object_add(o, "expires", json_object_new_string(l_ts_str));
                }
                json_object_array_add(l_arr, o);
                if (l_limit > 0 && !--l_limit)
                    break;
            }
            dap_ledger_datum_iter_delete(it);
        }
        json_object_object_add(l_json_reply, "orders", l_arr);
    } break; // ORDERS

    case CMD_ORDERBOOK: {
        if (!l_pair_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -pair"), -2;
        const char *l_depth_str = NULL, *l_tick_price_str = NULL, *l_tick_dec_str = NULL;
        int l_depth = 20;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-depth", &l_depth_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tick_price", &l_tick_price_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tick", &l_tick_dec_str);
        bool l_cumul = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-cumulative") >= l_arg_index;

        if (l_depth_str) {
            l_depth = atoi(l_depth_str);
            if (l_depth < 1)
                l_depth = 1;
            else if (l_depth > 1000)
                l_depth = 1000; // depth cap
        }

        uint256_t l_step = uint256_0;
        bool l_has_step = false;
        // Tick step: either explicit price step or derived from decimals
        if (l_tick_price_str) {
            l_step = dap_chain_balance_scan(l_tick_price_str);
            l_has_step = !IS_ZERO_256(l_step);
        } else if (l_tick_dec_str) {
            int l_decml = atoi(l_tick_dec_str);
            if (l_decml < 0)
                l_decml = 0;
            else if (l_decml > 18)
                l_decml = 18;
            uint256_t l_ten18 = GET_256_FROM_64(1000000000000000000ULL), l_denom = GET_256_FROM_64(1ULL), l_ten = GET_256_FROM_64(10ULL);
            for (int i = 0; i < l_decml; ++i) {
                MULT_256_256(l_denom, l_ten, &l_denom);
            }
            DIV_256(l_ten18, l_denom, &l_step);
            l_has_step = !IS_ZERO_256(l_step);
        }

        dex_orderbook_level_t *l_asks_tbl = NULL, *l_bids_tbl = NULL;
        // Early-stop thresholds for binning to improve performance at large books
        uint256_t l_ask_stop_price = uint256_0, l_bid_stop_price = uint256_0;
        bool l_ask_stop_set = false, l_bid_stop_set = false;
        int l_asks_bins_count = 0, l_bids_bins_count = 0;

        dap_time_t l_now_ts = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        l_json_reply = json_object_new_object();
        if (s_dex_cache_enabled) {
            dex_pair_key_t key = {.net_id_quote = l_net->pub.id, .net_id_base = l_net->pub.id};
            dap_strncpy(key.token_quote, l_ticker_quote, sizeof(key.token_quote) - 1);
            dap_strncpy(key.token_base, l_ticker_base, sizeof(key.token_base) - 1);
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            dex_pair_index_t *l_pair_bucket = NULL;
            HASH_FIND(hh, s_dex_pair_index, &key, DEX_PAIR_KEY_CMP_SIZE, l_pair_bucket);
            if (l_pair_bucket) {
                dex_order_cache_entry_t *l_entry = NULL, *l_tmp = NULL;
                HASH_ITER(hh_pair_bucket, l_pair_bucket->asks, l_entry, l_tmp)
                {
                    if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires)
                        continue;
                    uint256_t l_bin_pair = l_entry->level.match.rate;
                    if (l_has_step) {
                        DIV_256(l_bin_pair, l_step, &l_bin_pair);
                        MULT_256_256(l_bin_pair, l_step, &l_bin_pair);
                        if (l_ask_stop_set && compare256(l_bin_pair, l_ask_stop_price) > 0)
                            break;
                    }
                    dex_orderbook_level_t *l_lvl = NULL;
                    HASH_FIND(hh, l_asks_tbl, &l_bin_pair, sizeof(l_bin_pair), l_lvl);
                    if (!l_lvl) {
                        l_lvl = DAP_NEW_Z(dex_orderbook_level_t);
                        l_lvl->price = l_bin_pair;
                        HASH_ADD(hh, l_asks_tbl, price, sizeof(l_lvl->price), l_lvl);
                        l_asks_bins_count++;
                        if (l_has_step && !l_ask_stop_set && l_asks_bins_count == l_depth) {
                            l_ask_stop_price = l_bin_pair;
                            l_ask_stop_set = true;
                        }
                    }
                    SUM_256_256(l_lvl->vol_base, l_entry->level.match.value, &l_lvl->vol_base);
                    uint256_t l_add_q = {};
                    MULT_256_COIN(l_entry->level.match.value, l_entry->level.match.rate, &l_add_q);
                    SUM_256_256(l_lvl->vol_quote, l_add_q, &l_lvl->vol_quote);
                    l_lvl->orders++;
                }
                dex_order_cache_entry_t *l_bids_last = HASH_LAST_EX(hh_pair_bucket, l_pair_bucket->bids);
                for (l_entry = l_bids_last; l_entry; l_entry = (dex_order_cache_entry_t *)l_entry->hh_pair_bucket.prev) {
                    if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires)
                        continue;
                    uint256_t l_bin_pair = l_entry->level.match.rate;
                    if (l_has_step) {
                        DIV_256(l_bin_pair, l_step, &l_bin_pair);
                        MULT_256_256(l_bin_pair, l_step, &l_bin_pair);
                        if (l_bid_stop_set && compare256(l_bin_pair, l_bid_stop_price) < 0)
                            break;
                    }
                    dex_orderbook_level_t *l_lvl = NULL;
                    HASH_FIND(hh, l_bids_tbl, &l_bin_pair, sizeof(l_bin_pair), l_lvl);
                    if (!l_lvl) {
                        l_lvl = DAP_NEW_Z(dex_orderbook_level_t);
                        l_lvl->price = l_bin_pair;
                        HASH_ADD(hh, l_bids_tbl, price, sizeof(l_lvl->price), l_lvl);
                        l_bids_bins_count++;
                        if (l_has_step && !l_bid_stop_set && l_bids_bins_count == l_depth) {
                            l_bid_stop_price = l_bin_pair;
                            l_bid_stop_set = true;
                        }
                    }
                    SUM_256_256(l_lvl->vol_quote, l_entry->level.match.value, &l_lvl->vol_quote);
                    uint256_t l_add_b = {};
                    DIV_256_COIN(l_entry->level.match.value, l_entry->level.match.rate, &l_add_b);
                    SUM_256_256(l_lvl->vol_base, l_add_b, &l_lvl->vol_base);
                    l_lvl->orders++;
                }
            }
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
        } else {
            // Check pair whitelist before scanning ledger
            dex_pair_key_t l_key_check = {.net_id_quote = l_net->pub.id, .net_id_base = l_net->pub.id};
            dap_strncpy(l_key_check.token_quote, l_ticker_quote, sizeof(l_key_check.token_quote) - 1);
            dap_strncpy(l_key_check.token_base, l_ticker_base, sizeof(l_key_check.token_base) - 1);
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            dex_pair_index_t *l_pb_check = NULL;
            HASH_FIND(hh, s_dex_pair_index, &l_key_check, DEX_PAIR_KEY_CMP_SIZE, l_pb_check);
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
            if (!l_pb_check) {
                json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_canon_str));
                json_object_object_add(l_json_reply, "asks", json_object_new_array());
                json_object_object_add(l_json_reply, "bids", json_object_new_array());
                s_add_units(l_json_reply, l_ticker_base, l_ticker_quote);
                break; // Pair not whitelisted
            }

            dap_chain_tx_out_cond_t *l_out_cond = NULL;
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            if (!it) {
                json_object_put(l_json_reply);
                return dap_json_rpc_error_add(*json_arr_reply, -3, "ledger iterator failed"), -3;
            }
            for (dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it)) {
                int l_out_idx = 0;
                l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                if (!l_out_cond ||
                    /* dap_ledger_tx_is_used_out_item(l_ledger, it, l_out_idx, NULL) */ // FASTER, BUT UNSAFE DUE TO RACES ON LEDGER_ITEMS!
                    dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL))
                    continue;
                if (l_out_cond->header.ts_expires && l_now_ts > l_out_cond->header.ts_expires)
                    continue;
                const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &it->cur_hash);
                if (!l_sell_tok)
                    continue;
                dex_pair_key_t l_key_o = {};
                uint8_t l_side_o = 0;
                uint256_t l_price = {};
                s_dex_pair_normalize(l_sell_tok, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                                     l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key_o, &l_side_o,
                                     &l_price);
                if (dap_strcmp(l_key_o.token_quote, l_ticker_quote) || dap_strcmp(l_key_o.token_base, l_ticker_base))
                    continue;
                uint256_t l_bin_pair = l_price;
                if (l_has_step) {
                    DIV_256(l_bin_pair, l_step, &l_bin_pair);
                    MULT_256_256(l_bin_pair, l_step, &l_bin_pair);
                }
                dex_orderbook_level_t *l_lvl = NULL;
                if (l_side_o == DEX_SIDE_ASK) {
                    HASH_FIND(hh, l_asks_tbl, &l_bin_pair, sizeof(l_bin_pair), l_lvl);
                    if (!l_lvl) {
                        l_lvl = DAP_NEW_Z(dex_orderbook_level_t);
                        l_lvl->price = l_bin_pair;
                        HASH_ADD(hh, l_asks_tbl, price, sizeof(l_lvl->price), l_lvl);
                    }
                    SUM_256_256(l_lvl->vol_base, l_out_cond->header.value, &l_lvl->vol_base);
                    uint256_t l_add_quote;
                    MULT_256_COIN(l_out_cond->header.value, l_price, &l_add_quote);
                    SUM_256_256(l_lvl->vol_quote, l_add_quote, &l_lvl->vol_quote);
                } else {
                    HASH_FIND(hh, l_bids_tbl, &l_bin_pair, sizeof(l_bin_pair), l_lvl);
                    if (!l_lvl) {
                        l_lvl = DAP_NEW_Z(dex_orderbook_level_t);
                        l_lvl->price = l_bin_pair;
                        HASH_ADD(hh, l_bids_tbl, price, sizeof(l_lvl->price), l_lvl);
                    }
                    SUM_256_256(l_lvl->vol_quote, l_out_cond->header.value, &l_lvl->vol_quote);
                    uint256_t l_add_base;
                    DIV_256_COIN(l_out_cond->header.value, l_price, &l_add_base);
                    SUM_256_256(l_lvl->vol_base, l_add_base, &l_lvl->vol_base);
                }
                ++l_lvl->orders;
            }
            dap_ledger_datum_iter_delete(it);
        }
        // sort
        HASH_SORT(l_asks_tbl, s_cmp_agg_level_price_asc);
        HASH_SORT(l_bids_tbl, s_cmp_agg_level_price_desc);
        // emit
        json_object *l_arr_asks = json_object_new_array(), *l_arr_bids = json_object_new_array();
        json_object_object_add(l_json_reply, "last_update_ts", json_object_new_uint64(dap_ledger_get_blockchain_time(l_net->pub.ledger)));
        json_object_object_add(l_json_reply, "request_ts", json_object_new_uint64(dap_time_now()));

        // Best prices (first entries after sorting)
        if (l_asks_tbl) {
            json_object_object_add(l_json_reply, "best_ask", json_object_new_string(dap_uint256_to_char_ex(l_asks_tbl->price).frac));
        }
        if (l_bids_tbl) {
            json_object_object_add(l_json_reply, "best_bid", json_object_new_string(dap_uint256_to_char_ex(l_bids_tbl->price).frac));
        }
        if (l_asks_tbl && l_bids_tbl) {
            uint256_t l_mid = {}, l_spread = {}, l_sum = {};
            // mid = (ask + bid)/2, spread = ask - bid in QUOTE/BASE
            SUM_256_256(l_sum, l_asks_tbl->price, &l_sum);
            SUM_256_256(l_sum, l_bids_tbl->price, &l_sum);
            DIV_256(l_sum, GET_256_FROM_64(2ULL), &l_mid);
            SUBTRACT_256_256(l_asks_tbl->price, l_bids_tbl->price, &l_spread);
            json_object_object_add(l_json_reply, "mid", json_object_new_string(dap_uint256_to_char_ex(l_mid).frac));
            json_object_object_add(l_json_reply, "spread", json_object_new_string(dap_uint256_to_char_ex(l_spread).frac));
        }
        // Emit asks side (ascending prices); cumulative if requested
        uint256_t l_cumul_base = uint256_0, l_cumul_quote = uint256_0;
        int l_count = 0;
        dex_orderbook_level_t *l_iter = NULL, *l_tmp;
        HASH_ITER(hh, l_asks_tbl, l_iter, l_tmp)
        {
            json_object *o = json_object_new_object();
            json_object_object_add(o, "price", json_object_new_string(dap_uint256_to_char_ex(l_iter->price).frac));
            json_object_object_add(o, "volume_base", json_object_new_string(dap_uint256_to_char_ex(l_iter->vol_base).frac));
            json_object_object_add(o, "volume_quote", json_object_new_string(dap_uint256_to_char_ex(l_iter->vol_quote).frac));
            json_object_object_add(o, "orders", json_object_new_int((int)l_iter->orders));
            if (l_cumul) {
                SUM_256_256(l_cumul_base, l_iter->vol_base, &l_cumul_base);
                SUM_256_256(l_cumul_quote, l_iter->vol_quote, &l_cumul_quote);
                json_object_object_add(o, "cum_base", json_object_new_string(dap_uint256_to_char_ex(l_cumul_base).frac));
                json_object_object_add(o, "cum_quote", json_object_new_string(dap_uint256_to_char_ex(l_cumul_quote).frac));
            }
            json_object_array_add(l_arr_asks, o);
            HASH_DEL(l_asks_tbl, l_iter);
            DAP_DELETE(l_iter);
            if (++l_count >= l_depth)
                break;
        }
        // Emit bids side (descending prices); cumulative if requested
        l_cumul_base = uint256_0, l_cumul_quote = uint256_0;
        l_count = 0;
        HASH_ITER(hh, l_bids_tbl, l_iter, l_tmp)
        {
            json_object *o = json_object_new_object();
            json_object_object_add(o, "price", json_object_new_string(dap_uint256_to_char_ex(l_iter->price).frac));
            json_object_object_add(o, "volume_base", json_object_new_string(dap_uint256_to_char_ex(l_iter->vol_base).frac));
            json_object_object_add(o, "volume_quote", json_object_new_string(dap_uint256_to_char_ex(l_iter->vol_quote).frac));
            json_object_object_add(o, "orders", json_object_new_int((int)l_iter->orders));
            if (l_cumul) {
                SUM_256_256(l_cumul_base, l_iter->vol_base, &l_cumul_base);
                SUM_256_256(l_cumul_quote, l_iter->vol_quote, &l_cumul_quote);
                json_object_object_add(o, "cum_base", json_object_new_string(dap_uint256_to_char_ex(l_cumul_base).frac));
                json_object_object_add(o, "cum_quote", json_object_new_string(dap_uint256_to_char_ex(l_cumul_quote).frac));
            }
            json_object_array_add(l_arr_bids, o);
            HASH_DEL(l_bids_tbl, l_iter);
            DAP_DELETE(l_iter);
            if (++l_count >= l_depth)
                break;
        }
        // free
        if (l_asks_tbl) {
            HASH_ITER(hh, l_asks_tbl, l_iter, l_tmp)
            {
                HASH_DELETE(hh, l_asks_tbl, l_iter);
                DAP_DELETE(l_iter);
            }
        }
        if (l_bids_tbl) {
            HASH_ITER(hh, l_bids_tbl, l_iter, l_tmp)
            {
                HASH_DELETE(hh, l_bids_tbl, l_iter);
                DAP_DELETE(l_iter);
            }
        }
        json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_canon_str));
        json_object_object_add(l_json_reply, "asks", l_arr_asks);
        json_object_object_add(l_json_reply, "bids", l_arr_bids);
        s_add_units(l_json_reply, l_ticker_base, l_ticker_quote);
    } break; // ORDERBOOK

    case CMD_STATUS: {
        if (!l_pair_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -pair"), -2;

        uint32_t l_asks_cnt = 0, l_bids_cnt = 0;
        uint256_t l_best_ask = uint256_0, l_best_bid_inv = uint256_0;
        bool l_has_ask = false, l_has_bid = false;
        dap_time_t l_now_ts = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        if (s_dex_cache_enabled) {
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            if (l_seller_str) {
                dex_seller_index_t *l_sb = NULL;
                HASH_FIND(hh, s_dex_seller_index, &l_seller_addr, sizeof(l_seller_addr), l_sb);
                if (l_sb && l_sb->entries) {
                    dex_order_cache_entry_t *e = NULL, *tmp;
                    HASH_ITER(hh_seller_bucket, l_sb->entries, e, tmp)
                    {
                        if (e->ts_expires && l_now_ts > e->ts_expires)
                            continue;
                        if (dap_strcmp(e->pair_key_ptr->token_quote, l_ticker_quote) ||
                            dap_strcmp(e->pair_key_ptr->token_base, l_ticker_base))
                            continue;
                        if ((e->side_version & 0x1) == DEX_SIDE_ASK) {
                            if (!l_has_ask || compare256(e->level.match.rate, l_best_ask) < 0) {
                                l_best_ask = e->level.match.rate;
                                l_has_ask = true;
                            }
                            l_asks_cnt++;
                        } else {
                            if (!l_has_bid || compare256(e->level.match.rate, l_best_bid_inv) > 0) {
                                l_best_bid_inv = e->level.match.rate;
                                l_has_bid = true;
                            }
                            l_bids_cnt++;
                        }
                    }
                }
            } else {
                dex_pair_key_t l_key = {.net_id_quote = l_net->pub.id, .net_id_base = l_net->pub.id};
                dap_strncpy(l_key.token_quote, l_ticker_quote, sizeof(l_key.token_quote) - 1);
                dap_strncpy(l_key.token_base, l_ticker_base, sizeof(l_key.token_base) - 1);
                dex_pair_index_t *l_pair_bucket = NULL;
                HASH_FIND(hh, s_dex_pair_index, &l_key, DEX_PAIR_KEY_CMP_SIZE, l_pair_bucket);
                if (l_pair_bucket) {
                    dex_order_cache_entry_t *l_entry;
                    for (l_entry = l_pair_bucket->asks; l_entry; l_entry = (dex_order_cache_entry_t *)l_entry->hh_pair_bucket.next) {
                        if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires)
                            continue;
                        if (!l_has_ask) {
                            l_best_ask = l_entry->level.match.rate;
                            l_has_ask = true;
                        }
                        l_asks_cnt++;
                    }
                    dex_order_cache_entry_t *l_last_bid = HASH_LAST_EX(hh_pair_bucket, l_pair_bucket->bids);
                    for (l_entry = l_last_bid; l_entry; l_entry = (dex_order_cache_entry_t *)l_entry->hh_pair_bucket.prev) {
                        if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires)
                            continue;
                        if (!l_has_bid) {
                            l_best_bid_inv = l_entry->level.match.rate;
                            l_has_bid = true;
                        }
                        l_bids_cnt++;
                    }
                }
            }
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
        } else {
            // Check pair whitelist before scanning ledger
            dex_pair_key_t l_key = {.net_id_quote = l_net->pub.id, .net_id_base = l_net->pub.id};
            dap_strncpy(l_key.token_quote, l_ticker_quote, sizeof(l_key.token_quote) - 1);
            dap_strncpy(l_key.token_base, l_ticker_base, sizeof(l_key.token_base) - 1);
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            dex_pair_index_t *l_pb_check = NULL;
            HASH_FIND(hh, s_dex_pair_index, &l_key, DEX_PAIR_KEY_CMP_SIZE, l_pb_check);
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
            // If pair not whitelisted, return empty response (no liquidity)
            if (l_pb_check) {
                dap_chain_tx_out_cond_t *l_out_cond = NULL;
                dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
                if (!it)
                    return dap_json_rpc_error_add(*json_arr_reply, -3, "ledger iterator failed"), -3;
                for (dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it)) {
                    int l_out_idx = 0;
                    l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                    if (!l_out_cond || /* dap_ledger_tx_is_used_out_item(l_ledger, it, l_out_idx, NULL) */ // FASTER, BUT UNSAFE DUE TO
                                                                                                           // RACES ON LEDGER_ITEMS!
                        dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL))
                        continue;
                    if (l_out_cond->header.ts_expires && l_now_ts > l_out_cond->header.ts_expires)
                        continue;
                    if (l_seller_str && !dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_seller_addr))
                        continue;
                    const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &it->cur_hash);
                    if (!l_sell_tok)
                        continue;
                    uint8_t l_side_o = 0;
                    uint256_t l_price = {};
                    s_dex_pair_normalize(l_sell_tok, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                                         l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key, &l_side_o,
                                         &l_price);
                    if (strcmp(l_key.token_quote, l_ticker_quote) || strcmp(l_key.token_base, l_ticker_base))
                        continue;
                    if (l_side_o == DEX_SIDE_ASK) {
                        if (!l_has_ask || compare256(l_price, l_best_ask) < 0) {
                            l_best_ask = l_price;
                            l_has_ask = true;
                        }
                        l_asks_cnt++;
                    } else {
                        if (!l_has_bid || compare256(l_price, l_best_bid_inv) > 0) {
                            l_best_bid_inv = l_price;
                            l_has_bid = true;
                        }
                        l_bids_cnt++;
                    }
                }
                dap_ledger_datum_iter_delete(it);
            }
        }

        l_json_reply = json_object_new_object();
        json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_canon_str));
        json_object_object_add(l_json_reply, "asks", json_object_new_int((int)l_asks_cnt));
        json_object_object_add(l_json_reply, "bids", json_object_new_int((int)l_bids_cnt));
        json_object_object_add(l_json_reply, "count", json_object_new_int((int)(l_asks_cnt + l_bids_cnt)));
        if (l_has_ask)
            json_object_object_add(l_json_reply, "best_ask", json_object_new_string(dap_uint256_to_char_ex(l_best_ask).frac));
        if (l_has_bid)
            json_object_object_add(l_json_reply, "best_bid", json_object_new_string(dap_uint256_to_char_ex(l_best_bid_inv).frac));
        if (l_has_ask && l_has_bid) {
            uint256_t l_mid = uint256_0, l_spread = uint256_0, l_sum = uint256_0;
            SUM_256_256(l_sum, l_best_ask, &l_sum);
            SUM_256_256(l_sum, l_best_bid_inv, &l_sum);
            DIV_256(l_sum, GET_256_FROM_64(2ULL), &l_mid);
            SUBTRACT_256_256(l_best_ask, l_best_bid_inv, &l_spread);
            json_object_object_add(l_json_reply, "mid", json_object_new_string(dap_uint256_to_char_ex(l_mid).frac));
            json_object_object_add(l_json_reply, "spread", json_object_new_string(dap_uint256_to_char_ex(l_spread).frac));
        }
    } break; // STATUS

    case CMD_TVL: {
        const char *l_token = NULL, *l_by_str = NULL, *l_top_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_token);
        if (!l_token)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -token"), -2;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-by", &l_by_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-top", &l_top_str);

        int l_topN = l_top_str ? atoi(l_top_str) : 0;
        if (l_topN < 0)
            l_topN = 0;
        else if (l_topN > 1000)
            l_topN = 1000;
        uint256_t l_sum = uint256_0;
        dap_time_t l_now_ts = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        l_tvl_pair_sum_t *l_pair_sums = NULL;
        if (s_dex_cache_enabled) {
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            if (!s_dex_pair_index) {
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
                goto tvl_output;
            }
            for (dex_pair_index_t *l_pb = s_dex_pair_index; l_pb; l_pb = (dex_pair_index_t *)l_pb->hh.next) {
                dex_order_cache_entry_t *l_head = NULL, *e, *tmp;
                if (!dap_strcmp(l_pb->key.token_quote, l_token))
                    l_head = l_pb->bids;
                else if (!dap_strcmp(l_pb->key.token_base, l_token))
                    l_head = l_pb->asks;
                if (!l_head)
                    continue;
                HASH_ITER(hh_pair_bucket, l_head, e, tmp)
                {
                    if (e->ts_expires && l_now_ts > e->ts_expires)
                        continue;
                    SUM_256_256(l_sum, e->level.match.value, &l_sum);
                    if (l_by_str && !dap_strcmp(l_by_str, "pair")) {
                        char l_key_buf[TVL_PAIR_LEN];
                        // Emit pair as BASE/QUOTE → key.buy_token/key.sell_token
                        snprintf(l_key_buf, sizeof(l_key_buf), "%s/%s", l_pb->key.token_base, l_pb->key.token_quote);
                        l_tvl_pair_sum_t *l_ps = NULL;
                        HASH_FIND_STR(l_pair_sums, l_key_buf, l_ps);
                        if (!l_ps) {
                            l_ps = DAP_NEW_Z(l_tvl_pair_sum_t);
                            dap_strncpy(l_ps->pair, l_key_buf, sizeof(l_ps->pair) - 1);
                            HASH_ADD_STR(l_pair_sums, pair, l_ps);
                        }
                        SUM_256_256(l_ps->tvl, e->level.match.value, &l_ps->tvl);
                    }
                }
            }
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
        } else {
            // Ledger fallback: sum active unspent SRV_DEX outs that sell <token>
            dap_chain_tx_out_cond_t *l_out_cond = NULL;
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            if (!it)
                return dap_json_rpc_error_add(*json_arr_reply, -3, "ledger iterator failed"), -3;
            for (dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it)) {
                int l_out_idx = 0;
                l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                if (!l_out_cond || dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL))
                    continue;
                if (l_out_cond->header.ts_expires && l_now_ts > l_out_cond->header.ts_expires)
                    continue;
                const char *l_sell_tok_tx = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &it->cur_hash);
                if (!l_sell_tok_tx)
                    continue;
                if (!dap_strcmp(l_sell_tok_tx, l_token)) {
                    SUM_256_256(l_sum, l_out_cond->header.value, &l_sum);
                    if (l_by_str && !dap_strcmp(l_by_str, "pair")) {
                        dex_pair_key_t l_key_o = {};
                        uint8_t l_side_o = 0;
                        uint256_t l_price_o = uint256_0;
                        s_dex_pair_normalize(l_sell_tok_tx, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                                             l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key_o, &l_side_o,
                                             &l_price_o);
                        char l_key_buf[TVL_PAIR_LEN];
                        // Emit pair as BASE/QUOTE → l_key_o.buy_token/l_key_o.sell_token
                        snprintf(l_key_buf, sizeof(l_key_buf), "%s/%s", l_key_o.token_base, l_key_o.token_quote);
                        l_tvl_pair_sum_t *l_ps = NULL;
                        HASH_FIND_STR(l_pair_sums, l_key_buf, l_ps);
                        if (!l_ps) {
                            l_ps = DAP_NEW_Z(l_tvl_pair_sum_t);
                            dap_strncpy(l_ps->pair, l_key_buf, sizeof(l_ps->pair) - 1);
                            HASH_ADD_STR(l_pair_sums, pair, l_ps);
                        }
                        SUM_256_256(l_ps->tvl, l_out_cond->header.value, &l_ps->tvl);
                    }
                }
            }
            dap_ledger_datum_iter_delete(it);
        }
    tvl_output:
        l_json_reply = json_object_new_object();
        json_object_object_add(l_json_reply, "token", json_object_new_string(l_token));
        json_object_object_add(l_json_reply, "tvl", json_object_new_string(dap_uint256_to_char_ex(l_sum).frac));

        json_object *l_units = json_object_new_object();
        json_object_object_add(l_units, "tvl", json_object_new_string(l_token));
        json_object_object_add(l_json_reply, "units", l_units);

        if (l_pair_sums) {
            HASH_SORT(l_pair_sums, s_cmp_tvl_desc);
            json_object *l_jarr = json_object_new_array();
            int l_emitted = 0;
            for (l_tvl_pair_sum_t *l_ps = l_pair_sums; l_ps && (l_topN == 0 || l_emitted < l_topN);
                 l_ps = (l_tvl_pair_sum_t *)l_ps->hh.next, ++l_emitted) {
                json_object *o = json_object_new_object();
                json_object_object_add(o, "pair", json_object_new_string(l_ps->pair));
                json_object_object_add(o, "tvl", json_object_new_string(dap_uint256_to_char_ex(l_ps->tvl).frac));
                json_object_array_add(l_jarr, o);
            }
            l_tvl_pair_sum_t *l_cur, *l_tmp;
            HASH_ITER(hh, l_pair_sums, l_cur, l_tmp)
            {
                HASH_DELETE(hh, l_pair_sums, l_cur);
                DAP_DELETE(l_cur);
            }
            json_object_object_add(l_json_reply, "by_pair", l_jarr);
        }
    } break; // TVL

    case CMD_SPREAD: {
        if (!l_pair_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -pair"), -2;
        bool l_verbose = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-verbose") >= l_arg_index;
        uint256_t l_best_ask = uint256_0, l_best_bid = uint256_0;
        bool l_has_ask = false, l_has_bid = false;
        dap_hash_fast_t l_best_ask_root = {0}, l_best_ask_tail = {0}, l_best_bid_root = {0}, l_best_bid_tail = {0};
        dap_time_t l_now_ts = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        if (s_dex_cache_enabled) {
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            dex_pair_key_t l_key = (dex_pair_key_t){.net_id_quote = l_net->pub.id, .net_id_base = l_net->pub.id};
            dap_strncpy(l_key.token_quote, l_ticker_quote, sizeof(l_key.token_quote) - 1);
            dap_strncpy(l_key.token_base, l_ticker_base, sizeof(l_key.token_base) - 1);
            dex_pair_index_t *l_pb = NULL;
            HASH_FIND(hh, s_dex_pair_index, &l_key, DEX_PAIR_KEY_CMP_SIZE, l_pb);
            if (l_pb) {
                for (dex_order_cache_entry_t *e = l_pb->asks; e; e = (dex_order_cache_entry_t *)e->hh_pair_bucket.next) {
                    if (e->ts_expires && l_now_ts > e->ts_expires)
                        continue;
                    l_best_ask = e->level.match.rate;
                    l_has_ask = true;
                    if (l_verbose) {
                        l_best_ask_root = e->level.match.root;
                        l_best_ask_tail = e->level.match.tail;
                    }
                    break;
                }
                dex_order_cache_entry_t *l_last_bid = HASH_LAST_EX(hh_pair_bucket, l_pb->bids);
                for (dex_order_cache_entry_t *e = l_last_bid; e; e = (dex_order_cache_entry_t *)e->hh_pair_bucket.prev) {
                    if (e->ts_expires && l_now_ts > e->ts_expires)
                        continue;
                    l_best_bid = e->level.match.rate;
                    l_has_bid = true;
                    if (l_verbose) {
                        l_best_bid_root = e->level.match.root;
                        l_best_bid_tail = e->level.match.tail;
                    }
                    break;
                }
            }
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
        } else {
            // Check pair whitelist before scanning ledger
            dex_pair_key_t l_key_check = (dex_pair_key_t){.net_id_quote = l_net->pub.id, .net_id_base = l_net->pub.id};
            dap_strncpy(l_key_check.token_quote, l_ticker_quote, sizeof(l_key_check.token_quote) - 1);
            dap_strncpy(l_key_check.token_base, l_ticker_base, sizeof(l_key_check.token_base) - 1);
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            dex_pair_index_t *l_pb_check = NULL;
            HASH_FIND(hh, s_dex_pair_index, &l_key_check, DEX_PAIR_KEY_CMP_SIZE, l_pb_check);
            pthread_rwlock_unlock(&s_dex_cache_rwlock);

            // Ledger fallback: scan best ask/bid for the pair
            dap_chain_tx_out_cond_t *l_out_cond = NULL;
            dap_ledger_datum_iter_t *it = NULL;
            if (l_pb_check) {
                it = dap_ledger_datum_iter_create(l_net);
                if (!it)
                    return dap_json_rpc_error_add(*json_arr_reply, -3, "ledger iterator failed"), -3;
                for (dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it)) {
                    int l_out_idx = 0;
                    l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                    if (!l_out_cond)
                        continue;
                    if (dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL))
                        continue;
                    if (l_out_cond->header.ts_expires && l_now_ts > l_out_cond->header.ts_expires)
                        continue;
                    const char *l_sell_tok_tx = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &it->cur_hash);
                    if (!l_sell_tok_tx)
                        continue;
                    dex_pair_key_t l_key = (dex_pair_key_t){};
                    uint8_t l_side = 0;
                    uint256_t l_price = uint256_0;
                    s_dex_pair_normalize(l_sell_tok_tx, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                                         l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key, &l_side,
                                         &l_price);
                    if (dap_strcmp(l_key.token_quote, l_ticker_quote) || dap_strcmp(l_key.token_base, l_ticker_base))
                        continue;
                    if (l_side == DEX_SIDE_ASK) {
                        if (!l_has_ask || compare256(l_price, l_best_ask) < 0) {
                            l_best_ask = l_price;
                            l_has_ask = true;
                            if (l_verbose) {
                                l_best_ask_root = l_out_cond->subtype.srv_dex.order_root_hash;
                                l_best_ask_tail = it->cur_hash;
                            }
                        }
                    } else {
                        if (!l_has_bid || compare256(l_price, l_best_bid) > 0) {
                            l_best_bid = l_price;
                            l_has_bid = true;
                            if (l_verbose) {
                                l_best_bid_root = l_out_cond->subtype.srv_dex.order_root_hash;
                                l_best_bid_tail = it->cur_hash;
                            }
                        }
                    }
                }
                dap_ledger_datum_iter_delete(it);
            }
        }

        l_json_reply = json_object_new_object();
        json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_canon_str));
        if (l_has_ask && l_has_bid) {
            uint256_t l_spread = l_best_ask;
            SUBTRACT_256_256(l_spread, l_best_bid, &l_spread);
            json_object_object_add(l_json_reply, "best_ask", json_object_new_string(dap_uint256_to_char_ex(l_best_ask).frac));
            json_object_object_add(l_json_reply, "best_bid", json_object_new_string(dap_uint256_to_char_ex(l_best_bid).frac));
            json_object_object_add(l_json_reply, "spread", json_object_new_string(dap_uint256_to_char_ex(l_spread).frac));
            if (l_verbose) {
                json_object_object_add(l_json_reply, "best_ask_root",
                                       json_object_new_string(dap_hash_fast_to_str_static(&l_best_ask_root)));
                json_object_object_add(l_json_reply, "best_ask_tail",
                                       json_object_new_string(dap_hash_fast_to_str_static(&l_best_ask_tail)));
                json_object_object_add(l_json_reply, "best_bid_root",
                                       json_object_new_string(dap_hash_fast_to_str_static(&l_best_bid_root)));
                json_object_object_add(l_json_reply, "best_bid_tail",
                                       json_object_new_string(dap_hash_fast_to_str_static(&l_best_bid_tail)));
            }
        } else
            json_object_object_add(l_json_reply, "error", json_object_new_string("not enough asks/bids"));
    } break; // SPREAD

    case CMD_HISTORY: {
        const char *l_from_str = NULL, *l_to_str = NULL, *l_bucket_str = NULL, *l_view_str = NULL, *l_type_str = NULL;
        const char *l_buyer_str = NULL, *l_order_hash_str = NULL;
        bool l_fill_missing = dap_cli_server_cmd_check_option(a_argv, 2, a_argc, "-fill") >= 2;

        dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-from", &l_from_str);
        dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-to", &l_to_str);
        dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-bucket", &l_bucket_str);
        dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-view", &l_view_str);
        dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-type", &l_type_str);
        dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-order", &l_order_hash_str);
        if (!l_pair_str && !l_order_hash_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -pair | -order"), -2;
        uint64_t l_bucket = l_bucket_str ? strtoull(l_bucket_str, NULL, 10) : 0ULL;
        if (l_fill_missing && !l_bucket)
            l_bucket = s_dex_history_bucket_sec ? s_dex_history_bucket_sec : DAP_SEC_PER_DAY;

        uint64_t l_t_from = 0, l_t_to = 0;
        if (l_from_str && !s_parse_natural_time(l_net->pub.ledger, l_from_str, &l_t_from))
            l_t_from = strtoull(l_from_str, NULL, 10);
        if (l_to_str && !s_parse_natural_time(l_net->pub.ledger, l_to_str, &l_t_to))
            l_t_to = strtoull(l_to_str, NULL, 10);
        if (l_t_from && l_t_to && l_t_to < l_t_from) {
            uint64_t t = l_t_from;
            l_t_from = l_t_to;
            l_t_to = t;
        }

        const char *l_limit_str = NULL, *l_offset_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-limit", &l_limit_str);
        dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-offset", &l_offset_str);
        dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "-buyer", &l_buyer_str);
        dap_chain_addr_t l_buyer_addr;
        if (l_buyer_str) {
            dap_chain_addr_t *l_buyer_tmp = dap_chain_addr_from_str(l_buyer_str);
            if (!l_buyer_tmp)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "bad buyer addr %s", l_buyer_str), -2;
            l_buyer_addr = *l_buyer_tmp;
            DAP_DELETE(l_buyer_tmp);
        }

        int l_limit = l_limit_str ? atoi(l_limit_str) : 0, l_offset = l_offset_str ? atoi(l_offset_str) : 0;
        enum { VIEW_EVENTS, VIEW_SUMMARY, VIEW_OHLC, VIEW_VOLUME } l_view = VIEW_EVENTS;
        uint8_t l_filter_flags = 0;
        if (l_view_str) {
            if (!strcmp(l_view_str, "events")) {
                l_view = VIEW_EVENTS;
                if (l_order_hash_str)
                    l_filter_flags = DEX_OP_ANY;
            } else if (!strcmp(l_view_str, "summary")) {
                l_view = VIEW_SUMMARY;
                if (l_order_hash_str)
                    l_filter_flags = DEX_OP_ANY;
            } else if (!strcmp(l_view_str, "ohlc")) {
                l_filter_flags = DEX_OP_MARKET;
                l_view = VIEW_OHLC;
            } else if (!strcmp(l_view_str, "volume")) {
                l_filter_flags = DEX_OP_MARKET | DEX_OP_TARGET;
                l_view = VIEW_VOLUME;
            } else
                return dap_json_rpc_error_add(*json_arr_reply, -2, "bad view %s, use: events | summary | ohlc | volume", l_view_str), -2;
        }
        if (l_type_str) {
            if (!strcmp(l_type_str, "market"))
                l_filter_flags = DEX_OP_MARKET;
            else if (!strcmp(l_type_str, "trade"))
                l_filter_flags = DEX_OP_MARKET | DEX_OP_TARGET;
            else if (l_view == VIEW_OHLC)
                return dap_json_rpc_error_add(*json_arr_reply, -2, " wrong type %s for view ohlc, use: market | trade", l_type_str), -2;
            else if (!strcmp(l_type_str, "targeted"))
                l_filter_flags = DEX_OP_TARGET;
            else if (l_view == VIEW_VOLUME)
                return dap_json_rpc_error_add(*json_arr_reply, -2, " wrong type %s for view volume, use: market | targeted | trade",
                                              l_type_str),
                       -2;
            else if (!strcmp(l_type_str, "order"))
                l_filter_flags = DEX_OP_CREATE;
            else if (!strcmp(l_type_str, "update"))
                l_filter_flags = DEX_OP_UPDATE;
            else if (!strcmp(l_type_str, "cancel"))
                l_filter_flags = DEX_OP_CANCEL;
            else if (!strcmp(l_type_str, "all"))
                l_filter_flags = DEX_OP_ANY;
            else
                return dap_json_rpc_error_add(*json_arr_reply, -2,
                                              "bad type %s, use: all | trade | market | targeted | order | update | cancel", l_type_str),
                       -2;
        }
        switch (l_view) {
        case VIEW_EVENTS:
            if (l_bucket_str || l_fill_missing)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "-bucket/-fill are invalid for -view events"), -2;
            // TODO: Implement ledger fallback for events view when cache is disabled.
            if (!s_dex_history_enabled || !s_dex_cache_enabled)
                return dap_json_rpc_error_add(*json_arr_reply, -1, "events view requires both history_cache and cache_enabled"), -1;
            break;
        case VIEW_SUMMARY:
            if (l_bucket_str || l_fill_missing)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "-bucket/-fill are invalid for -view summary"), -2;
            if (!s_dex_history_enabled || !s_dex_cache_enabled)
                return dap_json_rpc_error_add(*json_arr_reply, -1, "summary view requires both history_cache and cache_enabled"), -1;
            break;
        case VIEW_OHLC:
        case VIEW_VOLUME:
            if (l_limit_str || l_offset_str)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "-limit/-offset are valid only for -view events"), -2;
            // TODO: Distinguish MARKET vs TARGETED in ledger fallback if possible.
            if (!s_dex_history_enabled && (l_filter_flags & (DEX_OP_MARKET | DEX_OP_TARGET)))
                l_filter_flags = DEX_OP_MARKET | DEX_OP_TARGET;
        default:
            break;
        }

        dap_hash_fast_t l_order_root = {}, l_given_hash = {};
        if (l_order_hash_str) {
            if (dap_chain_hash_fast_from_str(l_order_hash_str, &l_given_hash))
                return dap_json_rpc_error_add(*json_arr_reply, -2, "bad order hash %s", l_order_hash_str), -2;
            // Resolve to root: try cache first, then ledger
            bool l_found = false;
            if (s_dex_cache_enabled) {
                pthread_rwlock_rdlock(&s_dex_cache_rwlock);
                dex_order_cache_entry_t *l_by_tail = NULL;
                HASH_FIND(level.hh_tail, s_dex_index_by_tail, &l_given_hash, sizeof(dap_hash_fast_t), l_by_tail);
                if (l_by_tail) {
                    l_order_root = l_by_tail->level.match.root;
                    l_found = true;
                }
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
            }
            if (!l_found) {
                // Fallback: find root via ledger
                dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_given_hash);
                if (l_tx) {
                    dap_chain_tx_out_cond_t *l_out = NULL;
                    l_order_root =
                        dap_ledger_get_first_chain_tx_hash_ex(l_net->pub.ledger, l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out);
                    if (dap_hash_fast_is_blank(&l_order_root)) {
                        if (!l_out)
                            return dap_json_rpc_error_add(*json_arr_reply, -2, "ambiguous order root for tx %s", l_order_hash_str), -2;
                        l_order_root = l_given_hash; // OUT_COND with blank root => this tx is the root
                    }
                } else
                    return dap_json_rpc_error_add(*json_arr_reply, -2, "order hash %s not found", l_order_hash_str), -2;
            }
        }
        if (l_order_hash_str) {
            bool l_pair_found = false;
            if (s_dex_cache_enabled) {
                pthread_rwlock_rdlock(&s_dex_cache_rwlock);
                dex_order_cache_entry_t *l_entry = NULL;
                HASH_FIND(level.hh, s_dex_orders_cache, &l_order_root, sizeof(l_order_root), l_entry);
                if (l_entry && l_entry->pair_key_ptr) {
                    if (l_pair_str) {
                        if (dap_strcmp(l_ticker_base, l_entry->pair_key_ptr->token_base) ||
                            dap_strcmp(l_ticker_quote, l_entry->pair_key_ptr->token_quote))
                            return dap_json_rpc_error_add(*json_arr_reply, -2, "order %s does not match pair %s", l_order_hash_str,
                                                          l_pair_canon_str),
                                   pthread_rwlock_unlock(&s_dex_cache_rwlock), -2;
                    } else {
                        l_ticker_base = l_entry->pair_key_ptr->token_base;
                        l_ticker_quote = l_entry->pair_key_ptr->token_quote;
                        snprintf(l_pair_canon_str, sizeof(l_pair_canon_str), "%s/%s", l_ticker_base, l_ticker_quote);
                    }
                    l_pair_found = true;
                }
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
            }
            if (!l_pair_found && s_dex_history_enabled) {
                pthread_rwlock_rdlock(&s_dex_cache_rwlock);
                dex_hist_pair_t *l_pair = NULL, *l_pair_tmp;
                HASH_ITER(hh, s_dex_history, l_pair, l_pair_tmp)
                {
                    dex_hist_order_idx_t *l_oi = NULL;
                    HASH_FIND(hh, l_pair->order_idx, &l_order_root, sizeof(dap_hash_fast_t), l_oi);
                    if (l_oi) {
                        if (l_pair_str) {
                            if (dap_strcmp(l_ticker_base, l_pair->key.token_base) || dap_strcmp(l_ticker_quote, l_pair->key.token_quote))
                                return dap_json_rpc_error_add(*json_arr_reply, -2, "order %s does not match pair %s", l_order_hash_str,
                                                              l_pair_canon_str),
                                       pthread_rwlock_unlock(&s_dex_cache_rwlock), -2;
                        } else {
                            l_ticker_base = l_pair->key.token_base;
                            l_ticker_quote = l_pair->key.token_quote;
                            snprintf(l_pair_canon_str, sizeof(l_pair_canon_str), "%s/%s", l_ticker_base, l_ticker_quote);
                        }
                        l_pair_found = true;
                        break;
                    }
                }
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
            }
            if (!l_pair_found) {
                dap_chain_datum_tx_t *l_root_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_order_root);
                if (l_root_tx) {
                    dap_chain_tx_out_cond_t *l_out =
                        dap_chain_datum_tx_out_cond_get(l_root_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
                    const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &l_order_root);
                    if (l_out && l_sell_tok && *l_sell_tok) {
                        dex_pair_key_t l_key = {};
                        uint8_t l_side = 0;
                        uint256_t l_price = uint256_0;
                        s_dex_pair_normalize(l_sell_tok, l_out->subtype.srv_dex.sell_net_id, l_out->subtype.srv_dex.buy_token,
                                             l_out->subtype.srv_dex.buy_net_id, l_out->subtype.srv_dex.rate, &l_key, &l_side, &l_price);
                        if (*l_key.token_base && *l_key.token_quote) {
                            if (l_pair_str) {
                                if (dap_strcmp(l_ticker_base, l_key.token_base) || dap_strcmp(l_ticker_quote, l_key.token_quote))
                                    return dap_json_rpc_error_add(*json_arr_reply, -2, "order %s does not match pair %s", l_order_hash_str,
                                                                  l_pair_canon_str),
                                           -2;
                            } else {
                                size_t l_base_len = strnlen(l_key.token_base, sizeof(l_key.token_base));
                                size_t l_quote_len = strnlen(l_key.token_quote, sizeof(l_key.token_quote));
                                if (l_base_len + l_quote_len + 2 > sizeof(l_pair_storage))
                                    return dap_json_rpc_error_add(*json_arr_reply, -2, "pair buffer overflow for order %s",
                                                                  l_order_hash_str),
                                           -2;
                                dap_strncpy(l_pair_storage, l_key.token_base, sizeof(l_pair_storage) - 1);
                                l_ticker_base = l_pair_storage;
                                l_ticker_quote = l_pair_storage + l_base_len + 1;
                                dap_strncpy((char *)l_ticker_quote, l_key.token_quote, sizeof(l_pair_storage) - l_base_len - 1);
                                snprintf(l_pair_canon_str, sizeof(l_pair_canon_str), "%s/%s", l_ticker_base, l_ticker_quote);
                            }
                            l_pair_found = true;
                        }
                    }
                }
            }
            if (!l_pair_found)
                return dap_json_rpc_error_add(*json_arr_reply, -2,
                                              l_pair_str ? "pair not resolved for order %s" : "pair not resolved for order %s, use -pair",
                                              l_order_hash_str),
                       -2;
        }

        l_json_reply = json_object_new_object();
        json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_canon_str));
        json_object_object_add(l_json_reply, "request_ts", json_object_new_int64((int64_t)dap_time_now()));
        if (l_order_hash_str)
            json_object_object_add(l_json_reply, "order_root", json_object_new_string(dap_hash_fast_to_str_static(&l_order_root)));
        dex_pair_key_t l_key = (dex_pair_key_t){.net_id_quote = l_net->pub.id, .net_id_base = l_net->pub.id};
        dap_strncpy(l_key.token_quote, l_ticker_quote, sizeof(l_key.token_quote) - 1);
        dap_strncpy(l_key.token_base, l_ticker_base, sizeof(l_key.token_base) - 1);

        // Raw events mode: requires both caches for correct classification
        if (l_view == VIEW_EVENTS) {
            json_object *l_arr = json_object_new_array();
            int l_count = s_history_get_raw_events(l_net, &l_key, l_t_from, l_t_to ? l_t_to : UINT64_MAX, l_filter_flags, l_limit, l_offset,
                                                   l_seller_str ? &l_seller_addr : NULL, l_buyer_str ? &l_buyer_addr : NULL,
                                                   l_order_hash_str ? &l_order_root : NULL, l_arr);
            const char *l_events_key = l_order_hash_str                                 ? "history"
                                       : l_type_str && !dap_strcmp(l_type_str, "order") ? "orders"
                                       : l_type_str && (!dap_strcmp(l_type_str, "trade") || !dap_strcmp(l_type_str, "market") ||
                                                        !dap_strcmp(l_type_str, "targeted"))
                                           ? "trades"
                                           : "events";
            json_object_object_add(l_json_reply, l_events_key, l_arr);
            json_object_object_add(l_json_reply, "count", json_object_new_int(l_count));
            s_add_units(l_json_reply, l_ticker_base, l_ticker_quote);
            break;
        }

        if (l_view == VIEW_SUMMARY) {
            json_object *l_arr = json_object_new_array();
            int l_count = s_history_get_summary(l_net, &l_key, l_filter_flags, l_limit, l_offset, l_seller_str ? &l_seller_addr : NULL,
                                                l_order_hash_str ? &l_order_root : NULL, l_arr);
            json_object_object_add(l_json_reply, "summary", l_arr);
            json_object_object_add(l_json_reply, "count", json_object_new_int(l_count));
            s_add_units(l_json_reply, l_ticker_base, l_ticker_quote);
            break;
        }

        // Common variables for totals
        bool l_want_ohlc = (l_view == VIEW_OHLC);
        uint256_t l_sum_base = uint256_0, l_sum_quote = uint256_0, l_spot_price = uint256_0;
        int q = 0;

        if (s_dex_history_enabled) {
            q = s_history_get_totals(&l_key, l_t_from, l_t_to ? l_t_to : UINT64_MAX, l_seller_str ? &l_seller_addr : NULL,
                                     l_buyer_str ? &l_buyer_addr : NULL, l_order_hash_str ? &l_order_root : NULL, l_filter_flags,
                                     &l_sum_base, &l_sum_quote, &l_spot_price, NULL);
            json_object *l_arr = json_object_new_array();
            int l_count = l_bucket ? s_history_build_ohlcv_series(&l_key, l_t_from, l_t_to ? l_t_to : UINT64_MAX, l_bucket, l_want_ohlc,
                                                                  l_fill_missing, l_seller_str ? &l_seller_addr : NULL,
                                                                  l_buyer_str ? &l_buyer_addr : NULL,
                                                                  l_order_hash_str ? &l_order_root : NULL, l_filter_flags, l_arr)
                                   : 0;
            json_object_object_add(l_json_reply, "market_only", json_object_new_boolean(true));
            json_object_object_add(l_json_reply, l_want_ohlc ? "ohlc" : "volume", l_arr);
            if (l_bucket)
                json_object_object_add(l_json_reply, "count", json_object_new_int(l_count));
        } else {
            // Ledger fallback: aggregate OHLC/volume over time window
            dex_bucket_agg_t *l_buckets = NULL;
            uint64_t l_spot_ts = 0;
            // Fast path for -order: walk spenders chain instead of scanning whole ledger
            if (l_order_hash_str) do {
                // Find root TX and its DEX OUT_COND
                dap_chain_datum_tx_t *l_root_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_order_root);
                if (!l_root_tx)
                    break; // Order not found, empty result
                int l_out_idx = 0;
                dap_chain_tx_out_cond_t *l_prev_out =
                    dap_chain_datum_tx_out_cond_get(l_root_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                if (!l_prev_out)
                    break;
                const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &l_order_root);
                if (!l_sell_tok)
                    break;
                // Normalize pair once (all events in chain have same pair)
                uint8_t l_side = 0;
                uint256_t l_price_canon = uint256_0;
                s_dex_pair_normalize(l_sell_tok, l_prev_out->subtype.srv_dex.sell_net_id, l_prev_out->subtype.srv_dex.buy_token,
                                        l_prev_out->subtype.srv_dex.buy_net_id, l_prev_out->subtype.srv_dex.rate, &l_key, &l_side,
                                        &l_price_canon);
                if (dap_strcmp(l_key.token_quote, l_ticker_quote) || dap_strcmp(l_key.token_base, l_ticker_base))
                    break; // Pair mismatch, empty result
                // Walk the chain
                dap_hash_fast_t l_cur_hash = l_order_root;
                while (true) {
                    dap_hash_fast_t l_spender_hash = {};
                    if (!dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &l_cur_hash, l_out_idx, &l_spender_hash) ||
                        dap_hash_fast_is_blank(&l_spender_hash))
                        break; // Not spent = order still open
                    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_spender_hash);
                    if (!l_tx)
                        break;
                    // Find our residual (same order_root) - key check FIRST
                    dap_chain_tx_out_cond_t *l_residual = NULL;
                    int l_res_idx = 0;
                    while ((l_residual = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_res_idx)) !=
                            NULL) {
                        if (dap_hash_fast_compare(&l_residual->subtype.srv_dex.order_root_hash, &l_order_root))
                            break;
                        l_res_idx++;
                    }
                    // Determine event type and compute executed amount
                    dap_time_t l_ts = l_tx->header.ts_created;
                    bool l_in_range = (!l_t_from || l_ts >= (dap_time_t)l_t_from) && (!l_t_to || l_ts <= (dap_time_t)l_t_to);
                    bool l_is_trade = false;
                    uint256_t l_executed = uint256_0;
                    if (l_residual) {
                        // Has our residual: partial EXCHANGE or UPDATE
                        if ((dex_tx_type_t)l_residual->subtype.srv_dex.tx_type == DEX_TX_TYPE_EXCHANGE) {
                            // Partial EXCHANGE: executed = prev - residual
                            if (compare256(l_prev_out->header.value, l_residual->header.value) <= 0) {
                                log_it(L_CRITICAL, "Chain walk: residual %s >= prev value %s (data corruption?)",
                                        dap_uint256_to_char_ex(l_residual->header.value).frac,
                                        dap_uint256_to_char_ex(l_prev_out->header.value).frac);
                                break;
                            }
                            SUBTRACT_256_256(l_prev_out->header.value, l_residual->header.value, &l_executed);
                            l_is_trade = true;
                        }
                        // Continue chain
                        l_cur_hash = l_spender_hash;
                        l_out_idx = l_res_idx;
                        l_prev_out = l_residual;
                    } else {
                        // No our residual: full EXCHANGE or INVALIDATE
                        if (s_dex_verify_payout(l_tx, l_net, l_prev_out->subtype.srv_dex.buy_token,
                                                &l_prev_out->subtype.srv_dex.seller_addr)) {
                            l_executed = l_prev_out->header.value;
                            // Dust refund adjustment for full execution
                            uint256_t l_srv_fee_req = uint256_0;
                            const dap_chain_addr_t *l_srv_addr_ptr = NULL;
                            if (!dap_strcmp(l_sell_tok, l_net->pub.native_ticker) &&
                                dap_chain_addr_compare(&l_prev_out->subtype.srv_dex.seller_addr, &s_dex_service_fee_addr)) {
                                pthread_rwlock_rdlock(&s_dex_cache_rwlock);
                                dex_pair_index_t *l_pi_fee = s_dex_pair_index_get(&l_key);
                                uint8_t l_fee_cfg = l_pi_fee ? l_pi_fee->key.fee_config : 0;
                                l_srv_fee_req = s_dex_get_srv_fee(l_fee_cfg);
                                pthread_rwlock_unlock(&s_dex_cache_rwlock);
                                if (!IS_ZERO_256(l_srv_fee_req))
                                    l_srv_addr_ptr = &s_dex_service_fee_addr;
                            }
                            s_adjust_exec_for_dust_refund(l_tx, &l_prev_out->subtype.srv_dex.seller_addr, l_sell_tok, l_srv_addr_ptr,
                                                            l_srv_fee_req, &l_executed);
                            l_is_trade = true;
                        }
                        // End of chain (full execution or INVALIDATE)
                    }
                    // Accumulate volume for trades
                    if (l_is_trade && l_in_range &&
                        (!l_seller_str || dap_chain_addr_compare(&l_prev_out->subtype.srv_dex.seller_addr, &l_seller_addr))) {
                        bool l_buyer_match = true;
                        if (l_buyer_str) {
                            dap_chain_addr_t l_buyer_tx = s_dex_extract_buyer_addr(l_tx, l_net->pub.id);
                            l_buyer_match = dap_chain_addr_compare(&l_buyer_tx, &l_buyer_addr);
                        }
                        if (l_buyer_match) {
                            dex_bq_t l_bq = s_exec_to_canon_base_quote(l_executed, l_price_canon, l_side);
                            SUM_256_256(l_sum_base, l_bq.base, &l_sum_base);
                            SUM_256_256(l_sum_quote, l_bq.quote, &l_sum_quote);
                            if (l_ts >= l_spot_ts) {
                                l_spot_ts = l_ts;
                                l_spot_price = l_price_canon;
                            }
                            q++;
                            if (l_bucket) {
                                uint64_t l_ts_bucket = s_hist_bucket_ts(l_ts, l_bucket);
                                dex_bucket_agg_t *l_ba = NULL;
                                HASH_FIND(hh, l_buckets, &l_ts_bucket, sizeof(l_ts_bucket), l_ba);
                                if (!l_ba && (l_ba = DAP_NEW_Z(dex_bucket_agg_t))) {
                                    l_ba->ohlcv.ts = l_ts_bucket;
                                    l_ba->first_ts = l_ba->last_ts = l_ts;
                                    l_ba->ohlcv.open = l_ba->ohlcv.high = l_ba->ohlcv.low = l_ba->ohlcv.close = l_price_canon;
                                    HASH_ADD(hh, l_buckets, ohlcv.ts, sizeof(l_ba->ohlcv.ts), l_ba);
                                }
                                if (l_ba) {
                                    if (l_ts < l_ba->first_ts) {
                                        l_ba->first_ts = l_ts;
                                        l_ba->ohlcv.open = l_price_canon;
                                    }
                                    if (l_ts >= l_ba->last_ts) {
                                        l_ba->last_ts = l_ts;
                                        l_ba->ohlcv.close = l_price_canon;
                                    }
                                    if (compare256(l_price_canon, l_ba->ohlcv.high) > 0)
                                        l_ba->ohlcv.high = l_price_canon;
                                    if (compare256(l_price_canon, l_ba->ohlcv.low) < 0)
                                        l_ba->ohlcv.low = l_price_canon;
                                    SUM_256_256(l_ba->ohlcv.volume_base, l_bq.base, &l_ba->ohlcv.volume_base);
                                    SUM_256_256(l_ba->ohlcv.volume_quote, l_bq.quote, &l_ba->ohlcv.volume_quote);
                                    l_ba->ohlcv.trades++;
                                }
                            }
                        }
                    }
                    if (!l_residual)
                        break;
                }
            } while (0);
            else {
                dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
                if (!it)
                    return dap_json_rpc_error_add(*json_arr_reply, -3, "ledger iterator failed"), -3;
                for (dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it)) {
                    if (l_t_from && l_tx->header.ts_created < (dap_time_t)l_t_from)
                        continue;
                    if (l_t_to && l_tx->header.ts_created > (dap_time_t)l_t_to)
                        continue;
                    if (!dap_chain_datum_tx_item_get(l_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL))
                        continue;
                    if (l_buyer_str) {
                        dap_chain_addr_t l_buyer_tx = s_dex_extract_buyer_addr(l_tx, l_net->pub.id);
                        if (!dap_chain_addr_compare(&l_buyer_tx, &l_buyer_addr))
                            continue;
                    }
                    dap_chain_tx_out_cond_t *l_out_cond =
                        dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
                    byte_t *l_it_in;
                    size_t l_sz_in = 0;
                    int l_dex_in_i = 0;
                    TX_ITEM_ITER_TX(l_it_in, l_sz_in, l_tx) if (*l_it_in == TX_ITEM_TYPE_IN_COND)
                    {
                        dap_chain_tx_in_cond_t *l_in = (dap_chain_tx_in_cond_t *)l_it_in;
                        dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_in->header.tx_prev_hash);
                        if (!l_prev_tx)
                            continue;
                        int l_prev_dex_idx = 0;
                        dap_chain_tx_out_cond_t *l_prev =
                            dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_dex_idx);
                        // Skip if IN_COND doesn't spend DEX OUT
                        if (!l_prev || (int)l_in->header.tx_out_prev_idx != l_prev_dex_idx)
                            continue;
                        if (l_seller_str && !dap_chain_addr_compare(&l_prev->subtype.srv_dex.seller_addr, &l_seller_addr)) {
                            l_dex_in_i++;
                            continue;
                        }
                        if (l_order_hash_str) {
                            dap_hash_fast_t l_root_hash = dap_hash_fast_is_blank(&l_prev->subtype.srv_dex.order_root_hash)
                                                              ? l_in->header.tx_prev_hash
                                                              : l_prev->subtype.srv_dex.order_root_hash;
                            if (!dap_hash_fast_compare(&l_root_hash, &l_order_root)) {
                                l_dex_in_i++;
                                continue;
                            }
                        }
                        const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &l_in->header.tx_prev_hash);
                        if (!l_sell_tok)
                            continue;
                        uint8_t l_side = 0;
                        uint256_t l_price_canon = uint256_0;
                        s_dex_pair_normalize(l_sell_tok, l_prev->subtype.srv_dex.sell_net_id, l_prev->subtype.srv_dex.buy_token,
                                             l_prev->subtype.srv_dex.buy_net_id, l_prev->subtype.srv_dex.rate, &l_key, &l_side,
                                             &l_price_canon);
                        if (dap_strcmp(l_key.token_quote, l_ticker_quote) || dap_strcmp(l_key.token_base, l_ticker_base)) {
                            l_dex_in_i++;
                            continue;
                        }
                        if ((l_key.net_id_quote.uint64 != l_net->pub.id.uint64 || l_key.net_id_base.uint64 != l_net->pub.id.uint64)) {
                            if (s_cross_net_policy == CROSS_NET_REJECT) {
                                l_dex_in_i++;
                                continue;
                            } else if (s_cross_net_policy == CROSS_NET_WARN)
                                log_it(L_WARNING, "Cross-net trade met in history scan: %s/%s", l_ticker_base, l_ticker_quote);
                        }
                        if (!s_dex_verify_payout(l_tx, l_net, l_prev->subtype.srv_dex.buy_token, &l_prev->subtype.srv_dex.seller_addr)) {
                            l_dex_in_i++;
                            continue;
                        }
                        uint256_t l_executed_i = s_dex_calc_executed_amount(l_prev, l_out_cond, l_dex_in_i, l_prev_tx,
                                                                            &l_in->header.tx_prev_hash, l_net->pub.ledger);
                        if (!l_out_cond && l_dex_in_i == 0 && l_sell_tok && *l_sell_tok) {
                            uint256_t l_srv_fee_req = uint256_0;
                            const dap_chain_addr_t *l_srv_addr_ptr = NULL;
                            if (!dap_strcmp(l_sell_tok, l_net->pub.native_ticker) &&
                                dap_chain_addr_compare(&l_prev->subtype.srv_dex.seller_addr, &s_dex_service_fee_addr)) {
                                pthread_rwlock_rdlock(&s_dex_cache_rwlock);
                                dex_pair_index_t *l_pi_fee = s_dex_pair_index_get(&l_key);
                                uint8_t l_fee_cfg = l_pi_fee ? l_pi_fee->key.fee_config : 0;
                                l_srv_fee_req = s_dex_get_srv_fee(l_fee_cfg);
                                pthread_rwlock_unlock(&s_dex_cache_rwlock);
                                if (!IS_ZERO_256(l_srv_fee_req))
                                    l_srv_addr_ptr = &s_dex_service_fee_addr;
                            }
                            s_adjust_exec_for_dust_refund(l_tx, &l_prev->subtype.srv_dex.seller_addr, l_sell_tok, l_srv_addr_ptr,
                                                          l_srv_fee_req, &l_executed_i);
                        }
                        dex_bq_t l_bq = s_exec_to_canon_base_quote(l_executed_i, l_price_canon, l_side);
                        SUM_256_256(l_sum_base, l_bq.base, &l_sum_base);
                        SUM_256_256(l_sum_quote, l_bq.quote, &l_sum_quote);
                        if (l_tx->header.ts_created >= l_spot_ts) {
                            l_spot_ts = l_tx->header.ts_created;
                            l_spot_price = l_price_canon;
                        }
                        q++;
                        if (l_bucket) {
                            uint64_t l_ts_bucket = s_hist_bucket_ts(l_tx->header.ts_created, l_bucket);
                            dex_bucket_agg_t *l_ba = NULL;
                            HASH_FIND(hh, l_buckets, &l_ts_bucket, sizeof(l_ts_bucket), l_ba);
                            if (!l_ba) {
                                l_ba = DAP_NEW_Z(dex_bucket_agg_t);
                                l_ba->ohlcv.ts = l_ts_bucket;
                                l_ba->first_ts = l_ba->last_ts = l_tx->header.ts_created;
                                l_ba->ohlcv.open = l_ba->ohlcv.high = l_ba->ohlcv.low = l_ba->ohlcv.close = l_price_canon;
                                HASH_ADD(hh, l_buckets, ohlcv.ts, sizeof(l_ba->ohlcv.ts), l_ba);
                            }
                            if (l_tx->header.ts_created < l_ba->first_ts) {
                                l_ba->first_ts = l_tx->header.ts_created;
                                l_ba->ohlcv.open = l_price_canon;
                            }
                            if (l_tx->header.ts_created >= l_ba->last_ts) {
                                l_ba->last_ts = l_tx->header.ts_created;
                                l_ba->ohlcv.close = l_price_canon;
                            }
                            if (compare256(l_price_canon, l_ba->ohlcv.high) > 0)
                                l_ba->ohlcv.high = l_price_canon;
                            if (compare256(l_price_canon, l_ba->ohlcv.low) < 0)
                                l_ba->ohlcv.low = l_price_canon;
                            SUM_256_256(l_ba->ohlcv.volume_base, l_bq.base, &l_ba->ohlcv.volume_base);
                            SUM_256_256(l_ba->ohlcv.volume_quote, l_bq.quote, &l_ba->ohlcv.volume_quote);
                            l_ba->ohlcv.trades++;
                        }
                        l_dex_in_i++;
                    }
                }
                dap_ledger_datum_iter_delete(it);
            }
            // Unified emit: always volume; OHLC optionally
            json_object *l_arr = json_object_new_array();
            if (l_bucket && l_buckets) {
                HASH_SORT(l_buckets, s_cmp_agg_bucket_ts);
                uint64_t l_prev_ts = 0;
                uint256_t l_prev_close = uint256_0;
                dex_bucket_agg_t *l_cur, *l_tmp;
                HASH_ITER(hh, l_buckets, l_cur, l_tmp)
                {
                    if (l_fill_missing && l_prev_ts) {
                        for (uint64_t t = l_prev_ts + l_bucket; t < l_cur->ohlcv.ts; t += l_bucket) {
                            dex_bucket_agg_t l_miss = {
                                .ohlcv = {.ts = t, .open = l_prev_close, .high = l_prev_close, .low = l_prev_close, .close = l_prev_close},
                                .first_ts = t,
                                .last_ts = t + l_bucket - 1};
                            s_hist_json_emit_bucket(l_arr, &l_miss, l_want_ohlc);
                        }
                    }
                    s_hist_json_emit_bucket(l_arr, l_cur, l_want_ohlc);
                    l_prev_ts = l_cur->ohlcv.ts;
                    l_prev_close = l_cur->ohlcv.close;
                    HASH_DEL(l_buckets, l_cur);
                    DAP_DELETE(l_cur);
                }
            }
            // Attach outputs
            json_object_object_add(l_json_reply, "market_only", json_object_new_boolean(false));
            json_object_object_add(l_json_reply, l_want_ohlc ? "ohlc" : "volume", l_arr);
            if (l_bucket)
                json_object_object_add(l_json_reply, "count", json_object_new_int((int)json_object_array_length(l_arr)));
        }
        // Common totals emit
        json_object *l_tot = json_object_new_object();
        json_object_object_add(l_tot, "trades", json_object_new_int(q));
        json_object_object_add(l_tot, "sum_base", json_object_new_string(dap_uint256_to_char_ex(l_sum_base).frac));
        json_object_object_add(l_tot, "sum_quote", json_object_new_string(dap_uint256_to_char_ex(l_sum_quote).frac));
        if (!IS_ZERO_256(l_spot_price))
            json_object_object_add(l_tot, "spot", json_object_new_string(dap_uint256_to_char_ex(l_spot_price).frac));
        if (!IS_ZERO_256(l_sum_base)) {
            uint256_t l_vwap = uint256_0;
            DIV_256_COIN(l_sum_quote, l_sum_base, &l_vwap);
            json_object_object_add(l_tot, "vwap", json_object_new_string(dap_uint256_to_char_ex(l_vwap).frac));
        }
        json_object_object_add(l_json_reply, "totals", l_tot);
        s_add_units(l_json_reply, l_ticker_base, l_ticker_quote);
    } break; // HISTORY

    case CMD_CANCEL_ALL_BY_SELLER: {
        if (!l_pair_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -pair"), -2;
        if (!l_fee_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -fee"), -2;
        const char *l_seller_str = NULL, *l_limit_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-seller", &l_seller_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-limit", &l_limit_str);
        bool l_dry_run = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-dry-run") >= l_arg_index;
        if (!l_seller_str || !l_fee_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -seller or -fee"), -2;
        dap_chain_addr_t *l_seller_tmp = dap_chain_addr_from_str(l_seller_str);
        if (!l_seller_tmp)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad seller address %s", l_seller_str), -2;
        dap_chain_addr_t l_seller = *l_seller_tmp;
        DAP_DELETE(l_seller_tmp);
        int l_limit = l_limit_str ? atoi(l_limit_str) : INT_MAX, l_cnt = 0;
        if (l_limit < 0)
            l_limit *= -1;
        // Require wallet even for dry-run; verify ownership matches seller
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
        if (!l_wallet) {
            return dap_json_rpc_error_add(*json_arr_reply, -3, "wallet open failed"), -3;
        }
        dap_chain_addr_t *l_w_addr = dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);
        if (!l_w_addr) {
            dap_chain_wallet_close(l_wallet);
            return dap_json_rpc_error_add(*json_arr_reply, -3, "wallet %s not available", l_wallet_str), -3;
        }
        bool l_addr_match = dap_chain_addr_compare(l_w_addr, &l_seller);
        DAP_DELETE(l_w_addr);
        if (!l_addr_match) {
            dap_chain_wallet_close(l_wallet);
            return dap_json_rpc_error_add(*json_arr_reply, -2, "seller addr != wallet addr"), -2;
        }
        l_json_reply = json_object_new_object();
        json_object *l_arr = json_object_new_array();
        if (l_dry_run) {
            // Report candidates only (filtered by pair)
            if (s_dex_cache_enabled) {
                pthread_rwlock_rdlock(&s_dex_cache_rwlock);
                dex_seller_index_t *l_sb = NULL;
                HASH_FIND(hh, s_dex_seller_index, &l_seller, sizeof(l_seller), l_sb);
                if (l_sb && l_sb->entries) {
                    dex_order_cache_entry_t *l_e = NULL, *l_tmp;
                    HASH_ITER(hh_seller_bucket, l_sb->entries, l_e, l_tmp)
                    {
                        // Filter by pair
                        if (l_e->pair_key_ptr && !strcmp(l_e->pair_key_ptr->token_base, l_ticker_base) &&
                            !strcmp(l_e->pair_key_ptr->token_quote, l_ticker_quote)) {
                            json_object *o = json_object_new_object();
                            json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&l_e->level.match.tail)));
                            json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&l_e->level.match.root)));
                            json_object_array_add(l_arr, o);
                            if (++l_cnt >= l_limit)
                                break;
                        }
                    }
                }
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
            } else {
                // Fallback to ledger scan when cache disabled
                dap_time_t l_now = dap_ledger_get_blockchain_time(l_net->pub.ledger);
                dap_ledger_datum_iter_t *l_it = dap_ledger_datum_iter_create(l_net);
                if (!l_it) {
                    dap_chain_wallet_close(l_wallet);
                    json_object_put(l_json_reply);
                    json_object_put(l_arr);
                    return dap_json_rpc_error_add(*json_arr_reply, -3, "ledger iterator failed"), -3;
                }
                for (dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(l_it); l_tx;
                     l_tx = dap_ledger_datum_iter_get_next(l_it)) {
                    int l_out_idx = 0;
                    dap_chain_tx_out_cond_t *l_out_cond =
                        dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                    if (!l_out_cond)
                        continue;
                    if (l_out_cond->header.ts_expires && l_now > l_out_cond->header.ts_expires)
                        continue;
                    if (!dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_seller))
                        continue;
                    if (dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &l_it->cur_hash, l_out_idx, NULL))
                        continue;
                    const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &l_it->cur_hash);
                    if (!l_sell_tok)
                        continue;
                    dex_pair_key_t l_key = {};
                    uint8_t l_side = 0;
                    uint256_t l_price = uint256_0;
                    s_dex_pair_normalize(l_sell_tok, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                                         l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key, &l_side,
                                         &l_price);
                    if (strcmp(l_key.token_base, l_ticker_base) || strcmp(l_key.token_quote, l_ticker_quote))
                        continue;
                    json_object *o = json_object_new_object();
                    json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&l_it->cur_hash)));
                    json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&l_it->cur_hash)));
                    json_object_array_add(l_arr, o);
                    if (++l_cnt >= l_limit)
                        break;
                }
                dap_ledger_datum_iter_delete(l_it);
            }
        } else {
            // Compose one aggregated cancel-all transaction
            dap_chain_datum_tx_t *l_cancel_tx = NULL;
            l_ret = dap_chain_net_srv_dex_cancel_all_by_seller(l_net, &l_seller, l_ticker_base, l_ticker_quote, l_limit, l_fee, l_wallet,
                                                               &l_cancel_tx);
            if (l_ret != DEX_CANCEL_ALL_ERROR_OK) {
                dap_chain_wallet_close(l_wallet);
                json_object_put(l_json_reply);
                json_object_put(l_arr);
                l_json_reply = NULL;
                l_err_str = DEX_ERROR_STR(s_cancel_all_error_str, l_ret);
                break;
            }
            // Submit composed datum via mempool
            char *l_hash_hex = s_dex_tx_put(l_cancel_tx, l_net);
            if (!l_hash_hex) {
                dap_chain_wallet_close(l_wallet);
                json_object_put(l_json_reply);
                json_object_put(l_arr);
                return dap_json_rpc_error_add(*json_arr_reply, -4, "mempool put failed"), -4;
            }
            json_object *o = json_object_new_object();
            json_object_object_add(o, "tx", json_object_new_string(l_hash_hex));
            json_object_array_add(l_arr, o);
            DAP_DELETE(l_hash_hex);
            l_cnt = 1;
        }
        dap_chain_wallet_close(l_wallet);
        json_object_object_add(l_json_reply, "result", l_arr);
        json_object_object_add(l_json_reply, "count", json_object_new_int(l_cnt));
    } break; // CANCEL_ALL_BY_SELLER

    case CMD_PURCHASE: {
        if (!l_value_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -value"), -2;
        const char *l_order_str = NULL, *l_rate_str = NULL, *l_unit_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_str);
        if (!l_order_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -order"), -2;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-unit", &l_unit_str);
        bool l_create_leftover = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-create_leftover_order") >= l_arg_index;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-leftover_rate", &l_rate_str);
        if (!l_unit_str)
            l_unit_str = "sell";
        bool l_is_budget_buy;
        if (!dap_strcmp(l_unit_str, "buy"))
            l_is_budget_buy = true;
        else if (!dap_strcmp(l_unit_str, "sell"))
            l_is_budget_buy = false;
        else
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad -unit '%s', expected 'sell' or 'buy'", l_unit_str), -2;
        dap_hash_fast_t l_order = {};
        if (dap_chain_hash_fast_from_str(l_order_str, &l_order))
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad order hash %s", l_order_str), -2;
        uint256_t l_leftover_rate = l_rate_str ? dap_chain_balance_scan(l_rate_str) : uint256_0;
        if (l_create_leftover && IS_ZERO_256(l_leftover_rate))
            return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -leftover_rate"), -2;
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
        if (!l_wallet)
            return dap_json_rpc_error_add(*json_arr_reply, -3, "wallet open failed"), -3;
        l_ret = dap_chain_net_srv_dex_purchase(l_net, &l_order, l_value, l_is_budget_buy, l_fee, l_wallet, l_create_leftover,
                                               l_leftover_rate, &l_datum);
        dap_chain_wallet_close(l_wallet);
        if (l_ret != DEX_PURCHASE_ERROR_OK) {
            l_err_str = DEX_ERROR_STR(s_purchase_error_str, l_ret);
            break;
        }
    } break; // PURCHASE

    case CMD_PURCHASE_MULTI: {
        if (!l_value_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -value"), -2;
        const char *l_orders_str = NULL, *l_rate_str = NULL, *l_unit_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-orders", &l_orders_str);
        if (!l_orders_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -orders"), -2;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-unit", &l_unit_str);
        bool l_create_leftover = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-create_leftover_order") >= l_arg_index;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-leftover_rate", &l_rate_str);
        if (l_create_leftover && !l_rate_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -leftover_rate"), -2;
        if (!l_create_leftover && l_rate_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "leftover_rate not allowed"), -2;
        if (!l_unit_str)
            l_unit_str = "sell";
        bool l_is_budget_buy;
        if (!dap_strcmp(l_unit_str, "buy"))
            l_is_budget_buy = true;
        else if (!dap_strcmp(l_unit_str, "sell"))
            l_is_budget_buy = false;
        else
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad -unit '%s', expected 'sell' or 'buy'", l_unit_str), -2;
        uint256_t l_leftover_rate = l_rate_str ? dap_chain_balance_scan(l_rate_str) : uint256_0;
        if (l_create_leftover && IS_ZERO_256(l_leftover_rate))
            return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -leftover_rate"), -2;
        int l_num = 1;
        char *l_orders_copy = strdup(l_orders_str), *l_delim;
        for (l_delim = l_orders_copy; (l_delim = strchr(l_delim, ',')); ++l_num, *l_delim = '\0')
            ;
        dap_hash_fast_t *l_hashes = DAP_NEW_Z_COUNT(dap_hash_fast_t, l_num);
        if (!l_hashes) {
            DAP_DELETE(l_orders_copy);
            return dap_json_rpc_error_add(*json_arr_reply, -3, "oom"), -3;
        }
        l_delim = l_orders_copy;
        for (int l_idx = 0; l_idx < l_num; ++l_idx) {
            if (dap_chain_hash_fast_from_str(l_delim, &l_hashes[l_idx])) {
                dap_json_rpc_error_add(*json_arr_reply, -2, "bad order hash %s", l_delim);
                DAP_DEL_MULTY(l_hashes, l_orders_copy);
                return -2;
            }
            l_delim = strchr(l_delim, '\0') + 1;
        }
        DAP_DELETE(l_orders_copy);
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
        if (!l_wallet) {
            DAP_DELETE(l_hashes);
            return dap_json_rpc_error_add(*json_arr_reply, -3, "wallet open failed"), -3;
        }
        l_ret = dap_chain_net_srv_dex_purchase_multi(l_net, l_hashes, l_num, l_value, l_is_budget_buy, l_fee, l_wallet, l_create_leftover,
                                                     l_leftover_rate, &l_datum);
        dap_chain_wallet_close(l_wallet);
        DAP_DELETE(l_hashes);
        if (l_ret != DEX_PURCHASE_ERROR_OK) {
            l_err_str = DEX_ERROR_STR(s_purchase_error_str, l_ret);
            break;
        }
    } break; // PURCHASE_MULTI

    case CMD_PURCHASE_AUTO: {
        if (!l_value_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -value"), -2;
        const char *l_sell_tok = NULL, *l_buy_tok = NULL, *l_rate_cap_str = NULL, *l_rate_str = NULL, *l_unit_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_sell", &l_sell_tok);
        if (!l_sell_tok)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -token_sell"), -2;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_buy", &l_buy_tok);
        if (!l_buy_tok)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -token_buy"), -2;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-rate_cap", &l_rate_cap_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-unit", &l_unit_str);
        bool l_create_leftover = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-create_leftover_order") >= l_arg_index;
        bool l_dry_run = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-dry-run") >= l_arg_index;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-leftover_rate", &l_rate_str);
        if (l_create_leftover && !l_rate_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -leftover_rate"), -2;
        if (!l_create_leftover && l_rate_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "leftover_rate not allowed"), -2;
        if (!l_unit_str)
            l_unit_str = "sell";
        bool l_is_budget_buy;
        if (!dap_strcmp(l_unit_str, "buy"))
            l_is_budget_buy = true;
        else if (!dap_strcmp(l_unit_str, "sell"))
            l_is_budget_buy = false;
        else
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad -unit '%s', expected 'sell' or 'buy'", l_unit_str), -2;
        uint256_t l_leftover_rate = l_rate_str ? dap_chain_balance_scan(l_rate_str) : uint256_0;
        if (l_create_leftover && IS_ZERO_256(l_leftover_rate))
            return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -leftover_rate"), -2;
        uint256_t l_rate_cap = l_rate_cap_str ? dap_chain_balance_scan(l_rate_cap_str) : uint256_0;
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
        if (!l_wallet)
            return dap_json_rpc_error_add(*json_arr_reply, -3, "wallet open failed"), -3;

        dex_match_table_entry_t *l_matches = NULL;
        l_ret = dap_chain_net_srv_dex_purchase_auto_ex(l_net, l_sell_tok, l_buy_tok, l_value, l_is_budget_buy, l_fee, l_rate_cap, l_wallet,
                                                       l_create_leftover, l_leftover_rate, l_dry_run ? NULL : &l_datum, &l_matches);
        dap_chain_wallet_close(l_wallet);

        if (l_ret == DEX_PURCHASE_ERROR_OK) {
            json_object *l_arr = json_object_new_array();
            uint256_t l_total_sell = uint256_0, l_total_buy = uint256_0;
            dex_match_table_entry_t *l_cur, *l_tmp;
            HASH_ITER(hh, l_matches, l_cur, l_tmp)
            {
                json_object *o = json_object_new_object();
                // side=0 (ASK): seller sells BASE, buys QUOTE; side=1 (BID): seller sells QUOTE, buys BASE
                bool l_is_bid = (l_cur->side_version & 0x1);
                json_object_object_add(o, "token_sell",
                                       json_object_new_string(l_is_bid ? l_cur->pair_key->token_quote : l_cur->pair_key->token_base));
                json_object_object_add(o, "token_buy",
                                       json_object_new_string(l_is_bid ? l_cur->pair_key->token_base : l_cur->pair_key->token_quote));
                json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&l_cur->match.root)));
                json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&l_cur->match.tail)));
                json_object_object_add(o, "rate", json_object_new_string(dap_uint256_to_char_ex(l_cur->match.rate).frac));
                uint256_t l_exec_buy = uint256_0;
                MULT_256_COIN(l_cur->exec_sell, l_cur->match.rate, &l_exec_buy);
                json_object_object_add(o, "executed_sell", json_object_new_string(dap_uint256_to_char_ex(l_cur->exec_sell).frac));
                json_object_object_add(o, "executed_buy", json_object_new_string(dap_uint256_to_char_ex(l_exec_buy).frac));
                json_object_array_add(l_arr, o);
                if (!IS_ZERO_256(l_cur->exec_sell))
                    SUM_256_256(l_total_sell, l_cur->exec_sell, &l_total_sell);
                if (!IS_ZERO_256(l_exec_buy))
                    SUM_256_256(l_total_buy, l_exec_buy, &l_total_buy);
            }
            l_json_reply = json_object_new_object();
            json_object_object_add(l_json_reply, "orders", json_object_new_int((int)HASH_CNT(hh, l_matches)));
            json_object_object_add(l_json_reply, "sell", json_object_new_string(dap_uint256_to_char_ex(l_total_sell).frac));
            json_object_object_add(l_json_reply, "buy", json_object_new_string(dap_uint256_to_char_ex(l_total_buy).frac));
            json_object_object_add(l_json_reply, "matches", l_arr);
            if (l_dry_run)
                json_object_object_add(l_json_reply, "dry_run", json_object_new_boolean(true));
        } else
            l_err_str = DEX_ERROR_STR(s_purchase_error_str, l_ret);
        s_dex_match_pair_index_clear(&l_matches);
    } break; // PURCHASE_AUTO

    case CMD_SLIPPAGE: {
        /* SLIPPAGE
         * Simulate order-book execution for a hypothetical trade to estimate:
         * - effective price (VWAP) for consumed volume
         * - absolute and percent slippage vs the current best price
         * Implementation walks price levels and accumulates BASE/QUOTE totals.
         */
        if (!l_pair_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -pair"), -2;
        const char *l_val_str = NULL, *l_side_str = NULL, *l_unit_str = NULL, *l_max_sl_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_val_str);
        if (!l_val_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -value"), -2;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-side", &l_side_str);
        if (!l_side_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -side"), -2;
        bool l_side_buy = !dap_strcmp(l_side_str, "buy");
        if (!l_side_buy && dap_strcmp(l_side_str, "sell"))
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad -side %s", l_side_str), -2;

        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-unit", &l_unit_str);
        if (!l_unit_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -unit"), -2;
        bool l_unit_base = !dap_strcmp(l_unit_str, "base");
        if (!l_unit_base && dap_strcmp(l_unit_str, "quote"))
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad -unit %s", l_unit_str), -2;

        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-max_slippage_pct", &l_max_sl_str);

        uint256_t l_budget = dap_chain_balance_scan(l_val_str);
        if (IS_ZERO_256(l_budget))
            return dap_json_rpc_error_add(*json_arr_reply, -2, "value must be > 0"), -2;

        uint256_t l_total_base = uint256_0, l_total_quote = uint256_0, l_best_ref = uint256_0, l_best_price = uint256_0;
        bool l_has_limit = l_max_sl_str && *l_max_sl_str;
        uint256_t l_max_sl = l_has_limit ? dap_chain_balance_scan(l_max_sl_str) : uint256_0;
        int l_used_levels = 0;
        dap_time_t l_now_ts = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        dex_pair_key_t l_key = {.net_id_quote = l_net->pub.id, .net_id_base = l_net->pub.id};
        dap_strncpy(l_key.token_quote, l_ticker_quote, sizeof(l_key.token_quote) - 1);
        dap_strncpy(l_key.token_base, l_ticker_base, sizeof(l_key.token_base) - 1);
        if (s_dex_cache_enabled) {
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            // Use pair buckets (asks/bids) ordered by best price first
            dex_pair_index_t *l_pb = NULL;
            HASH_FIND(hh, s_dex_pair_index, &l_key, DEX_PAIR_KEY_CMP_SIZE, l_pb);
            if (!l_pb) {
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
                return dap_json_rpc_error_add(*json_arr_reply, -2, "pair %s not found", l_pair_str), -2;
            }
            if (l_has_limit)
                l_best_ref = l_side_buy ? (l_pb->asks ? l_pb->asks->level.match.rate : uint256_0)
                                        : (l_pb->bids ? l_pb->bids->level.match.rate : uint256_0);
            dex_order_cache_entry_t *e, *tmp;
            if (l_side_buy) {
                if (!l_unit_base) {
                    // BUY with QUOTE budget: convert QUOTE->BASE per price level
                    uint256_t l_budget_q = l_budget;
                    HASH_ITER(hh_pair_bucket, l_pb->asks, e, tmp)
                    {
                        if (e->ts_expires && l_now_ts > e->ts_expires)
                            continue;
                        s_consume_buy_quote(&l_budget_q, e->level.match.rate, e->level.match.value, &l_total_base, &l_total_quote,
                                            &l_used_levels);
                        if (IS_ZERO_256(l_budget_q) ||
                            s_slippage_exceeds_limit(l_total_base, l_total_quote, l_best_ref, l_max_sl, l_side_buy))
                            break;
                    }
                    l_budget = l_budget_q;
                } else {
                    // BUY with BASE budget: take BASE directly, compute QUOTE cost
                    uint256_t l_budget_b = l_budget;
                    HASH_ITER(hh_pair_bucket, l_pb->asks, e, tmp)
                    {
                        if (e->ts_expires && l_now_ts > e->ts_expires)
                            continue;
                        s_consume_buy_base(&l_budget_b, e->level.match.rate, e->level.match.value, &l_total_base, &l_total_quote,
                                           &l_used_levels);
                        if (IS_ZERO_256(l_budget_b) ||
                            s_slippage_exceeds_limit(l_total_base, l_total_quote, l_best_ref, l_max_sl, l_side_buy))
                            break;
                    }
                    l_budget = l_budget_b;
                }
            } else {
                dex_order_cache_entry_t *l_last = HASH_LAST_EX(hh_pair_bucket, l_pb->bids);
                if (l_unit_base) {
                    // SELL with BASE budget: convert BASE->QUOTE at each price level
                    uint256_t l_budget_b = l_budget;
                    // Reverse iteration
                    for (e = l_last; e && !IS_ZERO_256(l_budget_b); e = (dex_order_cache_entry_t *)e->hh_pair_bucket.prev) {
                        if (e->ts_expires && l_now_ts > e->ts_expires)
                            continue;
                        s_consume_sell_pair_base(&l_budget_b, e->level.match.rate, e->level.match.value, &l_total_base, &l_total_quote,
                                                 &l_used_levels);
                        if (IS_ZERO_256(l_budget_b) ||
                            s_slippage_exceeds_limit(l_total_base, l_total_quote, l_best_ref, l_max_sl, l_side_buy))
                            break;
                    }
                    l_budget = l_budget_b;
                } else {
                    // SELL with QUOTE target: compute required BASE per level
                    uint256_t l_budget_q = l_budget;
                    for (e = l_last; e && !IS_ZERO_256(l_budget_q); e = (dex_order_cache_entry_t *)e->hh_pair_bucket.prev) {
                        if (e->ts_expires && l_now_ts > e->ts_expires)
                            continue;
                        s_consume_sell_pair_quote(&l_budget_q, e->level.match.rate, e->level.match.value, &l_total_base, &l_total_quote,
                                                  &l_used_levels);
                        if (IS_ZERO_256(l_budget_q) ||
                            s_slippage_exceeds_limit(l_total_base, l_total_quote, l_best_ref, l_max_sl, l_side_buy))
                            break;
                    }
                    l_budget = l_budget_q;
                }
            }
            l_best_price = l_best_ref;
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
        } else {
            // Ledger fallback: check pair whitelist first
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            dex_pair_index_t *l_pb_check = NULL;
            HASH_FIND(hh, s_dex_pair_index, &l_key, DEX_PAIR_KEY_CMP_SIZE, l_pb_check);
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
            if (!l_pb_check)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "pair %s not found", l_pair_str), -2;

            // 1) Build temporary levels table from on-chain unspent SRV_DEX outs
            // 2) Sort by price (ASK asc for BUY, BID desc for SELL)
            // 3) Walk levels same as the cache path
            dex_order_level_t *l_levels = NULL, *e, *tmp;
            dap_chain_tx_out_cond_t *l_out_cond = NULL;
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            if (!it)
                return dap_json_rpc_error_add(*json_arr_reply, -3, "ledger iterator failed"), -3;
            for (dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it)) {
                int l_out_idx = 0;
                l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                if (!l_out_cond)
                    continue;
                if (dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL))
                    continue;
                if (l_out_cond->header.ts_expires && l_now_ts > l_out_cond->header.ts_expires)
                    continue;
                const char *l_sell_tok_tx = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &it->cur_hash);
                if (!l_sell_tok_tx)
                    continue;
                uint8_t l_side = 0;
                uint256_t l_price = uint256_0;
                s_dex_pair_normalize(l_sell_tok_tx, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                                     l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key, &l_side, &l_price);
                if (dap_strcmp(l_key.token_quote, l_ticker_quote) || dap_strcmp(l_key.token_base, l_ticker_base))
                    continue;
                if ((l_side_buy && l_side != DEX_SIDE_ASK) || (!l_side_buy && l_side != DEX_SIDE_BID))
                    continue;
                dex_order_level_t *l_lvl = DAP_NEW_Z(dex_order_level_t);
                l_lvl->match.value = l_out_cond->header.value;
                l_lvl->match.rate = l_price;
                l_lvl->match.min_fill = l_out_cond->subtype.srv_dex.min_fill;
                l_lvl->match.root = dap_ledger_get_first_chain_tx_hash(l_net->pub.ledger, l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                l_lvl->match.tail = it->cur_hash;
                HASH_ADD(hh, l_levels, match.root, sizeof(l_lvl->match.root), l_lvl);
            }
            dap_ledger_datum_iter_delete(it);
            if (!l_levels) {
                // No orders found in ledger - set zero metrics and proceed to JSON output
                l_total_base = l_total_quote = uint256_0;
                l_used_levels = 0;
            } else {
                // sort by price
                if (l_side_buy)
                    HASH_SORT(l_levels, s_cmp_level_entries_ask);
                else
                    HASH_SORT(l_levels, s_cmp_level_entries_bid);
                l_best_price = l_levels->match.rate;
                if (l_has_limit)
                    l_best_ref = l_best_price;

                if (l_side_buy) {
                    // BUY path over sorted ASKs
                    if (!l_unit_base) {
                        // QUOTE budget
                        uint256_t l_budget_q = l_budget;
                        HASH_ITER(hh, l_levels, e, tmp)
                        {
                            s_consume_buy_quote(&l_budget_q, e->match.rate, e->match.value, &l_total_base, &l_total_quote, &l_used_levels);
                            bool l_break = IS_ZERO_256(l_budget_q) ||
                                           s_slippage_exceeds_limit(l_total_base, l_total_quote, l_best_ref, l_max_sl, l_side_buy);
                            HASH_DEL(l_levels, e);
                            DAP_DELETE(e);
                            if (l_break)
                                break;
                        }
                        l_budget = l_budget_q;
                    } else {
                        // BASE budget
                        uint256_t l_budget_b = l_budget;
                        HASH_ITER(hh, l_levels, e, tmp)
                        {
                            s_consume_buy_base(&l_budget_b, e->match.rate, e->match.value, &l_total_base, &l_total_quote, &l_used_levels);
                            bool l_break = IS_ZERO_256(l_budget_b) ||
                                           s_slippage_exceeds_limit(l_total_base, l_total_quote, l_best_ref, l_max_sl, l_side_buy);
                            HASH_DEL(l_levels, e);
                            DAP_DELETE(e);
                            if (l_break)
                                break;
                        }
                        l_budget = l_budget_b;
                    }
                } else {
                    // SELL path over sorted BIDs
                    if (!l_unit_base) {
                        // QUOTE target
                        uint256_t l_budget_q = l_budget;
                        HASH_ITER(hh, l_levels, e, tmp)
                        {
                            s_consume_sell_pair_quote(&l_budget_q, e->match.rate, e->match.value, &l_total_base, &l_total_quote,
                                                      &l_used_levels);
                            bool l_break = IS_ZERO_256(l_budget_q) ||
                                           s_slippage_exceeds_limit(l_total_base, l_total_quote, l_best_ref, l_max_sl, l_side_buy);
                            HASH_DEL(l_levels, e);
                            DAP_DELETE(e);
                            if (l_break)
                                break;
                        }
                        l_budget = l_budget_q;
                    } else {
                        // BASE budget
                        uint256_t l_budget_b = l_budget;
                        HASH_ITER(hh, l_levels, e, tmp)
                        {
                            s_consume_sell_pair_base(&l_budget_b, e->match.rate, e->match.value, &l_total_base, &l_total_quote,
                                                     &l_used_levels);
                            bool l_break = IS_ZERO_256(l_budget_b) ||
                                           s_slippage_exceeds_limit(l_total_base, l_total_quote, l_best_ref, l_max_sl, l_side_buy);
                            HASH_DEL(l_levels, e);
                            DAP_DELETE(e);
                            if (l_break)
                                break;
                        }
                        l_budget = l_budget_b;
                    }
                }
                // Free temp items if left any
                if (l_levels)
                    HASH_ITER(hh, l_levels, e, tmp)
                    {
                        HASH_DEL(l_levels, e);
                        DAP_DELETE(e);
                    }
            }
        }
        // Always return success with metrics (even if no liquidity)
        l_json_reply = json_object_new_object();
        json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_canon_str));
        json_object_object_add(l_json_reply, "side", json_object_new_string(l_side_buy ? "buy" : "sell"));

        if (!IS_ZERO_256(l_total_base) && !IS_ZERO_256(l_total_quote)) {
            // Has liquidity - emit full metrics
            json_object_object_add(l_json_reply, "has_liquidity", json_object_new_boolean(true));

            uint256_t l_vwap = uint256_0;
            DIV_256_COIN(l_total_quote, l_total_base, &l_vwap);
            uint256_t l_sl = uint256_0;
            if (!IS_ZERO_256(l_best_price)) {
                if (l_side_buy) {
                    l_sl = l_vwap;
                    SUBTRACT_256_256(l_sl, l_best_price, &l_sl);
                } else {
                    l_sl = l_best_price;
                    SUBTRACT_256_256(l_sl, l_vwap, &l_sl);
                }
            }
            uint256_t l_sl_pct = uint256_0;
            if (!IS_ZERO_256(l_best_price)) {
                uint256_t l_ratio = uint256_0;
                if (l_side_buy)
                    DIV_256(l_vwap, l_best_price, &l_ratio);
                else
                    DIV_256(l_best_price, l_vwap, &l_ratio);
                uint256_t l_one = GET_256_FROM_64(1000000000000000000ULL);
                if (compare256(l_ratio, l_one) >= 0) {
                    uint256_t l_delta = uint256_0;
                    SUBTRACT_256_256(l_ratio, l_one, &l_delta);
                    uint256_t l_hundred = GET_256_FROM_64(100ULL);
                    MULT_256_256(l_delta, l_hundred, &l_sl_pct);
                }
            }
            json_object_object_add(l_json_reply, "effective_price", json_object_new_string(dap_uint256_to_char_ex(l_vwap).frac));
            json_object_object_add(l_json_reply, l_side_buy ? "best_ask" : "best_bid",
                                   json_object_new_string(dap_uint256_to_char_ex(l_best_price).frac));
            json_object_object_add(l_json_reply, "slippage", json_object_new_string(dap_uint256_to_char_ex(l_sl).frac));
            json_object_object_add(l_json_reply, "slippage_pct", json_object_new_string(dap_uint256_to_char_ex(l_sl_pct).frac));
            json_object_object_add(l_json_reply, "price_impact_pct", json_object_new_string(dap_uint256_to_char_ex(l_sl_pct).frac));
            json_object_object_add(l_json_reply, "filled_base", json_object_new_string(dap_uint256_to_char_ex(l_total_base).frac));
            json_object_object_add(l_json_reply, "spent_quote", json_object_new_string(dap_uint256_to_char_ex(l_total_quote).frac));
            json_object_object_add(l_json_reply, "levels_used", json_object_new_int(l_used_levels));
            json_object_object_add(l_json_reply, "totally_filled", json_object_new_boolean(IS_ZERO_256(l_budget)));

            if (l_max_sl_str) {
                uint256_t l_max_sl = dap_chain_balance_scan(l_max_sl_str);
                if (compare256(l_sl_pct, l_max_sl) > 0)
                    json_object_object_add(l_json_reply, "warning", json_object_new_string("max_slippage_exceeded"));
            }
        } else
            // No liquidity - just the flag
            json_object_object_add(l_json_reply, "has_liquidity", json_object_new_boolean(false));
    } break; // SLIPPAGE

    case CMD_FIND_MATCHES: {
        const char *l_order_str = NULL, *l_addr_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_str);
        if (!l_order_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -order"), -2;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-addr", &l_addr_str);
        if (!l_addr_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -addr"), -2;

        dap_hash_fast_t l_order_hash = {};
        if (dap_chain_hash_fast_from_str(l_order_str, &l_order_hash))
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad order hash %s", l_order_str), -2;
        dap_chain_addr_t *l_addr_tmp = dap_chain_addr_from_str(l_addr_str);
        if (!l_addr_tmp)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad addr %s", l_addr_str), -2;
        dap_chain_addr_t l_addr = *l_addr_tmp;
        DAP_DELETE(l_addr_tmp);

        dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_order_hash);
        if (!l_tx)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "order not found %s", l_order_str), -2;

        int l_out_idx = 0;
        dap_chain_tx_out_cond_t *l_xchange_out = NULL;
        dap_chain_tx_out_cond_t *l_dex_out = NULL;
        dap_hash_fast_t l_tail = l_order_hash;
        dap_hash_fast_t l_xchange_tail =
            dap_ledger_get_final_chain_tx_hash(l_net->pub.ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_order_hash, false);
        const char *l_sell_tok = NULL, *l_buy_tok = NULL;
        dap_chain_net_id_t l_sell_net = {}, l_buy_net = {};
        uint256_t l_rate_canon = uint256_0, l_budget = uint256_0;
        bool l_owner_ok = true;
        bool l_is_legacy = false;
        if (!dap_hash_fast_is_blank(&l_xchange_tail)) {
            l_is_legacy = true;
            l_tail = l_xchange_tail;
            l_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_tail);
            if (!l_tx)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "order tail not found %s",
                                              dap_hash_fast_to_str_static(&l_tail)),
                       -2;
            l_xchange_out = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_out_idx);
            if (!l_xchange_out)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "order is not XCHANGE"), -2;
            if (IS_ZERO_256(l_xchange_out->header.value) ||
                dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &l_tail, l_out_idx, NULL))
                return dap_json_rpc_error_add(*json_arr_reply, -2, "order closed"), -2;

            l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &l_tail);
            l_buy_tok = l_xchange_out->subtype.srv_xchange.buy_token;
            l_sell_net = l_xchange_out->subtype.srv_xchange.sell_net_id;
            l_buy_net = l_xchange_out->subtype.srv_xchange.buy_net_id;
            l_budget = l_xchange_out->header.value;
            l_owner_ok = dap_chain_addr_compare(&l_addr, &l_xchange_out->subtype.srv_xchange.seller_addr);
            if (!l_sell_tok || !*l_sell_tok || !l_buy_tok || !*l_buy_tok)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "order tokens not found"), -2;
            if (!s_dex_rate_legacy_to_canon(l_sell_tok, l_buy_tok, l_xchange_out->subtype.srv_xchange.rate, &l_rate_canon))
                return dap_json_rpc_error_add(*json_arr_reply, -2, "bad legacy rate"), -2;
        } else {
            if (s_dex_resolve_order_tail(l_net, &l_order_hash, &l_tail))
                return dap_json_rpc_error_add(*json_arr_reply, -2, "order not found %s", l_order_str), -2;
            l_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_tail);
            if (!l_tx)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "order tail not found %s", dap_hash_fast_to_str_static(&l_tail)), -2;
            l_dex_out = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
            if (!l_dex_out)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "order is not DEX"), -2;
            l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &l_tail);
            l_buy_tok = l_dex_out->subtype.srv_dex.buy_token;
            l_sell_net = l_dex_out->subtype.srv_dex.sell_net_id;
            l_buy_net = l_dex_out->subtype.srv_dex.buy_net_id;
            l_rate_canon = l_dex_out->subtype.srv_dex.rate;
            l_budget = l_dex_out->header.value;
            if (IS_ZERO_256(l_dex_out->header.value) ||
                dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &l_tail, l_out_idx, NULL))
                return dap_json_rpc_error_add(*json_arr_reply, -2, "order closed"), -2;
            l_owner_ok = dap_chain_addr_compare(&l_addr, &l_dex_out->subtype.srv_dex.seller_addr);
            if (!l_sell_tok || !*l_sell_tok || !l_buy_tok || !*l_buy_tok)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "order tokens not found"), -2;
        }

        dex_pair_key_t l_key = {};
        uint8_t l_side = 0;
        s_dex_pair_normalize(l_sell_tok, l_sell_net, l_buy_tok, l_buy_net, l_rate_canon, &l_key, &l_side, NULL);
        bool l_is_budget_buy = false;
        dex_match_criteria_t l_crit = {l_sell_tok, l_buy_tok, l_sell_net, l_buy_net, l_rate_canon, l_budget, l_is_budget_buy, &l_addr};
        uint256_t l_leftover = uint256_0;
        dex_match_table_entry_t *l_matches = s_dex_matches_build_by_criteria(l_net, &l_crit, &l_leftover);

        l_json_reply = json_object_new_object();
        json_object_object_add(l_json_reply, "order_hash", json_object_new_string(l_order_str));
        if (!dap_hash_fast_compare(&l_tail, &l_order_hash))
            json_object_object_add(l_json_reply, "order_tail", json_object_new_string(dap_hash_fast_to_str_static(&l_tail)));
        json_object_object_add(l_json_reply, "legacy", json_object_new_boolean(l_is_legacy));
        char l_pair_buf[DAP_CHAIN_TICKER_SIZE_MAX * 2 + 4] = "";
        snprintf(l_pair_buf, sizeof(l_pair_buf), "%s/%s", l_key.token_base, l_key.token_quote);
        json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_buf));
        json_object_object_add(l_json_reply, "side", json_object_new_string(l_side == DEX_SIDE_ASK ? "ask" : "bid"));
        json_object_object_add(l_json_reply, "rate", json_object_new_string(dap_uint256_to_char_ex(l_rate_canon).frac));
        json_object_object_add(l_json_reply, "budget", json_object_new_string(dap_uint256_to_char_ex(l_budget).frac));
        json_object_object_add(l_json_reply, "budget_token", json_object_new_string(l_sell_tok));
        json_object_object_add(l_json_reply, "addr_matches_owner", json_object_new_boolean(l_owner_ok));
        if (!l_owner_ok)
            json_object_object_add(l_json_reply, "warning", json_object_new_string("addr_not_owner"));

        json_object *l_arr = json_object_new_array();
        int l_match_cnt = 0;
        if (l_matches) {
            dex_match_table_entry_t *l_cur, *l_tmp;
            HASH_ITER(hh, l_matches, l_cur, l_tmp)
            {
                bool l_match_is_bid = (l_cur->side_version & 0x1);
                const char *l_order_token = l_match_is_bid ? l_cur->pair_key->token_quote : l_cur->pair_key->token_base;
                uint256_t l_exec_order = l_cur->exec_sell;
                if (l_match_is_bid) {
                    if (!IS_ZERO_256(l_cur->exec_quote))
                        l_exec_order = l_cur->exec_quote;
                    else
                        MULT_256_COIN(l_exec_order, l_cur->match.rate, &l_exec_order);
                }
                uint256_t l_pct = uint256_0, l_ratio = uint256_0;
                if (!IS_ZERO_256(l_cur->match.value)) {
                    DIV_256_COIN(l_exec_order, l_cur->match.value, &l_ratio);
                    MULT_256_256(l_ratio, GET_256_FROM_64(100ULL), &l_pct);
                }
                json_object *o = json_object_new_object();
                json_object_object_add(o, "token_sell",
                                       json_object_new_string(l_match_is_bid ? l_cur->pair_key->token_quote : l_cur->pair_key->token_base));
                json_object_object_add(o, "token_buy",
                                       json_object_new_string(l_match_is_bid ? l_cur->pair_key->token_base : l_cur->pair_key->token_quote));
                json_object_object_add(o, "side", json_object_new_string(l_match_is_bid ? "bid" : "ask"));
                json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&l_cur->match.root)));
                json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&l_cur->match.tail)));
                json_object_object_add(o, "rate", json_object_new_string(dap_uint256_to_char_ex(l_cur->match.rate).frac));
                json_object_object_add(o, "order_value", json_object_new_string(dap_uint256_to_char_ex(l_cur->match.value).frac));
                json_object_object_add(o, "order_token", json_object_new_string(l_order_token));
                json_object_object_add(o, "executed", json_object_new_string(dap_uint256_to_char_ex(l_exec_order).frac));
                json_object_object_add(o, "fill_pct", json_object_new_string(dap_uint256_to_char_ex(l_pct).frac));
                json_object_array_add(l_arr, o);
                ++l_match_cnt;
            }
            s_dex_match_pair_index_clear(&l_matches);
        }
        json_object_object_add(l_json_reply, "matches", l_arr);
        json_object_object_add(l_json_reply, "matches_count", json_object_new_int(l_match_cnt));
    } break; // FIND_MATCHES

    case CMD_MIGRATE: {
        if (IS_ZERO_256(l_fee))
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -fee"), -2;
        const char *l_from_hash_str = NULL, *l_rate_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-from", &l_from_hash_str);
        if (!l_from_hash_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -from"), -2;
        dap_hash_fast_t l_from_hash = {};
        if (dap_chain_hash_fast_from_str(l_from_hash_str, &l_from_hash))
            return dap_json_rpc_error_add(*json_arr_reply, -2, "bad -from %s", l_from_hash_str), -2;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-rate", &l_rate_str);
        if (!l_rate_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -rate"), -2;
        uint256_t l_rate = dap_chain_balance_scan(l_rate_str);
        if (IS_ZERO_256(l_rate))
            return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -rate"), -2;
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
        if (!l_wallet)
            return dap_json_rpc_error_add(*json_arr_reply, -3, "wallet open failed"), -3;
        l_ret = dap_chain_net_srv_dex_migrate(l_net, &l_from_hash, l_rate, l_fee, l_wallet, &l_datum);
        dap_chain_wallet_close(l_wallet);
        if (l_ret != DEX_MIGRATE_ERROR_OK)
            l_err_str = DEX_ERROR_STR(s_migrate_error_str, l_ret);
    } break; // MIGRATE

    case CMD_PAIRS: {
        l_json_reply = json_object_new_object();
        json_object *l_pairs_arr = json_object_new_array();
        pthread_rwlock_rdlock(&s_dex_cache_rwlock);
        dex_pair_index_t *l_pair, *l_tmp;
        HASH_ITER(hh, s_dex_pair_index, l_pair, l_tmp)
        {
            // Filter by network: show pairs where base or quote token belongs to requested net
            if (l_pair->key.net_id_base.uint64 != l_net->pub.id.uint64 && l_pair->key.net_id_quote.uint64 != l_net->pub.id.uint64)
                continue;
            json_object *l_pair_obj = json_object_new_object();
            json_object_object_add(l_pair_obj, "base_token", json_object_new_string(l_pair->key.token_base));
            json_object_object_add(l_pair_obj, "quote_token", json_object_new_string(l_pair->key.token_quote));
            json_object_object_add(l_pair_obj, "net_id_base", json_object_new_uint64(l_pair->key.net_id_base.uint64));
            json_object_object_add(l_pair_obj, "net_id_quote", json_object_new_uint64(l_pair->key.net_id_quote.uint64));

            // Fee info: fee_config + decoded mode/value
            json_object *l_fee_obj = json_object_new_object();
            uint8_t l_fc = l_pair->key.fee_config;
            uint8_t l_val = l_fc & 0x7F;
            uint256_t l_fee_val = s_dex_fee_config_to_val(l_fc);
            json_object_object_add(l_fee_obj, "config", json_object_new_int((int)l_fc));
            json_object_object_add(l_fee_obj, "value", json_object_new_string(dap_uint256_to_char_ex(l_fee_val).frac));
            if (l_fc & 0x80) {
                // Percent mode: value × 0.1% of INPUT
                json_object_object_add(l_fee_obj, "type", json_object_new_string(l_val ? "input_pct" : "disabled"));
            } else {
                // Native mode: value × 0.01 native or global fallback
                json_object_object_add(l_fee_obj, "type", json_object_new_string("native"));
                json_object_object_add(l_fee_obj, "ticker", json_object_new_string(l_net->pub.native_ticker));
            }
            json_object_object_add(l_pair_obj, "fee", l_fee_obj);

            json_object_array_add(l_pairs_arr, l_pair_obj);
        }
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
        json_object_object_add(l_json_reply, "pairs", l_pairs_arr);
        json_object_object_add(l_json_reply, "count", json_object_new_int(json_object_array_length(l_pairs_arr)));
    } break; // PAIRS

    case CMD_DECREE: {
        // Decree requires wallet for signing
        if (!l_wallet_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "decree requires -w wallet"), -2;

        // Service key is required for decree signing
        const char *l_service_key_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-service_key", &l_service_key_str);
        if (!l_service_key_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "decree requires -service_key"), -2;

        dap_cert_t *l_service_cert = dap_cert_find_by_name(l_service_key_str);
        if (!l_service_cert)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "service cert '%s' not found", l_service_key_str), -2;

        // Parse and validate decree method
        const char *l_method_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-method", &l_method_str);
        if (!l_method_str)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "missing -method"), -2;

        // Map string to dex_decree_method_t (early validation)
        dex_decree_method_t l_method = DEX_DECREE_UNKNOWN;
        if (!dap_strcmp(l_method_str, "fee_set"))
            l_method = DEX_DECREE_FEE_SET;
        else if (!dap_strcmp(l_method_str, "pair_add"))
            l_method = DEX_DECREE_PAIR_ADD;
        else if (!dap_strcmp(l_method_str, "pair_remove"))
            l_method = DEX_DECREE_PAIR_REMOVE;
        else if (!dap_strcmp(l_method_str, "pair_fee_set"))
            l_method = DEX_DECREE_PAIR_FEE_SET;
        else if (!dap_strcmp(l_method_str, "pair_fee_set_all"))
            l_method = DEX_DECREE_PAIR_FEE_SET_ALL;
        if (l_method == DEX_DECREE_UNKNOWN)
            return dap_json_rpc_error_add(*json_arr_reply, -2, "unknown method '%s'", l_method_str), -2;
        dap_chain_t *l_chain = dap_chain_net_get_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
        if (!l_chain)
            return dap_json_rpc_error_add(*json_arr_reply, -3, "chain not found"), -3;
        // Max TSD buffer: METHOD(1) + FEE_AMOUNT(32) + FEE_ADDR(49) + TOKEN_BASE(10) + TOKEN_QUOTE(10) + NET_BASE(8) + NET_QUOTE(8) +
        // FEE_CONFIG(1) = sizeof(dap_tsd_t) * 8 + 119 bytes data ≈ 200 bytes (conservative estimate)
        byte_t l_tsd_buf[512] = {};
        byte_t *l_ptr = l_tsd_buf;

        // Write METHOD TSD
        uint8_t l_method_byte = (uint8_t)l_method;
        l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_METHOD, &l_method_byte, sizeof(uint8_t));

        // Parse fee params (usage depends on method)
        const char *l_fee_amount_str = NULL, *l_fee_addr_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee_amount", &l_fee_amount_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee_addr", &l_fee_addr_str);

        switch (l_method) {
        case DEX_DECREE_FEE_SET: {
            // fee_set requires both -fee_amount and -fee_addr, no other params
            if (!l_fee_amount_str || !l_fee_addr_str)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "fee_set requires -fee_amount and -fee_addr"), -2;

            uint256_t l_fee_amount = dap_chain_balance_scan(l_fee_amount_str);
            if (IS_ZERO_256(l_fee_amount))
                return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -fee_amount"), -2;

            dap_chain_addr_t *l_fee_addr = dap_chain_addr_from_str(l_fee_addr_str);
            if (!l_fee_addr)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -fee_addr"), -2;

            l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_AMOUNT, &l_fee_amount, sizeof(uint256_t));
            l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_ADDR, l_fee_addr, sizeof(dap_chain_addr_t));
            DAP_DELETE(l_fee_addr);
        } break;

        case DEX_DECREE_PAIR_FEE_SET_ALL: {
            if (l_fee_amount_str || l_fee_addr_str)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "pair_fee_set_all: -fee_amount/-fee_addr not allowed"), -2;

            uint8_t l_fee_config = 0;
            const char *l_err_msg = NULL;
            int l_parsed = s_parse_fee_config_cli(a_argc, a_argv, l_arg_index, &l_fee_config, &l_err_msg);
            if (l_parsed < 0)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "%s", l_err_msg), -2;
            if (l_parsed == 0) {
                // Fallback to raw -fee_config for backward compatibility
                const char *l_fee_config_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee_config", &l_fee_config_str);
                if (!l_fee_config_str)
                    return dap_json_rpc_error_add(*json_arr_reply, -2, "pair_fee_set_all requires -fee_pct, -fee_native, or -fee_config"),
                           -2;
                l_fee_config = (uint8_t)strtoul(l_fee_config_str, NULL, 0);
            }
            l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_CONFIG, &l_fee_config, sizeof(uint8_t));
        } break;

        case DEX_DECREE_PAIR_ADD:
        case DEX_DECREE_PAIR_REMOVE:
        case DEX_DECREE_PAIR_FEE_SET: {
            // Pair operations: no fee_amount/fee_addr allowed
            if (l_fee_amount_str || l_fee_addr_str)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "pair operations: -fee_amount/-fee_addr not allowed"), -2;

            const char *l_token_base = NULL, *l_token_quote = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_base", &l_token_base);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_quote", &l_token_quote);
            if (!l_token_base || !l_token_quote)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "pair operations require -token_base and -token_quote"), -2;

            const char *l_net_base_str = NULL, *l_net_quote_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net_base", &l_net_base_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net_quote", &l_net_quote_str);

            dap_chain_net_id_t l_net_base = l_net->pub.id, l_net_quote = l_net->pub.id;
            if (l_net_base_str) {
                dap_chain_net_t *l_net_tmp = dap_chain_net_by_name(l_net_base_str);
                if (!l_net_tmp)
                    return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -net_base"), -2;
                l_net_base = l_net_tmp->pub.id;
            }
            if (l_net_quote_str) {
                dap_chain_net_t *l_net_tmp = dap_chain_net_by_name(l_net_quote_str);
                if (!l_net_tmp)
                    return dap_json_rpc_error_add(*json_arr_reply, -2, "invalid -net_quote"), -2;
                l_net_quote = l_net_tmp->pub.id;
            }

            l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_BASE, l_token_base, dap_strlen(l_token_base) + 1);
            l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_QUOTE, l_token_quote, dap_strlen(l_token_quote) + 1);
            l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_BASE, &l_net_base, sizeof(uint64_t));
            l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_QUOTE, &l_net_quote, sizeof(uint64_t));

            // Handle fee config (human-readable or raw)
            uint8_t l_fee_config = 0;
            const char *l_err_msg = NULL;
            int l_parsed = s_parse_fee_config_cli(a_argc, a_argv, l_arg_index, &l_fee_config, &l_err_msg);
            if (l_parsed < 0)
                return dap_json_rpc_error_add(*json_arr_reply, -2, "%s", l_err_msg), -2;
            if (l_parsed == 0) {
                // Fallback to raw -fee_config
                const char *l_fee_config_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee_config", &l_fee_config_str);
                if (l_method == DEX_DECREE_PAIR_FEE_SET && !l_fee_config_str)
                    return dap_json_rpc_error_add(*json_arr_reply, -2, "pair_fee_set requires -fee_pct, -fee_native, or -fee_config"), -2;
                if (l_fee_config_str) {
                    if (l_method == DEX_DECREE_PAIR_REMOVE)
                        return dap_json_rpc_error_add(*json_arr_reply, -2, "pair_remove: fee params not allowed"), -2;
                    l_fee_config = (uint8_t)strtoul(l_fee_config_str, NULL, 0);
                    l_parsed = 1;
                }
            } else if (l_method == DEX_DECREE_PAIR_REMOVE) {
                return dap_json_rpc_error_add(*json_arr_reply, -2, "pair_remove: fee params not allowed"), -2;
            }
            if (l_parsed > 0)
                l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_CONFIG, &l_fee_config, sizeof(uint8_t));
        } break;

        default:
            return dap_json_rpc_error_add(*json_arr_reply, -2, "unknown decree method"), -2;
        }

        // Calculate actual TSD size
        size_t l_tsd_size = l_ptr - l_tsd_buf;
        char *l_hash_str = NULL;
        // Create decree and submit to mempool
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
        if (l_wallet) {
            dap_enc_key_t *l_key_from = dap_chain_wallet_get_key(l_wallet, 0);
            if (l_key_from) {
                l_hash_str =
                    dap_chain_mempool_tx_create_service_decree(l_chain, l_key_from, l_service_cert->enc_key,
                                                               (dap_chain_net_srv_uid_t){.uint64 = DAP_CHAIN_NET_SRV_DEX_ID}, // a_srv_uid
                                                               l_tsd_buf,  // a_service_decree_data
                                                               l_tsd_size, // a_service_decree_data_size
                                                               l_fee,      // a_fee_value (no additional fee)
                                                               "hex"       // a_hash_out_type
                    );
                dap_enc_key_delete(l_key_from);
            } else {
                dap_json_rpc_error_add(*json_arr_reply, -3, "wallet key not found");
                l_ret = -3;
            }
            dap_chain_wallet_close(l_wallet);
        } else {
            dap_json_rpc_error_add(*json_arr_reply, -3, "wallet open failed");
            l_ret = -3;
        }

        if (l_ret)
            return l_ret;

        l_json_reply = json_object_new_object();
        if (l_hash_str) {
            json_object_object_add(l_json_reply, "status", json_object_new_string("decree_submitted"));
            json_object_object_add(l_json_reply, "tx_hash", json_object_new_string(l_hash_str));
            json_object_object_add(l_json_reply, "method", json_object_new_string(l_method_str));
            json_object_object_add(l_json_reply, "tsd_size", json_object_new_int64(l_tsd_size));
            DAP_DELETE(l_hash_str);
            l_ret = 0;
        } else {
            json_object_object_add(l_json_reply, "status", json_object_new_string("decree_submission_failed"));
            json_object_object_add(l_json_reply, "error", json_object_new_string("mempool tx creation failed"));
            l_ret = -4;
        };
    } break; // DECREE

    default:
        return dap_json_rpc_error_add(*json_arr_reply, -1, "unknown command"), -1;
    }

    if (!l_json_reply)
        l_json_reply = json_object_new_object();
    json_object_object_add(l_json_reply, "command", json_object_new_string(l_cmd_str[l_cmd]));

    if (!l_ret) {
        if (l_datum) {
            char *l_hash = s_dex_tx_put(l_datum, l_net);
            if (l_hash) {
                json_object_object_add(l_json_reply, "tx_hash", json_object_new_string(l_hash));
                DAP_DELETE(l_hash);
            } else {
                l_ret = -3;
                dap_json_rpc_error_add(*json_arr_reply, l_ret, "cannot place TX to mempool");
            }
        }
    } else
        dap_json_rpc_error_add(*json_arr_reply, l_ret, "error %d: %s", l_ret, l_err_str);
    json_object_array_add(*json_arr_reply, l_json_reply);
    return l_ret;
#undef DEX_ERROR_STR
}