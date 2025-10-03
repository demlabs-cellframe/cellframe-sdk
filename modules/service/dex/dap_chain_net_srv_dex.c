/*
 * DEX v2 service (SRV_DEX)
 */

#include <pthread.h>
#include <stdbool.h>
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
#include "dap_math_ops.h"
#include "dap_hash.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv_dex.h"
#include "dap_config.h"
#include "dap_cli_server.h"
#include "dap_chain_mempool.h"
#include "dap_strfuncs.h"
#include "uthash.h"
#include "dap_time.h"
/* #include "utlist.h" */
#define LOG_TAG "dap_chain_net_srv_dex"

typedef struct dex_pair_key {
    dap_chain_net_id_t sell_net_id, buy_net_id;
    char sell_token[DAP_CHAIN_TICKER_SIZE_MAX], buy_token[DAP_CHAIN_TICKER_SIZE_MAX];
} dex_pair_key_t;

typedef struct dex_order_match {
    uint256_t value, rate;          // remaining sell amount, canonical QUOTE/BASE price
    dap_hash_fast_t root, tail;     // order chain root, current tail tx hash
    uint8_t min_fill;               // combined: low7=pct (0..100), bit7=from_origin
    int prev_idx;                   // index of SRV_DEX OUT in tail tx (optional, -1 if unknown)
} dex_order_match_t;

// Unified lightweight order view for matching/simulation (cache and ledger)
typedef struct dex_order_level {
    dex_order_match_t match;
    UT_hash_handle hh, hh_tail;
} dex_order_level_t;

// Level comparators for HASH_SORT over dex_order_level_t
static inline int s_cmp_level_entries_ask(dex_order_level_t *a, dex_order_level_t *b) { return compare256_ptr(&a->match.rate, &b->match.rate); }
static inline int s_cmp_level_entries_bid(dex_order_level_t *a, dex_order_level_t *b) { return compare256_ptr(&b->match.rate, &a->match.rate); }

typedef struct dex_order_cache_entry {
    dex_order_level_t level;       // unified order state
    // Pointer-only references to parent bucket keys (no duplication in entries)
    const dex_pair_key_t    *pair_key_ptr;    // points to dex_pair_index_t.key
    const dap_chain_addr_t  *seller_addr_ptr; // points to dex_seller_index_t.seller_addr
    UT_hash_handle hh_pair_bucket, hh_seller_bucket;
    dap_time_t ts_created, ts_expires;
    uint32_t flags;
    uint8_t  side_version;   // bit0=side; bits1..7=version
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
 static bool s_dex_cache_enabled = false; // global switch from config

typedef struct dex_pair_index {
    dex_pair_key_t key;
    dex_order_cache_entry_t *asks, *bids; // heads keyed by hh_pair_bucket
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
    dex_order_match_t   match;          // match snapshot
    dex_pair_key_t     *pair_key;       // pair key (sell/buy tickers + nets)
    dap_chain_addr_t    seller_addr;    // inline seller address
    uint8_t             side_version;   // from cache payload
    uint32_t            flags;          // from cache payload
    dap_time_t          ts_created, ts_expires;
    uint256_t           exec_sell, exec_min; // executed and minimal BASE for this entry
    UT_hash_handle      hh;             // keyed by match.tail
} dex_match_table_entry_t;

// Match criteria
typedef struct dex_match_criteria {
    const char *sell_token, *buy_token; // what buyer wants to get // what buyer pays
    dap_chain_net_id_t sell_net_id, buy_net_id;
    uint256_t max_buy_value, min_rate;  // amount in buy_token // rate threshold (minimum acceptable for buyer)
} dex_match_criteria_t;

// Match table sort helpers (by price)
static inline int s_cmp_match_entries_ask(dex_match_table_entry_t *a, dex_match_table_entry_t *b) { return compare256_ptr(&a->match.rate, &b->match.rate); }
static inline int s_cmp_match_entries_bid(dex_match_table_entry_t *a, dex_match_table_entry_t *b) { return compare256_ptr(&b->match.rate, &a->match.rate); }

// UX helpers
static bool s_parse_natural_time(dap_ledger_t *a_ledger, const char *a_str, dap_time_t *a_out_ts)
{
    dap_ret_val_if_any(false, !a_str, !*a_str, !a_out_ts, !a_ledger);

    /* "now" */
    if (!dap_strcmp(a_str, "now")) {
        *a_out_ts = dap_time_now();
        return true;
    }
    /* "-1h", "-30m", "-2d" */
    if (*a_str == '-') {
        int l_val;
        for (l_val = 0; dap_is_digit(*a_str); l_val = l_val * 10 + (*a_str - '0'), a_str++);
        if (!l_val) return false;
        dap_time_t delta = l_val, l_now = dap_time_now();
        switch (*a_str) {
            case 'm': delta *= 60; break;
            case 'h': delta *= 3600; break; 
            case 'd': delta *= 86400; break;
            default: return false;
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

static void s_ledger_tx_add_notify_dex(void *a_arg, dap_ledger_t *a_ledger,
    dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, dap_chan_ledger_notify_opcodes_t a_opcode);
static dex_tx_type_t s_dex_tx_classify(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_in_cond_t **a_in_cond,
                             dap_chain_tx_out_cond_t **a_out_cond, int *a_out_idx);
static char* s_dex_tx_put(dap_chain_datum_tx_t *a_tx, dap_chain_net_t *a_net);

static dex_match_table_entry_t *s_dex_matches_build_by_criteria(dap_chain_net_t *a_net, const dex_match_criteria_t *a_criteria);
static int s_dex_match_snapshot_by_tail(dap_chain_net_t *a_net, const dap_hash_fast_t *a_tail, dex_match_table_entry_t *a_out, dex_pair_key_t *a_out_key);
static dex_match_table_entry_t *s_dex_matches_build_by_hashes(dap_chain_net_t *a_net, const dap_hash_fast_t *a_hashes,
        size_t a_count, uint256_t a_budget_quote, int *a_out_err);

// Forward decl for cleanup helper
static inline void s_dex_matches_clear(dex_match_table_entry_t **a_head) {
    if (!a_head || !*a_head) return;
    dex_match_table_entry_t *e = NULL, *t = NULL; HASH_ITER(hh, *a_head, e, t) {
        HASH_DEL(*a_head, e); DAP_DELETE(e);
    }
}

static inline void s_dex_match_pair_index_clear(dex_match_table_entry_t **a_idx) {
    dap_ret_if_any(!a_idx, !*a_idx);
    DAP_DELETE((*a_idx)->pair_key);
    s_dex_matches_clear(a_idx);
}

#define DEX_MAX_IN 64
// Cross-net policy: soft control outside consensus
typedef enum { CROSS_NET_REJECT = 0, CROSS_NET_WARN = 1, CROSS_NET_ALLOW = 2 } cross_net_policy_t;
static cross_net_policy_t s_cross_net_policy = CROSS_NET_REJECT; // default

static inline const char *s_cross_net_policy_str(cross_net_policy_t p) {
    return p == CROSS_NET_ALLOW ? "allow" : p == CROSS_NET_WARN ? "warn" : "reject";
}

// Verificator error codes (positive) and messages; return values remain negative (-code)
typedef enum {
    DEXV_OK                        = 0,
    DEXV_INVALID_PARAMS            = 1,
    DEXV_MULTIPLE_SRV_DEX_OUT      = 2,
    DEXV_NO_IN                     = 3,
    DEXV_PREV_TX_NOT_FOUND         = 5,
    DEXV_PREV_OUT_NOT_FOUND        = 6,
    DEXV_EXPIRED                   = 7,
    DEXV_BASELINE_BUY_TOKEN        = 8,
    DEXV_BASELINE_TUPLE            = 9,
    DEXV_INVALID_RESIDUAL          = 10,
    DEXV_MIN_FILL_AON              = 11,
    DEXV_MIN_FILL_NOT_REACHED      = 12,
    DEXV_TX_TYPE_MISMATCH          = 13,
    DEXV_IMMUTABLES_VIOLATION      = 14,
    DEXV_SERVICE_FEE_UNDERPAID     = 15,
    DEXV_NETWORK_FEE_UNDERPAID     = 16,
    DEXV_BUY_TOKEN_LEAK            = 17,
    DEXV_SELLER_PAID_IN_UPDATE     = 18,
    DEXV_BUYER_ADDR_MISSING        = 20,
    DEXV_BUYER_MISMATCH            = 21,
    DEXV_MULTI_BUYER_DEST          = 22,
    DEXV_FINAL_NATIVE_MISMATCH     = 23,
    DEXV_FINAL_NONNATIVE_MISMATCH  = 24,
} dex_verif_code_t;

static const char *s_dex_verif_err_strs[] = {
    [DEXV_INVALID_PARAMS]           = "Invalid parameters",
    [DEXV_MULTIPLE_SRV_DEX_OUT]     = "More than one SRV_DEX out",
    [DEXV_NO_IN]                    = "No IN_COND",
    [DEXV_PREV_TX_NOT_FOUND]        = "Previous tx not found",
    [DEXV_PREV_OUT_NOT_FOUND]       = "Previous SRV_DEX out not found",
    [DEXV_EXPIRED]                  = "Previous order expired",
    [DEXV_BASELINE_BUY_TOKEN]       = "Baseline buy token mismatch",
    [DEXV_BASELINE_TUPLE]           = "Baseline market tuple mismatch",
    [DEXV_INVALID_RESIDUAL]         = "Invalid residual (leftover) value",
    [DEXV_MIN_FILL_AON]             = "AON min_fill disallowed for partial update",
    [DEXV_MIN_FILL_NOT_REACHED]     = "Min_fill threshold not satisfied",
    [DEXV_TX_TYPE_MISMATCH]         = "SRV_DEX tx_type mismatch to scenario",
    [DEXV_IMMUTABLES_VIOLATION]     = "Immutable fields changed in update",
    [DEXV_SERVICE_FEE_UNDERPAID]    = "Service fee underpaid or misrouted",
    [DEXV_NETWORK_FEE_UNDERPAID]    = "Network fee underpaid",
    [DEXV_BUY_TOKEN_LEAK]           = "Unexpected buy-token payouts (non-seller/non-service)",
    [DEXV_SELLER_PAID_IN_UPDATE]    = "Seller paid in owner update",
    [DEXV_BUYER_ADDR_MISSING]       = "Buyer address not found",
    [DEXV_BUYER_MISMATCH]           = "Buyer-leftover seller mismatch",
    [DEXV_MULTI_BUYER_DEST]         = "Multiple buyer destinations",
    [DEXV_FINAL_NATIVE_MISMATCH]    = "Final sell payout mismatch (native)",
    [DEXV_FINAL_NONNATIVE_MISMATCH] = "Final sell payout mismatch (non-native)",
};

static const char *s_dex_verif_err_str(int a_ret)
{
    int l_code = dap_abs(a_ret);
    return l_code > 0 && (size_t)l_code < sizeof(s_dex_verif_err_strs) / sizeof(s_dex_verif_err_strs[0])
        ? s_dex_verif_err_strs[l_code] : "unknown error";
}

// Service fee storage by net id
static dap_chain_net_srv_fee_item_t *s_dex_service_fees = NULL;
static pthread_rwlock_t s_dex_service_fees_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static bool s_dex_get_service_fee(dap_chain_net_id_t a_net_id, uint256_t *a_fee, dap_chain_addr_t *a_addr, uint16_t *a_type)
{
    dap_chain_net_srv_fee_item_t *l_fee = NULL;
    bool l_res = false;
    pthread_rwlock_rdlock(&s_dex_service_fees_rwlock);
    HASH_FIND(hh, s_dex_service_fees, &a_net_id, sizeof(a_net_id), l_fee);
    if (l_fee && !IS_ZERO_256(l_fee->fee)) {
        if (a_type) *a_type = l_fee->fee_type;
        if (a_addr) *a_addr = l_fee->fee_addr;
        if (a_fee)  *a_fee  = l_fee->fee;
        l_res = true;
    }
    pthread_rwlock_unlock(&s_dex_service_fees_rwlock);
    return l_res;
}

/* History cache (OHLCV) switches */
static bool s_dex_history_enabled = false; // enabled via config
static uint64_t s_dex_history_bucket_sec = 60ULL; // default bucket size

static inline int s_rate_cmp_asc(dex_order_cache_entry_t *a, dex_order_cache_entry_t *b) {
    return compare256(a->level.match.rate, b->level.match.rate);
}

static inline uint256_t s_calc_pct(const uint256_t a, const uint64_t b) {
    uint256_t l_ret = uint256_0;
    if (b && !IS_ZERO_256(a)) {
        MULT_256_COIN(a, GET_256_FROM_64(b), &l_ret);
        DIV_256(l_ret, GET_256_FROM_64(100ULL), &l_ret);
    }
    return l_ret;
}

/*
 * s_dex_fetch_min_abs
 * Compute absolute minimum fill amount against the original order value
 * Inputs:
 *   - a_ledger: ledger handle
 *   - a_hash:   transaction hash pointing to the order output (root or specific tail)
 *   - a_out:    pointer to result
 * Logic:
 *   - Find transaction by hash, get SRV_DEX out_cond
 *   - Extract percentage (low 7 bits of min_fill) and compute pct% of out_cond->value
 * Returns 0 on success, -1 on failure.
 */
static int s_dex_fetch_min_abs(dap_ledger_t *a_ledger, const dap_hash_fast_t *a_hash, uint256_t *a_out) {
    dap_ret_val_if_any(-1, !a_hash, !a_out);
    if ( s_dex_cache_enabled ) {
        int l_ret = -1;
        //pthread_rwlock_rdlock(&s_dex_cache_rwlock);  // lock in caller
        dex_order_cache_entry_t *e = NULL; HASH_FIND(level.hh_tail, s_dex_index_by_tail, a_hash, sizeof(*a_hash), e);
        if (e) {
            *a_out = s_calc_pct(e->level.match.value, e->level.match.min_fill & 0x7F);
            l_ret = 0;
        }
        //pthread_rwlock_unlock(&s_dex_cache_rwlock);  // unlock in caller
        return l_ret;
    }
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_ledger, a_hash);
    if ( l_tx ) {
        dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
        if ( l_out_cond ) {
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

static int s_token_tuple_cmp(dap_chain_net_id_t a_net, const char *a_tok, dap_chain_net_id_t b_net, const char *b_tok)
{
    return a_net.uint64 < b_net.uint64 ? -1 : a_net.uint64 > b_net.uint64 ? 1 : strcmp(a_tok, b_tok);
}

// Normalize pair to canonical base/quote ordering and compute side and canonical price
/*
 * s_pair_normalize
 * Canonicalize an order pair and compute canonical side and QUOTE/BASE price.
 * Inputs:
 *   - a_sell_tok/a_sell_net: order's sell token and net (as submitted)
 *   - a_buy_tok/a_buy_net:   buy token and net (as submitted)
 *   - a_rate_buy_per_sell:   price in units of BUY per 1 SELL (scaled 1e18)
 *   - a_canon_key:           output canonical key (BASE=lexicographically smaller tuple)
 *   - a_side:                output side (ASK if (sell,buy) already canonical; BID otherwise)
 *   - a_price_canon:         output price QUOTE/BASE (if BID, inverted)
 * Logic:
 *   - Compare (sell_net,sell_tok) vs (buy_net,buy_tok). If sell<=buy → ASK; else BID and invert rate.
 * Returns: void; no output if required pointers are NULL.
 */
static void s_pair_normalize(const char *a_sell_tok, dap_chain_net_id_t a_sell_net,
                             const char *a_buy_tok, dap_chain_net_id_t a_buy_net,
                             const uint256_t a_rate_buy_per_sell,
                             dex_pair_key_t *a_canon_key, uint8_t *a_side, uint256_t *a_price_canon)
{
    dap_ret_if_any(!a_sell_tok, !*a_sell_tok, !a_buy_tok, !*a_buy_tok, !a_canon_key);
    if ( strcmp(a_sell_tok, a_buy_tok) >= 0 ) {
        a_canon_key->sell_net_id = a_sell_net;
        a_canon_key->buy_net_id = a_buy_net;
        dap_strncpy(a_canon_key->sell_token, a_sell_tok, sizeof(a_canon_key->sell_token)-1);
        dap_strncpy(a_canon_key->buy_token, a_buy_tok, sizeof(a_canon_key->buy_token)-1);
        if (a_side) {
            *a_side = DEX_SIDE_ASK;
        }
        if (a_price_canon) {
            *a_price_canon = a_rate_buy_per_sell;
        }
    } else {
        a_canon_key->sell_net_id = a_buy_net; a_canon_key->buy_net_id = a_sell_net;
        dap_strncpy(a_canon_key->sell_token, a_buy_tok, sizeof(a_canon_key->sell_token)-1);
        dap_strncpy(a_canon_key->buy_token, a_sell_tok, sizeof(a_canon_key->buy_token)-1);
        if (a_side) {
            *a_side = DEX_SIDE_BID;
        }
        if (a_price_canon) {
            uint256_t one = GET_256_FROM_64(1000000000000000000ULL); // 10^18
            DIV_256_COIN(one, a_rate_buy_per_sell, a_price_canon);
        }
    }
}

/*
 * s_dex_pair_index_get_or_create
 * Lookup pair bucket by canonical key or create a new one.
 * Inputs: a_key — canonical pair (BASE/QUOTE).
 * On miss: allocate bucket, copy key, add to top-level hash.
 * Returns pointer to bucket or NULL on allocation failure.
 */
static dex_pair_index_t *s_dex_pair_index_get_or_create(const dex_pair_key_t *a_key)
{
    dap_ret_val_if_any(NULL, !a_key);
    dex_pair_index_t *l_ret = NULL;
    HASH_FIND(hh, s_dex_pair_index, a_key, sizeof(*a_key), l_ret);
    if (!l_ret) {
        l_ret = DAP_NEW_Z_RET_VAL_IF_FAIL(dex_pair_index_t, NULL);
        l_ret->key = *a_key;
        HASH_ADD(hh, s_dex_pair_index, key, sizeof(l_ret->key), l_ret);
    }
    return l_ret;
}
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
    dex_seller_index_t *l_ret = NULL;
    HASH_FIND(hh, s_dex_seller_index, a_addr, sizeof(*a_addr), l_ret);
    if (!l_ret) {
        l_ret = DAP_NEW_Z_RET_VAL_IF_FAIL(dex_seller_index_t, NULL);
        l_ret->seller_addr = *a_addr;
        HASH_ADD(hh, s_dex_seller_index, seller_addr, sizeof(l_ret->seller_addr), l_ret);
    }
    return l_ret;
}

// Comparator for pair bucket entries: rate ASC, ts_created ASC, root ASC
static int s_cmp_pair_bucket_entries(dex_order_cache_entry_t *a, dex_order_cache_entry_t *b)
{
    int l_rc = s_rate_cmp_asc(a, b);
    return l_rc ? l_rc : a->ts_created < b->ts_created ? -1 : a->ts_created > b->ts_created
        ? 1 : memcmp(&a->level.match.root, &b->level.match.root, sizeof(a->level.match.root));
}

/*
 * Sort entries in pair buckets:
 * - Asks: ascending by price (QUOTE/BASE), then ts_created, then root
 * - Bids: keep the same ascending order; where highest-first is needed, iterate in reverse
 * This keeps a single comparator and stable ordering across buckets.
 */
static void s_dex_pair_bucket_sort(dex_pair_index_t *a_bucket)
{
    dap_ret_if_any(!a_bucket);
    if (a_bucket->asks)
        HASH_SRT(hh_pair_bucket, a_bucket->asks, s_cmp_pair_bucket_entries);
    if (a_bucket->bids) {
        HASH_SRT(hh_pair_bucket, a_bucket->bids, s_cmp_pair_bucket_entries);
    }
}

// -------- Transient order set based on dex_order_cache_entry_t --------

// Add single hash (root or tail) to transient table
static int s_dex_match_snapshot_by_tail(dap_chain_net_t *a_net, const dap_hash_fast_t *a_tail, dex_match_table_entry_t *a_out, dex_pair_key_t *a_out_key)
{
    dap_ret_val_if_any(-1, !a_net, !a_tail, !a_out);
    // Cache first
    if (s_dex_cache_enabled) {
        pthread_rwlock_rdlock(&s_dex_cache_rwlock);
        dex_order_cache_entry_t *e = NULL; HASH_FIND(level.hh_tail, s_dex_index_by_tail, a_tail, sizeof(*a_tail), e);
        if (e) {
            *a_out = (dex_match_table_entry_t){ .match = e->level.match,
                .seller_addr = *(dap_chain_addr_t*)e->seller_addr_ptr, .side_version = e->side_version,
                .flags = e->flags, .ts_created = e->ts_created, .ts_expires = e->ts_expires };
            if (a_out_key) *a_out_key = *e->pair_key_ptr;
        }
        if (!e) return pthread_rwlock_unlock(&s_dex_cache_rwlock), -1;
    } else {
        // Ledger fallback
        dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, (dap_chain_hash_fast_t *)a_tail);
        if (!l_tx) return -2;
        int l_out_idx = 0;
        dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
        if (!l_out_cond) return -3;
        const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, (dap_chain_hash_fast_t*)a_tail);
        if (!l_sell_tok) return -4;
        dex_pair_key_t l_key = { }; uint8_t l_side = 0; uint256_t l_price = uint256_0;
        s_pair_normalize(l_sell_tok, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
            l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key, &l_side, &l_price);
        *a_out = (dex_match_table_entry_t){
            .match = (dex_order_match_t){
                .value = l_out_cond->header.value, .rate = l_price,
                .root = dap_ledger_get_first_chain_tx_hash(a_net->pub.ledger, l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX),
                .tail = *a_tail, .min_fill = l_out_cond->subtype.srv_dex.min_fill, .prev_idx = l_out_idx },
            .seller_addr = l_out_cond->subtype.srv_dex.seller_addr,
            .side_version = (uint8_t)((l_out_cond->subtype.srv_dex.version & 0x7F) << 1) | (l_side & 0x1),
            .flags = l_out_cond->subtype.srv_dex.flags,
            .ts_created = l_tx->header.ts_created, .ts_expires = l_out_cond->header.ts_expires };
        if (a_out_key) *a_out_key = l_key;
    }
    // Precompute exec_min once per snapshot
    uint8_t l_pct = a_out->match.min_fill & 0x7F;
    if (l_pct) {
        if (a_out->match.min_fill & 0x80) {
            // from origin (uses cache-first inside s_dex_fetch_min_abs)
            if ( s_dex_fetch_min_abs(a_net->pub.ledger, &a_out->match.root, &a_out->exec_min) )
                a_out->exec_min = uint256_0;
        } else
            a_out->exec_min = s_calc_pct(a_out->match.value, l_pct);
    }
    if ( s_dex_cache_enabled )
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
    return 0;
}

// Build transient table from hashes (roots or tails). Uses cache when available; otherwise reads ledger once per hash.
static dex_match_table_entry_t *s_dex_matches_build_by_hashes(dap_chain_net_t *a_net, const dap_hash_fast_t *a_hashes,
        size_t a_count, uint256_t a_budget_quote, int *a_out_err)
{
    dap_do_if_any(
        if (a_out_err) *a_out_err = DEX_PURCHASE_MULTI_ERROR_INVALID_ARGUMENT; return NULL;
    , !a_net, !a_hashes, !a_count);
    dex_match_table_entry_t *l_entries = NULL, *l_cur = DAP_NEW_Z(dex_match_table_entry_t);
    dex_pair_key_t *l_key_common = NULL;
    uint8_t l_side0 = ~0;
    size_t i;
    for ( i = 0; i < a_count || ( DAP_DELETE(l_cur), false ); ++i ) {
        dex_pair_key_t l_cur_key;
        if ( s_dex_match_snapshot_by_tail(a_net, &a_hashes[i], l_cur, &l_cur_key) ) 
            continue;
        if (IS_ZERO_256(l_cur->match.value) || IS_ZERO_256(l_cur->match.rate))
            continue;
        // exec_min is computed inside snapshot_by_tail; nothing to do here
        if (!l_key_common)
            l_key_common = DAP_DUP(&l_cur_key);
        // Enforce single-pair: first mismatch aborts with error
        else if ( memcmp(l_key_common, &l_cur_key, sizeof(l_cur_key)) )
            break;
        // Enforce single-side: fix by the first entry and require all others to match
        uint8_t l_side_i = l_cur->side_version & 0x1;
        if (l_side0 == (uint8_t)~0)
            l_side0 = l_side_i;
        else if (l_side_i != l_side0)
            break;       
        l_cur->pair_key = l_key_common;

        HASH_ADD(hh, l_entries, match.tail, sizeof(l_cur->match.tail), l_cur);
        l_cur = DAP_NEW_Z(dex_match_table_entry_t);
    }
    if ( !l_entries ) {
        DAP_DELETE(l_key_common);
        if (a_out_err) *a_out_err = DEX_PURCHASE_MULTI_ERROR_ORDERS_EMPTY;
        return NULL;
    } else if ( i != a_count ) {
        s_dex_match_pair_index_clear(&l_entries);
        if (a_out_err) *a_out_err = DEX_PURCHASE_MULTI_ERROR_PAIR_MISMATCH;
        return NULL;
    }

    // Sort by better price: ASK asc (cheaper quote), BID desc (higher quote)
    if (l_side0 == DEX_SIDE_ASK) HASH_SORT(l_entries, s_cmp_match_entries_ask);
    else HASH_SORT(l_entries, s_cmp_match_entries_bid);
    
    if ( IS_ZERO_256(a_budget_quote) ) {
        // Full-fill attempt: execute full value for all matches
        dex_match_table_entry_t *tmp = NULL; HASH_ITER(hh, l_entries, l_cur, tmp) l_cur->exec_sell = l_cur->match.value;
    } else {
        dex_match_table_entry_t *tmp = NULL; HASH_ITER(hh, l_entries, l_cur, tmp) {
            if ( IS_ZERO_256(a_budget_quote) ) {
                HASH_DEL(l_entries, l_cur); DAP_DELETE(l_cur);
                continue;
            }
            uint8_t l_pct = l_cur->match.min_fill & 0x7F;
            if ( l_side0 == DEX_SIDE_ASK ) {
                uint256_t l_max_q = uint256_0; MULT_256_COIN(l_cur->match.value, l_cur->match.rate, &l_max_q);
                if ( compare256(a_budget_quote, l_max_q) >= 0 ) {
                    l_cur->exec_sell = l_cur->match.value;
                    SUBTRACT_256_256(a_budget_quote, l_max_q, &a_budget_quote);
                    continue;
                } else if (l_pct != 100) {
                    DIV_256_COIN(a_budget_quote, l_cur->match.rate, &l_cur->exec_sell);
                    if ( l_pct > 0 && compare256(l_cur->exec_sell, l_cur->exec_min) >= 0 && !IS_ZERO_256(l_cur->exec_sell) ) {
                        a_budget_quote = uint256_0;
                        continue;
                    }
                }
            } else {
                // max BASE needed to fully consume this QUOTE
                uint256_t l_max_b = uint256_0; DIV_256_COIN(l_cur->match.value, l_cur->match.rate, &l_max_b);
                if (compare256(a_budget_quote, l_max_b) >= 0) {
                    l_cur->exec_sell = l_max_b; SUBTRACT_256_256(a_budget_quote, l_max_b, &a_budget_quote);
                } else if (l_pct != 100) {
                    // Partial: take all remaining BASE budget; verify min_fill against QUOTE executed
                    l_cur->exec_sell = a_budget_quote; // BASE executed
                    if ( l_pct > 0 && !IS_ZERO_256(l_cur->exec_sell) ) {
                        uint256_t l_exec_q = uint256_0; MULT_256_COIN(l_cur->exec_sell, l_cur->match.rate, &l_exec_q);
                        if ( compare256(l_exec_q, l_cur->exec_min) >= 0 ) {
                            a_budget_quote = uint256_0;
                            continue;
                        }
                    }
                }
            }
            HASH_DEL(l_entries, l_cur); DAP_DELETE(l_cur);
        }
    }
    if (a_out_err) *a_out_err = DEX_PURCHASE_MULTI_ERROR_OK;
    return l_entries;
}

// Allocate matches into execution index: greedily consume QUOTE budget across ASK entries
// Build final matched table from a temporary snapshot set; result entries are independent snapshots

// Build matches by criteria (one stage): cache-first over pair buckets; ledger fallback builds a temp snapshot table
static dex_match_table_entry_t *s_dex_matches_build_by_criteria(dap_chain_net_t *a_net, const dex_match_criteria_t *a_criteria)
{
    if (!a_net || !a_criteria) return NULL;
    dex_match_table_entry_t *l_res = NULL;
    // Canonical pair and side
    dex_pair_key_t l_key = { }; uint8_t l_side = 0; s_pair_normalize(a_criteria->sell_token, a_criteria->sell_net_id,
        a_criteria->buy_token, a_criteria->buy_net_id, GET_256_FROM_64(1000000000000000000ULL), &l_key, &l_side, NULL);
    uint256_t l_budget = a_criteria->max_buy_value;
    // Prepare common pair key for all matches
    dex_pair_key_t *l_common = DAP_DUP(&l_key);

    // Cache path
    if (s_dex_cache_enabled) {
        pthread_rwlock_rdlock(&s_dex_cache_rwlock);
        dex_pair_index_t *l_pair_bucket = NULL; HASH_FIND(hh, s_dex_pair_index, &l_key, sizeof(l_key), l_pair_bucket);
        if (l_pair_bucket) {
            dap_time_t l_now_ts = dap_ledger_get_blockchain_time(a_net->pub.ledger);
            dex_order_cache_entry_t *head = (l_side == DEX_SIDE_ASK) ? l_pair_bucket->asks : l_pair_bucket->bids;
            dex_order_cache_entry_t *e = NULL, *tmp = NULL;
            HASH_ITER(hh_pair_bucket, head, e, tmp) {
                if ( IS_ZERO_256(l_budget) && !IS_ZERO_256(a_criteria->max_buy_value) ) break;
                if ( e->ts_expires && l_now_ts > e->ts_expires ) continue;
                if ( !IS_ZERO_256(a_criteria->min_rate) ) {
                    int l_cmp = compare256(e->level.match.rate, a_criteria->min_rate);
                    if ( l_side == DEX_SIDE_ASK ? (l_cmp > 0) : (l_cmp < 0) )
                        continue;
                }
                // Decide execution against current budget
                uint256_t l_exec_sell = uint256_0;
                if ( IS_ZERO_256(a_criteria->max_buy_value) )
                    l_exec_sell = e->level.match.value;
                else {
                    if (l_side == DEX_SIDE_ASK) {
                        uint256_t l_max_q = uint256_0; MULT_256_COIN(e->level.match.value, e->level.match.rate, &l_max_q);
                        if ( compare256(l_budget, l_max_q) >= 0 ) {
                            l_exec_sell = e->level.match.value;
                            SUBTRACT_256_256(l_budget, l_max_q, &l_budget);
                        } else {
                            uint8_t l_pct = e->level.match.min_fill & 0x7F;
                            if (l_pct == 100) continue;
                            DIV_256_COIN(l_budget, e->level.match.rate, &l_exec_sell);
                            if (l_pct > 0) {
                                uint256_t l_min_abs = uint256_0;
                                int l_min_fetch_res = 0;
                                if ( (e->level.match.min_fill & 0x80) )
                                    l_min_fetch_res = s_dex_fetch_min_abs(a_net->pub.ledger, &e->level.match.root, &l_min_abs);
                                else
                                    l_min_abs = s_calc_pct(e->level.match.value, l_pct);
                                if ( l_min_fetch_res || compare256(l_exec_sell, l_min_abs) < 0 ) continue;
                                l_budget = uint256_0;
                            }
                        }
                    } else { // BID
                        uint256_t l_max_b = uint256_0; DIV_256_COIN(e->level.match.value, e->level.match.rate, &l_max_b);
                        if ( compare256(l_budget, l_max_b) >= 0 ) {
                            l_exec_sell = e->level.match.value;
                            SUBTRACT_256_256(l_budget, l_max_b, &l_budget);
                        } else {
                            uint8_t l_pct = e->level.match.min_fill & 0x7F;
                            if (l_pct == 100) continue;
                            // Partial: BASE budget directly defines exec_sell in BASE
                            l_exec_sell = l_budget;
                            if (l_pct > 0) {
                                uint256_t l_min_abs = uint256_0;
                                int l_min_fetch_res = 0;
                                if ( (e->level.match.min_fill & 0x80) )
                                    l_min_fetch_res = s_dex_fetch_min_abs(a_net->pub.ledger, &e->level.match.root, &l_min_abs);
                                else
                                    l_min_abs = s_calc_pct(e->level.match.value, l_pct);
                                // Compare executed QUOTE against required SELL (QUOTE)
                                uint256_t l_exec_q = uint256_0; MULT_256_COIN(l_exec_sell, e->level.match.rate, &l_exec_q);
                                if ( l_min_fetch_res || compare256(l_exec_q, l_min_abs) < 0 ) continue;
                                l_budget = uint256_0;
                            }
                        }
                    }
                }
                if (IS_ZERO_256(l_exec_sell)) continue;
                // Snapshot entry for composer (attach common pair key)
                dex_match_table_entry_t *l_match = DAP_NEW(dex_match_table_entry_t);
                *l_match = (dex_match_table_entry_t) {
                    .match = e->level.match,
                    .pair_key = l_common,
                    .seller_addr = *(dap_chain_addr_t*)e->seller_addr_ptr,
                    .side_version = e->side_version,
                    .flags = e->flags,
                    .ts_created = e->ts_created,
                    .ts_expires = e->ts_expires,
                    .exec_sell = l_exec_sell
                };
                HASH_ADD(hh, l_res, match.tail, sizeof(l_match->match.tail), l_match);
            }
        }
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
        return l_res;
    }
    // Ledger fallback: collect snapshots by criteria into temp table, then reuse from_temp logic
    dex_order_cache_entry_t *l_tmp = NULL;
    dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(a_net);
    for (dap_chain_datum_tx_t *tx = dap_ledger_datum_iter_get_first(it); tx; tx = dap_ledger_datum_iter_get_next(it)) {
        if ( IS_ZERO_256(l_budget) && !IS_ZERO_256(a_criteria->max_buy_value) ) break;
        int l_out_idx = 0; dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_out_cond_get(tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
        if ( !l_out || dap_ledger_tx_hash_is_used_out_item(a_net->pub.ledger, &it->cur_hash, l_out_idx, NULL) )
            continue;
        if (l_out->header.ts_expires && dap_ledger_get_blockchain_time(a_net->pub.ledger) > l_out->header.ts_expires)
            continue;
        const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &it->cur_hash);
        if (!l_sell_tok) continue;
        dex_pair_key_t l_key_cur; uint8_t l_side_cur = 0; uint256_t l_price = uint256_0;
        s_pair_normalize(l_sell_tok, l_out->subtype.srv_dex.sell_net_id, l_out->subtype.srv_dex.buy_token, l_out->subtype.srv_dex.buy_net_id, l_out->subtype.srv_dex.rate, &l_key_cur, &l_side_cur, &l_price);
        if ( strcmp(l_key_cur.sell_token, l_key.sell_token)
            || strcmp(l_key_cur.buy_token, l_key.buy_token)
            || l_key_cur.sell_net_id.uint64 != l_key.sell_net_id.uint64
            || l_key_cur.buy_net_id.uint64 != l_key.buy_net_id.uint64
            || l_side_cur != l_side ) continue;
        if (!IS_ZERO_256(a_criteria->min_rate) ) {
            int l_cmp = compare256(l_price, a_criteria->min_rate);
            if ( l_side == DEX_SIDE_ASK ? (l_cmp > 0) : (l_cmp < 0) )
                continue;
        }
        // Decide execution amount and emit final match entry directly
        uint256_t l_exec_sell = uint256_0;
        if ( IS_ZERO_256(a_criteria->max_buy_value) )
            l_exec_sell = l_out->header.value;
        else {
            if (l_side == DEX_SIDE_ASK) {
                uint256_t l_max_q = uint256_0; MULT_256_COIN(l_out->header.value, l_price, &l_max_q);
                if ( compare256(l_budget, l_max_q) >= 0 ) {
                    l_exec_sell = l_out->header.value;
                    SUBTRACT_256_256(l_budget, l_max_q, &l_budget);
                } else {
                    uint8_t l_pct = l_out->subtype.srv_dex.min_fill & 0x7F;
                    if (l_pct == 100) continue;
                    DIV_256_COIN(l_budget, l_price, &l_exec_sell);
                    if (l_pct > 0) {
                        uint256_t l_min_abs = uint256_0;
                        int l_min_fetch_res = 0;
                        if ( (l_out->subtype.srv_dex.min_fill & 0x80) )
                            l_min_fetch_res = s_dex_fetch_min_abs(a_net->pub.ledger, &it->cur_hash, &l_min_abs);
                        else
                            l_min_abs = s_calc_pct(l_out->header.value, l_pct);
                        if ( l_min_fetch_res || compare256(l_exec_sell, l_min_abs) < 0 ) continue;
                    }
                }
            } else {
                uint256_t l_max_b = uint256_0;
                DIV_256_COIN(l_out->header.value, l_price, &l_max_b);
                if ( compare256(l_budget, l_max_b) >= 0 ) {
                    l_exec_sell = l_out->header.value;
                    SUBTRACT_256_256(l_budget, l_max_b, &l_budget);
                } else {
                    uint8_t l_pct = l_out->subtype.srv_dex.min_fill & 0x7F;
                    if (l_pct == 100) continue;
                    uint256_t l_exec_q = l_budget;
                    MULT_256_COIN(l_exec_q, l_price, &l_exec_sell);
                    if (l_pct > 0) {
                        uint256_t l_min_abs = uint256_0;
                        int l_min_fetch_res = 0;
                        if ( (l_out->subtype.srv_dex.min_fill & 0x80) )
                            l_min_fetch_res = s_dex_fetch_min_abs(a_net->pub.ledger, &it->cur_hash, &l_min_abs);
                        else
                            l_min_abs = s_calc_pct(l_out->header.value, l_pct);
                        if ( l_min_fetch_res || compare256(l_exec_sell, l_min_abs) < 0 ) continue;
                    }
                    l_budget = uint256_0;
                }
            }
        }
        if (IS_ZERO_256(l_exec_sell)) continue;
        dex_match_table_entry_t *l_match = DAP_NEW(dex_match_table_entry_t);
        *l_match = (dex_match_table_entry_t) {
            .match = { .value = l_out->header.value,
                .rate = l_price, .root = dap_ledger_get_first_chain_tx_hash(a_net->pub.ledger, tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX),
                .tail = it->cur_hash, .min_fill = l_out->subtype.srv_dex.min_fill, .prev_idx = l_out_idx },
            .pair_key = l_common,
            .seller_addr = l_out->subtype.srv_dex.seller_addr,
            .side_version = (uint8_t)((l_out->subtype.srv_dex.version & 0x7F) << 1) | (l_side_cur & 0x1),
            .flags = l_out->subtype.srv_dex.flags,
            .ts_created = tx->header.ts_created,
            .ts_expires = l_out->header.ts_expires,
            .exec_sell = l_exec_sell
        };
        HASH_ADD(hh, l_res, match.tail, sizeof(l_match->match.tail), l_match);
    }
    dap_ledger_datum_iter_delete(it);
    return l_res;
}

static dap_chain_datum_tx_t *s_dex_compose_from_match_table(dap_chain_net_t *a_net, dap_chain_wallet_t *a_wallet,
        uint256_t a_value_buy, uint256_t a_fee, bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate,
        dex_match_table_entry_t *a_matches)
{
    dap_ret_val_if_any(NULL, !a_net, !a_wallet, !a_matches);
    // Overview
    // - Canonical units: BASE=sell_token, QUOTE=buy_token; price=QUOTE/BASE
    // - Aggregate executed volumes; detect at most one partial order
    // - Inputs: BUY (QUOTE) from buyer; NATIVE for network/validator/service_native
    // - Outputs: BASE to buyer, QUOTE to sellers, explicit fees, native cashback, optional leftover, residual UPDATE
    // - No ledger lookups; a_matches is a self-contained snapshot
    const char *l_native = a_net->pub.native_ticker;
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    // Take pair from the first match
    dex_match_table_entry_t *l_match0 = a_matches;
    // All matches are guaranteed to share the same canonical pair and side
    dex_pair_key_t *l_key0 = l_match0->pair_key;
    const char *l_sell_ticker = l_key0->sell_token, *l_buy_ticker = l_key0->buy_token;
    // Totals and partial detection
    uint256_t l_total_sell = uint256_0, l_total_buy = uint256_0, l_best_rate = uint256_0; // BASE, QUOTE, best rate
    dap_hash_fast_t *l_partial_tail = NULL;
    // Aggregate executed volumes and capture the first partial order (if any)
    dex_match_table_entry_t *l_cur_match, *l_tmp, *l_partial_match = NULL; HASH_ITER(hh, a_matches, l_cur_match, l_tmp) {
        SUM_256_256(l_total_sell, l_cur_match->exec_sell, &l_total_sell);
        uint256_t l_exec_buy = uint256_0;
        MULT_256_COIN(l_cur_match->exec_sell, l_cur_match->match.rate, &l_exec_buy);
        SUM_256_256(l_total_buy, l_exec_buy, &l_total_buy);
        if ( !l_partial_tail && compare256(l_cur_match->match.value, l_cur_match->exec_sell) > 0) 
            l_partial_tail = &l_cur_match->match.tail;
        if (IS_ZERO_256(l_best_rate) || compare256(l_cur_match->match.rate, l_best_rate) < 0)
            l_best_rate = l_cur_match->match.rate;
    }
    if (l_partial_tail)
        HASH_FIND(hh, a_matches, l_partial_tail, sizeof(*l_partial_tail), l_partial_match);
    // Fees
    // Estimation for input selection (native side):
    // - l_total_fee = validator + optional network + optional service_native (fixed/percent)
    // - Own-fees (OWN_*) are paid in BUY (QUOTE) and accounted separately
    uint256_t l_total_fee = a_fee, l_net_fee = uint256_0; dap_chain_addr_t l_net_addr = { };
    bool l_net_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_addr);
    if (l_net_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);
    uint16_t l_srv_type = 0;
    uint256_t l_srv_fee = uint256_0;
    dap_chain_addr_t l_srv_addr = { };
    bool l_srv_used = s_dex_get_service_fee(a_net->pub.id, &l_srv_fee, &l_srv_addr, &l_srv_type);
    if (l_srv_used) {
        if (l_srv_type == SERVICE_FEE_NATIVE_FIXED)
            SUM_256_256(l_total_fee, l_srv_fee, &l_total_fee);
        else if (l_srv_type == SERVICE_FEE_NATIVE_PERCENT) {
            // For full-fill mode (a_value_buy == 0), estimate native percent from executed l_total_buy
            uint256_t l_fee_percent_base = a_value_buy;
            if (IS_ZERO_256(l_fee_percent_base))
                l_fee_percent_base = l_total_buy;
            uint256_t l_v; MULT_256_COIN(l_srv_fee, l_fee_percent_base, &l_v);
            SUM_256_256(l_total_fee, l_v, &l_total_fee);
        }
    }
    // Pre-compute BUY-side own fee (for full-fill input selection), zero otherwise
    uint256_t l_srv_own_actual_for_input = uint256_0;
    if (l_srv_used) {
        if (l_srv_type == SERVICE_FEE_OWN_FIXED)
            l_srv_own_actual_for_input = l_srv_fee;
        else if (l_srv_type == SERVICE_FEE_OWN_PERCENT) {
            MULT_256_COIN(l_srv_fee, l_total_buy, &l_srv_own_actual_for_input);
        }
    }
    // Buyer (payer) address is taken from the wallet; all BUY inputs and change go here
    dap_chain_addr_t *l_wal_tmp = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_wal_tmp) return NULL;
    dap_chain_addr_t l_buyer_addr = *l_wal_tmp;
    DAP_DELETE(l_wal_tmp);
    // Create tx and collect inputs: 1) BUY inputs 2) NATIVE inputs (if needed)
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) return NULL; // inputs then in_conds then outs
    dap_list_t *l_u = NULL, *l_f = NULL;
    uint256_t l_vt = uint256_0, l_ft = uint256_0;
    // Collect BUY-token (QUOTE) inputs sufficient to cover sellers payout and own-fee
    // In full-fill mode (a_value_buy == 0), take exact required value: l_total_buy + own_fee(own types)
    uint256_t l_buy_need = a_value_buy;
    if (IS_ZERO_256(l_buy_need))
        SUM_256_256(l_total_buy, l_srv_own_actual_for_input, &l_buy_need);
    if ( dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_buy_ticker, &l_buyer_addr, &l_u, l_buy_need, &l_vt) == -101 )
        l_u = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_buy_ticker, &l_buyer_addr, l_buy_need, &l_vt);
    if (!l_u) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    uint256_t l_added = dap_chain_datum_tx_add_in_item_list(&l_tx, l_u);
    dap_list_free_full(l_u, NULL);
    if ( !EQUAL_256(l_added, l_vt) ) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    bool l_srv_native_used = l_srv_used && (l_srv_type == SERVICE_FEE_NATIVE_FIXED || l_srv_type == SERVICE_FEE_NATIVE_PERCENT);
    // Collect native inputs (ft) to pay validator/network/service_native; excess becomes cashback
    if ( l_net_used || !IS_ZERO_256(a_fee) || l_srv_native_used ) {
        uint256_t l_need = l_total_fee; 
        if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_native, &l_buyer_addr, &l_f, l_need, &l_ft) == -101)
            l_f = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native, &l_buyer_addr, l_need, &l_ft);
        if (!l_f) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        uint256_t l_af = dap_chain_datum_tx_add_in_item_list(&l_tx, l_f);
        dap_list_free_full(l_f, NULL);
        if ( !EQUAL_256(l_af, l_ft) ) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    // IN_COND: partial first
    // Spend sellers' SRV_DEX outs: partial (if any) first so that its residual UPDATE is appended after payouts
    if ( l_partial_match ) {
        int l_idx = l_partial_match->match.prev_idx;
        if ( dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_partial_match->match.tail, l_idx < 0 ? 0 : l_idx, 0) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    HASH_ITER(hh, a_matches, l_cur_match, l_tmp) {
        if ( l_partial_match == l_cur_match )
            continue;
        int l_idx = l_cur_match->match.prev_idx;
        if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_cur_match->match.tail, l_idx < 0 ? 0 : l_idx, 0) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    // OUTs
    // Buyer receives BASE: sum of executed SELL across all matches
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_buyer_addr, l_total_sell, l_sell_ticker) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    // Each seller receives QUOTE proportional to their executed part
    HASH_ITER(hh, a_matches, l_cur_match, l_tmp) {
        uint256_t l_exec_buy = uint256_0;
        MULT_256_COIN(l_cur_match->exec_sell, l_cur_match->match.rate, &l_exec_buy);
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_cur_match->seller_addr, l_exec_buy, l_buy_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    // Service / network / cashback
    // Rationale:
    // - Pay service_native and network explicitly from native inputs
    // - Pay own-fee in BUY-token (QUOTE)
    // - Return native cashback (ft - actual_native_total) to buyer
    uint256_t l_srv_own_actual = uint256_0, l_srv_native_actual = uint256_0;
    int l_add_res = 0;
    if (l_srv_used) {
        if (l_srv_type == SERVICE_FEE_NATIVE_FIXED) {
            l_srv_native_actual = l_srv_fee;
            l_add_res = dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_srv_addr, l_srv_native_actual, l_native);
        } else if (l_srv_type == SERVICE_FEE_NATIVE_PERCENT) {
            uint256_t v = l_srv_fee; MULT_256_COIN(v, l_total_buy, &v); l_srv_native_actual = v;
            l_add_res = dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_srv_addr, l_srv_native_actual, l_native);
        } else if (l_srv_type == SERVICE_FEE_OWN_FIXED) {
            l_srv_own_actual = l_srv_fee;
            l_add_res = dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_srv_addr, l_srv_own_actual, l_buy_ticker);
        } else if (l_srv_type == SERVICE_FEE_OWN_PERCENT) {
            l_srv_own_actual = l_srv_fee; MULT_256_COIN(l_srv_own_actual, l_total_buy, &l_srv_own_actual);
            l_add_res = dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_srv_addr, l_srv_own_actual, l_buy_ticker);
        }
        if (l_add_res == -1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    if (l_net_used && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_addr, l_net_fee, l_native) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    // Native cashback: ft - (a_fee + net + service_native_actual) -> buyer
    {
        uint256_t l_total_native_actual = a_fee;
        if (l_net_used)
            SUM_256_256(l_total_native_actual, l_net_fee, &l_total_native_actual);
        if ( !IS_ZERO_256(l_srv_native_actual) )
            SUM_256_256(l_total_native_actual, l_srv_native_actual, &l_total_native_actual);
        uint256_t l_cashback = uint256_0;
        SUBTRACT_256_256(l_ft, l_total_native_actual, &l_cashback);
        if ( !IS_ZERO_256(l_cashback) && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_buyer_addr, l_cashback, l_native) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    // Remaining BUY after paying sellers and own-fee. For full-fill inputs were exact, leftover is zero.
    uint256_t l_leftover_buy = uint256_0, l_tmpv = a_value_buy;
    if ( !IS_ZERO_256(l_srv_own_actual) )
        SUBTRACT_256_256(l_tmpv, l_srv_own_actual, &l_tmpv);
    // Budget safety: ensure buy inputs cover sellers payout after own-fee (only when user-specified budget)
    if (!IS_ZERO_256(a_value_buy)) {
        if ( compare256(l_tmpv, l_total_buy) < 0 ) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        SUBTRACT_256_256(l_tmpv, l_total_buy, &l_leftover_buy);
    } // Otherwise: inputs were selected exactly, no leftover expected
    
    // Buyer leftover: unspent BUY after paying sellers and own-fee
    // If enabled and there is no partial seller, emit EXCHANGE (sell BUY, buy SELL) with provided rate or inverse(canonical)
    // Otherwise return change in BUY-token to buyer
    if (!IS_ZERO_256(l_leftover_buy)) {
        if (a_create_buyer_order_on_leftover && !l_partial_tail) {
            uint256_t l_rate_new = uint256_0;
            if ( !IS_ZERO_256(a_leftover_rate) )
                l_rate_new = a_leftover_rate;
            else {
                if (IS_ZERO_256(l_best_rate)) {
                    dap_chain_datum_tx_delete(l_tx);
                    return NULL;
                }
                DIV_256_COIN(GET_256_FROM_64(1000000000000000000ULL), l_best_rate, &l_rate_new);
            }
            // Create EXCHANGE order (sell BUY, buy SELL) for the leftover value
            dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_dex(
                (dap_chain_net_srv_uid_t){ .uint64 = DAP_CHAIN_NET_SRV_DEX_ID },
                    l_key0->buy_net_id, l_leftover_buy, l_key0->sell_net_id, l_sell_ticker,
                    l_rate_new, &l_buyer_addr, NULL, 0, 1, 0,
                    DEX_TX_TYPE_EXCHANGE, NULL, 0);
                if (!l_out_cond) {
                    dap_chain_datum_tx_delete(l_tx);
                    return NULL;
            }
            dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_out_cond);
            DAP_DELETE(l_out_cond);
        } else {
            if ( dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_buyer_addr, l_leftover_buy, l_buy_ticker) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    }
    // Seller residual (partial fill): remaining BASE re-issued as UPDATE with original rate/min_fill/flags
    if (l_partial_match) {
        uint256_t l_residual = uint256_0;
        SUBTRACT_256_256(l_partial_match->match.value, l_partial_match->exec_sell, &l_residual);
        if (!IS_ZERO_256(l_residual)) {
            // Re-issue UPDATE for the same order parameters (root/min_fill/version/flags)
            dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_dex(
                (dap_chain_net_srv_uid_t){ .uint64 = DAP_CHAIN_NET_SRV_DEX_ID },
                l_key0->sell_net_id, l_residual, l_key0->buy_net_id, l_buy_ticker,
                l_partial_match->match.rate, &l_partial_match->seller_addr, &l_partial_match->match.root,
                 l_partial_match->match.min_fill, (l_partial_match->side_version >> 1), l_partial_match->flags, DEX_TX_TYPE_UPDATE, NULL, 0);
            if (!l_out_cond) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
            dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_out_cond);
            DAP_DELETE(l_out_cond);
        }
    }
    // Finalize and sign with buyer's key; no further mutations after signature
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    int l_sign = dap_chain_datum_tx_add_sign_item(&l_tx, l_key);
    dap_enc_key_delete(l_key);
    if (l_sign != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    return l_tx;
}
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
static int s_cmp_agg_level_price_asc(dex_orderbook_level_t *a, dex_orderbook_level_t *b) { return compare256(a->price, b->price); }
static int s_cmp_agg_level_price_desc(dex_orderbook_level_t *a, dex_orderbook_level_t *b) { return compare256(b->price, a->price); }

/*
 * dex_bucket_agg_t — time-bucket aggregator for historical metrics.
 * Used by:
 *   - CMD_MARKET_RATE: OHLC over trades (confirmed EXCHANGE) aggregated into buckets
 *   - CMD_VOLUME: per-bucket volumes (BASE/QUOTE) and trade counts
 * Fields:
 *   open/high/low/close — QUOTE/BASE prices for the bucket window (canonical pair)
 *   sum_base/sum_quote  — accumulated volumes for the bucket (BASE and QUOTE)
 *   ts                  — bucket timestamp (window start), used as hash key
 *   first_ts/last_ts    — actual min/max trade timestamps seen in the bucket (for diagnostics)
 *   trades              — number of trades aggregated in this bucket
 *   hh                  — local UTHash handle for the transient bucket table inside the command
 */
typedef struct dex_bucket_agg {
    uint256_t open, high, low, close;
    uint256_t sum_base, sum_quote;
    uint64_t ts, first_ts, last_ts;
    uint32_t trades;
    // Per-bucket trade index to support O(1) add/remove without ledger scans
    struct dex_trade_rec *trades_idx; // hash: (prev_tail, tx_hash) -> trade record
    UT_hash_handle hh;      // per-pair bucket hash handle (key: ts)
} dex_bucket_agg_t;

// Per-bucket trade record used to support precise add/remove without ledger scans
// Define pair container before index helpers to allow dereference in helpers
typedef struct dex_hist_pair {
    dex_pair_key_t   key;       // canonical BASE/QUOTE
    dex_bucket_agg_t *buckets;  // hash ts -> bucket (dex_bucket_agg_t)
    uint256_t        last_price;// last QUOTE/BASE price for open propagation
    UT_hash_handle   hh;        // top-level hash by pair
} dex_hist_pair_t;

typedef struct dex_trade_key {
    dap_hash_fast_t tx_hash, prev_tail;
} DAP_ALIGN_PACKED dex_trade_key_t;

typedef struct dex_trade_rec {
    dex_trade_key_t key;
    uint64_t ts;            // trade timestamp
    uint256_t price, add_base, add_quote; // canonical QUOTE/BASE, base and quote delta added to bucket
    UT_hash_handle hh;
} dex_trade_rec_t;

/*
 * Experimental: In-memory historical OHLCV cache (hash-based)
 * Purpose: fast read path for CMD_MARKET_RATE / CMD_VOLUME without scanning the ledger.
 */

static dex_hist_pair_t *s_dex_history = NULL; // pair -> buckets
// History uses the same unified lock to avoid desync

/*
 * s_hist_idx_add_rec
 * Add a single trade record into the per-bucket trades index.
 * Preconditions:
 *   - Caller holds WR-lock for history (pair/bucket won't be mutated concurrently)
 *   - a_tx_hash is non-null (used as part of unique key)
 * Behavior:
 *   - Builds key (tx_hash, prev_tail) and inserts a compact record with ts, price,
 *     and deltas (add_base/add_quote) already projected to canonical BASE/QUOTE.
 *   - Safe no-op on missing mandatory params.
 */
static inline void s_hist_idx_add_rec(dex_hist_pair_t *p, dex_bucket_agg_t *b,
                                      const dap_hash_fast_t *a_tx_hash, const dap_hash_fast_t *a_prev_tail,
                                      uint64_t a_ts, const uint256_t *a_price,
                                      const uint256_t *a_add_base, const uint256_t *a_add_quote)
{
    dap_ret_if_any(!p, !b, !a_tx_hash, !a_price);
    dex_trade_rec_t *l_rec = DAP_NEW_Z_RET_IF_FAIL(dex_trade_rec_t);
    *l_rec = (dex_trade_rec_t) {
        .key = {
            .tx_hash = *a_tx_hash,
            .prev_tail = a_prev_tail ? *a_prev_tail : (dap_hash_fast_t) { }
        },
        .ts = a_ts, .price = *a_price,
        .add_base = a_add_base ? *a_add_base : uint256_0,
        .add_quote = a_add_quote ? *a_add_quote : uint256_0
    };
    HASH_ADD(hh, b->trades_idx, key, sizeof(l_rec->key), l_rec);
}

/*
 * s_hist_idx_remove_rec_apply
 * Remove a single trade record from the per-bucket index and apply inverse delta.
 *
 * What is "inverse delta" and why apply it here?
 * - When a trade is appended (on opcode 'a'), its contribution (delta) to the bucket
 *   aggregates is added: sum_base += add_base; sum_quote += add_quote; trades++.
 * - During a reorg (opcode 'd'), the chain removes the corresponding transaction.
 *   To keep the in-memory aggregates consistent without rescanning the ledger,
 *   we must undo that prior contribution: sum_base -= add_base; sum_quote -= add_quote;
 *   trades--. This exact rollback of the previously applied delta is the "inverse delta".
 * - This guarantees that bucket aggregates and pair-level last_price become equal to the
 *   state as if the removed trade had never existed.
 *
 * Preconditions:
 *   - Caller holds WR-lock for history (pair/bucket are not mutated concurrently)
 *
 * Behavior:
 *   - Looks up trade by (tx_hash, prev_tail) in the bucket index and subtracts its volumes
 *     from bucket sums (defensively clamped at zero) and decrements trades.
 *   - If the bucket becomes empty: removes the bucket from the per-pair hash and frees it.
 *   - Else: conservatively recomputes OHLC and first/last timestamps from the remaining
 *     trade records to handle potential removal of extremes.
 *   - Updates pair->last_price to the close of the latest bucket (by ts). If the pair
 *     has no buckets left, removes the pair entry as well.
 *
 * Notes:
 *   - All amounts are already in canonical BASE/QUOTE units (ASK/BID projection is done
 *     at append time), so inverse delta operates on canonical sums directly.
 *   - Complexity: O(k) over trades in the affected bucket only; no ledger scans needed.
 */
static inline void s_hist_idx_remove_rec_apply(dex_hist_pair_t *a_pair, dex_bucket_agg_t *a_bucket,
                                               const dap_hash_fast_t *a_tx_hash, const dap_hash_fast_t *a_prev_tail)
{
    if (!a_pair || !a_bucket || !a_tx_hash) return;
    dex_trade_key_t l_key = { .tx_hash = *a_tx_hash, .prev_tail = a_prev_tail ? *a_prev_tail : (dap_hash_fast_t) { } };
    dex_trade_rec_t *l_rec = NULL; HASH_FIND(hh, a_bucket->trades_idx, &l_key, sizeof(l_key), l_rec);
    if (!l_rec) return;
    // inverse delta
    if ( !IS_ZERO_256(l_rec->add_base) ) {
        if ( compare256(a_bucket->sum_base, l_rec->add_base) >= 0 )
            SUBTRACT_256_256(a_bucket->sum_base, l_rec->add_base, &a_bucket->sum_base);
        else
            a_bucket->sum_base = uint256_0;
    }
    if ( !IS_ZERO_256(l_rec->add_quote) ) {
        if ( compare256(a_bucket->sum_quote, l_rec->add_quote) >= 0 )
            SUBTRACT_256_256(a_bucket->sum_quote, l_rec->add_quote, &a_bucket->sum_quote);
        else
            a_bucket->sum_quote = uint256_0;
    }
    if (a_bucket->trades)
        --a_bucket->trades;

    // Remove record first
    HASH_DELETE(hh, a_bucket->trades_idx, l_rec);
    DAP_DELETE(l_rec);
    
    // If emptied, drop bucket and remove empty pair if needed
    if (!a_bucket->trades) {
        HASH_DELETE(hh, a_pair->buckets, a_bucket);
        DAP_DELETE(a_bucket);
    } else {
        // Recompute high/low/close when necessary (conservatively recompute always for simplicity and correctness)
        uint256_t l_new_high = uint256_0, l_new_low = uint256_0, l_new_close = a_bucket->close, l_new_open = a_bucket->open;
        uint64_t l_max_ts_local = 0, l_min_ts_local = UINT64_MAX;
        dex_trade_rec_t *l_cur, *l_tmp;
        HASH_ITER(hh, a_bucket->trades_idx, l_cur, l_tmp) {
            if ( IS_ZERO_256(l_new_high) || compare256(l_cur->price, l_new_high) > 0 ) l_new_high = l_cur->price;
            if ( IS_ZERO_256(l_new_low)  || compare256(l_cur->price, l_new_low) < 0 ) l_new_low = l_cur->price;
            if ( l_cur->ts <= l_min_ts_local ) { l_min_ts_local = l_cur->ts; l_new_open = l_cur->price; }
            if ( l_cur->ts >= l_max_ts_local ) { l_max_ts_local = l_cur->ts; l_new_close = l_cur->price; }
        }
        if ( !IS_ZERO_256(l_new_high) ) a_bucket->high = l_new_high;
        if ( !IS_ZERO_256(l_new_low) ) a_bucket->low  = l_new_low;
        if ( l_min_ts_local != UINT64_MAX ) a_bucket->first_ts = l_min_ts_local;
        if ( l_max_ts_local ) a_bucket->last_ts  = l_max_ts_local;
        a_bucket->open = l_new_open; a_bucket->close = l_new_close;
    }
    // Update pair last_price to close of the latest remaining bucket
    uint64_t l_max_ts = 0;
    uint256_t l_last_close = uint256_0;
    dex_bucket_agg_t *l_bucket_cur = NULL, *l_bucket_tmp = NULL;
    HASH_ITER(hh, a_pair->buckets, l_bucket_cur, l_bucket_tmp) {
        if (l_bucket_cur->ts >= l_max_ts) { l_max_ts = l_bucket_cur->ts; l_last_close = l_bucket_cur->close; }
    }
    a_pair->last_price = l_last_close;
    // If pair buckets became empty — delete pair entry
    if (!a_pair->buckets) {
        HASH_DELETE(hh, s_dex_history, a_pair);
        DAP_DELETE(a_pair);
    }
}
static int s_cmp_bucket_ts(dex_bucket_agg_t *a, dex_bucket_agg_t *b) { return a->ts < b->ts ? -1 : a->ts > b->ts ? 1 : 0; }

/*
 * s_hist_bucket_ts
 * Normalize an arbitrary timestamp to the start of its aggregation bucket.
 * Formula: floor(ts / bucket_sec) * bucket_sec.
 * This guarantees that all trades within the same time window map to the same key
 * and that range iteration can advance in fixed steps of bucket_sec.
 */
static inline uint64_t s_hist_bucket_ts(dap_time_t a_ts, uint64_t a_bucket_sec) {
    return (uint64_t)(a_ts / (dap_time_t)a_bucket_sec) * a_bucket_sec;
}

/*
 * s_hist_pair_get_or_create
 * Lookup or create a history entry for the canonical pair (BASE/QUOTE).
 * Returns a pointer to the per-pair container that owns the per-bucket hash table.
 */
static dex_hist_pair_t *s_hist_pair_get_or_create(const dex_pair_key_t *a_key)
{
    dex_hist_pair_t *p = NULL; HASH_FIND(hh, s_dex_history, a_key, sizeof(*a_key), p);
    if (!p) {
        p = DAP_NEW_Z_RET_VAL_IF_FAIL(dex_hist_pair_t, NULL);
        p->key = *a_key;
        HASH_ADD(hh, s_dex_history, key, sizeof(p->key), p);
    }
    return p;
}

/*
 * dex_history_append_trade
 * Incrementally update OHLCV for the bucket that corresponds to the trade timestamp.
 * - a_key: canonical pair key (BASE/QUOTE)
 * - a_ts: trade timestamp (blockchain time)
 * - a_price_q_per_b: QUOTE/BASE price of the trade in canonical terms
 * - a_qty_base / a_qty_quote: traded volumes (at least one is non-zero)
 * - a_bucket_sec: bucket granularity in seconds
 * - a_tx_hash / a_prev_tail: optional pointers used to index the trade for precise reorg deletes
 * Behavior: creates bucket if absent, initializes open/high/low/close, accumulates sums and trades,
 * stores a per-trade record in the bucket index (if hashes provided), and propagates last_price
 * for correct open in the next bucket.
 */
static void dex_history_append_trade(const dex_pair_key_t *a_key, dap_time_t a_ts, const uint256_t a_price_q_per_b,
                                     const uint256_t a_qty_base, const uint256_t a_qty_quote, uint64_t a_bucket_sec,
                                     const dap_hash_fast_t *a_tx_hash, const dap_hash_fast_t *a_prev_tail)
{
    dap_ret_if_any(!a_key, !a_bucket_sec, IS_ZERO_256(a_price_q_per_b), IS_ZERO_256(a_qty_base) && IS_ZERO_256(a_qty_quote));
    //pthread_rwlock_wrlock(&s_dex_history_rwlock);
    dex_hist_pair_t *l_pair = s_hist_pair_get_or_create(a_key);
    if ( l_pair ) {
        uint64_t l_ts = s_hist_bucket_ts(a_ts, a_bucket_sec);
        dex_bucket_agg_t *l_bucket = NULL; HASH_FIND(hh, l_pair->buckets, &l_ts, sizeof(l_ts), l_bucket);
        if ( l_bucket ) {
            if ( compare256(a_price_q_per_b, l_bucket->high) > 0 ) l_bucket->high = a_price_q_per_b;
            if ( compare256(a_price_q_per_b, l_bucket->low)  < 0 ) l_bucket->low = a_price_q_per_b;
            if (!IS_ZERO_256(a_qty_base)) SUM_256_256(l_bucket->sum_base,  a_qty_base,  &l_bucket->sum_base);
            if (!IS_ZERO_256(a_qty_quote)) SUM_256_256(l_bucket->sum_quote, a_qty_quote, &l_bucket->sum_quote);
            l_bucket->close = a_price_q_per_b;
            ++l_bucket->trades;
            l_pair->last_price = a_price_q_per_b;
            // Add trade record into per-bucket index for reorg deletes
            if (a_tx_hash)
                s_hist_idx_add_rec(l_pair, l_bucket, a_tx_hash, a_prev_tail, (uint64_t)a_ts, &a_price_q_per_b, &a_qty_base, &a_qty_quote);
            // Update actual trade timestamps seen in this bucket
            if ( !l_bucket->first_ts || (uint64_t)a_ts < l_bucket->first_ts )
                l_bucket->first_ts = (uint64_t)a_ts;
            if ( (uint64_t)a_ts > l_bucket->last_ts )
                l_bucket->last_ts = (uint64_t)a_ts;
        } else if (( l_bucket = DAP_NEW_Z(dex_bucket_agg_t) )) {
            *l_bucket = (dex_bucket_agg_t) {
                .open = IS_ZERO_256(l_pair->last_price) ? a_price_q_per_b : l_pair->last_price,
                .high = a_price_q_per_b,
                .low  = a_price_q_per_b,
                .close= a_price_q_per_b,
                .sum_base  = a_qty_base,
                .sum_quote = a_qty_quote,
                .ts = l_ts,
                .first_ts = (uint64_t)a_ts,
                .last_ts  = (uint64_t)a_ts,
                .trades = 1,
                .trades_idx = NULL,
            };
            HASH_ADD(hh, l_pair->buckets, ts, sizeof(l_bucket->ts), l_bucket);
            l_pair->last_price = a_price_q_per_b;
            if (a_tx_hash)
                s_hist_idx_add_rec(l_pair, l_bucket, a_tx_hash, a_prev_tail, (uint64_t)a_ts, &a_price_q_per_b, &a_qty_base, &a_qty_quote);
        }
    }
    //pthread_rwlock_unlock(&s_dex_history_rwlock);
}

typedef struct dex_history_ctx {
    uint256_t sum_base, sum_quote, last_price;
    dap_time_t bucket_sec, prev_ts;
    unsigned with_ohlc : 1, fill_missing : 1, trades;
    dap_ledger_t *ledger;
    dap_chain_addr_t *seller;
    json_object *arr;
} dex_history_ctx_t;

/*
 * dex_history_read_range
 * Read a contiguous range of buckets [a_ts_from..a_ts_to] with step a_bucket_sec.
 * Emits a dense array of dex_bucket_agg_t (one per expected bucket position).
 * Missing buckets are emitted as zero-initialized entries (caller may post-process).
 * Returns number of entries or a negative error code; caller owns returned table.
 */
typedef void (*dex_history_iter_cb_t)(const dex_bucket_agg_t *a_bucket, dex_history_ctx_t *a_ctx);
static int dex_history_for_each_range(const dex_pair_key_t *a_key, uint64_t a_ts_from, uint64_t a_ts_to, uint64_t a_bucket_sec,
                                      dex_history_iter_cb_t a_cb, dex_history_ctx_t *a_ctx)
{
    dap_ret_val_if_any(-1, !a_key, !a_bucket_sec, a_ts_to < a_ts_from, !a_cb);
    int l_ret = 0;
    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    dex_hist_pair_t *l_pair = NULL; HASH_FIND(hh, s_dex_history, a_key, sizeof(*a_key), l_pair);
    if (l_pair) {
        uint64_t ts = s_hist_bucket_ts((dap_time_t)a_ts_from, a_bucket_sec), ts_to = s_hist_bucket_ts((dap_time_t)a_ts_to, a_bucket_sec);
        for ( ; ts <= ts_to; ts += a_bucket_sec ) {
            dex_bucket_agg_t *l_buck = NULL;
            HASH_FIND(hh, l_pair->buckets, &ts, sizeof(ts), l_buck); 
            if (l_buck) { a_cb(l_buck, a_ctx); ++l_ret; }
        }
    }
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    return l_ret;
}

// ---- History iterators: JSON-building callbacks ----
static inline void s_hist_json_emit_bucket(json_object *a_arr, const dex_bucket_agg_t *a_b, bool a_with_ohlc) {
    dap_ret_if_any(!a_arr, !a_b);
    json_object *o = json_object_new_object();
    json_object_object_add(o, "ts", json_object_new_uint64(a_b->ts));
    json_object_object_add(o, "first_ts", json_object_new_uint64(a_b->first_ts));
    json_object_object_add(o, "last_ts", json_object_new_uint64(a_b->last_ts));
    if (a_with_ohlc) {
        json_object_object_add(o, "open",  json_object_new_string(dap_uint256_to_char_ex(a_b->open).frac));
        json_object_object_add(o, "high",  json_object_new_string(dap_uint256_to_char_ex(a_b->high).frac));
        json_object_object_add(o, "low",   json_object_new_string(dap_uint256_to_char_ex(a_b->low).frac));
        json_object_object_add(o, "close", json_object_new_string(dap_uint256_to_char_ex(a_b->close).frac));
    }
    json_object_object_add(o, "volume_base",  json_object_new_string(dap_uint256_to_char_ex(a_b->sum_base).frac));
    json_object_object_add(o, "volume_quote", json_object_new_string(dap_uint256_to_char_ex(a_b->sum_quote).frac));
    json_object_object_add(o, "trades", json_object_new_uint64(a_b->trades));
    json_object_array_add(a_arr, o);
}
static void s_hist_cb_build_volume(const dex_bucket_agg_t *a_buck, dex_history_ctx_t *a_ctx)
{
    dap_ret_if_any(!a_ctx, !a_buck);
    // Fill gaps with synthetic buckets if requested
    if (a_ctx->with_ohlc && a_ctx->arr && a_ctx->fill_missing && a_ctx->bucket_sec && a_ctx->prev_ts
        && a_buck->ts > a_ctx->prev_ts + a_ctx->bucket_sec && !IS_ZERO_256(a_ctx->last_price)) {
        for (uint64_t t = a_ctx->prev_ts + a_ctx->bucket_sec; t < a_buck->ts; t += a_ctx->bucket_sec) {
            dex_bucket_agg_t l_b = { .last_ts = t + a_ctx->bucket_sec - 1 };
            l_b.ts = l_b.first_ts = t; l_b.open = l_b.high = l_b.low = l_b.close = a_ctx->last_price;
            s_hist_json_emit_bucket(a_ctx->arr, &l_b, true);
        }
    }
    s_hist_json_emit_bucket(a_ctx->arr, a_buck, a_ctx->with_ohlc);
    if (!IS_ZERO_256(a_buck->sum_base))  SUM_256_256(a_ctx->sum_base,  a_buck->sum_base,  &a_ctx->sum_base);
    if (!IS_ZERO_256(a_buck->sum_quote)) SUM_256_256(a_ctx->sum_quote, a_buck->sum_quote, &a_ctx->sum_quote);
    a_ctx->trades += a_buck->trades;
    if (a_ctx->with_ohlc) { a_ctx->last_price = a_buck->close; a_ctx->prev_ts = a_buck->ts; }
}

static void s_hist_cb_build_volume_seller(const dex_bucket_agg_t *a_b, dex_history_ctx_t *a_ctx)
{
    dap_ret_if_any(!a_ctx, !a_b, !a_ctx->seller, !a_ctx->ledger);
    uint256_t l_sum_base = uint256_0, l_sum_quote = uint256_0;
    unsigned l_trades = 0;
    dap_time_t l_first_ts = 0, l_last_ts = 0;
    // for OHLC
    uint256_t l_open = uint256_0, l_high = uint256_0, l_low = uint256_0, l_close = uint256_0;
    dex_trade_rec_t *l_cur = NULL, *l_tmp = NULL;
    HASH_ITER(hh, a_b->trades_idx, l_cur, l_tmp) {
        if (dap_hash_fast_is_blank(&l_cur->key.prev_tail)) continue;
        if (s_dex_cache_enabled) {
            const dex_order_cache_entry_t *e = NULL;
            HASH_FIND(level.hh_tail, s_dex_index_by_tail, &l_cur->key.prev_tail, sizeof(l_cur->key.prev_tail), e);
            if (!e || !e->seller_addr_ptr || !dap_chain_addr_compare(e->seller_addr_ptr, a_ctx->seller))
                continue;
        } else {
            dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_ctx->ledger, &l_cur->key.prev_tail);
            if (!l_prev_tx) continue;
            dap_chain_tx_out_cond_t *l_prev = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
            if (!l_prev || !dap_chain_addr_compare(&l_prev->subtype.srv_dex.seller_addr, a_ctx->seller))
                continue;
        }
        // include this trade
        if (!IS_ZERO_256(l_cur->add_base))  SUM_256_256(l_sum_base,  l_cur->add_base,  &l_sum_base);
        if (!IS_ZERO_256(l_cur->add_quote)) SUM_256_256(l_sum_quote, l_cur->add_quote, &l_sum_quote);
        if (!l_trades || l_cur->ts < l_first_ts) {
            l_first_ts = l_cur->ts;
            if (a_ctx->with_ohlc) l_open = l_cur->price;
        }
        if (!l_trades || l_cur->ts > l_last_ts) {
            l_last_ts = l_cur->ts;
            if (a_ctx->with_ohlc) l_close = l_cur->price;
        }
        if (a_ctx->with_ohlc) {
            if (compare256(l_cur->price, l_high) > 0) l_high = l_cur->price;
            if (compare256(l_cur->price, l_low) < 0) l_low = l_cur->price;
        }
        ++l_trades;
    }
    if (!l_trades) return;
    dex_bucket_agg_t l_b = { .ts = a_b->ts, .first_ts = l_first_ts, .last_ts = l_last_ts,
        .sum_base = l_sum_base, .sum_quote = l_sum_quote, .trades = l_trades };
    if (a_ctx->with_ohlc) {
        l_b.open = l_open; l_b.high = l_high; l_b.low = l_low; l_b.close = l_close;
    }
    s_hist_cb_build_volume(&l_b, a_ctx);
}
/*
 * Remove entry from all secondary indices in O(1) using back-pointers:
 * - Tail index: delete from s_dex_index_by_tail
 * - Pair index: use a_entry->pair_bucket and a_entry->side to delete from asks/bids; drop empty bucket
 * - Seller index: use a_entry->seller_bucket to delete; drop empty seller bucket
 * Safe against key mutations because it doesn't rely on entry->pair_key/seller_addr.
 */
static void s_dex_indexes_remove(dex_order_cache_entry_t *a_entry)
{
    dap_ret_if_any(!a_entry);
    // tail index
    if (a_entry->level.hh_tail.tbl)
        HASH_DELETE(level.hh_tail, s_dex_index_by_tail, a_entry);
    // pair index
    if (a_entry->pair_key_ptr) {
        dex_pair_index_t *pb = (dex_pair_index_t*)(void*)a_entry->pair_key_ptr;
        if ((a_entry->side_version & 0x1) == DEX_SIDE_ASK)
            HASH_DELETE(hh_pair_bucket, pb->asks, a_entry);
        else
            HASH_DELETE(hh_pair_bucket, pb->bids, a_entry);
        if (!pb->asks && !pb->bids) { HASH_DELETE(hh, s_dex_pair_index, pb); DAP_DELETE(pb); }
        a_entry->pair_key_ptr = NULL;
    }
    // seller index
    if (a_entry->seller_addr_ptr) {
        dex_seller_index_t *sb = (dex_seller_index_t*)(void*)a_entry->seller_addr_ptr;
        HASH_DELETE(hh_seller_bucket, sb->entries, a_entry);
        if (!sb->entries) { HASH_DELETE(hh, s_dex_seller_index, sb); DAP_DELETE(sb); }
        a_entry->seller_addr_ptr = NULL;
    }
}

/*
 * Insert entry into all secondary indices:
 * - Tail index: add by tail (assumes prior s_dex_indexes_remove was called)
 * - Pair index: put into asks/bids bucket in-order (rate ASC, ts_created ASC, root ASC);
 *   store back-pointer a_entry->pair_bucket
 * - Seller index: put in-order by ts_created ASC then root; store back-pointer a_entry->seller_bucket
 * Requires: up-to-date fields (seller_addr, pair_key, tail, side, rate, ts_created) already set.
 */
static void s_dex_indexes_insert(dex_order_cache_entry_t *a_entry)
{
    dap_ret_if_any(!a_entry);
    HASH_ADD(level.hh, s_dex_index_by_tail, level.match.tail, sizeof(a_entry->level.match.tail), a_entry);
    dex_pair_index_t *pb = s_dex_pair_index_get_or_create((const dex_pair_key_t*)a_entry->pair_key_ptr);
    dex_seller_index_t *sb = s_dex_seller_index_get_or_create((const dap_chain_addr_t*)a_entry->seller_addr_ptr);
    a_entry->pair_key_ptr = &pb->key; a_entry->seller_addr_ptr = &sb->seller_addr;
    if (pb) {
        if ((a_entry->side_version & 0x1) == DEX_SIDE_ASK)
            HASH_ADD_INORDER(hh_pair_bucket, pb->asks, level.match.root, sizeof(a_entry->level.match.root), a_entry, s_cmp_pair_bucket_entries);
        else // BID
            HASH_ADD_INORDER(hh_pair_bucket, pb->bids, level.match.root, sizeof(a_entry->level.match.root), a_entry, s_cmp_pair_bucket_entries);
    }
    if (sb) {
        #define CMP_SELLER(a,b) ((a)->ts_created < (b)->ts_created) ? -1 : ((a)->ts_created > (b)->ts_created ? 1 : memcmp(&(a)->level.match.root, &(b)->level.match.root, sizeof((a)->level.match.root)))
        HASH_ADD_INORDER(hh_seller_bucket, sb->entries, level.match.root, sizeof(a_entry->level.match.root), a_entry, CMP_SELLER);
        #undef CMP_SELLER
    }
}

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
 * 2) Derive canonical pair (BASE/QUOTE), side and canonical price via s_pair_normalize()
 * 3) Remove entry from all secondary indices via back-pointers (O(1))
 * 4) Update entry fields (pair_key, tail, price, side, value, seller_addr, ts_expires, flags, version/fill)
 * 5) Insert entry into all indices (tail, pair bucket, seller bucket); store back-pointers
 */
static void s_dex_cache_upsert(dap_ledger_t *a_ledger, const char *a_sell_token,
        dap_chain_hash_fast_t *a_root, dap_chain_hash_fast_t *a_tail, dap_chain_tx_out_cond_t *a_cond, int a_prev_idx)
{
    dap_ret_if_any(!a_root, !a_tail, !a_cond);
    /*
     * PHASE 1 (no lock): fast validation and canonicalization
     * - resolve sell_token (arg or by tail from ledger)
     * - validate buy_token
     * - normalize pair to BASE/QUOTE and compute canonical price (QUOTE/BASE)
     * Any failure: early return without touching cache/indices.
     */
    const char *sell_ticker = (a_sell_token && *a_sell_token) ? a_sell_token : (a_ledger ? dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tail) : NULL);
    if (!sell_ticker || !*sell_ticker) 
        return log_it(L_WARNING, "upsert skipped: sell token not resolved for root \"%s\" and tail \"%s\"",
                                dap_hash_fast_to_str_static(a_root), dap_hash_fast_to_str_static(a_tail));
    if (!*a_cond->subtype.srv_dex.buy_token)
        return log_it(L_WARNING, "upsert skipped: empty buy_token for root \"%s\"", dap_hash_fast_to_str_static(a_root));
    
    dex_pair_key_t new_key = { };
    uint8_t side = 0; uint256_t price_canon = uint256_0;
    s_pair_normalize(sell_ticker, a_cond->subtype.srv_dex.sell_net_id, a_cond->subtype.srv_dex.buy_token, a_cond->subtype.srv_dex.buy_net_id,
                     a_cond->subtype.srv_dex.rate, &new_key, &side, &price_canon);
    if (!*new_key.sell_token || !*new_key.buy_token) 
        return log_it(L_WARNING, "upsert skipped: pair normalization failed for root \"%s\"", dap_hash_fast_to_str_static(a_root));

    /*
     * PHASE 2 (with WR lock): atomically update primary table and all indices
     * Strict order: find/create → update non-index fields → remove → apply indexed fields → insert → log
     */
    pthread_rwlock_wrlock(&s_dex_cache_rwlock);
    dex_order_cache_entry_t *e = NULL; HASH_FIND(level.hh, s_dex_orders_cache, a_root, sizeof(*a_root), e);
    if (!e) {
        /* First appearance for this root: create entry and set ts_created */
        e = DAP_NEW_Z(dex_order_cache_entry_t);
        e->level.match.root = *a_root;
        e->ts_created = dap_ledger_get_blockchain_time(a_ledger);
        HASH_ADD(level.hh, s_dex_orders_cache, level.match.root, sizeof(e->level.match.root), e);
    } else {
        /* Existing entry: detach from indices first (back-pointer removal, O(1))
         * New entries are not indexed yet, so removal would be a no-op — we do it only for existing ones for efficiency.
         */
        s_dex_indexes_remove(e);
    }
    /* Apply indexed fields and current state */
    e->level.match.value    = a_cond->header.value;
    e->ts_expires     = a_cond->header.ts_expires;
    e->flags          = a_cond->subtype.srv_dex.flags;
    e->pair_key_ptr   = &s_dex_pair_index_get_or_create(&new_key)->key;
    e->seller_addr_ptr= &s_dex_seller_index_get_or_create(&a_cond->subtype.srv_dex.seller_addr)->seller_addr;
    e->level.match.tail   = *a_tail;
    e->level.match.rate   = price_canon;
    e->side_version = (uint8_t)((a_cond->subtype.srv_dex.version & 0x7F) << 1) | (side & 0x1);
    e->level.match.min_fill = a_cond->subtype.srv_dex.min_fill;
    e->level.match.prev_idx = a_prev_idx;
    
    /* Insert back into indices (tail, pair, seller); back-pointers are set inside */
    s_dex_indexes_insert(e);

    log_it(L_DEBUG, "upsert root=%s tail=%s pair=%s/%s side=%s price=%s value=%s seller=%s",
           dap_hash_fast_to_str_static(a_root), dap_hash_fast_to_str_static(a_tail),
           e->pair_key_ptr ? e->pair_key_ptr->sell_token : "?",
           e->pair_key_ptr ? e->pair_key_ptr->buy_token  : "?",
           (e->side_version & 0x1) ? "BID" : "ASK",
           dap_uint256_to_char_ex(e->level.match.rate).frac, dap_uint256_to_char_ex(e->level.match.value).frac,
           dap_chain_addr_to_str_static((dap_chain_addr_t*)e->seller_addr_ptr));
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
}

static inline void s_dex_cache_remove_entry(dex_order_cache_entry_t *a_entry)
{
    dap_ret_if_any(!a_entry);
	s_dex_indexes_remove(a_entry);
    HASH_DELETE(level.hh, s_dex_orders_cache, a_entry);
    DAP_DELETE(a_entry);
}

static void s_dex_cache_remove_by_root(dap_chain_hash_fast_t *a_root)
{
    dap_ret_if_any(!a_root);
    dex_order_cache_entry_t *e = NULL;
    HASH_FIND(level.hh, s_dex_orders_cache, a_root, sizeof(*a_root), e);
	s_dex_cache_remove_entry(e);
}

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
 * Return codes (negative on failure):
 *   -1  : invalid parameters
 *   -2  : more than one SRV_DEX OUT in TX
 *   -3  : no IN_COND items (not a DEX exchange)
 *   -5/-6: previous TX or previous SRV_DEX OUT not found
 *   -7  : previous order expired
 *   -8/-9: baseline (market tuple) mismatch
 *   -10 : invalid residual (leftover >= previous)
 *   -11 : AON (100%) min_fill is disallowed for partial update
 *   -12 : min_fill threshold not satisfied or origin root not found
 *   -14 : immutability violation (rate/tokens/nets/seller/version/min_fill/flags/root)
 *   -15 : service fee underpaid (or misrouted own-fee)
 *   -16 : network fee underpaid
 *   -18 : seller payout in buy token != expected
 *   -20 : buyer address not determinable for buyer-leftover
 *   -21 : buyer-leftover seller_addr != buyer address
 *   -22 : multiple distinct buyer destinations (policy: single buyer only)
 *   -23 : final payout (sell, native case) mismatch
 *   -24 : final payout (sell, non-native) mismatch
 */
static int s_dex_verificator_callback(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_tx_out_cond,
                                      dap_chain_datum_tx_t *a_tx_in, bool a_owner, UNUSED_ARG bool a_check_for_apply)
{
    #define m_ret_err(a_err) { return log_it(L_WARNING, "Verification error %d: %s", -a_err, s_dex_verif_err_str(a_err)), -a_err; }

    dap_do_if_any(m_ret_err(DEXV_INVALID_PARAMS), !a_tx_in, !a_tx_out_cond);

    // Phase 0: Pre-scan TX items (O(n))
    //  - Count IN_COND items
    //  - Locate a SINGLE SRV_DEX OUT (enforce at most one)
    //  - Cache the very first IN_COND (l_in0) and resolve its previous SRV_DEX OUT
    //    to enable:
    //      * fast-path owner update (1 IN + SRV_DEX OUT with non-blank root)
    //      * baseline extraction for Phase 2
    int l_in_cond_count = 0;
    dap_chain_tx_in_cond_t *l_in0 = NULL;
    dap_chain_tx_out_cond_t *l_out_cond = NULL, *l_prev_out0 = NULL;
    dap_chain_datum_tx_t *l_prev_tx0 = NULL;

    byte_t *it; size_t sz, l_sz_in0 = 0;
    TX_ITEM_ITER_TX(it, sz, a_tx_in) {
        switch (*it) {
        case TX_ITEM_TYPE_IN_COND:
            ++l_in_cond_count;
            if ( !l_in0 ) {
                l_in0 = (dap_chain_tx_in_cond_t*)it;
                l_prev_tx0 = dap_ledger_tx_find_by_hash(a_ledger, &l_in0->header.tx_prev_hash);
                if (!l_prev_tx0) m_ret_err(DEXV_PREV_TX_NOT_FOUND);
                l_prev_out0 = dap_chain_datum_tx_out_cond_get(l_prev_tx0, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
                if (!l_prev_out0) m_ret_err(DEXV_PREV_OUT_NOT_FOUND);
                l_sz_in0 = sz;
            }
            break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *l_out = (dap_chain_tx_out_cond_t*)it;
            if (l_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX) {
                if (l_out_cond) m_ret_err(DEXV_MULTIPLE_SRV_DEX_OUT); // no more than one SRV_DEX output
                l_out_cond = l_out;
            }
        }
        default: break;
        }
    }
    
    // Phase 1: Fast-paths based on IN count
    //   - ORDER (create): 0 IN_COND + SRV_DEX OUT with tx_type=ORDER is allowed
    //  - 0 IN: invalid (-3)
    //  - 1 IN + SRV_DEX OUT with non-blank root + a_owner==true:
    //      owner UPDATE (no trade) — verify immutables and ensure seller gets no payout in buy token
    switch (l_in_cond_count) {
    case 0:
        if ( l_out_cond && l_out_cond->subtype.srv_dex.tx_type == DEX_TX_TYPE_ORDER ) return 0;
        m_ret_err(DEXV_NO_IN);
    case 1:
        if ( a_owner && l_out_cond && !dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash) ) {
            /* Fast-path: owner update in one TX (IN_COND consumes previous SRV_DEX, single SRV_DEX OUT with same root, no payouts)
             * Only allowed when the spender is the seller
             * Previous SRV_DEX and baseline already extracted
             */
            // Root must match: seller-leftover update must preserve original order root
            dap_hash_fast_t l_expected_root0 = dap_ledger_get_first_chain_tx_hash(a_ledger, l_prev_tx0, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
            if ( memcmp(&l_out_cond->subtype.srv_dex.order_root_hash, &l_expected_root0, sizeof(dap_hash_fast_t)) ) m_ret_err(DEXV_IMMUTABLES_VIOLATION);

            // Seller, nets and tokens must match: immutable order tuple
            if ( !dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_prev_out0->subtype.srv_dex.seller_addr) ||
                l_prev_out0->subtype.srv_dex.sell_net_id.uint64 != l_out_cond->subtype.srv_dex.sell_net_id.uint64 ||
                l_prev_out0->subtype.srv_dex.buy_net_id.uint64 != l_out_cond->subtype.srv_dex.buy_net_id.uint64 )
                m_ret_err(DEXV_IMMUTABLES_VIOLATION);
            if ( strcmp(l_out_cond->subtype.srv_dex.buy_token, l_prev_out0->subtype.srv_dex.buy_token) ) m_ret_err(DEXV_IMMUTABLES_VIOLATION);

            // tx_type byte check: UPDATE strictly required here
            if (l_out_cond->subtype.srv_dex.tx_type != DEX_TX_TYPE_UPDATE)
                m_ret_err(DEXV_TX_TYPE_MISMATCH);

            // Ensure no payout to seller in buy_token (no trade path): any buy-token payments to seller signal a trade
            uint256_t l_paid0 = uint256_0, l_srv_fee = uint256_0;
            uint16_t l_srv_type = 0; dap_chain_addr_t l_srv_fee_addr = { };
            bool l_is_srv_fee_used = s_dex_get_service_fee(a_ledger->net->pub.id, &l_srv_fee, &l_srv_fee_addr, &l_srv_type)
                                        && (l_srv_type == SERVICE_FEE_OWN_FIXED || l_srv_type == SERVICE_FEE_OWN_PERCENT);
            TX_ITEM_ITER_TX(it, sz, a_tx_in) {
                switch (*it) {
                case TX_ITEM_TYPE_OUT_EXT: {
                    dap_chain_tx_out_ext_t *o = (dap_chain_tx_out_ext_t*)it;
                    if ( l_is_srv_fee_used && !dap_strcmp(o->token, l_prev_out0->subtype.srv_dex.buy_token) && dap_chain_addr_compare(&o->addr, &l_srv_fee_addr))
                        m_ret_err(DEXV_SERVICE_FEE_UNDERPAID);
                    if ( !dap_strcmp(o->token, l_prev_out0->subtype.srv_dex.buy_token) && dap_chain_addr_compare(&o->addr, &l_prev_out0->subtype.srv_dex.seller_addr) )
                        SUM_256_256(l_paid0, o->header.value, &l_paid0);
                } break;
                case TX_ITEM_TYPE_OUT_STD: {
                    dap_chain_tx_out_std_t *o = (dap_chain_tx_out_std_t*)it;
                    if ( l_is_srv_fee_used && !dap_strcmp(o->token, l_prev_out0->subtype.srv_dex.buy_token) && dap_chain_addr_compare(&o->addr, &l_srv_fee_addr))
                        m_ret_err(DEXV_SERVICE_FEE_UNDERPAID);
                    if ( !dap_strcmp(o->token, l_prev_out0->subtype.srv_dex.buy_token) && dap_chain_addr_compare(&o->addr, &l_prev_out0->subtype.srv_dex.seller_addr) )
                        SUM_256_256(l_paid0, o->value, &l_paid0);
                }
                default: break;
            }
            }
            if (!IS_ZERO_256(l_paid0)) m_ret_err(DEXV_SELLER_PAID_IN_UPDATE); // payout not allowed for pure update
            return 0;
        }
    default:
        break;
    }
    
    /*
     * Phase 2: Two-pass pointer-based verification using pre-counted INs
     * ------------------------------------------------------------------
     * First pass over IN items (from the first IN onward):
     *   - Establish baseline market tuple (sell_ticker, buy_ticker, sell/buy nets) from first IN
     *     and enforce it for every IN (one market per TX).
     *   - Collect pointers to previous SRV_DEX outs and previous TX for each IN.
     *   - Deduplicate sellers as pointer set for O(1) per-seller aggregation (linear search is OK for small N).
     *
     * Compute expected amounts per seller and totals:
     *   - expected_buy[seller] += executed_i * rate_i, totals += executed_i/buy_i.
     *   - If a single SRV_DEX OUT has non-blank root → treat as seller-leftover (first IN only):
     *       * executed_i = prev.value − leftover.value
     *       * validate immutables and root equality
     *       * enforce min_fill (low7=percent, bit7=from_origin)
     *
     * Second pass over OUT items:
     *   - Aggregate per-seller paid_buy in buy token
     *   - Aggregate paid_sell_any in sell token excluding fee destinations (net/service)
     *   - Collect validator FEE, network fee, service fee
     *
     * Validate:
     *   - For every seller: paid_buy == expected_buy (exact)
     *   - Buyer-leftover (blank root): single SRV_DEX OUT, seller_addr equals unique buyer sell-destination
     *   - paid_net >= req_net, paid_srv >= req_srv
     *   - Final buyer payout in sell: native→totals minus fees; non-native→equals totals
     */

    typedef struct in_info {
        dap_chain_tx_out_cond_t *prev;
        dap_chain_datum_tx_t *prev_tx;
        const char *sell_ticker;
    } in_info_t;

    typedef struct seller_info {
        const dap_chain_addr_t *addr;
        uint256_t expected_buy;
        uint256_t paid_buy;
    } seller_info_t;

    in_info_t *l_ins_agg = DAP_NEW_Z_COUNT(in_info_t, l_in_cond_count), *l_in_cur = l_ins_agg;
    seller_info_t *l_sellers_agg = DAP_NEW_Z_COUNT(seller_info_t, l_in_cond_count);
    dap_time_t l_now = dap_ledger_get_blockchain_time(a_ledger);
    
    // Baseline from first IN: locks market (sell/buy tickers and nets) for all INs within TX
    const char *l_buy_ticker  = l_prev_out0->subtype.srv_dex.buy_token, 
               *l_sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_in0->header.tx_prev_hash);
    if (!l_sell_ticker) return -8;
    dap_chain_net_id_t l_base_sell_net = l_prev_out0->subtype.srv_dex.sell_net_id,
                       l_base_buy_net  = l_prev_out0->subtype.srv_dex.buy_net_id;

    *l_ins_agg = (in_info_t){ .prev = l_prev_out0, .prev_tx = l_prev_tx0, .sell_ticker = l_sell_ticker };
    *l_sellers_agg = (seller_info_t){ .addr = &l_prev_out0->subtype.srv_dex.seller_addr };
    int l_uniq_sellers_q = 1;

    // First pass over IN items only: iterate from the first IN onward to avoid re-processing earlier items
    int l_err = 0;
    TX_ITEM_ITER( it, sz, (byte_t*)l_in0 + l_sz_in0, (size_t)(a_tx_in->tx_items + a_tx_in->header.tx_items_size - (byte_t*)l_in0) ) {
        if ( *it != TX_ITEM_TYPE_IN_COND ) continue;

        dap_chain_tx_in_cond_t *l_in_cond = (dap_chain_tx_in_cond_t*)it;
        dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_in_cond->header.tx_prev_hash);
        if (!l_tx) { l_err = -5; break; }

        dap_chain_tx_out_cond_t *l_prev = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
        if (!l_prev) { l_err = -6; break; }

        // Expiry
        if ( l_prev->header.ts_expires && l_now > l_prev->header.ts_expires ) { l_err = -7; break; }
        if ( strcmp(l_prev->subtype.srv_dex.buy_token, l_buy_ticker) ) { l_err = -8; break; }
        if ( l_prev->subtype.srv_dex.sell_net_id.uint64 != l_base_sell_net.uint64
            || l_prev->subtype.srv_dex.buy_net_id.uint64 != l_base_buy_net.uint64
            || strcmp(dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_in_cond->header.tx_prev_hash), l_sell_ticker) ) { l_err = -9; break; }

        *(l_in_cur++) = (in_info_t){ .prev = l_prev, .prev_tx = l_tx, .sell_ticker = l_sell_ticker };

        // Deduplicate seller pointers into sellers[0..l_uniq_sellers_q)
        int l_dup_idx = -1;
        for (int j = 0; j < l_uniq_sellers_q; ++j) {
            if ( dap_chain_addr_compare(l_sellers_agg[j].addr, &l_prev->subtype.srv_dex.seller_addr)) {
                l_dup_idx = j; break;
            }
        }
        if (l_dup_idx == -1)
            l_sellers_agg[l_uniq_sellers_q++] = (seller_info_t){ .addr = &l_prev->subtype.srv_dex.seller_addr };
    }
    if (l_err) { DAP_DEL_MULTY(l_ins_agg, l_sellers_agg); m_ret_err(l_err); }
    
    // Expected buys and totals per seller (handle seller-leftover/min_fill for the first IN if present)
    uint256_t l_executed_total_sell = uint256_0, l_executed_total_buy = uint256_0;
    for (int i = 0; i < l_in_cond_count; ++i) {
        dap_chain_tx_out_cond_t *l_prev = l_ins_agg[i].prev;
        dap_chain_datum_tx_t *l_tx = l_ins_agg[i].prev_tx;
        uint256_t l_executed_i = l_prev->header.value;
        if (i == 0 && l_out_cond && !dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash)) {
            if ( !dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_prev->subtype.srv_dex.seller_addr) ) {
                l_err = -14; break;
            }
            if ( compare256(l_prev->header.value, l_out_cond->header.value) <= 0 ) {
                l_err = -10; break;
            }
            SUBTRACT_256_256(l_prev->header.value, l_out_cond->header.value, &l_executed_i);
            dap_hash_fast_t l_root_hash = dap_ledger_get_first_chain_tx_hash(a_ledger, l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
            // min_fill semantics:
            //  - low 7 bits = percentage (1..100), 100% means AON and is disallowed for partial update
            //  - bit7 (0x80) selects base amount: 0 = current remain, 1 = original order value (root)
            if (l_out_cond->subtype.srv_dex.buy_net_id.uint64 != l_prev->subtype.srv_dex.buy_net_id.uint64
                || l_out_cond->subtype.srv_dex.sell_net_id.uint64 != l_prev->subtype.srv_dex.sell_net_id.uint64
                || strcmp(l_out_cond->subtype.srv_dex.buy_token, l_prev->subtype.srv_dex.buy_token)
                || compare256(l_out_cond->subtype.srv_dex.rate, l_prev->subtype.srv_dex.rate) != 0
                || !dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_prev->subtype.srv_dex.seller_addr)
                || l_out_cond->subtype.srv_dex.version != l_prev->subtype.srv_dex.version
                || l_out_cond->subtype.srv_dex.min_fill != l_prev->subtype.srv_dex.min_fill
                || l_out_cond->subtype.srv_dex.flags != l_prev->subtype.srv_dex.flags) { l_err = -14; break; }
            if (memcmp(&l_out_cond->subtype.srv_dex.order_root_hash, &l_root_hash, sizeof(dap_hash_fast_t)) != 0) { l_err = -14; break; }

            if (l_out_cond->subtype.srv_dex.tx_type != DEX_TX_TYPE_UPDATE) { l_err = -13; break; }
            uint8_t l_pct = l_prev->subtype.srv_dex.min_fill & 0x7F;
            if (l_pct == 100) { l_err = -11; break; }
            if (l_pct > 0) {
                uint256_t l_base_val;
                if ( (l_prev->subtype.srv_dex.min_fill & 0x80) ) {
                    dap_chain_datum_tx_t *l_root_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_root_hash);
                    if (!l_root_tx) { l_err = -12; break; }
                    dap_chain_tx_out_cond_t *l_root_out = dap_chain_datum_tx_out_cond_get(l_root_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
                    if (!l_root_out) { l_err = -12; break; }
                    l_base_val = l_root_out->header.value;  
                } else
                    l_base_val = l_prev->header.value;
                if ( compare256(l_executed_i, s_calc_pct(l_base_val, l_pct)) < 0 ) { l_err = -12; break; }
            }
        }

        int l_search_idx = -1;
        for (int j = 0; j < l_uniq_sellers_q; j++) {
            if (dap_chain_addr_compare(l_sellers_agg[j].addr, &l_prev->subtype.srv_dex.seller_addr)) {
                l_search_idx = j; break; 
            }
        }
        if (l_search_idx < 0) { l_err = -14; break; }
        uint256_t l_buy_i = uint256_0;
        MULT_256_COIN(l_executed_i, l_prev->subtype.srv_dex.rate, &l_buy_i);
        SUM_256_256(l_sellers_agg[l_search_idx].expected_buy, l_buy_i, &l_sellers_agg[l_search_idx].expected_buy);
        SUM_256_256(l_executed_total_sell, l_executed_i, &l_executed_total_sell);
        SUM_256_256(l_executed_total_buy,  l_buy_i, &l_executed_total_buy);
    }
    DAP_DELETE(l_ins_agg);
    if (l_err) { 
        DAP_DELETE(l_sellers_agg);
        return l_err;
    }

    // Fees config and second pass over OUT items
    //  - Resolve required network/service fees (percent service fee uses totals from the first pass)
    //  - Accumulate per-seller paid_buy and total paid_sell_any excluding fee destinations
    const char *l_native_ticker = a_ledger->net->pub.native_ticker;
    uint256_t net_fee_req = uint256_0, srv_fee_cfg = uint256_0, srv_fee_req = uint256_0;
    dap_chain_addr_t net_addr = { }; bool net_used = dap_chain_net_tx_get_fee(a_ledger->net->pub.id, &net_fee_req, &net_addr);
    dap_chain_addr_t srv_addr = { }; uint16_t srv_type = 0; bool srv_used = s_dex_get_service_fee(a_ledger->net->pub.id, &srv_fee_cfg, &srv_addr, &srv_type);
    srv_fee_req = srv_fee_cfg;
    if (srv_used && (srv_type == SERVICE_FEE_NATIVE_PERCENT || srv_type == SERVICE_FEE_OWN_PERCENT))
        MULT_256_COIN(srv_fee_req, l_executed_total_buy, &srv_fee_req);
    const char *srv_ticker = srv_used ? ((srv_type == SERVICE_FEE_OWN_FIXED || srv_type == SERVICE_FEE_OWN_PERCENT) ? l_buy_ticker : l_native_ticker) : NULL;
    uint256_t paid_sell_any = uint256_0, paid_net = uint256_0, paid_srv = uint256_0, validator_fee = uint256_0, buy_others = uint256_0;
    dap_chain_addr_t *l_buyer_addr = NULL; bool l_buyer_addr_uniq = true;
    TX_ITEM_ITER_TX(it, sz, a_tx_in) {
        switch (*it) {
        case TX_ITEM_TYPE_OUT_EXT: {
            dap_chain_tx_out_ext_t *o = (dap_chain_tx_out_ext_t*)it;
            if ( !strcmp(o->token, l_buy_ticker) ) {
                for (int j = 0; j < l_uniq_sellers_q; j++) {
                    if (dap_chain_addr_compare(&o->addr, l_sellers_agg[j].addr)) {
                        SUM_256_256(l_sellers_agg[j].paid_buy, o->header.value, &l_sellers_agg[j].paid_buy);
                        break;
                    }
                }
                bool is_seller = false;
                for (int j = 0; j < l_uniq_sellers_q && !is_seller; j++)
                    if (dap_chain_addr_compare(&o->addr, l_sellers_agg[j].addr)) is_seller = true;
                bool is_srv_buy = srv_used && srv_ticker && !strcmp(l_buy_ticker, srv_ticker) && dap_chain_addr_compare(&o->addr, &srv_addr);
                if (!is_seller && !is_srv_buy)
                    SUM_256_256(buy_others, o->header.value, &buy_others);
            }
            if ( !strcmp(o->token, l_sell_ticker) ) {
                // Exclude fee destinations (network/service) from buyer payout detection and amount
                bool is_fee_addr = (net_used && !strcmp(o->token, l_native_ticker) && dap_chain_addr_compare(&o->addr, &net_addr))
                                 || (srv_used && srv_ticker && !strcmp(o->token, srv_ticker) && dap_chain_addr_compare(&o->addr, &srv_addr));
                if (!is_fee_addr) {
                    SUM_256_256(paid_sell_any, o->header.value, &paid_sell_any);
                    if (!l_buyer_addr) l_buyer_addr = &o->addr; else if (!dap_chain_addr_compare(l_buyer_addr, &o->addr)) l_buyer_addr_uniq = false;
                }
            }
            if (net_used && !strcmp(o->token, l_native_ticker) && dap_chain_addr_compare(&o->addr, &net_addr))
                SUM_256_256(paid_net, o->header.value, &paid_net);
            if (srv_used && !strcmp(o->token, srv_ticker) && dap_chain_addr_compare(&o->addr, &srv_addr))
                SUM_256_256(paid_srv, o->header.value, &paid_srv);
        } break;
        case TX_ITEM_TYPE_OUT_STD: {
            dap_chain_tx_out_std_t *o = (dap_chain_tx_out_std_t*)it;
            if ( !strcmp(o->token, l_buy_ticker) ) {
                for (int j = 0; j < l_uniq_sellers_q; j++) {
                    if (dap_chain_addr_compare(&o->addr, l_sellers_agg[j].addr)) {
                        SUM_256_256(l_sellers_agg[j].paid_buy, o->value, &l_sellers_agg[j].paid_buy);
                        break;
                    }
                }
                bool is_seller = false;
                for (int j = 0; j < l_uniq_sellers_q && !is_seller; j++)
                    if (dap_chain_addr_compare(&o->addr, l_sellers_agg[j].addr)) is_seller = true;
                bool is_srv_buy = srv_used && srv_ticker && !strcmp(l_buy_ticker, srv_ticker) && dap_chain_addr_compare(&o->addr, &srv_addr);
                if (!is_seller && !is_srv_buy)
                    SUM_256_256(buy_others, o->value, &buy_others);
            }
            if ( !strcmp(o->token, l_sell_ticker) ) {
                // Exclude fee destinations (network/service) from buyer payout detection and amount
                bool is_fee_addr = (net_used && !strcmp(o->token, l_native_ticker) && dap_chain_addr_compare(&o->addr, &net_addr))
                                 || (srv_used && srv_ticker && !strcmp(o->token, srv_ticker) && dap_chain_addr_compare(&o->addr, &srv_addr));
                if (!is_fee_addr) {
                    SUM_256_256(paid_sell_any, o->value, &paid_sell_any);
                    if (!l_buyer_addr) l_buyer_addr = &o->addr; else if (!dap_chain_addr_compare(l_buyer_addr, &o->addr)) l_buyer_addr_uniq = false;
                }
            }
            if (net_used && !strcmp(o->token, l_native_ticker) && dap_chain_addr_compare(&o->addr, &net_addr))
                SUM_256_256(paid_net, o->value, &paid_net);
            if (srv_used && !strcmp(o->token, srv_ticker) && dap_chain_addr_compare(&o->addr, &srv_addr))
                SUM_256_256(paid_srv, o->value, &paid_srv);
        } break;
        case TX_ITEM_TYPE_OUT: {
            dap_chain_tx_out_t *o = (dap_chain_tx_out_t*)it;
            // Buy token payouts in native form (when buy token == native): count sellers and detect leaks
            if ( !strcmp(l_buy_ticker, l_native_ticker) ) {
                for (int j = 0; j < l_uniq_sellers_q; j++) {
                    if (dap_chain_addr_compare(&o->addr, l_sellers_agg[j].addr)) {
                        SUM_256_256(l_sellers_agg[j].paid_buy, o->header.value, &l_sellers_agg[j].paid_buy);
                        break;
                    }
                }
                bool is_seller = false;
                for (int j = 0; j < l_uniq_sellers_q && !is_seller; j++)
                    if (dap_chain_addr_compare(&o->addr, l_sellers_agg[j].addr)) is_seller = true;
                bool is_srv_buy = srv_used && srv_ticker && !strcmp(l_buy_ticker, srv_ticker) && dap_chain_addr_compare(&o->addr, &srv_addr);
                if (!is_seller && !is_srv_buy)
                    SUM_256_256(buy_others, o->header.value, &buy_others);
            }
            if ( !strcmp(l_sell_ticker, l_native_ticker) ) {
                // Exclude native fee/service destinations from buyer payout
                bool is_fee_addr = (net_used && dap_chain_addr_compare(&o->addr, &net_addr))
                                 || (srv_used && (srv_type == SERVICE_FEE_NATIVE_FIXED || srv_type == SERVICE_FEE_NATIVE_PERCENT) && dap_chain_addr_compare(&o->addr, &srv_addr));
                if (!is_fee_addr) {
                    SUM_256_256(paid_sell_any, o->header.value, &paid_sell_any);
                    if (!l_buyer_addr) l_buyer_addr = &o->addr;
                    else if (!dap_chain_addr_compare(l_buyer_addr, &o->addr)) l_buyer_addr_uniq = false;
                }
            }
        } break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *oc = (dap_chain_tx_out_cond_t*)it;
            if (oc->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                SUM_256_256(validator_fee, oc->header.value, &validator_fee);
        } break;
        default: break;
        }
    }
    // Per-seller equality
    for (int j = 0; j < l_uniq_sellers_q; j++) {
        if ( compare256(l_sellers_agg[j].paid_buy, l_sellers_agg[j].expected_buy ) ) {
            l_err = -18; break;
        }
    }
    DAP_DELETE(l_sellers_agg);
    if (l_err) m_ret_err(l_err);

    // Buyer-leftover branch (blank root): ensure single recipient of sell (excluding fees) matches OUT seller_addr
    if (l_out_cond && dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash)) {
        if ( !l_buyer_addr )
            m_ret_err(DEXV_BUYER_ADDR_MISSING);
        if (!l_buyer_addr_uniq)
            m_ret_err(DEXV_MULTI_BUYER_DEST); // multiple distinct buyer destinations not allowed
        if ( !dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, l_buyer_addr) )
            m_ret_err(DEXV_BUYER_MISMATCH);
        // No unexpected payouts in buy token (only sellers and, if configured, service)
        if (!IS_ZERO_256(buy_others))
            m_ret_err(DEXV_BUY_TOKEN_LEAK);
        // tx_type=EXCHANGE (buyer-leftover) expected
        if (l_out_cond->subtype.srv_dex.tx_type != DEX_TX_TYPE_EXCHANGE)
            m_ret_err(DEXV_TX_TYPE_MISMATCH);
    }
    // Network fee: protect validator/mempool economics
    if (net_used && !IS_ZERO_256(net_fee_req) && compare256(paid_net, net_fee_req) < 0)
        m_ret_err(DEXV_NETWORK_FEE_UNDERPAID);
    // Service fee: native/own (fixed or percent of total buy)
    if (srv_used && compare256(paid_srv, srv_fee_req) < 0)
        m_ret_err(DEXV_SERVICE_FEE_UNDERPAID);
    // Buyer payout in sell: final conservation check
    if (!dap_strcmp(l_sell_ticker, l_native_ticker)) {
        // Final buyer payout check (sell token, native case):
        // expected = total executed sell - (validator fee + network fee + native service fee if configured)
        uint256_t expected = l_executed_total_sell;
        SUBTRACT_256_256(expected, validator_fee, &expected);
        if (net_used && !IS_ZERO_256(net_fee_req))
            SUBTRACT_256_256(expected, net_fee_req, &expected);
        if (srv_used && (srv_type == SERVICE_FEE_NATIVE_FIXED || srv_type == SERVICE_FEE_NATIVE_PERCENT)) {
            uint256_t srv_nat = srv_fee_cfg;
            if (srv_type == SERVICE_FEE_NATIVE_PERCENT)
                MULT_256_COIN(srv_nat, l_executed_total_buy, &srv_nat);
            SUBTRACT_256_256(expected, srv_nat, &expected);
        }
        if ( compare256(paid_sell_any, expected) )
            m_ret_err(DEXV_FINAL_NATIVE_MISMATCH);
    }
    return 0;
    #undef m_ret_err
}

static int s_cli_srv_dex(int a_argc, char **a_argv, void **a_str_reply, int a_version);

int dap_chain_net_srv_dex_init()
{
    // Register verificator for SRV_DEX
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, s_dex_verificator_callback, NULL, NULL);

    // Load soft policy for cross-net matching (outside consensus)
    const char *l_policy = dap_config_get_item_str_default(g_config, "srv_dex", "cross_net_policy", "reject");
    s_cross_net_policy = !dap_strcmp(l_policy, "allow") ? CROSS_NET_ALLOW : !dap_strcmp(l_policy, "warn") ? CROSS_NET_WARN : CROSS_NET_REJECT;

    log_it(L_INFO, "cross_net_policy=%s", s_cross_net_policy_str(s_cross_net_policy));
    // Read cache switch from config
    s_dex_cache_enabled = dap_config_get_item_bool_default(g_config, "srv_dex", "memcached", false);
    log_it(L_INFO, "cache %s", s_dex_cache_enabled ? "ENABLED" : "DISABLED");
    // Read history cache switch and bucket size
    s_dex_history_enabled = dap_config_get_item_bool_default(g_config, "srv_dex", "history_cache", false);
    s_dex_history_bucket_sec = (uint64_t)dap_config_get_item_uint32_default(g_config, "srv_dex", "history_bucket_sec", 600); // 10 minutes
    log_it(L_INFO, "history cache %s (bucket=%uus)", s_dex_history_enabled ? "ENABLED" : "DISABLED", (unsigned)s_dex_history_bucket_sec);

    // Subscribe cache to ledger notifications for all nets
    if (s_dex_cache_enabled || s_dex_history_enabled) {
    for (dap_chain_net_t *net = dap_chain_net_iter_start(); net; net = dap_chain_net_iter_next(net))
        dap_ledger_tx_add_notify(net->pub.ledger, s_ledger_tx_add_notify_dex, NULL);
    }

    // CLI: register handler
    dap_cli_server_cmd_add("srv_dex", s_cli_srv_dex, NULL, "DEX v2 service commands",
        "srv_dex order create -net <net_name> -token_sell <ticker> -token_buy <ticker> -w <wallet> -value <value> -rate <rate> -fee <fee>\n"
        "srv_dex order remove -net <net_name> -order <order_hash> -w <wallet> -fee <fee>\n"
        "srv_dex order update -net <net_name> -order <root_hash> -w <wallet> [-rate <rate>] [-value_new <value>] -fee <fee>\n"
        "srv_dex orders -net <net_name> -pair <BASE/QUOTE> [-seller <addr>]\n"
        "srv_dex migrate -net <net_name> -from <tx[:idx]> -rate <RATE> -fee <FEE> -w <wallet>\n"
        "srv_dex orderbook -net <net_name> -pair <BASE/QUOTE> -depth <N>\n"
        "srv_dex status -net <net_name> -pair <BASE/QUOTE> [-seller <addr>]\n"
        "srv_dex market_rate -net <net_name> -pair <BASE/QUOTE> [-from <T0>] [-to <T1>] [-bucket <sec>]\n"
        "srv_dex tvl -net <net_name> -token <ticker>\n"
        "srv_dex spread -net <net_name> -pair <BASE/QUOTE>\n"
        "srv_dex volume -net <net_name> -pair <BASE/QUOTE> [-from <T0>] [-to <T1>] [-bucket <sec>]\n"
        "srv_dex slippage -net <net_name> -pair <BASE/QUOTE> -value <VALUE> [-side buy|sell]\n"
        "srv_dex history -net <net_name> -order <order_hash>\n"
        "srv_dex purchase -net <net_name> -order <order_hash> -w <wallet> -value <value> -fee <fee>\n"
        "srv_dex purchase_multi -net <net_name> -orders <hash1,hash2,...> -w <wallet> -value <value> -fee <fee> [-create_leftover_order 0|1]\n"
        "srv_dex purchase_auto -net <net_name> -token_sell <ticker> -token_buy <ticker> -w <wallet> -value <value> [-min_rate <r>] [-fee <value>] [-create_leftover_order 0|1] [-dry-run]\n"
        "srv_dex cancel_all_by_seller -net <net_name> -seller <addr> -w <wallet> -fee <fee> [-limit <N>] [-dry-run]\n"
    );
    return 0;
}
void dap_chain_net_srv_dex_deinit()
{
    // Free caches
    pthread_rwlock_wrlock(&s_dex_cache_rwlock);
    dex_order_cache_entry_t *e_it, *e_tmp; HASH_ITER(level.hh, s_dex_orders_cache, e_it, e_tmp) { 
        HASH_DELETE(level.hh_tail, s_dex_index_by_tail, e_it); 
        HASH_DELETE(level.hh, s_dex_orders_cache, e_it); 
        DAP_DELETE(e_it);
    }
    // Free pair index
    dex_pair_index_t *pb_it, *pb_tmp; HASH_ITER(hh, s_dex_pair_index, pb_it, pb_tmp) {
        HASH_DELETE(hh, s_dex_pair_index, pb_it);
        DAP_DELETE(pb_it);
    }
    // Free seller index
    dex_seller_index_t *sb_it, *sb_tmp; HASH_ITER(hh, s_dex_seller_index, sb_it, sb_tmp) {
        HASH_DELETE(hh, s_dex_seller_index, sb_it);
        DAP_DELETE(sb_it);
    }

    // Free history cache (buckets and pairs)
    dex_hist_pair_t *hp_it, *hp_tmp; HASH_ITER(hh, s_dex_history, hp_it, hp_tmp) {
        // free per-pair buckets
        dex_bucket_agg_t *b_it, *b_tmp; HASH_ITER(hh, hp_it->buckets, b_it, b_tmp) {
            // free per-bucket trade index
            dex_trade_rec_t *tr_it, *tr_tmp; HASH_ITER(hh, b_it->trades_idx, tr_it, tr_tmp) {
                HASH_DELETE(hh, b_it->trades_idx, tr_it);
                DAP_DELETE(tr_it);
            }
            HASH_DELETE(hh, hp_it->buckets, b_it);
            DAP_DELETE(b_it);
        }
        HASH_DELETE(hh, s_dex_history, hp_it); 
        DAP_DELETE(hp_it);
    }
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    pthread_rwlock_destroy(&s_dex_cache_rwlock);

    // Free service fee table
    pthread_rwlock_wrlock(&s_dex_service_fees_rwlock);
    dap_chain_net_srv_fee_item_t *sf_it, *sf_tmp; HASH_ITER(hh, s_dex_service_fees, sf_it, sf_tmp) {
        HASH_DELETE(hh, s_dex_service_fees, sf_it);
        DAP_DELETE(sf_it);
    }
    pthread_rwlock_unlock(&s_dex_service_fees_rwlock);
    pthread_rwlock_destroy(&s_dex_service_fees_rwlock);
}

// Determine DEX TX type; simplified: ORDER if OUT_COND(SRV_DEX) and no IN_COND; EXCHANGE if IN_COND with SRV_DEX; INVALIDATE if IN_COND and no SRV_DEX OUT_COND
static dex_tx_type_t s_dex_tx_classify(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_in_cond_t **a_in_cond,
                             dap_chain_tx_out_cond_t **a_out_cond, int *a_out_idx)
{
    // Locate SRV_DEX OUT (single expected by design)
    int l_out_idx = 0;
    dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
    if (a_out_cond) *a_out_cond = l_out;
    if (a_out_idx) *a_out_idx = l_out_idx;
    // Find first IN_COND
    dap_chain_tx_in_cond_t *l_in0 = (dap_chain_tx_in_cond_t*)dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL);
    if (a_in_cond) *a_in_cond = l_in0;
    // If SRV_DEX OUT present, trust declared type (verifier enforces consistency)
    if (l_out) return (dex_tx_type_t)l_out->subtype.srv_dex.tx_type;
    // No SRV_DEX OUT: if there is no IN either — not a DEX tx
    if (!l_in0) return DEX_TX_TYPE_UNDEFINED;

    const char *l_buy_tok = NULL;
    const dap_chain_addr_t *l_seller_addr = NULL;
    dex_tx_type_t l_ret = DEX_TX_TYPE_INVALIDATE;
    // Try cache first
    if (s_dex_cache_enabled) {
        pthread_rwlock_rdlock(&s_dex_cache_rwlock);
        dex_order_cache_entry_t *e = NULL; HASH_FIND(level.hh_tail, s_dex_index_by_tail, &l_in0->header.tx_prev_hash, sizeof(l_in0->header.tx_prev_hash), e);
        if (e && e->seller_addr_ptr && e->pair_key_ptr) {
            l_seller_addr = (const dap_chain_addr_t*)e->seller_addr_ptr;
            l_buy_tok = e->pair_key_ptr->buy_token;
        }
    } else {
        // Fallback to ledger
        dap_chain_datum_tx_t *l_tx_prev = a_ledger ? dap_ledger_tx_find_by_hash(a_ledger, &l_in0->header.tx_prev_hash) : NULL;
        dap_chain_tx_out_cond_t *l_prev_out = dap_chain_datum_tx_out_cond_get(l_tx_prev, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
        l_seller_addr = &l_prev_out->subtype.srv_dex.seller_addr;
        l_buy_tok = l_prev_out->subtype.srv_dex.buy_token;
    }
    byte_t *it; size_t sz;
    TX_ITEM_ITER_TX(it, sz, a_tx) {
        if (*it == TX_ITEM_TYPE_OUT_EXT) {
            dap_chain_tx_out_ext_t *o = (dap_chain_tx_out_ext_t*)it;
            if (!strcmp(o->token, l_buy_tok) && dap_chain_addr_compare(&o->addr, l_seller_addr)) l_ret = DEX_TX_TYPE_EXCHANGE;
        } else if (*it == TX_ITEM_TYPE_OUT_STD) {
            dap_chain_tx_out_std_t *o = (dap_chain_tx_out_std_t*)it;
            if (!strcmp(o->token, l_buy_tok) && dap_chain_addr_compare(&o->addr, l_seller_addr)) l_ret = DEX_TX_TYPE_EXCHANGE;
        }
    }
    if (s_dex_cache_enabled)
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
    return l_ret;
}

typedef struct dex_bq {
    uint256_t base, quote;
} dex_bq_t;

#define EXEC_TO_CANON_BQ(exec, rate, side) \
    ({ dex_bq_t l_bq = { }; \
       if ( (side) == DEX_SIDE_ASK ) { \
            l_bq.base = (exec); MULT_256_COIN(l_bq.base, (rate), &l_bq.quote); \
       } else { \
            l_bq.quote = (exec); DIV_256_COIN(l_bq.quote, (rate), &l_bq.base); \
       } \
       l_bq; })

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
static void s_ledger_tx_add_notify_dex(void *UNUSED_ARG a_arg, dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, dap_chan_ledger_notify_opcodes_t a_opcode)
{
    if (a_opcode != 'a' && a_opcode != 'd')
        return;
    dap_chain_tx_in_cond_t *l_in_cond = NULL;
    dap_chain_tx_out_cond_t *l_out_cond = NULL; int l_out_idx = 0;
    switch ( s_dex_tx_classify(a_ledger, a_tx, &l_in_cond, &l_out_cond, &l_out_idx) ) {
    case DEX_TX_TYPE_UNDEFINED: return;
    case DEX_TX_TYPE_ORDER:
        if ( a_opcode == 'a' ) {
            // Add to cache
            s_dex_cache_upsert(a_ledger, dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tx_hash), a_tx_hash, a_tx_hash, l_out_cond, /*prev_idx*/0);
            log_it(L_DEBUG, "Order cached, root = tail = %s", dap_hash_fast_to_str_static(a_tx_hash));
        } else {
            // Remove from cache
            pthread_rwlock_wrlock(&s_dex_cache_rwlock);
            s_dex_cache_remove_by_root(a_tx_hash);
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
            log_it(L_DEBUG, "Order removed, root = %s", dap_hash_fast_to_str_static(a_tx_hash));
        } break;
    case DEX_TX_TYPE_EXCHANGE:
    case DEX_TX_TYPE_UPDATE: {
        pthread_rwlock_wrlock(&s_dex_cache_rwlock);
        if (a_opcode == 'a') {
            const char *l_prev0_sell_token = NULL, *l_prev0_buy_token = NULL;
            const dap_chain_addr_t *l_prev0_seller_addr = NULL;
            // Residual update context:
            //  - non-blank root in OUT means seller's leftover should persist under the original root
            //  - per protocol, residual is allowed only for the first IN in the TX
            bool l_residual_update = l_out_cond && !dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash);
            dap_hash_fast_t l_residual_root = l_residual_update ? l_out_cond->subtype.srv_dex.order_root_hash : (dap_hash_fast_t){ };
            // Prefill baseline from first IN using cache if available:
            //  - use cache to quickly retrieve sell/buy tickers and seller address
            //  - needed later to choose sell_ticker for buyer-leftover and for history
            if (l_in_cond && s_dex_cache_enabled) {
                const dex_order_cache_entry_t *e0 = NULL;
                HASH_FIND(level.hh_tail, s_dex_index_by_tail, &l_in_cond->header.tx_prev_hash, sizeof(l_in_cond->header.tx_prev_hash), e0);
                if (e0) {
                    l_prev0_sell_token = (e0->side_version & 0x1) ? e0->pair_key_ptr->buy_token : e0->pair_key_ptr->sell_token;
                    l_prev0_buy_token  = (e0->side_version & 0x1) ? e0->pair_key_ptr->sell_token : e0->pair_key_ptr->buy_token;
                    l_prev0_seller_addr = (const dap_chain_addr_t*)e0->seller_addr_ptr;
                }
            }
            int l_in_idx = 0; byte_t *it; size_t sz;
            TX_ITEM_ITER_TX(it, sz, a_tx) if (*it == TX_ITEM_TYPE_IN_COND) {
                dap_hash_fast_t l_prev_hash = ((dap_chain_tx_in_cond_t*)it)->header.tx_prev_hash;

                // Cache lookup by tail
                const dex_order_cache_entry_t *e = NULL;
                if (s_dex_cache_enabled)
                    HASH_FIND(level.hh_tail, s_dex_index_by_tail, &l_prev_hash, sizeof(l_prev_hash), e);


                // History append: prefer cache (precise data about previous order),
                // otherwise fallback to ledger (heavier, but restores required minimum)
                if (s_dex_history_enabled) {
                    if (e) {
                        // executed_i — actual executed amount for this IN
                        // by default equals prev.value; if residual on first IN — subtract leftover
                        uint256_t l_executed_i = e->level.match.value;
                        bool is_residual_on_first_in = l_residual_update && (l_in_idx == 0) && !dap_hash_fast_compare(&e->level.match.root, &l_residual_root);
                        if ( is_residual_on_first_in && compare256(e->level.match.value, l_out_cond->header.value) > 0 )
                            SUBTRACT_256_256(e->level.match.value, l_out_cond->header.value, &l_executed_i);

                        dex_bq_t l_bq = EXEC_TO_CANON_BQ( l_executed_i, e->level.match.rate, e->side_version & 0x1 );
                        if ((e->pair_key_ptr->sell_net_id.uint64 == a_ledger->net->pub.id.uint64) && (e->pair_key_ptr->buy_net_id.uint64 == a_ledger->net->pub.id.uint64))
                            dex_history_append_trade(e->pair_key_ptr, a_tx->header.ts_created, e->level.match.rate,
                         l_bq.base, l_bq.quote, s_dex_history_bucket_sec, a_tx_hash, &l_prev_hash);
                        else if (s_cross_net_policy == CROSS_NET_WARN)
                            log_it(L_WARNING, "cross-net trade seen in notifier: %s/%s", e->pair_key_ptr->sell_token, e->pair_key_ptr->buy_token);
                    } else {
                        // Fallback: derive previous order from ledger
                        dap_chain_datum_tx_t *l_tx_i = dap_ledger_tx_find_by_hash(a_ledger, &l_prev_hash);
                        if (l_tx_i) {
                            dap_chain_tx_out_cond_t *prev_cond_i = dap_chain_datum_tx_out_cond_get(l_tx_i, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
                            if (prev_cond_i) {
                                const char *l_sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_prev_hash);
                                if ( l_sell_ticker ) {
                                    // Compute executed_i (respect residual on first IN if root matches)
                                    uint256_t executed_i = prev_cond_i->header.value;
                                    if (l_residual_update && l_in_idx == 0) {
                                        dap_hash_fast_t root_hash_i = dap_ledger_get_first_chain_tx_hash(a_ledger, l_tx_i, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                                        if (!dap_hash_fast_compare(&root_hash_i, &l_residual_root) && compare256(prev_cond_i->header.value, l_out_cond->header.value) > 0)
                                            SUBTRACT_256_256(prev_cond_i->header.value, l_out_cond->header.value, &executed_i);
                                    }
                                    // Normalize pair and price to canonical units (price QUOTE/BASE)
                                    dex_pair_key_t l_key = { };
                                    uint8_t l_side = 0;
                                    uint256_t l_price_canon = uint256_0;
                                    s_pair_normalize(l_sell_ticker, prev_cond_i->subtype.srv_dex.sell_net_id, prev_cond_i->subtype.srv_dex.buy_token,
                                                     prev_cond_i->subtype.srv_dex.buy_net_id, prev_cond_i->subtype.srv_dex.rate, &l_key, &l_side, &l_price_canon);
                                    dex_bq_t l_bq = EXEC_TO_CANON_BQ( executed_i, l_price_canon, l_side );
                                    if ((l_key.sell_net_id.uint64 == a_ledger->net->pub.id.uint64) && (l_key.buy_net_id.uint64 == a_ledger->net->pub.id.uint64))
                                        dex_history_append_trade(&l_key, a_tx->header.ts_created, l_price_canon,
                                     l_bq.base, l_bq.quote, s_dex_history_bucket_sec, a_tx_hash, &l_prev_hash);
                                    else if (s_cross_net_policy == CROSS_NET_WARN)
                                        log_it(L_WARNING, "cross-net trade seen in notifier: %s/%s", l_key.sell_token, l_key.buy_token);
                                }
                            }
                        }
                    }
                }

                // Cache maintenance:
                //  - if residual on the first IN (root matches) — update order under original root
                //  - otherwise current tail is fully spent and must be removed from cache
                if (s_dex_cache_enabled) {
                    if ( e && l_residual_update && l_in_idx == 0 && !dap_hash_fast_compare(&e->level.match.root, &l_residual_root) ) {
                        const char *l_sell_ticker = (e->side_version & 0x1) ? e->pair_key_ptr->buy_token : e->pair_key_ptr->sell_token;
                        s_dex_cache_upsert(a_ledger, *l_sell_ticker ? l_sell_ticker : NULL, &l_out_cond->subtype.srv_dex.order_root_hash, a_tx_hash, l_out_cond, l_out_idx);
        } else {
                        dex_order_cache_entry_t *e_del = NULL; HASH_FIND(level.hh_tail, s_dex_index_by_tail, &l_prev_hash, sizeof(l_prev_hash), e_del);
                        s_dex_cache_remove_entry(e_del);
                    }
                }
                l_in_idx++;
            }
            // Buyer-leftover (blank root) creates a new order (root=tail=a_tx_hash):
            //  - OUT seller matches seller of the first IN  → keep previous sell token
            //  - otherwise it's the buyer → sell token becomes previous buy token
            if (s_dex_cache_enabled) {
                if (l_out_cond && dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash)) {
                    const char *l_sell_ticker_new = l_prev0_seller_addr && dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, l_prev0_seller_addr)
                        ? l_prev0_sell_token : l_prev0_buy_token;
                    s_dex_cache_upsert(a_ledger, (l_sell_ticker_new && *l_sell_ticker_new) ? l_sell_ticker_new : NULL, a_tx_hash, a_tx_hash, l_out_cond, l_out_idx);
                    log_it(L_DEBUG, "Buyer leftover order created, root=tail=%s", dap_hash_fast_to_str_static(a_tx_hash));
                }
            } 
        } else { // 'd' reorg
            // Reorg handling:
            //  - remove created buyer-leftover (if any)
            //  - restore all prev_tail into cache and adjust history
            if (s_dex_cache_enabled) {
                if ( l_out_cond && dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash) )
                    s_dex_cache_remove_by_root(a_tx_hash);
            }
            byte_t *it; size_t sz = 0;
            TX_ITEM_ITER_TX(it, sz, a_tx) if (*it == TX_ITEM_TYPE_IN_COND) {
                dap_hash_fast_t l_prev_hash = ((dap_chain_tx_in_cond_t*)it)->header.tx_prev_hash;
                dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_prev_hash);
                if (!l_prev_tx) continue;
                int l_prev_out_idx = 0;
                dap_chain_tx_out_cond_t *l_prev_cout = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_out_idx);
                if (!l_prev_cout) continue;
                const char *l_sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, &l_prev_hash);
                if ( l_sell_ticker ) {
                    if (s_dex_cache_enabled) {
                        dap_hash_fast_t root_hash_i = dap_ledger_get_first_chain_tx_hash(a_ledger, l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                        s_dex_cache_upsert(a_ledger, l_sell_ticker, &root_hash_i, &l_prev_hash, l_prev_cout, l_prev_out_idx);
                    }
                    if (s_dex_history_enabled) {
                        dex_pair_key_t l_key = { };
                        uint8_t l_side=0;
                        uint256_t l_price_canon = uint256_0;
                        s_pair_normalize(l_sell_ticker, l_prev_cout->subtype.srv_dex.sell_net_id, l_prev_cout->subtype.srv_dex.buy_token,
                             l_prev_cout->subtype.srv_dex.buy_net_id, l_prev_cout->subtype.srv_dex.rate, &l_key, &l_side, &l_price_canon);
                        uint64_t l_bts = s_hist_bucket_ts(a_tx->header.ts_created, s_dex_history_bucket_sec);
                        dex_hist_pair_t *l_pair = NULL; HASH_FIND(hh, s_dex_history, &l_key, sizeof(l_key), l_pair);
                        if (l_pair) {
                            dex_bucket_agg_t *l_bucket = NULL; HASH_FIND(hh, l_pair->buckets, &l_bts, sizeof(l_bts), l_bucket);
                            if (l_bucket)
                                s_hist_idx_remove_rec_apply(l_pair, l_bucket, a_tx_hash, &l_prev_hash);
                        }
                    }
                }
            }
        }
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
    }
    default: return;
    }
}
/*
 * Matching algorithm (applies to both ledger and cache implementations):
 *
 * Inputs:
 *   - criteria: desired pair (sell_token/buy_token with nets), max_buy_value (budget in QUOTE), min_rate (threshold)
 *   - orders: normalized to canonical price rate = QUOTE/BASE
 * Sides:
 *   - DEX_SIDE_ASK: seller sells BASE; buyer pays in QUOTE; effective price is QUOTE/BASE (canonical)
 *   - DEX_SIDE_BID: seller sells QUOTE; buyer receives BASE; effective price stays QUOTE/BASE (canonical)
 * Filters:
 *   - Expiry time
 *   - Pair and side match
 *   - Price threshold: for ASK, require price <= min_rate when min_rate > 0 (buyers want equal/cheaper)
 * Collection and sorting:
 *   - Ledger path collects levels from the ledger and sorts by rate (ASK asc, BID desc)
 *   - Cache path iterates in-memory buckets that are already kept sorted
 * Consumption semantics:
 *   - Budget is expressed in QUOTE. We greedily consume from best price to worse until budget is exhausted.
 *   - ASK full fill: executed_sell = value; executed_buy = value * rate; budget -= executed_buy
 *   - ASK partial:   executed_sell = floor(budget / rate); executed_buy = executed_sell * rate; budget -= executed_buy
 *   - BID full fill: executed_sell = value; executed_buy = value / rate; budget -= executed_buy
 *   - BID partial:   executed_sell = budget * rate; executed_buy = budget;        budget  = 0
 *   - Min-fill policy: lower 7 bits are percent threshold; high bit (0x80) means measure percent from origin (root value) rather than current value.
 */


dap_hash_fast_t *dap_chain_net_srv_dex_match_hashes(
    dap_chain_net_t *a_net, const char *a_sell_token, const char *a_buy_token,
    dap_chain_net_id_t *a_sell_net_id, dap_chain_net_id_t *a_buy_net_id,
    uint256_t *a_max_buy_value, uint256_t *a_min_rate, size_t *a_num_matches)
{
    dap_ret_val_if_any(NULL, !a_net, !a_sell_token, !a_buy_token);
    dex_match_criteria_t l_crit = { a_sell_token, a_buy_token,
         a_sell_net_id ? *a_sell_net_id : (dap_chain_net_id_t){ },
          a_buy_net_id ? *a_buy_net_id: (dap_chain_net_id_t){ },
         a_max_buy_value ? *a_max_buy_value : uint256_0, a_min_rate ? *a_min_rate : uint256_0 };
    dap_hash_fast_t *l_hashes = NULL;
    size_t i = 0, q;
    dex_match_table_entry_t *l_matches = s_dex_matches_build_by_criteria(a_net, &l_crit);
    if (!l_matches) return NULL;
    q = HASH_CNT(hh, l_matches);
    l_hashes = DAP_NEW_Z_COUNT(dap_hash_fast_t, q);
    dex_match_table_entry_t *l_cur, *l_tmp; HASH_ITER(hh, l_matches, l_cur, l_tmp) l_hashes[i++] = l_cur->match.tail;
    s_dex_matches_clear(&l_matches);
    if (a_num_matches) *a_num_matches = q;
    return l_hashes;
}


#define TVL_PAIR_LEN (2 * DAP_CHAIN_TICKER_SIZE_MAX + 2)
typedef struct l_tvl_pair_sum { 
    char pair[TVL_PAIR_LEN];
    uint256_t tvl;
    UT_hash_handle hh;
} l_tvl_pair_sum_t;

static inline int s_cmp_tvl_desc(l_tvl_pair_sum_t *a, l_tvl_pair_sum_t *b) {
    return compare256(b->tvl, a->tvl);
}

// ---------------- CLI ----------------
static int s_cli_srv_dex(int a_argc, char **a_argv, void **a_str_reply, int a_version)
{
    json_object **json_arr_reply = (json_object **)a_str_reply; int l_arg_index = 1;
    enum { CMD_ORDER, CMD_ORDERS, CMD_ORDERBOOK,
        CMD_STATUS, CMD_HISTORY,
        CMD_PURCHASE, CMD_PURCHASE_MULTI, CMD_PURCHASE_AUTO,
        CMD_CANCEL_ALL_BY_SELLER,
        CMD_MARKET_RATE, CMD_TVL, CMD_SPREAD, CMD_VOLUME, CMD_SLIPPAGE,
        CMD_MIGRATE,
        CMD_MAX_NUM
    } l_cmd = CMD_MAX_NUM;
    static const char *l_cmd_str[CMD_MAX_NUM] = { 
        [CMD_ORDER] = "order", [CMD_ORDERS] = "orders", [CMD_ORDERBOOK] = "orderbook",
        [CMD_STATUS] = "status", [CMD_HISTORY] = "history",
        [CMD_PURCHASE] = "purchase", [CMD_PURCHASE_MULTI] = "purchase_multi", [CMD_PURCHASE_AUTO] = "purchase_auto",
        [CMD_CANCEL_ALL_BY_SELLER] = "cancel_all_by_seller",
        [CMD_MARKET_RATE] = "market_rate", [CMD_TVL] = "tvl", [CMD_SPREAD] = "spread", [CMD_VOLUME] = "volume", [CMD_SLIPPAGE] = "slippage",
        [CMD_MIGRATE] = "migrate" };
    
    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "order", NULL)) l_cmd = CMD_ORDER;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "orders", NULL)) l_cmd = CMD_ORDERS;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "status", NULL)) l_cmd = CMD_STATUS;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "history", NULL)) l_cmd = CMD_HISTORY;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "purchase_multi", NULL)) l_cmd = CMD_PURCHASE_MULTI;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "purchase", NULL)) l_cmd = CMD_PURCHASE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "purchase_auto", NULL)) l_cmd = CMD_PURCHASE_AUTO;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "orderbook", NULL)) l_cmd = CMD_ORDERBOOK;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "market_rate", NULL)) l_cmd = CMD_MARKET_RATE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "tvl", NULL)) l_cmd = CMD_TVL;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "spread", NULL)) l_cmd = CMD_SPREAD;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "volume", NULL)) l_cmd = CMD_VOLUME;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "slippage", NULL)) l_cmd = CMD_SLIPPAGE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "migrate", NULL)) l_cmd = CMD_MIGRATE;
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "cancel_all_by_seller", NULL)) l_cmd = CMD_CANCEL_ALL_BY_SELLER;

    if (l_cmd == CMD_MAX_NUM)
        return dap_json_rpc_error_add(*json_arr_reply, -1, "unknown command %s", a_argv[l_arg_index]), -1;

    const char *l_net_str = NULL, *l_wallet_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_str);
    if ( !l_net_str )
        return dap_json_rpc_error_add(*json_arr_reply, -2, "-net required"), -2;

    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
    if ( !l_net )
        return dap_json_rpc_error_add(*json_arr_reply, -3, "net not found"), -3;
    
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_str);
    if ( !l_wallet_str )
        return dap_json_rpc_error_add(*json_arr_reply, -4, "-w required"), -4;

    const char *l_pair_str = NULL;
    // Simplified pair canonicalization
    char l_pair_storage[DAP_CHAIN_TICKER_SIZE_MAX * 2 + 4] = ""; // space for possible spaces
#define PAIR_CANON_SIMPL(_base, _quote) do { \
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-pair", &l_pair_str); \
    if (!l_pair_str) \
        return dap_json_rpc_error_add(*json_arr_reply, -5, "missing -pair"), -5; \
    dap_strncpy(l_pair_storage, l_pair_str, sizeof(l_pair_storage) - 1); \
    char *_slash = strchr(l_pair_storage, '/'); \
    if ( !_slash || _slash == l_pair_storage || *(_slash + 1) == '\0' ) \
        return dap_json_rpc_error_add(*json_arr_reply, -6, "bad -pair \"%s\"", l_pair_str), -6; \
    while (*_slash == ' ') { \
        *_slash = '\0'; \
        ++_slash; \
    } \
    *_slash = '\0'; \
    if ( strncmp(l_pair_storage, _slash + 1, (size_t)(_slash - l_pair_storage)) > 0 ) { \
        _base = l_pair_storage; _quote = _slash + 1; \
    } else { \
        _base = _slash + 1; _quote = l_pair_storage; \
    } \
} while (0)

    int l_ret = 0;
    dap_chain_datum_tx_t *l_datum = NULL;
    json_object *l_json_reply = NULL;
    switch (l_cmd) {
    case CMD_ORDER: {
        enum { SUBCMD_CREATE, SUBCMD_REMOVE, SUBCMD_UPDATE, SUBCMD_NONE } l_subcmd = SUBCMD_NONE;
        const char *l_sell = NULL, *l_buy = NULL, *l_val_str = NULL, *l_rate_str = NULL, *l_fee_str = NULL, *l_subcmd_str = NULL, *l_order_hash_str = NULL;
        if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "create", &l_subcmd_str)) l_subcmd = SUBCMD_CREATE;
        else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "remove", &l_subcmd_str)) l_subcmd = SUBCMD_REMOVE;
        else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index+1), "update", &l_subcmd_str)) l_subcmd = SUBCMD_UPDATE;            

        switch (l_subcmd) {
        case SUBCMD_CREATE: {
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_sell", &l_sell);
            if (!l_sell)
                return dap_json_rpc_error_add(*json_arr_reply, -7, "missing -token_sell"), -7;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_buy", &l_buy);
            if (!l_buy)
                return dap_json_rpc_error_add(*json_arr_reply, -8, "missing -token_buy"), -8;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_val_str);
            if (!l_val_str)
                return dap_json_rpc_error_add(*json_arr_reply, -9, "missing -value"), -9;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-rate", &l_rate_str);
            if (!l_rate_str)
                return dap_json_rpc_error_add(*json_arr_reply, -10, "missing -rate"), -10;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
            if (!l_fee_str)
                return dap_json_rpc_error_add(*json_arr_reply, -11, "missing -fee"), -11;

            const char *l_min_fill_pct_str = NULL, *l_fill_policy_str = NULL;
            int l_min_fill_pct = 0;
            uint8_t l_policy = 0;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-min_fill_pct", &l_min_fill_pct_str);
            if (l_min_fill_pct_str) {
                l_min_fill_pct = atoi(l_min_fill_pct_str);
                if (l_min_fill_pct < 0) l_min_fill_pct = 0;
                if (l_min_fill_pct > 100) l_min_fill_pct = 100;
            }
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fill_policy", &l_fill_policy_str);
            if (l_fill_policy_str) {
                if ( !strcmp(l_fill_policy_str, "AON") ) {
                    if (l_min_fill_pct_str && l_min_fill_pct != 100)
                        return dap_json_rpc_error_add(*json_arr_reply, -13, "incompatible -fill_policy and -min_fill_pct"), -13;
                    l_policy = 100;
                    if (!l_min_fill_pct_str) l_min_fill_pct = 100;
                } else if ( !strcmp(l_fill_policy_str, "MIN") )
                    l_policy = (uint8_t)l_min_fill_pct;
                else if ( !strcmp(l_fill_policy_str, "MIN_FROM_ORIGIN") )
                    l_policy = (uint8_t)( 0x80 | l_min_fill_pct );
                else if ( !strcmp(l_fill_policy_str, "PARTIAL_OK") )
                    l_policy = 0;
                else return dap_json_rpc_error_add(*json_arr_reply, -13, "invalid -fill_policy"), -13;
            } else {
                if ( l_min_fill_pct_str )
                    return dap_json_rpc_error_add(*json_arr_reply, -13, "unspecified -fill_policy for -min_fill_pct"), -13;
                l_fill_policy_str = "PARTIAL_OK";
            }

            uint256_t l_val = dap_chain_coins_to_balance(l_val_str),
                l_rate = dap_chain_coins_to_balance(l_rate_str),
                l_fee = dap_chain_coins_to_balance(l_fee_str);
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
            if (!l_wallet)
                return dap_json_rpc_error_add(*json_arr_reply, -12, "wallet open failed"), -12;
            l_ret = dap_chain_net_srv_dex_create(l_net, l_buy, l_sell, l_val, l_rate, l_policy, l_fee, l_wallet, &l_datum);
            dap_chain_wallet_close(l_wallet);
            if ( l_ret != DEX_CREATE_ERROR_OK )
                break;

            l_json_reply = json_object_new_object();
            json_object_object_add(l_json_reply, "min_fill_pct", json_object_new_int(l_min_fill_pct));
            json_object_object_add(l_json_reply, "fill_policy", json_object_new_string(l_fill_policy_str));
        } break;
        case SUBCMD_REMOVE: {
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if ( !l_order_hash_str )
                return dap_json_rpc_error_add(*json_arr_reply, -14, "missing -order"), -11;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
                return dap_json_rpc_error_add(*json_arr_reply, -11, "missing -fee"), -11;
            dap_hash_fast_t l_order_hash = { };
            if ( dap_chain_hash_fast_from_str(l_order_hash_str, &l_order_hash) )
                return dap_json_rpc_error_add(*json_arr_reply, -14, "invalid -order \"%s\"", l_order_hash_str), -11;
            uint256_t fee = dap_chain_coins_to_balance(l_fee_str);
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
            if (!l_wallet)
                return dap_json_rpc_error_add(*json_arr_reply, -12, "wallet open failed"), -12;
            l_ret = dap_chain_net_srv_dex_remove(l_net, &l_order_hash, fee, l_wallet, &l_datum);
            dap_chain_wallet_close(l_wallet);
        } break;
        case SUBCMD_UPDATE: {
            const char *l_rate_new_str = NULL, *l_value_new_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_hash_str);
            if (!l_order_hash_str)
                return dap_json_rpc_error_add(*json_arr_reply, -14, "missing -order"), -14;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
            if (!l_fee_str)
                return dap_json_rpc_error_add(*json_arr_reply, -15, "missing -fee"), -15;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-rate", &l_rate_new_str);
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value_new", &l_value_new_str);
            if ( !l_rate_new_str && !l_value_new_str )
                return dap_json_rpc_error_add(*json_arr_reply, -16, "missing -rate or -value_new"), -16;
            
            uint256_t l_fee = dap_chain_coins_to_balance(l_fee_str);
            uint256_t new_rate = l_rate_new_str ? dap_chain_coins_to_balance(l_rate_new_str) : uint256_0;
            uint256_t new_value = l_value_new_str ? dap_chain_coins_to_balance(l_value_new_str) : uint256_0;
            dap_hash_fast_t l_root = { };
            dap_chain_hash_fast_from_str(l_order_hash_str, &l_root);
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
            if (!l_wallet)
                return dap_json_rpc_error_add(*json_arr_reply, -12, "wallet \"%s\" open failed", l_wallet_str), -12;
            l_ret = dap_chain_net_srv_dex_update(l_net, &l_root, !!l_rate_new_str, new_rate, !!l_value_new_str, new_value, l_fee, l_wallet, &l_datum);
            dap_chain_wallet_close(l_wallet);
        } break;
        default:
            return dap_json_rpc_error_add(*json_arr_reply, -6, "unknown subcommand %s", l_subcmd_str), -6;
        }
    } break; // CMD_ORDER

    case CMD_ORDERS: {
        const char *l_base, *l_quote; PAIR_CANON_SIMPL(l_base, l_quote);
        const char *l_seller_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-seller", &l_seller_str);
        dap_chain_addr_t l_seller;
        if (l_seller_str) {
            dap_chain_addr_t *l_seller_tmp = dap_chain_addr_from_str(l_seller_str);
            if (!l_seller_tmp)
                return dap_json_rpc_error_add(*json_arr_reply, -61, "bad seller addr %s", l_seller_str), -61;
            l_seller = *l_seller_tmp; DAP_DELETE(l_seller_tmp);
        }
        l_json_reply = json_object_new_object();
        json_object *l_arr = json_object_new_array();

        dap_time_t l_now_ts = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        if ( s_dex_cache_enabled ) {
            if ( l_seller_str ) {
                const char *l_limit_str = NULL, *l_offset_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-limit", &l_limit_str);
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-offset", &l_offset_str);
                int l_limit = l_limit_str ? atoi(l_limit_str) : 0, l_offset = l_offset_str ? atoi(l_offset_str) : 0; // 0 = no limit
                pthread_rwlock_rdlock(&s_dex_cache_rwlock);
                dex_seller_index_t *l_seller_bucket = NULL; HASH_FIND(hh, s_dex_seller_index, &l_seller, sizeof(l_seller), l_seller_bucket);
                if (l_seller_bucket && l_seller_bucket->entries) {
                    dex_order_cache_entry_t *e, *tmp; HASH_ITER(hh_seller_bucket, l_seller_bucket->entries, e, tmp) {
                        if (e->ts_expires && l_now_ts > e->ts_expires) continue;
                        if (dap_strcmp(e->pair_key_ptr->sell_token, l_quote) || dap_strcmp(e->pair_key_ptr->buy_token, l_base)) continue;
                        if (l_offset-- > 0) continue;
                        json_object *o = json_object_new_object();
                        json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&e->level.match.root)));
                        json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&e->level.match.tail)));
                        json_object_object_add(o, "price", json_object_new_string(dap_uint256_to_char_ex(e->level.match.rate).frac));
                        json_object_object_add(o, "value_sell", json_object_new_string(dap_uint256_to_char_ex(e->level.match.value).frac));
                        json_object_array_add(l_arr,o);
                        if (--l_limit == 0) break;
                    }
                }
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
            } else {
                dex_pair_key_t l_key = { .sell_net_id = l_net->pub.id, .buy_net_id = l_net->pub.id };
                dap_strncpy(l_key.sell_token, l_quote, sizeof(l_key.sell_token) - 1);
                dap_strncpy(l_key.buy_token, l_base, sizeof(l_key.buy_token) - 1);
                pthread_rwlock_rdlock(&s_dex_cache_rwlock);
                dex_pair_index_t *l_pair_bucket = NULL; HASH_FIND(hh, s_dex_pair_index, &l_key, sizeof(l_key), l_pair_bucket);
                if ( l_pair_bucket ) {
                    dex_order_cache_entry_t *l_entry = NULL;
                    HASH_ITER(hh_pair_bucket, l_pair_bucket->asks, l_entry, l_entry) {
                        if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires)
                            continue;
                        json_object *o = json_object_new_object();
                        json_object_object_add(o, "side", json_object_new_string("ASK"));
                        json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&l_entry->level.match.root)));
                        json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&l_entry->level.match.tail)));
                        json_object_object_add(o, "price", json_object_new_string(dap_uint256_to_char_ex(l_entry->level.match.rate).frac));
                        json_object_object_add(o, "value_sell", json_object_new_string(dap_uint256_to_char_ex(l_entry->level.match.value).frac));
                        json_object_array_add(l_arr, o);
                    }
                    dex_order_cache_entry_t *l_bids_last = HASH_LAST_EX(hh_pair_bucket, l_pair_bucket->bids);
                    for (l_entry = l_bids_last; l_entry; l_entry = (dex_order_cache_entry_t*)l_entry->hh_pair_bucket.prev) {
                        if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires) continue;
                        json_object *o = json_object_new_object();
                        json_object_object_add(o, "side", json_object_new_string("BID"));
                        json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&l_entry->level.match.root)));
                        json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&l_entry->level.match.tail)));
                        json_object_object_add(o, "price", json_object_new_string(dap_uint256_to_char_ex(l_entry->level.match.rate).frac));
                        json_object_object_add(o, "value_sell", json_object_new_string(dap_uint256_to_char_ex(l_entry->level.match.value).frac));
                        json_object_array_add(l_arr, o);
                    }
                } else
                    json_object_object_add(l_json_reply, "error", json_object_new_string("no orders"));
            }
        // Fallback to ledger scanner
        } else {
            dap_chain_tx_out_cond_t *l_out_cond = NULL;
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            for ( dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it) ) {
                int l_out_idx = 0;
                l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                if ( !l_out_cond || /* dap_ledger_tx_is_used_out_item(l_ledger, it, l_out_idx, NULL) */ // FASTER, BUT UNSAFE DUE TO RACES ON LEDGER_ITEMS! 
                    dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL) )
                    continue;
                if ( l_out_cond->header.ts_expires && l_now_ts > l_out_cond->header.ts_expires )
                    continue;
                if ( l_seller_str && !dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_seller) )
                    continue;
                const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &it->cur_hash);
                if (!l_sell_tok) continue;
                dex_pair_key_t l_key_o = { };
                uint8_t l_side_o = 0;
                uint256_t l_price = { };
                s_pair_normalize(l_sell_tok, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token, l_out_cond->subtype.srv_dex.buy_net_id,
                            l_out_cond->subtype.srv_dex.rate, &l_key_o, &l_side_o, &l_price);
                // Filter: normalized key has SELL=QUOTE, BUY=BASE; our l_sell=BASE, l_buy=QUOTE
                if ( strcmp(l_key_o.sell_token, l_quote) || strcmp(l_key_o.buy_token, l_base)
                    || l_key_o.sell_net_id.uint64 != l_net->pub.id.uint64 || l_key_o.buy_net_id.uint64 != l_net->pub.id.uint64 )
                    continue;
                json_object *o = json_object_new_object();
                json_object_object_add(o, "side", json_object_new_string(l_side_o ? "BID" : "ASK"));
                json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash) ? &it->cur_hash : &l_out_cond->subtype.srv_dex.order_root_hash)));
                json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&it->cur_hash)));
                json_object_object_add(o, "price", json_object_new_string(dap_uint256_to_char_ex(l_price).frac));
                json_object_object_add(o, "value_sell", json_object_new_string(dap_uint256_to_char_ex(l_out_cond->header.value).frac));
                json_object_array_add(l_arr, o);
            }
            dap_ledger_datum_iter_delete(it);
        }
        json_object_object_add(l_json_reply,"orders",l_arr);
    } break; // ORDERS

    case CMD_ORDERBOOK: {
        const char *l_base, *l_quote; PAIR_CANON_SIMPL(l_base, l_quote);
        const char *l_depth_str = NULL, *l_tick_price_str = NULL, *l_tick_dec_str = NULL;
        int l_depth = 20;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-depth", &l_depth_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tick_price", &l_tick_price_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tick", &l_tick_dec_str);
        bool l_cumul = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "cumulative") >= l_arg_index;

        if (l_depth_str) {
            l_depth = atoi(l_depth_str);
            if (l_depth < 1) l_depth = 1;
            else if (l_depth > 1000) l_depth = 1000; // depth cap
        } else
            l_depth = 20;
        
        uint256_t l_step = uint256_0; bool l_has_step = false;
        // Tick step: either explicit price step or derived from decimals
        if (l_tick_price_str) {
            l_step = dap_chain_coins_to_balance(l_tick_price_str);
            l_has_step = !IS_ZERO_256(l_step);
        } else if (l_tick_dec_str) {
            int l_decml = atoi(l_tick_dec_str);
            if (l_decml < 0) l_decml = 0;
            else if (l_decml > 18) l_decml = 18;
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

        // Bin helper: floor price to nearest multiple of step
#define BIN_PRICE(p) ({ !l_has_step ? p : ({ uint256_t q = { }; DIV_256(p, l_step, &q); MULT_256_256(q, l_step, &q); q; }); })
        dap_time_t l_now_ts = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        if ( s_dex_cache_enabled ) {
            dex_pair_key_t key = { .sell_net_id = l_net->pub.id, .buy_net_id = l_net->pub.id };
            dap_strncpy(key.sell_token, l_quote, sizeof(key.sell_token) - 1);
            dap_strncpy(key.buy_token, l_base, sizeof(key.buy_token) - 1);
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            dex_pair_index_t *l_pair_bucket = NULL; HASH_FIND(hh, s_dex_pair_index, &key, sizeof(key), l_pair_bucket);
            if ( l_pair_bucket) {
                dex_order_cache_entry_t *l_entry = NULL;
                HASH_ITER(hh_pair_bucket, l_pair_bucket->asks, l_entry, l_entry) {
                    if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires) continue;
                    uint256_t l_bin_pair = BIN_PRICE(l_entry->level.match.rate);
                    if (l_has_step && l_ask_stop_set && compare256(l_bin_pair, l_ask_stop_price) > 0)
                        break;
                    dex_orderbook_level_t *l_lvl = NULL; HASH_FIND(hh, l_asks_tbl, &l_bin_pair, sizeof(l_bin_pair), l_lvl);
                    if ( !l_lvl ) {
                        l_lvl = DAP_NEW_Z(dex_orderbook_level_t);
                        l_lvl->price = l_bin_pair;
                        HASH_ADD(hh, l_asks_tbl, price, sizeof(l_lvl->price), l_lvl);
                        l_asks_bins_count++;
                        if ( l_has_step && !l_ask_stop_set && l_asks_bins_count == l_depth ) {
                            l_ask_stop_price = l_bin_pair;
                            l_ask_stop_set = true;
                        }
                    }
                    SUM_256_256(l_lvl->vol_base, l_entry->level.match.value, &l_lvl->vol_base);
                    uint256_t l_add_q = { };
                    MULT_256_COIN(l_entry->level.match.value, l_entry->level.match.rate, &l_add_q);
                    SUM_256_256(l_lvl->vol_quote, l_add_q, &l_lvl->vol_quote);
                    l_lvl->orders++;
                }
                dex_order_cache_entry_t *l_bids_last = HASH_LAST_EX(hh_pair_bucket, l_pair_bucket->bids);
                for (l_entry = l_bids_last; l_entry; l_entry = (dex_order_cache_entry_t*)l_entry->hh_pair_bucket.prev) {
                    if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires) continue;
                    uint256_t l_bin_pair = BIN_PRICE(l_entry->level.match.rate);
                    if (l_has_step && l_bid_stop_set && compare256(l_bin_pair, l_bid_stop_price) < 0)
                        break;
                    dex_orderbook_level_t *l_lvl = NULL; HASH_FIND(hh, l_bids_tbl, &l_bin_pair, sizeof(l_bin_pair), l_lvl);
                    if (!l_lvl) {
                        l_lvl = DAP_NEW_Z(dex_orderbook_level_t);
                        l_lvl->price = l_bin_pair;
                        HASH_ADD(hh, l_bids_tbl, price, sizeof(l_lvl->price), l_lvl);
                        l_bids_bins_count++;
                        if ( l_has_step && !l_bid_stop_set && l_bids_bins_count == l_depth ) {
                            l_bid_stop_price = l_bin_pair;
                            l_bid_stop_set = true;
                        }
                    }
                    SUM_256_256(l_lvl->vol_quote, l_entry->level.match.value, &l_lvl->vol_quote);
                    uint256_t l_add_b = { };
                    DIV_256_COIN(l_entry->level.match.value, l_entry->level.match.rate, &l_add_b);
                    SUM_256_256(l_lvl->vol_base, l_add_b, &l_lvl->vol_base);
                    l_lvl->orders++;
                }
            }
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
        } else {
            dap_chain_tx_out_cond_t *l_out_cond = NULL;
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            for ( dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it) ) {
                int l_out_idx = 0;
                l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                if ( !l_out_cond || /* dap_ledger_tx_is_used_out_item(l_ledger, it, l_out_idx, NULL) */ // FASTER, BUT UNSAFE DUE TO RACES ON LEDGER_ITEMS! 
                    dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL) )
                    continue;
                if ( l_out_cond->header.ts_expires && l_now_ts > l_out_cond->header.ts_expires )
                    continue;
                const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &it->cur_hash);
                if (!l_sell_tok) continue;
                dex_pair_key_t l_key_o = { };
                uint8_t l_side_o = 0;
                uint256_t l_price = { };
                s_pair_normalize(l_sell_tok, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token, l_out_cond->subtype.srv_dex.buy_net_id,
                                l_out_cond->subtype.srv_dex.rate, &l_key_o, &l_side_o, &l_price);
                if (dap_strcmp(l_key_o.sell_token, l_quote) || dap_strcmp(l_key_o.buy_token, l_base))
                    continue;
                uint256_t l_bin_pair = BIN_PRICE(l_price);
                dex_orderbook_level_t *l_lvl = NULL;
                if ( l_side_o == DEX_SIDE_ASK ) {
                    HASH_FIND(hh, l_asks_tbl, &l_bin_pair, sizeof(l_bin_pair), l_lvl);
                    if (!l_lvl) {
                        l_lvl = DAP_NEW_Z(dex_orderbook_level_t);
                        l_lvl->price = l_bin_pair;
                        HASH_ADD(hh, l_asks_tbl, price, sizeof(l_lvl->price), l_lvl);
                    }
                    SUM_256_256(l_lvl->vol_base,l_out_cond->header.value,&l_lvl->vol_base);
                    uint256_t l_add_quote; MULT_256_COIN(l_out_cond->header.value,l_price,&l_add_quote);
                    SUM_256_256(l_lvl->vol_quote,l_add_quote,&l_lvl->vol_quote);
                } else {
                    HASH_FIND(hh, l_bids_tbl, &l_bin_pair, sizeof(l_bin_pair), l_lvl);
                    if (!l_lvl) {
                        l_lvl = DAP_NEW_Z(dex_orderbook_level_t);
                        l_lvl->price = l_bin_pair;
                        HASH_ADD(hh, l_bids_tbl, price, sizeof(l_lvl->price), l_lvl);
                    }
                    SUM_256_256(l_lvl->vol_quote,l_out_cond->header.value,&l_lvl->vol_quote);
                    uint256_t l_add_base; DIV_256_COIN(l_out_cond->header.value,l_price,&l_add_base);
                    SUM_256_256(l_lvl->vol_base,l_add_base,&l_lvl->vol_base);
                }
                ++l_lvl->orders;
            }
            dap_ledger_datum_iter_delete(it);
        }
#undef BIN_PRICE
        // sort
        HASH_SORT(l_asks_tbl, s_cmp_agg_level_price_asc);
        HASH_SORT(l_bids_tbl, s_cmp_agg_level_price_desc);
        // emit
        l_json_reply = json_object_new_object();
        json_object *l_arr_asks = json_object_new_array(), *l_arr_bids = json_object_new_array();
        json_object_object_add(l_json_reply, "last_update_ts", json_object_new_uint64(dap_ledger_get_blockchain_time(l_net->pub.ledger)));
        json_object_object_add(l_json_reply, "request_ts", json_object_new_uint64(dap_time_now()));

        // Best prices (first entries after sorting)
        if (l_asks_tbl) { json_object_object_add(l_json_reply, "best_ask", json_object_new_string(dap_uint256_to_char_ex(l_asks_tbl->price).frac)); }
        if (l_bids_tbl) { json_object_object_add(l_json_reply, "best_bid", json_object_new_string(dap_uint256_to_char_ex(l_bids_tbl->price).frac)); }
        if (l_asks_tbl && l_bids_tbl) { 
            uint256_t l_mid = { }, l_spread = { }, l_sum = { };
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
        dex_orderbook_level_t *l_iter = NULL, *l_tmp; HASH_ITER(hh, l_asks_tbl, l_iter, l_tmp) { 
                json_object *o = json_object_new_object();
            json_object_object_add(o, "price", json_object_new_string(dap_uint256_to_char_ex(l_iter->price).frac));
            json_object_object_add(o, "volume_base", json_object_new_string(dap_uint256_to_char_ex(l_iter->vol_base).frac));
            json_object_object_add(o, "volume_quote", json_object_new_string(dap_uint256_to_char_ex(l_iter->vol_quote).frac));
            json_object_object_add(o, "orders", json_object_new_int((int)l_iter->orders));
            if (l_cumul){
                SUM_256_256(l_cumul_base,l_iter->vol_base,&l_cumul_base); SUM_256_256(l_cumul_quote, l_iter->vol_quote, &l_cumul_quote);
                json_object_object_add(o, "cum_base", json_object_new_string(dap_uint256_to_char_ex(l_cumul_base).frac));
                json_object_object_add(o, "cum_quote", json_object_new_string(dap_uint256_to_char_ex(l_cumul_quote).frac));
            }
            json_object_array_add(l_arr_asks,o);
            HASH_DEL(l_asks_tbl, l_iter);
            DAP_DELETE(l_iter);
            if (++l_count > l_depth) break;
        }
        // Emit bids side (descending prices); cumulative if requested
        l_cumul_base = uint256_0, l_cumul_quote = uint256_0;
        l_count = 0;
        HASH_ITER(hh, l_bids_tbl, l_iter, l_tmp) {
            json_object *o = json_object_new_object();
            json_object_object_add(o, "price", json_object_new_string(dap_uint256_to_char_ex(l_iter->price).frac));
            json_object_object_add(o, "volume_base", json_object_new_string(dap_uint256_to_char_ex(l_iter->vol_base).frac));
            json_object_object_add(o, "volume_quote", json_object_new_string(dap_uint256_to_char_ex(l_iter->vol_quote).frac));
            json_object_object_add(o, "orders", json_object_new_int((int)l_iter->orders));
            if (l_cumul){
                SUM_256_256(l_cumul_base,l_iter->vol_base,&l_cumul_base); SUM_256_256(l_cumul_quote,l_iter->vol_quote,&l_cumul_quote);
                json_object_object_add(o, "cum_base", json_object_new_string(dap_uint256_to_char_ex(l_cumul_base).frac));
                json_object_object_add(o, "cum_quote", json_object_new_string(dap_uint256_to_char_ex(l_cumul_quote).frac));
            }
            json_object_array_add(l_arr_bids,o);
            HASH_DEL(l_bids_tbl, l_iter);
            DAP_DELETE(l_iter);
            if (++l_count > l_depth) break;
        }
        // free
        if (l_asks_tbl) { HASH_ITER(hh, l_asks_tbl, l_iter, l_tmp) { HASH_DELETE(hh, l_asks_tbl, l_iter); DAP_DELETE(l_iter); } }
        if (l_bids_tbl) { HASH_ITER(hh, l_bids_tbl, l_iter, l_tmp) { HASH_DELETE(hh, l_bids_tbl, l_iter); DAP_DELETE(l_iter); } }
        json_object_object_add(l_json_reply,"pair",json_object_new_string(l_pair_str));
        json_object_object_add(l_json_reply,"asks",l_arr_asks);
        json_object_object_add(l_json_reply,"bids",l_arr_bids);
        s_add_units(l_json_reply, l_base, l_quote);
    } break; // ORDERBOOK

    case CMD_STATUS: {
        const char *l_base, *l_quote; PAIR_CANON_SIMPL(l_base, l_quote);
        const char *l_seller_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-seller", &l_seller_str);
        dap_chain_addr_t l_seller;
        if (l_seller_str) {
            dap_chain_addr_t *l_seller_tmp = dap_chain_addr_from_str(l_seller_str);
            if (!l_seller_tmp)
                return dap_json_rpc_error_add(*json_arr_reply, -61, "bad seller addr %s", l_seller_str), -61;
            l_seller = *l_seller_tmp; DAP_DELETE(l_seller_tmp);
        }

        uint32_t l_asks_cnt = 0, l_bids_cnt = 0;
        uint256_t l_best_ask = uint256_0, l_best_bid_inv = uint256_0;
        bool l_has_ask = false, l_has_bid = false;
        dap_time_t l_now_ts = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        if (s_dex_cache_enabled) {
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            if ( l_seller_str ) {
                dex_seller_index_t *l_sb = NULL; HASH_FIND(hh, s_dex_seller_index, &l_seller, sizeof(l_seller), l_sb);
                if (l_sb && l_sb->entries) {
                    dex_order_cache_entry_t *e = NULL, *tmp; HASH_ITER(hh_seller_bucket, l_sb->entries, e, tmp) {
                        if (e->ts_expires && l_now_ts > e->ts_expires) continue;
                        if (dap_strcmp(e->pair_key_ptr->sell_token, l_quote) || dap_strcmp(e->pair_key_ptr->buy_token, l_base)) continue;
                        if ((e->side_version & 0x1) == DEX_SIDE_ASK) {
                            if (!l_has_ask || compare256(e->level.match.rate, l_best_ask) < 0) { l_best_ask = e->level.match.rate; l_has_ask = true; }
                            l_asks_cnt++;
                        } else {
                            if (!l_has_bid || compare256(e->level.match.rate, l_best_bid_inv) > 0) { l_best_bid_inv = e->level.match.rate; l_has_bid = true; }
                            l_bids_cnt++;
                        }
                    }
                }
            } else {
                dex_pair_key_t l_key = { .sell_net_id = l_net->pub.id, .buy_net_id = l_net->pub.id };
                dap_strncpy(l_key.sell_token, l_quote, sizeof(l_key.sell_token)-1);
                dap_strncpy(l_key.buy_token, l_base, sizeof(l_key.buy_token)-1);
                dex_pair_index_t *l_pair_bucket = NULL; HASH_FIND(hh, s_dex_pair_index, &l_key, sizeof(l_key), l_pair_bucket);
                if (l_pair_bucket) {
                    dex_order_cache_entry_t *l_entry;
                    for (l_entry = l_pair_bucket->asks; l_entry; l_entry = (dex_order_cache_entry_t*)l_entry->hh_pair_bucket.next) {
                        if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires) continue;
                        if (!l_has_ask) { l_best_ask = l_entry->level.match.rate; l_has_ask = true; }
                        l_asks_cnt++;
                    }
                    dex_order_cache_entry_t *l_last_bid = HASH_LAST_EX(hh_pair_bucket, l_pair_bucket->bids);
                    for (l_entry = l_last_bid; l_entry; l_entry = (dex_order_cache_entry_t*)l_entry->hh_pair_bucket.prev) {
                        if (l_entry->ts_expires && l_now_ts > l_entry->ts_expires) continue;
                        if (!l_has_bid) { l_best_bid_inv = l_entry->level.match.rate; l_has_bid = true; }
                        l_bids_cnt++;
                    }
                }
            }
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
        } else {
            dap_chain_tx_out_cond_t *l_out_cond = NULL;
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            for ( dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it) ) {
                int l_out_idx = 0;
                l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                if ( !l_out_cond || /* dap_ledger_tx_is_used_out_item(l_ledger, it, l_out_idx, NULL) */ // FASTER, BUT UNSAFE DUE TO RACES ON LEDGER_ITEMS! 
                    dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL) )
                    continue;
                if ( l_out_cond->header.ts_expires && l_now_ts > l_out_cond->header.ts_expires )
                    continue;
                if ( l_seller_str && !dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_seller) )
                    continue;
                const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &it->cur_hash);
                if (!l_sell_tok) continue;
                dex_pair_key_t l_key_o = { };
                uint8_t l_side_o = 0;
                uint256_t l_price = { };
                s_pair_normalize(l_sell_tok, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token, l_out_cond->subtype.srv_dex.buy_net_id,
                                l_out_cond->subtype.srv_dex.rate, &l_key_o, &l_side_o, &l_price);
                if (dap_strcmp(l_key_o.sell_token, l_quote) || dap_strcmp(l_key_o.buy_token, l_base))
                    continue;
                if (l_side_o == DEX_SIDE_ASK) {
                    if (!l_has_ask || compare256(l_price, l_best_ask) < 0) { l_best_ask = l_price; l_has_ask = true; }
                    l_asks_cnt++;
                } else {
                    if (!l_has_bid || compare256(l_price, l_best_bid_inv) > 0) { l_best_bid_inv = l_price; l_has_bid = true; }
                    l_bids_cnt++;
                }
            }
            dap_ledger_datum_iter_delete(it);
        }

        l_json_reply = json_object_new_object();
        json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_str));
        json_object_object_add(l_json_reply, "asks", json_object_new_int((int)l_asks_cnt));
        json_object_object_add(l_json_reply, "bids", json_object_new_int((int)l_bids_cnt));
        json_object_object_add(l_json_reply, "count", json_object_new_int((int)(l_asks_cnt + l_bids_cnt)));
        if (l_has_ask) json_object_object_add(l_json_reply, "best_ask", json_object_new_string(dap_uint256_to_char_ex(l_best_ask).frac));
        if (l_has_bid) json_object_object_add(l_json_reply, "best_bid", json_object_new_string(dap_uint256_to_char_ex(l_best_bid_inv).frac));
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
        if (!l_token) return dap_json_rpc_error_add(*json_arr_reply, -80, "missing -token"), -80;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-by", &l_by_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-top", &l_top_str);
        
        int l_topN = l_top_str ? atoi(l_top_str) : 0; if (l_topN > 1000) l_topN = 1000;
        uint256_t l_sum = uint256_0;
        dap_time_t l_now_ts = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        l_tvl_pair_sum_t *l_pair_sums = NULL;
        if ( s_dex_cache_enabled ) {
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            for (dex_pair_index_t *l_pb = s_dex_pair_index; l_pb; l_pb = (dex_pair_index_t*)l_pb->hh.next) {
                // asks sell BASE; index key stores SELL=QUOTE, BUY=BASE → BASE=key.buy_token
                if ( !dap_strcmp(l_pb->key.sell_token, l_token) ) {
                    for (dex_order_cache_entry_t *e = l_pb->asks; e; e = (dex_order_cache_entry_t*)e->hh_pair_bucket.next) {
                        if ( e->ts_expires && l_now_ts > e->ts_expires ) continue;
                        SUM_256_256(l_sum, e->level.match.value, &l_sum);
                        if (l_by_str && !dap_strcmp(l_by_str, "pair")) {
                            char l_key_buf[TVL_PAIR_LEN] = {0};
                            // Emit pair as BASE/QUOTE → key.buy_token/key.sell_token
                            snprintf(l_key_buf, sizeof(l_key_buf), "%s/%s", l_pb->key.buy_token, l_pb->key.sell_token);
                            l_tvl_pair_sum_t *l_ps = NULL; HASH_FIND_STR(l_pair_sums, l_key_buf, l_ps);
                            if (!l_ps) {
                                l_ps = DAP_NEW_Z(l_tvl_pair_sum_t);
                                dap_strncpy(l_ps->pair, l_key_buf, sizeof(l_ps->pair)-1);
                                HASH_ADD_STR(l_pair_sums, pair, l_ps);
                            }
                            SUM_256_256(l_ps->tvl, e->level.match.value, &l_ps->tvl);
                        }
                    }
                }
                // bids sell QUOTE; BASE/QUOTE string uses key.buy_token/key.sell_token
                if (!dap_strcmp(l_pb->key.buy_token, l_token)) {
                    for (dex_order_cache_entry_t *e = l_pb->bids; e; e = (dex_order_cache_entry_t*)e->hh_pair_bucket.next) {
                        if ( e->ts_expires && l_now_ts > e->ts_expires ) continue;
                        SUM_256_256(l_sum, e->level.match.value, &l_sum);
                        if (l_by_str && !dap_strcmp(l_by_str, "pair")) {
                            char l_key_buf[TVL_PAIR_LEN] = {0};
                            snprintf(l_key_buf, sizeof(l_key_buf), "%s/%s", l_pb->key.buy_token, l_pb->key.sell_token);
                            l_tvl_pair_sum_t *l_ps = NULL; HASH_FIND_STR(l_pair_sums, l_key_buf, l_ps);
                            if (!l_ps) {
                                l_ps = DAP_NEW_Z(l_tvl_pair_sum_t);
                                dap_strncpy(l_ps->pair, l_key_buf, sizeof(l_ps->pair)-1);
                                HASH_ADD_STR(l_pair_sums, pair, l_ps);
                            }
                            SUM_256_256(l_ps->tvl, e->level.match.value, &l_ps->tvl);
                        }
                    }
                }
            }
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
        } else {
            // Ledger fallback: sum active unspent SRV_DEX outs that sell <token>
            dap_chain_tx_out_cond_t *l_out_cond = NULL;
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            for ( dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it) ) {
                int l_out_idx = 0;
                l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                if (!l_out_cond || dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL))
                    continue;
                if (l_out_cond->header.ts_expires && l_now_ts > l_out_cond->header.ts_expires)
                    continue;
                const char *l_sell_tok_tx = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &it->cur_hash);
                if (!l_sell_tok_tx) continue;
                if (!dap_strcmp(l_sell_tok_tx, l_token)) {
                    SUM_256_256(l_sum, l_out_cond->header.value, &l_sum);
                    if (l_by_str && !dap_strcmp(l_by_str, "pair")) {
                        dex_pair_key_t l_key_o = { };
                        uint8_t l_side_o = 0;
                        uint256_t l_price_o = uint256_0;
                        s_pair_normalize(l_sell_tok_tx, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                                         l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key_o, &l_side_o, &l_price_o);
                        char l_key_buf[TVL_PAIR_LEN];
                        // Emit pair as BASE/QUOTE → l_key_o.buy_token/l_key_o.sell_token
                        snprintf(l_key_buf, sizeof(l_key_buf), "%s/%s", l_key_o.buy_token, l_key_o.sell_token);
                        l_tvl_pair_sum_t *l_ps = NULL; HASH_FIND_STR(l_pair_sums, l_key_buf, l_ps);
                        if (!l_ps) {
                            l_ps = DAP_NEW_Z(l_tvl_pair_sum_t);
                            dap_strncpy(l_ps->pair, l_key_buf, sizeof(l_ps->pair)-1);
                            HASH_ADD_STR(l_pair_sums, pair, l_ps);
                        }
                        SUM_256_256(l_ps->tvl, l_out_cond->header.value, &l_ps->tvl);
                    }
                }
            }
            dap_ledger_datum_iter_delete(it);
        }
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
            for (l_tvl_pair_sum_t *l_ps = l_pair_sums; l_ps && (!l_topN || l_emitted < l_topN); l_ps = (l_tvl_pair_sum_t*)l_ps->hh.next, ++l_emitted) {
                json_object *o = json_object_new_object();
                json_object_object_add(o, "pair", json_object_new_string(l_ps->pair));
                json_object_object_add(o, "tvl", json_object_new_string(dap_uint256_to_char_ex(l_ps->tvl).frac));
                json_object_array_add(l_jarr, o);
            }
            l_tvl_pair_sum_t *l_cur, *l_tmp;
            HASH_ITER(hh, l_pair_sums, l_cur, l_tmp) {
                HASH_DELETE(hh, l_pair_sums, l_cur);
                DAP_DELETE(l_cur);
            }
            json_object_object_add(l_json_reply, "by_pair", l_jarr);
        }
    } break; // TVL
    
    case CMD_SPREAD: {
        const char *l_base, *l_quote; PAIR_CANON_SIMPL(l_base, l_quote);
        bool l_verbose = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-verbose") >= l_arg_index;
        uint256_t l_best_ask = uint256_0, l_best_bid_inv = uint256_0;
        bool l_has_ask = false, l_has_bid = false;
        dap_hash_fast_t l_best_ask_root = {0}, l_best_ask_tail = {0}, l_best_bid_root = {0}, l_best_bid_tail = {0};
        dap_time_t l_now_ts = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        if (s_dex_cache_enabled) {
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            dex_pair_key_t l_key = (dex_pair_key_t){ .sell_net_id = l_net->pub.id, .buy_net_id = l_net->pub.id };
            dap_strncpy(l_key.sell_token, l_quote, sizeof(l_key.sell_token)-1);
            dap_strncpy(l_key.buy_token, l_base, sizeof(l_key.buy_token)-1);
            dex_pair_index_t *l_pb = NULL; HASH_FIND(hh, s_dex_pair_index, &l_key, sizeof(l_key), l_pb);
            if (l_pb) {
                for (dex_order_cache_entry_t *e = l_pb->asks; e; e = (dex_order_cache_entry_t*)e->hh_pair_bucket.next) {
                    if (e->ts_expires && l_now_ts > e->ts_expires) continue;
                    l_best_ask = e->level.match.rate; l_has_ask = true;
                    if (l_verbose) {
                        l_best_ask_root = e->level.match.root; l_best_ask_tail = e->level.match.tail;
                    } break;
                }
                dex_order_cache_entry_t *l_last_bid = HASH_LAST_EX(hh_pair_bucket, l_pb->bids);
                for (dex_order_cache_entry_t *e = l_last_bid; e; e = (dex_order_cache_entry_t*)e->hh_pair_bucket.prev) {
                    if (e->ts_expires && l_now_ts > e->ts_expires) continue;
                    l_best_bid_inv = e->level.match.rate; l_has_bid = true;
                    if (l_verbose) {
                        l_best_bid_root = e->level.match.root; l_best_bid_tail = e->level.match.tail;
                     } break;
                }
            }
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
        } else {
            // Ledger fallback: scan best ask/bid for the pair
            dap_chain_tx_out_cond_t *l_out_cond = NULL;
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            for ( dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it) ) {
                int l_out_idx = 0;
                l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                if (!l_out_cond) continue;
                if (dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL)) continue;
                if (l_out_cond->header.ts_expires && l_now_ts > l_out_cond->header.ts_expires) continue;
                const char *l_sell_tok_tx = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &it->cur_hash);
                if (!l_sell_tok_tx) continue;
                dex_pair_key_t l_key = (dex_pair_key_t){ };
                uint8_t l_side = 0;
                uint256_t l_price = uint256_0;
                s_pair_normalize(l_sell_tok_tx, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                     l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key, &l_side, &l_price);
                if ( dap_strcmp(l_key.sell_token, l_quote) || dap_strcmp(l_key.buy_token, l_base) ) continue;
                if (l_side == DEX_SIDE_ASK) {
                    if (!l_has_ask || compare256(l_price, l_best_ask) < 0) {
                        l_best_ask = l_price; l_has_ask = true;
                        l_best_ask_root = l_out_cond->subtype.srv_dex.order_root_hash;
                        l_best_ask_tail = it->cur_hash;
                    }
                } else {
                    if (!l_has_bid || compare256(l_price, l_best_bid_inv) > 0) {
                        l_best_bid_inv = l_price; l_has_bid = true; 
                        l_best_bid_root = l_out_cond->subtype.srv_dex.order_root_hash;
                        l_best_bid_tail = it->cur_hash;
                    }
                }
            }
            dap_ledger_datum_iter_delete(it);
        }

        l_json_reply = json_object_new_object();
        json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_str));
        if (l_has_ask && l_has_bid) {
            uint256_t l_spread = l_best_ask;
            SUBTRACT_256_256(l_spread, l_best_bid_inv, &l_spread);
            json_object_object_add(l_json_reply, "best_ask", json_object_new_string(dap_uint256_to_char_ex(l_best_ask).frac));
            json_object_object_add(l_json_reply, "best_bid", json_object_new_string(dap_uint256_to_char_ex(l_best_bid_inv).frac));
            json_object_object_add(l_json_reply, "spread", json_object_new_string(dap_uint256_to_char_ex(l_spread).frac));
            if (l_verbose) {
                json_object_object_add(l_json_reply, "best_ask_root", json_object_new_string(dap_hash_fast_to_str_static(&l_best_ask_root)));
                json_object_object_add(l_json_reply, "best_ask_tail", json_object_new_string(dap_hash_fast_to_str_static(&l_best_ask_tail)));
                json_object_object_add(l_json_reply, "best_bid_root", json_object_new_string(dap_hash_fast_to_str_static(&l_best_bid_root)));
                json_object_object_add(l_json_reply, "best_bid_tail", json_object_new_string(dap_hash_fast_to_str_static(&l_best_bid_tail)));
            }
        } else
            json_object_object_add(l_json_reply, "error", json_object_new_string("not enough asks/bids"));
    } break; // SPREAD

    case CMD_HISTORY: {
        const char *l_from_str = NULL, *l_to_str = NULL, *l_bucket_str = NULL, *l_mode_str = NULL, *l_fill_str = NULL;
        const char *l_base, *l_quote; PAIR_CANON_SIMPL(l_base, l_quote);
        const char *l_seller_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-seller", &l_seller_str);
        dap_chain_addr_t l_seller;
        if (l_seller_str) {
            dap_chain_addr_t *l_seller_tmp = dap_chain_addr_from_str(l_seller_str);
            if (!l_seller_tmp)
                return dap_json_rpc_error_add(*json_arr_reply, -61, "bad seller addr %s", l_seller_str), -61;
            l_seller = *l_seller_tmp; DAP_DELETE(l_seller_tmp);
        }
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-from", &l_from_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-to", &l_to_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-bucket", &l_bucket_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-mode", &l_mode_str);
        bool l_fill_missing = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-fill") >= l_arg_index;

        uint64_t l_t_from = 0, l_t_to = 0;
        if ( l_from_str && !s_parse_natural_time(l_net->pub.ledger, l_from_str, &l_t_from) )
            l_t_from = strtoull(l_from_str, NULL, 10);
        if ( l_to_str && !s_parse_natural_time(l_net->pub.ledger, l_to_str, &l_t_to) )
            l_t_to = strtoull(l_to_str, NULL, 10);
        if ( l_t_from && l_t_to && l_t_to < l_t_from ) { uint64_t t = l_t_from; l_t_from = l_t_to; l_t_to = t; }

        uint64_t l_bucket = l_bucket_str ? strtoull(l_bucket_str, NULL, 10) : 0ULL;

        bool l_want_ohlc;
        if (!l_mode_str) l_want_ohlc = true;
        else if (!dap_strcmp(l_mode_str, "volume_only")) l_want_ohlc = false;
        else return dap_json_rpc_error_add(*json_arr_reply, -61, "bad mode %s", l_mode_str), -61;

        l_json_reply = json_object_new_object();
        json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_str));
        json_object_object_add(l_json_reply, "request_ts", json_object_new_int64((int64_t)dap_time_now()));

        if (s_dex_history_enabled && l_bucket) {
            json_object *l_arr = json_object_new_array();
            dex_history_ctx_t l_ctx = { .arr = l_arr, .bucket_sec = l_bucket, .fill_missing = !!l_fill_missing, .with_ohlc = !!l_want_ohlc };
            if (l_want_ohlc) {
                if (l_seller_str) { l_ctx.ledger = l_net->pub.ledger; l_ctx.seller = &l_seller; }
                dex_pair_key_t l_key = (dex_pair_key_t){ .sell_net_id = l_net->pub.id, .buy_net_id = l_net->pub.id };
                dap_strncpy(l_key.sell_token, l_quote, sizeof(l_key.sell_token) - 1);
                dap_strncpy(l_key.buy_token,  l_base,  sizeof(l_key.buy_token)  - 1);
                dex_history_for_each_range(&l_key, l_t_from, l_t_to ? l_t_to : UINT64_MAX,
                     l_bucket, l_seller_str ? s_hist_cb_build_volume_seller : s_hist_cb_build_volume, &l_ctx);
                json_object_object_add(l_json_reply, "ohlc", l_arr);
            }
            json_object_object_add(l_json_reply, "volume", l_arr);
            json_object *l_tot = json_object_new_object();
            json_object_object_add(l_tot, "trades", json_object_new_int(l_ctx.trades));
            json_object_object_add(l_tot, "sum_base", json_object_new_string(dap_uint256_to_char_ex(l_ctx.sum_base).frac));
            json_object_object_add(l_tot, "sum_quote", json_object_new_string(dap_uint256_to_char_ex(l_ctx.sum_quote).frac));
            json_object_object_add(l_json_reply, "totals", l_tot);
        } else {
            // Ledger fallback: aggregate OHLC/volume over time window
            dex_bucket_agg_t *l_buckets = NULL;
            uint256_t l_sum_base_all = uint256_0, l_sum_quote_all = uint256_0;
            uint32_t l_trades_all = 0;
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            for ( dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it) ) {
                if (l_t_from && l_tx->header.ts_created < (dap_time_t)l_t_from) continue;
                if (l_t_to   && l_tx->header.ts_created > (dap_time_t)l_t_to) continue;
                if (!dap_chain_datum_tx_item_get(l_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL)) continue;
                dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
                if (!l_out_cond) continue;
                byte_t *l_it_in; size_t l_sz_in = 0;
                int l_dex_in_i = 0;
                TX_ITEM_ITER_TX(l_it_in, l_sz_in, l_tx) if (*l_it_in == TX_ITEM_TYPE_IN_COND) {
                    dap_chain_tx_in_cond_t *l_in = (dap_chain_tx_in_cond_t*)l_it_in;
                    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_in->header.tx_prev_hash);
                    if (!l_prev_tx) continue;
                    dap_chain_tx_out_cond_t *l_prev = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
                    if (!l_prev) continue;
                    if (l_seller_str && !dap_chain_addr_compare(&l_prev->subtype.srv_dex.seller_addr, &l_seller)) {
                        l_dex_in_i++; continue;
                    }
                    const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &l_in->header.tx_prev_hash); if (!l_sell_tok) continue;
                    dex_pair_key_t l_key = { }; uint8_t l_side = 0; uint256_t l_price_canon = uint256_0;
                    s_pair_normalize(l_sell_tok, l_prev->subtype.srv_dex.sell_net_id, l_prev->subtype.srv_dex.buy_token,
                         l_prev->subtype.srv_dex.buy_net_id, l_prev->subtype.srv_dex.rate, &l_key, &l_side, &l_price_canon);
                    if ( dap_strcmp(l_key.sell_token, l_quote) || dap_strcmp(l_key.buy_token, l_base) ) {
                        l_dex_in_i++;
                        continue;
                    }
                    if ( (l_key.sell_net_id.uint64 != l_net->pub.id.uint64 || l_key.buy_net_id.uint64 != l_net->pub.id.uint64) ) {
                        if (s_cross_net_policy == CROSS_NET_REJECT) {
                            l_dex_in_i++;
                            continue;
                        } else if (s_cross_net_policy == CROSS_NET_WARN)
                            log_it(L_WARNING, "cross-net trade seen in history scan: %s/%s", l_base, l_quote);
                    }
                    uint256_t l_executed_i = l_prev->header.value;
                    if (l_out_cond && !dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash) && l_dex_in_i == 0) {
                        dap_hash_fast_t l_root0 = dap_ledger_get_first_chain_tx_hash(l_net->pub.ledger, l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                        if (!dap_hash_fast_compare(&l_root0, &l_out_cond->subtype.srv_dex.order_root_hash))
                            if (compare256(l_prev->header.value, l_out_cond->header.value) > 0)
                                SUBTRACT_256_256(l_prev->header.value, l_out_cond->header.value, &l_executed_i);
                    }
                    uint256_t l_buy_i = uint256_0; MULT_256_COIN(l_executed_i, l_price_canon, &l_buy_i);
                    bool l_payout_i = false; byte_t *l_ito; size_t l_szo = 0;
                    TX_ITEM_ITER_TX(l_ito, l_szo, l_tx) {
                        if (*l_ito == TX_ITEM_TYPE_OUT_EXT) {
                            dap_chain_tx_out_ext_t *o = (dap_chain_tx_out_ext_t*)l_ito;
                            if ( !dap_strcmp(o->token, l_prev->subtype.srv_dex.buy_token)
                                && dap_chain_addr_compare(&o->addr, &l_prev->subtype.srv_dex.seller_addr)) {
                                l_payout_i = true;
                                break;
                            }
                        } else if (*l_ito == TX_ITEM_TYPE_OUT_STD) {
                            dap_chain_tx_out_std_t *o = (dap_chain_tx_out_std_t*)l_ito;
                            if ( !dap_strcmp(o->token, l_prev->subtype.srv_dex.buy_token)
                                && dap_chain_addr_compare(&o->addr, &l_prev->subtype.srv_dex.seller_addr)) {
                                l_payout_i = true;
                                break;
                            }
                        }
                    }
                    if (!l_payout_i) {
                        l_dex_in_i++;
                        continue;
                    }
                    dex_bq_t l_bq = EXEC_TO_CANON_BQ( l_executed_i, l_price_canon, l_side );
                    SUM_256_256(l_sum_base_all, l_bq.base, &l_sum_base_all);
                    SUM_256_256(l_sum_quote_all, l_bq.quote, &l_sum_quote_all);
                    l_trades_all++;
                    if (l_bucket) {
                        uint64_t l_ts_bucket = (uint64_t)l_tx->header.ts_created;
                        l_ts_bucket -= (l_ts_bucket % l_bucket);
                        dex_bucket_agg_t *l_ba = NULL; HASH_FIND(hh, l_buckets, &l_ts_bucket, sizeof(l_ts_bucket), l_ba);
                        if (!l_ba) {
                            l_ba = DAP_NEW_Z(dex_bucket_agg_t);
                            l_ba->ts = l_ts_bucket;
                            l_ba->first_ts = l_ba->last_ts = l_tx->header.ts_created;
                            l_ba->open = l_ba->high = l_ba->low = l_ba->close = l_price_canon;
                            HASH_ADD(hh, l_buckets, ts, sizeof(l_ba->ts), l_ba);
                        }
                        if (l_tx->header.ts_created < l_ba->first_ts) {
                            l_ba->first_ts = l_tx->header.ts_created;
                            l_ba->open = l_price_canon;
                        }
                        if (l_tx->header.ts_created >= l_ba->last_ts) {
                            l_ba->last_ts = l_tx->header.ts_created;
                            l_ba->close = l_price_canon;
                        }
                        if (compare256(l_price_canon, l_ba->high) > 0) l_ba->high = l_price_canon;
                        if (compare256(l_price_canon, l_ba->low)  < 0) l_ba->low  = l_price_canon;
                        SUM_256_256(l_ba->sum_base,  l_bq.base,  &l_ba->sum_base);
                        SUM_256_256(l_ba->sum_quote, l_bq.quote, &l_ba->sum_quote);
                        l_ba->trades++;
                    }
                    l_dex_in_i++;
                }
            }
            dap_ledger_datum_iter_delete(it);

            // Unified emit: always volume; OHLC optionally
            json_object *l_arr = json_object_new_array();
            if (l_bucket && l_buckets) {
                HASH_SORT(l_buckets, s_cmp_bucket_ts);
                uint64_t l_prev_ts = 0;
                uint256_t l_prev_close = uint256_0;
                dex_bucket_agg_t *l_cur, *l_tmp; HASH_ITER(hh, l_buckets, l_cur, l_tmp) {
                    if (l_want_ohlc && l_fill_missing && l_prev_ts) {
                        for (uint64_t t = l_prev_ts + l_bucket; t < l_cur->ts; t += l_bucket) {
                            dex_bucket_agg_t l_miss = { .ts = t, .first_ts = t, .last_ts = t + l_bucket - 1,
                                .open = l_prev_close, .high = l_prev_close, .low = l_prev_close, .close = l_prev_close };
                            s_hist_json_emit_bucket(l_arr, &l_miss, true);
                        }
                    }
                    s_hist_json_emit_bucket(l_arr, l_cur, l_want_ohlc);
                    l_prev_ts = l_cur->ts; l_prev_close = l_cur->close;
                    HASH_DEL(l_buckets, l_cur); DAP_DELETE(l_cur);
                }
            }
            // Attach outputs
            if (l_want_ohlc) json_object_object_add(l_json_reply, "ohlc", l_arr);
            json_object_object_add(l_json_reply, "volume", l_arr);
            json_object *l_tot = json_object_new_object();
            json_object_object_add(l_tot, "trades", json_object_new_int((int)l_trades_all));
            json_object_object_add(l_tot, "sum_base", json_object_new_string(dap_uint256_to_char_ex(l_sum_base_all).frac));
            json_object_object_add(l_tot, "sum_quote", json_object_new_string(dap_uint256_to_char_ex(l_sum_quote_all).frac));
            json_object_object_add(l_json_reply, "totals", l_tot);
        }
    } break; // HISTORY 

    case CMD_MARKET_RATE: {
        const char *l_base, *l_quote; PAIR_CANON_SIMPL(l_base, l_quote);
        const char *l_from_str = NULL, *l_to_str = NULL, *l_bucket_str = NULL, *l_fill_str = NULL, *l_decimals_str = NULL; 
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-from", &l_from_str); 
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-to", &l_to_str); 
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-bucket", &l_bucket_str);
        bool l_fill_missing = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-fill") >= l_arg_index;

        uint64_t l_t_from = 0, l_t_to = 0;
        if ( l_from_str && !s_parse_natural_time(l_net->pub.ledger, l_from_str, &l_t_from) )
            l_t_from = strtoull(l_from_str, NULL, 10);
        if ( l_to_str && !s_parse_natural_time(l_net->pub.ledger, l_to_str, &l_t_to) )
            l_t_to = strtoull(l_to_str, NULL, 10);
        if ( l_t_from && l_t_to && l_t_to < l_t_from ) { uint64_t t = l_t_from; l_t_from = l_t_to; l_t_to = t; }

        uint64_t l_bucket = l_bucket_str ? strtoull(l_bucket_str, NULL, 10) : 0ULL;
        if ( l_bucket && l_bucket > 365ULL*24ULL*3600ULL ) l_bucket = 365ULL*24ULL*3600ULL; 
        //int l_decN = l_decimals_str ? atoi(l_decimals_str) : -1;
        //if (l_decN > 18) l_decN = 18;

        dex_bucket_agg_t *l_buckets = NULL;
        uint256_t l_sum_quote = uint256_0, l_sum_base = uint256_0, l_last_price = uint256_0;
        bool l_have_spot = false;
        uint64_t l_spot_ts = 0; int l_trades = 0;
        if (s_dex_history_enabled && l_bucket) {
            // VOLUME-only path: visual order BASE/QUOTE
            dex_pair_key_t l_key = (dex_pair_key_t){ .sell_net_id = l_net->pub.id, .buy_net_id = l_net->pub.id };
            dap_strncpy(l_key.sell_token, l_base,  sizeof(l_key.sell_token)  - 1);
            dap_strncpy(l_key.buy_token,  l_quote, sizeof(l_key.buy_token)   - 1);
            json_object *l_arr = json_object_new_array();
            dex_history_ctx_t l_ctx = { .arr = l_arr, .bucket_sec = l_bucket, .fill_missing = l_fill_missing, .with_ohlc = 1 };
            dex_history_for_each_range(&l_key, l_t_from, l_t_to ? l_t_to : UINT64_MAX,
                 l_bucket, s_hist_cb_build_volume, &l_ctx);
            l_sum_base = l_ctx.sum_base; l_sum_quote = l_ctx.sum_quote; l_trades = l_ctx.trades;
            if ( !IS_ZERO_256(l_ctx.last_price) ) {
                l_have_spot = true;
                l_spot_ts = l_t_to ? l_t_to : dap_time_now();
                l_last_price = l_ctx.last_price;
            }
        } else {
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            for ( dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it) ) {
                if (l_t_from && l_tx->header.ts_created < (dap_time_t)l_t_from) continue;
                if (l_t_to   && l_tx->header.ts_created > (dap_time_t)l_t_to) continue;
                if (!dap_chain_datum_tx_item_get(l_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL)) continue;
                dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
                if ( !l_out_cond ) continue;
                int l_prev_idx = 0, l_in_i = 0;
                byte_t *l_it_in; size_t l_sz_in = 0;
                TX_ITEM_ITER_TX(l_it_in, l_sz_in, l_tx) if ( *l_it_in == TX_ITEM_TYPE_IN_COND ) {
                    dap_chain_tx_in_cond_t *l_in = (dap_chain_tx_in_cond_t*)l_it_in;
                    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_in->header.tx_prev_hash);
                    if (!l_prev_tx) continue;
                    dap_chain_tx_out_cond_t *l_prev = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_idx);
                    if (!l_prev) continue;
                    const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &l_in->header.tx_prev_hash);
                    if (!l_sell_tok) continue;
                    dex_pair_key_t l_key = { };
                    uint8_t l_side = 0;
                    uint256_t l_price_canon = uint256_0;
                    s_pair_normalize(l_sell_tok, l_prev->subtype.srv_dex.sell_net_id, l_prev->subtype.srv_dex.buy_token,
                         l_prev->subtype.srv_dex.buy_net_id, l_prev->subtype.srv_dex.rate, &l_key, &l_side, &l_price_canon);
                    if ( dap_strcmp(l_key.sell_token, l_quote) || dap_strcmp(l_key.buy_token, l_base) ) { 
                        l_in_i++; continue;
                    }
                    if ( l_key.sell_net_id.uint64 != l_net->pub.id.uint64 || l_key.buy_net_id.uint64 != l_net->pub.id.uint64 ) {
                        if (s_cross_net_policy == CROSS_NET_REJECT) {
                            l_in_i++; continue;
                        } else if (s_cross_net_policy == CROSS_NET_WARN)
                            log_it(L_WARNING, "cross-net trade seen in market_rate scan: %s/%s", l_base, l_quote);
                    }
                    uint256_t l_executed_i = l_prev->header.value;
                    if (l_out_cond && !dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash) && l_in_i == 0) {
                        dap_hash_fast_t l_root0 = dap_ledger_get_first_chain_tx_hash(l_net->pub.ledger, l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                        if ( !dap_hash_fast_compare(&l_root0, &l_out_cond->subtype.srv_dex.order_root_hash) )
                            if (compare256(l_prev->header.value, l_out_cond->header.value) > 0)
                                SUBTRACT_256_256(l_prev->header.value, l_out_cond->header.value, &l_executed_i);
                    }
                    uint256_t l_buy_i = uint256_0; MULT_256_COIN(l_executed_i, l_price_canon, &l_buy_i);
                    bool l_payout_i = false;
                    byte_t *l_ito; size_t l_szo = 0;
                    TX_ITEM_ITER_TX(l_ito, l_szo, l_tx) {
                        if ( *l_ito == TX_ITEM_TYPE_OUT_EXT ) {
                            dap_chain_tx_out_ext_t *o = (dap_chain_tx_out_ext_t*)l_ito;
                            if ( !dap_strcmp(o->token, l_prev->subtype.srv_dex.buy_token)
                                && dap_chain_addr_compare(&o->addr, &l_prev->subtype.srv_dex.seller_addr) )
                            {
                                l_payout_i = true; break;
                            }
                        } else if (*l_ito == TX_ITEM_TYPE_OUT_STD) {
                            dap_chain_tx_out_std_t *o = (dap_chain_tx_out_std_t*)l_ito;
                            if ( !dap_strcmp(o->token, l_prev->subtype.srv_dex.buy_token)
                                && dap_chain_addr_compare(&o->addr, &l_prev->subtype.srv_dex.seller_addr))
                            {
                                l_payout_i = true; break;
                            }
                        }
                    }
                    if ( !l_payout_i ) {
                        l_in_i++; continue;
                    }
                    dex_bq_t l_bq = EXEC_TO_CANON_BQ( l_executed_i, l_price_canon, l_side );
                    SUM_256_256(l_sum_base, l_bq.base, &l_sum_base);
                    SUM_256_256(l_sum_quote, l_bq.quote, &l_sum_quote);
                    if ( l_tx->header.ts_created >= l_spot_ts ) {
                        l_have_spot = true;
                        l_spot_ts = l_tx->header.ts_created;
                        l_last_price = l_price_canon;
                    }
                    ++l_trades; ++l_in_i;
                    if (l_bucket) {
                        uint64_t l_ts_bucket = l_tx->header.ts_created;
                        l_ts_bucket -= ( l_ts_bucket % l_bucket );
                        dex_bucket_agg_t *l_ba = NULL; HASH_FIND(hh, l_buckets, &l_ts_bucket, sizeof(l_ts_bucket), l_ba);
                        if (!l_ba) {
                            l_ba = DAP_NEW_Z(dex_bucket_agg_t);
                            l_ba->ts = l_ts_bucket;
                            l_ba->first_ts = l_ba->last_ts = l_tx->header.ts_created;
                            l_ba->open = l_ba->high = l_ba->low = l_ba->close = l_price_canon;
                            HASH_ADD(hh, l_buckets, ts, sizeof(l_ba->ts), l_ba);
                        } 
                        if ( l_tx->header.ts_created < l_ba->first_ts) {
                            l_ba->first_ts = l_tx->header.ts_created;
                            l_ba->open = l_price_canon;
                        }
                        if ( l_tx->header.ts_created >= l_ba->last_ts) {
                            l_ba->last_ts = l_tx->header.ts_created;
                            l_ba->close = l_price_canon;
                        }
                        if (compare256(l_price_canon, l_ba->high) > 0)
                            l_ba->high = l_price_canon;
                        if (compare256(l_price_canon, l_ba->low) < 0)
                            l_ba->low = l_price_canon;
                        SUM_256_256(l_ba->sum_base, l_bq.base, &l_ba->sum_base);
                        SUM_256_256(l_ba->sum_quote, l_bq.quote, &l_ba->sum_quote);
                        ++l_ba->trades;
                    }
                }
            }
            dap_ledger_datum_iter_delete(it);
        }
        
        l_json_reply = json_object_new_object();
        json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_str));
        json_object_object_add(l_json_reply, "granularity_sec", json_object_new_uint64(l_bucket));
        json_object_object_add(l_json_reply, "request_ts", json_object_new_uint64(dap_time_now()));
        if (l_have_spot)
            json_object_object_add(l_json_reply, "spot", json_object_new_string(dap_uint256_to_char_ex(l_last_price).frac));
        if (!IS_ZERO_256(l_sum_base)) {
            uint256_t l_vwap = uint256_0; DIV_256_COIN(l_sum_quote, l_sum_base, &l_vwap);
            json_object_object_add(l_json_reply, "vwap", json_object_new_string(dap_uint256_to_char_ex(l_vwap).frac));
        }
        json_object_object_add(l_json_reply, "trades", json_object_new_int(l_trades));
        json_object_object_add(l_json_reply, "volume_base", json_object_new_string(dap_uint256_to_char_ex(l_sum_base).frac));
        json_object_object_add(l_json_reply, "volume_quote", json_object_new_string(dap_uint256_to_char_ex(l_sum_quote).frac));
        if (l_bucket && l_buckets) {
            HASH_SORT(l_buckets, s_cmp_bucket_ts);
            json_object *l_arr = json_object_new_array();
            dex_bucket_agg_t *l_cur, *l_tmp;
            uint64_t l_prev_ts = 0;
            uint256_t l_prev_close = l_last_price;
            HASH_ITER(hh, l_buckets, l_cur, l_tmp) {
                if (l_fill_missing && l_prev_ts) {
                    for (uint64_t t = l_prev_ts + l_bucket; t < l_cur->ts; t += l_bucket) {
                        dex_bucket_agg_t l_miss = { .ts = t, .first_ts = t, .last_ts = t + l_bucket - 1,
                            .open = l_prev_close, .high = l_prev_close, .low = l_prev_close, .close = l_prev_close };
                        s_hist_json_emit_bucket(l_arr, &l_miss, true);
                    }
                }
                s_hist_json_emit_bucket(l_arr, l_cur, true);
                l_prev_ts = l_cur->ts; l_prev_close = l_cur->close;
                HASH_DEL(l_buckets, l_cur); DAP_DELETE(l_cur);
            }
            json_object_object_add(l_json_reply, "ohlc", l_arr);
        }
        s_add_units(l_json_reply, l_base, l_quote);
    } break; // MARKET_RATE

    case CMD_VOLUME: {
        const char *l_base, *l_quote; PAIR_CANON_SIMPL(l_base, l_quote);
        const char *l_from_str = NULL, *l_to_str = NULL, *l_bucket_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-from", &l_from_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-to", &l_to_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-bucket", &l_bucket_str);

        uint64_t l_t_from = 0, l_t_to = 0;
        if ( l_from_str && !s_parse_natural_time(l_net->pub.ledger, l_from_str, &l_t_from) )
            l_t_from = strtoull(l_from_str, NULL, 10);
        if ( l_to_str && !s_parse_natural_time(l_net->pub.ledger, l_to_str, &l_t_to) )
            l_t_to = strtoull(l_to_str, NULL, 10);
        if ( l_t_from && l_t_to && l_t_to < l_t_from ) { uint64_t t = l_t_from; l_t_from = l_t_to; l_t_to = t; }

        uint64_t l_bucket = l_bucket_str ? strtoull(l_bucket_str, NULL, 10) : 0ULL;

        dex_bucket_agg_t *l_buckets = NULL;
        uint256_t l_sum_base_all = uint256_0, l_sum_quote_all = uint256_0;
        int l_trades_all = 0;
        if (s_dex_history_enabled && l_bucket) {
            // VOLUME-only path: volume in "visual" order BASE/QUOTE
            dex_pair_key_t l_key = (dex_pair_key_t){ .sell_net_id = l_net->pub.id, .buy_net_id = l_net->pub.id };
            dap_strncpy(l_key.sell_token, l_base,  sizeof(l_key.sell_token)  - 1);
            dap_strncpy(l_key.buy_token,  l_quote, sizeof(l_key.buy_token)   - 1);
            json_object *l_arr = json_object_new_array();
            dex_history_ctx_t l_ctx = { .arr = l_arr };
            dex_history_for_each_range(&l_key, l_t_from, l_t_to ? l_t_to : UINT64_MAX,
                 l_bucket, s_hist_cb_build_volume, &l_ctx);
            l_sum_base_all = l_ctx.sum_base;
            l_sum_quote_all = l_ctx.sum_quote;
            l_trades_all = l_ctx.trades;
        } else {
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            for ( dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it) ) {
                if (l_t_from && l_tx->header.ts_created < l_t_from) continue;
                if (l_t_to   && l_tx->header.ts_created > l_t_to) continue;
                if ( !dap_chain_datum_tx_item_get(l_tx, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL) ) continue;
                dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
                byte_t *l_it_in; size_t l_sz_in = 0; 
                int l_in_i = 0;
                TX_ITEM_ITER_TX(l_it_in, l_sz_in, l_tx) if ( *l_it_in == TX_ITEM_TYPE_IN_COND ) {
                    dap_chain_tx_in_cond_t *l_in = (dap_chain_tx_in_cond_t*)l_it_in;
                    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_in->header.tx_prev_hash); 
                    if (!l_prev_tx) continue;
                    dap_chain_tx_out_cond_t *l_prev = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
                    if (!l_prev) continue;
                    const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &l_in->header.tx_prev_hash);
                    if (!l_sell_tok) continue;
                    dex_pair_key_t l_key = { };
                    uint8_t l_side = 0;
                    uint256_t l_price_canon = uint256_0;
                    s_pair_normalize(l_sell_tok, l_prev->subtype.srv_dex.sell_net_id, l_prev->subtype.srv_dex.buy_token,
                         l_prev->subtype.srv_dex.buy_net_id, l_prev->subtype.srv_dex.rate, &l_key, &l_side, &l_price_canon);
                    if (dap_strcmp(l_key.sell_token, l_quote) || dap_strcmp(l_key.buy_token, l_base)) {
                        l_in_i++; continue;
                    }
                    if ( l_key.sell_net_id.uint64 != l_net->pub.id.uint64 || l_key.buy_net_id.uint64 != l_net->pub.id.uint64 ) {
                        if (s_cross_net_policy == CROSS_NET_REJECT) {
                            l_in_i++; continue;
                        } else if (s_cross_net_policy == CROSS_NET_WARN)
                            log_it(L_WARNING, "cross-net trade seen in volume scan: %s/%s", l_base, l_quote);
                    }
                    uint256_t l_executed_i = l_prev->header.value;
                    if (l_out_cond && !dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash) && l_in_i == 0) {
                        dap_hash_fast_t l_root0 = dap_ledger_get_first_chain_tx_hash(l_net->pub.ledger, l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                        if ( !dap_hash_fast_compare(&l_root0, &l_out_cond->subtype.srv_dex.order_root_hash) )
                            if ( compare256(l_prev->header.value, l_out_cond->header.value) > 0 )
                                SUBTRACT_256_256(l_prev->header.value, l_out_cond->header.value, &l_executed_i);
                    }
                    uint256_t l_buy_i = uint256_0; MULT_256_COIN(l_executed_i, l_price_canon, &l_buy_i);
                    bool l_payout_i = false;
                    byte_t *l_ito; size_t l_szo = 0; TX_ITEM_ITER_TX(l_ito, l_szo, l_prev_tx) {
                        if ( *l_ito == TX_ITEM_TYPE_OUT_EXT ) {
                            dap_chain_tx_out_ext_t *o = (dap_chain_tx_out_ext_t*)l_ito;
                            if (!dap_strcmp(o->token, l_prev->subtype.srv_dex.buy_token)
                                && dap_chain_addr_compare(&o->addr, &l_prev->subtype.srv_dex.seller_addr))
                            {
                                    l_payout_i = true; break;
                            }
                        } else if ( *l_ito == TX_ITEM_TYPE_OUT_STD ) {
                            dap_chain_tx_out_std_t *o = (dap_chain_tx_out_std_t*)l_ito;
                            if (!dap_strcmp(o->token, l_prev->subtype.srv_dex.buy_token)
                                && dap_chain_addr_compare(&o->addr, &l_prev->subtype.srv_dex.seller_addr))
                                {
                                    l_payout_i = true; break;
                                }
                        }
                    }
                    if ( !l_payout_i ) { l_in_i++; continue; }
                    dex_bq_t l_bq = EXEC_TO_CANON_BQ( l_executed_i, l_price_canon, l_side );
                    SUM_256_256(l_sum_base_all, l_bq.base, &l_sum_base_all);
                    SUM_256_256(l_sum_quote_all, l_bq.quote, &l_sum_quote_all);
                    ++l_trades_all; ++l_in_i;
                    if (l_bucket) {
                        uint64_t l_ts_bucket = l_prev_tx->header.ts_created;
                        l_ts_bucket -= ( l_ts_bucket % l_bucket );
                        dex_bucket_agg_t *l_ba = NULL; HASH_FIND(hh, l_buckets, &l_ts_bucket, sizeof(l_ts_bucket), l_ba);
                        if (!l_ba) {
                            l_ba = DAP_NEW_Z(dex_bucket_agg_t);
                            l_ba->ts = l_ts_bucket;
                            l_ba->first_ts = l_ba->last_ts = l_prev_tx->header.ts_created;
                            HASH_ADD(hh, l_buckets, ts, sizeof(l_ba->ts), l_ba);
                        }
                        if (l_prev_tx->header.ts_created < l_ba->first_ts)
                            l_ba->first_ts = l_prev_tx->header.ts_created;
                        if (l_prev_tx->header.ts_created >  l_ba->last_ts)
                            l_ba->last_ts  = l_prev_tx->header.ts_created;
                        SUM_256_256(l_ba->sum_base,  l_bq.base,  &l_ba->sum_base);
                        SUM_256_256(l_ba->sum_quote, l_bq.quote, &l_ba->sum_quote);
                        ++l_ba->trades;
                    }
                }
            }
            dap_ledger_datum_iter_delete(it);
        }

        l_json_reply = json_object_new_object();
        json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_str));
        json_object_object_add(l_json_reply, "request_ts", json_object_new_uint64(dap_time_now()));
        json_object_object_add(l_json_reply, "volume_base", json_object_new_string(dap_uint256_to_char_ex(l_sum_base_all).frac));
        json_object_object_add(l_json_reply, "volume_quote", json_object_new_string(dap_uint256_to_char_ex(l_sum_quote_all).frac));
        json_object_object_add(l_json_reply, "trades", json_object_new_int(l_trades_all));
        if (l_bucket && l_buckets) {
            HASH_SORT(l_buckets, s_cmp_bucket_ts);
            json_object *l_arr = json_object_new_array();
            dex_bucket_agg_t *l_cur, *l_tmp; HASH_ITER(hh, l_buckets, l_cur, l_tmp) {
                s_hist_json_emit_bucket(l_arr, l_cur, false);
                HASH_DEL(l_buckets, l_cur); DAP_DELETE(l_cur);
            }
            json_object_object_add(l_json_reply,"buckets",l_arr);
        }
        s_add_units(l_json_reply, l_base, l_quote);
    } break; // VOLUME

    case CMD_CANCEL_ALL_BY_SELLER: {
        const char *l_seller_str = NULL, *l_fee_str = NULL, *l_limit_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-seller", &l_seller_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-limit", &l_limit_str);
        bool l_dry_run = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-dry-run") >= l_arg_index;
        if (!l_seller_str || !l_fee_str)
            return dap_json_rpc_error_add(*json_arr_reply, -61, "missing -seller or -fee"), -61;
        dap_chain_addr_t *l_seller_tmp = dap_chain_addr_from_str(l_seller_str); if (!l_seller_tmp)
            return dap_json_rpc_error_add(*json_arr_reply, -62, "bad seller address %s", l_seller_str), -62;
        dap_chain_addr_t l_seller = *l_seller_tmp; DAP_DELETE(l_seller_tmp);
        int l_limit = l_limit_str ? atoi(l_limit_str) : INT_MAX, l_cnt = 0;
        if (l_limit < 0) l_limit *= -1;
        uint256_t l_fee = dap_chain_coins_to_balance(l_fee_str);
        // Require wallet even for dry-run; verify ownership matches seller
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
        if (!l_wallet) {
            return dap_json_rpc_error_add(*json_arr_reply, -63, "wallet open failed"), -63;
        }
        dap_chain_addr_t *l_w_addr = dap_chain_wallet_get_addr(l_wallet, l_net->pub.id);
        if (!l_w_addr) {
            dap_chain_wallet_close(l_wallet);
            return dap_json_rpc_error_add(*json_arr_reply, -64, "wallet %s not available", l_wallet_str), -64;
        }
        bool l_addr_match = dap_chain_addr_compare(l_w_addr, &l_seller);
        DAP_DELETE(l_w_addr);
        if (!l_addr_match) {
            dap_chain_wallet_close(l_wallet);
            return dap_json_rpc_error_add(*json_arr_reply, -65, "seller addr != wallet addr"), -65;
        }
        json_object *l_obj = json_object_new_object();
        json_object *l_arr = json_object_new_array();
        if (s_dex_cache_enabled) {
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            dap_time_t l_now = dap_ledger_get_blockchain_time(l_net->pub.ledger);
            dex_seller_index_t *l_sb = NULL; HASH_FIND(hh, s_dex_seller_index, &l_seller, sizeof(l_seller), l_sb);
            if (l_sb && l_sb->entries) {
                dex_order_cache_entry_t *l_e = NULL, *l_tmp; HASH_ITER(hh_seller_bucket, l_sb->entries, l_e, l_tmp) {
                    if (l_e->ts_expires && l_now > l_e->ts_expires) continue;
                    if (l_dry_run) {
                        json_object *o = json_object_new_object();
                        json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&l_e->level.match.tail)));
                        json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&l_e->level.match.root)));
                        json_object_array_add(l_arr, o);
                    } else {
                        /*dap_chain_net_srv_dex_remove_error_t l_err = dap_chain_net_srv_dex_remove(l_net, &l_e->level.match.root, l_fee, l_wallet, &l_datum);
                        json_object *o = json_object_new_object();
                        if (l_err == DEX_REMOVE_ERROR_OK) {
                            json_object_object_add(o, "removed_root", json_object_new_string(dap_hash_fast_to_str_static(&l_e->level.match.root)));
                            json_object_object_add(o, "tx", json_object_new_string(l_hash_res));
                        } else {
                            
                            dap_chain_wallet_close(l_wallet);
                            json_object_put(l_obj);
                            json_object_put(l_arr);
                            return dap_json_rpc_error_add(*json_arr_reply, -63, "removing tx %s error %d", dap_hash_fast_to_str_static(&l_e->level.match.root), l_err), -63;
                            
                            json_object_object_add(o, "error_remove_root", json_object_new_string(dap_hash_fast_to_str_static(&l_e->level.match.root)));
                            json_object_object_add(o, "error_remove_code", json_object_new_int(l_err));
                        }
                        json_object_array_add(l_arr, o);
                    */} // TODO!
                    if (++l_cnt >= l_limit) break;
                }
            }
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
        } else {
            // Ledger fallback: scan SRV_DEX unspent outs by seller
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            for (dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it)) {
                int l_out_idx = 0;
                dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                if (!l_out_cond) continue;
                if ( l_out_cond->header.ts_expires && dap_ledger_get_blockchain_time(l_net->pub.ledger) > l_out_cond->header.ts_expires ) continue;
                if ( !dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, &l_seller) ) continue;
                if ( dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL)) continue;
                dap_hash_fast_t l_root = dap_ledger_get_first_chain_tx_hash(l_net->pub.ledger, l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                if (l_dry_run) {
                    json_object *o = json_object_new_object();
                    json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&it->cur_hash)));
                    json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&l_root)));
                    json_object_array_add(l_arr, o);
                } else {
                    /*dap_chain_net_srv_dex_remove_error_t l_err = dap_chain_net_srv_dex_remove(l_net, &l_root, l_fee, l_wallet, l_hash_res);
                    json_object *o = json_object_new_object();
                    if (l_err == DEX_REMOVE_ERROR_OK) {
                        json_object_object_add(o, "removed_root", json_object_new_string(dap_hash_fast_to_str_static(&l_root)));
                        json_object_object_add(o, "tx", json_object_new_string(l_hash_res));
                    } else {
                        
                        dap_chain_wallet_close(l_wallet);
                        json_object_put(l_obj);
                        json_object_put(l_arr);
                        return dap_json_rpc_error_add(*json_arr_reply, -63, "removing tx %s error %d", dap_hash_fast_to_str_static(&l_root), l_err), -63;
                        
                        json_object_object_add(o, "error_remove_root", json_object_new_string(dap_hash_fast_to_str_static(&l_root)));
                        json_object_object_add(o, "error_remove_code", json_object_new_int(l_err));
                    }
                    json_object_array_add(l_arr, o);
                */}
                if (++l_cnt >= l_limit) break;
            }
            dap_ledger_datum_iter_delete(it);
        }
        dap_chain_wallet_close(l_wallet);
        json_object_object_add(l_obj, "result", l_arr);
        json_object_object_add(l_obj, "count", json_object_new_int(l_cnt));
        json_object_array_add(*json_arr_reply, l_obj);
    } break; // CANCEL_ALL_BY_SELLER

    case CMD_PURCHASE: {
        const char *l_order_str = NULL, *l_value_str = NULL, *l_fee_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-order", &l_order_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
        if (!l_order_str || !l_value_str)
            return dap_json_rpc_error_add(*json_arr_reply, -61, "missing -order or -value"), -61;
        dap_hash_fast_t l_order; 
        if ( dap_chain_hash_fast_from_str(l_order_str, &l_order) )
            return dap_json_rpc_error_add(*json_arr_reply, -62, "bad order hash %s", l_order_str), -62;
        uint256_t l_value = dap_chain_coins_to_balance(l_value_str), l_fee = dap_chain_coins_to_balance(l_fee_str);
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
        if (!l_wallet)
            return dap_json_rpc_error_add(*json_arr_reply, -63, "wallet open failed"), -63;
        l_ret = dap_chain_net_srv_dex_purchase(l_net, &l_order, l_value, l_fee, l_wallet, &l_datum);
        dap_chain_wallet_close(l_wallet);
        //if (l_ret != DEX_PURCHASE_ERROR_OK)
        //    break;
            //return dap_json_rpc_error_add(*json_arr_reply, -62, "purchase error %d", l_ret), -62;
    } break; // PURCHASE
    
    case CMD_PURCHASE_MULTI: {
        const char *l_orders_str = NULL, *l_value_str = NULL, *l_fee_str = NULL, *l_leftover_str = NULL, *l_rate_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-orders", &l_orders_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
        bool l_create_leftover = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-create_leftover_order") >= l_arg_index;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-leftover_rate", &l_rate_str);
        if (l_create_leftover && !l_rate_str)
            return dap_json_rpc_error_add(*json_arr_reply, -62, "missing -leftover_rate"), -62;
        else if (!l_create_leftover && l_rate_str)
            return dap_json_rpc_error_add(*json_arr_reply, -62, "leftover_rate not allowed"), -62;
        if (!l_orders_str || !l_value_str)
            return dap_json_rpc_error_add(*json_arr_reply, -61, "missing -orders or -value"), -61;
        uint256_t l_value = dap_chain_coins_to_balance(l_value_str), l_fee = dap_chain_coins_to_balance(l_fee_str);
        uint256_t l_leftover_rate = l_rate_str ? dap_chain_coins_to_balance(l_rate_str) : uint256_0;
        if ( IS_ZERO_256(l_value) )
            return dap_json_rpc_error_add(*json_arr_reply, -62, "value must be > 0"), -62;
        if ( l_create_leftover && IS_ZERO_256(l_leftover_rate) )
            return dap_json_rpc_error_add(*json_arr_reply, -62, "leftover_rate must be > 0"), -62;
        int l_num = 1;
        char *l_orders_copy = strdup(l_orders_str), *l_delim;
        for ( l_delim = l_orders_copy; ( l_delim = strchr(l_delim, ',') ); ++l_num, *l_delim = '\0' );
        dap_hash_fast_t *l_hashes = DAP_NEW_Z_COUNT(dap_hash_fast_t, l_num);
        if (!l_hashes) {
            DAP_DELETE(l_orders_copy);
            return dap_json_rpc_error_add(*json_arr_reply, -63, "oom"), -63;
        }
        l_delim = l_orders_copy;
        for (int l_idx = 0; l_idx < l_num; ++l_idx) {
            if ( dap_chain_hash_fast_from_str(l_delim, &l_hashes[l_idx]) ) {
                dap_json_rpc_error_add(*json_arr_reply, -64, "bad order hash %s", l_delim);
                DAP_DEL_MULTY(l_hashes, l_orders_copy);
                return -64;
            }
            l_delim = strchr(l_delim, '\0') + 1;
        }
        DAP_DELETE(l_orders_copy);
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
        if ( l_wallet ) {
            l_ret = dap_chain_net_srv_dex_purchase_multi(l_net, l_hashes, l_num, l_value, l_fee,
                l_wallet, l_create_leftover, l_leftover_rate, &l_datum);
            dap_chain_wallet_close(l_wallet);
        } else
            l_ret = -13;
        DAP_DELETE(l_hashes);
    } break; // PURCHASE_MULTI
    
    case CMD_PURCHASE_AUTO: {
        const char *l_sell_tok = NULL, *l_buy_tok = NULL, *l_value_str = NULL, *l_fee_str = NULL, *l_min_rate_str = NULL, *l_leftover_str = NULL, *l_rate_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_sell", &l_sell_tok);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token_buy", &l_buy_tok);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
        if (!l_sell_tok || !l_buy_tok || !l_value_str)
            return dap_json_rpc_error_add(*json_arr_reply, -61, "missing -token_sell or -token_buy or -value"), -61;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-min_rate", &l_min_rate_str);
        bool l_create_leftover = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-create_leftover_order") >= l_arg_index;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-leftover_rate", &l_rate_str);
        if (l_create_leftover && !l_rate_str)
            return dap_json_rpc_error_add(*json_arr_reply, -62, "missing -leftover_rate"), -62;
        else if (!l_create_leftover && l_rate_str)
            return dap_json_rpc_error_add(*json_arr_reply, -62, "leftover_rate not allowed"), -62;
        uint256_t l_leftover_rate = l_rate_str ? dap_chain_coins_to_balance(l_rate_str) : uint256_0;
        if ( l_create_leftover && IS_ZERO_256(l_leftover_rate) )
            return dap_json_rpc_error_add(*json_arr_reply, -62, "leftover_rate must be > 0"), -62;
        uint256_t l_max_buy_value = dap_chain_coins_to_balance(l_value_str);
        if ( IS_ZERO_256(l_max_buy_value) )
            return dap_json_rpc_error_add(*json_arr_reply, -62, "max_buy_value must be > 0"), -62;
        uint256_t l_fee = l_fee_str ? dap_chain_coins_to_balance(l_fee_str) : uint256_0;
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
        if ( !l_wallet )
            return dap_json_rpc_error_add(*json_arr_reply, -63, "wallet %s open failed", l_wallet_str), -63;
        
        dex_match_table_entry_t *l_matches = NULL;
        dap_chain_net_srv_dex_purchase_auto_error_t l_ret = dap_chain_net_srv_dex_purchase_auto(l_net, l_sell_tok, l_buy_tok,
            l_max_buy_value, l_fee, l_min_rate_str ? dap_chain_coins_to_balance(l_min_rate_str) : uint256_0,
            l_wallet, l_create_leftover, l_leftover_rate, &l_datum, &l_matches);
        dap_chain_wallet_close(l_wallet);
        
        if ( l_ret == DEX_PURCHASE_AUTO_ERROR_OK ) {
            json_object *l_arr = json_object_new_array();
            uint256_t l_total_sell = uint256_0, l_total_buy = uint256_0;
            dex_match_table_entry_t *l_cur, *l_tmp; HASH_ITER(hh, l_matches, l_cur, l_tmp) {
                json_object *o = json_object_new_object();
                json_object_object_add(o, "token_sell", json_object_new_string(l_cur->pair_key->sell_token));
                json_object_object_add(o, "token_buy", json_object_new_string(l_cur->pair_key->buy_token));
                json_object_object_add(o, "root", json_object_new_string(dap_hash_fast_to_str_static(&l_cur->match.root)));
                json_object_object_add(o, "tail", json_object_new_string(dap_hash_fast_to_str_static(&l_cur->match.tail)));
                json_object_object_add(o, "rate", json_object_new_string(dap_uint256_to_char_ex(l_cur->match.rate).frac));
                uint256_t l_exec_buy = uint256_0; MULT_256_COIN(l_cur->exec_sell, l_cur->match.rate, &l_exec_buy);
                json_object_object_add(o, "executed_sell", json_object_new_string(dap_uint256_to_char_ex(l_cur->exec_sell).frac));
                json_object_object_add(o, "executed_buy", json_object_new_string(dap_uint256_to_char_ex(l_exec_buy).frac));
                json_object_array_add(l_arr, o);
                if (!IS_ZERO_256(l_cur->exec_sell)) SUM_256_256(l_total_sell, l_cur->exec_sell, &l_total_sell);
                if (!IS_ZERO_256(l_exec_buy))  SUM_256_256(l_total_buy,  l_exec_buy,  &l_total_buy);
            }
            l_json_reply = json_object_new_object();
            json_object_object_add(l_json_reply, "orders", json_object_new_int((int)HASH_CNT(hh, l_matches)));
            json_object_object_add(l_json_reply, "sell", json_object_new_string(dap_uint256_to_char_ex(l_total_sell).frac));
            json_object_object_add(l_json_reply, "buy", json_object_new_string(dap_uint256_to_char_ex(l_total_buy).frac));
            json_object_object_add(l_json_reply, "matches", l_arr);
        }
        s_dex_match_pair_index_clear(&l_matches);
    } break; // PURCHASE_AUTO

    case CMD_SLIPPAGE: {
        /* SLIPPAGE
         * Simulate order-book execution for a hypothetical trade to estimate:
         * - effective price (VWAP) for consumed volume
         * - absolute and percent slippage vs the current best price
         * Implementation walks price levels and accumulates BASE/QUOTE totals.
         */
        const char *l_pair_str = NULL, *l_val_str = NULL, *l_side_str = NULL, *l_unit_str = NULL, *l_max_sl_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-pair", &l_pair_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_val_str);
        if (!l_pair_str || !l_val_str)
            return dap_json_rpc_error_add(*json_arr_reply, -85, "missing -pair or -value"), -85;
        // Parse trade direction (buy=consume ASKs, sell=consume BIDs)
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-side", &l_side_str);
        if (!l_side_str)
            return dap_json_rpc_error_add(*json_arr_reply, -86, "missing -side"), -86;
        bool l_side_buy = !dap_strcmp(l_side_str, "buy");
        if (!l_side_buy && dap_strcmp(l_side_str, "sell"))
            return dap_json_rpc_error_add(*json_arr_reply, -86, "bad -side %s", l_side_str), -86;
        
        // Budget unit: base (in BASE currency) or quote (in QUOTE currency)
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-unit", &l_unit_str);
        if (!l_unit_str)
            return dap_json_rpc_error_add(*json_arr_reply, -87, "missing -unit"), -87;
        bool l_unit_base = !dap_strcmp(l_unit_str, "base");
        if (!l_unit_base && dap_strcmp(l_unit_str, "quote"))
            return dap_json_rpc_error_add(*json_arr_reply, -87, "bad -unit %s", l_unit_str), -87;

        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-max_slippage_pct", &l_max_sl_str);
        // Optional early-stop constraint: abort simulation when slippage_pct exceeds this limit

        uint256_t l_budget = dap_chain_coins_to_balance(l_val_str);
        if (IS_ZERO_256(l_budget))
            return dap_json_rpc_error_add(*json_arr_reply, -87, "value must be > 0"), -87;
        const char *l_base, *l_quote; PAIR_CANON_SIMPL(l_base, l_quote);

        uint256_t l_total_base = uint256_0, l_total_quote = uint256_0, l_best_ref = uint256_0, l_best_price = uint256_0;
        bool l_has_limit = l_max_sl_str && *l_max_sl_str;
        uint256_t l_max_sl = l_has_limit ? dap_chain_coins_to_balance(l_max_sl_str) : uint256_0;
        int l_used_levels = 0;

        // Budget consumption helpers: fully/partially consume a level and update totals
#define BUDGET_CONSUME_BUY_BASE(_budget, _rate, _value) do { \
            uint256_t l_max_b = _value, l_add_q = uint256_0; \
            if ( compare256(_budget, l_max_b) >= 0 ) { \
                SUM_256_256(l_total_base, l_max_b, &l_total_base); MULT_256_COIN(l_max_b, _rate, &l_add_q); \
                SUM_256_256(l_total_quote, l_add_q, &l_total_quote); SUBTRACT_256_256(_budget, l_max_b, &_budget); \
                l_used_levels++; \
            } else { \
                MULT_256_COIN(_budget, _rate, &l_add_q); \
                if (!IS_ZERO_256(_budget)) l_used_levels++; \
                SUM_256_256(l_total_base, _budget, &l_total_base); SUM_256_256(l_total_quote, l_add_q, &l_total_quote); \
                _budget = uint256_0; \
            } \
        } while(0)

#define BUDGET_CONSUME_BUY_QUOTE(_budget, _rate, _value) do { \
            uint256_t l_max_q = uint256_0; MULT_256_COIN(_value, _rate, &l_max_q); \
            if ( compare256(_budget, l_max_q) >= 0 ) { \
                SUM_256_256(l_total_base, _value, &l_total_base); SUM_256_256(l_total_quote, l_max_q, &l_total_quote); \
                SUBTRACT_256_256(_budget, l_max_q, &_budget); \
                l_used_levels++; \
            } else { \
                uint256_t l_take_b = uint256_0; DIV_256_COIN(_budget, _rate, &l_take_b); \
                if (!IS_ZERO_256(_budget)) l_used_levels++; \
                SUM_256_256(l_total_base, l_take_b, &l_total_base); SUM_256_256(l_total_quote, _budget, &l_total_quote); \
                _budget = uint256_0; \
            } \
        } while(0)


#define BUDGET_CONSUME_SELL_BASE(_budget, _rate, _value) do { \
            uint256_t l_max_b = uint256_0; DIV_256_COIN(_value, _rate, &l_max_b); \
            if ( compare256(_budget, l_max_b) >= 0 ) { \
                SUM_256_256(l_total_base, l_max_b, &l_total_base); SUM_256_256(l_total_quote, _value, &l_total_quote); \
                SUBTRACT_256_256(_budget, l_max_b, &_budget); \
                l_used_levels++; \
            } else { \
                uint256_t l_take_q = uint256_0; \
                MULT_256_COIN(_budget, _rate, &l_take_q); \
                if (!IS_ZERO_256(_budget)) l_used_levels++; \
                SUM_256_256(l_total_base, _budget, &l_total_base); SUM_256_256(l_total_quote, l_take_q, &l_total_quote); \
                _budget = uint256_0; \
            } \
        } while(0)
#define BUDGET_CONSUME_SELL_QUOTE(_budget, _rate, _value) do { \
            uint256_t l_max_q = _value, l_add_b = uint256_0; \
            if (compare256(_budget, l_max_q) >= 0) { \
                SUM_256_256(l_total_quote, l_max_q, &l_total_quote); DIV_256_COIN(l_max_q, _rate, &l_add_b); \
                SUM_256_256(l_total_base, l_add_b, &l_total_base); SUBTRACT_256_256(_budget, l_max_q, &_budget); \
                l_used_levels++; \
            } else { \
                DIV_256_COIN(_budget, _rate, &l_add_b); \
                if (!IS_ZERO_256(_budget)) l_used_levels++; \
                SUM_256_256(l_total_quote, _budget, &l_total_quote); SUM_256_256(l_total_base, l_add_b, &l_total_base); \
                _budget = uint256_0; \
            } \
        } while(0)

        // Early-exit guard: recompute VWAP, derive slippage_pct vs best reference price
#define BUDGET_CHECK_SL_LIMIT ({ \
            bool l_break = false; \
            uint256_t l_vwap_i = uint256_0; DIV_256_COIN(l_total_quote, l_total_base, &l_vwap_i); \
            uint256_t l_ratio_i = uint256_0; DIV_256(l_vwap_i, l_best_ref, &l_ratio_i); \
            uint256_t l_one = GET_256_FROM_64(1000000000000000000ULL); \
            if (compare256(l_ratio_i, l_one) >= 0) { \
                uint256_t l_delta = uint256_0; SUBTRACT_256_256(l_ratio_i, l_one, &l_delta); \
                uint256_t l_pct = uint256_0; MULT_256_256(l_delta, GET_256_FROM_64(100ULL), &l_pct); \
                if (compare256(l_pct, l_max_sl) > 0) { l_break = true; } \
            } \
            l_break; \
        })
        dap_time_t l_now_ts = dap_ledger_get_blockchain_time(l_net->pub.ledger);
        if (s_dex_cache_enabled) {
            pthread_rwlock_rdlock(&s_dex_cache_rwlock);
            // Use pair buckets (asks/bids) ordered by best price first
            dex_pair_key_t l_key = { .sell_net_id = l_net->pub.id, .buy_net_id = l_net->pub.id };
            dap_strncpy(l_key.sell_token, l_quote, sizeof(l_key.sell_token) - 1);
            dap_strncpy(l_key.buy_token,  l_base,  sizeof(l_key.buy_token)  - 1);
            dex_pair_index_t *l_pb = NULL; HASH_FIND(hh, s_dex_pair_index, &l_key, sizeof(l_key), l_pb);
            if ( !l_pb ) {
                pthread_rwlock_unlock(&s_dex_cache_rwlock);
                return dap_json_rpc_error_add(*json_arr_reply, -88, "no liquidity for pair %s", l_pair_str), -88;
            }
            if ( l_has_limit )
                l_best_ref = l_side_buy ? (l_pb->asks ? l_pb->asks->level.match.rate : uint256_0) : (l_pb->bids ? l_pb->bids->level.match.rate : uint256_0);
            dex_order_cache_entry_t *e, *tmp;
            if ( l_side_buy ) {
                if ( !l_unit_base ) {
                    // BUY with QUOTE budget: convert QUOTE->BASE per price level
                    uint256_t l_budget_q = l_budget;
                    HASH_ITER(hh_pair_bucket, l_pb->asks, e, tmp) {
                        if ( e->ts_expires && l_now_ts > e->ts_expires ) continue;
                        BUDGET_CONSUME_BUY_QUOTE(l_budget_q, e->level.match.rate, e->level.match.value);
                        if ( IS_ZERO_256(l_budget_q) || ( !IS_ZERO_256(l_best_ref) && BUDGET_CHECK_SL_LIMIT ) ) break;
                    }
                    l_budget = l_budget_q;
                } else {
                    // BUY with BASE budget: take BASE directly, compute QUOTE cost
                    uint256_t l_budget_b = l_budget;
                    HASH_ITER(hh_pair_bucket, l_pb->asks, e, tmp) {
                        if (e->ts_expires && l_now_ts > e->ts_expires) continue;
                        BUDGET_CONSUME_BUY_BASE(l_budget_b, e->level.match.rate, e->level.match.value);
                        if ( IS_ZERO_256(l_budget_b) || ( !IS_ZERO_256(l_best_ref) && BUDGET_CHECK_SL_LIMIT ) ) break;
                    }
                    l_budget = l_budget_b;
                }
            } else {
                dex_order_cache_entry_t *l_last = HASH_LAST_EX(hh_pair_bucket, l_pb->bids);
                if ( l_unit_base ) {
                    // SELL with BASE budget: convert BASE->QUOTE at each price level
                    uint256_t l_budget_b = l_budget;
                    // Reverse iteration
                    for (e = l_last; e && !IS_ZERO_256(l_budget_b); e = (dex_order_cache_entry_t*)e->hh_pair_bucket.prev) {
                        if (e->ts_expires && l_now_ts > e->ts_expires) continue;
                        BUDGET_CONSUME_SELL_BASE(l_budget_b, e->level.match.rate, e->level.match.value);
                        if ( IS_ZERO_256(l_budget_b) || ( !IS_ZERO_256(l_best_ref) && BUDGET_CHECK_SL_LIMIT ) ) break;
                    }
                    l_budget = l_budget_b;
                } else {
                    // SELL with QUOTE target: compute required BASE per level
                    uint256_t l_budget_q = l_budget;
                    for (e = l_last; e && !IS_ZERO_256(l_budget_q); e = (dex_order_cache_entry_t*)e->hh_pair_bucket.prev) {
                        if (e->ts_expires && l_now_ts > e->ts_expires) continue;
                        BUDGET_CONSUME_SELL_QUOTE(l_budget_q, e->level.match.rate, e->level.match.value);
                        if ( IS_ZERO_256(l_budget_q) || ( !IS_ZERO_256(l_best_ref) && BUDGET_CHECK_SL_LIMIT ) ) break;
                    }
                    l_budget = l_budget_q;
                }
            }
            l_best_price = l_best_ref;
            pthread_rwlock_unlock(&s_dex_cache_rwlock);
        } else {
            // Ledger fallback (no cache)
            // 1) Build temporary levels table from on-chain unspent SRV_DEX outs
            // 2) Sort by price (ASK asc for BUY, BID desc for SELL)
            // 3) Walk levels same as the cache path
            dex_order_level_t *l_levels = NULL, *e, *tmp;
            dap_chain_tx_out_cond_t *l_out_cond = NULL;
            dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(l_net);
            for (dap_chain_datum_tx_t *l_tx = dap_ledger_datum_iter_get_first(it); l_tx; l_tx = dap_ledger_datum_iter_get_next(it)) {
                int l_out_idx = 0;
                l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
                if (!l_out_cond) continue;
                if (dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, &it->cur_hash, l_out_idx, NULL)) continue;
                if (l_out_cond->header.ts_expires && l_now_ts > l_out_cond->header.ts_expires) continue;
                const char *l_sell_tok_tx = dap_ledger_tx_get_token_ticker_by_hash(l_net->pub.ledger, &it->cur_hash);
                if (!l_sell_tok_tx) continue;
                dex_pair_key_t l_key = (dex_pair_key_t){ };
                uint8_t l_side = 0;
                uint256_t l_price = uint256_0;
                s_pair_normalize(l_sell_tok_tx, l_out_cond->subtype.srv_dex.sell_net_id, l_out_cond->subtype.srv_dex.buy_token,
                     l_out_cond->subtype.srv_dex.buy_net_id, l_out_cond->subtype.srv_dex.rate, &l_key, &l_side, &l_price);
                if ( dap_strcmp(l_key.sell_token, l_quote) || dap_strcmp(l_key.buy_token, l_base) ) continue;
                if ( ( l_side_buy && l_side != DEX_SIDE_ASK ) || ( !l_side_buy && l_side != DEX_SIDE_BID) ) continue;
                dex_order_level_t *l_lvl = DAP_NEW_Z(dex_order_level_t);
                l_lvl->match.value = l_out_cond->header.value;
                l_lvl->match.rate = l_price;
                l_lvl->match.min_fill = l_out_cond->subtype.srv_dex.min_fill;
                l_lvl->match.root = dap_ledger_get_first_chain_tx_hash(l_net->pub.ledger, l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
                l_lvl->match.tail = it->cur_hash;
                HASH_ADD(hh, l_levels, match.root, sizeof(l_lvl->match.root), l_lvl);
            }
            dap_ledger_datum_iter_delete(it);
            if ( !l_levels )
                return dap_json_rpc_error_add(*json_arr_reply, -88, "no liquidity for pair %s", l_pair_str), -88;

            // sort by price
            if (l_side_buy) HASH_SORT(l_levels, s_cmp_level_entries_ask);
            else HASH_SORT(l_levels, s_cmp_level_entries_bid);
            l_best_price = l_levels->match.rate;
            if (l_has_limit) l_best_ref = l_best_price;

            if (l_side_buy) {
                // BUY path over sorted ASKs
                if ( !l_unit_base ) {
                    // QUOTE budget
                    uint256_t l_budget_q = l_budget;
                    HASH_ITER(hh, l_levels, e, tmp) {
                        BUDGET_CONSUME_BUY_QUOTE(l_budget_q, e->match.rate, e->match.value);
                        bool l_break = IS_ZERO_256(l_budget_q) || ( !IS_ZERO_256(l_best_ref) && BUDGET_CHECK_SL_LIMIT );
                        HASH_DEL(l_levels, e); DAP_DELETE(e);
                        if (l_break) break;
                    }
                    l_budget = l_budget_q;
                } else {
                    // BASE budget
                    uint256_t l_budget_b = l_budget;
                    HASH_ITER(hh, l_levels, e, tmp) {
                        BUDGET_CONSUME_BUY_BASE(l_budget_b, e->match.rate, e->match.value);
                        bool l_break = IS_ZERO_256(l_budget_b) || ( !IS_ZERO_256(l_best_ref) && BUDGET_CHECK_SL_LIMIT );
                        HASH_DEL(l_levels, e); DAP_DELETE(e);
                        if (l_break) break;
                    }
                    l_budget = l_budget_b;
                }
            } else {
                // SELL path over sorted BIDs
                if ( !l_unit_base ) {
                    // QUOTE target
                    uint256_t l_budget_q = l_budget;
                    HASH_ITER(hh, l_levels, e, tmp) {
                        BUDGET_CONSUME_SELL_QUOTE(l_budget_q, e->match.rate, e->match.value);
                        bool l_break = IS_ZERO_256(l_budget_q) || ( !IS_ZERO_256(l_best_ref) && BUDGET_CHECK_SL_LIMIT );
                        HASH_DEL(l_levels, e); DAP_DELETE(e);
                        if (l_break) break;
                    }
                    l_budget = l_budget_q;
                } else {
                    // BASE budget
                    uint256_t l_budget_b = l_budget;
                    HASH_ITER(hh, l_levels, e, tmp) {
                        BUDGET_CONSUME_SELL_BASE(l_budget_b, e->match.rate, e->match.value);
                        bool l_break = IS_ZERO_256(l_budget_b) || ( !IS_ZERO_256(l_best_ref) && BUDGET_CHECK_SL_LIMIT );
                        HASH_DEL(l_levels, e); DAP_DELETE(e);
                        if (l_break) break;
                    }
                    l_budget = l_budget_b;
                }
            }
            // Free temp items if left any
            if (l_levels) HASH_ITER(hh, l_levels, e, tmp) { HASH_DEL(l_levels, e); DAP_DELETE(e); }
        }
#undef PAIR_CANON_SIMPL
#undef BUDGET_CHECK_SL_LIMIT
#undef BUDGET_CONSUME_BUY_BASE
#undef BUDGET_CONSUME_BUY_QUOTE
#undef BUDGET_CONSUME_SELL_BASE
#undef BUDGET_CONSUME_SELL_QUOTE
        if ( !IS_ZERO_256(l_total_base) && !IS_ZERO_256(l_total_quote) ) {
            // Emit effective price (VWAP), best price and slippage metrics
            l_json_reply = json_object_new_object();
            json_object_object_add(l_json_reply, "pair", json_object_new_string(l_pair_str));
            json_object_object_add(l_json_reply, "side", json_object_new_string(l_side_buy ? "buy" : "sell"));

            uint256_t l_vwap = uint256_0; DIV_256_COIN(l_total_quote, l_total_base, &l_vwap);
            uint256_t l_sl = uint256_0;
            if ( !IS_ZERO_256(l_best_price) ) {
                if (l_side_buy) {
                    l_sl = l_vwap; SUBTRACT_256_256(l_sl, l_best_price, &l_sl);
                } else {
                    l_sl = l_best_price; SUBTRACT_256_256(l_sl, l_vwap, &l_sl);
                }
            }
            uint256_t l_sl_pct = uint256_0;
            if ( !IS_ZERO_256(l_best_price) ) {
                uint256_t l_ratio = uint256_0;
                if (l_side_buy) DIV_256(l_vwap, l_best_price, &l_ratio);
                else DIV_256(l_best_price, l_vwap, &l_ratio);
                uint256_t l_one = GET_256_FROM_64(1000000000000000000ULL);
                if ( compare256(l_ratio, l_one) >= 0 ) {
                    uint256_t l_delta = uint256_0; SUBTRACT_256_256(l_ratio, l_one, &l_delta);
                    uint256_t l_hundred = GET_256_FROM_64(100ULL); MULT_256_256(l_delta, l_hundred, &l_sl_pct);
                }
            }
            json_object_object_add(l_json_reply, "effective_price", json_object_new_string(dap_uint256_to_char_ex(l_vwap).frac));
            json_object_object_add(l_json_reply, l_side_buy ? "best_ask" : "best_bid", json_object_new_string(dap_uint256_to_char_ex(l_best_price).frac));
            json_object_object_add(l_json_reply, "slippage", json_object_new_string(dap_uint256_to_char_ex(l_sl).frac));
            json_object_object_add(l_json_reply, "slippage_pct", json_object_new_string(dap_uint256_to_char_ex(l_sl_pct).frac));
            json_object_object_add(l_json_reply, "price_impact_pct", json_object_new_string(dap_uint256_to_char_ex(l_sl_pct).frac));
            json_object_object_add(l_json_reply, "filled_base", json_object_new_string(dap_uint256_to_char_ex(l_total_base).frac));
            json_object_object_add(l_json_reply, "spent_quote", json_object_new_string(dap_uint256_to_char_ex(l_total_quote).frac));
            json_object_object_add(l_json_reply, "levels_used", json_object_new_int(l_used_levels));
            if (l_max_sl_str) {
                uint256_t l_max_sl = dap_chain_coins_to_balance(l_max_sl_str);
                if ( compare256(l_sl_pct, l_max_sl) > 0 )
                    json_object_object_add(l_json_reply, "error", json_object_new_string("max_slippage_exceeded"));
            }
            json_object_object_add(l_json_reply, "totally_filled", json_object_new_boolean(IS_ZERO_256(l_budget)));
        } else
            return dap_json_rpc_error_add(*json_arr_reply, -88, "no liquidity for pair %s", l_pair_str), -88;
    } break; // SLIPPAGE
    
    case CMD_MIGRATE: {
        const char *l_from_hash_str = NULL, *l_rate_str = NULL, *l_fee_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-from",  &l_from_hash_str);
        if (!l_from_hash_str)
            return dap_json_rpc_error_add(*json_arr_reply, -89, "missing -from"), -89;
        dap_hash_fast_t l_from_hash = { };
        if (dap_chain_hash_fast_from_str(l_from_hash_str, &l_from_hash))
            return dap_json_rpc_error_add(*json_arr_reply, -90, "bad -from %s", l_from_hash_str), -90;
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-rate",  &l_rate_str);
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee",   &l_fee_str);
        if (!l_from_hash_str || !l_rate_str || !l_fee_str)
            return dap_json_rpc_error_add(*json_arr_reply, -90, "missing args"), -90;
        uint256_t l_rate = dap_chain_coins_to_balance(l_rate_str), l_fee  = dap_chain_coins_to_balance(l_fee_str);
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
        if (!l_wallet)
            return dap_json_rpc_error_add(*json_arr_reply, -91, "wallet %s open failed", l_wallet_str), -91;
        l_ret = dap_chain_net_srv_dex_migrate(l_net, &l_from_hash, l_rate, l_fee, l_wallet, &l_datum);
        dap_chain_wallet_close(l_wallet);
    } break; // MIGRATE

    default: return dap_json_rpc_error_add(*json_arr_reply, -1, "unknown command"), -1; }

    if (!l_json_reply)
        l_json_reply = json_object_new_object();
    json_object_object_add(l_json_reply, "command", json_object_new_string(l_cmd_str[l_cmd]));

    if ( !l_ret ) {
        if ( l_datum ) {
            char *l_hash = s_dex_tx_put(l_datum, l_net);
            if ( l_hash ) {
                json_object_object_add(l_json_reply, "tx_hash", json_object_new_string(l_hash));
                DAP_DELETE(l_hash); 
            } else {
                l_ret = -3;
                dap_json_rpc_error_add(*json_arr_reply, l_ret, "cannot place TX to mempool");
            }
        }
    } else
        dap_json_rpc_error_add(*json_arr_reply, l_ret, "error %d", l_ret);
    json_object_array_add(*json_arr_reply, l_json_reply);
    return l_ret;
}

static char* s_dex_tx_put(dap_chain_datum_tx_t *a_tx, dap_chain_net_t *a_net)
{
    char *l_ret = NULL;
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, a_tx, l_tx_size);
    DAP_DELETE(a_tx);
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    if ( l_chain )
        l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    return l_ret;
}

dap_chain_net_srv_dex_create_error_t dap_chain_net_srv_dex_create(dap_chain_net_t *a_net, const char *a_token_buy,
                                      const char *a_token_sell, uint256_t a_value_sell,
                                      uint256_t a_rate, uint8_t a_min_fill_combined,
                                      uint256_t a_fee, dap_chain_wallet_t *a_wallet,
                                      dap_chain_datum_tx_t **a_tx)
{
    dap_ret_val_if_any(DEX_CREATE_ERROR_INVALID_ARGUMENT, !a_net, !a_token_buy, !a_token_sell, !a_wallet, !a_tx);
    *a_tx = NULL;
    if (!dap_ledger_token_ticker_check(a_net->pub.ledger, a_token_sell))
        return DEX_CREATE_ERROR_TOKEN_TICKER_SELL_NOT_FOUND;
    if (!dap_ledger_token_ticker_check(a_net->pub.ledger, a_token_buy))
        return DEX_CREATE_ERROR_TOKEN_TICKER_BUY_NOT_FOUND;
    if (IS_ZERO_256(a_rate)) return DEX_CREATE_ERROR_RATE_IS_ZERO;
    if (IS_ZERO_256(a_fee)) return DEX_CREATE_ERROR_FEE_IS_ZERO;
    if (IS_ZERO_256(a_value_sell)) return DEX_CREATE_ERROR_VALUE_SELL_IS_ZERO;

    uint256_t l_balance_sell = dap_chain_wallet_get_balance(a_wallet, a_net->pub.id, a_token_sell),
        l_need_sell = a_value_sell;
    const char *l_native = a_net->pub.native_ticker;
    if ( !dap_strcmp(a_net->pub.native_ticker, a_token_sell) ) {
        if ( SUM_256_256(l_need_sell, a_fee, &l_need_sell) )
            return DEX_CREATE_ERROR_INTEGER_OVERFLOW;
    } else {
        if ( compare256(dap_chain_wallet_get_balance(a_wallet, a_net->pub.id, l_native), a_fee) < 0 )
            return DEX_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE;
    }
    if (compare256(l_balance_sell, l_need_sell) < 0)
        return DEX_CREATE_ERROR_NOT_ENOUGH_CASH;

    // Compose full TX: lock sell funds into SRV_DEX, pay fees, return change
    
    bool l_sell_native = !dap_strcmp(a_token_sell, l_native);
    // Network fee
    uint256_t l_net_fee = uint256_0, l_total_native_fee = a_fee;
    dap_chain_addr_t l_net_addr;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_addr);
    if (l_net_fee_used)
        SUM_256_256(l_total_native_fee, l_net_fee, &l_total_native_fee);

    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_wallet_addr) return DEX_CREATE_ERROR_COMPOSE_TX;
    dap_chain_addr_t l_owner_addr = *l_wallet_addr; DAP_DELETE(l_wallet_addr);

    // Collect inputs
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_list_t *l_list_sell_in = NULL, *l_list_fee_in = NULL;
    uint256_t l_sell_transfer = uint256_0, l_fee_transfer = uint256_0;
    if (l_sell_native) {
        uint256_t l_need = a_value_sell;
        if ( !IS_ZERO_256(l_total_native_fee) )
            SUM_256_256(l_need, l_total_native_fee, &l_need);
        if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_native, &l_owner_addr, &l_list_sell_in, l_need, &l_sell_transfer) == -101)
            l_list_sell_in = dap_ledger_get_list_tx_outs_with_val(a_net->pub.ledger, l_native, &l_owner_addr, l_need, &l_sell_transfer);
        if (!l_list_sell_in) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_CREATE_ERROR_COMPOSE_TX;
        }
        uint256_t l_added = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_sell_in);
        dap_list_free_full(l_list_sell_in, NULL);
        if (!EQUAL_256(l_added, l_sell_transfer)) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_CREATE_ERROR_COMPOSE_TX;
        }
    } else {
        if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, a_token_sell, &l_owner_addr, &l_list_sell_in, a_value_sell, &l_sell_transfer) == -101)
            l_list_sell_in = dap_ledger_get_list_tx_outs_with_val(a_net->pub.ledger, a_token_sell, &l_owner_addr, a_value_sell, &l_sell_transfer);
        if (!l_list_sell_in) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_CREATE_ERROR_COMPOSE_TX;
        }
        uint256_t l_added = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_sell_in);
        dap_list_free_full(l_list_sell_in, NULL);
        if (!EQUAL_256(l_added, l_sell_transfer)) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_CREATE_ERROR_COMPOSE_TX;
        }
        if (!IS_ZERO_256(l_total_native_fee)) {
            if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_native, &l_owner_addr, &l_list_fee_in, l_total_native_fee, &l_fee_transfer) == -101)
                l_list_fee_in = dap_ledger_get_list_tx_outs_with_val(a_net->pub.ledger, l_native, &l_owner_addr, l_total_native_fee, &l_fee_transfer);
            if (!l_list_fee_in) {
                dap_chain_datum_tx_delete(l_tx);
                return DEX_CREATE_ERROR_COMPOSE_TX;
            }
            uint256_t l_added_fee = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_in);
            dap_list_free_full(l_list_fee_in, NULL);
            if (!EQUAL_256(l_added_fee, l_fee_transfer)) {
                dap_chain_datum_tx_delete(l_tx);
                return DEX_CREATE_ERROR_COMPOSE_TX;
            }
        }
    }

    // Add SRV_DEX out (locks sell funds)
    uint8_t l_min_fill = a_min_fill_combined, l_version = 1;
    uint32_t l_flags = 0;
    dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_item_out_cond_create_srv_dex((dap_chain_net_srv_uid_t){ .uint64 = DAP_CHAIN_NET_SRV_DEX_ID }, a_net->pub.id, a_value_sell,
            a_net->pub.id, a_token_buy, a_rate, &l_owner_addr, NULL, l_min_fill, l_version, l_flags, DEX_TX_TYPE_ORDER, NULL, 0);
    if (!l_out) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_CREATE_ERROR_COMPOSE_TX;
    }
    dap_chain_datum_tx_add_item(&l_tx, l_out);
    DAP_DELETE(l_out);

    // Fees
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_CREATE_ERROR_COMPOSE_TX;
    }

    if (l_net_fee_used && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_addr, l_net_fee, l_native) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_CREATE_ERROR_COMPOSE_TX;
    }

    // Change/cashback
    if (l_sell_native) {
        uint256_t l_needed = a_value_sell;
        if (!IS_ZERO_256(l_total_native_fee))
            SUM_256_256(l_needed, l_total_native_fee, &l_needed);
        uint256_t l_change = uint256_0;
        SUBTRACT_256_256(l_sell_transfer, l_needed, &l_change);
        if ( !IS_ZERO_256(l_change)
            && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_change, l_native) != 1 )
        { 
            dap_chain_datum_tx_delete(l_tx);
            return DEX_CREATE_ERROR_COMPOSE_TX;
        }
    } else {
        // change in sell token
        uint256_t l_change_sell = uint256_0;
        SUBTRACT_256_256(l_sell_transfer, a_value_sell, &l_change_sell);
        if ( !IS_ZERO_256(l_change_sell)
            && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_change_sell, a_token_sell) != 1 )
        {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_CREATE_ERROR_COMPOSE_TX;
        }
        // native cashback
        if (!IS_ZERO_256(l_total_native_fee)) {
            uint256_t l_cashback = uint256_0; SUBTRACT_256_256(l_fee_transfer, l_total_native_fee, &l_cashback);
            if (!IS_ZERO_256(l_cashback)) if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_owner_addr, l_cashback, l_native) == -1) {
                dap_chain_datum_tx_delete(l_tx); return DEX_CREATE_ERROR_COMPOSE_TX;
            }
        }
    }

    // Sign and publish
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    int l_sign_res = dap_chain_datum_tx_add_sign_item(&l_tx, l_key);
    dap_enc_key_delete(l_key);
    if (l_sign_res != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_CREATE_ERROR_COMPOSE_TX;
    }
    *a_tx = l_tx;
    return DEX_CREATE_ERROR_OK;
}

/*
 * Update existing order by owner (seller-leftover update):
 * - Finds the current tail of the order chain via the ledger (source of truth)
 * - Verifies that wallet addr matches order's seller_addr
 * - Composes 1-TX update: IN_COND(tail[idx]) + OUT_COND(SRV_DEX new state) with tx_type=UPDATE
 * - Pays native network fee (and optionally validator fee) from wallet UTXOs
 * - Signs and submits to mempool
 */
 dap_chain_net_srv_dex_update_error_t dap_chain_net_srv_dex_update(
    dap_chain_net_t *a_net, dap_hash_fast_t *a_order_root,
    bool a_has_new_rate, uint256_t a_new_rate,
    bool a_has_new_value, uint256_t a_new_value,
    uint256_t a_fee, dap_chain_wallet_t *a_wallet,
    dap_chain_datum_tx_t **a_tx)
{
    // Parameter validation: must have net, order root, wallet, out ptr, and at least one changed field
    dap_ret_val_if_any(DEX_UPDATE_ERROR_INVALID_ARGUMENT, !a_net, !a_order_root, !a_wallet, !a_tx, (!a_has_new_rate && !a_has_new_value));
    *a_tx = NULL;
    // Find actual tail in the ledger (canonical). For SRV_DEX: blank => current tx is owner; non-blank => use stored root.
    dap_hash_fast_t l_tail = dap_ledger_get_final_chain_tx_hash(a_net->pub.ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, a_order_root, false);
    if ( dap_hash_fast_is_blank(&l_tail) ) l_tail = *a_order_root;

    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, &l_tail);
    if (!l_prev_tx) return DEX_UPDATE_ERROR_NOT_FOUND;
    
    int l_prev_idx = 0; dap_chain_tx_out_cond_t *l_prev = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_idx);
    if (!l_prev) return DEX_UPDATE_ERROR_NOT_FOUND;
    
    const char *l_sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, &l_tail);
    if (!l_sell_ticker) return DEX_UPDATE_ERROR_NOT_FOUND;

    const char *l_buy_ticker = l_prev->subtype.srv_dex.buy_token;
    
    // Owner check: wallet addr must be equal to order's seller_addr
    dap_chain_addr_t l_wallet_addr;
    {
        dap_chain_addr_t *l_tmp = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
        if ( !l_tmp ) return DEX_UPDATE_ERROR_COMPOSE_TX;
        l_wallet_addr = *l_tmp;
        DAP_DELETE(l_tmp);
    }
    

    if ( !dap_chain_addr_compare(&l_wallet_addr, &l_prev->subtype.srv_dex.seller_addr) )
        return DEX_UPDATE_ERROR_NOT_OWNER;

    // New parameters (fallback to previous values when not provided)
    uint256_t l_new_rate = a_has_new_rate ? a_new_rate : l_prev->subtype.srv_dex.rate;
    uint256_t l_new_value = a_has_new_value ? a_new_value : l_prev->header.value;

    // Compose 1-TX update: IN_COND(l_tail[idx]) + OUT_COND(SRV_DEX new state)
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx)
        return DEX_UPDATE_ERROR_COMPOSE_TX;

    if ( dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_tail, l_prev_idx, 0) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_UPDATE_ERROR_COMPOSE_TX;
    }
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_DEX_ID };
    dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_item_out_cond_create_srv_dex(l_uid, a_net->pub.id, l_new_value,
        a_net->pub.id, l_buy_ticker, l_new_rate, &l_wallet_addr,
        a_order_root, l_prev->subtype.srv_dex.min_fill,
        l_prev->subtype.srv_dex.version, l_prev->subtype.srv_dex.flags, DEX_TX_TYPE_UPDATE, NULL, 0);
    if (!l_out) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_UPDATE_ERROR_COMPOSE_TX;
    }
    // Explicitly mark composer-declared type to be verified later by the verificator
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_out);
    DAP_DELETE(l_out);

    // Delta handling: lock additional sell if increased, or return surplus if decreased
    uint256_t l_delta = uint256_0;
    int l_cmp = compare256(l_new_value, l_prev->header.value);
    if (l_cmp > 0) {
        // Increase: need extra inputs in sell token for delta = new - prev
        SUBTRACT_256_256(l_new_value, l_prev->header.value, &l_delta);
        dap_list_t *l_list_sell_in = NULL;
        uint256_t l_sell_transfer = { };
        if ( dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_sell_ticker, &l_wallet_addr, &l_list_sell_in, l_delta, &l_sell_transfer) == -101 )
            l_list_sell_in = dap_ledger_get_list_tx_outs_with_val(a_net->pub.ledger, l_sell_ticker, &l_wallet_addr, l_delta, &l_sell_transfer);
        if ( !l_list_sell_in ) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_UPDATE_ERROR_COMPOSE_TX;
        }
        uint256_t l_added_sell = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_sell_in);
        dap_list_free_full(l_list_sell_in, NULL);
        if ( !EQUAL_256(l_added_sell, l_sell_transfer) ) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_UPDATE_ERROR_COMPOSE_TX;
        }
    } else if (l_cmp < 0) {
        // Decrease: refund delta = prev - new in sell token to seller
        SUBTRACT_256_256(l_prev->header.value, l_new_value, &l_delta);
        if ( dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_wallet_addr, l_delta, l_sell_ticker) == -1 ) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_UPDATE_ERROR_COMPOSE_TX;
        }
    }

    // Fees: pay validator/network in native token. UTXO selection uses wallet cache first, then falls back to the ledger.
    // Note: this is wallet UTXO cache (not to be confused with DEX order caches).
    uint256_t l_net_fee = { }, l_total_native_fee = a_fee;
    dap_chain_addr_t l_net_addr = { };
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_addr);
    if (l_net_fee_used) SUM_256_256(l_total_native_fee, l_net_fee, &l_total_native_fee);
    if (!IS_ZERO_256(a_fee)) {
        if ( dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1 ) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_UPDATE_ERROR_COMPOSE_TX;
        }
    }
    if (l_net_fee_used) {
        // Pay network from native inputs (+ cashback when input sum exceeds total fees)
        dap_list_t *l_list_fee_out = NULL;
        uint256_t l_fee_transfer = { };
        if ( dap_chain_wallet_cache_tx_find_outs_with_val(a_net, a_net->pub.native_ticker, &l_wallet_addr, &l_list_fee_out, l_total_native_fee, &l_fee_transfer) == -101 )
            l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(a_net->pub.ledger, a_net->pub.native_ticker, &l_wallet_addr, l_total_native_fee, &l_fee_transfer);
        if (!l_list_fee_out) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_UPDATE_ERROR_COMPOSE_TX;
        }
        uint256_t l_added_fee = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
        if ( !EQUAL_256(l_added_fee, l_fee_transfer) ) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_UPDATE_ERROR_COMPOSE_TX;
        }
        if ( dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_addr, l_net_fee, a_net->pub.native_ticker) != 1 ) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_UPDATE_ERROR_COMPOSE_TX;
        }
        // Cashback (l_fee_transfer - l_total_native_fee) in native back to owner
        uint256_t l_fee_back = uint256_0; SUBTRACT_256_256(l_fee_transfer, l_total_native_fee, &l_fee_back);
        if (!IS_ZERO_256(l_fee_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_wallet_addr, l_fee_back, a_net->pub.native_ticker) == -1) { 
                dap_chain_datum_tx_delete(l_tx);
                return DEX_UPDATE_ERROR_COMPOSE_TX;
            }
        }
    }
    // Sign and submit
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    int l_sign_res = dap_chain_datum_tx_add_sign_item(&l_tx, l_key);
    dap_enc_key_delete(l_key);
    if ( l_sign_res != 1 ) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_UPDATE_ERROR_COMPOSE_TX;
    }
    *a_tx = l_tx;
    return DEX_UPDATE_ERROR_OK;
}

static dap_chain_datum_tx_t *s_dex_tx_create_exchange(dap_chain_net_t *a_net, dap_chain_wallet_t *a_wallet,
                                                      dap_hash_fast_t *a_prev_hash, uint256_t a_value_buy,
                                                      uint256_t a_fee)
{
    dap_ret_val_if_any(NULL, !a_net, !a_wallet, !a_prev_hash);

    const char *l_native_ticker = a_net->pub.native_ticker;
    dap_ledger_t *l_ledger = a_net->pub.ledger;

    dap_chain_addr_t *l_wallet_addr = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_wallet_addr)
        return NULL;
    dap_chain_addr_t l_buyer_addr = *l_wallet_addr; DAP_DELETE(l_wallet_addr);

    // Load previous conditional out (tail)
    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(l_ledger, a_prev_hash);
    if (!l_cond_tx)
        return NULL;
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_prev_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_cond_idx);
    if (!l_prev_cond)
        return NULL;
    if (dap_ledger_tx_hash_is_used_out_item(l_ledger, a_prev_hash, l_prev_cond_idx, NULL))
        return NULL;

    const char *l_sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, a_prev_hash);
    if (!l_sell_ticker)
        return NULL;
    const char *l_buy_ticker = l_prev_cond->subtype.srv_dex.buy_token;
    const dap_chain_addr_t *l_seller_addr = &l_prev_cond->subtype.srv_dex.seller_addr;
    uint256_t l_rate = l_prev_cond->subtype.srv_dex.rate;
    if (IS_ZERO_256(l_rate))
        return NULL;

    // Calculate required inputs for buyer (include service fee own if any)
    uint256_t l_value_need = a_value_buy, l_total_fee = a_fee, l_net_fee = uint256_0,
        l_fee_transfer = uint256_0, l_value_transfer = uint256_0, l_srv_fee_est = uint256_0;
    dap_chain_addr_t l_net_fee_addr;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_fee_addr);
    if (l_net_fee_used) SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);
    // DEX service fee (estimate upfront like xchange for input selection)
    dap_chain_addr_t l_srv_addr_est;
    uint16_t l_srv_type_est = 0;
    bool l_srv_used_est = s_dex_get_service_fee(a_net->pub.id, &l_srv_fee_est, &l_srv_addr_est, &l_srv_type_est);
    if (l_srv_used_est) {
        switch (l_srv_type_est) {
        case SERVICE_FEE_NATIVE_PERCENT:
            MULT_256_COIN(l_srv_fee_est, a_value_buy, &l_srv_fee_est);
            SUM_256_256(l_total_fee, l_srv_fee_est, &l_total_fee);
            break;
        case SERVICE_FEE_NATIVE_FIXED:
            SUM_256_256(l_total_fee, l_srv_fee_est, &l_total_fee);
            break;
        case SERVICE_FEE_OWN_PERCENT: {
            MULT_256_COIN(l_srv_fee_est, a_value_buy, &l_srv_fee_est);
            SUM_256_256(l_value_need, l_srv_fee_est, &l_value_need);
            break; }
        case SERVICE_FEE_OWN_FIXED:
            SUM_256_256(l_value_need, l_srv_fee_est, &l_value_need);
            break;
        default: break;
        }
    }

    // Collect inputs in buy token
    dap_list_t *l_list_used_out = NULL, *l_list_fee_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_buy_ticker, &l_buyer_addr, &l_list_used_out, l_value_need, &l_value_transfer) == -101)
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_buy_ticker, &l_buyer_addr, l_value_need, &l_value_transfer);
    if (!l_list_used_out) return NULL;

    bool l_pay_with_native = !dap_strcmp(l_sell_ticker, l_native_ticker),
        l_buy_with_native = !dap_strcmp(l_buy_ticker, l_native_ticker);
    if (!l_pay_with_native) {
        if (l_buy_with_native)
            SUM_256_256(l_value_need, l_total_fee, &l_value_need);
        else {
            if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_native_ticker, &l_buyer_addr, &l_list_fee_out, l_total_fee, &l_fee_transfer) == -101)
                l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker, &l_buyer_addr, l_total_fee, &l_fee_transfer);
            if (!l_list_fee_out) { dap_list_free_full(l_list_used_out, NULL); return NULL; }
        }
    }

    // Create tx and add inputs
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    uint256_t l_added = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_added, l_value_transfer)) {
        dap_chain_datum_tx_delete(l_tx);
        dap_list_free_full(l_list_fee_out, NULL);
        return NULL;
    }
    if (!l_pay_with_native && !l_buy_with_native) {
        uint256_t l_added_fee = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
        dap_list_free_full(l_list_fee_out, NULL);
        if (!EQUAL_256(l_added_fee, l_fee_transfer)) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }

    // Add conditional input from order
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, a_prev_hash, l_prev_cond_idx, 0) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // Compute execution amounts
    uint256_t l_datoshi_sell, l_datoshi_buy = a_value_buy, l_value_back;
    DIV_256_COIN(l_datoshi_buy, l_rate, &l_datoshi_sell);
    if (compare256(l_prev_cond->header.value, l_datoshi_sell) < 0) {
        l_datoshi_sell = l_prev_cond->header.value; // cap by available liquidity
        MULT_256_COIN(l_datoshi_sell, l_rate, &l_datoshi_buy);
        // decrease fee base if needed
    }
    // Transfer selling coins to buyer (sell token)
    uint256_t l_value_sell_to_buyer = l_datoshi_sell;
    if (l_pay_with_native) {
        // Пересчёт фактической суммы native fee: a_fee + net_fee + (service native actual)
        uint256_t l_service_native_actual = uint256_0;
        if (l_srv_used_est && (l_srv_type_est == SERVICE_FEE_NATIVE_FIXED || l_srv_type_est == SERVICE_FEE_NATIVE_PERCENT)) {
            l_service_native_actual = l_srv_fee_est;
            if (l_srv_type_est == SERVICE_FEE_NATIVE_PERCENT)
                MULT_256_COIN(l_service_native_actual, l_datoshi_buy, &l_service_native_actual);
        }
        uint256_t l_total_fee_native_actual = a_fee;
        if (l_net_fee_used)
            SUM_256_256(l_total_fee_native_actual, l_net_fee, &l_total_fee_native_actual);
        if (!IS_ZERO_256(l_service_native_actual))
            SUM_256_256(l_total_fee_native_actual, l_service_native_actual, &l_total_fee_native_actual);
        if (compare256(l_datoshi_sell, l_total_fee_native_actual) <= 0) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        SUBTRACT_256_256(l_datoshi_sell, l_total_fee_native_actual, &l_value_sell_to_buyer);
    }
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_buyer_addr, l_value_sell_to_buyer, l_sell_ticker) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // Residual conditional out (if partial)
    if (compare256(l_prev_cond->header.value, l_datoshi_sell) == 1) {
        SUBTRACT_256_256(l_prev_cond->header.value, l_datoshi_sell, &l_value_back);
        dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_dex(
            (dap_chain_net_srv_uid_t){ .uint64 = DAP_CHAIN_NET_SRV_DEX_ID }, a_net->pub.id, l_value_back,
                a_net->pub.id, l_buy_ticker, l_rate, l_seller_addr,
            &l_prev_cond->subtype.srv_dex.order_root_hash, l_prev_cond->subtype.srv_dex.min_fill,
            l_prev_cond->subtype.srv_dex.version, l_prev_cond->subtype.srv_dex.flags,
                DEX_TX_TYPE_UPDATE, NULL, 0);
        if (!l_tx_out) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        // Preserve combined min_fill byte already passed above
        // If root hash is zero, set root to first tx of the order chain
        if (dap_hash_fast_is_blank(&l_tx_out->subtype.srv_dex.order_root_hash)) {
            dap_hash_fast_t l_root_hash = dap_ledger_get_first_chain_tx_hash(l_ledger, l_cond_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
            l_tx_out->subtype.srv_dex.order_root_hash = l_root_hash;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
    }

    // Transfer buying coins to seller (buy token)
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_seller_addr, l_datoshi_buy, l_buy_ticker) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    // Validator fee
    if (!IS_ZERO_256(a_fee) && dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    // Service fee (DEX) уже оценена и учтена в total_fee/value_need. Добавляем выходы согласно типу (пересчитанные от l_datoshi_buy)
    if (l_srv_used_est) {
        uint256_t l_service_fee = l_srv_fee_est;
        if (l_srv_type_est == SERVICE_FEE_NATIVE_PERCENT || l_srv_type_est == SERVICE_FEE_OWN_PERCENT)
            MULT_256_COIN(l_service_fee, l_datoshi_buy, &l_service_fee);
        if (l_srv_type_est == SERVICE_FEE_NATIVE_PERCENT || l_srv_type_est == SERVICE_FEE_NATIVE_FIXED) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_srv_addr_est, l_service_fee, l_native_ticker) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        } else if (l_srv_type_est == SERVICE_FEE_OWN_PERCENT || l_srv_type_est == SERVICE_FEE_OWN_FIXED) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_srv_addr_est, l_service_fee, l_buy_ticker) == -1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    }
    if (l_net_fee_used) { if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_fee_addr, l_net_fee, l_native_ticker) == -1) { dap_chain_datum_tx_delete(l_tx); return NULL; } }
    // Fee cashback (if separate fee inputs)
    if (!l_pay_with_native && !l_buy_with_native) {
        // Возврат лишнего от нативного бандла: используем фактическую native сумму (net + validator + service_native)
        uint256_t l_service_native_actual = uint256_0;
        if (l_srv_used_est && (l_srv_type_est == SERVICE_FEE_NATIVE_FIXED || l_srv_type_est == SERVICE_FEE_NATIVE_PERCENT)) {
            l_service_native_actual = l_srv_fee_est;
            if (l_srv_type_est == SERVICE_FEE_NATIVE_PERCENT) MULT_256_COIN(l_service_native_actual, l_datoshi_buy, &l_service_native_actual);
        }
        uint256_t l_total_fee_native_actual = a_fee; if (l_net_fee_used) SUM_256_256(l_total_fee_native_actual, l_net_fee, &l_total_fee_native_actual);
        if (!IS_ZERO_256(l_service_native_actual)) SUM_256_256(l_total_fee_native_actual, l_service_native_actual, &l_total_fee_native_actual);
        SUBTRACT_256_256(l_fee_transfer, l_total_fee_native_actual, &l_value_back);
        if (!IS_ZERO_256(l_value_back))
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_buyer_addr, l_value_back, l_native_ticker) == -1) { dap_chain_datum_tx_delete(l_tx); return NULL; }
    }
    // Change in buy token to buyer
    SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
    if (!IS_ZERO_256(l_value_back))
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_buyer_addr, l_value_back, l_buy_ticker) == -1) { dap_chain_datum_tx_delete(l_tx); return NULL; }

    // Sign
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    int l_sign_res = dap_chain_datum_tx_add_sign_item(&l_tx, l_key);
    dap_enc_key_delete(l_key);
    if (l_sign_res != 1) {
        dap_chain_datum_tx_delete(l_tx);      
        return NULL;
    }
    return l_tx;
}

dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase(dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash,
                                        uint256_t a_value_buy, uint256_t a_fee, dap_chain_wallet_t *a_wallet, dap_chain_datum_tx_t **a_tx)
{
    dap_ret_val_if_any(DEX_PURCHASE_ERROR_INVALID_ARGUMENT, !a_net, !a_order_hash, !a_wallet, !a_tx);
    *a_tx = NULL;
    // Find tail
    dap_hash_fast_t l_tail = dap_ledger_get_final_chain_tx_hash(a_net->pub.ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, a_order_hash, false);
    if (dap_hash_fast_is_blank(&l_tail))
        l_tail = *a_order_hash; // fallback: assume provided hash is current
    dap_chain_datum_tx_t *l_tx = s_dex_tx_create_exchange(a_net, a_wallet, &l_tail, a_value_buy, a_fee);
    if (!l_tx)
        return DEX_PURCHASE_ERROR_COMPOSE_TX;
    *a_tx = l_tx;
    return DEX_PURCHASE_ERROR_OK;
}

dap_chain_net_srv_dex_purchase_multi_error_t dap_chain_net_srv_dex_purchase_multi(dap_chain_net_t *a_net,
        dap_hash_fast_t *a_order_hashes, size_t a_orders_count, uint256_t a_value_buy, uint256_t a_fee,
        dap_chain_wallet_t *a_wallet, bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate, dap_chain_datum_tx_t **a_tx)
{
    dap_ret_val_if_any(DEX_PURCHASE_MULTI_ERROR_INVALID_ARGUMENT, !a_net, !a_order_hashes, !a_orders_count, !a_wallet, !a_tx);
    *a_tx = NULL;
    if (a_orders_count == 0) return DEX_PURCHASE_MULTI_ERROR_ORDERS_EMPTY;
    // Build matches directly from hashes (cache-first, then ledger)
    int l_err = DEX_PURCHASE_MULTI_ERROR_OK;
    dex_match_table_entry_t *l_matches = s_dex_matches_build_by_hashes(a_net, a_order_hashes, a_orders_count, a_value_buy, &l_err);
    if (!l_matches)
        return (dap_chain_net_srv_dex_purchase_multi_error_t)(l_err ? l_err : DEX_PURCHASE_MULTI_ERROR_COMPOSE_TX);
    dap_chain_datum_tx_t *l_tx = s_dex_compose_from_match_table(a_net, a_wallet, a_value_buy, a_fee, a_create_buyer_order_on_leftover, a_leftover_rate, l_matches);
    s_dex_match_pair_index_clear(&l_matches);
    if (!l_tx)
        return DEX_PURCHASE_MULTI_ERROR_COMPOSE_TX;
    *a_tx = l_tx;
    return DEX_PURCHASE_MULTI_ERROR_OK;
}

dap_chain_net_srv_dex_purchase_auto_error_t dap_chain_net_srv_dex_purchase_auto(
    dap_chain_net_t *a_net,
    const char *a_sell_token, const char *a_buy_token,
    uint256_t a_value_buy, uint256_t a_fee, uint256_t a_min_rate,
    dap_chain_wallet_t *a_wallet, bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate,
    dap_chain_datum_tx_t **a_tx, dex_match_table_entry_t **a_matches)
{
    dap_ret_val_if_any(DEX_PURCHASE_AUTO_ERROR_INVALID_ARGUMENT,
        !a_net, !a_sell_token, !a_buy_token, !a_wallet, !a_tx, IS_ZERO_256(a_fee), IS_ZERO_256(a_value_buy));
    *a_tx = NULL;
    if (a_matches)
        *a_matches = NULL;
    dex_match_criteria_t l_crit = { .sell_token = a_sell_token, .buy_token = a_buy_token,
        .sell_net_id = a_net->pub.id, .buy_net_id = a_net->pub.id, .max_buy_value = a_value_buy, .min_rate = a_min_rate };
    dex_match_table_entry_t *l_matches = s_dex_matches_build_by_criteria(a_net, &l_crit);
    if (!l_matches)
        return DEX_PURCHASE_AUTO_ERROR_NO_MATCHES;
    dap_chain_datum_tx_t *l_tx = s_dex_compose_from_match_table(a_net, a_wallet, a_value_buy, a_fee,
            a_create_buyer_order_on_leftover, a_leftover_rate, l_matches);
    if (l_tx) {
        if (a_matches)
            *a_matches = l_matches;
        else
            s_dex_matches_clear(&l_matches);
        *a_tx = l_tx;
        return DEX_PURCHASE_AUTO_ERROR_OK;
    } else
        return s_dex_matches_clear(&l_matches), DEX_PURCHASE_AUTO_ERROR_COMPOSE_TX;
}

dap_chain_net_srv_dex_remove_error_t dap_chain_net_srv_dex_remove(dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash,
                                      uint256_t a_fee, dap_chain_wallet_t *a_wallet,
                                      dap_chain_datum_tx_t **a_tx)
{
    dap_ret_val_if_any(DEX_REMOVE_ERROR_INVALID_ARGUMENT, !a_net, !a_order_hash, !a_wallet, !a_tx);
    *a_tx = NULL;
    if ( IS_ZERO_256(a_fee) )
        return DEX_REMOVE_ERROR_FEE_IS_ZERO;
    const char *l_native_ticker = a_net->pub.native_ticker;
    dap_ledger_t *l_ledger = a_net->pub.ledger;
    dap_hash_fast_t l_tail = dap_ledger_get_final_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, a_order_hash, false);
    if (dap_hash_fast_is_blank(&l_tail))
        l_tail = *a_order_hash;
    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(l_ledger, &l_tail);
    if (!l_cond_tx)
        return DEX_REMOVE_ERROR_TX_NOT_FOUND;
    int l_prev_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_prev_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_prev_cond_idx);
    if ( !l_prev_cond || dap_ledger_tx_hash_is_used_out_item(l_ledger, &l_tail, l_prev_cond_idx, NULL) )
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
    uint256_t l_net_fee = {}, l_total_fee = a_fee, l_fee_transfer = {}, l_value_transfer = {}, l_fee_back = {};
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_addr_fee);
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);
    const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_tail);
    bool l_single_channel = l_tx_ticker && !dap_strcmp(l_tx_ticker, l_native_ticker);

    // Create tx
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // in_cond
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_tail, l_prev_cond_idx, 0) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_REMOVE_ERROR_COMPOSE_TX;
    }
    if (!l_single_channel) {
        // gather fee inputs in native
        dap_list_t *l_list_used_out = NULL;
        if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_native_ticker, &l_wallet_addr, &l_list_used_out, l_total_fee, &l_value_transfer) == -101)
            l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker, &l_wallet_addr, l_total_fee, &l_value_transfer);
        if ( !l_list_used_out ) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_REMOVE_ERROR_COMPOSE_TX;
        }
        uint256_t l_added = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        dap_list_free_full(l_list_used_out, NULL);
        if (!EQUAL_256(l_added, l_value_transfer)) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_REMOVE_ERROR_COMPOSE_TX;
        }
        // return coins to owner
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_wallet_addr, l_prev_cond->header.value, l_tx_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_REMOVE_ERROR_COMPOSE_TX;
        }
        // network fee
        if (l_net_fee_used && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_REMOVE_ERROR_COMPOSE_TX;
        }
        // fee cashback
        SUBTRACT_256_256(l_value_transfer, l_total_fee, &l_fee_back);
        if (!IS_ZERO_256(l_fee_back) && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_wallet_addr, l_fee_back, l_native_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_REMOVE_ERROR_COMPOSE_TX;
        }
    } else {
        // single-channel: fee deducted from value
        if (compare256(l_prev_cond->header.value, l_total_fee) <= 0) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_REMOVE_ERROR_COMPOSE_TX;
        }
        uint256_t l_coin_back = {};
        SUBTRACT_256_256(l_prev_cond->header.value, l_total_fee, &l_coin_back);
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_wallet_addr, l_coin_back, l_native_ticker) == -1) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_REMOVE_ERROR_COMPOSE_TX;
        }
        if (l_net_fee_used && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_REMOVE_ERROR_COMPOSE_TX;
        }
    }
    // validator fee
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_REMOVE_ERROR_COMPOSE_TX;
        }
    }
    // sign and put
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    int l_sign_res = dap_chain_datum_tx_add_sign_item(&l_tx, l_key);
    dap_enc_key_delete(l_key);
    if (l_sign_res != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_REMOVE_ERROR_COMPOSE_TX;
    }
    *a_tx = l_tx;
    return DEX_REMOVE_ERROR_OK;
}

// Compose migration TX: IN_COND on SRV_XCHANGE prev + OUT_COND(SRV_DEX)
dap_chain_net_srv_dex_migrate_error_t dap_chain_net_srv_dex_migrate(
    dap_chain_net_t *a_net, dap_hash_fast_t *a_prev_hash,
    uint256_t a_rate_new, uint256_t a_fee,
    dap_chain_wallet_t *a_wallet, dap_chain_datum_tx_t **a_tx)
{
    dap_ret_val_if_any(DEX_MIGRATE_ERROR_INVALID_ARGUMENT, !a_net, !a_prev_hash, !a_wallet, !a_tx, IS_ZERO_256(a_rate_new), IS_ZERO_256(a_fee));
    *a_tx = NULL;
    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_hash(a_net->pub.ledger, a_prev_hash);
    if (!l_prev_tx) return DEX_MIGRATE_ERROR_PREV_NOT_FOUND;
    int l_prev_idx = 0;
    dap_chain_tx_out_cond_t *l_prev_out = dap_chain_datum_tx_out_cond_get(l_prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_prev_idx);
    if (!l_prev_out) return DEX_MIGRATE_ERROR_PREV_NOT_XCHANGE;
    // seller and tokens
    const char *sell_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_net->pub.ledger, a_prev_hash);
    if (!sell_ticker) return DEX_MIGRATE_ERROR_PREV_NOT_FOUND;
    const char *buy_ticker = l_prev_out->subtype.srv_xchange.buy_token;
    // owner wallet addr
    dap_chain_addr_t *l_addr_tmp = dap_chain_wallet_get_addr(a_wallet, a_net->pub.id);
    if (!l_addr_tmp) return DEX_MIGRATE_ERROR_COMPOSE_TX;
    dap_chain_addr_t l_addr = *l_addr_tmp; DAP_DELETE(l_addr_tmp);
    bool l_is_owner = dap_chain_addr_compare(&l_addr, &l_prev_out->subtype.srv_xchange.seller_addr);
    if (!l_is_owner) return DEX_MIGRATE_ERROR_NOT_OWNER;

    // Compose TX with proper fee inputs from wallet (no funds appear from nowhere)
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // 1) Spend previous SRV_XCHANGE conditional out
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, a_prev_hash, l_prev_idx, 0) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_MIGRATE_ERROR_COMPOSE_TX;
    }

    // 2) Collect native inputs for fees (validator + optional network)
    const char *l_native = a_net->pub.native_ticker;
    uint256_t l_net_fee = uint256_0, l_total_native_fee = a_fee, l_fee_transfer = uint256_0;
    dap_chain_addr_t l_net_addr = { };
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_net_addr);
    if (l_net_fee_used) SUM_256_256(l_total_native_fee, l_net_fee, &l_total_native_fee);
    dap_list_t *l_list_fee_in = NULL;
    if (!IS_ZERO_256(l_total_native_fee)) {
        if (dap_chain_wallet_cache_tx_find_outs_with_val(a_net, l_native, &l_addr, &l_list_fee_in, l_total_native_fee, &l_fee_transfer) == -101)
            l_list_fee_in = dap_ledger_get_list_tx_outs_with_val(a_net->pub.ledger, l_native, &l_addr, l_total_native_fee, &l_fee_transfer);
        if (!l_list_fee_in) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_MIGRATE_ERROR_COMPOSE_TX;
        }
        uint256_t l_added_fee = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_in); dap_list_free_full(l_list_fee_in, NULL);
        if (!EQUAL_256(l_added_fee, l_fee_transfer)) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_MIGRATE_ERROR_COMPOSE_TX; }
    }

    // 3) Add SRV_DEX out (lock XCHANGE sell amount with new rate)
    dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_item_out_cond_create_srv_dex((dap_chain_net_srv_uid_t){ .uint64 = DAP_CHAIN_NET_SRV_DEX_ID },
        l_prev_out->subtype.srv_xchange.sell_net_id, l_prev_out->header.value,
        l_prev_out->subtype.srv_xchange.buy_net_id, buy_ticker, a_rate_new,
        &l_addr, NULL, 0, 1, 0, DEX_TX_TYPE_ORDER, NULL, 0);
    if (!l_out) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_MIGRATE_ERROR_COMPOSE_TX;
    }
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_out);
    DAP_DELETE(l_out);

    // 4) Add validator fee item and optional network fee output
    if (!IS_ZERO_256(a_fee)) if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_MIGRATE_ERROR_COMPOSE_TX;
    }
    if (l_net_fee_used) if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_addr, l_net_fee, l_native) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_MIGRATE_ERROR_COMPOSE_TX;
    }
    // 5) Native cashback (change) back to wallet if fee inputs exceed required total
    if (!IS_ZERO_256(l_fee_transfer) && compare256(l_fee_transfer, l_total_native_fee) == 1) {
        uint256_t l_cashback = uint256_0; SUBTRACT_256_256(l_fee_transfer, l_total_native_fee, &l_cashback);
        if (!IS_ZERO_256(l_cashback) && ( dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, l_cashback, l_native) == -1 )) {
            dap_chain_datum_tx_delete(l_tx);
            return DEX_MIGRATE_ERROR_COMPOSE_TX;
        }
    }

    // 6) Sign and submit
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    int l_sign_res = dap_chain_datum_tx_add_sign_item(&l_tx, l_key);
    dap_enc_key_delete(l_key);
    if ( l_sign_res != 1 ) {
        dap_chain_datum_tx_delete(l_tx);
        return DEX_MIGRATE_ERROR_COMPOSE_TX;
    }
    *a_tx = l_tx;
    return DEX_MIGRATE_ERROR_OK;
}
