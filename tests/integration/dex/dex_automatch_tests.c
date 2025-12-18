/**
 * @file dex_automatch_tests.c
 * @brief Auto-matcher tests for purchase_auto function
 * 
 * Test groups:
 * - A: Direction=ASK, Budget=buy_token
 * - B: Direction=ASK, Budget=sell_token
 * - C: Direction=BID, Budget=buy_token
 * - D: Direction=BID, Budget=sell_token
 * - W: Buyer role variations (service, net collector)
 * - E: Edge cases (dust, AON conflicts, FIFO)
 */

#include "dex_automatch_tests.h"
#include "dex_test_helpers.h"
#include "dex_test_common.h"
#include "dap_chain_net_srv_dex.h"
#include "dap_chain_wallet.h"
#include "dap_chain_ledger.h"
#include "dap_chain_datum_tx.h"

// ============================================================================
// CONSTANTS
// ============================================================================

#define MAX_MATCHES 32

// ============================================================================
// MULTI-MATCH TAMPERING HELPERS
// ============================================================================

// Context for multi-match tampering (address-based, not index-based)
typedef struct {
    dap_ledger_t *ledger;       // Ledger for seller address lookup
    const char *buy_token;      // Token of seller payouts
    uint256_t transfer_amount;
    int seller_idx_from;        // Which seller to steal FROM (by IN_COND order)
    int seller_idx_to;          // Which seller to give TO
} tamper_cross_seller_ctx_t;

typedef struct {
    dap_ledger_t *ledger;
    const char *buy_token;
    int skip_seller_idx;        // Which seller to skip (by IN_COND order)
} tamper_skip_seller_ctx_t;

typedef struct {
    const dap_chain_addr_t *buyer_addr;
    const dap_chain_addr_t *srv_addr;
    const char *buy_token;        // Cashback token
    const char *fee_token;        // Fee token (may differ)
    uint256_t transfer_amount;
} tamper_fee_steal_ctx_t;

typedef struct {
    int in_cond_idx_a;        // First IN_COND to swap
    int in_cond_idx_b;        // Second IN_COND to swap
} tamper_swap_incond_ctx_t;

typedef struct {
    int in_cond_idx;          // IN_COND to duplicate
} tamper_dup_incond_ctx_t;

typedef struct {
    uint256_t inflate_amount; // Amount to add to leftover
} tamper_leftover_ctx_t;

typedef struct {
    int in_cond_idx_a;
    int in_cond_idx_b;
    dap_hash_fast_t order_hash_0;
    dap_hash_fast_t order_hash_1;
    dap_chain_addr_t seller_0;
    dap_chain_addr_t seller_1;
} tamper_hijack_ctx_t;

typedef struct {
    int in_cond_idx_a;
    int in_cond_idx_b;
    dap_hash_fast_t order_hash_0;
    dap_hash_fast_t order_hash_1;
    dap_chain_addr_t seller_0;
    dap_chain_addr_t seller_1;
    dap_chain_addr_t buyer_addr;
    uint256_t rate_0;
    uint256_t rate_1;
    uint256_t order_value;
} tamper_fake_partial_ctx_t;

// T01: Cross-seller steal — transfer between seller payouts (address-based)
// Must find TWO DIFFERENT seller addresses to be a valid attack
static bool s_tamper_cross_seller(dap_chain_datum_tx_t *tx, void *user_data) {
    tamper_cross_seller_ctx_t *ctx = user_data;
    if (!ctx || !ctx->ledger || !ctx->buy_token) return false;
    
    // Get seller addresses from IN_COND via ledger lookup
    dex_test_seller_info_t sellers[MAX_MATCHES];
    int seller_count = dex_test_get_sellers_from_tx(tx, ctx->ledger, sellers, MAX_MATCHES);
    
    // Find two DIFFERENT seller addresses
    int idx_from = -1, idx_to = -1;
    for (int i = 0; i < seller_count && idx_to < 0; i++) {
        if (idx_from < 0) {
            idx_from = i;
        } else if (!dap_chain_addr_compare(&sellers[i].addr, &sellers[idx_from].addr)) {
            idx_to = i;  // Found different address
        }
    }
    
    if (idx_from < 0 || idx_to < 0) {
        log_it(L_DEBUG, "T01: need at least 2 different seller addresses (have %d sellers)", seller_count);
        return false;
    }
    
    // Find seller payouts by address and token
    uint256_t *val_from = dex_test_find_seller_payout(tx, &sellers[idx_from].addr, ctx->buy_token);
    uint256_t *val_to = dex_test_find_seller_payout(tx, &sellers[idx_to].addr, ctx->buy_token);
    
    if (!val_from || !val_to || val_from == val_to) {
        log_it(L_DEBUG, "T01: seller payouts not found or same pointer");
        return false;
    }
    
    log_it(L_DEBUG, "T01: stealing from seller[%d] to seller[%d], amount=%s",
        idx_from, idx_to, dap_uint256_to_char_ex(ctx->transfer_amount).frac);
    
    // Transfer: from -= amount, to += amount
    SUBTRACT_256_256(*val_from, ctx->transfer_amount, val_from);
    SUM_256_256(*val_to, ctx->transfer_amount, val_to);
    return true;
}

// T02: Skip middle seller — zero out one seller's payout (address-based)
static bool s_tamper_skip_seller(dap_chain_datum_tx_t *tx, void *user_data) {
    tamper_skip_seller_ctx_t *ctx = user_data;
    if (!ctx || !ctx->ledger || !ctx->buy_token) return false;
    
    // Get seller addresses from IN_COND via ledger lookup
    dex_test_seller_info_t sellers[MAX_MATCHES];
    int seller_count = dex_test_get_sellers_from_tx(tx, ctx->ledger, sellers, MAX_MATCHES);
    
    if (ctx->skip_seller_idx >= seller_count) {
        log_it(L_DEBUG, "T02: seller index %d out of range (have %d)",
            ctx->skip_seller_idx, seller_count);
        return false;
    }
    
    // Find seller payout by address and token
    uint256_t *val = dex_test_find_seller_payout(tx, &sellers[ctx->skip_seller_idx].addr, ctx->buy_token);
    if (!val) {
        log_it(L_DEBUG, "T02: seller payout not found for address");
        return false;
    }
    
    *val = uint256_0;
    return true;
}

// T03: Swap IN_COND order + adjust OUT_COND.root_hash (partial attack)
// Attack: swap IN_CONDs AND update leftover root — but don't fix payouts
static bool s_tamper_swap_incond(dap_chain_datum_tx_t *tx, void *user_data) {
    tamper_swap_incond_ctx_t *ctx = user_data;
    if (!ctx) return false;
    
    dap_chain_tx_in_cond_t *cond_a = NULL, *cond_b = NULL;
    dap_chain_tx_out_cond_t *out_cond = NULL;
    int cond_count = 0;
    
    uint8_t *item = NULL;
    size_t item_size = 0;
    TX_ITEM_ITER_TX(item, item_size, tx) {
        if (*item == TX_ITEM_TYPE_IN_COND) {
            if (cond_count == ctx->in_cond_idx_a)
                cond_a = (dap_chain_tx_in_cond_t *)item;
            if (cond_count == ctx->in_cond_idx_b)
                cond_b = (dap_chain_tx_in_cond_t *)item;
            cond_count++;
        } else if (*item == TX_ITEM_TYPE_OUT_COND) {
            dap_chain_tx_out_cond_t *oc = (dap_chain_tx_out_cond_t *)item;
            if (oc->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX &&
                !dap_hash_fast_is_blank(&oc->subtype.srv_dex.order_root_hash))
                out_cond = oc;  // Seller leftover (non-blank root)
        }
    }
    
    if (!cond_a || !cond_b) return false;
    
    // Save original cond_b prev_hash (this was the partial order)
    dap_hash_fast_t orig_b_hash = cond_b->header.tx_prev_hash;
    
    // Swap prev_hash
    dap_hash_fast_t tmp_hash = cond_a->header.tx_prev_hash;
    cond_a->header.tx_prev_hash = cond_b->header.tx_prev_hash;
    cond_b->header.tx_prev_hash = tmp_hash;
    
    // Swap prev_idx
    int tmp_idx = cond_a->header.tx_out_prev_idx;
    cond_a->header.tx_out_prev_idx = cond_b->header.tx_out_prev_idx;
    cond_b->header.tx_out_prev_idx = tmp_idx;
    
    // Quality attack: update OUT_COND.root_hash to match new IN_COND[0]
    // After swap, cond_a contains the full order (now first IN_COND)
    // We point leftover's root to this full order, attempting overflow:
    //   executed(full=10) + leftover(5) = 15 > original(10)
    if (out_cond) {
        out_cond->subtype.srv_dex.order_root_hash = cond_a->header.tx_prev_hash;
    }
    
    return true;
}

// T09: COMPLETE leftover hijack attack (Attack Vector 2)
static bool s_tamper_complete_hijack(dap_chain_datum_tx_t *tx, void *user_data) {
    tamper_hijack_ctx_t *ctx = user_data;
    if (!ctx) return false;
    
    dap_chain_tx_in_cond_t *cond_a = NULL, *cond_b = NULL;
    dap_chain_tx_out_cond_t *seller_leftover = NULL;
    dap_chain_tx_out_std_t *payout_0 = NULL, *payout_1 = NULL;
    int cond_count = 0;
    
    uint8_t *item = NULL;
    size_t item_size = 0;
    TX_ITEM_ITER_TX(item, item_size, tx) {
        if (*item == TX_ITEM_TYPE_IN_COND) {
            if (cond_count == ctx->in_cond_idx_a)
                cond_a = (dap_chain_tx_in_cond_t *)item;
            if (cond_count == ctx->in_cond_idx_b)
                cond_b = (dap_chain_tx_in_cond_t *)item;
            cond_count++;
        } else if (*item == TX_ITEM_TYPE_OUT_COND) {
            dap_chain_tx_out_cond_t *oc = (dap_chain_tx_out_cond_t *)item;
            if (oc->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX &&
                !dap_hash_fast_is_blank(&oc->subtype.srv_dex.order_root_hash))
                seller_leftover = oc;
        }
    }
    
    if (seller_leftover) {
        TX_ITEM_ITER_TX(item, item_size, tx) {
            if (*item != TX_ITEM_TYPE_OUT_STD) continue;
            dap_chain_tx_out_std_t *out = (dap_chain_tx_out_std_t *)item;
            if (dap_strcmp(out->token, seller_leftover->subtype.srv_dex.buy_token))
                continue;
            if (!payout_0 && dap_chain_addr_compare(&out->addr, &ctx->seller_0))
                payout_0 = out;
            else if (!payout_1 && dap_chain_addr_compare(&out->addr, &ctx->seller_1))
                payout_1 = out;
        }
    }
    
    if (!cond_a || !cond_b || !seller_leftover || !payout_0 || !payout_1) {
        log_it(L_DEBUG, "T09: Missing components for complete hijack (need 2 IN_COND, seller leftover, 2 seller payouts)");
        return false;
    }
    
    // Step 1: Swap IN_CONDs (tx_prev_hash and tx_out_prev_idx)
    dap_hash_fast_t tmp_hash = cond_a->header.tx_prev_hash;
    cond_a->header.tx_prev_hash = cond_b->header.tx_prev_hash;
    cond_b->header.tx_prev_hash = tmp_hash;
    
    int tmp_idx = cond_a->header.tx_out_prev_idx;
    cond_a->header.tx_out_prev_idx = cond_b->header.tx_out_prev_idx;
    cond_b->header.tx_out_prev_idx = tmp_idx;
    
    // Step 2: Update OUT_COND.root_hash/seller_addr to point to new IN_COND[0]
    seller_leftover->subtype.srv_dex.order_root_hash = cond_a->header.tx_prev_hash;
    const dap_chain_addr_t *new_leftover_owner = dap_hash_fast_compare(&cond_a->header.tx_prev_hash, &ctx->order_hash_0)
        ? &ctx->seller_0
        : dap_hash_fast_compare(&cond_a->header.tx_prev_hash, &ctx->order_hash_1) ? &ctx->seller_1 : NULL;
    if (!new_leftover_owner)
        return false;
    seller_leftover->subtype.srv_dex.seller_addr = *new_leftover_owner;
    
    // Step 3: Swap seller payout ADDRESSES only (steal payout by redirecting amounts)
    dap_chain_addr_t tmp_addr = payout_0->addr;
    payout_0->addr = payout_1->addr;
    payout_1->addr = tmp_addr;
    
    return true;
}

// T10: Fake-first partial (different rates) with payout/cashback adjustment
// Goal: craft a "consistent" TX that would pass naive checks, but must be rejected by canonical validation.
static bool s_tamper_fake_first_partial_consistent(dap_chain_datum_tx_t *tx, void *user_data) {
    tamper_fake_partial_ctx_t *ctx = user_data;
    if (!ctx) return false;
    
    dap_chain_tx_in_cond_t *cond_a = NULL, *cond_b = NULL;
    dap_chain_tx_out_cond_t *seller_leftover = NULL;
    dap_chain_tx_out_std_t *payout_0 = NULL, *payout_1 = NULL, *buyer_cashback = NULL;
    int cond_count = 0;
    
    uint8_t *item = NULL;
    size_t item_size = 0;
    TX_ITEM_ITER_TX(item, item_size, tx) {
        if (*item == TX_ITEM_TYPE_IN_COND) {
            if (cond_count == ctx->in_cond_idx_a)
                cond_a = (dap_chain_tx_in_cond_t *)item;
            if (cond_count == ctx->in_cond_idx_b)
                cond_b = (dap_chain_tx_in_cond_t *)item;
            cond_count++;
        } else if (*item == TX_ITEM_TYPE_OUT_COND) {
            dap_chain_tx_out_cond_t *oc = (dap_chain_tx_out_cond_t *)item;
            if (oc->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX &&
                !dap_hash_fast_is_blank(&oc->subtype.srv_dex.order_root_hash))
                seller_leftover = oc;
        }
    }
    
    if (seller_leftover) {
        TX_ITEM_ITER_TX(item, item_size, tx) {
            if (*item != TX_ITEM_TYPE_OUT_STD) continue;
            dap_chain_tx_out_std_t *out = (dap_chain_tx_out_std_t *)item;
            if (dap_strcmp(out->token, seller_leftover->subtype.srv_dex.buy_token))
                continue;
            if (!payout_0 && dap_chain_addr_compare(&out->addr, &ctx->seller_0))
                payout_0 = out;
            else if (!payout_1 && dap_chain_addr_compare(&out->addr, &ctx->seller_1))
                payout_1 = out;
            else if (!buyer_cashback && dap_chain_addr_compare(&out->addr, &ctx->buyer_addr))
                buyer_cashback = out;
        }
    }
    
    if (!cond_a || !cond_b || !seller_leftover || !payout_0 || !payout_1 || !buyer_cashback)
        return false;
    
    // Step 1: Swap IN_CONDs (place full at idx0, partial at idx1)
    dap_hash_fast_t tmp_hash = cond_a->header.tx_prev_hash;
    cond_a->header.tx_prev_hash = cond_b->header.tx_prev_hash;
    cond_b->header.tx_prev_hash = tmp_hash;
    
    int tmp_idx = cond_a->header.tx_out_prev_idx;
    cond_a->header.tx_out_prev_idx = cond_b->header.tx_out_prev_idx;
    cond_b->header.tx_out_prev_idx = tmp_idx;
    
    // Step 2: Re-anchor leftover to new IN_COND[0] (root/seller/rate)
    seller_leftover->subtype.srv_dex.order_root_hash = cond_a->header.tx_prev_hash;
    
    const dap_chain_addr_t *new_leftover_owner = dap_hash_fast_compare(&cond_a->header.tx_prev_hash, &ctx->order_hash_0)
        ? &ctx->seller_0
        : dap_hash_fast_compare(&cond_a->header.tx_prev_hash, &ctx->order_hash_1) ? &ctx->seller_1 : NULL;
    const uint256_t *new_leftover_rate = dap_hash_fast_compare(&cond_a->header.tx_prev_hash, &ctx->order_hash_0)
        ? &ctx->rate_0
        : dap_hash_fast_compare(&cond_a->header.tx_prev_hash, &ctx->order_hash_1) ? &ctx->rate_1 : NULL;
    if (!new_leftover_owner || !new_leftover_rate)
        return false;
    
    seller_leftover->subtype.srv_dex.seller_addr = *new_leftover_owner;
    seller_leftover->subtype.srv_dex.rate = *new_leftover_rate;
    
    // Step 3: Make seller payouts consistent with tampered exec (and compensate via buyer cashback)
    if (compare256(ctx->order_value, seller_leftover->header.value) <= 0)
        return false;
    
    uint256_t exec_partial = uint256_0;
    SUBTRACT_256_256(ctx->order_value, seller_leftover->header.value, &exec_partial);
    
    uint256_t new_payout_0 = uint256_0, new_payout_1 = uint256_0;
    if (dap_hash_fast_compare(&cond_a->header.tx_prev_hash, &ctx->order_hash_0)) {
        MULT_256_COIN(exec_partial, ctx->rate_0, &new_payout_0);
        MULT_256_COIN(ctx->order_value, ctx->rate_1, &new_payout_1);
    } else if (dap_hash_fast_compare(&cond_a->header.tx_prev_hash, &ctx->order_hash_1)) {
        MULT_256_COIN(exec_partial, ctx->rate_1, &new_payout_1);
        MULT_256_COIN(ctx->order_value, ctx->rate_0, &new_payout_0);
    } else
        return false;
    
    uint256_t cur_sum = uint256_0, new_sum = uint256_0;
    SUM_256_256(payout_0->value, payout_1->value, &cur_sum);
    SUM_256_256(new_payout_0, new_payout_1, &new_sum);
    
    int cmp = compare256(new_sum, cur_sum);
    if (cmp > 0) {
        uint256_t delta = uint256_0;
        SUBTRACT_256_256(new_sum, cur_sum, &delta);
        if (compare256(buyer_cashback->value, delta) < 0)
            return false;
        SUBTRACT_256_256(buyer_cashback->value, delta, &buyer_cashback->value);
    } else if (cmp < 0) {
        uint256_t delta = uint256_0;
        SUBTRACT_256_256(cur_sum, new_sum, &delta);
        SUM_256_256(buyer_cashback->value, delta, &buyer_cashback->value);
    }
    
    payout_0->value = new_payout_0;
    payout_1->value = new_payout_1;
    
    return true;
}

// T04: Partial exec undercount — reduce exec by inflating seller leftover
static bool s_tamper_partial_undercount(dap_chain_datum_tx_t *tx, void *user_data) {
    tamper_leftover_ctx_t *ctx = user_data;
    if (!ctx) return false;
    
    // Find seller leftover OUT_COND (with non-zero root_hash)
    uint8_t *item = NULL;
    size_t item_size = 0;
    TX_ITEM_ITER_TX(item, item_size, tx) {
        if (*item != TX_ITEM_TYPE_OUT_COND) continue;
        dap_chain_tx_out_cond_t *out_cond = (dap_chain_tx_out_cond_t *)item;
        if (out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX) {
            dap_hash_fast_t zero_hash = {0};
            if (!dap_hash_fast_compare(&out_cond->subtype.srv_dex.order_root_hash, &zero_hash)) {
                // Seller leftover (has root_hash) — inflate value
                SUM_256_256(out_cond->header.value, ctx->inflate_amount, &out_cond->header.value);
                return true;
            }
        }
    }
    return false;
}

// T05: Duplicate IN_COND (double-spend attack)
static bool s_tamper_dup_incond(dap_chain_datum_tx_t *tx, void *user_data) {
    tamper_dup_incond_ctx_t *ctx = user_data;
    if (!ctx) return false;
    
    dap_chain_tx_in_cond_t *target = NULL;
    int cond_count = 0;
    
    uint8_t *item = NULL;
    size_t item_size = 0;
    TX_ITEM_ITER_TX(item, item_size, tx) {
        if (*item != TX_ITEM_TYPE_IN_COND) continue;
        if (cond_count == ctx->in_cond_idx) {
            target = (dap_chain_tx_in_cond_t *)item;
            break;
        }
        cond_count++;
    }
    
    if (!target) return false;
    
    // Find another IN_COND and overwrite with target's data
    cond_count = 0;
    TX_ITEM_ITER_TX(item, item_size, tx) {
        if (*item != TX_ITEM_TYPE_IN_COND) continue;
        if (cond_count != ctx->in_cond_idx) {
            dap_chain_tx_in_cond_t *other = (dap_chain_tx_in_cond_t *)item;
            other->header.tx_prev_hash = target->header.tx_prev_hash;
            other->header.tx_out_prev_idx = target->header.tx_out_prev_idx;
            return true;
        }
        cond_count++;
    }
    return false;
}

// T06: Fee aggregation steal — steal from service fee to buyer cashback (address-based)
static bool s_tamper_fee_to_buyer(dap_chain_datum_tx_t *tx, void *user_data) {
    tamper_fee_steal_ctx_t *ctx = user_data;
    if (!ctx || !ctx->buyer_addr || !ctx->srv_addr || !ctx->buy_token)
        return false;
    
    // Find service fee OUT (to srv_addr in fee_token)
    uint256_t *fee_val = NULL;
    const char *fee_token = ctx->fee_token ? ctx->fee_token : ctx->buy_token;
    
    byte_t *it; size_t sz;
    TX_ITEM_ITER_TX(it, sz, tx) {
        if (*it == TX_ITEM_TYPE_OUT_STD) {
            dap_chain_tx_out_std_t *out = (dap_chain_tx_out_std_t *)it;
            if (dap_chain_addr_compare(&out->addr, ctx->srv_addr) &&
                !dap_strcmp(out->token, fee_token)) {
                fee_val = &out->value;
                break;
            }
        }
    }
    
    // Find buyer cashback OUT (to buyer_addr in buy_token)
    uint256_t *cashback_val = NULL;
    TX_ITEM_ITER_TX(it, sz, tx) {
        if (*it == TX_ITEM_TYPE_OUT_STD) {
            dap_chain_tx_out_std_t *out = (dap_chain_tx_out_std_t *)it;
            if (dap_chain_addr_compare(&out->addr, ctx->buyer_addr) &&
                !dap_strcmp(out->token, ctx->buy_token)) {
                cashback_val = &out->value;
                break;
            }
        }
    }
    
    if (!fee_val || !cashback_val) {
        log_it(L_DEBUG, "T06: fee or cashback not found");
        return false;
    }
    
    // Transfer from fee to cashback
    if (compare256(*fee_val, ctx->transfer_amount) < 0) return false;
    SUBTRACT_256_256(*fee_val, ctx->transfer_amount, fee_val);
    SUM_256_256(*cashback_val, ctx->transfer_amount, cashback_val);
    return true;
}

// T07: Buyer leftover seller_addr tampering (ownership hijack)
static bool s_tamper_buyer_leftover_addr(dap_chain_datum_tx_t *tx, void *user_data) {
    UNUSED(user_data);
    
    // Find buyer leftover OUT_COND (blank root_hash = new order)
    dap_chain_tx_out_cond_t *buyer_leftover = NULL;
    
    uint8_t *item = NULL;
    size_t item_size = 0;
    TX_ITEM_ITER_TX(item, item_size, tx) {
        if (*item != TX_ITEM_TYPE_OUT_COND) continue;
        dap_chain_tx_out_cond_t *out_cond = (dap_chain_tx_out_cond_t *)item;
        if (out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX) {
            dap_hash_fast_t zero_hash = {0};
            if (dap_hash_fast_compare(&out_cond->subtype.srv_dex.order_root_hash, &zero_hash))
                buyer_leftover = out_cond;
        }
    }
    
    if (!buyer_leftover) return false;
    
    // Corrupt seller_addr - change first byte (ownership hijack attempt)
    buyer_leftover->subtype.srv_dex.seller_addr.data.key[0] ^= 0xFF;
    return true;
}

// T08: Seller leftover value inflation
static bool s_tamper_seller_leftover_inflate(dap_chain_datum_tx_t *tx, void *user_data) {
    tamper_leftover_ctx_t *ctx = user_data;
    if (!ctx) return false;
    
    // Find seller leftover OUT_COND (one with non-zero root_hash)
    uint8_t *item = NULL;
    size_t item_size = 0;
    TX_ITEM_ITER_TX(item, item_size, tx) {
        if (*item != TX_ITEM_TYPE_OUT_COND) continue;
        dap_chain_tx_out_cond_t *out_cond = (dap_chain_tx_out_cond_t *)item;
        if (out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX) {
            dap_hash_fast_t zero_hash = {0};
            if (!dap_hash_fast_compare(&out_cond->subtype.srv_dex.order_root_hash, &zero_hash)) {
                // Seller leftover (has root_hash)
                SUM_256_256(out_cond->header.value, ctx->inflate_amount, &out_cond->header.value);
                return true;
            }
        }
    }
    return false;
}

// ============================================================================
// TEST TEMPLATES - GROUP A: ASK + budget_buy
// ============================================================================

// Pairs for testing (from test_pair_configs in dex_test_common.c):
// P0: KEL/USDT  - % fee, neither native
// P1: KEL/TestCoin - % fee, native=QUOTE  
// P2: CELL/USDT - abs fee, neither native (config 6)
// P3: CELL/USDC - exempt pair, zero fee (config 7)

static const automatch_test_template_t s_group_a_tests[] = {
    // ========== BASIC BUDGET SCENARIOS (no leftover) ==========
    // A01: Partial budget, single match, cashback
    {
        .name = "A01",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "10.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 1,
        .expected_exec_sell = NULL, .expected_exec_buy = NULL,
        .expect_leftover_order = false, .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // A02: Partial budget, multi-match, cashback
    {
        .name = "A02",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "50.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,  // Multiple matches expected
        .expected_exec_sell = NULL, .expected_exec_buy = NULL,
        .expect_leftover_order = false, .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // A03: Exact budget for two orders (10+10=20)
    {
        .name = "A03",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "20.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expected_exec_sell = NULL, .expected_exec_buy = "20.0",
        .expect_leftover_order = false, .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // A04: Overflow budget, drains orderbook + cashback
    {
        .name = "A04",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "1000.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expected_exec_sell = NULL, .expected_exec_buy = NULL,
        .expect_leftover_order = false, .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // ========== RATE FILTER SCENARIOS ==========
    // min_rate semantics: max acceptable price for buyer (reject orders with rate > min_rate)
    // A05: Rate filter - filters expensive orders (rate > 2.55)
    {
        .name = "A05",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "100.0", .is_budget_buy = true,
        .min_rate = "2.55",  // Accept rate <= 2.55, reject 2.6, 2.8, 3.0
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,  // Matches rate=2.5, 2.55
        .expected_exec_sell = NULL, .expected_exec_buy = NULL,
        .expect_leftover_order = false, .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // A06: Rate filter - filters ALL orders (all rates > 2.0) → NO_MATCHES error
    {
        .name = "A06",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "100.0", .is_budget_buy = true,
        .min_rate = "2.0",  // All orders have rate > 2.0, none accepted
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 0,
        .expected_exec_sell = NULL, .expected_exec_buy = NULL,
        .expect_leftover_order = false, .expect_cashback = false,
        .expected_error = 6,  // DEX_PURCHASE_AUTO_ERROR_NO_MATCHES
        .buyer = WALLET_BOB
    },
    // ========== FEE POLICY SCENARIOS ==========
    // A07: Native=QUOTE fee policy (KEL/TestCoin)
    {
        .name = "A07",
        .sell_token = "TestCoin", .buy_token = "KEL",
        .budget = "50.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expected_exec_sell = NULL, .expected_exec_buy = NULL,
        .expect_leftover_order = false, .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // A08: Absolute fee policy (CELL/USDT)
    {
        .name = "A08",
        .sell_token = "USDT", .buy_token = "CELL",
        .budget = "50.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expected_exec_sell = NULL, .expected_exec_buy = NULL,
        .expect_leftover_order = false, .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // A09: Exempt pair, zero fee (CELL/USDC)
    {
        .name = "A09",
        .sell_token = "USDC", .buy_token = "CELL",
        .budget = "50.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expected_exec_sell = NULL, .expected_exec_buy = NULL,
        .expect_leftover_order = false, .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // ========== LEFTOVER ORDER SCENARIOS (last) ==========
    // A10: Overflow budget + leftover ORDER creation
    {
        .name = "A10",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "1000.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = true, .leftover_rate = "2.5",
        .expected_match_count = -1,
        .expected_exec_sell = NULL, .expected_exec_buy = NULL,
        .expect_leftover_order = true, .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // A11: No match + leftover ORDER (fresh order from full budget)
    {
        .name = "A11",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "100.0", .is_budget_buy = true,
        .min_rate = "2.0",  // All orders filtered (rate > 2.0)
        .create_leftover = true, .leftover_rate = "2.0",
        .expected_match_count = 0,
        .expected_exec_sell = NULL, .expected_exec_buy = NULL,
        .expect_leftover_order = true, .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // A12: Absolute fee policy (CELL/USDT, fee_config=4 → 0.04 TestCoin native)
    // 4 ASK orders seeded: Alice@2.5,2.6,2.8 + Carol@2.6 (10 each)
    // budget=50 CELL matches all 4 orders (40 CELL total), cashback expected
    {
        .name = "A12",
        .sell_token = "USDT", .buy_token = "CELL",
        .budget = "50.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 4,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // A13: Exempt pair (CELL/USDC, fee_config=0x80 → zero service fee)
    // 4 ASK orders seeded: Alice@2.5,2.6,2.8 + Carol@2.6 (10 each)
    {
        .name = "A13",
        .sell_token = "USDC", .buy_token = "CELL",
        .budget = "50.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 4,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
};

// ============================================================================
// TEST TEMPLATES - GROUP B: ASK + budget_sell
// ============================================================================

static const automatch_test_template_t s_group_b_tests[] = {
    // B01: Partial fill
    {
        .name = "B01",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "25.0", .is_budget_buy = false,  // 25 USDT to spend
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // B02: Multi-match
    {
        .name = "B02",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "150.0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // B03: Two orders with cashback
    // Alice@2.5 (25 USDT) + Alice@2.6 (26 USDT) = 51 USDT, 1 USDT cashback
    {
        .name = "B03",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "52.0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 2,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // B04: Drain + cashback
    {
        .name = "B04",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "5000.0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // B05: Drain + leftover ORDER
    {
        .name = "B05",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "5000.0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = true, .leftover_rate = "2.5",
        .expected_match_count = -1,
        .expect_leftover_order = true, .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // B06: Rate filter
    {
        .name = "B06",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "200.0", .is_budget_buy = false,
        .min_rate = "2.5",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // B07: Native=QUOTE
    {
        .name = "B07",
        .sell_token = "TestCoin", .buy_token = "KEL",
        .budget = "100.0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // B08: Abs fee
    {
        .name = "B08",
        .sell_token = "USDT", .buy_token = "CELL",
        .budget = "100.0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
};

// ============================================================================
// TEST TEMPLATES - GROUP C: BID + budget_buy
// Alice as buyer (Bob creates BID orders in seed, Alice creates ASK)
// ============================================================================

static const automatch_test_template_t s_group_c_tests[] = {
    // C01: Multi-match on BID orders
    // BID orders: Bob@0.3,0.4,0.6 + Carol@0.4 (7.5 KEL each, ~2.25-4.5 USDT)
    // budget=10 USDT matches 2+ orders, cashback expected
    {
        .name = "C01",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "10.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,  // Multiple BID matches
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // C02: Multi-match
    {
        .name = "C02",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "100.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // C03: Drain all BID orders
    // All 4 BID orders total ~12.75 USDT, budget=52 matches all with cashback
    {
        .name = "C03",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "52.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,  // All BID orders
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // C04: Drain + cashback (drain all BID orders in orderbook)
    {
        .name = "C04",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "200.0", .is_budget_buy = true,  // Reduced to realistic amount
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // C05: Drain + leftover (budget must fit Alice's KEL balance after leftover conversion)
    {
        .name = "C05",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "100.0", .is_budget_buy = true,  // 100 USDT, leftover ~60 USDT -> 150 KEL
        .min_rate = "0",
        .create_leftover = true, .leftover_rate = "0.4",
        .expected_match_count = -1,
        .expect_leftover_order = true, .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // C06: Rate filter
    {
        .name = "C06",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "200.0", .is_budget_buy = true,
        .min_rate = "0.4",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // C07: Threshold minfill - budget covers multiple BID orders
    {
        .name = "C07",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "30.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,  // Multiple BID matches
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // C08: Native=QUOTE
    {
        .name = "C08",
        .sell_token = "KEL", .buy_token = "TestCoin",
        .budget = "50.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
};

// ============================================================================
// TEST TEMPLATES - GROUP D: BID + budget_sell
// Alice as buyer (Bob creates BID orders in seed)
// ============================================================================

static const automatch_test_template_t s_group_d_tests[] = {
    // D01: Partial fill
    {
        .name = "D01",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "5.0", .is_budget_buy = false,  // Spend 5 KEL
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // D02: Multi-match
    {
        .name = "D02",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "50.0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // D03: Drain + cashback
    {
        .name = "D03",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "1000.0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // D04: Drain + leftover
    {
        .name = "D04",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "1000.0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = true, .leftover_rate = "0.4",
        .expected_match_count = -1,
        .expect_leftover_order = true, .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // D05: Rate filter
    {
        .name = "D05",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "100.0", .is_budget_buy = false,
        .min_rate = "0.4",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // D06: Abs fee
    {
        .name = "D06",
        .sell_token = "CELL", .buy_token = "USDT",
        .budget = "20.0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
};

// ============================================================================
// TEST TEMPLATES - GROUP W: Buyer Role Variations
// ============================================================================

static const automatch_test_template_t s_group_w_tests[] = {
    // W01: Carol (service wallet) - fee waived
    {
        .name = "W01",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "10.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_CAROL
    },
    // W02: Bob as buyer (regular fees) - comparison baseline
    {
        .name = "W02",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "10.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // W03: Carol drains orderbook
    {
        .name = "W03",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "1000.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_CAROL
    },
    // W04: Carol native fee aggregation
    {
        .name = "W04",
        .sell_token = "TestCoin", .buy_token = "KEL",
        .budget = "50.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_CAROL
    },
};

// ============================================================================
// TEST TEMPLATES - GROUP E: Edge Cases
// ============================================================================

static const automatch_test_template_t s_group_e_tests[] = {
    // E01: Min-fill threshold violation - budget too small for 50% min_fill orders
    // Skip first order (rate=2.5, min_fill=0%), target order with rate=2.6 (min_fill=50%)
    // budget=4 KEL < 5 KEL (50% of 10) → should skip to next, but rate=2.8 needs 7.5 KEL (75%)
    // Result: only the first PARTIAL_OK order matches with partial fill
    {
        .name = "E01",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "4.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 1,  // Only first PARTIAL_OK order
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // E02: AON skipped, partial matched after
    // First match is PARTIAL_OK (rate=2.5), full fill. Budget remaining hits AON (rate=2.55).
    // AON @ 2.55 (15 KEL) skipped (budget=5 < 15), next partial @ 2.6 (min_fill=50%=5) exact match.
    {
        .name = "E02",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "15.0", .is_budget_buy = true,  // 10 + 5 = first full + second partial
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 2,  // First PARTIAL_OK + skip AON + second min_fill=50%
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // E03: Min-fill violation - remaining budget < min_fill threshold
    // budget=14 KEL: full fill first order (10 KEL), 4 KEL remaining
    // Next order (rate=2.6, min_fill=50%=5 KEL) → 4 < 5 → skip
    // All remaining orders have min_fill > 4 KEL → all skipped
    {
        .name = "E03",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "14.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 1,  // Only first PARTIAL_OK order matched
        .expect_cashback = true,    // 4 KEL cashback
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // E04: Self-skip with continuation - own order exists in matching set
    // Carol BUYS KEL with USDT → matcher looks for ASK orders
    // Order sequence: Alice@2.5(10) → AON@2.55(15) → Alice@2.6(10) → Carol@2.6(skip) → Alice@2.8(10)
    // With budget=40, matches: Alice@2.5(10), AON@2.55(15), Alice@2.6(10), skip Carol@2.6, partial Alice@2.8
    // Verifies that Carol's own order is correctly skipped in the middle of matching
    {
        .name = "E04",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "40.0", .is_budget_buy = true,  // Enough to reach Carol@2.6
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 3,  // Alice@2.5 + AON@2.55 + Alice@2.6 (Carol@2.6 skipped, 2.8 min_fill not met)
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_CAROL
    },
    // E05: Dust leftover (budget just over one order payout)
    // Budget 25.001 USDT (sell): [0] @ 2.5 needs 25 USDT → 0.001 USDT dust leftover
    {
        .name = "E05",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "25.001", .is_budget_buy = false,  // Just over one order
        .min_rate = "0",
        .create_leftover = true, .leftover_rate = "2.5",
        .expected_match_count = 1,
        .expect_leftover_order = false,  // Leftover too small (dust)
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // E06: Insufficient balance for sale
    // Bob tries to SELL KEL but has insufficient balance after prior tests
    // This tests graceful handling of balance exhaustion during purchase_auto
    {
        .name = "E06",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "10.0", .is_budget_buy = false,  // Dave has 0 KEL
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 0,
        .expect_cashback = false,
        .expected_error = 7,  // DEX_PURCHASE_AUTO_ERROR_INSUFFICIENT_FUNDS
        .buyer = WALLET_DAVE
    },
    // E07: FIFO tie-break (same rate, earlier timestamp first)
    // budget=15 KEL: [0] full 10, [1] AON skip, [2] partial 5 (min=5)
    // Alice @ 2.6 created before Carol @ 2.6, so Alice matched first
    {
        .name = "E07",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "15.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 2,  // [0] Alice @ 2.5 full, [2] Alice @ 2.6 partial
        .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // E08: Zero budget (unlimited) - match all available liquidity
    // budget=0 means "use all available balance" → drain orderbook
    {
        .name = "E08",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,  // Don't check exact count
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // E09: Dust remainder after multi-match
    // budget=35.01 KEL: 3 orders + 0.01 dust (not enough for min-fill)
    {
        .name = "E09",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "35.01", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 3,  // [0] 10, AON skip, [2] 10, [3] 10, 5.01 left < min
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // E10: Min-fill boundary exact (budget = exactly min_fill threshold)
    // Order [2] @ 2.6 has min_fill=50% = 5 KEL, budget=15 gives exactly 5 after [0]
    {
        .name = "E10",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "15.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 2,  // [0] full 10, [2] partial 5 (exact min-fill)
        .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_BOB
    },
    // E11: Empty orderbook - no orders exist for the pair/direction
    // USDC/KEL pair has no ASK orders seeded (only standard pairs get orders)
    // Buyer tries to buy KEL with USDC → no ASK orders → NO_MATCHES
    {
        .name = "E11",
        .sell_token = "USDC", .buy_token = "KEL",
        .budget = "100.0", .is_budget_buy = true,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 0,
        .expect_cashback = false,
        .expected_error = 6,  // DEX_PURCHASE_AUTO_ERROR_NO_MATCHES
        .buyer = WALLET_ALICE
    },
    // E12: Large multi-match (5+ orders matched in single TX)
    // budget=75 KEL: should match 5+ orders across different rates
    // Tests aggregation of multiple sellers, service fees, payouts
    {
        .name = "E12",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "75.0", .is_budget_buy = true,  // Large budget for 5+ matches
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -5,  // Expect >= 5 matches (negative = minimum)
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB  // Bob has USDT
    },
    // E13: Mixed min_fill policies in single match
    // Budget hits orders with different min_fill: 0% + AON
    // Order@2.5 (min_fill=0%): 10 KEL full, Order@2.55 (AON=15): 15 KEL full
    // Remaining 2.5 KEL < all other min_fill thresholds → rejected
    {
        .name = "E13",
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "27.5", .is_budget_buy = true,  // 10 (0%) + 15 (AON) = 25, 2.5 left
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 2,  // Order@2.5 + AON@2.55, rest rejected
        .expect_cashback = true,
        .expected_error = 0,
        .buyer = WALLET_BOB  // Bob has USDT
    },
};

// ============================================================================
// TEST TEMPLATES - GROUP F: BID Edge Cases (mirror of E for BID direction)
// Alice SELLS KEL → matcher looks for BID orders (buyers of KEL)
// BID orders seeded: Bob@0.3(7.5), Bob@0.4(7.5), Bob@0.6(7.5), Carol@0.4(7.5), Bob AON@0.35(10)
// For seller (Alice), higher rate = better (more USDT per KEL)
// ============================================================================

static const automatch_test_template_t s_group_f_tests[] = {
    // F01: Min-fill threshold violation in BID direction
    // Alice sells 3 KEL, best BID is Bob@0.6 (min_fill=75%=5.625 KEL) → 3 < 5.625 → skip
    // Next Bob@0.4 (min_fill=50%=3.75) → 3 < 3.75 → skip
    // Carol@0.4 (min_fill=50%=3.75) → 3 < 3.75 → skip
    // Bob@0.3 (min_fill=0%) → matches with 3 KEL
    {
        .name = "F01",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "3.0", .is_budget_buy = false,  // Sell 3 KEL
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 1,  // Only Bob@0.3 (min_fill=0%)
        .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // F02: AON skipped in BID, partial matched after
    // Alice sells 20 KEL: Bob@0.6(12.5 full) → 7.5 left → AON@0.35 skip (needs 28.57)
    // → Bob@0.4 skip (min_fill 50%=9.375 > 7.5) → Bob@0.3 partial (min_fill=0%)
    {
        .name = "F02",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "20.0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 2,  // Bob@0.6 full + Bob@0.3 partial (AON and 0.4s skipped)
        .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // F03: Self-skip in BID direction
    // Carol sells KEL → her BID@0.4 should be skipped
    // Bob@0.6(12.5 full) → 7.5 left → Carol@0.4 skip → Bob@0.4 skip (min_fill) → Bob@0.3 partial
    {
        .name = "F03",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "20.0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 2,  // Bob@0.6 + Bob@0.3 (Carol@0.4 self-skip, Bob@0.4 min_fill skip)
        .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_CAROL
    },
    // F04: Zero budget in BID (unlimited) - drain all BID orders
    {
        .name = "F04",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "0", .is_budget_buy = false,
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = -1,  // Don't check exact count
        .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // F05: BID rate filter - min_rate filters low-rate BIDs
    // For seller, min_rate means "minimum acceptable rate" (reject BIDs with rate < min_rate)
    // min_rate=0.5 → only Bob@0.6 matches
    {
        .name = "F05",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "10.0", .is_budget_buy = false,
        .min_rate = "0.5",  // Only accept BIDs with rate >= 0.5
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 1,  // Only Bob@0.6
        .expect_cashback = false,
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
    // F06: BID dust remainder - use Bob@0.3 (min_fill=0%) to avoid min_fill issues
    // Alice sells 25.01 KEL: Bob@0.6(12.5) + others... → 0.01 dust left
    // But since Bob@0.6 has min_fill=75%, we need enough to fill it fully
    // Simplify: just test partial fill that doesn't violate min_fill
    {
        .name = "F06",
        .sell_token = "KEL", .buy_token = "USDT",
        .budget = "12.5", .is_budget_buy = false,  // Exactly Bob@0.6 capacity
        .min_rate = "0",
        .create_leftover = false, .leftover_rate = NULL,
        .expected_match_count = 1,
        .expect_cashback = false,  // Exact match, no dust
        .expected_error = 0,
        .buyer = WALLET_ALICE
    },
};

// ============================================================================
// TAMPERING TEST DESCRIPTORS - GROUP T
// ============================================================================

typedef struct {
    const char *name;
    const char *description;
    tamper_callback_fn tamper_fn;
    void *tamper_ctx;        // Will be set up at runtime
    // Base scenario: multi-match with partial fill
    const char *sell_token;
    const char *buy_token;
    const char *budget;
    bool is_budget_buy;
    const char *min_rate;    // Optional: filter orders by min rate
    bool create_leftover;
    const char *leftover_rate;
    wallet_id_t buyer;
} tamper_test_template_t;

// Static contexts (filled before test with ledger/addresses)
static tamper_cross_seller_ctx_t s_ctx_t01 = { .seller_idx_from = 0, .seller_idx_to = 1 };
static tamper_skip_seller_ctx_t s_ctx_t02 = { .skip_seller_idx = 1 };
static tamper_swap_incond_ctx_t s_ctx_t03 = { .in_cond_idx_a = 0, .in_cond_idx_b = 1 };
static tamper_leftover_ctx_t s_ctx_t04 = { 0 };  // inflate_amount set at runtime
static tamper_dup_incond_ctx_t s_ctx_t05 = { .in_cond_idx = 0 };
static tamper_fee_steal_ctx_t s_ctx_t06 = { 0 };  // filled at runtime
static tamper_leftover_ctx_t s_ctx_t08 = { 0 };  // inflate_amount set at runtime
static tamper_hijack_ctx_t s_ctx_t09 = { .in_cond_idx_a = 0, .in_cond_idx_b = 1 };
static tamper_fake_partial_ctx_t s_ctx_t10 = { .in_cond_idx_a = 0, .in_cond_idx_b = 1 };
static tamper_hijack_ctx_t s_ctx_t11 = { .in_cond_idx_a = 0, .in_cond_idx_b = 1 };  // BID version of T09
static tamper_fake_partial_ctx_t s_ctx_t12 = { .in_cond_idx_a = 0, .in_cond_idx_b = 1 };  // BID version of T10

static const tamper_test_template_t s_group_t_tests[] = {
    // T01: Cross-seller steal — transfer between seller payouts
    {
        .name = "T01",
        .description = "Cross-seller steal: +1 to seller[0], -1 from seller[1]",
        .tamper_fn = s_tamper_cross_seller,
        .tamper_ctx = &s_ctx_t01,
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "50.0", .is_budget_buy = true,
        .create_leftover = false, .leftover_rate = NULL,
        .buyer = WALLET_BOB,
    },
    // T02: Skip middle seller — zero out one seller's payout
    {
        .name = "T02",
        .description = "Skip seller[1] payout (set to 0)",
        .tamper_fn = s_tamper_skip_seller,
        .tamper_ctx = &s_ctx_t02,
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "50.0", .is_budget_buy = true,
        .create_leftover = false, .leftover_rate = NULL,
        .buyer = WALLET_BOB,
    },
    // T03: Swap IN_COND order (quality attack: same rate/mf, different orders)
    // Use KEL/TestCoin pair (no AON between @2.5 and @2.6)
    // Budget 25 KEL: [0]@2.5 full(10), [1]Alice@2.6 full(10), [2]Carol@2.6 partial(5)
    // Swap makes Alice (full) appear as leftover owner → executed+leftover > original
    {
        .name = "T03",
        .description = "Swap IN_COND (quality attack: same rate/mf, overflow check)",
        .tamper_fn = s_tamper_swap_incond,
        .tamper_ctx = &s_ctx_t03,
        .sell_token = "TestCoin", .buy_token = "KEL",  // No AON on this pair!
        .budget = "25.0", .is_budget_buy = true,
        .create_leftover = false, .leftover_rate = NULL,
        .buyer = WALLET_BOB,
    },
    // T04: Partial exec undercount — inflate seller leftover
    {
        .name = "T04",
        .description = "Inflate seller leftover (partial undercount)",
        .tamper_fn = s_tamper_partial_undercount,
        .tamper_ctx = &s_ctx_t04,
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "15.0", .is_budget_buy = true,  // Will create partial fill
        .create_leftover = false, .leftover_rate = NULL,
        .buyer = WALLET_BOB,
    },
    // T05: Duplicate IN_COND (double-spend attack)
    {
        .name = "T05",
        .description = "Duplicate IN_COND[0] (double-spend attempt)",
        .tamper_fn = s_tamper_dup_incond,
        .tamper_ctx = &s_ctx_t05,
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "50.0", .is_budget_buy = true,
        .create_leftover = false, .leftover_rate = NULL,
        .buyer = WALLET_BOB,
    },
    // T06: Fee aggregation steal (address-based)
    {
        .name = "T06",
        .description = "Steal from service fee to buyer cashback",
        .tamper_fn = s_tamper_fee_to_buyer,
        .tamper_ctx = &s_ctx_t06,
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "50.0", .is_budget_buy = true,
        .create_leftover = false, .leftover_rate = NULL,
        .buyer = WALLET_BOB,
    },
    // T07: Buyer leftover seller_addr hijack
    {
        .name = "T07",
        .description = "Hijack buyer leftover ownership (change seller_addr)",
        .tamper_fn = s_tamper_buyer_leftover_addr,
        .tamper_ctx = NULL,
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "100.0", .is_budget_buy = true,
        .create_leftover = true, .leftover_rate = "2.5",
        .buyer = WALLET_BOB,
    },
    // T08: Seller leftover value inflation
    {
        .name = "T08",
        .description = "Inflate seller leftover value",
        .tamper_fn = s_tamper_seller_leftover_inflate,
        .tamper_ctx = &s_ctx_t08,
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "15.0", .is_budget_buy = true,  // Partial fill creates seller leftover
        .create_leftover = false, .leftover_rate = NULL,
        .buyer = WALLET_BOB,
    },
    // T09: COMPLETE leftover hijack — full Attack Vector 2
    // Creates exclusive orders Alice@2.0 and Carol@2.0 (same rate, different sellers!)
    // Budget=15: Alice full (10), Carol partial (5)
    // Attack swaps to: Alice partial (5), Carol full (10)
    // If this passes, verifier has critical vulnerability!
    {
        .name = "T09",
        .description = "Complete leftover hijack (Attack Vector 2: same rate)",
        .tamper_fn = s_tamper_complete_hijack,
        .tamper_ctx = &s_ctx_t09,
        .sell_token = "TestCoin", .buy_token = "KEL",
        .budget = "15.0", .is_budget_buy = true,
        .min_rate = NULL,  // Will match exclusive @2.0 orders first
        .create_leftover = false, .leftover_rate = NULL,
        .buyer = WALLET_BOB,
    },
    // T10: Fake-first partial with consistent payouts (different rates)
    {
        .name = "T10",
        .description = "Fake-first partial (different rates) with payout/cashback adjustment",
        .tamper_fn = s_tamper_fake_first_partial_consistent,
        .tamper_ctx = &s_ctx_t10,
        .sell_token = "USDT", .buy_token = "KEL",
        .budget = "15.0", .is_budget_buy = true,
        .min_rate = NULL,
        .create_leftover = false, .leftover_rate = NULL,
        .buyer = WALLET_CAROL,
    },
    // T11: BID version of T09 — Complete leftover hijack for BID orders
    // Creates BID orders: seller sells QUOTE (USDT), wants BASE (KEL)
    // Bob@0.5 and Carol@0.5 (same rate, different sellers)
    // Alice sells KEL → matches both BID orders
    // Attack swaps: Bob partial (5), Carol full (10) → Bob full (10), Carol partial (5)
    {
        .name = "T11",
        .description = "BID: Complete leftover hijack (Attack Vector 2: same rate)",
        .tamper_fn = s_tamper_complete_hijack,
        .tamper_ctx = &s_ctx_t11,
        .sell_token = "KEL", .buy_token = "USDT",  // Alice sells KEL for USDT (matches BID orders)
        .budget = "15.0", .is_budget_buy = false,  // Budget in KEL (sell token)
        .min_rate = NULL,
        .create_leftover = false, .leftover_rate = NULL,
        .buyer = WALLET_ALICE,
    },
    // T12: BID version of T10 — Fake-first partial for BID orders
    // Creates BID orders: Bob@0.5 and Dave@0.476 (different rates)
    // Carol sells KEL → matches BID orders
    {
        .name = "T12",
        .description = "BID: Fake-first partial (different rates) with payout adjustment",
        .tamper_fn = s_tamper_fake_first_partial_consistent,
        .tamper_ctx = &s_ctx_t12,
        .sell_token = "KEL", .buy_token = "USDT",  // Carol sells KEL for USDT
        .budget = "15.0", .is_budget_buy = false,  // Budget in KEL (sell token)
        .min_rate = NULL,
        .create_leftover = false, .leftover_rate = NULL,
        .buyer = WALLET_CAROL,
    },
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static uint256_t s_parse_amount(const char *str) {
    if (!str || !*str || !dap_strcmp(str, "0"))
        return uint256_0;
    return dap_chain_balance_scan(str);
}

// ============================================================================
// TEST EXECUTION
// ============================================================================

int run_automatch_test(dex_test_fixture_t *f, const automatch_test_template_t *tmpl) {
    log_it(L_INFO, "=== AUTOMATCH TEST %s ===", tmpl->name);
    
    // Debug: dump orderbook for E04 (self-skip test)
    if (!strcmp(tmpl->name, "E04")) {
        test_dex_dump_orderbook(f, "Before E04 (self-skip test)");
    }
    
    // Parse parameters
    uint256_t l_budget = s_parse_amount(tmpl->budget);
    uint256_t l_min_rate = s_parse_amount(tmpl->min_rate);
    uint256_t l_leftover_rate = tmpl->leftover_rate ? s_parse_amount(tmpl->leftover_rate) : uint256_0;
    uint256_t l_fee = dap_chain_coins_to_balance("0.05");  // Standard net fee
    
    dap_chain_wallet_t *l_wallet = get_wallet(f, tmpl->buyer);
    if (!l_wallet) {
        log_it(L_ERROR, "Test %s: buyer wallet not found", tmpl->name);
        return -1;
    }
    
    // Take balance snapshot before
    const dap_chain_addr_t *l_buyer_addr = get_wallet_addr(f, tmpl->buyer);
    uint256_t l_buyer_sell_before = dap_ledger_calc_balance(
        f->net->net->pub.ledger, l_buyer_addr, tmpl->sell_token);
    uint256_t l_buyer_buy_before = dap_ledger_calc_balance(
        f->net->net->pub.ledger, l_buyer_addr, tmpl->buy_token);
    
    log_it(L_INFO, "  Buyer %s balance before: %s=%s, %s=%s",
        get_wallet_name(tmpl->buyer),
        tmpl->sell_token, dap_uint256_to_char(l_buyer_sell_before, NULL),
        tmpl->buy_token, dap_uint256_to_char(l_buyer_buy_before, NULL));
    
    // Execute purchase_auto
    dap_chain_datum_tx_t *l_tx = NULL;
    dex_match_table_entry_t *l_matches = NULL;
    
    int l_ret = dap_chain_net_srv_dex_purchase_auto(
        f->net->net,
        tmpl->sell_token,
        tmpl->buy_token,
        l_budget,
        tmpl->is_budget_buy,
        l_fee,
        l_min_rate,
        l_wallet,
        tmpl->create_leftover,
        l_leftover_rate,
        &l_tx,
        &l_matches
    );
    
    // Check expected error
    if (tmpl->expected_error != 0) {
        if (l_ret == 0) {
            log_it(L_ERROR, "Test %s: expected error %d but got success", 
                tmpl->name, tmpl->expected_error);
            DAP_DEL_Z(l_tx);
            return -1;
        }
        if (l_ret != tmpl->expected_error) {
            log_it(L_ERROR, "Test %s: expected error %d but got %d", 
                tmpl->name, tmpl->expected_error, l_ret);
            DAP_DEL_Z(l_tx);
            return -1;
        }
        log_it(L_INFO, "  Test %s: got expected error %d", tmpl->name, l_ret);
        return 0;
    }
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Test %s: purchase_auto failed with %d", tmpl->name, l_ret);
        return -1;
    }
    
    // Count actual matches by IN_COND items in TX
    int l_actual_match_count = l_tx ? dex_test_count_in_cond(l_tx) : 0;
    bool l_has_matches = (l_actual_match_count > 0);
    log_it(L_INFO, "  Match count: %d", l_actual_match_count);
    
    // Verify match expectation:
    //   expected_match_count == 0  → expect no matches
    //   expected_match_count > 0   → expect exact count
    //   expected_match_count == -1 → don't check count (just has_matches)
    //   expected_match_count < -1  → expect >= abs(count), e.g. -5 means ≥5
    if (tmpl->expected_match_count == 0 && l_has_matches) {
        log_it(L_ERROR, "Test %s: expected no matches but got %d", tmpl->name, l_actual_match_count);
        DAP_DEL_Z(l_tx);
        return -1;
    }
    if (tmpl->expected_match_count > 0) {
        if (l_actual_match_count != tmpl->expected_match_count) {
            log_it(L_ERROR, "Test %s: expected %d matches but got %d", 
                tmpl->name, tmpl->expected_match_count, l_actual_match_count);
            DAP_DEL_Z(l_tx);
            return -1;
        }
    }
    if (tmpl->expected_match_count < -1) {
        int l_min_expected = -tmpl->expected_match_count;
        if (l_actual_match_count < l_min_expected) {
            log_it(L_ERROR, "Test %s: expected >= %d matches but got %d",
                tmpl->name, l_min_expected, l_actual_match_count);
            DAP_DEL_Z(l_tx);
            return -1;
        }
    }
    
    // Structural expectations (lightweight)
    dap_chain_tx_out_cond_t *l_out_cond = dex_test_find_dex_out_cond(l_tx);
    if (tmpl->expect_leftover_order) {
        if (!l_out_cond ||
            !dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash) ||
            !dap_chain_addr_compare(&l_out_cond->subtype.srv_dex.seller_addr, l_buyer_addr)) {
            log_it(L_ERROR, "Test %s: expected buyer-leftover OUT_COND (blank root, seller==buyer)", tmpl->name);
            DAP_DEL_Z(l_tx);
            return -1;
        }
    } else if (!tmpl->create_leftover && l_out_cond && dap_hash_fast_is_blank(&l_out_cond->subtype.srv_dex.order_root_hash)) {
        // Error only if leftover was NOT requested but was created
        log_it(L_ERROR, "Test %s: unexpected buyer-leftover OUT_COND (blank root)", tmpl->name);
        DAP_DEL_Z(l_tx);
        return -1;
    }
    
    // E07: Assert FIFO tie-break at same rate (2.6) chooses Alice first
    if (!strcmp(tmpl->name, "E07")) {
        dap_chain_tx_in_cond_t *l_first_in = NULL;
        int l_in_cond_idx = 0;
        uint8_t *item = NULL;
        size_t item_size = 0;
        TX_ITEM_ITER_TX(item, item_size, l_tx) {
            if (*item != TX_ITEM_TYPE_IN_COND) continue;
            if (l_in_cond_idx++ == 0) {
                l_first_in = (dap_chain_tx_in_cond_t *)item;
                break;
            }
        }
        dex_order_info_t l_info = {0};
        if (!l_first_in || test_dex_order_get_info(f->net->net->pub.ledger, &l_first_in->header.tx_prev_hash, &l_info) != 0 ||
            !dap_chain_addr_compare(&l_info.seller_addr, &f->alice_addr)) {
            log_it(L_ERROR, "Test %s: FIFO tie-break verification failed (expected partial from Alice)", tmpl->name);
            DAP_DEL_Z(l_tx);
            return -1;
        }
    }
    
    // Apply TX to ledger
    if (l_tx) {
        size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
        dap_hash_fast_t l_tx_hash;
        dap_hash_fast(l_tx, l_tx_size, &l_tx_hash);
        
        int l_apply_ret = dap_ledger_tx_add(
            f->net->net->pub.ledger, l_tx, &l_tx_hash, false, NULL);
        
        if (l_apply_ret != DAP_LEDGER_CHECK_OK) {
            log_it(L_ERROR, "Test %s: TX apply failed with %d", tmpl->name, l_apply_ret);
            DAP_DEL_Z(l_tx);
            return -1;
        }
        
        // Check balances after
        uint256_t l_buyer_sell_after = dap_ledger_calc_balance(
            f->net->net->pub.ledger, l_buyer_addr, tmpl->sell_token);
        uint256_t l_buyer_buy_after = dap_ledger_calc_balance(
            f->net->net->pub.ledger, l_buyer_addr, tmpl->buy_token);
        
        log_it(L_INFO, "  Buyer balance after: %s=%s, %s=%s",
            tmpl->sell_token, dap_uint256_to_char(l_buyer_sell_after, NULL),
            tmpl->buy_token, dap_uint256_to_char(l_buyer_buy_after, NULL));
        
        //dap_chain_net_srv_dex_dump_history_cache();
        
        // Rollback TX
        int l_rollback_ret = dap_ledger_tx_remove(
            f->net->net->pub.ledger, l_tx, &l_tx_hash);
        
        if (l_rollback_ret != 0) {
            log_it(L_WARNING, "Test %s: rollback failed with %d", tmpl->name, l_rollback_ret);
        }
        //dap_chain_net_srv_dex_dump_history_cache();
        
        // Verify rollback
        uint256_t l_buyer_sell_restored = dap_ledger_calc_balance(
            f->net->net->pub.ledger, l_buyer_addr, tmpl->sell_token);
        uint256_t l_buyer_buy_restored = dap_ledger_calc_balance(
            f->net->net->pub.ledger, l_buyer_addr, tmpl->buy_token);
        
        if (!EQUAL_256(l_buyer_sell_before, l_buyer_sell_restored) ||
            !EQUAL_256(l_buyer_buy_before, l_buyer_buy_restored)) {
            log_it(L_ERROR, "Test %s: rollback verification failed", tmpl->name);
            DAP_DEL_Z(l_tx);
            return -1;
        }
        
        log_it(L_INFO, "  Rollback verified OK");
    }
    
    // Cleanup: matches are freed by dex module, TX by caller
    DAP_DEL_Z(l_tx);
    
    log_it(L_INFO, "  Test %s: PASSED", tmpl->name);
    return 0;
}

static int s_run_test_group(dex_test_fixture_t *f, const char *group_name,
                            const automatch_test_template_t *tests, size_t count,
                            bool a_stop_on_fail) {
    log_it(L_INFO, "======== AUTOMATCH GROUP %s (%zu tests) ========", group_name, count);
    
    int l_passed = 0, l_failed = 0;
    
    for (size_t i = 0; i < count; i++) {
        int ret = run_automatch_test(f, &tests[i]);
        if (ret == 0) {
            l_passed++;
        } else {
            l_failed++;
            if (a_stop_on_fail) {
                log_it(L_ERROR, "Group %s: stopping on first failure (test %s)", 
                    group_name, tests[i].name);
                return -1;
            }
        }
    }
    
    log_it(L_INFO, "Group %s: %d passed, %d failed", group_name, l_passed, l_failed);
    return l_failed;
}

// ============================================================================
// TAMPERING TEST EXECUTION
// ============================================================================

// Helper: create exclusive orders for Attack Vector 2 test
static int s_create_attack_vector_2_orders(dex_test_fixture_t *f, 
                                            const char *sell_token, const char *buy_token,
                                            dap_hash_fast_t *out_alice_hash, dap_hash_fast_t *out_carol_hash)
{
    // Create 2 orders with same rate (2.0) from different sellers
    // These will be matched first (better than existing 2.5+ orders)
    uint256_t l_value = dap_chain_coins_to_balance("10.0");
    uint256_t l_rate = dap_chain_coins_to_balance("2.0");
    
    dap_chain_wallet_t *l_alice = get_wallet(f, WALLET_ALICE);
    dap_chain_wallet_t *l_carol = get_wallet(f, WALLET_CAROL);
    if (!l_alice || !l_carol) return -1;
    
    // Alice order @ 2.0 (minfill=0% = partial OK)
    dap_chain_datum_tx_t *l_tx_alice = NULL;
    dap_chain_net_srv_dex_create_error_t err = dap_chain_net_srv_dex_create(
        f->net->net, buy_token, sell_token, l_value, l_rate, 
        MINFILL_NONE, f->network_fee, l_alice, &l_tx_alice
    );
    if (err != DEX_CREATE_ERROR_OK || !l_tx_alice) {
        log_it(L_ERROR, "T09 setup: failed to create Alice order (err=%d)", err);
        return -1;
    }
    dap_hash_fast(l_tx_alice, dap_chain_datum_tx_get_size(l_tx_alice), out_alice_hash);
    int ret = dap_ledger_tx_add(f->net->net->pub.ledger, l_tx_alice, out_alice_hash, false, NULL);
    if (ret != 0) {
        log_it(L_ERROR, "T09 setup: failed to add Alice order to ledger");
        DAP_DELETE(l_tx_alice);
        return -1;
    }
    log_it(L_INFO, "T09 setup: Alice order @ 2.0 created");
    DAP_DELETE(l_tx_alice);
    
    // Carol order @ 2.0 (minfill=0% = partial OK)
    dap_chain_datum_tx_t *l_tx_carol = NULL;
    err = dap_chain_net_srv_dex_create(
        f->net->net, buy_token, sell_token, l_value, l_rate,
        MINFILL_NONE, f->network_fee, l_carol, &l_tx_carol
    );
    if (err != DEX_CREATE_ERROR_OK || !l_tx_carol) {
        log_it(L_ERROR, "T09 setup: failed to create Carol order (err=%d)", err);
        return -1;
    }
    dap_hash_fast(l_tx_carol, dap_chain_datum_tx_get_size(l_tx_carol), out_carol_hash);
    ret = dap_ledger_tx_add(f->net->net->pub.ledger, l_tx_carol, out_carol_hash, false, NULL);
    if (ret != 0) {
        log_it(L_ERROR, "T09 setup: failed to add Carol order to ledger");
        DAP_DELETE(l_tx_carol);
        return -1;
    }
    log_it(L_INFO, "T09 setup: Carol order @ 2.0 created");
    DAP_DELETE(l_tx_carol);
    
    return 0;
}

static int s_create_t10_orders(dex_test_fixture_t *f,
                                const char *sell_token, const char *buy_token,
                                dap_hash_fast_t *out_alice_hash, dap_hash_fast_t *out_dave_hash)
{
    uint256_t l_value = dap_chain_coins_to_balance("10.0");
    uint256_t l_rate_alice = dap_chain_coins_to_balance("2.0");
    uint256_t l_rate_dave = dap_chain_coins_to_balance("2.1");
    
    if (!f || !sell_token || !buy_token || !out_alice_hash || !out_dave_hash)
        return -1;
    
    // Dave is not funded by default (net fee collector only), fund minimal balances for order creation.
    if (test_dex_fund_wallet(f, f->dave, "KEL", "100.0") != 0 ||
        test_dex_fund_wallet(f, f->dave, "TestCoin", "100.0") != 0) {
        log_it(L_ERROR, "T10 setup: failed to fund Dave");
        return -6;
    }
    
    // Alice order @ 2.0
    dap_chain_datum_tx_t *l_tx_alice = NULL;
    dap_chain_net_srv_dex_create_error_t err = dap_chain_net_srv_dex_create(
        f->net->net, buy_token, sell_token, l_value, l_rate_alice,
        MINFILL_NONE, f->network_fee, f->alice, &l_tx_alice
    );
    if (err != DEX_CREATE_ERROR_OK || !l_tx_alice) {
        log_it(L_ERROR, "T10 setup: failed to create Alice order (err=%d)", err);
        return -2;
    }
    dap_hash_fast(l_tx_alice, dap_chain_datum_tx_get_size(l_tx_alice), out_alice_hash);
    int ret = dap_ledger_tx_add(f->net->net->pub.ledger, l_tx_alice, out_alice_hash, false, NULL);
    if (ret != 0) {
        log_it(L_ERROR, "T10 setup: failed to add Alice order to ledger");
        DAP_DELETE(l_tx_alice);
        return -3;
    }
    log_it(L_INFO, "T10 setup: Alice order @ 2.0 created");
    DAP_DELETE(l_tx_alice);
    
    // Dave order @ 2.1
    dap_chain_datum_tx_t *l_tx_dave = NULL;
    err = dap_chain_net_srv_dex_create(
        f->net->net, buy_token, sell_token, l_value, l_rate_dave,
        MINFILL_NONE, f->network_fee, f->dave, &l_tx_dave
    );
    if (err != DEX_CREATE_ERROR_OK || !l_tx_dave) {
        log_it(L_ERROR, "T10 setup: failed to create Dave order (err=%d)", err);
        return -4;
    }
    dap_hash_fast(l_tx_dave, dap_chain_datum_tx_get_size(l_tx_dave), out_dave_hash);
    ret = dap_ledger_tx_add(f->net->net->pub.ledger, l_tx_dave, out_dave_hash, false, NULL);
    if (ret != 0) {
        log_it(L_ERROR, "T10 setup: failed to add Dave order to ledger");
        DAP_DELETE(l_tx_dave);
        return -5;
    }
    log_it(L_INFO, "T10 setup: Dave order @ 2.1 created");
    DAP_DELETE(l_tx_dave);
    
    return 0;
}

// Helper: create BID orders for Attack Vector 2 (T11)
// BID order: seller sells QUOTE, wants BASE
// For KEL/USDT pair: seller sells USDT, wants KEL
static int s_create_attack_vector_2_orders_bid(dex_test_fixture_t *f,
                                                const char *base_token, const char *quote_token,
                                                dap_hash_fast_t *out_bob_hash, dap_hash_fast_t *out_carol_hash)
{
    // Create 2 BID orders with same rate (0.8 USDT per KEL) from different sellers
    // BID: seller sells QUOTE (USDT), wants BASE (KEL)
    // dap_chain_net_srv_dex_create(net, buy_token=BASE, sell_token=QUOTE, value_of_QUOTE, rate)
    // Rate 0.8 is higher than existing 0.6 orders, so these will be matched first
    uint256_t l_value = dap_chain_coins_to_balance("10.0");  // 10 USDT
    uint256_t l_rate = dap_chain_coins_to_balance("0.8");    // 0.8 USDT/KEL (best rate)
    
    dap_chain_wallet_t *l_bob = get_wallet(f, WALLET_BOB);
    dap_chain_wallet_t *l_carol = get_wallet(f, WALLET_CAROL);
    if (!l_bob || !l_carol) return -1;
    
    // Bob BID order @ 0.5
    dap_chain_datum_tx_t *l_tx_bob = NULL;
    dap_chain_net_srv_dex_create_error_t err = dap_chain_net_srv_dex_create(
        f->net->net, base_token, quote_token, l_value, l_rate,
        MINFILL_NONE, f->network_fee, l_bob, &l_tx_bob
    );
    if (err != DEX_CREATE_ERROR_OK || !l_tx_bob) {
        log_it(L_ERROR, "T11 setup: failed to create Bob BID order (err=%d)", err);
        return -1;
    }
    dap_hash_fast(l_tx_bob, dap_chain_datum_tx_get_size(l_tx_bob), out_bob_hash);
    int ret = dap_ledger_tx_add(f->net->net->pub.ledger, l_tx_bob, out_bob_hash, false, NULL);
    if (ret != 0) {
        log_it(L_ERROR, "T11 setup: failed to add Bob order to ledger");
        DAP_DELETE(l_tx_bob);
        return -1;
    }
    log_it(L_INFO, "T11 setup: Bob BID order @ 0.5 created (sells %s, wants %s)", quote_token, base_token);
    DAP_DELETE(l_tx_bob);
    
    // Carol BID order @ 0.5
    dap_chain_datum_tx_t *l_tx_carol = NULL;
    err = dap_chain_net_srv_dex_create(
        f->net->net, base_token, quote_token, l_value, l_rate,
        MINFILL_NONE, f->network_fee, l_carol, &l_tx_carol
    );
    if (err != DEX_CREATE_ERROR_OK || !l_tx_carol) {
        log_it(L_ERROR, "T11 setup: failed to create Carol BID order (err=%d)", err);
        return -1;
    }
    dap_hash_fast(l_tx_carol, dap_chain_datum_tx_get_size(l_tx_carol), out_carol_hash);
    ret = dap_ledger_tx_add(f->net->net->pub.ledger, l_tx_carol, out_carol_hash, false, NULL);
    if (ret != 0) {
        log_it(L_ERROR, "T11 setup: failed to add Carol order to ledger");
        DAP_DELETE(l_tx_carol);
        return -1;
    }
    log_it(L_INFO, "T11 setup: Carol BID order @ 0.5 created");
    DAP_DELETE(l_tx_carol);
    
    return 0;
}

// Helper: create BID orders for T12 (different rates)
static int s_create_t12_orders_bid(dex_test_fixture_t *f,
                                    const char *base_token, const char *quote_token,
                                    dap_hash_fast_t *out_bob_hash, dap_hash_fast_t *out_dave_hash)
{
    uint256_t l_value = dap_chain_coins_to_balance("10.0");  // 10 USDT
    uint256_t l_rate_bob = dap_chain_coins_to_balance("0.9");   // 0.9 USDT/KEL (best rate)
    uint256_t l_rate_dave = dap_chain_coins_to_balance("0.85"); // 0.85 USDT/KEL (second best)
    
    // Fund Dave
    if (test_dex_fund_wallet(f, f->dave, "KEL", "100.0") != 0 ||
        test_dex_fund_wallet(f, f->dave, "USDT", "100.0") != 0) {
        log_it(L_ERROR, "T12 setup: failed to fund Dave");
        return -6;
    }
    
    // Bob BID order @ 0.5
    dap_chain_datum_tx_t *l_tx_bob = NULL;
    dap_chain_net_srv_dex_create_error_t err = dap_chain_net_srv_dex_create(
        f->net->net, base_token, quote_token, l_value, l_rate_bob,
        MINFILL_NONE, f->network_fee, f->bob, &l_tx_bob
    );
    if (err != DEX_CREATE_ERROR_OK || !l_tx_bob) {
        log_it(L_ERROR, "T12 setup: failed to create Bob BID order (err=%d)", err);
        return -2;
    }
    dap_hash_fast(l_tx_bob, dap_chain_datum_tx_get_size(l_tx_bob), out_bob_hash);
    int ret = dap_ledger_tx_add(f->net->net->pub.ledger, l_tx_bob, out_bob_hash, false, NULL);
    if (ret != 0) {
        log_it(L_ERROR, "T12 setup: failed to add Bob order to ledger");
        DAP_DELETE(l_tx_bob);
        return -3;
    }
    log_it(L_INFO, "T12 setup: Bob BID order @ 0.5 created");
    DAP_DELETE(l_tx_bob);
    
    // Dave BID order @ 0.476
    dap_chain_datum_tx_t *l_tx_dave = NULL;
    err = dap_chain_net_srv_dex_create(
        f->net->net, base_token, quote_token, l_value, l_rate_dave,
        MINFILL_NONE, f->network_fee, f->dave, &l_tx_dave
    );
    if (err != DEX_CREATE_ERROR_OK || !l_tx_dave) {
        log_it(L_ERROR, "T12 setup: failed to create Dave BID order (err=%d)", err);
        return -4;
    }
    dap_hash_fast(l_tx_dave, dap_chain_datum_tx_get_size(l_tx_dave), out_dave_hash);
    ret = dap_ledger_tx_add(f->net->net->pub.ledger, l_tx_dave, out_dave_hash, false, NULL);
    if (ret != 0) {
        log_it(L_ERROR, "T12 setup: failed to add Dave order to ledger");
        DAP_DELETE(l_tx_dave);
        return -5;
    }
    log_it(L_INFO, "T12 setup: Dave BID order @ 0.476 created");
    DAP_DELETE(l_tx_dave);
    
    return 0;
}

static int s_run_tamper_test(dex_test_fixture_t *f, const tamper_test_template_t *tmpl) {
    log_it(L_INFO, "=== TAMPER TEST %s: %s ===", tmpl->name, tmpl->description);
    
    // Special setup for T09/T11: create exclusive orders for Attack Vector 2
    // T09: ASK orders (seller sells BASE, wants QUOTE)
    // T11: BID orders (seller sells QUOTE, wants BASE)
    dap_hash_fast_t l_t09_alice_hash = {0}, l_t09_carol_hash = {0};
    dap_hash_fast_t l_t10_alice_hash = {0}, l_t10_dave_hash = {0};
    dap_hash_fast_t l_t11_bob_hash = {0}, l_t11_carol_hash = {0};
    dap_hash_fast_t l_t12_bob_hash = {0}, l_t12_dave_hash = {0};
    
    if (strcmp(tmpl->name, "T09") == 0) {
        // Create ASK orders: seller sells KEL (buy_token), wants TestCoin (sell_token)
        if (s_create_attack_vector_2_orders(f, tmpl->buy_token, tmpl->sell_token,
                                            &l_t09_alice_hash, &l_t09_carol_hash) != 0) {
            log_it(L_ERROR, "T09: failed to create exclusive orders");
            return -1;
        }
        tamper_hijack_ctx_t *l_ctx = (tamper_hijack_ctx_t *)tmpl->tamper_ctx;
        if (l_ctx) {
            l_ctx->order_hash_0 = l_t09_alice_hash;
            l_ctx->order_hash_1 = l_t09_carol_hash;
            l_ctx->seller_0 = f->alice_addr;
            l_ctx->seller_1 = f->carol_addr;
        }
    } else if (strcmp(tmpl->name, "T10") == 0) {
        if (s_create_t10_orders(f, tmpl->buy_token, tmpl->sell_token,
                                &l_t10_alice_hash, &l_t10_dave_hash) != 0) {
            log_it(L_ERROR, "T10: failed to create exclusive orders");
            return -1;
        }
        tamper_fake_partial_ctx_t *l_ctx = (tamper_fake_partial_ctx_t *)tmpl->tamper_ctx;
        if (l_ctx) {
            l_ctx->order_hash_0 = l_t10_alice_hash;
            l_ctx->order_hash_1 = l_t10_dave_hash;
            l_ctx->seller_0 = f->alice_addr;
            l_ctx->seller_1 = f->dave_addr;
            l_ctx->buyer_addr = f->carol_addr;
            l_ctx->rate_0 = dap_chain_coins_to_balance("2.0");
            l_ctx->rate_1 = dap_chain_coins_to_balance("2.1");
            l_ctx->order_value = dap_chain_coins_to_balance("10.0");
        }
    } else if (strcmp(tmpl->name, "T11") == 0) {
        // Create BID orders: seller sells USDT (buy_token), wants KEL (sell_token)
        // For BID KEL/USDT: seller sells USDT, buys KEL → buy=KEL, sell=USDT
        if (s_create_attack_vector_2_orders_bid(f, tmpl->sell_token, tmpl->buy_token,
                                                 &l_t11_bob_hash, &l_t11_carol_hash) != 0) {
            log_it(L_ERROR, "T11: failed to create exclusive BID orders");
            return -1;
        }
        tamper_hijack_ctx_t *l_ctx = (tamper_hijack_ctx_t *)tmpl->tamper_ctx;
        if (l_ctx) {
            l_ctx->order_hash_0 = l_t11_bob_hash;
            l_ctx->order_hash_1 = l_t11_carol_hash;
            l_ctx->seller_0 = f->bob_addr;
            l_ctx->seller_1 = f->carol_addr;
        }
    } else if (strcmp(tmpl->name, "T12") == 0) {
        // Create BID orders with different rates
        if (s_create_t12_orders_bid(f, tmpl->sell_token, tmpl->buy_token,
                                     &l_t12_bob_hash, &l_t12_dave_hash) != 0) {
            log_it(L_ERROR, "T12: failed to create exclusive BID orders");
            return -1;
        }
        tamper_fake_partial_ctx_t *l_ctx = (tamper_fake_partial_ctx_t *)tmpl->tamper_ctx;
        if (l_ctx) {
            l_ctx->order_hash_0 = l_t12_bob_hash;
            l_ctx->order_hash_1 = l_t12_dave_hash;
            l_ctx->seller_0 = f->bob_addr;
            l_ctx->seller_1 = f->dave_addr;
            l_ctx->buyer_addr = f->carol_addr;
            l_ctx->rate_0 = dap_chain_coins_to_balance("0.9");
            l_ctx->rate_1 = dap_chain_coins_to_balance("0.85");
            l_ctx->order_value = dap_chain_coins_to_balance("10.0");
        }
    }
    
    // Step 1: Create a valid multi-match TX
    uint256_t l_budget = s_parse_amount(tmpl->budget);
    uint256_t l_fee = dap_chain_coins_to_balance("0.05");
    uint256_t l_min_rate = tmpl->min_rate ? s_parse_amount(tmpl->min_rate) : uint256_0;
    uint256_t l_leftover_rate = tmpl->leftover_rate ? s_parse_amount(tmpl->leftover_rate) : uint256_0;
    
    dap_chain_wallet_t *l_wallet = get_wallet(f, tmpl->buyer);
    if (!l_wallet) {
        log_it(L_ERROR, "Tamper %s: wallet not found", tmpl->name);
        return -1;
    }
    
    dap_chain_datum_tx_t *l_tx = NULL;
    dex_match_table_entry_t *l_matches = NULL;
    
    int l_ret = dap_chain_net_srv_dex_purchase_auto(
        f->net->net,
        tmpl->sell_token,
        tmpl->buy_token,
        l_budget,
        tmpl->is_budget_buy,
        l_fee,
        l_min_rate,
        l_wallet,
        tmpl->create_leftover,
        l_leftover_rate,
        &l_tx,
        &l_matches
    );
    
    if (l_ret != 0 || !l_tx) {
        log_it(L_ERROR, "Tamper %s: failed to create base TX (ret=%d)", tmpl->name, l_ret);
        return -1;
    }
    
    // Step 2: Setup runtime context if needed
    dap_chain_addr_t *l_buyer_addr = dap_chain_wallet_get_addr(l_wallet, f->net->net->pub.id);
    
    if (tmpl->tamper_ctx) {
        if (tmpl->tamper_fn == s_tamper_cross_seller) {
            tamper_cross_seller_ctx_t *ctx = (tamper_cross_seller_ctx_t *)tmpl->tamper_ctx;
            ctx->ledger = f->net->net->pub.ledger;
            // Seller receives buyer's sell_token (for ASK: USDT, not KEL)
            ctx->buy_token = tmpl->sell_token;
            ctx->transfer_amount = dap_chain_coins_to_balance("1.0");
        } else if (tmpl->tamper_fn == s_tamper_skip_seller) {
            tamper_skip_seller_ctx_t *ctx = (tamper_skip_seller_ctx_t *)tmpl->tamper_ctx;
            ctx->ledger = f->net->net->pub.ledger;
            ctx->buy_token = tmpl->sell_token;
        } else if (tmpl->tamper_fn == s_tamper_fee_to_buyer) {
            tamper_fee_steal_ctx_t *ctx = (tamper_fee_steal_ctx_t *)tmpl->tamper_ctx;
            ctx->buyer_addr = l_buyer_addr;
            ctx->srv_addr = &f->carol_addr;  // Carol is service fee collector in test fixture
            // Service fee and buyer cashback are in sell_token (USDT for ASK)
            ctx->buy_token = tmpl->sell_token;
            ctx->fee_token = tmpl->sell_token;
            ctx->transfer_amount = dap_chain_coins_to_balance("0.1");
        } else if (tmpl->tamper_fn == s_tamper_partial_undercount ||
                   tmpl->tamper_fn == s_tamper_seller_leftover_inflate) {
            tamper_leftover_ctx_t *ctx = (tamper_leftover_ctx_t *)tmpl->tamper_ctx;
            ctx->inflate_amount = dap_chain_coins_to_balance("5.0");
        }
    }
    
    // Step 3: Apply tampering and verify rejection
    int l_tamper_ret = test_dex_tamper_and_verify_rejection_ex(
        f, l_tx, l_wallet,
        tmpl->tamper_fn,
        (void *)tmpl->tamper_ctx,
        tmpl->description,
        true
    );
    
    DAP_DEL_Z(l_tx);
    
    if (l_tamper_ret != 0) {
        log_it(L_ERROR, "Tamper %s: tampering test failed", tmpl->name);
        return -1;
    }
    
    log_it(L_INFO, "  Tamper test %s: PASSED (TX correctly rejected)", tmpl->name);
    return 0;
}

static int s_run_tamper_group(dex_test_fixture_t *f, bool a_stop_on_fail) {
    size_t count = sizeof(s_group_t_tests) / sizeof(s_group_t_tests[0]);
    log_it(L_INFO, "======== TAMPERING GROUP T (%zu tests) ========", count);
    
    int l_passed = 0, l_failed = 0;
    
    for (size_t i = 0; i < count; i++) {
        int ret = s_run_tamper_test(f, &s_group_t_tests[i]);
        if (ret == 0) {
            l_passed++;
        } else {
            l_failed++;
            if (a_stop_on_fail) {
                log_it(L_ERROR, "Group T: stopping on first failure (test %s)", 
                    s_group_t_tests[i].name);
                return -1;
            }
        }
    }
    
    log_it(L_INFO, "Group T: %d passed, %d failed", l_passed, l_failed);
    return l_failed;
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int run_automatch_tests(dex_test_fixture_t *f) {
    log_it(L_INFO, "================================================================");
    log_it(L_INFO, "           AUTO-MATCHER TESTS");
    log_it(L_INFO, "================================================================");
    
    bool l_stop_on_fail = true;  // Early exit on first failure
    int l_ret;

#define RUN_GROUP(name, arr) do { \
    l_ret = s_run_test_group(f, name, arr, sizeof(arr) / sizeof(arr[0]), l_stop_on_fail); \
    if (l_stop_on_fail && l_ret < 0) { \
        log_it(L_ERROR, "Stopping automatch tests after group %s failure", name); \
        return -1; \
    } \
} while(0)
    
    RUN_GROUP("A", s_group_a_tests);
    RUN_GROUP("B", s_group_b_tests);
    RUN_GROUP("C", s_group_c_tests);
    RUN_GROUP("D", s_group_d_tests);
    RUN_GROUP("W", s_group_w_tests);
    RUN_GROUP("E", s_group_e_tests);
    RUN_GROUP("F", s_group_f_tests);
    
#undef RUN_GROUP
    
    // Run tampering tests (Group T)
    l_ret = s_run_tamper_group(f, l_stop_on_fail);
    if (l_stop_on_fail && l_ret < 0) {
        log_it(L_ERROR, "Stopping automatch tests after group T failure");
        return -1;
    }
    
    log_it(L_INFO, "================================================================");
    log_it(L_INFO, "  AUTOMATCH TESTS COMPLETE: ALL PASSED");
    log_it(L_INFO, "================================================================");
    
    return 0;
}


