/**
 * @file dex_test_scenarios.h
 * @brief Test scenario types and matrix generation for DEX integration tests
 * 
 * Wallet roles:
 *   Alice = ASK seller only, BID buyer
 *   Bob   = BID seller only, ASK buyer  
 *   Carol = Service holder, both sides
 */

#pragma once

#include "dex_test_common.h"

// ============================================================================
// WALLET ABSTRACTION
// ============================================================================

typedef enum {
    WALLET_ALICE = 0,
    WALLET_BOB,
    WALLET_CAROL,
    WALLET_COUNT
} wallet_id_t;

#define SIDE_ASK 0
#define SIDE_BID 1

// ============================================================================
// MIN_FILL ENCODING
// ============================================================================
// Bits 0-6: percentage (0-100)
// Bit 7 (0x80): from_origin (% of original order), else from_current (% of leftover)

#define MINFILL_NONE        0           // No restriction (any partial OK)
#define MINFILL_50_CURRENT  50          // 50% of current leftover
#define MINFILL_75_CURRENT  75          // 75% of current leftover
#define MINFILL_50_ORIGIN   (50 | 0x80) // 50% of original order
#define MINFILL_75_ORIGIN   (75 | 0x80) // 75% of original order
#define MINFILL_AON         100         // All-Or-None (full only)

#define MINFILL_IS_FROM_ORIGIN(mf) (((mf) & 0x80) != 0)
#define MINFILL_PCT(mf)            ((mf) & 0x7F)

// ============================================================================
// ORDER TEMPLATE
// ============================================================================

typedef struct {
    uint8_t side;           // SIDE_ASK or SIDE_BID
    uint8_t min_fill;       // MINFILL_* constant
    wallet_id_t seller;     // Order creator
    const char *amount;     // Sell amount string
    const char *rate;       // Rate string (varies per template for rate-limit tests)
} order_template_t;

// ============================================================================
// BUYER SCENARIO
// ============================================================================

typedef struct {
    wallet_id_t buyer;
    bool expect_fee_waived; // Carol as buyer
    bool do_rollback;       // Rollback after valid TX (false = final)
} buyer_scenario_t;

// ============================================================================
// ORDER TEMPLATES FOR TEST_PAIR
// ============================================================================

/**
 * Standard order templates per TEST_PAIR (8 orders)
 * 
 * Alice ASK (3): varied rates for rate-limit testing
 *   - min_fill=0 (any partial), rate=4.8 (cheapest)
 *   - min_fill=50% current, rate=5.0 (mid)
 *   - min_fill=75% origin, rate=5.2 (most expensive)
 * 
 * Bob BID (3): varied rates (inverse for BID)
 *   - min_fill=0 (any partial), rate=0.21 (best for seller)
 *   - min_fill=50% current, rate=0.20 (mid)
 *   - min_fill=75% origin, rate=0.19 (worst for seller)
 * 
 * Carol (2): service holder as seller
 *   - ASK: min_fill=50%, rate=5.5
 *   - BID: min_fill=50%, rate=0.18
 */
// Order values and rates chosen so Bob accumulates enough KEL:
// 1. Bob gets per KEL pair: 4*20 + 95.18 + 10 = 185.18 KEL (from 2 pairs: 370.36)
// 2. Bob spends on CELL/KEL: 60 (BID lock) + 212 (ASK buy) + 29 (Carol) = 301 KEL
// 3. Remaining margin: ~69 KEL
// Low BID rates (0.5-0.8) give high payout (value/rate) to accumulate BASE tokens
static const order_template_t ORDER_TEMPLATES[] = {
    // Alice ASK orders - realistic rates for CELL/KEL cross-rate ~2.5
    {SIDE_ASK, MINFILL_AON,        WALLET_ALICE, "20.0", "2.5"},  // full only
    {SIDE_ASK, MINFILL_NONE,       WALLET_ALICE, "20.0", "2.6"},  // any partial
    {SIDE_ASK, MINFILL_50_CURRENT, WALLET_ALICE, "20.0", "2.7"},  // 50% of current
    {SIDE_ASK, MINFILL_75_ORIGIN,  WALLET_ALICE, "20.0", "2.8"},  // 75% of origin
    
    // Bob BID orders - LOW rates for HIGH payout (15/0.3=50, 15/0.4=37.5, etc.)
    {SIDE_BID, MINFILL_AON,        WALLET_BOB,   "15.0", "0.3"},  // payout=50
    {SIDE_BID, MINFILL_NONE,       WALLET_BOB,   "15.0", "0.4"},  // payout=37.5
    {SIDE_BID, MINFILL_50_CURRENT, WALLET_BOB,   "15.0", "0.5"},  // payout=30
    {SIDE_BID, MINFILL_75_ORIGIN,  WALLET_BOB,   "15.0", "0.6"},  // payout=25
    
    // Carol orders (service holder as seller)
    {SIDE_ASK, MINFILL_50_CURRENT, WALLET_CAROL, "10.0", "2.3"},  // service seller (rate 2.3 → Bob pays 23 KEL)
    {SIDE_BID, MINFILL_50_CURRENT, WALLET_CAROL, "50.0", "5.0"},  // service buyer
};

#define ORDER_TEMPLATES_COUNT (sizeof(ORDER_TEMPLATES) / sizeof(ORDER_TEMPLATES[0]))

// ============================================================================
// WALLET ACCESSORS
// ============================================================================

static inline dap_chain_wallet_t* get_wallet(dex_test_fixture_t *f, wallet_id_t id) {
    switch (id) {
        case WALLET_ALICE: return f->alice;
        case WALLET_BOB:   return f->bob;
        case WALLET_CAROL: return f->carol;
        default:           return NULL;
    }
}

static inline dap_chain_addr_t* get_wallet_addr(dex_test_fixture_t *f, wallet_id_t id) {
    switch (id) {
        case WALLET_ALICE: return &f->alice_addr;
        case WALLET_BOB:   return &f->bob_addr;
        case WALLET_CAROL: return &f->carol_addr;
        default:           return NULL;
    }
}

static inline const char* get_wallet_name(wallet_id_t id) {
    switch (id) {
        case WALLET_ALICE: return "Alice";
        case WALLET_BOB:   return "Bob";
        case WALLET_CAROL: return "Carol";
        default:           return "Unknown";
    }
}

// ============================================================================
// ROLE HELPERS
// ============================================================================

/**
 * Get regular seller for side (Alice=ASK, Bob=BID)
 */
static inline wallet_id_t get_regular_seller(uint8_t side) {
    return (side == SIDE_ASK) ? WALLET_ALICE : WALLET_BOB;
}

/**
 * Get regular buyer for side (Bob=ASK buyer, Alice=BID buyer)
 */
static inline wallet_id_t get_regular_buyer(uint8_t side) {
    return (side == SIDE_ASK) ? WALLET_BOB : WALLET_ALICE;
}

/**
 * Check if wallet is service holder
 */
static inline bool is_service_wallet(wallet_id_t id) {
    return id == WALLET_CAROL;
}

/**
 * Get min_fill description for logging
 */
static inline const char* get_minfill_desc(uint8_t min_fill) {
    static char buf[32];
    if (min_fill == 0) return "none";
    if (min_fill == 100) return "AON";
    snprintf(buf, sizeof(buf), "%d%%%s", 
             MINFILL_PCT(min_fill),
             MINFILL_IS_FROM_ORIGIN(min_fill) ? " origin" : " current");
    return buf;
}

// ============================================================================
// BUYER SCENARIO GENERATION
// ============================================================================

/**
 * Generate buyer scenarios for given seller
 * 
 * Regular seller (Alice/Bob): opposite_regular → Carol → self
 * Carol seller: Alice → Bob → Carol(self)
 * 
 * @param side Order side
 * @param seller Seller wallet ID
 * @param out Output array (at least 3 elements)
 * @param count Output: number of scenarios
 */
static inline void generate_buyer_scenarios(
    uint8_t side,
    wallet_id_t seller,
    buyer_scenario_t *out,
    size_t *count)
{
    size_t n = 0;
    
    // Self-purchase is now forbidden, so we only test non-self buyers
    // Last scenario is always final (no rollback)
    
    if (seller == WALLET_CAROL) {
        // Service seller: Alice, Bob (Carol self-buy forbidden)
        out[n++] = (buyer_scenario_t){
            .buyer = WALLET_ALICE,
            .expect_fee_waived = false,
            .do_rollback = true
        };
        out[n++] = (buyer_scenario_t){
            .buyer = WALLET_BOB,
            .expect_fee_waived = false,
            .do_rollback = false  // final
        };
    } else {
        // Regular seller: Carol first (rollback), then opposite (keeps tokens)
        wallet_id_t opposite = get_regular_buyer(side);
        out[n++] = (buyer_scenario_t){
            .buyer = WALLET_CAROL,
            .expect_fee_waived = true,
            .do_rollback = true   // rollback after Carol
        };
        out[n++] = (buyer_scenario_t){
            .buyer = opposite,
            .expect_fee_waived = false,
            .do_rollback = false  // final, keeps tokens
        };
    }
    
    *count = n;
}

// ============================================================================
// TOKEN HELPERS
// ============================================================================

/**
 * Get sell/buy tokens based on side and pair
 * ASK: sells BASE, buys QUOTE
 * BID: sells QUOTE, buys BASE
 */
static inline void get_order_tokens(
    const test_pair_config_t *pair,
    uint8_t side,
    const char **out_sell_token,
    const char **out_buy_token)
{
    if (side == SIDE_ASK) {
        *out_sell_token = pair->base_token;
        *out_buy_token = pair->quote_token;
    } else {
        *out_sell_token = pair->quote_token;
        *out_buy_token = pair->base_token;
    }
}

// ============================================================================
// LIFECYCLE PHASE ENUM
// ============================================================================

typedef enum {
    PHASE_CREATE,
    PHASE_FULL_BUY,
    PHASE_PARTIAL_BUY,
    PHASE_SUB_MINFILL,
    PHASE_CANCEL
} lifecycle_phase_t;

// ============================================================================
// TEST EXECUTION CONTEXT
// ============================================================================

typedef struct {
    dex_test_fixture_t *fixture;
    const test_pair_config_t *pair;
    const order_template_t *tmpl;
    dex_order_info_t order;         // Order info (fetched from ledger)
    dap_hash_fast_t order_hash;     // Current order tail hash
    size_t pair_idx;                // Index in TEST_PAIRS
    size_t tmpl_idx;                // Index in ORDER_TEMPLATES
} test_context_t;


