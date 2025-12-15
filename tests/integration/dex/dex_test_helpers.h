/**
 * @file dex_test_helpers.h
 * @brief Shared helpers for DEX integration tests
 * @details
 * Contains delta calculation, verification, and tampering utilities
 * used by both lifecycle and automatch tests.
 */

#pragma once

#include "dex_test_scenarios.h"
#include "dap_chain_net_srv_dex.h"
#include "dap_chain_datum_tx_items.h"

// ============================================================================
// CONSTANTS
// ============================================================================

#define DEX_TEST_POW18 DAP_DEX_POW18
#define DEX_TEST_NATIVE_FEE_FALLBACK (DAP_DEX_FEE_UNIT_NATIVE * 10)  // 0.1 token

// ============================================================================
// FEE CALCULATION HELPERS
// ============================================================================

/**
 * @brief Get native absolute fee from fee_config
 * @param fee_config Pair fee configuration byte
 * @return Fee amount in native token units
 */
static inline uint128_t dex_test_get_native_srv_fee(uint8_t fee_config) {
    uint8_t mult = fee_config & 0x7F;
    return mult > 0 ? (uint128_t)mult * DAP_DEX_FEE_UNIT_NATIVE : DEX_TEST_NATIVE_FEE_FALLBACK;
}

/**
 * @brief Calculate percentage of value
 * @param value Base value
 * @param pct Percentage (0-100)
 * @return value * pct / 100
 */
static inline uint256_t dex_test_calc_pct(uint256_t value, uint8_t pct) {
    uint256_t result = uint256_0;
    if (pct && !IS_ZERO_256(value)) {
        MULT_256_256(value, GET_256_FROM_64(pct), &result);
        DIV_256(result, GET_256_FROM_64(100), &result);
    }
    return result;
}

/**
 * @brief Adjust buyer deltas for native token fees
 * @details When native token is traded, net_fee affects buyer spending/receiving
 */
static inline void dex_test_adjust_native_fee(
    uint8_t side, bool quote_is_native, bool base_is_native, bool buyer_is_net_collector,
    uint128_t net_fee,
    uint128_t *buyer_spending, uint128_t *buyer_receiving)
{
    uint128_t fee = buyer_is_net_collector ? net_fee : 2 * net_fee;
    if (fee == 0) return;
    
    if (side == SIDE_ASK) {
        if (quote_is_native)
            *buyer_spending += fee;
        else if (base_is_native)
            *buyer_receiving -= fee;
    } else {
        if (base_is_native)
            *buyer_spending += fee;
        else if (quote_is_native)
            *buyer_receiving -= fee;
    }
}

/**
 * @brief Adjust buyer deltas for absolute service fee when native is traded
 */
static inline void dex_test_adjust_abs_service_fee(
    uint8_t side, bool quote_is_native, bool base_is_native, uint8_t fee_cfg,
    uint128_t *buyer_spending, uint128_t *buyer_receiving)
{
    if ((fee_cfg & 0x80) || (!quote_is_native && !base_is_native))
        return;
    
    uint128_t abs_fee = dex_test_get_native_srv_fee(fee_cfg);
    
    if (side == SIDE_ASK) {
        if (quote_is_native)
            *buyer_spending += abs_fee;
        else if (base_is_native)
            *buyer_receiving -= abs_fee;
    } else {
        if (base_is_native)
            *buyer_spending += abs_fee;
        else if (quote_is_native)
            *buyer_receiving -= abs_fee;
    }
}

// ============================================================================
// PARTICIPANT CONTEXT
// ============================================================================

typedef struct {
    const dap_chain_addr_t *buyer;
    const dap_chain_addr_t *seller;
    const dap_chain_addr_t *net_fee_collector;
    const dap_chain_addr_t *service_addr;
    bool buyer_is_net_collector;
    bool seller_is_net_collector;
    bool seller_is_service;
} dex_test_participants_t;

// ============================================================================
// EXPECTED DELTAS
// ============================================================================

typedef struct {
    uint128_t buyer_base;
    uint128_t buyer_quote;
    uint128_t seller_base;
    uint128_t seller_quote;
    bool buyer_base_dec;
    bool buyer_quote_dec;
} dex_test_expected_deltas_t;

// ============================================================================
// TAMPERING TYPES
// ============================================================================

typedef struct {
    dap_chain_addr_t *target_addr;
    const char *token;
    uint256_t original_value;
    uint256_t tampered_value;
} dex_tamper_output_data_t;

typedef enum {
    TAMPER_OUT_SELLER_PAYOUT,   // OUT_STD to seller in buy_token
    TAMPER_OUT_BUYER_PAYOUT,    // OUT_STD to buyer in sell_token
    TAMPER_OUT_BUYER_CASHBACK,  // OUT_STD to buyer in buy_token
    TAMPER_OUT_NET_FEE,         // OUT_STD to net_addr in native
    TAMPER_OUT_SRV_FEE,         // OUT_STD to srv_addr in fee_token
    TAMPER_OUT_VALIDATOR_FEE    // OUT_COND subtype=FEE
} dex_tamper_out_type_t;

typedef struct {
    dex_tamper_out_type_t source;
    dex_tamper_out_type_t destination;
    uint256_t transfer_amount;
    const dap_chain_addr_t *seller_addr;
    const dap_chain_addr_t *buyer_addr;
    const dap_chain_addr_t *net_addr;
    const dap_chain_addr_t *srv_addr;
    const char *native_ticker;
    const char *buy_ticker;
    const char *sell_ticker;
    const char *fee_ticker;
} dex_tamper_transfer_data_t;

// ============================================================================
// TX MANIPULATION
// ============================================================================

/**
 * @brief Tamper ts_created in TX header
 */
bool dex_test_tamper_ts_created(dap_chain_datum_tx_t *tx, void *user_data);

/**
 * @brief Resign TX after tampering: strip old sigs, add new with wallet key[0]
 */
int dex_test_resign_tx(dap_chain_datum_tx_t **a_tx, dap_chain_wallet_t *wallet);

/**
 * @brief Inflate output value to target address
 */
bool dex_test_tamper_inflate_output(dap_chain_datum_tx_t *tx, void *user_data);

/**
 * @brief Transfer funds between OUTs (preserves total, fails DEX verifier)
 */
bool dex_test_tamper_transfer_funds(dap_chain_datum_tx_t *tx, void *user_data);

/**
 * @brief Find OUT_COND with SRV_DEX subtype
 */
dap_chain_tx_out_cond_t *dex_test_find_dex_out_cond(dap_chain_datum_tx_t *tx);

/**
 * @brief Tamper order_root_hash in DEX OUT_COND
 * @param user_data NULL = blank hash, otherwise pointer to new hash
 */
bool dex_test_tamper_order_root_hash(dap_chain_datum_tx_t *tx, void *user_data);

/**
 * @brief Tamper tx_type in DEX OUT_COND
 * @param user_data Pointer to uint8_t with new tx_type
 */
bool dex_test_tamper_tx_type(dap_chain_datum_tx_t *tx, void *user_data);

/**
 * @brief Tamper rate in DEX OUT_COND
 * @param user_data Pointer to uint256_t with new rate
 */
bool dex_test_tamper_rate(dap_chain_datum_tx_t *tx, void *user_data);

/**
 * @brief Tamper buy_token in DEX OUT_COND
 * @param user_data Pointer to new token string
 */
bool dex_test_tamper_buy_token(dap_chain_datum_tx_t *tx, void *user_data);

/**
 * @brief Tamper min_fill in DEX OUT_COND
 * @param user_data Pointer to uint8_t with new min_fill
 */
bool dex_test_tamper_min_fill(dap_chain_datum_tx_t *tx, void *user_data);

/**
 * @brief Find OUT value by type
 * @param skip_ptr If not NULL, skip this pointer (for finding different OUT of same type)
 */
uint256_t *dex_test_find_out_value_ex(dap_chain_datum_tx_t *tx, dex_tamper_out_type_t type,
                                       const dex_tamper_transfer_data_t *ctx, uint256_t *skip_ptr);

static inline uint256_t *dex_test_find_out_value(dap_chain_datum_tx_t *tx, dex_tamper_out_type_t type,
                                                  const dex_tamper_transfer_data_t *ctx) {
    return dex_test_find_out_value_ex(tx, type, ctx, NULL);
}

// ============================================================================
// TX ANALYSIS HELPERS
// ============================================================================

/**
 * @brief Count IN_COND items in transaction
 */
int dex_test_count_in_cond(dap_chain_datum_tx_t *tx);

/**
 * @brief Seller info extracted from IN_COND
 */
typedef struct {
    dap_chain_addr_t addr;
    dap_hash_fast_t order_hash;
    uint256_t value;
} dex_test_seller_info_t;

/**
 * @brief Get sellers from IN_COND items via ledger lookup
 * @param tx Transaction to analyze
 * @param ledger Ledger for prev_tx lookup
 * @param sellers Output array (caller allocates, max_count elements)
 * @param max_count Max sellers to extract
 * @return Number of sellers found, or -1 on error
 */
int dex_test_get_sellers_from_tx(dap_chain_datum_tx_t *tx, dap_ledger_t *ledger,
                                  dex_test_seller_info_t *sellers, int max_count);

/**
 * @brief Find seller payout OUT_STD by address and token
 * @return Pointer to value field, or NULL if not found
 */
uint256_t *dex_test_find_seller_payout(dap_chain_datum_tx_t *tx, 
                                        const dap_chain_addr_t *seller_addr,
                                        const char *buy_token);

// ============================================================================
// WALLET UTILITIES
// ============================================================================

/**
 * @brief Get wallet by address comparison
 */
dap_chain_wallet_t *dex_test_wallet_by_addr(dex_test_fixture_t *f, const dap_chain_addr_t *addr);


