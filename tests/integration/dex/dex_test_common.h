/**
 * @file dex_test_common.h
 * @brief Common definitions and structures for DEX integration tests
 * @details
 * This header provides shared types, macros, and forward declarations
 * used across all DEX test groups.
 * 
 * @author Cellframe Development Team
 * @date 2025
 */

#pragma once

#include <stdbool.h>
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_chain_ledger.h"
#include "dap_chain_wallet.h"
#include "../fixtures/test_ledger_fixtures.h"

#define LOG_TAG "dex_test_common"

// ============================================================================
// DECREE TYPES
// ============================================================================

// Decree method types (must match dap_chain_net_srv_dex.c)
typedef enum {
    DEX_DECREE_UNKNOWN,
    DEX_DECREE_FEE_SET,
    DEX_DECREE_PAIR_ADD,
    DEX_DECREE_PAIR_REMOVE,
    DEX_DECREE_PAIR_FEE_SET,
    DEX_DECREE_PAIR_FEE_SET_ALL
} dex_decree_method_t;

// TSD types for decree parameters (must match dap_chain_net_srv_dex.c)
#define DEX_DECREE_TSD_METHOD        0x0000
#define DEX_DECREE_TSD_TOKEN_BASE    0x0001
#define DEX_DECREE_TSD_TOKEN_QUOTE   0x0002
#define DEX_DECREE_TSD_NET_BASE      0x0003
#define DEX_DECREE_TSD_NET_QUOTE     0x0004
#define DEX_DECREE_TSD_FEE_CONFIG    0x0005
#define DEX_DECREE_TSD_FEE_AMOUNT    0x0020
#define DEX_DECREE_TSD_FEE_ADDR      0x0021

// ============================================================================
// ORDER INFO (fetched from ledger on demand)
// ============================================================================

typedef struct dex_order_info {
    dap_hash_fast_t root;
    dap_hash_fast_t tail;
    uint8_t side;              // 0=ASK, 1=BID
    uint256_t price;           // rate
    uint256_t value;           // remaining value
    dap_chain_addr_t seller_addr;
    char token_buy[DAP_CHAIN_TICKER_SIZE_MAX];
    char token_sell[DAP_CHAIN_TICKER_SIZE_MAX];
    uint8_t min_fill;
} dex_order_info_t;

// ============================================================================
// TEST PARAMETERIZATION
// ============================================================================

// Forward declaration for test_scenario_fn
typedef struct dex_test_fixture dex_test_fixture_t;

/**
 * @brief Token pair configuration for parameterized tests
 * @details Defines a specific token pair with associated fee policy.
 * Allows running the same test scenario with different token/fee combinations.
 */
typedef struct test_pair_config {
    const char *base_token;        // Token being traded (e.g., "KEL")
    const char *quote_token;       // Token used for pricing (e.g., "USDT")
    bool quote_is_native;          // true if quote token is native (TestCoin)
    bool base_is_native;           // true if base token is native (TestCoin)
    uint8_t fee_config;            // Fee configuration byte:
                                   //   bit7=1: (fee_config & 0x7F) % fee in QUOTE
                                   //   bit7=0: fee_config absolute units in NATIVE (TestCoin)
    const char *description;       // Human-readable description for logs
} test_pair_config_t;

/**
 * @brief Function signature for parameterized test scenarios
 * @param f Test fixture
 * @param pair Token pair configuration
 * @return 0 on success, negative error code on failure
 */
typedef int (*test_scenario_fn)(dex_test_fixture_t *f, const test_pair_config_t *pair);

// ============================================================================
// TEST FIXTURE
// ============================================================================

/**
 * @brief Network fee collector configuration
 * @details Determines who receives network fee, affecting balance delta calculations
 */
typedef enum {
    NET_FEE_DAVE,   // Separate wallet (neutral case)
    NET_FEE_ALICE,  // Seller may == net collector
    NET_FEE_BOB     // Seller may == net collector
} net_fee_collector_t;

typedef struct dex_test_fixture {
    test_net_fixture_t *net;
    
    dap_chain_wallet_t *alice;
    dap_chain_wallet_t *bob;
    dap_chain_wallet_t *carol;
    dap_chain_wallet_t *dave;      // Network fee collector
    
    dap_chain_addr_t alice_addr;
    dap_chain_addr_t bob_addr;
    dap_chain_addr_t carol_addr;
    dap_chain_addr_t dave_addr;
    
    uint256_t network_fee;
    net_fee_collector_t net_fee_collector;  // Current net fee collector
} dex_test_fixture_t;

// ============================================================================
// FORWARD DECLARATIONS - Decree Helpers
// ============================================================================

int test_decree_pair_add(dap_ledger_t *a_ledger, const char *a_token_base, const char *a_token_quote,
                         dap_chain_net_id_t a_net_id, uint8_t a_fee_config);

int test_decree_pair_fee_set(dap_ledger_t *a_ledger, const char *a_token_base, const char *a_token_quote,
                             dap_chain_net_id_t a_net_id, uint8_t a_fee_config);

int test_decree_fee_set(dap_ledger_t *a_ledger, uint256_t a_fee_amount, const dap_chain_addr_t *a_service_addr);

/**
 * @brief Set network fee collector
 * @param fixture Test fixture
 * @param collector Which wallet collects network fee
 */
void test_set_net_fee_collector(dex_test_fixture_t *fixture, net_fee_collector_t collector);

/**
 * @brief Get current network fee collector address
 * @param fixture Test fixture
 * @return Pointer to collector address
 */
const dap_chain_addr_t* test_get_net_fee_addr(dex_test_fixture_t *fixture);

// ============================================================================
// FORWARD DECLARATIONS - Order Lookup (from ledger)
// ============================================================================

/**
 * @brief Get order info from ledger by hash (root or tail)
 * @param ledger Ledger to search in
 * @param hash Order hash (root or tail)
 * @param out Output structure (filled on success)
 * @return 0 on success, -1 invalid args, -2 tx not found, -3 no DEX out_cond
 */
int test_dex_order_get_info(dap_ledger_t *ledger, const dap_hash_fast_t *hash, dex_order_info_t *out);

// ============================================================================
// FORWARD DECLARATIONS - Tampering Helper
// ============================================================================

// Returns true if tampering was applied, false if skipped (OUT not found)
typedef bool (*tamper_callback_fn)(dap_chain_datum_tx_t *tx, void *user_data);

int test_dex_tamper_and_verify_rejection(
    dex_test_fixture_t *fixture,
    dap_chain_datum_tx_t *tx_template,
    dap_chain_wallet_t *wallet,
    tamper_callback_fn tamper_fn,
    void *tamper_data,
    const char *tamper_description);

int test_dex_add_tx(dex_test_fixture_t *fixture, dap_chain_datum_tx_t *tx);

// ============================================================================
// FORWARD DECLARATIONS - Wallet Funding Helper
// ============================================================================

/**
 * @brief Fund wallet with tokens via emission + transaction
 * @param fixture Test fixture
 * @param wallet Wallet to fund
 * @param token_ticker Token to emit
 * @param amount_str Amount as string (e.g. "10000.0")
 * @return 0 on success, negative error code on failure
 */
int test_dex_fund_wallet(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const char *token_ticker,
    const char *amount_str);

// ============================================================================
// FORWARD DECLARATIONS - Order Creation/Purchase Helpers
// ============================================================================

int test_dex_order_create_ex(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const char *token_buy,
    const char *token_sell,
    const char *amount_sell,
    const char *rate,
    uint8_t min_fill,
    dap_hash_fast_t *out_hash);

int test_dex_order_create(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const char *token_buy,
    const char *token_sell,
    const char *amount_sell,
    const char *rate,
    dap_hash_fast_t *out_hash);

int test_dex_order_purchase_auto(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const char *token_buy,
    const char *token_sell,
    const char *amount_buy,
    bool use_sell_budget,
    bool create_buyer_leftover,
    dap_hash_fast_t *out_hash,
    uint256_t *out_leftover_quote);

int test_dex_order_purchase(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const dap_hash_fast_t *order_hash,
    const char *budget_str,
    dap_hash_fast_t *out_hash);

int test_dex_order_cancel(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const dap_hash_fast_t *order_hash,
    dap_hash_fast_t *out_hash);

int test_dex_order_cancel_all(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const char *token_sell,
    dap_hash_fast_t *out_hash);

int test_dex_order_update(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const dap_hash_fast_t *order_hash,
    const char *new_rate,
    const char *new_value,
    dap_hash_fast_t *out_hash);

// ============================================================================
// FORWARD DECLARATIONS - Balance Verification
// ============================================================================

bool test_dex_verify_balance(dex_test_fixture_t *f, const dap_chain_addr_t *addr,
                             const char *token, const char *expected);

void test_dex_dump_balances(dex_test_fixture_t *f, const char *label);

void test_dex_dump_orderbook(dex_test_fixture_t *f, const char *label);

// ============================================================================
// FORWARD DECLARATIONS - Parameterized Test Runner
// ============================================================================

/**
 * @brief Run a test scenario with multiple token pair configurations
 * @param f Test fixture
 * @param test_name Test name for logging
 * @param scenario Scenario function to execute
 * @param pairs Array of pair configurations
 * @param num_pairs Number of configurations in array
 */
void test_run_parameterized(
    dex_test_fixture_t *f,
    const char *test_name,
    test_scenario_fn scenario,
    const test_pair_config_t *pairs,
    size_t num_pairs);

/**
 * @brief Rollback transaction from ledger
 * @param f Test fixture
 * @param tx_hash Transaction hash to remove
 * @param phase_name Phase name for logging
 * @return 0 on success, negative on error
 */
 int test_dex_rollback_tx(
    dex_test_fixture_t *f,
    dap_hash_fast_t *tx_hash,
    const char *phase_name
);

/**
 * @brief Get standard pair configurations for full coverage
 * @return Pointer to standard pairs array (8 configurations)
 */
const test_pair_config_t* test_get_standard_pairs(void);

/**
 * @brief Get count of standard pair configurations
 * @return Number of standard configurations (8)
 */
size_t test_get_standard_pairs_count(void);

/**
 * @brief Get stratified sample of pair configurations (minimum coverage)
 * @param out_count Output parameter for sample size (4 configurations)
 * @return Pointer to stratified sample array
 * 
 * @details Sample includes:
 * - Config 0: KEL/USDT (2% QUOTE) - baseline
 * - Config 1: KEL/TestCoin (2% QUOTE) - native as QUOTE + fee token
 * - Config 3: KEL/USDT (2 TC absolute) - absolute fee
 * - Config 4: KEL/TestCoin (5 TC absolute) - native as QUOTE + absolute fee
 * 
 * Covers both scenarios where TestCoin is simultaneously QUOTE and fee collection token.
 */
const test_pair_config_t* test_get_stratified_sample(size_t *out_count);

// ============================================================================
// USAGE EXAMPLES
// ============================================================================

/**
 * Example 1: Run test with all 8 standard configurations (full coverage)
 * 
 * void test_group_1_1_scenario(dex_test_fixture_t *f, const test_pair_config_t *pair) {
 *     // Test body using pair->base_token, pair->quote_token, etc.
 * }
 * 
 * void test_group_1_1_order_creation(dex_test_fixture_t *f) {
 *     test_run_parameterized(f, "1.1 Order Creation", 
 *                           test_group_1_1_scenario,
 *                           test_get_standard_pairs(),
 *                           test_get_standard_pairs_count());
 * }
 */

/**
 * Example 2: Run test with stratified sample (4 configurations, fast smoke test)
 * 
 * void test_group_1_2_simple_purchase(dex_test_fixture_t *f) {
 *     size_t sample_count;
 *     const test_pair_config_t *sample = test_get_stratified_sample(&sample_count);
 *     
 *     test_run_parameterized(f, "1.2 Simple Purchase", 
 *                           test_group_1_2_scenario,
 *                           sample, sample_count);
 * }
 * 
 * // This will run test with 4 critical configurations including:
 * // - Native TestCoin as QUOTE token (2 variants: % and absolute fee)
 * // - Non-native USDT as QUOTE token (2 variants: % and absolute fee)
 */

/**
 * Example 3: Run test with custom configuration subset
 * 
 * void test_group_1_3_custom(dex_test_fixture_t *f) {
 *     static const test_pair_config_t custom_pairs[] = {
 *         { "KEL", "USDT", false, false, 0x80|2, "Custom 1" },
 *         { "KEL", "TestCoin", true, false, 5, "Custom 2" }
 *     };
 *     
 *     test_run_parameterized(f, "1.3 Custom Test",
 *                           test_group_1_3_scenario,
 *                           custom_pairs, 2);
 * }
 */

// ============================================================================
// BALANCE SNAPSHOTS - For verifying exchange correctness
// ============================================================================

/**
 * @brief Single wallet balance in context of a specific pair
 */
typedef struct {
    uint256_t base;       // BASE token balance
    uint256_t quote;      // QUOTE token balance
    uint256_t fee_token;  // Fee token balance (TestCoin if different from base/quote)
} wallet_balance_t;

/**
 * @brief Snapshot of all wallets' balances for a specific pair
 */
typedef struct {
    wallet_balance_t alice;
    wallet_balance_t bob;
    wallet_balance_t carol;
    char base_token[DAP_CHAIN_TICKER_SIZE_MAX];
    char quote_token[DAP_CHAIN_TICKER_SIZE_MAX];
    char fee_token[DAP_CHAIN_TICKER_SIZE_MAX];
} balance_snapshot_t;

/**
 * @brief Take snapshot of all wallets' balances
 */
balance_snapshot_t test_dex_take_snapshot(
    dex_test_fixture_t *f,
    const char *base_token,
    const char *quote_token,
    const char *fee_token);

// ============================================================================
// EXCHANGE CALCULATION - Compute min_fill thresholds from order parameters
// ============================================================================

/**
 * @brief Calculated min_fill thresholds for an order
 */
typedef struct {
    uint256_t origin_value;          // Original order value
    uint256_t current_value;         // Current order value
    uint256_t min_from_origin;       // pct% of origin_value
    uint256_t min_from_current;      // pct% of current_value
    uint256_t test_between;          // Value > min_from_current but < min_from_origin
    uint8_t pct;                     // Percentage (0-100)
    bool from_origin;                // true if from_origin policy
} minfill_calc_t;

/**
 * @brief Calculate min_fill thresholds
 * @param origin_value Original order value
 * @param current_value Current order value (may differ after partial)
 * @param min_fill min_fill byte from order
 * @param out Output structure
 */
void test_dex_calc_minfill(
    uint256_t origin_value,
    uint256_t current_value,
    uint8_t min_fill,
    minfill_calc_t *out);

/**
 * @brief Convert BASE amount to QUOTE using rate
 */
static inline uint256_t test_dex_base_to_quote(uint256_t base, uint256_t rate) {
    uint256_t result;
    MULT_256_COIN(base, rate, &result);
    return result;
}

/**
 * @brief Convert QUOTE amount to BASE using rate
 */
static inline uint256_t test_dex_quote_to_base(uint256_t quote, uint256_t rate) {
    uint256_t result;
    DIV_256_COIN(quote, rate, &result);
    return result;
}


// ============================================================================
// DELTA VERIFICATION (uint128 arithmetic)
// ============================================================================

/**
 * @brief Balance snapshot for exchange participant
 */
typedef struct {
    uint256_t base;   // sell_token balance
    uint256_t quote;  // buy_token balance
    uint256_t fee;    // fee token (TestCoin) balance
} balance_snap_t;

/**
 * @brief Take balance snapshot for an address
 */
void test_dex_snap_take(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
                        const char *a_base_token, const char *a_quote_token,
                        balance_snap_t *a_snap);

/**
 * @brief Verify balance changes match expectations
 * @param label Participant label for logging
 * @param before Snapshot before operation
 * @param after Snapshot after operation
 * @param delta_base Expected base token change (uint128)
 * @param base_decreased true if base should decrease
 * @param delta_quote Expected quote token change (uint128)
 * @param quote_decreased true if quote should decrease
 * @return 0 on success, -1 on mismatch
 */
int test_dex_snap_verify(const char *label,
                         const balance_snap_t *before, const balance_snap_t *after,
                         uint128_t delta_base, bool base_decreased,
                         uint128_t delta_quote, bool quote_decreased);

/**
 * @brief Verify fee token (TestCoin) balance change
 */
int test_dex_snap_verify_fee(const char *label,
                             const balance_snap_t *before, const balance_snap_t *after,
                             uint128_t delta_fee, bool fee_decreased);

/**
 * @brief Verify balance delta matches expected value (low-level)
 */
int test_dex_verify_delta(const char *label, uint256_t before, uint256_t after,
                          uint128_t expected, bool decreased);

/**
 * @brief Take balance snapshot using pair tokens (consistent base/quote regardless of order side)
 */
static inline void test_dex_snap_take_pair(dap_ledger_t *ledger, const dap_chain_addr_t *addr,
                                           const test_pair_config_t *pair, balance_snap_t *snap)
{
    test_dex_snap_take(ledger, addr, pair->base_token, pair->quote_token, snap);
}

// ============================================================================
// MIN_FILL TAMPERING - For testing verifier rejection of illegal partial fills
// ============================================================================

/**
 * @brief Adjust min_fill field in order (cache or ledger depending on config)
 * @param fixture Test fixture
 * @param a_order_tail Order tail hash
 * @param a_new_minfill New min_fill value (0 = no restriction, 100 = AON)
 * @param a_out_old_minfill [out] Returns old value for restore (can be NULL)
 * @return 0 on success, -1 invalid args, -2 order not found
 */
int test_dex_adjust_minfill(dex_test_fixture_t *fixture, const dap_hash_fast_t *a_order_tail,
                            uint8_t a_new_minfill, uint8_t *a_out_old_minfill);

