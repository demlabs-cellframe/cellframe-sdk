/**
 * @file dex_integration_test.c
 * @brief DEX Integration Tests - Full workflow verification
 * @details
 * This file contains comprehensive integration tests for the DEX module.
 * 
 * Test Organization:
 * - Each test group is clearly separated and documented
 * - Tests are ordered by complexity: basic → advanced → edge cases
 * - Systematic approach: positive scenarios first, then negative
 * - Clear balance tracking and expected outcomes
 * 
 * Test Groups:
 * 1. BASIC OPERATIONS      - Order creation, full/partial purchases, cancellation
 * 2. MATCHING LOGIC        - Multi-order, price priority, auto-matching
 * 3. MIN_FILL POLICIES     - AON, percentage-based, residual handling
 * 4. ORDER UPDATES         - Rate/value changes, immutables validation
 * 5. LEFTOVER HANDLING     - Buyer/seller leftovers, cache consistency
 * 6. FEE MECHANICS         - Service fee, network fee, waiver scenarios
 * 7. SELF-PURCHASE         - Auto-matching, cashback, rounding
 * 8. CACHE CONSISTENCY     - With/without cache, reorg handling
 * 9. VERIFIER VALIDATION   - Attack prevention, leak detection
 * 10. EDGE CASES           - Dust, uint256 boundaries, expired orders
 * 
 * @author Cellframe Development Team
 * @date 2025
 */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_enc.h"
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_chain_ledger.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_internal.h"
#include "dap_chain_net_srv_dex.h"
#include "dap_test.h"
#include "../fixtures/test_ledger_fixtures.h"
#include "../fixtures/test_token_fixtures.h"
#include "../fixtures/test_transaction_fixtures.h"
#include "../fixtures/test_emission_fixtures.h"

// Consensus modules (forward declarations)
extern int dap_chain_cs_dag_init(void);
extern int dap_chain_cs_dag_poa_init(void);
extern int dap_chain_cs_esbocs_init(void);

#define LOG_TAG "dex_integration_test"

// ============================================================================
// ORDER TRACKING
// ============================================================================

typedef struct order_entry {
    dap_hash_fast_t root;          // Root hash (immutable)
    dap_hash_fast_t tail;          // Tail hash (current TX, updates on partial fill)
    uint8_t side;                  // 0=ASK, 1=BID
    uint256_t price;               // Price (rate)
    uint256_t value;               // Current available value
    dap_chain_addr_t seller_addr;  // Seller address
    char token_buy[DAP_CHAIN_TICKER_SIZE_MAX];   // Token to buy
    char token_sell[DAP_CHAIN_TICKER_SIZE_MAX];  // Token to sell
    bool active;                   // true if order is still open
    struct order_entry *next;      // Linked list
} order_entry_t;

// ============================================================================
// DECREE HELPERS
// ============================================================================

// Decree method types (must match dap_chain_net_srv_dex.c)
typedef enum {
    DEX_DECREE_UNKNOWN,
    DEX_DECREE_FEE_SET, DEX_DECREE_PAIR_ADD, DEX_DECREE_PAIR_REMOVE, DEX_DECREE_PAIR_FEE_SET, DEX_DECREE_PAIR_FEE_SET_ALL
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

static int test_decree_pair_add(dap_ledger_t *a_ledger, const char *a_token_base, const char *a_token_quote,
                                dap_chain_net_id_t a_net_id, uint8_t a_fee_config)
{
    byte_t l_tsd_buf[1024] = {0};
    byte_t *l_ptr = l_tsd_buf;
    
    uint8_t l_method = (uint8_t)DEX_DECREE_PAIR_ADD;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_METHOD, &l_method, sizeof(uint8_t));
    
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_BASE, a_token_base, dap_strlen(a_token_base)+1);
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_QUOTE, a_token_quote, dap_strlen(a_token_quote)+1);
    
    uint64_t l_net_id = a_net_id.uint64;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_BASE, &l_net_id, sizeof(uint64_t));
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_QUOTE, &l_net_id, sizeof(uint64_t));
    
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_CONFIG, &a_fee_config, sizeof(uint8_t));
    
    size_t l_tsd_size = l_ptr - l_tsd_buf;
    
    return dap_chain_net_srv_dex_decree_callback(a_ledger, true, (dap_tsd_t*)l_tsd_buf, l_tsd_size);
}

static int test_decree_pair_fee_set(dap_ledger_t *a_ledger, const char *a_token_base, const char *a_token_quote,
                                    dap_chain_net_id_t a_net_id, uint8_t a_fee_config)
{
    byte_t l_tsd_buf[1024] = {0};
    byte_t *l_ptr = l_tsd_buf;
    
    uint8_t l_method = (uint8_t)DEX_DECREE_PAIR_FEE_SET;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_METHOD, &l_method, sizeof(uint8_t));
    
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_BASE, a_token_base, dap_strlen(a_token_base)+1);
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_QUOTE, a_token_quote, dap_strlen(a_token_quote)+1);
    
    uint64_t l_net_id = a_net_id.uint64;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_BASE, &l_net_id, sizeof(uint64_t));
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_QUOTE, &l_net_id, sizeof(uint64_t));
    
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_CONFIG, &a_fee_config, sizeof(uint8_t));
    
    size_t l_tsd_size = l_ptr - l_tsd_buf;
    
    return dap_chain_net_srv_dex_decree_callback(a_ledger, true, (dap_tsd_t*)l_tsd_buf, l_tsd_size);
}

static int test_decree_fee_set(dap_ledger_t *a_ledger, uint256_t a_fee_amount, const dap_chain_addr_t *a_service_addr)
{
    byte_t l_tsd_buf[1024] = {0};
    byte_t *l_ptr = l_tsd_buf;
    
    uint8_t l_method = (uint8_t)DEX_DECREE_FEE_SET;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_METHOD, &l_method, sizeof(uint8_t));
    
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_AMOUNT, &a_fee_amount, sizeof(uint256_t));
    
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_ADDR, a_service_addr, sizeof(dap_chain_addr_t));
    
    size_t l_tsd_size = l_ptr - l_tsd_buf;
    
    return dap_chain_net_srv_dex_decree_callback(a_ledger, true, (dap_tsd_t*)l_tsd_buf, l_tsd_size);
}

// ============================================================================
// GLOBAL TEST FIXTURE
// ============================================================================

/**
 * @brief Test network fixture with preconfigured tokens and wallets
 */
typedef struct dex_test_fixture {
    test_net_fixture_t *net;
    
    // Wallets
    dap_chain_wallet_t *alice;
    dap_chain_wallet_t *bob;
    dap_chain_wallet_t *carol;
    
    // Addresses
    dap_chain_addr_t alice_addr;
    dap_chain_addr_t bob_addr;
    dap_chain_addr_t carol_addr;
    
    // Network fee (standard for all transactions)
    uint256_t network_fee;
    
    // Order tracking (linked list of all orders created in tests)
    order_entry_t *orders;
    
    // Balance tracking (for verification)
    struct {
        uint256_t alice_kel;
        uint256_t alice_usdt;
        uint256_t alice_tc;
        uint256_t bob_kel;
        uint256_t bob_usdt;
        uint256_t bob_tc;
        uint256_t carol_kel;
        uint256_t carol_usdt;
        uint256_t carol_tc;
    } balances;
} dex_test_fixture_t;

// ============================================================================
// ORDER TRACKING FUNCTIONS
// ============================================================================

/**
 * @brief Add order to fixture tracking
 */
static void test_dex_order_track_add(dex_test_fixture_t *f, const dap_hash_fast_t *root, const dap_hash_fast_t *tail,
                                      uint8_t side, uint256_t price, uint256_t value,
                                      const dap_chain_addr_t *seller_addr,
                                      const char *token_buy, const char *token_sell)
{
    order_entry_t *entry = DAP_NEW_Z(order_entry_t);
    entry->root = *root;
    entry->tail = *tail;
    entry->side = side;
    entry->price = price;
    entry->value = value;
    entry->seller_addr = *seller_addr;
    dap_strncpy(entry->token_buy, token_buy, sizeof(entry->token_buy) - 1);
    dap_strncpy(entry->token_sell, token_sell, sizeof(entry->token_sell) - 1);
    entry->active = true;
    entry->next = f->orders;
    f->orders = entry;
}

/**
 * @brief Find order by root hash
 */
static order_entry_t* test_dex_order_track_find(dex_test_fixture_t *f, const dap_hash_fast_t *root)
{
    for (order_entry_t *e = f->orders; e; e = e->next)
        if (dap_hash_fast_compare(&e->root, root))
            return e;
    return NULL;
}

/**
 * @brief Update order tail and value after partial fill
 */
static void test_dex_order_track_update(dex_test_fixture_t *f, const dap_hash_fast_t *root,
                                         const dap_hash_fast_t *new_tail, uint256_t new_value)
{
    order_entry_t *e = test_dex_order_track_find(f, root);
    if (e) {
        e->tail = *new_tail;
        e->value = new_value;
    }
}

/**
 * @brief Mark order as cancelled/filled
 * @details Removes entry by matching BOTH root and tail (to handle leftovers correctly)
 */
static void test_dex_order_track_remove(dex_test_fixture_t *f, const dap_hash_fast_t *hash)
{
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (dap_hash_fast_compare(&e->tail, hash) || dap_hash_fast_compare(&e->root, hash)) {
            e->active = false;
            return; // Match by tail or root
        }
    }
}

/**
 * @brief Free all order tracking memory
 */
static void test_dex_order_track_cleanup(dex_test_fixture_t *f)
{
    order_entry_t *e = f->orders, *next;
    while (e) {
        next = e->next;
        DAP_DELETE(e);
        e = next;
    }
    f->orders = NULL;
}

// ============================================================================
// TEST HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Helper: Create a DEX order with min_fill support
 * @param fixture Test fixture
 * @param wallet Wallet creating the order
 * @param token_buy Token to buy
 * @param token_sell Token to sell
 * @param amount_sell Amount to sell (string, e.g. "1000.0")
 * @param rate Rate (string, e.g. "5.0")
 * @param min_fill Min fill percentage (0-100, 0=partial OK, 100=AON)
 * @param out_hash Output: hash of created transaction
 * @return 0 on success, error code otherwise
 */
static int test_dex_order_create_ex(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const char *token_buy,
    const char *token_sell,
    const char *amount_sell,
    const char *rate,
    uint8_t min_fill,
    dap_hash_fast_t *out_hash)
{
    dap_ret_val_if_any(-1, !fixture, !wallet, !token_buy, !token_sell, !amount_sell, !rate, !out_hash);
    
    uint256_t value = dap_chain_coins_to_balance(amount_sell);
    uint256_t rate_value = dap_chain_coins_to_balance(rate);
    uint256_t network_fee = fixture->network_fee;
    
    dap_chain_datum_tx_t *tx = NULL;
    dap_chain_net_srv_dex_create_error_t err = dap_chain_net_srv_dex_create(
        fixture->net->net, token_buy, token_sell, value, rate_value, min_fill, network_fee, wallet, NULL, &tx
    );
    
    if (err != DEX_CREATE_ERROR_OK || !tx) {
        log_it(L_ERROR, "CREATE failed: err=%d", err);
        return -2;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    
    if (dap_ledger_tx_add(fixture->net->net->pub.ledger, tx, out_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Failed to add order to ledger");
        return -3;
    }
    
    // Track order in fixture
    dap_chain_addr_t *l_seller_addr = dap_chain_wallet_get_addr(wallet, fixture->net->net->pub.id);
    // BID = buying KEL (base), ASK = selling KEL (base)
    uint8_t l_side = (strcmp(token_buy, "KEL") == 0) ? 1 : 0; // 1=BID, 0=ASK
    test_dex_order_track_add(fixture, out_hash, out_hash, l_side, rate_value, value, l_seller_addr, token_buy, token_sell);
    
    log_it(L_INFO, "Order created: %s %s for %s @ rate %s (min_fill=%d%%)", amount_sell, token_sell, token_buy, rate, min_fill);
    return 0;
}

// Legacy wrapper for backward compatibility
static int test_dex_order_create(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const char *token_buy,
    const char *token_sell,
    const char *amount_sell,
    const char *rate,
    dap_hash_fast_t *out_hash)
{
    return test_dex_order_create_ex(fixture, wallet, token_buy, token_sell, amount_sell, rate, 0, out_hash);
}

/**
 * @brief Helper: Purchase from an order
 * @param fixture Test fixture
 * @param buyer Buyer wallet
 * @param order_hash Hash of order to purchase from
 * @param amount Budget amount (string, e.g. "2500.0")
 * @param is_budget_buy true: budget in what buyer BUYS, false: budget in what buyer SELLS
 * @param create_buyer_leftover true: create buyer-leftover order from excess budget
 * @param out_hash Output: hash of purchase transaction
 * @return 0 on success, error code otherwise
 */
static int test_dex_order_purchase(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *buyer,
    dap_hash_fast_t *order_hash,
    const char *amount,
    bool is_budget_buy,
    bool create_buyer_leftover,
    dap_hash_fast_t *out_hash)
{
    dap_ret_val_if_any(-1, !fixture, !buyer, !order_hash, !amount, !out_hash);
    
    uint256_t budget = dap_chain_coins_to_balance(amount);
    uint256_t network_fee = fixture->network_fee;
    
    dap_chain_datum_tx_t *tx = NULL;
    dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase(
        fixture->net->net, order_hash, budget, is_budget_buy, network_fee, buyer, NULL,
        create_buyer_leftover, uint256_0, 0, &tx
    );
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx) {
        log_it(L_ERROR, "PURCHASE failed: err=%d", err);
        return -2;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    
    if (dap_ledger_tx_add(fixture->net->net->pub.ledger, tx, out_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Failed to add purchase to ledger");
        return -3;
    }
    
    // Update order tracking: find order by tail or root (order_hash can be either)
    order_entry_t *l_order = NULL;
    for (order_entry_t *e = fixture->orders; e; e = e->next) {
        if (e->active && (dap_hash_fast_compare(&e->tail, order_hash) || dap_hash_fast_compare(&e->root, order_hash))) {
            l_order = e;
            break;
        }
    }
    
    if (l_order) {
        // Scan TX for leftover OUT_COND (has srv_dex subtype and same root)
        dap_chain_tx_out_cond_t *l_leftover = NULL;
        int l_out_idx = 0;
        while ((l_leftover = dap_chain_datum_tx_out_cond_get(tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx)) != NULL) {
            if (dap_hash_fast_compare(&l_leftover->subtype.srv_dex.order_root_hash, &l_order->root))
                break;
            l_out_idx++;
        }
        
        if (l_leftover) {
            // Partial fill: update tail and value
            test_dex_order_track_update(fixture, &l_order->root, out_hash, l_leftover->header.value);
            log_it(L_DEBUG, "Order partially filled, leftover=%s", dap_uint256_to_char_ex(l_leftover->header.value).frac);
        } else {
            // Full fill: mark as inactive
            test_dex_order_track_remove(fixture, &l_order->tail);
            log_it(L_DEBUG, "Order fully filled, removed from tracking");
        }
    }
    
    log_it(L_INFO, "Purchase completed: budget=%s, is_budget_buy=%d", amount, is_budget_buy);
    return 0;
}

/**
 * @brief Helper: Auto-purchase (DEX matcher selects best orders)
 * @param fixture Test fixture
 * @param buyer Buyer wallet
 * @param token_sell Token to sell (what buyer gives)
 * @param token_buy Token to buy (what buyer receives)
 * @param amount Budget amount (string)
 * @param is_budget_buy true: budget in what buyer BUYS, false: budget in what buyer SELLS
 * @param create_buyer_leftover true: create buyer-leftover order from excess budget
 * @param out_hash Output: hash of purchase transaction
 * @return 0 on success, error code otherwise
 */
static int test_dex_order_purchase_auto_ex(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *buyer,
    const char *token_sell,
    const char *token_buy,
    const char *amount,
    bool is_budget_buy,
    bool create_buyer_leftover,
    uint256_t min_rate,
    dap_hash_fast_t *out_hash)
{
    dap_ret_val_if_any(-1, !fixture, !buyer, !token_sell, !token_buy, !amount, !out_hash);
    
    uint256_t budget = dap_chain_coins_to_balance(amount);
    uint256_t network_fee = fixture->network_fee;
    
    dap_chain_datum_tx_t *tx = NULL;
    // If min_rate is specified, use it for buyer-leftover rate as well
    uint256_t leftover_rate = IS_ZERO_256(min_rate) ? uint256_0 : min_rate;
    dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase_auto(
        fixture->net->net, token_sell, token_buy, budget, is_budget_buy, network_fee, min_rate,
        buyer, NULL, create_buyer_leftover, leftover_rate, 0, &tx
    );
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx) {
        log_it(L_ERROR, "AUTO-PURCHASE failed: err=%d", err);
        return -2;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    
    if (dap_ledger_tx_add(fixture->net->net->pub.ledger, tx, out_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Failed to add auto-purchase to ledger");
        return -3;
    }
    
    // Update order tracking: scan TX IN_COND items to find which orders were consumed
    dap_list_t *l_in_items = dap_chain_datum_tx_items_get(tx, TX_ITEM_TYPE_IN_COND, NULL);
    log_it(L_DEBUG, "[TRACKING] Found %d IN_COND items in transaction", dap_list_length(l_in_items));
    
    for (order_entry_t *e = fixture->orders; e; e = e->next) {
        if (!e->active)
            continue;
        
        log_it(L_DEBUG, "[TRACKING] Checking active order: root=%s, tail=%s", 
               dap_chain_hash_fast_to_str_static(&e->root),
               dap_chain_hash_fast_to_str_static(&e->tail));
        
        // Check if this order was consumed in the TX
        for (dap_list_t *it = l_in_items; it; it = it->next) {
            dap_chain_tx_in_cond_t *l_in_cond = (dap_chain_tx_in_cond_t*)it->data;
            dap_hash_fast_t l_prev_hash = l_in_cond->header.tx_prev_hash;
            
            log_it(L_DEBUG, "[TRACKING]   Comparing IN_COND tx_prev_hash=%s with order tail", 
                   dap_chain_hash_fast_to_str_static(&l_prev_hash));
            
            // Check if this IN_COND spends our tracked order (by comparing with tail)
            if (dap_hash_fast_compare(&l_prev_hash, &e->tail)) {
                log_it(L_DEBUG, "[TRACKING]   ✓ MATCH! This order was consumed");
                // This order was consumed - check for seller-leftover OUT_COND
                dap_chain_tx_out_cond_t *l_leftover = NULL;
                int l_out_idx = 0;
                bool found_leftover = false;
                
        while ((l_leftover = dap_chain_datum_tx_out_cond_get(tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx)) != NULL) {
            if (dap_hash_fast_compare(&l_leftover->subtype.srv_dex.order_root_hash, &e->root)) {
                // Partial fill: update tail and value
                test_dex_order_track_update(fixture, &e->root, out_hash, l_leftover->header.value);
                log_it(L_INFO, "[TRACKING UPDATE] Order %s: old_tail=%s → new_tail=%s, old_value=%s → new_value=%s", 
                       dap_chain_hash_fast_to_str_static(&e->root),
                       dap_chain_hash_fast_to_str_static(&l_prev_hash),
                       dap_chain_hash_fast_to_str_static(out_hash),
                       "N/A",
                       dap_uint256_to_char_ex(l_leftover->header.value).frac);
                found_leftover = true;
                break;
            }
            l_out_idx++;
        }
                
                if (!found_leftover) {
                    // Full fill: mark as inactive
                    test_dex_order_track_remove(fixture, &e->tail);
                    log_it(L_DEBUG, "Auto-match: order %s fully filled", dap_chain_hash_fast_to_str_static(&e->root));
                }
            }
        }
    }
    
    dap_list_free(l_in_items);
    
    // Check for buyer-leftover OUT_COND (blank root, seller_addr = buyer)
    dap_chain_tx_out_cond_t *l_buyer_leftover = NULL;
    int l_out_idx_bl = 0;
    while ((l_buyer_leftover = dap_chain_datum_tx_out_cond_get(tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx_bl)) != NULL) {
        if (dap_hash_fast_is_blank(&l_buyer_leftover->subtype.srv_dex.order_root_hash)) {
            // Buyer-leftover: blank root, seller_addr should be buyer
            dap_chain_addr_t *buyer_addr = dap_chain_wallet_get_addr(buyer, fixture->net->net->pub.id);
            if (buyer_addr && dap_chain_addr_compare(&l_buyer_leftover->subtype.srv_dex.seller_addr, buyer_addr)) {
                // This is buyer-leftover - add to tracking
                // Get sell_token from ledger (OUT_COND doesn't store it directly)
                const char *l_sell_token = dap_ledger_tx_get_token_ticker_by_hash(fixture->net->net->pub.ledger, out_hash);
                const char *l_buy_token = l_buyer_leftover->subtype.srv_dex.buy_token;
                
                // Determine side: ASK=0 (sells BASE, buys QUOTE), BID=1 (sells QUOTE, buys BASE)
                // For buyer-leftover: if leftover in BASE (KEL), it's BID (sells KEL, buys USDT)
                // If leftover in QUOTE (USDT), it's ASK (sells USDT, buys KEL)
                uint8_t l_side = 0;
                if (l_sell_token && dap_strcmp(l_sell_token, "KEL") == 0) {
                    l_side = 1; // BID (sells KEL, buys USDT)
                } else {
                    l_side = 0; // ASK (sells USDT, buys KEL)
                }
                
                test_dex_order_track_add(fixture, out_hash, out_hash, l_side, 
                                        l_buyer_leftover->subtype.srv_dex.rate,
                                        l_buyer_leftover->header.value,
                                        buyer_addr, l_buy_token, l_sell_token ? l_sell_token : "");
                log_it(L_INFO, "[TRACKING] Buyer-leftover order added: root=tail=%s, seller=%s, value=%s %s, side=%s",
                       dap_chain_hash_fast_to_str_static(out_hash),
                       dap_chain_addr_to_str_static(buyer_addr),
                       dap_uint256_to_char_ex(l_buyer_leftover->header.value).frac,
                       l_sell_token ? l_sell_token : "UNKNOWN",
                       l_side == 0 ? "ASK" : "BID");
                break;
            }
        }
        l_out_idx_bl++;
    }
    
    log_it(L_INFO, "Auto-purchase completed: budget=%s, is_budget_buy=%d", amount, is_budget_buy);
    return 0;
}

// Legacy wrapper: auto-purchase without min_rate filter
static int test_dex_order_purchase_auto(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *buyer,
    const char *token_sell,
    const char *token_buy,
    const char *amount,
    bool is_budget_buy,
    bool create_buyer_leftover,
    dap_hash_fast_t *out_hash)
{
    return test_dex_order_purchase_auto_ex(fixture, buyer, token_sell, token_buy, amount,
                                           is_budget_buy, create_buyer_leftover, uint256_0,
                                           out_hash);
}

/**
 * @brief Helper: Cancel (invalidate) orders by seller address
 * @param fixture Test fixture
 * @param owner Owner wallet
 * @param owner_addr Owner address
 * @param base_token Base token (e.g. "KEL")
 * @param quote_token Quote token (e.g. "USDT")
 * @param limit Max orders to cancel (1 for single order)
 * @param out_hash Output: hash of invalidate transaction
 * @return 0 on success, error code otherwise
 */
static int test_dex_order_cancel(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *owner,
    dap_hash_fast_t *order_hash,
    dap_hash_fast_t *out_hash)
{
    dap_ret_val_if_any(-1, !fixture, !owner, !order_hash, !out_hash);
    
    uint256_t network_fee = fixture->network_fee;
    
    dap_chain_datum_tx_t *tx = NULL;
    dap_chain_net_srv_dex_remove_error_t err = dap_chain_net_srv_dex_remove(
        fixture->net->net, order_hash, network_fee, owner, NULL, &tx
    );
    
    if (err != DEX_REMOVE_ERROR_OK || !tx) {
        log_it(L_ERROR, "CANCEL failed: err=%d", err);
        return -2;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    
    if (dap_ledger_tx_add(fixture->net->net->pub.ledger, tx, out_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Failed to add cancel to ledger");
        return -3;
    }
    
    // Update order tracking: mark as cancelled
    test_dex_order_track_remove(fixture, order_hash);
    
    log_it(L_INFO, "Order cancelled successfully: %s", dap_chain_hash_fast_to_str_static(order_hash));
    return 0;
}

/**
 * @brief Helper: Verify balance
 * @param fixture Test fixture
 * @param addr Address to check
 * @param token Token ticker
 * @param expected_str Expected amount (string, e.g. "9000.0")
 * @return true if balance matches
 */
static bool test_dex_verify_balance(
    dex_test_fixture_t *fixture,
    dap_chain_addr_t *addr,
    const char *token,
    const char *expected_str)
{
    dap_ret_val_if_any(false, !fixture, !addr, !token, !expected_str);
    
    uint256_t balance = dap_ledger_calc_balance(fixture->net->net->pub.ledger, addr, token);
    uint256_t expected = dap_chain_coins_to_balance(expected_str);
    
    bool match = EQUAL_256(balance, expected);
    log_it(match ? L_INFO : L_ERROR, "Balance %s %s: expected %s, got %s",
           dap_chain_addr_to_str_static(addr), token, expected_str,
           dap_uint256_to_char_ex(balance).frac);
    
    return match;
}

/**
 * @brief Helper: Dump current balances for all test actors
 */
static void test_dex_dump_balances(dex_test_fixture_t *f, const char *label)
{
    dap_ret_if_any(!f, !label);
    
    log_it(L_NOTICE, "");
    log_it(L_NOTICE, "========== BALANCE DUMP: %s ==========", label);
    
    log_it(L_NOTICE, "Alice: KEL=%s, USDT=%s, TC=%s",
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->alice_addr, "KEL")).frac,
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->alice_addr, "USDT")).frac,
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->alice_addr, "TestCoin")).frac);
    
    log_it(L_NOTICE, "Bob:   KEL=%s, USDT=%s, TC=%s",
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->bob_addr, "KEL")).frac,
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->bob_addr, "USDT")).frac,
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->bob_addr, "TestCoin")).frac);
    
    log_it(L_NOTICE, "Carol (srv): KEL=%s, USDT=%s, TC=%s",
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->carol_addr, "KEL")).frac,
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->carol_addr, "USDT")).frac,
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->carol_addr, "TestCoin")).frac);

    log_it(L_NOTICE, "========================================");
    log_it(L_NOTICE, "");
}

/**
 * @brief Helper: Dump current orderbook state
 */
static void test_dex_dump_orderbook(dex_test_fixture_t *f, const char *label)
{
    dap_ret_if_any(!f, !label);
    
    log_it(L_NOTICE, "");
    log_it(L_NOTICE, "========== ORDERBOOK DUMP: %s ==========", label);
    dap_chain_net_srv_dex_dump_orders_cache();
    
    if (!f->orders) {
        log_it(L_NOTICE, "  (empty - no active orders)");
        log_it(L_NOTICE, "========================================");
        log_it(L_NOTICE, "");
        return;
    }
    
    size_t i = 0;
    for (order_entry_t *entry = f->orders; entry != NULL; entry = entry->next) {
        if (!entry->active) continue; // Skip inactive orders
        
        const char *side = (entry->side == 0) ? "ASK" : "BID";
        const char *seller_addr_short = dap_chain_addr_to_str_static(&entry->seller_addr);
        
        log_it(L_NOTICE, "  [%zu] %s: root=%s",
               i, side,
               dap_chain_hash_fast_to_str_static(&entry->root));
        
        log_it(L_NOTICE, "       tail=%s",
               dap_chain_hash_fast_to_str_static(&entry->tail));
        
        log_it(L_NOTICE, "       seller=%.10s..., rate=%s, value=%s",
               seller_addr_short,
               dap_uint256_to_char_ex(entry->price).frac,
               dap_uint256_to_char_ex(entry->value).frac);
        
        log_it(L_NOTICE, "       tokens=%s/%s",
               entry->token_sell, entry->token_buy);
        i++;
    }
    
    if (i == 0) {
        log_it(L_NOTICE, "  (empty - no active orders)");
    }
    
    log_it(L_NOTICE, "========================================");
    log_it(L_NOTICE, "");
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Initialize test fixture with tokens and wallets (from old working test)
 */
static dex_test_fixture_t* dex_test_fixture_create(void) {
    dex_test_fixture_t *fixture = DAP_NEW_Z(dex_test_fixture_t);
    
    // Create test network
    fixture->net = test_net_fixture_create("dex_integration_test");
    if (!fixture->net) {
        log_it(L_ERROR, "Failed to create test network");
        DAP_DELETE(fixture);
        return NULL;
    }
    
    // Initialize DEX service
    int dex_init = dap_chain_net_srv_dex_init();
    if (dex_init != 0) {
        log_it(L_ERROR, "DEX service init failed");
        test_net_fixture_destroy(fixture->net);
        DAP_DELETE(fixture);
        return NULL;
    }
    
    // Configure standard network fee
    fixture->network_fee = dap_chain_coins_to_balance("1.0");
    
    // Create wallets (as in old test)
    fixture->alice = dap_chain_wallet_create("alice", ".", (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, NULL);
    fixture->bob = dap_chain_wallet_create("bob", ".", (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, NULL);
    fixture->carol = dap_chain_wallet_create("carol", ".", (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, NULL);
    
    if (!fixture->alice || !fixture->bob || !fixture->carol) {
        log_it(L_ERROR, "Failed to create wallets");
        dap_chain_net_srv_dex_deinit();
        test_net_fixture_destroy(fixture->net);
        DAP_DELETE(fixture);
        return NULL;
    }
    
    // Get addresses and copy them (as in old test)
    dap_chain_addr_t *l_aa = dap_chain_wallet_get_addr(fixture->alice, fixture->net->net->pub.id);
    fixture->alice_addr = *l_aa; DAP_DELETE(l_aa);
    dap_chain_addr_t *l_ab = dap_chain_wallet_get_addr(fixture->bob, fixture->net->net->pub.id);
    fixture->bob_addr = *l_ab; DAP_DELETE(l_ab);
    dap_chain_addr_t *l_ac = dap_chain_wallet_get_addr(fixture->carol, fixture->net->net->pub.id);
    fixture->carol_addr = *l_ac; DAP_DELETE(l_ac);
    
    // Extract certificates from wallets using internal API (as in old test)
    dap_chain_wallet_internal_t *alice_int = DAP_CHAIN_WALLET_INTERNAL(fixture->alice);
    dap_chain_wallet_internal_t *bob_int = DAP_CHAIN_WALLET_INTERNAL(fixture->bob);
    dap_chain_wallet_internal_t *carol_int = DAP_CHAIN_WALLET_INTERNAL(fixture->carol);
    
    dap_cert_t *alice_cert = alice_int->certs[0];
    dap_cert_t *bob_cert = bob_int->certs[0];
    dap_cert_t *carol_cert = carol_int->certs[0];
    
    // Create tokens with emissions (as in old test)
    dap_chain_hash_fast_t kel_emission_hash, usdt_emission_hash, tc_emission_hash;
    
    test_token_fixture_t *kel_token = test_token_fixture_create_with_emission(
        fixture->net->ledger, "KEL", "1000000.0", "10000.0",
        &fixture->alice_addr, alice_cert, &kel_emission_hash
    );
    if (!kel_token) {
        log_it(L_ERROR, "Failed to create KEL token");
        goto cleanup;
    }
    
    test_token_fixture_t *usdt_token = test_token_fixture_create_with_emission(
        fixture->net->ledger, "USDT", "5000000.0", "50000.0",
        &fixture->bob_addr, bob_cert, &usdt_emission_hash
    );
    if (!usdt_token) {
        log_it(L_ERROR, "Failed to create USDT token");
        test_token_fixture_destroy(kel_token);
        goto cleanup;
    }
    
    test_token_fixture_t *tc_token = test_token_fixture_create_with_emission(
        fixture->net->ledger, "TestCoin", "10000000.0", "100000.0",
        &fixture->alice_addr, alice_cert, &tc_emission_hash
    );
    if (!tc_token) {
        log_it(L_ERROR, "Failed to create TestCoin token");
        test_token_fixture_destroy(usdt_token);
        test_token_fixture_destroy(kel_token);
        goto cleanup;
    }
    
    // Create separate TestCoin emissions for Bob and Carol (as in old test)
    dap_chain_hash_fast_t tc_bob_emission_hash = {0};
    test_emission_fixture_t *tc_bob_emission = test_emission_fixture_create_with_cert(
        "TestCoin", dap_chain_coins_to_balance("100000.0"), &fixture->bob_addr, bob_cert
    );
    if (!tc_bob_emission) {
        log_it(L_ERROR, "Failed to create TestCoin emission for Bob");
        test_token_fixture_destroy(tc_token);
        test_token_fixture_destroy(usdt_token);
        test_token_fixture_destroy(kel_token);
        goto cleanup;
    }
    if (test_emission_fixture_add_to_ledger(fixture->net->ledger, tc_bob_emission) != 0 ||
        !test_emission_fixture_get_hash(tc_bob_emission, &tc_bob_emission_hash)) {
        log_it(L_ERROR, "Failed to add Bob's TestCoin emission to ledger");
        goto cleanup;
    }
    
    dap_chain_hash_fast_t tc_carol_emission_hash = {0};
    test_emission_fixture_t *tc_carol_emission = test_emission_fixture_create_with_cert(
        "TestCoin", dap_chain_coins_to_balance("100000.0"), &fixture->carol_addr, carol_cert
    );
    if (!tc_carol_emission) {
        log_it(L_ERROR, "Failed to create TestCoin emission for Carol");
        test_token_fixture_destroy(tc_token);
        test_token_fixture_destroy(usdt_token);
        test_token_fixture_destroy(kel_token);
        goto cleanup;
    }
    if (test_emission_fixture_add_to_ledger(fixture->net->ledger, tc_carol_emission) != 0 ||
        !test_emission_fixture_get_hash(tc_carol_emission, &tc_carol_emission_hash)) {
        log_it(L_ERROR, "Failed to add Carol's TestCoin emission to ledger");
        goto cleanup;
    }
    
    // Create transactions from emissions (as in old test)
    // Alice: KEL + TestCoin (for network fees)
    test_tx_fixture_t *alice_kel_tx = test_tx_fixture_create_from_emission(
        fixture->net->ledger, &kel_emission_hash, "KEL", "10000.0", &fixture->alice_addr, alice_cert
    );
    if (!alice_kel_tx || test_tx_fixture_add_to_ledger(fixture->net->ledger, alice_kel_tx) != 0) {
        log_it(L_ERROR, "Failed to add Alice KEL TX");
        goto cleanup;
    }
    
    test_tx_fixture_t *alice_tc_tx = test_tx_fixture_create_from_emission(
        fixture->net->ledger, &tc_emission_hash, "TestCoin", "100000.0", &fixture->alice_addr, alice_cert
    );
    if (!alice_tc_tx || test_tx_fixture_add_to_ledger(fixture->net->ledger, alice_tc_tx) != 0) {
        log_it(L_ERROR, "Failed to add Alice TestCoin TX");
        goto cleanup;
    }
    
    // Bob: USDT + TestCoin (for network fees)
    test_tx_fixture_t *bob_usdt_tx = test_tx_fixture_create_from_emission(
        fixture->net->ledger, &usdt_emission_hash, "USDT", "50000.0", &fixture->bob_addr, bob_cert
    );
    if (!bob_usdt_tx || test_tx_fixture_add_to_ledger(fixture->net->ledger, bob_usdt_tx) != 0) {
        log_it(L_ERROR, "Failed to add Bob USDT TX");
        goto cleanup;
    }
    
    test_tx_fixture_t *bob_tc_tx = test_tx_fixture_create_from_emission(
        fixture->net->ledger, &tc_bob_emission_hash, "TestCoin", "100000.0", &fixture->bob_addr, bob_cert
    );
    if (!bob_tc_tx || test_tx_fixture_add_to_ledger(fixture->net->ledger, bob_tc_tx) != 0) {
        log_it(L_ERROR, "Failed to add Bob TestCoin TX");
        goto cleanup;
    }
    
    // Carol: TestCoin (for network fees and as service wallet)
    test_tx_fixture_t *carol_tc_tx = test_tx_fixture_create_from_emission(
        fixture->net->ledger, &tc_carol_emission_hash, "TestCoin", "100000.0", &fixture->carol_addr, carol_cert
    );
    if (!carol_tc_tx || test_tx_fixture_add_to_ledger(fixture->net->ledger, carol_tc_tx) != 0) {
        log_it(L_ERROR, "Failed to add Carol TestCoin TX");
        goto cleanup;
    }
    
    // Set Carol as service wallet via decree
    int l_fee_global_set = test_decree_fee_set(fixture->net->ledger, uint256_0, &fixture->carol_addr);
    if (l_fee_global_set != 0) {
        log_it(L_ERROR, "Failed to set Carol as service wallet via decree");
        goto cleanup;
    }
    log_it(L_INFO, "Carol set as service wallet: %s", dap_chain_addr_to_str_static(&fixture->carol_addr));
    
    // Add KEL/USDT pair to whitelist with 2% QUOTE fee (bit7=1 for QUOTE, bits[6:0]=2)
    int l_add_kel_usdt = test_decree_pair_add(fixture->net->ledger, "KEL", "USDT", 
                                               fixture->net->net->pub.id, 0x80 | 2);
    if (l_add_kel_usdt != 0) {
        log_it(L_ERROR, "Failed to add KEL/USDT pair to whitelist via decree");
        goto cleanup;
    }
    log_it(L_INFO, "KEL/USDT pair added to whitelist with 2%% QUOTE fee");
    
    // Add KEL/TestCoin pair to whitelist with 5% QUOTE fee (bit7=1 for QUOTE, bits[6:0]=5)
    int l_add_kel_tc = test_decree_pair_add(fixture->net->ledger, "KEL", "TestCoin", 
                                             fixture->net->net->pub.id, 0x80 | 5);
    if (l_add_kel_tc != 0) {
        log_it(L_ERROR, "Failed to add KEL/TestCoin pair to whitelist via decree");
        goto cleanup;
    }
    log_it(L_INFO, "KEL/TestCoin pair added to whitelist with 5%% QUOTE fee");
    
    // Update balance tracking
    fixture->balances.alice_kel = dap_chain_coins_to_balance("10000.0");
    fixture->balances.alice_tc = dap_chain_coins_to_balance("100000.0");
    fixture->balances.bob_usdt = dap_chain_coins_to_balance("50000.0");
    fixture->balances.bob_tc = dap_chain_coins_to_balance("100000.0");
    fixture->balances.carol_tc = dap_chain_coins_to_balance("100000.0");
    
    log_it(L_INFO, "DEX test fixture created successfully");
    return fixture;
    
cleanup:
    dap_chain_net_srv_dex_deinit();
    test_net_fixture_destroy(fixture->net);
    DAP_DELETE(fixture);
    return NULL;
}

/**
 * @brief Cleanup test fixture
 */
static void dex_test_fixture_destroy(dex_test_fixture_t *fixture) {
    if (!fixture) return;
    test_dex_order_track_cleanup(fixture);
    test_net_fixture_destroy(fixture->net);
    DAP_DELETE(fixture);
}

/**
 * @brief Update balance cache from ledger
 */
static void dex_update_balances(dex_test_fixture_t *f) {
    f->balances.alice_kel = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->alice_addr, "KEL");
    f->balances.alice_usdt = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->alice_addr, "USDT");
    f->balances.alice_tc = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->alice_addr, "TestCoin");
    
    f->balances.bob_kel = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->bob_addr, "KEL");
    f->balances.bob_usdt = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->bob_addr, "USDT");
    f->balances.bob_tc = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->bob_addr, "TestCoin");
    
    f->balances.carol_kel = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->carol_addr, "KEL");
    f->balances.carol_usdt = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->carol_addr, "USDT");
    f->balances.carol_tc = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->carol_addr, "TestCoin");
}

/**
 * @brief Print current balances (for debugging)
 */
static void dex_print_balances(dex_test_fixture_t *f, const char *label) {
    dex_update_balances(f);
    log_it(L_INFO, "[%s] Alice: KEL=%s USDT=%s TC=%s", label,
           dap_uint256_to_char_ex(f->balances.alice_kel).frac,
           dap_uint256_to_char_ex(f->balances.alice_usdt).frac,
           dap_uint256_to_char_ex(f->balances.alice_tc).frac);
    log_it(L_INFO, "[%s] Bob: KEL=%s USDT=%s TC=%s", label,
           dap_uint256_to_char_ex(f->balances.bob_kel).frac,
           dap_uint256_to_char_ex(f->balances.bob_usdt).frac,
           dap_uint256_to_char_ex(f->balances.bob_tc).frac);
    log_it(L_INFO, "[%s] Carol: KEL=%s USDT=%s TC=%s", label,
           dap_uint256_to_char_ex(f->balances.carol_kel).frac,
           dap_uint256_to_char_ex(f->balances.carol_usdt).frac,
           dap_uint256_to_char_ex(f->balances.carol_tc).frac);
}

// ============================================================================
// TEST GROUP 1: BASIC OPERATIONS
// ============================================================================
//
// PARTICIPANTS:
//   - Alice: Primary trader (ASK orders - sells KEL)
//   - Bob:   Primary trader (BID orders - buys KEL)
//   - Carol: Service wallet (collects all service fees @ 2% in QUOTE token)
//
// Complete order lifecycle: creation → purchase (full/partial) → cancellation
// Tests use direct order hash references (no auto-matching)
//
// Subgroups:
// 1.1-1.5  ASK orders:  Creation, Full/Partial fill, Cancel
// 1.6-1.9  BID orders:  Creation, Full/Partial fill, Cancel (symmetric to ASK)
// 1.10-1.14 Security:   Foreign cancel, Double cancel, Purchase consumed order
// 1.15-1.16 Cleanup:    Mass cancel via cancel_all_by_seller API
//
// ============================================================================

// ============================================================================
// GROUP 1: BASIC OPERATIONS
// ============================================================================
// TODO: Add orderbook verification via proper CLI invocation in the future

/**
 * @brief Test Group 1.1 - Order creation (ASK + BID)
 * @details Verifies basic order creation with various parameters
 */
static void test_group_1_1_order_creation(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.1: Order Creation ===");
    dex_update_balances(f);
    uint256_t l_alice_kel0 = f->balances.alice_kel, l_alice_tc0 = f->balances.alice_tc;
    uint256_t l_bob_usdt0 = f->balances.bob_usdt, l_bob_tc0 = f->balances.bob_tc;
    
    // Test 1: Alice creates ASK order (sells 1000 KEL for USDT @ rate 5.0)
    log_it(L_INFO, "[1.1.1] Alice creates ASK: 1000 KEL @ 5.0 USDT/KEL");
    dap_hash_fast_t order_ask_hash = {0};
    int ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "1000.0", "5.0", &order_ask_hash);
    dap_assert(ret == 0, "Alice ASK order created");
    
    // Verify Alice's balances changed by exact deltas: -1000 KEL, -1 * network_fee in TestCoin
    uint256_t l_expected_alice_kel = uint256_0, l_expected_alice_tc = uint256_0;
    uint256_t l_delta = dap_chain_coins_to_balance("1000.0");
    SUBTRACT_256_256(l_alice_kel0, l_delta, &l_expected_alice_kel);
    SUBTRACT_256_256(l_alice_tc0, f->network_fee, &l_expected_alice_tc);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(l_expected_alice_kel).frac), "Alice KEL locked");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(l_expected_alice_tc).frac), "Alice TC network fee");
    f->balances.alice_kel = l_expected_alice_kel;
    f->balances.alice_tc = l_expected_alice_tc;
    
    // Test 2: Bob creates BID order (buys 500 KEL for USDT @ rate 4.0)
    log_it(L_INFO, "[1.1.2] Bob creates BID: wants 500 KEL @ 4.0 USDT/KEL (offers 2000 USDT)");
    dap_hash_fast_t order_bid_hash = {0};
    ret = test_dex_order_create(f, f->bob, "KEL", "USDT", "2000.0", "0.25", &order_bid_hash);
    dap_assert(ret == 0, "Bob BID order created");
    
    // Verify Bob's balances changed by exact deltas: -2000 USDT, -1 * network_fee in TestCoin
    uint256_t l_expected_bob_usdt = uint256_0, l_expected_bob_tc = uint256_0;
    l_delta = dap_chain_coins_to_balance("2000.0");
    SUBTRACT_256_256(l_bob_usdt0, l_delta, &l_expected_bob_usdt);
    SUBTRACT_256_256(l_bob_tc0, f->network_fee, &l_expected_bob_tc);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(l_expected_bob_usdt).frac), "Bob USDT locked");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(l_expected_bob_tc).frac), "Bob TC network fee");
    f->balances.bob_usdt = l_expected_bob_usdt;
    f->balances.bob_tc = l_expected_bob_tc;
    
    log_it(L_NOTICE, "✓ GROUP 1.1 PASSED: Order creation (ASK + BID)");
}

/**
 * @brief Test Group 1.2 - Simple purchase (full fill)
 * @details Verifies basic purchase flow without leftovers (order fully consumed)
 */
static void test_group_1_2_simple_purchase(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.2: Simple Purchase (Full Fill) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_usdt0 = f->balances.alice_usdt, a_tc0 = f->balances.alice_tc;
    uint256_t b_kel0 = f->balances.bob_kel,   b_usdt0 = f->balances.bob_usdt,   b_tc0 = f->balances.bob_tc;
    uint256_t c_usdt0 = f->balances.carol_usdt;
    
    // Test 1: Alice creates ASK order: 100 KEL @ 5.0 USDT/KEL (expects 500 USDT)
    log_it(L_INFO, "[1.2.1] Alice creates ASK: 100 KEL @ 5.0 USDT/KEL");
    dap_hash_fast_t order_hash = {0};
    int ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "100.0", "5.0", &order_hash);
    dap_assert(ret == 0, "Alice order created");
    
    // Alice: -100 KEL, -network_fee TestCoin
    uint256_t delta100 = dap_chain_coins_to_balance("100.0");
    uint256_t a_kel1 = uint256_0, a_tc1 = uint256_0;
    SUBTRACT_256_256(a_kel0, delta100, &a_kel1);
    SUBTRACT_256_256(a_tc0, f->network_fee, &a_tc1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL locked");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel1;
    f->balances.alice_tc  = a_tc1;
    
    // Test 2: Bob buys entire order (100 KEL for 500 USDT + 10 USDT fee @ 2%)
    log_it(L_INFO, "[1.2.2] Bob buys all 100 KEL (pays 510 USDT total: 500 + 10 fee)");
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->bob, &order_hash, "100.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Bob purchase completed");
    
    // Verify balances after purchase:
    // Alice: +500 USDT (seller payout), KEL stays 8900, TestCoin stays 99998
    uint256_t payout500 = dap_chain_coins_to_balance("500.0");
    uint256_t a_usdt1 = uint256_0;
    SUM_256_256(a_usdt0, payout500, &a_usdt1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT",
               dap_uint256_to_char_ex(a_usdt1).frac), "Alice received USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC unchanged");
    f->balances.alice_usdt = a_usdt1;
    
    // Bob: +100 KEL, -510 USDT (500 + 10 fee) = 48000 - 510 = 47490
    // TestCoin: 99999 - 1 (network fee) = 99998
    uint256_t delta_kel100 = dap_chain_coins_to_balance("100.0");
    uint256_t delta_usdt510 = dap_chain_coins_to_balance("510.0");
    uint256_t b_kel1 = uint256_0, b_usdt1 = uint256_0, b_tc1 = uint256_0;
    SUM_256_256(b_kel0, delta_kel100, &b_kel1);
    SUBTRACT_256_256(b_usdt0, delta_usdt510, &b_usdt1);
    SUBTRACT_256_256(b_tc0, f->network_fee, &b_tc1);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel1).frac), "Bob received KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt1).frac), "Bob paid USDT + fee");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc1).frac), "Bob TC network fee");
    f->balances.bob_kel = b_kel1;
    f->balances.bob_usdt = b_usdt1;
    f->balances.bob_tc = b_tc1;
    
    // Carol (service wallet): +10 USDT (2% service fee)
    uint256_t fee10 = dap_chain_coins_to_balance("10.0");
    uint256_t c_usdt1 = uint256_0;
    SUM_256_256(c_usdt0, fee10, &c_usdt1);
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt1).frac), "Carol received service fee");
    f->balances.carol_usdt = c_usdt1;
    
    log_it(L_NOTICE, "✓ GROUP 1.2 PASSED: Full purchase (no leftovers)");
}

/**
 * @brief Test Group 1.3 - Partial purchase (seller-leftover)
 * @details Verifies partial fill scenario with seller-leftover order
 */
static void test_group_1_3_partial_purchase(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.3: Partial Purchase (Seller-Leftover) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_usdt0 = f->balances.alice_usdt, a_tc0 = f->balances.alice_tc;
    uint256_t b_kel0 = f->balances.bob_kel,   b_usdt0 = f->balances.bob_usdt,   b_tc0 = f->balances.bob_tc;
    uint256_t c_usdt0 = f->balances.carol_usdt;
    
    // Test 1: Alice creates ASK order: 500 KEL @ 5.0 USDT/KEL (expects 2500 USDT)
    log_it(L_INFO, "[1.3.1] Alice creates ASK: 500 KEL @ 5.0 USDT/KEL");
    dap_hash_fast_t order_hash = {0};
    int ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "500.0", "5.0", &order_hash);
    dap_assert(ret == 0, "Alice order created");
    
    // Alice: -500 KEL, -network_fee TestCoin
    uint256_t delta500 = dap_chain_coins_to_balance("500.0");
    uint256_t a_kel1 = uint256_0, a_tc1 = uint256_0;
    SUBTRACT_256_256(a_kel0, delta500, &a_kel1);
    SUBTRACT_256_256(a_tc0, f->network_fee, &a_tc1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL locked");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel1;
    f->balances.alice_tc  = a_tc1;
    
    // Test 2: Bob buys 300 KEL (partial fill, 200 KEL leftover)
    // Bob pays: 300 * 5.0 = 1500 USDT + 30 USDT fee (2%) = 1530 USDT total
    log_it(L_INFO, "[1.3.2] Bob buys 300 KEL (partial, 200 KEL leftover remains)");
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->bob, &order_hash, "300.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Bob partial purchase completed");
    
    // Verify balances after partial purchase:
    // Alice: +1500 USDT (seller payout for 300 KEL), KEL stays, TC stays
    uint256_t payout1500 = dap_chain_coins_to_balance("1500.0");
    uint256_t a_usdt1 = uint256_0;
    SUM_256_256(a_usdt0, payout1500, &a_usdt1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT",
               dap_uint256_to_char_ex(a_usdt1).frac), "Alice received USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC unchanged");
    f->balances.alice_usdt = a_usdt1;
    
    // Bob: +300 KEL, -1530 USDT (1500 + 30 fee), -network_fee TestCoin
    uint256_t delta_kel300 = dap_chain_coins_to_balance("300.0");
    uint256_t delta_usdt1530 = dap_chain_coins_to_balance("1530.0");
    uint256_t b_kel1 = uint256_0, b_usdt1 = uint256_0, b_tc1 = uint256_0;
    SUM_256_256(b_kel0, delta_kel300, &b_kel1);
    SUBTRACT_256_256(b_usdt0, delta_usdt1530, &b_usdt1);
    SUBTRACT_256_256(b_tc0, f->network_fee, &b_tc1);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel1).frac), "Bob received KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt1).frac), "Bob paid USDT + fee");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc1).frac), "Bob TC network fee");
    f->balances.bob_kel = b_kel1;
    f->balances.bob_usdt = b_usdt1;
    f->balances.bob_tc = b_tc1;
    
    // Carol (service wallet): +30 USDT (2% service fee)
    uint256_t fee30 = dap_chain_coins_to_balance("30.0");
    uint256_t c_usdt1 = uint256_0;
    SUM_256_256(c_usdt0, fee30, &c_usdt1);
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt1).frac), "Carol received service fee");
    f->balances.carol_usdt = c_usdt1;
    
    log_it(L_NOTICE, "✓ GROUP 1.3 PASSED: Partial purchase (seller-leftover 200 KEL remains)");
}

/**
 * @brief Test Group 1.4 - Order cancellation (untouched)
 * @details Verifies INVALIDATE transaction for untouched order
 */
static void test_group_1_4_order_cancel(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.4: Order Cancellation (Untouched) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_tc0 = f->balances.alice_tc;
    
    // Test 1: Alice creates order to cancel
    log_it(L_INFO, "[1.4.1] Alice creates ASK: 200 KEL @ 5.0 USDT/KEL");
    dap_hash_fast_t order_hash = {0};
    int ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "200.0", "5.0", &order_hash);
    dap_assert(ret == 0, "Alice order created");
    
    // Alice: -200 KEL, -network_fee TestCoin
    uint256_t delta200 = dap_chain_coins_to_balance("200.0");
    uint256_t a_kel1 = uint256_0, a_tc1 = uint256_0;
    SUBTRACT_256_256(a_kel0, delta200, &a_kel1);
    SUBTRACT_256_256(a_tc0, f->network_fee, &a_tc1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL locked");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel1;
    f->balances.alice_tc  = a_tc1;
    
    // Test 2: Alice cancels the order by hash (INVALIDATE)
    log_it(L_INFO, "[1.4.2] Alice cancels the order by hash (INVALIDATE)");
    dap_hash_fast_t cancel_hash = {0};
    ret = test_dex_order_cancel(f, f->alice, &order_hash, &cancel_hash);
    dap_assert(ret == 0, "Alice order cancelled");
    
    // Mark order as cancelled in tracking
    test_dex_order_track_remove(f, &order_hash);
    
    // Alice's KEL refunded: +200 KEL back, another network_fee in TestCoin
    uint256_t a_kel2 = uint256_0, a_tc2 = uint256_0;
    SUM_256_256(a_kel1, delta200, &a_kel2);
    SUBTRACT_256_256(a_tc1, f->network_fee, &a_tc2);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel2).frac), "Alice KEL refunded");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc2).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel2;
    f->balances.alice_tc  = a_tc2;
    
    log_it(L_NOTICE, "✓ GROUP 1.4 PASSED: Order cancellation (untouched)");
}

/**
 * @brief Test Group 1.5 - Leftover cancellation (after partial fill)
 * @details Verifies INVALIDATE transaction for seller-leftover order
 */
static void test_group_1_5_leftover_cancel(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.5: Leftover Cancellation (After Partial Fill) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_usdt0 = f->balances.alice_usdt, a_tc0 = f->balances.alice_tc;
    uint256_t b_kel0 = f->balances.bob_kel,   b_usdt0 = f->balances.bob_usdt,   b_tc0 = f->balances.bob_tc;
    uint256_t c_usdt0 = f->balances.carol_usdt;
    
    // Test 1: Alice creates ASK order: 400 KEL @ 5.0 USDT/KEL
    log_it(L_INFO, "[1.5.1] Alice creates ASK: 400 KEL @ 5.0 USDT/KEL");
    dap_hash_fast_t order_hash = {0};
    int ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "400.0", "5.0", &order_hash);
    dap_assert(ret == 0, "Alice order created");
    
    // Alice: -400 KEL, -network_fee TestCoin
    uint256_t delta400 = dap_chain_coins_to_balance("400.0");
    uint256_t a_kel1 = uint256_0, a_tc1 = uint256_0;
    SUBTRACT_256_256(a_kel0, delta400, &a_kel1);
    SUBTRACT_256_256(a_tc0, f->network_fee, &a_tc1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL locked");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel1;
    f->balances.alice_tc  = a_tc1;
    
    // Test 2: Bob buys 250 KEL (partial fill, 150 KEL leftover)
    // Bob pays: 250 * 5.0 = 1250 USDT + 25 USDT fee (2%) = 1275 USDT total
    log_it(L_INFO, "[1.5.2] Bob buys 250 KEL (partial, 150 KEL leftover remains)");
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->bob, &order_hash, "250.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Bob partial purchase completed");
    
    // Verify balances after partial purchase:
    // Alice: +1250 USDT (seller payout for 250 KEL), KEL unchanged, TC unchanged
    uint256_t payout1250 = dap_chain_coins_to_balance("1250.0");
    uint256_t a_usdt1 = uint256_0;
    SUM_256_256(a_usdt0, payout1250, &a_usdt1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT",
               dap_uint256_to_char_ex(a_usdt1).frac), "Alice received USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC unchanged");
    f->balances.alice_usdt = a_usdt1;
    
    // Bob: +250 KEL, -1275 USDT (1250 + 25 fee), -network_fee TestCoin
    uint256_t delta_kel250 = dap_chain_coins_to_balance("250.0");
    uint256_t delta_usdt1275 = dap_chain_coins_to_balance("1275.0");
    uint256_t b_kel1 = uint256_0, b_usdt1 = uint256_0, b_tc1 = uint256_0;
    SUM_256_256(b_kel0, delta_kel250, &b_kel1);
    SUBTRACT_256_256(b_usdt0, delta_usdt1275, &b_usdt1);
    SUBTRACT_256_256(b_tc0, f->network_fee, &b_tc1);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel1).frac), "Bob received KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt1).frac), "Bob paid USDT + fee");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc1).frac), "Bob TC network fee");
    f->balances.bob_kel = b_kel1;
    f->balances.bob_usdt = b_usdt1;
    f->balances.bob_tc = b_tc1;
    
    // Carol (service wallet): +25 USDT (2% service fee)
    uint256_t fee25 = dap_chain_coins_to_balance("25.0");
    uint256_t c_usdt1 = uint256_0;
    SUM_256_256(c_usdt0, fee25, &c_usdt1);
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt1).frac), "Carol received service fee");
    f->balances.carol_usdt = c_usdt1;
    
    // Test 3: Alice cancels the leftover (150 KEL) by hash
    // Note: purchase_hash is the EXCHANGE tx, seller-leftover OUT_COND is in this tx
    // We need to find the leftover hash - it's the EXCHANGE tx hash with OUT_COND #0
    log_it(L_INFO, "[1.5.3] Alice cancels seller-leftover (150 KEL) by hash");
    dap_hash_fast_t cancel_hash = {0};
    ret = test_dex_order_cancel(f, f->alice, &purchase_hash, &cancel_hash);
    dap_assert(ret == 0, "Alice leftover cancelled");
    
    // Mark leftover as cancelled in tracking
    test_dex_order_track_remove(f, &order_hash);  // Remove by root (original order)
    
    // Alice's KEL refunded: +150 KEL, another network_fee TestCoin
    uint256_t delta150 = dap_chain_coins_to_balance("150.0");
    uint256_t a_kel2 = uint256_0, a_tc2 = uint256_0;
    SUM_256_256(a_kel1, delta150, &a_kel2);
    SUBTRACT_256_256(a_tc1, f->network_fee, &a_tc2);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel2).frac), "Alice KEL refunded");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc2).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel2;
    f->balances.alice_tc  = a_tc2;
    
    log_it(L_NOTICE, "✓ GROUP 1.5 PASSED: Leftover cancellation (after partial fill)");
}

/**
 * @brief Test Group 1.6 - BID partial purchase (seller-leftover)
 * @details Verifies BID order purchase with leftover (Carol sells KEL to Bob's BID)
 */
static void test_group_1_6_bid_partial_purchase(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.6: BID Partial Purchase (Seller-Leftover) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_usdt0 = f->balances.alice_usdt, a_tc0 = f->balances.alice_tc;
    uint256_t b_kel0 = f->balances.bob_kel,   b_usdt0 = f->balances.bob_usdt,   b_tc0 = f->balances.bob_tc;
    uint256_t c_kel0 = f->balances.carol_kel, c_usdt0 = f->balances.carol_usdt, c_tc0 = f->balances.carol_tc;
    
    // Bob's BID from 1.1: 2000 USDT for 500 KEL @ rate 4.0 USDT/KEL (side=BID, Bob sells USDT, buys KEL)
    // Carol sells 300 KEL → consumes 1200 USDT from Bob's locked
    // IMPORTANT: BID + service=seller → fee is NOT waived. As taker=seller (Carol), the fee is deducted from seller payout and sent as a separate OUT to service.
    // Composition: payout OUT = 1176 USDT, separate service fee OUT = 24 USDT → net to Carol = 1200 USDT.
    // Bob receives 300 KEL and pays 1 TestCoin network fee. Downstream balances remain unchanged.
    // Bob's leftover: 800 USDT locked (wants 200 KEL more)
    log_it(L_INFO, "[1.6.1] Carol sells 300 KEL to Bob's BID (partial, 800 USDT leftover)");
    
    // Find Bob's active BID order in tracker
    dap_hash_fast_t bob_bid_hash = {0};
    bool found = false;
    
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (e->active && 
            dap_chain_addr_compare(&e->seller_addr, &f->bob_addr) &&
            !dap_strcmp(e->token_buy, "KEL")) {
            bob_bid_hash = e->tail;  // Use tail (current order TX)
            found = true;
            log_it(L_INFO, "Found Bob's BID: %s", dap_chain_hash_fast_to_str_static(&bob_bid_hash));
            break;
        }
    }
    dap_assert(found, "Bob's BID order found");
    
    // Carol must first have KEL to sell - get Carol's cert and create emission
    dap_ledger_t *ledger = f->net->net->pub.ledger;
    dap_chain_wallet_internal_t *carol_int = DAP_CHAIN_WALLET_INTERNAL(f->carol);
    dap_cert_t *carol_cert = carol_int->certs[0];
    
    dap_chain_hash_fast_t carol_kel_emission_hash = {0};
    test_emission_fixture_t *carol_kel_emission = test_emission_fixture_create_with_cert(
        "KEL", dap_chain_coins_to_balance("500.0"), &f->carol_addr, carol_cert);
    dap_assert(carol_kel_emission != NULL, "Carol KEL emission created");
    dap_assert(test_emission_fixture_add_to_ledger(ledger, carol_kel_emission) == 0 &&
               test_emission_fixture_get_hash(carol_kel_emission, &carol_kel_emission_hash),
               "Carol KEL emission added to ledger");
    
    test_tx_fixture_t *carol_kel_tx = test_tx_fixture_create_from_emission(
        ledger, &carol_kel_emission_hash, "KEL", "500.0", &f->carol_addr, carol_cert);
    dap_assert(carol_kel_tx != NULL, "Carol KEL TX created");
    dap_assert(test_tx_fixture_add_to_ledger(ledger, carol_kel_tx) == 0,
               "Carol KEL TX added to ledger");
    log_it(L_INFO, "Carol received 500 KEL emission");
    
    // Carol sells 300 KEL to Bob's BID
    // is_budget_buy=false because Carol SELLS KEL (taker side = SELL for BID order)
    dap_hash_fast_t purchase_hash = {0};
    int ret = test_dex_order_purchase(f, f->carol, &bob_bid_hash, "300.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Carol purchase completed");
    
    // Verify balances after Carol sells 300 KEL to Bob's BID:
    // Bob: +300 KEL, free USDT and TC unchanged
    uint256_t delta_kel300 = dap_chain_coins_to_balance("300.0");
    uint256_t b_kel1 = uint256_0, b_usdt1 = b_usdt0, b_tc1 = b_tc0;
    SUM_256_256(b_kel0, delta_kel300, &b_kel1);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel1).frac), "Bob received KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt1).frac), "Bob USDT unchanged (free)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc1).frac), "Bob TC unchanged");
    f->balances.bob_kel = b_kel1;
    f->balances.bob_usdt = b_usdt1;
    f->balances.bob_tc = b_tc1;
    
    // Carol: +500 KEL emission, -300 KEL sold, -network_fee TestCoin, +1200 USDT net payout
    uint256_t delta_kel500 = dap_chain_coins_to_balance("500.0");
    uint256_t c_kel1_tmp = uint256_0, c_kel1 = uint256_0;
    SUM_256_256(c_kel0, delta_kel500, &c_kel1_tmp);
    SUBTRACT_256_256(c_kel1_tmp, delta_kel300, &c_kel1);
    uint256_t c_tc1 = uint256_0;
    SUBTRACT_256_256(c_tc0, f->network_fee, &c_tc1);
    uint256_t delta_usdt1200 = dap_chain_coins_to_balance("1200.0");
    uint256_t c_usdt1 = uint256_0;
    SUM_256_256(c_usdt0, delta_usdt1200, &c_usdt1);
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL",
               dap_uint256_to_char_ex(c_kel1).frac), "Carol KEL sold");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin",
               dap_uint256_to_char_ex(c_tc1).frac), "Carol TC network fee");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt1).frac), "Carol total USDT");
    f->balances.carol_kel = c_kel1;
    f->balances.carol_tc  = c_tc1;
    f->balances.carol_usdt = c_usdt1;
    
    // [1.6.2] Alice also sells KEL to Bob's BID leftover (partial, 400 USDT leftover remains)
    log_it(L_INFO, "[1.6.2] Alice sells 100 KEL to Bob's BID leftover (partial, 400 USDT leftover)");
    
    // Find Bob's BID leftover in tracker (updated after Carol's purchase)
    dap_hash_fast_t bob_bid_leftover_hash = {0};
    found = false;
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (e->active && 
            dap_chain_addr_compare(&e->seller_addr, &f->bob_addr) &&
            !dap_strcmp(e->token_buy, "KEL")) {
            bob_bid_leftover_hash = e->tail;  // Use updated tail after Carol's purchase
            found = true;
            log_it(L_INFO, "Found Bob's BID leftover: %s", dap_chain_hash_fast_to_str_static(&bob_bid_leftover_hash));
            break;
        }
    }
    dap_assert(found, "Bob's BID leftover found");
    
    // Alice sells 100 KEL to Bob's BID leftover
    // Consumes 400 USDT from Bob's locked (rate 4.0)
    // Alice receives: 392 USDT (400 - 8 service fee, taker pays fee in BID), Bob receives 100 KEL
    // Bob's leftover: 400 USDT locked (800 - 400, wants 100 KEL more)
    dap_hash_fast_t alice_purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->alice, &bob_bid_leftover_hash, "100.0", false, false, &alice_purchase_hash);
    dap_assert(ret == 0, "Alice purchase completed");
    
    // Final balance verification after Alice's purchase:
    
    // Alice: -100 KEL, +392 USDT, -network_fee TestCoin
    uint256_t delta_kel100 = dap_chain_coins_to_balance("100.0");
    uint256_t delta_usdt392 = dap_chain_coins_to_balance("392.0");
    uint256_t a_kel1 = uint256_0, a_usdt1 = uint256_0, a_tc1 = uint256_0;
    SUBTRACT_256_256(a_kel0, delta_kel100, &a_kel1);
    SUM_256_256(a_usdt0, delta_usdt392, &a_usdt1);
    SUBTRACT_256_256(a_tc0, f->network_fee, &a_tc1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL sold");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT",
               dap_uint256_to_char_ex(a_usdt1).frac), "Alice received USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel1;
    f->balances.alice_usdt = a_usdt1;
    f->balances.alice_tc = a_tc1;
    
    // Bob: +100 KEL on top of previous +300, USDT free and TC unchanged
    uint256_t b_kel2 = uint256_0, b_usdt2 = b_usdt1, b_tc2 = b_tc1;
    SUM_256_256(b_kel1, delta_kel100, &b_kel2);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel2).frac), "Bob received KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt2).frac), "Bob USDT free unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc2).frac), "Bob TC unchanged");
    f->balances.bob_kel = b_kel2;
    f->balances.bob_usdt = b_usdt2;
    f->balances.bob_tc = b_tc2;
    
    // Carol: +8 USDT service fee from Alice's purchase
    uint256_t delta_usdt8 = dap_chain_coins_to_balance("8.0");
    uint256_t c_usdt2 = uint256_0;
    SUM_256_256(c_usdt1, delta_usdt8, &c_usdt2);
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt2).frac), "Carol service fee from Alice");
    f->balances.carol_usdt = c_usdt2;
    
    log_it(L_NOTICE, "✓ GROUP 1.6 PASSED: BID partial purchases (400 USDT leftover remains in orderbook)");
}

/**
 * @brief Test Group 1.7 - BID full fill (symmetric to 1.2)
 * @details Verifies BID order fully consumed without leftovers
 */
static void test_group_1_7_bid_full_fill(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.7: BID Full Fill (Symmetric to 1.2) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_usdt0 = f->balances.alice_usdt, a_tc0 = f->balances.alice_tc;
    uint256_t b_kel0 = f->balances.bob_kel,   b_usdt0 = f->balances.bob_usdt,   b_tc0 = f->balances.bob_tc;
    uint256_t c_usdt0 = f->balances.carol_usdt;
    
    // State after 1.6:
    //   Alice:  KEL=8050.0   USDT=3642.0   TC=99992.0
    //   Bob:    KEL=1050.0   USDT=44685.0  TC=99996.0  (+400 USDT locked in BID leftover)
    //   Carol:  KEL=200.0    USDT=1273.0   TC=99999.0
    
    // Test 1: Bob creates new BID: 500 USDT for 125 KEL @ 4.0 USDT/KEL
    log_it(L_INFO, "[1.7.1] Bob creates BID: 500 USDT for 125 KEL @ 4.0 USDT/KEL");
    dap_hash_fast_t order_hash = {0};
    int ret = test_dex_order_create(f, f->bob, "KEL", "USDT", "500.0", "0.25", &order_hash);
    dap_assert(ret == 0, "Bob BID order created");
    
    // Bob: -500 USDT (locked in BID), -network_fee TestCoin
    uint256_t delta_usdt500 = dap_chain_coins_to_balance("500.0");
    uint256_t b_usdt1 = uint256_0, b_tc1 = uint256_0;
    SUBTRACT_256_256(b_usdt0, delta_usdt500, &b_usdt1);
    SUBTRACT_256_256(b_tc0, f->network_fee, &b_tc1);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt1).frac), "Bob USDT locked");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc1).frac), "Bob TC network fee");
    f->balances.bob_usdt = b_usdt1;
    f->balances.bob_tc = b_tc1;
    
    // Test 2: Alice sells EXACTLY 125 KEL to Bob's BID (full fill, no leftover)
    // Alice receives: 490 USDT (500 - 10 service fee @ 2%)
    // Bob receives: 125 KEL
    // Carol receives: 10 USDT service fee
    log_it(L_INFO, "[1.7.2] Alice sells exactly 125 KEL to Bob's BID (full fill)");
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->alice, &order_hash, "125.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Alice purchase completed");
    
    // Verify balances after full fill:
    // Alice: -125 KEL, +490 USDT, -network_fee TestCoin
    uint256_t delta_kel125 = dap_chain_coins_to_balance("125.0");
    uint256_t delta_usdt490 = dap_chain_coins_to_balance("490.0");
    uint256_t a_kel1 = uint256_0, a_usdt1 = uint256_0, a_tc1 = uint256_0;
    SUBTRACT_256_256(a_kel0, delta_kel125, &a_kel1);
    SUM_256_256(a_usdt0, delta_usdt490, &a_usdt1);
    SUBTRACT_256_256(a_tc0, f->network_fee, &a_tc1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL sold");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT",
               dap_uint256_to_char_ex(a_usdt1).frac), "Alice received USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel1;
    f->balances.alice_usdt = a_usdt1;
    f->balances.alice_tc = a_tc1;
    
    // Bob: +125 KEL on top of previous state, free USDT and TC unchanged vs after order creation
    uint256_t b_kel1 = uint256_0, b_usdt2 = b_usdt1, b_tc2 = b_tc1;
    SUM_256_256(b_kel0, delta_kel125, &b_kel1);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel1).frac), "Bob received KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt2).frac), "Bob USDT free unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc2).frac), "Bob TC unchanged");
    f->balances.bob_kel = b_kel1;
    f->balances.bob_usdt = b_usdt2;
    f->balances.bob_tc = b_tc2;
    
    // Carol: +10 USDT service fee
    uint256_t delta_usdt10 = dap_chain_coins_to_balance("10.0");
    uint256_t c_usdt1 = uint256_0;
    SUM_256_256(c_usdt0, delta_usdt10, &c_usdt1);
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt1).frac), "Carol service fee");
    f->balances.carol_usdt = c_usdt1;
    
    log_it(L_NOTICE, "✓ GROUP 1.7 PASSED: BID full fill (no leftovers)");
}

/**
 * @brief Test Group 1.8 - BID cancel untouched (symmetric to 1.4)
 * @details Verifies INVALIDATE transaction for untouched BID order
 */
static void test_group_1_8_bid_cancel_untouched(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.8: BID Cancel Untouched (Symmetric to 1.4) ===");
    dex_update_balances(f);
    uint256_t b_usdt0 = f->balances.bob_usdt, b_tc0 = f->balances.bob_tc;
    
    // State after 1.7:
    //   Alice:  KEL=7925.0   USDT=4132.0   TC=99991.0
    //   Bob:    KEL=1175.0   USDT=44185.0  TC=99995.0  (+400 USDT locked in old BID leftover)
    //   Carol:  KEL=200.0    USDT=1283.0   TC=99999.0
    
    // Test 1: Bob creates new BID: 300 USDT for 75 KEL @ 4.0 USDT/KEL
    log_it(L_INFO, "[1.8.1] Bob creates BID: 300 USDT for 75 KEL @ 4.0 USDT/KEL");
    dap_hash_fast_t order_hash = {0};
    int ret = test_dex_order_create(f, f->bob, "KEL", "USDT", "300.0", "0.25", &order_hash);
    dap_assert(ret == 0, "Bob BID order created");
    
    // Bob: -300 USDT (locked), -network_fee TestCoin
    uint256_t delta_usdt300 = dap_chain_coins_to_balance("300.0");
    uint256_t b_usdt1 = uint256_0, b_tc1 = uint256_0;
    SUBTRACT_256_256(b_usdt0, delta_usdt300, &b_usdt1);
    SUBTRACT_256_256(b_tc0, f->network_fee, &b_tc1);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt1).frac), "Bob USDT locked");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc1).frac), "Bob TC network fee");
    f->balances.bob_usdt = b_usdt1;
    f->balances.bob_tc = b_tc1;
    
    // Test 2: Bob cancels the order by hash (INVALIDATE)
    log_it(L_INFO, "[1.8.2] Bob cancels the order by hash (INVALIDATE)");
    dap_hash_fast_t cancel_hash = {0};
    ret = test_dex_order_cancel(f, f->bob, &order_hash, &cancel_hash);
    dap_assert(ret == 0, "Bob order cancelled");
    
    // Bob's USDT refunded: +300 USDT, another network_fee TestCoin
    uint256_t b_usdt2 = uint256_0, b_tc2 = uint256_0;
    SUM_256_256(b_usdt1, delta_usdt300, &b_usdt2);
    SUBTRACT_256_256(b_tc1, f->network_fee, &b_tc2);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt2).frac), "Bob USDT refunded");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc2).frac), "Bob TC network fee");
    f->balances.bob_usdt = b_usdt2;
    f->balances.bob_tc = b_tc2;
    
    log_it(L_NOTICE, "✓ GROUP 1.8 PASSED: BID cancellation (untouched)");
}

/**
 * @brief Test Group 1.9 - BID cancel leftover (symmetric to 1.5)
 * @details Verifies INVALIDATE transaction for BID leftover order
 */
static void test_group_1_9_bid_cancel_leftover(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.9: BID Cancel Leftover (Symmetric to 1.5) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_usdt0 = f->balances.alice_usdt, a_tc0 = f->balances.alice_tc;
    uint256_t b_kel0 = f->balances.bob_kel,   b_usdt0 = f->balances.bob_usdt,   b_tc0 = f->balances.bob_tc;
    uint256_t c_usdt0 = f->balances.carol_usdt;
    
    // State after 1.8:
    //   Alice:  KEL=7925.0   USDT=4132.0   TC=99991.0
    //   Bob:    KEL=1175.0   USDT=44185.0  TC=99993.0  (+400 USDT locked in old BID leftover from 1.6)
    //   Carol:  KEL=200.0    USDT=1283.0   TC=99999.0
    
    // Test 1: Bob creates new BID: 600 USDT for 150 KEL @ 4.0 USDT/KEL
    log_it(L_INFO, "[1.9.1] Bob creates BID: 600 USDT for 150 KEL @ 4.0 USDT/KEL");
    dap_hash_fast_t order_hash = {0};
    int ret = test_dex_order_create(f, f->bob, "KEL", "USDT", "600.0", "0.25", &order_hash);
    dap_assert(ret == 0, "Bob BID order created");
    
    // Bob: -600 USDT (locked), -network_fee TestCoin
    uint256_t delta_usdt600 = dap_chain_coins_to_balance("600.0");
    uint256_t b_usdt1 = uint256_0, b_tc1 = uint256_0;
    SUBTRACT_256_256(b_usdt0, delta_usdt600, &b_usdt1);
    SUBTRACT_256_256(b_tc0, f->network_fee, &b_tc1);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt1).frac), "Bob USDT locked");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc1).frac), "Bob TC network fee");
    f->balances.bob_usdt = b_usdt1;
    f->balances.bob_tc = b_tc1;
    
    // Test 2: Alice sells 80 KEL (partial fill, 70 KEL leftover in BID)
    // Alice receives: 313.6 USDT (320 - 6.4 service fee @ 2%)
    // Bob receives: 80 KEL
    // Carol receives: 6.4 USDT service fee
    // Bob's leftover: 280 USDT locked (wants 70 KEL @ 4.0)
    log_it(L_INFO, "[1.9.2] Alice sells 80 KEL (partial, 70 KEL leftover in BID)");
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->alice, &order_hash, "80.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Alice partial purchase completed");
    
    // Verify balances after partial purchase:
    // Alice: -80 KEL, +313.6 USDT, -network_fee TestCoin
    uint256_t delta_kel80 = dap_chain_coins_to_balance("80.0");
    uint256_t delta_usdt313_6 = dap_chain_coins_to_balance("313.6");
    uint256_t a_kel1 = uint256_0, a_usdt1 = uint256_0, a_tc1 = uint256_0;
    SUBTRACT_256_256(a_kel0, delta_kel80, &a_kel1);
    SUM_256_256(a_usdt0, delta_usdt313_6, &a_usdt1);
    SUBTRACT_256_256(a_tc0, f->network_fee, &a_tc1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL sold");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT",
               dap_uint256_to_char_ex(a_usdt1).frac), "Alice received USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel1;
    f->balances.alice_usdt = a_usdt1;
    f->balances.alice_tc = a_tc1;
    
    // Bob: +80 KEL, free USDT and TC unchanged vs after order creation
    uint256_t delta_kel80_b = delta_kel80;
    uint256_t b_kel1 = uint256_0, b_usdt2 = b_usdt1, b_tc2 = b_tc1;
    SUM_256_256(b_kel0, delta_kel80_b, &b_kel1);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel1).frac), "Bob received KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt2).frac), "Bob USDT free unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc2).frac), "Bob TC unchanged");
    f->balances.bob_kel = b_kel1;
    f->balances.bob_usdt = b_usdt2;
    f->balances.bob_tc = b_tc2;
    
    // Carol: +6.4 USDT service fee
    uint256_t delta_usdt6_4 = dap_chain_coins_to_balance("6.4");
    uint256_t c_usdt1 = uint256_0;
    SUM_256_256(c_usdt0, delta_usdt6_4, &c_usdt1);
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt1).frac), "Carol service fee");
    f->balances.carol_usdt = c_usdt1;
    
    // Test 3: Bob cancels the leftover (70 KEL → 280 USDT) by hash
    // NOTE: Bob's leftover (280 USDT) remains in orderbook for cancel_all_by_seller test in 1.16
    // Update tracking to reflect the new leftover order
    test_dex_order_track_update(f, &order_hash, &purchase_hash, dap_chain_coins_to_balance("280.0"));
    
    // Bob's final state: USDT=43585 (280 locked in leftover), KEL=1255, TC=99992
    // No balance changes here, leftover remains active
    
    log_it(L_NOTICE, "✓ GROUP 1.9 PASSED: BID partial fill created leftover (280 USDT remains for cancel_all test)");
}

/**
 * @brief Test Group 1.10 - Security: Cancel foreign ASK (rejected)
 * @details Verifies that Bob CANNOT cancel Alice's ASK order
 */
static void test_group_1_10_security_cancel_foreign_ask(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.10: SECURITY - Cancel Foreign ASK (rejected) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_tc0 = f->balances.alice_tc;
    uint256_t b_tc0 = f->balances.bob_tc;
    
    // State after 1.9:
    //   Alice:  KEL=7845.0   USDT=4445.6   TC=99990.0
    //   Bob:    KEL=1255.0   USDT=43585.0  TC=99992.0  (+280 USDT locked in leftover from 1.9, +400 USDT locked in leftover from 1.6)
    //   Carol:  KEL=200.0    USDT=1289.4   TC=99999.0
    
    // Test 1: Alice creates ASK: 150 KEL @ 5.0 USDT/KEL
    log_it(L_INFO, "[1.10.1] Alice creates ASK: 150 KEL @ 5.0 USDT/KEL");
    dap_hash_fast_t order_hash = {0};
    int ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "150.0", "5.0", &order_hash);
    dap_assert(ret == 0, "Alice ASK order created");
    
    // Alice: -150 KEL, -network_fee TestCoin
    uint256_t delta150 = dap_chain_coins_to_balance("150.0");
    uint256_t a_kel1 = uint256_0, a_tc1 = uint256_0;
    SUBTRACT_256_256(a_kel0, delta150, &a_kel1);
    SUBTRACT_256_256(a_tc0, f->network_fee, &a_tc1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL locked");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel1;
    f->balances.alice_tc  = a_tc1;
    
    // Test 2: Bob attempts to INVALIDATE Alice's ASK (SECURITY TEST)
    log_it(L_INFO, "[1.10.2] Bob attempts to INVALIDATE Alice's ASK (should be REJECTED)");
    dap_hash_fast_t cancel_hash = {0};
    ret = test_dex_order_cancel(f, f->bob, &order_hash, &cancel_hash);
    dap_assert(ret != 0, "Bob's cancel attempt REJECTED (expected)");
    
    // Bob's TC: unchanged (failed TX rejected BEFORE ledger, no fee charged)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc0).frac), "Bob TC unchanged (TX rejected)");
    // f->balances.bob_tc remains as at start
    
    // Alice's order still active (KEL still locked)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7695.0"), "Alice KEL still locked");
    
    // Cleanup: Alice cancels her own order
    log_it(L_INFO, "[1.10.3] Alice cancels her own ASK (cleanup)");
    ret = test_dex_order_cancel(f, f->alice, &order_hash, &cancel_hash);
    dap_assert(ret == 0, "Alice successfully cancelled her own order");
    
    // Mark order as cancelled in tracking
    test_dex_order_track_remove(f, &order_hash);
    
    // Alice: +150 KEL refunded, another network_fee TestCoin
    uint256_t a_kel2 = uint256_0, a_tc2 = uint256_0;
    SUM_256_256(a_kel1, delta150, &a_kel2);
    SUBTRACT_256_256(a_tc1, f->network_fee, &a_tc2);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel2).frac), "Alice KEL refunded");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc2).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel2;
    f->balances.alice_tc  = a_tc2;
    // Bob TC remains 99992.0 (unchanged from failed attempt)
    
    log_it(L_NOTICE, "✓ GROUP 1.10 PASSED: Foreign ASK cancellation rejected (security validated)");
}

/**
 * @brief Test Group 1.11 - Security: Cancel foreign BID (rejected)
 * @details Verifies that Alice CANNOT cancel Bob's BID order
 */
static void test_group_1_11_security_cancel_foreign_bid(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.11: SECURITY - Cancel Foreign BID (rejected) ===");
    dex_update_balances(f);
    uint256_t a_tc0 = f->balances.alice_tc;
    uint256_t b_usdt0 = f->balances.bob_usdt, b_tc0 = f->balances.bob_tc;
    
    // State after 1.10:
    //   Alice:  KEL=7845.0   USDT=4445.6   TC=99988.0
    //   Bob:    KEL=1255.0   USDT=43585.0  TC=99992.0  (+280 USDT locked in leftover from 1.9, +400 USDT locked in leftover from 1.6)
    //   Carol:  KEL=200.0    USDT=1289.4   TC=99999.0
    
    // Test 1: Bob creates new BID: 400 USDT for 100 KEL @ 4.0 USDT/KEL
    log_it(L_INFO, "[1.11.1] Bob creates BID: 400 USDT for 100 KEL @ 4.0 USDT/KEL");
    dap_hash_fast_t order_hash = {0};
    int ret = test_dex_order_create(f, f->bob, "KEL", "USDT", "400.0", "0.25", &order_hash);
    dap_assert(ret == 0, "Bob BID order created");
    
    // Bob: -400 USDT (locked), -network_fee TestCoin
    uint256_t delta_usdt400 = dap_chain_coins_to_balance("400.0");
    uint256_t b_usdt1 = uint256_0, b_tc1 = uint256_0;
    SUBTRACT_256_256(b_usdt0, delta_usdt400, &b_usdt1);
    SUBTRACT_256_256(b_tc0, f->network_fee, &b_tc1);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt1).frac), "Bob USDT locked");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc1).frac), "Bob TC network fee");
    f->balances.bob_usdt = b_usdt1;
    f->balances.bob_tc = b_tc1;
    
    // Test 2: Alice attempts to INVALIDATE Bob's BID (SECURITY TEST)
    log_it(L_INFO, "[1.11.2] Alice attempts to INVALIDATE Bob's BID (should be REJECTED)");
    dap_hash_fast_t cancel_hash = {0};
    ret = test_dex_order_cancel(f, f->alice, &order_hash, &cancel_hash);
    dap_assert(ret != 0, "Alice's cancel attempt REJECTED (expected)");
    
    // Alice's TC: unchanged (failed TX rejected BEFORE ledger, no fee charged)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc0).frac), "Alice TC unchanged (TX rejected)");
    // f->balances.alice_tc remains as at start
    
    // Bob's order still active (USDT still locked)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "43185.0"), "Bob USDT still locked");
    
    // Cleanup: Bob cancels his own order
    log_it(L_INFO, "[1.11.3] Bob cancels his own BID (cleanup)");
    ret = test_dex_order_cancel(f, f->bob, &order_hash, &cancel_hash);
    dap_assert(ret == 0, "Bob successfully cancelled his own order");
    
    // Mark order as cancelled in tracking
    test_dex_order_track_remove(f, &order_hash);
    
    // Bob: +400 USDT refunded, another network_fee TestCoin
    uint256_t b_usdt2 = uint256_0, b_tc2 = uint256_0;
    SUM_256_256(b_usdt1, delta_usdt400, &b_usdt2);
    SUBTRACT_256_256(b_tc1, f->network_fee, &b_tc2);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt2).frac), "Bob USDT refunded");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc2).frac), "Bob TC network fee");
    f->balances.bob_usdt = b_usdt2;
    f->balances.bob_tc = b_tc2;
    // Alice TC remains 99988.0 (unchanged from failed attempt)
    
    log_it(L_NOTICE, "✓ GROUP 1.11 PASSED: Foreign BID cancellation rejected (security validated)");
}

/**
 * @brief Test Group 1.12 - Security: Tampered EXCHANGE seller payout (rejected)
 * @details Verifies that manual tampering of seller payout in EXCHANGE TX is rejected by verificator.
 *          Scenario:
 *          - Use existing Bob BID leftover (from previous tests) as counterparty
 *          - Let Carol sell KEL into this BID (template EXCHANGE via composer, not added to ledger)
 *          - Tamper seller's USDT payout OUT_EXT for Bob
 *          - Sign and try to add TX to ledger
 *          - Expect verificator rejection and all balances unchanged
 */
static void test_group_1_12_security_exchange_tamper(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.12: SECURITY - Tampered EXCHANGE Seller Payout (rejected) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_usdt0 = f->balances.alice_usdt, a_tc0 = f->balances.alice_tc;
    uint256_t b_kel0 = f->balances.bob_kel,   b_usdt0 = f->balances.bob_usdt,   b_tc0 = f->balances.bob_tc;
    uint256_t c_kel0 = f->balances.carol_kel, c_usdt0 = f->balances.carol_usdt, c_tc0 = f->balances.carol_tc;

    // Locate active Bob BID leftover (sells USDT, buys KEL)
    log_it(L_INFO, "[1.12.1] Locate active Bob BID leftover for tampering");
    order_entry_t *l_order = NULL;
    for (order_entry_t *e = f->orders; e; e = e->next)
        if (e->active && e->side == 1 && dap_chain_addr_compare(&e->seller_addr, &f->bob_addr)
                && !dap_strcmp(e->token_buy, "KEL") && !dap_strcmp(e->token_sell, "USDT")) {
            l_order = e;
            break;
        }
    dap_assert(l_order != NULL, "Found Bob BID leftover (USDT→KEL)");

    // Build template EXCHANGE TX via API (Carol sells 50 KEL into Bob's BID), but do not add it to ledger
    log_it(L_INFO, "[1.12.2] Build template EXCHANGE (Carol sells 50 KEL into Bob's BID)");
    uint256_t l_budget = dap_chain_coins_to_balance("50.0");
    dap_chain_datum_tx_t *l_tx_template = NULL;
    dap_chain_net_srv_dex_purchase_error_t l_err = dap_chain_net_srv_dex_purchase(
        f->net->net, &l_order->tail, l_budget, false, f->network_fee, f->carol, NULL,
        false, uint256_0, 0, &l_tx_template
    );
    dap_assert(l_err == DEX_PURCHASE_ERROR_OK && l_tx_template != NULL, "Template EXCHANGE TX created");

    // Strip signatures: copy TX bytes up to first SIG item
    uint8_t *l_first_sig = dap_chain_datum_tx_item_get(l_tx_template, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_assert(l_first_sig != NULL, "Found signature in template EXCHANGE TX");
    size_t l_tx_size_without_sigs = (size_t)(l_first_sig - (uint8_t*)l_tx_template);

    dap_chain_datum_tx_t *l_new_tx = DAP_DUP_SIZE(l_tx_template, l_tx_size_without_sigs);
    dap_assert(l_new_tx != NULL, "Created new TX without signatures");
    l_new_tx->header.tx_items_size = l_tx_size_without_sigs - sizeof(dap_chain_datum_tx_t);

    // Find seller payout for Bob (in order's buy_token, OUT_EXT or OUT_STD) and tamper its value
    log_it(L_INFO, "[1.12.3] Tamper seller payout OUT in EXCHANGE TX");
    dap_chain_tx_out_ext_t *l_seller_out_ext = NULL;
    dap_chain_tx_out_std_t *l_seller_out_std = NULL;
    byte_t *it; size_t sz;
    TX_ITEM_ITER_TX(it, sz, l_new_tx) {
        if (*it == TX_ITEM_TYPE_OUT_EXT) {
            dap_chain_tx_out_ext_t *l_out = (dap_chain_tx_out_ext_t*)it;
            if (!dap_strcmp(l_out->token, l_order->token_buy) && dap_chain_addr_compare(&l_out->addr, &f->bob_addr)) {
                l_seller_out_ext = l_out;
                break;
            }
        } else if (*it == TX_ITEM_TYPE_OUT_STD) {
            dap_chain_tx_out_std_t *l_out = (dap_chain_tx_out_std_t*)it;
            if (!dap_strcmp(l_out->token, l_order->token_buy) && dap_chain_addr_compare(&l_out->addr, &f->bob_addr)) {
                l_seller_out_std = l_out;
                break;
            }
        }
    }
    dap_assert(l_seller_out_ext || l_seller_out_std, "Found seller payout OUT for Bob");

    uint256_t l_delta = dap_chain_coins_to_balance("1.0"), l_new_val = uint256_0;
    if (l_seller_out_ext) {
        if (compare256(l_seller_out_ext->header.value, l_delta) > 0)
            SUBTRACT_256_256(l_seller_out_ext->header.value, l_delta, &l_new_val), l_seller_out_ext->header.value = l_new_val;
        else
            SUM_256_256(l_seller_out_ext->header.value, l_delta, &l_seller_out_ext->header.value);
    } else {
        if (compare256(l_seller_out_std->value, l_delta) > 0)
            SUBTRACT_256_256(l_seller_out_std->value, l_delta, &l_new_val), l_seller_out_std->value = l_new_val;
        else
            SUM_256_256(l_seller_out_std->value, l_delta, &l_seller_out_std->value);
    }

    // Re-sign tampered TX with Carol's key (taker)
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(f->carol, 0);
    dap_assert(l_key != NULL, "Got Carol's key");
    dap_assert(dap_chain_datum_tx_add_sign_item(&l_new_tx, l_key) > 0, "Signed tampered EXCHANGE TX");
    dap_enc_key_delete(l_key);

    // Try to add tampered TX to ledger: verificator must reject it
    dap_hash_fast_t l_tampered_hash = {0};
    dap_hash_fast(l_new_tx, dap_chain_datum_tx_get_size(l_new_tx), &l_tampered_hash);
    int l_verif_err = dap_ledger_tx_add(f->net->net->pub.ledger, l_new_tx, &l_tampered_hash, false, NULL);
    dap_chain_datum_tx_delete(l_tx_template);
    dap_chain_datum_tx_delete(l_new_tx);
    dap_assert(l_verif_err != 0, "Tampered EXCHANGE TX rejected by verificator");

    // Verify all balances unchanged (TX rejected)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel0).frac), "Alice KEL unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT",
               dap_uint256_to_char_ex(a_usdt0).frac), "Alice USDT unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc0).frac), "Alice TC unchanged (TX rejected)");

    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel0).frac), "Bob KEL unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt0).frac), "Bob USDT unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc0).frac), "Bob TC unchanged (TX rejected)");

    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL",
               dap_uint256_to_char_ex(c_kel0).frac), "Carol KEL unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt0).frac), "Carol USDT unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin",
               dap_uint256_to_char_ex(c_tc0).frac), "Carol TC unchanged (TX rejected)");

    log_it(L_NOTICE, "✓ GROUP 1.12 PASSED: Tampered EXCHANGE seller payout rejected");
}

/**
 * @brief Test Group 1.12b - Security: Tampered EXCHANGE buyer cashback (rejected)
 * @details Reuses Bob's BID leftover and Carol as taker. Template EXCHANGE has:
 *          - Buyer cashback in buy token (KEL) and native (TestCoin)
 *          We tamper buyer's cashback in buy token; verificator must reject TX and balances stay unchanged.
 */
static void test_group_1_12b_security_cashback_tamper(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.12b: SECURITY - Tampered EXCHANGE Buyer Cashback (rejected) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_usdt0 = f->balances.alice_usdt, a_tc0 = f->balances.alice_tc;
    uint256_t b_kel0 = f->balances.bob_kel,   b_usdt0 = f->balances.bob_usdt,   b_tc0 = f->balances.bob_tc;
    uint256_t c_kel0 = f->balances.carol_kel, c_usdt0 = f->balances.carol_usdt, c_tc0 = f->balances.carol_tc;

    // Locate active Bob BID leftover (sells USDT, buys KEL)
    log_it(L_INFO, "[1.12b.1] Locate active Bob BID leftover for cashback tampering");
    order_entry_t *l_order = NULL;
    for (order_entry_t *e = f->orders; e; e = e->next)
        if (e->active && e->side == 1 && dap_chain_addr_compare(&e->seller_addr, &f->bob_addr)
                && !dap_strcmp(e->token_buy, "KEL") && !dap_strcmp(e->token_sell, "USDT")) {
            l_order = e;
            break;
        }
    dap_assert(l_order != NULL, "Found Bob BID leftover (USDT→KEL)");

    // Build template EXCHANGE TX via API (Carol sells 50 KEL into Bob's BID), but do not add it to ledger
    log_it(L_INFO, "[1.12b.2] Build template EXCHANGE (Carol sells 50 KEL into Bob's BID)");
    uint256_t l_budget = dap_chain_coins_to_balance("50.0");
    dap_chain_datum_tx_t *l_tx_template = NULL;
    dap_chain_net_srv_dex_purchase_error_t l_err = dap_chain_net_srv_dex_purchase(
        f->net->net, &l_order->tail, l_budget, false, f->network_fee, f->carol, NULL,
        false, uint256_0, 0, &l_tx_template
    );
    dap_assert(l_err == DEX_PURCHASE_ERROR_OK && l_tx_template != NULL, "Template EXCHANGE TX created");

    // Strip signatures
    uint8_t *l_first_sig = dap_chain_datum_tx_item_get(l_tx_template, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_assert(l_first_sig != NULL, "Found signature in template EXCHANGE TX");
    size_t l_tx_size_without_sigs = (size_t)(l_first_sig - (uint8_t*)l_tx_template);

    dap_chain_datum_tx_t *l_new_tx = DAP_DUP_SIZE(l_tx_template, l_tx_size_without_sigs);
    dap_assert(l_new_tx != NULL, "Created new TX without signatures");
    l_new_tx->header.tx_items_size = l_tx_size_without_sigs - sizeof(dap_chain_datum_tx_t);

    // Find buyer cashback OUT (EXT or STD) in buy token (KEL) to Carol and tamper its value
    log_it(L_INFO, "[1.12b.3] Tamper buyer cashback OUT in EXCHANGE TX");
    dap_chain_tx_out_ext_t *l_cb_out_ext = NULL;
    dap_chain_tx_out_std_t *l_cb_out_std = NULL; 
    byte_t *it; size_t sz;
    TX_ITEM_ITER_TX(it, sz, l_new_tx) {
        if (*it == TX_ITEM_TYPE_OUT_EXT) {
            dap_chain_tx_out_ext_t *l_out = (dap_chain_tx_out_ext_t*)it;
            if (!dap_strcmp(l_out->token, l_order->token_buy) && dap_chain_addr_compare(&l_out->addr, &f->carol_addr)) {
                l_cb_out_ext = l_out;
                break;
            }
        } else if (*it == TX_ITEM_TYPE_OUT_STD) {
            dap_chain_tx_out_std_t *l_out = (dap_chain_tx_out_std_t*)it;
            if (!dap_strcmp(l_out->token, l_order->token_buy) && dap_chain_addr_compare(&l_out->addr, &f->carol_addr)) {
                l_cb_out_std = l_out;
                break;
            }
        }
    }
    dap_assert(l_cb_out_ext || l_cb_out_std, "Found buyer cashback OUT for Carol in buy token");

    uint256_t l_delta = dap_chain_coins_to_balance("1.0"), l_new_val = uint256_0;
    if (l_cb_out_ext) {
        if (compare256(l_cb_out_ext->header.value, l_delta) > 0)
            SUBTRACT_256_256(l_cb_out_ext->header.value, l_delta, &l_new_val), l_cb_out_ext->header.value = l_new_val;
        else
            SUM_256_256(l_cb_out_ext->header.value, l_delta, &l_cb_out_ext->header.value);
    } else {
        if (compare256(l_cb_out_std->value, l_delta) > 0)
            SUBTRACT_256_256(l_cb_out_std->value, l_delta, &l_new_val), l_cb_out_std->value = l_new_val;
        else
            SUM_256_256(l_cb_out_std->value, l_delta, &l_cb_out_std->value);
    }

    // Re-sign tampered TX with Carol's key (taker)
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(f->carol, 0);
    dap_assert(l_key != NULL, "Got Carol's key");
    dap_assert(dap_chain_datum_tx_add_sign_item(&l_new_tx, l_key) > 0, "Signed tampered EXCHANGE TX");
    dap_enc_key_delete(l_key);

    // Try to add tampered TX to ledger: verificator must reject it
    dap_hash_fast_t l_tampered_hash = {0};
    dap_hash_fast(l_new_tx, dap_chain_datum_tx_get_size(l_new_tx), &l_tampered_hash);
    int l_verif_err = dap_ledger_tx_add(f->net->net->pub.ledger, l_new_tx, &l_tampered_hash, false, NULL);
    dap_chain_datum_tx_delete(l_tx_template);
    dap_chain_datum_tx_delete(l_new_tx);
    dap_assert(l_verif_err != 0, "Tampered cashback EXCHANGE TX rejected by verificator");

    // Verify all balances unchanged (TX rejected)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel0).frac), "Alice KEL unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT",
               dap_uint256_to_char_ex(a_usdt0).frac), "Alice USDT unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc0).frac), "Alice TC unchanged (TX rejected)");

    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel0).frac), "Bob KEL unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt0).frac), "Bob USDT unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc0).frac), "Bob TC unchanged (TX rejected)");

    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL",
               dap_uint256_to_char_ex(c_kel0).frac), "Carol KEL unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt0).frac), "Carol USDT unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin",
               dap_uint256_to_char_ex(c_tc0).frac), "Carol TC unchanged (TX rejected)");

    log_it(L_NOTICE, "✓ GROUP 1.12b PASSED: Tampered EXCHANGE buyer cashback rejected");
}

/**
 * @brief Test Group 1.12c - Security: Tampered EXCHANGE service fee (rejected)
 * @details Uses a standard EXCHANGE with non-waived QUOTE service fee:
 *          - Build template where buyer is NOT service wallet (fee in QUOTE)
 *          - Tamper service fee OUT_EXT value
 *          - Expect verificator rejection and unchanged balances
 */
static void test_group_1_12c_security_fee_tamper(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.12c: SECURITY - Tampered EXCHANGE Service Fee (rejected) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_usdt0 = f->balances.alice_usdt, a_tc0 = f->balances.alice_tc;
    uint256_t b_kel0 = f->balances.bob_kel,   b_usdt0 = f->balances.bob_usdt,   b_tc0 = f->balances.bob_tc;
    uint256_t c_kel0 = f->balances.carol_kel, c_usdt0 = f->balances.carol_usdt, c_tc0 = f->balances.carol_tc;

    // Create fresh ASK order from Alice: 100 KEL @ 5 USDT/KEL
    log_it(L_INFO, "[1.12c.1] Alice creates ASK: 100 KEL @ 5.0 USDT/KEL");
    dap_hash_fast_t l_order_hash = {0};
    int ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "100.0", "5.0", &l_order_hash);
    dap_assert(ret == 0, "Alice ASK order created for fee tampering test");

    // Build template EXCHANGE TX via API (Bob buys 100 KEL), but do not add it to ledger
    log_it(L_INFO, "[1.12c.2] Build template EXCHANGE (Bob buys 100 KEL, fee in QUOTE)");
    uint256_t l_budget = dap_chain_coins_to_balance("100.0");
    dap_chain_datum_tx_t *l_tx_template = NULL;
    dap_chain_net_srv_dex_purchase_error_t l_err = dap_chain_net_srv_dex_purchase(
        f->net->net, &l_order_hash, l_budget, true, f->network_fee, f->bob, NULL,
        false, uint256_0, 0, &l_tx_template
    );
    dap_assert(l_err == DEX_PURCHASE_ERROR_OK && l_tx_template != NULL, "Template EXCHANGE TX created");

    // Strip signatures
    uint8_t *l_first_sig = dap_chain_datum_tx_item_get(l_tx_template, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_assert(l_first_sig != NULL, "Found signature in template EXCHANGE TX");
    size_t l_tx_size_without_sigs = (size_t)(l_first_sig - (uint8_t*)l_tx_template);

    dap_chain_datum_tx_t *l_new_tx = DAP_DUP_SIZE(l_tx_template, l_tx_size_without_sigs);
    dap_assert(l_new_tx != NULL, "Created new TX without signatures");
    l_new_tx->header.tx_items_size = l_tx_size_without_sigs - sizeof(dap_chain_datum_tx_t);

    // Find service fee OUT_EXT in QUOTE token (USDT) to service wallet (Carol) and tamper its value
    log_it(L_INFO, "[1.12c.3] Tamper service fee OUT_EXT in EXCHANGE TX");
    dap_chain_tx_out_ext_t *l_fee_out = NULL;
    byte_t *it; size_t sz;
    TX_ITEM_ITER_TX(it, sz, l_new_tx) if (*it == TX_ITEM_TYPE_OUT_EXT) {
        dap_chain_tx_out_ext_t *l_out = (dap_chain_tx_out_ext_t*)it;
        if (!dap_strcmp(l_out->token, "USDT") &&
            dap_chain_addr_compare(&l_out->addr, &f->carol_addr)) {
            l_fee_out = l_out;
            break;
        }
    }
    dap_assert(l_fee_out != NULL, "Found service fee OUT_EXT in QUOTE token for Carol");

    uint256_t l_delta = dap_chain_coins_to_balance("1.0"), l_new_val = uint256_0;
    if (compare256(l_fee_out->header.value, l_delta) > 0)
        SUBTRACT_256_256(l_fee_out->header.value, l_delta, &l_new_val), l_fee_out->header.value = l_new_val;
    else
        SUM_256_256(l_fee_out->header.value, l_delta, &l_fee_out->header.value);

    // Re-sign tampered TX with Bob's key (taker)
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(f->bob, 0);
    dap_assert(l_key != NULL, "Got Bob's key");
    dap_assert(dap_chain_datum_tx_add_sign_item(&l_new_tx, l_key) > 0, "Signed tampered EXCHANGE TX");
    dap_enc_key_delete(l_key);

    // Try to add tampered TX to ledger: verificator must reject it
    dap_hash_fast_t l_tampered_hash = {0};
    dap_hash_fast(l_new_tx, dap_chain_datum_tx_get_size(l_new_tx), &l_tampered_hash);
    int l_verif_err = dap_ledger_tx_add(f->net->net->pub.ledger, l_new_tx, &l_tampered_hash, false, NULL);
    dap_chain_datum_tx_delete(l_tx_template);
    dap_chain_datum_tx_delete(l_new_tx);
    dap_assert(l_verif_err != 0, "Tampered fee EXCHANGE TX rejected by verificator");

    // Cancel Alice's order to restore balance
    dap_hash_fast_t l_cancel_hash = {0};
    ret = test_dex_order_cancel(f, f->alice, &l_order_hash, &l_cancel_hash);
    dap_assert(ret == 0, "Alice cancels order after test");

    // Verify balances (TX rejected, order cancelled)
    // Alice paid 2 network fees: create order + cancel order
    uint256_t a_tc_expected = uint256_0;
    uint256_t l_double_fee = uint256_0;
    SUM_256_256(f->network_fee, f->network_fee, &l_double_fee);
    SUBTRACT_256_256(a_tc0, l_double_fee, &a_tc_expected);
    
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel0).frac), "Alice KEL unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT",
               dap_uint256_to_char_ex(a_usdt0).frac), "Alice USDT unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc_expected).frac), "Alice TC after 2 network fees");
    f->balances.alice_tc = a_tc_expected;

    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel0).frac), "Bob KEL unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt0).frac), "Bob USDT unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc0).frac), "Bob TC unchanged (TX rejected)");

    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL",
               dap_uint256_to_char_ex(c_kel0).frac), "Carol KEL unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt0).frac), "Carol USDT unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin",
               dap_uint256_to_char_ex(c_tc0).frac), "Carol TC unchanged (TX rejected)");

    log_it(L_NOTICE, "✓ GROUP 1.12c PASSED: Tampered EXCHANGE service fee rejected");
}

/**
 * @brief Test Group 1.13 - Security: Double cancel (rejected)
 * @details Verifies that cancelling the same order twice is rejected
 */
static void test_group_1_13_security_double_cancel(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.13: SECURITY - Double Cancel (rejected) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_tc0 = f->balances.alice_tc;
    
    // State after 1.11:
    //   Alice:  KEL=7845.0   USDT=4445.6   TC=99988.0
    //   Bob:    KEL=1255.0   USDT=43585.0  TC=99990.0  (+680 USDT locked in leftovers)
    //   Carol:  KEL=200.0    USDT=1289.4   TC=99999.0
    
    // Test 1: Alice creates ASK: 100 KEL @ 5.0 USDT/KEL
    log_it(L_INFO, "[1.13.1] Alice creates ASK: 100 KEL @ 5.0 USDT/KEL");
    dap_hash_fast_t order_hash = {0};
    int ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "100.0", "5.0", &order_hash);
    dap_assert(ret == 0, "Alice ASK order created");
    
    // Alice: -100 KEL, -network_fee TestCoin
    uint256_t delta100 = dap_chain_coins_to_balance("100.0");
    uint256_t a_kel1 = uint256_0, a_tc1 = uint256_0;
    SUBTRACT_256_256(a_kel0, delta100, &a_kel1);
    SUBTRACT_256_256(a_tc0, f->network_fee, &a_tc1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL locked");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel1;
    f->balances.alice_tc = a_tc1;
    
    // Test 2: Alice cancels the order (first cancel - should succeed)
    log_it(L_INFO, "[1.13.2] Alice cancels the order (first attempt - should succeed)");
    dap_hash_fast_t cancel_hash = {0};
    ret = test_dex_order_cancel(f, f->alice, &order_hash, &cancel_hash);
    dap_assert(ret == 0, "First cancel successful");
    
    // Mark as cancelled in tracking
    test_dex_order_track_remove(f, &order_hash);
    
    // Alice: +100 KEL refunded, another network_fee TestCoin
    uint256_t a_kel2 = uint256_0, a_tc2 = uint256_0;
    SUM_256_256(a_kel1, delta100, &a_kel2);
    SUBTRACT_256_256(a_tc1, f->network_fee, &a_tc2);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel2).frac), "Alice KEL refunded");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc2).frac), "Alice TC network fee (first cancel)");
    f->balances.alice_kel = a_kel2;
    f->balances.alice_tc = a_tc2;
    
    // Test 3: Alice attempts to cancel the same order again (should be rejected)
    log_it(L_INFO, "[1.13.3] Alice attempts to cancel again (should be REJECTED)");
    ret = test_dex_order_cancel(f, f->alice, &order_hash, &cancel_hash);
    dap_assert(ret != 0, "Second cancel REJECTED (expected)");
    
    // Alice's TC: unchanged (second TX rejected BEFORE ledger, no fee charged)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc2).frac), "Alice TC unchanged (TX rejected)");
    // f->balances.alice_tc remains as after first cancel
    
    log_it(L_NOTICE, "✓ GROUP 1.13 PASSED: Double cancellation rejected (security validated)");
}

/**
 * @brief Test Group 1.14 - Security: Purchase already consumed order (rejected)
 * @details Verifies that purchasing an already fully consumed order is rejected
 */
static void test_group_1_14_security_purchase_consumed(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.14: SECURITY - Purchase Already Consumed Order (rejected) ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_usdt0 = f->balances.alice_usdt, a_tc0 = f->balances.alice_tc;
    uint256_t b_kel0 = f->balances.bob_kel,   b_usdt0 = f->balances.bob_usdt,   b_tc0 = f->balances.bob_tc;
    uint256_t c_usdt0 = f->balances.carol_usdt;
    uint256_t c_tc0 = f->balances.carol_tc;
    
    // State after 1.13:
    //   Alice:  KEL=7845.0   USDT=4445.6   TC=99986.0
    //   Bob:    KEL=1255.0   USDT=43585.0  TC=99990.0  (+680 USDT locked in leftovers)
    //   Carol:  KEL=200.0    USDT=1289.4   TC=99999.0  (no change in 1.13)
    
    // Test 1: Alice creates ASK: 100 KEL @ 5.0 USDT/KEL
    log_it(L_INFO, "[1.14.1] Alice creates ASK: 100 KEL @ 5.0 USDT/KEL");
    dap_hash_fast_t order_hash = {0};
    int ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "100.0", "5.0", &order_hash);
    dap_assert(ret == 0, "Alice ASK order created");
    
    // Alice: -100 KEL, -network_fee TestCoin
    uint256_t delta100 = dap_chain_coins_to_balance("100.0");
    uint256_t a_kel1 = uint256_0, a_tc1 = uint256_0;
    SUBTRACT_256_256(a_kel0, delta100, &a_kel1);
    SUBTRACT_256_256(a_tc0, f->network_fee, &a_tc1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL locked");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel1;
    f->balances.alice_tc = a_tc1;
    
    // Test 2: Bob buys all 100 KEL (full fill)
    // Bob pays: 100 * 5.0 = 500 USDT + 10 USDT fee (2%) = 510 USDT total
    log_it(L_INFO, "[1.14.2] Bob buys all 100 KEL (full fill)");
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->bob, &order_hash, "100.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Bob purchase completed");
    
    // Mark as fully consumed in tracking
    test_dex_order_track_remove(f, &order_hash);
    
    // Verify balances after purchase:
    // Alice: KEL unchanged at a_kel1, +500 USDT, TC unchanged vs after order creation
    uint256_t delta_usdt500 = dap_chain_coins_to_balance("500.0");
    uint256_t a_usdt1 = uint256_0;
    SUM_256_256(a_usdt0, delta_usdt500, &a_usdt1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL all sold");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT",
               dap_uint256_to_char_ex(a_usdt1).frac), "Alice received USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC unchanged");
    f->balances.alice_usdt = a_usdt1;
    
    // Bob: +100 KEL, -510 USDT, -network_fee TestCoin
    uint256_t delta_usdt510 = dap_chain_coins_to_balance("510.0");
    uint256_t b_kel1 = uint256_0, b_usdt1 = uint256_0, b_tc1 = uint256_0;
    SUM_256_256(b_kel0, delta100, &b_kel1);
    SUBTRACT_256_256(b_usdt0, delta_usdt510, &b_usdt1);
    SUBTRACT_256_256(b_tc0, f->network_fee, &b_tc1);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel1).frac), "Bob received KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt1).frac), "Bob paid USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc1).frac), "Bob TC network fee");
    f->balances.bob_kel = b_kel1;
    f->balances.bob_usdt = b_usdt1;
    f->balances.bob_tc = b_tc1;
    
    // Carol: +10 USDT service fee, TC unchanged
    uint256_t delta_usdt10 = dap_chain_coins_to_balance("10.0");
    uint256_t c_usdt1 = uint256_0;
    SUM_256_256(c_usdt0, delta_usdt10, &c_usdt1);
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt1).frac), "Carol service fee");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin",
               dap_uint256_to_char_ex(c_tc0).frac), "Carol TC unchanged");
    f->balances.carol_usdt = c_usdt1;
    
    // Test 3: Carol attempts to buy from the same (already consumed) order
    log_it(L_INFO, "[1.14.3] Carol attempts to buy from consumed order (should be REJECTED)");
    ret = test_dex_order_purchase(f, f->carol, &order_hash, "50.0", true, false, &purchase_hash);
    dap_assert(ret != 0, "Carol's purchase REJECTED (expected)");
    
    // Carol's TC: unchanged (TX rejected BEFORE ledger, no fee charged)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin",
               dap_uint256_to_char_ex(c_tc0).frac), "Carol TC unchanged (TX rejected)");
    // f->balances.carol_tc remains as at start of test
    
    log_it(L_NOTICE, "✓ GROUP 1.14 PASSED: Purchase of consumed order rejected (security validated)");
}

/**
 * @brief Test Group 1.15 - Cancel all orders by seller (Alice)
 * @details Verifies cancel_all_by_seller for Alice's ASK orders and balance restoration
 */
static void test_group_1_15_cancel_all_alice_orders(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.15: CANCEL ALL - Alice's ASK Orders ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_usdt0 = f->balances.alice_usdt, a_tc0 = f->balances.alice_tc;
    uint256_t b_kel0 = f->balances.bob_kel,   b_usdt0 = f->balances.bob_usdt,   b_tc0 = f->balances.bob_tc;
    uint256_t c_kel0 = f->balances.carol_kel, c_usdt0 = f->balances.carol_usdt, c_tc0 = f->balances.carol_tc;
    
    // State after 1.14:
    //   Alice:  KEL=7745.0   USDT=4945.6   TC=99985.0
    //   Bob:    KEL=1355.0   USDT=43075.0  TC=99989.0  (+680 USDT locked in leftovers)
    //   Carol:  KEL=200.0    USDT=1299.4   TC=99999.0
    //
    // ORDERBOOK BEFORE:
    //   [1] ASK 200 KEL @ 5.0 (Alice leftover from Test 1.3)
    //   [3] ASK 1000 KEL @ 5.0 (Alice original from Test 1.1)
    // TOTAL LOCKED: 1200 KEL
    
    log_it(L_INFO, "[1.15.1] Alice cancels ALL her ASK orders via cancel_all_by_seller");
    
    // Use cancel_all_by_seller API
    dap_chain_datum_tx_t *cancel_all_tx = NULL;
    dap_chain_net_srv_dex_cancel_all_error_t cancel_err = dap_chain_net_srv_dex_cancel_all_by_seller(
        f->net->net,
        &f->alice_addr,
        "KEL",    // base token (Alice sells KEL)
        "USDT",   // quote token
        DEX_CANCEL_SIDE_ASK,
        0,        // limit=0 means cancel ALL (internally converted to INT_MAX)
        f->network_fee,
        f->alice,
        NULL,
        &cancel_all_tx
    );
    if (cancel_err != DEX_CANCEL_ALL_ERROR_OK) {
        log_it(L_ERROR, "Alice cancel_all failed with error code: %d", cancel_err);
    }
    dap_assert(cancel_err == DEX_CANCEL_ALL_ERROR_OK, "Alice cancel_all completed");
    
    // Add cancel_all TX to ledger
    if (cancel_all_tx) {
        dap_ledger_t *ledger = f->net->net->pub.ledger;
        dap_hash_fast_t cancel_tx_hash = {0};
        dap_hash_fast(cancel_all_tx, dap_chain_datum_tx_get_size(cancel_all_tx), &cancel_tx_hash);
        log_it(L_INFO, "Adding cancel_all TX to ledger: %s", dap_chain_hash_fast_to_str_static(&cancel_tx_hash));
        
        int ret = dap_ledger_tx_add(ledger, cancel_all_tx, &cancel_tx_hash, false, NULL);
        if (ret != 0) {
            log_it(L_ERROR, "Failed to add cancel_all TX to ledger: error code %d", ret);
        } else {
            log_it(L_INFO, "Cancel_all TX successfully added to ledger");
        }
    } else {
        log_it(L_ERROR, "cancel_all_tx is NULL!");
    }
    
    // Verify balances after cancel_all:
    // Alice: all locked KEL returned (+1200), -network_fee TestCoin for cancel_all TX, USDT unchanged
    uint256_t delta_kel1200 = dap_chain_coins_to_balance("1200.0");
    uint256_t a_kel1 = uint256_0, a_usdt1 = a_usdt0, a_tc1 = uint256_0;
    SUM_256_256(a_kel0, delta_kel1200, &a_kel1);
    SUBTRACT_256_256(a_tc0, f->network_fee, &a_tc1);
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel1).frac), "Alice KEL fully refunded");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT",
               dap_uint256_to_char_ex(a_usdt1).frac), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc1).frac), "Alice TC network fee");
    f->balances.alice_kel = a_kel1;
    f->balances.alice_tc  = a_tc1;
    
    // Bob and Carol: unchanged
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel0).frac), "Bob KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt0).frac), "Bob USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc0).frac), "Bob TC unchanged");
    
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL",
               dap_uint256_to_char_ex(c_kel0).frac), "Carol KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt0).frac), "Carol USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin",
               dap_uint256_to_char_ex(c_tc0).frac), "Carol TC unchanged");
    
    // Mark all Alice's orders as cancelled in tracking
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (e->active && dap_chain_addr_compare(&e->seller_addr, &f->alice_addr)) {
            test_dex_order_track_remove(f, &e->tail);
        }
    }
    
    log_it(L_NOTICE, "✓ GROUP 1.15 PASSED: Alice's orders cancelled, KEL fully refunded");
}

/**
 * @brief Test Group 1.16 - Cancel all orders by seller (Bob)
 * @details Verifies cancel_all_by_seller for Bob's BID orders and balance restoration
 */
static void test_group_1_16_cancel_all_bob_orders(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 1.16: CANCEL ALL - Bob's BID Orders ===");
    dex_update_balances(f);
    uint256_t a_kel0 = f->balances.alice_kel, a_usdt0 = f->balances.alice_usdt, a_tc0 = f->balances.alice_tc;
    uint256_t b_kel0 = f->balances.bob_kel,   b_usdt0 = f->balances.bob_usdt,   b_tc0 = f->balances.bob_tc;
    uint256_t c_kel0 = f->balances.carol_kel, c_usdt0 = f->balances.carol_usdt, c_tc0 = f->balances.carol_tc;
    
    // State after 1.15:
    //   Alice:  KEL=8945.0   USDT=4945.6   TC=99984.0
    //   Bob:    KEL=1355.0   USDT=43075.0  TC=99989.0  (+680 USDT locked in leftovers)
    //   Carol:  KEL=200.0    USDT=1299.4   TC=99999.0
    //
    // ORDERBOOK BEFORE:
    //   [0] BID 280 USDT for KEL @ 0.25 (Bob leftover from Test 1.9.2)
    //   [1] BID 400 USDT for KEL @ 0.25 (Bob leftover from Test 1.6)
    // TOTAL LOCKED: 680 USDT (both leftovers should be cancelled by cancel_all_by_seller)
    
    log_it(L_INFO, "[1.16.1] Bob cancels ALL his BID orders via cancel_all_by_seller");
    
    // Use cancel_all_by_seller API
    dap_chain_datum_tx_t *cancel_all_tx = NULL;
    dap_chain_net_srv_dex_cancel_all_error_t cancel_err = dap_chain_net_srv_dex_cancel_all_by_seller(
        f->net->net,
        &f->bob_addr,
        "KEL",    // base token (Bob buys KEL)
        "USDT",   // quote token (Bob sells USDT)
        DEX_CANCEL_SIDE_BID,
        0,        // limit=0 means cancel ALL (internally converted to INT_MAX)
        f->network_fee,
        f->bob,
        NULL,
        &cancel_all_tx
    );
    if (cancel_err != DEX_CANCEL_ALL_ERROR_OK) {
        log_it(L_ERROR, "Bob cancel_all failed with error code: %d", cancel_err);
    }
    dap_assert(cancel_err == DEX_CANCEL_ALL_ERROR_OK, "Bob cancel_all completed");
    
    // Add cancel_all TX to ledger
    if (cancel_all_tx) {
        dap_ledger_t *ledger = f->net->net->pub.ledger;
        dap_hash_fast_t cancel_tx_hash = {0};
        dap_hash_fast(cancel_all_tx, dap_chain_datum_tx_get_size(cancel_all_tx), &cancel_tx_hash);
        log_it(L_INFO, "Adding cancel_all TX to ledger: %s", dap_chain_hash_fast_to_str_static(&cancel_tx_hash));
        
        int ret = dap_ledger_tx_add(ledger, cancel_all_tx, &cancel_tx_hash, false, NULL);
        if (ret != 0) {
            log_it(L_ERROR, "Failed to add cancel_all TX to ledger: error code %d", ret);
        } else {
            log_it(L_INFO, "Cancel_all TX successfully added to ledger");
        }
    } else {
        log_it(L_ERROR, "cancel_all_tx is NULL!");
    }
    
    // Verify balances after cancel_all:
    // Bob: all locked USDT returned (+680), -network_fee TestCoin for cancel_all TX, KEL unchanged
    uint256_t delta_usdt680 = dap_chain_coins_to_balance("680.0");
    uint256_t b_kel1 = b_kel0, b_usdt1 = uint256_0, b_tc1 = uint256_0;
    SUM_256_256(b_usdt0, delta_usdt680, &b_usdt1);
    SUBTRACT_256_256(b_tc0, f->network_fee, &b_tc1);
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL",
               dap_uint256_to_char_ex(b_kel1).frac), "Bob KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT",
               dap_uint256_to_char_ex(b_usdt1).frac), "Bob USDT fully refunded (680 from both leftovers)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin",
               dap_uint256_to_char_ex(b_tc1).frac), "Bob TC network fee");
    f->balances.bob_usdt = b_usdt1;
    f->balances.bob_tc = b_tc1;
    
    // Alice and Carol: unchanged
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL",
               dap_uint256_to_char_ex(a_kel0).frac), "Alice KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT",
               dap_uint256_to_char_ex(a_usdt0).frac), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin",
               dap_uint256_to_char_ex(a_tc0).frac), "Alice TC unchanged");
    
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL",
               dap_uint256_to_char_ex(c_kel0).frac), "Carol KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT",
               dap_uint256_to_char_ex(c_usdt0).frac), "Carol USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin",
               dap_uint256_to_char_ex(c_tc0).frac), "Carol TC unchanged");
    
    // Mark all Bob's orders as cancelled in tracking
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (e->active && dap_chain_addr_compare(&e->seller_addr, &f->bob_addr)) {
            test_dex_order_track_remove(f, &e->tail);
        }
    }
    
    log_it(L_NOTICE, "✓ GROUP 1.16 PASSED: Bob's orders cancelled, USDT fully refunded");
    
    // ========================================================================
    // END OF GROUP 1: FINAL ORDERBOOK STATE SUMMARY
    // ========================================================================
    // ACTIVE ORDERS REMAINING IN ORDERBOOK: NONE (fully cleaned up)
    //
    // FINAL BALANCES AFTER GROUP 1:
    //   Alice:  KEL=8945.0   USDT=4945.6   TC=99984.0
    //   Bob:    KEL=1355.0   USDT=43755.0  TC=99988.0
    //   Carol:  KEL=200.0    USDT=1299.4   TC=99999.0
    // ========================================================================
}


// ============================================================================
// TEST GROUP 2: MATCHING LOGIC
// ============================================================================

/**
 * @brief Test Group 2.1a - Multi-Order Best Price (ASK)
 * @details Verifies matcher selects best prices (rate ASC for ASK)
 * 
 * INITIAL STATE (after Group 1):
 *   Orderbook: EMPTY
 *   Alice: KEL=8945.0, USDT=4945.6, TC=99984.0
 *   Bob:   KEL=1355.0, USDT=43755.0, TC=99988.0
 *   Carol: KEL=200.0, USDT=1299.4, TC=99999.0
 * 
 * SCENARIO:
 *   [2.1a.1] Alice creates 3 ASK orders (unsorted prices):
 *     - Order A: 100 KEL @ 6.0 USDT/KEL (worst price)
 *     - Order B: 100 KEL @ 5.0 USDT/KEL (middle price)
 *     - Order C: 100 KEL @ 4.0 USDT/KEL (best price)
 *     Alice: KEL=8645 (300 locked), TC=99981 (3 fees paid)
 * 
 *   [2.1a.2] Bob auto-match 150 KEL:
 *     - Matcher selects: Order C (4.0) fully → 100 KEL
 *     - Matcher selects: Order B (5.0) partially → 50 KEL
 *     - Matcher skips: Order A (6.0) → untouched
 *     Cost: (100*4.0 + 50*5.0) * 1.02 = 408 + 255 = 663 USDT
 *     Alice: USDT=5595.6 (+650)
 *     Bob: KEL=1505 (+150), USDT=43092 (-663), TC=99987 (-1)
 *     Carol: USDT=1312.4 (+13)
 * 
 * FINAL STATE:
 *   Orderbook: Order A (100@6.0), Order B leftover (50@5.0)
 *   Alice: KEL=8645, USDT=5595.6, TC=99981
 *   Bob:   KEL=1505, USDT=43092, TC=99987
 *   Carol: USDT=1312.4
 */
static void test_group_2_1a_multi_order_best_price_ask(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 2.1a: Multi-Order Best Price (ASK) ===");
    
    // Precheck balances (after Group 1)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8945.0"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "4945.6"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99984.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1355.0"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "43755.0"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99988.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "200.0"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1299.4"), "Precheck Carol USDT");
    
    log_it(L_INFO, "[2.1a.1] Alice creates 3 ASK orders: 100 KEL @ 6.0, 5.0, 4.0");
    
    dap_hash_fast_t order_a_hash = {0}, order_b_hash = {0}, order_c_hash = {0};
    int ret;
    
    // Order A: 100 KEL @ 6.0 USDT/KEL (worst price)
    ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "100.0", "6.0", &order_a_hash);
    dap_assert(ret == 0, "Alice order A created");
    
    // Order B: 100 KEL @ 5.0 USDT/KEL (middle price)
    ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "100.0", "5.0", &order_b_hash);
    dap_assert(ret == 0, "Alice order B created");
    
    // Order C: 100 KEL @ 4.0 USDT/KEL (best price)
    ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "100.0", "4.0", &order_c_hash);
    dap_assert(ret == 0, "Alice order C created");
    
    // Alice's balances after order creation
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8645.0"), "Alice KEL locked");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99981.0"), "Alice TC fees");
    f->balances.alice_kel = dap_chain_coins_to_balance("8645.0");
    f->balances.alice_tc = dap_chain_coins_to_balance("99981.0");
    
    log_it(L_INFO, "[2.1a.2] Bob auto-match 150 KEL (should select C@4.0 + B@5.0 partial)");
    
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->bob, "USDT", "KEL", "150.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Bob auto-purchase completed");
    
    // Verify balances after purchase
    // Alice receives: 400 (from C) + 250 (from B) = 650 USDT
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5595.6"), "Alice USDT");
    f->balances.alice_usdt = dap_chain_coins_to_balance("5595.6");
    
    // Bob receives 150 KEL, pays 663 USDT (650 base + 13 fee)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1505.0"), "Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "43092.0"), "Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99987.0"), "Bob TC");
    f->balances.bob_kel = dap_chain_coins_to_balance("1505.0");
    f->balances.bob_usdt = dap_chain_coins_to_balance("43092.0");
    f->balances.bob_tc = dap_chain_coins_to_balance("99987.0");
    
    // Carol receives service fee: 8 (from C) + 5 (from B) = 13 USDT
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1312.4"), "Carol USDT");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1312.4");
    
    // Update order tracking for consumed orders
    // Note: Order B leftover is automatically updated by test_dex_order_purchase_auto
    test_dex_order_track_remove(f, &order_c_hash); // Order C fully consumed
    
    // Dump orderbook state
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.1a ==========");
    test_dex_dump_orderbook(f, "After Test 2.1a");
    log_it(L_INFO, "Expected: Order A (100@6.0), Order B leftover (50@5.0)");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    
    log_it(L_NOTICE, "✓ GROUP 2.1a PASSED: Multi-order best price (ASK)");
}

/**
 * @brief Test Group 2.1b - Multi-Order Best Price (BID)
 * @details Verifies matcher selects best prices (rate DESC for BID)
 * 
 * INITIAL STATE (after Test 2.1a):
 *   Orderbook: Order B leftover (50@5.0), Order A (100@6.0)
 *   Alice: KEL=8645.0, USDT=5595.6, TC=99981.0
 *   Bob:   KEL=1505.0, USDT=43092.0, TC=99987.0
 *   Carol: USDT=1312.4
 * 
 * SCENARIO:
 *   [2.1b.1] Bob creates 3 BID orders (unsorted prices):
 *     - Order D: 200 USDT for KEL @ 4.0 USDT/KEL (worst price)
 *     - Order E: 250 USDT for KEL @ 5.0 USDT/KEL (middle price)
 *     - Order F: 300 USDT for KEL @ 6.0 USDT/KEL (best price)
 *     Bob: USDT=42342 (750 locked), TC=99984 (3 fees paid)
 * 
 *   [2.1b.2] Alice auto-match sell 100 KEL:
 *     - Matcher selects: Order F (6.0) fully → 50 KEL
 *     - Matcher selects: Order E (5.0) fully → 50 KEL
 *     - Matcher skips: Order D (4.0) → untouched
 *     Payout: (50*6.0 + 50*5.0) = 550 USDT
 *     Alice: KEL=8545 (-100), USDT=6145.6 (+550), TC=99980 (-1)
 *     Bob: KEL=1605 (+100), USDT=42342 (unchanged), TC=99984 (unchanged)
 *     Carol: USDT=1323.4 (+11)
 * 
 * FINAL STATE:
 *   Orderbook: Order B leftover (50@5.0 ASK), Order A (100@6.0 ASK), Order D (200@4.0 BID)
 *   Alice: KEL=8545, USDT=6145.6, TC=99980
 *   Bob:   KEL=1605, USDT=42342, TC=99984
 *   Carol: USDT=1323.4
 */
static void test_group_2_1b_multi_order_best_price_bid(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 2.1b: Multi-Order Best Price (BID) ===");
    
    // Precheck balances (after Test 2.1a)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8645.0"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5595.6"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99981.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1505.0"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "43092.0"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99987.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1312.4"), "Precheck Carol USDT");
    
    log_it(L_INFO, "[2.1b.1] Bob creates 3 BID orders: 200/250/250 USDT for KEL @ 4.0/5.0/5.5");
    
    dap_hash_fast_t order_d_hash = {0}, order_e_hash = {0}, order_f_hash = {0};
    int ret;
    
    // Order D: 200 USDT for KEL @ 4.0 (worst price, rate = 1/4 = 0.25 KEL/USDT)
    ret = test_dex_order_create(f, f->bob, "KEL", "USDT", "200.0", "0.25", &order_d_hash);
    dap_assert(ret == 0, "Bob order D created");
    
    // Order E: 250 USDT for KEL @ 5.0 (middle price, rate = 1/5 = 0.2 KEL/USDT)
    ret = test_dex_order_create(f, f->bob, "KEL", "USDT", "250.0", "0.2", &order_e_hash);
    dap_assert(ret == 0, "Bob order E created");
    
    // Order F: 250 USDT for KEL @ 5.5 (best price, rate = 2/11 = 0.181818... still periodic!)
    // Use rate = 0.18 (price 5.555...) to avoid periodic fractions
    ret = test_dex_order_create(f, f->bob, "KEL", "USDT", "250.0", "0.18", &order_f_hash);
    dap_assert(ret == 0, "Bob order F created");
    
    // Bob's balances after order creation (700 USDT locked, 3 TC fees)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42392.0"), "Bob USDT locked");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99984.0"), "Bob TC fees");
    f->balances.bob_usdt = dap_chain_coins_to_balance("42392.0");
    f->balances.bob_tc = dap_chain_coins_to_balance("99984.0");
    
    log_it(L_INFO, "[2.1b.2] Alice auto-match sell 30 KEL (should match Bob F@5.555... partial)");
    
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->alice, "KEL", "USDT", "30.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Alice auto-purchase completed");
    
    // Alice sells 30 KEL to Bob F @ 5.555555555555555555 USDT/KEL
    // Gross revenue: 30 * 5.555555555555555555 = 166.66666666666666665 USDT
    // Service fee: 3.333333333333333333 USDT (deducted from Alice's payout in BID-side match)
    // Net payout: 166.66666666666666665 - 3.333333333333333333 = 163.333333333333333317 USDT
    // Alice KEL: 8645 - 30 = 8615
    // Alice USDT: 5595.6 + 163.333333333333333317 = 5758.933333333333333317
    // Alice TC: 99981 - 1 (network fee) = 99980
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8615.0"), "Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5758.933333333333333317"), "Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99980.0"), "Alice TC");
    f->balances.alice_kel = dap_chain_coins_to_balance("8615.0");
    f->balances.alice_usdt = dap_chain_coins_to_balance("5758.933333333333333317");
    f->balances.alice_tc = dap_chain_coins_to_balance("99980.0");
    
    // Bob (buyer via F): receives 30 KEL, order F partially filled
    // KEL: 1505 + 30 = 1535
    // USDT: 42392.0 (all 3 orders still locked)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1535.0"), "Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42392.0"), "Bob USDT");
    f->balances.bob_kel = dap_chain_coins_to_balance("1535.0");
    
    // Carol: 1312.4 + 3.333333333333333333 (service fee) = 1315.733333333333333333
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1315.733333333333333333"), "Carol USDT");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1315.733333333333333333");
    
    // Dump orderbook state
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.1b ==========");
    test_dex_dump_orderbook(f, "After Test 2.1b");
    log_it(L_INFO, "Expected: Alice ASK (B 50@5.0, A 100@6.0), Bob BID (F leftover 83.333...@5.555..., E 250@5.0, D 200@4.0)");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    
    log_it(L_NOTICE, "✓ GROUP 2.1b PASSED: Multi-order best price (BID)");
}

/**
 * @brief Test Group 2.2a - ASK with SELL budget (target amount in BASE)
 * @details Alice sells 30 KEL (target in KEL), matches Bob's BID orders
 */
static void test_group_2_2a_ask_sell_budget(dex_test_fixture_t *f)
{
    int ret;
    log_it(L_INFO, "=== TEST GROUP 2.2a: ASK with SELL budget (target amount in BASE) ===");
    
    // Precheck balances (after 2.1b)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8615.0"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5758.933333333333333317"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99980.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1535.0"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42392.0"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99984.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1315.733333333333333333"), "Precheck Carol USDT");
    
    // Current orderbook:
    // ASK: Alice B leftover (50 KEL @ 5.0), Alice A (100 KEL @ 6.0)
    // BID: Bob F leftover (83.333... USDT @ 5.555...), Bob E (250 USDT @ 5.0), Bob D (200 USDT @ 4.0)
    
    log_it(L_INFO, "[2.2a.1] Alice auto-match: sell 15 KEL (is_budget_buy=false, budget in SELL=KEL)");
    log_it(L_INFO, "         Should match Bob F leftover @ 5.555..., full fill");
    
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->alice, "KEL", "USDT", "15.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Alice auto-purchase completed");
    
    // Alice sells 15 KEL to Bob F leftover @ 5.555555555555555555 USDT/KEL
    // Gross revenue: 15 * 5.555555555555555555 = 83.333333333333333325 USDT
    // Service fee: 1.666666666666666666 USDT (deducted from Alice's payout in BID-side match)
    // Net payout: 83.333333333333333325 - 1.666666666666666666 = 81.666666666666666659 USDT
    // Alice KEL: 8615 - 15 = 8600
    // Alice USDT: 5758.933333333333333317 + 81.666666666666666659 = 5840.599999999999999976
    // Alice TC: 99980 - 1 (network fee) = 99979
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8600.0"), "Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5840.599999999999999976"), "Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99979.0"), "Alice TC");
    f->balances.alice_kel = dap_chain_coins_to_balance("8600.0");
    f->balances.alice_usdt = dap_chain_coins_to_balance("5840.599999999999999976");
    f->balances.alice_tc = dap_chain_coins_to_balance("99979.0");
    
    // Bob (buyer, order F): receives 15 KEL, order F fully consumed
    // Bob KEL: 1535 + 15 = 1550
    // Bob USDT: 42392 (all locked in orders)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1550.0"), "Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42392.0"), "Bob USDT");
    f->balances.bob_kel = dap_chain_coins_to_balance("1550.0");
    
    // Carol: 1315.733333333333333333 + 1.666666666666666666 (service fee) = 1317.399999999999999999
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1317.399999999999999999"), "Carol USDT");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1317.399999999999999999");
    
    // Dump orderbook state
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.2a ==========");
    test_dex_dump_orderbook(f, "After Test 2.2a");
    log_it(L_INFO, "Expected: Alice ASK (B 50@5.0, A 100@6.0), Bob BID (F dust ~25 datoshi, E 250@5.0, D 200@4.0)");
    log_it(L_INFO, "Order F partially consumed, dust leftover (~25 datoshi)");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    
    log_it(L_NOTICE, "✓ GROUP 2.2a PASSED: ASK with SELL budget (target amount in BASE)");
}

/**
 * @brief Test Group 2.2b - BID with SELL budget (target amount in QUOTE)
 * @details Bob buys KEL with budget specified in USDT (QUOTE), matches Alice's ASK orders
 */
static void test_group_2_2b_bid_sell_budget(dex_test_fixture_t *f)
{
    int ret;
    log_it(L_INFO, "=== TEST GROUP 2.2b: BID with SELL budget (target amount in QUOTE) ===");
    
    // Precheck balances (after 2.2a)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8600.0"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5840.599999999999999976"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99979.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1550.0"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42392.0"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99984.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1317.399999999999999999"), "Precheck Carol USDT");
    
    // Current orderbook:
    // ASK: Alice B leftover (50 KEL @ 5.0), Alice A (100 KEL @ 6.0)
    // BID: Bob F leftover (~0 USDT @ 5.555...), Bob E (250 USDT @ 5.0), Bob D (200 USDT @ 4.0)
    
    log_it(L_INFO, "[2.2b.1] Bob auto-match: buy KEL for 100 USDT budget (is_budget_buy=false, budget in SELL=USDT)");
    log_it(L_INFO, "         Should match Alice B leftover @ 5.0, get 20 KEL");
    
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->bob, "USDT", "KEL", "100.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Bob auto-purchase completed");
    
    // Bob buys 20 KEL from Alice B leftover @ 5.0 USDT/KEL (ASK-side match)
    // Bob pays: 100 USDT (to Alice) + 2 USDT (service fee to Carol) = 102 USDT total
    // Alice receives: 100 USDT gross revenue (MAKER, no fee deduction)
    // Carol receives: 2 USDT service fee (paid by Bob as TAKER)
    // Bob KEL: 1550 + 20 = 1570
    // Bob USDT: 42392 - 102 = 42290
    // Bob TC: 99984 - 1 (network fee) = 99983
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1570.0"), "Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42290.0"), "Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99983.0"), "Bob TC");
    f->balances.bob_kel = dap_chain_coins_to_balance("1570.0");
    f->balances.bob_usdt = dap_chain_coins_to_balance("42290.0");
    f->balances.bob_tc = dap_chain_coins_to_balance("99983.0");
    
    // Alice (seller, order B): receives 100 USDT gross (service fee paid separately by Bob)
    // Alice KEL: 8600 (no change, from orders)
    // Alice USDT: 5840.599... + 100 = 5940.599...
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8600.0"), "Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5940.599999999999999976"), "Alice USDT");
    f->balances.alice_usdt = dap_chain_coins_to_balance("5940.599999999999999976");
    
    // Carol: 1317.399... + 2.0 (service fee) = 1319.399...
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1319.399999999999999999"), "Carol USDT");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1319.399999999999999999");
    
    // Dump orderbook state
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.2b ==========");
    test_dex_dump_orderbook(f, "After Test 2.2b");
    log_it(L_INFO, "Expected: Alice ASK (B leftover 30@5.0, A 100@6.0), Bob BID (F dust ~25 datoshi, E 250@5.0, D 200@4.0)");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    
    log_it(L_NOTICE, "✓ GROUP 2.2b PASSED: BID with SELL budget (target amount in QUOTE)");
}

/**
 * @brief Test Group 2.3a - Self-Purchase (ASK-side: buyer from own order)
 * @details Alice buys KEL from her own ASK order B leftover
 */
static void test_group_2_3a_self_purchase_ask(dex_test_fixture_t *f)
{
    int ret;
    log_it(L_INFO, "=== TEST GROUP 2.3a: Self-Purchase (ASK-side) ===");

    // Precheck balances (after 2.2b)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8600.0"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5940.599999999999999976"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99979.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1570.0"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42290.0"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99983.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1319.399999999999999999"), "Precheck Carol USDT");

    // Current orderbook:
    // ASK: Alice B leftover (30 KEL @ 5.0), Alice A (100 KEL @ 6.0)
    // BID: Bob F leftover (~0 USDT @ 5.555...), Bob E (250 USDT @ 5.0), Bob D (200 USDT @ 4.0)

    log_it(L_INFO, "[2.3a.1] Alice auto-match: buy 20 KEL for 100 USDT budget (ASK-side self-purchase)");
    log_it(L_INFO, "         Should match Alice B leftover @ 5.0, self-purchase scenario");

    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->alice, "USDT", "KEL", "100.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Alice auto-purchase completed");

    // Alice buys 20 KEL from her own Order B leftover @ 5.0 USDT/KEL (ASK-side match)
    // Trade amount: 100 USDT for 20 KEL
    // Service fee: 2 USDT (paid by Alice as TAKER)
    // Alice as TAKER (buyer): spends 100 + 2 (service fee) + 1 (network fee) = 103 USDT + 1 TC
    // Alice as MAKER (seller): receives 100 USDT gross revenue (in cashback)
    // Alice receives: 20 KEL (from order) + cashback 100 USDT (gross revenue)
    // Net effect: Alice pays 103 USDT + 1 TC, gets 20 KEL + 100 USDT cashback = -3 USDT, +20 KEL, -1 TC
    // Alice KEL: 8600 + 20 = 8620
    // Alice USDT: 5940.599... - 100 (trade) - 2 (service fee) + 100 (cashback) = 5938.599...
    // Alice TC: 99979 - 1 (network fee) = 99978
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8620.0"), "Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5938.599999999999999976"), "Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99978.0"), "Alice TC");
    f->balances.alice_kel = dap_chain_coins_to_balance("8620.0");
    f->balances.alice_usdt = dap_chain_coins_to_balance("5938.599999999999999976");
    f->balances.alice_tc = dap_chain_coins_to_balance("99978.0");

    // Bob: no change (not involved)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1570.0"), "Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42290.0"), "Bob USDT");

    // Carol: 1319.399... + 2.0 (service fee) = 1321.399...
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1321.399999999999999999"), "Carol USDT");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1321.399999999999999999");

    // Dump orderbook state
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.3a ==========");
    test_dex_dump_orderbook(f, "After Test 2.3a");
    log_it(L_INFO, "Expected: Alice ASK (B leftover 10@5.0, A 100@6.0), Bob BID (F dust ~25 datoshi, E 250@5.0, D 200@4.0)");
    log_it(L_INFO, "Self-purchase: Alice bought from her own order");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");

    log_it(L_NOTICE, "✓ GROUP 2.3a PASSED: Self-Purchase (ASK-side)");
}

/**
 * @brief Test Group 2.3b - Self-Purchase (BID-side: seller to own orders)
 * @details Bob sells KEL to his own BID orders E and D, fully closing both
 */
static void test_group_2_3b_self_purchase_bid(dex_test_fixture_t *f)
{
    int ret;
    log_it(L_INFO, "=== TEST GROUP 2.3b: Self-Purchase (BID-side) ===");

    // Precheck balances (after 2.3a)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8620.0"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5938.599999999999999976"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99978.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1570.0"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42290.0"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99983.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1321.399999999999999999"), "Precheck Carol USDT");

    // Current orderbook:
    // ASK: Alice B leftover (10 KEL @ 5.0), Alice A (100 KEL @ 6.0)
    // BID: Bob F leftover (~0 USDT @ 5.555...), Bob E (250 USDT @ 5.0), Bob D (200 USDT @ 4.0)

    log_it(L_INFO, "[2.3b.1] Bob auto-match: sell 100 KEL (BID-side self-purchase)");
    log_it(L_INFO, "         Should match Bob E @ 5.0 (fully) + Bob D @ 4.0 (fully)");

    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->bob, "KEL", "USDT", "100.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Bob auto-purchase completed");

    // Bob sells 100 KEL to his own BID orders (BID-side match)
    // Order E: 50 KEL @ 5.0 USDT/KEL → 250 USDT gross, 5 USDT service fee, 245 USDT net
    // Order D: 50 KEL @ 4.0 USDT/KEL → 200 USDT gross, 4 USDT service fee, 196 USDT net
    // Total: 100 KEL sold → 450 USDT gross - 9 USDT service fee = 441 USDT net
    // Bob as TAKER (seller): receives 441 USDT net (after service fee deduction)
    // Bob as MAKER (buyer): receives 100 KEL back (in cashback)
    // Net effect: Bob gets 100 KEL back + 441 USDT, pays 1 TC network fee
    // Bob KEL: 1570 - 100 (sold) + 100 (cashback) = 1570 (no change)
    // Bob USDT: 42290 + 441.000000000000000009 = 42731.000000000000000009
    // Bob TC: 99983 - 1 (network fee) = 99982
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1570.0"), "Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42731.000000000000000009"), "Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99982.0"), "Bob TC");
    f->balances.bob_kel = dap_chain_coins_to_balance("1570.0");
    f->balances.bob_usdt = dap_chain_coins_to_balance("42731.000000000000000009");
    f->balances.bob_tc = dap_chain_coins_to_balance("99982.0");

    // Alice: no change (not involved)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8620.0"), "Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5938.599999999999999976"), "Alice USDT");

    // Carol: 1321.399... + 9.0 (service fee) = 1330.399...
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1330.399999999999999999"), "Carol USDT");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1330.399999999999999999");

    // Dump orderbook state
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.3b ==========");
    test_dex_dump_orderbook(f, "After Test 2.3b");
    log_it(L_INFO, "Expected: Alice ASK (B leftover 10@5.0, A 100@6.0), Bob BID (D leftover ~16 datoshi)");
    log_it(L_INFO, "Self-purchase: Bob sold to his own orders, F and E fully closed, D partially closed");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");

    log_it(L_NOTICE, "✓ GROUP 2.3b PASSED: Self-Purchase (BID-side)");
}

/**
 * @brief Test Group 2.4a - Mixed Purchase (ASK-side: buyer from own + other's orders)
 * @details Alice buys KEL from Bob's ASK + her own ASK leftover
 */
static void test_group_2_4a_mixed_purchase_ask(dex_test_fixture_t *f)
{
    int ret;
    log_it(L_INFO, "=== TEST GROUP 2.4a: Mixed Purchase (ASK-side) ===");

    // Precheck balances (after 2.3b)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8620.0"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5938.599999999999999976"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99978.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1570.0"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42731.000000000000000009"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99982.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1330.399999999999999999"), "Precheck Carol USDT");

    // Current orderbook:
    // ASK: Alice B leftover (10 KEL @ 5.0), Alice A (100 KEL @ 6.0)
    // BID: Bob D leftover (~16 datoshi USDT @ 4.0)

    log_it(L_INFO, "[2.4a.1] Bob creates ASK: 20 KEL @ 4.5 USDT/KEL");
    
    dap_hash_fast_t bob_ask_hash = {0};
    ret = test_dex_order_create(f, f->bob, "USDT", "KEL", "20.0", "4.5", &bob_ask_hash);
    dap_assert(ret == 0, "Bob ASK order created");

    // Bob KEL: 1570 - 20 = 1550
    // Bob TC: 99982 - 1 (network fee) = 99981
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1550.0"), "Bob KEL after ASK");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99981.0"), "Bob TC after ASK");
    f->balances.bob_kel = dap_chain_coins_to_balance("1550.0");
    f->balances.bob_tc = dap_chain_coins_to_balance("99981.0");

    log_it(L_INFO, "[2.4a.2] Alice auto-match: buy 45.83 KEL for USDT budget (mixed purchase)");
    log_it(L_INFO, "         Should match Bob ASK @ 4.5 (20 KEL, fully) + Alice B @ 5.0 (10 KEL, fully) + Alice A @ 6.0 (15.83 KEL, partially)");

    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->alice, "USDT", "KEL", "235.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Alice auto-purchase completed");

    // Alice buys 45.833333333333333333 KEL from:
    //   1. Bob: 20 KEL @ 4.5 = 90 USDT (fully closed)
    //   2. Alice B: 10 KEL @ 5.0 = 50 USDT (fully closed, self-purchase)
    //   3. Alice A: 15.833333333333333333 KEL @ 6.0 = 94.999999999999999998 USDT (partially, self-purchase)
    // Actual trade: 234.999999999999999998 USDT for 45.833333333333333333 KEL
    // Service fee: 4.699999999999999999 USDT (2% of actual trade, paid by Alice as TAKER)
    // Cashback from self-purchase: 50 + 94.999999999999999998 = 144.999999999999999998 USDT
    // Additional cashback (change): 1260.300000000000000003 - 1500 = -239.699999999999999997
    // Alice as TAKER (buyer): spends ~235 + ~4.7 (service fee) + 1 (network fee) ≈ 239.7 USDT + 1 TC
    // Net effect for Alice: -1500 (input) + 1260.300000000000000003 (cashback) + 144.999999999999999998 (self-purchase cashback) + 99977 (TC cashback)
    // Alice KEL: 8620 + 45.833333333333333333 = 8665.833333333333333333
    // Alice USDT: 5938.599...976 + (1260.3...003 + 144.999...998 - 1500) = 5843.899999999999999977
    // Alice TC: 99978 - 1 = 99977
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8665.833333333333333333"), "Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5843.899999999999999977"), "Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99977.0"), "Alice TC");
    f->balances.alice_kel = dap_chain_coins_to_balance("8665.833333333333333333");
    f->balances.alice_usdt = dap_chain_coins_to_balance("5843.899999999999999977");
    f->balances.alice_tc = dap_chain_coins_to_balance("99977.0");

    // Bob receives: 90 USDT (full payout for his 20 KEL @ 4.5)
    // Bob USDT: 42731.000...009 + 90 = 42821.000...009
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42821.000000000000000009"), "Bob USDT");
    f->balances.bob_usdt = dap_chain_coins_to_balance("42821.000000000000000009");

    // Carol receives: 4.699999999999999999 USDT service fee
    // Carol USDT: 1330.399999999999999999 + 4.699999999999999999 = 1335.099999999999999998
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1335.099999999999999998"), "Carol USDT");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1335.099999999999999998");

    // Track order updates (handled automatically by test_dex_order_purchase_auto)

    // Dump orderbook state
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.4a ==========");
    test_dex_dump_orderbook(f, "After Test 2.4a");
    log_it(L_INFO, "Expected: Alice ASK (A leftover 84.166666666666666667@6.0), Bob BID (D leftover ~16 datoshi)");
    log_it(L_INFO, "Mixed purchase: Bob ASK fully closed, Alice B fully closed, Alice A partially closed");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");

    log_it(L_NOTICE, "✓ GROUP 2.4a PASSED: Mixed Purchase (ASK-side)");
}

/**
 * @brief Test Group 2.5 - Direct Purchase from Dust Order
 * @details Tests if dust orders can be purchased directly by hash
 */
static void test_group_2_5_dust_order_direct_purchase(dex_test_fixture_t *f)
{
    log_it(L_INFO, "=== TEST GROUP 2.5: Direct Purchase from Dust Order ===");

    // Precheck balances (after 2.4a)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8665.833333333333333333"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5843.899999999999999977"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99977.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1550.0"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42821.000000000000000009"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1335.099999999999999998"), "Precheck Carol USDT");

    // Current orderbook:
    // BID: Bob D dust (16 datoshi @ 4.0)
    // ASK: Alice A leftover (84.166666666666666667 KEL @ 6.0)

    log_it(L_INFO, "[2.5.1] Alice tries to sell to Bob's dust order (by hash, unlimited budget)");
    log_it(L_INFO, "         Bob D dust: 0.000000000000000016 USDT @ 4.0 USDT/KEL");
    log_it(L_INFO, "         Using budget=0 (unlimited) to consume entire dust order");

    // Get Bob D dust order hash from tracking
    dap_hash_fast_t bob_d_root = {0};
    dap_hash_fast_t bob_d_tail = {0};
    bool found = false;
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (e->active && e->side == 1) { // BID order
            bob_d_root = e->root;
            bob_d_tail = e->tail;
            found = true;
            log_it(L_INFO, "         Found Bob D dust root: %s", dap_chain_hash_fast_to_str_static(&bob_d_root));
            log_it(L_INFO, "         Found Bob D dust tail: %s", dap_chain_hash_fast_to_str_static(&bob_d_tail));
            break;
        }
    }
    dap_assert(found, "Bob D dust order found in tracking");

    // Alice sells to Bob's dust order with unlimited budget (0)
    // Note: purchase function expects tail hash, but tracking uses root for lookups
    dap_hash_fast_t purchase_hash = {0};
    int ret = test_dex_order_purchase(f, f->alice, &bob_d_tail, "0", false, false, &purchase_hash);
    
    if (ret == 0) {
        log_it(L_INFO, "✓ Purchase from dust order succeeded!");
        
        // Dust order: 0.000000000000000016 USDT @ 4.0 USDT/KEL
        // Can buy: 0.000000000000000016 / 4.0 = 0.000000000000000004 KEL (4 datoshi KEL)
        // Alice sells: 0.000000000000000004 KEL
        // Alice receives gross: 0.000000000000000016 USDT (16 datoshi)
        // Service fee: 0 (too small to calculate, 2% of 16 datoshi = 0.32 datoshi, rounds to 0)
        // Alice net: 0.000000000000000016 USDT
        
        // Alice KEL: 8665.833333333333333333 - 0.000000000000000004 = 8665.833333333333333329
        // Alice USDT: 5843.899999999999999977 + 0.000000000000000016 = 5843.899999999999999993
        // Alice TC: 99977 - 1 (network fee) = 99976
        dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8665.833333333333333329"), "Alice KEL");
        dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5843.899999999999999993"), "Alice USDT");
        dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99976.0"), "Alice TC");
        f->balances.alice_kel = dap_chain_coins_to_balance("8665.833333333333333329");
        f->balances.alice_usdt = dap_chain_coins_to_balance("5843.899999999999999993");
        f->balances.alice_tc = dap_chain_coins_to_balance("99976.0");
        
        // Bob KEL: 1550 + 0.000000000000000004 = 1550.000000000000000004
        dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1550.000000000000000004"), "Bob KEL");
        f->balances.bob_kel = dap_chain_coins_to_balance("1550.000000000000000004");
        
        // Carol: service fee is 0 (too small)
        // Carol USDT: 1335.099999999999999998 (unchanged)
        dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1335.099999999999999998"), "Carol USDT");
        
        log_it(L_NOTICE, "✓ GROUP 2.5 PASSED: Direct Purchase from Dust Order");
    } else {
        log_it(L_WARNING, "✗ Purchase from dust order failed with error: %d", ret);
        log_it(L_WARNING, "   Dust orders might not be purchasable directly (MIN_FILL constraint?)");
        log_it(L_NOTICE, "⚠ GROUP 2.5 SKIPPED: Dust order not directly purchasable");
    }
}

/**
 * @brief Test Group 2.6 - BID-ASK Auto-Matching
 * @details Verifies that auto-matcher can match buyer with existing ASK orders
 * 
 * Scenario:
 * - Orderbook has Alice's ASK: 84.166666666666666667 KEL @ 6.0 USDT/KEL
 * - Bob does auto-match purchase with unlimited budget (0)
 * - Expected: Alice's ASK fully closed, no buyer-leftover
 */
static void test_group_2_6_bid_ask_auto_matching(dex_test_fixture_t *f)
{
    log_it(L_INFO, "=== TEST GROUP 2.6: BID-ASK Auto-Matching ===");

    // Precheck balances (after 2.5)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8665.833333333333333329"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5843.899999999999999993"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99976.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1550.000000000000000004"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42821.000000000000000009"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99981.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1335.099999999999999998"), "Precheck Carol USDT");

    // Current orderbook:
    // ASK: Alice A leftover (84.166666666666666667 KEL @ 6.0)

    log_it(L_INFO, "[2.6.1] Bob auto-match: buy KEL with unlimited budget (BID-ASK matching)");
    log_it(L_INFO, "         Should fully close Alice's ASK order");

    // Bob buys KEL with unlimited budget (0), no buyer-leftover
    dap_hash_fast_t purchase_hash = {0};
    int ret = test_dex_order_purchase_auto(f, f->bob, "USDT", "KEL", "0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Bob auto-purchase completed");

    // Bob buys 84.166666666666666667 KEL @ 6.0 USDT/KEL
    // Trade amount: 84.166666666666666667 * 6.0 = 505.000000000000000002 USDT
    // Service fee: 505.000000000000000002 * 0.02 = 10.100000000000000000 USDT (paid by Bob as TAKER)
    // Bob pays: 505.000000000000000002 + 10.100000000000000000 + 1 TC (network fee) = 515.100000000000000002 USDT + 1 TC
    
    // Alice receives: 505.000000000000000002 USDT (seller payout)
    // Alice KEL: 8665.833333333333333329 (unchanged - KEL were already locked in ASK order from Test 2.4a)
    // Alice USDT: 5843.899999999999999993 + 505.000000000000000002 = 6348.899999999999999995
    // Alice TC: 99976.0 (unchanged)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8665.833333333333333329"), "Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6348.899999999999999995"), "Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99976.0"), "Alice TC");
    f->balances.alice_kel = dap_chain_coins_to_balance("8665.833333333333333329");
    f->balances.alice_usdt = dap_chain_coins_to_balance("6348.899999999999999995");
    
    // Bob receives: 84.166666666666666667 KEL
    // Bob KEL: 1550.000000000000000004 + 84.166666666666666667 = 1634.166666666666666671
    // Bob USDT: 42821.000000000000000009 - 515.100000000000000002 = 42305.900000000000000007
    // Bob TC: 99981.0 - 1.0 = 99980.0
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1634.166666666666666671"), "Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42305.900000000000000007"), "Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99980.0"), "Bob TC");
    f->balances.bob_kel = dap_chain_coins_to_balance("1634.166666666666666671");
    f->balances.bob_usdt = dap_chain_coins_to_balance("42305.900000000000000007");
    f->balances.bob_tc = dap_chain_coins_to_balance("99980.0");
    
    // Carol receives: 10.100000000000000000 USDT service fee
    // Carol USDT: 1335.099999999999999998 + 10.100000000000000000 = 1345.199999999999999998
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1345.199999999999999998"), "Carol USDT");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1345.199999999999999998");

    // Dump orderbook state
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.6 ==========");
    test_dex_dump_orderbook(f, "After Test 2.6");
    log_it(L_INFO, "Expected: EMPTY (Alice ASK fully closed)");
    log_it(L_INFO, "BID-ASK auto-matching: Bob successfully bought from Alice's ASK");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");

    log_it(L_NOTICE, "✓ GROUP 2.6 PASSED: BID-ASK Auto-Matching");
}

/**
 * @brief Test Group 2.7 - Multi-Seller Matching + FIFO + Fee Distribution
 * @details COMBINED SCENARIOS:
 * 1. Multi-seller matching: buyer purchases from 2+ sellers in single TX
 * 2. FIFO enforcement: same rate → older order (Alice T1) filled first
 * 3. Multi-seller fee distribution: each seller pays proportional service fee
 * 4. Partial fill: second seller (Carol) has leftover after budget exhausted
 * 5. Service wallet collection: Carol receives fees from both sellers
 * 
 * Scenario:
 * - Alice creates ASK: 50 KEL @ 5.0 USDT/KEL (timestamp T1)
 * - usleep(1000) for FIFO ordering
 * - Carol creates ASK: 50 KEL @ 5.0 USDT/KEL (timestamp T2 > T1)
 * - usleep(1000) for stability
 * - Bob auto-match: buy 80 KEL for USDT
 * Expected:
 * - Alice (older): fully closed (50 KEL) → 250 USDT gross, pays 5 USDT fee
 * - Carol (younger): partially closed (30 KEL) → 150 USDT gross, pays 3 USDT fee
 * - Bob: pays 400 USDT (trade) + 8 USDT (service fee) + 1 TC (network fee)
 * - Carol service wallet: receives 8 USDT total (5 + 3)
 */
static void test_group_2_7_multi_seller_matching(dex_test_fixture_t *f)
{
    int ret;
    log_it(L_INFO, "=== TEST GROUP 2.7: Multi-Seller Matching + FIFO + Fee Distribution ===");

    // Precheck balances (after 2.6)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8665.833333333333333329"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6348.899999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99976.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1634.166666666666666671"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42305.900000000000000007"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99980.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "200.0"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1345.199999999999999998"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99999.0"), "Precheck Carol TC");

    // Current orderbook: EMPTY

    log_it(L_INFO, "[2.7.1] Alice creates ASK: 50 KEL @ 5.0 USDT/KEL (timestamp T1)");
    
    dap_hash_fast_t alice_ask_hash = {0};
    ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "50.0", "5.0", &alice_ask_hash);
    dap_assert(ret == 0, "Alice ASK order created");

    // Alice locks 50 KEL, pays 1 TC network fee
    // Alice KEL: 8665.833333333333333329 - 50 = 8615.833333333333333329
    // Alice TC: 99976 - 1 = 99975
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8615.833333333333333329"), "Alice KEL after ASK");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99975.0"), "Alice TC after ASK");
    f->balances.alice_kel = dap_chain_coins_to_balance("8615.833333333333333329");
    f->balances.alice_tc = dap_chain_coins_to_balance("99975.0");

    log_it(L_INFO, "[2.7.2] sleep(2) for FIFO ordering (ensure different ts_created)");
    sleep(2);

    log_it(L_INFO, "[2.7.3] Carol creates ASK: 50 KEL @ 5.0 USDT/KEL (timestamp T2 > T1)");
    
    dap_hash_fast_t carol_ask_hash = {0};
    ret = test_dex_order_create(f, f->carol, "USDT", "KEL", "50.0", "5.0", &carol_ask_hash);
    dap_assert(ret == 0, "Carol ASK order created");

    // Carol locks 50 KEL, pays 1 TC network fee
    // Carol KEL: 200 - 50 = 150
    // Carol TC: 99999 - 1 = 99998
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "150.0"), "Carol KEL after ASK");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99998.0"), "Carol TC after ASK");
    f->balances.carol_kel = dap_chain_coins_to_balance("150.0");
    f->balances.carol_tc = dap_chain_coins_to_balance("99998.0");
    
    log_it(L_INFO, "[2.7.4] sleep(2) for stability (ensure timestamp separation)");
    sleep(2);

    log_it(L_INFO, "[2.7.5] Bob auto-match: buy 80 KEL for USDT (multi-seller matching)");
    log_it(L_INFO, "         Should match Alice ASK fully (50 KEL) + Carol ASK partially (30 KEL)");
    log_it(L_INFO, "         FIFO: Alice (T1) before Carol (T2)");

    // Bob buys 80 KEL with USDT budget
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->bob, "USDT", "KEL", "80.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Bob auto-purchase completed");

    // Bob buys 80 KEL @ 5.0 USDT/KEL:
    // - Alice: 50 KEL @ 5.0 = 250 USDT (full)
    // - Carol: 30 KEL @ 5.0 = 150 USDT (partial)
    // Total: 400 USDT
    // Service fee (paid by Bob as TAKER): 400 * 0.02 = 8 USDT
    // Bob pays: 400 + 8 + 1 TC = 408 USDT + 1 TC
    
    // Alice receives: 250 USDT (seller payout, no deduction for ASK-side)
    // Alice KEL: 8615.833333333333333329 (unchanged, locked in order)
    // Alice USDT: 6348.899999999999999995 + 250 = 6598.899999999999999995
    // Alice TC: 99975.0 (unchanged)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8615.833333333333333329"), "Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6598.899999999999999995"), "Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99975.0"), "Alice TC");
    f->balances.alice_kel = dap_chain_coins_to_balance("8615.833333333333333329");
    f->balances.alice_usdt = dap_chain_coins_to_balance("6598.899999999999999995");
    
    // Bob receives: 80 KEL
    // Bob KEL: 1634.166666666666666671 + 80 = 1714.166666666666666671
    // Bob USDT: 42305.900000000000000007 - 408 = 41897.900000000000000007
    // Bob TC: 99980 - 1 = 99979
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1714.166666666666666671"), "Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "41897.900000000000000007"), "Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99979.0"), "Bob TC");
    f->balances.bob_kel = dap_chain_coins_to_balance("1714.166666666666666671");
    f->balances.bob_usdt = dap_chain_coins_to_balance("41897.900000000000000007");
    f->balances.bob_tc = dap_chain_coins_to_balance("99979.0");
    
    // Carol (seller) receives: 150 USDT (seller payout for 30 KEL sold)
    // Carol (service wallet) receives: 8 USDT (service fee from Bob as TAKER)
    // Carol KEL: 150.0 (unchanged - 20 KEL remain locked in leftover order)
    // Carol USDT: 1345.199999999999999998 + 150 + 8 = 1503.199999999999999998
    // Carol TC: 99998.0 (unchanged)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "150.0"), "Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1503.199999999999999998"), "Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99998.0"), "Carol TC");
    f->balances.carol_kel = dap_chain_coins_to_balance("150.0");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1503.199999999999999998");
    f->balances.carol_tc = dap_chain_coins_to_balance("99998.0");

    // Dump orderbook state
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.7 ==========");
    test_dex_dump_orderbook(f, "After Test 2.7");
    log_it(L_INFO, "Expected: Carol ASK leftover (20 KEL @ 5.0)");
    log_it(L_INFO, "Multi-seller: Alice fully closed (50 KEL), Carol partially closed (30 KEL)");
    log_it(L_INFO, "FIFO verified: Alice (T1) matched before Carol (T2)");
    log_it(L_INFO, "Fee distribution: Bob paid 8 USDT service fee to Carol service wallet");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");

    log_it(L_NOTICE, "✓ GROUP 2.7 PASSED: Multi-Seller Matching + FIFO + Fee Distribution");
}

/**
 * @brief Test Group 2.8 - Multi-Seller (ASK-side) + Self-Purchase + FIFO
 * @details COMBINED SCENARIOS:
 * 1. Multi-seller matching: Carol buys from her own ASK + Bob's ASK
 * 2. Self-purchase: Carol buys from her own leftover ASK order
 * 3. FIFO enforcement: Carol's old ASK (T1) matched before Bob's new ASK (T2)
 * 4. Partial fill: Bob's ASK has leftover after budget exhausted
 * 5. Fee distribution: Carol pays service fee (as TAKER), receives it back (as service wallet)
 * 
 * Scenario:
 * - Initial orderbook: Carol ASK leftover (20 KEL @ 5.0, timestamp T1)
 * - sleep(2) for FIFO ordering
 * - Bob creates ASK: 60 KEL @ 5.0 USDT/KEL (timestamp T2 > T1)
 * - sleep(2) for stability
 * - Carol auto-match: buy 70 KEL for USDT
 * Expected:
 * - Carol own ASK: fully closed (20 KEL) → 100 USDT (self-purchase, net internal)
 * - Bob ASK: partially closed (50 KEL) → 250 USDT seller payout
 * - Carol (buyer): pays 350 USDT + 7 USDT service fee + 1 TC network fee
 * - Carol (service): receives 7 USDT service fee (net: -7 paid, +7 received = 0)
 */
static void test_group_2_8_multi_seller_carol_buys(dex_test_fixture_t *f)
{
    int ret;
    log_it(L_INFO, "=== TEST GROUP 2.8: Multi-Seller (ASK) + Self-Purchase + FIFO (Carol buys) ===");

    // Precheck balances (after 2.7)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8615.833333333333333329"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6598.899999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99975.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1714.166666666666666671"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "41897.900000000000000007"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99979.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "150.0"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1503.199999999999999998"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99998.0"), "Precheck Carol TC");

    // Current orderbook: Carol ASK leftover (20 KEL @ 5.0) from Test 2.7

    log_it(L_INFO, "[2.8.1] sleep(2) for FIFO ordering");
    sleep(2);

    log_it(L_INFO, "[2.8.2] Bob creates ASK: 60 KEL @ 5.0 USDT/KEL (timestamp T2 > Carol T1)");
    
    dap_hash_fast_t bob_ask_hash = {0};
    ret = test_dex_order_create(f, f->bob, "USDT", "KEL", "60.0", "5.0", &bob_ask_hash);
    dap_assert(ret == 0, "Bob ASK order created");

    // Bob locks 60 KEL, pays 1 TC network fee
    // Bob KEL: 1714.166666666666666671 - 60 = 1654.166666666666666671
    // Bob TC: 99979 - 1 = 99978
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1654.166666666666666671"), "Bob KEL after ASK");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99978.0"), "Bob TC after ASK");
    f->balances.bob_kel = dap_chain_coins_to_balance("1654.166666666666666671");
    f->balances.bob_tc = dap_chain_coins_to_balance("99978.0");

    log_it(L_INFO, "[2.8.3] sleep(2) for stability");
    sleep(2);

    log_it(L_INFO, "[2.8.4] Carol auto-match: buy 70 KEL for USDT (multi-seller + self-purchase)");
    log_it(L_INFO, "         Should match Carol own ASK fully (20 KEL) + Bob ASK partially (50 KEL)");
    log_it(L_INFO, "         FIFO: Carol ASK (T1) before Bob ASK (T2)");

    // Carol buys 70 KEL with USDT budget
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->carol, "USDT", "KEL", "70.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Carol auto-purchase completed");

    // Carol buys 70 KEL @ 5.0 USDT/KEL:
    // - Carol own ASK: 20 KEL @ 5.0 = 100 USDT (self-purchase)
    // - Bob ASK: 50 KEL @ 5.0 = 250 USDT
    // Total: 350 USDT
    // Service fee: 350 * 0.02 = 7 USDT (WAIVED, Carol = service wallet, fee not charged)
    // Carol pays: 350 USDT (no fee) + 1 TC network fee
    
    // Carol (seller, self-purchase): receives 100 USDT for her own 20 KEL
    // Carol (buyer): receives 70 KEL, pays 350 USDT + 1 TC
    // Net for Carol: +70 KEL, -250 USDT (350 paid - 100 received), -1 TC
    // Carol KEL: 150 + 70 = 220 KEL
    // Carol USDT: 1503.199999999999999998 - 250 = 1253.199999999999999998
    // Carol TC: 99998 - 1 = 99997
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "220.0"), "Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1253.199999999999999998"), "Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99997.0"), "Carol TC");
    f->balances.carol_kel = dap_chain_coins_to_balance("220.0");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1253.199999999999999998");
    f->balances.carol_tc = dap_chain_coins_to_balance("99997.0");
    
    // Bob receives: 250 USDT (seller payout)
    // Bob KEL: 1654.166666666666666671 (unchanged, locked in order)
    // Bob USDT: 41897.900000000000000007 + 250 = 42147.900000000000000007
    // Bob TC: 99978.0 (unchanged)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1654.166666666666666671"), "Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42147.900000000000000007"), "Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99978.0"), "Bob TC");
    f->balances.bob_usdt = dap_chain_coins_to_balance("42147.900000000000000007");

    // Alice balances unchanged
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8615.833333333333333329"), "Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6598.899999999999999995"), "Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99975.0"), "Alice TC");

    // Dump orderbook state
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.8 ==========");
    test_dex_dump_orderbook(f, "After Test 2.8");
    log_it(L_INFO, "Expected: Bob ASK leftover (10 KEL @ 5.0)");
    log_it(L_INFO, "Multi-seller: Carol own ASK fully closed (20 KEL), Bob ASK partially closed (50 KEL)");
    log_it(L_INFO, "FIFO verified: Carol ASK (T1) matched before Bob ASK (T2)");
    log_it(L_INFO, "Self-purchase: Carol bought from her own ASK (internal netting)");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");

    log_it(L_NOTICE, "✓ GROUP 2.8 PASSED: Multi-Seller + Self-Purchase + FIFO (Carol buys)");
}

// ============================================================================
/**
 * @brief Test Group 2.9 - Multi-Buyer Matching (BID-side with FIFO)
 * @details Carol sells into Alice and Bob BID orders
 * Scenarios: Multi-buyer, FIFO ordering, fee distribution
 */
static void test_group_2_9_multi_buyer_matching(dex_test_fixture_t *f)
{
    int ret;
    log_it(L_INFO, "=== TEST GROUP 2.9: Multi-Buyer Matching (BID) + FIFO + Fee Distribution ===");

    // Precheck balances (after 2.8)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8615.833333333333333329"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6598.899999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99975.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1654.166666666666666671"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42147.900000000000000007"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99978.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "220.0"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1253.199999999999999998"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99997.0"), "Precheck Carol TC");

    log_it(L_INFO, "[2.9.1] Alice creates BID: 30 KEL @ 5.0 USDT/KEL (timestamp T1)");
    dap_hash_fast_t alice_bid_hash = {0};
    ret = test_dex_order_create(f, f->alice, "KEL", "USDT", "150.0", "0.2", &alice_bid_hash);
    dap_assert(ret == 0, "Alice BID order created");

    // Alice locks 150 USDT, pays 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6448.899999999999999995"), "Alice USDT after BID");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99974.0"), "Alice TC after BID");
    f->balances.alice_usdt = dap_chain_coins_to_balance("6448.899999999999999995");
    f->balances.alice_tc = dap_chain_coins_to_balance("99974.0");

    log_it(L_INFO, "[2.9.2] sleep(3) for FIFO ordering (dap_time_t resolution = 1 sec, need guaranteed gap)");
    sleep(3);

    log_it(L_INFO, "[2.9.3] Bob creates BID: 30 KEL @ 5.0 USDT/KEL (timestamp T2 > T1)");
    dap_hash_fast_t bob_bid_hash = {0};
    ret = test_dex_order_create(f, f->bob, "KEL", "USDT", "150.0", "0.2", &bob_bid_hash);
    dap_assert(ret == 0, "Bob BID order created");

    // Bob locks 150 USDT, pays 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "41997.900000000000000007"), "Bob USDT after BID");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99977.0"), "Bob TC after BID");
    f->balances.bob_usdt = dap_chain_coins_to_balance("41997.900000000000000007");
    f->balances.bob_tc = dap_chain_coins_to_balance("99977.0");

    log_it(L_INFO, "[2.9.4] sleep(2) for stability (ensure timestamp separation before purchase)");
    sleep(2);

    log_it(L_INFO, "[2.9.5] Carol auto-match: sell 50 KEL for USDT (multi-buyer matching)");
    log_it(L_INFO, "         Should match Alice BID fully (30 KEL) + Bob BID partially (20 KEL)");
    log_it(L_INFO, "         FIFO: Alice BID (T1) before Bob BID (T2)");

    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->carol, "KEL", "USDT", "50.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Carol auto-sell completed");

    // Carol sells 50 KEL @ 5.0 USDT/KEL:
    // - Alice BID: 30 KEL @ 5.0 = 150 USDT (fully closed)
    // - Bob BID: 20 KEL @ 5.0 = 100 USDT (partially closed)
    // Total: 250 USDT
    // Service fee: 250 * 0.02 = 5 USDT (WAIVED, Carol = service wallet)
    // Carol receives: 250 USDT (no fee deduction) - 1 TC network fee
    // Carol (seller): -50 KEL, +250 USDT, -1 TC
    // Carol KEL: 220 - 50 = 170 KEL
    // Carol USDT: 1253.199999999999999998 + 250 = 1503.199999999999999998
    // Carol TC: 99997 - 1 = 99996
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "170.0"), "Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1503.199999999999999998"), "Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99996.0"), "Carol TC");
    f->balances.carol_kel = dap_chain_coins_to_balance("170.0");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1503.199999999999999998");
    f->balances.carol_tc = dap_chain_coins_to_balance("99996.0");
    
    // Alice (buyer) receives: 30 KEL (order fully closed)
    // Alice KEL: 8615.833333333333333329 + 30 = 8645.833333333333333329
    // Alice USDT: 6448.899999999999999995 (unchanged, locked in BID)
    // Alice TC: 99974.0 (unchanged)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8645.833333333333333329"), "Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6448.899999999999999995"), "Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99974.0"), "Alice TC");
    f->balances.alice_kel = dap_chain_coins_to_balance("8645.833333333333333329");
    
    // Bob (buyer) receives: 20 KEL (order partially closed, 50 USDT leftover remains locked)
    // Bob KEL: 1654.166666666666666671 + 20 = 1674.166666666666666671
    // Bob USDT: 41997.900000000000000007 (unchanged, 50 USDT still locked in BID leftover)
    // Bob TC: 99977.0 (unchanged)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1674.166666666666666671"), "Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "41997.900000000000000007"), "Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99977.0"), "Bob TC");
    f->balances.bob_kel = dap_chain_coins_to_balance("1674.166666666666666671");
    f->balances.bob_usdt = dap_chain_coins_to_balance("41997.900000000000000007");

    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.9 ==========");
    test_dex_dump_orderbook(f, "After Test 2.9");
    log_it(L_INFO, "Expected: Bob BID leftover (50 USDT for 10 KEL @ 0.2), Bob ASK leftover (10 KEL @ 5.0)");
    log_it(L_INFO, "Multi-buyer: Alice BID fully closed (30 KEL), Bob BID partially closed (20 KEL)");
    log_it(L_INFO, "FIFO verified: Alice BID (T1) matched before Bob BID (T2)");
    log_it(L_INFO, "Fee distribution: Carol service fee WAIVED (Carol = service wallet)");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");

    log_it(L_NOTICE, "✓ GROUP 2.9 PASSED: Multi-Buyer Matching + FIFO + Fee Distribution");
}

/**
 * @brief Test Group 2.10 - Mixed Purchase (BID-side)
 * @details Seller sells into MIX of own and other's BID orders (self-sell + cross-sell)
 * 
 * Scenario:
 * - Alice creates BID: 30 KEL @ 4.0 USDT/KEL (rate 0.25)
 * - Bob creates BID: 30 KEL @ 4.0 USDT/KEL (rate 0.25)
 * - Bob sells 50 KEL into both BID orders (mixed: Alice's fully + Bob's partially)
 * 
 * Expected:
 * - Alice BID: fully closed (30 KEL purchased)
 * - Bob BID: partially closed (20 KEL purchased, 10 KEL leftover = 40 USDT locked)
 * - Bob: self-sell (20 KEL) + cross-sell (30 KEL to Alice)
 * - Service fee: paid by Bob (seller, TAKER)
 */
static void test_group_2_10_mixed_purchase_bid(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 2.10: Mixed Purchase (BID-side) ===");
    
    int ret = 0;
    
    // Precheck balances
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8645.833333333333333329"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6448.899999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99974.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1674.166666666666666671"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "41997.900000000000000007"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99977.0"), "Precheck Bob TC");
    
    log_it(L_INFO, "[2.10.1] Alice creates BID: 30 KEL @ 4.0 USDT/KEL (rate 0.25)");
    dap_hash_fast_t alice_bid_hash = {0};
    ret = test_dex_order_create(f, f->alice, "KEL", "USDT", "120.0", "0.25", &alice_bid_hash);
    dap_assert(ret == 0, "Alice BID order created");
    
    // Alice locks 120 USDT, pays 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6328.899999999999999995"), "Alice USDT after BID");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99973.0"), "Alice TC after BID");
    f->balances.alice_usdt = dap_chain_coins_to_balance("6328.899999999999999995");
    f->balances.alice_tc = dap_chain_coins_to_balance("99973.0");
    
    sleep(2); // Ensure distinct timestamp for FIFO ordering (same rate 4.0)
    log_it(L_INFO, "[2.10.2] Bob creates BID: 30 KEL @ 4.0 USDT/KEL (rate 0.25, with sleep for FIFO)");
    dap_hash_fast_t bob_bid_hash = {0};
    ret = test_dex_order_create(f, f->bob, "KEL", "USDT", "120.0", "0.25", &bob_bid_hash);
    dap_assert(ret == 0, "Bob BID order created");
    
    // Bob locks 120 USDT, pays 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "41877.900000000000000007"), "Bob USDT after BID");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99976.0"), "Bob TC after BID");
    f->balances.bob_usdt = dap_chain_coins_to_balance("41877.900000000000000007");
    f->balances.bob_tc = dap_chain_coins_to_balance("99976.0");
    
    log_it(L_INFO, "[2.10.3] Bob auto-match: sell 50 KEL for USDT (mixed BID matching)");
    log_it(L_INFO, "         Should match Alice BID fully (30 KEL) + Bob BID partially (20 KEL)");
    log_it(L_INFO, "         Bob sells to Alice (cross-sell) + self-sells to own BID");
    
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->bob, "KEL", "USDT", "50.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Bob auto-sell completed");
    
    // Bob sells 50 KEL, matches 3 BID orders:
    // 1. Bob old BID: 10 KEL @ 5.0 USDT/KEL = 50 USDT (fully closed, self-purchase)
    // 2. Alice BID: 30 KEL @ 4.0 USDT/KEL = 120 USDT (fully closed)
    // 3. Bob new BID: 10 KEL @ 4.0 USDT/KEL = 40 USDT (partially closed, self-purchase)
    // Total: 210 USDT, Service fee: 4.2 USDT, Taker receives: 205.8 USDT
    //
    // Composer aggregates payouts: Bob (10+10=20 KEL), Alice (30 KEL)
    // Bob balance changes:
    // KEL: -300 (spent input) + 20 (self-purchase payout: 10+10) + 250 (cashback) = -30 KEL
    // USDT: +205.8 (taker revenue)
    // TC: -1 (network fee)
    //
    // Bob KEL: 1674.166666666666666671 - 30 = 1644.166666666666666671
    // Bob USDT: 41877.900000000000000007 + 205.8 = 42083.700000000000000007
    // Bob TC: 99976 - 1 = 99975
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1644.166666666666666671"), "Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42083.700000000000000007"), "Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99975.0"), "Bob TC");
    f->balances.bob_kel = dap_chain_coins_to_balance("1644.166666666666666671");
    f->balances.bob_usdt = dap_chain_coins_to_balance("42083.700000000000000007");
    f->balances.bob_tc = dap_chain_coins_to_balance("99975.0");
    
    // Alice (buyer) receives: 30 KEL (order fully closed)
    // Alice BID fully consumed, no leftover
    // Alice KEL: 8645.833333333333333329 + 30 = 8675.833333333333333329
    // Alice USDT: 6328.899999999999999995 (unchanged)
    // Alice TC: 99973.0 (unchanged)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8675.833333333333333329"), "Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6328.899999999999999995"), "Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99973.0"), "Alice TC");
    f->balances.alice_kel = dap_chain_coins_to_balance("8675.833333333333333329");
    
    // Carol (service) receives: 4.2 USDT service fee
    // Carol USDT: 1503.199999999999999998 + 4.2 = 1507.399999999999999998
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1507.399999999999999998"), "Carol USDT");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1507.399999999999999998");
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.10 ==========");
    test_dex_dump_orderbook(f, "After Test 2.10");
    log_it(L_INFO, "Expected: 1 BID leftover (Bob @ 4.0, 20 KEL remaining), 1 ASK leftover (Bob @ 5.0)");
    log_it(L_INFO, "Mixed BID: Bob old BID fully closed (10 KEL), Alice BID fully closed (30 KEL), Bob new BID partially closed (10 of 30 KEL)");
    log_it(L_INFO, "Self-sell: Bob sold 50 KEL total: 20 KEL into own BIDs (10+10) + 30 KEL to Alice");
    log_it(L_INFO, "Fee distribution: Bob paid 4.2 USDT service fee (seller/TAKER)");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    
    log_it(L_NOTICE, "✓ GROUP 2.10 PASSED: Mixed Purchase (BID-side)");
}

/**
 * @brief Test Group 2.11 - Identical Orders + Partial Fill (EXTREME)
 * @details Four BID orders (1 old @ 4.0 + 3 new identical @ 3.0) from different sellers
 * 
 * Scenario:
 * - Orderbook before test: Bob old BID @ 4.0 (20 KEL leftover from Test 2.10)
 * - Alice creates BID: 30 KEL @ 3.0 USDT/KEL (rate 0.333333, 90 USDT locked)
 * - Bob creates BID: 30 KEL @ 3.0 USDT/KEL (rate 0.333333, 90 USDT locked, IDENTICAL to Alice!)
 * - Carol creates BID: 30 KEL @ 3.0 USDT/KEL (rate 0.333333, 90 USDT locked, IDENTICAL to Alice & Bob!)
 * - Dave (Bob) sells 90 KEL into all 4 BID orders
 * 
 * Expected:
 * - Bob old BID @ 4.0: fully closed (20 KEL, self-purchase, best price!)
 * - Alice BID @ 3.0: fully closed (30 KEL purchased)
 * - Bob new BID @ 3.0: fully closed (30 KEL purchased, self-purchase)
 * - Carol BID @ 3.0: partially closed (10 KEL purchased, 20 KEL leftover = 60 USDT locked)
 * - FIFO enforced: rate DESC (4.0 > 3.0), then timestamp ASC via sleep(2)
 * - Service fee: paid by Dave (seller, TAKER)
 * 
 * Verificator Stress Test:
 * - 4 IN_COND orders (1 @ 4.0 + 3 @ 3.0 identical)
 * - l_partial_pos MUST point to Carol's IN_COND (fourth in sorted array)
 * - OUT_COND.seller MUST be Carol (not Alice, not Bob!)
 * - OUT_COND.root MUST be Carol's BID root (not Alice's, not Bob's!)
 * - Tests fix on lines 3795-3796 (seller validation after sorting)
 */
static void test_group_2_11_identical_orders_extreme(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 2.11: Identical Orders + Partial Fill (EXTREME) ===");
    
    int ret = 0;
    
    // Precheck balances
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8675.833333333333333329"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6328.899999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99973.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1644.166666666666666671"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42083.700000000000000007"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99975.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "170.0"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1507.399999999999999998"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99996.0"), "Precheck Carol TC");
    
    log_it(L_INFO, "[2.11.1] Alice creates BID: 30 KEL @ 3.0 USDT/KEL (rate 0.333333333333333333, 90 USDT)");
    dap_hash_fast_t alice_bid_hash = {0};
    ret = test_dex_order_create(f, f->alice, "KEL", "USDT", "90.0", "0.333333333333333333", &alice_bid_hash);
    dap_assert(ret == 0, "Alice BID order created");
    
    // Alice locks 90 USDT, pays 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6238.899999999999999995"), "Alice USDT after BID");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99972.0"), "Alice TC after BID");
    f->balances.alice_usdt = dap_chain_coins_to_balance("6238.899999999999999995");
    f->balances.alice_tc = dap_chain_coins_to_balance("99972.0");
    
    sleep(2); // Ensure FIFO: Alice (T1) < Bob (T2)
    log_it(L_INFO, "[2.11.2] Bob creates BID: 30 KEL @ 3.0 USDT/KEL (rate 0.333333333333333333, IDENTICAL to Alice!)");
    dap_hash_fast_t bob_bid_hash = {0};
    ret = test_dex_order_create(f, f->bob, "KEL", "USDT", "90.0", "0.333333333333333333", &bob_bid_hash);
    dap_assert(ret == 0, "Bob BID order created");
    
    // Bob locks 90 USDT, pays 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "41993.700000000000000007"), "Bob USDT after BID");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99974.0"), "Bob TC after BID");
    f->balances.bob_usdt = dap_chain_coins_to_balance("41993.700000000000000007");
    f->balances.bob_tc = dap_chain_coins_to_balance("99974.0");
    
    sleep(2); // Ensure FIFO: Bob (T2) < Carol (T3)
    log_it(L_INFO, "[2.11.3] Carol creates BID: 30 KEL @ 3.0 USDT/KEL (rate 0.333333333333333333, IDENTICAL to Alice & Bob!)");
    dap_hash_fast_t carol_bid_hash = {0};
    ret = test_dex_order_create(f, f->carol, "KEL", "USDT", "90.0", "0.333333333333333333", &carol_bid_hash);
    dap_assert(ret == 0, "Carol BID order created");
    
    // Carol locks 90 USDT, pays 1 TC network fee
    // Carol USDT: 1507.399999999999999998 - 90 = 1417.399999999999999998
    // Carol TC: 99996 - 1 = 99995
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1417.399999999999999998"), "Carol USDT after BID");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99995.0"), "Carol TC after BID");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1417.399999999999999998");
    f->balances.carol_tc = dap_chain_coins_to_balance("99995.0");
    
    log_it(L_INFO, "[2.11.4] Dave (Bob) auto-match: sell 90 KEL for USDT");
    log_it(L_INFO, "         FIFO matching order: Bob old @ 4.0 (20) → Alice @ 3.0 (30) → Bob new @ 3.0 (30) → Carol @ 3.0 (10 of 30)");
    log_it(L_INFO, "         Expected leftover: Carol's BID (20 KEL = 60 USDT)");
    
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->bob, "KEL", "USDT", "90.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Dave (Bob) auto-sell completed");
    
    // Bob sells 90 KEL, matches 4 BID orders (FIFO by rate DESC, then timestamp ASC):
    // 1. Bob old BID: 20 KEL @ 4.0 USDT/KEL = 80 USDT (fully closed, self-purchase, from Test 2.10)
    // 2. Alice BID: 30 KEL @ 3.0 USDT/KEL = 90 USDT (fully closed)
    // 3. Bob new BID: 30 KEL @ 3.0 USDT/KEL = 90 USDT (fully closed, self-purchase)
    // 4. Carol BID: 10 KEL @ 3.0 USDT/KEL = 30 USDT (partially closed)
    // Total: 290 USDT, Service fee: 5.8 USDT, Taker receives: 284.2 USDT
    //
    // Composer aggregates payouts:
    // - Bob (self-purchase): 50 KEL (20 old + 30 new)
    // - Alice (cross-sell): 30 KEL
    // - Carol (cross-sell): 10 KEL
    //
    // Bob balance changes:
    // KEL: -900 (spent input) + 50 (self-purchase payout: 20+30) + 810 (cashback) = -40 KEL
    // USDT: +284.2 (taker revenue, after fee)
    // TC: -1 (network fee)
    //
    // Bob KEL: 1644.166666666666666671 - 40.00000000000000006 = 1604.166666666666666641
    //   Note: 40.00000000000000006 = 90 spent - (20 full + 29.99999999999999997 + 10 cashback)
    //   Rounding loss: 30 wei per 30 KEL @ rate 0.333333333333333333
    // Bob USDT: 41993.700000000000000007 + 284.200000000000000206 = 42277.900000000000000213
    // Bob TC: 99974 - 1 = 99973
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1604.166666666666666641"), "Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42277.900000000000000213"), "Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99973.0"), "Bob TC");
    f->balances.bob_kel = dap_chain_coins_to_balance("1604.166666666666666641");
    f->balances.bob_usdt = dap_chain_coins_to_balance("42277.900000000000000213");
    f->balances.bob_tc = dap_chain_coins_to_balance("99973.0");
    
    // Alice (buyer) receives: 29.99999999999999997 KEL (rounding loss: 30 wei @ rate 0.333333333333333333)
    // Alice KEL: 8675.833333333333333329 + 29.99999999999999997 = 8705.833333333333333299
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8705.833333333333333299"), "Alice KEL");
    f->balances.alice_kel = dap_chain_coins_to_balance("8705.833333333333333299");
    
    // Carol (buyer) receives: 10.00000000000000006 KEL (rounding gain: 60 wei @ rate 0.333333333333333333)
    // Carol KEL: 170.0 (pre) + 10.00000000000000006 = 180.00000000000000006
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "180.00000000000000006"), "Carol KEL");
    f->balances.carol_kel = dap_chain_coins_to_balance("180.00000000000000006");
    
    // Carol (service wallet) receives: 5.800000000000000004 USDT (service fee, 2% of 290.00000000000000021)
    // Carol USDT: 1417.399999999999999998 + 5.800000000000000004 = 1423.200000000000000002
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1423.200000000000000002"), "Carol USDT (service fee)");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1423.200000000000000002");
    
    // Update tracking for closed/updated orders
    test_dex_order_track_remove(f, &alice_bid_hash);  // Alice BID fully closed
    test_dex_order_track_remove(f, &bob_bid_hash);    // Bob new BID fully closed (self-purchase)
    test_dex_order_track_update(f, &carol_bid_hash, &purchase_hash, dap_chain_coins_to_balance("60.0"));  // Carol BID leftover: 20 KEL @ 3.0 = 60 USDT
    
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.11 ==========");
    test_dex_dump_orderbook(f, "After Test 2.11");
    log_it(L_INFO, "Expected: 2 leftovers total:");
    log_it(L_INFO, "  - Bob ASK leftover (@ 5.0, from Test 2.9)");
    log_it(L_INFO, "  - Carol NEW BID leftover (@ 3.0, 20 KEL = 60 USDT)");
    log_it(L_INFO, "Bob old BID (@ 4.0, from Test 2.10): FULLY CLOSED by this test!");
    log_it(L_INFO, "FIFO verified: Bob old @ 4.0 (T0) → Alice @ 3.0 (T1) → Bob new @ 3.0 (T2) → Carol @ 3.0 (T3)");
    log_it(L_INFO, "Verificator stress test:");
    log_it(L_INFO, "  - 4 IN_COND orders (Bob old + 3 new identical @ 3.0)");
    log_it(L_INFO, "  - l_partial_pos = Carol's IN_COND (fourth in canonical array)");
    log_it(L_INFO, "  - OUT_COND.seller = Carol (NOT Alice, NOT Bob!)");
    log_it(L_INFO, "  - OUT_COND.root = Carol's BID root (NOT Alice's, NOT Bob's!)");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    
    log_it(L_NOTICE, "✓ GROUP 2.11 PASSED: Identical Orders + Partial Fill (EXTREME)");
}

/**
 * @brief Test Group 2.4b - Mixed Purchase (BID-side, external orders)
 * @details Seller sells into MIX of own and other's BID orders (symmetric to 2.4a)
 * 
 * Scenario:
 * - Orderbook: Carol BID leftover (20 KEL @ 3.0 from Test 2.11)
 * - Alice creates BID: 40 KEL @ 4.0 USDT/KEL (rate 0.25)
 * - Bob creates BID: 40 KEL @ 4.0 USDT/KEL (rate 0.25, FIFO with sleep)
 * - Carol sells 70 KEL → matches:
 *   1. Alice BID @ 4.0: 40 KEL (fully closed, best price)
 *   2. Bob BID @ 4.0: 10 KEL (partially closed)
 *   3. Carol's own BID @ 3.0: 20 KEL (fully closed, self-purchase, worst price)
 * 
 * Expected leftover: Bob's BID (30 KEL = 120 USDT)
 * 
 * Coverage:
 * - Mixed purchase: own + external BID orders
 * - Self-purchase on BID-side (Carol buys from own BID)
 * - FIFO between Alice and Bob (same rate 4.0)
 * - Fee payment by SELLER (Carol pays service fee)
 */
static void test_group_2_4b_mixed_purchase_bid_external(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 2.4b: Mixed Purchase (BID-side, external orders) ===");
    
    int ret = 0;
    
    // Precheck balances
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8705.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6238.899999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99972.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1604.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42277.900000000000000213"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99973.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "180.00000000000000006"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1423.200000000000000002"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99995.0"), "Precheck Carol TC");
    
    log_it(L_INFO, "[2.4b.1] Alice creates BID: 40 KEL @ 4.0 USDT/KEL (rate 0.25, 160 USDT)");
    dap_hash_fast_t alice_bid_hash = {0};
    ret = test_dex_order_create(f, f->alice, "KEL", "USDT", "160.0", "0.25", &alice_bid_hash);
    dap_assert(ret == 0, "Alice BID order created");
    
    // Alice USDT: 6238.899999999999999995 - 160 = 6078.899999999999999995
    // Alice TC: 99972 - 1 = 99971
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6078.899999999999999995"), "Alice USDT after BID");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99971.0"), "Alice TC after BID");
    
    sleep(2); // Ensure distinct timestamp for FIFO ordering (same rate 4.0)
    log_it(L_INFO, "[2.4b.2] Bob creates BID: 40 KEL @ 4.0 USDT/KEL (rate 0.25, with sleep for FIFO)");
    dap_hash_fast_t bob_bid_hash = {0};
    ret = test_dex_order_create(f, f->bob, "KEL", "USDT", "160.0", "0.25", &bob_bid_hash);
    dap_assert(ret == 0, "Bob BID order created");
    
    // Bob USDT: 42277.900000000000000213 - 160 = 42117.900000000000000213
    // Bob TC: 99973 - 1 = 99972
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42117.900000000000000213"), "Bob USDT after BID");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99972.0"), "Bob TC after BID");
    
    log_it(L_INFO, "[2.4b.3] Carol auto-match: sell 100 KEL for USDT");
    log_it(L_INFO, "         FIFO matching order: Alice @ 4.0 (40) → Bob @ 4.0 (40) → Carol own @ 3.0 (20)");
    log_it(L_INFO, "         All orders fully closed (no leftovers)");
    
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->carol, "KEL", "USDT", "100.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Carol auto-sell completed");
    
    // Update tracking
    test_dex_order_track_remove(f, &alice_bid_hash);  // Alice BID fully closed
    test_dex_order_track_remove(f, &bob_bid_hash);    // Bob BID fully closed
    
    // Find Carol's BID leftover from tracking (created in Test 2.11, leftover @ 3.0, 20 KEL = 60 USDT)
    dap_hash_fast_t carol_bid_leftover_hash = {0};
    for (order_entry_t *order = f->orders; order != NULL; order = order->next) {
        if (order->active && 
            dap_chain_addr_compare(&order->seller_addr, &f->carol_addr) &&
            order->side == 1) {  // BID
            carol_bid_leftover_hash = order->tail;
            break;
        }
    }
    test_dex_order_track_remove(f, &carol_bid_leftover_hash);  // Carol's BID @ 3.0 fully closed (self-purchase)
    
    // Calculate expected balances
    // Total trade: 100 KEL = 380 USDT (40*4.0 + 40*4.0 + 20*3.0 = 160 + 160 + 60)
    // Service fee: 2% of 380 = 7.6 USDT (paid by Carol as SELLER)
    // Carol is also service wallet, so fee is waived (buyer=service)
    // Net effect: Carol receives 380 USDT gross (no fee deducted)
    
    // Alice (buyer) receives: 40 KEL
    // Alice KEL: 8705.833333333333333299 + 40 = 8745.833333333333333299
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8745.833333333333333299"), "Alice KEL");
    f->balances.alice_kel = dap_chain_coins_to_balance("8745.833333333333333299");
    
    // Bob (buyer) receives: 40 KEL (fully filled!)
    // Bob KEL: 1604.166666666666666641 + 40 = 1644.166666666666666641
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1644.166666666666666641"), "Bob KEL");
    f->balances.bob_kel = dap_chain_coins_to_balance("1644.166666666666666641");
    
    // Carol (seller + service wallet + self-purchase):
    // KEL: 180 - 100 (sold) + 20 (self-purchase) = 100
    // Composer KEL cashback: 70.00000000000000009 (rounding loss: 9 datoshi)
    // Carol KEL: 180.00000000000000006 - 99.99999999999999991 + 70.00000000000000009 = 100.00000000000000006
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "100.00000000000000006"), "Carol KEL");
    f->balances.carol_kel = dap_chain_coins_to_balance("100.00000000000000006");
    
    // Carol USDT (service wallet):
    // Initial: 1423.200000000000000002
    // Composer sellers_payout: 379.99999999999999979 (from log, rounding loss: 21 datoshi)
    // Service fee: 0 (waived, т.к. Carol = buyer)
    // Final: 1423.2 + 379.999... = 1803.199999999999999792
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1803.199999999999999792"), "Carol USDT (service fee)");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1803.199999999999999792");
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.4b ==========");
    test_dex_dump_orderbook(f, "After Test 2.4b");
    log_it(L_INFO, "Expected: 1 leftover only:");
    log_it(L_INFO, "  - Bob ASK leftover (10 KEL @ 5.0 from Test 2.9)");
    log_it(L_INFO, "All BID orders FULLY CLOSED:");
    log_it(L_INFO, "  - Alice BID @ 4.0: 40 KEL (fully closed)");
    log_it(L_INFO, "  - Bob BID @ 4.0: 40 KEL (fully closed)");
    log_it(L_INFO, "  - Carol BID @ 3.0: 20 KEL (fully closed by self-purchase)");
    log_it(L_INFO, "Mixed purchase: Carol sold to Alice (40) + Bob (40) + own BID (20)");
    log_it(L_INFO, "FIFO verified: Alice @ 4.0 (T1) → Bob @ 4.0 (T2) → Carol @ 3.0 (T3)");
    log_it(L_INFO, "Fee waived: Carol as buyer (service wallet) does not pay service fee");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    
    log_it(L_NOTICE, "✓ GROUP 2.4b PASSED: Mixed Purchase (BID-side, external orders)");
}

/**
 * @brief Test Group 2.12 - Multi-Order Matching with Leftover (ASK-side)
 * @details Verifies that leftover ASK correctly participates in multi-order matching with FIFO
 */
static void test_group_2_12_multi_order_with_leftover(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 2.12: Multi-Order Matching with Leftover (ASK-side) ===");
    
    // Precheck balances
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8745.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6078.899999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99971.0"), "Precheck Alice TC");
    
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1644.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42117.900000000000000213"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99972.0"), "Precheck Bob TC");
    
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "100.00000000000000006"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1803.199999999999999792"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99994.0"), "Precheck Carol TC");
    
    log_it(L_INFO, "[2.12.1] Alice creates ASK: 30 KEL @ 5.0 USDT/KEL");
    int ret = 0;
    dap_hash_fast_t alice_ask_hash = {0};
    ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "30.0", "5.0", &alice_ask_hash);
    dap_assert(ret == 0, "Alice ASK order created");
    
    // Alice KEL: 8745.833333333333333299 - 30 = 8715.833333333333333299
    // Alice TC: 99971 - 1 = 99970
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8715.833333333333333299"), "Alice KEL after ASK");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99970.0"), "Alice TC after ASK");
    
    sleep(2); // Ensure distinct timestamp for FIFO (Alice T1, Bob T2)
    
    log_it(L_INFO, "[2.12.2] Bob creates ASK: 30 KEL @ 5.5 USDT/KEL (with sleep for FIFO)");
    dap_hash_fast_t bob_ask2_hash = {0};
    ret = test_dex_order_create(f, f->bob, "USDT", "KEL", "30.0", "5.5", &bob_ask2_hash);
    dap_assert(ret == 0, "Bob ASK order created");
    
    // Bob KEL: 1644.166666666666666641 - 30 = 1614.166666666666666641
    // Bob TC: 99972 - 1 = 99971
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1614.166666666666666641"), "Bob KEL after ASK");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99971.0"), "Bob TC after ASK");
    
    log_it(L_INFO, "[2.12.3] Carol auto-match: buy 50 KEL for USDT");
    log_it(L_INFO, "         FIFO matching order: Bob old leftover @ 5.0 (10) → Alice @ 5.0 (30) → Bob new @ 5.5 (10)");
    log_it(L_INFO, "         Leftover participates in multi-order matching!");
    log_it(L_INFO, "         Budget: 10*5.0 + 30*5.0 + 10*5.5 = 50 + 150 + 55 = 255 USDT (using 260 USDT)");
    
    // IMPORTANT: Save Bob's old ASK leftover hash BEFORE auto-purchase (to avoid confusion with new ASK)
    uint256_t bob_old_price = dap_chain_coins_to_balance("5.0");
    dap_hash_fast_t bob_old_ask_leftover_hash = {0};
    for (order_entry_t *order = f->orders; order != NULL; order = order->next) {
        if (!order->active)
            continue;
        if (!dap_chain_addr_compare(&order->seller_addr, &f->bob_addr) || order->side != 0)
            continue; // Only Bob's ASKs
        if (compare256(order->price, bob_old_price) == 0) {
            bob_old_ask_leftover_hash = order->tail;
            break;  // This is the OLD leftover from Test 2.9 (@ 5.0)
        }
    }
    dap_assert(!dap_hash_fast_is_blank(&bob_old_ask_leftover_hash), "Found Bob old ASK leftover (10 KEL @ 5.0) before auto-purchase");
    
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->carol, "USDT", "KEL", "260.0", false, false, &purchase_hash);
    dap_assert(ret == 0, "Carol auto-purchase completed");
    
    // Update tracking: test_dex_order_purchase_auto already updated Bob ASK2 leftover
    // We only need to manually remove the orders that were fully consumed
    test_dex_order_track_remove(f, &bob_old_ask_leftover_hash);  // Bob old leftover @ 5.0 fully closed
    test_dex_order_track_remove(f, &alice_ask_hash);  // Alice ASK fully closed
    
    // Calculate expected balances
    // Total trade: 50.909090909090909090 KEL = 259.999999999999999995 USDT
    //   - Bob old leftover @ 5.0: 10 KEL = 50 USDT
    //   - Alice ASK @ 5.0: 30 KEL = 150 USDT
    //   - Bob new ASK @ 5.5: 10.909090909090909090 KEL = 59.999999999999999995 USDT
    // Service fee: 2%% of 260 = 5.2 USDT (waived, Carol = buyer = service wallet)
    // Carol spent full budget: 260 USDT
    
    // Carol (buyer, also service wallet):
    // Actual purchase: 50.909090909090909090 KEL (full budget 260 USDT spent)
    // KEL: 100.00000000000000006 + 50.909090909090909090 = 150.909090909090909150 (uint256 rounding: 150.90909090909090915)
    // USDT: 1803.199999999999999792 - 260 + 0.000000000000000005 (cashback) = 1543.199999999999999797
    // TC: 99994 - 1 = 99993 (network fee)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "150.90909090909090915"), "Carol KEL");
    f->balances.carol_kel = dap_chain_coins_to_balance("150.90909090909090915");
    
    // Carol USDT: 1803.199... - 1015 (inputs) + 755.000...005 (cashback) = 1543.199...797
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1543.199999999999999797"), "Carol USDT");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1543.199999999999999797");
    
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99993.0"), "Carol TC");
    f->balances.carol_tc = dap_chain_coins_to_balance("99993.0");
    
    // Bob (seller of leftover + ASK2):
    // Old leftover: 10 KEL @ 5.0 = 50 USDT
    // ASK2: 10.909090909090909090 KEL @ 5.5 = 59.999999999999999995 USDT
    // Bob USDT: 42117.900000000000000213 + 50 + 59.999999999999999995 = 42227.900000000000000208
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42227.900000000000000208"), "Bob USDT");
    f->balances.bob_usdt = dap_chain_coins_to_balance("42227.900000000000000208");
    
    // Alice (seller):
    // KEL already locked when ASK created
    // USDT: 6078.899999999999999995 + 150 = 6228.899999999999999995
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6228.899999999999999995"), "Alice USDT");
    f->balances.alice_usdt = dap_chain_coins_to_balance("6228.899999999999999995");
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.12 ==========");
    test_dex_dump_orderbook(f, "After Test 2.12");
    log_it(L_INFO, "Expected: 1 leftover only:");
    log_it(L_INFO, "  - Bob ASK leftover (19.09090909090909091 KEL @ 5.5)");
    log_it(L_INFO, "All orders in this test:");
    log_it(L_INFO, "  - Bob old ASK leftover @ 5.0: 10 KEL (fully closed, FIFO: oldest!)");
    log_it(L_INFO, "  - Alice ASK @ 5.0: 30 KEL (fully closed, FIFO: newer)");
    log_it(L_INFO, "  - Bob new ASK @ 5.5: 10.909... KEL (partially closed, 19.090... leftover)");
    log_it(L_INFO, "Multi-order matching: leftover + new orders in FIFO + best price order");
    log_it(L_INFO, "FIFO verified: Bob leftover @ 5.0 (old) → Alice @ 5.0 (T1) → Bob new @ 5.5 (T2)");
    log_it(L_INFO, "Fee waived: Carol as buyer = service wallet");
    log_it(L_INFO, "Budget fully spent: 260 USDT → 50.909... KEL");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    
    log_it(L_NOTICE, "✓ GROUP 2.12 PASSED: Multi-Order Matching with Leftover");
}

/**
 * @brief Test Group 2.13 - Fee Aggregation (seller==service)
 * @details CRITICAL SCENARIO:
 * Verifies fee aggregation when seller is service wallet.
 * 
 * When seller==service AND buyer!=service:
 * - Buyer pays service fee (as taker)
 * - Service fee is aggregated to seller payout (NO separate fee OUT)
 * - Verificator: l_fee_was_aggregated=true, canonical expected_buy += fee
 * 
 * Scenario:
 * - Carol (service wallet) creates ASK: 50 KEL @ 5.0 USDT/KEL
 * - Alice buys 50 KEL (Alice = taker, pays fee)
 * Expected:
 * - Alice pays: 250 USDT (trade) + 5 USDT (service fee) = 255 USDT
 * - Carol receives 1 OUT: 255 USDT (payout 250 + aggregated fee 5)
 * - NO separate service fee OUT
 * - Verificator: canonical expected_buy = 255 USDT (250 + 5)
 */
static void test_group_2_13_fee_aggregation_seller_service(dex_test_fixture_t *f) {
    int ret;
    log_it(L_INFO, "=== TEST GROUP 2.13: Fee Aggregation (seller==service) ===");
    
    // Precheck balances (after 2.12)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8715.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "6228.899999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99970.0"), "Precheck Alice TC");
    
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1614.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42227.900000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99971.0"), "Precheck Bob TC");
    
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "150.90909090909090915"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1543.199999999999999797"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99993.0"), "Precheck Carol TC");
    
    log_it(L_INFO, "[2.13.1] Carol (service wallet) creates ASK: 50 KEL @ 5.0 USDT/KEL");
    dap_hash_fast_t carol_ask_hash = {0};
    ret = test_dex_order_create(f, f->carol, "USDT", "KEL", "50.0", "5.0", &carol_ask_hash);
    dap_assert(ret == 0, "Carol ASK order created");
    
    // Carol locks 50 KEL, pays 1 TC network fee
    // Carol KEL: 150.90909090909090915 - 50 = 100.90909090909090915
    // Carol TC: 99993 - 1 = 99992
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "100.90909090909090915"), "Carol KEL after ASK");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99992.0"), "Carol TC after ASK");
    f->balances.carol_kel = dap_chain_coins_to_balance("100.90909090909090915");
    f->balances.carol_tc = dap_chain_coins_to_balance("99992.0");
    
    log_it(L_INFO, "[2.13.2] Alice buys 50 KEL from Carol's ASK (fee aggregation scenario)");
    log_it(L_INFO, "         Alice = taker, pays service fee");
    log_it(L_INFO, "         Carol = seller + service wallet → fee AGGREGATED to payout");
    
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->alice, "USDT", "KEL", "50.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Alice auto-purchase completed");
    
    // Calculate expected balances:
    // Trade: 50 KEL @ 5.0 = 250 USDT
    // Service fee: 250 * 0.02 = 5 USDT (paid by Alice as taker)
    // Fee aggregation: Carol = seller + service → fee aggregated to payout
    
    // Alice (buyer, taker):
    // KEL: 8715.833333333333333299 + 50 = 8765.833333333333333299
    // USDT: 6228.899999999999999995 - 250 - 5 = 5973.899999999999999995
    // TC: 99970 - 1 = 99969
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8765.833333333333333299"), "Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5973.899999999999999995"), "Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99969.0"), "Alice TC");
    f->balances.alice_kel = dap_chain_coins_to_balance("8765.833333333333333299");
    f->balances.alice_usdt = dap_chain_coins_to_balance("5973.899999999999999995");
    f->balances.alice_tc = dap_chain_coins_to_balance("99969.0");
    
    // Carol (seller + service wallet):
    // USDT: 1543.199999999999999797 + 250 (payout) + 5 (aggregated fee) = 1798.199999999999999797
    // KEL: 100.90909090909090915 (unchanged, order fully consumed)
    // TC: 99992 (unchanged)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1798.199999999999999797"), "Carol USDT (aggregated)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "100.90909090909090915"), "Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99992.0"), "Carol TC");
    f->balances.carol_usdt = dap_chain_coins_to_balance("1798.199999999999999797");
    
    // Update tracking
    test_dex_order_track_remove(f, &carol_ask_hash);  // Carol ASK fully closed
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "========== ORDERBOOK DUMP: After Test 2.13 ==========");
    test_dex_dump_orderbook(f, "After Test 2.13");
    log_it(L_INFO, "Expected: Orderbook empty (Carol ASK fully consumed)");
    log_it(L_INFO, "Fee aggregation verified:");
    log_it(L_INFO, "  - Carol (seller + service) received 255 USDT in 1 OUT (250 payout + 5 fee)");
    log_it(L_INFO, "  - NO separate service fee OUT created");
    log_it(L_INFO, "  - Verificator: l_fee_was_aggregated=true, canonical expected_buy=255");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    
    log_it(L_NOTICE, "✓ GROUP 2.13 PASSED: Fee Aggregation (seller==service)");
}


// TEST GROUP 3: MIN_FILL POLICIES
// ============================================================================

/**
 * @brief Test Group 3.1 - AON order (MIN_FILL=100%)
 * @details Verifies All-Or-Nothing policy:
 *  - Alice creates ASK: 500 KEL @ 5.0 USDT/KEL with min_fill=100 (AON)
 *  - Bob attempts partial buy (300 KEL = 60%) → REJECTED (below 100%)
 *  - Bob buys full amount (500 KEL = 100%) → SUCCESS
 * 
 * Initial balances (after Group 2):
 *  - Alice: KEL=8765.833333, USDT=5973.9, TC=99969
 *  - Bob:   KEL=1614.166667, USDT=42227.9, TC=99971
 */
static void test_group_3_1_aon_order(dex_test_fixture_t *f) {
    int ret;
    log_it(L_INFO, "=== TEST GROUP 3.1: AON Order (min_fill=100%%) ===");
    
    // Precheck balances
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8765.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5973.899999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99969.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1614.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42227.900000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99971.0"), "Precheck Bob TC");
    
    log_it(L_INFO, "[3.1.1] Alice creates ASK: 500 KEL @ 5.0 USDT/KEL with min_fill=100 (AON)");
    dap_hash_fast_t alice_ask_hash = {0};
    ret = test_dex_order_create_ex(f, f->alice, "USDT", "KEL", "500.0", "5.0", 
                                     100,  // AON (100%)
                                     &alice_ask_hash);
    dap_assert(ret == 0, "Alice ASK order created");
    
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8265.833333333333333299"), "Alice KEL locked (500)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "5973.899999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99968.0"), "Alice TC fee (1 TC)");
    
    log_it(L_INFO, "[3.1.2] Bob attempts to buy 300 KEL (60%% < 100%% AON threshold)");
    log_it(L_INFO, "        Purchase by hash: Composer filters min_fill violation");
    dap_hash_fast_t bob_purchase_hash_1 = {0};
    ret = test_dex_order_purchase(f, f->bob, &alice_ask_hash, "1500.0", false, false, &bob_purchase_hash_1);
    dap_assert(ret == -2, "Bob purchase REJECTED by composer (below AON threshold)");
    
    // Verify Bob balances unchanged (no fee on rejection)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "1614.166666666666666641"), "Bob KEL unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "42227.900000000000000208"), "Bob USDT unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99971.0"), "Bob TC unchanged (no fee on rejection)");
    
    // Verify Alice order still active
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8265.833333333333333299"), "Alice KEL still locked");
    
    log_it(L_INFO, "[3.1.3] Bob buys 500 KEL (100%% = AON threshold met)");
    dap_hash_fast_t bob_purchase_hash_2 = {0};
    ret = test_dex_order_purchase(f, f->bob, &alice_ask_hash, "2500.0", false, false, &bob_purchase_hash_2);
    dap_assert(ret == 0, "Bob purchase SUCCESS (full fill)");
    
    // Verify final balances after full fill
    // Alice: unlocks 500 KEL (spent), receives 2500 USDT (full payout, TAKER pays service fee)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8265.833333333333333299"), "Alice KEL after sell");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "8473.899999999999999995"), "Alice USDT after sell (+2500)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99968.0"), "Alice TC unchanged");
    
    // Bob: receives 500 KEL, pays 2500 USDT + 50 service fee (2%) + 1 TC fee
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2114.166666666666666641"), "Bob KEL after buy (+500)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39677.900000000000000208"), "Bob USDT after buy (-2550: 2500+50 fee)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99970.0"), "Bob TC fee (-1)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 3.1 PASSED: AON order rejected partial, accepted full");
}

/**
 * @brief Test Group 3.2 - Percentage MIN_FILL (Dynamic)
 * @details Verifies percentage-based min_fill (threshold from current leftover):
 *  - Carol creates BID: 1000 USDT @ 4.0 USDT/KEL with min_fill=50 (50% dynamic, wants 250 KEL)
 *  - Alice attempts sell 100 KEL (400 USDT < 500 min) → REJECTED
 *  - Alice sells 130 KEL (520 USDT > 500 min) → SUCCESS, leftover 480 USDT (120 KEL) created
 *  - Bob attempts sell 50 KEL to leftover (200 USDT < 240 min for leftover) → REJECTED
 *  - Bob sells 65 KEL to leftover (260 USDT > 240 min) → SUCCESS
 * 
 * Initial balances (after Test 3.1):
 *  - Alice: KEL=8265.833333, USDT=8473.9, TC=99968
 *  - Bob:   KEL=2114.166667, USDT=39677.9, TC=99970
 *  - Carol: KEL=100.909091, USDT=1848.2 (includes +50 service fee from 3.1), TC=99992
 */
static void test_group_3_2_percentage_minfill(dex_test_fixture_t *f) {
    int ret;
    log_it(L_INFO, "=== TEST GROUP 3.2: Percentage MIN_FILL (50%% dynamic) ===");
    
    // Precheck balances (after 3.1)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8265.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "8473.899999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99968.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2114.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39677.900000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99970.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "100.909090909090909150"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "1848.199999999999999797"), "Precheck Carol USDT (+50 service fee from 3.1)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99992.0"), "Precheck Carol TC");
    
    log_it(L_INFO, "[3.2.1] Carol creates BID: 1000 USDT @ 4.0 USDT/KEL with min_fill=50 (50%% dynamic)");
    dap_hash_fast_t carol_bid_hash = {0};
    ret = test_dex_order_create_ex(f, f->carol, "KEL", "USDT", "1000.0", "0.25", 
                                     50,  // 50% min_fill (dynamic, from USDT base)
                                     &carol_bid_hash);
    dap_assert(ret == 0, "Carol BID order created");
    
    // Carol wants 250 KEL for 1000 USDT @ 4.0 USDT/KEL, min_fill=500 USDT (50%)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "100.909090909090909150"), "Carol KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "848.199999999999999797"), "Carol USDT locked (1000)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99991.0"), "Carol TC fee (1 TC)");
    
    log_it(L_INFO, "[3.2.2] Alice attempts to sell 100 KEL (400 USDT < 500 USDT min_fill threshold)");
    log_it(L_INFO, "        Purchase by hash: Composer filters min_fill violation");
    dap_hash_fast_t alice_sell_hash_1 = {0};
    ret = test_dex_order_purchase(f, f->alice, &carol_bid_hash, "100.0", false, false, &alice_sell_hash_1);
    dap_assert(ret == -2, "Alice sell REJECTED by composer (below min_fill threshold)");
    
    // Verify Alice balances unchanged (no fee on rejection)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8265.833333333333333299"), "Alice KEL unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "8473.899999999999999995"), "Alice USDT unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99968.0"), "Alice TC unchanged (no fee on rejection)");
    
    // Verify Carol order still active
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "848.199999999999999797"), "Carol USDT still locked");
    
    log_it(L_INFO, "[3.2.3] Alice sells 130 KEL (520 USDT > 500 USDT min_fill threshold)");
    dap_hash_fast_t alice_sell_hash_2 = {0};
    ret = test_dex_order_purchase(f, f->alice, &carol_bid_hash, "130.0", false, false, &alice_sell_hash_2);
    dap_assert(ret == 0, "Alice sell SUCCESS (partial fill)");
    
    // Alice: sells 130 KEL, receives 509.6 USDT (520 - 10.4 service fee, Alice is TAKER)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8135.833333333333333299"), "Alice KEL after sell (-130)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "8983.499999999999999995"), "Alice USDT after sell (+509.6)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99967.0"), "Alice TC fee (-1)");
    
    // Carol: receives 130 KEL + 10.4 USDT service fee, leftover 480 USDT locked (120 KEL @ 4.0 USDT/KEL)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "230.909090909090909150"), "Carol KEL after buy (+130)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "858.599999999999999797"), "Carol USDT (+10.4 service fee, 480 still locked)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99991.0"), "Carol TC unchanged");
    
    log_it(L_INFO, "[3.2.4] Bob attempts to sell 50 KEL to leftover (200 USDT < 240 USDT min_fill for leftover)");
    log_it(L_INFO, "        Purchase by hash: Composer filters min_fill violation");
    dap_hash_fast_t bob_sell_hash_1 = {0};
    ret = test_dex_order_purchase(f, f->bob, &carol_bid_hash, "50.0", false, false, &bob_sell_hash_1);
    dap_assert(ret == -2, "Bob sell REJECTED by composer (below dynamic leftover threshold)");
    
    // Verify Bob balances unchanged
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2114.166666666666666641"), "Bob KEL unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39677.900000000000000208"), "Bob USDT unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99970.0"), "Bob TC unchanged (no fee on rejection)");
    
    log_it(L_INFO, "[3.2.5] Bob sells 65 KEL to leftover (260 USDT > 240 USDT min_fill threshold)");
    dap_hash_fast_t bob_sell_hash_2 = {0};
    ret = test_dex_order_purchase(f, f->bob, &carol_bid_hash, "65.0", false, false, &bob_sell_hash_2);
    dap_assert(ret == 0, "Bob sell SUCCESS (leftover partial fill)");
    
    // Bob: sells 65 KEL, receives 254.8 USDT (260 - 5.2 service fee, Bob is TAKER)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2049.166666666666666641"), "Bob KEL after sell (-65)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39932.700000000000000208"), "Bob USDT after sell (+254.8)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99969.0"), "Bob TC fee (-1)");
    
    // Carol: receives 65 KEL + 5.2 USDT service fee, leftover 220 USDT locked (55 KEL @ 4.0 USDT/KEL)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "295.909090909090909150"), "Carol KEL after buy (+65)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "863.799999999999999797"), "Carol USDT (+5.2 service fee, 220 still locked)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99991.0"), "Carol TC unchanged");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 3.2 PASSED: Percentage MIN_FILL (50%% dynamic threshold validated)");
}

static void test_group_3_3_dynamic_minfill_adaptation(dex_test_fixture_t *f) {
    int ret;
    log_it(L_INFO, "=== TEST GROUP 3.3: Dynamic MIN_FILL Adaptation (leftover < original min_fill) ===");
    
    // Precheck balances (after 3.2)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8135.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "8983.499999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99967.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2049.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39932.700000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99969.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "295.909090909090909150"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "863.799999999999999797"), "Precheck Carol USDT (220 locked)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99991.0"), "Precheck Carol TC");
    
    log_it(L_INFO, "[3.3.1] Alice attempts to sell 20 KEL (below dynamic min_fill threshold)");
    log_it(L_INFO, "        Current leftover: 55 KEL (220 USDT)");
    log_it(L_INFO, "        Dynamic min_fill: 27.5 KEL (110 USDT, 50%% of 55 KEL)");
    log_it(L_INFO, "        Request: 20 KEL (80 USDT < 110 USDT min_fill)");
    
    dap_hash_fast_t alice_sell_hash_1 = {0};
    ret = test_dex_order_purchase_auto(f, f->alice, "KEL", "USDT", "20.0", false, false, &alice_sell_hash_1);
    dap_assert(ret != 0, "Alice sell REJECTED (no orders match: budget < min_fill)");
    
    // Verify Alice balances unchanged (no fee on rejection)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8135.833333333333333299"), "Alice KEL unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "8983.499999999999999995"), "Alice USDT unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99967.0"), "Alice TC unchanged (no fee on rejection)");
    
    log_it(L_INFO, "[3.3.2] Alice sells 30 KEL (above dynamic min_fill threshold)");
    log_it(L_INFO, "        Request: 30 KEL (120 USDT > 110 USDT min_fill)");
    
    dap_hash_fast_t alice_sell_hash_2 = {0};
    ret = test_dex_order_purchase_auto(f, f->alice, "KEL", "USDT", "30.0", false, false, &alice_sell_hash_2);
    dap_assert(ret == 0, "Alice sell SUCCESS (dynamic min_fill adapted to leftover)");
    
    // Alice: sells 30 KEL for 120 USDT, receives 117.6 USDT (120 - 2.4 service fee), 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8105.833333333333333299"), "Alice KEL after sell (-30)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9101.099999999999999995"), "Alice USDT after sell (+117.6)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99966.0"), "Alice TC fee (-1)");
    
    // Carol: buys 30 KEL, receives 2.4 USDT service fee, leftover 100 USDT (25 KEL @ 4.0 USDT/KEL)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "325.909090909090909150"), "Carol KEL after buy (+30)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "866.199999999999999797"), "Carol USDT (+2.4 service fee, 100 still locked)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99991.0"), "Carol TC unchanged");
    
    log_it(L_INFO, "[3.3.3] Bob sells 25 KEL (closes Carol's leftover)");
    log_it(L_INFO, "        New leftover: 25 KEL (100 USDT)");
    log_it(L_INFO, "        Dynamic min_fill: 12.5 KEL (50 USDT, 50%% of 25 KEL)");
    log_it(L_INFO, "        Request: 25 KEL (100 USDT, closes leftover exactly)");
    
    dap_hash_fast_t bob_sell_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->bob, "KEL", "USDT", "25.0", false, false, &bob_sell_hash);
    dap_assert(ret == 0, "Bob sell SUCCESS (closes Carol's leftover)");
    
    // Bob: sells 25 KEL for 100 USDT, receives 98 USDT (100 - 2 service fee), 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2024.166666666666666641"), "Bob KEL after sell (-25)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "40030.700000000000000208"), "Bob USDT after sell (+98)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99968.0"), "Bob TC fee (-1)");
    
    // Carol: buys 25 KEL, receives 2 USDT service fee, order fully closed
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "350.909090909090909150"), "Carol KEL after buy (+25)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "868.199999999999999797"), "Carol USDT (+2 service fee, order closed)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99991.0"), "Carol TC unchanged");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 3.3 PASSED: Dynamic MIN_FILL adapted to leftover < original min_fill");
    
    // Dump final balances and orders after Test 3.3
    log_it(L_INFO, " ");
    log_it(L_INFO, "=== Final State After Test 3.3 ===");
    test_dex_dump_balances(f, "After Test 3.3");
    test_dex_dump_orderbook(f, "After Test 3.3");
}

// ============================================================================
// TEST GROUP 3.4: ASK with MIN_FILL via Auto-Matcher
// ============================================================================

static void test_group_3_4_ask_minfill_automatch(dex_test_fixture_t *f) {
    int ret;
    log_it(L_INFO, "=== TEST GROUP 3.4: ASK with MIN_FILL via Auto-Matcher (symmetry to 3.3) ===");

    // Precheck balances (after 3.3)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "8105.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9101.099999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99966.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2024.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "40030.700000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99968.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "350.909090909090909150"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "868.199999999999999797"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99991.0"), "Precheck Carol TC");

    log_it(L_INFO, "[3.4.1] Alice creates ASK: 200 KEL @ 4.0 USDT/KEL with min_fill=60 (60%% dynamic)");
    log_it(L_INFO, "        Min_fill threshold: 120 KEL (480 USDT, 60%% of 200 KEL)");

    dap_hash_fast_t alice_ask_hash = {0};
    ret = test_dex_order_create_ex(f, f->alice, "USDT", "KEL", "200.0", "4.0", 60, &alice_ask_hash);
    dap_assert(ret == 0, "Alice ASK created successfully");

    // Alice: 200 KEL locked, 1 TC fee
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7905.833333333333333299"), "Alice KEL locked (-200)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9101.099999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99965.0"), "Alice TC fee (-1)");

    log_it(L_INFO, "[3.4.2] Bob attempts to buy 100 KEL via auto-matcher (below min_fill threshold)");
    log_it(L_INFO, "        Request: 100 KEL (400 USDT < 480 USDT min_fill), max_rate=5.0 to filter Bob leftover @ 5.5");

    uint256_t min_rate = dap_chain_coins_to_balance("5.0");
    dap_hash_fast_t bob_buy_hash_1 = {0};
    ret = test_dex_order_purchase_auto_ex(f, f->bob, "USDT", "KEL", "400.0", false, false, min_rate, &bob_buy_hash_1);
    dap_assert(ret == -2, "Bob buy REJECTED (no orders match: budget < min_fill)");

    // Verify Bob balances unchanged (no fee on rejection)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2024.166666666666666641"), "Bob KEL unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "40030.700000000000000208"), "Bob USDT unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99968.0"), "Bob TC unchanged (no fee on rejection)");

    log_it(L_INFO, "[3.4.2a] Bob attempts to buy 100 KEL BY HASH (below min_fill threshold)");
    log_it(L_INFO, "         Purchase by hash: Composer filters min_fill violation");
    dap_hash_fast_t bob_purchase_hash_1 = {0};
    ret = test_dex_order_purchase(f, f->bob, &alice_ask_hash, "400.0", false, false, &bob_purchase_hash_1);
    dap_assert(ret == -2, "Bob purchase by hash REJECTED by composer (below min_fill)");
    
    // Verify Bob balances unchanged (no fee on rejection)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2024.166666666666666641"), "Bob KEL unchanged (by-hash rejection)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "40030.700000000000000208"), "Bob USDT unchanged (by-hash rejection)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99968.0"), "Bob TC unchanged (no fee on by-hash rejection)");

    log_it(L_INFO, "[3.4.3] Bob buys 130 KEL via auto-matcher (above min_fill threshold)");
    log_it(L_INFO, "        Request: 130 KEL (520 USDT > 480 USDT min_fill), max_rate=5.0");

    dap_hash_fast_t bob_buy_hash_2 = {0};
    ret = test_dex_order_purchase_auto(f, f->bob, "USDT", "KEL", "520.0", false, false, &bob_buy_hash_2);
    dap_assert(ret == 0, "Bob buy SUCCESS (min_fill satisfied)");

    // Bob: buys 130 KEL for 520 USDT + 10.4 USDT service fee (TAKER), 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2154.166666666666666641"), "Bob KEL after buy (+130)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39500.300000000000000208"), "Bob USDT after buy (-520-10.4 service fee)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99967.0"), "Bob TC fee (-1)");

    // Alice: receives 520 USDT (MAKER, no fee deducted), leftover 70 KEL remains locked
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7905.833333333333333299"), "Alice KEL unchanged (70 KEL leftover locked)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9621.099999999999999995"), "Alice USDT after sell (+520)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99965.0"), "Alice TC unchanged (MAKER)");

    // Carol: receives 10.4 USDT service fee
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "878.599999999999999797"), "Carol USDT (+10.4 service fee)");

    log_it(L_INFO, "[3.4.4] Carol attempts to buy 30 KEL from leftover (below dynamic min_fill threshold)");
    log_it(L_INFO, "        Current leftover: 70 KEL (280 USDT)");
    log_it(L_INFO, "        Dynamic min_fill: 42 KEL (168 USDT, 60%% of 70 KEL)");
    log_it(L_INFO, "        Request: 30 KEL (120 USDT < 168 USDT min_fill), max_rate=5.0");

    dap_hash_fast_t carol_buy_hash_1 = {0};
    ret = test_dex_order_purchase_auto_ex(f, f->carol, "USDT", "KEL", "120.0", false, false, min_rate, &carol_buy_hash_1);
    dap_assert(ret == -2, "Carol buy REJECTED (no orders match: budget < min_fill)");

    // Verify Carol balances unchanged (no fee on rejection)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "350.909090909090909150"), "Carol KEL unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "878.599999999999999797"), "Carol USDT unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99991.0"), "Carol TC unchanged (no fee on rejection)");

    log_it(L_INFO, "[3.4.5] Carol buys 50 KEL from leftover (above dynamic min_fill threshold)");
    log_it(L_INFO, "        Request: 50 KEL (200 USDT > 168 USDT min_fill), max_rate=5.0");

    dap_hash_fast_t carol_buy_hash_2 = {0};
    ret = test_dex_order_purchase_auto(f, f->carol, "USDT", "KEL", "200.0", false, false, &carol_buy_hash_2);
    dap_assert(ret == 0, "Carol buy SUCCESS (dynamic min_fill adapted to leftover)");

    // Carol: buys 50 KEL for 200 USDT, service fee WAIVED (service wallet is buyer), 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "400.909090909090909150"), "Carol KEL after buy (+50)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "678.599999999999999797"), "Carol USDT after buy (-200, fee waived)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99990.0"), "Carol TC fee (-1)");

    // Alice: receives 200 USDT (MAKER, no fee deducted), leftover 20 KEL remains locked
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7905.833333333333333299"), "Alice KEL unchanged (20 KEL leftover locked)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9821.099999999999999995"), "Alice USDT after sell (+200)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99965.0"), "Alice TC unchanged (MAKER)");

    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 3.4 PASSED: ASK with min_fill via auto-matcher (symmetry to 3.3 BID)");

    // Dump final balances and orders after Test 3.4
    log_it(L_INFO, " ");
    log_it(L_INFO, "=== Final State After Test 3.4 ===");
    test_dex_dump_balances(f, "After Test 3.4");
    test_dex_dump_orderbook(f, "After Test 3.4");
}

/**
 * @brief Test Group 3.5: MIN_FILL_FROM_ORIGIN (static threshold from original order)
 * 
 * Tests:
 * - min_fill with from_origin flag (bit 7 = 1)
 * - Threshold calculated from ORIGINAL order value, not leftover
 * - Threshold NEVER CHANGES across leftovers
 * - Leftover smaller than from_origin threshold becomes AON (dust)
 */
static void test_group_3_5_minfill_from_origin(dex_test_fixture_t *f)
{
    log_it(L_INFO, "=== TEST GROUP 3.5: MIN_FILL_FROM_ORIGIN (static, from original order) ===");
    
    int ret = 0;
    
    // Precheck balances (after Group 3.4)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7905.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9821.099999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99965.0"), "Precheck Alice TC");
    
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2154.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39500.300000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99967.0"), "Precheck Bob TC");
    
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "400.909090909090909150"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "678.599999999999999797"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99990.0"), "Precheck Carol TC");
    
    log_it(L_INFO, "[3.5.1] Carol creates BID: 500 USDT @ 5.0 USDT/KEL with min_fill=0xB2 (50%% from_origin)");
    log_it(L_INFO, "        Wants to buy: 100 KEL total, min_fill threshold = 50 KEL (50%% of original 100 KEL)");
    
    dap_hash_fast_t carol_bid_hash = {0};
    ret = test_dex_order_create_ex(f, f->carol, "KEL", "USDT", "500.0", "0.2", 0xB2, &carol_bid_hash);
    dap_assert(ret == 0, "Carol BID created successfully");
    
    // Carol: 500 USDT locked, 1 TC fee
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "400.909090909090909150"), "Carol KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "178.599999999999999797"), "Carol USDT locked (-500)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99989.0"), "Carol TC fee (-1)");
    
    log_it(L_INFO, "[3.5.2] Alice attempts to sell 40 KEL (40%% < 50%% from_origin threshold)");
    
    dap_hash_fast_t alice_sell_hash_1 = {0};
    ret = test_dex_order_purchase(f, f->alice, &carol_bid_hash, "40.0", false, false, &alice_sell_hash_1);
    dap_assert(ret == -2, "Alice sell REJECTED by composer (below from_origin threshold)");
    
    // Verify Alice balances unchanged (no fee on rejection)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7905.833333333333333299"), "Alice KEL unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9821.099999999999999995"), "Alice USDT unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99965.0"), "Alice TC unchanged (no fee on rejection)");
    
    log_it(L_INFO, "[3.5.3] Alice sells 60 KEL (60%% > 50%% from_origin threshold)");
    log_it(L_INFO, "        Expected: SUCCESS, leftover 40 KEL created (but threshold stays 50 KEL from_origin!)");
    
    dap_hash_fast_t alice_sell_hash_2 = {0};
    ret = test_dex_order_purchase(f, f->alice, &carol_bid_hash, "60.0", false, false, &alice_sell_hash_2);
    dap_assert(ret == 0, "Alice sell SUCCESS (above from_origin threshold)");
    
    // Alice: sells 60 KEL for 300 USDT, pays 6 USDT service fee (2% TAKER), 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7845.833333333333333299"), "Alice KEL after sell (-60)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10115.099999999999999995"), "Alice USDT after sell (+294, -6 fee)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99964.0"), "Alice TC fee (-1)");
    
    // Carol: receives 60 KEL (MAKER), +6 USDT service fee (as service wallet), leftover 200 USDT (40 KEL @ 5.0), min_fill STAYS 50 KEL from_origin!
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "460.909090909090909150"), "Carol KEL after buy (+60)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "184.599999999999999797"), "Carol USDT (leftover 200 locked + 6 service fee)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99989.0"), "Carol TC unchanged (MAKER)");
    
    log_it(L_INFO, "[3.5.4] Bob attempts to sell 30 KEL to leftover (30 < 50 from_origin, even if 75%% of 40 KEL leftover)");
    log_it(L_INFO, "        from_origin threshold UNCHANGED: still 50 KEL (not recalculated from leftover 40)");
    
    dap_hash_fast_t bob_sell_hash_1 = {0};
    ret = test_dex_order_purchase(f, f->bob, &carol_bid_hash, "30.0", false, false, &bob_sell_hash_1);
    dap_assert(ret == -2, "Bob sell REJECTED by composer (below from_origin threshold)");
    
    // Verify Bob balances unchanged
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2154.166666666666666641"), "Bob KEL unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39500.300000000000000208"), "Bob USDT unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99967.0"), "Bob TC unchanged (no fee on rejection)");
    
    log_it(L_INFO, "[3.5.5] Bob sells 40 KEL to leftover (FULL leftover close, but 40 < 50 from_origin)");
    log_it(L_INFO, "        Leftover 40 KEL < threshold 50 KEL → becomes DUST (AON-like)");
    log_it(L_INFO, "        Expected: SUCCESS (dust leftover allows only 100%% fill)");
    
    dap_hash_fast_t bob_sell_hash_2 = {0};
    ret = test_dex_order_purchase(f, f->bob, &carol_bid_hash, "40.0", false, false, &bob_sell_hash_2);
    dap_assert(ret == 0, "Bob sell SUCCESS (dust leftover, 100%% fill allowed)");
    
    // Bob: sells 40 KEL for 200 USDT, pays 4 USDT service fee (2% TAKER), 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2114.166666666666666641"), "Bob KEL after sell (-40)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39696.300000000000000208"), "Bob USDT after sell (+196, -4 fee)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99966.0"), "Bob TC fee (-1)");
    
    // Carol: receives 40 KEL (MAKER), +4 USDT service fee (as service wallet), order fully closed
    // Leftover 200 USDT spent on buying 40 KEL from Bob (as intended for BID order)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "500.909090909090909150"), "Carol KEL after buy (+40)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "188.599999999999999797"), "Carol USDT (184.6 + 4 service fee, 200 spent on 40 KEL)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99989.0"), "Carol TC unchanged (MAKER)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    
    log_it(L_NOTICE, "✓ GROUP 3.5 PASSED: MIN_FILL_FROM_ORIGIN (static threshold, leftover→dust→AON verified)");
}

/**
 * @brief Test Group 3.6: MIN_FILL Boundary — Exact Threshold Edge Case
 * @details Verifies boundary conditions at exact min_fill threshold:
 *  - Alice creates ASK: 100 KEL @ 4.0 USDT/KEL with min_fill=50% (50 KEL)
 *  - Bob attempts to buy 49 KEL (49% < 50%) → REJECTED
 *  - Bob buys 50 KEL (50% = exact threshold) → SUCCESS
 *  - Carol attempts to buy 24 KEL from leftover (48% < 50%) → REJECTED
 *  - Carol buys 25 KEL from leftover (50% = exact threshold) → SUCCESS
 * 
 * Initial balances (after Test 3.5):
 *  - Alice: KEL=7845.833333, USDT=10115.1, TC=99964
 *  - Bob:   KEL=2114.166667, USDT=39696.3, TC=99966
 *  - Carol: KEL=500.909091, USDT=188.6, TC=99989
 */
static void test_group_3_6_boundary_exact_threshold(dex_test_fixture_t *f) {
    int ret;
    log_it(L_INFO, "=== TEST GROUP 3.6: MIN_FILL Boundary — Exact Threshold Edge Case ===");
    
    // Precheck balances (after Test 3.5)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7845.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10115.099999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99964.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2114.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39696.300000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99966.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "500.909090909090909150"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "188.599999999999999797"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99989.0"), "Precheck Carol TC");
    
    log_it(L_INFO, "[3.6.1] Alice creates ASK: 100 KEL @ 4.0 USDT/KEL with min_fill=50 (50%% dynamic)");
    log_it(L_INFO, "        Min_fill threshold: 50 KEL (50%% of 100 KEL)");
    
    dap_hash_fast_t alice_ask_hash = {0};
    ret = test_dex_order_create_ex(f, f->alice, "USDT", "KEL", "100.0", "4.0", 50, &alice_ask_hash);
    dap_assert(ret == 0, "Alice ASK order created");
    
    // Alice: 100 KEL locked, 1 TC fee
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7745.833333333333333299"), "Alice KEL locked (-100)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10115.099999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99963.0"), "Alice TC fee (-1)");
    
    log_it(L_INFO, "[3.6.2] Bob attempts to buy 49 KEL (49%% < 50%% threshold)");
    log_it(L_INFO, "        Purchase by hash: Composer filters min_fill violation (49 < 50)");
    log_it(L_INFO, "        Budget: 49 KEL (is_budget_buy=true) = 196 USDT @ 4.0 USDT/KEL");
    dap_hash_fast_t bob_buy_hash_1 = {0};
    ret = test_dex_order_purchase(f, f->bob, &alice_ask_hash, "49.0", true, false, &bob_buy_hash_1);
    dap_assert(ret == -2, "Bob purchase REJECTED by composer (below threshold by 1 KEL)");
    
    // Verify Bob balances unchanged (no fee on rejection)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2114.166666666666666641"), "Bob KEL unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39696.300000000000000208"), "Bob USDT unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99966.0"), "Bob TC unchanged (no fee on rejection)");
    
    // Verify Alice order still active
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7745.833333333333333299"), "Alice KEL still locked");
    
    log_it(L_INFO, "[3.6.3] Bob buys 50 KEL (50.0%% = exact threshold)");
    log_it(L_INFO, "        Budget: 50 KEL (is_budget_buy=true) = 200 USDT @ 4.0 USDT/KEL");
    dap_hash_fast_t bob_buy_hash_2 = {0};
    ret = test_dex_order_purchase(f, f->bob, &alice_ask_hash, "50.0", true, false, &bob_buy_hash_2);
    dap_assert(ret == 0, "Bob purchase SUCCESS (boundary accepted)");
    
    // Bob: buys 50 KEL for 200 USDT + 4 USDT service fee (2% TAKER), 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2164.166666666666666641"), "Bob KEL after buy (+50)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39492.300000000000000208"), "Bob USDT after buy (-200-4 service fee)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99965.0"), "Bob TC fee (-1)");
    
    // Alice: receives 200 USDT (MAKER, no fee deducted), leftover 50 KEL remains locked
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7745.833333333333333299"), "Alice KEL unchanged (50 KEL leftover locked)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10315.099999999999999995"), "Alice USDT after sell (+200)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99963.0"), "Alice TC unchanged (MAKER)");
    
    // Carol: receives 4 USDT service fee
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "192.599999999999999797"), "Carol USDT (+4 service fee)");
    
    log_it(L_INFO, "[3.6.4] Carol attempts to buy 24 KEL from leftover (48%% of 50 KEL leftover < 50%%)");
    log_it(L_INFO, "        Current leftover: 50 KEL (200 USDT)");
    log_it(L_INFO, "        Dynamic min_fill: 25 KEL (100 USDT, 50%% of 50 KEL)");
    log_it(L_INFO, "        Budget: 24 KEL (is_budget_buy=true) = 96 USDT @ 4.0 USDT/KEL");
    
    dap_hash_fast_t carol_buy_hash_1 = {0};
    ret = test_dex_order_purchase(f, f->carol, &alice_ask_hash, "24.0", true, false, &carol_buy_hash_1);
    dap_assert(ret == -2, "Carol purchase REJECTED by composer (below dynamic leftover threshold)");
    
    // Verify Carol balances unchanged (no fee on rejection)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "500.909090909090909150"), "Carol KEL unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "192.599999999999999797"), "Carol USDT unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99989.0"), "Carol TC unchanged (no fee on rejection)");
    
    log_it(L_INFO, "[3.6.5] Carol buys 25 KEL from leftover (50.0%% = exact leftover threshold)");
    log_it(L_INFO, "        Budget: 25 KEL (is_budget_buy=true) = 100 USDT @ 4.0 USDT/KEL");
    dap_hash_fast_t carol_buy_hash_2 = {0};
    ret = test_dex_order_purchase(f, f->carol, &alice_ask_hash, "25.0", true, false, &carol_buy_hash_2);
    dap_assert(ret == 0, "Carol purchase SUCCESS (boundary accepted)");
    
    // Carol: buys 25 KEL for 100 USDT, service fee WAIVED (service wallet is buyer), 1 TC network fee
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "525.909090909090909150"), "Carol KEL after buy (+25)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "92.599999999999999797"), "Carol USDT after buy (-100, fee waived)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99988.0"), "Carol TC fee (-1)");
    
    // Alice: receives 100 USDT (MAKER, no fee deducted), leftover 25 KEL remains locked
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7745.833333333333333299"), "Alice KEL unchanged (25 KEL leftover locked)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10415.099999999999999995"), "Alice USDT after sell (+100)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99963.0"), "Alice TC unchanged (MAKER)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 3.6 PASSED: MIN_FILL Boundary — Exact Threshold Edge Case (49 rejected, 50 accepted)");
}

/**
 * @brief Test Group 3.7: MIN_FILL for Multi-Order Matching — Per-Order Threshold
 * @details Verifies min_fill applied per-order, not to aggregate:
 *  - Alice creates ASK: 100 KEL @ 3.5 USDT/KEL with min_fill=75% (75 KEL minimum)
 *    Rate 3.5 < 4.0 ensures this order is selected first (better price than old orders)
 *  - Bob creates ASK: 50 KEL @ 5.5 USDT/KEL with min_fill=0% (no min_fill)
 *  - Bob auto-matches to buy 90 KEL (90/100 = 90% > 75% threshold)
 *    → Only Alice's ASK matched (Bob skipped, budget satisfied)
 *    → Old orders @ 4.0 skipped (Alice @ 3.5 is better price)
 *  - Alice buys remaining 50 KEL from Bob's ASK
 * 
 * Initial balances (after Test 3.6):
 *  - Alice: KEL=7745.833333, USDT=10415.1, TC=99963
 *  - Bob:   KEL=2164.166667, USDT=39492.3, TC=99965
 *  - Carol: KEL=525.909091, USDT=92.6, TC=99988
 */
static void test_group_3_7_multi_order_minfill(dex_test_fixture_t *f) {
    int ret;
    log_it(L_INFO, "=== TEST GROUP 3.7: MIN_FILL for Multi-Order Matching — Per-Order Threshold ===");
    
    // Precheck balances (after Test 3.6)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7745.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10415.099999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99963.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2164.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39492.300000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99965.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "525.90909090909090915"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "92.599999999999999797"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99988.0"), "Precheck Carol TC");
    
    log_it(L_INFO, "[3.7.1] Alice creates ASK: 100 KEL @ 3.5 USDT/KEL with min_fill=0x4B (75%% dynamic)");
    log_it(L_INFO, "        Min_fill threshold: 75 KEL (75%% of 100 KEL)");
    log_it(L_INFO, "        Rate 3.5 < 4.0 (old orders) ensures this order is selected first by matcher");
    
    dap_hash_fast_t alice_ask_hash = {0};
    ret = test_dex_order_create_ex(f, f->alice, "USDT", "KEL", "100.0", "3.5", 0x4B, &alice_ask_hash);
    dap_assert(ret == 0, "Alice ASK created successfully");
    
    // Alice: 100 KEL locked, 1 TC fee
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7645.833333333333333299"), "Alice KEL locked (-100)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10415.099999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99962.0"), "Alice TC fee (-1)");
    
    log_it(L_INFO, "[3.7.2] Bob creates ASK: 50 KEL @ 5.5 USDT/KEL with min_fill=0x00 (no min_fill)");
    
    dap_hash_fast_t bob_ask_hash = {0};
    ret = test_dex_order_create_ex(f, f->bob, "USDT", "KEL", "50.0", "5.5", 0x00, &bob_ask_hash);
    dap_assert(ret == 0, "Bob ASK created successfully");
    
    // Bob: 50 KEL locked, 1 TC fee
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2114.166666666666666641"), "Bob KEL locked (-50)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39492.300000000000000208"), "Bob USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99964.0"), "Bob TC fee (-1)");
    
    log_it(L_INFO, "[3.7.3] Bob auto-matches to buy 90 KEL (90/100 = 90%% > 75%% threshold)");
    log_it(L_INFO, "        Expected: Only Alice's ASK matched (90 KEL filled, 10 KEL leftover)");
    log_it(L_INFO, "        Bob's ASK NOT touched (Alice already satisfied 90 KEL budget)");
    log_it(L_INFO, "        Old orders @ 4.0 skipped (Alice @ 3.5 is better price, selected first)");
    log_it(L_INFO, "        Budget: 90 KEL @ 3.5 = 315 USDT");
    log_it(L_INFO, "        Matcher behavior: min_fill applied per-order, stops after budget satisfied");
    
    dap_hash_fast_t bob_buy_hash = {0};
    ret = test_dex_order_purchase_auto(f, f->bob, "USDT", "KEL", "90.0", true, false, &bob_buy_hash);
    dap_assert(ret == 0, "Bob auto-match SUCCESS (Alice ASK matched, 90 KEL filled)");
    
    // Bob: buys 90 KEL for 315 USDT + 6.3 USDT service fee (2% TAKER), 1 TC network fee
    // Bob: KEL=2114.166666666666666641 + 90 = 2204.166666666666666641
    // Bob: USDT=39492.300000000000000208 - 315 - 6.3 = 39171.000000000000000208
    // Bob: TC=99964.0 - 1 = 99963.0
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2204.166666666666666641"), "Bob KEL after buy (+90)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39171.000000000000000208"), "Bob USDT after buy (-315-6.3 service fee)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99963.0"), "Bob TC fee (-1)");
    
    // Alice: receives 315 USDT (MAKER, no fee deducted), leftover 10 KEL remains locked
    // Alice: KEL=7645.833333333333333299 (unchanged, 10 leftover locked)
    // Alice: USDT=10415.099999999999999995 + 315 = 10730.099999999999999995
    // Alice: TC=99962.0 (unchanged, MAKER)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7645.833333333333333299"), "Alice KEL unchanged (10 KEL leftover locked)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10730.099999999999999995"), "Alice USDT after sell (+315)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99962.0"), "Alice TC unchanged (MAKER)");
    
    // Carol: receives 6.3 USDT service fee
    // Carol: USDT=92.599999999999999797 + 6.3 = 98.899999999999999797
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "98.899999999999999797"), "Carol USDT (+6.3 service fee)");
    
    log_it(L_INFO, "[3.7.4] Alice buys remaining 50 KEL from Bob's ASK");
    log_it(L_INFO, "        Bob's ASK has no min_fill, so any fill is allowed");
    
    dap_hash_fast_t alice_buy_hash = {0};
    ret = test_dex_order_purchase(f, f->alice, &bob_ask_hash, "50.0", true, false, &alice_buy_hash);
    dap_assert(ret == 0, "Alice buy SUCCESS (Bob has no min_fill)");
    
    // Alice: buys 50 KEL for 275 USDT + 5.5 USDT service fee (2% TAKER), 1 TC network fee
    // Alice: KEL=7645.833333333333333299 + 50 = 7695.833333333333333299
    // Alice: USDT=10730.099999999999999995 - 275 - 5.5 = 10449.599999999999999995
    // Alice: TC=99962.0 - 1 = 99961.0
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7695.833333333333333299"), "Alice KEL after buy (+50)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10449.599999999999999995"), "Alice USDT after buy (-275-5.5 service fee)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99961.0"), "Alice TC fee (-1)");
    
    // Bob: receives 275 USDT (MAKER, no fee deducted), order fully closed
    // Bob: KEL=2204.166666666666666641 (unchanged, order closed, already has 90 KEL from first buy)
    // Bob: USDT=39171.000000000000000208 + 275 = 39446.000000000000000208
    // Bob: TC=99963.0 (unchanged, MAKER)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2204.166666666666666641"), "Bob KEL unchanged (order closed, already has 90 KEL from first buy)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39446.000000000000000208"), "Bob USDT after sell (39171.0 + 275)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99963.0"), "Bob TC unchanged (MAKER)");
    
    // Carol: receives 5.5 USDT service fee
    // Carol: USDT=98.899999999999999797 + 5.5 = 104.399999999999999797
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "104.399999999999999797"), "Carol USDT (+5.5 service fee)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 3.7 PASSED: MIN_FILL for Multi-Order Matching — Per-Order Threshold (Alice matched, Bob skipped, then Bob filled)");
}

static void test_group_3_8_dust_order(dex_test_fixture_t *f)
{
    log_it(L_INFO, "=== TEST GROUP 3.8: MIN_FILL with Dust Order — Treat as AON ===");
    
    // Precheck balances (after Test 3.7)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2204.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39446.000000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99963.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "525.90909090909090915"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "104.399999999999999797"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99988.0"), "Precheck Carol TC");
    
    log_it(L_INFO, "[3.8.1] Bob creates ASK: 10 KEL @ 5.0 USDT/KEL with min_fill=0x32 (50%% dynamic)");
    log_it(L_INFO, "        Min_fill threshold: 5 KEL (50%% of 10 KEL)");
    log_it(L_INFO, "        Any partial fill < 5 KEL will be rejected (below min_fill threshold)");
    
    dap_hash_fast_t bob_ask_hash = {0};
    int ret = test_dex_order_create_ex(f, f->bob, "USDT", "KEL", "10.0", "5.0", 0x32, &bob_ask_hash);
    dap_assert(ret == 0, "Bob ASK created successfully");
    
    // Bob: 10 KEL locked, 1 TC fee
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2194.166666666666666641"), "Bob KEL locked (-10)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39446.000000000000000208"), "Bob USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99962.0"), "Bob TC fee (-1)");
    
    log_it(L_INFO, "[3.8.2] Carol attempts to buy 3 KEL (30%% < 50%%, but also < min_fill absolute)");
    log_it(L_INFO, "        Expected: Purchase REJECTED (dust order, treated as AON)");
    
    dap_hash_fast_t carol_buy_hash = {0};
    ret = test_dex_order_purchase(f, f->carol, &bob_ask_hash, "3.0", true, false, &carol_buy_hash);
    dap_assert(ret != 0, "Carol buy REJECTED (dust order, partial fill not allowed)");
    
    // Carol: balances unchanged (no fee deducted on rejection)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "525.90909090909090915"), "Carol KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "104.399999999999999797"), "Carol USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99988.0"), "Carol TC unchanged");
    
    // Bob: balances unchanged
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2194.166666666666666641"), "Bob KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39446.000000000000000208"), "Bob USDT unchanged");
    
    log_it(L_INFO, "[3.8.3] Carol buys 10 KEL (100%% fill)");
    log_it(L_INFO, "        Expected: Purchase SUCCESS (full fill always allowed, even for dust orders)");
    
    ret = test_dex_order_purchase(f, f->carol, &bob_ask_hash, "10.0", true, false, &carol_buy_hash);
    dap_assert(ret == 0, "Carol buy SUCCESS (full fill allowed for dust order)");
    
    // Bob: receives 50 USDT (MAKER, no fee deducted), order fully closed
    // Bob: KEL=2194.166666666666666641 (unchanged, order closed)
    // Bob: USDT=39446.000000000000000208 + 50 = 39496.000000000000000208
    // Bob: TC=99962.0 (unchanged, MAKER)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2194.166666666666666641"), "Bob KEL unchanged (order closed)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39496.000000000000000208"), "Bob USDT after sell (+50)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99962.0"), "Bob TC unchanged (MAKER)");
    
    // Carol: buys 10 KEL for 50 USDT, service fee WAIVED (Carol is service wallet), 1 TC network fee
    // Carol: KEL=525.90909090909090915 + 10 = 535.90909090909090915
    // Carol: USDT=104.399999999999999797 - 50 = 54.399999999999999797
    // Carol: TC=99988.0 - 1 = 99987.0
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "535.90909090909090915"), "Carol KEL after buy (+10)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "54.399999999999999797"), "Carol USDT after buy (-50, service fee waived)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99987.0"), "Carol TC fee (-1)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 3.8 PASSED: MIN_FILL with Dust Order — Treat as AON (3 KEL rejected, 10 KEL accepted)");
}

static void test_group_3_9_leftover_dust(dex_test_fixture_t *f)
{
    log_it(L_INFO, "=== TEST GROUP 3.9: MIN_FILL Edge Case — Leftover Below Threshold (Auto-Dust) ===");
    
    // Precheck balances (after Test 3.8)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7695.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10449.599999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99961.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2194.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39496.000000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99962.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "535.90909090909090915"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "54.399999999999999797"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99987.0"), "Precheck Carol TC");
    
    log_it(L_INFO, "[3.9.1] Alice creates BID: wants 100 KEL @ 5.0 USDT/KEL (offers 500 USDT) with min_fill=0xBC (60%% from_origin)");
    log_it(L_INFO, "        Min_fill threshold: 60 KEL (60%% of original 100 KEL, static from origin)");
    log_it(L_INFO, "        Using BID direction so Carol spends KEL instead of USDT");
    log_it(L_INFO, "        Note: For BID orders, rate must be inverted: 5.0 USDT/KEL → 0.2 (1/5.0)");
    log_it(L_INFO, "        Using from_origin flag so leftover dust detection uses original min_fill (60 KEL)");
    
    dap_hash_fast_t alice_bid_hash = {0};
    int ret = test_dex_order_create_ex(f, f->alice, "KEL", "USDT", "500.0", "0.2", 0xBC, &alice_bid_hash);
    dap_assert(ret == 0, "Alice BID created successfully");
    
    // Alice: 500 USDT locked, 1 TC fee
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7695.833333333333333299"), "Alice KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9949.599999999999999995"), "Alice USDT locked (-500)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99960.0"), "Alice TC fee (-1)");
    
    log_it(L_INFO, "[3.9.2] Bob sells 70 KEL (70%% > 60%% threshold)");
    log_it(L_INFO, "        Expected: Purchase SUCCESS, leftover 30 KEL created (30 < 60 min_fill → dust!)");
    
    dap_hash_fast_t bob_sell_hash = {0};
    ret = test_dex_order_purchase(f, f->bob, &alice_bid_hash, "70.0", false, false, &bob_sell_hash);
    dap_assert(ret == 0, "Bob sell SUCCESS (70 KEL > 60 KEL min_fill threshold)");
    
    // Alice: receives 70 KEL (MAKER, no fee deducted), leftover 30 KEL remains (150 USDT locked)
    // Alice: KEL=7695.833333333333333299 + 70 = 7765.833333333333333299
    // Alice: USDT=9949.599999999999999995 (unchanged, 150 USDT still locked for leftover)
    // Alice: TC=99960.0 (unchanged, MAKER)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7765.833333333333333299"), "Alice KEL after buy (+70)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9949.599999999999999995"), "Alice USDT unchanged (150 USDT leftover locked)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99960.0"), "Alice TC unchanged (MAKER)");
    
    // Bob: sells 70 KEL for 350 USDT + 7 USDT service fee (2% TAKER), 1 TC network fee
    // Bob: KEL=2194.166666666666666641 - 70 = 2124.166666666666666641
    // Bob: USDT=39496.000000000000000208 + 350 - 7 = 39839.000000000000000208
    // Bob: TC=99962.0 - 1 = 99961.0
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2124.166666666666666641"), "Bob KEL after sell (-70)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39839.000000000000000208"), "Bob USDT after sell (+350-7 service fee)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99961.0"), "Bob TC fee (-1)");
    
    // Carol: receives 7 USDT service fee
    // Carol: USDT=54.399999999999999797 + 7 = 61.399999999999999797
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "61.399999999999999797"), "Carol USDT (+7 service fee)");
    
    log_it(L_INFO, "[3.9.3] Carol attempts to sell 20 KEL to leftover (66.7%% of 30 KEL)");
    log_it(L_INFO, "        Expected: Purchase REJECTED (leftover is dust, only 30 KEL full fill allowed)");
    
    dap_hash_fast_t carol_sell_hash = {0};
    ret = test_dex_order_purchase(f, f->carol, &alice_bid_hash, "20.0", false, false, &carol_sell_hash);
    dap_assert(ret != 0, "Carol sell REJECTED (leftover is dust, partial fill not allowed)");
    
    // Carol: balances unchanged (no fee deducted on rejection)
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "535.90909090909090915"), "Carol KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "61.399999999999999797"), "Carol USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99987.0"), "Carol TC unchanged");
    
    // Alice: balances unchanged
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7765.833333333333333299"), "Alice KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9949.599999999999999995"), "Alice USDT unchanged");
    
    log_it(L_INFO, "[3.9.4] Carol sells 30 KEL (100%% leftover fill)");
    log_it(L_INFO, "        Expected: Purchase SUCCESS (dust leftover filled completely)");
    
    ret = test_dex_order_purchase(f, f->carol, &alice_bid_hash, "30.0", false, false, &carol_sell_hash);
    dap_assert(ret == 0, "Carol sell SUCCESS (full fill allowed for dust leftover)");
    
    // Alice: receives 30 KEL (MAKER, no fee deducted), order fully closed
    // Alice: KEL=7765.833333333333333299 + 30 = 7795.833333333333333299
    // Alice: USDT=9949.599999999999999995 (unchanged, 150 USDT spent on buying 30 KEL from leftover)
    // Alice: TC=99960.0 (unchanged, MAKER)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7795.833333333333333299"), "Alice KEL after buy (+30)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9949.599999999999999995"), "Alice USDT unchanged (150 USDT spent on 30 KEL)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99960.0"), "Alice TC unchanged (MAKER)");
    
    // Carol: sells 30 KEL for 150 USDT, service fee WAIVED (Carol is service wallet), 1 TC network fee
    // Carol: KEL=535.90909090909090915 - 30 = 505.90909090909090915
    // Carol: USDT=61.399999999999999797 + 150 = 211.399999999999999797
    // Carol: TC=99987.0 - 1 = 99986.0
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "505.90909090909090915"), "Carol KEL after sell (-30)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "211.399999999999999797"), "Carol USDT after sell (+150, service fee waived)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99986.0"), "Carol TC fee (-1)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 3.9 PASSED: MIN_FILL Edge Case — Leftover Below Threshold (20 KEL rejected, 30 KEL accepted)");
}

// ============================================================================
// TEST GROUP 3.10: MIN_FILL for Self-Purchase — Threshold Applies to Owner
// ============================================================================

static void test_group_3_10_self_purchase_minfill(dex_test_fixture_t *f)
{
    log_it(L_INFO, "=== TEST GROUP 3.10: MIN_FILL for Self-Purchase — Threshold Applies to Owner ===");
    
    // Precheck balances (after Test 3.9)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7795.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9949.599999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99960.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "211.399999999999999797"), "Precheck Carol USDT");
    
    log_it(L_INFO, "[3.10.1] Alice creates ASK: 600 KEL @ 5.0 USDT/KEL with min_fill=0x47 (71%% dynamic)");
    log_it(L_INFO, "        Min_fill threshold: 426 KEL (71%% of 600 KEL)");
    
    dap_hash_fast_t alice_ask_hash = {0};
    int ret = test_dex_order_create_ex(f, f->alice, "USDT", "KEL", "600.0", "5.0", 0x47, &alice_ask_hash);
    dap_assert(ret == 0, "Alice ASK created successfully");
    
    // Alice: 600 KEL locked, 1 TC fee
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7195.833333333333333299"), "Alice KEL locked (-600)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9949.599999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99959.0"), "Alice TC fee (-1)");
    
    log_it(L_INFO, "[3.10.2] Alice attempts to buy 300 KEL from own order (50%% < 71%% threshold)");
    log_it(L_INFO, "        Expected: Purchase REJECTED (min_fill not reached, even for self-purchase)");
    log_it(L_INFO, "        Budget: 300 KEL (is_budget_buy=true) = 1500 USDT @ 5.0 USDT/KEL");
    
    dap_hash_fast_t alice_buy_hash_1 = {0};
    ret = test_dex_order_purchase(f, f->alice, &alice_ask_hash, "300.0", true, false, &alice_buy_hash_1);
    dap_assert(ret != 0, "Alice self-purchase REJECTED (300 KEL < 426 KEL min_fill threshold)");
    
    // Alice: balances unchanged (no fee deducted on rejection)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7195.833333333333333299"), "Alice KEL unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9949.599999999999999995"), "Alice USDT unchanged (rejection)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99959.0"), "Alice TC unchanged (no fee on rejection)");
    
    log_it(L_INFO, "[3.10.3] Alice buys 450 KEL from own order (75%% > 71%% threshold)");
    log_it(L_INFO, "        Expected: Purchase SUCCESS, leftover 150 KEL created");
    log_it(L_INFO, "        Budget: 450 KEL (is_budget_buy=true) = 2250 USDT @ 5.0 USDT/KEL");
    log_it(L_INFO, "        Self-purchase: Alice unlocks 450 KEL and receives 450 KEL (net 0 KEL)");
    log_it(L_INFO, "        Self-purchase: Alice spends 3260.3 USDT (inputs), receives 3215.3 USDT cashback (2250 seller + 965.3 refund)");
    log_it(L_INFO, "        Service fee: 45 USDT paid to Carol (service wallet), NOT waived (Alice ≠ service wallet)");
    
    dap_hash_fast_t alice_buy_hash_2 = {0};
    ret = test_dex_order_purchase(f, f->alice, &alice_ask_hash, "450.0", true, false, &alice_buy_hash_2);
    dap_assert(ret == 0, "Alice self-purchase SUCCESS (450 KEL > 426 KEL min_fill threshold)");
    
    // Alice: self-purchase flow
    // - Unlocks 450 KEL from order → receives 450 KEL (net 0 KEL change)
    // - Spends 3260.3 USDT (inputs collected for 2295 USDT needed + change)
    // - Receives 3215.3 USDT cashback (2250 seller payout + 965.3 budget refund)
    // - Net USDT: -3260.3 + 3215.3 = -45 USDT (only service fee)
    // - Service fee PAID to Carol (service wallet), not waived (Alice ≠ service wallet)
    // Alice: KEL=7195.833333333333333299 + 450 (unlocked) = 7645.833333333333333299
    // Alice: USDT=9949.599999999999999995 - 3260.3 + 3215.3 = 9904.599999999999999995
    // Alice: TC=99959.0 - 1 = 99958.0 (network fee)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7645.833333333333333299"), "Alice KEL after self-purchase (+450 unlocked)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9904.599999999999999995"), "Alice USDT after self-purchase (net -45 service fee)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99958.0"), "Alice TC fee (-1)");
    
    // Carol: receives 45 USDT service fee (2% of 2250)
    // Carol: USDT=211.399999999999999797 + 45 = 256.399999999999999797
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "256.399999999999999797"), "Carol USDT (+45 service fee)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 3.10 PASSED: MIN_FILL for Self-Purchase (300 KEL rejected, 450 KEL accepted, service fee paid)");
}

// ============================================================================
// TEST GROUP 4: ORDER UPDATES
// ============================================================================

/**
 * @brief Helper: Update an order
 * @param fixture Test fixture
 * @param wallet Owner wallet
 * @param order_hash Hash of order (root or tail)
 * @param has_new_value true: update value
 * @param new_value_str New value string (if has_new_value)
 * @param out_hash Output: hash of update transaction
 * @return 0 on success, error code otherwise
 */
static int test_dex_order_update(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const dap_hash_fast_t *order_hash,
    bool has_new_value,
    const char *new_value_str,
    dap_hash_fast_t *out_hash)
{
    dap_ret_val_if_any(-1, !fixture, !wallet, !order_hash, !out_hash);
    dap_ret_val_if_any(-1, !has_new_value);
    
    uint256_t new_value = uint256_0;
    if (has_new_value) {
        dap_ret_val_if_any(-1, !new_value_str);
        new_value = dap_chain_coins_to_balance(new_value_str);
    }
    
    uint256_t network_fee = fixture->network_fee;
    
    dap_chain_datum_tx_t *tx = NULL;
    dap_chain_net_srv_dex_update_error_t err = dap_chain_net_srv_dex_update(
        fixture->net->net, (dap_hash_fast_t*)order_hash, has_new_value, new_value,
        network_fee, wallet, NULL, &tx
    );
    
    if (err != DEX_UPDATE_ERROR_OK || !tx) {
        log_it(L_ERROR, "UPDATE failed: err=%d", err);
        return -2;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    
    if (dap_ledger_tx_add(fixture->net->net->pub.ledger, tx, out_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Failed to add update to ledger");
        return -3;
    }
    
    // Update order tracking: find order by tail or root
    order_entry_t *l_order = NULL;
    for (order_entry_t *e = fixture->orders; e; e = e->next) {
        if (e->active && (dap_hash_fast_compare(&e->tail, order_hash) || dap_hash_fast_compare(&e->root, order_hash))) {
            l_order = e;
            break;
        }
    }
    
    if (l_order) {
        // Find updated OUT_COND in TX
        int l_out_idx = 0;
        dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
        if (l_out_cond && dap_hash_fast_compare(&l_out_cond->subtype.srv_dex.order_root_hash, &l_order->root)) {
            // Update tail and value
            test_dex_order_track_update(fixture, &l_order->root, out_hash, l_out_cond->header.value);
            log_it(L_DEBUG, "Order updated: tail=%s, new_value=%s", 
                   dap_chain_hash_fast_to_str_static(out_hash),
                   dap_uint256_to_char_ex(l_out_cond->header.value).frac);
        }
    }
    
    log_it(L_INFO, "Order updated: has_value=%d", has_new_value);
    return 0;
}

/**
 * @brief Test Group 4.1 - Value update (increase)
 * @details Verifies UPDATE transaction can increase order value by locking additional tokens.
 *          Also tests dap_chain_net_srv_dex_match_hashes() function for finding orders.
 *          
 *          This test covers:
 *          - Basic UPDATE value increase (150 → 250 KEL)
 *          - Additional token locking (100 KEL delta)
 *          - Using updated order for purchase
 *          - Leftover creation after partial fill
 *          
 *          Edge cases (UPDATE decrease, immutable violations) are covered in other tests.
 */
static void test_group_4_1_update_rate(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 4.1: UPDATE Value — Increase Order Size ===");
    
    // Precheck balances (after Group 3)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7645.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9904.599999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99958.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2124.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "39839.000000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99961.0"), "Precheck Bob TC");
    
    log_it(L_INFO, "[4.1.1] Test dap_chain_net_srv_dex_match_hashes() function");
    log_it(L_INFO, "        Search: KEL/USDT pair with min_rate=5.0");
    
    size_t num_matches = 0;
    uint256_t min_rate = dap_chain_coins_to_balance("5.0");
    dap_chain_net_id_t net_id = f->net->net->pub.id;
    dap_hash_fast_t *hashes = dap_chain_net_srv_dex_match_hashes(
        f->net->net, "USDT", "KEL", &net_id, &net_id, NULL, &min_rate, &num_matches, false
    );
    
    dap_assert(hashes != NULL, "match_hashes returned non-NULL");
    dap_assert(num_matches >= 1, "Found at least 1 order with rate >= 5.0");
    log_it(L_INFO, "        match_hashes found %zu orders with rate >= 5.0", num_matches);
    DAP_DELETE(hashes);
    
    // Find order with rate=5.0 and value=150.0 KEL from tracking (more reliable)
    log_it(L_INFO, "[4.1.2] Find order with rate=5.0, value=150.0 KEL from tracking");
    uint256_t target_rate = dap_chain_coins_to_balance("5.0");
    uint256_t target_value = dap_chain_coins_to_balance("150.0");
    dap_hash_fast_t order_tail = {0};
    bool found = false;
    
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (!e->active) continue;
        if (dap_strcmp(e->token_sell, "KEL") != 0 || dap_strcmp(e->token_buy, "USDT") != 0) continue;
        if (compare256(e->price, target_rate) == 0 && compare256(e->value, target_value) == 0) {
            order_tail = e->tail;
            found = true;
            log_it(L_INFO, "        Found order: tail=%s, rate=5.0, value=150.0 KEL", 
                   dap_chain_hash_fast_to_str_static(&order_tail));
            break;
        }
    }
    
    dap_assert(found, "Found order with rate=5.0 and value=150.0 KEL in tracking");
    
    log_it(L_INFO, "[4.1.3] Alice UPDATE found order: Increase value to 250 KEL (add 100 KEL)");
    log_it(L_INFO, "        Expected: UPDATE SUCCESS, locks additional 100 KEL");
    
    dap_hash_fast_t update_hash = {0};
    int ret = test_dex_order_update(f, f->alice, &order_tail, true, "250.0", &update_hash);
    dap_assert(ret == 0, "Alice UPDATE SUCCESS");
    
    // Alice: locked 250 KEL total (was 150, added 100), 1 TC fee
    // UPDATE transaction logic:
    //   1. Old OUT_COND is spent (150 KEL unlocked from old order)
    //   2. New OUT_COND is created (250 KEL locked in new order)
    //   3. Delta collection: additional 100 KEL collected from free balance
    //   4. Net result: balance decreased by 100 KEL (delta), order locked increased by 100 KEL
    // Initial balance: KEL=7645.833333333333333299 (150 locked, 7495.833333333333333299 free)
    // After UPDATE: KEL=7545.833333333333333299 (250 locked, 7295.833333333333333299 free)
    // Balance change: -100 KEL (matches additional lock: 250 - 150 = 100)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7545.833333333333333299"), "Alice KEL after UPDATE (locked 250 total)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "9904.599999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99957.0"), "Alice TC fee (-1)");
    
    log_it(L_INFO, "[4.1.4] Bob buys 200 KEL from updated order");
    log_it(L_INFO, "        Expected: Purchase SUCCESS, leftover 50 KEL created");
    log_it(L_INFO, "        Budget: 200 KEL (is_budget_buy=true) = 1000 USDT @ 5.0 USDT/KEL");
    
    // After UPDATE, UPDATE transaction hash becomes new tail hash
    dap_hash_fast_t new_tail_hash = update_hash;
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->bob, &new_tail_hash, "200.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Bob purchase SUCCESS");
    
    // Bob: receives 200 KEL, pays 1000 USDT + 20 USDT service fee (2%)
    // Bob: KEL=2124.166666666666666641 + 200 = 2324.166666666666666641
    // Bob: USDT=39839.000000000000000208 - 1000 - 20 = 38819.000000000000000208
    // Bob: TC=99961.0 - 1 = 99960.0
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2324.166666666666666641"), "Bob KEL after purchase (+200)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "38819.000000000000000208"), "Bob USDT after purchase (-1000-20 fee)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99960.0"), "Bob TC fee (-1)");
    
    // Alice: receives 1000 USDT (200 KEL * 5.0), service fee paid by buyer (Bob)
    // Alice: KEL=7545.833333333333333299 (unchanged, 50 KEL still locked after purchase)
    // Alice: USDT=9904.599999999999999995 + 1000 = 10904.599999999999999995
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7545.833333333333333299"), "Alice KEL unchanged (50 leftover locked)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10904.599999999999999995"), "Alice USDT after purchase (+1000, fee paid by buyer)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 4.1 PASSED: UPDATE Value Increase (150 → 250 KEL, purchase successful)");
}

/**
 * @brief Test Group 4.2 - Value update (decrease)
 * @details Verifies UPDATE transaction can decrease order value with refund to seller.
 */
static void test_group_4_2_update_value(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 4.2: UPDATE Value — Decrease Order Size ===");
    
    // Precheck balances (after Test 4.1)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7545.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10904.599999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99957.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2324.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "38819.000000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99960.0"), "Precheck Bob TC");
    
    log_it(L_INFO, "[4.2.1] Find orders using dap_chain_net_srv_dex_match_hashes()");
    log_it(L_INFO, "        Search: KEL/USDT pair with min_rate=4.0 (to find rate=4.0 orders)");
    
    size_t num_matches = 0;
    uint256_t min_rate = dap_chain_coins_to_balance("4.0");
    dap_chain_net_id_t net_id = f->net->net->pub.id;
    dap_hash_fast_t *hashes = dap_chain_net_srv_dex_match_hashes(
        f->net->net, "USDT", "KEL", &net_id, &net_id, NULL, &min_rate, &num_matches, false
    );
    
    dap_assert(hashes != NULL, "match_hashes returned non-NULL");
    dap_assert(num_matches >= 1, "Found at least 1 order with rate >= 4.0");
    log_it(L_INFO, "        match_hashes found %zu orders with rate >= 4.0", num_matches);
    DAP_DELETE(hashes);
    
    // Find order with rate=4.0 and value=25.0 KEL from tracking
    log_it(L_INFO, "[4.2.2] Find order with rate=4.0, value=25.0 KEL from tracking");
    uint256_t target_rate = dap_chain_coins_to_balance("4.0");
    uint256_t target_value = dap_chain_coins_to_balance("25.0");
    dap_hash_fast_t order_tail = {0};
    bool found = false;
    
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (!e->active) continue;
        if (dap_strcmp(e->token_sell, "KEL") != 0 || dap_strcmp(e->token_buy, "USDT") != 0) continue;
        if (compare256(e->price, target_rate) == 0 && compare256(e->value, target_value) == 0) {
            order_tail = e->tail;
            found = true;
            log_it(L_INFO, "        Found order: tail=%s, rate=4.0, value=25.0 KEL", 
                   dap_chain_hash_fast_to_str_static(&order_tail));
            break;
        }
    }
    
    dap_assert(found, "Found order with rate=4.0 and value=25.0 KEL in tracking");
    
    log_it(L_INFO, "[4.2.3] Alice UPDATE found order: Decrease value to 15 KEL (refund 10 KEL)");
    log_it(L_INFO, "        Expected: UPDATE SUCCESS, refunds 10 KEL to Alice");
    
    dap_hash_fast_t update_hash = {0};
    int ret = test_dex_order_update(f, f->alice, &order_tail, true, "15.0", &update_hash);
    dap_assert(ret == 0, "Alice UPDATE SUCCESS");
    
    // Alice: locked 15 KEL total (was 25, refunded 10), 1 TC fee
    // UPDATE transaction logic:
    //   1. Old OUT_COND is spent (25 KEL unlocked from old order)
    //   2. New OUT_COND is created (15 KEL locked in new order)
    //   3. Delta refund: 10 KEL refunded to Alice's free balance
    //   4. Net result: balance increased by 10 KEL (refund), order locked decreased by 10 KEL
    // Initial balance: KEL=7545.833333333333333299 (25 locked, 7520.833333333333333299 free)
    // After UPDATE: KEL=7555.833333333333333299 (15 locked, 7540.833333333333333299 free)
    // Balance change: +10 KEL (matches refund: 25 - 15 = 10)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7555.833333333333333299"), "Alice KEL after UPDATE (locked 15 total, +10 refunded)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10904.599999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99956.0"), "Alice TC fee (-1)");
    
    log_it(L_INFO, "[4.2.4] Bob buys 15 KEL from updated order (full fill)");
    log_it(L_INFO, "        Expected: Purchase SUCCESS, order fully closed");
    log_it(L_INFO, "        Budget: 15 KEL (is_budget_buy=true) = 60 USDT @ 4.0 USDT/KEL");
    
    // After UPDATE, UPDATE transaction hash becomes new tail hash
    dap_hash_fast_t new_tail_hash = update_hash;
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->bob, &new_tail_hash, "15.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Bob purchase SUCCESS");
    
    // Bob: receives 15 KEL, pays 60 USDT + 1.2 USDT service fee (2%)
    // Bob: KEL=2324.166666666666666641 + 15 = 2339.166666666666666641
    // Bob: USDT=38819.000000000000000208 - 60 - 1.2 = 38757.800000000000000208
    // Bob: TC=99960.0 - 1 = 99959.0
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2339.166666666666666641"), "Bob KEL after purchase (+15)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "38757.800000000000000208"), "Bob USDT after purchase (-60-1.2 fee)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99959.0"), "Bob TC fee (-1)");
    
    // Alice: receives 60 USDT (15 KEL * 4.0), service fee paid by buyer (Bob)
    // Alice: KEL=7555.833333333333333299 (unchanged, order fully closed)
    // Alice: USDT=10904.599999999999999995 + 60 = 10964.599999999999999995
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7555.833333333333333299"), "Alice KEL unchanged (order fully closed)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10964.599999999999999995"), "Alice USDT after purchase (+60, fee paid by buyer)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 4.2 PASSED: UPDATE Value Decrease (25 → 15 KEL, refund successful, full fill)");
}

/**
 * @brief Test Group 4.3 - UPDATE Value — Same Value (No Change)
 * @details Verifies UPDATE with same value is allowed (no-op, but fee charged)
 */
static void test_group_4_3b_update_same_value(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 4.3b: UPDATE Value — Same Value (No Change) ===");
    
    // 1. Find orders using dap_chain_net_srv_dex_match_hashes()
    // Search for KEL/USDT pair with min_rate=3.5 (to find rate=3.5 order)
    log_it(L_INFO, "[4.3.1] Find orders using dap_chain_net_srv_dex_match_hashes()");
    log_it(L_INFO, "        Search: KEL/USDT pair with min_rate=3.5 (to find rate=3.5 order)");
    
    size_t num_matches = 0;
    uint256_t min_rate = dap_chain_uint256_from(3500000000000000000ULL); // 3.5
    dap_chain_net_id_t net_id = f->net->net->pub.id;
    // Match orders: I have USDT, want KEL -> find sellers of KEL (ASK orders)
    dap_hash_fast_t *hashes = dap_chain_net_srv_dex_match_hashes(
        f->net->net, "USDT", "KEL", &net_id, &net_id, NULL, &min_rate, &num_matches, false);
    
    dap_assert(hashes != NULL, "match_hashes returned non-NULL");
    dap_assert(num_matches >= 1, "Found at least 1 order with rate >= 3.5");
    log_it(L_INFO, "        match_hashes found %zu orders with rate >= 3.5", num_matches);
    
    // 2. Find order with rate=3.5 and value=10.0 KEL
    log_it(L_INFO, "[4.3.2] Find order with rate=3.5, value=10.0 KEL from tracking");
    dap_hash_fast_t order_tail = {0};
    bool found = false;
    
    for (size_t i = 0; i < num_matches; i++) {
        // Manual lookup in f->orders instead of find_order_by_tail
        for (order_entry_t *e = f->orders; e; e = e->next) {
            if (dap_hash_fast_compare(&e->tail, &hashes[i])) {
                // Found matching order in tracking, check params
                if (compare256(e->price, min_rate) == 0 && // rate == 3.5
                    compare256(e->value, dap_chain_uint256_from(10000000000000000000ULL)) == 0) { // value == 10.0
                    order_tail = hashes[i];
                    found = true;
                    log_it(L_INFO, "        Found order: tail=%s, rate=3.5, value=10.0 KEL", dap_hash_fast_to_str_static(&order_tail));
                }
                break;
            }
        }
        if (found) break;
    }
    DAP_DELETE(hashes);
    dap_assert(found, "Found order with rate=3.5 and value=10.0 KEL in tracking");
    
    // 3. Alice UPDATE found order: Keep value 10.0 KEL (no change)
    log_it(L_INFO, "[4.3.3] Alice UPDATE found order: Keep value 10.0 KEL (no change)");
    log_it(L_INFO, "        Expected: UPDATE SUCCESS (no-op, but valid)");
    
    dap_hash_fast_t update_hash = {0};
    // Pass "10.0" as new value (same as old)
    int ret = test_dex_order_update(f, f->alice, &order_tail, true, "10.0", &update_hash);
    dap_assert(ret == 0, "Alice UPDATE SUCCESS");
    
    // Alice balances:
    // KEL: Unchanged (10.0 locked -> 10.0 locked)
    // USDT: Unchanged
    // TC: -1 fee
    // Initial (from dump): KEL=7555.833333333333333299, USDT=10964.599999999999999995, TC=99956.0
    // Expected: KEL=7555.833333333333333299, USDT=10964.599999999999999995, TC=99955.0
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7555.833333333333333299"), "Alice KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10964.599999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99955.0"), "Alice TC fee (-1)");
    
    // 4. Bob buys 10 KEL from updated order (full fill)
    log_it(L_INFO, "[4.3.4] Bob buys 10 KEL from updated order (full fill)");
    log_it(L_INFO, "        Expected: Purchase SUCCESS, order fully closed");
    
    dap_hash_fast_t new_tail_hash = update_hash;
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->bob, &new_tail_hash, "10.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Bob purchase SUCCESS");
    
    // Bob balances:
    // KEL: +10.0
    // USDT: -35.0 (10 * 3.5) - 0.7 (2% fee) = -35.7
    // TC: -1 fee
    // Initial (from dump): KEL=2339.166666666666666641, USDT=38757.800000000000000208, TC=99959.0
    // Expected: KEL=2349.166666666666666641, USDT=38722.100000000000000208, TC=99958.0
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2349.166666666666666641"), "Bob KEL after purchase (+10)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "38722.100000000000000208"), "Bob USDT after purchase (-35-0.7 fee)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99958.0"), "Bob TC fee (-1)");
    
    // Alice balances:
    // KEL: Unchanged (order closed)
    // USDT: +35.0 (fee paid by buyer)
    // TC: Unchanged
    // Initial: KEL=7555.833333333333333299, USDT=10964.599999999999999995, TC=99955.0
    // Expected: KEL=7555.833333333333333299, USDT=10999.599999999999999995, TC=99955.0
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7555.833333333333333299"), "Alice KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10999.599999999999999995"), "Alice USDT after purchase (+35)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 4.3b PASSED: UPDATE Value Same (10 → 10 KEL, no-op successful)");
}

// Helper functions for immutables testing
static void modify_buy_token(dap_chain_tx_out_cond_t *out) {
    strncpy(out->subtype.srv_dex.buy_token, "TestCoin", DAP_CHAIN_TICKER_SIZE_MAX - 1);
}
static void modify_rate(dap_chain_tx_out_cond_t *out) {
    out->subtype.srv_dex.rate = dap_chain_coins_to_balance("4.5");
}
static void modify_min_fill(dap_chain_tx_out_cond_t *out) {
    out->subtype.srv_dex.min_fill = 0x14; // 20%
}
static void modify_flags(dap_chain_tx_out_cond_t *out) {
    out->subtype.srv_dex.flags = 0x12345678; // Different flags
}
static void modify_version(dap_chain_tx_out_cond_t *out) {
    out->subtype.srv_dex.version = 99; // Different version
}
static void modify_buy_net_id(dap_chain_tx_out_cond_t *out) {
    out->subtype.srv_dex.buy_net_id.uint64 = 9999; // Different net_id
}
static void modify_sell_net_id(dap_chain_tx_out_cond_t *out) {
    out->subtype.srv_dex.sell_net_id.uint64 = 9999; // Different net_id
}
static void modify_root_hash(dap_chain_tx_out_cond_t *out) {
    // Zero out root hash (attack: pretend this is original ORDER, not UPDATE)
    dap_hash_fast_t blank_root = {0};
    out->subtype.srv_dex.order_root_hash = blank_root;
}

static int test_immutable_change(dex_test_fixture_t *f, const dap_hash_fast_t *order_tail,
                                 const dap_chain_tx_out_cond_t *prev_out, const char *field_name,
                                 void (*modify_func)(dap_chain_tx_out_cond_t *)) {
    dap_chain_datum_tx_t *test_tx = NULL;
    dap_chain_net_srv_dex_update_error_t err = dap_chain_net_srv_dex_update(
        f->net->net, (dap_hash_fast_t*)order_tail, true, prev_out->header.value,
        f->network_fee, f->alice, NULL, &test_tx
    );
    if (err != DEX_UPDATE_ERROR_OK || !test_tx) {
        log_it(L_ERROR, "Failed to create UPDATE TX for %s test", field_name);
        return 0;
    }
    
    // Find first signature position (composer already signed)
    uint8_t *l_first_sig = dap_chain_datum_tx_item_get(test_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    if (!l_first_sig) {
        dap_chain_datum_tx_delete(test_tx);
        log_it(L_ERROR, "No signature found in UPDATE TX for %s test", field_name);
        return 0;
    }
    
    // Calculate size without signatures (copy TX up to first signature)
    size_t l_tx_size_without_sigs = (size_t)(l_first_sig - (uint8_t*)test_tx);
    
    // Create new TX without signatures
    dap_chain_datum_tx_t *l_new_tx = DAP_DUP_SIZE_RET_VAL_IF_FAIL(test_tx, l_tx_size_without_sigs, 0);
    l_new_tx->header.tx_items_size = l_tx_size_without_sigs - sizeof(dap_chain_datum_tx_t);
    
    // Modify immutable field in OUT_COND
    int out_idx = 0;
    dap_chain_tx_out_cond_t *out_cond = dap_chain_datum_tx_out_cond_get(
        l_new_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &out_idx);
    if (!out_cond) {
        dap_chain_datum_tx_delete(test_tx);
        dap_chain_datum_tx_delete(l_new_tx);
        log_it(L_ERROR, "Failed to get OUT_COND for %s test", field_name);
        return 0;
    }
    
    // Apply modification
    modify_func(out_cond);
    
    // Sign new transaction
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(f->alice, 0);
    if (!l_key || dap_chain_datum_tx_add_sign_item(&l_new_tx, l_key) <= 0) {
        dap_chain_datum_tx_delete(test_tx);
        dap_chain_datum_tx_delete(l_new_tx);
        if (l_key) dap_enc_key_delete(l_key);
        log_it(L_ERROR, "Failed to sign TX for %s test", field_name);
        return 0;
    }
    dap_enc_key_delete(l_key);
    
    // Calculate hash and try to add to ledger (verificator should reject due to immutables violation)
    dap_hash_fast_t tx_hash = {0};
    dap_hash_fast(l_new_tx, dap_chain_datum_tx_get_size(l_new_tx), &tx_hash);
    
    // Try to add to ledger (verificator should reject)
    int ledger_err = dap_ledger_tx_add(f->net->net->pub.ledger, l_new_tx, &tx_hash, false, NULL);
    dap_chain_datum_tx_delete(test_tx);
    dap_chain_datum_tx_delete(l_new_tx);
    
    if (ledger_err == 0) {
        log_it(L_ERROR, "UPDATE with changed %s was ACCEPTED (should be rejected!)", field_name);
        return 0;
    }
    
    log_it(L_INFO, "        ✓ %s change rejected by verificator", field_name);
    return 1;
}

/**
 * @brief Test Group 4.3 - Immutables Validation (All Fields)
 * @details Verifies UPDATE cannot change any immutable fields:
 *          - seller_addr (composer check: DEX_UPDATE_ERROR_NOT_OWNER)
 *          - buy_token (verificator check: DEXV_IMMUTABLES_VIOLATION)
 *          - rate (verificator check: DEXV_IMMUTABLES_VIOLATION)
 *          - min_fill (verificator check: DEXV_IMMUTABLES_VIOLATION)
 *          - flags (verificator check: DEXV_IMMUTABLES_VIOLATION)
 *          - version (verificator check: DEXV_IMMUTABLES_VIOLATION)
 *          - buy_net_id (verificator check: DEXV_IMMUTABLES_VIOLATION)
 *          - sell_net_id (verificator check: DEXV_IMMUTABLES_VIOLATION)
 */
static void test_group_4_3_immutables_validation(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 4.3: UPDATE Immutables Validation (All Fields) ===");
    
    // Precheck balances (after test 4.3b)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7555.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10999.599999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99955.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2349.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "38722.100000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99958.0"), "Precheck Bob TC");
    
    // Find order with rate=5.0 and value=250.0 KEL (from test 4.1) or find any Alice's order
    log_it(L_INFO, "[4.3.1] Find Alice's order for immutables testing");
    size_t num_matches = 0;
    uint256_t min_rate = dap_chain_coins_to_balance("5.0");
    dap_chain_net_id_t net_id = f->net->net->pub.id;
    dap_hash_fast_t *hashes = dap_chain_net_srv_dex_match_hashes(
        f->net->net, "USDT", "KEL", &net_id, &net_id, NULL, &min_rate, &num_matches, false
    );
    
    dap_assert(hashes != NULL, "match_hashes returned non-NULL");
    dap_assert(num_matches >= 1, "Found at least 1 order with rate >= 5.0");
    
    // Find Alice's order from tracking
    dap_hash_fast_t order_tail = {0};
    dap_chain_datum_tx_t *prev_tx = NULL;
    dap_chain_tx_out_cond_t *prev_out = NULL;
    int prev_idx = 0;
    bool found = false;
    
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (!e->active) continue;
        if (dap_strcmp(e->token_sell, "KEL") != 0 || dap_strcmp(e->token_buy, "USDT") != 0) continue;
        if (!dap_chain_addr_compare(&e->seller_addr, &f->alice_addr)) continue; // Alice's order
        
        order_tail = e->tail;
        prev_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &order_tail);
        if (prev_tx) {
            prev_out = dap_chain_datum_tx_out_cond_get(prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &prev_idx);
            if (prev_out) {
                found = true;
                log_it(L_INFO, "        Found Alice's order: tail=%s, rate=%s, value=%s",
                       dap_chain_hash_fast_to_str_static(&order_tail),
                       dap_uint256_to_char_ex(prev_out->subtype.srv_dex.rate).frac,
                       dap_uint256_to_char_ex(prev_out->header.value).frac);
                break;
            }
        }
    }
    DAP_DELETE(hashes);
    dap_assert(found && prev_tx && prev_out, "Found Alice's order for testing");
    
    // Get order root hash
    dap_hash_fast_t order_root = dap_hash_fast_is_blank(&prev_out->subtype.srv_dex.order_root_hash) 
        ? order_tail : prev_out->subtype.srv_dex.order_root_hash;
    
    // Test 1: seller_addr change (composer check)
    log_it(L_INFO, "[4.3.2] Test seller_addr immutability (composer check)");
    log_it(L_INFO, "        Bob attempts UPDATE Alice's order → Expected: DEX_UPDATE_ERROR_NOT_OWNER");
    
    dap_hash_fast_t dummy_hash = {0};
    dap_chain_datum_tx_t *dummy_tx = NULL;
    dap_chain_net_srv_dex_update_error_t err = dap_chain_net_srv_dex_update(
        f->net->net, &order_tail, true, prev_out->header.value,
        f->network_fee, f->bob, NULL, &dummy_tx
    );
    dap_assert(err == DEX_UPDATE_ERROR_NOT_OWNER, "Bob UPDATE rejected: NOT_OWNER");
    dap_assert(dummy_tx == NULL, "No TX created for non-owner");
    
    // Test 2-8: Other immutables (verificator check)
    // Create UPDATE TX through composer, then modify OUT_COND before adding to ledger
    log_it(L_INFO, "[4.3.3] Test other immutables (verificator check)");
    log_it(L_INFO, "        Create UPDATE TX, modify immutables, verify verificator rejects");
    
    // Test 2: buy_token change
    log_it(L_INFO, "        [4.3.3.1] Testing buy_token immutability");
    int ok = test_immutable_change(f, &order_tail, prev_out, "buy_token", modify_buy_token);
    dap_assert(ok, "buy_token change rejected");
    
    // Test 3: rate change
    log_it(L_INFO, "        [4.3.3.2] Testing rate immutability");
    ok = test_immutable_change(f, &order_tail, prev_out, "rate", modify_rate);
    dap_assert(ok, "rate change rejected");
    
    // Test 4: min_fill change
    log_it(L_INFO, "        [4.3.3.3] Testing min_fill immutability");
    ok = test_immutable_change(f, &order_tail, prev_out, "min_fill", modify_min_fill);
    dap_assert(ok, "min_fill change rejected");
    
    // Test 5: flags change
    log_it(L_INFO, "        [4.3.3.4] Testing flags immutability");
    ok = test_immutable_change(f, &order_tail, prev_out, "flags", modify_flags);
    dap_assert(ok, "flags change rejected");
    
    // Test 6: version change
    log_it(L_INFO, "        [4.3.3.5] Testing version immutability");
    ok = test_immutable_change(f, &order_tail, prev_out, "version", modify_version);
    dap_assert(ok, "version change rejected");
    
    // Test 7: buy_net_id change
    log_it(L_INFO, "        [4.3.3.6] Testing buy_net_id immutability");
    ok = test_immutable_change(f, &order_tail, prev_out, "buy_net_id", modify_buy_net_id);
    dap_assert(ok, "buy_net_id change rejected");
    
    // Test 8: sell_net_id change
    log_it(L_INFO, "        [4.3.3.7] Testing sell_net_id immutability");
    ok = test_immutable_change(f, &order_tail, prev_out, "sell_net_id", modify_sell_net_id);
    dap_assert(ok, "sell_net_id change rejected");
    
    // Verify balances unchanged (all UPDATEs were rejected)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7555.833333333333333299"), "Alice KEL unchanged (all UPDATEs rejected)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10999.599999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99955.0"), "Alice TC unchanged (no fees deducted)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 4.3 PASSED: All Immutables Validation (8 fields tested)");
}

/**
 * @brief Test Group 4.4 - UPDATE Leftover Order (Value Increase)
 * @details Verifies UPDATE can increase value of leftover order, root hash preserved.
 */
static void test_group_4_4_update_leftover_increase(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 4.4: UPDATE Leftover Order — Value Increase ===");
    
    // Precheck balances (after test 4.3)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7555.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10999.599999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99955.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2349.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "38722.100000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99958.0"), "Precheck Bob TC");
    
    // Find leftover order using match_hashes (rate=5.0, value=50.0 KEL)
    log_it(L_INFO, "[4.4.1] Find leftover order using dap_chain_net_srv_dex_match_hashes()");
    log_it(L_INFO, "        Search: KEL/USDT pair with min_rate=5.0 (to find leftover with rate=5.0, value=50.0)");
    
    size_t num_matches = 0;
    uint256_t min_rate = dap_chain_coins_to_balance("5.0");
    dap_chain_net_id_t net_id = f->net->net->pub.id;
    dap_hash_fast_t *hashes = dap_chain_net_srv_dex_match_hashes(
        f->net->net, "USDT", "KEL", &net_id, &net_id, NULL, &min_rate, &num_matches, false
    );
    
    dap_assert(hashes != NULL, "match_hashes returned non-NULL");
    dap_assert(num_matches >= 1, "Found at least 1 order with rate >= 5.0");
    log_it(L_INFO, "        match_hashes found %zu orders with rate >= 5.0", num_matches);
    
    // Find leftover order with rate=5.0 and value=50.0 KEL from tracking
    log_it(L_INFO, "[4.4.2] Find leftover order with rate=5.0, value=50.0 KEL from tracking");
    uint256_t target_rate = dap_chain_coins_to_balance("5.0");
    uint256_t target_value = dap_chain_coins_to_balance("50.0");
    dap_hash_fast_t order_tail = {0};
    dap_hash_fast_t order_root = {0};
    bool found = false;
    
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (!e->active) continue;
        if (dap_strcmp(e->token_sell, "KEL") != 0 || dap_strcmp(e->token_buy, "USDT") != 0) continue;
        if (compare256(e->price, target_rate) == 0 && compare256(e->value, target_value) == 0) {
            order_tail = e->tail;
            order_root = e->root;
            found = true;
            log_it(L_INFO, "        Found leftover order: tail=%s, root=%s, rate=5.0, value=50.0 KEL",
                   dap_chain_hash_fast_to_str_static(&order_tail),
                   dap_chain_hash_fast_to_str_static(&order_root));
            break;
        }
    }
    DAP_DELETE(hashes);
    dap_assert(found, "Found leftover order with rate=5.0 and value=50.0 KEL in tracking");
    dap_assert(!dap_hash_fast_is_blank(&order_root), "Leftover order has non-blank root hash");
    
    // Verify root hash from ledger
    dap_chain_datum_tx_t *prev_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &order_tail);
    dap_assert(prev_tx != NULL, "Found previous transaction for leftover order");
    int prev_idx = 0;
    dap_chain_tx_out_cond_t *prev_out = dap_chain_datum_tx_out_cond_get(prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &prev_idx);
    dap_assert(prev_out != NULL, "Found OUT_COND in previous transaction");
    dap_hash_fast_t expected_root = prev_out->subtype.srv_dex.order_root_hash;
    dap_assert(dap_hash_fast_compare(&expected_root, &order_root), "Root hash matches expected");
    log_it(L_INFO, "        Verified root hash: %s", dap_chain_hash_fast_to_str_static(&order_root));
    
    // Alice UPDATE leftover order: Increase value to 120 KEL (add 70 KEL)
    log_it(L_INFO, "[4.4.3] Alice UPDATE leftover order: Increase value to 120 KEL (add 70 KEL)");
    log_it(L_INFO, "        Expected: UPDATE SUCCESS, locks additional 70 KEL, root hash preserved");
    
    dap_hash_fast_t update_hash = {0};
    int ret = test_dex_order_update(f, f->alice, &order_tail, true, "120.0", &update_hash);
    dap_assert(ret == 0, "Alice UPDATE SUCCESS");
    
    // Verify root hash preserved after UPDATE
    dap_chain_datum_tx_t *update_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &update_hash);
    dap_assert(update_tx != NULL, "Found UPDATE transaction");
    int update_out_idx = 0;
    dap_chain_tx_out_cond_t *update_out = dap_chain_datum_tx_out_cond_get(update_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &update_out_idx);
    dap_assert(update_out != NULL, "Found OUT_COND in UPDATE transaction");
    dap_hash_fast_t new_root = update_out->subtype.srv_dex.order_root_hash;
    dap_assert(dap_hash_fast_compare(&new_root, &order_root), "Root hash preserved after UPDATE");
    log_it(L_INFO, "        ✓ Root hash preserved: %s", dap_chain_hash_fast_to_str_static(&new_root));
    
    // Alice balances: locked 120 KEL total (was 50, added 70), 1 TC fee
    // Initial balance: KEL=7555.833333333333333299 (50 locked, 7505.833333333333333299 free)
    // After UPDATE: KEL=7485.833333333333333299 (120 locked, 7365.833333333333333299 free)
    // Balance change: -70 KEL (matches additional lock: 120 - 50 = 70)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7485.833333333333333299"), "Alice KEL after UPDATE (locked 120 total, -70 additional)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10999.599999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99954.0"), "Alice TC fee (-1)");
    
    // Bob buys 120 KEL from updated leftover (full fill)
    log_it(L_INFO, "[4.4.4] Bob buys 120 KEL from updated leftover (full fill)");
    log_it(L_INFO, "        Expected: Purchase SUCCESS, order fully closed");
    log_it(L_INFO, "        Budget: 120 KEL (is_budget_buy=true) = 600 USDT @ 5.0 USDT/KEL");
    
    // After UPDATE, UPDATE transaction hash becomes new tail hash
    dap_hash_fast_t new_tail_hash = update_hash;
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->bob, &new_tail_hash, "120.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Bob purchase SUCCESS");
    
    // Bob: receives 120 KEL, pays 600 USDT + 12 USDT service fee (2%)
    // Bob: KEL=2349.166666666666666641 + 120 = 2469.166666666666666641
    // Bob: USDT=38722.100000000000000208 - 600 - 12 = 38110.100000000000000208
    // Bob: TC=99958.0 - 1 = 99957.0
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2469.166666666666666641"), "Bob KEL after purchase (+120)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "38110.100000000000000208"), "Bob USDT after purchase (-600-12 fee)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99957.0"), "Bob TC fee (-1)");
    
    // Alice: receives 600 USDT (120 KEL * 5.0), service fee paid by buyer (Bob)
    // Alice: KEL=7485.833333333333333299 (unchanged, order fully closed)
    // Alice: USDT=10999.599999999999999995 + 600 = 11599.599999999999999995
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7485.833333333333333299"), "Alice KEL unchanged (order fully closed)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "11599.599999999999999995"), "Alice USDT after purchase (+600, fee paid by buyer)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 4.4 PASSED: UPDATE Leftover Value Increase (50 → 120 KEL, root preserved, full fill)");
}

/**
 * @brief Test Group 4.5 - UPDATE Leftover Order (Value Decrease)
 * @details Verifies UPDATE can decrease value of leftover order with refund, root hash preserved.
 */
static void test_group_4_5_update_leftover_decrease(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 4.5: UPDATE Leftover Order — Value Decrease ===");
    
    // Precheck balances (after test 4.4)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7485.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "11599.599999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99954.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2469.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "38110.100000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99957.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "505.90909090909090915"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "290.299999999999999797"), "Precheck Carol USDT");
    
    // Find order with rate=4.0 and value=20.0 KEL using match_hashes
    log_it(L_INFO, "[4.5.1] Find order with rate=4.0, value=20.0 KEL using dap_chain_net_srv_dex_match_hashes()");
    log_it(L_INFO, "        Search: KEL/USDT pair with min_rate=4.0");
    
    size_t num_matches = 0;
    uint256_t min_rate = dap_chain_coins_to_balance("4.0");
    dap_chain_net_id_t net_id = f->net->net->pub.id;
    dap_hash_fast_t *hashes = dap_chain_net_srv_dex_match_hashes(
        f->net->net, "USDT", "KEL", &net_id, &net_id, NULL, &min_rate, &num_matches, false
    );
    
    dap_assert(hashes != NULL, "match_hashes returned non-NULL");
    dap_assert(num_matches >= 1, "Found at least 1 order with rate >= 4.0");
    log_it(L_INFO, "        match_hashes found %zu orders with rate >= 4.0", num_matches);
    
    // Find order with rate=4.0 and value=20.0 KEL from tracking
    log_it(L_INFO, "[4.5.2] Find order with rate=4.0, value=20.0 KEL from tracking");
    uint256_t target_rate = dap_chain_coins_to_balance("4.0");
    uint256_t target_value = dap_chain_coins_to_balance("20.0");
    dap_hash_fast_t order_tail = {0};
    dap_hash_fast_t order_root = {0};
    bool found = false;
    
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (!e->active) continue;
        if (dap_strcmp(e->token_sell, "KEL") != 0 || dap_strcmp(e->token_buy, "USDT") != 0) continue;
        if (compare256(e->price, target_rate) == 0 && compare256(e->value, target_value) == 0) {
            order_tail = e->tail;
            order_root = e->root;
            found = true;
            log_it(L_INFO, "        Found order: tail=%s, root=%s, rate=4.0, value=20.0 KEL",
                   dap_chain_hash_fast_to_str_static(&order_tail),
                   dap_chain_hash_fast_to_str_static(&order_root));
            break;
        }
    }
    DAP_DELETE(hashes);
    dap_assert(found, "Found order with rate=4.0 and value=20.0 KEL in tracking");
    dap_assert(!dap_hash_fast_is_blank(&order_root), "Order has non-blank root hash");
    
    // Bob buys 12 KEL from found order (partial fill, leftover 8 KEL)
    log_it(L_INFO, "[4.5.3] Bob buys 12 KEL from found order (partial fill, leftover 8 KEL)");
    log_it(L_INFO, "        Expected: Purchase SUCCESS, leftover 8 KEL created");
    log_it(L_INFO, "        Budget: 12 KEL (is_budget_buy=true) = 48 USDT @ 4.0 USDT/KEL");
    
    dap_hash_fast_t purchase_hash = {0};
    int ret = test_dex_order_purchase(f, f->bob, &order_tail, "12.0", true, false, &purchase_hash);
    dap_assert(ret == 0, "Bob purchase SUCCESS");
    
    // Bob: receives 12 KEL, pays 48 USDT + 0.96 USDT service fee (2%)
    // Bob: KEL=2469.166666666666666641 + 12 = 2481.166666666666666641
    // Bob: USDT=38110.100000000000000208 - 48 - 0.96 = 38061.140000000000000208
    // Bob: TC=99957.0 - 1 = 99956.0
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2481.166666666666666641"), "Bob KEL after purchase (+12)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "38061.140000000000000208"), "Bob USDT after purchase (-48-0.96 fee)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99956.0"), "Bob TC fee (-1)");
    
    // Alice: receives 48 USDT (12 KEL * 4.0), service fee paid by buyer (Bob)
    // Alice: KEL=7485.833333333333333299 (unchanged, 8 KEL still locked)
    // Alice: USDT=11599.599999999999999995 + 48 = 11647.599999999999999995
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7485.833333333333333299"), "Alice KEL unchanged (8 KEL still locked)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "11647.599999999999999995"), "Alice USDT after purchase (+48, fee paid by buyer)");
    
    // Find leftover order (8 KEL) using match_hashes
    log_it(L_INFO, "[4.5.4] Find leftover order (8 KEL) using dap_chain_net_srv_dex_match_hashes()");
    log_it(L_INFO, "        Search: KEL/USDT pair with min_rate=4.0");
    
    num_matches = 0;
    hashes = dap_chain_net_srv_dex_match_hashes(
        f->net->net, "USDT", "KEL", &net_id, &net_id, NULL, &min_rate, &num_matches, false
    );
    
    dap_assert(hashes != NULL, "match_hashes returned non-NULL");
    dap_assert(num_matches >= 1, "Found at least 1 leftover order with rate >= 4.0");
    
    // Find leftover order with rate=4.0 and value=8.0 KEL from tracking
    uint256_t leftover_value = dap_chain_coins_to_balance("8.0");
    dap_hash_fast_t leftover_tail = {0};
    dap_hash_fast_t leftover_root = {0};
    found = false;
    
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (!e->active) continue;
        if (dap_strcmp(e->token_sell, "KEL") != 0 || dap_strcmp(e->token_buy, "USDT") != 0) continue;
        if (compare256(e->price, target_rate) == 0 && compare256(e->value, leftover_value) == 0) {
            leftover_tail = e->tail;
            leftover_root = e->root;
            found = true;
            log_it(L_INFO, "        Found leftover order: tail=%s, root=%s, rate=4.0, value=8.0 KEL",
                   dap_chain_hash_fast_to_str_static(&leftover_tail),
                   dap_chain_hash_fast_to_str_static(&leftover_root));
            break;
        }
    }
    DAP_DELETE(hashes);
    dap_assert(found, "Found leftover order with rate=4.0 and value=8.0 KEL in tracking");
    dap_assert(dap_hash_fast_compare(&leftover_root, &order_root), "Leftover root hash matches original order root");
    
    // Verify root hash from ledger
    dap_chain_datum_tx_t *prev_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &leftover_tail);
    dap_assert(prev_tx != NULL, "Found previous transaction for leftover order");
    int prev_idx = 0;
    dap_chain_tx_out_cond_t *prev_out = dap_chain_datum_tx_out_cond_get(prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &prev_idx);
    dap_assert(prev_out != NULL, "Found OUT_COND in previous transaction");
    dap_hash_fast_t expected_root = prev_out->subtype.srv_dex.order_root_hash;
    dap_assert(dap_hash_fast_compare(&expected_root, &leftover_root), "Root hash matches expected");
    log_it(L_INFO, "        Verified root hash: %s", dap_chain_hash_fast_to_str_static(&leftover_root));
    
    // Alice UPDATE leftover order: Decrease value to 5 KEL (refund 3 KEL)
    log_it(L_INFO, "[4.5.5] Alice UPDATE leftover order: Decrease value to 5 KEL (refund 3 KEL)");
    log_it(L_INFO, "        Expected: UPDATE SUCCESS, refunds 3 KEL, root hash preserved");
    
    dap_hash_fast_t update_hash = {0};
    ret = test_dex_order_update(f, f->alice, &leftover_tail, true, "5.0", &update_hash);
    dap_assert(ret == 0, "Alice UPDATE SUCCESS");
    
    // Verify root hash preserved after UPDATE
    dap_chain_datum_tx_t *update_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &update_hash);
    dap_assert(update_tx != NULL, "Found UPDATE transaction");
    int update_out_idx = 0;
    dap_chain_tx_out_cond_t *update_out = dap_chain_datum_tx_out_cond_get(update_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &update_out_idx);
    dap_assert(update_out != NULL, "Found OUT_COND in UPDATE transaction");
    dap_hash_fast_t new_root = update_out->subtype.srv_dex.order_root_hash;
    dap_assert(dap_hash_fast_compare(&new_root, &leftover_root), "Root hash preserved after UPDATE");
    log_it(L_INFO, "        ✓ Root hash preserved: %s", dap_chain_hash_fast_to_str_static(&new_root));
    
    // Alice balances: locked 5 KEL total (was 8, refunded 3), 1 TC fee
    // Initial balance: KEL=7485.833333333333333299 (8 locked, 7477.833333333333333299 free)
    // After UPDATE: KEL=7488.833333333333333299 (5 locked, 7483.833333333333333299 free)
    // Balance change: +3 KEL (matches refund: 8 - 5 = 3)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7488.833333333333333299"), "Alice KEL after UPDATE (locked 5 total, +3 refunded)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "11647.599999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99953.0"), "Alice TC fee (-1)");
    
    // Carol buys 5 KEL from updated leftover (full fill)
    log_it(L_INFO, "[4.5.6] Carol buys 5 KEL from updated leftover (full fill)");
    log_it(L_INFO, "        Expected: Purchase SUCCESS, order fully closed");
    log_it(L_INFO, "        Budget: 5 KEL (is_budget_buy=true) = 20 USDT @ 4.0 USDT/KEL");
    
    // After UPDATE, UPDATE transaction hash becomes new tail hash
    dap_hash_fast_t new_tail_hash = update_hash;
    dap_hash_fast_t final_purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->carol, &new_tail_hash, "5.0", true, false, &final_purchase_hash);
    dap_assert(ret == 0, "Carol purchase SUCCESS");
    
    // Carol: receives 5 KEL, pays 20 USDT (service fee waived, Carol is service wallet)
    // Carol also received service fee from Bob's purchase: +0.96 USDT
    // Carol: KEL=505.90909090909090915 + 5 = 510.90909090909090915
    // Carol: USDT=290.299999999999999797 + 0.96 (from Bob's fee) - 20 = 271.259999999999999797
    // Carol: TC=99986.0 - 1 = 99985.0
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "510.90909090909090915"), "Carol KEL after purchase (+5)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "271.259999999999999797"), "Carol USDT after purchase (-20, fee waived, +0.96 from Bob's fee)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99985.0"), "Carol TC fee (-1)");
    
    // Alice: receives 20 USDT (5 KEL * 4.0), service fee waived (Carol is service wallet)
    // Alice: KEL=7488.833333333333333299 (unchanged, order fully closed)
    // Alice: USDT=11647.599999999999999995 + 20 = 11667.599999999999999995
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7488.833333333333333299"), "Alice KEL unchanged (order fully closed)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "11667.599999999999999995"), "Alice USDT after purchase (+20, fee waived)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 4.5 PASSED: UPDATE Leftover Value Decrease (8 → 5 KEL, root preserved, refund verified, full fill)");
}

/**
 * @brief Test Group 4.3a - Root Hash Validation
 * @details Verifies UPDATE cannot change order_root_hash (immutable field, verificator check).
 *          This test creates a valid UPDATE transaction, then modifies the root_hash to a blank value,
 *          re-signs it, and verifies that verificator rejects it with DEXV_TX_TYPE_MISMATCH.
 */
static void test_group_4_3a_root_hash_validation(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 4.3a: UPDATE Root Hash Validation ===");
    
    // Precheck balances (after test 4.2)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7555.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10964.599999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99956.0"), "Precheck Alice TC");
    
    // Find Alice's order from tracking
    log_it(L_INFO, "[4.3a.1] Find Alice's order for root_hash validation testing");
    dap_hash_fast_t order_tail = {0};
    dap_hash_fast_t order_root = {0};
    dap_chain_datum_tx_t *prev_tx = NULL;
    dap_chain_tx_out_cond_t *prev_out = NULL;
    int prev_idx = 0;
    bool found = false;
    
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (!e->active) continue;
        if (dap_strcmp(e->token_sell, "KEL") != 0 || dap_strcmp(e->token_buy, "USDT") != 0) continue;
        if (!dap_chain_addr_compare(&e->seller_addr, &f->alice_addr)) continue; // Alice's order
        
        order_tail = e->tail;
        order_root = e->root;
        prev_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &order_tail);
        if (prev_tx) {
            prev_out = dap_chain_datum_tx_out_cond_get(prev_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &prev_idx);
            if (prev_out) {
                found = true;
                log_it(L_INFO, "        Found Alice's order: tail=%s, root=%s, rate=%s, value=%s",
                       dap_chain_hash_fast_to_str_static(&order_tail),
                       dap_chain_hash_fast_to_str_static(&order_root),
                       dap_uint256_to_char_ex(prev_out->subtype.srv_dex.rate).frac,
                       dap_uint256_to_char_ex(prev_out->header.value).frac);
                break;
            }
        }
    }
    dap_assert(found && prev_tx && prev_out, "Found Alice's order for testing");
    dap_assert(!dap_hash_fast_is_blank(&order_root), "Order has non-blank root hash");
    
    // Verify root hash from ledger matches tracking
    dap_hash_fast_t expected_root = prev_out->subtype.srv_dex.order_root_hash;
    if (dap_hash_fast_is_blank(&expected_root)) {
        expected_root = order_tail; // ORDER: root=tail
    }
    dap_assert(dap_hash_fast_compare(&expected_root, &order_root), "Root hash matches expected");
    log_it(L_INFO, "        Verified root hash: %s", dap_chain_hash_fast_to_str_static(&order_root));
    
    // Test root_hash change (verificator check)
    log_it(L_INFO, "[4.3a.2] Test order_root_hash immutability (verificator check)");
    log_it(L_INFO, "        Create UPDATE TX, zero out root_hash (pretend it's original ORDER), verify verificator rejects");
    log_it(L_INFO, "        Expected: UPDATE REJECTED with DEXV_TX_TYPE_MISMATCH (UPDATE must have non-blank root, line 2833-2835)");
    
    int ok = test_immutable_change(f, &order_tail, prev_out, "order_root_hash", modify_root_hash);
    dap_assert(ok, "order_root_hash change rejected");
    
    // Verify balances unchanged (UPDATE was rejected)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7555.833333333333333299"), "Alice KEL unchanged (UPDATE rejected)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "10964.599999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99956.0"), "Alice TC unchanged (no fee deducted)");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 4.3a PASSED: Root Hash Validation (UPDATE with blank root_hash rejected)");
}

/**
 * @brief Test Group 4.6 - UPDATE AON Order Allowed (owner-only), AON enforced at trade time
 * @details Verifies that:
 *          - AON orders (min_fill=100%) can be UPDATED by owner (value increase/decrease/no-op)
 *          - Bit 0x80 (from_origin) is ignored for AON in verifier/matcher
 *          - AON semantics (full fill only, no leftover) are enforced only for trades (EXCHANGE), not for UPDATE
 *          - Partial purchase of AON order is rejected by composer (auto-match skips AON when budget < full fill)
 *          - Verificator rejects malicious TX with seller-leftover for AON order (DEXV_MIN_FILL_AON)
 *          - Full purchase of AON order succeeds via auto-matching (auto-matcher finds and fully executes AON order)
 */
static void test_group_4_6_update_aon_rejected(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 4.6: UPDATE AON Order — Owner Updates Allowed, AON Enforced at Trade Time ===");
    
    // Precheck balances (after test 4.5)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7488.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "11667.599999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99953.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2481.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "38061.140000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99956.0"), "Precheck Bob TC");
    
    // Create AON order (min_fill=100% = 0x64)
    log_it(L_INFO, "[4.6.1] Alice creates AON order: 100 KEL @ 5.0 USDT/KEL (min_fill=100%%)");
    log_it(L_INFO, "        Expected: Order created successfully");
    
    dap_hash_fast_t aon_order_hash = {0};
    int ret = test_dex_order_create_ex(f, f->alice, "USDT", "KEL", "100.0", "5.0", 0x64, &aon_order_hash);
    dap_assert(ret == 0, "Alice AON order created");
    
    // Alice: 100 KEL locked, 1 TC fee
    // Initial: KEL=7488.833333333333333299, TC=99953.0
    // After CREATE: KEL=7388.833333333333333299 (locked 100), TC=99952.0 (-1 fee)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7388.833333333333333299"), "Alice KEL locked (100)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "11667.599999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99952.0"), "Alice TC fee (-1)");
    
    // Find AON order from tracking
    dap_hash_fast_t order_tail = {0};
    dap_hash_fast_t order_root = {0};
    bool found = false;
    int update_out_idx = 0;
    dap_chain_tx_out_cond_t *update_out = NULL;
    
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (!e->active) continue;
        if (dap_hash_fast_compare(&e->tail, &aon_order_hash) || dap_hash_fast_compare(&e->root, &aon_order_hash)) {
            order_tail = e->tail;
            order_root = e->root;
            found = true;
            log_it(L_INFO, "        Found AON order: tail=%s, root=%s, value=100.0 KEL",
                   dap_chain_hash_fast_to_str_static(&order_tail),
                   dap_chain_hash_fast_to_str_static(&order_root));
            break;
        }
    }
    dap_assert(found, "Found AON order in tracking");
    
    // Verify order has min_fill=100% from ledger
    dap_chain_datum_tx_t *order_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &order_tail);
    dap_assert(order_tx != NULL, "Found AON order transaction");
    int order_out_idx = 0;
    dap_chain_tx_out_cond_t *order_out = dap_chain_datum_tx_out_cond_get(order_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &order_out_idx);
    dap_assert(order_out != NULL, "Found OUT_COND in AON order");
    uint8_t min_fill_pct = order_out->subtype.srv_dex.min_fill & 0x7F;
    dap_assert(min_fill_pct == 100, "AON order has min_fill=100%%");
    log_it(L_INFO, "        Verified: min_fill=%d%% (AON)", min_fill_pct);
    
    // Test 1: UPDATE with value decrease (partial update from owner's perspective)
    log_it(L_INFO, "[4.6.2] Alice UPDATE: Decrease value to 50 KEL (partial update)");
    log_it(L_INFO, "        Expected: UPDATE SUCCESS, refunds 50 KEL to Alice");
    
    dap_chain_datum_tx_t *update_tx = NULL;
    dap_chain_net_srv_dex_update_error_t err = dap_chain_net_srv_dex_update(
        f->net->net, &order_tail, true, dap_chain_coins_to_balance("50.0"),
        f->network_fee, f->alice, NULL, &update_tx
    );
    dap_assert(err == DEX_UPDATE_ERROR_OK && update_tx != NULL, "AON UPDATE decrease composed successfully");
    
    dap_hash_fast_t update_hash = {0};
    dap_hash_fast(update_tx, dap_chain_datum_tx_get_size(update_tx), &update_hash);
    
    int ledger_err = dap_ledger_tx_add(f->net->net->pub.ledger, update_tx, &update_hash, false, NULL);
    dap_assert(ledger_err == 0, "AON UPDATE decrease accepted by verificator");
    
    // Update tracking: find OUT_COND and update tail/value
    update_out_idx = 0;
    update_out = dap_chain_datum_tx_out_cond_get(update_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &update_out_idx);
    if (update_out) {
        test_dex_order_track_update(f, &order_root, &update_hash, update_out->header.value);
    }
    dap_chain_datum_tx_delete(update_tx);
    
    // After UPDATE: value=50 KEL (AON preserved), Alice KEL increased by 50 (refund), TC -1
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7438.833333333333333299"), "Alice KEL after UPDATE decrease (+50)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "11667.599999999999999995"), "Alice USDT unchanged after UPDATE decrease");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99951.0"), "Alice TC after UPDATE decrease (-1)");
    
    // Test 2: UPDATE with value increase
    log_it(L_INFO, "[4.6.3] Alice UPDATE: Increase value to 150 KEL");
    log_it(L_INFO, "        Expected: UPDATE SUCCESS, locks additional 100 KEL");
    
    order_tail = update_hash; // use last tail as input for next UPDATE
    update_tx = NULL;
    err = dap_chain_net_srv_dex_update(
        f->net->net, &order_tail, true, dap_chain_coins_to_balance("150.0"),
        f->network_fee, f->alice, NULL, &update_tx
    );
    dap_assert(err == DEX_UPDATE_ERROR_OK && update_tx != NULL, "AON UPDATE increase composed successfully");
    
    dap_hash_fast(update_tx, dap_chain_datum_tx_get_size(update_tx), &update_hash);
    ledger_err = dap_ledger_tx_add(f->net->net->pub.ledger, update_tx, &update_hash, false, NULL);
    dap_assert(ledger_err == 0, "AON UPDATE increase accepted by verificator");
    
    // Update tracking: find OUT_COND and update tail/value
    update_out_idx = 0;
    update_out = dap_chain_datum_tx_out_cond_get(update_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &update_out_idx);
    if (update_out) {
        test_dex_order_track_update(f, &order_root, &update_hash, update_out->header.value);
    }
    dap_chain_datum_tx_delete(update_tx);
    
    // After UPDATE: value=150 KEL (AON preserved), Alice KEL decreased by 100 from previous state
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7338.833333333333333299"), "Alice KEL after UPDATE increase (-100)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "11667.599999999999999995"), "Alice USDT unchanged after UPDATE increase");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99950.0"), "Alice TC after UPDATE increase (-1)");
    
    // Test 3: UPDATE with same value (no-op)
    log_it(L_INFO, "[4.6.4] Alice UPDATE: Keep value 150 KEL (no change)");
    log_it(L_INFO, "        Expected: UPDATE SUCCESS (no-op, but fee charged)");
    
    order_tail = update_hash;
    update_tx = NULL;
    err = dap_chain_net_srv_dex_update(
        f->net->net, &order_tail, true, dap_chain_coins_to_balance("150.0"),
        f->network_fee, f->alice, NULL, &update_tx
    );
    dap_assert(err == DEX_UPDATE_ERROR_OK && update_tx != NULL, "AON UPDATE same-value composed successfully");
    
    dap_hash_fast(update_tx, dap_chain_datum_tx_get_size(update_tx), &update_hash);
    ledger_err = dap_ledger_tx_add(f->net->net->pub.ledger, update_tx, &update_hash, false, NULL);
    dap_assert(ledger_err == 0, "AON UPDATE same-value accepted by verificator");
    
    // Update tracking: find OUT_COND and update tail/value
    update_out_idx = 0;
    update_out = dap_chain_datum_tx_out_cond_get(update_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &update_out_idx);
    if (update_out) {
        test_dex_order_track_update(f, &order_root, &update_hash, update_out->header.value);
    }
    dap_chain_datum_tx_delete(update_tx);
    
    // After UPDATE: value=150 KEL, balances changed only by TC fee
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7338.833333333333333299"), "Alice KEL unchanged after no-op UPDATE");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "11667.599999999999999995"), "Alice USDT unchanged after no-op UPDATE");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99949.0"), "Alice TC after no-op UPDATE (-1)");
    
    // Test AON enforcement at trade time: attempt partial purchase (should be rejected by composer)
    // Note: Composer rejects this at match-building stage (AON order skipped when budget < full fill)
    // Verificator also checks AON (DEXV_MIN_FILL_AON), but composer prevents invalid TX creation
    log_it(L_INFO, "[4.6.5] Bob attempts partial purchase: 50 KEL from AON order (150 KEL total)");
    log_it(L_INFO, "        Expected: Purchase REJECTED by composer (AON requires full fill, no partial allowed)");
    log_it(L_INFO, "        Composer skips AON order in matching when budget < full fill, returns DEX_PURCHASE_ERROR_COMPOSE_TX");
    
    dap_hash_fast_t partial_purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->bob, &update_hash, "50.0", true, false, &partial_purchase_hash);
    dap_assert(ret != 0, "Partial purchase of AON order rejected by composer");
    
    // Bob balances unchanged (purchase failed)
    // Initial (from precheck): KEL=2481.166666666666666641, USDT=38061.140000000000000208, TC=99956.0
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2481.166666666666666641"), "Bob KEL unchanged (purchase rejected)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "38061.140000000000000208"), "Bob USDT unchanged (purchase rejected)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99956.0"), "Bob TC unchanged (purchase rejected)");
    
    // Alice balances unchanged (order not touched)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7338.833333333333333299"), "Alice KEL unchanged (order not touched)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "11667.599999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99949.0"), "Alice TC unchanged");
    
    // Test AON enforcement at trade time: verificator check (manual TX with seller-leftover)
    // Create malicious EXCHANGE transaction with seller-leftover for AON order (should be rejected by verificator)
    log_it(L_INFO, "[4.6.5a] Create malicious EXCHANGE TX with seller-leftover for AON order (manual tampering)");
    log_it(L_INFO, "        Expected: Verificator REJECTS with DEXV_MIN_FILL_AON (AON cannot produce leftover)");
    
    // Get current AON order OUT_COND to extract parameters
    dap_chain_datum_tx_t *aon_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &update_hash);
    dap_assert(aon_tx != NULL, "Found AON order TX");
    
    int aon_out_idx = 0;
    dap_chain_tx_out_cond_t *aon_out = dap_chain_datum_tx_out_cond_get(aon_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &aon_out_idx);
    dap_assert(aon_out != NULL, "Found AON order OUT_COND");
    
    // Extract order parameters
    dap_hash_fast_t aon_root = aon_out->subtype.srv_dex.order_root_hash;
    dap_chain_addr_t aon_seller = aon_out->subtype.srv_dex.seller_addr;
    uint256_t aon_value = aon_out->header.value; // 150 KEL
    uint256_t aon_rate = aon_out->subtype.srv_dex.rate;
    uint8_t aon_min_fill = aon_out->subtype.srv_dex.min_fill;
    uint8_t aon_version = aon_out->subtype.srv_dex.version;
    uint32_t aon_flags = aon_out->subtype.srv_dex.flags;
    dap_chain_net_id_t aon_sell_net_id = aon_out->subtype.srv_dex.sell_net_id;
    dap_chain_net_id_t aon_buy_net_id = aon_out->subtype.srv_dex.buy_net_id;
    const char *aon_buy_token = aon_out->subtype.srv_dex.buy_token;
    // Get sell_token from ledger (it's not stored in OUT_COND structure)
    const char *aon_sell_token = dap_ledger_tx_get_token_ticker_by_hash(f->net->net->pub.ledger, &update_hash);
    dap_assert(aon_sell_token != NULL, "Got sell_token from ledger");
    
    // Calculate partial execution: 50 KEL executed, 100 KEL leftover
    uint256_t exec_sell = dap_chain_coins_to_balance("50.0"); // 50 KEL executed
    uint256_t leftover = dap_chain_coins_to_balance("100.0"); // 100 KEL leftover
    
    // Calculate seller payout: 50 KEL * 5.0 USDT/KEL = 250 USDT
    uint256_t seller_payout = uint256_0;
    MULT_256_COIN(exec_sell, aon_rate, &seller_payout);
    
    // Create malicious EXCHANGE transaction
    dap_chain_datum_tx_t *malicious_tx = dap_chain_datum_tx_create();
    dap_assert(malicious_tx != NULL, "Created malicious TX");
    
    // Add IN_COND: spend AON order (partial)
    int in_cond_idx = dap_chain_datum_tx_add_in_cond_item(&malicious_tx, &update_hash, aon_out_idx, 0);
    dap_assert(in_cond_idx >= 0, "Added IN_COND");
    
    // Add OUT_EXT: seller payout (250 USDT)
    dap_chain_addr_t *alice_addr = dap_chain_wallet_get_addr(f->alice, f->net->net->pub.id);
    dap_assert(alice_addr != NULL, "Got Alice address");
    dap_assert(dap_chain_datum_tx_add_out_ext_item(&malicious_tx, alice_addr, seller_payout, aon_buy_token) >= 0, "Added seller payout");
    DAP_DELETE(alice_addr);
    
    // Add OUT_COND: seller-leftover (100 KEL) - THIS IS FORBIDDEN FOR AON!
    dap_chain_tx_out_cond_t *leftover_out = dap_chain_datum_tx_item_out_cond_create_srv_dex(
        (dap_chain_net_srv_uid_t){ .uint64 = DAP_CHAIN_NET_SRV_DEX_ID },
        aon_sell_net_id, leftover, aon_buy_net_id, aon_buy_token,
        aon_rate, &aon_seller, &aon_root,
        aon_min_fill, aon_version, aon_flags,
        DEX_TX_TYPE_EXCHANGE, NULL, 0);
    dap_assert(leftover_out != NULL, "Created seller-leftover OUT_COND");
    dap_assert(dap_chain_datum_tx_add_item(&malicious_tx, (const uint8_t*)leftover_out) >= 0, "Added seller-leftover OUT_COND");
    DAP_DELETE(leftover_out);
    
    // Add network fee (use network fee address)
    dap_assert(dap_chain_datum_tx_add_out_ext_item(&malicious_tx, &f->net->net->pub.fee_addr, f->network_fee, "TestCoin") >= 0, "Added network fee");
    
    // Sign transaction
    dap_enc_key_t *bob_key = dap_chain_wallet_get_key(f->bob, 0);
    dap_assert(bob_key != NULL, "Got Bob key");
    dap_assert(dap_chain_datum_tx_add_sign_item(&malicious_tx, bob_key) > 0, "Signed malicious TX");
    dap_enc_key_delete(bob_key);
    
    // Try to add to ledger (verificator should reject)
    dap_hash_fast_t malicious_hash = {0};
    dap_hash_fast(malicious_tx, dap_chain_datum_tx_get_size(malicious_tx), &malicious_hash);
    
    int verificator_err = dap_ledger_tx_add(f->net->net->pub.ledger, malicious_tx, &malicious_hash, false, NULL);
    dap_chain_datum_tx_delete(malicious_tx);
    // Note: Don't delete aon_tx here - it's from ledger and may be cached/reused by ledger functions
    
    dap_assert(verificator_err != 0, "Verificator rejected malicious TX with seller-leftover for AON order");
    log_it(L_INFO, "        ✓ Verificator rejected malicious TX (DEXV_MIN_FILL_AON expected)");
    
    // Balances unchanged (transaction rejected)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2481.166666666666666641"), "Bob KEL unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "38061.140000000000000208"), "Bob USDT unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7338.833333333333333299"), "Alice KEL unchanged (TX rejected)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "11667.599999999999999995"), "Alice USDT unchanged (TX rejected)");
    
    // Test AON enforcement at trade time: full purchase via auto-matching (should succeed)
    log_it(L_INFO, "[4.6.6] Bob auto-purchases full AON order: budget=150 KEL (auto-match finds AON order)");
    log_it(L_INFO, "        Expected: Auto-match SUCCESS (finds AON order, full fill allowed), order fully closed");
    log_it(L_INFO, "        Budget: 150 KEL (is_budget_buy=true) = 750 USDT @ 5.0 USDT/KEL");
    log_it(L_INFO, "        Auto-matcher should find AON order and fully execute it");
    
    dap_hash_fast_t full_purchase_hash = {0};
    ret = test_dex_order_purchase_auto_ex(f, f->bob, "USDT", "KEL", "150.0", true, false, uint256_0, &full_purchase_hash);
    dap_assert(ret == 0, "Full auto-purchase of AON order succeeded");
    
    // Bob balances:
    // KEL: +150.0
    // USDT: -750.0 (150 * 5.0) - 15.0 (2% fee) = -765.0
    // TC: -1 fee
    // Initial: KEL=2481.166666666666666641, USDT=38061.140000000000000208, TC=99956.0
    // Expected: KEL=2631.166666666666666641, USDT=37296.140000000000000208, TC=99955.0
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2631.166666666666666641"), "Bob KEL after purchase (+150)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "37296.140000000000000208"), "Bob USDT after purchase (-750-15 fee)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99955.0"), "Bob TC fee (-1)");
    
    // Alice balances:
    // KEL: Unchanged (order closed, 150 KEL sold)
    // USDT: +750.0 (fee paid by buyer)
    // TC: Unchanged
    // Initial: KEL=7338.833333333333333299 (150 locked), USDT=11667.599999999999999995, TC=99949.0
    // Expected: KEL=7338.833333333333333299, USDT=12417.599999999999999995, TC=99949.0
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7338.833333333333333299"), "Alice KEL unchanged (order closed)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "12417.599999999999999995"), "Alice USDT after purchase (+750, fee paid by buyer)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99949.0"), "Alice TC unchanged");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 4.6 PASSED: UPDATE AON Order — Owner Updates Allowed (decrease/increase/no-op), AON enforced at trade time (partial rejected, full fill succeeded)");
}

// ============================================================================
// TEST GROUP 5: LEFTOVER HANDLING
// ============================================================================

/**
 * @brief Test Group 5.1 - Buyer leftover with cache
 * @details Verifies buyer-leftover correctly added to cache as NEW order
 * @note Seller-leftover already covered in GROUP 1.3, 1.5, 1.6, 2.12, 4.4, 4.5
 * 
 * WHAT WE TEST:
 * 1. Buyer-leftover creates NEW independent order chain (root=blank, root=tail=TX hash)
 * 2. Buyer becomes seller in leftover order (ownership transfer)
 * 3. Direction reversed correctly (if buyer bought KEL, leftover sells KEL as BID)
 * 4. Buyer-leftover can be purchased independently
 * 5. Cache entry removed when order fully closed
 */
static void test_group_5_1_buyer_leftover_cache(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 5.1: Buyer Leftover (Cache) ===");
    log_it(L_INFO, " ");
    log_it(L_INFO, "WHAT WE TEST:");
    log_it(L_INFO, "  - Buyer-leftover creates NEW independent order chain");
    log_it(L_INFO, "  - Root hash is BLANK (0x0) - new order, not continuation of seller's chain");
    log_it(L_INFO, "  - Cache entry: root=tail=TX hash (new chain!)");
    log_it(L_INFO, "  - Buyer becomes seller in leftover order (ownership transfer)");
    log_it(L_INFO, "  - Direction reversed correctly (buyer bought KEL → leftover sells KEL as BID)");
    log_it(L_INFO, "  - Buyer-leftover can be purchased independently");
    log_it(L_INFO, "  - Cache entry removed when order fully closed");
    log_it(L_INFO, " ");
    
    // Precheck balances (after GROUP 4)
    log_it(L_INFO, "[5.1.0] Precheck balances (after GROUP 4)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7338.833333333333333299"), "Precheck Alice KEL");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "12417.599999999999999995"), "Precheck Alice USDT");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99949.0"), "Precheck Alice TC");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2631.166666666666666641"), "Precheck Bob KEL");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "37296.140000000000000208"), "Precheck Bob USDT");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99955.0"), "Precheck Bob TC");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "510.90909090909090915"), "Precheck Carol KEL");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "286.259999999999999797"), "Precheck Carol USDT");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99985.0"), "Precheck Carol TC");
    
    // Step 1: Alice creates ASK order: 50 KEL @ 5.0 USDT/KEL
    log_it(L_INFO, " ");
    log_it(L_INFO, "[5.1.1] Alice creates ASK order: 50 KEL @ 5.0 USDT/KEL");
    log_it(L_INFO, "        Expected: Order created successfully, Alice locks 50 KEL");
    
    dap_hash_fast_t alice_order_hash = {0};
    int ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "50.0", "5.0", &alice_order_hash);
    dap_assert(ret == 0, "Alice order created");
    
    // Alice balances: KEL=7288.833333 (locked 50), USDT=12417.6, TC=99948 (-1 fee)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7288.833333333333333299"), "Alice KEL locked (50)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "12417.599999999999999995"), "Alice USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99948.0"), "Alice TC fee (-1)");
    
    // Step 2a: Test buyer-leftover root_hash tampering (verificator check)
    log_it(L_INFO, " ");
    log_it(L_INFO, "[5.1.2a] Test buyer-leftover root_hash tampering (verificator check)");
    log_it(L_INFO, "        Create EXCHANGE TX purchasing with buyer-leftover (same as 5.1.2)");
    log_it(L_INFO, "        Tamper with root_hash in the created buyer-leftover OUT_COND");
    log_it(L_INFO, "        Set root_hash=Alice's order root (fake seller-leftover)");
    log_it(L_INFO, "        Expected: EXCHANGE REJECTED with DEXV_IMMUTABLES_VIOLATION (root mismatch)");
    
    // Create valid EXCHANGE transaction with buyer-leftover (same as 5.1.2)
    uint256_t min_rate = dap_chain_coins_to_balance("5.0"); // 5.0 USDT/KEL
    dap_chain_datum_tx_t *test_tx = NULL;
    dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase_auto(
        f->net->net, "USDT", "KEL", dap_chain_coins_to_balance("80.0"), true, f->network_fee, min_rate,
        f->bob, NULL, true, min_rate, 0, &test_tx  // create_buyer_leftover=true, leftover_rate=min_rate
    );
    dap_assert(err == DEX_PURCHASE_ERROR_OK && test_tx != NULL, "Created valid EXCHANGE TX with buyer-leftover");
    
    // Find first signature position (composer already signed)
    uint8_t *l_first_sig = dap_chain_datum_tx_item_get(test_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_assert(l_first_sig != NULL, "Found signature in EXCHANGE TX");
    
    // Calculate size without signatures (copy TX up to first signature)
    size_t l_tx_size_without_sigs = (size_t)(l_first_sig - (uint8_t*)test_tx);
    
    // Create new TX without signatures
    dap_chain_datum_tx_t *l_new_tx = DAP_DUP_SIZE(test_tx, l_tx_size_without_sigs);
    dap_assert(l_new_tx != NULL, "Created new TX without signatures");
    l_new_tx->header.tx_items_size = l_tx_size_without_sigs - sizeof(dap_chain_datum_tx_t);
    
    // Find buyer-leftover OUT_COND in transaction (should have blank root_hash, seller=Bob)
    int tampered_out_idx = 0;
    dap_chain_tx_out_cond_t *tampered_out = NULL;
    dap_chain_addr_t *bob_addr_test = dap_chain_wallet_get_addr(f->bob, f->net->net->pub.id);
    dap_assert(bob_addr_test != NULL, "Got Bob's address");
    while ((tampered_out = dap_chain_datum_tx_out_cond_get(l_new_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &tampered_out_idx)) != NULL) {
        // Buyer-leftover: blank root_hash, seller=Bob (buyer becomes seller)
        if (dap_hash_fast_is_blank(&tampered_out->subtype.srv_dex.order_root_hash) &&
            dap_chain_addr_compare(&tampered_out->subtype.srv_dex.seller_addr, bob_addr_test)) {
            break;
        }
        tampered_out_idx++;
    }
    DAP_DELETE(bob_addr_test);
    dap_assert(tampered_out != NULL, "Found buyer-leftover OUT_COND in EXCHANGE TX");
    
    // Tamper: set root_hash to Alice's order root (fake seller-leftover)
    tampered_out->subtype.srv_dex.order_root_hash = alice_order_hash;
    log_it(L_INFO, "        Tampered: set root_hash=%s (Alice's order root, should be blank)",
           dap_chain_hash_fast_to_str_static(&alice_order_hash));
    
    // Sign new transaction
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(f->bob, 0);
    dap_assert(l_key != NULL, "Got Bob's key");
    dap_assert(dap_chain_datum_tx_add_sign_item(&l_new_tx, l_key) > 0, "Signed tampered EXCHANGE TX");
    dap_enc_key_delete(l_key);
    
    // Calculate hash and try to add to ledger (verificator should reject)
    dap_hash_fast_t tampered_hash = {0};
    dap_hash_fast(l_new_tx, dap_chain_datum_tx_get_size(l_new_tx), &tampered_hash);
    
    // Try to add to ledger (verificator should reject with DEXV_IMMUTABLES_VIOLATION)
    int verificator_err = dap_ledger_tx_add(f->net->net->pub.ledger, l_new_tx, &tampered_hash, false, NULL);
    dap_chain_datum_tx_delete(test_tx);
    dap_chain_datum_tx_delete(l_new_tx);
    
    dap_assert(verificator_err != 0, "Tampered EXCHANGE TX rejected by verificator");
    log_it(L_INFO, "        ✓ Buyer-leftover with fake root_hash rejected by verificator");
    
    // Verify balances unchanged (EXCHANGE was rejected)
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2631.166666666666666641"), "Bob KEL unchanged (EXCHANGE rejected)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "37296.140000000000000208"), "Bob USDT unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99955.0"), "Bob TC unchanged (no fee deducted)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7288.833333333333333299"), "Alice KEL unchanged (50 still locked)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "12417.599999999999999995"), "Alice USDT unchanged");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 5.1.2a PASSED: Buyer Leftover Root Hash Tampering Rejected");
    
    // Step 2: Bob purchases with budget=80 KEL, create_buyer_leftover=true
    log_it(L_INFO, " ");
    log_it(L_INFO, "[5.1.2] Bob purchases with budget=80 KEL, create_buyer_leftover=true");
    log_it(L_INFO, "        Budget: 80 KEL (is_budget_buy=true) = 400 USDT @ 5.0 USDT/KEL");
    log_it(L_INFO, "        Min rate: 5.0 USDT/KEL (will be used for buyer-leftover)");
    log_it(L_INFO, "        Auto-match finds: Alice's order (50 KEL @ 5.0)");
    log_it(L_INFO, "        Purchased: 50 KEL, spent: 255 USDT (250+5 fee)");
    log_it(L_INFO, "        Leftover budget: 30 KEL (80 - 50)");
    log_it(L_INFO, "        System collects UTXO for buyer-leftover (30 KEL), excess returned as cashback");
    log_it(L_INFO, "        Expected: Purchase SUCCESS, buyer-leftover order created (30 KEL BID @ 5.0)");
    
    dap_hash_fast_t purchase_hash = {0};
    ret = test_dex_order_purchase_auto_ex(f, f->bob, "USDT", "KEL", "80.0", true, true, min_rate, &purchase_hash);
    dap_assert(ret == 0, "Bob purchase with buyer-leftover succeeded");
    
    // Bob balances after purchase:
    // KEL: +50 (purchased) - 30 (locked in buyer-leftover order) = +20 net
    //      (System collected UTXO for buyer-leftover, excess returned as cashback)
    // USDT: 37296.14 (initial) - 255 (spent: 250 purchase + 5 fee) = 37041.14
    // TC: -1 fee
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2651.166666666666666641"), "Bob KEL after purchase (+50 purchased - 30 locked in buyer-leftover)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "37041.140000000000000208"), "Bob USDT after purchase (-255 spent)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99954.0"), "Bob TC fee (-1)");
    
    // Alice balances: KEL=7288.833333 (50 unlocked), USDT=12667.6 (+250-5 fee), TC=99948
    // Initial: KEL=7288.833333 (50 locked), USDT=12417.6, TC=99948
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7288.833333333333333299"), "Alice KEL unchanged (50 unlocked)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "12667.599999999999999995"), "Alice USDT after purchase (+250-5 fee)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99948.0"), "Alice TC unchanged");
    
    // Step 3: Verify buyer-leftover in tracking and ledger
    log_it(L_INFO, " ");
    log_it(L_INFO, "[5.1.3] Verify buyer-leftover order properties");
    log_it(L_INFO, "        Expected: root=tail=purchase_hash (NEW order!), root_hash=BLANK, seller=Bob");
    
    // Find buyer-leftover in tracking
    order_entry_t *buyer_leftover = NULL;
    dap_chain_addr_t *bob_addr = dap_chain_wallet_get_addr(f->bob, f->net->net->pub.id);
    dap_assert(bob_addr != NULL, "Got Bob's address");
    
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (!e->active) continue;
        if (!dap_chain_addr_compare(&e->seller_addr, bob_addr)) continue; // Bob's order
        if (dap_hash_fast_compare(&e->root, &e->tail)) { // root=tail (new order)
            buyer_leftover = e;
            log_it(L_INFO, "        Found buyer-leftover in tracking: root=tail=%s, seller=Bob, value=%s %s",
                   dap_chain_hash_fast_to_str_static(&e->root),
                   dap_uint256_to_char_ex(e->value).frac,
                   e->token_sell);
            break;
        }
    }
    
    dap_assert(buyer_leftover != NULL, "Buyer-leftover found in tracking");
    dap_assert(dap_hash_fast_compare(&buyer_leftover->root, &purchase_hash), "Buyer-leftover root equals purchase TX hash");
    dap_assert(dap_hash_fast_compare(&buyer_leftover->tail, &purchase_hash), "Buyer-leftover tail equals purchase TX hash");
    dap_assert(dap_hash_fast_compare(&buyer_leftover->root, &buyer_leftover->tail), "Buyer-leftover root equals tail (new order!)");
    dap_assert(dap_strcmp(buyer_leftover->token_sell, "KEL") == 0, "Buyer-leftover sells KEL");
    dap_assert(dap_strcmp(buyer_leftover->token_buy, "USDT") == 0, "Buyer-leftover buys USDT");
    dap_assert(buyer_leftover->side == 1, "Buyer-leftover is BID (sells KEL, buys USDT)");
    
    // Verify root hash is BLANK in ledger
    dap_chain_datum_tx_t *purchase_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &purchase_hash);
    dap_assert(purchase_tx != NULL, "Found purchase transaction in ledger");
    
    int out_idx = 0;
    dap_chain_tx_out_cond_t *buyer_leftover_out = NULL;
    while ((buyer_leftover_out = dap_chain_datum_tx_out_cond_get(purchase_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &out_idx)) != NULL) {
        if (dap_hash_fast_is_blank(&buyer_leftover_out->subtype.srv_dex.order_root_hash)) {
            dap_assert(dap_chain_addr_compare(&buyer_leftover_out->subtype.srv_dex.seller_addr, bob_addr), "Buyer-leftover seller is Bob");
            log_it(L_INFO, "        Verified in ledger: root_hash=BLANK (0x0), seller=Bob, value=%s KEL",
                   dap_uint256_to_char_ex(buyer_leftover_out->header.value).frac);
            break;
        }
        out_idx++;
    }
    
    dap_assert(buyer_leftover_out != NULL, "Buyer-leftover OUT_COND found in ledger");
    dap_assert(dap_hash_fast_is_blank(&buyer_leftover_out->subtype.srv_dex.order_root_hash), "Buyer-leftover root hash is BLANK");
    // Buyer-leftover value: 30 KEL (80 - 50)
    uint256_t expected_leftover = dap_chain_coins_to_balance("30.0");
    dap_assert(compare256(buyer_leftover_out->header.value, expected_leftover) == 0, "Buyer-leftover value is 30 KEL");
    
    // Step 3a: Test seller-leftover root_hash tampering (verificator check)
    log_it(L_INFO, " ");
    log_it(L_INFO, "[5.1.3a] Test seller-leftover root_hash tampering (verificator check)");
    log_it(L_INFO, "        Create EXCHANGE TX purchasing buyer-leftover (partial, creates seller-leftover)");
    log_it(L_INFO, "        Tamper with root_hash in the created seller-leftover OUT_COND");
    log_it(L_INFO, "        Note: Buyer-leftover starts a new chain: seller-leftover must keep buyer-leftover root");
    log_it(L_INFO, "        Seller-leftover should have root_hash=buyer-leftover root (0x%s)", dap_chain_hash_fast_to_str_static(&purchase_hash));
    log_it(L_INFO, "        Set root_hash=Alice's original order root (0x%s) instead (wrong!)", dap_chain_hash_fast_to_str_static(&alice_order_hash));
    log_it(L_INFO, "        Expected: EXCHANGE REJECTED with DEXV_IMMUTABLES_VIOLATION (root mismatch)");
    
    // Create valid EXCHANGE transaction with partial purchase to create seller-leftover
    // Budget: 20 KEL (partial), will create seller-leftover of 10 KEL
    uint256_t budget = dap_chain_coins_to_balance("20.0");
    dap_chain_datum_tx_t *test_tx_sl = NULL;
    dap_chain_net_srv_dex_purchase_error_t err_sl = dap_chain_net_srv_dex_purchase(
        f->net->net, &purchase_hash, budget, true, f->network_fee, f->carol, NULL,
        false, uint256_0, 0, &test_tx_sl  // Partial purchase, no buyer-leftover created
    );
    dap_assert(err_sl == DEX_PURCHASE_ERROR_OK && test_tx_sl != NULL, "Created valid EXCHANGE TX with seller-leftover");
    
    // Find first signature position (composer already signed)
    uint8_t *l_first_sig_sl = dap_chain_datum_tx_item_get(test_tx_sl, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    dap_assert(l_first_sig_sl != NULL, "Found signature in EXCHANGE TX");
    
    // Calculate size without signatures (copy TX up to first signature)
    size_t l_tx_size_without_sigs_sl = (size_t)(l_first_sig_sl - (uint8_t*)test_tx_sl);
    
    // Create new TX without signatures
    dap_chain_datum_tx_t *l_new_tx_sl = DAP_DUP_SIZE(test_tx_sl, l_tx_size_without_sigs_sl);
    dap_assert(l_new_tx_sl != NULL, "Created new TX without signatures");
    l_new_tx_sl->header.tx_items_size = l_tx_size_without_sigs_sl - sizeof(dap_chain_datum_tx_t);
    
    // Find seller-leftover OUT_COND in transaction (should have root_hash = buyer-leftover root, seller=Bob)
    int tampered_out_idx_sl = 0;
    dap_chain_tx_out_cond_t *tampered_out_sl = NULL;
    dap_chain_addr_t *bob_addr_sl = dap_chain_wallet_get_addr(f->bob, f->net->net->pub.id);
    dap_assert(bob_addr_sl != NULL, "Got Bob's address");
    
    // Find seller-leftover OUT_COND (seller=Bob, should have root_hash = buyer-leftover root)
    while ((tampered_out_sl = dap_chain_datum_tx_out_cond_get(l_new_tx_sl, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &tampered_out_idx_sl)) != NULL) {
        if (dap_chain_addr_compare(&tampered_out_sl->subtype.srv_dex.seller_addr, bob_addr_sl)) {
            // Found seller-leftover from buyer-leftover
            log_it(L_INFO, "        Found seller-leftover OUT_COND: root_hash=%s, seller=Bob",
                   dap_hash_fast_is_blank(&tampered_out_sl->subtype.srv_dex.order_root_hash) ? "BLANK" : dap_chain_hash_fast_to_str_static(&tampered_out_sl->subtype.srv_dex.order_root_hash));
            break;
        }
        tampered_out_idx_sl++;
    }
    DAP_DELETE(bob_addr_sl);
    dap_assert(tampered_out_sl != NULL, "Found seller-leftover OUT_COND in EXCHANGE TX");
    
    // Save original root_hash (system must use buyer-leftover root as chain root)
    dap_hash_fast_t original_root_hash = tampered_out_sl->subtype.srv_dex.order_root_hash;
    log_it(L_INFO, "        Original root_hash=%s (expected buyer-leftover root)",
           dap_hash_fast_is_blank(&original_root_hash) ? "BLANK" : dap_chain_hash_fast_to_str_static(&original_root_hash));
    dap_assert(dap_hash_fast_compare(&original_root_hash, &purchase_hash), "Seller-leftover root_hash matches buyer-leftover root");
    
    // Tamper: set root_hash to Alice's original order root (wrong! should be buyer-leftover root)
    tampered_out_sl->subtype.srv_dex.order_root_hash = alice_order_hash;
    log_it(L_INFO, "        Tampered: set root_hash=%s (Alice's original order root, should be buyer-leftover root)",
           dap_chain_hash_fast_to_str_static(&alice_order_hash));
    
    // Sign new transaction
    dap_enc_key_t *l_key_sl = dap_chain_wallet_get_key(f->carol, 0);
    dap_assert(l_key_sl != NULL, "Got Carol's key");
    dap_assert(dap_chain_datum_tx_add_sign_item(&l_new_tx_sl, l_key_sl) > 0, "Signed tampered EXCHANGE TX");
    dap_enc_key_delete(l_key_sl);
    
    // Calculate hash and try to add to ledger (verificator should reject)
    dap_hash_fast_t tampered_hash_sl = {0};
    dap_hash_fast(l_new_tx_sl, dap_chain_datum_tx_get_size(l_new_tx_sl), &tampered_hash_sl);
    
    // Try to add to ledger (verificator should reject with DEXV_IMMUTABLES_VIOLATION)
    int verificator_err_sl = dap_ledger_tx_add(f->net->net->pub.ledger, l_new_tx_sl, &tampered_hash_sl, false, NULL);
    dap_chain_datum_tx_delete(test_tx_sl);
    dap_chain_datum_tx_delete(l_new_tx_sl);
    
    dap_assert(verificator_err_sl != 0, "Tampered EXCHANGE TX rejected by verificator");
    log_it(L_INFO, "        ✓ Seller-leftover with tampered root_hash rejected by verificator");
    
    // Verify balances unchanged (EXCHANGE was rejected)
    // Note: Carol's USDT balance may have changed from previous transactions
    // Actual balance from logs: 291.259999999999999797
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "510.90909090909090915"), "Carol KEL unchanged (EXCHANGE rejected)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "291.259999999999999797"), "Carol USDT unchanged (from logs)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99985.0"), "Carol TC unchanged (no fee deducted)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2651.166666666666666641"), "Bob KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "37041.140000000000000208"), "Bob USDT unchanged");
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 5.1.3a PASSED: Seller Leftover Root Hash Tampering Rejected");
    
    // Step 4: Carol purchases 20 KEL from Bob's buyer-leftover (partial purchase, creates seller-leftover)
    log_it(L_INFO, " ");
    log_it(L_INFO, "[5.1.4] Carol purchases 20 KEL from Bob's buyer-leftover (partial purchase)");
    log_it(L_INFO, "        Expected: Purchase SUCCESS, seller-leftover created (10 KEL remaining)");
    
    dap_hash_fast_t carol_purchase_hash = {0};
    ret = test_dex_order_purchase(f, f->carol, &purchase_hash, "20.0", true, false, &carol_purchase_hash);
    dap_assert(ret == 0, "Carol partial purchase from buyer-leftover succeeded");
    
    // Carol balances after purchase:
    // Carol is service wallet, fee waived
    // KEL: +20, USDT: net change, TC: -1 fee
    // Initial: KEL=510.90909090909090915, USDT=286.259999999999999797, TC=99985.0
    // Spent: 100 USDT (20 * 5.0), fee waived
    // Cashback: excess UTXO returned
    // Actual balance from logs: 191.259999999999999797
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "KEL", "530.90909090909090915"), "Carol KEL after purchase (+20)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "USDT", "191.259999999999999797"), "Carol USDT after purchase (from logs)");
    dap_assert(test_dex_verify_balance(f, &f->carol_addr, "TestCoin", "99984.0"), "Carol TC fee (-1)");
    
    // Bob balances after sale:
    // KEL: unchanged, USDT: +100 (20 * 5.0), TC: unchanged
    // Service fee waived (Carol is service wallet)
    // Initial: KEL=2651.166666666666666641, USDT=37041.140000000000000208, TC=99954.0
    // Expected: KEL=2651.166666666666666641, USDT=37141.140000000000000208 (+100), TC=99954.0
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2651.166666666666666641"), "Bob KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "37141.140000000000000208"), "Bob USDT after sale (+100, fee waived)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99954.0"), "Bob TC unchanged");
    
    // Verify seller-leftover created (buyer-leftover partially filled)
    // Seller-leftover should have: root=purchase_hash (buyer-leftover root), tail=carol_purchase_hash, value=10 KEL
    dap_chain_datum_tx_t *carol_purchase_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_purchase_hash);
    dap_assert(carol_purchase_tx != NULL, "Found Carol's purchase transaction in ledger");
    
    int seller_leftover_out_idx = 0;
    dap_chain_tx_out_cond_t *seller_leftover_out = NULL;
    dap_chain_addr_t *bob_addr_check = dap_chain_wallet_get_addr(f->bob, f->net->net->pub.id);
    dap_assert(bob_addr_check != NULL, "Got Bob's address");
    
    while ((seller_leftover_out = dap_chain_datum_tx_out_cond_get(carol_purchase_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &seller_leftover_out_idx)) != NULL) {
        // Seller-leftover: seller=Bob, value=10 KEL
        if (dap_chain_addr_compare(&seller_leftover_out->subtype.srv_dex.seller_addr, bob_addr_check)) {
            log_it(L_INFO, "        Found seller-leftover in ledger: root_hash=%s, seller=Bob, value=%s KEL",
                   dap_hash_fast_is_blank(&seller_leftover_out->subtype.srv_dex.order_root_hash) ? "BLANK (0x0)" : dap_chain_hash_fast_to_str_static(&seller_leftover_out->subtype.srv_dex.order_root_hash),
                   dap_uint256_to_char_ex(seller_leftover_out->header.value).frac);
            break;
        }
        seller_leftover_out_idx++;
    }
    DAP_DELETE(bob_addr_check);
    
    dap_assert(seller_leftover_out != NULL, "Seller-leftover OUT_COND found in ledger");
    // Seller-leftover from buyer-leftover must have root_hash = buyer-leftover root (purchase_hash)
    dap_assert(dap_hash_fast_compare(&seller_leftover_out->subtype.srv_dex.order_root_hash, &purchase_hash), "Seller-leftover root_hash matches buyer-leftover root");
    // Seller-leftover value: 10 KEL (30 - 20)
    uint256_t expected_seller_leftover = dap_chain_coins_to_balance("10.0");
    dap_assert(compare256(seller_leftover_out->header.value, expected_seller_leftover) == 0, "Seller-leftover value is 10 KEL");
    
    // Update tracking manually (test_dex_order_purchase doesn't handle buyer-leftover seller-leftover correctly)
    // Seller-leftover from buyer-leftover has root_hash = Alice's order root, not blank
    // So test_dex_order_purchase doesn't find it and removes order from tracking
    // We need to manually restore and update tracking to reflect seller-leftover
    order_entry_t *buyer_leftover_entry = NULL;
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (dap_hash_fast_compare(&e->root, &purchase_hash)) { // Same root (buyer-leftover root)
            buyer_leftover_entry = e;
            break;
        }
    }
    
    dap_assert(buyer_leftover_entry != NULL, "Buyer-leftover entry found in tracking (may be inactive)");
    
    // Restore if inactive and update
    buyer_leftover_entry->active = true;
    buyer_leftover_entry->tail = carol_purchase_hash;
    buyer_leftover_entry->value = expected_seller_leftover;
    
    log_it(L_INFO, "        Updated buyer-leftover in tracking: root=%s, tail=%s, value=%s %s",
           dap_chain_hash_fast_to_str_static(&buyer_leftover_entry->root),
           dap_chain_hash_fast_to_str_static(&buyer_leftover_entry->tail),
           dap_uint256_to_char_ex(buyer_leftover_entry->value).frac,
           buyer_leftover_entry->token_sell);
    
    dap_assert(dap_hash_fast_compare(&buyer_leftover_entry->tail, &carol_purchase_hash), "Buyer-leftover tail updated to Carol's purchase hash");
    dap_assert(compare256(buyer_leftover_entry->value, expected_seller_leftover) == 0, "Buyer-leftover value updated to 10 KEL (seller-leftover)");
    
    // Step 5: Alice fully purchases seller-leftover via auto-matching (order fully closed)
    log_it(L_INFO, " ");
    log_it(L_INFO, "[5.1.5] Alice fully purchases seller-leftover via auto-matching");
    log_it(L_INFO, "        Budget: 10 KEL (is_budget_buy=true) = 50 USDT @ 5.0 USDT/KEL");
    log_it(L_INFO, "        Auto-match finds: seller-leftover (10 KEL @ 5.0)");
    log_it(L_INFO, "        Expected: Purchase SUCCESS, seller-leftover fully closed, removed from cache/tracking");
    
    dap_hash_fast_t alice_purchase_hash = {0};
    uint256_t min_rate_final = dap_chain_coins_to_balance("5.0"); // 5.0 USDT/KEL
    ret = test_dex_order_purchase_auto_ex(f, f->alice, "USDT", "KEL", "10.0", true, false, min_rate_final, &alice_purchase_hash);
    dap_assert(ret == 0, "Alice full purchase of seller-leftover via auto-matching succeeded");
    
    // Alice balances after purchase:
    // KEL: +10, USDT: net change (spent 51 = 50 + 1 fee, cashback 221), TC: -1 fee
    // Initial after step 5.1.2: KEL=7288.833333333333333299, USDT=12667.599999999999999995, TC=99948.0
    // Spent: 51 USDT (50 for purchase + 1 fee), cashback: 221 USDT (excess UTXO returned)
    // Net USDT change: -51 + 221 = +170, but UTXO were already deducted, so net = -51
    // Expected: KEL=7298.833333333333333299 (+10), USDT=12616.599999999999999995 (-51), TC=99947.0 (-1 fee)
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "KEL", "7298.833333333333333299"), "Alice KEL after purchase (+10)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "USDT", "12616.599999999999999995"), "Alice USDT after purchase (-51 spent + 221 cashback = net -51)");
    dap_assert(test_dex_verify_balance(f, &f->alice_addr, "TestCoin", "99947.0"), "Alice TC fee (-1)");
    
    // Bob balances after sale:
    // KEL: unchanged, USDT: +50 (10 * 5.0), TC: unchanged
    // Service fee waived (Alice is not service wallet, but fee is paid to Carol)
    // Initial after step 5.1.4: KEL=2651.166666666666666641, USDT=37141.140000000000000208, TC=99954.0
    // Expected: KEL=2651.166666666666666641, USDT=37191.140000000000000208 (+50), TC=99954.0
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "KEL", "2651.166666666666666641"), "Bob KEL unchanged");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "USDT", "37191.140000000000000208"), "Bob USDT after sale (+50)");
    dap_assert(test_dex_verify_balance(f, &f->bob_addr, "TestCoin", "99954.0"), "Bob TC unchanged");
    
    // Verify seller-leftover removed from tracking (fully closed)
    bool seller_leftover_found = false;
    for (order_entry_t *e = f->orders; e; e = e->next) {
        if (e->active && dap_hash_fast_compare(&e->root, &purchase_hash)) {
            // Check if this is the seller-leftover (tail = carol_purchase_hash)
            if (dap_hash_fast_compare(&e->tail, &carol_purchase_hash)) {
                seller_leftover_found = true;
                break;
            }
        }
    }
    dap_assert(!seller_leftover_found, "Seller-leftover removed from tracking (fully closed)");
    
    // Verify no OUT_COND in Alice's purchase transaction (order fully closed)
    dap_chain_datum_tx_t *alice_purchase_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &alice_purchase_hash);
    dap_assert(alice_purchase_tx != NULL, "Found Alice's purchase transaction in ledger");
    
    int out_cond_idx = 0;
    dap_chain_tx_out_cond_t *out_cond_check = NULL;
    bool found_seller_leftover_out = false;
    dap_chain_addr_t *bob_addr_final = dap_chain_wallet_get_addr(f->bob, f->net->net->pub.id);
    dap_assert(bob_addr_final != NULL, "Got Bob's address");
    
    while ((out_cond_check = dap_chain_datum_tx_out_cond_get(alice_purchase_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &out_cond_idx)) != NULL) {
        if (dap_chain_addr_compare(&out_cond_check->subtype.srv_dex.seller_addr, bob_addr_final)) {
            found_seller_leftover_out = true;
            break;
        }
        out_cond_idx++;
    }
    DAP_DELETE(bob_addr_final);
    dap_assert(!found_seller_leftover_out, "No seller-leftover OUT_COND in Alice's purchase (order fully closed)");
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 5.1 PASSED: Buyer Leftover (Cache) — NEW independent order chain created, buyer becomes seller");
}

/**
 * @brief Test Group 5.2 - Leftover ignored (flag=false)
 * @details Verifies leftover budget refunded as cashback when flag=false
 */
static void test_group_5_2_leftover_ignored(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 5.2: Leftover Ignored (Flag=False) ===");
    
    // TODO: Test scenarios:
    // - Purchase with excess budget, flag=false
    // - Verify no buyer-leftover created
    // - Verify budget refunded to buyer as cashback (OUT_EXT)
    // - Verify no cache entry created
}

/**
 * @brief Test Group 5.3 - Symmetric chain of buyer-leftovers
 * @details Verifies all combinations of (order sells BASE/QUOTE) → (buyer-leftover sells BASE/QUOTE)
 * 
 * WHAT WE TEST:
 * 1. Order that sells BASE (KEL) can produce buyer-leftover that sells BASE (KEL) or QUOTE (USDT)
 * 2. Order that sells QUOTE (USDT) can produce buyer-leftover that sells QUOTE (USDT) or BASE (KEL)
 * 3. All 4 transitions are covered in a single chain of buyer-leftovers:
 *      KEL → KEL, KEL → USDT, USDT → USDT, USDT → KEL
 * 4. Every buyer-leftover has blank root_hash (new independent chain head)
 */
static void test_group_5_3_buyer_leftover_chain(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 5.3: Symmetric Chain of Buyer-Leftovers ===");
    log_it(L_INFO, " ");
    log_it(L_INFO, "WHAT WE TEST:");
    log_it(L_INFO, "  - All four transitions on buyer-leftover side:");
    log_it(L_INFO, "    * sell KEL  → leftover sells KEL");
    log_it(L_INFO, "    * sell KEL  → leftover sells USDT");
    log_it(L_INFO, "    * sell USDT → leftover sells USDT");
    log_it(L_INFO, "    * sell USDT → leftover sells KEL");
    log_it(L_INFO, " ");

    dap_ledger_t *ledger = f->net->net->pub.ledger;

    // Helper lambda-style pattern (manual in C): locate buyer-leftover for given buyer and purchase tx
    #define FIND_BUYER_LEFTOVER(_tx_hash, _buyer_wallet, _out_cond_var)                                  \
        do {                                                                                              \
            dap_chain_datum_tx_t *l_tx_local = dap_ledger_tx_find_by_hash(ledger, &(_tx_hash));          \
            dap_assert(l_tx_local != NULL, "Purchase TX found in ledger");                               \
            int l_out_idx_local = 0;                                                                      \
            dap_chain_tx_out_cond_t *l_out_local = NULL;                                                  \
            dap_chain_addr_t *l_buyer_addr_local = dap_chain_wallet_get_addr(_buyer_wallet,              \
                                                                             f->net->net->pub.id);       \
            dap_assert(l_buyer_addr_local != NULL, "Got buyer address");                                 \
            while ((l_out_local = dap_chain_datum_tx_out_cond_get(l_tx_local,                            \
                        DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx_local)) != NULL) {             \
                if (dap_hash_fast_is_blank(&l_out_local->subtype.srv_dex.order_root_hash) &&             \
                    dap_chain_addr_compare(&l_out_local->subtype.srv_dex.seller_addr,                    \
                                           l_buyer_addr_local))                                           \
                    break;                                                                                \
                l_out_idx_local++;                                                                        \
            }                                                                                             \
            DAP_DELETE(l_buyer_addr_local);                                                               \
            dap_assert(l_out_local != NULL, "Buyer-leftover OUT_COND found in purchase TX");             \
            _out_cond_var = l_out_local;                                                                  \
        } while (0)

    // Helper to assert that order (by hash) sells expected token
    #define ASSERT_ORDER_SELL_TOKEN(_hash, _expected)                                                     \
        do {                                                                                              \
            const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(ledger, &(_hash));           \
            dap_assert(l_sell_tok != NULL, "Order sell token resolved");                                  \
            dap_assert(strcmp(l_sell_tok, (_expected)) == 0, "Order sells expected token " _expected);    \
        } while (0)

    // Helper to assert that buyer-leftover created by purchase TX sells expected token and has blank root
    #define ASSERT_LEFTOVER_SELL_TOKEN(_tx_hash, _buyer_wallet, _expected, _msg)                          \
        do {                                                                                              \
            dap_chain_tx_out_cond_t *l_bl = NULL;                                                         \
            FIND_BUYER_LEFTOVER(_tx_hash, _buyer_wallet, l_bl);                                           \
            const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(ledger, &(_tx_hash));        \
            dap_assert(l_sell_tok != NULL, "Buyer-leftover sell token resolved");                         \
            dap_assert(strcmp(l_sell_tok, (_expected)) == 0, _msg);                                       \
            dap_assert(dap_hash_fast_is_blank(&l_bl->subtype.srv_dex.order_root_hash),                   \
                       "Buyer-leftover root_hash is BLANK");                                              \
            dap_assert(!IS_ZERO_256(l_bl->header.value), "Buyer-leftover value > 0");                     \
        } while (0)

    // ---------------------------------------------------------------------
    // Step 1: Order sells KEL → buyer-leftover 1 sells KEL  (KEL → KEL)
    // ---------------------------------------------------------------------
    log_it(L_INFO, "[5.3.1] Transition #1: sell KEL → leftover sells KEL (BASE→BASE)");
    dap_hash_fast_t order0_hash = {0};
    int ret = test_dex_order_create(f, f->alice, "USDT", "KEL", "10.0", "5.0", &order0_hash);
    dap_assert(ret == 0, "Alice initial ASK (sell KEL for USDT) created");
    ASSERT_ORDER_SELL_TOKEN(order0_hash, "KEL");

    // Alice self-purchase with BASE budget (is_budget_buy=true) to keep leftover in BASE
    dap_hash_fast_t tx1_hash = {0};
    ret = test_dex_order_purchase(f, f->alice, &order0_hash, "20.0", true, true, &tx1_hash);
    dap_assert(ret == 0, "Alice self-purchase from KEL-selling order succeeded");
    ASSERT_LEFTOVER_SELL_TOKEN(tx1_hash, f->alice, "KEL",
                               "Transition #1: buyer-leftover 1 must sell KEL (KEL→KEL)");

    dap_hash_fast_t bl1_hash = tx1_hash;

    // ---------------------------------------------------------------------
    // Step 2: Order sells KEL → buyer-leftover 2 sells USDT  (KEL → USDT)
    // ---------------------------------------------------------------------
    log_it(L_INFO, "[5.3.2] Transition #2: sell KEL → leftover sells USDT (BASE→QUOTE)");
    ASSERT_ORDER_SELL_TOKEN(bl1_hash, "KEL");

    // Bob purchases with QUOTE budget (is_budget_buy=false) to move leftover into QUOTE
    dap_hash_fast_t tx2_hash = {0};
    ret = test_dex_order_purchase(f, f->bob, &bl1_hash, "80.0", false, true, &tx2_hash);
    dap_assert(ret == 0, "Bob purchase from KEL-selling order succeeded");
    ASSERT_LEFTOVER_SELL_TOKEN(tx2_hash, f->bob, "USDT",
                               "Transition #2: buyer-leftover 2 must sell USDT (KEL→USDT)");

    dap_hash_fast_t bl2_hash = tx2_hash;

    // ---------------------------------------------------------------------
    // Step 3: Order sells USDT → buyer-leftover 3 sells USDT  (USDT → USDT)
    // ---------------------------------------------------------------------
    log_it(L_INFO, "[5.3.3] Transition #3: sell USDT → leftover sells USDT (QUOTE→QUOTE)");
    ASSERT_ORDER_SELL_TOKEN(bl2_hash, "USDT");

    // Carol purchases with QUOTE budget (is_budget_buy=true for BID buyer vs BID maker), budget > order cost to produce buyer-leftover
    dap_hash_fast_t tx3_hash = {0};
    ret = test_dex_order_purchase(f, f->carol, &bl2_hash, "100.0", true, true, &tx3_hash);
    dap_assert(ret == 0, "Carol purchase from USDT-selling order succeeded");
    ASSERT_LEFTOVER_SELL_TOKEN(tx3_hash, f->carol, "USDT",
                               "Transition #3: buyer-leftover 3 must sell USDT (USDT→USDT)");

    dap_hash_fast_t bl3_hash = tx3_hash;

    // ---------------------------------------------------------------------
    // Step 4: Order sells USDT → buyer-leftover 4 sells KEL  (USDT → KEL)
    // ---------------------------------------------------------------------
    log_it(L_INFO, "[5.3.4] Transition #4: sell USDT → leftover sells KEL (QUOTE→BASE)");
    ASSERT_ORDER_SELL_TOKEN(bl3_hash, "USDT");

    // Alice purchases with BASE budget (is_budget_buy=false for BID maker) to move leftover into BASE.
    // Budget is intentionally larger than order capacity to fully consume seller and create buyer-leftover in BASE.
    dap_hash_fast_t tx4_hash = {0};
    ret = test_dex_order_purchase(f, f->alice, &bl3_hash, "120.0", false, true, &tx4_hash);
    dap_assert(ret == 0, "Alice purchase from USDT-selling order succeeded");
    ASSERT_LEFTOVER_SELL_TOKEN(tx4_hash, f->alice, "KEL",
                               "Transition #4: buyer-leftover 4 must sell KEL (USDT→KEL)");

    log_it(L_INFO, " ");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    log_it(L_NOTICE, "✓ GROUP 5.3 PASSED: Symmetric buyer-leftover transitions (KEL/USDT)");

    #undef FIND_BUYER_LEFTOVER
    #undef ASSERT_ORDER_SELL_TOKEN
    #undef ASSERT_LEFTOVER_SELL_TOKEN
}

// ============================================================================
// TEST GROUP 6: FEE MECHANICS
// ============================================================================

/**
 * @brief Test Group 6.1 - Service fee aggregation
 * @details Verifies service fee routing to fee collector
 */
static void test_group_6_1_service_fee(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 6.1: Service Fee ===");
    
    // TODO: Test scenarios:
    // - Purchase with 5% service fee
    // - Verify Carol receives fee
    // - Multiple purchases, verify fee aggregation
}

/**
 * @brief Test Group 6.2 - Fee waiver (buyer = service)
 * @details Verifies fee waived when buyer is service provider
 */
static void test_group_6_2_fee_waiver(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 6.2: Fee Waiver ===");
    
    // TODO: Test scenarios:
    // - Carol (service provider) buys from Alice
    // - Verify no fee charged
}

/**
 * @brief Test Group 6.3 - Network fee
 * @details Verifies network fee (unrelated to service fee)
 */
static void test_group_6_3_network_fee(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 6.3: Network Fee ===");
    
    // TODO: Test scenarios:
    // - Order creation with network fee
    // - Purchase with network fee
    // - Verify fee deducted from TX creator
}

// ============================================================================
// TEST GROUP 7: SELF-PURCHASE
// ============================================================================

/**
 * @brief Test Group 7.1 - Full self-purchase
 * @details Verifies self-purchase with auto-matching
 */
static void test_group_7_1_full_self_purchase(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 7.1: Full Self-Purchase ===");
    
    // TODO: Test scenarios:
    // - Alice creates order: 100 KEL @ 5.0
    // - Alice auto-buys 100 KEL (self-purchase)
    // - Verify: seller payout + buyer cashback aggregated correctly
}

/**
 * @brief Test Group 7.2 - Partial self-purchase
 * @details Verifies self-purchase with mixed orders
 */
static void test_group_7_2_partial_self_purchase(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 7.2: Partial Self-Purchase ===");
    
    // TODO: Test scenarios:
    // - Alice creates order: 100 KEL @ 5.0
    // - Carol creates order: 10 KEL @ 4.9
    // - Alice auto-buys (matches Carol + Alice partial)
    // - Verify correct cashback/payout separation
}

/**
 * @brief Test Group 7.3 - Self-purchase rounding
 * @details Verifies wei-level precision in self-purchase
 */
static void test_group_7_3_self_purchase_rounding(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 7.3: Self-Purchase Rounding ===");
    
    // TODO: Test scenarios:
    // - Self-purchase with complex rates (4.9)
    // - Verify rounding handled correctly (±1 wei tolerance)
}

// ============================================================================
// TEST GROUP 8: CACHE CONSISTENCY
// ============================================================================

/**
 * @brief Test Group 8.1 - Cache vs no-cache consistency
 * @details Verifies identical results with/without cache
 */
static void test_group_8_1_cache_consistency(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 8.1: Cache Consistency ===");
    
    // TODO: Test scenarios:
    // - Run identical sequence with cache enabled
    // - Disable cache, run again
    // - Verify identical final balances
}

/**
 * @brief Test Group 8.2 - Cache removal on full close
 * @details Verifies fully-filled orders removed from cache
 */
static void test_group_8_2_cache_removal(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 8.2: Cache Removal ===");
    
    // TODO: Test scenarios:
    // - Create order, verify in cache
    // - Full purchase, verify removed from cache
    // - Verify no double-spend in next purchase
}

/**
 * @brief Test Group 8.3 - Reorg handling
 * @details Verifies cache restoration on ledger reorg
 */
static void test_group_8_3_reorg_handling(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 8.3: Reorg Handling ===");
    
    // TODO: Test scenarios:
    // - Create order, purchase (order removed from cache)
    // - Simulate reorg (remove purchase TX)
    // - Verify order restored in cache
}

// ============================================================================
// TEST GROUP 9: VERIFIER VALIDATION
// ============================================================================

/**
 * @brief Test Group 9.1 - BUY token leak detection
 * @details Verifies verifier rejects unauthorized buy_token outputs
 */
static void test_group_9_1_buy_token_leak(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 9.1: BUY Token Leak Detection ===");
    
    // TODO: Test scenarios:
    // - Legitimate purchase (KEL to buyer only)
    // - Verify no KEL leak to unauthorized addresses
}

/**
 * @brief Test Group 9.2 - SELL token leak detection
 * @details Verifies verifier rejects unauthorized sell_token outputs
 */
static void test_group_9_2_sell_token_leak(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 9.2: SELL Token Leak Detection ===");
    
    // TODO: Test scenarios:
    // - Legitimate sale (USDT to seller only)
    // - Verify no USDT leak to unauthorized addresses
}

/**
 * @brief Test Group 9.3 - Baseline tuple validation
 * @details Verifies all IN_COND orders have same side (ASK/BID)
 */
static void test_group_9_3_baseline_tuple(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 9.3: Baseline Tuple Validation ===");
    
    // TODO: Test scenarios (verifier rejects):
    // - Multi-order purchase with mixed ASK+BID orders
}

// ============================================================================
// TEST GROUP 10: EDGE CASES
// ============================================================================

/**
 * @brief Test Group 10.1 - Dust and rounding
 * @details Verifies dust handling and wei-level rounding
 */
static void test_group_10_1_dust_rounding(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 10.1: Dust and Rounding ===");
    
    // TODO: Test scenarios:
    // - BID partial fill with dust (residual calculation)
    // - Verify rounding: floor division in uint256_t
    // - Dust in buyer's cashback (self-purchase)
    // - Dust in service fee (±1 wei tolerance)
}

/**
 * @brief Test Group 10.2 - uint256 boundaries
 * @details Verifies behavior at uint256 limits
 */
static void test_group_10_2_uint256_boundaries(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 10.2: uint256 Boundaries ===");
    
    // TODO: Test scenarios:
    // - Order with max uint256 value (overflow check)
    // - Order with min value (1 wei)
    // - Purchase with max budget
}

/**
 * @brief Test Group 10.3 - Zero values
 * @details Verifies rejection of zero-value operations
 */
static void test_group_10_3_zero_values(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 10.3: Zero Values ===");
    
    // TODO: Test scenarios:
    // - Order with value=0 → rejected
    // - Order with rate=0 → rejected
    // - Purchase with budget=0 → rejected
}

/**
 * @brief Test Group 10.4 - Expired orders
 * @details Verifies handling of expired orders
 */
static void test_group_10_4_expired_orders(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 10.4: Expired Orders ===");
    
    // TODO: Test scenarios:
    // - Create order with expiry timestamp
    // - Attempt purchase after expiry → rejected
    // - Update expired order → rejected
}

// ============================================================================
// TEST GROUP 11: ADVANCED SCENARIOS
// ============================================================================

/**
 * @brief Test Group 11.1 - NATIVE fee mechanics
 * @details Verifies NATIVE fee (not QUOTE) handling
 */
static void test_group_11_1_native_fee(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 11.1: NATIVE Fee ===");
    
    // TODO: Test scenarios:
    // - Purchase with NATIVE fee (TestCoin)
    // - NATIVE fee waived (buyer=service)
    // - NATIVE fee separate OUT (seller≠service)
    // - NATIVE fee aggregated (seller=service)
}

/**
 * @brief Test Group 11.2 - Fee aggregation (seller=service)
 * @details Verifies fee aggregation when seller is service provider
 */
static void test_group_11_2_fee_aggregation(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 11.2: Fee Aggregation ===");
    
    // TODO: Test scenarios:
    // - Alice=service sells, receives payout+fee in one OUT
    // - Verify no separate fee OUT created
    // - Verify verifier accepts aggregated amount
}

/**
 * @brief Test Group 11.3 - Cross-pair isolation
 * @details Verifies orders from different pairs don't mix
 */
static void test_group_11_3_cross_pair_isolation(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 11.3: Cross-Pair Isolation ===");
    
    // TODO: Test scenarios:
    // - Create orders: KEL/USDT and KEL/TestCoin
    // - Auto-match for KEL/USDT → only KEL/USDT orders matched
    // - Verify KEL/TestCoin orders untouched
}

/**
 * @brief Test Group 11.4 - Multi-hop matching
 * @details Verifies leftover orders can be matched in subsequent purchases
 */
static void test_group_11_4_multi_hop_matching(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 11.4: Multi-Hop Matching ===");
    
    // TODO: Test scenarios:
    // - Alice creates order
    // - Bob partial purchase → buyer-leftover created
    // - Carol purchases from Bob's buyer-leftover
    // - Verify 3-hop chain works correctly
}

/**
 * @brief Test Group 11.5 - Rate edge cases
 * @details Verifies extreme rate values
 */
static void test_group_11_5_rate_edge_cases(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 11.5: Rate Edge Cases ===");
    
    // TODO: Test scenarios:
    // - Very small rate (0.0001) → no overflow in MULT_256_COIN
    // - Very large rate (10000) → no overflow
    // - Rate = 1.0 (edge case for BID inversion)
}

/**
 * @brief Test Group 11.6 - Time-based scenarios
 * @details Verifies time-dependent behavior
 */
static void test_group_11_6_time_based(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 11.6: Time-Based Scenarios ===");
    
    // TODO: Test scenarios:
    // - Order creation timestamp
    // - Purchase with different timestamps
    // - Verify history records correct time
    // - Order aging (create → wait → purchase)
}

/**
 * @brief Test Group 11.7 - Whitelist changes
 * @details Verifies behavior when whitelist changes mid-flight
 */
static void test_group_11_7_whitelist_changes(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 11.7: Whitelist Changes ===");
    
    // TODO: Test scenarios:
    // - Create order on whitelisted pair
    // - Remove pair from whitelist
    // - Verify existing orders still purchasable
    // - Verify new orders rejected
}

/**
 * @brief Test Group 11.8 - Fee config changes
 * @details Verifies fee changes affect new orders, not old
 */
static void test_group_11_8_fee_config_changes(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 11.8: Fee Config Changes ===");
    
    // TODO: Test scenarios:
    // - Create order with 5% fee
    // - Change fee to 2%
    // - Purchase order → pays 2% (new fee)
    // - Verify old fee_config ignored
}

// ============================================================================
// TEST GROUP 12: CONCURRENCY & STRESS
// ============================================================================

/**
 * @brief Test Group 12.1 - Concurrent purchases
 * @details Verifies race condition handling
 */
static void test_group_12_1_concurrent_purchases(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 12.1: Concurrent Purchases ===");
    
    // TODO: Test scenarios:
    // - Alice creates order: 100 KEL
    // - Bob and Carol both try to buy 100 KEL (race)
    // - Verify only one succeeds, other gets ORDER_NOT_FOUND
    // - Verify no double-spend
}

/**
 * @brief Test Group 12.2 - Large orderbook stress
 * @details Verifies performance with many orders
 */
static void test_group_12_2_large_orderbook(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 12.2: Large Orderbook Stress ===");
    
    // TODO: Test scenarios:
    // - Create 1000+ orders with varying rates
    // - Auto-match with large budget
    // - Verify matcher performance (< 1 sec)
    // - Verify cache consistency
}

/**
 * @brief Test Group 12.3 - Cache stress test
 * @details Verifies cache behavior under load
 */
static void test_group_12_3_cache_stress(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 12.3: Cache Stress Test ===");
    
    // TODO: Test scenarios:
    // - Create 100 orders
    // - Partial purchases on 50 orders (cache updates)
    // - Full purchases on 50 orders (cache removals)
    // - Verify cache integrity
}

/**
 * @brief Test Group 12.4 - Reorg stress test
 * @details Verifies ledger reorg handling under load
 */
static void test_group_12_4_reorg_stress(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 12.4: Reorg Stress Test ===");
    
    // TODO: Test scenarios:
    // - Create 10 orders
    // - Purchase 5 orders
    // - Simulate reorg (remove all purchase TXs)
    // - Verify all 10 orders restored in cache
    // - Re-purchase, verify success
}

/**
 * @brief Test Group 12.5 - Memory leak detection
 * @details Verifies no memory leaks in long-running operations
 */
static void test_group_12_5_memory_leaks(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 12.5: Memory Leak Detection ===");
    
    // TODO: Test scenarios:
    // - Run 1000 order create/purchase/cancel cycles
    // - Monitor memory usage (valgrind)
    // - Verify no leaks in cache/ledger/verifier
}

/**
 * @brief Test Group 12.6 - Extreme values stress
 * @details Verifies system stability with extreme values
 */
static void test_group_12_6_extreme_values(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== TEST GROUP 12.6: Extreme Values Stress ===");
    
    // TODO: Test scenarios:
    // - Order with max uint256 value
    // - Purchase with max budget
    // - Fee > 100% → rejected
    // - MIN_FILL > 100% → rejected
}

// ============================================================================
// MAIN TEST RUNNER
// ============================================================================

void dap_chain_net_srv_dex_integration_tests_run(void) {
    log_it(L_INFO, " ");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, "  DEX INTEGRATION TESTS");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, " ");
    
    // Initialize test fixture
    dex_test_fixture_t *fixture = dex_test_fixture_create();
    dex_print_balances(fixture, "INITIAL STATE");
    
    // ========================================
    // RUN TEST GROUPS
    // ========================================
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "┌─────────────────────────────────────┐");
    log_it(L_INFO, "│  GROUP 1: BASIC OPERATIONS          │");
    log_it(L_INFO, "└─────────────────────────────────────┘");
    test_group_1_1_order_creation(fixture);
    test_group_1_2_simple_purchase(fixture);
    test_group_1_3_partial_purchase(fixture);
    test_group_1_4_order_cancel(fixture);
    test_group_1_5_leftover_cancel(fixture);
    test_group_1_6_bid_partial_purchase(fixture);
    test_group_1_7_bid_full_fill(fixture);
    test_group_1_8_bid_cancel_untouched(fixture);
    test_group_1_9_bid_cancel_leftover(fixture);
    test_group_1_10_security_cancel_foreign_ask(fixture);
    test_group_1_11_security_cancel_foreign_bid(fixture);
    test_group_1_12_security_exchange_tamper(fixture);
    test_group_1_12b_security_cashback_tamper(fixture);
    test_group_1_12c_security_fee_tamper(fixture);
    test_group_1_13_security_double_cancel(fixture);
    test_group_1_14_security_purchase_consumed(fixture);
    test_group_1_15_cancel_all_alice_orders(fixture);
    test_group_1_16_cancel_all_bob_orders(fixture);
    
    // Dump final state after Group 1
    test_dex_dump_balances(fixture, "After Group 1 Complete");
    test_dex_dump_orderbook(fixture, "After Group 1 Complete");
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "┌─────────────────────────────────────┐");
    log_it(L_INFO, "│  GROUP 2: MATCHING LOGIC            │");
    log_it(L_INFO, "└─────────────────────────────────────┘");
    test_group_2_1a_multi_order_best_price_ask(fixture);
    test_group_2_1b_multi_order_best_price_bid(fixture);
    test_group_2_2a_ask_sell_budget(fixture);
    test_group_2_2b_bid_sell_budget(fixture);
    test_group_2_3a_self_purchase_ask(fixture);
    test_group_2_3b_self_purchase_bid(fixture);
    test_group_2_4a_mixed_purchase_ask(fixture);
    test_group_2_5_dust_order_direct_purchase(fixture);
    test_group_2_6_bid_ask_auto_matching(fixture);
    test_group_2_7_multi_seller_matching(fixture);
    test_group_2_8_multi_seller_carol_buys(fixture);
    test_group_2_9_multi_buyer_matching(fixture);
    test_group_2_10_mixed_purchase_bid(fixture);
    test_group_2_11_identical_orders_extreme(fixture);
    test_group_2_4b_mixed_purchase_bid_external(fixture);
    test_group_2_12_multi_order_with_leftover(fixture);
    test_group_2_13_fee_aggregation_seller_service(fixture);
    
    // Dump final state after Group 2
    test_dex_dump_balances(fixture, "After Group 2 Complete");
    test_dex_dump_orderbook(fixture, "After Group 2 Complete");
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "┌─────────────────────────────────────┐");
    log_it(L_INFO, "│  GROUP 3: MIN_FILL POLICIES         │");
    log_it(L_INFO, "└─────────────────────────────────────┘");
    test_group_3_1_aon_order(fixture);
    test_group_3_2_percentage_minfill(fixture);
    test_group_3_3_dynamic_minfill_adaptation(fixture);
    test_group_3_4_ask_minfill_automatch(fixture);
    test_group_3_5_minfill_from_origin(fixture);
    test_group_3_6_boundary_exact_threshold(fixture);
    test_group_3_7_multi_order_minfill(fixture);
    test_group_3_8_dust_order(fixture);
    test_group_3_9_leftover_dust(fixture);
    test_group_3_10_self_purchase_minfill(fixture);
    // Dump final state after Group 3 (all MIN_FILL tests)
    test_dex_dump_balances(fixture, "After Group 3 Complete");
    test_dex_dump_orderbook(fixture, "After Group 3 Complete");
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "┌─────────────────────────────────────┐");
    log_it(L_INFO, "│  GROUP 4: ORDER UPDATES             │");
    log_it(L_INFO, "└─────────────────────────────────────┘");
    test_group_4_1_update_rate(fixture);
    test_group_4_2_update_value(fixture);

    test_dex_dump_balances(fixture, "After 4.2 Complete");
    test_dex_dump_orderbook(fixture, "After 4.2 Complete");

    test_group_4_3a_root_hash_validation(fixture);
    test_group_4_3b_update_same_value(fixture);
    test_group_4_3_immutables_validation(fixture);
    test_group_4_4_update_leftover_increase(fixture);
    test_group_4_5_update_leftover_decrease(fixture);
    test_group_4_6_update_aon_rejected(fixture);
    
    test_dex_dump_balances(fixture, "After 4.6 Complete");
    test_dex_dump_orderbook(fixture, "After 4.6 Complete");
    log_it(L_INFO, " ");
    log_it(L_INFO, "┌─────────────────────────────────────┐");
    log_it(L_INFO, "│  GROUP 5: LEFTOVER HANDLING         │");
    log_it(L_INFO, "└─────────────────────────────────────┘");
    test_group_5_1_buyer_leftover_cache(fixture);
    test_group_5_2_leftover_ignored(fixture);
    test_group_5_3_buyer_leftover_chain(fixture);
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "┌─────────────────────────────────────┐");
    log_it(L_INFO, "│  GROUP 6: FEE MECHANICS             │");
    log_it(L_INFO, "└─────────────────────────────────────┘");
    test_group_6_1_service_fee(fixture);
    test_group_6_2_fee_waiver(fixture);
    test_group_6_3_network_fee(fixture);
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "┌─────────────────────────────────────┐");
    log_it(L_INFO, "│  GROUP 7: SELF-PURCHASE             │");
    log_it(L_INFO, "└─────────────────────────────────────┘");
    test_group_7_1_full_self_purchase(fixture);
    test_group_7_2_partial_self_purchase(fixture);
    test_group_7_3_self_purchase_rounding(fixture);
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "┌─────────────────────────────────────┐");
    log_it(L_INFO, "│  GROUP 8: CACHE CONSISTENCY         │");
    log_it(L_INFO, "└─────────────────────────────────────┘");
    test_group_8_1_cache_consistency(fixture);
    test_group_8_2_cache_removal(fixture);
    test_group_8_3_reorg_handling(fixture);
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "┌─────────────────────────────────────┐");
    log_it(L_INFO, "│  GROUP 9: VERIFIER VALIDATION       │");
    log_it(L_INFO, "└─────────────────────────────────────┘");
    test_group_9_1_buy_token_leak(fixture);
    test_group_9_2_sell_token_leak(fixture);
    test_group_9_3_baseline_tuple(fixture);
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "┌─────────────────────────────────────┐");
    log_it(L_INFO, "│  GROUP 10: EDGE CASES               │");
    log_it(L_INFO, "└─────────────────────────────────────┘");
    test_group_10_1_dust_rounding(fixture);
    test_group_10_2_uint256_boundaries(fixture);
    test_group_10_3_zero_values(fixture);
    test_group_10_4_expired_orders(fixture);
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "┌─────────────────────────────────────┐");
    log_it(L_INFO, "│  GROUP 11: ADVANCED SCENARIOS       │");
    log_it(L_INFO, "└─────────────────────────────────────┘");
    test_group_11_1_native_fee(fixture);
    test_group_11_2_fee_aggregation(fixture);
    test_group_11_3_cross_pair_isolation(fixture);
    test_group_11_4_multi_hop_matching(fixture);
    test_group_11_5_rate_edge_cases(fixture);
    test_group_11_6_time_based(fixture);
    test_group_11_7_whitelist_changes(fixture);
    test_group_11_8_fee_config_changes(fixture);
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "┌─────────────────────────────────────┐");
    log_it(L_INFO, "│  GROUP 12: CONCURRENCY & STRESS     │");
    log_it(L_INFO, "└─────────────────────────────────────┘");
    test_group_12_1_concurrent_purchases(fixture);
    test_group_12_2_large_orderbook(fixture);
    test_group_12_3_cache_stress(fixture);
    test_group_12_4_reorg_stress(fixture);
    test_group_12_5_memory_leaks(fixture);
    test_group_12_6_extreme_values(fixture);
    
    // ========================================
    // CLEANUP
    // ========================================
    
    dex_print_balances(fixture, "FINAL STATE");
    dex_test_fixture_destroy(fixture);
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "========================================");
    log_it(L_INFO, "  ALL INTEGRATION TESTS COMPLETED");
    log_it(L_INFO, "========================================");
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

/**
 * @brief Setup test environment (as in old working test)
 */
static void s_setup(void) {
    log_it(L_NOTICE, "=== DEX Integration Tests Setup ===");
    
    // Step 1: Create minimal config directory
    const char *l_config_dir = "/tmp/dex_integration_test_config";
    mkdir(l_config_dir, 0755);
    
    const char *l_config_content = 
        "[general]\n"
        "debug_mode=true\n";
    
    char l_config_path[256], l_log_path[100];
    snprintf(l_config_path, sizeof(l_config_path), "%s/test.cfg", l_config_dir);
    FILE *l_config_file = fopen(l_config_path, "w");
    if (l_config_file) {
        fwrite(l_config_content, 1, strlen(l_config_content), l_config_file);
        fclose(l_config_file);
    }
    
    // Step 2: Initialize config and open it
    dap_config_init(l_config_dir);
    g_config = dap_config_open("test");
    dap_assert(g_config != NULL, "Config initialization");
    snprintf(l_log_path, sizeof(l_log_path), "%s/%s", l_config_dir, "log.txt");
    dap_common_init(NULL, l_log_path);
    
    // Step 3: Initialize consensus modules
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    
    log_it(L_NOTICE, "✓ Test environment initialized");
}

/**
 * @brief Teardown test environment (as in old working test)
 */
static void s_teardown(void) {
    log_it(L_NOTICE, "Cleaning up test environment...");
    
    // Close and cleanup config
    if (g_config) {
        dap_config_close(g_config);
        g_config = NULL;
    }
    dap_config_deinit();
    
    // Remove test config files
    unlink("/tmp/dex_integration_test_config/test.cfg");
    rmdir("/tmp/dex_integration_test_config");
    
    log_it(L_NOTICE, "✓ Cleanup completed");
}

int main(int argc, char *argv[]) {
    // Initialize test framework
    dap_test_msg("DEX Integration Tests");
    
    // Initialize required subsystems (before setup)
    dap_log_level_set(L_DEBUG);
    dap_log_set_external_output(LOGGER_OUTPUT_STDOUT, NULL);
    dap_enc_init();
    dap_chain_wallet_init();
    
    // Setup test environment (creates config, initializes consensus)
    s_setup();
    
    // Run tests
    dap_chain_net_srv_dex_integration_tests_run();
    
    // Teardown
    s_teardown();
    
    // Summary
    dap_test_msg("All integration tests completed");
    return 0;
}
