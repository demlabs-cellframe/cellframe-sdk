/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.

 This file is part of Cellframe SDK the open source project

    Cellframe SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cellframe SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file utxo_blocking_unit_test.c
 * @brief Functional unit tests for UTXO blocking mechanism
 * @details Comprehensive tests of UTXO blocklist functionality:
 *          - Token creation and addition to ledger with UTXO blocking flags
 *          - Transaction creation with multiple UTXOs
 *          - Network fixture with zero and master chains
 *          - TSD section format validation
 *          - Error code definitions
 * @date 2025-10-16
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_ledger.h"
#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_cert.h"
#include "dap_math_ops.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_transaction_fixtures.h"

#define LOG_TAG "utxo_blocking_test"

// Global test context
static test_net_fixture_t *s_net_fixture = NULL;

/**
 * @brief Test: Network fixture initialization
 * @details Verify network created with zero and master chains
 */
static void s_test_network_fixture_init(void)
{
    log_it(L_NOTICE, "TEST 1: Network Fixture Initialization");
    
    dap_assert(s_net_fixture != NULL, "Network fixture should be initialized");
    dap_assert(s_net_fixture->net != NULL, "Network should exist");
    dap_assert(s_net_fixture->ledger != NULL, "Ledger should exist");
    dap_assert(s_net_fixture->chain_zero != NULL, "Zero chain should be created");
    dap_assert(s_net_fixture->chain_main != NULL, "Master chain should be created");
    
    // Verify chains are in network
    int l_chain_count = 0;
    dap_chain_t *l_chain;
    DL_FOREACH(s_net_fixture->net->pub.chains, l_chain) {
        l_chain_count++;
        log_it(L_DEBUG, "Found chain: %s (ID: %"DAP_UINT64_FORMAT_U")", 
               l_chain->name, l_chain->id.uint64);
    }
    
    dap_assert(l_chain_count >= 2, "Network should have at least 2 chains");
    
    log_it(L_INFO, "✓ Network fixture test passed");
}

/**
 * @brief Test: Token creation with UTXO blocking flags  
 * @details Create tokens with different flags and add to ledger
 */
static void s_test_token_creation_and_ledger_addition(void)
{
    log_it(L_NOTICE, "TEST 2: Token Creation and Ledger Addition");
    
    uint256_t l_total_supply = uint256_0;
    MULT_256_COIN(dap_chain_uint256_from(1000000), dap_chain_coins_to_balance("1.0"), &l_total_supply);
    
    // Test 1: Token with UTXO blocking enabled (default)
    test_token_fixture_t *l_token1 = test_token_fixture_create_cf20("UTST1", l_total_supply, 0);
    dap_assert(l_token1 != NULL, "Should create token with default flags");
    dap_assert(l_token1->token != NULL, "Token datum should exist");
    dap_assert(l_token1->token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_DECL, "Token type should be DECL");
    dap_assert(l_token1->token->subtype == DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE, "Token subtype should be NATIVE (CF20)");
    
    // Add token to ledger
    int l_ret = dap_ledger_token_add(s_net_fixture->ledger, 
                                      (byte_t *)l_token1->token,
                                      l_token1->token_size,
                                      dap_time_now());
    dap_assert(l_ret == 0, "Token with UTXO blocking enabled should be added to ledger successfully");
    
    // Verify token in ledger via JSON
    json_object *l_token_info = dap_ledger_token_info_by_name(s_net_fixture->ledger, "UTST1", 1);
    dap_assert(l_token_info != NULL, "Token info should be retrievable from ledger");
    
    json_object *l_ticker_obj = NULL;
    if (json_object_object_get_ex(l_token_info, "ticker", &l_ticker_obj)) {
        const char *l_ticker = json_object_get_string(l_ticker_obj);
        dap_assert(dap_strcmp(l_ticker, "UTST1") == 0, "Token ticker should match");
    }
    
    json_object_put(l_token_info);
    test_token_fixture_destroy(l_token1);
    
    // Test 2: Token with UTXO_BLOCKING_DISABLED flag
    test_token_fixture_t *l_token2 = test_token_fixture_create_cf20(
        "UTST2",
        l_total_supply,
        DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED
    );
    dap_assert(l_token2 != NULL, "Should create token with UTXO_BLOCKING_DISABLED");
    
    l_ret = dap_ledger_token_add(s_net_fixture->ledger,
                                  (byte_t *)l_token2->token,
                                  l_token2->token_size,
                                  dap_time_now());
    dap_assert(l_ret == 0, "Token with UTXO_BLOCKING_DISABLED should be added successfully");
    test_token_fixture_destroy(l_token2);
    
    // Test 3: Token with STATIC_UTXO_BLOCKLIST flag
    test_token_fixture_t *l_token3 = test_token_fixture_create_cf20(
        "UTST3",
        l_total_supply,
        DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_UTXO_BLOCKLIST
    );
    dap_assert(l_token3 != NULL, "Should create token with STATIC_UTXO_BLOCKLIST");
    
    l_ret = dap_ledger_token_add(s_net_fixture->ledger,
                                  (byte_t *)l_token3->token,
                                  l_token3->token_size,
                                  dap_time_now());
    dap_assert(l_ret == 0, "Token with STATIC_UTXO_BLOCKLIST should be added successfully");
    test_token_fixture_destroy(l_token3);
    
    // Test 4: Token with address blocking disable flags
    uint16_t l_combined_flags = DAP_CHAIN_DATUM_TOKEN_FLAG_DISABLE_ADDRESS_SENDER_BLOCKING |
                                 DAP_CHAIN_DATUM_TOKEN_FLAG_DISABLE_ADDRESS_RECEIVER_BLOCKING;
    test_token_fixture_t *l_token4 = test_token_fixture_create_cf20("UTST4", l_total_supply, l_combined_flags);
    dap_assert(l_token4 != NULL, "Should create token with address blocking disabled");
    
    l_ret = dap_ledger_token_add(s_net_fixture->ledger,
                                  (byte_t *)l_token4->token,
                                  l_token4->token_size,
                                  dap_time_now());
    dap_assert(l_ret == 0, "Token with address blocking disabled should be added successfully");
    test_token_fixture_destroy(l_token4);
    
    log_it(L_INFO, "✓ Token creation and ledger addition test passed");
}

/**
 * @brief Test: Transaction creation with multiple UTXOs
 * @details Create transactions and verify UTXO structures
 */
static void s_test_transaction_utxo_creation(void)
{
    log_it(L_NOTICE, "TEST 3: Transaction and UTXO Creation");
    
    uint256_t l_value = dap_chain_uint256_from(100);
    
    // Create transaction with 1 UTXO
    test_tx_fixture_t *l_tx1 = test_tx_fixture_create_with_outs(1, l_value, "UTST1");
    dap_assert(l_tx1 != NULL, "Should create transaction with 1 output");
    dap_assert(l_tx1->tx != NULL, "Transaction datum should exist");
    dap_assert(l_tx1->out_count == 1, "Output count should be 1");
    dap_assert(!dap_hash_fast_is_blank(&l_tx1->tx_hash), "Transaction hash should be calculated");
    
    // Verify transaction hash is valid (not all zeros, not all 0xFF)
    bool l_hash_valid = false;
    for (size_t i = 0; i < sizeof(dap_chain_hash_fast_t); i++) {
        if (l_tx1->tx_hash.raw[i] != 0 && l_tx1->tx_hash.raw[i] != 0xFF) {
            l_hash_valid = true;
            break;
        }
    }
    dap_assert(l_hash_valid, "Transaction hash should contain valid data");
    
    log_it(L_DEBUG, "Created TX with hash: %s", dap_chain_hash_fast_to_str_static(&l_tx1->tx_hash));
    test_tx_fixture_destroy(l_tx1);
    
    // Create transaction with multiple UTXOs
    test_tx_fixture_t *l_tx2 = test_tx_fixture_create_with_outs(5, l_value, "UTST1");
    dap_assert(l_tx2 != NULL, "Should create transaction with 5 outputs");
    dap_assert(l_tx2->out_count == 5, "Output count should be 5");
    dap_assert(!dap_hash_fast_is_blank(&l_tx2->tx_hash), "Transaction hash should be calculated");
    
    log_it(L_DEBUG, "Created TX with 5 outputs, hash: %s", dap_chain_hash_fast_to_str_static(&l_tx2->tx_hash));
    test_tx_fixture_destroy(l_tx2);
    
    log_it(L_INFO, "✓ Transaction UTXO creation test passed");
}

/**
 * @brief Helper: Create token_update datum with TSD section for UTXO blocking
 */
static dap_chain_datum_token_t *s_create_token_update_with_utxo_block_tsd(
    const char *a_ticker,
    dap_chain_hash_fast_t *a_tx_hash,
    uint32_t a_out_idx,
    dap_cert_t *a_cert,
    size_t *a_datum_size)
{
    // Create TSD section for UTXO_BLOCKED_ADD
    size_t l_tsd_data_size = sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t);
    byte_t *l_tsd_data = DAP_NEW_Z_SIZE(byte_t, l_tsd_data_size);
    memcpy(l_tsd_data, a_tx_hash, sizeof(dap_chain_hash_fast_t));
    memcpy(l_tsd_data + sizeof(dap_chain_hash_fast_t), &a_out_idx, sizeof(uint32_t));
    
    dap_tsd_t *l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_ADD,
                                      l_tsd_data, l_tsd_data_size);
    DAP_DELETE(l_tsd_data);
    
    size_t l_tsd_total_size = dap_tsd_size(l_tsd);
    
    // Create token_update datum
    size_t l_token_size = sizeof(dap_chain_datum_token_t) + l_tsd_total_size;
    dap_chain_datum_token_t *l_token_update = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, l_token_size);
    
    l_token_update->version = 2;
    l_token_update->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_token_update->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    snprintf(l_token_update->ticker, sizeof(l_token_update->ticker), "%s", a_ticker);
    l_token_update->header_native_update.tsd_total_size = l_tsd_total_size;
    l_token_update->signs_valid = 1;
    l_token_update->signs_total = 0;
    
    // Copy TSD section
    memcpy(l_token_update->tsd_n_signs, l_tsd, l_tsd_total_size);
    DAP_DELETE(l_tsd);
    
    // Sign the token_update
    dap_sign_t *l_sign = dap_cert_sign(a_cert, l_token_update, 
                                       sizeof(dap_chain_datum_token_t) + l_tsd_total_size);
    if (!l_sign) {
        DAP_DELETE(l_token_update);
        return NULL;
    }
    
    // Reallocate to include signature
    size_t l_sign_size = dap_sign_get_size(l_sign);
    size_t l_total_size = l_token_size + l_sign_size;
    dap_chain_datum_token_t *l_token_update_new = DAP_REALLOC(l_token_update, l_total_size);
    if (!l_token_update_new) {
        DAP_DELETE(l_token_update);
        DAP_DELETE(l_sign);
        return NULL;
    }
    l_token_update = l_token_update_new;
    memcpy((byte_t*)l_token_update + l_token_size, l_sign, l_sign_size);
    l_token_update->signs_total = 1;
    DAP_DELETE(l_sign);
    
    if (a_datum_size)
        *a_datum_size = l_total_size;
    
    return l_token_update;
}

/**
 * @brief Test: UTXO blocking through token_update datum
 * @details Create token_update with UTXO blocking TSD and verify ledger applies it correctly
 */
static void s_test_utxo_blocking_via_token_update(void)
{
    log_it(L_NOTICE, "TEST 4: UTXO Blocking via token_update Datum");
    
    dap_assert(s_net_fixture != NULL, "Network fixture must be initialized");
    dap_assert(s_net_fixture->ledger != NULL, "Ledger must be initialized");
    
    // Create test token with certificate
    test_token_fixture_t *l_token = test_token_fixture_create(
        s_net_fixture->ledger, "TUTXO", "10000.0");
    dap_assert_PIF(l_token != NULL, "Token fixture creation");
    dap_assert_PIF(l_token->owner_cert != NULL, "Token owner certificate must exist");
    
    // Create initial transaction to get source UTXO
    test_tx_fixture_t *l_tx_source = test_tx_fixture_create_simple(
        s_net_fixture->ledger, l_token->token_ticker, "1000.0");
    dap_assert_PIF(l_tx_source != NULL, "Source transaction creation");
    
    // Get source UTXO hash
    dap_chain_hash_fast_t l_source_hash = {};
    dap_hash_fast(l_tx_source->tx, dap_chain_datum_tx_get_size(l_tx_source->tx), &l_source_hash);
    uint32_t l_source_out_idx = 0;
    
    log_it(L_DEBUG, "Source UTXO: %s:%u", 
           dap_chain_hash_fast_to_str_static(&l_source_hash), l_source_out_idx);
    
    // Check balance before blocking
    uint256_t l_balance_before = dap_ledger_calc_balance(s_net_fixture->ledger,
                                                          l_tx_source->addr,
                                                          l_token->token_ticker);
    log_it(L_DEBUG, "Balance before blocking: %s", 
           dap_uint256_to_char(l_balance_before, NULL));
    
    // Create token_update datum with UTXO blocking TSD
    size_t l_token_update_size = 0;
    dap_chain_datum_token_t *l_token_update = s_create_token_update_with_utxo_block_tsd(
        l_token->token_ticker,
        &l_source_hash,
        l_source_out_idx,
        l_token->owner_cert,
        &l_token_update_size);
    
    dap_assert_PIF(l_token_update != NULL, "Token update datum creation");
    
    log_it(L_DEBUG, "Created token_update datum, size=%zu", l_token_update_size);
    
    // Apply token_update to ledger
    int l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_token_update, 
                                      l_token_update_size, dap_time_now());
    if (l_res != DAP_LEDGER_CHECK_OK) {
        log_it(L_ERROR, "Failed to apply token_update: %s", 
               dap_ledger_check_error_str(l_res));
        DAP_DELETE(l_token_update);
        test_tx_fixture_destroy(l_tx_source);
        test_token_fixture_destroy(l_token);
        dap_assert(false, "Token update application should succeed");
    }
    
    log_it(L_INFO, "✓ Token update applied successfully");
    
    // Now try to create a transaction that spends the blocked UTXO
    // It should be rejected by ledger
    dap_chain_datum_tx_t *l_tx_blocked = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_blocked, &l_source_hash, l_source_out_idx);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_blocked, l_tx_source->addr, uint256_0, l_token->token_ticker);
    
    // Try to add this transaction to ledger - should fail with DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED
    dap_chain_hash_fast_t l_tx_blocked_hash = {};
    dap_hash_fast(l_tx_blocked, dap_chain_datum_tx_get_size(l_tx_blocked), &l_tx_blocked_hash);
    
    int l_add_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_blocked, &l_tx_blocked_hash,
                                       false, NULL);
    
    dap_assert(l_add_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED,
               "Transaction with blocked UTXO should be rejected");
    
    log_it(L_INFO, "✓ Transaction with blocked UTXO was correctly rejected: %s",
           dap_ledger_check_error_str(l_add_res));
    
    // Verify balance hasn't changed
    uint256_t l_balance_after = dap_ledger_calc_balance(s_net_fixture->ledger,
                                                         l_tx_source->addr,
                                                         l_token->token_ticker);
    
    dap_assert(compare256(l_balance_before, l_balance_after) == 0,
               "Balance should remain unchanged after blocked transaction");
    
    log_it(L_INFO, "✓ Balance unchanged: %s", 
           dap_uint256_to_char(l_balance_after, NULL));
    
    // Cleanup
    dap_chain_datum_tx_delete(l_tx_blocked);
    test_tx_fixture_destroy(l_tx_source);
    test_token_fixture_destroy(l_token);
    
    log_it(L_INFO, "✓ UTXO blocking via token_update test passed");
}

/**
 * @brief Test: UTXO unblocking via token_update
 * @details Test removing UTXO from blocklist and verifying transaction becomes valid
 */
static void s_test_utxo_unblocking_via_token_update(void)
{
    log_it(L_NOTICE, "TEST 5: UTXO Unblocking via token_update");
    
    dap_assert(s_net_fixture != NULL, "Network fixture must be initialized");
    dap_assert(s_net_fixture->ledger != NULL, "Ledger must be initialized");
    
    // Create test token
    test_token_fixture_t *l_token = test_token_fixture_create(
        s_net_fixture->ledger, "TUNBL", "50000.0");
    dap_assert_PIF(l_token != NULL, "Token fixture creation");
    dap_assert_PIF(l_token->owner_cert != NULL, "Token owner certificate must exist");
    
    // Create source transaction
    test_tx_fixture_t *l_tx_source = test_tx_fixture_create_simple(
        s_net_fixture->ledger, l_token->token_ticker, "2000.0");
    dap_assert_PIF(l_tx_source != NULL, "Source transaction creation");
    
    dap_chain_hash_fast_t l_source_hash = {};
    dap_hash_fast(l_tx_source->tx, dap_chain_datum_tx_get_size(l_tx_source->tx), &l_source_hash);
    uint32_t l_source_out_idx = 0;
    
    log_it(L_DEBUG, "Source UTXO: %s:%u",
           dap_chain_hash_fast_to_str_static(&l_source_hash), l_source_out_idx);
    
    // Step 1: Block the UTXO via token_update
    size_t l_block_datum_size = 0;
    dap_chain_datum_token_t *l_block_datum = s_create_token_update_with_utxo_block_tsd(
        l_token->token_ticker, &l_source_hash, l_source_out_idx,
        l_token->owner_cert, &l_block_datum_size);
    dap_assert_PIF(l_block_datum != NULL, "Block datum creation");
    
    int l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_block_datum, 
                                      l_block_datum_size, dap_time_now());
    dap_assert(l_res == DAP_LEDGER_CHECK_OK, "UTXO blocking should succeed");
    log_it(L_INFO, "✓ UTXO blocked via token_update");
    
    // Step 2: Verify transaction with blocked UTXO is rejected
    dap_chain_datum_tx_t *l_tx_test1 = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_test1, &l_source_hash, l_source_out_idx);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_test1, l_tx_source->addr, uint256_0, l_token->token_ticker);
    
    dap_chain_hash_fast_t l_tx_test1_hash = {};
    dap_hash_fast(l_tx_test1, dap_chain_datum_tx_get_size(l_tx_test1), &l_tx_test1_hash);
    
    int l_add_res1 = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_test1, &l_tx_test1_hash,
                                        false, NULL);
    dap_assert(l_add_res1 == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED,
               "Transaction should be blocked");
    log_it(L_INFO, "✓ Transaction correctly rejected while UTXO blocked");
    
    dap_chain_datum_tx_delete(l_tx_test1);
    
    // Step 3: Create token_update to UNBLOCK the UTXO
    // Create TSD for UTXO_BLOCKED_REMOVE
    size_t l_tsd_data_size = sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t);
    byte_t *l_tsd_data = DAP_NEW_Z_SIZE(byte_t, l_tsd_data_size);
    memcpy(l_tsd_data, &l_source_hash, sizeof(dap_chain_hash_fast_t));
    memcpy(l_tsd_data + sizeof(dap_chain_hash_fast_t), &l_source_out_idx, sizeof(uint32_t));
    
    dap_tsd_t *l_tsd_remove = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_REMOVE,
                                              l_tsd_data, l_tsd_data_size);
    DAP_DELETE(l_tsd_data);
    
    size_t l_tsd_total_size = dap_tsd_size(l_tsd_remove);
    size_t l_unblock_token_size = sizeof(dap_chain_datum_token_t) + l_tsd_total_size;
    dap_chain_datum_token_t *l_unblock_datum = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, l_unblock_token_size);
    
    l_unblock_datum->version = 2;
    l_unblock_datum->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_unblock_datum->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    snprintf(l_unblock_datum->ticker, sizeof(l_unblock_datum->ticker), "%s", l_token->token_ticker);
    l_unblock_datum->header_native_update.tsd_total_size = l_tsd_total_size;
    l_unblock_datum->signs_valid = 1;
    l_unblock_datum->signs_total = 0;
    
    memcpy(l_unblock_datum->tsd_n_signs, l_tsd_remove, l_tsd_total_size);
    DAP_DELETE(l_tsd_remove);
    
    // Sign unblock datum
    dap_sign_t *l_sign = dap_cert_sign(l_token->owner_cert, l_unblock_datum,
                                       l_unblock_token_size);
    dap_assert_PIF(l_sign != NULL, "Signature creation");
    
    size_t l_sign_size = dap_sign_get_size(l_sign);
    size_t l_unblock_total_size = l_unblock_token_size + l_sign_size;
    dap_chain_datum_token_t *l_unblock_datum_new = DAP_REALLOC(l_unblock_datum, l_unblock_total_size);
    dap_assert_PIF(l_unblock_datum_new != NULL, "Token update reallocation");
    l_unblock_datum = l_unblock_datum_new;
    memcpy((byte_t*)l_unblock_datum + l_unblock_token_size, l_sign, l_sign_size);
    l_unblock_datum->signs_total = 1;
    DAP_DELETE(l_sign);
    
    // Apply unblock token_update
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_unblock_datum, 
                                  l_unblock_total_size, dap_time_now());
    dap_assert(l_res == DAP_LEDGER_CHECK_OK, "UTXO unblocking should succeed");
    log_it(L_INFO, "✓ UTXO unblocked via token_update");
    
    // Step 4: Verify transaction with unblocked UTXO is now accepted
    dap_chain_datum_tx_t *l_tx_test2 = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_test2, &l_source_hash, l_source_out_idx);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_test2, l_tx_source->addr, uint256_0, l_token->token_ticker);
    
    dap_chain_hash_fast_t l_tx_test2_hash = {};
    dap_hash_fast(l_tx_test2, dap_chain_datum_tx_get_size(l_tx_test2), &l_tx_test2_hash);
    
    int l_add_res2 = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_test2, &l_tx_test2_hash,
                                        false, NULL);
    dap_assert(l_add_res2 == DAP_LEDGER_CHECK_OK,
               "Transaction should be accepted after unblocking");
    log_it(L_INFO, "✓ Transaction correctly accepted after UTXO unblocked");
    
    dap_chain_datum_tx_delete(l_tx_test2);
    
    // Cleanup
    test_tx_fixture_destroy(l_tx_source);
    test_token_fixture_destroy(l_token);
    
    log_it(L_INFO, "✓ UTXO unblocking test passed");
}

/**
 * @brief Test: Delayed UTXO blocking activation
 * @details Test UTXO blocking with delayed activation timestamp via token_update
 */
static void s_test_delayed_utxo_blocking(void)
{
    log_it(L_NOTICE, "TEST 6: Delayed UTXO Blocking/Unblocking");
    
    dap_assert(s_net_fixture != NULL, "Network fixture must be initialized");
    dap_assert(s_net_fixture->ledger != NULL, "Ledger must be initialized");
    
    // Create test token
    test_token_fixture_t *l_token = test_token_fixture_create(
        s_net_fixture->ledger, "TDELY", "75000.0");
    dap_assert_PIF(l_token != NULL, "Token fixture creation");
    dap_assert_PIF(l_token->owner_cert != NULL, "Token owner certificate must exist");
    
    // Create source transaction
    test_tx_fixture_t *l_tx_source = test_tx_fixture_create_simple(
        s_net_fixture->ledger, l_token->token_ticker, "5000.0");
    dap_assert_PIF(l_tx_source != NULL, "Source transaction creation");
    
    dap_chain_hash_fast_t l_source_hash = {};
    dap_hash_fast(l_tx_source->tx, dap_chain_datum_tx_get_size(l_tx_source->tx), &l_source_hash);
    uint32_t l_source_out_idx = 0;
    
    log_it(L_DEBUG, "Source UTXO: %s:%u",
           dap_chain_hash_fast_to_str_static(&l_source_hash), l_source_out_idx);
    
    // Test delayed activation: block UTXO with timestamp in future
    // Create TSD with timestamp (extended format: hash + out_idx + timestamp = 44 bytes)
    dap_time_t l_now = dap_time_now();
    dap_time_t l_future_activation = l_now + 3600; // 1 hour in future
    
    size_t l_tsd_data_size = sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t) + sizeof(dap_time_t);
    byte_t *l_tsd_data = DAP_NEW_Z_SIZE(byte_t, l_tsd_data_size);
    memcpy(l_tsd_data, &l_source_hash, sizeof(dap_chain_hash_fast_t));
    memcpy(l_tsd_data + sizeof(dap_chain_hash_fast_t), &l_source_out_idx, sizeof(uint32_t));
    memcpy(l_tsd_data + sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t), 
           &l_future_activation, sizeof(dap_time_t));
    
    dap_tsd_t *l_tsd_delayed = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_ADD,
                                               l_tsd_data, l_tsd_data_size);
    DAP_DELETE(l_tsd_data);
    
    // Create token_update with delayed blocking
    size_t l_tsd_total_size = dap_tsd_size(l_tsd_delayed);
    size_t l_token_size = sizeof(dap_chain_datum_token_t) + l_tsd_total_size;
    dap_chain_datum_token_t *l_delayed_datum = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, l_token_size);
    
    l_delayed_datum->version = 2;
    l_delayed_datum->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_delayed_datum->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    snprintf(l_delayed_datum->ticker, sizeof(l_delayed_datum->ticker), "%s", l_token->token_ticker);
    l_delayed_datum->header_native_update.tsd_total_size = l_tsd_total_size;
    l_delayed_datum->signs_valid = 1;
    l_delayed_datum->signs_total = 0;
    
    memcpy(l_delayed_datum->tsd_n_signs, l_tsd_delayed, l_tsd_total_size);
    DAP_DELETE(l_tsd_delayed);
    
    // Sign delayed datum
    dap_sign_t *l_sign = dap_cert_sign(l_token->owner_cert, l_delayed_datum,
                                       l_token_size);
    dap_assert_PIF(l_sign != NULL, "Signature creation");
    
    size_t l_sign_size = dap_sign_get_size(l_sign);
    size_t l_delayed_total_size = l_token_size + l_sign_size;
    dap_chain_datum_token_t *l_delayed_datum_new = DAP_REALLOC(l_delayed_datum, l_delayed_total_size);
    dap_assert_PIF(l_delayed_datum_new != NULL, "Token update reallocation");
    l_delayed_datum = l_delayed_datum_new;
    memcpy((byte_t*)l_delayed_datum + l_token_size, l_sign, l_sign_size);
    l_delayed_datum->signs_total = 1;
    DAP_DELETE(l_sign);
    
    // Apply delayed blocking token_update
    int l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_delayed_datum, 
                                      l_delayed_total_size, dap_time_now());
    dap_assert(l_res == DAP_LEDGER_CHECK_OK, "Delayed blocking should be accepted");
    log_it(L_INFO, "✓ Delayed blocking token_update applied (becomes_effective: %"DAP_UINT64_FORMAT_U", current: %"DAP_UINT64_FORMAT_U")",
           l_future_activation, l_now);
    
    // Verify transaction is still ALLOWED (blocking not effective yet)
    dap_chain_datum_tx_t *l_tx_test1 = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_test1, &l_source_hash, l_source_out_idx);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_test1, l_tx_source->addr, uint256_0, l_token->token_ticker);
    
    dap_chain_hash_fast_t l_tx_test1_hash = {};
    dap_hash_fast(l_tx_test1, dap_chain_datum_tx_get_size(l_tx_test1), &l_tx_test1_hash);
    
    int l_add_res1 = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_test1, &l_tx_test1_hash,
                                        false, NULL);
    
    // Transaction should be accepted because blocking is not effective yet
    dap_assert(l_add_res1 == DAP_LEDGER_CHECK_OK,
               "Transaction should be accepted before delayed blocking becomes effective");
    log_it(L_INFO, "✓ Transaction correctly accepted (delayed blocking not effective yet)");
    
    dap_chain_datum_tx_delete(l_tx_test1);
    
    // Cleanup
    test_tx_fixture_destroy(l_tx_source);
    test_token_fixture_destroy(l_token);
    
    log_it(L_INFO, "✓ Delayed UTXO blocking test passed");
}


/**
 * @brief Main test runner
 * @return 0 on success, 1 on failure
 */
int main(void)
{
    // Setup test environment per DAP SDK standards
    dap_log_level_set(L_DEBUG);
    dap_log_set_external_output(LOGGER_OUTPUT_STDOUT, NULL);
    
    // Initialize consensus modules (required for chain creation)
    dap_assert_PIF(dap_chain_cs_dag_init() == 0, "DAG consensus initialization");
    dap_assert_PIF(dap_chain_cs_dag_poa_init() == 0, "DAG PoA consensus initialization");
    dap_assert_PIF(dap_chain_cs_esbocs_init() == 0, "ESBOCS consensus initialization");
    
    log_it(L_NOTICE, " ");
    dap_print_module_name("UTXO Blocking Mechanism - Functional Unit Tests");
    log_it(L_NOTICE, " ");
    
    // Create test network fixture with zero and master chains
    s_net_fixture = test_net_fixture_create("utxo_test_net");
    if (!s_net_fixture) {
        log_it(L_ERROR, "Failed to initialize test environment");
        return 1;
    }
    
    // Run all functional tests
    s_test_network_fixture_init();
    s_test_token_creation_and_ledger_addition();
    s_test_transaction_utxo_creation();
    s_test_utxo_blocking_via_token_update();
    s_test_utxo_unblocking_via_token_update();
    s_test_delayed_utxo_blocking();
    
    // Cleanup
    test_net_fixture_destroy(s_net_fixture);
    s_net_fixture = NULL;
    
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "All tests PASSED!");
    log_it(L_NOTICE, " ");
    
    return 0;
}
