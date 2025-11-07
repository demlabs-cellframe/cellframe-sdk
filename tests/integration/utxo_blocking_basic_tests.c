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
 * @file utxo_blocking_basic_tests.c
 * @brief Basic UTXO blocking integration tests (Tests 1-6)
 *          - UTXO unblocking through token_update
 *          - Delayed activation and unblocking (becomes_effective, becomes_unblocked)
 *          - Flag enforcement with real transactions
 * @date 2025-10-16
 */

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_tsd.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_tsd.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net_tx.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"
#include "utxo_blocking_test_helpers.h"
#include "utxo_blocking_basic_tests.h"

#include <stdlib.h>
#include <string.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_tsd.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_tsd.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"

#define LOG_TAG "utxo_blocking_integration"

// Global test context

#include "utxo_blocking_test_helpers.h"
#include "utxo_blocking_basic_tests.h"
/**
 * @brief Integration Test 1: Full UTXO blocking lifecycle with REAL emission
 * @details End-to-end: Token+Emission → TX → Block via token_update → Verify rejection
 */
void utxo_blocking_test_full_utxo_blocking_lifecycle(void)
{
    dap_print_module_name("Integration Test 1: Full Lifecycle (REAL Emission)");
    
    // Step 1: Create address
    log_it(L_DEBUG, "Generating key...");
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");
    log_it(L_DEBUG, "Key generated");
    
    log_it(L_DEBUG, "Creating address...");
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);
    log_it(L_DEBUG, "Address created");
    
    // Step 2: Create certificate wrapper for the key
    log_it(L_DEBUG, "Creating certificate wrapper...");
    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Certificate allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "test_emission_cert");
    log_it(L_DEBUG, "Certificate wrapper created");
    
    // Step 3: Create token WITH emission using new fixtures API
    log_it(L_INFO, "Step 3: Creating token with emission...");
    dap_chain_hash_fast_t l_emission_hash;
    // NOTE: Now we can use any emission value - change will be calculated automatically
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "INTG1", "10000.0", "5000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");
    
    log_it(L_INFO, "✓ Token+Emission created");
    log_it(L_INFO, "  Token ticker: INTG1");
    log_it(L_INFO, "  Emission value: 5000.0");
    log_it(L_INFO, "  Emission hash: %s", dap_chain_hash_fast_to_str_static(&l_emission_hash));
    log_it(L_INFO, "  Address: %s", dap_chain_addr_to_str_static(&l_addr));
    
    // Step 4: Create REAL transaction from emission (with automatic change)
    log_it(L_INFO, "Step 4: Creating transaction from emission...");
    log_it(L_INFO, "  Spending 1000.0 from 5000.0 emission (change: 4000.0)");
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "INTG1", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "Transaction from emission created");
    
    log_it(L_INFO, "✓ Transaction created, hash: %s", 
           dap_chain_hash_fast_to_str_static(&l_tx->tx_hash));
    
    // Step 5: Verify emission exists in ledger before adding transaction
    log_it(L_INFO, "Step 5: Verifying emission in ledger...");
    dap_chain_datum_token_emission_t *l_emission_check = dap_ledger_token_emission_find(
        s_net_fixture->ledger, &l_emission_hash);
    if (l_emission_check) {
        log_it(L_INFO, "✓ Emission found in ledger");
    } else {
        log_it(L_ERROR, "❌ Emission NOT found in ledger!");
    }
    
    // Step 6: Add transaction to ledger
    log_it(L_INFO, "Step 6: Adding transaction to ledger...");
    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "Transaction added to ledger");
    
    log_it(L_INFO, "✓ Transaction added: %s", 
           dap_chain_hash_fast_to_str_static(&l_tx->tx_hash));
    
    // Step 5: Check balance before blocking
    uint256_t l_balance_before = dap_ledger_calc_balance(s_net_fixture->ledger, &l_addr, "INTG1");
    log_it(L_DEBUG, "Balance before blocking: %s", dap_uint256_to_char(l_balance_before, NULL));
    
    // Step 7: Block UTXO via token_update
    log_it(L_INFO, "Step 7: Blocking UTXO via token_update...");
    log_it(L_INFO, "  Blocking TX hash: %s, out_idx: 0", 
           dap_chain_hash_fast_to_str_static(&l_tx->tx_hash));
    
    size_t l_update_size = 0;
    dap_chain_datum_token_t *l_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "INTG1", &l_tx->tx_hash, 0, l_token->owner_cert, 0, &l_update_size);
    dap_assert_PIF(l_update != NULL, "Token update created");
    
    log_it(L_INFO, "  Token update size: %zu bytes", l_update_size);
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_update, l_update_size, dap_time_now());
    log_it(L_INFO, "  Token update result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0, "Token update applied");
    DAP_DELETE(l_update);
    
    log_it(L_INFO, "✓ UTXO blocked via token_update");
    
    // Step 8: Try to spend blocked UTXO - should fail
    log_it(L_INFO, "Step 8: Trying to spend blocked UTXO...");
    dap_chain_datum_tx_t *l_tx_blocked = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_blocked, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_blocked, &l_addr, dap_chain_balance_scan("100.0"), "INTG1");
    dap_chain_datum_tx_add_out_ext_item(&l_tx_blocked, &l_addr, dap_chain_balance_scan("900.0"), "INTG1"); // Change
    dap_chain_datum_tx_add_sign_item(&l_tx_blocked, l_key);
    
    dap_chain_hash_fast_t l_blocked_hash;
    dap_hash_fast(l_tx_blocked, dap_chain_datum_tx_get_size(l_tx_blocked), &l_blocked_hash);
    
    log_it(L_INFO, "  Trying to add TX spending blocked UTXO...");
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_blocked, &l_blocked_hash, false, NULL);
    log_it(L_INFO, "  Result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    log_it(L_INFO, "  Expected: %d (DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED)", DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED);
    
    if (l_res != DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED) {
        log_it(L_ERROR, "❌ FAILED! Expected BLOCKED (%d), got %d (%s)",
               DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED, l_res, dap_ledger_check_error_str(l_res));
    } else {
        log_it(L_INFO, "✓ Correctly rejected blocked UTXO");
    }
    
    dap_assert(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED, 
               "Transaction with blocked UTXO should be rejected");
    
    log_it(L_INFO, "✓ Blocked UTXO spending rejected: %s", dap_ledger_check_error_str(l_res));
    
    // Step 8: Verify balance unchanged
    uint256_t l_balance_after = dap_ledger_calc_balance(s_net_fixture->ledger, &l_addr, "INTG1");
    dap_assert(compare256(l_balance_before, l_balance_after) == 0, "Balance should not change");
    
    // Cleanup
    DAP_DELETE(l_tx_blocked);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    // Free cert wrapper (but not the key - it will be freed separately)
    l_cert->enc_key = NULL;  // Don't free key here
    DAP_DELETE(l_cert);
    dap_enc_key_delete(l_key);
    
    dap_pass_msg("Full UTXO blocking lifecycle test passed");
}

/**
 * @brief Integration Test 2: UTXO unblocking
 * @details Block UTXO → Unblock via token_update → Verify can spend
 */
void utxo_blocking_test_utxo_unblocking(void)
{
    dap_print_module_name("Integration Test 2: UTXO Unblocking");
    
    // Step 1: Create key and address
    log_it(L_INFO, "Step 1: Creating key and address...");
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");
    
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Certificate allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "test_unblock_cert");
    
    // Step 2: Create token with emission
    log_it(L_INFO, "Step 2: Creating token with emission...");
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "INTG2", "10000.0", "3000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");
    
    log_it(L_INFO, "✓ Token 'INTG2' created with emission (3000.0)");
    
    // Step 3: Create transaction from emission
    log_it(L_INFO, "Step 3: Creating transaction from emission...");
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "INTG2", "500.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "Transaction from emission created");
    
    // Step 4: Add transaction to ledger
    log_it(L_INFO, "Step 4: Adding transaction to ledger...");
    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "Transaction added to ledger");
    
    log_it(L_INFO, "✓ Transaction added: %s", dap_chain_hash_fast_to_str_static(&l_tx->tx_hash));
    
    // Step 5: Block UTXO
    log_it(L_INFO, "Step 5: Blocking UTXO via token_update...");
    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "INTG2", &l_tx->tx_hash, 0, l_token->owner_cert, 0, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Block token update created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_block_update, l_block_size, dap_time_now());
    dap_assert_PIF(l_res == 0, "Block token update applied");
    DAP_DELETE(l_block_update);
    
    log_it(L_INFO, "✓ UTXO blocked");
    
    // Step 6: Verify UTXO is blocked
    log_it(L_INFO, "Step 6: Verifying UTXO is blocked...");
    dap_chain_datum_tx_t *l_tx_blocked = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_blocked, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_blocked, &l_addr, dap_chain_balance_scan("100.0"), "INTG2");
    dap_chain_datum_tx_add_out_ext_item(&l_tx_blocked, &l_addr, dap_chain_balance_scan("400.0"), "INTG2"); // Change
    dap_chain_datum_tx_add_sign_item(&l_tx_blocked, l_key);
    
    dap_chain_hash_fast_t l_blocked_hash;
    dap_hash_fast(l_tx_blocked, dap_chain_datum_tx_get_size(l_tx_blocked), &l_blocked_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_blocked, &l_blocked_hash, false, NULL);
    log_it(L_INFO, "  Spending blocked UTXO result: %d (expected: %d)", 
           l_res, DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED);
    dap_assert(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED, 
               "Spending blocked UTXO should be rejected");
    
    log_it(L_INFO, "✓ Blocked UTXO correctly rejected");
    
    // Step 7: Unblock UTXO
    log_it(L_INFO, "Step 7: Unblocking UTXO via token_update...");
    size_t l_unblock_size = 0;
    dap_chain_datum_token_t *l_unblock_update = utxo_blocking_test_create_token_update_with_utxo_unblock_tsd(
        "INTG2", &l_tx->tx_hash, 0, l_token->owner_cert, 0, &l_unblock_size);
    dap_assert_PIF(l_unblock_update != NULL, "Unblock token update created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_unblock_update, l_unblock_size, dap_time_now());
    dap_assert_PIF(l_res == 0, "Unblock token update applied");
    DAP_DELETE(l_unblock_update);
    
    log_it(L_INFO, "✓ UTXO unblocked");
    
    // Step 8: Verify UTXO can be spent after unblocking
    log_it(L_INFO, "Step 8: Verifying UTXO can be spent after unblocking...");
    dap_chain_datum_tx_t *l_tx_unblocked = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_unblocked, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_unblocked, &l_addr, dap_chain_balance_scan("100.0"), "INTG2");
    dap_chain_datum_tx_add_out_ext_item(&l_tx_unblocked, &l_addr, dap_chain_balance_scan("400.0"), "INTG2"); // Change
    dap_chain_datum_tx_add_sign_item(&l_tx_unblocked, l_key);
    
    dap_chain_hash_fast_t l_unblocked_hash;
    dap_hash_fast(l_tx_unblocked, dap_chain_datum_tx_get_size(l_tx_unblocked), &l_unblocked_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_unblocked, &l_unblocked_hash, false, NULL);
    log_it(L_INFO, "  Spending unblocked UTXO result: %d (expected: 0 = success)", l_res);
    dap_assert(l_res == 0, "Spending unblocked UTXO should succeed");
    
    log_it(L_INFO, "✓ Unblocked UTXO successfully spent");
    
    // Cleanup
    DAP_DELETE(l_tx_unblocked);
    DAP_DELETE(l_tx_blocked);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_cert->enc_key = NULL;
    DAP_DELETE(l_cert);
    dap_enc_key_delete(l_key);
    
    dap_pass_msg("UTXO unblocking test passed");
}

/**
 * @brief Integration Test 3: Delayed activation
 * @details Block UTXO with future becomes_effective → Verify works only after time
 */
void utxo_blocking_test_delayed_activation(void)
{
    dap_print_module_name("Integration Test 3: Delayed Activation");
    
    // Step 1: Create key and address
    log_it(L_INFO, "Step 1: Creating key and address...");
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");
    
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Certificate allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "test_delayed_cert");
    
    // Step 2: Create token with emission
    log_it(L_INFO, "Step 2: Creating token with emission...");
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "INTG3", "10000.0", "4000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");
    
    log_it(L_INFO, "✓ Token 'INTG3' created with emission (4000.0)");
    
    // Step 3: Create transaction from emission
    log_it(L_INFO, "Step 3: Creating transaction from emission...");
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "INTG3", "600.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "Transaction from emission created");
    
    // Step 4: Add transaction to ledger
    log_it(L_INFO, "Step 4: Adding transaction to ledger...");
    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "Transaction added to ledger");
    
    log_it(L_INFO, "✓ Transaction added: %s", dap_chain_hash_fast_to_str_static(&l_tx->tx_hash));
    
    // Step 5: Block UTXO with becomes_effective in the FUTURE
    log_it(L_INFO, "Step 5: Blocking UTXO with delayed activation...");
    dap_time_t l_current_time = dap_time_now();
    dap_time_t l_future_time = l_current_time + 100000; // +100000 sec (far future, immune to test timing)
    
    log_it(L_INFO, "  Current blockchain time: %llu", (unsigned long long)l_current_time);
    log_it(L_INFO, "  Becomes effective at: %llu (+100000 sec)", (unsigned long long)l_future_time);
    
    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "INTG3", &l_tx->tx_hash, 0, l_token->owner_cert, l_future_time, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Delayed block token update created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_block_update, l_block_size, l_current_time);
    dap_assert_PIF(l_res == 0, "Delayed block token update applied");
    DAP_DELETE(l_block_update);
    
    log_it(L_INFO, "✓ UTXO blocked with delayed activation (becomes_effective = %llu)", 
           (unsigned long long)l_future_time);
    
    // Step 6: Try to spend UTXO BEFORE activation time - should SUCCEED (block not active yet)
    log_it(L_INFO, "Step 6: Trying to spend UTXO BEFORE activation time...");
    dap_time_t l_time_before_tx = dap_time_now();
    dap_time_t l_ledger_time = dap_ledger_get_blockchain_time(s_net_fixture->ledger);
    log_it(L_INFO, "  Current time: %llu", (unsigned long long)l_time_before_tx);
    log_it(L_INFO, "  Ledger blockchain time: %llu", (unsigned long long)l_ledger_time);
    log_it(L_INFO, "  Future activation time: %llu", (unsigned long long)l_future_time);
    log_it(L_INFO, "  Time diff (future - ledger): %lld sec", (long long)(l_future_time - l_ledger_time));
    
    dap_chain_datum_tx_t *l_tx_before = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_before, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_before, &l_addr, dap_chain_balance_scan("200.0"), "INTG3");
    dap_chain_datum_tx_add_out_ext_item(&l_tx_before, &l_addr, dap_chain_balance_scan("400.0"), "INTG3"); // Change
    dap_chain_datum_tx_add_sign_item(&l_tx_before, l_key);
    
    dap_chain_hash_fast_t l_before_hash;
    dap_hash_fast(l_tx_before, dap_chain_datum_tx_get_size(l_tx_before), &l_before_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_before, &l_before_hash, false, NULL);
    log_it(L_INFO, "  Result: %d (expected: 0 = success, block not active yet)", l_res);
    if (l_res != 0) {
        log_it(L_ERROR, "  TX REJECTED! Error code: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
        log_it(L_ERROR, "  This means UTXO is ALREADY BLOCKED even though activation time is in future!");
    }
    dap_assert(l_res == 0, "Spending UTXO before activation time should succeed");
    
    log_it(L_INFO, "✓ UTXO spent successfully BEFORE activation time");
    
    // Step 7: Create second transaction from CHANGE output of first transaction
    // Note: l_tx has 2 outputs: 0=600.0 (spent in Step 6), 1=3400.0 (change, still available)
    log_it(L_INFO, "Step 7: Creating second transaction from change output...");
    dap_chain_datum_tx_t *l_tx2_datum = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx2_datum, &l_tx->tx_hash, 1); // Use change output
    dap_chain_datum_tx_add_out_ext_item(&l_tx2_datum, &l_addr, dap_chain_balance_scan("700.0"), "INTG3");
    dap_chain_datum_tx_add_out_ext_item(&l_tx2_datum, &l_addr, dap_chain_balance_scan("2700.0"), "INTG3"); // Change
    dap_chain_datum_tx_add_sign_item(&l_tx2_datum, l_key);
    
    dap_chain_hash_fast_t l_tx2_hash;
    dap_hash_fast(l_tx2_datum, dap_chain_datum_tx_get_size(l_tx2_datum), &l_tx2_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx2_datum, &l_tx2_hash, false, NULL);
    dap_assert_PIF(l_res == 0, "Second transaction added to ledger");
    
    log_it(L_INFO, "✓ Second transaction added: %s", dap_chain_hash_fast_to_str_static(&l_tx2_hash));
    
    // Step 8: Block second UTXO with becomes_effective in the PAST (already active)
    log_it(L_INFO, "Step 8: Blocking second UTXO with PAST activation time...");
    dap_time_t l_past_time = l_current_time - 100; // -100 sec (already active)
    
    log_it(L_INFO, "  Becomes effective at: %llu (-100 sec, already active)", 
           (unsigned long long)l_past_time);
    
    size_t l_block2_size = 0;
    dap_chain_datum_token_t *l_block2_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "INTG3", &l_tx2_hash, 0, l_token->owner_cert, l_past_time, &l_block2_size);
    dap_assert_PIF(l_block2_update != NULL, "Second block token update created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_block2_update, l_block2_size, l_current_time);
    dap_assert_PIF(l_res == 0, "Second block token update applied");
    DAP_DELETE(l_block2_update);
    
    log_it(L_INFO, "✓ Second UTXO blocked with PAST activation time (immediately active)");
    
    // Step 9: Try to spend second UTXO - should FAIL (block already active)
    log_it(L_INFO, "Step 9: Trying to spend UTXO with PAST activation time...");
    dap_chain_datum_tx_t *l_tx_after = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_after, &l_tx2_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_after, &l_addr, dap_chain_balance_scan("300.0"), "INTG3");
    dap_chain_datum_tx_add_out_ext_item(&l_tx_after, &l_addr, dap_chain_balance_scan("400.0"), "INTG3"); // Change
    dap_chain_datum_tx_add_sign_item(&l_tx_after, l_key);
    
    dap_chain_hash_fast_t l_after_hash;
    dap_hash_fast(l_tx_after, dap_chain_datum_tx_get_size(l_tx_after), &l_after_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_after, &l_after_hash, false, NULL);
    log_it(L_INFO, "  Result: %d (expected: %d = blocked, already active)", 
           l_res, DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED);
    dap_assert(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED, 
               "Spending UTXO with past activation time should be blocked");
    
    log_it(L_INFO, "✓ UTXO with PAST activation time correctly blocked");
    
    // Cleanup
    DAP_DELETE(l_tx_after);
    DAP_DELETE(l_tx_before);
    DAP_DELETE(l_tx2_datum);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_cert->enc_key = NULL;
    DAP_DELETE(l_cert);
    dap_enc_key_delete(l_key);
    
    dap_pass_msg("Delayed activation test passed");
}

/**
 * @brief Integration Test 4: UTXO CLEAR operation
 * @details Test clearing entire UTXO blocklist
 */
void utxo_blocking_test_utxo_clear_operation(void)
{
    dap_print_module_name("Integration Test 4: UTXO CLEAR Operation");
    
    dap_ledger_t *l_ledger = s_net_fixture->ledger;
    
    // Create key and certificate
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");
    
    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "clear_test_cert");
    
    dap_chain_addr_t l_addr;
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);
    
    // Create token with emission
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        l_ledger, "INTG4", "10000.0", "5000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token created");
    
    // Create TX from emission
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        l_ledger, &l_emission_hash, "INTG4", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");
    
    int l_add_res = test_tx_fixture_add_to_ledger(l_ledger, l_tx);
    dap_assert_PIF(l_add_res == 0, "TX added");
    
    // Block UTXO
    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "INTG4", &l_tx->tx_hash, 0, l_token->owner_cert, 0, &l_block_size);
    int l_block_ret = dap_ledger_token_add(l_ledger, (byte_t*)l_block_update, l_block_size, dap_time_now());
    dap_assert_PIF(l_block_ret == 0, "UTXO blocked");
    DAP_DELETE(l_block_update);
    
    log_it(L_INFO, "✓ UTXO blocked");
    
    // Create CLEAR token_update
    dap_chain_datum_token_t *l_clear_base = DAP_NEW_Z(dap_chain_datum_token_t);
    l_clear_base->version = 2;
    l_clear_base->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_clear_base->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_clear_base->ticker, "INTG4", DAP_CHAIN_TICKER_SIZE_MAX - 1);
    
    dap_tsd_t *l_clear_tsd = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_CLEAR, NULL, 0);
    l_clear_base->header_native_decl.tsd_total_size = l_clear_tsd->size;
    
    // Create unsigned datum
    size_t l_clear_datum_size = sizeof(dap_chain_datum_token_t) + l_clear_tsd->size;
    dap_chain_datum_token_t *l_clear_datum_unsigned = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, l_clear_datum_size);
    memcpy(l_clear_datum_unsigned, l_clear_base, sizeof(dap_chain_datum_token_t));
    memcpy(((byte_t*)l_clear_datum_unsigned) + sizeof(dap_chain_datum_token_t), l_clear_tsd, l_clear_tsd->size);
    
    // Sign the datum
    dap_sign_t *l_sign = dap_cert_sign(l_cert, l_clear_datum_unsigned, l_clear_datum_size);
    dap_assert_PIF(l_sign != NULL, "CLEAR datum signed");
    
    size_t l_sign_size = dap_sign_get_size(l_sign);
    dap_chain_datum_token_t *l_clear_datum = DAP_REALLOC(l_clear_datum_unsigned, l_clear_datum_size + l_sign_size);
    memcpy(((byte_t*)l_clear_datum) + l_clear_datum_size, l_sign, l_sign_size);
    l_clear_datum->signs_total = 1;
    l_clear_datum_size += l_sign_size;
    DAP_DELETE(l_sign);
    
    int l_clear_res = dap_ledger_token_add(l_ledger, (byte_t*)l_clear_datum, l_clear_datum_size, dap_time_now());
    dap_assert(l_clear_res == 0, "CLEAR operation succeeded");
    
    log_it(L_INFO, "✓ CLEAR operation applied");
    
    // Cleanup
    DAP_DELETE(l_clear_tsd);
    DAP_DELETE(l_clear_base);
    DAP_DELETE(l_clear_datum);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_cert->enc_key = NULL;
    DAP_DELETE(l_cert);
    dap_enc_key_delete(l_key);
    
    dap_pass_msg("UTXO CLEAR operation test passed");
}

/**
 * @brief Integration Test 5: Irreversible flags
 * @details Test that irreversible flags cannot be unset via token_update
 *          Tests the actual ledger validation logic with real token_update datums
 */
void utxo_blocking_test_irreversible_flags(void)
{
    dap_print_module_name("Integration Test 5: Irreversible Flags (Ledger Validation)");
    
    dap_ledger_t *l_ledger = s_net_fixture->ledger;
    
    // Create test certificate
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");
    
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Certificate allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "irrev_test_cert");
    
    // Create token with one irreversible flag set
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        l_ledger, "IRREV", "10000.0", "5000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token created");
    
    // Step 1: Set ARBITRAGE_TX_DISABLED flag (irreversible)
    size_t l_update1_size = 0;
    dap_chain_datum_token_t *l_update1 = utxo_blocking_test_create_token_update_with_utxo_flags(
        "IRREV", DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_ARBITRAGE_TX_DISABLED, l_token->owner_cert, &l_update1_size);
    dap_assert_PIF(l_update1 != NULL, "Update 1 created");
    dap_assert_PIF(l_update1_size > 0, "Update 1 size is valid");
    
    int l_res1 = dap_ledger_token_add(l_ledger, (byte_t*)l_update1, l_update1_size, dap_time_now());
    if (l_res1 != 0) {
        const char *l_error_str = dap_ledger_check_error_str(l_res1);
        fprintf(stderr, "ERROR: Update 1 failed with error code: %d (%s)\n", l_res1, l_error_str ? l_error_str : "unknown");
        fflush(stderr);
        log_it(L_ERROR, "Update 1 failed with error code: %d (%s)", l_res1, l_error_str ? l_error_str : "unknown");
    }
    dap_assert(l_res1 == 0, "Update 1: Set ARBITRAGE_TX_DISABLED succeeded");
    log_it(L_INFO, "✓ Update 1: ARBITRAGE_TX_DISABLED flag set");
    
    // Step 2: Try to unset ARBITRAGE_TX_DISABLED (should FAIL)
    uint32_t l_flags2 = 0; // Try to unset all flags
    dap_tsd_t *l_tsd2 = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_FLAGS, &l_flags2, sizeof(uint32_t));
    
    dap_chain_datum_token_t *l_update2_base = DAP_NEW_Z(dap_chain_datum_token_t);
    l_update2_base->version = 2;
    l_update2_base->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_update2_base->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_update2_base->ticker, "IRREV", DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_update2_base->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_update2_base->signs_valid = 0;
    l_update2_base->signs_total = 0;
    l_update2_base->total_supply = uint256_0;
    l_update2_base->header_native_update.padding = 0;  // padding field for UPDATE (replaces flags in DECL)
    l_update2_base->header_native_update.decimals = 0;
    l_update2_base->header_native_update.tsd_total_size = dap_tsd_size(l_tsd2);  // Full TSD size (header + data)
    
    size_t l_update2_size = sizeof(dap_chain_datum_token_t) + dap_tsd_size(l_tsd2);
    dap_chain_datum_token_t *l_update2_unsigned = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, l_update2_size);
    memcpy(l_update2_unsigned, l_update2_base, sizeof(dap_chain_datum_token_t));
    memcpy(((byte_t*)l_update2_unsigned) + sizeof(dap_chain_datum_token_t), l_tsd2, dap_tsd_size(l_tsd2));
    
    // Use token owner certificate for signing (not emission owner)
    dap_sign_t *l_sign2 = dap_cert_sign(l_token->owner_cert, l_update2_unsigned, l_update2_size);
    dap_assert_PIF(l_sign2 != NULL, "Update 2 signed");
    
    size_t l_sign2_size = dap_sign_get_size(l_sign2);
    dap_chain_datum_token_t *l_update2 = DAP_REALLOC(l_update2_unsigned, l_update2_size + l_sign2_size);
    memcpy(((byte_t*)l_update2) + l_update2_size, l_sign2, l_sign2_size);
    l_update2->signs_total = 1;
    l_update2_size += l_sign2_size;
    DAP_DELETE(l_sign2);
    
    int l_res2 = dap_ledger_token_add(l_ledger, (byte_t*)l_update2, l_update2_size, dap_time_now());
    if (l_res2 != DAP_LEDGER_TOKEN_UPDATE_CHECK_IRREVERSIBLE_FLAGS_VIOLATION) {
        const char *l_error_str = dap_ledger_check_error_str(l_res2);
        fprintf(stderr, "ERROR: Update 2 returned code %d (%s), expected %d\n", 
                l_res2, l_error_str ? l_error_str : "unknown", 
                DAP_LEDGER_TOKEN_UPDATE_CHECK_IRREVERSIBLE_FLAGS_VIOLATION);
        fflush(stderr);
        log_it(L_ERROR, "Update 2 returned code %d (%s), expected %d", 
               l_res2, l_error_str ? l_error_str : "unknown", 
               DAP_LEDGER_TOKEN_UPDATE_CHECK_IRREVERSIBLE_FLAGS_VIOLATION);
    }
    dap_assert(l_res2 == DAP_LEDGER_TOKEN_UPDATE_CHECK_IRREVERSIBLE_FLAGS_VIOLATION,
               "Update 2: Unsetting ARBITRAGE_TX_DISABLED should FAIL");
    log_it(L_INFO, "✓ Update 2: Unsetting ARBITRAGE_TX_DISABLED correctly rejected");
    
    // Step 3: CRITICAL TEST - Try to unset bit 2 while setting bit 4 (should FAIL)
    // This is the case that numeric comparison (<) fails to catch
    uint32_t l_flags3 = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_ARBITRAGE_TX_DISABLED; // BIT 4 = 0x10
    // Old flags have BIT 2 set (ARBITRAGE_TX_DISABLED was set in step 1)
    // Wait, we set ARBITRAGE_TX_DISABLED in step 1, so old has BIT 4
    // Let's set BIT 2 first, then try to unset it while setting BIT 4
    
    // First, set BIT 2 (DISABLE_ADDRESS_SENDER_BLOCKING)
    uint32_t l_flags3a = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_ARBITRAGE_TX_DISABLED | 
                         DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_DISABLE_ADDRESS_SENDER_BLOCKING; // BIT 4 | BIT 2
    dap_tsd_t *l_tsd3a = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_FLAGS, &l_flags3a, sizeof(uint32_t));
    
    dap_chain_datum_token_t *l_update3a_base = DAP_NEW_Z(dap_chain_datum_token_t);
    l_update3a_base->version = 2;
    l_update3a_base->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_update3a_base->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_update3a_base->ticker, "IRREV", DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_update3a_base->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_update3a_base->signs_valid = 0;
    l_update3a_base->signs_total = 0;
    l_update3a_base->total_supply = uint256_0;
    l_update3a_base->header_native_update.decimals = 0;
    l_update3a_base->header_native_update.padding = 0;  // padding field for UPDATE (replaces flags in DECL)
    l_update3a_base->header_native_update.tsd_total_size = dap_tsd_size(l_tsd3a);  // Full TSD size (header + data)
    
    size_t l_update3a_size = sizeof(dap_chain_datum_token_t) + dap_tsd_size(l_tsd3a);
    dap_chain_datum_token_t *l_update3a_unsigned = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, l_update3a_size);
    memcpy(l_update3a_unsigned, l_update3a_base, sizeof(dap_chain_datum_token_t));
    memcpy(((byte_t*)l_update3a_unsigned) + sizeof(dap_chain_datum_token_t), l_tsd3a, dap_tsd_size(l_tsd3a));
    
    // Use token owner certificate for signing (not emission owner)
    dap_sign_t *l_sign3a = dap_cert_sign(l_token->owner_cert, l_update3a_unsigned, l_update3a_size);
    dap_assert_PIF(l_sign3a != NULL, "Update 3a signed");
    
    size_t l_sign3a_size = dap_sign_get_size(l_sign3a);
    dap_chain_datum_token_t *l_update3a = DAP_REALLOC(l_update3a_unsigned, l_update3a_size + l_sign3a_size);
    memcpy(((byte_t*)l_update3a) + l_update3a_size, l_sign3a, l_sign3a_size);
    l_update3a->signs_total = 1;
    l_update3a_size += l_sign3a_size;
    DAP_DELETE(l_sign3a);
    
    int l_res3a = dap_ledger_token_add(l_ledger, (byte_t*)l_update3a, l_update3a_size, dap_time_now());
    dap_assert(l_res3a == 0, "Update 3a: Set BIT 2 and BIT 4 succeeded");
    log_it(L_INFO, "✓ Update 3a: BIT 2 and BIT 4 set");
    
    // Verify flags were saved correctly after Update 3a
    uint32_t l_verify_flags = 0;
    int l_verify_res = dap_ledger_token_get_flags(l_ledger, "IRREV", &l_verify_flags);
    if (l_verify_res == 0) {
        uint32_t l_verify_utxo = l_verify_flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_MASK;
        uint32_t l_verify_irrev = l_verify_flags & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_IRREVERSIBLE_MASK;
        log_it(L_INFO, "After Update 3a: token flags=0x%08X, UTXO flags=0x%08X, irreversible=0x%08X", 
               l_verify_flags, l_verify_utxo, l_verify_irrev);
        dap_assert((l_verify_utxo & (DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_ARBITRAGE_TX_DISABLED | 
                                     DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_DISABLE_ADDRESS_SENDER_BLOCKING)) ==
                   (DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_ARBITRAGE_TX_DISABLED | 
                    DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_DISABLE_ADDRESS_SENDER_BLOCKING),
                   "Update 3a: Flags correctly saved in ledger");
    }
    
    // Now try to unset BIT 2 while keeping BIT 4 (should FAIL)
    uint32_t l_flags3b = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_ARBITRAGE_TX_DISABLED; // Only BIT 4
    log_it(L_INFO, "Creating Update 3b with flags: 0x%08X (should be 0x10, BIT 4 only)", l_flags3b);
    dap_tsd_t *l_tsd3b = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_FLAGS, &l_flags3b, sizeof(uint32_t));
    // Verify TSD contains correct flags
    uint32_t l_tsd3b_flags = dap_tsd_get_scalar(l_tsd3b, uint32_t);
    log_it(L_INFO, "Update 3b TSD flags: 0x%08X (should be 0x10)", l_tsd3b_flags);
    if (l_tsd3b_flags != 0x10) {
        log_it(L_ERROR, "Update 3b TSD flags mismatch: expected 0x10, got 0x%08X", l_tsd3b_flags);
        dap_assert(0, "Update 3b TSD flags must be 0x10 (BIT 4 only)");
    }
    
    dap_chain_datum_token_t *l_update3b_base = DAP_NEW_Z(dap_chain_datum_token_t);
    l_update3b_base->version = 2;
    l_update3b_base->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_update3b_base->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_update3b_base->ticker, "IRREV", DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_update3b_base->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_update3b_base->signs_valid = 0;
    l_update3b_base->signs_total = 0;
    l_update3b_base->total_supply = uint256_0;
    l_update3b_base->header_native_update.padding = 0;  // padding field for UPDATE (replaces flags in DECL)
    l_update3b_base->header_native_update.decimals = 0;
    l_update3b_base->header_native_update.tsd_total_size = dap_tsd_size(l_tsd3b);  // Full TSD size (header + data)
    
    size_t l_update3b_size = sizeof(dap_chain_datum_token_t) + dap_tsd_size(l_tsd3b);
    dap_chain_datum_token_t *l_update3b_unsigned = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, l_update3b_size);
    memcpy(l_update3b_unsigned, l_update3b_base, sizeof(dap_chain_datum_token_t));
    memcpy(((byte_t*)l_update3b_unsigned) + sizeof(dap_chain_datum_token_t), l_tsd3b, dap_tsd_size(l_tsd3b));
    
    // Use token owner certificate for signing (not emission owner)
    dap_sign_t *l_sign3b = dap_cert_sign(l_token->owner_cert, l_update3b_unsigned, l_update3b_size);
    dap_assert_PIF(l_sign3b != NULL, "Update 3b signed");
    
    size_t l_sign3b_size = dap_sign_get_size(l_sign3b);
    dap_chain_datum_token_t *l_update3b = DAP_REALLOC(l_update3b_unsigned, l_update3b_size + l_sign3b_size);
    memcpy(((byte_t*)l_update3b) + l_update3b_size, l_sign3b, l_sign3b_size);
    l_update3b->signs_total = 1;
    l_update3b_size += l_sign3b_size;
    DAP_DELETE(l_sign3b);
    
    int l_res3b = dap_ledger_token_add(l_ledger, (byte_t*)l_update3b, l_update3b_size, dap_time_now());
    dap_assert(l_res3b == DAP_LEDGER_TOKEN_UPDATE_CHECK_IRREVERSIBLE_FLAGS_VIOLATION,
               "Update 3b: CRITICAL - Unsetting BIT 2 while keeping BIT 4 should FAIL (bitwise check)");
    log_it(L_INFO, "✓ Update 3b: CRITICAL test passed - bitwise check correctly rejected unsetting BIT 2");
    
    // Step 4: Set BIT 4 while keeping BIT 2 (should SUCCEED)
    uint32_t l_flags4 = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_ARBITRAGE_TX_DISABLED | 
                        DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_DISABLE_ADDRESS_SENDER_BLOCKING; // BIT 4 | BIT 2
    dap_tsd_t *l_tsd4 = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_FLAGS, &l_flags4, sizeof(uint32_t));
    
    dap_chain_datum_token_t *l_update4_base = DAP_NEW_Z(dap_chain_datum_token_t);
    l_update4_base->version = 2;
    l_update4_base->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_update4_base->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_update4_base->ticker, "IRREV", DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_update4_base->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_update4_base->signs_valid = 0;
    l_update4_base->signs_total = 0;
    l_update4_base->total_supply = uint256_0;
    l_update4_base->header_native_update.decimals = 0;
    l_update4_base->header_native_update.tsd_total_size = dap_tsd_size(l_tsd4);  // Full TSD size (header + data)
    
    size_t l_update4_size = sizeof(dap_chain_datum_token_t) + dap_tsd_size(l_tsd4);
    dap_chain_datum_token_t *l_update4_unsigned = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, l_update4_size);
    memcpy(l_update4_unsigned, l_update4_base, sizeof(dap_chain_datum_token_t));
    memcpy(((byte_t*)l_update4_unsigned) + sizeof(dap_chain_datum_token_t), l_tsd4, dap_tsd_size(l_tsd4));
    
    dap_sign_t *l_sign4 = dap_cert_sign(l_cert, l_update4_unsigned, l_update4_size);
    dap_assert_PIF(l_sign4 != NULL, "Update 4 signed");
    
    size_t l_sign4_size = dap_sign_get_size(l_sign4);
    dap_chain_datum_token_t *l_update4 = DAP_REALLOC(l_update4_unsigned, l_update4_size + l_sign4_size);
    memcpy(((byte_t*)l_update4) + l_update4_size, l_sign4, l_sign4_size);
    l_update4->signs_total = 1;
    l_update4_size += l_sign4_size;
    DAP_DELETE(l_sign4);
    
    int l_res4 = dap_ledger_token_add(l_ledger, (byte_t*)l_update4, l_update4_size, dap_time_now());
    dap_assert(l_res4 == 0, "Update 4: Setting BIT 4 while keeping BIT 2 succeeded");
    log_it(L_INFO, "✓ Update 4: Setting BIT 4 while keeping BIT 2 correctly allowed");
    
    // Cleanup
    // l_update1 was created by helper function, just delete it
    DAP_DELETE(l_update1);
    // l_update2, l_update3a, l_update3b, l_update4 were created manually
    DAP_DELETE(l_tsd2);
    DAP_DELETE(l_update2_base);
    DAP_DELETE(l_update2);
    DAP_DELETE(l_tsd3a);
    DAP_DELETE(l_update3a_base);
    DAP_DELETE(l_update3a);
    DAP_DELETE(l_tsd3b);
    DAP_DELETE(l_update3b_base);
    DAP_DELETE(l_update3b);
    DAP_DELETE(l_tsd4);
    DAP_DELETE(l_update4_base);
    DAP_DELETE(l_update4);
    test_token_fixture_destroy(l_token);
    l_cert->enc_key = NULL;
    DAP_DELETE(l_cert);
    dap_enc_key_delete(l_key);
    
    dap_pass_msg("Irreversible flags test passed (ledger validation with bitwise check)");
}

/**
 * @brief Integration Test 6: UTXO_BLOCKING_DISABLED flag real behaviour
 * @details Comprehensive test verifying that UTXO_BLOCKING_DISABLED flag:
 *          1. Can be set during token_decl
 *          2. Prevents UTXO blocking operations at ledger level
 *          3. Keeps UTXOs spendable even when block attempts are made
 *          4. Is enforced for all blocking TSD types (ADD/REMOVE/CLEAR)
 */
void utxo_blocking_test_utxo_blocking_disabled_behaviour(void)
{
    dap_print_module_name("Integration Test 6: UTXO_BLOCKING_DISABLED flag behaviour");
    
    // ========== PHASE 1: Token Creation with UTXO_BLOCKING_DISABLED ==========
    log_it(L_INFO, "PHASE 1: Creating token with UTXO_BLOCKING_DISABLED flag");
    
    // Step 1.1: Generate key and address
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");
    
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Certificate allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "test_noblock_cert");
    
    // Step 1.2: Create TSD section with UTXO_FLAGS
    log_it(L_DEBUG, "Creating TSD section with UTXO_BLOCKING_DISABLED flag (0x%x)", 
           DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED);
    
    uint32_t l_utxo_flags = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED;
    dap_tsd_t *l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_FLAGS, 
                                      &l_utxo_flags, sizeof(uint32_t));
    dap_assert_PIF(l_tsd != NULL, "TSD UTXO_FLAGS creation");
    size_t l_tsd_size = dap_tsd_size(l_tsd);
    
    // Step 1.3: Create token datum with TSD
    log_it(L_DEBUG, "Creating token datum NOBLOCK with TSD section (size=%zu)", l_tsd_size);
    
    dap_chain_datum_token_t *l_token_datum = DAP_NEW_Z(dap_chain_datum_token_t);
    dap_assert_PIF(l_token_datum != NULL, "Token datum allocation");
    
    l_token_datum->version = 2;
    l_token_datum->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
    l_token_datum->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_token_datum->ticker, "NOBLOCK", DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_token_datum->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_token_datum->signs_valid = 0;
    l_token_datum->total_supply = dap_chain_balance_scan("1000000.0");
    l_token_datum->header_native_decl.decimals = 18;
    l_token_datum->header_native_decl.flags = 0;  // No flags in header anymore - moved to TSD
    l_token_datum->header_native_decl.tsd_total_size = l_tsd_size;
    l_token_datum->signs_total = 0;
    
    // Realloc to fit TSD
    dap_chain_datum_token_t *l_token_new = DAP_REALLOC(l_token_datum, sizeof(dap_chain_datum_token_t) + l_tsd_size);
    dap_assert_PIF(l_token_new != NULL, "Token realloc for TSD");
    l_token_datum = l_token_new;
    memcpy(l_token_datum->tsd_n_signs, l_tsd, l_tsd_size);
    DAP_DELETE(l_tsd);
    
    // Step 1.4: Sign token (with TSD)
    dap_sign_t *l_sign = dap_cert_sign(l_cert, l_token_datum, sizeof(dap_chain_datum_token_t) + l_tsd_size);
    dap_assert_PIF(l_sign != NULL, "Token signing");
    
    size_t l_sign_size = dap_sign_get_size(l_sign);
    l_token_new = DAP_REALLOC(l_token_datum, sizeof(dap_chain_datum_token_t) + l_tsd_size + l_sign_size);
    dap_assert_PIF(l_token_new != NULL, "Token realloc for signature");
    l_token_datum = l_token_new;
    
    memcpy(l_token_datum->tsd_n_signs + l_tsd_size, l_sign, l_sign_size);
    l_token_datum->signs_total = 1;
    DAP_DELETE(l_sign);
    
    size_t l_token_size = sizeof(dap_chain_datum_token_t) + l_tsd_size + l_sign_size;
    
    // Step 1.5: Add token to ledger
    int l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_token_datum, l_token_size, dap_time_now());
    log_it(L_INFO, "  Token add result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_OK, "Token added to ledger");
    
    // Step 1.6: Verify token exists in ledger with correct UTXO flags from TSD
    dap_chain_datum_token_t *l_token_check = dap_ledger_token_ticker_check(s_net_fixture->ledger, "NOBLOCK");
    dap_assert_PIF(l_token_check != NULL, "Token found in ledger");
    
    // Parse TSD to verify UTXO_FLAGS
    size_t l_check_token_size = sizeof(dap_chain_datum_token_t) + 
                                l_token_check->header_native_decl.tsd_total_size +
                                l_token_check->signs_total * sizeof(dap_sign_t);  // Approximate
    dap_tsd_t *l_tsd_check = dap_chain_datum_token_tsd_get(l_token_check, l_check_token_size);
    dap_assert_PIF(l_tsd_check != NULL, "TSD section found in token");
    
    bool l_utxo_flags_found = false;
    uint32_t l_utxo_flags_from_ledger = 0;
    for (size_t l_offset = 0; l_offset < l_token_check->header_native_decl.tsd_total_size; ) {
        dap_tsd_t *l_tsd_item = (dap_tsd_t *)(((byte_t*)l_tsd_check) + l_offset);
        if (l_tsd_item->type == DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_FLAGS) {
            l_utxo_flags_from_ledger = *(uint32_t*)l_tsd_item->data;
            l_utxo_flags_found = true;
            break;
        }
        l_offset += dap_tsd_size(l_tsd_item);
    }
    
    dap_assert_PIF(l_utxo_flags_found, "UTXO_FLAGS TSD section found");
    dap_assert_PIF(l_utxo_flags_from_ledger & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED,
                   "UTXO_BLOCKING_DISABLED flag is set in TSD");
    
    log_it(L_INFO, "✓ Token NOBLOCK created with UTXO_BLOCKING_DISABLED in TSD (verified in ledger)");
    
    // ========== PHASE 2: Create Emission and UTXO ==========
    log_it(L_INFO, "PHASE 2: Creating emission and UTXO");
    
    // Step 2.0: Verify token exists in ledger before creating emission
    dap_chain_datum_token_t *l_token_verify = dap_ledger_token_ticker_check(s_net_fixture->ledger, "NOBLOCK");
    dap_assert_PIF(l_token_verify != NULL, "Token NOBLOCK exists in ledger before emission");
    
    // Step 2.1: Create emission using fixture with cert
    test_emission_fixture_t *l_emission_fixture = test_emission_fixture_create_with_cert(
        "NOBLOCK",
        dap_chain_balance_scan("10000.0"),
        &l_addr,
        l_cert
    );
    dap_assert_PIF(l_emission_fixture != NULL, "Emission fixture creation");
    
    // Add emission to ledger
    l_res = test_emission_fixture_add_to_ledger(s_net_fixture->ledger, l_emission_fixture);
    log_it(L_INFO, "  Emission add result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_OK, "Emission added to ledger");
    
    // Get emission hash from fixture
    dap_chain_hash_fast_t l_emission_hash;
    bool l_hash_ok = test_emission_fixture_get_hash(l_emission_fixture, &l_emission_hash);
    dap_assert_PIF(l_hash_ok, "Emission hash retrieved");
    
    log_it(L_INFO, "✓ Emission created: 10000 NOBLOCK, hash: %s",
           dap_chain_hash_fast_to_str_static(&l_emission_hash));
    
    // Step 2.2: Create transaction from emission using fixture (for proper TX structure)
    test_tx_fixture_t *l_tx_fixture = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "NOBLOCK", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx_fixture != NULL, "Transaction fixture created from emission");
    
    // Step 2.3: Add transaction to ledger
    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx_fixture);
    log_it(L_INFO, "  TX add result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0, "Transaction added to ledger");
    
    log_it(L_INFO, "✓ Transaction added to ledger");
    log_it(L_INFO, "✓ Transaction created UTXO: %s:0 (1000.0 NOBLOCK)", 
           dap_chain_hash_fast_to_str_static(&l_tx_fixture->tx_hash));
    
    // ========== PHASE 3: Attempt UTXO Blocking (should be REJECTED) ==========
    log_it(L_INFO, "PHASE 3: Attempting UTXO blocking operations (all should be REJECTED)");
    
    // Step 3.1: Try UTXO_BLOCKED_ADD
    log_it(L_DEBUG, "  Test 3.1: UTXO_BLOCKED_ADD (should fail)");
    size_t l_update_size = 0;
    dap_chain_datum_token_t *l_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "NOBLOCK", &l_tx_fixture->tx_hash, 0, l_cert, 0, &l_update_size);
    dap_assert_PIF(l_update != NULL, "Token update (ADD) created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_update, l_update_size, dap_time_now());
    log_it(L_INFO, "    UTXO_BLOCKED_ADD result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN, 
                   "UTXO_BLOCKED_ADD correctly REJECTED (TSD_FORBIDDEN)");
    DAP_DELETE(l_update);
    
    // Step 3.2: Try UTXO_BLOCKED_REMOVE (should also fail, even though nothing is blocked)
    log_it(L_DEBUG, "  Test 3.2: UTXO_BLOCKED_REMOVE (should fail)");
    l_update = utxo_blocking_test_create_token_update_with_utxo_unblock_tsd(
        "NOBLOCK", &l_tx_fixture->tx_hash, 0, l_cert, 0, &l_update_size);
    dap_assert_PIF(l_update != NULL, "Token update (REMOVE) created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_update, l_update_size, dap_time_now());
    log_it(L_INFO, "    UTXO_BLOCKED_REMOVE result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN, 
                   "UTXO_BLOCKED_REMOVE correctly REJECTED (TSD_FORBIDDEN)");
    DAP_DELETE(l_update);
    
    // Step 3.3: Try UTXO_BLOCKED_CLEAR (should also fail)
    log_it(L_DEBUG, "  Test 3.3: UTXO_BLOCKED_CLEAR (should fail)");
    dap_tsd_t *l_tsd_clear = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_CLEAR, NULL, 0);
    dap_assert_PIF(l_tsd_clear != NULL, "TSD CLEAR created");
    
    dap_chain_datum_token_t *l_clear_token = DAP_NEW_Z(dap_chain_datum_token_t);
    dap_assert_PIF(l_clear_token != NULL, "Token datum (CLEAR) allocation");
    
    l_clear_token->version = 2;
    l_clear_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_clear_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_clear_token->ticker, "NOBLOCK", DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_clear_token->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_clear_token->signs_valid = 0;
    l_clear_token->total_supply = uint256_0;
    l_clear_token->header_native_decl.decimals = 0;
    l_clear_token->header_native_decl.flags = 0;
    l_clear_token->signs_total = 0;
    
    size_t l_tsd_clear_size = dap_tsd_size(l_tsd_clear);
    l_clear_token->header_native_decl.tsd_total_size = l_tsd_clear_size;
    
    l_clear_token = DAP_REALLOC(l_clear_token, sizeof(dap_chain_datum_token_t) + l_tsd_clear_size);
    dap_assert_PIF(l_clear_token != NULL, "Token realloc for TSD");
    memcpy(l_clear_token->tsd_n_signs, l_tsd_clear, l_tsd_clear_size);
    DAP_DELETE(l_tsd_clear);
    
    dap_sign_t *l_clear_sign = dap_cert_sign(l_cert, l_clear_token, sizeof(dap_chain_datum_token_t) + l_tsd_clear_size);
    dap_assert_PIF(l_clear_sign != NULL, "Token update (CLEAR) signing");
    
    size_t l_clear_sign_size = dap_sign_get_size(l_clear_sign);
    l_clear_token = DAP_REALLOC(l_clear_token, sizeof(dap_chain_datum_token_t) + l_tsd_clear_size + l_clear_sign_size);
    dap_assert_PIF(l_clear_token != NULL, "Token realloc for signature");
    memcpy(l_clear_token->tsd_n_signs + l_tsd_clear_size, l_clear_sign, l_clear_sign_size);
    l_clear_token->signs_total = 1;
    DAP_DELETE(l_clear_sign);
    
    l_update_size = sizeof(dap_chain_datum_token_t) + l_tsd_clear_size + l_clear_sign_size;
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_clear_token, l_update_size, dap_time_now());
    log_it(L_INFO, "    UTXO_BLOCKED_CLEAR result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN, 
                   "UTXO_BLOCKED_CLEAR correctly REJECTED (TSD_FORBIDDEN)");
    DAP_DELETE(l_clear_token);
    
    log_it(L_INFO, "✓ All UTXO blocking operations correctly REJECTED (flag enforcement works)");
    
    // ========== PHASE 4: Verify UTXO Spendability ==========
    log_it(L_INFO, "PHASE 4: Verifying UTXO remains spendable");
    
    // Step 4.1: Create transaction spending the UTXO
    dap_chain_datum_tx_t *l_spend_tx = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_spend_tx, &l_tx_fixture->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_spend_tx, &l_addr, dap_chain_balance_scan("500.0"), "NOBLOCK");
    dap_chain_datum_tx_add_out_ext_item(&l_spend_tx, &l_addr, dap_chain_balance_scan("500.0"), "NOBLOCK"); // Change
    dap_chain_datum_tx_add_sign_item(&l_spend_tx, l_key);
    
    dap_chain_hash_fast_t l_spend_hash;
    dap_hash_fast(l_spend_tx, dap_chain_datum_tx_get_size(l_spend_tx), &l_spend_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_spend_tx, &l_spend_hash, false, NULL);
    log_it(L_INFO, "  Spend TX result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0, "UTXO is SPENDABLE (blocking disabled)");
    DAP_DELETE(l_spend_tx);
    
    log_it(L_INFO, "✓ UTXO successfully spent (hash: %s)", dap_chain_hash_fast_to_str_static(&l_spend_hash));
    
    // ========== PHASE 5: Balance Verification ==========
    log_it(L_INFO, "PHASE 5: Verifying final balance");
    
    uint256_t l_final_balance = dap_ledger_calc_balance(s_net_fixture->ledger, &l_addr, "NOBLOCK");
    const char *l_balance_str = dap_uint256_to_char(l_final_balance, NULL);
    log_it(L_INFO, "  Final balance: %s NOBLOCK", l_balance_str);
    
    // Expected: 9000 (tx1 out[1] change) + 500 (spend out[0]) + 500 (spend out[1]) = 10000
    // (TX1:0 was spent, so we have: TX1:1 + Spend:0 + Spend:1)
    uint256_t l_expected = dap_chain_balance_scan("10000.0");
    dap_assert_PIF(compare256(l_final_balance, l_expected) == 0,
                   "Final balance matches expected value (10000.0)");
    
    log_it(L_INFO, "✓ Balance verification passed");
    
    // ========== Summary ==========
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, "UTXO_BLOCKING_DISABLED Comprehensive Verification PASSED:");
    log_it(L_NOTICE, "  ✓ Phase 1: Token created with flag (verified in ledger)");
    log_it(L_NOTICE, "  ✓ Phase 2: Emission and UTXO created successfully");
    log_it(L_NOTICE, "  ✓ Phase 3: All blocking operations rejected (ADD/REMOVE/CLEAR)");
    log_it(L_NOTICE, "  ✓ Phase 4: UTXO remains spendable");
    log_it(L_NOTICE, "  ✓ Phase 5: Balance calculations correct");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, " ");
    
    // Cleanup
    test_tx_fixture_destroy(l_tx_fixture);
    DAP_DELETE(l_token_datum);
    test_emission_fixture_destroy(l_emission_fixture);  // Also deletes l_cert
    // Note: l_cert is deleted by test_emission_fixture_destroy, don't delete twice
    
    dap_pass_msg("✅ UTXO_BLOCKING_DISABLED comprehensive test PASSED (5 phases verified)");
}

/**
 * @brief Test 7: Arbitrage Transaction Validation
 * @details NOTE: Arbitrage transactions validation is tested in:
 *          - cellframe-sdk/modules/net/dap_chain_ledger.c: s_ledger_tx_check_arbitrage_outputs()
 *          - CLI tests: utxo_blocking_cli_integration_test.c
 *          - Documentation: UTXO_BLOCKING_EXAMPLES.md section 10
 *          
 *          KEY SECURITY: Arbitrage can ONLY send funds to net->pub.fee_addr
 */
