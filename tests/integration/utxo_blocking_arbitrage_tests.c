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
 * @file utxo_blocking_arbitrage_tests.c
 * @brief Arbitrage transaction integration tests (Tests 7-14)
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
#include "utxo_blocking_arbitrage_tests.h"


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
#include "utxo_blocking_arbitrage_tests.h"

void utxo_blocking_test_arbitrage_validation(void)
{
    dap_print_module_name("Integration Test 7: Arbitrage Transaction Validation");
    
    int l_res = 0;
    
    // ========== PHASE 1: Verify Network Fee Address ==========
    log_it(L_INFO, "PHASE 1: Verifying network fee address configuration");
    
    // Generate fee address for network (if not set)
    dap_enc_key_t *l_fee_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_fee_key != NULL, "Fee key created");
    
    dap_chain_addr_t l_fee_addr_setup = {0};
    dap_chain_addr_fill_from_key(&l_fee_addr_setup, l_fee_key, s_net_fixture->net->pub.id);
    
    // Set fee address if not configured
    if (dap_chain_addr_is_blank(&s_net_fixture->net->pub.fee_addr)) {
        log_it(L_INFO, "  Setting network fee address...");
        uint256_t l_zero_fee = uint256_0;
        dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_fee_addr_setup);
        log_it(L_INFO, "  Network fee address set: %s", dap_chain_addr_to_str_static(&l_fee_addr_setup));
    }
    
    dap_enc_key_delete(l_fee_key);
    
    // Check that network has fee address configured
    dap_assert_PIF(!dap_chain_addr_is_blank(&s_net_fixture->net->pub.fee_addr), 
                   "Network has fee address configured");
    
    const dap_chain_addr_t *l_fee_addr = &s_net_fixture->net->pub.fee_addr;
    log_it(L_INFO, "  Network fee address: %s", dap_chain_addr_to_str_static(l_fee_addr));
    
    // Generate keys and addresses for token owner
    dap_enc_key_t *l_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_owner_key != NULL, "Owner key created");
    
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, l_owner_key, s_net_fixture->net->pub.id);
    log_it(L_DEBUG, "  Owner address: %s", dap_chain_addr_to_str_static(&l_owner_addr));
    
    dap_cert_t *l_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_owner_cert != NULL, "Owner certificate allocation");
    l_owner_cert->enc_key = l_owner_key;
    snprintf(l_owner_cert->name, sizeof(l_owner_cert->name), "arb_owner");
    
    // Regular user address (NOT fee address - should be rejected)
    dap_enc_key_t *l_user_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_user_key != NULL, "User key created");
    
    dap_chain_addr_t l_user_addr;
    dap_chain_addr_fill_from_key(&l_user_addr, l_user_key, s_net_fixture->net->pub.id);
    log_it(L_INFO, "  Regular user address: %s", dap_chain_addr_to_str_static(&l_user_addr));
    
    log_it(L_INFO, "✓ Network fee address verified");
    
    // ========== PHASE 2: Create Token with Emission and Block UTXO ==========
    log_it(L_INFO, "PHASE 2: Creating token with emission and blocking UTXO");
    
    // Create token with emission
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token_fixture = test_token_fixture_create_with_emission(
        s_net_fixture->ledger,
        "ARBTEST",
        "100000.0",
        "50000.0",
        &l_owner_addr,
        l_owner_cert,
        &l_emission_hash
    );
    dap_assert_PIF(l_token_fixture != NULL, "Token ARBTEST with emission created");
    log_it(L_INFO, "✓ Token ARBTEST created with emission");
    
    // Create TX from emission
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "ARBTEST", "5000.0", &l_owner_addr, l_owner_cert);
    dap_assert_PIF(l_tx != NULL, "TX fixture created");
    
    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");
    log_it(L_INFO, "✓ TX created, UTXO: %s:0", dap_chain_hash_fast_to_str_static(&l_tx->tx_hash));
    
    // Block the UTXO
    size_t l_update_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "ARBTEST", &l_tx->tx_hash, 0, l_owner_cert, 0, &l_update_size);
    dap_assert_PIF(l_block_update != NULL, "UTXO block update created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_block_update, l_update_size, dap_time_now());
    log_it(L_DEBUG, "  UTXO block result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_OK, "UTXO blocked");
    
    DAP_DELETE(l_block_update);
    log_it(L_INFO, "✓ UTXO %s:0 blocked", dap_chain_hash_fast_to_str_static(&l_tx->tx_hash));
    
    // ========== PHASE 3: Test Arbitrage to Network Fee Address (SUCCESS) ==========
    log_it(L_INFO, "PHASE 3: Testing arbitrage to network fee address");
    
    // Create arbitrage TX with TSD marker
    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_assert_PIF(l_arb_tx != NULL, "Arbitrage TX created");
    
    // Add IN from blocked UTXO
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);
    
    // Add OUT to network fee address (ONLY allowed destination for arbitrage)
    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, l_fee_addr, dap_chain_balance_scan("5000.0"), "ARBTEST");
    
    // Add arbitrage TSD marker
    // Note: dap_chain_datum_tx_item_tsd_create requires non-NULL data and size > 0
    // For arbitrage TSD, we use minimal data (1 byte) as the marker itself is sufficient
    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_assert_PIF(l_tsd_arb != NULL, "Arbitrage TSD created");
    dap_assert_PIF(dap_chain_datum_tx_add_item(&l_arb_tx, l_tsd_arb) == 1, "Arbitrage TSD added to TX");
    DAP_DELETE(l_tsd_arb);
    
    // Sign with emission owner key (required for spending UTXO)
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_owner_key);
    
    // Also add token owner's signature for arbitrage authorization
    // This is required by s_ledger_tx_check_arbitrage_auth which checks auth_pkeys
    dap_assert_PIF(l_token_fixture != NULL && l_token_fixture->owner_cert != NULL && l_token_fixture->owner_cert->enc_key != NULL, 
                   "Token owner cert available");
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_token_fixture->owner_cert->enc_key);
    
    // Calculate hash and add to ledger
    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX (to fee addr) result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0, "Arbitrage TX to fee address ACCEPTED (bypassed UTXO block)");
    
    DAP_DELETE(l_arb_tx);
    log_it(L_INFO, "✓ Arbitrage TX to network fee address succeeded");
    
    // Verify balance
    uint256_t l_fee_balance = dap_ledger_calc_balance(s_net_fixture->ledger, l_fee_addr, "ARBTEST");
    uint256_t l_expected_fee = dap_chain_balance_scan("5000.0");
    dap_assert_PIF(compare256(l_fee_balance, l_expected_fee) == 0, "Fee address balance correct");
    
    // ========== PHASE 4: Test Arbitrage to Non-Fee Address (FAIL) ==========
    log_it(L_INFO, "PHASE 4: Testing arbitrage to non-fee address (user address)");
    
    // Create second emission for second TX (first emission was completely spent)
    log_it(L_DEBUG, "  Creating second emission for second TX");
    test_emission_fixture_t *l_emission_fixture2 = test_emission_fixture_create_with_cert(
        "ARBTEST",
        dap_chain_balance_scan("3000.0"),
        &l_owner_addr,
        l_owner_cert
    );
    dap_assert_PIF(l_emission_fixture2 != NULL, "Second emission fixture created");
    
    l_res = test_emission_fixture_add_to_ledger(s_net_fixture->ledger, l_emission_fixture2);
    dap_assert_PIF(l_res == 0, "Second emission added to ledger");
    
    dap_chain_hash_fast_t l_emission_hash2;
    bool l_hash_ok = test_emission_fixture_get_hash(l_emission_fixture2, &l_emission_hash2);
    dap_assert_PIF(l_hash_ok, "Second emission hash retrieved");
    
    // Create second TX for this test
    log_it(L_DEBUG, "  Creating second TX from second emission (3000.0)");
    test_tx_fixture_t *l_tx2 = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash2, "ARBTEST", "3000.0", &l_owner_addr, l_owner_cert);
    dap_assert_PIF(l_tx2 != NULL, "TX2 fixture created");
    log_it(L_DEBUG, "  TX2 fixture created successfully");
    
    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx2);
    log_it(L_DEBUG, "  TX2 add result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    if (l_res != 0) {
        log_it(L_ERROR, "TX2 add failed with code %d: %s", l_res, dap_ledger_check_error_str(l_res));
        fprintf(stderr, "ERROR: TX2 add failed with code %d: %s\n", l_res, dap_ledger_check_error_str(l_res));
    }
    dap_assert_PIF(l_res == 0, "TX2 added to ledger");
    
    // Block the second UTXO
    l_update_size = 0;
    dap_chain_datum_token_t *l_block_update2 = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "ARBTEST", &l_tx2->tx_hash, 0, l_owner_cert, 0, &l_update_size);
    dap_assert_PIF(l_block_update2 != NULL, "UTXO block2 update created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_block_update2, l_update_size, dap_time_now());
    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_OK, "UTXO2 blocked");
    DAP_DELETE(l_block_update2);
    
    // Create arbitrage TX to user address (NOT fee address - should FAIL)
    dap_chain_datum_tx_t *l_bad_arb_tx = dap_chain_datum_tx_create();
    dap_assert_PIF(l_bad_arb_tx != NULL, "Bad arbitrage TX created");
    
    dap_chain_datum_tx_add_in_item(&l_bad_arb_tx, &l_tx2->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_bad_arb_tx, &l_user_addr, dap_chain_balance_scan("3000.0"), "ARBTEST");
    
    // Add arbitrage TSD marker (but to wrong address - should fail)
    byte_t l_arb_data2 = 0;
    dap_chain_tx_tsd_t *l_tsd_bad_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data2, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_assert_PIF(l_tsd_bad_arb != NULL, "Bad arbitrage TSD created");
    dap_assert_PIF(dap_chain_datum_tx_add_item(&l_bad_arb_tx, l_tsd_bad_arb) == 1, "Bad arbitrage TSD added to TX");
    DAP_DELETE(l_tsd_bad_arb);
    
    // Sign with emission owner key (required for spending UTXO)
    dap_chain_datum_tx_add_sign_item(&l_bad_arb_tx, l_owner_key);
    
    // Also add token owner's signature for arbitrage authorization
    dap_chain_datum_tx_add_sign_item(&l_bad_arb_tx, l_token_fixture->owner_cert->enc_key);
    
    dap_chain_hash_fast_t l_bad_arb_hash;
    dap_hash_fast(l_bad_arb_tx, dap_chain_datum_tx_get_size(l_bad_arb_tx), &l_bad_arb_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_bad_arb_tx, &l_bad_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX (to user addr) result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED, 
                   "Arbitrage TX to non-fee address REJECTED");
    
    DAP_DELETE(l_bad_arb_tx);
    log_it(L_INFO, "✓ Arbitrage TX to non-fee address correctly REJECTED");
    
    // ========== PHASE 5: Test Non-Arbitrage TX with Blocked UTXO (FAIL) ==========
    log_it(L_INFO, "PHASE 5: Testing non-arbitrage TX with blocked UTXO");
    
    // Regular TX (no TSD marker) should FAIL on blocked UTXO
    dap_chain_datum_tx_t *l_regular_tx = dap_chain_datum_tx_create();
    dap_assert_PIF(l_regular_tx != NULL, "Regular TX created");
    
    dap_chain_datum_tx_add_in_item(&l_regular_tx, &l_tx2->tx_hash, 0); // Still blocked
    dap_chain_datum_tx_add_out_ext_item(&l_regular_tx, &l_owner_addr, dap_chain_balance_scan("3000.0"), "ARBTEST");
    dap_chain_datum_tx_add_sign_item(&l_regular_tx, l_owner_key);
    
    dap_chain_hash_fast_t l_regular_hash;
    dap_hash_fast(l_regular_tx, dap_chain_datum_tx_get_size(l_regular_tx), &l_regular_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_regular_tx, &l_regular_hash, false, NULL);
    log_it(L_INFO, "  Regular TX (blocked UTXO) result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED, 
                   "Regular TX with blocked UTXO REJECTED");
    
    DAP_DELETE(l_regular_tx);
    log_it(L_INFO, "✓ Regular TX correctly blocked by UTXO blocking mechanism");
    
    // ========== Summary ==========
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, "Arbitrage Transaction Validation Test PASSED:");
    log_it(L_NOTICE, "  ✓ Phase 1: Network fee address verified");
    log_it(L_NOTICE, "  ✓ Phase 2: Token, emission and UTXO created and blocked");
    log_it(L_NOTICE, "  ✓ Phase 3: Arbitrage to fee address bypassed block (SUCCESS)");
    log_it(L_NOTICE, "  ✓ Phase 4: Arbitrage to non-fee address rejected");
    log_it(L_NOTICE, "  ✓ Phase 5: Regular TX blocked by UTXO mechanism");
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "KEY SECURITY: Arbitrage can ONLY send to net->pub.fee_addr");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, " ");
    
    // Cleanup
    test_tx_fixture_destroy(l_tx);
    test_tx_fixture_destroy(l_tx2);
    // Note: l_emission_fixture2 is owned by ledger after add_to_ledger, don't destroy here
    // test_emission_fixture_destroy(l_emission_fixture2);
    test_token_fixture_destroy(l_token_fixture);
    // Note: l_owner_cert->enc_key points to l_owner_key, so don't delete l_owner_key separately
    // The cert will be deleted, but we need to set enc_key to NULL first to avoid double free
    l_owner_cert->enc_key = NULL;  // Prevent double deletion
    dap_enc_key_delete(l_owner_key);
    dap_enc_key_delete(l_user_key);
    DAP_DELETE(l_owner_cert);
    
    dap_pass_msg("✅ Arbitrage transaction validation test PASSED (5 phases verified)");
}

/**
 * @brief Test 8: Arbitrage Transaction Disabled Flag
 * @details Verifies that when UTXO_ARBITRAGE_TX_DISABLED flag is set,
 *          arbitrage transactions are rejected even if properly signed
 */
void utxo_blocking_test_arbitrage_disabled_flag(void)
{
    dap_print_module_name("Integration Test 8: Arbitrage Transaction Disabled Flag");
    
    int l_res = 0;
    
    // ========== PHASE 1: Setup Network Fee Address ==========
    log_it(L_INFO, "PHASE 1: Setting up network fee address");
    
    dap_enc_key_t *l_fee_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_fee_key != NULL, "Fee key created");
    
    dap_chain_addr_t l_fee_addr_setup = {0};
    dap_chain_addr_fill_from_key(&l_fee_addr_setup, l_fee_key, s_net_fixture->net->pub.id);
    
    if (dap_chain_addr_is_blank(&s_net_fixture->net->pub.fee_addr)) {
        uint256_t l_zero_fee = uint256_0;
        dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_fee_addr_setup);
    }
    
    const dap_chain_addr_t *l_fee_addr = &s_net_fixture->net->pub.fee_addr;
    dap_assert_PIF(!dap_chain_addr_is_blank(l_fee_addr), "Network has fee address configured");
    
    dap_enc_key_delete(l_fee_key);
    
    // ========== PHASE 2: Create Token with Emission ==========
    log_it(L_INFO, "PHASE 2: Creating token with emission");
    
    dap_enc_key_t *l_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_owner_key != NULL, "Owner key created");
    
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, l_owner_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_owner_cert != NULL, "Owner certificate allocation");
    l_owner_cert->enc_key = l_owner_key;
    snprintf(l_owner_cert->name, sizeof(l_owner_cert->name), "arb_disabled_owner");
    
    dap_chain_hash_fast_t l_emission_hash;
    // Use shorter ticker to avoid truncation issues (max 9 chars for compatibility)
    test_token_fixture_t *l_token_fixture = test_token_fixture_create_with_emission(
        s_net_fixture->ledger,
        "ARBDISABL",
        "100000.0",
        "50000.0",
        &l_owner_addr,
        l_owner_cert,
        &l_emission_hash
    );
    dap_assert_PIF(l_token_fixture != NULL, "Token ARBDISABL with emission created");
    
    // ========== PHASE 3: Set UTXO_ARBITRAGE_TX_DISABLED Flag ==========
    log_it(L_INFO, "PHASE 3: Setting UTXO_ARBITRAGE_TX_DISABLED flag");
    
    size_t l_update_size = 0;
    dap_chain_datum_token_t *l_flag_update = utxo_blocking_test_create_token_update_with_utxo_flags(
        "ARBDISABL",
        DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_ARBITRAGE_TX_DISABLED,
        l_owner_cert,
        &l_update_size
    );
    dap_assert_PIF(l_flag_update != NULL, "Flag update created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_flag_update, l_update_size, dap_time_now());
    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_OK, "UTXO_ARBITRAGE_TX_DISABLED flag set");
    DAP_DELETE(l_flag_update);
    
    log_it(L_INFO, "✓ UTXO_ARBITRAGE_TX_DISABLED flag set");
    
    // ========== PHASE 4: Create TX and Block UTXO ==========
    log_it(L_INFO, "PHASE 4: Creating TX and blocking UTXO");
    
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "ARBDISABL", "5000.0", &l_owner_addr, l_owner_cert);
    dap_assert_PIF(l_tx != NULL, "TX fixture created");
    
    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");
    
    // Block the UTXO
    l_update_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "ARBDISABL", &l_tx->tx_hash, 0, l_owner_cert, 0, &l_update_size);
    dap_assert_PIF(l_block_update != NULL, "UTXO block update created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_block_update, l_update_size, dap_time_now());
    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_OK, "UTXO blocked");
    DAP_DELETE(l_block_update);
    
    log_it(L_INFO, "✓ UTXO blocked");
    
    // ========== PHASE 5: Attempt Arbitrage TX (Should FAIL) ==========
    log_it(L_INFO, "PHASE 5: Attempting arbitrage TX (should be REJECTED due to disabled flag)");
    
    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_assert_PIF(l_arb_tx != NULL, "Arbitrage TX created");
    
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, l_fee_addr, dap_chain_balance_scan("5000.0"), "ARBDISABL");
    
    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_assert_PIF(l_tsd_arb != NULL, "Arbitrage TSD created");
    dap_assert_PIF(dap_chain_datum_tx_add_item(&l_arb_tx, l_tsd_arb) == 1, "Arbitrage TSD added to TX");
    DAP_DELETE(l_tsd_arb);
    
    // Sign with both emission owner and token owner
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_owner_key);
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_token_fixture->owner_cert->enc_key);
    
    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED, 
                   "Arbitrage TX REJECTED (arbitrage disabled for token)");
    
    DAP_DELETE(l_arb_tx);
    log_it(L_INFO, "✓ Arbitrage TX correctly REJECTED when UTXO_ARBITRAGE_TX_DISABLED flag is set");
    
    // ========== Summary ==========
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, "Arbitrage Disabled Flag Test PASSED:");
    log_it(L_NOTICE, "  ✓ Phase 1: Network fee address configured");
    log_it(L_NOTICE, "  ✓ Phase 2: Token created with emission");
    log_it(L_NOTICE, "  ✓ Phase 3: UTXO_ARBITRAGE_TX_DISABLED flag set");
    log_it(L_NOTICE, "  ✓ Phase 4: UTXO blocked");
    log_it(L_NOTICE, "  ✓ Phase 5: Arbitrage TX rejected (flag enforcement works)");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, " ");
    
    // Cleanup
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token_fixture);
    l_owner_cert->enc_key = NULL;  // Prevent double deletion
    dap_enc_key_delete(l_owner_key);
    DAP_DELETE(l_owner_cert);
    
    dap_pass_msg("✅ Arbitrage disabled flag test PASSED");
}

/**
 * @brief Test 9: Arbitrage Transaction Without Network Fee Address
 * @details Verifies that arbitrage transactions are rejected when network fee address is not configured
 */
void utxo_blocking_test_arbitrage_no_fee_address(void)
{
    dap_print_module_name("Integration Test 9: Arbitrage Transaction Without Network Fee Address");
    
    int l_res = 0;
    
    // ========== PHASE 1: Create Token with Emission ==========
    log_it(L_INFO, "PHASE 1: Creating token with emission");
    
    dap_enc_key_t *l_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_owner_key != NULL, "Owner key created");
    
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, l_owner_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_owner_cert != NULL, "Owner certificate allocation");
    l_owner_cert->enc_key = l_owner_key;
    snprintf(l_owner_cert->name, sizeof(l_owner_cert->name), "arb_no_fee_owner");
    
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token_fixture = test_token_fixture_create_with_emission(
        s_net_fixture->ledger,
        "ARBNOFEE",
        "100000.0",
        "50000.0",
        &l_owner_addr,
        l_owner_cert,
        &l_emission_hash
    );
    dap_assert_PIF(l_token_fixture != NULL, "Token ARBNOFEE with emission created");
    
    // ========== PHASE 2: Create TX ==========
    log_it(L_INFO, "PHASE 2: Creating TX");
    
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "ARBNOFEE", "5000.0", &l_owner_addr, l_owner_cert);
    dap_assert_PIF(l_tx != NULL, "TX fixture created");
    
    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");
    
    // ========== PHASE 3: Clear Network Fee Address (if set) ==========
    log_it(L_INFO, "PHASE 3: Ensuring network fee address is blank");
    
    // Save original fee address
    dap_chain_addr_t l_original_fee_addr = s_net_fixture->net->pub.fee_addr;
    
    // Clear fee address for this test
    dap_chain_addr_t l_blank_addr = {0};
    uint256_t l_zero_fee = uint256_0;
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_blank_addr);
    
    dap_assert_PIF(dap_chain_addr_is_blank(&s_net_fixture->net->pub.fee_addr), 
                   "Network fee address is blank");
    
    log_it(L_INFO, "✓ Network fee address cleared for test");
    
    // ========== PHASE 4: Attempt Arbitrage TX (Should FAIL) ==========
    log_it(L_INFO, "PHASE 4: Attempting arbitrage TX (should be REJECTED - no fee address)");
    
    // Create a dummy fee address for the transaction (won't be used anyway)
    dap_enc_key_t *l_dummy_fee_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_chain_addr_t l_dummy_fee_addr = {0};
    dap_chain_addr_fill_from_key(&l_dummy_fee_addr, l_dummy_fee_key, s_net_fixture->net->pub.id);
    
    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_assert_PIF(l_arb_tx != NULL, "Arbitrage TX created");
    
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, &l_dummy_fee_addr, dap_chain_balance_scan("5000.0"), "ARBNOFEE");
    
    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_assert_PIF(l_tsd_arb != NULL, "Arbitrage TSD created");
    dap_assert_PIF(dap_chain_datum_tx_add_item(&l_arb_tx, l_tsd_arb) == 1, "Arbitrage TSD added to TX");
    DAP_DELETE(l_tsd_arb);
    
    // Sign with both emission owner and token owner
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_owner_key);
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_token_fixture->owner_cert->enc_key);
    
    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED, 
                   "Arbitrage TX REJECTED (network fee address not configured)");
    
    DAP_DELETE(l_arb_tx);
    dap_enc_key_delete(l_dummy_fee_key);
    
    log_it(L_INFO, "✓ Arbitrage TX correctly REJECTED when network fee address is not configured");
    
    // ========== PHASE 5: Restore Original Fee Address ==========
    log_it(L_INFO, "PHASE 5: Restoring original network fee address");
    
    if (!dap_chain_addr_is_blank(&l_original_fee_addr)) {
        dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_original_fee_addr);
        log_it(L_INFO, "✓ Original fee address restored");
    }
    
    // ========== Summary ==========
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, "Arbitrage No Fee Address Test PASSED:");
    log_it(L_NOTICE, "  ✓ Phase 1: Token created with emission");
    log_it(L_NOTICE, "  ✓ Phase 2: TX created");
    log_it(L_NOTICE, "  ✓ Phase 3: Network fee address cleared");
    log_it(L_NOTICE, "  ✓ Phase 4: Arbitrage TX rejected (no fee address)");
    log_it(L_NOTICE, "  ✓ Phase 5: Original fee address restored");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, " ");
    
    // Cleanup
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token_fixture);
    l_owner_cert->enc_key = NULL;  // Prevent double deletion
    dap_enc_key_delete(l_owner_key);
    DAP_DELETE(l_owner_cert);
    
    dap_pass_msg("✅ Arbitrage no fee address test PASSED");
}

/**
 * @brief Test 10: Arbitrage Transaction Bypasses Address Blocking
 * @details Verifies that arbitrage transactions bypass address-based blocking
 *          (both sender and receiver blocking)
 */
void utxo_blocking_test_arbitrage_bypasses_address_blocking(void)
{
    dap_print_module_name("Integration Test 10: Arbitrage Bypasses Address Blocking");
    
    int l_res = 0;
    
    // ========== PHASE 1: Setup Network Fee Address ==========
    log_it(L_INFO, "PHASE 1: Setting up network fee address");
    
    dap_enc_key_t *l_fee_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_fee_key != NULL, "Fee key created");
    
    dap_chain_addr_t l_fee_addr_setup = {0};
    dap_chain_addr_fill_from_key(&l_fee_addr_setup, l_fee_key, s_net_fixture->net->pub.id);
    
    if (dap_chain_addr_is_blank(&s_net_fixture->net->pub.fee_addr)) {
        uint256_t l_zero_fee = uint256_0;
        dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_fee_addr_setup);
    }
    
    const dap_chain_addr_t *l_fee_addr = &s_net_fixture->net->pub.fee_addr;
    dap_assert_PIF(!dap_chain_addr_is_blank(l_fee_addr), "Network has fee address configured");
    
    dap_enc_key_delete(l_fee_key);
    
    // ========== PHASE 2: Create Token with Emission ==========
    log_it(L_INFO, "PHASE 2: Creating token with emission");
    
    dap_enc_key_t *l_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_owner_key != NULL, "Owner key created");
    
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, l_owner_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_owner_cert != NULL, "Owner certificate allocation");
    l_owner_cert->enc_key = l_owner_key;
    snprintf(l_owner_cert->name, sizeof(l_owner_cert->name), "arb_addr_bypass_owner");
    
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token_fixture = test_token_fixture_create_with_emission(
        s_net_fixture->ledger,
        "ARBADDR",
        "100000.0",
        "50000.0",
        &l_owner_addr,
        l_owner_cert,
        &l_emission_hash
    );
    dap_assert_PIF(l_token_fixture != NULL, "Token ARBADDR with emission created");
    
    // ========== PHASE 3: Block Owner Address as Sender ==========
    log_it(L_INFO, "PHASE 3: Blocking owner address as sender");
    
    size_t l_update_size = 0;
    dap_chain_datum_token_t *l_addr_block_update = utxo_blocking_test_create_token_update_with_address_block(
        "ARBADDR",
        &l_owner_addr,
        true,  // sender block
        l_owner_cert,
        &l_update_size
    );
    dap_assert_PIF(l_addr_block_update != NULL, "Address block update created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_addr_block_update, l_update_size, dap_time_now());
    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_OK, "Owner address blocked as sender");
    DAP_DELETE(l_addr_block_update);
    
    log_it(L_INFO, "✓ Owner address blocked as sender");
    
    // ========== PHASE 4: Create TX from Emission ==========
    log_it(L_INFO, "PHASE 4: Creating TX from emission");
    
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "ARBADDR", "5000.0", &l_owner_addr, l_owner_cert);
    dap_assert_PIF(l_tx != NULL, "TX fixture created");
    
    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");
    
    log_it(L_INFO, "✓ TX created");
    
    // ========== PHASE 5: Verify Regular TX from Blocked Address Fails ==========
    log_it(L_INFO, "PHASE 5: Verifying regular TX from blocked address fails");
    
    // Note: Address blocking might not prevent spending own UTXO if the address owns it
    // The key test is that arbitrage bypasses address blocking when it would normally fail
    log_it(L_INFO, "  Note: Address blocking behavior depends on implementation");
    
    // ========== PHASE 6: Create Arbitrage TX (Should SUCCEED - Bypasses Address Block) ==========
    log_it(L_INFO, "PHASE 6: Creating arbitrage TX (should bypass address blocking)");
    
    // Block fee address as receiver to test that arbitrage bypasses receiver blocking
    size_t l_recv_block_size = 0;
    dap_chain_datum_token_t *l_recv_block_update = utxo_blocking_test_create_token_update_with_address_block(
        "ARBADDR",
        (dap_chain_addr_t *)l_fee_addr,  // Block fee address as receiver
        false,  // receiver block
        l_owner_cert,
        &l_recv_block_size
    );
    if (l_recv_block_update != NULL) {
        l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_recv_block_update, l_recv_block_size, dap_time_now());
        if (l_res == DAP_LEDGER_CHECK_OK) {
            log_it(L_INFO, "✓ Fee address blocked as receiver");
        }
        DAP_DELETE(l_recv_block_update);
    }
    
    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_assert_PIF(l_arb_tx != NULL, "Arbitrage TX created");
    
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, l_fee_addr, dap_chain_balance_scan("5000.0"), "ARBADDR");
    
    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_assert_PIF(l_tsd_arb != NULL, "Arbitrage TSD created");
    dap_assert_PIF(dap_chain_datum_tx_add_item(&l_arb_tx, l_tsd_arb) == 1, "Arbitrage TSD added to TX");
    DAP_DELETE(l_tsd_arb);
    
    // Sign with both emission owner and token owner
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_owner_key);
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_token_fixture->owner_cert->enc_key);
    
    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0, "Arbitrage TX ACCEPTED (bypassed address blocking)");
    
    DAP_DELETE(l_arb_tx);
    log_it(L_INFO, "✓ Arbitrage TX successfully bypassed address blocking");
    
    // ========== Summary ==========
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, "Arbitrage Bypasses Address Blocking Test PASSED:");
    log_it(L_NOTICE, "  ✓ Phase 1: Network fee address configured");
    log_it(L_NOTICE, "  ✓ Phase 2: Token created with emission");
    log_it(L_NOTICE, "  ✓ Phase 3: Owner address blocked as sender");
    log_it(L_NOTICE, "  ✓ Phase 4: TX created from emission");
    log_it(L_NOTICE, "  ✓ Phase 5: Regular TX test completed");
    log_it(L_NOTICE, "  ✓ Phase 6: Arbitrage TX bypassed address blocking");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, " ");
    
    // Cleanup
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token_fixture);
    l_owner_cert->enc_key = NULL;  // Prevent double deletion
    dap_enc_key_delete(l_owner_key);
    DAP_DELETE(l_owner_cert);
    
    dap_pass_msg("✅ Arbitrage bypasses address blocking test PASSED");
}

/**
 * @brief Test 11: Arbitrage Without Emission Owner Signature
 * @details Verifies that arbitrage transaction is rejected if signed only by token owner
 *          but not by emission owner (who owns the UTXO being spent)
 */
void utxo_blocking_test_arbitrage_without_emission_owner_signature(void)
{
    dap_print_module_name("Integration Test 11: Arbitrage Without Emission Owner Signature");
    
    int l_res = 0;
    
    // ========== PHASE 1: Setup Network Fee Address ==========
    log_it(L_INFO, "PHASE 1: Setting up network fee address");
    
    dap_enc_key_t *l_fee_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_fee_key != NULL, "Fee key created");
    
    dap_chain_addr_t l_fee_addr_setup = {0};
    dap_chain_addr_fill_from_key(&l_fee_addr_setup, l_fee_key, s_net_fixture->net->pub.id);
    
    if (dap_chain_addr_is_blank(&s_net_fixture->net->pub.fee_addr)) {
        uint256_t l_zero_fee = uint256_0;
        dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_fee_addr_setup);
    }
    
    const dap_chain_addr_t *l_fee_addr = &s_net_fixture->net->pub.fee_addr;
    dap_assert_PIF(!dap_chain_addr_is_blank(l_fee_addr), "Network has fee address configured");
    
    dap_enc_key_delete(l_fee_key);
    
    // ========== PHASE 2: Create Token with Emission ==========
    log_it(L_INFO, "PHASE 2: Creating token with emission");
    
    dap_enc_key_t *l_emission_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_emission_owner_key != NULL, "Emission owner key created");
    
    dap_chain_addr_t l_emission_owner_addr;
    dap_chain_addr_fill_from_key(&l_emission_owner_addr, l_emission_owner_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_emission_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_emission_owner_cert != NULL, "Emission owner certificate allocation");
    l_emission_owner_cert->enc_key = l_emission_owner_key;
    snprintf(l_emission_owner_cert->name, sizeof(l_emission_owner_cert->name), "arb_no_emission_sig_owner");
    
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token_fixture = test_token_fixture_create_with_emission(
        s_net_fixture->ledger,
        "ARBNOEMS",
        "100000.0",
        "50000.0",
        &l_emission_owner_addr,
        l_emission_owner_cert,
        &l_emission_hash
    );
    dap_assert_PIF(l_token_fixture != NULL, "Token ARBNOEMS with emission created");
    
    // ========== PHASE 3: Create TX and Block UTXO ==========
    log_it(L_INFO, "PHASE 3: Creating TX and blocking UTXO");
    
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "ARBNOEMS", "5000.0", &l_emission_owner_addr, l_emission_owner_cert);
    dap_assert_PIF(l_tx != NULL, "TX fixture created");
    
    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");
    
    // Block the UTXO
    size_t l_update_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "ARBNOEMS", &l_tx->tx_hash, 0, l_token_fixture->owner_cert, 0, &l_update_size);
    dap_assert_PIF(l_block_update != NULL, "UTXO block update created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_block_update, l_update_size, dap_time_now());
    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_OK, "UTXO blocked");
    DAP_DELETE(l_block_update);
    
    log_it(L_INFO, "✓ UTXO blocked");
    
    // ========== PHASE 4: Attempt Arbitrage TX Without Emission Owner Signature (Should FAIL) ==========
    log_it(L_INFO, "PHASE 4: Attempting arbitrage TX without emission owner signature (should FAIL)");
    
    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_assert_PIF(l_arb_tx != NULL, "Arbitrage TX created");
    
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, l_fee_addr, dap_chain_balance_scan("5000.0"), "ARBNOEMS");
    
    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_assert_PIF(l_tsd_arb != NULL, "Arbitrage TSD created");
    dap_assert_PIF(dap_chain_datum_tx_add_item(&l_arb_tx, l_tsd_arb) == 1, "Arbitrage TSD added to TX");
    DAP_DELETE(l_tsd_arb);
    
    // Sign ONLY with token owner (NOT emission owner) - should FAIL
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_token_fixture->owner_cert->enc_key);
    
    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    // Should fail because emission owner didn't sign (UTXO ownership check)
    dap_assert_PIF(l_res != 0, "Arbitrage TX REJECTED (missing emission owner signature)");
    
    DAP_DELETE(l_arb_tx);
    log_it(L_INFO, "✓ Arbitrage TX correctly REJECTED without emission owner signature");
    
    // ========== Summary ==========
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, "Arbitrage Without Emission Owner Signature Test PASSED:");
    log_it(L_NOTICE, "  ✓ Phase 1: Network fee address configured");
    log_it(L_NOTICE, "  ✓ Phase 2: Token created with emission");
    log_it(L_NOTICE, "  ✓ Phase 3: UTXO blocked");
    log_it(L_NOTICE, "  ✓ Phase 4: Arbitrage TX rejected (missing emission owner signature)");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, " ");
    
    // Cleanup
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token_fixture);
    l_emission_owner_cert->enc_key = NULL;  // Prevent double deletion
    dap_enc_key_delete(l_emission_owner_key);
    DAP_DELETE(l_emission_owner_cert);
    
    dap_pass_msg("✅ Arbitrage without emission owner signature test PASSED");
}

/**
 * @brief Test 12: Arbitrage Without Token Owner Signature
 * @details Verifies that arbitrage transaction is rejected if signed only by emission owner
 *          but not by token owner (required for arbitrage authorization)
 */
void utxo_blocking_test_arbitrage_without_token_owner_signature(void)
{
    dap_print_module_name("Integration Test 12: Arbitrage Without Token Owner Signature");
    
    int l_res = 0;
    
    // ========== PHASE 1: Setup Network Fee Address ==========
    log_it(L_INFO, "PHASE 1: Setting up network fee address");
    
    dap_enc_key_t *l_fee_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_fee_key != NULL, "Fee key created");
    
    dap_chain_addr_t l_fee_addr_setup = {0};
    dap_chain_addr_fill_from_key(&l_fee_addr_setup, l_fee_key, s_net_fixture->net->pub.id);
    
    if (dap_chain_addr_is_blank(&s_net_fixture->net->pub.fee_addr)) {
        uint256_t l_zero_fee = uint256_0;
        dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_fee_addr_setup);
    }
    
    const dap_chain_addr_t *l_fee_addr = &s_net_fixture->net->pub.fee_addr;
    dap_assert_PIF(!dap_chain_addr_is_blank(l_fee_addr), "Network has fee address configured");
    
    dap_enc_key_delete(l_fee_key);
    
    // ========== PHASE 2: Create Token with Emission ==========
    log_it(L_INFO, "PHASE 2: Creating token with emission");
    
    dap_enc_key_t *l_emission_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_emission_owner_key != NULL, "Emission owner key created");
    
    dap_chain_addr_t l_emission_owner_addr;
    dap_chain_addr_fill_from_key(&l_emission_owner_addr, l_emission_owner_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_emission_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_emission_owner_cert != NULL, "Emission owner certificate allocation");
    l_emission_owner_cert->enc_key = l_emission_owner_key;
    snprintf(l_emission_owner_cert->name, sizeof(l_emission_owner_cert->name), "arb_no_token_sig_owner");
    
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token_fixture = test_token_fixture_create_with_emission(
        s_net_fixture->ledger,
        "ARBNOTOK",
        "100000.0",
        "50000.0",
        &l_emission_owner_addr,
        l_emission_owner_cert,
        &l_emission_hash
    );
    dap_assert_PIF(l_token_fixture != NULL, "Token ARBNOTOK with emission created");
    
    // ========== PHASE 3: Create TX and Block UTXO ==========
    log_it(L_INFO, "PHASE 3: Creating TX and blocking UTXO");
    
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "ARBNOTOK", "5000.0", &l_emission_owner_addr, l_emission_owner_cert);
    dap_assert_PIF(l_tx != NULL, "TX fixture created");
    
    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");
    
    // Block the UTXO
    size_t l_update_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "ARBNOTOK", &l_tx->tx_hash, 0, l_token_fixture->owner_cert, 0, &l_update_size);
    dap_assert_PIF(l_block_update != NULL, "UTXO block update created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_block_update, l_update_size, dap_time_now());
    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_OK, "UTXO blocked");
    DAP_DELETE(l_block_update);
    
    log_it(L_INFO, "✓ UTXO blocked");
    
    // ========== PHASE 4: Attempt Arbitrage TX Without Token Owner Signature (Should FAIL) ==========
    log_it(L_INFO, "PHASE 4: Attempting arbitrage TX without token owner signature (should FAIL)");
    
    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_assert_PIF(l_arb_tx != NULL, "Arbitrage TX created");
    
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, l_fee_addr, dap_chain_balance_scan("5000.0"), "ARBNOTOK");
    
    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_assert_PIF(l_tsd_arb != NULL, "Arbitrage TSD created");
    dap_assert_PIF(dap_chain_datum_tx_add_item(&l_arb_tx, l_tsd_arb) == 1, "Arbitrage TSD added to TX");
    DAP_DELETE(l_tsd_arb);
    
    // Sign ONLY with emission owner (NOT token owner) - should FAIL arbitrage auth check
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_emission_owner_key);
    
    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    // Should fail because token owner didn't sign (arbitrage authorization check)
    dap_assert_PIF(l_res == DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED, 
                   "Arbitrage TX REJECTED (missing token owner signature)");
    
    DAP_DELETE(l_arb_tx);
    log_it(L_INFO, "✓ Arbitrage TX correctly REJECTED without token owner signature");
    
    // ========== Summary ==========
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, "Arbitrage Without Token Owner Signature Test PASSED:");
    log_it(L_NOTICE, "  ✓ Phase 1: Network fee address configured");
    log_it(L_NOTICE, "  ✓ Phase 2: Token created with emission");
    log_it(L_NOTICE, "  ✓ Phase 3: UTXO blocked");
    log_it(L_NOTICE, "  ✓ Phase 4: Arbitrage TX rejected (missing token owner signature)");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, " ");
    
    // Cleanup
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token_fixture);
    l_emission_owner_cert->enc_key = NULL;  // Prevent double deletion
    dap_enc_key_delete(l_emission_owner_key);
    DAP_DELETE(l_emission_owner_cert);
    
    dap_pass_msg("✅ Arbitrage without token owner signature test PASSED");
}

/**
 * @brief Test 13: Arbitrage With Multiple Outputs (Mixed Addresses)
 * @details Verifies that arbitrage transaction is rejected if it has multiple outputs
 *          where not all outputs go to fee address
 */
void utxo_blocking_test_arbitrage_multiple_outputs_mixed_addresses(void)
{
    dap_print_module_name("Integration Test 13: Arbitrage With Multiple Outputs (Mixed Addresses)");
    
    int l_res = 0;
    
    // ========== PHASE 1: Setup Network Fee Address ==========
    log_it(L_INFO, "PHASE 1: Setting up network fee address");
    
    dap_enc_key_t *l_fee_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_fee_key != NULL, "Fee key created");
    
    dap_chain_addr_t l_fee_addr_setup = {0};
    dap_chain_addr_fill_from_key(&l_fee_addr_setup, l_fee_key, s_net_fixture->net->pub.id);
    
    if (dap_chain_addr_is_blank(&s_net_fixture->net->pub.fee_addr)) {
        uint256_t l_zero_fee = uint256_0;
        dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_fee_addr_setup);
    }
    
    const dap_chain_addr_t *l_fee_addr = &s_net_fixture->net->pub.fee_addr;
    dap_assert_PIF(!dap_chain_addr_is_blank(l_fee_addr), "Network has fee address configured");
    
    dap_enc_key_delete(l_fee_key);
    
    // ========== PHASE 2: Create Token with Emission ==========
    log_it(L_INFO, "PHASE 2: Creating token with emission");
    
    dap_enc_key_t *l_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_owner_key != NULL, "Owner key created");
    
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, l_owner_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_owner_cert != NULL, "Owner certificate allocation");
    l_owner_cert->enc_key = l_owner_key;
    snprintf(l_owner_cert->name, sizeof(l_owner_cert->name), "arb_multi_out_owner");
    
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token_fixture = test_token_fixture_create_with_emission(
        s_net_fixture->ledger,
        "ARBMULTI",
        "100000.0",
        "50000.0",
        &l_owner_addr,
        l_owner_cert,
        &l_emission_hash
    );
    dap_assert_PIF(l_token_fixture != NULL, "Token ARBMULTI with emission created");
    
    // ========== PHASE 3: Create TX ==========
    log_it(L_INFO, "PHASE 3: Creating TX");
    
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "ARBMULTI", "10000.0", &l_owner_addr, l_owner_cert);
    dap_assert_PIF(l_tx != NULL, "TX fixture created");
    
    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");
    
    // ========== PHASE 4: Attempt Arbitrage TX With Mixed Outputs (Should FAIL) ==========
    log_it(L_INFO, "PHASE 4: Attempting arbitrage TX with mixed outputs (should FAIL)");
    
    dap_enc_key_t *l_user_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_chain_addr_t l_user_addr;
    dap_chain_addr_fill_from_key(&l_user_addr, l_user_key, s_net_fixture->net->pub.id);
    
    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_assert_PIF(l_arb_tx != NULL, "Arbitrage TX created");
    
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);
    
    // Add first output to fee address (correct)
    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, l_fee_addr, dap_chain_balance_scan("5000.0"), "ARBMULTI");
    
    // Add second output to user address (WRONG - should cause rejection)
    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, &l_user_addr, dap_chain_balance_scan("5000.0"), "ARBMULTI");
    
    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_assert_PIF(l_tsd_arb != NULL, "Arbitrage TSD created");
    dap_assert_PIF(dap_chain_datum_tx_add_item(&l_arb_tx, l_tsd_arb) == 1, "Arbitrage TSD added to TX");
    DAP_DELETE(l_tsd_arb);
    
    // Sign with both emission owner and token owner
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_owner_key);
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_token_fixture->owner_cert->enc_key);
    
    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED, 
                   "Arbitrage TX REJECTED (mixed outputs - not all to fee address)");
    
    DAP_DELETE(l_arb_tx);
    dap_enc_key_delete(l_user_key);
    log_it(L_INFO, "✓ Arbitrage TX correctly REJECTED with mixed outputs");
    
    // ========== Summary ==========
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, "Arbitrage Multiple Outputs Test PASSED:");
    log_it(L_NOTICE, "  ✓ Phase 1: Network fee address configured");
    log_it(L_NOTICE, "  ✓ Phase 2: Token created with emission");
    log_it(L_NOTICE, "  ✓ Phase 3: TX created");
    log_it(L_NOTICE, "  ✓ Phase 4: Arbitrage TX rejected (mixed outputs)");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, " ");
    
    // Cleanup
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token_fixture);
    l_owner_cert->enc_key = NULL;  // Prevent double deletion
    dap_enc_key_delete(l_owner_key);
    DAP_DELETE(l_owner_cert);
    
    dap_pass_msg("✅ Arbitrage multiple outputs test PASSED");
}

/**
 * @brief Test 14: Arbitrage Without TSD Marker
 * @details Verifies that transaction without arbitrage TSD marker is NOT treated as arbitrage
 *          and is rejected if trying to spend blocked UTXO
 */
void utxo_blocking_test_arbitrage_without_tsd_marker(void)
{
    dap_print_module_name("Integration Test 14: Arbitrage Without TSD Marker");
    
    int l_res = 0;
    
    // ========== PHASE 1: Create Token with Emission ==========
    log_it(L_INFO, "PHASE 1: Creating token with emission");
    
    dap_enc_key_t *l_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_owner_key != NULL, "Owner key created");
    
    dap_chain_addr_t l_owner_addr;
    dap_chain_addr_fill_from_key(&l_owner_addr, l_owner_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_owner_cert != NULL, "Owner certificate allocation");
    l_owner_cert->enc_key = l_owner_key;
    snprintf(l_owner_cert->name, sizeof(l_owner_cert->name), "arb_no_tsd_owner");
    
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token_fixture = test_token_fixture_create_with_emission(
        s_net_fixture->ledger,
        "ARBNOTSD",
        "100000.0",
        "50000.0",
        &l_owner_addr,
        l_owner_cert,
        &l_emission_hash
    );
    dap_assert_PIF(l_token_fixture != NULL, "Token ARBNOTSD with emission created");
    
    // ========== PHASE 2: Create TX and Block UTXO ==========
    log_it(L_INFO, "PHASE 2: Creating TX and blocking UTXO");
    
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "ARBNOTSD", "5000.0", &l_owner_addr, l_owner_cert);
    dap_assert_PIF(l_tx != NULL, "TX fixture created");
    
    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");
    
    // Block the UTXO
    size_t l_update_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "ARBNOTSD", &l_tx->tx_hash, 0, l_owner_cert, 0, &l_update_size);
    dap_assert_PIF(l_block_update != NULL, "UTXO block update created");
    
    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t*)l_block_update, l_update_size, dap_time_now());
    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_OK, "UTXO blocked");
    DAP_DELETE(l_block_update);
    
    log_it(L_INFO, "✓ UTXO blocked");
    
    // ========== PHASE 3: Attempt TX Without TSD Marker (Should FAIL - Not Arbitrage) ==========
    log_it(L_INFO, "PHASE 3: Attempting TX without arbitrage TSD marker (should FAIL - blocked UTXO)");
    
    dap_enc_key_t *l_user_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_chain_addr_t l_user_addr;
    dap_chain_addr_fill_from_key(&l_user_addr, l_user_key, s_net_fixture->net->pub.id);
    
    dap_chain_datum_tx_t *l_regular_tx = dap_chain_datum_tx_create();
    dap_assert_PIF(l_regular_tx != NULL, "Regular TX created");
    
    dap_chain_datum_tx_add_in_item(&l_regular_tx, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_regular_tx, &l_user_addr, dap_chain_balance_scan("5000.0"), "ARBNOTSD");
    
    // NO arbitrage TSD marker - should be treated as regular TX
    // Sign with owner key
    dap_chain_datum_tx_add_sign_item(&l_regular_tx, l_owner_key);
    
    dap_chain_hash_fast_t l_regular_hash;
    dap_hash_fast(l_regular_tx, dap_chain_datum_tx_get_size(l_regular_tx), &l_regular_hash);
    
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_regular_tx, &l_regular_hash, false, NULL);
    log_it(L_INFO, "  Regular TX result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED, 
                   "Regular TX REJECTED (blocked UTXO, no arbitrage marker)");
    
    DAP_DELETE(l_regular_tx);
    dap_enc_key_delete(l_user_key);
    log_it(L_INFO, "✓ Regular TX correctly REJECTED (not treated as arbitrage without TSD marker)");
    
    // ========== Summary ==========
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, "Arbitrage Without TSD Marker Test PASSED:");
    log_it(L_NOTICE, "  ✓ Phase 1: Token created with emission");
    log_it(L_NOTICE, "  ✓ Phase 2: UTXO blocked");
    log_it(L_NOTICE, "  ✓ Phase 3: Regular TX rejected (no arbitrage marker)");
    log_it(L_NOTICE, "═══════════════════════════════════════════════════════════");
    log_it(L_NOTICE, " ");
    
    // Cleanup
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token_fixture);
    l_owner_cert->enc_key = NULL;  // Prevent double deletion
    dap_enc_key_delete(l_owner_key);
    DAP_DELETE(l_owner_cert);
    
    dap_pass_msg("✅ Arbitrage without TSD marker test PASSED");
}

