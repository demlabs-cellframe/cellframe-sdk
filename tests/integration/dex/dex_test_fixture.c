/**
 * @file dex_test_fixture.c
 * @brief Test fixture implementation for DEX integration tests
 * @details
 * Creates test environment with network, wallets, tokens, and DEX configuration.
 * 
 * @author Cellframe Development Team
 * @date 2025
 */

#include "dex_test_fixture.h"
#include "dap_chain_wallet_internal.h"
#include "dap_chain_net_srv_dex.h"
#include "dap_chain_net_tx.h"
#include "../fixtures/test_token_fixtures.h"
#include "../fixtures/test_transaction_fixtures.h"
#include "../fixtures/test_emission_fixtures.h"

dex_test_fixture_t* dex_test_fixture_create(void) {
    dex_test_fixture_t *fixture = DAP_NEW_Z(dex_test_fixture_t);
    
    fixture->net = test_net_fixture_create("dex_integration_test");
    if (!fixture->net) {
        log_it(L_ERROR, "Failed to create test network");
        DAP_DELETE(fixture);
        return NULL;
    }
    
    int dex_init = dap_chain_net_srv_dex_init();
    if (dex_init != 0) {
        log_it(L_ERROR, "DEX service init failed");
        test_net_fixture_destroy(fixture->net);
        DAP_DELETE(fixture);
        return NULL;
    }
    
    fixture->network_fee = dap_chain_coins_to_balance("1.0");
    // NOTE: Network fee is set AFTER token distribution (tokens distributed without fee)
    
    fixture->alice = dap_chain_wallet_create("alice", ".", (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, NULL);
    fixture->bob = dap_chain_wallet_create("bob", ".", (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, NULL);
    fixture->carol = dap_chain_wallet_create("carol", ".", (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, NULL);
    fixture->dave = dap_chain_wallet_create("dave", ".", (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, NULL);
    
    if (!fixture->alice || !fixture->bob || !fixture->carol || !fixture->dave) {
        log_it(L_ERROR, "Failed to create wallets");
        dap_chain_net_srv_dex_deinit();
        test_net_fixture_destroy(fixture->net);
        DAP_DELETE(fixture);
        return NULL;
    }
    
    dap_chain_addr_t *l_aa = dap_chain_wallet_get_addr(fixture->alice, fixture->net->net->pub.id);
    fixture->alice_addr = *l_aa; DAP_DELETE(l_aa);
    dap_chain_addr_t *l_ab = dap_chain_wallet_get_addr(fixture->bob, fixture->net->net->pub.id);
    fixture->bob_addr = *l_ab; DAP_DELETE(l_ab);
    dap_chain_addr_t *l_ac = dap_chain_wallet_get_addr(fixture->carol, fixture->net->net->pub.id);
    fixture->carol_addr = *l_ac; DAP_DELETE(l_ac);
    dap_chain_addr_t *l_ad = dap_chain_wallet_get_addr(fixture->dave, fixture->net->net->pub.id);
    fixture->dave_addr = *l_ad; DAP_DELETE(l_ad);
    
    // Default: Dave collects network fee (neutral)
    fixture->net_fee_collector = NET_FEE_DAVE;
    
    dap_chain_wallet_internal_t *alice_int = DAP_CHAIN_WALLET_INTERNAL(fixture->alice);
    dap_chain_wallet_internal_t *bob_int = DAP_CHAIN_WALLET_INTERNAL(fixture->bob);
    dap_chain_wallet_internal_t *carol_int = DAP_CHAIN_WALLET_INTERNAL(fixture->carol);
    
    dap_cert_t *alice_cert = alice_int->certs[0];
    dap_cert_t *bob_cert = bob_int->certs[0];
    dap_cert_t *carol_cert = carol_int->certs[0];
    
    // ============================================================================
    // TOKEN DISTRIBUTION STRATEGY
    // ============================================================================
    // Symmetrical reversibility principle: actors can create opposite orders
    // to "unwind" state back to initial balances (minus fees).
    //
    // ALICE (ASK seller):
    //   - CELL  = 5000   (creates ASK on CELL/* pairs)
    //   - KEL   = 10000  (creates ASK on KEL/* pairs)
    //   - USDT  = 0      (INTENTIONALLY ZERO - cannot create BID on own pairs)
    //   - TC    = 100000 (network fees)
    //
    // BOB (BID buyer → reverse ASK seller):
    //   - CELL  = 0      (INTENTIONALLY ZERO - will receive from Alice's ASK)
    //   - KEL   = 0      (INTENTIONALLY ZERO - will receive from Alice's ASK)
    //   - USDT  = 50000  (buys CELL/KEL, then creates reverse BID)
    //   - TC    = 100000 (network fees)
    //
    // CAROL (universal actor + service fee collector):
    //   - CELL  = 2000   (can participate in any pair)
    //   - KEL   = 3000   (can participate in any pair)
    //   - USDT  = 10000  (can participate in any pair)
    //   - TC    = 100000 (collects service fees + network fees)
    //
    // Example symmetric scenario:
    //   1. Alice: ASK 1000 CELL @ 10 USDT  (CELL locked)
    //   2. Bob:   BUY 1000 CELL for 10000 USDT (Alice gets USDT, Bob gets CELL)
    //   3. Bob:   BID 1000 CELL @ 10 USDT  (CELL locked, Bob now has USDT)
    //   4. Alice: SELL 1000 CELL to Bob    (Bob gets CELL back, Alice gets USDT back)
    //   Result: ~initial state (minus 2x fees + 2x network fees)
    // ============================================================================
    
    dap_chain_hash_fast_t kel_emission_hash, usdt_emission_hash, tc_emission_hash, cell_emission_hash;
    
    test_token_fixture_t *cell_token = test_token_fixture_create_with_emission(
        fixture->net->ledger, "CELL", "1000000.0", "5000.0",
        &fixture->alice_addr, alice_cert, &cell_emission_hash
    );
    if (!cell_token) {
        log_it(L_ERROR, "Failed to create CELL token");
        goto cleanup;
    }
    
    test_token_fixture_t *kel_token = test_token_fixture_create_with_emission(
        fixture->net->ledger, "KEL", "1000000.0", "10000.0",
        &fixture->alice_addr, alice_cert, &kel_emission_hash
    );
    if (!kel_token) {
        log_it(L_ERROR, "Failed to create KEL token");
        test_token_fixture_destroy(cell_token);
        goto cleanup;
    }
    
    test_token_fixture_t *usdt_token = test_token_fixture_create_with_emission(
        fixture->net->ledger, "USDT", "5000000.0", "50000.0",
        &fixture->bob_addr, bob_cert, &usdt_emission_hash
    );
    if (!usdt_token) {
        log_it(L_ERROR, "Failed to create USDT token");
        test_token_fixture_destroy(kel_token);
        test_token_fixture_destroy(cell_token);
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
        test_token_fixture_destroy(cell_token);
        goto cleanup;
    }
    
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
    
    // Carol's token emissions (universal actor + fee collector)
    dap_chain_hash_fast_t cell_carol_emission_hash = {0};
    test_emission_fixture_t *cell_carol_emission = test_emission_fixture_create_with_cert(
        "CELL", dap_chain_coins_to_balance("2000.0"), &fixture->carol_addr, carol_cert
    );
    if (!cell_carol_emission) {
        log_it(L_ERROR, "Failed to create CELL emission for Carol");
        goto cleanup;
    }
    if (test_emission_fixture_add_to_ledger(fixture->net->ledger, cell_carol_emission) != 0 ||
        !test_emission_fixture_get_hash(cell_carol_emission, &cell_carol_emission_hash)) {
        log_it(L_ERROR, "Failed to add Carol's CELL emission to ledger");
        goto cleanup;
    }
    
    dap_chain_hash_fast_t kel_carol_emission_hash = {0};
    test_emission_fixture_t *kel_carol_emission = test_emission_fixture_create_with_cert(
        "KEL", dap_chain_coins_to_balance("3000.0"), &fixture->carol_addr, carol_cert
    );
    if (!kel_carol_emission) {
        log_it(L_ERROR, "Failed to create KEL emission for Carol");
        goto cleanup;
    }
    if (test_emission_fixture_add_to_ledger(fixture->net->ledger, kel_carol_emission) != 0 ||
        !test_emission_fixture_get_hash(kel_carol_emission, &kel_carol_emission_hash)) {
        log_it(L_ERROR, "Failed to add Carol's KEL emission to ledger");
        goto cleanup;
    }
    
    dap_chain_hash_fast_t usdt_carol_emission_hash = {0};
    test_emission_fixture_t *usdt_carol_emission = test_emission_fixture_create_with_cert(
        "USDT", dap_chain_coins_to_balance("10000.0"), &fixture->carol_addr, carol_cert
    );
    if (!usdt_carol_emission) {
        log_it(L_ERROR, "Failed to create USDT emission for Carol");
        goto cleanup;
    }
    if (test_emission_fixture_add_to_ledger(fixture->net->ledger, usdt_carol_emission) != 0 ||
        !test_emission_fixture_get_hash(usdt_carol_emission, &usdt_carol_emission_hash)) {
        log_it(L_ERROR, "Failed to add Carol's USDT emission to ledger");
        goto cleanup;
    }
    
    dap_chain_hash_fast_t tc_carol_emission_hash = {0};
    test_emission_fixture_t *tc_carol_emission = test_emission_fixture_create_with_cert(
        "TestCoin", dap_chain_coins_to_balance("100000.0"), &fixture->carol_addr, carol_cert
    );
    if (!tc_carol_emission) {
        log_it(L_ERROR, "Failed to create TestCoin emission for Carol");
        goto cleanup;
    }
    if (test_emission_fixture_add_to_ledger(fixture->net->ledger, tc_carol_emission) != 0 ||
        !test_emission_fixture_get_hash(tc_carol_emission, &tc_carol_emission_hash)) {
        log_it(L_ERROR, "Failed to add Carol's TestCoin emission to ledger");
        goto cleanup;
    }
    
    test_tx_fixture_t *alice_cell_tx = test_tx_fixture_create_from_emission(
        fixture->net->ledger, &cell_emission_hash, "CELL", "5000.0", &fixture->alice_addr, alice_cert
    );
    if (!alice_cell_tx || test_tx_fixture_add_to_ledger(fixture->net->ledger, alice_cell_tx) != 0) {
        log_it(L_ERROR, "Failed to add Alice CELL TX");
        goto cleanup;
    }
    
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
    
    // Carol's transactions (universal actor + fee collector)
    test_tx_fixture_t *carol_cell_tx = test_tx_fixture_create_from_emission(
        fixture->net->ledger, &cell_carol_emission_hash, "CELL", "2000.0", &fixture->carol_addr, carol_cert
    );
    if (!carol_cell_tx || test_tx_fixture_add_to_ledger(fixture->net->ledger, carol_cell_tx) != 0) {
        log_it(L_ERROR, "Failed to add Carol CELL TX");
        goto cleanup;
    }
    
    test_tx_fixture_t *carol_kel_tx = test_tx_fixture_create_from_emission(
        fixture->net->ledger, &kel_carol_emission_hash, "KEL", "3000.0", &fixture->carol_addr, carol_cert
    );
    if (!carol_kel_tx || test_tx_fixture_add_to_ledger(fixture->net->ledger, carol_kel_tx) != 0) {
        log_it(L_ERROR, "Failed to add Carol KEL TX");
        goto cleanup;
    }
    
    test_tx_fixture_t *carol_usdt_tx = test_tx_fixture_create_from_emission(
        fixture->net->ledger, &usdt_carol_emission_hash, "USDT", "10000.0", &fixture->carol_addr, carol_cert
    );
    if (!carol_usdt_tx || test_tx_fixture_add_to_ledger(fixture->net->ledger, carol_usdt_tx) != 0) {
        log_it(L_ERROR, "Failed to add Carol USDT TX");
        goto cleanup;
    }
    
    test_tx_fixture_t *carol_tc_tx = test_tx_fixture_create_from_emission(
        fixture->net->ledger, &tc_carol_emission_hash, "TestCoin", "100000.0", &fixture->carol_addr, carol_cert
    );
    if (!carol_tc_tx || test_tx_fixture_add_to_ledger(fixture->net->ledger, carol_tc_tx) != 0) {
        log_it(L_ERROR, "Failed to add Carol TestCoin TX");
        goto cleanup;
    }
    
    // Set network fee NOW (after all token distributions, so they don't require fee)
    // Default: Dave is network fee collector (neutral, separate from service fee)
    dap_chain_net_tx_set_fee(fixture->net->net->pub.id, fixture->network_fee, fixture->dave_addr);
    log_it(L_NOTICE, "Network fee configured: 1.0 TestCoin → Dave (neutral)");
    
    int l_fee_global_set = test_decree_fee_set(fixture->net->ledger, uint256_0, &fixture->carol_addr);
    if (l_fee_global_set != 0) {
        log_it(L_ERROR, "Failed to set Carol as service wallet via decree");
        goto cleanup;
    }
    log_it(L_INFO, "Carol set as service wallet: %s", dap_chain_addr_to_str_static(&fixture->carol_addr));
    
    // Initialize all standard test pair configurations
    log_it(L_NOTICE, "Initializing standard test pair configurations...");
    const test_pair_config_t *std_pairs = test_get_standard_pairs();
    size_t std_pairs_count = test_get_standard_pairs_count();
    
    for (size_t i = 0; i < std_pairs_count; i++) {
        int ret = test_decree_pair_add(fixture->net->ledger,
                                       std_pairs[i].base_token,
                                       std_pairs[i].quote_token,
                                       fixture->net->net->pub.id,
                                       std_pairs[i].fee_config);
        if (ret != 0) {
            log_it(L_ERROR, "Failed to add pair %s/%s (config 0x%02X) via decree",
                   std_pairs[i].base_token, std_pairs[i].quote_token, std_pairs[i].fee_config);
            goto cleanup;
        }
        log_it(L_DEBUG, "✓ Pair %zu/%zu configured: %s", i+1, std_pairs_count, std_pairs[i].description);
    }
    log_it(L_NOTICE, "✓ All %zu standard pairs configured successfully", std_pairs_count);
    
    log_it(L_INFO, "DEX test fixture created successfully");
    return fixture;
    
cleanup:
    dap_chain_net_srv_dex_deinit();
    test_net_fixture_destroy(fixture->net);
    DAP_DELETE(fixture);
    return NULL;
}

void dex_test_fixture_destroy(dex_test_fixture_t *fixture) {
    if (!fixture) return;
    test_net_fixture_destroy(fixture->net);
    DAP_DELETE(fixture);
}

void dex_print_balances(dex_test_fixture_t *f, const char *label) {
    // Read balances directly from ledger (no caching)
    dap_ledger_t *ledger = f->net->net->pub.ledger;
    
    uint256_t alice_cell = dap_ledger_calc_balance(ledger, &f->alice_addr, "CELL");
    uint256_t alice_kel = dap_ledger_calc_balance(ledger, &f->alice_addr, "KEL");
    uint256_t alice_usdt = dap_ledger_calc_balance(ledger, &f->alice_addr, "USDT");
    uint256_t alice_tc = dap_ledger_calc_balance(ledger, &f->alice_addr, "TestCoin");
    
    uint256_t bob_cell = dap_ledger_calc_balance(ledger, &f->bob_addr, "CELL");
    uint256_t bob_kel = dap_ledger_calc_balance(ledger, &f->bob_addr, "KEL");
    uint256_t bob_usdt = dap_ledger_calc_balance(ledger, &f->bob_addr, "USDT");
    uint256_t bob_tc = dap_ledger_calc_balance(ledger, &f->bob_addr, "TestCoin");
    
    uint256_t carol_cell = dap_ledger_calc_balance(ledger, &f->carol_addr, "CELL");
    uint256_t carol_kel = dap_ledger_calc_balance(ledger, &f->carol_addr, "KEL");
    uint256_t carol_usdt = dap_ledger_calc_balance(ledger, &f->carol_addr, "USDT");
    uint256_t carol_tc = dap_ledger_calc_balance(ledger, &f->carol_addr, "TestCoin");
    
    uint256_t dave_tc = dap_ledger_calc_balance(ledger, &f->dave_addr, "TestCoin");
    
    log_it(L_INFO, "[%s] Alice: CELL=%s KEL=%s USDT=%s TC=%s", label,
           dap_uint256_to_char_ex(alice_cell).frac,
           dap_uint256_to_char_ex(alice_kel).frac,
           dap_uint256_to_char_ex(alice_usdt).frac,
           dap_uint256_to_char_ex(alice_tc).frac);
    log_it(L_INFO, "[%s] Bob: CELL=%s KEL=%s USDT=%s TC=%s", label,
           dap_uint256_to_char_ex(bob_cell).frac,
           dap_uint256_to_char_ex(bob_kel).frac,
           dap_uint256_to_char_ex(bob_usdt).frac,
           dap_uint256_to_char_ex(bob_tc).frac);
    log_it(L_INFO, "[%s] Carol (srv): CELL=%s KEL=%s USDT=%s TC=%s", label,
           dap_uint256_to_char_ex(carol_cell).frac,
           dap_uint256_to_char_ex(carol_kel).frac,
           dap_uint256_to_char_ex(carol_usdt).frac,
           dap_uint256_to_char_ex(carol_tc).frac);
    log_it(L_INFO, "[%s] Dave (net): TC=%s", label,
           dap_uint256_to_char_ex(dave_tc).frac);
}

