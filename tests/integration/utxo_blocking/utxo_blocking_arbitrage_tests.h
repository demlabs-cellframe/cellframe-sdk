/**
 * @file utxo_blocking_arbitrage_tests.h
 * @brief Arbitrage transaction integration tests (Tests 7-14)
 * @date 2025-01-16
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Test 7: Arbitrage transaction validation
void utxo_blocking_test_arbitrage_validation(void);

// Test 8: Arbitrage disabled flag
void utxo_blocking_test_arbitrage_disabled_flag(void);

// Test 9: Arbitrage without fee address
void utxo_blocking_test_arbitrage_no_fee_address(void);

// Test 10: Arbitrage bypasses address blocking
void utxo_blocking_test_arbitrage_bypasses_address_blocking(void);

// Test 11: Arbitrage without emission owner signature
void utxo_blocking_test_arbitrage_without_emission_owner_signature(void);

// Test 12: Arbitrage without token owner signature
void utxo_blocking_test_arbitrage_without_token_owner_signature(void);

// Test 13: Arbitrage with multiple outputs (mixed addresses)
void utxo_blocking_test_arbitrage_multiple_outputs_mixed_addresses(void);

// Test 14: Arbitrage without TSD marker
void utxo_blocking_test_arbitrage_without_tsd_marker(void);

// Security regression tests (Tests 15-18)
void utxo_blocking_test_arbitrage_forged_owner_signature(void);
void utxo_blocking_test_arbitrage_duplicate_owner_key(void);
void utxo_blocking_test_arbitrage_zero_auth_signs_valid(void);
void utxo_blocking_test_arbitrage_unknown_output_type_rejected(void);

// Coverage tests (Tests 19-22)
void utxo_blocking_test_arbitrage_cross_token_bypass(void);
void utxo_blocking_test_arbitrage_two_of_two_auth(void);
void utxo_blocking_test_arbitrage_single_channel(void);
void utxo_blocking_test_arbitrage_no_auth_keys(void);

#ifdef __cplusplus
}
#endif

