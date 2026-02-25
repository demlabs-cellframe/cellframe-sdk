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

#ifdef __cplusplus
}
#endif

