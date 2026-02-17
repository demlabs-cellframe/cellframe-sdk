/**
 * @file utxo_blocking_basic_tests.h
 * @brief Basic UTXO blocking integration tests (Tests 1-6)
 * @date 2025-01-16
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Test 1: Full UTXO blocking lifecycle
void utxo_blocking_test_full_utxo_blocking_lifecycle(void);

// Test 2: UTXO unblocking
void utxo_blocking_test_utxo_unblocking(void);

// Test 3: Delayed activation
void utxo_blocking_test_delayed_activation(void);

// Test 4: UTXO CLEAR operation
void utxo_blocking_test_utxo_clear_operation(void);

// Test 5: Irreversible flags
void utxo_blocking_test_irreversible_flags(void);

// Test 6: UTXO_BLOCKING_DISABLED flag behaviour
void utxo_blocking_test_utxo_blocking_disabled_behaviour(void);

#ifdef __cplusplus
}
#endif

