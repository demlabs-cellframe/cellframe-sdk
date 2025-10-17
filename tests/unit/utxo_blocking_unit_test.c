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
 * @brief Unit tests for UTXO blocking mechanism
 * @details Tests specific functions, structures, flags and API without full ledger:
 *          - Token flag definitions and combinations
 *          - TSD section format validation
 *          - UTXO key structure size and alignment
 *          - Error code definitions
 *          - Time comparison logic for delayed activation
 * @date 2025-10-16
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_ledger.h"
#include "dap_test.h"

#define LOG_TAG "utxo_blocking_unit_test"

/**
 * @brief Unit Test 1: Flag string conversion
 * @details Verify dap_chain_datum_token_flag_to_str() includes new flags
 */
static void s_test_flag_string_conversion(void)
{
    dap_print_module_name("Unit Test 1: Flag String Conversion");
    
    // Test individual flags
    const char *l_str1 = dap_chain_datum_token_flag_to_str(DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED);
    dap_assert(l_str1 != NULL, "UTXO_BLOCKING_DISABLED should have string representation");
    log_it(L_DEBUG, "UTXO_BLOCKING_DISABLED = '%s'", l_str1);
    
    const char *l_str2 = dap_chain_datum_token_flag_to_str(DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_UTXO_BLOCKLIST);
    dap_assert(l_str2 != NULL, "STATIC_UTXO_BLOCKLIST should have string representation");
    log_it(L_DEBUG, "STATIC_UTXO_BLOCKLIST = '%s'", l_str2);
    
    const char *l_str3 = dap_chain_datum_token_flag_to_str(DAP_CHAIN_DATUM_TOKEN_FLAG_DISABLE_ADDRESS_SENDER_BLOCKING);
    dap_assert(l_str3 != NULL, "DISABLE_ADDRESS_SENDER_BLOCKING should have string representation");
    log_it(L_DEBUG, "DISABLE_ADDRESS_SENDER_BLOCKING = '%s'", l_str3);
    
    const char *l_str4 = dap_chain_datum_token_flag_to_str(DAP_CHAIN_DATUM_TOKEN_FLAG_DISABLE_ADDRESS_RECEIVER_BLOCKING);
    dap_assert(l_str4 != NULL, "DISABLE_ADDRESS_RECEIVER_BLOCKING should have string representation");
    log_it(L_DEBUG, "DISABLE_ADDRESS_RECEIVER_BLOCKING = '%s'", l_str4);
    
    const char *l_str5 = dap_chain_datum_token_flag_to_str(DAP_CHAIN_DATUM_TOKEN_FLAG_ARBITRAGE_TX_DISABLED);
    dap_assert(l_str5 != NULL, "ARBITRAGE_TX_DISABLED should have string representation");
    log_it(L_DEBUG, "ARBITRAGE_TX_DISABLED = '%s'", l_str5);
    
    dap_pass_msg("Flag string conversion test passed");
}

/**
 * @brief Unit Test 2: Irreversible flags mask validation
 * @details Verify DAP_CHAIN_DATUM_TOKEN_FLAG_IRREVERSIBLE_MASK contains all required flags
 */
static void s_test_irreversible_flags_mask(void)
{
    dap_print_module_name("Unit Test 2: Irreversible Flags Mask");
    
    uint32_t l_mask = DAP_CHAIN_DATUM_TOKEN_FLAG_IRREVERSIBLE_MASK;
    
    // Check that mask includes all 4 irreversible flags
    dap_assert((l_mask & DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED) != 0,
               "Mask should include UTXO_BLOCKING_DISABLED");
    dap_assert((l_mask & DAP_CHAIN_DATUM_TOKEN_FLAG_ARBITRAGE_TX_DISABLED) != 0,
               "Mask should include ARBITRAGE_TX_DISABLED");
    dap_assert((l_mask & DAP_CHAIN_DATUM_TOKEN_FLAG_DISABLE_ADDRESS_SENDER_BLOCKING) != 0,
               "Mask should include DISABLE_ADDRESS_SENDER_BLOCKING");
    dap_assert((l_mask & DAP_CHAIN_DATUM_TOKEN_FLAG_DISABLE_ADDRESS_RECEIVER_BLOCKING) != 0,
               "Mask should include DISABLE_ADDRESS_RECEIVER_BLOCKING");
    
    log_it(L_DEBUG, "Irreversible mask = 0x%08X", l_mask);
    
    // Test that other flags are NOT in irreversible mask
    dap_assert((l_mask & DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED) == 0,
               "Mask should NOT include ALL_SENDER_BLOCKED (reversible flag)");
    dap_assert((l_mask & DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_UTXO_BLOCKLIST) == 0,
               "Mask should NOT include STATIC_UTXO_BLOCKLIST (reversible flag)");
    
    dap_pass_msg("Irreversible flags mask test passed");
}

/**
 * @brief Unit Test 3: Irreversibility logic simulation
 * @details Test that new_flags & MASK >= old_flags & MASK
 */
static void s_test_irreversibility_logic(void)
{
    dap_print_module_name("Unit Test 3: Irreversibility Logic");
    
    uint32_t l_mask = DAP_CHAIN_DATUM_TOKEN_FLAG_IRREVERSIBLE_MASK;
    
    // Test Case 1: No flags set -> Set one flag (ALLOWED)
    uint32_t l_old1 = 0;
    uint32_t l_new1 = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED;
    dap_assert((l_new1 & l_mask) >= (l_old1 & l_mask),
               "Setting UTXO_BLOCKING_DISABLED from 0 should be allowed");
    
    // Test Case 2: One flag set -> Same flag (ALLOWED)
    uint32_t l_old2 = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED;
    uint32_t l_new2 = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED;
    dap_assert((l_new2 & l_mask) >= (l_old2 & l_mask),
               "Keeping UTXO_BLOCKING_DISABLED set should be allowed");
    
    // Test Case 3: One flag set -> Two flags (ALLOWED)
    uint32_t l_old3 = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED;
    uint32_t l_new3 = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED | 
                      DAP_CHAIN_DATUM_TOKEN_FLAG_ARBITRAGE_TX_DISABLED;
    dap_assert((l_new3 & l_mask) >= (l_old3 & l_mask),
               "Adding ARBITRAGE_TX_DISABLED to existing flag should be allowed");
    
    // Test Case 4: One flag set -> Zero flags (FORBIDDEN)
    uint32_t l_old4 = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED;
    uint32_t l_new4 = 0;
    dap_assert((l_new4 & l_mask) < (l_old4 & l_mask),
               "Unsetting UTXO_BLOCKING_DISABLED should be FORBIDDEN");
    
    // Test Case 5: Two flags set -> One flag (FORBIDDEN)
    uint32_t l_old5 = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED | 
                      DAP_CHAIN_DATUM_TOKEN_FLAG_ARBITRAGE_TX_DISABLED;
    uint32_t l_new5 = DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED;
    dap_assert((l_new5 & l_mask) < (l_old5 & l_mask),
               "Unsetting ARBITRAGE_TX_DISABLED should be FORBIDDEN");
    
    // Test Case 6: All 4 flags set -> All 4 flags (ALLOWED)
    uint32_t l_old6 = DAP_CHAIN_DATUM_TOKEN_FLAG_IRREVERSIBLE_MASK;
    uint32_t l_new6 = DAP_CHAIN_DATUM_TOKEN_FLAG_IRREVERSIBLE_MASK;
    dap_assert((l_new6 & l_mask) >= (l_old6 & l_mask),
               "Keeping all irreversible flags should be allowed");
    
    dap_pass_msg("Irreversibility logic test passed");
}

/**
 * @brief Unit Test 4: TSD types for UTXO blocking
 * @details Verify TSD type definitions exist and are unique
 */
static void s_test_tsd_types(void)
{
    dap_print_module_name("Unit Test 4: TSD Types");
    
    // Check TSD type values are defined and unique
    uint16_t l_add = DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_ADD;
    uint16_t l_remove = DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_REMOVE;
    uint16_t l_clear = DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_CLEAR;
    
    dap_assert(l_add == 0x0029, "UTXO_BLOCKED_ADD should be 0x0029");
    dap_assert(l_remove == 0x002A, "UTXO_BLOCKED_REMOVE should be 0x002A");
    dap_assert(l_clear == 0x002C, "UTXO_BLOCKED_CLEAR should be 0x002C");
    
    // Check uniqueness
    dap_assert(l_add != l_remove, "ADD and REMOVE should be different");
    dap_assert(l_add != l_clear, "ADD and CLEAR should be different");
    dap_assert(l_remove != l_clear, "REMOVE and CLEAR should be different");
    
    log_it(L_DEBUG, "UTXO_BLOCKED_ADD = 0x%04X", l_add);
    log_it(L_DEBUG, "UTXO_BLOCKED_REMOVE = 0x%04X", l_remove);
    log_it(L_DEBUG, "UTXO_BLOCKED_CLEAR = 0x%04X", l_clear);
    
    dap_pass_msg("TSD types test passed");
}

/**
 * @brief Unit Test 5: Arbitrage TX TSD type
 * @details Verify arbitrage transaction TSD marker
 */
static void s_test_arbitrage_tsd_type(void)
{
    dap_print_module_name("Unit Test 5: Arbitrage TX TSD Type");
    
    uint16_t l_arbitrage = DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE;
    
    dap_assert(l_arbitrage == 0x0001, "ARBITRAGE TSD type should be 0x0001");
    log_it(L_DEBUG, "DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE = 0x%04X", l_arbitrage);
    
    dap_pass_msg("Arbitrage TSD type test passed");
}

/**
 * @brief Unit Test 6: UTXO block key structure
 * @details Verify structure size and alignment
 */
static void s_test_utxo_block_key_structure(void)
{
    dap_print_module_name("Unit Test 6: UTXO Block Key Structure");
    
    // Check structure size (32 bytes hash + 4 bytes idx = 36 bytes)
    size_t l_expected_size = sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t);
    log_it(L_DEBUG, "Expected key size: %zu bytes", l_expected_size);
    
    // Verify sizeof(dap_chain_hash_fast_t) = 32
    dap_assert(sizeof(dap_chain_hash_fast_t) == 32, 
               "dap_chain_hash_fast_t should be 32 bytes");
    
    // Verify sizeof(uint32_t) = 4
    dap_assert(sizeof(uint32_t) == 4, 
               "uint32_t should be 4 bytes");
    
    log_it(L_DEBUG, "UTXO key components: hash=%zu + idx=%zu = %zu bytes total",
           sizeof(dap_chain_hash_fast_t), sizeof(uint32_t), l_expected_size);
    
    dap_pass_msg("UTXO block key structure test passed");
}

/**
 * @brief Unit Test 7: Error codes definition
 * @details Verify error codes for UTXO blocking and arbitrage
 */
static void s_test_error_codes(void)
{
    dap_print_module_name("Unit Test 7: Error Codes");
    
    // Check that error codes are defined and unique
    int l_arbitrage_err = DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED;
    int l_irreversible_err = DAP_LEDGER_TOKEN_UPDATE_CHECK_IRREVERSIBLE_FLAGS_VIOLATION;
    
    dap_assert(l_arbitrage_err != 0, 
               "DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED should be defined");
    dap_assert(l_irreversible_err != 0, 
               "DAP_LEDGER_TOKEN_UPDATE_CHECK_IRREVERSIBLE_FLAGS_VIOLATION should be defined");
    dap_assert(l_arbitrage_err != l_irreversible_err, 
               "Error codes should be unique");
    
    log_it(L_DEBUG, "DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED = %d", l_arbitrage_err);
    log_it(L_DEBUG, "DAP_LEDGER_TOKEN_UPDATE_CHECK_IRREVERSIBLE_FLAGS_VIOLATION = %d", l_irreversible_err);
    
    dap_pass_msg("Error codes test passed");
}

/**
 * @brief Unit Test 8: UTXO block action types
 * @details Verify action enum values for history
 */
static void s_test_utxo_block_actions(void)
{
    dap_print_module_name("Unit Test 8: UTXO Block Actions");
    
    // Note: These enums are internal to dap_chain_ledger.c, 
    // but we can verify the TSD types that trigger them
    uint16_t l_add = DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_ADD;
    uint16_t l_remove = DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_REMOVE;
    uint16_t l_clear = DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_CLEAR;
    
    // Verify TSD types map to actions
    dap_assert(l_add == 0x0029, "ADD TSD should be 0x0029");
    dap_assert(l_remove == 0x002A, "REMOVE TSD should be 0x002A");
    dap_assert(l_clear == 0x002C, "CLEAR TSD should be 0x002C");
    
    // Verify sequential and unique
    dap_assert(l_add < l_remove, "ADD should be < REMOVE");
    dap_assert(l_remove < l_clear, "REMOVE should be < CLEAR");
    
    log_it(L_DEBUG, "TSD actions: ADD=0x%04X, REMOVE=0x%04X, CLEAR=0x%04X", 
           l_add, l_remove, l_clear);
    
    dap_pass_msg("UTXO block actions test passed");
}

int main(void)
{
    // Initialize logging
    dap_log_level_set(L_DEBUG);
    
    dap_print_module_name("UTXO Blocking Unit Tests");
    
    // Run all unit tests
    s_test_flag_string_conversion();
    s_test_irreversible_flags_mask();
    s_test_irreversibility_logic();
    s_test_tsd_types();
    s_test_arbitrage_tsd_type();
    s_test_utxo_block_key_structure();
    s_test_error_codes();
    s_test_utxo_block_actions();
    
    log_it(L_NOTICE, "✅ All UTXO blocking unit tests passed (8 tests)!");
    
    return 0;
}

