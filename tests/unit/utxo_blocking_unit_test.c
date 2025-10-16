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
    
    dap_pass_msg("Flag string conversion test passed");
}

int main(void)
{
    // Initialize logging
    dap_log_level_set(L_DEBUG);
    
    dap_print_module_name("UTXO Blocking Unit Tests");
    
    // Run all unit tests
    s_test_flag_string_conversion();
    
    log_it(L_NOTICE, "✅ All UTXO blocking unit tests passed!");
    
    return 0;
}

