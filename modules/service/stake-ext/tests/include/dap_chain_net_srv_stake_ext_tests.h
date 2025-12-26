/*
 * Authors:
 * Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2024
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "dap_chain_net_srv_stake_ext.h"

/**
 * @brief Run all stake_ext service tests
 */
void dap_srv_stake_ext_test_run(void);

// ===== 1. stake_ext CACHE TESTS =====

/**
 * @brief Test stake_ext cache initialization and cleanup
 */
void dap_srv_stake_ext_test_cache_init(void);

/**
 * @brief Test stake_ext management in cache
 */
void dap_srv_stake_ext_test_cache_stake_ext_management(void);

/**
 * @brief Test bid management in cache
 */
void dap_srv_stake_ext_test_cache_lock_management(void);

/**
 * @brief Test cache statistics and counters
 */
void dap_srv_stake_ext_test_cache_statistics(void);

// ===== 2. stake_ext STATE TESTS =====

/**
 * @brief Test stake_ext status transitions
 */
void dap_srv_stake_ext_test_status_transitions(void);

/**
 * @brief Test stake_ext status validation and conversion
 */
void dap_srv_stake_ext_test_status_validation(void);

// ===== 3. TRANSACTION TESTS =====

/**
 * @brief Test stake_ext event processing
 */
void dap_srv_stake_ext_test_event_processing(void);

/**
 * @brief Test stake_ext lock transactions
 */
void dap_srv_stake_ext_test_lock_transactions(void);

/**
 * @brief Test lock unlock transactions
 */
void dap_srv_stake_ext_test_unlock_transactions(void);

// ===== 4. LEDGER INTEGRATION TESTS =====

/**
 * @brief Test event callback handlers
 */
void dap_srv_stake_ext_test_event_callbacks(void);

/**
 * @brief Test ledger synchronization
 */
void dap_srv_stake_ext_test_ledger_sync(void);

/**
 * @brief Test verificator functions
 */
void dap_srv_stake_ext_test_verificators(void);

// ===== 5. DATA PROCESSING TESTS =====

/**
 * @brief Test event data parsing
 */
void dap_srv_stake_ext_test_data_parsing(void);

/**
 * @brief Test boundary conditions
 */
void dap_srv_stake_ext_test_boundary_conditions(void);

// ===== 6. SECURITY AND ERROR TESTS =====

/**
 * @brief Test error handling
 */
void dap_srv_stake_ext_test_error_handling(void);

/**
 * @brief Test thread safety
 */
void dap_srv_stake_ext_test_thread_safety(void);



