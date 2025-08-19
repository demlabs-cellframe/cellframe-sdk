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

#include "dap_chain_net_srv_auctions.h"

/**
 * @brief Run all auction service tests
 */
void dap_auctions_test_run(void);

// ===== 1. AUCTION CACHE TESTS =====

/**
 * @brief Test auction cache initialization and cleanup
 */
void dap_auctions_test_cache_init(void);

/**
 * @brief Test auction management in cache
 */
void dap_auctions_test_cache_auction_management(void);

/**
 * @brief Test bid management in cache
 */
void dap_auctions_test_cache_bid_management(void);

/**
 * @brief Test cache statistics and counters
 */
void dap_auctions_test_cache_statistics(void);

// ===== 2. AUCTION STATE TESTS =====

/**
 * @brief Test auction status transitions
 */
void dap_auctions_test_status_transitions(void);

/**
 * @brief Test auction status validation and conversion
 */
void dap_auctions_test_status_validation(void);

// ===== 3. TRANSACTION TESTS =====

/**
 * @brief Test auction event processing
 */
void dap_auctions_test_event_processing(void);

/**
 * @brief Test auction bid transactions
 */
void dap_auctions_test_bid_transactions(void);

/**
 * @brief Test bid withdrawal transactions
 */
void dap_auctions_test_withdraw_transactions(void);

// ===== 4. LEDGER INTEGRATION TESTS =====

/**
 * @brief Test event callback handlers
 */
void dap_auctions_test_event_callbacks(void);

/**
 * @brief Test ledger synchronization
 */
void dap_auctions_test_ledger_sync(void);

/**
 * @brief Test verificator functions
 */
void dap_auctions_test_verificators(void);

// ===== 5. DATA PROCESSING TESTS =====

/**
 * @brief Test event data parsing
 */
void dap_auctions_test_data_parsing(void);

/**
 * @brief Test boundary conditions
 */
void dap_auctions_test_boundary_conditions(void);

// ===== 6. SECURITY AND ERROR TESTS =====

/**
 * @brief Test error handling
 */
void dap_auctions_test_error_handling(void);

/**
 * @brief Test thread safety
 */
void dap_auctions_test_thread_safety(void);

// ===== 7. PERFORMANCE TESTS =====

/**
 * @brief Test scalability and performance
 */
void dap_auctions_test_performance(void);
