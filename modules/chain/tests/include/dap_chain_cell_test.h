/*
 * Authors:
 * Olzhas Zharasbaev
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
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

/**
 * @brief Run all chain cell read/write tests
 * 
 * Tests cover:
 * - Non-mapped (file-based) read/write operations
 * - Memory-mapped read/write operations
 * - Multiple atoms with varying sizes
 */
void dap_chain_cell_tests_run(void);

/**
 * @brief Run integration test with real chain files
 * 
 * @param a_chains_path Path to directory with real chain files (e.g., /opt/cellframe-node/var/lib/network/riemann/main)
 * @param a_cell_id Cell ID to test (usually 0 for main chain)
 * @param a_test_count Number of random atoms to read and verify (default 50)
 * @param a_show_samples Number of sample transactions to show in JSON format (0 = don't show)
 */
void dap_chain_cell_real_chain_test(const char *a_chains_path, uint64_t a_cell_id, int a_test_count, int a_show_samples);
