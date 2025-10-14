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

#include "dap_common.h"

// Run all wallet cache DB tests
void dap_wallet_cache_db_tests_run(void);

// Individual test cases
void test_wallet_cache_db_structures(void);
void test_wallet_cache_db_size_calculation(void);
void test_wallet_cache_db_creation(void);
void test_wallet_cache_db_key_generation(void);
void test_wallet_cache_db_memory(void);
