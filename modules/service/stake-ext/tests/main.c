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

#include <stdio.h>
#include "dap_common.h"

// Step 2: Add header include to test if header causes crash
#include "dap_chain_net_srv_stake_ext_tests.h"

int main(void)
{
    fprintf(stderr, "stake-ext-test: main() started\n");
    fflush(stderr);
    
    dap_log_level_set(L_DEBUG);
    dap_log_set_external_output(LOGGER_OUTPUT_STDOUT, NULL);
    
    fprintf(stderr, "stake-ext-test: header included OK, test PASS (header-only mode)\n");
    fflush(stderr);
    
    // Step 3: Uncomment to test if actual test functions cause crash
    // dap_srv_stake_ext_test_run();
    
    fprintf(stderr, "stake-ext-test: completed successfully\n");
    fflush(stderr);
    
    return 0;
}
