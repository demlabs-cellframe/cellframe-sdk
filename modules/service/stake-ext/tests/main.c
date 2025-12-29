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
#include "dap_chain_net_srv_stake_ext_tests.h"

int main(void)
{
    // Early debug output to catch SEGFAULT location
    printf("stake-ext-test: Starting...\n");
    fflush(stdout);
    
    dap_log_level_set(L_DEBUG);
    
    printf("stake-ext-test: Log level set\n");
    fflush(stdout);
    
    dap_log_set_external_output(LOGGER_OUTPUT_STDOUT, NULL);
    
    printf("stake-ext-test: External output set, running tests...\n");
    fflush(stdout);
    
    dap_srv_stake_ext_test_run();
    
    printf("stake-ext-test: Tests completed\n");
    fflush(stdout);
    
    return 0;
}
