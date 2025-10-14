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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_wallet_cache_db_test.h"

static void print_usage(const char *prog_name)
{
    printf("\nUsage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  --help              Show this help message\n");
    printf("  --verbose           Enable verbose output\n");
    printf("\n");
    printf("Description:\n");
    printf("  Run unit tests for wallet cache DB structures and helper functions.\n");
    printf("  Tests include: structures, size calculation, key generation, memory management.\n");
    printf("\n");
    printf("Note:\n");
    printf("  These are simplified unit tests that do not require GlobalDB.\n");
    printf("  Full save/load tests will be run in integration tests.\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    bool verbose = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else {
            fprintf(stderr, "ERROR: Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("       WALLET CACHE DB TEST SUITE - INITIALIZATION           \n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");
    
    // Initialize DAP common subsystem
    printf("Initializing DAP common subsystem...\n");
    dap_common_init("wallet_cache_test", NULL);
    
    // Initialize config with default values
    printf("Initializing configuration...\n");
    dap_config_init(NULL);
    
    // Set log level
    if (verbose) {
        dap_log_level_set(L_DEBUG);
        printf("Log level: DEBUG\n");
    } else {
        dap_log_level_set(L_WARNING); // Suppress INFO logs for cleaner test output
        printf("Log level: WARNING\n");
    }
    
    printf("Initialization complete.\n");
    printf("\n");
    
    // Run tests
    dap_wallet_cache_db_tests_run();
    
    // Cleanup
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("                    CLEANUP                                   \n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");
    
    printf("Cleaning up DAP common...\n");
    dap_common_deinit();
    
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("              TEST SUITE COMPLETED SUCCESSFULLY               \n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");
    
    return 0;
}
