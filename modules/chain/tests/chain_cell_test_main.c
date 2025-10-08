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

#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain_cell.h"
#include "dap_chain_cell_test.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void print_usage(const char *prog_name)
{
    printf("\nUsage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  --help              Show this help message\n");
    printf("  --real-chain PATH   Test with real chain files from PATH\n");
    printf("  --cell-id ID        Cell ID to test (default: 0, hex format)\n");
    printf("  --test-count N      Number of random reads to test (default: 50)\n");
    printf("  --show-samples N    Show N sample transactions in JSON (default: 0)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s\n", prog_name);
    printf("      Run standard unit tests only\n\n");
    printf("  %s --real-chain /opt/cellframe-node/var/lib/network/riemann/main\n", prog_name);
    printf("      Run tests + integration test with real Riemann main chain (cell 0)\n\n");
    printf("  %s --real-chain /path/to/chains --cell-id 1 --test-count 100\n", prog_name);
    printf("      Test cell 1 with 100 random reads\n\n");
    printf("  %s --real-chain /path/to/chains --show-samples 5\n", prog_name);
    printf("      Show 5 sample transactions found both ways (iterator vs offset)\n\n");
}

int main(int argc, char *argv[])
{
    const char *l_real_chain_path = NULL;
    uint64_t l_cell_id = 0;
    int l_test_count = 50;
    int l_show_samples = 0;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--real-chain") == 0) {
            if (i + 1 < argc) {
                l_real_chain_path = argv[++i];
            } else {
                fprintf(stderr, "ERROR: --real-chain requires a path argument\n");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--cell-id") == 0) {
            if (i + 1 < argc) {
                l_cell_id = strtoull(argv[++i], NULL, 16);
            } else {
                fprintf(stderr, "ERROR: --cell-id requires a hex value\n");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--test-count") == 0) {
            if (i + 1 < argc) {
                l_test_count = atoi(argv[++i]);
                if (l_test_count <= 0) {
                    fprintf(stderr, "ERROR: --test-count must be positive\n");
                    return 1;
                }
            } else {
                fprintf(stderr, "ERROR: --test-count requires a number\n");
                print_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--show-samples") == 0) {
            if (i + 1 < argc) {
                l_show_samples = atoi(argv[++i]);
                if (l_show_samples < 0) {
                    fprintf(stderr, "ERROR: --show-samples must be non-negative\n");
                    return 1;
                }
            } else {
                fprintf(stderr, "ERROR: --show-samples requires a number\n");
                print_usage(argv[0]);
                return 1;
            }
        } else {
            fprintf(stderr, "ERROR: Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Initialize DAP common subsystem
    dap_common_init("chain_cell_test", NULL);
    
    // Initialize config with default values
    dap_config_init(NULL);
    
    // Set log level for tests - DEBUG to see error messages
    dap_log_level_set(L_DEBUG);
    
    // Initialize chain cell subsystem
    dap_chain_cell_init();
    
    // Run standard unit tests
    dap_chain_cell_tests_run();
    
    // Run real chain integration test if path provided
    if (l_real_chain_path) {
        printf("\n=== Running Real Chain Integration Test ===\n");
        printf("Chain path: %s\n", l_real_chain_path);
        printf("Cell ID: 0x%lx\n", l_cell_id);
        printf("Test count: %d\n", l_test_count);
        if (l_show_samples > 0) {
            printf("Show samples: %d transactions\n", l_show_samples);
        }
        printf("\n");
        
        dap_chain_cell_real_chain_test(l_real_chain_path, l_cell_id, l_test_count, l_show_samples);
    } else {
        printf("\nTIP: You can test with real chain files using:\n");
        printf("  %s --real-chain /opt/cellframe-node/var/lib/network/riemann/main\n\n", argv[0]);
    }
    
    // Cleanup
    dap_common_deinit();
    
    return 0;
}
