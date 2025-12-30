/*
 * Minimal test to isolate ARM 32-bit crash
 */

#include <stdio.h>
#include "dap_common.h"
#include "dap_math_ops.h"

// Test function that uses uint256 operations - suspected cause of crash
static void test_uint256_operation(void)
{
    uint256_t amount = GET_256_FROM_64(1000000);
    (void)amount; // Suppress unused warning
}

void minimal_test_run(void)
{
    fprintf(stderr, "minimal_test: starting\n");
    fflush(stderr);
    
    test_uint256_operation();
    
    fprintf(stderr, "minimal_test: PASS\n");
    fflush(stderr);
}

