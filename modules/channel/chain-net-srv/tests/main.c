/**
 * @file main.c
 * @brief Main entry point for Billing Module Tests
 * @details Entry point for running all billing module test categories
 * @authors Dmitriy Gerasimov
 * @date 2025
 * @copyright (c) 2017-2025 Demlabs Ltd
 */

#include "dap_billing_tests.h"

int main(void) {
    // Run all billing module tests
    dap_billing_tests_run();
    return 0;
}