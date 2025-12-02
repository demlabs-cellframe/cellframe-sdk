/**
 * @file dex_lifecycle_tests.h
 * @brief Order lifecycle tests API
 */

#pragma once

#include "dex_test_scenarios.h"

/**
 * Run single order lifecycle (create → full buy → partial → sub-minfill)
 */
int run_order_lifecycle(
    dex_test_fixture_t *f,
    const test_pair_config_t *pair,
    const order_template_t *tmpl,
    size_t pair_idx,
    size_t tmpl_idx);

/**
 * Run all lifecycle tests for all pairs and templates
 * @return 0 on success, error code on first failure (stops immediately)
 */
int run_lifecycle_tests(dex_test_fixture_t *f);

