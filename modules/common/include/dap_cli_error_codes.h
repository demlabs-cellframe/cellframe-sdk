/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2026
 * All rights reserved.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Register an error code with a name
 * @param a_code_name String identifier for the error
 * @param a_code_value Numeric error code value
 * @param a_description Human-readable description (optional, can be NULL)
 * @return 0 on success, -1 on error
 */
int dap_cli_error_code_register(const char *a_code_name, int a_code_value, const char *a_description);

/**
 * @brief Get error code by name
 * @param a_code_name String identifier for the error
 * @return Error code value, or -1 if not found
 */
int dap_cli_error_code_get(const char *a_code_name);

/**
 * @brief Initialize CLI error code registry
 */
void dap_cli_error_codes_init(void);

/**
 * @brief Cleanup CLI error code registry
 */
void dap_cli_error_codes_deinit(void);
