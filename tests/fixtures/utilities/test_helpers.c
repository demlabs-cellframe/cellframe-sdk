/*
 * Authors:
 * Dmitry Gerasimov <ceo@cellframe.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe SDK  https://gitlab.demlabs.net/cellframe/cellframe-sdk
 * Copyright  (c) 2025
 * All rights reserved.

 This file is part of Cellframe SDK the open source project

    Cellframe SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cellframe SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "test_helpers.h"
#include "dap_config.h"
#include "dap_common.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_TAG "dap_test_helpers"

// Memory tracking for leak detection
static size_t s_allocated_memory = 0;
static size_t s_allocation_count = 0;

/**
 * @brief Test memory allocation with tracking
 */
void* dap_test_mem_alloc(size_t a_size) {
    void* l_ptr = DAP_NEW_SIZE(uint8_t, a_size);
    if (l_ptr) {
        s_allocated_memory += a_size;
        s_allocation_count++;
        log_it(L_DEBUG, "Test allocated %zu bytes (total: %zu)", a_size, s_allocated_memory);
    }
    return l_ptr;
}

/**
 * @brief Free test memory with tracking
 */
void dap_test_mem_free(void* a_ptr) {
    if (a_ptr) {
        DAP_DELETE(a_ptr);
        s_allocation_count--;
        log_it(L_DEBUG, "Test freed memory (allocations remaining: %zu)", s_allocation_count);
    }
}

/**
 * @brief Generate random bytes for testing
 */
void dap_test_random_bytes(uint8_t* a_buffer, size_t a_size) {
    if (!a_buffer || a_size == 0) {
        return;
    }

    // Initialize random seed if not done
    static bool s_rand_initialized = false;
    if (!s_rand_initialized) {
        srand((unsigned int)time(NULL));
        s_rand_initialized = true;
    }

    for (size_t i = 0; i < a_size; i++) {
        a_buffer[i] = (uint8_t)(rand() % 256);
    }
}

/**
 * @brief Generate random string for testing
 */
char* dap_test_random_string(size_t a_length) {
    if (a_length == 0) {
        return NULL;
    }

    char* l_str = DAP_NEW_SIZE(char, a_length + 1);
    if (!l_str) {
        return NULL;
    }

    // Character set for random strings
    const char* l_charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t l_charset_len = strlen(l_charset);

    for (size_t i = 0; i < a_length; i++) {
        l_str[i] = l_charset[rand() % l_charset_len];
    }
    l_str[a_length] = '\0';

    return l_str;
}

/**
 * @brief Setup minimal Cellframe SDK environment for testing
 */
int dap_test_sdk_init(void) {
    printf("=== PRINTF: Inside dap_test_sdk_init() ===\n");
    fflush(stdout);

    log_it(L_INFO, "Initializing Cellframe SDK test environment");

    // Reset memory tracking
    s_allocated_memory = 0;
    s_allocation_count = 0;

    printf("=== PRINTF: About to call dap_sdk_init() ===\n");
    fflush(stdout);

    // Initialize Cellframe SDK with core modules (needed for complex tests)
    int ret = dap_sdk_init();

    printf("=== PRINTF: dap_sdk_init() returned: %d ===\n", ret);
    fflush(stdout);
    if (ret != 0) {
        log_it(L_ERROR, "Failed to initialize Cellframe SDK: %d", ret);
        return ret;
    }

    printf("=== PRINTF: About to return 0 from dap_test_sdk_init() ===\n");
    fflush(stdout);

    log_it(L_INFO, "Cellframe SDK test environment initialized successfully");

    printf("=== PRINTF: Returning 0 from dap_test_sdk_init() ===\n");
    fflush(stdout);
    return 0;
}

/**
 * @brief Cleanup Cellframe SDK test environment
 */
void dap_test_sdk_cleanup(void) {
    log_it(L_INFO, "Cleaning up Cellframe SDK test environment");

    // Deinitialize Cellframe SDK
    dap_sdk_deinit();

    // Report memory leaks if any
    if (s_allocation_count > 0) {
        log_it(L_WARNING, "Memory leak detected: %zu allocations not freed", s_allocation_count);
    } else {
        log_it(L_INFO, "No memory leaks detected");
    }

    log_it(L_INFO, "Cellframe SDK test environment cleanup completed");
}
