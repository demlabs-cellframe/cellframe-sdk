/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2026
 * All rights reserved.
 */

#include <string.h>
#include <stdlib.h>
#include "dap_cli_error_codes.h"
#include "dap_common.h"
#include "dap_strfuncs.h"

#define LOG_TAG "cli_error_codes"

// Error code registry entry
typedef struct dap_cli_error_entry {
    char *name;
    int code;
    char *description;
    struct dap_cli_error_entry *next;
} dap_cli_error_entry_t;

// Global registry
static dap_cli_error_entry_t *s_error_registry = NULL;

/**
 * @brief Initialize CLI error code registry
 */
void dap_cli_error_codes_init(void) {
    // Already initialized
    if (s_error_registry != NULL) {
        return;
    }
    log_it(L_DEBUG, "CLI error code registry initialized");
}

/**
 * @brief Cleanup CLI error code registry
 */
void dap_cli_error_codes_deinit(void) {
    dap_cli_error_entry_t *l_current = s_error_registry;
    while (l_current) {
        dap_cli_error_entry_t *l_next = l_current->next;
        DAP_DELETE(l_current->name);
        DAP_DELETE(l_current->description);
        DAP_DELETE(l_current);
        l_current = l_next;
    }
    s_error_registry = NULL;
}

/**
 * @brief Register an error code with a name
 */
int dap_cli_error_code_register(const char *a_code_name, int a_code_value, const char *a_description) {
    if (!a_code_name) {
        log_it(L_ERROR, "Cannot register error code: NULL name");
        return -1;
    }
    
    // Check if already registered
    dap_cli_error_entry_t *l_current = s_error_registry;
    while (l_current) {
        if (strcmp(l_current->name, a_code_name) == 0) {
            log_it(L_WARNING, "Error code '%s' already registered with value %d, updating to %d",
                   a_code_name, l_current->code, a_code_value);
            l_current->code = a_code_value;
            if (a_description) {
                DAP_DELETE(l_current->description);
                l_current->description = dap_strdup(a_description);
            }
            return 0;
        }
        l_current = l_current->next;
    }
    
    // Create new entry
    dap_cli_error_entry_t *l_entry = DAP_NEW_Z(dap_cli_error_entry_t);
    if (!l_entry) {
        log_it(L_CRITICAL, "Memory allocation failed for error code entry");
        return -1;
    }
    
    l_entry->name = dap_strdup(a_code_name);
    l_entry->code = a_code_value;
    l_entry->description = a_description ? dap_strdup(a_description) : NULL;
    l_entry->next = s_error_registry;
    s_error_registry = l_entry;
    
    log_it(L_DEBUG, "Registered error code: %s = %d%s%s", 
           a_code_name, a_code_value,
           a_description ? " (" : "",
           a_description ? a_description : "");
    return 0;
}

/**
 * @brief Get error code by name
 */
int dap_cli_error_code_get(const char *a_code_name) {
    if (!a_code_name) {
        return -1;
    }
    
    dap_cli_error_entry_t *l_current = s_error_registry;
    while (l_current) {
        if (strcmp(l_current->name, a_code_name) == 0) {
            return l_current->code;
        }
        l_current = l_current->next;
    }
    
    // Not found - return generic error
    log_it(L_WARNING, "Error code '%s' not registered, returning -1", a_code_name);
    return -1;
}
