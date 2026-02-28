/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#include "dap_chain_ledger_cli_cmd_registry.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_ht.h"

#define LOG_TAG "ledger_cli_registry"

// Command entry in registry
typedef struct dap_ledger_cli_cmd_entry {
    char *category;                          // e.g., "tx"
    char *command;                           // e.g., "create"
    dap_ledger_cli_cmd_handler_t handler;    // Handler function
    char *description;                       // Short description
    char key[256];                           // Hash key: "category:command"
    dap_ht_handle_t hh;                       // Hash table handle
} dap_ledger_cli_cmd_entry_t;

// Global registry
static dap_ledger_cli_cmd_entry_t *s_cmd_registry = NULL;
static pthread_rwlock_t s_registry_lock = PTHREAD_RWLOCK_INITIALIZER;

/**
 * @brief Create registry key from category and command
 */
static void s_make_key(const char *a_category, const char *a_command, char *a_key_out, size_t a_key_size)
{
    snprintf(a_key_out, a_key_size, "%s:%s", a_category ? a_category : "", a_command ? a_command : "");
}

/**
 * @brief Register CLI command
 */
int dap_ledger_cli_cmd_register(const char *a_category, 
                                 const char *a_command,
                                 dap_ledger_cli_cmd_handler_t a_handler,
                                 const char *a_description)
{
    if (!a_category || !a_command || !a_handler) {
        log_it(L_ERROR, "Invalid parameters for CLI command registration");
        return -1;
    }
    
    dap_ledger_cli_cmd_entry_t *l_entry = DAP_NEW_Z(dap_ledger_cli_cmd_entry_t);
    if (!l_entry) {
        log_it(L_CRITICAL, "Memory allocation failed");
        return -2;
    }
    
    l_entry->category = dap_strdup(a_category);
    l_entry->command = dap_strdup(a_command);
    l_entry->handler = a_handler;
    l_entry->description = a_description ? dap_strdup(a_description) : NULL;
    
    s_make_key(a_category, a_command, l_entry->key, sizeof(l_entry->key));
    
    pthread_rwlock_wrlock(&s_registry_lock);
    
    // Check if already registered
    dap_ledger_cli_cmd_entry_t *l_existing = NULL;
    dap_ht_find_str(s_cmd_registry, l_entry->key, l_existing);
    if (l_existing) {
        pthread_rwlock_unlock(&s_registry_lock);
        log_it(L_WARNING, "CLI command '%s %s' already registered, replacing", a_category, a_command);
        dap_ledger_cli_cmd_unregister(a_category, a_command);
        pthread_rwlock_wrlock(&s_registry_lock);
    }
    
    dap_ht_add_str(s_cmd_registry, key, l_entry);
    pthread_rwlock_unlock(&s_registry_lock);
    
    log_it(L_INFO, "Registered CLI command: %s %s", a_category, a_command);
    return 0;
}

/**
 * @brief Unregister CLI command
 */
void dap_ledger_cli_cmd_unregister(const char *a_category, const char *a_command)
{
    if (!a_category || !a_command) {
        return;
    }
    
    char l_key[256];
    s_make_key(a_category, a_command, l_key, sizeof(l_key));
    
    pthread_rwlock_wrlock(&s_registry_lock);
    
    dap_ledger_cli_cmd_entry_t *l_entry = NULL;
    dap_ht_find_str(s_cmd_registry, l_key, l_entry);
    
    if (l_entry) {
        dap_ht_del(s_cmd_registry, l_entry);
        DAP_DELETE(l_entry->category);
        DAP_DELETE(l_entry->command);
        DAP_DELETE(l_entry->description);
        DAP_DELETE(l_entry);
        log_it(L_INFO, "Unregistered CLI command: %s %s", a_category, a_command);
    }
    
    pthread_rwlock_unlock(&s_registry_lock);
}

/**
 * @brief Find and execute registered command
 */
int dap_ledger_cli_cmd_execute(const char *a_category, 
                                const char *a_command,
                                int a_argc, char **a_argv,
                                dap_json_t *a_json_arr_reply, int a_version)
{
    if (!a_category || !a_command) {
        log_it(L_ERROR, "Invalid parameters for command execution");
        return -1;
    }
    
    char l_key[256];
    s_make_key(a_category, a_command, l_key, sizeof(l_key));
    
    pthread_rwlock_rdlock(&s_registry_lock);
    
    dap_ledger_cli_cmd_entry_t *l_entry = NULL;
    dap_ht_find_str(s_cmd_registry, l_key, l_entry);
    
    if (!l_entry) {
        pthread_rwlock_unlock(&s_registry_lock);
        log_it(L_DEBUG, "CLI command not found: %s %s", a_category, a_command);
        return -2;
    }
    
    dap_ledger_cli_cmd_handler_t l_handler = l_entry->handler;
    pthread_rwlock_unlock(&s_registry_lock);
    
    log_it(L_DEBUG, "Executing CLI command: %s %s", a_category, a_command);
    return l_handler(a_argc, a_argv, a_json_arr_reply, a_version);
}

/**
 * @brief Check if command is registered
 */
bool dap_ledger_cli_cmd_is_registered(const char *a_category, const char *a_command)
{
    if (!a_category) {
        return false;
    }
    
    if (!a_command) {
        // Check if any command in this category exists
        pthread_rwlock_rdlock(&s_registry_lock);
        dap_ledger_cli_cmd_entry_t *l_entry, *l_tmp;
        dap_ht_foreach(s_cmd_registry, l_entry, l_tmp) {
            if (strcmp(l_entry->category, a_category) == 0) {
                pthread_rwlock_unlock(&s_registry_lock);
                return true;
            }
        }
        pthread_rwlock_unlock(&s_registry_lock);
        return false;
    }
    
    char l_key[256];
    s_make_key(a_category, a_command, l_key, sizeof(l_key));
    
    pthread_rwlock_rdlock(&s_registry_lock);
    dap_ledger_cli_cmd_entry_t *l_entry = NULL;
    dap_ht_find_str(s_cmd_registry, l_key, l_entry);
    pthread_rwlock_unlock(&s_registry_lock);
    
    return l_entry != NULL;
}

/**
 * @brief Get list of registered categories
 */
const char** dap_ledger_cli_cmd_get_categories(size_t *a_count)
{
    // TODO: Implement if needed for help/autocomplete
    if (a_count) {
        *a_count = 0;
    }
    return NULL;
}

/**
 * @brief Get list of commands in category
 */
const char** dap_ledger_cli_cmd_get_commands(const char *a_category, size_t *a_count)
{
    // TODO: Implement if needed for help/autocomplete
    if (a_count) {
        *a_count = 0;
    }
    return NULL;
}

/**
 * @brief Initialize CLI command registry
 */
int dap_ledger_cli_cmd_registry_init(void)
{
    log_it(L_INFO, "Initializing CLI command registry");
    s_cmd_registry = NULL;
    pthread_rwlock_init(&s_registry_lock, NULL);
    return 0;
}

/**
 * @brief Deinitialize CLI command registry
 */
void dap_ledger_cli_cmd_registry_deinit(void)
{
    log_it(L_INFO, "Deinitializing CLI command registry");
    
    pthread_rwlock_wrlock(&s_registry_lock);
    
    dap_ledger_cli_cmd_entry_t *l_entry, *l_tmp;
    dap_ht_foreach(s_cmd_registry, l_entry, l_tmp) {
        dap_ht_del(s_cmd_registry, l_entry);
        DAP_DELETE(l_entry->category);
        DAP_DELETE(l_entry->command);
        DAP_DELETE(l_entry->description);
        DAP_DELETE(l_entry);
    }
    
    s_cmd_registry = NULL;
    pthread_rwlock_unlock(&s_registry_lock);
    pthread_rwlock_destroy(&s_registry_lock);
}

