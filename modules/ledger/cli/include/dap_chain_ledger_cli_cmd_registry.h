/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#pragma once

#include "dap_json.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief CLI Command Registry System
 * 
 * ARCHITECTURE: Dependency Inversion для CLI команд
 * 
 * ПРИНЦИПЫ:
 * - Модули регистрируют свои CLI команды, а не вызываются напрямую
 * - Dispatcher не знает о конкретных модулях (Zero Coupling)
 * - Plugin система для расширения CLI без изменения dispatcher
 * 
 * ИСПОЛЬЗОВАНИЕ:
 * 
 * 1. Модуль регистрирует команду:
 *    ```c
 *    // В tx_module_init():
 *    dap_ledger_cli_cmd_register("tx", "create", ledger_cli_tx_create, 
 *                                 "Create transaction");
 *    ```
 * 
 * 2. Dispatcher автоматически находит и вызывает:
 *    ```c
 *    // User: ledger tx create -net ...
 *    // Dispatcher -> finds "tx" category -> finds "create" -> calls handler
 *    ```
 * 
 * 3. Модуль может зарегистрировать несколько команд:
 *    ```c
 *    dap_ledger_cli_cmd_register("tx", "create", ...);
 *    dap_ledger_cli_cmd_register("tx", "verify", ...);
 *    dap_ledger_cli_cmd_register("tx", "history", ...);
 *    dap_ledger_cli_cmd_register("token", "list", ...);
 *    ```
 */

/**
 * @brief CLI command handler function type
 * 
 * @param a_argc Argument count (starting from command, not category)
 * @param a_argv Argument vector (starting from command, not category)
 * @param a_json_arr_reply JSON array for reply
 * @param a_version API version
 * @return 0 on success, error code on failure
 */
typedef int (*dap_ledger_cli_cmd_handler_t)(int a_argc, char **a_argv, 
                                             dap_json_t *a_json_arr_reply, int a_version);

/**
 * @brief Register CLI command
 * 
 * @param a_category Command category (e.g., "tx", "token", "event")
 * @param a_command Command name (e.g., "create", "list", "verify")
 * @param a_handler Handler function
 * @param a_description Short description for help
 * @return 0 on success, negative on error
 */
int dap_ledger_cli_cmd_register(const char *a_category, 
                                 const char *a_command,
                                 dap_ledger_cli_cmd_handler_t a_handler,
                                 const char *a_description);

/**
 * @brief Unregister CLI command
 * 
 * @param a_category Command category
 * @param a_command Command name
 */
void dap_ledger_cli_cmd_unregister(const char *a_category, const char *a_command);

/**
 * @brief Find and execute registered command
 * 
 * Used by dispatcher to route commands to registered handlers
 * 
 * @param a_category Command category
 * @param a_command Command name
 * @param a_argc Argument count
 * @param a_argv Argument vector
 * @param a_json_arr_reply JSON reply array
 * @param a_version API version
 * @return 0 on success, error code on failure
 */
int dap_ledger_cli_cmd_execute(const char *a_category, 
                                const char *a_command,
                                int a_argc, char **a_argv,
                                dap_json_t *a_json_arr_reply, int a_version);

/**
 * @brief Check if command is registered
 * 
 * @param a_category Command category
 * @param a_command Command name (NULL to check if category exists)
 * @return true if registered, false otherwise
 */
bool dap_ledger_cli_cmd_is_registered(const char *a_category, const char *a_command);

/**
 * @brief Get list of registered categories
 * 
 * @param a_count OUT: Number of categories
 * @return Array of category names (caller must NOT free)
 */
const char** dap_ledger_cli_cmd_get_categories(size_t *a_count);

/**
 * @brief Get list of commands in category
 * 
 * @param a_category Category name
 * @param a_count OUT: Number of commands
 * @return Array of command names (caller must NOT free)
 */
const char** dap_ledger_cli_cmd_get_commands(const char *a_category, size_t *a_count);

/**
 * @brief Initialize CLI command registry
 * 
 * @return 0 on success, negative on error
 */
int dap_ledger_cli_cmd_registry_init(void);

/**
 * @brief Deinitialize CLI command registry
 */
void dap_ledger_cli_cmd_registry_deinit(void);

#ifdef __cplusplus
}
#endif

