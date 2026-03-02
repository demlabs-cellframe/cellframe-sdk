/**
 * @file test_cli_global_db_mocked.c
 * @brief Unit tests for global_db CLI command with DAP Mock Framework
 * 
 * Tests the global_db CLI command using mocked dependencies to verify:
 * - Command registration and invocation
 * - Parameter validation
 * - JSON output structure
 * - Table output formatting
 * 
 * @author Cellframe Team
 * @copyright DeM Labs Inc. 2025
 * @license GPL-3.0
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "dap_common.h"
#include "dap_test.h"
#include "dap_mock.h"
#include "dap_json.h"
#include "dap_cli_server.h"
#include "dap_global_db_cli.h"
#include "dap_global_db_cli_wrap.h"

#define LOG_TAG "test_cli_global_db_mocked"

// ============================================================================
// MOCK DECLARATIONS
// ============================================================================

/**
 * @brief Mock for dap_global_db_flush_sync_w
 */
DAP_MOCK_DECLARE(dap_global_db_flush_sync_w, {
    .return_value.i = 0
});

/**
 * @brief Mock for dap_global_db_get_sync_w
 */
DAP_MOCK_DECLARE(dap_global_db_get_sync_w, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_global_db_set_sync_w
 */
DAP_MOCK_DECLARE(dap_global_db_set_sync_w, {
    .return_value.i = 0
});

/**
 * @brief Mock for dap_global_db_del_sync_w
 */
DAP_MOCK_DECLARE(dap_global_db_del_sync_w, {
    .return_value.i = 0
});

/**
 * @brief Mock for dap_global_db_driver_hash_count_w
 */
DAP_MOCK_DECLARE(dap_global_db_driver_hash_count_w, {
    .return_value.i = 0
});

/**
 * @brief Mock for dap_global_db_get_all_sync_w
 */
DAP_MOCK_DECLARE(dap_global_db_get_all_sync_w, {
    .return_value.ptr = NULL
});

// ============================================================================
// EXTERNAL REAL FUNCTION DECLARATIONS
// ============================================================================

extern int __real_dap_global_db_flush_sync_w(void);
extern uint8_t* __real_dap_global_db_get_sync_w(const char *a_group, const char *a_key, 
                                                 size_t *a_value_len, bool *a_is_pinned, dap_nanotime_t *a_ts);
extern int __real_dap_global_db_set_sync_w(const char *a_group, const char *a_key, 
                                            const void *a_value, size_t a_value_len, bool a_pin);
extern int __real_dap_global_db_del_sync_w(const char *a_group, const char *a_key);
extern size_t __real_dap_global_db_driver_hash_count_w(const char *a_group);
extern dap_global_db_obj_t* __real_dap_global_db_get_all_sync_w(const char *a_group, size_t *a_count);

// ============================================================================
// WRAP FUNCTION IMPLEMENTATIONS
// ============================================================================

int __wrap_dap_global_db_flush_sync_w(void)
{
    if (g_mock_dap_global_db_flush_sync_w && g_mock_dap_global_db_flush_sync_w->enabled) {
        g_mock_dap_global_db_flush_sync_w->call_count++;
        log_it(L_DEBUG, "MOCK: dap_global_db_flush_sync_w() called");
        return g_mock_dap_global_db_flush_sync_w->return_value.i;
    }
    return __real_dap_global_db_flush_sync_w();
}

uint8_t* __wrap_dap_global_db_get_sync_w(const char *a_group, const char *a_key, 
                                          size_t *a_value_len, bool *a_is_pinned, dap_nanotime_t *a_ts)
{
    if (g_mock_dap_global_db_get_sync_w && g_mock_dap_global_db_get_sync_w->enabled) {
        g_mock_dap_global_db_get_sync_w->call_count++;
        log_it(L_DEBUG, "MOCK: dap_global_db_get_sync_w(group=%s, key=%s) called", 
               a_group ? a_group : "NULL", a_key ? a_key : "NULL");
        return (uint8_t*)g_mock_dap_global_db_get_sync_w->return_value.ptr;
    }
    return __real_dap_global_db_get_sync_w(a_group, a_key, a_value_len, a_is_pinned, a_ts);
}

int __wrap_dap_global_db_set_sync_w(const char *a_group, const char *a_key, 
                                     const void *a_value, size_t a_value_len, bool a_pin)
{
    if (g_mock_dap_global_db_set_sync_w && g_mock_dap_global_db_set_sync_w->enabled) {
        g_mock_dap_global_db_set_sync_w->call_count++;
        log_it(L_DEBUG, "MOCK: dap_global_db_set_sync_w(group=%s, key=%s) called", 
               a_group ? a_group : "NULL", a_key ? a_key : "NULL");
        return g_mock_dap_global_db_set_sync_w->return_value.i;
    }
    return __real_dap_global_db_set_sync_w(a_group, a_key, a_value, a_value_len, a_pin);
}

int __wrap_dap_global_db_del_sync_w(const char *a_group, const char *a_key)
{
    if (g_mock_dap_global_db_del_sync_w && g_mock_dap_global_db_del_sync_w->enabled) {
        g_mock_dap_global_db_del_sync_w->call_count++;
        log_it(L_DEBUG, "MOCK: dap_global_db_del_sync_w(group=%s, key=%s) called", 
               a_group ? a_group : "NULL", a_key ? a_key : "NULL");
        return g_mock_dap_global_db_del_sync_w->return_value.i;
    }
    return __real_dap_global_db_del_sync_w(a_group, a_key);
}

size_t __wrap_dap_global_db_driver_hash_count_w(const char *a_group)
{
    if (g_mock_dap_global_db_driver_hash_count_w && g_mock_dap_global_db_driver_hash_count_w->enabled) {
        g_mock_dap_global_db_driver_hash_count_w->call_count++;
        log_it(L_DEBUG, "MOCK: dap_global_db_driver_hash_count_w(group=%s) called", 
               a_group ? a_group : "NULL");
        return (size_t)g_mock_dap_global_db_driver_hash_count_w->return_value.i;
    }
    return __real_dap_global_db_driver_hash_count_w(a_group);
}

dap_global_db_obj_t* __wrap_dap_global_db_get_all_sync_w(const char *a_group, size_t *a_count)
{
    if (g_mock_dap_global_db_get_all_sync_w && g_mock_dap_global_db_get_all_sync_w->enabled) {
        g_mock_dap_global_db_get_all_sync_w->call_count++;
        log_it(L_DEBUG, "MOCK: dap_global_db_get_all_sync_w(group=%s) called", 
               a_group ? a_group : "NULL");
        return (dap_global_db_obj_t*)g_mock_dap_global_db_get_all_sync_w->return_value.ptr;
    }
    return __real_dap_global_db_get_all_sync_w(a_group, a_count);
}

// ============================================================================
// MOCK SETUP/TEARDOWN HELPERS
// ============================================================================

/**
 * @brief Initialize all mocks
 */
static void s_mocks_init(void)
{
    DAP_MOCK_ENABLE(dap_global_db_flush_sync_w);
    DAP_MOCK_ENABLE(dap_global_db_get_sync_w);
    DAP_MOCK_ENABLE(dap_global_db_set_sync_w);
    DAP_MOCK_ENABLE(dap_global_db_del_sync_w);
    DAP_MOCK_ENABLE(dap_global_db_driver_hash_count_w);
    DAP_MOCK_ENABLE(dap_global_db_get_all_sync_w);
}

/**
 * @brief Disable all mocks
 */
static void s_mocks_disable(void)
{
    DAP_MOCK_DISABLE(dap_global_db_flush_sync_w);
    DAP_MOCK_DISABLE(dap_global_db_get_sync_w);
    DAP_MOCK_DISABLE(dap_global_db_set_sync_w);
    DAP_MOCK_DISABLE(dap_global_db_del_sync_w);
    DAP_MOCK_DISABLE(dap_global_db_driver_hash_count_w);
    DAP_MOCK_DISABLE(dap_global_db_get_all_sync_w);
}

// ============================================================================
// TESTS: Parameter Validation
// ============================================================================

/**
 * @brief Test global_db with no subcommand
 */
static void test_global_db_no_subcommand(void)
{
    dap_print_module_name("test_global_db_no_subcommand");
    
    // global_db with no subcommand should fail with error
    char *l_argv[] = {"global_db"};
    dap_json_t *l_json_reply = dap_json_array_new();
    
    int l_ret = com_global_db(1, l_argv, l_json_reply, 2);
    
    // Should fail - no valid subcommand
    dap_assert(l_ret != 0 || dap_json_array_length(l_json_reply) == 0, 
               "global_db with no subcommand should fail or return empty");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_global_db_no_subcommand PASSED");
}

/**
 * @brief Test global_db record with no subcommand
 */
static void test_global_db_record_no_subcommand(void)
{
    dap_print_module_name("test_global_db_record_no_subcommand");
    
    // global_db record with no sub-subcommand should fail
    char *l_argv[] = {"global_db", "record"};
    dap_json_t *l_json_reply = dap_json_array_new();
    
    int l_ret = com_global_db(2, l_argv, l_json_reply, 2);
    
    // Should fail - needs get/pin/unpin
    dap_assert(l_ret != 0, "global_db record without subcommand should fail");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_global_db_record_no_subcommand PASSED");
}

/**
 * @brief Test global_db record get with missing params
 */
static void test_global_db_record_get_missing_params(void)
{
    dap_print_module_name("test_global_db_record_get_missing_params");
    
    s_mocks_init();
    
    // Set mock to return NULL (record not found)
    g_mock_dap_global_db_get_sync_w->return_value.ptr = NULL;
    
    // global_db record get without -group and -key
    char *l_argv[] = {"global_db", "record", "get"};
    dap_json_t *l_json_reply = dap_json_array_new();
    
    int l_ret = com_global_db(3, l_argv, l_json_reply, 2);
    
    // Should fail - record not found
    dap_assert(l_ret != 0, "global_db record get without params should fail");
    
    dap_json_object_free(l_json_reply);
    s_mocks_disable();
    dap_print_module_name("test_global_db_record_get_missing_params PASSED");
}

/**
 * @brief Test global_db write with missing params
 */
static void test_global_db_write_missing_params(void)
{
    dap_print_module_name("test_global_db_write_missing_params");
    
    // global_db write without required params
    char *l_argv[] = {"global_db", "write"};
    dap_json_t *l_json_reply = dap_json_array_new();
    
    int l_ret = com_global_db(2, l_argv, l_json_reply, 2);
    
    // Should fail - missing group, key, value
    dap_assert(l_ret != 0, "global_db write without params should fail");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_global_db_write_missing_params PASSED");
}

/**
 * @brief Test global_db read with missing group
 */
static void test_global_db_read_missing_group(void)
{
    dap_print_module_name("test_global_db_read_missing_group");
    
    // global_db read without -group
    char *l_argv[] = {"global_db", "read", "-key", "testkey"};
    dap_json_t *l_json_reply = dap_json_array_new();
    
    int l_ret = com_global_db(4, l_argv, l_json_reply, 2);
    
    // Should fail - missing group
    dap_assert(l_ret != 0, "global_db read without -group should fail");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_global_db_read_missing_group PASSED");
}

/**
 * @brief Test global_db delete with missing params
 */
static void test_global_db_delete_missing_params(void)
{
    dap_print_module_name("test_global_db_delete_missing_params");
    
    // global_db delete without -group
    char *l_argv[] = {"global_db", "delete"};
    dap_json_t *l_json_reply = dap_json_array_new();
    
    int l_ret = com_global_db(2, l_argv, l_json_reply, 2);
    
    // Should fail - missing group
    dap_assert(l_ret != 0, "global_db delete without params should fail");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_global_db_delete_missing_params PASSED");
}

/**
 * @brief Test global_db flush command (success)
 */
static void test_global_db_flush_success(void)
{
    dap_print_module_name("test_global_db_flush_success");
    
    s_mocks_init();
    
    // Set mock to return success
    g_mock_dap_global_db_flush_sync_w->return_value.i = 0;
    
    char *l_argv[] = {"global_db", "flush"};
    dap_json_t *l_json_reply = dap_json_array_new();
    
    int l_ret = com_global_db(2, l_argv, l_json_reply, 2);
    
    // Should succeed
    dap_assert(l_ret == 0, "global_db flush should succeed");
    dap_assert(dap_json_array_length(l_json_reply) > 0, "flush should return response");
    
    dap_json_object_free(l_json_reply);
    s_mocks_disable();
    dap_print_module_name("test_global_db_flush_success PASSED");
}

/**
 * @brief Test global_db get_keys with missing group
 */
static void test_global_db_get_keys_missing_group(void)
{
    dap_print_module_name("test_global_db_get_keys_missing_group");
    
    // global_db get_keys without -group
    char *l_argv[] = {"global_db", "get_keys"};
    dap_json_t *l_json_reply = dap_json_array_new();
    
    int l_ret = com_global_db(2, l_argv, l_json_reply, 2);
    
    // Should fail - missing group
    dap_assert(l_ret != 0, "global_db get_keys without -group should fail");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_global_db_get_keys_missing_group PASSED");
}

// ============================================================================
// TESTS: Table Output Formatting
// ============================================================================

/**
 * @brief Test global_db group_list -h table output
 */
static void test_global_db_group_list_table_output(void)
{
    dap_print_module_name("global_db group_list -h table output");
    
    // Get the command to access func_rpc
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("global_db");
    dap_assert(l_cmd != NULL, "global_db command found");
    dap_assert(l_cmd->func_rpc != NULL, "global_db command has func_rpc for table formatting");
    
    // Prepare mock JSON input for group_list
    // Structure: [{group_list: [{group_name: "...", keys_count: N}, ...], total_count: N}]
    dap_json_t *l_json_input = dap_json_array_new();
    dap_json_t *l_obj = dap_json_object_new();
    dap_json_t *l_group_list = dap_json_array_new();
    
    // Add test groups as objects with group_name key
    dap_json_t *l_group1 = dap_json_object_new();
    dap_json_object_add_string(l_group1, "local.nodes", "10");  // format: group_name: keys_count
    dap_json_array_add(l_group_list, l_group1);
    
    dap_json_t *l_group2 = dap_json_object_new();
    dap_json_object_add_string(l_group2, "global.tokens", "5");
    dap_json_array_add(l_group_list, l_group2);
    
    dap_json_object_add_object(l_obj, "group_list", l_group_list);
    dap_json_object_add_int(l_obj, "total_count", 2);
    dap_json_array_add(l_json_input, l_obj);
    
    // Prepare output
    dap_json_t *l_json_output = dap_json_array_new();
    
    // Call func_rpc with -h flag and group_list subcommand
    char *l_cmd_params[] = {"global_db", "group_list", "-h"};
    int l_ret = l_cmd->func_rpc(l_json_input, l_json_output, l_cmd_params, 3);
    
    dap_assert(l_ret == 0, "table formatting succeeds");
    dap_assert(dap_json_array_length(l_json_output) > 0, "output array has content");
    
    // Get the formatted string - it's in {output: "..."} object
    dap_json_t *l_result_obj = dap_json_array_get_idx(l_json_output, 0);
    dap_assert(l_result_obj != NULL, "result object exists");
    
    dap_json_t *l_output = NULL;
    dap_json_object_get_ex(l_result_obj, "output", &l_output);
    dap_assert(l_output != NULL, "output field exists");
    
    const char *l_str = dap_json_get_string(l_output);
    dap_assert(l_str != NULL, "table string exists");
    
    // Check content
    dap_assert(strstr(l_str, "Groups") != NULL, "table has Groups header");
    dap_assert(strstr(l_str, "total") != NULL, "table shows total");
    dap_assert(strstr(l_str, "local.nodes") != NULL, "table contains local.nodes group");
    dap_assert(strstr(l_str, "global.tokens") != NULL, "table contains global.tokens group");
    
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_print_module_name("global_db group_list -h table output complete");
}

/**
 * @brief Test global_db group_list -h table output (empty)
 */
static void test_global_db_group_list_table_empty(void)
{
    dap_print_module_name("global_db group_list -h table (empty)");
    
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("global_db");
    dap_assert(l_cmd != NULL, "global_db command found");
    
    // Empty array input - should return -1 (fallback to original JSON)
    dap_json_t *l_json_input = dap_json_array_new();
    dap_json_t *l_json_output = dap_json_array_new();
    
    char *l_cmd_params[] = {"global_db", "group_list", "-h"};
    int l_ret = l_cmd->func_rpc(l_json_input, l_json_output, l_cmd_params, 3);
    
    // Empty array returns -1 to use original JSON, or 0 with "Response array is empty"
    dap_assert(l_ret == -1 || l_ret == 0, "table formatting handles empty data gracefully");
    
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_print_module_name("global_db group_list -h table empty test complete");
}

/**
 * @brief Test global_db get_keys -h table output
 */
static void test_global_db_get_keys_table_output(void)
{
    dap_print_module_name("global_db get_keys -h table output");
    
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("global_db");
    dap_assert(l_cmd != NULL, "global_db command found");
    dap_assert(l_cmd->func_rpc != NULL, "global_db command has func_rpc for table formatting");
    
    // Prepare mock JSON input for get_keys
    // Structure: [{group_name: "...", keys_list: [{key: "...", time: "...", type: "..."}, ...]}]
    dap_json_t *l_json_input = dap_json_array_new();
    dap_json_t *l_obj = dap_json_object_new();
    dap_json_t *l_keys_list = dap_json_array_new();
    
    // Add test keys
    dap_json_t *l_key1 = dap_json_object_new();
    dap_json_object_add_string(l_key1, "key", "node1");
    dap_json_object_add_string(l_key1, "time", "2024-01-01 12:00:00");
    dap_json_object_add_string(l_key1, "type", "data");
    dap_json_array_add(l_keys_list, l_key1);
    
    dap_json_t *l_key2 = dap_json_object_new();
    dap_json_object_add_string(l_key2, "key", "node2");
    dap_json_object_add_string(l_key2, "time", "2024-01-02 15:30:00");
    dap_json_object_add_string(l_key2, "type", "data");
    dap_json_array_add(l_keys_list, l_key2);
    
    dap_json_object_add_string(l_obj, "group_name", "local.nodes");
    dap_json_object_add_object(l_obj, "keys_list", l_keys_list);
    dap_json_array_add(l_json_input, l_obj);
    
    // Prepare output
    dap_json_t *l_json_output = dap_json_array_new();
    
    // Call func_rpc with -h flag and get_keys subcommand
    char *l_cmd_params[] = {"global_db", "get_keys", "-group", "local.nodes", "-h"};
    int l_ret = l_cmd->func_rpc(l_json_input, l_json_output, l_cmd_params, 5);
    
    dap_assert(l_ret == 0, "table formatting succeeds");
    dap_assert(dap_json_array_length(l_json_output) > 0, "output array has content");
    
    // Get the formatted string - it's in {output: "..."} object
    dap_json_t *l_result_obj = dap_json_array_get_idx(l_json_output, 0);
    dap_assert(l_result_obj != NULL, "result object exists");
    
    dap_json_t *l_output = NULL;
    dap_json_object_get_ex(l_result_obj, "output", &l_output);
    dap_assert(l_output != NULL, "output field exists");
    
    const char *l_str = dap_json_get_string(l_output);
    dap_assert(l_str != NULL, "table string exists");
    
    // Check content
    dap_assert(strstr(l_str, "Keys") != NULL, "table has Keys header");
    dap_assert(strstr(l_str, "local.nodes") != NULL, "table shows group name");
    dap_assert(strstr(l_str, "node1") != NULL, "table contains key1");
    dap_assert(strstr(l_str, "node2") != NULL, "table contains key2");
    
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_print_module_name("global_db get_keys -h table output complete");
}

// ============================================================================
// Main
// ============================================================================

/**
 * @brief Main test function
 */
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    
    dap_common_init("test_cli_global_db_mocked", NULL);
    dap_log_level_set(L_ERROR);
    
    dap_mock_init();
    
    // Initialize CLI commands
    dap_global_db_cli_init();
    
    dap_print_module_name("CLI Global DB Mocked Tests");
    printf("Testing global_db CLI with DAP Mock Framework\n\n");
    
    // Run parameter validation tests
    test_global_db_no_subcommand();
    test_global_db_record_no_subcommand();
    test_global_db_record_get_missing_params();
    test_global_db_write_missing_params();
    test_global_db_read_missing_group();
    test_global_db_delete_missing_params();
    test_global_db_flush_success();
    test_global_db_get_keys_missing_group();
    
    // Run table output tests
    test_global_db_group_list_table_output();
    test_global_db_group_list_table_empty();
    test_global_db_get_keys_table_output();
    
    dap_mock_deinit();
    
    dap_print_module_name("All CLI Global DB mocked tests passed!");
    printf("\n✓ All %d tests passed\n", 11);
    
    return 0;
}
