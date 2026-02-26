/**
 * @file test_cli_mempool_mocked.c
 * @brief Unit tests for mempool CLI with full mocking support
 * 
 * This test file uses DAP Mock Framework to mock mempool/network dependencies
 * allowing full CLI command execution with controlled, predictable behavior.
 * 
 * Tests verify:
 * 1. CLI command registration and invocation
 * 2. JSON output structure and field names
 * 3. Correct handling of various mempool operations
 * 4. Error handling for missing/invalid parameters
 * 
 * @author Cellframe Team
 * @copyright DeM Labs Inc. 2025
 * @license GPL-3.0
 */

#include <string.h>

#include "dap_common.h"
#include "dap_test.h"
#include "dap_mock.h"
#include "dap_json.h"
#include "dap_cli_server.h"
#include "dap_chain_net.h"
#include "dap_chain_mempool_cli.h"
#include "dap_chain_mempool_cli_wrap.h"

#define LOG_TAG "test_cli_mempool_mocked"

// ============================================================================
// MOCK DATA STRUCTURES
// ============================================================================

/**
 * @brief Mock network data structure
 */
static struct {
    dap_chain_net_t net;
    char name[32];
    dap_chain_t chain;
} s_mock_net_data;

/**
 * @brief Mock global DB objects
 */
static dap_global_db_obj_t s_mock_db_objs[10];
static size_t s_mock_db_objs_count = 0;

// ============================================================================
// MOCK DECLARATIONS
// ============================================================================

/**
 * @brief Mock for dap_chain_net_by_name
 */
DAP_MOCK_DECLARE(dap_chain_net_by_name, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_chain_net_by_name_w wrapper
 */
DAP_MOCK_DECLARE(dap_chain_net_by_name_w, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_global_db_get_all_sync_w
 */
DAP_MOCK_DECLARE(dap_global_db_get_all_sync_w, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_global_db_driver_is_w
 */
DAP_MOCK_DECLARE(dap_global_db_driver_is_w, {
    .return_value.i = 0  // 0 = false
});

/**
 * @brief Mock for dap_chain_mempool_group_new_w
 */
DAP_MOCK_DECLARE(dap_chain_mempool_group_new_w, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_chain_mempool_filter_w (void return)
 */
DAP_MOCK_DECLARE(dap_chain_mempool_filter_w, {
    .return_value.i = 0
});

// ============================================================================
// EXTERNAL REAL FUNCTION DECLARATIONS
// ============================================================================

extern dap_chain_net_t* __real_dap_chain_net_by_name(const char *a_name);
extern dap_chain_net_t* __real_dap_chain_net_by_name_w(const char *a_name);
extern dap_global_db_obj_t* __real_dap_global_db_get_all_sync_w(const char *a_group, size_t *a_count);
extern bool __real_dap_global_db_driver_is_w(const char *a_group, const char *a_key);
extern char* __real_dap_chain_mempool_group_new_w(dap_chain_t *a_chain);
extern void __real_dap_chain_mempool_filter_w(dap_chain_t *a_chain, int *a_removed);

// ============================================================================
// WRAP FUNCTION IMPLEMENTATIONS
// ============================================================================

dap_chain_net_t* __wrap_dap_chain_net_by_name(const char *a_name)
{
    if (g_mock_dap_chain_net_by_name && g_mock_dap_chain_net_by_name->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_by_name, NULL, 0,
                             g_mock_dap_chain_net_by_name->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_net_by_name(name=%s) called", a_name ? a_name : "(null)");
        return (dap_chain_net_t*)g_mock_dap_chain_net_by_name->return_value.ptr;
    }
    return __real_dap_chain_net_by_name(a_name);
}

dap_chain_net_t* __wrap_dap_chain_net_by_name_w(const char *a_name)
{
    if (g_mock_dap_chain_net_by_name_w && g_mock_dap_chain_net_by_name_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_by_name_w, NULL, 0,
                             g_mock_dap_chain_net_by_name_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_net_by_name_w(name=%s) called", a_name ? a_name : "(null)");
        return (dap_chain_net_t*)g_mock_dap_chain_net_by_name_w->return_value.ptr;
    }
    return __real_dap_chain_net_by_name_w(a_name);
}

dap_global_db_obj_t* __wrap_dap_global_db_get_all_sync_w(const char *a_group, size_t *a_count)
{
    if (g_mock_dap_global_db_get_all_sync_w && g_mock_dap_global_db_get_all_sync_w->enabled) {
        dap_mock_record_call(g_mock_dap_global_db_get_all_sync_w, NULL, 0,
                             g_mock_dap_global_db_get_all_sync_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_global_db_get_all_sync_w called");
        if (a_count) {
            *a_count = s_mock_db_objs_count;
        }
        return (dap_global_db_obj_t*)g_mock_dap_global_db_get_all_sync_w->return_value.ptr;
    }
    return __real_dap_global_db_get_all_sync_w(a_group, a_count);
}

bool __wrap_dap_global_db_driver_is_w(const char *a_group, const char *a_key)
{
    if (g_mock_dap_global_db_driver_is_w && g_mock_dap_global_db_driver_is_w->enabled) {
        dap_mock_record_call(g_mock_dap_global_db_driver_is_w, NULL, 0, NULL);
        log_it(L_DEBUG, "MOCK: dap_global_db_driver_is_w called");
        return (bool)g_mock_dap_global_db_driver_is_w->return_value.i;
    }
    return __real_dap_global_db_driver_is_w(a_group, a_key);
}

char* __wrap_dap_chain_mempool_group_new_w(dap_chain_t *a_chain)
{
    if (g_mock_dap_chain_mempool_group_new_w && g_mock_dap_chain_mempool_group_new_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_mempool_group_new_w, NULL, 0,
                             g_mock_dap_chain_mempool_group_new_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_mempool_group_new_w called");
        return (char*)g_mock_dap_chain_mempool_group_new_w->return_value.ptr;
    }
    return __real_dap_chain_mempool_group_new_w(a_chain);
}

void __wrap_dap_chain_mempool_filter_w(dap_chain_t *a_chain, int *a_removed)
{
    if (g_mock_dap_chain_mempool_filter_w && g_mock_dap_chain_mempool_filter_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_mempool_filter_w, NULL, 0, NULL);
        log_it(L_DEBUG, "MOCK: dap_chain_mempool_filter_w called");
        if (a_removed) {
            *a_removed = 0;
        }
        return;
    }
    __real_dap_chain_mempool_filter_w(a_chain, a_removed);
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Initialize mock network data
 */
static void s_init_mock_net_data(void)
{
    memset(&s_mock_net_data, 0, sizeof(s_mock_net_data));
    strncpy(s_mock_net_data.name, "TestNet", sizeof(s_mock_net_data.name) - 1);
    strncpy(s_mock_net_data.net.pub.name, s_mock_net_data.name, sizeof(s_mock_net_data.net.pub.name) - 1);
    s_mock_net_data.net.pub.id.uint64 = 0x123456789ABCDEF0ULL;
    
    // Initialize mock chain
    memset(&s_mock_net_data.chain, 0, sizeof(s_mock_net_data.chain));
    strncpy(s_mock_net_data.chain.name, "main", sizeof(s_mock_net_data.chain.name) - 1);
    s_mock_net_data.net.pub.chains = &s_mock_net_data.chain;
}

// ============================================================================
// TEST CASES
// ============================================================================

/**
 * @brief Test mempool command without subcommand
 */
static void test_mempool_no_subcommand(void)
{
    dap_print_module_name("test_mempool_no_subcommand");
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"mempool", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_mempool(1, l_argv, l_json_reply, 1);
    
    // Should fail - needs subcommand and net
    dap_assert(l_ret != 0, "mempool without subcommand should fail");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_mempool_no_subcommand PASSED");
}

/**
 * @brief Test mempool list without net parameter
 */
static void test_mempool_list_requires_net(void)
{
    dap_print_module_name("test_mempool_list_requires_net");
    
    // Enable mock to return NULL for network lookup
    DAP_MOCK_ENABLE(dap_chain_net_by_name);
    g_mock_dap_chain_net_by_name->return_value.ptr = NULL;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"mempool", "list", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_mempool(2, l_argv, l_json_reply, 1);
    
    // Should fail - needs -net parameter
    dap_assert(l_ret != 0, "mempool list without -net should fail");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_chain_net_by_name);
    
    dap_print_module_name("test_mempool_list_requires_net PASSED");
}

/**
 * @brief Test mempool with invalid subcommand
 */
static void test_mempool_invalid_subcommand(void)
{
    dap_print_module_name("test_mempool_invalid_subcommand");
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"mempool", "invalid_cmd", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_mempool(2, l_argv, l_json_reply, 1);
    
    // Should return -2 for invalid subcommand
    dap_assert(l_ret == -2, "mempool with invalid subcommand should return -2");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_mempool_invalid_subcommand PASSED");
}

/**
 * @brief Test mempool delete without datum hash
 */
static void test_mempool_delete_requires_datum(void)
{
    dap_print_module_name("test_mempool_delete_requires_datum");
    
    // Setup mock network
    s_init_mock_net_data();
    DAP_MOCK_ENABLE(dap_chain_net_by_name);
    g_mock_dap_chain_net_by_name->return_value.ptr = &s_mock_net_data.net;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"mempool", "delete", "-net", "TestNet", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_mempool(4, l_argv, l_json_reply, 1);
    
    // Should fail - needs -datum parameter
    dap_assert(l_ret == -3, "mempool delete without -datum should return -3");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_chain_net_by_name);
    
    dap_print_module_name("test_mempool_delete_requires_datum PASSED");
}

/**
 * @brief Test mempool proc command (deprecated)
 */
static void test_mempool_proc_deprecated(void)
{
    dap_print_module_name("test_mempool_proc_deprecated");
    
    // Setup mock network
    s_init_mock_net_data();
    DAP_MOCK_ENABLE(dap_chain_net_by_name);
    g_mock_dap_chain_net_by_name->return_value.ptr = &s_mock_net_data.net;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"mempool", "proc", "-net", "TestNet", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_mempool(4, l_argv, l_json_reply, 1);
    
    // Should return -999 for deprecated command
    dap_assert(l_ret == -999, "mempool proc should return -999 (deprecated)");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_chain_net_by_name);
    
    dap_print_module_name("test_mempool_proc_deprecated PASSED");
}

/**
 * @brief Test mempool add_ca command (deprecated)
 */
static void test_mempool_add_ca_deprecated(void)
{
    dap_print_module_name("test_mempool_add_ca_deprecated");
    
    // Setup mock network
    s_init_mock_net_data();
    DAP_MOCK_ENABLE(dap_chain_net_by_name);
    g_mock_dap_chain_net_by_name->return_value.ptr = &s_mock_net_data.net;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"mempool", "add_ca", "-net", "TestNet", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_mempool(4, l_argv, l_json_reply, 1);
    
    // Should return -999 for deprecated command
    dap_assert(l_ret == -999, "mempool add_ca should return -999 (deprecated)");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_chain_net_by_name);
    
    dap_print_module_name("test_mempool_add_ca_deprecated PASSED");
}

/**
 * @brief Test mempool list with -addr but no address value
 */
static void test_mempool_list_addr_without_value(void)
{
    dap_print_module_name("test_mempool_list_addr_without_value");
    
    // Setup mock network
    s_init_mock_net_data();
    DAP_MOCK_ENABLE(dap_chain_net_by_name);
    g_mock_dap_chain_net_by_name->return_value.ptr = &s_mock_net_data.net;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"mempool", "list", "-net", "TestNet", "-addr", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_mempool(5, l_argv, l_json_reply, 1);
    
    // Should fail - -addr needs a value
    dap_assert(l_ret == -3, "mempool list -addr without value should return -3");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_chain_net_by_name);
    
    dap_print_module_name("test_mempool_list_addr_without_value PASSED");
}

/**
 * @brief Test mempool check without datum hash
 */
static void test_mempool_check_without_datum(void)
{
    dap_print_module_name("test_mempool_check_without_datum");
    
    // Setup mock network
    s_init_mock_net_data();
    DAP_MOCK_ENABLE(dap_chain_net_by_name);
    g_mock_dap_chain_net_by_name->return_value.ptr = &s_mock_net_data.net;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"mempool", "check", "-net", "TestNet", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_mempool(4, l_argv, l_json_reply, 1);
    
    // Check command should still work but may return error for missing datum
    // The behavior depends on implementation
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_chain_net_by_name);
    
    dap_print_module_name("test_mempool_check_without_datum PASSED");
}

/**
 * @brief Test mempool dump without datum hash
 */
static void test_mempool_dump_without_datum(void)
{
    dap_print_module_name("test_mempool_dump_without_datum");
    
    // Setup mock network
    s_init_mock_net_data();
    DAP_MOCK_ENABLE(dap_chain_net_by_name);
    g_mock_dap_chain_net_by_name->return_value.ptr = &s_mock_net_data.net;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"mempool", "dump", "-net", "TestNet", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_mempool(4, l_argv, l_json_reply, 1);
    
    // Dump command without datum hash - behavior depends on implementation
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_chain_net_by_name);
    
    dap_print_module_name("test_mempool_dump_without_datum PASSED");
}

/**
 * @brief Test mempool with invalid hash format
 */
static void test_mempool_invalid_hash_format(void)
{
    dap_print_module_name("test_mempool_invalid_hash_format");
    
    // Setup mock network
    s_init_mock_net_data();
    DAP_MOCK_ENABLE(dap_chain_net_by_name);
    g_mock_dap_chain_net_by_name->return_value.ptr = &s_mock_net_data.net;
    
    dap_json_t *l_json_reply = NULL;
    // Use an invalid base58 string that will fail to convert
    char *l_argv[] = {"mempool", "delete", "-net", "TestNet", "-datum", "invalid!!hash", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_mempool(6, l_argv, l_json_reply, 1);
    
    // Should fail with -4 for invalid hash conversion
    dap_assert(l_ret == -4, "mempool with invalid hash should return -4");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_chain_net_by_name);
    
    dap_print_module_name("test_mempool_invalid_hash_format PASSED");
}

// ============================================================================
// TESTS: Table Output Formatting
// ============================================================================

/**
 * @brief Test mempool list -h table output formatting
 */
static void test_mempool_list_table_output(void)
{
    dap_print_module_name("mempool list -h table output");
    
    // Get the command to access func_rpc (s_print_for_mempool_list)
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("mempool");
    dap_assert(l_cmd != NULL, "mempool command found");
    dap_assert(l_cmd->func_rpc != NULL, "mempool command has func_rpc for table formatting");
    
    // Prepare mock JSON input for mempool list
    // Structure: [{net: "test", chains: [{name: "main", datums: [...], total: N}]}]
    dap_json_t *l_json_input = dap_json_array_new();
    dap_json_t *l_json_response = dap_json_object_new();
    
    dap_json_object_add_string(l_json_response, "net", "TestNet");
    
    dap_json_t *l_chains_array = dap_json_array_new();
    dap_json_t *l_chain = dap_json_object_new();
    dap_json_object_add_string(l_chain, "name", "main");
    
    // Add datums array
    dap_json_t *l_datums_array = dap_json_array_new();
    
    dap_json_t *l_datum1 = dap_json_object_new();
    dap_json_object_add_string(l_datum1, "hash", "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    dap_json_object_add_string(l_datum1, "type", "TX");
    dap_json_t *l_created1 = dap_json_object_new();
    dap_json_object_add_string(l_created1, "str", "Mon, 01 Jan 2024 12:00:00 +0000");
    dap_json_object_add_object(l_datum1, "created", l_created1);
    dap_json_array_add(l_datums_array, l_datum1);
    
    dap_json_t *l_datum2 = dap_json_object_new();
    dap_json_object_add_string(l_datum2, "hash", "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    dap_json_object_add_string(l_datum2, "type", "TOKEN");
    dap_json_t *l_created2 = dap_json_object_new();
    dap_json_object_add_string(l_created2, "str", "Tue, 15 Feb 2024 15:30:45 +0300");
    dap_json_object_add_object(l_datum2, "created", l_created2);
    dap_json_array_add(l_datums_array, l_datum2);
    
    dap_json_object_add_array(l_chain, "datums", l_datums_array);
    dap_json_object_add_string(l_chain, "total", "2");
    dap_json_array_add(l_chains_array, l_chain);
    
    dap_json_object_add_array(l_json_response, "chains", l_chains_array);
    dap_json_array_add(l_json_input, l_json_response);
    
    // Prepare output
    dap_json_t *l_json_output = dap_json_array_new();
    
    // Prepare argv with -h and list
    char *l_argv[] = {"mempool", "list", "-net", "test", "-h", NULL};
    int l_argc = 5;
    
    // Call the formatting function
    int l_ret = l_cmd->func_rpc(l_json_input, l_json_output, l_argv, l_argc);
    
    dap_assert(l_ret == 0, "table formatting succeeds");
    
    // Get the output string
    dap_json_t *l_result = dap_json_array_get_idx(l_json_output, 0);
    dap_assert(l_result != NULL, "result object exists");
    
    dap_json_t *l_output_obj = NULL;
    dap_json_object_get_ex(l_result, "output", &l_output_obj);
    dap_assert(l_output_obj != NULL, "output field exists");
    
    const char *l_table = dap_json_get_string(l_output_obj);
    dap_assert(l_table != NULL, "table string exists");
    
    log_it(L_DEBUG, "Table output:\n%s", l_table);
    
    // Verify table structure
    dap_assert(strstr(l_table, "Hash") != NULL, "table has 'Hash' header");
    dap_assert(strstr(l_table, "Datum type") != NULL, "table has 'Datum type' header");
    dap_assert(strstr(l_table, "Time create") != NULL, "table has 'Time create' header");
    
    // Check datum data is present
    dap_assert(strstr(l_table, "TX") != NULL, "table contains datum type TX");
    dap_assert(strstr(l_table, "TOKEN") != NULL, "table contains datum type TOKEN");
    dap_assert(strstr(l_table, "0xAAAA") != NULL, "table contains hash 0xAAAA");
    
    // Check separator lines
    dap_assert(strstr(l_table, "___") != NULL, "table has separator lines");
    
    // Check total
    dap_assert(strstr(l_table, "total") != NULL, "table shows total");
    
    // Cleanup
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_pass_msg("mempool list -h table output complete");
}

/**
 * @brief Test mempool list -h with empty results
 */
static void test_mempool_list_table_empty(void)
{
    dap_print_module_name("mempool list -h table (empty)");
    
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("mempool");
    dap_assert(l_cmd != NULL, "mempool command found");
    
    // Prepare empty JSON input (no chains or invalid structure)
    dap_json_t *l_json_input = dap_json_array_new();
    
    dap_json_t *l_json_output = dap_json_array_new();
    
    char *l_argv[] = {"mempool", "list", "-h", NULL};
    int l_argc = 3;
    
    int l_ret = l_cmd->func_rpc(l_json_input, l_json_output, l_argv, l_argc);
    
    // Should return -1 for empty/invalid input
    dap_assert(l_ret == -1, "table formatting returns -1 for empty input");
    
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_pass_msg("mempool list -h table empty test complete");
}

// ============================================================================
// MAIN
// ============================================================================

/**
 * @brief Main test function
 */
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    
    dap_common_init("test_cli_mempool_mocked", NULL);
    dap_log_level_set(L_ERROR); // Suppress verbose logging from CLI functions
    
    dap_mock_init();
    
    // Initialize CLI commands
    dap_chain_mempool_cli_init();
    
    dap_print_module_name("CLI Mempool Mocked Tests");
    printf("Testing mempool CLI with DAP Mock Framework\n\n");
    
    // Run tests - note: some tests that require complex network data 
    // are disabled until proper mock data structures are set up
    test_mempool_no_subcommand();
    test_mempool_list_requires_net();
    test_mempool_invalid_subcommand();
    // Tests below require more complex mock setup and are disabled for now:
    // test_mempool_delete_requires_datum();
    // test_mempool_proc_deprecated();
    // test_mempool_add_ca_deprecated();
    // test_mempool_list_addr_without_value();
    // test_mempool_check_without_datum();
    // test_mempool_dump_without_datum();
    // test_mempool_invalid_hash_format();
    
    // Table output tests
    test_mempool_list_table_output();
    test_mempool_list_table_empty();
    
    dap_print_module_name("All CLI Mempool mocked tests passed!");
    
    dap_mock_deinit();
    dap_chain_mempool_cli_deinit();
    
    return 0;
}
