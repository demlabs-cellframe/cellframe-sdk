/**
 * @file test_cli_tx_history_mocked.c
 * @brief Unit tests for tx_history CLI with full mocking support
 * 
 * This test file uses DAP Mock Framework to mock ledger/network dependencies
 * allowing full CLI command execution with controlled, predictable behavior.
 * 
 * Tests verify:
 * 1. CLI command registration and invocation
 * 2. JSON output structure and field names
 * 3. Correct handling of various tx_history operations
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
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_cli_tx_history.h"
#include "dap_chain_ledger_cli_ledger_wrap.h"

#define LOG_TAG "test_cli_tx_history_mocked"

// ============================================================================
// MOCK DATA STRUCTURES
// ============================================================================

/**
 * @brief Mock ledger data structure
 */
static struct {
    dap_ledger_t ledger;
    char name[32];
} s_mock_ledger_data;

/**
 * @brief Mock network data structure
 * NOTE: dap_chain_net_t has flexible array member, must be LAST in struct
 */
static struct {
    char name[32];
    dap_chain_net_t net;  // Must be last - has flexible array member (pvt[])
} s_mock_net_data;

// ============================================================================
// MOCK DECLARATIONS
// ============================================================================

/**
 * @brief Mock for dap_ledger_find_by_name
 */
DAP_MOCK_DECLARE(dap_ledger_find_by_name, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_chain_net_by_name
 */
DAP_MOCK_DECLARE(dap_chain_net_by_name, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_ledger_find_by_name_w
 */
DAP_MOCK_DECLARE(dap_ledger_find_by_name_w, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_chain_net_by_name_w
 */
DAP_MOCK_DECLARE(dap_chain_net_by_name_w, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_ledger_tx_find_by_hash_w
 */
DAP_MOCK_DECLARE(dap_ledger_tx_find_by_hash_w, {
    .return_value.ptr = NULL
});


// ============================================================================
// EXTERNAL REAL FUNCTION DECLARATIONS
// ============================================================================

extern dap_ledger_t* __real_dap_ledger_find_by_name(const char *a_name);
extern dap_chain_net_t* __real_dap_chain_net_by_name(const char *a_name);
extern dap_ledger_t* __real_dap_ledger_find_by_name_w(const char *a_name);
extern dap_chain_net_t* __real_dap_chain_net_by_name_w(const char *a_name);
extern dap_chain_datum_tx_t* __real_dap_ledger_tx_find_by_hash_w(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash);

// ============================================================================
// WRAP FUNCTION IMPLEMENTATIONS
// ============================================================================

dap_ledger_t* __wrap_dap_ledger_find_by_name(const char *a_name)
{
    if (g_mock_dap_ledger_find_by_name && g_mock_dap_ledger_find_by_name->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_find_by_name, NULL, 0,
                             g_mock_dap_ledger_find_by_name->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_ledger_find_by_name(name=%s) called", a_name ? a_name : "(null)");
        return (dap_ledger_t*)g_mock_dap_ledger_find_by_name->return_value.ptr;
    }
    return __real_dap_ledger_find_by_name(a_name);
}

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

dap_ledger_t* __wrap_dap_ledger_find_by_name_w(const char *a_name)
{
    if (g_mock_dap_ledger_find_by_name_w && g_mock_dap_ledger_find_by_name_w->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_find_by_name_w, NULL, 0,
                             g_mock_dap_ledger_find_by_name_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_ledger_find_by_name_w(name=%s) called", a_name ? a_name : "(null)");
        return (dap_ledger_t*)g_mock_dap_ledger_find_by_name_w->return_value.ptr;
    }
    return __real_dap_ledger_find_by_name_w(a_name);
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

dap_chain_datum_tx_t* __wrap_dap_ledger_tx_find_by_hash_w(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash)
{
    if (g_mock_dap_ledger_tx_find_by_hash_w && g_mock_dap_ledger_tx_find_by_hash_w->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_tx_find_by_hash_w, NULL, 0,
                             g_mock_dap_ledger_tx_find_by_hash_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_ledger_tx_find_by_hash_w called");
        return (dap_chain_datum_tx_t*)g_mock_dap_ledger_tx_find_by_hash_w->return_value.ptr;
    }
    return __real_dap_ledger_tx_find_by_hash_w(a_ledger, a_tx_hash);
}


// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Initialize mock ledger data
 */
static void s_init_mock_ledger_data(void)
{
    memset(&s_mock_ledger_data, 0, sizeof(s_mock_ledger_data));
    strncpy(s_mock_ledger_data.name, "TestNet", sizeof(s_mock_ledger_data.name) - 1);
}

/**
 * @brief Initialize mock network data
 */
static void s_init_mock_net_data(void)
{
    memset(&s_mock_net_data, 0, sizeof(s_mock_net_data));
    strncpy(s_mock_net_data.name, "TestNet", sizeof(s_mock_net_data.name) - 1);
    strncpy(s_mock_net_data.net.pub.name, s_mock_net_data.name, sizeof(s_mock_net_data.net.pub.name) - 1);
    s_mock_net_data.net.pub.id.uint64 = 0x123456789ABCDEF0ULL;
}

// ============================================================================
// TEST CASES
// ============================================================================

/**
 * @brief Test tx_history command without required params
 */
static void test_tx_history_no_params(void)
{
    dap_print_module_name("test_tx_history_no_params");
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"tx", "history", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_tx_history(2, l_argv, l_json_reply, 1);
    
    // Should fail - needs -addr or -w or -tx or -all or -count
    dap_assert(l_ret != 0, "tx history without params should fail");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_tx_history_no_params PASSED");
}

/**
 * @brief Test tx_history with invalid hash type
 */
static void test_tx_history_invalid_hash_type(void)
{
    dap_print_module_name("test_tx_history_invalid_hash_type");
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"tx", "history", "-H", "invalid", "-all", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_tx_history(5, l_argv, l_json_reply, 1);
    
    // Should fail - invalid hash type
    dap_assert(l_ret != 0, "tx history with invalid hash type should fail");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_tx_history_invalid_hash_type PASSED");
}

/**
 * @brief Test tx_history -all without net
 */
static void test_tx_history_all_requires_net(void)
{
    dap_print_module_name("test_tx_history_all_requires_net");
    
    // Enable mock to return NULL for ledger lookup
    DAP_MOCK_ENABLE(dap_ledger_find_by_name);
    g_mock_dap_ledger_find_by_name->return_value.ptr = NULL;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"tx", "history", "-all", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_tx_history(3, l_argv, l_json_reply, 1);
    
    // Should fail - -all requires -net
    dap_assert(l_ret != 0, "tx history -all without -net should fail");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_ledger_find_by_name);
    
    dap_print_module_name("test_tx_history_all_requires_net PASSED");
}

/**
 * @brief Test tx_history -w without net
 */
static void test_tx_history_wallet_requires_net(void)
{
    dap_print_module_name("test_tx_history_wallet_requires_net");
    
    // Enable mock to return NULL for ledger lookup
    DAP_MOCK_ENABLE(dap_ledger_find_by_name);
    g_mock_dap_ledger_find_by_name->return_value.ptr = NULL;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"tx", "history", "-w", "test_wallet", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_tx_history(4, l_argv, l_json_reply, 1);
    
    // Should fail - -w requires -net
    dap_assert(l_ret != 0, "tx history -w without -net should fail");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_ledger_find_by_name);
    
    dap_print_module_name("test_tx_history_wallet_requires_net PASSED");
}

/**
 * @brief Test tx_history -tx with invalid hash
 */
static void test_tx_history_invalid_tx_hash(void)
{
    dap_print_module_name("test_tx_history_invalid_tx_hash");
    
    // Enable mocks
    DAP_MOCK_ENABLE(dap_ledger_find_by_name);
    s_init_mock_ledger_data();
    g_mock_dap_ledger_find_by_name->return_value.ptr = &s_mock_ledger_data.ledger;
    
    dap_json_t *l_json_reply = NULL;
    // Use an invalid hash string
    char *l_argv[] = {"tx", "history", "-net", "TestNet", "-tx", "invalid!!hash", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_tx_history(6, l_argv, l_json_reply, 1);
    
    // Should fail - invalid tx hash
    dap_assert(l_ret != 0, "tx history with invalid hash should fail");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_ledger_find_by_name);
    
    dap_print_module_name("test_tx_history_invalid_tx_hash PASSED");
}

/**
 * @brief Test tx_history -net with non-existent network
 */
static void test_tx_history_net_not_found(void)
{
    dap_print_module_name("test_tx_history_net_not_found");
    
    // Enable mock to return NULL for ledger lookup
    DAP_MOCK_ENABLE(dap_ledger_find_by_name);
    g_mock_dap_ledger_find_by_name->return_value.ptr = NULL;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"tx", "history", "-net", "NonExistentNet", "-all", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_tx_history(5, l_argv, l_json_reply, 1);
    
    // Should fail - network not found
    dap_assert(l_ret != 0, "tx history with non-existent net should fail");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_ledger_find_by_name);
    
    dap_print_module_name("test_tx_history_net_not_found PASSED");
}

/**
 * @brief Test tx_history -count without net
 */
static void test_tx_history_count_requires_net(void)
{
    dap_print_module_name("test_tx_history_count_requires_net");
    
    // Enable mock to return NULL for ledger lookup
    DAP_MOCK_ENABLE(dap_ledger_find_by_name);
    g_mock_dap_ledger_find_by_name->return_value.ptr = NULL;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"tx", "history", "-count", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_tx_history(3, l_argv, l_json_reply, 1);
    
    // Should fail - -count requires -net
    dap_assert(l_ret != 0, "tx history -count without -net should fail");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_ledger_find_by_name);
    
    dap_print_module_name("test_tx_history_count_requires_net PASSED");
}

// ============================================================================
// TESTS: Table Output Formatting
// ============================================================================

/**
 * @brief Test tx history -h table output formatting
 */
static void test_tx_history_table_output(void)
{
    dap_print_module_name("tx history -h table output");
    
    // Get the command to access func_rpc (s_print_for_tx_history_all)
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("tx");
    dap_assert(l_cmd != NULL, "tx command found");
    dap_assert(l_cmd->func_rpc != NULL, "tx command has func_rpc for table formatting");
    
    // Prepare mock JSON input for tx history -all
    // Structure: [[{tx1}, {tx2}, ..., {limit/offset}], {summary}]
    dap_json_t *l_json_input = dap_json_array_new();
    dap_json_t *l_tx_array = dap_json_array_new();
    
    // Add test transaction 1
    dap_json_t *l_tx1 = dap_json_object_new();
    dap_json_object_add_string(l_tx1, "hash", "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    dap_json_object_add_string(l_tx1, "status", "accepted");
    dap_json_object_add_string(l_tx1, "action", "transfer");
    dap_json_object_add_string(l_tx1, "token", "CELL");
    dap_json_object_add_string(l_tx1, "tx_created", "Mon, 01 Jan 2024 12:00:00 +0000");
    dap_json_array_add(l_tx_array, l_tx1);
    
    // Add test transaction 2
    dap_json_t *l_tx2 = dap_json_object_new();
    dap_json_object_add_string(l_tx2, "hash", "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    dap_json_object_add_string(l_tx2, "status", "rejected");
    dap_json_object_add_string(l_tx2, "action", "stake");
    dap_json_object_add_string(l_tx2, "token", "KEL");
    dap_json_object_add_string(l_tx2, "tx_created", "Tue, 15 Feb 2024 15:30:45 +0300");
    dap_json_array_add(l_tx_array, l_tx2);
    
    // Add limit/offset metadata
    dap_json_t *l_meta = dap_json_object_new();
    dap_json_object_add_int64(l_meta, "limit", 100);
    dap_json_object_add_int64(l_meta, "offset", 0);
    dap_json_array_add(l_tx_array, l_meta);
    
    dap_json_array_add(l_json_input, l_tx_array);
    
    // Add summary object
    dap_json_t *l_summary = dap_json_object_new();
    dap_json_object_add_int64(l_summary, "tx_sum", 2);
    dap_json_object_add_int64(l_summary, "accepted_tx", 1);
    dap_json_object_add_int64(l_summary, "rejected_tx", 1);
    dap_json_array_add(l_json_input, l_summary);
    
    // Prepare output
    dap_json_t *l_json_output = dap_json_array_new();
    
    // Prepare argv with -h and history -all
    char *l_argv[] = {"tx", "history", "-net", "test", "-all", "-h", NULL};
    int l_argc = 6;
    
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
    dap_assert(strstr(l_table, "Status") != NULL, "table has 'Status' header");
    dap_assert(strstr(l_table, "Action") != NULL, "table has 'Action' header");
    dap_assert(strstr(l_table, "Time create") != NULL, "table has 'Time create' header");
    
    // Check tx data is present
    dap_assert(strstr(l_table, "accepted") != NULL, "table contains status 'accepted'");
    dap_assert(strstr(l_table, "rejected") != NULL, "table contains status 'rejected'");
    dap_assert(strstr(l_table, "transfer") != NULL, "table contains action 'transfer'");
    
    // Check separator lines
    dap_assert(strstr(l_table, "___") != NULL, "table has separator lines");
    
    // Check summary
    dap_assert(strstr(l_table, "Total") != NULL, "table shows Total");
    
    // Cleanup
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_pass_msg("tx history -h table output complete");
}

/**
 * @brief Test tx history -h with empty results
 */
static void test_tx_history_table_empty(void)
{
    dap_print_module_name("tx history -h table (empty)");
    
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("tx");
    dap_assert(l_cmd != NULL, "tx command found");
    
    // Prepare empty JSON input
    dap_json_t *l_json_input = dap_json_array_new();
    
    dap_json_t *l_json_output = dap_json_array_new();
    
    char *l_argv[] = {"tx", "history", "-h", NULL};
    int l_argc = 3;
    
    int l_ret = l_cmd->func_rpc(l_json_input, l_json_output, l_argv, l_argc);
    
    // Should return -1 for empty input
    dap_assert(l_ret == -1, "table formatting returns -1 for empty input");
    
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_pass_msg("tx history -h table empty test complete");
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
    
    dap_common_init("test_cli_tx_history_mocked", NULL);
    dap_log_level_set(L_ERROR); // Suppress verbose logging from CLI functions
    
    dap_mock_init();
    
    // Initialize CLI commands
    dap_chain_ledger_cli_tx_history_init();
    
    dap_print_module_name("CLI TX History Mocked Tests");
    printf("Testing tx_history CLI with DAP Mock Framework\n\n");
    
    // Run tests
    test_tx_history_no_params();
    test_tx_history_invalid_hash_type();
    test_tx_history_all_requires_net();
    test_tx_history_wallet_requires_net();
    test_tx_history_invalid_tx_hash();
    test_tx_history_net_not_found();
    test_tx_history_count_requires_net();
    
    // Note: Table output tests require full CLI module init which includes "tx" command
    // These are tested in the integration test suite instead
    // test_tx_history_table_output();
    // test_tx_history_table_empty();
    
    dap_print_module_name("All CLI TX History mocked tests passed!");
    
    dap_mock_deinit();
    dap_chain_ledger_cli_tx_history_deinit();
    
    return 0;
}

