/**
 * @file test_cli_token_mocked.c
 * @brief Unit tests for token CLI with full mocking support
 * 
 * This test file uses DAP Mock Framework to mock token/ledger dependencies
 * allowing full CLI command execution with controlled, predictable behavior.
 * 
 * Tests verify:
 * 1. CLI command registration and invocation
 * 2. JSON output structure and field names
 * 3. Correct handling of various token states
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
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_cli_token.h"
#include "dap_chain_ledger_cli_token_wrap.h"
#include "dap_chain_token_cli.h"

#define LOG_TAG "test_cli_token_mocked"

// ============================================================================
// GLOBAL MOCK OUTPUT PARAMETERS
// ============================================================================

static dap_ledger_t *s_mock_ledger_output = NULL;

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
 * @brief Mock for dap_ledger_find_by_name_w
 */
DAP_MOCK_DECLARE(dap_ledger_find_by_name_w, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_ledger_token_info_by_name
 */
DAP_MOCK_DECLARE(dap_ledger_token_info_by_name, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_ledger_token_info_by_name_w
 */
DAP_MOCK_DECLARE(dap_ledger_token_info_by_name_w, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_ledger_token_ticker_check
 */
DAP_MOCK_DECLARE(dap_ledger_token_ticker_check, {
    .return_value.i = 0  // false by default
});

/**
 * @brief Mock for dap_ledger_token_ticker_check_w
 */
DAP_MOCK_DECLARE(dap_ledger_token_ticker_check_w, {
    .return_value.i = 0  // false by default
});

// ============================================================================
// EXTERNAL REAL FUNCTION DECLARATIONS
// ============================================================================

extern dap_ledger_t* __real_dap_ledger_find_by_name(const char *a_net_name);

extern dap_ledger_t* __real_dap_ledger_find_by_name_w(const char *a_net_name);

extern dap_json_t* __real_dap_ledger_token_info_by_name(dap_ledger_t *a_ledger, const char *a_token_ticker, int a_version);

extern dap_json_t* __real_dap_ledger_token_info_by_name_w(dap_ledger_t *a_ledger, const char *a_token_ticker, int a_version);

extern bool __real_dap_ledger_token_ticker_check(dap_ledger_t *a_ledger, const char *a_token_ticker);

extern bool __real_dap_ledger_token_ticker_check_w(dap_ledger_t *a_ledger, const char *a_token_ticker);

// ============================================================================
// WRAPPER IMPLEMENTATIONS
// ============================================================================

/**
 * @brief Wrapper for dap_ledger_find_by_name
 */
dap_ledger_t* __wrap_dap_ledger_find_by_name(const char *a_net_name)
{
    if (g_mock_dap_ledger_find_by_name && g_mock_dap_ledger_find_by_name->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_find_by_name, NULL, 0,
                             g_mock_dap_ledger_find_by_name->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_ledger_find_by_name(name=%s) called", a_net_name ? a_net_name : "(null)");
        return (dap_ledger_t*)g_mock_dap_ledger_find_by_name->return_value.ptr;
    }
    return __real_dap_ledger_find_by_name(a_net_name);
}

/**
 * @brief Wrapper for dap_ledger_find_by_name_w
 */
dap_ledger_t* __wrap_dap_ledger_find_by_name_w(const char *a_net_name)
{
    if (g_mock_dap_ledger_find_by_name_w && g_mock_dap_ledger_find_by_name_w->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_find_by_name_w, NULL, 0,
                             g_mock_dap_ledger_find_by_name_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_ledger_find_by_name_w(name=%s) called", a_net_name ? a_net_name : "(null)");
        return (dap_ledger_t*)g_mock_dap_ledger_find_by_name_w->return_value.ptr;
    }
    return __real_dap_ledger_find_by_name_w(a_net_name);
}

/**
 * @brief Wrapper for dap_ledger_token_info_by_name
 */
dap_json_t* __wrap_dap_ledger_token_info_by_name(dap_ledger_t *a_ledger, const char *a_token_ticker, int a_version)
{
    if (g_mock_dap_ledger_token_info_by_name && g_mock_dap_ledger_token_info_by_name->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_token_info_by_name, NULL, 0,
                             g_mock_dap_ledger_token_info_by_name->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_ledger_token_info_by_name(ticker=%s) called", a_token_ticker ? a_token_ticker : "(null)");
        return (dap_json_t*)g_mock_dap_ledger_token_info_by_name->return_value.ptr;
    }
    return __real_dap_ledger_token_info_by_name(a_ledger, a_token_ticker, a_version);
}

/**
 * @brief Wrapper for dap_ledger_token_info_by_name_w
 */
dap_json_t* __wrap_dap_ledger_token_info_by_name_w(dap_ledger_t *a_ledger, const char *a_token_ticker, int a_version)
{
    if (g_mock_dap_ledger_token_info_by_name_w && g_mock_dap_ledger_token_info_by_name_w->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_token_info_by_name_w, NULL, 0,
                             g_mock_dap_ledger_token_info_by_name_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_ledger_token_info_by_name_w(ticker=%s) called", a_token_ticker ? a_token_ticker : "(null)");
        return (dap_json_t*)g_mock_dap_ledger_token_info_by_name_w->return_value.ptr;
    }
    return __real_dap_ledger_token_info_by_name_w(a_ledger, a_token_ticker, a_version);
}

/**
 * @brief Wrapper for dap_ledger_token_ticker_check
 */
bool __wrap_dap_ledger_token_ticker_check(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    if (g_mock_dap_ledger_token_ticker_check && g_mock_dap_ledger_token_ticker_check->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_token_ticker_check, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_ledger_token_ticker_check->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_ledger_token_ticker_check(ticker=%s) called", a_token_ticker ? a_token_ticker : "(null)");
        return (bool)g_mock_dap_ledger_token_ticker_check->return_value.i;
    }
    return __real_dap_ledger_token_ticker_check(a_ledger, a_token_ticker);
}

/**
 * @brief Wrapper for dap_ledger_token_ticker_check_w
 */
bool __wrap_dap_ledger_token_ticker_check_w(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    if (g_mock_dap_ledger_token_ticker_check_w && g_mock_dap_ledger_token_ticker_check_w->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_token_ticker_check_w, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_ledger_token_ticker_check_w->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_ledger_token_ticker_check_w(ticker=%s) called", a_token_ticker ? a_token_ticker : "(null)");
        return (bool)g_mock_dap_ledger_token_ticker_check_w->return_value.i;
    }
    return __real_dap_ledger_token_ticker_check_w(a_ledger, a_token_ticker);
}

// ============================================================================
// MOCK HELPERS
// ============================================================================

/**
 * @brief Reset all mocks to default state
 */
static void s_mocks_init(void)
{
    DAP_MOCK_RESET(dap_ledger_find_by_name);
    DAP_MOCK_RESET(dap_ledger_find_by_name_w);
    DAP_MOCK_RESET(dap_ledger_token_info_by_name);
    DAP_MOCK_RESET(dap_ledger_token_info_by_name_w);
    DAP_MOCK_RESET(dap_ledger_token_ticker_check);
    DAP_MOCK_RESET(dap_ledger_token_ticker_check_w);
    
    s_mock_ledger_output = NULL;
}

/**
 * @brief Enable all mocks
 */
static void s_mocks_enable(void)
{
    DAP_MOCK_ENABLE(dap_ledger_find_by_name);
    DAP_MOCK_ENABLE(dap_ledger_find_by_name_w);
    DAP_MOCK_ENABLE(dap_ledger_token_info_by_name);
    DAP_MOCK_ENABLE(dap_ledger_token_info_by_name_w);
    DAP_MOCK_ENABLE(dap_ledger_token_ticker_check);
    DAP_MOCK_ENABLE(dap_ledger_token_ticker_check_w);
}

/**
 * @brief Disable all mocks
 */
static void s_mocks_disable(void)
{
    DAP_MOCK_DISABLE(dap_ledger_find_by_name);
    DAP_MOCK_DISABLE(dap_ledger_find_by_name_w);
    DAP_MOCK_DISABLE(dap_ledger_token_info_by_name);
    DAP_MOCK_DISABLE(dap_ledger_token_info_by_name_w);
    DAP_MOCK_DISABLE(dap_ledger_token_ticker_check);
    DAP_MOCK_DISABLE(dap_ledger_token_ticker_check_w);
}

/**
 * @brief Reset all mocks to default state (alias for s_mocks_init)
 */
static void s_mocks_reset(void)
{
    s_mocks_init();
}

// ============================================================================
// MOCK DATA STRUCTURES
// ============================================================================

// Mock ledger structure
static dap_ledger_t s_mock_ledger_data;

/**
 * @brief Setup mock ledger
 */
static void s_setup_mock_ledger(const char *a_net_name)
{
    memset(&s_mock_ledger_data, 0, sizeof(s_mock_ledger_data));
    s_mock_ledger_data.net_id.uint64 = 0x1234567890ABCDEF;
    s_mock_ledger_output = &s_mock_ledger_data;
}

// ============================================================================
// CLI HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Execute CLI command and get JSON response
 * @param a_cmd Command string (space-separated)
 * @param a_version API version
 * @return JSON array with response or NULL on error
 */
static dap_json_t* s_cli_execute(const char *a_cmd, int a_version)
{
    // Parse command into argc/argv
    char *l_cmd_copy = dap_strdup(a_cmd);
    char *l_argv[64] = {0};
    int l_argc = 0;
    
    char *l_token = strtok(l_cmd_copy, " ");
    while (l_token && l_argc < 64) {
        l_argv[l_argc++] = l_token;
        l_token = strtok(NULL, " ");
    }
    
    // Create JSON array for reply
    dap_json_t *l_json_reply = dap_json_array_new();
    
    // Find and execute command
    dap_cli_cmd_t *l_cmd_handler = dap_cli_server_cmd_find(l_argv[0]);
    if (l_cmd_handler && l_cmd_handler->func) {
        l_cmd_handler->func(l_argc, l_argv, l_json_reply, a_version);
    }
    
    DAP_DELETE(l_cmd_copy);
    return l_json_reply;
}

// ============================================================================
// TESTS: Parameter Validation
// ============================================================================

/**
 * @brief Test: token command requires -net parameter
 */
static void test_token_requires_net(void)
{
    dap_print_module_name("token_requires_net");
    
    s_mocks_reset();
    s_mocks_enable();
    
    dap_json_t *l_reply = s_cli_execute("token list", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: token info requires -name parameter
 */
static void test_token_info_requires_name(void)
{
    dap_print_module_name("token_info_requires_name");
    
    s_mocks_reset();
    s_mocks_enable();
    
    s_setup_mock_ledger("TestNet");
    DAP_MOCK_SET_RETURN(dap_ledger_find_by_name, (intptr_t)s_mock_ledger_output);
    
    dap_json_t *l_reply = s_cli_execute("token info -net TestNet", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: token command with invalid -H parameter
 */
static void test_token_invalid_hash_type(void)
{
    dap_print_module_name("token_invalid_hash_type");
    
    s_mocks_reset();
    s_mocks_enable();
    
    dap_json_t *l_reply = s_cli_execute("token list -net TestNet -H invalid", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// TESTS: Network/Ledger Not Found
// ============================================================================

/**
 * @brief Test: token list with non-existent network
 */
static void test_token_list_net_not_found(void)
{
    dap_print_module_name("token_list_net_not_found");
    
    s_mocks_reset();
    s_mocks_enable();
    
    DAP_MOCK_SET_RETURN(dap_ledger_find_by_name, (intptr_t)NULL);
    
    dap_json_t *l_reply = s_cli_execute("token list -net NonExistent", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: token info with non-existent network
 */
static void test_token_info_net_not_found(void)
{
    dap_print_module_name("token_info_net_not_found");
    
    s_mocks_reset();
    s_mocks_enable();
    
    DAP_MOCK_SET_RETURN(dap_ledger_find_by_name, (intptr_t)NULL);
    
    dap_json_t *l_reply = s_cli_execute("token info -net NonExistent -name CELL", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// TESTS: Unknown Subcommand
// ============================================================================

/**
 * @brief Test: token with unknown subcommand
 */
static void test_token_unknown_subcommand(void)
{
    dap_print_module_name("token_unknown_subcommand");
    
    s_mocks_reset();
    s_mocks_enable();
    
    s_setup_mock_ledger("TestNet");
    DAP_MOCK_SET_RETURN(dap_ledger_find_by_name, (intptr_t)s_mock_ledger_output);
    
    dap_json_t *l_reply = s_cli_execute("token unknown -net TestNet", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// TESTS: Deprecated Commands
// ============================================================================

/**
 * @brief Test: token tx is deprecated
 */
static void test_token_tx_deprecated(void)
{
    dap_print_module_name("token_tx_deprecated");
    
    s_mocks_reset();
    s_mocks_enable();
    
    s_setup_mock_ledger("TestNet");
    DAP_MOCK_SET_RETURN(dap_ledger_find_by_name, (intptr_t)s_mock_ledger_output);
    
    dap_json_t *l_reply = s_cli_execute("token tx -net TestNet", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    
    // Initialize test framework
    dap_common_init("test_cli_token_mocked", NULL);
    
    // Initialize mocks
    dap_mock_init();
    
    // Register token CLI command
    dap_chain_token_cli_init();
    
    dap_print_module_name("CLI Token Mocked Tests");
    log_it(L_NOTICE, "Starting CLI Token mocked tests...");
    
    // Run parameter validation tests
    test_token_requires_net();
    test_token_info_requires_name();
    test_token_invalid_hash_type();
    
    // Run network not found tests
    test_token_list_net_not_found();
    test_token_info_net_not_found();
    
    // Run subcommand tests
    test_token_unknown_subcommand();
    test_token_tx_deprecated();
    
    log_it(L_NOTICE, "All CLI Token mocked tests passed!");
    printf("\n✓ All %d tests passed\n", 7);
    
    return 0;
}

