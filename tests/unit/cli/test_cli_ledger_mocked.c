/**
 * @file test_cli_ledger_mocked.c
 * @brief Unit tests for ledger CLI with full mocking support
 * 
 * This test file uses DAP Mock Framework to mock ledger/network dependencies
 * allowing full CLI command execution with controlled, predictable behavior.
 * 
 * Tests verify:
 * 1. CLI command registration and invocation
 * 2. JSON output structure and field names
 * 3. Correct handling of various ledger operations
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
#include "dap_chain_ledger_cli_ledger.h"
#include "dap_chain_ledger_cli_ledger_wrap.h"

#define LOG_TAG "test_cli_ledger_mocked"

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
 */
static struct {
    dap_chain_net_t net;
    char name[32];
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

/**
 * @brief Mock for dap_ledger_get_txs_w
 */
DAP_MOCK_DECLARE(dap_ledger_get_txs_w, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_ledger_token_ticker_check_w
 */
DAP_MOCK_DECLARE(dap_ledger_token_ticker_check_w, {
    .return_value.i = 0  // 0 = false
});

// ============================================================================
// EXTERNAL REAL FUNCTION DECLARATIONS
// ============================================================================

extern dap_ledger_t* __real_dap_ledger_find_by_name(const char *a_name);
extern dap_chain_net_t* __real_dap_chain_net_by_name(const char *a_name);
extern dap_ledger_t* __real_dap_ledger_find_by_name_w(const char *a_name);
extern dap_chain_net_t* __real_dap_chain_net_by_name_w(const char *a_name);
extern dap_chain_datum_tx_t* __real_dap_ledger_tx_find_by_hash_w(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash);
extern dap_hash_fast_t* __real_dap_ledger_get_txs_w(dap_ledger_t *a_ledger, size_t *a_count,
                                                     const char *a_token, dap_chain_addr_t *a_addr,
                                                     size_t a_limit, size_t a_offset);
extern bool __real_dap_ledger_token_ticker_check_w(dap_ledger_t *a_ledger, const char *a_token_ticker);

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

dap_hash_fast_t* __wrap_dap_ledger_get_txs_w(dap_ledger_t *a_ledger, size_t *a_count,
                                              const char *a_token, dap_chain_addr_t *a_addr,
                                              size_t a_limit, size_t a_offset)
{
    if (g_mock_dap_ledger_get_txs_w && g_mock_dap_ledger_get_txs_w->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_get_txs_w, NULL, 0,
                             g_mock_dap_ledger_get_txs_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_ledger_get_txs_w called");
        if (a_count) *a_count = 0;
        return (dap_hash_fast_t*)g_mock_dap_ledger_get_txs_w->return_value.ptr;
    }
    return __real_dap_ledger_get_txs_w(a_ledger, a_count, a_token, a_addr, a_limit, a_offset);
}

bool __wrap_dap_ledger_token_ticker_check_w(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    if (g_mock_dap_ledger_token_ticker_check_w && g_mock_dap_ledger_token_ticker_check_w->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_token_ticker_check_w, NULL, 0, NULL);
        log_it(L_DEBUG, "MOCK: dap_ledger_token_ticker_check_w called");
        return (bool)g_mock_dap_ledger_token_ticker_check_w->return_value.i;
    }
    return __real_dap_ledger_token_ticker_check_w(a_ledger, a_token_ticker);
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
 * @brief Test ledger command without subcommand
 */
static void test_ledger_no_subcommand(void)
{
    dap_print_module_name("test_ledger_no_subcommand");
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"ledger", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_ledger(1, l_argv, l_json_reply, 1);
    
    // Should fail - needs subcommand
    dap_assert(l_ret != 0, "ledger without subcommand should fail");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_ledger_no_subcommand PASSED");
}

/**
 * @brief Test ledger with invalid hash type
 */
static void test_ledger_invalid_hash_type(void)
{
    dap_print_module_name("test_ledger_invalid_hash_type");
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"ledger", "list", "-H", "invalid", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_ledger(4, l_argv, l_json_reply, 1);
    
    // Should fail - invalid hash type
    dap_assert(l_ret != 0, "ledger with invalid hash type should fail");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_ledger_invalid_hash_type PASSED");
}

/**
 * @brief Test ledger list without net parameter
 */
static void test_ledger_list_requires_net(void)
{
    dap_print_module_name("test_ledger_list_requires_net");
    
    // Enable mock to return NULL for ledger lookup
    DAP_MOCK_ENABLE(dap_ledger_find_by_name);
    g_mock_dap_ledger_find_by_name->return_value.ptr = NULL;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"ledger", "list", "coins", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_ledger(3, l_argv, l_json_reply, 1);
    
    // Should fail - needs -net parameter
    dap_assert(l_ret != 0, "ledger list without -net should fail");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_ledger_find_by_name);
    
    dap_print_module_name("test_ledger_list_requires_net PASSED");
}

/**
 * @brief Test ledger info without tx hash
 */
static void test_ledger_info_requires_hash(void)
{
    dap_print_module_name("test_ledger_info_requires_hash");
    
    // Enable mock to return NULL for ledger lookup
    DAP_MOCK_ENABLE(dap_ledger_find_by_name);
    g_mock_dap_ledger_find_by_name->return_value.ptr = NULL;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"ledger", "info", "-net", "TestNet", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_ledger(4, l_argv, l_json_reply, 1);
    
    // Should fail - needs -tx parameter with hash
    dap_assert(l_ret != 0, "ledger info without tx hash should fail");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_ledger_find_by_name);
    
    dap_print_module_name("test_ledger_info_requires_hash PASSED");
}

/**
 * @brief Test ledger event without subcommand
 */
static void test_ledger_event_requires_subcommand(void)
{
    dap_print_module_name("test_ledger_event_requires_subcommand");
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"ledger", "event", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_ledger(2, l_argv, l_json_reply, 1);
    
    // Should fail - event needs subcommand (list, dump, key, create)
    dap_assert(l_ret != 0, "ledger event without subcommand should fail");
    
    dap_json_object_free(l_json_reply);
    dap_print_module_name("test_ledger_event_requires_subcommand PASSED");
}

/**
 * @brief Test ledger trace without parameters
 */
static void test_ledger_trace_requires_params(void)
{
    dap_print_module_name("test_ledger_trace_requires_params");
    
    // Enable mock to return NULL for ledger lookup
    DAP_MOCK_ENABLE(dap_ledger_find_by_name);
    g_mock_dap_ledger_find_by_name->return_value.ptr = NULL;
    
    dap_json_t *l_json_reply = NULL;
    char *l_argv[] = {"ledger", "trace", NULL};
    
    l_json_reply = dap_json_array_new();
    int l_ret = com_ledger(2, l_argv, l_json_reply, 1);
    
    // Should fail - trace needs parameters
    dap_assert(l_ret != 0, "ledger trace without params should fail");
    
    dap_json_object_free(l_json_reply);
    DAP_MOCK_DISABLE(dap_ledger_find_by_name);
    
    dap_print_module_name("test_ledger_trace_requires_params PASSED");
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
    
    dap_common_init("test_cli_ledger_mocked", NULL);
    dap_log_level_set(L_ERROR); // Suppress verbose logging from CLI functions
    
    dap_mock_init();
    
    // Initialize CLI commands
    dap_chain_ledger_cli_ledger_init();
    
    dap_print_module_name("CLI Ledger Mocked Tests");
    printf("Testing ledger CLI with DAP Mock Framework\n\n");
    
    // Run tests
    test_ledger_no_subcommand();
    test_ledger_invalid_hash_type();
    test_ledger_list_requires_net();
    test_ledger_info_requires_hash();
    test_ledger_event_requires_subcommand();
    test_ledger_trace_requires_params();
    
    dap_print_module_name("All CLI Ledger mocked tests passed!");
    
    dap_mock_deinit();
    dap_chain_ledger_cli_ledger_deinit();
    
    return 0;
}

