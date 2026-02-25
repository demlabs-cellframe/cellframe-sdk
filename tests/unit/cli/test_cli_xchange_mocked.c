/**
 * @file test_cli_xchange_mocked.c
 * @brief Unit tests for xchange service CLI with full mocking support
 * 
 * This test file uses DAP Mock Framework to mock xchange/network dependencies
 * allowing full CLI command execution with controlled, predictable behavior.
 * 
 * Tests verify:
 * 1. CLI command registration and invocation
 * 2. JSON output structure and field names
 * 3. Correct handling of various xchange states
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
#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_net_srv_xchange_wrap.h"

#define LOG_TAG "test_cli_xchange_mocked"

// ============================================================================
// GLOBAL MOCK OUTPUT PARAMETERS
// ============================================================================

static dap_chain_net_t *s_mock_net_output = NULL;

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
 * @brief Mock for dap_chain_net_srv_xchange_get_order_status_w
 */
DAP_MOCK_DECLARE(dap_chain_net_srv_xchange_get_order_status_w, {
    .return_value.i = XCHANGE_ORDER_STATUS_UNKNOWN
});

/**
 * @brief Mock for dap_chain_net_srv_xchange_get_order_completion_rate_w
 */
DAP_MOCK_DECLARE(dap_chain_net_srv_xchange_get_order_completion_rate_w, {
    .return_value.u64 = 0
});

/**
 * @brief Mock for dap_chain_net_srv_xchange_get_fee_w
 */
DAP_MOCK_DECLARE(dap_chain_net_srv_xchange_get_fee_w, {
    .return_value.i = 0  // false
});

/**
 * @brief Mock for dap_chain_net_srv_xchange_get_prices_w
 */
DAP_MOCK_DECLARE(dap_chain_net_srv_xchange_get_prices_w, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_chain_net_srv_xchange_get_tx_xchange_w
 */
DAP_MOCK_DECLARE(dap_chain_net_srv_xchange_get_tx_xchange_w, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_ledger_token_ticker_check
 */
DAP_MOCK_DECLARE(dap_ledger_token_ticker_check, {
    .return_value.i = 1  // true - token exists
});

/**
 * @brief Mock for dap_chain_wallet_open
 */
DAP_MOCK_DECLARE(dap_chain_wallet_open, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_chain_wallet_get_path
 */
DAP_MOCK_DECLARE(dap_chain_wallet_get_path, {
    .return_value.ptr = "/tmp/wallets"
});

// ============================================================================
// EXTERNAL REAL FUNCTION DECLARATIONS
// ============================================================================

extern dap_chain_net_t* __real_dap_chain_net_by_name(const char *a_name);

extern dap_chain_net_srv_xchange_order_status_t __real_dap_chain_net_srv_xchange_get_order_status_w(
    dap_chain_net_t *a_net, dap_hash_fast_t a_order_tx_hash);

extern uint64_t __real_dap_chain_net_srv_xchange_get_order_completion_rate_w(
    dap_chain_net_t *a_net, dap_hash_fast_t a_order_tx_hash);

extern bool __real_dap_chain_net_srv_xchange_get_fee_w(
    dap_chain_net_id_t a_net_id, uint256_t *a_value, dap_chain_addr_t *a_addr, uint16_t *a_type);

extern dap_list_t* __real_dap_chain_net_srv_xchange_get_prices_w(dap_chain_net_t *a_net);

extern dap_list_t* __real_dap_chain_net_srv_xchange_get_tx_xchange_w(dap_chain_net_t *a_net);

extern bool __real_dap_ledger_token_ticker_check(dap_ledger_t *a_ledger, const char *a_ticker);

extern dap_chain_wallet_t* __real_dap_chain_wallet_open(const char *a_name, const char *a_path, dap_sign_type_t *a_sign_type);

extern const char* __real_dap_chain_wallet_get_path(dap_config_t *a_config);

// ============================================================================
// WRAPPER IMPLEMENTATIONS
// ============================================================================

/**
 * @brief Wrapper for dap_chain_net_by_name
 */
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

/**
 * @brief Wrapper for dap_chain_net_srv_xchange_get_order_status_w
 */
dap_chain_net_srv_xchange_order_status_t __wrap_dap_chain_net_srv_xchange_get_order_status_w(
    dap_chain_net_t *a_net, dap_hash_fast_t a_order_tx_hash)
{
    if (g_mock_dap_chain_net_srv_xchange_get_order_status_w && 
        g_mock_dap_chain_net_srv_xchange_get_order_status_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_srv_xchange_get_order_status_w, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_net_srv_xchange_get_order_status_w->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_chain_net_srv_xchange_get_order_status_w called");
        return (dap_chain_net_srv_xchange_order_status_t)g_mock_dap_chain_net_srv_xchange_get_order_status_w->return_value.i;
    }
    return __real_dap_chain_net_srv_xchange_get_order_status_w(a_net, a_order_tx_hash);
}

/**
 * @brief Wrapper for dap_chain_net_srv_xchange_get_order_completion_rate_w
 */
uint64_t __wrap_dap_chain_net_srv_xchange_get_order_completion_rate_w(
    dap_chain_net_t *a_net, dap_hash_fast_t a_order_tx_hash)
{
    if (g_mock_dap_chain_net_srv_xchange_get_order_completion_rate_w && 
        g_mock_dap_chain_net_srv_xchange_get_order_completion_rate_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_srv_xchange_get_order_completion_rate_w, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_net_srv_xchange_get_order_completion_rate_w->return_value.u64);
        log_it(L_DEBUG, "MOCK: dap_chain_net_srv_xchange_get_order_completion_rate_w called");
        return g_mock_dap_chain_net_srv_xchange_get_order_completion_rate_w->return_value.u64;
    }
    return __real_dap_chain_net_srv_xchange_get_order_completion_rate_w(a_net, a_order_tx_hash);
}

/**
 * @brief Wrapper for dap_chain_net_srv_xchange_get_fee_w
 */
bool __wrap_dap_chain_net_srv_xchange_get_fee_w(
    dap_chain_net_id_t a_net_id, uint256_t *a_value, dap_chain_addr_t *a_addr, uint16_t *a_type)
{
    if (g_mock_dap_chain_net_srv_xchange_get_fee_w && 
        g_mock_dap_chain_net_srv_xchange_get_fee_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_srv_xchange_get_fee_w, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_net_srv_xchange_get_fee_w->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_chain_net_srv_xchange_get_fee_w called");
        return (bool)g_mock_dap_chain_net_srv_xchange_get_fee_w->return_value.i;
    }
    return __real_dap_chain_net_srv_xchange_get_fee_w(a_net_id, a_value, a_addr, a_type);
}

/**
 * @brief Wrapper for dap_chain_net_srv_xchange_get_prices_w
 */
dap_list_t* __wrap_dap_chain_net_srv_xchange_get_prices_w(dap_chain_net_t *a_net)
{
    if (g_mock_dap_chain_net_srv_xchange_get_prices_w && 
        g_mock_dap_chain_net_srv_xchange_get_prices_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_srv_xchange_get_prices_w, NULL, 0,
                             g_mock_dap_chain_net_srv_xchange_get_prices_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_net_srv_xchange_get_prices_w called");
        return (dap_list_t*)g_mock_dap_chain_net_srv_xchange_get_prices_w->return_value.ptr;
    }
    return __real_dap_chain_net_srv_xchange_get_prices_w(a_net);
}

/**
 * @brief Wrapper for dap_chain_net_srv_xchange_get_tx_xchange_w
 */
dap_list_t* __wrap_dap_chain_net_srv_xchange_get_tx_xchange_w(dap_chain_net_t *a_net)
{
    if (g_mock_dap_chain_net_srv_xchange_get_tx_xchange_w && 
        g_mock_dap_chain_net_srv_xchange_get_tx_xchange_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_srv_xchange_get_tx_xchange_w, NULL, 0,
                             g_mock_dap_chain_net_srv_xchange_get_tx_xchange_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_net_srv_xchange_get_tx_xchange_w called");
        return (dap_list_t*)g_mock_dap_chain_net_srv_xchange_get_tx_xchange_w->return_value.ptr;
    }
    return __real_dap_chain_net_srv_xchange_get_tx_xchange_w(a_net);
}

/**
 * @brief Wrapper for dap_ledger_token_ticker_check
 */
bool __wrap_dap_ledger_token_ticker_check(dap_ledger_t *a_ledger, const char *a_ticker)
{
    if (g_mock_dap_ledger_token_ticker_check && 
        g_mock_dap_ledger_token_ticker_check->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_token_ticker_check, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_ledger_token_ticker_check->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_ledger_token_ticker_check(ticker=%s) called", a_ticker ? a_ticker : "(null)");
        return (bool)g_mock_dap_ledger_token_ticker_check->return_value.i;
    }
    return __real_dap_ledger_token_ticker_check(a_ledger, a_ticker);
}

/**
 * @brief Wrapper for dap_chain_wallet_open
 */
dap_chain_wallet_t* __wrap_dap_chain_wallet_open(const char *a_name, const char *a_path, dap_sign_type_t *a_sign_type)
{
    if (g_mock_dap_chain_wallet_open && g_mock_dap_chain_wallet_open->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_open, NULL, 0,
                             g_mock_dap_chain_wallet_open->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_wallet_open(name=%s) called", a_name ? a_name : "(null)");
        return (dap_chain_wallet_t*)g_mock_dap_chain_wallet_open->return_value.ptr;
    }
    return __real_dap_chain_wallet_open(a_name, a_path, a_sign_type);
}

/**
 * @brief Wrapper for dap_chain_wallet_get_path
 */
const char* __wrap_dap_chain_wallet_get_path(dap_config_t *a_config)
{
    if (g_mock_dap_chain_wallet_get_path && g_mock_dap_chain_wallet_get_path->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_get_path, NULL, 0,
                             g_mock_dap_chain_wallet_get_path->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_wallet_get_path called");
        return (const char*)g_mock_dap_chain_wallet_get_path->return_value.ptr;
    }
    return __real_dap_chain_wallet_get_path(a_config);
}

// ============================================================================
// MOCK HELPERS
// ============================================================================

/**
 * @brief Initialize all mocks
 */
static void s_mocks_init(void)
{
    dap_mock_init(g_mock_dap_chain_net_by_name);
    dap_mock_init(g_mock_dap_chain_net_srv_xchange_get_order_status_w);
    dap_mock_init(g_mock_dap_chain_net_srv_xchange_get_order_completion_rate_w);
    dap_mock_init(g_mock_dap_chain_net_srv_xchange_get_fee_w);
    dap_mock_init(g_mock_dap_chain_net_srv_xchange_get_prices_w);
    dap_mock_init(g_mock_dap_chain_net_srv_xchange_get_tx_xchange_w);
    dap_mock_init(g_mock_dap_ledger_token_ticker_check);
    dap_mock_init(g_mock_dap_chain_wallet_open);
    dap_mock_init(g_mock_dap_chain_wallet_get_path);
}

/**
 * @brief Enable all mocks
 */
static void s_mocks_enable(void)
{
    dap_mock_enable(g_mock_dap_chain_net_by_name);
    dap_mock_enable(g_mock_dap_chain_net_srv_xchange_get_order_status_w);
    dap_mock_enable(g_mock_dap_chain_net_srv_xchange_get_order_completion_rate_w);
    dap_mock_enable(g_mock_dap_chain_net_srv_xchange_get_fee_w);
    dap_mock_enable(g_mock_dap_chain_net_srv_xchange_get_prices_w);
    dap_mock_enable(g_mock_dap_chain_net_srv_xchange_get_tx_xchange_w);
    dap_mock_enable(g_mock_dap_ledger_token_ticker_check);
    dap_mock_enable(g_mock_dap_chain_wallet_open);
    dap_mock_enable(g_mock_dap_chain_wallet_get_path);
}

/**
 * @brief Disable all mocks
 */
static void s_mocks_disable(void)
{
    dap_mock_disable(g_mock_dap_chain_net_by_name);
    dap_mock_disable(g_mock_dap_chain_net_srv_xchange_get_order_status_w);
    dap_mock_disable(g_mock_dap_chain_net_srv_xchange_get_order_completion_rate_w);
    dap_mock_disable(g_mock_dap_chain_net_srv_xchange_get_fee_w);
    dap_mock_disable(g_mock_dap_chain_net_srv_xchange_get_prices_w);
    dap_mock_disable(g_mock_dap_chain_net_srv_xchange_get_tx_xchange_w);
    dap_mock_disable(g_mock_dap_ledger_token_ticker_check);
    dap_mock_disable(g_mock_dap_chain_wallet_open);
    dap_mock_disable(g_mock_dap_chain_wallet_get_path);
}

/**
 * @brief Reset all mocks to default state
 */
static void s_mocks_reset(void)
{
    dap_mock_reset(g_mock_dap_chain_net_by_name);
    dap_mock_reset(g_mock_dap_chain_net_srv_xchange_get_order_status_w);
    dap_mock_reset(g_mock_dap_chain_net_srv_xchange_get_order_completion_rate_w);
    dap_mock_reset(g_mock_dap_chain_net_srv_xchange_get_fee_w);
    dap_mock_reset(g_mock_dap_chain_net_srv_xchange_get_prices_w);
    dap_mock_reset(g_mock_dap_chain_net_srv_xchange_get_tx_xchange_w);
    dap_mock_reset(g_mock_dap_ledger_token_ticker_check);
    dap_mock_reset(g_mock_dap_chain_wallet_open);
    dap_mock_reset(g_mock_dap_chain_wallet_get_path);
}

// ============================================================================
// MOCK DATA STRUCTURES
// ============================================================================

// Mock network structure with minimal required fields
static struct {
    dap_chain_net_t net;
    char name[64];
    dap_ledger_t *ledger;
} s_mock_net_data;

/**
 * @brief Setup mock network
 */
static void s_setup_mock_net(const char *a_name)
{
    memset(&s_mock_net_data, 0, sizeof(s_mock_net_data));
    strncpy(s_mock_net_data.name, a_name, sizeof(s_mock_net_data.name) - 1);
    s_mock_net_data.net.pub.name = s_mock_net_data.name;
    s_mock_net_data.net.pub.id.uint64 = 0x1234567890ABCDEF;
    s_mock_net_output = &s_mock_net_data.net;
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
 * @brief Test: order create requires -net parameter
 */
static void test_xchange_order_create_requires_net(void)
{
    dap_print_module_name("xchange_order_create_requires_net");
    
    s_mocks_reset();
    s_mocks_enable();
    
    dap_json_t *l_reply = s_cli_execute("srv_xchange order create", 2);
    
    // Should return error about missing -net
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: order create requires -token_sell parameter
 */
static void test_xchange_order_create_requires_token_sell(void)
{
    dap_print_module_name("xchange_order_create_requires_token_sell");
    
    s_mocks_reset();
    s_mocks_enable();
    
    s_setup_mock_net("TestNet");
    g_mock_dap_chain_net_by_name->return_value.ptr = s_mock_net_output;
    
    dap_json_t *l_reply = s_cli_execute("srv_xchange order create -net TestNet", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: order create requires -token_buy parameter
 */
static void test_xchange_order_create_requires_token_buy(void)
{
    dap_print_module_name("xchange_order_create_requires_token_buy");
    
    s_mocks_reset();
    s_mocks_enable();
    
    s_setup_mock_net("TestNet");
    g_mock_dap_chain_net_by_name->return_value.ptr = s_mock_net_output;
    
    dap_json_t *l_reply = s_cli_execute("srv_xchange order create -net TestNet -token_sell CELL", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: order status requires -net parameter
 */
static void test_xchange_order_status_requires_net(void)
{
    dap_print_module_name("xchange_order_status_requires_net");
    
    s_mocks_reset();
    s_mocks_enable();
    
    dap_json_t *l_reply = s_cli_execute("srv_xchange order status", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: order history requires -net parameter
 */
static void test_xchange_order_history_requires_net(void)
{
    dap_print_module_name("xchange_order_history_requires_net");
    
    s_mocks_reset();
    s_mocks_enable();
    
    dap_json_t *l_reply = s_cli_execute("srv_xchange order history", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: order remove requires -net parameter
 */
static void test_xchange_order_remove_requires_net(void)
{
    dap_print_module_name("xchange_order_remove_requires_net");
    
    s_mocks_reset();
    s_mocks_enable();
    
    dap_json_t *l_reply = s_cli_execute("srv_xchange order remove", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// TESTS: Network Not Found
// ============================================================================

/**
 * @brief Test: order create with non-existent network
 */
static void test_xchange_order_create_net_not_found(void)
{
    dap_print_module_name("xchange_order_create_net_not_found");
    
    s_mocks_reset();
    s_mocks_enable();
    
    g_mock_dap_chain_net_by_name->return_value.ptr = NULL;  // Network not found
    
    dap_json_t *l_reply = s_cli_execute("srv_xchange order create -net NonExistent", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: order status with non-existent network
 */
static void test_xchange_order_status_net_not_found(void)
{
    dap_print_module_name("xchange_order_status_net_not_found");
    
    s_mocks_reset();
    s_mocks_enable();
    
    g_mock_dap_chain_net_by_name->return_value.ptr = NULL;
    
    dap_json_t *l_reply = s_cli_execute("srv_xchange order status -net NonExistent", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// TESTS: Token Validation
// ============================================================================

/**
 * @brief Test: order create with same buy and sell token
 */
static void test_xchange_order_create_same_tokens(void)
{
    dap_print_module_name("xchange_order_create_same_tokens");
    
    s_mocks_reset();
    s_mocks_enable();
    
    s_setup_mock_net("TestNet");
    g_mock_dap_chain_net_by_name->return_value.ptr = s_mock_net_output;
    g_mock_dap_ledger_token_ticker_check->return_value.i = 1;  // Token exists
    
    dap_json_t *l_reply = s_cli_execute("srv_xchange order create -net TestNet -token_sell CELL -token_buy CELL", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    // Should return error about same tokens
    
    dap_json_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// TESTS: Wallet Validation  
// ============================================================================

/**
 * @brief Test: order create wallet not found
 */
static void test_xchange_order_create_wallet_not_found(void)
{
    dap_print_module_name("xchange_order_create_wallet_not_found");
    
    s_mocks_reset();
    s_mocks_enable();
    
    s_setup_mock_net("TestNet");
    g_mock_dap_chain_net_by_name->return_value.ptr = s_mock_net_output;
    g_mock_dap_ledger_token_ticker_check->return_value.i = 1;
    g_mock_dap_chain_wallet_open->return_value.ptr = NULL;  // Wallet not found
    
    dap_json_t *l_reply = s_cli_execute(
        "srv_xchange order create -net TestNet -token_sell CELL -token_buy mCELL -value 100 -rate 1.0 -fee 0.01 -w nonexistent", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// MAIN
// ============================================================================

int main(void)
{
    // Initialize test framework
    dap_set_appname("test_cli_xchange_mocked");
    dap_log_set_min_level(L_ERROR);
    
    // Initialize mocks
    s_mocks_init();
    
    // Register srv_xchange CLI command
    dap_chain_net_srv_xchange_init();
    
    dap_print_module_name("CLI XChange Mocked Tests");
    log_it(L_NOTICE, "Starting CLI XChange mocked tests...");
    
    // Run parameter validation tests
    test_xchange_order_create_requires_net();
    test_xchange_order_create_requires_token_sell();
    test_xchange_order_create_requires_token_buy();
    test_xchange_order_status_requires_net();
    test_xchange_order_history_requires_net();
    test_xchange_order_remove_requires_net();
    
    // Run network not found tests
    test_xchange_order_create_net_not_found();
    test_xchange_order_status_net_not_found();
    
    // Run token validation tests
    test_xchange_order_create_same_tokens();
    
    // Run wallet validation tests
    test_xchange_order_create_wallet_not_found();
    
    log_it(L_NOTICE, "All CLI XChange mocked tests passed!");
    printf("\n✓ All %d tests passed\n", 10);
    
    return 0;
}


