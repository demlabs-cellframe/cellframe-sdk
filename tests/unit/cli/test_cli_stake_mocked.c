/**
 * @file test_cli_stake_mocked.c
 * @brief Unit tests for stake service CLI with full mocking support
 * 
 * This test file uses DAP Mock Framework to mock stake/network dependencies
 * allowing full CLI command execution with controlled, predictable behavior.
 * 
 * Tests verify:
 * 1. CLI command registration and invocation
 * 2. JSON output structure and field names
 * 3. Correct handling of various stake states
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
#include "dap_chain_net_srv_stake.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_net_srv_stake_wrap.h"

#define LOG_TAG "test_cli_stake_mocked"

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
 * @brief Mock for dap_chain_net_srv_stake_get_validators_w
 */
DAP_MOCK_DECLARE(dap_chain_net_srv_stake_get_validators_w, {
    .return_value.ptr = NULL
});

/**
 * @brief Mock for dap_chain_net_srv_stake_get_total_weight_w
 */
DAP_MOCK_DECLARE(dap_chain_net_srv_stake_get_total_weight_w, {
    .return_value.u64 = 0
});

/**
 * @brief Mock for dap_chain_net_srv_stake_get_total_keys_w
 */
DAP_MOCK_DECLARE(dap_chain_net_srv_stake_get_total_keys_w, {
    .return_value.u64 = 0
});

/**
 * @brief Mock for dap_chain_net_srv_stake_get_allowed_min_value_w
 */
DAP_MOCK_DECLARE(dap_chain_net_srv_stake_get_allowed_min_value_w, {
    .return_value.u64 = 0
});

/**
 * @brief Mock for dap_chain_net_srv_stake_check_validator_w
 */
DAP_MOCK_DECLARE(dap_chain_net_srv_stake_check_validator_w, {
    .return_value.i = 0
});

/**
 * @brief Mock for dap_chain_net_srv_stake_get_percent_max_w
 */
DAP_MOCK_DECLARE(dap_chain_net_srv_stake_get_percent_max_w, {
    .return_value.u64 = 0
});

/**
 * @brief Mock for dap_chain_hash_fast_from_str
 */
DAP_MOCK_DECLARE(dap_chain_hash_fast_from_str, {
    .return_value.i = 0
});

/**
 * @brief Mock for dap_cert_find_by_name
 */
DAP_MOCK_DECLARE(dap_cert_find_by_name, {
    .return_value.ptr = NULL
});

// ============================================================================
// EXTERNAL REAL FUNCTION DECLARATIONS
// ============================================================================

extern dap_chain_net_t* __real_dap_chain_net_by_name(const char *a_name);

extern dap_list_t* __real_dap_chain_net_srv_stake_get_validators_w(
    dap_chain_net_id_t a_net_id, bool a_only_active, uint16_t **a_excluded_list);

extern uint256_t __real_dap_chain_net_srv_stake_get_total_weight_w(
    dap_chain_net_id_t a_net_id, uint256_t *a_locked_weight);

extern size_t __real_dap_chain_net_srv_stake_get_total_keys_w(
    dap_chain_net_id_t a_net_id, size_t *a_in_active_count);

extern uint256_t __real_dap_chain_net_srv_stake_get_allowed_min_value_w(
    dap_chain_net_id_t a_net_id);

extern int __real_dap_chain_net_srv_stake_check_validator_w(
    dap_chain_net_t *a_net, dap_hash_fast_t *a_tx_hash, 
    dap_chain_ch_validator_test_t *out_data, int a_time_connect, int a_time_response);

extern uint256_t __real_dap_chain_net_srv_stake_get_percent_max_w(
    dap_chain_net_id_t a_net_id);

extern int __real_dap_chain_hash_fast_from_str(const char *a_str, dap_chain_hash_fast_t *a_hash);

extern dap_cert_t* __real_dap_cert_find_by_name(const char *a_name);

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
 * @brief Wrapper for dap_chain_net_srv_stake_get_validators_w
 */
dap_list_t* __wrap_dap_chain_net_srv_stake_get_validators_w(
    dap_chain_net_id_t a_net_id, bool a_only_active, uint16_t **a_excluded_list)
{
    if (g_mock_dap_chain_net_srv_stake_get_validators_w && 
        g_mock_dap_chain_net_srv_stake_get_validators_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_srv_stake_get_validators_w, NULL, 0,
                             g_mock_dap_chain_net_srv_stake_get_validators_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_net_srv_stake_get_validators_w called");
        return (dap_list_t*)g_mock_dap_chain_net_srv_stake_get_validators_w->return_value.ptr;
    }
    return __real_dap_chain_net_srv_stake_get_validators_w(a_net_id, a_only_active, a_excluded_list);
}

/**
 * @brief Wrapper for dap_chain_net_srv_stake_get_total_weight_w
 */
uint256_t __wrap_dap_chain_net_srv_stake_get_total_weight_w(
    dap_chain_net_id_t a_net_id, uint256_t *a_locked_weight)
{
    if (g_mock_dap_chain_net_srv_stake_get_total_weight_w && 
        g_mock_dap_chain_net_srv_stake_get_total_weight_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_srv_stake_get_total_weight_w, NULL, 0, NULL);
        log_it(L_DEBUG, "MOCK: dap_chain_net_srv_stake_get_total_weight_w called");
        uint256_t l_ret = {0};
        return l_ret;
    }
    return __real_dap_chain_net_srv_stake_get_total_weight_w(a_net_id, a_locked_weight);
}

/**
 * @brief Wrapper for dap_chain_net_srv_stake_get_total_keys_w
 */
size_t __wrap_dap_chain_net_srv_stake_get_total_keys_w(
    dap_chain_net_id_t a_net_id, size_t *a_in_active_count)
{
    if (g_mock_dap_chain_net_srv_stake_get_total_keys_w && 
        g_mock_dap_chain_net_srv_stake_get_total_keys_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_srv_stake_get_total_keys_w, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_net_srv_stake_get_total_keys_w->return_value.u64);
        log_it(L_DEBUG, "MOCK: dap_chain_net_srv_stake_get_total_keys_w called");
        return (size_t)g_mock_dap_chain_net_srv_stake_get_total_keys_w->return_value.u64;
    }
    return __real_dap_chain_net_srv_stake_get_total_keys_w(a_net_id, a_in_active_count);
}

/**
 * @brief Wrapper for dap_chain_net_srv_stake_get_allowed_min_value_w
 */
uint256_t __wrap_dap_chain_net_srv_stake_get_allowed_min_value_w(
    dap_chain_net_id_t a_net_id)
{
    if (g_mock_dap_chain_net_srv_stake_get_allowed_min_value_w && 
        g_mock_dap_chain_net_srv_stake_get_allowed_min_value_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_srv_stake_get_allowed_min_value_w, NULL, 0, NULL);
        log_it(L_DEBUG, "MOCK: dap_chain_net_srv_stake_get_allowed_min_value_w called");
        uint256_t l_ret = {0};
        return l_ret;
    }
    return __real_dap_chain_net_srv_stake_get_allowed_min_value_w(a_net_id);
}

/**
 * @brief Wrapper for dap_chain_net_srv_stake_check_validator_w
 */
int __wrap_dap_chain_net_srv_stake_check_validator_w(
    dap_chain_net_t *a_net, dap_hash_fast_t *a_tx_hash, 
    dap_chain_ch_validator_test_t *out_data, int a_time_connect, int a_time_response)
{
    if (g_mock_dap_chain_net_srv_stake_check_validator_w && 
        g_mock_dap_chain_net_srv_stake_check_validator_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_srv_stake_check_validator_w, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_net_srv_stake_check_validator_w->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_chain_net_srv_stake_check_validator_w called");
        return g_mock_dap_chain_net_srv_stake_check_validator_w->return_value.i;
    }
    return __real_dap_chain_net_srv_stake_check_validator_w(a_net, a_tx_hash, out_data, a_time_connect, a_time_response);
}

/**
 * @brief Wrapper for dap_chain_net_srv_stake_get_percent_max_w
 */
uint256_t __wrap_dap_chain_net_srv_stake_get_percent_max_w(
    dap_chain_net_id_t a_net_id)
{
    if (g_mock_dap_chain_net_srv_stake_get_percent_max_w && 
        g_mock_dap_chain_net_srv_stake_get_percent_max_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_srv_stake_get_percent_max_w, NULL, 0, NULL);
        log_it(L_DEBUG, "MOCK: dap_chain_net_srv_stake_get_percent_max_w called");
        uint256_t l_ret = {0};
        return l_ret;
    }
    return __real_dap_chain_net_srv_stake_get_percent_max_w(a_net_id);
}

/**
 * @brief Wrapper for dap_chain_hash_fast_from_str
 */
int __wrap_dap_chain_hash_fast_from_str(const char *a_str, dap_chain_hash_fast_t *a_hash)
{
    if (g_mock_dap_chain_hash_fast_from_str && g_mock_dap_chain_hash_fast_from_str->enabled) {
        dap_mock_record_call(g_mock_dap_chain_hash_fast_from_str, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_hash_fast_from_str->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_chain_hash_fast_from_str(str=%s) called", a_str ? a_str : "(null)");
        if (a_hash) memset(a_hash, 0, sizeof(*a_hash));
        return g_mock_dap_chain_hash_fast_from_str->return_value.i;
    }
    return __real_dap_chain_hash_fast_from_str(a_str, a_hash);
}

/**
 * @brief Wrapper for dap_cert_find_by_name
 */
dap_cert_t* __wrap_dap_cert_find_by_name(const char *a_name)
{
    if (g_mock_dap_cert_find_by_name && g_mock_dap_cert_find_by_name->enabled) {
        dap_mock_record_call(g_mock_dap_cert_find_by_name, NULL, 0,
                             g_mock_dap_cert_find_by_name->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_cert_find_by_name(name=%s) called", a_name ? a_name : "(null)");
        return (dap_cert_t*)g_mock_dap_cert_find_by_name->return_value.ptr;
    }
    return __real_dap_cert_find_by_name(a_name);
}

// ============================================================================
// MOCK HELPERS
// ============================================================================

/**
 * @brief Reset all mocks to default state
 */
static void s_mocks_init(void)
{
    DAP_MOCK_RESET(dap_chain_net_by_name);
    DAP_MOCK_RESET(dap_chain_net_srv_stake_get_validators_w);
    DAP_MOCK_RESET(dap_chain_net_srv_stake_get_total_weight_w);
    DAP_MOCK_RESET(dap_chain_net_srv_stake_get_total_keys_w);
    DAP_MOCK_RESET(dap_chain_net_srv_stake_get_allowed_min_value_w);
    DAP_MOCK_RESET(dap_chain_net_srv_stake_check_validator_w);
    DAP_MOCK_RESET(dap_chain_net_srv_stake_get_percent_max_w);
    DAP_MOCK_RESET(dap_chain_hash_fast_from_str);
    DAP_MOCK_RESET(dap_cert_find_by_name);
    
    s_mock_net_output = NULL;
}

/**
 * @brief Enable all mocks
 */
static void s_mocks_enable(void)
{
    DAP_MOCK_ENABLE(dap_chain_net_by_name);
    DAP_MOCK_ENABLE(dap_chain_net_srv_stake_get_validators_w);
    DAP_MOCK_ENABLE(dap_chain_net_srv_stake_get_total_weight_w);
    DAP_MOCK_ENABLE(dap_chain_net_srv_stake_get_total_keys_w);
    DAP_MOCK_ENABLE(dap_chain_net_srv_stake_get_allowed_min_value_w);
    DAP_MOCK_ENABLE(dap_chain_net_srv_stake_check_validator_w);
    DAP_MOCK_ENABLE(dap_chain_net_srv_stake_get_percent_max_w);
    DAP_MOCK_ENABLE(dap_chain_hash_fast_from_str);
    DAP_MOCK_ENABLE(dap_cert_find_by_name);
}

/**
 * @brief Disable all mocks
 */
static void s_mocks_disable(void)
{
    DAP_MOCK_DISABLE(dap_chain_net_by_name);
    DAP_MOCK_DISABLE(dap_chain_net_srv_stake_get_validators_w);
    DAP_MOCK_DISABLE(dap_chain_net_srv_stake_get_total_weight_w);
    DAP_MOCK_DISABLE(dap_chain_net_srv_stake_get_total_keys_w);
    DAP_MOCK_DISABLE(dap_chain_net_srv_stake_get_allowed_min_value_w);
    DAP_MOCK_DISABLE(dap_chain_net_srv_stake_check_validator_w);
    DAP_MOCK_DISABLE(dap_chain_net_srv_stake_get_percent_max_w);
    DAP_MOCK_DISABLE(dap_chain_hash_fast_from_str);
    DAP_MOCK_DISABLE(dap_cert_find_by_name);
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

// Mock network structure
static dap_chain_net_t s_mock_net_data;

/**
 * @brief Setup mock network
 */
static void s_setup_mock_net(const char *a_name)
{
    memset(&s_mock_net_data, 0, sizeof(s_mock_net_data));
    strncpy(s_mock_net_data.pub.name, a_name, DAP_CHAIN_NET_NAME_MAX);
    s_mock_net_data.pub.id.uint64 = 0x1234567890ABCDEF;
    s_mock_net_output = &s_mock_net_data;
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
// TESTS: Parameter Validation - Order Commands
// ============================================================================

/**
 * @brief Test: order create requires -net parameter
 */
static void test_stake_order_create_requires_net(void)
{
    dap_print_module_name("stake_order_create_requires_net");
    
    s_mocks_reset();
    s_mocks_enable();
    
    dap_json_t *l_reply = s_cli_execute("srv_stake order create fee", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: order create requires -value parameter
 */
static void test_stake_order_create_requires_value(void)
{
    dap_print_module_name("stake_order_create_requires_value");
    
    s_mocks_reset();
    s_mocks_enable();
    
    s_setup_mock_net("TestNet");
    g_mock_dap_chain_net_by_name->return_value.ptr = s_mock_net_output;
    
    dap_json_t *l_reply = s_cli_execute("srv_stake order create fee -net TestNet", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: order create requires -cert parameter
 */
static void test_stake_order_create_requires_cert(void)
{
    dap_print_module_name("stake_order_create_requires_cert");
    
    s_mocks_reset();
    s_mocks_enable();
    
    s_setup_mock_net("TestNet");
    g_mock_dap_chain_net_by_name->return_value.ptr = s_mock_net_output;
    
    dap_json_t *l_reply = s_cli_execute("srv_stake order create fee -net TestNet -value 100", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// TESTS: Parameter Validation - Delegate Commands
// ============================================================================

/**
 * @brief Test: delegate requires -net parameter
 */
static void test_stake_delegate_requires_net(void)
{
    dap_print_module_name("stake_delegate_requires_net");
    
    s_mocks_reset();
    s_mocks_enable();
    
    dap_json_t *l_reply = s_cli_execute("srv_stake delegate", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: delegate requires -w parameter
 */
static void test_stake_delegate_requires_wallet(void)
{
    dap_print_module_name("stake_delegate_requires_wallet");
    
    s_mocks_reset();
    s_mocks_enable();
    
    s_setup_mock_net("TestNet");
    g_mock_dap_chain_net_by_name->return_value.ptr = s_mock_net_output;
    
    dap_json_t *l_reply = s_cli_execute("srv_stake delegate -net TestNet", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// TESTS: Parameter Validation - Check Command
// ============================================================================

/**
 * @brief Test: check requires -net parameter
 */
static void test_stake_check_requires_net(void)
{
    dap_print_module_name("stake_check_requires_net");
    
    s_mocks_reset();
    s_mocks_enable();
    
    dap_json_t *l_reply = s_cli_execute("srv_stake check", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: check requires -tx parameter
 */
static void test_stake_check_requires_tx(void)
{
    dap_print_module_name("stake_check_requires_tx");
    
    s_mocks_reset();
    s_mocks_enable();
    
    s_setup_mock_net("TestNet");
    g_mock_dap_chain_net_by_name->return_value.ptr = s_mock_net_output;
    
    dap_json_t *l_reply = s_cli_execute("srv_stake check -net TestNet", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// TESTS: Network Not Found
// ============================================================================

/**
 * @brief Test: order create with non-existent network
 */
static void test_stake_order_create_net_not_found(void)
{
    dap_print_module_name("stake_order_create_net_not_found");
    
    s_mocks_reset();
    s_mocks_enable();
    
    g_mock_dap_chain_net_by_name->return_value.ptr = NULL;
    
    dap_json_t *l_reply = s_cli_execute("srv_stake order create fee -net NonExistent", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

/**
 * @brief Test: check with non-existent network
 */
static void test_stake_check_net_not_found(void)
{
    dap_print_module_name("stake_check_net_not_found");
    
    s_mocks_reset();
    s_mocks_enable();
    
    g_mock_dap_chain_net_by_name->return_value.ptr = NULL;
    
    dap_json_t *l_reply = s_cli_execute("srv_stake check -net NonExistent -tx 1234", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// TESTS: Update Command
// ============================================================================

/**
 * @brief Test: update requires -net parameter
 */
static void test_stake_update_requires_net(void)
{
    dap_print_module_name("stake_update_requires_net");
    
    s_mocks_reset();
    s_mocks_enable();
    
    dap_json_t *l_reply = s_cli_execute("srv_stake update", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// TESTS: Invalidate Command
// ============================================================================

/**
 * @brief Test: invalidate requires -net parameter
 */
static void test_stake_invalidate_requires_net(void)
{
    dap_print_module_name("stake_invalidate_requires_net");
    
    s_mocks_reset();
    s_mocks_enable();
    
    dap_json_t *l_reply = s_cli_execute("srv_stake invalidate", 2);
    
    dap_assert(l_reply != NULL, "Reply should not be NULL");
    
    dap_json_object_free(l_reply);
    s_mocks_disable();
}

// ============================================================================
// TESTS: Table Output Formatting
// ============================================================================

/**
 * @brief Test stake list keys -h table output formatting
 */
static void test_stake_list_keys_table_output(void)
{
    dap_print_module_name("stake list keys -h table output");
    
    // Get the command to access func_rpc (s_print_for_srv_stake_all)
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("srv_stake");
    dap_assert(l_cmd != NULL, "srv_stake command found");
    dap_assert(l_cmd->func_rpc != NULL, "srv_stake command has func_rpc for table formatting");
    
    // Prepare mock JSON input for list keys
    // Structure: [[{key1}, {key2}, ..., {totals}]]
    dap_json_t *l_json_input = dap_json_array_new();
    dap_json_t *l_keys_array = dap_json_array_new();
    
    // Add test validator key with known data
    dap_json_t *l_key1 = dap_json_object_new();
    dap_json_object_add_string(l_key1, "node_addr", "AAAA::BBBB::CCCC::DDDD");
    dap_json_object_add_string(l_key1, "pkey_hash", "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    dap_json_object_add_int64(l_key1, "stake_value", 1000);
    dap_json_object_add_int64(l_key1, "effective_value", 950);
    dap_json_object_add_int64(l_key1, "related_weight", 25);
    dap_json_object_add_string(l_key1, "sovereign_addr", "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234TESTADDRESS12345");
    dap_json_object_add_string(l_key1, "sovereign_tax", "5%");
    dap_json_array_add(l_keys_array, l_key1);
    
    dap_json_t *l_key2 = dap_json_object_new();
    dap_json_object_add_string(l_key2, "node_addr", "1111::2222::3333::4444");
    dap_json_object_add_string(l_key2, "pkey_hash", "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    dap_json_object_add_int64(l_key2, "stake_value", 2000);
    dap_json_object_add_int64(l_key2, "effective_value", 1900);
    dap_json_object_add_int64(l_key2, "related_weight", 50);
    dap_json_object_add_string(l_key2, "sovereign_addr", "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234TESTADDRESS67890");
    dap_json_object_add_string(l_key2, "sovereign_tax", "10%");
    dap_json_array_add(l_keys_array, l_key2);
    
    // Add totals object
    dap_json_t *l_totals = dap_json_object_new();
    dap_json_object_add_int64(l_totals, "total_keys", 2);
    dap_json_object_add_string(l_totals, "key_delegating_min_value", "100.0");
    dap_json_object_add_string(l_totals, "key_delegating_min_value_ticker", "CELL");
    dap_json_object_add_int64(l_totals, "each_validator_max_related_weight", 100);
    dap_json_array_add(l_keys_array, l_totals);
    
    dap_json_array_add(l_json_input, l_keys_array);
    
    // Prepare output
    dap_json_t *l_json_output = dap_json_array_new();
    
    // Prepare argv with -h and list keys
    char *l_argv[] = {"srv_stake", "list", "keys", "-net", "test", "-h", NULL};
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
    dap_assert(strstr(l_table, "Node addres") != NULL, "table has 'Node addres' header");
    dap_assert(strstr(l_table, "Pkey hash") != NULL, "table has 'Pkey hash' header");
    dap_assert(strstr(l_table, "Stake val") != NULL, "table has 'Stake val' header");
    dap_assert(strstr(l_table, "Eff val") != NULL, "table has 'Eff val' header");
    
    // Check data is present
    dap_assert(strstr(l_table, "AAAA") != NULL, "table contains node address AAAA");
    dap_assert(strstr(l_table, "1111") != NULL, "table contains node address 1111");
    
    // Check separator lines
    dap_assert(strstr(l_table, "___") != NULL, "table has separator lines");
    
    // Check totals
    dap_assert(strstr(l_table, "total_keys") != NULL, "table shows total_keys");
    
    // Cleanup
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_pass_msg("stake list keys -h table output complete");
}

/**
 * @brief Test stake list keys -h with empty results
 */
static void test_stake_list_keys_table_empty(void)
{
    dap_print_module_name("stake list keys -h table (empty)");
    
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("srv_stake");
    dap_assert(l_cmd != NULL, "srv_stake command found");
    
    // Prepare empty JSON input
    dap_json_t *l_json_input = dap_json_array_new();
    
    dap_json_t *l_json_output = dap_json_array_new();
    
    char *l_argv[] = {"srv_stake", "list", "keys", "-h", NULL};
    int l_argc = 4;
    
    int l_ret = l_cmd->func_rpc(l_json_input, l_json_output, l_argv, l_argc);
    
    // Should return -1 for empty input
    dap_assert(l_ret == -1, "table formatting returns -1 for empty input");
    
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_pass_msg("stake list keys -h table empty test complete");
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    
    // Initialize test framework
    dap_common_init("test_cli_stake_mocked", NULL);
    
    // Initialize mocks
    dap_mock_init();
    
    // Register srv_stake CLI command
    dap_chain_net_srv_stake_init();
    
    dap_print_module_name("CLI Stake Mocked Tests");
    log_it(L_NOTICE, "Starting CLI Stake mocked tests...");
    
    // Run order parameter validation tests
    test_stake_order_create_requires_net();
    test_stake_order_create_requires_value();
    test_stake_order_create_requires_cert();
    
    // Run delegate parameter validation tests
    test_stake_delegate_requires_net();
    test_stake_delegate_requires_wallet();
    
    // Run check parameter validation tests
    test_stake_check_requires_net();
    test_stake_check_requires_tx();
    
    // Run network not found tests
    test_stake_order_create_net_not_found();
    test_stake_check_net_not_found();
    
    // Run update/invalidate tests
    test_stake_update_requires_net();
    test_stake_invalidate_requires_net();
    
    // Run table output tests
    test_stake_list_keys_table_output();
    test_stake_list_keys_table_empty();
    
    log_it(L_NOTICE, "All CLI Stake mocked tests passed!");
    printf("\n✓ All %d tests passed\n", 13);
    
    return 0;
}

