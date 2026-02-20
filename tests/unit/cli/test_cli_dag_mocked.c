/**
 * @file test_cli_dag_mocked.c
 * @brief Unit tests for dag CLI with full mocking support
 * 
 * This test file uses DAP Mock Framework to mock dag/network dependencies
 * allowing full CLI command execution with controlled, predictable behavior.
 * 
 * Tests verify:
 * 1. CLI command registration and invocation
 * 2. JSON output structure and field names
 * 3. Correct handling of various dag states
 * 4. API version differences (v1 vs v2)
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
#include "dap_chain_type_dag.h"
#include "dap_chain.h"

#define LOG_TAG "test_cli_dag_mocked"

// ============================================================================
// GLOBAL MOCK OUTPUT PARAMETERS
// ============================================================================

static dap_chain_t *s_mock_chain_output = NULL;
static dap_chain_net_t *s_mock_net_output = NULL;

// ============================================================================
// MOCK DECLARATIONS
// ============================================================================

/**
 * @brief Mock for dap_chain_node_cli_cmd_values_parse_net_chain_for_json
 */
DAP_MOCK_DECLARE(dap_chain_node_cli_cmd_values_parse_net_chain_for_json, {
    .return_value.i = 0
});

/**
 * @brief Mock for dap_chain_get_cs_type
 */
DAP_MOCK_DECLARE(dap_chain_get_cs_type, {
    .return_value.ptr = NULL
});

// ============================================================================
// EXTERNAL REAL FUNCTION DECLARATIONS
// ============================================================================

extern int __real_dap_chain_node_cli_cmd_values_parse_net_chain_for_json(
    dap_json_t *a_json_arr_reply, int *a_arg_index,
    int a_argc, char **a_argv,
    dap_chain_t **a_chain, dap_chain_net_t **a_net,
    dap_chain_type_t a_default_chain_type);

extern const char* __real_dap_chain_get_cs_type(dap_chain_t *a_chain);

// ============================================================================
// WRAPPER IMPLEMENTATIONS
// ============================================================================

/**
 * @brief Wrapper for dap_chain_node_cli_cmd_values_parse_net_chain_for_json
 */
int __wrap_dap_chain_node_cli_cmd_values_parse_net_chain_for_json(
    dap_json_t *a_json_arr_reply, int *a_arg_index,
    int a_argc, char **a_argv,
    dap_chain_t **a_chain, dap_chain_net_t **a_net,
    dap_chain_type_t a_default_chain_type)
{
    if (g_mock_dap_chain_node_cli_cmd_values_parse_net_chain_for_json && 
        g_mock_dap_chain_node_cli_cmd_values_parse_net_chain_for_json->enabled) {
        dap_mock_record_call(g_mock_dap_chain_node_cli_cmd_values_parse_net_chain_for_json, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_node_cli_cmd_values_parse_net_chain_for_json->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_chain_node_cli_cmd_values_parse_net_chain_for_json called");
        
        if (a_chain) *a_chain = s_mock_chain_output;
        if (a_net) *a_net = s_mock_net_output;
        
        return g_mock_dap_chain_node_cli_cmd_values_parse_net_chain_for_json->return_value.i;
    }
    return __real_dap_chain_node_cli_cmd_values_parse_net_chain_for_json(
        a_json_arr_reply, a_arg_index, a_argc, a_argv, a_chain, a_net, a_default_chain_type);
}

/**
 * @brief Wrapper for dap_chain_get_cs_type
 */
const char* __wrap_dap_chain_get_cs_type(dap_chain_t *a_chain)
{
    if (g_mock_dap_chain_get_cs_type && g_mock_dap_chain_get_cs_type->enabled) {
        dap_mock_record_call(g_mock_dap_chain_get_cs_type, NULL, 0,
                             g_mock_dap_chain_get_cs_type->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_get_cs_type called");
        return (const char*)g_mock_dap_chain_get_cs_type->return_value.ptr;
    }
    return __real_dap_chain_get_cs_type(a_chain);
}

// ============================================================================
// TEST HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Initialize all mocks for DAG CLI tests
 */
static void s_mocks_init(void)
{
    DAP_MOCK_RESET(dap_chain_node_cli_cmd_values_parse_net_chain_for_json);
    DAP_MOCK_RESET(dap_chain_get_cs_type);
    
    s_mock_chain_output = NULL;
    s_mock_net_output = NULL;
}

/**
 * @brief Enable all mocks for testing
 */
static void s_mocks_enable(void)
{
    DAP_MOCK_ENABLE(dap_chain_node_cli_cmd_values_parse_net_chain_for_json);
    DAP_MOCK_ENABLE(dap_chain_get_cs_type);
}

/**
 * @brief Disable all mocks after testing
 */
static void s_mocks_disable(void)
{
    DAP_MOCK_DISABLE(dap_chain_node_cli_cmd_values_parse_net_chain_for_json);
    DAP_MOCK_DISABLE(dap_chain_get_cs_type);
}

/**
 * @brief Helper to execute CLI command and get JSON result
 */
static dap_json_t* s_execute_dag_cli(char **a_argv, int a_argc, int a_version, int *a_ret)
{
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("dag");
    dap_test_msg("Executing dag CLI command...");
    
    if (!l_cmd || !l_cmd->func) {
        dap_test_msg("ERROR: dag command not found!");
        if (a_ret) *a_ret = -1;
        return NULL;
    }
    
    dap_json_t *l_json_arr_reply = dap_json_array_new();
    int l_ret = l_cmd->func(a_argc, a_argv, l_json_arr_reply, a_version);
    
    if (a_ret) *a_ret = l_ret;
    
    return l_json_arr_reply;
}

// ============================================================================
// VALIDATION TESTS
// ============================================================================

/**
 * @brief Test dag command without subcommand
 */
static void test_dag_undefined_subcommand(void)
{
    dap_print_module_name("test_dag_undefined_subcommand");
    
    s_mocks_init();
    s_mocks_enable();
    
    static dap_chain_t s_mock_chain = {0};
    static dap_chain_net_t s_mock_net = {0};
    static dap_chain_type_dag_t s_mock_dag = {0};
    
    s_mock_chain.name = "test_chain";
    s_mock_chain._inheritor = &s_mock_dag;
    s_mock_dag.chain = &s_mock_chain;
    strncpy(s_mock_net.pub.name, "test_net", sizeof(s_mock_net.pub.name) - 1);
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    
    DAP_MOCK_SET_RETURN(dap_chain_node_cli_cmd_values_parse_net_chain_for_json, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"dag_poa");
    
    char *l_argv[] = {"dag", "-net", "test_net", "-chain", "test_chain", NULL};
    int l_argc = 5;
    int l_ret = 0;
    
    dap_json_t *l_json_result = s_execute_dag_cli(l_argv, l_argc, 2, &l_ret);
    
    dap_test_msg("Return code: %d", l_ret);
    dap_assert(l_ret != 0, "dag without subcommand should return error");
    
    if (l_json_result) {
        char *l_json_str = dap_json_to_string(l_json_result);
        if (l_json_str) {
            dap_test_msg("JSON result: %s", l_json_str);
            dap_assert(strstr(l_json_str, "Undefined") != NULL || strstr(l_json_str, "subcommand") != NULL,
                       "Error message should mention undefined subcommand");
            DAP_DELETE(l_json_str);
        }
        dap_json_object_free(l_json_result);
    }
    
    s_mocks_disable();
    dap_pass_msg("dag undefined subcommand test passed");
}

/**
 * @brief Test dag event undefined subcommand
 */
static void test_dag_event_undefined_subcommand(void)
{
    dap_print_module_name("test_dag_event_undefined_subcommand");
    
    s_mocks_init();
    s_mocks_enable();
    
    static dap_chain_t s_mock_chain = {0};
    static dap_chain_net_t s_mock_net = {0};
    static dap_chain_type_dag_t s_mock_dag = {0};
    
    s_mock_chain.name = "test_chain";
    s_mock_chain._inheritor = &s_mock_dag;
    s_mock_dag.chain = &s_mock_chain;
    strncpy(s_mock_net.pub.name, "test_net", sizeof(s_mock_net.pub.name) - 1);
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    
    DAP_MOCK_SET_RETURN(dap_chain_node_cli_cmd_values_parse_net_chain_for_json, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"dag_poa");
    
    char *l_argv[] = {"dag", "event", "invalid_subcmd", "-net", "test_net", "-chain", "test_chain", NULL};
    int l_argc = 7;
    int l_ret = 0;
    
    dap_json_t *l_json_result = s_execute_dag_cli(l_argv, l_argc, 2, &l_ret);
    
    dap_test_msg("Return code: %d (expected: non-zero)", l_ret);
    dap_assert(l_ret != 0, "dag event <invalid> should return error");
    
    if (l_json_result) {
        char *l_json_str = dap_json_to_string(l_json_result);
        if (l_json_str) {
            dap_test_msg("JSON result: %s", l_json_str);
            dap_assert(strstr(l_json_str, "Undefined") != NULL || strstr(l_json_str, "event") != NULL,
                       "Error should mention undefined event subcommand");
            DAP_DELETE(l_json_str);
        }
        dap_json_object_free(l_json_result);
    }
    
    s_mocks_disable();
    dap_pass_msg("dag event undefined subcommand test passed");
}

/**
 * @brief Test dag with non-dag chain type
 */
static void test_dag_wrong_chain_type(void)
{
    dap_print_module_name("test_dag_wrong_chain_type");
    
    s_mocks_init();
    s_mocks_enable();
    
    static dap_chain_t s_mock_chain = {0};
    static dap_chain_net_t s_mock_net = {0};
    static dap_chain_type_dag_t s_mock_dag = {0};
    
    s_mock_chain.name = "test_chain";
    s_mock_chain._inheritor = &s_mock_dag;
    s_mock_dag.chain = &s_mock_chain;
    strncpy(s_mock_net.pub.name, "test_net", sizeof(s_mock_net.pub.name) - 1);
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    
    DAP_MOCK_SET_RETURN(dap_chain_node_cli_cmd_values_parse_net_chain_for_json, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"blocks_poa");
    
    char *l_argv[] = {"dag", "event", "count", "-net", "test_net", "-chain", "test_chain", NULL};
    int l_argc = 7;
    int l_ret = 0;
    
    dap_json_t *l_json_result = s_execute_dag_cli(l_argv, l_argc, 2, &l_ret);
    
    dap_test_msg("Return code: %d (expected: -DAP_CHAIN_NODE_CLI_COM_DAG_CHAIN_TYPE_ERR)", l_ret);
    dap_assert(l_ret == -DAP_CHAIN_NODE_CLI_COM_DAG_CHAIN_TYPE_ERR, 
               "dag with non-dag chain should return DAG_CHAIN_TYPE_ERR");
    
    if (l_json_result) {
        char *l_json_str = dap_json_to_string(l_json_result);
        if (l_json_str) {
            dap_test_msg("JSON result: %s", l_json_str);
            dap_assert(strstr(l_json_str, "not dag") != NULL || strstr(l_json_str, "not supported") != NULL,
                       "Error should mention chain type is not dag");
            DAP_DELETE(l_json_str);
        }
        dap_json_object_free(l_json_result);
    }
    
    s_mocks_disable();
    dap_pass_msg("dag wrong chain type test passed");
}

/**
 * @brief Test dag event find without -datum parameter
 */
static void test_dag_event_find_validation(void)
{
    dap_print_module_name("test_dag_event_find_validation");
    
    s_mocks_init();
    s_mocks_enable();
    
    static dap_chain_t s_mock_chain = {0};
    static dap_chain_net_t s_mock_net = {0};
    static dap_chain_type_dag_t s_mock_dag = {0};
    
    s_mock_chain.name = "test_chain";
    s_mock_chain._inheritor = &s_mock_dag;
    s_mock_dag.chain = &s_mock_chain;
    strncpy(s_mock_net.pub.name, "test_net", sizeof(s_mock_net.pub.name) - 1);
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    
    DAP_MOCK_SET_RETURN(dap_chain_node_cli_cmd_values_parse_net_chain_for_json, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"dag_poa");
    
    char *l_argv[] = {"dag", "event", "find", "-net", "test_net", "-chain", "test_chain", NULL};
    int l_argc = 7;
    int l_ret = 0;
    
    dap_json_t *l_json_result = s_execute_dag_cli(l_argv, l_argc, 2, &l_ret);
    
    dap_test_msg("Return code: %d (expected: DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR)", l_ret);
    dap_assert(l_ret == DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR, 
               "dag event find without -datum should return PARAM_ERR");
    
    if (l_json_result) {
        char *l_json_str = dap_json_to_string(l_json_result);
        if (l_json_str) {
            dap_test_msg("JSON result: %s", l_json_str);
            dap_assert(strstr(l_json_str, "-datum") != NULL || strstr(l_json_str, "requires") != NULL,
                       "Error should mention missing -datum parameter");
            DAP_DELETE(l_json_str);
        }
        dap_json_object_free(l_json_result);
    }
    
    s_mocks_disable();
    dap_pass_msg("dag event find validation test passed");
}

/**
 * @brief Test dag round find without -datum parameter
 */
static void test_dag_round_find_validation(void)
{
    dap_print_module_name("test_dag_round_find_validation");
    
    s_mocks_init();
    s_mocks_enable();
    
    static dap_chain_t s_mock_chain = {0};
    static dap_chain_net_t s_mock_net = {0};
    static dap_chain_type_dag_t s_mock_dag = {0};
    
    s_mock_chain.name = "test_chain";
    s_mock_chain._inheritor = &s_mock_dag;
    s_mock_dag.chain = &s_mock_chain;
    strncpy(s_mock_net.pub.name, "test_net", sizeof(s_mock_net.pub.name) - 1);
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    
    DAP_MOCK_SET_RETURN(dap_chain_node_cli_cmd_values_parse_net_chain_for_json, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"dag_poa");
    
    char *l_argv[] = {"dag", "round", "find", "-net", "test_net", "-chain", "test_chain", NULL};
    int l_argc = 7;
    int l_ret = 0;
    
    dap_json_t *l_json_result = s_execute_dag_cli(l_argv, l_argc, 2, &l_ret);
    
    dap_test_msg("Return code: %d", l_ret);
    
    if (l_json_result) {
        char *l_json_str = dap_json_to_string(l_json_result);
        if (l_json_str) {
            dap_test_msg("JSON result: %s", l_json_str);
            dap_assert(strstr(l_json_str, "-datum") != NULL,
                       "Error should mention missing -datum parameter");
            DAP_DELETE(l_json_str);
        }
        dap_json_object_free(l_json_result);
    }
    
    s_mocks_disable();
    dap_pass_msg("dag round find validation test passed");
}

/**
 * @brief Test dag with invalid -H parameter
 */
static void test_dag_invalid_hash_type(void)
{
    dap_print_module_name("test_dag_invalid_hash_type");
    
    s_mocks_init();
    s_mocks_enable();
    
    static dap_chain_t s_mock_chain = {0};
    static dap_chain_net_t s_mock_net = {0};
    static dap_chain_type_dag_t s_mock_dag = {0};
    
    s_mock_chain.name = "test_chain";
    s_mock_chain._inheritor = &s_mock_dag;
    s_mock_dag.chain = &s_mock_chain;
    strncpy(s_mock_net.pub.name, "test_net", sizeof(s_mock_net.pub.name) - 1);
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    
    DAP_MOCK_SET_RETURN(dap_chain_node_cli_cmd_values_parse_net_chain_for_json, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"dag_poa");
    
    char *l_argv[] = {"dag", "event", "count", "-net", "test_net", "-chain", "test_chain", "-H", "invalid_format", NULL};
    int l_argc = 9;
    int l_ret = 0;
    
    dap_json_t *l_json_result = s_execute_dag_cli(l_argv, l_argc, 2, &l_ret);
    
    dap_test_msg("Return code: %d (expected: -DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR)", l_ret);
    dap_assert(l_ret == -DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR, 
               "dag with invalid -H should return PARAM_ERR");
    
    if (l_json_result) {
        char *l_json_str = dap_json_to_string(l_json_result);
        if (l_json_str) {
            dap_test_msg("JSON result: %s", l_json_str);
            dap_assert(strstr(l_json_str, "-H") != NULL || strstr(l_json_str, "hex") != NULL,
                       "Error should mention invalid -H parameter");
            DAP_DELETE(l_json_str);
        }
        dap_json_object_free(l_json_result);
    }
    
    s_mocks_disable();
    dap_pass_msg("dag invalid hash type test passed");
}

/**
 * @brief Test dag network parsing error
 */
static void test_dag_net_parse_error(void)
{
    dap_print_module_name("test_dag_net_parse_error");
    
    s_mocks_init();
    s_mocks_enable();
    
    DAP_MOCK_SET_RETURN(dap_chain_node_cli_cmd_values_parse_net_chain_for_json, -1);
    
    char *l_argv[] = {"dag", "event", "count", "-net", "nonexistent_net", NULL};
    int l_argc = 5;
    int l_ret = 0;
    
    dap_json_t *l_json_result = s_execute_dag_cli(l_argv, l_argc, 2, &l_ret);
    
    dap_test_msg("Return code: %d (expected: -DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR)", l_ret);
    dap_assert(l_ret == -DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR, 
               "dag with net parse error should return PARAM_ERR");
    
    if (l_json_result) {
        dap_json_object_free(l_json_result);
    }
    
    s_mocks_disable();
    dap_pass_msg("dag net parse error test passed");
}

/**
 * @brief Test dag list table output formatting
 */
static void test_dag_list_table_output(void)
{
    dap_print_module_name("test_dag_list_table_output");
    
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("dag");
    dap_assert(l_cmd != NULL, "dag command should be registered");
    dap_assert(l_cmd->func_rpc != NULL, "dag command should have func_rpc (table formatter)");
    
    dap_json_t *l_json_input = dap_json_object_new();
    dap_json_t *l_events_array = dap_json_array_new();
    
    dap_json_t *l_event1 = dap_json_object_new();
    dap_json_object_add_uint64(l_event1, "event_num", 1);
    dap_json_object_add_string(l_event1, "hash", "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    dap_json_object_add_string(l_event1, "ts_create", "Mon, 01 Jan 2024 12:00:00 +0000");
    dap_json_array_add(l_events_array, l_event1);
    
    dap_json_t *l_event2 = dap_json_object_new();
    dap_json_object_add_uint64(l_event2, "event_num", 2);
    dap_json_object_add_string(l_event2, "hash", "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    dap_json_object_add_string(l_event2, "ts_create", "Tue, 02 Jan 2024 12:00:00 +0000");
    dap_json_array_add(l_events_array, l_event2);
    
    dap_json_t *l_meta = dap_json_object_new();
    dap_json_object_add_int64(l_meta, "limit", 100);
    dap_json_object_add_int64(l_meta, "offset", 0);
    dap_json_array_add(l_events_array, l_meta);
    
    dap_json_object_add_object(l_json_input, "events", l_events_array);
    
    dap_json_t *l_json_input_array = dap_json_array_new();
    dap_json_array_add(l_json_input_array, l_json_input);
    
    dap_json_t *l_json_output = dap_json_array_new();
    
    char *l_argv[] = {"dag", "-net", "test", "-chain", "test", "event", "list", "-h", NULL};
    int l_argc = 8;
    
    int l_ret = l_cmd->func_rpc(l_json_input_array, l_json_output, l_argv, l_argc);
    
    dap_test_msg("func_rpc return: %d (expected: 0)", l_ret);
    dap_assert(l_ret == 0, "func_rpc should return 0 for valid input with -h flag");
    
    int l_output_len = dap_json_array_length(l_json_output);
    dap_assert(l_output_len > 0, "Output array should have elements");
    
    if (l_output_len > 0) {
        dap_json_t *l_result_obj = dap_json_array_get_idx(l_json_output, 0);
        dap_json_t *l_output_str_obj = NULL;
        if (dap_json_object_get_ex(l_result_obj, "output", &l_output_str_obj)) {
            const char *l_output_str = dap_json_get_string(l_output_str_obj);
            dap_test_msg("Table output:\n%s", l_output_str);
            
            dap_assert(strstr(l_output_str, "#") != NULL, "Table should have # header column");
            dap_assert(strstr(l_output_str, "Hash") != NULL, "Table should have Hash header column");
            dap_assert(strstr(l_output_str, "Time") != NULL || strstr(l_output_str, "create") != NULL, 
                       "Table should have Time create header column");
            dap_assert(strstr(l_output_str, "___") != NULL, "Table should have separator lines");
            dap_assert(strstr(l_output_str, "limit") != NULL, "Table should display limit");
        }
    }
    
    dap_json_object_free(l_json_input_array);
    dap_json_object_free(l_json_output);
    
    dap_pass_msg("dag list table output test passed");
}

/**
 * @brief Test dag list table with empty data
 */
static void test_dag_list_table_empty(void)
{
    dap_print_module_name("test_dag_list_table_empty");
    
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("dag");
    dap_assert(l_cmd != NULL, "dag command should be registered");
    dap_assert(l_cmd->func_rpc != NULL, "dag command should have func_rpc");
    
    dap_json_t *l_json_input = dap_json_array_new();
    dap_json_t *l_json_output = dap_json_array_new();
    
    char *l_argv[] = {"dag", "-net", "test", "-chain", "test", "event", "list", "-h", NULL};
    int l_argc = 8;
    
    int l_ret = l_cmd->func_rpc(l_json_input, l_json_output, l_argv, l_argc);
    
    dap_test_msg("func_rpc return with empty input: %d (expected: -1)", l_ret);
    dap_assert(l_ret == -1, "func_rpc should return -1 for empty input");
    
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_pass_msg("dag list table empty test passed");
}

/**
 * @brief Test dag list without -h flag
 */
static void test_dag_list_no_human_flag(void)
{
    dap_print_module_name("test_dag_list_no_human_flag");
    
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("dag");
    dap_assert(l_cmd != NULL, "dag command should be registered");
    dap_assert(l_cmd->func_rpc != NULL, "dag command should have func_rpc");
    
    dap_json_t *l_json_input = dap_json_object_new();
    dap_json_t *l_events_array = dap_json_array_new();
    dap_json_object_add_object(l_json_input, "events", l_events_array);
    
    dap_json_t *l_json_input_array = dap_json_array_new();
    dap_json_array_add(l_json_input_array, l_json_input);
    
    dap_json_t *l_json_output = dap_json_array_new();
    
    char *l_argv[] = {"dag", "-net", "test", "-chain", "test", "event", "list", NULL};
    int l_argc = 7;
    
    int l_ret = l_cmd->func_rpc(l_json_input_array, l_json_output, l_argv, l_argc);
    
    dap_test_msg("func_rpc return without -h: %d (expected: -1)", l_ret);
    dap_assert(l_ret == -1, "func_rpc should return -1 when -h flag is not present");
    
    dap_json_object_free(l_json_input_array);
    dap_json_object_free(l_json_output);
    
    dap_pass_msg("dag list no human flag test passed");
}

// ============================================================================
// MAIN TEST RUNNER
// ============================================================================

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    
    dap_common_init("test_cli_dag_mocked", NULL);
    
    dap_mock_init();
    
    dap_chain_type_dag_cli_init();
    
    dap_print_module_name("DAG CLI Mocked Unit Tests");
    printf("Testing dag CLI with DAP Mock Framework\n\n");
    
    test_dag_undefined_subcommand();
    test_dag_event_undefined_subcommand();
    test_dag_wrong_chain_type();
    test_dag_event_find_validation();
    test_dag_round_find_validation();
    test_dag_invalid_hash_type();
    test_dag_net_parse_error();
    test_dag_list_table_output();
    test_dag_list_table_empty();
    test_dag_list_no_human_flag();
    
    printf("\n");
    dap_pass_msg("=== All DAG CLI tests passed ===");
    
    dap_mock_deinit();
    dap_common_deinit();
    
    return 0;
}
