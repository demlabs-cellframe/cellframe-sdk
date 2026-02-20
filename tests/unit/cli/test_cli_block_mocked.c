/**
 * @file test_cli_block_mocked.c
 * @brief Unit tests for block CLI with full mocking support
 * 
 * This test file uses DAP Mock Framework to mock block/network dependencies
 * allowing full CLI command execution with controlled, predictable behavior.
 * 
 * Tests verify:
 * 1. CLI command registration and invocation
 * 2. JSON output structure and field names
 * 3. Correct handling of various block states
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
#include "dap_chain_type_blocks.h"
#include "dap_chain_block_cache.h"
#include "dap_chain_net.h"
#include "dap_chain.h"

#define LOG_TAG "test_cli_block_mocked"

// ============================================================================
// GLOBAL MOCK OUTPUT PARAMETERS
// ============================================================================

static dap_chain_t *s_mock_chain_output = NULL;
static dap_chain_net_t *s_mock_net_output = NULL;

// ============================================================================
// MOCK DECLARATIONS
// ============================================================================

// Network parsing mock
DAP_MOCK_DECLARE(dap_chain_net_parse_net_chain, {
    .return_value.i = 0
});

// Network by name mock
DAP_MOCK_DECLARE(dap_chain_net_by_name, {
    .return_value.ptr = NULL
});

// Chain get CS type mock
DAP_MOCK_DECLARE(dap_chain_get_cs_type, {
    .return_value.ptr = NULL
});

// Block cache get by hash wrapper mock
DAP_MOCK_DECLARE(dap_chain_block_cache_get_by_hash_w, {
    .return_value.ptr = NULL
});

// Block cache get by number wrapper mock
DAP_MOCK_DECLARE(dap_chain_block_cache_get_by_number_w, {
    .return_value.ptr = NULL
});

// Hash from string mock
DAP_MOCK_DECLARE(dap_chain_hash_fast_from_str, {
    .return_value.i = 0
});

// Block count wrapper mock
DAP_MOCK_DECLARE(dap_chain_type_blocks_get_count_w, {
    .return_value.u64 = 0
});

// Get last block wrapper mock
DAP_MOCK_DECLARE(dap_chain_type_blocks_get_last_w, {
    .return_value.ptr = NULL
});

// ============================================================================
// EXTERNAL REAL FUNCTION DECLARATIONS
// ============================================================================

extern int __real_dap_chain_net_parse_net_chain(dap_json_t *a_json_arr_reply, int *a_arg_index, 
                                                  int a_argc, char **a_argv, 
                                                  dap_chain_t **a_chain, dap_chain_net_t **a_net, 
                                                  dap_chain_type_t a_default_type);
extern dap_chain_net_t* __real_dap_chain_net_by_name(const char *a_name);
extern const char* __real_dap_chain_get_cs_type(dap_chain_t *a_chain);
extern dap_chain_block_cache_t* __real_dap_chain_block_cache_get_by_hash_w(dap_chain_type_blocks_t *a_blocks, 
                                                                          dap_chain_hash_fast_t *a_block_hash);
extern dap_chain_block_cache_t* __real_dap_chain_block_cache_get_by_number_w(dap_chain_type_blocks_t *a_blocks, 
                                                                            uint64_t a_block_number);
extern int __real_dap_chain_hash_fast_from_str(const char *a_str, dap_chain_hash_fast_t *a_hash);
extern uint64_t __real_dap_chain_type_blocks_get_count_w(dap_chain_type_blocks_t *a_blocks);
extern dap_chain_block_cache_t* __real_dap_chain_type_blocks_get_last_w(dap_chain_type_blocks_t *a_blocks);

// ============================================================================
// WRAPPER IMPLEMENTATIONS
// ============================================================================

/**
 * @brief Wrapper for dap_chain_net_parse_net_chain
 */
int __wrap_dap_chain_net_parse_net_chain(dap_json_t *a_json_arr_reply, int *a_arg_index, 
                                          int a_argc, char **a_argv, 
                                          dap_chain_t **a_chain, dap_chain_net_t **a_net, 
                                          dap_chain_type_t a_default_type)
{
    if (g_mock_dap_chain_net_parse_net_chain && g_mock_dap_chain_net_parse_net_chain->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_parse_net_chain, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_net_parse_net_chain->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_chain_net_parse_net_chain called");
        
        // Set output parameters from global mock variables
        if (a_chain) *a_chain = s_mock_chain_output;
        if (a_net) *a_net = s_mock_net_output;
        
        return g_mock_dap_chain_net_parse_net_chain->return_value.i;
    }
    return __real_dap_chain_net_parse_net_chain(a_json_arr_reply, a_arg_index, a_argc, a_argv, 
                                                  a_chain, a_net, a_default_type);
}

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

/**
 * @brief Wrapper for dap_chain_block_cache_get_by_hash_w
 */
dap_chain_block_cache_t* __wrap_dap_chain_block_cache_get_by_hash_w(dap_chain_type_blocks_t *a_blocks, 
                                                                   dap_chain_hash_fast_t *a_block_hash)
{
    if (g_mock_dap_chain_block_cache_get_by_hash_w && g_mock_dap_chain_block_cache_get_by_hash_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_block_cache_get_by_hash_w, NULL, 0,
                             g_mock_dap_chain_block_cache_get_by_hash_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_block_cache_get_by_hash_w called");
        return (dap_chain_block_cache_t*)g_mock_dap_chain_block_cache_get_by_hash_w->return_value.ptr;
    }
    return __real_dap_chain_block_cache_get_by_hash_w(a_blocks, a_block_hash);
}

/**
 * @brief Wrapper for dap_chain_block_cache_get_by_number_w
 */
dap_chain_block_cache_t* __wrap_dap_chain_block_cache_get_by_number_w(dap_chain_type_blocks_t *a_blocks, 
                                                                     uint64_t a_block_number)
{
    if (g_mock_dap_chain_block_cache_get_by_number_w && g_mock_dap_chain_block_cache_get_by_number_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_block_cache_get_by_number_w, NULL, 0,
                             g_mock_dap_chain_block_cache_get_by_number_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_block_cache_get_by_number_w(num=%"DAP_UINT64_FORMAT_U") called", a_block_number);
        return (dap_chain_block_cache_t*)g_mock_dap_chain_block_cache_get_by_number_w->return_value.ptr;
    }
    return __real_dap_chain_block_cache_get_by_number_w(a_blocks, a_block_number);
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
 * @brief Wrapper for dap_chain_type_blocks_get_count_w
 */
uint64_t __wrap_dap_chain_type_blocks_get_count_w(dap_chain_type_blocks_t *a_blocks)
{
    (void)a_blocks;
    if (g_mock_dap_chain_type_blocks_get_count_w && g_mock_dap_chain_type_blocks_get_count_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_type_blocks_get_count_w, NULL, 0,
                             (void*)(uintptr_t)g_mock_dap_chain_type_blocks_get_count_w->return_value.u64);
        log_it(L_DEBUG, "MOCK: dap_chain_type_blocks_get_count_w called, returning %"DAP_UINT64_FORMAT_U"",
               g_mock_dap_chain_type_blocks_get_count_w->return_value.u64);
        return g_mock_dap_chain_type_blocks_get_count_w->return_value.u64;
    }
    return __real_dap_chain_type_blocks_get_count_w(a_blocks);
}

/**
 * @brief Wrapper for dap_chain_type_blocks_get_last_w
 */
dap_chain_block_cache_t* __wrap_dap_chain_type_blocks_get_last_w(dap_chain_type_blocks_t *a_blocks)
{
    (void)a_blocks;
    if (g_mock_dap_chain_type_blocks_get_last_w && g_mock_dap_chain_type_blocks_get_last_w->enabled) {
        dap_mock_record_call(g_mock_dap_chain_type_blocks_get_last_w, NULL, 0,
                             g_mock_dap_chain_type_blocks_get_last_w->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_type_blocks_get_last_w called");
        return (dap_chain_block_cache_t*)g_mock_dap_chain_type_blocks_get_last_w->return_value.ptr;
    }
    return __real_dap_chain_type_blocks_get_last_w(a_blocks);
}

// ============================================================================
// MOCK NETWORK/CHAIN STRUCTURES
// ============================================================================

static dap_chain_net_t s_mock_net = {
    .pub = {
        .name = "test_net",
        .id = { .uint64 = 0x0102030405060708 }
    }
};

static dap_chain_t s_mock_chain;
static dap_chain_type_blocks_t s_mock_blocks;
static dap_chain_block_cache_t s_mock_block_cache;

/**
 * @brief Initialize mock chain and blocks structures
 */
static void s_init_mock_structures(void)
{
    memset(&s_mock_chain, 0, sizeof(s_mock_chain));
    memset(&s_mock_blocks, 0, sizeof(s_mock_blocks));
    memset(&s_mock_block_cache, 0, sizeof(s_mock_block_cache));
    
    s_mock_chain.name = "test_chain";
    s_mock_chain._inheritor = &s_mock_blocks;
    s_mock_blocks.chain = &s_mock_chain;
    
    // Initialize mock block cache
    s_mock_block_cache.block_number = 42;
    strncpy(s_mock_block_cache.block_hash_str, "0xABCDEF1234567890", sizeof(s_mock_block_cache.block_hash_str) - 1);
    s_mock_block_cache.ts_created = 1700000000;  // Some timestamp
    s_mock_block_cache.datum_count = 5;
    s_mock_block_cache.sign_count = 3;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Reset all mocks to default state
 */
static void s_reset_mocks(void)
{
    DAP_MOCK_RESET(dap_chain_net_parse_net_chain);
    DAP_MOCK_RESET(dap_chain_net_by_name);
    DAP_MOCK_RESET(dap_chain_get_cs_type);
    DAP_MOCK_RESET(dap_chain_block_cache_get_by_hash_w);
    DAP_MOCK_RESET(dap_chain_block_cache_get_by_number_w);
    DAP_MOCK_RESET(dap_chain_hash_fast_from_str);
    DAP_MOCK_RESET(dap_chain_type_blocks_get_count_w);
    DAP_MOCK_RESET(dap_chain_type_blocks_get_last_w);
    
    DAP_MOCK_ENABLE(dap_chain_net_parse_net_chain);
    DAP_MOCK_ENABLE(dap_chain_net_by_name);
    DAP_MOCK_ENABLE(dap_chain_get_cs_type);
    DAP_MOCK_ENABLE(dap_chain_block_cache_get_by_hash_w);
    DAP_MOCK_ENABLE(dap_chain_block_cache_get_by_number_w);
    DAP_MOCK_ENABLE(dap_chain_hash_fast_from_str);
    DAP_MOCK_ENABLE(dap_chain_type_blocks_get_count_w);
    DAP_MOCK_ENABLE(dap_chain_type_blocks_get_last_w);
}

/**
 * @brief Execute CLI command via registered handler
 */
static int s_execute_cli_command(const char *a_cmd, int a_argc, char **a_argv, 
                                  dap_json_t *a_json_reply, int a_version)
{
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find(a_cmd);
    if (!l_cmd) {
        log_it(L_ERROR, "Command '%s' not found", a_cmd);
        return -1;
    }
    
    return l_cmd->func(a_argc, a_argv, a_json_reply, a_version);
}

// ============================================================================
// TESTS
// ============================================================================

/**
 * @brief Test block dump CLI command - validation tests
 */
static void test_block_dump_cli_validation(void)
{
    dap_print_module_name("block dump CLI (validation)");
    
    // Setup mocks
    s_reset_mocks();
    
    // Test 1: dump without -hash or -num (should fail)
    {
        // Setup mock output for net/chain parse
        s_mock_chain_output = &s_mock_chain;
        s_mock_net_output = &s_mock_net;
        DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
        DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
        
        char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "dump", NULL};
        int l_argc = 6;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "block dump (no hash/num) returned: %d", l_ret);
        dap_assert(l_ret != 0, "block dump without -hash or -num returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "hash") != NULL || strstr(l_json_str, "number") != NULL,
                   "error mentions hash or number");
        
        dap_json_object_free(l_json_reply);
    }
    
    // Test 2: dump with invalid -H parameter (should fail)
    {
        s_mock_chain_output = &s_mock_chain;
        s_mock_net_output = &s_mock_net;
        DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
        DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
        
        char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "dump", 
                          "-H", "invalid", "-hash", "somehash", NULL};
        int l_argc = 10;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "block dump (invalid -H) returned: %d", l_ret);
        dap_assert(l_ret != 0, "block dump with invalid -H returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "-H") != NULL || strstr(l_json_str, "hex") != NULL,
                   "error mentions -H parameter");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("block dump CLI validation complete");
}

/**
 * @brief Test block dump CLI command - block not found by hash
 */
static void test_block_dump_cli_not_found(void)
{
    dap_print_module_name("block dump CLI (not found by hash)");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    DAP_MOCK_SET_RETURN(dap_chain_hash_fast_from_str, 0);
    DAP_MOCK_SET_RETURN(dap_chain_block_cache_get_by_hash_w, (intptr_t)NULL);
    
    char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "dump", 
                      "-hash", "0x1234567890abcdef", NULL};
    int l_argc = 8;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block dump (not found) returned: %d", l_ret);
    dap_assert(l_ret != 0, "block dump returns error when block not found");
    
    const char *l_json_str = dap_json_to_string(l_json_reply);
    dap_assert(l_json_str != NULL, "JSON response exists");
    dap_assert(strstr(l_json_str, "find") != NULL || strstr(l_json_str, "Can't") != NULL,
               "error mentions can't find block");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block dump CLI (not found by hash) complete");
}

/**
 * @brief Test block dump CLI command - block not found by number
 */
static void test_block_dump_cli_by_number_not_found(void)
{
    dap_print_module_name("block dump CLI (not found by number)");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    DAP_MOCK_SET_RETURN(dap_chain_block_cache_get_by_number_w, (intptr_t)NULL);
    
    char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "dump", 
                      "-num", "12345", NULL};
    int l_argc = 8;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block dump (not found by number) returned: %d", l_ret);
    dap_assert(l_ret != 0, "block dump returns error when block not found by number");
    
    const char *l_json_str = dap_json_to_string(l_json_reply);
    dap_assert(l_json_str != NULL, "JSON response exists");
    dap_assert(strstr(l_json_str, "find") != NULL || strstr(l_json_str, "Can't") != NULL,
               "error mentions can't find block");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block dump CLI (not found by number) complete");
}

/**
 * @brief Test block dump CLI command - wrong chain type
 */
static void test_block_dump_cli_wrong_chain_type(void)
{
    dap_print_module_name("block dump CLI (wrong chain type)");
    
    // Setup mocks
    s_reset_mocks();
    
    // Setup mock output for net/chain parse
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    // Return non-block chain type
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"dag_poa");
    
    char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "dump", 
                      "-hash", "somehash", NULL};
    int l_argc = 8;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block dump (wrong chain type) returned: %d", l_ret);
    dap_assert(l_ret != 0, "block dump returns error for wrong chain type");
    
    const char *l_json_str = dap_json_to_string(l_json_reply);
    dap_assert(l_json_str != NULL, "JSON response exists");
    dap_assert(strstr(l_json_str, "block") != NULL || strstr(l_json_str, "type") != NULL,
               "error mentions chain type");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block dump CLI (wrong chain type) complete");
}

/**
 * @brief Test block list CLI command - validation
 */
static void test_block_list_cli_validation(void)
{
    dap_print_module_name("block list CLI (validation)");
    
    // Setup mocks
    s_reset_mocks();
    
    // Setup mock output for net/chain parse
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    
    // Test: list signed + first_signed at same time (should fail)
    {
        char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "list", 
                          "signed", "first_signed", NULL};
        int l_argc = 8;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "block list (signed + first_signed) returned: %d", l_ret);
        dap_assert(l_ret != 0, "block list with both signed options returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "signed") != NULL || strstr(l_json_str, "Choose") != NULL,
                   "error mentions signed options");
        
        dap_json_object_free(l_json_reply);
    }
    
    // Test: list signed without -cert or -pkey_hash (should fail)
    {
        char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "list", 
                          "signed", NULL};
        int l_argc = 7;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "block list (signed without cert) returned: %d", l_ret);
        dap_assert(l_ret != 0, "block list signed without -cert returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "-cert") != NULL || strstr(l_json_str, "pkey_hash") != NULL,
                   "error mentions -cert or pkey_hash");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("block list CLI validation complete");
}

/**
 * @brief Test block net parse failure
 */
static void test_block_net_parse_failure(void)
{
    dap_print_module_name("block CLI (net parse failure)");
    
    // Setup mocks
    s_reset_mocks();
    
    // Return error from net parse
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, -DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR);
    
    char *l_argv[] = {"block", "-net", "nonexistent_net", "dump", "-hash", "somehash", NULL};
    int l_argc = 6;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block (net parse failure) returned: %d", l_ret);
    dap_assert(l_ret != 0, "block command returns error on net parse failure");
    
    // Verify mock was called
    int l_parse_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_net_parse_net_chain);
    log_it(L_DEBUG, "dap_chain_net_parse_net_chain call count: %d", l_parse_calls);
    dap_assert(l_parse_calls == 1, "net parse was called");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block CLI (net parse failure) complete");
}

/**
 * @brief Test block count CLI command
 */
static void test_block_count_cli(void)
{
    dap_print_module_name("block count CLI");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    g_mock_dap_chain_type_blocks_get_count_w->return_value.u64 = 12345;
    
    char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "count", NULL};
    int l_argc = 6;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block count returned: %d", l_ret);
    dap_assert(l_ret == 0, "block count returns success");
    
    const char *l_json_str = dap_json_to_string(l_json_reply);
    log_it(L_DEBUG, "block count JSON: %s", l_json_str ? l_json_str : "(null)");
    dap_assert(l_json_str != NULL, "JSON response exists");
    dap_assert(strstr(l_json_str, "12345") != NULL, "response contains block count");
    
    // Verify mock was called
    int l_count_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_type_blocks_get_count_w);
    dap_assert(l_count_calls == 1, "get_count_w was called");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block count CLI complete");
}

/**
 * @brief Test block last CLI command with existing block
 */
static void test_block_last_cli(void)
{
    dap_print_module_name("block last CLI");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    DAP_MOCK_SET_RETURN(dap_chain_type_blocks_get_last_w, (intptr_t)&s_mock_block_cache);
    g_mock_dap_chain_type_blocks_get_count_w->return_value.u64 = 100;
    
    char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "last", NULL};
    int l_argc = 6;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block last returned: %d", l_ret);
    dap_assert(l_ret == 0, "block last returns success");
    
    const char *l_json_str = dap_json_to_string(l_json_reply);
    log_it(L_DEBUG, "block last JSON: %s", l_json_str ? l_json_str : "(null)");
    dap_assert(l_json_str != NULL, "JSON response exists");
    dap_assert(strstr(l_json_str, "last_block_num") != NULL, "response contains last_block_num");
    dap_assert(strstr(l_json_str, "42") != NULL, "response contains block number 42");
    dap_assert(strstr(l_json_str, "last_block_hash") != NULL, "response contains last_block_hash");
    
    // Verify mocks were called
    int l_last_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_type_blocks_get_last_w);
    dap_assert(l_last_calls == 1, "get_last_w was called");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block last CLI complete");
}

/**
 * @brief Test block last CLI command with empty chain
 */
static void test_block_last_cli_empty(void)
{
    dap_print_module_name("block last CLI (empty chain)");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    DAP_MOCK_SET_RETURN(dap_chain_type_blocks_get_last_w, (intptr_t)NULL);
    g_mock_dap_chain_type_blocks_get_count_w->return_value.u64 = 0;
    
    char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "last", NULL};
    int l_argc = 6;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block last (empty) returned: %d", l_ret);
    dap_assert(l_ret == 0, "block last on empty chain returns success");
    
    const char *l_json_str = dap_json_to_string(l_json_reply);
    log_it(L_DEBUG, "block last (empty) JSON: %s", l_json_str ? l_json_str : "(null)");
    dap_assert(l_json_str != NULL, "JSON response exists");
    dap_assert(strstr(l_json_str, "last_block_num") != NULL, "response contains last_block_num");
    dap_assert(strstr(l_json_str, "empty") != NULL, "response contains 'empty' for hash");
    dap_assert(strstr(l_json_str, "never") != NULL, "response contains 'never' for ts_created");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block last CLI (empty chain) complete");
}

/**
 * @brief Test block find CLI command - validation (missing -datum)
 */
static void test_block_find_cli_validation(void)
{
    dap_print_module_name("block find CLI (validation)");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    
    // Test: find without -datum (should fail)
    char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "find", NULL};
    int l_argc = 6;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block find (no datum) returned: %d", l_ret);
    dap_assert(l_ret != 0, "block find without -datum returns error");
    
    const char *l_json_str = dap_json_to_string(l_json_reply);
    dap_assert(l_json_str != NULL, "JSON response exists");
    dap_assert(strstr(l_json_str, "-datum") != NULL || strstr(l_json_str, "datum") != NULL,
               "error mentions -datum parameter");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block find CLI (validation) complete");
}

/**
 * @brief Test block fee CLI command - validation (missing collect)
 */
static void test_block_fee_cli_validation(void)
{
    dap_print_module_name("block fee CLI (validation)");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    
    // Test: fee without 'collect' (should fail)
    char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "fee", NULL};
    int l_argc = 6;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block fee (no collect) returned: %d", l_ret);
    dap_assert(l_ret != 0, "block fee without 'collect' returns error");
    
    const char *l_json_str = dap_json_to_string(l_json_reply);
    dap_assert(l_json_str != NULL, "JSON response exists");
    dap_assert(strstr(l_json_str, "collect") != NULL,
               "error mentions 'collect' subcommand");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block fee CLI (validation) complete");
}

/**
 * @brief Test block reward set CLI command - validation (missing -poa_cert)
 */
static void test_block_reward_set_cli_validation(void)
{
    dap_print_module_name("block reward set CLI (validation)");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    
    // Test: reward set without -poa_cert (should fail)
    {
        char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "reward", "set", NULL};
        int l_argc = 7;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "block reward set (no poa_cert) returned: %d", l_ret);
        dap_assert(l_ret != 0, "block reward set without -poa_cert returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "-poa_cert") != NULL || strstr(l_json_str, "poa_cert") != NULL,
                   "error mentions -poa_cert parameter");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("block reward set CLI (validation) complete");
}

/**
 * @brief Test block autocollect CLI command - validation (missing action)
 */
static void test_block_autocollect_cli_validation(void)
{
    dap_print_module_name("block autocollect CLI (validation)");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    
    // Test: autocollect without status/start/stop (should fail or show help)
    char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", "autocollect", NULL};
    int l_argc = 6;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block autocollect (no action) returned: %d", l_ret);
    // autocollect without renew/status returns error "requires subcommand 'status'"
    dap_assert(l_ret != 0, "block autocollect without action returns error");
    
    const char *l_json_str = dap_json_to_string(l_json_reply);
    dap_assert(l_json_str != NULL, "JSON response exists");
    dap_assert(strstr(l_json_str, "status") != NULL,
               "error mentions 'status' subcommand");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block autocollect CLI (validation) complete");
}

/**
 * @brief Test block autocollect renew CLI command - validation (missing -cert)
 */
static void test_block_autocollect_renew_cli_validation(void)
{
    dap_print_module_name("block autocollect renew CLI (validation)");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    
    // Test 1: autocollect renew without -cert (should fail)
    {
        char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", 
                          "autocollect", "renew", NULL};
        int l_argc = 7;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "block autocollect renew (no cert) returned: %d", l_ret);
        dap_assert(l_ret != 0, "block autocollect renew without -cert returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "-cert") != NULL || strstr(l_json_str, "cert") != NULL,
                   "error mentions -cert parameter");
        
        dap_json_object_free(l_json_reply);
    }
    
    // Test 2: autocollect renew with -cert but without -addr (should fail)
    {
        s_reset_mocks();
        s_mock_chain_output = &s_mock_chain;
        s_mock_net_output = &s_mock_net;
        DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
        DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
        
        char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", 
                          "autocollect", "renew", "-cert", "nonexistent_cert", NULL};
        int l_argc = 9;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "block autocollect renew (nonexistent cert) returned: %d", l_ret);
        // Should fail because cert doesn't exist
        dap_assert(l_ret != 0, "block autocollect renew with nonexistent cert returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "certificate") != NULL || strstr(l_json_str, "cert") != NULL,
                   "error mentions certificate");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("block autocollect renew CLI (validation) complete");
}

/**
 * @brief Test block reward collect CLI command - validation (missing parameters)
 */
static void test_block_reward_collect_cli_validation(void)
{
    dap_print_module_name("block reward collect CLI (validation)");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    
    // Test: reward collect without required params (should fail)
    char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", 
                      "reward", "collect", NULL};
    int l_argc = 7;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block reward collect (no params) returned: %d", l_ret);
    // Should fail due to missing parameters like -cert, -addr, etc.
    dap_assert(l_ret != 0, "block reward collect without params returns error");
    
    const char *l_json_str = dap_json_to_string(l_json_reply);
    dap_assert(l_json_str != NULL, "JSON response exists");
    // Should mention some required parameter
    dap_assert(strstr(l_json_str, "-cert") != NULL || strstr(l_json_str, "-addr") != NULL ||
               strstr(l_json_str, "-hashes") != NULL || strstr(l_json_str, "parameter") != NULL,
               "error mentions required parameter");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block reward collect CLI (validation) complete");
}

/**
 * @brief Test block fee collect CLI command - validation (missing parameters)
 */
static void test_block_fee_collect_cli_validation(void)
{
    dap_print_module_name("block fee collect CLI (validation)");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    
    // Test: fee collect without -cert (should fail)
    char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", 
                      "fee", "collect", NULL};
    int l_argc = 7;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block fee collect (no cert) returned: %d", l_ret);
    // Should fail due to missing -cert parameter
    dap_assert(l_ret != 0, "block fee collect without -cert returns error");
    
    const char *l_json_str = dap_json_to_string(l_json_reply);
    dap_assert(l_json_str != NULL, "JSON response exists");
    dap_assert(strstr(l_json_str, "-cert") != NULL || strstr(l_json_str, "cert") != NULL ||
               strstr(l_json_str, "-addr") != NULL,
               "error mentions required parameter");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block fee collect CLI (validation) complete");
}

/**
 * @brief Test block with undefined subcommand
 */
static void test_block_undefined_subcommand(void)
{
    dap_print_module_name("block undefined subcommand");
    
    s_reset_mocks();
    
    s_mock_chain_output = &s_mock_chain;
    s_mock_net_output = &s_mock_net;
    DAP_MOCK_SET_RETURN(dap_chain_net_parse_net_chain, 0);
    DAP_MOCK_SET_RETURN(dap_chain_get_cs_type, (intptr_t)"esbocs");
    
    // Test: undefined subcommand
    char *l_argv[] = {"block", "-net", "test_net", "-chain", "test_chain", 
                      "invalid_subcmd", NULL};
    int l_argc = 6;
    
    dap_json_t *l_json_reply = dap_json_array_new();
    int l_ret = s_execute_cli_command("block", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "block (undefined subcmd) returned: %d", l_ret);
    dap_assert(l_ret != 0, "block with undefined subcommand returns error");
    
    const char *l_json_str = dap_json_to_string(l_json_reply);
    log_it(L_DEBUG, "block (undefined subcmd) JSON: %s", l_json_str ? l_json_str : "(null)");
    dap_assert(l_json_str != NULL, "JSON response exists");
    dap_assert(strstr(l_json_str, "Undefined") != NULL || strstr(l_json_str, "undefined") != NULL ||
               strstr(l_json_str, "invalid") != NULL,
               "error mentions undefined/invalid subcommand");
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("block undefined subcommand complete");
}

/**
 * @brief Test block list -h table output formatting
 * 
 * Tests the s_print_for_block_list function which formats block list
 * as a human-readable table with proper headers, separators and alignment.
 */
static void test_block_list_table_output(void)
{
    dap_print_module_name("block list -h table output");
    
    // Get the command to access func_rpc (s_print_for_block_list)
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("block");
    dap_assert(l_cmd != NULL, "block command found");
    dap_assert(l_cmd->func_rpc != NULL, "block command has func_rpc for table formatting");
    
    // Prepare mock JSON input (simulating block list result)
    // Structure: [[{block1}, {block2}, ...], {meta}]
    dap_json_t *l_json_input = dap_json_array_new();
    dap_json_t *l_json_blocks_array = dap_json_array_new();
    
    // Add test blocks with known data
    dap_json_t *l_block1 = dap_json_object_new();
    dap_json_object_add_uint64(l_block1, "block_num", 1);
    dap_json_object_add_string(l_block1, "hash", "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    dap_json_object_add_string(l_block1, "ts_create", "Mon, 01 Jan 2024 12:00:00 +0000");
    dap_json_array_add(l_json_blocks_array, l_block1);
    
    dap_json_t *l_block2 = dap_json_object_new();
    dap_json_object_add_uint64(l_block2, "block_num", 12345);
    dap_json_object_add_string(l_block2, "hash", "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    dap_json_object_add_string(l_block2, "ts_create", "Tue, 15 Feb 2024 15:30:45 +0300");
    dap_json_array_add(l_json_blocks_array, l_block2);
    
    dap_json_t *l_block3 = dap_json_object_new();
    dap_json_object_add_uint64(l_block3, "block_num", 99999);
    dap_json_object_add_string(l_block3, "hash", "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
    dap_json_object_add_string(l_block3, "ts_create", "Wed, 20 Mar 2024 08:15:30 +0500");
    dap_json_array_add(l_json_blocks_array, l_block3);
    
    // Add limit/offset metadata
    dap_json_t *l_meta = dap_json_object_new();
    dap_json_object_add_int64(l_meta, "limit", 100);
    dap_json_object_add_int64(l_meta, "offset", 0);
    dap_json_array_add(l_json_blocks_array, l_meta);
    
    dap_json_array_add(l_json_input, l_json_blocks_array);
    
    // Add second element (required by function)
    dap_json_t *l_dummy = dap_json_object_new();
    dap_json_array_add(l_json_input, l_dummy);
    
    // Prepare output
    dap_json_t *l_json_output = dap_json_array_new();
    
    // Prepare argv with -h and list
    char *l_argv[] = {"block", "-net", "test", "-chain", "test", "list", "-h", NULL};
    int l_argc = 7;
    
    // Call the formatting function
    int l_ret = l_cmd->func_rpc(l_json_input, l_json_output, l_argv, l_argc);
    
    log_it(L_DEBUG, "s_print_for_block_list returned: %d", l_ret);
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
    // 1. Check header separator line
    dap_assert(strstr(l_table, "_______________") != NULL, "table has top separator line");
    
    // 2. Check column headers
    dap_assert(strstr(l_table, "Block #") != NULL, "table has 'Block #' header");
    dap_assert(strstr(l_table, "Block hash") != NULL, "table has 'Block hash' header");
    dap_assert(strstr(l_table, "Time create") != NULL, "table has 'Time create' header");
    
    // 3. Check that block data is present
    dap_assert(strstr(l_table, "0xAAAAAAAA") != NULL, "table contains block 1 hash");
    dap_assert(strstr(l_table, "0xBBBBBBBB") != NULL, "table contains block 2 hash");
    dap_assert(strstr(l_table, "0xCCCCCCCC") != NULL, "table contains block 3 hash");
    
    // 4. Check block numbers are present
    dap_assert(strstr(l_table, "1") != NULL, "table contains block number 1");
    dap_assert(strstr(l_table, "12345") != NULL, "table contains block number 12345");
    dap_assert(strstr(l_table, "99999") != NULL, "table contains block number 99999");
    
    // 5. Check timestamps are present
    dap_assert(strstr(l_table, "2024") != NULL, "table contains year in timestamps");
    
    // 6. Check footer separator
    dap_assert(strstr(l_table, "__________|") != NULL, "table has footer separator");
    
    // 7. Check limit/offset display
    dap_assert(strstr(l_table, "limit:") != NULL, "table shows limit");
    dap_assert(strstr(l_table, "100") != NULL, "table shows limit value 100");
    
    // 8. Check proper column separators (|)
    int l_pipe_count = 0;
    for (const char *p = l_table; *p; p++) {
        if (*p == '|') l_pipe_count++;
    }
    // Each row has 3 pipes (| hash | time |), 3 blocks + header = 4 rows minimum = 12+ pipes
    dap_assert(l_pipe_count >= 9, "table has proper column separators");
    
    // Cleanup
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_pass_msg("block list -h table output complete");
}

/**
 * @brief Test block list -h with empty results
 */
static void test_block_list_table_empty(void)
{
    dap_print_module_name("block list -h table (empty)");
    
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("block");
    dap_assert(l_cmd != NULL, "block command found");
    
    // Prepare empty JSON input (only 1 element - should return -1)
    dap_json_t *l_json_input = dap_json_array_new();
    dap_json_t *l_json_blocks_array = dap_json_array_new();
    dap_json_array_add(l_json_input, l_json_blocks_array);
    // No second element - array length <= 1
    
    dap_json_t *l_json_output = dap_json_array_new();
    
    char *l_argv[] = {"block", "list", "-h", NULL};
    int l_argc = 3;
    
    int l_ret = l_cmd->func_rpc(l_json_input, l_json_output, l_argv, l_argc);
    
    log_it(L_DEBUG, "s_print_for_block_list (empty) returned: %d", l_ret);
    // Should return -1 for insufficient data
    dap_assert(l_ret == -1, "table formatting returns -1 for empty/insufficient data");
    
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_pass_msg("block list -h table (empty) complete");
}

/**
 * @brief Test block list without -h (should not format table)
 */
static void test_block_list_no_human_flag(void)
{
    dap_print_module_name("block list (no -h flag)");
    
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find("block");
    dap_assert(l_cmd != NULL, "block command found");
    
    // Prepare valid JSON input
    dap_json_t *l_json_input = dap_json_array_new();
    dap_json_t *l_json_blocks_array = dap_json_array_new();
    
    dap_json_t *l_block1 = dap_json_object_new();
    dap_json_object_add_uint64(l_block1, "block_num", 1);
    dap_json_object_add_string(l_block1, "hash", "0xAAAA");
    dap_json_object_add_string(l_block1, "ts_create", "2024-01-01");
    dap_json_array_add(l_json_blocks_array, l_block1);
    
    dap_json_array_add(l_json_input, l_json_blocks_array);
    dap_json_array_add(l_json_input, dap_json_object_new());
    
    dap_json_t *l_json_output = dap_json_array_new();
    
    // No -h flag
    char *l_argv[] = {"block", "list", NULL};
    int l_argc = 2;
    
    int l_ret = l_cmd->func_rpc(l_json_input, l_json_output, l_argv, l_argc);
    
    log_it(L_DEBUG, "s_print_for_block_list (no -h) returned: %d", l_ret);
    // Should return -1 because -h is not present
    dap_assert(l_ret == -1, "table formatting returns -1 without -h flag");
    
    dap_json_object_free(l_json_input);
    dap_json_object_free(l_json_output);
    
    dap_pass_msg("block list (no -h flag) complete");
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    
    // Initialize DAP subsystems
    dap_common_init("test_cli_block_mocked", NULL);
    
    // Initialize mock framework
    dap_mock_init();
    
    // Initialize mock structures
    s_init_mock_structures();
    
    // Initialize block CLI commands only (not full block module)
    dap_chain_type_blocks_cli_init();
    
    dap_print_module_name("Block CLI Tests with Mocking");
    printf("Testing block CLI with DAP Mock Framework\n\n");
    
    // Run tests
    test_block_dump_cli_validation();
    test_block_dump_cli_not_found();
    test_block_dump_cli_by_number_not_found();
    test_block_dump_cli_wrong_chain_type();
    test_block_list_cli_validation();
    test_block_net_parse_failure();
    test_block_count_cli();
    test_block_last_cli();
    test_block_last_cli_empty();
    test_block_find_cli_validation();
    test_block_fee_cli_validation();
    test_block_reward_set_cli_validation();
    test_block_autocollect_cli_validation();
    test_block_autocollect_renew_cli_validation();
    test_block_reward_collect_cli_validation();
    test_block_fee_collect_cli_validation();
    test_block_undefined_subcommand();
    test_block_list_table_output();
    test_block_list_table_empty();
    test_block_list_no_human_flag();
    
    printf("\n");
    dap_pass_msg("=== All mocked block CLI tests passed ===");
    
    // Cleanup
    dap_mock_deinit();
    dap_common_deinit();
    
    return 0;
}
