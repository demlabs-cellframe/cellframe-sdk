/**
 * @file dex_test_main.c
 * @brief Main entry point for DEX integration tests
 */

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include "dex_test_fixture.h"
#include "dex_lifecycle_tests.h"
#include "dex_automatch_tests.h"
#include "dap_config.h"
#include "dap_enc.h"
#include "dap_test.h"
#include "dap_chain_wallet.h"
#include "dap_cli_server.h"
#include "dap_chain_node_cli.h"
#include "json.h"

extern int dap_chain_cs_dag_init(void);
extern int dap_chain_cs_dag_poa_init(void);
extern int dap_chain_cs_esbocs_init(void);

// ============================================================================
// SETUP / TEARDOWN
// ============================================================================

static void s_setup(bool a_cache) {
    log_it(L_NOTICE, "=== DEX Integration Tests Setup ===");
    
    const char *l_config_dir = "/tmp/dex_integration_test_config";
    mkdir(l_config_dir, 0755);
    
    const char *l_config_content = a_cache ?
        "[general]\ndebug_mode=true\n[srv_dex]\nmemcached=true\n" :
        "[general]\ndebug_mode=true";
    
    char l_config_path[256], l_log_path[100];
    snprintf(l_config_path, sizeof(l_config_path), "%s/test.cfg", l_config_dir);
    FILE *l_config_file = fopen(l_config_path, "w");
    if (l_config_file) {
        fwrite(l_config_content, 1, strlen(l_config_content), l_config_file);
        fclose(l_config_file);
    }
    
    dap_config_init(l_config_dir);
    g_config = dap_config_open("test");
    dap_assert(g_config != NULL, "Config initialization");
    snprintf(l_log_path, sizeof(l_log_path), "%s/%s", l_config_dir, "log.txt");
    dap_common_init(NULL, l_log_path);
    
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    
    // Initialize CLI server (without network listener) for CLI tests
    dap_cli_server_init(false, "cli-server");
    dap_chain_node_cli_init(g_config);
    
    log_it(L_NOTICE, "Test environment initialized (with CLI)");
}

static void s_teardown(void) {
    log_it(L_NOTICE, "Cleaning up test environment...");
    
    // Clean up CLI server first
    dap_chain_node_cli_delete();
    
    if (g_config) {
        dap_config_close(g_config);
        g_config = NULL;
    }
    dap_config_deinit();
    
    unlink("/tmp/dex_integration_test_config/test.cfg");
    rmdir("/tmp/dex_integration_test_config");
    
    log_it(L_NOTICE, "Cleanup completed");
}

// ============================================================================
// CLI TESTS
// ============================================================================

static int s_test_cli_pairs(dex_test_fixture_t *fixture) {
    log_it(L_NOTICE, "=== CLI Test: srv_dex pairs ===");
    
    // Build JSON-RPC request for srv_dex pairs
    // Format: params[0] = "cmd;subcmd;-arg;value;..." (split by ';')
    // a_argv[0] = "srv_dex", a_argv[1] = "pairs", a_argv[2] = "-net", a_argv[3] = "name"
    char l_json_request[1024];
    snprintf(l_json_request, sizeof(l_json_request),
             "{\"method\":\"srv_dex\",\"params\":[\"srv_dex;pairs;-net;%s\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
             fixture->net->net->pub.name);
    
    log_it(L_INFO, "CLI request: %s", l_json_request);
    
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    if (!l_reply) {
        log_it(L_ERROR, "CLI command returned NULL");
        return -1;
    }
    
    log_it(L_INFO, "CLI reply: %s", l_reply);
    
    // Parse JSON reply
    json_object *l_json = json_tokener_parse(l_reply);
    if (!l_json) {
        log_it(L_ERROR, "Failed to parse JSON reply");
        return -2;
    }
    
    // Check for error
    json_object *l_error = NULL;
    if (json_object_object_get_ex(l_json, "error", &l_error)) {
        log_it(L_ERROR, "CLI returned error: %s", json_object_to_json_string(l_error));
        json_object_put(l_json);
        return -3;
    }
    
    // Extract result
    json_object *l_result = NULL;
    if (json_object_object_get_ex(l_json, "result", &l_result)) {
        json_object *l_pairs = NULL;
        if (json_object_object_get_ex(l_result, "pairs", &l_pairs)) {
            int l_count = json_object_array_length(l_pairs);
            log_it(L_NOTICE, "Found %d trading pairs:", l_count);
            
            for (int i = 0; i < l_count; i++) {
                json_object *l_pair = json_object_array_get_idx(l_pairs, i);
                log_it(L_INFO, "  [%d] %s", i, json_object_to_json_string(l_pair));
            }
        }
    }
    
    json_object_put(l_json);
    log_it(L_NOTICE, "CLI pairs test PASSED");
    return 0;
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    
    dap_test_msg("DEX Integration Tests");
    
    dap_log_level_set(L_DEBUG);
    dap_log_set_external_output(LOGGER_OUTPUT_STDOUT, NULL);
    dap_enc_init();
    dap_chain_wallet_init();
    
    s_setup(true);
    
    dex_test_fixture_t *fixture = dex_test_fixture_create();
    if (!fixture) {
        log_it(L_ERROR, "Failed to create test fixture");
        s_teardown();
        return 1;
    }
    
    dex_print_balances(fixture, "INITIAL STATE");
    int ret = 0;
    // Run lifecycle tests (long)
    /*ret = run_lifecycle_tests(fixture);
    if (ret != 0) {
        log_it(L_ERROR, "Lifecycle tests FAILED with code %d", ret);
        dex_test_fixture_destroy(fixture);
        s_teardown();
        return ret;
    }
    
    // Extra cleanup: cancel any remaining orders after lifecycle tests
    ret = run_cancel_all_active(fixture);
    if (ret != 0) {
        log_it(L_WARNING, "Post-lifecycle cleanup failed: %d (continuing)", ret);
    }*/
    
    // Seed orderbook for matcher tests (short)
    ret = run_seed_orderbook(fixture);
    if (ret != 0) {
        log_it(L_ERROR, "Orderbook seeding FAILED with code %d", ret);
        dex_test_fixture_destroy(fixture);
        s_teardown();
        return ret;
    }
    
    // Run CLI tests after lifecycle tests
    ret = s_test_cli_pairs(fixture);
    if (ret != 0) {
        log_it(L_WARNING, "CLI pairs test failed with code %d (non-fatal)", ret);
    }
    
    // Run automatch tests (uses seeded orderbook from lifecycle tests)
    ret = run_automatch_tests(fixture);
    if (ret != 0) {
        log_it(L_ERROR, "Automatch tests FAILED with code %d", ret);
        dex_test_fixture_destroy(fixture);
        s_teardown();
        return ret;
    }
    
    // TODO: Add when implemented
    // run_leftover_tests(fixture);
    // run_operations_tests(fixture);
    
    dex_test_fixture_destroy(fixture);
    s_teardown();
    
    dap_test_msg("All integration tests completed");
    return 0;
}
