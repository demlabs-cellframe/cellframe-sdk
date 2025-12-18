/**
 * @file dex_test_main.c
 * @brief Main entry point for DEX integration tests
 */

#include <stdio.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#include <stdlib.h>
#define TEST_MKDIR(path) _mkdir(path)
#else
#include <unistd.h>
#define TEST_MKDIR(path) mkdir(path, 0755)
#endif
#include "dex_test_fixture.h"
#include "dex_test_common.h"
#include "dex_lifecycle_tests.h"
#include "dex_automatch_tests.h"
#include "dap_chain_net_srv_dex.h"
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
    
#ifdef _WIN32
    char l_config_dir[256];
    const char *l_temp = getenv("TEMP");
    if (!l_temp) l_temp = getenv("TMP");
    if (!l_temp) l_temp = ".";
    snprintf(l_config_dir, sizeof(l_config_dir), "%s\\dex_integration_test_config", l_temp);
#else
    const char *l_config_dir = "/tmp/dex_integration_test_config";
#endif
    TEST_MKDIR(l_config_dir);
    
    const char *l_config_content = a_cache ?
        "[general]\ndebug_mode=true\n[srv_dex]\nmemcached=true\nhistory_cache=true\n" :
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

static int s_test_cli_bucket_alignment(dex_test_fixture_t *fixture) {
    log_it(L_NOTICE, "=== CLI Test: Bucket Calendar Alignment ===");
    
    // Test different bucket sizes and verify calendar alignment
    // bucket_sec values: 3600 (hour), 86400 (day), 604800 (week), 2592000 (month), 31536000 (year)
    const struct { uint64_t sec; const char *name; } buckets[] = {
        { 3600,     "1h (hour)" },
        { 86400,    "1d (day)" },
        { 604800,   "1w (week)" },
        { 2592000,  "1M (month)" },
        { 31536000, "1Y (year)" }
    };
    
    for (size_t i = 0; i < sizeof(buckets)/sizeof(buckets[0]); i++) {
        char l_json_request[1024];
        snprintf(l_json_request, sizeof(l_json_request),
            "{\"method\":\"srv_dex\",\"params\":[\"srv_dex;market_rate;-net;%s;-pair;KEL/USDT;-bucket;%"DAP_UINT64_FORMAT_U"\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
            fixture->net->net->pub.name, buckets[i].sec);
        
        log_it(L_INFO, "Testing bucket %s (%"DAP_UINT64_FORMAT_U" sec)", buckets[i].name, buckets[i].sec);
        
        char *l_reply = dap_cli_cmd_exec(l_json_request);
        if (!l_reply) {
            log_it(L_WARNING, "  CLI returned NULL for bucket %s", buckets[i].name);
            continue;
        }
        
        json_object *l_json = json_tokener_parse(l_reply);
        if (!l_json) {
            log_it(L_WARNING, "  Failed to parse JSON for bucket %s", buckets[i].name);
            DAP_DELETE(l_reply);
            continue;
        }
        
        json_object *l_error = NULL;
        if (json_object_object_get_ex(l_json, "error", &l_error)) {
            log_it(L_WARNING, "  Error for bucket %s: %s", buckets[i].name, json_object_to_json_string(l_error));
            json_object_put(l_json);
            DAP_DELETE(l_reply);
            continue;
        }
        
        json_object *l_result = NULL;
        if (json_object_object_get_ex(l_json, "result", &l_result)) {
            json_object *l_ohlc = NULL;
            if (json_object_object_get_ex(l_result, "ohlc", &l_ohlc)) {
                int l_count = json_object_array_length(l_ohlc);
                log_it(L_NOTICE, "  Bucket %s: %d candles", buckets[i].name, l_count);
                for (int j = 0; j < l_count && j < 3; j++) {
                    json_object *l_candle = json_object_array_get_idx(l_ohlc, j);
                    json_object *l_ts = NULL, *l_ts_str = NULL;
                    if (json_object_object_get_ex(l_candle, "ts", &l_ts) &&
                        json_object_object_get_ex(l_candle, "ts_str", &l_ts_str)) {
                        log_it(L_NOTICE, "    [%d] ts=%"DAP_UINT64_FORMAT_U" (%s)", 
                            j, (uint64_t)json_object_get_int64(l_ts), json_object_get_string(l_ts_str));
                    }
                }
            }
        }
        
        json_object_put(l_json);
        DAP_DELETE(l_reply);
    }
    
    log_it(L_NOTICE, "Bucket alignment test complete");
    return 0;
}

static int s_test_cli_raw_trades(dex_test_fixture_t *fixture) {
    log_it(L_NOTICE, "=== CLI Test: Raw Trades (history -mode trades) ===");
    
    char l_json_request[1024];
    snprintf(l_json_request, sizeof(l_json_request),
        "{\"method\":\"srv_dex\",\"params\":[\"srv_dex;history;-net;%s;-pair;KEL/USDT;-mode;trades\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
        fixture->net->net->pub.name);
    
    log_it(L_INFO, "CLI request: %s", l_json_request);
    
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    if (!l_reply) {
        log_it(L_ERROR, "CLI returned NULL");
        return -1;
    }
    
    log_it(L_INFO, "CLI reply:\n%s", l_reply);
    
    json_object *l_json = json_tokener_parse(l_reply);
    if (!l_json) {
        log_it(L_ERROR, "Failed to parse JSON reply");
        DAP_DELETE(l_reply);
        return -2;
    }
    
    json_object *l_error = NULL;
    if (json_object_object_get_ex(l_json, "error", &l_error)) {
        log_it(L_ERROR, "CLI returned error: %s", json_object_to_json_string(l_error));
        json_object_put(l_json);
        DAP_DELETE(l_reply);
        return -3;
    }
    
    json_object *l_result = NULL;
    if (json_object_object_get_ex(l_json, "result", &l_result)) {
        json_object *l_trades = NULL, *l_count = NULL;
        if (json_object_object_get_ex(l_result, "trades", &l_trades) &&
            json_object_object_get_ex(l_result, "count", &l_count)) {
            int l_total = json_object_get_int(l_count);
            int l_arr_len = json_object_array_length(l_trades);
            log_it(L_NOTICE, "Raw trades: count=%d, array_length=%d", l_total, l_arr_len);
        }
    }
    
    json_object_put(l_json);
    DAP_DELETE(l_reply);
    log_it(L_NOTICE, "Raw trades test PASSED");
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
    ret = run_lifecycle_tests(fixture);
    if (ret != 0) {
        log_it(L_ERROR, "Lifecycle tests FAILED with code %d", ret);
        dex_test_fixture_destroy(fixture);
        s_teardown();
        return ret;
    }
    
    // Dump orderbook and history after lifecycle (has trades)
    test_dex_dump_orderbook(fixture, "After lifecycle tests");
    
    /*dap_chain_net_srv_dex_dump_history_cache();
    
    // Test bucket calendar alignment (while history has data)
    ret = s_test_cli_bucket_alignment(fixture);
    if (ret != 0) {
        log_it(L_WARNING, "Bucket alignment test failed with code %d (non-fatal)", ret);
    }
    
    // Test raw trades output
    ret = s_test_cli_raw_trades(fixture);
    if (ret != 0) {
        log_it(L_WARNING, "Raw trades test failed with code %d (non-fatal)", ret);
    }*/
    
    // Cleanup before multi-execution tests
    ret = run_cancel_all_active(fixture);
    if (ret != 0) {
        log_it(L_WARNING, "Post-lifecycle cleanup failed: %d (continuing)", ret);
    }
    test_dex_dump_orderbook(fixture, "After cancel-all (pre-multi)");
    
    // Run multi-execution tests on clean orderbook
    ret = run_multi_execution_tests(fixture);
    if (ret != 0) {
        log_it(L_ERROR, "Multi-execution tests FAILED with code %d", ret);
        dex_test_fixture_destroy(fixture);
        s_teardown();
        return ret;
    }
    
    // Dump after multi-execution (has new trades)
    test_dex_dump_orderbook(fixture, "After multi-execution tests");
    dap_chain_net_srv_dex_dump_history_cache();
    
    // Cleanup after multi-execution
    ret = run_cancel_all_active(fixture);
    if (ret != 0) {
        log_it(L_WARNING, "Post-multi cleanup failed: %d (continuing)", ret);
    }
    test_dex_dump_orderbook(fixture, "After cancel-all (pre-seed)");
    
    // Seed orderbook for automatch tests
    ret = run_seed_orderbook(fixture);
    if (ret != 0) {
        log_it(L_ERROR, "Orderbook seeding FAILED with code %d", ret);
        dex_test_fixture_destroy(fixture);
        s_teardown();
        return ret;
    }
    
    // Run CLI tests
    ret = s_test_cli_pairs(fixture);
    if (ret != 0) {
        log_it(L_WARNING, "CLI pairs test failed with code %d (non-fatal)", ret);
    }
    
    // Run automatch tests (uses seeded orderbook)
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
