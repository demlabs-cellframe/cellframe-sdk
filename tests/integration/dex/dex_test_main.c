/**
 * @file dex_test_main.c
 * @brief Main entry point for DEX integration tests
 */

#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include "dap_file_utils.h"
#include "test_ledger_fixtures.h"
#include "dex_test_fixture.h"
#include "dex_test_common.h"
#include "dex_lifecycle_tests.h"
#include "dex_automatch_tests.h"
#include "dex_migration_tests.h"
#include "dap_chain_net_srv_dex.h"
#include "dap_config.h"
#include "dap_enc.h"
#include "dap_test.h"
#include "dap_chain_wallet.h"
#include "dap_cli_server.h"
#include "dap_chain_node_cli.h"

extern int dap_chain_cs_dag_init(void);
extern int dap_chain_cs_dag_poa_init(void);
extern int dap_chain_cs_esbocs_init(void);
extern int dap_nonconsensus_init(void);

// ============================================================================
// SETUP / TEARDOWN
// ============================================================================

static bool s_cache_enabled = false;
static char s_config_dir[512];
static char s_gdb_dir[512];
static char s_certs_dir[512];

static void s_setup(bool a_cache) {
    s_cache_enabled = a_cache;
    log_it(L_NOTICE, "=== DEX Integration Tests Setup ===");
    
    const char *l_tmp = test_get_temp_dir();
    snprintf(s_config_dir, sizeof(s_config_dir), "%s/dex_integration_test_config", l_tmp);
    snprintf(s_gdb_dir, sizeof(s_gdb_dir), "%s/dex_intg_test_gdb", l_tmp);
    snprintf(s_certs_dir, sizeof(s_certs_dir), "%s/dex_intg_test_certs", l_tmp);

    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
    dap_rm_rf(s_config_dir);

    dap_mkdir_with_parents(s_config_dir);
    
    char l_config_content[2048];
    snprintf(l_config_content, sizeof(l_config_content),
        a_cache ?
        "[general]\ndebug_mode=true\n"
        "[srv_dex]\ncache_enabled=true\nhistory_cache=true\n"
        "[global_db]\ndriver=mdbx\npath=%s\n"
        "[resources]\nca_folders=%s\n" :
        "[general]\ndebug_mode=true\n"
        "[srv_dex]\ncache_enabled=false\n"
        "[global_db]\ndriver=mdbx\npath=%s\n"
        "[resources]\nca_folders=%s\n",
        s_gdb_dir, s_certs_dir);
    
    char l_config_path[1024], l_log_path[1024];
    snprintf(l_config_path, sizeof(l_config_path), "%s/test.cfg", s_config_dir);
    FILE *l_config_file = fopen(l_config_path, "w");
    if (l_config_file) {
        fwrite(l_config_content, 1, strlen(l_config_content), l_config_file);
        fclose(l_config_file);
    }
    
    dap_mkdir_with_parents(s_certs_dir);
    
    dap_config_init(s_config_dir);
    g_config = dap_config_open("test");
    dap_assert(g_config != NULL, "Config initialization");
    snprintf(l_log_path, sizeof(l_log_path), "%s/log.txt", s_config_dir);
    dap_common_init(NULL, l_log_path);
    
    int l_env_res = test_env_init(s_config_dir, s_gdb_dir);
    dap_assert(l_env_res == 0, "Test environment initialization");
    
    dap_ledger_init();
    
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    dap_nonconsensus_init();
    
    dap_cli_server_init(false, "cli-server");
    dap_chain_node_cli_init(g_config);
    
    log_it(L_NOTICE, "Test environment initialized (with CLI)");
}

static void s_teardown(void) {
    log_it(L_NOTICE, "Cleaning up test environment...");
    
    dap_chain_node_cli_delete();
    test_env_deinit();
    
    if (g_config) {
        dap_config_close(g_config);
        g_config = NULL;
    }
    dap_config_deinit();
    
    dap_rm_rf(s_config_dir);
    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
    
    log_it(L_NOTICE, "Cleanup completed");
}

// ============================================================================
// CLI TESTS
// ============================================================================

static bool s_ts_is_bucket_aligned(uint64_t a_ts, uint64_t a_bucket_sec)
{
    if (!a_bucket_sec)
        return false;
    if (a_bucket_sec < 86400ULL)
        return (a_ts % a_bucket_sec) == 0;
    if (a_bucket_sec == 86400ULL)
        return (a_ts % 86400ULL) == 0;
    if (a_bucket_sec == 604800ULL) {
        if (a_ts % 86400ULL)
            return false;
        uint64_t l_days = a_ts / 86400ULL;
        return ((l_days + 3ULL) % 7ULL) == 0; // Monday 00:00 UTC
    }
    time_t l_time = (time_t)a_ts;
    struct tm l_tm = {0};
#ifdef _WIN32
    gmtime_s(&l_tm, &l_time);
#else
    gmtime_r(&l_time, &l_tm);
#endif
    if (l_tm.tm_hour || l_tm.tm_min || l_tm.tm_sec)
        return false;
    if (a_bucket_sec >= 365ULL * 86400ULL)
        return l_tm.tm_mon == 0 && l_tm.tm_mday == 1;
    if (a_bucket_sec >= 28ULL * 86400ULL)
        return l_tm.tm_mday == 1;
    return (a_ts % a_bucket_sec) == 0;
}

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
            "{\"method\":\"srv_dex\",\"params\":[\"srv_dex;history;-net;%s;-pair;KEL/USDT;-view;ohlc;-bucket;%"DAP_UINT64_FORMAT_U"\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
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
        
        json_object *l_result_raw = NULL;
        if (!json_object_object_get_ex(l_json, "result", &l_result_raw)) {
            log_it(L_WARNING, "  No 'result' in reply for bucket %s", buckets[i].name);
            json_object_put(l_json);
            DAP_DELETE(l_reply);
            continue;
        }
        json_object *l_result = json_object_is_type(l_result_raw, json_type_array)
            ? json_object_array_get_idx(l_result_raw, 0) : l_result_raw;
        if (!l_result) {
            log_it(L_WARNING, "  Empty result array for bucket %s", buckets[i].name);
            json_object_put(l_json);
            DAP_DELETE(l_reply);
            continue;
        }
        json_object *l_ohlc = NULL;
        if (!json_object_object_get_ex(l_result, "ohlc", &l_ohlc) || !json_object_is_type(l_ohlc, json_type_array)) {
            log_it(L_WARNING, "  Missing 'ohlc' array for bucket %s", buckets[i].name);
            json_object_put(l_json);
            DAP_DELETE(l_reply);
            continue;
        }
        int l_count = json_object_array_length(l_ohlc);
        log_it(L_NOTICE, "  Bucket %s: %d candles", buckets[i].name, l_count);
        uint64_t l_prev_ts = 0;
        for (int j = 0; j < l_count; j++) {
            json_object *l_candle = json_object_array_get_idx(l_ohlc, j);
            json_object *l_ts = NULL;
            if (!l_candle || !json_object_object_get_ex(l_candle, "ts", &l_ts)) {
                log_it(L_ERROR, "  Bucket %s: candle[%d] missing ts", buckets[i].name, j);
                json_object_put(l_json);
                DAP_DELETE(l_reply);
                return -10;
            }
            uint64_t l_ts_u = (uint64_t)json_object_get_int64(l_ts);
            if (j && l_ts_u < l_prev_ts) {
                log_it(L_ERROR, "  Bucket %s: candle[%d] ts out of order (%"DAP_UINT64_FORMAT_U" < %"DAP_UINT64_FORMAT_U")",
                    buckets[i].name, j, l_ts_u, l_prev_ts);
                json_object_put(l_json);
                DAP_DELETE(l_reply);
                return -11;
            }
            if (!s_ts_is_bucket_aligned(l_ts_u, buckets[i].sec)) {
                log_it(L_ERROR, "  Bucket %s: candle[%d] ts not aligned (%"DAP_UINT64_FORMAT_U", bucket=%"DAP_UINT64_FORMAT_U")",
                    buckets[i].name, j, l_ts_u, buckets[i].sec);
                json_object_put(l_json);
                DAP_DELETE(l_reply);
                return -12;
            }
            l_prev_ts = l_ts_u;
        }
        
        json_object_put(l_json);
        DAP_DELETE(l_reply);
    }
    
    log_it(L_NOTICE, "Bucket alignment test complete");
    return 0;
}

static int s_test_cli_raw_trades(dex_test_fixture_t *fixture) {
    log_it(L_NOTICE, "=== CLI Test: Raw Trades (history -view events -type trade) ===");
    
    char l_json_request[1024];
    snprintf(l_json_request, sizeof(l_json_request),
        "{\"method\":\"srv_dex\",\"params\":[\"srv_dex;history;-net;%s;-pair;KEL/USDT;-view;events;-type;trade\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
        fixture->net->net->pub.name);
    
    log_it(L_INFO, "CLI request: %s", l_json_request);
    
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    if (!l_reply) {
        log_it(L_ERROR, "CLI returned NULL");
        return -1;
    }
    
    json_object *l_json = json_tokener_parse(l_reply);
    DAP_DELETE(l_reply);
    if (!l_json) {
        log_it(L_ERROR, "Failed to parse JSON reply");
        return -2;
    }
    
    json_object *l_error = NULL;
    if (json_object_object_get_ex(l_json, "error", &l_error)) {
        log_it(L_ERROR, "CLI returned error: %s", json_object_to_json_string(l_error));
        json_object_put(l_json);
        return -3;
    }
    
    json_object *l_result_raw = NULL;
    if (!json_object_object_get_ex(l_json, "result", &l_result_raw)) {
        log_it(L_ERROR, "No 'result' field in reply");
        json_object_put(l_json);
        return -4;
    }
    
    // JSON-RPC returns result as array, extract first element
    json_object *l_result = json_object_is_type(l_result_raw, json_type_array)
        ? json_object_array_get_idx(l_result_raw, 0) : l_result_raw;
    if (!l_result) {
        log_it(L_ERROR, "Empty result array");
        json_object_put(l_json);
        return -5;
    }
    
    json_object *l_trades = NULL, *l_count = NULL;
    if (!json_object_object_get_ex(l_result, "trades", &l_trades) ||
        !json_object_object_get_ex(l_result, "count", &l_count)) {
        log_it(L_ERROR, "Missing 'trades' or 'count' in result");
        json_object_put(l_json);
        return -6;
    }
    
    int l_total = json_object_get_int(l_count);
    int l_arr_len = json_object_array_length(l_trades);
    log_it(L_NOTICE, "Raw trades: count=%d, array_length=%d", l_total, l_arr_len);
    
    // STRICT: must have at least one trade (MARKET or TARGETED, ORDER excluded)
    if (l_total == 0) {
        log_it(L_ERROR, "Expected trades count > 0 (MARKET/TARGETED), got 0");
        json_object_put(l_json);
        return -7;
    }

    if (l_total != l_arr_len) {
        log_it(L_ERROR, "Count mismatch: count=%d, array_length=%d", l_total, l_arr_len);
        json_object_put(l_json);
        return -9;
    }
    
    // Verify types are MARKET or TARGETED (not ORDER) and time ordering is ascending
    uint64_t l_prev_ts = 0;
    for (int i = 0; i < l_arr_len; i++) {
        json_object *l_trade = json_object_array_get_idx(l_trades, i);
        json_object *l_type = NULL, *l_ts = NULL, *l_seller = NULL, *l_buyer = NULL;
        if (!l_trade || !json_object_object_get_ex(l_trade, "type", &l_type) || !json_object_object_get_ex(l_trade, "ts", &l_ts)) {
            log_it(L_ERROR, "Trade[%d] missing type/ts", i);
            json_object_put(l_json);
            return -10;
        }
        const char *l_type_str = json_object_get_string(l_type);
        if (dap_strcmp(l_type_str, "market trade") != 0 && dap_strcmp(l_type_str, "targeted trade") != 0) {
            log_it(L_ERROR, "Unexpected type '%s' in trades (expected market trade/targeted trade)", l_type_str);
            json_object_put(l_json);
            return -8;
        }
        uint64_t l_ts_u = (uint64_t)json_object_get_int64(l_ts);
        if (i && l_ts_u < l_prev_ts) {
            log_it(L_ERROR, "Trades not sorted by ts: trade[%d] ts=%"DAP_UINT64_FORMAT_U" < prev=%"DAP_UINT64_FORMAT_U, i, l_ts_u, l_prev_ts);
            json_object_put(l_json);
            return -11;
        }
        if (!json_object_object_get_ex(l_trade, "seller", &l_seller) || !json_object_is_type(l_seller, json_type_string) ||
            !json_object_object_get_ex(l_trade, "buyer", &l_buyer) || !json_object_is_type(l_buyer, json_type_string)) {
            log_it(L_ERROR, "Trade[%d] missing seller/buyer", i);
            json_object_put(l_json);
            return -12;
        }
        const char *l_seller_str = json_object_get_string(l_seller), *l_buyer_str = json_object_get_string(l_buyer);
        if (!l_seller_str || !*l_seller_str || !l_buyer_str || !*l_buyer_str || !dap_strcmp(l_seller_str, l_buyer_str)) {
            log_it(L_ERROR, "Trade[%d] invalid seller/buyer", i);
            json_object_put(l_json);
            return -13;
        }
        l_prev_ts = l_ts_u;
        if (i < 5)
            log_it(L_DEBUG, "  [%d] type=%s", i, l_type_str);
    }
    
    json_object_put(l_json);
    log_it(L_NOTICE, "Raw trades test PASSED (count=%d)", l_total);
    return 0;
}

static int s_test_cli_history_orders(dex_test_fixture_t *fixture) {
    log_it(L_NOTICE, "=== CLI Test: History Orders Only (history -view events -type order) ===");
    
    char l_json_request[1024];
    snprintf(l_json_request, sizeof(l_json_request),
        "{\"method\":\"srv_dex\",\"params\":[\"srv_dex;history;-net;%s;-pair;KEL/USDT;-view;events;-type;order\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
        fixture->net->net->pub.name);
    
    log_it(L_INFO, "CLI request: %s", l_json_request);
    
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    if (!l_reply) {
        log_it(L_ERROR, "CLI returned NULL");
        return -1;
    }
    
    json_object *l_json = json_tokener_parse(l_reply);
    DAP_DELETE(l_reply);
    if (!l_json) {
        log_it(L_ERROR, "Failed to parse JSON reply");
        return -2;
    }
    
    json_object *l_error = NULL;
    if (json_object_object_get_ex(l_json, "error", &l_error)) {
        log_it(L_ERROR, "CLI returned error: %s", json_object_to_json_string(l_error));
        json_object_put(l_json);
        return -3;
    }
    
    json_object *l_result_raw = NULL;
    if (!json_object_object_get_ex(l_json, "result", &l_result_raw)) {
        log_it(L_ERROR, "No 'result' field in reply");
        json_object_put(l_json);
        return -4;
    }
    
    // JSON-RPC returns result as array, extract first element
    json_object *l_result = json_object_is_type(l_result_raw, json_type_array)
        ? json_object_array_get_idx(l_result_raw, 0) : l_result_raw;
    if (!l_result) {
        log_it(L_ERROR, "Empty result array");
        json_object_put(l_json);
        return -5;
    }
    
    json_object *l_orders = NULL, *l_count = NULL;
    if (!json_object_object_get_ex(l_result, "orders", &l_orders) ||
        !json_object_object_get_ex(l_result, "count", &l_count)) {
        log_it(L_ERROR, "Missing 'orders' or 'count' in result (check -type order filter)");
        json_object_put(l_json);
        return -6;
    }
    
    int l_total = json_object_get_int(l_count);
    int l_arr_len = json_object_array_length(l_orders);
    log_it(L_NOTICE, "Order creations: count=%d, array_length=%d", l_total, l_arr_len);
    
    // STRICT: must have at least one ORDER record
    if (l_total == 0) {
        log_it(L_ERROR, "Expected orders count > 0, got 0 (ORDER records not in history?)");
        json_object_put(l_json);
        return -7;
    }

    if (l_total != l_arr_len) {
        log_it(L_ERROR, "Count mismatch: count=%d, array_length=%d", l_total, l_arr_len);
        json_object_put(l_json);
        return -9;
    }
    
    // Verify all entries have type "order"
    for (int i = 0; i < l_arr_len; i++) {
        json_object *l_order = json_object_array_get_idx(l_orders, i);
        json_object *l_type = NULL, *l_tx_hash = NULL, *l_seller = NULL;
        if (!l_order || !json_object_object_get_ex(l_order, "type", &l_type) || !json_object_object_get_ex(l_order, "tx_hash", &l_tx_hash)) {
            log_it(L_ERROR, "Order[%d] missing type/tx_hash", i);
            json_object_put(l_json);
            return -10;
        }
        const char *l_type_str = json_object_get_string(l_type);
        if (dap_strcmp(l_type_str, "new order") != 0 && dap_strcmp(l_type_str, "market trade | new order") != 0 &&
            dap_strcmp(l_type_str, "targeted trade | new order") != 0) {
            log_it(L_ERROR, "Expected type 'new order|market trade | new order|targeted trade | new order', got '%s'", l_type_str);
            json_object_put(l_json);
            return -8;
        }
        if (!json_object_object_get_ex(l_order, "seller", &l_seller) || !json_object_is_type(l_seller, json_type_string) ||
            !json_object_get_string(l_seller) || !*json_object_get_string(l_seller)) {
            log_it(L_ERROR, "Order[%d] missing seller", i);
            json_object_put(l_json);
            return -11;
        }
        if (i < 5) {
            log_it(L_DEBUG, "  [%d] tx_hash=%s", i, json_object_get_string(l_tx_hash));
        }
    }
    
    json_object_put(l_json);
    log_it(L_NOTICE, "History orders test PASSED (count=%d)", l_total);
    return 0;
}

static int s_test_cli_history_ohlc(dex_test_fixture_t *fixture) {
    log_it(L_NOTICE, "=== CLI Test: History OHLC (history -view ohlc -bucket) ===");
    
    char l_json_request[1024];
    snprintf(l_json_request, sizeof(l_json_request),
        "{\"method\":\"srv_dex\",\"params\":[\"srv_dex;history;-net;%s;-pair;KEL/USDT;-view;ohlc;-bucket;3600\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
        fixture->net->net->pub.name);
    
    log_it(L_INFO, "CLI request: %s", l_json_request);
    
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    if (!l_reply) {
        log_it(L_ERROR, "CLI returned NULL");
        return -1;
    }
    
    json_object *l_json = json_tokener_parse(l_reply);
    DAP_DELETE(l_reply);
    if (!l_json) {
        log_it(L_ERROR, "Failed to parse JSON reply");
        return -2;
    }
    
    json_object *l_error = NULL;
    if (json_object_object_get_ex(l_json, "error", &l_error)) {
        log_it(L_ERROR, "CLI returned error: %s", json_object_to_json_string(l_error));
        json_object_put(l_json);
        return -3;
    }
    
    json_object *l_result_raw = NULL;
    if (!json_object_object_get_ex(l_json, "result", &l_result_raw)) {
        log_it(L_ERROR, "No 'result' field in reply");
        json_object_put(l_json);
        return -4;
    }
    
    // JSON-RPC returns result as array, extract first element
    json_object *l_result = json_object_is_type(l_result_raw, json_type_array)
        ? json_object_array_get_idx(l_result_raw, 0) : l_result_raw;
    if (!l_result) {
        log_it(L_ERROR, "Empty result array");
        json_object_put(l_json);
        return -5;
    }
    
    // market_only is informational: true with cache, false with ledger fallback
    json_object *l_market_only = NULL;
    if (json_object_object_get_ex(l_result, "market_only", &l_market_only)) {
        log_it(L_NOTICE, "market_only=%s (cache=%s)",
            json_object_get_boolean(l_market_only) ? "true" : "false",
            s_cache_enabled ? "on" : "off");
    }
    
    // Check OHLC data
    json_object *l_ohlc = NULL;
    if (json_object_object_get_ex(l_result, "ohlc", &l_ohlc)) {
        int l_count = json_object_array_length(l_ohlc);
        log_it(L_NOTICE, "OHLC candles: %d", l_count);
        if (l_count > 0) {
            json_object *l_first = json_object_array_get_idx(l_ohlc, 0);
            json_object *l_open = NULL, *l_close = NULL, *l_trades = NULL;
            if (json_object_object_get_ex(l_first, "open", &l_open) &&
                json_object_object_get_ex(l_first, "close", &l_close) &&
                json_object_object_get_ex(l_first, "trades", &l_trades)) {
                log_it(L_DEBUG, "  [0] open=%s close=%s trades=%d",
                    json_object_get_string(l_open),
                    json_object_get_string(l_close),
                    json_object_get_int(l_trades));
            }
        }
    }
    
    // Check spot price
    json_object *l_spot = NULL;
    if (json_object_object_get_ex(l_result, "spot", &l_spot)) {
        log_it(L_NOTICE, "Spot price: %s", json_object_get_string(l_spot));
    }
    
    // Check totals
    json_object *l_totals = NULL;
    if (json_object_object_get_ex(l_result, "totals", &l_totals)) {
        json_object *l_vol_base = NULL, *l_trades_total = NULL;
        if (json_object_object_get_ex(l_totals, "volume_base", &l_vol_base) &&
            json_object_object_get_ex(l_totals, "trades", &l_trades_total)) {
            log_it(L_NOTICE, "Totals: volume_base=%s, trades=%d",
                json_object_get_string(l_vol_base),
                json_object_get_int(l_trades_total));
        }
    }
    
    json_object_put(l_json);
    log_it(L_NOTICE, "History OHLC test PASSED");
    return 0;
}

static int s_test_cli_volume(dex_test_fixture_t *fixture) {
    log_it(L_NOTICE, "=== CLI Test: Volume via History (history -view volume) ===");
    
    char l_json_request[1024];
    snprintf(l_json_request, sizeof(l_json_request),
        "{\"method\":\"srv_dex\",\"params\":[\"srv_dex;history;-net;%s;-pair;KEL/USDT;-view;volume;-bucket;3600\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
        fixture->net->net->pub.name);
    
    log_it(L_INFO, "CLI request: %s", l_json_request);
    
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    if (!l_reply) {
        log_it(L_ERROR, "CLI returned NULL");
        return -1;
    }
    
    json_object *l_json = json_tokener_parse(l_reply);
    DAP_DELETE(l_reply);
    if (!l_json) {
        log_it(L_ERROR, "Failed to parse JSON reply");
        return -2;
    }
    
    json_object *l_error = NULL;
    if (json_object_object_get_ex(l_json, "error", &l_error)) {
        log_it(L_ERROR, "CLI returned error: %s", json_object_to_json_string(l_error));
        json_object_put(l_json);
        return -3;
    }
    
    json_object *l_result_raw = NULL;
    if (!json_object_object_get_ex(l_json, "result", &l_result_raw)) {
        log_it(L_ERROR, "No 'result' field in reply");
        json_object_put(l_json);
        return -4;
    }
    
    // JSON-RPC returns result as array, extract first element
    json_object *l_result = json_object_is_type(l_result_raw, json_type_array)
        ? json_object_array_get_idx(l_result_raw, 0) : l_result_raw;
    if (!l_result) {
        log_it(L_ERROR, "Empty result array");
        json_object_put(l_json);
        return -5;
    }
    
    // Check totals (history -view volume returns totals with sum_base/sum_quote)
    json_object *l_totals = NULL;
    if (!json_object_object_get_ex(l_result, "totals", &l_totals)) {
        log_it(L_ERROR, "Missing 'totals' in result");
        json_object_put(l_json);
        return -6;
    }
    
    json_object *l_sum_base = NULL, *l_sum_quote = NULL, *l_trades = NULL;
    if (!json_object_object_get_ex(l_totals, "sum_base", &l_sum_base) ||
        !json_object_object_get_ex(l_totals, "sum_quote", &l_sum_quote) ||
        !json_object_object_get_ex(l_totals, "trades", &l_trades)) {
        log_it(L_ERROR, "Missing sum_base/sum_quote/trades in totals");
        json_object_put(l_json);
        return -7;
    }
    
    int l_trades_count = json_object_get_int(l_trades);
    log_it(L_NOTICE, "Volume totals: sum_base=%s, sum_quote=%s, trades=%d",
        json_object_get_string(l_sum_base),
        json_object_get_string(l_sum_quote),
        l_trades_count);
    
    // STRICT: must have at least one trade
    if (l_trades_count == 0) {
        log_it(L_ERROR, "Expected trades > 0 in volume result");
        json_object_put(l_json);
        return -8;
    }
    
    // Check volume buckets array
    json_object *l_volume = NULL;
    if (json_object_object_get_ex(l_result, "volume", &l_volume)) {
        int l_count = json_object_array_length(l_volume);
        log_it(L_NOTICE, "Volume buckets: %d", l_count);
        
        // Log first bucket
        if (l_count > 0) {
            json_object *l_first = json_object_array_get_idx(l_volume, 0);
            json_object *l_ts = NULL, *l_base = NULL, *l_cnt = NULL;
            if (json_object_object_get_ex(l_first, "ts", &l_ts) &&
                json_object_object_get_ex(l_first, "volume_base", &l_base) &&
                json_object_object_get_ex(l_first, "trades", &l_cnt)) {
                log_it(L_DEBUG, "  [0] ts=%"DAP_UINT64_FORMAT_U" volume_base=%s trades=%d",
                    (uint64_t)json_object_get_int64(l_ts),
                    json_object_get_string(l_base),
                    json_object_get_int(l_cnt));
            }
        }
    }
    
    json_object_put(l_json);
    log_it(L_NOTICE, "Volume test PASSED (trades=%d)", l_trades_count);
    return 0;
}

static int s_test_cli_history_by_order(dex_test_fixture_t *fixture, const char *a_order_hash) {
    log_it(L_NOTICE, "=== CLI Test: History by Order Hash (-order) ===");
    
    if (!a_order_hash || !*a_order_hash) {
        log_it(L_ERROR, "No order hash provided - s_get_first_order_hash() failed");
        return -1;
    }
    
    char l_json_request[1024];
    snprintf(l_json_request, sizeof(l_json_request),
        "{\"method\":\"srv_dex\",\"params\":[\"srv_dex;history;-net;%s;-pair;KEL/USDT;-view;events;-order;%s\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
        fixture->net->net->pub.name, a_order_hash);
    
    log_it(L_INFO, "CLI request: %s", l_json_request);
    
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    if (!l_reply) {
        log_it(L_ERROR, "CLI returned NULL");
        return -2;
    }
    
    json_object *l_json = json_tokener_parse(l_reply);
    DAP_DELETE(l_reply);
    if (!l_json) {
        log_it(L_ERROR, "Failed to parse JSON reply");
        return -3;
    }
    
    json_object *l_error = NULL;
    if (json_object_object_get_ex(l_json, "error", &l_error)) {
        log_it(L_ERROR, "CLI returned error: %s", json_object_to_json_string(l_error));
        json_object_put(l_json);
        return -4;
    }
    
    json_object *l_result_raw = NULL;
    if (!json_object_object_get_ex(l_json, "result", &l_result_raw)) {
        log_it(L_ERROR, "No 'result' field in reply");
        json_object_put(l_json);
        return -5;
    }
    
    // JSON-RPC returns result as array, extract first element
    json_object *l_result = json_object_is_type(l_result_raw, json_type_array)
        ? json_object_array_get_idx(l_result_raw, 0) : l_result_raw;
    if (!l_result) {
        log_it(L_ERROR, "Empty result array");
        json_object_put(l_json);
        return -6;
    }
    
    // Check order_root in response
    json_object *l_order_root = NULL;
    if (json_object_object_get_ex(l_result, "order_root", &l_order_root)) {
        log_it(L_NOTICE, "Resolved order_root: %s", json_object_get_string(l_order_root));
    }
    
    json_object *l_trades = NULL, *l_count = NULL;
    if (!json_object_object_get_ex(l_result, "history", &l_trades) ||
        !json_object_object_get_ex(l_result, "count", &l_count)) {
        log_it(L_ERROR, "Missing 'history' or 'count' in result");
        json_object_put(l_json);
        return -7;
    }
    
    int l_total = json_object_get_int(l_count);
    int l_arr_len = json_object_array_length(l_trades);
    log_it(L_NOTICE, "Events for order %s: count=%d, array_length=%d", a_order_hash, l_total, l_arr_len);
    
    // For a matched order, we expect at least one event
    // Note: if order was never matched, count=0 is valid - but our lifecycle tests DO execute orders
    if (l_total == 0) {
        log_it(L_ERROR, "No events found for order - filter logic might be broken!");
        json_object_put(l_json);
        return -8;
    }
    
    // Log first few trades
    for (int i = 0; i < l_arr_len && i < 5; i++) {
        json_object *l_trade = json_object_array_get_idx(l_trades, i);
        json_object *l_price = NULL, *l_base = NULL, *l_type = NULL, *l_tx = NULL;
        if (json_object_object_get_ex(l_trade, "price", &l_price) &&
            json_object_object_get_ex(l_trade, "base", &l_base) &&
            json_object_object_get_ex(l_trade, "type", &l_type) &&
            json_object_object_get_ex(l_trade, "tx_hash", &l_tx)) {
            log_it(L_DEBUG, "  [%d] price=%s base=%s type=%s tx=%s",
                i, json_object_get_string(l_price),
                json_object_get_string(l_base),
                json_object_get_string(l_type),
                json_object_get_string(l_tx));
        }
    }
    
    json_object_put(l_json);
    log_it(L_NOTICE, "History by order test PASSED (count=%d)", l_total);
    return 0;
}

// Helper: extract prev_tail from first trade (which links to an order that WAS matched)
// This ensures we test -order filter on an order that has actual trades
static const char *s_get_first_order_hash(dex_test_fixture_t *fixture) {
    static char s_hash[128] = {0};
    s_hash[0] = '\0';
    
    // Get first TRADE (not ORDER) - its prev_tail points to the consumed order
    char l_json_request[1024];
    snprintf(l_json_request, sizeof(l_json_request),
        "{\"method\":\"srv_dex\",\"params\":[\"srv_dex;history;-net;%s;-pair;KEL/USDT;-view;events;-type;trade;-limit;1\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
        fixture->net->net->pub.name);
    
    log_it(L_DEBUG, "s_get_first_order_hash: request=%s", l_json_request);
    
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    if (!l_reply) {
        log_it(L_WARNING, "s_get_first_order_hash: CLI returned NULL");
        return NULL;
    }
    
    json_object *l_json = json_tokener_parse(l_reply);
    DAP_DELETE(l_reply);
    if (!l_json) {
        log_it(L_WARNING, "s_get_first_order_hash: failed to parse JSON");
        return NULL;
    }
    
    json_object *l_error = NULL;
    if (json_object_object_get_ex(l_json, "error", &l_error)) {
        log_it(L_WARNING, "s_get_first_order_hash: CLI error: %s", json_object_to_json_string(l_error));
        json_object_put(l_json);
        return NULL;
    }
    
    json_object *l_result_raw = NULL;
    if (!json_object_object_get_ex(l_json, "result", &l_result_raw)) {
        log_it(L_WARNING, "s_get_first_order_hash: no 'result' field");
        json_object_put(l_json);
        return NULL;
    }
    
    // JSON-RPC returns result as array, extract first element
    json_object *l_result = json_object_is_type(l_result_raw, json_type_array)
        ? json_object_array_get_idx(l_result_raw, 0) : l_result_raw;
    if (!l_result) {
        log_it(L_WARNING, "s_get_first_order_hash: empty result array");
        json_object_put(l_json);
        return NULL;
    }
    
    json_object *l_trades = NULL;
    if (!json_object_object_get_ex(l_result, "trades", &l_trades)) {
        log_it(L_WARNING, "s_get_first_order_hash: no 'trades' field");
        json_object_put(l_json);
        return NULL;
    }
    
    int l_len = json_object_array_length(l_trades);
    if (l_len == 0) {
        log_it(L_WARNING, "s_get_first_order_hash: trades array is empty (no trades in history)");
        json_object_put(l_json);
        return NULL;
    }
    
    // Use prev_tail from first trade - this is the order that was consumed
    json_object *l_first = json_object_array_get_idx(l_trades, 0);
    json_object *l_prev_tail = NULL;
    if (json_object_object_get_ex(l_first, "prev_tail", &l_prev_tail)) {
        const char *l_hash_str = json_object_get_string(l_prev_tail);
        // Skip blank hashes (all zeros like 0x0000... or 000000...)
        if (l_hash_str && strspn(l_hash_str, "0xX") != strlen(l_hash_str)) {
            dap_strncpy(s_hash, l_hash_str, sizeof(s_hash) - 1);
            log_it(L_DEBUG, "s_get_first_order_hash: found prev_tail=%s", s_hash);
        } else {
            log_it(L_DEBUG, "s_get_first_order_hash: prev_tail is blank: %s", l_hash_str ? l_hash_str : "(null)");
        }
    }
    
    if (!s_hash[0]) {
        log_it(L_WARNING, "s_get_first_order_hash: no valid prev_tail in first trade (hash=%s)",
            l_prev_tail ? json_object_get_string(l_prev_tail) : "(no field)");
    }
    
    json_object_put(l_json);
    return s_hash[0] ? s_hash : NULL;
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
    
    // Migration tests: legacy SRV_XCHANGE -> SRV_DEX
    ret = run_migration_tests(fixture);
    if (ret != 0) {
        log_it(L_ERROR, "Migration tests FAILED with code %d", ret);
        dex_test_fixture_destroy(fixture);
        s_teardown();
        return ret;
    }
    
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
    
    dap_chain_net_srv_dex_dump_history_cache();
    
    // Test bucket calendar alignment (while history has data)
    ret = s_test_cli_bucket_alignment(fixture);
    if (ret != 0) {
        log_it(L_WARNING, "Bucket alignment test failed with code %d (non-fatal)", ret);
    }
    
    // Test raw trades output - STRICT (requires cache)
    if (s_cache_enabled) {
        ret = s_test_cli_raw_trades(fixture);
        if (ret != 0) {
            log_it(L_ERROR, "Raw trades test FAILED with code %d", ret);
            dex_test_fixture_destroy(fixture);
            s_teardown();
            return ret;
        }
    } else {
        log_it(L_WARNING, "Skipping raw trades test (requires cache)");
    }
    
    // Test history -type order filter - STRICT (requires cache)
    if (s_cache_enabled) {
        ret = s_test_cli_history_orders(fixture);
        if (ret != 0) {
            log_it(L_ERROR, "History orders test FAILED with code %d", ret);
            dex_test_fixture_destroy(fixture);
            s_teardown();
            return ret;
        }
    } else {
        log_it(L_WARNING, "Skipping history orders test (requires cache)");
    }
    
    // Test history -view ohlc -bucket
    ret = s_test_cli_history_ohlc(fixture);
    if (ret != 0) {
        log_it(L_ERROR, "History OHLC test FAILED with code %d", ret);
        dex_test_fixture_destroy(fixture);
        s_teardown();
        return ret;
    }
    
    // Test volume command with history cache - STRICT
    ret = s_test_cli_volume(fixture);
    if (ret != 0) {
        log_it(L_ERROR, "Volume test FAILED with code %d", ret);
        dex_test_fixture_destroy(fixture);
        s_teardown();
        return ret;
    }
    
    // Test history -order <hash> (requires cache for s_get_first_order_hash helper)
    if (s_cache_enabled) {
        const char *l_order_hash = s_get_first_order_hash(fixture);
        ret = s_test_cli_history_by_order(fixture, l_order_hash);
        if (ret != 0) {
            log_it(L_ERROR, "History by order test FAILED with code %d", ret);
            dex_test_fixture_destroy(fixture);
            s_teardown();
            return ret;
        }
    } else {
        log_it(L_WARNING, "Skipping history by order test (requires cache)");
    }
    
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

    // Cancel with extra native input (cashback scenario)
    ret = run_cancel_extra_native_input_tests(fixture);
    if (ret != 0) {
        log_it(L_ERROR, "Cancel extra native input tests FAILED with code %d", ret);
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
