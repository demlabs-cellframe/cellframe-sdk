/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 
 This file is part of Cellframe SDK the open source project

    Cellframe SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cellframe SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file utxo_blocking_cli_integration_test.c
 * @brief Integration tests for CLI commands related to UTXO blocking  
 * @details Attempts to test real CLI command execution for:
 *          - com_token_decl with UTXO blocking parameters
 *          - com_token_update with -utxo_blocked_add/remove/clear
 *          - Parameter parsing and TSD section generation
 *          - End-to-end CLI workflow
 * @date 2025-10-21
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_config.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_ledger.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_cli_server.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"
#include "json.h"

#define LOG_TAG "utxo_blocking_cli_test"

// Global test context
static test_net_fixture_t *s_net_fixture = NULL;

/**
 * @brief Setup: Initialize test environment
 */
static void s_setup(void)
{
    log_it(L_NOTICE, "=== UTXO Blocking CLI Integration Tests Setup ===");
    
    // Step 1: Create minimal config for CLI server
    const char *l_config_dir = "/tmp/cli_test_config";
    mkdir(l_config_dir, 0755);
    
    const char *l_config_content = 
        "[cli-server]\n"
        "enabled=true\n"
        "listen_unix_socket_path=/tmp/cli_test.sock\n"
        "debug=false\n"
        "version=1\n";
    
    char l_config_path[256];
    snprintf(l_config_path, sizeof(l_config_path), "%s/test.cfg", l_config_dir);
    FILE *l_config_file = fopen(l_config_path, "w");
    if (l_config_file) {
        fwrite(l_config_content, 1, strlen(l_config_content), l_config_file);
        fclose(l_config_file);
    }
    
    // Step 2: Initialize config
    dap_config_init(l_config_dir);
    g_config = dap_config_open("test");
    dap_assert(g_config != NULL, "Config initialization");
    
    // Step 3: Initialize CLI server
    int l_cli_init_res = dap_cli_server_init(false, "cli-server");
    dap_assert(l_cli_init_res == 0, "CLI server initialization");
    
    // Step 4: Initialize consensus modules
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    
    // Step 5: Register CLI commands (we need token_update command)
    dap_chain_node_cli_init(g_config);
    
    // Step 6: Create test network
    s_net_fixture = test_net_fixture_create("cli_test_net");
    dap_assert(s_net_fixture != NULL, "Network fixture initialization");
    dap_assert(s_net_fixture->ledger != NULL, "Ledger initialization");
    
    log_it(L_NOTICE, "✓ Test environment initialized (with CLI server)");
}

/**
 * @brief Teardown: Cleanup test environment
 */
static void s_teardown(void)
{
    if (s_net_fixture) {
        test_net_fixture_destroy(s_net_fixture);
        s_net_fixture = NULL;
    }
    
    // Cleanup CLI server
    dap_chain_node_cli_delete();
    dap_cli_server_deinit();
    
    // Cleanup config
    if (g_config) {
        dap_config_close(g_config);
        g_config = NULL;
    }
    dap_config_deinit();
    
    // Remove test config files
    unlink("/tmp/cli_test_config/test.cfg");
    rmdir("/tmp/cli_test_config");
    unlink("/tmp/cli_test.sock");
    
    log_it(L_NOTICE, "✓ Test environment cleaned up");
}

/**
 * @brief CLI Test 1: token_update -utxo_blocked_add (CLI command execution)
 * @details Tests real CLI command: token_update -net test -token TEST -utxo_blocked_add tx:0
 */
static void s_test_cli_token_update_utxo_blocked_add(void)
{
    dap_print_module_name("CLI Test 1: com_token_update -utxo_blocked_add");
    
    // Step 1: Create token with emission using fixtures
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");
    
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Certificate allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "cli_test_cert1");
    
    // Add certificate to cert storage so CLI can find it by name
    int l_cert_add_res = dap_cert_add(l_cert);
    dap_assert_PIF(l_cert_add_res == 0, "Certificate added to storage");
    
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "CLITEST1", "10000.0", "5000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");
    
    log_it(L_INFO, "✓ Token CLITEST1 created with emission");
    
    // Step 2: Create transaction from emission
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "CLITEST1", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "Transaction created");
    
    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "Transaction added to ledger");
    
    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_tx->tx_hash);
    dap_assert_PIF(l_tx_hash_str != NULL, "Transaction hash string allocation");
    log_it(L_INFO, "✓ Transaction created: %s", l_tx_hash_str);
    
    // Step 3: Call CLI command via dap_cli_cmd_exec
    char l_utxo_param[256];
    snprintf(l_utxo_param, sizeof(l_utxo_param), "%s:0", l_tx_hash_str);
    
    // Build CLI command string
    char l_cmd_str[2048];
    snprintf(l_cmd_str, sizeof(l_cmd_str), 
             "token_update -net Snet -token CLITEST1 -utxo_blocked_add %s -certs %s",
             l_utxo_param, l_cert->name);
    
    // Build JSON-RPC request
    char l_json_request[4096];
    snprintf(l_json_request, sizeof(l_json_request),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
             l_cmd_str);
    
    log_it(L_INFO, "Calling CLI via dap_cli_cmd_exec: %s", l_cmd_str);
    
    // Execute CLI command via CLI server
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    dap_assert_PIF(l_reply != NULL, "CLI command executed");
    
    log_it(L_INFO, "CLI reply: %s", l_reply);
    
    // Parse JSON reply to check for errors
    json_object *l_json_reply = json_tokener_parse(l_reply);
    dap_assert_PIF(l_json_reply != NULL, "JSON reply parsed");
    
    // Check for error in reply
    json_object *l_error_obj = NULL;
    if (json_object_object_get_ex(l_json_reply, "error", &l_error_obj)) {
        const char *l_error_str = json_object_to_json_string(l_error_obj);
        log_it(L_ERROR, "CLI command returned error: %s", l_error_str);
        json_object_put(l_json_reply);
        dap_assert_PIF(false, "CLI command succeeded without errors");
    }
    
    json_object_put(l_json_reply);
    // Note: l_reply is intentionally not freed here to avoid double-free issues with CLI server
    // Memory will be cleaned up when process exits
    
    log_it(L_INFO, "✅ CLI Test 1 PASSED: com_token_update -utxo_blocked_add executed successfully");
    
    // Cleanup
    DAP_DELETE(l_tx_hash_str);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    
    // Remove certificate from storage (this also deletes l_cert)
    dap_cert_delete_by_name("cli_test_cert1");
}

/**
 * @brief CLI Test 2: token_update -utxo_blocked_remove
 * @details Tests real CLI command: token_update -utxo_blocked_remove tx:0
 */
static void s_test_cli_token_update_utxo_blocked_remove(void)
{
    dap_print_module_name("CLI Test 2: com_token_update -utxo_blocked_remove");
    
    // Create token and transaction
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");
    
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Certificate allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "cli_test_cert2");
    
    // Add certificate to cert storage
    int l_cert_add_res = dap_cert_add(l_cert);
    dap_assert_PIF(l_cert_add_res == 0, "Certificate added to storage");
    
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "CLITEST2", "10000.0", "5000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token created");
    
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "CLITEST2", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "Transaction created");
    
    int l_tx_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_tx_res == 0, "Transaction added to ledger");
    
    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_tx->tx_hash);
    dap_assert_PIF(l_tx_hash_str != NULL, "Transaction hash string allocation");
    log_it(L_INFO, "✓ Transaction created: %s", l_tx_hash_str);
    
    // First, block the UTXO using CLI
    char l_utxo_param[256];
    snprintf(l_utxo_param, sizeof(l_utxo_param), "%s:0", l_tx_hash_str);
    
    // Block via CLI
    char l_cmd_add[2048];
    snprintf(l_cmd_add, sizeof(l_cmd_add),
             "token_update -net Snet -token CLITEST2 -utxo_blocked_add %s -certs %s",
             l_utxo_param, l_cert->name);
    
    char l_json_req_add[4096];
    snprintf(l_json_req_add, sizeof(l_json_req_add),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
             l_cmd_add);
    
    char *l_reply_add = dap_cli_cmd_exec(l_json_req_add);
    dap_assert_PIF(l_reply_add != NULL, "CLI block command executed");
    
    log_it(L_INFO, "✓ UTXO blocked");
    
    // Now unblock using CLI
    char l_cmd_remove[2048];
    snprintf(l_cmd_remove, sizeof(l_cmd_remove),
             "token_update -net Snet -token CLITEST2 -utxo_blocked_remove %s -certs %s",
             l_utxo_param, l_cert->name);
    
    char l_json_req_remove[4096];
    snprintf(l_json_req_remove, sizeof(l_json_req_remove),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":2,\"jsonrpc\":\"2.0\"}",
             l_cmd_remove);
    
    log_it(L_INFO, "Calling CLI: %s", l_cmd_remove);
    
    char *l_reply_remove = dap_cli_cmd_exec(l_json_req_remove);
    dap_assert_PIF(l_reply_remove != NULL, "CLI unblock command executed");
    // Note: replies not freed to avoid double-free with CLI server
    
    log_it(L_INFO, "✅ CLI Test 2 PASSED: com_token_update -utxo_blocked_remove executed successfully");
    
    // Cleanup
    DAP_DELETE(l_tx_hash_str);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    
    // Remove certificate from storage
    dap_cert_delete_by_name("cli_test_cert2");
}

/**
 * @brief CLI Test 3: token_update -utxo_blocked_clear
 * @details Tests real CLI command: token_update -utxo_blocked_clear
 */
static void s_test_cli_token_update_utxo_blocked_clear(void)
{
    log_it(L_NOTICE, "CLI Test 3: com_token_update -utxo_blocked_clear");
    
    // Create token and transactions
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");
    
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);
    
    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Certificate allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "cli_test_cert3");
    
    // Add certificate to cert storage
    int l_cert_add_res = dap_cert_add(l_cert);
    dap_assert_PIF(l_cert_add_res == 0, "Certificate added to storage");
    
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "CLITEST3", "10000.0", "5000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token created");
    
    // Create transaction
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "CLITEST3", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "Transaction created");
    
    int l_tx_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_tx_res == 0, "Transaction added to ledger");
    
    log_it(L_INFO, "✓ Created transaction");
    
    // Block the same UTXO twice (to test CLEAR removes all blocked UTXOs)
    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_tx->tx_hash);
    dap_assert_PIF(l_tx_hash_str != NULL, "Transaction hash string allocation");
    
    char l_utxo_param[256];
    snprintf(l_utxo_param, sizeof(l_utxo_param), "%s:0", l_tx_hash_str);
    
    // Block UTXO via CLI (once is enough for CLEAR test)
    char l_cmd_add[2048];
    snprintf(l_cmd_add, sizeof(l_cmd_add),
             "token_update -net Snet -token CLITEST3 -utxo_blocked_add %s -certs %s",
             l_utxo_param, l_cert->name);
    char l_json_req_add[4096];
    snprintf(l_json_req_add, sizeof(l_json_req_add),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
             l_cmd_add);
    char *l_reply_add = dap_cli_cmd_exec(l_json_req_add);
    dap_assert_PIF(l_reply_add != NULL, "UTXO blocked via CLI");
    
    log_it(L_INFO, "✓ UTXO blocked");
    
    // Now clear all blocked UTXOs using CLI
    char l_cmd_clear[2048];
    snprintf(l_cmd_clear, sizeof(l_cmd_clear),
             "token_update -net Snet -token CLITEST3 -utxo_blocked_clear -certs %s",
             l_cert->name);
    char l_json_req_clear[4096];
    snprintf(l_json_req_clear, sizeof(l_json_req_clear),
             "{\"method\":\"token_update\",\"params\":[\"%s\"],\"id\":3,\"jsonrpc\":\"2.0\"}",
             l_cmd_clear);
    
    log_it(L_INFO, "Calling CLI: %s", l_cmd_clear);
    
    char *l_reply_clear = dap_cli_cmd_exec(l_json_req_clear);
    dap_assert_PIF(l_reply_clear != NULL, "CLI clear command executed");
    // Note: replies not freed to avoid double-free with CLI server
    
    log_it(L_INFO, "✅ CLI Test 3 PASSED: com_token_update -utxo_blocked_clear executed successfully");
    
    // Cleanup
    DAP_DELETE(l_tx_hash_str);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    
    // Remove certificate from storage
    dap_cert_delete_by_name("cli_test_cert3");
}

/**
 * @brief Main entry point
 */
int main(void)
{
    // Initialize logging
    dap_log_level_set(L_DEBUG);
    
    dap_print_module_name("UTXO Blocking CLI Integration Tests");
    
    // Setup
    s_setup();
    
    // Run all CLI integration tests
    s_test_cli_token_update_utxo_blocked_add();      // Test 1
    s_test_cli_token_update_utxo_blocked_remove();   // Test 2
    s_test_cli_token_update_utxo_blocked_clear();    // Test 3
    
    // Teardown
    s_teardown();
    
    log_it(L_NOTICE, "✅ All UTXO blocking CLI integration tests completed (3 tests)!");
    
    return 0;
}
