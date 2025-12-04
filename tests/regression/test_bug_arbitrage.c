/*
 * Regression tests for Arbitrage Transaction bugs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_config.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_tsd.h"
#include "dap_tsd.h"
#include "dap_chain_ledger.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_none.h"
#include "dap_cli_server.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_node.h"
#include "dap_cert_file.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_mempool.h"
#include "dap_chain_wallet.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"
#include "utxo_blocking_test_helpers.h"
#include "dap_config.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_file_utils.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_cs_none.h"
#include <json-c/json.h>

#define LOG_TAG "regression_arbitrage_test"

// Helper to create base transaction from emission
static dap_chain_datum_tx_t *s_create_base_tx_from_emission(
    dap_chain_datum_token_emission_t *a_emission,
    dap_chain_hash_fast_t *a_emission_hash,
    dap_chain_addr_t *a_addr_to,
    dap_cert_t *a_cert)
{
    dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
    l_tx->header.ts_created = time(NULL);
    
    // Add input from emission
    dap_chain_tx_in_ems_t l_in_ems = {
        .header = {
            .type = TX_ITEM_TYPE_IN_EMS,
            .token_emission_chain_id = {.uint64 = 0},
            .token_emission_hash = *a_emission_hash
        }
    };
    strcpy(l_in_ems.header.ticker, a_emission->hdr.ticker);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)&l_in_ems);
    
    // Add output with full emission value (no fee for base tx)
    dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, a_emission->hdr.value, a_emission->hdr.ticker);
    
    // Sign transaction
    dap_chain_datum_tx_add_sign_item(&l_tx, a_cert->enc_key);
    
    return l_tx;
}

// Test constants
#define ARBITRAGE_TX_VALUE "1000.0"
#define ARBITRAGE_TX_VALUE_DATOSHI "1000000000000000000000" // 1000.0 * 10^18
#define ARBITRAGE_FEE "0.1"
#define TEST_TOKEN_TICKER "REGARB"  // Changed to alpha-numeric only
#define TEST_TOKEN_SUPPLY "1000000.0"

// Global test context
test_net_fixture_t *s_net_fixture = NULL;

static void s_setup(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    log_it(L_NOTICE, "=== Regression Tests: Arbitrage Bugs Setup ===");
    
    // Clean up
    system("rm -rf /tmp/reg_test_gdb");
    system("rm -rf /tmp/reg_test_certs");
    system("rm -rf /tmp/reg_test_config");
    system("rm -rf /tmp/reg_test_wallets");
    
    // Create config
    dap_mkdir_with_parents("/tmp/reg_test_config");
    dap_mkdir_with_parents("/tmp/reg_test_wallets");
    FILE *l_cfg = fopen("/tmp/reg_test_config/test.cfg", "w");
    if (l_cfg) {
        fprintf(l_cfg, "[general]\ndebug_mode=true\n\n[cli-server]\nenabled=true\n\n[resources]\nwallets_path=/tmp/reg_test_wallets\n");
        fclose(l_cfg);
    }
    
    // Initialize consensus modules
    dap_chain_cs_init();
    dap_chain_cs_dag_init();  // Must be called before dap_chain_cs_dag_poa_init()
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    dap_nonconsensus_init();
    
    // Create test environment
    test_env_init("/tmp/reg_test_config", "/tmp/reg_test_gdb");
    s_net_fixture = test_net_fixture_create("RegNet");
    dap_assert_PIF(s_net_fixture != NULL, "Network fixture created");
    
    // Init CLI
    dap_chain_node_cli_init(g_config);
}

static void s_cleanup(void)
{
    log_it(L_NOTICE, "=== Regression Tests: Cleanup ===");
    if (s_net_fixture) {
        test_net_fixture_destroy(s_net_fixture);
        s_net_fixture = NULL;
    }
    dap_chain_node_cli_delete();
    test_env_deinit();
    system("rm -rf /tmp/reg_test_gdb");
    system("rm -rf /tmp/reg_test_certs");
    system("rm -rf /tmp/reg_test_config");
    system("rm -rf /tmp/reg_test_wallets");
}

// Helper to create token, emission and base transaction
// Returns token fixture so caller can access token owner certificate
static test_token_fixture_t *s_create_token_and_emission(const char *a_ticker, dap_chain_addr_t *a_addr_owner, dap_cert_t *a_cert_owner)
{
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, a_ticker, TEST_TOKEN_SUPPLY, TEST_TOKEN_SUPPLY, a_addr_owner, a_cert_owner, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token created with emission");
    
    // Create base transaction to activate emission and credit balance
    // Get emission from ledger
    dap_chain_datum_token_emission_t *l_emission = (dap_chain_datum_token_emission_t *)
        dap_ledger_token_emission_find(s_net_fixture->ledger, &l_emission_hash);
    dap_assert_PIF(l_emission != NULL, "Emission found in ledger");
    
    // Create base TX using helper
    dap_chain_datum_tx_t *l_base_tx = s_create_base_tx_from_emission(
        l_emission, &l_emission_hash, a_addr_owner, a_cert_owner);
    dap_assert_PIF(l_base_tx != NULL, "Base TX created");
    
    // Add base TX to ledger
    size_t l_base_tx_size = dap_chain_datum_tx_get_size(l_base_tx);
    dap_hash_fast_t l_base_tx_hash;
    dap_hash_fast(l_base_tx, l_base_tx_size, &l_base_tx_hash);
    
    int l_add_result = dap_ledger_tx_add(s_net_fixture->ledger, l_base_tx, &l_base_tx_hash, false, NULL);
    dap_assert_PIF(l_add_result == 0, "Base TX added to ledger");
    
    log_it(L_INFO, "Token %s emission activated with base transaction", a_ticker);
    
    // Process mempool to ledger (if any pending datums)
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);
    
    return l_token;  // Return fixture so caller can access owner certificate
}

/**
 * @brief Test Bug #1: Arbitrage transaction creation availability
 * Expectation: Should be able to create arbitrage transaction immediately after token emission
 */
static void test_bug_arbitrage_availability(void)
{
    log_it(L_INFO, "TEST: Bug #1 - Arbitrage Availability");
    
    // 1. Create wallet FIRST to get consistent key/address
    dap_mkdir_with_parents("/tmp/reg_test_wallets");  // Create wallet directory
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_create_with_seed("reg_wallet_avail", "/tmp/reg_test_wallets", (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, NULL, 0, NULL);
    dap_assert_PIF(l_wallet != NULL, "Wallet created");
    
    // 2. Get key and address from wallet (not vice versa!)
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);
    
    log_it(L_INFO, "Wallet address from chain: %s", dap_chain_addr_to_str(&l_addr));
    
    // 3. Create cert and tokens/emissions
    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "reg_test_cert_avail");
    dap_cert_add(l_cert);
    
    // IMPORTANT: Create token and get fixture to access token owner certificate
    // The token will be created with its own internal certificate (token owner)
    // which may be different from the wallet certificate
    test_token_fixture_t *l_token_fixture = s_create_token_and_emission(TEST_TOKEN_TICKER, &l_addr, l_cert);
    dap_cert_t *l_token_owner_cert = l_token_fixture->owner_cert;
    
    // Add token owner certificate to system so it can be found by name via -certs parameter
    // This is necessary because CLI looks up certificates by name
    dap_cert_add(l_token_owner_cert);
    
    log_it(L_INFO, "Token owner certificate added to system: %s", l_token_owner_cert->name);
    
    // Create TestCoin token and emission for fee payment
    s_create_token_and_emission("TestCoin", &l_addr, l_cert);
    
    // Set fee for network (0.1 TestCoin)
    uint256_t l_fee_value = dap_chain_balance_scan(ARBITRAGE_FEE);
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_fee_value, l_addr);
    
    // Check balances before creating transaction (for debugging)
    uint256_t l_balance_regarb = dap_ledger_calc_balance(s_net_fixture->ledger, &l_addr, TEST_TOKEN_TICKER);
    uint256_t l_balance_testcoin = dap_ledger_calc_balance(s_net_fixture->ledger, &l_addr, "TestCoin");
    char *l_bal_regarb_str = dap_chain_balance_to_coins(l_balance_regarb);
    char *l_bal_testcoin_str = dap_chain_balance_to_coins(l_balance_testcoin);
    log_it(L_INFO, "Wallet balances: REGARB=%s, TestCoin=%s", l_bal_regarb_str, l_bal_testcoin_str);
    DAP_DELETE(l_bal_regarb_str);
    DAP_DELETE(l_bal_testcoin_str);
    
    // 3. Attempt to create arbitrage transaction immediately
    char l_cmd[2048];

    // Command: tx_create -net ... -chain ... -from_wallet ... -token ... -value ... -arbitrage -certs ...
    // Note: -to_addr is omitted for arbitrage (fee address is used automatically)
    // NOTE: -certs parameter is REQUIRED for arbitrage transactions to provide token owner signature
    
    snprintf(l_cmd, sizeof(l_cmd), 
             "tx_create -net %s -chain %s -from_wallet reg_wallet_avail -token %s -value %s -arbitrage -fee %s -certs %s",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             TEST_TOKEN_TICKER, ARBITRAGE_TX_VALUE, ARBITRAGE_FEE, l_token_owner_cert->name);
    
    log_it(L_INFO, "Creating arbitrage TX with command: %s", l_cmd);
    
    // Convert to JSON-RPC format
    char l_json_req[4096];
    char *l_json_req_ptr = utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd, "tx_create",
                                                                    l_json_req, sizeof(l_json_req), 1);
    dap_assert_PIF(l_json_req_ptr != NULL, "JSON-RPC request created");
    
    log_it(L_INFO, "JSON-RPC request: %s", l_json_req);
             
    // Execute
    log_it(L_INFO, "Executing dap_cli_cmd_exec...");
    char *l_reply = dap_cli_cmd_exec(l_json_req);
    log_it(L_INFO, "Execution completed, reply: %s", l_reply ? l_reply : "NULL");
    log_it(L_INFO, "tx_create reply: %s", l_reply ? l_reply : "NULL");
    
    // Check for success (hash)
    dap_assert_PIF(l_reply != NULL, "Reply received");
    
    // Parse JSON-RPC response
    json_object *l_json = json_tokener_parse(l_reply);
    dap_assert_PIF(l_json != NULL, "JSON reply parsed");
    
    // Get result field
    json_object *l_json_result = NULL;
    if (json_object_object_get_ex(l_json, "result", &l_json_result)) {
        const char *l_result_str = json_object_get_string(l_json_result);
        if (l_result_str && strstr(l_result_str, "0x")) {
            log_it(L_INFO, "✓ Arbitrage transaction created successfully (immediate): %s", l_result_str);
        } else {
            log_it(L_ERROR, "✗ Arbitrage transaction failed: %s", l_result_str ? l_result_str : "NULL");
            json_object_put(l_json);
            DAP_DELETE(l_reply);
            dap_assert_PIF(false, "Arbitrage TX created");
        }
    } else {
        log_it(L_ERROR, "✗ No result field in JSON response");
        json_object_put(l_json);
        DAP_DELETE(l_reply);
        dap_assert_PIF(false, "Arbitrage TX created");
    }
    
    json_object_put(l_json);
    DAP_DELETE(l_reply);
    dap_chain_wallet_close(l_wallet);
}

/**
 * @brief Test Bug #2: Arbitrage transaction arguments (-value, -token)
 * Expectation: -value and -token flags should be respected
 */
static void test_bug_arbitrage_arguments(void)
{
    log_it(L_INFO, "TEST: Bug #2 - Arbitrage Arguments");
    
    // NOTE: Do NOT reset network fee to zero here!
    // The fee address MUST be configured for arbitrage transactions to work
    // We'll set it later with the new wallet address
    // dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, uint256_0, (dap_chain_addr_t){});
    
    // 1. Create wallet FIRST to get consistent key/address
    dap_mkdir_with_parents("/tmp/reg_test_wallets");  // Create wallet directory
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_create_with_seed("reg_wallet_args", "/tmp/reg_test_wallets", (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, NULL, 0, NULL);
    dap_assert_PIF(l_wallet != NULL, "Wallet created");
    
    // 2. Get key and address from wallet
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);
    
    log_it(L_INFO, "Second test wallet address: %s", dap_chain_addr_to_str(&l_addr));
    log_it(L_INFO, "Second test wallet pointer: %p", l_wallet);
    
    // 3. Create cert and tokens/emissions
    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "reg_test_cert_args");
    dap_cert_add(l_cert);
    
    // IMPORTANT: Reset fee BEFORE creating tokens to avoid fee requirement on base transactions
    // We'll set it again after creating tokens
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, uint256_0, l_addr);
    
    // IMPORTANT: Change native ticker to TestCoin2 for this test (to avoid conflict with first test's TestCoin)
    // Save original ticker to restore later
    const char *l_original_native_ticker = s_net_fixture->net->pub.native_ticker;
    s_net_fixture->net->pub.native_ticker = "TestCoin2";
    
    const char *l_ticker = "REGARGS";  // Changed to alpha-numeric only and within size limit
    
    // IMPORTANT: Create TestCoin2 FIRST to ensure wallet has funds for paying base TX fee
    // Base transaction for REGARGS will need to pay fee in TestCoin2
    // This must be done BEFORE creating REGARGS token
    // Use TestCoin2 to avoid conflict with first test's TestCoin
    s_create_token_and_emission("TestCoin2", &l_addr, l_cert);
    
    // IMPORTANT: Get token owner certificate for arbitrage authorization
    test_token_fixture_t *l_token_fixture = s_create_token_and_emission(l_ticker, &l_addr, l_cert);
    dap_cert_t *l_token_owner_cert = l_token_fixture->owner_cert;
    
    // Add token owner certificate to system so it can be found by name via -certs parameter
    dap_cert_add(l_token_owner_cert);
    
    log_it(L_INFO, "Token owner certificate added to system: %s", l_token_owner_cert->name);
    
    // Set fee for network
    uint256_t l_fee_value = dap_chain_balance_scan(ARBITRAGE_FEE);
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_fee_value, l_addr);
    
    // 4. Create Arbitrage TX with specific VALUE
    // Use a specific weird value to check
    const char *l_value_check = "123.456"; 
    // Datoshi: 123456000000000000000
    
    char l_cmd[2048];
    snprintf(l_cmd, sizeof(l_cmd), 
             "tx_create -net %s -chain %s -from_wallet reg_wallet_args -token %s -value %s -arbitrage -fee %s -certs %s",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             l_ticker, l_value_check, ARBITRAGE_FEE, l_token_owner_cert->name);
    
    // Convert to JSON-RPC format
    char l_json_req[4096];
    char *l_json_req_ptr = utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd, "tx_create",
                                                                    l_json_req, sizeof(l_json_req), 1);
    dap_assert_PIF(l_json_req_ptr != NULL, "JSON-RPC request created");
             
    char *l_reply = dap_cli_cmd_exec(l_json_req);
    log_it(L_INFO, "tx_create reply: %s", l_reply ? l_reply : "NULL");
    
    dap_assert_PIF(l_reply != NULL, "Arbitrage TX reply received");
    
    // Parse JSON-RPC response
    json_object *l_json = json_tokener_parse(l_reply);
    dap_assert_PIF(l_json != NULL, "JSON reply parsed");
    
    // Get result field
    json_object *l_json_result = NULL;
    dap_assert_PIF(json_object_object_get_ex(l_json, "result", &l_json_result), "Result field exists");
    
    const char *l_result_str = json_object_get_string(l_json_result);
    dap_assert_PIF(l_result_str && strstr(l_result_str, "0x"), "Arbitrage TX created");
    
    // Extract hash (format is "Transaction successfully placed to mempool with hash 0x...")
    char *l_hash_str = strstr(l_result_str, "0x");
    if (l_hash_str) {
        char l_hash_hex[67] = {0};
        // Copy just the hash part (66 characters after 0x)
        strncpy(l_hash_hex, l_hash_str, 66);
        
        // 3. Verify transaction details in mempool
        dap_chain_hash_fast_t l_tx_hash;
        dap_chain_hash_fast_from_str(l_hash_hex, &l_tx_hash);
        
        char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(&l_tx_hash);
        dap_chain_datum_t *l_datum = dap_chain_mempool_datum_get(s_net_fixture->chain_main, l_tx_hash_str);
        DAP_DELETE(l_tx_hash_str);
        
        dap_assert_PIF(l_datum != NULL, "Datum found in mempool");
        dap_assert_PIF(l_datum->header.type_id == DAP_CHAIN_DATUM_TX, "Datum is a transaction");
        
        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
        dap_assert_PIF(l_tx != NULL, "Transaction found in mempool");
        
        // Check output value
        dap_list_t *l_out_list = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
        bool l_found_value = false;
        
        uint256_t l_val_expected = dap_chain_balance_scan(l_value_check);
        
        log_it(L_INFO, "Looking for output value: %s", l_value_check);
        
        // Get transaction items
        dap_list_t *l_all_items = dap_chain_datum_tx_items_get(l_tx, TX_ITEM_TYPE_ANY, NULL);
        for (dap_list_t *it = l_all_items; it; it = it->next) {
            byte_t *l_item_ptr = (byte_t*)it->data;
            byte_t l_type = *l_item_ptr;
            
            if (l_type == TX_ITEM_TYPE_OUT_STD) {
                dap_chain_tx_out_std_t *l_out_std = (dap_chain_tx_out_std_t*)l_item_ptr;
                const char *l_val_str_balance, *l_val_str = dap_uint256_to_char(l_out_std->value, &l_val_str_balance);
                log_it(L_INFO, "Found OUT_STD: value=%s (%s), token=%s, address=%s", 
                       l_val_str ? l_val_str : "NULL", 
                       l_val_str_balance ? l_val_str_balance : "NULL",
                       l_out_std->token,
                       dap_chain_addr_to_str_static(&l_out_std->addr));
            } else if (l_type == TX_ITEM_TYPE_OUT) {
                dap_chain_tx_out_t *l_out = (dap_chain_tx_out_t*)l_item_ptr;
                const char *l_val_str_balance, *l_val_str = dap_uint256_to_char(l_out->header.value, &l_val_str_balance);
                log_it(L_INFO, "Found OUT: value=%s (%s), address=%s", 
                       l_val_str ? l_val_str : "NULL", 
                       l_val_str_balance ? l_val_str_balance : "NULL",
                       dap_chain_addr_to_str_static(&l_out->addr));
            } else if (l_type == TX_ITEM_TYPE_OUT_EXT) {
                dap_chain_tx_out_ext_t *l_out_ext = (dap_chain_tx_out_ext_t*)l_item_ptr;
                const char *l_val_str_balance, *l_val_str = dap_uint256_to_char(l_out_ext->header.value, &l_val_str_balance);
                log_it(L_INFO, "Found OUT_EXT: value=%s (%s), token=%s, address=%s", 
                       l_val_str ? l_val_str : "NULL", 
                       l_val_str_balance ? l_val_str_balance : "NULL",
                       l_out_ext->token,
                       dap_chain_addr_to_str_static(&l_out_ext->addr));
            }
        }
        dap_list_free(l_all_items);
        
        for (dap_list_t *it = l_out_list; it; it = it->next) {
            byte_t l_item_type = *(byte_t*)it->data;
            uint256_t l_val_out = {};
            const char *l_token_ticker = NULL;
            
            if (l_item_type == TX_ITEM_TYPE_OUT_STD) {
                dap_chain_tx_out_std_t *l_out_std = (dap_chain_tx_out_std_t*)it->data;
                l_val_out = l_out_std->value;
                l_token_ticker = l_out_std->token;
            } else if (l_item_type == TX_ITEM_TYPE_OUT) {
                l_val_out = ((dap_chain_tx_out_t*)it->data)->header.value;
                l_token_ticker = l_ticker;  // OUT doesn't store token, assume it's the arbitrage token
            } else if (l_item_type == TX_ITEM_TYPE_OUT_EXT) {
                dap_chain_tx_out_ext_t *l_out_ext = (dap_chain_tx_out_ext_t*)it->data;
                l_val_out = l_out_ext->header.value;
                l_token_ticker = l_out_ext->token;
            }
            
            const char *l_val_str_balance, *l_val_str = dap_uint256_to_char(l_val_out, &l_val_str_balance);
            log_it(L_INFO, "Checking output: value=%s (%s), token=%s", 
                   l_val_str ? l_val_str : "NULL", 
                   l_val_str_balance ? l_val_str_balance : "NULL",
                   l_token_ticker ? l_token_ticker : "unknown");
            
            // Check if this output is for REGARGS token AND has the expected value
            if (l_token_ticker && strcmp(l_token_ticker, l_ticker) == 0 && EQUAL_256(l_val_out, l_val_expected)) {
                l_found_value = true;
                break;
            }
        }
        dap_list_free(l_out_list);
        
        if (l_found_value) {
            log_it(L_INFO, "✓ Transaction output matches requested value %s", l_value_check);
        } else {
            log_it(L_ERROR, "✗ Transaction output does NOT match requested value %s", l_value_check);
            json_object_put(l_json);
            DAP_DELETE(l_reply);
            dap_assert_PIF(false, "Value argument respected");
        }
    }
    
    json_object_put(l_json);
    DAP_DELETE(l_reply);
    dap_chain_wallet_close(l_wallet);
}

int main(int argc, char **argv)
{
    dap_print_module_name("Arbitrage Regression Tests");
    
    // Setup
    s_setup();
    
    // Tests
    test_bug_arbitrage_availability();
    test_bug_arbitrage_arguments();
    
    // Cleanup
    s_cleanup();
    
    return 0;
}
