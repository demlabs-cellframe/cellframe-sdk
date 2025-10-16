/**
 * @file test_transaction_fixtures.c
 * @brief Implementation of transaction test fixtures
 */

#include "test_transaction_fixtures.h"
#include "dap_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_ledger.h"
#include "dap_hash.h"
#include "dap_enc_key.h"
#include "dap_sign.h"
#include "dap_math_ops.h"

#define LOG_TAG "test_transaction_fixtures"

/**
 * @brief Create a test key for transaction signing
 * @return dap_enc_key_t* Key or NULL on error
 */
static dap_enc_key_t *s_test_key_create(void)
{
    const char *l_seed = "test_tx_fixture_seed_20250416";
    dap_enc_key_t *l_key = dap_enc_key_new_generate(
        DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
        NULL,  // kex_buf
        0,     // kex_size  
        l_seed,
        strlen(l_seed),
        0      // key_size (use default)
    );
    
    if (!l_key) {
        log_it(L_ERROR, "Failed to generate test key");
    }
    
    return l_key;
}

test_tx_fixture_t *test_tx_fixture_create_simple(
    dap_ledger_t *a_ledger,
    const char *a_token_ticker,
    const char *a_value_str)
{
    if (!a_ledger || !a_token_ticker || !a_value_str) {
        log_it(L_ERROR, "Invalid parameters");
        return NULL;
    }
    
    test_tx_fixture_t *l_fixture = DAP_NEW_Z(test_tx_fixture_t);
    if (!l_fixture) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    // Create test key
    dap_enc_key_t *l_key = s_test_key_create();
    if (!l_key) {
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Create address
    l_fixture->addr = DAP_NEW_Z(dap_chain_addr_t);
    if (!l_fixture->addr) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_enc_key_delete(l_key);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    dap_chain_addr_fill_from_key(l_fixture->addr, l_key, (dap_chain_net_id_t){.uint64 = 0x0FA0});
    
    // Parse value
    uint256_t l_value = dap_chain_balance_scan(a_value_str);
    
    // Create emission transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        dap_enc_key_delete(l_key);
        DAP_DELETE(l_fixture->addr);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Add output with the specified value
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_fixture->addr, l_value, a_token_ticker) != 1) {
        log_it(L_ERROR, "Failed to add output to transaction");
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_key);
        DAP_DELETE(l_fixture->addr);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Sign transaction
    if (dap_chain_datum_tx_add_sign_item(&l_tx, l_key) != 1) {
        log_it(L_ERROR, "Failed to sign transaction");
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_key);
        DAP_DELETE(l_fixture->addr);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Calculate transaction hash
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_hash_fast(l_tx, l_tx_size, &l_fixture->tx_hash);
    
    // Add transaction to ledger (emission)
    int l_res = dap_ledger_tx_add(a_ledger, l_tx, &l_fixture->tx_hash, true, NULL);
    if (l_res != DAP_LEDGER_CHECK_OK) {
        log_it(L_ERROR, "Failed to add transaction to ledger: %s",
               dap_ledger_check_error_str(l_res));
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_key);
        DAP_DELETE(l_fixture->addr);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    l_fixture->tx = l_tx;
    l_fixture->out_count = 1;
    dap_enc_key_delete(l_key);
    
    log_it(L_INFO, "Simple test transaction created: value=%s, ticker=%s, hash=%s",
           a_value_str, a_token_ticker, dap_chain_hash_fast_to_str_static(&l_fixture->tx_hash));
    
    return l_fixture;
}

test_tx_fixture_t *test_tx_fixture_create_with_outs(
    uint32_t a_out_count,
    uint256_t a_value_per_out,
    const char *a_token_ticker)
{
    if (!a_token_ticker || a_out_count == 0) {
        log_it(L_ERROR, "Invalid parameters");
        return NULL;
    }

    test_tx_fixture_t *l_fixture = DAP_NEW_Z(test_tx_fixture_t);
    if (!l_fixture) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }

    l_fixture->out_count = a_out_count;
    
    // Create test key for signing
    dap_enc_key_t *l_key = s_test_key_create();
    if (!l_key) {
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Create transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        dap_enc_key_delete(l_key);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Add outputs
    dap_chain_addr_t l_addr_to = {};
    dap_chain_addr_fill_from_key(&l_addr_to, l_key, (dap_chain_net_id_t){.uint64 = 0x0FA0});
    
    for (uint32_t i = 0; i < a_out_count; i++) {
        dap_chain_tx_out_ext_t *l_out = dap_chain_datum_tx_item_out_ext_create(
            &l_addr_to, 
            a_value_per_out, 
            a_token_ticker
        );
        if (!l_out) {
            log_it(L_ERROR, "Failed to create output %u", i);
            dap_chain_datum_tx_delete(l_tx);
            dap_enc_key_delete(l_key);
            DAP_DELETE(l_fixture);
            return NULL;
        }
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_out);
        DAP_DELETE(l_out);
    }
    
    // Sign transaction
    if (dap_chain_datum_tx_add_sign_item(&l_tx, l_key) != 1) {
        log_it(L_ERROR, "Failed to sign transaction");
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_key);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Calculate transaction hash
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_hash_fast(l_tx, l_tx_size, &l_fixture->tx_hash);
    
    l_fixture->tx = l_tx;
    dap_enc_key_delete(l_key);
    
    log_it(L_INFO, "Test transaction fixture created with %u outputs (size=%zu)", 
           a_out_count, l_tx_size);
    return l_fixture;
}

void test_tx_fixture_destroy(test_tx_fixture_t *a_fixture)
{
    if (!a_fixture)
        return;

    if (a_fixture->tx)
        DAP_DELETE(a_fixture->tx);
    
    if (a_fixture->addr)
        DAP_DELETE(a_fixture->addr);
    
    DAP_DELETE(a_fixture);
    
    log_it(L_INFO, "Test transaction fixture destroyed");
}

