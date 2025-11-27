/**
 * @file test_transaction_fixtures.c
 * @brief Implementation of transaction test fixtures
 */

#include "test_transaction_fixtures.h"
#include "test_ledger_fixtures.h"
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
    // For UTXO blocking tests, we only need tx_hash and out_idx
    // We create a mock transaction (without real inputs) just to have valid hash
    
    UNUSED(a_ledger); // Not used in mock transaction creation
    
    if (!a_token_ticker || !a_value_str) {
        log_it(L_ERROR, "Invalid parameters");
        return NULL;
    }
    
    test_tx_fixture_t *l_fixture = DAP_NEW_Z(test_tx_fixture_t);
    if (!l_fixture) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    // Create test key and address
    dap_enc_key_t *l_key = s_test_key_create();
    if (!l_key) {
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
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
    
    // Create mock transaction (without inputs)
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        dap_enc_key_delete(l_key);
        DAP_DELETE(l_fixture->addr);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Add output
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_fixture->addr, l_value, a_token_ticker) != 1) {
        log_it(L_ERROR, "Failed to add output");
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
    
    // Calculate hash (this is what we need for UTXO blocking tests)
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_hash_fast(l_tx, l_tx_size, &l_fixture->tx_hash);
    
    // DON'T add to ledger - this is just a mock for testing UTXO blocking
    // The fixture provides tx_hash and out_idx that can be blocked/unblocked
    
    l_fixture->tx = l_tx;
    l_fixture->out_count = 1;
    dap_enc_key_delete(l_key);
    
    log_it(L_INFO, "Mock transaction created for UTXO blocking tests: value=%s, ticker=%s, hash=%s",
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

/**
 * @brief Create transaction from emission (real transaction with IN_EMS)
 */
test_tx_fixture_t *test_tx_fixture_create_from_emission(
    dap_ledger_t *a_ledger,
    dap_chain_hash_fast_t *a_emission_hash,
    const char *a_token_ticker,
    const char *a_value_str,
    dap_chain_addr_t *a_addr_to,
    dap_cert_t *a_cert)
{
    if (!a_ledger || !a_emission_hash || !a_token_ticker || !a_value_str || !a_addr_to || !a_cert) {
        log_it(L_ERROR, "Invalid parameters");
        return NULL;
    }
    
    test_tx_fixture_t *l_fixture = DAP_NEW_Z(test_tx_fixture_t);
    if (!l_fixture) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    // Clone address
    l_fixture->addr = DAP_NEW_Z(dap_chain_addr_t);
    if (!l_fixture->addr) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    memcpy(l_fixture->addr, a_addr_to, sizeof(dap_chain_addr_t));
    
    // Parse value
    uint256_t l_value = dap_chain_balance_scan(a_value_str);
    if (IS_ZERO_256(l_value)) {
        log_it(L_ERROR, "Invalid value: %s", a_value_str);
        test_tx_fixture_destroy(l_fixture);
        return NULL;
    }
    
    // Create transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        test_tx_fixture_destroy(l_fixture);
        return NULL;
    }
    
    // Add IN_EMS (input from emission) - this is how real transactions from emission work
    dap_chain_tx_in_ems_t l_in_ems = {
        .header = {
            .type = TX_ITEM_TYPE_IN_EMS,
            .token_emission_chain_id = {.uint64 = 0},
            .token_emission_hash = *a_emission_hash
        }
    };
    strncpy(l_in_ems.header.ticker, a_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_in_ems.header.ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    
    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)&l_in_ems) != 1) {
        log_it(L_ERROR, "Failed to add IN_EMS to transaction");
        dap_chain_datum_tx_delete(l_tx);
        test_tx_fixture_destroy(l_fixture);
        return NULL;
    }
    
    // Add main output
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, l_value, a_token_ticker) != 1) {
        log_it(L_ERROR, "Failed to add output");
        dap_chain_datum_tx_delete(l_tx);
        test_tx_fixture_destroy(l_fixture);
        return NULL;
    }
    
    // Get emission value to calculate change
    dap_chain_datum_token_emission_t *l_emission = dap_ledger_token_emission_find(a_ledger, a_emission_hash);
    if (l_emission) {
        uint256_t l_emission_value = l_emission->hdr.value;
        
        // If emission value > requested value, add change output
        if (compare256(l_emission_value, l_value) > 0) {
            uint256_t l_change = {0};
            SUBTRACT_256_256(l_emission_value, l_value, &l_change);
            
            if (!IS_ZERO_256(l_change)) {
                log_it(L_DEBUG, "Adding change output: %s", dap_uint256_to_char(l_change, NULL));
                if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, l_change, a_token_ticker) != 1) {
                    log_it(L_ERROR, "Failed to add change output");
                    dap_chain_datum_tx_delete(l_tx);
                    test_tx_fixture_destroy(l_fixture);
                    return NULL;
                }
            }
        }
    } else {
        log_it(L_WARNING, "Could not find emission in ledger to calculate change");
    }
    
    // Sign transaction
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_cert->enc_key) != 1) {
        log_it(L_ERROR, "Failed to sign transaction");
        dap_chain_datum_tx_delete(l_tx);
        test_tx_fixture_destroy(l_fixture);
        return NULL;
    }
    
    // Calculate hash
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_hash_fast(l_tx, l_tx_size, &l_fixture->tx_hash);
    
    l_fixture->tx = l_tx;
    l_fixture->out_count = 1;
    
    log_it(L_INFO, "Created REAL transaction from emission: value=%s, ticker=%s, hash=%s",
           a_value_str, a_token_ticker, dap_chain_hash_fast_to_str_static(&l_fixture->tx_hash));
    
    return l_fixture;
}

/**
 * @brief Add transaction to ledger using public API
 */
int test_tx_fixture_add_to_ledger(
    dap_ledger_t *a_ledger,
    test_tx_fixture_t *a_fixture)
{
    if (!a_ledger || !a_fixture || !a_fixture->tx) {
        log_it(L_ERROR, "Invalid parameters");
        return -1;
    }
    
    // Use ONLY public API - dap_ledger_tx_add()
    int l_result = dap_ledger_tx_add(
        a_ledger,
        a_fixture->tx,
        &a_fixture->tx_hash,
        false,  // a_from_threshold
        NULL    // a_datum_index_data
    );
    
    if (l_result == 0) {
        log_it(L_INFO, "Successfully added transaction to ledger: hash=%s",
               dap_chain_hash_fast_to_str_static(&a_fixture->tx_hash));
    } else {
        log_it(L_WARNING, "Failed to add transaction to ledger: error=%s",
               dap_ledger_check_error_str(l_result));
    }
    
    return l_result;
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

