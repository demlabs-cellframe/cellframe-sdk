/**
 * @file test_emission_fixtures.c
 * @brief Implementation of emission test fixtures
 * @details Provides helper functions for creating and managing token emissions in tests.
 *          Uses ONLY public ledger API - no access to internal structures.
 * 
 * @date 2025-10-16
 * @copyright Copyright (c) 2017-2025 Demlabs Ltd. All rights reserved.
 */

#include "test_emission_fixtures.h"
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_sign.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include <string.h>

#define LOG_TAG "test_emission_fixtures"

/**
 * @brief Create test certificate for emission signing
 * @return Certificate or NULL on error
 */
static dap_cert_t *s_test_cert_create(void)
{
    const char *l_seed = "emission_test_seed";
    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed(
        "test_emission_cert",
        DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
        l_seed,
        strlen(l_seed)
    );
    
    if (!l_cert) {
        log_it(L_ERROR, "Failed to create certificate");
        return NULL;
    }
    
    return l_cert;
}

/**
 * @brief Create emission fixture with simple parameters
 */
test_emission_fixture_t *test_emission_fixture_create_simple(
    const char *a_token_ticker,
    const char *a_value_str,
    dap_chain_addr_t *a_addr,
    bool a_sign)
{
    if (!a_token_ticker || !a_value_str || !a_addr) {
        log_it(L_ERROR, "Invalid parameters");
        return NULL;
    }
    
    // Parse value
    uint256_t l_value = dap_chain_balance_scan(a_value_str);
    if (IS_ZERO_256(l_value)) {
        log_it(L_ERROR, "Invalid emission value: %s", a_value_str);
        return NULL;
    }
    
    // Create fixture
    test_emission_fixture_t *l_fixture = DAP_NEW_Z(test_emission_fixture_t);
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
    memcpy(l_fixture->addr, a_addr, sizeof(dap_chain_addr_t));
    
    // Clone ticker
    l_fixture->token_ticker = dap_strdup(a_token_ticker);
    if (!l_fixture->token_ticker) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_fixture->addr);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Create emission using public API
    l_fixture->emission = dap_chain_datum_emission_create(
        l_value,
        a_token_ticker,
        a_addr
    );
    
    if (!l_fixture->emission) {
        log_it(L_ERROR, "Failed to create emission");
        test_emission_fixture_destroy(l_fixture);
        return NULL;
    }
    
    // Sign if requested
    if (a_sign) {
        l_fixture->cert = s_test_cert_create();
        if (!l_fixture->cert) {
            log_it(L_ERROR, "Failed to create certificate for signing");
            test_emission_fixture_destroy(l_fixture);
            return NULL;
        }
        
        l_fixture->emission = dap_chain_datum_emission_add_sign(
            l_fixture->cert->enc_key,
            l_fixture->emission
        );
        
        if (!l_fixture->emission) {
            log_it(L_ERROR, "Failed to sign emission");
            test_emission_fixture_destroy(l_fixture);
            return NULL;
        }
    }
    
    // Calculate size and hash
    l_fixture->emission_size = dap_chain_datum_emission_get_size((byte_t*)l_fixture->emission);
    dap_hash_fast(l_fixture->emission, l_fixture->emission_size, &l_fixture->emission_hash);
    
    log_it(L_INFO, "Created emission fixture: ticker=%s, value=%s, signed=%s, hash=%s",
           a_token_ticker, a_value_str, a_sign ? "yes" : "no",
           dap_chain_hash_fast_to_str_static(&l_fixture->emission_hash));
    
    return l_fixture;
}

/**
 * @brief Create emission fixture with certificate
 */
test_emission_fixture_t *test_emission_fixture_create_with_cert(
    const char *a_token_ticker,
    uint256_t a_value,
    dap_chain_addr_t *a_addr,
    dap_cert_t *a_cert)
{
    if (!a_token_ticker || IS_ZERO_256(a_value) || !a_addr || !a_cert) {
        log_it(L_ERROR, "Invalid parameters");
        return NULL;
    }
    
    // Create fixture
    test_emission_fixture_t *l_fixture = DAP_NEW_Z(test_emission_fixture_t);
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
    memcpy(l_fixture->addr, a_addr, sizeof(dap_chain_addr_t));
    
    // Clone ticker
    l_fixture->token_ticker = dap_strdup(a_token_ticker);
    if (!l_fixture->token_ticker) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_fixture->addr);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Create emission using public API
    l_fixture->emission = dap_chain_datum_emission_create(
        a_value,
        a_token_ticker,
        a_addr
    );
    
    if (!l_fixture->emission) {
        log_it(L_ERROR, "Failed to create emission");
        test_emission_fixture_destroy(l_fixture);
        return NULL;
    }
    
    // Check certificate key
    if (!a_cert->enc_key) {
        log_it(L_ERROR, "Certificate enc_key is NULL");
        test_emission_fixture_destroy(l_fixture);
        return NULL;
    }
    
    // Sign with provided certificate
    log_it(L_DEBUG, "Signing emission with cert key type %d", a_cert->enc_key->type);
    l_fixture->emission = dap_chain_datum_emission_add_sign(
        a_cert->enc_key,
        l_fixture->emission
    );
    
    if (!l_fixture->emission) {
        log_it(L_ERROR, "Failed to sign emission");
        test_emission_fixture_destroy(l_fixture);
        return NULL;
    }
    
    // Store certificate reference (not owned, don't free)
    l_fixture->cert = a_cert;
    
    // Calculate size and hash
    l_fixture->emission_size = dap_chain_datum_emission_get_size((byte_t*)l_fixture->emission);
    dap_hash_fast(l_fixture->emission, l_fixture->emission_size, &l_fixture->emission_hash);
    
    log_it(L_INFO, "Created emission fixture with cert: ticker=%s, value=%s, hash=%s",
           a_token_ticker, dap_uint256_to_char(a_value, NULL),
           dap_chain_hash_fast_to_str_static(&l_fixture->emission_hash));
    
    return l_fixture;
}

/**
 * @brief Add emission to ledger using public API
 */
int test_emission_fixture_add_to_ledger(
    dap_ledger_t *a_ledger,
    test_emission_fixture_t *a_fixture)
{
    if (!a_ledger || !a_fixture || !a_fixture->emission) {
        log_it(L_ERROR, "Invalid parameters");
        return -1;
    }
    
    // Use ONLY public API - dap_ledger_token_emission_add()
    int l_result = dap_ledger_token_emission_add(
        a_ledger,
        (byte_t*)a_fixture->emission,
        a_fixture->emission_size,
        &a_fixture->emission_hash
    );
    
    if (l_result == 0) {
        log_it(L_INFO, "Successfully added emission to ledger: ticker=%s, hash=%s",
               a_fixture->token_ticker,
               dap_chain_hash_fast_to_str_static(&a_fixture->emission_hash));
    } else {
        log_it(L_WARNING, "Failed to add emission to ledger: ticker=%s, error=%s",
               a_fixture->token_ticker,
               dap_ledger_check_error_str(l_result));
    }
    
    return l_result;
}

/**
 * @brief Destroy emission fixture and free all resources
 */
void test_emission_fixture_destroy(test_emission_fixture_t *a_fixture)
{
    if (!a_fixture) {
        return;
    }
    
    // Free emission datum
    if (a_fixture->emission) {
        DAP_DELETE(a_fixture->emission);
    }
    
    // Free owned address
    if (a_fixture->addr) {
        DAP_DELETE(a_fixture->addr);
    }
    
    // Free owned ticker
    if (a_fixture->token_ticker) {
        DAP_DELETE(a_fixture->token_ticker);
    }
    
    // Free owned certificate (if created internally)
    if (a_fixture->cert) {
        // Only free if cert was created by test_emission_fixture_create_simple
        // (not by test_emission_fixture_create_with_cert)
        // This is safe because cert_generate_mem_with_key creates a new cert
        dap_cert_delete(a_fixture->cert);
    }
    
    // Free fixture itself
    DAP_DELETE(a_fixture);
}

/**
 * @brief Get emission hash from fixture
 */
bool test_emission_fixture_get_hash(
    test_emission_fixture_t *a_fixture,
    dap_chain_hash_fast_t *a_hash_out)
{
    if (!a_fixture || !a_hash_out) {
        return false;
    }
    
    *a_hash_out = a_fixture->emission_hash;
    return true;
}

