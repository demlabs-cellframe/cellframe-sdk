/**
 * @file test_token_fixtures.c
 * @brief Implementation of token test fixtures
 */

#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "dap_common.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_ledger.h"
#include "dap_cert.h"
#include "dap_sign.h"
#include "dap_math_ops.h"
#include "dap_time.h"
#include "dap_hash.h"

#define LOG_TAG "test_token_fixtures"

/**
 * @brief Create a test certificate for token signing
 * @return dap_cert_t* Certificate or NULL on error
 */
static dap_cert_t *s_test_cert_create(void)
{
    const char *l_seed = "test_token_fixture_seed_2024";
    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed(
        "test_fixture_cert",
        DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
        l_seed,
        strlen(l_seed)
    );
    if (!l_cert) {
        log_it(L_ERROR, "Failed to generate test certificate");
    }
    return l_cert;
}

test_token_fixture_t *test_token_fixture_create(
    dap_ledger_t *a_ledger,
    const char *a_ticker,
    const char *a_total_supply_str)
{
    if (!a_ledger || !a_ticker || !a_total_supply_str) {
        log_it(L_ERROR, "Invalid parameters");
        return NULL;
    }
    
    test_token_fixture_t *l_fixture = DAP_NEW_Z(test_token_fixture_t);
    if (!l_fixture) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    dap_strncpy(l_fixture->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    l_fixture->token_ticker = dap_strdup(a_ticker);
    l_fixture->flags = 0;
    
    // Create owner certificate FIRST
    l_fixture->owner_cert = s_test_cert_create();
    if (!l_fixture->owner_cert) {
        DAP_DELETE(l_fixture->token_ticker);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Parse total supply
    uint256_t l_total_supply = dap_chain_balance_scan(a_total_supply_str);
    
    // Create CF20 token datum
    dap_chain_datum_token_t *l_token = DAP_NEW_Z(dap_chain_datum_token_t);
    if (!l_token) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_cert_delete(l_fixture->owner_cert);
        DAP_DELETE(l_fixture->token_ticker);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    l_token->version = 2;
    l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
    l_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_token->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_token->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_token->signs_valid = 0;  // No auth requirements for test tokens (allows emission without auth)
    l_token->total_supply = l_total_supply;
    l_token->header_native_decl.decimals = 18;
    l_token->header_native_decl.flags = 0;
    l_token->header_native_decl.tsd_total_size = 0;
    l_token->signs_total = 0;
    
    // Sign the token with owner certificate
    dap_sign_t *l_sign = dap_cert_sign(l_fixture->owner_cert, l_token, sizeof(dap_chain_datum_token_t));
    if (!l_sign) {
        log_it(L_ERROR, "Failed to sign token");
        DAP_DELETE(l_token);
        dap_cert_delete(l_fixture->owner_cert);
        DAP_DELETE(l_fixture->token_ticker);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    size_t l_sign_size = dap_sign_get_size(l_sign);
    dap_chain_datum_token_t *l_token_new = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + l_sign_size);
    if (!l_token_new) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_token);
        DAP_DELETE(l_sign);
        dap_cert_delete(l_fixture->owner_cert);
        DAP_DELETE(l_fixture->token_ticker);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    l_token = l_token_new;
    
    memcpy(l_token->tsd_n_signs, l_sign, l_sign_size);
    l_token->signs_total = 1;
    DAP_DELETE(l_sign);
    
    l_fixture->token = l_token;
    l_fixture->token_size = sizeof(dap_chain_datum_token_t) + l_sign_size;
    
    // Add token to ledger
    int l_res = dap_ledger_token_add(a_ledger, (byte_t*)l_fixture->token, 
                                      l_fixture->token_size, dap_time_now());
    if (l_res != DAP_LEDGER_CHECK_OK) {
        log_it(L_ERROR, "Failed to add token to ledger: %s",
               dap_ledger_check_error_str(l_res));
        test_token_fixture_destroy(l_fixture);
        return NULL;
    }
    
    log_it(L_INFO, "Test token created and added to ledger: %s (supply=%s) [emission not created for fixture simplicity]",
           a_ticker, a_total_supply_str);
    
    return l_fixture;
}

test_token_fixture_t *test_token_fixture_create_cf20(
    const char *a_ticker,
    uint256_t a_total_supply,
    uint32_t a_flags)
{
    if (!a_ticker) {
        log_it(L_ERROR, "Token ticker is NULL");
        return NULL;
    }

    test_token_fixture_t *l_fixture = DAP_NEW_Z(test_token_fixture_t);
    if (!l_fixture) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }

    dap_strncpy(l_fixture->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    l_fixture->flags = a_flags;
    
    // Create test certificate for signing
    dap_cert_t *l_cert = s_test_cert_create();
    if (!l_cert) {
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Create CF20 token datum
    dap_chain_datum_token_t *l_token = DAP_NEW_Z(dap_chain_datum_token_t);
    if (!l_token) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_cert_delete(l_cert);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    l_token->version = 2;
    l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
    l_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    dap_strncpy(l_token->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    l_token->signs_valid = 1;
    l_token->total_supply = a_total_supply;
    l_token->header_native_decl.decimals = 18;
    l_token->header_native_decl.flags = a_flags;
    l_token->header_native_decl.tsd_total_size = 0;
    l_token->signs_total = 0;
    
    // Sign the token
    dap_sign_t *l_sign = dap_cert_sign(l_cert, l_token, sizeof(dap_chain_datum_token_t));
    if (l_sign) {
        size_t l_sign_size = dap_sign_get_size(l_sign);
        l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + l_sign_size);
        if (!l_token) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            DAP_DELETE(l_sign);
            dap_cert_delete(l_cert);
            DAP_DELETE(l_fixture);
            return NULL;
        }
        memcpy(l_token->tsd_n_signs, l_sign, l_sign_size);
        DAP_DELETE(l_sign);
        l_token->signs_total = 1;
        l_fixture->token_size = sizeof(dap_chain_datum_token_t) + l_sign_size;
    } else {
        log_it(L_ERROR, "Failed to sign token");
        DAP_DELETE(l_token);
        dap_cert_delete(l_cert);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    l_fixture->token = l_token;
    dap_cert_delete(l_cert);
    
    log_it(L_INFO, "Test CF20 token fixture created: %s (flags=0x%04X, size=%zu)", 
           a_ticker, a_flags, l_fixture->token_size);
    return l_fixture;
}

test_token_fixture_t *test_token_fixture_create_with_utxo_blocking(
    const char *a_ticker,
    uint256_t a_total_supply)
{
    // Create token with UTXO_BLOCKING_ENABLED flag (BIT(16))
    return test_token_fixture_create_cf20(a_ticker, a_total_supply, (1 << 16));
}

/**
 * @brief Create token with emission automatically
 */
test_token_fixture_t *test_token_fixture_create_with_emission(
    dap_ledger_t *a_ledger,
    const char *a_ticker,
    const char *a_total_supply_str,
    const char *a_emission_value_str,
    dap_chain_addr_t *a_addr,
    dap_cert_t *a_emission_cert,
    dap_chain_hash_fast_t *a_emission_hash_out)
{
    if (!a_ledger || !a_ticker || !a_total_supply_str || !a_emission_value_str || !a_addr || !a_emission_cert) {
        log_it(L_ERROR, "Invalid parameters");
        return NULL;
    }
    
    // Step 1: Create token using existing function
    test_token_fixture_t *l_token_fixture = test_token_fixture_create(
        a_ledger,
        a_ticker,
        a_total_supply_str
    );
    
    if (!l_token_fixture) {
        log_it(L_ERROR, "Failed to create token fixture");
        return NULL;
    }
    
    // Step 2: Create emission using provided certificate
    uint256_t l_emission_value = dap_chain_balance_scan(a_emission_value_str);
    if (IS_ZERO_256(l_emission_value)) {
        log_it(L_ERROR, "Invalid emission value: %s", a_emission_value_str);
        test_token_fixture_destroy(l_token_fixture);
        return NULL;
    }
    
    test_emission_fixture_t *l_emission_fixture = test_emission_fixture_create_with_cert(
        a_ticker,
        l_emission_value,
        a_addr,
        a_emission_cert  // Use provided cert for emission
    );
    
    if (!l_emission_fixture) {
        log_it(L_ERROR, "Failed to create emission fixture");
        test_token_fixture_destroy(l_token_fixture);
        return NULL;
    }
    
    // Step 3: Add emission to ledger using public API
    int l_result = test_emission_fixture_add_to_ledger(a_ledger, l_emission_fixture);
    if (l_result != 0) {
        log_it(L_WARNING, "Failed to add emission to ledger: %s",
               dap_ledger_check_error_str(l_result));
        test_emission_fixture_destroy(l_emission_fixture);
        test_token_fixture_destroy(l_token_fixture);
        return NULL;
    }
    
    // Step 4: Return emission hash if requested
    if (a_emission_hash_out) {
        test_emission_fixture_get_hash(l_emission_fixture, a_emission_hash_out);
    }
    
    // NOTE: Do NOT destroy emission fixture here - ledger may need it
    // or caller may need emission data. Let caller destroy it if needed.
    // For now, we accept this small memory leak in tests.
    // TODO: Better lifecycle management for emission fixtures
    
    log_it(L_INFO, "Created token with emission: ticker=%s, total_supply=%s, emission_value=%s",
           a_ticker, a_total_supply_str, a_emission_value_str);
    
    log_it(L_WARNING, "NOTE: Emission fixture not freed - caller must manage lifecycle");
    
    return l_token_fixture;
}

void test_token_fixture_destroy(test_token_fixture_t *a_fixture)
{
    if (!a_fixture)
        return;

    if (a_fixture->token)
        DAP_DELETE(a_fixture->token);
    
    if (a_fixture->owner_cert)
        dap_cert_delete(a_fixture->owner_cert);
    
    if (a_fixture->token_ticker)
        DAP_DELETE(a_fixture->token_ticker);
    
    DAP_DELETE(a_fixture);
    
    log_it(L_INFO, "Test token fixture destroyed");
}

