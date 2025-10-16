/**
 * @file test_token_fixtures.c
 * @brief Implementation of token test fixtures
 */

#include "test_token_fixtures.h"
#include "dap_common.h"
#include "dap_chain_datum_token.h"
#include "dap_cert.h"
#include "dap_sign.h"

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

test_token_fixture_t *test_token_fixture_create_cf20(
    const char *a_ticker,
    uint256_t a_total_supply,
    uint16_t a_flags)
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

void test_token_fixture_destroy(test_token_fixture_t *a_fixture)
{
    if (!a_fixture)
        return;

    if (a_fixture->token)
        DAP_DELETE(a_fixture->token);
    
    DAP_DELETE(a_fixture);
    
    log_it(L_INFO, "Test token fixture destroyed");
}

