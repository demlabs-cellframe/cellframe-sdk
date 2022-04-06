#include "rand/dap_rand.h"
#include "dap_enc_dilithium_test.h"
#include "dap_enc_dilithium.h"
#include "dap_sign.h"

static void test_signing_verifying(void)
{
    static size_t source_size = 0;
    size_t seed_size = sizeof(uint8_t);
    uint8_t seed[seed_size];

    randombytes(seed, seed_size);

    dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, seed, seed_size, 0);

    size_t max_signature_size = dap_enc_dilithium_calc_signature_unserialized_size();
    uint8_t* sig = calloc(max_signature_size, 1);

    int step = 1 + random_uint32_t( 20);
    source_size += (size_t) step;

    uint8_t source[source_size];
    randombytes(source, source_size);

    size_t siglen = key->enc_na(key, source, source_size, sig, max_signature_size);
    dap_assert_PIF(siglen > 0, "Signing message");

    size_t verify = key->dec_na(key, source, source_size, sig, siglen);
    dap_assert_PIF(!verify, "Verifying signature");

    dilithium_signature_delete((dilithium_signature_t*)sig);
    free(sig);
    dap_enc_key_delete(key);
}

static void test_signing_verifying_serial(void)
{
    size_t seed_size = sizeof(uint8_t);
    uint8_t seed[seed_size];

    randombytes(seed, seed_size);

    dap_enc_key_t *key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, seed, seed_size, 0);

    size_t source_size = 1 + random_uint32_t(20);
    uint8_t source[source_size];
    randombytes(source, source_size);

    dap_sign_t *sign = dap_sign_create(key, source, source_size, 0);
    dap_assert_PIF(sign, "Signing message and serialize");

    int verify = dap_sign_verify(sign, source, source_size);
    dap_assert_PIF(verify == 1, "Deserialize and verifying signature");

    free(sign);
    dap_enc_key_delete(key);
}

static void init_test_case()
{
    srand((uint32_t) time(NULL));
    dap_enc_key_init();
}

static void cleanup_test_case()
{
    dap_enc_key_deinit();
}

void dap_enc_dilithium_tests_run()
{
    dap_print_module_name("dap_enc_dilithium");
    init_test_case();

    benchmark_mgs_time("Signing and verifying message 1 time", benchmark_test_time(test_signing_verifying, 1));

    benchmark_mgs_time("Signing and verifying message with serialization 1 time", benchmark_test_time(test_signing_verifying_serial, 1));

    cleanup_test_case();
}

