#include "rand/dap_rand.h"
#include "dap_enc_picnic_test.h"
#include "../sig_picnic/picnic.h"

static void test_signing_verifying(void)
{
    static size_t source_size = 0;
    size_t seed_size = sizeof(int);
    uint8_t seed[seed_size];

    randombytes(seed, seed_size);

    dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_PICNIC, NULL, 0, seed, seed_size, 0);

    size_t max_signature_size = dap_enc_picnic_calc_signature_size(key);
    uint8_t* sig = calloc(max_signature_size, 1);

    int step = 1 + random_uint32_t( 20);
    source_size += (size_t) step;

    uint8_t source[source_size];
    randombytes(source, source_size);

    size_t siglen = key->enc_na(key, source, source_size, sig, max_signature_size);
    dap_assert_PIF(siglen > 0, "Signing message");

    size_t verify = key->dec_na(key, source, source_size, sig, siglen);
    dap_assert_PIF(!verify, "Verifying signature");

    free(sig);
    dap_enc_key_delete(key);
    //dap_pass_msg("Signing and verifying message");
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

void dap_enc_picnic_tests_run()
{
    dap_print_module_name("dap_enc_picnic");
    init_test_case();

    benchmark_mgs_time("Signing and verifying message 1 time", benchmark_test_time(test_signing_verifying, 1));

    cleanup_test_case();
}
