#include "dap_enc_ringct20_test.h"
#include "dap_enc_ringct20.h"
#include "ringct20/ringct20_params.h"
#include "rand/dap_rand.h"

static void test_signing_verifying(void)
{
    size_t source_size = 1 + random_uint32_t(20);
    uint8_t * source = DAP_NEW_SIZE(uint8_t, source_size);
    randombytes(source, source_size);
    size_t seed_size = sizeof(uint8_t);
    uint8_t seed[seed_size];

    randombytes(seed, seed_size);

    dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_RINGCT20, NULL, 0, seed, seed_size, 0);

    size_t max_signature_size = dap_enc_ringct20_calc_signature_size();
    uint8_t* sig = calloc(max_signature_size, 1);



    size_t siglen = key->enc_na(key, source, source_size, sig, max_signature_size);
    dap_assert_PIF(siglen > 0, "Signing message");

    size_t verify = key->dec_na(key, source, source_size, sig, siglen);

    dap_assert_PIF(!verify, "Verifying signature");

    ringct20_signature_delete((ringct20_signature_t*)sig);
    DAP_DELETE(source);
    free(sig);
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

void dap_enc_ringct20_tests_run(const int times)
{
    dap_print_module_name("dap_enc_ringct20");
    init_test_case();
    char print_buf[512];
    sprintf_s(print_buf, 512, "Signing and verifying message %d time", times);

    benchmark_mgs_time(print_buf, benchmark_test_time(test_signing_verifying, times));

    cleanup_test_case();
}

