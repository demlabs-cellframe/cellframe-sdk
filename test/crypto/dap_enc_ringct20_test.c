#include "dap_test_generator.h"
#include "dap_enc_ringct20_test.h"
#include "dap_enc_ringct20.h"
#include "ringct20/ringct20_params.h"

static void test_signing_verifying(void)
{
    static size_t source_size = 0;
    size_t seed_size = sizeof(uint8_t);
    uint8_t seed[seed_size];

    generate_random_byte_array(seed, seed_size);

    dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_RINGCT20, NULL, 0, seed, seed_size, 0);

    size_t max_signature_size = dap_enc_ringct20_calc_signature_size();
    uint8_t* sig = calloc(max_signature_size, 1);

    int step = 1 + (rand() % 20);
    source_size += (size_t) step;

    uint8_t source[source_size];
    generate_random_byte_array(source, source_size);

    size_t siglen = key->enc_na(key, source, source_size, sig, max_signature_size);
    dap_assert_PIF(siglen > 0, "Signing message");

    size_t verify = key->dec_na(key, source, source_size, sig, siglen);

    dap_assert_PIF(!verify, "Verifying signature");

    ringct20_signature_delete((ringct20_signature_t*)sig);
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

