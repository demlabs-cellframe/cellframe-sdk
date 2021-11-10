#include "dap_enc_sign_multi_test.h"
#include "dap_test.h"
#include "rand/dap_rand.h"
#include "dap_sign.h"

#define SIGNATURE_TYPE_COUNT 4
#define KEYS_TOTAL_COUNT 10

static void test_signing_verifying(void)
{
    size_t seed_size = 10;
    uint8_t seed[seed_size];

    randombytes(seed, seed_size);

    dap_enc_key_type_t key_type_arr[SIGNATURE_TYPE_COUNT] = {\
             DAP_ENC_KEY_TYPE_SIG_TESLA,\
             DAP_ENC_KEY_TYPE_SIG_BLISS,\
             DAP_ENC_KEY_TYPE_SIG_DILITHIUM,\
             DAP_ENC_KEY_TYPE_SIG_PICNIC};
    int step;
    dap_enc_key_t* key[KEYS_TOTAL_COUNT];
    for (int i = 0; i < KEYS_TOTAL_COUNT; i++) {
        step = random_uint32_t( SIGNATURE_TYPE_COUNT);
        key[i] = dap_enc_key_new_generate(key_type_arr[step], NULL, 0, seed, seed_size, 0);
    }
    step = 1 + random_uint32_t( 2000);
    size_t source_size = (size_t) step;

    uint8_t *source = DAP_NEW_SIZE(uint8_t, source_size);
    randombytes(source, source_size);

    dap_multi_sign_params_t *params = dap_multi_sign_params_make(SIG_TYPE_MULTI_CHAINED, KEYS_TOTAL_COUNT, 5,\
                                                                 key[0], key[1], key[2], key[3], key[4], key[5],\
                                                                 key[6], key[7], key[8], key[9], 3, 5, 7, 1, 10);
    dap_assert_PIF(params, "Creating multi-sign parameters");

    dap_multi_sign_t *sign = dap_multi_sign_create(params, source, source_size);
    dap_assert_PIF(sign, "Signing message");

    size_t serialized_size = 0;
    uint8_t *serialized_sign = dap_multi_sign_serialize(sign, &serialized_size);
    dap_assert_PIF(serialized_sign, "Serializing signature");

    dap_multi_sign_t *deserialized_sign = dap_multi_sign_deserialize(SIG_TYPE_MULTI_CHAINED, serialized_sign, serialized_size);
    dap_assert_PIF(deserialized_sign, "Deserializing signature");

    int verify = dap_multi_sign_verify(deserialized_sign, source, source_size);
    dap_assert_PIF(verify == 1, "Verifying signature");

    dap_multi_sign_delete(deserialized_sign);
    dap_multi_sign_delete(sign);
    dap_multi_sign_params_delete(params);
    DAP_DELETE(serialized_sign);
    DAP_DELETE(source);
    for (int i = 0; i < KEYS_TOTAL_COUNT; i++) {
        dap_enc_key_delete(key[i]);
    }
}

static void init_test_case()
{
    srand((uint32_t) time(NULL));
}


void dap_enc_multi_sign_tests_run()
{
    dap_print_module_name("dap_enc_sign_multi");
    init_test_case();

    benchmark_mgs_time("Signing and verifying message 1 time", benchmark_test_time(test_signing_verifying, 10));
}
