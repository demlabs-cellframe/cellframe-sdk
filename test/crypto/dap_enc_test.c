#include "dap_enc_test.h"
#include "dap_test.h"
#include "dap_test_generator.h"
#include "dap_enc_key.h"
#include "dap_enc_base64.h"
#include "dap_enc.h"

static void _encrypt_decrypt(enum dap_enc_key_type key_type,
                             enum dap_enc_data_type data_type,
                             size_t count_steps)
{
    size_t source_size = 1;

    for (int i = 0; i < count_steps; i++) {
        int step = 1 + (rand() % 20);
        source_size += (size_t)step;

        const char *kex_data = "123";
        size_t kex_size = strlen(kex_data);
        const size_t seed_size = 1 + (rand() % 1000);
        uint8_t seed[seed_size];

        generate_random_byte_array(seed, seed_size);

        dap_enc_key_t* key = dap_enc_key_new_generate(key_type, kex_data, kex_size, seed, seed_size, 0);

        uint8_t source[source_size];
        uint8_t *decode_result;
        uint8_t *encrypt_result;

        generate_random_byte_array(source, source_size);

        size_t encrypted_size = dap_enc_code(key, source,
                                             source_size,
                                             (void**)&encrypt_result,
                                             data_type);

        size_t out_size = dap_enc_decode(key,
                                         encrypt_result,
                                         encrypted_size,
                                         (void**)&decode_result,
                                         data_type);

        dap_assert_PIF(source_size == out_size, "Check result decode size");

        dap_assert_PIF(memcmp(source, decode_result, source_size) == 0,
"Check source and encode->decode data");

        free(encrypt_result);
        free(decode_result);
        dap_enc_key_delete(key);
    }
}

void test_encode_decode_raw(size_t count_steps)
{
    _encrypt_decrypt(DAP_ENC_KEY_TYPE_AES, DAP_ENC_DATA_TYPE_RAW, count_steps);
    dap_pass_msg("Test encode->decode raw");
}

void test_encode_decode_raw_b64(size_t count_steps)
{
    _encrypt_decrypt(DAP_ENC_KEY_TYPE_AES, DAP_ENC_DATA_TYPE_B64, count_steps);
    dap_pass_msg("Test encode->decode raw base64");
}

void test_encode_decode_raw_b64_url_safe(size_t count_steps)
{
    _encrypt_decrypt(DAP_ENC_KEY_TYPE_AES, DAP_ENC_DATA_TYPE_B64_URLSAFE, count_steps);
    dap_pass_msg("Test encode->decode raw base64 url safe");
}

static void init_test_case()
{
    dap_enc_key_init();
}

static void cleanup_test_case()
{
    dap_enc_key_deinit();
}

void dap_enc_tests_run() {
    dap_print_module_name("dap_enc");
    init_test_case();
    test_encode_decode_raw(50);
    test_encode_decode_raw_b64(50);
    test_encode_decode_raw_b64_url_safe(50);
    cleanup_test_case();
}
