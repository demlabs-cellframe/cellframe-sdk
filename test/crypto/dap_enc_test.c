#include "dap_enc_test.h"
#include "dap_test.h"
#include "dap_test_generator.h"
#include "dap_enc_key.h"
#include "dap_enc_base64.h"
#include "dap_enc.h"

void test_encode_decode_raw(int count_steps)
{
    size_t source_size = 1;
    for (int i = 0; i < count_steps; i++) {
        int step = 1 + (rand() % 20);
        source_size += (size_t)step;

        dap_enc_key_t * key = dap_enc_key_new(DAP_ENC_KEY_TYPE_AES);

        uint8_t source[source_size];
        uint8_t decode_result[source_size];
        uint8_t encrypt_result[source_size];

        generate_random_byte_array(source, source_size);

        size_t encrypted_size = dap_enc_code(key, source,
                                             source_size,
                                             encrypt_result,
                                             DAP_ENC_DATA_TYPE_RAW);

        size_t out_size = dap_enc_decode(key,
                                         encrypt_result,
                                         encrypted_size,
                                         decode_result,
                                         DAP_ENC_DATA_TYPE_RAW);

        dap_assert_PIF(source_size == out_size, "Check result decode size");
        dap_enc_key_delete(key);
    }

    dap_pass_msg("Test encode->decode raw");
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
    cleanup_test_case();
}
