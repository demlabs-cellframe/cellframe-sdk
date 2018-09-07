#include "dap_enc_aes_test.h"

static const int BYTE_SIZE = 256;



void test_encode_decode(int count_steps) {
    size_t source_size = 0;

    for(int i = 1; i <= count_steps; i++) {
        int step = 1 + (rand() % 20);
        source_size += (size_t)step;
        dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_AES, 0);

        uint8_t source[source_size];
        uint8_t encrypted[source_size + AES_BLOCK_SIZE];
        uint8_t result[source_size + AES_BLOCK_SIZE];
        generate_random_byte_array(source, source_size, BYTE_SIZE);

        size_t encrypted_size = dap_enc_aes_encode(key, source,
                                                   source_size, encrypted);

        size_t result_size = dap_enc_aes_decode(key, encrypted,
                                                encrypted_size, result);

        dap_assert_PIF(source_size == result_size, "Check result decode size");

        dap_assert_PIF(memcmp(source, result, source_size) == 0,
                       "Check source and encode->decode data");

        dap_enc_key_delete(key);
    }

    dap_pass_msg("Encode and decode")
}

void init_test_case() {
    srand((uint)time(NULL));
    dap_enc_key_init();
}

void cleanup_test_case() {
    dap_enc_key_deinit();
}

void dap_enc_aes_tests_run() {
    dap_print_module_name("dap_enc_aes");
    init_test_case();

    test_encode_decode(50);

    cleanup_test_case();
}
