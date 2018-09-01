#include "dap_enc_base64_test.h"

static const int BYTE_SIZE = 255;

void test_encode_decode_base64(int count_steps) {
    size_t source_size = 0;

    for (int i=1; i<= count_steps;i++) {
        int step = 1 + (rand() % 20 );
        source_size += (size_t)step;
        source_size += BYTE_SIZE;

        uint8_t source[source_size];
        char in[source_size];
        uint8_t out[source_size];
        generate_random_byte_array(source, source_size, BYTE_SIZE);

        size_t encrypted_size = dap_enc_base64_encode(source, source_size, in, DAP_ENC_STANDARD_B64);
        size_t out_size = dap_enc_base64_decode(in, encrypted_size, out, DAP_ENC_STANDARD_B64);

        dap_assert_PIF(source_size == out_size, "Check result decode size");
        dap_assert_PIF(memcmp(source, out, out_size) != 0, "Check source and encode->decode data");
    }

    dap_pass_msg("Encode and decode")
}

void dap_enc_base64_tests_run() {
    dap_print_module_name("dap_enc_base64");
    test_encode_decode_base64(50);
}
