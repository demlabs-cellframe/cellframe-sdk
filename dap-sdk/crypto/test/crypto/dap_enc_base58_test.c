#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "dap_common.h"
#include "dap_test.h"
#include "rand/dap_rand.h"
#include "dap_enc_base58.h"
#include "dap_enc_base58_test.h"

size_t source_size;

static void test_encode_decode_base58(void)
{
//    static size_t source_size = 0;
//    source_size = 0;
    int step = 1 + random_uint32_t( 20);
    source_size += (size_t) step;

    uint8_t source[source_size];
    randombytes(source, source_size);
    //source[0] = 0;
    //source[1] = 0;
    size_t encode_result_size = DAP_ENC_BASE58_ENCODE_SIZE(source_size);
    char encode_result[encode_result_size];
    uint8_t decode_result[source_size];

    size_t encrypted_size = dap_enc_base58_encode(source, source_size, encode_result);
    size_t out_size = dap_enc_base58_decode(encode_result, decode_result);
    dap_assert_PIF(encrypted_size <= encode_result_size, "Calculate encrypted_size");
    dap_assert_PIF(source_size == out_size, "Check result decode size");
    dap_assert_PIF(memcmp(source, decode_result, source_size) == 0, "Check source and encode->decode data");
}

void dap_enc_base58_tests_run() {
    dap_print_module_name("dap_enc_base58");
    source_size = 0;
    benchmark_mgs_time("Encode and decode DAP_ENC_STANDARD_B58 100 times",
            benchmark_test_time(test_encode_decode_base58, 100));

    benchmark_mgs_rate("Encode and decode DAP_ENC_STANDARD_B58",
            benchmark_test_rate(test_encode_decode_base58, 1));

}
