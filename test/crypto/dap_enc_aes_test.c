#include "dap_enc_aes_test.h"

static const int BYTE_SIZE = 256;

void generate_random_byte_array(uint8_t* array, const size_t size) {
    for(size_t i = 0; i < size; i++) {
        array[i] = (uint8_t)rand() % BYTE_SIZE;
    }
}

void test_encode_decode(const size_t source_size) {
    dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_AES, 0);

    uint8_t source[source_size];
    uint8_t encrypted[source_size + AES_BLOCK_SIZE];
    uint8_t result[source_size + AES_BLOCK_SIZE];
    generate_random_byte_array(source, source_size);

    size_t encrypted_size = dap_enc_aes_encode(key, source,
                                               source_size, encrypted);

    size_t result_size = dap_enc_aes_decode(key, encrypted,
                                            encrypted_size, result);

    dap_assert_PIF(source_size == result_size, "Check result decode size");

    dap_assert_PIF(memcmp(source,result,source_size) == 0, "Check source and encode->decode data");
    dap_enc_key_delete(key);
}


//void test_encode_decode(int source_size){
//    dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_AES, 0);
//    uint8_t* source = (uint8_t*)malloc(source_size);
//    uint8_t* encrypted = (uint8_t*)malloc(source_size+16);
//    uint8_t* result = (uint8_t*)malloc(source_size+16);
//    generate_random_byte_array(source,source_size);
//    size_t encrypted_size = dap_enc_aes_encode(key,source,source_size,encrypted);
//    size_t result_size = dap_enc_aes_decode(key,encrypted,encrypted_size,result);

//    if(source_size != result_size) {
//        dap_test_msg("FAIL");
//    }

//    dap_assert(source_size == result_size,"Size error");
//    dap_assert(memcmp(source,result,source_size) == 0,"Encryption error");
//    free(source);
//    free(encrypted);
//    free(result);
//    dap_enc_key_delete(key);
//}


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

    const size_t step = 3, count_steps = 1000;

    for(size_t i = 1; i <= count_steps; i++) {
         //test_encode_decode(231);
        test_encode_decode(step * i);
    }
    cleanup_test_case();
}
