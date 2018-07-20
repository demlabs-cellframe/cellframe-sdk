#include "dap_enc_aes_test.h"

static const size_t BYTE_SIZE = 256;

void generate_random_byte_array(uint8_t* array, int size){
    srand(time(NULL));
    for(int i=0 ; i< size; i++){
        array[i] = rand()%BYTE_SIZE;
    }
}

void test_encode_decode(int source_size){
    dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_AES, 0);
    uint8_t* source = (uint8_t*)malloc(source_size);
    uint8_t* encrypted = (uint8_t*)malloc(source_size+16);
    uint8_t* result = (uint8_t*)malloc(source_size+16);
    generate_random_byte_array(source,source_size);
    size_t encrypted_size = dap_enc_aes_encode(key,source,source_size,encrypted);
    size_t result_size = dap_enc_aes_decode(key,encrypted,encrypted_size,result);
    dap_assert(source_size == result_size,"Size error");
    dap_assert(memcmp(source,result,source_size) == 0,"Encryption error");
    free(source);
    free(encrypted);
    free(result);
    dap_enc_key_delete(key);    
}


void init_test_case() {
   dap_enc_key_init();
}

void cleanup_test_case() {
    dap_enc_key_deinit();
}

void dap_enc_aes_tests_run() {
    dap_print_module_name("dap_enc_aes");
    init_test_case();
    test_encode_decode(10);
    test_encode_decode(100);
    test_encode_decode(1000);
    test_encode_decode(10000);
    test_encode_decode(100000);
    test_encode_decode(1000000);
    cleanup_test_case();
}