#include "dap_enc_iaes_test.h"

void test_encode_decode(int count_steps)
{
    size_t source_size = 0;

    for(int i = 1; i <= count_steps; i++) {
        int step = 1 + (rand() % 20);
        source_size += (size_t)step;

        const char *kex_data = "123";
        size_t kex_size = strlen(kex_data);
        const size_t seed_size = 1 + (rand() % 1000);
        uint8_t seed[seed_size];

        generate_random_byte_array(seed, seed_size);

        dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_AES, kex_data, kex_size, seed, seed_size, 0);

        uint8_t source[source_size];
        generate_random_byte_array(source, source_size);

        uint8_t * buf_encrypted = NULL;
        uint8_t * buf_decrypted = NULL;

        size_t encrypted_size = key->enc(key, source,
                                         source_size, (void**)&buf_encrypted);

        size_t result_size = key->dec(key, buf_encrypted,
                                      encrypted_size, (void**)&buf_decrypted);

        dap_assert_PIF(source_size == result_size, "Check result decode size");

        dap_assert_PIF(memcmp(source, buf_decrypted, source_size) == 0,
                       "Check source and encode->decode data");

        free(buf_encrypted);
        free(buf_decrypted);
        dap_enc_key_delete(key);
    }

    dap_pass_msg("Encode and decode")
}

void init_test_case()
{
    srand((uint)time(NULL));
    dap_enc_key_init();
}

void cleanup_test_case()
{
    dap_enc_key_deinit();
}

void dap_enc_aes_tests_run()
{
    dap_print_module_name("dap_enc_aes");
    init_test_case();

    test_encode_decode(50);

    cleanup_test_case();
}
