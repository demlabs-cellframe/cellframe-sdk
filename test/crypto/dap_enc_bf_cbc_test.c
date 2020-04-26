#include"dap_enc_key.h"
#include"rand/dap_rand.h"
#include"dap_test.h"
//#include"blowfish/blowfish.h"

static void test_encode_decode(int count_steps)
{
    size_t source_size = 0;

    for(int i = 0; i < count_steps; i++) {
        source_size = 1 + random_uint32_t(20000);
//        printf("src_size = %d\n", source_size);fflush(stdout);
        const size_t seed_size = 16;
        uint8_t seed[seed_size];

        const size_t kex_size = 32;
        uint8_t kex[kex_size];

        randombytes(seed, seed_size);
        randombytes(kex, kex_size);

        dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_BF_CBC, kex, kex_size, seed, seed_size, 32);

        uint8_t *source = DAP_NEW_SIZE(uint8_t, source_size+0);
        memset(source, 0xff, source_size + 0);
//        for(int i = 0; i < 16; ++i)
//            printf("%.2x ", source[i]);
//        printf("\n");fflush(stdout);
        randombase64(source, source_size);
//        for(int i = 0; i < 16; ++i)
//            printf("%.2x ", source[i]);
//        printf("\n");fflush(stdout);

        uint8_t * buf_encrypted = NULL;
        uint8_t * buf_decrypted = NULL;

        size_t encrypted_size = key->enc(key, source, source_size, (void**) &buf_encrypted);
//        for(int i = 0; i < 16; ++i)
//            printf("%.2x ", source[i]);
//        printf("\n");fflush(stdout);
        //buf_encrypted[encrypted_size-1]=0;
//        DAP_DELETE(source);

        size_t result_size = key->dec(key, buf_encrypted, encrypted_size, (void**) &buf_decrypted);
 //       DAP_DELETE(source);

//        printf("pt_size = %d, decr_size = %d, encrypted_size = %d\n", source_size, result_size,encrypted_size);
//        fflush(stdout);
//        source[source_size] = 0;
//        //printf("pt  = %s\n", source);
//        fflush(stdout);
//       // printf("pt2 = %s\n", buf_decrypted);
//        fflush(stdout);

        dap_assert_PIF(source_size == result_size, "Check result decode size");

        dap_assert_PIF(memcmp(source, buf_decrypted, source_size) == 0,
                "Check source and encode->decode data");

        free(buf_encrypted);
        free(buf_decrypted);
        dap_enc_key_delete(key);
    }

    dap_pass_msg("Encode and decode");
}

static void test_encode_decode_fast(int count_steps)
{
    const size_t buf_size = 4096;
    char buf_encrypt_out[buf_size];
    char buf_decrypt_out[buf_size];


    size_t seed_size = 16;
    uint8_t seed[seed_size];

    size_t kex_size = 32;
    uint8_t kex[kex_size];

    randombytes(seed, seed_size);
    randombytes(kex, kex_size);

    dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_BF_CBC, kex, kex_size, NULL, 0, 32);

    size_t source_size = 0;

    for(int i = 0; i < count_steps; i++) {
        source_size = 1 + random_uint32_t(2000);

        uint8_t *source = DAP_NEW_SIZE(uint8_t,source_size + 0);
        randombase64(source, source_size);


        size_t encrypted_size = key->enc_na(key, source, source_size, buf_encrypt_out, buf_size);

        size_t result_size = key->dec_na(key, buf_encrypt_out, encrypted_size, buf_decrypt_out, buf_size);



        dap_assert_PIF(source_size == result_size, "Check result decode size");

        dap_assert_PIF(memcmp(source, buf_decrypt_out, source_size) == 0,
                "Check source and encode->decode data");
        DAP_DELETE(source);
    }

    dap_enc_key_delete(key);
    dap_pass_msg("Encode and decode fast");
}


static void init_test_case()
{
    dap_enc_key_init();
}

static void cleanup_test_case()
{
    dap_enc_key_deinit();
}

void dap_enc_bf_cbc_tests_run()
{
    dap_print_module_name("dap_enc_bf_cbc");
    init_test_case();

    test_encode_decode(100);
    test_encode_decode_fast(100);

    cleanup_test_case();
}
