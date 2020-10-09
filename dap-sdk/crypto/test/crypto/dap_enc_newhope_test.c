#include "dap_enc_newhope.h"

#include "dap_common.h"
#include"dap_test.h"
#include<stdio.h>

static void init_test_case()
{
    dap_enc_key_init();
}

static void cleanup_test_case()
{
    dap_enc_key_deinit();
}
void test_newhope_kem();
void dap_enc_newhope_tests_run(const int times)
{
    dap_print_module_name("dap_enc_newhope");
    init_test_case();
    char tmp_buf[256];
    snprintf(tmp_buf, sizeof(tmp_buf), "Key Exchange %d times", times);

    benchmark_mgs_time(tmp_buf, benchmark_test_time(test_newhope_kem, times));

    cleanup_test_case();
}

void test_newhope_kem()
{
    //Alice generates a public key
    dap_enc_key_t* alice_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_RLWE_NEWHOPE_CPA_KEM, NULL, 0, NULL, 0, 0);
    uint8_t *al_pub = alice_key->pub_key_data;
    size_t al_pub_size = alice_key->pub_key_data_size;
    uint8_t *sendb = NULL;

    //Bob derives a secret key and creates a response
    dap_enc_key_t* bob_key = dap_enc_key_new(DAP_ENC_KEY_TYPE_RLWE_NEWHOPE_CPA_KEM);
    size_t sendb_size = bob_key->gen_bob_shared_key(bob_key, al_pub, al_pub_size,(void**)&sendb);
    dap_assert_PIF(sendb_size == NEWHOPE_CPAKEM_CIPHERTEXTBYTES, "Bob gen shared key");


    //Alice uses Bobs response to get her secre key
    alice_key->gen_alice_shared_key(alice_key, NULL, sendb_size, sendb);

    uint8_t *a_key = alice_key->priv_key_data,
            *b_key = bob_key->priv_key_data;
    int verify = memcmp(a_key, b_key, alice_key->priv_key_data_size)
            || alice_key->priv_key_data_size != bob_key->priv_key_data_size;
    dap_assert_PIF(!verify, "Verifying KEM Shared key");
//    if(!verify)
//    {
//        int j;
//        for(j=0;j<32;j++)
//            printf("%02x ", a_key[j]);
//        printf("\n");
//        for(j=0;j<32;j++)
//            printf("%02x ", b_key[j]);
//        printf("\n");
//        printf("newhope KEM ERROR\n");
//    }
    DAP_DEL_Z(sendb);
    dap_enc_key_delete(alice_key);
    dap_enc_key_delete(bob_key);
}

