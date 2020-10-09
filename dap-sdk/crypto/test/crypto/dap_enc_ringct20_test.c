#include "dap_enc_ringct20_test.h"
#include "dap_enc_ringct20.h"
#include "ringct20/ringct20_params.h"
#include "rand/dap_rand.h"


static void test_signing_verifying2(void)
{
    size_t source_size = 1 + random_uint32_t(20);
    uint8_t * source = DAP_NEW_SIZE(uint8_t, source_size);
    randombytes(source, source_size);
    size_t seed_size = sizeof(uint8_t);
    uint8_t seed[seed_size];

    randombytes(seed, seed_size);

    dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_RINGCT20, NULL, 0, seed, seed_size, 0);

    const int allpbknum = 100;
    void *allpbk_buf = NULL;
    ringct20_param_t *p = calloc(sizeof(ringct20_param_t),1);
    if (! ringct20_params_init( p, RINGCT20_MINSEC))
    {
        ringct20_params_free(p);
        return;
    }

    size_t allpbk_size = CRUTCH_gen_pbk_list(p, &allpbk_buf, allpbknum);
    key->getallpbkList(key, allpbk_buf,allpbk_size);

    size_t max_signature_size = dap_enc_ringct20_calc_signature_size();
    uint8_t* sig = calloc(max_signature_size, 1);



    size_t siglen = key->enc_na(key, source, source_size, sig, max_signature_size);
    dap_assert_PIF(siglen > 0, "Signing message");

//Extract aList//CRUTCH
    uint8_t *sigdata = (uint8_t*)*(int*)(sig + 4);
//    for(int i = 0; i < 16; ++i)
//        printf("%.2x ", sigdata[i]);
//    printf(" = sig_extract\n"); fflush(stdout);
    uint32_t unpacked_size = 0;
    //unpack sec_kind
    //memcpy(sec_kind, sigdata + unpacked_size, sizeof(DAP_RINGCT20_SIGN_SECURITY));
    unpacked_size += sizeof(DAP_RINGCT20_SIGN_SECURITY);
    //unpack wLen
    int wLen;
    memcpy(&wLen, sigdata + unpacked_size, sizeof(wLen));
//    printf("wLen = %x\n", wLen);fflush(stdout);
    unpacked_size += sizeof(wLen);
    //unpack a_list
    size_t poly_size = 896;
    size_t pbk_size = 4 + poly_size;
    uint8_t *pbkList_buf = DAP_NEW_SIZE(uint8_t, pbk_size*wLen);
    for(int i = 0; i < wLen; ++i)
    {
        *(int*)(pbkList_buf + i*pbk_size + 0) = 0;//kind CRUTCH
        memcpy(pbkList_buf + i*pbk_size + 4, sigdata + unpacked_size, poly_size);
        unpacked_size += poly_size;
    }
//Extrackt aList

   // size_t verify = key->dec_na(key, source, source_size, sig, siglen);
//    for(int i = 0; i < 32; ++i)
//        printf("%.2x ", pbkList_buf[i]);
//    printf(" = pbkList_buf\n"); fflush(stdout);
//    for(int i = 0; i < 32; ++i)
//        printf("%.2x ", pbkList_buf[pbk_size+i]);
//    printf(" = pbkList_buf\n"); fflush(stdout);
//    for(int i = 0; i < 32; ++i)
//        printf("%.2x ", pbkList_buf[pbk_size*2+i]);
//    printf(" = pbkList_buf\n"); fflush(stdout);

    size_t verify = key->dec_na_ext(key, source, source_size, sig, siglen,pbkList_buf,wLen);
//Corrupt pbkList
    int numpbk = 3;
//    for(int i = 0; i < 32; ++i)
//        printf("%.2x ", ((uint8_t*)allpbk_buf)[numpbk*pbk_size + i]);
//    printf(" = allpbk\n"); fflush(stdout);
    memcpy(pbkList_buf, allpbk_buf + numpbk*pbk_size, pbk_size);//Replace first pbk key with random pbk key

//Corrupt pbkList

//    for(int i = 0; i < 32; ++i)
//        printf("%.2x ", pbkList_buf[i]);
//    printf(" = corrupt pbkList_buf\n"); fflush(stdout);
//    for(int i = 0; i < 32; ++i)
//        printf("%.2x ", pbkList_buf[i+pbk_size]);
//    printf(" = corrupt pbkList_buf\n"); fflush(stdout);
//    for(int i = 0; i < 32; ++i)
//        printf("%.2x ", pbkList_buf[i+2*pbk_size]);
//    printf(" = corrupt pbkList_buf\n"); fflush(stdout);
    size_t verify_corrupt_sign = key->dec_na_ext(key, source, source_size, sig, siglen,pbkList_buf,wLen);

    //printf("verify = %d, verify_corrupt_sign = %d\n", verify, verify_corrupt_sign);fflush(stdout);
    dap_assert_PIF(!verify, "Verifying signature");
    dap_assert_PIF(verify_corrupt_sign, "to Reject Corrupt signature");

    ringct20_signature_delete((ringct20_signature_t*)sig);

    DAP_DELETE(allpbk_buf);
    ringct20_params_free(p);
    DAP_DELETE(source);
    free(sig);
    dap_enc_key_delete(key);
}

//DEBUG TO USE IT get back:dap_enc_sig_ringct20_get_sign_with_pb_list,//dap_enc_sig_ringct20_get_sign,
static void test_signing_verifying(void)
{

    size_t source_size = 1 + random_uint32_t(20);
    uint8_t * source = DAP_NEW_SIZE(uint8_t, source_size);
    randombytes(source, source_size);
    size_t seed_size = sizeof(uint8_t);
    uint8_t seed[seed_size];

    randombytes(seed, seed_size);

    dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_RINGCT20, NULL, 0, seed, seed_size, 0);

    size_t max_signature_size = dap_enc_ringct20_calc_signature_size();
    uint8_t* sig = calloc(max_signature_size, 1);



    size_t siglen = key->enc_na(key, source, source_size, sig, max_signature_size);
    dap_assert_PIF(siglen > 0, "Signing message");

    size_t verify = key->dec_na(key, source, source_size, sig, siglen);

    dap_assert_PIF(!verify, "Verifying signature");

    ringct20_signature_delete((ringct20_signature_t*)sig);
    DAP_DELETE(source);
    free(sig);
    dap_enc_key_delete(key);
}

static void init_test_case()
{
    srand((uint32_t) time(NULL));
    dap_enc_key_init();
}

static void cleanup_test_case()
{
    dap_enc_key_deinit();
}

void dap_enc_ringct20_tests_run(const int times)
{
    dap_print_module_name("dap_enc_ringct20");
    init_test_case();
    char print_buf[512];
    snprintf(print_buf, sizeof(print_buf), "Signing and verifying message %d time", times);

    benchmark_mgs_time(print_buf, benchmark_test_time(test_signing_verifying2, times));

    cleanup_test_case();
}

