#include "dap_enc_ringct20_test.h"
#include "dap_enc_ringct20.h"
#include "ringct20/ringct20_params.h"
#include "rand/dap_rand.h"

#define MSIZE 2
#define WSIZE 3
#define NSIZE 3

// From original implementation https://github.com/chainchip/Lattice-RingCT-v2.0/blob/master/Ring2.0/ring_test.c

void LRCT_Byte_Test()
{
    poly_ringct20 a, ra;
    uint8_t seed[NEWHOPE_RINGCT20_SYMBYTES] = { 0 };
    unsigned char bCof[NEWHOPE_RINGCT20_POLYBYTES] = { 0 };
    randombytes(seed, NEWHOPE_RINGCT20_SYMBYTES);
    poly_uniform_ringct20(&a, seed);
//    printf("begin:\n");
//    poly_print(&a);
//    printf("serial:\n");
    poly_serial(&a);
//    poly_print(&a);
    poly_tobytes(bCof, &a);
//    printf("ra:\n");
    poly_frombytes(&ra, bCof);
//    poly_print(&ra);


}

void LRCT_Setup_Test()
{
    poly_ringct20 A[2], H[2];
    poly_ringct20 S[2];
    poly_ringct20 L[2];
    poly_ringct20 h;
    poly_ringct20 u[3];
    poly_ringct20 c1;
    poly_ringct20* t[2];
    unsigned char msg[2] = { 0x01, 0x02 };
    unsigned char msg2[2] = { 0x02, 0x03 };
    int msgLen = 2;
    unsigned char bt[NEWHOPE_RINGCT20_POLYBYTES] = { 0 };
    size_t mLen = 2;
    size_t i = 0;
    size_t k = 0;
    int result = 0;
    int w = 2;
    int pai = 1;

    t[0] = (poly_ringct20 *)malloc((3) * sizeof(poly_ringct20));
    t[1] = (poly_ringct20 *)malloc((3) * sizeof(poly_ringct20));

    for (i = 0; i < 2; i++)
    {
        for (k = 0; k < 3; k++)
        {
            poly_init(t[i] + k);
        }

    }
    LRCT_Setup(A, H, 2);
    LRCT_SampleKey(S, 2);
    LRCT_KeyGen(L, A, S, 2);
    LRCT_SampleKey(S, 2);
    LRCT_KeyGen(L+1, A, S, 2);

    for (k = 0; k < 3; k++)
    {
        randombytes(bt, NEWHOPE_RINGCT20_POLYBYTES);
        poly_frombytes(u + k, bt);
        poly_serial(u + k);
        ///poly_print(u+k);
    }
//    printf("====================================\n");
    LRCT_SigGen(&c1, t, &h, A, H,S, u, mLen, L, w,pai, msg, msgLen);
//    printf("c1\n");
//    poly_print(&c1);
//    printf("=================\n");
    result = LRCT_SigVer(&c1, t, A, H, mLen, &h, L,w, msg, msgLen);
    dap_assert_PIF(result == 1, "Sign Verify");
    result = LRCT_SigVer(&c1, t, A, H, mLen, &h, L, w, msg2, msgLen);
    dap_assert_PIF(result != 1, "Sign Verify");
    free(t[0]);
    free(t[1]);

}

void MIMO_LRCT_Setup_Test()
{
    poly_ringct20 A[MSIZE], H[MSIZE];
    poly_ringct20 SList[MSIZE*NSIZE];
    poly_ringct20 S[MSIZE];
    poly_ringct20 LList[NSIZE*WSIZE];
    poly_ringct20 hList[NSIZE];
    poly_ringct20 c1;
    poly_ringct20 tList[NSIZE*WSIZE*(MSIZE+1)];
    int i, j, k;
    int pai = 2;
    unsigned char msg[2] = { 0x01, 0x02 };
    unsigned char msg2[2] = { 0x01, 0x03 };
    int msgLen = 2;
    int result = 0;
    MIMO_LRCT_Setup(A, H, MSIZE);
    for ( i = 0; i < NSIZE; i++)
    {
        LRCT_SampleKey(SList + i*MSIZE, MSIZE);
        MIMO_LRCT_KeyGen(LList + i*WSIZE + (pai-1) , A, SList + i * MSIZE, MSIZE);
    }
    for ( i = 0; i < WSIZE; i++)
    {
        if (i != pai-1)
        {
            for (j = 0; j < NSIZE; j++)
            {
                LRCT_SampleKey(S, MSIZE);
                MIMO_LRCT_KeyGen(LList + j* WSIZE + i, A, S, MSIZE);
            }
        }

    }
    MIMO_LRCT_SigGen(&c1, tList, hList, SList, NSIZE, A, H, MSIZE, LList, WSIZE, pai, msg, msgLen);
    result = MIMO_LRCT_SigVer(&c1, tList, hList, NSIZE, A, /*H,*/ MSIZE, LList, WSIZE, msg, msgLen);
    dap_assert_PIF(result == 1, "Sign verify");
    result = MIMO_LRCT_SigVer(&c1, tList, hList, NSIZE, A, /*H,*/ MSIZE, LList, WSIZE, msg2, msgLen);
    dap_assert_PIF(result != 1, "Sign verify");
}

void LRCT_Spent_Test()
{
    poly_ringct20 A[MSIZE], H[MSIZE];
    poly_ringct20 skPai[MSIZE], pkPai;
    poly_ringct20 ckPai[MSIZE];
    poly_ringct20* t[WSIZE];
    unsigned char bMessage[4] = { 0x01, 0x02, 0x03, 0x4 };
    size_t msglen = 4;
    IW iw;
    //////////////////
    poly_ringct20 skOA[MSIZE];
    poly_ringct20 pkOA;
    IW iwOA;
    poly_ringct20 ckOA[MSIZE];
    ////////////////////
    IW iwList[WSIZE];
    poly_ringct20 skTmp[MSIZE];
    poly_ringct20 pkList[WSIZE];
    poly_ringct20 ckList[WSIZE][MSIZE];
    unsigned char bListMessage[2] = { 0x01, 0x02};
    size_t msgListlen = 2;
    int i = 0;
    ///////////////////
    poly_ringct20 L[WSIZE];
    int paiIndex = 1;
    poly_ringct20 c1, h;
    unsigned char bSignMessage[3] = { 0x01, 0x02, 0x03 };
    size_t msgSignlen = 3;
    int result =0;
    size_t k = 0;
    /////////////////
    for ( i = 0; i < WSIZE; i++)
    {
        t[i] = (poly_ringct20 *)malloc((MSIZE+1) * sizeof(poly_ringct20));
        for (k = 0; k < MSIZE+1; k++)
        {
            poly_init(t[i] + k);
        }
    }
    ///////////////////
    LRCT_Setup(A, H, MSIZE);
    LRCT_SampleKey(skPai, MSIZE);
    LRCT_KeyGen(&pkPai, A, skPai, MSIZE);//A*S+0
    LRCT_Mint(&iw, ckPai, &pkPai, A, MSIZE, bMessage, msglen);//A*ck + $
    ///
    LRCT_SampleKey(skOA, MSIZE);
    LRCT_KeyGen(&pkOA, A, skOA, MSIZE);//
    //LRCT_Mint(&iwOA, ckOA, &pkOA, A, MSIZE, bMessage, msglen);
    //////
    for( i = 0; i < WSIZE; i++)
    {
        if (i == paiIndex)
        {
            poly_cofcopy(&iwList[i].a, &iw.a);
            poly_cofcopy(&iwList[i].cn, &iw.cn);
        }
        else
        {
            LRCT_SampleKey(skTmp, MSIZE);
            LRCT_KeyGen(pkList + i, A, skTmp, MSIZE);//A*S+0
            LRCT_Mint(iwList + i, ckList[i], pkList + i, A, MSIZE, bListMessage, msgListlen);
        }

    }
    LRCT_Spend(&iwOA, ckOA, &c1, t, &h, L, bSignMessage, msgSignlen, iwList, WSIZE, paiIndex, skPai, ckPai, bMessage, msglen, &pkOA, A, H, MSIZE);
    result = LRCT_Verify(&c1, t, &h, A, H, MSIZE, bSignMessage, msgSignlen, L, WSIZE);
    dap_assert_PIF(result == 1, "Sign Verify");
    for (i = 0; i < WSIZE; i++)
    {
        free(t[i]);
    }
}


void LRCT_Mul_Test()
{
    poly_ringct20 A[2], H[2], H2[2];
    poly_ringct20 h,h1,r;
    poly_ringct20 S[2];
    LRCT_Setup(A, H, 2);
    LRCT_SampleKey(S, 2);

    LRCT_MatrixMulPoly(&h, H, S, 2);


    for (size_t i = 0; i < NEWHOPE_RINGCT20_N; i++)
    {
        h.coeffs[i] = coeff_freeze2Q(NEWHOPE_RINGCT20_2Q + NEWHOPE_RINGCT20_Q - h.coeffs[i] * 2);
    }
    LRCT_ConstMulMatrix(H2, H, 2, 2);
    LRCT_MatrixMulPoly(&h1, H2, S, 2);
    poly_add_ringct20(&r, &h1, &h);
//    poly_print(&r);


}
void LRCT_MatrixMulVect_Test()
{
    poly_ringct20 A[2], H[2];
    LRCT_Setup(A, H, 2);
    uint8_t bt[2] = { 0 };
    bt[0] = 1;
    bt[1] = 2;


}
void LRCT_Lift_Test()
{
    poly_ringct20 A[2], H[2], LA[3], H2[3];
    poly_ringct20 h;
    poly_ringct20 S[2];
    LRCT_SampleKey(S, 2);
    LRCT_Setup(A, H, 2);
    LRCT_MatrixMulPoly(&h, H, S, 2);
    LRCT_Lift(LA, H, &h, 2);
    ////////////////////////////////////
    LRCT_ConstMulMatrix(H2, H, 2, 2);
    for (size_t i = 0; i < NEWHOPE_RINGCT20_N; i++)
    {
        H2[2].coeffs[i] = coeff_freeze2Q(NEWHOPE_RINGCT20_2Q + NEWHOPE_RINGCT20_Q - h.coeffs[i] * 2);
    }
    for (size_t i = 0; i < 3; i++)
    {
        dap_assert_PIF(poly_equal(LA + i, H2 + i) == 1, "Poly equality");
    }
}
void LRCT_KDF_Test()
{

}

void LRCT_Com_Test()
{
    IW iw;
    poly_ringct20 ck[2];
    size_t mLen = 2;
    poly_ringct20  A[2], H[2], sk[2];
    unsigned char bMessage[4] = { 0x01, 0x02, 0x03, 0x4 };
    size_t msglen = 4;
    poly_ringct20 a;
    LRCT_Setup(A, H, mLen);
    LRCT_SampleKey(sk, mLen);
    LRCT_KeyGen(&a, A, sk, mLen);
//    printf("public key:");
//    poly_print(&a);
    LRCT_Mint(&iw, ck, &a, A, mLen, bMessage, msglen);
//    printf("a:\n");
//    poly_print(&(iw.a));
//    printf("cn:\n");
//    poly_print(&(iw.cn));
}
//ntt 变换测试
void LRCT_Fun_Test()
{
    uint8_t seed[NEWHOPE_RINGCT20_SYMBYTES] = { 0 };
    poly_ringct20 a;
    randombytes(seed, NEWHOPE_RINGCT20_SYMBYTES);
    poly_uniform_ringct20(&a, seed);
    poly_serial(&a);
    ////////////
//    printf("begin:\n");
//    poly_print(&a);
    //////
    poly_ntt_ringct20(&a);
//    printf("after:\n");
//    poly_print(&a);
    ////
    poly_invntt(&a);
//    printf("recover:\n");
//    poly_print(&a);

}
//移位测试
void LRCT_Shift_Test()
{
    poly_ringct20 r, a;
    poly_init(&r);
    poly_init(&a);
    r.coeffs[NEWHOPE_RINGCT20_N - 1] = 1;
    r.coeffs[0] = 1;

    poly_ntt_ringct20(&r);
    poly_shift(&a, &r, 1);
    poly_invntt(&a);

    poly_serial(&a);
//    poly_print(&a);
}
void LRCT_ComHom_Test()
{
    unsigned char message[2] = { 0xF0, 0x0F };
    int messLen = 2;
    int messBitLen = messLen*8;
    int i = 0;
    unsigned char bitTmp = 0;
    poly_ringct20 *CKi = (poly_ringct20 *)malloc((MSIZE*(messBitLen)) * sizeof(poly_ringct20));
    poly_ringct20 *comList = (poly_ringct20 *)malloc(((messBitLen)) * sizeof(poly_ringct20));
    poly_ringct20  A[MSIZE], H[MSIZE], sk[MSIZE], ck0[MSIZE], tmpM[MSIZE];
    poly_ringct20 a, r, tmp;

    poly_init(&a);
    poly_init(&tmp);
    poly_init(&r);
    for ( i = 0; i < MSIZE; i++)
    {
        poly_init(ck0 + i);
    }
    LRCT_Setup(A, H, MSIZE);
    LRCT_SampleKey(sk, MSIZE);
    //left
    LRCT_nttCom(&r, A, sk, MSIZE, message, messLen);
    //right
    for (i = 1; i < messBitLen; i++)
    {
        LRCT_SampleKey(CKi + i*MSIZE, MSIZE);
    }

    LRCT_GetCK0(CKi, sk, MSIZE, CKi+MSIZE, messBitLen-1);

    for ( i = 0; i < messBitLen; i++)
    {
        LRCT_MatrixShift(tmpM, CKi+i*MSIZE, MSIZE, i);
        LRCT_MatrixAddMatrix(ck0, ck0, tmpM, MSIZE);
    }
    for ( i = 0; i < MSIZE; i++)
    {
        dap_assert_PIF(poly_equal(ck0 + i, sk + i) == 1, "poly equality")
    }

    for ( i = 0; i < messLen; i++)
    {
        bitTmp = (message[i] & 0x01);
        LRCT_nttCom(comList + i * 8, A, CKi + (i * 8) * MSIZE, MSIZE, &bitTmp, 1);
        //////////////////////////////
        bitTmp = (message[i] & 0x02)>>1;
        LRCT_nttCom(comList + i * 8 + 1, A, CKi + (i * 8 + 1) * MSIZE, MSIZE, &bitTmp, 1);
        ////////////
        bitTmp = (message[i] & 0x04)>>2;
        LRCT_nttCom(comList + i * 8 + 2, A, CKi + (i * 8 + 2) * MSIZE, MSIZE, &bitTmp, 1);
        ////////////
        bitTmp = (message[i] & 0x08)>>3;
        LRCT_nttCom(comList + i * 8 + 3, A, CKi + (i * 8 + 3) * MSIZE, MSIZE, &bitTmp, 1);

        ////////////
        bitTmp = (message[i] & 0x10)>>4;
        LRCT_nttCom(comList + i * 8 + 4, A, CKi + (i * 8 + 4) * MSIZE, MSIZE, &bitTmp, 1);

        ////////////
        bitTmp = (message[i] & 0x20)>>5;
        LRCT_nttCom(comList + i * 8 + 5, A, CKi + (i * 8 + 5) * MSIZE, MSIZE, &bitTmp, 1);

        ////////////
        bitTmp = (message[i] & 0x40)>>6;
        LRCT_nttCom(comList + i * 8 + 6, A, CKi + (i * 8 + 6) * MSIZE, MSIZE, &bitTmp, 1);

        ////////////
        bitTmp = (message[i] & 0x80)>>7;
        LRCT_nttCom(comList + i * 8 + 7, A, CKi + (i * 8 + 7) * MSIZE, MSIZE, &bitTmp, 1);
    }
    //poly_cofcopy(&a, comList);
    for ( i = 0; i < messBitLen; i++)
    {
        poly_shift(&tmp, comList + i, i);
        poly_add_ringct20(&a, &a, &tmp);
    }
//    printf("a:\n");
//    poly_print(&a);
//    printf("r:\n");
//    poly_print(&r);
    dap_assert_PIF(poly_equal(&a, &r) == 1, "poly equality");
    free(CKi);
    free(comList);
}


static void test_signing_verifying2(void)
{
    size_t source_size = 1 + random_uint32_t(20);
    uint8_t * source = DAP_NEW_SIZE(uint8_t, source_size);
    randombytes(source, source_size);
    size_t seed_size = sizeof(uint8_t);
    uint8_t seed[seed_size];

    randombytes(seed, seed_size);

    // one keypair
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
//    uint8_t *sigdata = (uint8_t*)*(int*)(sig + 4);
    uint8_t *sigdata = (uint8_t*) ((ringct20_signature_t*) sig)->sig_data;
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

    snprintf(print_buf, sizeof(print_buf), "Byte test %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(LRCT_Byte_Test, times));

    snprintf(print_buf, sizeof(print_buf), "Signing and verifying message SISO mode %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(LRCT_Setup_Test, times));

    snprintf(print_buf, sizeof(print_buf), "Signing and verifying message MIMO mode %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(MIMO_LRCT_Setup_Test, times));

    snprintf(print_buf, sizeof(print_buf), "Spent test %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(LRCT_Spent_Test, times));

    snprintf(print_buf, sizeof(print_buf), "Mul test %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(LRCT_Mul_Test, times));

    snprintf(print_buf, sizeof(print_buf), "MatrixMulVect test %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(LRCT_MatrixMulVect_Test, times));

    snprintf(print_buf, sizeof(print_buf), "Lift test %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(LRCT_Lift_Test, times));

    snprintf(print_buf, sizeof(print_buf), "KDF test %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(LRCT_KDF_Test, times));

    snprintf(print_buf, sizeof(print_buf), "Com test %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(LRCT_Com_Test, times));

    snprintf(print_buf, sizeof(print_buf), "Fun test %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(LRCT_Fun_Test, times));

    snprintf(print_buf, sizeof(print_buf), "Shift test %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(LRCT_Shift_Test, times));

    snprintf(print_buf, sizeof(print_buf), "ComHom test %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(LRCT_ComHom_Test, times));

    snprintf(print_buf, sizeof(print_buf), "Signing and verifying message %d time", times);
    benchmark_mgs_time(print_buf, benchmark_test_time(test_signing_verifying2, times));

    cleanup_test_case();
}

