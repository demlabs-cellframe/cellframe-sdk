#include <stdio.h>
#include "ring.h"
#include "sha3/KeccakHash.h"


#define Keccak_HashInitialize_SHA3_KDF(hashInstance, out_bytes)        Keccak_HashInitialize(hashInstance, 1088,  512, out_bytes*8, 0x06)

void LRCT_SampleKey(poly_ringct20 *r, int mLen)
{
	uint8_t seed[NEWHOPE_RINGCT20_SYMBYTES] = { 0 };
    int i;
	for ( i = 0; i < mLen; i++)
	{
#ifndef NEW_SAMPLE_KEY
        randombytes(seed, NEWHOPE_RINGCT20_SYMBYTES);
		for (size_t j = 0; j < NEWHOPE_RINGCT20_SYMBYTES; j++)
		{

			r[i].coeffs[j * 8 + 0] = (seed[j] & 0x01);
			r[i].coeffs[j * 8 + 1] = (seed[j] & 0x02)>>1;
			r[i].coeffs[j * 8 + 2] = (seed[j] & 0x04)>>2;
			r[i].coeffs[j * 8 + 3] = (seed[j] & 0x08)>>3;
			r[i].coeffs[j * 8 + 4] = (seed[j] & 0x10)>>4;
			r[i].coeffs[j * 8 + 5] = (seed[j] & 0x20)>>5;
			r[i].coeffs[j * 8 + 6] = (seed[j] & 0x40)>>6;
			r[i].coeffs[j * 8 + 7] = (seed[j] & 0x80)>>7;
		}
        randombytes(seed, NEWHOPE_RINGCT20_SYMBYTES);
		for (size_t j = 0; j < NEWHOPE_RINGCT20_SYMBYTES; j++)
		{

			r[i].coeffs[NEWHOPE_RINGCT20_SYMBYTES * 8 + j * 8 + 0] = (seed[j] & 0x01);
			r[i].coeffs[NEWHOPE_RINGCT20_SYMBYTES * 8 + j * 8 + 1] = (seed[j] & 0x02)>>1;
			r[i].coeffs[NEWHOPE_RINGCT20_SYMBYTES * 8 + j * 8 + 2] = (seed[j] & 0x04)>>2;
			r[i].coeffs[NEWHOPE_RINGCT20_SYMBYTES * 8 + j * 8 + 3] = (seed[j] & 0x08)>>3;
			r[i].coeffs[NEWHOPE_RINGCT20_SYMBYTES * 8 + j * 8 + 4] = (seed[j] & 0x10)>>4;
			r[i].coeffs[NEWHOPE_RINGCT20_SYMBYTES * 8 + j * 8 + 5] = (seed[j] & 0x20)>>5;
			r[i].coeffs[NEWHOPE_RINGCT20_SYMBYTES * 8 + j * 8 + 6] = (seed[j] & 0x40)>>6;
			r[i].coeffs[NEWHOPE_RINGCT20_SYMBYTES * 8 + j * 8 + 7] = (seed[j] & 0x80)>>7;
		}
#else
        uint8_t stm[NEWHOPE_RINGCT20_N*2];
        randombytes(stm, NEWHOPE_RINGCT20_N*2);
        const int gamma = 8;
        for(int j = 0; j < NEWHOPE_RINGCT20_N; ++j)
        {
            uint16_t v = stm[2*j];
            v<<= 8;
            v ^= stm[2*j + 1];
            v %= gamma;
            v -= gamma/2;
            if(v < 0)
                v += NEWHOPE_RINGCT20_Q;
            r[i].coeffs[j] = v;
        }
#endif
	}

}
void LRCT_Setup(poly_ringct20 *A, poly_ringct20 *H, int mLen)
{

	uint8_t seed[NEWHOPE_RINGCT20_SYMBYTES] = { 0 };
    int i = 0;

	for ( i = 0; i < mLen; i++)
	{
        randombytes(seed, NEWHOPE_RINGCT20_SYMBYTES);
		poly_uniform_ringct20(A + i, seed);
		poly_serial(A + i);
        randombytes(seed, NEWHOPE_RINGCT20_SYMBYTES);
		poly_uniform_ringct20(H + i, seed);
		poly_serial(H + i);
	}
}

void LRCT_KeyGen(poly_ringct20 *a, poly_ringct20 *A, poly_ringct20 *S, int mLen)
{
	LRCT_MatrixMulPoly(a, A, S,  mLen);
	poly_serial(a);
}

void LRCT_SigGen(poly_ringct20 *c1, poly_ringct20 **t, poly_ringct20 *h,
                 poly_ringct20 *A, poly_ringct20 *H, poly_ringct20 *S, poly_ringct20 *u,
                 int  mLen, poly_ringct20 *L, int w, int pai, const unsigned char *msg, int msgLen)
{
	//H2q
    int i, j, k;
	poly_ringct20 *H2q = (poly_ringct20 *)malloc((mLen + 1) * sizeof(poly_ringct20));
	poly_ringct20 *S2q = (poly_ringct20 *)malloc((mLen + 1) * sizeof(poly_ringct20));
	poly_ringct20 *A2qp = (poly_ringct20 *)malloc((mLen + 1) * sizeof(poly_ringct20));
	poly_ringct20 *tmp2q = (poly_ringct20 *)malloc((mLen + 1) * sizeof(poly_ringct20));
	poly_ringct20  tmp, tmp1;
	poly_ringct20 c,  cpai;
    //SHA256_CTX ctx;
    Keccak_HashInstance ctx;

//	unsigned char bHash[32] = { 0 };
	unsigned char bpoly[NEWHOPE_RINGCT20_POLYBYTES] = { 0 };
	unsigned char bt[NEWHOPE_RINGCT20_POLYBYTES] = { 0 };
	uint8_t coin = 0;
	for ( i = 0; i < (mLen+1); i++)
	{
		poly_init(H2q + i);
		poly_init(S2q + i);
		poly_init(A2qp + i);
		poly_init(tmp2q + i);
	}
	///////////1.
	LRCT_MatrixMulPoly(h, H, S, mLen);//h = HS_{pai}
	LRCT_Lift(H2q, H, h, mLen);//H_{2q}
	poly_copy(S2q, S, mLen);
	poly_setValue(S2q + mLen, 1);//S_{2q}
	///////////2.
	LRCT_Lift(A2qp, A, L + pai, mLen);
    //SHA256_Init(&ctx);
    Keccak_HashInitialize_SHA3_KDF(&ctx, NEWHOPE_RINGCT20_POLYBYTES);
	for (i = 0; i < w; i++)
	{
		poly_tobytes(bpoly, L + i);
        //SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
        Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);
    }
    for ( i = 0; i < mLen+1; i++)
    {
        poly_tobytes(bpoly, H2q + i);
        //SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
        Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);
    }
    //SHA256_Update(&ctx, msg, msgLen);//msg
    Keccak_HashUpdate(&ctx, msg, msgLen*8);

	LRCT_MatrixMulPoly(&tmp, A2qp, u, mLen + 1);
	poly_tobytes(bpoly, &tmp);
    //SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);//A2qb*U
    Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);

	LRCT_MatrixMulPoly(&tmp, H2q, u, mLen + 1);
	poly_tobytes(bpoly, &tmp);
    //SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);//H2q*U
    Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);
    //SHA256_Final(bHash, &ctx);//C_(pai+1)
    //Keccak_HashFinal(&ctx, bHash);
    Keccak_HashFinal(&ctx, bt);

    //SHA256_KDF(bHash, 32, NEWHOPE_RINGCT20_POLYBYTES, bt);
    //Keccak_256KDF(bHash, 32, bt, NEWHOPE_RINGCT20_POLYBYTES);

    poly_frombytes(&c, bt);
    poly_serial(&c);
    //poly_print(&c);
	/////////////////////////////////////
	for ( i = 0; i < (w-1); i++)
	{
		j = (pai + i+1) % w;
		if (j == 0)
		{
			poly_cofcopy(c1, &c);
		}
		LRCT_Lift(tmp2q, A, L + j, mLen);
        //SHA256_Init(&ctx);
        Keccak_HashInitialize_SHA3_KDF(&ctx, NEWHOPE_RINGCT20_POLYBYTES);//Keccak_HashInitialize_SHA3_256(&ctx);

		for (k = 0; k < w; k++)
		{
			poly_tobytes(bpoly, L + k);
            //SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
            Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);


		}
		for (k = 0; k < mLen+1; k++)
		{
			poly_tobytes(bpoly, H2q + k);
            //SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
            Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);

        }
        //SHA256_Update(&ctx, msg, msgLen);//msg
        Keccak_HashUpdate(&ctx, msg, msgLen*8);

		
		for ( k = 0; k < mLen+1; k++)
		{
            randombytes(bt, NEWHOPE_RINGCT20_POLYBYTES);
			poly_frombytes(t[j] + k, bt);
			poly_serial(t[j] + k);
		}
		LRCT_MatrixMulPoly(&tmp, tmp2q, t[j], mLen + 1);
		poly_constmul(&tmp1, &c, NEWHOPE_RINGCT20_Q);
		poly_add_ringct20(&tmp, &tmp, &tmp1);//(+ qC_i)% Q
		poly_tobytes(bpoly, &tmp);
        //SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);//
        Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);

		LRCT_MatrixMulPoly(&tmp, H2q, t[j], mLen + 1);
		poly_add_ringct20(&tmp, &tmp, &tmp1);//(+ qC_i)% Q
		poly_tobytes(bpoly, &tmp);
        //SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);//H2q*U
        Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);
        //SHA256_Final(bHash, &ctx);//C_(pai+1)
        //Keccak_HashFinal(&ctx, bHash);
        Keccak_HashFinal(&ctx, bt);
//        printf("sign bHash======================%d:\n", j);
//        BytePrint(bHash, 32);

        //SHA256_KDF(bHash, 32, NEWHOPE_RINGCT20_POLYBYTES, bt);
//        Keccak_256KDF(bHash, 32, bt, NEWHOPE_RINGCT20_POLYBYTES);
		poly_frombytes(&c, bt);
		poly_serial(&c);//C_{j+1}
        if (j == (w + pai-1)%w)
		{
			poly_cofcopy(&cpai, &c);
            if(pai == 0)
            {
                poly_cofcopy(c1, &c);
            }
            break;
		}

	}
    randombytes(&coin, 1);
	LRCT_PolyMultMatrix(tmp2q, &cpai, S2q, mLen + 1);//S2qpai *c_pai
	if (coin&0x01)//b =1
	{
		LRCT_MatrixSubMatrix(t[pai], u, tmp2q, mLen + 1);
	}
	else {
		LRCT_MatrixAddMatrix(t[pai], u, tmp2q, mLen + 1);
	}

	free(H2q);
	free(S2q);
	free(A2qp);
	free(tmp2q);
}
int LRCT_SigVer(const poly_ringct20 *c1, poly_ringct20 **t, poly_ringct20 *A, poly_ringct20 *H, int mLen, poly_ringct20 *h, poly_ringct20 *L,
    int w, const unsigned char *msg, int msgLen)
{
    int i,k;
	poly_ringct20 *H2q = (poly_ringct20 *)malloc((mLen + 1) * sizeof(poly_ringct20));
	poly_ringct20 *A2qp = (poly_ringct20 *)malloc((mLen + 1) * sizeof(poly_ringct20));
	poly_ringct20 c, tmp, tmp1;
    //SHA256_CTX ctx;
    Keccak_HashInstance ctx;
//	unsigned char bHash[32] = { 0 };
	unsigned char bpoly[NEWHOPE_RINGCT20_POLYBYTES] = { 0 };
	for (i = 0; i < (mLen + 1); i++)
	{
		poly_init(H2q + i);
		//poly_init(S2q + i);
		poly_init(A2qp + i);
	}
	LRCT_Lift(H2q, H, h, mLen);
	poly_cofcopy(&c, c1);
	for ( i = 0; i < w; i++)
	{
		LRCT_Lift(A2qp, A, L+i, mLen);
        //SHA256_Init(&ctx);
        Keccak_HashInitialize_SHA3_KDF(&ctx, NEWHOPE_RINGCT20_POLYBYTES);//Keccak_HashInitialize_SHA3_256(&ctx);
		for (k = 0; k < w; k++)
		{
			poly_tobytes(bpoly, L + k);
            //SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
            Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);

        }
		for (k = 0; k < mLen+1; k++)
		{
			poly_tobytes(bpoly, H2q + k);
            //SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
            Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);
        }
        //SHA256_Update(&ctx, msg, msgLen);//msg
        Keccak_HashUpdate(&ctx, msg, msgLen*8);

		poly_constmul(&tmp1, &c, NEWHOPE_RINGCT20_Q);

		LRCT_MatrixMulPoly(&tmp, A2qp, t[i], mLen + 1);
		poly_add_ringct20(&tmp, &tmp, &tmp1);//(+ qC_i)% Q
		poly_tobytes(bpoly, &tmp);
        //SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);//A2qb*U
        Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);

		LRCT_MatrixMulPoly(&tmp, H2q, t[i], mLen + 1);
		poly_add_ringct20(&tmp, &tmp, &tmp1);//(+ qC_i)% Q
		poly_serial(&tmp);
		poly_tobytes(bpoly, &tmp);
        //SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);//H2q*U
        Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);

        //SHA256_Final(bHash, &ctx);//C_(pai+1)
        //Keccak_HashFinal(&ctx, bHash);
        Keccak_HashFinal(&ctx, bpoly);
//        printf("sign bHash======================%d:\n", j);
//        BytePrint(bHash, 32);

        //SHA256_KDF(bHash, 32, NEWHOPE_RINGCT20_POLYBYTES, bpoly);
        //Keccak_256KDF(bHash, 32, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
        poly_frombytes(&c, bpoly);
		poly_serial(&c);
	}
	free(H2q);
	free(A2qp);
	if (poly_equal(&c, c1) ==1)
	{
		return 1;
	}
	return 0;
}

void LRCT_Mint(IW *iw, poly_ringct20 *ck, poly_ringct20 *a, poly_ringct20 *A, int mLen, unsigned char* bMessage, size_t msglen)
{
	LRCT_SampleKey(ck, mLen);
	LRCT_nttCom(&(iw->cn), A, ck, mLen, bMessage, msglen);
	poly_cofcopy(&(iw->a), a);
}
void LRCT_Spend(IW *iwOA, poly_ringct20 *ckOA, poly_ringct20 *c1, poly_ringct20 **t, poly_ringct20 *h, poly_ringct20 *L, unsigned char* bSignMess, size_t sigMsgLen, IW *iws, size_t iwsLen,
    int PaiInd, poly_ringct20 *skPai, poly_ringct20 *ckPai, unsigned char* bVal, size_t bvalLen, poly_ringct20 *OA, poly_ringct20 *A, poly_ringct20 *H, int mLen)
{

	poly_ringct20 *u = (poly_ringct20 *)malloc((mLen+1)*sizeof(poly_ringct20));
	poly_ringct20 *S = (poly_ringct20 *)malloc((mLen) * sizeof(poly_ringct20));
	size_t i;
	poly_ringct20 tmp;
	LRCT_Mint(iwOA, ckOA, OA, A, mLen, bVal, bvalLen);

	for ( i = 0; i < iwsLen; i++)
	{
		poly_add_ringct20(&tmp, &iws[i].a, &iws[i].cn);
		poly_sub_ringct20(L + i, &tmp, &(iwOA->cn));
	}
	LRCT_SampleKey(u, mLen + 1);
	LRCT_MatrixAddMatrix(S, skPai, ckPai, mLen);
	LRCT_MatrixSubMatrix(S, S, ckOA, mLen);
	LRCT_SigGen(c1, t, h, A, H, S, u, mLen, L, iwsLen, PaiInd, bSignMess, sigMsgLen);

	free(u);
	free(S);
}
int LRCT_Verify(poly_ringct20 *c1, poly_ringct20 **t, poly_ringct20 *h, poly_ringct20* A, poly_ringct20 *H, int mLen,
    unsigned char* bSignMess, size_t sigMsgLen, poly_ringct20 *L, int iwsLen)
{
	int result = 0;
	result = LRCT_SigVer(c1, t, A, H, mLen, h, L, iwsLen, bSignMess, sigMsgLen);
	return result;
}
/////multiple
void MIMO_LRCT_Setup(poly_ringct20 *A, poly_ringct20 *H, int mLen)
{
	uint8_t seed[NEWHOPE_RINGCT20_SYMBYTES] = { 0 };
    int i = 0;

	for (i = 0; i < mLen; i++)
	{
        randombytes(seed, NEWHOPE_RINGCT20_SYMBYTES);
		poly_uniform_ringct20(A + i, seed);
		poly_serial(A + i);
        randombytes(seed, NEWHOPE_RINGCT20_SYMBYTES);
		poly_uniform_ringct20(H + i, seed);
		poly_serial(H + i);
	}
}
void MIMO_LRCT_KeyGen(poly_ringct20 *a, poly_ringct20 *A, poly_ringct20 *S, int mLen)
{
	LRCT_MatrixMulPoly(a, A, S, mLen);
	poly_serial(a);
}
void MIMO_LRCT_Mint(IW *iw, poly_ringct20 *ck, poly_ringct20 *a, poly_ringct20 *A, int mLen, unsigned char* bMessage, size_t msglen)
{
	LRCT_SampleKey(ck, mLen);
	LRCT_nttCom(&(iw->cn), A, ck, mLen, bMessage, msglen);
	poly_cofcopy(&(iw->a), a);
}
void MIMO_LRCT_Hash(/*int *pTable, */poly_ringct20 *cn, poly_ringct20 *a, poly_ringct20 *ia, int beta)
{
    //SHA256_CTX ctx;
    Keccak_HashInstance ctx;

//	unsigned char bHash[32] = { 0 };
	unsigned char bpoly[NEWHOPE_RINGCT20_POLYBYTES] = { 0 };
    unsigned char bt[NEWHOPE_RINGCT20_POLYCOMPRESSEDBYTES] = { 0 };
	int i;
	int tmpTable[NEWHOPE_RINGCT20_N] = { 0 };
	for ( i = 0; i < NEWHOPE_RINGCT20_N; i++)
	{
		tmpTable[i] = i;
	}
    Keccak_HashInitialize_SHA3_KDF(&ctx, NEWHOPE_RINGCT20_POLYCOMPRESSEDBYTES);//Keccak_HashInitialize_SHA3_256(&ctx);//SHA256_Init(&ctx);
	////H(L)
	for (i = 0; i < beta; i++)
	{
		poly_tobytes(bpoly, cn + i);
        Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
		poly_tobytes(bpoly, a + i);
        Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
		poly_tobytes(bpoly, ia + i);
        Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
	}///H_1(L||)
    //Keccak_HashFinal(&ctx, bHash);//SHA256_Final(bHash, &ctx);//C_(pai)
    //Keccak_256KDF(bHash, 32, bt, NEWHOPE_RINGCT20_POLYCOMPRESSEDBYTES);//CHECKIT//SHA256_KDF(bHash, 32, NEWHOPE_RINGCT20_POLYCOMPRESSEDBYTES, bt);
    Keccak_HashFinal(&ctx, bt);

}
////

//void ZKP_OR(poly_ringct20 *ck, int bit, int betaLen)
//{}
//////
void MIMO_LRCT_SigGen(poly_ringct20 *c1, poly_ringct20 *tList, poly_ringct20 *hList, poly_ringct20 *SList, int NLen,
	poly_ringct20 *A, poly_ringct20 *H, int mLen,  poly_ringct20 *LList, int wLen, uint8_t pai, unsigned char *msg, int msgLen)
{
	poly_ringct20 *H2q = (poly_ringct20 *)malloc(NLen*(mLen + 1) * sizeof(poly_ringct20));
	poly_ringct20 *A2qp = (poly_ringct20 *)malloc((mLen + 1) * sizeof(poly_ringct20));
	poly_ringct20 *tmp2q = (poly_ringct20 *)malloc((mLen + 1) * sizeof(poly_ringct20));
	poly_ringct20 *u = (poly_ringct20 *)malloc(NLen*(mLen + 1) * sizeof(poly_ringct20));
	poly_ringct20 *S2q = (poly_ringct20 *)malloc((mLen + 1) * sizeof(poly_ringct20));
	/////
    //SHA256_CTX ctx;
    Keccak_HashInstance ctx;

	poly_ringct20 tmp, tmp1, ctmp;
	poly_ringct20 c, cpai;
//	unsigned char bHash[32] = { 0 };
	unsigned char bpoly[NEWHOPE_RINGCT20_POLYBYTES] = { 0 };
	unsigned char bt[NEWHOPE_RINGCT20_POLYBYTES] = { 0 };
	uint8_t coin = 0;
	int i = 0;
	int k = 0;
	int j = 0;
	int index = 0;
    //init dynamic variables
	for (i = 0; i < (mLen + 1); i++)
	{
		poly_init(A2qp + i);
		poly_init(S2q + i);
		poly_init(tmp2q + i);
	}
	for ( i = 0; i < NLen*(mLen+1); i++)
	{
		poly_init(H2q + i);
		poly_init(u+i);
	}
	/////
    Keccak_HashInitialize_SHA3_KDF(&ctx, NEWHOPE_RINGCT20_POLYBYTES);//Keccak_HashInitialize_SHA3_256(&ctx);//SHA256_Init(&ctx);
	////H(L)
	for ( i = 0; i < wLen*NLen; i++)
	{
		poly_tobytes(bpoly, LList + i);
        Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
	}///H_1(L||)
	///H(L||H2q..)
	for (i = 0; i < NLen; i++)
	{
		LRCT_MatrixMulPoly(hList + i, H, SList + i * mLen, mLen);
		LRCT_Lift(H2q + i * (mLen + 1), A, hList + i, mLen);
		for (k = 0; k < mLen + 1; k++)
		{
			poly_tobytes(bpoly, H2q + i * (mLen + 1) + k);
            Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
		}
	}
	////H(L||...||mu)
    Keccak_HashUpdate(&ctx, msg, msgLen*8);//SHA256_Update(&ctx, msg, msgLen);
	/////u
	for ( i = 0; i < NLen; i++)
	{
		for (k = 0; k < mLen + 1; k++)
		{
            randombytes(bt, NEWHOPE_RINGCT20_POLYBYTES);
			poly_frombytes(u + i * (mLen + 1) + k, bt);
			poly_serial(u + i * (mLen + 1) + k);
		}
	}
	//////H(L||...||mu||(A2qp*U ,H2q*U)...||)
	for (i = 0; i < NLen; i++)
	{
		LRCT_Lift(A2qp, A, LList + i*wLen + (pai - 1), mLen);
		LRCT_MatrixMulPoly(&tmp, A2qp, u + i * (mLen + 1), mLen + 1);

		LRCT_MatrixMulPoly(&tmp1, H2q + i * (mLen + 1), u+ i * (mLen + 1), mLen + 1);
		poly_tobytes(bpoly, &tmp);
        Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
		poly_tobytes(bpoly, &tmp1);
        Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
	}
    //Keccak_HashFinal(&ctx, bHash);//Keccak_HashFinal(&ctx, bHash);//SHA256_Final(bHash, &ctx);//C_(pai)
    //Keccak_256KDF(bHash, 32, bt, NEWHOPE_RINGCT20_POLYBYTES);//SHA256_KDF(bHash, 32, NEWHOPE_RINGCT20_POLYBYTES, bt);
    Keccak_HashFinal(&ctx, bt);
	poly_frombytes(&c, bt);
	poly_serial(&c);
	//////////////////////
	poly_cofcopy(&ctmp, &c);
	for (i = 0; i < (wLen-1) ; i++)
	{
		index = (pai + i ) % (wLen);
		if (index == 0)
		{
			poly_cofcopy(c1, &ctmp);
		}

        Keccak_HashInitialize_SHA3_KDF(&ctx, NEWHOPE_RINGCT20_POLYBYTES);//Keccak_HashInitialize_SHA3_256(&ctx);//SHA256_Init(&ctx);
		////H_1(L||)
		for (j = 0; j < wLen*NLen; j++)
		{
			poly_tobytes(bpoly, LList + j);
            Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
		}
		for (j = 0; j < NLen; j++)
		{
			for (k = 0; k < mLen + 1; k++)
			{
				poly_tobytes(bpoly, H2q + j * (mLen + 1) + k);
                Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
			}
		}//H_1(L||H2q)
        Keccak_HashUpdate(&ctx, msg, msgLen*8);//SHA256_Update(&ctx, msg, msgLen);//H(L||...||mu)

		poly_constmul(&tmp1, &ctmp, NEWHOPE_RINGCT20_Q);//qC_i
		for (j = 0; j < NLen; j++)
		{
		   LRCT_Lift(tmp2q, A, LList + j * wLen + index, mLen);
			for (k = 0; k < mLen + 1; k++)
			{
                randombytes(bt, NEWHOPE_RINGCT20_POLYBYTES);
				poly_frombytes(tList + j * wLen*(mLen + 1) + index * (mLen + 1) + k, bt);
				poly_serial(tList + j * wLen*(mLen + 1) + index * (mLen+1)+ k);
			}
			LRCT_MatrixMulPoly(&tmp, tmp2q, tList + j * wLen*(mLen + 1) + index * (mLen + 1), mLen + 1);
		
			poly_add_ringct20(&tmp, &tmp, &tmp1);//(+ qC_i)% Q
			poly_tobytes(bpoly, &tmp);
            Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);//
			////////
			LRCT_MatrixMulPoly(&tmp, H2q + j * (mLen + 1), tList + j * wLen*(mLen + 1) + index * (mLen + 1), mLen + 1);
			poly_add_ringct20(&tmp, &tmp, &tmp1);//(+ qC_i)% Q
			poly_tobytes(bpoly, &tmp);
            Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);//H2q*U
		}
        //Keccak_HashFinal(&ctx, bHash);//SHA256_Final(bHash, &ctx);//
        //Keccak_256KDF(bHash, 32, bt, NEWHOPE_RINGCT20_POLYBYTES);//SHA256_KDF(bHash, 32, NEWHOPE_RINGCT20_POLYBYTES, bt);
        Keccak_HashFinal(&ctx, bt);
		poly_frombytes(&ctmp, bt);
		poly_serial(&ctmp);//C_{index+1}
		if (index == (pai - 2))
		{
			poly_cofcopy(&cpai, &ctmp);
			break;
		}
	}
	for ( i = 0; i < NLen; i++)
	{
		poly_copy(S2q, SList+i*mLen, mLen);
		poly_setValue(S2q + mLen, 1);//S_{2q}
		//////
        randombytes(&coin, 1);
		LRCT_PolyMultMatrix(tmp2q, &cpai, S2q, mLen + 1);//S2qpai *c_pai
		if (coin & 0x01)//b =1
		{
            LRCT_MatrixSubMatrix(tList + i * wLen*(mLen + 1) + (pai - 1) * (mLen + 1), u + i * (mLen + 1), tmp2q, mLen + 1);
		}
		else {
            LRCT_MatrixAddMatrix(tList + i * wLen*(mLen + 1) + (pai - 1) * (mLen + 1), u + i * (mLen + 1), tmp2q, mLen + 1);
		}
	}
	/////
    //free variables
		free(A2qp);
		free(S2q);
		free(tmp2q);
		free(H2q );
		free(u);


}
int MIMO_LRCT_SigVer(poly_ringct20 *c1, poly_ringct20 *tList, poly_ringct20 *hList, int NLen, poly_ringct20 *A,/* poly_ringct20 *H,*/
    int mLen, poly_ringct20 *LList, int wLen, unsigned char *msg, int msgLen)
{
    int i,j, k;
	poly_ringct20 *H2q = (poly_ringct20 *)malloc(NLen*(mLen + 1) * sizeof(poly_ringct20));
	poly_ringct20 *A2qp = (poly_ringct20 *)malloc((mLen + 1) * sizeof(poly_ringct20));
	poly_ringct20 ctmp,tmp, tmp1;
    //SHA256_CTX ctx;
    Keccak_HashInstance ctx;

//	unsigned char bHash[32] = { 0 };
	unsigned char bpoly[NEWHOPE_RINGCT20_POLYBYTES] = { 0 };
	/////////
	poly_cofcopy(&ctmp, c1);
	for (i = 0; i < NLen; i++)
	{
		LRCT_Lift(H2q + i * (mLen + 1), A, hList + i, mLen);
	}
	//////
	for (i = 0; i < wLen; i++)
	{
        Keccak_HashInitialize_SHA3_KDF(&ctx, NEWHOPE_RINGCT20_POLYBYTES);//Keccak_HashInitialize_SHA3_256(&ctx);//SHA256_Init(&ctx);
		for (k = 0; k < wLen*NLen; k++)
		{
			poly_tobytes(bpoly, LList + k);
            Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
		}///H_1(L||)
		for (j = 0; j< NLen; j++)
		{
			for (k = 0; k < (mLen + 1); k++)
			{
				poly_tobytes(bpoly, H2q + j * (mLen + 1) + k);
                Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
			}
		}
        Keccak_HashUpdate(&ctx, msg, msgLen*8);//Keccak_HashUpdate(&ctx, msg, msgLen*8);//SHA256_Update(&ctx, msg, msgLen);//H(L||...||mu)

		poly_constmul(&tmp1, &ctmp, NEWHOPE_RINGCT20_Q);//qC_i
		for ( j = 0; j < NLen; j++)
		{
			LRCT_Lift(A2qp, A, LList + j * wLen + i , mLen);
			LRCT_MatrixMulPoly(&tmp, A2qp, tList + j * wLen*(mLen + 1) + i * (mLen + 1), mLen + 1);
			poly_add_ringct20(&tmp, &tmp, &tmp1);//(+ qC_i)% Q
			poly_tobytes(bpoly, &tmp);
            Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);
			
			LRCT_MatrixMulPoly(&tmp, H2q + j * (mLen + 1), tList + j * wLen*(mLen + 1) + i* (mLen + 1), mLen + 1);
			poly_add_ringct20(&tmp, &tmp, &tmp1);//(+ qC_i)% Q
			poly_tobytes(bpoly, &tmp);
            Keccak_HashUpdate(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES*8);//SHA256_Update(&ctx, bpoly, NEWHOPE_RINGCT20_POLYBYTES);//H2q*U
		}
        //Keccak_HashFinal(&ctx, bHash);//SHA256_Final(bHash, &ctx);//
        //Keccak_256KDF(bHash, 32, bpoly, NEWHOPE_RINGCT20_POLYBYTES);//SHA256_KDF(bHash, 32, NEWHOPE_RINGCT20_POLYBYTES, bpoly);
        Keccak_HashFinal(&ctx, bpoly);
		poly_frombytes(&ctmp, bpoly);
		poly_serial(&ctmp);//
	}
	if (poly_equal(&ctmp, c1) == 1)
	{
		return 1;
	}
	return 0;	
}





void LRCT_Lift(poly_ringct20 *LA, poly_ringct20 *A, poly_ringct20 *a, int mLen)
{
    int i = 0;
    int j = 0;
	for ( i = 0; i < mLen; i++)
	{
		for ( j = 0; j < NEWHOPE_RINGCT20_N; j++)
		{
			LA[i].coeffs[j] = 2 * A[i].coeffs[j];
		}	
	}
	for ( j = 0; j < NEWHOPE_RINGCT20_N; j++)
	{
		LA[mLen].coeffs[j] = coeff_freeze2Q(NEWHOPE_RINGCT20_2Q+ NEWHOPE_RINGCT20_Q - a->coeffs[j] * 2);
	}
}

void LRCT_Com(poly_ringct20 *r, poly_ringct20 *A, poly_ringct20 *sk, int mLen, unsigned char *bMessage, size_t msglen)
{
	poly_ringct20 tmp;
    size_t j;

	LRCT_MatrixMulPoly(&tmp, A, sk, mLen);
	poly_cofcopy(r, &tmp);
	for (j = 0; j < msglen; j++)
	{

		r->coeffs[j * 8 + 0] = (tmp.coeffs[j * 8 + 0] + (bMessage[j]&0x01))%NEWHOPE_RINGCT20_Q;
		r->coeffs[j * 8 + 1] = (tmp.coeffs[j * 8 + 1] + ((bMessage[j] & 0x02) >> 1)) % NEWHOPE_RINGCT20_Q;
		r->coeffs[j * 8 + 2] = (tmp.coeffs[j * 8 + 2] + ((bMessage[j] & 0x04) >> 2)) % NEWHOPE_RINGCT20_Q;
		r->coeffs[j * 8 + 3] = (tmp.coeffs[j * 8 + 3] + ((bMessage[j] & 0x08) >> 3)) % NEWHOPE_RINGCT20_Q;
		r->coeffs[j * 8 + 4] = (tmp.coeffs[j * 8 + 4] + ((bMessage[j] & 0x10) >> 4)) % NEWHOPE_RINGCT20_Q;
		r->coeffs[j * 8 + 5] = (tmp.coeffs[j * 8 + 5] + ((bMessage[j] & 0x20) >> 5)) % NEWHOPE_RINGCT20_Q;
		r->coeffs[j * 8 + 6] = (tmp.coeffs[j * 8 + 6] + ((bMessage[j] & 0x40) >> 6)) % NEWHOPE_RINGCT20_Q;
		r->coeffs[j * 8 + 7] = (tmp.coeffs[j * 8 + 7] + ((bMessage[j] & 0x80) >> 7)) % NEWHOPE_RINGCT20_Q;
	}

}
void LRCT_nttCom(poly_ringct20 *r, poly_ringct20 *A, poly_ringct20 *sk, int mLen, unsigned char *bMessage, size_t msglen)
{
	poly_ringct20 tmp, pMess;
	size_t j;
	poly_init(&pMess);
	LRCT_MatrixMulPoly(&tmp, A, sk, mLen);
	//poly_cofcopy(r, &tmp);
	for (j = 0; j < msglen; j++)
	{

		pMess.coeffs[j * 8 + 0] =  (bMessage[j] & 0x01) % NEWHOPE_RINGCT20_Q;
		pMess.coeffs[j * 8 + 1] = (((bMessage[j] & 0x02) >> 1)) % NEWHOPE_RINGCT20_Q;
		pMess.coeffs[j * 8 + 2] = (((bMessage[j] & 0x04) >> 2)) % NEWHOPE_RINGCT20_Q;
		pMess.coeffs[j * 8 + 3] = ( ((bMessage[j] & 0x08) >> 3)) % NEWHOPE_RINGCT20_Q;
		pMess.coeffs[j * 8 + 4] = ( ((bMessage[j] & 0x10) >> 4)) % NEWHOPE_RINGCT20_Q;
		pMess.coeffs[j * 8 + 5] = ( ((bMessage[j] & 0x20) >> 5)) % NEWHOPE_RINGCT20_Q;
		pMess.coeffs[j * 8 + 6] = (((bMessage[j] & 0x40) >> 6)) % NEWHOPE_RINGCT20_Q;
		pMess.coeffs[j * 8 + 7] = ( ((bMessage[j] & 0x80) >> 7)) % NEWHOPE_RINGCT20_Q;
	}
	poly_ntt_ringct20(&pMess);
	poly_add_ringct20(r, &tmp, &pMess);
}



//N*M mul M*1  
void LRCT_MatrixMulPoly(poly_ringct20 *r, poly_ringct20 *A, poly_ringct20 *s, int mLen)
{
    int i;
	poly_ringct20 tmp, tmpA, tmps;
	poly_init(r);
	for ( i = 0; i < mLen; i++)
	{
		poly_cofcopy(&tmpA, A + i);
		poly_cofcopy(&tmps, s + i);
	  // poly_ntt_ringct20(&tmpA);
		//poly_ntt_ringct20(&tmps);
		poly_mul_pointwise(&tmp, &tmpA, &tmps);
		poly_add_ringct20(r, r, &tmp);
	}
	//poly_invntt(r);
}
//M*N  mul N*1
void LRCT_PolyMultMatrix(poly_ringct20 *r, poly_ringct20 *p, poly_ringct20 *A, int mLen)
{
    for (int i = 0; i < mLen; i++)
	{
		poly_mul_pointwise(r+i, A+i, p);
	}
}

void LRCT_MatrixAddMatrix(poly_ringct20 *R, poly_ringct20 *A, poly_ringct20 *B, int mLen)
{
    for (int i = 0; i < mLen; i++)
	{
		poly_add_ringct20(R + i, A + i, B + i);
	}
}
void LRCT_MatrixSubMatrix(poly_ringct20 *R, poly_ringct20 *A, poly_ringct20 *B, int mLen)
{
    for (int i = 0; i < mLen; i++)
	{
		poly_sub_ringct20(R + i, A + i, B + i);
	}
}

void LRCT_ConstMulMatrix(poly_ringct20 *r, const poly_ringct20 *A, uint16_t cof, int mLen)
{
    int i, j;
	for (i = 0; i < mLen; i++)
	{
		for ( j = 0; j < NEWHOPE_RINGCT20_N; j++)
		{
			r[i].coeffs[j] = cof * A[i].coeffs[j];
		}
		
	}
}
///
void LRCT_MatrixShift(poly_ringct20 *desCK, poly_ringct20* rCK, int mLen, int iNumber)
{
    for (int i = 0; i < mLen; i++)
	{
		poly_shift(desCK + i, rCK + i, iNumber);
	}
}

void LRCT_GetCK0(poly_ringct20 *CK0, poly_ringct20 * CK, int mLen, poly_ringct20* CKi, int messBitLen)
{
    int i;
	poly_ringct20 *tmp = (poly_ringct20 *)malloc((mLen) * sizeof(poly_ringct20));
	poly_ringct20 *desCK = (poly_ringct20 *)malloc((mLen) * sizeof(poly_ringct20));
	for (i = 0; i < (mLen); i++)
	{
		poly_init(tmp + i);
		poly_init(desCK + i);
	}

	for ( i = 0; i < messBitLen; i++)
	{
		LRCT_MatrixShift(desCK, CKi + i * mLen, mLen, i + 1);
		LRCT_MatrixAddMatrix(tmp, tmp, desCK, mLen);
	}
	LRCT_MatrixSubMatrix(CK0, CK, tmp, mLen);
	free(tmp);
	free(desCK);
}
