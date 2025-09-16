#ifndef RING_RINGCT20_H
#define RING_RINGCT20_H


#include "params.h"
#include "poly.h"
#include"dap_crypto_common.h"
/**
*function: setup

*/

typedef struct {
    poly_ringct20 a;
    poly_ringct20 cn;
} IW;

void LRCT_Setup(poly_ringct20 *A, poly_ringct20 *H, int mLen);
void LRCT_KeyGen(poly_ringct20 *a, poly_ringct20 *A, poly_ringct20 *S, int mLen);
void LRCT_SigGen(poly_ringct20 *c1, poly_ringct20 **t, poly_ringct20 *h, poly_ringct20 *A, poly_ringct20 *H,
                 poly_ringct20 *S, poly_ringct20 *u, int mLen, poly_ringct20 *L, int w,
                 int pai, const unsigned char *msg, int msgLen);
int LRCT_SigVer(const poly_ringct20 *c1, poly_ringct20 **t, poly_ringct20 *A, poly_ringct20 *H, int mLen, poly_ringct20 *h, poly_ringct20 *L,
                int w, const unsigned char *msg, int msgLen);
/////Single output trading scheme
/*
plan description:
*/
void LRCT_Mint(IW *iw, poly_ringct20 *ck, poly_ringct20 *a, poly_ringct20 *A, int mLen, unsigned char* bMessage, size_t msglen);
void LRCT_Spend(IW *iwOA, poly_ringct20 *ckOA, poly_ringct20 *c1, poly_ringct20 **t, poly_ringct20 *h, poly_ringct20 *L, unsigned char* bSignMess, size_t sigMsgLen, IW *iws, size_t iwsLen,
                int PaiInd, poly_ringct20 *skPai, poly_ringct20 *ckPai, unsigned char* bVal, size_t bvalLen, poly_ringct20 *OA, poly_ringct20 *A, poly_ringct20 *H, int mLen);
int LRCT_Verify(poly_ringct20 *c1, poly_ringct20 **t, poly_ringct20 *h, poly_ringct20* A, poly_ringct20 *H, int mLen,
    unsigned char* bSignMess, size_t sigMsgLen, poly_ringct20 *L, int iwsLen);

//
/*
MIMO SCheme
*/

/*
Function declaration: system initialization, generating public parameters
Output: public matrix A, H, row number mLen
*/
void MIMO_LRCT_Setup(poly_ringct20 *A, poly_ringct20 *H, int mLen);
/*
Function declaration: key generation.
Input: matrix A, private key S, matrix row number mLen
Output: user public key
*/
void MIMO_LRCT_KeyGen(poly_ringct20 *a, poly_ringct20 *A, poly_ringct20 *S, int mLen);
/*
Function declaration: signature generation
Input: private key list SList, length NLen, public parameters A, H, matrix width mLen, public key list LList, length wLen, trader position pai, signature message msg, message length msgLen
Output: polynomial c1, t-list tList, h-list hList.
*/
void MIMO_LRCT_SigGen(poly_ringct20 *c1, poly_ringct20 *tList, poly_ringct20 *hList, poly_ringct20 *SList, int NLen,
    poly_ringct20 *A, poly_ringct20 *H, int mLen, poly_ringct20 *LList, int wLen, uint8_t pai, unsigned char *msg, int msgLen);
/*
Function declaration: signature verification
Input: signature (c1, t-list tList, h-list: hList, number of transactions, public parameters A, H, matrix width mLen, public key list LList, list length wLen, signature message, message length)
*/
int MIMO_LRCT_SigVer(poly_ringct20 *c1, poly_ringct20 *tList, poly_ringct20 *hList, int NLen, poly_ringct20 *A, /*poly_ringct20 *H,*/
    int mLen, poly_ringct20 *LList, int wLen, unsigned char *msg, int msgLen);
/*

*/
void MIMO_LRCT_Mint(IW *iw, poly_ringct20 *ck, poly_ringct20 *a, poly_ringct20 *A, int mLen, unsigned char* bMessage, size_t msglen);
/// 
void MIMO_LRCT_Hash(/*int *pTable, */poly_ringct20 *cn, poly_ringct20 *a, poly_ringct20 *ia, int beta);

//////
void ZKP_OR(poly_ringct20 *ck , int bit, int betaLen);
////////////

void LRCT_Lift(poly_ringct20 *LA, poly_ringct20 *A, poly_ringct20 *a, int mLen);
/*
Function declaration: promise message m, r = A * sk + m
Input: public matrix A, private key sk, matrix row number mLen, acknowledge message m, message length bMessage
Output: Commitment r (polynomial N * 1)
*/
void LRCT_Com(poly_ringct20 *r, poly_ringct20 *A, poly_ringct20 *sk, int mLen, unsigned char *bMessage, size_t msglen);
void LRCT_nttCom(poly_ringct20 *r, poly_ringct20 *A, poly_ringct20 *sk, int mLen, unsigned char *bMessage, size_t msglen);

/*
Function declaration: matrix A (N * M) * matrix s (M * 1)
Input: matrix A, matrix s, matrix rows mLen
Output: matrix r = A * s (N * 1)
*/
void LRCT_MatrixMulPoly(poly_ringct20 *r, poly_ringct20 *A, poly_ringct20 *s, int mLen);
/*
Function declaration: constant * matrix
Input: constant cof, matrix A, number of matrix rows (mLen)
Output: matrix r
*/
void LRCT_ConstMulMatrix(poly_ringct20 *r, const poly_ringct20 *A, uint16_t cof, int mLen);
/*
Function declaration: matrix A (M rows and N columns) * polynomial p (N rows and 1 column)
Input: polynomial p, matrix A, matrix rows mLen
Output: polynomial r (M rows and 1 column)
*/
void LRCT_PolyMultMatrix(poly_ringct20 *r, poly_ringct20 *p, poly_ringct20 *A,  int mLen);
/*
Function declaration: matrix addition (A + B)
Input: matrix A, matrix B, matrix size mLen
Output: Matrix R = (A + B)
*/
void LRCT_MatrixAddMatrix(poly_ringct20 *R, poly_ringct20 *A, poly_ringct20 *B, int mLen);
/*
Function declaration: Matrix subtraction (A-B)
Input: matrix A, matrix B, matrix size mLen
Output: Matrix R = (A-B)
*/
void LRCT_MatrixSubMatrix(poly_ringct20 *R, poly_ringct20 *A, poly_ringct20 *B, int mLen);

///////////////////*
/*
Function declaration: key extraction function
Input: Key length mLen
Output: polynomial matrix r (n * mLen)
*/
/////////////////
void LRCT_SampleKey(poly_ringct20 *r, int mLen);

void LRCT_MatrixShift(poly_ringct20 *desCK, poly_ringct20* rCK, int mLen, int iNumber);

void LRCT_GetCK0(poly_ringct20 *CK0, poly_ringct20 * CK, int mLen, poly_ringct20* CKi, int messBitLen);
#endif

