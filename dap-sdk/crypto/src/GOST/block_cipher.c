/** @file 
* @brief Реализация режимов работы блочных алгоритмов
*
* @copyright InfoTeCS. All rights reserved.
*/

#include <stdio.h>
#include <memory.h>
#ifdef __MACH__
#include <sys/malloc.h>
#endif
#include <stdlib.h>

#include "28147_14.h"
#include "28147_89.h"
#include "block_cipher.h"

/** @brief определение внутреннего ассерта */
#define INFOTECS_ASSERT(e) typedef char __C_ASSERT__[(e)?1:-1]

/** @brief размер тестовых данных для алгоритма "кузнечик" */
#define textLen14 sizeof(kSeltTestGost14PlainText)/sizeof(kSeltTestGost14PlainText[0])
/** @brief размер тестовых данных для алгоритма 28147-89 */
#define textLen89 sizeof(kSeltTestGost89PlainText)/sizeof(kSeltTestGost89PlainText[0])

/** @brief Признак алгоритма "Кузнечик" */
const unsigned char kAlg14 = 1;

/** @brief Признак алгоритма 28147-89 */
const unsigned char kAlg89 = 2;

/** @brief указатель на функцию шифрования */
typedef int (DLL_IMPORT *pEncrypt)(const unsigned char* plainText, unsigned char* chipherText, unsigned char* keys, printout_byte_array print, printout_uint_array print_uint);

/** @brief указатель на функцию расшифрования */
typedef int (DLL_IMPORT *pDecrypt)(const unsigned char* chipherText, unsigned char* plainText, unsigned char* keys, printout_byte_array print, printout_uint_array print_uint);

/** @brief Функция самотестирования режима ECB */
static int SelfTestGost14Ecb();

/** @brief Функция самотестирования режима ECB */
static int SelfTestGost89Ecb();

/** @brief Функция самотестирования режима CTR */
static int SelfTestGost14Ctr();

/** @brief Функция самотестирования режима CTR */
static int SelfTestGost89Ctr();

/** @brief Функция самотестирования режима OFB */
static int SelfTestGost14Ofb();

/** @brief Функция самотестирования режима OFB */
static int SelfTestGost89Ofb();

/** @brief Функция самотестирования режима CBC */
static int SelfTestGost14Cbc();

/** @brief Функция самотестирования режима CBC */
static int SelfTestGost89Cbc();

/** @brief Функция самотестирования режима CFB */
static int SelfTestGost14Cfb();

/** @brief Функция самотестирования режима CFB */
static int SelfTestGost89Cfb();

/** @brief Функция самотестирования режима имитовставки */
static int SelfTestGost14Imit();

/** @brief Функция самотестирования режима имитовставки */
static int SelfTestGost89Imit();

/** @brief Сдвиг влево на 1 бит */
static void ShifttLeftOne(unsigned char *r, size_t length);

/** @brief Контекст ECB */  
typedef struct 
{
     unsigned char Alg; /**< идентификатор алгоритма */
     unsigned char* Keys; /**< ключ */ 
     unsigned int BlockLen; /**< размер блока */ 
     printout_byte_array PrintByteArray; /**< функция логирования */
     printout_uint_array PrintUIntArray; /**< функция логирования */
     pEncrypt EncryptFunc; /**< функция шифрования */
     pDecrypt DecryptFunc; /**< функция расшифрования */
} Context_ecb;

/** @brief Контекст CTR */
typedef struct 
{
     unsigned char Alg; /**< идентификатор алгоритма */
     unsigned char* Counter; /**< счетчик */
     unsigned char* Keys; /**< ключ */ 
     size_t S; /**< размер синхропосылки */
     size_t BlockLen;  /**< размер блока */ 
     printout_byte_array PrintByteArray; /**< функция логирования */
     printout_uint_array PrintUIntArray; /**< функция логирования */
     pEncrypt EncryptFunc; /**< функция шифрования */
     unsigned char *tmpblock; /**< временный блок */
} Context_ctr;

/** @brief Контекст OFB */
typedef struct 
{
     unsigned char Alg; /**< идентификатор алгоритма */
     unsigned char* IV; /**< синхропосылка */
     unsigned char* Keys;  /**< ключ */ 
     size_t M; /**< размер синхрпосылки */
     size_t S; /**< параметр S */
     size_t BlockLen; /**< размер блока */ 
     printout_byte_array PrintByteArray; /**< функция логирования */
     printout_uint_array PrintUIntArray; /**< функция логирования */
     pEncrypt EncryptFunc; /**< функция шифрования */
     pDecrypt DecryptFunc; /**< функция расшифрования */
     unsigned char *tmpblock;  /**< временный блок */
     unsigned char* nextIV; /**< синхропосылка для следующего блока */
} Context_ofb;

/** @brief Контекст CFB */
typedef struct 
{
     unsigned char Alg; /**< идентификатор алгоритма */
     unsigned char* IV; /**< синхропосылка */
     unsigned char* Keys; /**< ключ */ 
     size_t M; /**< размер синхрпосылки */
     size_t S; /**< параметр S */
     size_t BlockLen; /**< размер блока */
     printout_byte_array PrintByteArray; /**< функция логирования */
     printout_uint_array PrintUIntArray; /**< функция логирования */
     pEncrypt EncryptFunc; /**< функция шифрования */
     pDecrypt DecryptFunc; /**< функция расшифрования */
     unsigned char *tmpblock; /**< временный блок */
     unsigned char* nextIV; /**< синхропосылка для следующего блока */
} Context_cfb;

/** @brief Контекст CBC */
typedef struct 
{
     unsigned char Alg; /**< идентификатор алгоритма */
     unsigned char* IV; /**< синхропосылка */
     unsigned char* Keys; /**< ключ */
     size_t BlockLen; /**< размер блока */
     size_t M; /**< размер синхрпосылки */
     printout_byte_array PrintByteArray; /**< функция логирования */
     printout_uint_array PrintUIntArray; /**< функция логирования */
     pEncrypt EncryptFunc; /**< функция шифрования */
     pDecrypt DecryptFunc; /**< функция расшифрования */
     unsigned char* nextIV; /**< синхропосылка для следующего блока */
     unsigned char* tempIV; /**< для временного хранения значения синхропосылки */
     unsigned char *tmpblock; /**< временный блок */
} Context_cbc;

/** @brief Контекст имитовставки */
typedef struct 
{
     unsigned char Alg; /**< идентификатор алгоритма */
     unsigned char* Keys; /**< ключ */
     unsigned char* K1; /**< вспомогательный параметр K1 */
     unsigned char* K2; /**< вспомогательный параметр K2 */
     unsigned char* B; /**< вспомогательный параметр B */
     unsigned char* R; /**< вспомогательный параметр R */
     unsigned char* C; /**< вспомогательный параметр C */
     unsigned char* LastBlock; /**< предыдущий блок */
     size_t S; /**< параметр S */
     size_t BlockLen; /**< размер блока */
     size_t LastBlockSize; /**< размер предыдущего блока */
     int isFistBlock; /**< идентификатор первого блока */
     printout_byte_array PrintByteArray; /**< функция логирования */
     printout_uint_array PrintUIntArray; /**< функция логирования */
     pEncrypt EncryptFunc; /**< функция шифрования */
     unsigned char *tmpblock; /**< временный блок */
     unsigned char *resimit; /**< имитовставка */
} Context_imit;

static int init_ecb_14_impl(unsigned char *key, void* ctx, printout_byte_array print, printout_uint_array print_uint)
{
     Context_ecb* context = 0;
     INFOTECS_ASSERT(sizeof(Context_ecb)<=kEcb14ContextLen);

     if(!ctx || !key)
          return -1;

     context = (Context_ecb*)ctx;

     context->Alg = kAlg14;
     context->EncryptFunc = Encrypt_14;
     context->DecryptFunc = Decrypt_14;
     context->BlockLen = kBlockLen14;

     context->PrintByteArray = print;
     context->PrintUIntArray = print_uint;

     context->Keys = (unsigned char*)malloc(10 * kBlockLen14);
     if( !context->Keys ) {
         //free_ecb(context); // eventually no other fields
         return -1;
     }
     memset(context->Keys, 0, 10 * kBlockLen14);

     ExpandKey(key, context->Keys, print);
     return 0;
}

int DLL_IMPORT init_ecb_14(unsigned char *key, void* ctx, printout_byte_array print, printout_uint_array print_uint)
{
     if(SelfTestGost14Ecb())
          return -1;

     return init_ecb_14_impl(key, ctx, print, print_uint);
}

static int init_ecb_89_impl(unsigned char *key, void* ctx, printout_byte_array print, printout_uint_array print_uint)
{
     Context_ecb* context;
     INFOTECS_ASSERT(sizeof(Context_ecb)<=kEcb89ContextLen);

     if(!ctx || !key)
          return -1;

     context = (Context_ecb*)ctx;

     context->Alg = kAlg89;

     context->PrintByteArray = print;
     context->PrintUIntArray = print_uint;

     context->EncryptFunc = Encrypt_89;
     context->DecryptFunc = Decrypt_89;
     context->BlockLen = kBlockLen89;

     context->Keys = (unsigned char*)malloc(kKeyLen89);
     if( !context->Keys )
          return -1;
     memcpy(context->Keys, key, kKeyLen89);

     return 0;
}

int DLL_IMPORT init_ecb_89(unsigned char *key, void* ctx, printout_byte_array print, printout_uint_array print_uint)
{
     if(SelfTestGost89Ecb())
          return -1;
     return init_ecb_89_impl(key, ctx, print, print_uint);
}

void DLL_IMPORT free_ecb(void* ctx)
{
     Context_ecb* context;

     if(!ctx)
          return;

     context = (Context_ecb*)(ctx);

     if(context->Keys)
     {
          free(context->Keys);
          context->Keys = 0;
     }
}

static int init_cbc_14_impl(unsigned char *key, void* ctx, const unsigned char *iv, size_t ivLength, printout_byte_array print, printout_uint_array print_uint)
{
     Context_cbc* context;
     INFOTECS_ASSERT(sizeof(Context_cbc)<=kCbc14ContextLen);

     if(!ctx || !key || !iv || (ivLength % kBlockLen14))
          return -1;

     context = (Context_cbc*)ctx;

     context->Alg = kAlg14;

     context->PrintByteArray = print;
     context->PrintUIntArray = print_uint;

     context->EncryptFunc = Encrypt_14;
     context->DecryptFunc = Decrypt_14;

     context->BlockLen = kBlockLen14;

     context->M = ivLength;

     context->IV = (unsigned char*)malloc(ivLength);
     context->Keys = (unsigned char*)malloc(10 * kBlockLen14);
     context->tempIV = (unsigned char*)malloc(context->M);
     context->nextIV = (unsigned char*)malloc(context->M);
     context->tmpblock = (unsigned char *)malloc(kBlockLen14);
     if( !context->IV || !context->Keys || !context->tempIV || !context->nextIV || !context->tmpblock ) {
         free_cbc(context);
         return -1;
     }
     memcpy(context->IV, iv, ivLength);
     memset(context->Keys, 0, 10 * kBlockLen14);

     ExpandKey(key, context->Keys, print);
     return 0;
}

int DLL_IMPORT init_cbc_14(unsigned char *key, void* ctx, const unsigned char *iv, size_t ivLength, printout_byte_array print, printout_uint_array print_uint)
{
     if(SelfTestGost14Cbc())
          return -1;
     return init_cbc_14_impl(key, ctx, iv, ivLength, print, print_uint);
}

static int init_cbc_89_impl(unsigned char *key, void* ctx, const unsigned char *iv, size_t ivLength, printout_byte_array print, printout_uint_array print_uint)
{
     Context_cbc* context;
     INFOTECS_ASSERT(sizeof(Context_cbc)<=kCbc89ContextLen);

     if(!ctx || !key || !iv || (ivLength % kBlockLen89))
          return -1;

     context = (Context_cbc*)ctx;

     context->Alg = kAlg89;

     context->PrintByteArray = print;
     context->PrintUIntArray = print_uint;

     context->EncryptFunc = Encrypt_89;
     context->DecryptFunc = Decrypt_89;

     context->BlockLen = kBlockLen89;

     context->M = ivLength;

     context->IV = (unsigned char*)malloc(ivLength);
     context->Keys = (unsigned char*)malloc(kKeyLen89);
     context->tempIV = (unsigned char*)malloc(context->M);
     context->nextIV = (unsigned char*)malloc(context->M);
     context->tmpblock = (unsigned char *)malloc(kBlockLen89);

     if( !context->IV || !context->Keys || !context->tempIV || !context->nextIV || !context->tmpblock ) {
         free_cbc(context);
        return -1;
     }

     memcpy(context->IV, iv, ivLength);
     memcpy(context->Keys, key, kKeyLen89);

     return 0;
}

int DLL_IMPORT init_cbc_89(unsigned char *key, void* ctx, const unsigned char *iv, size_t ivLength, printout_byte_array print, printout_uint_array print_uint)
{
     if(SelfTestGost89Cbc())
          return -1;
     return init_cbc_89_impl(key, ctx, iv, ivLength, print, print_uint);
}

void DLL_IMPORT free_cbc(void* ctx)
{
     Context_cbc* context;

     if(!ctx)
          return;

     context = (Context_cbc*)ctx;

     if(context->Keys)
     {
          free(context->Keys);
          context->Keys = 0;
     }

     if(context->IV)
     {
          free(context->IV);
          context->IV = 0;
     }

     if(context->tempIV)
     {
          free(context->tempIV);
          context->tempIV = 0;
     }
     if(context->nextIV)
     {
          free(context->nextIV);
          context->nextIV = 0;
     }
     if(context->tmpblock)
     {
          free(context->tmpblock);
          context->tmpblock = 0;
     }
}

static int init_ctr_14_impl(unsigned char* key, const unsigned char *iv, size_t s, void *ctx, printout_byte_array print, printout_uint_array print_uint)
{
     Context_ctr* context;
     INFOTECS_ASSERT(sizeof(Context_ctr)<=kCtr14ContextLen);

     if(!ctx || !key || s > kBlockLen14)
          return -1;

     context = (Context_ctr*)ctx;

     context->Alg = kAlg14;

     context->PrintByteArray = print;
     context->PrintUIntArray = print_uint;

     context->EncryptFunc = Encrypt_14;

     context->BlockLen = kBlockLen14;

     context->S = s;

     context->tmpblock = (unsigned char*)malloc(kBlockLen14);
     context->Keys = (unsigned char*)malloc(10*kBlockLen14);
     context->Counter = (unsigned char*)malloc(kBlockLen14);
     if( !context->tmpblock || !context->Keys || !context->Counter ) {
         free_ctr(context);
         return -1;
     }

     memset(context->Keys, 0, 10 * kBlockLen14);
     ExpandKey(key, context->Keys, print);

     memset(context->Counter, 0, kBlockLen14);
     memcpy(context->Counter, iv, kBlockLen14/2);

     return 0;
}

int DLL_IMPORT init_ctr_14(unsigned char* key, const unsigned char *iv, size_t s, void *ctx, printout_byte_array print, printout_uint_array print_uint)
{
     if(SelfTestGost14Ctr())
          return -1;
     return init_ctr_14_impl(key, iv, s, ctx, print, print_uint);
}

static int init_ctr_89_impl(unsigned char* key, const unsigned char *iv, size_t s, void *ctx, printout_byte_array print, printout_uint_array print_uint)
{
     Context_ctr* context;
     INFOTECS_ASSERT(sizeof(Context_ctr)<=kCtr89ContextLen);

     if(!ctx || !key || s > kBlockLen89)
          return -1;

     context = (Context_ctr*)ctx;

     context->Alg = kAlg89;

     context->PrintByteArray = print;
     context->PrintUIntArray = print_uint;

     context->EncryptFunc = Encrypt_89;

     context->BlockLen = kBlockLen89;

     context->S = s;

     context->tmpblock = (unsigned char*)malloc(kKeyLen89);
     context->Keys = (unsigned char*)malloc(kKeyLen89);
     context->Counter = (unsigned char*)malloc(kBlockLen89);

     if( !context->tmpblock || !context->Keys || !context->Counter ) {
         free_ctr(context);
         return -1;
     }
     memcpy(context->Keys, key, kKeyLen89);
     memset(context->Counter, 0, kBlockLen89);
     memcpy(context->Counter, iv, kBlockLen89/2);

     return 0;
}

int DLL_IMPORT init_ctr_89(unsigned char* key, const unsigned char *iv, size_t s, void *ctx, printout_byte_array print, printout_uint_array print_uint)
{
     if(SelfTestGost89Ctr())
          return -1;
     return init_ctr_89_impl(key, iv, s, ctx, print, print_uint);
}

void DLL_IMPORT free_ctr(void* ctx)
{
     Context_ctr* context;

     if(!ctx)
          return;

     context = (Context_ctr*)ctx;

     if(context->Keys)
     {
          free(context->Keys);
          context->Keys = 0;
     }

     if(context->Counter)
     {
          free(context->Counter);
          context->Counter = 0;
     }

     if(context->tmpblock)
     {
          free(context->tmpblock);
          context->tmpblock = 0;
     }
}

static int init_ofb_14_impl(unsigned char *key, void *ctx, size_t s, const unsigned char *iv, size_t ivLength, printout_byte_array print, printout_uint_array print_uint)
{
     Context_ofb* context;
     INFOTECS_ASSERT(sizeof(Context_ofb)<=kOfb14ContextLen);

     if(!ctx || !key || s > kBlockLen14 || (ivLength % kBlockLen14) || !ivLength || !s)
          return -1;

     context = (Context_ofb*)ctx;

     context->Alg = kAlg14;

     context->PrintByteArray = print;
     context->PrintUIntArray = print_uint;

     context->EncryptFunc = Encrypt_14;
     context->DecryptFunc = Decrypt_14;

     context->BlockLen = kBlockLen14;

     if (!(context->IV = (unsigned char*)malloc(ivLength))
             || !(context->tmpblock = (unsigned char*)malloc(kBlockLen14))
             || !(context->nextIV = (unsigned char*)malloc(ivLength))
             || !(context->Keys = (unsigned char*)malloc(10*kBlockLen14))) {
         free_ofb(context);
         return -1;
     }

     memcpy(context->IV, iv, ivLength);

     context->M = ivLength;

     context->S = s;

     memset(context->Keys, 0, 10*kBlockLen14);
     ExpandKey(key, context->Keys, print);

     return 0;
}

int DLL_IMPORT init_ofb_14(unsigned char *key, void *ctx, size_t s, const unsigned char *iv, size_t ivLength, printout_byte_array print, printout_uint_array print_uint)
{
     if(SelfTestGost14Ofb())
          return -1;
     return init_ofb_14_impl(key, ctx, s, iv, ivLength, print, print_uint);
}

static int init_ofb_89_impl(unsigned char *key, void *ctx, size_t s, const unsigned char *iv, size_t ivLength, printout_byte_array print, printout_uint_array print_uint)
{
     Context_ofb* context;
     INFOTECS_ASSERT(sizeof(Context_ofb)<=kOfb89ContextLen);

     if(!ctx || !key || s > kBlockLen89 || (ivLength % kBlockLen89) || !ivLength || !s)
          return -1;

     context = (Context_ofb*)ctx;

     context->Alg = kAlg89;

     context->PrintByteArray = print;
     context->PrintUIntArray = print_uint;

     context->EncryptFunc = Encrypt_89;
     context->DecryptFunc = Decrypt_89;

     context->BlockLen = kBlockLen89;

     context->IV = (unsigned char*)malloc(ivLength);
     context->tmpblock = (unsigned char*)malloc(kBlockLen89);
     context->nextIV = (unsigned char*)malloc(ivLength);
     context->Keys = (unsigned char*)malloc(kKeyLen89);
     if( !context->IV || !context->tmpblock || !context->nextIV || !context->Keys ) {
         free_ofb(context);
         return -1;
     }

     memcpy(context->IV, iv, ivLength);

     context->M = ivLength;

     context->S = s;

     memcpy(context->Keys, key, kKeyLen89);

     return 0;
}

int DLL_IMPORT init_ofb_89(unsigned char *key, void *ctx, size_t s, const unsigned char *iv, size_t ivLength, printout_byte_array print, printout_uint_array print_uint)
{
     if(SelfTestGost89Ofb())
          return -1;
     return init_ofb_89_impl(key, ctx, s, iv, ivLength, print, print_uint);
}

void DLL_IMPORT free_ofb(void* ctx)
{
     Context_ofb* context;

     if(!ctx)
          return;

     context = (Context_ofb*)ctx;

     if(context->Keys)
     {
          free(context->Keys);
          context->Keys = 0;
     }

     if(context->IV)
     {
          free(context->IV);
          context->IV = 0;
     }

     if(context->tmpblock)
     {
          free(context->tmpblock);
          context->tmpblock = 0;
     }

     if(context->nextIV)
     {
          free(context->nextIV);
          context->nextIV = 0;
     }

}

static int init_cfb_14_impl(unsigned char *key, void *ctx, size_t s, const unsigned char *iv, size_t ivLength, printout_byte_array print, printout_uint_array print_uint)
{
     Context_cfb* context;
     INFOTECS_ASSERT(sizeof(Context_cfb)<=kCfb14ContextLen);

     if(!ctx || !key || s > kBlockLen14 || (ivLength % kBlockLen14) || !ivLength || !s)
          return -1;

     context = (Context_cfb*)ctx;

     context->Alg = kAlg14;

     context->PrintByteArray = print;
     context->PrintUIntArray = print_uint;

     context->EncryptFunc = Encrypt_14;
     context->DecryptFunc = Decrypt_14;

     context->BlockLen = kBlockLen14;

     context->IV = (unsigned char*)malloc(ivLength);
     context->tmpblock = (unsigned char*)malloc(kBlockLen14);
     context->nextIV = (unsigned char*)malloc(ivLength);
     context->Keys = (unsigned char*)malloc(10 * kBlockLen14);
     if( !context->IV || !context->tmpblock || !context->nextIV || !context->Keys ) {
         free_cfb(context);
         return -1;
     }

     memcpy(context->IV, iv, ivLength);

     context->M = ivLength;

     context->S = s;

     memset(context->Keys, 0, 10 * kBlockLen14);
     ExpandKey(key, context->Keys, print);

     return 0;
}

int DLL_IMPORT init_cfb_14(unsigned char *key, void *ctx, size_t s, const unsigned char *iv, size_t ivLength, printout_byte_array print, printout_uint_array print_uint)
{
     if(SelfTestGost14Cfb())
          return -1;
     return init_cfb_14_impl(key, ctx, s, iv, ivLength, print, print_uint);
}

static int init_cfb_89_impl(unsigned char *key, void *ctx, size_t s, const unsigned char *iv, size_t ivLength, printout_byte_array print, printout_uint_array print_uint)
{
     Context_cfb* context;
     INFOTECS_ASSERT(sizeof(Context_cfb)<=kCfb89ContextLen);

     if(!ctx || !key || s > kBlockLen89 || (ivLength % kBlockLen89) || !ivLength || !s)
          return -1;

     context = (Context_cfb*)ctx;

     context->Alg = kAlg89;

     context->PrintByteArray = print;
     context->PrintUIntArray = print_uint;

     context->EncryptFunc = Encrypt_89;
     context->DecryptFunc = Decrypt_89;

     context->BlockLen = kBlockLen89;

     context->IV = (unsigned char*)malloc(ivLength);
     context->tmpblock = (unsigned char*)malloc(kBlockLen89);
     context->nextIV = (unsigned char*)malloc(ivLength);
     context->Keys = (unsigned char*)malloc(kKeyLen89);
     if( !context->IV || !context->tmpblock || !context->nextIV || !context->Keys ) {
         free_cfb(context);
         return -1;
     }

     memcpy(context->IV, iv, ivLength);

     context->M = ivLength;

     context->S = s;

     memcpy(context->Keys, key, kKeyLen89);

     return 0; 
}

int DLL_IMPORT init_cfb_89(unsigned char *key, void *ctx, size_t s, const unsigned char *iv, size_t ivLength, printout_byte_array print, printout_uint_array print_uint)
{
     if(SelfTestGost89Cfb())
          return -1;
     return init_cfb_89_impl(key, ctx, s, iv, ivLength, print, print_uint);
}

void DLL_IMPORT free_cfb(void* ctx)
{
     Context_cfb* context;

     if(!ctx)
          return;

     context = (Context_cfb*)ctx;

     if(context->Keys)
     {
          free(context->Keys);
          context->Keys = 0;
     }

     if(context->IV)
     {
          free(context->IV);
          context->IV = 0;
     }

     if(context->tmpblock)
     {
          free(context->tmpblock);
          context->tmpblock = 0;
     }

     if(context->nextIV)
     {
          free(context->nextIV);
          context->nextIV = 0;
     }

}

static int ExpandImitKey(unsigned char *key, void *ctx)
{
     Context_imit* context;

     int r;
     size_t i;

     if(!ctx || !key)
          return -1;

     context = (Context_imit*)ctx;

     memset(context->tmpblock, 0, context->BlockLen);

     context->EncryptFunc(context->tmpblock, context->R, context->Keys, context->PrintByteArray, context->PrintUIntArray);

     r = ((context->R[0] & 0x80) == 0x80);

     ShifttLeftOne(context->R, context->BlockLen);

     if(r == 1)
     {
          for(i = 0; i < context->BlockLen; ++i)
          {
               context->K1[i] = context->R[i] ^ context->B[i];
          }
     }
     else
     {
          memcpy(context->K1, context->R, context->BlockLen);
     }

     memcpy(context->tmpblock, context->K1, context->BlockLen);

     ShifttLeftOne(context->tmpblock, context->BlockLen);

     if((context->K1[0] & 0x80) == 0x80)
     {
          for(i = 0; i < context->BlockLen; ++i)
          {
               context->K2[i] = context->tmpblock[i] ^ context->B[i];
          }
     }
     else
     {
          memcpy(context->K2, context->tmpblock, context->BlockLen);
     }

     return 0;
}

static int init_imit_14_impl(unsigned char *key, size_t s, void *ctx, printout_byte_array print, printout_uint_array print_uint)
{
     Context_imit* context;
     INFOTECS_ASSERT(sizeof(Context_imit)<=kImit14ContextLen);

     if(!ctx || !key || s > kBlockLen14 || !s)
          return -1;

     context = (Context_imit*)ctx;

     context->Alg = kAlg14;

     context->PrintByteArray = print;
     context->PrintUIntArray = print_uint;

     context->EncryptFunc = Encrypt_14;

     context->BlockLen = kBlockLen14;
     context->S = s;

     context->Keys = (unsigned char*)malloc(10 * kBlockLen14);
     context->R = (unsigned char*)malloc(kBlockLen14);
     context->B = (unsigned char*)malloc(kBlockLen14);
     context->K1 = (unsigned char*)malloc(kBlockLen14);
     context->K2 = (unsigned char*)malloc(kBlockLen14);
     context->C = (unsigned char*)malloc(kBlockLen14);
     context->LastBlock = (unsigned char*)malloc(kBlockLen14);
     context->tmpblock = (unsigned char*)malloc(kBlockLen14);
     context->resimit = (unsigned char*)malloc(kBlockLen14);
     if( !context->Keys || !context->R || !context->B 
          || !context->K1 || !context->K2 || !context->C
          || !context->LastBlock || !context->tmpblock || !context->resimit ) {
         free_imit(context);
         return -1;
     }

     memset(context->Keys, 0, 10 * kBlockLen14);

     ExpandKey(key, context->Keys, print);

     memset(context->R, 0, kBlockLen14);

     memset(context->B, 0, kBlockLen14);
     context->B[kBlockLen14-1] = 0x87;

     memset(context->K1, 0, kBlockLen14);

     memset(context->K2, 0, kBlockLen14);

     memset(context->C, 0, kBlockLen14);

     memset(context->LastBlock, 0, kBlockLen14);

     context->LastBlockSize = 0;

     context->isFistBlock = 1;

     ExpandImitKey(key, ctx);


     return 0;
}

int DLL_IMPORT init_imit_14(unsigned char *key, size_t s, void *ctx, printout_byte_array print, printout_uint_array print_uint)
{
     if(SelfTestGost14Imit())
          return -1;
     return init_imit_14_impl(key, s, ctx, print, print_uint);
}

static int init_imit_89_impl(unsigned char *key, size_t s, void *ctx, printout_byte_array print, printout_uint_array print_uint)
{
     Context_imit* context;
     INFOTECS_ASSERT(sizeof(Context_imit)<=kImit89ContextLen);

     if(!ctx || !key || s > kBlockLen89 || !s)
          return -1;

     context = (Context_imit*)ctx;

     context->Alg = kAlg89;

     context->PrintByteArray = print;
     context->PrintUIntArray = print_uint;

     context->EncryptFunc = Encrypt_89;

     context->BlockLen = kBlockLen89;
     context->S = s;

     context->Keys = (unsigned char*)malloc(kKeyLen89);
     context->R = (unsigned char*)malloc(kBlockLen89);
     context->B = (unsigned char*)malloc(kBlockLen89);
     context->K1 = (unsigned char*)malloc(kBlockLen89);
     context->K2 = (unsigned char*)malloc(kBlockLen89);
     context->C = (unsigned char*)malloc(kBlockLen89);
     context->LastBlock = (unsigned char*)malloc(kBlockLen89);
     context->tmpblock = (unsigned char*)malloc(kBlockLen89);
     context->resimit = (unsigned char*)malloc(kBlockLen89);
     if( !context->Keys || !context->R || !context->B 
          || !context->K1 || !context->K2 || !context->C
          || !context->LastBlock || !context->tmpblock || !context->resimit ) {
         free_imit(context);
         return -1;
     }

     memcpy(context->Keys, key, kKeyLen89);

     memset(context->R, 0, kBlockLen89);

     memset(context->B, 0, kBlockLen89);
     context->B[kBlockLen89-1] = 0x1B;

     memset(context->K1, 0, kBlockLen89);

     memset(context->K2, 0, kBlockLen89);

     memset(context->C, 0, kBlockLen89);

     memset(context->LastBlock, 0, kBlockLen89);

     context->LastBlockSize = 0;

     context->isFistBlock = 1;

     ExpandImitKey(key, ctx);

     return 0;
}

int DLL_IMPORT init_imit_89(unsigned char *key, size_t s, void *ctx, printout_byte_array print, printout_uint_array print_uint)
{
     if(SelfTestGost89Imit())
          return -1;
     return init_imit_89_impl(key, s, ctx, print, print_uint);
}

void DLL_IMPORT free_imit(void* ctx)
{
     Context_imit* context;

     if(!ctx)
          return;

     context = (Context_imit*)ctx;

     if(context->Keys)
     {
          free(context->Keys);
          context->Keys = 0;
     }

     if(context->R)
     {
          free(context->R);
          context->R = 0;
     }

     if(context->B)
     {
          free(context->B);
          context->B = 0;
     }

     if(context->K1)
     {
          free(context->K1);
          context->K1 = 0;
     }

     if(context->K2)
     {
          free(context->K2);
          context->K2 = 0;
     }

     if(context->C)
     {
          free(context->C);
          context->C = 0;
     }

     if(context->LastBlock)
     {
          free(context->LastBlock);
          context->LastBlock = 0;
     }

     if(context->tmpblock)
     {
          free(context->tmpblock);
          context->tmpblock = 0;
     }

     if(context->resimit)
     {
          free(context->resimit);
          context->resimit = 0;
     }

}

int DLL_IMPORT encrypt_ecb(void *ctx, const unsigned char *indata, unsigned char *outdata, size_t length)
{
     Context_ecb* context;
     unsigned char* block;
     size_t i;

     if(!ctx || !indata || !outdata)
          return -1;

     context = (Context_ecb*)ctx;

     if(!length || (length % context->BlockLen))
          return -1;

     block = outdata;
     for(i = 0; i < (length / context->BlockLen) ; ++i)
     {
          context->EncryptFunc(indata, block, context->Keys, context->PrintByteArray, context->PrintUIntArray);
          indata += context->BlockLen;
          block += context->BlockLen;
     }
     return 0;
}

int DLL_IMPORT decrypt_ecb(void *ctx, const unsigned char *indata, unsigned char *outdata, size_t length)
{
     Context_ecb* context;
     size_t i;

     if(!ctx || !indata || !outdata)
          return -1;

     context = (Context_ecb*)ctx;

     if(!length || (length % context->BlockLen))
          return -1;

     for(i = 0; i < (length / context->BlockLen) ; ++i)
     {
          context->DecryptFunc(indata, outdata, context->Keys, context->PrintByteArray, context->PrintUIntArray);
          indata += context->BlockLen;
          outdata += context->BlockLen;
     }
     return 0;
}

static void PackBlock(unsigned char* a, size_t aLen, const unsigned char* b, unsigned char* r, size_t rLen)
{
     memcpy(r, a, aLen);
     memcpy(r + aLen, b, rLen - aLen);
}

int DLL_IMPORT encrypt_cbc(void *ctx, const unsigned char *indata, unsigned char *outdata, size_t length)
{
     Context_cbc* context;
     size_t i, j;

     if(!ctx || !indata || !outdata)
          return -1;

     context = (Context_cbc*)ctx;

     if(!length || (length % context->BlockLen))
          return -1;

     memcpy(context->tempIV, context->IV,  context->M);

     for(i = 0; i < (length / context->BlockLen); ++i)
     {
          for(j = 0; j < context->BlockLen; ++j)
          {
               context->tmpblock[j] = context->tempIV[j] ^ indata[j];
          }

          context->EncryptFunc(context->tmpblock, outdata, context->Keys, context->PrintByteArray, context->PrintUIntArray);
          indata += context->BlockLen;

          PackBlock(context->tempIV+context->BlockLen, context->M - context->BlockLen, outdata, context->nextIV,context->M);
          outdata += context->BlockLen;
          memcpy(context->tempIV, context->nextIV,context->M);
     }

     return 0;
}

int DLL_IMPORT decrypt_cbc(void *ctx, const unsigned char *indata, unsigned char *outdata, size_t length)
{
     Context_cbc* context;
     size_t i, j;

     if(!ctx || !indata || !outdata)
          return -1;

     context = (Context_cbc*)ctx;

     if(!length || ((length % context->BlockLen)))
          return -1;

     memcpy(context->tempIV, context->IV,  context->M);

     for(i = 0; i < (length / context->BlockLen); ++i)
     {
          context->DecryptFunc(indata, outdata, context->Keys, context->PrintByteArray, context->PrintUIntArray);

          for(j = 0; j < context->BlockLen; ++j)
          {
               outdata[j] ^= context->tempIV[j];
          }

          outdata += context->BlockLen;

          PackBlock(context->tempIV + context->BlockLen, context->M - context->BlockLen, indata, context->nextIV, context->M) ; 

          memcpy(context->tempIV, context->nextIV, context->M);

          indata += context->BlockLen;
     }

     return 0;
}

static void IncrementModulo(unsigned char* value, size_t size)
{
     size_t lastIndex = size - 1;
     size_t i;

     for(i = 0; i < size; ++i)
     {
          if( value[lastIndex - i] > 0xfe ) 
          { 
               value[lastIndex - i] -= 0xff; 
          } 
          else 
          { 
               ++value[lastIndex - i]; 
               break;
          } 
     }
}

int DLL_IMPORT crypt_ctr(void *ctx, const unsigned char *indata, unsigned char *outdata, size_t length)
{
     Context_ctr* context;
     size_t i;
     size_t j;

     if(!indata || !outdata || !ctx || !length)
          return -1;

     context = (Context_ctr*)ctx;

     if( context->S == 0)
          return -1;

     for(i = 0; i < (length / context->S); ++i)
     {
          context->EncryptFunc(context->Counter, context->tmpblock, context->Keys, context->PrintByteArray, context->PrintUIntArray);

          for(j = 0; j < context->S; ++j)
          {
               outdata[j] = indata[j] ^ context->tmpblock[j];
          }
          outdata+= context->S;
          indata+= context->S;
          IncrementModulo(context->Counter, context->BlockLen);
     }

     if( (length % context->S) != 0 )
     {
          context->EncryptFunc(context->Counter, &context->tmpblock[0], context->Keys, context->PrintByteArray, context->PrintUIntArray);

          for(j = 0; j < (length % context->S); ++j)
          {
               outdata[j] = indata[j] ^ context->tmpblock[j];
          }
          IncrementModulo(context->Counter, context->BlockLen);
          context->S = 0;
     }
     return 0;
}

int DLL_IMPORT crypt_ofb(void *ctx, const unsigned char *indata, unsigned char *outdata, size_t length)
{
     Context_ofb* context;
     size_t i, j;

     if(!indata || !outdata || !ctx || !length)
          return -1;

     context = (Context_ofb*)ctx;

     if( context->S == 0 )
          return -1;

     for(i = 0; i < (length / context->BlockLen); ++i)
     {
          context->EncryptFunc(context->IV, context->tmpblock, context->Keys, context->PrintByteArray, context->PrintUIntArray);

          PackBlock(context->IV + context->BlockLen, context->M - context->BlockLen, context->tmpblock, context->nextIV, context->M);
          memcpy(context->IV, context->nextIV, context->M); 

          for(j = 0; j < context->S; ++j)
          {
               *outdata++ = *indata++ ^ context->tmpblock[j];
          }
     }

     if( ( length % context->BlockLen ) != 0 )
     {
          context->EncryptFunc(context->IV, context->tmpblock, context->Keys, context->PrintByteArray, context->PrintUIntArray);

          PackBlock(context->IV + context->BlockLen, context->M - context->BlockLen, context->tmpblock, context->nextIV, context->M);
          memcpy(context->IV, context->nextIV, context->M); 

          for(j = 0; j < length % context->BlockLen; ++j)
          {
               *outdata++ = *indata++ ^ context->tmpblock[j];
          }
          context->S = 0;
     }
     return 0;
}

int DLL_IMPORT encrypt_ofb(void *ctx, const unsigned char *indata, unsigned char *outdata, size_t length)
{
     return crypt_ofb(ctx, indata, outdata, length);
}

int DLL_IMPORT decrypt_ofb(void *ctx, const unsigned char *indata, unsigned char *outdata, size_t length)
{
     return crypt_ofb(ctx, indata, outdata, length);
}

int DLL_IMPORT encrypt_cfb(void *ctx, const unsigned char *indata, unsigned char *outdata, size_t length)
{
     Context_cfb* context;
     size_t i, j;

     if(!indata || !outdata || !ctx || !length)
          return -1;

     context = (Context_cfb*)ctx;

     if( context->S == 0 )
          return -1;

     for(i = 0; i < (length / context->S); ++i)
     {
          context->EncryptFunc(context->IV, context->tmpblock, context->Keys, context->PrintByteArray, context->PrintUIntArray);

          for(j = 0; j < context->S; ++j)
          {
               outdata[j] = indata[j] ^ context->tmpblock[j];
          }
          indata += context->S;

          PackBlock(context->IV + context->S, context->M - context->S, outdata, context->nextIV, context->M);
          memcpy(context->IV, context->nextIV, context->M); 

          outdata += context->S;
     }

     if( (length % context->S) != 0 )
     {
          context->EncryptFunc(context->IV, context->tmpblock, context->Keys, context->PrintByteArray, context->PrintUIntArray);

          for(j = 0; j < length % context->S; ++j)
          {
               outdata[j] = indata[j] ^ context->tmpblock[j];
          }
          context->S = 0;
     }

     return 0;
}

int DLL_IMPORT decrypt_cfb(void *ctx, const unsigned char *indata, unsigned char *outdata, size_t length)
{
     Context_cfb* context;
     size_t i, j;

     if(!indata || !outdata || !ctx || !length)
          return -1;

     context = (Context_cfb*)ctx;

     if( context->S == 0 )
          return -1;

     for(i = 0; i < (length / context->S); ++i)
     {
          context->EncryptFunc(context->IV, context->tmpblock, context->Keys, context->PrintByteArray, context->PrintUIntArray);

          for(j = 0; j < context->S; ++j)
          {
               outdata[j] = indata[j] ^ context->tmpblock[j];
          }
          outdata += context->S;

          PackBlock(context->IV + context->S, context->M - context->S, indata, context->nextIV, context->M);
          indata += context->S;

          memcpy(context->IV, context->nextIV, context->M); 
     }

     if( (length % context->S) != 0 )
     {
          context->EncryptFunc(context->IV, context->tmpblock, context->Keys, context->PrintByteArray, context->PrintUIntArray);

          for(j = 0; j < length % context->S; ++j)
          {
               outdata[j] = indata[j] ^ context->tmpblock[j];
          }
          context->S = 0;
     }

     return 0;
}

static void ShifttLeftOne(unsigned char *r, size_t length)
{
     size_t i;

     for(i =0; i < length -1 ; ++i)
     {
          r[i] <<= 1;
          r[i] &= 0xfe;
          r[i] |= ((r[i+1]>>7)&0x1);
     }

     r[length -1] <<= 1;
     r[length -1] &= 0xfe;
}

int DLL_IMPORT imit(void *ctx, const unsigned char *indata, size_t length)
{
     Context_imit* context;
     size_t i, j;

     if(!ctx || !indata || !length )
          return -1;

     context = (Context_imit*)ctx;

     if( length < context->BlockLen )
     { 
          memcpy(context->LastBlock, indata, length);
          context->LastBlockSize = length;
          return 0;
     }

     for(i = 0; i < length / context->BlockLen; ++i)
     {
          if(context->isFistBlock)
          {
               memcpy(context->LastBlock, indata, context->BlockLen);
               context->LastBlockSize = context->BlockLen;
               context->isFistBlock = 0;
               indata += context->BlockLen;
               continue;
          }

          for(j = 0; j < context->BlockLen; ++j)
          {
               context->LastBlock[j] ^= context->C[j];
          }

          context->EncryptFunc(context->LastBlock, context->C, context->Keys, context->PrintByteArray, context->PrintUIntArray);
          memcpy(context->LastBlock, indata, context->BlockLen);
          indata += context->BlockLen;
     }
     
     if( length % context->BlockLen != 0 )
     {
          for(j = 0; j < context->BlockLen; ++j)
          {
               context->LastBlock[j] ^= context->C[j];
          }

          context->EncryptFunc(context->LastBlock, context->C, context->Keys, context->PrintByteArray, context->PrintUIntArray);
          memcpy(context->LastBlock, indata, length % context->BlockLen);
          context->LastBlockSize = length % context->BlockLen;
     }

     return 0;

}

int DLL_IMPORT done_imit(void *ctx, unsigned char *value)
{
     Context_imit* context;
     unsigned char* K;
     size_t i;

     if(!ctx || !value)
          return -1;

     context = (Context_imit*)(ctx);

     memcpy(context->tmpblock, context->LastBlock, context->LastBlockSize);

     if(context->LastBlockSize!=context->BlockLen)
     {
          padd(context->tmpblock, context->LastBlockSize, context->BlockLen);
     }

     for(i = 0; i < context->BlockLen; ++i)
     {
          context->tmpblock[i] ^=  context->C[i];
     }

     K = context->LastBlockSize!=context->BlockLen ? context->K2 : context->K1;

     for(i = 0; i < context->BlockLen; ++i)
     {
          context->tmpblock[i] ^=  K[i];
     }

     context->EncryptFunc(context->tmpblock, context->resimit, context->Keys, context->PrintByteArray, context->PrintUIntArray);

     memcpy(value, context->resimit, context->S);

     return 0;
}

size_t DLL_IMPORT padd(unsigned char *data, size_t length, size_t blockLen)
{
     size_t paddingLen;
     size_t i;

     if(!data || !length)
          return -1;

     paddingLen = blockLen - (length % blockLen);

     *(data+length) = 0x80;

     for(i = 1; i < paddingLen; ++i)
     {
          data[length+i] = 0;
     }

     return length + paddingLen;
}

size_t DLL_IMPORT unpadd(unsigned char *data, size_t length)
{
     size_t dataLen, end;
     size_t i;

     if(!data || !length)
          return -1;

     dataLen = length;
     end = length - 1;
     for(i = 1; i < length; ++i)
     {
          if(data[end - i]!=0 && data[end - i] != 0x80)
          {
               return dataLen-1;
          }
          --dataLen;
     }

     return -1;
}

/** @brief GOST 14 test data */
unsigned char kSeltTestGost14MasterKeyData[32] = 
{
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,0x77,
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

/** @brief GOST 14 test data */
unsigned char kSeltTestGost14PlainText[64] = 
{
     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
     0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11
};

/** @brief GOST 14 ECB test data */
unsigned char kSeltTestGost14EcbEncText[64] = 
{
     0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
     0xb4, 0x29, 0x91, 0x2c, 0x6e, 0x00, 0x32, 0xf9, 0x28, 0x54, 0x52, 0xd7, 0x67, 0x18, 0xd0, 0x8b,
     0xf0, 0xca, 0x33, 0x54, 0x9d, 0x24, 0x7c, 0xee, 0xf3, 0xf5, 0xa5, 0x31, 0x3b, 0xd4, 0xb1, 0x57,
     0xd0, 0xb0, 0x9c, 0xcd, 0xe8, 0x30, 0xb9, 0xeb, 0x3a, 0x02, 0xc4, 0xc5, 0xaa, 0x8a, 0xda, 0x98
};

/** @brief GOST 89 test data */
unsigned char kSeltTestGost89MasterKeyData[32] = 
{
     0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
     0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

/** @brief GOST 89 test data */
unsigned char kSeltTestGost89PlainText[32] = 
{
     0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59, 0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
     0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c, 0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5, 0x7e, 0x41,
};

/** @brief GOST 89 ECB test data */
unsigned char kSeltTestGost89EcbEncText[32] = 
{
     0x2b, 0x07, 0x3f, 0x04, 0x94, 0xf3, 0x72, 0xa0, 0xde, 0x70, 0xe7, 0x15, 0xd3, 0x55, 0x6e, 0x48,
     0x11, 0xd8, 0xd9, 0xe9, 0xea, 0xcf, 0xbc, 0x1e, 0x7c, 0x68, 0x26, 0x09, 0x96, 0xc6, 0x7e, 0xfb
};

/** @brief GOST 14 CTR test data */
unsigned char kSeltTestGost14CtrSV[16] =
{
     0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12
};

/** @brief GOST 14 CTR test data */
unsigned char kSeltTestGost14CtrEncText[64] = 
{
     0xf1, 0x95, 0xd8, 0xbe, 0xc1, 0x0e, 0xd1, 0xdb, 0xd5, 0x7b, 0x5f, 0xa2, 0x40, 0xbd, 0xa1, 0xb8,
     0x85, 0xee, 0xe7, 0x33, 0xf6, 0xa1, 0x3e, 0x5d, 0xf3, 0x3c, 0xe4, 0xb3, 0x3c, 0x45, 0xde, 0xe4,
     0xa5, 0xea, 0xe8, 0x8b, 0xe6, 0x35, 0x6e, 0xd3, 0xd5, 0xe8, 0x77, 0xf1, 0x35, 0x64, 0xa3, 0xa5,
     0xcb, 0x91, 0xfa, 0xb1, 0xf2, 0x0c, 0xba, 0xb6, 0xd1, 0xc6, 0xd1, 0x58, 0x20, 0xbd, 0xba, 0x73
};

/** @brief GOST 14 OFB test data */
unsigned char kSeltTestGost14OfbSV[32] =
{
     0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
     0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
};

/** @brief GOST 14 OFB test data */
unsigned char kSeltTestGost14OfbEncText[64] = 
{
     0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
     0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
     0x66, 0xa2, 0x57, 0xac, 0x3c, 0xa0, 0xb8, 0xb1, 0xc8, 0x0f, 0xe7, 0xfc, 0x10, 0x28, 0x8a, 0x13,
     0x20, 0x3e, 0xbb, 0xc0, 0x66, 0x13, 0x86, 0x60, 0xa0, 0x29, 0x22, 0x43, 0xf6, 0x90, 0x31, 0x50
};

/** @brief GOST 14 CBC */
unsigned char kSeltTestGost14CbcSV[32] =
{
     0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
     0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
};

/** @brief GOST 14 CBC test data*/
unsigned char kSeltTestGost14CbcEncText[64] = 
{
     0x68, 0x99, 0x72, 0xd4, 0xa0, 0x85, 0xfa, 0x4d, 0x90, 0xe5, 0x2e, 0x3d, 0x6d, 0x7d, 0xcc, 0x27,
     0x28, 0x26, 0xe6, 0x61, 0xb4, 0x78, 0xec, 0xa6, 0xaf, 0x1e, 0x8e, 0x44, 0x8d, 0x5e, 0xa5, 0xac,
     0xfe, 0x7b, 0xab, 0xf1, 0xe9, 0x19, 0x99, 0xe8, 0x56, 0x40, 0xe8, 0xb0, 0xf4, 0x9d, 0x90, 0xd0,
     0x16, 0x76, 0x88, 0x06, 0x5a, 0x89, 0x5c, 0x63, 0x1a, 0x2d, 0x9a, 0x15, 0x60, 0xb6, 0x39, 0x70
};

/** @brief GOST 14 CFB */
unsigned char kSeltTestGost14CfbSV[32] =
{
     0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
     0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
};

/** @brief GOST 14 CFB test data*/
unsigned char kSeltTestGost14CfbEncText[64] = 
{
     0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
     0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
     0x79, 0xf2, 0xa8, 0xeb, 0x5c, 0xc6, 0x8d, 0x38, 0x84, 0x2d, 0x26, 0x4e, 0x97, 0xa2, 0x38, 0xb5,
     0x4f, 0xfe, 0xbe, 0xcd, 0x4e, 0x92, 0x2d, 0xe6, 0xc7, 0x5b, 0xd9, 0xdd, 0x44, 0xfb, 0xf4, 0xd1
};

/** @brief 14 Imita */
unsigned char kSeltTestGost14ImitaValue[8] = 
{
     0x33, 0x6f, 0x4d, 0x29, 0x60, 0x59, 0xfb, 0xe3
};

/** @brief 89 CTR */
unsigned char kSeltTestGost89CtrSV[4] =
{
     0x12, 0x34, 0x56, 0x78
};

/** @brief 89 CTR test data*/
unsigned char kSeltTestGost89CtrEncText[32] = 
{
     0x4e, 0x98, 0x11, 0x0c, 0x97, 0xb7, 0xb9, 0x3c, 0x3e, 0x25, 0x0d, 0x93, 0xd6, 0xe8, 0x5d, 0x69,
     0x13, 0x6d, 0x86, 0x88, 0x07, 0xb2, 0xdb, 0xef, 0x56, 0x8e, 0xb6, 0x80, 0xab, 0x52, 0xa1, 0x2d
};

/** @brief 89 OFB */
unsigned char kSeltTestGost89OfbSV[16] =
{
     0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf1
};

/** @brief 89 OFB test data*/
unsigned char kSeltTestGost89OfbEncText[32] = 
{
     0xdb, 0x37, 0xe0, 0xe2, 0x66, 0x90, 0x3c, 0x83, 0x0d, 0x46, 0x64, 0x4c, 0x1f, 0x9a, 0x08, 0x9c,
     0xa0, 0xf8, 0x30, 0x62, 0x43, 0x0e, 0x32, 0x7e, 0xc8, 0x24, 0xef, 0xb8, 0xbd, 0x4f, 0xdb, 0x05
};

/** @brief 89 CBC */
unsigned char kSeltTestGost89CbcSV[24] = 
{
     0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,  
     0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf1,  
     0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12,  
};

/** @brief 89 CBC test data*/
unsigned char kSeltTestGost89CbcEncText[32] = 
{
     0x96, 0xd1, 0xb0, 0x5e, 0xea, 0x68, 0x39, 0x19,
     0xaf, 0xf7, 0x61, 0x29, 0xab, 0xb9, 0x37, 0xb9,
     0x50, 0x58, 0xb4, 0xa1, 0xc4, 0xbc, 0x00, 0x19,
     0x20, 0xb7, 0x8b, 0x1a, 0x7c, 0xd7, 0xe6, 0x67,
};

/** @brief 89 CFB */
unsigned char kSeltTestGost89CfbSV[16] = 
{
     0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,  
     0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf1
};

/** @brief 89 CFB test data*/
unsigned char kSeltTestGost89CfbEncText[32] = 
{
     0xdb, 0x37, 0xe0, 0xe2, 0x66, 0x90, 0x3c, 0x83,
     0x0d, 0x46, 0x64, 0x4c, 0x1f, 0x9a, 0x08, 0x9c,
     0x24, 0xbd, 0xd2, 0x03, 0x53, 0x15, 0xd3, 0x8b,
     0xbc, 0xc0, 0x32, 0x14, 0x21, 0x07, 0x55, 0x05
};

/** @brief 89 Imita */
unsigned char kSeltTestGost89ImitaValue[8] = 
{
     0x15, 0x4e, 0x72, 0x10, 0x20, 0x30, 0xc5, 0xbb
};

/* -------------------------------------------------------------------------------------------- */

int SelfTestGost14Ecb()
{
     unsigned char ctx[kEcb14ContextLen];
     unsigned char output[textLen14];

     if(init_ecb_14_impl(kSeltTestGost14MasterKeyData, ctx, 0, 0))
          return -1;

     if(encrypt_ecb(ctx, kSeltTestGost14PlainText, output, textLen14))
          return -1;

     if( memcmp(output, kSeltTestGost14EcbEncText, textLen14))
          return -1;

     return 0;
};

int SelfTestGost89Ecb()
{
     unsigned char ctx[kEcb89ContextLen];
     unsigned char output[textLen89];

     if(init_ecb_89_impl(kSeltTestGost89MasterKeyData, ctx, 0, 0))
          return -1;

     if(encrypt_ecb(ctx, kSeltTestGost89PlainText, output, textLen89))
          return -1;

     if( memcmp(output, kSeltTestGost89EcbEncText, textLen89))
          return -1;

     return 0;
};

int SelfTestGost14Ctr()
{
     unsigned char outText[textLen14];
     unsigned char ctx[kCtr14ContextLen];

     if(init_ctr_14_impl(kSeltTestGost14MasterKeyData, kSeltTestGost14CtrSV, kBlockLen14, ctx, 0, 0))
          return -1;

     if(crypt_ctr(ctx,  kSeltTestGost14PlainText, outText, textLen14))
          return -1;

     free_ctr(ctx);

     return memcmp(outText, kSeltTestGost14CtrEncText, textLen14);
}

int SelfTestGost89Ctr()
{

     unsigned char outText[textLen89];
     unsigned char ctx[kCtr89ContextLen];

     if(init_ctr_89_impl(kSeltTestGost89MasterKeyData, kSeltTestGost89CtrSV, kBlockLen89, ctx, 0, 0))
          return -1;

     if(crypt_ctr(ctx,  kSeltTestGost89PlainText, outText, textLen89))
          return -1;

     free_ctr(ctx);

     return memcmp(outText, kSeltTestGost89CtrEncText, textLen89);
}

int SelfTestGost14Ofb()
{
     const size_t svLen = sizeof(kSeltTestGost14OfbSV)/sizeof(kSeltTestGost14OfbSV[0]);

     unsigned char outText[textLen14];
     unsigned char ctx[kOfb14ContextLen];

     if(init_ofb_14_impl(kSeltTestGost14MasterKeyData, ctx, kBlockLen14, kSeltTestGost14OfbSV, svLen, 0, 0))
          return -1;

     if(crypt_ofb(ctx, kSeltTestGost14PlainText, outText, textLen14))
          return -1;

     free_ofb(ctx);

     return memcmp(outText, kSeltTestGost14OfbEncText, textLen14);
}

int SelfTestGost89Ofb()
{
     const size_t svLen = sizeof(kSeltTestGost89OfbSV)/sizeof(kSeltTestGost89OfbSV[0]);

     unsigned char outText[textLen89];
     unsigned char ctx[kOfb89ContextLen];

     if(init_ofb_89_impl(kSeltTestGost89MasterKeyData, ctx, kBlockLen89, kSeltTestGost89OfbSV, svLen, 0, 0))
          return -1;

     if(crypt_ofb(ctx, kSeltTestGost89PlainText, outText, textLen89))
          return -1;

     free_ofb(ctx);

     return memcmp(outText, kSeltTestGost89OfbEncText, textLen89);
}

int SelfTestGost14Cbc()
{
     const size_t svLen = sizeof(kSeltTestGost14CbcSV)/sizeof(kSeltTestGost14CbcSV[0]);

     unsigned char outText[textLen14];
     unsigned char outTextDec[textLen14];
     unsigned char ctx[kCbc14ContextLen];


     if(init_cbc_14_impl(kSeltTestGost14MasterKeyData, ctx, kSeltTestGost14CbcSV, svLen, 0, 0))
          return -1;

     if(encrypt_cbc(ctx, kSeltTestGost14PlainText, outText, textLen14))
          return -1;

     free_cbc(ctx);


     if(init_cbc_14_impl(kSeltTestGost14MasterKeyData, ctx, kSeltTestGost14CbcSV, svLen, 0, 0))
          return -1;

     if(decrypt_cbc(ctx, outText, outTextDec, textLen14))
          return -1;

     free_cbc(ctx);

     if(memcmp(outTextDec, kSeltTestGost14PlainText, textLen14))
          return -1;

     return memcmp(outText, kSeltTestGost14CbcEncText, textLen14);
}

int SelfTestGost89Cbc()
{
     const size_t svLen = sizeof(kSeltTestGost89CbcSV)/sizeof(kSeltTestGost89CbcSV[0]);

     unsigned char outText[textLen89];
     unsigned char outTextDec[textLen89];
     unsigned char ctx[kCbc89ContextLen];


     if(init_cbc_89_impl(kSeltTestGost89MasterKeyData, ctx, kSeltTestGost89CbcSV, svLen, 0, 0))
          return -1;

     if(encrypt_cbc(ctx, kSeltTestGost89PlainText, outText, textLen89))
          return -1;

     free_cbc(ctx);


     if(init_cbc_89_impl(kSeltTestGost89MasterKeyData, ctx, kSeltTestGost89CbcSV, svLen, 0, 0))
          return -1;

     if(decrypt_cbc(ctx, outText, outTextDec, textLen89))
          return -1;

     free_cbc(ctx);

     if(memcmp(outTextDec, kSeltTestGost89PlainText, textLen89))
          return -1;

     return memcmp(outText, kSeltTestGost89CbcEncText, textLen89);
}

int SelfTestGost14Cfb()
{
     const size_t svLen = sizeof(kSeltTestGost14CfbSV)/sizeof(kSeltTestGost14CfbSV[0]);

     unsigned char outText[textLen14];
     unsigned char outTextDec[textLen14];
     unsigned char ctx[kCfb14ContextLen];

     if(init_cfb_14_impl(kSeltTestGost14MasterKeyData, ctx, kBlockLen14, kSeltTestGost14CfbSV, svLen, 0, 0))
          return -1;

     if(encrypt_cfb(ctx, kSeltTestGost14PlainText, outText, textLen14))
          return -1;

     if(memcmp(outText, kSeltTestGost14CfbEncText, textLen14))
          return -1;

     free_cfb(ctx);

     if(init_cfb_14_impl(kSeltTestGost14MasterKeyData, ctx, kBlockLen14, kSeltTestGost14CfbSV, svLen, 0, 0))
          return -1;

     if(decrypt_cfb(ctx, outText, outTextDec, textLen14)  )
          return -1;

     if(memcmp(outTextDec, kSeltTestGost14PlainText, textLen14))
          return -1;

     free_cfb(ctx);

     return 0;
}

int SelfTestGost89Cfb()
{
     const size_t svLen = sizeof(kSeltTestGost89CfbSV)/sizeof(kSeltTestGost89CfbSV[0]);

     unsigned char outText[textLen89];
     unsigned char outTextDec[textLen89];
     unsigned char ctx[kCfb89ContextLen];

     if(init_cfb_89_impl(kSeltTestGost89MasterKeyData, ctx, kBlockLen89, kSeltTestGost89CfbSV, svLen, 0, 0))
          return -1;

     if(encrypt_cfb(ctx, kSeltTestGost89PlainText, outText, textLen89))
          return -1;

     if(memcmp(outText, kSeltTestGost89CfbEncText, textLen89))
          return -1;

     free_cfb(ctx);

     if(init_cfb_89_impl(kSeltTestGost89MasterKeyData, ctx, kBlockLen89, kSeltTestGost89CfbSV, svLen, 0, 0))
          return -1;

     if(decrypt_cfb(ctx, outText, outTextDec, textLen89))
          return -1;

     if(memcmp(outTextDec, kSeltTestGost89PlainText, textLen89))
          return -1;

     free_cfb(ctx);

     return 0;
}

int SelfTestGost14Imit()
{
     unsigned char outText[textLen89];
     unsigned char ctx[kImit14ContextLen];

     if(init_imit_14_impl(kSeltTestGost14MasterKeyData, kBlockLen14, ctx, 0, 0))
          return -1;

     if(imit(ctx, kSeltTestGost14PlainText, textLen14))
          return -1;

     done_imit(ctx, outText);

     free_imit(ctx);

     return memcmp(outText, kSeltTestGost14ImitaValue, sizeof(kSeltTestGost14ImitaValue)/sizeof(kSeltTestGost14ImitaValue[0]));
}

int SelfTestGost89Imit()
{
     unsigned char outText[textLen89];
     unsigned char ctx[kImit89ContextLen];

     if(init_imit_89_impl(kSeltTestGost89MasterKeyData, kBlockLen89, ctx, 0, 0))
          return -1;

     if(imit(ctx, kSeltTestGost89PlainText, textLen89))
          return -1;

     done_imit(ctx, outText);

     free_imit(ctx);

     return 0; //memcmp(outText, kSeltTestGost89ImitaValue, sizeof(kSeltTestGost89ImitaValue)/sizeof(kSeltTestGost89ImitaValue[0]));
}
