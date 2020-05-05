/** @file 
 * @brief Реализация функций тестирования алгоритмов "кузнечик" и 28147-89. А также режимов работы блочных шифров
 *
 * @copyright InfoTeCS. All rights reserved.
 */

#include <memory.h>

#include "28147_14.h"
#include "block_cipher.h"
#include "28147_89.h"
#include "test_data.inc"
#include "print_data.h"

/** @brief размер тестовых данных для алгоритма "кузнечик" */
#define textLen14 sizeof(kGost14PlainText)

/** @brief размер тестовых данных для алгоритма "28147-89" */
#define textLen89 sizeof(kGost89PlaintText)
 
/** @brief тестирование преобразования S из алгоритма "кузнечик" */
int testS()
{
     unsigned char tmp[kBlockLen14];
     unsigned int i;

     PrintLabel("Test S function start.");

     for(i = 0; i < 4; ++i)
     {
          funcS(kSData[i], tmp, 0);

          PrintBlockLeft("Test ", i+1);
          PrintBlock("Input Value: ", kSData[i], kBlockLen14, kBlockLen14);
          PrintEmptyLine();
          PrintBlock("Output Value: ", tmp, kBlockLen14, kBlockLen14);
          PrintEmptyLine();
          PrintBlock("Control Value: ", kSData[i+1], kBlockLen14, kBlockLen14);
          PrintEmptyLine();

          if(memcmp(tmp, kSData[i+1], kBlockLen14))
               return -1;
     }
     
     return 0;
}

/** @brief тестирование преобразования R из алгоритма "кузнечик" */
int testR()
{
     unsigned char tmp[kBlockLen14];
     int i;
     
     PrintLabel("Test R function start.");

     for(i =0; i < 4; ++i)
     {
          if(funcR(kRData[i], tmp, 0))
               return -1;
          
          PrintBlockLeft("Test ", i+1);
          PrintBlock("Input Value: ", kRData[i], kBlockLen14, kBlockLen14);
          PrintEmptyLine();
          PrintBlock("Output Value: ", tmp, kBlockLen14, kBlockLen14);
          PrintEmptyLine();
          PrintBlock("Control Value: ", kRData[i+1], kBlockLen14, kBlockLen14);
          PrintEmptyLine();

          if(memcmp(tmp, kRData[i+1], kBlockLen14))
               return -1;
     }

     return 0;
}

/** @brief тестирование преобразования L из алгоритма "кузнечик" */
int testL()
{
     unsigned char tmp[kBlockLen14];
     int i;

     PrintLabel("Test L function start.");

     for(i =0; i < 4; ++i)
     {
          if(funcL(kLData[i], tmp, 0))
               return -1;

          PrintBlockLeft("Test ", i+1);
          PrintBlock("Input Value: ", kLData[i], kBlockLen14, kBlockLen14);
          PrintEmptyLine();
          PrintBlock("Output Value: ", tmp, kBlockLen14, kBlockLen14);
          PrintEmptyLine();
          PrintBlock("Control Value: ", kLData[i+1], kBlockLen14, kBlockLen14);
          PrintEmptyLine();
          
          if( memcmp(tmp, kLData[i+1], kBlockLen14))
               return -1;
     }
     return 0;
}

/** @brief тестирование разворачивания ключа из алгоритма "кузнечик" */
int testExpandKey()
{
     const size_t keyLen = sizeof(kMasterKeyData)/sizeof(kMasterKeyData[0]);
     unsigned char keys[160];
     int i;

     PrintLabel("Test Expand Key function start.");

     if(ExpandKey(kMasterKeyData, keys, 0))
          return -1;

     PrintBlock("Master Key: ", kMasterKeyData, keyLen, kBlockLen14);
     PrintEmptyLine();
          
     for(i = 0; i < 10; ++i)
     {
          PrintBlock("Output Key: ", keys+i*kBlockLen14, kBlockLen14, kBlockLen14);
          PrintBlock("Control Key: ", (unsigned char*)kKData[i], kBlockLen14, kBlockLen14);
          PrintEmptyLine();

          if( memcmp(keys+i*kBlockLen14, kKData[i], kBlockLen14))
               return -1;
     }

     return 0;
}

/** @brief тестирование шифрования по алгоритму "кузнечик" */
int testEncrypt()
{
     const size_t keyLen = sizeof(kMasterKeyData)/sizeof(kMasterKeyData[0]);

     unsigned char ctx[kEcb14ContextLen];
     unsigned char output[kBlockLen14];

     PrintLabel("Test Encrypt start.");

     if(init_ecb_14(kMasterKeyData, ctx, 0, 0))
          return -1;

     if(encrypt_ecb(ctx, kPlainTextData, output, kBlockLen14))
          return -1;

     PrintBlock("Master Key: ", kMasterKeyData, keyLen, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Input Value: ", kPlainTextData, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", output, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ", kChipherTextData, kBlockLen14, kBlockLen14);
     PrintEmptyLine();

     if( memcmp(output, kChipherTextData, kBlockLen14))
          return -1;

     return 0;
}

/** @brief тестирование расшифрования по алгоритму "кузнечик" */
int testDecrypt()
{
     const size_t keyLen = sizeof(kMasterKeyData)/sizeof(kMasterKeyData[0]);

     unsigned char ctx[kEcb14ContextLen];
     unsigned char output[kBlockLen14];

     PrintLabel("Test Decrypt start.");

     if(init_ecb_14(kMasterKeyData, ctx, 0, 0))
          return -1;

     if(decrypt_ecb(ctx, kChipherTextData, output, kBlockLen14))
          return -1;

     PrintBlock("Master Key: ", kMasterKeyData, keyLen, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Input Value: ", kChipherTextData, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", output, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ", kPlainTextData, kBlockLen14, kBlockLen14);
     PrintEmptyLine();

     if( memcmp(output, kPlainTextData, kBlockLen14)  )
          return -1;

     free_ecb(ctx);

     return 0;
}

/** @brief тестирование шифроавание в режиме ecb по алгоритму "кузнечик" */
int gost14_ECB_test()
{
     unsigned char ctx[kEcb14ContextLen];
     unsigned char output[textLen14];
     unsigned char outputE[textLen14];

     PrintLabel("Ecb mode 28147-14 test start.");

     if(init_ecb_14(kMasterKeyData, ctx, print_array, print_uint_array))
          return -1;

     if(encrypt_ecb(ctx, kGost14PlainText, output, textLen14))
          return -1;

     PrintBlock("Master Key: ", kMasterKeyData, 32, kBlockLen14);
     PrintEmptyLine();
     PrintLineLeft("Test Encrypt.");
     PrintEmptyLine();
     PrintBlock("Input Value: ", kGost14PlainText, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", output, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ", kGost14EcbEncText, kBlockLen14, kBlockLen14);
     PrintEmptyLine();

     if( memcmp(output, kGost14EcbEncText, textLen14))
          return -1;

     if(init_ecb_14(kMasterKeyData, ctx, print_array, print_uint_array))
          return -1;

     if(decrypt_ecb(ctx, output, outputE, textLen14))
          return -1;

     PrintLineLeft("Test Decrypt.");
     PrintEmptyLine();
     PrintBlock("Input Value: ", output, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outputE, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ", kGost14PlainText, kBlockLen14, kBlockLen14);
     PrintEmptyLine();

     if( memcmp(outputE, kGost14PlainText, textLen14))
          return -1;

     free_ecb(ctx);

     return 0;
}

/** @brief тестирование режима ctr алгоритма "кузнечик" */
int gost14_CTR_test()
{
     const size_t svLen = sizeof(kGost14CtrSV);

     unsigned char outText[textLen14];
     unsigned char ctx[kCtr14ContextLen];

     PrintLabel("CTR mode 28147-14 test start.");
     
     if(init_ctr_14(kMasterKeyData, kGost14CtrSV, svLen, ctx, print_array, print_uint_array))
          return -1;

     if(crypt_ctr(ctx,  kGost14PlainText, outText, textLen14))
          return -1;

     free_ctr(ctx);
   
     PrintBlock("Master Key: ", kMasterKeyData, 32, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("SV: ", kGost14CtrSV, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Input Value: ", kGost14PlainText, textLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outText, textLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ", kGost14CtrC, textLen14, kBlockLen14);
     PrintEmptyLine();

     return memcmp(outText, kGost14CtrC, textLen14);
}

/** @brief тестирование режима ofb алгоритма "кузнечик" */
int gost14_OFB_test()
{
     const size_t svLen = sizeof(kGost14OfbSV);

     unsigned char outText[textLen14];
     unsigned char ctx[kOfb14ContextLen];

     PrintLabel("OFB mode 28147-14 test start.");

     if(init_ofb_14(kMasterKeyData, ctx, kBlockLen14, kGost14OfbSV, svLen, print_array, print_uint_array))
          return -1;

     if(crypt_ofb(ctx, kGost14PlainText, outText, textLen14))
          return -1;

     free_ofb(ctx);

     PrintBlock("Master Key: ", kMasterKeyData, 32, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("SV: ", kGost14OfbSV, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Input Value: ", kGost14PlainText, textLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outText, textLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ", kGost14OfbC, textLen14, kBlockLen14);
     PrintEmptyLine();

     return memcmp(outText, kGost14OfbC, textLen14);
}

/** @brief тестирование режима cbc алгоритма "кузнечик" */
int gost14_CBC_test()
{
     const size_t svLen = sizeof(kGost14CbcSV);

     unsigned char outText[textLen14];
     unsigned char outTextDec[textLen14];
     unsigned char ctx[kCbc14ContextLen];

     PrintLabel("CBC mode 28147-14 test start.");
     
     if(init_cbc_14(kMasterKeyData, ctx, kGost14CbcSV, svLen, print_array, print_uint_array))
          return -1;

     if(encrypt_cbc(ctx, kGost14PlainText, outText, textLen14))
          return -1;

     free_cbc(ctx);

     PrintBlock("Master Key: ", kMasterKeyData, 32, kBlockLen14);
     PrintEmptyLine();
     PrintLineLeft("Test Encrypt.");
     PrintEmptyLine();
     PrintBlock("SV: ", kGost14CbcSV, svLen, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Input Value: ", kGost14PlainText, textLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outText, textLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ",  kGost14CbcC, textLen14, kBlockLen14);
     PrintEmptyLine();

     if(init_cbc_14(kMasterKeyData, ctx, kGost14CbcSV, svLen, print_array, print_uint_array))
          return -1;

     if(decrypt_cbc(ctx, outText, outTextDec, textLen14))
          return -1;

     free_cbc(ctx);

     PrintLineLeft("Test Decrypt.");
     PrintEmptyLine();
     PrintBlock("Input Value: ", outText, textLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outTextDec, textLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ", kGost14PlainText, textLen14, kBlockLen14);
     PrintEmptyLine();

     if(memcmp(outTextDec, kGost14PlainText, textLen14))
          return -1;

     return memcmp(outText, kGost14CbcC, textLen14);
}

/** @brief тестирование режима cfb алгоритма "кузнечик" */
int gost14_CFB_test()
{
     const size_t svLen = sizeof(kGost14CfbSV);

     unsigned char outText[textLen14];
     unsigned char outTextDec[textLen14];
     unsigned char ctx[kCfb14ContextLen];

     PrintLabel("CFB mode 28147-14 test start.");

     if(init_cfb_14(kMasterKeyData, ctx, kBlockLen14, kGost14CfbSV, svLen, print_array, print_uint_array))
          return -1;

     if(encrypt_cfb(ctx, kGost14PlainText, outText, textLen89))
          return -1;

     if(memcmp(outText, kGost14CfbC, textLen89))
          return -1;

     PrintBlock("Master Key: ", kMasterKeyData, 32, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("SV: ", kGost14CfbSV, svLen, kBlockLen14);
     PrintEmptyLine();
     PrintLineLeft("Test Encrypt.");
     PrintEmptyLine();
     PrintBlock("Input Value: ", kGost14PlainText, textLen89, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outText, textLen89, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ",  kGost14CfbC, textLen89, kBlockLen14);
     PrintEmptyLine();

     free_cfb(ctx);

     if(init_cfb_14(kMasterKeyData, ctx, 16, kGost14CfbSV, svLen, print_array, print_uint_array))
          return -1;

     if(decrypt_cfb(ctx, outText, outTextDec, textLen89))
          return -1;

     PrintLineLeft("Test Decrypt.");
     PrintEmptyLine();
     PrintBlock("Input Value: ", outText, textLen89, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outTextDec, textLen89, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ",  kGost14PlainText, textLen89, kBlockLen14);
     PrintEmptyLine();

     if(memcmp(outTextDec, kGost14PlainText, textLen89))
          return -1;

     free_cfb(ctx);

     return 0;
}

/** @brief тестирование режима имитовставки алгоритма "кузнечик" */
int gost14_imita_test()
{
     const size_t imitLen = sizeof(kGost14ImitS);
     unsigned char outText[16];
     unsigned char ctx[kImit14ContextLen];

     PrintLabel("Imita mode 28147-14 test start.");

     if(init_imit_14(kMasterKeyData, kBlockLen14, ctx, print_array, print_uint_array))
          return -1;

     if(imit(ctx, kGost14PlainText, textLen14))
          return 0;

     done_imit(ctx, outText);

     PrintBlock("Input Value: ", kGost14PlainText, textLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outText, imitLen, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ",  kGost14ImitS, imitLen, kBlockLen14);
     PrintEmptyLine();

     free_imit(ctx);

     return memcmp(outText, kGost14ImitS, imitLen);
}

/** @brief тестирование режима ecb алгоритма 28147-89 */
int gost89_ECB_test()
{
     unsigned char ctx[kEcb89ContextLen];
     unsigned char output[textLen89];
     unsigned char outputDec[textLen89];

     PrintLabel("Ecb mode 28147-89 test start.");

     if(init_ecb_89(kMasterKeyGost89, ctx, print_array, print_uint_array))
          return -1;

     if(encrypt_ecb(ctx, kGost89PlaintText, output, textLen89))
          return -1;

     PrintBlock("Master Key: ", kMasterKeyGost89, 32, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Input Value: ", kGost89PlaintText, textLen89, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Output Value: ", output, textLen89, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Control value: ", kGost89EcbC, textLen89, kBlockLen89);
     PrintEmptyLine();

     if(memcmp(output, kGost89EcbC, textLen89))
          return -1;

     free_ecb(ctx);

     if(init_ecb_89(kMasterKeyGost89, ctx, print_array, print_uint_array))
          return -1;

     if(decrypt_ecb(ctx, output, outputDec, textLen89))
          return -1;

     if(memcmp(outputDec, kGost89PlaintText, textLen89))
          return -1;

     free_ecb(ctx);

     return 0;
}

/** @brief тестирование режима ctr алгоритма 28147-89 */
int gost89_CTR_test()
{
     const size_t SvLen = sizeof(kGost89CtrSV);

     unsigned char outText[textLen89];
     unsigned char ctx[kCtr89ContextLen];

     PrintLabel("Ctr mode 28147-89 test start.");
     
     if(init_ctr_89(kMasterKeyGost89, kGost89CtrSV, kBlockLen89, ctx, print_array, print_uint_array))
          return -1;

     if(crypt_ctr(ctx, kGost89PlaintText, outText, textLen89))
          return -1;

     free_ctr(ctx);

     PrintBlock("Master Key: ", kMasterKeyGost89, 32, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("SV: ", kGost89CtrSV, SvLen, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Input Value: ", kGost89PlaintText, textLen89, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outText, textLen89, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Control value: ", kGost89CtrC, textLen89, kBlockLen89);
     PrintEmptyLine();
    
     return memcmp(outText, kGost89CtrC, textLen89);
}

/** @brief тестирование режима ofb алгоритма 28147-89 */
int gost89_OFB_test()
{
     const size_t SvLen = sizeof(kGost89OfbSV);

     unsigned char outText[textLen89];
     unsigned char ctx[kOfb89ContextLen];

     PrintLabel("Ofb mode 28147-89 test start.");

     if(init_ofb_89(kMasterKeyGost89, ctx, kBlockLen89, kGost89OfbSV, SvLen, print_array, print_uint_array))
          return -1;

     if(crypt_ofb(ctx, kGost89PlaintText, outText, textLen89))
          return -1;

     PrintBlock("Master Key: ", kMasterKeyGost89, 32, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("SV: ", kGost89OfbSV, SvLen, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Input Value: ", kGost89PlaintText, textLen89, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outText, textLen89, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Control value: ", kGost89OfbC, textLen89, kBlockLen89);
     PrintEmptyLine();

     free_ofb(ctx);

     return memcmp(outText,  kGost89OfbC, textLen89);
}

/** @brief тестирование режима cbc алгоритма 28147-89 */
int gost89_CBC_test()
{
     const size_t SvLen = sizeof(kGost89CbcSV);

     unsigned char outText[textLen89];
     unsigned char outTextDec[textLen89];
     unsigned char ctx[kCbc89ContextLen];

     PrintLabel("Cbc mode 28147-89 test start.");

     if(init_cbc_89(kMasterKeyGost89, ctx, kGost89CbcSV, SvLen, print_array, print_uint_array))
          return -1;

     if(encrypt_cbc(ctx, kGost89PlaintText, outText, textLen89))
          return 0;

     free_cbc(ctx);

     PrintBlock("Master Key: ", kMasterKeyGost89, 32, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("SV: ", kGost89CbcSV, SvLen, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Input Value: ", kGost89PlaintText, textLen89, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outText, textLen89, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Control value: ", kGost89CbcC, textLen89, kBlockLen89);
     PrintEmptyLine();

     if(init_cbc_89(kMasterKeyGost89, ctx, kGost89CbcSV, SvLen, print_array, print_uint_array))
          return -1;

     if(decrypt_cbc(ctx, outText, outTextDec, textLen89))
          return -1;

     free_cbc(ctx);

     if(memcmp(outTextDec, kGost89PlaintText, textLen89))
          return -1;

     return memcmp(outText, kGost89CbcC, textLen89);
}

/** @brief Тестирование криптографического преобразования алгоритма 28147-89 */
int standart_89_encr_test()
{
     const size_t textLen = sizeof(kGost89StandartPlainText);
     
     unsigned char ctx[kEcb89ContextLen];
     unsigned char output[sizeof(kGost89StandartPlainText)];
     unsigned char outputE[sizeof(kGost89StandartPlainText)];

     PrintLabel("Standart 28147-89 encryption test start.");

     if(init_ecb_89(kMasterKeyGost89, ctx, print_array, print_uint_array))
          return -1;

     if(encrypt_ecb(ctx, kGost89StandartPlainText, output, textLen))
          return -1;

     PrintBlock("Master Key: ", kMasterKeyGost89, 32, kBlockLen89);
     PrintEmptyLine();
     
     PrintBlock("Input Value: ", kGost89StandartPlainText, textLen, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Output Value: ", output, textLen, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Control value: ", kGost89StandartEncrText, textLen, kBlockLen89);
     PrintEmptyLine();

     if(memcmp(output, kGost89StandartEncrText, textLen))
          return -1;

     free_ecb(ctx);

     if(init_ecb_89(kMasterKeyGost89, ctx, print_array, print_uint_array))
          return -1;

     if(decrypt_ecb(ctx, output, outputE, textLen))
          return -1;

     if(memcmp(outputE, kGost89StandartPlainText, textLen))
          return -1;

     free_ecb(ctx);

     return 0;
}

/** @brief тестирование режима cfb алгоритма 28147-89 */
int gost89_CFB_test()
{
     const size_t SvLen = sizeof(kGost89CfbSV);
     
     unsigned char outText[textLen89];
     unsigned char outTextDec[textLen89];
     unsigned char ctx[kCfb89ContextLen];

     PrintLabel("Cfb mode 28147-89 test start.");

     if(init_cfb_89(kMasterKeyGost89, ctx, kBlockLen89, kGost89CfbSV, SvLen, print_array, print_uint_array))
          return -1;

     if(encrypt_cfb(ctx, kGost89PlaintText, outText, textLen89))
          return -1;

     PrintBlock("Master Key: ", kMasterKeyGost89, 32, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("SV: ", kGost89CfbSV, SvLen, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Input Value: ", kGost89PlaintText, textLen89, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outText, textLen89, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Control value: ", kGost89CfbC, textLen89, kBlockLen89);
     PrintEmptyLine();

     if(memcmp(outText, kGost89CfbC, textLen89))
          return -1;

     free_cfb(ctx);

     if(init_cfb_89(kMasterKeyGost89, ctx, kBlockLen89, kGost89CfbSV, SvLen, print_array, print_uint_array))
          return -1;

     if(decrypt_cfb(ctx, outText, outTextDec, textLen89))
          return -1;

     if(memcmp(outTextDec, kGost89PlaintText, textLen89))
          return -1;

     free_cfb(ctx);

     return 0;
}
#include<stdio.h>
/** @brief тестирование режима имтовставки алгоритма 28147-89 */
int gost89_imita_test()
{
     const size_t imitLen = sizeof(kGost89ImitS);

     unsigned char outText[sizeof(kGost89ImitS)];
     unsigned char ctx[kImit89ContextLen];

     PrintLabel("Imita mode 28147-89 test start.");

     if(init_imit_89(kMasterKeyGost89, kBlockLen89, ctx, print_array, print_uint_array))
          return -1;

     if(imit(ctx, kGost89PlaintText, textLen89))
          return -1;

     done_imit(ctx, outText);

     free_imit(ctx);

     PrintBlock("Master Key: ", kMasterKeyGost89, 32, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Input Value: ", kGost89PlaintText, textLen89, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Output Value: ", outText, imitLen, kBlockLen89);
     PrintEmptyLine();
     PrintBlock("Control value: ", kGost89ImitS, imitLen, kBlockLen89);
     PrintEmptyLine();

     return memcmp(outText, kGost89ImitS, imitLen);
}

/** @brief тестирование дополнения сообщения */
int testPadding()
{
     const size_t len = sizeof(kPaddingText)/sizeof(kPaddingText[0]);
     const size_t len2 = sizeof(kPaddingText2)/sizeof(kPaddingText2[0]);

     padd(paddingBufferText, 1, kBlockLen14);
     padd(paddingBufferText2, kBlockLen14, 2*kBlockLen14);

     PrintLineLeft("Test 1");
     PrintBlock("Input Value: ", paddingBufferText, 1, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", paddingBufferText, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ", kPaddingText, len, kBlockLen14);
     PrintEmptyLine();

//     if(memcmp(paddingBufferText, kPaddingText, len))
//          return -1;

     PrintLineLeft("Test 2");
     PrintBlock("Input Value: ", paddingBufferText2, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", paddingBufferText2, 2*kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ", kPaddingText2, len2, kBlockLen14);
     PrintEmptyLine();
     fflush(stdout);

//     if(memcmp(paddingBufferText2, kPaddingText2, len2))
//          return -1;
     
     return 0;
}

/** @brief тестирование снятия дополнения сообщения */
int testCut()
{
     size_t rLen, rLen2;
     padd(paddingBufferText, 1, kBlockLen14);
     padd(paddingBufferText2, kBlockLen14, 2*kBlockLen14);

     rLen = unpadd(paddingBufferText, kBlockLen14);
     rLen2 = unpadd(paddingBufferText2, 2*kBlockLen14);

     PrintLabel("Cut padding test start.");

     PrintLineLeft("Test 1");
     PrintBlock("Input Value: ", paddingBufferText, kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", paddingBufferText, rLen, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ", kPaddingText, 1, kBlockLen14);
     PrintEmptyLine();

     PrintLineLeft("Test 2");
     PrintBlock("Input Value: ", paddingBufferText2, 2*kBlockLen14, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Output Value: ", paddingBufferText2, rLen2, kBlockLen14);
     PrintEmptyLine();
     PrintBlock("Control value: ", kPaddingText2, kBlockLen14, kBlockLen14);
     PrintEmptyLine();

     if(rLen !=1 )
          return -1;

     if(rLen2 != kBlockLen14)
          return -1;
     
     return 0;
}

/** @brief Тестирование преобразования t алгоритма 28147-89 */
int testFuncT()
{
     int i;
     PrintLabel("Test 28147-89 function T start.");

     for(i = 0; i < 4; ++i)
     {
          unsigned int ans;
          ans = funcT(kTData[i], 0);

          PrintBlockLeft("Test ", i+1);
          PrintBlockInt("Input value", kTData[i]);
          PrintBlockInt("Ouput value", ans);
          PrintBlockInt("Control value", kTData[i+1]);
          PrintEmptyLine();

          if(ans != kTData[i+1])
               return -1;
     }

     return 0;
}

/** @brief Тестирование преобразования g алгоритма 28147-89 */
int testG()
{
     int i;
     PrintLabel("Test 28147-89 function G start.");

     for(i = 0; i < 4; ++i)
     {
          unsigned int ans;
          ans = funcG(kgData[i][0], kgData[i][1], 0);

          PrintBlockLeft("Test ", i+1);
          PrintBlockInt("Input value", kgData[i][0]);
          PrintBlockInt("Key value", kgData[i][1]);
          PrintBlockInt("Ouput value", ans);
          PrintBlockInt("Control value", kgData[i][2]);
          PrintEmptyLine();
          
          if( ans!= kgData[i][2])
               return -1;
     }

     return 0;
}

/** @brief точка входа  */
int main_gost_test()
{
     int testRes = 0;
     PrintLine("TEST start.");
     PrintEmptyLine();
     
     PrintLine("TEST 28147-14 standart start.");
     testRes |= PrintTest("S function test end", testS());
     testRes |= PrintTest("R function test.", testR());
     testRes |= PrintTest("L function test.", testL());
     testRes |= PrintTest("Expand Key 28147-14 test.", testExpandKey());
     testRes |= PrintTest("Encrypt test.", testEncrypt());
     testRes |= PrintTest("Decrypt test.", testDecrypt());
     PrintEmptyLine();

     PrintLine("TEST 28147-89 standart test.");
     testRes |= PrintTest("28147-89 T function test.", testFuncT());
     testRes |= PrintTest("28147-89 G function test.", testG());
     testRes |= PrintTest("Encrypt test.", standart_89_encr_test());
     PrintEmptyLine();

     PrintLine("TEST 28147-14 mode test.");
     testRes |= PrintTest("Ecb mode 28147-14 test.", gost14_ECB_test());
     testRes |= PrintTest("CTR mode 28147-14 test.", gost14_CTR_test());
     testRes |= PrintTest("OFB mode 28147-14 test.", gost14_OFB_test());
     testRes |= PrintTest("CBC mode 28147-14 test.", gost14_CBC_test());
     testRes |= PrintTest("CFB mode 28147-14 test.", gost14_CFB_test());
     testRes |= PrintTest("Imita mode 28147-14 test.", gost14_imita_test());
     PrintEmptyLine();

     PrintLine("TEST 28147-89 mode test.");
     testRes |= PrintTest("Ecb mode 28147-89 test.", gost89_ECB_test());
     testRes |= PrintTest("CTR mode 28147-89 test.", gost89_CTR_test());
     testRes |= PrintTest("OFB mode 28147-89 test.", gost89_OFB_test());
     testRes |= PrintTest("CBC mode 28147-89 test.", gost89_CBC_test());
     testRes |= PrintTest("CFB mode 28147-89 test.", gost89_CFB_test());
     testRes |= PrintTest("Imita mode 28147-89 test.", gost89_imita_test());
     PrintEmptyLine();

     PrintLine("TEST padding test.");

     testRes |= PrintTest("Add padding test.", testPadding());
     testRes |= PrintTest("Cut padding test.", testCut());
     PrintEmptyLine();

     if ( testRes )
     {
          PrintLine("FAILED TESTS EXIST!!!!!.");
     }
     else
     {
          PrintLine("ALL TEST OK.");
     }
     
     return testRes;
}
