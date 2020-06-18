/** @file 
 * @brief Реализация алгоритма 28147-89
 *
 * @copyright InfoTeCS. All rights reserved.
 */

#include <string.h>
#include <stdint.h>

#include "28147_89.h"

/** @brief Конвертирует массив байт в int32
 *
 * @param[in] input массив из 4 байт
 * @return int32 число
 */
static unsigned int uint8ToUint32(const unsigned char* input)
{
     unsigned int r = ( (input[3]) | (input[2]<<8) | (input[1]<<16) | (input[0]<<24));
     return r;
}

/** @brief Конвертирует int32 в массив байт
 *
 * @param[in] input int32 число
 * @param[out] output массив из 4 байт
 */
static void uint32ToUint8(unsigned int input, unsigned char* output)
{
     int i;
     for(i = 0; i < 4; ++i)
     {
          output[3-i] = ( ( input >> (8*i) ) & 0x000000ff );
     }
}


/** @brief Таблица подстановки  id-tc26-gost-28147-param-Z OID: 1.2.643.7.1.2.5.1.1 */
unsigned char p[8][16] =
{
     {0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1},
     {0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf},
     {0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0},
     {0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb},
     {0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc},
     {0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0},
     {0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7},
     {0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2}

};

/** @brief используемый байт ключа при шифровании */
unsigned char kEncRoundKey[32] = 
{
     0, 4, 8, 12, 16, 20, 24, 28, 0, 4, 8, 12, 16, 20, 24, 28, 0, 4, 8, 12, 16, 20, 24, 28, 28, 24, 20, 16, 12, 8, 4, 0
};

/** @brief используемый байт ключа при расшифровании */
unsigned char kDecRoundKey[32] = 
{
     0, 4, 8, 12, 16, 20, 24, 28, 28, 24, 20, 16, 12, 8, 4, 0, 28, 24, 20, 16, 12, 8, 4, 0, 28, 24, 20, 16, 12, 8, 4, 0
};

unsigned int DLL_IMPORT funcT(unsigned int a, printout_uint_array print)
{
     unsigned int res = 0;

     res ^=   p[ 0 ][ a & 0x0000000f ];
     res ^= ( p[ 1 ][ ( ( a & 0x000000f0 ) >>  4 ) ] << 4 );
     res ^= ( p[ 2 ][ ( ( a & 0x00000f00 ) >>  8 ) ] << 8 );
     res ^= ( p[ 3 ][ ( ( a & 0x0000f000 ) >> 12 ) ] << 12 );
     res ^= ( p[ 4 ][ ( ( a & 0x000f0000 ) >> 16 ) ] << 16 );
     res ^= ( p[ 5 ][ ( ( a & 0x00f00000 ) >> 20 ) ] << 20 );
     res ^= ( p[ 6 ][ ( ( a & 0x0f000000 ) >> 24 ) ] << 24 );
     res ^= ( p[ 7 ][ ( ( a & 0xf0000000 ) >> 28 ) ] << 28 );

     if(print)
     {
          print("funcT: a: ", &a, 1);
          print("funcT: output: ", &res, 1);
     }

     return res;
}

unsigned int DLL_IMPORT funcG(unsigned int a, unsigned int k, printout_uint_array print)
{
     
     unsigned int c = a + k;
     unsigned int tmp = funcT(c, print);
     unsigned int r = (tmp<<11) | (tmp >> 21);

     if(print)
     {
          print("funcG: a: ", &a, 1);
          print("funcG: k: ", &k, 1);
          print("funcG: output: ", &r, 1);
     }

     return r;
}

void DLL_IMPORT Round(unsigned int* a1, unsigned int* a0, unsigned int k, printout_uint_array print)
{
     unsigned int a;
     unsigned int tmp;

     if(print)
     {
          print("Round: input a1: ", a1, 1);
          print("Round: input a0: ", a0, 1);
          print("Round: k: ", &k, 1);
     }

     a = *a0;
     tmp = funcG(*a0, k, print);
    
     *a0 = *a1 ^ tmp;
     *a1 = a;

     if(print)
     {
          print("Round: output a1: ", a1, 1);
          print("Round: output a0: ", a0, 1);
     }
}

void DLL_IMPORT RoundShtrih(unsigned int* a1, unsigned int* a0, unsigned int k, printout_uint_array print)
{
     unsigned int tmp;

     if(print)
     {
          print("RoundShtrih: input a1: ", a1, 1);
          print("RoundShtrih: input a0: ", a0, 1);
          print("RoundShtrih: k: ", &k, 1);
     }

     tmp = funcG(*a0, k, print);
     *a1 ^= tmp;

     if(print)
     {
          print("RoundShtrih: output a1: ", a1, 1);
          print("RoundShtrih: output a0: ", a0, 1);
     }
}

int DLL_IMPORT CryptBlock(const unsigned char* input, unsigned char* output, unsigned char* key, unsigned char* keyIndex, printout_uint_array print)
{
     unsigned int a1 = uint8ToUint32(input);
     unsigned int a0 = uint8ToUint32(input + 4);
     int i;

     if(print)
     {
          print("CryptBlock: input a1:", &a1, 1);
          print("CryptBlock: input a0:", &a0, 1);
     }

     
     for(i = 0; i < 31; ++i)
     {
          Round(&a1, &a0, uint8ToUint32(key + keyIndex[i]), print);
     }

     RoundShtrih(&a1, &a0, uint8ToUint32(key + keyIndex[31]), print);

     if(print)
     {
          print("CryptBlock: output a1:", &a1, 1);
          print("CryptBlock: output a0:", &a0, 1);
     }

     uint32ToUint8(a1, output);
     uint32ToUint8(a0, output+4);

     return 0;
}

int DLL_IMPORT EncryptBlock(const unsigned char* input, unsigned char* output, unsigned char* key, printout_uint_array print)
{
     return CryptBlock(input, output, key, kEncRoundKey, print);
}

int DLL_IMPORT DecryptBlock(const unsigned char* input, unsigned char* output, unsigned char* key, printout_uint_array print)
{
     return CryptBlock(input, output, key, kDecRoundKey, print);
}

int DLL_IMPORT Encrypt_89(const unsigned char* input, unsigned char* output, unsigned char* key, printout_byte_array print, printout_uint_array print_uint)
{
     if( !input || !output || !key )
     {
          if(print)
               print("Encrypt_89: internal error!", 0, 0);
          return -1;
     }

     if(EncryptBlock(input, output, key, print_uint))
         return -1;

     if(print)
     {
          print("Encrypt_89: plain text: ", input, 8);
          print("Encrypt_89: chipher text: ", output, 8);
     }

     return 0;
}

int DLL_IMPORT Decrypt_89(const unsigned char* input, unsigned char* output, unsigned char* key, printout_byte_array print, printout_uint_array print_uint)
{
     if( !input || !output || !key )
     {
          if(print)
               print("Decrypt_89: internal error!", 0, 0);
          return -1;
     }

     if(DecryptBlock(input, output, key, print_uint))
          return -1;

     if(print)
     {
          print("Encrypt_89: chipher text: ", input, 8);
          print("Encrypt_89: plain text: ", output, 8);
     }
     
     return 0;
}
