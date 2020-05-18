/** @file 
 * @brief Реализация алгоритма "Кузнечик"
 *
 * @copyright InfoTeCS. All rights reserved.
 */

#include <string.h>
#include <stdint.h>
#include <memory.h>

#include "28147_14.h"
#include "table.h"

/** @brief Нелинейное биективное преобразование множества двоичных векторов. */
static const unsigned char kPi[256] =
{
	252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250, 218,  35, 197,   4,  77, 
	233, 119, 240, 219, 147,  46, 153, 186,  23,  54, 241, 187,  20, 205,  95, 193,
	249,  24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66,	139,   1, 142,  79,
	  5, 132,   2, 174, 227, 106, 143, 160,   6,  11, 237, 152, 127, 212, 211,  31,
	235,  52,  44,  81,	234, 200,  72, 171, 242,  42, 104, 162, 253,  58, 206, 204,
	181, 112,  14,  86,   8,  12, 118,  18, 191, 114,  19,  71, 156, 183,  93, 135,
	 21, 161, 150,  41,  16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
	 50, 117,  25,  61, 255,  53, 138, 126, 109,  84, 198, 128, 195, 189,  13,  87,
	223, 245,  36, 169,  62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,   3,
	224,  15, 236, 222, 122, 148, 176, 188, 220, 232,  40,  80,  78,  51,  10,  74,
	167, 151,  96, 115,  30,   0,  98,  68,  26, 184,  56, 130, 100, 159,  38,  65,
	173,  69,  70, 146,  39,  94,  85,  47, 140, 163, 165, 125, 105, 213, 149,  59,
	  7,  88, 179,  64, 134, 172,  29, 247,  48,  55, 107, 228,	136, 217, 231, 137,
	225,  27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144, 202, 216, 133,  97,
	 32, 113, 103, 164,  45,  43,   9,  91, 203, 155,  37, 208, 190, 229, 108,  82,
	 89, 166, 116, 210, 230, 244, 180, 192,	209, 102, 175, 194,  57,  75,  99, 182
};

/** @brief Обратное нелинейное биективное преобразование множества двоичных векторов. */
static const unsigned char kReversePi[256] =
{
     0xa5,0x2d,0x32,0x8f,0x0e,0x30,0x38,0xc0,0x54,0xe6,0x9e,0x39,0x55,0x7e,0x52,0x91,
     0x64,0x03,0x57,0x5a,0x1c,0x60,0x07,0x18,0x21,0x72,0xa8,0xd1,0x29,0xc6,0xa4,0x3f,
     0xe0,0x27,0x8d,0x0c,0x82,0xea,0xae,0xb4,0x9a,0x63,0x49,0xe5,0x42,0xe4,0x15,0xb7,
     0xc8,0x06,0x70,0x9d,0x41,0x75,0x19,0xc9,0xaa,0xfc,0x4d,0xbf,0x2a,0x73,0x84,0xd5,
     0xc3,0xaf,0x2b,0x86,0xa7,0xb1,0xb2,0x5b,0x46,0xd3,0x9f,0xfd,0xd4,0x0f,0x9c,0x2f,
     0x9b,0x43,0xef,0xd9,0x79,0xb6,0x53,0x7f,0xc1,0xf0,0x23,0xe7,0x25,0x5e,0xb5,0x1e,
     0xa2,0xdf,0xa6,0xfe,0xac,0x22,0xf9,0xe2,0x4a,0xbc,0x35,0xca,0xee,0x78,0x05,0x6b,
     0x51,0xe1,0x59,0xa3,0xf2,0x71,0x56,0x11,0x6a,0x89,0x94,0x65,0x8c,0xbb,0x77,0x3c,
     0x7b,0x28,0xab,0xd2,0x31,0xde,0xc4,0x5f,0xcc,0xcf,0x76,0x2c,0xb8,0xd8,0x2e,0x36,
     0xdb,0x69,0xb3,0x14,0x95,0xbe,0x62,0xa1,0x3b,0x16,0x66,0xe9,0x5c,0x6c,0x6d,0xad,
     0x37,0x61,0x4b,0xb9,0xe3,0xba,0xf1,0xa0,0x85,0x83,0xda,0x47,0xc5,0xb0,0x33,0xfa,
     0x96,0x6f,0x6e,0xc2,0xf6,0x50,0xff,0x5d,0xa9,0x8e,0x17,0x1b,0x97,0x7d,0xec,0x58,
     0xf7,0x1f,0xfb,0x7c,0x09,0x0d,0x7a,0x67,0x45,0x87,0xdc,0xe8,0x4f,0x1d,0x4e,0x04,
     0xeb,0xf8,0xf3,0x3e,0x3d,0xbd,0x8a,0x88,0xdd,0xcd,0x0b,0x13,0x98,0x02,0x93,0x80,
     0x90,0xd0,0x24,0x34,0xcb,0xed,0xf4,0xce,0x99,0x10,0x44,0x40,0x92,0x3a,0x01,0x26,
     0x12,0x1a,0x48,0x68,0xf5,0x81,0x8b,0xc7,0xd6,0x20,0x0a,0x08,0x00,0x4c,0xd7,0x74
};

/** @brief Коэффициенты умножения в преобразовании l */
static const  unsigned char kB[16] = {148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1};

int DLL_IMPORT  funcX(unsigned char* a, unsigned char* b, unsigned char* outdata, printout_byte_array print)
{
     unsigned int i;

     if(!a || !b || !outdata)
     {
          if(print)
               print("funcX: internal error!", 0, 0);
          return -1;
     }

     for(i = 0; i < 16; ++i)
     {
          outdata[i] = a[i] ^ b[i];
     }

     if(print)
     {
          print("funcX: a: ", a, 16);
          print("funcX: b: ", b, 16);
          print("funcX: result: ", outdata, 16);
     }

     return 0;
}

int DLL_IMPORT  funcS(unsigned char* indata, unsigned char* outdata, printout_byte_array print)
{
     size_t i = 0;

     if(!indata || !outdata)
     {
          if(print)
               print("funcS: internal error!", 0, 0);
          return -1;
     }

     for(i = 0; i < 16; ++i)
     {
          outdata[i] = kPi[indata[i]];
     }

     if(print)
     {
          print("funcS: input: ", indata, 16);
          print("funcS: output: ", outdata, 16);
     }

     return 0;
}

int DLL_IMPORT  funcReverseS(unsigned char* indata, unsigned char*  outdata, printout_byte_array print)
{
     unsigned int i;

     if(!indata || !outdata)
     {
          if(print)
               print("funcReverseS: internal error!", 0, 0);
          return -1;
     }

     for(i = 0; i < 16; ++i)
          outdata[i] = kReversePi[indata[i]];

     if(print)
     {
          print("funcReverseS: input: ", indata, 16);
          print("funcReverseS: output: ", outdata, 16);
     }

     return 0;
}

int DLL_IMPORT  funcR(unsigned char* indata, unsigned char* outdata, printout_byte_array print)
{
     size_t i;
     unsigned char sum = 0;

     if(!indata || !outdata)
     {
          if(print)
               print("funcR: internal error!", 0, 0);
          return -1;
     }
     
     for(i = 0; i < 16; ++i)
     {
          sum ^= multTable[indata[i]*256 + kB[i]];
     }

     outdata[0] = sum;
     memcpy(outdata+1, indata, 15);

     if(print)
     {
          print("funcR: input: ", indata, 16);
          print("funcR: output: ", outdata, 16);
     }

     return 0;
}

int DLL_IMPORT  funcReverseR(unsigned char* indata, unsigned char* outdata, printout_byte_array print)
{
     unsigned char tmp[16];
     unsigned char sum = 0;
     unsigned int i;

     if(!indata || !outdata)
     {
          if(print)
               print("funcReverseR: internal error!", 0, 0);
          return -1;
     }

     memcpy(tmp, indata+1, 15);
     tmp[15] = indata[0];

     
     for(i = 0; i < 16; ++i)
     {
          sum ^= multTable[tmp[i]*256 + kB[i]];
     }

     memcpy(outdata, tmp, 15); 
     outdata[15] = sum;

     if(print)
     {
          print("funcReverseR: input: ", indata, 16);
          print("funcReverseR: output: ", outdata, 16);
     }
     
     return 0;
}

int DLL_IMPORT  funcL(unsigned char* indata, unsigned char* outdata, printout_byte_array print)
{
     unsigned char tmp[16];
     int i = 0;

     if(!indata || !outdata)
     {
          if(print)
               print("funcL: internal error!", 0, 0);
          return -1;
     }

     memcpy(tmp, indata, 16);

     for(i = 0; i < 16; ++i)
     {
          funcR(tmp, outdata, print);
          memcpy(tmp, outdata, 16);
     }

     if(print)
     {
          print("funcL: input: ", indata, 16);
          print("funcL: output: ", outdata, 16);
     }

     return 0;
}

int DLL_IMPORT  funcReverseL(unsigned char* indata, unsigned char* outdata, printout_byte_array print)
{
     unsigned char tmp[16];
     unsigned int i;

     if(!indata || !outdata)
     {
          if(print)
               print("funcReverseL: internal error!", 0, 0);
          return -1;
     }

     memcpy(tmp, indata, 16);

     for(i = 0; i < 16; ++i)
     {
          funcReverseR(tmp, outdata, print);
          memcpy(tmp, outdata, 16);
     }

     if(print)
     {
          print("funcReverseL: input: ", indata, 16);
          print("funcReverseL: output: ", outdata, 16);
     }

     return 0;
}

int DLL_IMPORT  funcLSX(unsigned char* a, unsigned char* b, unsigned char* outdata, printout_byte_array print)
{
     unsigned char temp1[16];
     unsigned char temp2[16];

     if(!a || !b || !outdata)
     {
          if(print)
               print("funcLSX: internal error!", 0, 0);
          return -1;
     }

     funcX(a, b, temp1, print);
     funcS(temp1, temp2, print);
     funcL(temp2, outdata, print);

     if(print)
     {
          print("funcLSX: a: ", a, 16);
          print("funcLSX: b: ", b, 16);
          print("funcLSX: output: ", outdata, 16);
     }

     return 0;
}

int DLL_IMPORT  funcReverseLSX(unsigned char* a, unsigned char* b, unsigned char* outdata, printout_byte_array print)
{
     unsigned char temp1[16];
     unsigned char temp2[16];

     if(!a || !b || !outdata)
     {
          if(print)
               print("funcReverseLSX: internal error!", 0, 0);
          return -1;
     }

     funcX(a, b, temp1, print);
     funcReverseL(temp1, temp2, print);
     funcReverseS(temp2, outdata, print);

     if(print)
     {
          print("funcReverseLSX: a: ", a, 16);
          print("funcReverseLSX: b: ", b, 16);
          print("funcReverseLSX: output: ", outdata, 16);
     }

     return 0;
}

int DLL_IMPORT  funcF(unsigned char* inputKey, unsigned char* inputKeySecond, unsigned char* iterationConst, unsigned char* outputKey, unsigned char* outputKeySecond, printout_byte_array print)
{
     unsigned char temp1[16];
     unsigned char temp2[16];

     if(!inputKey || !inputKeySecond || !iterationConst || !outputKey || !outputKeySecond)
     {
          if(print)
               print("funcF: internal error!", 0, 0);
          return -1;
     }

     funcLSX(inputKey, iterationConst, temp1, print);
     funcX(temp1, inputKeySecond, temp2, print);

     memcpy(outputKeySecond, inputKey, 16);
     memcpy(outputKey, temp2, 16);   

     if(print)
     {
          print("funcF: input key: ", inputKey, 16);
          print("funcF: input key: ", inputKeySecond, 16);
          print("funcF: iterration const: ", iterationConst, 16);
          print("funcF: output key: ", outputKey, 16);
          print("funcF: output key: ", outputKeySecond, 16);
     }

     return 0;
}

int DLL_IMPORT  funcC(unsigned char number, unsigned char* output, printout_byte_array print)
{
     unsigned char tempI[16];

     if(!output)
     {
          if(print)
               print("funcC: internal error!", 0, 0);
          return -1;
     }
     
     memset( tempI, 0, 15 );
     tempI[15] = number;
     funcL(tempI, output, print);

     return 0;
}

int DLL_IMPORT  ExpandKey(unsigned char* masterKey, unsigned char* keys, printout_byte_array print)
{
     unsigned char C[16];
     unsigned char temp1[16];
     unsigned char temp2[16];
     unsigned char j, i;


     if( !masterKey || !keys)
     {
          if(print)
               print("ExpandKey: internal error!", 0, 0);
          return -1;
     }

     
     memcpy(keys, masterKey, 16);
     memcpy(keys + 16, masterKey + 16, 16);

     if(print)
     {
          print("ExpandKey: master key: ", masterKey, 16);
          print("ExpandKey: output key: ", keys, 16);
          print("ExpandKey: output key: ", keys + 16, 16);
     }

     for(j = 0; j < 4; ++j)
     {
          memcpy(temp1, keys + j * 2 * 16, 16);
          memcpy(temp2, keys + (j * 2 + 1) * 16, 16);

          for( i = 1; i < 8; ++i )
          {
               funcC(j*8+i, C, print);
               funcF(temp1, temp2, C, temp1, temp2, print);
          }
          
          funcC(j*8+8, C, print);
          funcF(temp1, temp2, C, temp1, temp2, print);

          memcpy(keys + (j * 2 + 2) * 16, temp1, 16);
          memcpy(keys + (j * 2 + 3) * 16, temp2, 16);

          if(print)
          {
               print("ExpandKey: output key: ", keys + (j * 2 + 2) * 16, 16);
               print("ExpandKey: output key: ", keys + (j * 2 + 3) * 16, 16);
          }
     }

    
     return 0;
}

int DLL_IMPORT  Encrypt_14(const unsigned char* plainText, unsigned char* chipherText, unsigned char* keys, printout_byte_array print, printout_uint_array print_uint)
{
     unsigned char xTemp[16];
     unsigned char yTemp[16];
     int i;

     (void)print_uint;

     if(!plainText || !chipherText || !keys)
     {
          if(print)
               print("Encrypt_14: internal error!", 0, 0);
          return -1;
     }

     memcpy(xTemp, plainText, 16);
     
     for(i = 0; i < 9; ++i)
     {
          funcLSX(xTemp, keys + 16*i, yTemp, print);
          memcpy(xTemp, yTemp, 16);
     }
     funcX(yTemp, keys+9*16, chipherText, print);

     if(print)
     {
          for(i = 0; i < 10; ++i)
          {
               print("Encrypt_14: key: ", keys, 16);
               keys += 16;

          }
          print("Encrypt_14: plain text: ", plainText, 16);
          print("Encrypt_14: chipher text: ", chipherText, 16);
     }

     return 0;
}

int DLL_IMPORT  Decrypt_14(const unsigned char* chipherText, unsigned char* plainText, unsigned char* keys, printout_byte_array print, printout_uint_array print_uint)
{
     unsigned char xTemp[16];
     unsigned char yTemp[16];
     int i;

     (void)print_uint;

     if(!plainText || !chipherText || !keys)
     {
          if(print)
               print("Decrypt_14: internal error!", 0, 0);
          return -1;
     }

     memcpy(xTemp, chipherText, 16);
     for(i = 0; i < 9; ++i)
     {
          funcReverseLSX(xTemp, keys+(9-i)*16, yTemp, print);
          memcpy(xTemp, yTemp, 16);
     }
     funcX(yTemp, keys, plainText, print);

     if(print)
     {
          for(i = 0; i < 10; ++i)
          {
               print("Decrypt_14: key: ", keys, 16);
               keys += 16;

          }
          print("Decrypt_14: chipher text : ", chipherText, 16);
          print("Decrypt_14: plain text: ", plainText, 16);
     }

     return 0;
}
