/*
Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to our website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _Xoodoo_SnP_h_
#define _Xoodoo_SnP_h_

#include <stddef.h>
#include <stdint.h>

/** For the documentation, see SnP-documentation.h.
 */

#define Xoodoo_implementation      "32-bit optimized implementation"
#define Xoodoo_stateSizeInBytes    (3*4*4)
#define Xoodoo_stateAlignment      4
#define Xoodoo_HasNround

#define Xoodoo_StaticInitialize()
void Xoodoo_Initialize(void *state);
#define Xoodoo_AddByte(argS, argData, argOffset)    ((uint8_t*)argS)[argOffset] ^= (argData)
void Xoodoo_AddBytes(void *state, const uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_OverwriteBytes(void *state, const uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_OverwriteWithZeroes(void *state, unsigned int byteCount);
void Xoodoo_Permute_Nrounds(void *state, unsigned int nrounds);
void Xoodoo_Permute_6rounds(void *state);
void Xoodoo_Permute_12rounds(void *state);
void Xoodoo_ExtractBytes(const void *state, uint8_t *data, unsigned int offset, unsigned int length);
void Xoodoo_ExtractAndAddBytes(const void *state, const uint8_t *input, uint8_t *output, unsigned int offset, unsigned int length);

//#define Xoodoo_FastXoofff_supported
//void Xoofff_AddIs( uint8_t *output, const uint8_t *input, size_t bitLen);
//size_t Xoofff_CompressFastLoop(uint8_t *k, uint8_t *xAccu, const uint8_t *input, size_t length);
//size_t Xoofff_ExpandFastLoop(uint8_t *yAccu, const uint8_t *kRoll, uint8_t *output, size_t length);

#define CyclistFullBlocks_supported
size_t Xoodyak_AbsorbKeyedFullBlocks(void *state, const uint8_t *X, size_t XLen);
size_t Xoodyak_AbsorbHashFullBlocks(void *state, const uint8_t *X, size_t XLen);
size_t Xoodyak_SqueezeHashFullBlocks(void *state, uint8_t *Y, size_t YLen);
size_t Xoodyak_SqueezeKeyedFullBlocks(void *state, uint8_t *Y, size_t YLen);
size_t Xoodyak_EncryptFullBlocks(void *state, const uint8_t *I, uint8_t *O, size_t IOLen);
size_t Xoodyak_DecryptFullBlocks(void *state, const uint8_t *I, uint8_t *O, size_t IOLen);

#endif
