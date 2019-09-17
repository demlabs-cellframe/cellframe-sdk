/*
Implementation by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
Michaël Peeters, Gilles Van Assche and Ronny Van Keer,
hereby denoted as "the implementer".

For more information, feedback or questions, please refer to our website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

Please refer to SnP-documentation.h for more details.
*/

#ifndef _KeccakP_1600_SnP_h_
#define _KeccakP_1600_SnP_h_

#define SYSVABI __attribute__((sysv_abi))

#define KeccakP1600_implementation      "64-bit optimized implementation (lane complementing, all rounds unrolled) compiled by GCC 4.7.4 for Nehalem"
#define KeccakP1600_stateSizeInBytes    200
#define KeccakP1600_stateAlignment      8
#define KeccakF1600_FastLoop_supported

#include <stddef.h>

#define KeccakP1600_StaticInitialize()
SYSVABI void KeccakP1600_Initialize(void *state);
SYSVABI void KeccakP1600_AddByte(void *state, unsigned char data, unsigned int offset);
SYSVABI void KeccakP1600_AddBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length);
SYSVABI void KeccakP1600_OverwriteBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length);
SYSVABI void KeccakP1600_OverwriteWithZeroes(void *state, unsigned int byteCount);
SYSVABI void KeccakP1600_Permute_12rounds(void *state);
SYSVABI void KeccakP1600_Permute_24rounds(void *state);
SYSVABI void KeccakP1600_ExtractBytes(const void *state, unsigned char *data, unsigned int offset, unsigned int length);
SYSVABI void KeccakP1600_ExtractAndAddBytes(const void *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
SYSVABI size_t KeccakF1600_FastLoop_Absorb(void *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen);

#endif
