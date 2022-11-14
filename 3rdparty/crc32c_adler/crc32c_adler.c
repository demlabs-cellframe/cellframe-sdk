/*
  CRC32C_ADLER -- Computes CRC32C Checksums
  Version 1.2, Date 05/21/18
  Copyright (C) 2013 Mark Adler <madler@alumni.caltech.edu>
  Copyright (C) 2018 Fonic <https://github.com/fonic>

  Provides both a hardware-accelerated algorithm (*) and a software algorithm.
  Note that this computes CRC32C checksums, not CRC32 (without 'C') checksums
  used by Ethernet, gzip, etc.

  (*) CRC instruction on Intel SSE 4.2 processors.  SSE 4.2 was first supported
      by Nehalem processors introduced in November, 2008.

  Version history:
  1.0  10 Feb 2013  First version
  1.1   1 Aug 2013  Correct comments on why three crc instructions in parallel
  1.2  21 May 2018  Add header file, revise hardware support check, eliminate
                    pthreads, restructure code, revise comments and description

  Version 1.1 by Mark Adler was originally published here:
  https://stackoverflow.com/a/17646775

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software.  If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "crc32c_adler.h"

/* CRC32C (iSCSI) polynomial in reversed bit order. */
#define POLY 0x82f63b78


/******************************************************************************
 *                                                                            *
 *  Software Algorithm (1) - Table-driven, 8 Bytes / Iteration                *
 *                                                                            *
 ******************************************************************************/

/* Table for software algorithm. */
static uint32_t crc32c_table[8][256];

/* Flag to indicate if crc32c_init_sw() has been called. */
static int crc32c_sw_initialized = 0;

/* Initialize table for software algorithm. */
static void crc32c_init_sw(void)
{
    uint32_t n, crc, k;

    for (n = 0; n < 256; n++) {
        crc = n;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc32c_table[0][n] = crc;
    }
    for (n = 0; n < 256; n++) {
        crc = crc32c_table[0][n];
        for (k = 1; k < 8; k++) {
            crc = crc32c_table[0][crc & 0xff] ^ (crc >> 8);
            crc32c_table[k][n] = crc;
        }
    }
    crc32c_sw_initialized = 1;
}

/* Compute CRC32C checksum. */
uint32_t crc32c_sw(uint32_t crci, const void *buf, size_t len)
{
    const unsigned char *next = buf;
    uint64_t crc;

    if (!crc32c_sw_initialized)
        crc32c_init_sw();

    crc = crci ^ 0xffffffff;
    while (len && ((uintptr_t)next & 7) != 0) {
        crc = crc32c_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    while (len >= 8) {
        crc ^= *(uint64_t *)next;
        crc = crc32c_table[7][crc & 0xff] ^
              crc32c_table[6][(crc >> 8) & 0xff] ^
              crc32c_table[5][(crc >> 16) & 0xff] ^
              crc32c_table[4][(crc >> 24) & 0xff] ^
              crc32c_table[3][(crc >> 32) & 0xff] ^
              crc32c_table[2][(crc >> 40) & 0xff] ^
              crc32c_table[1][(crc >> 48) & 0xff] ^
              crc32c_table[0][crc >> 56];
        next += 8;
        len -= 8;
    }
    while (len) {
        crc = crc32c_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    return (uint32_t)crc ^ 0xffffffff;
}


/******************************************************************************
 *                                                                            *
 *  Software Algorithm (2) - Table-driven, 16 Bytes / Iteration               *
 *                                                                            *
 ******************************************************************************/

/* Table for software algorithm. */
static uint32_t crc32c_table2[16][256];

/* Flag to indicate if crc32c_init_sw2() has been called. */
static int crc32c_table2_initialized = 0;

/* Initialize table for software algorithm. */
static void crc32c_init_sw2(void)
{
    for(int i = 0; i < 256; i++)
    {
        uint32_t res = (uint32_t)i;
        for(int t = 0; t < 16; t++) {
            for (int k = 0; k < 8; k++) res = (res & 1) == 1 ? POLY ^ (res >> 1) : (res >> 1);
            crc32c_table2[t][i] = res;
        }
    }
    crc32c_table2_initialized = 1;
}

/* Compute CRC32C checksum. */
uint32_t crc32c_sw2(uint32_t crci, const void *buf, size_t len)
{
    const unsigned char *next = buf;
#ifdef __x86_64__
    uint64_t crc;
#else
    uint32_t crc;
#endif

    if(!crc32c_table2_initialized)
        crc32c_init_sw2();

    crc = crci ^ 0xffffffff;
#ifdef __x86_64__
    while (len && ((uintptr_t)next & 7) != 0)
    {
        crc = crc32c_table2[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        --len;
    }
    while (len >= 16)
    {
        crc ^= *(uint64_t *)next;
        uint64_t high = *(uint64_t *)(next + 8);
        crc = crc32c_table2[15][crc & 0xff]
            ^ crc32c_table2[14][(crc >> 8) & 0xff]
            ^ crc32c_table2[13][(crc >> 16) & 0xff]
            ^ crc32c_table2[12][(crc >> 24) & 0xff]
            ^ crc32c_table2[11][(crc >> 32) & 0xff]
            ^ crc32c_table2[10][(crc >> 40) & 0xff]
            ^ crc32c_table2[9][(crc >> 48) & 0xff]
            ^ crc32c_table2[8][crc >> 56]
            ^ crc32c_table2[7][high & 0xff]
            ^ crc32c_table2[6][(high >> 8) & 0xff]
            ^ crc32c_table2[5][(high >> 16) & 0xff]
            ^ crc32c_table2[4][(high >> 24) & 0xff]
            ^ crc32c_table2[3][(high >> 32) & 0xff]
            ^ crc32c_table2[2][(high >> 40) & 0xff]
            ^ crc32c_table2[1][(high >> 48) & 0xff]
            ^ crc32c_table2[0][high >> 56];
        next += 16;
        len -= 16;
    }
#else
    while (len && ((uintptr_t)next & 3) != 0)
    {
        crc = crc32c_table2[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        --len;
    }
    while (len >= 12)
    {
        crc ^= *(uint32_t *)next;
        uint32_t high = *(uint32_t *)(next + 4);
        uint32_t high2 = *(uint32_t *)(next + 8);
        crc = crc32c_table2[11][crc & 0xff]
            ^ crc32c_table2[10][(crc >> 8) & 0xff]
            ^ crc32c_table2[9][(crc >> 16) & 0xff]
            ^ crc32c_table2[8][crc >> 24]
            ^ crc32c_table2[7][high & 0xff]
            ^ crc32c_table2[6][(high >> 8) & 0xff]
            ^ crc32c_table2[5][(high >> 16) & 0xff]
            ^ crc32c_table2[4][high >> 24]
            ^ crc32c_table2[3][high2 & 0xff]
            ^ crc32c_table2[2][(high2 >> 8) & 0xff]
            ^ crc32c_table2[1][(high2 >> 16) & 0xff]
            ^ crc32c_table2[0][high2 >> 24];
        next += 12;
        len -= 12;
    }
#endif
    while (len)
    {
        crc = crc32c_table2[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        --len;
    }
    return (uint32_t)crc ^ 0xffffffff;
}


/******************************************************************************
 *                                                                            *
 *  Hardware Algorithm - SSE 4.2                                              *
 *                                                                            *
 ******************************************************************************/

/* Multiply a matrix times a vector over the Galois field of two elements,
   GF(2).  Each element is a bit in an unsigned integer.  mat must have at
   least as many entries as the power of two for most significant one bit in
   vec. */
static inline uint32_t gf2_matrix_times(uint32_t *mat, uint32_t vec)
{
    uint32_t sum;

    sum = 0;
    while (vec) {
        if (vec & 1)
            sum ^= *mat;
        vec >>= 1;
        mat++;
    }
    return sum;
}

/* Multiply a matrix by itself over GF(2).  Both mat and square must have 32
   rows. */
static inline void gf2_matrix_square(uint32_t *square, uint32_t *mat)
{
    int n;

    for (n = 0; n < 32; n++)
        square[n] = gf2_matrix_times(mat, mat[n]);
}

/* Construct an operator to apply len zeros to a crc.  len must be a power of
   two.  If len is not a power of two, then the result is the same as for the
   largest power of two less than len.  The result for len == 0 is the same as
   for len == 1.  A variant of this routine could be easily written for any
   len, but that is not needed for this application. */
static void crc32c_zeros_op(uint32_t *even, size_t len)
{
    int n;
    uint32_t row;
    uint32_t odd[32];           /* odd-power-of-two zeros operator */

    /* Put operator for one zero bit in odd. */
    odd[0] = POLY;              /* CRC32C polynomial */
    row = 1;
    for (n = 1; n < 32; n++) {
        odd[n] = row;
        row <<= 1;
    }

    /* Put operator for two zero bits in even. */
    gf2_matrix_square(even, odd);

    /* Put operator for four zero bits in odd. */
    gf2_matrix_square(odd, even);

    /* First square will put the operator for one zero byte (eight zero bits),
       in even -- next square puts operator for two zero bytes in odd, and so
       on, until len has been rotated down to zero. */
    do {
        gf2_matrix_square(even, odd);
        len >>= 1;
        if (len == 0)
            return;
        gf2_matrix_square(odd, even);
        len >>= 1;
    } while (len);

    /* Answer ended up in odd -- copy to even. */
    for (n = 0; n < 32; n++)
        even[n] = odd[n];
}

/* Take a length and build four lookup tables for applying the zeros operator
   for that length, byte-by-byte on the operand. */
static void crc32c_zeros(uint32_t zeros[][256], size_t len)
{
    uint32_t n;
    uint32_t op[32];

    crc32c_zeros_op(op, len);
    for (n = 0; n < 256; n++) {
        zeros[0][n] = gf2_matrix_times(op, n);
        zeros[1][n] = gf2_matrix_times(op, n << 8);
        zeros[2][n] = gf2_matrix_times(op, n << 16);
        zeros[3][n] = gf2_matrix_times(op, n << 24);
    }
}

/* Apply the zeros operator table to crc. */
static inline uint32_t crc32c_shift(uint32_t zeros[][256], uint32_t crc)
{
    return zeros[0][crc & 0xff] ^ zeros[1][(crc >> 8) & 0xff] ^
           zeros[2][(crc >> 16) & 0xff] ^ zeros[3][crc >> 24];
}

/* Block sizes for three-way parallel crc computation.  LONG and SHORT must
   both be powers of two.  The associated string constants must be set
   accordingly, for use in constructing the assembler instructions. */
#define LONG 8192
#define LONGx1 "8192"
#define LONGx2 "16384"
#define SHORT 256
#define SHORTx1 "256"
#define SHORTx2 "512"

/* Tables for hardware algorithm that shift a crc by LONG and SHORT zeros. */
static uint32_t crc32c_long[4][256];
static uint32_t crc32c_short[4][256];

/* Flag to indicate if crc32c_init_hw() has been called. */
static int crc32c_hw_initialized = 0;

/* Initialize tables for shifting crcs. */
static void crc32c_init_hw(void)
{
    crc32c_zeros(crc32c_long, LONG);
    crc32c_zeros(crc32c_short, SHORT);
    crc32c_hw_initialized = 1;
}

/* Compute CRC32C checksum. */
uint32_t crc32c_hw(uint32_t crc, const void *buf, size_t len)
{
    const unsigned char *next = buf;
    const unsigned char *end;
    uint64_t crc0, crc1, crc2;      /* need to be 64 bits for crc32q */

    /* Populate shift tables the first time through. */
    if (!crc32c_hw_initialized)
        crc32c_init_hw();

    /* Pre-process the crc. */
    crc0 = crc ^ 0xffffffff;

    /* Compute the crc for up to seven leading bytes to bring the data pointer
       to an eight-byte boundary. */
    while (len && ((uintptr_t)next & 7) != 0) {
        __asm__("crc32b\t" "(%1), %0"
                : "=r"(crc0)
                : "r"(next), "0"(crc0));
        next++;
        len--;
    }

    /* Compute the crc on sets of LONG*3 bytes, executing three independent crc
       instructions, each on LONG bytes -- this is optimized for the Nehalem,
       Westmere, Sandy Bridge, and Ivy Bridge architectures, which have a
       throughput of one crc per cycle, but a latency of three cycles. */
    while (len >= LONG*3) {
        crc1 = 0;
        crc2 = 0;
        end = next + LONG;
        do {
            __asm__("crc32q\t" "(%3), %0\n\t"
                    "crc32q\t" LONGx1 "(%3), %1\n\t"
                    "crc32q\t" LONGx2 "(%3), %2"
                    : "=r"(crc0), "=r"(crc1), "=r"(crc2)
                    : "r"(next), "0"(crc0), "1"(crc1), "2"(crc2));
            next += 8;
        } while (next < end);
        crc0 = crc32c_shift(crc32c_long, crc0) ^ crc1;
        crc0 = crc32c_shift(crc32c_long, crc0) ^ crc2;
        next += LONG*2;
        len -= LONG*3;
    }

    /* Do the same thing, but now on SHORT*3 blocks for the remaining data less
       than a LONG*3 block. */
    while (len >= SHORT*3) {
        crc1 = 0;
        crc2 = 0;
        end = next + SHORT;
        do {
            __asm__("crc32q\t" "(%3), %0\n\t"
                    "crc32q\t" SHORTx1 "(%3), %1\n\t"
                    "crc32q\t" SHORTx2 "(%3), %2"
                    : "=r"(crc0), "=r"(crc1), "=r"(crc2)
                    : "r"(next), "0"(crc0), "1"(crc1), "2"(crc2));
            next += 8;
        } while (next < end);
        crc0 = crc32c_shift(crc32c_short, crc0) ^ crc1;
        crc0 = crc32c_shift(crc32c_short, crc0) ^ crc2;
        next += SHORT*2;
        len -= SHORT*3;
    }

    /* Compute the crc on the remaining eight-byte units less than a SHORT*3
       block. */
    end = next + (len - (len & 7));
    while (next < end) {
        __asm__("crc32q\t" "(%1), %0"
                : "=r"(crc0)
                : "r"(next), "0"(crc0));
        next += 8;
    }
    len &= 7;

    /* Compute the crc for up to seven trailing bytes. */
    while (len) {
        __asm__("crc32b\t" "(%1), %0"
                : "=r"(crc0)
                : "r"(next), "0"(crc0));
        next++;
        len--;
    }

    /* Return a post-processed crc. */
    return (uint32_t)crc0 ^ 0xffffffff;
}


/******************************************************************************
 *                                                                            *
 *  Other Functions                                                           *
 *                                                                            *
 ******************************************************************************/

/* Variables to store information on hardware support. */
static int crc32c_hardware_support = 0;
static int crc32c_hardware_checked = 0;

/* Check for hardware support (SSE 4.2).  Note that this does not check for
   the existence of the cpuid instruction itself, which was introduced on the
   486SL in 1992, so this will fail on earlier x86 processors.  cpuid works
   on all Pentium and later processors. */
int crc32c_hw_support()
{
    if (!crc32c_hardware_checked) {
        do {
            uint32_t eax, ecx;
            eax = 1;
            __asm__("cpuid"
                    : "=c"(ecx)
                    : "a"(eax)
                    : "%ebx", "%edx");
            (crc32c_hardware_support) = (ecx >> 20) & 1;
        } while (0);
        crc32c_hardware_checked = 1;
    }
    return crc32c_hardware_support;
}

/* Disable hardware algorithm even if supported by hardware. */
void crc32c_hw_disable()
{
    crc32c_hardware_support = 0;
    crc32c_hardware_checked = 1;
}

/* Compute CRC32C checksum. Use hardware algorithm if supported,
   fall back on software algorithm otherwise. */
uint32_t crc32c(uint32_t crc, const void *buf, size_t len)
{
    return crc32c_hw_support() ? crc32c_hw(crc, buf, len) : crc32c_sw(crc, buf, len);
}
