#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "dap_crypto_common.h"

// Extended datatype support

#if defined(GENERIC_IMPLEMENTATION)
    typedef uint64_t uint128_t[2];
#elif (TARGET == TARGET_AMD64 && OS_TARGET == OS_LINUX) && (COMPILER == COMPILER_GCC || COMPILER == COMPILER_CLANG)
    #define UINT128_SUPPORT
    typedef unsigned uint128_t __attribute__((mode(TI)));
#elif (TARGET == TARGET_ARM64 && OS_TARGET == OS_LINUX) && (COMPILER == COMPILER_GCC || COMPILER == COMPILER_CLANG)
    #define UINT128_SUPPORT
    typedef unsigned uint128_t __attribute__((mode(TI)));
#elif (TARGET == TARGET_AMD64) && (OS_TARGET == OS_WIN && COMPILER == COMPILER_VC)
    #define SCALAR_INTRIN_SUPPORT
    typedef uint64_t uint128_t[2];
#elif (TARGET == TARGET_AMD64 && OS_TARGET == OS_WIN && COMPILER == COMPILER_GCC)
    typedef uint64_t uint128_t[2];
#else
    #error -- "Unsupported configuration"
#endif

// Macro definitions

#define NBITS_TO_NBYTES(nbits)      (((nbits)+7)/8)                                          // Conversion macro from number of bits to number of bytes
#define NBITS_TO_NWORDS(nbits)      (((nbits)+(sizeof(digit_t)*8)-1)/(sizeof(digit_t)*8))    // Conversion macro from number of bits to number of computer words
#define NBYTES_TO_NWORDS(nbytes)    (((nbytes)+sizeof(digit_t)-1)/sizeof(digit_t))           // Conversion macro from number of bytes to number of computer words

// Macro to avoid compiler warnings when detecting unreferenced parameters
#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(PAR) ((void)(PAR))
#endif

#define PASSED_DEFEO    0
#define FAILED_DEFEO  1

/********************** Constant-time unsigned comparisons ***********************/

// The following functions return 1 (TRUE) if condition is true, 0 (FALSE) otherwise

static __inline unsigned int is_digit_nonzero_ct(digit_t x)
{ // Is x != 0?
    return (unsigned int)((x | (0-x)) >> (RADIX-1));
}

static __inline unsigned int is_digit_zero_ct(digit_t x)
{ // Is x = 0?
    return (unsigned int)(1 ^ is_digit_nonzero_ct(x));
}

static __inline unsigned int is_digit_lessthan_ct(digit_t x, digit_t y)
{ // Is x < y?
    return (unsigned int)((x ^ ((x ^ y) | ((x - y) ^ y))) >> (RADIX-1));
}


/********************** Macros for platform-dependent operations **********************/

#if ((COMPILER == COMPILER_GCC && OS_TARGET == OS_WIN) || defined(GENERIC_IMPLEMENTATION) )

    // Digit multiplication
    #define MUL(multiplier, multiplicand, hi, lo)                                                     \
        digit_x_digit((multiplier), (multiplicand), &(lo));

    // Digit addition with carry
    #define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                         \
        { digit_t tempReg = (addend1) + (digit_t)(carryIn);                                           \
        (sumOut) = (addend2) + tempReg;                                                               \
        (carryOut) = (is_digit_lessthan_ct(tempReg, (digit_t)(carryIn)) | is_digit_lessthan_ct((sumOut), tempReg)); }

    // Digit subtraction with borrow
    #define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                             \
        { digit_t tempReg = (minuend) - (subtrahend);                                                 \
        unsigned int borrowReg = (is_digit_lessthan_ct((minuend), (subtrahend)) | ((borrowIn) & is_digit_zero_ct(tempReg)));  \
        (differenceOut) = tempReg - (digit_t)(borrowIn);                                              \
        (borrowOut) = borrowReg; }

    // Shift right with flexible datatype
    #define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
        (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (DigitSize - (shift)));

    // Shift left with flexible datatype
    #define SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
        (shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> (DigitSize - (shift)));

    // 64x64-bit multiplication
    #define MUL128(multiplier, multiplicand, product)                                                 \
        mp_mul751((digit_t*)&(multiplier), (digit_t*)&(multiplicand), (digit_t*)&(product), NWORDS_FIELD/2);

    // 128-bit addition, inputs < 2^127
    #define ADD128(addend1, addend2, addition)                                                        \
        mp_addd((digit_t*)(addend1), (digit_t*)(addend2), (digit_t*)(addition), NWORDS_FIELD);

    // 128-bit addition with output carry
    #define ADC128(addend1, addend2, carry, addition)                                                 \
        (carry) = mp_addd((digit_t*)(addend1), (digit_t*)(addend2), (digit_t*)(addition), NWORDS_FIELD);

#elif (TARGET == TARGET_AMD64 && COMPILER == COMPILER_VC)

    // Digit multiplication
    #define MUL(multiplier, multiplicand, hi, lo)                                                     \
        (lo) = _umul128((multiplier), (multiplicand), (hi));

    // Digit addition with carry
    #define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                         \
        (carryOut) = _addcarry_u64((carryIn), (addend1), (addend2), &(sumOut));

    // Digit subtraction with borrow
    #define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                             \
        (borrowOut) = _subborrow_u64((borrowIn), (minuend), (subtrahend), &(differenceOut));

    // Digit shift right
    #define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
        (shiftOut) = __shiftright128((lowIn), (highIn), (shift));

    // Digit shift left
    #define SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
        (shiftOut) = __shiftleft128((lowIn), (highIn), (shift));

    // 64x64-bit multiplication
    #define MUL128(multiplier, multiplicand, product)                                                 \
        (product)[0] = _umul128((multiplier), (multiplicand), &(product)[1]);

    // 128-bit addition, inputs < 2^127
    #define ADD128(addend1, addend2, addition)                                                        \
        { unsigned char carry = _addcarry_u64(0, (addend1)[0], (addend2)[0], &(addition)[0]);         \
        _addcarry_u64(carry, (addend1)[1], (addend2)[1], &(addition)[1]); }

    // 128-bit addition with output carry
    #define ADC128(addend1, addend2, carry, addition)                                                 \
        (carry) = _addcarry_u64(0, (addend1)[0], (addend2)[0], &(addition)[0]);                       \
        (carry) = _addcarry_u64((carry), (addend1)[1], (addend2)[1], &(addition)[1]);

    // 128-bit subtraction, subtrahend < 2^127
    #define SUB128(minuend, subtrahend, difference)                                                   \
        { unsigned char borrow = _subborrow_u64(0, (minuend)[0], (subtrahend)[0], &(difference)[0]);  \
        _subborrow_u64(borrow, (minuend)[1], (subtrahend)[1], &(difference)[1]); }

    // 128-bit right shift, max. shift value is 64
    #define SHIFTR128(Input, shift, shiftOut)                                                         \
        (shiftOut)[0]  = __shiftright128((Input)[0], (Input)[1], (shift));                            \
        (shiftOut)[1] = (Input)[1] >> (shift);

    // 128-bit left shift, max. shift value is 64
    #define SHIFTL128(Input, shift, shiftOut)                                                         \
        (shiftOut)[1]  = __shiftleft128((Input)[0], (Input)[1], (shift));                             \
        (shiftOut)[0] = (Input)[0] << (shift);

    #define MULADD128(multiplier, multiplicand, addend, carry, result);    \
        { uint128_t product;                                               \
          MUL128(multiplier, multiplicand, product);                       \
          ADC128(addend, product, carry, result); }

#elif ((TARGET == TARGET_AMD64 || TARGET == TARGET_ARM64) && OS_TARGET == OS_LINUX )

    // Digit multiplication
    #define MUL(multiplier, multiplicand, hi, lo)                                                     \
        { uint128_t tempReg = (uint128_t)(multiplier) * (uint128_t)(multiplicand);                    \
        *(hi) = (digit_t)(tempReg >> RADIX);                                                          \
        (lo) = (digit_t)tempReg; }

    // Digit addition with carry
    #define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                         \
        { uint128_t tempReg = (uint128_t)(addend1) + (uint128_t)(addend2) + (uint128_t)(carryIn);     \
        (carryOut) = (digit_t)(tempReg >> RADIX);                                                     \
        (sumOut) = (digit_t)tempReg; }

    // Digit subtraction with borrow
    #define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                             \
        { uint128_t tempReg = (uint128_t)(minuend) - (uint128_t)(subtrahend) - (uint128_t)(borrowIn); \
        (borrowOut) = (digit_t)(tempReg >> (sizeof(uint128_t)*8 - 1));                                \
        (differenceOut) = (digit_t)tempReg; }

    // Digit shift right
    #define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
        (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (RADIX - (shift)));

    // Digit shift left
    #define SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
        (shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> (RADIX - (shift)));

#endif

#endif
