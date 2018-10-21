#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


// Definition of operating system

#define OS_WIN       1

#define OS_TARGET OS_WIN

// Definition of compiler

#define COMPILER_GCC     2
#define COMPILER COMPILER_GCC

// Definition of the targeted architecture and basic data types
    
#define TARGET_x86          2
#define TARGET TARGET_x86
#define RADIX           32
#define LOG2RADIX       5
#ifndef digit_t
typedef unsigned int   digit_t0;        // Unsigned 32-bit digit
#endif

// Macro definitions

#define NBITS_TO_NBYTES(nbits)      (((nbits)+7)/8)                                          // Conversion macro from number of bits to number of bytes
#define NBITS_TO_NWORDS(nbits)      (((nbits)+(sizeof(digit_t)*8)-1)/(sizeof(digit_t)*8))    // Conversion macro from number of bits to number of computer words
#define NBYTES_TO_NWORDS(nbytes)    (((nbytes)+sizeof(digit_t)-1)/sizeof(digit_t))           // Conversion macro from number of bytes to number of computer words

// Macro to avoid compiler warnings when detecting unreferenced parameters
#define UNREFERENCED_PARAMETER(PAR) ((void)(PAR))

#define PASSED    0
#define FAILED    1

/********************** Constant-time unsigned comparisons ***********************/

// The following functions return 1 (TRUE) if condition is true, 0 (FALSE) otherwise

static __inline unsigned int is_digit_nonzero_ct(digit_t0 x)
{ // Is x != 0?
    return (unsigned int)((x | (0-x)) >> (RADIX-1));
}

static __inline unsigned int is_digit_zero_ct(digit_t0 x)
{ // Is x = 0?
    return (unsigned int)(1 ^ is_digit_nonzero_ct(x));
}

static __inline unsigned int is_digit_lessthan_ct(digit_t0 x, digit_t0 y)
{ // Is x < y?
    return (unsigned int)((x ^ ((x ^ y) | ((x - y) ^ y))) >> (RADIX-1)); 
}


/********************** Macros for platform-dependent operations **********************/

    
// Shift right with flexible datatype
#define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (DigitSize - (shift)));
    
// Shift left with flexible datatype
#define SHIFTL(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
    (shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> (DigitSize - (shift)));

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)                                                     \
    { uint64_t tempReg = (uint64_t)(multiplier) * (uint64_t)(multiplicand);                    \
    *(hi) = (digit_t)(tempReg >> RADIX);                                                          \
    (lo) = (digit_t)tempReg; }

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                         \
    { uint64_t tempReg = (uint64_t)(addend1) + (uint64_t)(addend2) + (uint64_t)(carryIn);     \
    (carryOut) = (digit_t)(tempReg >> RADIX);                                                     \
    (sumOut) = (digit_t)tempReg; }

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                             \
    { uint64_t tempReg = (uint64_t)(minuend) - (uint64_t)(subtrahend) - (uint64_t)(borrowIn); \
    (borrowOut) = (digit_t)(tempReg >> (sizeof(uint64_t)*8 - 1));                                \
    (differenceOut) = (digit_t)tempReg; }


#endif
