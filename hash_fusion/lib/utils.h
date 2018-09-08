#ifndef __UTILS_H__
#define __UTILS_H__

/*******************************************************************************
   utils.h

   Utilities header

   Author: brian.monahan@hpe.com
      
   (c) Copyright 2017 Hewlett Packard Enterprise Development LP 

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are
   met: 

   1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer. 

   2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution. 

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
   TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
   PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
*******************************************************************************/
#include "options.h"  // Various application specific options
#include <string.h>   // Memory functions e.g. memset
#include <stdarg.h>   // Variadic args ...
#include <stdint.h>   // Standard int sizes (C99)


/*******************************************************************************
   Enabling/disabling standard checks

   - The checks (i.e. req_..., needs_...) are described later (see below)

   - Useful for testing/ensuring correct behaviour.

   - They can all be enabled/disabled.

   - Because they may not be enabled, any essential checks must be made explicit.

*******************************************************************************/
// Comment out the following line to enable requires checking i.e. req_...
//#define SUPPRESS_REQUIRES_CHECKING

// Comment out the following line to enable needs checking i,e, needs_...
//#define SUPPRESS_NEEDS_CHECKING


/*******************************************************************************
   Standard sizes
*******************************************************************************/
// standard file block size = 4k / 8k
//#define BLOCKSIZE     (4 * 1024)
#define BLOCKSIZE     (8 * 1024)

// message/string buffer size
#define MSG_BUFSIZE   (4 * LINE_BUFSIZE)

// maximum line length
#define LINE_BUFSIZE  STD_BUFSIZE
#define TEXT_BUFSIZE  STD_BUFSIZE

// Standard buffer size
#define STD_BUFSIZE  1024

// DEBUG_LIMIT defines the maximum number of debug messages output
// - useful for catching rogue loops
//#define DEBUG_LIMIT 1000   //default
#define DEBUG_LIMIT 1000


/*******************************************************************************
   Simple types: Bytes, Tags, Pointers, Keys and Booleans

   Keys are encoded as opaque values e.g. unsigned long.

*******************************************************************************/
//typedef unsigned char     Byte_t;
typedef uint_fast8_t        Byte_t;     // Fastest implementation of 8-bit unsigned integers (C99) - typically it's unsigned char.
typedef Byte_t              Boolean_t;  // Boolean type


/*******************************************************************************
   Opaque types: Pointers, Keys, Positions and Objects

   Pointers, Keys, Positions and Objects are encoded as opaque values e.g. unsigned long.

*******************************************************************************/
typedef unsigned long       Opaque_t;   // Standard opaque type
typedef Opaque_t            Ptr_t;      // Opque pointer handles (useful for debugging/printing).
typedef Opaque_t            Key_t;      // Opaque key handles.
typedef Opaque_t            Posn_t;     // Opaque position handles.
typedef Opaque_t            Object_t;   // Opaque object pointer handles.

#define NULL_VAL            0           // Null opaque value


/*******************************************************************************
   Tagged types

	Tag values are byte sized (i.e. 256 possible tag values)

	- Typically used to discriminate data structure variants.
	  e.g. struct treeNode {
		        Tag_t   : tag;
		        ...
		        ...
		    };

*******************************************************************************/
typedef Byte_t              Tag_t;

// tag value operators - requires tag field to be first byte of object/structure.
#define checkTag(objPtr, tagValue)    (tagOf(objPtr) == (tagValue))
#define tagOf(objPtr)                 (*((Tag_t *)objPtr))


/*******************************************************************************
   Misc. operators/constants
*******************************************************************************/
// Standardised Boolean_t values
// - Only standardised boolean values can be compared for equality.
#define TRUE      1
#define FALSE     0

// Some Boolean synonyms
#define YES  TRUE
#define NO   FALSE

#define DO   TRUE
#define DONT FALSE


// makes general value into a standardised Boolean_t value
#define asBoolean(x)          ((x) ? TRUE : FALSE)
#define showBoolean(x)        ((x) ? "TRUE" : "FALSE")

// Negation
#define not(x)                ((x) ? FALSE : TRUE)

// Max and min macros
#define max(a,b)              ((a) > (b) ? (a) : (b))
#define min(a,b)              ((a) < (b) ? (a) : (b))
#define minmax(lo, val, hi)   ((val) < (lo) ? (lo) : ((hi) < (val) ? (hi) : (val)))

// General int powers for exp >= 0;
// - result = 0 if base = 0
long power(int base, int exp);

// Powers of 2
// pow2 : int->int
#define pow2(x)      ((1 << (x)))


/*******************************************************************************
   Function types

*******************************************************************************/
// Thunks - Pure function closures with no args and no results (i.e side-effects).
typedef void (*Thunk_t)();

// Void functions
// - Typically used as type for "finaliser" or "dealloc" functions (e.g. free)
typedef void (*VoidFn_t)(void * obj);

// Predicate functions (single argument)
typedef Boolean_t (*PredFn_t)(void *obj);

// Show functions (single argument)
typedef char *(*ShowFn_t)(void *obj);


/*******************************************************************************
   Printing NULL

*******************************************************************************/
// This denotes a NULL value in output
#define NULL_STR  "??"


/*******************************************************************************
   Linear Comparisons
*******************************************************************************/
// Comparison datatype
// - in C, enum types are indistinguishable from int
// - In this case, safer in practice to follow established convention.
typedef int Comparison_t;

// Standard comparison values
#define LT   -1   // a < b
#define EQ    0   // a == b
#define GT    1   // a > b

// Comparison functions over "keys" ...
// - this is either direct comparisons with basic types (e.g. integers) or indirect comparisons with
// - This implements the "compare" protocol:
//      LT   if (a less than b);
//      EQ   if (a equals b);
//      GT   if (a greater than b)
typedef Comparison_t (*CompareFn_t)(Key_t a, Key_t b);

// Simple conversion to conversion
#define asComparison(v)    ((v) < 0 ? LT : (v) == 0 ? EQ : GT)


/*******************************************************************************
   Numeric comparison functions
   - This makes sense for both signed and unsigned values
*******************************************************************************/
// Comparison result
Comparison_t cmp_char(char a, char b);
Comparison_t cmp_byte(Byte_t a, Byte_t b);

Comparison_t cmp_key(Key_t a, Key_t b);    // treats keys like pure unsigned long
Comparison_t cmp_posn(Posn_t a, Posn_t b); // treats positions like pure unsigned long

Comparison_t cmp_int(int a, int b);
Comparison_t cmp_long(long a, long b);

Comparison_t cmp_uint(int a, int b);
Comparison_t cmp_ulong(long a, long b);

Comparison_t cmp_float(float a, float b);
Comparison_t cmp_double(double a, double b);

Comparison_t cmp_string(char *a, char *b);


// Simple CMP macro - Comparison_tgr
// - Beware, this evaluates/expands arguments _twice_
//   This is fine if args are variables/literals, but not side-effecting expressions.
#define CMP(a, b)   ((a) < (b) ? LT : (a) == (b) ? EQ : GT)


/*******************************************************************************
   Key-based maximum and minimum
*******************************************************************************/
Key_t keyMax(CompareFn_t keyFn, Key_t keyA, Key_t keyB);
Key_t keyMin(CompareFn_t keyFn, Key_t keyA, Key_t keyB);


/*******************************************************************************
   Position-based maximum and minimum
*******************************************************************************/
Posn_t posnMax(CompareFn_t posnFn, Posn_t posnA, Posn_t posnB);
Posn_t posnMin(CompareFn_t posnFn, Posn_t posnA, Posn_t posnB);


/*******************************************************************************
   Key amd position values

   - These are typically opaque objects such as integers/longs or strings (i.e. pointers to char)
     or pointers to some key data object.

   - The NULL_KEY and NULL_POSN value (i.e. 0) is specified as a "default" value (with application-specific semantics).
     This value may or may not be meaningful.  It can legitimately be used as a standard key or position value or
     alternatively, as a "void", "invalid" or "non-key" value.  Exactly how it is treated is considered
     to be implementation specific/application defined.

   - When keys and positions are simple integers/longs, then we assume that
     keys and positions are strictly positive and linearly ordered by <.

   - Otherwise, a key/position comparison function is required that implements a
     linear less-than comparison ordering, using the compare protocol (see above)

   - Equal keys are typically specified exactly (as ==) - but can be used .

*******************************************************************************/
// The NULL_KEY and NULL_POSN values denotes a "default" key value.
#define NULL_KEY   ZERO_VAL
#define NULL_POSN  ZERO_VAL

// Default opaque literal value
#define ZERO_VAL   0


/*******************************************************************************
   Primitive memory allocation and nullify object
   - guaranteed zeroed allocation
*******************************************************************************/
//#define MEMALLOC(a, b)        (malloc((a) * (b)))
#define MEMALLOC(a, b)        (calloc((a), (b)))
#define ALLOC_STR(len)        ((char *)MEMALLOC((len)+1, 1))
#define ALLOC_BLK(sz)         ((void *)MEMALLOC((sz), 1))

#define ALLOC_OBJ(T)          ((T *)MEMALLOC(1, sizeof(T)))
#define ALLOC_ARR(dim, T)     ((T *)MEMALLOC((dim), sizeof(T)))

// Nullify macros - obj is a pointer to object to be nullified, T is the structure type.
#define NULLIFY_OBJ(obj, T)   { if ((obj) != NULL) memset((obj), 0x00, sizeof(T)); }
#define NULLIFY(obj, sz)      { memset((obj), 0x00, (sz)); }

// realloc considered unreliable ... (data corruption ??) ...
//#define REALLOC_BLK(ptr, sz)  ((void *)realloc((ptr), (sz)))
//#define REALLOC_OBJ(ptr, T)   ((T *)realloc((ptr), sizeof(T)))


/*******************************************************************************
   Fast multiply for byte values
*******************************************************************************/
// Fast Byte Multiply
//Byte_t byteMultiplyTable[256 * 256];
//void setupByteMultiply();      // Initialises byteMultiplyTable.
//void gen_ByteMultiplyTable();  // Generates a C source file for byteMultiplyTable.

//#define byteMult(x, y)     (byteMultiplyTable[(((Byte_t) x)<<8) | ((Byte_t)y)])


/*******************************************************************************
   Timing functions
*******************************************************************************/
double timeFunction(int repeat, Thunk_t runFun);

// Run each runFun repeatedly, returning total time taken ...
// Only the run function runFun is timed ...
// The setupFun is performed on each loop - and is not timed ...
double timeFunction2(int repeat, Thunk_t setupFun, Thunk_t runFun);


/*******************************************************************************
   Null functions
*******************************************************************************/
// The null thunk closure
void nullThunk ();

// The null VoidFn that does nothing at all.
void nullVoidFn(void *obj);


/*******************************************************************************
   Hex data printing ...
*******************************************************************************/
// prints hex bytes to stdout
void printHexBytes(Byte_t *bytes, int len);

// prints hex dump of data to stdout
void hexdump(void *data, int size, int width);


/******************************************************************************
  Basic string processing
  - generally update-in-place
******************************************************************************/
void toLowerCase(char *text);
void toUpperCase(char *text);

// Trims string
void rightTrim(char *text);  // Removes space chars from the end.
char *leftTrim(char *text);  // Returns left-trimmed string (no update to text made).
char *trim(char *text);      // Returns left-right-trimmed string (may be shorter).

/*******************************************************************************
   Reading and writing files ...
*******************************************************************************/
size_t readFile(const char *filename, Byte_t *blocks[], int maxBlocks);
void writeFile(const char *destFilename, int numChars, Byte_t *blocks[], int maxBlocks);


/*******************************************************************************
   Error messages

   The pattern of use is:

      diagnostic(fmt, v1, v2, v3, ...);
      error_exit();

   or, with a coding error i.e. the "impossible" case:

      diagnostic(fmt, v1, v2, v3, ...);
      codeError_exit();


   Note:  Question: Why is the diagnostic function not an exiting function?

          Answer:  It would have been nice to efficiently wrap everything into a
          single call like this:

               void errorFn(const char *fmt, ...);

          and used like this:

               errorFn(fmt, v1, v2, v3, ...);

          But then it would be necessary to explicitly include __FILE__ and __LINE__
          variables literally in code to obtain information.   To avoid this
          clumbsiness, the error_exit() and codeError_exit() macros are defined
          instead to wrap-up the usage of __FILE__ and __LINE__ to simplify their
          usage.


*******************************************************************************/

// This sets the error message to be issued at exit ...
void diagnostic(const char *fmt, ...);

//These macros provide error exits that display error messages defined by "diagnostic"
#define error_exit()       { __ERROR(); exit(1); }
#define codeError_exit()   { __CODE_ERROR(__FILE__, __LINE__); exit(1); }

void __ERROR();
void __CODE_ERROR(char *fileName, int lineNum);


/*******************************************************************************
   Debugging print statement  ...
   - Enable per file debugging by including "debug.h"
   - To enable, the variable debugOn must also be set to TRUE.
*******************************************************************************/

#ifndef __DEBUG_H__

   #undef debug
   #undef xdebug

   #undef DEBUG_CODE
   #undef XDEBUG_CODE

   #define debug        __XDEBUG
   #define xdebug       __XDEBUG

   #ifndef DEBUG_LIMIT
      #define DEBUG_LIMIT 1000
   #endif

#endif

Boolean_t debugOn;

// Useful position markers ... (these are string values)
#define POSN          (__POSITION(__FILE__ , __LINE__))
#define LINE_POSN     (__POSITION(NULL ,     __LINE__))
#define FILE_POSN     (__POSITION(__FILE__ , -1))

char *__POSITION(char *filename, int linenumber);

void __DEBUG(const char *fmt, ...);
void __XDEBUG(const char *fmt, ...);


/*******************************************************************************
   Asserts ...
*******************************************************************************/

#define ASSERT(msg, expr)    { __ASSERT((msg), (expr), __FILE__, __LINE__, TRUE); }   // exiting
#define WARN(msg, expr)      { __ASSERT((msg), (expr), __FILE__, __LINE__, FALSE); }  // non-exiting

#define XASSERT(msg, expr)   {}
#define XWARN(msg, expr)     {}

#undef NDEBUG // enable standard asserts ...

// always permit standard asserts
#include <assert.h>


/*******************************************************************************
   Standard conditions and checks
   - these are always evaluated
*******************************************************************************/
#define isa_Null(ptr)                  ((ptr) == NULL)
#define isa_NonNull(ptr)               ((ptr) != NULL)

#define isa_Same(ptr1, ptr2)                  ((ptr1) == (ptr2))
#define isa_Distinct(ptr1, ptr2)              ((ptr1) != (ptr2))
#define isa_DistinctIfNonNull(ptr1, ptr2)     ((ptr1) == NULL || (ptr2) == NULL || (ptr1) != (ptr2))

#define isa_EmptyStr(str)              ((str) == NULL || strlen(str) == 0)
#define isa_NonEmptyStr(str)           ((str) != NULL && strlen(str) > 0)

#define isa_Pos(i)                     ((i) > 0)
#define isa_Neg(i)                     ((i) < 0)

#define isa_PosZero(i)                 ((i) >= 0)
#define isa_NegZero(i)                 ((i) <= 0)

#define isa_Zero(i)                    ((i) == 0)
#define isa_NonZero(i)                 ((i) != 0)

#define is_EQ(i, j)                    ((i) == (j))
#define is_NEQ(i, j)                   ((i) != (j))

#define is_LT(i, j)                    ((i) < (j))
#define is_LE(i, j)                    ((i) <= (j))

#define is_NLT(i, j)                   ((i) >= (j))
#define is_NLE(i, j)                   ((i) >  (j))

#define is_GT(i, j)                    ((i) > (j))
#define is_GE(i, j)                    ((i) >= (j))

#define is_NGT(i, j)                   ((i) <= (j))
#define is_NGE(i, j)                   ((i) < (j))


/*******************************************************************************
   Standard pre-condition guards

   - There are several standard kind of check supported:

     -  req_...          =  "requires ..." check       (standard message,       exits on failure, suppressable).
     -  needs_...        =  "needs ..." check          (user-specified message, exits on failure, suppressable).
     -  ensure_...       =  "ensures ..." check.       (user-specified message, exits on failure, not suppressable).
     -  warn_if_not_...  =  "warn if not ..." check.   (user-specified message, does not exit   , not suppressable).

*******************************************************************************/
#ifdef SUPPRESS_REQUIRES_CHECKING

	#define req_Null(ptr)                {}
	#define req_NonNull(ptr)             {}

	#define req_Same(ptr1, ptr2)                {}
	#define req_Distinct(ptr1, ptr2)            {}
	#define req_DistinctIfNonNull(ptr1, ptr2)   {}

	#define req_EmptyStr(str)            {}
	#define req_NonEmptyStr(str)         {}

	#define req_Pos(i)                   {}
	#define req_Neg(i)                   {}

	#define req_PosZero(i)               {}
	#define req_NegZero(i)               {}

	#define req_Zero(i)                  {}
	#define req_NonZero(i)               {}

	#define req_EQ(i, j)                 {}
	#define req_NEQ(i, j)                {}

	#define req_LT(i, j)                 {}
	#define req_LE(i, j)                 {}

	#define req_NLT(i, j)                {}
	#define req_NLE(i, j)                {}

	#define req_GT(i, j)                 {}
	#define req_GE(i, j)                 {}

	#define req_NGT(i, j)                {}
	#define req_NGE(i, j)                {}

#else

	#define req_Null(ptr)                { needs_Null("Requires null pointer", (ptr)); }
	#define req_NonNull(ptr)             { needs_NonNull("Requires non-null pointer", (ptr)); }

	#define req_Same(ptr1, ptr2)                { needs_Same("Requires same pointer", (ptr1), (ptr2)); }
	#define req_Distinct(ptr1, ptr2)            { needs_Distinct("Requires distinct pointers", (ptr1), (ptr2)); }
	#define req_DistinctIfNonNull(ptr1, ptr2)   { needs_DistinctIfNonNull("Requires distinct pointers when non-null", (ptr1), (ptr2)); }

	#define req_EmptyStr(str)            { needs_EmptyStr("Requires empty string", (str)); }
	#define req_NonEmptyStr(str)         { needs_NonEmptyStr("Requires non-empty string",  (str)); }

	#define req_Pos(i)                   { needs_Pos("Requires positive number", (i)); }
	#define req_Neg(i)                   { needs_Neg("Requires negative number", (i)); }

	#define req_PosZero(i)               { needs_PosZero("Requires positive or zero number", (i)); }
	#define req_NegZero(i)               { needs_NegZero("Requires negative or zero number", (i)); }

	#define req_Zero(i)                  { needs_Zero("Requires zero number", (i)); }
	#define req_NonZero(i)               { needs_NonZero("Requires non-zero number", (i)); }

	#define req_EQ(i, j)                 { needs_EQ("Requires equal numbers", (i), (j)); }
	#define req_NEQ(i, j)                { needs_NEQ("Requires unequal numbers", (i), (j)); }

	#define req_LT(i, j)                 { needs_LT("Requires less than (e.g. i < j)", (i), (j)); }
	#define req_LE(i, j)                 { needs_LE("Requires less than or equal (e.g. i <= j)", (i), (j)); }

	#define req_NLT(i, j)                { needs_NLT("Requires not less than  (e.g. not i <= j)", (i), (j)); }
	#define req_NLE(i, j)                { needs_NLE("Requires not less than or equal (e.g. not i <= j)", (i), (j)); }

	#define req_GT(i, j)                 { needs_GT("Requires greater than  (e.g. i > j)", (i), (j)); }
	#define req_GE(i, j)                 { needs_GE("Requires greater than or equal (e.g. i >= j)", (i), (j)); }

	#define req_NGT(i, j)                { needs_NGT("Requires not greater than (e.g. not i > j)", (i), (j)); }
	#define req_NGE(i, j)                { needs_NGE("Requires not greater than or equal (e.g. not i >= j)", (i), (j)); }

#endif

#ifdef SUPPRESS_NEEDS_CHECKING

	#define needs_Null(msg, ptr)               {}
	#define needs_NonNull(msg, ptr)            {}

	#define needs_Same(msg, ptr1, ptr2)               {}
	#define needs_Distinct(msg, ptr1, ptr2)           {}
	#define needs_DistinctIfNonNull(msg, ptr1, ptr2)  {}

	#define needs_EmptyStr(msg, str)           {}
	#define needs_NonEmptyStr(msg, str)        {}

	#define needs_Pos(msg, i)                  {}
	#define needs_Neg(msg, i)                  {}

	#define needs_PosZero(msg, i)              {}
	#define needs_NegZero(msg, i)              {}

	#define needs_Zero(msg, i)                 {}
	#define needs_NonZero(msg, i)              {}

	#define needs_EQ(msg, i, j)                {}
	#define needs_NEQ(msg, i, j)               {}

	#define needs_LT(msg, i, j)                {}
	#define needs_LE(msg, i, j)                {}

	#define needs_NLT(msg, i, j)               {}
	#define needs_NLE(msg, i, j)               {}

	#define needs_GT(msg, i, j)                {}
	#define needs_GE(msg, i, j)                {}

	#define needs_NGT(msg, i, j)               {}
	#define needs_NGE(msg, i, j)               {}

#else

	#define needs_Null(msg, ptr)               { __REQUIRES(msg, isa_Null(ptr), __FILE__, __LINE__); }
	#define needs_NonNull(msg, ptr)            { __REQUIRES(msg, isa_NonNull(ptr), __FILE__, __LINE__); }

	#define needs_Same(msg, ptr1, ptr2)               { __REQUIRES(msg, isa_Same(ptr1, ptr2), __FILE__, __LINE__); }
	#define needs_Distinct(msg, ptr1, ptr2)           { __REQUIRES(msg, isa_Distinct(ptr1, ptr2), __FILE__, __LINE__); }
	#define needs_DistinctIfNonNull(msg, ptr1, ptr2)  { __REQUIRES(msg, isa_DistinctIfNonNull(ptr1, ptr2), __FILE__, __LINE__); }

	#define needs_EmptyStr(msg, str)           { __REQUIRES(msg, isa_EmptyStr(str), __FILE__, __LINE__); }
	#define needs_NonEmptyStr(msg, str)        { __REQUIRES(msg, isa_NonEmptyStr(str), __FILE__, __LINE__); }

	#define needs_Pos(msg, i)                  { __REQUIRES(msg, isa_Pos(i), __FILE__, __LINE__); }
	#define needs_Neg(msg, i)                  { __REQUIRES(msg, isa_Neg(i), __FILE__, __LINE__); }

	#define needs_PosZero(msg, i)              { __REQUIRES(msg, isa_PosZero(i), __FILE__, __LINE__); }
	#define needs_NegZero(msg, i)              { __REQUIRES(msg, isa_NegZero(i), __FILE__, __LINE__); }

	#define needs_Zero(msg, i)                 { __REQUIRES(msg, isa_Zero(i), __FILE__, __LINE__); }
	#define needs_NonZero(msg, i)              { __REQUIRES(msg, isa_NonZero(i), __FILE__, __LINE__); }

	#define needs_EQ(msg, i, j)                { __REQUIRES(msg, is_EQ(i, j), __FILE__, __LINE__); }
	#define needs_NEQ(msg, i, j)               { __REQUIRES(msg, is_NEQ(i, j), __FILE__, __LINE__); }

	#define needs_LT(msg, i, j)                { __REQUIRES(msg, is_LT(i, j), __FILE__, __LINE__); }
	#define needs_LE(msg, i, j)                { __REQUIRES(msg, is_LE(i, j), __FILE__, __LINE__); }

	#define needs_NLT(msg, i, j)               { __REQUIRES(msg, is_NLT(i, j), __FILE__, __LINE__); }
	#define needs_NLE(msg, i, j)               { __REQUIRES(msg, is_NLE(i, j), __FILE__, __LINE__); }

	#define needs_GT(msg, i, j)                { __REQUIRES(msg, is_GT(i, j), __FILE__, __LINE__); }
	#define needs_GE(msg, i, j)                { __REQUIRES(msg, is_GE(i, j), __FILE__, __LINE__); }

	#define needs_NGT(msg, i, j)               { __REQUIRES(msg, is_NGT(i, j), __FILE__, __LINE__); }
	#define needs_NGE(msg, i, j)               { __REQUIRES(msg, is_NGE(i, j), __FILE__, __LINE__); }

#endif

// ensure checks
#define ensure_Null(msg, ptr)               { __REQUIRES(msg, isa_Null(ptr), __FILE__, __LINE__); }
#define ensure_NonNull(msg, ptr)            { __REQUIRES(msg, isa_NonNull(ptr), __FILE__, __LINE__); }

#define ensure_Same(msg, ptr1, ptr2)               { __REQUIRES(msg, isa_Same(ptr1, ptr2), __FILE__, __LINE__); }
#define ensure_Distinct(msg, ptr1, ptr2)           { __REQUIRES(msg, isa_Distinct(ptr1, ptr2), __FILE__, __LINE__); }
#define ensure_DistinctIfNonNull(msg, ptr1, ptr2)  { __REQUIRES(msg, isa_DistinctIfNonNull(ptr1, ptr2), __FILE__, __LINE__); }

#define ensure_EmptyStr(msg, str)           { __REQUIRES(msg, isa_EmptyStr(str), __FILE__, __LINE__); }
#define ensure_NonEmptyStr(msg, str)        { __REQUIRES(msg, isa_NonEmptyStr(str), __FILE__, __LINE__); }

#define ensure_Pos(msg, i)                  { __REQUIRES(msg, isa_Pos(i), __FILE__, __LINE__); }
#define ensure_Neg(msg, i)                  { __REQUIRES(msg, isa_Neg(i), __FILE__, __LINE__); }

#define ensure_PosZero(msg, i)              { __REQUIRES(msg, isa_PosZero(i), __FILE__, __LINE__); }
#define ensure_NegZero(msg, i)              { __REQUIRES(msg, isa_NegZero(i), __FILE__, __LINE__); }

#define ensure_Zero(msg, i)                 { __REQUIRES(msg, isa_Zero(i), __FILE__, __LINE__); }
#define ensure_NonZero(msg, i)              { __REQUIRES(msg, isa_NonZero(i), __FILE__, __LINE__); }

#define ensure_EQ(msg, i, j)                { __REQUIRES(msg, is_EQ(i, j), __FILE__, __LINE__); }
#define ensure_NEQ(msg, i, j)               { __REQUIRES(msg, is_NEQ(i, j), __FILE__, __LINE__); }

#define ensure_LT(msg, i, j)                { __REQUIRES(msg, is_LT(i, j), __FILE__, __LINE__); }
#define ensure_LE(msg, i, j)                { __REQUIRES(msg, is_LE(i, j), __FILE__, __LINE__); }

#define ensure_NLT(msg, i, j)               { __REQUIRES(msg, is_NLT(i, j), __FILE__, __LINE__); }
#define ensure_NLE(msg, i, j)               { __REQUIRES(msg, is_NLE(i, j), __FILE__, __LINE__); }

#define ensure_GT(msg, i, j)                { __REQUIRES(msg, is_GT(i, j), __FILE__, __LINE__); }
#define ensure_GE(msg, i, j)                { __REQUIRES(msg, is_GE(i, j), __FILE__, __LINE__); }

#define ensure_NGT(msg, i, j)               { __REQUIRES(msg, is_NGT(i, j), __FILE__, __LINE__); }
#define ensure_NGE(msg, i, j)               { __REQUIRES(msg, is_NGE(i, j), __FILE__, __LINE__); }

#define ensure(msg, pred)                   { __REQUIRES(msg, (pred),  __FILE__, __LINE__); }
#define ensure_not(msg, pred)               { __REQUIRES(msg, (!(pred)), __FILE__, __LINE__); }

// WARNING checks
#define warn_if_not_Null(msg, ptr)               { __WARN_IF_NOT(msg, isa_Null(ptr), __FILE__, __LINE__); }
#define warn_if_not_NonNull(msg, ptr)            { __WARN_IF_NOT(msg, isa_NonNull(ptr), __FILE__, __LINE__); }

#define warn_if_not_Same(msg, ptr1, ptr2)               { __WARN_IF_NOT(msg, isa_Same(ptr1, ptr2), __FILE__, __LINE__); }
#define warn_if_not_Distinct(msg, ptr1, ptr2)           { __WARN_IF_NOT(msg, isa_Distinct(ptr1, ptr2), __FILE__, __LINE__); }
#define warn_if_not_DistinctIfNonNull(msg, ptr1, ptr2)  { __WARN_IF_NOT(msg, isa_DistinctIfNonNull(ptr1, ptr2), __FILE__, __LINE__); }

#define warn_if_not_EmptyStr(msg, str)           { __WARN_IF_NOT(msg, isa_EmptyStr(str), __FILE__, __LINE__); }
#define warn_if_not_NonEmptyStr(msg, str)        { __WARN_IF_NOT(msg, isa_NonEmptyStr(str), __FILE__, __LINE__); }

#define warn_if_not_Pos(msg, i)                  { __WARN_IF_NOT(msg, isa_Pos(i), __FILE__, __LINE__); }
#define warn_if_not_Neg(msg, i)                  { __WARN_IF_NOT(msg, isa_Neg(i), __FILE__, __LINE__); }

#define warn_if_not_PosZero(msg, i)              { __WARN_IF_NOT(msg, isa_PosZero(i), __FILE__, __LINE__); }
#define warn_if_not_NegZero(msg, i)              { __WARN_IF_NOT(msg, isa_NegZero(i), __FILE__, __LINE__); }

#define warn_if_not_Zero(msg, i)                 { __WARN_IF_NOT(msg, isa_Zero(i), __FILE__, __LINE__); }
#define warn_if_not_NonZero(msg, i)              { __WARN_IF_NOT(msg, isa_NonZero(i), __FILE__, __LINE__); }

#define warn_if_not_EQ(msg, i, j)                { __WARN_IF_NOT(msg, is_EQ(i, j), __FILE__, __LINE__); }
#define warn_if_not_NEQ(msg, i, j)               { __WARN_IF_NOT(msg, is_NEQ(i, j), __FILE__, __LINE__); }

#define warn_if_not_LT(msg, i, j)                { __WARN_IF_NOT(msg, is_LT(i, j), __FILE__, __LINE__); }
#define warn_if_not_LE(msg, i, j)                { __WARN_IF_NOT(msg, is_LE(i, j), __FILE__, __LINE__); }

#define warn_if_not_NLT(msg, i, j)               { __WARN_IF_NOT(msg, is_NLT(i, j), __FILE__, __LINE__); }
#define warn_if_not_NLE(msg, i, j)               { __WARN_IF_NOT(msg, is_NLE(i, j), __FILE__, __LINE__); }

#define warn_if_not_GT(msg, i, j)                { __WARN_IF_NOT(msg, is_GT(i, j), __FILE__, __LINE__); }
#define warn_if_not_GE(msg, i, j)                { __WARN_IF_NOT(msg, is_GE(i, j), __FILE__, __LINE__); }

#define warn_if_not_NGT(msg, i, j)               { __WARN_IF_NOT(msg, is_NGT(i, j), __FILE__, __LINE__); }
#define warn_if_not_NGE(msg, i, j)               { __WARN_IF_NOT(msg, is_NGE(i, j), __FILE__, __LINE__); }

#define warn_if_not(msg, pred)                   { __WARN_IF_NOT(msg, (pred),  __FILE__, __LINE__); }
#define warn_if(msg, pred)                       { __WARN_IF_NOT(msg, (!(pred)), __FILE__, __LINE__); }


// helper code signatures
void __REQUIRES(char *msg, int condition, char *fileName, int lineNum); // always exits
void __WARN_IF_NOT(char *msg, int condition, char *fileName, int lineNum); // doesn't exit
void __ASSERT(char *errMsg, int condition, char *fileName,  int lineNum, Boolean_t doExit);


#endif
