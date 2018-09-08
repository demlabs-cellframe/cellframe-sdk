/* utils.c

   Utilities code ...

   These are "typically" generic/general purpose - not requiring particular
   bespoke structs/data structures.

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
*/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

#include "utils.h"


/*******************************************************************************
   Expoentiation function
*******************************************************************************/
long power(int base, int exp) {
   if (base == 0) return 0;

   if (exp < 0) {
      diagnostic("power : Exponent is negative.");
      error_exit();
   }

   if (exp == 0) return 1;

   long result = 1;
   long oldResult = 1;

   for (int i = 0; i < exp; i++) {
     oldResult = result;
     result *= base;

     if (result < oldResult) {
        diagnostic("power : overflow detected for base=%i, exp=%i", base, exp);
        error_exit();
     }
   }

   return result;
}

/*******************************************************************************
   Comparison functions
   - This makes sense for both signed and unsigned values
*******************************************************************************/
Comparison_t cmp_char(char a, char b) { return CMP(a, b); }
Comparison_t cmp_byte(Byte_t a, Byte_t b) { return CMP(a, b); }

Comparison_t cmp_key(Key_t a, Key_t b) { return CMP(a, b); }
Comparison_t cmp_posn(Posn_t a, Posn_t b) { return CMP(a, b); }

Comparison_t cmp_int(int a, int b) { return CMP(a, b); }
Comparison_t cmp_long(long a, long b) { return CMP(a, b); }

Comparison_t cmp_uint(int a, int b) { return CMP(a, b); }
Comparison_t cmp_ulong(long a, long b) { return CMP(a, b); }

Comparison_t cmp_float(float a, float b) { return CMP(a, b); }
Comparison_t cmp_double(double a, double b) { return CMP(a, b); }

Comparison_t cmp_string(char *a, char *b) { return asComparison(strcmp(a, b)); }


/*******************************************************************************
   Key-based maximum and minimum
*******************************************************************************/
Key_t keyMax(CompareFn_t keyFn, Key_t keyA, Key_t keyB) {
   return (keyFn(keyA, keyB) >= 0 ? keyA : keyB);
}

Key_t keyMin(CompareFn_t keyFn, Key_t keyA, Key_t keyB) {
   return (keyFn(keyA, keyB) <= 0 ? keyA : keyB);
}


/*******************************************************************************
   Position-based maximum and minimum
   - identical to keyMax/keyMin
   - conceptually deals with positions not keys
*******************************************************************************/
Posn_t posnMax(CompareFn_t posnFn, Posn_t posnA, Posn_t posnB)  {
   return (posnFn(posnA, posnB) >= 0 ? posnA : posnB);
}

Posn_t posnMin(CompareFn_t posnFn, Posn_t posnA, Posn_t posnB) {
   return (posnFn(posnA, posnB) <= 0 ? posnA : posnB);
}


/******************************************************************************
  Timing functions
******************************************************************************/
static void nullFn() {}

double timeFunction(int repeat, Thunk_t runFun) {
  return timeFunction2(repeat, NULL, runFun);
}

double timeFunction2(int repeat, Thunk_t setupFun, Thunk_t runFun) {
   clock_t startTime, endTime = 0;

   int accumTicks = 0;
   int overHead = 0;
   int diffTime = 0;

   // Nothing to do
   if (runFun == NULL) {
      diagnostic("utils.timeFunction2: Null run function given - Nothing to measure!");
      error_exit();
   }

   Thunk_t setupFn = (setupFun == NULL ? nullFn : setupFun);
   Thunk_t runFn = runFun;

   // timing loop
   for(int i=0; i < repeat; i++) {

     // calling a null function
     startTime = clock();
     nullFn();
     endTime = clock();
     overHead = (int)(endTime - startTime);

     // call set-up function
     // - this part is NOT timed
     setupFn();

     // call actual function
     startTime = clock();
     runFn();
     endTime = clock();

     diffTime = (int)(endTime - startTime);

     // accum the internal time
     accumTicks += max(0, diffTime - overHead);
   }

   return (double)accumTicks/CLOCKS_PER_SEC;
}


/*******************************************************************************
   Null functions
*******************************************************************************/
// The null thunk closure
void nullThunk () {}

// The null VoidFn that does nothing at all.
void nullVoidFn(void *obj) {}


/******************************************************************************
  printBytes - print a pure byte vector
******************************************************************************/
void printHexBytes(Byte_t *bytes, int len) {
   for(int i = 0; i < len; i++)
      printf("%02x", bytes[i]);
}


/******************************************************************************
  HexDump utils.
******************************************************************************/

// Local prototypes
static void hexdump_line(char *arr, int count, int size, int width);
static void tabchars(char ch, int count);

// Dumps binary data in hex to stdout
void hexdump(void *data, int size, int width)
{
  // Check size sanity
  if (size <= 0)
  {
    printf("hexdump : Bad size: %i", size);
    exit(2);
  }

  // Check width sanity
  if (width <= 0)
  {
    printf("hexdump : Bad width: %i", width);
    exit(2);
  }

  // Allocate variables
  char *arr = (char *)malloc(size);
  Byte_t *ptr = (Byte_t *)data; // ptr is a byte pointer
  int count = 0;

  // Copy data to array arr
  for (int i = 0; i < size; i++)
  {
    arr[i] = *ptr; // copy current byte
    ptr    += 1;   // move ptr to next byte
  }

  int outWidth = sizeof(Byte_t *) + 3 + 3*width + 1 + 1*width;
  tabchars('=', outWidth);

  // reset ptr to data
  ptr = data;

  // write out each line of the hex dump
  while (count < size) {
    hexdump_line(arr, count, size, width);
    count += width;
  }

  tabchars('=', outWidth);

  // now free the storage ...
  free((void *)arr);
}

static void hexdump_line(char *arr, int count, int size, int width) {
  int i, j;
  unsigned int ch;

  // print current address ...
  printf("Ox%08lx ", (unsigned long)arr);

  // Now dump each element in hex
  for (i = 0; i < width; i++) {
    j = count + i;
    if (j < size)
    {
      printf("%02x ", (unsigned char)arr[j]);
    }
    else
    {
      printf("   ");
    }
  }

  // Now finally dump each element as a (printable) char
  for (i = 0; i < width; i++)
  {
    j = count + i;
    if (j < size)

    {
      ch = arr[j];
      if (ch >= ' ' && ch < 127)
      {
        printf("%c", (char)ch);
      }
      else
      {
        printf(".");
      }
    }
    else
    {
      printf(" ");
    }
  }
}


// Dumps string of chars to stdout
// - ch = char to be dumped out
// - count = number of chars to be dumped out
static void tabchars(char ch, int count) {
  int i = 0;
  for (i = 0; i < count; i++)
  {
    printf("%c", ch);
  }
}


/******************************************************************************
  Basic string processing
  - generally update-in-place
******************************************************************************/
void toLowerCase(char *text) {
   if (text == NULL) return;

   for (char *p = text; *p != 0; p++)
   	*p = tolower(*p);

   /*
   char lower = ('a' - 'A');

   for (char *p = text; *p != 0; p++) {
       if ('A' <= *p && *p <= 'Z')  *p += lower;
   }


   char ch;
   for (char i = 0; (ch = text[i]) != 0; i++) {
       //printf("%i. Char: '%c' (0x%x)\n", i, ch, (int)ch);
       if ('A' <= ch && ch <= 'Z') {
          text[i] += lower;
       }
   }
   */
}

void toUpperCase(char *text) {
   if (text == NULL) return;

   for (char *p = text; *p != 0; p++)
   	*p = toupper(*p);
}

void rightTrim(char *text) {
   if (text == NULL) return;

   for (int i = strlen(text)-1; i >= 0; i--) {
      if (isspace(text[i])) text[i] = 0;
      else
         break;
   }
}

char *leftTrim(char *text) {
   if (text == NULL) return NULL;

   char *p = text;

   while (*p != 0) {
      if (!isspace(*p)) return p;
      p++;
   }

   return p;
}

char *trim(char *text) {
   rightTrim(text);
   return leftTrim(text);
}

/******************************************************************************
  Reading and Writing Files to/from an array of blocks
******************************************************************************/

// readFile - takes a filename and reads it into a sequence of blocks
size_t readFile(const char *filename, Byte_t *blocks[], int maxBlocks)
{
   // initialise blocks
   for (int i = 0; i<maxBlocks; i++) {
      blocks[i] = NULL;
   }

   FILE *ifp = fopen(filename,"r");
   if (ifp == NULL) {
      diagnostic("Can't read file: %s", filename);
      codeError_exit();
   }

   size_t totalCharsRead = 0;
   size_t thisRead = 0;
   void *blockPtr  = NULL;

   for (int posn = 0; posn < maxBlocks && !feof(ifp); posn++) {
      blockPtr = ALLOC_BLK(BLOCKSIZE);
      thisRead = fread(blockPtr, 1, BLOCKSIZE, ifp);
      blocks[posn] = blockPtr;
      totalCharsRead += thisRead;
   }

   fclose(ifp);

   return totalCharsRead;
}


// writeFile - takes a destination filename and write a sequence of blocks to it
void writeFile(const char *destFilename, int numChars, Byte_t *blocks[], int maxBlocks)
{
   // count the number of non-null blocks
   int totalBlocks = 0;
   for (int i = 0; i < maxBlocks; i++) {
      if (blocks[i] != NULL) {
         totalBlocks++;
      }
   }

   // open the output file for writing
   FILE *ofp = fopen(destFilename,"w");
   if (ofp == NULL) {
      diagnostic("Output file exists: %s", destFilename);
      codeError_exit();
   }

   size_t charsRemaining = numChars;
   size_t thisWrite = 0;
   void *blockPtr  = NULL;  // current ptr to data block

   // write all blocks
   for (int posn = 0; posn < totalBlocks && charsRemaining > 0; posn++) {
      blockPtr = (void *)blocks[posn];
      thisWrite = (charsRemaining <= BLOCKSIZE ? charsRemaining : BLOCKSIZE);
      thisWrite = fwrite(blockPtr, 1, thisWrite, ofp);
      charsRemaining -= thisWrite;
   }

   fflush(ofp);
   fclose(ofp);
}


/******************************************************************************
  Assert statement
  -- either failStop (i.e. exit on failure of check)
  -- or soft warning (i.e. print message and continue on failure of check)
******************************************************************************/
void __ASSERT(char *errMsg, int condition, char *fileName, int lineNum, Boolean_t doExit) {
   if (condition == 0) {
      // condition is FALSE

      // Ensure non-NULL errMsg
      errMsg = (errMsg == NULL ? "" : errMsg);

      if (doExit) {
         // issue ASSERT failed message and then exits ...
         fprintf(stderr, "**** FAILED: check failed in file '%s' at line %i: %s ... exiting\n", fileName, lineNum, errMsg);
         exit(1);
      }
      else {
         // issue WARNING on message - and then continue ...
         fprintf(stderr, "**** WARNING: check failed in file '%s' at line %i: %s\n", fileName, lineNum, errMsg);
      }
   }
}


/******************************************************************************
  Standard checks
  __REQUIRES      - always exits if check fails
  __WARN_IF_NOT   - doesn't exit if check fails
******************************************************************************/
void __REQUIRES(char *msg, int condition, char *fileName, int lineNum) {
   __ASSERT(msg, condition, fileName, lineNum, TRUE);
}

void __WARN_IF_NOT(char *msg, int condition, char *fileName, int lineNum) {
   __ASSERT(msg, condition, fileName, lineNum, FALSE);
}


/******************************************************************************
  Debugging ...
  - to enable debugging, include the header "debug.h"
******************************************************************************/
Boolean_t debugOn  = FALSE;   // Controls debugging output.  Initially false.

static int debugCount = DEBUG_LIMIT;

void __DEBUG(const char *fmt, ...) {
   if (! debugOn) return;

   fflush(stderr);  // flush stderr
   fflush(NULL);    // flush all output

   va_list args;

   va_start(args, fmt);

   fprintf(stderr, ">>>> ");
   vfprintf(stderr, fmt, args);
   fprintf(stderr, "\n");

   fflush(stderr);  // flush stderr
   fflush(NULL);    // flush all output

   va_end(args);

   if (debugCount <= 0) {
      diagnostic("\n\n   DEBUG LIMIT (%i) EXCEEDED : Loop found??", DEBUG_LIMIT);
      error_exit();
   }

   debugCount--;
}

void __XDEBUG(const char *fmt, ...) {
}

static char __posnBuffer[LINE_BUFSIZE+1];
char *__POSITION(char *filename, int linenumber) {
   if (filename == NULL) {

      if (linenumber < 0) {
         // filename == NULL && line < 0
         return "";

      } else {

         // filename == NULL && line >= 0
         sprintf(__posnBuffer, "line %i", linenumber);
         return __posnBuffer;
      }
   } else {

      if (linenumber < 0) {
         // filename != NULL && line < 0
         return filename;

      } else {

         // filename != NULL && line >= 0
         sprintf(__posnBuffer, "[%s, line %i]", filename, linenumber);
         return __posnBuffer;
      }
   }
}


/******************************************************************************
  Error processing
******************************************************************************/
static char __errBuf[MSG_BUFSIZE+1];

void diagnostic(const char *fmt, ...) {
   va_list args;

   va_start(args, fmt);
   vsprintf(__errBuf, fmt, args);
   va_end(args);
}

void __ERROR() {
   printf("**** %s\n", __errBuf);
   exit(EXIT_FAILURE);
}

void __CODE_ERROR(char *fileName, int lineNum) {
   printf("**** CODE ERROR in file %s at line %i: %s\n", fileName, lineNum, __errBuf);
   exit(EXIT_FAILURE);
}
