/* stringbuffer.c

   String buffer are used to accumulate strings, typically for output.

   They are essentially the same as bytevectors ...
   The sentinel byte (i.e. at end of each bytevector) is NULL to allow for C-strings.

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
#include <string.h>

#include "utils.h"
#include "stringbuffer.h"


// local defines
#define getContent(sbuf)   ((char *)getContent_BV(sBuf))


// New string buffer with initial capacity
StringBuf_t *new_SB() {
   return allocate_SB(DEFAULT_STRINGBUFFER_CAPACITY);
}


// Makes a new string buffer with specified capacity
StringBuf_t *allocate_SB(int capacity) {

   StringBuf_t *sbuf = allocate_BV(capacity);
   setAppendOnly_BV(sbuf);

   return sbuf;
}


void ensureCapacity_SB(StringBuf_t *sBuf, int capacity)  {

   ensureCapacity_BV(sBuf, capacity);
}


// Resets the given string buffer ...
void reset_SB(StringBuf_t *sBuf) {
   reset_BV(sBuf);
   setAppendOnly_BV(sBuf);
}


// Returns length of the string in the string-buffer
size_t length_SB(StringBuf_t *sBuf) {
   return strlen(getContent(sBuf));
}


// Prints string buffer content to stdout
void print_SB(StringBuf_t *sBuf) {
   printf("%s", getContent(sBuf));
   fflush(stdout);
}


// Prints string buffer content to FILE stream
int fprint_SB(FILE *stream, StringBuf_t *sBuf) {
   int status = fprintf(stream, "%s", getContent(sBuf));
   fflush(stream);
   return status;
}


// Prints string buffer content into given string ...
int sprint_SB(char *buf, StringBuf_t *sBuf) {
   return sprintf(buf, "%s", getContent(sBuf));
}

static char addItems_buffer[MSG_BUFSIZE+1];

// flexible means to add formatted data content to string buffer
void addItems_SB(StringBuf_t *dest, const char *fmt, ...) {
   va_list args;

   va_start(args, fmt);
   vsprintf(addItems_buffer, fmt, args);
   va_end(args);

   addString_SB(dest, addItems_buffer);
}

// Appends content from string buffer to string buffer
void addBuffer_SB(StringBuf_t *dest, StringBuf_t *source) {
   appendInto_BV(dest, source);
}


// Appends content to string buffer
void addInt_SB(StringBuf_t *dest, int i) {
   addItems_SB(dest, "%i", i);
}

void addLong_SB(StringBuf_t *dest, long li) {
   addItems_SB(dest, "%li", li);
}

void addUInt_SB(StringBuf_t *dest, unsigned int ui) {
   addItems_SB(dest, "%u", ui);
}

void addULong_SB(StringBuf_t *dest, unsigned long ul) {
   addItems_SB(dest, "%lu", ul);
}

void addPtr_SB(StringBuf_t *dest, void *ptr) {
   addItems_SB(dest, "%p", ptr);
}

void addReal_SB(StringBuf_t *dest, double d) {
   addItems_SB(dest, "%g", d);
}

void addString_SB(StringBuf_t *dest, char *str) {
   appendContent_BV(dest, strlen(str), (Byte_t *)str);
}


// Appends formatted content to string buffer
void addIntF_SB(StringBuf_t *dest, const char *fmt, int i) {
   addItems_SB(dest, fmt, i);
}

void addLongF_SB(StringBuf_t *dest, const char *fmt, long li) {
   addItems_SB(dest, fmt, li);
}

void addUIntF_SB(StringBuf_t *dest, const char *fmt, unsigned int ui) {
   addItems_SB(dest, fmt, ui);
}

void addULongF_SB(StringBuf_t *dest, const char *fmt, unsigned long ul) {
   addItems_SB(dest, fmt, ul);
}

void addPtrF_SB(StringBuf_t *dest, const char *fmt, void *ptr) {
   addItems_SB(dest, fmt, ptr);
}

void addRealF_SB(StringBuf_t *dest, const char *fmt, double d) {
   addItems_SB(dest, fmt, d);
}

void addStringF_SB(StringBuf_t *dest, const char *fmt, char *str) {
   addItems_SB(dest, fmt, str);
}
