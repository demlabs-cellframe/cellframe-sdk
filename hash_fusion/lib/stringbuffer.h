#ifndef __STRINGBUFFER_H__
#define __STRINGBUFFER_H__

#include <stdio.h>
#include "utils.h"
#include "bytevector.h"

/*******************************************************************************
   stringbuffer.h

   String Buffers (i.e. a kind of bytevector)

   - Convenient way to build strings.
   - Appends content
   
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

typedef ByteVec_t StringBuf_t;

#define DEFAULT_STRINGBUFFER_CAPACITY  32


// New string buffer with default capacity
StringBuf_t *new_SB();

// Makes a new string buffer with (at least) specified capacity
StringBuf_t *allocate_SB(int capacity);

// Resets the given string buffer ...
void reset_SB(StringBuf_t *sBuf);

// Ensure capacity of given stringbuffer ...
void ensureCapacity_SB(StringBuf_t *sBuf, int capacity);

// Returns length of the string in the string-buffer
size_t length_SB(StringBuf_t *sBuf);

// Prints string buffer content to stdout
void print_SB(StringBuf_t *sBuf);

// Prints string buffer content to FILE stream
int fprint_SB(FILE *stream, StringBuf_t *sBuf);

// Prints string buffer content into given string ...
int sprint_SB(char *buf, StringBuf_t *sBuf);

// Flexible means to add formatted data content to string buffer
void addItems_SB(StringBuf_t *sBuf, const char *fmt, ...);

// Appends content from string buffer to string buffer
void addBuffer_SB(StringBuf_t *dest, StringBuf_t *source);


// Appends content to string buffer
void addInt_SB(StringBuf_t *dest, int i);

void addLong_SB(StringBuf_t *dest, long li);

void addUInt_SB(StringBuf_t *dest, unsigned int ui);

void addULong_SB(StringBuf_t *dest, unsigned long ul);

void addPtr_SB(StringBuf_t *dest, void *ptr);

void addReal_SB(StringBuf_t *dest, double d);

void addString_SB(StringBuf_t *dest, char *str);


// Appends formatted content to string buffer
void addIntF_SB(StringBuf_t *dest, const char *fmt, int i);

void addLongF_SB(StringBuf_t *dest, const char *fmt, long li);

void addUIntF_SB(StringBuf_t *dest, const char *fmt, unsigned int ui);

void addULongF_SB(StringBuf_t *dest, const char *fmt, unsigned long ul);

void addPtrF_SB(StringBuf_t *dest, const char *fmt, void *ptr);

void addRealF_SB(StringBuf_t *dest, const char *fmt, double d);

void addStringF_SB(StringBuf_t *dest, const char *fmt, char *str);


// Defining Error Message for string buffers ...
#define error_exit_SB(sBuf)        { diagnostic("%s", (char *)getContent_BV(sBuf)); error_exit(); }
#define codeError_exit_SB(sBuf)    { diagnostic("%s", (char *)getContent_BV(sBuf)); codeError_exit(); }

#endif
