//
//  CircularBuffer.h
//
//  Created by 罗亮富(Roen)zxllf23@163.com on 14-1-14.
//  Copyright (c) 2014年 All rights reserved.
//
//  Note: edited by Anatolii Kurotych

#ifndef YYDJ_Roen_CircularBuffer_h
#define YYDJ_Roen_CircularBuffer_h
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/*
 A circular buffer(circular queue, cyclic buffer or ring buffer), is a data structure that uses a single, fixed-size buffer as if it were connected end-to-end. This structure lends itself easily to buffering data streams. visit https://en.wikipedia.org/wiki/Circular_buffer to see more information.
 */

typedef struct dap_cbuf* dap_cbuf_t;

// Construct CircularBuffer with ‘size' in byte. You must call CircularBufferFree() in balance for destruction.
dap_cbuf_t dap_cbuf_create(size_t size);

// Destruct CircularBuffer
void dap_cbuf_delete(dap_cbuf_t cBuf);

// Reset the CircularBuffer
void dap_cbuf_reset(dap_cbuf_t cBuf);

//get the capacity of CircularBuffer
size_t dap_cbuf_get_size_max(dap_cbuf_t cBuf);

//get occupied data size of CircularBuffer
size_t dap_cbuf_get_size(dap_cbuf_t cBuf);

// Push data to the tail of a circular buffer from 'src' with 'length' size in byte.
void dap_cbuf_push(dap_cbuf_t cBuf, const void *src, size_t length);

// Pop data from a circular buffer to 'dataOut'  with wished 'length' size in byte,return the actual data size in byte popped out,which is less or equal to the input 'length parameter.
size_t dap_cbuf_pop(dap_cbuf_t cBuf, size_t length, void *dataOut);

// Read data from a circular buffer to 'dataOut'  with wished 'length' size in byte,return the actual data size in byte popped out,which is less or equal to the input 'length parameter.
size_t dap_cbuf_read(dap_cbuf_t cBuf, size_t length, void *dataOut);

//for test purpose, print the circular buffer's data content by printf(...); the 'hex' parameters indicates that if the data should be printed in asscii string or hex data format.
void dap_cbuf_print(dap_cbuf_t cBuf, bool hex);

#ifdef DAP_OS_UNIX
// Read data from a circular buffer to socketFd
int dap_cbuf_write_in_socket(dap_cbuf_t cBuf, int sockfd);
#endif
#endif
