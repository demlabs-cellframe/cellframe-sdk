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

typedef struct s_circularBuffer* circular_buffer_t;

// Construct CircularBuffer with ‘size' in byte. You must call CircularBufferFree() in balance for destruction.
extern circular_buffer_t circular_buffer_create(size_t size);

// Destruct CircularBuffer
extern void circular_buffer_free(circular_buffer_t cBuf);

// Reset the CircularBuffer
extern void circular_buffer_reset(circular_buffer_t cBuf);

//get the capacity of CircularBuffer
extern size_t circular_buffer_get_capacity(circular_buffer_t cBuf);

//get occupied data size of CircularBuffer
extern size_t circular_buffer_get_data_size(circular_buffer_t cBuf);

// Push data to the tail of a circular buffer from 'src' with 'length' size in byte.
extern void circular_buffer_push(circular_buffer_t cBuf, const void *src, size_t length);

// Pop data from a circular buffer to 'dataOut'  with wished 'length' size in byte,return the actual data size in byte popped out,which is less or equal to the input 'length parameter.
extern size_t circular_buffer_pop(circular_buffer_t cBuf, size_t length, void *dataOut);

// Read data from a circular buffer to 'dataOut'  with wished 'length' size in byte,return the actual data size in byte popped out,which is less or equal to the input 'length parameter.
extern size_t circular_buffer_read(circular_buffer_t cBuf, size_t length, void *dataOut);

//for test purpose, print the circular buffer's data content by printf(...); the 'hex' parameters indicates that if the data should be printed in asscii string or hex data format.
extern void circular_buffer_print(circular_buffer_t cBuf, bool hex);

#ifdef __unix__
// Read data from a circular buffer to socketFd
extern int circular_buffer_write_In_socket(circular_buffer_t cBuf, int sockfd);
#endif
#endif
