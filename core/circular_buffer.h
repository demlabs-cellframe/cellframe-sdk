//
//  CircularBuffer.h
//
//  Created by 罗亮富(Roen)zxllf23@163.com on 14-1-14.
//  Copyright (c) 2014年 All rights reserved.
//
//  Note: Edited by Kurotych Anatolii

#ifndef YYDJ_Roen_CircularBuffer_h
#define YYDJ_Roen_CircularBuffer_h
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/*
 A circular buffer(circular queue, cyclic buffer or ring buffer), is a data structure that uses a single, fixed-size buffer as if it were connected end-to-end. This structure lends itself easily to buffering data streams. visit https://en.wikipedia.org/wiki/Circular_buffer to see more information.
 */

typedef struct s_circularBuffer* CircularBuffer;

// Construct CircularBuffer with ‘size' in byte. You must call CircularBufferFree() in balance for destruction.
extern CircularBuffer CircularBufferCreate(size_t size);

// Destruct CircularBuffer
extern void CircularBufferFree(CircularBuffer cBuf);

// Reset the CircularBuffer
extern void CircularBufferReset(CircularBuffer cBuf);

//get the capacity of CircularBuffer
extern size_t CircularBufferGetCapacity(CircularBuffer cBuf);

//get occupied data size of CircularBuffer
extern size_t CircularBufferGetDataSize(CircularBuffer cBuf);

// Push data to the tail of a circular buffer from 'src' with 'length' size in byte.
extern void CircularBufferPush(CircularBuffer cBuf,void *src, size_t length);

// Pop data from a circular buffer to 'dataOut'  with wished 'length' size in byte,return the actual data size in byte popped out,which is less or equal to the input 'length parameter.
extern size_t CircularBufferPop(CircularBuffer cBuf, size_t length, void *dataOut);

// Read data from a circular buffer to 'dataOut'  with wished 'length' size in byte,return the actual data size in byte popped out,which is less or equal to the input 'length parameter.
extern size_t CircularBufferRead(CircularBuffer cBuf, size_t length, void *dataOut);

#ifdef __unix__
// Write data from a cicrular buffer to file descriptor. This is non blocking operation ( use flags MSG_DONTWAIT | MSG_NOSIGNAL )
// if >= 0 return write data count
// <= 0 reserved for errors
extern int CircularBufferWriteInSocket(CircularBuffer cBuf, int sockfd);
#endif

//for test purpose, print the circular buffer's data content by printf(...); the 'hex' parameters indicates that if the data should be printed in asscii string or hex data format.
extern void CircularBufferPrint(CircularBuffer cBuf, bool hex);
#endif
