//
//  CircularBuffer.c
//
//  Created by 罗亮富(Roen zxllf23@163.com) on 14-1-14.
//  Copyright (c) 2014年 All rights reserved.
//
//  Note: Edited by Kurotych Anatolii


#include "dap_circular_buffer.h"
#include <string.h>
#include <errno.h>

#include "dap_common.h"

#define LOG_TAG "circular_buffer"

struct s_circularBuffer{

    size_t capacity; //capacity bytes size
    size_t dataSize; //occupied data size
    size_t tailOffset; //head offset, the oldest byte position offset
    size_t headOffset; //tail offset, the lastest byte position offset
    u_int8_t *buffer;

};

extern CircularBuffer CircularBufferCreate(size_t size)
{
    size_t totalSize = sizeof(struct s_circularBuffer) + size;
    void *p = malloc(totalSize);
    CircularBuffer buffer = (CircularBuffer)p;
    buffer->buffer = p + sizeof(struct s_circularBuffer);
    buffer->capacity = size;
    CircularBufferReset(buffer);
    return buffer;
}

void CircularBufferFree(CircularBuffer cBuf)
{
    CircularBufferReset(cBuf);
    cBuf->capacity = 0;
    cBuf->dataSize = 0;
    cBuf->buffer = NULL;
    free(cBuf);
}

void CircularBufferReset(CircularBuffer cBuf)
{
    cBuf->headOffset = -1;
    cBuf->tailOffset = -1;
    cBuf->dataSize = 0;
}

size_t CircularBufferGetCapacity(CircularBuffer cBuf)
{
    return cBuf->capacity;
}

size_t CircularBufferGetDataSize(CircularBuffer cBuf)
{
    return cBuf->dataSize;
}

void CircularBufferPush(CircularBuffer cBuf,void *src, size_t length)
{
    if(length == 0)
        return;

    size_t writableLen = length;
    void *pSrc = src;

    if(writableLen > cBuf->capacity)//in case of size overflow
    {
        size_t overFlowLen = writableLen - cBuf->capacity;
        writableLen = cBuf->capacity;
        pSrc = src + overFlowLen;
    }


    bool resetHead = false;
    //in case the circle buffer won't be full after adding the data
    if(cBuf->tailOffset+writableLen < cBuf->capacity)
    {
        memcpy(&cBuf->buffer[cBuf->tailOffset + 1], pSrc, writableLen);

        if((cBuf->tailOffset < cBuf->headOffset) && (cBuf->tailOffset+writableLen >= cBuf->headOffset) )
            resetHead = true;

        cBuf->tailOffset += writableLen;
    }
    else//in case the circle buffer will be overflow after adding the data
    {
        size_t remainSize = cBuf->capacity - cBuf->tailOffset - 1; //the remain size
        memcpy(&cBuf->buffer[cBuf->tailOffset+1], pSrc, remainSize);

        size_t coverSize = writableLen - remainSize; //size of data to be covered from the beginning
        memcpy(cBuf->buffer, pSrc+remainSize, coverSize);

        if(cBuf->tailOffset < cBuf->headOffset)
            resetHead = true;
        else
        {
            if(coverSize>cBuf->headOffset)
                resetHead = true;
        }

        cBuf->tailOffset = coverSize - 1;
    }

    if(cBuf->headOffset == (size_t)-1)
        cBuf->headOffset = 0;

    if(resetHead)
    {
        if(cBuf->tailOffset+1 < cBuf->capacity)
            cBuf->headOffset = cBuf->tailOffset + 1;
        else
            cBuf->headOffset = 0;

        cBuf->dataSize = cBuf->capacity;
    }
    else
    {
        if(cBuf->tailOffset >= cBuf->headOffset)
            cBuf->dataSize = cBuf->tailOffset - cBuf->headOffset + 1;
        else
            cBuf->dataSize = cBuf->capacity - (cBuf->headOffset - cBuf->tailOffset - 1);
    }
}

#ifdef __unix__
#include <sys/types.h>
#include <sys/socket.h>

int CircularBufferWriteInSocket(CircularBuffer cBuf, int sockfd)
{
    if(cBuf->dataSize == 0) {
        return 0;
    }

    ssize_t rdLen = -1;

    if(cBuf->headOffset <= cBuf->tailOffset)
    {
        rdLen = send(sockfd,
                     &cBuf->buffer[cBuf->headOffset],
                     cBuf->dataSize, MSG_DONTWAIT | MSG_NOSIGNAL | MSG_DONTROUTE);
        if(rdLen < 0) {
            log_it(L_ERROR, "Can't write data in socket. %s", strerror(errno));
            return -1;
        }

        cBuf->headOffset += rdLen;
        if(cBuf->headOffset > cBuf->tailOffset)
        {
            cBuf->headOffset = -1;
            cBuf->tailOffset = -1;
        }

        cBuf->dataSize -= rdLen;
    }
    else
    {
        if(cBuf->headOffset + cBuf->dataSize <= cBuf->capacity)
        {
            log_it(L_CRITICAL, "We always trying write all data!");
            abort();
        }
        else
        {
            size_t countBytesToEnd = cBuf->capacity - cBuf->headOffset;
            rdLen = send(sockfd,
                         &cBuf->buffer[cBuf->headOffset],
                    countBytesToEnd, MSG_DONTWAIT | MSG_NOSIGNAL);
          //  log_it(L_DEBUG, "Write in socket: %s", &cBuf->buffer[cBuf->headOffset]);
            if(rdLen < 0) {
                log_it(L_ERROR, "Can't write data in socket. %s", strerror(errno));
                return -1;
            }

            if(rdLen < (ssize_t)countBytesToEnd) {
                log_it(L_WARNING, "rdLen < countBytesToEnd");
                CircularBufferPop(cBuf, rdLen, NULL);
                return rdLen;
            }

            cBuf->dataSize -= countBytesToEnd;
            cBuf->headOffset = 0;
            cBuf->tailOffset = cBuf->dataSize - 1;

            ssize_t rdLen2 = send(sockfd,
                         cBuf->buffer,
                         cBuf->dataSize, MSG_DONTWAIT | MSG_NOSIGNAL);

            if(rdLen2 < 0) {
                log_it(L_ERROR, "Can't write data in socket. %s", strerror(errno));
                return rdLen;
            }

            cBuf->headOffset = rdLen2;
            if(cBuf->headOffset > cBuf->tailOffset)
            {
                cBuf->headOffset = -1;
                cBuf->tailOffset = -1;
                cBuf->dataSize = 0;
            }
            return countBytesToEnd + rdLen2;
        }
    }

    return rdLen;

}

#endif

size_t inter_circularBuffer_read(CircularBuffer cBuf, size_t length, void *dataOut, bool resetHead)
{
    if(cBuf->dataSize == 0 || length == 0)
        return 0;

    size_t rdLen = length;

    if(cBuf->dataSize < rdLen)
        rdLen = cBuf->dataSize;


    if(cBuf->headOffset <= cBuf->tailOffset)
    {
        if(dataOut)
            memcpy(dataOut, &cBuf->buffer[cBuf->headOffset], rdLen);

        if(resetHead)
        {
            cBuf->headOffset += rdLen;
            if(cBuf->headOffset > cBuf->tailOffset)
            {
                cBuf->headOffset = -1;
                cBuf->tailOffset = -1;
            }
        }
    }
    else
    {
        if(cBuf->headOffset+rdLen <= cBuf->capacity)
        {
            if(dataOut)
                memcpy(dataOut, &cBuf->buffer[cBuf->headOffset], rdLen);

            if(resetHead)
            {
                cBuf->headOffset += rdLen;
                if(cBuf->headOffset == cBuf->capacity)
                    cBuf->headOffset = 0;
            }
        }
        else
        {
            size_t frg1Len = cBuf->capacity - cBuf->headOffset;
            if(dataOut)
                memcpy(dataOut, &cBuf->buffer[cBuf->headOffset], frg1Len);

            size_t frg2len = rdLen - frg1Len;
            if(dataOut)
                memcpy(dataOut+frg1Len, cBuf->buffer, frg2len);

            if(resetHead)
            {
                cBuf->headOffset = frg2len;
                if(cBuf->headOffset > cBuf->tailOffset)
                {
                    cBuf->headOffset = -1;
                    cBuf->tailOffset = -1;
                }
            }
        }
    }

    if(resetHead)
        cBuf->dataSize -= rdLen;

    return rdLen;
}


size_t CircularBufferPop(CircularBuffer cBuf, size_t length, void *dataOut)
{
    return inter_circularBuffer_read(cBuf,length,dataOut,true);
}

size_t CircularBufferRead(CircularBuffer cBuf, size_t length, void *dataOut)
{
    return inter_circularBuffer_read(cBuf,length,dataOut,false);
}


//print circular buffer's content into str,
void CircularBufferPrint(CircularBuffer cBuf, bool hex)
{
    u_int8_t *b = cBuf->buffer;
    size_t cSize = CircularBufferGetCapacity(cBuf);
    char *str = malloc(2*cSize+1);

    char c;

    for(size_t i=0; i<cSize; i++)
    {
        if(CircularBufferGetDataSize(cBuf) == 0)
        {
            c = '_';
        }
        else if (cBuf->tailOffset < cBuf->headOffset)
        {
            if(i>cBuf->tailOffset && i<cBuf->headOffset)
                c = '_';
            else
              c = b[i];
        }
        else
        {
            if(i>cBuf->tailOffset || i<cBuf->headOffset)
                c = '_';
            else
                c = b[i];
        }
        if(hex)
            sprintf(str+i*2, "%02X|",c);
        else
            sprintf(str+i*2, "%c|",c);
    }

    printf("CircularBuffer: %s <size %zu dataSize:%zu>\n",str,CircularBufferGetCapacity(cBuf),CircularBufferGetDataSize(cBuf));

    free(str);
}
