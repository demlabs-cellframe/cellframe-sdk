//
//  CircularBuffer.c
//
//  Created by 罗亮富(Roen zxllf23@163.com) on 14-1-14.
//  Copyright (c) 2014年 All rights reserved.
//
//  Note: Edited by Kurotych Anatolii


#include "dap_cbuf.h"
#include <string.h>
#include <errno.h>

#include "dap_common.h"

#define LOG_TAG "dap_cbuf"

struct dap_cbuf{

    size_t data_size_max; //capacity bytes size
    size_t data_size; //occupied data size
    size_t offset_tail; //head offset, the oldest byte position offset
    size_t offset_head; //tail offset, the lastest byte position offset
    uint8_t *buffer;

};

dap_cbuf_t dap_cbuf_create(size_t size)
{
    size_t totalSize = sizeof(struct dap_cbuf) + size;
    void *p = malloc(totalSize);
    dap_cbuf_t buffer = (dap_cbuf_t)p;
    buffer->buffer = p + sizeof(struct dap_cbuf);
    buffer->data_size_max = size;
    dap_cbuf_reset(buffer);
    return buffer;
}

void dap_cbuf_delete(dap_cbuf_t cBuf)
{
    dap_cbuf_reset(cBuf);
    cBuf->data_size_max = 0;
    cBuf->data_size = 0;
    cBuf->buffer = NULL;
    free(cBuf);
}

void dap_cbuf_reset(dap_cbuf_t cBuf)
{
    cBuf->offset_head = -1;
    cBuf->offset_tail = -1;
    cBuf->data_size = 0;
}

size_t dap_cbuf_get_size_max(dap_cbuf_t cBuf)
{
    return cBuf->data_size_max;
}

size_t dap_cbuf_get_size(dap_cbuf_t cBuf)
{
    return cBuf->data_size;
}

void dap_cbuf_push(dap_cbuf_t cBuf, const void *src, size_t length)
{
    if(length == 0)
        return;

    size_t writableLen = length;
    const void *pSrc = src;

    if(writableLen > cBuf->data_size_max)//in case of size overflow
    {
        size_t overFlowLen = writableLen - cBuf->data_size_max;
        writableLen = cBuf->data_size_max;
        pSrc = src + overFlowLen;
    }


    bool resetHead = false;
    //in case the circle buffer won't be full after adding the data
    if(cBuf->offset_tail+writableLen < cBuf->data_size_max)
    {
        memcpy(&cBuf->buffer[cBuf->offset_tail + 1], pSrc, writableLen);

        if((cBuf->offset_tail < cBuf->offset_head) && (cBuf->offset_tail+writableLen >= cBuf->offset_head) )
            resetHead = true;

        cBuf->offset_tail += writableLen;
    }
    else//in case the circle buffer will be overflow after adding the data
    {
        size_t remainSize = cBuf->data_size_max - cBuf->offset_tail - 1; //the remain size
        memcpy(&cBuf->buffer[cBuf->offset_tail+1], pSrc, remainSize);

        size_t coverSize = writableLen - remainSize; //size of data to be covered from the beginning
        memcpy(cBuf->buffer, pSrc+remainSize, coverSize);

        if(cBuf->offset_tail < cBuf->offset_head)
            resetHead = true;
        else
        {
            if(coverSize>cBuf->offset_head)
                resetHead = true;
        }

        cBuf->offset_tail = coverSize - 1;
    }

    if(cBuf->offset_head == (size_t)-1)
        cBuf->offset_head = 0;

    if(resetHead)
    {
        if(cBuf->offset_tail+1 < cBuf->data_size_max)
            cBuf->offset_head = cBuf->offset_tail + 1;
        else
            cBuf->offset_head = 0;

        cBuf->data_size = cBuf->data_size_max;
    }
    else
    {
        if(cBuf->offset_tail >= cBuf->offset_head)
            cBuf->data_size = cBuf->offset_tail - cBuf->offset_head + 1;
        else
            cBuf->data_size = cBuf->data_size_max - (cBuf->offset_head - cBuf->offset_tail - 1);
    }
}

#ifdef DAP_OS_UNIX
#include <sys/types.h>
#include <sys/socket.h>

int dap_cbuf_write_in_socket(dap_cbuf_t cBuf, int sockfd)
{
    if(cBuf->data_size == 0) {
        return 0;
    }

    ssize_t rdLen = -1;

    if(cBuf->offset_head <= cBuf->offset_tail)
    {
        rdLen = send(sockfd,
                     &cBuf->buffer[cBuf->offset_head],
                     cBuf->data_size, MSG_DONTWAIT | MSG_NOSIGNAL | MSG_DONTROUTE);
        if(rdLen < 0) {
            log_it(L_ERROR, "Can't write data in socket. %s", strerror(errno));
            return -1;
        }

        cBuf->offset_head += rdLen;
        if(cBuf->offset_head > cBuf->offset_tail)
        {
            cBuf->offset_head = -1;
            cBuf->offset_tail = -1;
        }

        cBuf->data_size -= rdLen;
    }
    else
    {
        if(cBuf->offset_head + cBuf->data_size <= cBuf->data_size_max)
        {
            rdLen = send(sockfd,
                         &cBuf->buffer[cBuf->offset_head],
                    cBuf->data_size, MSG_DONTWAIT | MSG_NOSIGNAL);

            if(rdLen < 0) {
                log_it(L_ERROR, "Can't write data in socket. %s", strerror(errno));
                return -1;
            }

            cBuf->offset_head += rdLen;
            if(cBuf->offset_head == cBuf->data_size_max)
                cBuf->offset_head = 0;
        }
        else
        {
            size_t countBytesToEnd = cBuf->data_size_max - cBuf->offset_head;
            rdLen = send(sockfd,
                         &cBuf->buffer[cBuf->offset_head],
                    countBytesToEnd, MSG_DONTWAIT | MSG_NOSIGNAL);
          //  log_it(L_DEBUG, "Write in socket: %s", &cBuf->buffer[cBuf->headOffset]);
            if(rdLen < 0) {
                log_it(L_ERROR, "Can't write data in socket. %s", strerror(errno));
                return -1;
            }

            if(rdLen < (ssize_t)countBytesToEnd) {
                log_it(L_WARNING, "rdLen < countBytesToEnd");
                dap_cbuf_pop(cBuf, rdLen, NULL);
                return rdLen;
            }

            cBuf->data_size -= countBytesToEnd;
            cBuf->offset_head = 0;
            cBuf->offset_tail = cBuf->data_size - 1;

            ssize_t rdLen2 = send(sockfd,
                         cBuf->buffer,
                         cBuf->data_size, MSG_DONTWAIT | MSG_NOSIGNAL);

            if(rdLen2 < 0) {
                log_it(L_ERROR, "Can't write data in socket. %s", strerror(errno));
                return rdLen;
            }

            cBuf->offset_head = rdLen2;
            if(cBuf->offset_head > cBuf->offset_tail)
            {
                cBuf->offset_head = -1;
                cBuf->offset_tail = -1;
                cBuf->data_size = 0;
            }
            return countBytesToEnd + rdLen2;
        }
    }

    return rdLen;

}

#endif

size_t inter_circularBuffer_read(dap_cbuf_t cBuf, size_t length, void *dataOut, bool resetHead)
{
    if(cBuf->data_size == 0 || length == 0)
        return 0;

    size_t rdLen = length;

    if(cBuf->data_size < rdLen)
        rdLen = cBuf->data_size;


    if(cBuf->offset_head <= cBuf->offset_tail)
    {
        if(dataOut)
            memcpy(dataOut, &cBuf->buffer[cBuf->offset_head], rdLen);

        if(resetHead)
        {
            cBuf->offset_head += rdLen;
            if(cBuf->offset_head > cBuf->offset_tail)
            {
                cBuf->offset_head = -1;
                cBuf->offset_tail = -1;
            }
        }
    }
    else
    {
        if(cBuf->offset_head+rdLen <= cBuf->data_size_max)
        {
            if(dataOut)
                memcpy(dataOut, &cBuf->buffer[cBuf->offset_head], rdLen);

            if(resetHead)
            {
                cBuf->offset_head += rdLen;
                if(cBuf->offset_head == cBuf->data_size_max)
                    cBuf->offset_head = 0;
            }
        }
        else
        {
            size_t frg1Len = cBuf->data_size_max - cBuf->offset_head;
            if(dataOut)
                memcpy(dataOut, &cBuf->buffer[cBuf->offset_head], frg1Len);

            size_t frg2len = rdLen - frg1Len;
            if(dataOut)
                memcpy(dataOut+frg1Len, cBuf->buffer, frg2len);

            if(resetHead)
            {
                cBuf->offset_head = frg2len;
                if(cBuf->offset_head > cBuf->offset_tail)
                {
                    cBuf->offset_head = -1;
                    cBuf->offset_tail = -1;
                }
            }
        }
    }

    if(resetHead)
        cBuf->data_size -= rdLen;

    return rdLen;
}


size_t dap_cbuf_pop(dap_cbuf_t cBuf, size_t length, void *dataOut)
{
    return inter_circularBuffer_read(cBuf,length,dataOut,true);
}

size_t dap_cbuf_read(dap_cbuf_t cBuf, size_t length, void *dataOut)
{
    return inter_circularBuffer_read(cBuf,length,dataOut,false);
}


//print circular buffer's content into str,
void dap_cbuf_print(dap_cbuf_t cBuf, bool hex)
{
    uint8_t *b = cBuf->buffer;
    size_t cSize = dap_cbuf_get_size(cBuf);
    char *str = malloc(2*cSize+1);

    char c;

    for(size_t i=0; i<cSize; i++)
    {
        if(dap_cbuf_get_size(cBuf) == 0)
        {
            c = '_';
        }
        else if (cBuf->offset_tail < cBuf->offset_head)
        {
            if(i>cBuf->offset_tail && i<cBuf->offset_head)
                c = '_';
            else
              c = b[i];
        }
        else
        {
            if(i>cBuf->offset_tail || i<cBuf->offset_head)
                c = '_';
            else
                c = b[i];
        }
        if(hex)
            dap_sprintf(str+i*2, "%02X|",c);
        else
            dap_sprintf(str+i*2, "%c|",c);
    }

    dap_printf("CircularBuffer: %s <size %zu dataSize:%zu>\n",
           str,dap_cbuf_get_size(cBuf),dap_cbuf_get_size_max(cBuf));
    free(str);
}
