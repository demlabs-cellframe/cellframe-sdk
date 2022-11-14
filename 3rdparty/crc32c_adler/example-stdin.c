/*
  TODO describe example
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "crc32c_adler.h"

#define SIZE (262144*3)
#define CHUNK SIZE

int main(int argc, char **argv)
{
    char *buf;
    ssize_t got;
    size_t off, n;
    uint32_t crc;

    (void)argv;
    crc = 0;
    buf = malloc(SIZE);
    if (buf == NULL) {
        fputs("out of memory", stderr);
        return 1;
    }
    while ((got = read(0, buf, SIZE)) > 0) {
        off = 0;
        do {
            n = (size_t)got - off;
            if (n > CHUNK)
                n = CHUNK;
            crc = argc > 1 ? crc32c_sw(crc, buf + off, n) :
                             crc32c(crc, buf + off, n);
            off += n;
        } while (off < (size_t)got);
    }
    free(buf);
    if (got == -1) {
        fputs("read error\n", stderr);
        return 1;
    }
    printf("%08x\n", crc);
    return 0;
}
