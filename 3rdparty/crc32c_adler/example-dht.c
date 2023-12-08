/*
  TODO describe example
*/
#define _GNU_SOURCE     /* random, srandom*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>      /* open, close etc. */
#include <string.h>     /* memcpy */
#include <netinet/in.h> /* AF_INET, INET_ADDRSTRLEN etc. */
#include <arpa/inet.h>  /* inet_ntop */

#include "crc32c_adler.h"

/* Convert id to hex string of formate used in BEP 42. */
char id_hex_str[20*2+2+1]; /* 20 bytes x 2 characters + 2 x ' ' + '\0' */
const char*
id_to_hex(const unsigned char *id)
{
    //const char* hex_chr = "0123456789ABCDEF";
    const char* hex_chr = "0123456789abcdef";
    for(int i=0,j=0; i < 20 && j < sizeof(id_hex_str)-2; i++) {
        id_hex_str[j++] = hex_chr[ (id[i]>>4) & 0x0F ];
        id_hex_str[j++] = hex_chr[  id[i]     & 0x0F ];
        if (i == 2 || i == 18) {
            id_hex_str[j++] = ' ';
        }
    }
    id_hex_str[sizeof(id_hex_str)-1] = '\0';
    return id_hex_str;
}

/* Generate node ID from IP address + predefined rand using example algorithm
   provided in BEP 42.

   Parameters:
   ip       IPv4 or IPv6 address (network byte order)
   iplen    number of octets to consider in ip (4 or 8)
   id       resulting node ID
   rand     predefined random value */
void crc32c_id(const uint8_t* ip, int iplen, uint8_t id[20], uint32_t rand)
{
    uint8_t v4_mask[] = { 0x03, 0x0f, 0x3f, 0xff };
    uint8_t v6_mask[] = { 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff };
    uint8_t* mask = iplen == 4 ? v4_mask : v6_mask;

    uint8_t ip_copy[8];
    memcpy(ip_copy, ip, iplen);

    for (int i = 0; i < iplen; ++i)
            ip_copy[i] &= mask[i];

    //uint32_t rand = random() & 0xff;
    uint8_t r = rand & 0x7;
    ip_copy[0] |= r << 5;

    uint32_t crc = 0;
    crc = crc32c(crc, ip_copy, iplen);

    /* only take the top 21 bits from crc */
    id[0] = (crc >> 24) & 0xff;
    id[1] = (crc >> 16) & 0xff;
    id[2] = ((crc >> 8) & 0xf8) | (random() & 0x7);
    for (int i = 3; i < 19; ++i) id[i] = random();
    id[19] = rand;
}

/* Find how many bits two ids have in common. */
int common_bits(const unsigned char *id1, const unsigned char *id2)
{
    int i, j;
    unsigned char xor;
    for(i = 0; i < 20; i++) {
        if(id1[i] != id2[i])
            break;
    }

    if(i == 20)
        return 160;

    xor = id1[i] ^ id2[i];

    j = 0;
    while((xor & 0x80) == 0) {
        xor <<= 1;
        j++;
    }

    return 8 * i + j;
}

/* Check if a node ID is correct in the sense of BEP 42. */
int check_id(const uint8_t id1[20], const uint8_t* ip, int iplen, uint32_t rand)
{
    /* Generate ID from IP + rand -> id2. */
    uint8_t id2[20];
    crc32c_id(ip, iplen, id2, rand);

    /* Compare id1 with id2:
       - the first 21 bits must match
       - the last byte must match rand */
    int cbits = common_bits(id1, id2);
    if (cbits < 21) {
        printf("Only the first %i bits match (expected: 21)\n", cbits);
        return 0;
    }
    if (id1[19] != id2[19]) {
        printf("Last byte does not match (expected: %u, got: %u)\n", id2[19], id1[19]);
        return 0;
    }
    return 1;
}

/* Main. */
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* Print which CRC32C algorithm is used. */
    printf("\nUsing %s algorithm.\n\n", crc32c_hw_support() ? "hardware-accelerated (SSE 4.2)" : "software");

    /* Seed random. */
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        perror("open(random)");
        exit(1);
    }
    unsigned seed;
    read(fd, &seed, sizeof(seed));
    srandom(seed);
    close(fd);

    /* Example IP/rand combinations as used in BEP 42. */
    uint8_t ip[5][4] = {
        { 124, 31, 75, 21 },
        { 21, 75, 31, 124 },
        { 65, 23, 51, 170 },
        { 84, 124, 73, 14 },
        { 43, 213, 53, 83 }
    };
    uint32_t rand[] = {
        1,
        86,
        22,
        65,
        90
    };
    int iplen = 4;
    uint8_t id[20];

    printf("IP              rand  Node ID                                    Ok?\n");
    printf("=============== ===== ========================================== ====\n");
    for (int i = 0; i < 5; ++i) {
        crc32c_id(ip[i], iplen, id, rand[i]);
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ip[i], ipstr, sizeof(ipstr));
        printf("%-15s  %2u   %s %s\n", ipstr, rand[i], id_to_hex(id), (check_id(id, ip[i], 4, rand[i]) ? "yes" : "no"));
    }

    return 0;
}
