#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "iaes_tables.h"
#include "dap_iaes_proto.h"

size_t iaes_calc_block128_size(size_t length_data)
{
    size_t new_length_data = length_data + 1;
    size_t padding = IAES_BLOCK_SIZE - new_length_data % IAES_BLOCK_SIZE;
    new_length_data += padding;
    return new_length_data;
}


void swap_endian(uint32_t *buff, unsigned long len)
{
    unsigned long i;
    for (i = 0; i < len; i ++)
        buff[i] = (buff[i] & 0xff) << 24 ^ ((buff[i] >> 8) & 0xff) << 16 ^ ((buff[i] >> 16) & 0xff) << 8 ^ (buff[i] >> 24);
}

void AES256_enc_cernelT(uint32_t * in, uint32_t * out, uint32_t * masterkey)
{           //first round includes replacement of byte order
    uint32_t t0, t1, t2, t3;
    uint32_t s0, s1, s2, s3;
    uint32_t k0, k1, k2, k3;
    uint32_t k4, k5, k6, k7;
    uint32_t temp;

    /*r1*/	s0 = ((in[0] & 0xff) << 24) ^ ((in[0] >> 8) & 0xff) << 16 ^ ((in[0] >> 16) & 0xff) << 8 ^ (in[0] >> 24) ^ masterkey[0];
            s1 = ((in[1] & 0xff) << 24) ^ ((in[1] >> 8) & 0xff) << 16 ^ ((in[1] >> 16) & 0xff) << 8 ^ (in[1] >> 24) ^ masterkey[1];
            s2 = ((in[2] & 0xff) << 24) ^ ((in[2] >> 8) & 0xff) << 16 ^ ((in[2] >> 16) & 0xff) << 8 ^ (in[2] >> 24) ^ masterkey[2];
            s3 = ((in[3] & 0xff) << 24) ^ ((in[3] >> 8) & 0xff) << 16 ^ ((in[3] >> 16) & 0xff) << 8 ^ (in[3] >> 24) ^ masterkey[3];
            //then canonical aes

            t0 = h_te0[(s0 >> 24) & 0xff] ^ h_te1[(s1 >> 16) & 0xff] ^ h_te2[(s2 >> 8) & 0xff] ^ h_te3[s3 & 0xff] ^ masterkey[4];
            t1 = h_te0[(s1 >> 24) & 0xff] ^ h_te1[(s2 >> 16) & 0xff] ^ h_te2[(s3 >> 8) & 0xff] ^ h_te3[s0 & 0xff] ^ masterkey[5];
            t2 = h_te0[(s2 >> 24) & 0xff] ^ h_te1[(s3 >> 16) & 0xff] ^ h_te2[(s0 >> 8) & 0xff] ^ h_te3[s1 & 0xff] ^ masterkey[6];
            t3 = h_te0[(s3 >> 24) & 0xff] ^ h_te1[(s0 >> 16) & 0xff] ^ h_te2[(s1 >> 8) & 0xff] ^ h_te3[s2 & 0xff] ^ masterkey[7];

     /*k2*/	temp = masterkey[7];
            k0 = masterkey[0] ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[0];
            k1 = masterkey[1] ^ k0;
            k2 = masterkey[2] ^ k1;
            k3 = masterkey[3] ^ k2;

    /*r2*/	s0 = h_te0[(t0 >> 24) & 0xff] ^ h_te1[(t1 >> 16) & 0xff] ^ h_te2[(t2 >> 8) & 0xff] ^ h_te3[t3 & 0xff] ^ k0;
            s1 = h_te0[(t1 >> 24) & 0xff] ^ h_te1[(t2 >> 16) & 0xff] ^ h_te2[(t3 >> 8) & 0xff] ^ h_te3[t0 & 0xff] ^ k1;
            s2 = h_te0[(t2 >> 24) & 0xff] ^ h_te1[(t3 >> 16) & 0xff] ^ h_te2[(t0 >> 8) & 0xff] ^ h_te3[t1 & 0xff] ^ k2;
            s3 = h_te0[(t3 >> 24) & 0xff] ^ h_te1[(t0 >> 16) & 0xff] ^ h_te2[(t1 >> 8) & 0xff] ^ h_te3[t2 & 0xff] ^ k3;

    /*k3*/	temp = k3;
            k4 = masterkey[4] ^ (h_te2[(temp >> 24) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 16) & 0xff] & 0x00ff0000) ^ (h_te0[(temp >> 8) & 0xff] & 0x0000ff00) ^ (h_te1[temp & 0xff] & 0x000000ff);
            k5 = masterkey[5] ^ k4;
            k6 = masterkey[6] ^ k5;
            k7 = masterkey[7] ^ k6;

    /*r3*/  t0 = h_te0[(s0 >> 24) & 0xff] ^ h_te1[(s1 >> 16) & 0xff] ^ h_te2[(s2 >> 8) & 0xff] ^ h_te3[s3 & 0xff] ^ k4;
            t1 = h_te0[(s1 >> 24) & 0xff] ^ h_te1[(s2 >> 16) & 0xff] ^ h_te2[(s3 >> 8) & 0xff] ^ h_te3[s0 & 0xff] ^ k5;
            t2 = h_te0[(s2 >> 24) & 0xff] ^ h_te1[(s3 >> 16) & 0xff] ^ h_te2[(s0 >> 8) & 0xff] ^ h_te3[s1 & 0xff] ^ k6;
            t3 = h_te0[(s3 >> 24) & 0xff] ^ h_te1[(s0 >> 16) & 0xff] ^ h_te2[(s1 >> 8) & 0xff] ^ h_te3[s2 & 0xff] ^ k7;

    /*k4*/	temp = k7;
            k0 = k0 ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[1];
            k1 = k1 ^ k0;
            k2 = k2 ^ k1;
            k3 = k3 ^ k2;

    /*r4*/	s0 = h_te0[(t0 >> 24) & 0xff] ^ h_te1[(t1 >> 16) & 0xff] ^ h_te2[(t2 >> 8) & 0xff] ^ h_te3[t3 & 0xff] ^ k0;
            s1 = h_te0[(t1 >> 24) & 0xff] ^ h_te1[(t2 >> 16) & 0xff] ^ h_te2[(t3 >> 8) & 0xff] ^ h_te3[t0 & 0xff] ^ k1;
            s2 = h_te0[(t2 >> 24) & 0xff] ^ h_te1[(t3 >> 16) & 0xff] ^ h_te2[(t0 >> 8) & 0xff] ^ h_te3[t1 & 0xff] ^ k2;
            s3 = h_te0[(t3 >> 24) & 0xff] ^ h_te1[(t0 >> 16) & 0xff] ^ h_te2[(t1 >> 8) & 0xff] ^ h_te3[t2 & 0xff] ^ k3;

    /*k5*/	temp = k3;
            k4 = k4 ^ (h_te2[(temp >> 24) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 16) & 0xff] & 0x00ff0000) ^ (h_te0[(temp >> 8) & 0xff] & 0x0000ff00) ^ (h_te1[temp & 0xff] & 0x000000ff);
            k5 = k5 ^ k4;
            k6 = k6 ^ k5;
            k7 = k7 ^ k6;

    /*r5*/	t0 = h_te0[(s0 >> 24) & 0xff] ^ h_te1[(s1 >> 16) & 0xff] ^ h_te2[(s2 >> 8) & 0xff] ^ h_te3[s3 & 0xff] ^ k4;
            t1 = h_te0[(s1 >> 24) & 0xff] ^ h_te1[(s2 >> 16) & 0xff] ^ h_te2[(s3 >> 8) & 0xff] ^ h_te3[s0 & 0xff] ^ k5;
            t2 = h_te0[(s2 >> 24) & 0xff] ^ h_te1[(s3 >> 16) & 0xff] ^ h_te2[(s0 >> 8) & 0xff] ^ h_te3[s1 & 0xff] ^ k6;
            t3 = h_te0[(s3 >> 24) & 0xff] ^ h_te1[(s0 >> 16) & 0xff] ^ h_te2[(s1 >> 8) & 0xff] ^ h_te3[s2 & 0xff] ^ k7;

    /*k6*/	temp = k7;
            k0 = k0 ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[2];
            k1 = k1 ^ k0;
            k2 = k2 ^ k1;
            k3 = k3 ^ k2;

    /*r6*/	s0 = h_te0[(t0 >> 24) & 0xff] ^ h_te1[(t1 >> 16) & 0xff] ^ h_te2[(t2 >> 8) & 0xff] ^ h_te3[t3 & 0xff] ^ k0;
            s1 = h_te0[(t1 >> 24) & 0xff] ^ h_te1[(t2 >> 16) & 0xff] ^ h_te2[(t3 >> 8) & 0xff] ^ h_te3[t0 & 0xff] ^ k1;
            s2 = h_te0[(t2 >> 24) & 0xff] ^ h_te1[(t3 >> 16) & 0xff] ^ h_te2[(t0 >> 8) & 0xff] ^ h_te3[t1 & 0xff] ^ k2;
            s3 = h_te0[(t3 >> 24) & 0xff] ^ h_te1[(t0 >> 16) & 0xff] ^ h_te2[(t1 >> 8) & 0xff] ^ h_te3[t2 & 0xff] ^ k3;

    /*k7*/	temp = k3;
            k4 = k4 ^ (h_te2[(temp >> 24) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 16) & 0xff] & 0x00ff0000) ^ (h_te0[(temp >> 8) & 0xff] & 0x0000ff00) ^ (h_te1[temp & 0xff] & 0x000000ff);
            k5 = k5 ^ k4;
            k6 = k6 ^ k5;
            k7 = k7 ^ k6;

    /*r7*/  t0 = h_te0[(s0 >> 24) & 0xff] ^ h_te1[(s1 >> 16) & 0xff] ^ h_te2[(s2 >> 8) & 0xff] ^ h_te3[s3 & 0xff] ^ k4;
            t1 = h_te0[(s1 >> 24) & 0xff] ^ h_te1[(s2 >> 16) & 0xff] ^ h_te2[(s3 >> 8) & 0xff] ^ h_te3[s0 & 0xff] ^ k5;
            t2 = h_te0[(s2 >> 24) & 0xff] ^ h_te1[(s3 >> 16) & 0xff] ^ h_te2[(s0 >> 8) & 0xff] ^ h_te3[s1 & 0xff] ^ k6;
            t3 = h_te0[(s3 >> 24) & 0xff] ^ h_te1[(s0 >> 16) & 0xff] ^ h_te2[(s1 >> 8) & 0xff] ^ h_te3[s2 & 0xff] ^ k7;

    /*k8*/	temp = k7;
            k0 = k0 ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[3];
            k1 = k1 ^ k0;
            k2 = k2 ^ k1;
            k3 = k3 ^ k2;

    /*r8*/	s0 = h_te0[(t0 >> 24) & 0xff] ^ h_te1[(t1 >> 16) & 0xff] ^ h_te2[(t2 >> 8) & 0xff] ^ h_te3[t3 & 0xff] ^ k0;
            s1 = h_te0[(t1 >> 24) & 0xff] ^ h_te1[(t2 >> 16) & 0xff] ^ h_te2[(t3 >> 8) & 0xff] ^ h_te3[t0 & 0xff] ^ k1;
            s2 = h_te0[(t2 >> 24) & 0xff] ^ h_te1[(t3 >> 16) & 0xff] ^ h_te2[(t0 >> 8) & 0xff] ^ h_te3[t1 & 0xff] ^ k2;
            s3 = h_te0[(t3 >> 24) & 0xff] ^ h_te1[(t0 >> 16) & 0xff] ^ h_te2[(t1 >> 8) & 0xff] ^ h_te3[t2 & 0xff] ^ k3;

     /*k9*/	temp = k3;
            k4 = k4 ^ (h_te2[(temp >> 24) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 16) & 0xff] & 0x00ff0000) ^ (h_te0[(temp >> 8) & 0xff] & 0x0000ff00) ^ (h_te1[temp & 0xff] & 0x000000ff);
            k5 = k5 ^ k4;
            k6 = k6 ^ k5;
            k7 = k7 ^ k6;

    /*r9*/	t0 = h_te0[(s0 >> 24) & 0xff] ^ h_te1[(s1 >> 16) & 0xff] ^ h_te2[(s2 >> 8) & 0xff] ^ h_te3[s3 & 0xff] ^ k4;
            t1 = h_te0[(s1 >> 24) & 0xff] ^ h_te1[(s2 >> 16) & 0xff] ^ h_te2[(s3 >> 8) & 0xff] ^ h_te3[s0 & 0xff] ^ k5;
            t2 = h_te0[(s2 >> 24) & 0xff] ^ h_te1[(s3 >> 16) & 0xff] ^ h_te2[(s0 >> 8) & 0xff] ^ h_te3[s1 & 0xff] ^ k6;
            t3 = h_te0[(s3 >> 24) & 0xff] ^ h_te1[(s0 >> 16) & 0xff] ^ h_te2[(s1 >> 8) & 0xff] ^ h_te3[s2 & 0xff] ^ k7;

    /*k10*/	temp = k7;
            k0 = k0 ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[4];
            k1 = k1 ^ k0;
            k2 = k2 ^ k1;
            k3 = k3 ^ k2;

    /*r10*/	s0 = h_te0[(t0 >> 24) & 0xff] ^ h_te1[(t1 >> 16) & 0xff] ^ h_te2[(t2 >> 8) & 0xff] ^ h_te3[t3 & 0xff] ^ k0;
            s1 = h_te0[(t1 >> 24) & 0xff] ^ h_te1[(t2 >> 16) & 0xff] ^ h_te2[(t3 >> 8) & 0xff] ^ h_te3[t0 & 0xff] ^ k1;
            s2 = h_te0[(t2 >> 24) & 0xff] ^ h_te1[(t3 >> 16) & 0xff] ^ h_te2[(t0 >> 8) & 0xff] ^ h_te3[t1 & 0xff] ^ k2;
            s3 = h_te0[(t3 >> 24) & 0xff] ^ h_te1[(t0 >> 16) & 0xff] ^ h_te2[(t1 >> 8) & 0xff] ^ h_te3[t2 & 0xff] ^ k3;

    /*k11*/	temp = k3;
            k4 = k4 ^ (h_te2[(temp >> 24) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 16) & 0xff] & 0x00ff0000) ^ (h_te0[(temp >> 8) & 0xff] & 0x0000ff00) ^ (h_te1[temp & 0xff] & 0x000000ff);
            k5 = k5 ^ k4;
            k6 = k6 ^ k5;
            k7 = k7 ^ k6;

    /*r11*/	t0 = h_te0[(s0 >> 24) & 0xff] ^ h_te1[(s1 >> 16) & 0xff] ^ h_te2[(s2 >> 8) & 0xff] ^ h_te3[s3 & 0xff] ^ k4;
            t1 = h_te0[(s1 >> 24) & 0xff] ^ h_te1[(s2 >> 16) & 0xff] ^ h_te2[(s3 >> 8) & 0xff] ^ h_te3[s0 & 0xff] ^ k5;
            t2 = h_te0[(s2 >> 24) & 0xff] ^ h_te1[(s3 >> 16) & 0xff] ^ h_te2[(s0 >> 8) & 0xff] ^ h_te3[s1 & 0xff] ^ k6;
            t3 = h_te0[(s3 >> 24) & 0xff] ^ h_te1[(s0 >> 16) & 0xff] ^ h_te2[(s1 >> 8) & 0xff] ^ h_te3[s2 & 0xff] ^ k7;

    /*k12*/	temp = k7;
            k0 = k0 ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[5];
            k1 = k1 ^ k0;
            k2 = k2 ^ k1;
            k3 = k3 ^ k2;

    /*r12*/	s0 = h_te0[(t0 >> 24) & 0xff] ^ h_te1[(t1 >> 16) & 0xff] ^ h_te2[(t2 >> 8) & 0xff] ^ h_te3[t3 & 0xff] ^ k0;
            s1 = h_te0[(t1 >> 24) & 0xff] ^ h_te1[(t2 >> 16) & 0xff] ^ h_te2[(t3 >> 8) & 0xff] ^ h_te3[t0 & 0xff] ^ k1;
            s2 = h_te0[(t2 >> 24) & 0xff] ^ h_te1[(t3 >> 16) & 0xff] ^ h_te2[(t0 >> 8) & 0xff] ^ h_te3[t1 & 0xff] ^ k2;
            s3 = h_te0[(t3 >> 24) & 0xff] ^ h_te1[(t0 >> 16) & 0xff] ^ h_te2[(t1 >> 8) & 0xff] ^ h_te3[t2 & 0xff] ^ k3;

    /*k13*/	temp = k3;
            k4 = k4 ^ (h_te2[(temp >> 24) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 16) & 0xff] & 0x00ff0000) ^ (h_te0[(temp >> 8) & 0xff] & 0x0000ff00) ^ (h_te1[temp & 0xff] & 0x000000ff);
            k5 = k5 ^ k4;
            k6 = k6 ^ k5;
            k7 = k7 ^ k6;

    /*r13*/	t0 = h_te0[(s0 >> 24) & 0xff] ^ h_te1[(s1 >> 16) & 0xff] ^ h_te2[((s2 >> 8) & 0xff)] ^ h_te3[(s3 & 0xff)] ^ k4;
            t1 = h_te0[(s1 >> 24) & 0xff] ^ h_te1[(s2 >> 16) & 0xff] ^ h_te2[((s3 >> 8) & 0xff)] ^ h_te3[(s0 & 0xff)] ^ k5;
            t2 = h_te0[(s2 >> 24) & 0xff] ^ h_te1[(s3 >> 16) & 0xff] ^ h_te2[((s0 >> 8) & 0xff)] ^ h_te3[(s1 & 0xff)] ^ k6;
            t3 = h_te0[(s3 >> 24) & 0xff] ^ h_te1[(s0 >> 16) & 0xff] ^ h_te2[((s1 >> 8) & 0xff)] ^ h_te3[(s2 & 0xff)] ^ k7;

    /*k14*/	temp = k7;
            k0 = k0 ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[6];
            k1 = k1 ^ k0;
            k2 = k2 ^ k1;
            k3 = k3 ^ k2;

    /*r14*/	out[0] = (h_te4[(t0 >> 24) & 0xff] & 0xff000000) ^ (h_te4[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (h_te4[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (h_te4[(t3 & 0xff)] & 0x000000ff) ^ k0;
            out[1] = (h_te4[(t1 >> 24) & 0xff] & 0xff000000) ^ (h_te4[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (h_te4[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (h_te4[(t0 & 0xff)] & 0x000000ff) ^ k1;
            out[2] = (h_te4[(t2 >> 24) & 0xff] & 0xff000000) ^ (h_te4[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (h_te4[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (h_te4[(t1 & 0xff)] & 0x000000ff) ^ k2;
            out[3] = (h_te4[(t3 >> 24) & 0xff] & 0xff000000) ^ (h_te4[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (h_te4[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (h_te4[(t2 & 0xff)] & 0x000000ff) ^ k3;
            //inverse byte order replacement
            swap_endian(out,4);
}



void IAES_256_CBC_encrypt(const uint8_t *data, uint8_t *cdata, uint8_t *ivec, unsigned long length, uint8_t *masterkey)
{
    size_t block_in32_size = IAES_BLOCK_SIZE/sizeof(uint32_t);
    uint32_t feedback[block_in32_size];

    memcpy(&feedback[0], ivec, IAES_BLOCK_SIZE);
    swap_endian((uint32_t *)masterkey, IAES_KEYSIZE/sizeof(uint32_t));

    size_t count_block, count32_word;
    for(count_block = 0; count_block < length/IAES_BLOCK_SIZE; count_block++)
    {
        for (count32_word = 0; count32_word < block_in32_size; count32_word++)
           *((uint32_t *)cdata + count_block * block_in32_size + count32_word) =
                *((uint32_t *)data + count_block * block_in32_size + count32_word) ^ feedback[count32_word];

        AES256_enc_cernelT(((uint32_t *)cdata + count_block * block_in32_size), feedback, (uint32_t *)masterkey);

        memcpy ((uint32_t *)cdata + count_block * block_in32_size, &feedback[0], IAES_BLOCK_SIZE);
    }
    swap_endian((uint32_t *)masterkey,IAES_KEYSIZE/sizeof(uint32_t));
}



void Key_Shedule_for_decrypT(uint32_t * key, uint32_t * rounds_keys)

{
    uint32_t master_key[IAES_KEYSIZE/sizeof(uint32_t)];
    memcpy(master_key, key, IAES_KEYSIZE);

    rounds_keys[56] = master_key[0];
    rounds_keys[57] = master_key[1];
    rounds_keys[58] = master_key[2];
    rounds_keys[59] = master_key[3];

    rounds_keys[52] = h_td0[h_te1[(master_key[4] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[4] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[4] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[4] & 0xff] & 0xff];
    rounds_keys[53] = h_td0[h_te1[(master_key[5] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[5] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[5] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[5] & 0xff] & 0xff];
    rounds_keys[54] = h_td0[h_te1[(master_key[6] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[6] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[6] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[6] & 0xff] & 0xff];
    rounds_keys[55] = h_td0[h_te1[(master_key[7] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[7] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[7] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[7] & 0xff] & 0xff];

    uint32_t temp = master_key[7];
    master_key[0] = master_key[0] ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[0];
    master_key[1] = master_key[1] ^ master_key[0];
    master_key[2] = master_key[2] ^ master_key[1];
    master_key[3] = master_key[3] ^ master_key[2];

    rounds_keys[48] = h_td0[h_te1[(master_key[0] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[0] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[0] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[0] & 0xff] & 0xff];
    rounds_keys[49] = h_td0[h_te1[(master_key[1] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[1] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[1] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[1] & 0xff] & 0xff];
    rounds_keys[50] = h_td0[h_te1[(master_key[2] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[2] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[2] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[2] & 0xff] & 0xff];
    rounds_keys[51] = h_td0[h_te1[(master_key[3] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[3] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[3] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[3] & 0xff] & 0xff];

    temp = master_key[3];
    master_key[4] = master_key[4] ^ (h_te2[(temp >> 24) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 16) & 0xff] & 0x00ff0000) ^ (h_te0[(temp >> 8) & 0xff] & 0x0000ff00) ^ (h_te1[temp & 0xff] & 0x000000ff);
    master_key[5] = master_key[5] ^ master_key[4];
    master_key[6] = master_key[6] ^ master_key[5];
    rounds_keys[44] = h_td0[h_te1[(master_key[4] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[4] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[4] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[4] & 0xff] & 0xff];
    master_key[7] = master_key[7] ^ master_key[6];

    rounds_keys[45] = h_td0[h_te1[(master_key[5] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[5] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[5] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[5] & 0xff] & 0xff];
    rounds_keys[46] = h_td0[h_te1[(master_key[6] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[6] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[6] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[6] & 0xff] & 0xff];
    rounds_keys[47] = h_td0[h_te1[(master_key[7] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[7] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[7] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[7] & 0xff] & 0xff];


    temp = master_key[7];
    master_key[0] = master_key[0] ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[1];
    master_key[1] = master_key[1] ^ master_key[0];
    master_key[2] = master_key[2] ^ master_key[1];
    master_key[3] = master_key[3] ^ master_key[2];

    rounds_keys[40] = h_td0[h_te1[(master_key[0] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[0] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[0] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[0] & 0xff] & 0xff];
    rounds_keys[41] = h_td0[h_te1[(master_key[1] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[1] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[1] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[1] & 0xff] & 0xff];
    rounds_keys[42] = h_td0[h_te1[(master_key[2] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[2] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[2] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[2] & 0xff] & 0xff];
    rounds_keys[43] = h_td0[h_te1[(master_key[3] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[3] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[3] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[3] & 0xff] & 0xff];


    temp = master_key[3];
    master_key[4] = master_key[4] ^ (h_te2[(temp >> 24) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 16) & 0xff] & 0x00ff0000) ^ (h_te0[(temp >> 8) & 0xff] & 0x0000ff00) ^ (h_te1[temp & 0xff] & 0x000000ff);
    master_key[5] = master_key[5] ^ master_key[4];
    master_key[6] = master_key[6] ^ master_key[5];
    master_key[7] = master_key[7] ^ master_key[6];

    rounds_keys[36] = h_td0[h_te1[(master_key[4] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[4] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[4] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[4] & 0xff] & 0xff];
    rounds_keys[37] = h_td0[h_te1[(master_key[5] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[5] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[5] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[5] & 0xff] & 0xff];
    rounds_keys[38] = h_td0[h_te1[(master_key[6] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[6] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[6] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[6] & 0xff] & 0xff];
    rounds_keys[39] = h_td0[h_te1[(master_key[7] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[7] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[7] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[7] & 0xff] & 0xff];

    temp = master_key[7];
    master_key[0] = master_key[0] ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[2];
    master_key[1] = master_key[1] ^ master_key[0];
    master_key[2] = master_key[2] ^ master_key[1];
    master_key[3] = master_key[3] ^ master_key[2];

    rounds_keys[32] = h_td0[h_te1[(master_key[0] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[0] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[0] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[0] & 0xff] & 0xff];
    rounds_keys[33] = h_td0[h_te1[(master_key[1] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[1] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[1] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[1] & 0xff] & 0xff];
    rounds_keys[34] = h_td0[h_te1[(master_key[2] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[2] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[2] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[2] & 0xff] & 0xff];
    rounds_keys[35] = h_td0[h_te1[(master_key[3] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[3] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[3] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[3] & 0xff] & 0xff];


    temp = master_key[3];
    master_key[4] = master_key[4] ^ (h_te2[(temp >> 24) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 16) & 0xff] & 0x00ff0000) ^ (h_te0[(temp >> 8) & 0xff] & 0x0000ff00) ^ (h_te1[temp & 0xff] & 0x000000ff);
    master_key[5] = master_key[5] ^ master_key[4];
    master_key[6] = master_key[6] ^ master_key[5];
    master_key[7] = master_key[7] ^ master_key[6];

    rounds_keys[28] = h_td0[h_te1[(master_key[4] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[4] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[4] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[4] & 0xff] & 0xff];
    rounds_keys[29] = h_td0[h_te1[(master_key[5] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[5] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[5] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[5] & 0xff] & 0xff];
    rounds_keys[30] = h_td0[h_te1[(master_key[6] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[6] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[6] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[6] & 0xff] & 0xff];
    rounds_keys[31] = h_td0[h_te1[(master_key[7] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[7] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[7] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[7] & 0xff] & 0xff];

    temp = master_key[7];
    master_key[0] = master_key[0] ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[3];
    master_key[1] = master_key[1] ^ master_key[0];
    master_key[2] = master_key[2] ^ master_key[1];
    master_key[3] = master_key[3] ^ master_key[2];

    rounds_keys[24] = h_td0[h_te1[(master_key[0] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[0] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[0] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[0] & 0xff] & 0xff];
    rounds_keys[25] = h_td0[h_te1[(master_key[1] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[1] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[1] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[1] & 0xff] & 0xff];
    rounds_keys[26] = h_td0[h_te1[(master_key[2] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[2] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[2] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[2] & 0xff] & 0xff];
    rounds_keys[27] = h_td0[h_te1[(master_key[3] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[3] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[3] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[3] & 0xff] & 0xff];

    temp = master_key[3];
    master_key[4] = master_key[4] ^ (h_te2[(temp >> 24) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 16) & 0xff] & 0x00ff0000) ^ (h_te0[(temp >> 8) & 0xff] & 0x0000ff00) ^ (h_te1[temp & 0xff] & 0x000000ff);
    master_key[5] = master_key[5] ^ master_key[4];
    master_key[6] = master_key[6] ^ master_key[5];
    master_key[7] = master_key[7] ^ master_key[6];

    rounds_keys[20] = h_td0[h_te1[(master_key[4] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[4] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[4] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[4] & 0xff] & 0xff];
    rounds_keys[21] = h_td0[h_te1[(master_key[5] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[5] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[5] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[5] & 0xff] & 0xff];
    rounds_keys[22] = h_td0[h_te1[(master_key[6] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[6] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[6] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[6] & 0xff] & 0xff];
    rounds_keys[23] = h_td0[h_te1[(master_key[7] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[7] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[7] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[7] & 0xff] & 0xff];

    temp = master_key[7];
    master_key[0] = master_key[0] ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[4];
    master_key[1] = master_key[1] ^ master_key[0];
    master_key[2] = master_key[2] ^ master_key[1];
    master_key[3] = master_key[3] ^ master_key[2];

    rounds_keys[16] = h_td0[h_te1[(master_key[0] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[0] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[0] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[0] & 0xff] & 0xff];
    rounds_keys[17] = h_td0[h_te1[(master_key[1] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[1] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[1] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[1] & 0xff] & 0xff];
    rounds_keys[18] = h_td0[h_te1[(master_key[2] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[2] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[2] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[2] & 0xff] & 0xff];
    rounds_keys[19] = h_td0[h_te1[(master_key[3] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[3] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[3] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[3] & 0xff] & 0xff];

    temp = master_key[3];
    master_key[4] = master_key[4] ^ (h_te2[(temp >> 24) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 16) & 0xff] & 0x00ff0000) ^ (h_te0[(temp >> 8) & 0xff] & 0x0000ff00) ^ (h_te1[temp & 0xff] & 0x000000ff);
    master_key[5] = master_key[5] ^ master_key[4];
    master_key[6] = master_key[6] ^ master_key[5];
    master_key[7] = master_key[7] ^ master_key[6];

    rounds_keys[12] = h_td0[h_te1[(master_key[4] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[4] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[4] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[4] & 0xff] & 0xff];
    rounds_keys[13] = h_td0[h_te1[(master_key[5] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[5] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[5] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[5] & 0xff] & 0xff];
    rounds_keys[14] = h_td0[h_te1[(master_key[6] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[6] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[6] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[6] & 0xff] & 0xff];
    rounds_keys[15] = h_td0[h_te1[(master_key[7] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[7] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[7] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[7] & 0xff] & 0xff];

    temp = master_key[7];
    master_key[0] = master_key[0] ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[5];
    master_key[1] = master_key[1] ^ master_key[0];
    master_key[2] = master_key[2] ^ master_key[1];
    master_key[3] = master_key[3] ^ master_key[2];

    rounds_keys[8]  = h_td0[h_te1[(master_key[0] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[0] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[0] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[0] & 0xff] & 0xff];
    rounds_keys[9]  = h_td0[h_te1[(master_key[1] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[1] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[1] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[1] & 0xff] & 0xff];
    rounds_keys[10] = h_td0[h_te1[(master_key[2] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[2] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[2] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[2] & 0xff] & 0xff];
    rounds_keys[11] = h_td0[h_te1[(master_key[3] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[3] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[3] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[3] & 0xff] & 0xff];

    temp = master_key[3];
    master_key[4] = master_key[4] ^ (h_te2[(temp >> 24) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 16) & 0xff] & 0x00ff0000) ^ (h_te0[(temp >> 8) & 0xff] & 0x0000ff00) ^ (h_te1[temp & 0xff] & 0x000000ff);
    master_key[5] = master_key[5] ^ master_key[4];
    master_key[6] = master_key[6] ^ master_key[5];
    master_key[7] = master_key[7] ^ master_key[6];

    rounds_keys[4] = h_td0[h_te1[(master_key[4] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[4] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[4] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[4] & 0xff] & 0xff];
    rounds_keys[5] = h_td0[h_te1[(master_key[5] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[5] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[5] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[5] & 0xff] & 0xff];
    rounds_keys[6] = h_td0[h_te1[(master_key[6] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[6] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[6] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[6] & 0xff] & 0xff];
    rounds_keys[7] = h_td0[h_te1[(master_key[7] >> 24) & 0xff] & 0xff] ^ h_td1[h_te1[(master_key[7] >> 16) & 0xff] & 0xff] ^ h_td2[h_te1[(master_key[7] >> 8) & 0xff] & 0xff] ^ h_td3[h_te1[master_key[7] & 0xff] & 0xff];

    temp = master_key[7];
    master_key[0] = master_key[0] ^ (h_te2[(temp >> 16) & 0xff] & 0xff000000) ^ (h_te3[(temp >> 8) & 0xff] & 0x00ff0000) ^ (h_te0[temp & 0xff] & 0x0000ff00) ^ (h_te1[(temp >> 24) & 0xff] & 0x000000ff) ^ rcon[6];
    master_key[1] = master_key[1] ^ master_key[0];
    master_key[2] = master_key[2] ^ master_key[1];
    master_key[3] = master_key[3] ^ master_key[2];
    rounds_keys[0] = master_key[0];
    rounds_keys[1] = master_key[1];
    rounds_keys[2] = master_key[2];
    rounds_keys[3] = master_key[3];

}


void AES256_dec_cernelT(uint32_t * in, uint32_t * out, uint32_t * decr_key)
{/*r1-xor*/
    uint32_t t0, t1, t2, t3;
    uint32_t s0, s1, s2, s3;
    //first round includes replacement of byte order
    s0 = ((in[0] & 0xff) << 24) ^ ((in[0] >> 8) & 0xff) << 16 ^ ((in[0] >> 16) & 0xff) << 8 ^ (in[0] >> 24) ^ decr_key[0];
    s1 = ((in[1] & 0xff) << 24) ^ ((in[1] >> 8) & 0xff) << 16 ^ ((in[1] >> 16) & 0xff) << 8 ^ (in[1] >> 24) ^ decr_key[1];
    s2 = ((in[2] & 0xff) << 24) ^ ((in[2] >> 8) & 0xff) << 16 ^ ((in[2] >> 16) & 0xff) << 8 ^ (in[2] >> 24) ^ decr_key[2];
    s3 = ((in[3] & 0xff) << 24) ^ ((in[3] >> 8) & 0xff) << 16 ^ ((in[3] >> 16) & 0xff) << 8 ^ (in[3] >> 24) ^ decr_key[3];
    //then canonical aes
/*r1*/		t0 = h_td0[(s0 >> 24) & 0xff] ^ h_td1[(s3 >> 16) & 0xff] ^ h_td2[(s2 >> 8) & 0xff] ^ h_td3[s1 & 0xff] ^ decr_key[4];
    t1 = h_td0[(s1 >> 24) & 0xff] ^ h_td1[(s0 >> 16) & 0xff] ^ h_td2[(s3 >> 8) & 0xff] ^ h_td3[s2 & 0xff] ^ decr_key[5];
    t2 = h_td0[(s2 >> 24) & 0xff] ^ h_td1[(s1 >> 16) & 0xff] ^ h_td2[(s0 >> 8) & 0xff] ^ h_td3[s3 & 0xff] ^ decr_key[6];
    t3 = h_td0[(s3 >> 24) & 0xff] ^ h_td1[(s2 >> 16) & 0xff] ^ h_td2[(s1 >> 8) & 0xff] ^ h_td3[s0 & 0xff] ^ decr_key[7];

/*r2*/		s0 = h_td0[(t0 >> 24) & 0xff] ^ h_td1[(t3 >> 16) & 0xff] ^ h_td2[(t2 >> 8) & 0xff] ^ h_td3[t1 & 0xff] ^ decr_key[8];
    s1 = h_td0[(t1 >> 24) & 0xff] ^ h_td1[(t0 >> 16) & 0xff] ^ h_td2[(t3 >> 8) & 0xff] ^ h_td3[t2 & 0xff] ^ decr_key[9];
    s2 = h_td0[(t2 >> 24) & 0xff] ^ h_td1[(t1 >> 16) & 0xff] ^ h_td2[(t0 >> 8) & 0xff] ^ h_td3[t3 & 0xff] ^ decr_key[10];
    s3 = h_td0[(t3 >> 24) & 0xff] ^ h_td1[(t2 >> 16) & 0xff] ^ h_td2[(t1 >> 8) & 0xff] ^ h_td3[t0 & 0xff] ^ decr_key[11];

/*r3*/		t0 = h_td0[(s0 >> 24) & 0xff] ^ h_td1[(s3 >> 16) & 0xff] ^ h_td2[(s2 >> 8) & 0xff] ^ h_td3[s1 & 0xff] ^ decr_key[12];
    t1 = h_td0[(s1 >> 24) & 0xff] ^ h_td1[(s0 >> 16) & 0xff] ^ h_td2[(s3 >> 8) & 0xff] ^ h_td3[s2 & 0xff] ^ decr_key[13];
    t2 = h_td0[(s2 >> 24) & 0xff] ^ h_td1[(s1 >> 16) & 0xff] ^ h_td2[(s0 >> 8) & 0xff] ^ h_td3[s3 & 0xff] ^ decr_key[14];
    t3 = h_td0[(s3 >> 24) & 0xff] ^ h_td1[(s2 >> 16) & 0xff] ^ h_td2[(s1 >> 8) & 0xff] ^ h_td3[s0 & 0xff] ^ decr_key[15];
/*r4*/
    s0 = h_td0[(t0 >> 24) & 0xff] ^ h_td1[(t3 >> 16) & 0xff] ^ h_td2[(t2 >> 8) & 0xff] ^ h_td3[t1 & 0xff] ^ decr_key[16];
    s1 = h_td0[(t1 >> 24) & 0xff] ^ h_td1[(t0 >> 16) & 0xff] ^ h_td2[(t3 >> 8) & 0xff] ^ h_td3[t2 & 0xff] ^ decr_key[17];
    s2 = h_td0[(t2 >> 24) & 0xff] ^ h_td1[(t1 >> 16) & 0xff] ^ h_td2[(t0 >> 8) & 0xff] ^ h_td3[t3 & 0xff] ^ decr_key[18];
    s3 = h_td0[(t3 >> 24) & 0xff] ^ h_td1[(t2 >> 16) & 0xff] ^ h_td2[(t1 >> 8) & 0xff] ^ h_td3[t0 & 0xff] ^ decr_key[19];

/*r5*/		t0 = h_td0[(s0 >> 24) & 0xff] ^ h_td1[(s3 >> 16) & 0xff] ^ h_td2[(s2 >> 8) & 0xff] ^ h_td3[s1 & 0xff] ^ decr_key[20];
    t1 = h_td0[(s1 >> 24) & 0xff] ^ h_td1[(s0 >> 16) & 0xff] ^ h_td2[(s3 >> 8) & 0xff] ^ h_td3[s2 & 0xff] ^ decr_key[21];
    t2 = h_td0[(s2 >> 24) & 0xff] ^ h_td1[(s1 >> 16) & 0xff] ^ h_td2[(s0 >> 8) & 0xff] ^ h_td3[s3 & 0xff] ^ decr_key[22];
    t3 = h_td0[(s3 >> 24) & 0xff] ^ h_td1[(s2 >> 16) & 0xff] ^ h_td2[(s1 >> 8) & 0xff] ^ h_td3[s0 & 0xff] ^ decr_key[23];

/*r6*/	    s0 = h_td0[(t0 >> 24) & 0xff] ^ h_td1[(t3 >> 16) & 0xff] ^ h_td2[(t2 >> 8) & 0xff] ^ h_td3[t1 & 0xff] ^ decr_key[24];
    s1 = h_td0[(t1 >> 24) & 0xff] ^ h_td1[(t0 >> 16) & 0xff] ^ h_td2[(t3 >> 8) & 0xff] ^ h_td3[t2 & 0xff] ^ decr_key[25];
    s2 = h_td0[(t2 >> 24) & 0xff] ^ h_td1[(t1 >> 16) & 0xff] ^ h_td2[(t0 >> 8) & 0xff] ^ h_td3[t3 & 0xff] ^ decr_key[26];
    s3 = h_td0[(t3 >> 24) & 0xff] ^ h_td1[(t2 >> 16) & 0xff] ^ h_td2[(t1 >> 8) & 0xff] ^ h_td3[t0 & 0xff] ^ decr_key[27];

/*r7*/		t0 = h_td0[(s0 >> 24) & 0xff] ^ h_td1[(s3 >> 16) & 0xff] ^ h_td2[(s2 >> 8) & 0xff] ^ h_td3[s1 & 0xff] ^ decr_key[28];
    t1 = h_td0[(s1 >> 24) & 0xff] ^ h_td1[(s0 >> 16) & 0xff] ^ h_td2[(s3 >> 8) & 0xff] ^ h_td3[s2 & 0xff] ^ decr_key[29];
    t2 = h_td0[(s2 >> 24) & 0xff] ^ h_td1[(s1 >> 16) & 0xff] ^ h_td2[(s0 >> 8) & 0xff] ^ h_td3[s3 & 0xff] ^ decr_key[30];
    t3 = h_td0[(s3 >> 24) & 0xff] ^ h_td1[(s2 >> 16) & 0xff] ^ h_td2[(s1 >> 8) & 0xff] ^ h_td3[s0 & 0xff] ^ decr_key[31];

/*r8*/		s0 = h_td0[(t0 >> 24) & 0xff] ^ h_td1[(t3 >> 16) & 0xff] ^ h_td2[(t2 >> 8) & 0xff] ^ h_td3[t1 & 0xff] ^ decr_key[32];
    s1 = h_td0[(t1 >> 24) & 0xff] ^ h_td1[(t0 >> 16) & 0xff] ^ h_td2[(t3 >> 8) & 0xff] ^ h_td3[t2 & 0xff] ^ decr_key[33];
    s2 = h_td0[(t2 >> 24) & 0xff] ^ h_td1[(t1 >> 16) & 0xff] ^ h_td2[(t0 >> 8) & 0xff] ^ h_td3[t3 & 0xff] ^ decr_key[34];
    s3 = h_td0[(t3 >> 24) & 0xff] ^ h_td1[(t2 >> 16) & 0xff] ^ h_td2[(t1 >> 8) & 0xff] ^ h_td3[t0 & 0xff] ^ decr_key[35];

/*r9*/		t0 = h_td0[(s0 >> 24) & 0xff] ^ h_td1[(s3 >> 16) & 0xff] ^ h_td2[(s2 >> 8) & 0xff] ^ h_td3[s1 & 0xff] ^ decr_key[36];
    t1 = h_td0[(s1 >> 24) & 0xff] ^ h_td1[(s0 >> 16) & 0xff] ^ h_td2[(s3 >> 8) & 0xff] ^ h_td3[s2 & 0xff] ^ decr_key[37];
    t2 = h_td0[(s2 >> 24) & 0xff] ^ h_td1[(s1 >> 16) & 0xff] ^ h_td2[(s0 >> 8) & 0xff] ^ h_td3[s3 & 0xff] ^ decr_key[38];
    t3 = h_td0[(s3 >> 24) & 0xff] ^ h_td1[(s2 >> 16) & 0xff] ^ h_td2[(s1 >> 8) & 0xff] ^ h_td3[s0 & 0xff] ^ decr_key[39];

/*r10*/	    s0 = h_td0[(t0 >> 24) & 0xff] ^ h_td1[(t3 >> 16) & 0xff] ^ h_td2[(t2 >> 8) & 0xff] ^ h_td3[t1 & 0xff] ^ decr_key[40];
    s1 = h_td0[(t1 >> 24) & 0xff] ^ h_td1[(t0 >> 16) & 0xff] ^ h_td2[(t3 >> 8) & 0xff] ^ h_td3[t2 & 0xff] ^ decr_key[41];
    s2 = h_td0[(t2 >> 24) & 0xff] ^ h_td1[(t1 >> 16) & 0xff] ^ h_td2[(t0 >> 8) & 0xff] ^ h_td3[t3 & 0xff] ^ decr_key[42];
    s3 = h_td0[(t3 >> 24) & 0xff] ^ h_td1[(t2 >> 16) & 0xff] ^ h_td2[(t1 >> 8) & 0xff] ^ h_td3[t0 & 0xff] ^ decr_key[43];

/*r11*/
    t0 = h_td0[(s0 >> 24) & 0xff] ^ h_td1[(s3 >> 16) & 0xff] ^ h_td2[(s2 >> 8) & 0xff] ^ h_td3[s1 & 0xff] ^ decr_key[44];
    t1 = h_td0[(s1 >> 24) & 0xff] ^ h_td1[(s0 >> 16) & 0xff] ^ h_td2[(s3 >> 8) & 0xff] ^ h_td3[s2 & 0xff] ^ decr_key[45];
    t2 = h_td0[(s2 >> 24) & 0xff] ^ h_td1[(s1 >> 16) & 0xff] ^ h_td2[(s0 >> 8) & 0xff] ^ h_td3[s3 & 0xff] ^ decr_key[46];
    t3 = h_td0[(s3 >> 24) & 0xff] ^ h_td1[(s2 >> 16) & 0xff] ^ h_td2[(s1 >> 8) & 0xff] ^ h_td3[s0 & 0xff] ^ decr_key[47];

/*r12*/		s0 = h_td0[(t0 >> 24) & 0xff] ^ h_td1[(t3 >> 16) & 0xff] ^ h_td2[(t2 >> 8) & 0xff] ^ h_td3[t1 & 0xff] ^ decr_key[48];
    s1 = h_td0[(t1 >> 24) & 0xff] ^ h_td1[(t0 >> 16) & 0xff] ^ h_td2[(t3 >> 8) & 0xff] ^ h_td3[t2 & 0xff] ^ decr_key[49];
    s2 = h_td0[(t2 >> 24) & 0xff] ^ h_td1[(t1 >> 16) & 0xff] ^ h_td2[(t0 >> 8) & 0xff] ^ h_td3[t3 & 0xff] ^ decr_key[50];
    s3 = h_td0[(t3 >> 24) & 0xff] ^ h_td1[(t2 >> 16) & 0xff] ^ h_td2[(t1 >> 8) & 0xff] ^ h_td3[t0 & 0xff] ^ decr_key[51];

/*r13*/		t0 = h_td0[(s0 >> 24) & 0xff] ^ h_td1[(s3 >> 16) & 0xff] ^ h_td2[(s2 >> 8) & 0xff] ^ h_td3[s1 & 0xff] ^ decr_key[52];
    t1 = h_td0[(s1 >> 24) & 0xff] ^ h_td1[(s0 >> 16) & 0xff] ^ h_td2[(s3 >> 8) & 0xff] ^ h_td3[s2 & 0xff] ^ decr_key[53];
    t2 = h_td0[(s2 >> 24) & 0xff] ^ h_td1[(s1 >> 16) & 0xff] ^ h_td2[(s0 >> 8) & 0xff] ^ h_td3[s3 & 0xff] ^ decr_key[54];
    t3 = h_td0[(s3 >> 24) & 0xff] ^ h_td1[(s2 >> 16) & 0xff] ^ h_td2[(s1 >> 8) & 0xff] ^ h_td3[s0 & 0xff] ^ decr_key[55];
/*r14*/
    out[0] = (h_td4[(t0 >> 24) & 0xff] & 0xff000000) ^ (h_td4[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (h_td4[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (h_td4[t1 & 0xff] & 0x000000ff) ^ decr_key[56];
    out[1] = (h_td4[(t1 >> 24) & 0xff] & 0xff000000) ^ (h_td4[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (h_td4[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (h_td4[t2 & 0xff] & 0x000000ff) ^ decr_key[57];
    out[2] = (h_td4[(t2 >> 24) & 0xff] & 0xff000000) ^ (h_td4[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (h_td4[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (h_td4[t3 & 0xff] & 0x000000ff) ^ decr_key[58];
    out[3] = (h_td4[(t3 >> 24) & 0xff] & 0xff000000) ^ (h_td4[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (h_td4[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (h_td4[t0 & 0xff] & 0x000000ff) ^ decr_key[59];
    //inverse byte order replacement
    swap_endian(out,4);}


size_t IAES_256_CBC_decrypt(const uint8_t *cdata, uint8_t *data, uint8_t *ivec, unsigned long length, uint8_t *masterkey)
 {
    size_t block_in32_size = IAES_BLOCK_SIZE/sizeof(uint32_t);
    uint32_t round_decrypt_key[60];
    uint32_t feedback[block_in32_size];

    memcpy(&feedback[0], ivec, IAES_BLOCK_SIZE);
    swap_endian((uint32_t *)masterkey, IAES_KEYSIZE/sizeof(uint32_t));
    Key_Shedule_for_decrypT((uint32_t *)masterkey, round_decrypt_key);

    size_t count_block, count32_word;
    for(count_block = 0; count_block < (length/IAES_BLOCK_SIZE); count_block++){

        AES256_dec_cernelT((uint32_t *)cdata + count_block*block_in32_size,
                           (uint32_t *)data + count_block*block_in32_size, round_decrypt_key);

        for (count32_word = 0; count32_word < block_in32_size; count32_word++)
            *((uint32_t *)data + count_block * block_in32_size + count32_word) ^= feedback[count32_word];
        memcpy(&feedback[0], (uint32_t *)cdata + count_block*block_in32_size, IAES_BLOCK_SIZE);
    }
    swap_endian((uint32_t *)masterkey, IAES_KEYSIZE/sizeof(uint32_t));
    return length;
}


