#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "enc_key.h"
#include "enc_fnam2.h"

void fnam2_crypt(int *key, int key_size,  unsigned long *num_block,  unsigned long b1,unsigned long b2,unsigned long b3,unsigned long b4, void * out );
void fnam2_decrypt(int *key, int key_size, unsigned long *num_block,  unsigned long b1,unsigned long b2,unsigned long b3,unsigned long b4, void * out );

/**
 * @brief enc_fnam2_key_new
 * @param key
 */
void enc_fnam2_key_new(struct enc_key * key)
{
    size_t i;
    for(i=0;i<key->data_size;i++)
        key->data[i] = rand()%255;
}


/**
 * @brief enc_fnam2_decode
 * @param key
 * @param key_size
 * @param in
 * @param in_size
 * @param out
 * @return
 */
size_t enc_fnam2_decode(struct enc_key * key, const void * in, size_t in_size,void * out)
{
    unsigned long num_block=0;
    int key_pos=0;
    const size_t block_size=16;
    const unsigned char * in_ul=(const unsigned char*) in;

    size_t pos;

    for (pos=0;pos<= in_size-block_size; pos+=block_size){
        fnam2_decrypt( (int *) (key->data+key_pos), block_size,&num_block, *((int*)(in_ul+pos)) ,
                     *((int*)(in_ul+pos+4)), *((int*)(in_ul+pos+8)),*((int*)(in_ul+pos+12)),out+pos);
        /*key_pos+=block_size;
        if(key_pos+block_size>=key->data_size)
            key_pos=0;*/
    }

    return pos;
}

/**
 * @brief enc_fnam2_encode
 * @param key
 * @param key_size
 * @param in
 * @param in_size
 * @param out
 * @return
 */
size_t enc_fnam2_encode(struct enc_key * key,const void * in, size_t in_size,void * out)
{
    unsigned long num_block=0;
    int key_pos=0;
    const size_t block_size=16;
    const unsigned char * in_ul=(const unsigned char*) in;

    size_t pos;


    for (pos=0;pos<= in_size-block_size; pos+=block_size){
        fnam2_crypt( (int *) (key->data+key_pos), block_size,&num_block, *((int*)(in_ul+pos)) ,
                     *((int*)(in_ul+pos+4)), *((int*)(in_ul+pos+8)),*((int*)(in_ul+pos+12)),out+pos);
       /* key_pos+=block_size;
        if(key_pos+block_size>=key->data_size)
            key_pos=0;*/
    }

    if(pos<in_size){
        char * buf = (char*) calloc(1,block_size);
        memcpy(buf,in_ul+pos, in_size-pos);
        fnam2_crypt(( int *)(key->data+key_pos), block_size,&num_block, *((int*)(buf)) ,
                     *((int*)(buf+4)), *((int*)(buf+8)),*((int*)(buf+12)),out+pos);
        pos+=block_size;
    }
    return pos;
}

void fnam2_crypt(int *key, int key_size,  unsigned long *num_block,  unsigned long b1,unsigned long b2,unsigned long b3,unsigned long b4, void * out )
{
    int subkey,i,ip,im;
    unsigned long Num=*num_block;
    int r;

    for(r=0;r<key_size*4;r++) {
        //Selecting the part of key for a concrete stage
        i=r%key_size;
        if(i==key_size) {ip=1;im=key_size-1;}
        if(i==1) {ip=2;im=key_size;}
        else {ip=i+1;im=i-1;}

        //Generating the subkey on the basis of nmber part of a key,
        //number of the block in a file and number of a round
        subkey=key[i]*r+(key[im]*Num+key[ip]);

        //F - function
        b1+=(((b2>>16)^((b2<<25)+subkey))+(subkey*(~(b2<<7))));
        b1=~b1;
        r++;

        i=r%key_size;
        if(i==key_size) {ip=1;im=key_size-1;}
        if(i==1) {ip=2;im=key_size;}
        else {ip=i+1;im=i-1;}
        subkey=key[i]*r+(key[im]*Num+key[ip]);
        b2+=(((b3>>16)^((b3<<25)+subkey))+(subkey*(~(b3<<7))));
        b2=~b2;
        r++;

        i=r%key_size;
        if(i==key_size) {ip=1;im=key_size-1;}
        if(i==1) {ip=2;im=key_size;}
        else {ip=i+1;im=i-1;}
        subkey=key[i]*r+(key[im]*Num+key[ip]);
        b3+=(((b4>>16)^((b4<<25)+subkey))+(subkey*(~(b4<<7))));
        b3=~b3;
        r++;

        i=r%key_size;
        if(i==key_size) {ip=1;im=key_size-1;}
        if(i==1) {ip=2;im=key_size;}
        else {ip=i+1;im=i-1;}
        subkey=key[i]*r+(key[im]*Num+key[ip]);
        b4+=(((b1>>16)^((b1<<25)+subkey))+(subkey*(~(b1<<7))));
        b4=~b4;
    }
    Num++;
    *num_block=Num;
    ((unsigned char*)out)[0]=b1;
    ((unsigned char*)out)[1]=b2;
    ((unsigned char*)out)[2]=b3;
    ((unsigned char*)out)[3]=b4;
}

void fnam2_decrypt(int *key, int key_size, unsigned long *num_block,  unsigned long b1,unsigned long b2,unsigned long b3,unsigned long b4, void * out )
{
    int subkey,i,ip,im;
    unsigned long Num=*num_block;
    int r;
    for(r=key_size*sizeof(int)-1;r>=0;r--){
        i=r%key_size;
        if(i==key_size) {ip=1;im=key_size-1;}
        if(i==1) {ip=2;im=key_size;}
        else {ip=i+1;im=i-1;}
        subkey=key[i]*r+(key[im]*Num+key[ip]);
        b4=~b4;
        b4-=(((b1>>16)^((b1<<25)+subkey))+(subkey*(~(b1<<7))));
        r--;

        i=r%key_size;
        if(i==key_size) {ip=1;im=key_size-1;}
        if(i==1) {ip=2;im=key_size;}
        else {ip=i+1;im=i-1;}
        subkey=key[i]*r+(key[im]*Num+key[ip]);
        b3=~b3;
        b3-=(((b4>>16)^((b4<<25)+subkey))+(subkey*(~(b4<<7))));
        r--;

        i=r%key_size;
        if(i==key_size) {ip=1;im=key_size-1;}
        if(i==1) {ip=2;im=key_size;}
        else {ip=i+1;im=i-1;}
        subkey=key[i]*r+(key[im]*Num+key[ip]);
        b2=~b2;
        b2-=(((b3>>16)^((b3<<25)+subkey))+(subkey*(~(b3<<7))));
        r--;

        i=r%key_size;
        if(i==key_size) {ip=1;im=key_size-1;}
        if(i==1) {ip=2;im=key_size;}
        else {ip=i+1;im=i-1;}
        subkey=key[i]*r+(key[im]*Num+key[ip]);
        b1=~b1;
        b1-=(((b2>>16)^((b2<<25)+subkey))+(subkey*(~(b2<<7))));
    }
    Num++;
    *num_block=Num;
    ((unsigned char*)out)[0]=b1;
    ((unsigned char*)out)[1]=b2;
    ((unsigned char*)out)[2]=b3;
    ((unsigned char*)out)[3]=b4;
}
