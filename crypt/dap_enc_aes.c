#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "enc_aes.h"
#include "enc_key.h"
#include "sap_aes.h"

typedef struct enc_aes_key{
    KeySchedule ks;
    byte salt[SALT_LEN*2];
} enc_aes_key_t;

#define ENC_AES_KEY(a) ((enc_aes_key_t *)((a)->internal) )

/**
 * @brief enc_aes_key_new
 * @param key
 */
void enc_aes_key_new(struct enc_key * key)
{
    char str[64];
    size_t i;
    for(i=0;i<sizeof(str);i++)
        str[i]=64+rand()%30;
    str[sizeof(str)-1]=0;
    enc_aes_key_create(key,str);
}

/**
 * @brief enc_aes_key_new
 * @param key
 */
void enc_aes_key_create(struct enc_key * key, const char *password_string)
{
    char *p1;
    char *p2;
    key->data= (unsigned char*) calloc(1,33);
    key->data_size=32;
    key->internal = calloc(1,sizeof(enc_aes_key_t) );
    key->enc=enc_aes_encode;
    key->dec=enc_aes_decode;

    size_t p_len=strlen(password_string)/2;
    p1= calloc(1,p_len+1);
    p2= calloc(1,p_len+1);
    memcpy(p1,password_string,p_len);
    memcpy(p2,password_string+p_len,p_len);

    Aes_KeyFromPassword(256,p1,key->data);
    Aes_KeyFromPassword(256,p2,ENC_AES_KEY(key)->salt);
    Aes_KeyExpansion( key->data , ENC_AES_KEY(key)->ks );
    if (p1)
    	free(p1);
    if (p2)
    	free(p2);
    //Aes_GenSalt(ENC_AES_KEY(key)->salt);
}

void enc_aes_key_delete(struct enc_key *key)
{
    (void) key;
}

/**
 * @brief enc_aes_public_decode
 * @param key
 * @param key_size
 * @param in
 * @param in_size
 * @param out
 * @return
 */
size_t enc_aes_decode(struct enc_key* key, const void * in, size_t in_size,void * out)
{
    memcpy(out,in,in_size);
    Aes_DecryptBlks( out,in_size,ENC_AES_KEY(key)->salt,ENC_AES_KEY(key)->ks );
    return in_size;

}

/**
 * @brief enc_aes_public_encode
 * @param key
 * @param key_size
 * @param in
 * @param in_size
 * @param out
 * @return
 */
size_t enc_aes_encode(struct enc_key* key, const void * in, size_t in_size,void * out)
{
    size_t ret=(in_size%AES_BLOCKSIZE) ? ( in_size+ (AES_BLOCKSIZE- (in_size%AES_BLOCKSIZE) ) ): in_size ;
    memcpy(out,in,in_size);
    if(ret-in_size)
        memset((unsigned char*)out+in_size,0,ret-in_size);
    Aes_EncryptBlks(out,ret,ENC_AES_KEY(key)->salt,ENC_AES_KEY(key)->ks );
    return ret;
}





