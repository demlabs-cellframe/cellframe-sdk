/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "enc.h"
#include "enc_key.h"
#include "common.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define LOG_TAG "enc"

#include <arpa/inet.h>

////////////////////////////////////////// BASE64 PART
static size_t b64_get_encodet_size(size_t in_size);
static size_t b64_get_decodet_size(size_t in_size);
static unsigned char b64_byte_decode(unsigned char b);
static unsigned char b64_byte_encode(unsigned char b);

static void Base64Decode(const char* in, size_t srcLen, unsigned char* out);
static void Base64Encode(const unsigned char* in, size_t srcLen, char* out);

static size_t b64_get_encodet_size(size_t in_size)
{
    return (in_size/3)*4 + ((in_size%3==1) ?2: (in_size%3==2) ? 3:0);
}

static size_t b64_get_decodet_size(size_t in_size)
{
    return (in_size/4)*3 + ((in_size%4==2) ?1: (in_size%5==3) ? 2:0);
}

static unsigned char b64_byte_decode(unsigned char b)
{
    if (( b == '+' ) || (b =='-') )
        return 62;
    if( (b == '/' ) || (b == '_') )
        return 63;
    if( b <= '9' )
        return (b - '0' + 52);
    if(b <= 'Z')
        return (b - 'A');
    return (b - 'a' + 26);
}

static unsigned char b64_byte_encode(unsigned char b)
{
    b &= 0x3f;
    if(b <= 25)
        return (b +'A');
    if(b <= 51)
        return (b - 26 + 'a');
    if(b <= 61)
        return (b - 52 + '0');
    if(b == 62)
        return '-';
    return '_';
}

static void Base64Decode(const char* source, size_t srcLen, unsigned char* out)
{
    unsigned char b1, b2, b3, b4;
    const unsigned char* srcBytes = (unsigned char*)source;
    unsigned char* dest = out;

    size_t dec_length = b64_get_decodet_size(srcLen);
    unsigned char *buffer = (unsigned char*)malloc(dec_length + 1);
    buffer[dec_length] = '\0';

    // walk through the source, taking 4 bytes at a time
    size_t source_index = 0;
    size_t dest_index = 0;
    size_t remaining = srcLen;
    for( ; remaining > 3; remaining -= 4 ) {
        b1 = b64_byte_decode(srcBytes[source_index++]);
        b2 = b64_byte_decode(srcBytes[source_index++]);
        b3 = b64_byte_decode(srcBytes[source_index++]);
        b4 = b64_byte_decode(srcBytes[source_index++]);

        dest[dest_index++] = (unsigned char)( ( b1 << 2 ) | ( b2 >> 4 ) );
        dest[dest_index++] = (unsigned char)( ( b2 << 4 ) | ( b3 >> 2 ) );
        dest[dest_index++] = (unsigned char)( ( b3 << 6 ) | b4 );
    }

    // process the remaining bytes
    b2 = b3 = 0;
    if( remaining > 0 ) {
        b1 = b64_byte_decode( srcBytes[source_index++] );
        if( remaining > 1 )
            b2 = b64_byte_decode( srcBytes[source_index++] );
        if( remaining == 3 )
            b3 = b64_byte_decode( srcBytes[source_index++] );

        dest[dest_index++] = (unsigned char)( ( b1 << 2 ) | ( b2 >> 4 ) );
        if( remaining == 3 )
            dest[dest_index++] = (unsigned char)( ( b2 << 4 ) | ( b3 >> 2 ) );
    }
}

static void Base64Encode(const unsigned char* source, size_t srcLen, char* out)
{
    unsigned char b1, b2, b3;
    unsigned char* dest = (unsigned char*)out;

    // walk through the source, taking 3 bytes at a time
    size_t source_index = 0;
    size_t dest_index = 0;
    size_t remaining = srcLen;
    for( ; remaining > 2; remaining -= 3 ) {
        b1 = source[ source_index++ ];
        b2 = source[ source_index++ ];
        b3 = source[ source_index++ ];
        dest[dest_index++] = b64_byte_encode( (unsigned char)( b1 >> 2 ) );
        dest[dest_index++] = b64_byte_encode( (unsigned char)( ( b1 << 4 ) | ( b2 >> 4 ) ) );
        dest[dest_index++] = b64_byte_encode( (unsigned char)( ( b2 << 2 ) | ( b3 >> 6 ) ) );
        dest[dest_index++] = b64_byte_encode( (unsigned char)b3 );
    }

    // process the remaining bytes
    b2 = 0;
    if( remaining > 0 ) {
        b1 = source[source_index++];
        if( remaining == 2 )
            b2 = source[source_index++];

        dest[dest_index++] = b64_byte_encode( (unsigned char)( b1 >> 2 ) );
        dest[dest_index++] = b64_byte_encode( (unsigned char)( ( b1 << 4 ) | ( b2 >> 4 ) ) );
        if( remaining == 2 )
            dest[dest_index++] = b64_byte_encode( (unsigned char)( b2 << 2 ) );
    }
}

size_t enc_base64_encode(const void * in, size_t in_size, char * out)
{
    size_t ret= b64_get_encodet_size(in_size);
    Base64Encode((const unsigned char*) in, in_size, out);
    out[ret]='\0';
    return ret;
}

size_t enc_base64_decode(const char *in, size_t in_size, void *out)
{
    Base64Decode(in, in_size, (unsigned char*) out);
    return b64_get_decodet_size(in_size);
}
////////////////////////////////////////////////////// end of BASE64 PART

////////////////////////////////////////// AES PART
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "enc_key.h"
typedef unsigned char KeySchedule[4*(14+1)][4];

static int _crypto_inited = 0;

typedef struct enc_aes_key{
    KeySchedule ks;
    unsigned char salt[AES_BLOCK_SIZE*2];
} enc_aes_key_t;

#define ENC_AES_KEY(a) ((enc_aes_key_t *)((a)->internal) )

/**
 * @brief enc_aes_key_new
 * @param key
 */
void enc_aes_key_new(struct enc_key * key)
{
    char str[64];
    int i;
    for(i=0;i<sizeof(str);i++)
        str[i]=64+rand()%30;
    str[sizeof(str)-1]=0;
    enc_aes_key_create(key,str);
}

/**
 * @brief enc_aes_key_new
 * @param key
 */
void enc_aes_key_create(struct enc_key * key, const char *str_key)
{
    key->data_size = strlen(str_key);
    key->data= (unsigned char*) malloc(key->data_size);
    memcpy(key->data, str_key, key->data_size);
    key->internal = calloc(1,sizeof(enc_aes_key_t) );
    key->enc=enc_aes_encode;
    key->dec=enc_aes_decode;

}

void enc_aes_key_delete(struct enc_key *key)
{
    (void) key;
}


size_t enc_aes_decode(struct enc_key* key, const void * in, size_t in_size,void * out)
{
    unsigned char *iv_dec = (unsigned char*)malloc(sizeof(unsigned char) *AES_BLOCK_SIZE);
    memset(iv_dec, 0, sizeof(unsigned char) *AES_BLOCK_SIZE);

    AES_KEY dec_key;
    AES_set_decrypt_key(key->data, 256, &dec_key);
    AES_cbc_encrypt(in, out, in_size,
                    &dec_key,iv_dec, AES_DECRYPT);

    free(iv_dec);

    return in_size;

}

size_t enc_aes_encode(struct enc_key* key, const void * in, size_t in_size,void * out)
{
    size_t ret = (in_size % AES_BLOCK_SIZE) ? ( in_size+ (AES_BLOCK_SIZE- (in_size%AES_BLOCK_SIZE) ) ) : in_size ;

    unsigned char *iv_enc = (unsigned char*) malloc( sizeof(unsigned char) *AES_BLOCK_SIZE);
    memset(iv_enc, 0, sizeof(unsigned char) *AES_BLOCK_SIZE);

    AES_KEY enc_key;
    AES_set_encrypt_key(key->data, 256, &enc_key);
    AES_cbc_encrypt(in, out, in_size, &enc_key,
                    iv_enc, AES_ENCRYPT);

    free(iv_enc);
    return ret;
}

////////////////////////////////////////// end of AES PART

/**
 * @brief enc_init
 * @return
 */
int enc_init()
{
    if (_crypto_inited)
        return 0;
    _crypto_inited = 1;

    srand(time(NULL));

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    return 0;
}


/**
 * @brief enc_code Encode data with key
 * @param key_private Private key
 * @param buf  Input buffer
 * @param buf_size Input buffer size
 * @param buf_out Output buffer
 * @return bytes actualy written in the output buffer
 */
size_t enc_code(struct enc_key * key,const void * buf,const size_t buf_size, void * buf_out, enc_data_type_t data_type_out)
{
    //log_it(NOTICE,"In enc code");
    if(key->enc){
        void *proc_buf;
        switch(data_type_out)
        {
            case ENC_DATA_TYPE_B64:{
                proc_buf=calloc(1,buf_size*2);
            }break;
            case ENC_DATA_TYPE_RAW:{
                proc_buf=buf_out;
            }break;
        }
        size_t ret=key->enc(key,buf,buf_size,proc_buf);
        if(data_type_out==ENC_DATA_TYPE_B64){
            ret=enc_base64_encode(proc_buf,ret,buf_out);
            free(proc_buf);
            return ret;
        }
        return ret;
    }else{
        return 0;
    }
}

/**
 * @brief enc_decode Decode data with key
 * @param key_public Public key
 * @param buf  Input buffer
 * @param buf_size Input buffer size
 * @param buf_out Output buffer
 * @param buf_out_max Maximum size of output buffer
 * @return bytes actualy written in the output buffer
 */
size_t enc_decode(struct enc_key * key,const void * buf, const size_t buf_size, void * buf_out, enc_data_type_t data_type_in)
{
    void *proc_buf;
    const void *proc_buf_const;
    size_t proc_buf_size;
    switch(data_type_in){
        case ENC_DATA_TYPE_B64:{
            proc_buf=calloc(1,buf_size);
            proc_buf_size= enc_base64_decode((const char*) buf,buf_size,proc_buf);
            proc_buf_const=proc_buf;
        }break;
        case ENC_DATA_TYPE_RAW:{
            proc_buf_const=buf;
            proc_buf_size=buf_size;
        }break;
    }

    if(key->dec){
        size_t ret=key->dec(key,proc_buf_const,proc_buf_size,buf_out);
        if(data_type_in==ENC_DATA_TYPE_B64)
            free(proc_buf);
        return ret;
    }else{
        return 0;
    }
}

/**
 * @brief read_key_from_bio
 * @param bio
 * @return
 */
char* read_key_from_bio(BIO * bio)
{
    size_t length = BIO_pending(bio);
    char *buff = (char*)malloc((length + 1)*sizeof(char));
    BIO_read(bio, buff, length);
    buff[length] = '\0';
    return buff;
}


/**
 * @brief bioToString
 * @param bio
 * @param string
 * @details make string from bio
 * @return
 */

int bioToString(BIO *bio, unsigned char **string)
{

    if( bio == NULL)
    {
        log_it(ERROR,"bioToString() BIO == NULL!");
        return -1;
    }

    size_t bioLength = BIO_pending(bio);

    *string = (unsigned char*)malloc(bioLength + 1);

    if(string == NULL)
    {
        log_it(ERROR,"bioToString failed.\n");
        return -1;
    }

    BIO_read(bio, *string, bioLength);

    (*string)[bioLength] = '\0';

    BIO_free_all(bio);

    return (int)bioLength;
}

/**
 * @brief enc_rsa_decode
 * @param key
 * @param in
 * @param in_size
 * @param out
 * @details decode by server local rsa key
 * @return
 */
size_t enc_rsa_decode(struct enc_key* key, const void * in, size_t in_size,void * out)
{
    size_t decrypt_len;

    if(in == NULL)
    {
         log_it(ERROR,"enc_rsa_decode failed (empty message for decode)");
         return 0;
    }

    if(key == NULL)
    {
         log_it(ERROR,"enc_rsa_decode failed (empty key for decode)");
         return 0;
    }

    if((decrypt_len = RSA_private_decrypt(in_size, (unsigned char*)in, (unsigned char*)out,
                                             ((rsa_key_t*)key->internal)->server_key, RSA_PKCS1_PADDING)) == -1)
    {
            log_it(ERROR,"enc_rsa_decode failed (incorrect decode)");
            return 0;
    }

    memset(out + decrypt_len, 0, 1);

    //log_it(INFO, "Decode out = %s",out);

    return decrypt_len;
}


/**
 * @brief enc_rsa_encode
 * @param key
 * @param in
 * @param in_size
 * @param out
 * @details encode by RSA Public key Client
 * @return
 */
size_t enc_rsa_encode(struct enc_key* key, void * in, size_t in_size,void * out)
{
    size_t encrypt_len = 0;

    if(in == NULL || key == NULL)
    {
         log_it(ERROR,"enc_rsa_encode failed");
    }

    if((encrypt_len = RSA_public_encrypt(in_size, (unsigned char*)in, (unsigned char*)out,
                                             (RSA*)((rsa_key_t*)key->internal)->client_public_key, RSA_PKCS1_PADDING)) == -1)
    {
            log_it(ERROR,"enc_rsa_encode Error Encrypt");
            return 0;
    }

    //log_it(INFO,"Encrypt Len = %d",encrypt_len);

    return encrypt_len;
}


/**
 * @brief getRsaKeyFromString
 * @param str_key
 * @param strLen
 * @return
 */
void setRsaPubKeyFromString(char *str_key, size_t strLen, struct enc_key * key)
{
    if(str_key == NULL)
    {
        log_it(ERROR,"getRsaKeyFromString failed");
        return;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, str_key,strLen);

    PEM_read_bio_RSAPublicKey( bio, (void*)&key->internal, NULL, NULL);

    BIO_free_all(bio);

    key->enc = (void*) enc_rsa_encode;
    key->dec = (void*) enc_rsa_decode;

    if ( key == NULL)
    {
        log_it(ERROR,"getRsaKeyFromString failed");
        return;
    }

}


/**
 * @brief getStringPrivateKeyFromRsa
 * @param key
 * @param out
 * @details get string public key from RSA* key ( Allocated memory for ptr )
 * @return
 */
size_t getStringPrivateKeyFromRsa(RSA *key, char **out)
{
    BIO *bio = BIO_new(BIO_s_mem());

    if(key == NULL)
    {
        log_it(ERROR,"getStringPubKeyFromRsa failed");
        return 0;
    }

    PEM_write_bio_RSAPrivateKey(bio,key,NULL,NULL,0,NULL,NULL);

    size_t key_len = BIO_pending(bio);
    *out = malloc(key_len + 1);

    BIO_read(bio, *out, key_len);

    BIO_free_all(bio);

    return key_len;
}


/**
 * @brief getStringPubKeyFromRsa
 * @param key
 * @param out
 * @details get string public key from RSA* key ( Allocated memory for ptr )
 * @return
 */
size_t getStringPubKeyFromRsa(RSA *key, char **out)
{
    BIO *bio = BIO_new(BIO_s_mem());

    if(key == NULL)
    {
        log_it(ERROR,"getStringPubKeyFromRsa failed");
        return 0;
    }

    PEM_write_bio_RSAPublicKey(bio, key);

    size_t key_len = BIO_pending(bio);
    *out = malloc(key_len + 1);

    BIO_read(bio, *out, key_len);
    //out[key_len] = '\0';

    BIO_free_all(bio);

    return key_len;
}


