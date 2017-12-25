#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "enc_key.h"
#include "enc_base64.h"
#include "enc_rsa.h"
#include "enc_sha.h"
#include "enc.h"
#include "Aes.h"

#define LOG_TAG "main"

char * buf_src;
size_t test_size=38915;

//char buf_src[]="Test string as long as it could be - much more than the one cypher block!!!";
//const size_t test_size=sizeof(buf_src);

bool test_enc_func( enc_key_t *key_enc, enc_key_t* key_dec,enc_data_type_t dt)
{
    bool noDiff=true;
    char *buf_crypto , * buf_out;
    size_t buf_crypto_size;
    size_t buf_out_size;
    size_t i;

    buf_crypto=(char*) calloc(1,test_size*4);

    buf_out = (char*) calloc(1,test_size*2);

    buf_crypto_size=enc_code(key_enc,buf_src,test_size,buf_crypto,dt);
    buf_out_size=enc_decode(key_dec,buf_crypto,buf_crypto_size,buf_out,dt);
    for(i=0; i<test_size;i++){
        if(buf_out[i]!=buf_src[i]){
            noDiff=false;
            break;
        }
    }

    free(buf_out);
    free(buf_crypto);

    if(noDiff){
        printf (" passed\n");
        return true;
    }else{
        printf (" ERROR: Output '%s'\n", buf_out );
        exit(1);
    }
    return false;
}

int main (int argc, const char *argv[])
{
    (void) argc;
    (void) argv;
    enc_key_t * key, * key_pub;
    printf("SafeCrypto test\n");

    enc_init();
    printf("-- Init buffers (test data size %lu )\n",test_size);

    printf( "-- Aes_Test %s\n", (Aes_Test()==0)?"passed":"was with ERROR" );

    buf_src=(char*) calloc(1,test_size);

    size_t i;
    for(i=0;i<test_size; i++)
        buf_src[i]=rand()%255;

    /*printf("-- Test FNAM2... ");
    key=enc_key_new(512/8,ENC_KEY_TYPE_FNAM2);
    test_enc_func( key,key, ENC_DATA_TYPE_RAW);
    enc_key_delete(key);

    exit(0);*/

   /* printf("-- Test RSA... ");
    key=enc_key_new(2048,ENC_KEY_TYPE_RSA_PVT);
    key_pub=enc_rsa_pvt_to_pub(key);
    test_enc_func(key_pub,key, ENC_DATA_TYPE_B64);
    enc_key_delete(key);
    enc_key_delete(key_pub);*/

    printf("-- Test AES... ");
    key=enc_key_create("TestPasswW0rdStringAsLongfgsdjgupsidfujp0sijughwrpighjsgjskigjsigh",ENC_KEY_TYPE_AES);
    test_enc_func( key,key, ENC_DATA_TYPE_B64);
    enc_key_delete(key);

    return 0;
}

