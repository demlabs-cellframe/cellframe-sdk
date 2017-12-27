#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "dap_enc_aes.h"
#include "dap_enc_key.h"

#define AES_BLOCKSIZE 16

typedef struct dap_enc_aes_key{
} dap_enc_aes_key_t;

#define DAP_ENC_AES_KEY(a) ((dap_enc_aes_key_t *)((a)->_inheritor) )


/**
 * @brief dap_enc_aes_key_delete
 * @param a_key
 */
void dap_enc_aes_key_delete(struct dap_enc_key *a_key)
{
    (void) a_key;
}

/**
 * @brief dap_enc_aes_key_new_generate
 * @param a_key
 */
void dap_enc_aes_key_new_generate(struct dap_enc_key * a_key)
{

}

/**
 * @brief dap_enc_aes_key_new_from
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
void dap_enc_aes_key_new_from(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size)
{

}


/**
 * @brief dap_enc_aes_decode
 * @param a_key
 * @param a_in
 * @param a_in_size
 * @param a_out
 * @return
 */
size_t dap_enc_aes_decode(struct dap_enc_key* a_key, const void * a_in, size_t a_in_size,void * a_out)
{
    memcpy(a_out,a_in,a_in_size);


    return a_in_size;
}

/**
 * @brief dap_enc_aes_encode
 * @param a_key
 * @param a_in
 * @param a_in_size
 * @param a_out
 * @return
 */
size_t dap_enc_aes_encode(struct dap_enc_key* a_key, const void * a_in, size_t a_in_size,void * a_out)
{
    size_t ret=(a_in_size%AES_BLOCKSIZE) ? ( a_in_size+ (AES_BLOCKSIZE- (a_in_size%AES_BLOCKSIZE) ) ): a_in_size ;
    memcpy(a_out,a_in,a_in_size);
    if(ret-a_in_size)
        memset((unsigned char*)a_out+a_in_size,0,ret-a_in_size);

    return ret;
}
