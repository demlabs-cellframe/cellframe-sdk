#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "oaes_lib.h"
#include "dap_enc_oaes.h"
#include "dap_common.h"

#define LOG_TAG "dap_enc_oaes"

static OAES_CTX* get_oaes_ctx(struct dap_enc_key *a_key)
{
    OAES_CTX *ctx = NULL;
    if(a_key && a_key->_inheritor &&
            a_key->_inheritor_size == sizeof(oaes_ctx)) {
        ctx = a_key->_inheritor;
    }
    return ctx;
}

void dap_enc_oaes_key_new(struct dap_enc_key * a_key)
{
    a_key->_inheritor = (uint8_t *) oaes_alloc();
    a_key->_inheritor_size = sizeof(oaes_ctx);
    a_key->type = DAP_ENC_KEY_TYPE_OAES;
    a_key->enc = dap_enc_oaes_encrypt;
    a_key->dec = dap_enc_oaes_decrypt;
    a_key->enc_na = dap_enc_oaes_encrypt_fast;
    a_key->dec_na = dap_enc_oaes_decrypt_fast;
}

void dap_enc_oaes_key_delete(struct dap_enc_key *a_key)
{

    OAES_CTX *ctx = get_oaes_ctx(a_key);
    if(ctx) {
        oaes_free(&ctx); // free(a_key->_inheritor);
        a_key->_inheritor_size = 0;
    }
}

void dap_enc_oaes_key_generate(struct dap_enc_key * a_key, const void *kex_buf,
        size_t kex_size, const void * seed, size_t seed_size, size_t key_size)
{
    a_key->last_used_timestamp = time(NULL);

    oaes_ctx *ctx = get_oaes_ctx(a_key);

    if(kex_size < key_size) {
        log_it(L_ERROR, "kex_size can't be less than key_size");
        return;
    }

    OAES_RET r = oaes_key_import_data(ctx, kex_buf, key_size);
    if(r != OAES_RET_SUCCESS) {
        log_it(L_ERROR, "Error generate key");
        return;
    }

    if(seed_size >= OAES_BLOCK_SIZE)
        memcpy(ctx->iv, seed, OAES_BLOCK_SIZE);
    else
        memset(ctx->iv, 0, OAES_BLOCK_SIZE);
}

size_t dap_enc_oaes_calc_encode_size(const size_t size_in)
{
    size_t a_out_size = 2 * OAES_BLOCK_SIZE + size_in
            + (size_in % OAES_BLOCK_SIZE == 0 ? 0 :
            OAES_BLOCK_SIZE - size_in % OAES_BLOCK_SIZE);
    return a_out_size;
}

size_t dap_enc_oaes_calc_decode_size(const size_t size_in)
{
    return size_in - 2 * OAES_BLOCK_SIZE;
}

size_t dap_enc_oaes_decrypt(struct dap_enc_key *a_key, const void * a_in,
        size_t a_in_size, void ** a_out) {
    OAES_CTX *ctx = get_oaes_ctx(a_key);
    if(!ctx)
        return 0;
    size_t a_out_size = dap_enc_oaes_calc_decode_size(a_in_size);
    *a_out = calloc(a_out_size, 1);
    OAES_RET ret = oaes_decrypt(ctx, a_in, a_in_size, *a_out, &a_out_size);
    if(ret != OAES_RET_SUCCESS) {
        a_out_size = 0;
        free(*a_out);
    }
    return a_out_size;
}

size_t dap_enc_oaes_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    OAES_CTX *ctx = get_oaes_ctx(a_key);
    if(!ctx)
        return 0;
    size_t a_out_size = dap_enc_oaes_calc_encode_size(a_in_size);
    *a_out = calloc(a_out_size, 1);
    OAES_RET ret = oaes_encrypt(ctx, a_in, a_in_size, *a_out, &a_out_size);
    if(ret != OAES_RET_SUCCESS) {
        a_out_size = 0;
        free(*a_out);
    }
    return a_out_size;
}

// Writes result ( out ) in already allocated buffer
size_t dap_enc_oaes_decrypt_fast(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size,
        void * buf_out, size_t buf_out_size)
{
    OAES_CTX *ctx = get_oaes_ctx(a_key);
    if(!ctx)
        return 0;

    OAES_RET ret = oaes_decrypt(ctx, a_in, a_in_size, buf_out, &buf_out_size);
    if(ret != OAES_RET_SUCCESS) {
        buf_out_size = 0;
    }
    return buf_out_size;
}

// Writes result ( out ) in already allocated buffer
size_t dap_enc_oaes_encrypt_fast(struct dap_enc_key * a_key, const void * a_in,
        size_t a_in_size, void * buf_out, size_t buf_out_size)
{
    OAES_CTX *ctx = get_oaes_ctx(a_key);
    if(!ctx)
        return 0;

    OAES_RET ret = oaes_encrypt(ctx, a_in, a_in_size, buf_out, &buf_out_size);
    if(ret != OAES_RET_SUCCESS) {
        buf_out_size = 0;
    }
    return buf_out_size;
}

