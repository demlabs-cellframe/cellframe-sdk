#include "dap_common.h"
#include "dap_enc_newhope.h"

#define LOG_TAG "dap_enc_newhope"

/**
 * @brief dap_enc_newhope_key_new_generate
 * @param a_key
 * @param a_size
 */
void dap_enc_newhope_key_new_generate(dap_enc_key_t * a_key, size_t a_size)
{
    (void)a_key;
    (void)a_size;
}

/**
 * @brief dap_enc_newhope_key_new_from_data
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
void dap_enc_newhope_key_new_from_data(dap_enc_key_t * a_key, const void * a_in, size_t a_in_size)
{
    (void)a_key;
    (void)a_in;
    (void)a_in_size;
}

/**
 * @brief dap_enc_newhope_key_new_from_data_public
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
void dap_enc_newhope_key_new_from_data_public(dap_enc_key_t * a_key, const void * a_in, size_t a_in_size)
{
    (void)a_key;
    (void)a_in;
    (void)a_in_size;
}

/**
 * @brief dap_enc_newhope_key_delete
 * @param a_key
 */
void dap_enc_newhope_key_delete(dap_enc_key_t *a_key)
{
    (void)a_key;
}

/**
 * @brief dap_enc_newhope_key_public_base64
 * @param a_key
 * @return
 */
char* dap_enc_newhope_key_public_base64(dap_enc_key_t *a_key)
{
    (void)a_key;
    return NULL;
}

/**
 * @brief dap_enc_newhope_key_public_raw
 * @param a_key
 * @param a_key_public
 * @return
 */
size_t dap_enc_newhope_key_public_raw(dap_enc_key_t *a_key, void ** a_key_public)
{
    (void)a_key;
    (void)a_key_public;
    return 0;
}

/**
 * @brief dap_enc_newhope_decode
 * @param a_key
 * @param a_in
 * @param a_in_size
 * @param a_out
 * @return
 */
size_t dap_enc_newhope_decode(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size,void * a_out)
{
    (void)a_key;
    (void)a_in;
    (void)a_in_size;
    (void)a_out;
    return 0;
}

/**
 * @brief dap_enc_newhope_encode
 * @param a_key
 * @param a_in
 * @param a_in_size
 * @param a_out
 * @return
 */
size_t dap_enc_newhope_encode(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size,void * a_out)
{
    (void)a_key;
    (void)a_in;
    (void)a_in_size;
    (void)a_out;
    return 0;
}
