#include "dap_common.h"
#include "dap_enc_picnic.h"

#define LOG_TAG "enc_picnic"

/**
 * @brief dap_enc_picnic_enc_na
 * @param b_key
 * @param a_buf_in
 * @param a_buf_in_size
 * @param a_buf_out
 * @param a_buf_out_size_max
 * @return
 */
size_t dap_enc_picnic_enc_na(dap_enc_key_t* b_key, const void *a_buf_in, const size_t a_buf_in_size,
                             void * a_buf_out, const size_t a_buf_out_size_max)
{
    (void)b_key; (void)a_buf_in;
    (void)a_buf_in_size; (void)a_buf_out;
    (void)a_buf_out_size_max;
    return 0;
}

/**
 * @brief dap_enc_picnic_dec_na
 * @param b_key
 * @param a_buf_in
 * @param a_buf_in_size
 * @param a_buf_out
 * @param a_buf_out_size_max
 * @return
 */
size_t dap_enc_picnic_dec_na(dap_enc_key_t* b_key, const void *a_buf_in, const size_t a_buf_in_size,
                             void * a_buf_out, const size_t a_buf_out_size_max)
{
    (void)b_key; (void)a_buf_in;
    (void)a_buf_in_size; (void)a_buf_out;
    (void)a_buf_out_size_max;
    return 0;
}

/**
 * @brief dap_enc_picnic_key_new
 * @param a_key
 */
void dap_enc_picnic_key_new(dap_enc_key_t* a_key)
{
    (void)a_key;
}

/**
 * @brief dap_enc_picnic_key_generate
 * @param a_key
 * @param seed_size
 * @param key_size
 */
void dap_enc_picnic_key_generate(dap_enc_key_t * a_key, const void* a_seed, size_t a_seed_size,
                                 size_t a_key_size)
{
    (void)a_key; (void)a_seed;
    (void)a_seed_size; (void)a_key_size;
}

/**
 * @brief dap_enc_picnic_key_new_from_raw_public
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
void dap_enc_picnic_key_new_from_raw_public(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size)
{
    (void)a_key; (void)a_in;
    (void)a_in_size;
}

/**
 * @brief dap_enc_picnic_key_new_from_raw_private
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
void dap_enc_picnic_key_new_from_raw_private(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size)
{
    (void)a_key; (void)a_in;
    (void)a_in_size;
}

/**
 * @brief dap_enc_picnic_key_delete
 * @param a_key
 */
void dap_enc_picnic_key_delete(dap_enc_key_t * a_key)
{
    (void)a_key;
}
