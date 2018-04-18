#ifndef _DAP_ENC_MSRLN16_H_
#define _DAP_ENC_MSRLN16_H_

#include <stddef.h>
#include "liboqs/crypto/rand/rand.h"

typedef struct dap_enc_key dap_enc_key_t;

//void dap_enc_msrln16_key_new_generate(dap_enc_key_t * a_key, size_t a_size);
//int OQS_KEX_rlwe_msrln16_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);
//int OQS_KEX_rlwe_msrln16_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len);

void dap_enc_msrln16_key_new_generate(OQS_RAND *rand);
// OQS_KEX_rlwe_msrln16_alice_1
void dap_enc_msrln16_key_new_from_data(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len);
//void dap_enc_msrln16_key_new_from_data(dap_enc_key_t * a_key, const void * a_in, size_t a_in_size);
void dap_enc_msrln16_key_new_from_data_public(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size);


// OQS_KEX_rlwe_msrln16_alice_priv_free
// OQS_KEX_rlwe_msrln16_free
void dap_enc_msrln16_key_delete();

/*?*/size_t dap_enc_msrln16_key_public_raw(dap_enc_key_t *a_key, void ** a_key_public);

//size_t dap_enc_msrln16_decode(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size,void * a_out);
size_t dap_enc_msrln16_decode(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);
size_t dap_enc_msrln16_encode(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len);
//size_t dap_enc_msrln16_encode(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size,void * a_out);

#endif
