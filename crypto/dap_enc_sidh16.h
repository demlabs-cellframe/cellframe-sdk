#ifndef _DAP_ENC_SIDH16_H_
#define _DAP_ENC_SIDH16_H_

#include <stddef.h>
#include "liboqs/kex/kex.h"
#include "liboqs/crypto/rand/rand.h"

struct dap_enc_key;

// OQS_KEX_sidh_cln16_new
int dap_enc_sidh16_key_new_generate(OQS_RAND *rand, const char *named_parameters);

// OQS_KEX_sidh_cln16_alice_1
void dap_enc_sidh16_key_new_from_data(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len);

// OQS_KEX_sidh_cln16_alice_priv_free
// OQS_KEX_sidh_cln16_free
void dap_enc_sidh16_key_delete();

// OQS_KEX_sidh_cln16_alice_0
size_t dap_enc_sidh16_encode(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len);

// OQS_KEX_sidh_cln16_bob
size_t dap_enc_sidh16_decode(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);


#endif
