#pragma once
#include "dap_enc_key.h"

void   dap_enc_kyber512_key_new_from_data_public( dap_enc_key_t * a_key, const void * a_in, size_t a_in_size );
void   dap_enc_kyber512_key_new( dap_enc_key_t* a_key );
size_t dap_enc_kyber512_gen_bob_shared_key ( dap_enc_key_t *b_key, const void *a_pub, size_t a_pub_size, void ** b_pub );
size_t dap_enc_kyber512_gen_alice_shared_key ( dap_enc_key_t *a_key, const void *a_priv, size_t b_pub_size, unsigned char *b_pub );
void   dap_enc_kyber512_key_delete( dap_enc_key_t* a_key );
void   dap_enc_kyber512_key_generate( dap_enc_key_t * a_key, const void *kex_buf, size_t kex_size, const void * seed, size_t seed_size, size_t key_size );

