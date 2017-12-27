#ifndef _ENC_AES_H_
#define _ENC_AES_H_

#include <stddef.h>

struct enc_key;

void enc_aes_key_new(struct enc_key * key);
void enc_aes_key_create(struct enc_key * key, const char *password_string);
void enc_aes_key_delete(struct enc_key *key);

size_t enc_aes_decode(struct enc_key* key, const void * in, size_t in_size,void * out);
size_t enc_aes_encode(struct enc_key* key, const void * in, size_t in_size,void * out);

#endif
