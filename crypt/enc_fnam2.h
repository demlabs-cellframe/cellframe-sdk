#ifndef _ENC_FNAM2_H_
#define _ENC_FNAM2_H_
#include <stddef.h>

struct enc_key;

extern void enc_fnam2_key_new(struct enc_key * key);

extern size_t enc_fnam2_decode(struct enc_key * key, const void * in, size_t in_size,void * out);
extern size_t enc_fnam2_encode(struct enc_key * key,const void * in, size_t in_size,void * out);

#endif
