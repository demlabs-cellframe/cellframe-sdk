#ifndef DAP_AES_PROTO_H
#define DAP_AES_PROTO_H

#include "stdint.h"
#include "stddef.h"

#define IAES_BLOCK_SIZE 16
#define IAES_KEYSIZE 32

void IAES_256_CBC_encrypt(const uint8_t *data, uint8_t *output, uint8_t * ivec, unsigned long length, uint8_t *masterkey);
size_t IAES_256_CBC_decrypt(const uint8_t *cdata, uint8_t *output, uint8_t * ivec, unsigned long length, uint8_t *key);

size_t iaes_block128_padding(const void *data, uint8_t **data_new, size_t length_data);
size_t iaes_calc_block128_size(size_t length_data);

#endif // DAP_AES_PROTO_H
