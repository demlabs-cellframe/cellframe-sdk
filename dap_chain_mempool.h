#pragma once

#include <stdint.h>
#include "dap_chain_datum.h"
/*
 // datum mempool structure
 typedef struct dap_datum_mempool {
 int16_t version;               // structure version
 uint16_t datum_count;          // datums count
 struct {
 int32_t datum_size;
 dap_chain_datum_t *datum;
 }DAP_ALIGN_PACKED data[];      // mass of datums
 }DAP_ALIGN_PACKED dap_datum_mempool_t;
 */

#define DAP_DATUM_MEMPOOL_VERSION "01"

// datum mempool structure
typedef struct dap_datum_mempool {
    uint16_t version;             // structure version
    uint16_t datum_count;// datums count
    dap_chain_datum_t **data;// mass of datums
}DAP_ALIGN_PACKED dap_datum_mempool_t;

uint8_t* dap_datum_mempool_serialize(dap_datum_mempool_t *datum_mempool, size_t *size);
dap_datum_mempool_t * dap_datum_mempool_deserialize(uint8_t *datum_mempool_str, size_t size);

void dap_datum_mempool_clean(dap_datum_mempool_t *datum);
void dap_datum_mempool_free(dap_datum_mempool_t *datum);

void dap_chain_mempool_add_proc(struct dap_http * sh, const char * url);

/**
 * Convert binary data to binhex encoded data.
 *
 * out output buffer, must be twice the number of bytes to encode.
 * len is the size of the data in the in[] buffer to encode.
 * return the number of bytes encoded, or -1 on error.
 */
int bin2hex(char *out, const unsigned char *in, int len);

/**
 * Convert binhex encoded data to binary data
 *
 * len is the size of the data in the in[] buffer to decode, and must be even.
 * out outputbuffer must be at least half of "len" in size.
 * The buffers in[] and out[] can be the same to allow in-place decoding.
 * return the number of bytes encoded, or -1 on error.
 */
int hex2bin(char *out, const unsigned char *in, int len);
