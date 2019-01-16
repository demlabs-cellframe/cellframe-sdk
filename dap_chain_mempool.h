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

// datum mempool structure
typedef struct dap_datum_mempool {
    int16_t version;             // structure version
    uint16_t datum_count;// datums count
    dap_chain_datum_t **data;// mass of datums
}DAP_ALIGN_PACKED dap_datum_mempool_t;

void dap_datum_mempool_clean(dap_datum_mempool_t *datum);
void dap_datum_mempool_free(dap_datum_mempool_t *datum);

void dap_chain_mempool_add_proc(struct dap_http * sh, const char * url);
