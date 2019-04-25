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

// action
enum {
    DAP_DATUM_MEMPOOL_NONE = 0, DAP_DATUM_MEMPOOL_ADD, DAP_DATUM_MEMPOOL_CHECK, DAP_DATUM_MEMPOOL_DEL
};

// datum mempool structure
typedef struct dap_datum_mempool {
    uint16_t version;        // structure version
    uint16_t datum_count;    // datums count
    dap_chain_datum_t **data;// mass of datums
}DAP_ALIGN_PACKED dap_datum_mempool_t;

int dap_datum_mempool_init();

extern const char* c_dap_datum_mempool_gdb_group;

uint8_t* dap_datum_mempool_serialize(dap_datum_mempool_t *datum_mempool, size_t *size);
dap_datum_mempool_t * dap_datum_mempool_deserialize(uint8_t *datum_mempool_str, size_t size);

void dap_datum_mempool_clean(dap_datum_mempool_t *datum);
void dap_datum_mempool_free(dap_datum_mempool_t *datum);

void dap_chain_mempool_add_proc(struct dap_http * sh, const char * url);

int dap_chain_mempool_tx_create(dap_enc_key_t *a_key_from,
        const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to, const dap_chain_addr_t* a_addr_fee,
                                const char a_token_ticker[10],
        uint64_t a_value, uint64_t a_value_fee);

int dap_chain_mempool_datum_add(dap_chain_datum_t * a_datum);
