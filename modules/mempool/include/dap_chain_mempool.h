#pragma once

#include <stdint.h>
#include "dap_chain_net.h"
#include "dap_chain_datum.h"
#include "dap_chain_ledger.h"
#include "dap_http.h"
#include "dap_cert.h"
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

int dap_datum_mempool_init(void);

extern const char* c_dap_datum_mempool_gdb_group;

uint8_t* dap_datum_mempool_serialize(dap_datum_mempool_t *datum_mempool, size_t *size);
dap_datum_mempool_t * dap_datum_mempool_deserialize(uint8_t *datum_mempool_str, size_t size);

void dap_datum_mempool_clean(dap_datum_mempool_t *datum);
void dap_datum_mempool_free(dap_datum_mempool_t *datum);

void dap_chain_mempool_add_proc(dap_http_t * a_http_server, const char * a_url);

char *dap_chain_mempool_datum_add(const dap_chain_datum_t *a_datum, dap_chain_t *a_chain);
dap_hash_fast_t*  dap_chain_mempool_tx_create(dap_chain_t *a_chain, dap_enc_key_t *a_key_from,
        const dap_chain_addr_t *a_addr_from, const dap_chain_addr_t *a_addr_to,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_fee);

// Make transfer transaction & insert to cache
dap_chain_hash_fast_t* dap_chain_mempool_tx_create_cond(dap_chain_net_t * a_net,
        dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_per_unit_max, dap_chain_net_srv_price_unit_uid_t a_unit,
        dap_chain_net_srv_uid_t a_srv_uid, uint256_t a_value_fee, const void *a_cond, size_t a_cond_size);

dap_chain_datum_t *dap_chain_tx_create_cond_input(dap_chain_net_t * a_net, dap_chain_hash_fast_t *a_tx_prev_hash,
                                                  const dap_chain_addr_t* a_addr_to, dap_enc_key_t *a_key_tx_sign,
                                                  dap_chain_datum_tx_receipt_t * a_receipt);
dap_chain_hash_fast_t* dap_chain_mempool_tx_create_cond_input(dap_chain_net_t * a_net, dap_chain_hash_fast_t *a_tx_prev_hash,
        const dap_chain_addr_t *a_addr_to, dap_enc_key_t *a_key_tx_sign, dap_chain_datum_tx_receipt_t *a_receipt);

int dap_chain_mempool_tx_create_massive(dap_chain_t * a_chain, dap_enc_key_t *a_key_from,
        const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_fee, size_t a_tx_num);

dap_chain_hash_fast_t *dap_chain_mempool_base_tx_create(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_emission_hash,
                                                        dap_chain_id_t a_emission_chain_id, uint256_t a_emission_value, const char *a_ticker,
                                                        dap_chain_addr_t *a_addr_to, dap_cert_t **a_certs, size_t a_certs_count);
dap_chain_datum_token_emission_t *dap_chain_mempool_emission_get(dap_chain_t *a_chain, const char *a_emission_hash_str);
dap_chain_datum_token_emission_t *dap_chain_mempool_datum_emission_extract(dap_chain_t *a_chain, byte_t *a_data, size_t a_size);
