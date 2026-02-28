#pragma once

#include <stdint.h>
// Forward declarations to avoid circular dependencies
typedef struct dap_chain dap_chain_t;
typedef struct dap_chain_net dap_chain_net_t;
typedef struct dap_ledger dap_ledger_t;
// dap_chain_net_srv_price_unit_uid_t already defined in dap_chain_common.h

#include "dap_chain_datum.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_http_server.h"
#include "dap_cert.h"

// Fee callback to break mempool → net dependency
// Registered by net module during initialization
typedef bool (*dap_chain_mempool_fee_get_callback_t)(dap_chain_net_id_t a_net_id, uint256_t *a_value, dap_chain_addr_t *a_addr);

/**
 * @brief Set fee getter callback (called by net module during init)
 * @param a_callback Fee getter function
 */
void dap_chain_mempool_set_fee_callback(dap_chain_mempool_fee_get_callback_t a_callback);

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

// dap_chain_mempool_tx_create_cond_input ret status
#define DAP_CHAIN_MEMPOOL_RET_STATUS_SUCCESS                    0
#define DAP_CHAIN_MEMPOOL_RET_STATUS_BAD_ARGUMENTS              -100
#define DAP_CHAIN_MEMPOOL_RET_STATUS_WRONG_ADDR                 -101
#define DAP_CHAIN_MEMPOOL_RET_STATUS_CANT_FIND_FINAL_TX_HASH    -102
#define DAP_CHAIN_MEMPOOL_RET_STATUS_NOT_NATIVE_TOKEN           -103
#define DAP_CHAIN_MEMPOOL_RET_STATUS_NO_COND_OUT                -104
#define DAP_CHAIN_MEMPOOL_RET_STATUS_NOT_ENOUGH                 -105
#define DAP_CHAIN_MEMPOOL_RET_STATUS_CANT_ADD_TX_OUT            -106
#define DAP_CHAIN_MEMPOOL_RET_STATUS_CANT_ADD_SIGN              -107



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
int dap_chain_mempool_delete_callback_init(void);

extern const char* c_dap_datum_mempool_gdb_group;

/**
 * @brief Get mempool group name for chain
 * @param a_chain Chain pointer
 * @return Group name string (must be freed by caller) or NULL on error
 */
char *dap_chain_mempool_group_new(dap_chain_t *a_chain);

void dap_chain_mempool_add_proc(dap_http_server_t * a_http_server, const char * a_url);

void dap_chain_mempool_filter(dap_chain_t *a_chain, int *a_removed);

char *dap_chain_mempool_datum_add(const dap_chain_datum_t *a_datum, dap_chain_t *a_chain, const char *a_hash_out_type);


bool dap_chain_mempool_out_is_used(dap_chain_net_t *a_net, dap_hash_sha3_256_t *a_out_hash, uint32_t a_out_idx);

char *dap_chain_mempool_base_tx_create(dap_chain_t *a_chain, dap_hash_sha3_256_t *a_emission_hash,
                                       dap_chain_id_t a_emission_chain_id, uint256_t a_emission_value,
                                       const char *a_ticker, dap_chain_addr_t *a_addr_to,
                                       dap_enc_key_t *a_private_key, const char *a_hash_out_type,
                                       uint256_t a_value_fee);
