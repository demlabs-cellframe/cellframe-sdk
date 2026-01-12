#pragma once

#include <stdint.h>
#include "dap_chain_net.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_chain_ledger.h"
#include "dap_http_server.h"
#include "dap_cert.h"
#include "dap_chain_block_cache.h"
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
#define DAP_CHAIN_MEMPOOl_RET_STATUS_SUCCESS                    0
#define DAP_CHAIN_MEMPOOL_RET_STATUS_BAD_ARGUMENTS              -100
#define DAP_CHAIN_MEMPOOl_RET_STATUS_WRONG_ADDR                 -101
#define DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_FIND_FINAL_TX_HASH    -102
#define DAP_CHAIN_MEMPOOl_RET_STATUS_NOT_NATIVE_TOKEN           -103
#define DAP_CHAIN_MEMPOOl_RET_STATUS_NO_COND_OUT                -104
#define DAP_CHAIN_MEMPOOl_RET_STATUS_NOT_ENOUGH                 -105
#define DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_TX_OUT            -106
#define DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_SIGN              -107

/**
 * @brief TSD type for SRV_PAY refill transaction marker
 * @details Value 0x16 (22) is chosen to avoid conflicts with:
 *          - Service TSD types (0x0001+)
 *          - Decree TSD types (0x0100+)
 *          - OUT_COND TSD types (0xf000+)
 *          Used to store refill amount in conditional transaction TSD section
 */
#define DAP_CHAIN_SRV_PAY_TSD_REFILL 0x16

#include "uthash.h"

/**
 * @brief SRV_PAY cache entry structure (in-memory UTHash)
 * 
 * Stores information about conditional transaction chain:
 * - root_hash: first TX in chain (hold)
 * - tail_hash: last TX in chain (after refills)
 * - value: current remaining value
 * - owner_pkey_hash: owner's public key hash
 */
typedef struct srv_pay_cache_entry {
    dap_hash_fast_t root_hash;          // First TX hash (key for primary index)
    dap_hash_fast_t tail_hash;          // Current tail TX hash (including remove TX)
    dap_hash_fast_t owner_pkey_hash;    // Owner's pkey hash
    uint256_t value;                    // Value before remove (0 after remove)
    uint64_t srv_uid;                   // Service UID
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX]; // Token ticker
    dap_chain_net_id_t net_id;          // Network ID
    dap_time_t ts_created;              // Creation timestamp
    int prev_cond_idx;                  // OUT_COND index in tail TX (-1 if removed)
    bool is_removed;                    // True if UT was removed (spent)
    UT_hash_handle hh;                  // Primary index by root_hash
    UT_hash_handle hh_tail;             // Secondary index by tail_hash
    UT_hash_handle hh_owner;            // Tertiary index by owner in owner bucket
} srv_pay_cache_entry_t;

/**
 * @brief Owner index bucket for grouping entries by owner pkey_hash
 */
typedef struct srv_pay_owner_index {
    dap_hash_fast_t owner_pkey_hash;    // Owner's pkey hash (key)
    srv_pay_cache_entry_t *entries;     // Head of entries list (keyed by hh_owner)
    UT_hash_handle hh;
} srv_pay_owner_index_t;

/**
 * @brief Result structure for cache queries - list of cache entries
 * @note Entries are DAP_DUP copies, caller MUST call dap_chain_srv_pay_cache_list_free() to free
 */
typedef struct srv_pay_cache_list {
    size_t count;
    srv_pay_cache_entry_t **entries;    // Array of DAP_DUP copies (freed by dap_chain_srv_pay_cache_list_free)
} srv_pay_cache_list_t;

// SRV_PAY cache functions
int dap_chain_srv_pay_cache_init(void);
void dap_chain_srv_pay_cache_deinit(void);

/**
 * @brief Get list of SRV_PAY cache entries for owner
 * @param a_net Network
 * @param a_pkey_hash Owner's public key hash
 * @return List of cache entries (caller MUST call dap_chain_srv_pay_cache_list_free() to free)
 */
srv_pay_cache_list_t *dap_chain_srv_pay_cache_get(dap_chain_net_t *a_net, dap_hash_fast_t *a_pkey_hash);

/**
 * @brief Free cache list structure and all DAP_DUP'd entries
 * @param a_list List returned by dap_chain_srv_pay_cache_get()
 */
void dap_chain_srv_pay_cache_list_free(srv_pay_cache_list_t *a_list);

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

uint8_t* dap_datum_mempool_serialize(dap_datum_mempool_t *datum_mempool, size_t *size);
dap_datum_mempool_t * dap_datum_mempool_deserialize(uint8_t *datum_mempool_str, size_t size);

void dap_datum_mempool_clean(dap_datum_mempool_t *datum);
void dap_datum_mempool_free(dap_datum_mempool_t *datum);

void dap_chain_mempool_add_proc(dap_http_server_t * a_http_server, const char * a_url);

void dap_chain_mempool_filter(dap_chain_t *a_chain, int *a_removed);

char *dap_chain_mempool_datum_add(const dap_chain_datum_t *a_datum, dap_chain_t *a_chain, const char *a_hash_out_type);

char *dap_chain_mempool_tx_create(dap_chain_t *a_chain, dap_enc_key_t *a_key_from,
        const dap_chain_addr_t *a_addr_from, const dap_chain_addr_t **a_addr_to,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t* a_value, uint256_t a_value_fee, const char *a_hash_out_type,
        size_t a_tx_num, dap_time_t *a_time_unlock);

// Extended version with support for arbitrary TSD sections (e.g. for arbitrage transactions)
char *dap_chain_mempool_tx_create_extended(dap_chain_t *a_chain, dap_enc_key_t *a_key_from,
        const dap_chain_addr_t *a_addr_from, const dap_chain_addr_t **a_addr_to,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t* a_value, uint256_t a_value_fee, const char *a_hash_out_type,
        size_t a_tx_num, dap_time_t *a_time_unlock, dap_list_t *a_tsd_list);

// Make transfer transaction & insert to cache
char *dap_chain_mempool_tx_create_cond(dap_chain_net_t *a_net,
        dap_enc_key_t *a_key_from, dap_hash_fast_t *a_pkey_cond_hash,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_per_unit_max,
        dap_chain_net_srv_price_unit_uid_t a_unit, dap_chain_net_srv_uid_t a_srv_uid,
        uint256_t a_value_fee, const void *a_cond,
        size_t a_cond_size, const char *a_hash_out_type);

char *dap_chain_mempool_tx_create_cond_input(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_tx_prev_hash,
        const dap_chain_addr_t *a_addr_to, dap_enc_key_t *a_key_tx_sign, dap_chain_datum_tx_receipt_t *a_receipt, const char *a_hash_out_type, int *a_ret_status);

// Refill conditional SRV_PAY transaction
char *dap_chain_mempool_tx_cond_refill(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from,
        dap_hash_fast_t *a_tx_cond_hash, uint256_t a_value, uint256_t a_value_fee, const char *a_hash_out_type);

int dap_chain_mempool_tx_create_massive(dap_chain_t * a_chain, dap_enc_key_t *a_key_from,
        const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_fee, size_t a_tx_num);

/**
 * @brief dap_chain_mempool_base_tx_create
 * @param a_chain
 * @param a_emission_hash
 * @param a_emission_chain_id
 * @param a_emission_value
 * @param a_ticker
 * @param a_addr_to
 * @param a_private_key For a basic transaction not in a native token, use the key obtained from the wallet. For the
 * basic transaction in the native token, use the key obtained from the certificate.
 * @param a_hash_out_type
 * @param a_value_fee
 * @return
 */
char *dap_chain_mempool_base_tx_create(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_emission_hash,
                                       dap_chain_id_t a_emission_chain_id, uint256_t a_emission_value, const char *a_ticker, dap_chain_addr_t *a_addr_to, dap_enc_key_t *a_private_key,
                                       const char *a_hash_out_type, uint256_t a_value_fee);

dap_chain_datum_t *dap_chain_mempool_datum_get(dap_chain_t *a_chain, const char *a_emission_hash_str);
dap_chain_datum_token_emission_t *dap_chain_mempool_emission_get(dap_chain_t *a_chain, const char *a_emission_hash_str);
dap_chain_datum_token_emission_t *dap_chain_mempool_datum_emission_extract(dap_chain_t *a_chain, byte_t *a_data, size_t a_size);
char *dap_chain_mempool_tx_coll_fee_create(dap_chain_cs_blocks_t *a_blocks, dap_enc_key_t *a_key_from, const dap_chain_addr_t* a_addr_to, dap_list_t *a_block_list,
                                           uint256_t a_value_fee, const char *a_hash_out_type);
char *dap_chain_mempool_tx_reward_create(dap_chain_cs_blocks_t *a_blocks, dap_enc_key_t *a_sign_key, dap_chain_addr_t *a_addr_to, dap_list_t *a_block_list,
                                         uint256_t a_value_fee, const char *a_hash_out_type);
bool dap_chain_mempool_out_is_used(dap_chain_net_t *a_net, dap_hash_fast_t *a_out_hash, uint32_t a_out_idx);
/**
 * @brief Compose event transaction following cellframe mempool style
 * @param[in] a_chain Chain to create transaction for
 * @param[in] a_key_from Private key for signing transaction
 * @param[in] a_service_key Service key for signing transaction
 * @param[in] a_group_name Event group name
 * @param[in] a_event_type Event type
 * @param[in] a_event_data Event data
 * @param[in] a_event_data_size Size of event data
 * @param[in] a_fee_value Fee value
 * @param[in] a_hash_out_type Hash output format
 * @return Transaction hash string on success, NULL on error
 */
char *dap_chain_mempool_tx_create_event(dap_chain_t *a_chain,
                                      dap_enc_key_t *a_key_from,
                                      dap_enc_key_t *a_service_key,
                                      dap_chain_net_srv_uid_t a_srv_uid,
                                      const char *a_group_name,
                                      uint16_t a_event_type,
                                      const void *a_event_data,
                                      size_t a_event_data_size,
                                      uint256_t a_fee_value,
                                      const char *a_hash_out_type);
