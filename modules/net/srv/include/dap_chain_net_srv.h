/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Aleksandr Lysikov <alexander.lysikov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2019
* All rights reserved.

This file is part of CellFrame SDK the open source project

CellFrame SDK is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CellFrame SDK is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_common.h"
#include "dap_stream_ch.h"
#include "dap_time.h"
#include "dap_stream_ch_chain_net_srv_pkt.h"
#include "uthash.h"

// ============================================================================
// SRV_PAY cache (in-memory UTHash)
// ============================================================================

/**
 * @brief TSD type for SRV_PAY refill transaction marker
 * @details Value 0x16 (22) is chosen to avoid conflicts with:
 *          - Service TSD types (0x0001+)
 *          - Decree TSD types (0x0100+)
 *          - OUT_COND TSD types (0xf000+)
 *          Used to store refill amount in conditional transaction TSD section
 */
#define DAP_CHAIN_SRV_PAY_TSD_REFILL 0x16

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

// ============================================================================

#define DAP_CHAIN_NET_SRV_GRACE_PERIOD_DEFAULT 60

//Service direction
enum dap_chain_net_srv_order_direction {
    SERV_DIR_UNDEFINED = 0,
    SERV_DIR_BUY = 1,
    SERV_DIR_SELL = 2
};
typedef byte_t dap_chain_net_srv_order_direction_t;

typedef struct {
    intmax_t limits_bytes; // Bytes provided for using the service left
    time_t limits_ts; //Time provided for using the service
} dap_stream_ch_chain_net_srv_remain_service_store_t;

typedef struct dap_chain_net_srv_abstract
{
    uint8_t c; //Class of service (once or permanent)
    dap_chain_net_srv_uid_t type_id; //Type of service
    union {
        struct {
            int bandwith;
            int abuse_resistant;
            size_t limit_bytes;
        } vpn;
        /*struct {
         int value;
         } another_srv;*/
    } proposal_params;

    //size_t pub_key_data_size;
    //void * pub_key_data;

    uint256_t price; //  service price, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
    uint8_t price_units; // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
    char decription[128];
}DAP_ALIGN_PACKED dap_chain_net_srv_abstract_t;

typedef void (*dap_chain_callback_trafic_t)(dap_events_socket_t *, dap_stream_ch_t *);

typedef struct dap_chain_net_srv_price
{
//    dap_chain_wallet_t *wallet;
    dap_chain_addr_t *wallet_addr;
    dap_cert_t *receipt_sign_cert;
    char *net_name;
    dap_chain_net_t *net;
    uint256_t value_datoshi;
    char token[DAP_CHAIN_TICKER_SIZE_MAX];
    uint64_t units;
    dap_chain_net_srv_price_unit_uid_t units_uid;
    struct dap_chain_net_srv_price *next;
    struct dap_chain_net_srv_price *prev;
} dap_chain_net_srv_price_t;

typedef struct dap_chain_net_srv dap_chain_net_srv_t;
typedef struct dap_chain_net_srv_usage dap_chain_net_srv_usage_t;

typedef struct dap_chain_net_srv_grace {
    dap_stream_worker_t *stream_worker;
    dap_stream_ch_uuid_t ch_uuid;
    dap_chain_net_srv_usage_t *usage;
    dap_timerfd_t *timer;
} dap_chain_net_srv_grace_t;

typedef struct dap_chain_net_srv_client_remote
{
    dap_stream_ch_t * ch; // Use ONLY in own context, not thread-safe
    time_t ts_created;
    dap_stream_worker_t * stream_worker;
    uint32_t session_id;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    struct dap_chain_net_srv_client_remote *prev;
    struct dap_chain_net_srv_client_remote *next;
} dap_chain_net_srv_client_remote_t;

typedef int  (*dap_chain_net_srv_callback_data_t)(dap_chain_net_srv_t *, uint32_t, dap_chain_net_srv_client_remote_t *, const void *, size_t);
typedef void* (*dap_chain_net_srv_callback_custom_data_t)(dap_chain_net_srv_t *, dap_chain_net_srv_usage_t *, const void *, size_t, size_t *);
typedef void (*dap_chain_net_srv_callback_ch_t)(dap_chain_net_srv_t *, dap_stream_ch_t *);
typedef dap_stream_ch_chain_net_srv_remain_service_store_t* (*dap_chain_net_srv_callback_get_remain_srvice_t)(dap_chain_net_srv_t *, uint32_t, dap_chain_net_srv_client_remote_t*);
typedef int (*dap_chain_net_srv_callback_save_remain_srvice_t)(dap_chain_net_srv_t *, uint32_t, dap_chain_net_srv_client_remote_t*);
// Process service decree
typedef void (*dap_chain_net_srv_callback_decree_t)(dap_chain_net_srv_t* a_srv, dap_chain_net_t* a_net, dap_chain_t* a_chain, dap_chain_datum_decree_t* a_decree, size_t a_decree_size);

typedef struct dap_chain_net_srv_banlist_item {
    dap_chain_hash_fast_t client_pkey_hash;
    dap_time_t end_of_ban_timestamp;
} dap_chain_net_srv_banlist_item_t;

typedef struct dap_chain_net_srv_callbacks {
    // For traffic control
    dap_chain_callback_trafic_t traffic;
    // Request for usage
    dap_chain_net_srv_callback_data_t requested;
    // Receipt first sign successfull
    dap_chain_net_srv_callback_data_t response_success;
    // Response error
    dap_chain_net_srv_callback_data_t response_error;
    // Receipt next sign succesfull
    dap_chain_net_srv_callback_data_t receipt_next_success;
    // Custom data processing
    dap_chain_net_srv_callback_custom_data_t custom_data;
    // Remain service getting drom DB
    dap_chain_net_srv_callback_get_remain_srvice_t get_remain_service;
    // Remain service saving to DB
    dap_chain_net_srv_callback_save_remain_srvice_t save_remain_service;
    // Decree processing
    dap_chain_net_srv_callback_decree_t decree;

    // Stream CH callbacks - channel opened, closed and write
    dap_chain_net_srv_callback_ch_t stream_ch_opened;
    dap_chain_net_srv_callback_ch_t stream_ch_closed;
    dap_chain_net_srv_callback_ch_t stream_ch_write;
} dap_chain_net_srv_callbacks_t;

typedef struct dap_chain_net_srv_grace_usage {
    dap_hash_fast_t tx_cond_hash;
    dap_chain_net_srv_grace_t *grace;
    UT_hash_handle hh;
} dap_chain_net_srv_grace_usage_t;

typedef struct dap_chain_net_srv
{
    dap_chain_net_srv_uid_t uid; // Unique ID for service.
    dap_chain_net_srv_abstract_t srv_common;
    // dap_chain_net_srv_price_t *pricelist;

    bool allow_free_srv;
    uint32_t grace_period;

    dap_chain_net_srv_callbacks_t callbacks;

    dap_chain_net_srv_grace_usage_t *grace_hash_tab;
    pthread_mutex_t grace_mutex;

    // Pointer to inheritor object
    void *_inheritor;
    // Pointer to internal server structure
    void *_internal;
} dap_chain_net_srv_t;

// Fees section
typedef enum dap_chain_net_srv_fee_tsd_type {
    TSD_FEE = 0x0001,
    TSD_FEE_TYPE,
    TSD_FEE_ADDR
} dap_chain_net_srv_fee_tsd_type_t;

typedef enum dap_chain_net_srv_fee_type {
    SERVICE_FEE_OWN_FIXED = 0x1,
    SERVICE_FEE_OWN_PERCENT,
    SERVICE_FEE_NATIVE_FIXED,
    SERIVCE_FEE_NATIVE_PERCENT
} dap_chain_net_srv_fee_type_t;

typedef struct dap_chain_net_srv_fee_item {
    dap_chain_net_id_t net_id;
    // Sevice fee
    uint16_t fee_type;
    uint256_t fee;
    dap_chain_addr_t fee_addr; // Addr collector

    UT_hash_handle hh;
} dap_chain_net_srv_fee_item_t;

int dap_chain_net_srv_init();
void dap_chain_net_srv_deinit(void);
dap_chain_net_srv_t* dap_chain_net_srv_add(dap_chain_net_srv_uid_t a_uid,
                                           const char *a_config_section,
                                           dap_chain_net_srv_callbacks_t* a_callbacks);

void dap_chain_net_srv_del(dap_chain_net_srv_t * a_srv);
void dap_chain_net_srv_del_all(void);

void dap_chain_net_srv_call_write_all(dap_stream_ch_t * a_client);
void dap_chain_net_srv_call_closed_all(dap_stream_ch_t * a_client);
void dap_chain_net_srv_call_opened_all(dap_stream_ch_t * a_client);

dap_chain_net_srv_t * dap_chain_net_srv_get(dap_chain_net_srv_uid_t a_uid);
dap_chain_net_srv_t* dap_chain_net_srv_get_by_name(const char *a_name);
size_t dap_chain_net_srv_count(void);
const dap_chain_net_srv_uid_t * dap_chain_net_srv_list(void);
dap_chain_datum_tx_receipt_t * dap_chain_net_srv_issue_receipt(dap_chain_net_srv_t *a_srv,
                                                               dap_chain_net_srv_price_t * a_price,
                                                               const void * a_ext, size_t a_ext_size, dap_hash_fast_t *a_prev_tx_hash);

int dap_chain_net_srv_parse_pricelist(dap_chain_net_srv_t *a_srv, const char *a_config_section);

int dap_chain_net_srv_price_apply_from_my_order(dap_chain_net_srv_t *a_srv, const char *a_config_section);
dap_chain_net_srv_price_t * dap_chain_net_srv_get_price_from_order(dap_chain_net_srv_t *a_srv, const char *a_config_section, dap_chain_hash_fast_t* a_order_hash);



DAP_STATIC_INLINE const char * dap_chain_net_srv_price_unit_uid_to_str( dap_chain_net_srv_price_unit_uid_t a_uid )
{
    switch ( a_uid.enm) {
        case SERV_UNIT_B: return "bytes";
        case SERV_UNIT_SEC: return "sec";
        case SERV_UNIT_PCS: return "pieces";
        default: return "UNKNOWN";
    }
}

DAP_STATIC_INLINE dap_chain_net_srv_price_unit_uid_t dap_chain_net_srv_price_unit_uid_from_str( const char  *a_unit_str )
{
    dap_chain_net_srv_price_unit_uid_t l_price_unit = { .enm = SERV_UNIT_UNDEFINED };
    if(!dap_strcmp(a_unit_str, "sec"))
        l_price_unit.enm = SERV_UNIT_SEC;
    else if(!dap_strcmp(a_unit_str, "b") || !dap_strcmp(a_unit_str, "bytes"))
        l_price_unit.enm = SERV_UNIT_B;
    else if(!dap_strcmp(a_unit_str, "pcs") || !dap_strcmp(a_unit_str, "pieces"))
        l_price_unit.enm = SERV_UNIT_PCS;
    return l_price_unit;
}

DAP_STATIC_INLINE bool dap_chain_net_srv_uid_compare(dap_chain_net_srv_uid_t a, dap_chain_net_srv_uid_t b)
{
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    return a.uint64 == b.uint64;
#else // DAP_CHAIN_NET_SRV_UID_SIZE == 16
    return !memcmp(&a, &b, DAP_CHAIN_NET_SRV_UID_SIZE);
#endif
}

DAP_STATIC_INLINE bool dap_chain_net_srv_uid_compare_scalar(const dap_chain_net_srv_uid_t a_uid1, const uint64_t a_id)
{
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    return a_uid1.uint64 == a_id;
#else
    return compare128(a_uid1.uint128, GET_128_FROM_64(a_id));
#endif
}

DAP_STATIC_INLINE const char *dap_chain_net_srv_fee_type_to_str(dap_chain_net_srv_fee_type_t a_fee_type) {
    switch (a_fee_type) {
        case SERVICE_FEE_OWN_FIXED: return "SERVICE_FEE_OWN_FIXED";
        case SERVICE_FEE_OWN_PERCENT: return "SERVICE_FEE_OWN_PERCENT";
        case SERVICE_FEE_NATIVE_FIXED: return "SERVICE_FEE_NATIVE_FIXED";
        case SERIVCE_FEE_NATIVE_PERCENT: return "SERIVCE_FEE_NATIVE_PERCENT";
        default: return "UNKNOWN";
    }
}

typedef enum s_com_net_srv_err{
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_OK = 0,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_HASH_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CONT_ERR,

    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_HASH_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_PARAM_CERT_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_LOAD_CERT_ERR,

    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_PARAM_CERT_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_HEX_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_CANT_GET_ERR,

    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DUMP_CANT_FIND_ERR,

    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DEL_CANT_FIND_HASH_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DEL_NEED_HASH_PARAM_ERR,

    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_ROLE_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_UNDEF_ORDER_DIR_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_RECOGNIZE_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_REQUIRED_PARAM_UID_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_PARSE_NODE_ADDR_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_UNDEF_PRICE_UNIT_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CERT_WITHOUT_KEY_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_LOAD_CERT_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CERT_NAME_NOT_WALID_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_ORDER_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_MISSED_PARAM_ERR,

    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_PPKHASH_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_CPKHASH_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_CANT_REC_UID_STR_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_UID_ERR,
    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_CANT_GET_REM_SERV_DATA_ERR,

    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UNKNOWN_SUB_COM_ERR,

    DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UNKNOWN    

} s_com_net_srv_err_t;
