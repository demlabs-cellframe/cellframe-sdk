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

#include "dap_chain_common.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_common.h"
#include "dap_stream_ch.h"
#include "dap_chain_net_srv_ch_pkt.h"
#include "dap_chain_net.h"

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
} dap_chain_net_srv_ch_remain_service_store_t;

typedef struct dap_chain_net_srv_abstract {
    uint8_t class; //Class of service (once or permanent)
    dap_chain_srv_uid_t type_id; //Type of service
    char decription[128];
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
} dap_chain_net_srv_abstract_t;


typedef struct dap_chain_net_srv_price
{
    uint256_t value_datoshi;
    char token[DAP_CHAIN_TICKER_SIZE_MAX];
    uint64_t units;
    dap_chain_net_srv_price_unit_uid_t units_uid;
} dap_chain_net_srv_price_t;

typedef struct dap_chain_net_srv dap_chain_net_srv_t;
typedef struct dap_chain_net_srv_usage dap_chain_net_srv_usage_t;
typedef struct dap_chain_net_srv_order dap_chain_net_srv_order_t;

typedef struct dap_chain_net_srv_grace {
    dap_stream_worker_t *stream_worker;
    dap_stream_ch_uuid_t ch_uuid;
    dap_chain_net_srv_usage_t *usage;
    dap_timerfd_t *timer;
} dap_chain_net_srv_grace_t;

typedef struct dap_chain_net_srv_client_remote {
    dap_stream_ch_t * ch; // Use ONLY in own context, not thread-safe
    time_t ts_created;
    dap_stream_worker_t * stream_worker;
    uint32_t session_id;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    struct dap_chain_net_srv_client_remote *prev;
    struct dap_chain_net_srv_client_remote *next;
} dap_chain_net_srv_client_remote_t;

typedef struct dap_chain_net_srv_banlist_item {
    dap_chain_hash_fast_t client_pkey_hash;
    dap_time_t end_of_ban_timestamp;
} dap_chain_net_srv_banlist_item_t;


// Common service callback
typedef int  (*dap_chain_net_srv_callback_data_t)(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client, const void *a_custom_data, size_t a_custom_data_size);
// Custom service callback
typedef void * (*dap_chain_net_srv_callback_custom_data_t)(dap_chain_net_srv_t *a_srv, dap_chain_net_srv_usage_t *a_usage, const void *a_custom_data, size_t a_sustom_data_size, size_t *a_out_data_size);\
// Store limits sevice callbacks
typedef dap_chain_net_srv_ch_remain_service_store_t * (*dap_chain_net_srv_callback_get_remain_service_t)(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client);
typedef int (*dap_chain_net_srv_callback_save_remain_service_t)(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t *a_srv_client);
typedef struct dap_chain_net_srv_callbacks {
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
    // Remain service getting from DB
    dap_chain_net_srv_callback_get_remain_service_t get_remain_service;
    // Remain service saving to DB
    dap_chain_net_srv_callback_save_remain_service_t save_remain_service;
} dap_chain_net_srv_callbacks_t;

typedef struct dap_chain_net_srv_grace_usage {
    dap_hash_fast_t tx_cond_hash;
    dap_chain_net_srv_grace_t *grace;
    UT_hash_handle hh;
} dap_chain_net_srv_grace_usage_t;

typedef struct dap_chain_net_srv {
    dap_chain_srv_uid_t uid;
    dap_chain_net_id_t net_id;
    dap_chain_addr_t wallet_addr;
    dap_cert_t *receipt_sign_cert;

    bool allow_free_srv;

    dap_chain_net_srv_callbacks_t callbacks;

    uint32_t grace_period;
    dap_chain_net_srv_grace_usage_t *grace_hash_tab;
    pthread_mutex_t grace_mutex;
    // Pointer to private service structure
    void *_pvt;
    // For python wrappers
    void *_inheritor;
} dap_chain_net_srv_t;

#ifdef __cplusplus
extern "C" {
#endif


int dap_chain_net_srv_init();
void dap_chain_net_srv_deinit(void);

dap_chain_net_srv_t *dap_chain_net_srv_create(dap_chain_net_id_t a_net_id, dap_chain_srv_uid_t a_srv_uid, dap_config_t *a_config, dap_chain_net_srv_callbacks_t *a_network_callbacks);
void dap_chain_net_srv_del(dap_chain_net_srv_t *a_srv);

dap_chain_datum_tx_receipt_t * dap_chain_net_srv_issue_receipt(dap_chain_net_srv_t *a_srv,
                                                               dap_chain_net_srv_price_t * a_price,
                                                               const void * a_ext, size_t a_ext_size, dap_hash_fast_t *a_prev_tx_hash);

int dap_chain_net_srv_parse_pricelist(dap_chain_net_srv_t *a_srv, const char *a_config_section);

int dap_chain_net_srv_price_apply_from_my_order(dap_chain_net_srv_t *a_srv, const char *a_config_section);
dap_chain_net_srv_price_t *dap_chain_net_srv_get_price_from_order(dap_chain_net_srv_t *a_service, dap_chain_net_srv_order_t *a_order);

DAP_STATIC_INLINE const char * dap_chain_net_srv_price_unit_uid_to_str( dap_chain_net_srv_price_unit_uid_t a_uid )
{
    switch ( a_uid.enm) {
        case SERV_UNIT_B: return "BYTE";
        case SERV_UNIT_SEC: return "SECOND";
        case SERV_UNIT_PCS: return "PIECES";
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

DAP_STATIC_INLINE bool dap_chain_net_srv_uid_compare(dap_chain_srv_uid_t a, dap_chain_srv_uid_t b)
{
    return a.uint64 == b.uint64;
}

DAP_STATIC_INLINE bool dap_chain_net_srv_uid_compare_scalar(const dap_chain_srv_uid_t a_uid1, const uint64_t a_id)
{
    return a_uid1.uint64 == a_id;
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

#ifdef __cplusplus
}
#endif