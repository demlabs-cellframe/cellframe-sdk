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
#include "dap_chain_net_remote.h"
#include "dap_chain_wallet.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_stream_ch.h"

//Service direction
enum dap_chain_net_srv_order_direction{
    SERV_DIR_BUY = 1,
    SERV_DIR_SELL = 2,
    SERV_DIR_UNDEFINED = 0
};
typedef byte_t dap_chain_net_srv_order_direction_t;


typedef struct dap_chain_net_srv_abstract
{
    uint8_t class; //Class of service (once or permanent)
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
    dap_chain_wallet_t *wallet;
    char *net_name;
    dap_chain_net_t *net;
    uint256_t value_datoshi;
    char token[DAP_CHAIN_TICKER_SIZE_MAX];
    uint64_t units;
    dap_chain_net_srv_price_unit_uid_t units_uid;
    struct dap_chain_net_srv_price *next;
    struct dap_chain_net_srv_price *prev;
} dap_chain_net_srv_price_t;

// Ch pkt types
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST                       0x01
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST                  0x10
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_RESPONSE                 0x11
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED                0x20
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_DATA                          0x30
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_DATA                 0x31
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS              0xf0
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR                0xff
// for connection testing
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_REQUEST                 0x40
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_RESPONSE                0x41

#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_UNDEFINED                  0x00000000

#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_NOT_FOUND          0x00000100
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_CH_NOT_FOUND       0x00000101
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_IN_CLIENT_MODE     0x00000102
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_NOT_FOUND          0x00000200
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_NO_LEDGER          0x00000201
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_CANT_ADD_USAGE             0x00000300
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND          0x00000400
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_COND_OUT        0x00000401
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ENOUGH         0x00000402
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ACCEPT_TOKEN   0x00000403
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_WRONG_SRV_UID      0x00000404
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_WRONG_SIZE                 0x00000405
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_BIG_SIZE                   0x00000406
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_CANT_FIND          0x00000500
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_NO_SIGN            0x00000501
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_WRONG_PKEY_HASH    0x00000502
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_BANNED_PKEY_HASH   0x00000503
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_PRICE_NOT_FOUND            0x00000600
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_WRONG_HASH                 0x00000BAD

#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_UNKNOWN                    0xffffffff
// TYPE_REQUEST
typedef struct dap_stream_ch_chain_net_srv_pkt_request_hdr{
    dap_chain_net_id_t net_id;// Network id wheither to request
    dap_chain_hash_fast_t tx_cond; // Conditioned transaction with paymemt for
    dap_chain_net_srv_uid_t srv_uid;
    char token[DAP_CHAIN_TICKER_SIZE_MAX];
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_request_hdr_t;

typedef struct dap_stream_ch_chain_net_srv_pkt_request{
    dap_stream_ch_chain_net_srv_pkt_request_hdr_t hdr;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_request_t;

// Custom service data packet
typedef struct dap_stream_ch_chain_net_srv_pkt_data_hdr{
    uint8_t version;
    uint16_t data_size;
    uint8_t padding;
    uint32_t usage_id;
    dap_chain_net_srv_uid_t srv_uid;
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_data_hdr_t;

typedef struct dap_stream_ch_chain_net_srv_pkt_data{
    dap_stream_ch_chain_net_srv_pkt_data_hdr_t hdr;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_data_t;


typedef struct dap_stream_ch_chain_net_srv_pkt_success_hdr{
    uint32_t usage_id;
    dap_chain_net_id_t net_id;
    dap_chain_net_srv_uid_t srv_uid;
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_success_hdr_t;

typedef struct dap_stream_ch_chain_net_srv_pkt_success{
    dap_stream_ch_chain_net_srv_pkt_success_hdr_t hdr;
    uint8_t custom_data[];
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_success_t;

// TYPE_RESPONSE_ERROR
typedef struct dap_stream_ch_chain_net_srv_pkt_error{
    dap_chain_net_id_t net_id;
    dap_chain_net_srv_uid_t srv_uid;
    uint32_t usage_id;
    uint32_t code; // error code
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_error_t;

// data packet for connectiont test
typedef struct dap_stream_ch_chain_net_srv_pkt_test{
    uint32_t usage_id;
    dap_chain_net_id_t net_id;
    dap_chain_net_srv_uid_t srv_uid;
    int32_t  time_connect_ms;
    struct timeval recv_time1;
    struct timeval recv_time2;
    struct timeval send_time1;
    struct timeval send_time2;
    char ip_send[16];
    char ip_recv[16];
    int32_t err_code;
    size_t data_size_send;
    size_t data_size_recv;
    size_t data_size;
    dap_chain_hash_fast_t data_hash;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_test_t;

typedef struct dap_chain_net_srv dap_chain_net_srv_t;
typedef struct dap_chain_net_srv_usage dap_chain_net_srv_usage_t;

typedef struct dap_chain_net_srv_grace {
    dap_stream_worker_t *stream_worker;
    dap_stream_ch_uuid_t ch_uuid;
    dap_chain_net_srv_usage_t *usage;
    dap_stream_ch_chain_net_srv_pkt_request_t *request;
    size_t request_size;
} dap_chain_net_srv_grace_t;

typedef struct dap_chain_net_srv_client_remote
{
    dap_stream_ch_t * ch; // Use ONLY in own context, not thread-safe
    time_t ts_created;
    dap_stream_worker_t * stream_worker;
    int session_id;
    dap_chain_net_remote_t *net_remote; // For remotes
    uint64_t bytes_received;
    uint64_t bytes_sent;
    struct dap_chain_net_srv_client_remote *prev;
    struct dap_chain_net_srv_client_remote *next;
} dap_chain_net_srv_client_remote_t;

typedef int  (*dap_chain_net_srv_callback_data_t)(dap_chain_net_srv_t *, uint32_t, dap_chain_net_srv_client_remote_t *, const void *, size_t);
typedef void* (*dap_chain_net_srv_callback_custom_data_t)(dap_chain_net_srv_t *, dap_chain_net_srv_usage_t *, const void *, size_t, size_t *);
typedef void (*dap_chain_net_srv_callback_ch_t)(dap_chain_net_srv_t *, dap_stream_ch_t *);

typedef struct dap_chain_net_srv_banlist_item {
    dap_chain_hash_fast_t client_pkey_hash;
    pthread_mutex_t *ht_mutex;
    struct dap_chain_net_srv_banlist_item **ht_head;
    UT_hash_handle hh;
} dap_chain_net_srv_banlist_item_t;

typedef struct dap_chain_net_srv
{
    dap_chain_net_srv_uid_t uid; // Unique ID for service.
    dap_chain_net_srv_abstract_t srv_common;
    dap_chain_net_srv_price_t *pricelist;

    uint32_t grace_period;
    pthread_mutex_t banlist_mutex;
    dap_chain_net_srv_banlist_item_t *ban_list;

    dap_chain_callback_trafic_t callback_trafic;

    // Request for usage
    dap_chain_net_srv_callback_data_t callback_requested;

    // Receipt first sign successfull
    dap_chain_net_srv_callback_data_t callback_response_success;

    // Response error
    dap_chain_net_srv_callback_data_t callback_response_error;

    // Receipt next sign succesfull
    dap_chain_net_srv_callback_data_t callback_receipt_next_success;

    // Custom data processing
    dap_chain_net_srv_callback_custom_data_t callback_custom_data;

    // Stream CH callbacks - channel opened, closed and write
    dap_chain_net_srv_callback_ch_t callback_stream_ch_opened;
    dap_chain_net_srv_callback_ch_t callback_stream_ch_closed;
    dap_chain_net_srv_callback_ch_t callback_stream_ch_write;
    // Pointer to inheritor object
    void *_inheritor;
    // Pointer to internal server structure
    void *_internal;
} dap_chain_net_srv_t;

int dap_chain_net_srv_init();
void dap_chain_net_srv_deinit(void);
bool dap_chain_net_srv_pay_verificator(dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx, bool a_owner);
dap_chain_net_srv_t* dap_chain_net_srv_add(dap_chain_net_srv_uid_t a_uid,
                                           const char *a_config_section,
                                           dap_chain_net_srv_callback_data_t a_callback_requested,
                                           dap_chain_net_srv_callback_data_t a_callback_response_success,
                                           dap_chain_net_srv_callback_data_t a_callback_response_error,
                                           dap_chain_net_srv_callback_data_t a_callback_receipt_next_success,
                                           dap_chain_net_srv_callback_custom_data_t a_callback_custom_data
                                           );

int dap_chain_net_srv_set_ch_callbacks(dap_chain_net_srv_uid_t a_uid,
                                       dap_chain_net_srv_callback_ch_t a_callback_stream_ch_opened,
                                       dap_chain_net_srv_callback_ch_t a_callback_stream_ch_closed,
                                       dap_chain_net_srv_callback_ch_t a_callback_stream_ch_write
                                       );

void dap_chain_net_srv_del(dap_chain_net_srv_t * a_srv);
void dap_chain_net_srv_del_all(void);

void dap_chain_net_srv_call_write_all(dap_stream_ch_t * a_client);
void dap_chain_net_srv_call_closed_all(dap_stream_ch_t * a_client);
void dap_chain_net_srv_call_opened_all(dap_stream_ch_t * a_client);

dap_chain_net_srv_t * dap_chain_net_srv_get(dap_chain_net_srv_uid_t a_uid);
size_t dap_chain_net_srv_count(void);
const dap_chain_net_srv_uid_t * dap_chain_net_srv_list(void);
dap_chain_datum_tx_receipt_t * dap_chain_net_srv_issue_receipt(dap_chain_net_srv_t *a_srv,
                                                               dap_chain_net_srv_price_t * a_price,
                                                               const void * a_ext, size_t a_ext_size);
uint8_t dap_stream_ch_chain_net_srv_get_id();
int dap_chain_net_srv_parse_pricelist(dap_chain_net_srv_t *a_srv, const char *a_config_section);

DAP_STATIC_INLINE const char * dap_chain_net_srv_price_unit_uid_to_str( dap_chain_net_srv_price_unit_uid_t a_uid )
{
    switch ( a_uid.enm) {
        case SERV_UNIT_B: return "BYTE";
        case SERV_UNIT_KB: return "KILOBYTE";
        case SERV_UNIT_MB: return "MEGABYTE";
        case SERV_UNIT_SEC: return "SECOND";
        case SERV_UNIT_DAY: return  "DAY";
        case SERV_UNIT_PCS: return "PIECES";
        default: return "UNKNOWN";
    }
}

DAP_STATIC_INLINE bool dap_chain_net_srv_uid_compare(dap_chain_net_srv_uid_t a, dap_chain_net_srv_uid_t b)
{
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    return a.uint64 == b.uint64;
#else // DAP_CHAIN_NET_SRV_UID_SIZE == 16
    return !memcmp(&a, &b, DAP_CHAIN_NET_SRV_UID_SIZE);
#endif
}
