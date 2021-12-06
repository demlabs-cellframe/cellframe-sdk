/*
 * Authors:
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "dap_server.h"
#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_stream_ch.h"
#include "dap_chain_common.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "dap_chain_wallet.h"
//#include "dap_chain_net_srv_stream_session.h"


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

    uint64_t price; //  service price, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
    uint8_t price_units; // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
    char decription[128];
}DAP_ALIGN_PACKED dap_chain_net_srv_abstract_t;

typedef void (*dap_chain_callback_trafic_t)(dap_events_socket_t *, dap_stream_ch_t *);

typedef struct dap_chain_net_srv_price
{
    dap_chain_wallet_t * wallet;
    char * net_name;
    dap_chain_net_t * net;
    uint64_t value_datoshi;
    char token[DAP_CHAIN_TICKER_SIZE_MAX];
    uint64_t units;
    dap_chain_net_srv_price_unit_uid_t units_uid;
    struct dap_chain_net_srv_price * next;
    struct dap_chain_net_srv_price * prev;
} dap_chain_net_srv_price_t;

// Ch pkt types
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST                       0x01
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST                  0x10
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_RESPONSE                 0x11
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED                0x20
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_DATA                          0x30
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
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_USAGE_CANT_ADD             0x00000300
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND          0x00000400
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_COND_OUT        0x00000401
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ENOUGH         0x00000402
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ACCEPT_TOKEN   0x00000403
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_WRONG_SRV_UID      0x00000404
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_WRONG_SIZE         0x00000405
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_CANT_FIND          0x00000500
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_NO_SIGN            0x00000501
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_WRONG_PKEY_HASH    0x00000502
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_BANNED_PKEY_HASH   0x00000503
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_PRICE_NOT_FOUND            0x00000600

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
    uint8_t offset[3];
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

typedef struct dap_chain_net_srv_usage dap_chain_net_srv_usage_t;

typedef struct dap_chain_net_srv_grace {
    dap_stream_worker_t *stream_worker;
    dap_stream_ch_uuid_t ch_uuid;
    dap_chain_net_srv_usage_t *usage;
    dap_stream_ch_chain_net_srv_pkt_request_t *request;
    size_t request_size;
} dap_chain_net_srv_grace_t;

DAP_STATIC_INLINE const char * dap_chain_net_srv_price_unit_uid_to_str( dap_chain_net_srv_price_unit_uid_t a_uid )
{
    switch ( a_uid.enm) {
        case SERV_UNIT_B: return "BYTE";
        case SERV_UNIT_KB: return "KILOBYTE";
        case SERV_UNIT_MB: return "MEGABYTE";
        case SERV_UNIT_SEC: return "SECOND";
        case SERV_UNIT_DAY: return  "DAY";
        default: return "UNKNOWN";
    }
}

uint8_t dap_stream_ch_chain_net_srv_get_id();

