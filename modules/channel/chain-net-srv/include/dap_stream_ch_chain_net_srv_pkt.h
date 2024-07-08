/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Cellframe       https://cellframe.net
* Demlabs Limited   https://demlabs.net
* Copyright  (c) 2017-2020
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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "dap_chain_net_srv_stream_session.h"

// Ch pkt types
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST                       0x01
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST                  0x10
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_RESPONSE                 0x11
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED                0x20
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_DATA                          0x30
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_DATA                 0x31
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NEW_TX_COND_REQUEST           0x40
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NEW_TX_COND_RESPONSE          0x41
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REMAIN_LIMITS_REQ             0x60
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REMAIN_LIMITS_RESP            0x61
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS              0xf0
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR                0xff
// for connection testing
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_REQUEST                 0x50
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_RESPONSE                0x51

#define DAP_CHAIN_NET_SRV_CH_REQUEST_SIZE_MAX                              10240 //4096

#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_UNDEFINED                  0x00000000

#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_NOT_FOUND          0x00000100
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_CH_NOT_FOUND       0x00000101
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_IN_CLIENT_MODE     0x00000102
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_NOT_FOUND          0x00000200
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_NO_LEDGER          0x00000201
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_IS_OFFLINE         0x00000202
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_CANT_ADD_USAGE             0x00000300
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND          0x00000400
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_COND_OUT        0x00000401
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ENOUGH         0x00000402
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ACCEPT_TOKEN   0x00000403
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_WRONG_SRV_UID      0x00000404
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_NEW_COND        0x00000405
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_WRONG_SIZE                 0x00000406
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_BIG_SIZE                   0x00000407
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NEW_TX_COND_NOT_ENOUGH     0x00000408
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_CANT_FIND          0x00000500
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_NO_SIGN            0x00000501
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_WRONG_PKEY_HASH    0x00000502
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_BANNED_PKEY_HASH   0x00000503
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_IS_NOT_PRESENT     0x00000504
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_PRICE_NOT_FOUND            0x00000600
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_WRONG_HASH                 0x00000BAD
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_ALLOC_MEMORY_ERROR         0x00BADA55


#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_UNKNOWN                    0xffffffff
// TYPE_REQUEST
typedef struct dap_stream_ch_chain_net_srv_pkt_request_hdr{
    dap_chain_net_id_t net_id;// Network id wheither to request
    dap_chain_hash_fast_t tx_cond; // Conditioned transaction with paymemt for
    dap_chain_net_srv_uid_t srv_uid;
    char token[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_hash_fast_t client_pkey_hash;
    dap_chain_hash_fast_t order_hash;
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
typedef struct dap_stream_ch_chain_net_srv_pkt_test {
    uint32_t                usage_id;
    dap_chain_net_id_t      net_id;
    dap_chain_net_srv_uid_t srv_uid;
    int32_t                 time_connect_ms;
    dap_nanotime_t          recv_time1, recv_time2, send_time1, send_time2;
    char                    host_send[DAP_HOSTADDR_STRLEN], host_recv[DAP_HOSTADDR_STRLEN];
    int32_t                 err_code;
    uint64_t                data_size_send, data_size_recv, data_size;
    dap_chain_hash_fast_t   data_hash;
    uint8_t                 data[];
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_test_t;

typedef struct dap_stream_ch_chain_net_srv_pkt_remain_service_req{
    dap_chain_net_id_t net_id;
    dap_chain_net_srv_uid_t srv_uid;
    dap_hash_fast_t user_pkey_hash;
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_remain_service_req_t;

typedef struct dap_stream_ch_chain_net_srv_pkt_remain_service_resp{
    dap_chain_net_id_t net_id;
    dap_chain_net_srv_uid_t srv_uid;
    dap_hash_fast_t user_pkey_hash;
    long int limits_bytes; // Bytes provided for using the service left
    long int limits_ts;
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_remain_service_resp_t;

size_t dap_stream_ch_chain_net_srv_pkt_data_write(dap_stream_ch_t *a_ch,
                                                  dap_chain_net_srv_uid_t a_srv_uid, uint32_t a_usage_id  ,
                                                  const void * a_data, size_t a_data_size);

DAP_PRINTF_ATTR(4, 5) size_t dap_stream_ch_chain_net_srv_pkt_data_write_f(dap_stream_ch_t *a_ch,
                                                                          dap_chain_net_srv_uid_t a_srv_uid,
                                                                          uint32_t a_usage_id,
                                                                          const char *a_str,
                                                                          ...);
