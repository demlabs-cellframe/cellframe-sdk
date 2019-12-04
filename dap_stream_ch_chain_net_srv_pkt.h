/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "dap_chain_net_srv_common.h"


// Ch pkt types
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST                       0x01
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST                  0x10
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_RESPONSE                 0x11
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS              0xf0
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR                0xff

#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_UNDEFINED                  0x00000000
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_NOT_FOUND          0x00000100
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_NOT_FOUND          0x00000200
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_NETWORK_NO_LEDGER          0x00000201
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_USAGE_CANT_ADD             0x00000300
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND          0x00000400
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NO_COND_OUT        0x00000401
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ENOUGH         0x00000402
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_ACCEPT_TOKEN   0x00000403
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_WRONG_SRV_UID      0x00000404
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_WRONG_SIZE         0x00000404
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_CANT_FIND          0x00000500
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_NO_SIGN            0x00000501
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_WRONG_PKEY_HASH         0x00000502

#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_UNKNOWN                    0xffffffff
// TYPE_REQUEST
typedef struct dap_stream_ch_chain_net_srv_pkt_request_hdr{
    dap_chain_net_id_t net_id;// Network id wheither to request
    dap_chain_hash_fast_t tx_cond; // Conditioned transaction with paymemt for
    dap_chain_net_srv_uid_t srv_uid;
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_request_hdr_t;

typedef struct dap_stream_ch_chain_net_srv_pkt_request{
    dap_stream_ch_chain_net_srv_pkt_request_hdr_t hdr;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_request_t;

// TYPE_RESPONSE_ERROR
typedef struct dap_stream_ch_chain_net_srv_pkt_error{
    uint32_t code; // error code
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_error_t;
