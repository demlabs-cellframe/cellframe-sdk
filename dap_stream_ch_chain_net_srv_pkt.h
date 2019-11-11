/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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
**/

#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "dap_chain_net_srv_common.h"


#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST                       0x01
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE                      0x02
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_DBG                           0x99
#define DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_ERROR                         0xff


typedef struct dap_stream_ch_chain_net_srv_pkt_request{
    struct{
        dap_chain_net_id_t net_id;// Network id wheither to request
        dap_chain_hash_fast_t tx_cond; // Conditioned transaction with paymemt for
        dap_chain_net_srv_uid_t srv_uid;
        dap_chain_net_srv_class_t srv_class;
    } hdr;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_srv_pkt_request;
