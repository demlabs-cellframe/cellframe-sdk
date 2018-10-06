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

#include <stdint.h>
#include <stddef.h>
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_block.h"

#define STREAM_CH_CHAIN_PKT_TYPE_GENERAL       0x00
#define STREAM_CH_CHAIN_PKT_TYPE_BLOCK         0x01
#define STREAM_CH_CHAIN_PKT_TYPE_DATUM         0x02
#define STREAM_CH_CHAIN_PKT_TYPE_GLOVAL_DB     0xff

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

typedef struct stream_ch_chain_pkt_hdr{
    dap_chain_id_t chain_id;
    uint8_t type; // Chain data type
    uint8_t padding1[3]; // Some padding
    union{
        struct{
            uint8_t padding[];
        }type_general;
        struct{
            dap_chain_datum_typeid_t datum_id;

        }type_block;
        struct{
            dap_chain_datum_typeid_t datum_id;
        }type_datum;
        struct{

        }type_global_db;
        uint64_t type_raw;
    };
}  __attribute__((packed)) dap_stream_ch_chain_pkt_hdr_t;

typedef struct dap_stream_ch_chain_pkt{
    dap_stream_ch_chain_pkt_hdr_t hdr;
    uint8_t data[];
} __attribute__((packed)) dap_stream_ch_chain_pkt_t;

