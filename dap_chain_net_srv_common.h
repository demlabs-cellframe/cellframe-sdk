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
#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_server.h"
#include "dap_stream_ch.h"
#include "dap_chain_ledger.h"

#define DAP_CHAIN_NET_SRV_UID_SIZE 8

typedef union {
    uint8_t raw[DAP_CHAIN_NET_SRV_UID_SIZE];
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    uint64_t raw_ui64[1];
    uint64_t uint64;
#elif DAP_CHAIN_NET_SRV_UID_SIZE == 16
    uint64_t raw_ui64[1];
    uint128_t uint128;
#endif
} dap_chain_net_srv_uid_t;

#define DAP_CHAIN_NET_SRV_PRICE_UNIT_UNDEFINED                        0x00000000
#define DAP_CHAIN_NET_SRV_PRICE_UNIT_BYTE                             0x00000001
#define DAP_CHAIN_NET_SRV_PRICE_UNIT_SECOND                           0x00000010
#define DAP_CHAIN_NET_SRV_PRICE_UNIT_BYTE_PER_SECOND                  0x00000100

typedef union {
    uint8_t raw[4];
    uint32_t raw_ui32[1];
    uint32_t uint32;
} dap_chain_net_srv_price_unit_uid_t;

//Classes of services
typedef enum {
    SERV_CLASS_ONCE = 1, // one-time service (Token exchange )
    SERV_CLASS_PERMANENT = 2 ,// Permanent working service (VPN, CDN, Streaming)
    SERV_CLASS_UNDEFINED = 0
} dap_chain_net_srv_class_t;

//Service direction
typedef enum dap_chain_net_srv_order_direction{
    SERV_DIR_BUY = 0x01,
    SERV_DIR_SELL = 0x02,
    SERV_DIR_UNDEFINED = 0x00
} dap_chain_net_srv_order_direction_t;

//Types of services
enum {
    SERV_ID_UNDEFINED = 0x00000000,
    SERV_ID_VPN = 0x00000001,
};

//Units of service
enum {
    SERV_UNIT_MB = 1, // megabytes
    SERV_UNIT_SEC = 2, // seconds
    SERV_UNIT_DAY = 3 // days
};

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

typedef void (*dap_chain_callback_trafic_t)(dap_client_remote_t *, dap_stream_ch_t *);

typedef struct dap_chain_net_srv
{
    dap_chain_net_srv_uid_t uid; // Unique ID for service.
    dap_chain_net_srv_abstract_t srv_common;

    dap_chain_callback_trafic_t callback_trafic;
    void * _internal;
    //void * _inhertor;
} dap_chain_net_srv_t;

DAP_STATIC_INLINE const char * dap_chain_net_srv_price_unit_uid_to_str( dap_chain_net_srv_price_unit_uid_t a_uid )
{
    switch ( a_uid.uint32 ) {
        case DAP_CHAIN_NET_SRV_PRICE_UNIT_BYTE: return "BYTE";
        case DAP_CHAIN_NET_SRV_PRICE_UNIT_SECOND: return "SECOND";
        case DAP_CHAIN_NET_SRV_PRICE_UNIT_BYTE_PER_SECOND: return  "BYTE_PER_SECOND";
        default: return "UNKNOWN";
    }
}

// Initialize dap_chain_net_srv_abstract_t structure
void dap_chain_net_srv_abstract_set(dap_chain_net_srv_abstract_t *a_cond, uint8_t a_class, uint128_t a_type_id,
        uint64_t a_price, uint8_t a_price_units, const char *a_decription);

// copy a_value_dst to a_uid_src
void dap_chain_net_srv_uid_set(dap_chain_net_srv_uid_t *a_uid_src, uint128_t a_value_dst);

// generate new dap_chain_net_srv_uid_t
bool dap_chain_net_srv_gen_uid(uint8_t *a_srv, size_t a_srv_size);

uint64_t dap_chain_net_srv_client_auth(dap_ledger_t  *a_ledger,
        const char *a_service_key, const dap_chain_net_srv_abstract_t **a_cond_out);
