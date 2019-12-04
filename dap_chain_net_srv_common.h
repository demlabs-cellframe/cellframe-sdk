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
#include "dap_chain_common.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net.h"



//Units of service



//Service direction
typedef enum dap_chain_net_srv_order_direction{
    SERV_DIR_BUY = 1,
    SERV_DIR_SELL = 2,
    SERV_DIR_UNDEFINED = 0
} dap_chain_net_srv_order_direction_t;




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

typedef struct dap_chain_net_srv_price
{
    char * net_name;
    dap_chain_net_t * net;
    uint64_t value_datoshi;
    double value_coins;
    char token[DAP_CHAIN_TICKER_SIZE_MAX];
    uint64_t units;
    dap_chain_net_srv_price_unit_uid_t units_uid;
    struct dap_chain_net_srv_price * next;
    struct dap_chain_net_srv_price * prev;
} dap_chain_net_srv_price_t;



DAP_STATIC_INLINE const char * dap_chain_net_srv_price_unit_uid_to_str( dap_chain_net_srv_price_unit_uid_t a_uid )
{
    switch ( a_uid.enm) {
        case SERV_UNIT_UNDEFINED: return "BYTE";
        case SERV_UNIT_MB: return "MEGABYTE";
        case SERV_UNIT_SEC: return "SECOND";
        case SERV_UNIT_DAY: return  "DAY";
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
