/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net    https:/gitlab.com/demlabs
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
*/

#pragma once
#include <stdint.h>
#include <stdio.h>

#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_chain_sign.h"
#include "dap_chain_pkey.h"

#define DAP_CHAIN_ID_SIZE 8
#define DAP_CHAIN_SHARD_ID_SIZE 8
#define DAP_CHAIN_NET_ID_SIZE 8
#define DAP_CHAIN_NODE_ROLE_SIZE 2
#define DAP_CHAIN_HASH_SIZE 32
#define DAP_CHAIN_HASH_FAST_SIZE 24
#define DAP_CHAIN_ADDR_HASH_SIZE 24
#define DAP_CHAIN_TIMESTAMP_SIZE 8
// Chain ID of the whole system
typedef union dap_chain_id{
    uint8_t raw[DAP_CHAIN_ID_SIZE];
    uint64_t uint64;
} DAP_ALIGN_PACKED dap_chain_id_t;

// Shard ID
typedef union dap_chain_shard_id{
    uint8_t raw[DAP_CHAIN_SHARD_ID_SIZE];
} DAP_ALIGN_PACKED dap_chain_shard_id_t;

/**
  *
  *
  *
  *
  */
typedef union dap_chain_node_role{
    enum {
        ROOT=0x00,
        ROOT_DELEGATE=0x01,
        SHARD_DELEGATE=0x02,
        ARCHIVE=0x10,
        MASTER = 0x20,
        FULL=0xf0,
        LIGHT=0xff } enums;
    uint8_t raw[DAP_CHAIN_NODE_ROLE_SIZE];
} DAP_ALIGN_PACKED dap_chain_node_role_t;


typedef union dap_chain_net_id{
    uint64_t uint64;
    uint8_t raw[DAP_CHAIN_NET_ID_SIZE];
} DAP_ALIGN_PACKED dap_chain_net_id_t;


typedef union dap_chain_hash{
    uint8_t raw[DAP_CHAIN_HASH_SIZE];
} DAP_ALIGN_PACKED dap_chain_hash_t;

typedef union dap_chain_hash_fast{
    uint8_t raw[DAP_CHAIN_HASH_FAST_SIZE];
} DAP_ALIGN_PACKED dap_chain_hash_fast_t;

typedef enum dap_chain_hash_kind {
    HASH_GOLD = 0, HASH_SILVER, HASH_COPPER, HASH_USELESS = -1
} dap_chain_hash_kind_t;


typedef struct dap_chain_addr{
    dap_chain_sign_type_t sig_type;
    uint8_t hash[DAP_CHAIN_ADDR_HASH_SIZE];
    uint64_t checksum;
} dap_chain_addr_t;


size_t dap_chain_hash_to_str(dap_chain_hash_t * a_hash, char * a_str, size_t a_str_max);

/**
 * @brief dap_chain_hash_to_str
 * @param a_hash
 * @return
 */
static inline char * dap_chain_hash_to_str_new(dap_chain_hash_t * a_hash)
{
    const size_t c_hash_str_size = sizeof(*a_hash)*2 +1 /*trailing zero*/ +2 /* heading 0x */  ;
    char * ret = DAP_NEW_Z_SIZE(char, c_hash_str_size);
    dap_chain_hash_to_str(a_hash,ret,c_hash_str_size);
    return ret;
}

/**
 * @brief dap_chain_hash_kind_check
 * @param a_hash
 * @details
 */
static inline dap_chain_hash_kind_t dap_chain_hash_kind_check(dap_chain_hash_t * a_hash, const uint8_t a_valuable_head  )
{
    register uint8_t i;
    register uint8_t l_hash_first = a_hash->raw[0];
    register uint8_t * l_hash_data = a_hash->raw;
    for ( i = 1; i < a_valuable_head; ++i ){
        if ( l_hash_data[i] != l_hash_first  )
            return HASH_USELESS;
    }
    if( l_hash_first == 0 )
        return HASH_GOLD;
    else
        return HASH_SILVER;
}
