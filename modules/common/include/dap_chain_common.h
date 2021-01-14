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
#include "dap_enc_key.h"
#include "dap_pkey.h"
#include "dap_sign.h"
#include "dap_hash.h"

#define DAP_CHAIN_ADDR_VERSION_CURRENT 1

#define DAP_CHAIN_ID_SIZE           8
#define DAP_CHAIN_SHARD_ID_SIZE     8
#define DAP_CHAIN_NET_ID_SIZE       8
#define DAP_CHAIN_NODE_ROLE_SIZE    2
#define DAP_CHAIN_HASH_SLOW_SIZE    32
#define DAP_CHAIN_TIMESTAMP_SIZE    8
#define DAP_CHAIN_TICKER_SIZE_MAX   10

#define DATOSHI_LD 1000000000.0L
#define DATOSHI_DEGREE 9
#define DATOSHI_POW 38

// Chain ID of the whole system
typedef union dap_chain_id {
    uint8_t raw[DAP_CHAIN_ID_SIZE];
    uint64_t uint64;
} DAP_ALIGN_PACKED dap_chain_id_t;

// Shard ID
typedef union dap_chain_cell_id {
    uint8_t raw[DAP_CHAIN_SHARD_ID_SIZE];
    uint64_t uint64;
} DAP_ALIGN_PACKED dap_chain_cell_id_t;


/**
  * @struct Node address
  *
  */
typedef union dap_chain_node_addr {
    uint64_t uint64;
    uint16_t words[sizeof(uint64_t)/2];
    uint8_t raw[sizeof(uint64_t)];  // Access to selected octects
} DAP_ALIGN_PACKED dap_chain_node_addr_t;

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define NODE_ADDR_FP_STR      "%04hX::%04hX::%04hX::%04hX"
#define NODE_ADDR_FP_ARGS(a)  a->words[2],a->words[3],a->words[0],a->words[1]
#define NODE_ADDR_FPS_ARGS(a)  &a->words[2],&a->words[3],&a->words[0],&a->words[1]
#define NODE_ADDR_FP_ARGS_S(a)  a.words[2],a.words[3],a.words[0],a.words[1]
#define NODE_ADDR_FPS_ARGS_S(a)  &a.words[2],&a.words[3],&a.words[0],&a.words[1]
#else
#define NODE_ADDR_FP_STR      "%04hX::%04hX::%04hX::%04hX"
#define NODE_ADDR_FP_ARGS(a)  a->words[3],a->words[2],a->words[1],a->words[0]
#define NODE_ADDR_FPS_ARGS(a)  &a->words[3],&a->words[2],&a->words[1],&a->words[0]
#define NODE_ADDR_FP_ARGS_S(a)  a.words[3],a.words[2],a.words[1],a.words[0]
#define NODE_ADDR_FPS_ARGS_S(a)  &a.words[3],&a.words[2],&a.words[1],&a.words[0]

#endif

inline static int dap_chain_node_addr_from_str( dap_chain_node_addr_t * a_addr, const char * a_addr_str){
    return (int) sscanf(a_addr_str,NODE_ADDR_FP_STR,NODE_ADDR_FPS_ARGS(a_addr) )-4;
}
/**
  *
  *
  *
  *
  */
typedef union dap_chain_node_role{
    enum {
        NODE_ROLE_ROOT_MASTER=0x00,
        NODE_ROLE_ROOT=0x01,
        NODE_ROLE_ARCHIVE=0x02,
        NODE_ROLE_CELL_MASTER=0x10,
        NODE_ROLE_MASTER = 0x20,
        NODE_ROLE_FULL=0xf0,
        NODE_ROLE_LIGHT=0xff } enums;
    uint8_t raw[DAP_CHAIN_NODE_ROLE_SIZE];
} DAP_ALIGN_PACKED dap_chain_node_role_t;


typedef union dap_chain_net_id{
    uint64_t uint64;
    uint8_t raw[DAP_CHAIN_NET_ID_SIZE];
} DAP_ALIGN_PACKED dap_chain_net_id_t;

typedef union dap_chain_hash_slow{
    uint8_t raw[DAP_CHAIN_HASH_SLOW_SIZE];
}  dap_chain_hash_slow_t;



typedef enum dap_chain_hash_slow_kind {
    HASH_GOLD = 0, HASH_SILVER, HASH_COPPER, HASH_USELESS = -1
} dap_chain_hash_slow_kind_t;


typedef struct dap_chain_addr{
    uint8_t addr_ver; // 0 for default
    dap_chain_net_id_t net_id;  // Testnet, mainnet or alternet
    dap_sign_type_t sig_type;
    union{
        //dap_chain_hash_fast_t hash;
        struct {
            uint8_t key_spend[sizeof(dap_chain_hash_fast_t)/2];
            uint8_t key_view[sizeof(dap_chain_hash_fast_t)/2];
        } key_sv;
        uint8_t key[sizeof(dap_chain_hash_fast_t)];
        uint8_t hash[sizeof(dap_chain_hash_fast_t)];
        dap_chain_hash_fast_t hash_fast;
    } data;
    dap_chain_hash_fast_t checksum;
}  DAP_ALIGN_PACKED dap_chain_addr_t;

typedef uint64_t dap_chain_time_t;
static inline dap_chain_time_t dap_chain_time_now() { return (dap_chain_time_t) time(NULL); }

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

typedef enum {
    SERV_UNIT_UNDEFINED = 0 ,
    SERV_UNIT_MB = 0x00000001, // megabytes
    SERV_UNIT_SEC = 0x00000002, // seconds
    SERV_UNIT_DAY = 0x00000003,  // days
    SERV_UNIT_KB = 0x00000010,  // kilobytes
    SERV_UNIT_B = 0x00000011,   // bytes
} serv_unit_enum_t;

typedef union {
    uint8_t raw[4];
    uint32_t raw_ui32[1];
    uint32_t uint32;
    serv_unit_enum_t enm;
} dap_chain_net_srv_price_unit_uid_t;

typedef enum dap_chain_tx_item_type {
    TX_ITEM_TYPE_IN = 0x00, /// @brief  Transaction: inputs
    TX_ITEM_TYPE_OUT = 0x10, /// @brief  Transaction: outputs
    TX_ITEM_TYPE_OUT_EXT = 0x11,
    TX_ITEM_TYPE_PKEY = 0x20,
    TX_ITEM_TYPE_SIG = 0x30,
    TX_ITEM_TYPE_TOKEN = 0x40,
    TX_ITEM_TYPE_TOKEN_EXT = 0x41,
    TX_ITEM_TYPE_IN_COND = 0x50, /// @brief  Transaction: conditon inputs
    TX_ITEM_TYPE_OUT_COND = 0x60, /// @brief  Transaction: conditon outputs
    TX_ITEM_TYPE_RECEIPT = 0x70,

    TX_ITEM_TYPE_OUT_ALL = 0xfe,
    TX_ITEM_TYPE_ANY = 0xff
} dap_chain_tx_item_type_t;


typedef struct dap_chain_receipt{
    dap_chain_net_srv_uid_t srv_uid; // Service UID
    dap_chain_net_srv_price_unit_uid_t units_type;
    uint64_t units; // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
    uint64_t value_datoshi; // Receipt value
} dap_chain_receipt_info_t;


#ifdef __cplusplus
extern "C" {
#endif

size_t dap_chain_hash_slow_to_str(dap_chain_hash_slow_t * a_hash, char * a_str, size_t a_str_max);

char* dap_chain_addr_to_str(const dap_chain_addr_t *a_addr);
dap_chain_addr_t* dap_chain_addr_from_str(const char *str);

dap_chain_net_id_t dap_chain_net_id_from_str(const char* a_str);
dap_chain_net_srv_uid_t dap_chain_net_srv_uid_from_str(const char* a_str);

void dap_chain_addr_fill(dap_chain_addr_t *a_addr, dap_sign_type_t a_type, dap_chain_hash_fast_t *a_pkey_hash, dap_chain_net_id_t a_net_id);
void dap_chain_addr_fill_from_key(dap_chain_addr_t *a_addr, dap_enc_key_t *a_key, dap_chain_net_id_t a_net_id);

int dap_chain_addr_check_sum(const dap_chain_addr_t *a_addr);

DAP_STATIC_INLINE long double dap_chain_datoshi_to_coins(uint64_t a_count)
{
    return (double)a_count / DATOSHI_LD;
}

DAP_STATIC_INLINE uint64_t dap_chain_coins_to_datoshi(long double a_count)
{
    return (uint64_t)(a_count * DATOSHI_LD);
}

DAP_STATIC_INLINE uint128_t dap_chain_uint128_from(uint64_t a_from)
{
#ifdef DAP_GLOBAL_IS_INT128
    return (uint128_t)a_from;
#else
    uint128_t l_ret = { .u64 = {0, a_from} };
    return l_ret;
#endif
}

uint64_t dap_chain_uint128_to(uint128_t a_from);

char *dap_chain_balance_print(uint128_t a_balance);
char *dap_chain_balance_to_coins(uint128_t a_balance);
uint128_t dap_chain_balance_scan(char *a_balance);
uint128_t dap_chain_coins_to_balance(char *a_coins);

/**
 * @brief dap_chain_hash_to_str
 * @param a_hash
 * @return
 */

static inline char * dap_chain_hash_slow_to_str_new(dap_chain_hash_slow_t * a_hash)
{
    const size_t c_hash_str_size = sizeof(*a_hash)*2 +1 /*trailing zero*/ +2 /* heading 0x */  ;
    char * ret = DAP_NEW_Z_SIZE(char, c_hash_str_size);
    dap_chain_hash_slow_to_str(a_hash,ret,c_hash_str_size);
    return ret;
}



/**
 * @brief dap_chain_hash_kind_check
 * @param a_hash
 * @details
 */
static inline dap_chain_hash_slow_kind_t dap_chain_hash_slow_kind_check(dap_chain_hash_slow_t * a_hash, const uint8_t a_valuable_head  )
{
    uint8_t i;
    uint8_t l_hash_first = a_hash->raw[0];
    uint8_t * l_hash_data = a_hash->raw;
    for ( i = 1; i < a_valuable_head; ++i ){
        if ( l_hash_data[i] != l_hash_first  )
            return HASH_USELESS;
    }
    if( l_hash_first == 0 )
        return HASH_GOLD;
    else
        return HASH_SILVER;
}


#ifdef __cplusplus
}
#endif
