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
#include "dap_math_convert.h"
#include "dap_enc_key.h"
#include "dap_pkey.h"
#include "dap_sign.h"
#include "dap_hash.h"
#include "json.h"
#include "dap_strfuncs.h"

#define DAP_CHAIN_ADDR_VERSION_CURRENT 1

#define DAP_CHAIN_ID_SIZE           8
#define DAP_CHAIN_SHARD_ID_SIZE     8
#define DAP_CHAIN_NET_ID_SIZE       8
#define DAP_CHAIN_NODE_ROLE_SIZE    4
#define DAP_CHAIN_HASH_SLOW_SIZE    32
#define DAP_CHAIN_TIMESTAMP_SIZE    8
#define DAP_CHAIN_TICKER_SIZE_MAX   10

#define DATOSHI_LD 1000000000.0L    // Deprecated
#define DATOSHI_DEGREE 18
#define DATOSHI_POW 39
#define DATOSHI_POW256 (DATOSHI_POW * 2)

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

int dap_id_uint64_parse(const char *a_id_str, uint64_t *a_id);

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

DAP_STATIC_INLINE bool dap_chain_node_addr_str_check(const char *a_addr_str) {
    size_t l_str_len = dap_strlen(a_addr_str);
    if (l_str_len == 22) {
        for (int n =0; n < 22; n+= 6) {
            if (!dap_is_xdigit(a_addr_str[n]) || !dap_is_xdigit(a_addr_str[n + 1]) ||
                !dap_is_xdigit(a_addr_str[n + 2]) || !dap_is_xdigit(a_addr_str[n + 3])) {
                return false;
            }
        }
        for (int n = 4; n < 18; n += 6) {
            if (a_addr_str[n] != ':' || a_addr_str[n + 1] != ':')
                return false;
        }
        return true;
    }
    return false;
}

DAP_STATIC_INLINE int dap_chain_node_addr_from_str(dap_chain_node_addr_t *a_addr, const char *a_addr_str)
{
    if (!a_addr || !a_addr_str){
        return -1;
    }
    if (sscanf(a_addr_str, NODE_ADDR_FP_STR, NODE_ADDR_FPS_ARGS(a_addr)) == 4)
        return 0;
    if (sscanf(a_addr_str, "0x%016" DAP_UINT64_FORMAT_x, &a_addr->uint64) == 1)
        return 0;
    return -1;
}

DAP_STATIC_INLINE bool dap_chain_node_addr_not_null(dap_chain_node_addr_t * a_addr) { return a_addr->uint64 != 0; }

enum {
    NODE_ROLE_ROOT_MASTER=0x00,
    NODE_ROLE_ROOT=0x01,
    NODE_ROLE_ARCHIVE=0x02,
    NODE_ROLE_CELL_MASTER=0x10,
    NODE_ROLE_MASTER = 0x20,
    NODE_ROLE_FULL=0xf0,
    NODE_ROLE_LIGHT=0xff
};
typedef union dap_chain_node_role{
    uint32_t enums;
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
    union {
        //dap_chain_hash_fast_t hash;
        struct {
            uint8_t key_spend[sizeof(dap_chain_hash_fast_t)/2];
            uint8_t key_view[sizeof(dap_chain_hash_fast_t)/2];
        } DAP_ALIGN_PACKED key_sv;
        uint8_t key[sizeof(dap_chain_hash_fast_t)];
        uint8_t hash[sizeof(dap_chain_hash_fast_t)];
        dap_chain_hash_fast_t hash_fast;
    } DAP_ALIGN_PACKED data;
    dap_chain_hash_fast_t checksum;
}  DAP_ALIGN_PACKED dap_chain_addr_t;

#define DAP_CHAIN_NET_SRV_UID_SIZE 8

typedef union {
    uint8_t raw[DAP_CHAIN_NET_SRV_UID_SIZE];
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    uint64_t raw_ui64;
    uint64_t uint64;
#elif DAP_CHAIN_NET_SRV_UID_SIZE == 16
    uint64_t raw_ui64[2];
    uint128_t uint128;
#endif
} dap_chain_net_srv_uid_t;

extern const dap_chain_net_srv_uid_t c_dap_chain_net_srv_uid_null;
extern const dap_chain_cell_id_t c_dap_chain_cell_id_null;
extern const dap_chain_addr_t c_dap_chain_addr_blank;

enum dap_chain_srv_unit_enum {
    SERV_UNIT_UNDEFINED = 0 ,
    SERV_UNIT_MB = 0x00000001, // megabytes
    SERV_UNIT_SEC = 0x00000002, // seconds
    SERV_UNIT_DAY = 0x00000003,  // days
    SERV_UNIT_KB = 0x00000010,  // kilobytes
    SERV_UNIT_B = 0x00000011,   // bytes
    SERV_UNIT_PCS = 0x00000022  // pieces
};
typedef uint32_t dap_chain_srv_unit_enum_t;

DAP_STATIC_INLINE const char *dap_chain_srv_unit_enum_to_str(dap_chain_srv_unit_enum_t a_unit_enum)
{
    switch (a_unit_enum) {
    case SERV_UNIT_UNDEFINED: return "SERV_UNIT_UNDEFINED";
    case SERV_UNIT_MB: return "SERV_UNIT_MB";
    case SERV_UNIT_SEC: return "SERV_UNIT_SEC";
    case SERV_UNIT_DAY: return "SERV_UNIT_DAY";
    case SERV_UNIT_KB: return "SERV_UNIT_KB";
    case SERV_UNIT_B: return "SERV_UNIT_B";
    case SERV_UNIT_PCS: return "SERV_UNIT_PCS";
    default: return "UNDEFINED";
    }
}

DAP_STATIC_INLINE dap_chain_srv_unit_enum_t dap_chain_srv_str_to_unit_enum(char* a_price_unit_str) {
    if (!a_price_unit_str)
        return SERV_UNIT_UNDEFINED;
    if (!dap_strcmp(a_price_unit_str, "MB")){
        return SERV_UNIT_MB;
    } else if (!dap_strcmp(a_price_unit_str, "SEC")){
        return SERV_UNIT_SEC;
    } else if (!dap_strcmp(a_price_unit_str, "DAY")){
        return SERV_UNIT_DAY;
    } else if (!dap_strcmp(a_price_unit_str, "KB")){
        return SERV_UNIT_KB;
    } else if (!dap_strcmp(a_price_unit_str, "B")){
        return SERV_UNIT_B;
    } else if (!dap_strcmp(a_price_unit_str, "PCS")){
        return SERV_UNIT_PCS;
    }
    return SERV_UNIT_UNDEFINED;
}

typedef union {
    uint8_t raw[4];
    uint32_t uint32;
    dap_chain_srv_unit_enum_t enm;
} DAP_ALIGN_PACKED dap_chain_net_srv_price_unit_uid_t;

enum dap_chain_tx_item_type {
    TX_ITEM_TYPE_IN = 0x00, /// @brief  Transaction: inputs

    TX_ITEM_TYPE_OUT_OLD = 0x10, /// @brief  Transaction: outputs
    TX_ITEM_TYPE_OUT_EXT = 0x11,
    TX_ITEM_TYPE_OUT = 0x12, // 256

    TX_ITEM_TYPE_PKEY = 0x20,
    TX_ITEM_TYPE_SIG = 0x30,
    TX_ITEM_TYPE_IN_EMS = 0x40,
    TX_ITEM_TYPE_IN_EMS_EXT = 0x41,

    TX_ITEM_TYPE_IN_COND = 0x50, /// @brief  Transaction: conditon inputs

    TX_ITEM_TYPE_OUT_COND_OLD = 0x60, // Obsolete
    TX_ITEM_TYPE_OUT_COND = 0x61, /// @brief  Transaction: 256 bit conditon outputs

    TX_ITEM_TYPE_RECEIPT = 0x70,

    TX_ITEM_TYPE_TSD = 0x80,

    TX_ITEM_TYPE_IN_ALL = 0xfd,
    TX_ITEM_TYPE_OUT_ALL = 0xfe,
    TX_ITEM_TYPE_ANY = 0xff
};
#define TX_ITEM_TYPE_UNKNOWN TX_ITEM_TYPE_ANY
typedef byte_t dap_chain_tx_item_type_t;

#ifdef __cplusplus
extern "C" {
#endif

size_t dap_chain_hash_slow_to_str(dap_chain_hash_slow_t * a_hash, char * a_str, size_t a_str_max);

char* dap_chain_addr_to_str(const dap_chain_addr_t *a_addr);
json_object *dap_chain_addr_to_json(const dap_chain_addr_t *a_addr);
dap_chain_addr_t* dap_chain_addr_from_str(const char *str);
bool dap_chain_addr_is_blank(const dap_chain_addr_t *a_addr);

DAP_STATIC_INLINE json_object *dap_chain_net_id_to_json(dap_chain_net_id_t a_net_id) {
    return json_object_new_uint64(a_net_id.uint64);
}

dap_chain_net_srv_uid_t dap_chain_net_srv_uid_from_str(const char* a_str);

void dap_chain_addr_fill(dap_chain_addr_t *a_addr, dap_sign_type_t a_type, dap_chain_hash_fast_t *a_pkey_hash, dap_chain_net_id_t a_net_id);
int dap_chain_addr_fill_from_key(dap_chain_addr_t *a_addr, dap_enc_key_t *a_key, dap_chain_net_id_t a_net_id);
int dap_chain_addr_fill_from_sign(dap_chain_addr_t *a_addr, dap_sign_t *a_sign, dap_chain_net_id_t a_net_id);

int dap_chain_addr_check_sum(const dap_chain_addr_t *a_addr);

DAP_STATIC_INLINE bool dap_chain_addr_compare(const dap_chain_addr_t *a_addr1, const dap_chain_addr_t *a_addr2)
{
    return !memcmp(a_addr1, a_addr2, sizeof(dap_chain_addr_t));
}

// Deprecated
DAP_STATIC_INLINE long double dap_chain_datoshi_to_coins(uint64_t a_count)
{
    return (double)a_count / DATOSHI_LD;
}
// Deprecated
DAP_STATIC_INLINE uint64_t dap_chain_coins_to_datoshi(long double a_count)
{
    return (uint64_t)(a_count * DATOSHI_LD);
}

DAP_STATIC_INLINE uint128_t dap_chain_uint128_from(uint64_t a_from)
{
    return GET_128_FROM_64(a_from);
}

// 256
uint128_t dap_chain_uint128_from_uint256(uint256_t a_from);

// 256
DAP_STATIC_INLINE uint256_t dap_chain_uint256_from(uint64_t a_from)
{
    return GET_256_FROM_64(a_from);
}

DAP_STATIC_INLINE uint256_t dap_chain_uint256_from_uint128(uint128_t a_from)
{
    return GET_256_FROM_128(a_from);
}

uint64_t dap_chain_uint128_to(uint128_t a_from);
// 256
uint64_t dap_chain_uint256_to(uint256_t a_from);

#define dap_chain_balance_print(a_balance) dap_uint256_uninteger_to_char(a_balance)
#define dap_chain_balance_scan(a_balance) dap_uint256_scan_uninteger(a_balance)
#define dap_chain_balance_to_coins(a) dap_uint256_decimal_to_char(a)
#define dap_chain_coins_to_balance(a) dap_uint256_scan_decimal(a)


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
