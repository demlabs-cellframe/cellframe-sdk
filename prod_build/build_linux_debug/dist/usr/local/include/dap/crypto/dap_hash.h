/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
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

#include "dap_common.h"
#include "KeccakHash.h"


#define DAP_HASH_FAST_SIZE          32
#define DAP_CHAIN_HASH_FAST_SIZE    DAP_HASH_FAST_SIZE
#define DAP_CHAIN_HASH_FAST_STR_LEN (DAP_HASH_FAST_SIZE * 2 + 2 /* heading 0x */)
#define DAP_CHAIN_HASH_FAST_STR_SIZE (DAP_CHAIN_HASH_FAST_STR_LEN + 1 /*trailing zero*/)
#define DAP_HASH_FAST_STR_SIZE DAP_CHAIN_HASH_FAST_STR_SIZE

typedef enum dap_hash_type {
    DAP_HASH_TYPE_KECCAK = 0,
    DAP_HASH_TYPE_SLOW_0 = 1
} dap_hash_type_t;

typedef union dap_chain_hash_fast{
    uint8_t raw[DAP_CHAIN_HASH_FAST_SIZE];
} DAP_ALIGN_PACKED dap_chain_hash_fast_t;
typedef dap_chain_hash_fast_t dap_hash_fast_t;
typedef dap_hash_fast_t dap_hash_t;
typedef struct dap_hash_str {
    char s[DAP_HASH_FAST_STR_SIZE];
} dap_hash_str_t;

#ifdef __cplusplus
extern "C" {
#endif

#include "SimpleFIPS202.h"

int dap_chain_hash_fast_from_str( const char * a_hash_str, dap_hash_fast_t *a_hash);
int dap_chain_hash_fast_from_hex_str( const char *a_hex_str, dap_chain_hash_fast_t *a_hash);
int dap_chain_hash_fast_from_base58_str(const char *a_base58_str,  dap_chain_hash_fast_t *a_hash);
/**
 * @brief
 * get SHA3_256 hash for specific data
 * @param a_data_in input data
 * @param a_data_in_size size of input data
 * @param a_hash_out returned hash
 * @return true
 * @return false
 */
DAP_STATIC_INLINE bool dap_hash_fast( const void *a_data_in, size_t a_data_in_size, dap_hash_fast_t *a_hash_out )
{
    if ( (a_data_in == NULL) || (a_data_in_size == 0) || (a_hash_out == NULL) )
        return false;

    //            dap_hash_keccak( a_data_in, a_data_in_size, a_data_out, a_data_out_size );

    SHA3_256( (unsigned char *)a_hash_out, (const unsigned char *)a_data_in, a_data_in_size );

    return true;
}


/**
 * @brief dap_hash_fast_compare
 * compare to hashes (dap_hash_fast_t) through memcmp
 * @param a_hash1 - dap_hash_fast_t hash1
 * @param a_hash2 - dap_hash_fast_t hash2
 * @return
 */
DAP_STATIC_INLINE bool dap_hash_fast_compare(const dap_hash_fast_t *a_hash1, const dap_hash_fast_t *a_hash2)
{
    if(!a_hash1 || !a_hash2)
        return false;
    return !memcmp(a_hash1, a_hash2, sizeof(dap_hash_fast_t)); /* 0 - true, <> 0 - false */
}

/**
 * @brief
 * compare hash with blank hash
 * @param a_hash
 * @return true
 * @return false
 */

DAP_STATIC_INLINE bool dap_hash_fast_is_blank( const dap_hash_fast_t *a_hash )
{
    static dap_hash_fast_t l_blank_hash = {};
    return dap_hash_fast_compare(a_hash, &l_blank_hash);
}

DAP_STATIC_INLINE void dap_chain_hash_fast_to_str_do(const dap_hash_fast_t *a_hash, char *a_str)
{
    a_str[0] = '0';
    a_str[1] = 'x';
    dap_htoa64((a_str + 2), a_hash->raw, DAP_CHAIN_HASH_FAST_SIZE);
    a_str[ DAP_CHAIN_HASH_FAST_STR_SIZE - 1 ] = '\0';
}

DAP_STATIC_INLINE int dap_chain_hash_fast_to_str(const dap_hash_fast_t *a_hash, char *a_str, size_t a_str_max )
{
    if(! a_hash )
        return -1;
    if(! a_str )
        return -2;
    if( a_str_max < DAP_CHAIN_HASH_FAST_STR_SIZE )
        return -3;
    dap_chain_hash_fast_to_str_do(a_hash, a_str);
    return DAP_CHAIN_HASH_FAST_STR_SIZE;
}

DAP_STATIC_INLINE dap_hash_str_t dap_chain_hash_fast_to_hash_str(const dap_hash_fast_t *a_hash) {
    dap_hash_str_t l_ret = { };
    dap_chain_hash_fast_to_str(a_hash, l_ret.s, DAP_CHAIN_HASH_FAST_STR_SIZE);
    return l_ret;
}

#define dap_chain_hash_fast_to_str_static(hash) dap_chain_hash_fast_to_hash_str(hash).s
#define dap_hash_fast_to_str dap_chain_hash_fast_to_str
#define dap_hash_fast_to_str_static dap_chain_hash_fast_to_str_static

DAP_STATIC_INLINE char *dap_chain_hash_fast_to_str_new(const dap_hash_fast_t *a_hash)
{
    if (!a_hash)
        return NULL;
    char *l_ret = DAP_NEW_Z_SIZE(char, DAP_CHAIN_HASH_FAST_STR_SIZE);
    // Avoid compiler warning with NULL '%s' argument
    dap_chain_hash_fast_to_str_do(a_hash, l_ret);
    return l_ret;
}

#define dap_hash_fast_to_str_new dap_chain_hash_fast_to_str_new

/**
 * @brief dap_hash_fast_str_new
 * @param a_data
 * @param a_data_size
 * @return
 */
DAP_STATIC_INLINE char *dap_hash_fast_str_new( const void *a_data, size_t a_data_size )
{
    if(!a_data || !a_data_size)
        return NULL;

    dap_chain_hash_fast_t l_hash = { };
    dap_hash_fast(a_data, a_data_size, &l_hash);
    char *a_str = DAP_NEW_Z_SIZE(char, DAP_CHAIN_HASH_FAST_STR_SIZE);
    if (dap_chain_hash_fast_to_str(&l_hash, a_str, DAP_CHAIN_HASH_FAST_STR_SIZE) > 0)
        return a_str;
    DAP_DELETE(a_str);
    return NULL;
}

DAP_STATIC_INLINE dap_hash_str_t dap_get_data_hash_str(const void *a_data, size_t a_data_size)
{
    dap_hash_str_t l_ret = { };
    dap_hash_fast_t dummy_hash;
    dap_hash_fast(a_data, a_data_size, &dummy_hash);
    dap_chain_hash_fast_to_str(&dummy_hash, l_ret.s, DAP_CHAIN_HASH_FAST_STR_SIZE);
    return l_ret;
}

#ifdef __cplusplus
}
#endif
