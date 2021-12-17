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
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#include "dap_common.h"
#include "dap_hash_keccak.h"

#include "KeccakHash.h"
#include "SimpleFIPS202.h"

#define DAP_HASH_FAST_SIZE  32
#define DAP_CHAIN_HASH_FAST_SIZE    32
#define DAP_CHAIN_HASH_FAST_STR_SIZE (DAP_CHAIN_HASH_FAST_SIZE * 2 + 2 /* heading 0x */ + 1 /*trailing zero*/)
#define DAP_CHAIN_HASH_MAX_SIZE 63

typedef enum dap_hash_type {
    DAP_HASH_TYPE_KECCAK = 0,
    DAP_HASH_TYPE_SLOW_0 = 1,
} dap_hash_type_t;

typedef union dap_chain_hash_fast{
    uint8_t raw[DAP_CHAIN_HASH_FAST_SIZE];
} DAP_ALIGN_PACKED dap_chain_hash_fast_t;
typedef dap_chain_hash_fast_t dap_hash_fast_t;

#ifdef __cplusplus
extern "C" {
#endif

int dap_chain_hash_fast_from_str( const char * a_hash_str, dap_hash_fast_t * a_hash);

/**
 * @brief 
 * get SHA3_256 hash for specific data
 * @param a_data_in input data
 * @param a_data_in_size size of input data
 * @param a_hash_out returned hash
 * @return true 
 * @return false 
 */
static inline bool dap_hash_fast( const void *a_data_in, size_t a_data_in_size, dap_hash_fast_t *a_hash_out )
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
static inline bool dap_hash_fast_compare(dap_hash_fast_t *a_hash1, dap_hash_fast_t *a_hash2)
{
    if(!a_hash1 || !a_hash2)
        return false;
    if(!memcmp(a_hash1, a_hash2, sizeof(dap_hash_fast_t)))
        return true;
    return false;
}

/**
 * @brief 
 * compare hash with blank hash
 * @param a_hash 
 * @return true 
 * @return false 
 */

static inline bool dap_hash_fast_is_blank( dap_hash_fast_t *a_hash )
{
    static dap_hash_fast_t l_blank_hash = {};
    return dap_hash_fast_compare( a_hash, &l_blank_hash);
}


DAP_STATIC_INLINE int dap_chain_hash_fast_to_str( dap_hash_fast_t *a_hash, char *a_str, size_t a_str_max )
{
    if(! a_hash )
        return -1;
    if(! a_str )
        return -2;
    if( a_str_max < DAP_CHAIN_HASH_FAST_STR_SIZE )
        return -3;
    a_str[0] = '0';
    a_str[1] = 'x';
    a_str[ DAP_CHAIN_HASH_FAST_STR_SIZE - 1 ] = 0;
    dap_htoa64((a_str + 2), a_hash->raw, DAP_CHAIN_HASH_FAST_SIZE);
    return DAP_CHAIN_HASH_FAST_STR_SIZE;
}

#define dap_hash_fast_to_str dap_chain_hash_fast_to_str

DAP_STATIC_INLINE char *dap_chain_hash_fast_to_str_new(dap_hash_fast_t * a_hash)
{
    const size_t c_hash_str_size = DAP_CHAIN_HASH_FAST_STR_SIZE;
    char * ret = DAP_NEW_Z_SIZE(char, c_hash_str_size);
    if(dap_chain_hash_fast_to_str( a_hash, ret, c_hash_str_size ) < 0 )
        DAP_DEL_Z(ret);
    return ret;
}

#define dap_hash_fast_to_str_new dap_chain_hash_fast_to_str_new

#ifdef __cplusplus
}
#endif
