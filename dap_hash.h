/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "dap_hash_slow.h"
#include "dap_hash_keccak.h"
#include "dap_chain_common.h"

#include "KeccakHash.h"
#include "SimpleFIPS202.h"

#define DAP_HASH_FAST_SIZE  32

typedef enum dap_hash_type {
    DAP_HASH_TYPE_KECCAK = 0,
    DAP_HASH_TYPE_SLOW_0 = 1,
} dap_hash_type_t;


static inline void dap_hash(const void * a_data_in, size_t a_data_in_size,
                     void * a_data_out, size_t a_data_out_size,
                     dap_hash_type_t a_type ){
    switch (a_type){
        case DAP_HASH_TYPE_KECCAK:
//            dap_hash_keccak( a_data_in, a_data_in_size, a_data_out, a_data_out_size );
            SHA3_256( (unsigned char *)a_data_out, (const unsigned char *)a_data_in, a_data_in_size );
        break;
        case DAP_HASH_TYPE_SLOW_0:
            if( a_data_out_size>= dap_hash_slow_size() ){
                dap_hash_slow(a_data_in,a_data_in_size,(char*) a_data_out);
            }
        break;
    }
}

static inline bool dap_hash_fast( const void *a_data_in, size_t a_data_in_size, dap_chain_hash_fast_t *a_hash_out )
{
    if ( (a_data_in == NULL) || (a_data_in_size == 0) || (a_hash_out == NULL) )
        return false;

    dap_hash(a_data_in, a_data_in_size, a_hash_out->raw, sizeof(a_hash_out->raw ),
            DAP_HASH_TYPE_KECCAK);

  //SHA3_256( (unsigned char *)a_hash_out, (const unsigned char *)a_data_in, a_data_in_size );

  return true;
}


/**
 * @brief dap_hash_fast_compare
 * @param a_hash1
 * @param a_hash2
 * @return
 */
static inline bool dap_hash_fast_compare(dap_chain_hash_fast_t *a_hash1, dap_chain_hash_fast_t *a_hash2)
{
    if(!a_hash1 || !a_hash2)
        return false;
    if(!memcmp(a_hash1, a_hash2, sizeof(dap_chain_hash_fast_t)))
        return true;
    return false;
}

static inline bool dap_hash_fast_is_blank( dap_chain_hash_fast_t *a_hash )
{
    static dap_chain_hash_fast_t l_blank_hash = { 0};
//    uint8_t *l_hast_bytes = (uint8_t*) a_hash;
//    for(size_t i = 0; i < sizeof(dap_chain_hash_fast_t); i++) {
//        if(l_hast_bytes[i])
//            return false;
//    }
    return dap_hash_fast_compare( a_hash, &l_blank_hash);
}


