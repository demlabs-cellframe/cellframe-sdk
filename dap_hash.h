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

#include "dap_hash_slow.h"
#include "dap_hash_keccak.h"



typedef enum dap_hash_type {
    DAP_HASH_TYPE_KECCAK = 0,
    DAP_HASH_TYPE_SLOW_0 = 1,
} dap_hash_type_t;

inline void dap_hash(void * a_data_in, size_t a_data_in_size,
                     void * a_data_out, size_t a_data_out_size,
                     dap_hash_type_t a_type ){
    switch (a_type){
        case DAP_HASH_TYPE_KECCAK:
            dap_hash_keccak(a_data_in,a_data_in_size, a_data_out,a_data_out_size);
        break;
        case DAP_HASH_TYPE_SLOW_0:
            if( a_data_out_size>= dap_hash_slow_size() ){
                dap_hash_slow(a_data_in,a_data_in_size,(char*) a_data_out);
            }
        break;
    }

}
