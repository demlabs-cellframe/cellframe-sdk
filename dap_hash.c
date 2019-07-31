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

#include "dap_common.h"
#include "dap_hash.h"

#include "KeccakHash.h"
#include "SimpleFIPS202.h"

#define LOG_TAG "dap_hash"

/**
int dap_hash_fast(const void *a_data_in, size_t a_data_in_size, dap_chain_hash_fast_t *a_hash_out)
{
    if(!a_data_in || !a_data_in_size || !a_hash_out)
        return -1;
//    dap_hash(a_data_in, a_data_in_size, a_hash_out->raw, sizeof(a_hash_out->raw),
//            DAP_HASH_TYPE_KECCAK);
    SHA3_256( (unsigned char *)a_hash_out, (const unsigned char *)a_data_in, a_data_in_size );

    return 1;
}
**/
