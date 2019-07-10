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

#define LOG_TAG "dap_hash"

int dap_hash_fast(const void *a_data_in, size_t a_data_in_size, dap_chain_hash_fast_t *a_hash_out)
{
    if(!a_data_in || !a_data_in_size || !a_hash_out)
        return -1;
    dap_hash(a_data_in, a_data_in_size, a_hash_out->raw, sizeof(a_hash_out->raw),
            DAP_HASH_TYPE_KECCAK);
    return 1;
}

bool dap_hash_fast_is_blank(dap_chain_hash_fast_t *a_hash)
{
    if(!a_hash)
        return true;
    uint8_t *l_hast_bytes = (uint8_t*) a_hash;
    for(size_t i = 0; i < sizeof(dap_chain_hash_fast_t); i++) {
        if(l_hast_bytes[i])
            return false;
    }
    return true;
}

bool dap_hash_fast_compare(dap_chain_hash_fast_t *a_hash1, dap_chain_hash_fast_t *a_hash2)
{
    if(!a_hash1 || !a_hash2)
        return false;
    if(!memcmp(a_hash1, a_hash2, sizeof(dap_chain_hash_fast_t)))
        return true;
    return false;
}
