/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
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

#include <string.h>
#include "dap_common.h"
#include "dap_chain_common.h"

#define LOG_TAG "chain_common"

/**
 * @brief dap_chain_hash_to_str
 * @param a_hash
 * @param a_str
 * @param a_str_max
 * @return
 */
size_t dap_chain_hash_to_str(dap_chain_hash_t * a_hash, char * a_str, size_t a_str_max)
{
    const size_t c_hash_str_size = sizeof(*a_hash)*2 +1 /*trailing zero*/ +2 /* heading 0x */  ;
    if (a_str_max < c_hash_str_size ){
        log_it(L_ERROR,"String for hash too small, need %u but have only %u",c_hash_str_size,a_str_max);
    }
    size_t i;
    snprintf(a_str,3,"0x");
    for (i = 0; i< sizeof(a_hash->data); ++i)
        snprintf(a_str+i*2+2,3,"%02x",a_hash->data[i]);
    a_str[c_hash_str_size]='\0';
    return  strlen(a_str);
}
