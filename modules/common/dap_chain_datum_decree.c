/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020, All rights reserved.

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

#include <memory.h>
#include <assert.h>
#include "dap_tsd.h"
#include "dap_common.h"
#include "dap_sign.h"
#include "dap_chain_datum_decree.h"

#define LOG_TAG "dap_chain_datum_decree"



dap_sign_t *dap_chain_datum_decree_get_sign(dap_chain_datum_decree_t *decree, size_t *sign_max_size)
{
    int ret = -1;
    uint32_t decree_tsd_pos = 0, decree_tsd_size = decree->header.tsd_size;
    dap_sign_t *l_sign = NULL;
    // Search sign section in tsd
    while(decree_tsd_pos < decree_tsd_size){
        dap_tsd_t *l_tsd = (dap_tsd_t *)(decree->tsd_sections + decree_tsd_pos);
        uint32_t l_decree_tsd_item_size = sizeof(dap_tsd_t) + l_tsd->size;
        if (!l_tsd->size || l_tsd->size > decree_tsd_size)
            return NULL;
        if (l_tsd->type != DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN)
        {
            decree_tsd_pos += l_decree_tsd_item_size;
            continue;
        }

        l_sign = (dap_sign_t *)(l_tsd->data);
        if ( ( l_sign->header.sign_size + l_sign->header.sign_pkey_size + sizeof (l_sign->header) )
              > l_decree_tsd_item_size ){
            log_it(L_WARNING,"Incorrect signature's header, possible corrupted data");
            return NULL;
        }

        decree_tsd_pos += l_decree_tsd_item_size;
    }

    // Check sign is found
    if (!l_sign)
    {
        log_it(L_WARNING,"Signature not found!");
        return NULL;
    }

    *sign_max_size = l_sign->header.sign_size + l_sign->header.sign_pkey_size + sizeof (l_sign->header);

    return l_sign;
}
