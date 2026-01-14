/*
 * Authors:
 * Dmitriy Gerasimov <naeper@demlabs.net>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * This file is part of CellFrame SDK the open source project
 *
 *    CellFrame SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    CellFrame SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dap_chain.h"
#include "dap_chain_net_types.h"
#include "dap_chain_net_utils.h"
#include "utlist.h"

/**
 * @brief dap_chain_net_get_default_chain_by_chain_type
 * @param a_datum_type
 * @return
 */
dap_chain_t * dap_chain_net_get_default_chain_by_chain_type(dap_chain_net_t *a_net, dap_chain_type_t a_datum_type)
{
    dap_chain_t * l_chain;

    if (!a_net)
        return NULL;

    DL_FOREACH(a_net->pub.chains, l_chain)
    {
        for(int i = 0; i < l_chain->default_datum_types_count; i++) {
            if(l_chain->default_datum_types[i] == a_datum_type)
                return l_chain;
        }
    }
    return NULL;
}
