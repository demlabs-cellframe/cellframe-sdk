/*
 * Authors:
 * Dmitrii Gerasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe https://cellframe.net
 * Copyright  (c) 2017-2019
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

#include "dap_chain_net_srv_order.h"

#include "dap_chain_global_db.h"

/**
 * @brief dap_chain_net_srv_order_init
 * @return
 */
int dap_chain_net_srv_order_init(void)
{
    return 0;
}

/**
 * @brief dap_chain_net_srv_order_deinit
 */
void dap_chain_net_srv_order_deinit()
{

}


dap_chain_net_srv_order_t * dap_chain_net_srv_order_find_by_pid(uint128_t a_proposal_id)
{
    return NULL;
}

int dap_chain_net_srv_order_find_all_by_(uint128_t proposal_id, dap_chain_net_srv_order_t *** a_output_orders, size_t * a_output_size)
{
    return 0;
}

void dap_chain_net_srv_order_destroy( dap_chain_net_srv_order_t * a_order)
{
    return 0;
}

void dap_chain_net_srv_order_destroy_all( dap_chain_net_srv_order_t *** a_orders, size_t * a_output_size)
{
    return 0;
}
