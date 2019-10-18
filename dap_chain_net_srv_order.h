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

#pragma once
#include "dap_common.h"
#include "dap_chain_net_srv_common.h"

typedef struct dap_chain_net_srv_order
{
    dap_chain_net_srv_proposal_uid_t proposal_id; // id trade proposal. Must be unique to the network
    dap_chain_net_srv_uid_t srv_uid; // Service UID
    dap_chain_net_srv_class_t srv_class:8; //Class of service (once or permanent)
    uint64_t *prices; //  service price, for SERV_CLASS_ONCE ONCE for the whole service, for SERV_CLASS_PERMANENT  for one unit.
    size_t prices_size;
    dap_chain_net_srv_price_unit_uid_t price_units; // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
    size_t price_units_size;

    dap_chain_node_addr_t node_addr; // Node address that servs the order (if present)
    dap_chain_hash_fast_t tx_cond_hash; // Hash index of conditioned transaction attached with order

    char comments[128];
} dap_chain_net_srv_order_t;

// Init/deinit should be call only if private
int dap_chain_net_srv_order_init(void);
void dap_chain_net_srv_order_deinit(void);

dap_chain_net_srv_order_t * dap_chain_net_srv_order_find_by_pid(uint128_t a_proposal_id);
int dap_chain_net_srv_order_find_all_by(dap_chain_net_srv_uid_t a_srv_uid, dap_chain_net_srv_class_t a_srv_class,
                                        dap_chain_net_srv_price_unit_uid_t a_price_unit, uint64_t a_price_min, uint64_t a_price_max,
                                        dap_chain_net_srv_order_t *** a_output_orders, size_t * a_output_size);
void dap_chain_net_srv_order_destroy( dap_chain_net_srv_order_t * a_order);
void dap_chain_net_srv_order_destroy_all( dap_chain_net_srv_order_t *** a_orders, size_t * a_output_size);

