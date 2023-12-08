/*
* Authors:
* Roman Padenkov <roman.padenkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2023-2024
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

#include "dap_chain_net.h"
#include "dap_chain_net_srv_order.h"

#define DAP_ORDER_URI_HASH "order_add_hash"

struct order_add_request {
    dap_chain_net_srv_order_t *order;
    dap_chain_net_t *net;
    dap_worker_t *worker;
    bool from_http;
    int link_replace_tries;
    int response;
    pthread_cond_t wait_cond;
    pthread_mutex_t wait_mutex;
};

int dap_chain_net_srv_request_send(dap_chain_net_t *a_net, dap_chain_net_srv_order_t *a_ordert, bool a_sync, int cmd);
