/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
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
#pragma once

#include "dap_chain_net_srv_common.h"


int dap_chain_net_srv_init(void);
void dap_chain_net_srv_deinit(void);

void dap_chain_net_srv_add(dap_chain_net_srv_t * a_srv);
void dap_chain_net_srv_del(dap_chain_net_srv_t * a_srv);
void dap_chain_net_srv_del_all(void);
dap_chain_net_srv_t * dap_chain_net_srv_get(dap_chain_net_srv_uid_t *a_uid);
size_t dap_chain_net_srv_count(void);
const dap_chain_net_srv_uid_t * dap_chain_net_srv_list(void);

// callback for traffic
void dap_chain_net_srv_traffic_callback(dap_server_t *a_server);
