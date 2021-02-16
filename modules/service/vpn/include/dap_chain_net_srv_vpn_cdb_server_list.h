/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
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

#include "dap_enc_http.h"
#include <stdbool.h>

struct dap_http;

int get_order_state(dap_chain_node_addr_t a_node_addr);

int dap_chain_net_srv_vpn_cdb_server_list_init(void);
void dap_chain_net_srv_vpn_cdb_server_list_deinit(void);
void dap_chain_net_srv_vpn_cdb_server_list_add_proc(struct dap_http * sh, const char * url);

void dap_chain_net_srv_vpn_cdb_server_list_cache_reset(void);
int dap_chain_net_srv_vpn_cdb_server_list_static_create(dap_chain_net_t *a_net);

