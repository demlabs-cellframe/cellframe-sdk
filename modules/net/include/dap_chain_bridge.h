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
#pragma once

#include "dap_config.h"
#include "dap_chain_net.h"

int dap_chain_bridge_init();
void dap_chain_bridge_deinit();

typedef int (*dap_chain_bridge_callback_init_t)(const char *,dap_chain_net_t * , dap_config_t *);

int dap_chain_bridge_register(const char * a_bridge_name, dap_chain_bridge_callback_init_t a_callback_init);
int dap_chain_bridge_add(const char * a_bridge_name, dap_chain_net_t * a_net,dap_config_t * a_net_config );
