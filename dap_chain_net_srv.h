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
#pragma once

#include "dap_chain_node.h"
#include "dap_chain_srv_pkt.h"

typedef struct dap_chain_srv
{
    dap_chain_node_t * node;
    dap_chain_srv_uid_t uid; // Unique ID for service.

    void * _internal;
    void * _inhertor;
} dap_chain_srv_t;

int dap_chain_srv_init();
void dap_chain_srv_deinit();

void dap_chain_srv_add(dap_chain_srv_t * a_srv);
dap_chain_srv_t * dap_chain_srv_get( dap_chain_srv_uid_t a_uid);
const size_t dap_chain_srv_count();
const dap_chain_srv_uid_t * dap_chain_srv_list();

