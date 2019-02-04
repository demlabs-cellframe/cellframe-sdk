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
#pragma once

#include <stdint.h>
#include "dap_chain_common.h"

#include <sys/socket.h>
#include <netinet/in.h>

#define DAP_CHAIN_NET_NAME_MAX 32

typedef struct dap_chain_net{
    struct {
        dap_chain_net_id_t id;
        char * name;
    } pub;
    uint8_t pvt[];
} dap_chain_net_t;

int dap_chain_net_init();
void dap_chain_net_deinit();

dap_chain_net_t * dap_chain_net_new (const char * a_id,  const char * a_name,
                                     const char* a_node_role , const char* a_node_name );
void dap_chain_net_delete( dap_chain_net_t * a_net);

dap_chain_net_t * dap_chain_net_by_name( const char * a_name);
dap_chain_net_id_t dap_chain_net_id_by_name( const char * a_name);
