/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

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
#include <stddef.h>

#include "dap_chain_common.h"
#include "dap_chain_node.h"


typedef struct dap_chain_node_ctl{
    struct {
        dap_chain_node_addr_t addr;
        struct in_addr *ipv4_addrs;
        size_t ipv4_addrs_size;
        struct in6_addr *ipv6_addrs;
        size_t ipv6_addrs_size;
    } pub;
    uint8_t pvt[];
} dap_chain_node_ctl_t;

dap_chain_node_ctl_t * dap_chain_node_ctl_new();
dap_chain_node_ctl_t * dap_chain_node_ctl_open( const char * a_name );
void dap_chain_node_ctl_delete(dap_chain_node_ctl_t * a_node);

