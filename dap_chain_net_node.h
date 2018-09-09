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
#include <sys/socket.h>
#include <netinet/in.h>

typedef union dap_chain_node_addr{
    uint64_t addr_raw;
    uint8_t addr_oct[sizeof(uint64_t)]; // Access to selected octects
} dap_chain_node_addr_t;

typedef struct dap_chain_node{
    dap_chain_node_addr_t addr;
    dap_chain_node_addr_t *uplinks;
    dap_chain_node_addr_t *downlinks;
    struct in_addr *ipv4_addrs;
    struct in6_addr *ipv6_addrs;
} dap_chain_net_node_t;
