/*
* Authors:
* Roman Khlopkov <roman.khlopkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2022
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

#include "dap_chain_node.h"
#include "dap_http_simple.h"

#define DAP_BALANCER_URI_HASH "f0intlt4eyl03htogu"
typedef struct dap_chain_net_node_balancer {
    size_t count_node;
    byte_t nodes_info[];
} dap_chain_net_node_balancer_t;

void dap_chain_net_balancer_http_issue_link(dap_http_simple_t *a_http_simple, void *a_arg);
dap_chain_node_info_t *dap_chain_net_balancer_dns_issue_link(char *a_str);
dap_chain_net_node_balancer_t *dap_chain_net_balancer_get_node(const char *a_net_name,uint16_t a_links_need);
void dap_chain_net_balancer_set_link_ban(dap_chain_node_info_t *a_node_info, const char *a_net_name);
void dap_chain_net_balancer_free_link_ban(dap_chain_net_t * a_net);
