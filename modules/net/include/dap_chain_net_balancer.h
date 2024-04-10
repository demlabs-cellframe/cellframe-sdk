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
#define DAP_BALANCER_PROTOCOL_VERSION 2
#define DAP_BALANCER_MAX_REPLY_SIZE 2048

typedef struct dap_chain_net_links {
    uint64_t count_node;
    byte_t nodes_info[];
} DAP_ALIGN_PACKED dap_chain_net_links_t;

void dap_chain_net_balancer_http_issue_link(dap_http_simple_t *a_http_simple, void *a_arg);
dap_link_info_t *dap_chain_net_balancer_dns_issue_link(const char *a_net_name);
int dap_chain_net_balancer_handshake(dap_chain_node_info_t *a_node_info, dap_chain_net_t * a_net);
dap_string_t *dap_chain_net_balancer_get_node_str(dap_chain_net_t *a_net);
int dap_chain_net_balancer_request(dap_chain_net_t *a_net, dap_link_info_t *a_balancer_link, int a_balancer_type);