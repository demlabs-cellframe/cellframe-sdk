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
#include "dap_json.h"

#define DAP_BALANCER_MAX_REPLY_SIZE 2048

typedef struct dap_balancer_request_info dap_balancer_request_info_t;

typedef enum dap_balancer_type {
    DAP_CHAIN_NET_BALANCER_TYPE_HTTP,
    DAP_CHAIN_NET_BALANCER_TYPE_DNS
} dap_balancer_type_t;

typedef struct dap_balancer_link_request {
    const char* host_addr;
    uint16_t host_port;
    dap_chain_net_t *net;
    dap_worker_t *worker;
    uint16_t required_links_count;
    dap_balancer_request_info_t *request_info;
    dap_balancer_type_t type;
} dap_balancer_link_request_t;


#ifdef __cplusplus
extern "C" {
#endif

DAP_STATIC_INLINE const char *dap_chain_net_balancer_type_to_str(dap_balancer_type_t a_type)
{
    switch (a_type) {
    case DAP_CHAIN_NET_BALANCER_TYPE_HTTP:  return "HTTP";
    case DAP_CHAIN_NET_BALANCER_TYPE_DNS:   return "DNS";
    default: break;
    }
    return "UNDEFINED";
}
void dap_chain_net_balancer_deinit();
void dap_chain_net_balancer_http_issue_link(dap_http_simple_t *a_http_simple, void *a_arg);
dap_link_info_t *dap_chain_net_balancer_dns_issue_link(const char *a_net_name);
int dap_chain_net_balancer_handshake(dap_chain_node_info_t *a_node_info, dap_chain_net_t * a_net);
dap_json_t *dap_chain_net_balancer_get_node_str(dap_chain_net_t *a_net);
void dap_chain_net_balancer_request(void *a_arg);

#ifdef __cplusplus
}
#endif