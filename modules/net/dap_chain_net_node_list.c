/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
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

#include "dap_chain_net_node_list.h"
#include "dap_chain_net.h"
#include "http_status_code.h"
#include "dap_chain_net_balancer.h"

#define LOG_TAG "dap_chain_net_node_list"

void dap_chain_net_node_check_http_issue_link(dap_http_simple_t *a_http_simple, void *a_arg)
{
    log_it(L_DEBUG,"Proc enc http request");
    http_status_code_t *l_return_code = (http_status_code_t *)a_arg;

    if (strcmp(a_http_simple->http_client->url_path, DAP_NODE_LIST_URI_HASH)) {
        log_it(L_ERROR, "Wrong path '%s' in the request to dap_chain_net_node_list module",
                                                            a_http_simple->http_client->url_path);
        *l_return_code = Http_Status_BadRequest;
        return;
    }
    int l_protocol_version = 0;
    char l_issue_method = 0;
    uint64_t addr = 0;
    uint32_t ipv4 = 0;
    uint16_t port = 0;
    const char l_net_token[] = "net=";
    sscanf(a_http_simple->http_client->in_query_string, "version=%d,method=%c,addr=%lu,ipv4=%d,port=%hu,net=",
                                                            &l_protocol_version, &l_issue_method, &addr, &ipv4, &port);
    if (l_protocol_version != 1 || l_issue_method != 'r') {
        log_it(L_ERROR, "Unsupported protocol version/method in the request to dap_chain_net_node_list module");
        *l_return_code = Http_Status_MethodNotAllowed;
        return;
    }
    char *l_net_str = strstr(a_http_simple->http_client->in_query_string, l_net_token);
    if (!l_net_str) {
        log_it(L_ERROR, "Net name token not found in the request to dap_chain_net_node_list module");
        *l_return_code = Http_Status_NotFound;
        return;
    }
    l_net_str += sizeof(l_net_token) - 1;
    char l_net_name[128] = {};
    strncpy(l_net_name, l_net_str, 127);
    log_it(L_DEBUG, "HTTP Node check parser retrieve netname %s", l_net_name);

    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    dap_chain_node_info_t * l_node_info = DAP_NEW_Z( dap_chain_node_info_t);
    l_node_info->hdr.address.uint64 = addr;
    l_node_info->hdr.ext_addr_v4.s_addr = ipv4;
    l_node_info->hdr.ext_port = port;

    bool res = dap_chain_net_balancer_handshake(l_node_info,l_net);

    if(res)
    {
        log_it(L_DEBUG, "ADD this addres to node list");
    }
    else
    {
        log_it(L_DEBUG, "Don't add this addres to node list");
    }

    //size_t l_data_send_size = sizeof(size_t) + (sizeof(dap_chain_node_info_t) * l_link_full_node_list->count_node);
    //dap_http_simple_reply(a_http_simple, l_link_full_node_list, l_data_send_size);
    DAP_DELETE(l_node_info);
}


