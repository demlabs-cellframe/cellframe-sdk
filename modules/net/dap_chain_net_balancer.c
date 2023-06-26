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

#include "dap_chain_net_balancer.h"
#include "dap_chain_net.h"
#include "http_status_code.h"

#define LOG_TAG "dap_chain_net_balancer"
dap_chain_node_info_t *dap_chain_net_balancer_get_node(const char *a_net_name)
{
    dap_list_t *l_node_addr_list = NULL,*l_objs_list = NULL;
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if (l_net == NULL) {
        uint16_t l_nets_count;
        dap_chain_net_t **l_nets = dap_chain_net_list(&l_nets_count);
        if (!l_nets_count) {
            log_it(L_WARNING, "No chain network present");
            return NULL;
        }
        l_net = l_nets[rand() % l_nets_count];
    }
    dap_global_db_obj_t *l_objs = NULL;
    size_t l_nodes_count = 0;
    size_t l_node_num = 0;
    l_objs = dap_chain_global_db_gr_load(l_net->pub.gdb_nodes, &l_nodes_count);
    if (!l_nodes_count || !l_objs)
        return NULL;
    l_node_addr_list = dap_chain_net_get_node_list_cfg(l_net);
    for(size_t i=0;i<l_nodes_count;i++)
    {
        bool l_check = true;
        for(dap_list_t *node_i = l_node_addr_list;node_i;node_i = node_i->next)
        {
            struct in_addr *l_node_addr_cfg = (struct in_addr*)node_i->data;
            dap_chain_node_info_t *l_node_cand = (dap_chain_node_info_t *)l_objs[i].value;
            if(l_node_cand->hdr.ext_addr_v4.s_addr && l_node_cand->hdr.ext_port &&
                (l_node_addr_cfg->s_addr != l_node_cand->hdr.ext_addr_v4.s_addr))
            {
                continue;
            }
            else
            {
                l_check = false;
                break;
            }
        }
        if(l_check){
            l_objs_list = dap_list_append(l_objs_list,l_objs[i].value);
            l_node_num++;
        }
    }
    dap_chain_global_db_objs_delete(l_objs, l_nodes_count);
    dap_list_free(l_node_addr_list);
    l_nodes_count = l_node_num;
    dap_chain_node_info_t *l_node_candidate;
    if(l_nodes_count)
    {
        dap_chain_node_info_t *l_node_info = DAP_NEW_Z(dap_chain_node_info_t);
        do{
            l_node_num = rand() % l_nodes_count;
            l_node_candidate = (dap_chain_node_info_t *)dap_list_nth_data(l_objs_list,l_node_num);
            memmove(l_node_info, l_node_candidate, sizeof(dap_chain_node_info_t));
        }while(l_node_candidate->hdr.ext_addr_v4.s_addr == 0);
        dap_list_free(l_objs_list);
        return l_node_info;

    }
    else
    {
        dap_list_free(l_objs_list);
        log_it(L_DEBUG, "Node list is empty");
        return NULL;
    }
}

dap_chain_node_info_t *dap_chain_balancer_issue_link(const char *a_net_name)
{
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    dap_chain_node_info_t *l_node_candidate = dap_chain_net_balancer_get_node(a_net_name);
    if(l_node_candidate)
    {
        log_it(L_DEBUG, "Network balancer issues ip %s",inet_ntoa(l_node_candidate->hdr.ext_addr_v4));

        inet_pton(AF_INET, "192.168.0.1", &(l_node_candidate->hdr.ext_addr_v4));
        //l_node_candidate->hdr.ext_addr_v4.s_addr = htonl(INADDR_LOOPBACK);
        return l_node_candidate;
    }
    else
    {
        dap_chain_node_info_t *l_link_node_info = dap_get_balancer_link_from_cfg(l_net);
        if(l_link_node_info)
        {          
            log_it(L_DEBUG, "Network balancer issues ip from net conf - %s",inet_ntoa(l_link_node_info->hdr.ext_addr_v4));
            inet_pton(AF_INET, "192.168.0.1", &(l_link_node_info->hdr.ext_addr_v4));
            //l_link_node_info->hdr.ext_addr_v4.s_addr = htonl(INADDR_LOOPBACK);
            return l_link_node_info;
        }
    }
    return NULL;
}

void dap_chain_net_balancer_http_issue_link(dap_http_simple_t *a_http_simple, void *a_arg)
{
    log_it(L_DEBUG,"Proc enc http request");
    http_status_code_t *l_return_code = (http_status_code_t *)a_arg;

    if (strcmp(a_http_simple->http_client->url_path, DAP_BALANCER_URI_HASH)) {
        log_it(L_ERROR, "Wrong path '%s' in the request to dap_chain_net_balancer module",
                                                            a_http_simple->http_client->url_path);
        *l_return_code = Http_Status_BadRequest;
        return;
    }
    int l_protocol_version = 0;
    char l_issue_method = 0;
    const char l_net_token[] = "net=";
    sscanf(a_http_simple->http_client->in_query_string, "version=%d,method=%c,net=",
                                                            &l_protocol_version, &l_issue_method);
    if (l_protocol_version != 1 || l_issue_method != 'r') {
        log_it(L_ERROR, "Unsupported prorocol version/method in the request to dap_chain_net_balancer module");
        *l_return_code = Http_Status_MethodNotAllowed;
        return;
    }
    char *l_net_str = strstr(a_http_simple->http_client->in_query_string, l_net_token);
    if (!l_net_str) {
        log_it(L_ERROR, "Net name token not found in the request to dap_chain_net_balancer module");
        *l_return_code = Http_Status_NotFound;
        return;
    }
    l_net_str += sizeof(l_net_token) - 1;
    char l_net_name[128] = {};
    strncpy(l_net_name, l_net_str, 127);
    log_it(L_DEBUG, "HTTP balancer parser retrieve netname %s", l_net_name);
    dap_chain_node_info_t *l_node_info = dap_chain_balancer_issue_link(l_net_name);
    if (!l_node_info) {
        log_it(L_WARNING, "Can't issue link for network %s, no acceptable links found", l_net_name);
        *l_return_code = Http_Status_NotFound;
        return;
    }
    *l_return_code = Http_Status_OK;
    dap_http_simple_reply(a_http_simple, l_node_info, sizeof(*l_node_info));
    DAP_DELETE(l_node_info);
}

/**
 * @brief dap_dns_resolve_hostname
 * @param str
 * @return
 */
dap_chain_node_info_t *dap_chain_net_balancer_dns_issue_link(char *a_str)
{
    log_it(L_DEBUG, "DNS balancer parser retrieve netname %s", a_str);
    return dap_chain_balancer_issue_link(a_str);
}
