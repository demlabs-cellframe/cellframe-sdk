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

dap_chain_node_info_t *s_balancer_issue_link(const char *a_net_name)
{
    dap_config_t *l_cfg=NULL;
    dap_string_t *l_cfg_path = dap_string_new("network/");
    dap_string_append(l_cfg_path,a_net_name);
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
    // get nodes list from global_db
    dap_global_db_obj_t *l_objs = NULL;
    size_t l_nodes_count = 0;
    size_t l_node_num;
    // read all node
    l_objs = dap_global_db_get_all_sync(l_net->pub.gdb_nodes, &l_nodes_count);
    if (!l_nodes_count || !l_objs)
        return NULL;
    dap_chain_node_info_t *l_node_candidate;
    for (int i = 0; i < 50; i++) {
        // 50 tryes for non empty address & port
        l_node_num = rand() % l_nodes_count;
        l_node_candidate = (dap_chain_node_info_t *)l_objs[l_node_num].value;
        if (l_node_candidate->hdr.ext_addr_v4.s_addr && l_node_candidate->hdr.ext_port)
            break;
    }
    if (!l_node_candidate->hdr.ext_addr_v4.s_addr || !l_node_candidate->hdr.ext_port)
        return NULL;
    //dell cfg seed from db
    if( ( l_cfg = dap_config_open ( l_cfg_path->str ) ) == NULL ) {
        log_it(L_ERROR,"Can't open default network config");
        dap_string_free(l_cfg_path,true);
    } else {
        uint16_t l_seed_nodes_hostnames_len =0;
        char ** l_seed_nodes_hostnames = dap_config_get_array_str( l_cfg , "general" ,"seed_nodes_hostnames"
                                                             ,&l_seed_nodes_hostnames_len);
        struct sockaddr l_sa = {};
        for(size_t i = 0;i<l_seed_nodes_hostnames_len;i++)
        {
            if(!dap_net_resolve_host(l_seed_nodes_hostnames[i], AF_INET, &l_sa))
            {
                struct in_addr *l_res = (struct in_addr *)&l_sa;
                if(l_node_candidate->hdr.ext_addr_v4.s_addr == l_res->s_addr)
                {
                    dap_global_db_del_sync(l_net->pub.gdb_nodes,l_objs[l_node_num].key);
                    if(l_nodes_count>1)
                        return NULL;
                }
            }
        }
    }
    dap_config_close(l_cfg);
    dap_chain_node_info_t *l_node_info = DAP_NEW_Z(dap_chain_node_info_t);
    memcpy(l_node_info, l_node_candidate, sizeof(dap_chain_node_info_t));
    dap_global_db_objs_delete(l_objs, l_nodes_count);
    log_it(L_DEBUG, "Network balancer issues ip %s", inet_ntoa(l_node_info->hdr.ext_addr_v4));
    return l_node_info;
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
    dap_chain_node_info_t *l_node_info = s_balancer_issue_link(l_net_name);
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
    return s_balancer_issue_link(a_str);
}
