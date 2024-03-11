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
#include "dap_chain_node_client.h"

#define LOG_TAG "dap_chain_net_balancer"

int dap_chain_net_balancer_handshake(dap_chain_node_info_t *a_node_info, dap_chain_net_t *a_net)
{
    dap_chain_node_client_t *l_client = dap_chain_node_client_connect_default_channels(a_net, a_node_info);
    return l_client ? dap_chain_node_client_wait(l_client, NODE_CLIENT_STATE_ESTABLISHED, 5000) : -1;
}

/*static uint64_t min_count_blocks_events(dap_global_db_obj_t * a_objs, size_t a_node_count, dap_chain_node_info_t **a_node_info_list, size_t a_count)
{
    uint64_t l_blocks_events = 0;
    for (size_t i = 0; i < a_node_count; i++) {
        dap_chain_node_info_t *l_node_cand = (dap_chain_node_info_t *)a_objs[i].value;
        if (!l_node_cand) {
            log_it(L_ERROR, "Invalid record, key %s", a_objs[i].key);
            continue;
        }
        for (dap_list_t *node_i = a_node_info_list; node_i; node_i = node_i->next) {
            if( !dap_strcmp(((dap_chain_node_info_t*)node_i->data)->ext_host, l_node_cand->ext_host) ) {
                if (!l_blocks_events || l_blocks_events > l_node_cand->info.atoms_count)
                    l_blocks_events = l_node_cand->info.atoms_count;
                break;
            }
        }
    }
    return l_blocks_events;
}*/


dap_chain_net_node_balancer_t *dap_chain_net_balancer_get_node(const char *a_net_name, uint16_t a_links_need)
{
// sanity check
    dap_return_val_if_pass(!a_net_name || !a_links_need, NULL);
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if (l_net == NULL) {
        log_it(L_WARNING, "There isn't any network by this name - %s", a_net_name);
        return NULL;
    }
    size_t l_node_num = 0;
    dap_link_info_t *l_links_info = dap_link_manager_get_net_links_info_list(l_net->pub.id.uint64, &l_node_num);
    if (!l_links_info || !l_node_num){        
        log_it(L_ERROR, "Active links list in net %s is empty", a_net_name);
        return NULL;
    }
    l_node_num = dap_min(l_node_num, a_links_need);
// memory alloc
    dap_chain_net_node_balancer_t *l_node_list_res = NULL;
    DAP_NEW_Z_SIZE_RET_VAL(l_node_list_res, dap_chain_net_node_balancer_t, sizeof(dap_chain_net_node_balancer_t) + l_node_num * sizeof(dap_link_info_t), NULL, l_links_info);
    dap_link_info_t *l_node_info = (dap_link_info_t *)l_node_list_res->nodes_info;
// func work
    dap_mempcpy(l_node_info, l_links_info, l_node_num * sizeof(dap_link_info_t));
    l_node_list_res->count_node = l_node_num;
    DAP_DELETE(l_links_info);
    return l_node_list_res;
}


dap_chain_net_node_balancer_t *dap_chain_net_balancer_get_node_old(const char *a_net_name, uint16_t a_links_need)
{
// sanity check
    dap_return_val_if_pass(!a_net_name || !a_links_need, NULL);
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if (l_net == NULL) {
        log_it(L_WARNING, "There isn't any network by this name - %s", a_net_name);
        return NULL;
    }
    size_t l_node_num = 0;
    dap_link_info_t *l_links_info = dap_link_manager_get_net_links_info_list(l_net->pub.id.uint64, &l_node_num);
    if (!l_links_info || !l_node_num){        
        log_it(L_ERROR, "Active links list in net %s is empty", a_net_name);
        return NULL;
    }
    l_node_num = dap_min(l_node_num, a_links_need);
// memory alloc
    dap_chain_net_node_balancer_t *l_node_list_res = NULL;
    DAP_NEW_Z_SIZE_RET_VAL(l_node_list_res, dap_chain_net_node_balancer_t, sizeof(dap_chain_net_node_balancer_t) + l_node_num * sizeof(dap_chain_node_info_old_t), NULL, l_links_info);
    dap_chain_node_info_old_t *l_node_info = (dap_chain_node_info_old_t *)l_node_list_res->nodes_info;
// func work
    for (size_t i = 0; i < l_node_num; ++i) {
        l_node_info[i].hdr.address.uint64 = l_links_info->node_addr.uint64;
        l_node_info[i].hdr.ext_port = l_links_info->uplink_port;
        inet_ntop(AF_INET,&(l_node_info + i)->hdr.ext_addr_v4,l_links_info->uplink_addr, INET_ADDRSTRLEN);
    }
    l_node_list_res->count_node = l_node_num;
    DAP_DELETE(l_links_info);
    return l_node_list_res;
}

dap_chain_net_node_balancer_t *s_balancer_issue_link(const char *a_net_name, uint16_t a_links_need, int a_protocol_version)
{
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    dap_chain_net_node_balancer_t *l_link_full_node_list = NULL;
    if (a_protocol_version == 1) {
        l_link_full_node_list = dap_chain_net_balancer_get_node_old(a_net_name, a_links_need);
    } else {
        l_link_full_node_list = dap_chain_net_balancer_get_node(a_net_name, a_links_need);
    }
    if (!l_link_full_node_list)
        return NULL;
    dap_link_info_t *l_node_info = (dap_link_info_t *)l_link_full_node_list->nodes_info;
    for(size_t i = 0; i < l_link_full_node_list->count_node; i++) {
        log_it(L_DEBUG, "Network balancer issues ip %s",
                (l_node_info + i)->uplink_addr);
    }
    return l_link_full_node_list;
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
    uint16_t links_need = 0;
    sscanf(a_http_simple->http_client->in_query_string, "version=%d,method=%c,needlink=%hu,net=",
                                                            &l_protocol_version, &l_issue_method, &links_need);
    if ((l_protocol_version != DAP_BALANCER_PROTOCOL_VERSION && l_protocol_version != 1) || l_issue_method != 'r') {
        log_it(L_ERROR, "Unsupported protocol version/method in the request to dap_chain_net_balancer module");
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
    links_need = links_need ? links_need : 5;
    log_it(L_DEBUG, "HTTP balancer parser retrieve netname %s", l_net_name);
    dap_chain_net_node_balancer_t *l_link_full_node_list = s_balancer_issue_link(l_net_name,links_need, l_protocol_version);
    if (!l_link_full_node_list) {
        log_it(L_WARNING, "Can't issue link for network %s, no acceptable links found", l_net_name);
        *l_return_code = Http_Status_NotFound;
        return;
    }
    *l_return_code = Http_Status_OK;
    size_t l_data_send_size = sizeof(uint64_t) + (sizeof(dap_link_info_t) * l_link_full_node_list->count_node);
    dap_http_simple_reply(a_http_simple, l_link_full_node_list, l_data_send_size);
    DAP_DELETE(l_link_full_node_list);
}

/**
 * @brief dap_dns_resolve_hostname
 * @param str
 * @return
 */
dap_link_info_t *dap_chain_net_balancer_dns_issue_link(char *a_str)
{
    log_it(L_DEBUG, "DNS balancer parser retrieve netname %s", a_str);
    dap_chain_net_node_balancer_t *l_balancer_reply = s_balancer_issue_link(a_str, 1, DAP_BALANCER_PROTOCOL_VERSION);
    if (!l_balancer_reply || !l_balancer_reply->count_node) {
        DAP_DEL_Z(l_balancer_reply);
        return NULL;
    }
    dap_link_info_t *l_res = DAP_DUP(( dap_link_info_t *)l_balancer_reply->nodes_info);
    DAP_DELETE(l_balancer_reply);
    return l_res;
}
