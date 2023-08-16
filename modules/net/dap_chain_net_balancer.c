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

static bool dap_chain_net_balancer_find_link(dap_chain_node_info_t *a_node_info,dap_chain_net_t * a_net)
{
    dap_list_t * l_link_list = a_net->pub.link_list;
    for(dap_list_t *ll = l_link_list; ll; ll = ll->next)
    {
        dap_chain_node_info_t *l_node_link = (dap_chain_node_info_t*)ll->data;
        if(l_node_link && l_node_link->hdr.ext_addr_v4.s_addr == a_node_info->hdr.ext_addr_v4.s_addr)
            return true;
    }

    return false;
}

void dap_chain_net_balancer_set_link_list(dap_chain_node_info_t *a_node_info, const char *a_net_name)
{
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if(dap_chain_net_balancer_find_link(a_node_info,l_net))
        return;

    dap_chain_node_info_t * l_node_info = DAP_NEW_Z( dap_chain_node_info_t);
    *l_node_info = *a_node_info;
    l_net->pub.link_list = dap_list_append(l_net->pub.link_list,l_node_info);

    log_it(L_DEBUG, "Add addr "NODE_ADDR_FP_STR" to balancer link list",NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address));
}

void dap_chain_net_balancer_free_link_list(dap_chain_net_t * a_net)
{
    dap_list_free_full(a_net->pub.link_list, NULL);
    a_net->pub.link_list = NULL;
    log_it(L_DEBUG, "Balancer link list cleared");
}

static bool dap_chain_net_balancer_handshake(dap_chain_node_info_t *a_node_info,dap_chain_net_t * a_net)
{
    dap_chain_node_client_t *l_client = dap_chain_node_client_connect_default_channels(a_net,a_node_info);
    if(!l_client) {
        return false;
    }
    // wait handshake
    int timeout_ms = 1000;
    int res = dap_chain_node_client_wait(l_client, NODE_CLIENT_STATE_ESTABLISHED, timeout_ms);
    if (res) {
        dap_chain_node_client_close_mt(l_client);
        return false;
    }
    return true;
}
static bool is_it_node_from_list(dap_list_t *a_node_addr_list, dap_chain_node_info_t *a_node_cand)
{
    for(dap_list_t *node_i = a_node_addr_list; node_i; node_i = node_i->next)
    {
        struct in_addr *l_node_addr_cfg = (struct in_addr*)node_i->data;
        if(a_node_cand->hdr.ext_addr_v4.s_addr && a_node_cand->hdr.ext_port &&
          (l_node_addr_cfg->s_addr == a_node_cand->hdr.ext_addr_v4.s_addr))
            return true;
    }
    return false;
}
static uint64_t min_count_blocks_events(dap_global_db_obj_t * a_objs,size_t a_node_count,dap_list_t * a_node_addr_list)
{
    uint64_t l_blocks_events = 0;
    for (size_t i = 0; i < a_node_count; i++) {
        dap_chain_node_info_t *l_node_cand = (dap_chain_node_info_t *)a_objs[i].value;
        for (dap_list_t *node_i = a_node_addr_list; node_i; node_i = node_i->next) {
            if(((struct in_addr*)node_i->data)->s_addr == l_node_cand->hdr.ext_addr_v4.s_addr) {
                if (!l_blocks_events || l_blocks_events > l_node_cand->hdr.blocks_events)
                    l_blocks_events = l_node_cand->hdr.blocks_events;
                break;
            }
        }
    }
    return l_blocks_events;
}

void dap_chain_net_balancer_prepare_list_links(const char *a_net_name,bool handshake_on)
{
    dap_list_t *l_node_addr_list = NULL,*l_links_temp = NULL;
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if (l_net == NULL) {
        log_it(L_WARNING, "There isn't any network by this name - %s", a_net_name);
        return;
    }

    dap_global_db_obj_t *l_objs = NULL;
    size_t l_nodes_count = 0,link_list_count = 0;
    uint64_t l_blocks_events = 0;
    // read all node
    l_objs = dap_global_db_get_all_sync(l_net->pub.gdb_nodes, &l_nodes_count);
    if (!l_nodes_count || !l_objs)
        return;

    l_node_addr_list = dap_chain_net_get_node_list_cfg(l_net);
    l_blocks_events = min_count_blocks_events(l_objs,l_nodes_count,l_node_addr_list);
    pthread_mutex_lock(&l_net->pub.balancer_mutex);
    //clear list links
    //link_list_count = dap_list_length(l_net->pub.link_list);
    if(!handshake_on)
    {
        log_it(L_DEBUG, "Adjusting node list");
        for (size_t i = 0; i < l_nodes_count; i++) {
            dap_chain_node_info_t *l_node_cand = (dap_chain_node_info_t *)l_objs[i].value;
            for(dap_list_t *node_i = l_net->pub.link_list; node_i; node_i = node_i->next)
            {
                dap_chain_node_info_t *l_node_list = (dap_chain_node_info_t *)node_i->data;
                if(l_node_list->hdr.address.uint64 == l_node_cand->hdr.address.uint64)
                {
                   // if(l_node_cand->hdr.blocks_events >= l_blocks_events/2)
                   // {
                        dap_chain_node_info_t * l_node_info = DAP_NEW_Z( dap_chain_node_info_t);
                        *l_node_info = *l_node_cand;
                        l_links_temp = dap_list_append(l_links_temp,l_node_info);
                   // }
                }
            }
        }
        dap_chain_net_balancer_free_link_list(l_net);
        l_net->pub.link_list = dap_list_copy(l_links_temp);
        dap_list_free(l_links_temp);
    }
    else{
        log_it(L_DEBUG, "Overwrite node list");
        dap_list_free_full(l_net->pub.link_list, NULL);
        l_net->pub.link_list = NULL;
        for (size_t i = 0; i < l_nodes_count; i++)
        {
            dap_chain_node_info_t *l_node_cand = (dap_chain_node_info_t *)l_objs[i].value;
            if(!is_it_node_from_list(l_node_addr_list, l_node_cand)){
                if(l_node_cand->hdr.blocks_events >= l_blocks_events){
                    if(dap_chain_net_balancer_handshake(l_node_cand,l_net)){
                        dap_chain_net_balancer_set_link_list(l_node_cand,l_net->pub.name);
                    }
                }
            }
        }
    }
    pthread_mutex_unlock(&l_net->pub.balancer_mutex);
    dap_global_db_objs_delete(l_objs, l_nodes_count);
    dap_list_free(l_node_addr_list);
}

static int callback_compare_node_list(const void * a_item1, const void * a_item2, void *a_unused)
{
    UNUSED(a_unused);
    if (!a_item1 || !a_item2) {
        return 0;
    }
    dap_chain_node_info_t *l_item1 = (dap_chain_node_info_t*)a_item1, *l_item2 = (dap_chain_node_info_t*)a_item2;
    return l_item1->hdr.links_number == l_item2->hdr.links_number
            ? 0 : l_item1->hdr.links_number > l_item2->hdr.links_number
              ? 1 : -1;
}

dap_chain_net_node_balancer_t *dap_chain_net_balancer_get_node(const char *a_net_name,uint16_t a_links_need)
{
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if (l_net == NULL) {
        log_it(L_WARNING, "There isn't any network by this name - %s", a_net_name);
        return NULL;
    }
    // get nodes list from global_db
    pthread_mutex_lock(&l_net->pub.balancer_mutex);
    size_t l_node_num = 0,l_links_need = 0;
    l_net->pub.link_list = dap_list_sort(l_net->pub.link_list, callback_compare_node_list);
    l_node_num = dap_list_length(l_net->pub.link_list);
    dap_chain_node_info_t *l_node_candidate;
    if(l_node_num)
    {
        l_links_need = l_node_num > a_links_need ? a_links_need : l_node_num;
        dap_chain_net_node_balancer_t *l_node_list_res = DAP_NEW_Z_SIZE(dap_chain_net_node_balancer_t,
                   sizeof(dap_chain_net_node_balancer_t) + l_links_need * sizeof(dap_chain_node_info_t));
        dap_chain_node_info_t * l_node_info = (dap_chain_node_info_t *)l_node_list_res->nodes_info;
        dap_list_t *nl = l_net->pub.link_list;
        for(size_t i=0; i<l_links_need; i++,nl = nl->next)
        {
            l_node_candidate = (dap_chain_node_info_t*)nl->data;
            *(l_node_info + i) = *l_node_candidate;
        }
        l_node_list_res->count_node = l_links_need;
        pthread_mutex_unlock(&l_net->pub.balancer_mutex);
        return l_node_list_res;
    }
    else
    {        
        log_it(L_ERROR, "Node list is empty");
        pthread_mutex_unlock(&l_net->pub.balancer_mutex);
        return NULL;
    }
}

dap_chain_net_node_balancer_t *s_balancer_issue_link(const char *a_net_name,uint16_t a_links_need)
{
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    dap_chain_net_node_balancer_t *l_link_full_node_list = dap_chain_net_balancer_get_node(a_net_name,a_links_need);
    if(l_link_full_node_list)
    {
        dap_chain_node_info_t * l_node_info = (dap_chain_node_info_t *)l_link_full_node_list->nodes_info;
        for(size_t i=0;i<l_link_full_node_list->count_node;i++)
        {
            log_it(L_DEBUG, "Network balancer issues ip %s, [%ld blocks]",inet_ntoa((l_node_info + i)->hdr.ext_addr_v4),l_node_info->hdr.blocks_events);

        }
        return l_link_full_node_list;
    }
    else
    {
        dap_chain_node_info_t *l_link_node_info = dap_get_balancer_link_from_cfg(l_net);
        if(l_link_node_info)
        {          
            log_it(L_DEBUG, "Network balancer issues ip from net conf - %s",inet_ntoa(l_link_node_info->hdr.ext_addr_v4));
            dap_chain_net_node_balancer_t * l_node_list_res = DAP_NEW_Z_SIZE(dap_chain_net_node_balancer_t,
                                                                             sizeof(dap_chain_net_node_balancer_t) + sizeof(dap_chain_node_info_t));
            l_node_list_res->count_node = 1;
            *(dap_chain_node_info_t*)l_node_list_res->nodes_info = *l_link_node_info;
            return l_node_list_res;
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
    uint16_t links_need = 0;
    sscanf(a_http_simple->http_client->in_query_string, "version=%d,method=%c,needlink=%d,net=",
                                                            &l_protocol_version, &l_issue_method,&links_need);
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
    links_need = links_need ? links_need : 5;
    log_it(L_DEBUG, "HTTP balancer parser retrieve netname %s", l_net_name);
    dap_chain_net_node_balancer_t *l_link_full_node_list = s_balancer_issue_link(l_net_name,links_need);
    if (!l_link_full_node_list) {
        log_it(L_WARNING, "Can't issue link for network %s, no acceptable links found", l_net_name);
        *l_return_code = Http_Status_NotFound;
        return;
    }
    *l_return_code = Http_Status_OK;
    size_t l_data_send_size = sizeof(size_t) + (sizeof(dap_chain_node_info_t) * l_link_full_node_list->count_node);
    dap_http_simple_reply(a_http_simple, l_link_full_node_list, l_data_send_size);
    DAP_DELETE(l_link_full_node_list);
}

/**
 * @brief dap_dns_resolve_hostname
 * @param str
 * @return
 */
dap_chain_node_info_t *dap_chain_net_balancer_dns_issue_link(char *a_str)
{
    log_it(L_DEBUG, "DNS balancer parser retrieve netname %s", a_str);
    return s_balancer_issue_link(a_str,3);
}
