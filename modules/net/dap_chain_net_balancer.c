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
#include "rand/dap_rand.h"

#define LOG_TAG "dap_chain_net_balancer"

static_assert(sizeof(dap_chain_net_links_t) + sizeof(dap_chain_node_info_old_t) < DAP_BALANCER_MAX_REPLY_SIZE, "DAP_BALANCER_MAX_REPLY_SIZE cannot accommodate information minimum about 1 link");
static const size_t s_max_links_response_count = (DAP_BALANCER_MAX_REPLY_SIZE - sizeof(dap_chain_net_links_t)) / sizeof(dap_chain_node_info_old_t);

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
}

dap_link_info_t *dap_link_manager_get_net_links_info_list(uint64_t a_net_id, size_t *a_count)
{
// sanity check
    dap_managed_net_t *l_net = s_find_net_by_id(a_net_id);
    dap_return_val_if_pass(!l_net, 0);
// func work
    size_t l_count = 0;
    dap_link_info_t *l_ret = NULL;
    dap_stream_node_addr_t *l_links_addrs = dap_cluster_get_all_members_addrs((dap_cluster_t *)l_net->link_clusters->data, &l_count);
    if (!l_links_addrs || !l_count) {
        return NULL;
    }
    DAP_NEW_Z_COUNT_RET_VAL(l_ret, dap_link_info_t, l_count, NULL, l_links_addrs);
    pthread_rwlock_rdlock(&s_link_manager->links_lock);
        for (int i = l_count - 1; i >= 0; --i) {
            dap_link_t *l_link = NULL;
            HASH_FIND(hh, s_link_manager->links, l_links_addrs + i, sizeof(l_links_addrs[i]), l_link);
            if (!l_link || l_link->uplink.state != LINK_STATE_ESTABLISHED) {
                --l_count;
                continue;
            }
            dap_mempcpy(l_ret + i, &l_link->uplink.client->link_info, sizeof(dap_link_info_t));
        }
    pthread_rwlock_unlock(&s_link_manager->links_lock);
    DAP_DELETE(l_links_addrs);
    if (!l_count) {
        DAP_DELETE(l_ret);
        return NULL;
    }
    if (a_count)
        *a_count = l_count;
    return l_ret;
}
*/

dap_link_info_t *s_get_links_info_list(dap_chain_net_t *a_net, size_t *a_count, bool a_external_call)
{
    static _Thread_local dap_global_db_driver_hash_t l_last_read_hash = {};
    assert(a_net && a_count);
    size_t l_count = *a_count;
    if (!l_count) {
        l_count = dap_global_db_driver_count(a_net->pub.gdb_nodes, c_dap_global_db_driver_hash_blank);
        if (!l_count)
            return NULL;
    }
    dap_store_obj_t *l_objs = dap_global_db_driver_cond_read(a_net->pub.gdb_nodes, l_last_read_hash, &l_count);
    if (!l_objs || !l_count) {
        l_last_read_hash = c_dap_global_db_driver_hash_blank;
        return a_external_call ? s_get_links_info_list(a_net, a_count, false) : NULL;
    }
    l_last_read_hash = dap_global_db_driver_hash_get(l_objs + l_count - 1);
    if (dap_global_db_driver_hash_is_blank(&l_last_read_hash))
        l_count--;
    dap_link_info_t *l_ret = NULL;
    DAP_NEW_Z_COUNT_RET_VAL(l_ret, dap_link_info_t, l_count, NULL, NULL);
    for (size_t i = 0; i < l_count; i++) {
        dap_link_info_t *l_cur_info = l_ret + i;
        dap_chain_node_info_t *l_db_info = (dap_chain_node_info_t *)(l_objs + i)->value;
        l_cur_info->node_addr = l_db_info->address;
        l_cur_info->uplink_port = l_db_info->ext_port;
        dap_strncpy(l_cur_info->uplink_addr, l_db_info->ext_host, dap_min(l_db_info->ext_host_len, DAP_HOSTADDR_STRLEN));
    }
    dap_store_obj_free(l_objs, l_count);
    if (a_external_call && l_count < *a_count) {
        size_t l_total_count = dap_global_db_driver_count(a_net->pub.gdb_nodes, c_dap_global_db_driver_hash_blank);
        if (l_count < l_total_count) {
            size_t l_tail_count = dap_min(l_total_count, *a_count) - l_count;
            dap_link_info_t *l_tail = s_get_links_info_list(a_net, &l_tail_count, false);
            if (l_tail && l_tail_count) {
                l_ret = DAP_REALLOC(l_ret, sizeof(dap_link_info_t) * (l_count + l_tail_count));
                memcpy(l_ret + sizeof(dap_link_info_t) * l_count, l_tail, sizeof(dap_link_info_t) * l_tail_count);
                l_count += l_tail_count;
                DAP_DELETE(l_tail);
            }
        }
    }
    *a_count = l_count;
    return l_ret;
}

dap_chain_net_links_t *dap_chain_net_balancer_get_node(const char *a_net_name, uint16_t a_links_need)
{
// sanity check
    dap_return_val_if_pass(!a_net_name || !a_links_need, NULL);
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if (l_net == NULL) {
        log_it(L_WARNING, "There isn't any network by this name - %s", a_net_name);
        return NULL;
    }
// preparing
    size_t l_node_num_prep = a_links_need;
    dap_link_info_t *l_links_info = s_get_links_info_list(l_net, &l_node_num_prep, true);
    if (!l_links_info || !l_node_num_prep){        
        log_it(L_ERROR, "Active node list in net %s is empty", a_net_name);
        return NULL;
    }
    size_t l_node_num_send = dap_min(s_max_links_response_count, l_node_num_prep);
// memory alloc
    dap_chain_net_links_t *l_node_list_res = NULL;
    DAP_NEW_Z_SIZE_RET_VAL(l_node_list_res, dap_chain_net_links_t, sizeof(dap_chain_net_links_t) + l_node_num_send * sizeof(dap_link_info_t), NULL, l_links_info);
    dap_link_info_t *l_node_info = (dap_link_info_t *)l_node_list_res->nodes_info;
// func work
    // if we can't send full list, choose random, not always firsts
    if (l_node_num_send < l_node_num_prep) {
        for (size_t i = 0; i < l_node_num_send; ++i)
            dap_mempcpy(l_node_info + i, l_links_info + dap_random_uint16() % l_node_num_prep, sizeof(dap_link_info_t));
    } else {
        dap_mempcpy(l_node_info, l_links_info, l_node_num_send * sizeof(dap_link_info_t));
    }
    l_node_list_res->count_node = l_node_num_send;
    DAP_DELETE(l_links_info);
    return l_node_list_res;
}


dap_chain_net_links_t *dap_chain_net_balancer_get_node_old(const char *a_net_name, uint16_t a_links_need)
{
// sanity check
    dap_return_val_if_pass(!a_net_name || !a_links_need, NULL);
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if (l_net == NULL) {
        log_it(L_WARNING, "There isn't any network by this name - %s", a_net_name);
        return NULL;
    }
// preparing
    size_t l_node_num_prep = a_links_need;
    dap_link_info_t *l_links_info = s_get_links_info_list(l_net, &l_node_num_prep, true);
    if (!l_links_info || !l_node_num_prep){        
        log_it(L_ERROR, "Active node list in net %s is empty", a_net_name);
        return NULL;
    }
    size_t l_node_num_send = dap_min(s_max_links_response_count, l_node_num_prep);
// memory alloc
    dap_chain_net_links_t *l_node_list_res = NULL;
    DAP_NEW_Z_SIZE_RET_VAL(l_node_list_res, dap_chain_net_links_t, sizeof(dap_chain_net_links_t) + l_node_num_send * sizeof(dap_chain_node_info_old_t), NULL, l_links_info);
    dap_chain_node_info_old_t *l_node_info = (dap_chain_node_info_old_t *)l_node_list_res->nodes_info;
// func work
    // if we can't send full list, choose random, not always firsts
    if (l_node_num_send < l_node_num_prep) {
        for (size_t i = 0; i < l_node_num_send; ++i) {
            size_t j = dap_random_uint16() % l_node_num_prep;
            l_node_info[i].hdr.address.uint64 = l_links_info[j].node_addr.uint64;
            l_node_info[i].hdr.ext_port = l_links_info[j].uplink_port;
            inet_pton(AF_INET, l_links_info[j].uplink_addr, &l_node_info[i].hdr.ext_addr_v4);
        }
    } else {
        for (size_t i = 0; i < l_node_num_send; ++i) {
            l_node_info[i].hdr.address.uint64 = l_links_info[i].node_addr.uint64;
            l_node_info[i].hdr.ext_port = l_links_info[i].uplink_port;
            inet_pton(AF_INET, l_links_info[i].uplink_addr, &l_node_info[i].hdr.ext_addr_v4);
        }
    }
    l_node_list_res->count_node = l_node_num_send;
    DAP_DELETE(l_links_info);
    return l_node_list_res;
}

DAP_STATIC_INLINE dap_chain_net_links_t *s_balancer_issue_link(const char *a_net_name, uint16_t a_links_need, int a_protocol_version)
{
    return a_protocol_version == 1 ? dap_chain_net_balancer_get_node_old(a_net_name, a_links_need) : dap_chain_net_balancer_get_node(a_net_name, a_links_need);
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
    dap_chain_net_links_t *l_link_full_node_list = s_balancer_issue_link(l_net_name, links_need, l_protocol_version);
    if (!l_link_full_node_list) {
        log_it(L_WARNING, "Can't issue link for network %s, no acceptable links found", l_net_name);
        *l_return_code = Http_Status_NotFound;
        return;
    }
    *l_return_code = Http_Status_OK;
    size_t l_data_send_size = sizeof(uint64_t);
    if (l_protocol_version == 1)
        l_data_send_size += sizeof(dap_chain_node_info_old_t) * l_link_full_node_list->count_node;
    else
        l_data_send_size += sizeof(dap_link_info_t) * l_link_full_node_list->count_node;
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
    dap_chain_net_links_t *l_balancer_reply = s_balancer_issue_link(a_str, 1, DAP_BALANCER_PROTOCOL_VERSION);
    if (!l_balancer_reply || !l_balancer_reply->count_node) {
        DAP_DEL_Z(l_balancer_reply);
        return NULL;
    }
    dap_link_info_t *l_res = DAP_DUP(( dap_link_info_t *)l_balancer_reply->nodes_info);
    DAP_DELETE(l_balancer_reply);
    return l_res;
}
