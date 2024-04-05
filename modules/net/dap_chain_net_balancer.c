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
#include "dap_chain_node_dns_client.h"
#include "rand/dap_rand.h"

#define LOG_TAG "dap_chain_net_balancer"


typedef struct dap_balancer_link_request {
    dap_link_info_t *info;
    dap_chain_net_t *net;
    dap_worker_t *worker;
    uint16_t links_requested_count;
} dap_balancer_link_request_t;

static_assert(sizeof(dap_chain_net_links_t) + sizeof(dap_chain_node_info_old_t) < DAP_BALANCER_MAX_REPLY_SIZE, "DAP_BALANCER_MAX_REPLY_SIZE cannot accommodate information minimum about 1 link");
static const size_t s_max_links_response_count = (DAP_BALANCER_MAX_REPLY_SIZE - sizeof(dap_chain_net_links_t)) / sizeof(dap_chain_node_info_old_t);

static dap_chain_net_links_t *s_get_ignored_node_addrs(dap_chain_net_t *a_net, size_t *a_size)
{
// sanity check
    dap_return_val_if_pass(!a_net, NULL);
// data preparing
    size_t
        l_size = 0,
        l_uplinks_count = 0,
        l_low_availability_count = 0;
    dap_stream_node_addr_t *l_uplinks = dap_link_manager_get_net_links_addrs(a_net->pub.id.uint64, &l_uplinks_count, NULL, true);
    dap_stream_node_addr_t *l_low_availability = dap_link_manager_get_ignored_addrs();
    if(!l_uplinks && !l_low_availability) {
        return NULL;
    }
    l_size = sizeof(dap_chain_net_links_t) + sizeof(dap_stream_node_addr_t) * (l_uplinks_count + l_low_availability_count);
// memory alloc
    dap_chain_net_links_t *l_ret = NULL;
    DAP_NEW_Z_SIZE_RET_VAL(l_ret, dap_chain_net_links_t, l_size, NULL, NULL);
// func work
    memcpy(l_ret->nodes_info, l_uplinks, l_uplinks_count * sizeof(dap_stream_node_addr_t));
    // memcpy(l_ret->nodes_info, l_low_availability, l_low_availability_count * sizeof(dap_stream_node_addr_t));
    l_ret->count_node = l_uplinks_count + l_low_availability_count;
    if (a_size)
        *a_size = l_size;
    DAP_DEL_MULTY(l_uplinks, l_low_availability);
    return l_ret;
}


/**
 * @brief s_net_state_link_prepare_success
 * @param a_worker
 * @param a_node_info
 * @param a_arg
 */
static void s_balancer_link_prepare_success(dap_chain_net_t *a_net, dap_chain_net_links_t *a_link_full_node_list)
{
    char l_err_str[128] = {0};
    struct json_object *l_json;
    for (size_t i = 0; i < a_link_full_node_list->count_node; ++i) {
        dap_link_info_t *l_link_info = (dap_link_info_t *)a_link_full_node_list->nodes_info + i;
        log_it(L_DEBUG,"Link " NODE_ADDR_FP_STR " [ %s : %u ] prepare success",
               NODE_ADDR_FP_ARGS_S(l_link_info->node_addr), l_link_info->uplink_addr, l_link_info->uplink_port);
        if (dap_net_link_add(a_net, &l_link_info->node_addr, l_link_info->uplink_addr, l_link_info->uplink_port))
            continue;
        // l_json = s_net_states_json_collect(a_net);  TODO for balancer
        snprintf(l_err_str, sizeof(l_err_str)
                     , "Link " NODE_ADDR_FP_STR " prepared"
                     , NODE_ADDR_FP_ARGS_S(l_link_info->node_addr));
        json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
        dap_notify_server_send_mt(json_object_get_string(l_json));
        json_object_put(l_json);
        log_it(L_DEBUG, "Link "NODE_ADDR_FP_STR" successfully added",
                 NODE_ADDR_FP_ARGS_S(l_link_info->node_addr));
    }
}

void s_http_balancer_link_prepare_success(void *a_response, size_t a_response_size, void *a_arg)
{
    dap_balancer_link_request_t *l_balancer_request = (dap_balancer_link_request_t *)a_arg;
    dap_chain_net_links_t *l_link_full_node_list = (dap_chain_net_links_t *)a_response;

    size_t l_response_size_need = sizeof(dap_chain_net_links_t) + (sizeof(dap_link_info_t) * l_balancer_request->links_requested_count);
    if (a_response_size < sizeof(dap_chain_net_links_t) + sizeof(dap_link_info_t) || a_response_size > l_response_size_need) {
        log_it(L_ERROR, "Invalid balancer response size %zu (expected %zu)", a_response_size, l_response_size_need);
        DAP_DELETE(l_balancer_request);
        return;
    }
    s_balancer_link_prepare_success(l_balancer_request->net, l_link_full_node_list);
    DAP_DELETE(l_balancer_request);
}

/**
 * @brief s_net_state_link_prepare_error
 * @param a_worker
 * @param a_node_info
 * @param a_arg
 * @param a_errno
 */
static void s_balancer_link_prepare_error(dap_chain_net_t *a_net, const char *a_addr, int a_errno)
{
    struct json_object *l_json = NULL; // TODO
    //s_net_states_json_collect(a_net);
    char l_err_str[512] = { '\0' };
    dap_snprintf(l_err_str, sizeof(l_err_str)
                 , "Link from balancer %s can't be prepared, errno %d"
                 , a_addr, a_errno);
    log_it(L_WARNING, "%s", l_err_str);
    json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
}

void s_http_balancer_link_prepare_error(int a_error_code, void *a_arg)
{
    dap_balancer_link_request_t *l_balancer_request = (dap_balancer_link_request_t *)a_arg;
    s_balancer_link_prepare_error(l_balancer_request->net, l_balancer_request->info->uplink_addr, a_error_code);
    DAP_DELETE(l_balancer_request);
}

int dap_chain_net_balancer_handshake(dap_chain_node_info_t *a_node_info, dap_chain_net_t *a_net)
{
    dap_chain_node_client_t *l_client = dap_chain_node_client_connect_default_channels(a_net, a_node_info);
    return l_client ? dap_chain_node_client_wait(l_client, NODE_CLIENT_STATE_ESTABLISHED, 5000) : -1;
}

static dap_chain_net_links_t *s_get_node_addrs(const char *a_net_name, uint16_t a_links_need, dap_chain_net_links_t *a_ignored, bool a_external_call)
{
// sanity check
    dap_return_val_if_pass(!a_net_name, NULL);
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if (!l_net) {
        log_it(L_WARNING, "There isn't any network by this name - %s", a_net_name);
        return NULL;
    }
// preparing
    dap_list_t *l_nodes_list = dap_get_nodes_states_list_sort(l_net, a_ignored ? a_ignored->nodes_info : (dap_chain_node_addr_t *)NULL, a_ignored ? a_ignored->count_node : 0);
    if (!l_nodes_list) {
        log_it(L_WARNING, "There isn't any nodes in net %s", a_net_name);
        return NULL;
    }
    size_t l_nodes_count = dap_list_length(l_nodes_list);
    if (a_links_need) {
       l_nodes_count = dap_min(l_nodes_count, a_links_need);
    }
    if (a_external_call) {
        l_nodes_count = dap_min(l_nodes_count, s_max_links_response_count);
    }
// memory alloc
    dap_chain_net_links_t *l_ret = DAP_NEW_Z_SIZE(dap_chain_net_links_t, sizeof(dap_chain_net_links_t) + l_nodes_count * sizeof(dap_link_info_t));
    if (!l_ret) {
        log_it(L_ERROR, "%s", g_error_memory_alloc);
        dap_list_free_full(l_nodes_list, NULL);
        return NULL;
    }
// func work
    dap_link_info_t *l_node_info = (dap_link_info_t *)l_ret->nodes_info;
    for(dap_list_t *i = l_nodes_list; i && l_ret->count_node < l_nodes_count; i = i->next, ++l_ret->count_node) {
        dap_mempcpy(l_node_info + l_ret->count_node, &((dap_chain_node_states_info_t *)i->data)->link_info , sizeof(dap_link_info_t));
    }
    dap_list_free_full(l_nodes_list, NULL);
    return l_ret;
}


static dap_chain_net_links_t *s_get_node_addrs_old(const char *a_net_name, uint16_t a_links_need)
{
// sanity check
    dap_return_val_if_pass(!a_net_name || !a_links_need, NULL);
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if (!l_net) {
        log_it(L_WARNING, "There isn't any network by this name - %s", a_net_name);
        return NULL;
    }
// preparing
    dap_list_t *l_nodes_list = dap_get_nodes_states_list_sort(l_net, NULL, 0);
    if (!l_nodes_list) {
        log_it(L_WARNING, "There isn't any nodes in net %s", a_net_name);
        return NULL;
    }
    size_t l_nodes_count = dap_min(s_max_links_response_count, dap_min(dap_list_length(l_nodes_list), a_links_need));
// memory alloc
    dap_chain_net_links_t *l_ret = DAP_NEW_Z_SIZE(dap_chain_net_links_t, sizeof(dap_chain_net_links_t) + l_nodes_count * sizeof(dap_chain_node_info_old_t));
    if (!l_ret) {
        log_it(L_ERROR, "%s", g_error_memory_alloc);
        dap_list_free_full(l_nodes_list, NULL);
        return NULL;
    }
// func work
   
    dap_chain_node_info_old_t *l_node_info = (dap_chain_node_info_old_t *)l_ret->nodes_info;
    for(dap_list_t *i = l_nodes_list; i && l_ret->count_node < l_nodes_count; i = i->next, ++l_ret->count_node) {
        l_node_info[l_ret->count_node].hdr.address.uint64 = ((dap_chain_node_states_info_t *)i->data)->link_info.node_addr.uint64;
        l_node_info[l_ret->count_node].hdr.ext_port = ((dap_chain_node_states_info_t *)i->data)->link_info.uplink_port;
        inet_pton(AF_INET, ((dap_chain_node_states_info_t *)i->data)->link_info.uplink_addr, &l_node_info[l_ret->count_node].hdr.ext_addr_v4);
    }
    dap_list_free_full(l_nodes_list, NULL);
    return l_ret;
}

static dap_chain_net_links_t *s_balancer_issue_link(const char *a_net_name, uint16_t a_links_need, int a_protocol_version, const char *a_ignored_enc)
{
    if(a_protocol_version == 1)
        return s_get_node_addrs_old(a_net_name, a_links_need);
    // prepare list of the ignred addrs
    size_t l_ignored_size = strlen(a_ignored_enc);
    dap_chain_net_links_t *l_ignored_dec = NULL;
    if (l_ignored_size) {
        DAP_NEW_Z_SIZE_RET_VAL(l_ignored_dec, dap_chain_net_links_t, l_ignored_size, NULL, NULL);
        dap_enc_base64_decode(a_ignored_enc, l_ignored_size, l_ignored_dec, DAP_ENC_DATA_TYPE_B64);
        if (l_ignored_size < DAP_ENC_BASE64_ENCODE_SIZE(sizeof(dap_chain_net_links_t) + sizeof(dap_stream_node_addr_t) * l_ignored_dec->count_node)) {
            log_it(L_ERROR, "Cant't decode ignored node list");
            DAP_DEL_Z(l_ignored_dec);
        }
    }
    dap_chain_net_links_t *l_ret = s_get_node_addrs(a_net_name, a_links_need, l_ignored_dec, true);
    DAP_DEL_Z(l_ignored_dec);
    return l_ret;
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
    const char l_ignored_token[] = "ignored=";
    uint16_t links_need = 0;
    sscanf(a_http_simple->http_client->in_query_string, "version=%d,method=%c,needlink=%hu",
                                                            &l_protocol_version, &l_issue_method, &links_need);
    if (l_protocol_version > DAP_BALANCER_PROTOCOL_VERSION || l_protocol_version < 1 || l_issue_method != 'r') {
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
    links_need = links_need ? links_need : s_max_links_response_count;

    char *l_ignored_str = NULL;
    if (l_protocol_version > 1) {
        l_ignored_str = strstr(a_http_simple->http_client->in_query_string, l_ignored_token);
        if (!l_ignored_str) {
            log_it(L_ERROR, "Net ignored token not found in the request to dap_chain_net_balancer module");
            *l_return_code = Http_Status_NotFound;
            return;
        }
        *(l_ignored_str - 1) = 0; // set 0 terminator to split string
        l_ignored_str += sizeof(l_ignored_token) - 1;
    } 
    log_it(L_DEBUG, "HTTP balancer parser retrieve netname %s", l_net_str);
    dap_chain_net_links_t *l_link_full_node_list = s_balancer_issue_link(l_net_str, links_need, l_protocol_version, l_ignored_str);
    if (!l_link_full_node_list) {
        log_it(L_WARNING, "Can't issue link for network %s, no acceptable links found", l_net_str);
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
    dap_chain_net_links_t *l_balancer_reply = s_balancer_issue_link(a_str, 1, DAP_BALANCER_PROTOCOL_VERSION, NULL);
    if (!l_balancer_reply || !l_balancer_reply->count_node) {
        DAP_DEL_Z(l_balancer_reply);
        return NULL;
    }
    dap_link_info_t *l_res = DAP_DUP(( dap_link_info_t *)l_balancer_reply->nodes_info);
    DAP_DELETE(l_balancer_reply);
    return l_res;
}

int dap_chain_net_balancer_request(dap_chain_net_t *a_net, dap_link_info_t *a_balancer_link, int a_balancer_type)
{
// sanity check
    dap_return_val_if_pass(!a_net, -1);
    size_t l_ignored_addrs_size = 0; // prepare list of the ignored addrs
    dap_chain_net_links_t *l_ignored_addrs = s_get_ignored_node_addrs(a_net, &l_ignored_addrs_size);
    size_t l_required_links_count = dap_link_manager_needed_links_count(a_net->pub.id.uint64);
    dap_chain_net_links_t *l_links = s_get_node_addrs(a_net->pub.name, l_required_links_count, l_ignored_addrs, false);
    if (l_links) {
        s_balancer_link_prepare_success(a_net, l_links);
        if (l_links->count_node >= l_required_links_count) {
            DAP_DEL_MULTY(l_ignored_addrs, l_links);
            return 0;
        }
        else
            l_required_links_count -= l_links->count_node;
        DAP_DELETE(l_links);
    }
    if (!a_balancer_link) {
        log_it(L_INFO, "Can't read seed nodes addresses, work with local balancer only");
        return 0;
    }
    // dynamic links from http balancer request
    dap_balancer_link_request_t *l_balancer_request = NULL;
    DAP_NEW_Z_RET_VAL(l_balancer_request, dap_balancer_link_request_t, -4, NULL);
    *l_balancer_request = (dap_balancer_link_request_t) {
        .info = a_balancer_link,
        .net = a_net,
        .worker = dap_events_worker_get_auto(),
        .links_requested_count = l_required_links_count
    };
    log_it(L_DEBUG, "Start balancer %s request to %s:%u",
           a_balancer_type == 0 ? "HTTP" : "DNS", l_balancer_request->info->uplink_addr, l_balancer_request->info->uplink_port);
    
    int ret;
    if (a_balancer_type == 0) {
        char *l_ignored_addrs_str = NULL;
        if (l_ignored_addrs) {
            DAP_NEW_Z_SIZE_RET_VAL(
                l_ignored_addrs_str, char, DAP_ENC_BASE64_ENCODE_SIZE(l_ignored_addrs_size) + 1,
                -7, l_ignored_addrs, l_balancer_request);
            dap_enc_base64_encode(l_ignored_addrs, l_ignored_addrs_size, l_ignored_addrs_str, DAP_ENC_DATA_TYPE_B64);
            DAP_DELETE(l_ignored_addrs);
        }
        // request prepare
        char *l_request = dap_strdup_printf("%s/%s?version=%d,method=r,needlink=%d,net=%s,ignored=%s",
                                                DAP_UPLINK_PATH_BALANCER,
                                                DAP_BALANCER_URI_HASH,
                                                DAP_BALANCER_PROTOCOL_VERSION,
                                                (int)l_required_links_count,
                                                a_net->pub.name,
                                                l_ignored_addrs_str ? l_ignored_addrs_str : "");
        ret = dap_client_http_request(l_balancer_request->worker,
                                                l_balancer_request->info->uplink_addr,
                                                l_balancer_request->info->uplink_port,
                                                "GET",
                                                "text/text",
                                                l_request,
                                                NULL,
                                                0,
                                                NULL,
                                                s_http_balancer_link_prepare_success,
                                                s_http_balancer_link_prepare_error,
                                                l_balancer_request,
                                                NULL) == NULL;
        DAP_DEL_MULTY(l_ignored_addrs_str, l_request);
    } else {
        l_balancer_request->info->uplink_port = DNS_LISTEN_PORT;
        // TODO: change signature and implementation
        ret = /* dap_chain_node_info_dns_request(l_balancer_request->worker,
                                                l_link_node_info->hdr.ext_addr_v4,
                                                l_link_node_info->hdr.ext_port,
                                                a_net->pub.name,
                                                s_dns_balancer_link_prepare_success,
                                                s_dns_balancer_link_prepare_error,
                                                l_balancer_request); */ -1;
    }
    if (ret) {
        log_it(L_ERROR, "Can't process balancer link %s request", a_balancer_type == 0 ? "HTTP" : "DNS");
        return -6;
    }
    return 0;
}

dap_string_t *dap_chain_net_balancer_get_node_str(dap_chain_net_t *a_net)
{
    dap_chain_net_links_t *l_links_info_list = s_get_node_addrs(a_net->pub.name, 0, NULL, false);  // TODO
    dap_string_t *l_ret = dap_string_new(l_links_info_list ? "" : "Empty");
    uint64_t l_node_num = l_links_info_list ? l_links_info_list->count_node : 0;
    for (uint64_t i = 0; i < l_node_num; ++i) {
        dap_link_info_t *l_link_info = (dap_link_info_t *)l_links_info_list->nodes_info + i;
        dap_string_append_printf(l_ret, NODE_ADDR_FP_STR"    %-20s\n",
                                    NODE_ADDR_FP_ARGS_S(l_link_info->node_addr),
                                    l_link_info->uplink_addr);
                                    /*l_node_link->info.links_number);*/
        if(i + 1 == s_max_links_response_count ) {
            dap_string_append_printf(l_ret, "-----------------------------------\n");
        }
    }
    dap_string_prepend_printf(l_ret, "Balancer link list for total %" DAP_UINT64_FORMAT_U " records:\n",
                                          l_node_num);
    DAP_DEL_Z(l_links_info_list);
    return l_ret;
}