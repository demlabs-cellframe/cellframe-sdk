/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Roman Khlopkov <roman.khlopkov@demlabs.net>
* Pavel Uhanov <pavel.uhanov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2024
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
#include "dap_net.h"
#include "dap_client_http.h"
#include "dap_enc_base64.h"
#include "dap_notify_srv.h"

#define LOG_TAG "dap_chain_net_balancer"

#define DAP_CHAIN_NET_BALANCER_REQUEST_DELAY 20 // sec

typedef struct dap_balancer_request_info {
    dap_chain_net_id_t net_id;
    dap_time_t request_time;
    UT_hash_handle hh;
} dap_balancer_request_info_t;

static_assert(sizeof(dap_chain_net_links_t) + sizeof(dap_chain_node_info_old_t) < DAP_BALANCER_MAX_REPLY_SIZE, "DAP_BALANCER_MAX_REPLY_SIZE cannot accommodate information minimum about 1 link");
static const size_t s_max_links_response_count = (DAP_BALANCER_MAX_REPLY_SIZE - sizeof(dap_chain_net_links_t)) / sizeof(dap_chain_node_info_old_t);
static dap_balancer_request_info_t* s_request_info_items = NULL;

/**
 * @brief forming json file with balancer info: class networkName nodeAddress hostAddress hostPort
 * @param a_net - responce net
 * @param a_host_info - host info
 */
struct json_object *s_balancer_states_json_collect(dap_chain_net_t *a_net, const char* a_host_addr, uint16_t a_host_port)
{
    struct json_object *l_json = json_object_new_object();
    json_object_object_add(l_json, "class"          , json_object_new_string("BalancerRequest"));
    json_object_object_add(l_json, "networkName"    , json_object_new_string((const char*)a_net->pub.name));
    json_object_object_add(l_json, "hostAddress"    , json_object_new_string(a_host_addr ? a_host_addr : "localhost"));
    if (a_host_addr)
        json_object_object_add(l_json, "hostPort"       , json_object_new_int(a_host_port));
    return l_json;
}

/**
 * @brief get ignored node addr
 * @param a_net - net
 * @param a_size - out ingored node count
 */
static dap_chain_net_links_t *s_get_ignored_node_addrs(dap_chain_net_t *a_net, size_t *a_size)
{
// sanity check
    dap_return_val_if_pass(!a_net, NULL);
// data preparing
    size_t
        l_size = 0,
        l_uplinks_count = 0,
        l_downlinks_count = 0,
        l_links_count = 0,
        l_low_availability_count = 0;
    dap_stream_node_addr_t
        *l_curr_addr = &dap_chain_net_get_my_node_info(a_net)->address,
        *l_links = dap_link_manager_get_net_links_addrs(a_net->pub.id.uint64, &l_uplinks_count, &l_downlinks_count, false),
        *l_low_availability = dap_link_manager_get_ignored_addrs(&l_low_availability_count, a_net->pub.id.uint64);
        l_links_count = l_uplinks_count + l_downlinks_count;
    if(!l_curr_addr->uint64 && !l_links && !l_low_availability) {
        log_it(L_WARNING, "Error forming ignore list in net %s, please check, should be minimum self addr", a_net->pub.name);
        return NULL;
    }
    l_size = sizeof(dap_chain_net_links_t) + sizeof(dap_stream_node_addr_t) * (l_links_count + l_low_availability_count + 1);
    // memory alloc
    dap_chain_net_links_t *l_ret = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_net_links_t, l_size, NULL, l_links, l_low_availability);
    l_ret->count_node = l_links_count + l_low_availability_count + 1;
    if (dap_log_level_get() <= L_DEBUG ) {
        char l_ignored_str[4096];
        int l_pos = snprintf(l_ignored_str, sizeof(l_ignored_str), 
                             "Next %zu nodes will be ignored in balancer links preparing in net %s:\n"
                             "\tSelf:\n\t\t"NODE_ADDR_FP_STR"\n\tActive links (%zu):\n",
                             l_ret->count_node, a_net->pub.name, NODE_ADDR_FP_ARGS(l_curr_addr), l_links_count);
        for (size_t i = 0; i < l_links_count && l_pos < (int)sizeof(l_ignored_str); ++i) {
            l_pos += snprintf(l_ignored_str + l_pos, sizeof(l_ignored_str) - l_pos, "\t\t"NODE_ADDR_FP_STR"\n", NODE_ADDR_FP_ARGS(l_links + i));
        }
        if (l_pos < (int)sizeof(l_ignored_str)) {
            l_pos += snprintf(l_ignored_str + l_pos, sizeof(l_ignored_str) - l_pos, "\tCooling (%zu):\n", l_low_availability_count);
            for (size_t i = 0; i < l_low_availability_count && l_pos < (int)sizeof(l_ignored_str); ++i) {
                l_pos += snprintf(l_ignored_str + l_pos, sizeof(l_ignored_str) - l_pos, "\t\t"NODE_ADDR_FP_STR"\n", NODE_ADDR_FP_ARGS(l_low_availability + i));
            }
        }
        log_it(L_DEBUG, "%s", l_ignored_str);
    }
// func work
    byte_t *l_mempos = dap_mempcpy(l_ret->nodes_info, l_curr_addr, sizeof(dap_stream_node_addr_t));
    if(l_links)
        l_mempos = dap_mempcpy(l_mempos, l_links, l_links_count * sizeof(dap_stream_node_addr_t));
    if(l_low_availability)
        dap_mempcpy(l_mempos, l_low_availability, l_low_availability_count * sizeof(dap_stream_node_addr_t));
    if (a_size)
        *a_size = l_size;
    DAP_DEL_MULTY(l_links, l_low_availability);
    return l_ret;
}

/**
 * @brief callback to success balancer request
 * @param a_net - responce net
 * @param a_link_full_node_list - getted node list
 * @param a_host_info - host info
 */
static void s_balancer_link_prepare_success(dap_chain_net_t* a_net, dap_chain_net_links_t *a_link_full_node_list, const char* a_host_addr, uint16_t a_host_port)
{
    char l_err_str[128] = {0};
    if (dap_log_level_get() <= L_DEBUG ) {
        char l_links_str[1024];
        int l_pos = snprintf(l_links_str, sizeof(l_links_str) - 1,
                             "Next %"DAP_UINT64_FORMAT_U" links prepared from balancer in net %s:\n",
                             a_link_full_node_list->count_node, a_net->pub.name);
        for (size_t i = 0; i < a_link_full_node_list->count_node && l_pos < (int)sizeof(l_links_str); ++i) {
            dap_link_info_t *l_link_info = (dap_link_info_t*)a_link_full_node_list->nodes_info + i;
            l_pos += snprintf(l_links_str + l_pos, sizeof(l_links_str) - l_pos - 1, "\t"NODE_ADDR_FP_STR " [ %s : %u ]\n",
                              NODE_ADDR_FP_ARGS_S(l_link_info->node_addr), l_link_info->uplink_addr, l_link_info->uplink_port);
        }
        log_it(L_DEBUG, "%s", l_links_str);
    }
    struct json_object *l_json;
    for (size_t i = 0; i < a_link_full_node_list->count_node; ++i) {
        dap_link_info_t *l_link_info = (dap_link_info_t *)a_link_full_node_list->nodes_info + i;
        if (dap_chain_net_link_add(a_net, &l_link_info->node_addr, l_link_info->uplink_addr, l_link_info->uplink_port))
            continue;
        l_json = s_balancer_states_json_collect(a_net, a_host_addr, a_host_port);
        dap_notify_server_send_mt(json_object_get_string(l_json));
        json_object_put(l_json);
    }
}

/**
 * @brief callback to error in balancer request preparing
 * @param a_request - balancer request
 * @param a_host_addr - host addr
 * @param a_errno - error code
 */
static void s_balancer_link_prepare_error(dap_balancer_link_request_t *a_request, const char *a_host_addr, uint16_t a_host_port, int a_errno)
{
    struct json_object *l_json = s_balancer_states_json_collect(a_request->net, a_host_addr, a_host_port);
    char l_err_str[256] = { '\0' };
    snprintf(l_err_str, sizeof(l_err_str)
            , "Links from balancer %s:%u in net %s can't be prepared, connection errno %d"
            , a_host_addr, a_host_port, a_request->net->pub.name, a_errno);
    log_it(L_WARNING, "%s", l_err_str);
    json_object_object_add(l_json, "errorMessage", json_object_new_string(l_err_str));
    dap_notify_server_send_mt(json_object_get_string(l_json));
    json_object_put(l_json);
}

/**
 * @brief callback to success http balancer request
 * @param a_response - response
 * @param a_response_size - a response size
 * @param a_arg - callback arg (l_balancer_request)
 */
void s_http_balancer_link_prepare_success(void *a_response,
                                          size_t a_response_size, void *a_arg, http_status_code_t a_response_code)
{
    dap_balancer_link_request_t *l_balancer_request = (dap_balancer_link_request_t *)a_arg;
    if (a_response_code != 200) {
        log_it(L_ERROR, "The server responded with code %d. It is not possible to install the link to %s:%u in net %s", a_response_code, l_balancer_request->host_addr, l_balancer_request->host_port, l_balancer_request->net->pub.name);
        s_balancer_link_prepare_error(l_balancer_request, l_balancer_request->host_addr, l_balancer_request->host_port, a_response_code);
        l_balancer_request->request_info->request_time = dap_time_now();
        DAP_DELETE(l_balancer_request);
        return;
    }
    dap_chain_net_links_t *l_link_full_node_list = (dap_chain_net_links_t *)a_response;

    size_t l_response_size_need = sizeof(dap_chain_net_links_t) + (sizeof(dap_link_info_t) * l_balancer_request->required_links_count);
    if (a_response_size < sizeof(dap_chain_net_links_t) + sizeof(dap_link_info_t) || a_response_size > l_response_size_need) {
        log_it(L_ERROR, "Invalid balancer response size %zu (expected %zu) in net %s from %s:%u", a_response_size, l_response_size_need, l_balancer_request->net->pub.name, l_balancer_request->host_addr, l_balancer_request->host_port);
        l_balancer_request->request_info->request_time = dap_time_now();
    } else {
        log_it(L_INFO, "Valid balancer response from %s:%u in net %s with %"DAP_UINT64_FORMAT_U" links", l_balancer_request->host_addr, l_balancer_request->host_port, l_balancer_request->net->pub.name, l_link_full_node_list->count_node);
        s_balancer_link_prepare_success(l_balancer_request->net, l_link_full_node_list, l_balancer_request->host_addr, l_balancer_request->host_port);
        l_balancer_request->request_info->request_time = 0;
    }
    DAP_DELETE(l_balancer_request);
}


/**
 * @brief callback to error in http balancer request preparing
 * @param a_errno - error code
 * @param a_arg - callback arg (l_balancer_request)
 */
static void s_http_balancer_link_prepare_error(int a_errno, void *a_arg)
{
    dap_balancer_link_request_t *l_balancer_request = (dap_balancer_link_request_t *)a_arg;
    s_balancer_link_prepare_error(l_balancer_request, l_balancer_request->host_addr, l_balancer_request->host_port, a_errno);
    l_balancer_request->request_info->request_time = dap_time_now();
    DAP_DELETE(l_balancer_request);
}

/**
 * @brief forming links info
 * @param a_net - net to froming info
 * @param a_links_need - needed link count, if 0 - max possible
 * @param a_ignored - list with ignored links
 * @param a_external_call - externl call flag, if false - max possible
 * @return if error NULL, or pointer to link info
 */
static dap_chain_net_links_t *s_get_node_addrs(dap_chain_net_t *a_net, uint16_t a_links_need, dap_chain_net_links_t *a_ignored, bool a_external_call)
{
// sanity check
    dap_return_val_if_pass(!a_net, NULL);
// preparing
    dap_list_t *l_nodes_list = dap_chain_node_get_states_list_sort(a_net, a_ignored ? (dap_chain_node_addr_t *)a_ignored->nodes_info : (dap_chain_node_addr_t *)NULL, a_ignored ? a_ignored->count_node : 0);
    if (!l_nodes_list) {
        log_it(L_DEBUG, "There isn't any nodes to %s list prepare in net %s", a_external_call ? "external" : "local", a_net->pub.name);
        if (!a_external_call)
            return NULL;
    }
    size_t l_nodes_count = dap_list_length(l_nodes_list);
    if (a_links_need) {
       l_nodes_count = dap_min(l_nodes_count, a_links_need);
    }
    if (a_external_call) {
        l_nodes_count = dap_min(l_nodes_count, s_max_links_response_count);
    }
    if (!l_nodes_count) {
        return NULL;
    }
// memory alloc
    dap_chain_net_links_t *l_ret = DAP_NEW_Z_SIZE(dap_chain_net_links_t, sizeof(dap_chain_net_links_t) + l_nodes_count * sizeof(dap_link_info_t));
    if (!l_ret) {
        log_it(L_ERROR, "%s", c_error_memory_alloc);
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

/**
 * @brief forming links info in old format
 * @param a_net - net to froming info
 * @param a_links_need - needed link count, if 0 - max possible
 * @return if error NULL, or pointer to link info
 */
static dap_chain_net_links_t *s_get_node_addrs_old(dap_chain_net_t *a_net, uint16_t a_links_need)
{
// sanity check
    dap_return_val_if_pass(!a_net, NULL);
// preparing
    dap_list_t *l_nodes_list = dap_chain_node_get_states_list_sort(a_net, NULL, 0);
    if (!l_nodes_list) {
        log_it(L_WARNING, "There isn't any nodes to list prepare in net %s", a_net->pub.name);
        return NULL;
    }
    size_t l_nodes_count = dap_list_length(l_nodes_list);
    if (a_links_need) {
       l_nodes_count = dap_min(l_nodes_count, a_links_need);
    }
    l_nodes_count = dap_min(l_nodes_count, s_max_links_response_count);
    if (!l_nodes_count) {
        return NULL;
    }
// memory alloc
    dap_chain_net_links_t *l_ret = DAP_NEW_Z_SIZE(dap_chain_net_links_t, sizeof(dap_chain_net_links_t) + l_nodes_count * sizeof(dap_chain_node_info_old_t));
    if (!l_ret) {
        log_it(L_ERROR, "%s", c_error_memory_alloc);
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

/**
 * @brief issue to balancer request
 * @param a_net_name - net name
 * @param a_links_need - needed link count, if 0 - max possible
 * @param a_protocol_version - balancer protocol version
 * @param a_ignored_enc - encrypted to base64 ignored node addrs
 * @return if error NULL, or pointer to link info
 */
static dap_chain_net_links_t *s_balancer_issue_link(const char *a_net_name, uint16_t a_links_need, int a_protocol_version, const char *a_ignored_enc)
{
    dap_return_val_if_pass(!a_net_name, NULL);
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if (!l_net)
        return log_it(L_WARNING, "There isn't any network by name \"%s\"", a_net_name), NULL;
        
    if ( a_protocol_version == 1 )
        return s_get_node_addrs_old(l_net, a_links_need);
    // prepare list of the ignred addrs
    size_t l_ignored_size = 0;
    dap_chain_net_links_t *l_ignored_dec = NULL;
    if (a_ignored_enc && *a_ignored_enc) {
        l_ignored_size = strlen(a_ignored_enc);
        l_ignored_dec = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_net_links_t, DAP_ENC_BASE64_DECODE_SIZE(l_ignored_size) + 1, NULL);
        dap_enc_base64_decode(a_ignored_enc, l_ignored_size, l_ignored_dec, DAP_ENC_DATA_TYPE_B64);
        size_t l_check_size = sizeof(dap_chain_net_links_t) + sizeof(dap_stream_node_addr_t) * l_ignored_dec->count_node;
        if (l_ignored_size < l_check_size) {
            log_it(L_ERROR, "Can't decode ignored node list in net %s, actual and expected sizes mismath: %zu < %zu",
                            a_net_name, l_ignored_size, l_check_size);
            DAP_DEL_Z(l_ignored_dec);
        }
    }
    dap_chain_net_links_t *l_ret = s_get_node_addrs(l_net, a_links_need, l_ignored_dec, true);
    DAP_DELETE(l_ignored_dec);
    return l_ret;
}

/**
 * @brief balancer deinit, use ONLY after dap_link_manager deinit
 */
void dap_chain_net_balancer_deinit()
{
    dap_balancer_request_info_t *l_item = NULL, *l_tmp = NULL;
    HASH_ITER(hh, s_request_info_items, l_item, l_tmp)
        HASH_DEL(s_request_info_items, l_item);
}

/**
 * @brief balancer handshake
 * @param a_node_info
 * @param a_net
 * @return -1 false, 0 timeout, 1 end of connection or sending data
 */
int dap_chain_net_balancer_handshake(dap_chain_node_info_t *a_node_info, dap_chain_net_t *a_net)
{
    dap_chain_node_client_t *l_client = dap_chain_node_client_connect_default_channels(a_net, a_node_info);
    return l_client ? dap_chain_node_client_wait(l_client, NODE_CLIENT_STATE_ESTABLISHED, 5000) : -1;
}

/**
 * @brief issue to http balancer request
 * @param a_http_simple - http request
 * @param a_arg - request arg
 */
void dap_chain_net_balancer_http_issue_link(dap_http_simple_t *a_http_simple, void *a_arg)
{
    log_it(L_DEBUG,"Proc enc http request from %s", a_http_simple->es_hostaddr);
    http_status_code_t *l_return_code = (http_status_code_t *)a_arg;

    if (strcmp(a_http_simple->http_client->url_path, DAP_BALANCER_URI_HASH)) {
        log_it(L_ERROR, "Wrong path '%s' in the request to dap_chain_net_balancer module",
                                                            a_http_simple->http_client->url_path);
        *l_return_code = Http_Status_BadRequest;
        return;
    }
    int l_protocol_version = 0;
    char l_issue_method = 0;
    const char l_net_token[] = "net=", l_ignored_token[] = "ignored=";
    uint16_t l_links_need = 0;
    sscanf(a_http_simple->http_client->in_query_string, "version=%d,method=%c,needlink=%hu",
                                                            &l_protocol_version, &l_issue_method, &l_links_need);
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
    dap_chain_net_links_t *l_link_full_node_list = s_balancer_issue_link(l_net_str, l_links_need, l_protocol_version, l_ignored_str);
    if (!l_link_full_node_list) {
        log_it(L_DEBUG, "Can't issue link for network %s, no acceptable links found", l_net_str);
        *l_return_code = Http_Status_NoContent;
        return;
    }
    *l_return_code = Http_Status_OK;
    size_t l_data_send_size = sizeof(dap_chain_net_links_t);
    if (l_protocol_version == 1)
        l_data_send_size += sizeof(dap_chain_node_info_old_t) * l_link_full_node_list->count_node;
    else
        l_data_send_size += sizeof(dap_link_info_t) * l_link_full_node_list->count_node;
    dap_http_simple_reply(a_http_simple, l_link_full_node_list, l_data_send_size);
    DAP_DELETE(l_link_full_node_list);
}

/**
 * @brief issue to dns balancer request
 * @param a_net_name - net name
 * @return if error NULL, or pointer to link info
 */
dap_link_info_t *dap_chain_net_balancer_dns_issue_link(const char *a_net_name)
{
// sanity check
    dap_return_val_if_pass(!a_net_name, NULL);
// func work
    log_it(L_DEBUG, "DNS balancer parser retrieve netname %s", a_net_name);
    dap_chain_net_links_t *l_balancer_reply = s_balancer_issue_link(a_net_name, 1, DAP_BALANCER_PROTOCOL_VERSION, NULL);
    if (!l_balancer_reply || !l_balancer_reply->count_node) {
        DAP_DEL_Z(l_balancer_reply);
        return NULL;
    }
    dap_link_info_t *l_res = DAP_DUP(( dap_link_info_t *)l_balancer_reply->nodes_info);
    DAP_DELETE(l_balancer_reply);
    return l_res;
}

/**
 * @brief prepare balancer request
 * @param a_net - net to addrs request
 * @param a_balancer_link - host to send request
 * @param a_balancer_type - http or DNS
 * @return if ok 0, error - other
 */
void dap_chain_net_balancer_request(void *a_arg)
{
// sanity check
    dap_return_if_fail(a_arg);
    dap_balancer_link_request_t *l_arg = (dap_balancer_link_request_t*)a_arg;
// period request check
    dap_balancer_request_info_t *l_item = NULL;
    HASH_FIND(hh, s_request_info_items, &l_arg->net->pub.id, sizeof(l_arg->net->pub.id), l_item);
    if (!l_item) {
        l_item = DAP_NEW_Z_RET_IF_FAIL(dap_balancer_request_info_t);
        l_item->net_id = l_arg->net->pub.id;
        HASH_ADD(hh, s_request_info_items, net_id, sizeof(l_item->net_id), l_item);
    }
    if (l_item->request_time + DAP_CHAIN_NET_BALANCER_REQUEST_DELAY > dap_time_now()) {
        log_it(L_DEBUG, "Who understands life, he is in no hurry. Dear %s, please wait few seconds", l_arg->net->pub.name);
        DAP_DELETE(a_arg);
        return;
    }
// preparing to request
    size_t
        l_ignored_addrs_size = 0,
        l_required_links_count = dap_link_manager_needed_links_count(l_arg->net->pub.id.uint64);
    dap_chain_net_links_t
        *l_ignored_addrs = s_get_ignored_node_addrs(l_arg->net, &l_ignored_addrs_size),
        *l_links = s_get_node_addrs(l_arg->net, l_required_links_count, l_ignored_addrs, false);
// links from local GDB
    if (l_links) {
        log_it(L_INFO, "%"DAP_UINT64_FORMAT_U" links successful prepared from global-db in net %s", l_links->count_node, l_arg->net->pub.name);
        s_balancer_link_prepare_success(l_arg->net, l_links, NULL, 0);
        if (l_links->count_node >= l_required_links_count)
            return DAP_DEL_MULTY(a_arg, l_ignored_addrs, l_links);
        l_required_links_count -= l_links->count_node;
        DAP_DELETE(l_links);
    }
// links from http balancer request
    if (!l_arg->host_addr || !*l_arg->host_addr || !l_arg->host_port)
        return DAP_DEL_MULTY(a_arg, l_ignored_addrs), log_it(L_INFO, "Can't read seed nodes addresses in net %s, work with local balancer only",
                                                            l_arg->net->pub.name);
    l_arg->worker = dap_worker_get_current();
    l_arg->required_links_count = l_required_links_count;
    l_arg->request_info = l_item;
    log_it(L_DEBUG, "Start balancer %s request to %s:%u in net %s",
                    dap_chain_net_balancer_type_to_str(l_arg->type), l_arg->host_addr, l_arg->host_port, l_arg->net->pub.name);
    
    if (l_arg->type == DAP_CHAIN_NET_BALANCER_TYPE_HTTP) {
        char *l_ignored_addrs_str = NULL;
        if (l_ignored_addrs) {
            l_ignored_addrs_str = DAP_NEW_Z_SIZE_RET_IF_FAIL(char, DAP_ENC_BASE64_ENCODE_SIZE(l_ignored_addrs_size) + 1, l_ignored_addrs, l_arg);
            dap_enc_base64_encode(l_ignored_addrs, l_ignored_addrs_size, l_ignored_addrs_str, DAP_ENC_DATA_TYPE_B64);
            DAP_DELETE(l_ignored_addrs);
        }
        // request prepare
        const char *l_net_name = l_arg->net->pub.name, *l_bal_type = dap_chain_net_balancer_type_to_str(l_arg->type);
        char *l_request = dap_strdup_printf("%s/%s?version=%d,method=r,needlink=%d,net=%s,ignored=%s",
                                                DAP_UPLINK_PATH_BALANCER,
                                                DAP_BALANCER_URI_HASH,
                                                DAP_BALANCER_PROTOCOL_VERSION,
                                                (int)l_required_links_count,
                                                l_arg->net->pub.name,
                                                l_ignored_addrs_str ? l_ignored_addrs_str : "");
        if (! dap_client_http_request(l_arg->worker, l_arg->host_addr, l_arg->host_port, "GET", "text/text",
                                      l_request, NULL, 0, NULL, s_http_balancer_link_prepare_success, 
                                      s_http_balancer_link_prepare_error, l_arg, NULL) )
            log_it(L_ERROR, "Can't process balancer link %s request in net %s", l_bal_type, l_net_name);
        DAP_DEL_MULTY(l_ignored_addrs_str, l_request);
    } else {
        l_arg->host_port = DNS_LISTEN_PORT;
        // TODO: change signature and implementation
        /* dap_chain_node_info_dns_request(l_balancer_request->worker,
                                            l_link_node_info->hdr.ext_addr_v4,
                                            l_link_node_info->hdr.ext_port,
                                            a_net->pub.name,
                                            s_dns_balancer_link_prepare_success,
                                            s_dns_balancer_link_prepare_error,
                                            l_balancer_request); */
    }
}

/**
 * @brief forming report about balacer response to request
 * @param a_net - net to report
 * @return if error NULL, other - report
 */
json_object *dap_chain_net_balancer_get_node_str(dap_chain_net_t *a_net)
{
// sanity check
    dap_return_val_if_pass(!a_net, NULL);
// func work
    json_object *l_jobj_out = json_object_new_object();
    if (!l_jobj_out) return dap_json_rpc_allocation_put(l_jobj_out);
    json_object *l_jobj_list_array = json_object_new_array();
    if (!l_jobj_list_array) return dap_json_rpc_allocation_put(l_jobj_out);
    json_object_object_add(l_jobj_out, "links_list", l_jobj_list_array);
    dap_chain_net_links_t *l_links_info_list = s_get_node_addrs(a_net, 0, NULL, false);  // TODO

    uint64_t l_node_num = l_links_info_list ? l_links_info_list->count_node : 0;
    for (uint64_t i = 0; i < l_node_num; ++i) {
        dap_link_info_t *l_link_info = (dap_link_info_t *)l_links_info_list->nodes_info + i;
        json_object *l_jobj_link = json_object_new_object();
        if (!l_jobj_link) return dap_json_rpc_allocation_put(l_jobj_out);
        char * l_node_addr = dap_strdup_printf(""NODE_ADDR_FP_STR"",NODE_ADDR_FP_ARGS_S(l_link_info->node_addr));
        json_object_object_add(l_jobj_link, "node_addr", json_object_new_string(l_node_addr));
        DAP_DELETE(l_node_addr);
        char * l_uplink_addr = dap_strdup_printf("%-16s", l_link_info->uplink_addr);
        json_object_object_add(l_jobj_link, "host_addr", json_object_new_string(l_uplink_addr));
        DAP_DELETE(l_uplink_addr);
        json_object_object_add(l_jobj_link, "port", json_object_new_uint64(l_link_info->uplink_port));

        if(i + 1 == s_max_links_response_count && i + 1 < l_node_num) {
            json_object_object_add(l_jobj_link, "status", json_object_new_string("Not send in http balancer response"));
        }
        json_object_array_add(l_jobj_list_array, l_jobj_link);
    }
    json_object_object_add(l_jobj_out, "links total", json_object_new_uint64(l_node_num));
    DAP_DEL_Z(l_links_info_list);
    return l_jobj_out;
}
