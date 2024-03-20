/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Roman Padenkov <roman.padenkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2023
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
#include "http_status_code.h"
#include "dap_chain_net_balancer.h"
#include "dap_client.h"
#include "dap_client_http.h"

#define LOG_TAG "dap_chain_net_node_list"

enum RetCode {
    ADD_OK = 1,
    ERR_NO_SERVER,
    ERR_NOT_ADDED,
    ERR_HASH,
    ERR_HANDSHAKE,
    ERR_EXISTS,
    ERR_NOT_PINNER,
    ERR_DELETED,
    ERR_WAIT_TIMEOUT,
    ERR_UNKNOWN
};

static int s_dap_chain_net_node_list_add_downlink(const char * a_group, const char *a_key, dap_chain_node_info_t * a_node_info) {
    char l_node_addr_str[INET_ADDRSTRLEN]={};
    inet_ntop(AF_INET, &a_node_info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
    if (!dap_global_db_set_sync(a_group, a_key, (uint8_t*)a_node_info, sizeof(dap_chain_node_info_t), true)) {
        log_it(L_DEBUG, "Add address"NODE_ADDR_FP_STR" (%s) to node list by "NODE_ADDR_FP_STR"",
                    NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address),l_node_addr_str,
                    NODE_ADDR_FP_ARGS_S(a_node_info->hdr.owner_address));
        return ADD_OK;
    } else {
        log_it(L_ERROR, "Address"NODE_ADDR_FP_STR" (%s) not added",
                    NODE_ADDR_FP_ARGS_S(a_node_info->hdr.address),l_node_addr_str);
        return ERR_NOT_ADDED;
    }
}

/**
 * @brief server function, makes handshake and add node to node list
 *
 * @param dap_http_simple_t *a_http_simple, void *a_arg
 * @return void
 * send value
 * 1 - Node addr successfully added to node list
 * 2 - Can't add this addres to node list
 * 3 - Can't calculate hash for addr
 * 4 - Can't do handshake
 * 5 - Already exists
 * 6 - I'am not the pinner this node (only for update links count)
 * 7 - Node deleted
 */
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
    uint64_t blocks = 0;
    uint16_t port = 0;
    uint32_t links_cnt = 0;
    const char l_net_token[] = "net=";
    sscanf(a_http_simple->http_client->in_query_string, "version=%d,method=%c,addr=%zu,port=%hu,lcnt=%d,blks=%zu,net=",
                                                            &l_protocol_version, &l_issue_method, &addr, &port, &links_cnt, &blocks);
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
    l_net_str += strlen(l_net_token);
    log_it(L_DEBUG, "HTTP Node check parser retrieve netname %s", l_net_str);

    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
    dap_chain_t *l_chain;
    DL_FOREACH(l_net->pub.chains, l_chain) {
        blocks = l_chain->callback_count_atom(l_chain);
    }
    dap_chain_node_info_t l_node_info = {
        .hdr.address.uint64 = addr,
        .hdr.owner_address.uint64 = dap_chain_net_get_cur_addr_int(l_net),
        .hdr.ext_port = port,
        .hdr.links_number = links_cnt,
        .hdr.blocks_events = blocks
    };    
    inet_pton(AF_INET, a_http_simple->es_hostaddr, &l_node_info.hdr.ext_addr_v4);
    uint8_t response = ERR_UNKNOWN;
    char *l_key = dap_chain_node_addr_to_hash_str(&l_node_info.hdr.address);
    if(!l_key)
    {
        log_it(L_DEBUG, "Can't calculate hash for addr");
        response = ERR_HASH;
    } else {
        size_t node_info_size = 0;
        dap_chain_node_info_t *l_node_inf_check = (dap_chain_node_info_t *) dap_global_db_get_sync(l_net->pub.gdb_nodes, l_key, &node_info_size, NULL, NULL);
        if(l_node_inf_check)
        {
            //is it pinner?
            if(l_node_inf_check->hdr.owner_address.uint64 == l_node_info.hdr.owner_address.uint64)
            {
                if((l_node_info.hdr.links_number != l_node_inf_check->hdr.links_number) ||
                   (l_node_info.hdr.ext_addr_v4.s_addr != l_node_inf_check->hdr.ext_addr_v4.s_addr))
                {
                    dap_global_db_del_sync(l_net->pub.gdb_nodes, l_key);
                    response = s_dap_chain_net_node_list_add_downlink(l_net->pub.gdb_nodes,l_key,&l_node_info);
                }
                else
                {
                    log_it(L_DEBUG, "The node already exists");
                    response = ERR_EXISTS;
                }
            }
            else
            {
                log_it(L_DEBUG, "I'am not the pinner this node");
                response = ERR_NOT_PINNER;
            }
            DAP_DELETE(l_node_inf_check);
        } else{
            if(dap_chain_net_balancer_handshake(&l_node_info,l_net))
                response = s_dap_chain_net_node_list_add_downlink(l_net->pub.gdb_nodes,l_key,&l_node_info);
            else
            {
                log_it(L_DEBUG, "Can't do handshake");
                response = ERR_HANDSHAKE;
            }
        }
        DAP_DELETE(l_key);
    }

    *l_return_code = Http_Status_OK;
    size_t l_data_send_size = sizeof(uint8_t);
    dap_http_simple_reply(a_http_simple, &response, l_data_send_size);
}

static void s_net_node_link_prepare_success(void *a_response, size_t a_response_size, void *a_arg) {
    struct node_link_request *l_node_list_request = (struct node_link_request *)a_arg;
    pthread_mutex_lock(&l_node_list_request->wait_mutex);
    l_node_list_request->response = *(uint8_t*)a_response;
    pthread_cond_signal(&l_node_list_request->wait_cond);
    pthread_mutex_unlock(&l_node_list_request->wait_mutex);
}
static void s_net_node_link_prepare_error(int a_error_code, void *a_arg){
    struct node_link_request * l_node_list_request = (struct node_link_request *)a_arg;
    dap_chain_node_info_t *l_node_info = l_node_list_request->link_info;
    if (!l_node_info) {
        log_it(L_WARNING, "Link prepare error, code %d", a_error_code);
        return;
    }
    pthread_mutex_lock(&l_node_list_request->wait_mutex);
    l_node_list_request->response = a_error_code;
    pthread_cond_signal(&l_node_list_request->wait_cond);
    pthread_mutex_unlock(&l_node_list_request->wait_mutex);
    char l_node_addr_str[INET_ADDRSTRLEN]={ '\0' };
    inet_ntop(AF_INET, &l_node_info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
    log_it(L_WARNING, "Link from  "NODE_ADDR_FP_STR" (%s) prepare error with code %d",
                                NODE_ADDR_FP_ARGS_S(l_node_info->hdr.address), l_node_addr_str, a_error_code);
}
static struct node_link_request *s_node_list_request_init ()
{
    struct node_link_request *l_node_list_request = DAP_NEW_Z(struct node_link_request);
    if(!l_node_list_request){
        return NULL;
    }
    l_node_list_request->worker = dap_events_worker_get_auto();
    l_node_list_request->from_http = true;
    l_node_list_request->response = 0;

    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
#ifdef DAP_OS_DARWIN
    struct timespec ts;
    ts.tv_sec = 10;
    ts.tv_nsec = 10;
    pthread_cond_timedwait_relative_np(&l_node_list_request->wait_cond, &l_node_list_request->wait_mutex,
                                       &ts);
#else
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
    pthread_cond_init(&l_node_list_request->wait_cond, &attr);
    pthread_mutex_init(&l_node_list_request->wait_mutex, NULL);
    return l_node_list_request;
}

static void s_node_list_request_deinit (struct node_link_request *a_node_list_request)
{
    pthread_cond_destroy(&a_node_list_request->wait_cond);
    pthread_mutex_destroy(&a_node_list_request->wait_mutex);
    DAP_DEL_Z(a_node_list_request->link_info);
}
static int dap_chain_net_node_list_wait(struct node_link_request *a_node_list_request, int a_timeout_ms){
    pthread_mutex_lock(&a_node_list_request->wait_mutex);
    if(a_node_list_request->response)
    {
        pthread_mutex_unlock(&a_node_list_request->wait_mutex);
        return a_node_list_request->response;
    }
    struct timespec l_cond_timeout;
    clock_gettime(CLOCK_MONOTONIC, &l_cond_timeout);
    l_cond_timeout.tv_sec += a_timeout_ms/1000;
    while (!a_node_list_request->response) {
        int l_wait = pthread_cond_timedwait(&a_node_list_request->wait_cond, &a_node_list_request->wait_mutex, &l_cond_timeout);
        if (l_wait == ETIMEDOUT) {
            log_it(L_NOTICE, "Waiting for status timeout");
            a_node_list_request->response = ERR_WAIT_TIMEOUT;
            break;
        } else {
            break;
        }
    }
    pthread_mutex_unlock(&a_node_list_request->wait_mutex);
    return a_node_list_request->response;
}

int dap_chain_net_node_list_request (dap_chain_net_t *a_net, dap_chain_node_info_t *a_link_node_request, bool a_sync, int cmd)
{
    enum Cmd {
        ADD,
        UPDATE
    };

    if (!a_net)
        return -1;
    dap_chain_node_info_t *l_link_node_info = NULL;
    char l_node_addr_str[INET_ADDRSTRLEN] = {};
    struct node_link_request *l_node_list_request;
    dap_chain_node_addr_t l_node_addr_cur = {
        .uint64 = dap_chain_net_get_cur_addr_int(a_net)
    };

    uint32_t links_count = 0;
    char *l_request = NULL;
    int ret = -1;
    if(cmd == ADD){ //request to add
        dap_list_t *l_node_list = dap_chain_net_get_node_list_cfg(a_net);

        l_node_list_request = s_node_list_request_init();
        if(!l_node_list_request){
            log_it(L_CRITICAL, "Memory allocation error");
            dap_list_free(l_node_list);
            return -2;
        }
        for (dap_list_t *l_tmp = l_node_list; l_tmp; l_tmp = dap_list_next(l_tmp)) {
            l_link_node_info = (dap_chain_node_info_t *)l_tmp->data;
            if(l_link_node_info->hdr.address.uint64 == l_node_addr_cur.uint64)
                continue;

            if (!l_link_node_info) {
                s_node_list_request_deinit(l_node_list_request);
                dap_list_free(l_node_list);
                log_it(L_ERROR, "Nodelist corrupted");
                return -3;
            }

            inet_ntop(AF_INET, &l_link_node_info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
            log_it(L_DEBUG, "Start node list HTTP request to %s", l_node_addr_str);

            l_node_list_request->net = a_net;
            l_node_list_request->link_info = l_link_node_info;

            l_request = dap_strdup_printf("%s/%s?version=1,method=r,addr=%zu,port=%hu,lcnt=%d,blks=%zu,net=%s",
                                          DAP_UPLINK_PATH_NODE_LIST,
                                          DAP_NODE_LIST_URI_HASH,
                                          a_link_node_request->hdr.address.uint64,
                                          a_link_node_request->hdr.ext_port,
                                          a_link_node_request->hdr.links_number,
                                          a_link_node_request->hdr.blocks_events,
                                          a_net->pub.name);

            if (dap_client_http_request(l_node_list_request->worker,
                                          l_node_addr_str,
                                          l_link_node_info->hdr.ext_port,
                                          "GET",
                                          "text/text",
                                          l_request,
                                          NULL,
                                          0,
                                          NULL,
                                          s_net_node_link_prepare_success,
                                          s_net_node_link_prepare_error,
                                          l_node_list_request,
                                          NULL))
            {
                ret = a_sync ? dap_chain_net_node_list_wait(l_node_list_request, 10000) : ADD_OK;
            }
            DAP_DELETE(l_request);
            if (ret == ADD_OK || ret == ERR_EXISTS) {
                break;
            } else {
                l_node_list_request->response = 0;
                switch (ret)
                {
                case ERR_NO_SERVER:
                    log_it(L_WARNING, "No server");
                    break;
                case ERR_NOT_ADDED:
                    log_it(L_WARNING, "Didn't add your addres node to node list");
                    break;
                case ERR_HASH:
                    log_it(L_WARNING, "Can't calculate hash for your addr");
                    break;
                case ERR_HANDSHAKE:
                    log_it(L_WARNING, "Can't do handshake for your node");
                    break;
                default:
                    log_it(L_WARNING, "Can't process node list HTTP request, error %d", ret);
                    break;
                }
            }
        }
        dap_list_free(l_node_list);
    } else {//request update or delete
        dap_chain_node_info_t *l_link_node_request = dap_chain_node_info_read(a_net, &l_node_addr_cur);
        if(!l_link_node_request )
        {
            log_it(L_WARNING, "There is not node address "NODE_ADDR_FP_STR" in node list",NODE_ADDR_FP_ARGS_S(l_node_addr_cur));
            return -2;
        }

        if (!(l_link_node_info = dap_chain_get_root_addr(a_net, &l_link_node_request->hdr.owner_address)))
        {
            DAP_DEL_Z(l_link_node_request);
            return -3;
        }

        inet_ntop(AF_INET, &l_link_node_info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
        log_it(L_DEBUG, "Start node list HTTP request to %s", l_node_addr_str);
        l_node_list_request = s_node_list_request_init();
        if(!l_node_list_request){
            log_it(L_CRITICAL, "Memory allocation error");
            DAP_DEL_Z(l_link_node_request);
            DAP_DELETE(l_link_node_info);
            return -4;
        }
        l_node_list_request->net = a_net;
        l_node_list_request->link_info = l_link_node_info;

        size_t l_blocks_events = 0;
        dap_chain_t *l_chain;
        DL_FOREACH(a_net->pub.chains, l_chain) {
            if(l_chain->callback_count_atom)
                l_blocks_events += l_chain->callback_count_atom(l_chain);
        }
        l_link_node_request->hdr.blocks_events = l_blocks_events;

        links_count = dap_chain_net_get_downlink_count(a_net);
        l_link_node_request->hdr.links_number = links_count;

        l_request = dap_strdup_printf("%s/%s?version=1,method=r,addr=%zu,port=%hu,lcnt=%d,blks=%zu,net=%s",
                                      DAP_UPLINK_PATH_NODE_LIST,
                                      DAP_NODE_LIST_URI_HASH,
                                      l_link_node_request->hdr.address.uint64,
                                      l_link_node_request->hdr.ext_port,
                                      l_link_node_request->hdr.links_number,
                                      l_link_node_request->hdr.blocks_events,
                                      a_net->pub.name);

        if (dap_client_http_request(l_node_list_request->worker,
                                      l_node_addr_str,
                                      l_link_node_info->hdr.ext_port,
                                      "GET",
                                      "text/text",
                                      l_request,
                                      NULL,
                                      0,
                                      NULL,
                                      s_net_node_link_prepare_success,
                                      s_net_node_link_prepare_error,
                                      l_node_list_request,
                                      NULL))
        {
            ret = a_sync ? dap_chain_net_node_list_wait(l_node_list_request, 10000) : ADD_OK;
        }
        DAP_DELETE(l_request);
        if (ret != ADD_OK && ret != ERR_EXISTS) {
            switch (ret)
            {
            case ERR_NO_SERVER:
                log_it(L_WARNING, "No server");
                break;
            case ERR_NOT_ADDED:
                log_it(L_WARNING, "Didn't add your addres node to node list");
                break;
            case ERR_HASH:
                log_it(L_WARNING, "Can't calculate hash for your addr");
                break;
            case ERR_HANDSHAKE:
                log_it(L_WARNING, "Can't do handshake for your node");
                break;
            default:
                log_it(L_WARNING, "Can't process node list HTTP request, error %d", ret);
                break;
            }
        }
    }
    s_node_list_request_deinit(l_node_list_request);
    return ret;
}

static void s_node_list_callback_notify(dap_global_db_context_t *a_context, dap_store_obj_t *a_obj, void *a_arg)
{
    if (!a_arg || !a_obj || !a_obj->key)
        return;
    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    assert(l_net);

    if (!dap_strcmp(a_obj->group, l_net->pub.gdb_nodes)) {
        if (a_obj->value && a_obj->type == DAP_DB$K_OPTYPE_ADD) {
            dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t *)a_obj->value;
            if(l_node_info->hdr.owner_address.uint64 == 0){
                log_it(L_NOTICE, "Node %s removed, there is not pinners", a_obj->key);
                dap_global_db_del_unsafe(a_context, a_obj->group, a_obj->key);
            } else {
                char l_node_ipv4_str[INET_ADDRSTRLEN]={ '\0' }, l_node_ipv6_str[INET6_ADDRSTRLEN]={ '\0' };
                inet_ntop(AF_INET, &l_node_info->hdr.ext_addr_v4, l_node_ipv4_str, INET_ADDRSTRLEN);
                inet_ntop(AF_INET6, &l_node_info->hdr.ext_addr_v6, l_node_ipv6_str, INET6_ADDRSTRLEN);
                char l_ts[128] = { '\0' };
                dap_gbd_time_to_str_rfc822(l_ts, sizeof(l_ts), a_obj->timestamp);

                log_it(L_MSG, "Add node "NODE_ADDR_FP_STR" %s %u, pinned by "NODE_ADDR_FP_STR" at %s",
                                         NODE_ADDR_FP_ARGS_S(l_node_info->hdr.address),
                                         l_node_ipv4_str, l_node_info->hdr.ext_port,
                                         NODE_ADDR_FP_ARGS_S(l_node_info->hdr.owner_address),
                                         l_ts);
            }
        }
    }
}

int dap_chain_net_node_list_init()
{
    uint16_t l_net_count = 0;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    for (uint16_t i = 0; i < l_net_count; i++) {
        dap_chain_net_add_gdb_notify_callback(l_net_list[i], s_node_list_callback_notify, l_net_list[i]);
    }
    DAP_DELETE(l_net_list);
    return 0;
}

