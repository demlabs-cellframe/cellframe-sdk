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
    DELETED_OK,
    ERR_WAIT_TIMEOUT,
    ERR_UNKNOWN
};

static int s_dap_chain_net_node_list_add(dap_chain_net_t *a_net, dap_chain_node_info_t *a_node_info) {
    return !dap_chain_node_info_save(a_net, a_node_info)
        ? ( log_it( L_DEBUG, "Add address " NODE_ADDR_FP_STR " '%s : %u' to nodelist",
                 NODE_ADDR_FP_ARGS_S(a_node_info->address),
                 a_node_info->ext_host, a_node_info->ext_port ), ADD_OK )
        : ( log_it( L_ERROR, "Address " NODE_ADDR_FP_STR " '%s : %u' not added",
                 NODE_ADDR_FP_ARGS_S(a_node_info->address),
                 a_node_info->ext_host, a_node_info->ext_port ), ERR_NOT_ADDED );
}

static int s_dap_chain_net_node_list_del(dap_chain_net_t *a_net, dap_chain_node_info_t *a_node_info) {
    return !dap_chain_node_info_del(a_net, a_node_info)
        ? ( log_it( L_DEBUG, "Delete address" NODE_ADDR_FP_STR " '%s : %u' from nodelist",
                 NODE_ADDR_FP_ARGS_S(a_node_info->address),
                 a_node_info->ext_host, a_node_info->ext_port ), DELETED_OK )
        : ( log_it( L_ERROR, "Address" NODE_ADDR_FP_STR " '%s : %u' not deleted",
                 NODE_ADDR_FP_ARGS_S(a_node_info->address),
                 a_node_info->ext_host, a_node_info->ext_port ), ERR_UNKNOWN );
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
    http_status_code_t *l_return_code = (http_status_code_t*)a_arg;    
    if ( strcmp(a_http_simple->http_client->url_path, DAP_NODE_LIST_URI_HASH) ) {
        log_it(L_ERROR, "Wrong path '%s' in the request to dap_chain_net_node_list module",
                        a_http_simple->http_client->url_path);
        *l_return_code = Http_Status_BadRequest;
        return;
    }
    int l_protocol_version = 0;
    char l_issue_method = 0;
    uint64_t addr = 0;
    uint16_t port = 0;
    const char l_net_token[] = "net=";
    if ( 4 != sscanf(a_http_simple->http_client->in_query_string, "version=%d,method=%c,addr=%zu,port=%hu,net=",
                                                                  &l_protocol_version, &l_issue_method, &addr, &port) )
    {
        log_it( L_ERROR, "Bad request \"%s\"", a_http_simple->http_client->in_query_string );
        *l_return_code = Http_Status_BadRequest;
        return;
    }
    if (l_protocol_version != 1) {
        log_it(L_ERROR, "Unsupported protocol version/method in the request to dap_chain_net_node_list module");
        *l_return_code = Http_Status_MethodNotAllowed;
        return;
    }
    char *l_key = dap_chain_node_addr_to_str_static( &(dap_chain_node_addr_t){.uint64 = addr} );
    if (!l_key) {
        log_it(L_ERROR, "Bad node address %zu", addr);
        *l_return_code = Http_Status_BadRequest;
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
    dap_chain_node_info_t *l_node_info;
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
    uint8_t l_response = ERR_UNKNOWN;
    switch (l_issue_method) {
    case 'a': {
        uint8_t l_host_size = dap_min(INET6_ADDRSTRLEN, (int)dap_strlen(a_http_simple->es_hostaddr) + 1);
        l_node_info = DAP_NEW_STACK_SIZE(dap_chain_node_info_t, sizeof(dap_chain_node_info_t) + l_host_size);
        *l_node_info = (dap_chain_node_info_t) {
            .address.uint64 = addr,
            .ext_port = port,
            .ext_host_len = dap_strncpy(l_node_info->ext_host, a_http_simple->es_hostaddr, l_host_size) - l_node_info->ext_host
        };
        l_response = !dap_chain_net_balancer_handshake(l_node_info, l_net)
            ? s_dap_chain_net_node_list_add(l_net, l_node_info)
            : ( log_it(L_DEBUG, "Can't do handshake with %s [ %s : %u ]", l_key, l_node_info->ext_host, l_node_info->ext_port),
            ERR_HANDSHAKE );
        *l_return_code = Http_Status_OK;
    } break;

    case 'r': {
        if ( !(l_node_info = (dap_chain_node_info_t*)dap_global_db_get_sync(l_net->pub.gdb_nodes, l_key, NULL, NULL, NULL)) ) {
            log_it(L_DEBUG,"Address %s is not present in nodelist", l_key);
            l_response = ERR_NOT_ADDED;
        } else {
            if ( dap_strcmp(l_node_info->ext_host, a_http_simple->es_hostaddr) ) {
                l_response = ERR_NOT_PINNER;
                *l_return_code = Http_Status_Forbidden;
            } else {
                l_response = !dap_global_db_del_sync(l_net->pub.gdb_nodes, l_key)
                    ? ( log_it(L_DEBUG, "Node %s successfully deleted from nodelist", l_key),
                    DELETED_OK )
                    : ( log_it(L_DEBUG, "Can't delete node %s from nodelist", l_key),
                    ERR_EXISTS );
                *l_return_code = Http_Status_OK;
            }
            DAP_DELETE(l_node_info);
        }
    } break;

    default:
        log_it(L_ERROR, "Unsupported protocol version/method in the request to dap_chain_net_node_list module");
        *l_return_code = Http_Status_MethodNotAllowed;
        return;
    }
    
    dap_http_simple_reply(a_http_simple, &l_response, sizeof(uint8_t));
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
    log_it(L_WARNING, "Link from  "NODE_ADDR_FP_STR" [ %s : %u ] prepare error with code %d",
           NODE_ADDR_FP_ARGS_S(l_node_info->address), l_node_info->ext_host,
           l_node_info->ext_port, a_error_code);
}
static struct node_link_request *s_node_list_request_init ()
{
    struct node_link_request *l_node_list_request = DAP_NEW_Z(struct node_link_request);
    if(!l_node_list_request){
        return NULL;
    }
    l_node_list_request->worker = dap_events_worker_get_auto();
    l_node_list_request->response = 0;

    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
#ifdef DAP_OS_DARWIN
    struct timespec ts;
    ts.tv_sec = 8;
    ts.tv_nsec = 0;
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

static int s_cb_node_addr_compare(dap_list_t *a_list_elem, dap_list_t *a_addr_elem) {
    dap_chain_node_info_t *l_link_node_info = (dap_chain_node_info_t*)a_list_elem->data;
    dap_chain_node_addr_t *l_addr = (dap_chain_node_addr_t*)a_addr_elem->data;
    return l_addr->uint64 != l_link_node_info->address.uint64;
}

int dap_chain_net_node_list_request (dap_chain_net_t *a_net, UNUSED_ARG const char *a_addr, uint16_t a_port, bool a_sync, char a_cmd)
{
    if (!a_net)
        return -1;
    
    uint16_t l_seeds_count = 0, i;
    dap_chain_node_info_t   **l_seed_nodes = dap_chain_net_get_seed_nodes(a_net, &l_seeds_count),
                            *l_my_node = dap_chain_net_get_my_node_info(a_net);
    if (!l_seed_nodes) {
        log_it(L_ERROR, "No servers available to make request. Check network config for seed nodes presence");
    }
    
    dap_chain_node_addr_t l_node_addr_cur = {
        .uint64 = dap_chain_net_get_cur_addr_int(a_net)
    };

    /*a_node_info->info.atoms_count = 0;
    dap_chain_t *l_chain; DL_FOREACH(a_net->pub.chains, l_chain) {
        if(l_chain->callback_count_atom)
            a_node_info->info.atoms_count += l_chain->callback_count_atom(l_chain);
    }
    a_node_info->info.links_number = 0; */ // TODO: dap_chain_net_get_downlink_count(a_net);
    
    for (i = 0; i < l_seeds_count; ++i) {
        if ( l_seed_nodes[i] == l_my_node )
            // We're in seed list, add directly
            return s_dap_chain_net_node_list_add( a_net, l_my_node );
    }

    struct node_link_request *l_link_node_request = s_node_list_request_init();
    if (!l_link_node_request) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -4;
    };

    char *l_request = dap_strdup_printf( "%s/%s?version=1,method=%c,addr=%zu,port=%hu,net=%s",
                                         DAP_UPLINK_PATH_NODE_LIST, DAP_NODE_LIST_URI_HASH, a_cmd,
                                         l_node_addr_cur.uint64, a_port, a_net->pub.name );
    int l_ret = -1;
    for (i = 0; i < l_seeds_count; ++i) {
        dap_chain_node_info_t *l_remote = (dap_chain_node_info_t*)l_seed_nodes[i];
        if ( dap_client_http_request(l_link_node_request->worker, l_remote->ext_host, l_remote->ext_port,
                                    "GET", "text/text", l_request, NULL, 0, NULL,
                                    s_net_node_link_prepare_success, s_net_node_link_prepare_error,
                                    l_link_node_request, NULL) )
        {
            l_ret = a_sync ? dap_chain_net_node_list_wait(l_link_node_request, 8000) : ADD_OK;
        }
        if (l_ret == ADD_OK || l_ret == ERR_EXISTS || l_ret == DELETED_OK)
            break;
        else {
            l_link_node_request->response = 0;
            switch (l_ret) {
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
                log_it(L_WARNING, "Can't process node list HTTP request, error %d", l_ret);
                break;
            }
        }
    }
    DAP_DELETE(l_request);
    s_node_list_request_deinit(l_link_node_request);
    return l_ret;
}

int dap_chain_net_node_list_init()
{
    /*for (dap_chain_net_t *it = dap_chain_net_iter_start(); it; it = dap_chain_net_iter_next(it)) {
        dap_chain_net_add_nodelist_notify_callback(it, s_node_list_callback_notify, it);
    }*/
    return 0;
}

/*static int node_info_del_with_reply(dap_chain_net_t *a_net, dap_chain_node_info_t *a_node_info, const char *alias_str,
        void **a_str_reply)
{
    int l_res = -1;
    if ( !a_node_info->address.uint64 && !alias_str ) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "addr not found");
        return l_res;
    }
    // find addr by alias or addr_str
    dap_chain_node_addr_t *l_addr_by_alias = dap_chain_node_alias_find(a_net, alias_str);
    if ( alias_str && !l_addr_by_alias ) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "alias not found");
        return l_res;
    }
    dap_chain_node_addr_t l_addr = l_addr_by_alias ? *l_addr_by_alias : a_node_info->address;
    char *a_key = dap_chain_node_addr_to_str_static(&l_addr);
    if ( !(l_res = dap_global_db_del_sync(a_net->pub.gdb_nodes, a_key)) ) {
        dap_list_t *list_aliases = get_aliases_by_name(a_net, &l_addr), *l_el = list_aliases;
        while (l_el) {
            dap_chain_node_alias_delete(a_net, (const char*)l_el->data);
            l_el = l_el->next;
        }
        dap_list_free_full(list_aliases, NULL);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Node deleted with all it's aliases");
    } else {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Node was not deleted from database");
    }
    DAP_DELETE(l_addr_by_alias);
    return l_res;
}*/
