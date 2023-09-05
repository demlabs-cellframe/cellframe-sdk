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
#include "http_status_code.h"
#include "dap_chain_net_balancer.h"
#include "dap_client.h"
#include "dap_client_http.h"

#define LOG_TAG "dap_chain_net_node_list"

#ifdef DAP_OS_WINDOWS
#define dap_cond_signal(x) SetEvent(x)
#else
#define dap_cond_signal(x) pthread_cond_broadcast(&x)
#endif

/**
 * @brief server function, makes handshake and add node to node list
 *
 * @param dap_http_simple_t *a_http_simple, void *a_arg
 * @return void
 * send value
 * 0 - Node addr successfully added to node list
 * 1 - Don't add this addres to node list
 * 2 - Can't calculate hash for addr
 * 3 - Can't do handshake
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
    l_node_info->hdr.cell_id.uint64 = 0;

    uint8_t response;
    if(dap_chain_net_balancer_handshake(l_node_info,l_net))
        response = 1;
    if(response)
    {
        char *a_key = dap_chain_node_addr_to_hash_str(&l_node_info->hdr.address);
        if(!a_key)
        {
            log_it(L_DEBUG, "Can't calculate hash for addr");
            response = 2;
            DAP_DELETE(l_node_info);
            return;
        }
        size_t l_node_info_size = dap_chain_node_info_get_size(l_node_info);
        bool res = dap_global_db_set_sync(l_net->pub.gdb_nodes, a_key, (uint8_t *) l_node_info, l_node_info_size,
                                     true) == 0;
        if(res)
        {
            char l_node_addr_str[INET_ADDRSTRLEN]={};
            inet_ntop(AF_INET, &l_node_info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
            log_it(L_DEBUG, "Add addres "NODE_ADDR_FP_STR" (%s) to node list",
                       NODE_ADDR_FP_ARGS_S(l_node_info->hdr.address),l_node_addr_str);
            response = 0;
        }
        else
        {
            response = 1;
            log_it(L_DEBUG, "Don't add this addres to node list");
        }
    }
    else
    {
        log_it(L_DEBUG, "Can't do handshake");
        response = 3;
    }
    *l_return_code = Http_Status_OK;
    size_t l_data_send_size = sizeof(uint8_t);
    dap_http_simple_reply(a_http_simple, &response, l_data_send_size);
    DAP_DELETE(l_node_info);
}

static void s_net_node_link_prepare_success(void *a_response, size_t a_response_size, void *a_arg){

    struct node_link_request * l_node_list_request = (struct node_link_request *)a_arg;
    dap_chain_node_info_t *l_node_info = l_node_list_request->link_info;
    l_node_list_request->response = *(uint8_t*)a_response;
    dap_cond_signal(l_node_list_request->wait_cond);
    //DAP_DELETE(l_node_info);
    //DAP_DELETE(l_node_list_request);
}
static void s_net_node_link_prepare_error(int a_error_code, void *a_arg){
    struct node_link_request * l_node_list_request = (struct node_link_request *)a_arg;
    dap_chain_node_info_t *l_node_info = l_node_list_request->link_info;
    char l_node_addr_str[INET_ADDRSTRLEN]={};
    inet_ntop(AF_INET, &l_node_info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
    log_it(L_WARNING, "Link from  "NODE_ADDR_FP_STR" (%s) prepare error with code %d",
                                NODE_ADDR_FP_ARGS_S(l_node_info->hdr.address), l_node_addr_str,a_error_code);
    //DAP_DELETE(l_node_info);
    //DAP_DELETE(l_node_list_request);
}
static struct node_link_request *s_node_list_request_init ()
{
    struct node_link_request *l_node_list_request = DAP_NEW_Z(struct node_link_request);
    if(!l_node_list_request){
        return NULL;
    }
    l_node_list_request->worker = dap_events_worker_get_auto();
    l_node_list_request->from_http = true;
    l_node_list_request->response = 5;//No server

#ifndef _WIN32
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
#ifndef DAP_OS_DARWIN
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
    pthread_cond_init(&l_node_list_request->wait_cond, &attr);
#else
    l_node_list_request->wait_cond = CreateEventA( NULL, FALSE, FALSE, NULL );
#endif
    pthread_mutex_init(&l_node_list_request->wait_mutex, NULL);

    return l_node_list_request;
}

static void s_node_list_request_dinit (struct node_link_request *a_node_list_request)
{
#ifndef _WIN32
    pthread_cond_destroy(&a_node_list_request->wait_cond);
#else
    CloseHandle( a_node_list_request->wait_cond );
#endif
    pthread_mutex_destroy(&a_node_list_request->wait_mutex);
    DAP_DEL_Z(a_node_list_request->link_info);
    DAP_DELETE(a_node_list_request);
}
static int dap_chain_net_node_list_wait(struct node_link_request *a_node_list_request, int a_timeout_ms){

    int ret = -1;
    pthread_mutex_lock(&a_node_list_request->wait_mutex);
    if(a_node_list_request->response)
    {
        pthread_mutex_unlock(&a_node_list_request->wait_mutex);
        return 0;
    }
#ifndef DAP_OS_WINDOWS
    // prepare for signal waiting
    struct timespec l_cond_timeout;
    clock_gettime( CLOCK_MONOTONIC, &l_cond_timeout);
    l_cond_timeout.tv_sec += a_timeout_ms/1000;
    // signal waiting
    while (!a_node_list_request->response) {
        int l_ret_wait = pthread_cond_timedwait(&a_node_list_request->wait_cond, &a_node_list_request->wait_mutex, &l_cond_timeout);
        if(l_ret_wait) {
            ret = a_node_list_request->response ? 0 : -2;
            break;
        }
        else if(l_ret_wait == ETIMEDOUT) { // 110 260
            //log_it(L_NOTICE,"Wait for status is stopped by timeout");
            ret = -1;
            break;
        }else if (l_ret_wait != 0 ){
            char l_errbuf[128];
            l_errbuf[0] = '\0';
            strerror_r(l_ret_wait,l_errbuf,sizeof (l_errbuf));
            log_it(L_ERROR, "Pthread condition timed wait returned \"%s\"(code %d)", l_errbuf, l_ret_wait);
        }
    }
    pthread_mutex_unlock(&a_node_list_request->wait_mutex);
#else
    pthread_mutex_unlock( &a_node_list_request->wait_mutex );
    DWORD wait = WaitForSingleObject( a_node_list_request->wait_cond, (uint32_t)a_timeout_ms);
    if ( wait == WAIT_OBJECT_0 && (
             a_node_list_request->response))
    {
        return a_node_list_request->response ? 0 : -2;
    } else if ( wait == WAIT_TIMEOUT || wait == WAIT_FAILED ) {
        return -1;
    }
#endif
    return ret;
}

int dap_chain_net_node_list_request (dap_chain_net_t *a_net, dap_chain_node_info_t *a_link_node_request)
{
    dap_chain_node_info_t *l_link_node_info = dap_get_balancer_link_from_cfg(a_net);
    if (!l_link_node_info)
        return false;
    char l_node_addr_str[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &l_link_node_info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
    log_it(L_DEBUG, "Start node list HTTP request to %s", l_node_addr_str);
    struct node_link_request *l_node_list_request = s_node_list_request_init();
    if(!l_node_list_request){
        log_it(L_CRITICAL, "Memory allocation error");
        DAP_DELETE(l_link_node_info);
        return false;
    }
    l_node_list_request->net = a_net;
    l_node_list_request->link_info = l_link_node_info;
    //l_node_list_request->link_replace_tries
    int ret = 0;

    char *l_request = dap_strdup_printf("%s/%s?version=1,method=r,addr=%lu,ipv4=%d,port=%hu,net=%s",
                                            DAP_UPLINK_PATH_NODE_LIST,
                                            DAP_NODE_LIST_URI_HASH,
                                            a_link_node_request->hdr.address.uint64,
                                            a_link_node_request->hdr.ext_addr_v4.s_addr,
                                            a_link_node_request->hdr.ext_port,
                                            a_net->pub.name);
    ret = dap_client_http_request(l_node_list_request->worker,
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
                                            NULL) == NULL;

    size_t rc = dap_chain_net_node_list_wait(l_node_list_request, 4000);
    log_it(L_DEBUG, "Stop node list HTTP request to ");
    if(ret || rc){
        s_node_list_request_dinit(l_node_list_request);
        return 4;
    }
    else{
        ret = l_node_list_request->response;        
        s_node_list_request_dinit(l_node_list_request);
        return ret;
    }
}

