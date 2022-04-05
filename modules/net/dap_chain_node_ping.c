/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
//#include <sys/socket.h>
#include <time.h>
#include <errno.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define __USE_GNU   /* See feature_test_macros(7) */
#include <pthread.h>

#include "dap_client.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"
#include "dap_chain_common.h"
#include "dap_chain_node.h"
#include "dap_chain_node_ping.h"

/*
 #include <stdlib.h>
 #include <stdio.h>
 #include <stddef.h>
 #include <stdint.h>
 #include <string.h>
 #include <stdbool.h>
 #include <assert.h>
 #include <ctype.h>
 #include <dirent.h>
 */

#ifdef WIN32
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <wepoll.h>
#else
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
#include <pthread.h>

#include "iputils/iputils.h"

#include "dap_common.h"
//#include "dap_client.h"
#include "dap_strfuncs.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_ping.h"

#define LOG_TAG "chain_node_ping"

static void* node_ping_proc(void *a_arg)
{
    struct in_addr l_addr = {};
    int l_port = 0;
    int l_count;
    if(!a_arg)
        return NULL ;
    memcpy(&l_count, a_arg, sizeof(int));
    memcpy(&l_port, (a_arg + sizeof(int)), sizeof(int));
    memcpy(&l_addr, (a_arg + 2 * sizeof(int)), sizeof(struct in_addr));
    DAP_DELETE(a_arg);

    char *host4 = DAP_NEW_SIZE(char, INET_ADDRSTRLEN);
    struct sockaddr_in sa4 = { .sin_family = AF_INET, .sin_addr = l_addr };
    const char* str_ip4 = inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa4)->sin_addr), host4, INET_ADDRSTRLEN);
    if(!str_ip4){
        DAP_DELETE(host4);
        return NULL ;
    }
    //printf(" %s %d ping start\n", str_ip4, l_count);
    /*
     // send ping
     ping_handle_t *l_ping_handle = ping_handle_create();
     //iputils_set_verbose();
     int res = ping_util(l_ping_handle, str_ip4, l_count);
     DAP_DELETE(l_ping_handle);
     printf(" %s %d ping=%d us\n",str_ip4,l_count,res );
     DAP_DELETE(host4);
     */

    // instead of ping to connect with server and send/recv header
    long res = -1;
    {
        struct timespec l_time_start, l_time_stop;
        struct sockaddr_in l_remote_addr = { 0 };
        //memset(&l_remote_addr, 0, sizeof(l_remote_addr));
        l_remote_addr.sin_family = AF_INET;
        l_remote_addr.sin_port = htons(l_port);
        l_remote_addr.sin_addr = l_addr;

        SOCKET l_socket = socket( PF_INET, SOCK_STREAM, 0);
        if(l_socket == INVALID_SOCKET) {
            log_it(L_ERROR, "Can't create socket");
            DAP_DELETE(host4);
            return (void*) -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &l_time_start);

        if(connect(l_socket, (struct sockaddr *) &l_remote_addr, sizeof(struct sockaddr_in)) != SOCKET_ERROR) {
            size_t l_buf_size = 1024;
            uint8_t l_buf[l_buf_size];

            const char* str_ip4 = inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa4)->sin_addr), host4,
            INET_ADDRSTRLEN);
            char *l_str_to_send = dap_strdup_printf("GET /%s/ping_sub_url HTTP/1.1\r\nHost: %s\r\n\r\n",
            DAP_UPLINK_PATH_ENC_INIT, str_ip4);
            // send data to bad suburl
            int l_send_count = send(l_socket, l_str_to_send, dap_strlen(l_str_to_send), 0);
            long l_recv_count = 0;
            // recv data with error message
            if(l_send_count > 30)
                l_recv_count = s_recv(l_socket, l_buf, l_buf_size, 1000);
            // connect/send/recv was successful
            if(l_recv_count > 20) {
                clock_gettime(CLOCK_MONOTONIC, &l_time_stop);
                res = timespec_diff(&l_time_start, &l_time_stop, NULL);
            }
            DAP_DELETE(l_str_to_send);
        }
        else {
            ; //log_it(L_INFO, "Can't connect to node for ping");
        }
        DAP_DELETE(host4);
        closesocket(l_socket);
    }
    return (void*)(size_t)res;
}

// start sending ping
int start_node_ping(pthread_t *a_thread, struct in_addr a_addr, int a_port, int a_count)
{
    uint8_t *l_data = DAP_NEW_Z_SIZE(uint8_t, sizeof(struct in_addr) + 2 * sizeof(int));
    memcpy(l_data, &a_count, sizeof(int));
    memcpy(l_data + sizeof(int), &a_port, sizeof(int));
    memcpy(l_data + 2 * sizeof(int), &a_addr, sizeof(struct in_addr));
    pthread_create(a_thread, NULL, node_ping_proc, l_data);
    return 0;
}

// wait for ending ping within timeout_ms milliseconds
int wait_node_ping(pthread_t l_thread, int timeout_ms)
{
    int l_ping_time = 0;
    struct timespec l_wait_time;
    clock_gettime(CLOCK_REALTIME, &l_wait_time);

    timeout_ms *= 1000;
    l_wait_time.tv_sec += timeout_ms / DAP_USEC_PER_SEC;
    l_wait_time.tv_nsec += 1000 * (timeout_ms % DAP_USEC_PER_SEC);
#if !defined(_WIN32) && !defined(__ANDROID__) && !defined (DAP_OS_DARWIN)
    int res = pthread_timedjoin_np(l_thread, (void **) &l_ping_time, &l_wait_time);
#else
    int res = pthread_join(l_thread, (void **) &l_ping_time);
#endif
    if(res == ETIMEDOUT) {
        pthread_kill(l_thread, 3); // SIGQUIT SIGABRT
    }
    else if(!res)
        return l_ping_time;
    return -1;
}

static dap_chain_node_addr_t *s_node_addr_tr = NULL, *s_node_addr_ping = NULL;

static void* node_ping_background_proc(void *a_arg)
{
    if (!a_arg)
        return 0;
    dap_chain_net_t *l_net = (dap_chain_net_t*)a_arg;
    dap_list_t *l_node_list = (dap_list_t*)(a_arg + sizeof(dap_chain_net_t*));
    dap_chain_node_addr_t l_node_addr = { 0 };

    // select the nearest node from the list
    unsigned int l_nodes_count = dap_list_length(l_node_list);
    unsigned int l_thread_id = 0;
    pthread_t l_threads[l_nodes_count];
    memset(l_threads, 0, l_nodes_count * sizeof(pthread_t));
    uint64_t l_nodes_addr[l_nodes_count];
    memset(l_nodes_addr, 0, l_nodes_count * sizeof(uint64_t));

    dap_list_t *l_node_list0 = l_node_list;

    int l_min_hops = INT32_MAX;
    int l_min_ping = INT32_MAX;
    // send ping to all nodes
    while(l_node_list) {
        dap_chain_node_addr_t *l_node_addr = l_node_list->data;
        dap_chain_node_info_t *l_node_info = dap_chain_node_info_read(l_net, l_node_addr);

        char *host4 = DAP_NEW_S_SIZE(char, INET_ADDRSTRLEN);
        struct sockaddr_in sa4 = { .sin_family = AF_INET, .sin_addr = l_node_info->hdr.ext_addr_v4 };
        const char* str_ip4 = inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa4)->sin_addr), host4, INET_ADDRSTRLEN);
        if(!str_ip4){
            continue;
        }
        int hops = 0, time_usec = 0;
#ifdef DAP_OS_LINUX
        int res = traceroute_util(str_ip4, &hops, &time_usec);
#endif
        if(l_min_hops>hops) {
            l_min_hops = hops;
            s_node_addr_tr = l_node_list->data;
        }

        // start sending ping
        start_node_ping(&l_threads[l_thread_id], l_node_info->hdr.ext_addr_v4, l_node_info->hdr.ext_port, 1);
        l_nodes_addr[l_thread_id] = l_node_info->hdr.address.uint64;
        l_thread_id++;
        DAP_DELETE(l_node_info);
        l_node_list = dap_list_next(l_node_list);
    }
    // wait for reply from nodes
    int best_node_pos = -1;
    int best_node_reply = INT32_MAX;
    // timeout for all threads
    int l_timeout_full_ms = 3000; // wait max 3 second
    for(l_thread_id = 0; l_thread_id < l_nodes_count; l_thread_id++) {
        if(l_timeout_full_ms < 100)
            l_timeout_full_ms = 100; // make small timeout anyway, may be
        struct timespec l_time_start;
        clock_gettime(CLOCK_MONOTONIC, &l_time_start);
        int res = wait_node_ping(l_threads[l_thread_id], l_timeout_full_ms);
        if(res > 0 && res < best_node_reply) {
            best_node_pos = l_thread_id;
            s_node_addr_ping = l_node_list->data;
            best_node_reply = res;
        }
        struct timespec l_time_stop;
        clock_gettime(CLOCK_MONOTONIC, &l_time_stop);
        l_timeout_full_ms -= timespec_diff(&l_time_start, &l_time_stop, NULL);
        //printf(" thread %x ping=%d\n", l_threads[l_thread_id], res);
    }
    if(best_node_pos > 0) {
        l_node_addr.uint64 = l_nodes_addr[best_node_pos];
    }

    // allocate memory for best node addresses
    dap_chain_node_addr_t *l_node_addr_tmp;
    l_node_addr_tmp = DAP_NEW(dap_chain_node_addr_t);
    memcpy(l_node_addr_tmp, s_node_addr_tr, sizeof(dap_chain_node_addr_t));
    DAP_DELETE(s_node_addr_tr);
    s_node_addr_tr = l_node_addr_tmp;

    l_node_addr_tmp = DAP_NEW(dap_chain_node_addr_t);
    memcpy(l_node_addr_tmp, s_node_addr_ping, sizeof(dap_chain_node_addr_t));
    DAP_DELETE(s_node_addr_ping);
    s_node_addr_ping = l_node_addr_tmp;
    dap_list_free_full(l_node_list0, free);
    return 0;
}

static pthread_t s_thread = 0;

// start background thread for testing connect to the nodes
int dap_chain_node_ping_background_start(dap_chain_net_t *a_net, dap_list_t *a_node_list)
{
    if(!a_node_list)
        return -1;
    // already started
    if(s_thread)
        return 0;
    // copy list
    dap_list_t *l_node_list = NULL;
    dap_list_t *l_node_list_tmp = a_node_list;
    while(l_node_list_tmp) {
        dap_chain_node_addr_t *l_addr = DAP_NEW(dap_chain_node_addr_t);
        memcpy(l_addr, l_node_list_tmp->data, sizeof(dap_chain_node_addr_t));
        l_node_list = dap_list_append(l_node_list, l_addr);
        l_node_list_tmp = dap_list_next(l_node_list_tmp);
    }
    // start searching for better nodes
    uint8_t *l_arg = DAP_NEW_SIZE(uint8_t, sizeof(dap_chain_net_t*) + sizeof(dap_list_t*));
    memcpy(l_arg, &a_net, sizeof(dap_chain_net_t*));
    memcpy(l_arg + sizeof(dap_chain_net_t*), &l_node_list, sizeof(dap_list_t*));
    pthread_create(&s_thread, NULL, node_ping_background_proc, l_arg);
    return 0;
}

const dap_chain_node_addr_t* dap_chain_node_ping_get_node_tr(void)
{
    return s_node_addr_tr;
}

const dap_chain_node_addr_t* dap_chain_node_ping_get_node_ping(void)
{
    return s_node_addr_ping;
}

int dap_chain_node_ping_background_stop(void)
{
    int l_ret = wait_node_ping(s_thread, 500);
    s_thread = 0;
    return l_ret;
}

int dap_chain_node_ping_background_status(void)
{
    if(s_thread)
        return 1;
    return 0;
}
