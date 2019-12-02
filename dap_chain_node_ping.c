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

#include "dap_common.h"
#include "dap_client.h"
#include "dap_strfuncs.h"
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
#endif

#include <pthread.h>

#include "dap_common.h"
//#include "dap_client.h"
#include "dap_strfuncs.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_ping.h"

#define LOG_TAG "chain_node_ping"

static void* node_ping_proc(void *a_arg)
{
    struct in_addr l_addr = { 0 };
    int l_port = 0;
    int l_count;
    if(!a_arg)
        return NULL;
    memcpy(&l_count, a_arg, sizeof(int));
    memcpy(&l_port, (a_arg + sizeof(int)), sizeof(int));
    memcpy(&l_addr, (a_arg + 2 * sizeof(int)), sizeof(struct in_addr));
    DAP_DELETE(a_arg);

    char *host4 = DAP_NEW_SIZE(char, INET_ADDRSTRLEN);
    struct sockaddr_in sa4 = { .sin_family = AF_INET, .sin_addr = l_addr };
    const char* str_ip4 = inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa4)->sin_addr), host4, INET_ADDRSTRLEN);
    if(!str_ip4)
        return NULL;
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
        else{
            ;//log_it(L_INFO, "Can't connect to node for ping");
        }
        closesocket(l_socket);
    }
    return (void*) res;
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

    int res = pthread_timedjoin_np(l_thread, (void **) &l_ping_time, &l_wait_time);
    if(res == ETIMEDOUT) {
        pthread_kill(l_thread, 3); // SIGQUIT SIGABRT
    }
    else if(!res)
        return l_ping_time;
    return -1;
}
