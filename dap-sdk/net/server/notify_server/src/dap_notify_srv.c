/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2021
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef DAP_OS_UNIX
#include <sys/socket.h>
#include <sys/un.h>
#elif DAP_OS_WINDOWS
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_events_socket.h"
#include "dap_notify_srv.h"

dap_events_socket_t * s_notify_server = NULL;
dap_events_socket_t * s_notify_server_queue = NULL;
static void s_notify_server_accept(dap_events_socket_t * a_es, int a_remote_socket, struct sockaddr* a_remote_addr );
static void s_notify_server_inter_queue(dap_events_socket_t * a_es, void * a_arg);

/**
 * @brief dap_notify_server_init
 * @param a_notify_socket_path
 * @return
 */
int dap_notify_server_init(const char * a_notify_socket_path)
{
    dap_events_socket_callbacks_t l_callbacks={0};
    l_callbacks.accept_callback = s_notify_server_accept;
    s_notify_server = dap_events_socket_create(DESCRIPTOR_TYPE_SOCKET_LOCAL_LISTENING,&l_callbacks );
    if (!s_notify_server)
        return -1;

#ifdef DAP_OS_UNIX
    struct sockaddr_un l_sock_un={0};
    l_sock_un.sun_family = AF_LOCAL;
    strncpy(l_sock_un.sun_path, a_notify_socket_path, sizeof(l_sock_un.sun_path) - 1);
#endif

    return 0;
}

/**
 * @brief dap_notify_server_deinit
 */
void dap_notify_server_deinit()
{

}

/**
 * @brief dap_notify_server_create_inter
 * @return
 */
struct dap_events_socket * dap_notify_server_create_inter()
{
    return NULL;
}

/**
 * @brief dap_notify_server_send_fmt_inter
 * @param a_input
 * @param a_format
 * @return
 */
int dap_notify_server_send_f_inter(struct dap_events_socket * a_input, const char * a_format,...)
{
    va_list va;
    va_start(va, a_format);
    size_t l_str_size=dap_vsnprintf(NULL,0,a_format,va);
    char * l_str = DAP_NEW_SIZE(char,l_str_size+1);
    dap_vsnprintf(l_str,l_str_size+1,a_format,va);
    return dap_events_socket_queue_ptr_send_to_input(a_input,l_str);
}

/**
 * @brief dap_notify_server_send_fmt_mt
 * @param a_format
 * @return
 */
int dap_notify_server_send_f_mt(const char * a_format,...)
{
    return -1;
}

/**
 * @brief s_notify_server_accept
 * @param a_es
 * @param a_remote_socket
 * @param a_remote_addr
 */
static void s_notify_server_accept(dap_events_socket_t * a_es, int a_remote_socket, struct sockaddr* a_remote_addr )
{

}

/**
 * @brief s_notify_server_inter_queue
 * @param a_es
 * @param a_arg
 */
static void s_notify_server_inter_queue(dap_events_socket_t * a_es, void * a_arg)
{

}
