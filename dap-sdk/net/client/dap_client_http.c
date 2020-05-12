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

#ifdef WIN32
// for Windows
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#else
// for Unix-like systems
#include <sys/types.h>
#include <sys/socket.h>
//#include <bits/socket_type.h>
#endif
#include <unistd.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_events_socket.h"
#include "dap_stream_ch_proc.h"
#include "dap_server.h"
#include "dap_client.h"
#include "dap_client_pvt.h"
#include "dap_client_http.h"

#define LOG_TAG "dap_client_http"

#define DAP_CLIENT_HTTP_RESPONSE_SIZE_MAX 65536 //40960

typedef struct dap_http_client_internal {

    dap_client_http_callback_data_t response_callback;
    dap_client_http_callback_error_t error_callback;

    void *obj; // dap_client_pvt_t *client_pvt;
    uint8_t *request;
    size_t request_size;
    size_t request_sent_size;

    int socket;

    bool is_header_read;
    size_t header_length;
    size_t content_length;

    uint8_t *response;
    size_t response_size;
    size_t response_size_max;

} dap_client_http_internal_t;

#define DAP_CLIENT_HTTP(a) (a ? (dap_client_http_internal_t *) (a)->_inheritor : NULL)

/**
 * @brief s_http_new
 * @param a_es
 * @param arg
 */
static void s_http_new(dap_events_socket_t * a_es, void * arg)
{
    UNUSED(arg);
    log_it(L_DEBUG, "HTTP client connected");
    dap_client_http_internal_t * l_client_http_internal = DAP_CLIENT_HTTP(a_es);
    if(!l_client_http_internal) {
        log_it(L_ERROR, "s_http_new: l_client_http_internal is NULL!");
        return;
    }
    l_client_http_internal->header_length = 0;
    l_client_http_internal->content_length = 0;
    l_client_http_internal->response_size = 0;
    l_client_http_internal->response_size_max = DAP_CLIENT_HTTP_RESPONSE_SIZE_MAX;
    l_client_http_internal->response = (uint8_t*) DAP_NEW_Z_SIZE(uint8_t, DAP_CLIENT_HTTP_RESPONSE_SIZE_MAX);
}

/**
 * @brief s_http_stream_write
 * @param a_es
 * @param arg
 */
static void s_http_write(dap_events_socket_t * a_es, void * arg)
{
    UNUSED(a_es);
    UNUSED(arg);
//    log_it(L_DEBUG, "s_http_write ");
//    dap_client_http_internal_t * l_client_http_internal = DAP_CLIENT_HTTP(a_es);
//    if(!l_client_internal) {
//        log_it(L_ERROR, "s_http_write: l_client_http_internal is NULL!");
//        return;
//    }

    //bool ready_to_write = false;
    //dap_events_socket_set_writable(a_es, ready_to_write);
}

/**
 * @brief s_http_stream_read
 * @param a_es
 * @param arg
 */
static void s_http_read(dap_events_socket_t * a_es, void * arg)
{
//    log_it(L_DEBUG, "s_http_read ");
    dap_client_http_internal_t * l_client_http_internal = DAP_CLIENT_HTTP(a_es);
    if(!l_client_http_internal) {
        log_it(L_ERROR, "s_http_read: l_client_http_internal is NULL!");
        return;
    }
    // read data
    l_client_http_internal->response_size += dap_events_socket_read(a_es,
            l_client_http_internal->response + l_client_http_internal->response_size,
            l_client_http_internal->response_size_max - l_client_http_internal->response_size);

    // if buffer is overfull then read once more
    if(l_client_http_internal->response_size >= DAP_CLIENT_HTTP_RESPONSE_SIZE_MAX) {
        log_it(L_ERROR, "s_http_read response_size(%d) overfull!!!", l_client_http_internal->response_size);
    }

    // search http header
    if(!l_client_http_internal->is_header_read && l_client_http_internal->response_size > 4
            && !l_client_http_internal->content_length) {
        for(size_t l_pos = 0; l_pos < l_client_http_internal->response_size - 4; l_pos++) {
            uint8_t *l_str = l_client_http_internal->response + l_pos;
            if(!dap_strncmp((const char*) l_str, "\r\n\r\n", 4)) {
                l_client_http_internal->header_length = l_pos + 4;
                l_client_http_internal->is_header_read = true;
                //dap_events_socket_shrink_buf_in(a_es, l_client_internal->header_size);
                break;
            }
        }
    }
    // process http header
    if(l_client_http_internal->is_header_read) {
        l_client_http_internal->response[l_client_http_internal->header_length - 1] = 0;
        // search strings in header
        char **l_strings = dap_strsplit((char*) l_client_http_internal->response, "\r\n", -1);
        if(l_strings) {
            int i = 0;
            while(l_strings[i]) {
                char *l_string = l_strings[i];
                char **l_values = dap_strsplit(l_string, ":", 2);
                if(l_values && l_values[0] && l_values[1])
                    if(!dap_strcmp("Content-Length", l_values[0])) {
                        l_client_http_internal->content_length = atoi(l_values[1]);
                        l_client_http_internal->is_header_read = false;
                    }
                dap_strfreev(l_values);
                if(l_client_http_internal->content_length)
                    break;
                i++;
            }
            dap_strfreev(l_strings);
        }

        // restore last symbol
        l_client_http_internal->response[l_client_http_internal->header_length - 1] = '\n';
    }

    // process data
    if(l_client_http_internal->content_length) {
        l_client_http_internal->is_header_read = false;
        /* debug
         if(l_client_internal->content_length != (l_client_internal->response_size - l_client_internal->header_length)) {
         log_it(L_DEBUG, "s_http_read error!!! content_length(%d)!=response_size-header_size(%d)=%d",
         l_client_internal->content_length, l_client_internal->header_length,
         l_client_internal->response_size - l_client_internal->header_length);
         }*/

        // received not enough data
        if(l_client_http_internal->content_length
                > (l_client_http_internal->response_size - l_client_http_internal->header_length)) {
            return;
        }
        // process data
        if(l_client_http_internal->response_callback)
            l_client_http_internal->response_callback(
                    l_client_http_internal->response + l_client_http_internal->header_length,
                    l_client_http_internal->content_length, //l_client_internal->response_size - l_client_internal->header_size,
                    l_client_http_internal->obj);
        l_client_http_internal->response_size -= l_client_http_internal->header_length;
        l_client_http_internal->response_size -= l_client_http_internal->content_length;
        l_client_http_internal->header_length = 0;
        l_client_http_internal->content_length = 0;
        // if the data remains, then read once more
        if(l_client_http_internal->response_size > 0) {
            s_http_read(a_es, arg);
        }
        else {
            // close connection
            dap_events_socket_kill_socket(a_es);
            //dap_events_socket_remove_and_delete(a_es, true); //dap_events_socket_delete(a_es, true);
        }
    }
}

/**
 * @brief s_http_stream_error
 * @param a_es
 * @param arg
 */
static void s_http_error(dap_events_socket_t * a_es, void * arg)
{
    log_it(L_INFO, "http client error");
    dap_client_http_internal_t * l_client_http_internal = DAP_CLIENT_HTTP(a_es);
    if(!l_client_http_internal) {
        log_it(L_ERROR, "s_http_write: l_client_http_internal is NULL!");
        return;
    }
    if(l_client_http_internal->error_callback)
        l_client_http_internal->error_callback((int)arg, l_client_http_internal->obj);

    // close connection
    dap_events_socket_kill_socket(a_es);
    //dap_events_socket_remove_and_delete(a_es, true);
    //dap_events_thread_wake_up( &a_es->events->proc_thread);
    //dap_events_socket_delete(a_es, false);
    //a_es->no_close = false;
}

/**
 * @brief s_http_delete
 * @param a_es
 * @param arg
 */
static void s_http_delete(dap_events_socket_t *a_es, void *arg)
{
    UNUSED(arg);
    // call from dap_events_socket_delete(ev_socket, true);
    log_it(L_DEBUG, "HTTP client disconnected");
    dap_client_http_internal_t * l_client_http_internal = DAP_CLIENT_HTTP(a_es);
    if(!l_client_http_internal) {
        log_it(L_ERROR, "s_http_write: l_client_http_internal is NULL!");
        return;
    }
    //close(l_client_http_internal->socket);
    //l_client_http_internal->socket = 0;

    DAP_DELETE(l_client_http_internal->response);
    l_client_http_internal->response = NULL;

    DAP_DELETE(l_client_http_internal);
    a_es->_inheritor = NULL;
}

/**
 * @brief resolve_host
 * @param a_host hostname
 * @param ai_family AF_INET  for ipv4 or AF_INET6 for ipv6
 * @param a_addr_out out addr (struct in_addr or struct in6_addr)
 * @param return 0 of OK, <0 Error
 */
int resolve_host(const char *a_host, int ai_family, struct sockaddr *a_addr_out)
{
    struct addrinfo l_hints, *l_res;
    void *l_cur_addr = NULL;

    memset(&l_hints, 0, sizeof(l_hints));
    l_hints.ai_family = PF_UNSPEC;
    l_hints.ai_socktype = SOCK_STREAM;
    l_hints.ai_flags |= AI_CANONNAME;

    int errcode = getaddrinfo(a_host, NULL, &l_hints, &l_res);
    if(errcode != 0)
            {
        return -2;
    }
    while(l_res)
    {
        if(ai_family == l_res->ai_family)
            switch (l_res->ai_family)
            {
            case AF_INET:
                l_cur_addr = &((struct sockaddr_in *) l_res->ai_addr)->sin_addr;
                memcpy(a_addr_out, l_cur_addr, sizeof(struct in_addr));
                break;
            case AF_INET6:
                l_cur_addr = &((struct sockaddr_in6 *) l_res->ai_addr)->sin6_addr;
                memcpy(a_addr_out, l_cur_addr, sizeof(struct in6_addr));
                break;
            }
        if(l_cur_addr) {
            freeaddrinfo(l_res);
            return 0;
        }
        l_res = l_res->ai_next;
    }
    freeaddrinfo(l_res);
    return -1;
}

/**
 * @brief dap_client_http_request_custom
 * @param a_uplink_addr
 * @param a_uplink_port
 * @param a_method GET or POST
 * @param a_request_content_type like "text/text"
 * @param a_path
 * @param a_request
 * @param a_request_size
 * @param a_cookie
 * @param a_response_callback
 * @param a_error_callback
 * @param a_obj
 * @param a_custom
 * @param a_custom_count
 */
void* dap_client_http_request_custom(const char *a_uplink_addr, uint16_t a_uplink_port, const char *a_method,
        const char *a_request_content_type, const char * a_path, void *a_request, size_t a_request_size, char *a_cookie,
        dap_client_http_callback_data_t a_response_callback, dap_client_http_callback_error_t a_error_callback,
        void *a_obj, char **a_custom, size_t a_custom_count)
{
    //log_it(L_DEBUG, "HTTP request on url '%s:%d'", a_uplink_addr, a_uplink_port);
    static dap_events_socket_callbacks_t l_s_callbacks = {
        .new_callback = s_http_new,
        .read_callback = s_http_read,
        .write_callback = s_http_write,
        .error_callback = s_http_error,
        .delete_callback = s_http_delete
    };

    // create socket
    int l_socket = socket( PF_INET, SOCK_STREAM, 0);
    // set socket param
    int buffsize = DAP_CLIENT_HTTP_RESPONSE_SIZE_MAX;
#ifdef _WIN32
      setsockopt((SOCKET)l_socket, SOL_SOCKET, SO_SNDBUF, (char *)&buffsize, sizeof(int) );
      setsockopt((SOCKET)l_socket, SOL_SOCKET, SO_RCVBUF, (char *)&buffsize, sizeof(int) );
#else
    setsockopt(l_socket, SOL_SOCKET, SO_SNDBUF, (void*) &buffsize, sizeof(buffsize));
    setsockopt(l_socket, SOL_SOCKET, SO_RCVBUF, (void*) &buffsize, sizeof(buffsize));
#endif
    dap_events_socket_t *l_ev_socket = dap_events_socket_wrap_no_add(NULL, l_socket, &l_s_callbacks);

    // create private struct
    dap_client_http_internal_t *l_client_http_internal = DAP_NEW_Z(dap_client_http_internal_t);
    l_ev_socket->_inheritor = l_client_http_internal;
    l_client_http_internal->error_callback = a_error_callback;
    l_client_http_internal->response_callback = a_response_callback;
    //l_client_http_internal->socket = l_socket;
    l_client_http_internal->obj = a_obj;

    struct sockaddr_in l_remote_addr;
    memset(&l_remote_addr, 0, sizeof(l_remote_addr));
    // get struct in_addr from ip_str
    inet_pton(AF_INET, a_uplink_addr, &(l_remote_addr.sin_addr));
    //Resolve addr if
    if(!l_remote_addr.sin_addr.s_addr) {
        if(resolve_host(a_uplink_addr, AF_INET, (struct sockaddr*) &l_remote_addr.sin_addr) < 0) {
            log_it(L_ERROR, "Wrong remote address '%s:%u'", a_uplink_addr, a_uplink_port);
            dap_events_socket_kill_socket(l_ev_socket);
            return NULL;
        }
    }
    // connect
    l_remote_addr.sin_family = AF_INET;
    l_remote_addr.sin_port = htons(a_uplink_port);
    int l_err = 0;
    if((l_err = connect(l_socket, (struct sockaddr *) &l_remote_addr, sizeof(struct sockaddr_in))) != -1) {
        //s_set_sock_nonblock(a_client_pvt->stream_socket, false);
        log_it(L_INFO, "Remote address connected (%s:%u) with sock_id %d", a_uplink_addr, a_uplink_port, l_socket);
        // add to dap_worker
        dap_events_socket_create_after(l_ev_socket);
    }
    else {
        log_it(L_ERROR, "Remote address can't connected (%s:%u) with sock_id %d err=%d", a_uplink_addr, a_uplink_port,
                l_socket, errno);
        //l_ev_socket->no_close = false;
        dap_events_socket_kill_socket(l_ev_socket);
        //shutdown(l_ev_socket->socket, SHUT_RDWR);
        //dap_events_socket_remove_and_delete(l_ev_socket, true);
        //l_ev_socket->socket = 0;
        return NULL ;
    }

    //dap_client_pvt_t * l_client_pvt = (dap_client_pvt_t*) a_obj;
    //dap_events_new();
    dap_string_t *l_request_headers = dap_string_new(NULL);

    if(a_request && (dap_strcmp(a_method, "POST") == 0 || dap_strcmp(a_method, "POST_ENC") == 0)) {
        char l_buf[1024];
        //log_it(L_DEBUG, "POST request with %u bytes of decoded data", a_request_size);

        if(a_request_content_type) {
            dap_snprintf(l_buf, sizeof(l_buf), "Content-Type: %s\r\n", a_request_content_type);
            l_request_headers = dap_string_append(l_request_headers, l_buf);
        }

        if(a_custom) {
            for( size_t i = 0; i < a_custom_count; i++) {
                l_request_headers = dap_string_append(l_request_headers, (char*) a_custom[i]);
                l_request_headers = dap_string_append(l_request_headers, "\r\n");
            }
        }

        if(a_cookie) {
            dap_snprintf(l_buf, sizeof(l_buf), "Cookie: %s\r\n", a_cookie);
            l_request_headers = dap_string_append(l_request_headers, l_buf);
        }

        dap_snprintf(l_buf, sizeof(l_buf), "Content-Length: %lu\r\n", a_request_size);
        l_request_headers = dap_string_append(l_request_headers, l_buf);
    }

    // adding string for GET request
    char *l_get_str = NULL;
    if(!dap_strcmp(a_method, "GET")) {
        char l_buf[1024];
        dap_snprintf(l_buf, sizeof(l_buf), "User-Agent: Mozilla\r\n");
        if(a_cookie) {
            dap_snprintf(l_buf, sizeof(l_buf), "Cookie: %s\r\n", a_cookie);
            l_request_headers = dap_string_append(l_request_headers, l_buf);
        }

        if(a_request)
            l_get_str = dap_strdup_printf("?%s", a_request);
    }

    // send header
    dap_events_socket_write_f(l_ev_socket, "%s /%s%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "%s"
            "\r\n",
            a_method, a_path, l_get_str ? l_get_str : "", a_uplink_addr, l_request_headers->str);
    // send data for POST request
    if(!l_get_str)
        dap_events_socket_write(l_ev_socket, a_request, a_request_size);
    dap_events_socket_set_writable(l_ev_socket, true);

    DAP_DELETE(l_get_str);
    dap_string_free(l_request_headers, true);
    return l_client_http_internal;
}

/**
 * @brief dap_client_http_request
 * @param a_uplink_addr
 * @param a_uplink_port
 * @param a_method GET or POST
 * @param a_request_content_type like "text/text"
 * @param a_path
 * @param a_request
 * @param a_request_size
 * @param a_cookie
 * @param a_response_callback
 * @param a_error_callback
 * @param a_obj
 * @param a_custom
 */
void* dap_client_http_request(const char *a_uplink_addr, uint16_t a_uplink_port, const char * a_method,
        const char* a_request_content_type, const char * a_path, void *a_request, size_t a_request_size,
        char * a_cookie, dap_client_http_callback_data_t a_response_callback,
        dap_client_http_callback_error_t a_error_callback, void *a_obj, void * a_custom)
{
    char *a_custom_new[1];
    size_t a_custom_count = 0;
    // use no more then one custom item only
    a_custom_new[0] = (char*) a_custom;
    if(a_custom)
        a_custom_count = 1;

    return dap_client_http_request_custom(a_uplink_addr, a_uplink_port, a_method, a_request_content_type, a_path,
            a_request, a_request_size, a_cookie, a_response_callback, a_error_callback, a_obj,
            a_custom_new, a_custom_count);
}
