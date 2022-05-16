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


#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "dap_net.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_events_socket.h"
#include "dap_timerfd.h"
#include "dap_stream_ch_proc.h"
#include "dap_server.h"
#include "dap_client.h"
#include "dap_client_pvt.h"
#include "dap_client_http.h"
#include "dap_enc_base64.h"
#ifndef DAP_NET_CLIENT_NO_SSL
#include <wolfssl/options.h>
#include "wolfssl/ssl.h"
#endif

#define LOG_TAG "dap_client_http"

#define DAP_CLIENT_HTTP_RESPONSE_SIZE_MAX 65536 //40960

typedef struct dap_http_client_internal {

    dap_client_http_callback_data_t response_callback;
    dap_client_http_callback_error_t error_callback;
    dap_client_http_callback_error_ext_t error_ext_callback;

    void *obj; // dap_client_pvt_t *client_pvt;
    byte_t *request;
    size_t request_size;
    size_t request_sent_size;
    bool is_over_ssl;

    int socket;

    bool is_header_read;
    bool is_closed_by_timeout;
    bool were_callbacks_called;
    size_t header_length;
    size_t content_length;
    time_t ts_last_read;
    uint8_t *response;
    size_t response_size;
    size_t response_size_max;

    // Request args
    char *uplink_addr;
    uint16_t uplink_port;
    char *method;
    char *request_content_type;
    char * path;
    char *cookie;
    char *request_custom_headers; // Custom headers

    // Request vars
    dap_worker_t * worker;

} dap_client_http_pvt_t;

#define PVT(a) (a ? (dap_client_http_pvt_t *) (a)->_inheritor : NULL)

static void s_http_connected(dap_events_socket_t * a_esocket); // Connected
#ifndef DAP_NET_CLIENT_NO_SSL
static void s_http_ssl_connected(dap_events_socket_t * a_esocket); // connected SSL callback
#endif
static void s_client_http_delete(dap_client_http_pvt_t * a_http_pvt);
static void s_http_read(dap_events_socket_t * a_es, void * arg);
static void s_http_error(dap_events_socket_t * a_es, int a_arg);
static bool s_timer_timeout_check(void * a_arg);
static bool s_timer_timeout_after_connected_check(void * a_arg);


static bool s_debug_more=false;
static uint64_t s_client_timeout_ms                     = 20000;
static uint64_t s_client_timeout_read_after_connect_ms       = 5000;
static uint32_t s_max_attempts = 5;

#ifndef DAP_NET_CLIENT_NO_SSL
static WOLFSSL_CTX *s_ctx;
#endif

/**
 * @brief dap_client_http_init
 * @return
 */
int dap_client_http_init()
{
    s_debug_more = dap_config_get_item_bool_default(g_config,"dap_client","debug_more",false);
    s_max_attempts = dap_config_get_item_uint32_default(g_config,"dap_client","max_tries",5);
    s_client_timeout_ms = dap_config_get_item_uint32_default(g_config,"dap_client","timeout",10)*1000;
    s_client_timeout_read_after_connect_ms = (time_t) dap_config_get_item_uint64_default(g_config,"dap_client","timeout_read_after_connect",5)*1000;
#ifndef DAP_NET_CLIENT_NO_SSL
    wolfSSL_Init();
    wolfSSL_Debugging_ON ();
    if ((s_ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL)
        return -1;
    const char *l_ssl_cert_path = dap_config_get_item_str(g_config, "dap_client", "ssl_cert_path");
    if (l_ssl_cert_path) {
        if (wolfSSL_CTX_load_verify_locations(s_ctx, l_ssl_cert_path, 0) != SSL_SUCCESS)
        return -2;
    } else
        wolfSSL_CTX_set_verify(s_ctx, WOLFSSL_VERIFY_NONE, 0);
    if (wolfSSL_CTX_UseSupportedCurve(s_ctx, WOLFSSL_ECC_SECP256R1) != SSL_SUCCESS) {
        log_it(L_ERROR, "WolfSSL UseSupportedCurve() handle error");
    }
    wolfSSL_CTX_UseSupportedCurve(s_ctx, WOLFSSL_ECC_SECP256R1);
    wolfSSL_CTX_UseSupportedCurve(s_ctx, WOLFSSL_ECC_SECP384R1);
    wolfSSL_CTX_UseSupportedCurve(s_ctx, WOLFSSL_ECC_SECP521R1);
    wolfSSL_CTX_UseSupportedCurve(s_ctx, WOLFSSL_ECC_X25519);
    wolfSSL_CTX_UseSupportedCurve(s_ctx, WOLFSSL_ECC_X448);

    if (s_debug_more) {
        const int l_ciphers_len = 2048;
        char l_buf[l_ciphers_len];
        wolfSSL_get_ciphers(l_buf, l_ciphers_len);
        log_it(L_DEBUG, "WolfSSL cipher list is :\n%s", l_buf);
    }
#endif
    return 0;
}

/**
 * @brief dap_client_http_deinit
 */
void dap_client_http_deinit()
{
#ifndef DAP_NET_CLIENT_NO_SSL
    wolfSSL_CTX_free(s_ctx);
    wolfSSL_Cleanup();
#endif
}


/**
 * @brief dap_client_http_get_connect_timeout_ms
 * @return
 */
uint64_t dap_client_http_get_connect_timeout_ms()
{
    return s_client_timeout_ms;
}

/**
 * @brief dap_client_http_set_connect_timeout_ms
 * @param a_timeout_ms
 */
void dap_client_http_set_connect_timeout_ms(uint64_t a_timeout_ms)
{
    s_client_timeout_ms = a_timeout_ms;
}

/**
 * @brief s_timer_timeout_after_connected_check
 * @param a_arg
 * @return
 */
static bool s_timer_timeout_after_connected_check(void * a_arg)
{
    assert(a_arg);
    dap_events_socket_uuid_t * l_es_uuid_ptr = (dap_events_socket_uuid_t *) a_arg;

    dap_worker_t * l_worker = dap_events_get_current_worker(dap_events_get_default()); // We're in own esocket context
    assert(l_worker);
    dap_events_socket_t * l_es = dap_worker_esocket_find_uuid( l_worker, *l_es_uuid_ptr);
    if(l_es){
        dap_client_http_pvt_t * l_http_pvt = PVT(l_es);
        assert(l_http_pvt);
        if ( time(NULL)- l_http_pvt->ts_last_read >= (time_t) s_client_timeout_read_after_connect_ms){
            log_it(L_WARNING, "Timeout for reading after connect for request http://%s:%u/%s, possible uplink is on heavy load or DPI between you",
                   l_http_pvt->uplink_addr, l_http_pvt->uplink_port, l_http_pvt->path);
            if(l_http_pvt->error_callback) {
                l_http_pvt->error_callback(ETIMEDOUT, l_http_pvt->obj);
                l_http_pvt->were_callbacks_called = true;
            }
            l_http_pvt->is_closed_by_timeout = true;
            log_it(L_INFO, "Close %s sock %"DAP_FORMAT_SOCKET" type %d by timeout",
                   l_es->remote_addr_str ? l_es->remote_addr_str : "", l_es->socket, l_es->type);
            dap_events_socket_remove_and_delete_unsafe(l_es, true);
        }
    }else{
        if(s_debug_more)
            log_it(L_DEBUG,"Esocket %"DAP_UINT64_FORMAT_U" is finished, close check timer", *l_es_uuid_ptr);
    }
    DAP_DEL_Z(l_es_uuid_ptr);
    return false;
}

/**
 * @brief s_timer_timeout_check
 * @details Returns 'false' to prevent looping the checks
 * @param a_arg
 * @return
 */
static bool s_timer_timeout_check(void * a_arg)
{
    dap_events_socket_uuid_t *l_es_uuid = (dap_events_socket_uuid_t*) a_arg;
    assert(l_es_uuid);

    dap_worker_t * l_worker = dap_events_get_current_worker(dap_events_get_default()); // We're in own esocket context
    assert(l_worker);
    dap_events_socket_t * l_es = dap_worker_esocket_find_uuid(l_worker, *l_es_uuid);
    if(l_es){
        if (l_es->flags & DAP_SOCK_CONNECTING ){
            dap_client_http_pvt_t * l_http_pvt = PVT(l_es);
            log_it(L_WARNING,"Connecting timeout for request http://%s:%u/%s, possible network problems or host is down",
                   l_http_pvt->uplink_addr, l_http_pvt->uplink_port, l_http_pvt->path);
            if(l_http_pvt->error_callback) {
                l_http_pvt->error_callback(ETIMEDOUT, l_http_pvt->obj);
                l_http_pvt->were_callbacks_called = true;
            }
            l_http_pvt->is_closed_by_timeout = true;
            log_it(L_INFO, "Close %s sock %"DAP_FORMAT_SOCKET" type %d by timeout",
                   l_es->remote_addr_str ? l_es->remote_addr_str : "", l_es->socket, l_es->type);
            dap_events_socket_remove_and_delete_unsafe(l_es, true);
        }else
            if(s_debug_more)
                log_it(L_DEBUG,"Socket %"DAP_FORMAT_SOCKET" is connected, close check timer", l_es->socket);
    }else
        if(s_debug_more)
            log_it(L_DEBUG,"Esocket %"DAP_UINT64_FORMAT_U" is finished, close check timer", *l_es_uuid);

    DAP_DEL_Z(l_es_uuid);
    return false;
}

/**
 * @brief s_http_stream_read
 * @param a_es
 * @param arg
 */
static void s_http_read(dap_events_socket_t * a_es, void * arg)
{
    UNUSED(arg);
    dap_client_http_pvt_t * l_http_pvt = PVT(a_es);
    if(!l_http_pvt) {
        log_it(L_ERROR, "s_http_read: l_client_http_internal is NULL!");
        return;
    }
    l_http_pvt->ts_last_read = time(NULL);
    // read data
    l_http_pvt->response_size += dap_events_socket_pop_from_buf_in(a_es,
            l_http_pvt->response + l_http_pvt->response_size,
            l_http_pvt->response_size_max - l_http_pvt->response_size);

    // if buffer is overfull then read once more
    if(l_http_pvt->response_size >= DAP_CLIENT_HTTP_RESPONSE_SIZE_MAX) {
        log_it(L_ERROR, "s_http_read response_size(%zu) overfull!!!", l_http_pvt->response_size);
    }

    // search http header
    if(!l_http_pvt->is_header_read && l_http_pvt->response_size > 4
            && !l_http_pvt->content_length) {
        for(size_t l_pos = 0; l_pos < l_http_pvt->response_size - 4; l_pos++) {
            uint8_t *l_str = l_http_pvt->response + l_pos;
            if(!dap_strncmp((const char*) l_str, "\r\n\r\n", 4)) {
                l_http_pvt->header_length = l_pos + 4;
                l_http_pvt->is_header_read = true;
                //dap_events_socket_shrink_buf_in(a_es, l_client_internal->header_size);
                break;
            }
        }
    }
    // process http header
    if(l_http_pvt->is_header_read) {
        const char *l_token = "Content-Length: ";
        char *l_content_len_ptr = strstr((char*)l_http_pvt->response, l_token);
        if (l_content_len_ptr) {
            l_http_pvt->content_length = atoi(l_content_len_ptr + strlen(l_token));
            l_http_pvt->is_header_read = false;
        }
    }

    // process data
    if(l_http_pvt->content_length) {
        l_http_pvt->is_header_read = false;

        // received not enough data
        if(l_http_pvt->content_length
                > (l_http_pvt->response_size - l_http_pvt->header_length)) {
            return;
        }else{
            // process data
            if(l_http_pvt->response_callback)
                l_http_pvt->response_callback(
                        l_http_pvt->response + l_http_pvt->header_length,
                        l_http_pvt->content_length, //l_client_internal->response_size - l_client_internal->header_size,
                        l_http_pvt->obj);
            l_http_pvt->response_size -= l_http_pvt->header_length;
            l_http_pvt->response_size -= l_http_pvt->content_length;
            l_http_pvt->header_length = 0;
            l_http_pvt->content_length = 0;
            l_http_pvt->were_callbacks_called = true;
            a_es->flags |= DAP_SOCK_SIGNAL_CLOSE;
            //dap_events_socket_remove_and_delete_unsafe(a_es, true);
        }

    }
}


/**
 * @brief s_http_stream_error
 * @param a_es
 * @param a_errno
 */
static void s_http_error(dap_events_socket_t * a_es, int a_errno)
{
    char l_errbuf[128];
    l_errbuf[0] = '\0';
    if (a_errno == ETIMEDOUT){
        strncpy(l_errbuf,"Connection timeout", sizeof (l_errbuf)-1);
    }else if (a_errno == ECONNREFUSED){
        strncpy(l_errbuf,"Host is down", sizeof (l_errbuf)-1);
    }else if (a_errno == EHOSTUNREACH){
        strncpy(l_errbuf,"No route to host", sizeof (l_errbuf)-1);
    }else if(a_errno)
        strerror_r(a_errno, l_errbuf, sizeof (l_errbuf));
    else
        strncpy(l_errbuf,"Unknown Error", sizeof (l_errbuf)-1);

    if (a_es->flags & DAP_SOCK_CONNECTING){
        log_it(L_WARNING, "Socket %"DAP_FORMAT_SOCKET" connecting error: %s (code %d)" , a_es->socket, l_errbuf, a_errno);
    }else
        log_it(L_WARNING, "Socket %"DAP_FORMAT_SOCKET" error: %s (code %d)", a_es->socket, l_errbuf, a_errno);

    dap_client_http_pvt_t * l_client_http_internal = PVT(a_es);

    if(!l_client_http_internal) {
        log_it(L_ERROR, "s_http_write: l_client_http_internal is NULL!");
        return;
    }
    if(l_client_http_internal->error_callback)
        l_client_http_internal->error_callback(a_errno, l_client_http_internal->obj);

    l_client_http_internal->were_callbacks_called = true;

    // close connection.
    a_es->flags |= DAP_SOCK_SIGNAL_CLOSE;
}

/**
 * @brief s_es_delete
 * @param a_es
 */
static void s_es_delete(dap_events_socket_t * a_es, void * a_arg)
{
    (void) a_arg;
    dap_client_http_pvt_t * l_client_http_internal = PVT(a_es);
    if(l_client_http_internal == NULL){
        log_it(L_WARNING, "For some reasons internal object is NULL");
        return;
    }
    if (! l_client_http_internal->were_callbacks_called){
        size_t l_response_size = l_client_http_internal->response_size> l_client_http_internal->header_length ?
                    l_client_http_internal->response_size - l_client_http_internal->header_length: 0;
        if (l_client_http_internal->content_length){
            log_it(L_WARNING, "Remote server disconnected before he sends all data: %zd data in buffer when expected %zd",
               l_client_http_internal->response_size, l_client_http_internal->content_length);
            l_client_http_internal->error_callback(-666, l_client_http_internal->obj); // -666 means remote server disconnected before he sends all
        }else if (l_response_size){
            log_it(L_INFO, "Remote server replied without no content length but we have the response %zd bytes size",
               l_response_size);

            //l_client_http_internal->error_callback(-10 , l_client_http_internal->obj);

            if(l_client_http_internal->response_callback)
                l_client_http_internal->response_callback(
                        l_client_http_internal->response + l_client_http_internal->header_length,
                        l_response_size,
                        l_client_http_internal->obj);
            l_client_http_internal->were_callbacks_called = true;
        }else if (l_client_http_internal->response_size){
            log_it(L_INFO, "Remote server disconnected with reply. Body is empty, only headers are in");
            l_client_http_internal->error_callback(-667 , l_client_http_internal->obj); // -667 means remote server replied only with headers
            l_client_http_internal->were_callbacks_called = true;
        }else{
            log_it(L_WARNING, "Remote server disconnected without reply");
            l_client_http_internal->error_callback(-668, l_client_http_internal->obj); // -668 means remote server disconnected before he sends anythinh
            l_client_http_internal->were_callbacks_called = true;
        }
    }

#ifndef DAP_NET_CLIENT_NO_SSL
    WOLFSSL *l_ssl = SSL(a_es);
    if (l_ssl) {
        wolfSSL_free(l_ssl);
        a_es->_pvt = NULL;
    }
#endif

    s_client_http_delete(l_client_http_internal);
    a_es->_inheritor = NULL;
}

/**
 * @brief s_client_http_delete
 * @param a_http_pvt
 */
static void s_client_http_delete(dap_client_http_pvt_t * a_http_pvt)
{
    // call from dap_events_socket_delete(ev_socket, true);
    if(s_debug_more)
        log_it(L_DEBUG, "HTTP client delete");

    if(!a_http_pvt) {
        log_it(L_ERROR, "s_http_write: l_client_http_internal is NULL!");
        return;
    }

    DAP_DEL_Z(a_http_pvt->method)
    DAP_DEL_Z(a_http_pvt->request_content_type)
    DAP_DEL_Z(a_http_pvt->uplink_addr)
    DAP_DEL_Z(a_http_pvt->cookie)
    DAP_DEL_Z(a_http_pvt->response)
    DAP_DEL_Z(a_http_pvt->path)
    DAP_DEL_Z(a_http_pvt->request)
    DAP_DEL_Z(a_http_pvt->request_custom_headers)
    DAP_DEL_Z(a_http_pvt)
}


/**
 * @brief dap_client_http_request_custom
 * @param a_worker
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
void* dap_client_http_request_custom(dap_worker_t * a_worker, const char *a_uplink_addr, uint16_t a_uplink_port, const char *a_method,
        const char *a_request_content_type, const char * a_path, const void *a_request, size_t a_request_size, char *a_cookie,
        dap_client_http_callback_data_t a_response_callback, dap_client_http_callback_error_t a_error_callback,
        void *a_obj, char *a_custom, bool a_over_ssl)
{

    //log_it(L_DEBUG, "HTTP request on url '%s:%d'", a_uplink_addr, a_uplink_port);
    static dap_events_socket_callbacks_t l_s_callbacks = {
        .connected_callback = s_http_connected,
        .read_callback = s_http_read,
        .error_callback = s_http_error,
        .delete_callback = s_es_delete
    };

    // create socket
#ifdef DAP_OS_WINDOWS
    SOCKET l_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (l_socket == INVALID_SOCKET) {
        int err = WSAGetLastError();
        log_it(L_ERROR, "Socket create error: %d", err);
        if(a_error_callback)
            a_error_callback(err, a_obj);
#else
    int l_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (l_socket == -1) {
        log_it(L_ERROR, "Error %d with socket create", errno);
        if(a_error_callback)
            a_error_callback(errno,a_obj);
#endif
        return NULL;
    }
    // Get socket flags
#if defined DAP_OS_WINDOWS
    u_long l_socket_flags = 1;
    if (ioctlsocket((SOCKET)l_socket, (long)FIONBIO, &l_socket_flags))
        log_it(L_ERROR, "Error ioctl %d", WSAGetLastError());
#else
    int l_socket_flags = fcntl(l_socket, F_GETFL);
    if (l_socket_flags == -1){
        log_it(L_ERROR, "Error %d can't get socket flags", errno);
        if(a_error_callback)
            a_error_callback(errno,a_obj);

        return NULL;
    }
    // Make it non-block
    if (fcntl( l_socket, F_SETFL,l_socket_flags| O_NONBLOCK) == -1){
        log_it(L_ERROR, "Error %d can't get socket flags", errno);
        if(a_error_callback)
            a_error_callback(errno,a_obj);

        return NULL;
    }
#endif
    // set socket param
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    dap_events_socket_t *l_ev_socket = dap_events_socket_wrap_no_add(dap_events_get_default(), l_socket, &l_s_callbacks);

    log_it(L_DEBUG,"Created client request socket %"DAP_FORMAT_SOCKET, l_socket);
    // create private struct
    dap_client_http_pvt_t *l_http_pvt = DAP_NEW_Z(dap_client_http_pvt_t);
    l_ev_socket->_inheritor = l_http_pvt;
    l_http_pvt->error_callback = a_error_callback;
    l_http_pvt->response_callback = a_response_callback;
    //l_client_http_internal->socket = l_socket;
    l_http_pvt->obj = a_obj;
    l_http_pvt->method = dap_strdup(a_method);
    l_http_pvt->path = dap_strdup(a_path);
    l_http_pvt->request_content_type = dap_strdup(a_request_content_type);

    l_http_pvt->request = DAP_NEW_Z_SIZE(byte_t, a_request_size+1);
    if (! l_http_pvt->request)
        return NULL;
    l_http_pvt->request_size = a_request_size;
    memcpy(l_http_pvt->request, a_request, a_request_size);

    l_http_pvt->uplink_addr = dap_strdup(a_uplink_addr);
    l_http_pvt->uplink_port = a_uplink_port;
    l_http_pvt->cookie = a_cookie;
    l_http_pvt->request_custom_headers = dap_strdup(a_custom);

    l_http_pvt->response_size_max = DAP_CLIENT_HTTP_RESPONSE_SIZE_MAX;
    l_http_pvt->response = (uint8_t*) DAP_NEW_Z_SIZE(uint8_t, DAP_CLIENT_HTTP_RESPONSE_SIZE_MAX);
    l_http_pvt->worker = a_worker;
    l_http_pvt->is_over_ssl = a_over_ssl;


    // get struct in_addr from ip_str
    inet_pton(AF_INET, a_uplink_addr, &(l_ev_socket->remote_addr.sin_addr));
    //Resolve addr if
    if(!l_ev_socket->remote_addr.sin_addr.s_addr) {
        if(dap_net_resolve_host(a_uplink_addr, AF_INET, (struct sockaddr*) &l_ev_socket->remote_addr.sin_addr) < 0) {
            log_it(L_ERROR, "Wrong remote address '%s:%u'", a_uplink_addr, a_uplink_port);
            s_client_http_delete( l_http_pvt);
            l_ev_socket->_inheritor = NULL;
            dap_events_socket_delete_unsafe( l_ev_socket, true);
            if(a_error_callback)
                a_error_callback(errno,a_obj);

            return NULL;
        }
    }
    l_ev_socket->remote_addr_str = dap_strdup(a_uplink_addr);
    // connect
    l_ev_socket->remote_addr.sin_family = AF_INET;
    l_ev_socket->remote_addr.sin_port = htons(a_uplink_port);
    l_ev_socket->flags |= DAP_SOCK_CONNECTING;
    l_ev_socket->type = DESCRIPTOR_TYPE_SOCKET_CLIENT;
    l_ev_socket->flags |= DAP_SOCK_READY_TO_WRITE;
    if (a_over_ssl) {
#ifndef DAP_NET_CLIENT_NO_SSL
        l_ev_socket->callbacks.connected_callback = s_http_ssl_connected;
#else
        log_it(L_ERROR,"We have no SSL implementation but trying to create SSL connection!");
#endif
    }
    int l_err = connect(l_socket, (struct sockaddr *) &l_ev_socket->remote_addr, sizeof(struct sockaddr_in));
    if (l_err == 0){
        log_it(L_DEBUG, "Connected momentaly with %s:%u!", a_uplink_addr, a_uplink_port);
        l_http_pvt->worker = a_worker?a_worker: dap_events_worker_get_auto();
        if (a_over_ssl) {
#ifndef DAP_NET_CLIENT_NO_SSL
            s_http_ssl_connected(l_ev_socket);
#endif
        }
        return l_http_pvt;
    }
#ifdef DAP_OS_WINDOWS
    else if(l_err == SOCKET_ERROR) {
        int l_err2 = WSAGetLastError();
        if (l_err2 == WSAEWOULDBLOCK) {
            log_it(L_DEBUG, "Connecting to %s:%u", a_uplink_addr, a_uplink_port);
            l_http_pvt->worker = a_worker?a_worker: dap_events_worker_get_auto();
            dap_worker_add_events_socket(l_ev_socket,l_http_pvt->worker);
            dap_events_socket_uuid_t * l_ev_uuid_ptr = DAP_NEW_Z(dap_events_socket_uuid_t);
            *l_ev_uuid_ptr = l_ev_socket->uuid;
            if (!dap_timerfd_start_on_worker(l_http_pvt->worker,s_client_timeout_ms, s_timer_timeout_check, l_ev_uuid_ptr)) {
                log_it(L_ERROR,"Can't run timer on worker %u for esocket uuid %"DAP_UINT64_FORMAT_U" for timeout check during connection attempt ",
                       l_http_pvt->worker->id, *l_ev_uuid_ptr);
                DAP_DEL_Z(l_ev_uuid_ptr)
            }
            return l_http_pvt;
        } else {
            log_it(L_ERROR, "Socket %zu connecting error: %d", l_ev_socket->socket, l_err2);
            s_client_http_delete( l_http_pvt);
            l_ev_socket->_inheritor = NULL;
            dap_events_socket_delete_unsafe( l_ev_socket, true);
            if(a_error_callback)
                a_error_callback(l_err2, a_obj);
            return NULL;
        }
    }
#else
    else if( errno == EINPROGRESS && l_err == -1){
        log_it(L_DEBUG, "Connecting to %s:%u", a_uplink_addr, a_uplink_port);
        l_http_pvt->worker = a_worker?a_worker: dap_events_worker_get_auto();
        dap_worker_add_events_socket(l_ev_socket,l_http_pvt->worker);
        dap_events_socket_uuid_t * l_ev_uuid_ptr = DAP_NEW_Z(dap_events_socket_uuid_t);
        *l_ev_uuid_ptr = l_ev_socket->uuid;
        if(dap_timerfd_start_on_worker(l_http_pvt->worker,s_client_timeout_ms, s_timer_timeout_check,l_ev_uuid_ptr) == NULL){
            log_it(L_ERROR,"Can't run timer on worker %u for esocket uuid %"DAP_UINT64_FORMAT_U" for timeout check during connection attempt ",
                   l_http_pvt->worker->id, *l_ev_uuid_ptr);
            DAP_DEL_Z(l_ev_uuid_ptr);
        }
        return l_http_pvt;
    }
    else{
        char l_errbuf[128];
        l_errbuf[0] = '\0';
        strerror_r(l_err, l_errbuf, sizeof (l_errbuf));
        log_it(L_ERROR, "Connecting error: \"%s\" (code %d)", l_errbuf, l_err);
        s_client_http_delete( l_http_pvt);
        l_ev_socket->_inheritor = NULL;
        dap_events_socket_delete_unsafe( l_ev_socket, true);
        if(a_error_callback)
            a_error_callback(errno,a_obj);

        return NULL;
    }
#endif
    return NULL;
}

#ifndef DAP_NET_CLIENT_NO_SSL
static void s_http_ssl_connected(dap_events_socket_t * a_esocket)
{
    assert(a_esocket);
    dap_client_http_pvt_t * l_http_pvt = PVT(a_esocket);
    assert(l_http_pvt);
    dap_worker_t *l_worker = l_http_pvt->worker;
    assert(l_worker);

    WOLFSSL *l_ssl = wolfSSL_new(s_ctx);
    if (!l_ssl)
        log_it(L_ERROR, "wolfSSL_new error");
    wolfSSL_set_fd(l_ssl, a_esocket->socket);
    a_esocket->_pvt = (void *)l_ssl;
    a_esocket->type = DESCRIPTOR_TYPE_SOCKET_CLIENT_SSL;
    a_esocket->flags |= DAP_SOCK_CONNECTING;
    a_esocket->flags |= DAP_SOCK_READY_TO_WRITE;
    a_esocket->callbacks.connected_callback = s_http_connected;
    dap_events_socket_handle_t * l_ev_socket_handler = DAP_NEW_Z(dap_events_socket_handle_t);
    l_ev_socket_handler->esocket = a_esocket;
    l_ev_socket_handler->esocket_uuid = a_esocket->uuid;
    dap_timerfd_start_on_worker(l_http_pvt->worker, s_client_timeout_ms, s_timer_timeout_check, l_ev_socket_handler);
}
#endif

/**
 * @brief s_http_connected
 * @param a_esocket
 */
static void s_http_connected(dap_events_socket_t * a_esocket)
{
    assert(a_esocket);
    dap_client_http_pvt_t * l_http_pvt = PVT(a_esocket);
    assert(l_http_pvt);
    assert(l_http_pvt->worker);

    log_it(L_INFO, "Remote address connected (%s:%u) with sock_id %"DAP_FORMAT_SOCKET, l_http_pvt->uplink_addr, l_http_pvt->uplink_port, a_esocket->socket);
    // add to dap_worker
    //dap_client_pvt_t * l_client_pvt = (dap_client_pvt_t*) a_obj;
    //dap_events_new();
    dap_events_socket_uuid_t * l_es_uuid_ptr = DAP_NEW_Z(dap_events_socket_uuid_t);
    *l_es_uuid_ptr = a_esocket->uuid;
    if(dap_timerfd_start_on_worker(l_http_pvt->worker, (unsigned long)s_client_timeout_read_after_connect_ms, s_timer_timeout_after_connected_check, l_es_uuid_ptr) == NULL ){
        DAP_DELETE(l_es_uuid_ptr);
        log_it(L_ERROR, "Can't run timerfo after connection check on worker id %u", l_http_pvt->worker->id);
    }

    char l_request_headers[1024] = { [0]='\0' };
    int l_offset = 0;
    size_t l_offset2 = sizeof(l_request_headers);
    if(l_http_pvt->request && (dap_strcmp(l_http_pvt->method, "POST") == 0 || dap_strcmp(l_http_pvt->method, "POST_ENC") == 0)) {
        //log_it(L_DEBUG, "POST request with %u bytes of decoded data", a_request_size);

        l_offset += l_http_pvt->request_content_type
                ? dap_snprintf(l_request_headers, l_offset2, "Content-Type: %s\r\n", l_http_pvt->request_content_type)
                : 0;

        // Add custom headers
        l_offset += l_http_pvt->request_custom_headers
                ? dap_snprintf(l_request_headers + l_offset, l_offset2 -= l_offset, "%s", l_http_pvt->request_custom_headers)
                : 0;

        // Setup cookie header
        l_offset += l_http_pvt->cookie
                ? dap_snprintf(l_request_headers + l_offset, l_offset2 -= l_offset, "Cookie: %s\r\n", l_http_pvt->cookie)
                : 0;

        // Set request size as Content-Length header
        l_offset += dap_snprintf(l_request_headers + l_offset, l_offset2 -= l_offset, "Content-Length: %zu\r\n", l_http_pvt->request_size);
    }

    // adding string for GET request
    char l_get_str[l_http_pvt->request_size + 2];
    l_get_str[0] = '\0';
    if(! dap_strcmp(l_http_pvt->method, "GET") ) {
        // We hide our request and mask them as possible
        l_offset += dap_snprintf(l_request_headers + l_offset, l_offset2 -= l_offset, "User-Agent: Mozilla\r\n");
        l_offset += l_http_pvt->request_custom_headers
                ? dap_snprintf(l_request_headers + l_offset, l_offset2 -= l_offset, "%s", l_http_pvt->request_custom_headers)
                : 0;
        l_offset += l_http_pvt->cookie
                ? dap_snprintf(l_request_headers + l_offset, l_offset2 -= l_offset, "Cookie: %s\r\n", l_http_pvt->cookie)
                : 0;

        if ((l_http_pvt->request_size && l_http_pvt->request_size))
            dap_snprintf(l_get_str, sizeof(l_get_str), "?%s", l_http_pvt->request) ;
    }

    // send header
    dap_events_socket_write_f_unsafe( a_esocket, "%s /%s%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "%s"
            "\r\n",
            l_http_pvt->method, l_http_pvt->path, l_get_str, l_http_pvt->uplink_addr, l_request_headers);
    // send data for POST request
    if (l_http_pvt->request && l_http_pvt->request_size) {
        dap_events_socket_write_unsafe( a_esocket, l_http_pvt->request, l_http_pvt->request_size);
    }
}


/**
 * @brief dap_client_http_request
 * @param a_worker
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
void* dap_client_http_request(dap_worker_t * a_worker,const char *a_uplink_addr, uint16_t a_uplink_port, const char * a_method,
        const char* a_request_content_type, const char * a_path, const void *a_request, size_t a_request_size,
        char * a_cookie, dap_client_http_callback_data_t a_response_callback,
        dap_client_http_callback_error_t a_error_callback, void *a_obj, void * a_custom)
{
    return dap_client_http_request_custom(a_worker, a_uplink_addr, a_uplink_port, a_method, a_request_content_type, a_path,
            a_request, a_request_size, a_cookie, a_response_callback, a_error_callback, a_obj,
            (char*)a_custom, false);
}
