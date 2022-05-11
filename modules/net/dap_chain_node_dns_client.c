/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * Dmitriy Gerasimov <dmitriy.gerasmiov@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2021
 * All rights reserved.

 This file is part of DapChain SDK the open source project

    DapChain SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DapChain SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DapChain SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dap_events.h"
#include "dap_timerfd.h"
#include "dap_chain_node_dns_server.h"
#include "dap_chain_node_dns_client.h"

#define LOG_TAG "dap_chain_node_dns_client"

struct dns_client
{
    dap_events_socket_t * parent;
    dap_chain_node_info_t *result;
    struct in_addr addr;
    uint16_t port;
    char *name;
    dap_dns_buf_t * dns_request;
    byte_t * buf;
    size_t buf_size;

    dap_dns_client_node_info_request_success_callback_t callback_success;
    dap_dns_client_node_info_request_error_callback_t callback_error;
    void * callbacks_arg;

    bool is_callbacks_called;
};

static void s_dns_client_esocket_read_callback(dap_events_socket_t * a_esocket, void * a_arg);
static void s_dns_client_esocket_error_callback(dap_events_socket_t * a_esocket, int a_error);
static bool s_dns_client_esocket_timeout_callback( void * a_arg);
static void s_dns_client_esocket_delete_callback(dap_events_socket_t * a_esocket, void * a_arg);
static void s_dns_client_esocket_worker_assign_callback(dap_events_socket_t * a_esocket, dap_worker_t * a_worker);

/**
 * @brief s_dns_client_esocket_read_callback
 * @param a_esocket
 * @param a_arg
 */
static void s_dns_client_esocket_read_callback(dap_events_socket_t * a_esocket, void * a_arg)
{
    (void) a_arg;
    struct dns_client * l_dns_client = (struct dns_client*) a_esocket->_inheritor;
    byte_t * l_buf = a_esocket->buf_in;
    size_t l_recieved = a_esocket->buf_in_size;
    size_t l_addr_point = DNS_HEADER_SIZE + strlen(l_dns_client->name) + 2 + 2 * sizeof(uint16_t) + DNS_ANSWER_SIZE - sizeof(uint32_t);
    if (l_recieved < l_addr_point + sizeof(uint32_t)) {
        log_it(L_WARNING, "DNS answer incomplete");
        l_dns_client->callback_error(a_esocket->worker, l_dns_client->result,l_dns_client->callbacks_arg,EIO );
        l_dns_client->is_callbacks_called = true;
        a_esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
        a_esocket->buf_in_size = a_esocket->buf_out_size = 0;
        return;
    }
    byte_t * l_cur = l_buf + 3 * sizeof(uint16_t);
    int l_answers_count = ntohs(*(uint16_t *)l_cur);
    if (l_answers_count != 1) {
        log_it(L_WARNING, "Incorrect DNS answer format");
        l_dns_client->callback_error(a_esocket->worker, l_dns_client->result,l_dns_client->callbacks_arg,EINVAL);
        l_dns_client->is_callbacks_called = true;
        a_esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
        a_esocket->buf_in_size = a_esocket->buf_out_size = 0;
        return;
    }
    l_cur = l_buf + l_addr_point;
    if ( l_dns_client->result) {
        l_dns_client->result->hdr.ext_addr_v4.s_addr = ntohl(*(uint32_t *)l_cur);
    }
    l_cur = l_buf + 5 * sizeof(uint16_t);
    int l_additions_count = ntohs(*(uint16_t *)l_cur);
    if (l_additions_count == 1) {
        l_cur = l_buf + l_addr_point + DNS_ANSWER_SIZE;
        if (l_dns_client->result) {
            l_dns_client->result->hdr.ext_port = ntohs(*(uint16_t *)l_cur);
        }
        l_cur += sizeof(uint16_t);
        if (l_dns_client->result) {
           l_dns_client->result->hdr.address.uint64 = be64toh(*(uint64_t *)l_cur);
        }
    }

    l_dns_client->callback_success(a_esocket->worker,l_dns_client->result,l_dns_client->callbacks_arg);
    l_dns_client->is_callbacks_called = true;
    a_esocket->flags |= DAP_SOCK_SIGNAL_CLOSE;
    a_esocket->buf_in_size = a_esocket->buf_out_size = 0;
}

/**
 * @brief s_dns_client_esocket_error_callback
 * @param a_esocket
 * @param a_error
 */
static void s_dns_client_esocket_error_callback(dap_events_socket_t * a_esocket, int a_error)
{
    struct dns_client * l_dns_client = (struct dns_client*) a_esocket->_inheritor;
    log_it(L_ERROR,"DNS client esocket error %d", a_error);
    l_dns_client->callback_error(a_esocket->worker, l_dns_client->result,l_dns_client->callbacks_arg,a_error);
    l_dns_client->is_callbacks_called = true;
}

/**
 * @brief s_dns_client_esocket_timeout_callback
 * @param a_worker
 * @param a_arg
 * @return
 */
static bool s_dns_client_esocket_timeout_callback(void * a_arg)
{
    assert(a_arg);
    dap_events_socket_uuid_t * l_es_uuid_ptr = (dap_events_socket_uuid_t *) a_arg;
    assert(l_es_uuid_ptr);

    dap_events_t * l_events = dap_events_get_default();
    assert(l_events);

    dap_worker_t * l_worker = dap_events_get_current_worker(l_events); // We're in own esocket context
    assert(l_worker);

    dap_events_socket_t * l_es;
    if((l_es = dap_worker_esocket_find_uuid(l_worker ,*l_es_uuid_ptr) ) != NULL){ // If we've not closed this esocket
        struct dns_client * l_dns_client = (struct dns_client*) l_es->_inheritor;
        log_it(L_WARNING,"DNS request timeout, bad network?");
        if(! l_dns_client->is_callbacks_called ){
            l_dns_client->callback_error(l_es->worker,l_dns_client->result,l_dns_client->callbacks_arg,ETIMEDOUT);
            l_dns_client->is_callbacks_called = true;
        }

        dap_events_socket_remove_and_delete_unsafe( l_es, false);
    }
    DAP_DEL_Z(l_es_uuid_ptr);
    return false;
}

/**
 * @brief s_dns_client_esocket_delete_callback
 * @param a_esocket
 * @param a_arg
 */
static void s_dns_client_esocket_delete_callback(dap_events_socket_t * a_esocket, void * a_arg)
{
    (void) a_arg;
    struct dns_client * l_dns_client = (struct dns_client*) a_esocket->_inheritor;
    if(! l_dns_client->is_callbacks_called )
        l_dns_client->callback_error(a_esocket->worker,l_dns_client->result,l_dns_client->callbacks_arg,EBUSY);
    if(l_dns_client->name)
        DAP_DELETE(l_dns_client->name);
    DAP_DEL_Z(l_dns_client->buf);
}

/**
 * @brief s_dns_client_esocket_worker_assign_callback
 * @param a_esocket
 * @param a_worker
 */
static void s_dns_client_esocket_worker_assign_callback(dap_events_socket_t * a_esocket, dap_worker_t * a_worker)
{
    struct dns_client * l_dns_client = (struct dns_client*) a_esocket->_inheritor;
    dap_events_socket_write_unsafe(a_esocket,l_dns_client->dns_request->data, l_dns_client->dns_request->size );

    dap_events_socket_uuid_t * l_es_uuid_ptr = DAP_NEW_Z(dap_events_socket_uuid_t);
    *l_es_uuid_ptr = a_esocket->uuid;
    dap_timerfd_start_on_worker(a_worker, dap_config_get_item_uint64_default(g_config,"dns_client","request_timeout",10)*1000,
                                 s_dns_client_esocket_timeout_callback,l_es_uuid_ptr);

}

/**
 * @brief dap_chain_node_info_dns_request
 * @param a_addr
 * @param a_port
 * @param a_name
 * @param a_result
 * @param a_callback_success
 * @param a_callback_error
 * @param a_callbacks_arg
 */
int dap_chain_node_info_dns_request(struct in_addr a_addr, uint16_t a_port, char *a_name, dap_chain_node_info_t *a_result,
                           dap_dns_client_node_info_request_success_callback_t a_callback_success,
                           dap_dns_client_node_info_request_error_callback_t a_callback_error,void * a_callbacks_arg)
{
    log_it(L_INFO, "DNS request for bootstrap nodelist  %s : %d, net %s", inet_ntoa(a_addr), a_port, a_name);

    struct dns_client * l_dns_client = DAP_NEW_Z(struct dns_client);
    if(!l_dns_client)
        return -1;
    l_dns_client->name = dap_strdup(a_name);
    l_dns_client->callback_error = a_callback_error;
    l_dns_client->callback_success = a_callback_success;
    l_dns_client->callbacks_arg = a_callbacks_arg;
    l_dns_client->addr = a_addr;

    l_dns_client->buf_size = 1024;
    l_dns_client->buf = DAP_NEW_Z_SIZE(byte_t,l_dns_client->buf_size);
    if (!l_dns_client->buf){
        DAP_DELETE(l_dns_client);
        return -2;
    }
    l_dns_client->dns_request = DAP_NEW_Z(dap_dns_buf_t);
    if( ! l_dns_client->dns_request){
        DAP_DELETE(l_dns_client->buf);
        DAP_DELETE(l_dns_client);
        return -3;
    }
    l_dns_client->dns_request->data = (char *)l_dns_client->buf;
    l_dns_client->result = a_result;
    dap_dns_buf_put_uint16(l_dns_client->dns_request, rand() % 0xFFFF);     // ID
    dap_dns_message_flags_t l_flags = {};
    dap_dns_buf_put_uint16(l_dns_client->dns_request, l_flags.val);
    dap_dns_buf_put_uint16(l_dns_client->dns_request, 1);                  // we have only 1 question
    dap_dns_buf_put_uint16(l_dns_client->dns_request, 0);
    dap_dns_buf_put_uint16(l_dns_client->dns_request, 0);
    dap_dns_buf_put_uint16(l_dns_client->dns_request, 0);
    size_t l_ptr = 0;

    uint8_t *l_cur = l_dns_client->buf + l_dns_client->dns_request->size;
    for (size_t i = 0; i <= strlen(a_name); i++)
    {
        if (a_name[i] == '.' || a_name[i] == 0)
        {
            *l_cur++ = i - l_ptr;
            for( ; l_ptr < i; l_ptr++)
            {
                *l_cur++ = a_name[l_ptr];
            }
            l_ptr++;
        }
    }
    *l_cur++='\0';
    l_dns_client->dns_request->size = l_cur - l_dns_client->buf;
    dap_dns_buf_put_uint16(l_dns_client->dns_request, DNS_RECORD_TYPE_A);
    dap_dns_buf_put_uint16(l_dns_client->dns_request, DNS_CLASS_TYPE_IN);

    dap_events_socket_callbacks_t l_esocket_callbacks={};

    l_esocket_callbacks.worker_assign_callback = s_dns_client_esocket_worker_assign_callback;
    l_esocket_callbacks.delete_callback = s_dns_client_esocket_delete_callback; // Delete client callback
    l_esocket_callbacks.read_callback = s_dns_client_esocket_read_callback; // Read function
    l_esocket_callbacks.error_callback = s_dns_client_esocket_error_callback; // Error processing function

    dap_events_socket_t * l_esocket = dap_events_socket_create(DESCRIPTOR_TYPE_SOCKET_UDP,&l_esocket_callbacks);
    // l_esocket->flags  |= DAP_SOCK_DROP_WRITE_IF_ZERO;
    l_esocket->remote_addr.sin_family = AF_INET;
    l_esocket->remote_addr.sin_port = htons(a_port);
    l_esocket->remote_addr.sin_addr = a_addr;
    l_esocket->_inheritor = l_dns_client;

    dap_worker_t * l_worker = dap_events_worker_get_auto();
    dap_events_socket_assign_on_worker_mt(l_esocket,l_worker);
    return 0;
}


/**
 * @brief dap_dns_buf_init Initialize DNS parser buffer
 * @param buf DNS buffer structure
 * @param msg DNS message
 * @return none
 */
void dap_dns_buf_init(dap_dns_buf_t *buf, char *msg)
{
    buf->data = msg;
    buf->size = 0;
}

/**
 * @brief dap_dns_buf_get_uint16 Get uint16 from network order
 * @param buf DNS buffer structure
 * @return uint16 in host order
 */
uint16_t dap_dns_buf_get_uint16(dap_dns_buf_t *buf)
{
    char c;
    c = buf->data[buf->size++];
    return c << 8 | buf->data[buf->size++];
}

/**
 * @brief dap_dns_buf_put_uint16 Put uint16 to network order
 * @param buf DNS buffer structure
 * @param val uint16 in host order
 * @return none
 */
void dap_dns_buf_put_uint16(dap_dns_buf_t *buf, uint16_t val)
{
    buf->data[buf->size++] = val >> 8;
    buf->data[buf->size++] = val;
}

/**
 * @brief dap_dns_buf_put_uint32 Put uint32 to network order
 * @param buf DNS buffer structure
 * @param val uint32 in host order
 * @return none
 */
void dap_dns_buf_put_uint32(dap_dns_buf_t *buf, uint32_t val)
{
    dap_dns_buf_put_uint16(buf, val >> 16);
    dap_dns_buf_put_uint16(buf, val);
}

/**
 * @brief dap_dns_buf_put_uint64 Put uint64 to network order
 * @param buf DNS buffer structure
 * @param val uint64 in host order
 * @return none
 */
void dap_dns_buf_put_uint64(dap_dns_buf_t *buf, uint64_t val)
{
    dap_dns_buf_put_uint32(buf, val >> 32);
    dap_dns_buf_put_uint32(buf, val);
}
