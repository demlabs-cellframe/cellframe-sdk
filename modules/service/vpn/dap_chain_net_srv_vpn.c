/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
 * All rights reserved.

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

#ifdef DAP_OS_LINUX
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#endif

#ifdef DAP_OS_DARWIN
#include <net/if.h>
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <netinet/in.h>

#elif defined(DAP_OS_BSD)
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_tun.h>
#include <sys/ioctl.h>
#endif

#if defined (DAP_OS_BSD)
typedef struct ip dap_os_iphdr_t;
#else
typedef struct iphdr dap_os_iphdr_t;
#endif


#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>

#include "uthash.h"
#include "utlist.h"

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_config.h"

#include "dap_events_socket.h"
#include "dap_http_client.h"

#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_pkt.h"

#include "dap_chain_net.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_client.h"
#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_srv_stream_session.h"
#include "dap_chain_net_vpn_client.h"
#include "dap_chain_net_vpn_client_tun.h"
#include "dap_chain_net_srv_vpn_cmd.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_ledger.h"
#include "dap_events.h"

#define LOG_TAG "dap_chain_net_srv_vpn"

#define SF_MAX_EVENTS 256

typedef struct vpn_local_network {
    struct in_addr ipv4_lease_last;
    struct in_addr ipv4_network_mask;
    struct in_addr ipv4_network_addr;
    struct in_addr ipv4_gw;
    int tun_ctl_fd;
    char * tun_device_name;
    int tun_fd;
#ifndef DAP_OS_DARWIN
    struct ifreq ifr;
#endif
    bool auto_cpu_reassignment;

    ch_vpn_pkt_t * pkt_out[400];
    size_t pkt_out_size;
    size_t pkt_out_rindex;
    size_t pkt_out_windex;
    pthread_mutex_t pkt_out_mutex;
    pthread_rwlock_t rwlock;
} vpn_local_network_t;

// Message for QUEUE_PTR operations
typedef struct tun_socket_msg{
    enum{
        TUN_SOCKET_MSG_NONE,
        TUN_SOCKET_MSG_IP_ASSIGNED,
        TUN_SOCKET_MSG_IP_UNASSIGNED,
        TUN_SOCKET_MSG_CH_VPN_SEND,
        TUN_SOCKET_MSG_ESOCKET_REASSIGNED,
    } type;
    dap_chain_net_srv_ch_vpn_t * ch_vpn;
    dap_events_socket_t * esocket;
    dap_events_socket_uuid_t esocket_uuid;
    bool is_reassigned_once;
    union{
        struct{ // Esocket reassigment
            uint32_t worker_id;
            struct in_addr addr;
        } esocket_reassigment;
        struct{  // IP assign/unassign
            uint32_t worker_id;
            struct in_addr addr;
            uint32_t usage_id;
        } ip_assigment;
        struct{  // IP assign/unassign
            uint32_t worker_id;
            struct in_addr addr;
        } ip_unassigment;
        struct{ // CH VPN send operation
            ch_vpn_pkt_t * pkt;
        } ch_vpn_send;
    };
} tun_socket_msg_t;

typedef struct{
    dap_chain_net_srv_t * srv;
    uint32_t usage_id;
    dap_chain_net_srv_client_remote_t * srv_client;
} remain_limits_save_arg_t;

dap_chain_net_srv_vpn_tun_socket_t ** s_tun_sockets = NULL;
dap_events_socket_t ** s_tun_sockets_queue_msg = NULL;

pthread_mutex_t s_tun_sockets_mutex_started;
pthread_cond_t s_tun_sockets_cond_started;
uint32_t s_tun_sockets_started = 0;

uint32_t s_tun_sockets_count = 0;
bool s_debug_more = false;

static dap_chain_net_srv_ch_vpn_t * s_ch_vpn_addrs  = NULL;
static pthread_rwlock_t s_clients_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static vpn_local_network_t *s_raw_server = NULL;
static pthread_rwlock_t s_raw_server_rwlock = PTHREAD_RWLOCK_INITIALIZER;

// Service callbacks
static int s_callback_requested(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t * a_srv_client
                                    , const void * a_custom_data, size_t a_custom_data_size );
static int s_callback_response_success(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t * a_srv_client
                                    , const void * a_custom_data, size_t a_custom_data_size );
static int s_callback_response_error(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t * a_srv_client
                                    , const void * a_custom_data, size_t a_custom_data_size );

static int s_callback_receipt_next_success(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t * a_srv_client,
                    const void * a_receipt_next, size_t a_receipt_next_size);
static dap_stream_ch_chain_net_srv_remain_service_store_t* s_callback_get_remain_service(dap_chain_net_srv_t * a_srv,  uint32_t usage_id,
                                         dap_chain_net_srv_client_remote_t * a_srv_client);
static int s_callback_save_remain_service(dap_chain_net_srv_t * a_srv,  uint32_t usage_id, dap_chain_net_srv_client_remote_t * a_srv_client);
static bool s_save_limits(void* arg);
// Stream callbacks
static void s_ch_vpn_new(dap_stream_ch_t* ch, void* arg);
static void s_ch_vpn_delete(dap_stream_ch_t* ch, void* arg);
static void s_ch_packet_in(dap_stream_ch_t* ch, void* a_arg);
static void s_ch_packet_out(dap_stream_ch_t* ch, void* arg);

static void s_ch_vpn_esocket_assigned(dap_events_socket_t* a_es, dap_worker_t * l_worker);
static void s_ch_vpn_esocket_unassigned(dap_events_socket_t* a_es, dap_worker_t * l_worker);


//static int srv_ch_sf_raw_write(uint8_t op_code, const void * data, size_t data_size);
//static void srv_stream_sf_disconnect(ch_vpn_socket_proxy_t * sf_sock);

static char *s_srv_vpn_addr = NULL, *s_srv_vpn_mask = NULL;

static void s_update_limits(dap_stream_ch_t * a_ch ,
                           dap_chain_net_srv_stream_session_t * a_srv_session,
                           dap_chain_net_srv_usage_t * a_usage, size_t a_bytes);

static void s_es_tun_new(dap_events_socket_t * a_es, void * arg);
static void s_es_tun_delete(dap_events_socket_t * a_es, void * arg);
static void s_es_tun_read(dap_events_socket_t * a_es, void * arg);
static void s_es_tun_error(dap_events_socket_t * a_es,int arg);
static void s_es_tun_write(dap_events_socket_t* a_es, void* arg);
static void s_es_tun_write_finished(dap_events_socket_t* a_es, void* a_arg, int a_errno);

static void s_tun_recv_msg_callback(dap_events_socket_t * a_esocket_queue, void * a_msg );
static void s_tun_send_msg_ip_assigned(uint32_t a_worker_own_id, uint32_t a_worker_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr);
static void s_tun_send_msg_ip_assigned_all(uint32_t a_worker_own_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr);
static void s_tun_send_msg_ip_unassigned(uint32_t a_worker_own_id, uint32_t a_worker_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr);
static void s_tun_send_msg_ip_unassigned_all(uint32_t a_worker_own_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr);

#if !defined(DAP_OS_DARWIN) && (defined(DAP_OS_LINUX) || defined (DAP_OS_BSD))

static int s_tun_deattach_queue(int fd);
static int s_tun_attach_queue(int fd);
#endif

static bool s_tun_client_send_data(dap_chain_net_srv_ch_vpn_info_t * a_ch_vpn_info, const void * a_data, size_t a_data_size);
static bool s_tun_client_send_data_unsafe(dap_chain_net_srv_ch_vpn_t * l_ch_vpn, ch_vpn_pkt_t * l_pkt_out);


static bool s_tun_client_send_data_unsafe(dap_chain_net_srv_ch_vpn_t * l_ch_vpn, ch_vpn_pkt_t * l_pkt_out)
{
    dap_chain_net_srv_stream_session_t *l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION(l_ch_vpn->ch->stream->session);
    dap_chain_net_srv_usage_t *l_usage = l_srv_session->usage_active;// dap_chain_net_srv_usage_find_unsafe(l_srv_session, l_ch_vpn->usage_id);
    size_t l_data_to_send = (l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header));
    debug_if(s_debug_more, L_DEBUG, "Sent stream pkt size %zu on worker #%u", l_data_to_send, l_ch_vpn->ch->stream_worker->worker->id);
    size_t l_data_sent = dap_stream_ch_pkt_write_unsafe(l_ch_vpn->ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, l_pkt_out, l_data_to_send);
    s_update_limits(l_ch_vpn->ch,l_srv_session,l_usage, l_data_sent);
    l_srv_session->stats.bytes_recv += l_data_sent;
    if ( l_data_sent < l_data_to_send){
        log_it(L_WARNING, "Wasn't sent all the data in tunnel (%zd was sent from %zd): probably buffer overflow", l_data_sent, l_data_to_send);
        l_srv_session->stats.bytes_recv_lost += l_data_to_send - l_data_sent;
        l_srv_session->stats.packets_recv_lost++;
        return false;
    } else {
        l_srv_session->stats.packets_recv++;
        return true;
    }
}

/**
 * @brief s_tun_client_send_data_inter
 * @param a_es_input
 * @param a_ch_vpn
 * @param a_pkt_out
 * @return
 */
static bool s_tun_client_send_data_inter(dap_events_socket_t * a_es_input, dap_chain_net_srv_ch_vpn_t  * a_ch_vpn, ch_vpn_pkt_t * a_pkt_out)
{
    dap_chain_net_srv_stream_session_t * l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION (a_ch_vpn->ch->stream->session );
    dap_chain_net_srv_usage_t * l_usage = l_srv_session->usage_active;// dap_chain_net_srv_usage_find_unsafe(l_srv_session,  a_ch_vpn->usage_id);

    size_t l_data_to_send = (a_pkt_out->header.op_data.data_size + sizeof(a_pkt_out->header));
    size_t l_data_sent = dap_stream_ch_pkt_write_inter(a_es_input, a_ch_vpn->ch->uuid, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, a_pkt_out, l_data_to_send);
    s_update_limits(a_ch_vpn->ch,l_srv_session,l_usage, l_data_sent );
    if ( l_data_sent < l_data_to_send){
        log_it(L_WARNING, "Wasn't sent all the data in tunnel (%zd was sent from %zd): probably buffer overflow", l_data_sent, l_data_to_send);
        l_srv_session->stats.bytes_recv_lost += l_data_to_send - l_data_sent;
        l_srv_session->stats.packets_recv_lost++;
        return false;
    }else{
        l_srv_session->stats.bytes_recv += l_data_sent;
        l_srv_session->stats.packets_recv++;
        return true;
    }
}


static bool s_tun_client_send_data(dap_chain_net_srv_ch_vpn_info_t * l_ch_vpn_info, const void * a_data, size_t a_data_size)
{
    assert(a_data_size > sizeof (dap_os_iphdr_t));
    ch_vpn_pkt_t *l_pkt_out             = DAP_NEW_Z_SIZE(ch_vpn_pkt_t, sizeof(l_pkt_out->header) + a_data_size);
    if (!l_pkt_out) {
        log_it(L_CRITICAL, "Memory allocation error");
        return false;
    }
    l_pkt_out->header.op_code           = VPN_PACKET_OP_CODE_VPN_RECV;
    l_pkt_out->header.sock_id           = s_raw_server->tun_fd;
    l_pkt_out->header.usage_id          = l_ch_vpn_info->usage_id;
    l_pkt_out->header.op_data.data_size = a_data_size;
    memcpy(l_pkt_out->data, a_data, a_data_size);

    if(l_ch_vpn_info->is_on_this_worker){
        dap_events_socket_t* l_es = dap_context_find(l_ch_vpn_info->worker->context, l_ch_vpn_info->esocket_uuid);
        if (!l_es) {
            log_it(L_ERROR, "No esocket %p on worker #%u, lost %zd data", l_ch_vpn_info->esocket, l_ch_vpn_info->worker->id, a_data_size);
            DAP_DEL_Z(l_pkt_out);
            return false;
        }
        if (l_es != l_ch_vpn_info->esocket) {
            log_it(L_ERROR, "Wrong esocket %p on worker #%u, lost %zd data", l_ch_vpn_info->esocket, l_ch_vpn_info->worker->id, a_data_size);
            DAP_DEL_Z(l_pkt_out);
            return false;
        }
       /*
        dap_stream_worker_t *l_stream_worker = (dap_stream_worker_t *)dap_worker_get_current()->_inheritor;
        s_tun_client_send_data_inter(l_stream_worker->queue_ch_io_input[l_ch_vpn_info->worker->id], l_ch_vpn_info->ch_vpn, l_pkt_out);
        */
        if(s_debug_more){
#ifdef DAP_OS_LINUX
            struct in_addr l_in_daddr = { .s_addr = ((dap_os_iphdr_t*)l_pkt_out->data)->daddr };
#else
            struct in_addr l_in_daddr;
            l_in_daddr.s_addr = ((dap_os_iphdr_t*)l_pkt_out->data)->ip_dst.s_addr;
#endif
            char l_str_daddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &l_in_daddr, l_str_daddr, sizeof(l_in_daddr));
            log_it(L_INFO, "Sent packet (%zd bytes) to desitnation %s in own context", a_data_size, l_str_daddr);
        }
        s_tun_client_send_data_unsafe(l_ch_vpn_info->ch_vpn, l_pkt_out);
    } else {
        /* Shift it to other worker context */
        tun_socket_msg_t* l_msg = DAP_NEW_Z(tun_socket_msg_t);
        if (!l_msg) {
            log_it(L_CRITICAL, "Memory allocation error");
            DAP_DEL_Z(l_pkt_out);
            return false;
        }
        l_msg->type             = TUN_SOCKET_MSG_CH_VPN_SEND;
        l_msg->ch_vpn           = l_ch_vpn_info->ch_vpn;
        l_msg->esocket          = l_ch_vpn_info->esocket;
        l_msg->esocket_uuid     = l_ch_vpn_info->esocket_uuid;
        l_msg->ch_vpn_send.pkt  = DAP_DUP_SIZE(l_pkt_out, sizeof(l_pkt_out->header) + a_data_size);

        if (dap_events_socket_queue_ptr_send(l_ch_vpn_info->queue_msg, l_msg) != 0) {
            log_it(L_WARNING, "Error on sending packet to foreign context queue, lost %zd bytes", a_data_size);
            DAP_DELETE(l_msg->ch_vpn_send.pkt);
            DAP_DELETE(l_msg);
            DAP_DEL_Z(l_pkt_out);
            return false;
        }

        if (s_debug_more) {
#ifdef DAP_OS_LINUX
            struct in_addr l_in_daddr = { .s_addr = ((struct iphdr*)l_pkt_out->data)->daddr };
#else
            struct in_addr l_in_daddr = { .s_addr = ((struct ip*)l_pkt_out->data)->ip_dst.s_addr };
#endif
            char l_str_daddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &l_in_daddr, l_str_daddr, sizeof(l_in_daddr));
            log_it(L_INFO, "Sent packet (%zd bytes) to desitnation %s in foreign context", a_data_size, l_str_daddr);
        }
    }
    DAP_DEL_Z(l_pkt_out);
    return true;
}

/**
 * @brief s_tun_recv_msg_callback
 * @param a_esocket_queue
 * @param a_msg
 */
static void s_tun_recv_msg_callback(dap_events_socket_t * a_esocket_queue, void * a_msg )
{
    tun_socket_msg_t *l_msg = (tun_socket_msg_t*)a_msg;
    switch (l_msg->type) {
        case TUN_SOCKET_MSG_ESOCKET_REASSIGNED: {
            assert(l_msg->esocket_reassigment.worker_id < s_tun_sockets_count);
            dap_chain_net_srv_vpn_tun_socket_t* l_tun_sock = s_tun_sockets[a_esocket_queue->context->worker->id];
            assert(l_tun_sock);
            dap_chain_net_srv_ch_vpn_info_t* l_info = NULL;
            HASH_FIND(hh, l_tun_sock->clients, &l_msg->esocket_reassigment.addr, sizeof(l_msg->esocket_reassigment.addr), l_info);
            if (l_info) { // Updating info
                l_info->worker = dap_events_worker_get(l_msg->esocket_reassigment.worker_id);
                l_info->queue_msg = s_tun_sockets_queue_msg[l_msg->esocket_reassigment.worker_id];
                l_info->is_reassigned_once = true;
                l_info->is_on_this_worker = (a_esocket_queue->context->worker->id == l_msg->esocket_reassigment.worker_id);
                if (s_debug_more) {
                    char l_addrbuf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &l_msg->esocket_reassigment.addr, l_addrbuf, sizeof(l_addrbuf));
                    log_it(L_INFO, "Tun:%u message: addr %s reassign on worker #%u", a_esocket_queue->context->worker->id,
                        l_addrbuf, l_msg->esocket_reassigment.worker_id);
                }
            }
            else  if (dap_log_level_get() <= L_INFO) {
                char l_addrbuf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &l_msg->esocket_reassigment.addr, l_addrbuf, sizeof(l_addrbuf));
                log_it(L_INFO, "Reassigment message for address %s on worker %u comes but no such address was found on tun socket %u",
                    l_addrbuf, l_msg->esocket_reassigment.worker_id, a_esocket_queue->context->worker->id);
            }
        } break; /* l_msg->type == TUN_SOCKET_MSG_ESOCKET_REASSIGNED */

        case TUN_SOCKET_MSG_IP_ASSIGNED:{
            assert(l_msg->ip_assigment.worker_id < s_tun_sockets_count);
            dap_chain_net_srv_vpn_tun_socket_t * l_tun_sock = s_tun_sockets[a_esocket_queue->context->worker->id];
            assert(l_tun_sock);

            dap_chain_net_srv_ch_vpn_info_t * l_new_info = NULL;
            HASH_FIND(hh,l_tun_sock->clients,&l_msg->ip_assigment.addr, sizeof (l_msg->ip_assigment.addr), l_new_info);
            if( l_new_info){
                char l_addrbuf[INET_ADDRSTRLEN]= { [0]='\0'};
                inet_ntop(AF_INET,&l_msg->ip_assigment.addr, l_addrbuf, sizeof (l_addrbuf));
                log_it(L_WARNING, "Already assigned address %s on tun sock #%u", l_addrbuf, l_tun_sock->worker_id);
            }else{
                l_new_info                      = DAP_NEW_Z(dap_chain_net_srv_ch_vpn_info_t);
                if (!l_new_info) {
        log_it(L_CRITICAL, "Memory allocation error");
                    DAP_DELETE(l_msg);
                    return;
                }
                l_new_info->ch_vpn              = l_msg->ch_vpn;
                l_new_info->addr_ipv4           = l_msg->ip_assigment.addr;
                l_new_info->queue_msg           = s_tun_sockets_queue_msg[l_msg->ip_assigment.worker_id];
                l_new_info->usage_id            = l_msg->ip_assigment.usage_id;
                l_new_info->is_reassigned_once  = l_msg->is_reassigned_once;
                l_new_info->is_on_this_worker   = (l_msg->ip_assigment.worker_id == a_esocket_queue->context->worker->id);
                l_new_info->esocket             = l_msg->esocket;
                l_new_info->esocket_uuid        = l_msg->esocket_uuid;
                l_new_info->worker              = dap_events_worker_get(l_msg->ip_assigment.worker_id);
                HASH_ADD(hh,l_tun_sock->clients, addr_ipv4, sizeof (l_new_info->addr_ipv4), l_new_info);
                if (dap_log_level_get() <= L_INFO) {
                    char l_addrbuf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &l_msg->ip_assigment.addr, l_addrbuf, sizeof(l_addrbuf));
                    log_it(L_DEBUG, "Tun:%u message: addr %s assigned for worker #%u on tun #u", a_esocket_queue->context->worker->id,
                        l_addrbuf, l_msg->ip_assigment.worker_id);
                }
            }
        }break; /* l_msg->type == TUN_SOCKET_MSG_IP_ASSIGNED */

        case TUN_SOCKET_MSG_IP_UNASSIGNED:{
            assert(l_msg->ip_unassigment.worker_id < s_tun_sockets_count);
            dap_chain_net_srv_vpn_tun_socket_t *l_tun_sock = s_tun_sockets[a_esocket_queue->context->worker->id];
            assert(l_tun_sock);

            dap_chain_net_srv_ch_vpn_info_t *l_new_info = NULL;
            HASH_FIND(hh, l_tun_sock->clients, &l_msg->ip_unassigment.addr, sizeof(l_msg->ip_unassigment.addr), l_new_info);
            if( l_new_info){
                HASH_DELETE(hh, l_tun_sock->clients, l_new_info);
                DAP_DELETE(l_new_info);
                if( dap_log_level_get() <= L_INFO){
                    char l_addrbuf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &l_msg->ip_unassigment.addr, l_addrbuf, sizeof(l_addrbuf));
                    log_it(L_INFO, "Unassigned %s address from tun sock #%u", l_addrbuf, l_tun_sock->worker_id);
                }
            }else{
                char l_addrbuf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &l_msg->ip_unassigment.addr, l_addrbuf, sizeof(l_addrbuf));
                log_it(L_ERROR, "Can't find address %s on tun sock #%u to unassign it", l_addrbuf, l_tun_sock->worker_id);
            }
        }break; /* l_msg->type == TUN_SOCKET_MSG_IP_UNASSIGNED */

        case TUN_SOCKET_MSG_CH_VPN_SEND: {
            if (dap_context_find(a_esocket_queue->context->worker->context, l_msg->esocket_uuid) == l_msg->esocket) {
                s_tun_client_send_data_unsafe(l_msg->ch_vpn, l_msg->ch_vpn_send.pkt);
                if (s_debug_more) {
                    char l_addrbuf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &l_msg->ip_assigment.addr, l_addrbuf, sizeof(l_addrbuf));
                    log_it(L_DEBUG, "Tun:%u message: send %u bytes for ch vpn protocol",
                        a_esocket_queue->context->worker->id, l_msg->ch_vpn_send.pkt->header.op_data.data_size);
                }
            }
            else {
                log_it(L_ERROR, "MSG: No esocket %p on worker #%u, lost %d data",
                    l_msg->esocket, a_esocket_queue->context->worker->id, l_msg->ch_vpn_send.pkt->header.op_data.data_size);
            }
            DAP_DELETE(l_msg->ch_vpn_send.pkt);
        } break; /* l_msg->type == TUN_SOCKET_MSG_CH_VPN_SEND */

        default:
            log_it(L_ERROR, "Wrong tun socket message type %d", l_msg->type);
    }
    DAP_DELETE(l_msg);
}

/**
 * @brief s_tun_send_msg_ip_assigned
 * @param a_worker_id
 * @param a_ch_vpn
 * @param a_addr
 */
static void s_tun_send_msg_ip_assigned(uint32_t a_worker_own_id, uint32_t a_worker_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr )
{
    struct tun_socket_msg * l_msg = DAP_NEW_Z(struct tun_socket_msg);
    if (!l_msg) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    }
    l_msg->type = TUN_SOCKET_MSG_IP_ASSIGNED;
    l_msg->ch_vpn = a_ch_vpn;
    l_msg->esocket = a_ch_vpn->ch->stream->esocket;
    l_msg->esocket_uuid = a_ch_vpn->ch->stream->esocket->uuid;
    l_msg->is_reassigned_once = a_ch_vpn->ch->stream->esocket->was_reassigned;
    l_msg->ip_assigment.addr = a_addr;
    l_msg->ip_assigment.worker_id = a_ch_vpn->ch->stream_worker->worker->id;
    l_msg->ip_assigment.usage_id = a_ch_vpn->usage_id;
    if(a_worker_own_id != a_worker_id){
        if (dap_events_socket_queue_ptr_send(s_tun_sockets_queue_msg[a_worker_id], l_msg) != 0){
            log_it(L_WARNING, "Cant send new  ip assign message to the tun msg queue #%u", a_worker_id);
        }
    }else{ // We're sending on our own worker so lets just call the process callback
        s_tun_recv_msg_callback(s_tun_sockets_queue_msg[a_worker_id], l_msg);
    }
}

/**
 * @brief s_tun_send_msg_ip_assigned_all
 * @param a_ch_vpn
 * @param a_addr
 */
static void s_tun_send_msg_ip_assigned_all(uint32_t a_worker_own_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr)
{
    for (uint32_t i = 0; i < s_tun_sockets_count; i++)
        s_tun_send_msg_ip_assigned(a_worker_own_id, i, a_ch_vpn, a_addr);
}

/**
 * @brief s_tun_send_msg_ip_unassigned
 * @param a_worker_id
 * @param a_ch_vpn
 * @param a_addr
 */
static void s_tun_send_msg_ip_unassigned(uint32_t a_worker_own_id, uint32_t a_worker_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr)
{
    struct tun_socket_msg * l_msg = DAP_NEW_Z(struct tun_socket_msg);
    if (!l_msg) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    }
    l_msg->type = TUN_SOCKET_MSG_IP_UNASSIGNED;
    l_msg->ch_vpn = a_ch_vpn;
    l_msg->ip_unassigment.addr = a_addr;
    l_msg->ip_unassigment.worker_id = a_ch_vpn->ch->stream_worker->worker->id;
    l_msg->esocket = a_ch_vpn->ch->stream->esocket;
    l_msg->esocket_uuid = a_ch_vpn->ch->stream->esocket ? a_ch_vpn->ch->stream->esocket->uuid : 0;
    l_msg->is_reassigned_once = a_ch_vpn->ch->stream->esocket ? a_ch_vpn->ch->stream->esocket->was_reassigned : false;


    if( a_worker_own_id != a_worker_id){
        if ( dap_events_socket_queue_ptr_send(s_tun_sockets_queue_msg[a_worker_id], l_msg) != 0 ) {
            log_it(L_WARNING, "Cant send new ip unassign message to the tun msg queue #%u", a_worker_id);
        }
    }else{ // We're sending on our own worker so lets just call the process callback
        s_tun_recv_msg_callback(s_tun_sockets_queue_msg[a_worker_id], l_msg);
    }
}

/**
 * @brief s_tun_send_msg_ip_unassigned_all
 * @param a_worker_own_id Current worker's id to not to send message on it but process it unsafely at current context
 * @param a_ch_vpn
 * @param a_addr
 */
static void s_tun_send_msg_ip_unassigned_all(uint32_t a_worker_own_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr)
{
    for( uint32_t i=0; i< s_tun_sockets_count; i++)
        s_tun_send_msg_ip_unassigned(a_worker_own_id,i, a_ch_vpn, a_addr);
}

/**
 * @brief s_tun_send_msg_esocket_reassigned_inter
 * @param a_worker_own_id Current worker's id
 * @param a_tun_socket
 * @param a_ch_vpn
 * @param a_esocket
 * @param a_esocket_uuid
 * @param a_addr
 * @param a_esocket_worker_id
 */
static void s_tun_send_msg_esocket_reassigned_inter(uint32_t a_worker_own_id, dap_chain_net_srv_vpn_tun_socket_t * a_tun_socket,
                                                   dap_chain_net_srv_ch_vpn_t * a_ch_vpn, dap_events_socket_t * a_esocket,
                                                   dap_events_socket_uuid_t a_esocket_uuid, struct in_addr a_addr)
{
    struct tun_socket_msg * l_msg = DAP_NEW_Z(struct tun_socket_msg);
    if (!l_msg) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    }
    l_msg->type = TUN_SOCKET_MSG_ESOCKET_REASSIGNED ;
    l_msg->ch_vpn = a_ch_vpn;
    l_msg->esocket_reassigment.addr = a_addr;
    l_msg->esocket_reassigment.worker_id = a_worker_own_id;
    l_msg->esocket = a_esocket;
    l_msg->esocket_uuid = a_esocket_uuid;
    l_msg->is_reassigned_once = true;

    if (a_worker_own_id != a_tun_socket->worker_id){
        if (dap_events_socket_queue_ptr_send_to_input(a_tun_socket->queue_tun_msg_input[a_tun_socket->worker_id] , l_msg) != 0){
            log_it(L_WARNING, "Cant send esocket reassigment message to the tun msg queue #%u", a_tun_socket->worker_id );
        }else
            log_it(L_DEBUG,"Sent reassign message to tun:%u", a_tun_socket->worker_id);
    }else
        s_tun_recv_msg_callback(s_tun_sockets_queue_msg[a_tun_socket->worker_id], l_msg);
}

/**
 * @brief s_tun_send_msg_esocket_reassigned_all_inter
 * @param a_worker_own_id  Current worker id
 * @param a_ch_vpn
 * @param a_esocket
 * @param a_esocket_uuid
 * @param a_addr
 * @param a_worker_id
 */
static void s_tun_send_msg_esocket_reassigned_all_inter(uint32_t a_worker_own_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, dap_events_socket_t * a_esocket,
                                                       dap_events_socket_uuid_t a_esocket_uuid, struct in_addr a_addr)
{
    for( uint32_t i=0; i< s_tun_sockets_count; i++)
        s_tun_send_msg_esocket_reassigned_inter(a_worker_own_id, s_tun_sockets[i] , a_ch_vpn, a_esocket, a_esocket_uuid, a_addr);
}


/**
 * @brief s_tun_event_stream_create
 * @param a_worker
 * @param a_tun_fd
 * @return
 */
static dap_events_socket_t * s_tun_event_stream_create(dap_worker_t * a_worker, int a_tun_fd)
{
    assert(a_worker);
    dap_events_socket_callbacks_t l_s_callbacks = {
        .new_callback            = s_es_tun_new,
        .read_callback           = s_es_tun_read,
        .write_callback          = s_es_tun_write,
        .error_callback          = s_es_tun_error,
        .delete_callback         = s_es_tun_delete,
        .write_finished_callback = s_es_tun_write_finished
    };

    dap_events_socket_t * l_es = dap_events_socket_wrap_no_add( a_tun_fd, &l_s_callbacks);
    l_es->type = DESCRIPTOR_TYPE_FILE;
    l_es->no_close = true;
    dap_events_socket_assign_on_worker_mt(l_es, a_worker);

    return l_es;
}

/**
 * @brief s_vpn_tun_create
 * @param g_config
 * @return
 */
static int s_vpn_tun_create(dap_config_t * g_config)
{
    const char *c_addr = dap_config_get_item_str(g_config, "srv_vpn", "network_address");
    const char *c_mask = dap_config_get_item_str(g_config, "srv_vpn", "network_mask");
    if(!c_addr || !c_mask){
        log_it(L_CRITICAL, "Error while reading network parameters from config (network_address and network_mask)");
        DAP_DELETE((void*)c_addr);
        DAP_DELETE((void*)c_mask);
        return -1;
    }

    inet_aton(c_addr, &s_raw_server->ipv4_network_addr );
    inet_aton(c_mask, &s_raw_server->ipv4_network_mask );
    s_raw_server->ipv4_gw.s_addr= (s_raw_server->ipv4_network_addr.s_addr | 0x01000000);
    s_raw_server->ipv4_lease_last.s_addr = s_raw_server->ipv4_gw.s_addr;

#ifdef DAP_OS_DARWIN
    s_tun_sockets_count = 1;
#elif defined (DAP_OS_LINUX) || defined (DAP_OS_BSD)
// Not for Darwin
    s_tun_sockets_count = dap_get_cpu_count();
    memset(&s_raw_server->ifr, 0, sizeof(s_raw_server->ifr));
    s_raw_server->ifr.ifr_flags = IFF_TUN | IFF_MULTI_QUEUE| IFF_NO_PI;
    s_raw_server->auto_cpu_reassignment = dap_config_get_item_bool_default(g_config, "srv_vpn", "auto_cpu_reassignment", false);
#else
#error "Undefined tun create for your platform"
#endif
    log_it(L_NOTICE, "Auto cpu reassignment is set to '%s'", s_raw_server->auto_cpu_reassignment ? "true" : "false");
    log_it(L_INFO, "Trying to initialize multiqueue for %u workers", s_tun_sockets_count);
    s_tun_sockets = DAP_NEW_Z_SIZE(dap_chain_net_srv_vpn_tun_socket_t*,s_tun_sockets_count*sizeof(dap_chain_net_srv_vpn_tun_socket_t*));
    s_tun_sockets_queue_msg =  DAP_NEW_Z_SIZE(dap_events_socket_t*,s_tun_sockets_count*sizeof(dap_events_socket_t*));

    int l_err = 0;
#if defined (DAP_OS_DARWIN)
    // Prepare structs
    struct ctl_info l_ctl_info = {0};

    // Copy utun control name
    if (strlcpy(l_ctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(l_ctl_info.ctl_name))
            >= sizeof(l_ctl_info.ctl_name)){
        l_err = -100; // How its possible to came into this part? Idk
        log_it(L_ERROR,"UTUN_CONTROL_NAME \"%s\" too long", UTUN_CONTROL_NAME);
        goto lb_err;
    }

    // Create utun socket
    int l_tun_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if( l_tun_fd < 0){
        int l_errno = errno;
        char l_errbuf[256];
        strerror_r(l_errno, l_errbuf,sizeof(l_errbuf));
        log_it(L_ERROR,"Opening utun device control (SYSPROTO_CONTROL) error: '%s' (code %d)", l_errbuf, l_errno);
        l_err = -101;
        goto lb_err;
    }
    log_it(L_INFO, "Utun SYSPROTO_CONTROL descriptor obtained");
    s_raw_server->tun_ctl_fd = l_tun_fd;

    // Pass control structure to the utun socket
    if( ioctl(l_tun_fd, CTLIOCGINFO, &l_ctl_info ) < 0 ){
        int l_errno = errno;
        char l_errbuf[256];
        strerror_r(l_errno, l_errbuf,sizeof(l_errbuf));
        log_it(L_ERROR,"Can't execute ioctl(CTLIOCGINFO): '%s' (code %d)", l_errbuf, l_errno);
        l_err = -102;
        goto lb_err;

    }
    log_it(L_INFO, "Utun CTLIOCGINFO structure passed through ioctl");

    // Trying to connect with one of utunX devices
    int l_ret = -1;
    for(int l_unit = 0; l_unit < 256; l_unit++){
        struct sockaddr_ctl l_sa_ctl = {0};
        l_sa_ctl.sc_id = l_ctl_info.ctl_id;
        l_sa_ctl.sc_len = sizeof(l_sa_ctl);
        l_sa_ctl.sc_family = AF_SYSTEM;
        l_sa_ctl.ss_sysaddr = AF_SYS_CONTROL;
        l_sa_ctl.sc_unit = l_unit + 1;

        // If connect successful, new utunX device should be created
        l_ret = connect(l_tun_fd, (struct sockaddr *)&l_sa_ctl, sizeof(l_sa_ctl));
        if(l_ret == 0)
            break;
    }
    if (l_ret < 0){
        int l_errno = errno;
        char l_errbuf[256];
        strerror_r(l_errno, l_errbuf,sizeof(l_errbuf));
        log_it(L_ERROR,"Can't create utun device: '%s' (code %d)", l_errbuf, l_errno);
        l_err = -103;
        goto lb_err;

    }

    // Get iface name of newly created utun dev.
    log_it(L_NOTICE, "Utun device created");
    char l_utunname[20];
    socklen_t l_utunname_len = sizeof(l_utunname);
    if (getsockopt(l_tun_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, l_utunname, &l_utunname_len) ){
        int l_errno = errno;
        char l_errbuf[256];
        strerror_r(l_errno, l_errbuf,sizeof(l_errbuf));
        log_it(L_ERROR,"Can't get utun device name: '%s' (code %d)", l_errbuf, l_errno);
        l_err = -104;
        goto lb_err;
    }
    s_raw_server->tun_device_name = strndup(l_utunname, l_utunname_len);
    log_it(L_NOTICE, "Utun device name \"%s\"", s_raw_server->tun_device_name);
#endif

    pthread_mutex_lock(&s_tun_sockets_mutex_started);
    for( uint8_t i =0; i< s_tun_sockets_count; i++){
        dap_worker_t * l_worker = dap_events_worker_get(i);
        assert( l_worker );
#if !defined(DAP_OS_DARWIN) &&( defined (DAP_OS_LINUX) || defined (DAP_OS_BSD))
        int l_tun_fd;
        if( (l_tun_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0 ) {
            log_it(L_ERROR,"Opening /dev/net/tun error: '%s'", strerror(errno));
            l_err = -100;
            break;
        }
        log_it(L_DEBUG,"Opening /dev/net/tun:%u", i);
        if( (l_err = ioctl(l_tun_fd, TUNSETIFF, (void *)& s_raw_server->ifr)) < 0 ) {
            log_it(L_CRITICAL, "ioctl(TUNSETIFF) error: '%s' ",strerror(errno));
            close(l_tun_fd);
            break;
        }
        s_tun_deattach_queue(l_tun_fd);
        s_raw_server->tun_device_name = strdup(s_raw_server->ifr.ifr_name);
        s_raw_server->tun_fd = l_tun_fd;

#elif !defined (DAP_OS_DARWIN)
#error "Undefined tun interface attach for your platform"
#endif
        s_tun_event_stream_create(l_worker, l_tun_fd);
    }
    if (l_err) {
        pthread_mutex_unlock(&s_tun_sockets_mutex_started);
        goto lb_err;
    }

    // Waiting for all the tun sockets
    while (s_tun_sockets_started != s_tun_sockets_count)
        pthread_cond_wait(&s_tun_sockets_cond_started, &s_tun_sockets_mutex_started);
    pthread_mutex_unlock(&s_tun_sockets_mutex_started);

    // Fill inter tun qyueue
    // Create for all previous created sockets the input queue
    for (size_t n=0; n< s_tun_sockets_count; n++){
        dap_chain_net_srv_vpn_tun_socket_t * l_tun_socket = s_tun_sockets[n];
        dap_worker_t * l_worker = dap_events_worker_get(n);
        for (size_t k=0; k< s_tun_sockets_count; k++){
            dap_events_socket_t * l_queue_msg_input = dap_events_socket_queue_ptr_create_input( s_tun_sockets_queue_msg[n] );
            l_tun_socket->queue_tun_msg_input[k] = l_queue_msg_input;
            dap_events_socket_assign_on_worker_mt( l_queue_msg_input, l_worker );
        }
    }

    char buf[256], l_str_ipv4_gw[INET_ADDRSTRLEN], l_str_ipv4_netmask[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &s_raw_server->ipv4_gw, l_str_ipv4_gw, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &s_raw_server->ipv4_network_mask, l_str_ipv4_netmask, INET_ADDRSTRLEN);
    log_it(L_NOTICE, "Brought up %s virtual network interface (%s/%s)", s_raw_server->tun_device_name, l_str_ipv4_gw, l_str_ipv4_netmask);
#if defined (DAP_OS_ANDROID) || defined (DAP_OS_LINUX)
    snprintf(buf,sizeof(buf),"ip link set %s up", s_raw_server->tun_device_name);
    system(buf);
    snprintf(buf,sizeof(buf),"ip addr add %s/%s dev %s ", 
        l_str_ipv4_gw, l_str_ipv4_netmask, s_raw_server->tun_device_name);
    system(buf);
#elif defined (DAP_OS_DARWIN)
    snprintf(buf,sizeof(buf),"ifconfig %s %s %s up",s_raw_server->tun_device_name,
             inet_ntoa(s_raw_server->ipv4_gw),inet_ntoa(s_raw_server->ipv4_gw));
    system(buf);
    snprintf(buf,sizeof(buf),"route add -net %s -netmask %s -interface %s", inet_ntoa(s_raw_server->ipv4_gw),c_mask,s_raw_server->tun_device_name );
    system(buf);
#else
#error "Not defined for your platform"
#endif
lb_err:
    return l_err;
}

/**
* @brief s_vpn_tun_init
* @return
*/
static int s_vpn_tun_init()
{
    s_raw_server=DAP_NEW_Z(vpn_local_network_t);
    if (!s_raw_server) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    pthread_rwlock_init(&s_raw_server->rwlock, NULL);
    pthread_mutex_init(&s_raw_server->pkt_out_mutex,NULL);
    pthread_mutex_init(&s_tun_sockets_mutex_started, NULL);
    pthread_cond_init(&s_tun_sockets_cond_started, NULL);

    return 0;
}

/**
 * @brief s_vpn_service_create
 * @param g_config
 * @return
 */
static int s_vpn_service_create(dap_config_t * g_config)
{
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
    dap_chain_net_srv_callbacks_t l_srv_callbacks = {};
    l_srv_callbacks.requested = s_callback_requested;
    l_srv_callbacks.response_success = s_callback_response_success;
    l_srv_callbacks.response_error = s_callback_response_error;
    l_srv_callbacks.receipt_next_success = s_callback_receipt_next_success;
    l_srv_callbacks.get_remain_service = s_callback_get_remain_service;
    l_srv_callbacks.save_remain_service = s_callback_save_remain_service;


    dap_chain_net_srv_t* l_srv = dap_chain_net_srv_add(l_uid, "srv_vpn", &l_srv_callbacks);

    dap_chain_net_srv_vpn_t* l_srv_vpn  = DAP_NEW_Z( dap_chain_net_srv_vpn_t);
    if(!l_srv_vpn) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    l_srv->_internal = l_srv_vpn;
    l_srv_vpn->parent = l_srv;

    // Read if we need to dump all pkt operations
    s_debug_more= dap_config_get_item_bool_default(g_config,"srv_vpn", "debug_more",false);
    return 0;

}


/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @param g_config
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_vpn_init(dap_config_t * g_config) {
    s_vpn_tun_init();

    log_it(L_DEBUG,"Initializing TUN driver...");
    if(s_vpn_tun_create(g_config) != 0){
        log_it(L_CRITICAL, "Error initializing TUN device driver!");
        return -1;
    }

    log_it(L_INFO,"TUN driver configured successfuly");
    s_vpn_service_create(g_config);
    dap_stream_ch_proc_add(DAP_STREAM_CH_ID_NET_SRV_VPN, s_ch_vpn_new, s_ch_vpn_delete, s_ch_packet_in,
            s_ch_packet_out);

    // add console command to display vpn statistics
    dap_cli_server_cmd_add ("vpn_stat", com_vpn_statistics, "VPN statistics",
            "vpn_stat -net <net name> [-full]\n"
            );
    return 0;
}

/**
 * @brief ch_sf_deinit
 */
void dap_chain_net_srv_vpn_deinit(void)
{
    pthread_mutex_destroy(&s_tun_sockets_mutex_started);
    pthread_cond_destroy(&s_tun_sockets_cond_started);
    DAP_DELETE(s_srv_vpn_addr);
    DAP_DELETE(s_srv_vpn_mask);
    if(s_raw_server)
        DAP_DELETE(s_raw_server);
}

/**
 * Callback calls after successful request for service
 */
static int s_callback_requested(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t * a_srv_client
                                    , const void * a_custom_data, size_t a_custom_data_size )
{

    // TODO parse custom data like JSON or smth like this
    (void) a_custom_data;
    (void) a_custom_data_size;
    (void) a_srv;
    return 0; // aways allow to use it for now
}

/**
 * Called if responses success with all signature checks
 */
static int s_callback_response_success(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t * a_srv_client
                                    , const void * a_request, size_t a_request_size )
{
    int l_ret = 0;
    const dap_chain_datum_tx_receipt_t * l_receipt = (const dap_chain_datum_tx_receipt_t *) a_request;
    size_t l_receipt_size = a_request_size;
    log_it( L_INFO, "s_callback_response_success is called");

//    dap_stream_ch_chain_net_srv_pkt_request_t * l_request =  (dap_stream_ch_chain_net_srv_pkt_request_t *) a_request;
//    dap_chain_net_srv_stream_session_t * l_srv_session = (dap_chain_net_srv_stream_session_t *) a_srv_client->ch->stream->session->_inheritor;
    dap_chain_net_srv_stream_session_t * l_srv_session = (dap_chain_net_srv_stream_session_t *) a_srv_client->ch->stream->session->_inheritor;
    dap_chain_net_srv_usage_t * l_usage_active = l_srv_session->usage_active;// dap_chain_net_srv_usage_find_unsafe(l_srv_session,a_usage_id);
    dap_chain_net_srv_ch_vpn_t * l_srv_ch_vpn =(dap_chain_net_srv_ch_vpn_t*) a_srv_client->ch->stream->channel[DAP_CHAIN_NET_SRV_VPN_ID] ?
            a_srv_client->ch->stream->channel[DAP_CHAIN_NET_SRV_VPN_ID]->internal : NULL;
    if ( !l_usage_active){
        log_it( L_ERROR, "No active service usage, can't success");
        return -1;
    }

    if (!l_srv_session->usage_active->is_active){
        l_srv_session->usage_active = l_usage_active;
        l_srv_session->usage_active->is_active = true;
        log_it(L_NOTICE,"Enable VPN service");

        if ( l_srv_ch_vpn ){ // If channel is already opened
            dap_stream_ch_set_ready_to_read_unsafe( l_srv_ch_vpn->ch , true );
            l_srv_ch_vpn->usage_id = a_usage_id;
        } else{
            log_it(L_WARNING, "VPN channel is not open, will be no data transmission");
            return -2;
        }
    }

    // set start limits
    if(!l_usage_active->is_free && l_usage_active->receipt){
        remain_limits_save_arg_t *l_args = DAP_NEW_Z(remain_limits_save_arg_t);
        l_args->srv = a_srv;
        l_args->srv_client = a_srv_client;
        l_args->usage_id = a_usage_id;
        l_usage_active->timer_es_uuid = dap_timerfd_start_on_worker(l_usage_active->client->stream_worker->worker, 60 * 1000,
                                                             (dap_timerfd_callback_t)s_save_limits, l_args)->esocket_uuid;
        l_srv_session->limits_units_type.uint32 = l_usage_active->receipt->receipt_info.units_type.uint32;
        switch( l_usage_active->receipt->receipt_info.units_type.enm){
            case SERV_UNIT_DAY:{
                l_srv_session->last_update_ts = time(NULL);
                if (l_usage_active->is_grace || l_srv_session->limits_ts == 0)
                    l_srv_session->limits_ts = (time_t)l_usage_active->receipt->receipt_info.units*24*3600;
                log_it(L_INFO,"%"DAP_UINT64_FORMAT_U" seconds more for VPN usage", l_usage_active->receipt->receipt_info.units);
            } break;
            case SERV_UNIT_SEC:{
                l_srv_session->last_update_ts = time(NULL);
                if (!l_usage_active->is_grace && l_srv_session->limits_ts <= 0){
                    l_srv_session->limits_ts += (time_t)l_usage_active->receipt->receipt_info.units;
                    log_it(L_INFO,"%"DAP_UINT64_FORMAT_U" seconds more for VPN usage", l_usage_active->receipt->receipt_info.units);
                }
            } break;
            case SERV_UNIT_B:{
                if (l_usage_active->is_grace || l_srv_session->limits_bytes == 0)
                    l_srv_session->limits_bytes = (uintmax_t) l_usage_active->receipt->receipt_info.units;
                log_it(L_INFO,"%"DAP_UINT64_FORMAT_U" bytes more for VPN usage", l_usage_active->receipt->receipt_info.units);
            } break;
            case SERV_UNIT_KB:{
                if (l_usage_active->is_grace || l_srv_session->limits_bytes == 0)
                    l_srv_session->limits_bytes = 1000ull * ( (uintmax_t) l_usage_active->receipt->receipt_info.units);
                log_it(L_INFO,"%"DAP_UINT64_FORMAT_U" bytes more for VPN usage", l_usage_active->receipt->receipt_info.units);
            } break;
            case SERV_UNIT_MB:{
                if (l_usage_active->is_grace || l_srv_session->limits_bytes == 0)
                    l_srv_session->limits_bytes = 1000000ull * ( (uintmax_t) l_usage_active->receipt->receipt_info.units);
                log_it(L_INFO,"%"DAP_UINT64_FORMAT_U" bytes more for VPN usage", l_usage_active->receipt->receipt_info.units);
            } break;
            default: {
                log_it(L_WARNING, "VPN doesnt accept serv unit type 0x%08X", l_usage_active->receipt->receipt_info.units_type.uint32 );
                dap_stream_ch_set_ready_to_write_unsafe(l_usage_active->client->ch,false);
                dap_stream_ch_set_ready_to_read_unsafe(l_usage_active->client->ch,false);
                dap_stream_ch_pkt_write_unsafe(l_usage_active->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
            }
        }
    } else if (!l_usage_active->is_free && !l_usage_active->receipt && l_usage_active->is_grace){
        l_srv_session->last_update_ts = time(NULL);
    }

    return l_ret;
}



static int s_callback_receipt_next_success(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t * a_srv_client,
                    const void * a_receipt_next, size_t a_receipt_next_size)
{
    dap_chain_net_srv_stream_session_t * l_srv_session = (dap_chain_net_srv_stream_session_t *) a_srv_client->ch->stream->session->_inheritor;
    dap_chain_net_srv_ch_vpn_t * l_srv_ch_vpn =(dap_chain_net_srv_ch_vpn_t*) a_srv_client->ch->stream->channel[DAP_CHAIN_NET_SRV_VPN_ID] ?
            a_srv_client->ch->stream->channel[DAP_CHAIN_NET_SRV_VPN_ID]->internal : NULL;

    if ( ! l_srv_ch_vpn ){
        log_it(L_ERROR, "No VPN service stream channel, its closed?");
        return -3;
    }

    const dap_chain_datum_tx_receipt_t * l_receipt_next = (const dap_chain_datum_tx_receipt_t *) a_receipt_next;
    size_t l_receipt_next_size = a_receipt_next_size;



    log_it(L_INFO, "Next receipt successfuly accepted");
    // usage is present, we've accepted packets
    dap_stream_ch_set_ready_to_read_unsafe( l_srv_ch_vpn->ch , true );
    return 0;
}

/**
 * If error
 */
static int s_callback_response_error(dap_chain_net_srv_t * a_srv, uint32_t a_usage_id, dap_chain_net_srv_client_remote_t * a_srv_client
                                    , const void * a_custom_data, size_t a_custom_data_size )
{
    if (a_custom_data_size != sizeof (dap_stream_ch_chain_net_srv_pkt_error_t)){
        log_it(L_ERROR, "Wrong custom data size, must be %zd", sizeof(dap_stream_ch_chain_net_srv_pkt_error_t) );
        return -1;
    }
    dap_stream_ch_chain_net_srv_pkt_error_t * l_err = (dap_stream_ch_chain_net_srv_pkt_error_t *)a_custom_data;
    log_it(L_WARNING,"Response error code 0x%08X", l_err->code);
    return 0;
}

static dap_stream_ch_chain_net_srv_remain_service_store_t* s_callback_get_remain_service(dap_chain_net_srv_t * a_srv,  uint32_t a_usage_id,
                                         dap_chain_net_srv_client_remote_t * a_srv_client)
{
    UNUSED(a_srv);
    dap_chain_net_srv_stream_session_t * l_srv_session = a_srv_client && a_srv_client->ch && a_srv_client->ch->stream && a_srv_client->ch->stream->session ?
                                            (dap_chain_net_srv_stream_session_t *) a_srv_client->ch->stream->session->_inheritor : NULL;

    if (!l_srv_session){
        log_it(L_DEBUG, "Can't find srv session");
        return NULL;
    }
    dap_chain_net_srv_usage_t* l_usage = dap_chain_net_srv_usage_find_unsafe(l_srv_session, a_usage_id);
    if (!l_usage){
        log_it(L_DEBUG, "Can't find usage.");
        return NULL;
    }

    dap_chain_net_t *l_net = l_usage->net;

    // get remain units from DB
    char *l_remain_limits_gdb_group =  dap_strdup_printf( "local.srv_pay.%s.vpn_srv.remain_limits", l_net->pub.name);
    char *l_user_key = dap_chain_hash_fast_to_str_new(&l_usage->client_pkey_hash);
    log_it(L_DEBUG, "Checkout user %s in group %s", l_user_key, l_remain_limits_gdb_group);
    dap_stream_ch_chain_net_srv_remain_service_store_t* l_remain_service = NULL;
    size_t l_remain_service_size = 0;
    l_remain_service = (dap_stream_ch_chain_net_srv_remain_service_store_t*) dap_global_db_get_sync(l_remain_limits_gdb_group, l_user_key, &l_remain_service_size, NULL, NULL);
    DAP_DELETE(l_remain_limits_gdb_group);
    DAP_DELETE(l_user_key);
    return l_remain_service;
}

// Limits saving vrapper for timer callback
static bool s_save_limits(void* arg)
{
    remain_limits_save_arg_t *l_args = (remain_limits_save_arg_t *)arg;

    s_callback_save_remain_service(l_args->srv,  l_args->usage_id, l_args->srv_client);

    return true;
}

static int s_callback_save_remain_service(dap_chain_net_srv_t * a_srv,  uint32_t a_usage_id,
                                          dap_chain_net_srv_client_remote_t * a_srv_client)
{

    UNUSED(a_srv);
    dap_chain_net_srv_stream_session_t * l_srv_session = a_srv_client && a_srv_client->ch && a_srv_client->ch->stream && a_srv_client->ch->stream->session ?
                                            (dap_chain_net_srv_stream_session_t *) a_srv_client->ch->stream->session->_inheritor : NULL;

    if (!l_srv_session){
        log_it(L_DEBUG, "Can't find srv session");
        return -100;
    }
    dap_chain_net_srv_usage_t* l_usage = dap_chain_net_srv_usage_find_unsafe(l_srv_session, a_usage_id);
    if (!l_usage){
        log_it(L_DEBUG, "Can't find usage.");
        return -101;
    }

    if (l_usage->is_free || !l_usage->is_limits_changed)
        return -110;

    dap_chain_net_t *l_net = l_usage->net;

    // save remain units from DB
    char *l_remain_limits_gdb_group =  dap_strdup_printf( "local.srv_pay.%s.vpn_srv.remain_limits", l_net->pub.name);
    char *l_user_key = dap_chain_hash_fast_to_str_new(&l_usage->client_pkey_hash);
    log_it(L_DEBUG, "Save user %s remain service into group %s", l_user_key, l_remain_limits_gdb_group);

    dap_stream_ch_chain_net_srv_remain_service_store_t l_remain_service = {};

    l_remain_service.remain_units_type.enm = l_srv_session->limits_units_type.enm;
    switch(l_remain_service.remain_units_type.enm){
        case SERV_UNIT_SEC:
        case SERV_UNIT_DAY:
            l_remain_service.limits_ts = l_srv_session->limits_ts >= 0 ? l_srv_session->limits_ts : 0;
            if (l_srv_session->usage_active->receipt_next && !l_srv_session->usage_active->is_grace)
                l_remain_service.limits_ts += l_srv_session->usage_active->receipt_next->receipt_info.units;
            break;
        case SERV_UNIT_MB:
        case SERV_UNIT_KB:
        case SERV_UNIT_B:
            l_remain_service.limits_bytes = l_srv_session->limits_bytes >= 0 ? l_srv_session->limits_bytes : 0;
            if (l_srv_session->usage_active->receipt_next && !l_srv_session->usage_active->is_grace)
                l_remain_service.limits_bytes += l_srv_session->usage_active->receipt_next->receipt_info.units;
            break;
    }

    if(dap_global_db_set_sync(l_remain_limits_gdb_group, l_user_key, &l_remain_service, sizeof(l_remain_service), false))
    {
        DAP_DELETE(l_remain_limits_gdb_group);
        DAP_DELETE(l_user_key);
        return -102;
    }
    DAP_DELETE(l_remain_limits_gdb_group);
    DAP_DELETE(l_user_key);
    return 0;
}

static void s_ch_vpn_esocket_assigned(dap_events_socket_t *a_es, dap_worker_t *a_worker)
{
    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT(a_es);
    assert(l_http_client);
    dap_stream_t *l_stream = DAP_STREAM(l_http_client);
    if (!l_stream)
        return;
    dap_stream_ch_t *l_ch = l_stream->channel[DAP_CHAIN_NET_SRV_VPN_ID];
    if (!l_ch)
        return;
    dap_chain_net_srv_ch_vpn_t * l_ch_vpn = CH_VPN(l_ch);
    assert(l_ch_vpn);
    s_tun_send_msg_esocket_reassigned_all_inter(a_worker->id, l_ch_vpn, l_ch_vpn->ch->stream->esocket,
                                               l_ch_vpn->ch->stream->esocket_uuid, l_ch_vpn->addr_ipv4);
}


static void s_ch_vpn_esocket_unassigned(dap_events_socket_t* a_es, dap_worker_t * a_worker)
{
    dap_chain_net_srv_ch_vpn_t * l_ch_vpn =  CH_VPN(((dap_stream_ch_t*) a_es->_inheritor)); //!!! a_es->_inheritor = dap_http_client
//    dap_chain_net_srv_vpn_tun_socket_t * l_tun_sock = l_ch_vpn->tun_socket;

   //dap_chain_net_srv_ch_vpn_info_t * l_info = NULL;
   // HASH_FIND(hh,l_tun_sock->clients,&l_ch_vpn->addr_ipv4 , sizeof (l_ch_vpn->addr_ipv4), l_info);

    s_tun_send_msg_esocket_reassigned_all_inter(a_es->context->worker->id, l_ch_vpn, l_ch_vpn->ch->stream->esocket,
                                               l_ch_vpn->ch->stream->esocket_uuid, l_ch_vpn->addr_ipv4);
}


/**
 * @brief s_new Callback to constructor of object of Ch
 * @param ch
 * @param arg
 */
void s_ch_vpn_new(dap_stream_ch_t* a_ch, void* a_arg)
{
    (void) a_arg;
    a_ch->stream->esocket->flags |= DAP_SOCK_REASSIGN_ONCE; // We will try to reassign on another worker
                                                            // to use FlowControl if its present in system
                                                            // If not - we prevent jumping between workers with this trick
    a_ch->stream->esocket->callbacks.worker_assign_callback = s_ch_vpn_esocket_assigned;

    a_ch->internal = DAP_NEW_Z(dap_chain_net_srv_ch_vpn_t);
    if (!a_ch->internal) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    }
    dap_chain_net_srv_ch_vpn_t * l_srv_vpn = CH_VPN(a_ch);

    if(a_ch->stream->session->_inheritor == NULL && a_ch->stream->session != NULL)
        dap_chain_net_srv_stream_session_create(a_ch->stream->session);
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
    l_srv_vpn->net_srv = dap_chain_net_srv_get(l_uid);
    l_srv_vpn->ch = a_ch;

    dap_chain_net_srv_stream_session_t * l_srv_session = (dap_chain_net_srv_stream_session_t *) a_ch->stream->session->_inheritor;

    l_srv_vpn->usage_id = l_srv_session->usage_active ?  l_srv_session->usage_active->id : 0;
}




/**
 * @brief stream_sf_delete
 * @param ch
 * @param arg
 */
static void s_ch_vpn_delete(dap_stream_ch_t* a_ch, void* arg)
{
    (void) arg;
    dap_chain_net_srv_ch_vpn_t * l_ch_vpn = CH_VPN(a_ch);
    dap_chain_net_srv_vpn_t * l_srv_vpn =(dap_chain_net_srv_vpn_t *) l_ch_vpn->net_srv->_internal;

    // So complicated to update usage client to be sure that nothing breaks it
    usage_client_t * l_usage_client = NULL;

    dap_chain_net_srv_stream_session_t *l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION(l_ch_vpn->ch->stream->session);
    dap_timerfd_delete_mt(l_srv_session->usage_active->client->stream_worker->worker, l_srv_session->usage_active->timer_es_uuid);

    bool l_is_unleased = false;
    if ( l_ch_vpn->addr_ipv4.s_addr ){ // if leased address
        s_tun_send_msg_ip_unassigned_all(a_ch->stream_worker->worker->id,l_ch_vpn, l_ch_vpn->addr_ipv4); // Signal all the workers that we're switching off

        pthread_rwlock_wrlock(& s_raw_server_rwlock);
        if( s_raw_server){
            if ( s_raw_server->ipv4_lease_last.s_addr == l_ch_vpn->addr_ipv4.s_addr ){
                s_raw_server->ipv4_lease_last.s_addr = ntohl( ntohl(s_raw_server->ipv4_lease_last.s_addr)-1 );
            }
            else
                l_is_unleased = true;
        }
        pthread_rwlock_unlock(& s_raw_server_rwlock);
    }
    pthread_rwlock_wrlock(&s_clients_rwlock);
    if(s_ch_vpn_addrs) {
        HASH_DEL(s_ch_vpn_addrs, l_ch_vpn);
    }

    if ( l_is_unleased ){ // If unleased
        log_it(L_DEBUG, "Unlease address %s and store in treshold", inet_ntoa(l_ch_vpn->addr_ipv4));
        dap_chain_net_srv_vpn_item_ipv4_t * l_item_unleased = DAP_NEW_Z(dap_chain_net_srv_vpn_item_ipv4_t);
        if (!l_item_unleased) {
            log_it(L_CRITICAL, "Memory allocation error");
            pthread_rwlock_unlock(&s_clients_rwlock);
            return;
        }
        l_item_unleased->addr.s_addr = l_ch_vpn->addr_ipv4.s_addr;
        l_item_unleased->next = l_srv_vpn->ipv4_unleased;
        l_srv_vpn->ipv4_unleased = l_item_unleased;
    }

    pthread_rwlock_unlock(&s_clients_rwlock);

    l_ch_vpn->ch = NULL;
    l_ch_vpn->net_srv = NULL;
    l_ch_vpn->is_allowed =false;
    DAP_DEL_Z(a_ch->internal);
}

/**
 * @brief s_check_limits
 * @param a_ch
 * @param a_srv_session
 * @param a_usage
 * @param a_bytes
 */
static void s_update_limits(dap_stream_ch_t * a_ch ,
                           dap_chain_net_srv_stream_session_t * a_srv_session,
                           dap_chain_net_srv_usage_t * a_usage, size_t a_bytes)
{
    bool l_issue_new_receipt = false;
    // Check if there are time limits

    if (a_usage->is_free || (!a_usage->receipt && !a_usage->is_grace) || !a_usage->is_active)
        return;

    if (a_usage->is_grace && !a_usage->receipt){
        a_srv_session->limits_bytes -= (intmax_t) a_bytes;
        a_srv_session->limits_ts -= time(NULL) - a_srv_session->last_update_ts;
        a_srv_session->last_update_ts = time(NULL);
        return;
    }

    if (a_usage->receipt->receipt_info.units_type.enm == SERV_UNIT_DAY ||
        a_usage->receipt->receipt_info.units_type.enm == SERV_UNIT_SEC){
        time_t l_current_limit_ts = 0;

        switch( a_usage->receipt->receipt_info.units_type.enm){
            case SERV_UNIT_DAY:{
                l_current_limit_ts = (time_t)a_usage->receipt->receipt_info.units*24*3600;
            } break;
            case SERV_UNIT_SEC:{
                l_current_limit_ts = (time_t)a_usage->receipt->receipt_info.units;
            }
        }

        a_srv_session->limits_ts -= time(NULL) - a_srv_session->last_update_ts;
        a_usage->is_limits_changed = true;

        if(a_srv_session->limits_ts < l_current_limit_ts/2 && !a_usage->receipt_next && !a_usage->is_grace){
            l_issue_new_receipt = true;
        }
        a_srv_session->last_update_ts = time(NULL);


        if( a_srv_session->limits_ts <= 0 && !a_usage->is_grace){
            log_it(L_INFO, "Limits by timestamp are over. Switch to the next receipt");
            DAP_DEL_Z(a_usage->receipt);
            a_usage->receipt = a_usage->receipt_next;
            a_usage->receipt_next = NULL;
            if ( a_usage->receipt){ // If there is next receipt add the time and request the next receipt
                a_srv_session->limits_units_type.uint32 = a_usage->receipt->receipt_info.units_type.uint32;
                switch( a_usage->receipt->receipt_info.units_type.enm){
                case SERV_UNIT_DAY:{
                    a_srv_session->limits_ts += (time_t)a_usage->receipt->receipt_info.units*24*3600;
                    log_it(L_INFO,"%"DAP_UINT64_FORMAT_U" days more for VPN usage", a_usage->receipt->receipt_info.units);
                } break;
                case SERV_UNIT_SEC:{
                    a_srv_session->limits_ts += (time_t)a_usage->receipt->receipt_info.units;
                    log_it(L_INFO,"%"DAP_UINT64_FORMAT_U" seconds more for VPN usage", a_srv_session->limits_ts);
                } break;
                default: {
                    log_it(L_WARNING, "VPN doesnt accept serv unit type 0x%08X for limits_ts", a_usage->receipt->receipt_info.units_type.uint32 );
                    dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
                    dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
                    dap_stream_ch_pkt_write_unsafe( a_usage->client->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
                }
                }
            }else if (!a_usage->is_grace){
                log_it( L_NOTICE, "No activate receipt in usage, switch off write callback for channel");
                dap_stream_ch_chain_net_srv_pkt_error_t l_err = { };
                l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_CANT_FIND ;
                dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
                dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
                dap_stream_ch_pkt_write_unsafe( a_usage->client->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , &l_err, sizeof(l_err));
            }
        }
    }else if ( a_usage->receipt->receipt_info.units_type.enm == SERV_UNIT_B ||
               a_usage->receipt->receipt_info.units_type.enm == SERV_UNIT_KB ||
               a_usage->receipt->receipt_info.units_type.enm == SERV_UNIT_MB ){
        intmax_t current_limit_bytes = 0;
        if ( a_usage->receipt){// if we have active receipt and a_srv_session->last_update_ts == 0 then we counts units by traffic
            switch( a_usage->receipt->receipt_info.units_type.enm){
            case SERV_UNIT_B:{
                current_limit_bytes = (uintmax_t) a_usage->receipt->receipt_info.units;
            } break;
            case SERV_UNIT_KB:{
                current_limit_bytes = 1000ull * ( (uintmax_t) a_usage->receipt->receipt_info.units);
            } break;
            case SERV_UNIT_MB:{
                current_limit_bytes = 1000000ull * ( (uintmax_t) a_usage->receipt->receipt_info.units);
            } break;
            }
        }


        a_srv_session->limits_bytes -= (intmax_t) a_bytes;
        a_usage->is_limits_changed = true;
        if (a_srv_session->limits_bytes && a_srv_session->limits_bytes < current_limit_bytes/2 && ! a_usage->receipt_next){
            l_issue_new_receipt = true;
        }

        if (a_srv_session->limits_bytes <= 0  && !a_usage->is_grace){
            log_it(L_INFO, "Limits by traffic is over. Switch to the next receipt");
            DAP_DEL_Z(a_usage->receipt);
            a_usage->receipt = a_usage->receipt_next;
            a_usage->receipt_next = NULL;
            if ( a_usage->receipt){ // If there is next receipt add the time and request the next receipt
                a_srv_session->limits_units_type.uint32 = a_usage->receipt->receipt_info.units_type.uint32;
                switch( a_usage->receipt->receipt_info.units_type.enm){
                case SERV_UNIT_B:{
                    a_srv_session->limits_bytes +=  (uintmax_t) a_usage->receipt->receipt_info.units;
                    log_it(L_INFO,"%"DAP_UINT64_FORMAT_U" bytes more for VPN usage", a_usage->receipt->receipt_info.units);
                } break;
                case SERV_UNIT_KB:{
                    a_srv_session->limits_bytes += 1000ull * ( (uintmax_t) a_usage->receipt->receipt_info.units);
                    log_it(L_INFO,"%"DAP_UINT64_FORMAT_U" bytes more for VPN usage", a_usage->receipt->receipt_info.units);
                } break;
                case SERV_UNIT_MB:{
                    a_srv_session->limits_bytes += 1000000ull * ( (uintmax_t) a_usage->receipt->receipt_info.units);
                    log_it(L_INFO,"%"DAP_UINT64_FORMAT_U" bytes more for VPN usage", a_usage->receipt->receipt_info.units);
                } break;
                default: {
                    log_it(L_WARNING, "VPN doesnt accept serv unit type 0x%08X for limits_bytes", a_usage->receipt->receipt_info.units_type.uint32 );
                    dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
                    dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
                    dap_stream_ch_pkt_write_unsafe( a_usage->client->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
                }
                }
            }else if (!a_usage->is_grace){
                log_it( L_NOTICE, "No activate receipt in usage, switch off write callback for channel");
                dap_stream_ch_chain_net_srv_pkt_error_t l_err = { };
                l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_RECEIPT_CANT_FIND ;
                dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
                dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
                dap_stream_ch_pkt_write_unsafe( a_usage->client->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , &l_err, sizeof(l_err));
            }
        }

    }
    // If issue new receipt
    if ( l_issue_new_receipt && !dap_hash_fast_is_blank(&a_usage->tx_cond_hash)) {
        if ( a_usage->receipt){
            log_it( L_NOTICE, "Send next receipt to sign");
            a_usage->receipt_next = dap_chain_net_srv_issue_receipt(a_usage->service, a_usage->price, NULL, 0);
            dap_stream_ch_pkt_write_unsafe(a_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST,
                                           a_usage->receipt_next, a_usage->receipt_next->size);
        }
    }

}


static void send_pong_pkt(dap_stream_ch_t* a_ch)
{
//    log_it(L_DEBUG,"---------------------------------- PONG!");
    ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
    if (!pkt_out) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    }
    pkt_out->header.op_code = VPN_PACKET_OP_CODE_PONG;

    dap_stream_ch_pkt_write_unsafe(a_ch, 'd', pkt_out,
            pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
    dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
    DAP_DELETE(pkt_out);
}

/**
 * @brief s_ch_packet_in_vpn_address_request
 * @param a_ch
 * @param a_usage
 */
static void s_ch_packet_in_vpn_address_request(dap_stream_ch_t* a_ch, dap_chain_net_srv_usage_t * a_usage){
    dap_chain_net_srv_ch_vpn_t         *l_ch_vpn = CH_VPN(a_ch);
    dap_chain_net_srv_vpn_t            *l_srv_vpn = (dap_chain_net_srv_vpn_t*)a_usage->service->_internal;
    dap_chain_net_srv_stream_session_t *l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION(l_ch_vpn->ch->stream->session);

    if (! s_raw_server)
        return;

    if ( l_ch_vpn->addr_ipv4.s_addr ) {
        log_it(L_WARNING, "IP address is already leased");
        ch_vpn_pkt_t* pkt_out           = DAP_NEW_STACK_SIZE(ch_vpn_pkt_t, sizeof(pkt_out->header));
        if (!pkt_out) {
            log_it(L_CRITICAL, "Memory allocation error");
            return;
        }
        pkt_out->header.op_code         = VPN_PACKET_OP_CODE_PROBLEM;
        pkt_out->header.sock_id         = s_raw_server->tun_fd;
        pkt_out->header.usage_id        = a_usage->id;
        pkt_out->header.op_problem.code = VPN_PROBLEM_CODE_ALREADY_ASSIGNED_ADDR;

        size_t l_data_to_write = /*pkt_out->header.op_data.data_size +*/ sizeof(pkt_out->header);
        size_t l_data_wrote = dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA,
            pkt_out, l_data_to_write);
        l_srv_session->stats.bytes_sent += l_data_wrote;
        if (l_data_wrote < l_data_to_write) {
            log_it(L_WARNING, "Buffer overflow: can't send packet with VPN_PROBLEM_CODE_ALREADY_ASSIGNED_ADDR: sent only %zd from %zd",
                l_data_wrote, l_data_to_write);
            l_srv_session->stats.bytes_sent_lost += l_data_to_write - l_data_wrote;
            l_srv_session->stats.packets_sent_lost++;
        }else{
            l_srv_session->stats.packets_sent++;
        }
        return;
    }
    dap_chain_net_srv_vpn_item_ipv4_t* l_item_ipv4 = l_srv_vpn->ipv4_unleased;
    if (l_item_ipv4) {
        log_it(L_WARNING, "Found a recently unleased IP address");
        l_ch_vpn->addr_ipv4.s_addr = l_item_ipv4->addr.s_addr;
        pthread_rwlock_wrlock( &s_clients_rwlock );
        HASH_ADD(hh, s_ch_vpn_addrs, addr_ipv4, sizeof (l_ch_vpn->addr_ipv4), l_ch_vpn);
        pthread_rwlock_unlock( &s_clients_rwlock );

        ch_vpn_pkt_t *l_pkt_out = DAP_NEW_STACK_SIZE(ch_vpn_pkt_t,
                sizeof(l_pkt_out->header) + sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_network_addr));
        l_pkt_out->header.sock_id           = s_raw_server->tun_fd;
        l_pkt_out->header.op_code           = VPN_PACKET_OP_CODE_VPN_ADDR_REPLY;
        l_pkt_out->header.usage_id          = a_usage->id;
        l_pkt_out->header.op_data.data_size = sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_gw);

        memcpy(l_pkt_out->data, &l_ch_vpn->addr_ipv4, sizeof(l_ch_vpn->addr_ipv4));
        memcpy(l_pkt_out->data + sizeof(l_ch_vpn->addr_ipv4), &s_raw_server->ipv4_gw ,
                sizeof(s_raw_server->ipv4_gw));

        size_t l_data_to_write = l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header);
        size_t l_data_wrote = dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA , l_pkt_out,
                l_data_to_write);
        l_srv_session->stats.bytes_sent += l_data_wrote;
        if (l_data_wrote < l_data_to_write){
            log_it(L_WARNING, "Buffer overflow: can't send packet with VPN_PACKET_OP_CODE_VPN_ADDR_REPLY: sent only %zd from %zd",
                    l_data_wrote,l_data_to_write );
            l_srv_session->stats.bytes_sent_lost += l_data_to_write - l_data_wrote;
            l_srv_session->stats.packets_sent_lost++;
        } else {
            char    l_str_ipv4addr[INET_ADDRSTRLEN],
                    l_str_ipv4gw[INET_ADDRSTRLEN],
                    l_str_ipv4mask[INET_ADDRSTRLEN],
                    l_str_ipv4netaddr[INET_ADDRSTRLEN],
                    l_str_ipv4last[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &l_ch_vpn->addr_ipv4, l_str_ipv4addr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &s_raw_server->ipv4_gw, l_str_ipv4gw, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &s_raw_server->ipv4_network_mask, l_str_ipv4mask, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &s_raw_server->ipv4_network_addr, l_str_ipv4netaddr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &s_raw_server->ipv4_lease_last, l_str_ipv4last, INET_ADDRSTRLEN);

            log_it(L_INFO, "VPN client IP address %s leased"
                    "\r\n\tnet gateway %s"
                    "\r\n\tnet mask %s"
                    "\r\n\tgw %s"
                    "\r\n\tlast_addr %s"
                    , l_str_ipv4addr
                    , l_str_ipv4gw
                    , l_str_ipv4mask
                    , l_str_ipv4netaddr
                    , l_str_ipv4last);

            l_srv_vpn->ipv4_unleased = l_item_ipv4->next;
            DAP_DEL_Z(l_item_ipv4);
            l_srv_session->stats.packets_sent++;
            s_tun_send_msg_ip_assigned_all(a_ch->stream_worker->worker->id, l_ch_vpn, l_ch_vpn->addr_ipv4);
        }
    }else{
        struct in_addr n_addr = { 0 }, n_addr_max;
        n_addr.s_addr = ntohl(s_raw_server->ipv4_lease_last.s_addr);
        n_addr.s_addr++;
        n_addr_max.s_addr = (ntohl(s_raw_server->ipv4_gw.s_addr)
                             | ~ntohl(s_raw_server->ipv4_network_mask.s_addr));

        //  Just for log output we revert it back and forward
        n_addr.s_addr = htonl(n_addr.s_addr);
        n_addr_max.s_addr = htonl(n_addr_max.s_addr);

        char l_str_naddr[INET_ADDRSTRLEN], l_str_naddr_max[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &n_addr, l_str_naddr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &n_addr_max, l_str_naddr_max, INET_ADDRSTRLEN);

        log_it(L_DEBUG, "\tnew_address         = %s"
                        "\r\n\tnew_address_max = %s"
               , l_str_naddr, l_str_naddr_max);

        n_addr.s_addr = ntohl(n_addr.s_addr);
        n_addr_max.s_addr = ntohl(n_addr_max.s_addr);
        if(n_addr.s_addr <= n_addr_max.s_addr) {
            n_addr.s_addr = htonl(n_addr.s_addr);
            n_addr_max.s_addr = htonl(n_addr_max.s_addr);

            s_raw_server->ipv4_lease_last.s_addr =n_addr.s_addr;
            a_ch->stream->session->tun_client_addr.s_addr = n_addr.s_addr;
            l_ch_vpn->addr_ipv4.s_addr = n_addr.s_addr;

            char    l_str_ipv4gw[INET_ADDRSTRLEN],
                    l_str_ipv4mask[INET_ADDRSTRLEN],
                    l_str_ipv4netaddr[INET_ADDRSTRLEN],
                    l_str_ipv4last[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &s_raw_server->ipv4_gw, l_str_ipv4gw, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &s_raw_server->ipv4_network_mask, l_str_ipv4mask, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &s_raw_server->ipv4_network_addr, l_str_ipv4netaddr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &s_raw_server->ipv4_lease_last, l_str_ipv4last, INET_ADDRSTRLEN);

            log_it(L_INFO, "VPN client new IP address %s leased"
                    "\r\n\tgateway %s"
                    "\r\n\tnet mask %s"
                    "\r\n\tnet addr %s"
                    "\r\n\tlast_addr %s"
                    , l_str_naddr
                    , l_str_ipv4gw
                    , l_str_ipv4mask
                    , l_str_ipv4netaddr
                    , l_str_ipv4last);

            pthread_rwlock_wrlock( &s_clients_rwlock );
            HASH_ADD(hh, s_ch_vpn_addrs, addr_ipv4, sizeof (l_ch_vpn->addr_ipv4), l_ch_vpn);
            pthread_rwlock_unlock( &s_clients_rwlock );

            ch_vpn_pkt_t *pkt_out = DAP_NEW_STACK_SIZE(ch_vpn_pkt_t,
                    sizeof(pkt_out->header) + sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_gw));
            pkt_out->header.sock_id             = s_raw_server->tun_fd;
            pkt_out->header.op_code             = VPN_PACKET_OP_CODE_VPN_ADDR_REPLY;
            pkt_out->header.op_data.data_size   = sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_gw);
            pkt_out->header.usage_id            = a_usage->id;

            memcpy(pkt_out->data, &l_ch_vpn->addr_ipv4, sizeof(l_ch_vpn->addr_ipv4));
            memcpy(pkt_out->data + sizeof(l_ch_vpn->addr_ipv4), &s_raw_server->ipv4_gw,
                    sizeof(s_raw_server->ipv4_gw));

            size_t l_data_to_write = pkt_out->header.op_data.data_size + sizeof(pkt_out->header);
            size_t l_data_wrote = dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out,
                                       l_data_to_write);
            l_srv_session->stats.bytes_sent += l_data_wrote;
            if (l_data_wrote < l_data_to_write){
                log_it(L_WARNING, "Buffer overflow: can't send packet with VPN_PACKET_OP_CODE_VPN_ADDR_REPLY: sent only %zd from %zd",
                        l_data_wrote,l_data_to_write );
                l_srv_session->stats.bytes_sent_lost += l_data_to_write - l_data_wrote;
                l_srv_session->stats.packets_sent_lost++;
            } else {
                l_srv_session->stats.packets_sent++;
                s_tun_send_msg_ip_assigned_all(a_ch->stream_worker->worker->id,l_ch_vpn, l_ch_vpn->addr_ipv4);
            }
        } else { // All the network is filled with clients, can't lease a new address
            log_it(L_ERROR, "No free IP address left, can't lease one...");
            ch_vpn_pkt_t* pkt_out           = DAP_NEW_STACK_SIZE(ch_vpn_pkt_t, sizeof(pkt_out->header));
            pkt_out->header.sock_id         = s_raw_server->tun_fd;
            pkt_out->header.op_code         = VPN_PACKET_OP_CODE_PROBLEM;
            pkt_out->header.usage_id        = a_usage->id;
            pkt_out->header.op_problem.code = VPN_PROBLEM_CODE_NO_FREE_ADDR;
            size_t l_data_to_write = /*pkt_out->header.op_data.data_size +*/ sizeof(pkt_out->header);
            size_t l_data_wrote = dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out, l_data_to_write);
            l_srv_session->stats.bytes_sent += l_data_wrote;
            if (l_data_wrote < l_data_to_write) {
                log_it(L_WARNING, "Buffer overflow: can't send packet with VPN_PACKET_OP_CODE_PROBLEM: sent only %zd from %zd",
                    l_data_wrote, l_data_to_write);
                l_srv_session->stats.bytes_sent_lost += l_data_to_write - l_data_wrote;
                l_srv_session->stats.packets_sent_lost++;
            } else {
                l_srv_session->stats.packets_sent++;
            }
        }
    }
}

/**
 * @brief stream_sf_packet_in
 * @param ch
 * @param arg
 */
void s_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg)
{
    dap_stream_ch_pkt_t * l_pkt = (dap_stream_ch_pkt_t *) a_arg;
    dap_chain_net_srv_stream_session_t * l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION (a_ch->stream->session );
    dap_chain_net_srv_ch_vpn_t *l_ch_vpn = CH_VPN(a_ch);
    dap_chain_net_srv_usage_t * l_usage = l_srv_session->usage_active;// dap_chain_net_srv_usage_find_unsafe(l_srv_session,  l_ch_vpn->usage_id);

    if ( ! l_usage){
        log_it(L_NOTICE, "No active usage in list, possible disconnected. Send nothing on this channel");
        dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
        return;
    }

    if ( ! l_usage->is_active ){
        log_it(L_INFO, "Usage inactivation: switch off packet input & output channels");
        if (l_usage->client)
            dap_stream_ch_pkt_write_unsafe( l_usage->client->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
        dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
        return;
    }
    // check role
    if (dap_chain_net_get_role(l_usage->net).enums < NODE_ROLE_MASTER) { 
        log_it(L_ERROR, 
            "You can't provide service with ID %X in net %s. Node role should be not lower than master\n", 
            l_usage->service->uid.uint64, l_usage->net->pub.name
            );
        if (l_usage->client)
            dap_stream_ch_pkt_write_unsafe( l_usage->client->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
        dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
        return;
    }

    // TODO move address leasing to this structure
    //dap_chain_net_srv_vpn_t * l_srv_vpn =(dap_chain_net_srv_vpn_t *) l_usage->service->_internal;

    ch_vpn_pkt_t * l_vpn_pkt = (ch_vpn_pkt_t *) l_pkt->data;
    size_t l_vpn_pkt_size = l_pkt->hdr.data_size - sizeof (l_vpn_pkt->header);

    debug_if(s_debug_more, L_INFO, "Got srv_vpn packet with op_code=0x%02x", l_vpn_pkt->header.op_code);

    if(l_vpn_pkt->header.op_code >= 0xb0) { // Raw packets
        switch (l_vpn_pkt->header.op_code) {
            case VPN_PACKET_OP_CODE_PING:
                a_ch->stream->esocket->last_ping_request = time(NULL);
                l_srv_session->stats.bytes_recv += l_vpn_pkt_size;
                l_srv_session->stats.packets_recv++;
                send_pong_pkt(a_ch);
            break;
            case VPN_PACKET_OP_CODE_PONG:
                a_ch->stream->esocket->last_ping_request = time(NULL);
                l_srv_session->stats.bytes_recv += l_vpn_pkt_size;
                l_srv_session->stats.packets_recv++;
            break;
            // for client
            case VPN_PACKET_OP_CODE_VPN_ADDR_REPLY: { // Assigned address for peer
                if(ch_sf_tun_addr_leased(CH_VPN(a_ch), l_vpn_pkt, l_vpn_pkt_size) < 0) {
                    log_it(L_ERROR, "Can't create tun");
                }else
                    s_tun_send_msg_ip_assigned_all(a_ch->stream_worker->worker->id, CH_VPN(a_ch), CH_VPN(a_ch)->addr_ipv4);
                l_srv_session->stats.bytes_recv += l_vpn_pkt_size;
                l_srv_session->stats.packets_recv++;
            } break;
            // for server
            case VPN_PACKET_OP_CODE_VPN_ADDR_REQUEST: { // Client request after L3 connection the new IP address
                log_it(L_INFO, "Received address request  ");
                if(s_raw_server){
                    s_ch_packet_in_vpn_address_request(a_ch, l_usage);
                }else{
                    dap_stream_ch_chain_net_srv_pkt_error_t l_err={0};
                    l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_IN_CLIENT_MODE;
                    dap_stream_ch_pkt_write_unsafe( l_usage->client->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR,
                                                    &l_err, sizeof (l_err));
                }
                l_srv_session->stats.bytes_recv += l_vpn_pkt_size;
                l_srv_session->stats.packets_recv++;
            } break;
            // for client only
            case VPN_PACKET_OP_CODE_VPN_RECV:{
                a_ch->stream->esocket->last_ping_request = time(NULL); // not ping, but better  ;-)
                dap_events_socket_t *l_es = dap_chain_net_vpn_client_tun_get_esock();
                // Find tun socket for current worker
                dap_chain_net_srv_vpn_tun_socket_t *l_tun =  l_es ? l_es->_inheritor : NULL; //!!! a_es->_inheritor = dap_stream_t
                //ch_sf_tun_socket_t * l_tun = s_tun_sockets[a_ch->stream_worker->worker->id];
                assert(l_tun);
                size_t l_ret = dap_events_socket_write_unsafe(l_tun->es, l_vpn_pkt->data, l_vpn_pkt->header.op_data.data_size);
                l_srv_session->stats.bytes_sent += l_ret;
                if (l_ret == l_vpn_pkt->header.op_data.data_size) {
                    l_srv_session->stats.packets_sent++;
                } else if (l_ret > 0) {
                    log_it (L_WARNING, "Lost %zd bytes, buffer overflow", l_vpn_pkt->header.op_data.data_size - l_ret);
                    l_srv_session->stats.bytes_sent_lost += (l_vpn_pkt->header.op_data.data_size - l_ret);
                    l_srv_session->stats.packets_sent_lost++;
                }
            } break;

            // for server only
            case VPN_PACKET_OP_CODE_VPN_SEND: {
                dap_chain_net_srv_vpn_tun_socket_t *l_tun = s_tun_sockets[a_ch->stream_worker->worker->id];
                assert(l_tun);
                size_t l_ret = dap_events_socket_write_unsafe(l_tun->es, l_vpn_pkt,
                    sizeof(l_vpn_pkt->header) + l_vpn_pkt->header.op_data.data_size) - sizeof(l_vpn_pkt->header);
                l_srv_session->stats.bytes_sent += l_ret;
                s_update_limits(a_ch, l_srv_session, l_usage, l_ret);
                if (l_ret == l_vpn_pkt->header.op_data.data_size) {
                    l_srv_session->stats.packets_sent++;
                }
                else if (l_ret > 0) {
                    log_it(L_WARNING, "Lost %zd bytes, buffer overflow", l_vpn_pkt->header.op_data.data_size - l_ret);
                    l_srv_session->stats.bytes_sent_lost += (l_vpn_pkt->header.op_data.data_size - l_ret);
                    l_srv_session->stats.packets_sent_lost++;
                }
            } break;
            default:
                log_it(L_WARNING, "Can't process SF type 0x%02x", l_vpn_pkt->header.op_code);
        }
    }
}

/**
 * @brief stream_sf_packet_out Packet Out Ch callback
 * @param ch
 * @param arg
 */
static void s_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg)
{
    (void) a_arg;
    dap_chain_net_srv_stream_session_t * l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION( a_ch->stream->session );
    dap_chain_net_srv_ch_vpn_t *l_ch_vpn = CH_VPN(a_ch);

    dap_chain_net_srv_usage_t * l_usage = l_srv_session->usage_active;// dap_chain_net_srv_usage_find_unsafe(l_srv_session,  l_ch_vpn->usage_id);
    if ( ! l_usage){
        log_it(L_NOTICE, "No active usage in list, possible disconnected. Send nothing on this channel");
        dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
        return;
    }

    if ( ! l_usage->is_active ){
        log_it(L_INFO, "Usage inactivation: switch off packet input & output channels");
        if (l_usage->client)
            dap_stream_ch_pkt_write_unsafe( l_usage->client->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
        dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
        return;
    }
    if ( (! l_usage->is_free) && (! l_usage->receipt && !l_usage->is_grace) ){
        log_it(L_WARNING, "No active receipt, switching off");
        if (l_usage->client)
            dap_stream_ch_pkt_write_unsafe( l_usage->client->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
        dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
        return;
    }
    // Check for empty buffer out here to prevent warnings in worker
    if ( ! a_ch->stream->esocket->buf_out_size )
        dap_events_socket_set_writable_unsafe(a_ch->stream->esocket,false);

}

/**
 * @brief m_es_tun_delete
 * @param a_es
 * @param arg
 */
static void s_es_tun_delete(dap_events_socket_t * a_es, void * arg)
{
    (void) arg;
    if (a_es->context->worker) {
        s_tun_sockets[a_es->context->worker->id] = NULL;
        dap_events_socket_remove_and_delete_unsafe(s_tun_sockets_queue_msg[a_es->context->worker->id],false);
        log_it(L_NOTICE,"Destroyed TUN event socket");
    }
}

/**
 * @brief s_es_tun_write
 * @param a_es
 * @param arg
 */
static void s_es_tun_write(dap_events_socket_t *a_es, void *arg)
{
    (void) arg;
    dap_chain_net_srv_vpn_tun_socket_t *l_tun = CH_SF_TUN_SOCKET(a_es);
    assert(l_tun);
    assert(l_tun->es == a_es);
    size_t l_shift = 0;
    debug_if(s_debug_more, L_DEBUG, "Write %lu bytes to tun", l_tun->es->buf_out_size);
    for (ssize_t l_pkt_size = 0, l_bytes_written = 0; l_tun->es->buf_out_size; ) {
        ch_vpn_pkt_t *l_vpn_pkt = (ch_vpn_pkt_t *)(l_tun->es->buf_out + l_shift);
        l_pkt_size = l_vpn_pkt->header.op_data.data_size;
        debug_if(s_debug_more, L_DEBUG, "Packet: op_code 0x%02x, data size %ld",
                 l_vpn_pkt->header.op_code, l_pkt_size);
        l_bytes_written = write(l_tun->es->fd, l_vpn_pkt->data, l_pkt_size);
        if (l_bytes_written == l_pkt_size) {
            l_pkt_size += sizeof(l_vpn_pkt->header);
            l_tun->es->buf_out_size -= l_pkt_size;
            l_shift += l_pkt_size;
        } else {
            int l_errno = errno;
            debug_if(l_bytes_written > 0, L_WARNING, /* How on earth can this be?... */
                     "Error on writing to tun: wrote %zd / %zd bytes", l_bytes_written, l_pkt_size);
            switch (l_errno) {
            case EAGAIN:
                /* Unwritten packets remain untouched in da buffa */
                break;
            case EINVAL:
                /* Something wrong with this packet... Doomp eet */
                debug_if(s_debug_more, L_ERROR, "Skip this packet...");
                l_pkt_size += sizeof(l_vpn_pkt->header);
                l_tun->es->buf_out_size -= l_pkt_size;
                l_shift += l_pkt_size;
                break;
            default: {
                char l_errbuf[128];
                strerror_r(l_errno, l_errbuf, sizeof(l_errbuf));
                log_it(L_ERROR, "Error on writing to tun: \"%s\" code %d", l_errbuf, errno);
                break;
            }}
            break; // Finish the buffer processing immediately
        }
    }
    if (l_tun->es->buf_out_size) {
        debug_if(s_debug_more, L_DEBUG, "Left %lu bytes unwritten", l_tun->es->buf_out_size);
        if (l_shift)
            memmove(l_tun->es->buf_out, &l_tun->es->buf_out[l_shift], l_tun->es->buf_out_size);
    }
    l_tun->buf_size_aux = l_tun->es->buf_out_size;  /* We backup the genuine buffer size... */
    l_tun->es->buf_out_size = 0;                    /* ... and insure the socket against coursing thru regular writing operations */
}

static void s_es_tun_write_finished(dap_events_socket_t *a_es, void *a_arg, int a_errno) {
    UNUSED(a_arg);
    UNUSED(a_errno);
    dap_chain_net_srv_vpn_tun_socket_t *l_tun = CH_SF_TUN_SOCKET(a_es);
    assert(l_tun);
    assert(l_tun->es == a_es);
    l_tun->es->buf_out_size = l_tun->buf_size_aux; /* Backup the genuine buffer size */
    dap_events_socket_set_writable_unsafe(a_es, l_tun->buf_size_aux > 0);
    debug_if(s_debug_more && (l_tun->buf_size_aux > 0), L_INFO, "%zd bytes still in buf_out, poll again", l_tun->buf_size_aux);
    l_tun->buf_size_aux = 0;
}

/**
 * @brief s_es_tun_read
 * @param a_es
 * @param arg
 */
static void s_es_tun_read(dap_events_socket_t * a_es, void * arg)
{
    (void) arg;
    dap_chain_net_srv_vpn_tun_socket_t * l_tun_socket = CH_SF_TUN_SOCKET(a_es);
    assert(l_tun_socket);
    size_t l_buf_in_size = a_es->buf_in_size;
    dap_os_iphdr_t *iph = ( dap_os_iphdr_t*) a_es->buf_in;
    if (s_debug_more){
        char l_str_daddr[INET_ADDRSTRLEN]={[0]='\0'};
        char l_str_saddr[INET_ADDRSTRLEN]={[0]='\0'};
        struct in_addr l_daddr;
        struct in_addr l_saddr;
        size_t l_ip_tot_len;
#ifdef DAP_OS_LINUX
        l_daddr.s_addr = iph->daddr;
        l_saddr.s_addr = iph->saddr;
        l_ip_tot_len = ntohs(iph->tot_len);
#else
        l_daddr.s_addr = iph->ip_dst.s_addr;
        l_saddr.s_addr = iph->ip_src.s_addr;
        l_ip_tot_len = ntohs(iph->ip_len);
#endif
        inet_ntop(AF_INET, &l_daddr, l_str_daddr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &l_saddr, l_str_saddr, INET_ADDRSTRLEN);
        log_it(L_DEBUG,"TUN#%u received ip packet %s->%s tot_len: %zu",
                        l_tun_socket->worker_id, l_str_saddr, l_str_daddr, l_ip_tot_len);
    }

    if(l_buf_in_size) {
        struct in_addr l_in_daddr;
#ifdef DAP_OS_LINUX
        l_in_daddr.s_addr = iph->daddr;
#else
        l_in_daddr.s_addr = iph->ip_dst.s_addr;
#endif
        dap_chain_net_srv_ch_vpn_info_t * l_vpn_info = NULL;
        // Try to find in worker's clients, without locks
        if ( l_tun_socket->clients){
            HASH_FIND_INT( l_tun_socket->clients,&l_in_daddr.s_addr,l_vpn_info );
        }
        if (l_vpn_info) {
            if ( !l_vpn_info->is_on_this_worker && !l_vpn_info->is_reassigned_once && s_raw_server->auto_cpu_reassignment) {
                log_it(L_NOTICE, "Reassigning from worker %u to %u", l_vpn_info->worker->id, a_es->context->worker->id);
                l_vpn_info->is_reassigned_once = true;
                s_tun_send_msg_esocket_reassigned_all_inter(a_es->context->worker->id, l_vpn_info->ch_vpn, l_vpn_info->esocket, l_vpn_info->esocket_uuid,
                    l_vpn_info->addr_ipv4);
                dap_events_socket_reassign_between_workers_mt(l_vpn_info->worker, l_vpn_info->esocket, a_es->context->worker);
            }
            s_tun_client_send_data(l_vpn_info, a_es->buf_in, l_buf_in_size);
        } else if(s_debug_more) {
            char l_str_daddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &l_in_daddr, l_str_daddr, sizeof(l_in_daddr));
            log_it(L_WARNING, "Can't find route for desitnation %s", l_str_daddr);
        }
        a_es->buf_in_size = 0;
    }
}

/**
 * @brief m_es_tun_error
 * @param a_es
 * @param a_error
 */
static void s_es_tun_error(dap_events_socket_t * a_es, int a_error)
{
    if (! a_es->_inheritor)
        return;
    log_it(L_CRITICAL, "Error %d in socket %"DAP_FORMAT_SOCKET" (socket type %d)", a_error, a_es->socket, a_es->type);
}

/**
 * @brief m_es_tun_new
 * @param a_es
 * @param arg
 */
static void s_es_tun_new(dap_events_socket_t * a_es, void * arg)
{
    (void) arg;
    dap_chain_net_srv_vpn_tun_socket_t * l_tun_socket = DAP_NEW_Z(dap_chain_net_srv_vpn_tun_socket_t);
    if ( l_tun_socket ){
        dap_worker_t * l_worker = l_tun_socket->worker = a_es->context->worker;
        uint32_t l_worker_id = l_tun_socket->worker_id = l_worker->id;
        l_tun_socket->es = a_es;

        s_tun_sockets_queue_msg[l_worker_id] = dap_context_create_queue(l_worker->context, s_tun_recv_msg_callback );
        s_tun_sockets[l_worker_id] = l_tun_socket;

        l_tun_socket->queue_tun_msg_input = DAP_NEW_Z_SIZE(dap_events_socket_t*,sizeof(dap_events_socket_t*)*
                                                            dap_events_thread_get_count());
        a_es->_inheritor = l_tun_socket;

#if !defined(DAP_OS_DARWIN) && (defined(DAP_OS_LINUX) || defined (DAP_OS_BSD))
        s_tun_attach_queue( a_es->fd );
#endif
        // Signal thats its ready
        pthread_mutex_lock(&s_tun_sockets_mutex_started);
        s_tun_sockets_started++;
        pthread_cond_broadcast(&s_tun_sockets_cond_started);
        pthread_mutex_unlock(&s_tun_sockets_mutex_started);

        log_it(L_NOTICE,"New TUN event socket initialized for worker %u" , l_tun_socket->worker_id);

    }else{
        log_it(L_ERROR, "Can't allocate memory for tun socket");
    }
}



#if !defined(DAP_OS_DARWIN) && (defined(DAP_OS_LINUX) || defined (DAP_OS_BSD))
/**
 * @brief s_tun_attach_queue
 * @param fd
 * @return
 */
static int s_tun_attach_queue(int fd)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_ATTACH_QUEUE;
    return ioctl(fd, TUNSETQUEUE, (void *)&ifr);
}

/**
 * @brief s_tun_deattach_queue
 * @param fd
 * @return
 */
static int s_tun_deattach_queue(int fd)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_DETACH_QUEUE;
    return ioctl(fd, TUNSETQUEUE, (void *)&ifr);
}

#endif
