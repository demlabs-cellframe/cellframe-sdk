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

#ifdef DAP_OS_BSD
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_tun.h>
#include <sys/ioctl.h>
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
    int tun_fd;
    struct ifreq ifr;
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


dap_chain_net_srv_vpn_tun_socket_t ** s_tun_sockets = NULL;
dap_events_socket_t ** s_tun_sockets_queue_msg = NULL;
pthread_mutex_t * s_tun_sockets_mutex_started = NULL;
pthread_cond_t * s_tun_sockets_cond_started = NULL;


uint32_t s_tun_sockets_count = 0;
bool s_debug_more = false;

static usage_client_t * s_clients = NULL;
static dap_chain_net_srv_ch_vpn_t * s_ch_vpn_addrs  = NULL;
static pthread_rwlock_t s_clients_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static pthread_mutex_t s_sf_socks_mutex;
static pthread_cond_t s_sf_socks_cond;
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


// Stream callbacks
static void s_ch_vpn_new(dap_stream_ch_t* ch, void* arg);
static void s_ch_vpn_delete(dap_stream_ch_t* ch, void* arg);
static void s_ch_packet_in(dap_stream_ch_t* ch, void* a_arg);
static void s_ch_packet_out(dap_stream_ch_t* ch, void* arg);

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
static void s_es_tun_write(dap_events_socket_t *a_es, void *arg);

static void s_tun_recv_msg_callback(dap_events_socket_t * a_esocket_queue, void * a_msg );
static void s_tun_send_msg_ip_assigned(uint32_t a_worker_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr);
static void s_tun_send_msg_ip_assigned_all(dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr);
static void s_tun_send_msg_ip_unassigned(uint32_t a_worker_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr);
static void s_tun_send_msg_ip_unassigned_all(dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr);

static int s_tun_deattach_queue(int fd);
static int s_tun_attach_queue(int fd);


static bool s_tun_client_send_data(dap_chain_net_srv_ch_vpn_info_t * a_ch_vpn_info, const void * a_data, size_t a_data_size);
static bool s_tun_client_send_data_unsafe(dap_chain_net_srv_ch_vpn_t * l_ch_vpn, ch_vpn_pkt_t * l_pkt_out);

static void s_tun_fifo_write(dap_chain_net_srv_vpn_tun_socket_t *a_tun, ch_vpn_pkt_t *a_pkt);
static ch_vpn_pkt_t *s_tun_fifo_read(dap_chain_net_srv_vpn_tun_socket_t *a_tun);


static bool s_tun_client_send_data_unsafe(dap_chain_net_srv_ch_vpn_t * l_ch_vpn, ch_vpn_pkt_t * l_pkt_out)
{
    dap_chain_net_srv_stream_session_t * l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION (l_ch_vpn->ch->stream->session );
    dap_chain_net_srv_usage_t * l_usage = dap_chain_net_srv_usage_find_unsafe(l_srv_session,  l_ch_vpn->usage_id);

    size_t l_data_to_send = (l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header));
    size_t l_data_sent = dap_stream_ch_pkt_write_unsafe(l_ch_vpn->ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, l_pkt_out, l_data_to_send);
    s_update_limits(l_ch_vpn->ch,l_srv_session,l_usage, l_data_sent );
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
    assert(a_data_size > sizeof (struct iphdr));
    ch_vpn_pkt_t *l_pkt_out = DAP_NEW_Z_SIZE(ch_vpn_pkt_t, sizeof(l_pkt_out->header) + a_data_size);
    l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_RECV;
    l_pkt_out->header.sock_id = s_raw_server->tun_fd;
    l_pkt_out->header.usage_id = l_ch_vpn_info->usage_id;
    l_pkt_out->header.op_data.data_size = a_data_size;
    memcpy(l_pkt_out->data, a_data, a_data_size);

    struct in_addr l_in_daddr;
    l_in_daddr.s_addr = ((struct iphdr* ) l_pkt_out->data)->daddr;

    if(l_ch_vpn_info->is_on_this_worker){
        dap_events_socket_t * l_es = NULL;
        if( (l_es= dap_worker_esocket_find_uuid( l_ch_vpn_info->worker, l_ch_vpn_info->esocket_uuid )) != NULL ){
            if(l_es != l_ch_vpn_info->esocket){
                log_it(L_WARNING, "Was wrong esocket %p on worker #%u, lost %zd data",l_ch_vpn_info->esocket, l_ch_vpn_info->worker->id,a_data_size );
                DAP_DELETE(l_pkt_out);
                return false;
            }
            if(s_debug_more){
                char l_str_daddr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET,&l_in_daddr,l_str_daddr,sizeof (l_in_daddr));
                log_it(L_DEBUG, "Sent packet size %zd for desitnation in own context", a_data_size);
            }

            s_tun_client_send_data_unsafe(l_ch_vpn_info->ch_vpn,l_pkt_out);
            DAP_DELETE(l_pkt_out);
        }else{
            log_it(L_WARNING, "Was no esocket %p on worker #%u, lost %zd data",l_ch_vpn_info->esocket, l_ch_vpn_info->worker->id,a_data_size );
            DAP_DELETE(l_pkt_out);
            return false;
        }

    }else{
        struct tun_socket_msg * l_msg= DAP_NEW_Z(struct tun_socket_msg);
        l_msg->type = TUN_SOCKET_MSG_CH_VPN_SEND;
        l_msg->ch_vpn = l_ch_vpn_info->ch_vpn;
        l_msg->esocket = l_ch_vpn_info->esocket;
        l_msg->esocket_uuid = l_ch_vpn_info->esocket_uuid;
        l_msg->ch_vpn_send.pkt = l_pkt_out;
        if (dap_events_socket_queue_ptr_send(l_ch_vpn_info->queue_msg, l_msg) != 0 ){
            log_it(L_WARNING, "Lost %zd data send in tunnel send operation in alien context: queue is overfilled?",a_data_size );
            DAP_DELETE(l_msg);
            DAP_DELETE(l_pkt_out);
            return false;
        }
        if(s_debug_more){
            char l_str_daddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET,&l_in_daddr,l_str_daddr,sizeof (l_in_daddr));
            log_it(L_INFO, "Sent packet for desitnation %zd between contexts",a_data_size);
        }

    }
    return true;
}

/**
 * @brief s_tun_recv_msg_callback
 * @param a_esocket_queue
 * @param a_msg
 */
static void s_tun_recv_msg_callback(dap_events_socket_t * a_esocket_queue, void * a_msg )
{
    struct tun_socket_msg * l_msg = (struct tun_socket_msg*) a_msg;
    switch (l_msg->type) {
        case TUN_SOCKET_MSG_ESOCKET_REASSIGNED:{
            assert(l_msg->esocket_reassigment.worker_id < s_tun_sockets_count);
            dap_chain_net_srv_vpn_tun_socket_t * l_tun_sock = s_tun_sockets[a_esocket_queue->worker->id];
            assert(l_tun_sock);
            dap_chain_net_srv_ch_vpn_info_t * l_info = NULL;
            HASH_FIND(hh,l_tun_sock->clients,&l_msg->esocket_reassigment.addr , sizeof (l_msg->esocket_reassigment.addr), l_info);
            if (l_info){ // Updating info
                l_info->worker = dap_events_worker_get(l_msg->esocket_reassigment.worker_id);
                l_info->queue_msg = s_tun_sockets_queue_msg[l_msg->esocket_reassigment.worker_id];
                l_info->is_reassigned_once = true;
                l_info->is_on_this_worker =(a_esocket_queue->worker->id == l_msg->esocket_reassigment.worker_id);
                if(dap_log_level_get() <= L_INFO){
                    char l_addrbuf[INET_ADDRSTRLEN]= { [0]='\0'};
                    inet_ntop(AF_INET,&l_msg->esocket_reassigment.addr, l_addrbuf, sizeof (l_addrbuf));
                    log_it(L_INFO, "Tun:%u message: addr %s reassign on worker #%u",a_esocket_queue->worker->id,
                           l_addrbuf, l_msg->esocket_reassigment.worker_id);
                }
            }else{
                if(dap_log_level_get() <= L_INFO){
                    char l_addrbuf[17];
                    inet_ntop(AF_INET,&l_msg->esocket_reassigment.addr, l_addrbuf, sizeof (l_addrbuf));
                    log_it(L_INFO,"Reassigment message for address %s on worker %u comes but no such address was found on tun socket %u",
                           l_addrbuf, l_msg->esocket_reassigment.worker_id,
                           a_esocket_queue->worker->id);
                }
            }
        } break;
        case TUN_SOCKET_MSG_IP_ASSIGNED:{
            assert(l_msg->ip_assigment.worker_id < s_tun_sockets_count);
            dap_chain_net_srv_vpn_tun_socket_t * l_tun_sock = s_tun_sockets[a_esocket_queue->worker->id];
            assert(l_tun_sock);

            dap_chain_net_srv_ch_vpn_info_t * l_new_info = NULL;
            HASH_FIND(hh,l_tun_sock->clients,&l_msg->ip_assigment.addr, sizeof (l_msg->ip_assigment.addr), l_new_info);
            if( l_new_info){
                char l_addrbuf[INET_ADDRSTRLEN]= { [0]='\0'};
                inet_ntop(AF_INET,&l_msg->ip_assigment.addr, l_addrbuf, sizeof (l_addrbuf));
                log_it(L_WARNING, "Already assigned address %s on tun sock #%u", l_addrbuf, l_tun_sock->worker_id);
            }else{
                l_new_info = DAP_NEW_Z(dap_chain_net_srv_ch_vpn_info_t);
                l_new_info->ch_vpn = l_msg->ch_vpn;
                l_new_info->addr_ipv4 = l_msg->ip_assigment.addr;
                l_new_info->queue_msg = s_tun_sockets_queue_msg[l_msg->ip_assigment.worker_id];
                l_new_info->usage_id = l_msg->ip_assigment.usage_id;
                l_new_info->is_reassigned_once = l_msg->is_reassigned_once;
                l_new_info->is_on_this_worker = (l_msg->ip_assigment.worker_id == a_esocket_queue->worker->id);
                l_new_info->esocket = l_msg->esocket;
                l_new_info->esocket_uuid = l_msg->esocket_uuid;
                l_new_info->worker = dap_events_worker_get(l_msg->ip_assigment.worker_id);
                HASH_ADD(hh,l_tun_sock->clients, addr_ipv4, sizeof (l_new_info->addr_ipv4), l_new_info);
                if(s_debug_more){
                    char l_addrbuf[INET_ADDRSTRLEN]= { [0]='\0'};
                    inet_ntop(AF_INET,&l_msg->ip_assigment.addr, l_addrbuf, sizeof (l_addrbuf));
                    log_it(L_DEBUG, "Tun:%u message: addr %s assigned for worker #%u on tun #u",a_esocket_queue->worker->id,
                           l_addrbuf, l_msg->ip_assigment.worker_id);
                }
            }

        }break;
        case TUN_SOCKET_MSG_IP_UNASSIGNED:{
            assert(l_msg->ip_unassigment.worker_id < s_tun_sockets_count);
            dap_chain_net_srv_vpn_tun_socket_t * l_tun_sock = s_tun_sockets[a_esocket_queue->worker->id];
            assert(l_tun_sock);

            dap_chain_net_srv_ch_vpn_info_t * l_new_info = NULL;
            HASH_FIND(hh,l_tun_sock->clients,&l_msg->ip_unassigment.addr, sizeof (l_msg->ip_unassigment.addr), l_new_info);
            if( l_new_info){
                HASH_DELETE(hh, l_tun_sock->clients, l_new_info);
                DAP_DELETE(l_new_info);
                if( dap_log_level_get() <= L_INFO){
                    char l_addrbuf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET,&l_msg->ip_unassigment.addr, l_addrbuf, sizeof (l_addrbuf));
                    log_it(L_INFO, "Unassigned %s address from tun sock #%u", l_addrbuf, l_tun_sock->worker_id);
                }
            }else{
                char l_addrbuf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET,&l_msg->ip_unassigment.addr, l_addrbuf, sizeof (l_addrbuf));
                log_it(L_WARNING, "Can't fund address %s on tun sock #%u to unassign it", l_addrbuf, l_tun_sock->worker_id);
            }

        }break;
        case TUN_SOCKET_MSG_CH_VPN_SEND:{
            if(s_debug_more){
                char l_addrbuf[INET_ADDRSTRLEN]= { [0]='\0'};
                inet_ntop(AF_INET,&l_msg->ip_assigment.addr, l_addrbuf, sizeof (l_addrbuf));
                log_it(L_DEBUG, "Tun:%u message: send %u bytes for ch vpn protocol",a_esocket_queue->worker->id,
                       l_msg->ch_vpn_send.pkt->header.op_data.data_size );
            }
            if(dap_worker_esocket_find_uuid( a_esocket_queue->worker, l_msg->esocket_uuid )== l_msg->esocket  ){
                    s_tun_client_send_data_unsafe(l_msg->ch_vpn,l_msg->ch_vpn_send.pkt);
            }
            DAP_DELETE(l_msg->ch_vpn_send.pkt);
        }break;
        default:log_it(L_ERROR,"Wrong tun socket message type %d", l_msg->type);
    }
    DAP_DELETE(l_msg);
}

/**
 * @brief s_tun_send_msg_ip_assigned
 * @param a_worker_id
 * @param a_ch_vpn
 * @param a_addr
 */
static void s_tun_send_msg_ip_assigned(uint32_t a_worker_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr )
{
    struct tun_socket_msg * l_msg = DAP_NEW_Z(struct tun_socket_msg);
    l_msg->type = TUN_SOCKET_MSG_IP_ASSIGNED;
    l_msg->ch_vpn = a_ch_vpn;
    l_msg->esocket = a_ch_vpn->ch->stream->esocket;
    l_msg->esocket_uuid = a_ch_vpn->ch->stream->esocket->uuid;
    l_msg->is_reassigned_once = a_ch_vpn->ch->stream->esocket->was_reassigned;
    l_msg->ip_assigment.addr = a_addr;
    l_msg->ip_assigment.worker_id = a_ch_vpn->ch->stream_worker->worker->id;
    l_msg->ip_assigment.usage_id = a_ch_vpn->usage_id;

    if (dap_events_socket_queue_ptr_send(s_tun_sockets_queue_msg[a_worker_id], l_msg) != 0){
        log_it(L_WARNING, "Cant send new  ip assign message to the tun msg queue #%u", a_worker_id);
    }
}

/**
 * @brief s_tun_send_msg_ip_assigned_all
 * @param a_ch_vpn
 * @param a_addr
 */
static void s_tun_send_msg_ip_assigned_all(dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr)
{
    for( uint32_t i=0; i< s_tun_sockets_count; i++)
        s_tun_send_msg_ip_assigned(i, a_ch_vpn , a_addr );
}

/**
 * @brief s_tun_send_msg_ip_unassigned
 * @param a_worker_id
 * @param a_ch_vpn
 * @param a_addr
 */
static void s_tun_send_msg_ip_unassigned(uint32_t a_worker_id, dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr)
{
    struct tun_socket_msg * l_msg = DAP_NEW_Z(struct tun_socket_msg);
    l_msg->type = TUN_SOCKET_MSG_IP_UNASSIGNED;
    l_msg->ch_vpn = a_ch_vpn;
    l_msg->ip_unassigment.addr = a_addr;
    l_msg->ip_unassigment.worker_id = a_ch_vpn->ch->stream_worker->worker->id;
    l_msg->esocket = a_ch_vpn->ch->stream->esocket;
    l_msg->esocket_uuid = a_ch_vpn->ch->stream->esocket->uuid;
    l_msg->is_reassigned_once = a_ch_vpn->ch->stream->esocket->was_reassigned;

    if ( dap_events_socket_queue_ptr_send(s_tun_sockets_queue_msg[a_worker_id], l_msg) != 0 ) {
        log_it(L_WARNING, "Cant send new  ip unassign message to the tun msg queue #%u", a_worker_id);
    }
}

/**
 * @brief s_tun_send_msg_ip_unassigned_all
 * @param a_ch_vpn
 * @param a_addr
 */
static void s_tun_send_msg_ip_unassigned_all(dap_chain_net_srv_ch_vpn_t * a_ch_vpn, struct in_addr a_addr)
{
    for( uint32_t i=0; i< s_tun_sockets_count; i++)
        s_tun_send_msg_ip_unassigned(i, a_ch_vpn, a_addr);
}

/**
 * @brief s_tun_send_msg_esocket_reasigned_inter
 * @param a_worker_id
 * @param a_ch_vpn
 * @param a_esocket
 * @param a_esocket_uuid
 * @param a_addr
 * @param a_esocket_worker_id
 */
static void s_tun_send_msg_esocket_reasigned_inter(dap_chain_net_srv_vpn_tun_socket_t * a_tun_socket,
                                                   dap_chain_net_srv_ch_vpn_t * a_ch_vpn, dap_events_socket_t * a_esocket,
                                                   dap_events_socket_uuid_t a_esocket_uuid, struct in_addr a_addr, uint32_t a_esocket_worker_id)
{
    struct tun_socket_msg * l_msg = DAP_NEW_Z(struct tun_socket_msg);
    l_msg->type = TUN_SOCKET_MSG_ESOCKET_REASSIGNED ;
    l_msg->ch_vpn = a_ch_vpn;
    l_msg->esocket_reassigment.addr = a_addr;
    l_msg->esocket_reassigment.worker_id = a_esocket_worker_id;
    l_msg->esocket = a_esocket;
    l_msg->esocket_uuid = a_esocket_uuid;
    l_msg->is_reassigned_once = true;

    if (dap_events_socket_queue_ptr_send_to_input(a_tun_socket->queue_tun_msg_input[a_esocket_worker_id] , l_msg) != 0){
        log_it(L_WARNING, "Cant send esocket reassigment message to the tun msg queue #%u", a_tun_socket->worker_id );
    }else
        log_it(L_DEBUG,"Sent reassign message to tun:%u", a_esocket_worker_id);
}

/**
 * @brief s_tun_send_msg_esocket_reasigned_all_inter
 * @param a_ch_vpn
 * @param a_esocket
 * @param a_esocket_uuid
 * @param a_addr
 * @param a_worker_id
 */
static void s_tun_send_msg_esocket_reasigned_all_inter(dap_chain_net_srv_ch_vpn_t * a_ch_vpn, dap_events_socket_t * a_esocket,
                                                       dap_events_socket_uuid_t a_esocket_uuid, struct in_addr a_addr, uint32_t a_worker_id)
{
    for( uint32_t i=0; i< s_tun_sockets_count; i++)
        s_tun_send_msg_esocket_reasigned_inter(s_tun_sockets[i] , a_ch_vpn, a_esocket, a_esocket_uuid, a_addr, a_worker_id);
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
    dap_events_socket_callbacks_t l_s_callbacks;
    memset(&l_s_callbacks,0,sizeof (l_s_callbacks));
    l_s_callbacks.new_callback = s_es_tun_new;
    l_s_callbacks.read_callback = s_es_tun_read;
    l_s_callbacks.error_callback = s_es_tun_error;
    l_s_callbacks.delete_callback = s_es_tun_delete;
    l_s_callbacks.write_callback = s_es_tun_write;

    dap_events_socket_t * l_es = dap_events_socket_wrap_no_add(a_worker->events ,
                                          a_tun_fd, &l_s_callbacks);
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
        log_it(L_ERROR, "%s: error while reading network parameters from config (network_address and network_mask)", __PRETTY_FUNCTION__);
        DAP_DELETE((void*)c_addr);
        DAP_DELETE((void*)c_mask);
        return -1;
    }

    inet_aton(c_addr, &s_raw_server->ipv4_network_addr );
    inet_aton(c_mask, &s_raw_server->ipv4_network_mask );
    s_raw_server->ipv4_gw.s_addr= (s_raw_server->ipv4_network_addr.s_addr | 0x01000000); // grow up some shit here!
    s_raw_server->ipv4_lease_last.s_addr = s_raw_server->ipv4_gw.s_addr;

    s_raw_server->auto_cpu_reassignment = dap_config_get_item_bool_default(g_config, "srv_vpn", "auto_cpu_reassignment", false);
    log_it(L_NOTICE, "Auto cpu reassignment is set to '%s'", s_raw_server->auto_cpu_reassignment ? "true" : "false");

    memset(&s_raw_server->ifr, 0, sizeof(s_raw_server->ifr));
    s_raw_server->ifr.ifr_flags = IFF_TUN | IFF_MULTI_QUEUE| IFF_NO_PI;

    uint32_t l_cpu_count = dap_get_cpu_count(); // maybe replace with getting s_threads_count directly
    log_it(L_NOTICE,"%s: trying to initialize multiqueue for %u workers", __PRETTY_FUNCTION__, l_cpu_count);
    s_tun_sockets_count = l_cpu_count;
    s_tun_sockets = DAP_NEW_Z_SIZE(dap_chain_net_srv_vpn_tun_socket_t*,s_tun_sockets_count*sizeof(dap_chain_net_srv_vpn_tun_socket_t*));
    s_tun_sockets_queue_msg =  DAP_NEW_Z_SIZE(dap_events_socket_t*,s_tun_sockets_count*sizeof(dap_events_socket_t*));
    s_tun_sockets_mutex_started = DAP_NEW_Z_SIZE(pthread_mutex_t,s_tun_sockets_count*sizeof(pthread_mutex_t));
    s_tun_sockets_cond_started = DAP_NEW_Z_SIZE(pthread_cond_t,s_tun_sockets_count*sizeof(pthread_cond_t));
    int err = -1;

    for( uint8_t i =0; i< l_cpu_count; i++){
        dap_worker_t * l_worker = dap_events_worker_get(i);
        assert( l_worker );
        int l_tun_fd;
        if( (l_tun_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0 ) {
            log_it(L_ERROR,"Opening /dev/net/tun error: '%s'", strerror(errno));
            err = -100;
            break;
        }
        log_it(L_DEBUG,"Opening /dev/net/tun:%u", i);
        if( (err = ioctl(l_tun_fd, TUNSETIFF, (void *)& s_raw_server->ifr)) < 0 ) {
            log_it(L_CRITICAL, "ioctl(TUNSETIFF) error: '%s' ",strerror(errno));
            close(l_tun_fd);
            break;
        }
        s_tun_deattach_queue(l_tun_fd);
        pthread_mutex_init(&s_tun_sockets_mutex_started[i],NULL);
        pthread_cond_init(&s_tun_sockets_cond_started[i],NULL);
        pthread_mutex_lock(&s_tun_sockets_mutex_started[i]);
        s_tun_event_stream_create(l_worker, l_tun_fd);
    }

    // Waiting for all the tun sockets
    for( uint8_t i =0; i< l_cpu_count; i++){
        pthread_cond_wait(&s_tun_sockets_cond_started[i], &s_tun_sockets_mutex_started[i]);
        pthread_mutex_unlock(&s_tun_sockets_mutex_started[i]);
    }

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


    if (! err ){
        char buf[256];
        log_it(L_NOTICE,"Bringed up %s virtual network interface (%s/%s)", s_raw_server->ifr.ifr_name,inet_ntoa(s_raw_server->ipv4_gw),c_mask);
        snprintf(buf,sizeof(buf),"ip link set %s up",s_raw_server->ifr.ifr_name);
        system(buf);
        snprintf(buf,sizeof(buf),"ip addr add %s/%s dev %s ",inet_ntoa(s_raw_server->ipv4_gw),c_mask, s_raw_server->ifr.ifr_name );
        system(buf);
    }

    return err;
}

/**
* @brief s_vpn_tun_init
* @return
*/
static int s_vpn_tun_init()
{
    s_raw_server=DAP_NEW_Z(vpn_local_network_t);
    pthread_rwlock_init(&s_raw_server->rwlock, NULL);
    pthread_mutex_init(&s_raw_server->pkt_out_mutex,NULL);
    pthread_mutex_init(&s_sf_socks_mutex, NULL);
    pthread_cond_init(&s_sf_socks_cond, NULL);

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
    dap_chain_net_srv_t *l_srv = dap_chain_net_srv_add(l_uid, "srv_vpn", s_callback_requested,
                                                       s_callback_response_success, s_callback_response_error,
                                                       s_callback_receipt_next_success, NULL);

    dap_chain_net_srv_vpn_t* l_srv_vpn  = DAP_NEW_Z( dap_chain_net_srv_vpn_t);
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
    dap_chain_node_cli_cmd_item_create ("vpn_stat", com_vpn_statistics, "VPN statistics",
            "vpn_stat -net <net name> [-full]\n"
            );
    return 0;
}

/**
 * @brief ch_sf_deinit
 */
void dap_chain_net_srv_vpn_deinit(void)
{
    pthread_mutex_destroy(&s_sf_socks_mutex);
    pthread_cond_destroy(&s_sf_socks_cond);
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


//    dap_stream_ch_chain_net_srv_pkt_request_t * l_request =  (dap_stream_ch_chain_net_srv_pkt_request_t *) a_request;
//    dap_chain_net_srv_stream_session_t * l_srv_session = (dap_chain_net_srv_stream_session_t *) a_srv_client->ch->stream->session->_inheritor;
    dap_chain_net_srv_stream_session_t * l_srv_session = (dap_chain_net_srv_stream_session_t *) a_srv_client->ch->stream->session->_inheritor;
    dap_chain_net_srv_usage_t * l_usage_active= dap_chain_net_srv_usage_find_unsafe(l_srv_session,a_usage_id);
    dap_chain_net_srv_ch_vpn_t * l_srv_ch_vpn =(dap_chain_net_srv_ch_vpn_t*) a_srv_client->ch->stream->channel[DAP_CHAIN_NET_SRV_VPN_ID] ?
            a_srv_client->ch->stream->channel[DAP_CHAIN_NET_SRV_VPN_ID]->internal : NULL;

    if ( !l_usage_active){
        log_it( L_ERROR, "No active service usage, can't success");
        return -1;
    }

    usage_client_t * l_usage_client = NULL;

    l_usage_client = DAP_NEW_Z(usage_client_t);
    l_usage_client->usage_id = a_usage_id;
    l_usage_client->receipt = DAP_NEW_SIZE(dap_chain_datum_tx_receipt_t,l_receipt_size);

    memcpy(l_usage_client->receipt, l_receipt, l_receipt_size);

    pthread_rwlock_wrlock(&s_clients_rwlock);
    HASH_ADD(hh, s_clients,usage_id,sizeof(a_usage_id),l_usage_client);
    l_srv_session->usage_active = l_usage_active;
    l_srv_session->usage_active->is_active = true;
    log_it(L_NOTICE,"Enable VPN service");

    if ( l_srv_ch_vpn ){ // If channel is already opened

        dap_stream_ch_set_ready_to_read_unsafe( l_srv_ch_vpn->ch , true );

        l_srv_ch_vpn->usage_id = a_usage_id;
        // So complicated to update usage client to be sure that nothing breaks it
        l_usage_client->ch_vpn = l_srv_ch_vpn;
    } else{
        log_it(L_WARNING, "VPN channel is not open, will be no data transmission");
        l_ret = -2;
    }
    pthread_rwlock_unlock(&s_clients_rwlock);
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
    a_ch->internal = DAP_NEW_Z(dap_chain_net_srv_ch_vpn_t);
    dap_chain_net_srv_ch_vpn_t * l_srv_vpn = CH_VPN(a_ch);

    if(a_ch->stream->session->_inheritor == NULL && a_ch->stream->session != NULL)
        dap_chain_net_srv_stream_session_create(a_ch->stream->session);
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
    l_srv_vpn->net_srv = dap_chain_net_srv_get(l_uid);
    l_srv_vpn->ch = a_ch;

    dap_chain_net_srv_stream_session_t * l_srv_session = (dap_chain_net_srv_stream_session_t *) a_ch->stream->session->_inheritor;

    l_srv_vpn->usage_id = l_srv_session->usage_active?  l_srv_session->usage_active->id : 0;

    if( l_srv_vpn->usage_id) {
        // So complicated to update usage client to be sure that nothing breaks it
        usage_client_t * l_usage_client = NULL;
        pthread_rwlock_rdlock(&s_clients_rwlock);
        HASH_FIND(hh,s_clients, &l_srv_vpn->usage_id,sizeof(l_srv_vpn->usage_id),l_usage_client );
        if (l_usage_client){
            l_usage_client->ch_vpn = l_srv_vpn;
        }
        pthread_rwlock_unlock(&s_clients_rwlock);
    }

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

    bool l_is_unleased = false;
    if ( l_ch_vpn->addr_ipv4.s_addr ){ // if leased address
        s_tun_send_msg_ip_unassigned_all(l_ch_vpn, l_ch_vpn->addr_ipv4); // Signal all the workers that we're switching off

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
        l_item_unleased->addr.s_addr = l_ch_vpn->addr_ipv4.s_addr;
        l_item_unleased->next = l_srv_vpn->ipv4_unleased;
        l_srv_vpn->ipv4_unleased = l_item_unleased;
    }

    HASH_FIND(hh,s_clients, &l_ch_vpn->usage_id,sizeof(l_ch_vpn->usage_id),l_usage_client );
    if (l_usage_client){
        l_usage_client->ch_vpn = NULL; // NULL the channel, nobody uses that indicates
    }

    pthread_rwlock_unlock(&s_clients_rwlock);

    l_ch_vpn->ch = NULL;
    l_ch_vpn->net_srv = NULL;
    l_ch_vpn->is_allowed =false;
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
    if( a_srv_session->limits_ts ){
        if( a_srv_session->limits_ts  < time(NULL) ){ // Limits out
            a_srv_session->limits_ts = 0;
            log_it(L_INFO, "Limits by timestamp are over. Switch to the next receipt");
            DAP_DELETE(a_usage->receipt);
            a_usage->receipt = a_usage->receipt_next;
            a_usage->receipt_next = NULL;
            l_issue_new_receipt = true;
            if ( a_usage->receipt){ // If there is next receipt add the time and request the next receipt
                a_srv_session->limits_units_type.uint32 = a_usage->receipt->receipt_info.units_type.uint32;
                switch( a_usage->receipt->receipt_info.units_type.enm){
                    case SERV_UNIT_DAY:{
                        a_srv_session->limits_ts = time(NULL) + (time_t)  a_usage->receipt->receipt_info.units*24*3600;
                        log_it(L_INFO,"%"DAP_UINT64_FORMAT_U" days more for VPN usage", a_usage->receipt->receipt_info.units);
                    } break;
                    case SERV_UNIT_SEC:{
                        a_srv_session->limits_ts = time(NULL) + (time_t)  a_usage->receipt->receipt_info.units;
                        log_it(L_INFO,"%"DAP_UINT64_FORMAT_U" seconds more for VPN usage", a_usage->receipt->receipt_info.units);
                    } break;
                    default: {
                        log_it(L_WARNING, "VPN doesnt accept serv unit type 0x%08X for limits_ts", a_usage->receipt->receipt_info.units_type.uint32 );
                        dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
                        dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
                        dap_stream_ch_pkt_write_unsafe( a_usage->client->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
                    }
                }

                //l_ch_vpn->limits_ts = time(NULL) + l_usage->receipt->receipt
            }else {
                log_it( L_NOTICE, "No activate receipt in usage, switch off write callback for channel");
                dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
                dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
                dap_stream_ch_pkt_write_unsafe( a_usage->client->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );
            }
        }
    }else if ( a_srv_session->limits_bytes ){
        if ( a_srv_session->limits_bytes >(uintmax_t) a_bytes ){
            // Update limits
            a_srv_session->limits_bytes -= (uintmax_t) a_bytes;
        }else{ // traffic out
            log_it(L_INFO, "Limits by traffic is over. Switch to the next receipt");
            DAP_DELETE(a_usage->receipt);
            a_usage->receipt = a_usage->receipt_next;
            a_usage->receipt_next = NULL;
            l_issue_new_receipt = true;
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


            }else {
                log_it( L_NOTICE, "No activate receipt in usage, switch off write callback for channel");
                dap_stream_ch_set_ready_to_write_unsafe(a_ch,false);
                dap_stream_ch_set_ready_to_read_unsafe(a_ch,false);
                dap_stream_ch_pkt_write_unsafe( a_usage->client->ch , DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED , NULL, 0 );

            }

        }
    }

    // If issue new receipt
    if ( l_issue_new_receipt ) {
        if ( a_usage->receipt){
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
    pkt_out->header.op_code = VPN_PACKET_OP_CODE_PONG;

    dap_stream_ch_pkt_write_unsafe(a_ch, 'd', pkt_out,
            pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
    dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
    free(pkt_out);
}

/**
 * @brief s_ch_packet_in_vpn_address_request
 * @param a_ch
 * @param a_usage
 */
static void s_ch_packet_in_vpn_address_request(dap_stream_ch_t* a_ch, dap_chain_net_srv_usage_t * a_usage){
    dap_chain_net_srv_ch_vpn_t *l_ch_vpn = CH_VPN(a_ch);
    dap_chain_net_srv_vpn_t * l_srv_vpn =(dap_chain_net_srv_vpn_t *) a_usage->service->_internal;
    dap_chain_net_srv_stream_session_t * l_srv_session= DAP_CHAIN_NET_SRV_STREAM_SESSION(l_ch_vpn->ch->stream->session);

    if (! s_raw_server)
        return;

    if ( l_ch_vpn->addr_ipv4.s_addr ){
        log_it(L_WARNING,"We already have ip address leased to us");
        ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
        pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;
        pkt_out->header.op_problem.code = VPN_PROBLEM_CODE_ALREADY_ASSIGNED_ADDR;
        pkt_out->header.sock_id = s_raw_server->tun_fd;
        pkt_out->header.usage_id = a_usage->id;

        size_t l_data_to_write = pkt_out->header.op_data.data_size + sizeof(pkt_out->header);
        size_t l_data_wrote = dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out,
                l_data_to_write);
        if (l_data_wrote < l_data_to_write){
            log_it(L_WARNING, "Buffer overfilled: can't send packet with VPN_PROBLEM_CODE_ALREADY_ASSIGNED_ADDR: sent only %zd from %zd",
                    l_data_wrote,l_data_to_write );
            l_srv_session->stats.bytes_sent_lost += l_data_to_write - l_data_wrote;
            l_srv_session->stats.packets_sent_lost++;
        }else{
            l_srv_session->stats.packets_sent++;
            l_srv_session->stats.bytes_sent+= l_data_wrote;
        }
        return;
    }
    dap_chain_net_srv_vpn_item_ipv4_t * l_item_ipv4 = l_srv_vpn->ipv4_unleased;
    if ( l_item_ipv4){
        log_it(L_WARNING,"We have unleased ip address");
        l_ch_vpn->addr_ipv4.s_addr = l_item_ipv4->addr.s_addr;

        pthread_rwlock_wrlock( &s_clients_rwlock );
        HASH_ADD(hh, s_ch_vpn_addrs, addr_ipv4, sizeof (l_ch_vpn->addr_ipv4), l_ch_vpn);
        pthread_rwlock_unlock( &s_clients_rwlock );

        ch_vpn_pkt_t *l_pkt_out = DAP_NEW_Z_SIZE(ch_vpn_pkt_t,
                sizeof(l_pkt_out->header) + sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_network_addr));
        l_pkt_out->header.sock_id = s_raw_server->tun_fd;
        l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_ADDR_REPLY;
        l_pkt_out->header.op_data.data_size = sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_gw);
        l_pkt_out->header.usage_id = a_usage->id;

        memcpy(l_pkt_out->data, &l_ch_vpn->addr_ipv4, sizeof(l_ch_vpn->addr_ipv4));
        memcpy(l_pkt_out->data + sizeof(l_ch_vpn->addr_ipv4), &s_raw_server->ipv4_gw ,
                sizeof(s_raw_server->ipv4_gw));

        size_t l_data_to_write =  l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header);
        size_t l_data_wrote = dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA , l_pkt_out,
                l_data_to_write);
        if (l_data_wrote < l_data_to_write){
            log_it(L_WARNING, "Buffer overfilled: can't send packet with VPN_PACKET_OP_CODE_VPN_ADDR_REPLY: sent only %zd from %zd",
                    l_data_wrote,l_data_to_write );
            dap_chain_net_srv_stream_session_t * l_srv_session= DAP_CHAIN_NET_SRV_STREAM_SESSION(l_ch_vpn->ch->stream->session);
            assert(l_srv_session);
            l_srv_session->stats.bytes_sent_lost += l_data_to_write - l_data_wrote;
            l_srv_session->stats.packets_sent_lost++;
        }else{
            log_it(L_NOTICE, "VPN client address %s leased", inet_ntoa(l_ch_vpn->addr_ipv4));
            log_it(L_INFO, "\tnet gateway %s", inet_ntoa(s_raw_server->ipv4_network_addr));
            log_it(L_INFO, "\tnet mask %s", inet_ntoa(s_raw_server->ipv4_network_mask));
            log_it(L_INFO, "\tgw %s", inet_ntoa(s_raw_server->ipv4_gw));
            log_it(L_INFO, "\tlast_addr %s", inet_ntoa(s_raw_server->ipv4_lease_last));
            l_srv_vpn->ipv4_unleased = l_item_ipv4->next;
            DAP_DELETE(l_item_ipv4);
            l_srv_session->stats.packets_sent++;
            l_srv_session->stats.bytes_sent+= l_data_wrote;
            s_tun_send_msg_ip_assigned_all(l_ch_vpn, l_ch_vpn->addr_ipv4);
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
        log_it(L_DEBUG, "Check if is address is lesser than");
        log_it(L_DEBUG,"    new_address     = %s", inet_ntoa(n_addr));
        log_it(L_DEBUG,"    new_address_max = %s", inet_ntoa(n_addr_max));
        n_addr.s_addr = ntohl(n_addr.s_addr);
        n_addr_max.s_addr = ntohl(n_addr_max.s_addr);
        if(n_addr.s_addr <= n_addr_max.s_addr ) {
            n_addr.s_addr = htonl(n_addr.s_addr);
            n_addr_max.s_addr = htonl(n_addr_max.s_addr);

            s_raw_server->ipv4_lease_last.s_addr =n_addr.s_addr;
            a_ch->stream->session->tun_client_addr.s_addr = n_addr.s_addr;
            l_ch_vpn->addr_ipv4.s_addr = n_addr.s_addr;

            log_it(L_NOTICE, "VPN client address %s leased", inet_ntoa(n_addr));
            log_it(L_INFO, "\tgateway %s", inet_ntoa(s_raw_server->ipv4_gw ));
            log_it(L_INFO, "\tnet mask %s", inet_ntoa(s_raw_server->ipv4_network_mask));
            log_it(L_INFO, "\tnet addr %s", inet_ntoa(s_raw_server->ipv4_network_addr ));
            log_it(L_INFO, "\tlast_addr %s", inet_ntoa(s_raw_server->ipv4_lease_last));
            pthread_rwlock_wrlock( &s_clients_rwlock );
            HASH_ADD(hh, s_ch_vpn_addrs, addr_ipv4, sizeof (l_ch_vpn->addr_ipv4), l_ch_vpn);
            pthread_rwlock_unlock( &s_clients_rwlock );

            ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1,
                    sizeof(pkt_out->header) + sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_gw));
            pkt_out->header.sock_id = s_raw_server->tun_fd;
            pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_ADDR_REPLY;
            pkt_out->header.op_data.data_size = sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_gw);
            pkt_out->header.usage_id = a_usage->id;

            memcpy(pkt_out->data, &l_ch_vpn->addr_ipv4, sizeof(l_ch_vpn->addr_ipv4));
            memcpy(pkt_out->data + sizeof(l_ch_vpn->addr_ipv4), &s_raw_server->ipv4_gw,
                    sizeof(s_raw_server->ipv4_gw));

            size_t l_data_to_write = pkt_out->header.op_data.data_size + sizeof(pkt_out->header);
            size_t l_data_wrote = dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out,
                                       l_data_to_write);
            if (l_data_wrote < l_data_to_write){
                log_it(L_WARNING, "Buffer overfilled: can't send packet with VPN_PACKET_OP_CODE_VPN_ADDR_REPLY: sent only %zd from %zd",
                        l_data_wrote,l_data_to_write );
                dap_chain_net_srv_stream_session_t * l_srv_session= DAP_CHAIN_NET_SRV_STREAM_SESSION(l_ch_vpn->ch->stream->session);
                assert(l_srv_session);
                l_srv_session->stats.bytes_sent_lost += l_data_to_write - l_data_wrote;
                l_srv_session->stats.packets_sent_lost++;
            }else{
                l_srv_session->stats.packets_sent++;
                l_srv_session->stats.bytes_sent+= l_data_wrote;
                s_tun_send_msg_ip_assigned_all(l_ch_vpn, l_ch_vpn->addr_ipv4);
            }
        } else { // All the network is filled with clients, can't lease a new address
            log_it(L_WARNING, "All the network is filled with clients, can't lease a new address");
            ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
            pkt_out->header.sock_id = s_raw_server->tun_fd;
            pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;
            pkt_out->header.usage_id = a_usage->id;
            pkt_out->header.op_problem.code = VPN_PROBLEM_CODE_NO_FREE_ADDR;
            size_t l_data_to_write = pkt_out->header.op_data.data_size + sizeof(pkt_out->header);
            size_t l_data_wrote = dap_stream_ch_pkt_write_unsafe(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out,
                    pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
            if (l_data_wrote < l_data_to_write){
                log_it(L_WARNING, "Buffer overfilled: can't send packet with VPN_PACKET_OP_CODE_PROBLEM: sent only %zd from %zd",
                        l_data_wrote,l_data_to_write );
                dap_chain_net_srv_stream_session_t * l_srv_session= DAP_CHAIN_NET_SRV_STREAM_SESSION(l_ch_vpn->ch->stream->session);
                assert(l_srv_session);
                l_srv_session->stats.bytes_sent_lost += l_data_to_write - l_data_wrote;
                l_srv_session->stats.packets_sent_lost++;
            }else{
                l_srv_session->stats.packets_sent++;
                l_srv_session->stats.bytes_sent+= l_data_wrote;
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
    dap_chain_net_srv_usage_t * l_usage = dap_chain_net_srv_usage_find_unsafe(l_srv_session,  l_ch_vpn->usage_id);

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


    // TODO move address leasing to this structure
    //dap_chain_net_srv_vpn_t * l_srv_vpn =(dap_chain_net_srv_vpn_t *) l_usage->service->_internal;

    ch_vpn_pkt_t * l_vpn_pkt = (ch_vpn_pkt_t *) l_pkt->data;
    size_t l_vpn_pkt_size = l_pkt->hdr.size - sizeof (l_vpn_pkt->header);

    if (s_debug_more)
        log_it(L_INFO, "Got srv_vpn packet with op_code=0x%02x", l_vpn_pkt->header.op_code);

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
                    s_tun_send_msg_ip_assigned_all(CH_VPN(a_ch), CH_VPN(a_ch)->addr_ipv4);
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
                dap_chain_net_srv_vpn_tun_socket_t *l_tun =  l_es ? l_es->_inheritor : NULL;
                //ch_sf_tun_socket_t * l_tun = s_tun_sockets[a_ch->stream_worker->worker->id];
                assert(l_tun);
                size_t l_ret = dap_events_socket_write_unsafe(l_tun->es, l_vpn_pkt->data, l_vpn_pkt->header.op_data.data_size);
                if (l_ret == l_vpn_pkt->header.op_data.data_size) {
                    l_srv_session->stats.packets_sent++;
                    l_srv_session->stats.bytes_sent += l_ret;
                } else if (l_ret > 0) {
                    log_it (L_WARNING, "Lost %zd bytes, buffer overflow", l_vpn_pkt->header.op_data.data_size - l_ret);
                    l_srv_session->stats.bytes_sent_lost += (l_vpn_pkt->header.op_data.data_size - l_ret);
                    l_srv_session->stats.packets_sent_lost++;
                }
            } break;

            // for server only
            case VPN_PACKET_OP_CODE_VPN_SEND: {
                dap_chain_net_srv_vpn_tun_socket_t * l_tun = s_tun_sockets[a_ch->stream_worker->worker->id];
                assert(l_tun);
                size_t l_size_to_send = l_vpn_pkt->header.op_data.data_size;
                ssize_t l_ret = write(l_tun->es->fd, l_vpn_pkt->data, l_size_to_send);
                if (l_ret > 0) {
                    s_update_limits(a_ch, l_srv_session, l_usage, l_ret);
                    if (l_ret == l_size_to_send) {
                        l_srv_session->stats.packets_sent++;
                        l_srv_session->stats.bytes_sent += l_ret;
                    } else {
                        log_it (L_WARNING, "Lost %zd bytes", l_size_to_send - l_ret);
                        l_srv_session->stats.bytes_sent_lost += (l_size_to_send - l_ret);
                        l_srv_session->stats.packets_sent_lost++;
                    }
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    s_tun_fifo_write(l_tun, l_vpn_pkt);
                    dap_events_socket_set_writable_unsafe(l_tun->es, true);
                } else {
                    char l_errbuf[128];
                    strerror_r(errno, l_errbuf, sizeof (l_errbuf));
                    log_it(L_WARNING,"Error with data sent: \"%s\" code %d", l_errbuf, errno);
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

    dap_chain_net_srv_usage_t * l_usage = dap_chain_net_srv_usage_find_unsafe(l_srv_session,  l_ch_vpn->usage_id);
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
    if ( (! l_usage->is_free) && (! l_usage->receipt) ){
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

static void s_tun_fifo_write(dap_chain_net_srv_vpn_tun_socket_t *a_tun, ch_vpn_pkt_t *a_pkt)
{
    if (!a_tun || !a_pkt)
        return;
    a_tun->fifo = dap_list_append(a_tun->fifo, DAP_DUP_SIZE(a_pkt,
                                                            a_pkt->header.op_data.data_size + sizeof(a_pkt->header)));
}

static ch_vpn_pkt_t *s_tun_fifo_read(dap_chain_net_srv_vpn_tun_socket_t *a_tun)
{
    if (!a_tun || !a_tun->fifo)
        return NULL;
    ch_vpn_pkt_t *l_ret = (ch_vpn_pkt_t *)a_tun->fifo->data;
    dap_list_t *l_to_delete = a_tun->fifo;
    a_tun->fifo = a_tun->fifo->next;
    DAP_DELETE(l_to_delete);
    return l_ret;
}

/**
 * @brief m_es_tun_delete
 * @param a_es
 * @param arg
 */
static void s_es_tun_delete(dap_events_socket_t * a_es, void * arg)
{
    (void) arg;
    if (a_es->worker) {
        s_tun_sockets[a_es->worker->id] = NULL;
        dap_events_socket_remove_and_delete_unsafe(s_tun_sockets_queue_msg[a_es->worker->id],false);
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
    ch_vpn_pkt_t *l_vpn_pkt = (ch_vpn_pkt_t *)l_tun->fifo->data;
    if (!l_vpn_pkt)
        return;
    a_es->buf_out_zero_count = 0;
    size_t l_size_to_send = l_vpn_pkt->header.op_data.data_size;
    ssize_t l_ret = write(l_tun->es->fd, l_vpn_pkt->data, l_size_to_send);
    if (l_ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return;
    }
    s_tun_fifo_read(l_tun);
    DAP_DELETE(l_vpn_pkt);
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
    struct iphdr *iph = (struct iphdr*) a_es->buf_in;
    if (s_debug_more){
        char l_str_daddr[INET_ADDRSTRLEN]={[0]='\0'};
        char l_str_saddr[INET_ADDRSTRLEN]={[0]='\0'};
        struct in_addr l_daddr={ .s_addr = iph->daddr};
        struct in_addr l_saddr={ .s_addr = iph->saddr};
        inet_ntop(AF_INET,&l_daddr,l_str_daddr,sizeof (iph->daddr));
        inet_ntop(AF_INET,&l_saddr,l_str_saddr,sizeof (iph->saddr));
        log_it(L_DEBUG,"m_es_tun_read() received ip packet %s->%s tot_len: %u ",
               l_str_saddr, l_str_saddr, iph->tot_len);
    }

    if(l_buf_in_size) {
        struct in_addr l_in_daddr;
        l_in_daddr.s_addr = iph->daddr;

        //
        dap_chain_net_srv_ch_vpn_info_t * l_vpn_info = NULL;
        // Try to find in worker's clients, without locks
        if ( l_tun_socket->clients){
            HASH_FIND_INT( l_tun_socket->clients,&l_in_daddr.s_addr,l_vpn_info );
        }
        // We found in local table, sending data (if possible)
        if (l_vpn_info){
            if ( !l_vpn_info->is_on_this_worker && !l_vpn_info->is_reassigned_once && s_raw_server->auto_cpu_reassignment ){
                log_it(L_NOTICE, "Reassigning from worker %u to %u", l_vpn_info->worker->id, a_es->worker->id);
                l_vpn_info->is_reassigned_once = true;
                s_tun_send_msg_esocket_reasigned_all_inter(l_vpn_info->ch_vpn, l_vpn_info->esocket,l_vpn_info->esocket_uuid,
                                                           l_vpn_info->addr_ipv4,a_es->worker->id);
                dap_events_socket_reassign_between_workers_mt( l_vpn_info->worker,l_vpn_info->esocket,a_es->worker);
            }
            s_tun_client_send_data(l_vpn_info, a_es->buf_in, l_buf_in_size);
        }else if(s_debug_more){
            char l_str_daddr[INET_ADDRSTRLEN]={[0]='\0'};
            inet_ntop(AF_INET,&l_in_daddr,l_str_daddr,sizeof (l_in_daddr));
            log_it(L_WARNING, "Can't find route for desitnation %s",l_str_daddr);
        }
    }
    a_es->buf_in_size=0; // NULL it out because read it all
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
    log_it(L_ERROR,"%s: error %d in socket %"DAP_FORMAT_SOCKET" (socket type %d)", __PRETTY_FUNCTION__, a_error, a_es->socket, a_es->type);
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
        dap_worker_t * l_worker = l_tun_socket->worker = a_es->worker;
        uint32_t l_worker_id = l_tun_socket->worker_id = l_worker->id;
        l_tun_socket->es = a_es;

        s_tun_sockets_queue_msg[l_worker_id] = dap_events_socket_create_type_queue_ptr_unsafe(l_worker, s_tun_recv_msg_callback );
        s_tun_sockets[l_worker_id] = l_tun_socket;

        l_tun_socket->queue_tun_msg_input = DAP_NEW_Z_SIZE(dap_events_socket_t*,sizeof(dap_events_socket_t*)*
                                                            dap_events_worker_get_count());
        a_es->_inheritor = l_tun_socket;
        s_tun_attach_queue( a_es->fd );

        // Signal thats its ready
        pthread_mutex_lock(&s_tun_sockets_mutex_started[l_worker_id]);
        pthread_mutex_unlock(&s_tun_sockets_mutex_started[l_worker_id]);
        pthread_cond_broadcast(&s_tun_sockets_cond_started[l_worker_id]);

        log_it(L_NOTICE,"New TUN event socket initialized for worker %u" , l_tun_socket->worker_id);

    }else{
        log_it(L_ERROR, "Can't allocate memory for tun socket");
    }
}

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
