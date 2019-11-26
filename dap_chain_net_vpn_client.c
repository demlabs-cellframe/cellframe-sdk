/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2019
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

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"

#include "dap_client.h"
#include "dap_chain_node_client.h"

#include "dap_stream_ch_proc.h"

#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_vpn_client.h"

#include "dap_stream_ch_pkt.h"
#include "dap_chain_net_vpn_client_tun.h"

typedef enum dap_http_client_state {
    DAP_HTTP_CLIENT_STATE_NONE = 0,
    DAP_HTTP_CLIENT_STATE_START = 1,
    DAP_HTTP_CLIENT_STATE_HEADERS = 2,
    DAP_HTTP_CLIENT_STATE_DATA = 3
} dap_http_client_state_t;

#define LOG_TAG "vpn_client"

static EPOLL_HANDLE sf_socks_epoll_fd;

static ch_vpn_socket_proxy_t *sf_socks = NULL;
static ch_vpn_socket_proxy_t *sf_socks_client = NULL;

static pthread_mutex_t sf_socks_mutex;

static dap_chain_node_info_t *s_node_info = NULL;
static dap_chain_node_client_t *s_vpn_client = NULL;

dap_stream_ch_t* dap_chain_net_vpn_client_get_stream_ch(void)
{
    if(!s_vpn_client)
        return NULL;
    dap_stream_ch_t *l_stream = dap_client_get_stream_ch(s_vpn_client->client, DAP_STREAM_CH_ID_NET_SRV_VPN );
    return l_stream;
}



/// TODO convert below callback to processor of stage
/*
void s_stage_callback()
{
    char* l_full_path = NULL;
    const char * l_path = "stream";
    const char *l_suburl = "globaldb";
    int l_full_path_size = snprintf(l_full_path, 0, "%s/%s?session_id=%s", DAP_UPLINK_PATH_STREAM, l_suburl,
            dap_client_get_stream_id(a_client_pvt->client));
    l_full_path = DAP_NEW_Z_SIZE(char, l_full_path_size + 1);
    snprintf(l_full_path, l_full_path_size + 1, "%s/%s?session_id=%s", DAP_UPLINK_PATH_STREAM, l_suburl,
            dap_client_get_stream_id(a_client_pvt->client));

    //dap_client_request(a_client_pvt->client, l_full_path, "12345", 0, m_stream_response, m_stream_error);

    const char *l_add_str = "";
    // if connect to vpn server
    const char l_active_vpn_channels[] = { VPN_CLIENT_ID, 0 };
    if(!dap_strcmp(a_client_pvt->active_channels, l_active_vpn_channels))
        l_add_str = "\r\nService-Key: test";

    {
        char *l_message = dap_strdup_printf("GET /%s HTTP/1.1\r\nHost: %s:%d%s\r\n\r\n",
                l_full_path, a_client_pvt->uplink_addr, a_client_pvt->uplink_port, l_add_str);
        size_t l_message_size = dap_strlen(l_message);
        int count = send(a_client_pvt->stream_socket, l_message, l_message_size, 0);
        DAP_DELETE(l_message);
    }
    DAP_DELETE(l_full_path);

}*/


/**
 * Start VPN client
 *
 * return: 0 Ok, 1 Already started, <0 Error
 */
int dap_chain_net_vpn_client_start(dap_chain_net_t *a_net, const char *a_ipv4_str, const char *a_ipv6_str, int a_port)
{
    int l_ret = 0;
    if(!a_ipv4_str) // && !a_ipv6_str)
        return -1;
    /*
     dap_client_t *l_client = DAP_NEW_Z(dap_client_t);
     dap_events_t *l_events = NULL; //dap_events_new();
     l_client = dap_client_new(l_events, s_stage_status_callback, s_stage_status_error_callback);
     char l_channels[2] = { VPN_CLIENT_ID, 0 };
     dap_client_set_active_channels(l_client, l_channels);
     dap_client_set_uplink(l_client, strdup(a_ip_v4), a_port);
     dap_client_go_stage(l_client, STAGE_STREAM_STREAMING, s_stage_connected_callback);
     */

    if(!s_node_info)
        s_node_info = DAP_NEW_Z(dap_chain_node_info_t);
    s_node_info->hdr.ext_port = a_port;

    dap_client_stage_t l_stage_target = STAGE_STREAM_STREAMING; //DAP_CLIENT_STAGE_STREAM_CTL;//STAGE_STREAM_STREAMING;
    const char l_active_channels[] = { DAP_STREAM_CH_ID_NET_SRV_VPN , 0 };
    if(a_ipv4_str)
        inet_pton(AF_INET, a_ipv4_str, &(s_node_info->hdr.ext_addr_v4));
    if(a_ipv6_str)
        inet_pton(AF_INET6, a_ipv6_str, &(s_node_info->hdr.ext_addr_v6));



    s_vpn_client = dap_chain_client_connect(s_node_info, l_stage_target, l_active_channels);
    if(!s_vpn_client) {
        log_it(L_ERROR, "Can't connect to VPN server=%s:%d", a_ipv4_str, a_port);
        // clean client struct
        dap_chain_node_client_close(s_vpn_client);
        DAP_DELETE(s_node_info);
        s_node_info = NULL;
        return -2;
    }
    // wait connected
    int timeout_ms = 500000; //5 sec = 5000 ms
    int res = dap_chain_node_client_wait(s_vpn_client, NODE_CLIENT_STATE_CONNECTED, timeout_ms);
    if(res) {
        log_it(L_ERROR, "No response from VPN server=%s:%d", a_ipv4_str, a_port);
        // clean client struct
        dap_chain_node_client_close(s_vpn_client);
        DAP_DELETE(s_node_info);
        s_node_info = NULL;
        return -3;
    }

    l_ret = dap_chain_net_vpn_client_tun_init(a_ipv4_str);

    // send first packet to server
//    if(0)
    {
        dap_stream_ch_t *l_ch = dap_chain_net_vpn_client_get_stream_ch();
        if(l_ch) { // Is present in hash table such destination address
            size_t l_ipv4_str_len = 0; //dap_strlen(a_ipv4_str);
            ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header) + l_ipv4_str_len);

            pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_ADDR_REQUEST;
            //pkt_out->header.sock_id = l_stream->stream->events_socket->socket;
            //pkt_out->header.op_connect.addr_size = l_ipv4_str_len; //remoteAddrBA.length();
            //pkt_out->header.op_connect.port = a_port;
            //memcpy(pkt_out->data, a_ipv4_str, l_ipv4_str_len);
            dap_stream_ch_pkt_write(l_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out,
                    pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
            dap_stream_ch_set_ready_to_write(l_ch, true);
            DAP_DELETE(pkt_out);
        }
    }

    /*    dap_stream_ch_t *l_stream = dap_client_get_stream_ch(s_vpn_client->client, VPN_CLIENT_ID);//dap_stream_ch_chain_get_id());
     size_t l_res = dap_stream_ch_chain_pkt_write(l_stream,
     VPN_PACKET_OP_CODE_CONNECT, a_net->pub.id, (dap_chain_id_t ) { { 0 } },
     a_net->pub.cell_id, NULL, 0);*/

    //return l_ret;
    // send connect packet to server
    /*    {
     dap_stream_ch_t *l_stream = dap_chain_net_vpn_client_get_stream();
     if(l_stream) { // Is present in hash table such destination address
     size_t l_ipv4_str_len = dap_strlen(a_ipv4_str);
     ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header) + l_ipv4_str_len);

     pkt_out->header.op_code = VPN_PACKET_OP_CODE_CONNECT;
     pkt_out->header.sock_id = l_stream->stream->events_socket->socket;
     pkt_out->header.op_connect.addr_size = l_ipv4_str_len; //remoteAddrBA.length();
     pkt_out->header.op_connect.port = a_port;
     memcpy(pkt_out->data, a_ipv4_str, l_ipv4_str_len);

     //            pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_RECV;
     //            pkt_out->header.sock_id = 123;
     //            pkt_out->header.op_data.data_size = 0;
     //memcpy(pkt_out->data, 0, 0);
     dap_stream_ch_pkt_write(l_stream, DATA_CHANNEL_ID, pkt_out,
     pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
     dap_stream_ch_set_ready_to_write(l_stream, true);
     DAP_DELETE(pkt_out);
     }
     }*/

    //l_ret = dap_chain_net_vpn_client_tun_init(a_ipv4_str);
    /*    {
     dap_stream_ch_t *l_stream = dap_chain_net_vpn_client_get_stream();
     if(l_stream) { // Is present in hash table such destination address
     ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header) + 0);
     pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_RECV;
     pkt_out->header.sock_id = 123;
     pkt_out->header.op_data.data_size = 0;
     //memcpy(pkt_out->data, 0, 0);
     dap_stream_ch_pkt_write(l_stream, DATA_CHANNEL_ID, pkt_out,
     pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
     dap_stream_ch_set_ready_to_write(l_stream, true);
     }
     }*/

    return l_ret;
}

int dap_chain_net_vpn_client_stop(void)
{
    // delete connection with VPN server
    if(!s_vpn_client) {
        dap_chain_node_client_close(s_vpn_client);
        s_vpn_client = NULL;
    }
    DAP_DELETE(s_node_info);
    s_node_info = NULL;
    int l_ret = dap_chain_net_vpn_client_tun_delete();

    return l_ret;
}

int dap_chain_net_vpn_client_status(void)
{
    if(!dap_chain_net_vpn_client_tun_status())
        // VPN client started
        return 1;
    return 0;
}

static void vpn_socket_delete(ch_vpn_socket_proxy_t * sf)
{
    close(sf->sock);
    pthread_mutex_destroy(&(sf->mutex));
    if(sf)
        free(sf);
}

static void send_pong_pkt(dap_stream_ch_t* a_ch)
{
//    log_it(L_DEBUG,"---------------------------------- PONG!");
    ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
    pkt_out->header.op_code = VPN_PACKET_OP_CODE_PONG;

    dap_stream_ch_pkt_write(a_ch, 'd', pkt_out,
            pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
    dap_stream_ch_set_ready_to_write(a_ch, true);
    free(pkt_out);
}

/**
 * @brief dap_chain_net_vpn_client_pkt_in
 * @param a_ch
 * @param a_arg
 */
void dap_chain_net_vpn_client_pkt_in(dap_stream_ch_t* a_ch, dap_stream_ch_pkt_t* a_pkt)
{
    ch_vpn_pkt_t * l_sf_pkt = (ch_vpn_pkt_t *) a_pkt->data;
    size_t l_sf_pkt_data_size = a_pkt->hdr.size - sizeof(l_sf_pkt->header);

    if(!a_pkt->hdr.size) {
        log_it(L_WARNING, "Bad input packet");
        return;
    }

    int remote_sock_id = l_sf_pkt->header.sock_id;
    if(l_sf_pkt->header.op_code == 0) { // Raw packets
        log_it(L_WARNING, "Bad op_code=0");
        return;
    }
//    log_it(L_DEBUG,"Got SF packet: remote_sock_id:%d op_code:0x%02x data_size:%lu"
//           ,remote_sock_id, l_sf_pkt->header.op_code, l_sf_pkt_data_size );
    if(l_sf_pkt->header.op_code >= 0xb0) { // Raw packets
        switch (l_sf_pkt->header.op_code) {
        case VPN_PACKET_OP_CODE_VPN_ADDR_REPLY: { // Assigned address for peer
            if(ch_sf_tun_addr_leased(CH_VPN(a_ch), l_sf_pkt, l_sf_pkt_data_size) < 0) {
                log_it(L_WARNING, "Can't create tun");
            }
        }
            break;
        case VPN_PACKET_OP_CODE_VPN_ADDR_REQUEST: // Client request after L3 connection the new IP address
            log_it(L_WARNING, "Got VPN_PACKET_OP_CODE_VPN_ADDR_REQUEST packet with id %d, it's very strange' ",
                    remote_sock_id);
            break;
        case VPN_PACKET_OP_CODE_VPN_SEND:
            log_it(L_WARNING, "Got VPN_PACKET_OP_CODE_VPN_SEND packet with id %d, it's very strange' ", remote_sock_id);

        case VPN_PACKET_OP_CODE_VPN_RECV:
            a_ch->stream->events_socket->last_ping_request = time(NULL); // not ping, but better  ;-)
            ch_sf_tun_send(CH_VPN(a_ch), l_sf_pkt->data, l_sf_pkt->header.op_data.data_size);
            break;
        case VPN_PACKET_OP_CODE_PING:
            a_ch->stream->events_socket->last_ping_request = time(NULL);
            send_pong_pkt(a_ch);
            break;
        case VPN_PACKET_OP_CODE_PONG:
            a_ch->stream->events_socket->last_ping_request = time(NULL);
            break;
        default:
            log_it(L_WARNING, "Can't process SF type 0x%02x", l_sf_pkt->header.op_code);
        }
    } else { // All except CONNECT
        ch_vpn_socket_proxy_t * sf_sock = NULL;
        if((l_sf_pkt->header.op_code != VPN_PACKET_OP_CODE_CONNECT) // tcp
        && (l_sf_pkt->header.op_code != VPN_PACKET_OP_CODE_CONNECTED)) { //udp

            pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
            log_it(L_DEBUG, "Looking in hash table with %d", remote_sock_id);
            HASH_FIND_INT((CH_VPN(a_ch)->socks), &remote_sock_id, sf_sock);
            pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

            if(sf_sock != NULL) {
                pthread_mutex_lock(&sf_sock->mutex); // Unlock it in your case as soon as possible to reduce lock time
                sf_sock->time_lastused = time(NULL);
                switch (l_sf_pkt->header.op_code) {
                case VPN_PACKET_OP_CODE_SEND: {
                    int ret;
                    if((ret = send(sf_sock->sock, l_sf_pkt->data, l_sf_pkt->header.op_data.data_size, 0)) < 0) {
                        log_it(L_INFO, "Disconnected from the remote host");
                        pthread_mutex_unlock(&sf_sock->mutex);
                        pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
                        HASH_DEL(CH_VPN(a_ch)->socks, sf_sock);
                        pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

                        pthread_mutex_lock(&sf_socks_mutex);
                        HASH_DELETE(hh2, sf_socks, sf_sock);
                        HASH_DELETE(hh_sock, sf_socks_client, sf_sock);

                        struct epoll_event ev;
                        ev.data.fd = sf_sock->sock;
                        ev.events = EPOLLIN;
                        if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_DEL, sf_sock->sock, &ev) < 0) {
                            log_it(L_ERROR, "Can't remove sock_id %d from the epoll fd", remote_sock_id);
                            //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=0x%02x result=-2",sf_pkt->sock_id, sf_pkt->op_code);
                        } else {
                            log_it(L_NOTICE, "Removed sock_id %d from the the epoll fd", remote_sock_id);
                            //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=0x%02x result=0",sf_pkt->sock_id, sf_pkt->op_code);
                        }
                        pthread_mutex_unlock(&sf_socks_mutex);

                        vpn_socket_delete(sf_sock);
                    } else {
                        sf_sock->bytes_sent += ret;
                        pthread_mutex_unlock(&sf_sock->mutex);
                    }
                    log_it(L_INFO, "Send action from %d sock_id (sf_packet size %lu,  ch packet size %lu, have sent %d)"
                            , sf_sock->id, l_sf_pkt->header.op_data.data_size, a_pkt->hdr.size, ret);
                }
                    break;
                case VPN_PACKET_OP_CODE_DISCONNECT: {
                    log_it(L_INFO, "Disconnect action from %d sock_id", sf_sock->id);

                    pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
                    HASH_DEL(CH_VPN(a_ch)->socks, sf_sock);
                    pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

                    pthread_mutex_lock(&sf_socks_mutex);

                    HASH_DELETE(hh2, sf_socks, sf_sock);
                    HASH_DELETE(hh_sock, sf_socks_client, sf_sock);

                    struct epoll_event ev;
                    ev.data.fd = sf_sock->sock;
                    ev.events = EPOLLIN;
                    if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_DEL, sf_sock->sock, &ev) < 0) {
                        log_it(L_ERROR, "Can't remove sock_id %d to the epoll fd", remote_sock_id);
                        //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=%uc result=-2",sf_pkt->sock_id, sf_pkt->op_code);
                    } else {
                        log_it(L_NOTICE, "Removed sock_id %d from the epoll fd", remote_sock_id);
                        //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=%uc result=0",sf_pkt->sock_id, sf_pkt->op_code);
                    }
                    pthread_mutex_unlock(&sf_socks_mutex);

                    pthread_mutex_unlock(&sf_sock->mutex);
                    vpn_socket_delete(sf_sock);
                }
                    break;
                default: {
                    log_it(L_WARNING, "Unprocessed op code 0x%02x", l_sf_pkt->header.op_code);
                    pthread_mutex_unlock(&sf_sock->mutex);
                }
                }
            } else
                log_it(L_WARNING, "Packet input: packet with sock_id %d thats not present in current stream channel",
                        remote_sock_id);
        } else {
            HASH_FIND_INT(CH_VPN(a_ch)->socks, &remote_sock_id, sf_sock);
            if(sf_sock) {
                log_it(L_WARNING, "Socket id %d is already used, take another number for socket id", remote_sock_id);
            } else { // Connect action
                struct sockaddr_in remote_addr;
                char addr_str[1024];
                size_t addr_str_size =
                        (l_sf_pkt->header.op_connect.addr_size > (sizeof(addr_str) - 1)) ?
                                (sizeof(addr_str) - 1) :
                                l_sf_pkt->header.op_connect.addr_size;
                memset(&remote_addr, 0, sizeof(remote_addr));
                remote_addr.sin_family = AF_INET;
                remote_addr.sin_port = htons(l_sf_pkt->header.op_connect.port);

                memcpy(addr_str, l_sf_pkt->data, addr_str_size);
                addr_str[addr_str_size] = 0;

                log_it(L_DEBUG, "Connect action to %s:%u (addr_size %lu)", addr_str, l_sf_pkt->header.op_connect.port,
                        l_sf_pkt->header.op_connect.addr_size);
                if(inet_pton(AF_INET, addr_str, &(remote_addr.sin_addr)) < 0) {
                    log_it(L_ERROR, "Wrong remote address '%s:%u'", addr_str, l_sf_pkt->header.op_connect.port);

                    ch_vpn_pkt_t *l_pkt_out = DAP_NEW_Z(ch_vpn_pkt_t);
                    l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;

                    dap_stream_ch_pkt_write(a_ch, 'd', l_pkt_out,
                            l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header));
                    dap_stream_ch_set_ready_to_write(a_ch, true);

                    free(l_pkt_out);

                } else {
                    int s;
                    if((s = socket(AF_INET,
                            (l_sf_pkt->header.op_code == VPN_PACKET_OP_CODE_CONNECT) ?
                            SOCK_STREAM :
                                                                                       SOCK_DGRAM, 0)) >= 0) {
                        log_it(L_DEBUG, "Socket is created (%d)", s);
                        if(connect(s, (struct sockaddr *) &remote_addr, sizeof(remote_addr)) >= 0) {
                            fcntl(s, F_SETFL, O_NONBLOCK);
                            log_it(L_INFO, "Remote address connected (%s:%u) with sock_id %d", addr_str,
                                    l_sf_pkt->header.op_connect.port, remote_sock_id);
                            ch_vpn_socket_proxy_t * sf_sock = NULL;
                            sf_sock = DAP_NEW_Z(ch_vpn_socket_proxy_t);
                            sf_sock->id = remote_sock_id;
                            sf_sock->sock = s;
                            sf_sock->ch = a_ch;
                            pthread_mutex_init(&sf_sock->mutex, NULL);

                            pthread_mutex_lock(&sf_socks_mutex);
                            pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
                            HASH_ADD_INT(CH_VPN(a_ch)->socks, id, sf_sock);
                            log_it(L_DEBUG, "Added %d sock_id with sock %d to the hash table", sf_sock->id,
                                    sf_sock->sock);
                            HASH_ADD(hh2, sf_socks, id, sizeof(sf_sock->id), sf_sock);
                            log_it(L_DEBUG, "Added %d sock_id with sock %d to the hash table", sf_sock->id,
                                    sf_sock->sock);
                            HASH_ADD(hh_sock, sf_socks_client, sock, sizeof(int), sf_sock);
                            // log_it(L_DEBUG,"Added %d sock_id with sock %d to the socks hash table",sf->id,sf->sock);
                            pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));
                            pthread_mutex_unlock(&sf_socks_mutex);

                            struct epoll_event ev;
                            ev.data.fd = s;
                            ev.events = EPOLLIN | EPOLLERR;

                            if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_ADD, s, &ev) == -1) {
                                log_it(L_ERROR, "Can't add sock_id %d to the epoll fd", remote_sock_id);
                                //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=%uc result=-2",sf_pkt->sock_id, sf_pkt->op_code);
                            } else {
                                log_it(L_NOTICE, "Added sock_id %d  with sock %d to the epoll fd", remote_sock_id, s);
                                //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=%uc result=0",sf_pkt->sock_id, sf_pkt->op_code);
                            }
                            dap_stream_ch_set_ready_to_write(a_ch, true);
                        } else {
                            ch_vpn_pkt_t *l_pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(l_pkt_out->header));
                            l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;

                            dap_stream_ch_pkt_write(a_ch, 'd', l_pkt_out,
                                    l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header));
                            dap_stream_ch_set_ready_to_write(a_ch, true);

                            free(l_pkt_out);

                            log_it(L_INFO, "Can't connect to the remote server %s", addr_str);
                            dap_stream_ch_pkt_write_f(a_ch, 'i', "sock_id=%d op_code=%c result=-1",
                                    l_sf_pkt->header.sock_id, l_sf_pkt->header.op_code);
                            dap_stream_ch_set_ready_to_write(a_ch, true);

                        }
                    } else {
                        log_it(L_ERROR, "Can't create the socket");
                        ch_vpn_pkt_t *l_pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(l_pkt_out->header));
                        l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;

                        dap_stream_ch_pkt_write(a_ch, 'd', l_pkt_out,
                                l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header));
                        dap_stream_ch_set_ready_to_write(a_ch, true);

                        free(l_pkt_out);

                    }
                }
            }
        }
    }
}

/**
 * @brief dap_chain_net_vpn_client_pkt_out
 * @param a_ch
 */
void dap_chain_net_vpn_client_pkt_out(dap_stream_ch_t* a_ch)
{
    ch_vpn_socket_proxy_t * l_cur = NULL, *l_tmp;
    bool l_is_smth_out = false;
//    log_it(L_DEBUG,"Socket forwarding packet out callback: %u sockets in hashtable", HASH_COUNT(CH_VPN(ch)->socks) );
    HASH_ITER(hh, CH_VPN(a_ch)->socks , l_cur, l_tmp)
    {
        bool l_signal_to_break = false;
        pthread_mutex_lock(&(l_cur->mutex));
        int i;
//        log_it(L_DEBUG,"Socket with id %d has %u packets in output buffer", cur->id, cur->pkt_out_size );
        if(l_cur->pkt_out_size) {
            for(i = 0; i < l_cur->pkt_out_size; i++) {
                ch_vpn_pkt_t * pout = l_cur->pkt_out[i];
                if(pout) {
                    if(dap_stream_ch_pkt_write(a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pout, pout->header.op_data.data_size + sizeof(pout->header))) {
                        l_is_smth_out = true;
                        if(pout)
                            free(pout);
                        l_cur->pkt_out[i] = NULL;
                    } else {
                        log_it(L_WARNING,
                                "Buffer is overflowed, breaking cycle to let the upper level cycle drop data to the output socket");
                        l_is_smth_out = true;
                        l_signal_to_break = true;
                        break;
                    }
                }
            }
        }

        if(l_signal_to_break) {
            pthread_mutex_unlock(&(l_cur->mutex));
            break;
        }
        l_cur->pkt_out_size = 0;
        if(l_cur->signal_to_delete) {
            log_it(L_NOTICE, "Socket id %d got signal to be deleted", l_cur->id);
            pthread_mutex_lock(&( CH_VPN(a_ch)->mutex));
            HASH_DEL(CH_VPN(a_ch)->socks, l_cur);
            pthread_mutex_unlock(&( CH_VPN(a_ch)->mutex));

            pthread_mutex_lock(&(sf_socks_mutex));
            HASH_DELETE(hh2, sf_socks, l_cur);
            HASH_DELETE(hh_sock, sf_socks_client, l_cur);
            pthread_mutex_unlock(&(sf_socks_mutex));

            pthread_mutex_unlock(&(l_cur->mutex));
            vpn_socket_delete(l_cur);
        } else
            pthread_mutex_unlock(&(l_cur->mutex));
    }
    /*    ch->writable = isSmthOut;
     if(isSmthOut) {
     if(ch->stream->conn_http)
     ch->stream->conn_http->state_write = DAP_HTTP_CLIENT_STATE_DATA; //SAP_HTTP_CONN_STATE_DATA;
     }*/
}

int dap_chain_net_vpn_client_init(dap_config_t * g_config)
{
    pthread_mutex_init(&sf_socks_mutex, NULL);

    return 0;
}

void dap_chain_net_vpn_client_deinit()
{
    pthread_mutex_destroy(&sf_socks_mutex);
}
