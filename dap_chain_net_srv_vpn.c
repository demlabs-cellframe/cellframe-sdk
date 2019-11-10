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

#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include "uthash.h"
#include "utlist.h"

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_config.h"

#include "dap_client_remote.h"
#include "dap_http_client.h"

#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_pkt.h"

#include "dap_chain_net.h"
#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_ledger.h"

#define LOG_TAG "dap_chain_net_srv_vpn"

#define SF_MAX_EVENTS 256

typedef struct vpn_local_network {
    struct in_addr client_addr_last;
    struct in_addr client_addr_mask;
    struct in_addr client_addr_host;
    struct in_addr client_addr;
    int tun_ctl_fd;
    int tun_fd;
    struct ifreq ifr;
    dap_stream_ch_vpn_remote_single_t * clients; // Remote clients identified by destination address

    ch_vpn_pkt_t * pkt_out[400];
    size_t pkt_out_size;
    size_t pkt_out_rindex;
    size_t pkt_out_windex;
    pthread_mutex_t pkt_out_mutex;

    pthread_mutex_t clients_mutex;
} vpn_local_network_t;

typedef struct list_addr_element {
    struct in_addr addr;
    struct list_addr_element *next;
} list_addr_element;

static list_addr_element *list_addr_head = NULL;

static ch_vpn_socket_proxy_t * sf_socks = NULL;
static ch_vpn_socket_proxy_t * sf_socks_client = NULL;
static pthread_mutex_t sf_socks_mutex;
static pthread_cond_t sf_socks_cond;
static int sf_socks_epoll_fd;
static pthread_t srv_sf_socks_pid;
static pthread_t srv_sf_socks_raw_pid;

vpn_local_network_t *raw_server;

void *srv_ch_sf_thread(void * arg);
void *srv_ch_sf_thread_raw(void *arg);
void srv_ch_sf_tun_create();
void srv_ch_sf_tun_destroy();

void srv_ch_sf_new(dap_stream_ch_t* ch, void* arg);
void srv_ch_sf_delete(dap_stream_ch_t* ch, void* arg);
void srv_ch_sf_packet_in(dap_stream_ch_t* ch, void* arg);
void srv_ch_sf_packet_out(dap_stream_ch_t* ch, void* arg);

//static int srv_ch_sf_raw_write(uint8_t op_code, const void * data, size_t data_size);
//void srv_stream_sf_disconnect(ch_vpn_socket_proxy_t * sf_sock);

static const char *s_srv_vpn_addr, *s_srv_vpn_mask;

/**
 * @brief dap_stream_ch_vpn_init Init actions for VPN stream channel
 * @param vpn_addr Zero if only client mode. Address if the node shares its local VPN
 * @param vpn_mask Zero if only client mode. Mask if the node shares its local VPN
 * @return 0 if everything is okay, lesser then zero if errors
 */
int dap_chain_net_srv_vpn_init(dap_config_t * g_config)
{
    const char *s_addr = dap_config_get_item_str(g_config, "vpn", "network_address");
    const char *s_mask = dap_config_get_item_str(g_config, "vpn", "network_mask");
    if(s_addr && s_mask) {
        s_srv_vpn_addr = strdup(s_addr);
        s_srv_vpn_mask = strdup(s_mask);

        raw_server = calloc(1, sizeof(vpn_local_network_t));
        pthread_mutex_init(&raw_server->clients_mutex, NULL);
        pthread_mutex_init(&raw_server->pkt_out_mutex, NULL);
        pthread_mutex_init(&sf_socks_mutex, NULL);
        pthread_cond_init(&sf_socks_cond, NULL);
        pthread_create(&srv_sf_socks_raw_pid, NULL, srv_ch_sf_thread_raw, NULL);
        pthread_create(&srv_sf_socks_pid, NULL, srv_ch_sf_thread, NULL);
        dap_stream_ch_proc_add(SERVICE_CHANNEL_ID, srv_ch_sf_new, srv_ch_sf_delete, srv_ch_sf_packet_in,
                srv_ch_sf_packet_out);
        return 0;
    }
    return -1;
}

/**
 * @brief ch_sf_deinit
 */
void dap_chain_net_srv_vpn_deinit()
{
    pthread_mutex_destroy(&sf_socks_mutex);
    pthread_cond_destroy(&sf_socks_cond);
    free((char*) s_srv_vpn_addr);
    free((char*) s_srv_vpn_mask);
    if(raw_server)
        free(raw_server);
}

void srv_ch_sf_tun_create()
{
    inet_aton(s_srv_vpn_addr, &raw_server->client_addr);
    inet_aton(s_srv_vpn_mask, &raw_server->client_addr_mask);
    raw_server->client_addr_host.s_addr = (raw_server->client_addr.s_addr | 0x01000000); // grow up some shit here!
    raw_server->client_addr_last.s_addr = raw_server->client_addr_host.s_addr;

    if((raw_server->tun_ctl_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        log_it(L_ERROR, "Opening /dev/net/tun error: '%s'", strerror(errno));
    } else {
        int err;
        memset(&raw_server->ifr, 0, sizeof(raw_server->ifr));
        raw_server->ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if((err = ioctl(raw_server->tun_ctl_fd, TUNSETIFF, (void *) &raw_server->ifr)) < 0) {
            log_it(L_CRITICAL, "ioctl(TUNSETIFF) error: '%s' ", strerror(errno));
            close(raw_server->tun_ctl_fd);
            raw_server->tun_ctl_fd = -1;
        } else {
            char buf[256];
            log_it(L_NOTICE, "Bringed up %s virtual network interface (%s/%s)", raw_server->ifr.ifr_name,
                    inet_ntoa(raw_server->client_addr_host), s_srv_vpn_mask);
            raw_server->tun_fd = raw_server->tun_ctl_fd; // Looks yes, its so
            snprintf(buf, sizeof(buf), "ip link set %s up", raw_server->ifr.ifr_name);
            int res = system(buf);
            snprintf(buf, sizeof(buf), "ip addr add %s/%s dev %s ", inet_ntoa(raw_server->client_addr_host),
                    s_srv_vpn_mask,
                    raw_server->ifr.ifr_name);
            res = system(buf);
            res = 0;
        }
    }

}

void srv_ch_sf_tun_destroy()
{
    close(raw_server->tun_fd);
    raw_server->tun_fd = -1;
}

static void callback_trafic(dap_client_remote_t *a_client, dap_stream_ch_t* a_ch)
{
    dap_chain_net_srv_vpn_t *l_ch_vpn = CH_VPN(a_ch);
    //dap_stream_ch_vpn_t *l_ch_vpn = (dap_stream_ch_vpn_t*)(a_ch->internal);
    if(!a_client || !l_ch_vpn)
        return;
    dap_chain_net_srv_abstract_t *srv_common = &l_ch_vpn->net_srv.srv_common;
    size_t bytes_max = srv_common->proposal_params.vpn.limit_bytes;
    static size_t bytes_cur_prev = 0;
    size_t bytes_cur = a_client->download_stat.buf_size_total;
    size_t delta_bytes = (bytes_cur > bytes_cur_prev) ? bytes_cur - bytes_cur_prev : 0;
    // make receipt transaction
    if(delta_bytes) {
        const dap_chain_net_srv_abstract_t *l_cond = &(l_ch_vpn->net_srv.srv_common);
        //l_cond->
        //if()
        //if(!dap_chain_mempool_tx_create_receipt(delta_bytes))
        //    bytes_cur_prev = bytes_cur; // if transaction added successfully
    }
    // no more traffic -> disconnect?
    if(bytes_cur >= bytes_max) {
        //dap_stream_delete(a_ch->stream);
        //dap_stream_ch_delete(a_ch);
        //srv_ch_sf_delete(a_ch, NULL);
    }

}

/**
 * @brief ch_sf_socket_delete
 * @param sf
 */
static void ch_sf_socket_delete(ch_vpn_socket_proxy_t * a_vpn_socket_proxy)
{
    close(a_vpn_socket_proxy->sock);
    pthread_mutex_destroy(& (a_vpn_socket_proxy->mutex) );
    if (a_vpn_socket_proxy)
        DAP_DELETE(a_vpn_socket_proxy);
}


/**
 * @brief stream_sf_new Callback to constructor of object of Ch
 * @param ch
 * @param arg
 */
void srv_ch_sf_new(dap_stream_ch_t* a_stream_ch, void* a_arg)
{
    (void) a_arg;

    a_stream_ch->internal = DAP_NEW_Z(dap_chain_net_srv_vpn_t);
    dap_chain_net_srv_vpn_t * sf = CH_VPN(a_stream_ch);
    pthread_mutex_init(&sf->mutex, NULL);
    sf->raw_l3_sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    //
    if(a_stream_ch->stream->session->service_key) {

        char *l_addr_base58;
        char *l_sign_hash_str;
        a_stream_ch->stream->session->service_key =
                "RpiDC8c1SxrT7TUExyGWNErgV6HtwkKhSd1yLEkTA9qHcSiYA4GXjE67KJQay2TzHdG2ouk42d8GgLyABu6rP55JeFYzBkqZ7CqijDEw;12345";

        const dap_chain_net_srv_abstract_t *l_cond = NULL;
        // debug
        const char *l_net_name = "kelvin-testnet";
        dap_ledger_t *l_ledger = dap_chain_ledger_by_net_name(l_net_name);
        // get value for service and fill l_cond struct
        uint64_t l_value = dap_chain_net_srv_client_auth(l_ledger, a_stream_ch->stream->session->service_key, &l_cond);

        // add service
        if(l_cond && l_value > 0)
                {
            dap_chain_net_srv_t l_srv;
            memset(&l_srv, 0, sizeof(dap_chain_net_srv_t));
            l_srv.callback_trafic = callback_trafic;
            // debug
            l_srv.srv_common.proposal_params.vpn.limit_bytes = 2000;
            if(l_cond)
                memcpy(&l_srv.srv_common, l_cond, sizeof(dap_chain_net_srv_abstract_t));
            dap_chain_net_srv_gen_uid((uint8_t*) &l_srv.uid, sizeof(l_srv.uid));
            dap_chain_net_srv_add(&l_srv);
            memcpy(&sf->net_srv, &l_srv, sizeof(dap_chain_net_srv_t)); // Unique ID for service.
        }

    }
}

/**
 * @brief stream_sf_delete
 * @param ch
 * @param arg
 */
void srv_ch_sf_delete(dap_stream_ch_t* ch, void* arg)
{
    log_it(L_DEBUG, "ch_sf_delete() for %s", ch->stream->conn->hostaddr);
    ch_vpn_socket_proxy_t * cur, *tmp;
    dap_stream_ch_vpn_remote_single_t * raw_client = 0;
    // in_addr_t raw_client_addr = CH_SF(ch)->tun_client_addr.s_addr;
    in_addr_t raw_client_addr = ch->stream->session->tun_client_addr.s_addr;

    if(raw_client_addr) {
        log_it(L_DEBUG, "ch_sf_delete() %s searching in hash table",
                inet_ntoa(ch->stream->session->tun_client_addr));
        list_addr_element *el = (list_addr_element*) malloc(sizeof(list_addr_element));
        //el->addr = CH_SF(ch)->tun_client_addr;
        el->addr = ch->stream->session->tun_client_addr;
        LL_APPEND(list_addr_head, el);
        //   LL_FOREACH(list_addr_head,el) log_it(L_INFO,"addr = %s", inet_ntoa(el->addr));

        pthread_mutex_lock(&raw_server->clients_mutex);

        HASH_FIND_INT(raw_server->clients, &raw_client_addr, raw_client);
        if(raw_client) {
            HASH_DEL(raw_server->clients, raw_client);
            log_it(L_DEBUG, "ch_sf_delete() %s removed from hash table",
                    inet_ntoa(ch->stream->session->tun_client_addr));
            free(raw_client);
        } else
            log_it(L_DEBUG, "ch_sf_delete() %s is not present in raw sockets hash table",
                    inet_ntoa(ch->stream->session->tun_client_addr));

        pthread_mutex_unlock(&raw_server->clients_mutex);
    }
    HASH_ITER(hh, CH_VPN(ch)->socks , cur, tmp)
    {
        log_it(L_DEBUG, "delete socket: %i", cur->sock);
        HASH_DEL(CH_VPN(ch)->socks, cur);
        if(cur)
            free(cur);
    }
    pthread_mutex_unlock(&( CH_VPN(ch)->mutex));
    if(CH_VPN(ch)->raw_l3_sock)
        close(CH_VPN(ch)->raw_l3_sock);
}

static void stream_sf_socket_delete(ch_vpn_socket_proxy_t * sf)
{
    dap_return_if_fail(sf);
    if(sf->sock > 0)
        close(sf->sock);
    // wait while mutex will be released if it be locked
    pthread_mutex_lock(&sf->mutex);
    pthread_mutex_unlock(&sf->mutex);

    pthread_mutex_destroy(&(sf->mutex));
    free(sf);
}

static void stream_sf_socket_ready_to_write(dap_stream_ch_t * ch, bool is_ready)
{
    pthread_mutex_lock(&ch->mutex);
    ch->ready_to_write = is_ready;
    if(is_ready)
        ch->stream->conn_http->state_write = DAP_HTTP_CLIENT_STATE_DATA;
    //!!!
    //dap_stream_ch_set_ready_to_write(ch, is_ready);
    dap_client_remote_ready_to_write(ch->stream->conn, is_ready);
    pthread_mutex_unlock(&ch->mutex);

}

static ch_vpn_pkt_t* srv_ch_sf_raw_read()
{
    ch_vpn_pkt_t*ret = NULL;
    pthread_mutex_lock(&raw_server->pkt_out_mutex);
    if(raw_server->pkt_out_rindex == (sizeof(raw_server->pkt_out) / sizeof(raw_server->pkt_out[0]))) {
        raw_server->pkt_out_rindex = 0; // ring the buffer!
    }
    if((raw_server->pkt_out_rindex != raw_server->pkt_out_windex) || (raw_server->pkt_out_size == 0)) {
        ret = raw_server->pkt_out[raw_server->pkt_out_rindex];
        raw_server->pkt_out_rindex++;
        raw_server->pkt_out_size--;
    } //else
      //  log_it(L_WARNING, "Packet drop on raw_read() operation, ring buffer is full");
    pthread_mutex_unlock(&raw_server->pkt_out_mutex);
    return ret;
}

/**
 * @brief stream_sf_packet_in
 * @param ch
 * @param arg
 */
void srv_ch_sf_packet_in(dap_stream_ch_t* ch, void* arg)
{
    dap_stream_ch_pkt_t * pkt = (dap_stream_ch_pkt_t *) arg;

    static bool client_connected = false;
    ch_vpn_pkt_t * sf_pkt = (ch_vpn_pkt_t *) pkt->data;

    int remote_sock_id = sf_pkt->header.sock_id;

    //log_it(L_DEBUG, "Got SF packet with id %d op_code 0x%02x", remote_sock_id, sf_pkt->header.op_code);
    if(sf_pkt->header.op_code >= 0xb0) { // Raw packets
        switch (sf_pkt->header.op_code) {
        case VPN_PACKET_OP_CODE_VPN_ADDR_REQUEST: { // Client request after L3 connection the new IP address
            log_it(L_DEBUG, "Got SF packet with id %d op_code 0x%02x", remote_sock_id, sf_pkt->header.op_code);
            struct in_addr n_addr = { 0 };

            if(n_addr.s_addr == 0) { // If the addres still in the network

                pthread_mutex_lock(&raw_server->clients_mutex);

                int count_free_addr = -1;
                list_addr_element *el;
                LL_COUNT(list_addr_head, el, count_free_addr);

                dap_stream_ch_vpn_remote_single_t * n_client = (dap_stream_ch_vpn_remote_single_t*) calloc(1,
                        sizeof(dap_stream_ch_vpn_remote_single_t));
                n_client->ch = ch;

                if(count_free_addr > 0) {
                    n_addr.s_addr = list_addr_head->addr.s_addr;
                    LL_DELETE(list_addr_head, list_addr_head);
                }
                else
                {
                    n_addr.s_addr = ntohl(raw_server->client_addr_last.s_addr);
                    n_addr.s_addr++;
                    n_addr.s_addr = ntohl(n_addr.s_addr);
                }

                n_client->addr = n_addr.s_addr;
                raw_server->client_addr_last.s_addr = n_addr.s_addr;
                ch->stream->session->tun_client_addr.s_addr = n_addr.s_addr;
                HASH_ADD_INT(raw_server->clients, addr, n_client);

                pthread_mutex_unlock(&raw_server->clients_mutex);

                log_it(L_NOTICE, "VPN client address %s leased", inet_ntoa(n_addr));
                log_it(L_INFO, "\tgateway %s", inet_ntoa(raw_server->client_addr_host));
                log_it(L_INFO, "\tmask %s", inet_ntoa(raw_server->client_addr_mask));
                log_it(L_INFO, "\taddr %s", inet_ntoa(raw_server->client_addr));
                log_it(L_INFO, "\tlast_addr %s", inet_ntoa(raw_server->client_addr_last));

                ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1,
                        sizeof(pkt_out->header) + sizeof(n_addr) + sizeof(raw_server->client_addr_host));
                pkt_out->header.sock_id = raw_server->tun_fd;
                pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_ADDR_REPLY;
                pkt_out->header.op_data.data_size = sizeof(n_addr) + sizeof(raw_server->client_addr_host);
                memcpy(pkt_out->data, &n_addr, sizeof(n_addr));
                memcpy(pkt_out->data + sizeof(n_addr), &raw_server->client_addr_host,
                        sizeof(raw_server->client_addr_host));
                dap_stream_ch_pkt_write(ch, DATA_CHANNEL_ID, pkt_out,
                        pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
                stream_sf_socket_ready_to_write(ch, true);

                //ch_sf_raw_write(n_addr.s_addr,STREAM_SF_PACKET_OP_CODE_RAW_L3_ADDR_REPLY,&n_addr,sizeof(n_addr));
            } else { // All the network is filled with clients, can't lease a new address
                log_it(L_WARNING, "All the network is filled with clients, can't lease a new address");
                ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
                pkt_out->header.sock_id = raw_server->tun_fd;
                pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;
                pkt_out->header.op_problem.code = VPN_PROBLEM_CODE_NO_FREE_ADDR;
                dap_stream_ch_pkt_write(ch, DATA_CHANNEL_ID, pkt_out,
                        pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
                stream_sf_socket_ready_to_write(ch, true);
            }
        }
            break;
        case VPN_PACKET_OP_CODE_VPN_SEND: {
            struct in_addr in_saddr, in_daddr;
            in_saddr.s_addr = ((struct iphdr*) sf_pkt->data)->saddr;
            in_daddr.s_addr = ((struct iphdr*) sf_pkt->data)->daddr;

            char str_daddr[42], str_saddr[42];
            strncpy(str_saddr, inet_ntoa(in_saddr), sizeof(str_saddr));
            strncpy(str_daddr, inet_ntoa(in_daddr), sizeof(str_daddr));
            int ret;
            //if( ch_sf_raw_write(STREAM_SF_PACKET_OP_CODE_RAW_SEND, sf_pkt->data, sf_pkt->op_data.data_size)<0){
            struct sockaddr_in sin = { 0 };
            sin.sin_family = AF_INET;
            sin.sin_port = 0;
            sin.sin_addr.s_addr = in_daddr.s_addr;

            //if((ret=sendto(CH_SF(ch)->raw_l3_sock , sf_pkt->data,sf_pkt->header.op_data.data_size,0,(struct sockaddr *) &sin, sizeof (sin)))<0){
            if((ret = write(raw_server->tun_fd, sf_pkt->data, sf_pkt->header.op_data.data_size)) < 0) {
                log_it(L_ERROR, "write() returned error %d : '%s'", ret, strerror(errno));
                //log_it(L_ERROR,"raw socket ring buffer overflowed");
                ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
                pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;
                pkt_out->header.op_problem.code = VPN_PROBLEM_CODE_PACKET_LOST;
                pkt_out->header.sock_id = raw_server->tun_fd;
                dap_stream_ch_pkt_write(ch, DATA_CHANNEL_ID, pkt_out,
                        pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
                stream_sf_socket_ready_to_write(ch, true);
            } else {
                //log_it(L_DEBUG, "Raw IP packet daddr:%s saddr:%s  %u from %d bytes sent to tun/tap interface",
                //        str_saddr, str_daddr, sf_pkt->header.op_data.data_size, ret);
                //log_it(L_DEBUG, "Raw IP sent %u bytes ", ret);
            }
            //}
        }
            break;
        default:
            log_it(L_WARNING, "Can't process SF type 0x%02x", sf_pkt->header.op_code);
        }
    } else { // All except CONNECT
        ch_vpn_socket_proxy_t * sf_sock = NULL;
        if(sf_pkt->header.op_code != VPN_PACKET_OP_CODE_CONNECT) {

            pthread_mutex_lock(&( CH_VPN(ch)->mutex));
            //      log_it(L_DEBUG,"Looking in hash table with %d",remote_sock_id);
            HASH_FIND_INT((CH_VPN(ch)->socks), &remote_sock_id, sf_sock);
            pthread_mutex_unlock(&( CH_VPN(ch)->mutex));

            if(sf_sock != NULL) {
                pthread_mutex_lock(&sf_sock->mutex); // Unlock it in your case as soon as possible to reduce lock time
                sf_sock->time_lastused = time(NULL);
                switch (sf_pkt->header.op_code) {
                case VPN_PACKET_OP_CODE_SEND: {
                    if(client_connected == false)
                    {
                        log_it(L_WARNING, "Drop Packet! User not connected!"); // Client need send
                        pthread_mutex_unlock(&sf_socks_mutex);
                        break;
                    }
                    int ret;
                    if((ret = send(sf_sock->sock, sf_pkt->data, sf_pkt->header.op_data.data_size, 0)) < 0) {
                        log_it(L_INFO, "Disconnected from the remote host");
                        pthread_mutex_unlock(&sf_sock->mutex);
                        pthread_mutex_lock(&( CH_VPN(ch)->mutex));
                        HASH_DEL(CH_VPN(ch)->socks, sf_sock);
                        pthread_mutex_unlock(&( CH_VPN(ch)->mutex));

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

                        stream_sf_socket_delete(sf_sock);
                    } else {
                        sf_sock->bytes_sent += ret;
                        pthread_mutex_unlock(&sf_sock->mutex);
                    }
                    //log_it(L_INFO, "Send action from %d sock_id (sf_packet size %lu,  ch packet size %lu, have sent %d)"
                    //        , sf_sock->id, sf_pkt->header.op_data.data_size, pkt->hdr.size, ret);
                }
                    break;
                case VPN_PACKET_OP_CODE_DISCONNECT: {
                    log_it(L_INFO, "Disconnect action from %d sock_id", sf_sock->id);

                    pthread_mutex_lock(&( CH_VPN(ch)->mutex));
                    HASH_DEL(CH_VPN(ch)->socks, sf_sock);
                    pthread_mutex_unlock(&( CH_VPN(ch)->mutex));

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
                    stream_sf_socket_delete(sf_sock);
                }
                    break;
                default: {
                    log_it(L_WARNING, "Unprocessed op code 0x%02x", sf_pkt->header.op_code);
                    pthread_mutex_unlock(&sf_sock->mutex);
                }
                }
            } //else
              //  log_it(L_WARNING, "Packet input: packet with sock_id %d thats not present in current stream channel",
              //          remote_sock_id);
        } else {
            HASH_FIND_INT(CH_VPN(ch)->socks, &remote_sock_id, sf_sock);
            if(sf_sock) {
                log_it(L_WARNING, "Socket id %d is already used, take another number for socket id", remote_sock_id);
            } else { // Connect action
                struct sockaddr_in remote_addr;
                char addr_str[1024];
                size_t addr_str_size =
                        (sf_pkt->header.op_connect.addr_size > (sizeof(addr_str) - 1)) ?
                                (sizeof(addr_str) - 1) :
                                sf_pkt->header.op_connect.addr_size;
                memset(&remote_addr, 0, sizeof(remote_addr));
                remote_addr.sin_family = AF_INET;
                remote_addr.sin_port = htons(sf_pkt->header.op_connect.port);

                memcpy(addr_str, sf_pkt->data, addr_str_size);
                addr_str[addr_str_size] = 0;

                log_it(L_DEBUG, "Connect action to %s:%u (addr_size %lu)", addr_str, sf_pkt->header.op_connect.port,
                        sf_pkt->header.op_connect.addr_size);
                if(inet_pton(AF_INET, addr_str, &(remote_addr.sin_addr)) < 0) {
                    log_it(L_ERROR, "Wrong remote address '%s:%u'", addr_str, sf_pkt->header.op_connect.port);
                } else {
                    int s;
                    if((s = socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
                        log_it(L_DEBUG, "Socket is created (%d)", s);
                        if(connect(s, (struct sockaddr *) &remote_addr, sizeof(remote_addr)) >= 0) {
                            fcntl(s, F_SETFL, O_NONBLOCK);
                            log_it(L_INFO, "Remote address connected (%s:%u) with sock_id %d", addr_str,
                                    sf_pkt->header.op_connect.port, remote_sock_id);
                            ch_vpn_socket_proxy_t * sf_sock = NULL;
                            sf_sock = DAP_NEW_Z(ch_vpn_socket_proxy_t);
                            sf_sock->id = remote_sock_id;
                            sf_sock->sock = s;
                            sf_sock->ch = ch;
                            pthread_mutex_init(&sf_sock->mutex, NULL);

                            pthread_mutex_lock(&sf_socks_mutex);
                            pthread_mutex_lock(&( CH_VPN(ch)->mutex));
                            HASH_ADD_INT(CH_VPN(ch)->socks, id, sf_sock);
                            log_it(L_DEBUG, "Added %d sock_id with sock %d to the hash table", sf_sock->id,
                                    sf_sock->sock);
                            HASH_ADD(hh2, sf_socks, id, sizeof(sf_sock->id), sf_sock);
                            log_it(L_DEBUG, "Added %d sock_id with sock %d to the hash table", sf_sock->id,
                                    sf_sock->sock);
                            HASH_ADD(hh_sock, sf_socks_client, sock, sizeof(int), sf_sock);
                            //log_it(L_DEBUG,"Added %d sock_id with sock %d to the socks hash table",sf->id,sf->sock);
                            pthread_mutex_unlock(&sf_socks_mutex);
                            pthread_mutex_unlock(&( CH_VPN(ch)->mutex));

                            struct epoll_event ev;
                            ev.data.fd = s;
                            ev.events = EPOLLIN | EPOLLERR;

                            if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_ADD, s, &ev) == -1) {
                                log_it(L_ERROR, "Can't add sock_id %d to the epoll fd", remote_sock_id);
                                //stream_ch_pkt_write_f(ch,'i',"sock_id=%d op_code=%uc result=-2",sf_pkt->sock_id, sf_pkt->op_code);
                            } else {
                                log_it(L_NOTICE, "Added sock_id %d  with sock %d to the epoll fd", remote_sock_id, s);
                                log_it(L_NOTICE, "Send Connected packet to User");
                                ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
                                pkt_out->header.sock_id = remote_sock_id;
                                pkt_out->header.op_code = VPN_PACKET_OP_CODE_CONNECTED;
                                dap_stream_ch_pkt_write(ch, SERVICE_CHANNEL_ID, pkt_out,
                                        pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
                                free(pkt_out);
                                client_connected = true;
                            }
                            stream_sf_socket_ready_to_write(ch, true);
                        } else {
                            log_it(L_INFO, "Can't connect to the remote server %s", addr_str);
                            dap_stream_ch_pkt_write_f(ch, 'i', "sock_id=%d op_code=%c result=-1",
                                    sf_pkt->header.sock_id, sf_pkt->header.op_code);
                            stream_sf_socket_ready_to_write(ch, true);
                        }
                    } else {
                        log_it(L_ERROR, "Can't create the socket");
                    }
                }
            }
        }
    }
}

/**
 * @brief stream_sf_disconnect
 * @param sf
 */
void srv_stream_sf_disconnect(ch_vpn_socket_proxy_t * sf_sock)
{
    struct epoll_event ev;
    ev.data.fd = sf_sock->sock;
    ev.events = EPOLLIN | EPOLLERR;
    if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_DEL, sf_sock->sock, &ev) == -1) {
        log_it(L_ERROR, "Can't del sock_id %d from the epoll fd", sf_sock->id);
        //stream_ch_pkt_write_f(sf->ch,'i',"sock_id=%d op_code=%uc result=-1",sf->id, STREAM_SF_PACKET_OP_CODE_RECV);
    } else {
        log_it(L_ERROR, "Removed sock_id %d from the epoll fd", sf_sock->id);
        //stream_ch_pkt_write_f(sf->ch,'i',"sock_id=%d op_code=%uc result=0",sf->id, STREAM_SF_PACKET_OP_CODE_RECV);
    }

    // Compise signal to disconnect to another side, with special opcode STREAM_SF_PACKET_OP_CODE_DISCONNECT
    ch_vpn_pkt_t * pkt_out;
    pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header) + 1);
    pkt_out->header.op_code = VPN_PACKET_OP_CODE_DISCONNECT;
    pkt_out->header.sock_id = sf_sock->id;
    sf_sock->pkt_out[sf_sock->pkt_out_size] = pkt_out;
    sf_sock->pkt_out_size++;
    sf_sock->signal_to_delete = true;
}

/**

 Socket forward
 **/

void * srv_ch_sf_thread(void * arg)
{
    struct epoll_event ev, events[SF_MAX_EVENTS] = { 0 };
    //pthread_mutex_lock(&sf_socks_mutex);
    sf_socks_epoll_fd = epoll_create(SF_MAX_EVENTS);
    sigset_t sf_sigmask;
    sigemptyset(&sf_sigmask);
    sigaddset(&sf_sigmask, SIGUSR2);

    while(1) {
        int nfds = epoll_pwait(sf_socks_epoll_fd, events, SF_MAX_EVENTS, 10000, &sf_sigmask);
        if(nfds < 0) {
            //log_it(L_CRITICAL,"Can't run epoll_wait: %s",strerror(errno));
            continue;
        }
        if(nfds > 0)
            log_it(L_DEBUG, "Epolled %d fd", nfds);
        else
            continue;
        int n;
        for(n = 0; n < nfds; ++n) {
            int s = events[n].data.fd;

            ch_vpn_socket_proxy_t * sf = NULL;
            pthread_mutex_lock(&sf_socks_mutex);
            HASH_FIND(hh_sock, sf_socks_client, &s, sizeof(s), sf);
            pthread_mutex_unlock(&sf_socks_mutex);
            if(sf) {
                if(events[n].events & EPOLLERR) {
                    log_it(L_NOTICE, "Socket id %d has EPOLLERR flag on", s);
                    pthread_mutex_lock(&(sf->mutex));
                    srv_stream_sf_disconnect(sf);
                    pthread_mutex_unlock(&(sf->mutex));
                } else if(events[n].events & EPOLLIN) {
                    char buf[1000000];
                    size_t buf_size;
                    ssize_t ret;
                    pthread_mutex_lock(&(sf->mutex));
                    if(sf->pkt_out_size < ((sizeof(sf->pkt_out) / sizeof(sf->pkt_out[0])) - 1)) {
                        ret = recv(sf->sock, buf, sizeof(buf), 0);
                        //log_it(L_DEBUG,"recv() returned %d",ret);
                        if(ret > 0) {
                            buf_size = ret;
                            ch_vpn_pkt_t * pout;
                            pout = sf->pkt_out[sf->pkt_out_size] = (ch_vpn_pkt_t *) calloc(1,
                                    buf_size + sizeof(pout->header));
                            pout->header.op_code = VPN_PACKET_OP_CODE_RECV;
                            pout->header.sock_id = sf->id;
                            pout->header.op_data.data_size = buf_size;
                            memcpy(pout->data, buf, buf_size);
                            sf->pkt_out_size++;
                            pthread_mutex_unlock(&(sf->mutex));
                            stream_sf_socket_ready_to_write(sf->ch, true);
                        } else {
                            log_it(L_NOTICE,
                                    "Socket id %d returned error on recv() function - may be host has disconnected", s);
                            pthread_mutex_unlock(&(sf->mutex));
                            stream_sf_socket_ready_to_write(sf->ch, true);
                            srv_stream_sf_disconnect(sf);
                        }
                    } else {
                        log_it(L_WARNING, "Can't receive data, full of stack");
                        pthread_mutex_unlock(&(sf->mutex));
                    }
                } else {
                    log_it(L_WARNING, "Unprocessed flags 0x%08X", events[n].events);
                }
            } else {
                if(epoll_ctl(sf_socks_epoll_fd, EPOLL_CTL_DEL, s, &ev) < 0) {
                    log_it(L_ERROR, "Can't remove sock_id %d to the epoll fd", s);
                } else {
                    log_it(L_NOTICE, "Socket id %d is removed from the list", s);
                }
            }
        }
        //pthread_mutex_unlock(&sf_socks_mutex);
    }
}

/**
 *
 *
 **/
void* srv_ch_sf_thread_raw(void *arg)
{
    srv_ch_sf_tun_create();

    if(raw_server->tun_fd <= 0) {
        log_it(L_CRITICAL, "Tun/tap file descriptor is not initialized");
        return NULL;
    }
    /*    if (fcntl(raw_server->tun_fd, F_SETFL, O_NONBLOCK) < 0){ ;
     log_it(L_CRITICAL,"Can't switch tun/tap socket into the non-block mode");
     return NULL;
     }
     if (fcntl(raw_server->tun_fd, F_SETFD, FD_CLOEXEC) < 0){;
     log_it(L_CRITICAL,"Can't switch tun/tap socket to not be passed across execs");
     return NULL;
     }
     */
    uint8_t *tmp_buf;
    ssize_t tmp_buf_size;
    static int tun_MTU = 100000; /// TODO Replace with detection of MTU size

    tmp_buf = (uint8_t *) calloc(1, tun_MTU);
    tmp_buf_size = 0;
    log_it(L_INFO, "Tun/tap thread starts with MTU = %d", tun_MTU);

    fd_set fds_read, fds_read_active;

    FD_ZERO(&fds_read);
    FD_SET(raw_server->tun_fd, &fds_read);
    FD_SET(get_select_breaker(), &fds_read);
    /// Main cycle
    do {
        fds_read_active = fds_read;
        int ret = select(FD_SETSIZE, &fds_read_active, NULL, NULL, NULL);
        //
        if(ret > 0) {
            if(FD_ISSET(get_select_breaker(), &fds_read_active)) { // Smth to send
                ch_vpn_pkt_t* pkt = srv_ch_sf_raw_read();
                if(pkt) {
                    int write_ret = write(raw_server->tun_fd, pkt->data, pkt->header.op_data.data_size);
                    if(write_ret > 0) {
                        //log_it(L_DEBUG, "Wrote out %d bytes to the tun/tap interface", write_ret);
                    } else {
                        log_it(L_ERROR, "Tun/tap write %u bytes returned '%s' error, code (%d)",
                                pkt->header.op_data.data_size, strerror(errno), write_ret);
                    }
                }
            }
            if(FD_ISSET(raw_server->tun_fd, &fds_read_active)) {
                int read_ret = read(raw_server->tun_fd, tmp_buf, tun_MTU);
                if(read_ret < 0) {
                    log_it(L_CRITICAL, "Tun/tap read returned '%s' error, code (%d)", strerror(errno), read_ret);
                    break;
                } else {
                    struct iphdr *iph = (struct iphdr*) tmp_buf;
                    struct in_addr in_daddr, in_saddr;
                    in_daddr.s_addr = iph->daddr;
                    in_saddr.s_addr = iph->saddr;
                    char str_daddr[42], str_saddr[42];
                    dap_snprintf(str_saddr, sizeof(str_saddr), "%s",inet_ntoa(in_saddr) );
                    dap_snprintf(str_daddr, sizeof(str_daddr), "%s",inet_ntoa(in_daddr) );

                    //log_it(L_DEBUG, "Read IP packet from tun/tap interface daddr=%s saddr=%s total_size = %d "
                    //        , str_daddr, str_saddr, read_ret);
                    dap_stream_ch_vpn_remote_single_t * raw_client = NULL;
                    pthread_mutex_lock(&raw_server->clients_mutex);
                    HASH_FIND_INT(raw_server->clients, &in_daddr.s_addr, raw_client);
//                  HASH_ADD_INT(CH_SF(ch)->socks, id, sf_sock );
//                  HASH_DEL(CH_SF(ch)->socks,sf_sock);
                    if(raw_client) { // Is present in hash table such destination address
                        ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header) + read_ret);
                        pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_RECV;
                        pkt_out->header.sock_id = raw_server->tun_fd;
                        pkt_out->header.op_data.data_size = read_ret;
                        memcpy(pkt_out->data, tmp_buf, read_ret);
                        dap_stream_ch_pkt_write(raw_client->ch, DATA_CHANNEL_ID, pkt_out,
                                pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
                        stream_sf_socket_ready_to_write(raw_client->ch, true);
                    }
                    pthread_mutex_unlock(&raw_server->clients_mutex);
                }
            }/*else {
             log_it(L_CRITICAL,"select() has no tun handler in the returned set");
             break;

             }*/
        } else {
            log_it(L_CRITICAL, "Select returned %d", ret);
            break;
        }
    } while(1);
    log_it(L_NOTICE, "Raw sockets listen thread is stopped");
    srv_ch_sf_tun_destroy();
    return NULL;
}

/**
 * @brief stream_sf_packet_out Packet Out Ch callback
 * @param ch
 * @param arg
 */
void srv_ch_sf_packet_out(dap_stream_ch_t* ch, void* arg)
{
    ch_vpn_socket_proxy_t * cur, *tmp;
    bool isSmthOut = false;
//    log_it(L_DEBUG,"Socket forwarding packet out callback: %u sockets in hashtable", HASH_COUNT(CH_SF(ch)->socks) );
    HASH_ITER(hh, CH_VPN(ch)->socks , cur, tmp)
    {
        bool signalToBreak = false;
        pthread_mutex_lock(&(cur->mutex));
        int i;
        //log_it(L_DEBUG, "Socket with id %d has %u packets in output buffer", cur->id, cur->pkt_out_size);
        if(cur->pkt_out_size) {
            for(i = 0; i < cur->pkt_out_size; i++) {
                ch_vpn_pkt_t * pout = cur->pkt_out[i];
                if(pout) {
                    if(dap_stream_ch_pkt_write(ch, DATA_CHANNEL_ID, pout,
                            pout->header.op_data.data_size + sizeof(pout->header))) {
                        isSmthOut = true;
                        free(pout);
                        cur->pkt_out[i] = NULL;
                    } else {
                        //log_it(L_WARNING,
                        //        "Buffer is overflowed, breaking cycle to let the upper level cycle drop data to the output socket");
                        isSmthOut = true;
                        signalToBreak = true;
                        break;
                    }
                }
            }
        }

        if(signalToBreak) {
            pthread_mutex_unlock(&(cur->mutex));
            break;
        }
        cur->pkt_out_size = 0;
        if(cur->signal_to_delete) {
            log_it(L_NOTICE, "Socket id %d got signal to be deleted", cur->id);
            pthread_mutex_lock(&( CH_VPN(ch)->mutex));
            HASH_DEL(CH_VPN(ch)->socks, cur);
            pthread_mutex_unlock(&( CH_VPN(ch)->mutex));

            pthread_mutex_lock(&(sf_socks_mutex));
            HASH_DELETE(hh2, sf_socks, cur);
            HASH_DELETE(hh_sock, sf_socks_client, cur);
            pthread_mutex_unlock(&(sf_socks_mutex));

            pthread_mutex_unlock(&(cur->mutex));
            stream_sf_socket_delete(cur);
        } else
            pthread_mutex_unlock(&(cur->mutex));
    }
    ch->ready_to_write = isSmthOut;
    if(isSmthOut) {
        ch->stream->conn_http->state_write = DAP_HTTP_CLIENT_STATE_DATA;
    }
    dap_client_remote_ready_to_write(ch->stream->conn, isSmthOut);
    //dap_stream_ch_set_ready_to_write(ch, isSmthOut);

}

