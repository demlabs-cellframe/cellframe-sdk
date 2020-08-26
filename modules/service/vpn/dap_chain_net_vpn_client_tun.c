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

#include <sys/epoll.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/in.h>

#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include "utlist.h"

#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "dap_stream.h"
#include "dap_stream_ch_pkt.h"
#include "dap_client.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_vpn_client.h"
#include "dap_chain_net_vpn_client_tun.h"

#define LOG_TAG "vpn_client_tun"

static int s_fd_tun; // tun0 file descriptor

static char s_dev[IFNAMSIZ];
// gateway address before tun start
static char *s_cur_gw = NULL;
// vpn server address
static char *s_cur_ipv4_server = NULL;
// new connection name
static const char *s_conn_name = "nodeVPNClient";
static char *s_last_used_connection_name = NULL, *s_last_used_connection_device = NULL;

static pthread_t s_thread_read_tun_id;
static pthread_mutex_t s_clients_mutex;
static dap_events_socket_t * s_tun_events_socket = NULL;

//list_addr_element * list_addr_head = NULL;
//ch_sf_tun_server_t * m_tun_server = NULL;
//pthread_t sf_socks_tun_pid;

int tun_device_create(char *dev)
{
    struct ifreq ifr;
    int fd, err;
    char clonedev[] = "/dev/net/tun";
    // open the clone device
    if((fd = open(clonedev, O_RDWR)) < 0) {
        log_it(L_ERROR, "Can't open %s device!", clonedev);
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if(dev && *dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    // try to create the device
    if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        log_it(L_ERROR, "Can't create tun network interface!");
        //qCritical() << "Can't create tun network interface!";
        return err;
    }
    if(dev)
        strcpy(dev, ifr.ifr_name);
    log_it(L_INFO, "Created %s network interface", ifr.ifr_name);
    return fd;
}

static char* run_bash_cmd(const char *a_cmd)
{
    char* l_ret_str = NULL;
    FILE* fp = popen(a_cmd, "r");
    char line[256] = { 0x0 };
    if(fgets(line, sizeof(line), fp) != NULL)
        l_ret_str = dap_strdup(dap_strstrip(line));
    pclose(fp);
    return l_ret_str;
}

static void exe_bash_cmd(const char *a_cmd)
{
//    char* l_ret_str = NULL;
    FILE* fp = popen(a_cmd, "r");
    pclose(fp);
}

/**
 * Get default gateway (only for Unix-like)
 *
 * return: gateway or NULL if error
 */
static char* get_def_gateway(void)
{
    char* l_gateway = run_bash_cmd("netstat -rn | grep 'UG[ \t]' | awk '{print $2}'"); //netstat -rn = route -n(for root only)
    return l_gateway;
}

/**
 * Get connection
 *
 * return: connection name or NULL
 */
static char* get_connection(const char *a_conn_name, char **a_connection_dev)
{
    if(!a_conn_name)
        return NULL;
    // NAME                UUID                                  TYPE      DEVICE
    //nodeVPNClient       a2b4cbc4-b8d2-4dd9-ac7f-81d9bf6fa276  tun       --
    char *l_cmd = dap_strdup_printf("nmcli connection show | grep %s | awk '{print $1}'", a_conn_name);
    char* l_connection_name = run_bash_cmd(l_cmd);
    DAP_DELETE(l_cmd);
    if(a_connection_dev) {
        l_cmd = dap_strdup_printf("nmcli connection show | grep %s | awk '{print $4}'", a_conn_name);
        *a_connection_dev = run_bash_cmd(l_cmd);
        DAP_DELETE(l_cmd);
    }
    return l_connection_name;
}

void save_current_connection_interface_data(char **a_last_used_connection_name, char **a_last_used_connection_device)
{
    // nmcli -t -f NAME,TIMESTAMP con show | sort -t: -nk2 | tail -n1 | cut -d: -f1
    char* l_res_str = run_bash_cmd("nmcli -terse --fields NAME,DEVICE con show | head -n1");

    char **l_res_str_arr = dap_strsplit(l_res_str, ":", 2);

    if(dap_str_countv(l_res_str_arr) != 2) {
        log_it(L_ERROR, "Can't get current connection interface name!");
        dap_strfreev(l_res_str_arr);
        return;
    }
    if(a_last_used_connection_name)
        *a_last_used_connection_name = l_res_str_arr[0];
    if(a_last_used_connection_device)
        *a_last_used_connection_device = l_res_str_arr[1];
    DAP_DELETE(l_res_str_arr);
}

void disableIPV6(const char *l_device_name)
{
    if(!l_device_name) {
        log_it(L_ERROR, "Can't disable IPV6 device name is empty");
        return;
    }
    char *l_disable_cmd = dap_strdup_printf("echo 1 > /proc/sys/net/ipv6/conf/%s/disable_ipv6", l_device_name);
    char* l_ret = run_bash_cmd(l_disable_cmd);
    DAP_DELETE(l_disable_cmd);
    DAP_DELETE(l_ret);
}

void enableIPV6(const char *l_device_name)
{
    if(!l_device_name) {
        log_it(L_ERROR, "Can't enable IPV6 device name is empty");
        return;
    }
    char *l_enable_cmd = dap_strdup_printf("echo 0 > /proc/sys/net/ipv6/conf/%s/disable_ipv6", l_device_name);
    char* l_ret = run_bash_cmd(l_enable_cmd);
    DAP_DELETE(l_enable_cmd);
    DAP_DELETE(l_ret);
}

static bool is_local_address(const char *a_address)
{
    if(!a_address)
        return true;
    //In accordance with the IANA standard
    char **l_octets = dap_strsplit(a_address, ".", -1);

    if(dap_str_countv(l_octets) < 4) {
        dap_strfreev(l_octets);
        return false;
    }
    int first_octet = strtol(l_octets[0], NULL, 10);
    int second_octet = strtol(l_octets[1], NULL, 10);
    if(first_octet == 10)
        return true;
    else if(first_octet == 172 && second_octet >= 16 && second_octet < 32)
        return true;
    else if(first_octet == 192 && second_octet == 168)
        return true;
    return false;

}

/**
 * Thread for read from /dev/net/tun
 */
static void* thread_read_tun(void *arg)
{
    //srv_ch_sf_tun_create();

    if(s_fd_tun <= 0) {
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
//    ssize_t tmp_buf_size;
    static int tun_MTU = 100000; /// TODO Replace with detection of MTU size

    tmp_buf = (uint8_t *) calloc(1, tun_MTU);
//    tmp_buf_size = 0;
    log_it(L_INFO, "Tun/tap thread starts with MTU = %d", tun_MTU);

    fd_set fds_read, fds_read_active;

    FD_ZERO(&fds_read);
    FD_SET(s_fd_tun, &fds_read);
    FD_SET(get_select_breaker(), &fds_read);
    /// Main cycle
    do {
        fds_read_active = fds_read;
        int ret = select(FD_SETSIZE, &fds_read_active, NULL, NULL, NULL);
        //
        if(ret > 0) {
            if(FD_ISSET(get_select_breaker(), &fds_read_active)) { // Smth to send
                ch_vpn_pkt_t* pkt = NULL; //TODO srv_ch_sf_raw_read();
                if(pkt) {
                    int write_ret = write(s_fd_tun, pkt->data, pkt->header.op_data.data_size);
                    if(write_ret > 0) {
                        log_it(L_DEBUG, "Wrote out %d bytes to the tun/tap interface", write_ret);
                    } else {
                        log_it(L_ERROR, "Tun/tap write %u bytes returned '%s' error, code (%d)",
                                pkt->header.op_data.data_size, strerror(errno), write_ret);
                    }
                }
            }
            // there is data in tun for sent to vpn server
            if(FD_ISSET(s_fd_tun, &fds_read_active)) {
                int read_ret = read(s_fd_tun, tmp_buf, tun_MTU);
                if(read_ret < 0) {
                    log_it(L_CRITICAL, "Tun/tap read returned '%s' error, code (%d)", strerror(errno), read_ret);
                    break;
                } else {
                    struct iphdr *iph = (struct iphdr*) tmp_buf;
                    struct in_addr in_daddr, in_saddr;
                    // destination address
                    in_daddr.s_addr = iph->daddr;
                    // source address
                    in_saddr.s_addr = iph->saddr;
                    char str_daddr[42], str_saddr[42];
                    strncpy(str_saddr, inet_ntoa(in_saddr), sizeof(str_saddr));
                    strncpy(str_daddr, inet_ntoa(in_daddr), sizeof(str_daddr));

                    if(iph->tot_len > (uint16_t) read_ret) {
                        log_it(L_INFO, "Tun/Tap interface returned only the fragment (tot_len =%u  read_ret=%d) ",
                                iph->tot_len, read_ret);
                    }
                    if(iph->tot_len < (uint16_t) read_ret) {
                        log_it(L_WARNING, "Tun/Tap interface returned more then one packet (tot_len =%u  read_ret=%d) ",
                                iph->tot_len, read_ret);
                    }

                    log_it(L_DEBUG, "Read IP packet from tun/tap interface daddr=%s saddr=%s total_size = %d "
                            , str_daddr, str_saddr, read_ret);

                    //dap_client_t *l_client = l_vpn_client ? l_vpn_client->client : NULL;
                    //DAP_CLIENT_PVT(l_client);
                    //dap_stream_ch_vpn_remote_single_t * raw_client = l_client->;

//                    HASH_FIND_INT(raw_server->clients, &in_daddr.s_addr, raw_client);
                    //                  HASH_ADD_INT(CH_SF(ch)->socks, id, sf_sock );
                    //                  HASH_DEL(CH_SF(ch)->socks,sf_sock);
//                    if(l_stream) { // Is present in hash table such destination address
                    dap_stream_ch_t *l_ch = dap_chain_net_vpn_client_get_stream_ch();
                    dap_stream_worker_t * l_stream_worker = dap_chain_net_vpn_client_get_stream_worker();
                    if(l_ch) {
                        // form packet to vpn-server
                        ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header) + read_ret);
                        pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_SEND; //VPN_PACKET_OP_CODE_VPN_RECV
                        pkt_out->header.sock_id = s_fd_tun;
                        pkt_out->header.op_data.data_size = read_ret;
                        memcpy(pkt_out->data, tmp_buf, read_ret);

                        // sent packet to vpn server
                        dap_stream_ch_pkt_write_mt(l_stream_worker,l_ch , DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out,
                                pkt_out->header.op_data.data_size + sizeof(pkt_out->header));

                        DAP_DELETE(pkt_out);
                    }
                    else {
                        log_it(L_DEBUG, "No remote client for income IP packet with addr %s", inet_ntoa(in_daddr));
                    }

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
    // close tun
    if(s_fd_tun > 0) {
        int l_fd_tun = s_fd_tun;
        s_fd_tun = 0;
        close(l_fd_tun);
    }

    return NULL;
}

int dap_chain_net_vpn_client_tun_init(const char *a_ipv4_server_str)
{
    if(s_cur_ipv4_server)
        DAP_DELETE(s_cur_ipv4_server);
    // set server address
    s_cur_ipv4_server = dap_strdup(a_ipv4_server_str);
    return 0;
}


static void m_client_tun_delete(dap_events_socket_t * a_es, void * arg)
{
  log_it(L_DEBUG, __PRETTY_FUNCTION__);
  //dap_chain_net_vpn_client_tun_delete();
  log_it(L_NOTICE, "Raw sockets listen thread is stopped");
}

static void m_client_tun_write(dap_events_socket_t * a_es, void * arg)
{
//    log_it(L_WARNING, __PRETTY_FUNCTION__);
}

static void m_client_tun_read(dap_events_socket_t * a_es, void * arg)
{
    const static int tun_MTU = 100000; /// TODO Replace with detection of MTU size
    uint8_t l_tmp_buf[tun_MTU];

    size_t l_read_ret;
    log_it(L_WARNING, __PRETTY_FUNCTION__);

    do{
        l_read_ret = dap_events_socket_pop_from_buf_in(a_es, l_tmp_buf, sizeof(l_tmp_buf));

        if(l_read_ret > 0) {
            struct iphdr *iph = (struct iphdr*) l_tmp_buf;
            struct in_addr in_daddr, in_saddr;
            in_daddr.s_addr = iph->daddr;
            in_saddr.s_addr = iph->saddr;
            char str_daddr[42], str_saddr[42];
            dap_snprintf(str_saddr, sizeof(str_saddr), "%s",inet_ntoa(in_saddr) );
            dap_snprintf(str_daddr, sizeof(str_daddr), "%s",inet_ntoa(in_daddr) );

            dap_stream_ch_t *l_ch = dap_chain_net_vpn_client_get_stream_ch();
            if(l_ch) {
                // form packet to vpn-server
                ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header) + l_read_ret);
                pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_SEND; //VPN_PACKET_OP_CODE_VPN_RECV
                pkt_out->header.sock_id = s_fd_tun;
                pkt_out->header.op_data.data_size = l_read_ret;
                memcpy(pkt_out->data, l_tmp_buf, l_read_ret);

                pthread_mutex_lock(&s_clients_mutex);
                // sent packet to vpn server
                dap_stream_ch_pkt_write_mt(l_ch->stream_worker,l_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out,
                        pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
                pthread_mutex_unlock(&s_clients_mutex);

                DAP_DELETE(pkt_out);
            }
            else {
                log_it(L_DEBUG, "No remote client for income IP packet with addr %s", inet_ntoa(in_daddr));
            }
        }
    }while(l_read_ret > 0);

    dap_events_socket_set_readable_unsafe(a_es, true);
}

static void m_client_tun_error(dap_events_socket_t * a_es, void * arg)
{
  log_it(L_DEBUG, __PRETTY_FUNCTION__);
}

int dap_chain_net_vpn_client_tun_create(const char *a_ipv4_addr_str, const char *a_ipv4_gw_str)
{
    //    char dev[IFNAMSIZ] = { 0 };
    memset(s_dev, 0, IFNAMSIZ);
    if((s_fd_tun = tun_device_create(s_dev)) < 0) {
        return -1;
    }
    // get current gateway
    DAP_DELETE(s_cur_gw);
    s_cur_gw = get_def_gateway();
    if(!s_cur_gw) {
        log_it(L_ERROR, "Can't get default gateway");
        return -2;
    }

    // delete default gateway
    char *l_cmd_del_gw = dap_strdup_printf("ip route del default via %s", s_cur_gw);
    char *l_cmd_ret = run_bash_cmd(l_cmd_del_gw);
    DAP_DELETE(l_cmd_del_gw);
    // check gateway
    char *s_cur_gw_tmp = get_def_gateway();
    if(s_cur_gw_tmp) {
        log_it(L_ERROR, "Can't delete default gateway %s)", s_cur_gw);
        DAP_DELETE(s_cur_gw_tmp);
        return -3;
    }
    DAP_DELETE(l_cmd_ret);

    DAP_DELETE(s_last_used_connection_name);
    DAP_DELETE(s_last_used_connection_device);
    s_last_used_connection_name = NULL;
    s_last_used_connection_device = NULL;
    save_current_connection_interface_data(&s_last_used_connection_name, &s_last_used_connection_device);
    disableIPV6(s_last_used_connection_device);

    // add new default gateway for vpn-server address
    if(!is_local_address(s_cur_ipv4_server)) {
        // This route don't need if address is local
        char *l_str_cmd = dap_strdup_printf("route add -host %s gw %s metric 10", s_cur_ipv4_server, s_cur_gw);
        char *l_cmd_ret = run_bash_cmd(l_str_cmd);
        DAP_DELETE(l_str_cmd);
        DAP_DELETE(l_cmd_ret);
    }

    // check and delete present connection
    char *l_conn_present = get_connection(s_conn_name, NULL);
    if(!dap_strcmp(l_conn_present, s_conn_name)) {
        char *l_str_cmd = dap_strdup_printf("nmcli c delete %s", s_conn_name);
        exe_bash_cmd(l_str_cmd);
        DAP_DELETE(l_str_cmd);
    }
    DAP_DELETE(l_conn_present);
    int l_ret = 0;
    // create new connection
    {
        // nmcli connection show
        char *l_cmd_add_con = dap_strdup_printf(
                "nmcli connection add type tun con-name %s autoconnect false ifname %s mode tun ip4 %s gw4 %s",
                s_conn_name, s_dev, a_ipv4_addr_str, a_ipv4_gw_str);
        char *l_cmd_ret = run_bash_cmd(l_cmd_add_con);
        l_conn_present = get_connection(s_conn_name, NULL);
        if(dap_strcmp(l_conn_present, s_conn_name))
            l_ret = -1;
        DAP_DELETE(l_cmd_ret);
        DAP_DELETE(l_cmd_add_con);
        DAP_DELETE(l_conn_present);
    }
    if(l_ret < 0) {
        log_it(L_ERROR, "Can't create network configuration (connection=%s)", s_conn_name);
        if(s_cur_gw) {
            char *l_str_cmd = dap_strdup_printf("ip route add default via %s", s_cur_gw);
            exe_bash_cmd(l_str_cmd);
            DAP_DELETE(l_str_cmd);
        }
        DAP_DELETE(s_cur_gw);
        return l_ret;
    }
    // modify new connection and up
    {
        char *l_str_cmd = dap_strdup_printf("nmcli connection modify %s +ipv4.ignore-auto-routes true", s_conn_name);
        exe_bash_cmd(l_str_cmd);
        DAP_DELETE(l_str_cmd);
        l_str_cmd = dap_strdup_printf("nmcli connection modify %s +ipv4.ignore-auto-dns true", s_conn_name);
        exe_bash_cmd(l_str_cmd);
        DAP_DELETE(l_str_cmd);
        l_str_cmd = dap_strdup_printf("nmcli connection modify %s +ipv4.dns-search %s", s_conn_name, s_conn_name);
        exe_bash_cmd(l_str_cmd);
        DAP_DELETE(l_str_cmd);
        l_str_cmd = dap_strdup_printf("nmcli connection modify %s ipv4.dns-priority 10", s_conn_name);
        exe_bash_cmd(l_str_cmd);
        DAP_DELETE(l_str_cmd);
        l_str_cmd = dap_strdup_printf("nmcli connection modify %s +ipv4.method manual", s_conn_name);
        exe_bash_cmd(l_str_cmd);
        DAP_DELETE(l_str_cmd);
        l_str_cmd = dap_strdup_printf("nmcli connection modify %s +ipv4.dns %s", s_conn_name, s_cur_gw);
        exe_bash_cmd(l_str_cmd);
        DAP_DELETE(l_str_cmd);
        l_str_cmd = dap_strdup_printf("nmcli connection modify %s +ipv4.route-metric 10", s_conn_name);
        exe_bash_cmd(l_str_cmd);
        DAP_DELETE(l_str_cmd);
        l_str_cmd = dap_strdup_printf("nmcli connection up %s", s_conn_name);
        exe_bash_cmd(l_str_cmd);
        DAP_DELETE(l_str_cmd);
    }

    pthread_mutex_init(&s_clients_mutex, NULL);

    if(is_dap_tun_in_worker()) {

        static dap_events_socket_callbacks_t l_s_callbacks = {
                .read_callback = m_client_tun_read,// for server
                .write_callback = m_client_tun_write,// for client
                .error_callback = m_client_tun_error,
                .delete_callback = m_client_tun_delete
        };

        s_tun_events_socket = dap_events_socket_wrap_no_add(NULL, s_fd_tun, &l_s_callbacks);
        s_tun_events_socket->type = DESCRIPTOR_TYPE_FILE;
        dap_worker_add_events_socket_auto(s_tun_events_socket);
        s_tun_events_socket->_inheritor = NULL;

        return 0;
    }
    else {
        pthread_create(&s_thread_read_tun_id, NULL, thread_read_tun, NULL);
    }


    //m_tunDeviceName = dev;
    //m_tunSocket = fd;
    return l_ret;
}

int dap_chain_net_vpn_client_tun_delete(void)
{
    if(is_dap_tun_in_worker())
    {
        pthread_mutex_lock(&s_clients_mutex);
        dap_events_socket_remove_and_delete_mt(s_tun_events_socket->worker, s_tun_events_socket);
        s_tun_events_socket = NULL;
        pthread_mutex_unlock(&s_clients_mutex);
    }

    // restore previous routing
    if(!s_conn_name || !s_last_used_connection_name)
        return -1;
    if(s_fd_tun > 0) {
        int l_fd_tun = s_fd_tun;
        s_fd_tun = 0;
        close(l_fd_tun);
    }
    char *l_str_cmd = dap_strdup_printf("ifconfig %s down", s_dev);
    exe_bash_cmd(l_str_cmd);
    DAP_DELETE(l_str_cmd);

    l_str_cmd = dap_strdup_printf("nmcli connection down %s", s_conn_name);
    exe_bash_cmd(l_str_cmd);
    DAP_DELETE(l_str_cmd);

    l_str_cmd = dap_strdup_printf("nmcli connection delete %s", s_conn_name);
    exe_bash_cmd(l_str_cmd);
    DAP_DELETE(l_str_cmd);

    // for example, ip route add default via 192.168.100.1
    if(s_cur_gw) {
        l_str_cmd = dap_strdup_printf("ip route add default via %s", s_cur_gw);
        exe_bash_cmd(l_str_cmd);
        DAP_DELETE(l_str_cmd);
    }

    enableIPV6(s_last_used_connection_device);

    l_str_cmd = dap_strdup_printf("nmcli connection up \"%s\"", s_last_used_connection_name);
    exe_bash_cmd(l_str_cmd);
    DAP_DELETE(l_str_cmd);

    DAP_DELETE(s_last_used_connection_name);
    DAP_DELETE(s_last_used_connection_device);
    s_last_used_connection_name = NULL;
    s_last_used_connection_device = NULL;
    return 0;
}

int dap_chain_net_vpn_client_tun_status(void)
{
    char *l_conn_dev = NULL;
    char *l_str_cmd = get_connection(s_conn_name, &l_conn_dev);
    if(!l_str_cmd)
        return -1;
    // connection must be present
    if(dap_strcmp(l_str_cmd, s_conn_name) || dap_strcmp(l_conn_dev, s_dev)) {
        DAP_DELETE(l_str_cmd);
        DAP_DELETE(l_conn_dev);
        return -2;
    }
    DAP_DELETE(l_str_cmd);
    DAP_DELETE(l_conn_dev);

    /* alternative method
    char *l_used_connection_name = NULL;
    char *l_used_connection_device = NULL;
    save_current_connection_interface_data(&l_used_connection_name, &l_used_connection_device);
    // connection must be upped
    if(!s_dev || dap_strcmp(l_used_connection_name, s_conn_name) || dap_strcmp(l_used_connection_device, s_dev)) {
        DAP_DELETE(l_used_connection_name);
        DAP_DELETE(l_used_connection_device);
        return -1;
    }
    DAP_DELETE(l_used_connection_name);
    DAP_DELETE(l_used_connection_device);*/

    // VPN client started
    return 0;
}

static void ch_sf_pkt_send(dap_stream_ch_t * a_ch, void * a_data, size_t a_data_size)
{
    ch_vpn_pkt_t *l_pkt_out;
    size_t l_pkt_out_size = sizeof(l_pkt_out->header) + a_data_size;
    //log_it(L_DEBUG,"Peer for addr %s found (pkt_size %d)"
    //       ,inet_ntoa(in_daddr), read_ret);
    if(!a_ch) {
        log_it(L_ERROR, "Try to send to NULL channel");
//        return;
    }
    l_pkt_out = DAP_NEW_Z_SIZE(ch_vpn_pkt_t, l_pkt_out_size);
    l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_RECV;
    l_pkt_out->header.sock_id = a_ch->stream->esocket->socket;
    l_pkt_out->header.op_data.data_size = a_data_size;
    memcpy(l_pkt_out->data, a_data, a_data_size);
    dap_stream_ch_pkt_write_unsafe(a_ch, 'd', l_pkt_out, l_pkt_out_size);
}

void ch_sf_tun_send(dap_chain_net_srv_ch_vpn_t * ch_sf, void * pkt_data, size_t pkt_data_size) {
    bool passPacket = true;
    /*switch(ch_sf_snort_pkt(pkt_data,pkt_data_size)){
     case SNORT_ALERT: passPacket=false; break;
     default: passPacket=true;
     }*/
//    log_it(L_DEBUG,"==== ch_sf_tun_send()");
    if(passPacket) {
//        log_it(L_DEBUG,"==== ch_sf_tun_send() ++");
        struct in_addr in_saddr, in_daddr, in_daddr_net;
        in_saddr.s_addr = ((struct iphdr*) pkt_data)->saddr;
        in_daddr.s_addr = ((struct iphdr*) pkt_data)->daddr;
        in_daddr_net.s_addr = ch_sf->ch->stream->session->tun_client_addr.s_addr; //in_daddr_net.s_addr = in_daddr.s_addr & m_tun_server->int_network_mask.s_addr;
        char * in_daddr_str = strdup(inet_ntoa(in_daddr));
        char * in_saddr_str = strdup(inet_ntoa(in_saddr));

        dap_stream_ch_t * l_route_ch = NULL; //ch_sf_peer_ch_find(ch_sf->ch->stream->session, pkt_data, pkt_data_size);

        if(l_route_ch) {
//            log_it(L_DEBUG, "Route packet %s=>%s to %d socket", in_saddr_str,in_daddr_str,l_route_ch->stream->events_socket->socket);
            ch_sf_pkt_send(l_route_ch, pkt_data, pkt_data_size);
//        }else /*if(m_tun_server->int_network.s_addr != in_daddr_net.s_addr )*/{ // No ways to route so write it out to the OS network stack
//        }else if(ch_sf_peer_ch_find(NULL, pkt_data,pkt_data_size)){ // No ways to route so write it out to the OS network stack
        } else { // if(!ch_sf_peer_ch_check(pkt_data,pkt_data_size)){ // No ways to route so write it out to the OS network stack
            int ret;
//            log_it(L_DEBUG, "Route packet %s=>%s size %u to the OS network stack",in_saddr_str,
//                   in_daddr_str,pkt_data_size);
            //if( ch_sf_raw_write(STREAM_SF_PACKET_OP_CODE_RAW_SEND, sf_pkt->data, sf_pkt->op_data.data_size)<0){
            struct sockaddr_in sin = { 0 };
            sin.sin_family = AF_INET;
            sin.sin_port = 0;
            sin.sin_addr.s_addr = in_daddr.s_addr;
            if((ret = sendto(ch_sf->raw_l3_sock, pkt_data, pkt_data_size, 0, (struct sockaddr *) &sin, sizeof(sin)))
                    < 0) {
                //    if((ret = write(raw_server->tun_fd, sf_pkt->data, sf_pkt->header.op_data.data_size))<0){
                log_it(L_ERROR, "write() returned error %d : '%s'", ret, strerror(errno));
                //log_it(ERROR,"raw socket ring buffer overflowed");
                ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header));
                pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;
                pkt_out->header.op_problem.code = VPN_PROBLEM_CODE_PACKET_LOST;
                pkt_out->header.sock_id = s_fd_tun;
                dap_stream_ch_pkt_write_unsafe(ch_sf->ch, 'd', pkt_out,
                        pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
            } else {
                //log_it(L_DEBUG, "Raw IP packet daddr:%s saddr:%s  %u from %d bytes sent to tun/tap interface",
                //  str_saddr,str_daddr, sf_pkt->header.op_data.data_size,ret);
//                log_it(L_DEBUG,"Raw IP sent %u bytes ",ret);
            }
        }/*else log_it(L_ERROR,"I don't know what to do with packet");*/

        if(in_daddr_str)
            free(in_daddr_str);
        if(in_saddr_str)
            free(in_saddr_str);
    }
}

/**
 * @brief ch_sf_tun_addr_leased
 * @param a_sf
 * @param a_pkt
 * @param a_pkt_data_size
 */
int ch_sf_tun_addr_leased(dap_chain_net_srv_ch_vpn_t * a_sf, ch_vpn_pkt_t * a_pkt, size_t a_pkt_data_size)
{
    // we'd receive address assigment from server
    struct in_addr l_addr = { 0 };
    struct in_addr l_netmask = { 0 };
    struct in_addr l_netaddr = { 0 };
    struct in_addr l_gw = { 0 };

    size_t l_route_net_count = 0;

    if(a_pkt_data_size < (sizeof(l_addr) + sizeof(l_gw))) {
        log_it(L_ERROR, "Too small ADDR_REPLY packet (%u bytes, need at least %u"
                , a_pkt_data_size, sizeof(l_addr));
        return -1;
    }

    l_route_net_count = (a_pkt_data_size - 3 * sizeof(struct in_addr)) / (2 * sizeof(struct in_addr));
    memcpy(&l_addr, a_pkt->data, sizeof(l_addr));
    memcpy(&l_gw, a_pkt->data + sizeof(l_addr), sizeof(l_gw));
    memcpy(&l_netmask, a_pkt->data + sizeof(l_addr) + sizeof(l_gw), sizeof(l_netmask));
    l_netaddr.s_addr = l_addr.s_addr & l_netmask.s_addr;

    char l_addr_buf[INET_ADDRSTRLEN];
    char l_gw_buf[INET_ADDRSTRLEN];
    //char l_netmask_buf[INET_ADDRSTRLEN];
    //char l_netaddr_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &l_addr, l_addr_buf, sizeof(l_addr_buf));
    inet_ntop(AF_INET, &l_gw, l_gw_buf, sizeof(l_gw_buf));
    //inet_ntop(AF_INET, &l_netmask, l_netmask_buf, sizeof(l_netmask_buf));
    //inet_ntop(AF_INET, &l_netaddr, l_netaddr_buf, sizeof(l_netaddr_buf));

    // start new tun connection with vpn address and vpn gateway
    int l_res = dap_chain_net_vpn_client_tun_create(l_addr_buf, l_gw_buf);
    return l_res;

    //log_it(L_DEBUG, "Raw IP packet daddr:%s saddr:%s  %u from %d bytes sent to tun/tap interface",

//    n_client->addr = l_addr.s_addr;
//    if(a_sf->ch->stream->session) {
//        a_sf->ch->stream->session->tun_client_addr.s_addr = l_addr.s_addr;
//        a_sf->ch->stream->session->tun_client_gw.s_addr = l_gw.s_addr;
//        a_sf->ch->stream->session->tun_client_mask.s_addr = l_netmask.s_addr;
//    }
//    HASH_ADD_INT(m_tun_server->clients, addr, n_client);
//    char l_addr_buf[INET_ADDRSTRLEN];
//    char l_netmask_buf[INET_ADDRSTRLEN];
//    char l_netaddr_buf[INET_ADDRSTRLEN];
//    char l_gw_buf[INET_ADDRSTRLEN];
//    char* err;
//    pthread_mutex_unlock(&m_tun_server->clients_mutex);
//    inet_ntop(AF_INET, &l_addr, l_addr_buf, sizeof(l_addr_buf));
//    inet_ntop(AF_INET, &l_gw, l_gw_buf, sizeof(l_gw_buf));
//    inet_ntop(AF_INET, &l_netmask, l_netmask_buf, sizeof(l_netmask_buf));
//    inet_ntop(AF_INET, &l_netaddr, l_netaddr_buf, sizeof(l_netaddr_buf));
//    log_it(L_NOTICE, "Registred tunnel %s=>%s  to %s/%s via remote socket %d", l_addr_buf, l_gw_buf, l_netaddr_buf,
//            l_netmask_buf,
//            a_sf->ch->stream->events_socket->socket);
//    if(a_sf->ch->stream->is_client_to_uplink) {
//        log_it(L_NOTICE, "Assign address %s to the network device %s", l_addr_buf, m_tun_server->ifr.ifr_name);
//        if(exec_with_ret_f(&err, "ip address add %s/%s dev %s", l_addr_buf, l_netmask_buf, m_tun_server->ifr.ifr_name))
//                {
//            log_it(L_ERROR,
//                    "Can't assign ip address, leased from remote server. Routing to the remote network will not work");
//            log_it(L_ERROR, "exec returns: '%s'", err);
//        }
//        ch_sf_tun_peer_add(a_sf, l_addr.s_addr, l_gw.s_addr, l_netmask.s_addr & l_gw.s_addr, l_netmask.s_addr);
//
//        size_t i;
//        log_it(L_DEBUG, "Found %u networks in reply", l_route_net_count);
//        for(i = 0; i < l_route_net_count; i++) {
//            in_addr_t l_r_netaddr;
//            in_addr_t l_r_netmask;
//
//            memcpy(&l_r_netaddr, a_pkt->data + (3 + i * 2) * sizeof(in_addr_t), sizeof(in_addr_t));
//            memcpy(&l_r_netmask, a_pkt->data + (4 + i * 2) * sizeof(in_addr_t), sizeof(in_addr_t));
//
//            if(!l_r_netaddr && !l_r_netmask) {
//                log_it(L_DEBUG, "Ignores default route from upstream");
//                continue;
//            }
//
////            ch_sf_tun_peer_add(a_sf, 0,0,l_r_netaddr,l_r_netmask);
//            ch_sf_tun_peer_add(a_sf, l_r_netaddr, l_r_netmask, l_r_netaddr, l_r_netmask);
//            inet_ntop(AF_INET, &l_r_netmask, l_netmask_buf, sizeof(l_netmask_buf));
//            inet_ntop(AF_INET, &l_r_netaddr, l_netaddr_buf, sizeof(l_netaddr_buf));
//
////            if(!l_r_netaddr && !l_r_netmask){
////                log_it(L_DEBUG,"Ignores default route from upstream");
////                log_it(L_DEBUG," %s/%s ",l_netaddr_buf, l_netmask_buf);
////                continue;
////            }
//
//            char *l_cmd = dap_strdup_printf("route add -net %s netmask %s dev %s metric 2",
//                    l_netaddr_buf, l_netmask_buf, m_tun_server->ifr.ifr_ifrn.ifrn_name);
//            exe_bash_cmd(l_cmd);
//        }
//
//    }
}

