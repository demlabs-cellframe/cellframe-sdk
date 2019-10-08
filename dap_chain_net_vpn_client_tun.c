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
#include "dap_stream_ch_pkt.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_vpn_client_tun.h"

#define LOG_TAG "vpn_client_tun"

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
static char* get_connection(const char *a_conn_name)
{
    if(!a_conn_name)
        return NULL;
    char *l_cmd = dap_strdup_printf("nmcli connection show | grep %s | awk '{print $1}'", a_conn_name);
    char* l_connection_name = run_bash_cmd(l_cmd);
    DAP_DELETE(l_cmd);
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

static int s_fd_tun; // tun0 file descriptor

static char s_dev[IFNAMSIZ];
static char *s_cur_gw = NULL;
static const char *s_conn_name = "nodeVPNClient";
static char *s_last_used_connection_name = NULL, *s_last_used_connection_device = NULL;

static pthread_t s_thread_read_tun_id;

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
                    // form packet to vpn-server
                    ch_vpn_pkt_t *pkt_out = (ch_vpn_pkt_t*) calloc(1, sizeof(pkt_out->header) + read_ret);
                    pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_SEND; //VPN_PACKET_OP_CODE_VPN_RECV
                    pkt_out->header.sock_id = s_fd_tun;
                    pkt_out->header.op_data.data_size = read_ret;
                    memcpy(pkt_out->data, tmp_buf, read_ret);
                    // sent packet to vpn-server
                    // TODO

                    /*                    dap_stream_ch_vpn_remote_single_t * raw_client = NULL;
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
                     } else {
                     log_it(L_DEBUG, "No remote client for income IP packet with addr %s", inet_ntoa(in_daddr));
                     }
                     pthread_mutex_unlock(&raw_server->clients_mutex);*/
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

/*        void DapTunWorkerAbstract::procDataFromTun(void * a_buf,size_t a_bufSize)
 {
 // struct ip *iph = (struct ip* ) tmpBuf;
 // qDebug() << "[DapChSockForw] saddr = " << ::inet_ntoa(iph->ip_src)<< " dadrr = " << inet_ntoa( iph->ip_dst) << " size = "<<tmpBufSize  ;
 DapSockForwPacket * pktOut =
 (DapSockForwPacket *)::calloc(1,sizeof(pktOut->header)+a_bufSize );
 pktOut->header.op_code = STREAM_SF_PACKET_OP_CODE_RAW_SEND;
 pktOut->header.socket_id = m_tunSocket;
 pktOut->header.op_data.data_size = a_bufSize;
 memcpy(pktOut->data, a_buf, pktOut->header.op_data.data_size);

 emit packetOut(pktOut);
 emit readPackets();
 }*/

int dap_chain_net_vpn_client_tun_init(const char *a_ipv4_str)
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
    if(!l_cmd_del_gw) {
        log_it(L_ERROR, "Can't delete dafault gateway %s)", s_cur_gw);
        DAP_DELETE(s_cur_gw);
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
    if(!is_local_address(a_ipv4_str)) {
        // This route don't need if address is local
        char *l_str_cmd = dap_strdup_printf("route add -host %s gw %s metric 10", a_ipv4_str, s_cur_gw);
        char *l_cmd_ret = run_bash_cmd(l_str_cmd);
        DAP_DELETE(l_str_cmd);
        DAP_DELETE(l_cmd_ret);
    }

    // check and delete present connection
    char *l_conn_present = get_connection(s_conn_name);
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
                s_conn_name, s_dev, a_ipv4_str, s_cur_gw);
        char *l_cmd_ret = run_bash_cmd(l_cmd_add_con);
        l_conn_present = get_connection(s_conn_name);
        if(dap_strcmp(l_conn_present, s_conn_name))
            l_ret = -1;
        DAP_DELETE(l_cmd_ret);
        DAP_DELETE(l_cmd_add_con);
        DAP_DELETE(l_conn_present);
    }
    if(l_ret < 0) {
        log_it(L_ERROR, "Can't create network configuration (connection=%s)", s_conn_name);
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

    pthread_create(&s_thread_read_tun_id, NULL, thread_read_tun, NULL);
    //m_tunDeviceName = dev;
    //m_tunSocket = fd;
    return l_ret;
}

int dap_chain_net_vpn_client_tun_delete(void)
{
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

    // ip route add default via 192.168.100.1
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
    char *l_str_cmd = get_connection(s_conn_name);
    if(!l_str_cmd)
        return 0;
    // connection must be present
    if(dap_strcmp(l_str_cmd, s_conn_name)) {
        DAP_DELETE(l_str_cmd);
        return 0;
    }
    DAP_DELETE(l_str_cmd);

    char *l_used_connection_name = NULL;
    char *l_used_connection_device = NULL;
    save_current_connection_interface_data(&l_used_connection_name, &l_used_connection_device);
    // connection must be upped
    if(dap_strcmp(l_used_connection_name, s_conn_name) || dap_strcmp(l_used_connection_device, s_dev)) {
        DAP_DELETE(l_used_connection_name);
        DAP_DELETE(l_used_connection_device);
        return -1;
    }
    DAP_DELETE(l_used_connection_name);
    DAP_DELETE(l_used_connection_device);

    // VPN client started
    return 0;
}







dap_stream_ch_pkt_t* ch_sf_tun_read();
void ch_sf_tun_destroy();

/**
 * @brief ch_sf_thread_tun
 * @param arg
 * @return
 */
void* ch_sf_thread_tun(void *arg)
{
    ch_sf_tun_create();

    if(m_tun_server->tun_fd <= 0) {
        log_it(L_CRITICAL, "Tun/tap file descriptor is not initialized");
        pthread_cond_signal(&m_tun_server->tun_started_cond);
        return NULL;
    }

    m_tun_server->tun_tx = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    struct sockaddr_ll my_addr = { 0 };
    struct ifreq s_ifr;

    strncpy(s_ifr.ifr_name, m_tun_server->ifr.ifr_name, sizeof(s_ifr.ifr_name));

    /* get interface index of tun0 */
    ioctl(m_tun_server->tun_tx, SIOCGIFINDEX, &s_ifr);

    /* fill sockaddr_ll struct to prepare binding */
    my_addr.sll_family = AF_PACKET;
    my_addr.sll_protocol = htons(ETH_P_ALL);
    my_addr.sll_ifindex = s_ifr.ifr_ifindex;

//    tun_server->tun_tx = socket();

    uint8_t *tmp_buf;
    ssize_t tmp_buf_size;
    static int tun_MTU = 100000; /// TODO Replace with detection of MTU size

    tmp_buf = (uint8_t *) calloc(1, tun_MTU);
    tmp_buf_size = 0;
    log_it(L_INFO, "Tun/tap thread starts with MTU = %d", tun_MTU);

    fd_set fds_read, fds_read_active;

    FD_ZERO(&fds_read);
    FD_SET(m_tun_server->tun_fd, &fds_read);
    FD_SET(get_select_breaker(), &fds_read);
    /// Main cycle
    pthread_cond_signal(&m_tun_server->tun_started_cond);
    do {
        fds_read_active = fds_read;
        int ret = select(FD_SETSIZE, &fds_read_active, NULL, NULL, NULL);
        //
        if(ret > 0) {
            if(FD_ISSET(get_select_breaker(), &fds_read_active)) { // Smth to send
//                log_it(L_DEBUG,"--------------------------- something to sent");
                dap_stream_ch_pkt_t* pkt = ch_sf_tun_read();
                if(pkt) {
                    int write_ret = write(m_tun_server->tun_fd, pkt->data, pkt->header.op_data.data_size);
                    if(write_ret > 0) {
                        log_it(L_DEBUG, "Wrote out %d bytes to the tun/tap interface", write_ret);
                    } else {
                        log_it(L_ERROR,"Tun/tap write %u bytes returned '%s' error, code (%d)",pkt->header.op_data.data_size,strerror(errno),write_ret);
                    }
                }
            }
            if(FD_ISSET(m_tun_server->tun_fd, &fds_read_active)) {
                int read_ret = read(m_tun_server->tun_fd, tmp_buf, tun_MTU);
                if(read_ret < 0) {
                    log_it(L_CRITICAL,"Tun/tap read returned '%s' error, code (%d)",strerror(errno),read_ret);
                    break;
                } else {
                    bool passPacket = true;
                    //log_it(L_DEBUG,"read %d from tun_fd",read_ret);
                    //switch(ch_sf_snort_pkt(tmp_buf,read_ret)){
                    //     case SNORT_ALERT: passPacket=false; break;
                    //     default: passPacket=true;
                    //}
                    if(passPacket) {
                        struct iphdr *iph = (struct iphdr*) tmp_buf;
                        struct in_addr in_daddr, in_saddr;
                        in_daddr.s_addr = iph->daddr;
                        in_saddr.s_addr = iph->saddr;
                        char str_daddr[42], str_saddr[42];
                        strncpy(str_saddr, inet_ntoa(in_saddr), sizeof(str_saddr));
                        strncpy(str_daddr, inet_ntoa(in_daddr), sizeof(str_daddr));
                        /*if(iph->tot_len > (uint16_t) read_ret ){
                         log_it(INFO,"Tun/Tap interface returned only the fragment (tot_len =%u  read_ret=%d) ",
                         iph->tot_len,read_ret);
                         }*/
                        /*if(iph->tot_len < (uint16_t) read_ret ){
                         log_it(WARNING,"Tun/Tap interface returned more then one packet (tot_len =%u  read_ret=%d) ",
                         iph->tot_len,read_ret);
                         }*/

                        //log_it(L_DEBUG,"Read IP packet from tun/tap interface daddr=%s saddr=%s total_size = %d "
                        //    ,str_daddr,str_saddr,read_ret);
                        ch_sf_tun_client_t * raw_client = NULL;
                        pthread_mutex_lock(&m_tun_server->clients_mutex);
                        HASH_FIND_INT(m_tun_server->clients, &in_daddr.s_addr, raw_client);
                        //                  HASH_ADD_INT(CH_SF(ch)->socks, id, sf_sock );
                        //                  HASH_DEL(CH_SF(ch)->socks,sf_sock);
                        if(raw_client) { // Is present in hash table such destination address
                            dap_stream_ch_pkt_t *pkt_out = (dap_stream_ch_pkt_t*) calloc(1,
                                    sizeof(pkt_out->header) + read_ret);
                            if(pkt_out) {
                                pkt_out->header.op_code = STREAM_SF_PACKET_OP_CODE_L3_RECV;
                                pkt_out->header.sock_id = m_tun_server->tun_fd;
                                pkt_out->header.op_data.data_size = read_ret;
                                memcpy(pkt_out->data, tmp_buf, read_ret);
                                stream_ch_pkt_write(raw_client->ch, 'd', pkt_out,
                                        pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
                                stream_sf_socket_ready_to_write(raw_client->ch, true);
                            } else
                                log_it(L_CRITICAL, "Can't allocate memory for the new packet: %s", strerror(errno));
                        } else {
                            ch_sf_peer_info_t * l_peer = NULL;
                            size_t i;
                            for(i = 0; i < m_tun_server->peers_count; i++) {
                                if(!(m_tun_server->peers[i].in_use))
                                    continue;
                                /*
                                 struct in_addr in_daddr_net;
                                 in_daddr_net.s_addr = m_tun_server->peers[i].netmask & in_daddr.s_addr;

                                 log_it(L_DEBUG,"Check peer #%u of %u  @%p",i,m_tun_server->peers_count,&m_tun_server->peers[i]);
                                 log_it(L_DEBUG,"--- dst net:   %s",inet_ntoa(in_daddr_net));
                                 log_it(L_DEBUG,"--- peer net:  %s",inet_ntoa(inet_makeaddr(htonl(m_tun_server->peers[i].netaddr),0)));
                                 log_it(L_DEBUG,"--- peer mask: %s",inet_ntoa(inet_makeaddr(htonl(m_tun_server->peers[i].netmask),0)));
                                 */
                                if((m_tun_server->peers[i].netmask & in_daddr.s_addr)
                                        == (m_tun_server->peers[i].netmask & m_tun_server->peers[i].netaddr)) { // Address in peer
                                    l_peer = m_tun_server->peers + i;
//                                    log_it(L_DEBUG,"*** Mutch!!");
                                    break;
                                }
                            }
                            if(l_peer) { // Peer is found
                                ch_sf_pkt_send(l_peer->ch, tmp_buf, read_ret);
                            } else {
                                log_it(L_DEBUG, "No remote client for income IP packet with addr %s ",
                                        inet_ntoa(in_daddr));
                            }
                        }
                        pthread_mutex_unlock(&m_tun_server->clients_mutex);
                    }
                }
            }/*else {
             log_it(CRITICAL,"select() has no tun handler in the returned set");
             break;

             }*/
        } else {
            log_it(L_CRITICAL, "Select returned %d", ret);
            break;
        }
    } while(1);
    ch_sf_tun_destroy();
    log_it(L_NOTICE, "Raw sockets listen thread is stopped");
    return NULL;
}

/**
 * @brief ms2ts
 * @param ts
 * @param ms
 */
static void ms2ts(struct timespec *ts, unsigned long ms)
{
    ts->tv_sec = ms / 1000;
    ts->tv_nsec = (ms % 1000) * 1000000;
}
/**
 * @brief ch_sf_tun_init
 * @return
 */
int ch_sf_tun_init()
{
    struct timespec l_time_wait;
    clock_gettime(CLOCK_REALTIME, &l_time_wait);
    l_time_wait.tv_sec += 10;

    m_tun_server = SAP_NEW_Z(ch_sf_tun_server_t);
    m_tun_server->peers_max = CH_SF_PEER_MAX;
    m_tun_server->peers = SAP_NEW_Z_SIZE(ch_sf_peer_info_t, m_tun_server->peers_max);
    pthread_mutex_init(&m_tun_server->clients_mutex, NULL);
    pthread_mutex_init(&m_tun_server->pkt_out_mutex, NULL);
    pthread_mutex_init(&m_tun_server->tun_started_mutex, NULL);
    pthread_cond_init(&m_tun_server->tun_started_cond, NULL);

    pthread_mutex_lock(&m_tun_server->tun_started_mutex);
    log_it(L_DEBUG, "Initializing TUN driver...");
    pthread_create(&sf_socks_tun_pid, NULL, ch_sf_thread_tun, NULL);
    pthread_cond_timedwait(&m_tun_server->tun_started_cond, &m_tun_server->tun_started_mutex, &l_time_wait);
    pthread_mutex_unlock(&m_tun_server->tun_started_mutex);
    log_it(L_INFO, "TUN driver configured successfuly");

    return 0;
}

/**
 * @brief ch_sf_tun_deinit
 */
void ch_sf_tun_deinit()
{
    if(m_tun_server) {
        ch_sf_tun_destroy();
        SAP_DELETE(m_tun_server->peers);
        free(m_tun_server);
    }
}

void ch_sf_tun_destroy()
{
    if(m_tun_server->tun_fd) {
        close(m_tun_server->tun_fd);
        m_tun_server->tun_fd = -1;
    }

}

/**
 * @brief ch_sf_tun_create
 */
void ch_sf_tun_create()
{
    inet_aton(my_config.vpn_addr, &m_tun_server->int_network);
    inet_aton(my_config.vpn_mask, &m_tun_server->int_network_mask);
    m_tun_server->int_network_addr.s_addr = (m_tun_server->int_network.s_addr | 0x01000000); // grow up some shit here!
    m_tun_server->client_addr_last.s_addr = m_tun_server->int_network_addr.s_addr;

    if((m_tun_server->tun_ctl_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        log_it(L_ERROR, "Opening /dev/net/tun error: '%s'", strerror(errno));
    } else {
        int err;
        memset(&m_tun_server->ifr, 0, sizeof(m_tun_server->ifr));
        m_tun_server->ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if((err = ioctl(m_tun_server->tun_ctl_fd, TUNSETIFF, (void *) &m_tun_server->ifr)) < 0) {
            log_it(L_CRITICAL, "ioctl(TUNSETIFF) error: '%s' ", strerror(errno));
            close(m_tun_server->tun_ctl_fd);
            m_tun_server->tun_ctl_fd = -1;
        } else {
            char buf[256];
            log_it(L_NOTICE, "Bringed up %s virtual network interface (%s/%s)", m_tun_server->ifr.ifr_name,
                    inet_ntoa(m_tun_server->int_network_addr), my_config.vpn_mask);
            m_tun_server->tun_fd = m_tun_server->tun_ctl_fd; // Looks yes, its so
//        snprintf(buf,sizeof(buf),"ip_sapnet link set %s up",m_tun_server->ifr.ifr_name);
            snprintf(buf, sizeof(buf), "ip link set %s up", m_tun_server->ifr.ifr_name);
            system(buf);
//        snprintf(buf,sizeof(buf),"ip_sapnet addr add %s/%s dev %s ",inet_ntoa(m_tun_server->int_network_addr),my_config.vpn_mask, m_tun_server->ifr.ifr_name );
            snprintf(buf, sizeof(buf), "ip addr add %s/%s dev %s ", inet_ntoa(m_tun_server->int_network_addr),
                    my_config.vpn_mask, m_tun_server->ifr.ifr_name);
            system(buf);
        }
    }

}

void ch_sf_tun_delete(ch_sf_t * ch_sf)
{
    ch_sf_tun_client_t * tun_client = 0;

    in_addr_t tun_client_addr = ch_sf->ch->stream->session
                                ? ch_sf->ch->stream->session->tun_client_addr.s_addr
                                  :
                                  0;
    char* l_tun_cliend_addr_str = strdup(inet_ntoa(ch_sf->ch->stream->session->tun_client_addr));
    char* l_tun_cliend_mask_str = strdup(inet_ntoa(ch_sf->ch->stream->session->tun_client_mask));

    bool need_remove_addr = false;

    struct in_addr l_tun_cliend_mask = ch_sf->ch->stream->session->tun_client_mask;

//    log_it(L_DEBUG,"b_1773 %x %x %x ",tun_client_addr,ch_sf->ch->stream->session,ch_sf->ch->stream->session->tun_client_addr.s_addr);
//    log_it(L_DEBUG, "b_1773 btw: %p %x %x",m_tun_server->peers,ch_sf->peer_id,sizeof(ch_sf_peer_info_t));
    if(tun_client_addr) {
        log_it(L_DEBUG, "ch_sf_tun_delete() %s searching in hash table", l_tun_cliend_addr_str);
        if((uint32_t) (m_tun_server->int_network.s_addr & m_tun_server->int_network_mask.s_addr)
                == (uint32_t) (tun_client_addr & m_tun_server->int_network_mask.s_addr)) {
            list_addr_element *el = (list_addr_element*) malloc(sizeof(list_addr_element));
            el->addr.s_addr = tun_client_addr;
            LL_APPEND(list_addr_head, el);
        } else
            need_remove_addr = true;
        pthread_mutex_lock(&m_tun_server->clients_mutex);
        size_t i;
        if(ch_sf->is_peer && m_tun_server->peers_count) {
            if(ch_sf->peer_id < m_tun_server->peers_count) {
                log_it(L_DEBUG, "Reorganize peer table");
//                log_it(L_DEBUG, "b_1773 memzero: %p %x",m_tun_server->peers+ch_sf->peer_id,sizeof(ch_sf_peer_info_t));
                memzero(m_tun_server->peers + ch_sf->peer_id, sizeof(ch_sf_peer_info_t));
                (m_tun_server->peers + ch_sf->peer_id)->netmask = 0xffffffff;
            }
        }
        HASH_FIND_INT(m_tun_server->clients, &tun_client_addr, tun_client);
        if(tun_client) {
            HASH_DEL(m_tun_server->clients, tun_client);
            log_it(L_DEBUG, "ch_sf_tun_delete() %s removed from hash table", l_tun_cliend_addr_str);
            free(tun_client);
        } else
            log_it(L_DEBUG, "ch_sf_tun_delete() %s is not present in raw sockets hash table", l_tun_cliend_addr_str);
        pthread_mutex_unlock(&m_tun_server->clients_mutex);

        if(need_remove_addr) {
            if(exec_with_ret_f(NULL, "ip addr del %s/%s dev %s", l_tun_cliend_addr_str, l_tun_cliend_mask_str,
                    m_tun_server->ifr.ifr_name))
                log_it(L_ERROR, "can't execute 'addr del %s/%s dev %s'", l_tun_cliend_addr_str, l_tun_cliend_mask_str,
                        m_tun_server->ifr.ifr_name);

        }
    }
    free(l_tun_cliend_addr_str);
    free(l_tun_cliend_mask_str);
}

/**
 * @brief ch_sf_tun_read
 * @return
 */
dap_stream_ch_pkt_t* ch_sf_tun_read()
{
//    log_it(L_DEBUG,"ch_sf_tun_read()");
    dap_stream_ch_pkt_t*ret = NULL;
    pthread_mutex_lock(&m_tun_server->pkt_out_mutex);
    if(m_tun_server->pkt_out_rindex == (sizeof(m_tun_server->pkt_out) / sizeof(m_tun_server->pkt_out[0]))) {
        m_tun_server->pkt_out_rindex = 0; // ring the buffer!
    }
    if((m_tun_server->pkt_out_rindex != m_tun_server->pkt_out_windex) || (m_tun_server->pkt_out_size == 0)) {
        ret = m_tun_server->pkt_out[m_tun_server->pkt_out_rindex];
        m_tun_server->pkt_out_rindex++;
        m_tun_server->pkt_out_size--;
    } //else  log_it(L_WARNING,"Packet drop on raw_read() operation, ring buffer is full");
    pthread_mutex_unlock(&m_tun_server->pkt_out_mutex);
    return ret;
}

/**
 * @brief ch_sf_raw_write
 * @param op_code
 * @param data
 * @param data_size
 * @return
 */
int ch_sf_tun_write(uint8_t op_code, const void * data, size_t data_size)
{
//    log_it(L_DEBUG,"ch_sf_tun_write()");
    pthread_mutex_lock(&m_tun_server->pkt_out_mutex);
    if(m_tun_server->pkt_out_windex == (sizeof(m_tun_server->pkt_out) / sizeof(m_tun_server->pkt_out[0])))
        m_tun_server->pkt_out_windex = 0; // ring the buffer!
    if((m_tun_server->pkt_out_windex < m_tun_server->pkt_out_rindex) || (m_tun_server->pkt_out_size == 0)) {
        dap_stream_ch_pkt_t * pkt = (dap_stream_ch_pkt_t *) calloc(1, data_size + sizeof(pkt->header));
        pkt->header.op_code = op_code;
        pkt->header.sock_id = m_tun_server->tun_fd;
        if(data_size > 0) {
            pkt->header.op_data.data_size = data_size;
            memcpy(pkt->data, data, data_size);
        }

        m_tun_server->pkt_out[m_tun_server->pkt_out_windex] = pkt;
        m_tun_server->pkt_out_windex++;
        m_tun_server->pkt_out_size++;
        pthread_mutex_unlock(&m_tun_server->pkt_out_mutex);
        send_select_break();
        return m_tun_server->pkt_out_windex;
    } else {
        pthread_mutex_unlock(&m_tun_server->pkt_out_mutex);
        log_it(L_WARNING, "Raw socket buffer overflow");
        return -1;
    }
}

void ch_sf_tun_send(ch_sf_t * ch_sf, void * pkt_data, size_t pkt_data_size) {
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
        in_daddr_net.s_addr = in_daddr.s_addr & m_tun_server->int_network_mask.s_addr;
        char * in_daddr_str = strdup(inet_ntoa(in_daddr));
        char * in_saddr_str = strdup(inet_ntoa(in_saddr));

        sap_stream_ch_t * l_route_ch = ch_sf_peer_ch_find(ch_sf->ch->stream->session, pkt_data, pkt_data_size);

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
                dap_stream_ch_pkt_t *pkt_out = (dap_stream_ch_pkt_t*) calloc(1, sizeof(pkt_out->header));
                pkt_out->header.op_code = STREAM_SF_PACKET_OP_CODE_PROBLEM;
                pkt_out->header.op_problem.code = STREAM_SF_PROBLEM_CODE_PACKET_LOST;
                pkt_out->header.sock_id = m_tun_server->tun_fd;
                stream_ch_pkt_write(ch_sf->ch, 'd', pkt_out,
                        pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
                stream_sf_socket_ready_to_write(ch_sf->ch, true);
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
void ch_sf_tun_addr_leased(ch_sf_t * a_sf, dap_stream_ch_pkt_t * a_pkt, size_t a_pkt_data_size)
{
// ------------------------------------------- we'd receive address assigment from server
    log_it(L_WARNING, "feature-2498  ======== We'd receive address assigment");
    a_sf->is_peer = false; // paranoja ?
    struct in_addr l_addr = { 0 };
    struct in_addr l_netmask = { 0 };
    struct in_addr l_netaddr = { 0 };
    struct in_addr l_gw = { 0 };

    size_t l_route_net_count = 0;

    if(a_pkt_data_size < (sizeof(l_addr) + sizeof(l_gw))) {
        log_it(L_ERROR, "Too small ADDR_REPLY packet (%u bytes, need at least %u"
                , a_pkt_data_size, sizeof(l_addr));
        return;
    }

    l_route_net_count = (a_pkt_data_size - 3 * sizeof(struct in_addr)) / (2 * sizeof(struct in_addr));

    pthread_mutex_lock(&m_tun_server->clients_mutex);
    ch_sf_tun_client_t * n_client = SAP_NEW_Z(ch_sf_tun_client_t);
    n_client->ch = a_sf->ch;

    memcpy(&l_addr, a_pkt->data, sizeof(l_addr));
    memcpy(&l_gw, a_pkt->data + sizeof(l_addr), sizeof(l_gw));
    memcpy(&l_netmask, a_pkt->data + sizeof(l_addr) + sizeof(l_gw), sizeof(l_netmask));
    l_netaddr.s_addr = l_addr.s_addr & l_netmask.s_addr;
    n_client->addr = l_addr.s_addr;
    if(a_sf->ch->stream->session) {
        a_sf->ch->stream->session->tun_client_addr.s_addr = l_addr.s_addr;
        a_sf->ch->stream->session->tun_client_gw.s_addr = l_gw.s_addr;
        a_sf->ch->stream->session->tun_client_mask.s_addr = l_netmask.s_addr;
    }
    HASH_ADD_INT(m_tun_server->clients, addr, n_client);
    char l_addr_buf[INET_ADDRSTRLEN];
    char l_netmask_buf[INET_ADDRSTRLEN];
    char l_netaddr_buf[INET_ADDRSTRLEN];
    char l_gw_buf[INET_ADDRSTRLEN];
    char* err;
    pthread_mutex_unlock(&m_tun_server->clients_mutex);
    inet_ntop(AF_INET, &l_addr, l_addr_buf, sizeof(l_addr_buf));
    inet_ntop(AF_INET, &l_gw, l_gw_buf, sizeof(l_gw_buf));
    inet_ntop(AF_INET, &l_netmask, l_netmask_buf, sizeof(l_netmask_buf));
    inet_ntop(AF_INET, &l_netaddr, l_netaddr_buf, sizeof(l_netaddr_buf));
    log_it(L_NOTICE, "Registred tunnel %s=>%s  to %s/%s via remote socket %d", l_addr_buf, l_gw_buf, l_netaddr_buf,
            l_netmask_buf,
            a_sf->ch->stream->events_socket->socket);
    if(a_sf->ch->stream->is_client_to_uplink) {
        log_it(L_NOTICE, "Assign address %s to the network device %s", l_addr_buf, m_tun_server->ifr.ifr_name);
        if(exec_with_ret_f(&err, "ip address add %s/%s dev %s", l_addr_buf, l_netmask_buf, m_tun_server->ifr.ifr_name))
                {
            log_it(L_ERROR,
                    "Can't assign ip address, leased from remote server. Routing to the remote network will not work");
            log_it(L_ERROR, "exec returns: '%s'", err);
        }
        ch_sf_tun_peer_add(a_sf, l_addr.s_addr, l_gw.s_addr, l_netmask.s_addr & l_gw.s_addr, l_netmask.s_addr);

        size_t i;
        log_it(L_DEBUG, "Found %u networks in reply", l_route_net_count);
        for(i = 0; i < l_route_net_count; i++) {
            in_addr_t l_r_netaddr;
            in_addr_t l_r_netmask;

            memcpy(&l_r_netaddr, a_pkt->data + (3 + i * 2) * sizeof(in_addr_t), sizeof(in_addr_t));
            memcpy(&l_r_netmask, a_pkt->data + (4 + i * 2) * sizeof(in_addr_t), sizeof(in_addr_t));

            if(!l_r_netaddr && !l_r_netmask) {
                log_it(L_DEBUG, "Ignores default route from upstream");
                continue;
            }

//            ch_sf_tun_peer_add(a_sf, 0,0,l_r_netaddr,l_r_netmask);
            ch_sf_tun_peer_add(a_sf, l_r_netaddr, l_r_netmask, l_r_netaddr, l_r_netmask);
            inet_ntop(AF_INET, &l_r_netmask, l_netmask_buf, sizeof(l_netmask_buf));
            inet_ntop(AF_INET, &l_r_netaddr, l_netaddr_buf, sizeof(l_netaddr_buf));

//            if(!l_r_netaddr && !l_r_netmask){
//                log_it(L_DEBUG,"Ignores default route from upstream");
//                log_it(L_DEBUG," %s/%s ",l_netaddr_buf, l_netmask_buf);
//                continue;
//            }

            exec_with_ret_f(NULL, "route add -net %s netmask %s dev %s metric 2",
                    l_netaddr_buf, l_netmask_buf, m_tun_server->ifr.ifr_ifrn.ifrn_name);
        }

    }
}

/**
 * @brief ch_sf_tun_addr_request
 * @param a_ch_sf
 * @param a_pkt_requet
 * @param a_pkt_data_size
 */
void ch_sf_tun_addr_request(ch_sf_t * a_ch_sf, dap_stream_ch_pkt_t * a_pkt_request, size_t a_pkt_data_size)
{
// ------------------------------------------- we'd receive address request with client routing info
    log_it(L_WARNING, "feature-2498  ======== We'd receive address request and try to serve it");
//    a_ch_sf->is_peer=false;           // paranoja ?
    struct in_addr n_addr = { 0 };
//    if(n_addr.s_addr==0 ){ // If the addres still in the network
    pthread_mutex_lock(&m_tun_server->clients_mutex);

    int count_free_addr = -1;
    list_addr_element *el;
    LL_COUNT(list_addr_head, el, count_free_addr);

    ch_sf_tun_client_t * n_client = (ch_sf_tun_client_t*) calloc(1, sizeof(ch_sf_tun_client_t));
    n_client->ch = a_ch_sf->ch;

    if(count_free_addr > 0) {
//            log_it(L_WARNING,"############################################################################ >0");
        n_addr.s_addr = list_addr_head->addr.s_addr;
        LL_DELETE(list_addr_head, list_addr_head);
    } else {
//            log_it(L_WARNING,"############################################################################ <=0");
        n_addr.s_addr = ntohl(m_tun_server->client_addr_last.s_addr);
        n_addr.s_addr++;

//            log_it(L_DEBUG,"net address: %x",ntohl(m_tun_server->int_network.s_addr));
//            log_it(L_DEBUG,"net mask: %x",ntohl(m_tun_server->int_network_mask.s_addr));
//            log_it(L_DEBUG,"net top: %x",ntohl(m_tun_server->int_network.s_addr)|~ntohl(m_tun_server->int_network_mask.s_addr));
//            log_it(L_DEBUG,"suggested addr: %x",n_addr.s_addr);

        if((uint32_t) n_addr.s_addr
                >= (uint32_t) (ntohl(m_tun_server->int_network.s_addr) | ~(ntohl(m_tun_server->int_network_mask.s_addr)))) { // no free addresses, abort request
            log_it(L_WARNING, "All the network is filled with clients, can't lease a new address");
            dap_stream_ch_pkt_t *pkt_out = (dap_stream_ch_pkt_t*) calloc(1, sizeof(pkt_out->header));
            pkt_out->header.sock_id = m_tun_server->tun_fd;
            pkt_out->header.op_code = STREAM_SF_PACKET_OP_CODE_PROBLEM;
            pkt_out->header.op_problem.code = STREAM_SF_PROBLEM_CODE_NO_FREE_ADDR;
            stream_ch_pkt_write(a_ch_sf->ch, 'd', pkt_out, pkt_out->header.op_data.data_size + sizeof(pkt_out->header));
            stream_sf_socket_ready_to_write(a_ch_sf->ch, true);
            return;
        }

        n_addr.s_addr = ntohl(n_addr.s_addr);
        m_tun_server->client_addr_last.s_addr = n_addr.s_addr;

    }

    n_client->addr = n_addr.s_addr;
//        m_tun_server->client_addr_last.s_addr = n_addr.s_addr;
    if(a_ch_sf->ch->stream->session)
        a_ch_sf->ch->stream->session->tun_client_addr.s_addr = n_addr.s_addr;

    HASH_ADD_INT(m_tun_server->clients, addr, n_client);
    log_it(L_NOTICE, "VPN client address %s leased", inet_ntoa(n_addr));
    log_it(L_INFO, "           gateway %s", inet_ntoa(m_tun_server->int_network_addr));
    log_it(L_INFO, "           mask %s", inet_ntoa(m_tun_server->int_network_mask));
    log_it(L_INFO, "           addr %s", inet_ntoa(m_tun_server->int_network));
    log_it(L_INFO, "           last_addr %s", inet_ntoa(m_tun_server->client_addr_last));

    dap_stream_ch_pkt_t *l_pkt_out;
    size_t l_pkt_out_size = sizeof(l_pkt_out->header) + sizeof(n_addr)
            + sizeof(m_tun_server->int_network_addr)
            + sizeof(m_tun_server->int_network_mask)
            + 2 * sizeof(in_addr_t) * (m_tun_server->peers_count);

    l_pkt_out = SAP_NEW_Z_SIZE(dap_stream_ch_pkt_t, l_pkt_out_size);
    l_pkt_out->header.sock_id = m_tun_server->tun_fd;
    l_pkt_out->header.op_code = STREAM_SF_PACKET_OP_CODE_L3_ADDR_REPLY;
    l_pkt_out->header.op_data.data_size = l_pkt_out_size - sizeof(l_pkt_out->header);

    size_t l_offset = 0, i;
    memcpy(l_pkt_out->data + l_offset, &n_addr, sizeof(n_addr));
    l_offset += sizeof(n_addr);
    memcpy(l_pkt_out->data + l_offset, &m_tun_server->int_network_addr, sizeof(m_tun_server->int_network_addr));
    l_offset += sizeof(m_tun_server->int_network_addr);
    memcpy(l_pkt_out->data + l_offset, &m_tun_server->int_network_mask, sizeof(m_tun_server->int_network_mask));
    l_offset += sizeof(m_tun_server->int_network_mask);
    log_it(L_DEBUG, "Additional %u networks in response", m_tun_server->peers_count);

    db_auth_info_t *ai = db_auth_info_by_cookie(a_ch_sf->ch->stream->conn_http->in_cookie);
    //    log_it(L_WARNING, "IN TUN SF Login: %s", ai->user);
    sap_stream_session_t * ss = a_ch_sf->ch->stream->session;
    for(i = 0; i < m_tun_server->peers_count; i++) {
        if(!(m_tun_server->peers[i].in_use))
            continue;
        if(m_tun_server->peers[i].ch) {
            char *host = m_tun_server->peers[i].ch->stream->events_socket->hostaddr;
            log_it(L_DEBUG, "Add netaddr to reply: %s ", host);
            log_it(L_DEBUG, "*** is_client_to_uplink *** %d", m_tun_server->peers[i].ch->stream->is_client_to_uplink);
            log_it(L_DEBUG, "*** I am peer: %d ***", a_ch_sf->is_peer);
//                if(ai)log_it(L_DEBUG, "*** ai *** %d",a_ch_sf->is_peer);
//                else log_it(L_DEBUG, "*** ai *** NULL");
//                if (my_config.scan_peers_conf || mod_sf_peer_list_is_have_access(host, ai->user, ai->groups)) {
            char net_addr[INET_ADDRSTRLEN] = { 0 };
            char mask[INET_ADDRSTRLEN] = { 0 };
            inet_ntop(AF_INET, &m_tun_server->peers[i].netaddr, net_addr, sizeof(net_addr));
            inet_ntop(AF_INET, &m_tun_server->peers[i].netmask, mask, sizeof(mask));

            log_it(L_DEBUG, "User %s have access to peer (host) %s\n"
                    "addr: %s mask: %s", ai->user, host, net_addr, mask);

            sap_stream_session_add_peer(ss, &m_tun_server->peers[i]);

            memcpy(l_pkt_out->data + l_offset, &m_tun_server->peers[i].netaddr, sizeof(m_tun_server->peers[i].netaddr));
            l_offset += sizeof(m_tun_server->peers[i].netaddr);
            memcpy(l_pkt_out->data + l_offset, &m_tun_server->peers[i].netmask, sizeof(m_tun_server->peers[i].netmask));
            l_offset += sizeof(m_tun_server->peers[i].netmask);
//                }
        } else
            log_it(L_WARNING, "Strange -- channel is NULL");
    }
    pthread_mutex_unlock(&m_tun_server->clients_mutex);
    log_it(L_DEBUG, "hotfix-2151: btw  'data '%p'' offset: '%x'' size: '%x'", l_pkt_out->data, l_offset,
            l_pkt_out_size);

    // Add peer to the downlink networks (if present)
    if(a_pkt_data_size > 0) {
//        log_it(L_DEBUG, "hotfix-2151: disable  'Add peer to the downlink networks'");
//        if( false){
        size_t l_downlinks_nets = a_pkt_data_size / (2 * sizeof(struct in_addr));
        size_t i;
        in_addr_t l_netaddr, l_netmask;
        char l_netaddr_buf[INET_ADDRSTRLEN], l_netmask_buf[INET_ADDRSTRLEN];
        log_it(L_DEBUG, "Additional %u networks in address request", l_downlinks_nets);
        for(i = 0; i < l_downlinks_nets; i++) {
            memcpy(&l_netaddr, a_pkt_request->data + i * 2 * sizeof(in_addr_t), sizeof(in_addr_t));
            memcpy(&l_netmask, a_pkt_request->data + (1 + i * 2) * sizeof(in_addr_t), sizeof(in_addr_t));
            if(!l_netaddr && !l_netmask) {
                log_it(L_DEBUG, "Ignores default route from downstream");
                continue;
            }
            inet_ntop(AF_INET, &l_netmask, l_netmask_buf, sizeof(l_netmask_buf));
            inet_ntop(AF_INET, &l_netaddr, l_netaddr_buf, sizeof(l_netaddr_buf));
            log_it(L_NOTICE, "Add in peer table the network %s/%s", l_netaddr_buf, l_netmask_buf);

            int ret = exec_with_ret_f(NULL, "route add -net %s netmask %s dev %s metric 5",
                    l_netaddr_buf, l_netmask_buf, m_tun_server->ifr.ifr_ifrn.ifrn_name);
            switch (ret) {
            case 0:
                case 7:
                case 0x700: // strange, but sometimes we obtain 7 in high byte.
//                    ch_sf_tun_peer_add(a_ch_sf,0,0,l_netaddr,l_netmask);
                ch_sf_tun_peer_add(a_ch_sf, l_netaddr, l_netmask, l_netaddr, l_netmask);
                break;
            default:
                log_it(L_WARNING, "Bad route for %s/%s ignored, cause %d", l_netaddr_buf, l_netmask_buf, ret);
            }

        }
    } else
        log_it(L_DEBUG, "Additional 0 networks in address request");

//        pthread_mutex_unlock(& m_tun_server->clients_mutex );

    stream_ch_pkt_write(a_ch_sf->ch, 'd', l_pkt_out, l_pkt_out_size);
    stream_sf_socket_ready_to_write(a_ch_sf->ch, true);

    //ch_sf_raw_write(n_addr.s_addr,STREAM_SF_PACKET_OP_CODE_RAW_L3_ADDR_REPLY,&n_addr,sizeof(n_addr));
//    }else{ // All the network is filled with clients, can't lease a new address
//    }
}
