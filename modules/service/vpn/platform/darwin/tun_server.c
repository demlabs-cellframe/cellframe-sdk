/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * This file is part of DAP (Distributed Applications Platform) the open source project
 *
 *    DAP is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    DAP is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DAP_OS_IOS

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_worker.h"
#include "dap_events_socket.h"
#include "dap_chain_net_srv_vpn.h"
#include "../tun_server.h"

#define LOG_TAG "tun_server_darwin"

// Global state
static struct {
    int tun_ctl_fd;
    char device_name[IFNAMSIZ];
    dap_chain_net_srv_vpn_tun_socket_t **tun_sockets;
    dap_events_socket_t **queue_msg_sockets;
    uint32_t socket_count;
    bool initialized;
} s_tun_state = {0};

/**
 * @brief Create UTUN device on macOS
 * @param a_out_fd Output: file descriptor
 * @param a_out_name Output: device name
 * @return 0 on success, negative on error
 */
static int s_create_utun_device(int *a_out_fd, char *a_out_name)
{
    struct ctl_info l_ctl_info = {0};

    // Copy utun control name
    if (strlcpy(l_ctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(l_ctl_info.ctl_name))
            >= sizeof(l_ctl_info.ctl_name)) {
        log_it(L_ERROR, "UTUN_CONTROL_NAME \"%s\" too long", UTUN_CONTROL_NAME);
        return -1;
    }

    // Create utun socket
    int l_tun_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (l_tun_fd < 0) {
        log_it(L_ERROR, "Failed to open SYSPROTO_CONTROL: %s", dap_strerror(errno));
        return -2;
    }
    log_it(L_INFO, "UTUN SYSPROTO_CONTROL descriptor obtained");

    // Pass control structure to the utun socket
    if (ioctl(l_tun_fd, CTLIOCGINFO, &l_ctl_info) < 0) {
        log_it(L_ERROR, "ioctl(CTLIOCGINFO) failed: %s", dap_strerror(errno));
        close(l_tun_fd);
        return -3;
    }
    log_it(L_INFO, "UTUN CTLIOCGINFO structure passed");

    // Try to connect with one of utunX devices
    int l_ret = -1;
    for (int l_unit = 0; l_unit < 256; l_unit++) {
        struct sockaddr_ctl l_sa_ctl = {0};
        l_sa_ctl.sc_id = l_ctl_info.ctl_id;
        l_sa_ctl.sc_len = sizeof(l_sa_ctl);
        l_sa_ctl.sc_family = AF_SYSTEM;
        l_sa_ctl.ss_sysaddr = AF_SYS_CONTROL;
        l_sa_ctl.sc_unit = l_unit + 1;

        // If connect successful, new utunX device should be created
        l_ret = connect(l_tun_fd, (struct sockaddr *)&l_sa_ctl, sizeof(l_sa_ctl));
        if (l_ret == 0)
            break;
    }

    if (l_ret < 0) {
        log_it(L_ERROR, "Failed to create utun device: %s", dap_strerror(errno));
        close(l_tun_fd);
        return -4;
    }

    log_it(L_NOTICE, "UTUN device created");

    // Get interface name of newly created utun device
    char l_utunname[20];
    socklen_t l_utunname_len = sizeof(l_utunname);
    if (getsockopt(l_tun_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, l_utunname, &l_utunname_len)) {
        log_it(L_ERROR, "Failed to get utun device name: %s", dap_strerror(errno));
        close(l_tun_fd);
        return -5;
    }

    strncpy(a_out_name, l_utunname, IFNAMSIZ - 1);
    *a_out_fd = l_tun_fd;

    log_it(L_NOTICE, "UTUN device name: %s", a_out_name);
    return 0;
}

/**
 * @brief Configure UTUN device network parameters
 * @param a_device_name Device name
 * @param a_config TUN configuration
 * @return 0 on success, negative on error
 */
static int s_configure_utun_network(const char *a_device_name, const dap_tun_server_config_t *a_config)
{
    char l_buf[256];
    char l_str_gw[INET_ADDRSTRLEN];
    char l_str_mask[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &a_config->gateway_addr, l_str_gw, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &a_config->network_mask, l_str_mask, INET_ADDRSTRLEN);

    // Configure interface
    snprintf(l_buf, sizeof(l_buf), "ifconfig %s %s %s up",
             a_device_name, l_str_gw, l_str_gw);
    if (system(l_buf) != 0) {
        log_it(L_ERROR, "Failed to configure interface");
        return -1;
    }

    // Add route
    snprintf(l_buf, sizeof(l_buf), "route add -net %s -netmask %s -interface %s",
             l_str_gw, l_str_mask, a_device_name);
    if (system(l_buf) != 0) {
        log_it(L_ERROR, "Failed to add route");
        return -2;
    }

    log_it(L_NOTICE, "Configured %s with %s/%s", a_device_name, l_str_gw, l_str_mask);
    return 0;
}

/**
 * @brief Initialize TUN device (single device for macOS)
 * @param a_config Configuration
 * @return 0 on success, negative on error
 */
int dap_tun_server_init(dap_config_t *a_config)
{
    if (s_tun_state.initialized) {
        log_it(L_WARNING, "TUN server already initialized");
        return 0;
    }

    // Read configuration
    const char *l_addr_str = dap_config_get_item_str(a_config, "srv_vpn", "network_address");
    const char *l_mask_str = dap_config_get_item_str(a_config, "srv_vpn", "network_mask");
    if (!l_addr_str || !l_mask_str) {
        log_it(L_CRITICAL, "Missing network_address or network_mask in config");
        return -1;
    }

    // Parse configuration
    dap_tun_server_config_t l_config = {0};
    inet_pton(AF_INET, l_addr_str, &l_config.network_addr);
    inet_pton(AF_INET, l_mask_str, &l_config.network_mask);
    l_config.gateway_addr.s_addr = (l_config.network_addr.s_addr | 0x01000000);
    l_config.auto_cpu_reassignment = dap_config_get_item_bool_default(a_config, "srv_vpn", "auto_cpu_reassignment", false);

    // macOS uses single TUN device (no multi-queue support)
    s_tun_state.socket_count = 1;
    log_it(L_INFO, "Initializing UTUN device (single socket for macOS)");

    // Create UTUN device
    int l_tun_fd;
    if (s_create_utun_device(&l_tun_fd, s_tun_state.device_name) < 0) {
        log_it(L_ERROR, "Failed to create UTUN device");
        return -2;
    }

    s_tun_state.tun_ctl_fd = l_tun_fd;

    // Configure network
    if (s_configure_utun_network(s_tun_state.device_name, &l_config) < 0) {
        log_it(L_ERROR, "Failed to configure UTUN network");
        close(l_tun_fd);
        return -3;
    }

    // Allocate arrays (single element for macOS)
    s_tun_state.tun_sockets = DAP_NEW_Z_SIZE(dap_chain_net_srv_vpn_tun_socket_t*,
                                               sizeof(dap_chain_net_srv_vpn_tun_socket_t*));
    s_tun_state.queue_msg_sockets = DAP_NEW_Z_SIZE(dap_events_socket_t*,
                                                     sizeof(dap_events_socket_t*));
    if (!s_tun_state.tun_sockets || !s_tun_state.queue_msg_sockets) {
        log_it(L_CRITICAL, "Memory allocation failed");
        close(l_tun_fd);
        DAP_DEL_Z(s_tun_state.tun_sockets);
        DAP_DEL_Z(s_tun_state.queue_msg_sockets);
        return -4;
    }

    s_tun_state.initialized = true;
    log_it(L_NOTICE, "TUN server initialized: %s", s_tun_state.device_name);
    return 0;
}

/**
 * @brief Deinitialize TUN device
 */
void dap_tun_server_deinit(void)
{
    if (!s_tun_state.initialized) {
        return;
    }

    if (s_tun_state.tun_ctl_fd >= 0) {
        close(s_tun_state.tun_ctl_fd);
    }

    DAP_DEL_Z(s_tun_state.tun_sockets);
    DAP_DEL_Z(s_tun_state.queue_msg_sockets);
    memset(&s_tun_state, 0, sizeof(s_tun_state));
}

/**
 * @brief Get TUN device name
 * @return Device name or NULL
 */
const char* dap_tun_server_get_device_name(void)
{
    return s_tun_state.initialized ? s_tun_state.device_name : NULL;
}

/**
 * @brief Get TUN device file descriptor
 * @param a_worker_id Worker ID (ignored on macOS, always returns main FD)
 * @return File descriptor or -1 on error
 */
int dap_tun_server_get_fd(uint32_t a_worker_id)
{
    (void)a_worker_id;  // Unused on macOS
    return s_tun_state.initialized ? s_tun_state.tun_ctl_fd : -1;
}

/**
 * @brief Get number of TUN sockets (always 1 for macOS)
 * @return Number of sockets
 */
uint32_t dap_tun_server_get_socket_count(void)
{
    return s_tun_state.socket_count;
}

/**
 * @brief Get TUN socket for specific worker
 * @param a_worker_id Worker ID
 * @return TUN socket or NULL
 */
struct dap_chain_net_srv_vpn_tun_socket* dap_tun_server_get_socket(uint32_t a_worker_id)
{
    if (a_worker_id >= s_tun_state.socket_count) {
        return NULL;
    }
    return s_tun_state.tun_sockets[a_worker_id];
}

/**
 * @brief Get message queue socket for specific worker
 * @param a_worker_id Worker ID
 * @return Queue socket or NULL
 */
dap_events_socket_t* dap_tun_server_get_queue_socket(uint32_t a_worker_id)
{
    if (a_worker_id >= s_tun_state.socket_count) {
        return NULL;
    }
    return s_tun_state.queue_msg_sockets[a_worker_id];
}

#endif // !DAP_OS_IOS

