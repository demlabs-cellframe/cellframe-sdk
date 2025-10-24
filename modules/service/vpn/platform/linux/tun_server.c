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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_worker.h"
#include "dap_events_socket.h"
#include "dap_chain_net_srv_vpn.h"
#include "../tun_server.h"

#define LOG_TAG "tun_server_linux"

// Global state
static struct {
    struct ifreq ifr;
    char device_name[IFNAMSIZ];
    dap_chain_net_srv_vpn_tun_socket_t **tun_sockets;
    dap_events_socket_t **queue_msg_sockets;
    uint32_t socket_count;
    bool initialized;
} s_tun_state = {0};

/**
 * @brief Attach TUN queue for multi-queue support
 * @param a_fd TUN file descriptor
 * @return 0 on success, negative on error
 */
static int s_tun_attach_queue(int a_fd)
{
    struct ifreq l_ifr;
    memset(&l_ifr, 0, sizeof(l_ifr));
    l_ifr.ifr_flags = IFF_ATTACH_QUEUE;
    return ioctl(a_fd, TUNSETQUEUE, (void *)&l_ifr);
}

/**
 * @brief Detach TUN queue
 * @param a_fd TUN file descriptor
 * @return 0 on success, negative on error
 */
static int s_tun_detach_queue(int a_fd)
{
    struct ifreq l_ifr;
    memset(&l_ifr, 0, sizeof(l_ifr));
    l_ifr.ifr_flags = IFF_DETACH_QUEUE;
    return ioctl(a_fd, TUNSETQUEUE, (void *)&l_ifr);
}

/**
 * @brief Create single TUN device with multi-queue support
 * @param a_worker Worker thread
 * @param a_config TUN configuration
 * @param a_out_fd Output: file descriptor
 * @return 0 on success, negative on error
 */
static int s_create_tun_device(dap_worker_t *a_worker, const dap_tun_server_config_t *a_config, int *a_out_fd)
{
    int l_tun_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (l_tun_fd < 0) {
        log_it(L_ERROR, "Failed to open /dev/net/tun: %s", dap_strerror(errno));
        return -1;
    }

    log_it(L_DEBUG, "Opening /dev/net/tun for worker #%u", a_worker->id);

    if (ioctl(l_tun_fd, TUNSETIFF, (void *)&s_tun_state.ifr) < 0) {
        log_it(L_CRITICAL, "ioctl(TUNSETIFF) failed: %s", dap_strerror(errno));
        close(l_tun_fd);
        return -2;
    }

    // Detach queue for proper multi-queue operation
    s_tun_detach_queue(l_tun_fd);

    *a_out_fd = l_tun_fd;
    return 0;
}

/**
 * @brief Configure TUN device network parameters
 * @param a_config TUN configuration
 * @return 0 on success, negative on error
 */
static int s_configure_tun_network(const dap_tun_server_config_t *a_config)
{
    char l_buf[256];
    char l_str_gw[INET_ADDRSTRLEN];
    char l_str_mask[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &a_config->gateway_addr, l_str_gw, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &a_config->network_mask, l_str_mask, INET_ADDRSTRLEN);

    // Bring interface up
    snprintf(l_buf, sizeof(l_buf), "ip link set %s up", s_tun_state.device_name);
    if (system(l_buf) != 0) {
        log_it(L_ERROR, "Failed to bring up interface: %s", s_tun_state.device_name);
        return -1;
    }

    // Configure IP address
    snprintf(l_buf, sizeof(l_buf), "ip addr add %s/%s dev %s",
             l_str_gw, l_str_mask, s_tun_state.device_name);
    if (system(l_buf) != 0) {
        log_it(L_ERROR, "Failed to configure IP address");
        return -2;
    }

    log_it(L_NOTICE, "Configured %s with %s/%s", s_tun_state.device_name, l_str_gw, l_str_mask);
    return 0;
}

/**
 * @brief Initialize TUN devices for all workers
 * @param a_config TUN configuration
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

    // Get number of workers (CPU cores)
    s_tun_state.socket_count = dap_get_cpu_count();
    log_it(L_INFO, "Initializing %u TUN sockets (multi-queue)", s_tun_state.socket_count);

    // Prepare ifreq for multi-queue TUN
    memset(&s_tun_state.ifr, 0, sizeof(s_tun_state.ifr));
    s_tun_state.ifr.ifr_flags = IFF_TUN | IFF_MULTI_QUEUE | IFF_NO_PI;

    // Allocate arrays
    s_tun_state.tun_sockets = DAP_NEW_Z_SIZE(dap_chain_net_srv_vpn_tun_socket_t*,
                                               s_tun_state.socket_count * sizeof(dap_chain_net_srv_vpn_tun_socket_t*));
    s_tun_state.queue_msg_sockets = DAP_NEW_Z_SIZE(dap_events_socket_t*,
                                                     s_tun_state.socket_count * sizeof(dap_events_socket_t*));
    if (!s_tun_state.tun_sockets || !s_tun_state.queue_msg_sockets) {
        log_it(L_CRITICAL, "Memory allocation failed");
        DAP_DEL_Z(s_tun_state.tun_sockets);
        DAP_DEL_Z(s_tun_state.queue_msg_sockets);
        return -2;
    }

    // Create TUN devices for each worker
    for (uint32_t i = 0; i < s_tun_state.socket_count; i++) {
        dap_worker_t *l_worker = dap_events_worker_get(i);
        if (!l_worker) {
            log_it(L_ERROR, "Failed to get worker #%u", i);
            return -3;
        }

        int l_tun_fd;
        if (s_create_tun_device(l_worker, &l_config, &l_tun_fd) < 0) {
            log_it(L_ERROR, "Failed to create TUN device for worker #%u", i);
            return -4;
        }

        // Save device name from first device
        if (i == 0) {
            strncpy(s_tun_state.device_name, s_tun_state.ifr.ifr_name, IFNAMSIZ - 1);
        }

        // Create event socket for TUN device
        // This will be done by calling code using dap_events_socket_wrap_no_add()
        // and then assigning to worker
    }

    // Configure network for the device
    if (s_configure_tun_network(&l_config) < 0) {
        log_it(L_ERROR, "Failed to configure TUN network");
        return -5;
    }

    s_tun_state.initialized = true;
    log_it(L_NOTICE, "TUN server initialized with %u sockets", s_tun_state.socket_count);
    return 0;
}

/**
 * @brief Deinitialize TUN devices
 */
void dap_tun_server_deinit(void)
{
    if (!s_tun_state.initialized) {
        return;
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
 * @brief Get number of TUN sockets
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

