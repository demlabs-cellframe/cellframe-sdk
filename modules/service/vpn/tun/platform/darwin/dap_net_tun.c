/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * This file is part of DAP SDK the open source project
 *
 *    DAP SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    DAP SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
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

#include "dap_net_tun.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_worker.h"
#include "dap_events_socket.h"

#define LOG_TAG "dap_net_tun_darwin"

/**
 * @brief Darwin-specific TUN device data
 */
typedef struct dap_net_tun_darwin {
    int *utun_fds;                      // UTUN file descriptors
    dap_events_socket_t **utun_es;     // Event sockets
    dap_events_socket_t **queue_msg_es; // Inter-worker queues
} dap_net_tun_darwin_t;

/**
 * @brief TUN device internal structure
 */
struct dap_net_tun {
    dap_net_tun_mode_t mode;
    
    struct in_addr network_addr;
    struct in_addr network_mask;
    struct in_addr gateway_addr;
    uint16_t mtu;
    
    uint32_t device_count;
    char **device_names;
    int *device_fds;
    dap_events_socket_t **event_sockets;
    
    dap_worker_t **workers;
    bool workers_allocated_internally;
    
    dap_net_tun_data_callback_t on_data_received;
    dap_net_tun_error_callback_t on_error;
    void *callback_arg;
    
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    
    void *platform_data;
};

/**
 * @brief Create UTUN device on macOS/iOS
 */
static int s_create_utun_device(int *a_out_fd, char *a_out_name, size_t a_name_size)
{
    struct ctl_info l_ctl_info = {0};
    
    // Copy utun control name
    if (strlcpy(l_ctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(l_ctl_info.ctl_name))
            >= sizeof(l_ctl_info.ctl_name)) {
        log_it(L_ERROR, "UTUN_CONTROL_NAME too long");
        return -1;
    }
    
    // Create utun socket
    int l_tun_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (l_tun_fd < 0) {
        log_it(L_ERROR, "Failed to open SYSPROTO_CONTROL: %s", dap_strerror(errno));
        return -2;
    }
    
    log_it(L_DEBUG, "UTUN SYSPROTO_CONTROL descriptor: fd=%d", l_tun_fd);
    
    // Get control info
    if (ioctl(l_tun_fd, CTLIOCGINFO, &l_ctl_info) < 0) {
        log_it(L_ERROR, "ioctl(CTLIOCGINFO) failed: %s", dap_strerror(errno));
        close(l_tun_fd);
        return -3;
    }
    
    // Try to connect with one of utunX devices
    int l_ret = -1;
    int l_connected_unit = -1;
    
    for (int l_unit = 0; l_unit < 256; l_unit++) {
        struct sockaddr_ctl l_sa_ctl = {0};
        l_sa_ctl.sc_id = l_ctl_info.ctl_id;
        l_sa_ctl.sc_len = sizeof(l_sa_ctl);
        l_sa_ctl.sc_family = AF_SYSTEM;
        l_sa_ctl.ss_sysaddr = AF_SYS_CONTROL;
        l_sa_ctl.sc_unit = l_unit + 1;
        
        l_ret = connect(l_tun_fd, (struct sockaddr *)&l_sa_ctl, sizeof(l_sa_ctl));
        if (l_ret == 0) {
            l_connected_unit = l_unit;
            break;
        }
    }
    
    if (l_ret < 0) {
        log_it(L_ERROR, "Failed to create utun device: %s", dap_strerror(errno));
        close(l_tun_fd);
        return -4;
    }
    
    // Get interface name
    char l_utunname[IFNAMSIZ];
    socklen_t l_utunname_len = sizeof(l_utunname);
    
    if (getsockopt(l_tun_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, l_utunname, &l_utunname_len)) {
        log_it(L_ERROR, "Failed to get utun device name: %s", dap_strerror(errno));
        close(l_tun_fd);
        return -5;
    }
    
    strncpy(a_out_name, l_utunname, a_name_size - 1);
    a_out_name[a_name_size - 1] = '\0';
    *a_out_fd = l_tun_fd;
    
    log_it(L_NOTICE, "Created UTUN device: %s (fd=%d, unit=%d)",
           a_out_name, l_tun_fd, l_connected_unit);
    
    return 0;
}

/**
 * @brief Configure UTUN network parameters
 */
static int s_configure_utun_network(dap_net_tun_t *a_tun)
{
    char l_buf[512];
    char l_str_gw[INET_ADDRSTRLEN];
    char l_str_mask[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &a_tun->gateway_addr, l_str_gw, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &a_tun->network_mask, l_str_mask, INET_ADDRSTRLEN);
    
    const char *l_dev_name = a_tun->device_names[0];
    
    // Configure interface with ifconfig
    snprintf(l_buf, sizeof(l_buf), "ifconfig %s %s %s up mtu %u",
             l_dev_name, l_str_gw, l_str_gw, a_tun->mtu);
    
    if (system(l_buf) != 0) {
        log_it(L_ERROR, "Failed to configure interface %s", l_dev_name);
        return -1;
    }
    
    log_it(L_NOTICE, "Configured %s: gw=%s, mtu=%u", l_dev_name, l_str_gw, a_tun->mtu);
    
    return 0;
}

/**
 * @brief Event socket callback for UTUN device
 */
static void s_utun_event_socket_callback(dap_events_socket_t *a_es, void *a_arg)
{
    dap_net_tun_t *l_tun = (dap_net_tun_t *)a_arg;
    
    if (!l_tun || !a_es || !a_es->buf_in_size) {
        return;
    }
    
    // macOS UTUN adds 4-byte protocol header - skip it
    const uint8_t *l_data = a_es->buf_in;
    size_t l_data_size = a_es->buf_in_size;
    
    if (l_data_size > 4) {
        l_data += 4;
        l_data_size -= 4;
    } else {
        log_it(L_WARNING, "UTUN packet too small: %zu bytes", a_es->buf_in_size);
        a_es->buf_in_size = 0;
        return;
    }
    
    // Update statistics
    l_tun->bytes_received += l_data_size;
    l_tun->packets_received++;
    
    // Call user callback
    if (l_tun->on_data_received) {
        l_tun->on_data_received(l_tun, l_data, l_data_size, l_tun->callback_arg);
    }
    
    a_es->buf_in_size = 0;
}

/**
 * @brief Error callback
 */
static void s_utun_event_socket_error(dap_events_socket_t *a_es, int a_error)
{
    dap_net_tun_t *l_tun = (dap_net_tun_t *)a_es->_inheritor;
    
    if (l_tun && l_tun->on_error) {
        l_tun->on_error(l_tun, a_error, l_tun->callback_arg);
    }
}

/**
 * @brief Create single UTUN device and assign to worker
 */
static int s_create_and_assign_utun(dap_net_tun_t *a_tun, dap_net_tun_darwin_t *a_darwin,
                                     uint32_t a_index, dap_worker_t *a_worker)
{
    char l_dev_name[IFNAMSIZ];
    int l_utun_fd;
    
    if (s_create_utun_device(&l_utun_fd, l_dev_name, sizeof(l_dev_name)) < 0) {
        log_it(L_ERROR, "Failed to create UTUN device #%u", a_index);
        return -1;
    }
    
    // Set non-blocking
    int l_flags = fcntl(l_utun_fd, F_GETFL, 0);
    fcntl(l_utun_fd, F_SETFL, l_flags | O_NONBLOCK);
    
    // Save device info
    a_tun->device_names[a_index] = dap_strdup(l_dev_name);
    a_tun->device_fds[a_index] = l_utun_fd;
    a_darwin->utun_fds[a_index] = l_utun_fd;
    
    // Create event socket wrapper
    dap_events_socket_t *l_utun_es = dap_events_socket_wrap_no_add(
        l_utun_fd,
        a_worker,
        s_utun_event_socket_callback,
        s_utun_event_socket_error,
        a_tun
    );
    
    if (!l_utun_es) {
        log_it(L_ERROR, "Failed to create event socket for UTUN device");
        close(l_utun_fd);
        return -2;
    }
    
    l_utun_es->_inheritor = a_tun;
    l_utun_es->flags |= DAP_SOCK_READY_TO_READ;
    
    // Assign to worker
    dap_worker_add_events_socket_unsafe(a_worker, l_utun_es);
    
    a_darwin->utun_es[a_index] = l_utun_es;
    a_tun->event_sockets[a_index] = l_utun_es;
    
    log_it(L_INFO, "Created UTUN device #%u: %s (fd=%d) on worker #%u",
           a_index, l_dev_name, l_utun_fd, a_worker->id);
    
    return 0;
}

/**
 * @brief Initialize TUN device(s)
 */
dap_net_tun_t* dap_net_tun_init(const dap_net_tun_config_t *a_config)
{
    if (!a_config) {
        log_it(L_ERROR, "Config is NULL");
        return NULL;
    }
    
    dap_net_tun_t *l_tun = DAP_NEW_Z(dap_net_tun_t);
    if (!l_tun) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    // Copy configuration
    l_tun->mode = a_config->mode;
    l_tun->network_addr = a_config->network_addr;
    l_tun->network_mask = a_config->network_mask;
    l_tun->gateway_addr = a_config->gateway_addr;
    l_tun->mtu = a_config->mtu ? a_config->mtu : 1500;
    l_tun->on_data_received = a_config->on_data_received;
    l_tun->on_error = a_config->on_error;
    l_tun->callback_arg = a_config->callback_arg;
    
    // Create Darwin-specific data
    dap_net_tun_darwin_t *l_darwin = DAP_NEW_Z(dap_net_tun_darwin_t);
    if (!l_darwin) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_tun);
        return NULL;
    }
    
    l_tun->platform_data = l_darwin;
    
    // Determine device count
    // Note: macOS UTUN doesn't support multi-queue like Linux IFF_MULTI_QUEUE
    // For SERVER mode, create multiple separate UTUN devices (one per worker)
    if (l_tun->mode == DAP_NET_TUN_MODE_CLIENT) {
        l_tun->device_count = 1;
    } else {
        uint32_t l_worker_count = a_config->worker_count ? a_config->worker_count : dap_get_cpu_count();
        l_tun->device_count = l_worker_count;
        
        log_it(L_INFO, "SERVER mode: creating %u separate UTUN devices (no native multi-queue on Darwin)",
               l_tun->device_count);
    }
    
    // Allocate arrays
    l_tun->device_names = DAP_NEW_Z_SIZE(char*, l_tun->device_count * sizeof(char*));
    l_tun->device_fds = DAP_NEW_Z_SIZE(int, l_tun->device_count * sizeof(int));
    l_tun->event_sockets = DAP_NEW_Z_SIZE(dap_events_socket_t*, l_tun->device_count * sizeof(dap_events_socket_t*));
    l_darwin->utun_fds = DAP_NEW_Z_SIZE(int, l_tun->device_count * sizeof(int));
    l_darwin->utun_es = DAP_NEW_Z_SIZE(dap_events_socket_t*, l_tun->device_count * sizeof(dap_events_socket_t*));
    
    if (!l_tun->device_names || !l_tun->device_fds || !l_tun->event_sockets ||
        !l_darwin->utun_fds || !l_darwin->utun_es) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_net_tun_deinit(l_tun);
        return NULL;
    }
    
    // Create UTUN device(s)
    for (uint32_t i = 0; i < l_tun->device_count; i++) {
        dap_worker_t *l_worker = NULL;
        
        if (l_tun->mode == DAP_NET_TUN_MODE_CLIENT) {
            l_worker = dap_events_get_current_worker() ? dap_events_get_current_worker() : dap_events_worker_get(0);
        } else {
            l_worker = a_config->workers ? a_config->workers[i] : dap_events_worker_get(i);
        }
        
        if (!l_worker) {
            log_it(L_ERROR, "Failed to get worker for device #%u", i);
            dap_net_tun_deinit(l_tun);
            return NULL;
        }
        
        if (s_create_and_assign_utun(l_tun, l_darwin, i, l_worker) < 0) {
            log_it(L_ERROR, "Failed to create and assign UTUN #%u", i);
            dap_net_tun_deinit(l_tun);
            return NULL;
        }
    }
    
    // Configure first device (others share same network config)
    if (s_configure_utun_network(l_tun) < 0) {
        log_it(L_ERROR, "Failed to configure UTUN network");
        dap_net_tun_deinit(l_tun);
        return NULL;
    }
    
    log_it(L_NOTICE, "TUN initialized on Darwin: mode=%s, devices=%u, primary=%s",
           l_tun->mode == DAP_NET_TUN_MODE_CLIENT ? "CLIENT" : "SERVER",
           l_tun->device_count,
           l_tun->device_names[0]);
    
    return l_tun;
}

/**
 * @brief Deinitialize TUN device(s)
 */
void dap_net_tun_deinit(dap_net_tun_t *a_tun)
{
    if (!a_tun)
        return;
    
    dap_net_tun_darwin_t *l_darwin = (dap_net_tun_darwin_t *)a_tun->platform_data;
    
    // Close event sockets
    if (l_darwin && l_darwin->utun_es) {
        for (uint32_t i = 0; i < a_tun->device_count; i++) {
            if (l_darwin->utun_es[i]) {
                dap_events_socket_delete_unsafe(l_darwin->utun_es[i], true);
            }
        }
        DAP_DELETE(l_darwin->utun_es);
    }
    
    // Close file descriptors
    if (l_darwin && l_darwin->utun_fds) {
        for (uint32_t i = 0; i < a_tun->device_count; i++) {
            if (l_darwin->utun_fds[i] >= 0) {
                close(l_darwin->utun_fds[i]);
            }
        }
        DAP_DELETE(l_darwin->utun_fds);
    }
    
    DAP_DELETE(l_darwin);
    
    // Free device names
    if (a_tun->device_names) {
        for (uint32_t i = 0; i < a_tun->device_count; i++) {
            DAP_DELETE(a_tun->device_names[i]);
        }
        DAP_DELETE(a_tun->device_names);
    }
    
    DAP_DELETE(a_tun->device_fds);
    DAP_DELETE(a_tun->event_sockets);
    DAP_DELETE(a_tun);
    
    log_it(L_INFO, "TUN device deinitialized");
}

/**
 * @brief Write data to UTUN device
 */
ssize_t dap_net_tun_write(dap_net_tun_t *a_tun, const void *a_data, size_t a_data_size)
{
    if (!a_tun || !a_data || a_data_size == 0) {
        return -1;
    }
    
    dap_net_tun_darwin_t *l_darwin = (dap_net_tun_darwin_t *)a_tun->platform_data;
    if (!l_darwin) {
        return -2;
    }
    
    // Select device (round-robin for SERVER with multiple devices)
    uint32_t l_device_index = 0;
    
    if (a_tun->mode == DAP_NET_TUN_MODE_SERVER && a_tun->device_count > 1) {
        static uint32_t s_round_robin = 0;
        l_device_index = s_round_robin % a_tun->device_count;
        s_round_robin++;
    }
    
    dap_events_socket_t *l_es = l_darwin->utun_es[l_device_index];
    if (!l_es) {
        return -3;
    }
    
    // macOS UTUN requires 4-byte protocol header (AF_INET = 0x02000000 in network byte order)
    uint8_t l_packet[a_data_size + 4];
    uint32_t l_proto = htonl(AF_INET);
    memcpy(l_packet, &l_proto, 4);
    memcpy(l_packet + 4, a_data, a_data_size);
    
    // Write via event socket
    size_t l_written = dap_events_socket_write_unsafe(l_es, l_packet, sizeof(l_packet));
    
    if (l_written > 4) {
        // Subtract protocol header from stats
        l_written -= 4;
        a_tun->bytes_sent += l_written;
        a_tun->packets_sent++;
    }
    
    return (ssize_t)l_written;
}

/**
 * @brief Get device name
 */
const char* dap_net_tun_get_device_name(dap_net_tun_t *a_tun, uint32_t a_device_index)
{
    if (!a_tun || a_device_index >= a_tun->device_count) {
        return NULL;
    }
    
    return a_tun->device_names[a_device_index];
}

/**
 * @brief Get device count
 */
uint32_t dap_net_tun_get_device_count(dap_net_tun_t *a_tun)
{
    return a_tun ? a_tun->device_count : 0;
}

/**
 * @brief Get statistics
 */
int dap_net_tun_get_stats(
    dap_net_tun_t *a_tun,
    uint64_t *a_bytes_sent,
    uint64_t *a_bytes_received,
    uint64_t *a_packets_sent,
    uint64_t *a_packets_received)
{
    if (!a_tun) {
        return -1;
    }
    
    if (a_bytes_sent) *a_bytes_sent = a_tun->bytes_sent;
    if (a_bytes_received) *a_bytes_received = a_tun->bytes_received;
    if (a_packets_sent) *a_packets_sent = a_tun->packets_sent;
    if (a_packets_received) *a_packets_received = a_tun->packets_received;
    
    return 0;
}

/**
 * @brief Get file descriptor
 */
int dap_net_tun_get_fd(dap_net_tun_t *a_tun, uint32_t a_device_index)
{
    if (!a_tun || a_device_index >= a_tun->device_count) {
        return -1;
    }
    
    return a_tun->device_fds[a_device_index];
}

/**
 * @brief Get mode
 */
dap_net_tun_mode_t dap_net_tun_get_mode(dap_net_tun_t *a_tun)
{
    return a_tun ? a_tun->mode : DAP_NET_TUN_MODE_CLIENT;
}

#endif // !DAP_OS_IOS

