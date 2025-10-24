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

#include "dap_net_tun.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_worker.h"
#include "dap_events_socket.h"

#define LOG_TAG "dap_net_tun_linux"

/**
 * @brief Linux-specific TUN device data
 */
typedef struct dap_net_tun_linux {
    struct ifreq ifr;                   // Interface request structure
    int *tun_fds;                       // Array of TUN file descriptors
    dap_events_socket_t **tun_es;      // Event sockets for TUN devices
    dap_events_socket_t **queue_msg_es; // Inter-worker queue message sockets
} dap_net_tun_linux_t;

/**
 * @brief TUN device internal structure (from dap_net_tun.h)
 */
struct dap_net_tun {
    dap_net_tun_mode_t mode;
    
    // Network configuration
    struct in_addr network_addr;
    struct in_addr network_mask;
    struct in_addr gateway_addr;
    uint16_t mtu;
    
    // Devices
    uint32_t device_count;
    char **device_names;
    int *device_fds;
    dap_events_socket_t **event_sockets;
    
    // Workers (SERVER mode only)
    dap_worker_t **workers;
    bool workers_allocated_internally;
    
    // Callbacks
    dap_net_tun_data_callback_t on_data_received;
    dap_net_tun_error_callback_t on_error;
    void *callback_arg;
    
    // Statistics
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    
    // Platform-specific data
    void *platform_data;
};

/**
 * @brief Attach TUN queue for multi-queue support
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
 */
static int s_tun_detach_queue(int a_fd)
{
    struct ifreq l_ifr;
    memset(&l_ifr, 0, sizeof(l_ifr));
    l_ifr.ifr_flags = IFF_DETACH_QUEUE;
    return ioctl(a_fd, TUNSETQUEUE, (void *)&l_ifr);
}

/**
 * @brief Configure TUN device network parameters
 */
static int s_configure_tun_network(dap_net_tun_t *a_tun)
{
    char l_buf[512];
    char l_str_addr[INET_ADDRSTRLEN];
    char l_str_gw[INET_ADDRSTRLEN];
    char l_str_mask[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &a_tun->network_addr, l_str_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &a_tun->gateway_addr, l_str_gw, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &a_tun->network_mask, l_str_mask, INET_ADDRSTRLEN);
    
    const char *l_dev_name = a_tun->device_names[0];
    
    // Bring interface up
    snprintf(l_buf, sizeof(l_buf), "ip link set %s up mtu %u", l_dev_name, a_tun->mtu);
    if (system(l_buf) != 0) {
        log_it(L_ERROR, "Failed to bring up interface %s", l_dev_name);
        return -1;
    }
    
    // Configure IP address
    snprintf(l_buf, sizeof(l_buf), "ip addr add %s/%s dev %s",
             l_str_gw, l_str_mask, l_dev_name);
    if (system(l_buf) != 0) {
        log_it(L_WARNING, "Failed to configure IP address (may already exist)");
    }
    
    log_it(L_NOTICE, "Configured %s: gw=%s, mask=%s, mtu=%u",
           l_dev_name, l_str_gw, l_str_mask, a_tun->mtu);
    
    return 0;
}

/**
 * @brief Event socket callback for TUN device
 */
static void s_tun_event_socket_callback(dap_events_socket_t *a_es, void *a_arg)
{
    dap_net_tun_t *l_tun = (dap_net_tun_t *)a_arg;
    
    if (!l_tun || !a_es || !a_es->buf_in_size) {
        return;
    }
    
    // Update statistics
    l_tun->bytes_received += a_es->buf_in_size;
    l_tun->packets_received++;
    
    // Call user callback
    if (l_tun->on_data_received) {
        l_tun->on_data_received(l_tun, a_es->buf_in, a_es->buf_in_size, l_tun->callback_arg);
    }
    
    // Reset buffer for next read
    a_es->buf_in_size = 0;
}

/**
 * @brief Error callback for TUN device
 */
static void s_tun_event_socket_error(dap_events_socket_t *a_es, int a_error)
{
    dap_net_tun_t *l_tun = (dap_net_tun_t *)a_es->_inheritor;
    
    if (l_tun && l_tun->on_error) {
        l_tun->on_error(l_tun, a_error, l_tun->callback_arg);
    }
}

/**
 * @brief Create single TUN device
 */
static int s_create_tun_device(dap_net_tun_t *a_tun, dap_net_tun_linux_t *a_linux, uint32_t a_index, dap_worker_t *a_worker)
{
    int l_tun_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (l_tun_fd < 0) {
        log_it(L_ERROR, "Failed to open /dev/net/tun: %s", dap_strerror(errno));
        return -1;
    }
    
    log_it(L_DEBUG, "Opened /dev/net/tun (fd=%d) for device index %u", l_tun_fd, a_index);
    
    // Set interface parameters
    if (ioctl(l_tun_fd, TUNSETIFF, (void *)&a_linux->ifr) < 0) {
        log_it(L_CRITICAL, "ioctl(TUNSETIFF) failed: %s", dap_strerror(errno));
        close(l_tun_fd);
        return -2;
    }
    
    // For multi-queue: detach queue for proper operation
    if (a_tun->mode == DAP_NET_TUN_MODE_SERVER && a_tun->device_count > 1) {
        s_tun_detach_queue(l_tun_fd);
    }
    
    // Save device name from first device
    if (a_index == 0 && !a_tun->device_names[0]) {
        a_tun->device_names[0] = dap_strdup(a_linux->ifr.ifr_name);
    }
    
    // Store FD
    a_linux->tun_fds[a_index] = l_tun_fd;
    a_tun->device_fds[a_index] = l_tun_fd;
    
    // Create event socket wrapper for TUN device
    dap_events_socket_t *l_tun_es = dap_events_socket_wrap_no_add(
        l_tun_fd,
        a_worker,
        s_tun_event_socket_callback,
        s_tun_event_socket_error,
        a_tun
    );
    
    if (!l_tun_es) {
        log_it(L_ERROR, "Failed to create event socket for TUN device");
        close(l_tun_fd);
        return -3;
    }
    
    l_tun_es->_inheritor = a_tun;
    l_tun_es->flags |= DAP_SOCK_READY_TO_READ;
    
    // Assign to worker
    dap_worker_add_events_socket_unsafe(a_worker, l_tun_es);
    
    a_linux->tun_es[a_index] = l_tun_es;
    a_tun->event_sockets[a_index] = l_tun_es;
    
    log_it(L_INFO, "Created TUN device #%u (fd=%d) on worker #%u",
           a_index, l_tun_fd, a_worker->id);
    
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
    
    // Create Linux-specific data
    dap_net_tun_linux_t *l_linux = DAP_NEW_Z(dap_net_tun_linux_t);
    if (!l_linux) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_tun);
        return NULL;
    }
    
    l_tun->platform_data = l_linux;
    
    // Determine device count
    if (l_tun->mode == DAP_NET_TUN_MODE_CLIENT) {
        l_tun->device_count = 1;
    } else {
        // SERVER mode: try multi-queue (one device per worker)
        uint32_t l_worker_count = a_config->worker_count ? a_config->worker_count : dap_get_cpu_count();
        l_tun->device_count = l_worker_count;
        
        // Setup workers
        if (a_config->workers) {
            l_tun->workers = a_config->workers;
            l_tun->workers_allocated_internally = false;
        } else {
            // Workers will be obtained via dap_events_worker_get()
            l_tun->workers = NULL;
            l_tun->workers_allocated_internally = false;
        }
    }
    
    // Allocate arrays
    l_tun->device_names = DAP_NEW_Z_SIZE(char*, l_tun->device_count * sizeof(char*));
    l_tun->device_fds = DAP_NEW_Z_SIZE(int, l_tun->device_count * sizeof(int));
    l_tun->event_sockets = DAP_NEW_Z_SIZE(dap_events_socket_t*, l_tun->device_count * sizeof(dap_events_socket_t*));
    l_linux->tun_fds = DAP_NEW_Z_SIZE(int, l_tun->device_count * sizeof(int));
    l_linux->tun_es = DAP_NEW_Z_SIZE(dap_events_socket_t*, l_tun->device_count * sizeof(dap_events_socket_t*));
    
    if (!l_tun->device_names || !l_tun->device_fds || !l_tun->event_sockets ||
        !l_linux->tun_fds || !l_linux->tun_es) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_net_tun_deinit(l_tun);
        return NULL;
    }
    
    // Prepare ifreq structure
    memset(&l_linux->ifr, 0, sizeof(l_linux->ifr));
    
    if (l_tun->mode == DAP_NET_TUN_MODE_SERVER && l_tun->device_count > 1) {
        // Multi-queue mode
        l_linux->ifr.ifr_flags = IFF_TUN | IFF_MULTI_QUEUE | IFF_NO_PI;
        log_it(L_INFO, "Using IFF_MULTI_QUEUE for %u devices", l_tun->device_count);
    } else {
        // Single device
        l_linux->ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    }
    
    // Set device name prefix if specified
    if (a_config->device_name_prefix) {
        strncpy(l_linux->ifr.ifr_name, a_config->device_name_prefix, IFNAMSIZ - 1);
    }
    
    // Create TUN device(s)
    for (uint32_t i = 0; i < l_tun->device_count; i++) {
        dap_worker_t *l_worker = NULL;
        
        if (l_tun->mode == DAP_NET_TUN_MODE_CLIENT) {
            // CLIENT mode: use current worker or default
            l_worker = dap_events_get_current_worker() ? dap_events_get_current_worker() : dap_events_worker_get(0);
        } else {
            // SERVER mode: assign to specific worker
            l_worker = a_config->workers ? a_config->workers[i] : dap_events_worker_get(i);
        }
        
        if (!l_worker) {
            log_it(L_ERROR, "Failed to get worker for device #%u", i);
            dap_net_tun_deinit(l_tun);
            return NULL;
        }
        
        if (s_create_tun_device(l_tun, l_linux, i, l_worker) < 0) {
            log_it(L_ERROR, "Failed to create TUN device #%u", i);
            dap_net_tun_deinit(l_tun);
            return NULL;
        }
    }
    
    // Configure network (only once, on first device)
    if (s_configure_tun_network(l_tun) < 0) {
        log_it(L_ERROR, "Failed to configure TUN network");
        dap_net_tun_deinit(l_tun);
        return NULL;
    }
    
    log_it(L_NOTICE, "TUN initialized: mode=%s, devices=%u, name=%s",
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
    
    dap_net_tun_linux_t *l_linux = (dap_net_tun_linux_t *)a_tun->platform_data;
    
    // Close event sockets
    if (l_linux && l_linux->tun_es) {
        for (uint32_t i = 0; i < a_tun->device_count; i++) {
            if (l_linux->tun_es[i]) {
                dap_events_socket_delete_unsafe(l_linux->tun_es[i], true);
            }
        }
        DAP_DELETE(l_linux->tun_es);
    }
    
    // Close file descriptors
    if (l_linux && l_linux->tun_fds) {
        for (uint32_t i = 0; i < a_tun->device_count; i++) {
            if (l_linux->tun_fds[i] >= 0) {
                close(l_linux->tun_fds[i]);
            }
        }
        DAP_DELETE(l_linux->tun_fds);
    }
    
    // Free queue message sockets
    if (l_linux && l_linux->queue_msg_es) {
        DAP_DELETE(l_linux->queue_msg_es);
    }
    
    // Free platform data
    DAP_DELETE(l_linux);
    
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
 * @brief Write data to TUN device
 */
ssize_t dap_net_tun_write(dap_net_tun_t *a_tun, const void *a_data, size_t a_data_size)
{
    if (!a_tun || !a_data || a_data_size == 0) {
        return -1;
    }
    
    dap_net_tun_linux_t *l_linux = (dap_net_tun_linux_t *)a_tun->platform_data;
    if (!l_linux) {
        return -2;
    }
    
    // Select device index
    uint32_t l_device_index = 0;
    
    if (a_tun->mode == DAP_NET_TUN_MODE_SERVER && a_tun->device_count > 1) {
        // Round-robin for SERVER mode with multiple devices
        static uint32_t s_round_robin = 0;
        l_device_index = s_round_robin % a_tun->device_count;
        s_round_robin++;
    }
    
    // Get event socket and use dap_events_socket_write_unsafe
    dap_events_socket_t *l_es = l_linux->tun_es[l_device_index];
    if (!l_es) {
        log_it(L_ERROR, "Event socket for device #%u is NULL", l_device_index);
        return -3;
    }
    
    // Write via event socket (efficient, worker-aware)
    size_t l_written = dap_events_socket_write_unsafe(l_es, a_data, a_data_size);
    
    if (l_written > 0) {
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

