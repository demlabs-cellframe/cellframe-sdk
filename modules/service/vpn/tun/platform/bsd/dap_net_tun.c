/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2021-2025
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
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <net/if_tun.h>
#include <arpa/inet.h>

#include "dap_net_tun.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_worker.h"
#include "dap_events_socket.h"

#define LOG_TAG "dap_net_tun_bsd"

/**
 * @brief BSD-specific TUN device data
 */
typedef struct dap_net_tun_bsd {
    int *tun_fds;
    dap_events_socket_t **tun_es;
} dap_net_tun_bsd_t;

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
 * @brief Create TUN device on BSD
 */
static int s_create_tun_device_bsd(int *a_out_fd, char *a_out_name, size_t a_name_size)
{
    // Try to open /dev/tunX devices
    for (int i = 0; i < 256; i++) {
        char l_dev_path[64];
        snprintf(l_dev_path, sizeof(l_dev_path), "/dev/tun%d", i);
        
        int l_fd = open(l_dev_path, O_RDWR | O_NONBLOCK);
        if (l_fd >= 0) {
            snprintf(a_out_name, a_name_size, "tun%d", i);
            *a_out_fd = l_fd;
            log_it(L_NOTICE, "Opened TUN device: %s (fd=%d)", a_out_name, l_fd);
            return 0;
        }
    }
    
    log_it(L_ERROR, "Failed to open any TUN device: %s", dap_strerror(errno));
    return -1;
}

/**
 * @brief Configure TUN network on BSD
 */
static int s_configure_tun_network_bsd(dap_net_tun_t *a_tun)
{
    char l_buf[512];
    char l_str_gw[INET_ADDRSTRLEN];
    char l_str_mask[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &a_tun->gateway_addr, l_str_gw, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &a_tun->network_mask, l_str_mask, INET_ADDRSTRLEN);
    
    const char *l_dev_name = a_tun->device_names[0];
    
    // Configure interface with ifconfig
    snprintf(l_buf, sizeof(l_buf), "ifconfig %s inet %s netmask %s up mtu %u",
             l_dev_name, l_str_gw, l_str_mask, a_tun->mtu);
    
    if (system(l_buf) != 0) {
        log_it(L_ERROR, "Failed to configure interface %s", l_dev_name);
        return -1;
    }
    
    log_it(L_NOTICE, "Configured %s: gw=%s, mask=%s, mtu=%u",
           l_dev_name, l_str_gw, l_str_mask, a_tun->mtu);
    
    return 0;
}

/**
 * @brief Event socket callback
 */
static void s_tun_event_socket_callback(dap_events_socket_t *a_es, void *a_arg)
{
    dap_net_tun_t *l_tun = (dap_net_tun_t *)a_arg;
    
    if (!l_tun || !a_es || !a_es->buf_in_size) {
        return;
    }
    
    l_tun->bytes_received += a_es->buf_in_size;
    l_tun->packets_received++;
    
    if (l_tun->on_data_received) {
        l_tun->on_data_received(l_tun, a_es->buf_in, a_es->buf_in_size, l_tun->callback_arg);
    }
    
    a_es->buf_in_size = 0;
}

/**
 * @brief Error callback
 */
static void s_tun_event_socket_error(dap_events_socket_t *a_es, int a_error)
{
    dap_net_tun_t *l_tun = (dap_net_tun_t *)a_es->_inheritor;
    
    if (l_tun && l_tun->on_error) {
        l_tun->on_error(l_tun, a_error, l_tun->callback_arg);
    }
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
    
    l_tun->mode = a_config->mode;
    l_tun->network_addr = a_config->network_addr;
    l_tun->network_mask = a_config->network_mask;
    l_tun->gateway_addr = a_config->gateway_addr;
    l_tun->mtu = a_config->mtu ? a_config->mtu : 1500;
    l_tun->on_data_received = a_config->on_data_received;
    l_tun->on_error = a_config->on_error;
    l_tun->callback_arg = a_config->callback_arg;
    
    dap_net_tun_bsd_t *l_bsd = DAP_NEW_Z(dap_net_tun_bsd_t);
    if (!l_bsd) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_tun);
        return NULL;
    }
    
    l_tun->platform_data = l_bsd;
    
    // BSD: create separate TUN devices for each worker (no multi-queue)
    if (l_tun->mode == DAP_NET_TUN_MODE_CLIENT) {
        l_tun->device_count = 1;
    } else {
        l_tun->device_count = a_config->worker_count ? a_config->worker_count : dap_get_cpu_count();
    }
    
    // Allocate arrays
    l_tun->device_names = DAP_NEW_Z_SIZE(char*, l_tun->device_count * sizeof(char*));
    l_tun->device_fds = DAP_NEW_Z_SIZE(int, l_tun->device_count * sizeof(int));
    l_tun->event_sockets = DAP_NEW_Z_SIZE(dap_events_socket_t*, l_tun->device_count * sizeof(dap_events_socket_t*));
    l_bsd->tun_fds = DAP_NEW_Z_SIZE(int, l_tun->device_count * sizeof(int));
    l_bsd->tun_es = DAP_NEW_Z_SIZE(dap_events_socket_t*, l_tun->device_count * sizeof(dap_events_socket_t*));
    
    if (!l_tun->device_names || !l_bsd->tun_fds || !l_bsd->tun_es) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_net_tun_deinit(l_tun);
        return NULL;
    }
    
    // Create TUN devices
    for (uint32_t i = 0; i < l_tun->device_count; i++) {
        char l_dev_name[32];
        int l_tun_fd;
        
        if (s_create_tun_device_bsd(&l_tun_fd, l_dev_name, sizeof(l_dev_name)) < 0) {
            log_it(L_ERROR, "Failed to create TUN device #%u", i);
            dap_net_tun_deinit(l_tun);
            return NULL;
        }
        
        l_tun->device_names[i] = dap_strdup(l_dev_name);
        l_tun->device_fds[i] = l_tun_fd;
        l_bsd->tun_fds[i] = l_tun_fd;
        
        // Get worker
        dap_worker_t *l_worker = (l_tun->mode == DAP_NET_TUN_MODE_CLIENT) ?
            (dap_events_get_current_worker() ? dap_events_get_current_worker() : dap_events_worker_get(0)) :
            (a_config->workers ? a_config->workers[i] : dap_events_worker_get(i));
        
        if (!l_worker) {
            log_it(L_ERROR, "Failed to get worker");
            dap_net_tun_deinit(l_tun);
            return NULL;
        }
        
        // Create event socket
        dap_events_socket_t *l_es = dap_events_socket_wrap_no_add(
            l_tun_fd, l_worker,
            s_tun_event_socket_callback,
            s_tun_event_socket_error,
            l_tun
        );
        
        if (!l_es) {
            log_it(L_ERROR, "Failed to create event socket");
            dap_net_tun_deinit(l_tun);
            return NULL;
        }
        
        l_es->_inheritor = l_tun;
        l_es->flags |= DAP_SOCK_READY_TO_READ;
        dap_worker_add_events_socket_unsafe(l_worker, l_es);
        
        l_bsd->tun_es[i] = l_es;
        l_tun->event_sockets[i] = l_es;
    }
    
    // Configure first device
    if (s_configure_tun_network_bsd(l_tun) < 0) {
        log_it(L_ERROR, "Failed to configure TUN network");
        dap_net_tun_deinit(l_tun);
        return NULL;
    }
    
    log_it(L_NOTICE, "TUN initialized on BSD: mode=%s, devices=%u",
           l_tun->mode == DAP_NET_TUN_MODE_CLIENT ? "CLIENT" : "SERVER",
           l_tun->device_count);
    
    return l_tun;
}

/**
 * @brief Deinitialize TUN device(s)
 */
void dap_net_tun_deinit(dap_net_tun_t *a_tun)
{
    if (!a_tun)
        return;
    
    dap_net_tun_bsd_t *l_bsd = (dap_net_tun_bsd_t *)a_tun->platform_data;
    
    if (l_bsd) {
        if (l_bsd->tun_es) {
            for (uint32_t i = 0; i < a_tun->device_count; i++) {
                if (l_bsd->tun_es[i]) {
                    dap_events_socket_delete_unsafe(l_bsd->tun_es[i], true);
                }
            }
            DAP_DELETE(l_bsd->tun_es);
        }
        
        if (l_bsd->tun_fds) {
            for (uint32_t i = 0; i < a_tun->device_count; i++) {
                if (l_bsd->tun_fds[i] >= 0) {
                    close(l_bsd->tun_fds[i]);
                }
            }
            DAP_DELETE(l_bsd->tun_fds);
        }
        
        DAP_DELETE(l_bsd);
    }
    
    if (a_tun->device_names) {
        for (uint32_t i = 0; i < a_tun->device_count; i++) {
            DAP_DELETE(a_tun->device_names[i]);
        }
        DAP_DELETE(a_tun->device_names);
    }
    
    DAP_DELETE(a_tun->device_fds);
    DAP_DELETE(a_tun->event_sockets);
    DAP_DELETE(a_tun);
}

/**
 * @brief Write data to TUN device
 */
ssize_t dap_net_tun_write(dap_net_tun_t *a_tun, const void *a_data, size_t a_data_size)
{
    if (!a_tun || !a_data || a_data_size == 0) {
        return -1;
    }
    
    dap_net_tun_bsd_t *l_bsd = (dap_net_tun_bsd_t *)a_tun->platform_data;
    if (!l_bsd) {
        return -2;
    }
    
    uint32_t l_device_index = 0;
    
    if (a_tun->mode == DAP_NET_TUN_MODE_SERVER && a_tun->device_count > 1) {
        static uint32_t s_round_robin = 0;
        l_device_index = s_round_robin % a_tun->device_count;
        s_round_robin++;
    }
    
    dap_events_socket_t *l_es = l_bsd->tun_es[l_device_index];
    if (!l_es) {
        return -3;
    }
    
    size_t l_written = dap_events_socket_write_unsafe(l_es, a_data, a_data_size);
    
    if (l_written > 0) {
        a_tun->bytes_sent += l_written;
        a_tun->packets_sent++;
    }
    
    return (ssize_t)l_written;
}

const char* dap_net_tun_get_device_name(dap_net_tun_t *a_tun, uint32_t a_device_index)
{
    if (!a_tun || a_device_index >= a_tun->device_count) {
        return NULL;
    }
    return a_tun->device_names[a_device_index];
}

uint32_t dap_net_tun_get_device_count(dap_net_tun_t *a_tun)
{
    return a_tun ? a_tun->device_count : 0;
}

int dap_net_tun_get_stats(dap_net_tun_t *a_tun, uint64_t *a_bytes_sent,
                           uint64_t *a_bytes_received, uint64_t *a_packets_sent,
                           uint64_t *a_packets_received)
{
    if (!a_tun) return -1;
    
    if (a_bytes_sent) *a_bytes_sent = a_tun->bytes_sent;
    if (a_bytes_received) *a_bytes_received = a_tun->bytes_received;
    if (a_packets_sent) *a_packets_sent = a_tun->packets_sent;
    if (a_packets_received) *a_packets_received = a_tun->packets_received;
    
    return 0;
}

int dap_net_tun_get_fd(dap_net_tun_t *a_tun, uint32_t a_device_index)
{
    if (!a_tun || a_device_index >= a_tun->device_count) {
        return -1;
    }
    return a_tun->device_fds[a_device_index];
}

dap_net_tun_mode_t dap_net_tun_get_mode(dap_net_tun_t *a_tun)
{
    return a_tun ? a_tun->mode : DAP_NET_TUN_MODE_CLIENT;
}

