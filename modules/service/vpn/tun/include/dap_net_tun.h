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

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "dap_events_socket.h"
#include "dap_worker.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Unified TUN/TAP device management for DAP SDK
 * 
 * Universal module for both VPN client and server TUN device management.
 * Supports multiple platforms with unified API and mode-based behavior.
 */

/**
 * @brief TUN device operation mode
 */
typedef enum dap_net_tun_mode {
    DAP_NET_TUN_MODE_CLIENT,    // Client mode: single device, single worker
    DAP_NET_TUN_MODE_SERVER     // Server mode: multi-device, multi-worker (if supported)
} dap_net_tun_mode_t;

/**
 * @brief TUN device handle
 */
typedef struct dap_net_tun dap_net_tun_t;

/**
 * @brief Data received callback
 * 
 * @param a_tun TUN device handle
 * @param a_data Received data
 * @param a_data_size Data size
 * @param a_arg User argument
 */
typedef void (*dap_net_tun_data_callback_t)(
    dap_net_tun_t *a_tun,
    const void *a_data,
    size_t a_data_size,
    void *a_arg);

/**
 * @brief Error callback
 * 
 * @param a_tun TUN device handle
 * @param a_error_code Error code
 * @param a_arg User argument
 */
typedef void (*dap_net_tun_error_callback_t)(
    dap_net_tun_t *a_tun,
    int a_error_code,
    void *a_arg);

/**
 * @brief TUN device initialization configuration
 */
typedef struct dap_net_tun_config {
    dap_net_tun_mode_t mode;            // Operation mode (CLIENT or SERVER)
    
    // Network configuration
    struct in_addr network_addr;        // VPN network address
    struct in_addr network_mask;        // VPN network mask
    struct in_addr gateway_addr;        // VPN gateway address
    
    // Device configuration
    const char *device_name_prefix;     // Device name prefix (e.g., "tun", "utun")
    uint16_t mtu;                        // MTU (0 = use default 1500)
    
    // Worker configuration (SERVER mode only)
    uint32_t worker_count;               // Number of workers (0 = auto-detect CPU count)
    dap_worker_t **workers;              // Pre-allocated worker array (optional, NULL = auto-create)
    
    // Callbacks
    dap_net_tun_data_callback_t on_data_received;
    dap_net_tun_error_callback_t on_error;
    void *callback_arg;
    
    // Platform-specific
    bool auto_cpu_reassignment;          // Enable auto CPU reassignment for streams (SERVER mode)
} dap_net_tun_config_t;

/**
 * @brief Initialize TUN device(s)
 * 
 * Creates one TUN device in CLIENT mode, or multiple devices (one per worker)
 * in SERVER mode if platform supports multi-queue.
 * 
 * @param a_config Configuration
 * @return TUN handle or NULL on error
 */
dap_net_tun_t* dap_net_tun_init(const dap_net_tun_config_t *a_config);

/**
 * @brief Deinitialize TUN device(s)
 * 
 * @param a_tun TUN handle
 */
void dap_net_tun_deinit(dap_net_tun_t *a_tun);

/**
 * @brief Write data to TUN device
 * 
 * In CLIENT mode: writes to single device
 * In SERVER mode: selects appropriate device based on destination IP (if multiple)
 * 
 * @param a_tun TUN handle
 * @param a_data Data to write
 * @param a_data_size Data size
 * @return Number of bytes written or -1 on error
 */
ssize_t dap_net_tun_write(dap_net_tun_t *a_tun, const void *a_data, size_t a_data_size);

/**
 * @brief Get TUN device name
 * 
 * @param a_tun TUN handle
 * @param a_device_index Device index (0 for CLIENT mode, 0..N-1 for SERVER mode)
 * @return Device name or NULL if index out of range
 */
const char* dap_net_tun_get_device_name(dap_net_tun_t *a_tun, uint32_t a_device_index);

/**
 * @brief Get number of TUN devices
 * 
 * @param a_tun TUN handle
 * @return 1 for CLIENT mode, N for SERVER mode with multi-queue
 */
uint32_t dap_net_tun_get_device_count(dap_net_tun_t *a_tun);

/**
 * @brief Get statistics
 * 
 * @param a_tun TUN handle
 * @param[out] a_bytes_sent Total bytes sent (all devices)
 * @param[out] a_bytes_received Total bytes received (all devices)
 * @param[out] a_packets_sent Total packets sent
 * @param[out] a_packets_received Total packets received
 * @return 0 on success, negative on error
 */
int dap_net_tun_get_stats(
    dap_net_tun_t *a_tun,
    uint64_t *a_bytes_sent,
    uint64_t *a_bytes_received,
    uint64_t *a_packets_sent,
    uint64_t *a_packets_received);

/**
 * @brief Get file descriptor for specific device (for integration with dap_events_socket)
 * 
 * @param a_tun TUN handle
 * @param a_device_index Device index
 * @return File descriptor or -1 on error
 */
int dap_net_tun_get_fd(dap_net_tun_t *a_tun, uint32_t a_device_index);

/**
 * @brief Get operation mode
 * 
 * @param a_tun TUN handle
 * @return Mode (CLIENT or SERVER)
 */
dap_net_tun_mode_t dap_net_tun_get_mode(dap_net_tun_t *a_tun);

#ifdef __cplusplus
}
#endif

