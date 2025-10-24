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

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "dap_worker.h"
#include "dap_events_socket.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief TUN device configuration
 */
typedef struct dap_tun_device_config {
    struct in_addr network_addr;    // Network address
    struct in_addr network_mask;    // Network mask
    struct in_addr gateway_addr;    // Gateway address
    char *device_name;              // Device name (e.g., "tun0", "utun0")
    bool multiqueue;                // Enable multi-queue (Linux)
    bool auto_cpu_reassignment;     // Enable automatic CPU reassignment
    uint32_t queue_count;           // Number of queues (for multi-queue)
} dap_tun_device_config_t;

/**
 * @brief TUN device handle
 * Platform-specific implementation is opaque
 */
typedef struct dap_tun_device dap_tun_device_t;

/**
 * @brief TUN device callbacks
 */
typedef struct dap_tun_device_callbacks {
    void (*on_data_received)(dap_tun_device_t *a_device, const void *a_data, size_t a_data_size, void *a_context);
    void (*on_error)(dap_tun_device_t *a_device, int a_error_code, void *a_context);
    void (*on_ready)(dap_tun_device_t *a_device, void *a_context);
} dap_tun_device_callbacks_t;

/**
 * @brief Create TUN device
 * @param a_config Device configuration
 * @param a_callbacks Callbacks for device events
 * @param a_context User context for callbacks
 * @return TUN device handle or NULL on error
 */
dap_tun_device_t* dap_tun_device_create(
    const dap_tun_device_config_t *a_config,
    const dap_tun_device_callbacks_t *a_callbacks,
    void *a_context);

/**
 * @brief Destroy TUN device
 * @param a_device TUN device handle
 */
void dap_tun_device_destroy(dap_tun_device_t *a_device);

/**
 * @brief Get TUN device file descriptor
 * @param a_device TUN device handle
 * @param a_queue_index Queue index (for multi-queue), 0 for single queue
 * @return File descriptor or -1 on error
 */
int dap_tun_device_get_fd(dap_tun_device_t *a_device, uint32_t a_queue_index);

/**
 * @brief Get TUN device name
 * @param a_device TUN device handle
 * @return Device name or NULL on error
 */
const char* dap_tun_device_get_name(dap_tun_device_t *a_device);

/**
 * @brief Write data to TUN device
 * @param a_device TUN device handle
 * @param a_data Data to write
 * @param a_data_size Data size
 * @return Number of bytes written or -1 on error
 */
ssize_t dap_tun_device_write(dap_tun_device_t *a_device, const void *a_data, size_t a_data_size);

/**
 * @brief Read data from TUN device
 * @param a_device TUN device handle
 * @param a_buffer Buffer to read into
 * @param a_buffer_size Buffer size
 * @return Number of bytes read or -1 on error
 */
ssize_t dap_tun_device_read(dap_tun_device_t *a_device, void *a_buffer, size_t a_buffer_size);

/**
 * @brief Set TUN device UP
 * @param a_device TUN device handle
 * @return 0 on success, negative on error
 */
int dap_tun_device_up(dap_tun_device_t *a_device);

/**
 * @brief Set TUN device DOWN
 * @param a_device TUN device handle
 * @return 0 on success, negative on error
 */
int dap_tun_device_down(dap_tun_device_t *a_device);

/**
 * @brief Configure TUN device address
 * @param a_device TUN device handle
 * @param a_addr IP address
 * @param a_mask Network mask
 * @return 0 on success, negative on error
 */
int dap_tun_device_configure_address(
    dap_tun_device_t *a_device,
    struct in_addr a_addr,
    struct in_addr a_mask);

/**
 * @brief Add route to TUN device
 * @param a_device TUN device handle
 * @param a_dest Destination network
 * @param a_mask Network mask
 * @param a_gateway Gateway address
 * @return 0 on success, negative on error
 */
int dap_tun_device_add_route(
    dap_tun_device_t *a_device,
    struct in_addr a_dest,
    struct in_addr a_mask,
    struct in_addr a_gateway);

/**
 * @brief Delete route from TUN device
 * @param a_device TUN device handle
 * @param a_dest Destination network
 * @param a_mask Network mask
 * @return 0 on success, negative on error
 */
int dap_tun_device_delete_route(
    dap_tun_device_t *a_device,
    struct in_addr a_dest,
    struct in_addr a_mask);

/**
 * @brief Get TUN device statistics
 * @param a_device TUN device handle
 * @param a_bytes_sent Output: bytes sent
 * @param a_bytes_received Output: bytes received
 * @param a_packets_sent Output: packets sent
 * @param a_packets_received Output: packets received
 * @return 0 on success, negative on error
 */
int dap_tun_device_get_stats(
    dap_tun_device_t *a_device,
    uint64_t *a_bytes_sent,
    uint64_t *a_bytes_received,
    uint64_t *a_packets_sent,
    uint64_t *a_packets_received);

#ifdef __cplusplus
}
#endif

