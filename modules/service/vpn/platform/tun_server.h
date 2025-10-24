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
#include <netinet/in.h>
#include "dap_worker.h"
#include "dap_events_socket.h"
#include "dap_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Server TUN configuration
 */
typedef struct dap_tun_server_config {
    struct in_addr network_addr;     // Network address
    struct in_addr network_mask;     // Network mask
    struct in_addr gateway_addr;     // Gateway address
    bool auto_cpu_reassignment;      // Enable automatic CPU reassignment
} dap_tun_server_config_t;

/**
 * @brief Server TUN handle (opaque)
 */
typedef struct dap_tun_server dap_tun_server_t;

/**
 * @brief Initialize server TUN device
 * @param a_config TUN configuration
 * @return 0 on success, negative on error
 */
int dap_tun_server_init(dap_config_t *a_config);

/**
 * @brief Deinitialize server TUN device
 */
void dap_tun_server_deinit(void);

/**
 * @brief Get TUN device name
 * @return Device name or NULL
 */
const char* dap_tun_server_get_device_name(void);

/**
 * @brief Get TUN device file descriptor for specific worker
 * @param a_worker_id Worker ID
 * @return File descriptor or -1 on error
 */
int dap_tun_server_get_fd(uint32_t a_worker_id);

/**
 * @brief Get number of TUN sockets (workers)
 * @return Number of TUN sockets
 */
uint32_t dap_tun_server_get_socket_count(void);

/**
 * @brief Get TUN socket for specific worker
 * @param a_worker_id Worker ID
 * @return TUN socket or NULL
 */
struct dap_chain_net_srv_vpn_tun_socket* dap_tun_server_get_socket(uint32_t a_worker_id);

/**
 * @brief Get message queue socket for specific worker
 * @param a_worker_id Worker ID
 * @return Queue socket or NULL
 */
dap_events_socket_t* dap_tun_server_get_queue_socket(uint32_t a_worker_id);

#ifdef __cplusplus
}
#endif

