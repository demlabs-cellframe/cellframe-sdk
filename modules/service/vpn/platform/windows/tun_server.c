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

#include "dap_common.h"
#include "dap_config.h"
#include "../tun_server.h"

#define LOG_TAG "tun_server_windows"

/**
 * @brief Initialize TUN device (Windows stub - WinTun/TAP-Windows implementation needed)
 * @param a_config Configuration
 * @return -1 (not implemented)
 */
int dap_tun_server_init(dap_config_t *a_config)
{
    (void)a_config;
    log_it(L_ERROR, "Windows TUN server not implemented yet. Use WinTun or TAP-Windows driver.");
    return -1;
}

/**
 * @brief Deinitialize TUN device
 */
void dap_tun_server_deinit(void)
{
    // Stub
}

/**
 * @brief Get TUN device name
 * @return NULL (not implemented)
 */
const char* dap_tun_server_get_device_name(void)
{
    return NULL;
}

/**
 * @brief Get TUN device file descriptor
 * @param a_worker_id Worker ID
 * @return -1 (not implemented)
 */
int dap_tun_server_get_fd(uint32_t a_worker_id)
{
    (void)a_worker_id;
    return -1;
}

/**
 * @brief Get number of TUN sockets
 * @return 0 (not implemented)
 */
uint32_t dap_tun_server_get_socket_count(void)
{
    return 0;
}

/**
 * @brief Get TUN socket for specific worker
 * @param a_worker_id Worker ID
 * @return NULL (not implemented)
 */
struct dap_chain_net_srv_vpn_tun_socket* dap_tun_server_get_socket(uint32_t a_worker_id)
{
    (void)a_worker_id;
    return NULL;
}

/**
 * @brief Get message queue socket for specific worker
 * @param a_worker_id Worker ID
 * @return NULL (not implemented)
 */
dap_events_socket_t* dap_tun_server_get_queue_socket(uint32_t a_worker_id)
{
    (void)a_worker_id;
    return NULL;
}

