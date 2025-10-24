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

#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Execute shell command with output capture
 * @param a_command Command to execute
 * @param a_output Buffer for output (can be NULL)
 * @param a_output_size Output buffer size
 * @return Exit code or negative on error
 */
int dap_tun_unix_exec_with_output(
    const char *a_command,
    char *a_output,
    size_t a_output_size);

/**
 * @brief Set interface UP or DOWN
 * @param a_ifname Interface name
 * @param a_up true for UP, false for DOWN
 * @return 0 on success, negative on error
 */
int dap_tun_unix_set_interface_state(const char *a_ifname, bool a_up);

/**
 * @brief Configure interface IP address
 * @param a_ifname Interface name
 * @param a_addr IP address
 * @param a_mask Network mask
 * @return 0 on success, negative on error
 */
int dap_tun_unix_configure_address(
    const char *a_ifname,
    struct in_addr a_addr,
    struct in_addr a_mask);

/**
 * @brief Add route
 * @param a_dest Destination network
 * @param a_mask Network mask
 * @param a_gateway Gateway address (can be NULL for interface route)
 * @param a_ifname Interface name (can be NULL if gateway is provided)
 * @return 0 on success, negative on error
 */
int dap_tun_unix_add_route(
    struct in_addr a_dest,
    struct in_addr a_mask,
    struct in_addr *a_gateway,
    const char *a_ifname);

/**
 * @brief Delete route
 * @param a_dest Destination network
 * @param a_mask Network mask
 * @return 0 on success, negative on error
 */
int dap_tun_unix_delete_route(
    struct in_addr a_dest,
    struct in_addr a_mask);

/**
 * @brief Get default gateway
 * @param a_gateway Output: default gateway address
 * @return 0 on success, negative on error
 */
int dap_tun_unix_get_default_gateway(struct in_addr *a_gateway);

/**
 * @brief Set MTU for interface
 * @param a_ifname Interface name
 * @param a_mtu MTU value
 * @return 0 on success, negative on error
 */
int dap_tun_unix_set_mtu(const char *a_ifname, uint32_t a_mtu);

#ifdef __cplusplus
}
#endif

