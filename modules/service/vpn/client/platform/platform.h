/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2021-2025
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Platform-specific network utility functions
 * 
 * These functions are implemented per-platform in:
 * - network_linux.c
 * - network_macos.c
 * - network_windows.c
 */

/**
 * @brief Get default gateway IP address (platform-specific)
 * @param a_out_gateway Output buffer for gateway IP
 * @param a_gateway_size Size of output buffer
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_platform_get_gateway(char *a_out_gateway, size_t a_gateway_size);

/**
 * @brief Get default network interface name (platform-specific)
 * @param a_out_interface Output buffer for interface name
 * @param a_interface_size Size of output buffer
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_platform_get_interface(char *a_out_interface, size_t a_interface_size);

/**
 * @brief Add host route for VPN server (platform-specific)
 * @param a_vpn_server_ip VPN server IP address
 * @param a_original_gateway Original default gateway
 * @param a_original_interface Original network interface (can be NULL)
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_platform_add_host_route(
    const char *a_vpn_server_ip,
    const char *a_original_gateway,
    const char *a_original_interface
);

#ifdef __cplusplus
}
#endif

