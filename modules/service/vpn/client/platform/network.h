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
 * @brief Platform-agnostic network management functions
 * 
 * These functions handle routing, DNS, and network configuration
 * backup/restore for all platforms (Linux, Darwin/macOS/iOS, Windows, BSD).
 * 
 * Implementation is provided by platform-specific modules in:
 * - linux/network.c
 * - darwin/network.c
 * - windows/network.c
 * - bsd/network.c
 * 
 * CMake selects the appropriate implementation at compile time.
 */

/**
 * @brief Get default gateway IP address
 * @param a_out_gateway Output buffer for gateway IP (min 64 bytes)
 * @param a_gateway_size Size of output buffer
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_platform_get_gateway(char *a_out_gateway, size_t a_gateway_size);

/**
 * @brief Get default network interface name
 * @param a_out_interface Output buffer for interface name (min 64 bytes)
 * @param a_interface_size Size of output buffer
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_platform_get_interface(char *a_out_interface, size_t a_interface_size);

/**
 * @brief Resolve hostname to IP address
 * @param a_hostname Hostname to resolve
 * @param a_out_ip Output buffer for IP address (min INET6_ADDRSTRLEN bytes)
 * @param a_ip_size Size of output buffer
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_platform_resolve_hostname(
    const char *a_hostname,
    char *a_out_ip,
    size_t a_ip_size
);

/**
 * @brief Add host route for VPN server IP via original gateway
 * @param a_vpn_server_ip VPN server IP address
 * @param a_original_gateway Original default gateway
 * @param a_original_interface Original network interface (can be NULL on some platforms)
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_platform_add_host_route(
    const char *a_vpn_server_ip,
    const char *a_original_gateway,
    const char *a_original_interface
);

/**
 * @brief Backup platform-specific network configuration
 * @param a_out_backup Output pointer for platform-specific backup data
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_platform_backup(void **a_out_backup);

/**
 * @brief Restore platform-specific network configuration
 * @param a_backup Platform-specific backup data
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_platform_restore(void *a_backup);

/**
 * @brief Apply VPN routing configuration
 * @param a_vpn_server_ip VPN server IP (for host route, can be NULL)
 * @param a_vpn_gateway VPN gateway IP
 * @param a_vpn_interface VPN interface name
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_platform_apply_routing(
    const char *a_vpn_server_ip,
    const char *a_vpn_gateway,
    const char *a_vpn_interface
);

/**
 * @brief Apply VPN DNS configuration
 * @param a_dns_servers Array of DNS server IPs
 * @param a_dns_count Number of DNS servers
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_platform_apply_dns(
    const char **a_dns_servers,
    size_t a_dns_count
);

/**
 * @brief Get public IP address
 * @param a_out_ip Output pointer for IP string (allocated by function, must be freed by caller)
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_platform_get_public_ip(char **a_out_ip);

#ifdef __cplusplus
}
#endif

