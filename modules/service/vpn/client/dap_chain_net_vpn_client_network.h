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
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Platform-independent network management API for VPN client
 * 
 * This header provides a unified interface for network configuration
 * across Linux, macOS, and Windows platforms. The implementation
 * automatically selects the correct platform-specific backend at compile time.
 */

// Forward declaration - use dap_chain_net_vpn_client_backup API for network backup
struct dap_chain_net_vpn_client_backup;

/**
 * @brief Get default gateway IP address
 * @param a_out_gateway Output buffer for gateway IP (min 46 bytes for IPv6)
 * @param a_gateway_size Size of output buffer
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_get_default_gateway(char *a_out_gateway, size_t a_gateway_size);

/**
 * @brief Get default network interface name
 * @param a_out_interface Output buffer for interface name (min 16 bytes)
 * @param a_interface_size Size of output buffer
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_get_default_interface(char *a_out_interface, size_t a_interface_size);

/**
 * @brief Backup current network configuration
 * @param a_original_gateway Original gateway IP
 * @param a_original_interface Original interface name
 * @param a_vpn_interface VPN interface name
 * @param a_dns_servers DNS servers array (optional)
 * @param a_dns_count Number of DNS servers
 * @param a_out_backup Output backup handle (must be freed with dap_chain_net_vpn_client_backup_free)
 * @return 0 on success, negative on error
 * @note This function populates the network fields in the backup structure.
 *       Use dap_chain_net_vpn_client_backup_save() to persist to file.
 */
/**
 * @brief Backup current network configuration before VPN connection
 * @param a_original_gateway Original default gateway IP
 * @param a_original_interface Original default network interface
 * @param a_out_backup Output pointer for backup structure
 * @return 0 on success, -1 on error
 * @note Platform-specific code determines VPN interface name and collects DNS settings
 */
int dap_chain_net_vpn_client_network_backup(
    const char *a_original_gateway,
    const char *a_original_interface,
    struct dap_chain_net_vpn_client_backup **a_out_backup
);

/**
 * @brief Restore network configuration from backup
 * @param a_backup Backup handle (can be NULL to skip restore)
 * @return 0 on success, negative on error
 * @note This function reads the network fields from the backup structure.
 *       The backup structure should have been loaded via dap_chain_net_vpn_client_backup_load().
 */
int dap_chain_net_vpn_client_network_restore(struct dap_chain_net_vpn_client_backup *a_backup);

/**
 * @brief Resolve hostname to IP address
 * @param a_hostname Hostname to resolve
 * @param a_out_ip Output buffer for IP address (min 46 bytes)
 * @param a_ip_size Size of output buffer
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_resolve_hostname(
    const char *a_hostname,
    char *a_out_ip,
    size_t a_ip_size
);

/**
 * @brief Add host route for VPN server IP via original gateway
 * @param a_vpn_server_ip VPN server IP address
 * @param a_original_gateway Original default gateway
 * @param a_original_interface Original network interface
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_add_host_route(
    const char *a_vpn_server_ip,
    const char *a_original_gateway,
    const char *a_original_interface
);

/**
 * @brief Apply VPN routing (set default route through VPN interface)
 * @param a_vpn_server_ip VPN server IP (for verification)
 * @param a_vpn_gateway VPN gateway IP (usually VPN server IP or tunnel endpoint)
 * @param a_vpn_interface VPN interface name (e.g., "tun0")
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_apply_routing(
    const char *a_vpn_server_ip,
    const char *a_vpn_gateway,
    const char *a_vpn_interface
);

/**
 * @brief Apply DNS configuration for VPN
 * @param a_dns_servers Array of DNS server IPs
 * @param a_dns_count Number of DNS servers
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_apply_dns(
    const char **a_dns_servers,
    size_t a_dns_count
);

/**
 * @brief Get public IP address (for connectivity testing)
 * @param a_out_ip Output buffer for IP address (allocated by function, must be freed by caller)
 * @return 0 on success, negative on error
 * @note Caller must free *a_out_ip with DAP_DELETE()
 */
int dap_chain_net_vpn_client_network_get_public_ip(char **a_out_ip);

#ifdef __cplusplus
}
#endif
