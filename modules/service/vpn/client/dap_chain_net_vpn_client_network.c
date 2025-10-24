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

#include "dap_chain_net_vpn_client_network.h"
#include "dap_chain_net_vpn_client_backup.h"
#include "dap_common.h"
#include "dap_strfuncs.h"

// Platform-specific API
#include "platform/platform.h"
#include "platform/network.h"

#define LOG_TAG "vpn_client_network"

int dap_chain_net_vpn_client_network_get_default_gateway(char *a_out_gateway, size_t a_gateway_size) {
    return dap_chain_net_vpn_client_network_platform_get_gateway(a_out_gateway, a_gateway_size);
}

int dap_chain_net_vpn_client_network_get_default_interface(char *a_out_interface, size_t a_interface_size) {
    return dap_chain_net_vpn_client_network_platform_get_interface(a_out_interface, a_interface_size);
}

int dap_chain_net_vpn_client_network_backup(
    const char *a_original_gateway,
    const char *a_original_interface,
    struct dap_chain_net_vpn_client_backup **a_out_backup
) {
    if (!a_out_backup) return -1;
    
    // Create new backup structure
    dap_chain_net_vpn_client_backup_t *l_backup = dap_chain_net_vpn_client_backup_new();
    if (!l_backup) {
        log_it(L_ERROR, "Failed to create backup structure");
        return -2;
    }
    
    // Populate original network configuration
    if (a_original_gateway) {
        l_backup->original_gateway = dap_strdup(a_original_gateway);
    }
    
    if (a_original_interface) {
        l_backup->original_interface = dap_strdup(a_original_interface);
    }
    
    // Platform-specific backup (collects DNS, determines VPN interface, etc.)
    if (dap_chain_net_vpn_client_network_platform_backup(&l_backup->platform_specific_backup) != 0) {
        log_it(L_ERROR, "Failed to backup platform-specific network configuration");
        dap_chain_net_vpn_client_backup_free(l_backup);
        return -3;
    }
    
    *a_out_backup = l_backup;
    log_it(L_INFO, "Network configuration backed up successfully");
    return 0;
}

int dap_chain_net_vpn_client_network_restore(struct dap_chain_net_vpn_client_backup *a_backup) {
    if (!a_backup) {
        log_it(L_DEBUG, "No backup to restore (NULL)");
        return 0;  // Nothing to restore
    }
    
    if (!a_backup->backup_valid) {
        log_it(L_WARNING, "Backup is marked as invalid, skipping restore");
        return -1;
    }
    
    log_it(L_INFO, "Restoring network configuration from backup");
    
    int l_ret = 0;
    
    // Platform-specific restore
    l_ret = dap_chain_net_vpn_client_network_platform_restore(a_backup->platform_specific_backup);
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to restore platform-specific network configuration (error %d)", l_ret);
        return l_ret;
    }
    
    log_it(L_INFO, "Network configuration restored successfully");
    return 0;
}

int dap_chain_net_vpn_client_network_resolve_hostname(
    const char *a_hostname,
    char *a_out_ip,
    size_t a_ip_size
) {
    return dap_chain_net_vpn_client_network_platform_resolve_hostname(a_hostname, a_out_ip, a_ip_size);
}

int dap_chain_net_vpn_client_network_add_host_route(
    const char *a_vpn_server_ip,
    const char *a_original_gateway,
    const char *a_original_interface
) {
    return dap_chain_net_vpn_client_network_platform_add_host_route(
        a_vpn_server_ip, a_original_gateway, a_original_interface);
}

int dap_chain_net_vpn_client_network_apply_routing(
    const char *a_vpn_server_ip,
    const char *a_vpn_gateway,
    const char *a_vpn_interface
) {
    if (!a_vpn_gateway || !a_vpn_interface) return -1;
    
    log_it(L_INFO, "Applying VPN routing: gateway=%s, interface=%s", a_vpn_gateway, a_vpn_interface);
    
    return dap_chain_net_vpn_client_network_platform_apply_routing(
        a_vpn_server_ip, a_vpn_gateway, a_vpn_interface);
}

int dap_chain_net_vpn_client_network_apply_dns(
    const char **a_dns_servers,
    size_t a_dns_count
) {
    if (!a_dns_servers || a_dns_count == 0) return -1;
    
    log_it(L_INFO, "Applying VPN DNS configuration (%zu servers)", a_dns_count);
    
    return dap_chain_net_vpn_client_network_platform_apply_dns(a_dns_servers, a_dns_count);
}

int dap_chain_net_vpn_client_network_get_public_ip(char **a_out_ip) {
    if (!a_out_ip) return -1;
    
    return dap_chain_net_vpn_client_network_platform_get_public_ip(a_out_ip);
}
