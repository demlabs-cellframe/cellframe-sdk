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

#include "network_bsd.h"
#include "dap_common.h"
#include <string.h>

#define LOG_TAG "vpn_network_bsd"

typedef struct dap_vpn_bsd_backup {
    char *resolv_conf_backup;    // /etc/resolv.conf content
    char *default_route_backup;  // Default route info
} dap_vpn_bsd_backup_t;

int dap_chain_net_vpn_client_network_platform_backup(void **a_out_backup) {
    if (!a_out_backup) return -1;
    
    dap_vpn_bsd_backup_t *l_backup = DAP_NEW_Z(dap_vpn_bsd_backup_t);
    if (!l_backup) {
        log_it(L_ERROR, "Failed to allocate BSD backup structure");
        return -2;
    }
    
    // Backup /etc/resolv.conf
    char *l_result = NULL;
    int l_ret = exec_with_ret(&l_result, "cat /etc/resolv.conf 2>&1");
    if (l_ret == 0 && l_result) {
        l_backup->resolv_conf_backup = l_result;
        log_it(L_DEBUG, "Backed up /etc/resolv.conf");
    } else {
        log_it(L_WARNING, "Failed to backup /etc/resolv.conf");
        DAP_DEL_Z(l_result);
    }
    
    // Backup default route
    l_result = NULL;
    l_ret = exec_with_ret(&l_result, "route -n get default 2>&1");
    if (l_ret == 0 && l_result) {
        l_backup->default_route_backup = l_result;
        log_it(L_DEBUG, "Backed up default route");
    } else {
        log_it(L_WARNING, "Failed to backup default route");
        DAP_DEL_Z(l_result);
    }
    
    *a_out_backup = l_backup;
    log_it(L_INFO, "BSD network configuration backup completed");
    return 0;
}

int dap_chain_net_vpn_client_network_platform_restore(void *a_backup) {
    if (!a_backup) {
        log_it(L_DEBUG, "No BSD backup to restore");
        return 0;
    }
    
    dap_vpn_bsd_backup_t *l_backup = (dap_vpn_bsd_backup_t *)a_backup;
    
    // Restore /etc/resolv.conf
    if (l_backup->resolv_conf_backup) {
        // Write backup content to /etc/resolv.conf
        char l_cmd[4096];
        snprintf(l_cmd, sizeof(l_cmd), "echo '%s' > /etc/resolv.conf 2>&1", 
                 l_backup->resolv_conf_backup);
        
        char *l_result = NULL;
        int l_ret = exec_with_ret(&l_result, l_cmd);
        if (l_ret != 0) {
            log_it(L_ERROR, "Failed to restore /etc/resolv.conf: %s", 
                   l_result ? l_result : "no output");
        } else {
            log_it(L_INFO, "Restored /etc/resolv.conf");
        }
        DAP_DEL_Z(l_result);
    }
    
    // Note: Default route restoration is complex and depends on specific configuration
    // Usually handled by the routing functions in the state machine
    
    // Free backup structure
    DAP_DEL_Z(l_backup->resolv_conf_backup);
    DAP_DEL_Z(l_backup->default_route_backup);
    DAP_DELETE(l_backup);
    
    log_it(L_INFO, "BSD network configuration restore completed");
    return 0;
}

int dap_chain_net_vpn_client_network_platform_apply_routing(
    const char *a_vpn_server_ip,
    const char *a_vpn_gateway,
    const char *a_vpn_interface
) {
    if (!a_vpn_gateway || !a_vpn_interface) return -1;
    
    log_it(L_INFO, "Applying BSD VPN routing: gateway=%s, interface=%s", 
           a_vpn_gateway, a_vpn_interface);
    
    // Delete default route
    char *l_result = NULL;
    int l_ret = exec_with_ret(&l_result, "route delete default 2>&1");
    if (l_ret != 0) {
        log_it(L_WARNING, "Failed to delete default route: %s", 
               l_result ? l_result : "no output");
    }
    DAP_DEL_Z(l_result);
    
    // Add new default route through VPN
    char l_cmd[512];
    snprintf(l_cmd, sizeof(l_cmd), "route add default %s 2>&1", a_vpn_gateway);
    
    l_ret = exec_with_ret(&l_result, l_cmd);
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to add VPN default route: %s", 
               l_result ? l_result : "no output");
        DAP_DEL_Z(l_result);
        return -2;
    }
    DAP_DEL_Z(l_result);
    
    log_it(L_INFO, "BSD VPN routing applied successfully");
    return 0;
}

int dap_chain_net_vpn_client_network_platform_apply_dns(
    const char **a_dns_servers,
    size_t a_dns_count
) {
    if (!a_dns_servers || a_dns_count == 0) return -1;
    
    log_it(L_INFO, "Applying BSD VPN DNS configuration");
    
    // Build new /etc/resolv.conf content
    char l_resolv_content[2048] = "# Generated by Cellframe VPN Client\n";
    for (size_t i = 0; i < a_dns_count; i++) {
        char l_line[128];
        snprintf(l_line, sizeof(l_line), "nameserver %s\n", a_dns_servers[i]);
        strncat(l_resolv_content, l_line, sizeof(l_resolv_content) - strlen(l_resolv_content) - 1);
    }
    
    // Write to /etc/resolv.conf
    char l_cmd[4096];
    snprintf(l_cmd, sizeof(l_cmd), "echo '%s' > /etc/resolv.conf 2>&1", l_resolv_content);
    
    char *l_result = NULL;
    int l_ret = exec_with_ret(&l_result, l_cmd);
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to update /etc/resolv.conf: %s", 
               l_result ? l_result : "no output");
        DAP_DEL_Z(l_result);
        return -2;
    }
    DAP_DEL_Z(l_result);
    
    log_it(L_INFO, "BSD VPN DNS configuration applied successfully");
    return 0;
}

int dap_chain_net_vpn_client_network_platform_get_public_ip(char **a_out_ip) {
    if (!a_out_ip) return -1;
    
    // Try curl first
    char *l_result = NULL;
    int l_ret = exec_with_ret(&l_result, "curl -s -4 ifconfig.me 2>/dev/null");
    
    if (l_ret == 0 && l_result && l_result[0]) {
        *a_out_ip = l_result;
        log_it(L_DEBUG, "Public IP (curl): %s", *a_out_ip);
        return 0;
    }
    DAP_DEL_Z(l_result);
    
    // Try wget as fallback
    l_ret = exec_with_ret(&l_result, "wget -qO- -4 ifconfig.me 2>/dev/null");
    if (l_ret == 0 && l_result && l_result[0]) {
        *a_out_ip = l_result;
        log_it(L_DEBUG, "Public IP (wget): %s", *a_out_ip);
        return 0;
    }
    DAP_DEL_Z(l_result);
    
    log_it(L_ERROR, "Failed to get public IP address");
    return -2;
}

