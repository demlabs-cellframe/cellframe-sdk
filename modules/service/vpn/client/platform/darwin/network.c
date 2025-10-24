#include "network_macos.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LOG_TAG "dap_chain_net_vpn_client_network_macos"

// Maximum buffer size for command output
#define MAX_CMD_OUTPUT 4096

typedef struct dap_chain_net_vpn_client_network_platform_backup {
    char *network_service;        // Network service name (e.g., "Wi-Fi", "Ethernet")
    char *default_gateway;        // Default gateway IP
    char *dns_servers;            // Space-separated DNS servers
    char *search_domains;         // Space-separated search domains
} dap_chain_net_vpn_client_network_platform_backup_t;

/**
 * Get active network service name (e.g., "Wi-Fi", "Ethernet")
 * @return Service name or NULL on error
 */
static char* get_active_network_service() {
    // Get list of network services ordered by priority
    char *l_services = NULL;
    exec_with_ret(&l_services, "networksetup -listnetworkserviceorder | grep '(1)' | sed 's/.*) \\(.*\\)/\\1/'");
    if (l_services && strlen(l_services) > 0) {
        // Return first active service
        char *l_newline = strchr(l_services, '\n');
        if (l_newline) *l_newline = '\0';
        log_it(L_DEBUG, "Found network service via listnetworkserviceorder: %s", l_services);
        return l_services;
    }
    
    DAP_DELETE(l_services);
    
    // Fallback: try to get service from default route
    char *l_route_if = NULL;
    exec_with_ret(&l_route_if, "route -n get default | grep interface | awk '{print $2}'");
    if (l_route_if && strlen(l_route_if) > 0) {
        // Convert interface name to service name
        char l_cmd[256];
        snprintf(l_cmd, sizeof(l_cmd), "networksetup -listallhardwareports | grep -A 1 'Device: %s' | grep 'Hardware Port' | cut -d' ' -f3-", l_route_if);
        char *l_service = NULL;
        exec_with_ret(&l_service, l_cmd);
        DAP_DELETE(l_route_if);
        
        if (l_service && strlen(l_service) > 0) {
            log_it(L_DEBUG, "Found network service via route interface: %s", l_service);
            return l_service;
        }
        DAP_DELETE(l_service);
    }
    
    DAP_DELETE(l_route_if);
    
    // Cannot determine network service - system misconfiguration
    log_it(L_ERROR, "Failed to determine active network service. Possible issues:");
    log_it(L_ERROR, "  1. No active network connection");
    log_it(L_ERROR, "  2. No default route configured");
    log_it(L_ERROR, "  3. System network configuration corrupted");
    log_it(L_ERROR, "  4. NetworkManager/networksetup not working properly");
    return NULL;
}

int dap_chain_net_vpn_client_network_platform_backup(void **a_out_backup) {
    if (!a_out_backup) return -1;
    
    dap_chain_net_vpn_client_network_platform_backup_t *l_backup = DAP_NEW_Z(dap_chain_net_vpn_client_network_platform_backup_t);
    if (!l_backup) {
        log_it(L_CRITICAL, "Failed to allocate backup structure");
        return -2;
    }
    
    log_it(L_INFO, "Backing up macOS network configuration...");
    
    // Get active network service
    l_backup->network_service = get_active_network_service();
    if (!l_backup->network_service) {
        log_it(L_ERROR, "Failed to determine active network service");
        DAP_DELETE(l_backup);
        return -3;
    }
    
    // Backup default gateway
    char *l_gw_output = NULL;
    exec_with_ret(&l_gw_output, "route -n get default | grep gateway | awk '{print $2}'");
    if (l_gw_output && strlen(l_gw_output) > 0) {
        l_backup->default_gateway = l_gw_output;
    }
    
    // Backup DNS servers
    char l_dns_cmd[512];
    snprintf(l_dns_cmd, sizeof(l_dns_cmd), "networksetup -getdnsservers '%s'", l_backup->network_service);
    char *l_dns_output = NULL;
    exec_with_ret(&l_dns_output, l_dns_cmd);
    if (l_dns_output && strlen(l_dns_output) > 0 && strstr(l_dns_output, "There aren't any") == NULL) {
        // Convert newlines to spaces
        for (char *p = l_dns_output; *p; p++) {
            if (*p == '\n') *p = ' ';
        }
        l_backup->dns_servers = l_dns_output;
    } else {
        DAP_DELETE(l_dns_output);
    }
    
    // Backup search domains
    char l_search_cmd[512];
    snprintf(l_search_cmd, sizeof(l_search_cmd), "networksetup -getsearchdomains '%s'", l_backup->network_service);
    char *l_search_output = NULL;
    exec_with_ret(&l_search_output, l_search_cmd);
    if (l_search_output && strlen(l_search_output) > 0 && strstr(l_search_output, "There aren't any") == NULL) {
        // Convert newlines to spaces
        for (char *p = l_search_output; *p; p++) {
            if (*p == '\n') *p = ' ';
        }
        l_backup->search_domains = l_search_output;
    } else {
        DAP_DELETE(l_search_output);
    }
    
    log_it(L_INFO, "macOS network backup complete: service=%s, gateway=%s, dns=%s",
           l_backup->network_service,
           l_backup->default_gateway ? l_backup->default_gateway : "none",
           l_backup->dns_servers ? l_backup->dns_servers : "none");
    
    *a_out_backup = l_backup;
    return 0;
}

int dap_chain_net_vpn_client_network_platform_restore(void *a_backup) {
    if (!a_backup) return -1;
    
    dap_chain_net_vpn_client_network_platform_backup_t *l_backup = (dap_chain_net_vpn_client_network_platform_backup_t*)a_backup;
    
    log_it(L_INFO, "Restoring macOS network configuration...");
    
    int l_ret = 0;
    
    if (!l_backup->network_service) {
        log_it(L_ERROR, "No network service in backup");
        l_ret = -1;
        goto cleanup;
    }
    
    // Restore DNS servers
    if (l_backup->dns_servers) {
        char l_cmd[1024];
        snprintf(l_cmd, sizeof(l_cmd), "networksetup -setdnsservers '%s' %s",
                 l_backup->network_service, l_backup->dns_servers);
        char *l_output = NULL;
        exec_with_ret(&l_output, l_cmd);
        if (l_output) {
            if (strlen(l_output) > 0) {
                log_it(L_WARNING, "DNS restore output: %s", l_output);
            }
            DAP_DELETE(l_output);
        }
        log_it(L_INFO, "Restored DNS servers: %s", l_backup->dns_servers);
    } else {
        // Clear DNS (use DHCP)
        char l_cmd[512];
        snprintf(l_cmd, sizeof(l_cmd), "networksetup -setdnsservers '%s' empty", l_backup->network_service);
        char *l_output = NULL;
        exec_with_ret(&l_output, l_cmd);
        DAP_DELETE(l_output);
        log_it(L_INFO, "Cleared DNS servers (using DHCP)");
    }
    
    // Restore search domains
    if (l_backup->search_domains) {
        char l_cmd[1024];
        snprintf(l_cmd, sizeof(l_cmd), "networksetup -setsearchdomains '%s' %s",
                 l_backup->network_service, l_backup->search_domains);
        char *l_output = NULL;
        exec_with_ret(&l_output, l_cmd);
        DAP_DELETE(l_output);
        log_it(L_INFO, "Restored search domains: %s", l_backup->search_domains);
    } else {
        // Clear search domains
        char l_cmd[512];
        snprintf(l_cmd, sizeof(l_cmd), "networksetup -setsearchdomains '%s' empty", l_backup->network_service);
        char *l_output = NULL;
        exec_with_ret(&l_output, l_cmd);
        DAP_DELETE(l_output);
    }
    
    // Restore default route (if needed)
    if (l_backup->default_gateway) {
        char l_cmd[512];
        snprintf(l_cmd, sizeof(l_cmd), "route delete default 2>/dev/null; route add default %s",
                 l_backup->default_gateway);
        char *l_output = NULL;
        exec_with_ret(&l_output, l_cmd);
        DAP_DELETE(l_output);
        log_it(L_INFO, "Restored default gateway: %s", l_backup->default_gateway);
    }
    
cleanup:
    // Cleanup backup structure
    DAP_DELETE(l_backup->network_service);
    DAP_DELETE(l_backup->default_gateway);
    DAP_DELETE(l_backup->dns_servers);
    DAP_DELETE(l_backup->search_domains);
    DAP_DELETE(l_backup);
    
    log_it(L_INFO, "macOS network restore complete (status: %d)", l_ret);
    return l_ret;
}

int dap_chain_net_vpn_client_network_platform_apply_routing(const char *a_vpn_server_ip,
                                                         const char *a_vpn_interface,
                                                         const char *a_vpn_gateway) {
    if (!a_vpn_server_ip || !a_vpn_interface) {
        log_it(L_ERROR, "Invalid arguments for apply_routing");
        return -1;
    }
    
    log_it(L_INFO, "Applying VPN routing: server=%s, interface=%s, gateway=%s",
           a_vpn_server_ip, a_vpn_interface, a_vpn_gateway ? a_vpn_gateway : "auto");
    
    char l_cmd[512];
    int l_ret = 0;
    
    // Step 1: Get current default gateway for host route
    char *l_orig_gw = NULL;
    exec_with_ret(&l_orig_gw, "route -n get default | grep gateway | awk '{print $2}'");
    
    // Step 2: Add host route for VPN server (to avoid routing loop)
    if (l_orig_gw && strlen(l_orig_gw) > 0) {
        snprintf(l_cmd, sizeof(l_cmd), "route add -host %s %s 2>/dev/null", 
                 a_vpn_server_ip, l_orig_gw);
        char *l_output = NULL;
        exec_with_ret(&l_output, l_cmd);
        if (l_output) {
            if (strlen(l_output) > 0 && strstr(l_output, "File exists") == NULL) {
                log_it(L_WARNING, "Host route add output: %s", l_output);
            }
            DAP_DELETE(l_output);
        }
        log_it(L_INFO, "Added host route: %s via %s", a_vpn_server_ip, l_orig_gw);
    }
    DAP_DELETE(l_orig_gw);
    
    // Step 3: Delete current default route
    char *l_del_output = NULL;
    exec_with_ret(&l_del_output, "route delete default 2>/dev/null");
    DAP_DELETE(l_del_output);
    
    // Step 4: Add new default route through VPN
    if (a_vpn_gateway) {
        snprintf(l_cmd, sizeof(l_cmd), "route add -net default %s -interface %s",
                 a_vpn_gateway, a_vpn_interface);
    } else {
        snprintf(l_cmd, sizeof(l_cmd), "route add -net default -interface %s",
                 a_vpn_interface);
    }
    
    char *l_route_output = NULL;
    exec_with_ret(&l_route_output, l_cmd);
    if (l_route_output) {
        if (strlen(l_route_output) > 0 && strstr(l_route_output, "add net default") == NULL) {
            log_it(L_ERROR, "Failed to add VPN default route: %s", l_route_output);
            l_ret = -2;
        } else {
            log_it(L_INFO, "Added VPN default route via %s", a_vpn_interface);
        }
        DAP_DELETE(l_route_output);
    }
    
    return l_ret;
}

int dap_chain_net_vpn_client_network_platform_apply_dns(const char **a_dns_servers, size_t a_dns_count) {
    if (!a_dns_servers || a_dns_count == 0) {
        log_it(L_ERROR, "Invalid DNS server list");
        return -1;
    }
    
    log_it(L_INFO, "Applying VPN DNS configuration (%zu servers)", a_dns_count);
    
    // Get active network service
    char *l_service = get_active_network_service();
    if (!l_service) {
        log_it(L_ERROR, "Failed to get active network service");
        return -2;
    }
    
    // Build DNS server list (space-separated)
    char l_dns_list[512] = {0};
    size_t l_offset = 0;
    for (size_t i = 0; i < a_dns_count && i < 8; i++) {
        int l_written = snprintf(l_dns_list + l_offset, sizeof(l_dns_list) - l_offset,
                                 "%s%s", i > 0 ? " " : "", a_dns_servers[i]);
        if (l_written < 0 || l_written >= (int)(sizeof(l_dns_list) - l_offset)) {
            break;
        }
        l_offset += l_written;
    }
    
    // Apply DNS via networksetup
    char l_cmd[1024];
    snprintf(l_cmd, sizeof(l_cmd), "networksetup -setdnsservers '%s' %s", l_service, l_dns_list);
    char *l_output = NULL;
    exec_with_ret(&l_output, l_cmd);
    
    int l_ret = 0;
    if (l_output && strlen(l_output) > 0) {
        log_it(L_WARNING, "DNS apply output: %s", l_output);
        l_ret = -3;
    } else {
        log_it(L_INFO, "DNS configuration applied: %s", l_dns_list);
    }
    
    DAP_DELETE(l_output);
    DAP_DELETE(l_service);
    return l_ret;
}

int dap_chain_net_vpn_client_network_platform_get_public_ip(char **a_out_ip) {
    if (!a_out_ip) return -1;
    
    // Get IP from default interface
    char *l_if_output = NULL;
    exec_with_ret(&l_if_output, "route -n get default | grep interface | awk '{print $2}'");
    if (!l_if_output || strlen(l_if_output) == 0) {
        DAP_DELETE(l_if_output);
        *a_out_ip = dap_strdup("0.0.0.0");
        return -1;
    }
    
    char l_cmd[256];
    snprintf(l_cmd, sizeof(l_cmd), "ifconfig %s | grep 'inet ' | awk '{print $2}' | head -1", l_if_output);
    DAP_DELETE(l_if_output);
    
    char *l_ip_output = NULL;
    exec_with_ret(&l_ip_output, l_cmd);
    if (l_ip_output && strlen(l_ip_output) > 0) {
        *a_out_ip = l_ip_output;
        log_it(L_INFO, "Got public IP: %s", *a_out_ip);
        return 0;
    }
    
    DAP_DELETE(l_ip_output);
    *a_out_ip = dap_strdup("0.0.0.0");
    log_it(L_WARNING, "Failed to determine public IP, using 0.0.0.0");
    return -2;
}
