#include "../network.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

#define LOG_TAG "dap_chain_net_vpn_client_network_windows"

// Maximum buffer size for command output
#define MAX_CMD_OUTPUT 4096

typedef struct dap_chain_net_vpn_client_network_platform_backup {
    char *interface_name;         // Interface name (e.g., "Ethernet", "Wi-Fi")
    char *default_gateway;        // Default gateway IP
    char *dns_servers;            // Comma-separated DNS servers
    DWORD interface_index;        // Interface index
} dap_chain_net_vpn_client_network_platform_backup_t;

/**
 * Get active network interface name
 */
static char* get_active_interface_name(DWORD *a_out_index) {
    PMIB_IPFORWARDTABLE l_route_table = NULL;
    ULONG l_size = 0;
    
    if (GetIpForwardTable(NULL, &l_size, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        return NULL;
    }
    
    l_route_table = (PMIB_IPFORWARDTABLE)DAP_NEW_Z_SIZE(char, l_size);
    if (!l_route_table) return NULL;
    
    if (GetIpForwardTable(l_route_table, &l_size, FALSE) != NO_ERROR) {
        DAP_DELETE(l_route_table);
        return NULL;
    }
    
    // Find default route (destination 0.0.0.0)
    DWORD l_if_index = 0;
    for (DWORD i = 0; i < l_route_table->dwNumEntries; i++) {
        if (l_route_table->table[i].dwForwardDest == 0) {
            l_if_index = l_route_table->table[i].dwForwardIfIndex;
            break;
        }
    }
    
    DAP_DELETE(l_route_table);
    
    if (l_if_index == 0) return NULL;
    
    // Get interface name
    PMIB_IFTABLE l_if_table = NULL;
    l_size = 0;
    
    if (GetIfTable(NULL, &l_size, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        return NULL;
    }
    
    l_if_table = (PMIB_IFTABLE)DAP_NEW_Z_SIZE(char, l_size);
    if (!l_if_table) return NULL;
    
    if (GetIfTable(l_if_table, &l_size, FALSE) != NO_ERROR) {
        DAP_DELETE(l_if_table);
        return NULL;
    }
    
    char *l_name = NULL;
    for (DWORD i = 0; i < l_if_table->dwNumEntries; i++) {
        if (l_if_table->table[i].dwIndex == l_if_index) {
            l_name = dap_strdup((char*)l_if_table->table[i].bDescr);
            if (a_out_index) *a_out_index = l_if_index;
            break;
        }
    }
    
    DAP_DELETE(l_if_table);
    return l_name;
}

int dap_chain_net_vpn_client_network_platform_backup(void **a_out_backup) {
    if (!a_out_backup) return -1;
    
    dap_chain_net_vpn_client_network_platform_backup_t *l_backup = DAP_NEW_Z(dap_chain_net_vpn_client_network_platform_backup_t);
    if (!l_backup) {
        log_it(L_CRITICAL, "Failed to allocate backup structure");
        return -2;
    }
    
    log_it(L_INFO, "Backing up Windows network configuration...");
    
    // Get active interface
    l_backup->interface_name = get_active_interface_name(&l_backup->interface_index);
    if (!l_backup->interface_name) {
        log_it(L_WARNING, "Failed to determine active interface");
    }
    
    // Backup default gateway
    char *l_gw_output = NULL;
    exec_with_ret(&l_gw_output, "route print 0.0.0.0 | findstr 0.0.0.0");
    if (l_gw_output && strlen(l_gw_output) > 0) {
        // Parse gateway from route output
        char *l_parts[5] = {0};
        int l_count = 0;
        char *l_tok = strtok(l_gw_output, " \t");
        while (l_tok && l_count < 5) {
            if (strlen(l_tok) > 0) {
                l_parts[l_count++] = l_tok;
            }
            l_tok = strtok(NULL, " \t");
        }
        // Gateway is typically the 3rd field (index 2)
        if (l_count >= 3 && l_parts[2]) {
            l_backup->default_gateway = dap_strdup(l_parts[2]);
        }
    }
    DAP_DELETE(l_gw_output);
    
    // Backup DNS servers
    if (l_backup->interface_name) {
        char l_cmd[512];
        snprintf(l_cmd, sizeof(l_cmd), "netsh interface ipv4 show dns \"%s\" | findstr \"DNS\"", 
                 l_backup->interface_name);
        char *l_dns_output = NULL;
        exec_with_ret(&l_dns_output, l_cmd);
        if (l_dns_output && strlen(l_dns_output) > 0) {
            // Parse DNS servers (format: "    DNS servers configured through DHCP:  8.8.8.8")
            char l_dns_buf[512] = {0};
            size_t l_dns_offset = 0;
            char *l_line = l_dns_output;
            while (l_line && *l_line) {
                char *l_colon = strrchr(l_line, ':');
                if (l_colon) {
                    l_colon++;
                    while (*l_colon == ' ') l_colon++;
                    char *l_end = strchr(l_colon, '\r');
                    if (!l_end) l_end = strchr(l_colon, '\n');
                    size_t l_len = l_end ? (l_end - l_colon) : strlen(l_colon);
                    if (l_len > 0 && l_dns_offset + l_len + 2 < sizeof(l_dns_buf)) {
                        if (l_dns_offset > 0) l_dns_buf[l_dns_offset++] = ',';
                        memcpy(l_dns_buf + l_dns_offset, l_colon, l_len);
                        l_dns_offset += l_len;
                    }
                }
                l_line = strchr(l_line, '\n');
                if (l_line) l_line++;
            }
            if (l_dns_offset > 0) {
                l_dns_buf[l_dns_offset] = '\0';
                l_backup->dns_servers = dap_strdup(l_dns_buf);
            }
        }
        DAP_DELETE(l_dns_output);
    }
    
    log_it(L_INFO, "Windows network backup complete: interface=%s, gateway=%s, dns=%s",
           l_backup->interface_name ? l_backup->interface_name : "none",
           l_backup->default_gateway ? l_backup->default_gateway : "none",
           l_backup->dns_servers ? l_backup->dns_servers : "none");
    
    *a_out_backup = l_backup;
    return 0;
}

int dap_chain_net_vpn_client_network_platform_restore(void *a_backup) {
    if (!a_backup) return -1;
    
    dap_chain_net_vpn_client_network_platform_backup_t *l_backup = (dap_chain_net_vpn_client_network_platform_backup_t*)a_backup;
    
    log_it(L_INFO, "Restoring Windows network configuration...");
    
    int l_ret = 0;
    
    // Restore DNS servers
    if (l_backup->interface_name && l_backup->dns_servers) {
        char l_cmd[1024];
        snprintf(l_cmd, sizeof(l_cmd), "netsh interface ipv4 set dns \"%s\" static %s primary",
                 l_backup->interface_name, l_backup->dns_servers);
        char *l_output = NULL;
        exec_with_ret(&l_output, l_cmd);
        DAP_DELETE(l_output);
        log_it(L_INFO, "Restored DNS servers: %s", l_backup->dns_servers);
    } else if (l_backup->interface_name) {
        // Reset to DHCP
        char l_cmd[512];
        snprintf(l_cmd, sizeof(l_cmd), "netsh interface ipv4 set dns \"%s\" dhcp", l_backup->interface_name);
        char *l_output = NULL;
        exec_with_ret(&l_output, l_cmd);
        DAP_DELETE(l_output);
        log_it(L_INFO, "Reset DNS to DHCP");
    }
    
    // Restore default route
    if (l_backup->default_gateway) {
        char l_cmd[512];
        snprintf(l_cmd, sizeof(l_cmd), "route delete 0.0.0.0 & route add 0.0.0.0 mask 0.0.0.0 %s",
                 l_backup->default_gateway);
        char *l_output = NULL;
        exec_with_ret(&l_output, l_cmd);
        DAP_DELETE(l_output);
        log_it(L_INFO, "Restored default gateway: %s", l_backup->default_gateway);
    }
    
    // Cleanup backup structure
    DAP_DELETE(l_backup->interface_name);
    DAP_DELETE(l_backup->default_gateway);
    DAP_DELETE(l_backup->dns_servers);
    DAP_DELETE(l_backup);
    
    log_it(L_INFO, "Windows network restore complete (status: %d)", l_ret);
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
    char *l_gw_output = NULL;
    exec_with_ret(&l_gw_output, "route print 0.0.0.0 | findstr 0.0.0.0");
    char *l_orig_gw = NULL;
    if (l_gw_output && strlen(l_gw_output) > 0) {
        char *l_parts[5] = {0};
        int l_count = 0;
        char *l_tok = strtok(l_gw_output, " \t");
        while (l_tok && l_count < 5) {
            if (strlen(l_tok) > 0) l_parts[l_count++] = l_tok;
            l_tok = strtok(NULL, " \t");
        }
        if (l_count >= 3 && l_parts[2]) {
            l_orig_gw = dap_strdup(l_parts[2]);
        }
    }
    DAP_DELETE(l_gw_output);
    
    // Step 2: Add host route for VPN server (to avoid routing loop)
    if (l_orig_gw) {
        snprintf(l_cmd, sizeof(l_cmd), "route add %s mask 255.255.255.255 %s", 
                 a_vpn_server_ip, l_orig_gw);
        char *l_output = NULL;
        exec_with_ret(&l_output, l_cmd);
        DAP_DELETE(l_output);
        log_it(L_INFO, "Added host route: %s via %s", a_vpn_server_ip, l_orig_gw);
        DAP_DELETE(l_orig_gw);
    }
    
    // Step 3: Delete current default route
    char *l_del_output = NULL;
    exec_with_ret(&l_del_output, "route delete 0.0.0.0");
    DAP_DELETE(l_del_output);
    
    // Step 4: Add new default route through VPN
    if (a_vpn_gateway) {
        snprintf(l_cmd, sizeof(l_cmd), "route add 0.0.0.0 mask 0.0.0.0 %s metric 1", a_vpn_gateway);
    } else {
        // For TAP/TUN interfaces without explicit gateway, use the interface
        snprintf(l_cmd, sizeof(l_cmd), "route add 0.0.0.0 mask 0.0.0.0 10.8.0.1 metric 1");
    }
    
    char *l_route_output = NULL;
    exec_with_ret(&l_route_output, l_cmd);
    if (l_route_output && strstr(l_route_output, "OK") == NULL) {
        log_it(L_ERROR, "Failed to add VPN default route: %s", l_route_output);
        l_ret = -2;
    } else {
        log_it(L_INFO, "Added VPN default route");
    }
    DAP_DELETE(l_route_output);
    
    return l_ret;
}

int dap_chain_net_vpn_client_network_platform_apply_dns(const char **a_dns_servers, size_t a_dns_count) {
    if (!a_dns_servers || a_dns_count == 0) {
        log_it(L_ERROR, "Invalid DNS server list");
        return -1;
    }
    
    log_it(L_INFO, "Applying VPN DNS configuration (%zu servers)", a_dns_count);
    
    // Get active interface name
    char *l_if_name = get_active_interface_name(NULL);
    if (!l_if_name) {
        log_it(L_ERROR, "Failed to get active interface name");
        return -2;
    }
    
    // Set primary DNS
    char l_cmd[1024];
    snprintf(l_cmd, sizeof(l_cmd), "netsh interface ipv4 set dns \"%s\" static %s primary",
             l_if_name, a_dns_servers[0]);
    char *l_output = NULL;
    exec_with_ret(&l_output, l_cmd);
    DAP_DELETE(l_output);
    
    // Add secondary DNS servers
    for (size_t i = 1; i < a_dns_count && i < 8; i++) {
        snprintf(l_cmd, sizeof(l_cmd), "netsh interface ipv4 add dns \"%s\" %s index=%zu",
                 l_if_name, a_dns_servers[i], i + 1);
        l_output = NULL;
        exec_with_ret(&l_output, l_cmd);
        DAP_DELETE(l_output);
    }
    
    log_it(L_INFO, "DNS configuration applied successfully");
    DAP_DELETE(l_if_name);
    return 0;
}

int dap_chain_net_vpn_client_network_platform_get_public_ip(char **a_out_ip) {
    if (!a_out_ip) return -1;
    
    // Get IP from active interface
    DWORD l_if_index = 0;
    char *l_if_name = get_active_interface_name(&l_if_index);
    DAP_DELETE(l_if_name);
    
    if (l_if_index == 0) {
        *a_out_ip = dap_strdup("0.0.0.0");
        return -1;
    }
    
    // Get IP address table
    PMIB_IPADDRTABLE l_addr_table = NULL;
    ULONG l_size = 0;
    
    if (GetIpAddrTable(NULL, &l_size, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        *a_out_ip = dap_strdup("0.0.0.0");
        return -2;
    }
    
    l_addr_table = (PMIB_IPADDRTABLE)DAP_NEW_Z_SIZE(char, l_size);
    if (!l_addr_table) {
        *a_out_ip = dap_strdup("0.0.0.0");
        return -3;
    }
    
    if (GetIpAddrTable(l_addr_table, &l_size, FALSE) != NO_ERROR) {
        DAP_DELETE(l_addr_table);
        *a_out_ip = dap_strdup("0.0.0.0");
        return -4;
    }
    
    // Find IP for interface
    for (DWORD i = 0; i < l_addr_table->dwNumEntries; i++) {
        if (l_addr_table->table[i].dwIndex == l_if_index) {
            struct in_addr l_addr;
            l_addr.s_addr = l_addr_table->table[i].dwAddr;
            *a_out_ip = dap_strdup(inet_ntoa(l_addr));
            DAP_DELETE(l_addr_table);
            log_it(L_INFO, "Got public IP: %s", *a_out_ip);
            return 0;
        }
    }
    
    DAP_DELETE(l_addr_table);
    *a_out_ip = dap_strdup("0.0.0.0");
    log_it(L_WARNING, "Failed to determine public IP, using 0.0.0.0");
    return -5;
}
