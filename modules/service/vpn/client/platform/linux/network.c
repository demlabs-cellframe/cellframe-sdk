#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <netdb.h>

#include "../network.h"
#include "../unix/network_common.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"

#define LOG_TAG "dap_chain_net_vpn_client_network_linux"

// Maximum buffer size for command output
#define MAX_CMD_OUTPUT 4096

typedef struct dap_chain_net_vpn_client_network_platform_backup {
    char *default_gateway;       // Gateway IP
    char *default_interface;     // Interface name (e.g., eth0, wlan0)
    char *default_metric;        // Route metric
    char *dns_servers;           // Space-separated DNS servers
    char *dns_search_domains;    // Space-separated search domains
    char *original_resolv_conf;  // Full content of /etc/resolv.conf
} dap_chain_net_vpn_client_network_platform_backup_t;



/**
 * Write content to file
 */
static int write_file_content(const char *a_path, const char *a_content) {
    if (!a_path || !a_content) return -1;
    
    FILE *l_file = fopen(a_path, "w");
    if (!l_file) {
        log_it(L_ERROR, "Failed to open file for writing: %s", a_path);
        return -1;
    }
    
    size_t l_len = strlen(a_content);
    size_t l_written = fwrite(a_content, 1, l_len, l_file);
    fclose(l_file);
    
    if (l_written != l_len) {
        log_it(L_ERROR, "Failed to write complete content to: %s", a_path);
        return -2;
    }
    
    return 0;
}

int dap_chain_net_vpn_client_network_platform_backup(void **a_out_backup) {
    if (!a_out_backup) return -1;
    
    dap_chain_net_vpn_client_network_platform_backup_t *l_backup = DAP_NEW_Z(dap_chain_net_vpn_client_network_platform_backup_t);
    if (!l_backup) {
        log_it(L_CRITICAL, "Failed to allocate backup structure");
        return -2;
    }
    
    log_it(L_INFO, "Backing up Linux network configuration...");
    
    // Backup default gateway and interface
    // Parse: "ip route show default" output: "default via 192.168.1.1 dev eth0 metric 100"
    char *l_route_output = NULL;
    exec_with_ret(&l_route_output, "ip route show default");
    if (l_route_output && strlen(l_route_output) > 0) {
        // Parse gateway
        char *l_via = strstr(l_route_output, "via ");
        if (l_via) {
            l_via += 4; // Skip "via "
            char *l_space = strchr(l_via, ' ');
            if (l_space) {
                size_t l_len = l_space - l_via;
                l_backup->default_gateway = DAP_NEW_Z_SIZE(char, l_len + 1);
                memcpy(l_backup->default_gateway, l_via, l_len);
                l_backup->default_gateway[l_len] = '\0';
            }
        }
        
        // Parse interface
        char *l_dev = strstr(l_route_output, "dev ");
        if (l_dev) {
            l_dev += 4; // Skip "dev "
            char *l_space = strchr(l_dev, ' ');
            size_t l_len = l_space ? (size_t)(l_space - l_dev) : strlen(l_dev);
            l_backup->default_interface = DAP_NEW_Z_SIZE(char, l_len + 1);
            memcpy(l_backup->default_interface, l_dev, l_len);
            l_backup->default_interface[l_len] = '\0';
        }
        
        // Parse metric
        char *l_metric = strstr(l_route_output, "metric ");
        if (l_metric) {
            l_metric += 7; // Skip "metric "
            char *l_space = strchr(l_metric, ' ');
            size_t l_len = l_space ? (size_t)(l_space - l_metric) : strlen(l_metric);
            l_backup->default_metric = DAP_NEW_Z_SIZE(char, l_len + 1);
            memcpy(l_backup->default_metric, l_metric, l_len);
            l_backup->default_metric[l_len] = '\0';
        }
        
        DAP_DELETE(l_route_output);
    }
    
    // Backup /etc/resolv.conf
    size_t l_resolv_size = 0;
    l_backup->original_resolv_conf = dap_file_get_contents2("/etc/resolv.conf", &l_resolv_size);
    
    // Parse DNS servers and search domains from resolv.conf
    if (l_backup->original_resolv_conf) {
        char *l_line = l_backup->original_resolv_conf;
        char l_dns_buf[256] = {0};
        char l_search_buf[256] = {0};
        size_t l_dns_offset = 0;
        size_t l_search_offset = 0;
        
        while (l_line && *l_line) {
            if (strncmp(l_line, "nameserver ", 11) == 0) {
                char *l_ip = l_line + 11;
                char *l_end = strchr(l_ip, '\n');
                size_t l_len = l_end ? (size_t)(l_end - l_ip) : strlen(l_ip);
                if (l_dns_offset + l_len + 2 < sizeof(l_dns_buf)) {
                    if (l_dns_offset > 0) l_dns_buf[l_dns_offset++] = ' ';
                    memcpy(l_dns_buf + l_dns_offset, l_ip, l_len);
                    l_dns_offset += l_len;
                }
            } else if (strncmp(l_line, "search ", 7) == 0) {
                char *l_domains = l_line + 7;
                char *l_end = strchr(l_domains, '\n');
                size_t l_len = l_end ? (size_t)(l_end - l_domains) : strlen(l_domains);
                if (l_search_offset + l_len + 1 < sizeof(l_search_buf)) {
                    memcpy(l_search_buf + l_search_offset, l_domains, l_len);
                    l_search_offset += l_len;
                }
            }
            l_line = strchr(l_line, '\n');
            if (l_line) l_line++;
        }
        
        if (l_dns_offset > 0) {
            l_dns_buf[l_dns_offset] = '\0';
            l_backup->dns_servers = dap_strdup(l_dns_buf);
        }
        if (l_search_offset > 0) {
            l_search_buf[l_search_offset] = '\0';
            l_backup->dns_search_domains = dap_strdup(l_search_buf);
        }
    }
    
    log_it(L_INFO, "Network backup complete: gateway=%s, interface=%s, dns=%s",
           l_backup->default_gateway ? l_backup->default_gateway : "none",
           l_backup->default_interface ? l_backup->default_interface : "none",
           l_backup->dns_servers ? l_backup->dns_servers : "none");
    
    *a_out_backup = l_backup;
    return 0;
}

int dap_chain_net_vpn_client_network_platform_restore(void *a_backup) {
    if (!a_backup) return -1;
    
    dap_chain_net_vpn_client_network_platform_backup_t *l_backup = (dap_chain_net_vpn_client_network_platform_backup_t*)a_backup;
    
    log_it(L_INFO, "Restoring Linux network configuration...");
    
    int l_ret = 0;
    
    // Restore default route
    if (l_backup->default_gateway && l_backup->default_interface) {
        char l_cmd[512];
        
        // Delete current default route (ignore errors, may not exist)
        char *l_del_result = NULL;
        exec_with_ret(&l_del_result, "ip route del default 2>/dev/null");
        DAP_DELETE(l_del_result);
        
        // Add back original default route
        if (l_backup->default_metric) {
            snprintf(l_cmd, sizeof(l_cmd), "ip route add default via %s dev %s metric %s",
                     l_backup->default_gateway, l_backup->default_interface, l_backup->default_metric);
        } else {
            snprintf(l_cmd, sizeof(l_cmd), "ip route add default via %s dev %s",
                     l_backup->default_gateway, l_backup->default_interface);
        }
        
        char *l_output = NULL;
        exec_with_ret(&l_output, l_cmd);
        if (l_output) {
            if (strlen(l_output) > 0) {
                log_it(L_WARNING, "Route restore output: %s", l_output);
            }
            DAP_DELETE(l_output);
        }
        
        log_it(L_INFO, "Restored default route: %s via %s", 
               l_backup->default_gateway, l_backup->default_interface);
    } else {
        log_it(L_WARNING, "No default route to restore");
        l_ret = -1;
    }
    
    // Restore /etc/resolv.conf
    if (l_backup->original_resolv_conf) {
        if (write_file_content("/etc/resolv.conf", l_backup->original_resolv_conf) == 0) {
            log_it(L_INFO, "Restored /etc/resolv.conf");
        } else {
            log_it(L_ERROR, "Failed to restore /etc/resolv.conf");
            l_ret = -2;
        }
    } else {
        log_it(L_WARNING, "No resolv.conf backup to restore");
    }
    
    // Cleanup backup structure
    DAP_DELETE(l_backup->default_gateway);
    DAP_DELETE(l_backup->default_interface);
    DAP_DELETE(l_backup->default_metric);
    DAP_DELETE(l_backup->dns_servers);
    DAP_DELETE(l_backup->dns_search_domains);
    DAP_DELETE(l_backup->original_resolv_conf);
    DAP_DELETE(l_backup);
    
    log_it(L_INFO, "Network restore complete (status: %d)", l_ret);
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
    char *l_orig_gw_output = NULL;
    exec_with_ret(&l_orig_gw_output, "ip route show default | awk '{print $3}'");
    char *l_orig_gw = NULL;
    if (l_orig_gw_output && strlen(l_orig_gw_output) > 0) {
        l_orig_gw = dap_strdup(l_orig_gw_output);
        DAP_DELETE(l_orig_gw_output);
    }
    
    // Step 2: Add host route for VPN server (to avoid routing loop)
    if (l_orig_gw) {
        snprintf(l_cmd, sizeof(l_cmd), "ip route add %s via %s 2>/dev/null", 
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
        DAP_DELETE(l_orig_gw);
    }
    
    // Step 3: Delete current default route
    char *l_del_output = NULL;
    exec_with_ret(&l_del_output, "ip route del default 2>/dev/null");
    if (l_del_output) {
        if (strlen(l_del_output) > 0) {
            log_it(L_DEBUG, "Default route delete output: %s", l_del_output);
        }
        DAP_DELETE(l_del_output);
    }
    
    // Step 4: Add new default route through VPN
    if (a_vpn_gateway) {
        snprintf(l_cmd, sizeof(l_cmd), "ip route add default via %s dev %s metric 1",
                 a_vpn_gateway, a_vpn_interface);
    } else {
        snprintf(l_cmd, sizeof(l_cmd), "ip route add default dev %s metric 1",
                 a_vpn_interface);
    }
    
    char *l_route_output = NULL;
    exec_with_ret(&l_route_output, l_cmd);
    if (l_route_output) {
        if (strlen(l_route_output) > 0) {
            log_it(L_ERROR, "Failed to add VPN default route: %s", l_route_output);
            l_ret = -2;
        } else {
            log_it(L_INFO, "Added VPN default route via %s", a_vpn_interface);
        }
        DAP_DELETE(l_route_output);
    }
    
    // Step 5: Bring interface up if needed
    snprintf(l_cmd, sizeof(l_cmd), "ip link set %s up 2>/dev/null", a_vpn_interface);
    char *l_up_output = NULL;
    exec_with_ret(&l_up_output, l_cmd);
    DAP_DELETE(l_up_output);
    
    return l_ret;
}

int dap_chain_net_vpn_client_network_platform_apply_dns(const char **a_dns_servers, size_t a_dns_count) {
    if (!a_dns_servers || a_dns_count == 0) {
        log_it(L_ERROR, "Invalid DNS server list");
        return -1;
    }
    
    log_it(L_INFO, "Applying VPN DNS configuration (%zu servers)", a_dns_count);
    
    // Build new resolv.conf content
    char l_resolv_content[2048] = "# Generated by Cellframe VPN Client\n";
    size_t l_offset = strlen(l_resolv_content);
    
    for (size_t i = 0; i < a_dns_count && i < 8; i++) {
        int l_written = snprintf(l_resolv_content + l_offset, 
                                 sizeof(l_resolv_content) - l_offset,
                                 "nameserver %s\n", a_dns_servers[i]);
        if (l_written < 0 || l_written >= (int)(sizeof(l_resolv_content) - l_offset)) {
            break;
        }
        l_offset += l_written;
    }
    
    // Write to /etc/resolv.conf
    int l_ret = write_file_content("/etc/resolv.conf", l_resolv_content);
    if (l_ret == 0) {
        log_it(L_INFO, "DNS configuration applied successfully");
    } else {
        log_it(L_ERROR, "Failed to write /etc/resolv.conf");
    }
    
    return l_ret;
}

int dap_chain_net_vpn_client_network_platform_get_public_ip(char **a_out_ip) {
    if (!a_out_ip) return -1;
    
    // Try to get IP from default interface
    char *l_default_if_output = NULL;
    exec_with_ret(&l_default_if_output, "ip route show default | awk '{print $5}' | head -1");
    if (!l_default_if_output || strlen(l_default_if_output) == 0) {
        DAP_DELETE(l_default_if_output);
        *a_out_ip = dap_strdup("0.0.0.0");
        return -1;
    }
    
    char l_cmd[256];
    snprintf(l_cmd, sizeof(l_cmd), "ip addr show %s | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1",
             l_default_if_output);
    DAP_DELETE(l_default_if_output);
    
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

int dap_chain_net_vpn_client_network_platform_resolve_hostname(
    const char *a_hostname,
    char *a_out_ip,
    size_t a_ip_size
) {
    // Use common Unix implementation
    return dap_chain_net_vpn_client_network_unix_resolve_hostname(a_hostname, a_out_ip, a_ip_size);
}

int dap_chain_net_vpn_client_network_platform_get_gateway(char *a_out_gateway, size_t a_gateway_size) {
    if (!a_out_gateway || a_gateway_size == 0) return -1;
    
    // Use 'ip route' command to get default gateway
    char *l_output = NULL;
    exec_with_ret(&l_output, "ip route show default | awk '{print $3}' | head -1");
    
    if (!l_output || strlen(l_output) == 0) {
        log_it(L_ERROR, "Failed to determine default gateway");
        DAP_DELETE(l_output);
        return -2;
    }
    
    // Remove trailing newline
    size_t l_len = strlen(l_output);
    if (l_len > 0 && l_output[l_len - 1] == '\n') {
        l_output[l_len - 1] = '\0';
        l_len--;
    }
    
    // Check buffer size
    if (l_len >= a_gateway_size) {
        log_it(L_ERROR, "Gateway string too long for buffer (%zu >= %zu)", l_len, a_gateway_size);
        DAP_DELETE(l_output);
        return -3;
    }
    
    strncpy(a_out_gateway, l_output, a_gateway_size - 1);
    a_out_gateway[a_gateway_size - 1] = '\0';
    
    DAP_DELETE(l_output);
    log_it(L_DEBUG, "Default gateway: %s", a_out_gateway);
    return 0;
}

int dap_chain_net_vpn_client_network_platform_get_interface(char *a_out_interface, size_t a_interface_size) {
    if (!a_out_interface || a_interface_size == 0) return -1;
    
    // Use 'ip route' command to get default interface
    char *l_output = NULL;
    exec_with_ret(&l_output, "ip route show default | awk '{print $5}' | head -1");
    
    if (!l_output || strlen(l_output) == 0) {
        log_it(L_ERROR, "Failed to determine default interface");
        DAP_DELETE(l_output);
        return -2;
    }
    
    // Remove trailing newline
    size_t l_len = strlen(l_output);
    if (l_len > 0 && l_output[l_len - 1] == '\n') {
        l_output[l_len - 1] = '\0';
        l_len--;
    }
    
    // Check buffer size
    if (l_len >= a_interface_size) {
        log_it(L_ERROR, "Interface string too long for buffer (%zu >= %zu)", l_len, a_interface_size);
        DAP_DELETE(l_output);
        return -3;
    }
    
    strncpy(a_out_interface, l_output, a_interface_size - 1);
    a_out_interface[a_interface_size - 1] = '\0';
    
    DAP_DELETE(l_output);
    log_it(L_DEBUG, "Default interface: %s", a_out_interface);
    return 0;
}

int dap_chain_net_vpn_client_network_platform_add_host_route(
    const char *a_vpn_server_ip,
    const char *a_original_gateway,
    const char *a_original_interface
) {
    if (!a_vpn_server_ip || !a_original_gateway || !a_original_interface) return -1;
    
    // Add route to VPN server via original gateway and interface
    // This ensures that VPN traffic itself goes directly, not through VPN tunnel
    char l_cmd[512];
    snprintf(l_cmd, sizeof(l_cmd),
             "ip route add %s via %s dev %s",
             a_vpn_server_ip, a_original_gateway, a_original_interface);
    
    char *l_output = NULL;
    int l_ret = exec_with_ret(&l_output, l_cmd);
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to add host route for VPN server %s: %s", 
               a_vpn_server_ip, l_output ? l_output : "unknown error");
        DAP_DELETE(l_output);
        return -2;
    }
    
    DAP_DELETE(l_output);
    log_it(L_INFO, "Added host route for VPN server %s via %s dev %s",
           a_vpn_server_ip, a_original_gateway, a_original_interface);
    return 0;
}

