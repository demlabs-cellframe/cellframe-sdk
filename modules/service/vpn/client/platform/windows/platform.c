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

#include "../platform.h"
#include "dap_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "vpn_network_windows"

int dap_chain_net_vpn_client_network_platform_get_gateway(char *a_out_gateway, size_t a_gateway_size) {
    if (!a_out_gateway || a_gateway_size == 0) return -1;
    
    // Use 'route print' and parse for default route (0.0.0.0)
    char *l_output = NULL;
    int l_ret = exec_with_ret(&l_output, "route print 0.0.0.0 | findstr \"0.0.0.0\"");
    if (l_ret != 0 || !l_output) {
        log_it(L_ERROR, "Failed to execute 'route print' command");
        DAP_DELETE(l_output);
        return -2;
    }
    
    if (strlen(l_output) == 0) {
        log_it(L_ERROR, "Empty output from 'route print'");
        DAP_DELETE(l_output);
        return -3;
    }
    
    // Parse: "0.0.0.0  0.0.0.0  <gateway>  <interface>  <metric>"
    char *l_line = dap_strdup(l_output);
    DAP_DELETE(l_output);
    
    char *token = strtok(l_line, " \t\r\n");
    int field = 0;
    while (token != NULL && field < 3) {
        if (field == 2) {  // Gateway is 3rd field
            strncpy(a_out_gateway, token, a_gateway_size - 1);
            a_out_gateway[a_gateway_size - 1] = '\0';
            log_it(L_DEBUG, "Default gateway: %s", a_out_gateway);
            DAP_DELETE(l_line);
            return 0;
        }
        token = strtok(NULL, " \t\r\n");
        field++;
    }
    
    DAP_DELETE(l_line);
    log_it(L_ERROR, "Failed to parse gateway from route output");
    return -4;
}

int dap_chain_net_vpn_client_network_platform_get_interface(char *a_out_interface, size_t a_interface_size) {
    if (!a_out_interface || a_interface_size == 0) return -1;
    
    // Use 'route print' to get interface
    char *l_output = NULL;
    int l_ret = exec_with_ret(&l_output, "route print 0.0.0.0 | findstr \"0.0.0.0\"");
    if (l_ret != 0 || !l_output) {
        log_it(L_ERROR, "Failed to execute 'route print' command");
        DAP_DELETE(l_output);
        return -2;
    }
    
    if (strlen(l_output) == 0) {
        log_it(L_ERROR, "Empty output from 'route print'");
        DAP_DELETE(l_output);
        return -3;
    }
    
    // Parse for interface IP (4th field)
    char *l_line = dap_strdup(l_output);
    DAP_DELETE(l_output);
    
    char *token = strtok(l_line, " \t\r\n");
    int field = 0;
    while (token != NULL && field < 4) {
        if (field == 3) {  // Interface is 4th field
            strncpy(a_out_interface, token, a_interface_size - 1);
            a_out_interface[a_interface_size - 1] = '\0';
            log_it(L_DEBUG, "Default interface: %s", a_out_interface);
            DAP_DELETE(l_line);
            return 0;
        }
        token = strtok(NULL, " \t\r\n");
        field++;
    }
    
    DAP_DELETE(l_line);
    log_it(L_ERROR, "Failed to parse interface from route output");
    return -4;
}

int dap_chain_net_vpn_client_network_platform_add_host_route(
    const char *a_vpn_server_ip,
    const char *a_original_gateway,
    const char *a_original_interface
) {
    if (!a_vpn_server_ip || !a_original_gateway) return -1;
    
    // Add host route: route add <vpn_server_ip> mask 255.255.255.255 <gateway>
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "route add %s mask 255.255.255.255 %s", 
             a_vpn_server_ip, a_original_gateway);
    
    log_it(L_DEBUG, "Adding host route: %s", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        log_it(L_ERROR, "Failed to add host route (exit code %d)", ret);
        return -2;
    }
    
    log_it(L_INFO, "Host route added: %s via %s", a_vpn_server_ip, a_original_gateway);
    return 0;
}

