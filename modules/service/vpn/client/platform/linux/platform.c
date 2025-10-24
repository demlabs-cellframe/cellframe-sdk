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
#include <string.h>

#define LOG_TAG "vpn_network_linux"

int dap_chain_net_vpn_client_network_platform_get_gateway(char *a_out_gateway, size_t a_gateway_size) {
    if (!a_out_gateway || a_gateway_size == 0) return -1;
    
    char *l_result = NULL;
    int l_ret = exec_with_ret(&l_result, "ip route show default | awk '/default/ {print $3}'");
    
    if (l_ret != 0 || !l_result) {
        log_it(L_ERROR, "Failed to execute 'ip route' command (exit code: %d)", l_ret);
        return -2;
    }
    
    if (!l_result[0]) {
        log_it(L_ERROR, "Gateway address is empty");
        DAP_DELETE(l_result);
        return -3;
    }
    
    strncpy(a_out_gateway, l_result, a_gateway_size - 1);
    a_out_gateway[a_gateway_size - 1] = '\0';
    DAP_DELETE(l_result);
    
    log_it(L_DEBUG, "Default gateway: %s", a_out_gateway);
    return 0;
}

int dap_chain_net_vpn_client_network_platform_get_interface(char *a_out_interface, size_t a_interface_size) {
    if (!a_out_interface || a_interface_size == 0) return -1;
    
    char *l_result = NULL;
    int l_ret = exec_with_ret(&l_result, "ip route show default | awk '/default/ {print $5}'");
    
    if (l_ret != 0 || !l_result) {
        log_it(L_ERROR, "Failed to execute 'ip route' command (exit code: %d)", l_ret);
        return -2;
    }
    
    if (!l_result[0]) {
        log_it(L_ERROR, "Interface name is empty");
        DAP_DELETE(l_result);
        return -3;
    }
    
    strncpy(a_out_interface, l_result, a_interface_size - 1);
    a_out_interface[a_interface_size - 1] = '\0';
    DAP_DELETE(l_result);
    
    log_it(L_DEBUG, "Default interface: %s", a_out_interface);
    return 0;
}

int dap_chain_net_vpn_client_network_platform_add_host_route(
    const char *a_vpn_server_ip,
    const char *a_original_gateway,
    const char *a_original_interface
) {
    if (!a_vpn_server_ip || !a_original_gateway) return -1;
    
    char l_cmd[512];
    if (a_original_interface) {
        snprintf(l_cmd, sizeof(l_cmd), "ip route add %s via %s dev %s 2>&1", 
                 a_vpn_server_ip, a_original_gateway, a_original_interface);
    } else {
        snprintf(l_cmd, sizeof(l_cmd), "ip route add %s via %s 2>&1", 
                 a_vpn_server_ip, a_original_gateway);
    }
    
    log_it(L_DEBUG, "Adding host route: %s", l_cmd);
    
    char *l_result = NULL;
    int l_ret = exec_with_ret(&l_result, l_cmd);
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to add host route (exit code: %d): %s", 
               l_ret, l_result ? l_result : "no output");
        DAP_DEL_Z(l_result);
        return -2;
    }
    
    DAP_DEL_Z(l_result);
    log_it(L_INFO, "Host route added: %s via %s", a_vpn_server_ip, a_original_gateway);
    return 0;
}
