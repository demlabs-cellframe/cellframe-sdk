/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * This file is part of DAP (Distributed Applications Platform) the open source project
 *
 *    DAP is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    DAP is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_exec.h"
#include "tun_device_common.h"

#define LOG_TAG "dap_tun_unix"

/**
 * @brief Execute shell command with output capture
 */
int dap_tun_unix_exec_with_output(
    const char *a_command,
    char *a_output,
    size_t a_output_size)
{
    if (!a_command) {
        log_it(L_ERROR, "Command is NULL");
        return -1;
    }
    
    log_it(L_DEBUG, "Executing: %s", a_command);
    
    char *l_output = NULL;
    int l_ret = exec_with_ret(&l_output, a_command);
    
    if (a_output && a_output_size > 0 && l_output) {
        strncpy(a_output, l_output, a_output_size - 1);
        a_output[a_output_size - 1] = '\0';
    }
    
    DAP_DELETE(l_output);
    
    if (l_ret != 0) {
        log_it(L_WARNING, "Command failed with exit code %d: %s", l_ret, a_command);
    }
    
    return l_ret;
}

/**
 * @brief Set interface UP or DOWN
 */
int dap_tun_unix_set_interface_state(const char *a_ifname, bool a_up)
{
    if (!a_ifname) {
        log_it(L_ERROR, "Interface name is NULL");
        return -1;
    }
    
#if defined(DAP_OS_LINUX) || defined(DAP_OS_BSD)
    char l_cmd[256];
    snprintf(l_cmd, sizeof(l_cmd), "ip link set %s %s", a_ifname, a_up ? "up" : "down");
    return dap_tun_unix_exec_with_output(l_cmd, NULL, 0);
#elif defined(DAP_OS_DARWIN)
    char l_cmd[256];
    snprintf(l_cmd, sizeof(l_cmd), "ifconfig %s %s", a_ifname, a_up ? "up" : "down");
    return dap_tun_unix_exec_with_output(l_cmd, NULL, 0);
#else
    log_it(L_ERROR, "Platform not supported");
    return -2;
#endif
}

/**
 * @brief Configure interface IP address
 */
int dap_tun_unix_configure_address(
    const char *a_ifname,
    struct in_addr a_addr,
    struct in_addr a_mask)
{
    if (!a_ifname) {
        log_it(L_ERROR, "Interface name is NULL");
        return -1;
    }
    
    char l_addr_str[INET_ADDRSTRLEN];
    char l_mask_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a_addr, l_addr_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &a_mask, l_mask_str, INET_ADDRSTRLEN);
    
#if defined(DAP_OS_LINUX) || defined(DAP_OS_BSD)
    char l_cmd[256];
    snprintf(l_cmd, sizeof(l_cmd), "ip addr add %s/%s dev %s", 
             l_addr_str, l_mask_str, a_ifname);
    return dap_tun_unix_exec_with_output(l_cmd, NULL, 0);
#elif defined(DAP_OS_DARWIN)
    char l_cmd[256];
    snprintf(l_cmd, sizeof(l_cmd), "ifconfig %s %s %s", 
             a_ifname, l_addr_str, l_addr_str);
    return dap_tun_unix_exec_with_output(l_cmd, NULL, 0);
#else
    log_it(L_ERROR, "Platform not supported");
    return -2;
#endif
}

/**
 * @brief Add route
 */
int dap_tun_unix_add_route(
    struct in_addr a_dest,
    struct in_addr a_mask,
    struct in_addr *a_gateway,
    const char *a_ifname)
{
    char l_dest_str[INET_ADDRSTRLEN];
    char l_mask_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a_dest, l_dest_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &a_mask, l_mask_str, INET_ADDRSTRLEN);
    
#if defined(DAP_OS_LINUX) || defined(DAP_OS_BSD)
    char l_cmd[512];
    if (a_gateway) {
        char l_gw_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, a_gateway, l_gw_str, INET_ADDRSTRLEN);
        snprintf(l_cmd, sizeof(l_cmd), "ip route add %s/%s via %s", 
                 l_dest_str, l_mask_str, l_gw_str);
    } else if (a_ifname) {
        snprintf(l_cmd, sizeof(l_cmd), "ip route add %s/%s dev %s", 
                 l_dest_str, l_mask_str, a_ifname);
    } else {
        log_it(L_ERROR, "Either gateway or interface must be provided");
        return -1;
    }
    return dap_tun_unix_exec_with_output(l_cmd, NULL, 0);
#elif defined(DAP_OS_DARWIN)
    char l_cmd[512];
    if (a_gateway) {
        char l_gw_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, a_gateway, l_gw_str, INET_ADDRSTRLEN);
        snprintf(l_cmd, sizeof(l_cmd), "route add -net %s -netmask %s %s", 
                 l_dest_str, l_mask_str, l_gw_str);
    } else if (a_ifname) {
        snprintf(l_cmd, sizeof(l_cmd), "route add -net %s -netmask %s -interface %s", 
                 l_dest_str, l_mask_str, a_ifname);
    } else {
        log_it(L_ERROR, "Either gateway or interface must be provided");
        return -1;
    }
    return dap_tun_unix_exec_with_output(l_cmd, NULL, 0);
#else
    log_it(L_ERROR, "Platform not supported");
    return -2;
#endif
}

/**
 * @brief Delete route
 */
int dap_tun_unix_delete_route(
    struct in_addr a_dest,
    struct in_addr a_mask)
{
    char l_dest_str[INET_ADDRSTRLEN];
    char l_mask_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a_dest, l_dest_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &a_mask, l_mask_str, INET_ADDRSTRLEN);
    
#if defined(DAP_OS_LINUX) || defined(DAP_OS_BSD)
    char l_cmd[256];
    snprintf(l_cmd, sizeof(l_cmd), "ip route del %s/%s", 
             l_dest_str, l_mask_str);
    return dap_tun_unix_exec_with_output(l_cmd, NULL, 0);
#elif defined(DAP_OS_DARWIN)
    char l_cmd[256];
    snprintf(l_cmd, sizeof(l_cmd), "route delete -net %s -netmask %s", 
             l_dest_str, l_mask_str);
    return dap_tun_unix_exec_with_output(l_cmd, NULL, 0);
#else
    log_it(L_ERROR, "Platform not supported");
    return -2;
#endif
}

/**
 * @brief Get default gateway
 */
int dap_tun_unix_get_default_gateway(struct in_addr *a_gateway)
{
    if (!a_gateway) {
        log_it(L_ERROR, "Gateway pointer is NULL");
        return -1;
    }
    
#if defined(DAP_OS_LINUX) || defined(DAP_OS_BSD)
    char l_output[1024];
    int l_ret = dap_tun_unix_exec_with_output("ip route show default", l_output, sizeof(l_output));
    if (l_ret != 0) {
        return l_ret;
    }
    
    // Parse "default via 192.168.1.1 dev eth0"
    char *l_via = strstr(l_output, "via ");
    if (l_via) {
        l_via += 4;  // Skip "via "
        char l_gw_str[INET_ADDRSTRLEN];
        sscanf(l_via, "%s", l_gw_str);
        if (inet_pton(AF_INET, l_gw_str, a_gateway) == 1) {
            return 0;
        }
    }
    
    log_it(L_ERROR, "Failed to parse default gateway from: %s", l_output);
    return -2;
#elif defined(DAP_OS_DARWIN)
    char l_output[1024];
    int l_ret = dap_tun_unix_exec_with_output("route -n get default", l_output, sizeof(l_output));
    if (l_ret != 0) {
        return l_ret;
    }
    
    // Parse "gateway: 192.168.1.1"
    char *l_gateway = strstr(l_output, "gateway:");
    if (l_gateway) {
        l_gateway += 8;  // Skip "gateway:"
        while (*l_gateway == ' ') l_gateway++;
        char l_gw_str[INET_ADDRSTRLEN];
        sscanf(l_gateway, "%s", l_gw_str);
        if (inet_pton(AF_INET, l_gw_str, a_gateway) == 1) {
            return 0;
        }
    }
    
    log_it(L_ERROR, "Failed to parse default gateway from: %s", l_output);
    return -2;
#else
    log_it(L_ERROR, "Platform not supported");
    return -3;
#endif
}

/**
 * @brief Set MTU for interface
 */
int dap_tun_unix_set_mtu(const char *a_ifname, uint32_t a_mtu)
{
    if (!a_ifname) {
        log_it(L_ERROR, "Interface name is NULL");
        return -1;
    }
    
#if defined(DAP_OS_LINUX) || defined(DAP_OS_BSD)
    char l_cmd[256];
    snprintf(l_cmd, sizeof(l_cmd), "ip link set %s mtu %u", a_ifname, a_mtu);
    return dap_tun_unix_exec_with_output(l_cmd, NULL, 0);
#elif defined(DAP_OS_DARWIN)
    char l_cmd[256];
    snprintf(l_cmd, sizeof(l_cmd), "ifconfig %s mtu %u", a_ifname, a_mtu);
    return dap_tun_unix_exec_with_output(l_cmd, NULL, 0);
#else
    log_it(L_ERROR, "Platform not supported");
    return -2;
#endif
}

