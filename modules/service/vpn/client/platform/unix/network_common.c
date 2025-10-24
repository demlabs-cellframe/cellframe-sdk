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

/**
 * @file network_common.c
 * @brief Common network functions for all Unix-like platforms (Linux, Darwin/macOS, BSD)
 * @date 2025-10-24
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "network_common.h"
#include "dap_common.h"

#define LOG_TAG "vpn_client_network_unix"

/**
 * @brief Resolve hostname to IP address (common for all Unix platforms)
 * @param a_hostname Hostname to resolve
 * @param a_out_ip Output buffer for IP address
 * @param a_ip_size Size of output buffer
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_unix_resolve_hostname(
    const char *a_hostname,
    char *a_out_ip,
    size_t a_ip_size
) {
    if (!a_hostname || !a_out_ip || a_ip_size == 0) return -1;
    
    // Use getaddrinfo for hostname resolution
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo(a_hostname, NULL, &hints, &res);
    if (status != 0) {
        log_it(L_ERROR, "Failed to resolve hostname '%s': %s", a_hostname, gai_strerror(status));
        return -2;
    }
    
    // Get first result
    void *addr;
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        addr = &(ipv4->sin_addr);
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        addr = &(ipv6->sin6_addr);
    }
    
    // Convert to string
    if (inet_ntop(res->ai_family, addr, a_out_ip, a_ip_size) == NULL) {
        log_it(L_ERROR, "Failed to convert IP address to string");
        freeaddrinfo(res);
        return -3;
    }
    
    log_it(L_DEBUG, "Resolved hostname '%s' to IP '%s'", a_hostname, a_out_ip);
    freeaddrinfo(res);
    return 0;
}

