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
 * @file network_common.h
 * @brief Common network functions for all Unix-like platforms
 * @date 2025-10-24
 * 
 * This header provides network functions that are common across
 * all Unix-like systems: Linux, Darwin/macOS, iOS, BSD
 */

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Resolve hostname to IP address (common for all Unix platforms)
 * @param a_hostname Hostname to resolve
 * @param a_out_ip Output buffer for IP address (min INET6_ADDRSTRLEN bytes)
 * @param a_ip_size Size of output buffer
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_network_unix_resolve_hostname(
    const char *a_hostname,
    char *a_out_ip,
    size_t a_ip_size
);

#ifdef __cplusplus
}
#endif

