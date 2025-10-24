/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2021-2025
 * All rights reserved.
 *
 * This file is part of DAP SDK the open source project
 *
 *    DAP SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    DAP SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "dap_chain_net.h"
#include "dap_config.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Network registry for VPN client
 * 
 * Manages list of supported networks that VPN client can use for payments.
 * Configuration loaded from networks.cfg or from main config [vpn_client_networks] section.
 */

/**
 * @brief Network information
 */
typedef struct dap_vpn_client_network {
    char *name;                     // Network name (e.g., "kelvin", "backbone")
    dap_chain_net_id_t chain_id;   // Blockchain ID
    char *node_addr;                // Node address for connection (host:port)
    char *token_ticker;             // Token ticker (e.g., "KEL", "CELL")
    bool enabled;                   // Is this network enabled
    dap_chain_net_t *net;          // Network pointer (if in embedded mode)
} dap_vpn_client_network_t;

/**
 * @brief Initialize network registry
 * 
 * @param a_config Configuration (if NULL, tries to load from default location)
 * @return 0 on success, negative on error
 */
int dap_vpn_client_network_registry_init(dap_config_t *a_config);

/**
 * @brief Deinitialize network registry
 */
void dap_vpn_client_network_registry_deinit(void);

/**
 * @brief Get network by name
 * 
 * @param a_name Network name
 * @return Network info or NULL if not found
 */
dap_vpn_client_network_t* dap_vpn_client_network_registry_get(const char *a_name);

/**
 * @brief Get list of all networks
 * 
 * @param[out] a_count Output: number of networks
 * @return Array of network pointers (do not free - owned by registry), or NULL
 */
dap_vpn_client_network_t** dap_vpn_client_network_registry_list(size_t *a_count);

/**
 * @brief Get list of enabled networks only
 * 
 * @param[out] a_count Output: number of enabled networks
 * @return Array of network pointers (do not free - owned by registry), or NULL
 */
dap_vpn_client_network_t** dap_vpn_client_network_registry_list_enabled(size_t *a_count);

/**
 * @brief Check if network is available and enabled
 * 
 * @param a_name Network name
 * @return true if available and enabled
 */
bool dap_vpn_client_network_registry_is_available(const char *a_name);

#ifdef __cplusplus
}
#endif

