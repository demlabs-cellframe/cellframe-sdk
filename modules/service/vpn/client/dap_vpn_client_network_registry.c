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

#include "dap_vpn_client_network_registry.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_config.h"
#include <string.h>

#define LOG_TAG "vpn_client_network_registry"

#define DEFAULT_NETWORK_SECTION_PREFIX "network_"

// Global registry
static dap_vpn_client_network_t **s_networks = NULL;
static size_t s_network_count = 0;

/**
 * @brief Parse network from config section
 */
static dap_vpn_client_network_t* s_parse_network_from_config(dap_config_t *a_config, const char *a_section_name)
{
    if (!a_config || !a_section_name) {
        return NULL;
    }
    
    dap_vpn_client_network_t *l_network = DAP_NEW_Z(dap_vpn_client_network_t);
    if (!l_network) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    // Extract network name from section name (remove "network_" prefix)
    const char *l_name_start = a_section_name;
    if (strncmp(a_section_name, DEFAULT_NETWORK_SECTION_PREFIX, strlen(DEFAULT_NETWORK_SECTION_PREFIX)) == 0) {
        l_name_start = a_section_name + strlen(DEFAULT_NETWORK_SECTION_PREFIX);
    }
    l_network->name = dap_strdup(l_name_start);
    
    // Parse enabled flag
    l_network->enabled = dap_config_get_item_bool_default(a_config, a_section_name, "enabled", true);
    
    // Parse chain_id
    const char *l_chain_id_str = dap_config_get_item_str(a_config, a_section_name, "chain_id");
    if (l_chain_id_str) {
        l_network->chain_id.uint64 = strtoull(l_chain_id_str, NULL, 0);
    }
    
    // Parse node address
    const char *l_node_addr = dap_config_get_item_str(a_config, a_section_name, "node_addr");
    if (l_node_addr) {
        l_network->node_addr = dap_strdup(l_node_addr);
    }
    
    // Parse token ticker
    const char *l_token = dap_config_get_item_str(a_config, a_section_name, "token_ticker");
    if (l_token) {
        l_network->token_ticker = dap_strdup(l_token);
    } else {
        l_network->token_ticker = dap_strdup("KEL"); // Default token
    }
    
    // In embedded mode, try to get dap_chain_net_t pointer
    l_network->net = dap_chain_net_by_id(l_network->chain_id);
    if (!l_network->net && l_network->name) {
        l_network->net = dap_chain_net_by_name(l_network->name);
    }
    
    log_it(L_INFO, "Loaded network '%s': chain_id=0x%016"DAP_UINT64_FORMAT_X", token=%s, enabled=%s",
           l_network->name, l_network->chain_id.uint64, l_network->token_ticker,
           l_network->enabled ? "yes" : "no");
    
    return l_network;
}

/**
 * @brief Free network info
 */
static void s_network_free(dap_vpn_client_network_t *a_network)
{
    if (!a_network)
        return;
    
    DAP_DELETE(a_network->name);
    DAP_DELETE(a_network->node_addr);
    DAP_DELETE(a_network->token_ticker);
    DAP_DELETE(a_network);
}

/**
 * @brief Initialize network registry
 */
int dap_vpn_client_network_registry_init(dap_config_t *a_config)
{
    if (!a_config) {
        log_it(L_ERROR, "Config is NULL");
        return -1;
    }
    
    // Get list of all sections starting with "network_"
    char **l_sections = NULL;
    size_t l_section_count = 0;
    
    // Parse all network sections
    // Note: dap_config doesn't have API to list sections, so we try known networks
    const char *l_known_networks[] = {"kelvin", "backbone", "subzero", "mileena", NULL};
    
    // Count available networks
    for (size_t i = 0; l_known_networks[i]; i++) {
        char l_section_name[128];
        snprintf(l_section_name, sizeof(l_section_name), "%s%s", 
                 DEFAULT_NETWORK_SECTION_PREFIX, l_known_networks[i]);
        
        // Check if section exists by trying to read a parameter
        if (dap_config_get_item_str(a_config, l_section_name, "enabled") ||
            dap_config_get_item_str(a_config, l_section_name, "chain_id")) {
            l_section_count++;
        }
    }
    
    if (l_section_count == 0) {
        log_it(L_WARNING, "No network sections found in config");
        return 0;
    }
    
    // Allocate network array
    s_networks = DAP_NEW_Z_SIZE(dap_vpn_client_network_t*, l_section_count * sizeof(dap_vpn_client_network_t*));
    if (!s_networks) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -2;
    }
    
    // Parse each network
    s_network_count = 0;
    for (size_t i = 0; l_known_networks[i]; i++) {
        char l_section_name[128];
        snprintf(l_section_name, sizeof(l_section_name), "%s%s",
                 DEFAULT_NETWORK_SECTION_PREFIX, l_known_networks[i]);
        
        if (dap_config_get_item_str(a_config, l_section_name, "enabled") ||
            dap_config_get_item_str(a_config, l_section_name, "chain_id")) {
            
            dap_vpn_client_network_t *l_network = s_parse_network_from_config(a_config, l_section_name);
            if (l_network) {
                s_networks[s_network_count++] = l_network;
            }
        }
    }
    
    log_it(L_NOTICE, "Network registry initialized with %zu networks", s_network_count);
    return 0;
}

/**
 * @brief Deinitialize network registry
 */
void dap_vpn_client_network_registry_deinit(void)
{
    if (s_networks) {
        for (size_t i = 0; i < s_network_count; i++) {
            s_network_free(s_networks[i]);
        }
        DAP_DELETE(s_networks);
        s_networks = NULL;
    }
    s_network_count = 0;
}

/**
 * @brief Get network by name
 */
dap_vpn_client_network_t* dap_vpn_client_network_registry_get(const char *a_name)
{
    if (!a_name || !s_networks) {
        return NULL;
    }
    
    for (size_t i = 0; i < s_network_count; i++) {
        if (s_networks[i]->name && strcmp(s_networks[i]->name, a_name) == 0) {
            return s_networks[i];
        }
    }
    
    return NULL;
}

/**
 * @brief Get list of all networks
 */
dap_vpn_client_network_t** dap_vpn_client_network_registry_list(size_t *a_count)
{
    if (!a_count)
        return NULL;
    
    *a_count = s_network_count;
    return s_networks;
}

/**
 * @brief Get list of enabled networks only
 */
dap_vpn_client_network_t** dap_vpn_client_network_registry_list_enabled(size_t *a_count)
{
    if (!a_count || !s_networks)
        return NULL;
    
    // Count enabled networks
    size_t l_enabled_count = 0;
    for (size_t i = 0; i < s_network_count; i++) {
        if (s_networks[i]->enabled) {
            l_enabled_count++;
        }
    }
    
    if (l_enabled_count == 0) {
        *a_count = 0;
        return NULL;
    }
    
    // Allocate array
    dap_vpn_client_network_t **l_enabled = DAP_NEW_Z_SIZE(dap_vpn_client_network_t*,
                                                           l_enabled_count * sizeof(dap_vpn_client_network_t*));
    if (!l_enabled) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    // Fill array
    size_t l_idx = 0;
    for (size_t i = 0; i < s_network_count && l_idx < l_enabled_count; i++) {
        if (s_networks[i]->enabled) {
            l_enabled[l_idx++] = s_networks[i];
        }
    }
    
    *a_count = l_enabled_count;
    return l_enabled;
}

/**
 * @brief Check if network is available and enabled
 */
bool dap_vpn_client_network_registry_is_available(const char *a_name)
{
    dap_vpn_client_network_t *l_network = dap_vpn_client_network_registry_get(a_name);
    return (l_network && l_network->enabled);
}

