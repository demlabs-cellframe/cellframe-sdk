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
 *    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_chain_net_srv_vpn_traffic.h"
#include "dap_chain_net_srv_vpn_internal.h"

#define LOG_TAG "dap_chain_net_srv_vpn_traffic"

#define MBPS_TO_BPS(mbps) ((uint64_t)(mbps) * 1024 * 1024 / 8)  // Convert Mbps to bytes per second
#define DEFAULT_BURST_SIZE_MULTIPLIER 2  // Allow 2x bandwidth as burst

/**
 * @brief Parse CIDR notation to check if IP is in range
 */
static bool s_ip_in_cidr(const char *a_ip, const char *a_cidr)
{
    if (!a_ip || !a_cidr)
        return false;
    
    char *l_cidr_copy = dap_strdup(a_cidr);
    char *l_slash = strchr(l_cidr_copy, '/');
    if (!l_slash) {
        DAP_DELETE(l_cidr_copy);
        return false;
    }
    
    *l_slash = '\0';
    uint32_t l_prefix_len = atoi(l_slash + 1);
    
    struct in_addr l_ip_addr, l_network_addr;
    if (inet_pton(AF_INET, a_ip, &l_ip_addr) != 1 ||
        inet_pton(AF_INET, l_cidr_copy, &l_network_addr) != 1) {
        DAP_DELETE(l_cidr_copy);
        return false;
    }
    
    DAP_DELETE(l_cidr_copy);
    
    // Create network mask
    uint32_t l_mask = (l_prefix_len == 0) ? 0 : (~0U << (32 - l_prefix_len));
    
    // Check if IP is in network
    return (ntohl(l_ip_addr.s_addr) & l_mask) == (ntohl(l_network_addr.s_addr) & l_mask);
}

/**
 * @brief Initialize traffic shaper
 */
dap_chain_net_srv_vpn_traffic_shaper_t* dap_chain_net_srv_vpn_traffic_shaper_create(
    uint32_t a_bandwidth_limit_mbps,
    uint32_t a_priority)
{
    dap_chain_net_srv_vpn_traffic_shaper_t *l_shaper = DAP_NEW_Z(dap_chain_net_srv_vpn_traffic_shaper_t);
    if (!l_shaper) {
        log_it(L_ERROR, "Failed to allocate traffic shaper");
        return NULL;
    }
    
    l_shaper->bandwidth_limit_bps = a_bandwidth_limit_mbps > 0 ? MBPS_TO_BPS(a_bandwidth_limit_mbps) : 0;
    l_shaper->priority = a_priority;
    
    // Initialize token bucket
    if (l_shaper->bandwidth_limit_bps > 0) {
        l_shaper->max_tokens = l_shaper->bandwidth_limit_bps * DEFAULT_BURST_SIZE_MULTIPLIER;
        l_shaper->tokens = l_shaper->max_tokens;  // Start with full bucket
        l_shaper->last_refill = time(NULL);
    }
    
    pthread_mutex_init(&l_shaper->mutex, NULL);
    
    log_it(L_INFO, "Traffic shaper created: bandwidth=%u Mbps (%lu bps), priority=%u",
           a_bandwidth_limit_mbps, l_shaper->bandwidth_limit_bps, a_priority);
    
    return l_shaper;
}

/**
 * @brief Check if packet can be sent (Token Bucket Algorithm)
 */
bool dap_chain_net_srv_vpn_traffic_shaper_allow(
    dap_chain_net_srv_vpn_traffic_shaper_t *a_shaper,
    size_t a_packet_size)
{
    if (!a_shaper)
        return true;
    
    // Unlimited bandwidth
    if (a_shaper->bandwidth_limit_bps == 0)
        return true;
    
    pthread_mutex_lock(&a_shaper->mutex);
    
    // Refill tokens based on elapsed time
    time_t l_now = time(NULL);
    time_t l_elapsed = l_now - a_shaper->last_refill;
    if (l_elapsed > 0) {
        uint64_t l_tokens_to_add = l_elapsed * a_shaper->bandwidth_limit_bps;
        a_shaper->tokens = (a_shaper->tokens + l_tokens_to_add > a_shaper->max_tokens) ?
                           a_shaper->max_tokens : (a_shaper->tokens + l_tokens_to_add);
        a_shaper->last_refill = l_now;
    }
    
    // Check if we have enough tokens
    bool l_allow = (a_shaper->tokens >= a_packet_size);
    
    if (l_allow) {
        a_shaper->tokens -= a_packet_size;
        a_shaper->bytes_sent += a_packet_size;
        a_shaper->packets_sent++;
    } else {
        a_shaper->bytes_dropped += a_packet_size;
        a_shaper->packets_dropped++;
        debug_if(g_vpn_debug_more, L_DEBUG, "Packet dropped by rate limiter: %zu bytes", a_packet_size);
    }
    
    pthread_mutex_unlock(&a_shaper->mutex);
    return l_allow;
}

/**
 * @brief Free traffic shaper
 */
void dap_chain_net_srv_vpn_traffic_shaper_free(dap_chain_net_srv_vpn_traffic_shaper_t *a_shaper)
{
    if (!a_shaper)
        return;
    
    pthread_mutex_destroy(&a_shaper->mutex);
    DAP_DELETE(a_shaper);
}

/**
 * @brief Create split tunneling configuration
 */
dap_chain_net_srv_vpn_split_tunnel_t* dap_chain_net_srv_vpn_split_tunnel_create(
    const char *a_exclude_routes)
{
    if (!a_exclude_routes || strlen(a_exclude_routes) == 0)
        return NULL;
    
    dap_chain_net_srv_vpn_split_tunnel_t *l_config = DAP_NEW_Z(dap_chain_net_srv_vpn_split_tunnel_t);
    if (!l_config) {
        log_it(L_ERROR, "Failed to allocate split tunnel config");
        return NULL;
    }
    
    l_config->enabled = true;
    
    // Parse comma-separated routes
    char *l_routes_copy = dap_strdup(a_exclude_routes);
    char *l_route = strtok(l_routes_copy, ",");
    size_t l_count = 0;
    size_t l_capacity = 10;
    l_config->exclude_routes = DAP_NEW_Z_SIZE(char*, l_capacity * sizeof(char*));
    
    while (l_route) {
        // Trim whitespace
        while (*l_route == ' ') l_route++;
        char *l_end = l_route + strlen(l_route) - 1;
        while (l_end > l_route && *l_end == ' ') *l_end-- = '\0';
        
        if (strlen(l_route) > 0) {
            if (l_count >= l_capacity) {
                l_capacity *= 2;
                l_config->exclude_routes = DAP_REALLOC(l_config->exclude_routes, l_capacity * sizeof(char*));
            }
            l_config->exclude_routes[l_count++] = dap_strdup(l_route);
        }
        
        l_route = strtok(NULL, ",");
    }
    
    l_config->exclude_routes_count = l_count;
    DAP_DELETE(l_routes_copy);
    
    log_it(L_INFO, "Split tunneling configured: %zu excluded routes", l_count);
    return l_config;
}

/**
 * @brief Check if packet should bypass VPN tunnel
 */
bool dap_chain_net_srv_vpn_split_tunnel_should_bypass(
    dap_chain_net_srv_vpn_split_tunnel_t *a_split_tunnel,
    const char *a_dest_ip)
{
    if (!a_split_tunnel || !a_split_tunnel->enabled || !a_dest_ip)
        return false;
    
    for (size_t i = 0; i < a_split_tunnel->exclude_routes_count; i++) {
        if (s_ip_in_cidr(a_dest_ip, a_split_tunnel->exclude_routes[i])) {
            return true;
        }
    }
    
    return false;
}

/**
 * @brief Free split tunneling configuration
 */
void dap_chain_net_srv_vpn_split_tunnel_free(dap_chain_net_srv_vpn_split_tunnel_t *a_split_tunnel)
{
    if (!a_split_tunnel)
        return;
    
    if (a_split_tunnel->exclude_routes) {
        for (size_t i = 0; i < a_split_tunnel->exclude_routes_count; i++) {
            DAP_DELETE(a_split_tunnel->exclude_routes[i]);
        }
        DAP_DELETE(a_split_tunnel->exclude_routes);
    }
    
    DAP_DELETE(a_split_tunnel);
}

/**
 * @brief Create DNS configuration
 */
dap_chain_net_srv_vpn_dns_config_t* dap_chain_net_srv_vpn_dns_config_create(
    const char *a_dns_servers)
{
    if (!a_dns_servers || strlen(a_dns_servers) == 0)
        return NULL;
    
    dap_chain_net_srv_vpn_dns_config_t *l_config = DAP_NEW_Z(dap_chain_net_srv_vpn_dns_config_t);
    if (!l_config) {
        log_it(L_ERROR, "Failed to allocate DNS config");
        return NULL;
    }
    
    l_config->override_system_dns = true;
    
    // Parse comma-separated DNS servers
    char *l_dns_copy = dap_strdup(a_dns_servers);
    char *l_dns = strtok(l_dns_copy, ",");
    size_t l_count = 0;
    size_t l_capacity = 5;
    l_config->dns_servers = DAP_NEW_Z_SIZE(char*, l_capacity * sizeof(char*));
    
    while (l_dns) {
        // Trim whitespace
        while (*l_dns == ' ') l_dns++;
        char *l_end = l_dns + strlen(l_dns) - 1;
        while (l_end > l_dns && *l_end == ' ') *l_end-- = '\0';
        
        if (strlen(l_dns) > 0) {
            if (l_count >= l_capacity) {
                l_capacity *= 2;
                l_config->dns_servers = DAP_REALLOC(l_config->dns_servers, l_capacity * sizeof(char*));
            }
            l_config->dns_servers[l_count++] = dap_strdup(l_dns);
        }
        
        l_dns = strtok(NULL, ",");
    }
    
    l_config->dns_servers_count = l_count;
    DAP_DELETE(l_dns_copy);
    
    log_it(L_INFO, "DNS configuration created: %zu DNS servers", l_count);
    return l_config;
}

/**
 * @brief Free DNS configuration
 */
void dap_chain_net_srv_vpn_dns_config_free(dap_chain_net_srv_vpn_dns_config_t *a_dns_config)
{
    if (!a_dns_config)
        return;
    
    if (a_dns_config->dns_servers) {
        for (size_t i = 0; i < a_dns_config->dns_servers_count; i++) {
            DAP_DELETE(a_dns_config->dns_servers[i]);
        }
        DAP_DELETE(a_dns_config->dns_servers);
    }
    
    DAP_DELETE(a_dns_config);
}

/**
 * @brief Create complete traffic configuration
 */
dap_chain_net_srv_vpn_traffic_config_t* dap_chain_net_srv_vpn_traffic_config_create(
    uint32_t a_bandwidth_limit_mbps,
    uint32_t a_priority,
    const char *a_exclude_routes,
    const char *a_dns_servers,
    bool a_compression_enabled)
{
    dap_chain_net_srv_vpn_traffic_config_t *l_config = DAP_NEW_Z(dap_chain_net_srv_vpn_traffic_config_t);
    if (!l_config) {
        log_it(L_ERROR, "Failed to allocate traffic config");
        return NULL;
    }
    
    // Create shaper if bandwidth limit is set
    if (a_bandwidth_limit_mbps > 0 || a_priority != 128) {
        l_config->shaper = dap_chain_net_srv_vpn_traffic_shaper_create(a_bandwidth_limit_mbps, a_priority);
    }
    
    // Create split tunnel config if routes are provided
    if (a_exclude_routes && strlen(a_exclude_routes) > 0) {
        l_config->split_tunnel = dap_chain_net_srv_vpn_split_tunnel_create(a_exclude_routes);
    }
    
    // Create DNS config if servers are provided
    if (a_dns_servers && strlen(a_dns_servers) > 0) {
        l_config->dns_config = dap_chain_net_srv_vpn_dns_config_create(a_dns_servers);
    }
    
    l_config->compression_enabled = a_compression_enabled;
    
    log_it(L_INFO, "Traffic configuration created: shaper=%s, split_tunnel=%s, dns=%s, compression=%s",
           l_config->shaper ? "enabled" : "disabled",
           l_config->split_tunnel ? "enabled" : "disabled",
           l_config->dns_config ? "enabled" : "disabled",
           l_config->compression_enabled ? "enabled" : "disabled");
    
    return l_config;
}

/**
 * @brief Free traffic configuration
 */
void dap_chain_net_srv_vpn_traffic_config_free(dap_chain_net_srv_vpn_traffic_config_t *a_config)
{
    if (!a_config)
        return;
    
    dap_chain_net_srv_vpn_traffic_shaper_free(a_config->shaper);
    dap_chain_net_srv_vpn_split_tunnel_free(a_config->split_tunnel);
    dap_chain_net_srv_vpn_dns_config_free(a_config->dns_config);
    
    DAP_DELETE(a_config);
}

