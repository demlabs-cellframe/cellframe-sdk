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

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Traffic shaping configuration
 * Controls bandwidth limiting and QoS for VPN traffic
 */
typedef struct dap_chain_net_srv_vpn_traffic_shaper {
    uint32_t bandwidth_limit_bps;     // Bandwidth limit in bytes per second (0 = unlimited)
    uint32_t priority;                // Priority level (0-255, higher = higher priority)
    
    // Token bucket algorithm for rate limiting
    uint64_t tokens;                  // Current token count
    uint64_t max_tokens;              // Maximum tokens (burst size)
    time_t last_refill;               // Last token refill timestamp
    
    // Statistics
    uint64_t bytes_sent;              // Total bytes sent
    uint64_t bytes_dropped;           // Bytes dropped due to rate limiting
    uint64_t packets_sent;            // Total packets sent
    uint64_t packets_dropped;         // Packets dropped due to rate limiting
    
    pthread_mutex_t mutex;            // Thread safety
} dap_chain_net_srv_vpn_traffic_shaper_t;

/**
 * @brief Split tunneling configuration
 * Defines which routes should bypass VPN tunnel
 */
typedef struct dap_chain_net_srv_vpn_split_tunnel {
    char **exclude_routes;            // Array of CIDR routes to exclude
    size_t exclude_routes_count;      // Number of excluded routes
    bool enabled;                     // Split tunneling enabled
} dap_chain_net_srv_vpn_split_tunnel_t;

/**
 * @brief DNS configuration for VPN session
 */
typedef struct dap_chain_net_srv_vpn_dns_config {
    char **dns_servers;               // Array of DNS server IPs
    size_t dns_servers_count;         // Number of DNS servers
    bool override_system_dns;         // Override system DNS settings
} dap_chain_net_srv_vpn_dns_config_t;

/**
 * @brief VPN session traffic configuration
 * Aggregates all traffic management settings
 */
typedef struct dap_chain_net_srv_vpn_traffic_config {
    dap_chain_net_srv_vpn_traffic_shaper_t *shaper;      // Traffic shaping
    dap_chain_net_srv_vpn_split_tunnel_t *split_tunnel;  // Split tunneling
    dap_chain_net_srv_vpn_dns_config_t *dns_config;      // DNS configuration
    bool compression_enabled;                              // Compression enabled
} dap_chain_net_srv_vpn_traffic_config_t;

/**
 * @brief Initialize traffic shaper
 * @param a_bandwidth_limit_mbps Bandwidth limit in Mbps (0 = unlimited)
 * @param a_priority Priority level (0-255)
 * @return Traffic shaper or NULL on error
 */
dap_chain_net_srv_vpn_traffic_shaper_t* dap_chain_net_srv_vpn_traffic_shaper_create(
    uint32_t a_bandwidth_limit_mbps,
    uint32_t a_priority);

/**
 * @brief Check if packet can be sent according to rate limit
 * Implements token bucket algorithm
 * @param a_shaper Traffic shaper
 * @param a_packet_size Packet size in bytes
 * @return true if packet can be sent, false if dropped
 */
bool dap_chain_net_srv_vpn_traffic_shaper_allow(
    dap_chain_net_srv_vpn_traffic_shaper_t *a_shaper,
    size_t a_packet_size);

/**
 * @brief Free traffic shaper
 * @param a_shaper Traffic shaper
 */
void dap_chain_net_srv_vpn_traffic_shaper_free(dap_chain_net_srv_vpn_traffic_shaper_t *a_shaper);

/**
 * @brief Create split tunneling configuration
 * @param a_exclude_routes Comma-separated CIDR routes to exclude
 * @return Split tunnel config or NULL on error
 */
dap_chain_net_srv_vpn_split_tunnel_t* dap_chain_net_srv_vpn_split_tunnel_create(
    const char *a_exclude_routes);

/**
 * @brief Check if packet should bypass VPN tunnel
 * @param a_split_tunnel Split tunnel config
 * @param a_dest_ip Destination IP address
 * @return true if packet should bypass tunnel
 */
bool dap_chain_net_srv_vpn_split_tunnel_should_bypass(
    dap_chain_net_srv_vpn_split_tunnel_t *a_split_tunnel,
    const char *a_dest_ip);

/**
 * @brief Free split tunneling configuration
 * @param a_split_tunnel Split tunnel config
 */
void dap_chain_net_srv_vpn_split_tunnel_free(dap_chain_net_srv_vpn_split_tunnel_t *a_split_tunnel);

/**
 * @brief Create DNS configuration
 * @param a_dns_servers Comma-separated DNS server IPs
 * @return DNS config or NULL on error
 */
dap_chain_net_srv_vpn_dns_config_t* dap_chain_net_srv_vpn_dns_config_create(
    const char *a_dns_servers);

/**
 * @brief Free DNS configuration
 * @param a_dns_config DNS config
 */
void dap_chain_net_srv_vpn_dns_config_free(dap_chain_net_srv_vpn_dns_config_t *a_dns_config);

/**
 * @brief Create complete traffic configuration from custom data
 * @param a_bandwidth_limit_mbps Bandwidth limit
 * @param a_priority Priority level
 * @param a_exclude_routes Split tunnel routes
 * @param a_dns_servers DNS servers
 * @param a_compression_enabled Compression flag
 * @return Traffic config or NULL on error
 */
dap_chain_net_srv_vpn_traffic_config_t* dap_chain_net_srv_vpn_traffic_config_create(
    uint32_t a_bandwidth_limit_mbps,
    uint32_t a_priority,
    const char *a_exclude_routes,
    const char *a_dns_servers,
    bool a_compression_enabled);

/**
 * @brief Free traffic configuration
 * @param a_config Traffic config
 */
void dap_chain_net_srv_vpn_traffic_config_free(dap_chain_net_srv_vpn_traffic_config_t *a_config);

#ifdef __cplusplus
}
#endif

