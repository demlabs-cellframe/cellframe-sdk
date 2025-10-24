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

#include <netinet/in.h>
#include <pthread.h>
#include <time.h>
#include "dap_hash.h"
#include "dap_chain_net_srv_vpn.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief IP address lease entry
 * Represents a single IP address lease to a VPN client
 */
typedef struct dap_chain_net_srv_vpn_addr_lease {
    struct in_addr addr;              // Leased address
    dap_chain_hash_fast_t client_hash; // Client public key hash
    time_t lease_time;                // When lease was created
    time_t last_activity;             // Last activity timestamp
    uint32_t lease_duration_sec;      // Lease duration (0 = unlimited)
    bool is_active;                   // Is lease currently active
    UT_hash_handle hh;                // Hash table handle
} dap_chain_net_srv_vpn_addr_lease_t;

/**
 * @brief Address pool manager
 * Manages IP address allocation and leasing for VPN service
 * Thread-safe implementation with read-write locks
 */
typedef struct dap_chain_net_srv_vpn_addr_pool {
    struct in_addr network_addr;      // Network address
    struct in_addr network_mask;      // Network mask
    struct in_addr gateway;           // Gateway address
    struct in_addr addr_min;          // First available address
    struct in_addr addr_max;          // Last available address
    struct in_addr addr_current;      // Current allocation pointer
    
    dap_chain_net_srv_vpn_addr_lease_t *leases;  // Hash table of active leases
    dap_chain_net_srv_vpn_item_ipv4_t *free_list; // List of freed addresses
    
    uint32_t default_lease_duration_sec;  // Default lease time (0 = unlimited)
    uint32_t lease_renewal_threshold_sec; // Renew when this much time left
    
    pthread_rwlock_t rwlock;          // Thread safety
    size_t total_addresses;           // Total available addresses
    size_t leased_count;              // Currently leased addresses
} dap_chain_net_srv_vpn_addr_pool_t;

/**
 * @brief Initialize address pool
 * Creates and configures a new address pool for VPN service
 * @param a_network_addr Network address
 * @param a_network_mask Network mask
 * @param a_gateway Gateway address
 * @param a_lease_duration_sec Default lease duration (0 = unlimited)
 * @return Address pool or NULL on error
 */
dap_chain_net_srv_vpn_addr_pool_t* dap_chain_net_srv_vpn_addr_pool_init(
    struct in_addr a_network_addr,
    struct in_addr a_network_mask,
    struct in_addr a_gateway,
    uint32_t a_lease_duration_sec);

/**
 * @brief Allocate address from pool
 * Allocates an IP address to a client, reusing freed addresses when possible
 * Thread-safe operation with write lock
 * @param a_pool Address pool
 * @param a_client_hash Client public key hash
 * @param a_out_addr Output address
 * @return 0 on success, negative on error
 */
int dap_chain_net_srv_vpn_addr_pool_allocate(
    dap_chain_net_srv_vpn_addr_pool_t *a_pool,
    dap_chain_hash_fast_t *a_client_hash,
    struct in_addr *a_out_addr);

/**
 * @brief Release address back to pool
 * Releases an IP address back to the pool for reuse
 * Thread-safe operation with write lock
 * @param a_pool Address pool
 * @param a_addr Address to release
 * @return 0 on success, negative on error
 */
int dap_chain_net_srv_vpn_addr_pool_release(
    dap_chain_net_srv_vpn_addr_pool_t *a_pool,
    struct in_addr a_addr);

/**
 * @brief Free address pool
 * Destroys address pool and releases all resources
 * @param a_pool Address pool
 */
void dap_chain_net_srv_vpn_addr_pool_free(dap_chain_net_srv_vpn_addr_pool_t *a_pool);

/**
 * @brief Get pool statistics
 * Returns current statistics about address pool usage
 * Thread-safe operation with read lock
 * @param a_pool Address pool
 * @param a_out_total Output total addresses
 * @param a_out_leased Output leased addresses
 * @param a_out_free Output free addresses
 * @return 0 on success, negative on error
 */
int dap_chain_net_srv_vpn_addr_pool_get_stats(
    dap_chain_net_srv_vpn_addr_pool_t *a_pool,
    size_t *a_out_total,
    size_t *a_out_leased,
    size_t *a_out_free);

#ifdef __cplusplus
}
#endif

