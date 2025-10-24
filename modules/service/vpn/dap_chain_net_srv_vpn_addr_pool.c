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

#include <arpa/inet.h>
#include <string.h>
#include "dap_common.h"
#include "dap_chain_net_srv_vpn_addr_pool.h"

#define LOG_TAG "dap_chain_net_srv_vpn_addr_pool"

/**
 * @brief Initialize address pool
 */
dap_chain_net_srv_vpn_addr_pool_t* dap_chain_net_srv_vpn_addr_pool_init(
    struct in_addr a_network_addr,
    struct in_addr a_network_mask,
    struct in_addr a_gateway,
    uint32_t a_lease_duration_sec)
{
    dap_chain_net_srv_vpn_addr_pool_t *l_pool = DAP_NEW_Z(dap_chain_net_srv_vpn_addr_pool_t);
    if (!l_pool) {
        log_it(L_ERROR, "Failed to allocate address pool");
        return NULL;
    }
    
    l_pool->network_addr = a_network_addr;
    l_pool->network_mask = a_network_mask;
    l_pool->gateway = a_gateway;
    l_pool->default_lease_duration_sec = a_lease_duration_sec;
    l_pool->lease_renewal_threshold_sec = a_lease_duration_sec > 0 ? a_lease_duration_sec / 4 : 0;
    
    // Calculate address range
    uint32_t l_net_addr = ntohl(a_network_addr.s_addr);
    uint32_t l_net_mask = ntohl(a_network_mask.s_addr);
    uint32_t l_gateway = ntohl(a_gateway.s_addr);
    
    // First usable address (network + 2, skip gateway)
    l_pool->addr_min.s_addr = htonl(l_gateway + 1);
    // Last usable address (broadcast - 1)
    l_pool->addr_max.s_addr = htonl((l_net_addr | ~l_net_mask) - 1);
    // Start allocation from minimum
    l_pool->addr_current = l_pool->addr_min;
    
    // Calculate total addresses
    uint32_t l_min = ntohl(l_pool->addr_min.s_addr);
    uint32_t l_max = ntohl(l_pool->addr_max.s_addr);
    l_pool->total_addresses = (l_max >= l_min) ? (l_max - l_min + 1) : 0;
    l_pool->leased_count = 0;
    
    // Initialize structures
    l_pool->leases = NULL;
    l_pool->free_list = NULL;
    pthread_rwlock_init(&l_pool->rwlock, NULL);
    
    char l_addr_min_str[INET_ADDRSTRLEN], l_addr_max_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &l_pool->addr_min, l_addr_min_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &l_pool->addr_max, l_addr_max_str, INET_ADDRSTRLEN);
    
    log_it(L_INFO, "Address pool initialized: range %s - %s (%zu addresses), lease duration %u sec",
           l_addr_min_str, l_addr_max_str, l_pool->total_addresses, a_lease_duration_sec);
    
    return l_pool;
}

/**
 * @brief Allocate address from pool
 */
int dap_chain_net_srv_vpn_addr_pool_allocate(
    dap_chain_net_srv_vpn_addr_pool_t *a_pool,
    dap_chain_hash_fast_t *a_client_hash,
    struct in_addr *a_out_addr)
{
    if (!a_pool || !a_client_hash || !a_out_addr)
        return -1;
    
    pthread_rwlock_wrlock(&a_pool->rwlock);
    
    // Check if client already has a lease
    dap_chain_net_srv_vpn_addr_lease_t *l_existing = NULL;
    HASH_FIND(hh, a_pool->leases, a_client_hash, sizeof(*a_client_hash), l_existing);
    if (l_existing && l_existing->is_active) {
        *a_out_addr = l_existing->addr;
        l_existing->last_activity = time(NULL);
        pthread_rwlock_unlock(&a_pool->rwlock);
        log_it(L_INFO, "Client already has lease: %s", inet_ntoa(l_existing->addr));
        return 0;
    }
    
    // Try to reuse freed address from free list
    if (a_pool->free_list) {
        dap_chain_net_srv_vpn_item_ipv4_t *l_item = a_pool->free_list;
        a_pool->free_list = l_item->next;
        
        *a_out_addr = l_item->addr;
        DAP_DELETE(l_item);
        
        // Create new lease
        dap_chain_net_srv_vpn_addr_lease_t *l_lease = DAP_NEW_Z(dap_chain_net_srv_vpn_addr_lease_t);
        if (!l_lease) {
            pthread_rwlock_unlock(&a_pool->rwlock);
            return -2;
        }
        
        l_lease->addr = *a_out_addr;
        l_lease->client_hash = *a_client_hash;
        l_lease->lease_time = time(NULL);
        l_lease->last_activity = l_lease->lease_time;
        l_lease->lease_duration_sec = a_pool->default_lease_duration_sec;
        l_lease->is_active = true;
        
        HASH_ADD(hh, a_pool->leases, addr, sizeof(l_lease->addr), l_lease);
        a_pool->leased_count++;
        
        pthread_rwlock_unlock(&a_pool->rwlock);
        log_it(L_INFO, "Reused address from free list: %s", inet_ntoa(*a_out_addr));
        return 0;
    }
    
    // Allocate new address
    if (a_pool->leased_count >= a_pool->total_addresses) {
        pthread_rwlock_unlock(&a_pool->rwlock);
        log_it(L_ERROR, "Address pool exhausted (%zu/%zu addresses used)", 
               a_pool->leased_count, a_pool->total_addresses);
        return -3;
    }
    
    // Find next available address
    uint32_t l_current = ntohl(a_pool->addr_current.s_addr);
    uint32_t l_max = ntohl(a_pool->addr_max.s_addr);
    uint32_t l_attempts = 0;
    
    while (l_attempts < a_pool->total_addresses) {
        struct in_addr l_candidate;
        l_candidate.s_addr = htonl(l_current);
        
        // Check if address is already leased
        dap_chain_net_srv_vpn_addr_lease_t *l_check = NULL;
        HASH_FIND(hh, a_pool->leases, &l_candidate, sizeof(l_candidate), l_check);
        
        if (!l_check || !l_check->is_active) {
            // Address available
            *a_out_addr = l_candidate;
            
            // Create lease
            dap_chain_net_srv_vpn_addr_lease_t *l_lease = DAP_NEW_Z(dap_chain_net_srv_vpn_addr_lease_t);
            if (!l_lease) {
                pthread_rwlock_unlock(&a_pool->rwlock);
                return -4;
            }
            
            l_lease->addr = *a_out_addr;
            l_lease->client_hash = *a_client_hash;
            l_lease->lease_time = time(NULL);
            l_lease->last_activity = l_lease->lease_time;
            l_lease->lease_duration_sec = a_pool->default_lease_duration_sec;
            l_lease->is_active = true;
            
            HASH_ADD(hh, a_pool->leases, addr, sizeof(l_lease->addr), l_lease);
            a_pool->leased_count++;
            
            // Move allocation pointer forward
            l_current++;
            if (l_current > l_max) {
                l_current = ntohl(a_pool->addr_min.s_addr);
            }
            a_pool->addr_current.s_addr = htonl(l_current);
            
            pthread_rwlock_unlock(&a_pool->rwlock);
            log_it(L_INFO, "Allocated new address: %s (total: %zu/%zu)",
                   inet_ntoa(*a_out_addr), a_pool->leased_count, a_pool->total_addresses);
            return 0;
        }
        
        // Try next address
        l_current++;
        if (l_current > l_max) {
            l_current = ntohl(a_pool->addr_min.s_addr);
        }
        l_attempts++;
    }
    
    pthread_rwlock_unlock(&a_pool->rwlock);
    log_it(L_ERROR, "No available addresses found after %u attempts", l_attempts);
    return -5;
}

/**
 * @brief Release address back to pool
 */
int dap_chain_net_srv_vpn_addr_pool_release(
    dap_chain_net_srv_vpn_addr_pool_t *a_pool,
    struct in_addr a_addr)
{
    if (!a_pool)
        return -1;
    
    pthread_rwlock_wrlock(&a_pool->rwlock);
    
    dap_chain_net_srv_vpn_addr_lease_t *l_lease = NULL;
    HASH_FIND(hh, a_pool->leases, &a_addr, sizeof(a_addr), l_lease);
    
    if (!l_lease) {
        pthread_rwlock_unlock(&a_pool->rwlock);
        log_it(L_WARNING, "Attempted to release non-leased address %s", inet_ntoa(a_addr));
        return -2;
    }
    
    l_lease->is_active = false;
    
    // Add to free list for reuse
    dap_chain_net_srv_vpn_item_ipv4_t *l_item = DAP_NEW_Z(dap_chain_net_srv_vpn_item_ipv4_t);
    if (l_item) {
        l_item->addr = a_addr;
        l_item->next = a_pool->free_list;
        a_pool->free_list = l_item;
    }
    
    if (a_pool->leased_count > 0) {
        a_pool->leased_count--;
    }
    
    pthread_rwlock_unlock(&a_pool->rwlock);
    log_it(L_INFO, "Released address %s (remaining: %zu/%zu)",
           inet_ntoa(a_addr), a_pool->leased_count, a_pool->total_addresses);
    return 0;
}

/**
 * @brief Free address pool
 */
void dap_chain_net_srv_vpn_addr_pool_free(dap_chain_net_srv_vpn_addr_pool_t *a_pool)
{
    if (!a_pool)
        return;
    
    pthread_rwlock_wrlock(&a_pool->rwlock);
    
    // Free all leases
    dap_chain_net_srv_vpn_addr_lease_t *l_lease, *l_tmp;
    HASH_ITER(hh, a_pool->leases, l_lease, l_tmp) {
        HASH_DEL(a_pool->leases, l_lease);
        DAP_DELETE(l_lease);
    }
    
    // Free free list
    dap_chain_net_srv_vpn_item_ipv4_t *l_item = a_pool->free_list;
    while (l_item) {
        dap_chain_net_srv_vpn_item_ipv4_t *l_next = l_item->next;
        DAP_DELETE(l_item);
        l_item = l_next;
    }
    
    pthread_rwlock_unlock(&a_pool->rwlock);
    pthread_rwlock_destroy(&a_pool->rwlock);
    
    DAP_DELETE(a_pool);
}

/**
 * @brief Get pool statistics
 */
int dap_chain_net_srv_vpn_addr_pool_get_stats(
    dap_chain_net_srv_vpn_addr_pool_t *a_pool,
    size_t *a_out_total,
    size_t *a_out_leased,
    size_t *a_out_free)
{
    if (!a_pool)
        return -1;
    
    pthread_rwlock_rdlock(&a_pool->rwlock);
    
    if (a_out_total)
        *a_out_total = a_pool->total_addresses;
    if (a_out_leased)
        *a_out_leased = a_pool->leased_count;
    if (a_out_free)
        *a_out_free = a_pool->total_addresses - a_pool->leased_count;
    
    pthread_rwlock_unlock(&a_pool->rwlock);
    return 0;
}

