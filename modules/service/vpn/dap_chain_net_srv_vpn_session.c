/**
 * @file dap_chain_net_srv_vpn_session.c
 * @brief VPN Service Session Management Implementation
 * @details Client session tracking using uthash, worker affinity management
 * 
 * @date 2025-10-25
 * @copyright (C) 2023-2025 Cellframe Network
 */

#include "dap_chain_net_srv_vpn_session.h"
#include "dap_chain_net_srv_vpn_internal.h"
#include "dap_common.h"
#include "uthash.h"
#include <arpa/inet.h>
#include <pthread.h>

#define LOG_TAG "dap_chain_net_srv_vpn_session"

/**
 * @brief Find VPN client session by destination IP address (thread-safe)
 */
dap_chain_net_srv_ch_vpn_t* vpn_srv_session_find_by_ip(struct in_addr a_ip_dst)
{
    pthread_rwlock_rdlock(&g_vpn_clients_rwlock);
    dap_chain_net_srv_ch_vpn_t *l_client = NULL;
    HASH_FIND(hh, g_vpn_ch_vpn_addrs, &a_ip_dst, sizeof(struct in_addr), l_client);
    pthread_rwlock_unlock(&g_vpn_clients_rwlock);
    
    return l_client;
}

/**
 * @brief Find VPN client session by stream channel
 */
dap_chain_net_srv_ch_vpn_t* vpn_srv_session_find_by_stream(dap_stream_ch_t *a_ch)
{
    if (!a_ch || !a_ch->stream || !a_ch->stream->session) {
        return NULL;
    }
    
    // Get VPN channel from stream session
    dap_chain_net_srv_ch_vpn_t *l_ch_vpn = (dap_chain_net_srv_ch_vpn_t *)a_ch->internal;
    return l_ch_vpn;
}

/**
 * @brief Add new client session to global registry (thread-safe)
 */
int vpn_srv_session_add(dap_chain_net_srv_ch_vpn_t *a_ch_vpn)
{
    if (!a_ch_vpn) {
        log_it(L_ERROR, "NULL client passed to session_add");
        return -1;
    }
    
    if (a_ch_vpn->addr_ipv4.s_addr == 0) {
        log_it(L_ERROR, "Client has no IP address assigned");
        return -2;
    }
    
    pthread_rwlock_wrlock(&g_vpn_clients_rwlock);
    
    // Check if already exists
    dap_chain_net_srv_ch_vpn_t *l_existing = NULL;
    HASH_FIND(hh, g_vpn_ch_vpn_addrs, &a_ch_vpn->addr_ipv4, sizeof(struct in_addr), l_existing);
    
    if (l_existing) {
        pthread_rwlock_unlock(&g_vpn_clients_rwlock);
        log_it(L_WARNING, "Client with IP %s already exists in registry",
               inet_ntoa(a_ch_vpn->addr_ipv4));
        return -3;
    }
    
    // Add to global hash table
    HASH_ADD(hh, g_vpn_ch_vpn_addrs, addr_ipv4, sizeof(a_ch_vpn->addr_ipv4), a_ch_vpn);
    pthread_rwlock_unlock(&g_vpn_clients_rwlock);
    
    if (dap_log_level_get() <= L_INFO) {
        log_it(L_INFO, "Added client session: %s", inet_ntoa(a_ch_vpn->addr_ipv4));
    }
    
    return 0;
}

/**
 * @brief Remove client session from global registry (thread-safe)
 */
int vpn_srv_session_remove(dap_chain_net_srv_ch_vpn_t *a_ch_vpn)
{
    if (!a_ch_vpn) {
        log_it(L_ERROR, "NULL client passed to session_remove");
        return -1;
    }
    
    pthread_rwlock_wrlock(&g_vpn_clients_rwlock);
    
    if (g_vpn_ch_vpn_addrs) {
        HASH_DEL(g_vpn_ch_vpn_addrs, a_ch_vpn);
    }
    
    pthread_rwlock_unlock(&g_vpn_clients_rwlock);
    
    if (dap_log_level_get() <= L_INFO) {
        log_it(L_INFO, "Removed client session: %s", inet_ntoa(a_ch_vpn->addr_ipv4));
    }
    
    return 0;
}

/**
 * @brief Cleanup all client sessions (on service deinit)
 */
void vpn_srv_session_cleanup_all(void)
{
    pthread_rwlock_wrlock(&g_vpn_clients_rwlock);
    
    dap_chain_net_srv_ch_vpn_t *l_client, *l_tmp;
    HASH_ITER(hh, g_vpn_ch_vpn_addrs, l_client, l_tmp) {
        HASH_DEL(g_vpn_ch_vpn_addrs, l_client);
        DAP_DELETE(l_client);
    }
    
    g_vpn_ch_vpn_addrs = NULL;
    pthread_rwlock_unlock(&g_vpn_clients_rwlock);
    
    log_it(L_INFO, "All client sessions cleaned up");
}

/**
 * @brief Add client to worker-local TUN socket registry
 */
int vpn_srv_session_tun_socket_add(uint32_t a_worker_id,
                                    dap_chain_net_srv_ch_vpn_t *a_ch_vpn,
                                    dap_events_socket_t *a_esocket)
{
    if (a_worker_id >= g_vpn_tun_sockets_count) {
        log_it(L_ERROR, "Invalid worker ID: %u (max: %u)", a_worker_id, g_vpn_tun_sockets_count);
        return -1;
    }
    
    if (!a_ch_vpn || !a_esocket) {
        log_it(L_ERROR, "NULL arguments passed to tun_socket_add");
        return -2;
    }
    
    dap_chain_net_srv_vpn_tun_socket_t *l_tun_sock = g_vpn_tun_sockets[a_worker_id];
    if (!l_tun_sock) {
        log_it(L_ERROR, "TUN socket for worker %u not initialized", a_worker_id);
        return -3;
    }
    
    // Check if already exists
    dap_chain_net_srv_ch_vpn_info_t *l_existing = NULL;
    HASH_FIND(hh, l_tun_sock->clients, &a_ch_vpn->addr_ipv4, sizeof(struct in_addr), l_existing);
    
    if (l_existing) {
        log_it(L_WARNING, "Client %s already in TUN socket %u registry",
               inet_ntoa(a_ch_vpn->addr_ipv4), a_worker_id);
        return -4;
    }
    
    // Create new info structure
    dap_chain_net_srv_ch_vpn_info_t *l_new_info = DAP_NEW_Z(dap_chain_net_srv_ch_vpn_info_t);
    if (!l_new_info) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -5;
    }
    
    l_new_info->ch_vpn = a_ch_vpn;
    l_new_info->esocket = a_esocket;
    l_new_info->esocket_uuid = a_esocket->uuid;
    l_new_info->addr_ipv4.s_addr = a_ch_vpn->addr_ipv4.s_addr;
    l_new_info->worker = dap_events_worker_get(a_worker_id);
    l_new_info->is_on_this_worker = true;
    
    // Add to worker-local hash table
    HASH_ADD(hh, l_tun_sock->clients, addr_ipv4, sizeof(l_new_info->addr_ipv4), l_new_info);
    
    if (dap_log_level_get() <= L_INFO) {
        log_it(L_INFO, "Added client %s to TUN socket worker %u",
               inet_ntoa(a_ch_vpn->addr_ipv4), a_worker_id);
    }
    
    return 0;
}

/**
 * @brief Remove client from worker-local TUN socket registry
 */
int vpn_srv_session_tun_socket_remove(uint32_t a_worker_id, struct in_addr a_addr)
{
    if (a_worker_id >= g_vpn_tun_sockets_count) {
        log_it(L_ERROR, "Invalid worker ID: %u (max: %u)", a_worker_id, g_vpn_tun_sockets_count);
        return -1;
    }
    
    dap_chain_net_srv_vpn_tun_socket_t *l_tun_sock = g_vpn_tun_sockets[a_worker_id];
    if (!l_tun_sock) {
        log_it(L_ERROR, "TUN socket for worker %u not initialized", a_worker_id);
        return -2;
    }
    
    dap_chain_net_srv_ch_vpn_info_t *l_info = NULL;
    HASH_FIND(hh, l_tun_sock->clients, &a_addr, sizeof(struct in_addr), l_info);
    
    if (!l_info) {
        log_it(L_WARNING, "Client %s not found in TUN socket %u registry",
               inet_ntoa(a_addr), a_worker_id);
        return -3;
    }
    
    HASH_DELETE(hh, l_tun_sock->clients, l_info);
    DAP_DELETE(l_info);
    
    if (dap_log_level_get() <= L_INFO) {
        log_it(L_INFO, "Removed client %s from TUN socket worker %u",
               inet_ntoa(a_addr), a_worker_id);
    }
    
    return 0;
}

/**
 * @brief Update client worker affinity after reassignment
 */
int vpn_srv_session_tun_socket_update_worker(uint32_t a_worker_id,
                                               struct in_addr a_addr,
                                               uint32_t a_new_worker_id)
{
    if (a_worker_id >= g_vpn_tun_sockets_count || a_new_worker_id >= g_vpn_tun_sockets_count) {
        log_it(L_ERROR, "Invalid worker IDs: %u -> %u (max: %u)",
               a_worker_id, a_new_worker_id, g_vpn_tun_sockets_count);
        return -1;
    }
    
    dap_chain_net_srv_vpn_tun_socket_t *l_tun_sock = g_vpn_tun_sockets[a_worker_id];
    if (!l_tun_sock) {
        log_it(L_ERROR, "TUN socket for worker %u not initialized", a_worker_id);
        return -2;
    }
    
    dap_chain_net_srv_ch_vpn_info_t *l_info = NULL;
    HASH_FIND(hh, l_tun_sock->clients, &a_addr, sizeof(struct in_addr), l_info);
    
    if (!l_info) {
        log_it(L_WARNING, "Client %s not found in TUN socket %u registry",
               inet_ntoa(a_addr), a_worker_id);
        return -3;
    }
    
    // Update worker affinity
    l_info->worker = dap_events_worker_get(a_new_worker_id);
    l_info->is_on_this_worker = (a_worker_id == a_new_worker_id);
    
    if (dap_log_level_get() <= L_INFO) {
        log_it(L_INFO, "Updated client %s worker affinity: %u -> %u",
               inet_ntoa(a_addr), a_worker_id, a_new_worker_id);
    }
    
    return 0;
}


