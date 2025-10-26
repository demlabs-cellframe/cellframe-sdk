/**
 * @file dap_chain_net_srv_vpn_internal.h
 * @brief Internal API for VPN service modules
 * @details Shared structures, forward declarations, and helper functions
 *          for internal use between VPN service modules
 * @date 2025-10-25
 */

#pragma once

#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_client.h"
#include "dap_chain_net_srv_stream_session.h"
#include "dap_stream_ch.h"
#include "dap_events_socket.h"
#include "dap_worker.h"
#include "dap_config.h"
#include "dap_chain_net.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net_srv_vpn_addr_pool.h"
#include "dap_chain_net_srv_vpn_traffic.h"
#include "dap_chain_net_srv_vpn_multihop.h"
#include "dap_chain_net_srv_vpn_tsd.h"
#include "../tun/include/dap_net_tun.h"
#include <netinet/in.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_TAG "dap_chain_net_srv_vpn"

// Maximum number of events for TUN socket handling
#define SF_MAX_EVENTS 256

// VPN custom data structure for JSON parsing
typedef struct dap_chain_net_srv_vpn_custom_data {
    // Routing preferences
    bool prefer_ipv6;
    bool split_tunneling;
    char *exclude_routes;  // Comma-separated CIDR list
    
    // QoS settings
    uint32_t bandwidth_limit_mbps;  // 0 = unlimited
    uint32_t priority;  // 0-255, higher = higher priority
    
    // Protocol preferences
    char *preferred_transport;  // "udp", "ws", "http", "tls"
    bool allow_fallback;
    
    // Advanced options
    uint32_t keepalive_interval_sec;
    bool compression_enabled;
    char *dns_servers;  // Comma-separated DNS IPs
    
    // Multi-hop parameters (parsed from payment TX TSD)
    bool is_multihop;
    uint8_t hop_index;              // This node's position in route
    uint8_t total_hops;             // Total hops in route
    uint8_t tunnel_count;           // Number of parallel tunnels
    uint32_t session_id;            // Multi-hop session ID
    dap_chain_node_addr_t *route;  // Complete route (all hop addresses)
} dap_chain_net_srv_vpn_custom_data_t;

/**
 * @brief VPN session private data (stored in session->custom_data)
 * @details Stores VPN-specific data that doesn't fit in standard session structure
 */
typedef struct dap_chain_net_srv_vpn_session_data {
    size_t receipt_next_size;  // Size of receipt_next for validation (SAFETY: store size locally)
    void *traffic_config;      // Pointer to traffic configuration
} dap_chain_net_srv_vpn_session_data_t;

/**
 * @brief Arguments for async remain_limits save callback
 */
typedef struct {
    dap_chain_net_srv_t * srv;
    uint32_t usage_id;
    dap_chain_net_srv_client_remote_t * srv_client;
} remain_limits_save_arg_t;

// Simplified server structure - platform-specific details moved to platform modules
typedef struct vpn_local_network {
    struct in_addr ipv4_lease_last;
    struct in_addr ipv4_network_addr;
    struct in_addr ipv4_network_mask;
    struct in_addr ipv4_gw;
    char *tun_device_name;
    bool auto_cpu_reassignment;
} vpn_local_network_t;

//==============================================================================
// Global state (defined in dap_chain_net_srv_vpn.c)
// Note: Using g_ prefix for global extern variables per DAP SDK conventions
//==============================================================================

// TUN device handle
extern dap_net_tun_t *g_vpn_tun_handle;
extern uint32_t g_vpn_tun_sockets_count;
extern bool g_vpn_debug_more;

// TUN sockets management
extern dap_chain_net_srv_vpn_tun_socket_t **g_vpn_tun_sockets;
extern dap_events_socket_t **g_vpn_tun_sockets_queue_msg;
extern uint32_t g_vpn_tun_sockets_started;
extern pthread_mutex_t g_vpn_tun_sockets_mutex_started;
extern pthread_cond_t g_vpn_tun_sockets_cond_started;

// Client addresses list
extern dap_chain_net_srv_ch_vpn_t *g_vpn_ch_vpn_addrs;
extern pthread_rwlock_t g_vpn_clients_rwlock;

// Server configuration
extern vpn_local_network_t *g_vpn_raw_server;
extern pthread_rwlock_t g_vpn_raw_server_rwlock;

// Address pool manager
extern dap_chain_net_srv_vpn_addr_pool_t *g_vpn_addr_pool;

//==============================================================================
// Forward declarations for internal modules
//==============================================================================

// Service callbacks (dap_chain_net_srv_vpn_callbacks.c)
int srv_vpn_callback_requested(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id,
                                dap_chain_net_srv_client_remote_t *a_srv_client,
                                const void *a_custom_data, size_t a_custom_data_size);

int srv_vpn_callback_response_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id,
                                       dap_chain_net_srv_client_remote_t *a_srv_client,
                                       const void *a_custom_data, size_t a_custom_data_size);

int srv_vpn_callback_response_error(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id,
                                     dap_chain_net_srv_client_remote_t *a_srv_client,
                                     const void *a_custom_data, size_t a_custom_data_size);

int srv_vpn_callback_receipt_next_success(dap_chain_net_srv_t *a_srv, uint32_t a_usage_id,
                                           dap_chain_net_srv_client_remote_t *a_srv_client,
                                           const void *a_receipt_next, size_t a_receipt_next_size);

dap_stream_ch_chain_net_srv_remain_service_store_t* srv_vpn_callback_get_remain_service(
    dap_chain_net_srv_t *a_srv, uint32_t usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client);

int srv_vpn_callback_save_remain_service(dap_chain_net_srv_t *a_srv, uint32_t usage_id,
                                          dap_chain_net_srv_client_remote_t *a_srv_client);

// Stream channel handlers (dap_chain_net_srv_vpn_stream.c)
void srv_vpn_stream_ch_new(dap_stream_ch_t *ch, void *arg);
void srv_vpn_stream_ch_delete(dap_stream_ch_t *ch, void *arg);
bool srv_vpn_stream_ch_packet_in(dap_stream_ch_t *ch, void *a_arg);
bool srv_vpn_stream_ch_packet_out(dap_stream_ch_t *ch, void *arg);
void srv_vpn_stream_esocket_assigned(dap_events_socket_t *a_es, dap_worker_t *l_worker);
void srv_vpn_stream_esocket_unassigned(dap_events_socket_t *a_es, dap_worker_t *l_worker);

// TUN device management (dap_chain_net_srv_vpn_tun.c)
int vpn_srv_tun_init(void);
int vpn_srv_tun_create(dap_config_t *a_config);
dap_events_socket_t* vpn_srv_tun_event_stream_create(dap_worker_t *a_worker, int a_tun_fd);
void vpn_srv_tun_data_received_callback(dap_net_tun_t *a_tun,
                                         const void *a_data, size_t a_data_size,
                                         const dap_net_tun_channel_info_t *a_channel_info,
                                         void *a_arg);
void vpn_srv_tun_error_callback(dap_net_tun_t *a_tun, int a_error, const char *a_error_msg, void *a_arg);
void vpn_srv_es_tun_new(dap_events_socket_t *a_es, void *a_arg);
void vpn_srv_es_tun_delete(dap_events_socket_t *a_es, void *a_arg);
void vpn_srv_es_tun_read(dap_events_socket_t *a_es, void *a_arg);
bool vpn_srv_es_tun_write(dap_events_socket_t *a_es, void *a_arg);
void vpn_srv_es_tun_write_finished(dap_events_socket_t *a_es, void *a_arg);
void vpn_srv_es_tun_error(dap_events_socket_t *a_es, int a_error);

// Session management (dap_chain_net_srv_vpn_session.c)
dap_chain_net_srv_ch_vpn_t* vpn_srv_session_find_by_ip(struct in_addr a_ip_dst);
dap_chain_net_srv_ch_vpn_t* vpn_srv_session_find_by_stream(dap_stream_ch_t *a_ch);
int vpn_srv_session_add(dap_chain_net_srv_ch_vpn_t *a_ch_vpn);
int vpn_srv_session_remove(dap_chain_net_srv_ch_vpn_t *a_ch_vpn);
void vpn_srv_session_cleanup_all(void);
int vpn_srv_session_tun_socket_add(uint32_t a_worker_id,
                                    dap_chain_net_srv_ch_vpn_t *a_ch_vpn,
                                    dap_events_socket_t *a_esocket);
int vpn_srv_session_tun_socket_remove(uint32_t a_worker_id, struct in_addr a_addr);
int vpn_srv_session_tun_socket_update_worker(uint32_t a_worker_id,
                                               struct in_addr a_addr,
                                               uint32_t a_new_worker_id);

// Traffic limits & stats (dap_chain_net_srv_vpn_limits.c)
void vpn_srv_limits_update(dap_stream_ch_t *a_ch,
                            dap_chain_net_srv_stream_session_t *a_srv_session,
                            dap_chain_net_srv_usage_t *a_usage,
                            size_t a_bytes);
bool vpn_srv_limits_save(void *a_arg);
dap_stream_ch_chain_net_srv_remain_service_store_t* vpn_srv_limits_get_remain_service(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client);
int vpn_srv_limits_save_remain_service(dap_chain_net_srv_t *a_srv,
                                        uint32_t a_usage_id,
                                        dap_chain_net_srv_client_remote_t *a_srv_client);
char* vpn_srv_limits_get_pkey_str(dap_chain_net_srv_usage_t *a_usage);

//==============================================================================
// Internal helper functions
//==============================================================================

/**
 * @brief Parse VPN custom data from JSON
 * @param a_json_str JSON string
 * @return Parsed custom data structure, NULL on error
 */
static inline dap_chain_net_srv_vpn_custom_data_t* parse_vpn_custom_data(const char *a_json_str) {
    if (!a_json_str)
        return NULL;
    
    // TODO: Implement JSON parsing using json-c
    // For now, return NULL to avoid unused warnings
    (void)a_json_str;
    return NULL;
}

/**
 * @brief Free VPN custom data structure
 * @param a_data Custom data to free
 */
static inline void free_vpn_custom_data(dap_chain_net_srv_vpn_custom_data_t *a_data) {
    if (!a_data)
        return;
    
    DAP_DELETE(a_data->exclude_routes);
    DAP_DELETE(a_data->preferred_transport);
    DAP_DELETE(a_data->dns_servers);
    DAP_DELETE(a_data->route);
    DAP_DELETE(a_data);
}

/**
 * @brief Get client by destination IP (thread-safe)
 * @param a_ip_dst Destination IP address
 * @return Client structure or NULL if not found
 */
static inline dap_chain_net_srv_ch_vpn_t* get_client_by_ip_safe(struct in_addr a_ip_dst) {
    pthread_rwlock_rdlock(&g_vpn_clients_rwlock);
    dap_chain_net_srv_ch_vpn_t *l_client = vpn_srv_session_find_by_ip(a_ip_dst);
    pthread_rwlock_unlock(&g_vpn_clients_rwlock);
    return l_client;
}

/**
 * @brief Log packet for debugging
 * @param a_prefix Log prefix
 * @param a_data Packet data
 * @param a_data_size Packet size
 */
static inline void debug_log_packet(const char *a_prefix, const uint8_t *a_data, size_t a_data_size) {
    if (!g_vpn_debug_more || !a_data || a_data_size == 0)
        return;
    
    log_it(L_DEBUG, "%s: packet size %zu bytes", a_prefix, a_data_size);
    
    // Log IP header if present
    if (a_data_size >= 20) {
        uint8_t l_version = (a_data[0] >> 4) & 0x0F;
        uint8_t l_protocol = a_data[9];
        log_it(L_DEBUG, "  IP version: %u, protocol: %u", l_version, l_protocol);
    }
}

#ifdef __cplusplus
}
#endif

