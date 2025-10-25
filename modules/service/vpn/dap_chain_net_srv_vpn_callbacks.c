/**
 * @file dap_chain_net_srv_vpn_callbacks.c
 * @brief VPN Service Callbacks Module Implementation
 * @details Service lifecycle callbacks (requested, response_success, response_error, receipt_next_success, etc.)
 * 
 * @date 2025-10-25
 * @copyright (C) 2023-2025 Cellframe Network
 */

#include "dap_chain_net_srv_vpn_callbacks.h"
#include "dap_chain_net_srv_vpn_internal.h"
#include "dap_chain_net_srv_vpn_multihop.h"
#include "dap_chain_net_srv_vpn_traffic.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_json_rpc_errors.h"
#include "dap_enc_key.h"
#include "json.h"
#include <time.h>

#define LOG_TAG "dap_chain_net_srv_vpn_callbacks"

// Helper function declarations (internal to this module)
static dap_chain_net_srv_vpn_custom_data_t *s_parse_vpn_custom_data_json(const void *a_custom_data, size_t a_custom_data_size);
static void s_free_vpn_custom_data(dap_chain_net_srv_vpn_custom_data_t *a_custom);
static bool s_parse_multihop_tsd_from_payment_tx(dap_chain_net_srv_vpn_custom_data_t *a_custom, dap_chain_datum_tx_t *a_payment_tx);
static void s_vpn_session_data_delete(void *a_data);

/**
 * @brief Free VPN session data callback
 */
static void s_vpn_session_data_delete(void *a_data)
{
    if (a_data) {
        dap_chain_net_srv_vpn_session_data_t *l_data = (dap_chain_net_srv_vpn_session_data_t *)a_data;
        // traffic_config is managed separately, just free the structure
        DAP_DEL_Z(l_data);
    }
}

/**
 * @brief Parse VPN custom data from JSON
 * @details Parses client-provided custom data (transport preferences, bandwidth, QoS, DNS, etc.)
 */
static dap_chain_net_srv_vpn_custom_data_t *s_parse_vpn_custom_data_json(
    const void *a_custom_data,
    size_t a_custom_data_size)
{
    if (!a_custom_data || !a_custom_data_size) {
        return NULL;
    }
    
    json_object *l_jobj = json_tokener_parse(a_custom_data);
    if (!l_jobj) {
        log_it(L_WARNING, "Failed to parse custom data JSON");
        return NULL;
    }
    
    dap_chain_net_srv_vpn_custom_data_t *l_custom = DAP_NEW_Z(dap_chain_net_srv_vpn_custom_data_t);
    if (!l_custom) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        json_object_put(l_jobj);
        return NULL;
    }
    
    // Parse bandwidth limit
    json_object *l_bandwidth = NULL;
    if (json_object_object_get_ex(l_jobj, "bandwidth_limit_mbps", &l_bandwidth)) {
        l_custom->bandwidth_limit_mbps = (uint32_t)json_object_get_int64(l_bandwidth);
    }
    
    // Parse priority (QoS)
    json_object *l_priority = NULL;
    if (json_object_object_get_ex(l_jobj, "priority", &l_priority)) {
        l_custom->priority = (uint8_t)json_object_get_int(l_priority);
    }
    
    // Parse split tunneling
    json_object *l_split_tunnel = NULL;
    if (json_object_object_get_ex(l_jobj, "split_tunneling", &l_split_tunnel)) {
        l_custom->split_tunneling = json_object_get_boolean(l_split_tunnel);
    }
    
    // Parse exclude routes
    json_object *l_exclude_routes = NULL;
    if (json_object_object_get_ex(l_jobj, "exclude_routes", &l_exclude_routes)) {
        const char *l_routes = json_object_get_string(l_exclude_routes);
        if (l_routes) {
            l_custom->exclude_routes = dap_strdup(l_routes);
        }
    }
    
    // Parse protocol preferences
    json_object *l_preferred_transport = NULL;
    if (json_object_object_get_ex(l_jobj, "preferred_transport", &l_preferred_transport)) {
        const char *l_transport = json_object_get_string(l_preferred_transport);
        if (l_transport) {
            l_custom->preferred_transport = dap_strdup(l_transport);
        }
    }
    
    json_object *l_allow_fallback = NULL;
    if (json_object_object_get_ex(l_jobj, "allow_fallback", &l_allow_fallback)) {
        l_custom->allow_fallback = json_object_get_boolean(l_allow_fallback);
    }
    
    // Parse advanced options
    json_object *l_keepalive = NULL;
    if (json_object_object_get_ex(l_jobj, "keepalive_interval_sec", &l_keepalive)) {
        l_custom->keepalive_interval_sec = (uint32_t)json_object_get_int64(l_keepalive);
    }
    
    json_object *l_compression = NULL;
    if (json_object_object_get_ex(l_jobj, "compression_enabled", &l_compression)) {
        l_custom->compression_enabled = json_object_get_boolean(l_compression);
    }
    
    json_object *l_dns = NULL;
    if (json_object_object_get_ex(l_jobj, "dns_servers", &l_dns)) {
        const char *l_dns_str = json_object_get_string(l_dns);
        if (l_dns_str) {
            l_custom->dns_servers = dap_strdup(l_dns_str);
        }
    }
    
    json_object_put(l_jobj);
    
    log_it(L_INFO, "VPN custom data parsed: transport=%s, bandwidth=%u Mbps, priority=%u, split_tunnel=%d",
           l_custom->preferred_transport ? l_custom->preferred_transport : "default",
           l_custom->bandwidth_limit_mbps,
           l_custom->priority,
           l_custom->split_tunneling);
    
    return l_custom;
}

/**
 * @brief Free VPN custom data structure
 */
static void s_free_vpn_custom_data(dap_chain_net_srv_vpn_custom_data_t *a_custom)
{
    if (!a_custom) return;
    
    DAP_DELETE(a_custom->exclude_routes);
    DAP_DELETE(a_custom->preferred_transport);
    DAP_DELETE(a_custom->dns_servers);
    DAP_DELETE(a_custom->route);
    DAP_DELETE(a_custom);
}

/**
 * @brief Parse multi-hop TSD data from payment transaction
 * @details Full implementation of TSD parsing for multi-hop VPN routing
 */
static bool s_parse_multihop_tsd_from_payment_tx(
    dap_chain_net_srv_vpn_custom_data_t *a_custom,
    dap_chain_datum_tx_t *a_payment_tx)
{
    if (!a_custom || !a_payment_tx) {
        return false;
    }
    
    // Search for TSD sections in transaction
    int l_tsd_count = 0;
    dap_list_t *l_tsd_list = dap_chain_datum_tx_items_get(
        a_payment_tx, TX_ITEM_TYPE_TSD, &l_tsd_count);
    
    if (!l_tsd_list || l_tsd_count == 0) {
        // No TSD data - this is not a multi-hop transaction
        a_custom->is_multihop = false;
        dap_list_free(l_tsd_list);
        return false;
    }
    
    bool l_found_multihop = false;
    
    // Parse TSD sections
    for (dap_list_t *l_iter = l_tsd_list; l_iter; l_iter = l_iter->next) {
        dap_chain_tx_tsd_t *l_tsd = (dap_chain_tx_tsd_t *)l_iter->data;
        if (!l_tsd || l_tsd->header.size < 1) {
            continue;
        }
        
        // TSD type determines what data it contains
        switch (l_tsd->header.type) {
            case 0x01: { // VPN_TSD_HOP_INDEX
                if (l_tsd->header.size >= sizeof(uint8_t)) {
                    a_custom->hop_index = *(uint8_t *)l_tsd->tsd;
                    l_found_multihop = true;
                    log_it(L_INFO, "Multi-hop TX detected: hop_index=%u", a_custom->hop_index);
                }
                break;
            }
            
            case 0x02: { // VPN_TSD_TOTAL_HOPS
                if (l_tsd->header.size >= sizeof(uint8_t)) {
                    a_custom->total_hops = *(uint8_t *)l_tsd->tsd;
                    log_it(L_DEBUG, "Total hops: %u", a_custom->total_hops);
                }
                break;
            }
            
            case 0x03: { // VPN_TSD_TUNNEL_COUNT
                if (l_tsd->header.size >= sizeof(uint8_t)) {
                    a_custom->tunnel_count = *(uint8_t *)l_tsd->tsd;
                    log_it(L_DEBUG, "Tunnel count: %u", a_custom->tunnel_count);
                } else {
                    a_custom->tunnel_count = 1;
                }
                break;
            }
            
            case 0x04: { // VPN_TSD_SESSION_ID
                if (l_tsd->header.size >= sizeof(uint32_t)) {
                    a_custom->session_id = *(uint32_t *)l_tsd->tsd;
                    log_it(L_DEBUG, "Session ID: %u", a_custom->session_id);
                }
                break;
            }
            
            case 0x05: { // VPN_TSD_ROUTE
                // Route is array of node addresses
                size_t l_hop_count = l_tsd->header.size / sizeof(dap_chain_node_addr_t);
                if (l_hop_count > 0 && l_hop_count <= 16) {
                    a_custom->route = DAP_NEW_SIZE(dap_chain_node_addr_t, l_tsd->header.size);
                    if (a_custom->route) {
                        memcpy(a_custom->route, l_tsd->tsd, l_tsd->header.size);
                        a_custom->total_hops = (uint8_t)l_hop_count;
                        log_it(L_DEBUG, "Route parsed: %zu hops", l_hop_count);
                    }
                }
                break;
            }
            
            default:
                // Unknown TSD type - skip
                break;
        }
    }
    
    dap_list_free(l_tsd_list);
    
    a_custom->is_multihop = l_found_multihop;
    return l_found_multihop;
}

/**
 * @brief Service request callback - called after successful request for service
 */
int vpn_srv_callback_requested(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client,
    const void *a_custom_data,
    size_t a_custom_data_size)
{
    UNUSED(a_srv);
    UNUSED(a_usage_id);
    
    // Parse custom data (JSON with VPN parameters)
    dap_chain_net_srv_vpn_custom_data_t *l_custom = s_parse_vpn_custom_data_json(a_custom_data, a_custom_data_size);
    
    // Get session and usage to access payment TX
    dap_chain_net_srv_stream_session_t *l_srv_session = 
        (dap_chain_net_srv_stream_session_t*)a_srv_client->ch->stream->session->_inheritor;
    
    if (l_srv_session && l_srv_session->usage_active && l_srv_session->usage_active->tx_cond) {
        // Parse multi-hop TSD from payment transaction
        if (!l_custom) {
            l_custom = DAP_NEW_Z(dap_chain_net_srv_vpn_custom_data_t);
        }
        
        if (l_custom) {
            s_parse_multihop_tsd_from_payment_tx(l_custom, l_srv_session->usage_active->tx_cond);
            
            // If multi-hop detected, create or update multi-hop session
            if (l_custom->is_multihop) {
                log_it(L_NOTICE, "Multi-hop VPN request detected: hop %u/%u, session_id=%u",
                       l_custom->hop_index, l_custom->total_hops, l_custom->session_id);
            }
        }
    }
    
    if (l_custom) {
        // Create simple traffic configuration
        dap_chain_net_srv_vpn_traffic_config_t *l_traffic_config = 
            dap_chain_net_srv_vpn_traffic_config_create(
                l_custom->bandwidth_limit_mbps,
                l_custom->priority,
                l_custom->exclude_routes,
                l_custom->dns_servers,
                l_custom->compression_enabled);
        
        if (l_traffic_config && l_srv_session) {
            // Free old config if present
            if (l_srv_session->custom_data && l_srv_session->custom_data_delete) {
                l_srv_session->custom_data_delete(l_srv_session->custom_data);
            }
            
            l_srv_session->custom_data = l_traffic_config;
            l_srv_session->custom_data_delete = (void (*)(void*))dap_chain_net_srv_vpn_traffic_config_free;
            
            log_it(L_INFO, "Traffic configuration applied to session");
        } else if (l_traffic_config) {
            log_it(L_WARNING, "Session not found, freeing traffic config");
            dap_chain_net_srv_vpn_traffic_config_free(l_traffic_config);
        }
        
        s_free_vpn_custom_data(l_custom);
    }
    
    return 0;
}

/**
 * @brief Response success callback
 */
int vpn_srv_callback_response_success(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client,
    const void *a_custom_data,
    size_t a_custom_data_size)
{
    UNUSED(a_srv);
    UNUSED(a_usage_id);
    UNUSED(a_custom_data);
    UNUSED(a_custom_data_size);
    
    dap_chain_net_srv_stream_session_t *l_srv_session = 
        (dap_chain_net_srv_stream_session_t*)a_srv_client->ch->stream->session->_inheritor;
    
    if (l_srv_session && l_srv_session->usage_active) {
        log_it(L_NOTICE, "VPN service response success for usage %u", l_srv_session->usage_active->id);
        
        // Initialize save_limits timer if not already set
        if (!l_srv_session->usage_active->save_limits_timer) {
            l_srv_session->usage_active->save_limits_timer = 
                dap_timerfd_start_on_worker(
                    a_srv_client->ch->stream_worker->worker,
                    3000,  // 3 seconds
                    vpn_srv_save_limits_timer_callback,
                    l_srv_session->usage_active);
        }
    }
    
    return 0;
}

/**
 * @brief Response error callback
 */
int vpn_srv_callback_response_error(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client,
    const void *a_custom_data,
    size_t a_custom_data_size)
{
    UNUSED(a_srv);
    UNUSED(a_usage_id);
    UNUSED(a_custom_data);
    UNUSED(a_custom_data_size);
    
    dap_chain_net_srv_stream_session_t *l_srv_session = 
        (dap_chain_net_srv_stream_session_t*)a_srv_client->ch->stream->session->_inheritor;
    
    if (l_srv_session && l_srv_session->usage_active) {
        log_it(L_WARNING, "VPN service response error for usage %u", l_srv_session->usage_active->id);
    }
    
    return 0;
}

/**
 * @brief Receipt next success callback
 */
int vpn_srv_callback_receipt_next_success(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client,
    const void *a_receipt_next,
    size_t a_receipt_next_size)
{
    UNUSED(a_srv);
    UNUSED(a_usage_id);
    
    if (!a_receipt_next || !a_receipt_next_size) {
        log_it(L_WARNING, "Receipt next is empty");
        return -1;
    }
    
    dap_chain_net_srv_stream_session_t *l_srv_session = 
        (dap_chain_net_srv_stream_session_t*)a_srv_client->ch->stream->session->_inheritor;
    
    if (l_srv_session && l_srv_session->usage_active) {
        log_it(L_NOTICE, "Receipt next success for usage %u (size=%zu)", 
               l_srv_session->usage_active->id, a_receipt_next_size);
        
        // Get or create VPN session data
        dap_chain_net_srv_vpn_session_data_t *l_vpn_data = 
            (dap_chain_net_srv_vpn_session_data_t *)l_srv_session->custom_data;
        
        if (!l_vpn_data) {
            l_vpn_data = DAP_NEW_Z(dap_chain_net_srv_vpn_session_data_t);
            if (!l_vpn_data) {
                log_it(L_CRITICAL, "Memory allocation failed for VPN session data");
                return -1;
            }
            l_srv_session->custom_data = l_vpn_data;
            l_srv_session->custom_data_delete = s_vpn_session_data_delete;
        }
        
        // Store receipt_next
        if (l_srv_session->usage_active->receipt_next) {
            DAP_DELETE(l_srv_session->usage_active->receipt_next);
        }
        
        l_srv_session->usage_active->receipt_next = DAP_DUP_SIZE(a_receipt_next, a_receipt_next_size);
        
        // SAFETY: Store size locally for validation
        l_vpn_data->receipt_next_size = a_receipt_next_size;
        
        log_it(L_DEBUG, "Stored receipt_next with size=%zu for safety validation", a_receipt_next_size);
    }
    
    return 0;
}

/**
 * @brief Get remaining service callback
 */
dap_stream_ch_chain_net_srv_remain_service_store_t *vpn_srv_callback_get_remain_service(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client)
{
    UNUSED(a_srv);
    UNUSED(a_usage_id);
    
    dap_chain_net_srv_stream_session_t *l_srv_session = 
        (dap_chain_net_srv_stream_session_t*)a_srv_client->ch->stream->session->_inheritor;
    
    if (!l_srv_session || !l_srv_session->usage_active) {
        return NULL;
    }
    
    dap_stream_ch_chain_net_srv_remain_service_store_t *l_ret = 
        DAP_NEW_Z(dap_stream_ch_chain_net_srv_remain_service_store_t);
    
    if (!l_ret) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    // Fill in remaining service data (new API - only limits_bytes and limits_ts)
    l_ret->limits_bytes = l_srv_session->limits_bytes;
    l_ret->limits_ts = l_srv_session->limits_ts;
    
    log_it(L_DEBUG, "Get remain service: bytes=%jd, ts=%ld", 
           (intmax_t)l_ret->limits_bytes, l_ret->limits_ts);
    
    return l_ret;
}

/**
 * @brief Save remaining service callback
 */
int vpn_srv_callback_save_remain_service(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client)
{
    UNUSED(a_usage_id);
    
    dap_chain_net_srv_stream_session_t *l_srv_session = 
        (dap_chain_net_srv_stream_session_t*)a_srv_client->ch->stream->session->_inheritor;
    
    if (!l_srv_session || !l_srv_session->usage_active) {
        return -1;
    }
    
    dap_chain_net_srv_usage_t *l_usage = l_srv_session->usage_active;
    
    // Get network from usage
    dap_chain_net_t *l_net = l_usage->net;
    if (!l_net) {
        log_it(L_ERROR, "No network in usage");
        return -1;
    }
    
    // Save limits to GDB
    char *l_gdb_group = dap_strdup_printf("%s.srv_vpn.limits", l_net->pub.gdb_groups_prefix);
    char *l_key = dap_chain_hash_fast_to_str_new(&l_usage->client_pkey_hash);
    
    // Create value structure (new API - only 2 fields)
    dap_stream_ch_chain_net_srv_remain_service_store_t l_store = {
        .limits_bytes = l_srv_session->limits_bytes,
        .limits_ts = l_srv_session->limits_ts
    };
    
    // Save to GDB (use sync API)
    int l_ret = dap_global_db_set_sync(
        l_gdb_group,
        l_key,
        &l_store,
        sizeof(l_store),
        false);  // not pinned
    
    if (l_ret == 0) {
        log_it(L_DEBUG, "Saved VPN limits to GDB: key=%s, bytes=%jd, ts=%ld",
               l_key, (intmax_t)l_store.limits_bytes, l_store.limits_ts);
        l_usage->is_limits_changed = false;
    } else {
        log_it(L_ERROR, "Failed to save VPN limits to GDB: key=%s", l_key);
    }
    
    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_key);
    
    return l_ret;
}

/**
 * @brief Timer callback wrapper for save_remain_service
 */
bool vpn_srv_save_limits_timer_callback(void *a_arg)
{
    dap_chain_net_srv_usage_t *l_usage = (dap_chain_net_srv_usage_t*)a_arg;
    
    if (!l_usage || !l_usage->is_limits_changed) {
        return true;  // Continue timer
    }
    
    if (l_usage->client && l_usage->client->ch) {
        dap_chain_net_srv_t *l_srv = l_usage->service;
        dap_chain_net_srv_client_remote_t l_srv_client = {
            .ch = l_usage->client->ch
        };
        
        vpn_srv_callback_save_remain_service(l_srv, l_usage->id, &l_srv_client);
    }
    
    return true;  // Continue timer
}

/**
 * @brief Get server public key hash string
 */
char *vpn_srv_get_my_pkey_str(dap_chain_net_srv_usage_t *a_usage)
{
    if (!a_usage || !a_usage->price || !a_usage->price->net) {
        log_it(L_DEBUG, "Invalid usage or price for pkey retrieval");
        return NULL;
    }
    
    // Get server's signing key from price certificate
    dap_cert_t *l_cert = a_usage->price->receipt_sign_cert;
    if (!l_cert || !l_cert->enc_key) {
        log_it(L_WARNING, "No server certificate or key configured");
        return NULL;
    }
    
    dap_chain_hash_fast_t l_pkey_hash = {0};
    if (dap_enc_key_get_pkey_hash(l_cert->enc_key, &l_pkey_hash) == 0) {
        return dap_chain_hash_fast_to_str_new(&l_pkey_hash);
    }
    
    return NULL;
}

// Public wrappers (for compatibility with callbacks.h exports)

dap_chain_net_srv_vpn_payment_data_t *vpn_srv_parse_payment_data(const char *a_json_str)
{
    if (!a_json_str) {
        return NULL;
    }
    
    return (dap_chain_net_srv_vpn_payment_data_t *)s_parse_vpn_custom_data_json(a_json_str, strlen(a_json_str));
}

void vpn_srv_free_payment_data(dap_chain_net_srv_vpn_payment_data_t *a_data)
{
    s_free_vpn_custom_data((dap_chain_net_srv_vpn_custom_data_t *)a_data);
}

