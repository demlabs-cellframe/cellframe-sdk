/**
 * @file dap_chain_net_vpn_client_service.c
 * @brief VPN Client Service Core Implementation
 * @date 2025-10-23
 * @copyright (c) 2025 Cellframe Network
 */

#include "dap_chain_net_vpn_client_service.h"
#include "dap_chain_net_vpn_client_state.h"
#include "dap_chain_net_vpn_client_backup.h"
#include "dap_config.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include <string.h>
#include <time.h>
#include <pthread.h>

#define LOG_TAG "dap_chain_net_vpn_client_service"

// Default configuration values
#define DEFAULT_CONNECTION_TIMEOUT_MS 5000  // 5 seconds
#define DEFAULT_RECONNECT_INTERVAL_MS 30000 // 30 seconds
#define DEFAULT_KEEPALIVE_INTERVAL_MS 10000 // 10 seconds
#define DEFAULT_KEEPALIVE_TIMEOUT_MS 30000  // 30 seconds

// Global service instance (singleton)
static dap_chain_net_vpn_client_service_t *s_service_instance = NULL;
static pthread_mutex_t s_service_instance_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Service instance structure
 */
struct dap_chain_net_vpn_client_service {
    dap_chain_net_vpn_client_sm_t *state_machine;
    dap_chain_net_vpn_client_backup_t *network_backup;
    
    // Connection info
    char *current_server_host;
    uint16_t current_server_port;
    dap_chain_net_vpn_client_config_t *current_config;
    
    // Statistics
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
    uint64_t total_packets_sent;
    uint64_t total_packets_received;
    
    // State callback
    dap_chain_net_vpn_client_service_state_callback_t state_callback;
    void *state_callback_user_data;
    
    // Thread safety
    pthread_mutex_t mutex;
};

// State names
static const char* s_state_names[] = {
    "DISCONNECTED",
    "CONNECTING",
    "CONNECTED",
    "CONNECTION_LOST",
    "RECONNECTING",
    "DISCONNECTING",
    "CONNECT_FAILED",
    "SHUTDOWN"
};

const char* dap_chain_net_vpn_client_service_state_to_string(
    dap_chain_net_vpn_client_service_state_t a_state) {
    if (a_state >= 0 && a_state < sizeof(s_state_names) / sizeof(s_state_names[0])) {
        return s_state_names[a_state];
    }
    return "UNKNOWN";
}

/**
 * @brief Load configuration from [vpn_client] section
 * @param a_sm State machine to apply config to
 */
static void load_config_from_file(dap_chain_net_vpn_client_sm_t *a_sm) {
    if (!a_sm) return;
    
    // Get global config
    extern dap_config_t *g_config;
    if (!g_config) {
        log_it(L_WARNING, "No global config available, using defaults");
        return;
    }
    
    // Load connection timeout
    uint32_t l_connection_timeout_ms = dap_config_get_item_uint32_default(
        g_config, "vpn_client", "connection_timeout_ms", DEFAULT_CONNECTION_TIMEOUT_MS);
    
    // Load reconnect settings
    bool l_auto_reconnect = dap_config_get_item_bool_default(
        g_config, "vpn_client", "auto_reconnect", true);
    uint32_t l_reconnect_interval_ms = dap_config_get_item_uint32_default(
        g_config, "vpn_client", "reconnect_interval_ms", DEFAULT_RECONNECT_INTERVAL_MS);
    uint32_t l_max_reconnect_attempts = dap_config_get_item_uint32_default(
        g_config, "vpn_client", "max_reconnect_attempts", 10);
    
    // Load keepalive settings
    uint32_t l_keepalive_interval_ms = dap_config_get_item_uint32_default(
        g_config, "vpn_client", "keepalive_interval_ms", DEFAULT_KEEPALIVE_INTERVAL_MS);
    uint32_t l_keepalive_timeout_ms = dap_config_get_item_uint32_default(
        g_config, "vpn_client", "keepalive_timeout_ms", DEFAULT_KEEPALIVE_TIMEOUT_MS);
    
    // Apply configuration to state machine
    dap_chain_net_vpn_client_reconnect_policy_t l_policy = {
        .enabled = l_auto_reconnect,
        .max_attempts = l_max_reconnect_attempts,
        .initial_delay_ms = l_reconnect_interval_ms,
        .max_delay_ms = 60000,
        .reset_after_ms = 300000
    };
    dap_chain_net_vpn_client_sm_set_reconnect_policy(a_sm, &l_policy);
    
    // Set timeouts via function API
    dap_chain_net_vpn_client_sm_set_keepalive(a_sm, l_keepalive_interval_ms, l_keepalive_timeout_ms);
    dap_chain_net_vpn_client_sm_set_connection_timeout(a_sm, l_connection_timeout_ms);
    
    log_it(L_INFO, "VPN client configuration loaded: conn_timeout=%u ms, reconnect=%s, keepalive=%u ms",
           l_connection_timeout_ms, l_auto_reconnect ? "enabled" : "disabled", l_keepalive_interval_ms);
}

// State machine callback wrapper
static void daemon_sm_state_changed_callback(
    dap_chain_net_vpn_client_sm_t *a_sm,
    dap_chain_net_vpn_client_state_t a_old_state,
    dap_chain_net_vpn_client_state_t a_new_state,
    dap_chain_net_vpn_client_event_t a_event,
    void *a_user_data)
{
    UNUSED(a_sm);
    UNUSED(a_old_state);
    UNUSED(a_event);
    
    dap_chain_net_vpn_client_service_t *l_daemon = (dap_chain_net_vpn_client_service_t*)a_user_data;
    if (!l_daemon) return;
    
    // Call daemon state callback if registered
    if (l_daemon->state_callback) {
        dap_chain_net_vpn_client_service_state_t l_daemon_state = 
            (dap_chain_net_vpn_client_service_state_t)a_new_state;
        l_daemon->state_callback(l_daemon_state, l_daemon->state_callback_user_data);
    }
}

dap_chain_net_vpn_client_service_t* dap_chain_net_vpn_client_service_create(void) {
    dap_chain_net_vpn_client_service_t *l_daemon = DAP_NEW_Z(dap_chain_net_vpn_client_service_t);
    if (!l_daemon) {
        log_it(L_CRITICAL, "Failed to allocate daemon structure");
        return NULL;
    }
    
    // Initialize state machine
    l_daemon->state_machine = dap_chain_net_vpn_client_sm_init();
    if (!l_daemon->state_machine) {
        log_it(L_ERROR, "Failed to initialize state machine");
        DAP_DELETE(l_daemon);
        return NULL;
    }
    
    // Load configuration from file
    load_config_from_file(l_daemon->state_machine);
    
    // Register state machine callback
    dap_chain_net_vpn_client_sm_register_callback(
        l_daemon->state_machine,
        daemon_sm_state_changed_callback,
        l_daemon
    );
    
    // Check for crash recovery backup
    if (dap_chain_net_vpn_client_backup_exists(NULL)) {
        log_it(L_WARNING, "Found backup file from previous crash, attempting auto-restore...");
        if (dap_chain_net_vpn_client_backup_auto_restore() == 0) {
            log_it(L_INFO, "Network configuration restored from crash backup");
        } else {
            log_it(L_ERROR, "Failed to restore network configuration from backup");
        }
    }
    
    pthread_mutex_init(&l_daemon->mutex, NULL);
    
    log_it(L_INFO, "Daemon created successfully");
    return l_daemon;
}

/**
 * @brief Get global service instance (singleton)
 */
dap_chain_net_vpn_client_service_t* dap_chain_net_vpn_client_service_get_instance(void) {
    pthread_mutex_lock(&s_service_instance_mutex);
    
    if (!s_service_instance) {
        log_it(L_DEBUG, "Creating new service instance");
        s_service_instance = dap_chain_net_vpn_client_service_create();
    }
    
    pthread_mutex_unlock(&s_service_instance_mutex);
    return s_service_instance;
}

void dap_chain_net_vpn_client_service_destroy(dap_chain_net_vpn_client_service_t *a_daemon) {
    if (!a_daemon) return;
    
    pthread_mutex_lock(&a_daemon->mutex);
    
    // Deinitialize state machine
    if (a_daemon->state_machine) {
        // Trigger shutdown event
        dap_chain_net_vpn_client_sm_transition(a_daemon->state_machine, VPN_EVENT_SHUTDOWN);
        dap_chain_net_vpn_client_sm_deinit(a_daemon->state_machine);
        a_daemon->state_machine = NULL;
    }
    
    // Free network backup
    if (a_daemon->network_backup) {
        dap_chain_net_vpn_client_backup_free(a_daemon->network_backup);
        a_daemon->network_backup = NULL;
    }
    
    // Free connection info
    DAP_DELETE(a_daemon->current_server_host);
    if (a_daemon->current_config) {
        DAP_DELETE(a_daemon->current_config->server_host);
        DAP_DELETE(a_daemon->current_config->network_name);
        DAP_DELETE(a_daemon->current_config->payment_tx_hash);
        DAP_DELETE(a_daemon->current_config->transport_type);
        DAP_DELETE(a_daemon->current_config->obfuscation_mode);
        DAP_DELETE(a_daemon->current_config->multi_hop_route);
        DAP_DELETE(a_daemon->current_config);
    }
    
    pthread_mutex_unlock(&a_daemon->mutex);
    pthread_mutex_destroy(&a_daemon->mutex);
    
    log_it(L_INFO, "Daemon destroyed");
    DAP_DELETE(a_daemon);
}

int dap_chain_net_vpn_client_service_connect(
    dap_chain_net_vpn_client_service_t *a_daemon,
    const dap_chain_net_vpn_client_config_t *a_config)
{
    if (!a_daemon || !a_config) return -1;
    
    pthread_mutex_lock(&a_daemon->mutex);
    
    // Check if already connecting or connected
    dap_chain_net_vpn_client_state_t l_state = 
        dap_chain_net_vpn_client_sm_get_state(a_daemon->state_machine);
    
    if (l_state != VPN_STATE_DISCONNECTED && 
        l_state != VPN_STATE_CONNECT_FAILED) {
        log_it(L_WARNING, "Cannot connect: already in state %s",
               dap_chain_net_vpn_client_state_to_string(l_state));
        pthread_mutex_unlock(&a_daemon->mutex);
        return -2;
    }
    
    // Store connection configuration
    if (a_daemon->current_config) {
        DAP_DELETE(a_daemon->current_config->server_host);
        DAP_DELETE(a_daemon->current_config->network_name);
        DAP_DELETE(a_daemon->current_config->payment_tx_hash);
        DAP_DELETE(a_daemon->current_config->transport_type);
        DAP_DELETE(a_daemon->current_config->obfuscation_mode);
        DAP_DELETE(a_daemon->current_config->multi_hop_route);
        DAP_DELETE(a_daemon->current_config);
    }
    
    a_daemon->current_config = DAP_NEW_Z(dap_chain_net_vpn_client_config_t);
    if (!a_daemon->current_config) {
        pthread_mutex_unlock(&a_daemon->mutex);
        return -3;
    }
    
    // Copy configuration
    a_daemon->current_config->server_host = a_config->server_host ? dap_strdup(a_config->server_host) : NULL;
    a_daemon->current_config->server_port = a_config->server_port;
    a_daemon->current_config->network_name = a_config->network_name ? dap_strdup(a_config->network_name) : NULL;
    a_daemon->current_config->payment_tx_hash = a_config->payment_tx_hash ? dap_strdup(a_config->payment_tx_hash) : NULL;
    a_daemon->current_config->transport_type = a_config->transport_type ? dap_strdup(a_config->transport_type) : NULL;
    a_daemon->current_config->obfuscation_mode = a_config->obfuscation_mode ? dap_strdup(a_config->obfuscation_mode) : NULL;
    a_daemon->current_config->enable_routing = a_config->enable_routing;
    a_daemon->current_config->enable_dns_override = a_config->enable_dns_override;
    a_daemon->current_config->auto_reconnect = a_config->auto_reconnect;
    a_daemon->current_config->reconnect_interval_ms = a_config->reconnect_interval_ms;
    a_daemon->current_config->multi_hop_enabled = a_config->multi_hop_enabled;
    a_daemon->current_config->multi_hop_route = a_config->multi_hop_route ? dap_strdup(a_config->multi_hop_route) : NULL;
    
    // Store server info
    DAP_DELETE(a_daemon->current_server_host);
    a_daemon->current_server_host = a_config->server_host ? dap_strdup(a_config->server_host) : NULL;
    a_daemon->current_server_port = a_config->server_port;
    
    // Set reconnect policy in state machine
    dap_chain_net_vpn_client_reconnect_policy_t l_policy = {
        .enabled = a_config->auto_reconnect,
        .max_attempts = 10,
        .initial_delay_ms = a_config->reconnect_interval_ms > 0 ? a_config->reconnect_interval_ms : 1000,
        .max_delay_ms = 60000,
        .reset_after_ms = 300000
    };
    dap_chain_net_vpn_client_sm_set_reconnect_policy(a_daemon->state_machine, &l_policy);
    
    // Set connection parameters in state machine
    dap_chain_net_vpn_client_connect_params_t l_params = {
        .server_address = a_config->server_host,
        .server_port = a_config->server_port,
        .network_name = a_config->network_name,
        .payment_tx_hash = a_config->payment_tx_hash,
        .transport_type = a_config->transport_type,
        .obfuscation_level = a_config->obfuscation_mode,
        .no_routing = !a_config->enable_routing,
        .no_dns = !a_config->enable_dns_override
    };
    dap_chain_net_vpn_client_sm_set_connect_params(a_daemon->state_machine, &l_params);
    
    // Trigger USER_CONNECT event
    int l_ret = dap_chain_net_vpn_client_sm_transition(
        a_daemon->state_machine,
        VPN_EVENT_USER_CONNECT
    );
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to initiate connection: %d", l_ret);
        pthread_mutex_unlock(&a_daemon->mutex);
        return -4;
    }
    
    log_it(L_INFO, "Connection initiated to %s:%u", 
           a_config->server_host, a_config->server_port);
    
    pthread_mutex_unlock(&a_daemon->mutex);
    return 0;
}

int dap_chain_net_vpn_client_service_disconnect(dap_chain_net_vpn_client_service_t *a_daemon) {
    if (!a_daemon) return -1;
    
    pthread_mutex_lock(&a_daemon->mutex);
    
    // Trigger USER_DISCONNECT event
    int l_ret = dap_chain_net_vpn_client_sm_transition(
        a_daemon->state_machine,
        VPN_EVENT_USER_DISCONNECT
    );
    
    if (l_ret != 0) {
        log_it(L_WARNING, "Disconnect transition failed: %d", l_ret);
        // Not critical, continue
    }
    
    log_it(L_INFO, "Disconnect initiated");
    
    pthread_mutex_unlock(&a_daemon->mutex);
    return 0;
}

int dap_chain_net_vpn_client_service_get_status(
    const dap_chain_net_vpn_client_service_t *a_daemon,
    dap_chain_net_vpn_client_service_status_t *a_out_status)
{
    if (!a_daemon || !a_out_status) return -1;
    
    pthread_mutex_lock((pthread_mutex_t*)&a_daemon->mutex);
    
    // Get current state from state machine
    dap_chain_net_vpn_client_state_t l_sm_state = 
        dap_chain_net_vpn_client_sm_get_state(a_daemon->state_machine);
    a_out_status->state = (dap_chain_net_vpn_client_service_state_t)l_sm_state;
    
    // Get server info
    a_out_status->server_host = a_daemon->current_server_host ? 
        dap_strdup(a_daemon->current_server_host) : NULL;
    a_out_status->server_port = a_daemon->current_server_port;
    
    // Get statistics from state machine
    uint64_t l_uptime = 0;
    uint64_t l_bytes_sent = 0;
    uint64_t l_bytes_received = 0;
    
    dap_chain_net_vpn_client_sm_get_stats(
        a_daemon->state_machine,
        &l_uptime,
        &l_bytes_sent,
        &l_bytes_received
    );
    
    a_out_status->uptime_seconds = l_uptime;
    a_out_status->bytes_sent = l_bytes_sent + a_daemon->total_bytes_sent;
    a_out_status->bytes_received = l_bytes_received + a_daemon->total_bytes_received;
    a_out_status->packets_sent = a_daemon->total_packets_sent;
    a_out_status->packets_received = a_daemon->total_packets_received;
    
    // Get reconnect attempt
    a_out_status->reconnect_attempt = 
        dap_chain_net_vpn_client_sm_get_reconnect_attempt(a_daemon->state_machine);
    
    pthread_mutex_unlock((pthread_mutex_t*)&a_daemon->mutex);
    return 0;
}

dap_chain_net_vpn_client_service_state_t dap_chain_net_vpn_client_service_get_state(
    const dap_chain_net_vpn_client_service_t *a_daemon)
{
    if (!a_daemon) return DAP_CHAIN_NET_VPN_CLIENT_SERVICE_STATE_DISCONNECTED;
    
    dap_chain_net_vpn_client_state_t l_sm_state = 
        dap_chain_net_vpn_client_sm_get_state(a_daemon->state_machine);
    
    return (dap_chain_net_vpn_client_service_state_t)l_sm_state;
}

int dap_chain_net_vpn_client_service_set_state_callback(
    dap_chain_net_vpn_client_service_t *a_daemon,
    dap_chain_net_vpn_client_service_state_callback_t a_callback,
    void *a_user_data)
{
    if (!a_daemon) return -1;
    
    pthread_mutex_lock(&a_daemon->mutex);
    a_daemon->state_callback = a_callback;
    a_daemon->state_callback_user_data = a_user_data;
    pthread_mutex_unlock(&a_daemon->mutex);
    
    return 0;
}

bool dap_chain_net_vpn_client_service_is_connected(
    const dap_chain_net_vpn_client_service_t *a_daemon)
{
    if (!a_daemon) return false;
    return dap_chain_net_vpn_client_sm_is_connected(a_daemon->state_machine);
}

void dap_chain_net_vpn_client_service_update_stats(
    dap_chain_net_vpn_client_service_t *a_daemon,
    uint64_t a_bytes_sent,
    uint64_t a_bytes_received)
{
    if (!a_daemon) return;
    
    pthread_mutex_lock(&a_daemon->mutex);
    a_daemon->total_bytes_sent += a_bytes_sent;
    a_daemon->total_bytes_received += a_bytes_received;
    pthread_mutex_unlock(&a_daemon->mutex);
}
