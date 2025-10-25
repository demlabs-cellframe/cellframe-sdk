/**
 * @file dap_chain_net_vpn_client_state.c
 * @brief VPN Client State Machine Implementation
 * @date 2025-10-23
 * @copyright (c) 2025 Cellframe Network
 */

#include "dap_chain_net_vpn_client_state.h"
#include "dap_chain_net_vpn_client_protocol_probe.h"
#include "dap_chain_net_vpn_client_connectivity_test.h"
#include "dap_chain_net_vpn_client_uplink_pool.h"
#include "dap_chain_net_vpn_client_backup.h"
#include "dap_chain_net_vpn_client_network.h"
#include "dap_chain_node_client.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "include/dap_chain_net_vpn_client_multihop_tx.h"
#include "include/dap_chain_net_vpn_client_receipt.h"
#include "dap_chain_net_vpn_client_payment.h"
#include "include/dap_vpn_client_wallet.h"
#include "dap_vpn_client_network_registry.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_client.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_timerfd.h"
#include "dap_worker.h"
#include "../../tun/include/dap_net_tun.h"  // Unified TUN API
#include <string.h>
#include <time.h>
#include <pthread.h>

#define LOG_TAG "dap_chain_net_vpn_client_state"

// Debug flag for verbose packet logging
static bool s_debug_more = false;

// Maximum number of state change callbacks
#define MAX_CALLBACKS 8

// Default reconnect policy
#define DEFAULT_MAX_ATTEMPTS 10
#define DEFAULT_INITIAL_DELAY_MS 1000
#define DEFAULT_MAX_DELAY_MS 60000
#define DEFAULT_RESET_AFTER_MS 300000  // 5 minutes

// Default connection timeout
#define DEFAULT_CONNECTION_TIMEOUT_MS 5000  // 5 seconds

// Default keepalive settings
#define DEFAULT_KEEPALIVE_INTERVAL_MS 10000   // 10 seconds
#define DEFAULT_KEEPALIVE_TIMEOUT_MS 30000    // 30 seconds

// Default protocol probe settings
#define DEFAULT_PROTOCOL_PROBE_TIMEOUT_MS 10000        // 10 seconds total
#define DEFAULT_PROTOCOL_PROBE_PER_PROTO_TIMEOUT_MS 5000  // 5 seconds per protocol

/**
 * @brief State machine context structure
 */
struct dap_chain_net_vpn_client_sm {
    dap_chain_net_vpn_client_state_t current_state;
    dap_chain_net_vpn_client_state_t previous_state;
    
    // Reconnect policy
    dap_chain_net_vpn_client_reconnect_policy_t reconnect_policy;
    uint32_t reconnect_attempt;
    int64_t connection_established_time;  // Timestamp when connection was established
    int64_t last_reconnect_time;          // Timestamp of last reconnect attempt
    
    // Connection parameters
    dap_chain_net_vpn_client_connect_params_t *connect_params;
    
    // Node client connection
    dap_chain_node_client_t *node_client;     // Active node client connection
    uint32_t connection_timeout_ms;           // Connection timeout in milliseconds
    dap_stream_ch_t *vpn_channel;             // VPN service stream channel ('R')
    
    // TUN Device
    dap_net_tun_t *tun_handle;               // Unified TUN device handle
    char *tun_device_name;                   // TUN device name (e.g., "tun0")
    char *tun_local_ip;                      // Client's VPN IP address
    char *tun_remote_ip;                     // Server's VPN gateway IP
    uint32_t tun_mtu;                        // MTU for TUN device
    
    // Statistics
    int64_t connection_start_time;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    
    // Keepalive
    dap_timerfd_t *keepalive_timer;
    uint32_t keepalive_interval_ms;
    uint32_t keepalive_timeout_ms;
    int64_t last_keepalive_response;
    
    // Protocol Probe & Connectivity Test
    dap_vpn_protocol_probe_t *protocol_probe;          // Active protocol probe
    dap_vpn_connectivity_test_t *connectivity_test;    // Active connectivity test
    
    // Multi-hop & Payment
    dap_chain_wallet_t *wallet;                        // Wallet for auto TX creation
    dap_vpn_client_receipt_collector_t *receipt_collector; // Receipt collector for multi-hop
    dap_stream_transport_type_t selected_protocol;    // Best protocol selected
    
    // Network Configuration Backup
    dap_chain_net_vpn_client_backup_t *network_backup;  // Network config backup
    
    // Callbacks
    dap_chain_net_vpn_client_state_callback_t callbacks[MAX_CALLBACKS];
    void *callback_user_data[MAX_CALLBACKS];
    size_t callback_count;
    
    // Thread safety
    pthread_mutex_t mutex;
};

// Forward declarations for state entry/exit actions
static void state_disconnected_entry(dap_chain_net_vpn_client_sm_t *a_sm);
static void state_connecting_entry(dap_chain_net_vpn_client_sm_t *a_sm);
static void state_verifying_connectivity_entry(dap_chain_net_vpn_client_sm_t *a_sm);
static void state_routing_setup_entry(dap_chain_net_vpn_client_sm_t *a_sm);
static void state_connected_entry(dap_chain_net_vpn_client_sm_t *a_sm);
static void state_connection_lost_entry(dap_chain_net_vpn_client_sm_t *a_sm);
static void state_reconnecting_entry(dap_chain_net_vpn_client_sm_t *a_sm);
static void state_disconnecting_entry(dap_chain_net_vpn_client_sm_t *a_sm);
static void state_connect_failed_entry(dap_chain_net_vpn_client_sm_t *a_sm);
static void state_shutdown_entry(dap_chain_net_vpn_client_sm_t *a_sm);

static void state_verifying_connectivity_exit(dap_chain_net_vpn_client_sm_t *a_sm);
static void state_routing_setup_exit(dap_chain_net_vpn_client_sm_t *a_sm);
static void state_connected_exit(dap_chain_net_vpn_client_sm_t *a_sm);

// TUN device callback functions
static void s_tun_data_received_callback(dap_net_tun_t *a_tun, const void *a_data, size_t a_data_size, void *a_user_data);
static void s_tun_error_callback(dap_net_tun_t *a_tun, int a_error_code, const char *a_error_msg, void *a_user_data);

// Stream channel packet callback
static void s_stream_ch_packet_in_callback(dap_stream_ch_t *a_ch, void *a_arg);

/**
 * @brief State transition table
 * 
 * table[current_state][event] = {new_state, allowed}
 */
static const struct {
    dap_chain_net_vpn_client_state_t new_state;
    bool allowed;
} s_transition_table[VPN_STATE_MAX][VPN_EVENT_MAX] = {
    // VPN_STATE_DISCONNECTED
    [VPN_STATE_DISCONNECTED] = {
        [VPN_EVENT_USER_CONNECT] = {VPN_STATE_CONNECTING, true},
        [VPN_EVENT_USER_DISCONNECT] = {VPN_STATE_DISCONNECTED, false},
        [VPN_EVENT_CONNECTION_SUCCESS] = {VPN_STATE_DISCONNECTED, false},
        [VPN_EVENT_CONNECTION_FAILED] = {VPN_STATE_DISCONNECTED, false},
        [VPN_EVENT_PROTOCOLS_PROBED] = {VPN_STATE_DISCONNECTED, false},
        [VPN_EVENT_VERIFICATION_SUCCESS] = {VPN_STATE_DISCONNECTED, false},
        [VPN_EVENT_VERIFICATION_FAILED] = {VPN_STATE_DISCONNECTED, false},
        [VPN_EVENT_ROUTING_COMPLETE] = {VPN_STATE_DISCONNECTED, false},
        [VPN_EVENT_CONNECTION_LOST] = {VPN_STATE_DISCONNECTED, false},
        [VPN_EVENT_KEEPALIVE_TIMEOUT] = {VPN_STATE_DISCONNECTED, false},
        [VPN_EVENT_RECONNECT_SUCCESS] = {VPN_STATE_DISCONNECTED, false},
        [VPN_EVENT_RECONNECT_FAILED] = {VPN_STATE_DISCONNECTED, false},
        [VPN_EVENT_SERVER_DISCONNECT] = {VPN_STATE_DISCONNECTED, false},
        [VPN_EVENT_SHUTDOWN] = {VPN_STATE_SHUTDOWN, true},
    },
    // VPN_STATE_CONNECTING
    [VPN_STATE_CONNECTING] = {
        [VPN_EVENT_USER_CONNECT] = {VPN_STATE_CONNECTING, false},
        [VPN_EVENT_USER_DISCONNECT] = {VPN_STATE_DISCONNECTING, true},
        [VPN_EVENT_CONNECTION_SUCCESS] = {VPN_STATE_VERIFYING_CONNECTIVITY, true},
        [VPN_EVENT_CONNECTION_FAILED] = {VPN_STATE_CONNECT_FAILED, true},
        [VPN_EVENT_PROTOCOLS_PROBED] = {VPN_STATE_CONNECTING, false},
        [VPN_EVENT_VERIFICATION_SUCCESS] = {VPN_STATE_CONNECTING, false},
        [VPN_EVENT_VERIFICATION_FAILED] = {VPN_STATE_CONNECTING, false},
        [VPN_EVENT_ROUTING_COMPLETE] = {VPN_STATE_CONNECTING, false},
        [VPN_EVENT_CONNECTION_LOST] = {VPN_STATE_CONNECTING, false},
        [VPN_EVENT_KEEPALIVE_TIMEOUT] = {VPN_STATE_CONNECT_FAILED, true},
        [VPN_EVENT_RECONNECT_SUCCESS] = {VPN_STATE_CONNECTING, false},
        [VPN_EVENT_RECONNECT_FAILED] = {VPN_STATE_CONNECTING, false},
        [VPN_EVENT_SERVER_DISCONNECT] = {VPN_STATE_CONNECTING, false},
        [VPN_EVENT_SHUTDOWN] = {VPN_STATE_SHUTDOWN, true},
    },
    // VPN_STATE_VERIFYING_CONNECTIVITY
    [VPN_STATE_VERIFYING_CONNECTIVITY] = {
        [VPN_EVENT_USER_CONNECT] = {VPN_STATE_VERIFYING_CONNECTIVITY, false},
        [VPN_EVENT_USER_DISCONNECT] = {VPN_STATE_DISCONNECTING, true},
        [VPN_EVENT_CONNECTION_SUCCESS] = {VPN_STATE_VERIFYING_CONNECTIVITY, false},
        [VPN_EVENT_CONNECTION_FAILED] = {VPN_STATE_CONNECT_FAILED, true},
        [VPN_EVENT_PROTOCOLS_PROBED] = {VPN_STATE_VERIFYING_CONNECTIVITY, false},
        [VPN_EVENT_VERIFICATION_SUCCESS] = {VPN_STATE_ROUTING_SETUP, true},
        [VPN_EVENT_VERIFICATION_FAILED] = {VPN_STATE_CONNECT_FAILED, true},
        [VPN_EVENT_ROUTING_COMPLETE] = {VPN_STATE_VERIFYING_CONNECTIVITY, false},
        [VPN_EVENT_CONNECTION_LOST] = {VPN_STATE_CONNECTION_LOST, true},
        [VPN_EVENT_KEEPALIVE_TIMEOUT] = {VPN_STATE_CONNECT_FAILED, true},
        [VPN_EVENT_RECONNECT_SUCCESS] = {VPN_STATE_VERIFYING_CONNECTIVITY, false},
        [VPN_EVENT_RECONNECT_FAILED] = {VPN_STATE_VERIFYING_CONNECTIVITY, false},
        [VPN_EVENT_SERVER_DISCONNECT] = {VPN_STATE_DISCONNECTING, true},
        [VPN_EVENT_SHUTDOWN] = {VPN_STATE_SHUTDOWN, true},
    },
    // VPN_STATE_ROUTING_SETUP
    [VPN_STATE_ROUTING_SETUP] = {
        [VPN_EVENT_USER_CONNECT] = {VPN_STATE_ROUTING_SETUP, false},
        [VPN_EVENT_USER_DISCONNECT] = {VPN_STATE_DISCONNECTING, true},
        [VPN_EVENT_CONNECTION_SUCCESS] = {VPN_STATE_ROUTING_SETUP, false},
        [VPN_EVENT_CONNECTION_FAILED] = {VPN_STATE_CONNECT_FAILED, true},
        [VPN_EVENT_PROTOCOLS_PROBED] = {VPN_STATE_ROUTING_SETUP, false},
        [VPN_EVENT_VERIFICATION_SUCCESS] = {VPN_STATE_ROUTING_SETUP, false},
        [VPN_EVENT_VERIFICATION_FAILED] = {VPN_STATE_ROUTING_SETUP, false},
        [VPN_EVENT_ROUTING_COMPLETE] = {VPN_STATE_CONNECTED, true},
        [VPN_EVENT_CONNECTION_LOST] = {VPN_STATE_CONNECTION_LOST, true},
        [VPN_EVENT_KEEPALIVE_TIMEOUT] = {VPN_STATE_CONNECT_FAILED, true},
        [VPN_EVENT_RECONNECT_SUCCESS] = {VPN_STATE_ROUTING_SETUP, false},
        [VPN_EVENT_RECONNECT_FAILED] = {VPN_STATE_ROUTING_SETUP, false},
        [VPN_EVENT_SERVER_DISCONNECT] = {VPN_STATE_DISCONNECTING, true},
        [VPN_EVENT_SHUTDOWN] = {VPN_STATE_SHUTDOWN, true},
    },
    // VPN_STATE_CONNECTED
    [VPN_STATE_CONNECTED] = {
        [VPN_EVENT_USER_CONNECT] = {VPN_STATE_CONNECTED, false},
        [VPN_EVENT_USER_DISCONNECT] = {VPN_STATE_DISCONNECTING, true},
        [VPN_EVENT_CONNECTION_SUCCESS] = {VPN_STATE_CONNECTED, false},
        [VPN_EVENT_CONNECTION_FAILED] = {VPN_STATE_CONNECTED, false},
        [VPN_EVENT_PROTOCOLS_PROBED] = {VPN_STATE_CONNECTED, false},
        [VPN_EVENT_VERIFICATION_SUCCESS] = {VPN_STATE_CONNECTED, false},
        [VPN_EVENT_VERIFICATION_FAILED] = {VPN_STATE_CONNECTED, false},
        [VPN_EVENT_ROUTING_COMPLETE] = {VPN_STATE_CONNECTED, false},
        [VPN_EVENT_CONNECTION_LOST] = {VPN_STATE_CONNECTION_LOST, true},
        [VPN_EVENT_KEEPALIVE_TIMEOUT] = {VPN_STATE_CONNECTION_LOST, true},
        [VPN_EVENT_RECONNECT_SUCCESS] = {VPN_STATE_CONNECTED, false},
        [VPN_EVENT_RECONNECT_FAILED] = {VPN_STATE_CONNECTED, false},
        [VPN_EVENT_SERVER_DISCONNECT] = {VPN_STATE_DISCONNECTING, true},
        [VPN_EVENT_SHUTDOWN] = {VPN_STATE_SHUTDOWN, true},
    },
    // VPN_STATE_CONNECTION_LOST
    [VPN_STATE_CONNECTION_LOST] = {
        [VPN_EVENT_USER_CONNECT] = {VPN_STATE_CONNECTION_LOST, false},
        [VPN_EVENT_USER_DISCONNECT] = {VPN_STATE_DISCONNECTING, true},
        [VPN_EVENT_CONNECTION_SUCCESS] = {VPN_STATE_RECONNECTING, true},
        [VPN_EVENT_CONNECTION_FAILED] = {VPN_STATE_DISCONNECTED, true},
        [VPN_EVENT_PROTOCOLS_PROBED] = {VPN_STATE_CONNECTION_LOST, false},
        [VPN_EVENT_VERIFICATION_SUCCESS] = {VPN_STATE_CONNECTION_LOST, false},
        [VPN_EVENT_VERIFICATION_FAILED] = {VPN_STATE_CONNECTION_LOST, false},
        [VPN_EVENT_ROUTING_COMPLETE] = {VPN_STATE_CONNECTION_LOST, false},
        [VPN_EVENT_CONNECTION_LOST] = {VPN_STATE_CONNECTION_LOST, false},
        [VPN_EVENT_KEEPALIVE_TIMEOUT] = {VPN_STATE_CONNECTION_LOST, false},
        [VPN_EVENT_RECONNECT_SUCCESS] = {VPN_STATE_CONNECTION_LOST, false},
        [VPN_EVENT_RECONNECT_FAILED] = {VPN_STATE_CONNECTION_LOST, false},
        [VPN_EVENT_SERVER_DISCONNECT] = {VPN_STATE_CONNECTION_LOST, false},
        [VPN_EVENT_SHUTDOWN] = {VPN_STATE_SHUTDOWN, true},
    },
    // VPN_STATE_RECONNECTING
    [VPN_STATE_RECONNECTING] = {
        [VPN_EVENT_USER_CONNECT] = {VPN_STATE_RECONNECTING, false},
        [VPN_EVENT_USER_DISCONNECT] = {VPN_STATE_DISCONNECTING, true},
        [VPN_EVENT_CONNECTION_SUCCESS] = {VPN_STATE_RECONNECTING, false},
        [VPN_EVENT_CONNECTION_FAILED] = {VPN_STATE_RECONNECTING, false},
        [VPN_EVENT_PROTOCOLS_PROBED] = {VPN_STATE_RECONNECTING, false},
        [VPN_EVENT_VERIFICATION_SUCCESS] = {VPN_STATE_RECONNECTING, false},
        [VPN_EVENT_VERIFICATION_FAILED] = {VPN_STATE_RECONNECTING, false},
        [VPN_EVENT_ROUTING_COMPLETE] = {VPN_STATE_RECONNECTING, false},
        [VPN_EVENT_CONNECTION_LOST] = {VPN_STATE_RECONNECTING, false},
        [VPN_EVENT_KEEPALIVE_TIMEOUT] = {VPN_STATE_RECONNECTING, false},
        [VPN_EVENT_RECONNECT_SUCCESS] = {VPN_STATE_CONNECTED, true},
        [VPN_EVENT_RECONNECT_FAILED] = {VPN_STATE_CONNECTION_LOST, true},
        [VPN_EVENT_SERVER_DISCONNECT] = {VPN_STATE_RECONNECTING, false},
        [VPN_EVENT_SHUTDOWN] = {VPN_STATE_SHUTDOWN, true},
    },
    // VPN_STATE_DISCONNECTING
    [VPN_STATE_DISCONNECTING] = {
        [VPN_EVENT_USER_CONNECT] = {VPN_STATE_DISCONNECTING, false},
        [VPN_EVENT_USER_DISCONNECT] = {VPN_STATE_DISCONNECTING, false},
        [VPN_EVENT_CONNECTION_SUCCESS] = {VPN_STATE_DISCONNECTED, true},
        [VPN_EVENT_CONNECTION_FAILED] = {VPN_STATE_DISCONNECTED, true},
        [VPN_EVENT_PROTOCOLS_PROBED] = {VPN_STATE_DISCONNECTING, false},
        [VPN_EVENT_VERIFICATION_SUCCESS] = {VPN_STATE_DISCONNECTING, false},
        [VPN_EVENT_VERIFICATION_FAILED] = {VPN_STATE_DISCONNECTING, false},
        [VPN_EVENT_ROUTING_COMPLETE] = {VPN_STATE_DISCONNECTING, false},
        [VPN_EVENT_CONNECTION_LOST] = {VPN_STATE_DISCONNECTED, true},
        [VPN_EVENT_KEEPALIVE_TIMEOUT] = {VPN_STATE_DISCONNECTED, true},
        [VPN_EVENT_RECONNECT_SUCCESS] = {VPN_STATE_DISCONNECTING, false},
        [VPN_EVENT_RECONNECT_FAILED] = {VPN_STATE_DISCONNECTING, false},
        [VPN_EVENT_SERVER_DISCONNECT] = {VPN_STATE_DISCONNECTED, true},
        [VPN_EVENT_SHUTDOWN] = {VPN_STATE_SHUTDOWN, true},
    },
    // VPN_STATE_CONNECT_FAILED
    [VPN_STATE_CONNECT_FAILED] = {
        [VPN_EVENT_USER_CONNECT] = {VPN_STATE_CONNECTING, true},
        [VPN_EVENT_USER_DISCONNECT] = {VPN_STATE_DISCONNECTED, true},
        [VPN_EVENT_CONNECTION_SUCCESS] = {VPN_STATE_CONNECT_FAILED, false},
        [VPN_EVENT_CONNECTION_FAILED] = {VPN_STATE_CONNECT_FAILED, false},
        [VPN_EVENT_PROTOCOLS_PROBED] = {VPN_STATE_CONNECT_FAILED, false},
        [VPN_EVENT_VERIFICATION_SUCCESS] = {VPN_STATE_CONNECT_FAILED, false},
        [VPN_EVENT_VERIFICATION_FAILED] = {VPN_STATE_CONNECT_FAILED, false},
        [VPN_EVENT_ROUTING_COMPLETE] = {VPN_STATE_CONNECT_FAILED, false},
        [VPN_EVENT_CONNECTION_LOST] = {VPN_STATE_CONNECT_FAILED, false},
        [VPN_EVENT_KEEPALIVE_TIMEOUT] = {VPN_STATE_DISCONNECTED, true},
        [VPN_EVENT_RECONNECT_SUCCESS] = {VPN_STATE_CONNECT_FAILED, false},
        [VPN_EVENT_RECONNECT_FAILED] = {VPN_STATE_CONNECT_FAILED, false},
        [VPN_EVENT_SERVER_DISCONNECT] = {VPN_STATE_CONNECT_FAILED, false},
        [VPN_EVENT_SHUTDOWN] = {VPN_STATE_SHUTDOWN, true},
    },
    // VPN_STATE_SHUTDOWN
    [VPN_STATE_SHUTDOWN] = {
        [VPN_EVENT_USER_CONNECT] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_USER_DISCONNECT] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_CONNECTION_SUCCESS] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_CONNECTION_FAILED] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_PROTOCOLS_PROBED] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_VERIFICATION_SUCCESS] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_VERIFICATION_FAILED] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_ROUTING_COMPLETE] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_CONNECTION_LOST] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_KEEPALIVE_TIMEOUT] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_RECONNECT_SUCCESS] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_RECONNECT_FAILED] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_SERVER_DISCONNECT] = {VPN_STATE_SHUTDOWN, false},
        [VPN_EVENT_SHUTDOWN] = {VPN_STATE_SHUTDOWN, false},
    },
};

// State name strings
static const char* s_state_names[VPN_STATE_MAX] = {
    "DISCONNECTED",
    "CONNECTING",
    "VERIFYING_CONNECTIVITY",
    "ROUTING_SETUP",
    "CONNECTED",
    "CONNECTION_LOST",
    "RECONNECTING",
    "DISCONNECTING",
    "CONNECT_FAILED",
    "SHUTDOWN"
};

// Event name strings
static const char* s_event_names[VPN_EVENT_MAX] = {
    "USER_CONNECT",
    "USER_DISCONNECT",
    "CONNECTION_SUCCESS",
    "CONNECTION_FAILED",
    "PROTOCOLS_PROBED",
    "VERIFICATION_SUCCESS",
    "VERIFICATION_FAILED",
    "ROUTING_COMPLETE",
    "CONNECTION_LOST",
    "KEEPALIVE_TIMEOUT",
    "RECONNECT_SUCCESS",
    "RECONNECT_FAILED",
    "SERVER_DISCONNECT",
    "SHUTDOWN"
};

const char* dap_chain_net_vpn_client_state_to_string(dap_chain_net_vpn_client_state_t a_state) {
    if (a_state >= 0 && a_state < VPN_STATE_MAX) {
        return s_state_names[a_state];
    }
    return "UNKNOWN";
}

const char* dap_chain_net_vpn_client_event_to_string(dap_chain_net_vpn_client_event_t a_event) {
    if (a_event >= 0 && a_event < VPN_EVENT_MAX) {
        return s_event_names[a_event];
    }
    return "UNKNOWN";
}

dap_chain_net_vpn_client_sm_t* dap_chain_net_vpn_client_sm_init(void) {
    dap_chain_net_vpn_client_sm_t *l_sm = DAP_NEW_Z(dap_chain_net_vpn_client_sm_t);
    if (!l_sm) {
        log_it(L_CRITICAL, "Failed to allocate state machine");
        return NULL;
    }
    
    l_sm->current_state = VPN_STATE_DISCONNECTED;
    l_sm->previous_state = VPN_STATE_DISCONNECTED;
    
    // Set default reconnect policy
    l_sm->reconnect_policy.enabled = true;
    l_sm->reconnect_policy.max_attempts = DEFAULT_MAX_ATTEMPTS;
    l_sm->reconnect_policy.initial_delay_ms = DEFAULT_INITIAL_DELAY_MS;
    l_sm->reconnect_policy.max_delay_ms = DEFAULT_MAX_DELAY_MS;
    l_sm->reconnect_policy.reset_after_ms = DEFAULT_RESET_AFTER_MS;
    
    l_sm->reconnect_attempt = 0;
    l_sm->connection_established_time = 0;
    l_sm->last_reconnect_time = 0;
    
    l_sm->connection_start_time = 0;
    l_sm->bytes_sent = 0;
    l_sm->bytes_received = 0;
    
    l_sm->connection_timeout_ms = DEFAULT_CONNECTION_TIMEOUT_MS;
    
    l_sm->keepalive_interval_ms = DEFAULT_KEEPALIVE_INTERVAL_MS;
    l_sm->keepalive_timeout_ms = DEFAULT_KEEPALIVE_TIMEOUT_MS;
    l_sm->last_keepalive_response = 0;
    
    pthread_mutex_init(&l_sm->mutex, NULL);
    
    log_it(L_INFO, "State machine initialized in state: %s", 
           dap_chain_net_vpn_client_state_to_string(l_sm->current_state));
    
    return l_sm;
}

void dap_chain_net_vpn_client_sm_deinit(dap_chain_net_vpn_client_sm_t *a_sm) {
    if (!a_sm) return;
    
    pthread_mutex_lock(&a_sm->mutex);
    
    // Stop keepalive if running
    if (a_sm->keepalive_timer) {
        dap_timerfd_delete_mt(dap_worker_get_current(), a_sm->keepalive_timer->esocket_uuid);
        a_sm->keepalive_timer = NULL;
    }
    
    // Stop and cleanup protocol probe if running
    if (a_sm->protocol_probe) {
        dap_vpn_protocol_probe_destroy(a_sm->protocol_probe);
        a_sm->protocol_probe = NULL;
    }
    
    // Stop and cleanup connectivity test if running
    if (a_sm->connectivity_test) {
        dap_vpn_connectivity_test_destroy(a_sm->connectivity_test);
        a_sm->connectivity_test = NULL;
    }
    
    // Free network backup
    if (a_sm->network_backup) {
        dap_chain_net_vpn_client_backup_free(a_sm->network_backup);
        a_sm->network_backup = NULL;
    }
    
    // Free connection parameters
    if (a_sm->connect_params) {
        dap_chain_net_vpn_client_connect_params_free(a_sm->connect_params);
        a_sm->connect_params = NULL;
    }
    
    pthread_mutex_unlock(&a_sm->mutex);
    pthread_mutex_destroy(&a_sm->mutex);
    
    log_it(L_INFO, "State machine deinitialized");
    DAP_DELETE(a_sm);
}

static void execute_state_entry_actions(dap_chain_net_vpn_client_sm_t *a_sm,
                                        dap_chain_net_vpn_client_state_t a_state) {
    switch (a_state) {
        case VPN_STATE_DISCONNECTED:
            state_disconnected_entry(a_sm);
            break;
        case VPN_STATE_CONNECTING:
            state_connecting_entry(a_sm);
            break;
        case VPN_STATE_VERIFYING_CONNECTIVITY:
            state_verifying_connectivity_entry(a_sm);
            break;
        case VPN_STATE_ROUTING_SETUP:
            state_routing_setup_entry(a_sm);
            break;
        case VPN_STATE_CONNECTED:
            state_connected_entry(a_sm);
            break;
        case VPN_STATE_CONNECTION_LOST:
            state_connection_lost_entry(a_sm);
            break;
        case VPN_STATE_RECONNECTING:
            state_reconnecting_entry(a_sm);
            break;
        case VPN_STATE_DISCONNECTING:
            state_disconnecting_entry(a_sm);
            break;
        case VPN_STATE_CONNECT_FAILED:
            state_connect_failed_entry(a_sm);
            break;
        case VPN_STATE_SHUTDOWN:
            state_shutdown_entry(a_sm);
            break;
        default:
            break;
    }
}

static void execute_state_exit_actions(dap_chain_net_vpn_client_sm_t *a_sm,
                                       dap_chain_net_vpn_client_state_t a_state) {
    switch (a_state) {
        case VPN_STATE_VERIFYING_CONNECTIVITY:
            state_verifying_connectivity_exit(a_sm);
            break;
        case VPN_STATE_ROUTING_SETUP:
            state_routing_setup_exit(a_sm);
            break;
        case VPN_STATE_CONNECTED:
            state_connected_exit(a_sm);
            break;
        default:
            // No exit action for this state
            break;
    }
}

int dap_chain_net_vpn_client_sm_transition(dap_chain_net_vpn_client_sm_t *a_sm,
                                            dap_chain_net_vpn_client_event_t a_event) {
    if (!a_sm) return -1;
    if (a_event < 0 || a_event >= VPN_EVENT_MAX) return -2;
    
    pthread_mutex_lock(&a_sm->mutex);
    
    dap_chain_net_vpn_client_state_t l_old_state = a_sm->current_state;
    
    // Check if transition is allowed
    if (l_old_state >= VPN_STATE_MAX || !s_transition_table[l_old_state][a_event].allowed) {
        log_it(L_WARNING, "Invalid transition: %s + %s (not allowed)",
               dap_chain_net_vpn_client_state_to_string(l_old_state),
               dap_chain_net_vpn_client_event_to_string(a_event));
        pthread_mutex_unlock(&a_sm->mutex);
        return -3;
    }
    
    dap_chain_net_vpn_client_state_t l_new_state = s_transition_table[l_old_state][a_event].new_state;
    
    // Perform transition
    log_it(L_INFO, "State transition: %s -> %s (event: %s)",
           dap_chain_net_vpn_client_state_to_string(l_old_state),
           dap_chain_net_vpn_client_state_to_string(l_new_state),
           dap_chain_net_vpn_client_event_to_string(a_event));
    
    // Execute exit actions for old state
    execute_state_exit_actions(a_sm, l_old_state);
    
    // Update state
    a_sm->previous_state = l_old_state;
    a_sm->current_state = l_new_state;
    
    // Execute entry actions for new state
    execute_state_entry_actions(a_sm, l_new_state);
    
    // Call registered callbacks
    for (size_t i = 0; i < a_sm->callback_count; i++) {
        if (a_sm->callbacks[i]) {
            a_sm->callbacks[i](a_sm, l_old_state, l_new_state, a_event, a_sm->callback_user_data[i]);
        }
    }
    
    pthread_mutex_unlock(&a_sm->mutex);
    return 0;
}

dap_chain_net_vpn_client_state_t dap_chain_net_vpn_client_sm_get_state(
    const dap_chain_net_vpn_client_sm_t *a_sm) {
    if (!a_sm) return VPN_STATE_DISCONNECTED;
    return a_sm->current_state;
}

int dap_chain_net_vpn_client_sm_register_callback(
    dap_chain_net_vpn_client_sm_t *a_sm,
    dap_chain_net_vpn_client_state_callback_t a_callback,
    void *a_user_data) {
    if (!a_sm || !a_callback) return -1;
    
    pthread_mutex_lock(&a_sm->mutex);
    
    if (a_sm->callback_count >= MAX_CALLBACKS) {
        log_it(L_ERROR, "Maximum number of callbacks reached");
        pthread_mutex_unlock(&a_sm->mutex);
        return -2;
    }
    
    a_sm->callbacks[a_sm->callback_count] = a_callback;
    a_sm->callback_user_data[a_sm->callback_count] = a_user_data;
    a_sm->callback_count++;
    
    pthread_mutex_unlock(&a_sm->mutex);
    return 0;
}

int dap_chain_net_vpn_client_sm_set_reconnect_policy(
    dap_chain_net_vpn_client_sm_t *a_sm,
    const dap_chain_net_vpn_client_reconnect_policy_t *a_policy) {
    if (!a_sm || !a_policy) return -1;
    
    pthread_mutex_lock(&a_sm->mutex);
    memcpy(&a_sm->reconnect_policy, a_policy, sizeof(dap_chain_net_vpn_client_reconnect_policy_t));
    pthread_mutex_unlock(&a_sm->mutex);
    
    log_it(L_INFO, "Reconnect policy updated: enabled=%d, max_attempts=%u, initial_delay=%u, max_delay=%u",
           a_policy->enabled, a_policy->max_attempts, a_policy->initial_delay_ms, a_policy->max_delay_ms);
    
    return 0;
}

int dap_chain_net_vpn_client_sm_get_reconnect_policy(
    const dap_chain_net_vpn_client_sm_t *a_sm,
    dap_chain_net_vpn_client_reconnect_policy_t *a_out_policy) {
    if (!a_sm || !a_out_policy) return -1;
    
    pthread_mutex_lock((pthread_mutex_t*)&a_sm->mutex);
    memcpy(a_out_policy, &a_sm->reconnect_policy, sizeof(dap_chain_net_vpn_client_reconnect_policy_t));
    pthread_mutex_unlock((pthread_mutex_t*)&a_sm->mutex);
    
    return 0;
}

int dap_chain_net_vpn_client_sm_set_connect_params(
    dap_chain_net_vpn_client_sm_t *a_sm,
    const dap_chain_net_vpn_client_connect_params_t *a_params) {
    if (!a_sm || !a_params) return -1;
    
    pthread_mutex_lock(&a_sm->mutex);
    
    // Free old params
    if (a_sm->connect_params) {
        dap_chain_net_vpn_client_connect_params_free(a_sm->connect_params);
    }
    
    // Copy new params
    a_sm->connect_params = DAP_NEW_Z(dap_chain_net_vpn_client_connect_params_t);
    if (!a_sm->connect_params) {
        pthread_mutex_unlock(&a_sm->mutex);
        return -2;
    }
    
    if (a_params->server_address) {
        a_sm->connect_params->server_address = dap_strdup(a_params->server_address);
    }
    a_sm->connect_params->server_port = a_params->server_port;
    if (a_params->network_name) {
        a_sm->connect_params->network_name = dap_strdup(a_params->network_name);
    }
    if (a_params->payment_tx_hash) {
        a_sm->connect_params->payment_tx_hash = dap_strdup(a_params->payment_tx_hash);
    }
    if (a_params->transport_type) {
        a_sm->connect_params->transport_type = dap_strdup(a_params->transport_type);
    }
    if (a_params->obfuscation_level) {
        a_sm->connect_params->obfuscation_level = dap_strdup(a_params->obfuscation_level);
    }
    a_sm->connect_params->connection_timeout_ms = a_params->connection_timeout_ms;
    a_sm->connect_params->no_routing = a_params->no_routing;
    a_sm->connect_params->no_dns = a_params->no_dns;
    
    // Update connection timeout in state machine
    if (a_params->connection_timeout_ms > 0) {
        a_sm->connection_timeout_ms = a_params->connection_timeout_ms;
        log_it(L_DEBUG, "Connection timeout set to %u ms from params", a_sm->connection_timeout_ms);
    }
    
    pthread_mutex_unlock(&a_sm->mutex);
    return 0;
}

void dap_chain_net_vpn_client_sm_set_keepalive(
    dap_chain_net_vpn_client_sm_t *a_sm,
    uint32_t a_interval_ms,
    uint32_t a_timeout_ms) {
    if (!a_sm) return;
    
    pthread_mutex_lock(&a_sm->mutex);
    a_sm->keepalive_interval_ms = a_interval_ms;
    a_sm->keepalive_timeout_ms = a_timeout_ms;
    pthread_mutex_unlock(&a_sm->mutex);
    
    log_it(L_DEBUG, "Keepalive parameters set: interval=%u ms, timeout=%u ms",
           a_interval_ms, a_timeout_ms);
}

void dap_chain_net_vpn_client_sm_set_connection_timeout(
    dap_chain_net_vpn_client_sm_t *a_sm,
    uint32_t a_timeout_ms) {
    if (!a_sm) return;
    
    pthread_mutex_lock(&a_sm->mutex);
    a_sm->connection_timeout_ms = a_timeout_ms;
    pthread_mutex_unlock(&a_sm->mutex);
    
    log_it(L_DEBUG, "Connection timeout set: %u ms", a_timeout_ms);
}

void dap_chain_net_vpn_client_connect_params_free(dap_chain_net_vpn_client_connect_params_t *a_params) {
    if (!a_params) return;
    
    DAP_DELETE(a_params->server_address);
    DAP_DELETE(a_params->network_name);
    DAP_DELETE(a_params->payment_tx_hash);
    DAP_DELETE(a_params->transport_type);
    DAP_DELETE(a_params->obfuscation_level);
    DAP_DELETE(a_params);
}

// Keepalive timer callback
static bool keepalive_timer_callback(void *a_arg) {
    dap_chain_net_vpn_client_sm_t *l_sm = (dap_chain_net_vpn_client_sm_t*)a_arg;
    if (!l_sm) return false;
    
    pthread_mutex_lock(&l_sm->mutex);
    
    // Check if we've received a response within timeout window
    int64_t l_now = time(NULL);
    int64_t l_elapsed = l_now - l_sm->last_keepalive_response;
    
    if (l_elapsed > (l_sm->keepalive_timeout_ms / 1000)) {
        log_it(L_WARNING, "Keepalive timeout: %ld seconds since last response (threshold: %u ms)",
               (long)l_elapsed, l_sm->keepalive_timeout_ms);
        
        // Trigger KEEPALIVE_TIMEOUT event
        pthread_mutex_unlock(&l_sm->mutex);
        dap_chain_net_vpn_client_sm_transition(l_sm, VPN_EVENT_KEEPALIVE_TIMEOUT);
        return false; // Stop timer, state machine will handle reconnect
    }
    
    // TODO: Send actual keepalive packet to server
    log_it(L_DEBUG, "Keepalive check: connection alive (%ld seconds since last response)",
           (long)l_elapsed);
    
    pthread_mutex_unlock(&l_sm->mutex);
    return true; // Continue timer
}

int dap_chain_net_vpn_client_sm_start_keepalive(
    dap_chain_net_vpn_client_sm_t *a_sm,
    uint32_t a_interval_ms,
    uint32_t a_timeout_ms) {
    if (!a_sm) return -1;
    
    pthread_mutex_lock(&a_sm->mutex);
    
    // Stop existing timer if running
    if (a_sm->keepalive_timer) {
        dap_timerfd_delete_mt(dap_worker_get_current(), a_sm->keepalive_timer->esocket_uuid);
        a_sm->keepalive_timer = NULL;
    }
    
    a_sm->keepalive_interval_ms = a_interval_ms;
    a_sm->keepalive_timeout_ms = a_timeout_ms;
    a_sm->last_keepalive_response = time(NULL);
    
    // Create timer with interval
    a_sm->keepalive_timer = dap_timerfd_create(
        a_interval_ms,
        keepalive_timer_callback,
        a_sm
    );
    
    if (!a_sm->keepalive_timer) {
        log_it(L_ERROR, "Failed to create keepalive timer");
        pthread_mutex_unlock(&a_sm->mutex);
        return -1;
    }
    
    // Timer already started on creation via dap_timerfd_start
    // Reset timer if needed
    dap_timerfd_reset_mt(dap_worker_get_current(), a_sm->keepalive_timer->esocket_uuid);
    
    log_it(L_INFO, "Keepalive started: interval=%u ms, timeout=%u ms", a_interval_ms, a_timeout_ms);
    
    pthread_mutex_unlock(&a_sm->mutex);
    return 0;
}

void dap_chain_net_vpn_client_sm_stop_keepalive(dap_chain_net_vpn_client_sm_t *a_sm) {
    if (!a_sm) return;
    
    pthread_mutex_lock(&a_sm->mutex);
    
    if (a_sm->keepalive_timer) {
        dap_timerfd_delete_mt(dap_worker_get_current(), a_sm->keepalive_timer->esocket_uuid);
        a_sm->keepalive_timer = NULL;
    }
    
    log_it(L_INFO, "Keepalive stopped");
    
    pthread_mutex_unlock(&a_sm->mutex);
}

void dap_chain_net_vpn_client_sm_keepalive_response(dap_chain_net_vpn_client_sm_t *a_sm) {
    if (!a_sm) return;
    
    pthread_mutex_lock(&a_sm->mutex);
    a_sm->last_keepalive_response = time(NULL);
    pthread_mutex_unlock(&a_sm->mutex);
    
    log_it(L_DEBUG, "Keepalive response received");
}

int dap_chain_net_vpn_client_sm_get_stats(
    const dap_chain_net_vpn_client_sm_t *a_sm,
    uint64_t *a_out_uptime_sec,
    uint64_t *a_out_bytes_sent,
    uint64_t *a_out_bytes_received) {
    if (!a_sm) return -1;
    
    pthread_mutex_lock((pthread_mutex_t*)&a_sm->mutex);
    
    if (a_out_uptime_sec) {
        if (a_sm->connection_start_time > 0) {
            *a_out_uptime_sec = (uint64_t)(time(NULL) - a_sm->connection_start_time);
        } else {
            *a_out_uptime_sec = 0;
        }
    }
    
    if (a_out_bytes_sent) {
        *a_out_bytes_sent = a_sm->bytes_sent;
    }
    
    if (a_out_bytes_received) {
        *a_out_bytes_received = a_sm->bytes_received;
    }
    
    pthread_mutex_unlock((pthread_mutex_t*)&a_sm->mutex);
    return 0;
}

uint32_t dap_chain_net_vpn_client_sm_get_reconnect_attempt(
    const dap_chain_net_vpn_client_sm_t *a_sm) {
    if (!a_sm) return 0;
    return a_sm->reconnect_attempt;
}

bool dap_chain_net_vpn_client_sm_is_connected(const dap_chain_net_vpn_client_sm_t *a_sm) {
    if (!a_sm) return false;
    dap_chain_net_vpn_client_state_t l_state = a_sm->current_state;
    return (l_state == VPN_STATE_CONNECTED || 
            l_state == VPN_STATE_RECONNECTING);
}

// State entry/exit action implementations

static void state_disconnected_entry(dap_chain_net_vpn_client_sm_t *a_sm) {
    log_it(L_INFO, "Entered DISCONNECTED state - cleaning up connection");
    
    // Reset connection state
    a_sm->reconnect_attempt = 0;
    a_sm->connection_start_time = 0;
    a_sm->connection_established_time = 0;
    
    // Cleanup TUN device
    if (a_sm->tun_handle) {
        log_it(L_INFO, "Closing TUN device: %s", a_sm->tun_device_name ? a_sm->tun_device_name : "unknown");
        dap_net_tun_deinit(a_sm->tun_handle);
        a_sm->tun_handle = NULL;
    }
    
    // Free TUN configuration
    DAP_DELETE(a_sm->tun_device_name);
    DAP_DELETE(a_sm->tun_local_ip);
    DAP_DELETE(a_sm->tun_remote_ip);
    a_sm->tun_mtu = 0;
    
    // Clear VPN channel reference
    a_sm->vpn_channel = NULL;
    
    // Close wallet if open
    if (a_sm->wallet) {
        log_it(L_DEBUG, "Closing wallet");
        dap_vpn_client_wallet_close(a_sm->wallet);
        a_sm->wallet = NULL;
    }
    
    // Free receipt collector if exists
    if (a_sm->receipt_collector) {
        log_it(L_DEBUG, "Freeing receipt collector");
        dap_vpn_client_receipt_collector_delete(a_sm->receipt_collector);
        a_sm->receipt_collector = NULL;
    }
    
    // Close node client connection if exists
    if (a_sm->node_client) {
        log_it(L_INFO, "Closing node client connection");
        dap_chain_node_client_close_mt(a_sm->node_client);
        a_sm->node_client = NULL;
    }
    
    // Restore network configuration if we had a connection
    if (a_sm->network_backup) {
        log_it(L_INFO, "Restoring original network configuration");
        
        if (dap_chain_net_vpn_client_network_restore(a_sm->network_backup) != 0) {
            log_it(L_ERROR, "Failed to restore network configuration");
            // Try to remove backup file anyway
        } else {
            log_it(L_INFO, "Network configuration restored successfully");
        }
        
        // Remove backup file
        if (dap_chain_net_vpn_client_backup_remove(NULL) != 0) {
            log_it(L_WARNING, "Failed to remove network backup file");
        } else {
            log_it(L_INFO, "Network backup file removed");
        }
        
        // Free backup structure
        dap_chain_net_vpn_client_backup_free(a_sm->network_backup);
        a_sm->network_backup = NULL;
    }
    
    log_it(L_INFO, "DISCONNECTED state: cleanup complete");
}

static void state_connecting_entry(dap_chain_net_vpn_client_sm_t *a_sm) {
    log_it(L_INFO, "Entered CONNECTING state");
    a_sm->connection_start_time = time(NULL);
    
    if (!a_sm->connect_params) {
        log_it(L_ERROR, "No connection parameters available");
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
        return;
    }
    
    // Determine transport to use
    dap_stream_transport_type_t l_transport_type = DAP_STREAM_TRANSPORT_HTTP; // default
    
    if (a_sm->connect_params->transport_type) {
        // User explicitly specified transport type - use it
        if (dap_strcmp(a_sm->connect_params->transport_type, "udp")) {
            l_transport_type = DAP_STREAM_TRANSPORT_UDP_BASIC;
        } else if (dap_strcmp(a_sm->connect_params->transport_type, "websocket") || 
                   dap_strcmp(a_sm->connect_params->transport_type, "ws")) {
            l_transport_type = DAP_STREAM_TRANSPORT_WEBSOCKET;
        } else if (dap_strcmp(a_sm->connect_params->transport_type, "http")) {
            l_transport_type = DAP_STREAM_TRANSPORT_HTTP;
        } else if (dap_strcmp(a_sm->connect_params->transport_type, "tls")) {
            l_transport_type = DAP_STREAM_TRANSPORT_TLS_DIRECT;
        } else {
            log_it(L_WARNING, "Unknown transport type '%s', falling back to HTTP",
                   a_sm->connect_params->transport_type);
            l_transport_type = DAP_STREAM_TRANSPORT_HTTP;
        }
        
        log_it(L_INFO, "Using explicitly specified transport: %s", 
               a_sm->connect_params->transport_type);
    } else {
        // No explicit transport specified - use default HTTP
        log_it(L_INFO, "No transport specified, using default: HTTP");
    }
    
    // Store selected transport
    a_sm->selected_protocol = l_transport_type;
    
    // Create node info structure
    dap_chain_node_info_t *l_node_info = DAP_NEW_Z_SIZE(dap_chain_node_info_t,
                                                         sizeof(dap_chain_node_info_t) +
                                                         strlen(a_sm->connect_params->server_address) + 1);
    if (!l_node_info) {
        log_it(L_CRITICAL, "Failed to allocate node info");
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
        return;
    }
    
    l_node_info->ext_port = a_sm->connect_params->server_port;
    strcpy(l_node_info->ext_host, a_sm->connect_params->server_address);
    l_node_info->ext_host_len = strlen(a_sm->connect_params->server_address);
    
    // Get network
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_sm->connect_params->network_name);
    if (!l_net) {
        log_it(L_ERROR, "Network '%s' not found", a_sm->connect_params->network_name);
        DAP_DELETE(l_node_info);
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
        return;
    }
    
    // Auto TX creation if wallet specified and no TX hashes provided
    if (a_sm->connect_params->wallet_name && !a_sm->connect_params->payment_tx_hashes) {
        log_it(L_INFO, "Auto-creating payment TX set from wallet '%s' for %u-hop route",
               a_sm->connect_params->wallet_name, a_sm->connect_params->hop_count);
        
        // Open wallet
        a_sm->wallet = dap_vpn_client_wallet_open(a_sm->connect_params->wallet_name);
        if (!a_sm->wallet) {
            log_it(L_ERROR, "Failed to open wallet '%s'", a_sm->connect_params->wallet_name);
            DAP_DELETE(l_node_info);
            dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
            return;
        }
        
        // Create TX set (works for both single-hop and multi-hop)
        // CRITICAL: All payment parameters must be explicitly specified
        if (!a_sm->connect_params->payment_token || strlen(a_sm->connect_params->payment_token) == 0) {
            log_it(L_ERROR, "Payment token not specified - cannot create payment TX");
            DAP_DELETE(l_node_info);
            dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
            return;
        }
        
        if (a_sm->connect_params->service_units == 0) {
            log_it(L_ERROR, "Service units not specified - cannot create payment TX");
            DAP_DELETE(l_node_info);
            dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
            return;
        }
        
        if (a_sm->connect_params->service_unit_type == 0) {
            log_it(L_ERROR, "Service unit type not specified - cannot create payment TX");
            DAP_DELETE(l_node_info);
            dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
            return;
        }
        
        log_it(L_INFO, "Creating payment TX set: %"DAP_UINT64_FORMAT_U" %s units in %s token",
               a_sm->connect_params->service_units, 
               dap_chain_net_srv_unit_enum_to_str(a_sm->connect_params->service_unit_type), 
               a_sm->connect_params->payment_token);
        
        a_sm->connect_params->payment_tx_hashes = dap_chain_net_vpn_client_multihop_tx_set_create(
            a_sm->wallet,
            l_net,
            a_sm->connect_params->route,
            a_sm->connect_params->hop_count,
            a_sm->connect_params->tunnel_count,
            a_sm->connect_params->service_units,
            a_sm->connect_params->service_unit_type,
            a_sm->connect_params->payment_token,
            a_sm->connect_params->session_id
        );
        
        if (!a_sm->connect_params->payment_tx_hashes) {
            log_it(L_ERROR, "Failed to create payment TX set");
            DAP_DELETE(l_node_info);
            dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
            return;
        }
        
        log_it(L_NOTICE, "Created %u payment TX(s) for route", a_sm->connect_params->hop_count);
    }
    
    // Create receipt collector (for both single-hop and multi-hop)
    if (a_sm->connect_params->payment_tx_hashes && a_sm->connect_params->hop_count > 0) {
        log_it(L_INFO, "Creating receipt collector for %u-hop route (session_id=%u)",
               a_sm->connect_params->hop_count, a_sm->connect_params->session_id);
        
        a_sm->receipt_collector = dap_vpn_client_receipt_collector_create(
            a_sm->connect_params->session_id,
            l_net,
            a_sm->connect_params->route,
            a_sm->connect_params->hop_count,
            a_sm->connect_params->payment_tx_hashes
        );
        
        if (!a_sm->receipt_collector) {
            log_it(L_ERROR, "Failed to create receipt collector");
            DAP_DELETE(l_node_info);
            dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
            return;
        }
    }
    
    // Create client with VPN service channel ('R' = 0x52)
    const char l_vpn_channels[] = {'R', '\0'};
    dap_chain_node_client_t *l_node_client = dap_chain_node_client_create_n_connect(
        l_net, l_node_info, l_vpn_channels, NULL, NULL);
    
    if (!l_node_client) {
        log_it(L_ERROR, "Failed to create node client");
        DAP_DELETE(l_node_info);
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
        return;
    }
    
    // Set transport type on the underlying dap_client
    dap_client_set_transport_type(l_node_client->client, l_transport_type);
    log_it(L_INFO, "Transport type %d set on client connection", l_transport_type);
    
    // Store node client in state machine
    a_sm->node_client = l_node_client;
    
    // Wait for connection to establish (use configured timeout or default)
    int timeout_ms = a_sm->connection_timeout_ms > 0 ? 
                     a_sm->connection_timeout_ms : DEFAULT_CONNECTION_TIMEOUT_MS;
    int l_result = dap_chain_node_client_wait(l_node_client, NODE_CLIENT_STATE_ESTABLISHED, timeout_ms);
    
    if (l_result != 1) {
        log_it(L_ERROR, "Connection timeout or error (result: %d, timeout: %d ms)", 
               l_result, timeout_ms);
        dap_chain_node_client_close_mt(l_node_client);
        a_sm->node_client = NULL;
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
        return;
    }
    
    log_it(L_INFO, "Connection established successfully with transport %d", l_transport_type);
    dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_SUCCESS);
}

// Forward declaration for callback
static void protocol_probe_complete_callback(dap_vpn_protocol_probe_t *a_probe,
                                              dap_vpn_protocol_probe_result_t *a_results,
                                              void *a_user_data);
static void connectivity_test_complete_callback(dap_vpn_connectivity_test_t *a_test,
                                                 dap_vpn_connectivity_result_t *a_result,
                                                 void *a_user_data);

static void state_verifying_connectivity_entry(dap_chain_net_vpn_client_sm_t *a_sm) {
    log_it(L_INFO, "Entered VERIFYING_CONNECTIVITY state - starting protocol probe");
    
    if (!a_sm->connect_params) {
        log_it(L_ERROR, "No connection parameters available for protocol probe");
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_VERIFICATION_FAILED);
        return;
    }
    
    // Get available transports
    dap_stream_transport_t *l_transports[] = {
        dap_stream_transport_find(DAP_STREAM_TRANSPORT_UDP_BASIC),
        dap_stream_transport_find(DAP_STREAM_TRANSPORT_HTTP),
        dap_stream_transport_find(DAP_STREAM_TRANSPORT_WEBSOCKET),
        dap_stream_transport_find(DAP_STREAM_TRANSPORT_UDP_QUIC_LIKE)
    };
    
    // Create protocol probe parameters
    dap_vpn_protocol_probe_params_t l_probe_params = {
        .server_address = a_sm->connect_params->server_address,
        .server_port = a_sm->connect_params->server_port,
        .protocols = l_transports,
        .protocol_count = 4,
        .timeout_ms = DEFAULT_PROTOCOL_PROBE_TIMEOUT_MS,
        .per_protocol_timeout_ms = DEFAULT_PROTOCOL_PROBE_PER_PROTO_TIMEOUT_MS,
        .on_probe_complete = protocol_probe_complete_callback,
        .user_data = a_sm,
        .parallel_mode = true,
        .skip_blocked_protocols = false
    };
    
    // Start parallel protocol probe
    a_sm->protocol_probe = dap_vpn_protocol_probe_parallel_start(&l_probe_params);
    if (!a_sm->protocol_probe) {
        log_it(L_ERROR, "Failed to start protocol probe");
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_VERIFICATION_FAILED);
        return;
    }
    
    log_it(L_INFO, "Protocol probe started for %u protocols", l_probe_params.protocol_count);
}

static void protocol_probe_complete_callback(dap_vpn_protocol_probe_t *a_probe,
                                              dap_vpn_protocol_probe_result_t *a_results,
                                              void *a_user_data) {
    dap_chain_net_vpn_client_sm_t *l_sm = (dap_chain_net_vpn_client_sm_t *)a_user_data;
    
    log_it(L_INFO, "Protocol probe completed");
    
    if (!a_results || a_results->protocol_count == 0) {
        log_it(L_ERROR, "No protocol probe results");
        dap_chain_net_vpn_client_sm_transition(l_sm, VPN_EVENT_VERIFICATION_FAILED);
        return;
    }
    
    // Use best protocol from results
    if (!a_results->best_protocol) {
        log_it(L_ERROR, "No working protocols found");
        dap_chain_net_vpn_client_sm_transition(l_sm, VPN_EVENT_VERIFICATION_FAILED);
        return;
    }
    
    dap_vpn_protocol_result_t *l_best = a_results->best_protocol;
    
    UNUSED(a_probe);
    
    log_it(L_INFO, "Best protocol: %s (score=%.2f)", 
           l_best->protocol_name, l_best->score);
    
    // Store selected transport from best protocol
    l_sm->selected_protocol = l_best->transport ? l_best->transport->type : DAP_STREAM_TRANSPORT_HTTP;
    
    // Now start connectivity test for the selected protocol
    dap_vpn_connectivity_test_params_t l_test_params = {
        .stream = l_best->stream,
        .protocol_name = l_best->protocol_name,
        .speed_test_url = "http://speedtest.example.com",
        .speed_test_size_mb = 10,
        .enable_speed_test = true,
        .latency_test_target = l_sm->connect_params->server_address,
        .latency_test_count = 3,
        .enable_latency_test = true,
        .dns_test_hostname = "dns.google.com",
        .http_test_url = "http://clients3.google.com/generate_204",
        .https_test_url = "https://www.google.com",
        .enable_connectivity_verify = true,
        .timeout_ms = 30000,
        .per_test_timeout_ms = 10000,
        .on_complete = connectivity_test_complete_callback,
        .user_data = l_sm
    };
    
    l_sm->connectivity_test = dap_vpn_connectivity_test_start(&l_test_params);
    if (!l_sm->connectivity_test) {
        log_it(L_ERROR, "Failed to start connectivity test");
        dap_chain_net_vpn_client_sm_transition(l_sm, VPN_EVENT_VERIFICATION_FAILED);
        return;
    }
    
    log_it(L_INFO, "Connectivity test started for protocol %s", l_best->protocol_name);
}

static void connectivity_test_complete_callback(dap_vpn_connectivity_test_t *a_test, 
                                                 dap_vpn_connectivity_result_t *a_result,
                                                 void *a_user_data) {
    dap_chain_net_vpn_client_sm_t *l_sm = (dap_chain_net_vpn_client_sm_t *)a_user_data;
    
    log_it(L_INFO, "Connectivity test completed");
    
    if (!a_result) {
        log_it(L_ERROR, "No connectivity test result");
        dap_chain_net_vpn_client_sm_transition(l_sm, VPN_EVENT_VERIFICATION_FAILED);
        return;
    }
    
    // Log detailed results
    log_it(L_INFO, "Connectivity test results:");
    log_it(L_INFO, "  DNS: %s",
           a_result->dns_working ? "OK" : "FAIL");
    log_it(L_INFO, "  HTTP: %s",
           a_result->http_working ? "OK" : "FAIL");
    log_it(L_INFO, "  HTTPS: %s",
           a_result->https_working ? "OK" : "FAIL");
    log_it(L_INFO, "  Latency: %u ms (min=%u, max=%u, jitter=%.1f)",
           a_result->latency_ms,
           a_result->latency_min_ms,
           a_result->latency_max_ms,
           a_result->jitter_ms);
    log_it(L_INFO, "  Speed: %.2f Mbps",
           a_result->throughput_mbps);
    log_it(L_INFO, "  Overall score: %.2f", a_result->score);
    
    // Check if connectivity is acceptable (score >= 0.4)
    #define CONNECTIVITY_SCORE_THRESHOLD 0.4f
    
    if (a_result->score >= CONNECTIVITY_SCORE_THRESHOLD) {
        log_it(L_INFO, "Connectivity verification SUCCESS (score %.2f >= threshold %.2f)",
               a_result->score, CONNECTIVITY_SCORE_THRESHOLD);
        
        // Trigger success event
        dap_chain_net_vpn_client_sm_transition(l_sm, VPN_EVENT_VERIFICATION_SUCCESS);
    } else {
        log_it(L_WARNING, "Connectivity verification FAILED (score %.2f < threshold %.2f)",
               a_result->score, CONNECTIVITY_SCORE_THRESHOLD);
        dap_chain_net_vpn_client_sm_transition(l_sm, VPN_EVENT_VERIFICATION_FAILED);
    }
    
    UNUSED(a_test);
}

static void state_routing_setup_entry(dap_chain_net_vpn_client_sm_t *a_sm) {
    log_it(L_INFO, "Entered ROUTING_SETUP state - configuring routing table");
    
    if (!a_sm->connect_params) {
        log_it(L_ERROR, "No connection parameters available for routing setup");
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
        return;
    }
    
    // Step 1: Get original gateway and interface
    char l_original_gateway[64] = {0};
    char l_original_interface[64] = {0};
    
    if (dap_chain_net_vpn_client_network_get_default_gateway(l_original_gateway, sizeof(l_original_gateway)) != 0) {
        log_it(L_ERROR, "Failed to get original default gateway");
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
        return;
    }
    
    if (dap_chain_net_vpn_client_network_get_default_interface(l_original_interface, sizeof(l_original_interface)) != 0) {
        log_it(L_ERROR, "Failed to get original default interface");
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
        return;
    }
    
    log_it(L_INFO, "Original gateway: %s, interface: %s", l_original_gateway, l_original_interface);
    
    // Step 2: Backup current network configuration
    // Platform-specific code will collect DNS and determine VPN interface name
    if (dap_chain_net_vpn_client_network_backup(
            l_original_gateway,
            l_original_interface,
            &a_sm->network_backup
        ) != 0) {
        log_it(L_ERROR, "Failed to backup network configuration");
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
        return;
    }
    
    log_it(L_INFO, "Network configuration backed up successfully");
    
    // Step 3: Add host route for VPN server IP (so it goes through original gateway)
    char l_vpn_server_ip[INET_ADDRSTRLEN];
    // Resolve server_addr to IP if it's a hostname
    if (dap_chain_net_vpn_client_network_resolve_hostname(
            a_sm->connect_params->server_address,
            l_vpn_server_ip,
            sizeof(l_vpn_server_ip)
        ) != 0) {
        log_it(L_ERROR, "Failed to resolve VPN server hostname: %s", a_sm->connect_params->server_address);
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
        return;
    }
    
    log_it(L_INFO, "VPN server resolved: %s -> %s", a_sm->connect_params->server_address, l_vpn_server_ip);
    
    if (dap_chain_net_vpn_client_network_add_host_route(
            l_vpn_server_ip,
            l_original_gateway,
            l_original_interface
        ) != 0) {
        log_it(L_ERROR, "Failed to add host route for VPN server");
        // Restore network config before failing
        dap_chain_net_vpn_client_network_restore(a_sm->network_backup);
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
        return;
    }
    
    log_it(L_INFO, "Host route added for VPN server: %s via %s", l_vpn_server_ip, l_original_gateway);
    
    // Step 4: VPN routing and DNS setup deferred
    // These will be configured once we have:
    // - VPN interface name (from TUN/TAP device creation)
    // - VPN gateway IP (from server handshake)
    // - DNS servers (from server or use existing)
    // This happens in the CONNECTED state after successful stream establishment
    
    log_it(L_INFO, "Network backup and host route configured, deferring full routing setup");
    
    // Step 5: Save backup to file (for crash recovery)
    if (a_sm->network_backup) {
        // Populate backup with VPN server info
        a_sm->network_backup->vpn_server_ip = dap_strdup(l_vpn_server_ip);
        a_sm->network_backup->connection_state = dap_strdup("routing_setup");
        
        if (dap_chain_net_vpn_client_backup_save(a_sm->network_backup, NULL) != 0) {
            log_it(L_WARNING, "Failed to save network backup to file");
        } else {
            log_it(L_INFO, "Network backup saved for crash recovery");
        }
    }
    
    // Step 7: Routing setup complete - trigger success event
    log_it(L_INFO, "Routing setup completed successfully");
    dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_ROUTING_COMPLETE);
}

static void state_connected_entry(dap_chain_net_vpn_client_sm_t *a_sm) {
    log_it(L_INFO, "Entered CONNECTED state");
    a_sm->connection_established_time = time(NULL);
    a_sm->reconnect_attempt = 0;  // Reset on successful connection
    
    // Get VPN channel from node client
    if (!a_sm->node_client || !a_sm->node_client->client || !a_sm->node_client->client->stream) {
        log_it(L_ERROR, "Invalid node client - cannot setup TUN device");
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_LOST);
        return;
    }
    
    // Find VPN service channel ('R')
    a_sm->vpn_channel = dap_client_get_stream_ch_unsafe(a_sm->node_client->client, 'R');
    if (!a_sm->vpn_channel) {
        log_it(L_ERROR, "VPN service channel not found");
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_LOST);
        return;
    }
    
    // TODO: Get VPN parameters from server handshake (local IP, remote IP, MTU)
    // For now, use reasonable defaults
    const char *l_local_ip = "10.8.0.2";   // Client IP in VPN subnet
    const char *l_remote_ip = "10.8.0.1";  // Server gateway IP
    const char *l_netmask = "255.255.255.0";
    uint32_t l_mtu = 1420;  // Conservative MTU for VPN
    
    // Create TUN device configuration
    dap_net_tun_config_t l_tun_config = {
        .mode = DAP_NET_TUN_MODE_CLIENT,
        .local_ip = l_local_ip,
        .remote_ip = l_remote_ip,
        .netmask = l_netmask,
        .mtu = l_mtu,
        .data_received_callback = s_tun_data_received_callback,
        .error_callback = s_tun_error_callback,
        .user_data = a_sm
    };
    
    // Initialize TUN device
    log_it(L_INFO, "Creating TUN device: local=%s, remote=%s, mtu=%u", l_local_ip, l_remote_ip, l_mtu);
    a_sm->tun_handle = dap_net_tun_init(&l_tun_config);
    
    if (!a_sm->tun_handle) {
        log_it(L_ERROR, "Failed to initialize TUN device");
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_LOST);
        return;
    }
    
    // Get and store TUN device name
    const char *l_device_name = dap_net_tun_get_device_name(a_sm->tun_handle);
    if (l_device_name) {
        a_sm->tun_device_name = dap_strdup(l_device_name);
        log_it(L_NOTICE, "TUN device created: %s", l_device_name);
    }
    
    // Store configuration for later use
    a_sm->tun_local_ip = dap_strdup(l_local_ip);
    a_sm->tun_remote_ip = dap_strdup(l_remote_ip);
    a_sm->tun_mtu = l_mtu;
    
    // Register stream channel packet callback
    a_sm->vpn_channel->stream->stream_worker->callbacks.read_callback = (dap_events_socket_callback_t)s_stream_ch_packet_in_callback;
    a_sm->vpn_channel->stream->stream_worker->callbacks.read_callback_arg = a_sm;
    
    log_it(L_NOTICE, "VPN tunnel fully established and operational");
    
    // Start keepalive timer
    dap_chain_net_vpn_client_sm_start_keepalive(
        a_sm,
        a_sm->keepalive_interval_ms,
        a_sm->keepalive_timeout_ms
    );
}

static void state_verifying_connectivity_exit(dap_chain_net_vpn_client_sm_t *a_sm) {
    log_it(L_INFO, "Exiting VERIFYING_CONNECTIVITY state");
    
    // Stop and cleanup protocol probe if still running
    if (a_sm->protocol_probe) {
        dap_vpn_protocol_probe_destroy(a_sm->protocol_probe);
        a_sm->protocol_probe = NULL;
        log_it(L_DEBUG, "Protocol probe stopped and cleaned up");
    }
    
    // Stop and cleanup connectivity test if still running
    if (a_sm->connectivity_test) {
        dap_vpn_connectivity_test_destroy(a_sm->connectivity_test);
        a_sm->connectivity_test = NULL;
        log_it(L_DEBUG, "Connectivity test stopped and cleaned up");
    }
}

static void state_routing_setup_exit(dap_chain_net_vpn_client_sm_t *a_sm) {
    log_it(L_INFO, "Exiting ROUTING_SETUP state");
    // Nothing specific to cleanup here - routing config stays in place
    // If we're exiting due to error, state_connect_failed_entry will handle restore
}

static void state_connected_exit(dap_chain_net_vpn_client_sm_t *a_sm) {
    log_it(L_INFO, "Exiting CONNECTED state");
    dap_chain_net_vpn_client_sm_stop_keepalive(a_sm);
}

static void state_connection_lost_entry(dap_chain_net_vpn_client_sm_t *a_sm) {
    log_it(L_WARNING, "Entered CONNECTION_LOST state");
    // TODO: Preserve backup file
    
    // Decide: reconnect or give up?
    if (a_sm->reconnect_policy.enabled) {
        if (a_sm->reconnect_policy.max_attempts == 0 || 
            a_sm->reconnect_attempt < a_sm->reconnect_policy.max_attempts) {
            // Trigger reconnect
            dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_SUCCESS);
        } else {
            log_it(L_ERROR, "Max reconnect attempts reached, giving up");
            dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
        }
    } else {
        log_it(L_INFO, "Auto-reconnect disabled, transitioning to DISCONNECTED");
        dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_FAILED);
    }
}

static void state_reconnecting_entry(dap_chain_net_vpn_client_sm_t *a_sm) {
    a_sm->reconnect_attempt++;
    
    // Calculate backoff delay: initial_delay * 2^attempt + jitter
    uint32_t l_delay = a_sm->reconnect_policy.initial_delay_ms * (1 << (a_sm->reconnect_attempt - 1));
    if (l_delay > a_sm->reconnect_policy.max_delay_ms) {
        l_delay = a_sm->reconnect_policy.max_delay_ms;
    }
    
    // Add jitter (0-1000ms)
    l_delay += (rand() % 1000);
    
    log_it(L_INFO, "Entered RECONNECTING state (attempt %u/%u, delay %u ms)",
           a_sm->reconnect_attempt,
           a_sm->reconnect_policy.max_attempts,
           l_delay);
    
    a_sm->last_reconnect_time = time(NULL);
    
    // TODO: Apply backoff delay
    // TODO: Start reconnection process
}

static void state_disconnecting_entry(dap_chain_net_vpn_client_sm_t *a_sm) {
    log_it(L_INFO, "Entered DISCONNECTING state - graceful shutdown");
    
    // Restore network configuration
    if (a_sm->network_backup) {
        log_it(L_INFO, "Restoring original network configuration");
        
        if (dap_chain_net_vpn_client_network_restore(a_sm->network_backup) != 0) {
            log_it(L_ERROR, "Failed to restore network configuration");
        } else {
            log_it(L_INFO, "Network configuration restored successfully");
        }
    }
    
    // Trigger transition to DISCONNECTED after restore
    dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_CONNECTION_SUCCESS);
}

static void state_connect_failed_entry(dap_chain_net_vpn_client_sm_t *a_sm) {
    log_it(L_ERROR, "Entered CONNECT_FAILED state - connection attempt failed");
    
    // Restore network configuration (if any changes were made)
    if (a_sm->network_backup) {
        log_it(L_INFO, "Restoring original network configuration after failure");
        
        if (dap_chain_net_vpn_client_network_restore(a_sm->network_backup) != 0) {
            log_it(L_ERROR, "Failed to restore network configuration");
        } else {
            log_it(L_INFO, "Network configuration restored successfully");
        }
        
        // Remove backup file
        if (dap_chain_net_vpn_client_backup_remove(NULL) != 0) {
            log_it(L_WARNING, "Failed to remove network backup file");
        }
        
        // Free backup structure
        dap_chain_net_vpn_client_backup_free(a_sm->network_backup);
        a_sm->network_backup = NULL;
    }
    
    // Auto-transition to DISCONNECTED
    log_it(L_INFO, "Transitioning from CONNECT_FAILED to DISCONNECTED");
    dap_chain_net_vpn_client_sm_transition(a_sm, VPN_EVENT_USER_DISCONNECT);
}

static void state_shutdown_entry(dap_chain_net_vpn_client_sm_t *a_sm) {
    log_it(L_INFO, "Entered SHUTDOWN state - emergency shutdown");
    
    // Force stop all ongoing operations
    if (a_sm->protocol_probe) {
        dap_vpn_protocol_probe_destroy(a_sm->protocol_probe);
        a_sm->protocol_probe = NULL;
    }
    
    if (a_sm->connectivity_test) {
        dap_vpn_connectivity_test_destroy(a_sm->connectivity_test);
        a_sm->connectivity_test = NULL;
    }
    
    // Stop keepalive
    if (a_sm->keepalive_timer) {
        dap_timerfd_delete_mt(dap_worker_get_current(), a_sm->keepalive_timer->esocket_uuid);
        a_sm->keepalive_timer = NULL;
    }
    
    // Restore network configuration
    if (a_sm->network_backup) {
        log_it(L_INFO, "Emergency restore of network configuration");
        
        if (dap_chain_net_vpn_client_network_restore(a_sm->network_backup) != 0) {
            log_it(L_CRITICAL, "Failed to restore network configuration during shutdown");
        } else {
            log_it(L_INFO, "Network configuration restored");
        }
        
        // Remove backup file
        dap_chain_net_vpn_client_backup_remove(NULL);
        dap_chain_net_vpn_client_backup_free(a_sm->network_backup);
        a_sm->network_backup = NULL;
    }
    
    log_it(L_INFO, "SHUTDOWN state: all resources cleaned up");
}

/**
 * @brief TUN device data received callback
 * 
 * Called when packet is read from TUN device (outgoing from client's perspective).
 * We need to forward this packet to the VPN server through the stream channel.
 */
static void s_tun_data_received_callback(dap_net_tun_t *a_tun, const void *a_data, size_t a_data_size, void *a_user_data) {
    dap_chain_net_vpn_client_sm_t *l_sm = (dap_chain_net_vpn_client_sm_t *)a_user_data;
    
    if (!l_sm || !l_sm->vpn_channel || !a_data || a_data_size == 0) {
        log_it(L_WARNING, "Invalid parameters in TUN data callback");
        return;
    }
    
    if (l_sm->current_state != VPN_STATE_CONNECTED) {
        log_it(L_DEBUG, "Dropping packet: not in CONNECTED state (current: %d)", l_sm->current_state);
        return;
    }
    
    // Forward packet to VPN server via stream channel
    size_t l_written = dap_stream_ch_pkt_write_unsafe(l_sm->vpn_channel, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA,
                                                        a_data, a_data_size);
    
    if (l_written != a_data_size) {
        log_it(L_ERROR, "Failed to write packet to stream channel: %zu/%zu bytes", l_written, a_data_size);
        return;
    }
    
    // Update statistics
    pthread_mutex_lock(&l_sm->mutex);
    l_sm->bytes_sent += a_data_size;
    pthread_mutex_unlock(&l_sm->mutex);
    
    debug_if(s_debug_more, L_DEBUG, "Forwarded %zu bytes from TUN to server", a_data_size);
}

/**
 * @brief TUN device error callback
 * 
 * Called when TUN device encounters an error.
 */
static void s_tun_error_callback(dap_net_tun_t *a_tun, int a_error_code, const char *a_error_msg, void *a_user_data) {
    UNUSED(a_tun);
    dap_chain_net_vpn_client_sm_t *l_sm = (dap_chain_net_vpn_client_sm_t *)a_user_data;
    
    log_it(L_ERROR, "TUN device error (code %d): %s", a_error_code, a_error_msg ? a_error_msg : "unknown");
    
    if (l_sm && l_sm->current_state == VPN_STATE_CONNECTED) {
        // Trigger connection lost event
        dap_chain_net_vpn_client_sm_transition(l_sm, VPN_EVENT_CONNECTION_LOST);
    }
}

/**
 * @brief Stream channel packet received callback
 * 
 * Called when packet is received from VPN server (incoming traffic).
 * We need to write this packet to the TUN device.
 */
static void s_stream_ch_packet_in_callback(dap_stream_ch_t *a_ch, void *a_arg) {
    dap_chain_net_vpn_client_sm_t *l_sm = (dap_chain_net_vpn_client_sm_t *)a_arg;
    
    if (!l_sm || !l_sm->tun_handle || !a_ch) {
        log_it(L_WARNING, "Invalid parameters in stream packet callback");
        return;
    }
    
    if (l_sm->current_state != VPN_STATE_CONNECTED) {
        log_it(L_DEBUG, "Dropping packet: not in CONNECTED state (current: %d)", l_sm->current_state);
        return;
    }
    
    // Get packet from stream channel
    dap_stream_ch_pkt_t *l_pkt = dap_stream_ch_pkt_read_unsafe(a_ch);
    if (!l_pkt) {
        return;  // No packet available
    }
    
    // Check packet type
    if (l_pkt->hdr.type != DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA) {
        log_it(L_WARNING, "Unexpected packet type: 0x%02x", l_pkt->hdr.type);
        DAP_DELETE(l_pkt);
        return;
    }
    
    // Write packet to TUN device
    size_t l_data_size = l_pkt->hdr.size;
    if (l_data_size > 0) {
        int l_result = dap_net_tun_write(l_sm->tun_handle, l_pkt->data, l_data_size);
        
        if (l_result < 0) {
            log_it(L_ERROR, "Failed to write %zu bytes to TUN device (error: %d)", l_data_size, l_result);
        } else {
            // Update statistics
            pthread_mutex_lock(&l_sm->mutex);
            l_sm->bytes_received += l_data_size;
            pthread_mutex_unlock(&l_sm->mutex);
            
            debug_if(s_debug_more, L_DEBUG, "Wrote %zu bytes from server to TUN", l_data_size);
        }
    }
    
    DAP_DELETE(l_pkt);
}

