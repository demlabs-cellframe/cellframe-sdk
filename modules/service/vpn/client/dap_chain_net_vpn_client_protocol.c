#include "dap_chain_net_vpn_client_protocol.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_time.h"
#include "dap_stream_transport.h"
#include "dap_stream_obfuscation.h"
#include "json.h"
#include <string.h>
#include <stdlib.h>

#define LOG_TAG "dap_chain_net_vpn_client_protocol"

// --- Helper Functions ---

static const char* dap_stream_transport_type_to_string(dap_stream_transport_type_t a_type) {
    switch (a_type) {
        case DAP_STREAM_TRANSPORT_HTTP: return "http";
        case DAP_STREAM_TRANSPORT_UDP_BASIC: return "udp";
        case DAP_STREAM_TRANSPORT_UDP_RELIABLE: return "udp_reliable";
        case DAP_STREAM_TRANSPORT_WEBSOCKET: return "websocket";
        case DAP_STREAM_TRANSPORT_TLS_DIRECT: return "tls";
        default: return "unknown";
    }
}

static dap_stream_transport_type_t dap_stream_transport_type_from_string(const char *a_str) {
    if (!a_str) return DAP_STREAM_TRANSPORT_HTTP;
    if (dap_strcmp(a_str, "http")) return DAP_STREAM_TRANSPORT_HTTP;
    if (dap_strcmp(a_str, "udp")) return DAP_STREAM_TRANSPORT_UDP_BASIC;
    if (dap_strcmp(a_str, "udp_reliable")) return DAP_STREAM_TRANSPORT_UDP_RELIABLE;
    if (dap_strcmp(a_str, "websocket")) return DAP_STREAM_TRANSPORT_WEBSOCKET;
    if (dap_strcmp(a_str, "tls")) return DAP_STREAM_TRANSPORT_TLS_DIRECT;
    return DAP_STREAM_TRANSPORT_HTTP;
}

static const char* dap_stream_obfuscation_level_to_string(dap_stream_obfuscation_level_t a_level) {
    switch (a_level) {
        case DAP_STREAM_OBFS_LEVEL_NONE: return "none";
        case DAP_STREAM_OBFS_LEVEL_LOW: return "low";
        case DAP_STREAM_OBFS_LEVEL_MEDIUM: return "medium";
        case DAP_STREAM_OBFS_LEVEL_HIGH: return "high";
        case DAP_STREAM_OBFS_LEVEL_PARANOID: return "paranoid";
        default: return "none";
    }
}

static dap_stream_obfuscation_level_t dap_stream_obfuscation_level_from_string(const char *a_str) {
    if (!a_str) return DAP_STREAM_OBFS_LEVEL_NONE;
    if (dap_strcmp(a_str, "none")) return DAP_STREAM_OBFS_LEVEL_NONE;
    if (dap_strcmp(a_str, "low")) return DAP_STREAM_OBFS_LEVEL_LOW;
    if (dap_strcmp(a_str, "medium")) return DAP_STREAM_OBFS_LEVEL_MEDIUM;
    if (dap_strcmp(a_str, "high")) return DAP_STREAM_OBFS_LEVEL_HIGH;
    if (dap_strcmp(a_str, "paranoid")) return DAP_STREAM_OBFS_LEVEL_PARANOID;
    return DAP_STREAM_OBFS_LEVEL_NONE;
}

// --- Utility Functions ---

const char* dap_chain_net_vpn_client_ipc_method_to_string(dap_chain_net_vpn_client_ipc_method_t a_method) {
    switch (a_method) {
        case VPN_IPC_METHOD_CONNECT: return "connect";
        case VPN_IPC_METHOD_DISCONNECT: return "disconnect";
        case VPN_IPC_METHOD_STATUS: return "status";
        case VPN_IPC_METHOD_CONFIG_GET: return "config_get";
        case VPN_IPC_METHOD_CONFIG_SET: return "config_set";
        case VPN_IPC_METHOD_SHUTDOWN: return "shutdown";
        default: return "unknown";
    }
}

dap_chain_net_vpn_client_ipc_method_t dap_chain_net_vpn_client_ipc_method_from_string(const char *a_method_str) {
    if (!a_method_str) return VPN_IPC_METHOD_UNKNOWN;
    if (strcmp(a_method_str, "connect") == 0) return VPN_IPC_METHOD_CONNECT;
    if (strcmp(a_method_str, "disconnect") == 0) return VPN_IPC_METHOD_DISCONNECT;
    if (strcmp(a_method_str, "status") == 0) return VPN_IPC_METHOD_STATUS;
    if (strcmp(a_method_str, "config_get") == 0) return VPN_IPC_METHOD_CONFIG_GET;
    if (strcmp(a_method_str, "config_set") == 0) return VPN_IPC_METHOD_CONFIG_SET;
    if (strcmp(a_method_str, "shutdown") == 0) return VPN_IPC_METHOD_SHUTDOWN;
    if (strcmp(a_method_str, "subscribe") == 0) return VPN_IPC_METHOD_SUBSCRIBE;
    if (strcmp(a_method_str, "unsubscribe") == 0) return VPN_IPC_METHOD_UNSUBSCRIBE;
    return VPN_IPC_METHOD_UNKNOWN;
}

const char* dap_chain_net_vpn_client_connection_status_to_string(dap_chain_net_vpn_client_connection_status_t a_status) {
    switch (a_status) {
        case VPN_CONNECTION_STATUS_DISCONNECTED: return "disconnected";
        case VPN_CONNECTION_STATUS_CONNECTING: return "connecting";
        case VPN_CONNECTION_STATUS_CONNECTED: return "connected";
        case VPN_CONNECTION_STATUS_DISCONNECTING: return "disconnecting";
        case VPN_CONNECTION_STATUS_ERROR: return "error";
        default: return "unknown";
    }
}

const char* dap_chain_net_vpn_client_ipc_error_code_to_string(dap_chain_net_vpn_client_ipc_error_code_t a_code) {
    switch (a_code) {
        case VPN_IPC_ERROR_PARSE_ERROR: return "Parse error";
        case VPN_IPC_ERROR_INVALID_REQUEST: return "Invalid request";
        case VPN_IPC_ERROR_METHOD_NOT_FOUND: return "Method not found";
        case VPN_IPC_ERROR_INVALID_PARAMS: return "Invalid parameters";
        case VPN_IPC_ERROR_INTERNAL_ERROR: return "Internal error";
        case VPN_IPC_ERROR_DAEMON_NOT_RUNNING: return "Daemon not running";
        case VPN_IPC_ERROR_ALREADY_CONNECTED: return "Already connected";
        case VPN_IPC_ERROR_NOT_CONNECTED: return "Not connected";
        case VPN_IPC_ERROR_NETWORK_FAILED: return "Network operation failed";
        case VPN_IPC_ERROR_PAYMENT_REQUIRED: return "Payment required";
        case VPN_IPC_ERROR_PAYMENT_INVALID: return "Payment invalid";
        case VPN_IPC_ERROR_SHUTDOWN_FAILED: return "Shutdown failed";
        case VPN_IPC_ERROR_CONFIG_INVALID: return "Configuration invalid";
        case VPN_IPC_ERROR_UNKNOWN_TRANSPORT: return "Unknown transport";
        case VPN_IPC_ERROR_UNKNOWN_OBFUSCATION: return "Unknown obfuscation";
        case VPN_IPC_ERROR_NO_WALLET: return "No wallet available";
        case VPN_IPC_ERROR_AUTO_SELECT_FAILED: return "Auto node selection failed";
        case VPN_IPC_ERROR_VPN_SERVICE_UNAVAILABLE: return "VPN service unavailable";
        case VPN_IPC_ERROR_MAX_CLIENTS: return "Maximum clients reached";
        case VPN_IPC_ERROR_AUTH_FAILED: return "Authentication failed";
        case VPN_IPC_ERROR_ROUTE_FAILED: return "Routing failed";
        case VPN_IPC_ERROR_GENERIC_FAILURE: return "Generic failure";
        default: return "Unknown error";
    }
}

const char* dap_chain_net_vpn_client_ipc_event_type_to_string(dap_chain_net_vpn_client_ipc_event_type_t a_type) {
    switch (a_type) {
        case VPN_IPC_EVENT_STATUS_CHANGED: return "status_changed";
        case VPN_IPC_EVENT_STATS_UPDATED: return "stats_updated";
        case VPN_IPC_EVENT_ERROR_OCCURRED: return "error_occurred";
        case VPN_IPC_EVENT_CONFIG_CHANGED: return "config_changed";
        case VPN_IPC_EVENT_NETWORK_CHANGED: return "network_changed";
        default: return "unknown";
    }
}

dap_chain_net_vpn_client_ipc_event_type_t dap_chain_net_vpn_client_ipc_event_type_from_string(const char *a_type_str) {
    if (!a_type_str) return VPN_IPC_EVENT_STATUS_CHANGED; // Default
    if (strcmp(a_type_str, "status_changed") == 0) return VPN_IPC_EVENT_STATUS_CHANGED;
    if (strcmp(a_type_str, "stats_updated") == 0) return VPN_IPC_EVENT_STATS_UPDATED;
    if (strcmp(a_type_str, "error_occurred") == 0) return VPN_IPC_EVENT_ERROR_OCCURRED;
    if (strcmp(a_type_str, "config_changed") == 0) return VPN_IPC_EVENT_CONFIG_CHANGED;
    if (strcmp(a_type_str, "network_changed") == 0) return VPN_IPC_EVENT_NETWORK_CHANGED;
    return VPN_IPC_EVENT_STATUS_CHANGED; // Default
}

// --- Internal JSON Serialization Helpers ---

static json_object* s_serialize_payment_config(const dap_chain_net_vpn_client_payment_config_t *a_payment) {
    if (!a_payment) return NULL;
    
    json_object *j_payment = json_object_new_object();
    if (!j_payment) return NULL;

    char l_tx_hash_str[DAP_HASH_FAST_SIZE * 2 + 1];
    dap_hash_fast_to_str(&a_payment->tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
    
    json_object_object_add(j_payment, "tx_hash", json_object_new_string(l_tx_hash_str));
    json_object_object_add(j_payment, "network_name", json_object_new_string(a_payment->network_name));
    
    return j_payment;
}

static int s_deserialize_payment_config(json_object *j_payment, dap_chain_net_vpn_client_payment_config_t *a_payment) {
    if (!j_payment || !a_payment) return -1;

    json_object *j_tx_hash, *j_network_name;
    
    if (!json_object_object_get_ex(j_payment, "tx_hash", &j_tx_hash) || 
        !json_object_is_type(j_tx_hash, json_type_string) ||
        !json_object_object_get_ex(j_payment, "network_name", &j_network_name) || 
        !json_object_is_type(j_network_name, json_type_string)) {
        log_it(L_ERROR, "Missing or invalid payment config fields");
        return -1;
    }

    const char *l_tx_hash_str = json_object_get_string(j_tx_hash);
    const char *l_network_name_str = json_object_get_string(j_network_name);

    if (dap_chain_net_vpn_client_payment_config_init(a_payment, l_tx_hash_str, l_network_name_str) != 0) {
        log_it(L_ERROR, "Failed to initialize payment config from JSON");
        return -1;
    }
    
    return 0;
}

static json_object* s_serialize_connect_params(const dap_chain_net_vpn_client_ipc_connect_params_t *a_params) {
    if (!a_params) return NULL;
    
    json_object *j_params = json_object_new_object();
    if (!j_params) return NULL;

    json_object_object_add(j_params, "host", json_object_new_string(a_params->host));
    json_object_object_add(j_params, "port", json_object_new_int(a_params->port));
    json_object_object_add(j_params, "transport", json_object_new_string(dap_stream_transport_type_to_string(a_params->transport)));
    json_object_object_add(j_params, "obfuscation", json_object_new_string(dap_stream_obfuscation_level_to_string(a_params->obfuscation)));
    json_object_object_add(j_params, "manage_routing", json_object_new_boolean(a_params->manage_routing));
    json_object_object_add(j_params, "manage_dns", json_object_new_boolean(a_params->manage_dns));

    json_object *j_payment = s_serialize_payment_config(&a_params->payment);
    if (j_payment) {
        json_object_object_add(j_params, "payment", j_payment);
    }

    if (a_params->wallet_name) {
        json_object_object_add(j_params, "wallet_name", json_object_new_string(a_params->wallet_name));
    }
    
    json_object_object_add(j_params, "auto_select_node", json_object_new_boolean(a_params->auto_select_node));
    
    if (a_params->region) {
        json_object_object_add(j_params, "region", json_object_new_string(a_params->region));
    }
    
    if (a_params->multi_hop_route) {
        json_object_object_add(j_params, "multi_hop_route", json_object_new_string(a_params->multi_hop_route));
    }
    
    return j_params;
}

static dap_chain_net_vpn_client_ipc_connect_params_t* s_deserialize_connect_params(json_object *j_params) {
    if (!j_params) return NULL;

    dap_chain_net_vpn_client_ipc_connect_params_t *l_params = DAP_NEW_Z(dap_chain_net_vpn_client_ipc_connect_params_t);
    if (!l_params) {
        log_it(L_CRITICAL, "Failed to allocate connect params");
        return NULL;
    }

    json_object *j_host, *j_port, *j_transport, *j_obfuscation, *j_payment, *j_manage_routing, *j_manage_dns;
    json_object *j_wallet_name, *j_auto_select_node, *j_region, *j_multi_hop_route;

    if (!json_object_object_get_ex(j_params, "host", &j_host) || !json_object_is_type(j_host, json_type_string) ||
        !json_object_object_get_ex(j_params, "port", &j_port) || !json_object_is_type(j_port, json_type_int) ||
        !json_object_object_get_ex(j_params, "transport", &j_transport) || !json_object_is_type(j_transport, json_type_string) ||
        !json_object_object_get_ex(j_params, "obfuscation", &j_obfuscation) || !json_object_is_type(j_obfuscation, json_type_string) ||
        !json_object_object_get_ex(j_params, "manage_routing", &j_manage_routing) || !json_object_is_type(j_manage_routing, json_type_boolean) ||
        !json_object_object_get_ex(j_params, "manage_dns", &j_manage_dns) || !json_object_is_type(j_manage_dns, json_type_boolean)) {
        log_it(L_ERROR, "Missing or invalid required connect params fields");
        DAP_DELETE(l_params);
        return NULL;
    }

    l_params->host = dap_strdup(json_object_get_string(j_host));
    l_params->port = (uint16_t)json_object_get_int(j_port);
    l_params->transport = dap_stream_transport_type_from_string(json_object_get_string(j_transport));
    l_params->obfuscation = dap_stream_obfuscation_level_from_string(json_object_get_string(j_obfuscation));
    l_params->manage_routing = json_object_get_boolean(j_manage_routing);
    l_params->manage_dns = json_object_get_boolean(j_manage_dns);

    if (json_object_object_get_ex(j_params, "payment", &j_payment) && json_object_is_type(j_payment, json_type_object)) {
        if (s_deserialize_payment_config(j_payment, &l_params->payment) != 0) {
            log_it(L_ERROR, "Failed to deserialize payment config");
            DAP_DELETE(l_params->host);
            DAP_DELETE(l_params);
            return NULL;
        }
    } else {
        log_it(L_ERROR, "Payment config is required for connect method");
        DAP_DELETE(l_params->host);
        DAP_DELETE(l_params);
        return NULL;
    }

    if (json_object_object_get_ex(j_params, "wallet_name", &j_wallet_name) && json_object_is_type(j_wallet_name, json_type_string)) {
        l_params->wallet_name = dap_strdup(json_object_get_string(j_wallet_name));
    }
    
    if (json_object_object_get_ex(j_params, "auto_select_node", &j_auto_select_node) && json_object_is_type(j_auto_select_node, json_type_boolean)) {
        l_params->auto_select_node = json_object_get_boolean(j_auto_select_node);
    }
    
    if (json_object_object_get_ex(j_params, "region", &j_region) && json_object_is_type(j_region, json_type_string)) {
        l_params->region = dap_strdup(json_object_get_string(j_region));
    }
    
    if (json_object_object_get_ex(j_params, "multi_hop_route", &j_multi_hop_route) && json_object_is_type(j_multi_hop_route, json_type_string)) {
        l_params->multi_hop_route = dap_strdup(json_object_get_string(j_multi_hop_route));
    }

    return l_params;
}

static json_object* s_serialize_status_result(const dap_chain_net_vpn_client_ipc_status_result_t *a_result) {
    if (!a_result) return NULL;
    
    json_object *j_result = json_object_new_object();
    if (!j_result) return NULL;

    json_object_object_add(j_result, "status", json_object_new_string(dap_chain_net_vpn_client_connection_status_to_string(a_result->status)));
    
    if (a_result->server_host) {
        json_object_object_add(j_result, "server_host", json_object_new_string(a_result->server_host));
        json_object_object_add(j_result, "server_port", json_object_new_int(a_result->server_port));
        json_object_object_add(j_result, "transport", json_object_new_string(dap_stream_transport_type_to_string(a_result->transport)));
        json_object_object_add(j_result, "obfuscation", json_object_new_string(dap_stream_obfuscation_level_to_string(a_result->obfuscation)));
        json_object_object_add(j_result, "uptime_sec", json_object_new_uint64(a_result->uptime_sec));
        json_object_object_add(j_result, "bytes_sent", json_object_new_uint64(a_result->bytes_sent));
        json_object_object_add(j_result, "bytes_recv", json_object_new_uint64(a_result->bytes_recv));
        
        if (a_result->current_ip) 
            json_object_object_add(j_result, "current_ip", json_object_new_string(a_result->current_ip));
        if (a_result->assigned_ip) 
            json_object_object_add(j_result, "assigned_ip", json_object_new_string(a_result->assigned_ip));
        if (a_result->assigned_dns) 
            json_object_object_add(j_result, "assigned_dns", json_object_new_string(a_result->assigned_dns));
        if (a_result->multi_hop_active_route) 
            json_object_object_add(j_result, "multi_hop_active_route", json_object_new_string(a_result->multi_hop_active_route));
    }
    
    return j_result;
}

static dap_chain_net_vpn_client_ipc_status_result_t* s_deserialize_status_result(json_object *j_result) {
    if (!j_result) return NULL;

    dap_chain_net_vpn_client_ipc_status_result_t *l_result = DAP_NEW_Z(dap_chain_net_vpn_client_ipc_status_result_t);
    if (!l_result) {
        log_it(L_CRITICAL, "Failed to allocate status result");
        return NULL;
    }

    json_object *j_status;
    if (!json_object_object_get_ex(j_result, "status", &j_status) || !json_object_is_type(j_status, json_type_string)) {
        log_it(L_ERROR, "Missing or invalid status field in status result");
        DAP_DELETE(l_result);
        return NULL;
    }
    
    const char *l_status_str = json_object_get_string(j_status);
    l_result->status_str = dap_strdup(l_status_str);
    
    if (strcmp(l_status_str, "disconnected") == 0) l_result->status = VPN_CONNECTION_STATUS_DISCONNECTED;
    else if (strcmp(l_status_str, "connecting") == 0) l_result->status = VPN_CONNECTION_STATUS_CONNECTING;
    else if (strcmp(l_status_str, "connected") == 0) l_result->status = VPN_CONNECTION_STATUS_CONNECTED;
    else if (strcmp(l_status_str, "disconnecting") == 0) l_result->status = VPN_CONNECTION_STATUS_DISCONNECTING;
    else if (strcmp(l_status_str, "error") == 0) l_result->status = VPN_CONNECTION_STATUS_ERROR;

    json_object *j_server_host, *j_server_port, *j_transport, *j_obfuscation, *j_uptime, *j_sent, *j_recv;
    json_object *j_current_ip, *j_assigned_ip, *j_assigned_dns, *j_multi_hop_active_route;
    
    if (json_object_object_get_ex(j_result, "server_host", &j_server_host) && json_object_is_type(j_server_host, json_type_string)) {
        l_result->server_host = dap_strdup(json_object_get_string(j_server_host));
        
        if (json_object_object_get_ex(j_result, "server_port", &j_server_port) && json_object_is_type(j_server_port, json_type_int))
            l_result->server_port = (uint16_t)json_object_get_int(j_server_port);
            
        if (json_object_object_get_ex(j_result, "transport", &j_transport) && json_object_is_type(j_transport, json_type_string))
            l_result->transport = dap_stream_transport_type_from_string(json_object_get_string(j_transport));
            
        if (json_object_object_get_ex(j_result, "obfuscation", &j_obfuscation) && json_object_is_type(j_obfuscation, json_type_string))
            l_result->obfuscation = dap_stream_obfuscation_level_from_string(json_object_get_string(j_obfuscation));
            
        if (json_object_object_get_ex(j_result, "uptime_sec", &j_uptime) && json_object_is_type(j_uptime, json_type_int))
            l_result->uptime_sec = json_object_get_uint64(j_uptime);
            
        if (json_object_object_get_ex(j_result, "bytes_sent", &j_sent) && json_object_is_type(j_sent, json_type_int))
            l_result->bytes_sent = json_object_get_uint64(j_sent);
            
        if (json_object_object_get_ex(j_result, "bytes_recv", &j_recv) && json_object_is_type(j_recv, json_type_int))
            l_result->bytes_recv = json_object_get_uint64(j_recv);
            
        if (json_object_object_get_ex(j_result, "current_ip", &j_current_ip) && json_object_is_type(j_current_ip, json_type_string))
            l_result->current_ip = dap_strdup(json_object_get_string(j_current_ip));
            
        if (json_object_object_get_ex(j_result, "assigned_ip", &j_assigned_ip) && json_object_is_type(j_assigned_ip, json_type_string))
            l_result->assigned_ip = dap_strdup(json_object_get_string(j_assigned_ip));
            
        if (json_object_object_get_ex(j_result, "assigned_dns", &j_assigned_dns) && json_object_is_type(j_assigned_dns, json_type_string))
            l_result->assigned_dns = dap_strdup(json_object_get_string(j_assigned_dns));
            
        if (json_object_object_get_ex(j_result, "multi_hop_active_route", &j_multi_hop_active_route) && json_object_is_type(j_multi_hop_active_route, json_type_string))
            l_result->multi_hop_active_route = dap_strdup(json_object_get_string(j_multi_hop_active_route));
    }

    return l_result;
}

// --- Serialization Functions ---

int dap_chain_net_vpn_client_ipc_request_serialize(const dap_chain_net_vpn_client_ipc_request_t *a_request, 
                                                     char **a_out_json, 
                                                     size_t *a_out_size) {
    if (!a_request || !a_out_json || !a_out_size) {
        log_it(L_ERROR, "Invalid parameters for request serialization");
        return -1;
    }

    json_object *j_request = json_object_new_object();
    if (!j_request) {
        log_it(L_CRITICAL, "Failed to create JSON object for request");
        return -1;
    }

    json_object_object_add(j_request, "jsonrpc", json_object_new_string(VPN_IPC_PROTOCOL_VERSION));
    json_object_object_add(j_request, "method", json_object_new_string(dap_chain_net_vpn_client_ipc_method_to_string(a_request->method)));
    
    if (a_request->id) {
        json_object_object_add(j_request, "id", json_object_new_string(a_request->id));
    }

    json_object *j_params = NULL;
    if (a_request->method == VPN_IPC_METHOD_CONNECT) {
        j_params = s_serialize_connect_params((dap_chain_net_vpn_client_ipc_connect_params_t*)a_request->params);
    }

    if (j_params) {
        json_object_object_add(j_request, "params", j_params);
    }

    const char *l_json_str = json_object_to_json_string_ext(j_request, JSON_C_TO_STRING_PRETTY);
    if (!l_json_str) {
        log_it(L_ERROR, "Failed to convert request JSON object to string");
        json_object_put(j_request);
        return -1;
    }

    *a_out_json = dap_strdup(l_json_str);
    *a_out_size = strlen(*a_out_json);
    json_object_put(j_request);
    
    return 0;
}

int dap_chain_net_vpn_client_ipc_request_deserialize(const char *a_json_str, 
                                                       dap_chain_net_vpn_client_ipc_request_t **a_out_request) {
    if (!a_json_str || !a_out_request) {
        log_it(L_ERROR, "Invalid parameters for request deserialization");
        return -1;
    }

    json_object *j_request = json_tokener_parse(a_json_str);
    if (!j_request) {
        log_it(L_ERROR, "Failed to parse JSON string for request");
        return -1;
    }

    dap_chain_net_vpn_client_ipc_request_t *l_request = DAP_NEW_Z(dap_chain_net_vpn_client_ipc_request_t);
    if (!l_request) {
        log_it(L_CRITICAL, "Failed to allocate request structure");
        json_object_put(j_request);
        return -1;
    }

    json_object *j_jsonrpc, *j_method, *j_params, *j_id;

    if (!json_object_object_get_ex(j_request, "jsonrpc", &j_jsonrpc) || !json_object_is_type(j_jsonrpc, json_type_string) ||
        strcmp(json_object_get_string(j_jsonrpc), VPN_IPC_PROTOCOL_VERSION) != 0) {
        log_it(L_ERROR, "Invalid or missing 'jsonrpc' field");
        dap_chain_net_vpn_client_ipc_request_free(l_request);
        json_object_put(j_request);
        return -1;
    }
    l_request->jsonrpc = dap_strdup(json_object_get_string(j_jsonrpc));

    if (!json_object_object_get_ex(j_request, "method", &j_method) || !json_object_is_type(j_method, json_type_string)) {
        log_it(L_ERROR, "Invalid or missing 'method' field");
        dap_chain_net_vpn_client_ipc_request_free(l_request);
        json_object_put(j_request);
        return -1;
    }
    l_request->method_str = dap_strdup(json_object_get_string(j_method));
    l_request->method = dap_chain_net_vpn_client_ipc_method_from_string(l_request->method_str);
    
    if (l_request->method == VPN_IPC_METHOD_UNKNOWN) {
        log_it(L_ERROR, "Unknown method: %s", l_request->method_str);
        dap_chain_net_vpn_client_ipc_request_free(l_request);
        json_object_put(j_request);
        return -1;
    }

    if (json_object_object_get_ex(j_request, "id", &j_id) && json_object_is_type(j_id, json_type_string)) {
        l_request->id = dap_strdup(json_object_get_string(j_id));
    }

    if (json_object_object_get_ex(j_request, "params", &j_params) && json_object_is_type(j_params, json_type_object)) {
        if (l_request->method == VPN_IPC_METHOD_CONNECT) {
            l_request->params = s_deserialize_connect_params(j_params);
            if (!l_request->params) {
                log_it(L_ERROR, "Failed to deserialize connect params");
                dap_chain_net_vpn_client_ipc_request_free(l_request);
                json_object_put(j_request);
                return -1;
            }
        }
    }

    *a_out_request = l_request;
    json_object_put(j_request);
    
    return 0;
}

int dap_chain_net_vpn_client_ipc_response_serialize(const dap_chain_net_vpn_client_ipc_response_t *a_response, 
                                                      char **a_out_json, 
                                                      size_t *a_out_size) {
    if (!a_response || !a_out_json || !a_out_size) {
        log_it(L_ERROR, "Invalid parameters for response serialization");
        return -1;
    }

    json_object *j_response = json_object_new_object();
    if (!j_response) {
        log_it(L_CRITICAL, "Failed to create JSON object for response");
        return -1;
    }

    json_object_object_add(j_response, "jsonrpc", json_object_new_string(VPN_IPC_PROTOCOL_VERSION));
    
    if (a_response->id) {
        json_object_object_add(j_response, "id", json_object_new_string(a_response->id));
    }

    if (a_response->error) {
        json_object *j_error = json_object_new_object();
        if (!j_error) {
            log_it(L_CRITICAL, "Failed to create JSON object for error");
            json_object_put(j_response);
            return -1;
        }
        json_object_object_add(j_error, "code", json_object_new_int(a_response->error->code));
        json_object_object_add(j_error, "message", json_object_new_string(a_response->error->message));
        json_object_object_add(j_response, "error", j_error);
    } else {
        json_object *j_result = NULL;
        if (a_response->result) {
            j_result = s_serialize_status_result((dap_chain_net_vpn_client_ipc_status_result_t*)a_response->result);
        }
        json_object_object_add(j_response, "result", j_result ? j_result : json_object_new_null());
    }

    const char *l_json_str = json_object_to_json_string_ext(j_response, JSON_C_TO_STRING_PRETTY);
    if (!l_json_str) {
        log_it(L_ERROR, "Failed to convert response JSON object to string");
        json_object_put(j_response);
        return -1;
    }

    *a_out_json = dap_strdup(l_json_str);
    *a_out_size = strlen(*a_out_json);
    json_object_put(j_response);
    
    return 0;
}

int dap_chain_net_vpn_client_ipc_response_deserialize(const char *a_json_str, 
                                                        dap_chain_net_vpn_client_ipc_response_t **a_out_response) {
    if (!a_json_str || !a_out_response) {
        log_it(L_ERROR, "Invalid parameters for response deserialization");
        return -1;
    }

    json_object *j_response = json_tokener_parse(a_json_str);
    if (!j_response) {
        log_it(L_ERROR, "Failed to parse JSON string for response");
        return -1;
    }

    dap_chain_net_vpn_client_ipc_response_t *l_response = DAP_NEW_Z(dap_chain_net_vpn_client_ipc_response_t);
    if (!l_response) {
        log_it(L_CRITICAL, "Failed to allocate response structure");
        json_object_put(j_response);
        return -1;
    }

    json_object *j_jsonrpc, *j_result, *j_error, *j_id;

    if (!json_object_object_get_ex(j_response, "jsonrpc", &j_jsonrpc) || !json_object_is_type(j_jsonrpc, json_type_string) ||
        strcmp(json_object_get_string(j_jsonrpc), VPN_IPC_PROTOCOL_VERSION) != 0) {
        log_it(L_ERROR, "Invalid or missing 'jsonrpc' field in response");
        dap_chain_net_vpn_client_ipc_response_free(l_response);
        json_object_put(j_response);
        return -1;
    }
    l_response->jsonrpc = dap_strdup(json_object_get_string(j_jsonrpc));

    if (json_object_object_get_ex(j_response, "id", &j_id) && json_object_is_type(j_id, json_type_string)) {
        l_response->id = dap_strdup(json_object_get_string(j_id));
    }

    if (json_object_object_get_ex(j_response, "error", &j_error) && json_object_is_type(j_error, json_type_object)) {
        l_response->error = DAP_NEW_Z(dap_chain_net_vpn_client_ipc_error_t);
        if (!l_response->error) {
            log_it(L_CRITICAL, "Failed to allocate error structure");
            dap_chain_net_vpn_client_ipc_response_free(l_response);
            json_object_put(j_response);
            return -1;
        }
        
        json_object *j_code, *j_message;
        if (!json_object_object_get_ex(j_error, "code", &j_code) || !json_object_is_type(j_code, json_type_int) ||
            !json_object_object_get_ex(j_error, "message", &j_message) || !json_object_is_type(j_message, json_type_string)) {
            log_it(L_ERROR, "Invalid or missing fields in error object");
            dap_chain_net_vpn_client_ipc_response_free(l_response);
            json_object_put(j_response);
            return -1;
        }
        
        l_response->error->code = (dap_chain_net_vpn_client_ipc_error_code_t)json_object_get_int(j_code);
        l_response->error->message = dap_strdup(json_object_get_string(j_message));
    } else if (json_object_object_get_ex(j_response, "result", &j_result)) {
        if (!json_object_is_type(j_result, json_type_null)) {
            l_response->result = s_deserialize_status_result(j_result);
            if (!l_response->result) {
                log_it(L_ERROR, "Failed to deserialize status result");
                dap_chain_net_vpn_client_ipc_response_free(l_response);
                json_object_put(j_response);
                return -1;
            }
        }
    }

    *a_out_response = l_response;
    json_object_put(j_response);
    
    return 0;
}

// --- Memory Management Functions ---

void dap_chain_net_vpn_client_ipc_request_free(dap_chain_net_vpn_client_ipc_request_t *a_request) {
    if (!a_request) return;
    
    DAP_DELETE(a_request->jsonrpc);
    DAP_DELETE(a_request->method_str);
    DAP_DELETE(a_request->id);
    
    if (a_request->method == VPN_IPC_METHOD_CONNECT && a_request->params) {
        dap_chain_net_vpn_client_ipc_connect_params_t *l_params = (dap_chain_net_vpn_client_ipc_connect_params_t*)a_request->params;
        DAP_DELETE(l_params->host);
        DAP_DELETE(l_params->wallet_name);
        DAP_DELETE(l_params->region);
        DAP_DELETE(l_params->multi_hop_route);
        DAP_DELETE(l_params);
    } else {
        DAP_DELETE(a_request->params);
    }
    
    DAP_DELETE(a_request);
}

void dap_chain_net_vpn_client_ipc_response_free(dap_chain_net_vpn_client_ipc_response_t *a_response) {
    if (!a_response) return;
    
    DAP_DELETE(a_response->jsonrpc);
    DAP_DELETE(a_response->id);
    
    if (a_response->error) {
        DAP_DELETE(a_response->error->message);
        DAP_DELETE(a_response->error->data);
        DAP_DELETE(a_response->error);
    }
    
    if (a_response->result) {
        dap_chain_net_vpn_client_ipc_status_result_t *l_result = (dap_chain_net_vpn_client_ipc_status_result_t*)a_response->result;
        DAP_DELETE(l_result->status_str);
        DAP_DELETE(l_result->server_host);
        DAP_DELETE(l_result->current_ip);
        DAP_DELETE(l_result->assigned_ip);
        DAP_DELETE(l_result->assigned_dns);
        DAP_DELETE(l_result->multi_hop_active_route);
        DAP_DELETE(l_result);
    }
    
    DAP_DELETE(a_response);
}

// --- Response Creation Helpers ---

dap_chain_net_vpn_client_ipc_response_t* dap_chain_net_vpn_client_ipc_response_create_success(const char *a_id, void *a_result) {
    dap_chain_net_vpn_client_ipc_response_t *l_response = DAP_NEW_Z(dap_chain_net_vpn_client_ipc_response_t);
    if (!l_response) return NULL;
    
    l_response->jsonrpc = dap_strdup(VPN_IPC_PROTOCOL_VERSION);
    l_response->id = a_id ? dap_strdup(a_id) : NULL;
    l_response->result = a_result;
    l_response->error = NULL;
    
    return l_response;
}

dap_chain_net_vpn_client_ipc_response_t* dap_chain_net_vpn_client_ipc_response_create_error(const char *a_id, 
                                                                                               dap_chain_net_vpn_client_ipc_error_code_t a_code, 
                                                                                               const char *a_message, 
                                                                                               void *a_data) {
    dap_chain_net_vpn_client_ipc_response_t *l_response = DAP_NEW_Z(dap_chain_net_vpn_client_ipc_response_t);
    if (!l_response) return NULL;
    
    l_response->jsonrpc = dap_strdup(VPN_IPC_PROTOCOL_VERSION);
    l_response->id = a_id ? dap_strdup(a_id) : NULL;
    l_response->result = NULL;
    
    l_response->error = DAP_NEW_Z(dap_chain_net_vpn_client_ipc_error_t);
    if (!l_response->error) {
        DAP_DELETE(l_response->jsonrpc);
        DAP_DELETE(l_response->id);
        DAP_DELETE(l_response);
        return NULL;
    }
    
    l_response->error->code = a_code;
    l_response->error->message = a_message ? dap_strdup(a_message) : dap_strdup(dap_chain_net_vpn_client_ipc_error_code_to_string(a_code));
    l_response->error->data = a_data;
    
    return l_response;
}


// --- Event Functions ---

dap_chain_net_vpn_client_ipc_event_t* dap_chain_net_vpn_client_ipc_event_create(dap_chain_net_vpn_client_ipc_event_type_t a_type,
                                                                                   void *a_data) {
    dap_chain_net_vpn_client_ipc_event_t *l_event = DAP_NEW_Z(dap_chain_net_vpn_client_ipc_event_t);
    if (!l_event) return NULL;
    
    l_event->type = a_type;
    l_event->timestamp = dap_time_now();
    l_event->data = a_data;
    
    return l_event;
}

int dap_chain_net_vpn_client_ipc_event_serialize(const dap_chain_net_vpn_client_ipc_event_t *a_event,
                                                   char **a_out_json,
                                                   size_t *a_out_size) {
    if (!a_event || !a_out_json || !a_out_size) {
        log_it(L_ERROR, "Invalid parameters for event serialization");
        return -1;
    }
    
    json_object *j_event = json_object_new_object();
    if (!j_event) {
        log_it(L_CRITICAL, "Failed to create JSON object for event");
        return -1;
    }
    
    json_object_object_add(j_event, "type", json_object_new_string(dap_chain_net_vpn_client_ipc_event_type_to_string(a_event->type)));
    json_object_object_add(j_event, "timestamp", json_object_new_uint64(a_event->timestamp));
    
    if (a_event->data) {
        switch (a_event->type) {
            case VPN_IPC_EVENT_STATUS_CHANGED:
            case VPN_IPC_EVENT_STATS_UPDATED: {
                json_object *j_data = s_serialize_status_result((dap_chain_net_vpn_client_ipc_status_result_t*)a_event->data);
                if (j_data) {
                    json_object_object_add(j_event, "data", j_data);
                }
                break;
            }
            case VPN_IPC_EVENT_ERROR_OCCURRED: {
                json_object_object_add(j_event, "data", json_object_new_string((const char*)a_event->data));
                break;
            }
            default:
                break;
        }
    }
    
    const char *l_json_str = json_object_to_json_string_ext(j_event, JSON_C_TO_STRING_PRETTY);
    if (!l_json_str) {
        log_it(L_ERROR, "Failed to convert event JSON object to string");
        json_object_put(j_event);
        return -1;
    }
    
    *a_out_json = dap_strdup(l_json_str);
    *a_out_size = strlen(*a_out_json);
    json_object_put(j_event);
    
    return 0;
}

int dap_chain_net_vpn_client_ipc_event_deserialize(const char *a_json_str,
                                                     dap_chain_net_vpn_client_ipc_event_t **a_out_event) {
    if (!a_json_str || !a_out_event) {
        log_it(L_ERROR, "Invalid parameters for event deserialization");
        return -1;
    }
    
    json_object *j_event = json_tokener_parse(a_json_str);
    if (!j_event) {
        log_it(L_ERROR, "Failed to parse JSON string for event");
        return -1;
    }
    
    dap_chain_net_vpn_client_ipc_event_t *l_event = DAP_NEW_Z(dap_chain_net_vpn_client_ipc_event_t);
    if (!l_event) {
        log_it(L_CRITICAL, "Failed to allocate event structure");
        json_object_put(j_event);
        return -1;
    }
    
    json_object *j_type, *j_timestamp, *j_data;
    
    if (!json_object_object_get_ex(j_event, "type", &j_type) || !json_object_is_type(j_type, json_type_string)) {
        log_it(L_ERROR, "Invalid or missing 'type' field in event");
        DAP_DELETE(l_event);
        json_object_put(j_event);
        return -1;
    }
    l_event->type = dap_chain_net_vpn_client_ipc_event_type_from_string(json_object_get_string(j_type));
    
    if (json_object_object_get_ex(j_event, "timestamp", &j_timestamp) && json_object_is_type(j_timestamp, json_type_int)) {
        l_event->timestamp = json_object_get_uint64(j_timestamp);
    }
    
    if (json_object_object_get_ex(j_event, "data", &j_data)) {
        switch (l_event->type) {
            case VPN_IPC_EVENT_STATUS_CHANGED:
            case VPN_IPC_EVENT_STATS_UPDATED:
                if (json_object_is_type(j_data, json_type_object)) {
                    l_event->data = s_deserialize_status_result(j_data);
                }
                break;
            case VPN_IPC_EVENT_ERROR_OCCURRED:
                if (json_object_is_type(j_data, json_type_string)) {
                    l_event->data = dap_strdup(json_object_get_string(j_data));
                }
                break;
            default:
                break;
        }
    }
    
    *a_out_event = l_event;
    json_object_put(j_event);
    
    return 0;
}

void dap_chain_net_vpn_client_ipc_event_free(dap_chain_net_vpn_client_ipc_event_t *a_event) {
    if (!a_event) return;
    
    if (a_event->data) {
        switch (a_event->type) {
            case VPN_IPC_EVENT_STATUS_CHANGED:
            case VPN_IPC_EVENT_STATS_UPDATED: {
                dap_chain_net_vpn_client_ipc_status_result_t *l_result = (dap_chain_net_vpn_client_ipc_status_result_t*)a_event->data;
                DAP_DELETE(l_result->status_str);
                DAP_DELETE(l_result->server_host);
                DAP_DELETE(l_result->current_ip);
                DAP_DELETE(l_result->assigned_ip);
                DAP_DELETE(l_result->assigned_dns);
                DAP_DELETE(l_result->multi_hop_active_route);
                DAP_DELETE(l_result);
                break;
            }
            case VPN_IPC_EVENT_ERROR_OCCURRED:
                DAP_DELETE(a_event->data);
                break;
            default:
                DAP_DELETE(a_event->data);
                break;
        }
    }
    
    DAP_DELETE(a_event);
}
