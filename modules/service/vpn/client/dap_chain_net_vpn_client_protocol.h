#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "dap_common.h"
#include "dap_stream_transport.h"
#include "dap_stream_obfuscation.h"
#include "dap_chain_net_vpn_client_payment.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief IPC Protocol Version (JSON-RPC 2.0)
 */
#define VPN_IPC_PROTOCOL_VERSION "2.0"

/**
 * @brief IPC Socket Path (Unix/Linux/macOS)
 */
#define VPN_IPC_SOCKET_PATH "/var/run/cellframe-vpn-clientd.sock"

/**
 * @brief IPC Named Pipe Name (Windows)
 */
#define VPN_IPC_NAMED_PIPE_NAME "\\\\.\\pipe\\cellframe-vpn-clientd"

/**
 * @brief IPC Methods
 */
typedef enum dap_chain_net_vpn_client_ipc_method {
    VPN_IPC_METHOD_UNKNOWN = 0,
    VPN_IPC_METHOD_CONNECT,
    VPN_IPC_METHOD_DISCONNECT,
    VPN_IPC_METHOD_STATUS,
    VPN_IPC_METHOD_CONFIG_GET,
    VPN_IPC_METHOD_CONFIG_SET,
    VPN_IPC_METHOD_SHUTDOWN,
    VPN_IPC_METHOD_SUBSCRIBE,
    VPN_IPC_METHOD_UNSUBSCRIBE
} dap_chain_net_vpn_client_ipc_method_t;

/**
 * @brief Subscription event types
 */
typedef enum dap_chain_net_vpn_client_ipc_event_type {
    VPN_IPC_EVENT_STATUS_CHANGED = 0,           ///< Connection status changed
    VPN_IPC_EVENT_STATS_UPDATED,                ///< Statistics updated
    VPN_IPC_EVENT_ERROR_OCCURRED,               ///< Error occurred
    VPN_IPC_EVENT_CONFIG_CHANGED,               ///< Configuration changed
    VPN_IPC_EVENT_NETWORK_CHANGED               ///< Network configuration changed
} dap_chain_net_vpn_client_ipc_event_type_t;

/**
 * @brief VPN Connection Status
 */
typedef enum dap_chain_net_vpn_client_connection_status {
    VPN_CONNECTION_STATUS_DISCONNECTED = 0,
    VPN_CONNECTION_STATUS_CONNECTING,
    VPN_CONNECTION_STATUS_CONNECTED,
    VPN_CONNECTION_STATUS_DISCONNECTING,
    VPN_CONNECTION_STATUS_ERROR
} dap_chain_net_vpn_client_connection_status_t;

/**
 * @brief IPC Error Codes (JSON-RPC 2.0 compatible)
 */
typedef enum dap_chain_net_vpn_client_ipc_error_code {
    VPN_IPC_ERROR_PARSE_ERROR = -32700,
    VPN_IPC_ERROR_INVALID_REQUEST = -32600,
    VPN_IPC_ERROR_METHOD_NOT_FOUND = -32601,
    VPN_IPC_ERROR_INVALID_PARAMS = -32602,
    VPN_IPC_ERROR_INTERNAL_ERROR = -32603,
    
    // Server errors (-32000 to -32099)
    VPN_IPC_ERROR_DAEMON_NOT_RUNNING = -32001,
    VPN_IPC_ERROR_ALREADY_CONNECTED = -32002,
    VPN_IPC_ERROR_NOT_CONNECTED = -32003,
    VPN_IPC_ERROR_NETWORK_FAILED = -32004,
    VPN_IPC_ERROR_PAYMENT_REQUIRED = -32005,
    VPN_IPC_ERROR_PAYMENT_INVALID = -32006,
    VPN_IPC_ERROR_SHUTDOWN_FAILED = -32007,
    VPN_IPC_ERROR_CONFIG_INVALID = -32008,
    VPN_IPC_ERROR_UNKNOWN_TRANSPORT = -32009,
    VPN_IPC_ERROR_UNKNOWN_OBFUSCATION = -32010,
    VPN_IPC_ERROR_NO_WALLET = -32011,
    VPN_IPC_ERROR_AUTO_SELECT_FAILED = -32012,
    VPN_IPC_ERROR_VPN_SERVICE_UNAVAILABLE = -32013,
    VPN_IPC_ERROR_MAX_CLIENTS = -32014,
    VPN_IPC_ERROR_AUTH_FAILED = -32015,
    VPN_IPC_ERROR_ROUTE_FAILED = -32016,
    VPN_IPC_ERROR_GENERIC_FAILURE = -32099
} dap_chain_net_vpn_client_ipc_error_code_t;

/**
 * @brief IPC Request Parameters for CONNECT method
 */
typedef struct dap_chain_net_vpn_client_ipc_connect_params {
    char *host;                                         ///< VPN server host
    uint16_t port;                                      ///< VPN server port
    dap_stream_transport_type_t transport;              ///< Transport type
    dap_stream_obfuscation_level_t obfuscation;     ///< Obfuscation intensity
    dap_chain_net_vpn_client_payment_config_t payment;  ///< Payment configuration
    bool manage_routing;                                ///< Manage system routing table
    bool manage_dns;                                    ///< Manage system DNS settings
    char *wallet_name;                                  ///< Wallet name (for node CLI, optional)
    bool auto_select_node;                              ///< Auto select node (for node CLI, optional)
    char *region;                                       ///< Preferred region (optional)
    char *multi_hop_route;                              ///< Multi-hop route string (optional)
} dap_chain_net_vpn_client_ipc_connect_params_t;

/**
 * @brief IPC Request Parameters for SUBSCRIBE method
 */
typedef struct dap_chain_net_vpn_client_ipc_subscribe_params {
    dap_chain_net_vpn_client_ipc_event_type_t *event_types; ///< Array of event types to subscribe to
    uint32_t event_count;                               ///< Number of event types
    uint32_t update_interval_ms;                        ///< Update interval for periodic events (e.g., stats)
} dap_chain_net_vpn_client_ipc_subscribe_params_t;

/**
 * @brief IPC Event notification structure
 */
typedef struct dap_chain_net_vpn_client_ipc_event {
    dap_chain_net_vpn_client_ipc_event_type_t type;     ///< Event type
    uint64_t timestamp;                                 ///< Event timestamp (Unix time)
    void *data;                                         ///< Event-specific data (type-dependent)
} dap_chain_net_vpn_client_ipc_event_t;

/**
 * @brief IPC Request structure (JSON-RPC 2.0)
 */
typedef struct dap_chain_net_vpn_client_ipc_request {
    char *jsonrpc;                                      ///< "2.0"
    dap_chain_net_vpn_client_ipc_method_t method;       ///< Method to call
    char *method_str;                                   ///< String representation of method
    void *params;                                       ///< Parameters (method-specific)
    char *id;                                           ///< Request ID (string or number)
} dap_chain_net_vpn_client_ipc_request_t;

/**
 * @brief IPC Error structure (JSON-RPC 2.0)
 */
typedef struct dap_chain_net_vpn_client_ipc_error {
    dap_chain_net_vpn_client_ipc_error_code_t code;     ///< Error code
    char *message;                                      ///< Error message
    void *data;                                         ///< Optional error data
} dap_chain_net_vpn_client_ipc_error_t;

/**
 * @brief IPC Response Result for STATUS method
 */
typedef struct dap_chain_net_vpn_client_ipc_status_result {
    dap_chain_net_vpn_client_connection_status_t status; ///< Current connection status
    char *status_str;                                   ///< String representation of status
    char *server_host;                                  ///< Connected server host
    uint16_t server_port;                               ///< Connected server port
    dap_stream_transport_type_t transport;              ///< Active transport type
    dap_stream_obfuscation_level_t obfuscation;     ///< Active obfuscation intensity
    uint64_t uptime_sec;                                ///< Uptime in seconds
    uint64_t bytes_sent;                                ///< Total bytes sent
    uint64_t bytes_recv;                                ///< Total bytes received
    char *current_ip;                                   ///< Current public IP (if VPN active)
    char *assigned_ip;                                  ///< Assigned IP by VPN server
    char *assigned_dns;                                 ///< Assigned DNS by VPN server
    char *multi_hop_active_route;                       ///< Active multi-hop route (if any)
} dap_chain_net_vpn_client_ipc_status_result_t;

/**
 * @brief IPC Response structure (JSON-RPC 2.0)
 */
typedef struct dap_chain_net_vpn_client_ipc_response {
    char *jsonrpc;                                      ///< "2.0"
    void *result;                                       ///< Result data (method-specific)
    dap_chain_net_vpn_client_ipc_error_t *error;        ///< Error object (if error)
    char *id;                                           ///< Request ID
} dap_chain_net_vpn_client_ipc_response_t;

// --- Utility Functions ---

/**
 * @brief Convert method enum to string
 * @param a_method Method enum
 * @return String representation
 */
const char* dap_chain_net_vpn_client_ipc_method_to_string(dap_chain_net_vpn_client_ipc_method_t a_method);

/**
 * @brief Convert string to method enum
 * @param a_method_str Method string
 * @return Method enum
 */
dap_chain_net_vpn_client_ipc_method_t dap_chain_net_vpn_client_ipc_method_from_string(const char *a_method_str);

/**
 * @brief Convert status enum to string
 * @param a_status Status enum
 * @return String representation
 */
const char* dap_chain_net_vpn_client_connection_status_to_string(dap_chain_net_vpn_client_connection_status_t a_status);

/**
 * @brief Convert error code to human-readable message
 * @param a_code Error code
 * @return Error message
 */
const char* dap_chain_net_vpn_client_ipc_error_code_to_string(dap_chain_net_vpn_client_ipc_error_code_t a_code);

/**
 * @brief Convert event type to string
 * @param a_type Event type
 * @return String representation
 */
const char* dap_chain_net_vpn_client_ipc_event_type_to_string(dap_chain_net_vpn_client_ipc_event_type_t a_type);

/**
 * @brief Convert string to event type
 * @param a_type_str Event type string
 * @return Event type enum
 */
dap_chain_net_vpn_client_ipc_event_type_t dap_chain_net_vpn_client_ipc_event_type_from_string(const char *a_type_str);

// --- Serialization Functions ---

/**
 * @brief Serialize a request to JSON string
 * @param a_request Request structure
 * @param a_out_json Output JSON string (caller must free)
 * @param a_out_size Output size
 * @return 0 on success, -1 on error
 */
int dap_chain_net_vpn_client_ipc_request_serialize(const dap_chain_net_vpn_client_ipc_request_t *a_request, 
                                                     char **a_out_json, 
                                                     size_t *a_out_size);

/**
 * @brief Deserialize a JSON string to request
 * @param a_json_str Input JSON string
 * @param a_out_request Output request structure (caller must free)
 * @return 0 on success, -1 on error
 */
int dap_chain_net_vpn_client_ipc_request_deserialize(const char *a_json_str, 
                                                       dap_chain_net_vpn_client_ipc_request_t **a_out_request);

/**
 * @brief Serialize a response to JSON string
 * @param a_response Response structure
 * @param a_out_json Output JSON string (caller must free)
 * @param a_out_size Output size
 * @return 0 on success, -1 on error
 */
int dap_chain_net_vpn_client_ipc_response_serialize(const dap_chain_net_vpn_client_ipc_response_t *a_response, 
                                                      char **a_out_json, 
                                                      size_t *a_out_size);

/**
 * @brief Deserialize a JSON string to response
 * @param a_json_str Input JSON string
 * @param a_out_response Output response structure (caller must free)
 * @return 0 on success, -1 on error
 */
int dap_chain_net_vpn_client_ipc_response_deserialize(const char *a_json_str, 
                                                        dap_chain_net_vpn_client_ipc_response_t **a_out_response);

// --- Memory Management Functions ---

/**
 * @brief Free a request structure and its contents
 * @param a_request Request structure to free
 */
void dap_chain_net_vpn_client_ipc_request_free(dap_chain_net_vpn_client_ipc_request_t *a_request);

/**
 * @brief Free a response structure and its contents
 * @param a_response Response structure to free
 */
void dap_chain_net_vpn_client_ipc_response_free(dap_chain_net_vpn_client_ipc_response_t *a_response);

// --- Response Creation Helpers ---

/**
 * @brief Create a success response
 * @param a_id Request ID
 * @param a_result Result data (ownership transferred)
 * @return Newly allocated response structure
 */
dap_chain_net_vpn_client_ipc_response_t* dap_chain_net_vpn_client_ipc_response_create_success(const char *a_id, 
                                                                                                 void *a_result);

/**
 * @brief Create an error response
 * @param a_id Request ID
 * @param a_code Error code
 * @param a_message Error message
 * @param a_data Optional error data (ownership transferred)
 * @return Newly allocated response structure
 */
dap_chain_net_vpn_client_ipc_response_t* dap_chain_net_vpn_client_ipc_response_create_error(const char *a_id, 
                                                                                               dap_chain_net_vpn_client_ipc_error_code_t a_code, 
                                                                                               const char *a_message, 
                                                                                               void *a_data);

// --- Event Functions ---

/**
 * @brief Create event notification
 * @param a_type Event type
 * @param a_data Event data (ownership transferred)
 * @return Newly allocated event structure
 */
dap_chain_net_vpn_client_ipc_event_t* dap_chain_net_vpn_client_ipc_event_create(dap_chain_net_vpn_client_ipc_event_type_t a_type,
                                                                                   void *a_data);

/**
 * @brief Serialize event to JSON string
 * @param a_event Event structure
 * @param a_out_json Output JSON string (caller must free)
 * @param a_out_size Output size
 * @return 0 on success, -1 on error
 */
int dap_chain_net_vpn_client_ipc_event_serialize(const dap_chain_net_vpn_client_ipc_event_t *a_event,
                                                   char **a_out_json,
                                                   size_t *a_out_size);

/**
 * @brief Deserialize event from JSON string
 * @param a_json_str Input JSON string
 * @param a_out_event Output event structure (caller must free)
 * @return 0 on success, -1 on error
 */
int dap_chain_net_vpn_client_ipc_event_deserialize(const char *a_json_str,
                                                     dap_chain_net_vpn_client_ipc_event_t **a_out_event);

/**
 * @brief Free event structure
 * @param a_event Event structure to free
 */
void dap_chain_net_vpn_client_ipc_event_free(dap_chain_net_vpn_client_ipc_event_t *a_event);

#ifdef __cplusplus
} // extern "C"
#endif

