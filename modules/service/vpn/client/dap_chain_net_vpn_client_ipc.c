#include "dap_chain_net_vpn_client_ipc.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_server.h"
#include "dap_events_socket.h"
#include "dap_worker.h"
#include "dap_time.h"
#include "json.h"
#include <string.h>
#include <unistd.h>
#include <sys/un.h>

#define LOG_TAG "dap_chain_net_vpn_client_ipc"
#define IPC_BUFFER_SIZE 65536

typedef struct dap_chain_net_vpn_client_ipc_client {
    dap_events_socket_t *esocket;
    uint32_t subscription_mask;                         // Bitmask of subscribed event types
    uint32_t update_interval_ms;                        // Update interval for periodic events
    uint64_t last_update_time;                          // Last update timestamp
    struct dap_chain_net_vpn_client_ipc_client *next;
} dap_chain_net_vpn_client_ipc_client_t;

typedef struct dap_chain_net_vpn_client_ipc_pvt {
    dap_chain_net_vpn_client_ipc_config_t config;
    dap_chain_net_vpn_client_ipc_handler_t handler;
    void *user_data;
    
    dap_server_t *server;
    bool running;
    
    pthread_mutex_t clients_mutex;
    dap_chain_net_vpn_client_ipc_client_t *clients;
    uint32_t client_count;
    
    pthread_t broadcast_thread;
    bool broadcast_thread_running;
} dap_chain_net_vpn_client_ipc_pvt_t;

static dap_chain_net_vpn_client_ipc_pvt_t *s_ipc = NULL;

// Forward declarations
static void s_new_client_callback(dap_events_socket_t *a_esocket, void *a_arg);
static void s_delete_client_callback(dap_events_socket_t *a_esocket, void *a_arg);
static void s_read_callback(dap_events_socket_t *a_esocket, void *a_arg);
static bool s_write_callback(dap_events_socket_t *a_esocket, void *a_arg);
static void s_handle_client_request(dap_events_socket_t *a_esocket, const char *a_data, size_t a_data_size);
static void* s_broadcast_thread_func(void *a_arg);
static dap_chain_net_vpn_client_ipc_client_t* s_find_client_by_esocket(dap_events_socket_t *a_esocket);

// --- Initialization ---

int dap_chain_net_vpn_client_ipc_init(const dap_chain_net_vpn_client_ipc_config_t *a_config,
                                       dap_chain_net_vpn_client_ipc_handler_t a_handler,
                                       void *a_user_data) {
    if (s_ipc) {
        log_it(L_ERROR, "IPC server already initialized");
        return -1;
    }
    
    if (!a_config || !a_handler) {
        log_it(L_ERROR, "Invalid IPC configuration or handler");
        return -2;
    }
    
    s_ipc = DAP_NEW_Z(dap_chain_net_vpn_client_ipc_pvt_t);
    if (!s_ipc) {
        log_it(L_CRITICAL, "Failed to allocate IPC server structure");
        return -3;
    }
    
    // Copy configuration
    memcpy(&s_ipc->config, a_config, sizeof(dap_chain_net_vpn_client_ipc_config_t));
    
    if (a_config->socket_path) {
        s_ipc->config.socket_path = dap_strdup(a_config->socket_path);
    }
    if (a_config->named_pipe) {
        s_ipc->config.named_pipe = dap_strdup(a_config->named_pipe);
    }
    
    s_ipc->handler = a_handler;
    s_ipc->user_data = a_user_data;
    
    pthread_mutex_init(&s_ipc->clients_mutex, NULL);
    
    log_it(L_INFO, "IPC server initialized (socket=%s, max_clients=%u)",
           s_ipc->config.socket_path ? s_ipc->config.socket_path : "N/A",
           s_ipc->config.max_clients);
    
    return 0;
}

void dap_chain_net_vpn_client_ipc_deinit() {
    if (!s_ipc) return;
    
    if (s_ipc->running) {
        dap_chain_net_vpn_client_ipc_stop();
    }
    
    pthread_mutex_destroy(&s_ipc->clients_mutex);
    
    DAP_DELETE(s_ipc->config.socket_path);
    DAP_DELETE(s_ipc->config.named_pipe);
    DAP_DELETE(s_ipc);
    s_ipc = NULL;
    
    log_it(L_INFO, "IPC server deinitialized");
}

// --- Server Control ---

int dap_chain_net_vpn_client_ipc_start() {
    if (!s_ipc) {
        log_it(L_ERROR, "IPC server not initialized");
        return -1;
    }
    
    if (s_ipc->running) {
        log_it(L_WARNING, "IPC server already running");
        return -2;
    }
    
    // Cleanup old socket if requested
    if (s_ipc->config.auto_cleanup && s_ipc->config.socket_path) {
        unlink(s_ipc->config.socket_path);
    }
    
    // Create dap_server with Unix socket
    dap_events_socket_callbacks_t l_server_callbacks = {0};
    dap_events_socket_callbacks_t l_client_callbacks = {
        .new_callback = s_new_client_callback,
        .delete_callback = s_delete_client_callback,
        .read_callback = s_read_callback
    };
    
    s_ipc->server = dap_server_new(s_ipc->config.socket_path,
                                     &l_server_callbacks,
                                     &l_client_callbacks);
    if (!s_ipc->server) {
        log_it(L_ERROR, "Failed to create dap_server");
        return -3;
    }
    
    // Server starts automatically on creation
    s_ipc->running = true;
    
    // Start broadcast thread for periodic updates
    s_ipc->broadcast_thread_running = true;
    if (pthread_create(&s_ipc->broadcast_thread, NULL, s_broadcast_thread_func, NULL) != 0) {
        log_it(L_ERROR, "Failed to create broadcast thread");
        s_ipc->broadcast_thread_running = false;
    }
    
    log_it(L_INFO, "IPC server started on %s", s_ipc->config.socket_path);
    return 0;
}

int dap_chain_net_vpn_client_ipc_stop() {
    if (!s_ipc) {
        log_it(L_ERROR, "IPC server not initialized");
        return -1;
    }
    
    if (!s_ipc->running) {
        log_it(L_WARNING, "IPC server not running");
        return -2;
    }
    
    s_ipc->running = false;
    
    // Stop broadcast thread
    if (s_ipc->broadcast_thread_running) {
        s_ipc->broadcast_thread_running = false;
        pthread_join(s_ipc->broadcast_thread, NULL);
    }
    
    // Stop server
    if (s_ipc->server) {
        dap_server_delete(s_ipc->server);
        s_ipc->server = NULL;
    }
    
    // Clean up clients
    pthread_mutex_lock(&s_ipc->clients_mutex);
    dap_chain_net_vpn_client_ipc_client_t *l_client = s_ipc->clients;
    while (l_client) {
        dap_chain_net_vpn_client_ipc_client_t *l_next = l_client->next;
        DAP_DELETE(l_client);
        l_client = l_next;
    }
    s_ipc->clients = NULL;
    s_ipc->client_count = 0;
    pthread_mutex_unlock(&s_ipc->clients_mutex);
    
    // Cleanup socket file
    if (s_ipc->config.socket_path) {
        unlink(s_ipc->config.socket_path);
    }
    
    log_it(L_INFO, "IPC server stopped");
    return 0;
}

bool dap_chain_net_vpn_client_ipc_is_running() {
    return s_ipc && s_ipc->running;
}

uint32_t dap_chain_net_vpn_client_ipc_get_client_count() {
    if (!s_ipc) return 0;
    
    pthread_mutex_lock(&s_ipc->clients_mutex);
    uint32_t l_count = s_ipc->client_count;
    pthread_mutex_unlock(&s_ipc->clients_mutex);
    
    return l_count;
}

// --- Event Broadcasting ---

int dap_chain_net_vpn_client_ipc_broadcast_event(const dap_chain_net_vpn_client_ipc_event_t *a_event) {
    if (!s_ipc || !a_event) {
        log_it(L_ERROR, "Invalid parameters for broadcast");
        return -1;
    }
    
    char *l_json = NULL;
    size_t l_json_size = 0;
    
    if (dap_chain_net_vpn_client_ipc_event_serialize(a_event, &l_json, &l_json_size) != 0) {
        log_it(L_ERROR, "Failed to serialize event for broadcast");
        return -2;
    }
    
    int l_notified = 0;
    uint32_t l_event_bit = (1 << a_event->type);
    
    pthread_mutex_lock(&s_ipc->clients_mutex);
    dap_chain_net_vpn_client_ipc_client_t *l_client = s_ipc->clients;
    while (l_client) {
        // Check if client subscribed to this event type
        if (l_client->subscription_mask & l_event_bit) {
            if (dap_events_socket_write_unsafe(l_client->esocket, l_json, l_json_size) == l_json_size) {
                l_notified++;
            } else {
                log_it(L_WARNING, "Failed to send event to client");
            }
        }
        l_client = l_client->next;
    }
    pthread_mutex_unlock(&s_ipc->clients_mutex);
    
    DAP_DELETE(l_json);
    
    log_it(L_DEBUG, "Broadcast event type %d to %d clients", a_event->type, l_notified);
    
    return l_notified;
}

int dap_chain_net_vpn_client_ipc_send_event(int a_client_fd, const dap_chain_net_vpn_client_ipc_event_t *a_event) {
    if (!s_ipc || !a_event) {
        log_it(L_ERROR, "Invalid parameters for send event");
        return -1;
    }
    
    char *l_json = NULL;
    size_t l_json_size = 0;
    
    if (dap_chain_net_vpn_client_ipc_event_serialize(a_event, &l_json, &l_json_size) != 0) {
        log_it(L_ERROR, "Failed to serialize event");
        return -2;
    }
    
    pthread_mutex_lock(&s_ipc->clients_mutex);
    dap_chain_net_vpn_client_ipc_client_t *l_client = s_ipc->clients;
    while (l_client) {
        if (l_client->esocket->socket == a_client_fd) {
            if (dap_events_socket_write_unsafe(l_client->esocket, l_json, l_json_size) != l_json_size) {
                log_it(L_ERROR, "Failed to send event to specific client");
                pthread_mutex_unlock(&s_ipc->clients_mutex);
                DAP_DELETE(l_json);
                return -3;
            }
            break;
        }
        l_client = l_client->next;
    }
    pthread_mutex_unlock(&s_ipc->clients_mutex);
    
    DAP_DELETE(l_json);
    
    return 0;
}

// --- Callbacks ---

static void s_new_client_callback(dap_events_socket_t *a_esocket, void *a_arg) {
    UNUSED(a_arg);
    
    if (!s_ipc) return;
    
    pthread_mutex_lock(&s_ipc->clients_mutex);
    
    // Check max clients
    if (s_ipc->client_count >= s_ipc->config.max_clients) {
        pthread_mutex_unlock(&s_ipc->clients_mutex);
        log_it(L_WARNING, "Maximum clients reached, rejecting connection");
        
        dap_chain_net_vpn_client_ipc_response_t *l_error_resp = 
            dap_chain_net_vpn_client_ipc_response_create_error(NULL, 
                                                                 VPN_IPC_ERROR_MAX_CLIENTS,
                                                                 "Maximum clients reached",
                                                                 NULL);
        char *l_json = NULL;
        size_t l_json_size = 0;
        if (dap_chain_net_vpn_client_ipc_response_serialize(l_error_resp, &l_json, &l_json_size) == 0) {
            dap_events_socket_write_unsafe(a_esocket, l_json, l_json_size);
            DAP_DELETE(l_json);
        }
        dap_chain_net_vpn_client_ipc_response_free(l_error_resp);
        
        dap_events_socket_remove_and_delete_unsafe(a_esocket, true);
        return;
    }
    
    // Create client structure
    dap_chain_net_vpn_client_ipc_client_t *l_client = DAP_NEW_Z(dap_chain_net_vpn_client_ipc_client_t);
    if (!l_client) {
        log_it(L_ERROR, "Failed to allocate client structure");
        pthread_mutex_unlock(&s_ipc->clients_mutex);
        dap_events_socket_remove_and_delete_unsafe(a_esocket, true);
        return;
    }
    
    l_client->esocket = a_esocket;
    l_client->subscription_mask = 0;
    l_client->update_interval_ms = 1000; // Default 1 second
    l_client->last_update_time = dap_time_now();
    
    // Add to client list
    l_client->next = s_ipc->clients;
    s_ipc->clients = l_client;
    s_ipc->client_count++;
    
    pthread_mutex_unlock(&s_ipc->clients_mutex);
    
    // Set socket callbacks  
    a_esocket->callbacks.read_callback = s_read_callback;
    a_esocket->callbacks.write_callback = s_write_callback;
    a_esocket->_inheritor = l_client;
    
    log_it(L_DEBUG, "New IPC client connected (fd=%d, total=%u)", a_esocket->socket, s_ipc->client_count);
}

static void s_delete_client_callback(dap_events_socket_t *a_esocket, void *a_arg) {
    UNUSED(a_arg);
    
    if (!s_ipc || !a_esocket) return;
    
    pthread_mutex_lock(&s_ipc->clients_mutex);
    
    dap_chain_net_vpn_client_ipc_client_t **l_prev = &s_ipc->clients;
    while (*l_prev) {
        if ((*l_prev)->esocket == a_esocket) {
            dap_chain_net_vpn_client_ipc_client_t *l_client = *l_prev;
            *l_prev = l_client->next;
            
            if (s_ipc->client_count > 0) {
                s_ipc->client_count--;
            }
            
            DAP_DELETE(l_client);
            
            log_it(L_DEBUG, "IPC client disconnected (fd=%d, remaining=%u)", 
                   a_esocket->socket, s_ipc->client_count);
            break;
        }
        l_prev = &(*l_prev)->next;
    }
    
    pthread_mutex_unlock(&s_ipc->clients_mutex);
}

static void s_read_callback(dap_events_socket_t *a_esocket, void *a_arg) {
    UNUSED(a_arg);
    
    if (!a_esocket || !a_esocket->buf_in_size) return;
    
    // Null-terminate for JSON parsing
    char *l_data = DAP_NEW_SIZE(char, a_esocket->buf_in_size + 1);
    if (!l_data) {
        log_it(L_CRITICAL, "Failed to allocate buffer for request");
        return;
    }
    
    memcpy(l_data, a_esocket->buf_in, a_esocket->buf_in_size);
    l_data[a_esocket->buf_in_size] = '\0';
    
    s_handle_client_request(a_esocket, l_data, a_esocket->buf_in_size);
    
    DAP_DELETE(l_data);
    
    // Reset input buffer
    a_esocket->buf_in_size = 0;
}

static bool s_write_callback(dap_events_socket_t *a_esocket, void *a_arg) {
    UNUSED(a_arg);
    UNUSED(a_esocket);
    // Write completed successfully
    return true;
}

static void s_handle_client_request(dap_events_socket_t *a_esocket, const char *a_data, size_t a_data_size) {
    UNUSED(a_data_size);
    
    log_it(L_DEBUG, "Received IPC request (%zu bytes)", a_data_size);
    
    // Deserialize request
    dap_chain_net_vpn_client_ipc_request_t *l_request = NULL;
    int l_deserialize_ret = dap_chain_net_vpn_client_ipc_request_deserialize(a_data, &l_request);
    
    if (l_deserialize_ret != 0 || !l_request) {
        log_it(L_ERROR, "Failed to deserialize IPC request");
        
        dap_chain_net_vpn_client_ipc_response_t *l_error_resp = 
            dap_chain_net_vpn_client_ipc_response_create_error(NULL,
                                                                 VPN_IPC_ERROR_PARSE_ERROR,
                                                                 "Failed to parse request",
                                                                 NULL);
        char *l_json = NULL;
        size_t l_json_size = 0;
        if (dap_chain_net_vpn_client_ipc_response_serialize(l_error_resp, &l_json, &l_json_size) == 0) {
            dap_events_socket_write_unsafe(a_esocket, l_json, l_json_size);
            DAP_DELETE(l_json);
        }
        dap_chain_net_vpn_client_ipc_response_free(l_error_resp);
        return;
    }
    
    // Handle subscription requests
    if (l_request->method == VPN_IPC_METHOD_SUBSCRIBE && l_request->params) {
        dap_chain_net_vpn_client_ipc_subscribe_params_t *l_sub_params = 
            (dap_chain_net_vpn_client_ipc_subscribe_params_t*)l_request->params;
        
        dap_chain_net_vpn_client_ipc_client_t *l_client = s_find_client_by_esocket(a_esocket);
        if (l_client) {
            // Set subscription mask
            l_client->subscription_mask = 0;
            for (uint32_t i = 0; i < l_sub_params->event_count; i++) {
                l_client->subscription_mask |= (1 << l_sub_params->event_types[i]);
            }
            l_client->update_interval_ms = l_sub_params->update_interval_ms;
            
            log_it(L_INFO, "Client subscribed to events (mask=0x%x, interval=%u ms)", 
                   l_client->subscription_mask, l_client->update_interval_ms);
        }
        
        // Send success response
        dap_chain_net_vpn_client_ipc_response_t *l_resp = 
            dap_chain_net_vpn_client_ipc_response_create_success(l_request->id, NULL);
        char *l_json = NULL;
        size_t l_json_size = 0;
        if (dap_chain_net_vpn_client_ipc_response_serialize(l_resp, &l_json, &l_json_size) == 0) {
            dap_events_socket_write_unsafe(a_esocket, l_json, l_json_size);
            DAP_DELETE(l_json);
        }
        dap_chain_net_vpn_client_ipc_response_free(l_resp);
        dap_chain_net_vpn_client_ipc_request_free(l_request);
        return;
    }
    
    // Call handler for other methods
    dap_chain_net_vpn_client_ipc_response_t *l_response = s_ipc->handler(l_request, s_ipc->user_data);
    
    dap_chain_net_vpn_client_ipc_request_free(l_request);
    
    if (!l_response) {
        log_it(L_ERROR, "Handler returned NULL response");
        return;
    }
    
    // Serialize response
    char *l_json = NULL;
    size_t l_json_size = 0;
    if (dap_chain_net_vpn_client_ipc_response_serialize(l_response, &l_json, &l_json_size) != 0) {
        log_it(L_ERROR, "Failed to serialize IPC response");
        dap_chain_net_vpn_client_ipc_response_free(l_response);
        return;
    }
    
    // Send response
    dap_events_socket_write_unsafe(a_esocket, l_json, l_json_size);
    
    DAP_DELETE(l_json);
    dap_chain_net_vpn_client_ipc_response_free(l_response);
}

static void* s_broadcast_thread_func(void *a_arg) {
    UNUSED(a_arg);
    
    log_it(L_DEBUG, "Broadcast thread started");
    
    while (s_ipc && s_ipc->broadcast_thread_running) {
        sleep(1); // Check every second
        
        // TODO: Send periodic updates (stats) to subscribed clients
        // This can be implemented by daemon calling broadcast_event() periodically
    }
    
    log_it(L_DEBUG, "Broadcast thread stopped");
    
    return NULL;
}

static dap_chain_net_vpn_client_ipc_client_t* s_find_client_by_esocket(dap_events_socket_t *a_esocket) {
    if (!s_ipc || !a_esocket) return NULL;
    
    pthread_mutex_lock(&s_ipc->clients_mutex);
    dap_chain_net_vpn_client_ipc_client_t *l_client = s_ipc->clients;
    while (l_client) {
        if (l_client->esocket == a_esocket) {
            pthread_mutex_unlock(&s_ipc->clients_mutex);
            return l_client;
        }
        l_client = l_client->next;
    }
    pthread_mutex_unlock(&s_ipc->clients_mutex);
    
    return NULL;
}
