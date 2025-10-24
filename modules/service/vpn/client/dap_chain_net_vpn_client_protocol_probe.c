/**
 * @file dap_chain_net_vpn_client_protocol_probe.c
 * @brief Parallel protocol probing implementation
 * @date 2025-10-23
 */

#include "dap_chain_net_vpn_client_protocol_probe.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_worker.h"
#include "dap_events_socket.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

#define LOG_TAG "vpn_protocol_probe"

// Forward declarations
typedef struct probe_task probe_task_t;

/**
 * @brief Probe instance structure
 */
struct dap_vpn_protocol_probe {
    dap_vpn_protocol_probe_params_t params;
    dap_vpn_protocol_probe_result_t results;
    
    // State
    bool is_running;
    bool is_cancelled;
    uint32_t probes_completed;
    
    // Timing
    uint64_t probe_start_ts;
    dap_timerfd_t *timeout_timer;
    
    // Thread safety
    pthread_mutex_t mutex;
    pthread_cond_t completion_cond;
};

/**
 * @brief Per-protocol probe task
 */
struct probe_task {
    dap_vpn_protocol_probe_t *probe;
    dap_stream_transport_t *transport;
    dap_vpn_protocol_result_t *result;
    uint32_t task_index;
};

// Helper: Get current timestamp in milliseconds
static uint64_t get_current_timestamp_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

// Helper: Timeout callback
static bool probe_timeout_callback(void *user_data) {
    dap_vpn_protocol_probe_t *probe = (dap_vpn_protocol_probe_t*)user_data;
    
    pthread_mutex_lock(&probe->mutex);
    
    if (probe->is_running && !probe->is_cancelled) {
        log_it(L_WARNING, "[%s] Probe timed out after %u ms", 
               LOG_TAG, probe->params.timeout_ms);
        
        probe->is_cancelled = true;
        
        // Mark incomplete probes as timeout
        for (uint32_t i = 0; i < probe->results.protocol_count; i++) {
            if (probe->results.protocols[i].status == PROTOCOL_PROBE_STATUS_PROBING) {
                probe->results.protocols[i].status = PROTOCOL_PROBE_STATUS_TIMEOUT;
                probe->results.protocols[i].probe_end_ts = get_current_timestamp_ms();
                probe->results.failed_count++;
            }
        }
        
        // Notify completion
        probe->is_running = false;
        pthread_cond_signal(&probe->completion_cond);
        
        if (probe->params.on_probe_complete) {
            probe->params.on_probe_complete(probe, &probe->results, probe->params.user_data);
        }
    }
    
    pthread_mutex_unlock(&probe->mutex);
    return false; // Stop timer
}

// Helper: Worker thread task for single protocol probe
static void probe_task_worker(void *user_data) {
    probe_task_t *task = (probe_task_t*)user_data;
    dap_vpn_protocol_probe_t *probe = task->probe;
    dap_vpn_protocol_result_t *result = task->result;
    
    log_it(L_INFO, "[%s] Probing protocol: %s", LOG_TAG, result->protocol_name);
    
    uint64_t start_ts = get_current_timestamp_ms();
    result->probe_start_ts = start_ts;
    result->status = PROTOCOL_PROBE_STATUS_PROBING;
    
    // Check if protocol is blocked
    pthread_mutex_lock(&probe->mutex);
    if (probe->params.skip_blocked_protocols && result->potentially_blocked) {
        log_it(L_INFO, "[%s] Skipping blocked protocol: %s", 
               LOG_TAG, result->protocol_name);
        result->status = PROTOCOL_PROBE_STATUS_FAILED;
        result->failure_reason = dap_strdup("Protocol marked as blocked");
        result->probe_end_ts = get_current_timestamp_ms();
        probe->probes_completed++;
        pthread_mutex_unlock(&probe->mutex);
        DAP_DELETE(task);
        return;
    }
    pthread_mutex_unlock(&probe->mutex);
    
    // Try to establish connection
    dap_stream_t *stream = NULL;
    
    // TODO: Implement actual connection establishment using transport
    // For now, simulate based on transport name
    bool success = false;
    if (strcmp(result->protocol_name, "UDP") == 0 ||
        strcmp(result->protocol_name, "TCP") == 0) {
        // Simulate connection
        success = true; // In real implementation, would call transport->ops->connect()
    }
    
    uint64_t end_ts = get_current_timestamp_ms();
    result->probe_end_ts = end_ts;
    result->connection_time_ms = (uint32_t)(end_ts - start_ts);
    
    pthread_mutex_lock(&probe->mutex);
    
    if (probe->is_cancelled) {
        // Probe was cancelled
        result->status = PROTOCOL_PROBE_STATUS_TIMEOUT;
        result->failure_reason = dap_strdup("Probe cancelled");
        if (stream) dap_stream_delete_unsafe(stream);
    } else if (success) {
        // Connection established
        result->status = PROTOCOL_PROBE_STATUS_ESTABLISHED;
        result->stream = stream;
        probe->results.established_count++;
        
        log_it(L_INFO, "[%s] Protocol %s established in %u ms", 
               LOG_TAG, result->protocol_name, result->connection_time_ms);
        
        // Notify callback
        if (probe->params.on_protocol_established) {
            probe->params.on_protocol_established(
                probe, 
                result->protocol_name, 
                stream, 
                probe->params.user_data
            );
        }
    } else {
        // Connection failed
        result->status = PROTOCOL_PROBE_STATUS_FAILED;
        result->failure_reason = dap_strdup("Connection failed");
        result->error_code = -1;
        probe->results.failed_count++;
        
        log_it(L_WARNING, "[%s] Protocol %s failed: %s", 
               LOG_TAG, result->protocol_name, result->failure_reason);
        
        // Update consecutive failures for block detection
        result->consecutive_failures++;
        if (result->consecutive_failures >= 2) {
            result->potentially_blocked = true;
            log_it(L_WARNING, "[%s] Protocol %s may be blocked (failures: %u)", 
                   LOG_TAG, result->protocol_name, result->consecutive_failures);
        }
    }
    
    probe->probes_completed++;
    
    // Check if all probes completed
    if (probe->probes_completed >= probe->results.protocol_count) {
        probe->is_running = false;
        pthread_cond_signal(&probe->completion_cond);
        
        log_it(L_INFO, "[%s] All probes completed: %u established, %u failed", 
               LOG_TAG, probe->results.established_count, probe->results.failed_count);
        
        // Notify completion callback
        if (probe->params.on_probe_complete) {
            probe->params.on_probe_complete(probe, &probe->results, probe->params.user_data);
        }
    }
    
    pthread_mutex_unlock(&probe->mutex);
    DAP_DELETE(task);
}

// =============================================================================
// API Implementation
// =============================================================================

dap_vpn_protocol_probe_params_t dap_vpn_protocol_probe_default_params(
    const char *server_address,
    uint16_t server_port)
{
    dap_vpn_protocol_probe_params_t params = {
        .server_address = server_address,
        .server_port = server_port,
        .protocols = NULL,
        .protocol_count = 0,
        .timeout_ms = 10000,
        .per_protocol_timeout_ms = 5000,
        .on_protocol_established = NULL,
        .on_probe_complete = NULL,
        .user_data = NULL,
        .skip_blocked_protocols = false,
        .parallel_mode = true,
        .max_concurrent = 0
    };
    return params;
}

dap_vpn_protocol_probe_t* dap_vpn_protocol_probe_parallel_start(
    const dap_vpn_protocol_probe_params_t *params)
{
    if (!params || !params->server_address || !params->protocols || params->protocol_count == 0) {
        log_it(L_ERROR, "[%s] Invalid probe parameters", LOG_TAG);
        return NULL;
    }
    
    dap_vpn_protocol_probe_t *probe = DAP_NEW_Z(dap_vpn_protocol_probe_t);
    if (!probe) {
        log_it(L_ERROR, "[%s] Failed to allocate probe", LOG_TAG);
        return NULL;
    }
    
    // Copy parameters
    probe->params = *params;
    probe->params.server_address = dap_strdup(params->server_address);
    
    // Initialize results
    probe->results.protocol_count = params->protocol_count;
    probe->results.protocols = DAP_NEW_Z_SIZE(dap_vpn_protocol_result_t, 
                                               sizeof(dap_vpn_protocol_result_t) * params->protocol_count);
    if (!probe->results.protocols) {
        log_it(L_ERROR, "[%s] Failed to allocate results array", LOG_TAG);
        DAP_DELETE((void*)probe->params.server_address);
        DAP_DELETE(probe);
        return NULL;
    }
    
    // Initialize per-protocol results
    for (uint32_t i = 0; i < params->protocol_count; i++) {
        probe->results.protocols[i].protocol_name = dap_strdup(params->protocols[i]->name);
        probe->results.protocols[i].transport = params->protocols[i];
        probe->results.protocols[i].status = PROTOCOL_PROBE_STATUS_IDLE;
        probe->results.protocols[i].score = 0.0f;
    }
    
    // Initialize synchronization
    pthread_mutex_init(&probe->mutex, NULL);
    pthread_cond_init(&probe->completion_cond, NULL);
    
    probe->is_running = true;
    probe->probe_start_ts = get_current_timestamp_ms();
    
    // Create timeout timer
    probe->timeout_timer = dap_timerfd_start(params->timeout_ms, probe_timeout_callback, probe);
    
    log_it(L_INFO, "[%s] Starting parallel probe for %u protocols (timeout: %u ms)", 
           LOG_TAG, params->protocol_count, params->timeout_ms);
    
    // Launch probe tasks
    if (params->parallel_mode) {
        // Parallel execution: dispatch all tasks to workers
        uint32_t concurrent = params->max_concurrent > 0 ? 
                              params->max_concurrent : params->protocol_count;
        
        for (uint32_t i = 0; i < params->protocol_count && i < concurrent; i++) {
            probe_task_t *task = DAP_NEW_Z(probe_task_t);
            task->probe = probe;
            task->transport = params->protocols[i];
            task->result = &probe->results.protocols[i];
            task->task_index = i;
            
            // Dispatch to worker pool
            dap_worker_exec_callback_on(dap_worker_get_auto(), probe_task_worker, task);
        }
    } else {
        // Sequential execution: probe one by one
        for (uint32_t i = 0; i < params->protocol_count; i++) {
            probe_task_t *task = DAP_NEW_Z(probe_task_t);
            task->probe = probe;
            task->transport = params->protocols[i];
            task->result = &probe->results.protocols[i];
            task->task_index = i;
            
            probe_task_worker(task); // Execute synchronously
            
            if (probe->is_cancelled) break;
        }
    }
    
    return probe;
}

void dap_vpn_protocol_probe_cancel(dap_vpn_protocol_probe_t *probe) {
    if (!probe) return;
    
    pthread_mutex_lock(&probe->mutex);
    probe->is_cancelled = true;
    probe->is_running = false;
    pthread_cond_signal(&probe->completion_cond);
    pthread_mutex_unlock(&probe->mutex);
    
    log_it(L_INFO, "[%s] Probe cancelled", LOG_TAG);
}

const dap_vpn_protocol_probe_result_t* dap_vpn_protocol_probe_get_results(
    const dap_vpn_protocol_probe_t *probe)
{
    return probe ? &probe->results : NULL;
}

const dap_vpn_protocol_probe_result_t* dap_vpn_protocol_probe_get_sorted_by_score(
    const dap_vpn_protocol_probe_t *probe)
{
    if (!probe) return NULL;
    
    // Simple bubble sort (small arrays)
    dap_vpn_protocol_probe_result_t *sorted = (dap_vpn_protocol_probe_result_t*)&probe->results;
    
    for (uint32_t i = 0; i < sorted->protocol_count - 1; i++) {
        for (uint32_t j = 0; j < sorted->protocol_count - i - 1; j++) {
            if (sorted->protocols[j].score < sorted->protocols[j + 1].score) {
                // Swap
                dap_vpn_protocol_result_t temp = sorted->protocols[j];
                sorted->protocols[j] = sorted->protocols[j + 1];
                sorted->protocols[j + 1] = temp;
            }
        }
    }
    
    return sorted;
}

bool dap_vpn_protocol_probe_all_verified(const dap_vpn_protocol_probe_t *probe) {
    if (!probe) return false;
    
    pthread_mutex_lock((pthread_mutex_t*)&probe->mutex);
    bool all_done = (probe->probes_completed >= probe->results.protocol_count);
    pthread_mutex_unlock((pthread_mutex_t*)&probe->mutex);
    
    return all_done;
}

void dap_vpn_protocol_probe_add_established(dap_vpn_protocol_probe_t *probe,
                                             const char *protocol_name,
                                             dap_stream_t *stream)
{
    if (!probe || !protocol_name) return;
    
    pthread_mutex_lock(&probe->mutex);
    
    for (uint32_t i = 0; i < probe->results.protocol_count; i++) {
        if (strcmp(probe->results.protocols[i].protocol_name, protocol_name) == 0) {
            probe->results.protocols[i].stream = stream;
            probe->results.protocols[i].status = PROTOCOL_PROBE_STATUS_ESTABLISHED;
            probe->results.established_count++;
            break;
        }
    }
    
    pthread_mutex_unlock(&probe->mutex);
}

void dap_vpn_protocol_probe_update_result(dap_vpn_protocol_probe_t *probe,
                                           const dap_vpn_protocol_result_t *result)
{
    if (!probe || !result) return;
    
    pthread_mutex_lock(&probe->mutex);
    
    for (uint32_t i = 0; i < probe->results.protocol_count; i++) {
        if (strcmp(probe->results.protocols[i].protocol_name, result->protocol_name) == 0) {
            probe->results.protocols[i].throughput_mbps = result->throughput_mbps;
            probe->results.protocols[i].latency_ms = result->latency_ms;
            probe->results.protocols[i].packet_loss_percent = result->packet_loss_percent;
            probe->results.protocols[i].score = result->score;
            
            if (result->score > 0.0f) {
                probe->results.verified_ok_count++;
            }
            
            // Update best protocol
            if (!probe->results.best_protocol || result->score > probe->results.best_score) {
                probe->results.best_protocol = &probe->results.protocols[i];
                probe->results.best_score = result->score;
            }
            
            break;
        }
    }
    
    pthread_mutex_unlock(&probe->mutex);
}

uint32_t dap_vpn_protocol_probe_get_established_count(const dap_vpn_protocol_probe_t *probe) {
    if (!probe) return 0;
    
    pthread_mutex_lock((pthread_mutex_t*)&probe->mutex);
    uint32_t count = probe->results.established_count;
    pthread_mutex_unlock((pthread_mutex_t*)&probe->mutex);
    
    return count;
}

void dap_vpn_protocol_probe_mark_blocked(dap_vpn_protocol_probe_t *probe,
                                          const char *protocol_name,
                                          uint32_t block_duration_ms)
{
    if (!probe || !protocol_name) return;
    
    pthread_mutex_lock(&probe->mutex);
    
    for (uint32_t i = 0; i < probe->results.protocol_count; i++) {
        if (strcmp(probe->results.protocols[i].protocol_name, protocol_name) == 0) {
            probe->results.protocols[i].potentially_blocked = true;
            if (block_duration_ms > 0) {
                probe->results.protocols[i].blocked_until_ts = 
                    get_current_timestamp_ms() + block_duration_ms;
            }
            log_it(L_WARNING, "[%s] Protocol %s marked as blocked for %u ms", 
                   LOG_TAG, protocol_name, block_duration_ms);
            break;
        }
    }
    
    pthread_mutex_unlock(&probe->mutex);
}

bool dap_vpn_protocol_probe_is_blocked(const dap_vpn_protocol_probe_t *probe,
                                        const char *protocol_name)
{
    if (!probe || !protocol_name) return false;
    
    pthread_mutex_lock((pthread_mutex_t*)&probe->mutex);
    
    bool blocked = false;
    uint64_t now = get_current_timestamp_ms();
    
    for (uint32_t i = 0; i < probe->results.protocol_count; i++) {
        if (strcmp(probe->results.protocols[i].protocol_name, protocol_name) == 0) {
            if (probe->results.protocols[i].potentially_blocked) {
                if (probe->results.protocols[i].blocked_until_ts == 0 ||
                    now < probe->results.protocols[i].blocked_until_ts) {
                    blocked = true;
                }
            }
            break;
        }
    }
    
    pthread_mutex_unlock((pthread_mutex_t*)&probe->mutex);
    return blocked;
}

void dap_vpn_protocol_probe_destroy(dap_vpn_protocol_probe_t *probe) {
    if (!probe) return;
    
    // Cancel if still running
    if (probe->is_running) {
        dap_vpn_protocol_probe_cancel(probe);
    }
    
    // Stop timer
    if (probe->timeout_timer) {
        dap_timerfd_delete_mt(dap_worker_get_current(), probe->timeout_timer->esocket_uuid);
        probe->timeout_timer = NULL;
    }
    
    // Free results
    for (uint32_t i = 0; i < probe->results.protocol_count; i++) {
        DAP_DELETE(probe->results.protocols[i].protocol_name);
        DAP_DELETE(probe->results.protocols[i].failure_reason);
        // Note: streams are owned by caller, don't delete
    }
    DAP_DELETE(probe->results.protocols);
    
    // Free parameters
    DAP_DELETE((void*)probe->params.server_address);
    
    // Destroy synchronization
    pthread_mutex_destroy(&probe->mutex);
    pthread_cond_destroy(&probe->completion_cond);
    
    DAP_DELETE(probe);
}

const char* dap_vpn_protocol_probe_status_to_string(dap_vpn_protocol_probe_status_t status) {
    switch (status) {
        case PROTOCOL_PROBE_STATUS_IDLE: return "IDLE";
        case PROTOCOL_PROBE_STATUS_PROBING: return "PROBING";
        case PROTOCOL_PROBE_STATUS_ESTABLISHED: return "ESTABLISHED";
        case PROTOCOL_PROBE_STATUS_FAILED: return "FAILED";
        case PROTOCOL_PROBE_STATUS_TIMEOUT: return "TIMEOUT";
        default: return "UNKNOWN";
    }
}

