/**
 * @file dap_stream_ch_chain_net_srv_usage_manager.c
 * @date 22 Jan 2025
 * @author Cellframe Team
 * @details Usage-Centric Resource Management implementation
 *
 * Manages all session resources through the usage object as natural lifecycle owner:
 * - Grace objects and timers
 * - Client resources and state
 * - Thread-safe operations through usage->rwlock
 * - Integration with existing Memory Manager
 */

#include "dap_stream_ch_chain_net_srv_usage_manager.h"
#include "dap_stream_ch_chain_net_srv_timer_utils.h"
#include "dap_stream_ch_chain_net_srv.h"

#define LOG_TAG "billing_usage_manager"

/**
 * @brief Convert usage error code to human-readable string
 */
const char* dap_billing_usage_error_to_string(dap_usage_manager_result_t error)
{
    switch (error) {
        case DAP_USAGE_MANAGER_SUCCESS: return "Success";
        case DAP_USAGE_MANAGER_ERROR_NULL_POINTER: return "NULL pointer error";
        case DAP_USAGE_MANAGER_ERROR_INVALID_PARAMETER: return "Invalid parameter";
        case DAP_USAGE_MANAGER_ERROR_ALLOC_FAILED: return "Memory allocation failed";
        case DAP_USAGE_MANAGER_ERROR_INVALID_STATE: return "Invalid usage state";
        case DAP_USAGE_MANAGER_ERROR_RESOURCE_BUSY: return "Resource busy";
        case DAP_USAGE_MANAGER_ERROR_CLEANUP_FAILED: return "Cleanup failed";
        default: return "Unknown error";
    }
}

/**
 * @brief Safe usage initialization
 */
dap_usage_manager_result_t dap_billing_usage_init_safe(dap_chain_net_srv_usage_t *usage,
                                                       const char *context)
{
    if (!usage) {
        log_it(L_ERROR, "Cannot initialize NULL usage: %s", context ? context : "unknown");
        return DAP_USAGE_MANAGER_ERROR_NULL_POINTER;
    }
    
    // Initialize rwlock if needed
    if (pthread_rwlock_init(&usage->rwlock, NULL) != 0) {
        log_it(L_ERROR, "Failed to initialize usage rwlock: %s", context ? context : "unknown");
        return DAP_USAGE_MANAGER_ERROR_CLEANUP_FAILED;
    }
    
    // Ensure timers are NULL initially
    usage->save_limits_timer = NULL;
    usage->receipts_timeout_timer = NULL;
    
    // Set active state
    usage->is_active = true;
    
    log_it(L_DEBUG, "Usage %u initialized safely: %s", usage->id, context ? context : "unknown");
    return DAP_USAGE_MANAGER_SUCCESS;
}

/**
 * @brief Safe usage cleanup - cleans up ALL resources
 */
dap_usage_manager_result_t dap_billing_usage_cleanup_safe(dap_chain_net_srv_usage_t *usage,
                                                          const char *context)
{
    if (!usage) {
        log_it(L_WARNING, "Attempted to cleanup NULL usage: %s", context ? context : "unknown");
        return DAP_USAGE_MANAGER_ERROR_NULL_POINTER;
    }
    
    // Write lock for exclusive access during cleanup
    pthread_rwlock_wrlock(&usage->rwlock);
    
    // Mark as inactive
    usage->is_active = false;
    
    // Cleanup all usage timers
    dap_billing_usage_timer_cleanup_safe(usage, &usage->save_limits_timer, "save_limits_cleanup");
    dap_billing_usage_timer_cleanup_safe(usage, &usage->receipts_timeout_timer, "receipts_timeout_cleanup");
    
    // Force cleanup all grace periods for this usage
    dap_billing_usage_force_cleanup_all_grace(usage);
    
    pthread_rwlock_unlock(&usage->rwlock);
    
    // Destroy rwlock
    pthread_rwlock_destroy(&usage->rwlock);
    
    log_it(L_DEBUG, "Usage %u cleaned up safely: %s", usage->id, context ? context : "unknown");
    return DAP_USAGE_MANAGER_SUCCESS;
}

/**
 * @brief Safe grace period creation bound to usage lifecycle
 */
dap_usage_manager_result_t dap_billing_usage_grace_create_safe(dap_chain_net_srv_usage_t *usage,
                                                               dap_hash_fast_t *tx_cond_hash,
                                                               uint32_t timeout_seconds,
                                                               const char *context)
{
    if (!usage || !tx_cond_hash || !usage->service) {
        log_it(L_ERROR, "Invalid parameters for grace creation: %s", context ? context : "unknown");
        return DAP_USAGE_MANAGER_ERROR_NULL_POINTER;
    }
    
    // Read lock for usage state check
    pthread_rwlock_rdlock(&usage->rwlock);
    
    if (!usage->is_active) {
        pthread_rwlock_unlock(&usage->rwlock);
        log_it(L_WARNING, "Cannot create grace for inactive usage %u: %s", 
               usage->id, context ? context : "unknown");
        return DAP_USAGE_MANAGER_ERROR_INVALID_STATE;
    }
    
    pthread_rwlock_unlock(&usage->rwlock);
    
    // Create grace object using Memory Manager
    dap_chain_net_srv_grace_usage_t *grace_item = 
        dap_billing_grace_item_create_safe(usage, context);
    
    if (!grace_item) {
        log_it(L_ERROR, "Failed to create grace item for usage %u: %s", 
               usage->id, context ? context : "unknown");
        return DAP_USAGE_MANAGER_ERROR_CLEANUP_FAILED;
    }
    
    // Setup grace item
    grace_item->tx_cond_hash = *tx_cond_hash;
    grace_item->grace->ch_uuid = usage->client->ch->uuid;
    grace_item->grace->stream_worker = usage->client->stream_worker;
    grace_item->grace->usage = usage;
    
    // Create timer for grace period using Timer Utils
    bool timer_created = dap_billing_grace_timer_create_safe(
        grace_item,
        timeout_seconds * 1000,
        context
    );
    
    if (!timer_created) {
        log_it(L_ERROR, "Failed to create grace timer for usage %u: %s", 
               usage->id, context ? context : "unknown");
        dap_billing_grace_item_destroy_safe(grace_item, "timer_creation_failed");
        return DAP_USAGE_MANAGER_ERROR_CLEANUP_FAILED;
    }
    
    // Add to service grace hash table with thread safety
    pthread_mutex_lock(&usage->service->grace_mutex);
    HASH_ADD(hh, usage->service->grace_hash_tab, tx_cond_hash, sizeof(dap_hash_fast_t), grace_item);
    pthread_mutex_unlock(&usage->service->grace_mutex);
    
    log_it(L_DEBUG, "Grace period created for usage %u: %s", usage->id, context ? context : "unknown");
    return DAP_USAGE_MANAGER_SUCCESS;
}

/**
 * @brief Safe grace period cleanup for specific usage
 */
dap_usage_manager_result_t dap_billing_usage_grace_cleanup_safe(dap_chain_net_srv_usage_t *usage,
                                                                dap_hash_fast_t *tx_cond_hash,
                                                                const char *context)
{
    if (!usage || !tx_cond_hash || !usage->service) {
        log_it(L_WARNING, "Invalid parameters for grace cleanup: %s", context ? context : "unknown");
        return DAP_USAGE_MANAGER_ERROR_NULL_POINTER;
    }
    
    // Find grace item in service hash table
    pthread_mutex_lock(&usage->service->grace_mutex);
    
    dap_chain_net_srv_grace_usage_t *grace_item = NULL;
    HASH_FIND(hh, usage->service->grace_hash_tab, tx_cond_hash, sizeof(dap_hash_fast_t), grace_item);
    
    if (!grace_item) {
        pthread_mutex_unlock(&usage->service->grace_mutex);
        log_it(L_DEBUG, "Grace item not found for cleanup in usage %u: %s", 
               usage->id, context ? context : "unknown");
        return DAP_USAGE_MANAGER_SUCCESS; // Not an error if already cleaned up
    }
    
    // Verify this grace belongs to our usage
    if (grace_item->grace->usage != usage) {
        pthread_mutex_unlock(&usage->service->grace_mutex);
        log_it(L_WARNING, "Grace item belongs to different usage (expected %u): %s", 
               usage->id, context ? context : "unknown");
        return DAP_USAGE_MANAGER_ERROR_INVALID_STATE;
    }
    
    // Remove from hash table
    HASH_DEL(usage->service->grace_hash_tab, grace_item);
    pthread_mutex_unlock(&usage->service->grace_mutex);
    
    // Cleanup timer
    dap_billing_grace_timer_cleanup_safe(grace_item, context);
    
    // Cleanup grace item through Memory Manager
    dap_billing_grace_item_destroy_safe(grace_item, context);
    
    log_it(L_DEBUG, "Grace period cleaned up for usage %u: %s", usage->id, context ? context : "unknown");
    return DAP_USAGE_MANAGER_SUCCESS;
}

/**
 * @brief Configure usage object with client-specific data from service request
 */
dap_usage_manager_result_t dap_billing_usage_configure_client_safe(dap_chain_net_srv_usage_t *usage,
                                                                   dap_stream_ch_t *stream_ch,
                                                                   dap_stream_ch_chain_net_srv_pkt_request_t *request,
                                                                   const char *context)
{
    if (!usage || !stream_ch || !request) {
        log_it(L_ERROR, "Invalid parameters for client configuration: %s", context ? context : "unknown");
        return DAP_USAGE_MANAGER_ERROR_INVALID_PARAMETER;
    }

    // Acquire write lock for usage modification
    pthread_rwlock_wrlock(&usage->rwlock);
    
    // Allocate client structure
    usage->client = DAP_NEW_Z(dap_chain_net_srv_client_remote_t);
    if (!usage->client) {
        log_it(L_ERROR, "Failed to allocate client structure: %s", context ? context : "unknown");
        pthread_rwlock_unlock(&usage->rwlock);
        return DAP_USAGE_MANAGER_ERROR_ALLOC_FAILED;
    }
    
    // Configure client connection details
    usage->client->stream_worker = stream_ch->stream_worker;
    usage->client->ch = stream_ch;
    usage->client->session_id = stream_ch->stream->session->id;
    usage->client->ts_created = time(NULL);
    
    // Set transaction and service details
    usage->tx_cond_hash = request->hdr.tx_cond;
    usage->ts_created = time(NULL);
    usage->client_pkey_hash = request->hdr.client_pkey_hash;
    
    // Initialize service state
    usage->service_state = DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_IDLE;
    usage->service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_IDLE;
    
    // Set timeout callback (external function)
    extern void s_start_receipt_timeout_timer(dap_chain_net_srv_usage_t *usage);
    usage->receipt_timeout_timer_start_callback = s_start_receipt_timeout_timer;
    
    pthread_rwlock_unlock(&usage->rwlock);
    
    log_it(L_DEBUG, "Usage client configuration completed successfully: %s", context ? context : "unknown");
    return DAP_USAGE_MANAGER_SUCCESS;
}

/**
 * @brief Safe timer management for usage timers
 */
dap_usage_manager_result_t dap_billing_usage_timer_create_safe(dap_chain_net_srv_usage_t *usage,
                                                               dap_timerfd_t **timer_ptr,
                                                               uint64_t timeout_ms,
                                                               dap_timerfd_callback_t callback,
                                                               void *callback_arg,
                                                               const char *context)
{
    if (!usage || !timer_ptr || !callback || !usage->client || !usage->client->stream_worker) {
        log_it(L_ERROR, "Invalid parameters for usage timer creation: %s", context ? context : "unknown");
        return DAP_USAGE_MANAGER_ERROR_NULL_POINTER;
    }
    
    // Cleanup existing timer if present
    if (*timer_ptr) {
        dap_billing_usage_timer_cleanup_safe(usage, timer_ptr, "replacing_existing_timer");
    }
    
    // Create timer using Timer Utils
    *timer_ptr = dap_billing_timer_create_safe(
        usage->client->stream_worker->worker,
        timeout_ms,
        callback,
        callback_arg,
        context
    );
    
    if (!*timer_ptr) {
        log_it(L_ERROR, "Failed to create timer for usage %u: %s", usage->id, context ? context : "unknown");
        return DAP_USAGE_MANAGER_ERROR_CLEANUP_FAILED;
    }
    
    log_it(L_DEBUG, "Timer created for usage %u: %s", usage->id, context ? context : "unknown");
    return DAP_USAGE_MANAGER_SUCCESS;
}

/**
 * @brief Safe timer cleanup for usage timers
 */
dap_usage_manager_result_t dap_billing_usage_timer_cleanup_safe(dap_chain_net_srv_usage_t *usage,
                                                                dap_timerfd_t **timer_ptr,
                                                                const char *context)
{
    if (!usage || !timer_ptr) {
        log_it(L_DEBUG, "Invalid parameters for usage timer cleanup: %s", context ? context : "unknown");
        return DAP_USAGE_MANAGER_ERROR_NULL_POINTER;
    }
    
    if (*timer_ptr) {
        dap_billing_timer_delete_safe(*timer_ptr, context);
        *timer_ptr = NULL;
        log_it(L_DEBUG, "Timer cleaned up for usage %u: %s", usage->id, context ? context : "unknown");
    }
    
    return DAP_USAGE_MANAGER_SUCCESS;
}

/**
 * @brief Check if usage is active (thread-safe)
 */
bool dap_billing_usage_is_active_safe(dap_chain_net_srv_usage_t *usage)
{
    if (!usage) {
        return false;
    }
    
    pthread_rwlock_rdlock(&usage->rwlock);
    bool is_active = usage->is_active;
    pthread_rwlock_unlock(&usage->rwlock);
    
    return is_active;
}

/**
 * @brief Set usage active state (thread-safe)
 */
dap_usage_manager_result_t dap_billing_usage_set_active_safe(dap_chain_net_srv_usage_t *usage, bool active)
{
    if (!usage) {
        return DAP_USAGE_MANAGER_ERROR_NULL_POINTER;
    }
    
    pthread_rwlock_wrlock(&usage->rwlock);
    usage->is_active = active;
    pthread_rwlock_unlock(&usage->rwlock);
    
    log_it(L_DEBUG, "Usage %u active state set to %s", usage->id, active ? "true" : "false");
    return DAP_USAGE_MANAGER_SUCCESS;
}

/**
 * @brief Validate usage resources
 */
bool dap_billing_usage_validate_resources(dap_chain_net_srv_usage_t *usage)
{
    if (!usage) {
        return false;
    }
    
    // Basic structural validation
    if (!usage->service || !usage->client) {
        log_it(L_ERROR, "Usage %u has invalid service or client", usage->id);
        return false;
    }
    
    // Check for orphaned timers (timers without valid workers)
    if (usage->save_limits_timer && (!usage->client->stream_worker || !usage->client->stream_worker->worker)) {
        log_it(L_WARNING, "Usage %u has timer but invalid worker", usage->id);
        return false;
    }
    
    return true;
}

/**
 * @brief Force cleanup all grace periods for this usage
 */
void dap_billing_usage_force_cleanup_all_grace(dap_chain_net_srv_usage_t *usage)
{
    if (!usage || !usage->service) {
        return;
    }
    
    pthread_mutex_lock(&usage->service->grace_mutex);
    
    dap_chain_net_srv_grace_usage_t *grace_item, *tmp;
    uint32_t cleaned_count = 0;
    
    // Iterate through all grace items and clean up those belonging to this usage
    HASH_ITER(hh, usage->service->grace_hash_tab, grace_item, tmp) {
        if (grace_item->grace && grace_item->grace->usage == usage) {
            // Remove from hash table
            HASH_DEL(usage->service->grace_hash_tab, grace_item);
            
            // Cleanup timer
            dap_billing_grace_timer_cleanup_safe(grace_item, "force_cleanup");
            
            // Cleanup grace item
            dap_billing_grace_item_destroy_safe(grace_item, "force_cleanup");
            
            cleaned_count++;
        }
    }
    
    pthread_mutex_unlock(&usage->service->grace_mutex);
    
    if (cleaned_count > 0) {
        log_it(L_DEBUG, "Force cleaned up %u grace periods for usage %u", cleaned_count, usage->id);
    }
}
