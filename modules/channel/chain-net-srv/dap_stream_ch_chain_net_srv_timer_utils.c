/**
 * @file dap_stream_ch_chain_net_srv_timer_utils.c
 * @date 22 Jan 2025
 * @author Cellframe Team
 * @details Safe Timer Utilities implementation
 *
 * Simple wrapper functions that solve timer consistency issues:
 * - Always use thread-safe timer deletion
 * - Proper error handling and cleanup
 * - Unified timer creation patterns
 */

#include "dap_stream_ch_chain_net_srv_timer_utils.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_stream_ch_chain_net_srv_memory_manager.h"

// Forward declaration for grace period finish callback
extern bool s_grace_period_finish(dap_chain_net_srv_grace_usage_t *a_grace);

#define LOG_TAG "billing_timer_utils"

/**
 * @brief Safe timer creation wrapper
 */
dap_timerfd_t* dap_billing_timer_create_safe(dap_worker_t *worker,
                                             uint64_t timeout_ms,
                                             dap_timerfd_callback_t callback,
                                             void *callback_arg,
                                             const char *context)
{
    if (!worker || !callback) {
        log_it(L_ERROR, "Invalid parameters for timer creation: %s", 
               context ? context : "unknown_context");
        return NULL;
    }
    
    // Create timer using standard function
    dap_timerfd_t *timer = dap_timerfd_start_on_worker(worker, timeout_ms, callback, callback_arg);
    
    if (!timer) {
        log_it(L_ERROR, "Timer creation failed: %s", context ? context : "unknown_context");
        return NULL;
    }
    
    log_it(L_DEBUG, "Timer created successfully: %s", context ? context : "unknown_context");
    return timer;
}

/**
 * @brief Safe timer cleanup wrapper
 */
void dap_billing_timer_delete_safe(dap_timerfd_t *timer, const char *context)
{
    if (!timer) {
        log_it(L_DEBUG, "Attempted to delete NULL timer: %s", context ? context : "unknown_context");
        return;
    }
    
    if (!timer->worker) {
        log_it(L_WARNING, "Timer has NULL worker, cannot use thread-safe deletion: %s", 
               context ? context : "unknown_context");
        return;
    }
    
    // Always use thread-safe deletion
    dap_timerfd_delete_mt(timer->worker, timer->esocket_uuid);
    
    log_it(L_DEBUG, "Timer deleted safely: %s", context ? context : "unknown_context");
}

/**
 * @brief Safe grace timer creation
 */
bool dap_billing_grace_timer_create_safe(dap_chain_net_srv_grace_usage_t *grace_item,
                                         uint64_t timeout_ms,
                                         const char *context)
{
    if (!grace_item || !grace_item->grace) {
        log_it(L_ERROR, "Invalid grace item for timer creation: %s", 
               context ? context : "unknown_context");
        return false;
    }
    
    dap_chain_net_srv_grace_t *grace = grace_item->grace;
    
    if (!grace->stream_worker || !grace->stream_worker->worker) {
        log_it(L_ERROR, "Grace item has no valid worker for timer: %s", 
               context ? context : "unknown_context");
        return false;
    }
    
    // Create timer with grace period callback
    // Note: s_grace_period_finish is defined in main billing module
    grace->timer = dap_billing_timer_create_safe(
        grace->stream_worker->worker,
        timeout_ms,
        (dap_timerfd_callback_t)s_grace_period_finish,
        grace_item,
        context
    );
    
    if (!grace->timer) {
        log_it(L_ERROR, "Failed to create grace timer, grace period will not work: %s", 
               context ? context : "unknown_context");
        return false;
    }
    
    log_it(L_DEBUG, "Grace timer created successfully: %s", context ? context : "unknown_context");
    return true;
}

/**
 * @brief Safe grace timer cleanup
 */
void dap_billing_grace_timer_cleanup_safe(dap_chain_net_srv_grace_usage_t *grace_item,
                                          const char *context)
{
    if (!grace_item || !grace_item->grace) {
        log_it(L_DEBUG, "Invalid grace item for timer cleanup: %s", 
               context ? context : "unknown_context");
        return;
    }
    
    dap_chain_net_srv_grace_t *grace = grace_item->grace;
    
    if (grace->timer) {
        dap_billing_timer_delete_safe(grace->timer, context);
        grace->timer = NULL;  // Always set to NULL after cleanup
        log_it(L_DEBUG, "Grace timer cleaned up: %s", context ? context : "unknown_context");
    } else {
        log_it(L_DEBUG, "Grace timer was already NULL: %s", context ? context : "unknown_context");
    }
}
