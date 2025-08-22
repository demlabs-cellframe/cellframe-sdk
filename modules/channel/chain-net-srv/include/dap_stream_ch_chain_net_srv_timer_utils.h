/**
 * @file dap_stream_ch_chain_net_srv_timer_utils.h
 * @date 22 Jan 2025
 * @author Cellframe Team
 * @details Safe Timer Utilities for billing service module
 *
 * Simple wrapper functions for consistent, thread-safe timer operations.
 * Solves timer memory leaks and inconsistent cleanup without additional tracking.
 */

#ifndef DAP_STREAM_CH_CHAIN_NET_SRV_TIMER_UTILS_H
#define DAP_STREAM_CH_CHAIN_NET_SRV_TIMER_UTILS_H

#include "dap_common.h"
#include "dap_worker.h"
#include "dap_timerfd.h"
#include "dap_chain_net_srv.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Safe timer creation wrapper
 * 
 * Creates a timer using dap_timerfd_start_on_worker with proper error handling.
 * Always use this instead of direct dap_timerfd_start_on_worker calls.
 * 
 * @param worker Worker for timer execution
 * @param timeout_ms Timeout in milliseconds
 * @param callback Timer callback function
 * @param callback_arg Argument for callback
 * @param context Debug context string (optional)
 * @return Timer pointer on success, NULL on failure
 */
dap_timerfd_t* dap_billing_timer_create_safe(dap_worker_t *worker,
                                             uint64_t timeout_ms,
                                             dap_timerfd_callback_t callback,
                                             void *callback_arg,
                                             const char *context);

/**
 * @brief Safe timer cleanup wrapper
 * 
 * Safely deletes a timer using thread-safe dap_timerfd_delete_mt.
 * Always use this instead of dap_timerfd_delete_unsafe.
 * 
 * @param timer Timer to delete (can be NULL)
 * @param context Debug context string (optional)
 */
void dap_billing_timer_delete_safe(dap_timerfd_t *timer, const char *context);

/**
 * @brief Convenience macros with automatic context
 */
#define DAP_BILLING_TIMER_CREATE(worker, timeout_ms, callback, arg) \
    dap_billing_timer_create_safe(worker, timeout_ms, callback, arg, __FILE__ ":" DAP_STRINGIFY(__LINE__))

#define DAP_BILLING_TIMER_DELETE(timer) \
    dap_billing_timer_delete_safe(timer, __FILE__ ":" DAP_STRINGIFY(__LINE__))

/**
 * @brief Safe grace timer creation
 * 
 * Creates a timer for grace period and stores it in grace->timer.
 * If timer creation fails, cleans up the grace item properly.
 * 
 * @param grace_item Grace item that will own the timer
 * @param timeout_ms Timer timeout in milliseconds  
 * @param context Debug context string
 * @return true if timer created successfully, false on failure
 */
bool dap_billing_grace_timer_create_safe(dap_chain_net_srv_grace_usage_t *grace_item,
                                         uint64_t timeout_ms,
                                         const char *context);

/**
 * @brief Safe grace timer cleanup
 * 
 * Safely deletes grace timer and sets grace->timer to NULL.
 * 
 * @param grace_item Grace item with timer to clean up
 * @param context Debug context string
 */
void dap_billing_grace_timer_cleanup_safe(dap_chain_net_srv_grace_usage_t *grace_item,
                                          const char *context);

#ifdef __cplusplus
}
#endif

#endif // DAP_STREAM_CH_CHAIN_NET_SRV_TIMER_UTILS_H
