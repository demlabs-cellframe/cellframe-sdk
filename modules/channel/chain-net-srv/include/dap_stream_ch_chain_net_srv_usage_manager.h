/**
 * @file dap_stream_ch_chain_net_srv_usage_manager.h
 * @date 22 Jan 2025
 * @author Cellframe Team
 * @details Usage-Centric Resource Management for billing service
 *
 * This header defines usage-centric management for all session resources:
 * grace objects, timers, memory, and cleanup operations.
 * Usage is the natural lifecycle owner for all session-related resources.
 */

#ifndef DAP_STREAM_CH_CHAIN_NET_SRV_USAGE_MANAGER_H
#define DAP_STREAM_CH_CHAIN_NET_SRV_USAGE_MANAGER_H

#include "dap_common.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_stream_session.h"
#include "dap_stream_ch_chain_net_srv_memory_manager.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_chain_net_srv_pkt.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Usage Manager operation results
 */
typedef enum {
    DAP_USAGE_MANAGER_SUCCESS = 0,
    DAP_USAGE_MANAGER_ERROR_NULL_POINTER,
    DAP_USAGE_MANAGER_ERROR_INVALID_PARAMETER,
    DAP_USAGE_MANAGER_ERROR_ALLOC_FAILED,
    DAP_USAGE_MANAGER_ERROR_INVALID_STATE,
    DAP_USAGE_MANAGER_ERROR_RESOURCE_BUSY,
    DAP_USAGE_MANAGER_ERROR_CLEANUP_FAILED
} dap_usage_manager_result_t;

/**
 * @brief Safe usage initialization
 * 
 * Initializes all usage-related resources safely:
 * - Sets up timers with proper cleanup
 * - Initializes locks and state
 * - Prepares for grace period management
 */
dap_usage_manager_result_t dap_billing_usage_init_safe(dap_chain_net_srv_usage_t *usage,
                                                       const char *context);

/**
 * @brief Safe usage cleanup
 * 
 * Cleans up ALL usage-related resources:
 * - All timers (save_limits, receipts_timeout, grace timers)
 * - All grace objects associated with this usage
 * - Client resources
 * - State cleanup
 */
dap_usage_manager_result_t dap_billing_usage_cleanup_safe(dap_chain_net_srv_usage_t *usage,
                                                          const char *context);

/**
 * @brief Safe grace period creation for usage
 * 
 * Creates grace period bound to specific usage:
 * - Allocates grace objects using Memory Manager
 * - Creates timer with proper cleanup
 * - Adds to service grace_hash_tab with thread safety
 * - Links everything through usage lifecycle
 */
dap_usage_manager_result_t dap_billing_usage_grace_create_safe(dap_chain_net_srv_usage_t *usage,
                                                               dap_hash_fast_t *tx_cond_hash,
                                                               uint32_t timeout_seconds,
                                                               const char *context);

/**
 * @brief Safe grace period cleanup for usage
 * 
 * Cleans up specific grace period:
 * - Removes from service grace_hash_tab
 * - Cleans up timer
 * - Frees grace objects through Memory Manager
 */
dap_usage_manager_result_t dap_billing_usage_grace_cleanup_safe(dap_chain_net_srv_usage_t *usage,
                                                                dap_hash_fast_t *tx_cond_hash,
                                                                const char *context);

/**
 * @brief Safe timer management for usage
 * 
 * Unified timer operations for all usage timers:
 * - save_limits_timer
 * - receipts_timeout_timer
 * - grace period timers
 */
dap_usage_manager_result_t dap_billing_usage_timer_create_safe(dap_chain_net_srv_usage_t *usage,
                                                               dap_timerfd_t **timer_ptr,
                                                               uint64_t timeout_ms,
                                                               dap_timerfd_callback_t callback,
                                                               void *callback_arg,
                                                               const char *context);

dap_usage_manager_result_t dap_billing_usage_timer_cleanup_safe(dap_chain_net_srv_usage_t *usage,
                                                                dap_timerfd_t **timer_ptr,
                                                                const char *context);

/**
 * @brief Configure usage object with client-specific data from service request
 * 
 * Sets up client connection, transaction conditions, and service state.
 * Includes client allocation, stream channel binding, and initial state setup.
 */
dap_usage_manager_result_t dap_billing_usage_configure_client_safe(dap_chain_net_srv_usage_t *usage,
                                                                   dap_stream_ch_t *stream_ch,
                                                                   dap_stream_ch_chain_net_srv_pkt_request_t *request,
                                                                   const char *context);

/**
 * @brief Usage lifecycle state management
 */
bool dap_billing_usage_is_active_safe(dap_chain_net_srv_usage_t *usage);
dap_usage_manager_result_t dap_billing_usage_set_active_safe(dap_chain_net_srv_usage_t *usage, bool active);

/**
 * @brief Convert usage manager error code to string
 */
const char* dap_billing_usage_error_to_string(dap_usage_manager_result_t error);

/**
 * @brief Usage resource validation
 */
bool dap_billing_usage_validate_resources(dap_chain_net_srv_usage_t *usage);
void dap_billing_usage_force_cleanup_all_grace(dap_chain_net_srv_usage_t *usage);

/**
 * @brief Error handling
 */
const char* dap_billing_usage_error_to_string(dap_usage_manager_result_t error);

/**
 * @brief Convenience macros
 */
#define DAP_BILLING_USAGE_INIT(usage) \
    dap_billing_usage_init_safe(usage, __FILE__ ":" DAP_STRINGIFY(__LINE__))

#define DAP_BILLING_USAGE_CLEANUP(usage) \
    dap_billing_usage_cleanup_safe(usage, __FILE__ ":" DAP_STRINGIFY(__LINE__))

#define DAP_BILLING_USAGE_GRACE_CREATE(usage, tx_hash, timeout) \
    dap_billing_usage_grace_create_safe(usage, tx_hash, timeout, __FILE__ ":" DAP_STRINGIFY(__LINE__))

#ifdef __cplusplus
}
#endif

#endif // DAP_STREAM_CH_CHAIN_NET_SRV_USAGE_MANAGER_H
