/**
 * @file dap_stream_ch_chain_net_srv_memory_manager.h
 * @date 22 Jan 2025
 * @author Cellframe Team
 * @details Simplified Memory Management for billing service module
 *
 * Simple grace object management without complex tracking or statistics.
 */

#ifndef DAP_STREAM_CH_CHAIN_NET_SRV_MEMORY_MANAGER_H
#define DAP_STREAM_CH_CHAIN_NET_SRV_MEMORY_MANAGER_H

#include <stdbool.h>
#include "dap_common.h"
#include "dap_chain_net_srv.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Memory Manager operation results
 */
typedef enum {
    DAP_MEMORY_MANAGER_SUCCESS = 0,               ///< Operation successful
    DAP_MEMORY_MANAGER_ERROR_NULL_POINTER,        ///< NULL pointer provided
    DAP_MEMORY_MANAGER_ERROR_ALLOCATION_FAILED    ///< Memory allocation failed
} dap_memory_manager_result_t;

// Grace object factory functions
dap_chain_net_srv_grace_usage_t* dap_billing_grace_item_create_safe(dap_chain_net_srv_usage_t *usage);
dap_memory_manager_result_t dap_billing_grace_item_destroy_safe(dap_chain_net_srv_grace_usage_t **grace_item);



#ifdef __cplusplus
}
#endif

#endif // DAP_STREAM_CH_CHAIN_NET_SRV_MEMORY_MANAGER_H