/**
 * @file dap_stream_ch_chain_net_srv_memory_manager.c
 * @date 22 Jan 2025
 * @author Cellframe Team
 * @details Simplified Memory Manager implementation for billing service
 *
 * Simple memory management for grace objects using standard DAP_NEW/DAP_DELETE.
 */

#include "dap_stream_ch_chain_net_srv_memory_manager.h"
#include "dap_common.h"

#define LOG_TAG "billing_memory_manager"

/**
 * @brief Initialize the memory manager system
 */
int dap_billing_memory_manager_init(void)
{
    log_it(L_INFO, "Billing Memory Manager initialized successfully");
    return 0;
}

/**
 * @brief Cleanup and deinitialize the memory manager
 */
void dap_billing_memory_manager_deinit(void)
{
    log_it(L_INFO, "Billing Memory Manager deinitialized");
}

/**
 * @brief Create a grace item safely
 */
dap_chain_net_srv_grace_usage_t* dap_billing_grace_item_create_safe(dap_chain_net_srv_usage_t *usage)
{
    if (!usage) {
        log_it(L_ERROR, "%s: Cannot create grace item without usage context", __func__);
        return NULL;
    }

    // Simple allocation using DAP_NEW
    dap_chain_net_srv_grace_usage_t *grace_item = DAP_NEW_Z(dap_chain_net_srv_grace_usage_t);
    if (!grace_item) {
        log_it(L_ERROR, "%s: Failed to allocate grace object", __func__);
        return NULL;
    }

    // Set usage reference in grace object
    grace_item->grace = DAP_NEW_Z(dap_chain_net_srv_grace_t);
    if (grace_item->grace) {
        grace_item->grace->usage = usage;
    }
    
    log_it(L_DEBUG, "%s: Grace item created successfully for usage %u", __func__, usage->id);
    return grace_item;
}

/**
 * @brief Destroy a grace item safely
 */
dap_memory_manager_result_t dap_billing_grace_item_destroy_safe(dap_chain_net_srv_grace_usage_t *grace_item)
{
    if (!grace_item) {
        log_it(L_ERROR, "%s: Attempted to destroy invalid grace item", __func__);
        return DAP_MEMORY_MANAGER_ERROR_NULL_POINTER;
    }

    log_it(L_DEBUG, "%s: Destroying grace item", __func__);
    
    // Cleanup internal grace object if exists
    if (grace_item->grace) {
        DAP_DELETE(grace_item->grace);
    }
    
    // Simple cleanup using DAP_DELETE
    DAP_DELETE(grace_item);
    
    log_it(L_DEBUG, "%s: Successfully destroyed grace item", __func__);
    return DAP_MEMORY_MANAGER_SUCCESS;
}