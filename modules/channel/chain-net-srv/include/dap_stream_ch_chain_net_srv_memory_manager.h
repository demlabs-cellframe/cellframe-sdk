/**
 * @file dap_stream_ch_chain_net_srv_memory_manager.h
 * @date 22 Jan 2025
 * @author Cellframe Team
 * @details Unified Memory Manager for billing service module
 *
 * This header defines a comprehensive memory management system for the billing
 * module, providing centralized allocation/deallocation, automatic leak detection,
 * and resource lifecycle tracking to eliminate memory issues.
 */

#ifndef DAP_STREAM_CH_CHAIN_NET_SRV_MEMORY_MANAGER_H
#define DAP_STREAM_CH_CHAIN_NET_SRV_MEMORY_MANAGER_H

#include <stdatomic.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>

#include "dap_common.h"
#include "dap_chain_net_srv.h"
#include "uthash.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Memory resource types for tracking and management
 */
typedef enum {
    DAP_MEMORY_RESOURCE_GRACE_ITEM,      ///< Grace usage item (main container)
    DAP_MEMORY_RESOURCE_GRACE_OBJECT,    ///< Grace object (inner data)
    DAP_MEMORY_RESOURCE_TIMER,           ///< Timer resource wrapper
    DAP_MEMORY_RESOURCE_RECEIPT,         ///< Receipt data
    DAP_MEMORY_RESOURCE_CALLBACK_ARGS    ///< Callback argument structures
} dap_memory_resource_type_t;

/**
 * @brief Memory Manager operation results
 */
typedef enum {
    DAP_MEMORY_MANAGER_SUCCESS = 0,               ///< Operation successful
    DAP_MEMORY_MANAGER_SUCCESS_DELAYED,           ///< Success but cleanup delayed (has references)
    DAP_MEMORY_MANAGER_SUCCESS_LEGACY,            ///< Success using legacy cleanup
    DAP_MEMORY_MANAGER_ERROR_NULL_POINTER,        ///< NULL pointer provided
    DAP_MEMORY_MANAGER_ERROR_ALLOCATION_FAILED,   ///< Memory allocation failed
    DAP_MEMORY_MANAGER_ERROR_CLEANUP_IN_PROGRESS, ///< Cleanup already in progress
    DAP_MEMORY_MANAGER_ERROR_RESOURCE_NOT_FOUND,  ///< Resource not found in tracking table
    DAP_MEMORY_MANAGER_ERROR_INVALID_TYPE         ///< Invalid resource type
} dap_memory_manager_result_t;

/**
 * @brief Resource tracker for memory management
 * 
 * Each allocated resource gets a tracker that monitors its lifecycle,
 * reference count, and cleanup status.
 */
typedef struct dap_memory_resource_tracker {
    void *resource_ptr;                    ///< Pointer to the actual resource
    dap_memory_resource_type_t resource_type; ///< Type of resource
    size_t resource_size;                  ///< Size of allocated memory
    time_t allocation_timestamp;           ///< When was it allocated
    uint32_t allocation_id;                ///< Unique allocation ID
    char allocation_location[128];         ///< Source location (__FILE__:__LINE__)
    atomic_int ref_count;                  ///< Reference count for safe cleanup
    atomic_bool cleanup_in_progress;       ///< Flag to prevent double cleanup
    
    UT_hash_handle hh;                     ///< UTHASH handle for hash table
} dap_memory_resource_tracker_t;

/**
 * @brief Main memory pool manager
 * 
 * Central coordinator for all memory operations in the billing module.
 * Provides basic resource tracking and unified cleanup.
 */
typedef struct dap_memory_pool_manager {
    pthread_mutex_t pool_mutex;            ///< Mutex for thread-safe operations
    dap_memory_resource_tracker_t *resource_table; ///< Hash table of tracked resources
    uint32_t next_allocation_id;           ///< Next ID to assign
    uint32_t active_allocations;           ///< Currently active allocations
} dap_memory_pool_manager_t;

/**
 * @brief Managed grace item wrapper
 * 
 * Wraps the original grace item with management metadata for
 * safe reference counting and cleanup coordination.
 */
typedef struct dap_managed_grace_item {
    dap_chain_net_srv_grace_usage_t grace_item; ///< The actual grace item
    dap_memory_resource_tracker_t tracker;      ///< Management tracker
    atomic_bool is_valid;                       ///< Validity flag
    char creation_context[128];                 ///< Creation context info
} dap_managed_grace_item_t;

// Global memory manager instance
extern dap_memory_pool_manager_t g_billing_memory_manager;

/**
 * @brief Unified allocation with automatic tracking
 * 
 * Use these macros instead of direct malloc/DAP_NEW for all billing resources
 */
#define DAP_BILLING_ALLOC(type, size) \
    dap_billing_memory_alloc(DAP_MEMORY_RESOURCE_##type, size, __FILE__, __LINE__)

#define DAP_BILLING_FREE(ptr, type) \
    dap_billing_memory_free(ptr, DAP_MEMORY_RESOURCE_##type, __FILE__, __LINE__)

// Core allocation functions
void* dap_billing_memory_alloc(dap_memory_resource_type_t resource_type,
                               size_t size,
                               const char *file,
                               int line);

dap_memory_manager_result_t dap_billing_memory_free(void *ptr,
                                                    dap_memory_resource_type_t resource_type,
                                                    const char *file,
                                                    int line);

// Memory pool management
int dap_billing_memory_manager_init(void);
void dap_billing_memory_manager_deinit(void);

// Grace object factory functions
dap_chain_net_srv_grace_usage_t* dap_billing_grace_item_create_safe(dap_chain_net_srv_usage_t *usage,
                                                                    const char *creation_context);

dap_memory_manager_result_t dap_billing_grace_item_destroy_safe(dap_chain_net_srv_grace_usage_t *grace_item,
                                                               const char *destruction_context);

dap_memory_manager_result_t dap_billing_grace_item_add_ref(dap_chain_net_srv_grace_usage_t *grace_item);
dap_memory_manager_result_t dap_billing_grace_item_release_ref(dap_chain_net_srv_grace_usage_t *grace_item);

// Resource tracking functions
dap_memory_resource_tracker_t* dap_billing_memory_find_tracker(void *ptr);
bool dap_billing_memory_is_managed_resource(void *ptr);

// Basic validation
bool dap_billing_memory_validate_tracker_table(void);
void dap_billing_memory_force_cleanup_leaked_resources(void);

// Helper function for error code to string conversion
const char* dap_billing_memory_error_to_string(dap_memory_manager_result_t error);

#ifdef __cplusplus
}
#endif

#endif // DAP_STREAM_CH_CHAIN_NET_SRV_MEMORY_MANAGER_H
