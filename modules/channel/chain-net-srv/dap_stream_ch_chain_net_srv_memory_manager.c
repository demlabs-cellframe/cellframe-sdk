/**
 * @file dap_stream_ch_chain_net_srv_memory_manager.c
 * @date 22 Jan 2025
 * @author Cellframe Team
 * @details Unified Memory Manager implementation for billing service
 *
 * Provides centralized, thread-safe memory management for all billing
 * module resources with automatic leak detection and comprehensive tracking.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "dap_stream_ch_chain_net_srv_memory_manager.h"
#include "dap_common.h"
#include "dap_strfuncs.h"

#define LOG_TAG "billing_memory_manager"

// Global memory manager instance
dap_memory_pool_manager_t g_billing_memory_manager = {0};

/**
 * @brief Convert error code to human-readable string
 */
const char* dap_billing_memory_error_to_string(dap_memory_manager_result_t error)
{
    switch (error) {
        case DAP_MEMORY_MANAGER_SUCCESS: return "Success";
        case DAP_MEMORY_MANAGER_SUCCESS_DELAYED: return "Success - cleanup delayed";
        case DAP_MEMORY_MANAGER_SUCCESS_LEGACY: return "Success - legacy cleanup used";
        case DAP_MEMORY_MANAGER_ERROR_NULL_POINTER: return "NULL pointer error";
        case DAP_MEMORY_MANAGER_ERROR_ALLOCATION_FAILED: return "Allocation failed";
        case DAP_MEMORY_MANAGER_ERROR_CLEANUP_IN_PROGRESS: return "Cleanup already in progress";
        case DAP_MEMORY_MANAGER_ERROR_RESOURCE_NOT_FOUND: return "Resource not found";
        case DAP_MEMORY_MANAGER_ERROR_INVALID_TYPE: return "Invalid resource type";
        default: return "Unknown error";
    }
}

/**
 * @brief Initialize the memory manager system
 */
int dap_billing_memory_manager_init(void)
{
    if (pthread_mutex_init(&g_billing_memory_manager.pool_mutex, NULL) != 0) {
        log_it(L_ERROR, "Failed to initialize memory manager mutex: %s", strerror(errno));
        return -1;
    }
    
    g_billing_memory_manager.resource_table = NULL;
    g_billing_memory_manager.next_allocation_id = 1;
    g_billing_memory_manager.active_allocations = 0;
    
    log_it(L_INFO, "Billing Memory Manager initialized successfully");
    return 0;
}

/**
 * @brief Cleanup and deinitialize the memory manager
 */
void dap_billing_memory_manager_deinit(void)
{
    pthread_mutex_lock(&g_billing_memory_manager.pool_mutex);
    
    // Force cleanup of any remaining resources
    dap_billing_memory_force_cleanup_leaked_resources();
    
    if (g_billing_memory_manager.active_allocations > 0) {
        log_it(L_WARNING, "Memory manager deinit: %u active allocations still present",
               g_billing_memory_manager.active_allocations);
    }
    
    // Clean up tracker table
    dap_memory_resource_tracker_t *tracker, *tmp;
    HASH_ITER(hh, g_billing_memory_manager.resource_table, tracker, tmp) {
        HASH_DEL(g_billing_memory_manager.resource_table, tracker);
        free(tracker);
    }
    
    pthread_mutex_unlock(&g_billing_memory_manager.pool_mutex);
    pthread_mutex_destroy(&g_billing_memory_manager.pool_mutex);
    
    log_it(L_INFO, "Billing Memory Manager deinitialized");
}

/**
 * @brief Thread-safe allocation with automatic tracking
 */
void* dap_billing_memory_alloc(dap_memory_resource_type_t resource_type,
                               size_t size,
                               const char *file,
                               int line)
{
    if (size == 0) {
        log_it(L_WARNING, "Attempted to allocate 0 bytes at %s:%d", file ? file : "unknown", line);
        return NULL;
    }
    
    // Allocate memory
    void *ptr = calloc(1, size);
    if (!ptr) {
        log_it(L_ERROR, "Failed to allocate %zu bytes for type %d at %s:%d", 
               size, resource_type, file ? file : "unknown", line);
        return NULL;
    }
    
    // Create tracker
    dap_memory_resource_tracker_t *tracker = (dap_memory_resource_tracker_t*)calloc(1, sizeof(dap_memory_resource_tracker_t));
    if (!tracker) {
        log_it(L_ERROR, "Failed to allocate resource tracker at %s:%d", file ? file : "unknown", line);
        free(ptr);
        return NULL;
    }
    
    // Initialize tracker
    tracker->resource_ptr = ptr;
    tracker->resource_type = resource_type;
    tracker->resource_size = size;
    tracker->allocation_timestamp = time(NULL);
    atomic_store(&tracker->ref_count, 1);
    atomic_store(&tracker->cleanup_in_progress, false);
    
    // Set allocation location
    if (file) {
        snprintf(tracker->allocation_location, sizeof(tracker->allocation_location), "%s:%d", file, line);
    } else {
        snprintf(tracker->allocation_location, sizeof(tracker->allocation_location), "unknown:0");
    }
    
    // Add to tracking table
    pthread_mutex_lock(&g_billing_memory_manager.pool_mutex);
    
    tracker->allocation_id = g_billing_memory_manager.next_allocation_id++;
    HASH_ADD_PTR(g_billing_memory_manager.resource_table, resource_ptr, tracker);
    g_billing_memory_manager.active_allocations++;
    
    pthread_mutex_unlock(&g_billing_memory_manager.pool_mutex);
    
    log_it(L_DEBUG, "Allocated %zu bytes (type %d, id %u) at %p: %s",
           size, resource_type, tracker->allocation_id, ptr, tracker->allocation_location);
    
    return ptr;
}

/**
 * @brief Thread-safe deallocation with tracking cleanup
 */
dap_memory_manager_result_t dap_billing_memory_free(void *ptr,
                                                    dap_memory_resource_type_t resource_type,
                                                    const char *file,
                                                    int line)
{
    if (!ptr) {
        log_it(L_WARNING, "Attempted to free NULL pointer at %s:%d", file ? file : "unknown", line);
        return DAP_MEMORY_MANAGER_ERROR_NULL_POINTER;
    }
    
    pthread_mutex_lock(&g_billing_memory_manager.pool_mutex);
    
    // Find tracker
    dap_memory_resource_tracker_t *tracker = NULL;
    HASH_FIND_PTR(g_billing_memory_manager.resource_table, &ptr, tracker);
    
    if (!tracker) {
        pthread_mutex_unlock(&g_billing_memory_manager.pool_mutex);
        log_it(L_WARNING, "Attempted to free untracked resource at %p (%s:%d) - using legacy free",
               ptr, file ? file : "unknown", line);
        free(ptr);
        return DAP_MEMORY_MANAGER_SUCCESS_LEGACY;
    }
    
    // Check resource type consistency
    if (tracker->resource_type != resource_type) {
        pthread_mutex_unlock(&g_billing_memory_manager.pool_mutex);
        log_it(L_ERROR, "Resource type mismatch: tracker has %d, requested %d at %s:%d",
               tracker->resource_type, resource_type, file ? file : "unknown", line);
        return DAP_MEMORY_MANAGER_ERROR_INVALID_TYPE;
    }
    
    // Check if cleanup is in progress
    bool expected = false;
    if (!atomic_compare_exchange_strong(&tracker->cleanup_in_progress, &expected, true)) {
        pthread_mutex_unlock(&g_billing_memory_manager.pool_mutex);
        log_it(L_WARNING, "Resource cleanup already in progress at %p (%s:%d)",
               ptr, file ? file : "unknown", line);
        return DAP_MEMORY_MANAGER_ERROR_CLEANUP_IN_PROGRESS;
    }
    
    // Check reference count
    int ref_count = atomic_load(&tracker->ref_count);
    if (ref_count > 1) {
        // Decrement reference count but don't free yet
        atomic_fetch_sub(&tracker->ref_count, 1);
        atomic_store(&tracker->cleanup_in_progress, false);
        pthread_mutex_unlock(&g_billing_memory_manager.pool_mutex);
        
        log_it(L_DEBUG, "Resource still has %d references, delaying cleanup at %p: %s",
               ref_count - 1, ptr, tracker->allocation_location);
        return DAP_MEMORY_MANAGER_SUCCESS_DELAYED;
    }
    
    // Remove from tracking table
    HASH_DEL(g_billing_memory_manager.resource_table, tracker);
    g_billing_memory_manager.active_allocations--;
    
    pthread_mutex_unlock(&g_billing_memory_manager.pool_mutex);
    
    log_it(L_DEBUG, "Freed resource at %p (type %d, id %u): %s",
           ptr, resource_type, tracker->allocation_id, tracker->allocation_location);
    
    // Free actual memory and tracker
    free(ptr);
    free(tracker);
    
    return DAP_MEMORY_MANAGER_SUCCESS;
}

/**
 * @brief Create a safely managed grace item
 */
dap_chain_net_srv_grace_usage_t* dap_billing_grace_item_create_safe(dap_chain_net_srv_usage_t *usage,
                                                                    const char *creation_context)
{
    if (!usage) {
        log_it(L_ERROR, "Cannot create grace item without usage context: %s", creation_context ? creation_context : "unknown");
        return NULL;
    }
    
    // Allocate managed grace item
    dap_managed_grace_item_t *managed = (dap_managed_grace_item_t*)DAP_BILLING_ALLOC(GRACE_ITEM, sizeof(dap_managed_grace_item_t));
    if (!managed) {
        log_it(L_ERROR, "Failed to allocate managed grace item: %s", creation_context ? creation_context : "unknown");
        return NULL;
    }
    
    // Initialize grace item
    memset(&managed->grace_item, 0, sizeof(dap_chain_net_srv_grace_usage_t));
    atomic_store(&managed->is_valid, true);
    
    // Set creation context
    if (creation_context) {
        strncpy(managed->creation_context, creation_context, sizeof(managed->creation_context) - 1);
        managed->creation_context[sizeof(managed->creation_context) - 1] = '\0';
    } else {
        strcpy(managed->creation_context, "unknown_context");
    }
    
    // Setup grace object
    managed->grace_item.grace = (dap_chain_net_srv_grace_t*)DAP_BILLING_ALLOC(GRACE_OBJECT, sizeof(dap_chain_net_srv_grace_t));
    if (!managed->grace_item.grace) {
        DAP_BILLING_FREE(managed, GRACE_ITEM);
        log_it(L_ERROR, "Failed to allocate grace object: %s", creation_context ? creation_context : "unknown");
        return NULL;
    }
    
    // Initialize grace object
    memset(managed->grace_item.grace, 0, sizeof(dap_chain_net_srv_grace_t));
    managed->grace_item.grace->usage = usage;
    managed->grace_item.grace->timer = NULL; // Will be set later by timer management
    
    log_it(L_DEBUG, "Created managed grace item %p: %s", &managed->grace_item, managed->creation_context);
    return &managed->grace_item;
}

/**
 * @brief Safely destroy a managed grace item
 */
dap_memory_manager_result_t dap_billing_grace_item_destroy_safe(dap_chain_net_srv_grace_usage_t *grace_item,
                                                               const char *destruction_context)
{
    if (!grace_item) {
        log_it(L_WARNING, "Attempted to destroy NULL grace item: %s", destruction_context ? destruction_context : "unknown");
        return DAP_MEMORY_MANAGER_ERROR_NULL_POINTER;
    }
    
    // Get managed wrapper
    dap_managed_grace_item_t *managed = 
        (dap_managed_grace_item_t*)((char*)grace_item - offsetof(dap_managed_grace_item_t, grace_item));
    
    // Validate the managed item
    if (!atomic_load(&managed->is_valid)) {
        log_it(L_ERROR, "Attempted to destroy invalid grace item: %s", destruction_context ? destruction_context : "unknown");
        return DAP_MEMORY_MANAGER_ERROR_INVALID_TYPE;
    }
    
    // Mark as invalid first
    atomic_store(&managed->is_valid, false);
    
    log_it(L_DEBUG, "Destroying managed grace item %p: %s (created: %s)",
           grace_item, destruction_context ? destruction_context : "unknown", managed->creation_context);
    
    // Free grace object if exists
    if (grace_item->grace) {
        DAP_BILLING_FREE(grace_item->grace, GRACE_OBJECT);
        grace_item->grace = NULL;
    }
    
    // Free managed grace item
    dap_memory_manager_result_t result = DAP_BILLING_FREE(managed, GRACE_ITEM);
    
    if (result == DAP_MEMORY_MANAGER_SUCCESS) {
        log_it(L_DEBUG, "Successfully destroyed managed grace item: %s", destruction_context ? destruction_context : "unknown");
    } else {
        log_it(L_WARNING, "Grace item destruction result: %s", dap_billing_memory_error_to_string(result));
    }
    
    return result;
}

/**
 * @brief Add reference to a grace item
 */
dap_memory_manager_result_t dap_billing_grace_item_add_ref(dap_chain_net_srv_grace_usage_t *grace_item)
{
    if (!grace_item) {
        return DAP_MEMORY_MANAGER_ERROR_NULL_POINTER;
    }
    
    dap_memory_resource_tracker_t *tracker = dap_billing_memory_find_tracker(grace_item);
    if (!tracker) {
        log_it(L_WARNING, "Attempted to add reference to unmanaged grace item at %p", grace_item);
        return DAP_MEMORY_MANAGER_ERROR_RESOURCE_NOT_FOUND;
    }
    
    int old_count = atomic_fetch_add(&tracker->ref_count, 1);
    log_it(L_DEBUG, "Added reference to grace item %p: %d -> %d", grace_item, old_count, old_count + 1);
    
    return DAP_MEMORY_MANAGER_SUCCESS;
}

/**
 * @brief Release reference to a grace item
 */
dap_memory_manager_result_t dap_billing_grace_item_release_ref(dap_chain_net_srv_grace_usage_t *grace_item)
{
    if (!grace_item) {
        return DAP_MEMORY_MANAGER_ERROR_NULL_POINTER;
    }
    
    dap_memory_resource_tracker_t *tracker = dap_billing_memory_find_tracker(grace_item);
    if (!tracker) {
        log_it(L_WARNING, "Attempted to release reference to unmanaged grace item at %p", grace_item);
        return DAP_MEMORY_MANAGER_ERROR_RESOURCE_NOT_FOUND;
    }
    
    int old_count = atomic_fetch_sub(&tracker->ref_count, 1);
    log_it(L_DEBUG, "Released reference to grace item %p: %d -> %d", grace_item, old_count, old_count - 1);
    
    // If this was the last reference and cleanup was delayed, trigger cleanup
    if (old_count == 1 && atomic_load(&tracker->cleanup_in_progress)) {
        log_it(L_INFO, "Last reference released, triggering delayed cleanup for grace item %p", grace_item);
        return dap_billing_grace_item_destroy_safe(grace_item, "delayed_cleanup_on_last_ref");
    }
    
    return DAP_MEMORY_MANAGER_SUCCESS;
}

/**
 * @brief Find resource tracker by pointer
 */
dap_memory_resource_tracker_t* dap_billing_memory_find_tracker(void *ptr)
{
    if (!ptr) {
        return NULL;
    }
    
    pthread_mutex_lock(&g_billing_memory_manager.pool_mutex);
    
    dap_memory_resource_tracker_t *tracker = NULL;
    HASH_FIND_PTR(g_billing_memory_manager.resource_table, &ptr, tracker);
    
    pthread_mutex_unlock(&g_billing_memory_manager.pool_mutex);
    
    return tracker;
}

/**
 * @brief Check if a resource is managed by the memory manager
 */
bool dap_billing_memory_is_managed_resource(void *ptr)
{
    return dap_billing_memory_find_tracker(ptr) != NULL;
}

/**
 * @brief Validate the integrity of the tracker table
 */
bool dap_billing_memory_validate_tracker_table(void)
{
    pthread_mutex_lock(&g_billing_memory_manager.pool_mutex);
    
    uint32_t hash_count = HASH_COUNT(g_billing_memory_manager.resource_table);
    bool is_valid = (hash_count == g_billing_memory_manager.active_allocations);
    
    if (!is_valid) {
        log_it(L_ERROR, "Tracker table validation failed: hash_count=%u, active_allocations=%u",
               hash_count, g_billing_memory_manager.active_allocations);
    }
    
    pthread_mutex_unlock(&g_billing_memory_manager.pool_mutex);
    
    return is_valid;
}

/**
 * @brief Force cleanup of all leaked resources (emergency cleanup)
 */
void dap_billing_memory_force_cleanup_leaked_resources(void)
{
    pthread_mutex_lock(&g_billing_memory_manager.pool_mutex);
    
    dap_memory_resource_tracker_t *tracker, *tmp;
    uint32_t cleaned_count = 0;
    
    HASH_ITER(hh, g_billing_memory_manager.resource_table, tracker, tmp) {
        // Mark for cleanup
        atomic_store(&tracker->cleanup_in_progress, true);
        atomic_store(&tracker->ref_count, 0);
        
        // Remove from table
        HASH_DEL(g_billing_memory_manager.resource_table, tracker);
        
        // Free memory
        if (tracker->resource_ptr) {
            free(tracker->resource_ptr);
        }
        free(tracker);
        
        cleaned_count++;
        g_billing_memory_manager.active_allocations--;
    }
    
    pthread_mutex_unlock(&g_billing_memory_manager.pool_mutex);
    
    if (cleaned_count > 0) {
        log_it(L_DEBUG, "Force cleanup completed: %u resources cleaned", cleaned_count);
    }
}
