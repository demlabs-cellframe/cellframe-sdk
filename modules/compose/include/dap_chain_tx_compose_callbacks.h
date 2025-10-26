/**
 * @file dap_chain_tx_compose_callbacks.h
 * @brief Universal transaction compose callback system
 * 
 * Provides abstract interface for services to integrate their compose logic
 * without creating circular dependencies
 * 
 * ## Usage Example
 * 
 * ### In service initialization (e.g., voting service):
 * 
 * ```c
 * // Define your compose callback
 * static dap_chain_datum_tx_t* s_voting_compose_callback(
 *     void *a_service_params, 
 *     dap_chain_tx_compose_config_t *a_config)
 * {
 *     // Cast service-specific parameters
 *     voting_compose_params_t *l_params = (voting_compose_params_t *)a_service_params;
 *     
 *     // Your compose logic here
 *     dap_chain_datum_tx_t *l_tx = dap_chain_tx_compose_poll_create(
 *         l_params->net_name,
 *         l_params->voting_params,
 *         a_config
 *     );
 *     
 *     return l_tx;
 * }
 * 
 * // In service init function:
 * int dap_chain_net_srv_voting_init(void)
 * {
 *     // ... other initialization ...
 *     
 *     // Register your compose callback
 *     dap_chain_tx_compose_service_callback_register(
 *         c_dap_chain_net_srv_voting_uid.uint64,
 *         s_voting_compose_callback
 *     );
 *     
 *     log_it(L_NOTICE, "Voting compose callback registered");
 *     return 0;
 * }
 * 
 * // In service deinit:
 * void dap_chain_net_srv_voting_deinit(void)
 * {
 *     dap_chain_tx_compose_service_callback_unregister(
 *         c_dap_chain_net_srv_voting_uid.uint64
 *     );
 *     // ... other cleanup ...
 * }
 * ```
 * 
 * ### In compose module (calling registered callbacks):
 * 
 * ```c
 * dap_chain_datum_tx_t* dap_chain_tx_compose_by_service(
 *     uint64_t a_srv_uid,
 *     void *a_service_params,
 *     dap_chain_tx_compose_config_t *a_config)
 * {
 *     dap_chain_tx_compose_callback_t l_callback = 
 *         dap_chain_tx_compose_service_callback_get(a_srv_uid);
 *     
 *     if (!l_callback) {
 *         log_it(L_ERROR, "No compose callback registered for service %"DAP_UINT64_FORMAT_X, 
 *                a_srv_uid);
 *         return NULL;
 *     }
 *     
 *     return l_callback(a_service_params, a_config);
 * }
 * ```
 */

#pragma once

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"

// Forward declarations
typedef struct dap_chain_tx_compose_config dap_chain_tx_compose_config_t;
typedef struct dap_chain_addr dap_chain_addr_t;

/**
 * @brief Generic service compose callback
 * Services can register their compose functions under unique service UIDs
 */
typedef dap_chain_datum_tx_t* (*dap_chain_tx_compose_callback_t)(
    void *a_service_params,    // Service-specific parameters
    dap_chain_tx_compose_config_t *a_config // Compose configuration
);

/**
 * @brief Register compose callback for specific service UID
 * @param a_srv_uid Service unique identifier
 * @param a_callback Compose callback function
 */
void dap_chain_tx_compose_service_callback_register(uint64_t a_srv_uid, dap_chain_tx_compose_callback_t a_callback);

/**
 * @brief Get compose callback for specific service UID
 * @param a_srv_uid Service unique identifier
 * @return Callback function or NULL if not registered
 */
dap_chain_tx_compose_callback_t dap_chain_tx_compose_service_callback_get(uint64_t a_srv_uid);

/**
 * @brief Unregister compose callback for specific service UID
 * @param a_srv_uid Service unique identifier
 */
void dap_chain_tx_compose_service_callback_unregister(uint64_t a_srv_uid);

/**
 * @brief Initialize compose callbacks system
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_tx_compose_callbacks_init(void);

/**
 * @brief Deinitialize compose callbacks system and free all resources
 */
void dap_chain_tx_compose_callbacks_deinit(void);
