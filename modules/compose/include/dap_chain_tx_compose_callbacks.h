/**
 * @file dap_chain_tx_compose_callbacks.h
 * @brief Universal transaction compose callback system
 * 
 * Provides abstract interface for services to integrate their compose logic
 * without creating circular dependencies
 */

#pragma once

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"

// Forward declarations
typedef struct compose_config compose_config_t;
typedef struct dap_chain_addr dap_chain_addr_t;

/**
 * @brief Generic service compose callback
 * Services can register their compose functions under unique service UIDs
 */
typedef dap_chain_datum_tx_t* (*dap_chain_tx_compose_callback_t)(
    void *a_service_params,    // Service-specific parameters
    compose_config_t *a_config // Compose configuration
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
