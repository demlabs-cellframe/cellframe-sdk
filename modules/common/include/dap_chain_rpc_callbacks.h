/**
 * @file dap_chain_rpc_callbacks.h
 * @brief RPC Callback Registry for dependency inversion
 * @details Implementation of Dependency Inversion Principle through callback patterns
 *          to eliminate cyclic dependencies between modules.
 *          
 * @author Cellframe Team
 * @date 2025-12-15
 * 
 * @note This module was created as part of Phase 5.3 architectural refactoring
 *       to eliminate cyclic dependencies following SLC methodology.
 *       
 * @see modules/net/dap_chain_node.c lines 32-34 (TODO comments)
 */

#pragma once

#include <pthread.h>
#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_hash.h"

// Forward declarations
typedef struct dap_chain dap_chain_t;
typedef struct dap_chain_net dap_chain_net_t;
typedef struct dap_chain_datum dap_chain_datum_t;
typedef struct dap_ledger dap_ledger_t;

/**
 * @brief Consensus RPC callback types
 * @details Used to eliminate net → consensus (esbocs) dependency
 *          Replaces direct #include "dap_chain_cs_esbocs.h" with callback pattern
 */
typedef struct dap_chain_rpc_consensus_params {
    dap_chain_t *chain;
    dap_chain_net_t *net;
    void *custom_data;
} dap_chain_rpc_consensus_params_t;

typedef int (*dap_chain_rpc_consensus_callback_t)(dap_chain_rpc_consensus_params_t *params, void *user_data);

/**
 * @brief Storage Type RPC callback types
 * @details Used to eliminate net → type_blocks dependency
 *          Replaces direct #include "dap_chain_type_blocks.h" with callback pattern
 */
typedef struct dap_chain_rpc_storage_params {
    dap_chain_t *chain;
    dap_chain_net_t *net;
    dap_hash_fast_t *block_hash;
    void *custom_data;
} dap_chain_rpc_storage_params_t;

typedef int (*dap_chain_rpc_storage_callback_t)(dap_chain_rpc_storage_params_t *params, void *user_data);

/**
 * @brief Service RPC callback types
 * @details Used to eliminate net → services (stake, etc) dependency
 *          Replaces direct #include "dap_chain_net_srv_stake_pos_delegate.h" with callback pattern
 */
typedef struct dap_chain_rpc_service_params {
    dap_chain_t *chain;
    dap_chain_net_t *net;
    const char *service_name;
    void *custom_data;
} dap_chain_rpc_service_params_t;

typedef int (*dap_chain_rpc_service_callback_t)(dap_chain_rpc_service_params_t *params, void *user_data);

/**
 * @brief Wallet operation callback types
 * @details Used to eliminate cyclic dependencies with wallet module
 */
typedef struct dap_chain_rpc_wallet_params {
    dap_chain_net_t *net;
    const char *wallet_name;
    uint256_t value;
    void *custom_data;
} dap_chain_rpc_wallet_params_t;

typedef int (*dap_chain_rpc_wallet_callback_t)(dap_chain_rpc_wallet_params_t *params, void *user_data);

/**
 * @brief Transaction notification callback types
 * @details Used for transaction notifications without cyclic dependencies
 */
typedef struct dap_chain_rpc_tx_notify_params {
    dap_chain_net_t *net;
    dap_chain_datum_t *tx_datum;
    dap_hash_fast_t *tx_hash;
    dap_ledger_t *ledger;
    void *custom_data;
} dap_chain_rpc_tx_notify_params_t;

typedef void (*dap_chain_rpc_tx_notify_callback_t)(dap_chain_rpc_tx_notify_params_t *params, void *user_data);

/**
 * @brief RPC Callback Registry
 * @details Thread-safe registry for all types of RPC callbacks
 */
typedef struct dap_chain_rpc_callbacks {
    // Consensus callbacks
    dap_chain_rpc_consensus_callback_t consensus_callback;
    void *consensus_user_data;
    
    // Storage type callbacks
    dap_chain_rpc_storage_callback_t storage_callback;
    void *storage_user_data;
    
    // Service callbacks
    dap_chain_rpc_service_callback_t service_callback;
    void *service_user_data;
    
    // Wallet callbacks
    dap_chain_rpc_wallet_callback_t wallet_callback;
    void *wallet_user_data;
    
    // Transaction notification callbacks
    dap_chain_rpc_tx_notify_callback_t tx_notify_callback;
    void *tx_notify_user_data;
    
    // Thread safety
    pthread_rwlock_t rwlock;
} dap_chain_rpc_callbacks_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize callback registry
 * @return 0 on success, negative on error
 */
int dap_chain_rpc_callbacks_init(void);

/**
 * @brief Deinitialize callback registry
 */
void dap_chain_rpc_callbacks_deinit(void);

/**
 * @brief Register consensus callback
 * @param callback Consensus callback function
 * @param user_data User data to pass to callback
 * @return 0 on success, negative on error
 * 
 * @note Thread-safe
 * @note Registered by consensus/esbocs module in its init()
 */
int dap_chain_rpc_callbacks_register_consensus(
    dap_chain_rpc_consensus_callback_t callback,
    void *user_data
);

/**
 * @brief Call consensus callback
 * @param params Parameters for callback
 * @return Result from callback or -1 if not registered
 * 
 * @note Thread-safe
 * @note Called by net module instead of direct include of esbocs
 */
int dap_chain_rpc_callbacks_notify_consensus(dap_chain_rpc_consensus_params_t *params);

/**
 * @brief Register storage type callback
 * @param callback Storage callback function
 * @param user_data User data to pass to callback
 * @return 0 on success, negative on error
 * 
 * @note Thread-safe
 * @note Registered by type/blocks module in its init()
 */
int dap_chain_rpc_callbacks_register_storage(
    dap_chain_rpc_storage_callback_t callback,
    void *user_data
);

/**
 * @brief Вызов storage type callback
 * @param params Parameters for callback
 * @return Result from callback or -1 if not registered
 * 
 * @note Thread-safe
 * @note Вызывается модулем net вместо прямого include type_blocks
 */
int dap_chain_rpc_callbacks_notify_storage(dap_chain_rpc_storage_params_t *params);

/**
 * @brief Регистрация service callback
 * @param callback Service callback function
 * @param user_data User data to pass to callback
 * @return 0 on success, negative on error
 * 
 * @note Thread-safe
 * @note Регистрируется модулем service/stake в своём init()
 */
int dap_chain_rpc_callbacks_register_service(
    dap_chain_rpc_service_callback_t callback,
    void *user_data
);

/**
 * @brief Call service callback
 * @param params Parameters for callback
 * @return Result from callback or -1 if not registered
 * 
 * @note Thread-safe
 * @note Called by net module instead of direct include of stake
 */
int dap_chain_rpc_callbacks_notify_service(dap_chain_rpc_service_params_t *params);

/**
 * @brief Register wallet callback
 * @param callback Wallet callback function
 * @param user_data User data to pass to callback
 * @return 0 on success, negative on error
 * 
 * @note Thread-safe
 */
int dap_chain_rpc_callbacks_register_wallet(
    dap_chain_rpc_wallet_callback_t callback,
    void *user_data
);

/**
 * @brief Вызов wallet callback
 * @param params Parameters for callback
 * @return Result from callback or -1 if not registered
 * 
 * @note Thread-safe
 */
int dap_chain_rpc_callbacks_notify_wallet(dap_chain_rpc_wallet_params_t *params);

/**
 * @brief Регистрация TX notification callback
 * @param callback TX notification callback function
 * @param user_data User data to pass to callback
 * @return 0 on success, negative on error
 * 
 * @note Thread-safe
 */
int dap_chain_rpc_callbacks_register_tx_notify(
    dap_chain_rpc_tx_notify_callback_t callback,
    void *user_data
);

/**
 * @brief Call TX notification callback
 * @param params Parameters for callback
 * 
 * @note Thread-safe
 * @note Can be called by multiple modules simultaneously
 */
void dap_chain_rpc_callbacks_notify_tx(dap_chain_rpc_tx_notify_params_t *params);

#ifdef __cplusplus
}
#endif

/**
 * @example Usage in net module (dap_chain_node.c)
 * 
 * Before:
 *   #include "dap_chain_cs_esbocs.h"
 *   dap_chain_cs_esbocs_some_function(chain);
 * 
 * After:
 *   #include "dap_chain_rpc_callbacks.h"
 *   dap_chain_rpc_consensus_params_t params = { .chain = chain, .net = net };
 *   dap_chain_rpc_callbacks_notify_consensus(&params);
 * 
 * @example Usage in esbocs module (dap_chain_cs_esbocs.c)
 * 
 * In init function:
 *   dap_chain_rpc_callbacks_register_consensus(my_consensus_handler, NULL);
 * 
 * Where my_consensus_handler:
 *   int my_consensus_handler(dap_chain_rpc_consensus_params_t *params, void *user_data) {
 *       // Process consensus operations
 *       return 0;
 *   }
 */
