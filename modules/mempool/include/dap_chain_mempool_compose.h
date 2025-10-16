/**
 * @file dap_chain_mempool_compose.h
 * @brief Mempool transaction compose API
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_tx_compose.h"

// Forward declarations
typedef struct dap_chain_tx_compose_config dap_chain_tx_compose_config_t;
typedef struct dap_chain_addr dap_chain_addr_t;
typedef struct dap_pkey dap_pkey_t;

// Error codes for mempool compose operations
typedef enum {
    TX_COND_CREATE_COMPOSE_ERROR_INVALID_FEE = 1,
    TX_COND_CREATE_COMPOSE_ERROR_INVALID_SERVICE_UID,
    TX_COND_CREATE_COMPOSE_ERROR_INVALID_UNIT,
    TX_COND_CREATE_COMPOSE_ERROR_INVALID_VALUE,
    TX_COND_CREATE_COMPOSE_ERROR_WALLET_OPEN_FAILED,
    TX_COND_CREATE_COMPOSE_ERROR_CERT_NOT_FOUND,
    TX_COND_CREATE_COMPOSE_ERROR_INVALID_CERT_KEY,
    TX_COND_CREATE_COMPOSE_ERROR_NATIVE_TOKEN_REQUIRED,
    TX_COND_CREATE_COMPOSE_ERROR_NOT_ENOUGH_FUNDS,
    TX_COND_CREATE_COMPOSE_ERROR_COND_OUTPUT_FAILED,
    TX_COND_CREATE_COMPOSE_ERROR_COIN_BACK_FAILED
} dap_tx_cond_create_compose_error_t;

/**
 * @brief Create conditional transaction for mempool
 */
dap_chain_datum_tx_t* dap_chain_mempool_compose_tx_create_cond(
    dap_chain_addr_t *a_wallet_addr, 
    dap_pkey_t *a_key_cond,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value, 
    uint256_t a_value_per_unit_max,
    dap_chain_net_srv_price_unit_uid_t a_unit, 
    dap_chain_srv_uid_t a_srv_uid,
    uint256_t a_value_fee, 
    const void *a_cond,
    size_t a_cond_size, 
    dap_chain_tx_compose_config_t *a_config);

