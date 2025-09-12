/*
 * Complex Wallet Application Header
 *
 * Interface definitions for advanced CellFrame SDK wallet operations
 */

#pragma once

#include "dap_common.h"
#include "dap_chain_wallet.h"
#include "dap_chain_tx_compose.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the wallet application
 * @param net_name Network name (e.g., "Backbone", "KelVPN")
 * @return 0 on success, -1 on error
 */
int wallet_init(const char *net_name);

/**
 * @brief Create a new wallet with generated keys
 * @param wallet_name Name for the new wallet
 * @return 0 on success, -1 on error
 */
int wallet_create(const char *wallet_name);

/**
 * @brief Load existing wallet from certificate file
 * @param wallet_name Name of the wallet to load
 * @return 0 on success, -1 on error
 */
int wallet_load(const char *wallet_name);

/**
 * @brief Get current wallet balance
 * @return 0 on success, -1 on error
 */
int wallet_get_balance(void);

/**
 * @brief Send transaction to specified address
 * @param recipient_address Recipient wallet address
 * @param amount Amount to send (as string)
 * @param token_ticker Token ticker (e.g., "CELL", "KEL")
 * @return 0 on success, -1 on error
 */
int wallet_send_transaction(const char *recipient_address,
                          const char *amount,
                          const char *token_ticker);

/**
 * @brief Get transaction history for current wallet
 * @return 0 on success, -1 on error
 */
int wallet_get_history(void);

/**
 * @brief Main wallet processing loop with menu
 * @return 0 on success, -1 on error
 */
int wallet_process(void);

/**
 * @brief Cleanup wallet resources and modules
 */
void wallet_cleanup(void);

#ifdef __cplusplus
}
#endif


