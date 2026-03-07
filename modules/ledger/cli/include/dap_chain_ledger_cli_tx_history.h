/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2019-2025
 * All rights reserved.
 *
 * This file is part of DAP (Distributed Applications Platform) the open source project
 *
 * DAP is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DAP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "dap_json.h"
#include "dap_chain.h"
#include "dap_chain_common.h"
#include "dap_chain_ledger.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Transaction history CLI command handler
 * @details Implements 'tx history' CLI subcommand:
 *          - tx history -addr <addr> - history for address
 *          - tx history -w <wallet> - history for wallet
 *          - tx history -tx <hash> - specific transaction info
 *          - tx history -all - all transactions
 *          - tx history -count - transaction count
 * 
 * @param a_argc Argument count
 * @param a_argv Argument values
 * @param a_json_arr_reply JSON array for reply
 * @param a_version API version
 * @return 0 on success, error code on failure
 */
int com_tx_history(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version);

/**
 * @brief Get transaction history by hash
 * @param a_json_arr_reply JSON reply array
 * @param a_tx_hash Transaction hash
 * @param a_chain Chain to search in
 * @param a_hash_out_type Output hash format ("hex" or "base58")
 * @param a_ledger Ledger instance
 * @param a_version API version
 * @return JSON object with TX info or NULL on error
 */
dap_json_t *dap_db_history_tx(dap_json_t *a_json_arr_reply,
                              dap_chain_hash_fast_t *a_tx_hash,
                              dap_chain_t *a_chain,
                              const char *a_hash_out_type,
                              dap_ledger_t *a_ledger,
                              int a_version);

/**
 * @brief Get transaction history for address
 * @param a_json_arr_reply JSON reply array
 * @param a_addr Address to get history for
 * @param a_chain Chain to search in
 * @param a_ledger Ledger instance
 * @param a_hash_out_type Output hash format
 * @param a_addr_str Address string representation
 * @param json_obj_summary Summary JSON object to fill
 * @param a_limit Max results
 * @param a_offset Results offset
 * @param a_brief Brief output mode
 * @param a_srv Service filter
 * @param a_action Action filter
 * @param a_head Direction flag
 * @param a_version API version
 * @return JSON array with TX history or NULL on error
 */
dap_json_t *dap_db_history_addr(dap_json_t *a_json_arr_reply,
                                dap_chain_addr_t *a_addr,
                                dap_chain_t *a_chain,
                                dap_ledger_t *a_ledger,
                                const char *a_hash_out_type,
                                const char *a_addr_str,
                                dap_json_t *json_obj_summary,
                                size_t a_limit, size_t a_offset,
                                bool a_brief, const char *a_srv,
                                dap_chain_tx_tag_action_type_t a_action,
                                bool a_head, int a_version);

/**
 * @brief Get all transactions history
 * @param a_json_arr_reply JSON reply array
 * @param a_chain Chain to search in
 * @param a_ledger Ledger instance
 * @param a_hash_out_type Output hash format
 * @param json_obj_summary Summary JSON object
 * @param a_limit Max results
 * @param a_offset Results offset
 * @param out_brief Brief output mode
 * @param a_srv Service filter
 * @param a_action Action filter
 * @param a_head Direction flag
 * @param a_version API version
 * @return JSON array with TX history or NULL on error
 */
dap_json_t *dap_db_history_tx_all(dap_json_t *a_json_arr_reply,
                                  dap_chain_t *a_chain,
                                  dap_ledger_t *a_ledger,
                                  const char *a_hash_out_type,
                                  dap_json_t *json_obj_summary,
                                  size_t a_limit, size_t a_offset,
                                  bool out_brief, const char *a_srv,
                                  dap_chain_tx_tag_action_type_t a_action,
                                  bool a_head, int a_version);

/**
 * @brief Initialize TX history CLI module
 * @return 0 on success, negative error code on failure
 */
int dap_chain_ledger_cli_tx_history_init(void);

/**
 * @brief Deinitialize TX history CLI module
 */
void dap_chain_ledger_cli_tx_history_deinit(void);

#ifdef __cplusplus
}
#endif
