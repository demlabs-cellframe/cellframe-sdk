/**
 * @file test_dex_fixtures.h
 * @brief Minimal DEX test fixtures
 * @details Helper functions for DEX testing - direct whitelist/fee manipulation
 * @date 2025-10-24
 */

#pragma once

#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "test_ledger_fixtures.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Add trading pair to whitelist (BYPASS decrees for testing)
 * @param a_net_id Network ID
 * @param a_base_ticker Base token ticker
 * @param a_quote_ticker Quote token ticker
 * @return 0 on success, error code otherwise
 * @note This function directly manipulates internal DEX structures for testing
 */
int test_dex_add_pair_direct(
    dap_chain_net_id_t a_net_id,
    const char *a_base_ticker,
    const char *a_quote_ticker
);

/**
 * @brief Set fee policy for pair (BYPASS decrees for testing)
 * @param a_net_id Network ID
 * @param a_base_ticker Base token ticker (NULL for all pairs)
 * @param a_quote_ticker Quote token ticker (NULL for all pairs)
 * @param a_fee_percent Fee percentage (0-100)
 * @return 0 on success, error code otherwise
 * @note This function directly manipulates internal DEX structures for testing
 */
int test_dex_set_fee_direct(
    dap_chain_net_id_t a_net_id,
    const char *a_base_ticker,
    const char *a_quote_ticker,
    uint8_t a_fee_percent
);

#ifdef __cplusplus
}
#endif




