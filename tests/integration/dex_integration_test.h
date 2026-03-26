/**
 * @file dex_integration_test.h
 * @brief DEX Integration Tests - Header
 * @author Cellframe Development Team
 * @date 2025
 */

#ifndef DAP_CHAIN_NET_SRV_DEX_INTEGRATION_TEST_H
#define DAP_CHAIN_NET_SRV_DEX_INTEGRATION_TEST_H

#include "dap_common.h"

/**
 * @brief Run all DEX integration tests
 * @details Executes comprehensive test suite covering:
 * - Basic operations (order creation, purchase, cancel)
 * - Matching logic (multi-order, partial fills, leftovers)
 * - MIN_FILL policies (AON, percentage, dust)
 * - Order updates (rate, value, immutables)
 * - Leftover handling (seller/buyer leftovers, cache)
 * - Fee mechanics (service fee, NATIVE fee, waiver, aggregation)
 * - Self-purchase scenarios (full, partial, rounding)
 * - Cache consistency (add, update, remove, reorg)
 * - Verifier validation (leak detection, baseline)
 * - Edge cases (dust, uint256 boundaries, zero values, expired orders)
 * - Advanced scenarios (cross-pair isolation, multi-hop, rate edge cases, whitelist/fee changes)
 * - Concurrency & stress (race conditions, large orderbook, memory leaks, extreme values)
 */
void dap_chain_net_srv_dex_integration_tests_run(void);

#endif // DAP_CHAIN_NET_SRV_DEX_INTEGRATION_TEST_H

