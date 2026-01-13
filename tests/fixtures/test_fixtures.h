/*
 * Common test fixtures for Cellframe SDK
 * Header file for shared test utilities
 */

#pragma once

#include "dap_common.h"
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct dap_chain_addr dap_chain_addr_t;

// ===== NETWORK FIXTURES =====

/**
 * @brief Create a test network
 * @param a_net_name Network name
 * @param a_net_id Network ID
 * @return Created network or NULL on error
 */
dap_chain_net_t *test_network_create(const char *a_net_name, uint64_t a_net_id);

/**
 * @brief Delete a test network
 * @param a_net Network to delete
 */
void test_network_delete(dap_chain_net_t *a_net);

// ===== DATA GENERATORS =====

/**
 * @brief Generate deterministic test hash
 * @param a_seed Seed value
 * @param a_hash Output hash
 */
void test_hash_generate(uint32_t a_seed, dap_hash_fast_t *a_hash);

/**
 * @brief Generate test address
 * @param a_seed Seed value
 * @param a_addr Output address
 */
void test_addr_generate(uint32_t a_seed, dap_chain_addr_t *a_addr);

#ifdef __cplusplus
}
#endif
