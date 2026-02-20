/**
 * @file test_cli_wallet_mocked.c
 * @brief Unit tests for wallet CLI with full mocking support
 * 
 * This test file uses DAP Mock Framework to mock wallet/network dependencies
 * allowing full CLI command execution with controlled, predictable behavior.
 * 
 * Tests verify:
 * 1. CLI command registration and invocation
 * 2. JSON output structure and field names
 * 3. Correct handling of various wallet states
 * 4. API version differences (v1 vs v2)
 * 
 * @author Cellframe Team
 * @copyright DeM Labs Inc. 2025
 * @license GPL-3.0
 */

#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_test.h"
#include "dap_mock.h"
#include "dap_json.h"
#include "dap_strfuncs.h"
#include "dap_cli_server.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_cli.h"
#include "dap_chain_wallet_internal.h"
#include "dap_chain_net.h"
#include "dap_chain_ledger.h"
#include "dap_chain_wallet_shared.h"
#include "dap_chain_wallet_cache.h"
#include "dap_sign.h"

#define LOG_TAG "test_cli_wallet_mocked"

// ============================================================================
// MOCK DECLARATIONS
// ============================================================================

// Wallet path mock
DAP_MOCK_DECLARE(dap_chain_wallet_get_path, {
    .return_value.ptr = (void*)"/tmp/test_wallets"
});

// Wallet open mock - will be configured per test
DAP_MOCK_DECLARE(dap_chain_wallet_open, {
    .return_value.ptr = NULL
});

// Wallet close mock
DAP_MOCK_DECLARE(dap_chain_wallet_close, { });

// Wallet signature check mock
DAP_MOCK_DECLARE(dap_chain_wallet_check_sign, {
    .return_value.ptr = (void*)""
});

// Wallet address mock
DAP_MOCK_DECLARE(dap_chain_wallet_get_addr, {
    .return_value.ptr = NULL
});

// Wallet create mock
DAP_MOCK_DECLARE(dap_chain_wallet_create_with_seed_multi, {
    .return_value.ptr = NULL
});

// Notify server mock - prevents crashes when notify server is not initialized
DAP_MOCK_DECLARE(dap_notify_server_send, {
    .return_value.i = 0
});

// Network mocks - for wallet info command
DAP_MOCK_DECLARE(dap_chain_net_by_name, {
    .return_value.ptr = NULL
});

DAP_MOCK_DECLARE(dap_chain_net_by_id, {
    .return_value.ptr = NULL
});

// Ledger mocks - for wallet info command
DAP_MOCK_DECLARE(dap_ledger_addr_get_token_ticker_all, { });

DAP_MOCK_DECLARE(dap_ledger_get_locked_values, {
    .return_value.ptr = NULL
});

// Shared wallet mock
DAP_MOCK_DECLARE(dap_chain_wallet_shared_get_tx_hashes_json, {
    .return_value.ptr = NULL
});

// Wallet activate/deactivate mocks
DAP_MOCK_DECLARE(dap_chain_wallet_activate, {
    .return_value.i = 0
});

DAP_MOCK_DECLARE(dap_chain_wallet_deactivate, {
    .return_value.i = 0
});

// Wallet save mock (for convert command)
DAP_MOCK_DECLARE(dap_chain_wallet_save, {
    .return_value.i = 0
});

// Wallet cache mocks (for outputs command)
DAP_MOCK_DECLARE(dap_chain_wallet_cache_tx_find_outs_mempool_check, {
    .return_value.i = 0
});

DAP_MOCK_DECLARE(dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check, {
    .return_value.i = 0
});

// Ledger conditional outputs mock (for outputs -cond command)
DAP_MOCK_DECLARE(dap_ledger_get_list_tx_cond_outs, {
    .return_value.ptr = NULL
});

// Address from string mock (for find command)
DAP_MOCK_DECLARE(dap_chain_addr_from_str, {
    .return_value.ptr = NULL
});

// NOTE: dap_config_get_item_str is a macro, can't mock directly
// Instead, wallet_get_path is used to control the path

// ============================================================================
// MOCK STRUCTURES
// ============================================================================

/**
 * @brief Mock network structure for wallet info tests
 */
static dap_chain_net_t s_mock_net = {
    .pub = {
        .id = { .uint64 = 0x0000000000000001 },
        .name = "test_net",
        .ledger = NULL,
        .native_ticker = "TEST"
    }
};

/**
 * @brief Mock wallet address for wallet info tests
 */
static dap_chain_addr_t s_mock_addr = {
    .net_id = { .uint64 = 0x0000000000000001 },
    .sig_type = { .type = SIG_TYPE_DILITHIUM },
    .data = { .hash_fast = { 0 } }
};

// ============================================================================
// LINKER WRAPPER IMPLEMENTATIONS
// ============================================================================
// These functions are called by the linker when --wrap is used.
// They check if mock is enabled and return mock value, otherwise call real.

// Declare real functions (provided by linker with --wrap)
extern const char* __real_dap_chain_wallet_get_path(dap_config_t *a_config);
extern dap_chain_wallet_t* __real_dap_chain_wallet_open(const char *a_wallet_name, 
                                                         const char *a_wallets_path, 
                                                         unsigned int *a_out_res);
extern void __real_dap_chain_wallet_close(dap_chain_wallet_t *a_wallet);
extern const char* __real_dap_chain_wallet_check_sign(dap_chain_wallet_t *a_wallet);
extern dap_chain_addr_t* __real_dap_chain_wallet_get_addr(dap_chain_wallet_t *a_wallet,
                                                           dap_chain_net_id_t a_net_id);
extern dap_chain_wallet_t* __real_dap_chain_wallet_create_with_seed_multi(const char *a_wallet_name,
                                                                           const char *a_wallets_path,
                                                                           const dap_sign_type_t *a_sig_types,
                                                                           size_t a_sig_count,
                                                                           const void *a_seed,
                                                                           size_t a_seed_size,
                                                                           const char *a_pass);
extern int __real_dap_notify_server_send(const char *a_data);
extern dap_chain_net_t* __real_dap_chain_net_by_name(const char *a_name);
extern dap_chain_net_t* __real_dap_chain_net_by_id(dap_chain_net_id_t a_id);
extern void __real_dap_ledger_addr_get_token_ticker_all(dap_ledger_t *a_ledger, 
                                                         dap_chain_addr_t *a_addr,
                                                         char ***a_tickers, 
                                                         size_t *a_tickers_size);
extern dap_ledger_locked_out_t* __real_dap_ledger_get_locked_values(dap_ledger_t *a_ledger, 
                                                                      dap_chain_addr_t *a_addr);
extern dap_json_t* __real_dap_chain_wallet_shared_get_tx_hashes_json(dap_hash_fast_t *a_pkey_hash, 
                                                                       const char *a_net_name);
extern int __real_dap_chain_wallet_activate(const char *a_name, ssize_t a_name_len, 
                                             const char *a_path, const char *a_pass, 
                                             ssize_t a_pass_len, unsigned a_ttl);
extern int __real_dap_chain_wallet_deactivate(const char *a_name, ssize_t a_name_len);
extern int __real_dap_chain_wallet_save(dap_chain_wallet_t *a_wallet, const char *a_pass);
extern int __real_dap_chain_wallet_cache_tx_find_outs_mempool_check(dap_chain_net_t *a_net, 
                                                    const char *a_token_ticker, 
                                                    const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, 
                                                    uint256_t *a_value_transfer,
                                                    bool a_mempool_check);
extern int __real_dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check(dap_chain_net_t *a_net, 
                                                    const char *a_token_ticker, 
                                                    const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, 
                                                    uint256_t a_value_needed, 
                                                    uint256_t *a_value_transfer,
                                                    bool a_mempool_check);
extern dap_list_t* __real_dap_ledger_get_list_tx_cond_outs(dap_ledger_t *a_ledger, 
                                                            dap_chain_tx_out_cond_subtype_t a_cond_type,
                                                            const char *a_token_ticker, 
                                                            dap_chain_addr_t *a_addr);
extern dap_chain_addr_t* __real_dap_chain_addr_from_str(const char *a_str);

/**
 * @brief Wrapper for dap_chain_wallet_get_path
 */
const char* __wrap_dap_chain_wallet_get_path(dap_config_t *a_config)
{
    if (g_mock_dap_chain_wallet_get_path && g_mock_dap_chain_wallet_get_path->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_get_path, NULL, 0,
                             g_mock_dap_chain_wallet_get_path->return_value.ptr);
        return (const char*)g_mock_dap_chain_wallet_get_path->return_value.ptr;
    }
    return __real_dap_chain_wallet_get_path(a_config);
}

/**
 * @brief Wrapper for dap_chain_wallet_open
 */
dap_chain_wallet_t* __wrap_dap_chain_wallet_open(const char *a_wallet_name,
                                                   const char *a_wallets_path,
                                                   unsigned int *a_out_res)
{
    if (g_mock_dap_chain_wallet_open && g_mock_dap_chain_wallet_open->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_open, NULL, 0,
                             g_mock_dap_chain_wallet_open->return_value.ptr);
        if (a_out_res)
            *a_out_res = 0;
        return (dap_chain_wallet_t*)g_mock_dap_chain_wallet_open->return_value.ptr;
    }
    return __real_dap_chain_wallet_open(a_wallet_name, a_wallets_path, a_out_res);
}

/**
 * @brief Wrapper for dap_chain_wallet_close
 */
void __wrap_dap_chain_wallet_close(dap_chain_wallet_t *a_wallet)
{
    if (g_mock_dap_chain_wallet_close && g_mock_dap_chain_wallet_close->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_close, NULL, 0, NULL);
        return;
    }
    __real_dap_chain_wallet_close(a_wallet);
}

/**
 * @brief Wrapper for dap_chain_wallet_check_sign
 */
const char* __wrap_dap_chain_wallet_check_sign(dap_chain_wallet_t *a_wallet)
{
    if (g_mock_dap_chain_wallet_check_sign && g_mock_dap_chain_wallet_check_sign->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_check_sign, NULL, 0,
                             g_mock_dap_chain_wallet_check_sign->return_value.ptr);
        return (const char*)g_mock_dap_chain_wallet_check_sign->return_value.ptr;
    }
    return __real_dap_chain_wallet_check_sign(a_wallet);
}

/**
 * @brief Wrapper for dap_chain_wallet_get_addr
 * 
 * Note: Returns a dynamically allocated copy of the mock address,
 * since the caller (wallet CLI) will call DAP_DELETE on it.
 */
dap_chain_addr_t* __wrap_dap_chain_wallet_get_addr(dap_chain_wallet_t *a_wallet,
                                                     dap_chain_net_id_t a_net_id)
{
    if (g_mock_dap_chain_wallet_get_addr && g_mock_dap_chain_wallet_get_addr->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_get_addr, NULL, 0,
                             g_mock_dap_chain_wallet_get_addr->return_value.ptr);
        // Return a heap-allocated copy since caller will DAP_DELETE it
        dap_chain_addr_t *l_src = (dap_chain_addr_t*)g_mock_dap_chain_wallet_get_addr->return_value.ptr;
        if (l_src) {
            dap_chain_addr_t *l_copy = DAP_NEW(dap_chain_addr_t);
            if (l_copy) {
                memcpy(l_copy, l_src, sizeof(dap_chain_addr_t));
            }
            return l_copy;
        }
        return NULL;
    }
    return __real_dap_chain_wallet_get_addr(a_wallet, a_net_id);
}

/**
 * @brief Wrapper for dap_chain_wallet_create_with_seed_multi
 */
dap_chain_wallet_t* __wrap_dap_chain_wallet_create_with_seed_multi(const char *a_wallet_name,
                                                                     const char *a_wallets_path,
                                                                     const dap_sign_type_t *a_sig_types,
                                                                     size_t a_sig_count,
                                                                     const void *a_seed,
                                                                     size_t a_seed_size,
                                                                     const char *a_pass)
{
    if (g_mock_dap_chain_wallet_create_with_seed_multi && 
        g_mock_dap_chain_wallet_create_with_seed_multi->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_create_with_seed_multi, NULL, 0,
                             g_mock_dap_chain_wallet_create_with_seed_multi->return_value.ptr);
        return (dap_chain_wallet_t*)g_mock_dap_chain_wallet_create_with_seed_multi->return_value.ptr;
    }
    return __real_dap_chain_wallet_create_with_seed_multi(a_wallet_name, a_wallets_path, 
                                                           a_sig_types, a_sig_count,
                                                           a_seed, a_seed_size, a_pass);
}

/**
 * @brief Wrapper for dap_notify_server_send
 * 
 * Mocks the notify server to prevent crashes when server is not initialized.
 */
int __wrap_dap_notify_server_send(const char *a_data)
{
    if (g_mock_dap_notify_server_send && g_mock_dap_notify_server_send->enabled) {
        dap_mock_record_call(g_mock_dap_notify_server_send, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_notify_server_send->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_notify_server_send called with %zu bytes", 
               a_data ? strlen(a_data) : 0);
        return g_mock_dap_notify_server_send->return_value.i;
    }
    return __real_dap_notify_server_send(a_data);
}

/**
 * @brief Wrapper for dap_chain_net_by_name
 */
dap_chain_net_t* __wrap_dap_chain_net_by_name(const char *a_name)
{
    if (g_mock_dap_chain_net_by_name && g_mock_dap_chain_net_by_name->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_by_name, NULL, 0,
                             g_mock_dap_chain_net_by_name->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_net_by_name('%s') called", a_name ? a_name : "(null)");
        return (dap_chain_net_t*)g_mock_dap_chain_net_by_name->return_value.ptr;
    }
    return __real_dap_chain_net_by_name(a_name);
}

/**
 * @brief Wrapper for dap_chain_net_by_id
 */
dap_chain_net_t* __wrap_dap_chain_net_by_id(dap_chain_net_id_t a_id)
{
    if (g_mock_dap_chain_net_by_id && g_mock_dap_chain_net_by_id->enabled) {
        dap_mock_record_call(g_mock_dap_chain_net_by_id, NULL, 0,
                             g_mock_dap_chain_net_by_id->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_net_by_id(0x%016llx) called", 
               (unsigned long long)a_id.uint64);
        return (dap_chain_net_t*)g_mock_dap_chain_net_by_id->return_value.ptr;
    }
    return __real_dap_chain_net_by_id(a_id);
}

/**
 * @brief Wrapper for dap_ledger_addr_get_token_ticker_all
 */
void __wrap_dap_ledger_addr_get_token_ticker_all(dap_ledger_t *a_ledger, 
                                                   dap_chain_addr_t *a_addr,
                                                   char ***a_tickers, 
                                                   size_t *a_tickers_size)
{
    if (g_mock_dap_ledger_addr_get_token_ticker_all && 
        g_mock_dap_ledger_addr_get_token_ticker_all->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_addr_get_token_ticker_all, NULL, 0, NULL);
        log_it(L_DEBUG, "MOCK: dap_ledger_addr_get_token_ticker_all called");
        // Return empty list
        if (a_tickers) *a_tickers = NULL;
        if (a_tickers_size) *a_tickers_size = 0;
        return;
    }
    __real_dap_ledger_addr_get_token_ticker_all(a_ledger, a_addr, a_tickers, a_tickers_size);
}

/**
 * @brief Wrapper for dap_ledger_get_locked_values
 */
dap_ledger_locked_out_t* __wrap_dap_ledger_get_locked_values(dap_ledger_t *a_ledger, 
                                                               dap_chain_addr_t *a_addr)
{
    if (g_mock_dap_ledger_get_locked_values && g_mock_dap_ledger_get_locked_values->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_get_locked_values, NULL, 0,
                             g_mock_dap_ledger_get_locked_values->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_ledger_get_locked_values called");
        return (dap_ledger_locked_out_t*)g_mock_dap_ledger_get_locked_values->return_value.ptr;
    }
    return __real_dap_ledger_get_locked_values(a_ledger, a_addr);
}

/**
 * @brief Wrapper for dap_chain_wallet_shared_get_tx_hashes_json
 */
dap_json_t* __wrap_dap_chain_wallet_shared_get_tx_hashes_json(dap_hash_fast_t *a_pkey_hash, 
                                                                const char *a_net_name)
{
    if (g_mock_dap_chain_wallet_shared_get_tx_hashes_json && 
        g_mock_dap_chain_wallet_shared_get_tx_hashes_json->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_shared_get_tx_hashes_json, NULL, 0,
                             g_mock_dap_chain_wallet_shared_get_tx_hashes_json->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_wallet_shared_get_tx_hashes_json called");
        return (dap_json_t*)g_mock_dap_chain_wallet_shared_get_tx_hashes_json->return_value.ptr;
    }
    return __real_dap_chain_wallet_shared_get_tx_hashes_json(a_pkey_hash, a_net_name);
}

/**
 * @brief Wrapper for dap_chain_wallet_activate
 */
int __wrap_dap_chain_wallet_activate(const char *a_name, ssize_t a_name_len, 
                                      const char *a_path, const char *a_pass, 
                                      ssize_t a_pass_len, unsigned a_ttl)
{
    if (g_mock_dap_chain_wallet_activate && g_mock_dap_chain_wallet_activate->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_activate, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_wallet_activate->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_chain_wallet_activate('%s', ttl=%u) called", 
               a_name ? a_name : "(null)", a_ttl);
        return g_mock_dap_chain_wallet_activate->return_value.i;
    }
    return __real_dap_chain_wallet_activate(a_name, a_name_len, a_path, a_pass, a_pass_len, a_ttl);
}

/**
 * @brief Wrapper for dap_chain_wallet_deactivate
 */
int __wrap_dap_chain_wallet_deactivate(const char *a_name, ssize_t a_name_len)
{
    if (g_mock_dap_chain_wallet_deactivate && g_mock_dap_chain_wallet_deactivate->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_deactivate, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_wallet_deactivate->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_chain_wallet_deactivate('%s') called", 
               a_name ? a_name : "(null)");
        return g_mock_dap_chain_wallet_deactivate->return_value.i;
    }
    return __real_dap_chain_wallet_deactivate(a_name, a_name_len);
}

/**
 * @brief Wrapper for dap_chain_wallet_save
 */
int __wrap_dap_chain_wallet_save(dap_chain_wallet_t *a_wallet, const char *a_pass)
{
    if (g_mock_dap_chain_wallet_save && g_mock_dap_chain_wallet_save->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_save, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_wallet_save->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_chain_wallet_save(wallet=%p, pass=%s) called", 
               (void*)a_wallet, a_pass ? "***" : "(null)");
        return g_mock_dap_chain_wallet_save->return_value.i;
    }
    return __real_dap_chain_wallet_save(a_wallet, a_pass);
}

/**
 * @brief Wrapper for dap_chain_wallet_cache_tx_find_outs_mempool_check
 */
int __wrap_dap_chain_wallet_cache_tx_find_outs_mempool_check(dap_chain_net_t *a_net, 
                                                    const char *a_token_ticker, 
                                                    const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, 
                                                    uint256_t *a_value_transfer,
                                                    bool a_mempool_check)
{
    if (g_mock_dap_chain_wallet_cache_tx_find_outs_mempool_check && 
        g_mock_dap_chain_wallet_cache_tx_find_outs_mempool_check->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_cache_tx_find_outs_mempool_check, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_wallet_cache_tx_find_outs_mempool_check->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_chain_wallet_cache_tx_find_outs_mempool_check(token=%s) called", 
               a_token_ticker ? a_token_ticker : "(null)");
        if (a_outs_list) *a_outs_list = NULL;
        if (a_value_transfer) *a_value_transfer = uint256_0;
        return g_mock_dap_chain_wallet_cache_tx_find_outs_mempool_check->return_value.i;
    }
    return __real_dap_chain_wallet_cache_tx_find_outs_mempool_check(a_net, a_token_ticker, a_addr, 
                                                                     a_outs_list, a_value_transfer, a_mempool_check);
}

/**
 * @brief Wrapper for dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check
 */
int __wrap_dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check(dap_chain_net_t *a_net, 
                                                    const char *a_token_ticker, 
                                                    const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, 
                                                    uint256_t a_value_needed, 
                                                    uint256_t *a_value_transfer,
                                                    bool a_mempool_check)
{
    if (g_mock_dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check && 
        g_mock_dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check->enabled) {
        dap_mock_record_call(g_mock_dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check, NULL, 0,
                             (void*)(intptr_t)g_mock_dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check->return_value.i);
        log_it(L_DEBUG, "MOCK: dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check(token=%s) called", 
               a_token_ticker ? a_token_ticker : "(null)");
        if (a_outs_list) *a_outs_list = NULL;
        if (a_value_transfer) *a_value_transfer = uint256_0;
        return g_mock_dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check->return_value.i;
    }
    return __real_dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check(a_net, a_token_ticker, a_addr, 
                                                                               a_outs_list, a_value_needed, 
                                                                               a_value_transfer, a_mempool_check);
}

/**
 * @brief Wrapper for dap_ledger_get_list_tx_cond_outs
 */
dap_list_t* __wrap_dap_ledger_get_list_tx_cond_outs(dap_ledger_t *a_ledger, 
                                                      dap_chain_tx_out_cond_subtype_t a_cond_type,
                                                      const char *a_token_ticker, 
                                                      dap_chain_addr_t *a_addr)
{
    if (g_mock_dap_ledger_get_list_tx_cond_outs && 
        g_mock_dap_ledger_get_list_tx_cond_outs->enabled) {
        dap_mock_record_call(g_mock_dap_ledger_get_list_tx_cond_outs, NULL, 0,
                             g_mock_dap_ledger_get_list_tx_cond_outs->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_ledger_get_list_tx_cond_outs(token=%s, cond_type=%d) called", 
               a_token_ticker ? a_token_ticker : "(null)", a_cond_type);
        return (dap_list_t*)g_mock_dap_ledger_get_list_tx_cond_outs->return_value.ptr;
    }
    return __real_dap_ledger_get_list_tx_cond_outs(a_ledger, a_cond_type, a_token_ticker, a_addr);
}

/**
 * @brief Wrapper for dap_chain_addr_from_str
 */
dap_chain_addr_t* __wrap_dap_chain_addr_from_str(const char *a_str)
{
    if (g_mock_dap_chain_addr_from_str && 
        g_mock_dap_chain_addr_from_str->enabled) {
        dap_mock_record_call(g_mock_dap_chain_addr_from_str, NULL, 0,
                             g_mock_dap_chain_addr_from_str->return_value.ptr);
        log_it(L_DEBUG, "MOCK: dap_chain_addr_from_str(str=%s) called", 
               a_str ? a_str : "(null)");
        return (dap_chain_addr_t*)g_mock_dap_chain_addr_from_str->return_value.ptr;
    }
    return __real_dap_chain_addr_from_str(a_str);
}

// ============================================================================
// TEST WALLET STRUCTURES
// ============================================================================

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Reset all mocks before each test
 */
static void s_reset_mocks(void)
{
    // Reset wallet mocks
    DAP_MOCK_RESET(dap_chain_wallet_get_path);
    DAP_MOCK_RESET(dap_chain_wallet_open);
    DAP_MOCK_RESET(dap_chain_wallet_close);
    DAP_MOCK_RESET(dap_chain_wallet_check_sign);
    DAP_MOCK_RESET(dap_chain_wallet_get_addr);
    DAP_MOCK_RESET(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_RESET(dap_notify_server_send);
    
    // Reset network/ledger mocks
    DAP_MOCK_RESET(dap_chain_net_by_name);
    DAP_MOCK_RESET(dap_chain_net_by_id);
    DAP_MOCK_RESET(dap_ledger_addr_get_token_ticker_all);
    DAP_MOCK_RESET(dap_ledger_get_locked_values);
    DAP_MOCK_RESET(dap_chain_wallet_shared_get_tx_hashes_json);
    
    // Reset activate/deactivate/save mocks
    DAP_MOCK_RESET(dap_chain_wallet_activate);
    DAP_MOCK_RESET(dap_chain_wallet_deactivate);
    DAP_MOCK_RESET(dap_chain_wallet_save);
    
    // Reset wallet cache/outputs mocks
    DAP_MOCK_RESET(dap_chain_wallet_cache_tx_find_outs_mempool_check);
    DAP_MOCK_RESET(dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check);
    DAP_MOCK_RESET(dap_ledger_get_list_tx_cond_outs);
    
    // Reset address mocks
    DAP_MOCK_RESET(dap_chain_addr_from_str);
    
    // Enable wallet mocks
    DAP_MOCK_ENABLE(dap_chain_wallet_get_path);
    DAP_MOCK_ENABLE(dap_chain_wallet_open);
    DAP_MOCK_ENABLE(dap_chain_wallet_close);
    DAP_MOCK_ENABLE(dap_chain_wallet_check_sign);
    DAP_MOCK_ENABLE(dap_chain_wallet_get_addr);
    DAP_MOCK_ENABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_ENABLE(dap_notify_server_send);
    
    // Enable network/ledger mocks
    DAP_MOCK_ENABLE(dap_chain_net_by_name);
    DAP_MOCK_ENABLE(dap_chain_net_by_id);
    DAP_MOCK_ENABLE(dap_ledger_addr_get_token_ticker_all);
    DAP_MOCK_ENABLE(dap_ledger_get_locked_values);
    DAP_MOCK_ENABLE(dap_chain_wallet_shared_get_tx_hashes_json);
    
    // Enable activate/deactivate/save mocks
    DAP_MOCK_ENABLE(dap_chain_wallet_activate);
    DAP_MOCK_ENABLE(dap_chain_wallet_deactivate);
    DAP_MOCK_ENABLE(dap_chain_wallet_save);
    
    // Enable wallet cache/outputs mocks
    DAP_MOCK_ENABLE(dap_chain_wallet_cache_tx_find_outs_mempool_check);
    DAP_MOCK_ENABLE(dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check);
    DAP_MOCK_ENABLE(dap_ledger_get_list_tx_cond_outs);
    
    // Enable address mocks
    DAP_MOCK_ENABLE(dap_chain_addr_from_str);
}

/**
 * @brief Execute CLI command by name
 */
static int s_execute_cli_command(const char *a_cmd_name, int a_argc, char **a_argv,
                                  dap_json_t *a_json_reply, int a_version)
{
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_find(a_cmd_name);
    if (!l_cmd || !l_cmd->func) {
        log_it(L_ERROR, "Command '%s' not found", a_cmd_name);
        return -100;
    }
    
    return l_cmd->func(a_argc, a_argv, a_json_reply, a_version);
}

// ============================================================================
// TESTS: Real CLI Command Execution
// ============================================================================

#define TEST_WALLETS_DIR "/tmp/test_wallets_cli"

/**
 * @brief Helper to create test directory
 */
static void s_create_test_dir(void)
{
    mkdir(TEST_WALLETS_DIR, 0755);
}

/**
 * @brief Helper to remove test wallet file
 */
static void s_remove_test_wallet(const char *a_wallet_name)
{
    char l_path[256];
    snprintf(l_path, sizeof(l_path), "%s/%s.dwallet", TEST_WALLETS_DIR, a_wallet_name);
    unlink(l_path);
}

/**
 * @brief Helper to check if wallet file exists
 */
static bool s_wallet_file_exists(const char *a_wallet_name)
{
    char l_path[256];
    snprintf(l_path, sizeof(l_path), "%s/%s.dwallet", TEST_WALLETS_DIR, a_wallet_name);
    FILE *l_file = fopen(l_path, "rb");
    if (l_file) {
        fclose(l_file);
        return true;
    }
    return false;
}

/**
 * @brief Helper to remove test directory
 */
static void s_cleanup_test_dir(void)
{
    rmdir(TEST_WALLETS_DIR);
}

/**
 * @brief Helper to create a wallet via CLI
 * 
 * @param a_wallet_name Wallet name to create
 * @return true on success, false on failure
 */
static bool s_create_wallet_cli(const char *a_wallet_name)
{
    // Remove any existing test wallet
    s_remove_test_wallet(a_wallet_name);
    
    // Prepare CLI arguments: "wallet new -w <name> -sign sig_dil"
    char *l_argv[] = {"wallet", "new", "-w", (char*)a_wallet_name, "-sign", "sig_dil", NULL};
    int l_argc = 6;
    
    // Create JSON reply
    dap_json_t *l_json_reply = dap_json_array_new();
    if (!l_json_reply) {
        return false;
    }
    
    // Execute CLI command
    int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "wallet new '%s' returned: %d", a_wallet_name, l_ret);
    
    // Print JSON result
    const char *l_json_str = dap_json_to_string(l_json_reply);
    if (l_json_str) {
        log_it(L_DEBUG, "wallet new JSON result: %s", l_json_str);
    }
    
    dap_json_object_free(l_json_reply);
    
    return (l_ret == 0) && s_wallet_file_exists(a_wallet_name);
}

/**
 * @brief Test wallet new CLI command with real file creation
 * 
 * This test:
 * 1. Creates a test directory
 * 2. Calls 'wallet new' via CLI to create two wallets
 * 3. Verifies the .dwallet files were created
 */
static void test_wallet_new_cli_real(void)
{
    dap_print_module_name("wallet new CLI (real files)");
    
    const char *l_wallet_name_1 = "cliTestWallet_1";
    const char *l_wallet_name_2 = "cliTestWallet_2";
    
    // Create test directory
    s_create_test_dir();
    
    // Setup mocks:
    // - wallet_get_path returns our test directory
    // - notify_server_send is mocked to prevent crash
    // - create_with_seed_multi is DISABLED (use real function)
    // - wallet_close is DISABLED (use real function)
    s_reset_mocks();
    
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Disable mocks that should use real implementation
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Create first wallet
    dap_assert(s_create_wallet_cli(l_wallet_name_1), "wallet 1 created");
    dap_assert(s_wallet_file_exists(l_wallet_name_1), "wallet 1 file exists");
    log_it(L_DEBUG, "Wallet file %s/%s.dwallet created successfully", 
           TEST_WALLETS_DIR, l_wallet_name_1);
    
    // Create second wallet
    dap_assert(s_create_wallet_cli(l_wallet_name_2), "wallet 2 created");
    dap_assert(s_wallet_file_exists(l_wallet_name_2), "wallet 2 file exists");
    log_it(L_DEBUG, "Wallet file %s/%s.dwallet created successfully", 
           TEST_WALLETS_DIR, l_wallet_name_2);
    
    // Verify notify mock was called (wallet creation triggers notification)
    int l_notify_count = DAP_MOCK_GET_CALL_COUNT(dap_notify_server_send);
    log_it(L_DEBUG, "notify_server_send mock calls: %d", l_notify_count);
    dap_assert(l_notify_count >= 2, "notify_server_send was called for both wallets");
    
    // NOTE: Do NOT cleanup here - wallet list test will use these wallets
    
    dap_pass_msg("wallet new CLI (real files) complete");
}

/**
 * @brief Test wallet list CLI command with real files
 * 
 * This test runs AFTER test_wallet_new_cli_real and verifies that
 * both created wallets appear in the list.
 */
static void test_wallet_list_cli_real(void)
{
    dap_print_module_name("wallet list CLI (real files)");
    
    const char *l_wallet_name_1 = "cliTestWallet_1";
    const char *l_wallet_name_2 = "cliTestWallet_2";
    
    // Verify wallet files exist from previous test
    dap_assert(s_wallet_file_exists(l_wallet_name_1), "test wallet 1 exists from previous test");
    dap_assert(s_wallet_file_exists(l_wallet_name_2), "test wallet 2 exists from previous test");
    
    // Setup mocks - only mock notify server
    s_reset_mocks();
    
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Disable mocks - use real wallet functions
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Prepare CLI arguments: "wallet list"
    char *l_argv[] = {"wallet", "list", NULL};
    int l_argc = 2;
    
    // Create JSON reply
    dap_json_t *l_json_reply = dap_json_array_new();
    dap_assert(l_json_reply != NULL, "JSON reply created");
    
    // Execute CLI command
    int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "wallet list returned: %d", l_ret);
    
    // Print JSON result
    const char *l_json_str = dap_json_to_string(l_json_reply);
    if (l_json_str) {
        log_it(L_DEBUG, "wallet list JSON result: %s", l_json_str);
    }
    
    // Verify command succeeded
    dap_assert(l_ret == 0, "wallet list command returned 0");
    
    // Verify JSON contains both wallet names
    dap_assert(l_json_str != NULL, "JSON result not empty");
    dap_assert(strstr(l_json_str, l_wallet_name_1) != NULL, "wallet list contains wallet 1");
    dap_assert(strstr(l_json_str, l_wallet_name_2) != NULL, "wallet list contains wallet 2");
    dap_assert(strstr(l_json_str, "sig_dil") != NULL, "wallet list shows signature type");
    
    log_it(L_DEBUG, "Wallets '%s' and '%s' found in list", l_wallet_name_1, l_wallet_name_2);
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("wallet list CLI (real files) complete");
}

/**
 * @brief Test wallet info CLI command - validation tests
 * 
 * Tests argument validation without network mocking.
 */
static void test_wallet_info_cli_validation(void)
{
    dap_print_module_name("wallet info CLI (validation)");
    
    const char *l_wallet_name_1 = "cliTestWallet_1";
    
    // Verify wallet exists
    dap_assert(s_wallet_file_exists(l_wallet_name_1), "test wallet exists");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Disable mocks - use real wallet functions
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Test 1: wallet info without -w or -addr (should fail)
    {
        char *l_argv[] = {"wallet", "info", NULL};
        int l_argc = 2;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet info (no args) returned: %d", l_ret);
        dap_assert(l_ret != 0, "wallet info without args returns error");
        
        dap_json_object_free(l_json_reply);
    }
    
    // Test 2: wallet info -w without -net (should fail with specific error)
    {
        char *l_argv[] = {"wallet", "info", "-w", (char*)l_wallet_name_1, NULL};
        int l_argc = 4;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet info -w (no net) returned: %d", l_ret);
        
        // Should return error about missing -net parameter
        dap_assert(l_ret != 0, "wallet info -w without -net returns error");
        
        // Check error message mentions -net
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet info error JSON: %s", l_json_str);
            dap_assert(strstr(l_json_str, "-net") != NULL, "error mentions -net parameter");
        }
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet info CLI validation complete");
}

/**
 * @brief Test wallet info CLI command - full test with mocked network
 * 
 * Uses mocked network and ledger to get full wallet info response.
 */
static void test_wallet_info_cli_with_mock_net(void)
{
    dap_print_module_name("wallet info CLI (mocked network)");
    
    const char *l_wallet_name_1 = "cliTestWallet_1";
    
    // Verify wallet exists
    dap_assert(s_wallet_file_exists(l_wallet_name_1), "test wallet exists");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Setup network mocks to return our mock network
    strncpy(s_mock_net.pub.name, "test_net", DAP_CHAIN_NET_NAME_MAX);
    DAP_MOCK_SET_RETURN(dap_chain_net_by_name, (intptr_t)&s_mock_net);
    DAP_MOCK_SET_RETURN(dap_chain_net_by_id, (intptr_t)&s_mock_net);
    
    // Setup address mock to return our mock address
    s_mock_addr.net_id = s_mock_net.pub.id;
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_addr, (intptr_t)&s_mock_addr);
    
    // Ledger mocks return empty data (no tokens, no locked values)
    // dap_ledger_addr_get_token_ticker_all - already returns empty list
    // dap_ledger_get_locked_values - already returns NULL
    // dap_chain_wallet_shared_get_tx_hashes_json - already returns NULL
    
    // Disable mocks - use real wallet functions (open, close, check_sign)
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Prepare CLI arguments: "wallet info -w cliTestWallet_1 -net test_net"
    char *l_argv[] = {"wallet", "info", "-w", (char*)l_wallet_name_1, "-net", "test_net", NULL};
    int l_argc = 6;
    
    // Create JSON reply
    dap_json_t *l_json_reply = dap_json_array_new();
    dap_assert(l_json_reply != NULL, "JSON reply created");
    
    // Execute CLI command
    int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
    
    log_it(L_DEBUG, "wallet info returned: %d", l_ret);
    
    // Print JSON result
    const char *l_json_str = dap_json_to_string(l_json_reply);
    if (l_json_str) {
        log_it(L_DEBUG, "wallet info JSON result: %s", l_json_str);
    }
    
    // Verify command succeeded
    dap_assert(l_ret == 0, "wallet info command returned 0");
    
    // Verify JSON contains expected fields
    dap_assert(l_json_str != NULL, "JSON result not empty");
    dap_assert(strstr(l_json_str, "wallet") != NULL, "JSON contains wallet field");
    dap_assert(strstr(l_json_str, l_wallet_name_1) != NULL, "JSON contains wallet name");
    dap_assert(strstr(l_json_str, "addr") != NULL, "JSON contains addr field");
    dap_assert(strstr(l_json_str, "network") != NULL, "JSON contains network field");
    dap_assert(strstr(l_json_str, "test_net") != NULL, "JSON contains network name");
    dap_assert(strstr(l_json_str, "sign") != NULL, "JSON contains sign field");
    
    // Verify mocks were called
    int l_net_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_net_by_name);
    dap_assert(l_net_calls >= 1, "dap_chain_net_by_name was called");
    
    int l_addr_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_wallet_get_addr);
    dap_assert(l_addr_calls >= 1, "dap_chain_wallet_get_addr was called");
    
    int l_ticker_calls = DAP_MOCK_GET_CALL_COUNT(dap_ledger_addr_get_token_ticker_all);
    dap_assert(l_ticker_calls >= 1, "dap_ledger_addr_get_token_ticker_all was called");
    
    log_it(L_DEBUG, "Mock call counts: net_by_name=%d, get_addr=%d, get_tickers=%d",
           l_net_calls, l_addr_calls, l_ticker_calls);
    
    dap_json_object_free(l_json_reply);
    
    dap_pass_msg("wallet info CLI (mocked network) complete");
}

/**
 * @brief Test wallet activate CLI command with mocked activate/deactivate
 * 
 * Uses mocked activate/deactivate functions to test CLI logic,
 * since real activation requires global config initialization.
 */
static void test_wallet_activate_deactivate_cli(void)
{
    dap_print_module_name("wallet activate/deactivate CLI (mocked)");
    
    const char *l_wallet_name = "cliTestWallet_1";  // Use existing wallet
    const char *l_password = "TestPass123";
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Enable activate/deactivate mocks - return success (0)
    DAP_MOCK_SET_RETURN(dap_chain_wallet_activate, 0);
    DAP_MOCK_SET_RETURN(dap_chain_wallet_deactivate, 0);
    
    // Disable mocks for wallet open/close (real operations)
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Verify wallet exists from previous tests
    dap_assert(s_wallet_file_exists(l_wallet_name), "test wallet exists");
    
    // Test 1: activate command (mocked to succeed)
    {
        char *l_argv[] = {"wallet", "activate", "-w", (char*)l_wallet_name, 
                          "-password", (char*)l_password, "-ttl", "120", NULL};
        int l_argc = 8;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet activate returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet activate JSON result: %s", l_json_str);
        }
        
        dap_assert(l_ret == 0, "wallet activate returned 0");
        dap_assert(l_json_str != NULL, "activate JSON not empty");
        dap_assert(strstr(l_json_str, l_wallet_name) != NULL, "activate response contains wallet name");
        dap_assert(strstr(l_json_str, "is activated") != NULL, "activate response shows activated");
        
        // Verify mock was called
        int l_activate_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_wallet_activate);
        dap_assert(l_activate_calls == 1, "dap_chain_wallet_activate was called");
        
        dap_json_object_free(l_json_reply);
    }
    
    // Test 2: activate again (mock returns -EBUSY for already activated)
    {
        DAP_MOCK_RESET(dap_chain_wallet_activate);
        DAP_MOCK_ENABLE(dap_chain_wallet_activate);
        DAP_MOCK_SET_RETURN(dap_chain_wallet_activate, -EBUSY);
        
        char *l_argv[] = {"wallet", "activate", "-w", (char*)l_wallet_name, 
                          "-password", (char*)l_password, NULL};
        int l_argc = 6;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        (void)l_ret;  // CLI may return 0 even on error (error is in JSON)
        
        log_it(L_DEBUG, "wallet activate (second time) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        log_it(L_DEBUG, "wallet activate (already active) JSON: %s", l_json_str);
        
        // Check error is in JSON response
        dap_assert(strstr(l_json_str, "already") != NULL, "error mentions 'already'");
        dap_assert(strstr(l_json_str, "errors") != NULL, "JSON contains errors");
        
        dap_json_object_free(l_json_reply);
    }
    
    // Test 3: deactivate command (mocked to succeed)
    {
        DAP_MOCK_RESET(dap_chain_wallet_deactivate);
        DAP_MOCK_ENABLE(dap_chain_wallet_deactivate);
        DAP_MOCK_SET_RETURN(dap_chain_wallet_deactivate, 0);
        
        char *l_argv[] = {"wallet", "deactivate", "-w", (char*)l_wallet_name, NULL};
        int l_argc = 4;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet deactivate returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet deactivate JSON result: %s", l_json_str);
        }
        
        dap_assert(l_ret == 0, "wallet deactivate returned 0");
        dap_assert(l_json_str != NULL, "deactivate JSON not empty");
        dap_assert(strstr(l_json_str, l_wallet_name) != NULL, "deactivate response contains wallet name");
        dap_assert(strstr(l_json_str, "is deactivated") != NULL, "deactivate response shows deactivated");
        
        // Verify mock was called
        int l_deactivate_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_wallet_deactivate);
        dap_assert(l_deactivate_calls == 1, "dap_chain_wallet_deactivate was called");
        
        dap_json_object_free(l_json_reply);
    }
    
    // Test 4: deactivate again (mock returns -EBUSY for already deactivated)
    {
        DAP_MOCK_RESET(dap_chain_wallet_deactivate);
        DAP_MOCK_ENABLE(dap_chain_wallet_deactivate);
        DAP_MOCK_SET_RETURN(dap_chain_wallet_deactivate, -EBUSY);
        
        char *l_argv[] = {"wallet", "deactivate", "-w", (char*)l_wallet_name, NULL};
        int l_argc = 4;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        (void)l_ret;  // CLI may return 0 even on error (error is in JSON)
        
        log_it(L_DEBUG, "wallet deactivate (second time) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        log_it(L_DEBUG, "wallet deactivate (already inactive) JSON: %s", l_json_str);
        
        // Check error is in JSON response  
        dap_assert(strstr(l_json_str, "already") != NULL, "error mentions 'already'");
        dap_assert(strstr(l_json_str, "errors") != NULL, "JSON contains errors");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet activate/deactivate CLI complete");
}

/**
 * @brief Test wallet activate with wrong password (mocked)
 */
static void test_wallet_activate_wrong_password(void)
{
    dap_print_module_name("wallet activate wrong password (mocked)");
    
    const char *l_wallet_name = "cliTestWallet_1";  // Use existing wallet
    const char *l_wrong_password = "WrongPass456";
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Mock activate to return -EAGAIN (wrong password)
    DAP_MOCK_SET_RETURN(dap_chain_wallet_activate, -EAGAIN);
    
    // Disable mocks for wallet open/close
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Try activate with wrong password
    {
        char *l_argv[] = {"wallet", "activate", "-w", (char*)l_wallet_name, 
                          "-password", (char*)l_wrong_password, NULL};
        int l_argc = 6;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        (void)l_ret;  // CLI may return 0 even on error (error is in JSON)
        
        log_it(L_DEBUG, "wallet activate (wrong password) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        log_it(L_DEBUG, "wallet activate (wrong password) JSON: %s", l_json_str);
        
        // Check error is in JSON response
        dap_assert(strstr(l_json_str, "Wrong password") != NULL, "error mentions wrong password");
        dap_assert(strstr(l_json_str, "errors") != NULL, "JSON contains errors");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet activate wrong password complete");
}

/**
 * @brief Test wallet activate on unprotected wallet (mocked)
 */
static void test_wallet_activate_unprotected(void)
{
    dap_print_module_name("wallet activate unprotected (mocked)");
    
    const char *l_wallet_name = "cliTestWallet_1";  // Unprotected wallet
    const char *l_password = "SomePassword";
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Mock activate to return -101 (can't activate unprotected wallet)
    DAP_MOCK_SET_RETURN(dap_chain_wallet_activate, -101);
    
    // Disable mocks for wallet open/close
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Try activate unprotected wallet
    {
        char *l_argv[] = {"wallet", "activate", "-w", (char*)l_wallet_name, 
                          "-password", (char*)l_password, NULL};
        int l_argc = 6;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        (void)l_ret;  // CLI may return 0 even on error (error is in JSON)
        
        log_it(L_DEBUG, "wallet activate (unprotected) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        log_it(L_DEBUG, "wallet activate (unprotected) JSON: %s", l_json_str);
        
        // Check error is in JSON response
        dap_assert(strstr(l_json_str, "unprotected") != NULL, "error mentions unprotected");
        dap_assert(strstr(l_json_str, "errors") != NULL, "JSON contains errors");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet activate unprotected complete");
}

/**
 * @brief Test wallet convert CLI command - add password protection
 * 
 * Tests converting an unprotected wallet to a protected one.
 * Uses mocked dap_chain_wallet_save to avoid actual file operations.
 */
static void test_wallet_convert_add_password(void)
{
    dap_print_module_name("wallet convert CLI (add password)");
    
    const char *l_wallet_name = "cliTestWallet_1";  // Use existing unprotected wallet
    const char *l_password = "NewSecurePass123";
    
    // Verify wallet exists
    dap_assert(s_wallet_file_exists(l_wallet_name), "test wallet exists");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Mock wallet_save to return success (0)
    DAP_MOCK_SET_RETURN(dap_chain_wallet_save, 0);
    
    // Disable mocks for wallet open/close/check_sign (real operations)
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Test: convert unprotected wallet with password
    {
        char *l_argv[] = {"wallet", "convert", "-w", (char*)l_wallet_name, 
                          "-password", (char*)l_password, NULL};
        int l_argc = 6;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet convert (add password) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet convert JSON result: %s", l_json_str);
        }
        
        dap_assert(l_ret == 0, "wallet convert returned 0");
        dap_assert(l_json_str != NULL, "convert JSON not empty");
        dap_assert(strstr(l_json_str, l_wallet_name) != NULL, "convert response contains wallet name");
        dap_assert(strstr(l_json_str, "success") != NULL, "convert response shows success status");
        dap_assert(strstr(l_json_str, "wallet_name") != NULL, "convert response contains wallet_name field");
        dap_assert(strstr(l_json_str, "sig_wallet") != NULL, "convert response contains sig_wallet field");
        
        // Verify mock was called twice (backup + actual save)
        int l_save_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_wallet_save);
        log_it(L_DEBUG, "dap_chain_wallet_save call count: %d", l_save_calls);
        dap_assert(l_save_calls == 2, "dap_chain_wallet_save was called twice (backup + convert)");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet convert (add password) complete");
}

/**
 * @brief Test wallet convert CLI command - already protected wallet (error)
 * 
 * Tests that attempting to convert an already protected wallet fails.
 */
static void test_wallet_convert_already_protected(void)
{
    dap_print_module_name("wallet convert CLI (already protected)");
    
    const char *l_wallet_name = "cliTestWallet_1";
    const char *l_password = "AnotherPass456";
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Create a mock wallet that appears to be already protected (ACTIVE flag set)
    static dap_chain_wallet_t s_protected_wallet;
    memset(&s_protected_wallet, 0, sizeof(s_protected_wallet));
    s_protected_wallet.flags = DAP_WALLET$M_FL_PROTECTED | DAP_WALLET$M_FL_ACTIVE;
    strncpy(s_protected_wallet.name, l_wallet_name, sizeof(s_protected_wallet.name) - 1);
    
    // Enable wallet_open mock to return our "protected" wallet
    DAP_MOCK_SET_RETURN(dap_chain_wallet_open, (intptr_t)&s_protected_wallet);
    
    // Enable wallet_close mock (to prevent real close on mock wallet)
    // Already enabled in s_reset_mocks
    
    // Disable wallet_create mock
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    
    // Test: try to convert already protected wallet (should fail)
    {
        char *l_argv[] = {"wallet", "convert", "-w", (char*)l_wallet_name, 
                          "-password", (char*)l_password, NULL};
        int l_argc = 6;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet convert (already protected) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet convert (already protected) JSON: %s", l_json_str);
        }
        
        // Should return error
        dap_assert(l_ret != 0, "wallet convert returned error for already protected wallet");
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "converted twice") != NULL || 
                   strstr(l_json_str, "errors") != NULL, "error message present");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet convert (already protected) complete");
}

/**
 * @brief Test wallet convert CLI command - remove password protection
 * 
 * Tests converting a protected wallet to unprotected using -remove_password.
 * Uses real wallet with mocked save/deactivate to test the logic.
 */
static void test_wallet_convert_remove_password(void)
{
    dap_print_module_name("wallet convert CLI (remove password)");
    
    const char *l_wallet_name = "cliTestWallet_1";
    
    // Verify wallet exists
    dap_assert(s_wallet_file_exists(l_wallet_name), "test wallet exists");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Mock wallet_save to return success
    DAP_MOCK_SET_RETURN(dap_chain_wallet_save, 0);
    
    // Mock deactivate to return success
    DAP_MOCK_SET_RETURN(dap_chain_wallet_deactivate, 0);
    
    // Disable mocks - use real wallet functions (open, close, check_sign)
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Test: convert with -remove_password on unprotected wallet
    // Note: Real wallet is unprotected, so -remove_password should work
    // (the CLI just saves without password in this case)
    {
        char *l_argv[] = {"wallet", "convert", "-w", (char*)l_wallet_name, 
                          "-remove_password", NULL};
        int l_argc = 5;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet convert (remove password) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet convert (remove password) JSON: %s", l_json_str);
        }
        
        dap_assert(l_ret == 0, "wallet convert (remove password) returned 0");
        dap_assert(l_json_str != NULL, "convert JSON not empty");
        dap_assert(strstr(l_json_str, l_wallet_name) != NULL, "response contains wallet name");
        dap_assert(strstr(l_json_str, "success") != NULL, "response shows success status");
        
        // Verify deactivate was called
        int l_deactivate_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_wallet_deactivate);
        log_it(L_DEBUG, "dap_chain_wallet_deactivate call count: %d", l_deactivate_calls);
        dap_assert(l_deactivate_calls == 1, "dap_chain_wallet_deactivate was called");
        
        // Verify save was called twice (backup + final save)
        int l_save_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_wallet_save);
        log_it(L_DEBUG, "dap_chain_wallet_save call count: %d", l_save_calls);
        dap_assert(l_save_calls == 2, "dap_chain_wallet_save was called twice");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet convert (remove password) complete");
}

/**
 * @brief Test wallet convert CLI command - missing password (error)
 * 
 * Tests that convert fails when password is missing and -remove_password not set.
 */
static void test_wallet_convert_missing_password(void)
{
    dap_print_module_name("wallet convert CLI (missing password)");
    
    const char *l_wallet_name = "cliTestWallet_1";
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Mock wallet_save to return success
    DAP_MOCK_SET_RETURN(dap_chain_wallet_save, 0);
    
    // Disable mocks for wallet open/close/check_sign (real operations)
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Test: convert without password (should fail)
    {
        char *l_argv[] = {"wallet", "convert", "-w", (char*)l_wallet_name, NULL};
        int l_argc = 4;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet convert (missing password) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet convert (missing password) JSON: %s", l_json_str);
        }
        
        // Should return error about missing password
        dap_assert(l_ret != 0, "wallet convert returned error for missing password");
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "password") != NULL, "error mentions password");
        dap_assert(strstr(l_json_str, "errors") != NULL, "JSON contains errors");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet convert (missing password) complete");
}

/**
 * @brief Test wallet convert CLI command - save failure (error)
 * 
 * Tests that convert handles save failures correctly.
 */
static void test_wallet_convert_save_failure(void)
{
    dap_print_module_name("wallet convert CLI (save failure)");
    
    const char *l_wallet_name = "cliTestWallet_1";
    const char *l_password = "TestPassword789";
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Mock wallet_save to return failure (-1)
    DAP_MOCK_SET_RETURN(dap_chain_wallet_save, -1);
    
    // Disable mocks for wallet open/close/check_sign (real operations)
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Test: convert with save failure
    {
        char *l_argv[] = {"wallet", "convert", "-w", (char*)l_wallet_name, 
                          "-password", (char*)l_password, NULL};
        int l_argc = 6;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet convert (save failure) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet convert (save failure) JSON: %s", l_json_str);
        }
        
        // Should return error about backup/save failure
        dap_assert(l_ret != 0, "wallet convert returned error on save failure");
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "backup") != NULL || strstr(l_json_str, "internal error") != NULL, 
                   "error mentions backup or internal error");
        dap_assert(strstr(l_json_str, "errors") != NULL, "JSON contains errors");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet convert (save failure) complete");
}

/**
 * @brief Test wallet outputs CLI command - validation tests
 * 
 * Tests argument validation for wallet outputs command.
 */
static void test_wallet_outputs_cli_validation(void)
{
    dap_print_module_name("wallet outputs CLI (validation)");
    
    const char *l_wallet_name = "cliTestWallet_1";
    
    // Verify wallet exists
    dap_assert(s_wallet_file_exists(l_wallet_name), "test wallet exists");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Disable mocks for wallet open/close
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Test 1: outputs without -w or -addr (should fail)
    {
        char *l_argv[] = {"wallet", "outputs", "-net", "test_net", "-token", "TEST", NULL};
        int l_argc = 6;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet outputs (no wallet) returned: %d", l_ret);
        dap_assert(l_ret != 0, "wallet outputs without -w or -addr returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "-w") != NULL || strstr(l_json_str, "-addr") != NULL, 
                   "error mentions -w or -addr");
        
        dap_json_object_free(l_json_reply);
    }
    
    // Test 2: outputs with -w but without -net (should fail)
    {
        char *l_argv[] = {"wallet", "outputs", "-w", (char*)l_wallet_name, "-token", "TEST", NULL};
        int l_argc = 6;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet outputs (no net) returned: %d", l_ret);
        dap_assert(l_ret != 0, "wallet outputs without -net returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "-net") != NULL, "error mentions -net");
        
        dap_json_object_free(l_json_reply);
    }
    
    // Test 3: outputs without -token (should fail)
    {
        // Setup network mock for this test
        DAP_MOCK_SET_RETURN(dap_chain_net_by_name, (intptr_t)&s_mock_net);
        DAP_MOCK_SET_RETURN(dap_chain_wallet_get_addr, (intptr_t)&s_mock_addr);
        
        char *l_argv[] = {"wallet", "outputs", "-w", (char*)l_wallet_name, "-net", "test_net", NULL};
        int l_argc = 6;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet outputs (no token) returned: %d", l_ret);
        dap_assert(l_ret != 0, "wallet outputs without -token returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "-token") != NULL, "error mentions -token");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet outputs CLI validation complete");
}

/**
 * @brief Test wallet outputs CLI command - basic outputs listing
 * 
 * Tests listing wallet outputs with mocked cache functions.
 */
static void test_wallet_outputs_cli_basic(void)
{
    dap_print_module_name("wallet outputs CLI (basic)");
    
    const char *l_wallet_name = "cliTestWallet_1";
    
    // Verify wallet exists
    dap_assert(s_wallet_file_exists(l_wallet_name), "test wallet exists");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Setup network mock
    DAP_MOCK_SET_RETURN(dap_chain_net_by_name, (intptr_t)&s_mock_net);
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_addr, (intptr_t)&s_mock_addr);
    
    // Cache mock returns empty list (return 0 = success)
    DAP_MOCK_SET_RETURN(dap_chain_wallet_cache_tx_find_outs_mempool_check, 0);
    
    // Disable mocks for wallet open/close
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Test: outputs with valid parameters (empty result)
    {
        char *l_argv[] = {"wallet", "outputs", "-w", (char*)l_wallet_name, 
                          "-net", "test_net", "-token", "TEST", NULL};
        int l_argc = 8;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet outputs (basic) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet outputs JSON: %s", l_json_str);
        }
        
        dap_assert(l_ret == 0, "wallet outputs returned 0");
        dap_assert(l_json_str != NULL, "JSON result not empty");
        dap_assert(strstr(l_json_str, "wallet_addr") != NULL, "JSON contains wallet_addr field");
        dap_assert(strstr(l_json_str, "outs") != NULL, "JSON contains outs field");
        dap_assert(strstr(l_json_str, "total_value") != NULL, "JSON contains total_value field");
        
        // Verify cache mock was called
        int l_cache_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_wallet_cache_tx_find_outs_mempool_check);
        log_it(L_DEBUG, "dap_chain_wallet_cache_tx_find_outs_mempool_check call count: %d", l_cache_calls);
        dap_assert(l_cache_calls == 1, "cache find outs was called");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet outputs CLI (basic) complete");
}

/**
 * @brief Test wallet outputs CLI command - with value filter
 * 
 * Tests listing wallet outputs with -value parameter.
 */
static void test_wallet_outputs_cli_with_value(void)
{
    dap_print_module_name("wallet outputs CLI (with value)");
    
    const char *l_wallet_name = "cliTestWallet_1";
    
    // Verify wallet exists
    dap_assert(s_wallet_file_exists(l_wallet_name), "test wallet exists");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Setup network mock
    DAP_MOCK_SET_RETURN(dap_chain_net_by_name, (intptr_t)&s_mock_net);
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_addr, (intptr_t)&s_mock_addr);
    
    // Cache mock returns empty list (return 0 = success)
    DAP_MOCK_SET_RETURN(dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check, 0);
    
    // Disable mocks for wallet open/close
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Test: outputs with -value parameter
    {
        char *l_argv[] = {"wallet", "outputs", "-w", (char*)l_wallet_name, 
                          "-net", "test_net", "-token", "TEST", "-value", "100.0", NULL};
        int l_argc = 10;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet outputs (with value) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet outputs (with value) JSON: %s", l_json_str);
        }
        
        dap_assert(l_ret == 0, "wallet outputs returned 0");
        dap_assert(l_json_str != NULL, "JSON result not empty");
        dap_assert(strstr(l_json_str, "wallet_addr") != NULL, "JSON contains wallet_addr field");
        dap_assert(strstr(l_json_str, "outs") != NULL, "JSON contains outs field");
        
        // Verify cache mock was called (with value version)
        int l_cache_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check);
        log_it(L_DEBUG, "dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check call count: %d", l_cache_calls);
        dap_assert(l_cache_calls == 1, "cache find outs with val was called");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet outputs CLI (with value) complete");
}

/**
 * @brief Test wallet outputs CLI command - conditional outputs
 * 
 * Tests listing conditional outputs with -cond parameter.
 */
static void test_wallet_outputs_cli_conditional(void)
{
    dap_print_module_name("wallet outputs CLI (conditional)");
    
    const char *l_wallet_name = "cliTestWallet_1";
    
    // Verify wallet exists
    dap_assert(s_wallet_file_exists(l_wallet_name), "test wallet exists");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Setup network mock with ledger
    s_mock_net.pub.ledger = (dap_ledger_t*)0x12345678;  // Fake ledger pointer
    DAP_MOCK_SET_RETURN(dap_chain_net_by_name, (intptr_t)&s_mock_net);
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_addr, (intptr_t)&s_mock_addr);
    
    // Ledger mock returns empty list (NULL)
    DAP_MOCK_SET_RETURN(dap_ledger_get_list_tx_cond_outs, (intptr_t)NULL);
    
    // Disable mocks for wallet open/close
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Test: outputs with -cond parameter
    {
        char *l_argv[] = {"wallet", "outputs", "-w", (char*)l_wallet_name, 
                          "-net", "test_net", "-token", "TEST", "-cond", NULL};
        int l_argc = 9;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet outputs (conditional) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet outputs (conditional) JSON: %s", l_json_str);
        }
        
        dap_assert(l_ret == 0, "wallet outputs returned 0");
        dap_assert(l_json_str != NULL, "JSON result not empty");
        dap_assert(strstr(l_json_str, "wallet_addr") != NULL, "JSON contains wallet_addr field");
        dap_assert(strstr(l_json_str, "outs") != NULL, "JSON contains outs field");
        
        // Verify ledger mock was called
        int l_ledger_calls = DAP_MOCK_GET_CALL_COUNT(dap_ledger_get_list_tx_cond_outs);
        log_it(L_DEBUG, "dap_ledger_get_list_tx_cond_outs call count: %d", l_ledger_calls);
        dap_assert(l_ledger_calls == 1, "ledger get cond outs was called");
        
        dap_json_object_free(l_json_reply);
    }
    
    // Reset ledger pointer
    s_mock_net.pub.ledger = NULL;
    
    dap_pass_msg("wallet outputs CLI (conditional) complete");
}

/**
 * @brief Test wallet outputs CLI command - invalid value parameter
 * 
 * Tests error handling for invalid -value parameter.
 */
static void test_wallet_outputs_cli_invalid_value(void)
{
    dap_print_module_name("wallet outputs CLI (invalid value)");
    
    const char *l_wallet_name = "cliTestWallet_1";
    
    // Verify wallet exists
    dap_assert(s_wallet_file_exists(l_wallet_name), "test wallet exists");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Setup network mock
    DAP_MOCK_SET_RETURN(dap_chain_net_by_name, (intptr_t)&s_mock_net);
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_addr, (intptr_t)&s_mock_addr);
    
    // Disable mocks for wallet open/close
    DAP_MOCK_DISABLE(dap_chain_wallet_create_with_seed_multi);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Test: outputs with invalid -value (zero/invalid format)
    {
        char *l_argv[] = {"wallet", "outputs", "-w", (char*)l_wallet_name, 
                          "-net", "test_net", "-token", "TEST", "-value", "invalid", NULL};
        int l_argc = 10;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet outputs (invalid value) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet outputs (invalid value) JSON: %s", l_json_str);
        }
        
        // Should return error about invalid value
        dap_assert(l_ret != 0, "wallet outputs returned error for invalid value");
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "value") != NULL || strstr(l_json_str, "256bit") != NULL, 
                   "error mentions value conversion issue");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet outputs CLI (invalid value) complete");
}

/**
 * @brief Test wallet find CLI command - validation tests
 * 
 * Tests argument validation for wallet find command.
 */
static void test_wallet_find_cli_validation(void)
{
    dap_print_module_name("wallet find CLI (validation)");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Test 1: find without -addr (should fail)
    {
        char *l_argv[] = {"wallet", "find", NULL};
        int l_argc = 2;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet find (no addr) returned: %d", l_ret);
        dap_assert(l_ret != 0, "wallet find without -addr returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "-addr") != NULL, "error mentions -addr");
        
        dap_json_object_free(l_json_reply);
    }
    
    // Test 2: find with invalid address (should fail)
    {
        // Mock returns NULL for invalid address
        DAP_MOCK_SET_RETURN(dap_chain_addr_from_str, (intptr_t)NULL);
        
        char *l_argv[] = {"wallet", "find", "-addr", "invalid_address_string", NULL};
        int l_argc = 4;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet find (invalid addr) returned: %d", l_ret);
        dap_assert(l_ret != 0, "wallet find with invalid addr returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "addr") != NULL || strstr(l_json_str, "recognized") != NULL, 
                   "error mentions address issue");
        
        // Verify mock was called
        int l_addr_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_addr_from_str);
        log_it(L_DEBUG, "dap_chain_addr_from_str call count: %d", l_addr_calls);
        dap_assert(l_addr_calls == 1, "dap_chain_addr_from_str was called");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet find CLI validation complete");
}

/**
 * @brief Test wallet find CLI command - successful find
 * 
 * Tests finding a wallet by address.
 */
static void test_wallet_find_cli_success(void)
{
    dap_print_module_name("wallet find CLI (success)");
    
    const char *l_wallet_name = "cliTestWallet_1";
    
    // Verify wallet exists
    dap_assert(s_wallet_file_exists(l_wallet_name), "test wallet exists");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Return real address from mock (using static mock addr with proper net_id)
    DAP_MOCK_SET_RETURN(dap_chain_addr_from_str, (intptr_t)&s_mock_addr);
    
    // Let wallet open/get_addr work with real files
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Mock wallet get_addr to return matching address
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_addr, (intptr_t)&s_mock_addr);
    
    // Test: find with valid address
    {
        char *l_argv[] = {"wallet", "find", "-addr", 
                          "16bv5nPhrJNQqNpwxBqcYrwMUwCrCVH2hmgK9hZzkmpK1mMVc8Kf5NZqjh3RxZXGKZfAjBUidgxuTwniQJNLWJRkiz4Ju4nhWeJtSTNX", 
                          NULL};
        int l_argc = 4;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet find (success) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet find JSON: %s", l_json_str);
        }
        
        dap_assert(l_ret == 0, "wallet find returned 0");
        dap_assert(l_json_str != NULL, "JSON result not empty");
        dap_assert(strstr(l_json_str, "wallet") != NULL, "JSON contains wallet field");
        dap_assert(strstr(l_json_str, "status") != NULL, "JSON contains status field");
        
        // Verify address from_str mock was called
        int l_addr_calls = DAP_MOCK_GET_CALL_COUNT(dap_chain_addr_from_str);
        log_it(L_DEBUG, "dap_chain_addr_from_str call count: %d", l_addr_calls);
        dap_assert(l_addr_calls == 1, "dap_chain_addr_from_str was called");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet find CLI (success) complete");
}

/**
 * @brief Test wallet find CLI command - wallet not found
 * 
 * Tests behavior when no wallet matches the address.
 */
static void test_wallet_find_cli_not_found(void)
{
    dap_print_module_name("wallet find CLI (not found)");
    
    const char *l_wallet_name = "cliTestWallet_1";
    
    // Verify wallet exists
    dap_assert(s_wallet_file_exists(l_wallet_name), "test wallet exists");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Create a different address that won't match
    static dap_chain_addr_t s_different_addr;
    memset(&s_different_addr, 0, sizeof(s_different_addr));
    s_different_addr.net_id.uint64 = 0x12345678;  // Different net_id
    s_different_addr.addr_ver = 0;  // Default version
    
    // Return different address from mock
    DAP_MOCK_SET_RETURN(dap_chain_addr_from_str, (intptr_t)&s_different_addr);
    
    // Let wallet open/close work with real files
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Mock wallet get_addr to return different address (won't match)
    static dap_chain_addr_t s_wallet_addr;
    memset(&s_wallet_addr, 0xFF, sizeof(s_wallet_addr));  // Completely different
    s_wallet_addr.net_id.uint64 = 0x12345678;  // Same net_id to get addr
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_addr, (intptr_t)&s_wallet_addr);
    
    // Test: find with address that doesn't match any wallet
    {
        char *l_argv[] = {"wallet", "find", "-addr", 
                          "SomeNonExistentAddressString123456789", 
                          NULL};
        int l_argc = 4;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet find (not found) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet find (not found) JSON: %s", l_json_str);
        }
        
        // Command returns 0 but with empty result (no matching wallet)
        dap_assert(l_ret == 0, "wallet find returned 0 (no error, just empty)");
        dap_assert(l_json_str != NULL, "JSON result exists");
        // Result should be empty array or not contain wallet name
        dap_assert(strstr(l_json_str, l_wallet_name) == NULL, 
                   "result doesn't contain non-matching wallet");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet find CLI (not found) complete");
}

/**
 * @brief Test wallet shared CLI command - validation tests
 * 
 * Tests argument validation for wallet shared command.
 */
static void test_wallet_shared_cli_validation(void)
{
    dap_print_module_name("wallet shared CLI (validation)");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Test 1: shared without subcommand (should fail)
    {
        char *l_argv[] = {"wallet", "shared", NULL};
        int l_argc = 2;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet shared (no subcommand) returned: %d", l_ret);
        dap_assert(l_ret != 0, "wallet shared without subcommand returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "Subcommand") != NULL || strstr(l_json_str, "recognized") != NULL ||
                   strstr(l_json_str, "net") != NULL, "error mentions subcommand or net issue");
        
        dap_json_object_free(l_json_reply);
    }
    
    // Test 2: shared with invalid -H parameter (should fail)
    {
        char *l_argv[] = {"wallet", "shared", "-H", "invalid_hash_type", "list", NULL};
        int l_argc = 5;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet shared (invalid -H) returned: %d", l_ret);
        dap_assert(l_ret != 0, "wallet shared with invalid -H returns error");
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "-H") != NULL || strstr(l_json_str, "hex") != NULL || 
                   strstr(l_json_str, "base58") != NULL, "error mentions -H parameter");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet shared CLI validation complete");
}

/**
 * @brief Test wallet shared list CLI command
 * 
 * Tests listing shared wallets.
 */
static void test_wallet_shared_cli_list(void)
{
    dap_print_module_name("wallet shared CLI (list)");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Disable real wallet operations
    DAP_MOCK_DISABLE(dap_chain_wallet_open);
    DAP_MOCK_DISABLE(dap_chain_wallet_close);
    DAP_MOCK_DISABLE(dap_chain_wallet_check_sign);
    
    // Test: shared list (no filters - may return 0 or error code 4 if GDB empty)
    {
        char *l_argv[] = {"wallet", "shared", "list", NULL};
        int l_argc = 3;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet shared list returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet shared list JSON: %s", l_json_str);
        }
        
        // List returns 0 if data exists, or code 4 if GDB empty (both are valid)
        dap_assert(l_ret == 0 || l_ret == 4, "wallet shared list returned 0 or 4 (no data)");
        dap_assert(l_json_str != NULL, "JSON result exists");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet shared CLI (list) complete");
}

/**
 * @brief Test wallet shared list CLI command - mutually exclusive params
 * 
 * Tests that -pkey, -addr, -w, -cert are mutually exclusive.
 */
static void test_wallet_shared_cli_list_exclusive_params(void)
{
    dap_print_module_name("wallet shared CLI (exclusive params)");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Test: shared list with multiple mutually exclusive params (should fail)
    {
        char *l_argv[] = {"wallet", "shared", "list", "-w", "wallet1", "-addr", "some_addr", NULL};
        int l_argc = 7;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet shared list (exclusive params) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet shared list (exclusive params) JSON: %s", l_json_str);
        }
        
        dap_assert(l_ret != 0, "wallet shared list with exclusive params returns error");
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "mutually exclusive") != NULL || 
                   strstr(l_json_str, "exclusive") != NULL ||
                   strstr(l_json_str, "-pkey") != NULL ||
                   strstr(l_json_str, "-addr") != NULL, 
                   "error mentions mutually exclusive parameters");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet shared CLI (exclusive params) complete");
}

/**
 * @brief Test wallet shared hold CLI command - requires net/chain
 * 
 * Tests that hold subcommand requires -net and -chain.
 */
static void test_wallet_shared_cli_hold_requires_net(void)
{
    dap_print_module_name("wallet shared CLI (hold requires net)");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Mock net_by_name to return NULL (network not found)
    DAP_MOCK_SET_RETURN(dap_chain_net_by_name, (intptr_t)NULL);
    
    // Test: shared hold without -net (should fail)
    {
        char *l_argv[] = {"wallet", "shared", "hold", "-w", "testWallet", NULL};
        int l_argc = 5;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet shared hold (no net) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet shared hold (no net) JSON: %s", l_json_str);
        }
        
        dap_assert(l_ret != 0, "wallet shared hold without -net returns error");
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "net") != NULL || strstr(l_json_str, "chain") != NULL, 
                   "error mentions net or chain");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet shared CLI (hold requires net) complete");
}

/**
 * @brief Test wallet shared info CLI command - requires net/chain
 * 
 * Tests that info subcommand requires -net and -chain.
 */
static void test_wallet_shared_cli_info_requires_net(void)
{
    dap_print_module_name("wallet shared CLI (info requires net)");
    
    // Setup mocks
    s_reset_mocks();
    DAP_MOCK_SET_RETURN(dap_chain_wallet_get_path, (intptr_t)TEST_WALLETS_DIR);
    
    // Mock net_by_name to return NULL (network not found)
    DAP_MOCK_SET_RETURN(dap_chain_net_by_name, (intptr_t)NULL);
    
    // Test: shared info without -net (should fail)
    {
        char *l_argv[] = {"wallet", "shared", "info", "-tx", "somehash", NULL};
        int l_argc = 5;
        
        dap_json_t *l_json_reply = dap_json_array_new();
        int l_ret = s_execute_cli_command("wallet", l_argc, l_argv, l_json_reply, 2);
        
        log_it(L_DEBUG, "wallet shared info (no net) returned: %d", l_ret);
        
        const char *l_json_str = dap_json_to_string(l_json_reply);
        if (l_json_str) {
            log_it(L_DEBUG, "wallet shared info (no net) JSON: %s", l_json_str);
        }
        
        dap_assert(l_ret != 0, "wallet shared info without -net returns error");
        dap_assert(l_json_str != NULL, "JSON response exists");
        dap_assert(strstr(l_json_str, "net") != NULL || strstr(l_json_str, "chain") != NULL, 
                   "error mentions net or chain");
        
        dap_json_object_free(l_json_reply);
    }
    
    dap_pass_msg("wallet shared CLI (info requires net) complete");
}

/**
 * @brief Cleanup test wallets directory
 */
static void test_cleanup_test_wallets(void)
{
    dap_print_module_name("cleanup test wallets");
    
    s_remove_test_wallet("cliTestWallet_1");
    s_remove_test_wallet("cliTestWallet_2");
    s_remove_test_wallet("cliTestWalletProtected");  // from previous failed test runs
    s_cleanup_test_dir();
    
    dap_pass_msg("test wallets cleaned up");
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    
    // Initialize DAP subsystems
    dap_common_init("test_cli_wallet_mocked", NULL);
    
    // Initialize mock framework
    dap_mock_init();
    
    // Initialize wallet CLI commands
    dap_chain_wallet_cli_init();
    
    dap_print_module_name("CLI Wallet Tests with Mocking");
    printf("Testing wallet CLI with DAP Mock Framework\n\n");
    
    // Run CLI tests with real file creation
    test_wallet_new_cli_real();             // Creates wallets in /tmp/test_wallets_cli/
    test_wallet_list_cli_real();            // Lists wallets, should find the created ones
    test_wallet_info_cli_validation();      // Tests wallet info argument validation
    test_wallet_info_cli_with_mock_net();   // Tests wallet info with mocked network
    test_wallet_activate_deactivate_cli();  // Tests activate/deactivate cycle (mocked)
    test_wallet_activate_wrong_password();  // Tests activate with wrong password (mocked)
    test_wallet_activate_unprotected();     // Tests activate on unprotected wallet (mocked)
    test_wallet_convert_add_password();     // Tests convert with password (mocked)
    test_wallet_convert_already_protected();// Tests convert already protected wallet (mocked)
    test_wallet_convert_remove_password();  // Tests convert with -remove_password (mocked)
    test_wallet_convert_missing_password(); // Tests convert without password (error)
    test_wallet_convert_save_failure();     // Tests convert with save failure (mocked)
    test_wallet_outputs_cli_validation();   // Tests outputs argument validation
    test_wallet_outputs_cli_basic();        // Tests outputs basic listing (mocked)
    test_wallet_outputs_cli_with_value();   // Tests outputs with -value filter (mocked)
    test_wallet_outputs_cli_conditional();  // Tests outputs with -cond (mocked)
    test_wallet_outputs_cli_invalid_value();// Tests outputs with invalid -value (error)
    test_wallet_find_cli_validation();      // Tests find argument validation
    test_wallet_find_cli_success();         // Tests find wallet by address (mocked)
    test_wallet_find_cli_not_found();       // Tests find when no wallet matches
    test_wallet_shared_cli_validation();    // Tests shared argument validation
    test_wallet_shared_cli_list();          // Tests shared list (mocked)
    test_wallet_shared_cli_list_exclusive_params(); // Tests shared list exclusive params
    test_wallet_shared_cli_hold_requires_net(); // Tests shared hold requires net
    test_wallet_shared_cli_info_requires_net(); // Tests shared info requires net
    test_cleanup_test_wallets();            // Cleanup after tests
    
    printf("\n");
    dap_pass_msg("=== All mocked wallet CLI tests passed ===");
    
    // Cleanup
    dap_chain_wallet_cli_deinit();
    dap_mock_deinit();
    dap_common_deinit();
    
    return 0;
}
