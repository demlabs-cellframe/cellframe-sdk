/*
 * Cellframe SDK — centralized initialization / deinitialization
 *
 * Authors:
 *   Dmitry Gerasimov <ceo@cellframe.net>
 *   DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025-2026
 * License: GPLv3
 */

#include "cellframe-sdk.h"
#include "dap_common.h"
#include "dap_config.h"

#include "dap_chain.h"
#include "dap_chain_type_dag.h"
#include "dap_chain_type_dag_poa.h"
#include "dap_chain_type_blocks.h"
#include "dap_chain_type_none.h"
#include "dap_chain_cs_esbocs.h"

#include "dap_chain_net.h"
#include "dap_chain_policy.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_cache.h"
#include "dap_chain_wallet_shared.h"

#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_net_srv_voting.h"
#include "dap_chain_net_srv_bridge.h"
#include "dap_chain_net_srv_stake.h"
#include "dap_chain_net_srv_stake_ext.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_net_srv_order.h"

#include "dap_chain_mempool.h"
#include "dap_chain_node.h"
#include "dap_chain_net_node_list.h"
#include "dap_global_db.h"

#ifndef DAP_OS_WASM
#include "dap_chain_net_cli.h"
#include "dap_chain_token_cli.h"
#include "dap_chain_mempool_cli.h"
#include "dap_chain_ledger_cli.h"
#include "dap_chain_net_tx_cli.h"
#include "dap_chain_wallet_cli.h"
#include "dap_cert_cli.h"
#endif

#define LOG_TAG "cellframe_sdk"

static bool     s_initialized = false;
static uint32_t s_modules     = 0;

#define CF_INIT(flag, call, label) \
    if (l_modules & (flag)) { \
        if ((call) != 0) \
            return log_it(L_CRITICAL, "Cellframe SDK: failed to init " label), -1; \
    }

#define CF_INIT_WARN(flag, call, label) \
    if (l_modules & (flag)) { \
        if ((call) != 0) \
            log_it(L_ERROR, "Cellframe SDK: failed to init " label); \
    }

int cellframe_sdk_init(uint32_t a_modules)
{
    if (s_initialized) {
        log_it(L_WARNING, "Cellframe SDK already initialized");
        return 0;
    }

    uint32_t l_modules = a_modules;
    log_it(L_NOTICE, "Cellframe SDK init (modules 0x%08X)", l_modules);

    /* 1. Chain core — always required when any chain module is requested */
    if (l_modules & (CF_MODULE_CHAIN | CF_MODULE_NETWORK | CF_MODULE_WALLET)) {
        if (dap_chain_init() != 0)
            return log_it(L_CRITICAL, "dap_chain_init failed"), -1;
    }

    /* 2. Consensus types */
    CF_INIT(CF_MODULE_CONSENSUS_DAG,    dap_chain_type_dag_init(),      "DAG consensus");
    CF_INIT(CF_MODULE_CONSENSUS_POA,    dap_chain_type_dag_poa_init(),  "DAG-PoA consensus");
    CF_INIT(CF_MODULE_CONSENSUS_BLOCKS, dap_chain_type_blocks_init(),   "Blocks consensus");
    CF_INIT(CF_MODULE_CONSENSUS_ESBOCS, dap_chain_cs_esbocs_init(),     "ESBOCS consensus");
    CF_INIT(CF_MODULE_CONSENSUS_NONE,   dap_nonconsensus_init(),        "No-consensus");

    /* 3. Network */
    CF_INIT(CF_MODULE_NETWORK, dap_chain_net_init(), "chain net");

    /* 4. Policy */
    if (l_modules & CF_MODULE_NETWORK) {
        if (dap_chain_policy_init() != 0)
            return log_it(L_CRITICAL, "dap_chain_policy_init failed"), -1;
    }

    /* 5. Wallet */
    CF_INIT(CF_MODULE_WALLET, dap_chain_wallet_init(), "wallet");

    /* 6. Services */
    if (l_modules & (CF_MODULE_SRV_XCHANGE | CF_MODULE_SRV_VOTING | CF_MODULE_SRV_BRIDGE |
                     CF_MODULE_SRV_STAKE | CF_MODULE_SRV_STAKE_EXT)) {
        if (dap_chain_net_srv_init() != 0)
            return log_it(L_CRITICAL, "dap_chain_net_srv_init failed"), -1;
    }

    CF_INIT_WARN(CF_MODULE_SRV_STAKE,     dap_chain_net_srv_stake_pos_delegate_init(), "delegated PoS");
    CF_INIT_WARN(CF_MODULE_SRV_XCHANGE,   dap_chain_net_srv_xchange_init(),            "xchange");
    CF_INIT_WARN(CF_MODULE_SRV_VOTING,    dap_chain_net_srv_voting_init(),              "voting");
    CF_INIT_WARN(CF_MODULE_SRV_BRIDGE,    dap_chain_net_srv_bridge_init(),              "bridge");
    CF_INIT_WARN(CF_MODULE_SRV_STAKE_EXT, dap_chain_net_srv_stake_ext_init(),           "stake-ext");
    CF_INIT_WARN(CF_MODULE_SRV_STAKE,     dap_chain_net_srv_stake_init(),               "stake-lock");

    /* 7. CLI modules */
#ifndef DAP_OS_WASM
    if (l_modules & CF_MODULE_CLI) {
        dap_chain_net_cli_init();
        dap_chain_wallet_cli_init();
        dap_chain_token_cli_init();
        dap_chain_mempool_cli_init();
        dap_chain_ledger_cli_init();
        dap_chain_net_tx_cli_init();
        dap_cert_cli_init();
    }
#endif

    /* 8. Wallet cache (after CLI so wallet commands are registered) */
    CF_INIT(CF_MODULE_WALLET_CACHE, dap_chain_wallet_cache_init(), "wallet cache");

    /* 9. Load networks, mempool, housekeeping */
    if (l_modules & CF_MODULE_NETWORK)
        dap_chain_net_load_all();

    if (l_modules & CF_MODULE_MEMPOOL) {
        dap_chain_net_srv_order_init();
        if (dap_datum_mempool_init() != 0)
            log_it(L_ERROR, "dap_datum_mempool_init failed");
        dap_chain_node_list_clean_init();
        dap_global_db_clean_init();
        dap_chain_node_mempool_autoproc_init();
    }

    s_initialized = true;
    s_modules = l_modules;
    log_it(L_NOTICE, "Cellframe SDK initialized (modules 0x%08X)", s_modules);
    return 0;
}

void cellframe_sdk_deinit(void)
{
    if (!s_initialized) return;
    log_it(L_INFO, "Deinitializing Cellframe SDK (modules 0x%08X)", s_modules);

    if (s_modules & CF_MODULE_MEMPOOL)
        dap_chain_node_mempool_autoproc_deinit();

    if (s_modules & CF_MODULE_SRV_XCHANGE)
        dap_chain_net_srv_xchange_deinit();
    if (s_modules & CF_MODULE_SRV_STAKE) {
        dap_chain_net_srv_stake_pos_delegate_deinit();
        dap_chain_net_srv_stake_deinit();
    }
    if (s_modules & CF_MODULE_SRV_BRIDGE)
        dap_chain_net_srv_bridge_deinit();
    if (s_modules & CF_MODULE_SRV_VOTING)
        dap_chain_net_srv_voting_deinit();

    if (s_modules & CF_MODULE_NETWORK)
        dap_chain_net_deinit();

    if (s_modules & (CF_MODULE_CHAIN | CF_MODULE_NETWORK | CF_MODULE_WALLET))
        dap_chain_deinit();

    s_initialized = false;
    s_modules = 0;
    log_it(L_NOTICE, "Cellframe SDK deinitialized");
}

bool     cellframe_sdk_is_initialized(void) { return s_initialized; }
uint32_t cellframe_sdk_get_modules(void)    { return s_modules; }
