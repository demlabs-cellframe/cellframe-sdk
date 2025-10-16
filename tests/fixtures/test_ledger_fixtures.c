/**
 * @file test_ledger_fixtures.c
 * @brief Implementation of ledger test fixtures
 */

#include "test_ledger_fixtures.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag_poa.h"

#define LOG_TAG "test_ledger_fixtures"

test_net_fixture_t *test_net_fixture_create(const char *a_net_name)
{
    if (!a_net_name) {
        log_it(L_ERROR, "Network name is NULL");
        return NULL;
    }

    test_net_fixture_t *l_fixture = DAP_NEW_Z(test_net_fixture_t);
    if (!l_fixture) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }

    l_fixture->net_name = dap_strdup(a_net_name);
    
    // Initialize test network infrastructure
    dap_chain_net_test_init();
    
    // Get or create test network with ID 0xFA0
    dap_chain_net_id_t l_net_id = {.uint64 = 0x0FA0};
    l_fixture->net = dap_chain_net_by_id(l_net_id);
    
    if (!l_fixture->net) {
        log_it(L_ERROR, "Failed to get test network");
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Create ledger with token emission checking
    uint16_t l_flags = DAP_LEDGER_CHECK_TOKEN_EMISSION | DAP_LEDGER_CHECK_LOCAL_DS;
    l_fixture->ledger = dap_ledger_create(l_fixture->net, l_flags);
    if (!l_fixture->ledger) {
        log_it(L_ERROR, "Failed to create ledger");
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Link ledger to network
    l_fixture->net->pub.ledger = l_fixture->ledger;
    
    // Create zero chain (like in production networks)
    char l_zero_chain_name[128];
    snprintf(l_zero_chain_name, sizeof(l_zero_chain_name), "%s_zero", a_net_name);
    l_fixture->chain_zero = dap_chain_create(
        l_fixture->net->pub.name,
        l_zero_chain_name,
        l_fixture->net->pub.id,
        (dap_chain_id_t){.uint64 = 0}
    );
    
    if (!l_fixture->chain_zero) {
        log_it(L_ERROR, "Failed to create zero chain");
        dap_ledger_handle_free(l_fixture->ledger);
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Create consensus for zero chain (DAG PoA)
    if (dap_chain_cs_type_create("dag_poa", l_fixture->chain_zero, NULL) != 0) {
        log_it(L_ERROR, "Failed to create consensus for zero chain");
        dap_chain_delete(l_fixture->chain_zero);
        dap_ledger_handle_free(l_fixture->ledger);
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Add zero chain to network
    DL_APPEND(l_fixture->net->pub.chains, l_fixture->chain_zero);
    
    // Create master/main chain (like in production networks)
    char l_main_chain_name[128];
    snprintf(l_main_chain_name, sizeof(l_main_chain_name), "%s_master", a_net_name);
    l_fixture->chain_main = dap_chain_create(
        l_fixture->net->pub.name,
        l_main_chain_name,
        l_fixture->net->pub.id,
        (dap_chain_id_t){.uint64 = 1}
    );
    
    if (!l_fixture->chain_main) {
        log_it(L_ERROR, "Failed to create master chain");
        // Cleanup zero chain
        DL_DELETE(l_fixture->net->pub.chains, l_fixture->chain_zero);
        dap_chain_delete(l_fixture->chain_zero);
        dap_ledger_handle_free(l_fixture->ledger);
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Create consensus for master chain (ESBOCS)
    if (dap_chain_cs_type_create("esbocs", l_fixture->chain_main, NULL) != 0) {
        log_it(L_ERROR, "Failed to create consensus for master chain");
        dap_chain_delete(l_fixture->chain_main);
        DL_DELETE(l_fixture->net->pub.chains, l_fixture->chain_zero);
        dap_chain_delete(l_fixture->chain_zero);
        dap_ledger_handle_free(l_fixture->ledger);
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Add master chain to network
    DL_APPEND(l_fixture->net->pub.chains, l_fixture->chain_main);
    
    log_it(L_INFO, "Test network fixture created: %s (net_id=0x%016"DAP_UINT64_FORMAT_X") with zero and master chains", 
           a_net_name, l_fixture->net->pub.id.uint64);
    return l_fixture;
}

void test_net_fixture_destroy(test_net_fixture_t *a_fixture)
{
    if (!a_fixture)
        return;

    // Remove chains from network and delete them
    if (a_fixture->chain_main) {
        DL_DELETE(a_fixture->net->pub.chains, a_fixture->chain_main);
        dap_chain_delete(a_fixture->chain_main);
        a_fixture->chain_main = NULL;
    }
    
    if (a_fixture->chain_zero) {
        DL_DELETE(a_fixture->net->pub.chains, a_fixture->chain_zero);
        dap_chain_delete(a_fixture->chain_zero);
        a_fixture->chain_zero = NULL;
    }
    
    // Cleanup ledger
    if (a_fixture->ledger) {
        dap_ledger_handle_free(a_fixture->ledger);
        a_fixture->ledger = NULL;
    }
    
    // Note: Network cleanup is handled by global network infrastructure
    // Don't delete the network directly as it may be shared
    
    DAP_DELETE(a_fixture->net_name);
    DAP_DELETE(a_fixture);
    
    log_it(L_INFO, "Test network fixture destroyed");
}
