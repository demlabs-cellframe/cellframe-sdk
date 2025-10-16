/**
 * @file test_ledger_fixtures.c
 * @brief Implementation of ledger test fixtures
 */

#include "test_ledger_fixtures.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain.h"
#include "dap_chain_cs.h"

#define LOG_TAG "test_ledger_fixtures"

/**
 * @brief Initialize minimal test network for fixture testing
 * @details Creates a simplified network without full consensus initialization
 * @param a_net_name Network name
 * @return dap_chain_net_t* or NULL on error
 */
static dap_chain_net_t *s_test_net_create_minimal(const char *a_net_name)
{
    // Try to initialize test network infrastructure if not already done
    dap_chain_net_test_init();
    
    // Get or create test network with ID 0xFA0
    dap_chain_net_id_t l_net_id = {.uint64 = 0x0FA0};
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_net_id);
    
    if (!l_net) {
        log_it(L_WARNING, "Could not create test network - network infrastructure may not be initialized");
        log_it(L_INFO, "Creating stub network fixture (limited functionality)");
        
        // Create a minimal stub for testing without full network initialization
        l_net = DAP_NEW_Z(dap_chain_net_t);
        if (!l_net) {
            return NULL;
        }
        l_net->pub.id = l_net_id;
        dap_strncpy(l_net->pub.name, a_net_name, sizeof(l_net->pub.name));
    }
    
    return l_net;
}

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
    
    // Create minimal test network
    l_fixture->net = s_test_net_create_minimal(a_net_name);
    if (!l_fixture->net) {
        log_it(L_ERROR, "Failed to create test network");
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Create ledger with token emission checking
    uint16_t l_flags = DAP_LEDGER_CHECK_TOKEN_EMISSION | DAP_LEDGER_CHECK_LOCAL_DS;
    l_fixture->ledger = dap_ledger_create(l_fixture->net, l_flags);
    if (!l_fixture->ledger) {
        log_it(L_ERROR, "Failed to create ledger");
        // Note: net cleanup handled by global infrastructure
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Link ledger to network
    l_fixture->net->pub.ledger = l_fixture->ledger;
    
    log_it(L_INFO, "Test network fixture created: %s (net_id=0x%016"DAP_UINT64_FORMAT_X")", 
           a_net_name, l_fixture->net->pub.id.uint64);
    return l_fixture;
}

void test_net_fixture_destroy(test_net_fixture_t *a_fixture)
{
    if (!a_fixture)
        return;

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

