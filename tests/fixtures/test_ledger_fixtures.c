/**
 * @file test_ledger_fixtures.c
 * @brief Implementation of ledger test fixtures
 */

#include "test_ledger_fixtures.h"
#include "dap_common.h"
#include "dap_config.h"

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
    
    // TODO: Initialize test network (placeholder)
    // l_fixture->net = dap_chain_net_create_test(a_net_name);
    // l_fixture->ledger = dap_ledger_create(l_fixture->net, DAP_LEDGER_CHECK_LOCAL_DS);
    
    log_it(L_INFO, "Test network fixture created: %s", a_net_name);
    return l_fixture;
}

void test_net_fixture_destroy(test_net_fixture_t *a_fixture)
{
    if (!a_fixture)
        return;

    // TODO: Cleanup network and ledger
    // if (a_fixture->ledger)
    //     dap_ledger_handle_free(a_fixture->ledger);
    // if (a_fixture->net)
    //     dap_chain_net_delete(a_fixture->net);

    DAP_DELETE(a_fixture->net_name);
    DAP_DELETE(a_fixture);
    
    log_it(L_INFO, "Test network fixture destroyed");
}

