/**
 * @file dex_test_main.c
 * @brief Main entry point for DEX integration tests
 */

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include "dex_test_fixture.h"
#include "dex_lifecycle_tests.h"
#include "dap_config.h"
#include "dap_enc.h"
#include "dap_test.h"
#include "dap_chain_wallet.h"

extern int dap_chain_cs_dag_init(void);
extern int dap_chain_cs_dag_poa_init(void);
extern int dap_chain_cs_esbocs_init(void);

// ============================================================================
// SETUP / TEARDOWN
// ============================================================================

static void s_setup(bool a_cache) {
    log_it(L_NOTICE, "=== DEX Integration Tests Setup ===");
    
    const char *l_config_dir = "/tmp/dex_integration_test_config";
    mkdir(l_config_dir, 0755);
    
    const char *l_config_content = a_cache ?
        "[general]\ndebug_mode=true\n[srv_dex]\nmemcached=true\n" :
        "[general]\ndebug_mode=true";
    
    char l_config_path[256], l_log_path[100];
    snprintf(l_config_path, sizeof(l_config_path), "%s/test.cfg", l_config_dir);
    FILE *l_config_file = fopen(l_config_path, "w");
    if (l_config_file) {
        fwrite(l_config_content, 1, strlen(l_config_content), l_config_file);
        fclose(l_config_file);
    }
    
    dap_config_init(l_config_dir);
    g_config = dap_config_open("test");
    dap_assert(g_config != NULL, "Config initialization");
    snprintf(l_log_path, sizeof(l_log_path), "%s/%s", l_config_dir, "log.txt");
    dap_common_init(NULL, l_log_path);
    
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    
    log_it(L_NOTICE, "Test environment initialized");
}

static void s_teardown(void) {
    log_it(L_NOTICE, "Cleaning up test environment...");
    
    if (g_config) {
        dap_config_close(g_config);
        g_config = NULL;
    }
    dap_config_deinit();
    
    unlink("/tmp/dex_integration_test_config/test.cfg");
    rmdir("/tmp/dex_integration_test_config");
    
    log_it(L_NOTICE, "Cleanup completed");
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    
    dap_test_msg("DEX Integration Tests");
    
    dap_log_level_set(L_DEBUG);
    dap_log_set_external_output(LOGGER_OUTPUT_STDOUT, NULL);
    dap_enc_init();
    dap_chain_wallet_init();
    
    s_setup(false);
    
    dex_test_fixture_t *fixture = dex_test_fixture_create();
    if (!fixture) {
        log_it(L_ERROR, "Failed to create test fixture");
        s_teardown();
        return 1;
    }
    
    dex_print_balances(fixture, "INITIAL STATE");
    
    // Run lifecycle tests (create, buy, partial, rollback, cancel)
    int ret = run_lifecycle_tests(fixture);
    if (ret != 0) {
        log_it(L_ERROR, "Lifecycle tests FAILED with code %d", ret);
        dex_test_fixture_destroy(fixture);
        s_teardown();
        return ret;
    }
    
    // TODO: Add when implemented
    // run_automatch_tests(fixture);
    // run_leftover_tests(fixture);
    // run_operations_tests(fixture);
    
    dex_test_fixture_destroy(fixture);
    s_teardown();
    
    dap_test_msg("All integration tests completed");
    return 0;
}
