#include "dap_config_test.h"
#include "dap_common_test.h"
#ifndef _WIN32
#ifdef  DAP_OS_UNIX
#include "dap_circular_test.h"
#include "dap_process_mem_test.h"
#include "dap_cpu_monitor_test.h"
#ifndef DAP_NETWORK_MONITOR_TEST_OFF
#include "dap_network_monitor.h"
#include "dap_network_monitor_test.h"
#endif
#endif
#endif
#include "dap_strfuncs_test.h"
#include "dap_common.h"


int main(void) {
    // switch off debug info from library
    dap_log_level_set(L_CRITICAL);
    dap_strfuncs_tests_run();
    dap_config_tests_run();
    dap_common_test_run();
#ifdef DAP_OS_UNIX
    dap_circular_test_run();
    dap_process_mem_test_run();
    dap_cpu_monitor_test_run();
#ifndef DAP_NETWORK_MONITOR_TEST_OFF
    dap_network_monitor_test_run();
#endif
#endif
}
