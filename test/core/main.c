#include "dap_config_test.h"
#include "dap_common_test.h"
#include "dap_network_monitor_test.h"
#include "dap_strfuncs_test.h"
#include "dap_common.h"


int main(void) {
    // switch off debug info from library
    set_log_level(L_CRITICAL);
    dap_strfuncs_tests_run();
    dap_config_tests_run();
    dap_common_test_run();
#ifdef __unix__
#include "dap_process_mem_test.h"
#include "dap_cpu_monitor_test.h"
#include "dap_network_monitor.h"
#include "dap_circular_test.h"
    dap_circular_test_run();
    dap_process_mem_test_run();
    dap_cpu_monitor_test_run();
    dap_network_monitor_test_run();
#endif
}
