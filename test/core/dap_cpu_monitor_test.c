#include "dap_cpu_monitor_test.h"
#include "dap_cpu_monitor.h"
#include "unistd.h"

static void init_test_case()
{
    dap_assert(dap_cpu_monitor_init() == 0, "Cpu module init");
}

static void deinit_test_case()
{
    dap_cpu_monitor_deinit();
}

static void test_cpu_get_stats()
{
    dap_cpu_stats_t stat = dap_cpu_get_stats();
    dap_assert(stat.cpu_cores_count > 0, "Check cpu count");
    dap_assert(stat.cpu_summary.total_time > 0, "Check cpu summary total_time");
    dap_assert(stat.cpu_summary.total_time > 0, "Check cpu summary idle_time");
    dap_assert(stat.cpu_cores_count > 0, "Check cpu count");
    for(unsigned i = 0; i < stat.cpu_cores_count; i++) {
        dap_assert_PIF(stat.cpus[i].ncpu == i, "Check ncpu and index in array");
        dap_assert_PIF(stat.cpus[i].idle_time > 0, "Check cpu idle_time");
        dap_assert_PIF(stat.cpus[i].total_time > 0, "Check cpu total_time");
    }
}

void dap_cpu_monitor_test_run()
{
    dap_print_module_name("dap_cpu_monitor");
    init_test_case();
    usleep(1000); // wait for new cpu parameters
    test_cpu_get_stats();

    dap_cpu_get_stats();
    deinit_test_case();
}
