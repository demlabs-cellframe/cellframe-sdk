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

void dap_cpu_monitor_test_run()
{
    dap_print_module_name("dap_cpu_monitor");
    init_test_case();
//    while (1) {
//        dap_cpu_stats_t s = dap_cpu_get_stats();
//        printf("Summary average load %f\n", s.cpu_summary.load);

//        for(int i = 0; i < s.cpu_cores_count; i++) {
//            printf("Core %d load %f \n", i + 1, s.cpus[i].load);
//        }
//        fflush(stdout);
//        sleep(1);
//    }

    dap_cpu_get_stats();
    deinit_test_case();
}
