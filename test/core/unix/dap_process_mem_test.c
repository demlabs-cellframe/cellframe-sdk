#include "dap_process_mem_test.h"
#include "dap_process_memory.h"

void test_current_process()
{
    dap_process_memory_t mem = get_proc_mem_current();
    dap_assert(mem.vsz != 0, "Check vsz current process");
    dap_assert(mem.rss != 0, "Check rss current process ");
}

void test_nonexistent_process()
{
    dap_process_memory_t mem = get_proc_mem_by_pid(-1);
    dap_assert(mem.vsz == 0, "Check vsz nonexistent process");
    dap_assert(mem.rss == 0, "Check rss nonexistent process");
}

void dap_process_mem_test_run()
{
    dap_print_module_name("dap_process_memory");
    test_current_process();
    test_nonexistent_process();
}
