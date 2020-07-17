#include "dap_test.h"
#include "dap_test_generator.h"
#include "dap_cellframe_sdk_init_test.h"

int main (){
    dap_print_module_name("First test. Test run");
    dap_assert_PIF((0 != 1) , " 0 != 1");
    dap_cellframe_sdk_init_test_run();
    return 0;
}
