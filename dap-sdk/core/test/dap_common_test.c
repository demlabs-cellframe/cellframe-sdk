#include "dap_common_test.h"

void test_put_int() {
    const int INT_VAL = 10;
    const char * EXPECTED_RESULT = "10";
    char * result_arr = dap_itoa(INT_VAL);
    dap_assert(strcmp(result_arr, EXPECTED_RESULT) == 0,
               "Check string result from itoa");
}

void dap_common_test_run() {
    dap_print_module_name("dap_common");
    test_put_int();
}
