#include "dap_common_test.h"

void test_put_int() {
    const int INT_VAL = 10;
    const char * EXPECTED_RESULT = "10";
    char * result_arr = itoa(INT_VAL);
    assert(strcmp(result_arr, EXPECTED_RESULT) == 0 && "test_put_int failed");
}

void dap_common_test_run() {
    printf("Start running dap_common_test\n");
    test_put_int();
}
