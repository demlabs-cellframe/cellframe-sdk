#include "dap_chain_ledger_tests.h"
int main(void){
    dap_log_level_set(L_WARNING);
    dap_log_set_external_output(LOGGER_OUTPUT_STDOUT, NULL);
    dap_ledger_test_run();
    return 0;
}
