#include "dap_chain_ledger_tests.h"
void dap_chain_cell_offset_tests_run(void);

int main(void){
    // dap_ledger_test_run();
    dap_chain_cell_offset_tests_run();
    dap_chain_cell_realfile_tests_run();
    return 0;
}
