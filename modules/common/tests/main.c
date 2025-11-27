#include "dap_struct_packing_tests.h"
#include "dap_chain_datum_tx_json_tests.h"

int main(void){
    dap_struct_packing_test_run();
    dap_chain_datum_tx_json_test_run();
    return 0;
}