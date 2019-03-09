#include "dap_common.h"
#include "dap_chain_cert_save_tests.h"

int main(void) {
    // switch off debug info from library
    set_log_level(L_CRITICAL);
    dap_chain_cert_save_tests_run();
    return 0;
}
