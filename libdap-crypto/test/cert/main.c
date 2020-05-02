#include "dap_common.h"
#include "dap_crypto_cert_save_tests.h"

void dap_sha3_tests_run(void);

int main(void) {
    // switch off debug info from library
    dap_log_level_set(L_CRITICAL);
    dap_crypto_cert_save_tests_run();
    dap_sha3_tests_run();
    return 0;
}
