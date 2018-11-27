#include "dap_enc_iaes_test.h"
#include "dap_enc_base64_test.h"
#include "dap_enc_test.h"
#include "dap_enc_msrln_test.h"
#include "dap_enc_defeo_test.h"
#include "dap_enc_sig_bliss_test.h"
#include "rand/dap_rand.h"

#include "dap_common.h"

int main(void)
{
    // switch off debug info from library
    set_log_level(L_CRITICAL);
    dap_enc_aes_tests_run();
    dap_enc_base64_tests_run();
    dap_enc_msrln_tests_run();
    dap_enc_tests_run();
    dap_enc_sig_bliss_tests_run();
    dap_enc_defeo_tests_run();
}
