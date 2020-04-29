#include "dap_enc_base64_test.h"
#include "dap_enc_base58_test.h"
#include "dap_enc_test.h"
#include "dap_enc_msrln_test.h"
#include "dap_enc_defeo_test.h"
#include "dap_enc_sig_bliss_test.h"
#include "dap_enc_picnic_test.h"
#include "dap_enc_tesla_test.h"
#include "dap_enc_dilithium_test.h"
#include "dap_enc_ringct20_test.h"
#include "dap_enc_sign_multi_test.h"
#include "rand/dap_rand.h"

#include "dap_common.h"

int main(void)
{
 // switch off debug info from library
    dap_log_level_set(L_CRITICAL);

    test_encypt_decrypt      (1000, DAP_ENC_KEY_TYPE_GOST_OFB,   32);
    test_encypt_decrypt_fast (1000, DAP_ENC_KEY_TYPE_GOST_OFB,   32);
    test_encypt_decrypt      (1000, DAP_ENC_KEY_TYPE_KUZN_OFB,  32);
    test_encypt_decrypt_fast (1000, DAP_ENC_KEY_TYPE_KUZN_OFB,  32);
    return 0;
    dap_enc_ringct20_tests_run(10);
    dap_enc_tests_run();

    test_encypt_decrypt      (1000, DAP_ENC_KEY_TYPE_BF_CBC,     0);
    test_encypt_decrypt_fast (1000, DAP_ENC_KEY_TYPE_BF_CBC,     0);
    test_encypt_decrypt      (1000, DAP_ENC_KEY_TYPE_BF_OFB,     0);
    test_encypt_decrypt_fast (1000, DAP_ENC_KEY_TYPE_BF_OFB,     0);
    test_encypt_decrypt      (1000, DAP_ENC_KEY_TYPE_IAES,       32);
    test_encypt_decrypt_fast (1000, DAP_ENC_KEY_TYPE_IAES,       32);
    test_encypt_decrypt      (1000, DAP_ENC_KEY_TYPE_OAES,       32);
    test_encypt_decrypt_fast (1000, DAP_ENC_KEY_TYPE_OAES,       32);

    dap_enc_picnic_tests_run();
    dap_enc_sig_bliss_tests_run();
    dap_enc_dilithium_tests_run();

    dap_enc_base64_tests_run();
    dap_enc_base58_tests_run();
    dap_enc_msrln_tests_run();
    dap_enc_defeo_tests_run();
    dap_enc_tesla_tests_run();
    dap_enc_multi_sign_tests_run();

}
