#include "dap_enc_sig_bliss_test.h"

static void message_signature_simulation_test()
{    
    dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_BLISS, NULL, 0, NULL, 0, 0);

    bliss_signature_t signature;

    char* text = "The message for test BLISS signature";
    uint8_t* msg = (uint8_t*)text;
    size_t msg_size = strlen(text);

    dap_assert(dap_enc_sig_bliss_get_sign( key, msg, msg_size, &signature, sizeof(signature)) == BLISS_B_NO_ERROR,
               "Sign msg");

    dap_assert(dap_enc_sig_bliss_verify_sign( key, msg, msg_size, &signature, sizeof(signature)) == BLISS_B_NO_ERROR,
               "Verify msg")

    bliss_signature_delete(&signature);
    dap_enc_key_delete(key);

    fflush(stdout);
}

void dap_enc_sig_bliss_tests_run(void)
{
    dap_print_module_name("dap_enc_sig_bliss_tests");
    message_signature_simulation_test();
}
