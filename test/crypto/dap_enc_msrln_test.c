#include "dap_test.h"
#include "dap_enc_msrln.h"

static void key_transfer_simulation_test()
{
    uint8_t *alice_msg;
    size_t alice_msg_len;

    uint8_t *bob_msg;
    size_t bob_msg_len;

    dap_enc_key_t* alice_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_MSRLN, NULL, 0, NULL, 0, 0);

    // generate Alice msg
    alice_msg = alice_key->pub_key_data;
    alice_msg_len = alice_key->pub_key_data_size;

    /* generate Bob's response */
    dap_enc_key_t* bob_key = dap_enc_key_new(DAP_ENC_KEY_TYPE_MSRLN);
    bob_key->gen_bob_shared_key(bob_key, alice_msg, alice_msg_len, (void**)&bob_key->pub_key_data);
    bob_msg = bob_key->pub_key_data;
    bob_msg_len = bob_key->pub_key_data_size;

    /* Alice processes Bob's response */
    alice_key->gen_alice_shared_key(alice_key, alice_key->priv_key_data, bob_msg_len, bob_msg);

    /* compare session key values */
    dap_assert(memcmp(alice_key->priv_key_data, bob_key->priv_key_data, alice_key->priv_key_data_size) == 0, "Session keys equals");

    dap_enc_key_delete(alice_key);
    dap_enc_key_delete(bob_key);

    dap_pass_msg("Key transfer simulation");
}

void dap_enc_msrln_tests_run(void)
{
    dap_print_module_name("dap_enc_msrln_test");

    key_transfer_simulation_test();
}
