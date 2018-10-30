#include "dap_test.h"
#include "dap_enc_msrln.h"

static void key_transfer_simulation_test()
{
    void *alice_priv = NULL;
    uint8_t *alice_msg = NULL;
    size_t alice_msg_len;
    uint8_t *alice_key = NULL;
    size_t alice_key_len;

    uint8_t *bob_msg;
    size_t bob_msg_len;
    uint8_t *bob_key = NULL;
    size_t bob_key_len;

    // setup
//    dap_enc_key_t *test_k = dap_enc_key_new(DAP_ENC_KEY_TYPE_MSRLN);
//    dap_enc_msrln_key_new_generate(test_k, NULL);

    dap_enc_key_t* test_k = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_MSRLN, NULL, 0, NULL, 0, 0);
    //test_k_inh->rand = rand;

    /* Alice's initial message */
//    alice_msg = malloc(test_k->pub_key_data_size);
//    memcpy(alice_msg, (uint8_t *) test_k->pub_key_data, test_k->pub_key_data_size * sizeof(uint8_t));

    alice_msg = test_k->pub_key_data;

    // dap_enc_key_t bob_key =
    /* Bob's response */
    dap_enc_key_t* bob_key2 = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_MSRLN, NULL, 0, NULL, 0, 0);

    dap_enc_msrln_encode(test_k, (unsigned char *) alice_msg, &test_k->priv_key_data_size, (unsigned char *) &bob_msg);
    bob_key = malloc(test_k->pub_key_data_size);
    memcpy(bob_key, (uint8_t *) test_k->pub_key_data, test_k->pub_key_data_size * sizeof(uint8_t));

    dap_enc_key_t * kk = dap_enc_key_new(DAP_ENC_KEY_TYPE_MSRLN);

    kk->pub_key_data_size = test_k->pub_key_data_size;
    kk->pub_key_data = (uint8_t *)malloc(kk->pub_key_data_size);
    memcpy(kk->pub_key_data, test_k->pub_key_data, kk->pub_key_data_size);

    /* Alice processes Bob's response */
    dap_enc_msrln_decode(test_k, test_k->priv_key_data, &test_k->priv_key_data_size, bob_msg);
    alice_key = malloc(test_k->pub_key_data_size);
    memcpy(alice_key, (uint8_t *) test_k->pub_key_data, test_k->pub_key_data_size * sizeof(uint8_t));

    /* compare session key values */
    dap_assert(memcmp(alice_key, bob_key, test_k->pub_key_data_size) == 0, "Session keys equals");

    free(alice_msg);
    free(alice_key);
    free(bob_msg);
    free(bob_key);
    dap_enc_msrln_key_delete(test_k);

    dap_pass_msg("Key transfer simulation");
}

void dap_enc_msrln_tests_run(void)
{
    dap_print_module_name("dap_enc_msrln_test");

    key_transfer_simulation_test();
  //  return rc;

}
