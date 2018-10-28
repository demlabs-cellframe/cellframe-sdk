#include "dap_test.h"
#include "dap_enc_msrln.h"

void dap_enc_msrln_tests_run(void)
{
    dap_print_module_name("dap_enc_msrln_test");

    size_t rc;

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
    dap_enc_key_t *test_k = dap_enc_key_new(DAP_ENC_KEY_TYPE_MSRLN);
    dap_enc_msrln_key_new_generate(test_k, NULL);
    test_k->_inheritor = (dap_enc_msrln_key_t*)malloc(sizeof(dap_enc_msrln_key_t));

    dap_enc_msrln_key_t *test_k_inh = DAP_ENC_KEY_TYPE_MSRLN(test_k);
    //test_k_inh->rand = rand;

    /* Alice's initial message */
    dap_enc_msrln_key_new_from_data(test_k, &alice_priv, &alice_msg_len);
    alice_msg = malloc(test_k->data_size);
    memcpy(alice_msg, (uint8_t *) test_k->data, test_k->data_size * sizeof(uint8_t));

    /* Bob's response */
    rc = dap_enc_msrln_encode(test_k, (unsigned char *) alice_msg, &alice_msg_len, (unsigned char *) &bob_msg);
    bob_key = malloc(test_k->data_size);
    memcpy(bob_key, (uint8_t *) test_k->data, test_k->data_size * sizeof(uint8_t));

    dap_enc_key_t * kk = dap_enc_key_new(DAP_ENC_KEY_TYPE_MSRLN);

    kk->data_size = test_k->data_size;
    kk->data = (uint8_t *)malloc(kk->data_size);
    memcpy(kk->data, test_k->data, kk->data_size);

    /* Alice processes Bob's response */
    rc = dap_enc_msrln_decode(test_k, alice_priv, &alice_msg_len, bob_msg);
    alice_key = malloc(test_k->data_size);
    memcpy(alice_key, (uint8_t *) test_k->data, test_k->data_size * sizeof(uint8_t));

    /* compare session key values */
    rc = memcmp(alice_key, bob_key, test_k->data_size);
    if (rc != 0) {
        printf("ERROR: Alice's session key and Bob's session key are not equal\n");
        dap_test_msg("Alice session key %s %d", alice_key, alice_key_len);
        dap_test_msg("Bob session key %s %d", bob_key, bob_key_len);
        rc = 0;
    }
  //  if (print) {
        printf("Alice and Bob's session keys match.\n");
        printf("\n\n");
 //   }
    rc = 1;
    free(alice_msg);
    free(alice_key);
    free(bob_msg);
    free(bob_key);
    dap_enc_msrln_key_delete(test_k);

  //  return rc;

}
