#include "dap_enc_kyber_test.h"

void key_kem_kyber512_transfer_simulation_test(void){
    dap_enc_key_t *alice_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_KEM_KYBER512, NULL, 0, NULL, 0, 0);
    uint8_t *alice_pkey = alice_key->pub_key_data;
    size_t alice_pkey_size = alice_key->pub_key_data_size;

//    dap_enc_key_t *bob_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_KEM_KYBER512, NULL, 0, NULL, 0, 0);
    dap_enc_key_t *bob_key = dap_enc_key_new(DAP_ENC_KEY_TYPE_KEM_KYBER512);
    bob_key->gen_bob_shared_key(bob_key, alice_pkey, alice_pkey_size, (void**)&bob_key->pub_key_data);
    uint8_t *bob_pkey = bob_key->pub_key_data;
    size_t bob_pkey_size = bob_key->pub_key_data_size;

    alice_key->gen_alice_shared_key(alice_key, alice_key->priv_key_data, bob_pkey_size, bob_pkey);

    dap_assert(memcmp(alice_key->shared_key, bob_key->shared_key, alice_key->shared_key_size) == 0, "Session keys equals");
}

int dap_enc_kyber_test_run(void) {
    dap_print_module_name("dap_enc_kyber_test_kem_kyber512");
    key_kem_kyber512_transfer_simulation_test();
}