#pragma once
#include "dap_enc_key.h"
void test_encode_decode(int count_steps, const dap_enc_key_type_t key_type, const int cipher_key_size);
void test_encode_decode_fast(int count_steps, const dap_enc_key_type_t key_type, const int cipher_key_size);

void dap_enc_tests_run(void);
