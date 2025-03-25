#include <stdlib.h>
#include <jni.h>

#include "dap_chain_wallet.h"
/* Header for class ru_forwolk_test_JNIHelloWorld */

#ifdef __cplusplus
extern "C" {
#endif

jlong wrapper_jni_dap_chain_wallet_open_file(JNIEnv *env, jobject obj, const jstring a_file_name, const jstring a_pass, jlong a_out_stat);



JNIEXPORT void JNICALL Java_ru_forwolk_test_JNIHelloWorld_printHelloWorld
  (JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif

// dap_chain_wallet_open_file
// dap_chain_wallet_get_addr
// dap_get_data_hash_str
// dap_hash_fast
// dap_hex2bin
// dap_sign_type_to_key_type
// dap_enc_key_new_generate
// dap_sign_type_from_str
// dap_chain_addr_fill_from_key
// dap_enc_key_delete
// json_tokener_parse
// json_parse_input_tx
// dap_chain_net_tx_to_json
// s_wallet_create
// dap_chain_datum_tx_add_sign_item
// dap_chain_wallet_get_key
// dap_enc_key_delete