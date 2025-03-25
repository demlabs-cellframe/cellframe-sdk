
#include <stdio.h>
#include <stdlib.h>

#include "dap_jni_wrapper_tx_signer.h"

static const char *JNIT_CLASS = "DAPTxSigner";

jlong wrapper_jni_dap_chain_wallet_open_file(JNIEnv *env, jobject obj, jstring a_file_name, jstring a_pass, jlong a_out_stat)
{
    (void)obj;

    const char *l_file_name = (*env)->GetStringUTFChars(env, a_file_name, 0);
    const char *l_pass = (*env)->GetStringUTFChars(env, a_pass, 0);

    
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open_file(l_file_name, )
    
    return (jlong)
}