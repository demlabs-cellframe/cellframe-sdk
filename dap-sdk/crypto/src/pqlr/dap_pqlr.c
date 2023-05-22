#include <assert.h>

// Contains common functions of PQLR library.
#include <pqlr/common/pqlr.h>
#include <pqlr/common/sei.h>
#include <pqlr/common/error_handler.h>
#include <pqlr/common/version.h>

#include "dap_common.h"
#include "dap_enc_key.h"

#define LOG_TAG "pqlr"

#include "dap_pqlr.h"
#include "dap_pqlr_dilithium.h"
#include "dap_pqlr_falcon.h"
#include "dap_pqlr_sphincs.h"
#include "dap_pqlr_saber.h"
#include "dap_pqlr_mceliece.h"
#include "dap_pqlr_newhope.h"

static pqlr_t s_pqlr;

/**
 * @brief dap_pqlr_init
 * @param a_callbacks
 * @return
 */
int dap_pqlr_init(dap_enc_key_callbacks_t * a_callbacks)
{
    assert(a_callbacks);
    s_pqlr = pqlr_singleton_instance();

    dap_enc_key_callbacks_t l_sig_dilithium={
            .name = "PQLR_SIG_DILITHIUM",

            .new_callback = dap_pqlr_dilithium_key_new,
            .new_generate_callback = dap_pqlr_dilithium_key_new_generate,
            .delete_callback = dap_pqlr_dilithium_key_delete,

            .enc_na = dap_pqlr_dilithium_create_sign,
            .dec_na = dap_pqlr_dilithium_verify_sign,
        };

    dap_enc_key_callbacks_t l_sig_sphincs={
            .name = "PQLR_SIG_SPHINCS",

            .new_callback = dap_pqlr_sphincs_key_new,
            .new_generate_callback = dap_pqlr_sphincs_key_new_generate,
            .delete_callback = dap_pqlr_sphincs_key_delete,

            .enc_na = dap_pqlr_sphincs_create_sign,
            .dec_na = dap_pqlr_sphincs_verify_sign,
        };

    dap_enc_key_callbacks_t l_sig_falcon={
            .name = "PQLR_SIG_FALCON",

            .new_callback = dap_pqlr_falcon_key_new,
            .new_generate_callback = dap_pqlr_falcon_key_new_generate,
            .delete_callback = dap_pqlr_falcon_key_delete,

            .enc_na = dap_pqlr_falcon_create_sign,
            .dec_na = dap_pqlr_falcon_verify_sign,
        };

    dap_enc_key_callbacks_t l_kem_saber={
            .name = "PQLR_KEM_SABER",

            .new_callback = dap_pqlr_saber_key_new,
            .new_generate_callback = dap_pqlr_saber_key_new_generate,
            .delete_callback = dap_pqlr_saber_key_delete,

        };

    dap_enc_key_callbacks_t l_kem_mceliece={
            .name = "PQLR_KEM_MCELIECE",

            .new_callback = dap_pqlr_mceliece_key_new,
            .new_generate_callback = dap_pqlr_mceliece_key_new_generate,
            .delete_callback = dap_pqlr_mceliece_key_delete,
        };

    dap_enc_key_callbacks_t l_kem_newhope={
            .name = "PQLR_KEM_NEWHOPE",

            .new_callback = dap_pqlr_newhope_key_new,
            .new_generate_callback = dap_pqlr_newhope_key_new_generate,
            .delete_callback = dap_pqlr_newhope_key_delete,
        };

    a_callbacks[DAP_ENC_KEY_TYPE_PQLR_SIG_DILITHIUM] = l_sig_dilithium;
    a_callbacks[DAP_ENC_KEY_TYPE_PQLR_SIG_FALCON] = l_sig_falcon;
    a_callbacks[DAP_ENC_KEY_TYPE_PQLR_SIG_SPHINCS] = l_sig_sphincs;
    a_callbacks[DAP_ENC_KEY_TYPE_PQLR_KEM_SABER] = l_kem_saber;
    a_callbacks[DAP_ENC_KEY_TYPE_PQLR_KEM_MCELIECE] = l_kem_mceliece;
    a_callbacks[DAP_ENC_KEY_TYPE_PQLR_KEM_NEWHOPE] = l_kem_newhope;
    return 0;
}

/**
 * @brief dap_pqlr_deinit
 */
void dap_pqlr_deinit()
{

}
