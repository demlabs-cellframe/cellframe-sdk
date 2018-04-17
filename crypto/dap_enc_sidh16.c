#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "dap_enc_sidh16.h"
#include "dap_enc_key.h"

#include <../libdap/core/dap_common.h>
#include <../libdap/crypto/liboqs/kex_sidh_cln16/kex_sidh_cln16.h>
#include <../libdap/crypto/liboqs/kex_sidh_cln16/SIDH.h>

static const char *P751 = "p751";
static const char *CompressedP751 = "compressedp751";

static int isCompressed(void *_inheritor) {
    if (_inheritor != NULL && strcmp(_inheritor, CompressedP751) == 0) {
        return 1;
    }
    return 0;
}

extern bool dap_sidh16_CurveIsogenyStruct_isnull(PCurveIsogenyStruct pCurveIsogeny);

dap_enc_key_t *dap_enc_sidh16_key_new_generate(struct dap_enc_key *a_key, size_t a_size) {
    dap_enc_key_t *k = DAP_NEW(dap_enc_key_t);
    dap_enc_sidh16_key_t *sidh_a_key = DAP_ENC_SIDH16_KEY(a_key);
    if(k == NULL)
        return NULL;
    // инициализация системы изогенных кривых
    PCurveIsogenyStruct curveIsogeny = oqs_sidh_cln16_curve_allocate(&CurveIsogeny_SIDHp751);
    if(curveIsogeny == NULL || dap_sidh16_CurveIsogenyStruct_isnull(curveIsogeny)) {
        DAP_DELETE(k);
        // освобождаем память для изогении
        oqs_sidh_cln16_curve_free(curveIsogeny);
        return NULL;
    }
    // Инициализировать изогенную структуру кривой pCurveIsogeny со статическими данными, извлеченными из pCurveIsogenyData. 
    // Это нужно вызвать после выделения памяти для pCurveIsogeny с помощью SIDH_curve_allocate()
    if(oqs_sidh_cln16_curve_initialize(curveIsogeny, &CurveIsogeny_SIDHp751) != SIDH_CRYPTO_SUCCESS) {
        DAP_DELETE(k);
        oqs_sidh_cln16_curve_free(curveIsogeny);
        return NULL;
    }
    k->data;
    k->data_size;
    k->type = DAP_ENC_KEY_TYPE_SIDH_CLN16;
    k->last_used_timestamp;
    k->enc = &dap_enc_sidh16_encode;
    k->dec = &dap_enc_sidh16_decode;
    k->delete_callback = &dap_enc_sidh16_key_delete;

    sidh_a_key->rand;
    sidh_a_key->user_curveIsogeny;
    return k;

}


void dap_enc_sidh16_key_new_from_data(struct dap_enc_key *a_key, const void *a_in, size_t a_in_size) {
    
}

void dap_enc_sidh16_key_delete(struct dap_enc_key *a_key) {
    dap_enc_sidh16_key_t *sidh_a_key = DAP_ENC_SIDH16_KEY(a_key);
    (void) a_key;
    if(!a_key){
        return;
    }
    oqs_sidh_cln16_curve_free((PCurveIsogenyStruct)sidh_a_key->user_curveIsogeny);
    sidh_a_key->user_curveIsogeny = NULL;
    DAP_DELETE(a_key);
}


// alice_0
size_t dap_enc_sidh16_encode(struct dap_enc_key *a_key, const void *a_in, size_t a_in_size, void *a_out) {
    int ret;
    dap_enc_sidh16_key_t *sidh_a_key = DAP_ENC_SIDH16_KEY(a_key);
    // non-compressed public key
    uint8_t *key_a_tmp_pub = NULL;
    if(!a_key || !a_in || !a_in_size || !a_out)
        return 0;

    int compressed = isCompressed(a_key->_inheritor);
    if(compressed) {
        key_a_tmp_pub = malloc(SIDH_PUBKEY_LEN);
        a_key->data = malloc(SIDH_COMPRESSED_PUBKEY_LEN);
        if(key_a_tmp_pub == NULL || a_in == NULL) {
            ret = 0;
            DAP_DELETE(a_key->data);
            a_in = NULL;
            a_key->data = NULL;
        }
    }
    else {
        // non-compressed key
         a_key->data = malloc(SIDH_PUBKEY_LEN);
         if(a_key->data == NULL) {
             ret = 0;
             DAP_DELETE(a_key->data = NULL);
             a_key->data = NULL;
             a_in = NULL;
         }
         key_a_tmp_pub = a_key->data;
    }
    a_in = malloc(SIDH_SECRETKEY_LEN);
    if(a_in == NULL) {
        ret = 0;
        DAP_DELETE(a_key->data = NULL);
        a_key->data = NULL;
        a_in = NULL;
    }

    // generate A key pair
    if(oqs_sidh_cln16_EphemeralKeyGeneration_A((unsigned char *)a_in, (unsigned char *)key_a_tmp_pub, sidh_a_key->user_curveIsogeny, sidh_a_key->rand) != SIDH_CRYPTO_SUCCESS) {
        ret = 0;
        DAP_DELETE(a_key->data = NULL);
        a_key->data = NULL;
        a_in = NULL;
    }
    if (compressed) {
        // compress Alice's public key
        oqs_sidh_cln16_PublicKeyCompression_A(key_a_tmp_pub, (unsigned char *) a_in, sidh_a_key->user_curveIsogeny);
        a_in_size = SIDH_COMPRESSED_PUBKEY_LEN;
    } else {
        a_in_size = SIDH_PUBKEY_LEN;
        key_a_tmp_pub = NULL;
    }

    ret = 1;
    DAP_DELETE(key_a_tmp_pub);
    return ret;
}



// int OQS_KEX_sidh_cln16_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len)
size_t dap_enc_sidh16_decode(struct dap_enc_key *a_key, const void *a_in, size_t a_in_size, void *a_out) {
    size_t ret;
    dap_enc_sidh16_key_t *sidh_a_key = DAP_ENC_SIDH16_KEY(a_key);
    uint8_t *bob_priv = NULL;
    // non-compressed public key
    uint8_t *bob_tmp_pub = NULL;
    // decompession values
    unsigned char *R = NULL, *A = NULL;

    if(!a_key || !a_in || !a_out){
        return 0;
    }

    a_out = NULL;
    a_key->data = NULL;

    int compressed = isCompressed(a_key->_inheritor);

    if(compressed) {
        if(sidh_a_key->alice_msg_len != SIDH_COMPRESSED_PUBKEY_LEN) {
            ret = 0;
            DAP_DELETE(a_out);
            a_out = NULL;
            DAP_DELETE(a_key->data);
            a_key->data = NULL;
        }
        bob_tmp_pub = malloc(SIDH_PUBKEY_LEN);
        a_out = malloc(SIDH_COMPRESSED_PUBKEY_LEN);
        if(bob_tmp_pub == NULL || a_out == NULL) {
            ret = 0;
            DAP_DELETE(a_out);
            a_out = NULL;
            DAP_DELETE(a_key->data);
            a_key->data = NULL;
        }
        A = malloc(SIDH_COMPRESSED_A_LEN);
        if(A == NULL) {
            ret = 0;
            DAP_DELETE(a_out);
            a_out = NULL;
            DAP_DELETE(a_key->data);
            a_key->data = NULL;
        }
        R = malloc(SIDH_COMPRESSED_R_LEN);
        if(R == NULL) {
            ret = 0;
            DAP_DELETE(a_out);
            a_out = NULL;
            DAP_DELETE(a_key->data);
            a_key->data = NULL;
        }
    }
    else {
        if(sidh_a_key->alice_msg_len != SIDH_PUBKEY_LEN) {
            ret = 0;
            DAP_DELETE(a_out);
            a_out = NULL;
            DAP_DELETE(a_key->data);
            a_key->data = NULL;
        }
        // non-compressed
        a_out = malloc(SIDH_PUBKEY_LEN);
        if(a_out == NULL) {
            ret = 0;
            DAP_DELETE(a_out);
            a_out = NULL;
            DAP_DELETE(a_key->data);
            a_key->data = NULL;
        }
        bob_tmp_pub = a_out;    // point to the pub key
    }

    bob_priv = malloc(SIDH_SECRETKEY_LEN);
    if(bob_priv == NULL){
        ret = 0;
        DAP_DELETE(a_out);
        a_out = NULL;
        DAP_DELETE(a_key->data);
        a_key->data = NULL;
    }
    a_key->data = malloc(SIDH_SHAREDKEY_LEN);
    if(a_key->data == NULL) {
        ret = 0;
        DAP_DELETE(a_out);
        a_out = NULL;
        DAP_DELETE(a_key->data);
        a_key->data = NULL;
    }

    // generate Bob's key pair
    if(oqs_sidh_cln16_EphemeralKeyGeneration_B((unsigned char *) bob_priv, (unsigned char *) bob_tmp_pub, sidh_a_key->user_curveIsogeny, sidh_a_key->rand) != SIDH_CRYPTO_SUCCESS) {
        ret = 0;
        DAP_DELETE(a_out);
        a_out = NULL;
        DAP_DELETE(a_key->data);
        a_key->data = NULL;
    }
    if(compressed) {
        // compress Bob's public key
        oqs_sidh_cln16_PublicKeyCompression_B(bob_tmp_pub, (unsigned char *) a_out, sidh_a_key->user_curveIsogeny);
        sidh_a_key->bob_msg_len = SIDH_COMPRESSED_PUBKEY_LEN;
        // decompress Alice's public key
        oqs_sidh_cln16_PublicKeyADecompression_B((unsigned char *) bob_priv, (unsigned char *) a_in, R, A, sidh_a_key->user_curveIsogeny);
        // compute Bob's shared secret
        if(oqs_sidh_cln16_EphemeralSecretAgreement_Compression_B((unsigned char *) bob_priv, R, A, (unsigned char *) a_key->data, sidh_a_key->user_curveIsogeny) != SIDH_CRYPTO_SUCCESS) {
            ret = 0;
            DAP_DELETE(a_out);
            a_out = NULL;
            DAP_DELETE(a_key->data);
            a_key->data = NULL;
        }
    } else {
       sidh_a_key->bob_msg_len = SIDH_PUBKEY_LEN;
        bob_tmp_pub = NULL;  // we do not want to double-free it
        // compute Bob's shared secret
        if(oqs_sidh_cln16_EphemeralSecretAgreement_B((unsigned char *) bob_priv, (unsigned char *) a_in, (unsigned char *) a_key->data, sidh_a_key->user_curveIsogeny) != SIDH_CRYPTO_SUCCESS) {
            ret = 0;
            DAP_DELETE(a_out);
            a_out = NULL;
            DAP_DELETE(a_key->data);
            a_key->data = NULL;
        }
    }
    sidh_a_key->key_len = SIDH_SHAREDKEY_LEN;
    ret = 1;
    DAP_DELETE(bob_tmp_pub);
    DAP_DELETE(bob_priv);
    DAP_DELETE(A);
    DAP_DELETE(R);

    return ret;
}


int OQS_KEX_sidh_cln16_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len) {

    int ret;
    // decompression values
    unsigned char *R = NULL, *A = NULL;

    if (!k || !alice_priv || !bob_msg || !key || !key_len) {
        return 0;
    }

    *key = NULL;

    int compressed = isCompressed(k->named_parameters);

    *key = malloc(SIDH_SHAREDKEY_LEN);
    if (*key == NULL) {
        goto err;
    }
    *key_len = SIDH_SHAREDKEY_LEN;

    if (compressed) {
        if (bob_msg_len != SIDH_COMPRESSED_PUBKEY_LEN) {
            goto err;
        }
        A = malloc(SIDH_COMPRESSED_A_LEN);
        if (A == NULL) {
            goto err;
        }
        R = malloc(SIDH_COMPRESSED_R_LEN);
        if (R == NULL) {
            goto err;
        }
        // compute Alice's shared secret
        oqs_sidh_cln16_PublicKeyBDecompression_A((unsigned char *) alice_priv, (unsigned char *) bob_msg, R, A, k->ctx);
        if (oqs_sidh_cln16_EphemeralSecretAgreement_Compression_A((unsigned char *) alice_priv, R, A, (unsigned char *) *key, k->ctx) != SIDH_CRYPTO_SUCCESS) {
            goto err;
        }
    } else {
        if (bob_msg_len != SIDH_PUBKEY_LEN) {
            goto err;
        }
        if (oqs_sidh_cln16_EphemeralSecretAgreement_A((unsigned char *) alice_priv, (unsigned char *) bob_msg, (unsigned char *) *key, k->ctx) != SIDH_CRYPTO_SUCCESS) {
            goto err;
        }
    }

    ret = 1;
    goto cleanup;

err:
    ret = 0;
    DAP_DELETE(*key);
    *key = NULL;

cleanup:
    DAP_DELETE(A);
    DAP_DELETE(R);

    return ret;
}





































